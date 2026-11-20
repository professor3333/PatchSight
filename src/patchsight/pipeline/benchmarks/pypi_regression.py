"""The PyPI regression set: frozen vulnerabilities with their recorded answers and pinned output.

Proposal §10: "a frozen set of 50 advisories whose expected output is pinned. It runs on
every pull request against cached responses." Each case holds what the Python path needs
after the model has answered, and nothing more:

* the rendered prompt's **metadata**: candidate IDs, paths, names and hunk positions. Its
  messages are emptied, so no advisory text and no third-party code is stored (rule 13);
* the names the changed files define that a proposed entry point can resolve to (exactly,
  or on a dotted boundary), and the files that define each name an entry point can become;
* the **recorded answers**, in call order (``None`` where the provider rejected one);
* the vulnerability's fallback records: names, paths and commit SHAs.

The replay goes through the live code: the extraction loop (validation, one repair,
dead letter), evidence, symbol naming, entry-point qualification and the record merge.
A change that moves any pinned field fails the check, which then lists every difference.
Re-pinning on purpose is a new commit that says why.

What it cannot see: how prompts are rendered (that needs the diffs), and model quality.
"""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.db import FixCommitRef, Record, SymbolEvidence
from patchsight.pipeline import build_db, llm_records
from patchsight.pipeline.extract.extractor import extract_prompt
from patchsight.pipeline.extract.prompt import RenderedPrompt
from patchsight.pipeline.llm.client import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    ProviderRejectedError,
    RateLimiter,
)
from patchsight.pipeline.llm.config import ModelConfig
from patchsight.pipeline.pypi_extract import PyPIExtraction, qualify_with, symbol_evidence

NAME = "pypi-regression-v1"
FROZEN = Path("benchmarks/pypi-regression-v1/cases.json")
# Re-freezing changes this on purpose, in a commit that says why.
FROZEN_SHA256 = "6be7576909f75806a9edffd564f39b953f5c3d64708d098b1133dd466bb81f79"


class ExpectedRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    package: str
    confidence: str
    source: str
    tier_reason: str | None
    symbols: tuple[str, ...]
    entry_points: tuple[str, ...]
    evidence: tuple[str, ...]  # qualified names that carry a rationale


class Expected(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    calls: int
    vulnerable_symbols: tuple[str, ...]
    entry_points: tuple[str, ...]
    evidence: tuple[SymbolEvidence, ...]
    merge: str
    records: tuple[ExpectedRecord, ...]


class Case(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    stratum: str  # why it was chosen
    packages: tuple[str, ...]
    input_hash: str
    fix_commits: tuple[FixCommitRef, ...]
    prompt: RenderedPrompt  # messages emptied
    known_names: tuple[str, ...]  # definitions a proposed entry point can resolve to
    definitions: dict[str, tuple[str, ...]]  # resolvable name -> changed files defining it
    kinds: tuple[tuple[str, str, str], ...]  # (path, name, kind) per candidate
    answers: tuple[str | None, ...]
    fallback: tuple[Record, ...]
    expected: Expected


class RegressionSet(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    model: str
    prompt_version: str
    source: str  # the runs the answers come from
    seed: int
    strata: dict[str, int]
    cases: tuple[Case, ...]


class _Recorded(LLMClient):
    """Serves the recorded answers in order; ``None`` replays a provider rejection."""

    def __init__(self, answers: Sequence[str | None]) -> None:
        super().__init__(_never, RateLimiter(10**9, 10**9), Path("/nonexistent"))
        self._answers = list(answers)

    def complete(self, request: LLMRequest) -> LLMResponse:
        if not self._answers:
            raise ProviderRejectedError("the recorded run made no further call")
        answer = self._answers.pop(0)
        if answer is None:
            raise ProviderRejectedError("recorded rejection")
        return LLMResponse(content=answer, prompt_tokens=0, completion_tokens=0, cached=True,
                           seconds=0.0)  # fmt: skip


def _never(request: LLMRequest) -> tuple[str, int, int]:  # pragma: no cover - never called
    raise AssertionError("a regression replay never calls a backend")


def _expected_records(records: Sequence[Record]) -> tuple[ExpectedRecord, ...]:
    return tuple(
        ExpectedRecord(
            package=r.package,
            confidence=r.confidence,
            source=r.source,
            tier_reason=r.tier_reason,
            symbols=tuple(sorted(s.qualified_name for s in r.symbols)),
            entry_points=tuple(sorted(r.entry_points)),
            evidence=tuple(sorted(e.qualified_name for e in r.evidence)),
        )
        for r in sorted(records, key=lambda r: r.package)
    )


def replay(case: Case, model: str, dotted_entry_points: bool) -> Expected:
    """The case's output, recomputed by the live code from its recorded answers."""
    config = ModelConfig(provider="replay", model=model, max_output_tokens=1, seed=0)
    outcome = extract_prompt(
        _Recorded(case.answers), config, case.vulnerability, case.prompt,
        set(case.known_names), dotted_entry_points,
    )  # fmt: skip
    kinds = {(path, name): kind for path, name, kind in case.kinds}
    paths = {name: set(files) for name, files in case.definitions.items()}
    extraction = PyPIExtraction(
        vulnerability=case.vulnerability, packages=case.packages, input_hash=case.input_hash,
        fix_commits=case.fix_commits,
        vulnerable_symbols=tuple(
            build_db.symbol_for(path, name, kinds[(path, name)])
            for path, name in outcome.vulnerable_locations
        ),
        entry_points=qualify_with(outcome.entry_points, paths),
        evidence=symbol_evidence(outcome, kinds), outcome=outcome,
    )  # fmt: skip
    records, merge = llm_records.merge(list(case.fallback), extraction, None)
    return Expected(
        status=outcome.status, calls=outcome.calls,
        vulnerable_symbols=tuple(sorted(s.qualified_name for s in extraction.vulnerable_symbols)),
        entry_points=extraction.entry_points, evidence=extraction.evidence, merge=merge,
        records=_expected_records(records),
    )  # fmt: skip


class Difference(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    field: str
    expected: str
    actual: str


def check(regression: RegressionSet, dotted_entry_points: bool) -> list[Difference]:
    differences = []
    for case in regression.cases:
        actual = replay(case, regression.model, dotted_entry_points)
        pinned, now = case.expected.model_dump(mode="json"), actual.model_dump(mode="json")
        for field in pinned:
            if pinned[field] != now[field]:
                differences.append(Difference(
                    vulnerability=case.vulnerability, field=field,
                    expected=json.dumps(pinned[field])[:300], actual=json.dumps(now[field])[:300],
                ))  # fmt: skip
    return differences


def select(outcomes: Mapping[str, PyPIExtraction], size: int, seed: int) -> list[tuple[str, str]]:
    """``(vulnerability, stratum)`` pairs: every rare outcome the runs produced, then a
    seeded sample of the common ones, so the set exercises each path of the loop."""
    import random

    def stratum(e: PyPIExtraction) -> str:
        o = e.outcome
        if o.status != "ok":
            return o.status  # dead_letter, repaired, no_candidates
        if o.provider_rejections:
            return "ok after a rejection"
        if o.truncated:
            return "ok, truncated"
        if e.entry_points:
            return "ok, with entry points"
        if len(e.packages) > 1 or len(e.fix_commits) > 1:
            return "ok, several packages or commits"
        return "ok"

    by_stratum: dict[str, list[str]] = {}
    for key in sorted(outcomes):
        by_stratum.setdefault(stratum(outcomes[key]), []).append(key)
    rng = random.Random(seed)  # noqa: S311 - a reproducible sample, not a secret
    quotas = {"dead_letter": 5, "repaired": 3, "no_candidates": 2, "ok after a rejection": 3,
              "ok, truncated": 8, "ok, with entry points": 10,
              "ok, several packages or commits": 6}  # fmt: skip
    chosen: list[tuple[str, str]] = []
    for name in sorted(by_stratum):
        keys = by_stratum[name]
        take = min(len(keys), quotas.get(name, 0))
        chosen += [(k, name) for k in sorted(rng.sample(keys, take))]
    rest = [k for k in by_stratum.get("ok", []) if k not in {c for c, _ in chosen}]
    chosen += [(k, "ok") for k in sorted(rng.sample(rest, max(0, size - len(chosen))))]
    return sorted(chosen)


def save(regression: RegressionSet, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(regression.model_dump_json(indent=1) + "\n", "utf-8")


def load(path: Path, sha256: str | None = FROZEN_SHA256) -> RegressionSet:
    """The frozen set, refused if its bytes are not the pinned ones."""
    import hashlib

    data = path.read_bytes()
    if sha256 is not None and hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError(f"{path} is not the pinned regression set; re-freeze on purpose")
    return RegressionSet.model_validate_json(data)
