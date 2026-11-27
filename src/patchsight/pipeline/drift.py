"""Live drift check (ADR 0016): ask the nightly model pinned prompts again, compare decisions.

A model behind a hosted API can change without notice: new weights, a new quantisation, a
changed serving path. The nightly's own outcomes cannot show it, because each night's prompts
are new. So every night a few prompts the model has answered before are asked again, live,
and its **decisions** are compared with the pinned answers: which candidates it marks
vulnerable and which entry points it names, as it returned them, before validation, so that a
validator change is not mistaken for drift. Rationale wording is not compared: E13 found that
it varies on the same prompt while the decisions stay the same.

A pinned prompt is compared only when tonight's rendering of it has the pinned request key
(the same model, decoding parameters, prompt version and rendered text). Otherwise its input
changed, for example an edited advisory or a config change, and the case is reported but not
compared.

The pinned file holds request keys, candidate IDs, the vulnerable candidates' paths and names
and the entry points: no code, no advisory text and no rationale (rule 13).
"""

import random
import re
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from patchsight.pipeline.extract.prompt import RenderedPrompt
from patchsight.pipeline.extract.schema import Extraction
from patchsight.pipeline.llm.client import (
    LLMClient,
    LLMRequest,
    ProviderRejectedError,
    QuotaExhaustedError,
    RateLimitedError,
)

PINNED = Path("benchmarks/drift/pypi-extractor-v1.json")
SIZE = 10
SEED = 20261127
MIN_CANDIDATES = 2  # a one-candidate prompt leaves only its entry points free to change
# Declared before the first live check (ADR 0016).
DRIFT_AT = 2  # changed cases in one night that make it drift
MIN_COMPARED = 5  # fewer compared cases, and no drift, is inconclusive


class Decisions(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerable: tuple[str, ...]  # candidate IDs the model marked vulnerable, in ID order
    entry_points: tuple[str, ...]  # as the model named them, sorted, once each


def _id_order(candidate_id: str) -> tuple[int, str]:
    match = re.fullmatch(r"[A-Z](\d+)", candidate_id)
    return (int(match.group(1)), "") if match else (10**9, candidate_id)


def decisions(content: str) -> Decisions | None:
    """The decisions in a raw answer, or None when it is not the schema's JSON."""
    try:
        answer = Extraction.model_validate_json(content)
    except ValidationError:
        return None
    vulnerable = {i.candidate_id for i in answer.items if i.is_vulnerable}
    return Decisions(
        vulnerable=tuple(sorted(vulnerable, key=_id_order)),
        entry_points=tuple(sorted(set(answer.public_entry_points))),
    )


def answers_every_candidate(content: str, prompt: RenderedPrompt) -> bool:
    """Whether a raw answer judges each of the prompt's candidates exactly once."""
    try:
        answer = Extraction.model_validate_json(content)
    except ValidationError:
        return False
    judged = [i.candidate_id for i in answer.items]
    return sorted(judged) == sorted(c.id for c in prompt.candidates)


def names(prompt: RenderedPrompt, ids: Sequence[str]) -> dict[str, str]:
    """``path:name`` of each candidate ID, for a reader of the report."""
    by_id = {c.id: f"{c.path}:{c.name}" for c in prompt.candidates}
    return {i: by_id[i] for i in ids if i in by_id}


class PinnedCase(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    request_key: str  # the first request's cache key when it was answered
    candidates: int
    expected: Decisions
    names: dict[str, str]  # the expected vulnerable candidates' ``path:name``


class Pinned(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    role: str
    model: str
    prompt_version: str
    config_sha256: str  # the LLM config the answers were given under
    seed: int
    pool: int  # vulnerabilities whose answer could be replayed, before the draw
    cases: tuple[PinnedCase, ...]


def draw(pool: Sequence[PinnedCase], size: int = SIZE, seed: int = SEED) -> list[PinnedCase]:
    """A seeded draw from the replayable answers with at least ``MIN_CANDIDATES``
    candidates, in vulnerability order."""
    ordered = sorted((c for c in pool if c.candidates >= MIN_CANDIDATES),
                     key=lambda c: c.vulnerability)  # fmt: skip
    chosen = random.Random(seed).sample(ordered, min(size, len(ordered)))  # noqa: S311
    return sorted(chosen, key=lambda c: c.vulnerability)


CaseStatus = Literal[
    "same",  # compared: the same decisions
    "changed",  # compared: other decisions
    "invalid",  # compared: the answer is not the schema's JSON
    "input_changed",  # tonight's prompt differs from the pinned one: not compared
    "no_prompt",  # no prompt tonight (the fix no longer maps, for example): not compared
    "rejected",  # the provider refused to answer: not compared
    "not_run",  # the daily cap stopped the check first
]
COMPARED: frozenset[CaseStatus] = frozenset({"same", "changed", "invalid"})


class CaseResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    status: CaseStatus
    got: Decisions | None = None
    names: dict[str, str] = {}  # ``path:name`` of the vulnerable candidates, both answers
    detail: str = ""  # why it was not compared


def compare(case: PinnedCase, content: str, prompt: RenderedPrompt) -> CaseResult:
    got = decisions(content)
    if got is None:
        return CaseResult(vulnerability=case.vulnerability, status="invalid")
    status: CaseStatus = "same" if got == case.expected else "changed"
    shown = (*case.expected.vulnerable, *got.vulnerable) if status == "changed" else ()
    return CaseResult(vulnerability=case.vulnerability, status=status, got=got,
                      names={**case.names, **names(prompt, shown)} if shown else {})  # fmt: skip


def check(
    cases: Sequence[PinnedCase],
    render: Callable[[str], RenderedPrompt | str],
    request_for: Callable[[RenderedPrompt], LLMRequest],
    llm: LLMClient,
) -> tuple[list[CaseResult], bool]:
    """Ask each pinned prompt again, in order, when tonight's request key is the pinned one.
    ``render`` gives a vulnerability's prompt tonight, or why there is none. Returns the
    results, and whether a daily cap stopped the check (the rest are then ``not_run``)."""
    results: list[CaseResult] = []
    stopped = False
    for case in cases:
        key = case.vulnerability
        if stopped:
            results.append(CaseResult(vulnerability=key, status="not_run"))
            continue
        prompt = render(key)
        if isinstance(prompt, str):
            detail = prompt.replace("_", " ")
            results.append(CaseResult(vulnerability=key, status="no_prompt", detail=detail))
            continue
        request = request_for(prompt)
        if request.cache_key() != case.request_key:
            results.append(CaseResult(vulnerability=key, status="input_changed"))
            continue
        try:
            with llm.tracer.advisory(key):
                content = llm.complete(request).content
        except (QuotaExhaustedError, RateLimitedError):
            stopped = True
            results.append(CaseResult(vulnerability=key, status="not_run"))
            continue
        except ProviderRejectedError:
            # The provider's message is not kept: it can name the account.
            results.append(CaseResult(vulnerability=key, status="rejected"))
            continue
        results.append(compare(case, content, prompt))
    return results, stopped


Verdict = Literal["ok", "note", "drift", "inconclusive"]


def verdict(results: Sequence[CaseResult]) -> Verdict:
    """ADR 0016: drift when 2 or more cases change in one night; with fewer, inconclusive
    when fewer than 5 were compared, a note when one changed, otherwise ok."""
    changed = sum(r.status in ("changed", "invalid") for r in results)
    if changed >= DRIFT_AT:
        return "drift"
    if sum(r.status in COMPARED for r in results) < MIN_COMPARED:
        return "inconclusive"
    return "note" if changed else "ok"


class DriftReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    pinned: str
    pinned_sha256: str
    model: str
    checked: str  # UTC date
    verdict: Verdict
    counts: dict[str, int]
    cases: tuple[CaseResult, ...]


def report(
    pinned: Pinned, pinned_sha256: str, checked: str, results: Sequence[CaseResult]
) -> DriftReport:
    counts = Counter(r.status for r in results)
    return DriftReport(pinned=pinned.name, pinned_sha256=pinned_sha256, model=pinned.model,
                       checked=checked, verdict=verdict(results),
                       counts={k: counts[k] for k in sorted(counts)},
                       cases=tuple(results))  # fmt: skip


VERDICTS = {
    "ok": "no decision changed",
    "note": "one decision changed; below the drift threshold of 2",
    "drift": "the model's decisions changed on 2 or more pinned prompts",
    "inconclusive": f"fewer than {MIN_COMPARED} pinned prompts could be compared",
}


def _decisions(d: Decisions | None, labels: dict[str, str]) -> str:
    if d is None:
        return "—"
    vulnerable = ", ".join(f"{i} `{labels.get(i, '?')}`" for i in d.vulnerable) or "none"
    entry = ", ".join(f"`{e}`" for e in d.entry_points) or "none"
    return f"vulnerable: {vulnerable}; entry points: {entry}"


def render_markdown(r: DriftReport, pinned: Pinned) -> str:
    counts = ", ".join(f"{k} {v}" for k, v in r.counts.items())
    lines = [
        f"# Live drift check, {r.checked}",
        "",
        f"**{r.verdict}:** {VERDICTS[r.verdict]} ({counts}).",
        "",
        f"`{r.model}` was asked {len(pinned.cases)} prompts it answered before "
        f"(`{r.pinned}`, SHA-256 `{r.pinned_sha256}`), and its decisions were compared with "
        "the pinned answers: the candidates it marks vulnerable and the entry points it names, "
        "before validation. Wording is not compared. A prompt whose input changed since is "
        "not compared (ADR 0016).",
        "",
        "| Vulnerability | Result | Detail |",
        "|---|---|---|",
    ]
    expected = {c.vulnerability: c for c in pinned.cases}
    for c in r.cases:
        detail = c.detail
        if c.status == "changed":
            pinned_case = expected[c.vulnerability]
            detail = (f"pinned {_decisions(pinned_case.expected, c.names)}; "
                      f"tonight {_decisions(c.got, c.names)}")  # fmt: skip
        lines.append(f"| `{c.vulnerability}` | {c.status} | {detail} |")
    lines.append("")
    return "\n".join(lines)
