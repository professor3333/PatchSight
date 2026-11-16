"""LLM extraction for PyPI vulnerabilities: the backfill (proposal §6; Phase 2, step 3).

Each vulnerability gets one extraction over the same definitions its fallback record lists:
the functions, methods and classes that ``build_db.fix_mappings`` finds in its fix commits.
Python bugs can sit in a class body, so classes compete too; the Go benchmark stays
function-level.

Every model answer is cached by request, so a stopped run resumes where it left off, and a
Kaggle run can be imported and replayed here with no model calls. A Kaggle session lasts at
most 12 hours, so a run can be split into deterministic shards and given a time budget.
Turning outcomes into database records, with confidence tiers (ADR 0004), is a separate step.
"""

import hashlib
import time
from collections import Counter
from collections.abc import Callable, Sequence

from pydantic import BaseModel, ConfigDict

from patchsight.db import FixCommitRef, HunkLocation, Symbol, SymbolEvidence
from patchsight.pipeline import build_db
from patchsight.pipeline.benchmarks.extraction import candidate_inputs
from patchsight.pipeline.diffs.commits import CommitMapping
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.extract.extractor import ExtractionOutcome, extract
from patchsight.pipeline.extract.prompt import AdvisoryText, PromptTemplate, render
from patchsight.pipeline.http import CacheMissError
from patchsight.pipeline.ingest.aliases import AliasGroup
from patchsight.pipeline.ingest.osv import Advisory
from patchsight.pipeline.llm.client import LLMClient
from patchsight.pipeline.llm.config import LLMConfig
from patchsight.pipeline.llm.tokens import TokenCounter
from patchsight.pipeline.pypi import PyPIClient

PYTHON_KINDS = frozenset({"function", "method", "class"})


class PyPIExtraction(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    packages: tuple[str, ...]
    input_hash: str
    fix_commits: tuple[FixCommitRef, ...]
    # The vulnerable candidates as database symbols (module-qualified, with path and kind).
    vulnerable_symbols: tuple[Symbol, ...]
    # The validated entry points, module-qualified from the files that define them, as the
    # scanner matches them (``yaml.full_load``, not ``full_load``).
    entry_points: tuple[str, ...] = ()
    # Rationale and cited hunk locations for each vulnerable symbol.
    evidence: tuple[SymbolEvidence, ...] = ()
    outcome: ExtractionOutcome


class PyPIExtractionRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    model: str
    role: str
    prompt_version: str
    vulnerabilities: int
    processed: int
    complete: bool  # False when the time budget ran out first
    skipped: dict[str, int]
    status: dict[str, int]
    truncated: int
    prompt_tokens: int
    completion_tokens: int
    calls: int
    cached_calls: int
    provider_rejections: int


class PromptPlan(BaseModel):
    """Prompt sizes for one vulnerability, measured without calling a model."""

    model_config = ConfigDict(frozen=True)

    vulnerability: str
    candidates: int
    full_prompt_tokens: int  # every candidate, no budget
    kept: int  # candidates kept under the role's budget and candidate limit
    truncated: bool


def plan_vulnerability(
    group: AliasGroup,
    by_id: dict[str, Advisory],
    github: GitHubClient,
    pypi: PyPIClient,
    config: LLMConfig,
    role: str,
    template: PromptTemplate,
    counter: TokenCounter,
) -> PromptPlan | str:
    """Render the prompt twice, unbounded and as it would be sent; no model call."""
    try:
        fixes = build_db.fix_mappings(group, by_id, github, pypi)
    except CacheMissError:
        return "cache_miss"
    if fixes.status != "mapped":
        return fixes.status
    if len(build_db.changed_symbols(fixes.mappings)) > build_db.MAX_SYMBOLS:
        return "too_broad"
    inputs, _ = candidate_inputs(fixes.mappings, PYTHON_KINDS)
    advisory = advisory_text(group, by_id)
    lines = config.budget.max_hunk_lines
    full = render(template, advisory, inputs, 10**9, counter, lines)
    sent = render(
        template, advisory, inputs, config.prompt_budget(role), counter, lines,
        config.candidate_limit(role),
    )  # fmt: skip
    return PromptPlan(
        vulnerability=group.key,
        candidates=len(inputs),
        full_prompt_tokens=full.estimated_tokens,
        kept=len(sent.candidates),
        truncated=sent.truncated,
    )


def symbol_evidence(
    outcome: ExtractionOutcome, kinds: dict[tuple[str, str], str]
) -> tuple[SymbolEvidence, ...]:
    """Evidence per qualified symbol. A definition changed by two commits appears as two
    candidates: its first rationale is kept and the cited hunks are combined."""
    merged: dict[str, tuple[str, list[HunkLocation]]] = {}
    for item in outcome.evidence:
        name = build_db.symbol_for(item.path, item.name, kinds[(item.path, item.name)])
        _, hunks = merged.setdefault(name.qualified_name, (item.rationale, []))
        for ref in item.hunks:
            location = HunkLocation(
                commit=ref.source, path=ref.path, old_start=ref.old_start,
                old_count=ref.old_count, new_start=ref.new_start, new_count=ref.new_count,
            )  # fmt: skip
            if location not in hunks:
                hunks.append(location)
    return tuple(
        SymbolEvidence(qualified_name=name, rationale=rationale, hunks=tuple(hunks))
        for name, (rationale, hunks) in sorted(merged.items())
    )


def qualify_entry_points(
    names: Sequence[str], mappings: Sequence[CommitMapping]
) -> tuple[str, ...]:
    """Module-qualify each entry point by every changed file that defines it.

    Entry points are validated against the definitions in the changed files, so each name
    has at least one; a file outside any importable module leaves the bare name.
    """
    paths: dict[str, set[str]] = {}
    for mapping in mappings:
        for file in mapping.files:
            for known in file.mapping.known_names:
                paths.setdefault(known, set()).add(file.mapping.path)
    qualified: set[str] = set()
    for name in names:
        for path in paths.get(name, ()):
            qualified.add(build_db.symbol_for(path, name, "function").qualified_name)
        if name not in paths:
            qualified.add(name)
    return tuple(sorted(qualified))


def in_shard(key: str, shard: int, shards: int) -> bool:
    """Whether a vulnerability belongs to shard ``shard`` of ``shards`` (1-based), stably."""
    if not 1 <= shard <= shards:
        raise ValueError(f"shard {shard} is not between 1 and {shards}")
    digest = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16)
    return digest % shards == shard - 1


def advisory_text(group: AliasGroup, by_id: dict[str, Advisory]) -> AdvisoryText:
    """One advisory text per vulnerability: the first summary and the longest details.

    Aliases (GHSA, PYSEC, CVE) usually repeat one text; the longest details carry the most.
    """
    advisories = [by_id[i] for i in group.advisory_ids]
    summary = next((a.summary for a in advisories if a.summary), "")
    details = max((a.details for a in advisories), key=len, default="")
    return AdvisoryText(id=group.key, summary=summary, details=details)


def extract_vulnerability(
    group: AliasGroup,
    by_id: dict[str, Advisory],
    github: GitHubClient,
    pypi: PyPIClient,
    llm: LLMClient,
    config: LLMConfig,
    role: str,
    template: PromptTemplate,
    counter: TokenCounter,
) -> PyPIExtraction | str:
    """The extraction for one vulnerability, or why it has none (a build status)."""
    try:
        fixes = build_db.fix_mappings(group, by_id, github, pypi)
    except CacheMissError:
        return "cache_miss"  # offline run without this response: visible, never "no fix"
    if fixes.status != "mapped":
        return fixes.status
    if len(build_db.changed_symbols(fixes.mappings)) > build_db.MAX_SYMBOLS:
        return "too_broad"
    inputs, known = candidate_inputs(fixes.mappings, PYTHON_KINDS)
    outcome = extract(
        llm, config.models[role], template, advisory_text(group, by_id), inputs, known,
        config.prompt_budget(role), counter, config.budget.max_hunk_lines,
        config.candidate_limit(role),
    )  # fmt: skip
    kinds = {(i.path, i.name): i.kind for i in inputs}
    return PyPIExtraction(
        entry_points=qualify_entry_points(outcome.entry_points, fixes.mappings),
        evidence=symbol_evidence(outcome, kinds),
        vulnerability=group.key,
        packages=fixes.packages,
        input_hash=build_db.input_hash(group, by_id),
        fix_commits=tuple(FixCommitRef(repo=m.repo, sha=m.sha) for m in fixes.mappings),
        vulnerable_symbols=tuple(
            build_db.symbol_for(path, name, kinds[(path, name)])
            for path, name in outcome.vulnerable_locations
        ),
        outcome=outcome,
    )


def run(
    groups: Sequence[AliasGroup],
    by_id: dict[str, Advisory],
    github: GitHubClient,
    pypi: PyPIClient,
    llm: LLMClient,
    config: LLMConfig,
    role: str,
    template: PromptTemplate,
    counter: TokenCounter,
    progress: Callable[[int, int], None] | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[list[PyPIExtraction], PyPIExtractionRun]:
    """Extract in key order. With a ``deadline`` (a ``clock`` value), no new vulnerability
    starts after it; the summary then says the run is incomplete."""
    results: list[PyPIExtraction] = []
    skipped: Counter[str] = Counter()
    ordered = sorted(groups, key=lambda g: g.key)
    processed = 0
    for number, group in enumerate(ordered, 1):
        if deadline is not None and clock() >= deadline:
            break
        processed = number
        result = extract_vulnerability(
            group, by_id, github, pypi, llm, config, role, template, counter
        )
        if isinstance(result, str):
            skipped[result] += 1
        else:
            results.append(result)
        if progress is not None and (number % 25 == 0 or number == len(ordered)):
            progress(number, len(ordered))
    outcomes = [r.outcome for r in results]
    return results, PyPIExtractionRun(
        model=config.models[role].model,
        role=role,
        prompt_version=template.version,
        vulnerabilities=len(ordered),
        processed=processed,
        complete=processed == len(ordered),
        skipped=dict(sorted(skipped.items())),
        status=dict(sorted(Counter(o.status for o in outcomes).items())),
        truncated=sum(o.truncated for o in outcomes),
        prompt_tokens=sum(o.prompt_tokens for o in outcomes),
        completion_tokens=sum(o.completion_tokens for o in outcomes),
        calls=sum(o.calls for o in outcomes),
        cached_calls=sum(o.cached_calls for o in outcomes),
        provider_rejections=sum(o.provider_rejections for o in outcomes),
    )
