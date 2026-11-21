"""Run LLM extraction on the Dunlap Go benchmark and score it against GoVulnDB symbols.

Candidates come from PatchSight's own fetch-and-map pipeline, the same candidate sets that
reproduce the published ChangedFuncs baseline. ChangedFuncs is scored on the same reports,
so every run carries its own naive baseline.
"""

import csv
import random
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import date
from pathlib import Path

from pydantic import BaseModel

from patchsight.eval.metrics import Interval, SetScores, score
from patchsight.pipeline.benchmarks import dunlap
from patchsight.pipeline.diffs.commits import CommitMapping, map_commit
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.extract.extractor import ExtractionOutcome, extract
from patchsight.pipeline.extract.prompt import AdvisoryText, CandidateInput, PromptTemplate
from patchsight.pipeline.llm.client import LLMClient
from patchsight.pipeline.llm.config import LLMConfig
from patchsight.pipeline.llm.tokens import TokenCounter

DUNLAP_ADVISORIES = "data/advisory-data/govulndb-2023-10-26.csv"
# The benchmark is function-level (Dunlap et al.), so only functions and methods compete.
FUNCTION_KINDS = frozenset({"function", "method"})
BOOTSTRAP = 2000
SEED = 20261114


class ExtractionRun(BaseModel):
    as_of: date
    model: str
    prompt_version: str
    reports: int
    split: str
    split_sha256: str | None
    sample_size: int | None
    sample_seed: int
    extraction: SetScores
    changedfuncs: SetScores
    status: dict[str, int]
    truncated: int
    invented_ids_first_attempt: int
    entry_points_dropped: int
    prompt_tokens: int
    completion_tokens: int
    estimated_prompt_tokens: int
    calls: int
    cached_calls: int
    provider_rejections: int
    outcomes: tuple[ExtractionOutcome, ...]


def load_advisories(path: Path) -> dict[str, AdvisoryText]:
    csv.field_size_limit(1 << 30)
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            row["id"]: AdvisoryText(id=row["id"], summary=row["summary"], details=row["details"])
            for row in csv.DictReader(handle)
        }


def candidate_inputs(
    mappings: Sequence[CommitMapping], kinds: frozenset[str] = FUNCTION_KINDS
) -> tuple[list[CandidateInput], set[str]]:
    """Candidates of the given kinds from mapped commits, and every known definition name."""
    inputs: list[CandidateInput] = []
    known: set[str] = set()
    for mapping in mappings:
        for file in mapping.files:
            known.update(file.mapping.known_names)
            by_index = {h.index: h for h in file.hunks}
            for changed in file.mapping.changed:
                if changed.kind not in kinds:
                    continue
                inputs.append(
                    CandidateInput(
                        path=file.mapping.path,
                        name=changed.name,
                        kind=changed.kind,
                        hunks=tuple(by_index[i] for i in changed.hunks if i in by_index),
                        source=mapping.sha,
                    )
                )
    return inputs, known


def select(
    reports: Sequence[dunlap.DunlapReport],
    size: int | None,
    seed: int,
    ids: frozenset[str] | None = None,
) -> list[dunlap.DunlapReport]:
    ordered = sorted((r for r in reports if ids is None or r.id in ids), key=lambda r: r.id)
    if size is None or size >= len(ordered):
        return ordered
    return sorted(random.Random(seed).sample(ordered, size), key=lambda r: r.id)  # noqa: S311


def run(
    github: GitHubClient,
    llm: LLMClient,
    config: LLMConfig,
    role: str,
    template: PromptTemplate,
    counter: TokenCounter,
    reports: Sequence[dunlap.DunlapReport],
    advisories: dict[str, AdvisoryText],
    as_of: date,
    sample_size: int | None,
    seed: int = SEED,
    ids: frozenset[str] | None = None,
    split: str = "all",
    split_sha256: str | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> ExtractionRun:
    model = config.models[role]
    budget = config.prompt_budget(role)
    limit = config.candidate_limit(role)
    truth: dict[str, set[str]] = {}
    predicted: dict[str, set[str]] = {}
    naive: dict[str, set[str]] = {}
    outcomes: list[ExtractionOutcome] = []
    chosen = select(reports, sample_size, seed, ids)
    for number, report in enumerate(chosen, 1):
        mappings = [
            map_commit(github, c.github_repo, c.sha, include=dunlap.paper_path_filter)
            for c in report.commits
        ]
        inputs, known = candidate_inputs(mappings)
        outcome = extract(
            llm,
            model,
            template,
            advisories[report.id],
            inputs,
            known,
            budget,
            counter,
            config.budget.max_hunk_lines,
            limit,
            config.validation.dotted_entry_points,
            config.budget.candidate_order,
        )
        outcomes.append(outcome)
        truth[report.id] = set(report.symbols)
        predicted[report.id] = set(outcome.vulnerable)
        naive[report.id] = {i.name for i in inputs}
        if progress is not None and (number % 10 == 0 or number == len(chosen)):
            progress(number, len(chosen))

    return ExtractionRun(
        as_of=as_of,
        model=model.model,
        prompt_version=template.version,
        reports=len(outcomes),
        split=split,
        split_sha256=split_sha256,
        sample_size=sample_size,
        sample_seed=seed,
        extraction=score(predicted, truth, BOOTSTRAP, seed),
        changedfuncs=score(naive, truth, BOOTSTRAP, seed),
        status=dict(sorted(Counter(o.status for o in outcomes).items())),
        truncated=sum(o.truncated for o in outcomes),
        invented_ids_first_attempt=sum(o.invented_ids_first_attempt for o in outcomes),
        entry_points_dropped=sum(o.entry_points_dropped for o in outcomes),
        prompt_tokens=sum(o.prompt_tokens for o in outcomes),
        completion_tokens=sum(o.completion_tokens for o in outcomes),
        estimated_prompt_tokens=sum(o.estimated_prompt_tokens for o in outcomes),
        calls=sum(o.calls for o in outcomes),
        cached_calls=sum(o.cached_calls for o in outcomes),
        provider_rejections=sum(o.provider_rejections for o in outcomes),
        outcomes=tuple(outcomes),
    )


def _row(label: str, s: SetScores) -> str:
    def ci(interval: Interval | None) -> str:
        return "" if interval is None else f" ({interval.low:.2f} to {interval.high:.2f})"

    return (
        f"| {label} | {s.precision:.3f}{ci(s.precision_ci95)} | {s.recall:.3f}{ci(s.recall_ci95)} "
        f"| {s.f1:.3f}{ci(s.f1_ci95)} | {s.miss_rate:.1%} |"
    )


def render_markdown(run_: ExtractionRun, source_lines: Sequence[str]) -> str:
    split_note = f"split `{run_.split}`" + (
        f" (SHA-256 `{run_.split_sha256}`)" if run_.split_sha256 else ""
    )
    if run_.sample_size is not None:
        scope = (
            f"a seeded random sample of {run_.reports} reports (seed {run_.sample_seed}) from "
            f"{split_note}. **A sample run, not the benchmark result.**"
        )
    else:
        scope = f"all {run_.reports} reports of {split_note}."
    estimate_ratio = (
        run_.prompt_tokens / run_.estimated_prompt_tokens if run_.estimated_prompt_tokens else 0.0
    )
    return "\n".join(
        [
            f"# LLM extraction on the Dunlap Go benchmark: `{run_.prompt_version}`, `{run_.model}`",
            "",
            "Generated by `python -m patchsight.pipeline dunlap-extract`; do not edit by hand.",
            "",
            "## Sources",
            "",
            *source_lines,
            "",
            "## Scope",
            "",
            f"Run on {scope}",
            "",
            "## Results",
            "",
            f"Unit: (report, function). 95% CIs from {BOOTSTRAP:,} bootstrap resamples of reports. "
            "ChangedFuncs is scored on the same reports.",
            "",
            "| System | Precision | Recall | F1 | Miss rate |",
            "|---|---|---|---|---|",
            _row("ChangedFuncs (naive)", run_.changedfuncs),
            _row(f"**{run_.model}**, `{run_.prompt_version}`", run_.extraction),
            "",
            "## Reliability",
            "",
            f"- Outcomes: {', '.join(f'{k} {v}' for k, v in run_.status.items())}. "
            "A dead-lettered report predicts nothing in this table; the confidence tiers in "
            "Phase 2 will fall back to ChangedFuncs instead.",
            f"- Invented candidate IDs on the first attempt (pre-validation hallucination): "
            f"{run_.invented_ids_first_attempt}. After validation: 0 by construction.",
            f"- Entry-point names dropped because they matched no known definition: "
            f"{run_.entry_points_dropped}.",
            f"- Prompts truncated to the token budget: {run_.truncated}.",
            "",
            "## Cost",
            "",
            f"- Calls: {run_.calls} ({run_.cached_calls} from cache; "
            f"{run_.provider_rejections} rejected by the provider and retried).",
            f"- Tokens: {run_.prompt_tokens:,} prompt and {run_.completion_tokens:,} completion "
            f"(mean {run_.prompt_tokens / max(run_.reports, 1):,.0f} prompt tokens per report).",
            f"- Token count accuracy: the provider reported {estimate_ratio:.2f} times the tokens "
            "PatchSight counted with the model's tokenizer.",
            "",
        ]
    )
