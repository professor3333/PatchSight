"""Replay bundles: re-score an LLM extraction run offline, from the model's own answers.

A run's prompts contain third-party code and cannot be published, but scoring needs only
what the model was shown *by ID* and what it answered. A replay bundle stores, per report:

* the rendered candidates: ID, function name, file path, and the hunk IDs each may cite;
* the model's raw answers, in order (``null`` where the provider rejected an attempt).

``replay`` runs the same validator and the same attempt logic as the live extractor on those
answers, so a stranger recomputes the published scores exactly, with no model, network or
code.
"""

import json
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.eval.metrics import SetScores, score
from patchsight.pipeline.benchmarks import dunlap
from patchsight.pipeline.benchmarks.extraction import candidate_inputs
from patchsight.pipeline.diffs.commits import map_commit
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.extract.extractor import extract
from patchsight.pipeline.extract.prompt import (
    AdvisoryText,
    Candidate,
    PromptTemplate,
    RenderedPrompt,
    render,
)
from patchsight.pipeline.extract.validate import ValidationFailedError, validate
from patchsight.pipeline.llm.client import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    ProviderRejectedError,
    RateLimiter,
)
from patchsight.pipeline.llm.config import LLMConfig
from patchsight.pipeline.llm.tokens import TokenCounter

REPLAY_VERSION = 1


class ReplayReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    candidates: tuple[Candidate, ...]
    answers: tuple[str | None, ...]
    truncated: bool
    dropped: tuple[str, ...]


class ReplayBundle(BaseModel):
    replay_version: int
    benchmark: str
    model: str
    prompt_version: str
    split: str = "all"
    reports: tuple[ReplayReport, ...]


class _CacheMissError(RuntimeError):
    pass


def _cache_only(request: LLMRequest) -> tuple[str, int, int]:
    raise _CacheMissError("a response is missing from the cache; export needs a complete run")


class _Recorder(LLMClient):
    """A cache-only client that records every answer it serves, in order."""

    def __init__(self, cache_dir: Path, counter: TokenCounter) -> None:
        super().__init__(_cache_only, RateLimiter(10**9, 10**9), cache_dir, counter)
        self.answers: list[str | None] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        try:
            response = super().complete(request)
        except ProviderRejectedError:
            self.answers.append(None)
            raise
        self.answers.append(response.content)
        return response


def export(
    github: GitHubClient,
    llm_cache: Path,
    config: LLMConfig,
    role: str,
    template: PromptTemplate,
    counter: TokenCounter,
    reports: Sequence[dunlap.DunlapReport],
    advisories: dict[str, AdvisoryText],
    split: str = "all",
) -> ReplayBundle:
    model = config.models[role]
    budget = config.prompt_budget(role)
    exported = []
    for report in sorted(reports, key=lambda r: r.id):
        mappings = [
            map_commit(github, c.github_repo, c.sha, include=dunlap.paper_path_filter)
            for c in report.commits
        ]
        inputs, known = candidate_inputs(mappings)
        prompt = render(
            template, advisories[report.id], inputs, budget, counter, config.budget.max_hunk_lines
        )
        recorder = _Recorder(llm_cache, counter)
        extract(
            recorder, model, template, advisories[report.id], inputs, known, budget, counter,
            config.budget.max_hunk_lines,
        )  # fmt: skip
        exported.append(
            ReplayReport(
                id=report.id,
                candidates=prompt.candidates,
                answers=tuple(recorder.answers),
                truncated=prompt.truncated,
                dropped=prompt.dropped,
            )
        )
    return ReplayBundle(
        replay_version=REPLAY_VERSION,
        benchmark="dunlap-dimva24",
        model=model.model,
        prompt_version=template.version,
        split=split,
        reports=tuple(exported),
    )


def replay_report(report: ReplayReport, prompt_version: str) -> tuple[str, set[str]]:
    """(status, predicted vulnerable names), by the live extractor's own rules."""
    if not report.candidates:
        return "no_candidates", set()
    prompt = RenderedPrompt(
        version=prompt_version,
        messages=(),
        candidates=report.candidates,
        hunk_ids=tuple(sorted({h for c in report.candidates for h in c.hunk_ids})),
        estimated_tokens=0,
        truncated=report.truncated,
        dropped=report.dropped,
    )
    names = {c.id: c.name for c in report.candidates}
    for attempt, answer in enumerate(report.answers[:2]):
        if answer is None:
            continue
        try:
            result = validate(answer, prompt, known_names=set())
        except ValidationFailedError:
            continue
        clean_first = attempt == 0 and report.answers[0] is not None
        return ("ok" if clean_first else "repaired"), {names[c] for c in result.vulnerable_ids}
    return "dead_letter", set()


def replay(
    bundle: ReplayBundle, truth: dict[str, set[str]], ids: frozenset[str] | None = None
) -> tuple[SetScores, dict[str, int]]:
    chosen = [r for r in bundle.reports if ids is None or r.id in ids]
    statuses: Counter[str] = Counter()
    predicted: dict[str, set[str]] = {}
    for report in chosen:
        status, names = replay_report(report, bundle.prompt_version)
        statuses[status] += 1
        predicted[report.id] = names
    return score(predicted, {r.id: truth[r.id] for r in chosen}), dict(sorted(statuses.items()))


def save(bundle: ReplayBundle, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle.model_dump(mode="json"), indent=1) + "\n", encoding="utf-8")


def load(path: Path) -> ReplayBundle:
    bundle = ReplayBundle.model_validate_json(path.read_text(encoding="utf-8"))
    if bundle.replay_version != REPLAY_VERSION:
        raise ValueError(f"{path} is replay version {bundle.replay_version}, not {REPLAY_VERSION}")
    return bundle
