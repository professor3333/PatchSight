"""The masked evaluation of the fix-commit locator (proposal section 10).

Labels come free by masking: take vulnerabilities whose advisories *do* link a fix commit
on the package's own repository, hide the link, and ask the locator to find it. The
sample is drawn once with a recorded seed and frozen in ``benchmarks/locator/``; it holds
IDs, repositories and commit SHAs only.

Metrics, per the proposal's targets:

* **exact-SHA accuracy**: the located commit is one the advisories link (target 70%+);
* **wrong-commit rate**: a commit was located, but not a linked one (target 5% or less);
* **abstention rate**, and GitHub and PyPI requests per vulnerability.

A wrong commit poisons extraction, while abstaining only costs coverage, so the
wrong-commit cap matters more than the hit rate.
"""

import json
import random
import statistics
from collections import Counter
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.http import HttpError, NotFoundError
from patchsight.pipeline.ingest.aliases import AliasGroup
from patchsight.pipeline.locator.baseline import Located, Variant, fixed_versions, locate
from patchsight.pipeline.pypi import PyPIClient
from patchsight.pipeline.week1 import wilson

SAMPLE_SIZE = 200
SEED = 20261118


class MaskedCase(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    advisory_ids: tuple[str, ...]
    package: str
    repo: str
    fixed: tuple[str, ...]
    truth: tuple[str, ...]  # the linked fix commits, as the advisories give them


class MaskedSample(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    seed: int
    snapshot_sha256: str
    eligible: int
    cases: tuple[MaskedCase, ...]


def eligible_case(
    group: AliasGroup, by_id: dict[str, Any], github: GitHubClient, pypi: PyPIClient
) -> MaskedCase | None:
    """A vulnerability the locator can be scored on: one package, a fixed version, and fix
    commits linked on a repository the package's PyPI metadata declares."""
    packages = sorted({p.name for i in group.advisory_ids for p in by_id[i].packages})
    if len(packages) != 1:
        return None
    package = packages[0]
    advisories = [by_id[i] for i in group.advisory_ids]
    fixed = sorted({str(v) for a in advisories for v in fixed_versions(a, package)})
    if not fixed:
        return None
    declared = set()
    for repo in pypi.declared_github_repos(package) or ():
        try:
            declared.add(github.canonical_repo(repo))
        except NotFoundError:
            continue
    truth: dict[str, None] = {}
    repo_of_truth = None
    for advisory in advisories:
        for c in advisory.fix_candidates:
            if c.kind != "github_commit" or not c.repo or not c.commit:
                continue
            try:
                repo = github.canonical_repo(c.repo)
            except (NotFoundError, HttpError):
                continue
            if repo in declared:
                truth.setdefault(c.commit.lower(), None)
                repo_of_truth = repo
    if not truth or repo_of_truth is None:
        return None
    return MaskedCase(
        vulnerability=group.key, advisory_ids=group.advisory_ids, package=package,
        repo=repo_of_truth, fixed=tuple(fixed), truth=tuple(truth),
    )  # fmt: skip


def draw(
    groups: Sequence[AliasGroup],
    by_id: dict[str, Any],
    github: GitHubClient,
    pypi: PyPIClient,
    snapshot_sha256: str,
    size: int = SAMPLE_SIZE,
    seed: int = SEED,
) -> MaskedSample:
    """Shuffle every vulnerability with a linked commit, then keep the first ``size``
    that are eligible. Deterministic for a snapshot and a seed."""
    with_commits = sorted(
        (
            g
            for g in groups
            if any(
                c.kind == "github_commit" for i in g.advisory_ids for c in by_id[i].fix_candidates
            )
        ),
        key=lambda g: g.key,
    )
    random.Random(seed).shuffle(with_commits)  # noqa: S311 - a reproducible sample, not a secret
    cases: list[MaskedCase] = []
    for group in with_commits:
        if (case := eligible_case(group, by_id, github, pypi)) is not None:
            cases.append(case)
            if len(cases) == size:
                break
    return MaskedSample(
        name="masked-v1", seed=seed, snapshot_sha256=snapshot_sha256,
        eligible=len(with_commits), cases=tuple(cases),
    )  # fmt: skip


def same_commit(located: str, linked: str) -> bool:
    """Linked SHAs can be abbreviated; a located one is always full."""
    a, b = located.lower(), linked.lower()
    return len(b) >= 7 and (a.startswith(b) or b.startswith(a))


class CaseResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    package: str
    located: Located
    outcome: str  # exact, wrong, abstained
    # For a wrong commit: whether a linked one was between the same two tags.
    linked_in_range: bool | None = None


def score(case: MaskedCase, located: Located) -> CaseResult:
    if located.commit is None:
        outcome = "abstained"
    elif any(same_commit(located.commit, t) for t in case.truth):
        outcome = "exact"
    else:
        outcome = "wrong"
    return CaseResult(
        vulnerability=case.vulnerability, package=case.package, located=located, outcome=outcome
    )


def run(
    sample: MaskedSample,
    by_id: dict[str, Any],
    github: GitHubClient,
    pypi: PyPIClient,
    variant: Variant,
) -> list[CaseResult]:
    results = []
    for case in sample.cases:
        advisories = [by_id[i] for i in case.advisory_ids if i in by_id]
        ids = sorted({*case.advisory_ids, *(x for a in advisories for x in a.aliases)})
        located = locate(ids, advisories, case.package, github, pypi, variant)
        result = score(case, located)
        if result.outcome == "wrong" and located.repo and located.base and located.head:
            # The same comparison the locator read, so it comes from the cache.
            data = github.http.get_json(
                f"/repos/{located.repo}/compare/{located.base}...{located.head}"
            )
            compared = [str(c["sha"]) for c in data.get("commits") or []]
            inside = any(same_commit(c, t) for c in compared for t in case.truth)
            result = result.model_copy(update={"linked_in_range": inside})
        results.append(result)
    return results


class VariantScores(BaseModel):
    model_config = ConfigDict(frozen=True)

    variant: str
    cases: int
    exact: int
    wrong: int
    abstained: int
    abstain_reasons: dict[str, int]
    wrong_linked_in_range: int  # wrong, though a linked commit was between the same tags
    median_requests: float

    def rate(self, n: int) -> tuple[float, float, float]:
        share = wilson(n, self.cases)
        return share.share, share.ci95_low, share.ci95_high


def summarise(variant: str, results: Sequence[CaseResult]) -> VariantScores:
    outcomes = Counter(r.outcome for r in results)
    return VariantScores(
        variant=variant,
        cases=len(results),
        exact=outcomes["exact"],
        wrong=outcomes["wrong"],
        abstained=outcomes["abstained"],
        abstain_reasons=dict(
            Counter(r.located.reason for r in results if r.outcome == "abstained").most_common()
        ),
        wrong_linked_in_range=sum(1 for r in results if r.linked_in_range),
        median_requests=statistics.median(r.located.requests for r in results) if results else 0,
    )


class LocatorReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    sample: str
    seed: int
    snapshot_sha256: str
    eligible: int
    scores: tuple[VariantScores, ...]
    results: dict[str, tuple[CaseResult, ...]]


def render_markdown(report: LocatorReport) -> str:
    def pct(scores: VariantScores, n: int) -> str:
        rate, low, high = scores.rate(n)
        return f"{rate:.1%} ({n}; {low:.1%} to {high:.1%})"

    cases = report.scores[0].cases if report.scores else 0
    lines = [
        "# Fix-commit locator: masked evaluation",
        "",
        "Generated by `python -m patchsight.pipeline locator-eval`; do not edit by hand.",
        "",
        f"- **Sample `{report.sample}`:** {cases} vulnerabilities drawn with seed {report.seed} "
        f"from the {report.eligible:,} whose advisories link a GitHub fix commit (OSV snapshot "
        f"`{report.snapshot_sha256[:12]}…`). Each has one package, a fixed version, and fix "
        "commits on a repository its PyPI metadata declares.",
        "- **Masked:** the locator never sees the advisory's references or git ranges. It "
        "reads the package's PyPI metadata, the repository's tags and the commits between "
        "the last vulnerable and the first fixed release.",
        "- **Exact** means the located commit is one the advisories link. A fix backported "
        "to another branch, or split over several commits, counts as wrong if the linked one "
        "is not chosen, so the wrong-commit rate is an upper bound.",
        "",
        "| Variant | Exact SHA | Wrong commit | Abstained | Lookups (median) |",
        "|---|---:|---:|---:|---:|",
        *(
            f"| `{s.variant}` | {pct(s, s.exact)} | {pct(s, s.wrong)} | {pct(s, s.abstained)} "
            f"| {s.median_requests:g} |"
            for s in report.scores
        ),
        "| **Target** (the agent) | 70% or more | 5% or less | — | — |",
        "",
        "Rates have Wilson 95% intervals. *Lookups* counts the GitHub and PyPI requests "
        "each vulnerability needs, answered from the cache or not. `baseline` is the "
        "proposal's: the first commit between the tags whose message says CVE, security or "
        "fix. `ranked` prefers a message "
        'naming the advisory\'s own IDs, then security words, then "fix".',
        "",
        "## Wrong commits",
        "",
        "| Variant | Wrong | A linked commit was between the same tags | It was not |",
        "|---|---:|---:|---:|",
        *(
            f"| `{s.variant}` | {s.wrong} | {s.wrong_linked_in_range} | "
            f"{s.wrong - s.wrong_linked_in_range} |"
            for s in report.scores
        ),
        "",
        "In the first case the right commit was in view and another was chosen: a better "
        "choice could fix it. In the second, the comparison itself missed the fix, for "
        "example because it was made on another branch: only another search could.",
        "",
        "## Why it abstained",
        "",
        "| Reason | " + " | ".join(f"`{s.variant}`" for s in report.scores) + " |",
        "|---|" + "---:|" * len(report.scores),
    ]
    reasons = sorted({k for s in report.scores for k in s.abstain_reasons})
    lines += [
        f"| {r} | " + " | ".join(str(s.abstain_reasons.get(r, 0)) for s in report.scores) + " |"
        for r in reasons
    ]
    lines.append("")
    return "\n".join(lines)


class AgentSummary(BaseModel):
    """How the agent got its answers, beyond the scores."""

    model_config = ConfigDict(frozen=True)

    model: str
    prompt_version: str
    outcomes: dict[str, int]  # found, discarded, abstained, step cap, invalid, error
    median_steps: float
    median_tool_calls: float
    prompt_tokens: int
    completion_tokens: int
    calls: int
    cached_calls: int


def run_agent(
    sample: MaskedSample,
    by_id: dict[str, Any],
    github: GitHubClient,
    pypi: PyPIClient,
    llm: Any,
    model: Any,
    template: Any,
    transcripts: Any = None,
    limit: int | None = None,
) -> tuple[list[CaseResult], list[Any]]:
    """The agent on the masked sample: scored results, and each run's summary. With
    ``transcripts`` (a directory), each case's message list is saved there."""
    from patchsight.pipeline.locator import agent

    results: list[CaseResult] = []
    runs: list[agent.AgentRun] = []
    for case in sample.cases[:limit]:
        advisories = [by_id[i] for i in case.advisory_ids if i in by_id]
        task = agent.build_task(case.vulnerability, advisories, case.package, github, pypi)
        run, messages = agent.locate(task, llm, model, template, github)
        runs.append(run)
        located = Located(repo=case.repo, commit=run.commit, reason=run.reason,
                          requests=run.tool_calls)  # fmt: skip
        results.append(score(case, located))
        if transcripts is not None:
            transcripts.mkdir(parents=True, exist_ok=True)
            path = transcripts / f"{case.vulnerability}.json"
            payload = {"run": run.model_dump(mode="json"), "messages": messages}
            path.write_text(json.dumps(payload, indent=1, ensure_ascii=False), "utf-8")
    return results, runs


def summarise_agent(runs: Sequence[Any], model: str, prompt_version: str) -> AgentSummary:
    return AgentSummary(
        model=model,
        prompt_version=prompt_version,
        outcomes=dict(Counter(r.outcome for r in runs).most_common()),
        median_steps=statistics.median(r.steps for r in runs) if runs else 0,
        median_tool_calls=statistics.median(r.tool_calls for r in runs) if runs else 0,
        prompt_tokens=sum(r.prompt_tokens for r in runs),
        completion_tokens=sum(r.completion_tokens for r in runs),
        calls=sum(r.calls for r in runs),
        cached_calls=sum(r.cached_calls for r in runs),
    )


def render_agent_markdown(
    report: LocatorReport, agent: AgentSummary, baselines: Sequence[VariantScores]
) -> str:
    """The agent's report, with the heuristic baselines from the committed report beside it."""

    def pct(scores: VariantScores, n: int) -> str:
        rate, low, high = scores.rate(n)
        return f"{rate:.1%} ({n}; {low:.1%} to {high:.1%})"

    mine = report.scores[0]
    lines = [
        "# Fix-commit locator agent: masked evaluation",
        "",
        "Generated by `python -m patchsight.pipeline locator-agent-eval`; do not edit by hand.",
        "",
        f"- **Sample `{report.sample}`:** the same {mine.cases} vulnerabilities as the "
        f"[baseline report](locator-{report.sample}.md), fix links hidden.",
        f"- **Agent:** `{agent.model}`, prompt `{agent.prompt_version}`, at most 8 steps, four "
        "read-only tools, the package's own repositories only (rule 8). Answers are kept only if "
        "the commit exists, sits between the release tags and touches non-test Python source.",
        "",
        "| Locator | Exact SHA | Wrong commit | Abstained |",
        "|---|---:|---:|---:|",
        *(
            f"| {label} | {pct(s, s.exact)} | {pct(s, s.wrong)} | {pct(s, s.abstained)} |"
            for label, s in (
                *((f"`{b.variant}` (heuristic)", b) for b in baselines),
                ("**agent**", mine),
            )
        ),
        "| **Target** | 70% or more | 5% or less | — |",
        "",
        "## How the agent ended",
        "",
        "| Outcome | Vulnerabilities |",
        "|---|---:|",
        *(f"| {k} | {v} |" for k, v in agent.outcomes.items()),
        "",
        f"- Steps per vulnerability: median {agent.median_steps:g}; tool calls: median "
        f"{agent.median_tool_calls:g}",
        f"- Tokens: {agent.prompt_tokens:,} in, {agent.completion_tokens:,} out, over "
        f"{agent.calls:,} model calls ({agent.cached_calls:,} from the cache)",
        "",
        "*Discarded* answers failed the verifier, so they count as abstentions above, never as "
        "found commits.",
        "",
    ]
    return "\n".join(lines)
