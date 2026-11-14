"""Check a random sample of fix candidates against GitHub: are they really fixes?

This is the condition attached to passing the Week 1 gate. A link to a commit is only a
*candidate*. A vulnerability counts as having a real fix only when a candidate:

1. resolves on GitHub (a commit, a merged pull request or a tag comparison);
2. sits on the package's own repository, as declared in its PyPI metadata or an OSV
   ``GIT`` range (renames followed); and
3. changes at least one non-test source file.

These are necessary conditions checked by code, with no LLM and no hand labelling. They
do not prove a commit is *the* fix; whether the right functions changed is measured later
against labelled data.
"""

import math
import random
import statistics
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.diffs.github import ChangeSet, GitHubClient
from patchsight.pipeline.diffs.paths import classify_path
from patchsight.pipeline.http import HttpError, NotFoundError, RateLimitError
from patchsight.pipeline.ingest.aliases import AliasGroup
from patchsight.pipeline.ingest.osv import Advisory
from patchsight.pipeline.ingest.references import FixCandidate
from patchsight.pipeline.pypi import PyPIClient
from patchsight.pipeline.week1 import GATE_THRESHOLD, GITHUB_KINDS, Share, wilson

CandidateStatus = Literal["resolved", "not_found", "unmerged", "error"]
Outcome = Literal[
    "fix_on_package_repo",
    "fix_repo_unconfirmed",
    "non_source_only",
    "other_repo_only",
    "unmerged_pr_only",
    "unresolvable",
]
OUTCOME_ORDER: tuple[Outcome, ...] = (
    "fix_on_package_repo",
    "fix_repo_unconfirmed",
    "non_source_only",
    "other_repo_only",
    "unmerged_pr_only",
    "unresolvable",
)
Verdict = Literal["met", "inconclusive", "not_met"]


class CandidateCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str
    url: str
    status: CandidateStatus
    repo: str | None = None
    on_package_repo: bool | None = None
    files: int = 0
    python_files: int = 0
    native_files: int = 0
    other_source_files: int = 0
    truncated: bool = False
    error: str | None = None

    @property
    def source_files(self) -> int:
        return self.python_files + self.native_files + self.other_source_files


class GroupCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    advisory_ids: tuple[str, ...]
    packages: tuple[str, ...]
    package_repos: tuple[str, ...]
    outcome: Outcome
    fix_touches_python: bool
    candidates: tuple[CandidateCheck, ...]


class Estimate(BaseModel):
    model_config = ConfigDict(frozen=True)

    share: float
    low: float
    high: float


class FixSampleReport(BaseModel):
    as_of: date
    seed: int
    vulnerabilities: int
    population: int
    gate_share: float
    sample_size: int
    outcomes: dict[str, int]
    real_fix_strict: Share
    real_fix_lenient: Share
    estimated_share_strict: Estimate
    estimated_share_lenient: Estimate
    verdict: Verdict
    fixes_touching_python: Share
    files_per_fix_median: float
    files_per_fix_p90: float
    truncated_fixes: int
    candidates_checked: int
    candidate_status: dict[str, int]
    groups: tuple[GroupCheck, ...]


def _count(change: ChangeSet) -> dict[str, int]:
    kinds = Counter(classify_path(f.filename) for f in change.files)
    return {
        "files": len(change.files),
        "python_files": kinds["python"],
        "native_files": kinds["native"],
        "other_source_files": kinds["other_source"],
    }


def check_candidate(
    github: GitHubClient, candidate: FixCandidate, package_repos: frozenset[str]
) -> CandidateCheck:
    """Resolve one GitHub candidate. Rate-limit errors propagate and stop the run."""
    base = {"kind": candidate.kind, "url": candidate.url}
    repo = candidate.repo or ""
    try:
        if candidate.kind == "github_commit" and candidate.commit:
            change = github.commit(repo, candidate.commit)
        elif candidate.kind == "github_pull" and candidate.number is not None:
            pull = github.pull(repo, candidate.number)
            if not pull.merged:
                return CandidateCheck(**base, status="unmerged", repo=pull.repo)
            change = github.pull_files(repo, candidate.number)
        elif candidate.kind == "github_compare" and candidate.base and candidate.head:
            change = github.compare(repo, candidate.base, candidate.head)
        else:
            return CandidateCheck(**base, status="error", error="not a GitHub candidate")
    except RateLimitError:
        raise
    except NotFoundError:
        return CandidateCheck(**base, status="not_found")
    except (HttpError, KeyError, ValueError) as error:
        return CandidateCheck(**base, status="error", error=f"{type(error).__name__}: {error}")
    on_repo = (change.repo in package_repos) if package_repos else None
    return CandidateCheck(
        **base,
        status="resolved",
        repo=change.repo,
        on_package_repo=on_repo,
        truncated=change.truncated,
        **_count(change),
    )


def classify_group(checks: Sequence[CandidateCheck]) -> Outcome:
    """The best outcome among a vulnerability's candidates (see ``OUTCOME_ORDER``)."""
    found: set[Outcome] = set()
    for check in checks:
        if check.status == "resolved":
            if check.on_package_repo is False:
                found.add("other_repo_only")
            elif check.source_files == 0:
                found.add("non_source_only")
            elif check.on_package_repo:
                found.add("fix_on_package_repo")
            else:
                found.add("fix_repo_unconfirmed")
        elif check.status == "unmerged":
            found.add("unmerged_pr_only")
        else:
            found.add("unresolvable")
    return next(o for o in OUTCOME_ORDER if o in found)


def package_repos(
    group: AliasGroup, by_id: dict[str, Advisory], github: GitHubClient, pypi: PyPIClient
) -> tuple[tuple[str, ...], frozenset[str]]:
    """The group's package names, and their canonical GitHub repositories."""
    packages = sorted({p.name for i in group.advisory_ids for p in by_id[i].packages})
    declared: set[str] = set()
    for package in packages:
        declared.update(pypi.declared_github_repos(package) or ())
    for advisory_id in group.advisory_ids:
        for candidate in by_id[advisory_id].fix_candidates:
            if candidate.origin == "git_range" and candidate.kind == "github_commit":
                declared.add(candidate.repo or "")
    canonical: set[str] = set()
    for repo in sorted(r for r in declared if r):
        try:
            canonical.add(github.canonical_repo(repo))
        except NotFoundError:
            continue
    return tuple(packages), frozenset(canonical)


def check_group(
    group: AliasGroup, by_id: dict[str, Advisory], github: GitHubClient, pypi: PyPIClient
) -> GroupCheck:
    packages, repos = package_repos(group, by_id, github, pypi)
    seen: set[tuple[str, str | None, str | None, int | None]] = set()
    checks = []
    for advisory_id in group.advisory_ids:
        for candidate in by_id[advisory_id].fix_candidates:
            identity = (candidate.kind, candidate.repo, candidate.commit, candidate.number)
            if candidate.kind not in GITHUB_KINDS or identity in seen:
                continue
            seen.add(identity)
            checks.append(check_candidate(github, candidate, repos))
    outcome = classify_group(checks)
    fixes = [c for c in checks if c.status == "resolved" and c.on_package_repo and c.source_files]
    return GroupCheck(
        key=group.key,
        advisory_ids=group.advisory_ids,
        packages=packages,
        package_repos=tuple(sorted(repos)),
        outcome=outcome,
        fix_touches_python=any(c.python_files for c in fixes),
        candidates=tuple(checks),
    )


def draw_sample(groups: Iterable[AliasGroup], size: int, seed: int) -> list[AliasGroup]:
    """A seeded random sample, drawn from groups sorted by key so it is reproducible."""
    ordered = sorted(groups, key=lambda g: g.key)
    return random.Random(seed).sample(ordered, min(size, len(ordered)))  # noqa: S311


def _scaled(gate_share: float, s: Share) -> Estimate:
    return Estimate(
        share=gate_share * s.share, low=gate_share * s.ci95_low, high=gate_share * s.ci95_high
    )


def build_report(
    checks: Sequence[GroupCheck],
    *,
    as_of: date,
    seed: int,
    vulnerabilities: int,
    population: int,
) -> FixSampleReport:
    n = len(checks)
    outcomes = Counter(c.outcome for c in checks)
    strict = wilson(outcomes["fix_on_package_repo"], n)
    lenient = wilson(outcomes["fix_on_package_repo"] + outcomes["fix_repo_unconfirmed"], n)
    gate_share = population / vulnerabilities if vulnerabilities else 0.0
    est_strict, est_lenient = _scaled(gate_share, strict), _scaled(gate_share, lenient)
    if est_strict.share >= GATE_THRESHOLD:
        verdict: Verdict = "met"
    elif est_lenient.share >= GATE_THRESHOLD:
        verdict = "inconclusive"
    else:
        verdict = "not_met"

    fixed = [c for c in checks if c.outcome == "fix_on_package_repo"]
    sizes = sorted(
        max(x.files for x in c.candidates if x.status == "resolved" and x.on_package_repo)
        for c in fixed
    )
    p90 = float(sizes[min(len(sizes) - 1, math.ceil(0.9 * len(sizes)) - 1)]) if sizes else 0.0
    all_candidates = [x for c in checks for x in c.candidates]
    return FixSampleReport(
        as_of=as_of,
        seed=seed,
        vulnerabilities=vulnerabilities,
        population=population,
        gate_share=gate_share,
        sample_size=n,
        outcomes={o: outcomes[o] for o in OUTCOME_ORDER},
        real_fix_strict=strict,
        real_fix_lenient=lenient,
        estimated_share_strict=est_strict,
        estimated_share_lenient=est_lenient,
        verdict=verdict,
        fixes_touching_python=wilson(sum(c.fix_touches_python for c in fixed), len(fixed)),
        files_per_fix_median=float(statistics.median(sizes)) if sizes else 0.0,
        files_per_fix_p90=p90,
        truncated_fixes=sum(
            any(x.truncated for x in c.candidates if x.on_package_repo) for c in fixed
        ),
        candidates_checked=len(all_candidates),
        candidate_status=dict(sorted(Counter(x.status for x in all_candidates).items())),
        groups=tuple(checks),
    )


_OUTCOME_TEXT: dict[str, str] = {
    "fix_on_package_repo": "Resolves on the package's own repo and changes non-test source",
    "fix_repo_unconfirmed": "Changes non-test source; package repo not declared anywhere",
    "non_source_only": "Resolves, but changes only tests, docs or metadata",
    "other_repo_only": "Resolves, but only on repos that are not the package's",
    "unmerged_pr_only": "Only an unmerged pull request",
    "unresolvable": "No candidate resolves (deleted, private or malformed)",
}


def _pct(s: Share) -> str:
    return f"{s.share:.1%} ({s.count} / {s.total}; 95% CI {s.ci95_low:.1%} to {s.ci95_high:.1%})"


def _est(e: Estimate) -> str:
    return f"{e.share:.1%} (95% CI {e.low:.1%} to {e.high:.1%})"


def render_markdown(report: FixSampleReport, manifest_lines: Sequence[str]) -> str:
    verdict_text = {
        "met": "**Condition met.** The real fix share is above the 40% threshold, so the "
        "fix-commit locator agent stays optional.",
        "inconclusive": "**Inconclusive.** Only the lenient estimate clears 40%; the owner "
        "decides whether to promote the fix-commit locator agent.",
        "not_met": "**Condition not met.** The real fix share is below 40%, so the fix-commit "
        "locator agent becomes essential (proposal §15).",
    }[report.verdict]
    rows = [f"| {_OUTCOME_TEXT[o]} | {report.outcomes[o]} |" for o in OUTCOME_ORDER]
    return "\n".join(
        [
            "# Fix-candidate sample check",
            "",
            f"The condition attached to the Week 1 gate. Snapshot of {report.as_of.isoformat()}; "
            "generated by `python -m patchsight.pipeline fix-sample`; do not edit by hand.",
            "",
            "## Sources",
            "",
            *manifest_lines,
            "",
            "Advisory data: OSV.dev, the GitHub Advisory Database and the PyPA Advisory "
            "Database (all CC BY 4.0). Repository data: the GitHub REST API and PyPI "
            "metadata. This report holds counts only; no third-party code.",
            "",
            "## Result",
            "",
            verdict_text,
            "",
            f"- Population: {report.population:,} of {report.vulnerabilities:,} vulnerabilities "
            f"have a GitHub fix candidate ({report.gate_share:.1%}, the Week 1 gate metric).",
            f"- Random sample: {report.sample_size} of them, seed {report.seed}.",
            f"- **Strict:** a real fix on the package's own repo: {_pct(report.real_fix_strict)}.",
            f"- **Lenient:** also counting fixes whose package repo is not declared: "
            f"{_pct(report.real_fix_lenient)}.",
            "",
            "Estimated share of *all* PyPI vulnerabilities with a real fix commit "
            "(gate metric times sample share; the gate metric's own ±1.1-point interval is "
            "ignored):",
            "",
            f"- Strict: **{_est(report.estimated_share_strict)}**",
            f"- Lenient: {_est(report.estimated_share_lenient)}",
            "",
            "## Outcomes",
            "",
            "Each vulnerability gets the best outcome among its candidates.",
            "",
            "| Outcome | Vulnerabilities |",
            "|---|---|",
            *rows,
            "",
            f"Candidates checked: {report.candidates_checked} "
            f"({', '.join(f'{k} {v}' for k, v in report.candidate_status.items())}).",
            "",
            "## What the real fixes look like",
            "",
            f"- Fixes that change Python source (what tree-sitter maps to functions): "
            f"{_pct(report.fixes_touching_python)}. The rest change only native code "
            "(C, Rust and so on) or templates and scripts, so they fall back to *unknown*.",
            f"- Files changed per fix, including tests and docs: median "
            f"{report.files_per_fix_median:.0f}, p90 {report.files_per_fix_p90:.0f}.",
            f"- Fixes whose file list GitHub truncated: {report.truncated_fixes}.",
            "",
            "## Limits of this check",
            "",
            "- These are necessary conditions, not proof. A commit on the right repo that "
            "changes source may still be a refactor rather than the fix; that is measured "
            "against labelled data later.",
            "- A package whose metadata names no GitHub repo and has no OSV GIT range lands "
            "in *repo not declared*, even when the candidate is correct.",
            "",
        ]
    )
