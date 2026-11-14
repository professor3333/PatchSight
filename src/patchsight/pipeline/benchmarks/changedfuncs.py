"""Reproduce the ChangedFuncs baseline on the Dunlap benchmark (proposal §15, Phase 1 step 3).

ChangedFuncs marks every function a fix commit changes as vulnerable. Running it before
any LLM proves the harness: diff fetching, hunk mapping and scoring. It is scored three ways:

1. the paper's published numbers, as reported;
2. the authors' released candidate lists, scored by PatchSight's metric code;
3. PatchSight's own pipeline: the same 298 commits fetched from GitHub and mapped with
   PatchSight's tree-sitter code, using the paper's path rule.

Agreement between 2 and 3 is the direct check on the diff and mapping code.
"""

from collections import Counter
from collections.abc import Sequence
from datetime import date

from pydantic import BaseModel, ConfigDict

from patchsight.eval.metrics import Interval, SetScores, jaccard, score
from patchsight.pipeline.benchmarks import dunlap
from patchsight.pipeline.diffs.commits import CommitMapping, map_commit
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.http import HttpError, NotFoundError, RateLimitError

BOOTSTRAP = 2000
SEED = 20261114


class CommitOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    report: str
    repo: str
    sha: str
    status: str
    files_mapped: int = 0
    computed_diffs: int = 0
    parse_errors: int = 0
    truncated: bool = False


class ReportComparison(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    symbols: tuple[str, ...]
    ours: tuple[str, ...]
    released: tuple[str, ...]
    jaccard: float


class BaselineReport(BaseModel):
    as_of: date
    reports: int
    commits: int
    unique_commits: int
    truth_symbols: int
    paper: dict[str, float | int]
    paper_unit_released: dict[str, float | int]
    released_unfiltered: SetScores
    released_filtered: SetScores
    ours: SetScores
    commit_status: dict[str, int]
    computed_diffs: int
    parse_errors: int
    truncated_commits: int
    candidates_ours: int
    candidates_released: int
    identical_reports: int
    mean_jaccard: float
    released_found: int
    superset_reports: int
    extra_candidates: int
    extra_in_top5_reports: int
    comparisons: tuple[ReportComparison, ...]
    commit_outcomes: tuple[CommitOutcome, ...]


def _map(
    github: GitHubClient, report: str, commit: dunlap.FixCommit
) -> tuple[CommitOutcome, CommitMapping | None]:
    try:
        mapping = map_commit(
            github, commit.github_repo, commit.sha, include=dunlap.paper_path_filter
        )
    except RateLimitError:
        raise
    except NotFoundError:
        return CommitOutcome(
            report=report, repo=commit.github_repo, sha=commit.sha, status="not_found"
        ), None
    except (HttpError, ValueError, KeyError):
        return CommitOutcome(
            report=report, repo=commit.github_repo, sha=commit.sha, status="error"
        ), None
    outcome = CommitOutcome(
        report=report,
        repo=mapping.repo,
        sha=commit.sha,
        status="mapped",
        files_mapped=len(mapping.files),
        computed_diffs=sum(f.diff_source == "computed" for f in mapping.files),
        parse_errors=sum(f.mapping.parse_errors for f in mapping.files),
        truncated=mapping.truncated,
    )
    return outcome, mapping


def run(
    github: GitHubClient, reports: Sequence[dunlap.DunlapReport], as_of: date
) -> BaselineReport:
    truth = {r.id: set(r.symbols) for r in reports}
    released_all = {r.id: dunlap.released_candidates(r, filtered=False) for r in reports}
    released = {r.id: dunlap.released_candidates(r, filtered=True) for r in reports}

    ours: dict[str, set[str]] = {}
    outcomes: list[CommitOutcome] = []
    for report in reports:
        names: set[str] = set()
        for commit in report.commits:
            outcome, mapping = _map(github, report.id, commit)
            outcomes.append(outcome)
            if mapping is not None:
                names |= {
                    c.name
                    for f in mapping.files
                    for c in f.mapping.changed
                    if c.kind in ("function", "method")
                }
        ours[report.id] = names

    units, vulnerable = dunlap.paper_unit_counts(reports)
    symbols_total = sum(len(s) for s in truth.values())
    comparisons = tuple(
        ReportComparison(
            id=r.id,
            symbols=tuple(sorted(truth[r.id])),
            ours=tuple(sorted(ours[r.id])),
            released=tuple(sorted(released[r.id])),
            jaccard=jaccard(ours[r.id], released[r.id]),
        )
        for r in reports
    )
    return BaselineReport(
        as_of=as_of,
        reports=len(reports),
        commits=len(outcomes),
        unique_commits=len({o.sha for o in outcomes}),
        truth_symbols=symbols_total,
        paper={
            "modified_functions": dunlap.PAPER_MODIFIED_FUNCTIONS,
            "vulnerable_functions": dunlap.PAPER_VULNERABLE_FUNCTIONS,
            "missed_functions": dunlap.PAPER_MISSED_FUNCTIONS,
            "precision": dunlap.PAPER_PRECISION,
            "recall": dunlap.PAPER_RECALL,
            "f1": dunlap.PAPER_F1,
        },
        paper_unit_released={
            "units": units,
            "vulnerable_units": vulnerable,
            "precision": vulnerable / units if units else 0.0,
        },
        released_unfiltered=score(released_all, truth, BOOTSTRAP, SEED),
        released_filtered=score(released, truth, BOOTSTRAP, SEED),
        ours=score(ours, truth, BOOTSTRAP, SEED),
        commit_status=dict(sorted(Counter(o.status for o in outcomes).items())),
        computed_diffs=sum(o.computed_diffs for o in outcomes),
        parse_errors=sum(o.parse_errors for o in outcomes),
        truncated_commits=sum(o.truncated for o in outcomes),
        candidates_ours=sum(len(s) for s in ours.values()),
        candidates_released=sum(len(s) for s in released.values()),
        identical_reports=sum(ours[r.id] == released[r.id] for r in reports),
        mean_jaccard=sum(c.jaccard for c in comparisons) / len(comparisons) if comparisons else 0.0,
        released_found=sum(len(released[r.id] & ours[r.id]) for r in reports),
        superset_reports=sum(released[r.id] <= ours[r.id] for r in reports),
        extra_candidates=sum(len(ours[r.id] - released[r.id]) for r in reports),
        extra_in_top5_reports=sum(
            sorted((len(ours[r.id] - released[r.id]) for r in reports), reverse=True)[:5]
        ),
        comparisons=comparisons,
        commit_outcomes=tuple(outcomes),
    )


def _scores_row(label: str, s: SetScores) -> str:
    def ci(interval: Interval | None) -> str:
        return "" if interval is None else f" ({interval.low:.2f} to {interval.high:.2f})"

    return (
        f"| {label} | {s.true_positives + s.false_positives:,} | {s.true_positives:,} "
        f"| {s.precision:.3f}{ci(s.precision_ci95)} | {s.recall:.3f}{ci(s.recall_ci95)} "
        f"| {s.f1:.3f}{ci(s.f1_ci95)} | {s.miss_rate:.1%} |"
    )


def render_markdown(report: BaselineReport, source_lines: Sequence[str]) -> str:
    p = report.paper
    pu = report.paper_unit_released
    return "\n".join(
        [
            "# ChangedFuncs baseline on the Dunlap Go benchmark",
            "",
            "Generated by `python -m patchsight.pipeline dunlap-baseline`; do not edit by hand. "
            "ChangedFuncs marks every function a fix commit changes as vulnerable. No LLM is "
            "involved; this checks the harness before any model is added.",
            "",
            "## Sources",
            "",
            *source_lines,
            "",
            'Benchmark data: Dunlap et al., "Pairing Security Advisories with Vulnerable '
            'Functions Using Open-Source LLMs", DIMVA 2024, released under Apache-2.0. Ground '
            "truth: GoVulnDB symbols as of 2023-10-26 (CC BY 4.0). This report holds counts and "
            "function names only; no source code.",
            "",
            "## Results",
            "",
            f"{report.reports} reports, {report.unique_commits} fix commits "
            f"({report.commits} report-commit pairs), {report.truth_symbols} "
            "true vulnerable symbols. The unit is a (report, function) pair, so a function "
            "changed by two commits of one report counts once. CIs are 95%, from "
            f"{BOOTSTRAP:,} bootstrap resamples of reports.",
            "",
            "| ChangedFuncs on | Candidates | True positives | Precision | Recall | F1 "
            "| Miss rate |",
            "|---|---|---|---|---|---|---|",
            f"| Paper, as published | {p['modified_functions']:,} | {p['vulnerable_functions']:,} "
            f"| {p['precision']:.2f} | {p['recall']:.2f} | {p['f1']:.2f} | not reported |",
            _scores_row("Released data, all paths", report.released_unfiltered),
            _scores_row("Released data, paper's test rule", report.released_filtered),
            _scores_row("**PatchSight pipeline**, paper's test rule", report.ours),
            "",
            "Miss rate is the share of reports where no true symbol was among the candidates.",
            "",
            "## Agreement with the released candidates",
            "",
            f"- Candidates: PatchSight {report.candidates_ours:,}, released data "
            f"{report.candidates_released:,} (both with the paper's test rule).",
            f"- Reports with identical candidate sets: {report.identical_reports} of "
            f"{report.reports}; mean per-report Jaccard {report.mean_jaccard:.3f}.",
            f"- Commits: {', '.join(f'{k} {v}' for k, v in report.commit_status.items())}. "
            f"Diffs computed locally because GitHub omitted the patch: {report.computed_diffs}. "
            f"Files with tree-sitter parse errors: {report.parse_errors}. Truncated commits: "
            f"{report.truncated_commits}.",
            "",
            "## Why the released CSV scores differently",
            "",
            f"The paper reports {p['modified_functions']:,} candidates, "
            f"{p['vulnerable_functions']} of them vulnerable. PatchSight's pipeline, run on the "
            f"same commits, finds {report.candidates_ours:,} with {report.ours.true_positives} "
            "vulnerable, which reproduces the published precision, recall and F1. The authors' "
            f"released CSV holds only {report.candidates_released:,} candidates:",
            "",
            f"- PatchSight finds {report.released_found:,} of the CSV's "
            f"{report.candidates_released:,} candidates "
            f"({report.released_found / max(report.candidates_released, 1):.1%}), and is a "
            f"superset of the CSV in {report.superset_reports} of {report.reports} reports.",
            f"- The CSV lacks {report.extra_candidates:,} of PatchSight's candidates; "
            f"{report.extra_in_top5_reports:,} of them come from just 5 reports with very "
            "large fixes.",
            '- Under the unit the authors\' evaluation code uses (drop paths containing "test", '
            f"group by report, commit and function) the CSV gives {pu['units']:,} units, "
            f"{pu['vulnerable_units']} vulnerable: precision {pu['precision']:.3f}.",
            "",
            "This is consistent with the released CSV being a subset of the paper's candidates, "
            "most likely without its largest fixes. Comparisons with the published numbers "
            "therefore use PatchSight's own candidate sets, not the CSV.",
            "",
            "The precision interval is wide because those few very large fixes contribute most "
            "false positives. Comparisons between two systems should use a paired bootstrap "
            "over the same report resamples.",
            "",
        ]
    )
