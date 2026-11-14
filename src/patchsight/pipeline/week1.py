"""Week 1 data gate: measure the PyPI advisory data before building on it (proposal §15).

Three questions decide the plan:

1. What share of PyPI vulnerabilities link a fix commit? Under about 40%, the fix-commit
   locator agent becomes essential.
2. What share already carry symbol data? This is the project's opening statistic.
3. How many new vulnerabilities arrive per day? This sizes the nightly LLM budget.

Counts are per vulnerability (alias group) unless stated, because one vulnerability often
appears as both a GHSA and a PYSEC record.
"""

import math
import statistics
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import date, datetime, timedelta

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.ingest.aliases import AliasGroup, alias_groups, first_published
from patchsight.pipeline.ingest.ghsa_repo import GhsaScan
from patchsight.pipeline.ingest.osv import Advisory, Excluded, Quarantined

GATE_THRESHOLD = 0.40
GITHUB_KINDS = frozenset({"github_commit", "github_pull", "github_compare"})
COMMIT_KINDS = frozenset({"github_commit", "gitlab_commit", "bitbucket_commit", "other_commit"})
# Proposal §7: ~6,000 input tokens per advisory against a 200,000-token daily cap per model.
TOKENS_PER_ADVISORY = 6_000
DAILY_TOKEN_CAP = 200_000


class Share(BaseModel):
    model_config = ConfigDict(frozen=True)

    count: int
    total: int
    share: float
    ci95_low: float
    ci95_high: float


class DailyRate(BaseModel):
    model_config = ConfigDict(frozen=True)

    days: int
    total: int
    mean: float
    median: float
    p90: float
    max: int


class Week1Report(BaseModel):
    as_of: date
    records_total: int
    records_by_source: dict[str, int]
    excluded: dict[str, int]
    quarantined: int
    quarantine_reasons: dict[str, int]
    advisories_in_scope: int
    in_scope_by_source: dict[str, int]
    vulnerabilities: int
    packages: int
    fix_link_any: Share
    fix_link_github: Share
    fix_link_github_commit: Share
    fix_link_strong: Share
    fix_link_by_kind: dict[str, int]
    records_with_fix_link_any: Share
    symbol_data_osv: Share
    symbol_data_osv_ids: tuple[str, ...]
    ghsa_repo: GhsaScan | None
    new_per_day_365: DailyRate
    new_per_day_90: DailyRate
    new_with_github_link_per_day_365: DailyRate
    modified_last_7_days: int
    modified_last_30_days: int
    advisories_per_day_per_model: int
    gate_metric: Share
    gate_passed: bool


def wilson(count: int, total: int, z: float = 1.959964) -> Share:
    """A proportion with its Wilson score 95% interval."""
    if total == 0:
        return Share(count=0, total=0, share=0.0, ci95_low=0.0, ci95_high=0.0)
    p = count / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return Share(
        count=count,
        total=total,
        share=p,
        # The Wilson interval always contains p; clamp away floating-point error at 0 and 1.
        ci95_low=max(0.0, min(p, centre - margin)),
        ci95_high=min(1.0, max(p, centre + margin)),
    )


def daily_rate(days_seen: Iterable[date], start: date, end: date) -> DailyRate:
    """Per-day counts over ``[start, end)``, including days with no arrivals."""
    counts = Counter(d for d in days_seen if start <= d < end)
    span = (end - start).days
    series = [counts.get(start + timedelta(days=i), 0) for i in range(span)]
    ordered = sorted(series)
    p90 = ordered[min(len(ordered) - 1, math.ceil(0.9 * len(ordered)) - 1)] if ordered else 0
    return DailyRate(
        days=span,
        total=sum(series),
        mean=statistics.fmean(series) if series else 0.0,
        median=statistics.median(series) if series else 0.0,
        p90=float(p90),
        max=max(series, default=0),
    )


def _group_has(group: AliasGroup, by_id: dict[str, Advisory], kinds: frozenset[str]) -> bool:
    return any(c.kind in kinds for i in group.advisory_ids for c in by_id[i].fix_candidates)


def _group_has_strong(group: AliasGroup, by_id: dict[str, Advisory]) -> bool:
    """A FIX-typed reference or a GIT range ``fixed`` commit, not just a WEB link."""
    return any(
        c.origin == "git_range" or c.reference_type == "FIX"
        for i in group.advisory_ids
        for c in by_id[i].fix_candidates
    )


def build_report(
    results: Sequence[Advisory | Excluded | Quarantined],
    as_of: datetime,
    ghsa_scan: GhsaScan | None = None,
) -> Week1Report:
    advisories = [r for r in results if isinstance(r, Advisory)]
    excluded = [r for r in results if isinstance(r, Excluded)]
    quarantined = [r for r in results if isinstance(r, Quarantined)]
    by_id = {a.id: a for a in advisories}
    groups = alias_groups(advisories)
    total_groups = len(groups)

    def share(predicate_kinds: frozenset[str]) -> Share:
        return wilson(sum(_group_has(g, by_id, predicate_kinds) for g in groups), total_groups)

    all_kinds = GITHUB_KINDS | COMMIT_KINDS | {"gitlab_merge_request"}
    kind_counts: Counter[str] = Counter()
    for group in groups:
        kinds = {c.kind for i in group.advisory_ids for c in by_id[i].fix_candidates}
        kind_counts.update(kinds)

    symbol_groups = [g for g in groups if any(by_id[i].symbol_hints for i in g.advisory_ids)]
    end = as_of.date()
    published = {g.key: first_published(g, by_id) for g in groups}
    new_days = [d.date() for d in published.values() if d is not None]
    github_days = [
        d.date()
        for g in groups
        if (d := published[g.key]) is not None and _group_has(g, by_id, GITHUB_KINDS)
    ]
    gate_metric = share(GITHUB_KINDS)
    return Week1Report(
        as_of=end,
        records_total=len(results),
        records_by_source=dict(
            sorted(
                Counter(
                    r.id.split("-", 1)[0] if not isinstance(r, Quarantined) else "unreadable"
                    for r in results
                ).items()
            )
        ),
        excluded=dict(sorted(Counter(r.reason for r in excluded).items())),
        quarantined=len(quarantined),
        quarantine_reasons=dict(Counter(q.reason for q in quarantined).most_common(10)),
        advisories_in_scope=len(advisories),
        in_scope_by_source=dict(sorted(Counter(a.source for a in advisories).items())),
        vulnerabilities=total_groups,
        packages=len({p.name for a in advisories for p in a.packages}),
        fix_link_any=share(all_kinds),
        fix_link_github=gate_metric,
        fix_link_github_commit=share(frozenset({"github_commit"})),
        fix_link_strong=wilson(sum(_group_has_strong(g, by_id) for g in groups), total_groups),
        fix_link_by_kind=dict(sorted(kind_counts.items())),
        records_with_fix_link_any=wilson(
            sum(bool(a.fix_candidates) for a in advisories), len(advisories)
        ),
        symbol_data_osv=wilson(len(symbol_groups), total_groups),
        symbol_data_osv_ids=tuple(i for g in symbol_groups for i in g.advisory_ids),
        ghsa_repo=ghsa_scan,
        new_per_day_365=daily_rate(new_days, end - timedelta(days=365), end),
        new_per_day_90=daily_rate(new_days, end - timedelta(days=90), end),
        new_with_github_link_per_day_365=daily_rate(github_days, end - timedelta(days=365), end),
        modified_last_7_days=sum(a.modified >= as_of - timedelta(days=7) for a in advisories),
        modified_last_30_days=sum(a.modified >= as_of - timedelta(days=30) for a in advisories),
        advisories_per_day_per_model=DAILY_TOKEN_CAP // TOKENS_PER_ADVISORY,
        gate_metric=gate_metric,
        gate_passed=gate_metric.share >= GATE_THRESHOLD,
    )


def _pct(s: Share) -> str:
    # Small shares need more decimals, or a handful of cases reads as "0.0%".
    fmt = ".2%" if 0 < s.share < 0.01 else ".1%"
    ci = f"95% CI {s.ci95_low:{fmt}} to {s.ci95_high:{fmt}}"
    return f"{s.share:{fmt}} ({s.count:,} / {s.total:,}; {ci})"


def _rate(r: DailyRate) -> str:
    stats = f"mean {r.mean:.1f}, median {r.median:.0f}, p90 {r.p90:.0f}, max {r.max}"
    return f"{stats} ({r.total:,} in {r.days} days)"


def render_markdown(report: Week1Report, manifest_lines: Sequence[str]) -> str:
    gate = "PASS" if report.gate_passed else "FAIL"
    lines = [
        "# Week 1 data gate",
        "",
        f"Measured on the OSV PyPI snapshot of {report.as_of.isoformat()}. "
        "Generated by `python -m patchsight.pipeline week1-report`; do not edit by hand.",
        "",
        "## Sources",
        "",
        *manifest_lines,
        "",
        "Advisory data: OSV.dev (CC BY 4.0), aggregating the GitHub Advisory Database "
        "(CC BY 4.0) and the PyPA Advisory Database (CC BY 4.0). This report contains "
        "counts derived from that data, not the data itself.",
        "",
        "## Gate result",
        "",
        f"**{gate}.** Share of PyPI vulnerabilities with at least one GitHub fix link "
        f"(commit, pull request or tag comparison): {_pct(report.gate_metric)}. "
        f"Threshold: {GATE_THRESHOLD:.0%}. Below it, the fix-commit locator agent becomes "
        "essential (proposal §15).",
        "",
        "This counts *candidate* links, so it is an upper bound. Only "
        f"{_pct(report.fix_link_strong)} carry an explicit fix signal (a FIX-typed "
        "reference or a GIT-range fixed commit); the rest are untyped links to commits or "
        "pull requests. How many candidates really are the fix is measured when the diffs "
        "are fetched.",
        "",
        "## Scope",
        "",
        f"- Records in the dump: {report.records_total:,} "
        f"({', '.join(f'{k} {v:,}' for k, v in report.records_by_source.items())})",
        f"- Excluded: {', '.join(f'{k} {v:,}' for k, v in report.excluded.items())}",
        f"- Quarantined as malformed: {report.quarantined:,}",
        f"- In-scope advisories: {report.advisories_in_scope:,} "
        f"({', '.join(f'{k} {v:,}' for k, v in report.in_scope_by_source.items())})",
        f"- Vulnerabilities after alias grouping: **{report.vulnerabilities:,}**, "
        f"across {report.packages:,} packages",
        "",
        "Malicious-package reports (`MAL-*`) are excluded: the whole package is malware, "
        "so there is no fix commit and no vulnerable function to find.",
        "",
        "## 1. Fix-commit links",
        "",
        "Per vulnerability (alias group):",
        "",
        f"- Any fix link, any host: {_pct(report.fix_link_any)}",
        f"- GitHub commit, PR or comparison (**gate metric**): {_pct(report.fix_link_github)}",
        f"- GitHub commit link specifically: {_pct(report.fix_link_github_commit)}",
        f"- Strong signal only (FIX-typed reference or GIT-range fixed commit): "
        f"{_pct(report.fix_link_strong)}",
        f"- Per record rather than per vulnerability, any host: "
        f"{_pct(report.records_with_fix_link_any)}",
        "",
        "Vulnerabilities by kind of link present (one vulnerability can have several):",
        "",
        "| Kind | Vulnerabilities |",
        "|---|---|",
        *(f"| `{k}` | {v:,} |" for k, v in report.fix_link_by_kind.items()),
        "",
        "A link is a *candidate*: whether it is on the package's own repository and is "
        "really the fix is checked when the diff is fetched. For reference, 78% of Go "
        "reports in Dunlap et al. had a patch link.",
        "",
        "## 2. Existing symbol data (the opening statistic)",
        "",
        f"- In the OSV dump (`ecosystem_specific.imports` or `affected_functions`): "
        f"{_pct(report.symbol_data_osv)}: {', '.join(report.symbol_data_osv_ids) or 'none'}",
    ]
    if report.ghsa_repo is not None:
        g = report.ghsa_repo
        lines.append(
            f"- In `github/advisory-database` itself: {len(g.with_symbol_data):,} of "
            f"{g.found:,} PyPI GHSA files checked carry symbol data "
            f"({len(g.missing)} expected file(s) not found at the publication-month path)"
        )
    lines += [
        "",
        "## 3. Arrival rate",
        "",
        "New vulnerabilities per day, by first publication across the alias group:",
        "",
        f"- Last 365 days: {_rate(report.new_per_day_365)}",
        f"- Last 90 days: {_rate(report.new_per_day_90)}",
        "- Last 365 days, with a GitHub fix link: "
        f"{_rate(report.new_with_github_link_per_day_365)}",
        "",
        f"Re-extraction pressure (lower bound, since each record shows only its latest "
        f"modification): {report.modified_last_7_days:,} in-scope advisories modified in "
        f"the last 7 days, {report.modified_last_30_days:,} in the last 30.",
        "",
        f"Budget check: at about {TOKENS_PER_ADVISORY:,} input tokens per advisory and a "
        f"{DAILY_TOKEN_CAP:,}-token daily cap, one model handles about "
        f"{report.advisories_per_day_per_model} advisories a day. These caps are reported "
        "by third parties and must be confirmed in the provider console.",
        "",
    ]
    return "\n".join(lines)
