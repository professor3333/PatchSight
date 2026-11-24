"""The proposal's success targets (§8), each against what was measured.

Every number comes from a committed report in ``docs/reports/``, or, for a target met by
construction, names the check that enforces it; none is typed in by hand. The
``scorecard`` command writes the table into ``docs/evaluation.md`` between two markers,
and a test regenerates it from the committed reports, so the page cannot drift from them.

Where a report exists for several databases, the newest published one counts; a shadow
database never does. On the Go holdout the entry-point variant that counts is the one
``configs/llm.toml`` runs (``validation.dotted_entry_points``).
"""

import json
import re
import statistics
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.eval.confidence import CHOSEN_RULE, TierScores
from patchsight.eval.holdout import TARGET as HIGH_MISS_TARGET
from patchsight.eval.holdout import HoldoutEvaluation, RuleResult
from patchsight.eval.metrics import SetScores
from patchsight.eval.panel import PanelReport
from patchsight.eval.reachability import FixtureRun
from patchsight.pipeline.benchmarks.extraction import BOOTSTRAP, ExtractionRun
from patchsight.pipeline.benchmarks.python_gold import DECLARED, GoldScores
from patchsight.pipeline.benchmarks.python_gold import NAME as GOLD
from patchsight.pipeline.locator.masked import LocatorReport
from patchsight.pipeline.operations import OperationsReport
from patchsight.pipeline.week1 import Share, wilson

REPORTS = Path("docs/reports")
PAGE = Path("docs/evaluation.md")
START, END = "<!-- scorecard:start -->", "<!-- scorecard:end -->"

EXTRACTOR = "extract-v1-qwen3.8-27b-q4km"  # Qwen3.8-27B, 4-bit, on Kaggle: the backfill's
SECOND = "extract-v1-gpt-oss-120b"
LABELS = {EXTRACTOR: "Qwen3.8-27B 4-bit", SECOND: "gpt-oss-120b"}
DUNLAP_TEST_TIERS = f"confidence-dunlap-test-{EXTRACTOR}-vs-{SECOND}"
HOLDOUT = f"holdout-go-holdout-v1-{EXTRACTOR}-vs-{SECOND}"

Status = Literal[
    "met", "met at the point estimate", "met by construction", "missed", "not measured yet"
]


class Row(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    threshold: str
    measured: str
    status: Status
    sources: tuple[str, ...]  # relative to docs/


class SplitRow(BaseModel):
    """Function-level extraction scores on one split, next to ChangedFuncs on the same."""

    model_config = ConfigDict(frozen=True)

    split: str
    scores: SetScores | None  # None: not measured yet
    changedfuncs_f1: float | None
    source: str


class Scorecard(BaseModel):
    model_config = ConfigDict(frozen=True)

    targets: tuple[Row, ...]
    splits: tuple[SplitRow, ...]


_DB_REPORT = re.compile(r"(?P<prefix>.+)-db-(?P<version>\d{4}(?:\.\d+)+)\.json")


def latest(reports: Path, prefix: str) -> Path:
    """The report on the newest published database: ``2026.11.18.1`` after ``2026.11.18``.
    Shadow databases (``…-shadow-<name>``) are never counted."""
    found = []
    for path in reports.glob(f"{prefix}-db-*.json"):
        match = _DB_REPORT.fullmatch(path.name)
        if match and match["prefix"] == prefix:
            found.append((tuple(int(p) for p in match["version"].split(".")), path))
    if not found:
        raise FileNotFoundError(f"no {prefix}-db-<version>.json in {reports}")
    return max(found)[1]


def _source(path: Path) -> str:
    return f"reports/{path.with_suffix('.md').name}"


def _share(share: Share) -> str:
    return f"{share.share:.1%} ({share.count:,} of {share.total:,})"


def _holdout(reports: Path, dotted: bool) -> RuleResult:
    holdout = HoldoutEvaluation.model_validate_json((reports / f"{HOLDOUT}.json").read_text())
    variant = "dotted" if dotted else "exact"
    return next(r for r in holdout.results if r.variant == variant)


def extraction_f1(reports: Path) -> Row:
    path = reports / f"extraction-dunlap-all-{EXTRACTOR}.json"
    s = ExtractionRun.model_validate_json(path.read_text()).extraction
    ci = s.f1_ci95
    measured = f"F1 {s.f1:.3f}" + (f" (95% CI {ci.low:.2f} to {ci.high:.2f})" if ci else "")
    status: Status = "missed"
    if s.f1 >= 0.66 and s.precision >= 0.60:
        status = "met" if ci is not None and ci.low >= 0.66 else "met at the point estimate"
    return Row(target="Extraction F1, Dunlap Go split", threshold="0.66 or more, P 0.60 or more",
               measured=f"{measured}, P {s.precision:.3f}", status=status,
               sources=(_source(path),))  # fmt: skip


def holdout_recall(reports: Path, dotted: bool) -> Row:
    path = reports / f"{HOLDOUT}.json"
    holdout = HoldoutEvaluation.model_validate_json(path.read_text())
    s = _holdout(reports, dotted).safety_overall
    measured = (f"{s.recall:.3f} ({s.truth_found:,} of {s.truth_symbols:,} labelled symbols); "
                f"ChangedFuncs {holdout.changedfuncs_safety.recall:.3f}")  # fmt: skip
    return Row(target="Recall after the fallback union, Go holdout", threshold="0.85 or more",
               measured=measured, status="met" if s.recall >= 0.85 else "missed",
               sources=(_source(path),))  # fmt: skip


def high_confidence_misses(reports: Path, dotted: bool) -> Row:
    tiers_path = reports / f"{DUNLAP_TEST_TIERS}.json"
    tiers = [TierScores.model_validate(t) for t in json.loads(tiers_path.read_text())]
    chosen = next(t for t in tiers if t.rule == CHOSEN_RULE and t.require_public and t.fallback)
    high = chosen.safety_high
    test = wilson(round(high.miss_rate * high.reports), high.reports)
    result = _holdout(reports, dotted)
    holdout = wilson(result.high_misses, result.high_reports)
    measured = "; ".join(
        f"{where} {_share(s)}, 95% CI {s.ci95_low:.1%} to {s.ci95_high:.1%}"
        for where, s in (("Dunlap test", test), ("Go holdout", holdout))
    )
    shares = (test, holdout)
    status: Status = "missed"
    if all(s.share <= HIGH_MISS_TARGET for s in shares):
        met = all(s.ci95_high <= HIGH_MISS_TARGET for s in shares)
        status = "met" if met else "met at the point estimate"
    return Row(target="Miss rate, high-confidence records", threshold="2% or less",
               measured=measured, status=status,
               sources=(_source(tiers_path), _source(reports / f"{HOLDOUT}.json")))  # fmt: skip


def python_gold(reports: Path) -> Row:
    path = reports / f"{GOLD}-eval.json"
    target, threshold = "Python gold set F1", "within 0.10 of the Go F1"
    if not path.exists():
        return Row(target=target, threshold=threshold, measured="—",
                   status="not measured yet", sources=("labelling-guideline.md",))  # fmt: skip
    scores = [GoldScores.model_validate(s) for s in json.loads(path.read_text())]
    gold = next(s for s in scores if s.system == "Extractor alone").strict.f1
    go_path = reports / f"extraction-dunlap-all-{EXTRACTOR}.json"
    go = ExtractionRun.model_validate_json(go_path.read_text()).extraction.f1
    return Row(target=target, threshold=threshold,
               measured=f"F1 {gold:.3f}; Go {go:.3f}, a gap of {abs(gold - go):.3f}",
               status="met" if abs(gold - go) <= 0.10 else "missed",
               sources=(_source(path), _source(go_path)))  # fmt: skip


def locator(reports: Path) -> Row:
    path = reports / "locator-masked-v1.json"
    scores = LocatorReport.model_validate_json(path.read_text()).scores
    names = {"baseline": "heuristic baseline", "ranked": "ranked heuristic"}
    measured = "; ".join(
        f"{names.get(s.variant, s.variant)} {s.exact / s.cases:.1%} exact, "
        f"{s.wrong / s.cases:.1%} wrong"
        for s in scores
    )
    met = any(s.exact / s.cases >= 0.70 and s.wrong / s.cases <= 0.05 for s in scores)
    return Row(target="Fix-commit locator, masked set",
               threshold="exact SHA 70% or more, wrong 5% or less",
               measured=f"{measured} (of {scores[0].cases} cases)",
               status="met" if met else "missed", sources=(_source(path),))  # fmt: skip


def schema_valid(reports: Path) -> Row:
    """Valid after one repair: every prompt sent, less the dead letters."""
    shares: list[tuple[str, Share]] = []
    sources = []
    for tag in (EXTRACTOR, SECOND):
        path = reports / f"extraction-dunlap-all-{tag}.json"
        status = ExtractionRun.model_validate_json(path.read_text()).status
        sent = sum(n for s, n in status.items() if s != "no_candidates")
        shares.append((f"{LABELS[tag]}, Dunlap", wilson(sent - status.get("dead_letter", 0), sent)))
        sources.append(_source(path))
    operations = reports / "operations.json"
    backfill = Counter[str]()
    for session in OperationsReport.model_validate_json(operations.read_text()).sessions:
        if session.mode == "pypi":
            backfill.update(session.status)
    sent = backfill.total()
    shares.append((f"{LABELS[EXTRACTOR]}, PyPI backfill",
                   wilson(sent - backfill["dead_letter"], sent)))  # fmt: skip
    sources.append(_source(operations))
    return Row(target="Schema-valid output after one retry", threshold="99% or more",
               measured="; ".join(f"{where} {_share(s)}" for where, s in shares),
               status="met" if all(s.share >= 0.99 for _, s in shares) else "missed",
               sources=tuple(sources))  # fmt: skip


def citations(root: Path) -> Row:
    bundles = sorted((root / "benchmarks" / "dunlap-v1").glob("extraction-*.json"))
    return Row(target="Citation accuracy after validation", threshold="100%",
               measured=f"100% of accepted answers: `make reproduce` re-validates the "
                        f"{len(bundles)} committed Dunlap answer sets on every push",
               status="met by construction",
               sources=("../src/patchsight/pipeline/extract/validate.py",))  # fmt: skip


def false_suppressions(reports: Path) -> Row:
    database_path = latest(reports, "reachability-fixtures")
    labelled_path = reports / "reachability-fixtures-labelled.json"
    runs = [FixtureRun.model_validate_json(p.read_text()) for p in (database_path, labelled_path)]
    calling = sum(o.calls for o in runs[0].outcomes)
    measured = "; ".join(
        f"{len(r.false_suppressions)} with "
        + ("the labelled records" if r.data == "labelled" else r.data)
        for r in runs
    )
    status: Status = "met" if all(not r.false_suppressions for r in runs) else "missed"
    return Row(target="False suppressions, reachability fixtures", threshold="0",
               measured=f"{measured} ({calling} of {len(runs[0].outcomes)} cases call)",
               status=status, sources=(_source(database_path), _source(labelled_path)))  # fmt: skip


def _panel(reports: Path) -> tuple[Path, PanelReport]:
    path = latest(reports, "panel")
    return path, PanelReport.model_validate_json(path.read_text())


def coverage(reports: Path) -> Row:
    path, panel = _panel(reports)
    share = wilson(panel.with_data, panel.alerts)
    return Row(target="Alerts with symbol data, 20-repository panel", threshold="50% or more",
               measured=f"{_share(share)} on database {panel.db_version}",
               status="met" if share.share >= 0.5 else "missed",
               sources=(_source(path),))  # fmt: skip


def latency(reports: Path) -> Row:
    path, panel = _panel(reports)
    p50, p95, scans = panel.latency(200)
    repositories = sum(r.dependencies >= 200 for r in panel.results)
    return Row(target="Scan time, 200-dependency repository, warm cache",
               threshold="p50 under 5 s, p95 under 15 s",
               measured=f"p50 {p50:.2f} s, p95 {p95:.2f} s ({scans} scans of {repositories} "
                        "repositories)",
               status="met" if scans and p50 < 5 and p95 < 15 else "missed",
               sources=(_source(path),))  # fmt: skip


def scan_tokens() -> Row:
    return Row(target="LLM tokens per scan", threshold="0",
               measured="0: the scanner cannot import the LLM client or the pipeline",
               status="met by construction",
               sources=("../tests/test_import_boundary.py",))  # fmt: skip


def prompt_tokens(reports: Path) -> Row:
    medians = []
    sources = []
    for benchmark, label in (("dunlap-all", "Dunlap"), ("go-holdout-v1", "Go holdout")):
        path = reports / f"extraction-{benchmark}-{EXTRACTOR}.json"
        run = ExtractionRun.model_validate_json(path.read_text())
        sent = [o.prompt_tokens for o in run.outcomes if o.calls]
        medians.append((label, statistics.median(sent), len(sent)))
        sources.append(_source(path))
    return Row(target="Input tokens per advisory, offline", threshold="median 6,000 or less",
               measured="; ".join(f"{label} median {m:,.0f} ({n} advisories)"
                                  for label, m, n in medians),
               status="met" if all(m <= 6000 for _, m, _ in medians) else "missed",
               sources=tuple(sources))  # fmt: skip


def nightly_dead_letters(reports: Path) -> Row:
    path = reports / "operations.json"
    outcomes = Counter[str]()
    nights = 0
    for night in OperationsReport.model_validate_json(path.read_text()).nightly:
        if night.extraction:
            nights += 1
            outcomes.update(night.extraction)
    target, threshold = "Nightly dead-letter rate after retries", "under 2%"
    if not nights:
        return Row(target=target, threshold=threshold, measured="—",
                   status="not measured yet", sources=(_source(path),))  # fmt: skip
    share = wilson(outcomes["dead_letter"], outcomes.total())
    return Row(target=target, threshold=threshold,
               measured=f"{_share(share)} over {nights} nights",
               status="met" if share.share < 0.02 else "missed",
               sources=(_source(path),))  # fmt: skip


def extraction_splits(reports: Path) -> list[SplitRow]:
    """The extractor on the three extraction splits the proposal names (§10)."""
    found = []
    benchmarks = {"dunlap-all": "Dunlap, all", "dunlap-dev": "Dunlap, dev",
                  "dunlap-test": "Dunlap, test", "go-holdout-v1": "Go holdout"}  # fmt: skip
    for benchmark, label in benchmarks.items():
        path = reports / f"extraction-{benchmark}-{EXTRACTOR}.json"
        run = ExtractionRun.model_validate_json(path.read_text())
        found.append(SplitRow(split=label, scores=run.extraction,
                              changedfuncs_f1=run.changedfuncs.f1,
                              source=_source(path)))  # fmt: skip
    gold = reports / f"{GOLD}-eval.json"
    label = f"Python gold set ({DECLARED} declared)"
    if gold.exists():
        scores = [GoldScores.model_validate(s) for s in json.loads(gold.read_text())]
        strict = next(s for s in scores if s.system == "Extractor alone").strict
        found.append(SplitRow(split=label, scores=strict, changedfuncs_f1=None,
                              source=_source(gold)))  # fmt: skip
    else:
        found.append(SplitRow(split=label, scores=None, changedfuncs_f1=None,
                              source="labelling-guideline.md"))  # fmt: skip
    return found


def build(root: Path, dotted: bool) -> Scorecard:
    """Every §8 target, in the proposal's order, and the extraction splits."""
    reports = root / REPORTS
    rows: list[Callable[[], Row]] = [
        lambda: extraction_f1(reports),
        lambda: holdout_recall(reports, dotted),
        lambda: high_confidence_misses(reports, dotted),
        lambda: python_gold(reports),
        lambda: locator(reports),
        lambda: schema_valid(reports),
        lambda: citations(root),
        lambda: false_suppressions(reports),
        lambda: coverage(reports),
        lambda: latency(reports),
        scan_tokens,
        lambda: prompt_tokens(reports),
        lambda: nightly_dead_letters(reports),
    ]
    return Scorecard(targets=tuple(row() for row in rows),
                     splits=tuple(extraction_splits(reports)))  # fmt: skip


def _link(source: str) -> str:
    name = Path(source).stem.replace(f"-vs-{SECOND}", "").replace(f"-{EXTRACTOR}", "")
    return f"[{name.replace(f'-{SECOND}', ', gpt-oss-120b')}]({source})"


def _split_line(row: SplitRow) -> str:
    link = _link(row.source)
    s = row.scores
    if s is None:
        return f"| {row.split} | — | — | — | — | — | — | not measured yet; {link} |"
    ci = s.f1_ci95
    f1 = f"**{s.f1:.3f}**" + (f" ({ci.low:.2f} to {ci.high:.2f})" if ci else "")
    changedfuncs = "—" if row.changedfuncs_f1 is None else f"{row.changedfuncs_f1:.3f}"
    return (f"| {row.split} | {s.reports} | {s.precision:.3f} | {s.recall:.3f} | {f1} | "
            f"{s.miss_rate:.1%} | {changedfuncs} | {link} |")  # fmt: skip


def render(card: Scorecard) -> str:
    rows = card.targets
    counts = Counter(r.status for r in rows)
    summary = ", ".join(f"{n} {status}" for status, n in sorted(counts.items()))
    lines = [
        START,
        "",
        "Generated by `python -m patchsight.pipeline scorecard` from the committed reports; "
        "do not edit by hand.",
        "",
        f"**{len(rows)} targets:** {summary}.",
        "",
        "| Target | Threshold | Measured | Result | Source |",
        "|---|---|---|---|---|",
        *(
            f"| {r.target} | {r.threshold} | {r.measured} | **{r.status}** | "
            f"{', '.join(_link(s) for s in r.sources)} |"
            for r in rows
        ),
        "",
        "### Extraction on each split",
        "",
        f"{LABELS[EXTRACTOR]} on Kaggle, scored by function. Intervals come from "
        f"{BOOTSTRAP:,} bootstrap resamples of whole advisories.",
        "",
        "| Split | Reports | Precision | Recall | F1 (95% CI) | Advisory miss rate | "
        "ChangedFuncs F1 | Source |",
        "|---|---:|---:|---:|---|---:|---:|---|",
        *(_split_line(row) for row in card.splits),
        "",
        END,
    ]
    return "\n".join(lines)


def fill(page: str, table: str) -> str:
    """The page with the text between the markers replaced."""
    start, end = page.find(START), page.find(END)
    if start < 0 or end < start:
        raise ValueError(f"the page has no {START} … {END} section")
    return page[:start] + table + page[end + len(END) :]
