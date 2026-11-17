"""Failure causes for extraction errors (proposal §10, "failure analysis").

Every missed true symbol (a false negative) gets exactly one cause, checked in this order:

* ``not_changed``: the fix did not change the symbol, so no patch-based method can find it
  (the ceiling ChangedFuncs also hits: "vulnerable function unchanged, callee changed");
* ``name_format``: the fix changed a definition that matches the symbol only on a dotted
  boundary (GoVulnDB's ``decryptTicket`` for the method ``Conn.decryptTicket``): a naming
  difference in the ground truth, not a missed function;
* ``dead_letter``: the symbol was changed, but the extraction failed;
* ``truncated``: changed, but dropped from the prompt to fit the token budget;
* ``model_missed``: shown to the model and judged not vulnerable.

Every false positive is either ``name_format`` (it matches a true symbol on a dotted
boundary) or ``model_false_positive``.

A report-level miss (no true symbol found: the safety metric) is attributed to its most
actionable cause: a shown-but-missed symbol first, then truncation, then the rest.

Not separated: "the fix adds a new helper". The replay data does not record which side of
the diff a candidate comes from, so such cases fall under ``model_false_positive``.
"""

from collections import Counter
from collections.abc import Mapping, Set

from pydantic import BaseModel, ConfigDict

from patchsight.eval.safety import lenient_match

MISS_CAUSES = ("not_changed", "name_format", "dead_letter", "truncated", "model_missed")
REPORT_MISS_ORDER = ("model_missed", "truncated", "dead_letter", "name_format", "not_changed")
VALID = frozenset({"ok", "repaired"})


class ReportInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    truth: frozenset[str]
    changed: frozenset[str]  # every changed function (ChangedFuncs)
    shown: frozenset[str]  # the candidates the prompt kept
    status: str
    predicted: frozenset[str]


class FailureBreakdown(BaseModel):
    model_config = ConfigDict(frozen=True)

    reports: int
    truth_symbols: int
    false_negatives: dict[str, int]
    false_positives: dict[str, int]
    report_misses: dict[str, int]
    examples: dict[str, tuple[str, ...]]  # cause -> report IDs (sorted)


def miss_cause(symbol: str, report: ReportInput) -> str:
    if symbol not in report.changed:
        if any(lenient_match(c, symbol) for c in report.changed):
            return "name_format"
        return "not_changed"
    if report.status not in VALID:
        return "dead_letter"
    if symbol not in report.shown:
        return "truncated"
    return "model_missed"


def breakdown(reports: Mapping[str, ReportInput]) -> FailureBreakdown:
    negatives: Counter[str] = Counter()
    positives: Counter[str] = Counter()
    misses: Counter[str] = Counter()
    examples: dict[str, set[str]] = {}
    total = 0
    for rid, report in sorted(reports.items()):
        total += len(report.truth)
        causes = {miss_cause(s, report) for s in report.truth - report.predicted}
        for symbol in report.truth - report.predicted:
            cause = miss_cause(symbol, report)
            negatives[cause] += 1
            examples.setdefault(cause, set()).add(rid)
        for symbol in report.predicted - report.truth:
            cause = (
                "name_format"
                if any(lenient_match(symbol, t) for t in report.truth)
                else "model_false_positive"
            )
            positives[cause] += 1
            examples.setdefault(f"fp:{cause}", set()).add(rid)
        if report.truth and not report.truth & report.predicted:
            misses[next(c for c in REPORT_MISS_ORDER if c in causes)] += 1
    return FailureBreakdown(
        reports=len(reports),
        truth_symbols=total,
        false_negatives={c: negatives[c] for c in MISS_CAUSES},
        false_positives={c: positives[c] for c in ("name_format", "model_false_positive")},
        report_misses={c: misses[c] for c in REPORT_MISS_ORDER},
        examples={k: tuple(sorted(v)) for k, v in sorted(examples.items())},
    )


def as_inputs(
    truth: Mapping[str, Set[str]],
    changed: Mapping[str, Set[str]],
    shown: Mapping[str, Set[str]],
    status: Mapping[str, str],
    predicted: Mapping[str, Set[str]],
) -> dict[str, ReportInput]:
    return {
        r: ReportInput(
            truth=frozenset(truth[r]),
            changed=frozenset(changed.get(r, set())),
            shown=frozenset(shown.get(r, set())),
            status=status.get(r, "dead_letter"),
            predicted=frozenset(predicted.get(r, set())),
        )
        for r in truth
    }
