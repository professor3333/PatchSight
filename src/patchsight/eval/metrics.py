"""Set-based extraction metrics over advisories (proposal §10).

The unit is a (report, symbol name) pair. For each report, predicted symbols are compared
with the true vulnerable symbols:

* true positive: predicted and true;
* false positive: predicted, not true;
* false negative: true, not predicted. This includes reports with no prediction at all.

Precision, recall and F1 are micro-averaged over all pairs. Confidence intervals come
from a bootstrap that resamples whole reports, not pairs, because symbols within one report
are correlated.
"""

import random
from collections.abc import Mapping, Set
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict

Predictions = Mapping[str, Set[str]]


class Interval(BaseModel):
    model_config = ConfigDict(frozen=True)

    low: float
    high: float


class SetScores(BaseModel):
    model_config = ConfigDict(frozen=True)

    reports: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    miss_rate: float
    exact_match: float
    precision_ci95: Interval | None = None
    recall_ci95: Interval | None = None
    f1_ci95: Interval | None = None


@dataclass(frozen=True)
class _Counts:
    tp: int
    fp: int
    fn: int
    missed: bool
    exact: bool


def _counts(predicted: Set[str], truth: Set[str]) -> _Counts:
    tp = len(predicted & truth)
    return _Counts(
        tp=tp,
        fp=len(predicted - truth),
        fn=len(truth - predicted),
        missed=bool(truth) and tp == 0,
        exact=predicted == truth,
    )


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    position = q * (len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def score(
    predicted: Predictions,
    truth: Predictions,
    bootstrap: int = 0,
    seed: int = 0,
) -> SetScores:
    """Score predictions for every report in ``truth``. Extra predicted reports are ignored."""
    reports = sorted(truth)
    per_report = [_counts(predicted.get(r, frozenset()), truth[r]) for r in reports]
    tp = sum(c.tp for c in per_report)
    fp = sum(c.fp for c in per_report)
    fn = sum(c.fn for c in per_report)
    precision, recall, f1 = _prf(tp, fp, fn)
    with_truth = [c for c, r in zip(per_report, reports, strict=True) if truth[r]]

    intervals: dict[str, Interval | None] = {
        "precision_ci95": None,
        "recall_ci95": None,
        "f1_ci95": None,
    }
    if bootstrap and per_report:
        rng = random.Random(seed)  # noqa: S311 - statistical resampling, not security
        samples: list[tuple[float, float, float]] = []
        for _ in range(bootstrap):
            draw = [per_report[rng.randrange(len(per_report))] for _ in per_report]
            samples.append(
                _prf(sum(c.tp for c in draw), sum(c.fp for c in draw), sum(c.fn for c in draw))
            )
        for index, key in enumerate(("precision_ci95", "recall_ci95", "f1_ci95")):
            values = [s[index] for s in samples]
            intervals[key] = Interval(
                low=_percentile(values, 0.025), high=_percentile(values, 0.975)
            )

    return SetScores(
        reports=len(reports),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        miss_rate=sum(c.missed for c in with_truth) / len(with_truth) if with_truth else 0.0,
        exact_match=sum(c.exact for c in per_report) / len(per_report) if per_report else 0.0,
        **intervals,
    )


def jaccard(a: Set[str], b: Set[str]) -> float:
    """Overlap of two sets; 1.0 when both are empty."""
    union = a | b
    return len(a & b) / len(union) if union else 1.0
