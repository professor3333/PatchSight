"""Parity between two runs of the same prompt on the same reports.

This is the quantisation parity check (proposal §7, §11): the self-hosted 4-bit model
against the hosted model, before trusting backfill output. It answers three questions:

* **Reliability:** which reports each run failed to answer (dead letters).
* **Quality:** precision, recall and F1 of each run on the reports *both* answered, and the
  F1 difference with a paired bootstrap that resamples reports.
* **Agreement:** how many answers are identical, and where they differ, whether one run's
  set contains the other's. A run that only ever adds symbols is more inclusive, which costs
  precision but never recall.
"""

import random
from collections.abc import Mapping, Set

from pydantic import BaseModel, ConfigDict

from patchsight.eval.metrics import Interval, SetScores, _counts, _percentile, _prf, score

# Outcome statuses that count as a valid answer. Anything else (dead letter, no candidates)
# leaves the report out of the paired comparison.
VALID = frozenset({"ok", "repaired"})
BOOTSTRAP = 5000
SEED = 20261116

# A run's answers: report ID -> vulnerable set, or None when the run has no valid answer.
Answers = Mapping[str, Set[str] | None]


class ParityScores(BaseModel):
    model_config = ConfigDict(frozen=True)

    reports: int
    reference_failed: tuple[str, ...]
    candidate_failed: tuple[str, ...]
    paired: int
    reference: SetScores
    candidate: SetScores
    f1_difference: float  # reference minus candidate
    f1_difference_ci95: Interval
    identical: int
    candidate_adds_only: int  # differing reports where the candidate's set strictly contains
    candidate_drops_only: int  # differing reports where the candidate's set is strictly inside
    both_add_and_drop: int
    differing: tuple[str, ...]


def parity(
    reference: Answers,
    candidate: Answers,
    truth: Mapping[str, Set[str]],
    bootstrap: int = BOOTSTRAP,
    seed: int = SEED,
) -> ParityScores:
    """Compare two runs over the reports in ``truth``."""
    reports = sorted(truth)
    ref_failed = tuple(r for r in reports if reference.get(r) is None)
    cand_failed = tuple(r for r in reports if candidate.get(r) is None)
    paired = [r for r in reports if reference.get(r) is not None and candidate.get(r) is not None]
    ref = {r: set(reference[r] or ()) for r in paired}
    cand = {r: set(candidate[r] or ()) for r in paired}
    paired_truth = {r: truth[r] for r in paired}

    ref_counts = [_counts(ref[r], truth[r]) for r in paired]
    cand_counts = [_counts(cand[r], truth[r]) for r in paired]

    def f1(indices: list[int]) -> float:
        a = _prf(*(sum(getattr(ref_counts[i], k) for i in indices) for k in ("tp", "fp", "fn")))
        b = _prf(*(sum(getattr(cand_counts[i], k) for i in indices) for k in ("tp", "fp", "fn")))
        return a[2] - b[2]

    everything = list(range(len(paired)))
    rng = random.Random(seed)  # noqa: S311 - statistical resampling, not security
    draws = [
        f1([rng.randrange(len(paired)) for _ in paired]) for _ in range(bootstrap if paired else 0)
    ]
    differing = [r for r in paired if ref[r] != cand[r]]
    return ParityScores(
        reports=len(reports),
        reference_failed=ref_failed,
        candidate_failed=cand_failed,
        paired=len(paired),
        reference=score(ref, paired_truth),
        candidate=score(cand, paired_truth),
        f1_difference=f1(everything) if paired else 0.0,
        f1_difference_ci95=Interval(
            low=_percentile(draws, 0.025) if draws else 0.0,
            high=_percentile(draws, 0.975) if draws else 0.0,
        ),
        identical=len(paired) - len(differing),
        candidate_adds_only=sum(cand[r] > ref[r] for r in differing),
        candidate_drops_only=sum(cand[r] < ref[r] for r in differing),
        both_add_and_drop=sum(not (cand[r] > ref[r] or cand[r] < ref[r]) for r in differing),
        differing=tuple(differing),
    )
