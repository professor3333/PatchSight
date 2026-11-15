"""A product-relevant safety view of extraction results.

The benchmark metric (``eval.metrics``) compares names exactly and ignores entry points,
which keeps it comparable with Dunlap et al. The scanner behaves differently, in two ways:

* it matches **entry points** as well as the vulnerable functions themselves;
* the ground truth names functions inconsistently. Older GoVulnDB entries list
  ``decryptTicket`` for the method ``Conn.decryptTicket``, and models write package
  prefixes (``syscall.ForkExec``).

This view therefore counts *product symbols* (the vulnerable functions plus the validated
entry points) and matches names leniently, on a dotted boundary: ``a.b.c`` matches ``b.c``
and ``c``. Its miss rate answers the safety question: how often would the database hold
nothing that reaches the true vulnerable symbol?
"""

from collections.abc import Mapping, Set

from pydantic import BaseModel, ConfigDict


def lenient_match(predicted: str, truth: str) -> bool:
    return predicted == truth or predicted.endswith(f".{truth}") or truth.endswith(f".{predicted}")


class SafetyScores(BaseModel):
    model_config = ConfigDict(frozen=True)

    reports: int
    truth_symbols: int
    truth_found: int
    recall: float
    miss_rate: float


def safety(predicted: Mapping[str, Set[str]], truth: Mapping[str, Set[str]]) -> SafetyScores:
    """Recall over true symbols and the report-level miss rate, with lenient matching."""
    found = total = missed = with_truth = 0
    for report, symbols in truth.items():
        if not symbols:
            continue
        with_truth += 1
        guesses = predicted.get(report, set())
        hits = sum(any(lenient_match(p, t) for p in guesses) for t in symbols)
        found += hits
        total += len(symbols)
        missed += hits == 0
    return SafetyScores(
        reports=with_truth,
        truth_symbols=total,
        truth_found=found,
        recall=found / total if total else 0.0,
        miss_rate=missed / with_truth if with_truth else 0.0,
    )
