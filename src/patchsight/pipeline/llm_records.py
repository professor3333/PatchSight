"""Database records from LLM extraction, with confidence tiers (ADR 0004, ADR 0005).

Every vulnerability starts from its fallback record (every changed definition). When the
extractor has a valid answer made from the same inputs:

* **high** confidence (both model families valid, prompt not truncated, the answers agree
  under ``subset``, and a public symbol is among them): the record holds the agreed symbols
  and both models' entry points;
* otherwise **low** confidence: every changed definition plus the entry points, so the
  record is never worse than the fallback at containing the vulnerable symbol.

An extractor answer that failed validation, or was made from different inputs (its
``input_hash`` no longer matches the advisory), leaves the fallback record unchanged.
"""

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from patchsight.db import Record, Symbol
from patchsight.eval.confidence import VALID, Answer, Decision, decide, is_public
from patchsight.pipeline.pypi_extract import PyPIExtraction


def load(path: Path) -> dict[str, PyPIExtraction]:
    """A pypi-extract JSONL file, keyed by vulnerability."""
    lines = path.read_text("utf-8").splitlines()
    loaded = (PyPIExtraction.model_validate_json(line) for line in lines if line.strip())
    return {e.vulnerability: e for e in loaded}


def needs_second_opinion(extraction: PyPIExtraction) -> bool:
    """Whether a second opinion could make this record high confidence (ADR 0004).

    It cannot when the extractor's own answer already fails a condition that does not
    depend on the second model: an invalid answer, a truncated prompt, an empty set, or
    no public symbol. Skipping those saves the second model's daily quota.
    """
    a = answer(extraction)
    names = a.vulnerable | a.entry_points
    return (
        a.status in VALID
        and not a.truncated
        and bool(a.vulnerable)
        and any(is_public(n, "python") for n in names)
    )


def answer(extraction: PyPIExtraction) -> Answer:
    outcome = extraction.outcome
    return Answer(
        status=outcome.status,
        vulnerable=frozenset(s.qualified_name for s in extraction.vulnerable_symbols),
        truncated=outcome.truncated,
        entry_points=frozenset(extraction.entry_points),
    )


def merge(
    fallback: Sequence[Record],
    primary: PyPIExtraction | None,
    secondary: PyPIExtraction | None,
) -> tuple[list[Record], str]:
    """The records for one vulnerability, and what happened (for the build report)."""
    if primary is None:
        return list(fallback), "fallback: no extraction"
    if any(r.input_hash != primary.input_hash for r in fallback):
        return list(fallback), "fallback: extraction made from older inputs"
    if primary.outcome.status not in VALID:
        return list(fallback), "fallback: extraction failed validation"
    if secondary is not None and secondary.input_hash != primary.input_hash:
        secondary = None  # a stale second opinion counts as none
    decision: Decision = decide(
        answer(primary), answer(secondary) if secondary else None, language="python"
    )
    valid_second = secondary is not None and secondary.outcome.status in VALID
    entry_points = set(primary.entry_points)
    if valid_second and secondary is not None:
        entry_points |= set(secondary.entry_points)
    symbols: tuple[Symbol, ...] | None = None  # None: keep the fallback set
    if decision.tier == "high" and secondary is not None:
        by_name: dict[str, Symbol] = {
            s.qualified_name: s
            for s in (*primary.vulnerable_symbols, *secondary.vulnerable_symbols)
        }
        symbols = tuple(by_name[name] for name in sorted(decision.agreed))
    records = [
        record.model_copy(
            update={
                "confidence": decision.tier,
                "source": "llm",
                "symbols": record.symbols if symbols is None else symbols,
                "entry_points": tuple(sorted(entry_points)),
                "model": primary.outcome.model,
                "prompt_version": primary.outcome.prompt_version,
                "truncated": primary.outcome.truncated,
                "second_opinion_model": secondary.outcome.model
                if valid_second and secondary
                else None,
                "tier_reason": decision.reason,
            }
        )
        for record in fallback
    ]
    return records, f"{decision.tier}: {decision.reason}"


def apply(
    records: Iterable[Record],
    primaries: Mapping[str, PyPIExtraction],
    secondaries: Mapping[str, PyPIExtraction],
) -> tuple[list[Record], dict[str, int]]:
    """Merge extraction into fallback records. Returns the records and outcome counts."""
    by_vulnerability: dict[str, list[Record]] = {}
    for record in records:
        by_vulnerability.setdefault(record.vulnerability, []).append(record)
    merged: list[Record] = []
    outcomes: Counter[str] = Counter()
    for vulnerability in sorted(by_vulnerability):
        result, outcome = merge(
            by_vulnerability[vulnerability],
            primaries.get(vulnerability),
            secondaries.get(vulnerability),
        )
        merged.extend(result)
        outcomes[outcome] += 1
    return merged, dict(sorted(outcomes.items()))
