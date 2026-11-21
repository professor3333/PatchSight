"""Database records from LLM extraction, with confidence tiers (ADR 0004, ADR 0005).

Every vulnerability starts from its fallback record (every changed definition). When the
extractor has a valid answer made from the same inputs:

* **high** confidence (both model families valid, prompt not truncated, the answers agree
  under ``subset``, and a public symbol is among them): the record holds the agreed symbols
  and both models' entry points;
* otherwise **low** confidence: every changed definition plus the entry points, so the
  record is never worse than the fallback at containing the vulnerable symbol.

An extractor answer made from different inputs (its ``input_hash`` no longer matches the
advisory) leaves the fallback record unchanged. One that failed (a dead letter, or no
candidates to judge) keeps the fallback symbols too, and its tier reason says which model and
prompt tried, so a nightly does not spend its quota on the same attempt again (ADR 0013).

**High confidence is withheld** (ADR 0008): the rule missed its safety target in its declared
test evaluation, so a record the rule would make high is kept low, with every changed
definition, and its tier reason says so. Lifting this takes a new ADR, not a flag.

A record that is already high confidence is never re-merged: it no longer stores every
changed definition, so a lower tier could not be rebuilt from it. ``merge`` can therefore run
again over a published database (``merge-llm``) as new extractions arrive.
"""

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.db import Record, Symbol, SymbolEvidence
from patchsight.eval.confidence import VALID, Answer, Decision, decide, is_public
from patchsight.pipeline.pypi_extract import PyPIExtraction

# ADR 0008: in the declared test evaluation (ADR 0004), 7.0% of high-confidence reports missed
# the vulnerable symbol, against a target of 2% or less. Until a revised rule meets the target
# on data not used to choose it, published databases hold no high-confidence records.
PUBLISH_HIGH = False
WITHHELD = "high confidence withheld (ADR 0008)"
FAILURES = {
    "dead_letter": "no valid answer after one repair",
    "no_candidates": "no changed definition to judge",
}


def _tried(model: str, prompt_version: str) -> str:
    return f"fallback: extraction by {model} (prompt {prompt_version}) failed"


def failed_note(model: str, prompt_version: str, status: str) -> str:
    """The tier reason of a fallback record whose extraction failed."""
    return f"{_tried(model, prompt_version)}: {FAILURES.get(status, status)}"


def attempted(record: Record, model: str, prompt_version: str) -> bool:
    """Whether this model and prompt already failed on the record's current inputs. A
    rebuilt record starts again without the note, so new inputs are always tried."""
    return record.source == "fallback" and (record.tier_reason or "").startswith(
        _tried(model, prompt_version)
    )


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
    publish_high: bool = PUBLISH_HIGH,
) -> tuple[list[Record], str]:
    """The records for one vulnerability, and what happened (for the build report)."""
    if any(r.confidence == "high" for r in fallback):
        return list(fallback), "kept: already high confidence"
    if primary is None:
        return list(fallback), "fallback: no extraction"
    if any(r.input_hash != primary.input_hash for r in fallback):
        return list(fallback), "fallback: extraction made from older inputs"
    if primary.outcome.status not in VALID:
        note = failed_note(
            primary.outcome.model, primary.outcome.prompt_version, primary.outcome.status
        )
        kept = [
            r.model_copy(update={"tier_reason": note}) if r.source == "fallback" else r
            for r in fallback
        ]
        return kept, "fallback: extraction failed validation"
    if secondary is not None and secondary.input_hash != primary.input_hash:
        secondary = None  # a stale second opinion counts as none
    decision: Decision = decide(
        answer(primary), answer(secondary) if secondary else None, language="python"
    )
    if decision.tier == "high" and not publish_high:
        decision = Decision(tier="low", reason=f"{WITHHELD}: {decision.reason}", agreed=frozenset())
    valid_second = secondary is not None and secondary.outcome.status in VALID
    entry_points = set(primary.entry_points)
    if valid_second and secondary is not None:
        entry_points |= set(secondary.entry_points)
    evidence: dict[str, SymbolEvidence] = {e.qualified_name: e for e in primary.evidence}
    if valid_second and secondary is not None:
        for item in secondary.evidence:
            evidence.setdefault(item.qualified_name, item)
    symbols: tuple[Symbol, ...] | None = None  # None: keep the fallback set
    if decision.tier == "high" and secondary is not None:
        by_name: dict[str, Symbol] = {
            s.qualified_name: s
            for s in (*primary.vulnerable_symbols, *secondary.vulnerable_symbols)
        }
        symbols = tuple(by_name[name] for name in sorted(decision.agreed))
        evidence = {k: v for k, v in evidence.items() if k in decision.agreed}
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
                "evidence": tuple(evidence[k] for k in sorted(evidence)),
            }
        )
        for record in fallback
    ]
    return records, f"{decision.tier}: {decision.reason}"


def apply(
    records: Iterable[Record],
    primaries: Mapping[str, PyPIExtraction],
    secondaries: Mapping[str, PyPIExtraction],
    publish_high: bool = PUBLISH_HIGH,
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
            publish_high,
        )
        merged.extend(result)
        outcomes[outcome] += 1
    return merged, dict(sorted(outcomes.items()))


class Picks(BaseModel):
    """How much of a database carries model picks (records whose source is the LLM)."""

    model_config = ConfigDict(frozen=True)

    vulnerabilities: int
    records: int


def picks(records: Iterable[Record]) -> Picks:
    chosen = [r for r in records if r.source == "llm"]
    return Picks(vulnerabilities=len({r.vulnerability for r in chosen}), records=len(chosen))


class MergeReport(BaseModel):
    """What one ``merge-llm`` run changed, for the release notes."""

    model_config = ConfigDict(frozen=True)

    previous_version: str
    db_version: str
    models: tuple[str, ...]  # extractor models whose answers were offered
    second_opinion_models: tuple[str, ...]
    prompt_versions: tuple[str, ...]
    before: Picks
    after: Picks
    tiers: dict[str, int]  # records by confidence, after the merge
    outcomes: dict[str, int]  # per vulnerability, as returned by apply


def merge_report(
    before: Sequence[Record],
    after: Sequence[Record],
    primaries: Mapping[str, PyPIExtraction],
    secondaries: Mapping[str, PyPIExtraction],
    outcomes: Mapping[str, int],
    previous_version: str,
    db_version: str,
) -> MergeReport:
    offered = [*primaries.values(), *secondaries.values()]
    return MergeReport(
        previous_version=previous_version,
        db_version=db_version,
        models=tuple(sorted({e.outcome.model for e in primaries.values()})),
        second_opinion_models=tuple(sorted({e.outcome.model for e in secondaries.values()})),
        prompt_versions=tuple(sorted({e.outcome.prompt_version for e in offered})),
        before=picks(before),
        after=picks(after),
        tiers=dict(sorted(Counter(r.confidence for r in after).items())),
        outcomes=dict(sorted(outcomes.items())),
    )
