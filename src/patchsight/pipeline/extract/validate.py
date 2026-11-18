"""Deterministic checks on the model's answer. Nothing the model says is trusted unchecked.

* The JSON must match the schema.
* Every candidate gets exactly one judgement. Unknown IDs are counted as invented.
* Every vulnerable judgement cites at least one hunk, and every cited hunk must be shown
  under that candidate.
* Entry points survive only if they name a definition known from the fetched source:
  exactly, or, when ``dotted`` is on, by matching exactly one definition on a dotted boundary
  (``SetValue`` names ``Paved.SetValue``; ``yaml.load`` names ``load``). An ambiguous name is
  dropped. A resolved entry point is kept as the definition's own name.
"""

import json
from collections import Counter
from collections.abc import Set

from pydantic import BaseModel, ConfigDict, ValidationError

from patchsight.eval.safety import lenient_match
from patchsight.pipeline.extract.prompt import RenderedPrompt
from patchsight.pipeline.extract.schema import Extraction


class ValidationFailedError(ValueError):
    def __init__(self, errors: list[str], invented_ids: int) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors
        self.invented_ids = invented_ids


class ValidatedExtraction(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerable_ids: tuple[str, ...]
    rationales: dict[str, str]
    evidence: dict[str, tuple[str, ...]]
    entry_points: tuple[str, ...]
    entry_points_dropped: tuple[str, ...]


def resolve_entry_point(name: str, allowed: Set[str], dotted: bool) -> str | None:
    """The definition an entry point names, or None when it names none (or several)."""
    if name in allowed:
        return name
    if not dotted:
        return None
    matches = [d for d in allowed if lenient_match(name, d)]
    return matches[0] if len(matches) == 1 else None


def validate(
    content: str, prompt: RenderedPrompt, known_names: Set[str], dotted_entry_points: bool = False
) -> ValidatedExtraction:
    try:
        extraction = Extraction.model_validate(json.loads(content))
    except (json.JSONDecodeError, ValidationError) as error:
        raise ValidationFailedError([f"not valid JSON for the schema: {error}"[:300]], 0) from None

    owners = {c.id: set(c.hunk_ids) for c in prompt.candidates}
    errors: list[str] = []
    counts = Counter(item.candidate_id for item in extraction.items)
    invented = sorted(i for i in counts if i not in owners)
    if invented:
        errors.append(f"unknown candidate IDs: {', '.join(invented)}")
    duplicated = sorted(i for i, n in counts.items() if n > 1 and i in owners)
    if duplicated:
        errors.append(f"more than one item for: {', '.join(duplicated)}")
    missing = sorted((set(owners) - set(counts)), key=lambda x: int(x[1:]))
    if missing:
        errors.append(f"no item for: {', '.join(missing)}")

    for item in extraction.items:
        if item.candidate_id not in owners:
            continue
        if not item.rationale.strip():
            errors.append(f"{item.candidate_id}: empty rationale")
        foreign = [h for h in item.evidence_hunk_ids if h not in owners[item.candidate_id]]
        if foreign:
            errors.append(
                f"{item.candidate_id}: cites hunks not shown under it: {', '.join(foreign)}"
            )
        if item.is_vulnerable and not item.evidence_hunk_ids:
            errors.append(f"{item.candidate_id}: vulnerable but cites no hunk")
    if errors:
        raise ValidationFailedError(errors, len(invented))

    allowed = set(known_names) | {c.name for c in prompt.candidates}
    resolved = {
        e: resolve_entry_point(e, allowed, dotted_entry_points)
        for e in extraction.public_entry_points
    }
    kept = tuple(sorted({d for d in resolved.values() if d is not None}))
    dropped = tuple(sorted({e for e, d in resolved.items() if d is None}))
    judged = {item.candidate_id: item for item in extraction.items}
    return ValidatedExtraction(
        vulnerable_ids=tuple(c.id for c in prompt.candidates if judged[c.id].is_vulnerable),
        rationales={cid: item.rationale for cid, item in judged.items()},
        evidence={cid: tuple(item.evidence_hunk_ids) for cid, item in judged.items()},
        entry_points=kept,
        entry_points_dropped=dropped,
    )
