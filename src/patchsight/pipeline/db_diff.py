"""Compare a shadow database with production, before a change is promoted (proposal §11).

A prompt or model change does not go straight into a release. Its database is built as a
*shadow* next to production, compared record by record, and a seeded sample of the changed
records is reviewed by hand. Only then is it promoted. This module makes the comparison and
draws the sample; the review itself is a person's.

A record is compared on what a scan or a reader of ``explain`` would see: confidence,
source, tier reason, models, prompt version, truncation, the inputs' hash, import roots,
symbols, entry points and the model's **picks** (the symbols with a rationale). In a
low-confidence record the symbols are every changed definition, so a prompt change usually
moves the picks, not the symbols.
"""

import random
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.db import Record, SymbolDatabase

SEED = 20261121
REVIEW = 20  # records a reviewer reads before a promotion

_SCALARS = (
    "confidence", "source", "tier_reason", "model", "second_opinion_model", "prompt_version",
    "truncated", "input_hash",
)  # fmt: skip


def _sets(record: Record) -> dict[str, frozenset[str]]:
    return {
        "symbols": frozenset(s.qualified_name for s in record.symbols),
        "entry_points": frozenset(record.entry_points),
        "picks": frozenset(e.qualified_name for e in record.evidence),
        "import_roots": frozenset(record.import_roots),
    }


class RecordChange(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    package: str
    kind: str  # added, removed or changed
    fields: tuple[str, ...]
    before: dict[str, str] = {}  # changed scalar fields, as text
    after: dict[str, str] = {}
    added: dict[str, tuple[str, ...]] = {}  # per set field
    removed: dict[str, tuple[str, ...]] = {}


def compare(before: Record | None, after: Record | None) -> RecordChange | None:
    if before is None and after is None:
        return None
    if before is None or after is None:
        record = after if after is not None else before
        if record is None:  # pragma: no cover - excluded above
            return None
        return RecordChange(
            vulnerability=record.vulnerability, package=record.package,
            kind="added" if before is None else "removed", fields=(),
        )  # fmt: skip
    fields: list[str] = []
    old: dict[str, str] = {}
    new: dict[str, str] = {}
    for name in _SCALARS:
        a, b = getattr(before, name), getattr(after, name)
        if a != b:
            fields.append(name)
            old[name], new[name] = str(a), str(b)
    added: dict[str, tuple[str, ...]] = {}
    removed: dict[str, tuple[str, ...]] = {}
    sets_before, sets_after = _sets(before), _sets(after)
    for name, a_set in sets_before.items():
        b_set = sets_after[name]
        if a_set != b_set:
            fields.append(name)
            if b_set - a_set:
                added[name] = tuple(sorted(b_set - a_set))
            if a_set - b_set:
                removed[name] = tuple(sorted(a_set - b_set))
    if not fields:
        return None
    return RecordChange(
        vulnerability=before.vulnerability, package=before.package, kind="changed",
        fields=tuple(fields), before=old, after=new, added=added, removed=removed,
    )  # fmt: skip


class DatabaseDiff(BaseModel):
    model_config = ConfigDict(frozen=True)

    production: str  # db_version
    shadow: str
    records_before: int
    records_after: int
    unchanged: int
    kinds: dict[str, int]
    fields: dict[str, int]  # changed records, per field
    changes: tuple[RecordChange, ...]
    review: tuple[str, ...]  # "vulnerability/package" keys of the review sample
    seed: int


def diff(production: Path, shadow: Path, review: int = REVIEW, seed: int = SEED) -> DatabaseDiff:
    old, new = SymbolDatabase(production), SymbolDatabase(shadow)
    try:
        before = {(r.vulnerability, r.package): r for r in old.all_records()}
        after = {(r.vulnerability, r.package): r for r in new.all_records()}
        versions = (old.meta.get("db_version", "?"), new.meta.get("db_version", "?"))
    finally:
        old.close()
        new.close()
    changes = [
        change for key in sorted(before.keys() | after.keys())
        if (change := compare(before.get(key), after.get(key))) is not None
    ]  # fmt: skip
    keys = [f"{c.vulnerability}/{c.package}" for c in changes]
    chosen = sorted(random.Random(seed).sample(keys, min(review, len(keys))))  # noqa: S311 - a reproducible review sample, not a secret
    return DatabaseDiff(
        production=versions[0], shadow=versions[1], records_before=len(before),
        records_after=len(after), unchanged=len(before.keys() & after.keys()) - sum(
            c.kind == "changed" for c in changes),
        kinds=dict(sorted(Counter(c.kind for c in changes).items())),
        fields=dict(sorted(Counter(f for c in changes for f in c.fields).items())),
        changes=tuple(changes), review=tuple(chosen), seed=seed,
    )  # fmt: skip


def _names(values: Sequence[str], limit: int = 6) -> str:
    shown = ", ".join(f"`{v}`" for v in values[:limit])
    return shown + (f" +{len(values) - limit}" if len(values) > limit else "")


def _describe(change: RecordChange) -> str:
    if change.kind != "changed":
        return change.kind

    def short(field: str, value: str) -> str:
        return value[:12] if field == "input_hash" else value

    parts = [
        f"{f}: {short(f, change.before[f])} → {short(f, change.after[f])}" for f in change.before
    ]
    parts += [f"{f} +{_names(v)}" for f, v in change.added.items()]
    parts += [f"{f} -{_names(v)}" for f, v in change.removed.items()]
    return "; ".join(parts)


def render_markdown(result: DatabaseDiff, purpose: str) -> str:
    r = result
    by_key = {f"{c.vulnerability}/{c.package}": c for c in r.changes}
    lines = [
        f"# Shadow database `{r.shadow}` against production `{r.production}`",
        "",
        "Generated by `python -m patchsight.pipeline db-diff`; the review columns are filled by "
        "hand. A change is promoted only after its shadow has been compared and the sample "
        "below reviewed.",
        "",
        f"- **The change:** {purpose}",
        f"- Records: {r.records_before:,} in production, {r.records_after:,} in the shadow; "
        f"{r.unchanged:,} unchanged",
        f"- Changed records: {', '.join(f'{k} {v:,}' for k, v in r.kinds.items()) or 'none'}",
        "",
        "## What changed, by field",
        "",
        "| Field | Records |",
        "|---|---:|",
        *(f"| {k} | {v:,} |" for k, v in r.fields.items()),
        "",
        f"## Review sample ({len(r.review)} of {len(r.changes)}, seed {r.seed})",
        "",
        "Read each record with `patchsight explain <id> --db <shadow>` and the fix commit, then "
        "mark it: **better**, **same** or **worse**, with a reason.",
        "",
        "| Record | Change | Verdict | Reason |",
        "|---|---|---|---|",
        *(f"| {key} | {_describe(by_key[key])} | | |" for key in r.review),
        "",
    ]
    return "\n".join(lines)
