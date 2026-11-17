"""Incremental database update: rebuild only what changed (the core of the nightly run).

The previous database's ``builds`` ledger records every vulnerability its builder
considered, with the hash of the inputs extraction reads (ADR 0001). Against a new snapshot:

* **carried:** the hash is unchanged, so the vulnerability keeps its records exactly as they
  were, LLM tiers and evidence included, and its ledger entry;
* **rebuilt** (hash changed) or **new** (not in the ledger): built again as fallback records,
  and listed for extraction if they have a record;
* **removed:** in the ledger but no longer in the snapshot (withdrawn, or merged into another
  alias group), so it is dropped.

Aliases are always recomputed from the new snapshot, so a carried vulnerability picks up any
new alias. A database without a ledger cannot be updated; rebuild it with ``build-db``.
"""

from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

from patchsight.db import BuildEntry, Record, SymbolDatabase
from patchsight.pipeline.build_db import fallback_records, input_hash
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.ingest.aliases import AliasGroup
from patchsight.pipeline.ingest.osv import Advisory
from patchsight.pipeline.pypi import PyPIClient


class UpdateReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    previous_version: str
    db_version: str
    carried: int
    rebuilt: int
    new: int
    removed: int
    status: dict[str, int]  # build statuses of the rebuilt and new vulnerabilities
    to_extract: tuple[str, ...]  # rebuilt or new vulnerabilities that have a record


class NoLedgerError(RuntimeError):
    """The previous database has no builds ledger, so changes cannot be detected."""


def update(
    previous: SymbolDatabase,
    groups: Sequence[AliasGroup],
    by_id: dict[str, Advisory],
    github: GitHubClient,
    pypi: PyPIClient,
    db_version: str,
    now: datetime | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[Record], dict[str, str], list[BuildEntry], UpdateReport]:
    ledger = previous.build_ledger()
    if not ledger:
        raise NoLedgerError("the previous database has no builds ledger; run build-db instead")
    now = now or datetime.now(UTC)
    records: list[Record] = []
    aliases: dict[str, str] = {}
    builds: list[BuildEntry] = []
    statuses: Counter[str] = Counter()
    counts: Counter[str] = Counter()
    to_extract: list[str] = []
    ordered = sorted(groups, key=lambda g: g.key)
    changed = {
        g.key
        for g in ordered
        if (entry := ledger.get(g.key)) is None or entry.input_hash != input_hash(g, by_id)
    }
    done = 0
    for group in ordered:
        entry = ledger.get(group.key)
        if entry is not None and group.key not in changed:
            kept = previous.records_for(group.key)
            builds.append(entry)
            counts["carried"] += 1
        else:
            kept, outcome = fallback_records(group, by_id, github, pypi, now)
            builds.append(
                BuildEntry(
                    vulnerability=group.key, input_hash=outcome.input_hash, status=outcome.status
                )
            )
            counts["new" if entry is None else "rebuilt"] += 1
            statuses[outcome.status] += 1
            if kept:
                to_extract.append(group.key)
            done += 1
            if progress is not None:
                progress(done, len(changed))
        if kept:
            records.extend(kept)
            aliases.update(dict.fromkeys(group.identifiers, group.key))
    current = {g.key for g in ordered}
    report = UpdateReport(
        previous_version=previous.meta.get("db_version", "?"),
        db_version=db_version,
        carried=counts["carried"],
        rebuilt=counts["rebuilt"],
        new=counts["new"],
        removed=sum(1 for key in ledger if key not in current),
        status=dict(sorted(statuses.items())),
        to_extract=tuple(to_extract),
    )
    return records, aliases, builds, report
