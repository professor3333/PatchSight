"""Group advisories that describe the same vulnerability.

The same vulnerability usually appears several times in the PyPI dump, for example as a
GHSA record and a PYSEC record that alias each other or share a CVE. Counting and
extraction work per group, so it is done once per vulnerability, not once per record.
"""

from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.ingest.osv import Advisory


class AliasGroup(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    advisory_ids: tuple[str, ...]
    identifiers: tuple[str, ...]


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            low, high = sorted((root_a, root_b))
            self.parent[high] = low


def alias_groups(advisories: Iterable[Advisory]) -> list[AliasGroup]:
    """Group advisories connected by any shared identifier. Independent of input order.

    The group key is the smallest advisory ID in the group, so it is deterministic.
    """
    union = _UnionFind()
    advisory_ids: set[str] = set()
    for advisory in advisories:
        advisory_ids.add(advisory.id)
        union.find(advisory.id)
        for alias in advisory.aliases:
            union.union(advisory.id, alias)

    members: dict[str, list[str]] = {}
    for identifier in union.parent:
        members.setdefault(union.find(identifier), []).append(identifier)

    groups = []
    for identifiers in members.values():
        ids = sorted(i for i in identifiers if i in advisory_ids)
        if ids:
            groups.append(
                AliasGroup(
                    key=ids[0], advisory_ids=tuple(ids), identifiers=tuple(sorted(identifiers))
                )
            )
    return sorted(groups, key=lambda group: group.key)


def first_published(group: AliasGroup, by_id: dict[str, Advisory]) -> datetime | None:
    """The earliest ``published`` timestamp among the group's advisories."""
    dates = [d for i in group.advisory_ids if (d := by_id[i].published) is not None]
    return min(dates) if dates else None
