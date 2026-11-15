"""Frozen evaluation splits.

A split divides a benchmark's reports into ``dev`` (used for prompt and model choices) and
``test`` (reported, never tuned on). Reports that share a fix commit are grouped first and
always land in the same split; otherwise the same diff would sit on both sides.

A split is written once to ``splits/`` and committed. Its SHA-256 is recorded in every
report built from it, and the loader refuses a file whose content does not match its own
hash, so a split cannot change silently.
"""

import hashlib
import json
import random
from collections.abc import Iterable, Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.benchmarks.dunlap import DunlapReport


class SplitError(RuntimeError):
    """A split file is missing, tampered with, or would be overwritten."""


class Split(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    benchmark: str
    method: str
    seed: int
    dev: tuple[str, ...]
    test: tuple[str, ...]

    def ids(self, part: str) -> frozenset[str]:
        if part == "dev":
            return frozenset(self.dev)
        if part == "test":
            return frozenset(self.test)
        if part == "all":
            return frozenset(self.dev) | frozenset(self.test)
        raise SplitError(f"unknown split part {part!r}; use dev, test or all")


class SplitFile(BaseModel):
    split: Split
    sha256: str


def _digest(split: Split) -> str:
    canonical = json.dumps(split.model_dump(mode="json"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def commit_groups(reports: Iterable[DunlapReport]) -> list[tuple[str, ...]]:
    """Reports connected through any shared fix commit, each group sorted, groups sorted."""
    parent: dict[str, str] = {}

    def find(item: str) -> str:
        parent.setdefault(item, item)
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    first_report: dict[str, str] = {}
    for report in reports:
        find(report.id)
        for commit in report.commits:
            owner = first_report.setdefault(commit.sha, report.id)
            a, b = find(owner), find(report.id)
            if a != b:
                parent[max(a, b)] = min(a, b)

    groups: dict[str, list[str]] = {}
    for report_id in parent:
        groups.setdefault(find(report_id), []).append(report_id)
    return sorted(tuple(sorted(g)) for g in groups.values())


def make_split(reports: Sequence[DunlapReport], name: str, dev_size: int, seed: int) -> Split:
    """Shuffle commit groups with ``seed`` and fill ``dev`` until it holds ``dev_size``
    reports (a group that would overshoot is skipped, so groups are never broken)."""
    groups = commit_groups(reports)
    random.Random(seed).shuffle(groups)  # noqa: S311 - reproducible sampling, not security
    dev: list[str] = []
    for group in groups:
        if len(dev) + len(group) <= dev_size:
            dev.extend(group)
        if len(dev) == dev_size:
            break
    dev_set = set(dev)
    test = [r.id for r in reports if r.id not in dev_set]
    return Split(
        name=name,
        benchmark="dunlap-dimva24",
        method=f"seeded shuffle of commit-sharing groups; dev filled to {dev_size} reports",
        seed=seed,
        dev=tuple(sorted(dev)),
        test=tuple(sorted(test)),
    )


def save_split(split: Split, path: Path) -> SplitFile:
    if path.exists():
        raise SplitError(f"{path} already exists; frozen splits are never overwritten")
    record = SplitFile(split=split, sha256=_digest(split))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return record


def load_split(path: Path) -> SplitFile:
    if not path.exists():
        raise SplitError(f"{path} does not exist; create it with dunlap-split")
    record = SplitFile.model_validate_json(path.read_text(encoding="utf-8"))
    if _digest(record.split) != record.sha256:
        raise SplitError(f"{path} does not match its recorded SHA-256; it was edited")
    return record
