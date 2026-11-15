import json
from pathlib import Path

import pytest

from patchsight.pipeline.benchmarks import dunlap, splits


def _report(report_id: str, *shas: str) -> dunlap.DunlapReport:
    return dunlap.DunlapReport(
        id=report_id,
        commits=tuple(dunlap.FixCommit(github_repo="o/r", sha=s, googlesource=False) for s in shas),
        symbols=frozenset({"F"}),
        released=(),
    )


REPORTS = [
    _report("GO-1", "a"),
    _report("GO-2", "b"),
    _report("GO-3", "c", "d"),
    _report("GO-4", "d"),  # shares d with GO-3
    _report("GO-5", "e"),  # shares e with GO-6, and GO-6 shares f with GO-7
    _report("GO-6", "e", "f"),
    _report("GO-7", "f"),
    *(_report(f"GO-{n}", f"s{n}") for n in range(8, 30)),
]


def test_commit_groups_follow_shared_commits_transitively() -> None:
    groups = splits.commit_groups(REPORTS)
    assert ("GO-3", "GO-4") in groups
    assert ("GO-5", "GO-6", "GO-7") in groups
    assert sum(len(g) for g in groups) == len(REPORTS)


@pytest.mark.parametrize("seed", [1, 2, 3, 20261114])
def test_split_keeps_groups_whole_and_partitions_everything(seed: int) -> None:
    split = splits.make_split(REPORTS, "t", dev_size=8, seed=seed)
    dev, test = set(split.dev), set(split.test)
    assert len(dev) == 8
    assert dev.isdisjoint(test)
    assert dev | test == {r.id for r in REPORTS}
    for group in splits.commit_groups(REPORTS):
        assert set(group) <= dev or set(group) <= test


def test_split_is_reproducible() -> None:
    first = splits.make_split(REPORTS, "t", 8, seed=5)
    assert first == splits.make_split(list(reversed(REPORTS)), "t", 8, seed=5)
    assert first != splits.make_split(REPORTS, "t", 8, seed=6)


def test_frozen_split_cannot_be_overwritten_or_edited(tmp_path: Path) -> None:
    path = tmp_path / "splits" / "t.json"
    split = splits.make_split(REPORTS, "t", 8, seed=5)
    saved = splits.save_split(split, path)
    assert splits.load_split(path) == saved
    with pytest.raises(splits.SplitError, match="never overwritten"):
        splits.save_split(split, path)

    data = json.loads(path.read_text())
    data["split"]["dev"] = data["split"]["dev"][1:]
    path.write_text(json.dumps(data))
    with pytest.raises(splits.SplitError, match="edited"):
        splits.load_split(path)


def test_split_parts() -> None:
    split = splits.make_split(REPORTS, "t", 8, seed=5)
    assert split.ids("all") == split.ids("dev") | split.ids("test")
    with pytest.raises(splits.SplitError):
        split.ids("validation")
