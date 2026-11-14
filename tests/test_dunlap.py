"""The Dunlap benchmark loader and the ChangedFuncs runner, on synthetic rows."""

import csv
from datetime import date
from pathlib import Path

import pytest

from patchsight.pipeline.benchmarks import changedfuncs, dunlap
from patchsight.pipeline.diffs.commits import CommitMapping, MappedFile
from patchsight.pipeline.diffs.mapping import ChangedDefinition, FileMapping
from patchsight.pipeline.http import NotFoundError

COLUMNS = [
    "id", "repo_owner", "repo_name", "repo_type", "vfc_sha", "file_name",
    "changed_combined_functions", "label_combined_unique", "symbol_name",
]  # fmt: skip
ROWS = [
    # Report 1: two commits; one function changed by both; a test file; one miss.
    ["GO-1", "Acme", "Lib", "GitHub", "s1", "a.go", "['Parse']", "[True]", "['Parse', 'Gone']"],
    ["GO-1", "Acme", "Lib", "GitHub", "s1", "a.go", "['helper']", "[False]", "['Parse', 'Gone']"],
    ["GO-1", "Acme", "Lib", "GitHub", "s2", "a.go", "['Parse']", "[True]", "['Parse', 'Gone']"],
    ["GO-1", "Acme", "Lib", "GitHub", "s1", "a_test.go", "['TestParse']", "[False]",
     "['Parse', 'Gone']"],
    # Report 2: a Go standard-library fix, hosted on go.googlesource.com.
    ["GO-2", "go.googlesource.com", "net", "GoogleSource", "s3", "http2/frame.go",
     "['Framer.ReadFrame']", "[True]", "['Framer.ReadFrame']"],
]  # fmt: skip


@pytest.fixture
def csv_path(tmp_path: Path) -> Path:
    path = tmp_path / "data.csv"
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        writer.writerows(ROWS)
    return path


def test_load(csv_path: Path) -> None:
    first, second = dunlap.load(csv_path)
    assert first.id == "GO-1"
    assert [(c.github_repo, c.sha) for c in first.commits] == [
        ("acme/lib", "s1"),
        ("acme/lib", "s2"),
    ]
    assert first.symbols == frozenset({"Parse", "Gone"})
    assert dunlap.released_candidates(first, filtered=True) == {"Parse", "helper"}
    assert dunlap.released_candidates(first, filtered=False) == {"Parse", "helper", "TestParse"}
    assert second.commits[0].github_repo == "golang/net"
    assert second.commits[0].googlesource


def test_paper_unit_counts_report_commit_function(csv_path: Path) -> None:
    # (GO-1,s1,Parse) (GO-1,s1,helper) (GO-1,s2,Parse) (GO-2,s3,Framer.ReadFrame)
    assert dunlap.paper_unit_counts(dunlap.load(csv_path)) == (4, 3)


@pytest.mark.parametrize(
    ("path", "kept"),
    [("a.go", True), ("a_test.go", False), ("testdata/x.go", False), ("Latest/x.go", False),
     ("a.py", False)],
)  # fmt: skip
def test_paper_path_filter(path: str, kept: bool) -> None:
    assert dunlap.paper_path_filter(path) is kept


def _mapping(repo: str, sha: str, names: list[str]) -> CommitMapping:
    changed = tuple(
        ChangedDefinition(path="a.go", name=n, kind="function", sides=("post",), hunks=(0,))
        for n in names
    )
    file = MappedFile(
        mapping=FileMapping(
            path="a.go", changed=changed, module_level_hunks=(), parse_errors=False
        ),
        status="modified",
        previous_path=None,
        diff_source="github_patch",
    )
    return CommitMapping(repo=repo, sha=sha, parent="p", files=(file,), skipped=(), truncated=False)


def test_run_scores_and_compares(csv_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_map(github: object, repo: str, sha: str, include: object) -> CommitMapping:
        if sha == "s3":
            raise NotFoundError("gone")
        return _mapping(repo, sha, {"s1": ["Parse", "helper"], "s2": ["Parse"]}[sha])

    monkeypatch.setattr(changedfuncs, "map_commit", fake_map)
    report = changedfuncs.run(object(), dunlap.load(csv_path), as_of=date(2026, 11, 14))  # type: ignore[arg-type]
    assert report.commit_status == {"mapped": 2, "not_found": 1}
    assert (report.ours.true_positives, report.ours.false_positives) == (1, 1)
    assert report.ours.false_negatives == 2  # Gone, and GO-2's symbol
    assert report.identical_reports == 1  # GO-1 matches; GO-2 has nothing
    text = changedfuncs.render_markdown(report, ["- source"])
    assert "PatchSight pipeline" in text
    assert "Why the released CSV scores differently" in text
    assert (report.released_found, report.superset_reports) == (2, 1)
    assert (report.extra_candidates, report.unique_commits) == (0, 3)
