"""The extractor on hard real inputs (benchmarks/dunlap-v1/robustness.json), offline."""

from pathlib import Path

from typer.testing import CliRunner

from patchsight.pipeline.__main__ import app
from patchsight.pipeline.benchmarks import robustness
from patchsight.pipeline.diffs.commits import CommitMapping, MappedFile, SkippedFile
from patchsight.pipeline.diffs.mapping import ChangedDefinition, FileMapping, Side

REPO = Path(__file__).resolve().parents[1]
NAME = "robustness-dunlap-v1-extract-v1-qwen3.8-27b-q4km"


def test_the_committed_report_regenerates_exactly(tmp_path: Path) -> None:
    """CI replays the committed answers with the live validator: the report must not drift."""
    (tmp_path / "benchmarks").symlink_to(REPO / "benchmarks")
    (tmp_path / "docs" / "reports").mkdir(parents=True)
    result = CliRunner().invoke(app, ["robustness-report", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Every report: 280 reports, F1 0.680, misses 48" in result.output  # the headline
    for suffix in (".md", ".json"):
        produced = (tmp_path / "docs" / "reports" / f"{NAME}{suffix}").read_text()
        assert produced == (REPO / "docs" / "reports" / f"{NAME}{suffix}").read_text()


def _changed(path: str, name: str, *sides: Side) -> ChangedDefinition:
    return ChangedDefinition(path=path, name=name, kind="function", sides=sides, hunks=(1,))


def _file(path: str, status: str, previous: str | None, *changed: ChangedDefinition) -> MappedFile:
    return MappedFile(
        mapping=FileMapping(path=path, changed=changed, module_level_hunks=(), parse_errors=False),
        status=status, previous_path=previous, diff_source="github_patch",
    )  # fmt: skip


def test_each_property_is_read_from_the_mapped_fix() -> None:
    fix = CommitMapping(
        repo="o/r", sha="b" * 40, parent="a" * 40, truncated=False,
        files=(_file("a.go", "modified", None, _changed("a.go", "New", "post"),
                     _changed("a.go", "Old", "pre", "post")),),
        skipped=(SkippedFile(path="README.md", reason="unsupported_language"),),
    )  # fmt: skip
    moved = CommitMapping(
        repo="o/r", sha="c" * 40, parent="b" * 40, truncated=False,
        files=(_file("b.go", "renamed", "old.go", _changed("b.go", "Kept", "post")),),
        skipped=(),
    )  # fmt: skip
    sources = {"a.go": b"package x\nfunc Old() {}\n", "old.go": b"package x\nfunc Kept() {}\n"}
    looked_up = []

    def before(mapping: CommitMapping, path: str, previous: str | None) -> bytes | None:
        looked_up.append(previous or path)
        return sources.get(previous or path)

    shown = [("a.go", "New"), ("a.go", "Old"), ("b.go", "Kept")]
    both = robustness.describe("GO-1", "dev", [fix, moved], shown, before)
    assert (both.commits, both.files, both.candidates) == (2, 3, 3)
    assert (both.renamed, both.add_only, both.adds_definition) == (True, False, True)
    assert looked_up == ["a.go", "old.go"]  # a renamed file is read under its old name

    only_moved = robustness.describe("GO-2", "test", [moved], [("b.go", "Kept")], before)
    assert (only_moved.renamed, only_moved.add_only, only_moved.adds_definition) == (
        True, True, False,  # only added lines, to a definition the file already had
    )  # fmt: skip
    nothing = robustness.describe("GO-3", "test", [], [], before)
    assert (nothing.add_only, nothing.adds_definition, nothing.candidates) == (False, False, 0)
