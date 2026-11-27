"""The keyword-match baseline: a changed function is vulnerable when the advisory names it."""

from pathlib import Path

from typer.testing import CliRunner

from patchsight.eval.metrics import SetScores
from patchsight.pipeline.__main__ import app
from patchsight.pipeline.benchmarks import keyword
from patchsight.pipeline.benchmarks.retrieval import Case, Item

REPO = Path(__file__).resolve().parents[1]
BASELINES = ("changedfuncs-baseline.json", "changedfuncs-go-holdout-v1.json")


def _case(report: str, split: str, named: dict[str, bool]) -> Case:
    items = tuple(
        Item(name=n, path="x.go", tokens=10, vulnerable=False, bm25_score=0.0, named=v)
        for n, v in named.items()
    )
    return Case(report=report, split=split, base_tokens=100, items=items, bm25=())


def test_it_keeps_the_named_candidates_and_changedfuncs_keeps_all() -> None:
    case = _case("GO-1", "dev", {"Parse": True, "helper": False, "T.Close": True})
    assert keyword.predicted(case) == {"Parse", "T.Close"}
    assert keyword.changed(case) == {"Parse", "helper", "T.Close"}


def test_an_advisory_that_names_nothing_is_a_miss_scored_against_every_label() -> None:
    """Labels the fix did not change count too: both baselines share the same truth."""
    named = _case("GO-1", "dev", {"Parse": True, "helper": False})
    silent = _case("GO-2", "dev", {"Run": False})
    truth = {"GO-1": {"Parse", "Unchanged"}, "GO-2": {"Run"}}
    s = keyword.score_split("t", "dev", [named, silent], truth)
    assert (s.names_a_candidate, s.names_a_true_one) == (1, 1)
    assert (s.keyword.true_positives, s.keyword.false_positives) == (1, 0)
    assert s.keyword.false_negatives == 2  # Unchanged and Run
    assert s.keyword.miss_rate == 0.5
    assert (s.changedfuncs.true_positives, s.changedfuncs.false_positives) == (2, 1)


def test_splits_are_all_then_each_by_name_or_the_only_one() -> None:
    cases = [_case("a", "test", {}), _case("b", "dev", {}), _case("c", "test", {})]
    assert [(n, [c.report for c in cs]) for n, cs in keyword.splits_of(cases)] == [
        ("all", ["a", "b", "c"]), ("dev", ["b"]), ("test", ["a", "c"]),
    ]  # fmt: skip
    only = [_case("h", "holdout", {})]
    assert [n for n, _ in keyword.splits_of(only)] == ["holdout"]


def _root(tmp_path: Path) -> Path:
    (tmp_path / "benchmarks").symlink_to(REPO / "benchmarks")
    reports = tmp_path / "docs" / "reports"
    reports.mkdir(parents=True)
    for name in BASELINES:
        (reports / name).symlink_to(REPO / "docs" / "reports" / name)
    return tmp_path


def test_the_committed_report_regenerates_exactly(tmp_path: Path) -> None:
    """CI recomputes the report from the frozen bundles alone: no diffs, no model."""
    root = _root(tmp_path)
    result = CliRunner().invoke(app, ["keyword-baseline", "--root", str(root)])
    assert result.exit_code == 0, result.output
    for suffix in (".md", ".json"):
        name = f"keyword-baseline{suffix}"
        produced = (root / "docs" / "reports" / name).read_text()
        assert produced == (REPO / "docs" / "reports" / name).read_text()


def test_it_refuses_candidates_that_are_not_changedfuncs_own(tmp_path: Path) -> None:
    root = _root(tmp_path)
    holdout = root / "docs" / "reports" / BASELINES[1]
    committed = SetScores.model_validate_json(holdout.read_text())
    holdout.unlink()
    holdout.write_text(committed.model_copy(update={"true_positives": 1}).model_dump_json())
    result = CliRunner().invoke(app, ["keyword-baseline", "--root", str(root)])
    assert result.exit_code != 0
    assert "do not reproduce" in result.output
