"""The offline benchmark bundle and the reproduce command."""

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from patchsight.pipeline.__main__ import app
from patchsight.pipeline.benchmarks import bundle, changedfuncs, dunlap, splits

ROOT = Path(__file__).resolve().parents[1]


def _report(rid: str, symbols: tuple[str, ...], names: tuple[str, ...]) -> bundle.BundleReport:
    return bundle.BundleReport(
        id=rid,
        symbols=symbols,
        commits=("s",),
        candidates=tuple(
            bundle.BundleCandidate(commit="s", path="a.go", name=n, kind="function") for n in names
        ),
    )


def test_changedfuncs_scores_from_a_bundle() -> None:
    data = bundle.Bundle(
        bundle_version=1, benchmark="b", source={}, path_rule="r",
        reports=(_report("A", ("f",), ("f", "g")), _report("B", ("h",), ())),
    )  # fmt: skip
    s = bundle.changedfuncs_scores(data)
    assert (s.true_positives, s.false_positives, s.false_negatives) == (1, 1, 1)
    assert bundle.changedfuncs_scores(data, frozenset({"A"})).recall == 1.0


def test_classes_are_not_function_candidates() -> None:
    report = _report("A", (), ("f",))
    with_class = report.model_copy(
        update={
            "candidates": (
                *report.candidates,
                bundle.BundleCandidate(commit="s", path="a.go", name="T", kind="class"),
            )
        }
    )
    assert with_class.changed_functions() == {"f"}


def test_export_uses_the_paper_rule_and_keeps_no_code(monkeypatch: pytest.MonkeyPatch) -> None:
    from patchsight.pipeline.diffs.commits import CommitMapping, MappedFile
    from patchsight.pipeline.diffs.mapping import ChangedDefinition, FileMapping

    seen: list[Any] = []

    def fake_map(github: object, repo: str, sha: str, include: Any) -> CommitMapping:
        seen.append(include)
        changed = (
            ChangedDefinition(
                path="a.go", name="Parse", kind="function", sides=("post",), hunks=(0,)
            ),
        )
        file = MappedFile(
            mapping=FileMapping(
                path="a.go", changed=changed, module_level_hunks=(), parse_errors=False
            ),
            status="modified",
            previous_path=None,
            diff_source="github_patch",
        )
        return CommitMapping(
            repo=repo, sha=sha, parent="p", files=(file,), skipped=(), truncated=False
        )

    monkeypatch.setattr(bundle, "map_commit", fake_map)
    fix = dunlap.FixCommit(github_repo="o/r", sha="s", googlesource=False)
    report = dunlap.DunlapReport(
        id="GO-1", commits=(fix,), symbols=frozenset({"Parse"}), released=()
    )
    exported = bundle.export(object(), [report], {"dataset_commit": "c"})  # type: ignore[arg-type]
    assert seen == [dunlap.paper_path_filter]
    assert exported.reports[0].candidates[0].model_dump() == {
        "commit": "s", "path": "a.go", "name": "Parse", "kind": "function",
    }  # fmt: skip


def test_committed_bundle_reproduces_the_committed_baseline() -> None:
    """The same check CI runs: committed bundle + split = committed report."""
    data = bundle.load(ROOT / "benchmarks/dunlap-v1/candidates.json")
    frozen = splits.load_split(ROOT / "splits/dunlap-v1.json")
    committed = changedfuncs.BaselineReport.model_validate_json(
        (ROOT / "docs/reports/changedfuncs-baseline.json").read_text()
    ).ours
    mine = bundle.changedfuncs_scores(data, frozen.split.ids("all"))
    assert (mine.true_positives, mine.false_positives, mine.false_negatives) == (
        committed.true_positives, committed.false_positives, committed.false_negatives,
    )  # fmt: skip
    assert len(data.reports) == 280


def test_reproduce_command_fails_on_a_mismatch(tmp_path: Path) -> None:
    for relative in ("benchmarks/dunlap-v1/candidates.json", "splits/dunlap-v1.json"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / relative).read_text())
    report = changedfuncs.BaselineReport.model_validate_json(
        (ROOT / "docs/reports/changedfuncs-baseline.json").read_text()
    )
    tampered = report.model_copy(
        update={"ours": report.ours.model_copy(update={"true_positives": 1})}
    )
    (tmp_path / "docs/reports").mkdir(parents=True)
    (tmp_path / "docs/reports/changedfuncs-baseline.json").write_text(tampered.model_dump_json())
    result = CliRunner().invoke(app, ["reproduce", "--root", str(tmp_path)])
    assert result.exit_code == 1
    assert "MISMATCH" in result.output
