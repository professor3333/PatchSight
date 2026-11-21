"""Evaluation sets frozen by SHA-256 in git (ADR 0014): no set changes unnoticed."""

import json
from pathlib import Path

from typer.testing import CliRunner

from patchsight.pipeline.__main__ import app
from patchsight.pipeline.benchmarks import frozen

REPO = Path(__file__).resolve().parents[1]


def test_every_committed_evaluation_set_matches_its_pin() -> None:
    manifest = frozen.load(REPO / frozen.MANIFEST)
    assert frozen.check(REPO, manifest) == []
    paths = {s.path for s in manifest.sets}
    # The proposal's datasets, each pinned: benchmark, holdout, gold set, fixtures, suites.
    for required in ("splits/dunlap-v1.json", "benchmarks/go-holdout-v1/reports.json",
                     "annotations/python-gold-v1/sample.json", "tests/fixtures/reachability",
                     "benchmarks/pypi-regression-v1/cases.json",
                     "benchmarks/dunlap-v1/injection-plans-dev.json"):  # fmt: skip
        assert required in paths


def test_the_regression_set_is_pinned_the_same_in_code_and_manifest() -> None:
    from patchsight.pipeline.benchmarks import pypi_regression

    pins = {s.path: s.sha256 for s in frozen.load(REPO / frozen.MANIFEST).sets}
    assert pins["benchmarks/pypi-regression-v1/cases.json"] == pypi_regression.FROZEN_SHA256


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "sets").mkdir()
    (tmp_path / "sets" / "labels.toml").write_text("a = 1\n")
    folder = tmp_path / "sets" / "programs"
    (folder / "one").mkdir(parents=True)
    (folder / "one" / "app.py").write_text("import yaml\n")
    manifest = frozen.Manifest(sets=(
        frozen.FrozenSet(name="labels", path="sets/labels.toml", kind="file",
                         sha256=frozen.digest(tmp_path / "sets" / "labels.toml"),
                         frozen="2026-11-21", what="labels"),
        frozen.FrozenSet(name="programs", path="sets/programs", kind="folder",
                         sha256=frozen.digest(folder), frozen="2026-11-21", what="programs"),
    ))  # fmt: skip
    (tmp_path / "manifests").mkdir()
    frozen.write(tmp_path / frozen.MANIFEST, manifest)
    return tmp_path


def test_an_edit_anywhere_in_a_set_is_caught_and_repinned_only_on_purpose(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    runner = CliRunner()
    assert runner.invoke(app, ["eval-sets", "--root", str(root)]).exit_code == 0
    # Caches and editor files are not part of a folder's contents.
    cache = root / "sets" / "programs" / "one" / "__pycache__"
    cache.mkdir()
    (cache / "app.cpython-312.pyc").write_bytes(b"\0")
    assert runner.invoke(app, ["eval-sets", "--root", str(root)]).exit_code == 0
    # A file added inside the folder, and a label edited, are both changes.
    (root / "sets" / "programs" / "one" / "extra.py").write_text("x = 1\n")
    (root / "sets" / "labels.toml").write_text("a = 2\n")
    result = runner.invoke(app, ["eval-sets", "--root", str(root)])
    assert result.exit_code == 1
    assert "changed: labels: sets/labels.toml" in result.stderr
    assert "changed: programs: sets/programs" in result.stderr
    # Re-pinning one set leaves the other still failing.
    result = runner.invoke(app, ["eval-sets", "--root", str(root), "--repin", "labels"])
    assert result.exit_code == 1
    assert "labels:" not in result.stderr
    pins = json.loads((root / frozen.MANIFEST).read_text())["sets"]
    assert pins[0]["sha256"] == frozen.digest(root / "sets" / "labels.toml")
    unknown = runner.invoke(app, ["eval-sets", "--root", str(root), "--repin", "nope"])
    assert unknown.exit_code == 2


def test_a_missing_set_is_reported(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "sets" / "labels.toml").unlink()
    manifest = frozen.load(root / frozen.MANIFEST)
    assert frozen.check(root, manifest) == ["labels: sets/labels.toml is missing"]
