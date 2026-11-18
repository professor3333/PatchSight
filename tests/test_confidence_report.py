"""confidence-report from the committed benchmark files, and its experiment variants."""

import shutil
from pathlib import Path

from typer.testing import CliRunner

from patchsight.pipeline.__main__ import app

REPO = Path(__file__).resolve().parents[1]
PAIR = ("extract-v1-qwen3.8-27b-q4km", "extract-v1-gpt-oss-120b")
COMMITTED = f"confidence-dunlap-dev-{PAIR[0]}-vs-{PAIR[1]}"


def _root(tmp_path: Path) -> Path:
    for name in ("benchmarks", "splits"):
        (tmp_path / name).symlink_to(REPO / name)
    reports = tmp_path / "docs" / "reports"
    reports.mkdir(parents=True)
    for source in (REPO / "docs" / "reports").glob("extraction-dunlap-dev-*.json"):
        shutil.copy(source, reports / source.name)
    return tmp_path


def _run(root: Path, *extra: str) -> None:
    result = CliRunner().invoke(app, [
        "confidence-report", "--primary", PAIR[0], "--secondary", PAIR[1], "--split", "dev",
        "--root", str(root), *extra,
    ])  # fmt: skip
    assert result.exit_code == 0, result.output


def test_the_committed_dev_report_regenerates_exactly(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _run(root)
    for suffix in (".md", ".json"):
        produced = (root / "docs" / "reports" / f"{COMMITTED}{suffix}").read_text()
        assert produced == (REPO / "docs" / "reports" / f"{COMMITTED}{suffix}").read_text()


def test_a_variant_reads_its_own_reports_and_writes_under_its_suffix(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _run(root, "--variant", "dotted")
    report = (root / "docs" / "reports" / f"{COMMITTED}-dotted.md").read_text()
    assert "- Variant `dotted`: entry points from the `-dotted` extraction reports" in report
    committed = (REPO / "docs" / "reports" / f"{COMMITTED}-dotted.md").read_text()
    assert report == committed
