import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchsight.pipeline.__main__ import app


def _bundle(path: Path, members: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return path


def test_import_places_responses_in_cache_and_the_rest_in_the_inbox(tmp_path: Path) -> None:
    archive = _bundle(
        tmp_path / "run.zip",
        {
            ".cache/llm/ab/abcd.json": '{"content": "{}"}',
            ".cache/llm/usage/model.jsonl": '{"t": 1, "tokens": 5}\n',
            "docs/reports/extraction-dunlap-all-x.md": "# report",
            "run-info.json": "{}",
        },
    )
    result = CliRunner().invoke(app, ["import-kaggle-run", str(archive), "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "imported 1 cached responses" in result.output
    assert (tmp_path / ".cache/llm/ab/abcd.json").exists()
    inbox = tmp_path / "data/interim/kaggle/run"
    assert (inbox / "docs/reports/extraction-dunlap-all-x.md").exists()
    assert (inbox / "run-info.json").exists()
    # The run's usage ledger never overwrites this machine's ledger.
    assert not (tmp_path / ".cache/llm/usage/model.jsonl").exists()
    assert (inbox / ".cache/llm/usage/model.jsonl").exists()


@pytest.mark.parametrize(
    "name",
    ["../outside.json", ".cache/llm/../../escape.json", "/etc/passwd", "src/patchsight/cli.py"],
)
def test_import_refuses_unexpected_paths(tmp_path: Path, name: str) -> None:
    archive = _bundle(tmp_path / "bad.zip", {name: "x"})
    result = CliRunner().invoke(app, ["import-kaggle-run", str(archive), "--root", str(tmp_path)])
    assert result.exit_code != 0
    assert "unexpected path" in result.output
    assert not (tmp_path.parent / "outside.json").exists()
