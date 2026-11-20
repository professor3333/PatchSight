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
            "pypi-run/pypi-extract-kaggle_extractor-shard1of4-summary.json": "{}",
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


def test_a_locator_run_brings_its_github_answers_into_the_cache(tmp_path: Path) -> None:
    archive = _bundle(
        tmp_path / "patchsight-kaggle-run-locator-qwen.zip",
        {
            ".cache/llm/cd/cdef.json": '{"content": "{}"}',
            ".cache/http/github/ef/efgh.json": '{"status": 200, "body": {}}',
            "docs/reports/locator-masked-v1-locate-v1-x.md": "# report",
        },
    )
    result = CliRunner().invoke(app, ["import-kaggle-run", str(archive), "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "imported 1 cached responses" in result.output  # model answers only
    assert (tmp_path / ".cache/http/github/ef/efgh.json").exists()  # so a replay is exact


def test_a_run_brings_its_trace_into_its_own_folder(tmp_path: Path) -> None:
    name = "data/interim/traces/pypi-extract-kaggle_extractor-shard4of4-20261121T030405Z.jsonl"
    archive = _bundle(tmp_path / "patchsight-kaggle-run-pypi-shard4of4.zip",
                      {name: '{"kind": "run_start"}\n', "run-info.json": "{}"})  # fmt: skip
    result = CliRunner().invoke(app, ["import-kaggle-run", str(archive), "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "data/interim/kaggle/patchsight-kaggle-run-pypi-shard4of4" / name).exists()
    assert not (tmp_path / name).exists()  # never mixed with this machine's own traces


def test_the_notebook_compiles_and_zips_the_trace() -> None:
    import ast
    import json

    notebook = Path(__file__).resolve().parents[1] / "notebooks" / "kaggle_full_run.ipynb"
    cells = [c for c in json.loads(notebook.read_text())["cells"] if c["cell_type"] == "code"]
    for cell in cells:
        lines = "".join(cell["source"]).splitlines()
        if lines and lines[0].startswith("%%"):
            continue  # a cell magic such as %%bash: not Python
        ast.parse("\n".join(line for line in lines if not line.lstrip().startswith(("!", "%"))))
    zipping = next(
        "".join(c["source"]) for c in cells if "zipfile.ZipFile(archive" in "".join(c["source"])
    )
    assert 'glob.glob(f"{REPO}/data/interim/traces/*.jsonl")' in zipping
