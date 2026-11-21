"""Nightly runs for the operations dashboard, from the reports each run keeps."""

import io
import json
import zipfile
from pathlib import Path

import httpx
import pytest

from patchsight.pipeline import nightly_runs
from patchsight.pipeline.operations import OperationsReport, render_markdown


def _zip(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, text in members.items():
            bundle.writestr(name, text)
    return buffer.getvalue()


UPDATE = {"previous_version": "2026.11.21", "db_version": "2026.11.22", "carried": 10,
          "rebuilt": 2, "new": 1, "removed": 0,
          "to_extract": ["GHSA-a", "GHSA-b", "GHSA-c"]}  # fmt: skip


@pytest.mark.parametrize(
    ("name", "place"),
    [("nightly-update.json", "nightly-update.json"), ("build/gate.json", "gate.json"),
     ("interim/traces/pypi-extract-x.jsonl", "traces/pypi-extract-x.jsonl"),
     ("build/nightly-targets.json", "nightly-targets.json"),
     ("build/other.sqlite", None), ("../gate.json", None), ("/etc/gate.json", None),
     ("traces/../../x.jsonl", None)],
)  # fmt: skip
def test_only_known_reports_are_taken_from_an_artifact(name: str, place: str | None) -> None:
    assert nightly_runs.report_path(name) == place


def _folder(tmp_path: Path, files: dict[str, str]) -> Path:
    folder = tmp_path / nightly_runs.DIRECTORY / "123"
    nightly_runs.unpack(_zip(files), folder)
    meta = {"id": 123, "event": "schedule", "conclusion": "success",
            "created_at": "2026-11-22T11:30:00Z"}  # fmt: skip
    (folder / "run.json").write_text(json.dumps(meta))
    return folder


def test_a_night_with_extraction_becomes_one_row(tmp_path: Path) -> None:
    trace = "\n".join(json.dumps(e) for e in [
        {"ts": "2026-11-22T11:40:00.000+00:00", "kind": "run_start", "command": "pypi-extract",
         "role": "extractor"},
        {"kind": "llm_call", "cached": False, "outcome": "ok", "seconds": 4.0,
         "completion_tokens": 400},
        {"kind": "run_end", "outcome": "complete", "seconds": 60.0},
    ])  # fmt: skip
    folder = _folder(tmp_path, {
        "build/nightly-update.json": json.dumps(UPDATE),
        "build/gate.json": json.dumps({"passed": True}),
        "build/release-notes.md": "notes",
        "build/nightly-targets.json": json.dumps(
            {"fresh": 3, "backlog": 40, "targets": ["GHSA-a", "GHSA-b", "GHSA-c", "GHSA-z"]}),
        "build/nightly-extract-extractor-summary.json": json.dumps(
            {"status": {"ok": 2, "dead_letter": 1}}),
        "interim/traces/pypi-extract-extractor-20261122T114000Z.jsonl": trace,
        "build/unrelated.bin": "x",
    })  # fmt: skip
    assert not (folder / "unrelated.bin").exists()
    run = nightly_runs.load_run(folder)
    assert (run.db_version, run.previous_version, run.to_extract) == ("2026.11.22", "2026.11.21", 3)
    assert (run.gate_passed, run.published, run.backlog) == (True, True, 40)
    assert run.dead_letter_rate == pytest.approx(1 / 3)
    assert [r.command for r in run.runs] == ["pypi-extract"]
    text = render_markdown(OperationsReport(generated_at=run.started, sessions=(), weeks=(),
                                            hosted=(), database=None, nightly=(run,)))  # fmt: skip
    assert ("| 2026-11-22 11:30 | schedule | success | `2026.11.22` | 10 / 2 / 1 / 0 | pass | 3 "
            "| 40 | dead_letter 1, ok 2 | 33.3% |") in text  # fmt: skip
    assert "| nightly 2026-11-22 | pypi-extract | extractor |" in text


def test_a_night_with_nothing_to_publish_says_so(tmp_path: Path) -> None:
    quiet = {**UPDATE, "rebuilt": 0, "new": 0, "to_extract": []}
    run = nightly_runs.load_run(_folder(tmp_path, {"nightly-update.json": json.dumps(quiet)}))
    assert (run.published, run.gate_passed, run.dead_letter_rate) == (False, None, None)
    text = render_markdown(OperationsReport(generated_at=run.started, sessions=(), weeks=(),
                                            hosted=(), database=None, nightly=(run,)))  # fmt: skip
    assert "`2026.11.22` (not published)" in text
    empty = OperationsReport(generated_at=run.started, sessions=(), weeks=(), hosted=(),
                             database=None)  # fmt: skip
    assert "No nightly report fetched yet" in render_markdown(empty)


def test_fetch_downloads_each_finished_run_once(tmp_path: Path) -> None:
    calls: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.headers["Authorization"] == "Bearer t"
        if request.url.path.endswith("/workflows/nightly.yml/runs"):
            return httpx.Response(200, json={"workflow_runs": [
                {"id": 1, "status": "completed", "event": "schedule", "conclusion": "success",
                 "created_at": "2026-11-22T11:30:00Z"},
                {"id": 2, "status": "in_progress", "event": "schedule", "conclusion": None,
                 "created_at": "2026-11-23T11:30:00Z"},
            ]})  # fmt: skip
        if request.url.path.endswith("/runs/1/artifacts"):
            return httpx.Response(200, json={"artifacts": [
                {"name": "nightly-reports", "expired": False,
                 "archive_download_url": "https://api.github.com/download/1"},
            ]})  # fmt: skip
        if request.url.path == "/download/1":
            return httpx.Response(200, content=_zip({"build/nightly-update.json": "{}"}))
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(answer))
    fetched = nightly_runs.fetch("t", "o/r", tmp_path, client=client)
    assert [f.name for f in fetched] == ["1"]  # the run still going is left for later
    assert (tmp_path / nightly_runs.DIRECTORY / "1" / "nightly-update.json").exists()
    again = nightly_runs.fetch("t", "o/r", tmp_path, client=client)
    assert again == []
    assert calls.count("/repos/o/r/actions/runs/1/artifacts") == 1
