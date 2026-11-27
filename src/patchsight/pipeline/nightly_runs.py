"""Nightly runs for the operations dashboard (issue #60), from the reports each run keeps.

Every nightly run uploads a ``nightly-reports`` artifact: the update report, the gate's
result, the release notes when it published, and, since ADR 0013, the targets it chose, the
extraction's summary, the merge report and the run's trace. ``fetch`` downloads them through
the GitHub API into ``data/interim/nightly/<run id>/``, once each, and ``load_run`` turns a
folder into a row.

Offline pipeline only. Only the expected report files are taken from an artifact; anything
else in it is refused.
"""

import io
import json
import re
import zipfile
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.sessions import TracedRun, load_traces

ARTIFACT = "nightly-reports"
DIRECTORY = Path("data/interim/nightly")
API = "https://api.github.com"
REPORTS = frozenset({
    "nightly-update.json", "nightly-import-names.json", "gate.json", "gate.md",
    "release-notes.md", "nightly-targets.json", "nightly-extract-extractor-summary.json",
    "nightly-merged-merge.json", "nightly-drift.json", "nightly-drift.md",
})  # fmt: skip


def report_path(name: str) -> str | None:
    """Where a file from an artifact goes in its run folder, or None to refuse it. Artifacts
    keep their paths below the files' common folder, which changed when traces were added,
    so a report is known by its name and a trace by its ``traces/`` folder."""
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    if path.name in REPORTS:
        return path.name
    if len(path.parts) >= 2 and path.parts[-2] == "traces" and path.suffix == ".jsonl":
        return f"traces/{path.name}"
    return None


_ANSWER = re.compile(r"[0-9a-f]{64}\.json")


def answer_path(name: str) -> str | None:
    """Where a model answer from the night's response cache (``.cache/llm/<ab>/<key>.json``)
    goes in the local one, or None to refuse it. The usage ledger is never taken."""
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) < 3:
        return None
    folder, file = path.parts[-2], path.name
    if path.parts[-3] == "llm" and _ANSWER.fullmatch(file) and folder == file[:2]:
        return f"{folder}/{file}"
    return None


def _is_answer(data: bytes) -> bool:
    """A cached answer ({content, prompt_tokens, completion_tokens}) or rejection."""
    try:
        record = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(record, dict):
        return False
    if set(record) == {"rejected"}:
        return isinstance(record["rejected"], str)
    return (
        set(record) == {"content", "prompt_tokens", "completion_tokens"}
        and isinstance(record["content"], str)
        and all(isinstance(record[k], int) for k in ("prompt_tokens", "completion_tokens"))
    )


def unpack(archive: bytes, target: Path, answers: Path | None = None) -> list[str]:
    """The known report files of one artifact, written into ``target``; with ``answers``, the
    night's model answers too, added to that response cache (an answer already there is
    kept). Returns the reports and answers written, answers as ``llm/<ab>/<key>.json``."""
    written = []
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for member in bundle.infolist():
            if member.is_dir():
                continue
            place = report_path(member.filename)
            if place is not None:
                destination = target / place
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(bundle.read(member))
                written.append(place)
                continue
            answer = answer_path(member.filename) if answers is not None else None
            if answer is None or answers is None or (answers / answer).exists():
                continue
            data = bundle.read(member)
            if not _is_answer(data):
                continue
            (answers / answer).parent.mkdir(parents=True, exist_ok=True)
            (answers / answer).write_bytes(data)
            written.append(f"llm/{answer}")
    return sorted(written)


def fetch(token: str, repo: str, root: Path, limit: int = 30,
          client: httpx.Client | None = None) -> list[Path]:  # fmt: skip
    """Download the reports of the latest ``limit`` nightly runs not yet fetched, and add
    their model answers to the local response cache (``<root>/.cache/llm``), so a replay
    under another configuration sees what the nightly extractor answered."""
    http = client or httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0),
                                  follow_redirects=True)  # fmt: skip
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    fetched = []
    try:
        listing = http.get(
            f"{API}/repos/{repo}/actions/workflows/nightly.yml/runs",
            params={"per_page": limit}, headers=headers,
        )  # fmt: skip
        listing.raise_for_status()
        for run in listing.json()["workflow_runs"]:
            folder = root / DIRECTORY / str(run["id"])
            if (folder / "run.json").exists() or run.get("status") != "completed":
                continue
            folder.mkdir(parents=True, exist_ok=True)
            artifacts = http.get(f"{API}/repos/{repo}/actions/runs/{run['id']}/artifacts",
                                 headers=headers)  # fmt: skip
            artifacts.raise_for_status()
            for artifact in artifacts.json()["artifacts"]:
                if artifact["name"] == ARTIFACT and not artifact.get("expired"):
                    archive = http.get(artifact["archive_download_url"], headers=headers)
                    archive.raise_for_status()
                    unpack(archive.content, folder, root / ".cache" / "llm")
            meta = {k: run.get(k) for k in ("id", "event", "conclusion", "created_at")}
            (folder / "run.json").write_text(json.dumps(meta, indent=2) + "\n", "utf-8")
            fetched.append(folder)
    finally:
        if client is None:
            http.close()
    return fetched


class NightlyRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: int
    event: str
    conclusion: str | None
    started: datetime
    db_version: str | None = None
    previous_version: str | None = None
    carried: int | None = None
    rebuilt: int | None = None
    new: int | None = None
    removed: int | None = None
    to_extract: int | None = None
    backlog: int | None = None  # vulnerabilities waiting from earlier nights (ADR 0013)
    gate_passed: bool | None = None
    published: bool = False
    extraction: dict[str, int] = {}  # outcome statuses, when the night extracted
    extraction_model: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    drift: str | None = None  # the live drift check's verdict (ADR 0016)
    drift_counts: dict[str, int] = {}
    runs: tuple[TracedRun, ...] = ()

    @property
    def dead_letter_rate(self) -> float | None:
        answered = sum(self.extraction.values())
        return self.extraction.get("dead_letter", 0) / answered if answered else None


def _json(path: Path) -> Mapping[str, Any] | None:
    return json.loads(path.read_text("utf-8")) if path.exists() else None


def load_run(folder: Path) -> NightlyRun:
    meta = json.loads((folder / "run.json").read_text("utf-8"))
    update = _json(folder / "nightly-update.json") or {}
    gate = _json(folder / "gate.json")
    summary = _json(folder / "nightly-extract-extractor-summary.json") or {}
    targets = _json(folder / "nightly-targets.json") or {}
    drift = _json(folder / "nightly-drift.json") or {}
    return NightlyRun(
        run_id=int(meta["id"]), event=str(meta.get("event")), conclusion=meta.get("conclusion"),
        started=datetime.fromisoformat(str(meta["created_at"]).replace("Z", "+00:00")),
        db_version=update.get("db_version"), previous_version=update.get("previous_version"),
        carried=update.get("carried"), rebuilt=update.get("rebuilt"), new=update.get("new"),
        removed=update.get("removed"),
        to_extract=len(update["to_extract"]) if "to_extract" in update else None,
        backlog=targets.get("backlog"),
        gate_passed=None if gate is None else bool(gate.get("passed")),
        published=(folder / "release-notes.md").exists(),
        extraction=dict(summary.get("status") or {}),
        extraction_model=summary.get("model"),
        prompt_tokens=summary.get("prompt_tokens"),
        completion_tokens=summary.get("completion_tokens"),
        drift=drift.get("verdict"), drift_counts=dict(drift.get("counts") or {}),
        runs=tuple(load_traces(folder / "traces")),
    )  # fmt: skip


def load_runs(root: Path) -> list[NightlyRun]:
    folders = [p.parent for p in (root / DIRECTORY).glob("*/run.json")]
    return sorted((load_run(f) for f in folders), key=lambda r: r.started)
