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
    "nightly-merged-merge.json",
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


def unpack(archive: bytes, target: Path) -> list[str]:
    """The known report files of one artifact, written into ``target``."""
    written = []
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for member in bundle.infolist():
            if member.is_dir():
                continue
            place = report_path(member.filename)
            if place is None:
                continue
            destination = target / place
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(bundle.read(member))
            written.append(place)
    return sorted(written)


def fetch(token: str, repo: str, root: Path, limit: int = 30,
          client: httpx.Client | None = None) -> list[Path]:  # fmt: skip
    """Download the reports of the latest ``limit`` nightly runs not yet fetched."""
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
                    unpack(archive.content, folder)
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
        runs=tuple(load_traces(folder / "traces")),
    )  # fmt: skip


def load_runs(root: Path) -> list[NightlyRun]:
    folders = [p.parent for p in (root / DIRECTORY).glob("*/run.json")]
    return sorted((load_run(f) for f in folders), key=lambda r: r.started)
