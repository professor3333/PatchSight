"""A run's trace: one JSON line per event, offline only (issue #60).

Events:

* ``run_start`` and ``run_end``: the command, its options, the code commit, and the outcome;
* ``llm_call``: one per model call, cached or not: the model, prompt version, input hash,
  whether the cache answered, the outcome, tokens and seconds;
* ``extraction``: one per advisory: status, retries and truncation.

Model and extraction events carry the advisory they belong to. Prompts, answers and
provider messages are never written, so a trace holds no third-party code and no account
details.

A tracer never raises. If its file cannot be written, it warns once and the run goes on:
a trace must not cost a ten-hour GPU session.
"""

import json
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

TRACE_DIR = Path("data/interim/traces")


class Tracer:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._advisory: str | None = None
        self._broken = False

    @contextmanager
    def advisory(self, advisory_id: str) -> Iterator[None]:
        """Events emitted inside belong to this advisory."""
        previous, self._advisory = self._advisory, advisory_id
        try:
            yield
        finally:
            self._advisory = previous

    def emit(self, kind: str, **fields: object) -> None:
        if self.path is None or self._broken:
            return
        event: dict[str, object] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "kind": kind,
        }
        if self._advisory is not None:
            event["advisory"] = self._advisory
        event.update(fields)
        try:
            line = json.dumps(event, default=str, ensure_ascii=False)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except (OSError, TypeError, ValueError) as error:
            self._broken = True
            print(f"warning: tracing stopped, the run goes on: {error}", file=sys.stderr)


def code_commit(root: Path) -> str:
    """The checked-out commit, or empty when ``root`` is not a git checkout."""
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True, text=True, check=False, timeout=10,
        ).stdout.strip()  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return ""


def trace_path(root: Path, name: str, started: datetime | None = None) -> Path:
    """A fresh file per run, so a resumed run is a second run, not a longer first one."""
    moment = (started or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return root / TRACE_DIR / f"{name}-{moment}.jsonl"
