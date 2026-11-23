"""Model runs and quotas, reconstructed from what each run leaves behind (issue #60).

Offline pipeline only. Two sources, both already written by every run:

* **Kaggle sessions.** ``import-kaggle-run`` unpacks each run into
  ``data/interim/kaggle/<zip name>/``. It holds ``run-info.json`` (commit, model, GPUs,
  mode), the client's usage ledger (one line per model call: when it finished, and its
  tokens) and, for the PyPI backfill, the run's own summary.
* **Hosted quota.** The same ledger, kept under ``.cache/llm/usage/`` for each hosted model,
  is what the client checks against the provider's daily cap.

A ledger line is written when a call finishes, so the first call's own duration is not
known: a session's span runs from its first answer to its last.
"""

import itertools
import json
import statistics
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

KAGGLE_WEEKLY_GPU_HOURS = 30  # as Kaggle stated it when the quota ran out, 2026-11-18


class LedgerEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    t: float
    tokens: int


def load_ledger(path: Path) -> list[LedgerEntry]:
    lines = path.read_text("utf-8").splitlines() if path.exists() else []
    return sorted(
        (LedgerEntry.model_validate_json(line) for line in lines if line), key=lambda e: e.t
    )


def _percentile(values: Sequence[float], share: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(share * len(ordered)))] if ordered else 0.0


class TracedRun(BaseModel):
    """One run's trace (``pipeline/trace.py``), summarised."""

    model_config = ConfigDict(frozen=True)

    trace: str  # file name
    command: str
    role: str | None
    model: str | None
    started: datetime
    outcome: str | None  # None: the run never wrote run_end (killed)
    seconds: float | None
    calls: int
    network_calls: int
    cache_hits: int
    rejections: int
    extractions: dict[str, int]
    latency_p50: float | None  # seconds per answered network call
    latency_p90: float | None
    completion_tokens_per_second: float | None


def load_trace(path: Path) -> TracedRun | None:
    """A trace file as one run; None when it has no run_start."""
    events = []
    for line in path.read_text("utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a line cut short when the session was killed
    start = next((e for e in events if e.get("kind") == "run_start"), None)
    if start is None:
        return None
    end = next((e for e in reversed(events) if e.get("kind") == "run_end"), None)
    calls = [e for e in events if e.get("kind") == "llm_call"]
    answered = [c for c in calls if not c.get("cached") and c.get("outcome") == "ok"]
    seconds = [float(c.get("seconds") or 0) for c in answered]
    generated = sum(int(c.get("completion_tokens") or 0) for c in answered)
    statuses = Counter(str(e.get("status")) for e in events if e.get("kind") == "extraction")
    return TracedRun(
        trace=path.name, command=str(start.get("command")), role=start.get("role"),
        model=start.get("model"), started=datetime.fromisoformat(str(start["ts"])),
        outcome=None if end is None else str(end.get("outcome")),
        seconds=None if end is None else float(end.get("seconds") or 0),
        calls=len(calls), network_calls=sum(not c.get("cached") for c in calls),
        cache_hits=sum(bool(c.get("cached")) for c in calls),
        rejections=sum(c.get("outcome") == "rejected" for c in calls),
        extractions=dict(sorted(statuses.items())),
        latency_p50=round(statistics.median(seconds), 1) if seconds else None,
        latency_p90=round(_percentile(seconds, 0.9), 1) if seconds else None,
        completion_tokens_per_second=round(generated / sum(seconds), 1) if sum(seconds) else None,
    )  # fmt: skip


def load_traces(directory: Path) -> list[TracedRun]:
    found = [load_trace(p) for p in sorted(directory.glob("*.jsonl"))]
    return sorted((r for r in found if r is not None), key=lambda r: r.started)


class _Summary(BaseModel):
    """The fields of a ``pypi-extract`` summary that a session reports."""

    model_config = ConfigDict(extra="ignore")

    vulnerabilities: int | None = None
    complete: bool | None = None
    status: dict[str, int] = {}
    truncated: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    provider_rejections: int | None = None


class Session(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    mode: str  # pypi, dunlap, holdout or locator
    part: str | None  # the shard or split
    model: str
    code_commit: str
    gpus: tuple[str, ...]
    first_answer: datetime
    last_answer: datetime
    hours: float
    calls: int
    tokens: int
    seconds_per_call_p50: float
    seconds_per_call_p90: float
    # From the backfill's own summary, when the run has one.
    vulnerabilities: int | None = None
    complete: bool | None = None
    status: dict[str, int] = {}
    truncated: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    provider_rejections: int | None = None
    runs: tuple[TracedRun, ...] = ()  # the session's traces, when the notebook saved them

    @property
    def answered(self) -> int:
        return sum(self.status.values())

    @property
    def dead_letter_rate(self) -> float | None:
        return self.status.get("dead_letter", 0) / self.answered if self.answered else None


def load_session(run: Path) -> Session | None:
    """One imported Kaggle run, or None when it holds no ledger (no model was called)."""
    info = json.loads((run / "run-info.json").read_text("utf-8"))
    ledgers = sorted((run / ".cache" / "llm" / "usage").glob("*.jsonl"))
    entries = sorted((e for ledger in ledgers for e in load_ledger(ledger)), key=lambda e: e.t)
    if not entries:
        return None
    gaps = [b.t - a.t for a, b in itertools.pairwise(entries)]
    mode = str(info.get("mode") or "dunlap")  # the first runs predate the field
    part = info.get("shard") or info.get("split") or info.get("topup")
    summary = _Summary()
    for path in sorted((run / "pypi-run").glob("*-summary.json")):
        summary = _Summary.model_validate_json(path.read_text("utf-8"))
    first, last = entries[0].t, entries[-1].t
    return Session(
        name=run.name, mode=mode, part=str(part) if part else None,
        model=f"{info.get('model_repo')}:{info.get('model_file')}",
        code_commit=str(info.get("patchsight_commit", ""))[:12],
        gpus=tuple(info.get("gpus") or ()),
        first_answer=datetime.fromtimestamp(first, UTC),
        last_answer=datetime.fromtimestamp(last, UTC),
        hours=round((last - first) / 3600, 2), calls=len(entries),
        tokens=sum(e.tokens for e in entries),
        seconds_per_call_p50=round(statistics.median(gaps), 1) if gaps else 0.0,
        seconds_per_call_p90=round(_percentile(gaps, 0.9), 1),
        **summary.model_dump(),
        runs=tuple(load_traces(run / "data" / "interim" / "traces")),
    )  # fmt: skip


def load_sessions(kaggle_dir: Path) -> list[Session]:
    runs = sorted(p.parent for p in kaggle_dir.glob("*/run-info.json"))
    found = [s for s in (load_session(r) for r in runs) if s is not None]
    return sorted(found, key=lambda s: s.first_answer)


class WeekUse(BaseModel):
    model_config = ConfigDict(frozen=True)

    week: str  # ISO week, e.g. 2026-W47
    hours: float
    sessions: int


def gpu_weeks(sessions: Iterable[Session]) -> list[WeekUse]:
    """Session spans by the ISO week of their first answer. Setup and saving are not in the
    ledger, so this is a lower bound on the quota a week used."""
    hours: dict[str, float] = {}
    count: Counter[str] = Counter()
    for s in sessions:
        year, week, _ = s.first_answer.isocalendar()
        key = f"{year}-W{week:02d}"
        hours[key] = hours.get(key, 0.0) + s.hours
        count[key] += 1
    return [WeekUse(week=k, hours=round(hours[k], 2), sessions=count[k]) for k in sorted(hours)]


class DayUse(BaseModel):
    model_config = ConfigDict(frozen=True)

    day: date
    calls: int
    tokens: int
    share_of_cap: float | None


def daily_use(entries: Iterable[LedgerEntry], cap: int | None) -> list[DayUse]:
    """Tokens per UTC day. The provider's cap is a rolling 24 hours, which the client
    enforces; calendar days are what a chart can show."""
    calls: Counter[date] = Counter()
    tokens: Counter[date] = Counter()
    for e in entries:
        day = datetime.fromtimestamp(e.t, UTC).date()
        calls[day] += 1
        tokens[day] += e.tokens
    return [
        DayUse(day=d, calls=calls[d], tokens=tokens[d],
               share_of_cap=round(tokens[d] / cap, 3) if cap else None)
        for d in sorted(tokens)
    ]  # fmt: skip
