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
    part = info.get("shard") or info.get("split")
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
