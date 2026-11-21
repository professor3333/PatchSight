"""The operations dashboard (issue #60): model runs, quota use, and what the database holds.

Offline, from files that already exist: imported Kaggle runs, the hosted models' usage
ledgers, and a published database. Nothing here calls a model or the network.
"""

import sqlite3
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.nightly_runs import NightlyRun
from patchsight.pipeline.sessions import (
    KAGGLE_WEEKLY_GPU_HOURS,
    DayUse,
    Session,
    TracedRun,
    WeekUse,
)


class HostedModel(BaseModel):
    model_config = ConfigDict(frozen=True)

    model: str
    tokens_per_day: int | None
    days: tuple[DayUse, ...]


class DatabaseView(BaseModel):
    model_config = ConfigDict(frozen=True)

    db_version: str
    records: dict[str, int]  # "source, confidence" -> records
    tier_reasons: dict[str, int]
    second_opinions: int
    builds: dict[str, int]  # ledger status -> vulnerabilities


def database_view(path: Path) -> DatabaseView:
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        meta = dict(db.execute("SELECT key, value FROM meta"))
        records = {
            f"{source}, {confidence}": n
            for source, confidence, n in db.execute(
                "SELECT source, confidence, COUNT(*) FROM records GROUP BY 1, 2 ORDER BY 3 DESC"
            )
        }
        reasons = dict(db.execute(
            "SELECT tier_reason, COUNT(*) FROM extraction GROUP BY 1 ORDER BY 2 DESC, 1"
        ))  # fmt: skip
        (second,) = db.execute(
            "SELECT COUNT(*) FROM extraction WHERE second_opinion_model IS NOT NULL"
        ).fetchone()
        builds = dict(db.execute("SELECT status, COUNT(*) FROM builds GROUP BY 1 ORDER BY 2 DESC"))
    return DatabaseView(
        db_version=meta["db_version"], records=records,
        tier_reasons={str(k): v for k, v in reasons.items()}, second_opinions=second,
        builds=builds,
    )  # fmt: skip


class OperationsReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    generated_at: datetime
    sessions: tuple[Session, ...]
    weeks: tuple[WeekUse, ...]
    hosted: tuple[HostedModel, ...]
    database: DatabaseView | None
    local_runs: tuple[TracedRun, ...] = ()  # traces of runs on the machine that wrote this
    nightly: tuple[NightlyRun, ...] = ()


def _n(value: int | None) -> str:
    return "—" if value is None else f"{value:,}"


def _sessions(sessions: Sequence[Session]) -> list[str]:
    lines = [
        "| Mode | Part | Code | First answer (UTC) | Hours | Calls | s per call (p50 / p90) "
        "| Tokens | Answered | Dead letters | Truncated | Rejections |",
        "|---|---|---|---|---:|---:|---|---:|---:|---:|---:|---:|",
    ]
    for s in sessions:
        dead = s.status.get("dead_letter", 0)
        rate = "—" if s.dead_letter_rate is None else f"{dead} ({s.dead_letter_rate:.1%})"
        lines.append(
            f"| {s.mode} | {s.part or '—'} | `{s.code_commit[:7]}` | "
            f"{s.first_answer:%Y-%m-%d %H:%M} | {s.hours:.2f} | {s.calls:,} | "
            f"{s.seconds_per_call_p50:.0f} / {s.seconds_per_call_p90:.0f} | {s.tokens:,} | "
            f"{_n(s.answered) if s.status else '—'} | {rate} | {_n(s.truncated)} | "
            f"{_n(s.provider_rejections)} |"
        )
    return lines


def _seconds(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value / 3600:.2f} h" if value >= 3600 else f"{value:.0f} s"


def _runs(rows: Sequence[tuple[str, TracedRun]]) -> list[str]:
    lines = [
        "| Where | Command | Role | Started (UTC) | Outcome | Wall time | Calls (network / "
        "cached) | Rejections | Extractions | s per answer (p50 / p90) | Generated tokens/s |",
        "|---|---|---|---|---|---:|---|---:|---|---|---:|",
    ]
    for where, r in rows:
        extractions = ", ".join(f"{k} {v:,}" for k, v in r.extractions.items()) or "—"
        latency = "—" if r.latency_p50 is None else f"{r.latency_p50:.0f} / {r.latency_p90:.0f}"
        speed = (
            "—"
            if r.completion_tokens_per_second is None
            else f"{r.completion_tokens_per_second:.1f}"
        )
        lines.append(
            f"| {where} | {r.command} | {r.role or '—'} | {r.started:%Y-%m-%d %H:%M} | "
            f"{r.outcome or 'no end (killed)'} | {_seconds(r.seconds)} | "
            f"{r.network_calls:,} / {r.cache_hits:,} | {r.rejections:,} | {extractions} | "
            f"{latency} | {speed} |"
        )
    return lines


def _nightly(runs: Sequence[NightlyRun]) -> list[str]:
    if not runs:
        return ["No nightly report fetched yet (`fetch-nightly`)."]
    lines = [
        "| Started (UTC) | Trigger | Result | Release | Carried / rebuilt / new / removed | "
        "Gate | To extract | Backlog | Extraction | Dead letters |",
        "|---|---|---|---|---|---|---:|---:|---|---:|",
    ]
    for r in runs:
        release = f"`{r.db_version}`" + ("" if r.published else " (not published)")
        changes = (
            "—" if r.carried is None
            else f"{r.carried:,} / {r.rebuilt:,} / {r.new:,} / {r.removed:,}"
        )  # fmt: skip
        gate = "—" if r.gate_passed is None else ("pass" if r.gate_passed else "**fail**")
        extraction = ", ".join(f"{k} {v:,}" for k, v in sorted(r.extraction.items())) or "—"
        rate = "—" if r.dead_letter_rate is None else f"{r.dead_letter_rate:.1%}"
        to_extract = "—" if r.to_extract is None else f"{r.to_extract:,}"
        backlog = "—" if r.backlog is None else f"{r.backlog:,}"
        lines.append(
            f"| {r.started:%Y-%m-%d %H:%M} | {r.event} | {r.conclusion or '—'} | "
            f"{release if r.db_version else '—'} | {changes} | {gate} | {to_extract} | "
            f"{backlog} | {extraction} | {rate} |"
        )
    return lines


def render_markdown(report: OperationsReport) -> str:
    r = report
    lines = [
        "# Operations: model runs, quota and the database",
        "",
        "Generated by `python -m patchsight.pipeline operations-report`; do not edit by hand. "
        "Built offline from the files each run leaves behind: imported Kaggle runs, the hosted "
        "models' usage ledgers and the published database.",
        "",
        f"Generated {r.generated_at:%Y-%m-%d %H:%M} UTC.",
        "",
        "## Kaggle sessions",
        "",
        "One row per run. A run's usage ledger records each model call when it finishes, so a "
        "session's hours run from its first answer to its last; setup and saving are not "
        "counted. The answers, dead letters and truncation come from the backfill's own summary.",
        "",
        *_sessions(r.sessions),
        "",
        f"GPU hours by ISO week, against Kaggle's weekly quota of {KAGGLE_WEEKLY_GPU_HOURS} hours "
        "(a lower bound on what each week used):",
        "",
        "| Week | Sessions | Hours answering | Share of the quota |",
        "|---|---:|---:|---:|",
        *(
            f"| {w.week} | {w.sessions} | {w.hours:.2f} | {w.hours / KAGGLE_WEEKLY_GPU_HOURS:.0%} |"
            for w in r.weeks
        ),
        "",
        "## Traced runs",
        "",
        "Runs that wrote a trace (`data/interim/traces/`): one line per model call and per "
        "extraction, with timings. Kaggle runs bring theirs home in the zip. A run with no end "
        "was killed before it could write one.",
        "",
        *(
            _runs(
                [
                    (f"Kaggle {s.mode} {s.part or ''}".strip(), run)
                    for s in r.sessions
                    for run in s.runs
                ]
                + [(f"nightly {n.started:%Y-%m-%d}", run) for n in r.nightly for run in n.runs]
                + [("this machine", run) for run in r.local_runs]
            )
            if any(s.runs for s in r.sessions) or r.local_runs or any(n.runs for n in r.nightly)
            else ["No traced run yet."]
        ),
        "",
        "## Nightly runs",
        "",
        "From the reports each run keeps (`fetch-nightly`). Since ADR 0013 a run with the Groq "
        "secret also extracts, at most 25 a night: its changed vulnerabilities (to extract), "
        "then those waiting from earlier nights for model picks (backlog). The dead-letter "
        "target is under 2% after retries.",
        "",
        *_nightly(r.nightly),
        "",
        "## Hosted models: tokens against the daily cap",
        "",
        "The provider's cap is a rolling 24 hours, which the client enforces before each call; "
        "this table groups the same ledger by UTC day.",
        "",
    ]
    for hosted in r.hosted:
        cap = _n(hosted.tokens_per_day)
        total = sum(d.tokens for d in hosted.days)
        lines += [
            f"### `{hosted.model}`, cap {cap} tokens a day",
            "",
            f"{sum(d.calls for d in hosted.days):,} calls and {total:,} tokens over "
            f"{len(hosted.days)} days.",
            "",
            "| Day | Calls | Tokens | Share of the cap |",
            "|---|---:|---:|---:|",
            *(
                f"| {d.day} | {d.calls:,} | {d.tokens:,} | "
                f"{'—' if d.share_of_cap is None else f'{d.share_of_cap:.0%}'} |"
                for d in hosted.days
            ),
            "",
        ]
    if r.database is not None:
        d = r.database
        lines += [
            f"## Database `{d.db_version}`",
            "",
            "| Records by source and confidence | Records |",
            "|---|---:|",
            *(f"| {k} | {v:,} |" for k, v in d.records.items()),
            "",
            "Why records with model picks are at their tier:",
            "",
            "| Tier reason | Records |",
            "|---|---:|",
            *(f"| {k} | {v:,} |" for k, v in d.tier_reasons.items()),
            "",
            (
                f"**Two-model agreement rate:** {d.second_opinions:,} records have a second "
                "opinion so far, so the rate is not measured yet."
                if d.second_opinions == 0
                else f"**Second opinions:** {d.second_opinions:,} records."
            ),
            "",
            "Every vulnerability the build considered, by ledger status:",
            "",
            "| Status | Vulnerabilities |",
            "|---|---:|",
            *(f"| {k} | {v:,} |" for k, v in d.builds.items()),
            "",
        ]
    return "\n".join(lines)
