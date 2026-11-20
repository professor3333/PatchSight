"""Kaggle sessions and quota use, from the files each run leaves behind (issue #60)."""

import json
from datetime import UTC, date, datetime
from pathlib import Path

from patchsight.pipeline import sessions

START = datetime(2026, 11, 16, 16, 0, tzinfo=UTC).timestamp()


def _run(root: Path, name: str, info: dict[str, object], gaps: list[float],
         summary: dict[str, object] | None = None) -> Path:  # fmt: skip
    run = root / name
    usage = run / ".cache" / "llm" / "usage"
    usage.mkdir(parents=True)
    (run / "run-info.json").write_text(json.dumps(info))
    t, lines = START, []
    for gap in [0.0, *gaps]:
        t += gap
        lines.append(json.dumps({"t": t, "tokens": 1000}))
    (usage / "model.jsonl").write_text("\n".join(lines) + "\n")
    if summary is not None:
        (run / "pypi-run").mkdir()
        (run / "pypi-run" / "pypi-extract-x-summary.json").write_text(json.dumps(summary))
    return run


INFO = {"patchsight_commit": "f5c053ed214b609e5e85", "model_repo": "org/Model-GGUF",
        "model_file": "m.gguf", "gpus": ["Tesla T4, 15360 MiB"], "mode": "pypi",
        "shard": "3/4"}  # fmt: skip


def test_a_backfill_session_from_its_ledger_and_summary(tmp_path: Path) -> None:
    summary = {"vulnerabilities": 10, "complete": True, "status": {"ok": 7, "dead_letter": 1},
               "truncated": 2, "prompt_tokens": 9000, "completion_tokens": 900,
               "provider_rejections": 1, "skipped": {"no_python_fix": 2}}  # fmt: skip
    run = _run(tmp_path, "patchsight-kaggle-run-pypi-shard3of4", INFO, [30, 30, 60, 3600], summary)
    session = sessions.load_session(run)
    assert session is not None
    assert (session.mode, session.part, session.calls, session.tokens) == ("pypi", "3/4", 5, 5000)
    assert session.hours == round(3720 / 3600, 2)
    assert (session.seconds_per_call_p50, session.seconds_per_call_p90) == (45.0, 3600.0)
    assert session.code_commit == "f5c053ed214b"
    assert session.model == "org/Model-GGUF:m.gguf"
    assert (session.answered, session.dead_letter_rate) == (8, 0.125)
    assert session.first_answer == datetime.fromtimestamp(START, UTC)


def test_early_runs_without_a_mode_or_a_ledger(tmp_path: Path) -> None:
    early = {k: v for k, v in INFO.items() if k not in ("mode", "shard")} | {"split": "all"}
    session = sessions.load_session(_run(tmp_path, "patchsight-kaggle-run", early, [20]))
    assert session is not None
    assert (session.mode, session.part, session.status, session.dead_letter_rate) == (
        "dunlap", "all", {}, None,
    )  # fmt: skip
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "run-info.json").write_text(json.dumps(INFO))
    assert sessions.load_session(empty) is None  # no model call, no session


def test_sessions_are_ordered_and_counted_by_iso_week(tmp_path: Path) -> None:
    _run(tmp_path, "b", INFO, [1800] * 4)
    later = tmp_path / "later"
    _run(tmp_path, "later", INFO, [3600])
    ledger = later / ".cache" / "llm" / "usage" / "model.jsonl"
    week_later = START + 7 * 86400
    ledger.write_text("".join(json.dumps({"t": week_later + i * 3600, "tokens": 5}) + "\n"
                              for i in range(3)))  # fmt: skip
    found = sessions.load_sessions(tmp_path)
    assert [s.name for s in found] == ["b", "later"]
    weeks = sessions.gpu_weeks(found)
    assert [(w.week, w.hours, w.sessions) for w in weeks] == [
        ("2026-W47", 2.0, 1), ("2026-W48", 2.0, 1),
    ]  # fmt: skip


def test_daily_use_against_a_cap() -> None:
    day = datetime(2026, 11, 18, 23, 0, tzinfo=UTC).timestamp()
    entries = [sessions.LedgerEntry(t=day, tokens=150_000),
               sessions.LedgerEntry(t=day + 7200, tokens=50_000),
               sessions.LedgerEntry(t=day + 7300, tokens=20_000)]  # fmt: skip
    use = sessions.daily_use(entries, 200_000)
    assert [(u.day, u.calls, u.tokens, u.share_of_cap) for u in use] == [
        (date(2026, 11, 18), 1, 150_000, 0.75), (date(2026, 11, 19), 2, 70_000, 0.35),
    ]  # fmt: skip
    assert sessions.daily_use(entries, None)[0].share_of_cap is None


def test_a_missing_ledger_is_empty(tmp_path: Path) -> None:
    assert sessions.load_ledger(tmp_path / "absent.jsonl") == []
