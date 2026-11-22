"""The operations dashboard (#60): sessions, quota and the database, offline."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchsight import db
from patchsight.pipeline import operations
from patchsight.pipeline.__main__ import app

REPO = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 20, tzinfo=UTC)


def _record(key: str, source: str, reason: str | None, second: str | None = None) -> db.Record:
    return db.Record(
        vulnerability=key, package="pkg", confidence="low", source=source,  # type: ignore[arg-type]
        import_roots=("pkg",), entry_points=(), symbols=(), fix_commits=(), model=None,
        prompt_version=None, input_hash="h", advisory_modified=NOW, truncated=False,
        extracted_at=NOW, second_opinion_model=second, tier_reason=reason,
    )  # fmt: skip


def _database(path: Path, second: str | None = None) -> Path:
    records = [_record("GHSA-1", "llm", "no valid second opinion"),
               _record("GHSA-2", "llm", "the two models disagree", second),
               _record("GHSA-3", "fallback", None)]  # fmt: skip
    builds = [db.BuildEntry(vulnerability=k, input_hash="h", status=s)
              for k, s in (("GHSA-1", "built"), ("GHSA-2", "built"), ("GHSA-3", "built"),
                           ("GHSA-4", "no_python_fix"))]  # fmt: skip
    db.write(path, records, {f"GHSA-{i}": f"GHSA-{i}" for i in range(1, 4)},
             {"db_version": "2026.11.20"}, builds=builds)  # fmt: skip
    return path


def test_the_database_view_counts_sources_reasons_and_the_ledger(tmp_path: Path) -> None:
    view = operations.database_view(_database(tmp_path / "db.sqlite", second="m2"))
    assert view.db_version == "2026.11.20"
    assert view.records == {"llm, low": 2, "fallback, low": 1}
    assert view.tier_reasons == {"no valid second opinion": 1, "the two models disagree": 1}
    assert view.second_opinions == 1
    assert view.builds == {"built": 3, "no_python_fix": 1}


def test_the_agreement_rate_is_not_claimed_without_second_opinions(tmp_path: Path) -> None:
    view = operations.database_view(_database(tmp_path / "db.sqlite"))
    report = operations.OperationsReport(
        generated_at=NOW, sessions=(), weeks=(), hosted=(), database=view
    )
    text = operations.render_markdown(report)
    assert "0 records have a second opinion so far, so the rate is not measured yet" in text
    assert "| llm, low | 2 |" in text


def test_the_command_reads_runs_ledgers_and_the_database(tmp_path: Path) -> None:
    run = tmp_path / "data" / "interim" / "kaggle" / "patchsight-kaggle-run-pypi-shard1of4"
    (run / ".cache" / "llm" / "usage").mkdir(parents=True)
    (run / "run-info.json").write_text(json.dumps(
        {"patchsight_commit": "abc1234def", "model_repo": "org/M", "model_file": "m.gguf",
         "gpus": [], "mode": "pypi", "shard": "1/4"}))  # fmt: skip
    start = NOW.timestamp()
    (run / ".cache" / "llm" / "usage" / "m.jsonl").write_text(
        "".join(json.dumps({"t": start + 30 * i, "tokens": 100}) + "\n" for i in range(4))
    )
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "llm.toml").write_text((REPO / "configs" / "llm.toml").read_text())
    usage = tmp_path / ".cache" / "llm" / "usage"
    usage.mkdir(parents=True)
    (usage / "qwen__qwen3.8-27b.jsonl").write_text(
        json.dumps({"t": start, "tokens": 50_000}) + "\n"
    )
    (tmp_path / "docs" / "reports").mkdir(parents=True)
    result = CliRunner().invoke(app, [
        "operations-report", "--root", str(tmp_path),
        "--db", str(_database(tmp_path / "db.sqlite")),
    ])  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "1 Kaggle sessions, 0.0 hours; 1 hosted models" in result.output
    text = (tmp_path / "docs" / "reports" / "operations.md").read_text()
    assert "| pypi | 1/4 | `abc1234` | 2026-11-20 00:00 | 0.03 | 4 | 30 / 30 | 400 |" in text
    assert "### `qwen/qwen3.8-27b`, cap 200,000 tokens a day" in text
    assert "| 2026-11-20 | 1 | 50,000 | 25% |" in text


def test_the_committed_report_renders_from_its_json() -> None:
    source = REPO / "docs" / "reports" / "operations.json"
    if not source.exists():
        pytest.skip("no committed operations report")
    report = operations.OperationsReport.model_validate_json(source.read_text())
    assert operations.render_markdown(report) == source.with_suffix(".md").read_text()


def test_traced_runs_are_listed_with_where_they_ran(tmp_path: Path) -> None:
    from patchsight.pipeline.sessions import TracedRun

    run = TracedRun(
        trace="t.jsonl", command="pypi-extract", role="second_opinion", model="m", started=NOW,
        outcome=None, seconds=None, calls=3, network_calls=2, cache_hits=1, rejections=1,
        extractions={"ok": 2}, latency_p50=12.0, latency_p90=40.0,
        completion_tokens_per_second=55.5,
    )  # fmt: skip
    report = operations.OperationsReport(
        generated_at=NOW, sessions=(), weeks=(), hosted=(), database=None, local_runs=(run,)
    )
    text = operations.render_markdown(report)
    assert (
        "| this machine | pypi-extract | second_opinion | 2026-11-20 00:00 | no end (killed) | — "
        "| 2 / 1 | 1 | ok 2 | 12 / 40 | 55.5 |"
    ) in text
    empty = operations.OperationsReport(generated_at=NOW, sessions=(), weeks=(), hosted=(),
                                        database=None)  # fmt: skip
    assert "No traced run yet." in operations.render_markdown(empty)


def test_work_is_priced_as_its_hosted_model_at_published_rates() -> None:
    from datetime import date

    from patchsight.pipeline.nightly_runs import NightlyRun
    from patchsight.pipeline.sessions import Session

    pricing = operations.Pricing(
        source="https://example.org/prices", retrieved=date(2026, 11, 22),
        models={"qwen/q": operations.Price(input=0.80, output=4.00)},
        hosted_equivalent={"repo:q.gguf": "qwen/q"},
    )  # fmt: skip
    when = datetime(2026, 11, 21, tzinfo=UTC)

    def session(mode: str, prompt: int | None, completion: int | None) -> Session:
        return Session(name="s", mode=mode, part="1/4", model="repo:q.gguf", code_commit="c",
                       gpus=(), first_answer=when, last_answer=when, hours=1.0, calls=10,
                       tokens=0, seconds_per_call_p50=1.0, seconds_per_call_p90=1.0,
                       status={"ok": 9, "dead_letter": 1}, prompt_tokens=prompt,
                       completion_tokens=completion)  # fmt: skip

    night = NightlyRun(run_id=1, event="schedule", conclusion="success", started=when,
                       extraction={"ok": 2}, extraction_model="qwen/q",
                       prompt_tokens=500_000, completion_tokens=50_000)  # fmt: skip
    found = operations.costs(
        [session("pypi", 1_000_000, 100_000), session("pypi", 1_000_000, 100_000),
         session("dunlap", None, None)],  # no split of its tokens: not priced
        [night, night.model_copy(update={"extraction_model": "unpriced/model"})],
        pricing,
    )  # fmt: skip
    assert [(c.what, c.priced_as, c.usd, c.units, c.unit) for c in found] == [
        ("PyPI backfill (2 Kaggle sessions)", "qwen/q", 2.40, 20, "vulnerability"),
        ("Nightly extraction (1 night)", "qwen/q", 0.60, 1, "night"),
    ]  # 2M input at $0.80 and 0.2M output at $4.00; 0.5M and 0.05M
    report = operations.OperationsReport(
        generated_at=when, sessions=(), weeks=(), hosted=(), database=None,
        pricing_source=pricing.source, pricing_retrieved=pricing.retrieved, costs=tuple(found),
    )  # fmt: skip
    text = operations.render_markdown(report)
    assert "| PyPI backfill (2 Kaggle sessions) | `qwen/q` | 2,000,000 | 200,000 | $2.40 |" in text
    assert "$0.1200 a vulnerability" in text
