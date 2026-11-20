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
