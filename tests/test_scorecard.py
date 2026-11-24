"""The success-targets table in docs/evaluation.md, read from the committed reports only."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchsight.eval import scorecard
from patchsight.pipeline.llm.config import load_config
from patchsight.pipeline.nightly_runs import NightlyRun
from patchsight.pipeline.operations import OperationsReport

REPO = Path(__file__).resolve().parents[1]


def test_the_committed_table_is_what_the_reports_give() -> None:
    dotted = load_config(REPO / "configs" / "llm.toml").validation.dotted_entry_points
    page = (REPO / scorecard.PAGE).read_text("utf-8")
    card = scorecard.build(REPO, dotted=dotted)
    assert scorecard.fill(page, scorecard.render(card)) == page, (
        "docs/evaluation.md is stale: run python -m patchsight.pipeline scorecard"
    )
    assert len(card.targets) == 13  # every target in proposal §8
    assert all(row.sources for row in card.targets)


def test_the_newest_published_database_counts_and_a_shadow_never(tmp_path: Path) -> None:
    for name in ("panel-db-2026.11.9", "panel-db-2026.11.18", "panel-db-2026.11.18.1",
                 "panel-db-2026.11.23-shadow-dotted", "other-panel-db-2026.12.1"):  # fmt: skip
        (tmp_path / f"{name}.json").write_text("{}")
    assert scorecard.latest(tmp_path, "panel").name == "panel-db-2026.11.18.1.json"
    with pytest.raises(FileNotFoundError):
        scorecard.latest(tmp_path, "reachability-fixtures")


def test_only_the_marked_section_is_replaced() -> None:
    page = f"intro\n{scorecard.START}\nold\n{scorecard.END}\nafter\n"
    assert scorecard.fill(page, f"{scorecard.START}\nnew\n{scorecard.END}") == (
        f"intro\n{scorecard.START}\nnew\n{scorecard.END}\nafter\n"
    )
    with pytest.raises(ValueError, match="no"):
        scorecard.fill("a page without the markers", "table")


def _operations(tmp_path: Path, nights: list[dict[str, int]]) -> Path:
    when = datetime(2026, 11, 23, tzinfo=UTC)
    runs = tuple(NightlyRun(run_id=i, event="schedule", conclusion="success", started=when,
                            extraction=n) for i, n in enumerate(nights))  # fmt: skip
    report = OperationsReport(generated_at=when, sessions=(), weeks=(), hosted=(),
                              database=None, nightly=runs)  # fmt: skip
    (tmp_path / "operations.json").write_text(report.model_dump_json())
    return tmp_path


def test_the_nightly_rate_counts_only_nights_that_extracted(tmp_path: Path) -> None:
    row = scorecard.nightly_dead_letters(_operations(tmp_path, [{}, {}]))
    assert (row.measured, row.status) == ("—", "not measured yet")
    row = scorecard.nightly_dead_letters(
        _operations(tmp_path, [{}, {"ok": 24, "repaired": 1}, {"ok": 23, "dead_letter": 2}])
    )
    assert (row.measured, row.status) == ("4.0% (2 of 50) over 2 nights", "missed")
    row = scorecard.nightly_dead_letters(_operations(tmp_path, [{"ok": 99, "dead_letter": 1}]))
    assert row.status == "met"  # 1.0%: under 2%
