"""The markdown report for a pull-request comment or a job summary."""

from datetime import UTC, datetime

from patchsight.scan.ast_scanner import Location
from patchsight.scan.lockfiles import Dependency
from patchsight.scan.report import MARKDOWN_MARKER, render_markdown
from patchsight.scan.verdicts import Alert

NOW = datetime(2026, 11, 20, tzinfo=UTC)
META = {"db_version": "2026.11.20", "built_at": NOW.isoformat(), "builder": "llm-v1"}
DEPENDENCIES = [
    Dependency(name="pyyaml", raw_name="PyYAML", version="5.3.1", source="requirements.txt",
               line=1),
    Dependency(name="flask", raw_name="flask", version=None, source="requirements.txt", line=2,
               unpinned_reason="no exact pin"),
]  # fmt: skip


def _alert(advisory: str, verdict: str, reason: str = "r", **extra: object) -> Alert:
    return Alert.model_validate(
        {"advisory": advisory, "package": "pyyaml", "version": "5.3.1", "verdict": verdict,
         "reason": reason, **extra}
    )  # fmt: skip


def test_the_report_counts_every_verdict_and_lists_called_first() -> None:
    alerts = [
        _alert("GHSA-u", "UNKNOWN", "symbol data is low confidence"),
        _alert("GHSA-c", "CALLED", aliases=("CVE-2020-14343",), matched=("yaml.full_load",),
               evidence=(Location(path="app/config.py", line=4),)),
        _alert("GHSA-n", "NOT_IMPORTED", "your code never imports yaml"),
    ]  # fmt: skip
    text = render_markdown(alerts, DEPENDENCIES, "requirements.txt", META, now=NOW)
    assert text.splitlines()[0] == MARKDOWN_MARKER
    assert "## PatchSight: 3 dependency alerts" in text
    for line in ("| 🔴 | CALLED (fix first) | 1 |", "| 🟢 | IMPORTED, NOT CALLED | 0 |",
                 "| ⚪ | NOT IMPORTED (transitive only) | 1 |"):  # fmt: skip
        assert line in text
    assert (
        "| GHSA-c (CVE-2020-14343) | pyyaml 5.3.1 | `yaml.full_load` | `app/config.py:4` |" in text
    )
    assert text.index("### 🔴") < text.index("<details><summary>⚪") < text.index("<summary>🟡")
    assert "Not checked, no exact pin: flask" in text
    assert "no alert is hidden" in text


def test_untrusted_text_cannot_break_the_table_or_inject_html() -> None:
    alert = _alert("GHSA-x", "UNKNOWN", "a | b\nc <img src=x onerror=alert(1)>")
    text = render_markdown([alert], DEPENDENCIES, "requirements.txt", META, now=NOW)
    row = next(line for line in text.splitlines() if line.startswith("| GHSA-x"))
    assert "a \\| b c &lt;img" in row
    assert "<img" not in text


def test_a_long_list_stays_under_the_limit_and_says_what_it_left_out() -> None:
    called = [_alert(f"GHSA-c{i:03d}", "CALLED", matched=("yaml.load",)) for i in range(5)]
    unknown = [_alert(f"GHSA-u{i:03d}", "UNKNOWN", "x" * 200) for i in range(300)]
    text = render_markdown(called + unknown, DEPENDENCIES, "requirements.txt", META, now=NOW,
                           limit=8_000)  # fmt: skip
    assert len(text) <= 8_000
    assert all(f"GHSA-c{i:03d}" in text for i in range(5))  # the urgent rows are all kept
    assert "| 🟡 | UNKNOWN (no symbol data, low confidence, or dynamic use) | 300 |" in text
    listed = sum(line.startswith("| GHSA-u") for line in text.splitlines())
    assert 0 < listed < 300
    assert f"| … | {300 - listed} more | | |" in text
    assert f"{300 - listed} alerts are counted above but not listed" in text


def test_a_stale_database_is_flagged() -> None:
    old = {**META, "built_at": "2026-11-01T00:00:00+00:00"}
    text = render_markdown([], DEPENDENCIES, "requirements.txt", old, now=NOW)
    assert "> [!WARNING]" in text
    assert "## PatchSight: 0 dependency alerts" in text
