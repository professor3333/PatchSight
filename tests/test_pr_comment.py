"""The Action's pull-request comment (scripts/pr-comment.sh), run against a stub gh."""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pr-comment.sh"
STUB = """#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$*" in
  *--paginate*) [ -n "${GH_EXISTING:-}" ] && echo "$GH_EXISTING"; exit "${GH_READ_FAILS:-0}" ;;
  *) exit "${GH_WRITE_FAILS:-0}" ;;
esac
"""


Run = tuple[subprocess.CompletedProcess[str], list[str]]


def _run(tmp_path: Path, report: str | None = "<!-- patchsight -->\n## PatchSight\n",
         number: str = "12", **env: str) -> Run:  # fmt: skip
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "gh").write_text(STUB)
    (bin_dir / "gh").chmod(0o755)
    path = tmp_path / "report.md"
    if report is not None:
        path.write_text(report)
    log = tmp_path / "gh.log"
    result = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, check=False,  # noqa: S607
        env={"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "GH_LOG": str(log),
             "GH_TOKEN": "t", "REPOSITORY": "owner/repo", "NUMBER": number,
             "REPORT": str(path), **env},
    )  # fmt: skip
    calls = log.read_text().splitlines() if log.exists() else []
    return result, calls


def test_a_first_report_is_posted(tmp_path: Path) -> None:
    result, calls = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Posted a pull-request comment." in result.stdout
    assert calls[0].startswith("api repos/owner/repo/issues/12/comments --paginate")
    assert calls[1] == f"api repos/owner/repo/issues/12/comments -F body=@{tmp_path / 'report.md'}"


def test_a_later_push_updates_the_same_comment(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, GH_EXISTING="987")
    assert "Updated the pull-request comment (987)." in result.stdout
    assert calls[1].startswith("api --method PATCH repos/owner/repo/issues/comments/987 -F body=@")
    assert len(calls) == 2


@pytest.mark.parametrize("failing", ["GH_READ_FAILS", "GH_WRITE_FAILS"])
def test_a_read_only_token_warns_and_never_fails_the_job(tmp_path: Path, failing: str) -> None:
    result, _ = _run(tmp_path, **{failing: "1"})
    assert result.returncode == 0
    assert "::warning::PatchSight could not" in result.stdout
    assert "pull-requests: write" in result.stdout


@pytest.mark.parametrize(
    ("report", "number"),
    [(None, "12"), ("not a PatchSight report\n", "12"), ("<!-- patchsight -->\n", "12; rm -rf /")],
)
def test_nothing_is_posted_without_a_report_or_a_pull_request(
    tmp_path: Path, report: str | None, number: str
) -> None:
    result, calls = _run(tmp_path, report=report, number=number)
    assert result.returncode == 0
    assert "::warning::" in result.stdout
    assert calls == []
