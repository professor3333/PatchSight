"""The repository panel: its definition, checkout, measurement and report, offline."""

import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchsight import db
from patchsight.eval import panel
from patchsight.scan import run

REPO = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 18, tzinfo=UTC)


def test_the_committed_panel_is_pinned_and_scannable() -> None:
    repos = panel.load(REPO / panel.PANEL)
    assert len(repos) == 20
    assert len({r.name for r in repos}) == 20
    for repo in repos:
        assert re.fullmatch(r"[0-9a-f]{40}", repo.commit), repo.name
        assert repo.url.startswith("https://github.com/"), repo.name
        name = Path(repo.lockfile).name
        assert name in ("poetry.lock", "uv.lock") or name.endswith(".txt"), repo.name


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.org", *args],  # noqa: S607
        cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip


def _project(tmp_path: Path) -> panel.Repo:
    source = tmp_path / "source"
    source.mkdir()
    (source / "requirements.txt").write_text("PyYAML==5.3.1\nrequests==2.31.0\nflask>=2\n")
    (source / "app.py").write_text("import yaml\n\ndef f(s):\n    return yaml.full_load(s)\n")
    _git("init", "-q", cwd=source)
    _git("add", ".", cwd=source)
    _git("commit", "-q", "-m", "x", cwd=source)
    _git("config", "uploadpack.allowReachableSHA1InWant", "true", cwd=source)
    commit = _git("rev-parse", "HEAD", cwd=source)
    return panel.Repo(name="demo", url=source.as_uri(), commit=commit, lockfile="requirements.txt")


def test_checkout_fetches_the_pinned_commit_once(tmp_path: Path) -> None:
    repo = _project(tmp_path)
    path = panel.checkout(repo, tmp_path / "cache", partial=False)
    assert (path / "app.py").exists()
    assert _git("rev-parse", "HEAD", cwd=path) == repo.commit
    (path / "marker").write_text("kept")
    assert panel.checkout(repo, tmp_path / "cache", partial=False) == path
    assert (path / "marker").exists()  # an up-to-date checkout is reused


def test_measure_counts_coverage_verdicts_and_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _project(tmp_path)
    path = panel.checkout(repo, tmp_path / "cache", partial=False)
    record = db.Record(
        vulnerability="GHSA-0001", package="pyyaml", confidence="low", source="fallback",
        import_roots=("yaml",), entry_points=(),
        symbols=(db.Symbol(qualified_name="yaml.full_load", module="yaml", name="full_load",
                           kind="function", path="lib/yaml/__init__.py"),),
        fix_commits=(db.FixCommitRef(repo="yaml/pyyaml", sha="a" * 40),), model=None,
        prompt_version=None, input_hash="h", advisory_modified=NOW, truncated=False,
        extracted_at=NOW,
    )  # fmt: skip
    database = tmp_path / "db.sqlite"
    db.write(database, [record], {"GHSA-0001": "GHSA-0001"}, {"db_version": "2026.11.18"})
    monkeypatch.setattr(
        run.osv_client,
        "query",
        lambda packages, client=None: {
            p: (["GHSA-0001"] if p[0] == "pyyaml" else ["GHSA-none"]) for p in packages
        },
    )
    result = panel.measure(repo, path, database, runs=3)
    assert (result.dependencies, result.pinned, result.python_files) == (3, 2, 1)
    assert (result.alerts, result.with_data) == (2, 1)
    assert result.verdicts == {
        "CALLED": 1, "IMPORTED_NOT_CALLED": 0, "NOT_IMPORTED": 0, "UNKNOWN": 1,
    }  # fmt: skip
    assert result.unknown_reasons == {"no symbol data for the advisory": 1}
    assert len(result.seconds) == 3

    report = panel.PanelReport(
        panel=panel.PANEL.as_posix(), db_version="2026.11.18", machine=panel.machine(),
        measured_at="2026-11-18", runs=3, results=(result,),
    )  # fmt: skip
    text = panel.render_markdown(report)
    assert "| Alerts with symbol data | **50.0%** (1 of 2) | 50% or more |" in text
    assert "0 repositories with 200 or more dependencies" in text
    assert "| no symbol data for the advisory | 1 | 1 |" in text
    assert panel.unknown_reason("a dynamic import with a computed name could load it") == (
        "a computed dynamic import somewhere in the code"
    )
    assert "host" not in panel.machine().lower()


def test_latency_percentiles() -> None:
    def result(dependencies: int, seconds: tuple[float, ...]) -> panel.RepoResult:
        return panel.RepoResult(
            name="r", commit="0" * 40, lockfile="requirements.txt", dependencies=dependencies,
            pinned=dependencies, python_files=1, alerts=0, with_data=0, verdicts={},
            seconds=seconds, code_scan_seconds=0.1,
        )  # fmt: skip

    report = panel.PanelReport(
        panel="p", db_version="v", machine="m", measured_at="d", runs=10,
        results=(result(10, tuple(float(i) for i in range(1, 11))), result(300, (20.0,))),
    )  # fmt: skip
    p50, p95, scans = report.latency()
    assert (p50, scans) == (6.0, 11)
    assert 10.0 < p95 <= 20.0
    assert report.latency(200) == (20.0, 20.0, 1)
    assert report.latency(1000) == (0.0, 0.0, 0)


def test_the_committed_report_renders_from_its_json() -> None:
    reports = sorted((REPO / "docs" / "reports").glob("panel-db-*.json"))
    assert reports
    for source in reports:
        report = panel.PanelReport.model_validate_json(source.read_text())
        assert panel.render_markdown(report) == source.with_suffix(".md").read_text()
