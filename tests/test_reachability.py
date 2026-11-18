"""Reachability fixtures: the manifest, the labelled run, its report and the pins."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from packaging.version import Version
from typer.testing import CliRunner

from patchsight import db
from patchsight.eval import reachability
from patchsight.pipeline.__main__ import app
from patchsight.scan import osv_client

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / reachability.FIXTURES
LOCKFILES = {"requirements.txt", "uv.lock", "poetry.lock", "pyproject.toml", "Pipfile"}


@pytest.fixture(scope="module")
def fixtures() -> reachability.Fixtures:
    return reachability.load(FIXTURES)


def test_the_manifest_matches_the_programs(fixtures: reachability.Fixtures) -> None:
    names = [c.name for c in fixtures.cases]
    assert len(names) == len(set(names))
    directories = {p.name for p in FIXTURES.iterdir() if p.is_dir()}
    assert directories == set(names)
    assert {c.advisory for c in fixtures.cases} == set(fixtures.advisories)
    for case in fixtures.cases:
        files = [p for p in (FIXTURES / case.name).rglob("*") if p.is_file()]
        assert any(p.suffix == ".py" for p in files), case.name
        assert not LOCKFILES.intersection(p.name for p in files), case.name
    for advisory in fixtures.advisories.values():
        assert str(Version(advisory.version)) == advisory.version
        reachability.labelled_record(advisory)  # every symbol is module:qualname under a root
    assert 40 <= len(fixtures.cases) <= 60
    calling = sum(c.calls for c in fixtures.cases)
    assert 0 < calling < len(fixtures.cases)


def test_labelled_data_gives_no_false_suppression(fixtures: reachability.Fixtures) -> None:
    result = reachability.run_labelled(fixtures, FIXTURES)
    assert result.false_suppressions == []
    assert [o.case for o in result.outcomes if not o.as_expected] == []


def _root(tmp_path: Path) -> Path:
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / reachability.FIXTURES).symlink_to(FIXTURES)
    (tmp_path / "docs" / "reports").mkdir(parents=True)
    return tmp_path


def test_the_committed_labelled_report_regenerates_exactly(tmp_path: Path) -> None:
    root = _root(tmp_path)
    result = CliRunner().invoke(app, ["reachability-report", "--root", str(root)])
    assert result.exit_code == 0, result.output
    for suffix in (".md", ".json"):
        name = f"reachability-fixtures-labelled{suffix}"
        produced = (root / "docs" / "reports" / name).read_text()
        assert produced == (REPO / "docs" / "reports" / name).read_text()


def test_a_database_run_looks_records_up_by_alias(
    tmp_path: Path, fixtures: reachability.Fixtures
) -> None:
    advisory = fixtures.advisories["GHSA-v845-jxx5-vc9f"]
    low = reachability.labelled_record(advisory).model_copy(
        update={"vulnerability": "PYSEC-0000-1", "confidence": "low", "source": "fallback"}
    )
    database = tmp_path / "db.sqlite"
    db.write(database, [low], {advisory.id: "PYSEC-0000-1"},
             {"db_version": "2026.1.1", "built_at": datetime.now(UTC).isoformat()})  # fmt: skip
    result = reachability.run_database(fixtures, FIXTURES, database)
    assert result.data == "database 2026.1.1"
    by_case = {o.case: o for o in result.outcomes}
    assert by_case["urllib3-poolmanager"].confidence == "low"
    assert by_case["urllib3-retry-reexport"].verdict == "CALLED"  # low data can raise
    assert by_case["urllib3-parse-url"].verdict == "UNKNOWN"  # but never lower
    assert by_case["pyyaml-full-load"].verdict == "UNKNOWN"  # no record
    assert result.false_suppressions == []

    root = _root(tmp_path / "root")
    cli = CliRunner().invoke(
        app, ["reachability-report", "--db", str(database), "--root", str(root)]
    )
    assert cli.exit_code == 0, cli.output
    text = (root / "docs" / "reports" / "reachability-fixtures-db-2026.1.1.md").read_text()
    assert "| Labelled data | This database |" in text


@pytest.mark.live
def test_every_pin_is_affected_by_its_advisory(fixtures: reachability.Fixtures) -> None:
    pins = [(a.package, a.version) for a in fixtures.advisories.values()]
    found = osv_client.query(pins)
    for advisory in fixtures.advisories.values():
        assert advisory.id in found.get((advisory.package, advisory.version), []), advisory.id


def test_pytest_never_collects_a_fixture_program() -> None:
    assert not [p for p in FIXTURES.rglob("*.py") if p.name.startswith("test_")]
