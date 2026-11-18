"""SARIF 2.1.0 output: every alert is a result, ranked by level, with stable identities."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from patchsight import db
from patchsight.cli import app
from patchsight.scan import run
from patchsight.scan.ast_scanner import Location
from patchsight.scan.lockfiles import Dependency
from patchsight.scan.sarif import FINGERPRINT, LEVELS, render_sarif, uri
from patchsight.scan.verdicts import Alert

META = {"db_version": "2026.11.18", "builder": "llm-v1", "built_at": datetime.now(UTC).isoformat()}
DEPENDENCIES = [
    Dependency(name="pyyaml", raw_name="PyYAML", version="5.3.1", source="requirements.txt",
               line=3),
    Dependency(name="requests", raw_name="requests", version="2.31.0", source="requirements.txt",
               line=4),
    Dependency(name="flask", raw_name="flask", version=None, source="requirements.txt", line=5,
               unpinned_reason="no exact pin"),
]  # fmt: skip
ALERTS = [
    Alert(advisory="GHSA-aaaa-aaaa-aaaa", aliases=("CVE-2020-14343",), package="pyyaml",
          version="5.3.1", verdict="CALLED", reason="references a vulnerable symbol",
          evidence=(Location(path="app/config.py", line=4), Location(path="app/cli.py", line=9)),
          matched=("yaml.full_load",), confidence="low"),
    Alert(advisory="GHSA-bbbb-bbbb-bbbb", package="requests", version="2.31.0",
          verdict="UNKNOWN", reason="no symbol data"),
    Alert(advisory="GHSA-cccc-cccc-cccc", package="requests", version="2.31.0",
          verdict="NOT_IMPORTED", reason="never imported"),
]  # fmt: skip


def _sarif(alerts: list[Alert] = ALERTS, base: str = "") -> dict[str, Any]:
    return json.loads(render_sarif(alerts, DEPENDENCIES, "requirements.txt", META, base))


def _assert_valid(log: dict[str, Any]) -> None:
    """The SARIF 2.1.0 required properties, for everything this renderer emits."""
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    (run_,) = log["runs"]
    driver = run_["tool"]["driver"]
    assert driver["name"] == "PatchSight"
    assert driver["semanticVersion"]
    rule_ids = [r["id"] for r in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["helpUri"].startswith("https://")
    for result in run_["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        assert result["level"] in {"none", "note", "warning", "error"}
        assert result["message"]["text"].strip()
        assert result["locations"], "code scanning needs a location for every result"
        for location in result["locations"] + result.get("relatedLocations", []):
            physical = location["physicalLocation"]
            assert physical["artifactLocation"]["uri"]
            assert physical["region"]["startLine"] >= 1
        ids = [loc["id"] for loc in result.get("relatedLocations", [])]
        assert len(ids) == len(set(ids))
        assert result["partialFingerprints"][FINGERPRINT]


def test_every_alert_is_a_valid_result() -> None:
    log = _sarif()
    _assert_valid(log)
    results = log["runs"][0]["results"]
    assert len(results) == len(ALERTS)  # rank, never hide
    assert [r["properties"]["verdict"] for r in results] == ["CALLED", "NOT_IMPORTED", "UNKNOWN"]


def test_levels_rank_called_first_and_never_drop_an_alert() -> None:
    assert LEVELS == {
        "CALLED": "error", "UNKNOWN": "warning", "IMPORTED_NOT_CALLED": "note",
        "NOT_IMPORTED": "note",
    }  # fmt: skip
    levels = {r["ruleId"]: r["level"] for r in _sarif()["runs"][0]["results"]}
    assert levels == {
        "GHSA-aaaa-aaaa-aaaa": "error", "GHSA-bbbb-bbbb-bbbb": "warning",
        "GHSA-cccc-cccc-cccc": "note",
    }  # fmt: skip


def test_called_points_at_the_code_and_the_rest_at_the_lockfile() -> None:
    called, not_imported, unknown = _sarif(base="services/api")["runs"][0]["results"]
    primary = called["locations"][0]["physicalLocation"]
    assert primary["artifactLocation"]["uri"] == "services/api/app/config.py"
    assert primary["region"]["startLine"] == 4
    related = [
        loc["physicalLocation"]["artifactLocation"]["uri"] for loc in called["relatedLocations"]
    ]
    assert related == ["services/api/app/cli.py", "requirements.txt"]
    for result in (not_imported, unknown):
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "requirements.txt"
        assert location["region"]["startLine"] == 4  # the requests pin
    assert "also CVE-2020-14343" in called["message"]["text"]
    assert "Matched: yaml.full_load." in called["message"]["text"]


def test_identity_survives_a_version_bump_and_moved_lines() -> None:
    before = _sarif()["runs"][0]["results"][0]["partialFingerprints"]
    bumped = ALERTS[0].model_copy(
        update={"version": "5.4", "evidence": (Location(path="x.py", line=1),)}
    )
    after = _sarif([bumped])["runs"][0]["results"][0]["partialFingerprints"]
    assert before == after
    other = ALERTS[0].model_copy(update={"package": "other"})
    assert _sarif([other])["runs"][0]["results"][0]["partialFingerprints"] != before


def test_run_properties_keep_the_database_unpinned_packages_and_the_caveat() -> None:
    properties = _sarif()["runs"][0]["properties"]
    assert properties["database"]["db_version"] == "2026.11.18"
    assert [u["name"] for u in properties["unpinned"]] == ["flask"]
    assert "no alert is hidden" in properties["note"]
    stale = json.loads(render_sarif(ALERTS, DEPENDENCIES, "requirements.txt",
                                    {**META, "built_at": "2026-01-01T00:00:00+00:00"}))  # fmt: skip
    (notice,) = stale["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notice["level"] == "warning"
    assert "days old" in notice["message"]["text"]


@pytest.mark.parametrize(
    ("path", "base", "expected"),
    [
        ("app/x.py", "", "app/x.py"),
        ("app/x.py", ".", "app/x.py"),
        ("app/x.py", "src", "src/app/x.py"),
        ("x.py", "../other", "../other/x.py"),
        ("/abs/x.py", "", "file:///abs/x.py"),
    ],
)
def test_uris_stay_relative_to_where_the_scan_runs(path: str, base: str, expected: str) -> None:
    assert uri(path, base) == expected


def test_scan_cli_writes_sarif(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    (project / "app").mkdir(parents=True)
    (project / "requirements.txt").write_text("PyYAML==5.3.1\n")
    (project / "app/config.py").write_text("import yaml\n\nyaml.full_load(open('c'))\n")
    record = db.Record(
        vulnerability="GHSA-0001-0001-0001", package="pyyaml", confidence="low",
        source="fallback", import_roots=("yaml",), entry_points=("yaml.full_load",),
        symbols=(db.Symbol(qualified_name="yaml.full_load", module="yaml", name="full_load",
                           kind="function", path="lib/yaml/__init__.py"),),
        fix_commits=(db.FixCommitRef(repo="yaml/pyyaml", sha="a" * 40),), model=None,
        prompt_version=None, input_hash="h", advisory_modified=datetime.now(UTC),
        truncated=False, extracted_at=datetime.now(UTC),
    )  # fmt: skip
    database = tmp_path / "db.sqlite"
    db.write(database, [record], {"GHSA-0001-0001-0001": "GHSA-0001-0001-0001"}, META)
    monkeypatch.setattr(
        run.osv_client,
        "query",
        lambda packages, client=None: {p: ["GHSA-0001-0001-0001"] for p in packages},
    )
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app, ["scan", "project", "--db", str(database), "--format", "sarif"]
    )
    assert result.exit_code == 0, result.output
    log = json.loads(result.output)
    _assert_valid(log)
    (only,) = log["runs"][0]["results"]
    assert only["level"] == "error"
    location = only["locations"][0]["physicalLocation"]
    assert (location["artifactLocation"]["uri"], location["region"]["startLine"]) == (
        "project/app/config.py", 3,
    )  # fmt: skip
