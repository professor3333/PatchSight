import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchsight import db

NOW = datetime(2026, 11, 15, tzinfo=UTC)


def _record(**overrides: object) -> db.Record:
    fields: dict[str, object] = {
        "vulnerability": "GHSA-0001-0001-0001",
        "package": "pyyaml",
        "confidence": "low",
        "source": "fallback",
        "import_roots": ("yaml",),
        "entry_points": (),
        "symbols": (
            db.Symbol(qualified_name="yaml.constructor.FullConstructor.make",
                      module="yaml.constructor", name="FullConstructor.make", kind="method",
                      path="lib/yaml/constructor.py"),
        ),
        "fix_commits": (db.FixCommitRef(repo="yaml/pyyaml", sha="a" * 40),),
        "model": None,
        "prompt_version": None,
        "input_hash": "h" * 64,
        "advisory_modified": NOW,
        "truncated": False,
        "extracted_at": NOW,
    }  # fmt: skip
    fields.update(overrides)
    return db.Record.model_validate(fields)


def test_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "p.sqlite"
    aliases = {"GHSA-0001-0001-0001": "GHSA-0001-0001-0001", "CVE-2099-1": "GHSA-0001-0001-0001"}
    assert db.write(path, [_record()], aliases, {"db_version": "2026.11.15"}) == 1
    database = db.SymbolDatabase(path)
    assert database.meta["db_version"] == "2026.11.15"
    assert database.meta["schema_version"] == str(db.SCHEMA_VERSION)
    assert database.vulnerability_for("CVE-2099-1") == "GHSA-0001-0001-0001"
    assert database.vulnerability_for("CVE-0000-0") is None
    record = database.record("GHSA-0001-0001-0001", "pyyaml")
    assert record == _record()
    assert database.record("GHSA-0001-0001-0001", "other") is None
    database.close()


def test_missing_database(tmp_path: Path) -> None:
    with pytest.raises(db.DatabaseError, match="no symbol database"):
        db.SymbolDatabase(tmp_path / "absent.sqlite")


def test_schema_version_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "p.sqlite"
    db.write(path, [], {}, {})
    connection = sqlite3.connect(path)
    connection.execute("UPDATE meta SET value = '999' WHERE key = 'schema_version'")
    connection.commit()
    connection.close()
    with pytest.raises(db.DatabaseError, match="schema version 999"):
        db.SymbolDatabase(path)


def test_not_a_database(tmp_path: Path) -> None:
    path = tmp_path / "p.sqlite"
    path.write_text("not sqlite")
    with pytest.raises(db.DatabaseError, match="not a PatchSight database"):
        db.SymbolDatabase(path)


def test_constraints_reject_bad_confidence(tmp_path: Path) -> None:
    path = tmp_path / "p.sqlite"
    with pytest.raises(ValueError, match="confidence"):
        db.write(path, [_record(confidence="certain")], {}, {})
