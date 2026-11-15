"""Publishing and downloading the symbol database, against a fake HTTPS server."""

import gzip
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from patchsight import db
from patchsight.cli import app
from patchsight.pipeline.__main__ import app as pipeline_app
from patchsight.scan import dbcache

POINTER = "https://example.org/latest.json"
ASSET = "https://example.org/patchsight-db-2026.11.15.sqlite.gz"


def _database(path: Path) -> Path:
    db.write(path, [], {}, {"db_version": "2026.11.15", "built_at": datetime.now(UTC).isoformat()})
    return path


def _server(tmp_path: Path, **overrides: object) -> tuple[httpx.Client, dict[str, int]]:
    served = overrides.pop("payload", None)
    payload = gzip.compress(_database(tmp_path / "source.sqlite").read_bytes(), mtime=0)
    pointer = {
        "db_version": "2026.11.15", "schema_version": db.SCHEMA_VERSION, "url": ASSET,
        "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
        "built_at": datetime.now(UTC).isoformat(), "records": 0,
    }  # fmt: skip
    pointer.update(overrides)
    hits = {"pointer": 0, "asset": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == POINTER:
            hits["pointer"] += 1
            return httpx.Response(200, json=pointer)
        if str(request.url) == ASSET:
            hits["asset"] += 1
            return httpx.Response(200, content=served if isinstance(served, bytes) else payload)
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler)), hits


def test_update_downloads_verifies_and_then_stays_current(tmp_path: Path) -> None:
    client, hits = _server(tmp_path)
    target = tmp_path / "cache" / "patchsight.sqlite"
    status, pointer = dbcache.update(client, POINTER, target)
    assert (status, pointer.db_version) == ("updated", "2026.11.15")
    assert db.SymbolDatabase(target).meta["db_version"] == "2026.11.15"
    assert dbcache.update(client, POINTER, target)[0] == "current"
    assert hits == {"pointer": 2, "asset": 1}


def test_tampered_download_never_replaces_a_working_database(tmp_path: Path) -> None:
    client, _ = _server(tmp_path, sha256="0" * 64)
    target = _database(tmp_path / "cache" / "patchsight.sqlite")
    before = target.read_bytes()
    with pytest.raises(db.DatabaseError, match="does not match the published SHA-256"):
        dbcache.update(client, POINTER, target)
    assert target.read_bytes() == before
    assert not list(target.parent.glob("*.download"))
    assert not list(target.parent.glob("*.new"))


def test_a_file_that_is_not_a_database_is_refused(tmp_path: Path) -> None:
    garbage = gzip.compress(b"not a database", mtime=0)
    client, _ = _server(tmp_path, payload=garbage, sha256=hashlib.sha256(garbage).hexdigest())
    target = tmp_path / "cache" / "patchsight.sqlite"
    with pytest.raises(db.DatabaseError, match="not a PatchSight database"):
        dbcache.update(client, POINTER, target)
    assert not target.exists()


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"schema_version": 999}, "upgrade PatchSight"),
        ({"url": "http://example.org/x.sqlite.gz"}, "non-HTTPS"),
    ],
)
def test_pointer_checks(tmp_path: Path, override: dict[str, object], message: str) -> None:
    client, _ = _server(tmp_path, **override)
    with pytest.raises(db.DatabaseError, match=message):
        dbcache.update(client, POINTER, tmp_path / "cache" / "p.sqlite")


def test_nothing_published_yet(tmp_path: Path) -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(db.DatabaseError, match="no database has been published yet"):
        dbcache.update(client, POINTER, tmp_path / "p.sqlite")


def test_db_info_and_missing_database_hint(tmp_path: Path) -> None:
    runner = CliRunner()
    database = _database(tmp_path / "p.sqlite")
    shown = runner.invoke(app, ["db", "info", "--db", str(database)])
    assert shown.exit_code == 0
    assert "db_version: 2026.11.15" in shown.output
    missing = runner.invoke(app, ["db", "info", "--db", str(tmp_path / "absent.sqlite")])
    assert missing.exit_code == 2
    assert "patchsight db update" in missing.output


def test_package_db_is_deterministic(tmp_path: Path) -> None:
    database = _database(tmp_path / "built.sqlite")
    runner = CliRunner()
    hashes = []
    for _ in range(2):
        result = runner.invoke(pipeline_app, ["package-db", str(database), "--root", str(tmp_path)])
        assert result.exit_code == 0, result.output
        pointer = json.loads((tmp_path / "releases" / "latest.json").read_text())
        asset = tmp_path / "data/build/release/patchsight-db-2026.11.15.sqlite.gz"
        assert pointer["sha256"] == hashlib.sha256(asset.read_bytes()).hexdigest()
        assert pointer["url"].endswith(
            "/releases/download/db-2026.11.15/patchsight-db-2026.11.15.sqlite.gz"
        )
        hashes.append(pointer["sha256"])
    assert hashes[0] == hashes[1]
