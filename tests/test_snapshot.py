import hashlib
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from patchsight.pipeline.ingest import snapshot

PAYLOAD = b"synthetic dump contents" * 1000


def _client(status: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, content=PAYLOAD, headers={"last-modified": "Sat, 14 Nov 2026 03:02:50 GMT"}
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_download_hashes_and_records(tmp_path: Path) -> None:
    dest = tmp_path / "data" / "raw" / "all.zip"
    with _client() as client:
        entry = snapshot.download(client, "dump", "https://example.org/all.zip", dest, tmp_path)
    assert dest.read_bytes() == PAYLOAD
    assert entry.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert entry.size == len(PAYLOAD)
    assert entry.path == "data/raw/all.zip"
    assert entry.last_modified == "Sat, 14 Nov 2026 03:02:50 GMT"
    assert not list(dest.parent.glob("*.part"))


def test_failed_download_leaves_no_file(tmp_path: Path) -> None:
    dest = tmp_path / "all.zip"
    with _client(status=500) as client, pytest.raises(httpx.HTTPStatusError):
        snapshot.download(client, "dump", "https://example.org/all.zip", dest, tmp_path)
    assert not dest.exists()


def _entry(tmp_path: Path, content: bytes) -> snapshot.SourceFile:
    path = tmp_path / "all.zip"
    path.write_bytes(content)
    return snapshot.SourceFile(
        name="dump",
        url="https://example.org/all.zip",
        path="all.zip",
        sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        size=len(content),
        last_modified=None,
        retrieved_at=datetime(2026, 11, 14, tzinfo=UTC),
    )


def test_verify_accepts_matching_file(tmp_path: Path) -> None:
    entry = _entry(tmp_path, PAYLOAD)
    assert snapshot.verify(entry, tmp_path) == tmp_path / "all.zip"


def test_verify_refuses_changed_file(tmp_path: Path) -> None:
    entry = _entry(tmp_path, PAYLOAD + b"tampered")
    with pytest.raises(snapshot.SnapshotMismatchError, match="manifest pins"):
        snapshot.verify(entry, tmp_path)


def test_verify_refuses_missing_file(tmp_path: Path) -> None:
    entry = _entry(tmp_path, PAYLOAD)
    (tmp_path / "all.zip").unlink()
    with pytest.raises(snapshot.SnapshotMismatchError, match="missing"):
        snapshot.verify(entry, tmp_path)


def test_manifest_round_trip_and_replacement(tmp_path: Path) -> None:
    first = _entry(tmp_path, PAYLOAD)
    second = first.model_copy(update={"name": "aaa"})
    newer = first.model_copy(update={"sha256": "0" * 64})
    manifest = snapshot.SnapshotManifest().with_file(first).with_file(second).with_file(newer)
    assert [f.name for f in manifest.files] == ["aaa", "dump"]
    assert manifest.file("dump").sha256 == "0" * 64

    path = tmp_path / "manifests" / "snapshot.json"
    snapshot.save_manifest(manifest, path)
    assert snapshot.load_manifest(path) == manifest
    assert snapshot.load_manifest(tmp_path / "absent.json") == snapshot.SnapshotManifest()
    with pytest.raises(KeyError):
        manifest.file("unknown")
