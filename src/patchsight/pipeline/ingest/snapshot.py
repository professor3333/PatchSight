"""Pinned source snapshots.

Every run of the pipeline reads inputs recorded in ``manifests/snapshot.json``: each
downloaded file with its SHA-256, and each cloned repository with its commit. A file whose
hash no longer matches the manifest is refused, so results are always traceable to the
exact inputs that produced them.
"""

import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict

OSV_PYPI_DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
OSV_PYPI_MODIFIED_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/modified_id.csv"

_CHUNK = 1 << 20


class SnapshotMismatchError(RuntimeError):
    """A local file does not match the hash pinned in the snapshot manifest."""


class SourceFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    url: str
    path: str
    sha256: str
    size: int
    last_modified: str | None
    retrieved_at: datetime


class SourceRepo(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    url: str
    path: str
    commit: str
    committed_at: datetime
    note: str = ""


class SnapshotManifest(BaseModel):
    files: tuple[SourceFile, ...] = ()
    repos: tuple[SourceRepo, ...] = ()

    def file(self, name: str) -> SourceFile:
        for entry in self.files:
            if entry.name == name:
                return entry
        raise KeyError(f"no file named {name!r} in the snapshot manifest")

    def with_file(self, entry: SourceFile) -> "SnapshotManifest":
        others = tuple(f for f in self.files if f.name != entry.name)
        return self.model_copy(update={"files": tuple(sorted((*others, entry), key=_name))})

    def with_repo(self, entry: SourceRepo) -> "SnapshotManifest":
        others = tuple(r for r in self.repos if r.name != entry.name)
        return self.model_copy(update={"repos": tuple(sorted((*others, entry), key=_name))})


def _name(entry: SourceFile | SourceRepo) -> str:
    return entry.name


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> SnapshotManifest:
    if not path.exists():
        return SnapshotManifest()
    return SnapshotManifest.model_validate_json(path.read_text(encoding="utf-8"))


def save_manifest(manifest: SnapshotManifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")


def download(client: httpx.Client, name: str, url: str, dest: Path, root: Path) -> SourceFile:
    """Stream ``url`` to ``dest``, hashing as it goes. Replaces ``dest`` only on success."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    size = 0
    with client.stream("GET", url) as response:
        response.raise_for_status()
        last_modified = response.headers.get("last-modified")
        with partial.open("wb") as handle:
            for chunk in response.iter_bytes(_CHUNK):
                handle.write(chunk)
                digest.update(chunk)
                size += len(chunk)
    partial.replace(dest)
    return SourceFile(
        name=name,
        url=url,
        path=dest.relative_to(root).as_posix(),
        sha256=digest.hexdigest(),
        size=size,
        last_modified=last_modified,
        retrieved_at=datetime.now(UTC),
    )


def verify(entry: SourceFile, root: Path) -> Path:
    """Return the local path of ``entry`` after checking its hash against the manifest."""
    path = root / entry.path
    if not path.exists():
        raise SnapshotMismatchError(f"{entry.path} is missing; run the snapshot step first")
    actual = sha256_file(path)
    if actual != entry.sha256:
        raise SnapshotMismatchError(
            f"{entry.path} has SHA-256 {actual}, but the manifest pins {entry.sha256}"
        )
    return path


def record_repo(name: str, url: str, path: Path, root: Path, note: str = "") -> SourceRepo:
    """Record the checked-out commit of a local clone."""
    output = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(path), "log", "-1", "--format=%H %cI"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return SourceRepo(
        name=name,
        url=url,
        path=path.relative_to(root).as_posix(),
        commit=output[0],
        committed_at=datetime.fromisoformat(output[1]),
        note=note,
    )
