"""Fetch and cache the published symbol database.

Releases are immutable files attached to GitHub releases. A small pointer, ``latest.json``,
names the current one with its SHA-256, so rolling back is one commit that moves the pointer
back (ADR 0006). The nightly pipeline keeps it on the ``db-pointer`` branch; the copy at
``releases/latest.json`` on ``main`` is the fallback, and what CLIs before 0.3.0 read.

``update`` downloads over HTTPS only, verifies the SHA-256, checks the schema version by
opening the file, and only then replaces the cached copy, so a failed or tampered download
never takes the place of a working database.
"""

import gzip
import hashlib
import os
import shutil
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict

from patchsight.db import SCHEMA_VERSION, DatabaseError, SymbolDatabase

_RAW = "https://raw.githubusercontent.com/professor3333/PatchSight"
POINTER_URLS = (f"{_RAW}/db-pointer/latest.json", f"{_RAW}/main/releases/latest.json")
POINTER_URL = POINTER_URLS[-1]
_CHUNK = 1 << 20


class Pointer(BaseModel):
    model_config = ConfigDict(frozen=True)

    db_version: str
    schema_version: int
    url: str
    sha256: str
    size: int
    built_at: datetime
    records: int


def cache_dir() -> Path:
    configured = os.environ.get("PATCHSIGHT_CACHE")
    return Path(configured) if configured else Path.home() / ".cache" / "patchsight"


def default_db_path() -> Path:
    configured = os.environ.get("PATCHSIGHT_DB")
    return Path(configured) if configured else cache_dir() / "patchsight.sqlite"


def _https(url: str) -> str:
    if not url.startswith("https://"):
        raise DatabaseError(f"refusing a non-HTTPS database URL: {url}")
    return url


def fetch_pointer(client: httpx.Client, urls: str | Sequence[str] = POINTER_URLS) -> Pointer:
    """The first published pointer among ``urls``. Only "not found" moves on to the next;
    any other failure is an error, never a silent fallback."""
    for url in (urls,) if isinstance(urls, str) else urls:
        response = client.get(_https(url))
        if response.status_code == 404:
            continue
        response.raise_for_status()
        break
    else:
        raise DatabaseError("no database has been published yet")
    pointer = Pointer.model_validate_json(response.content)
    if pointer.schema_version != SCHEMA_VERSION:
        raise DatabaseError(
            f"the published database uses schema {pointer.schema_version}, but this version of "
            f"PatchSight reads schema {SCHEMA_VERSION}; upgrade PatchSight"
        )
    return pointer


def update(
    client: httpx.Client | None = None,
    pointer_url: str | Sequence[str] = POINTER_URLS,
    target: Path | None = None,
) -> tuple[Literal["updated", "current"], Pointer]:
    owns = client is None
    client = client or httpx.Client(
        timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=True
    )
    target = target or default_db_path()
    record = target.with_name(target.name + ".json")
    try:
        pointer = fetch_pointer(client, pointer_url)
        if target.exists() and record.exists():
            current = Pointer.model_validate_json(record.read_text(encoding="utf-8"))
            if current.sha256 == pointer.sha256:
                return "current", pointer

        target.parent.mkdir(parents=True, exist_ok=True)
        download = target.with_name(target.name + ".download")
        digest = hashlib.sha256()
        with client.stream("GET", _https(pointer.url)) as response:
            response.raise_for_status()
            with download.open("wb") as handle:
                for chunk in response.iter_bytes(_CHUNK):
                    handle.write(chunk)
                    digest.update(chunk)
        if digest.hexdigest() != pointer.sha256:
            download.unlink(missing_ok=True)
            raise DatabaseError("the downloaded database does not match the published SHA-256")

        unpacked = target.with_name(target.name + ".new")
        if pointer.url.endswith(".gz"):
            with gzip.open(download, "rb") as source, unpacked.open("wb") as sink:
                shutil.copyfileobj(source, sink)
            download.unlink()
        else:
            download.replace(unpacked)
        try:
            SymbolDatabase(unpacked).close()  # checks the format and schema version
        except DatabaseError:
            unpacked.unlink(missing_ok=True)
            raise
        unpacked.replace(target)
        record.write_text(pointer.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return "updated", pointer
    finally:
        if owns:
            client.close()
