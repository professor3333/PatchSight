"""The symbol database: the one artefact that crosses from the offline pipeline to the scan.

A record maps one vulnerability (an alias group) and one package to the symbols that carry
the bug, with confidence, evidence and provenance. Every advisory ID and alias points at
its vulnerability, so the scanner can look up whatever ID OSV returns.

* ``high`` confidence: LLM extraction that passed validation and agreement checks.
* ``low`` confidence: the fallback (every changed function) or an unconfirmed extraction.
  Low-confidence symbols can make an alert ``CALLED`` but never ``IMPORTED_NOT_CALLED``.

Stdlib ``sqlite3`` only, so the scan path can read it without any pipeline dependency.
"""

import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION = 1

Confidence = Literal["high", "low"]
Source = Literal["llm", "fallback", "override"]

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE aliases (identifier TEXT PRIMARY KEY, vulnerability TEXT NOT NULL);
CREATE TABLE records (
    vulnerability TEXT NOT NULL,
    package TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('high', 'low')),
    source TEXT NOT NULL CHECK (source IN ('llm', 'fallback', 'override')),
    import_roots TEXT NOT NULL,
    entry_points TEXT NOT NULL,
    fix_commits TEXT NOT NULL,
    model TEXT,
    prompt_version TEXT,
    input_hash TEXT NOT NULL,
    advisory_modified TEXT NOT NULL,
    truncated INTEGER NOT NULL,
    extracted_at TEXT NOT NULL,
    PRIMARY KEY (vulnerability, package)
);
CREATE TABLE symbols (
    vulnerability TEXT NOT NULL,
    package TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    module TEXT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    FOREIGN KEY (vulnerability, package) REFERENCES records (vulnerability, package)
);
CREATE INDEX symbols_by_record ON symbols (vulnerability, package);
"""


class DatabaseError(RuntimeError):
    """The database is missing, of an unsupported schema version, or malformed."""


class FixCommitRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo: str
    sha: str


class Symbol(BaseModel):
    """A vulnerable definition. ``qualified_name`` is ``module.qualname`` when the module
    is known, otherwise just the qualname."""

    model_config = ConfigDict(frozen=True)

    qualified_name: str
    module: str | None
    name: str
    kind: str
    path: str


class Record(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    package: str
    confidence: Confidence
    source: Source
    import_roots: tuple[str, ...]
    entry_points: tuple[str, ...]
    symbols: tuple[Symbol, ...]
    fix_commits: tuple[FixCommitRef, ...]
    model: str | None
    prompt_version: str | None
    input_hash: str
    advisory_modified: datetime
    truncated: bool
    extracted_at: datetime


def write(
    path: Path, records: Iterable[Record], aliases: dict[str, str], meta: dict[str, str]
) -> int:
    """Write a fresh database file. Returns the number of records written."""
    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    count = 0
    try:
        connection.executescript(_SCHEMA)
        connection.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            sorted({**meta, "schema_version": str(SCHEMA_VERSION)}.items()),
        )
        connection.executemany("INSERT INTO aliases VALUES (?, ?)", sorted(aliases.items()))
        for record in records:
            count += 1
            connection.execute(
                "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.vulnerability,
                    record.package,
                    record.confidence,
                    record.source,
                    json.dumps(record.import_roots),
                    json.dumps(record.entry_points),
                    json.dumps([c.model_dump() for c in record.fix_commits]),
                    record.model,
                    record.prompt_version,
                    record.input_hash,
                    record.advisory_modified.isoformat(),
                    int(record.truncated),
                    record.extracted_at.isoformat(),
                ),
            )
            connection.executemany(
                "INSERT INTO symbols VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        record.vulnerability,
                        record.package,
                        s.qualified_name,
                        s.module,
                        s.name,
                        s.kind,
                        s.path,
                    )
                    for s in record.symbols
                ],
            )
        connection.commit()
    finally:
        connection.close()
    return count


class SymbolDatabase:
    """Read-only access for the scanner."""

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise DatabaseError(f"no symbol database at {path}")
        self._connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            self.meta = dict(self._connection.execute("SELECT key, value FROM meta").fetchall())
        except sqlite3.DatabaseError as error:
            raise DatabaseError(f"{path} is not a PatchSight database: {error}") from None
        version = self.meta.get("schema_version")
        if version != str(SCHEMA_VERSION):
            raise DatabaseError(
                f"{path} has schema version {version}; this version of PatchSight reads "
                f"version {SCHEMA_VERSION}. Update PatchSight or download a matching database."
            )

    def close(self) -> None:
        self._connection.close()

    def vulnerability_for(self, identifier: str) -> str | None:
        row = self._connection.execute(
            "SELECT vulnerability FROM aliases WHERE identifier = ?", (identifier,)
        ).fetchone()
        return str(row[0]) if row else None

    def record(self, vulnerability: str, package: str) -> Record | None:
        row = self._connection.execute(
            "SELECT * FROM records WHERE vulnerability = ? AND package = ?",
            (vulnerability, package),
        ).fetchone()
        if row is None:
            return None
        symbols = self._connection.execute(
            "SELECT qualified_name, module, name, kind, path FROM symbols "
            "WHERE vulnerability = ? AND package = ? ORDER BY qualified_name",
            (vulnerability, package),
        ).fetchall()
        return Record(
            vulnerability=row[0],
            package=row[1],
            confidence=row[2],
            source=row[3],
            import_roots=tuple(json.loads(row[4])),
            entry_points=tuple(json.loads(row[5])),
            fix_commits=tuple(FixCommitRef(**c) for c in json.loads(row[6])),
            model=row[7],
            prompt_version=row[8],
            input_hash=row[9],
            advisory_modified=datetime.fromisoformat(row[10]),
            truncated=bool(row[11]),
            extracted_at=datetime.fromisoformat(row[12]),
            symbols=tuple(
                Symbol(qualified_name=s[0], module=s[1], name=s[2], kind=s[3], path=s[4])
                for s in symbols
            ),
        )
