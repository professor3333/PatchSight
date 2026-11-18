"""The symbol database: the one artefact that crosses from the offline pipeline to the scan.

A record maps one vulnerability (an alias group) and one package to the symbols that carry
the bug, with confidence, evidence and provenance. Every advisory ID and alias points at
its vulnerability, so the scanner can look up whatever ID OSV returns.

* ``high`` confidence: LLM extraction that passed validation and agreement checks.
* ``low`` confidence: the fallback (every changed function) or an unconfirmed extraction.
  Low-confidence symbols can make an alert ``CALLED`` but never ``IMPORTED_NOT_CALLED``.

Stdlib ``sqlite3`` only, so the scan path can read it without any pipeline dependency.

Compatibility: three tables were added within schema version 1. ``extraction`` holds the
second-opinion model and the reason for the tier; ``evidence`` holds each flagged symbol's
rationale and cited hunk locations; ``builds`` is the ledger of every vulnerability
considered, with its input hash, for incremental updates. Readers that predate them never
query them, so they keep working; this reader treats a database without them as having no
such data. Evidence holds commit SHAs, paths and line ranges only, never code (rule 13).
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
CREATE TABLE extraction (
    vulnerability TEXT NOT NULL,
    package TEXT NOT NULL,
    second_opinion_model TEXT,
    tier_reason TEXT,
    PRIMARY KEY (vulnerability, package)
);
CREATE TABLE builds (
    vulnerability TEXT PRIMARY KEY,
    input_hash TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE evidence (
    vulnerability TEXT NOT NULL,
    package TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    rationale TEXT NOT NULL,
    hunks TEXT NOT NULL,
    PRIMARY KEY (vulnerability, package, qualified_name)
);
CREATE TABLE import_names (
    package TEXT PRIMARY KEY,
    names TEXT NOT NULL,
    source TEXT NOT NULL
);
"""


class DatabaseError(RuntimeError):
    """The database is missing, of an unsupported schema version, or malformed."""


class FixCommitRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo: str
    sha: str


class BuildEntry(BaseModel):
    """One vulnerability the builder considered, with or without a record: the ledger an
    incremental update compares against (ADR 0001: re-extract only when inputs change)."""

    model_config = ConfigDict(frozen=True)

    vulnerability: str
    input_hash: str
    status: str


class HunkLocation(BaseModel):
    """Where a cited diff hunk sits: the fix commit, the file and both line ranges."""

    model_config = ConfigDict(frozen=True)

    commit: str
    path: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int


class ImportNames(BaseModel):
    """A distribution's top-level import names, read from its wheels' file lists, and the
    wheels read. Empty ``names`` means none could be read; ``source`` says why."""

    model_config = ConfigDict(frozen=True)

    package: str
    names: tuple[str, ...]
    source: str


class SymbolEvidence(BaseModel):
    """Why the model flagged a symbol: a one-sentence rationale and the hunks it cited."""

    model_config = ConfigDict(frozen=True)

    qualified_name: str
    rationale: str
    hunks: tuple[HunkLocation, ...]


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
    # LLM records only: the second model's ID (ADR 0005) and why the tier was chosen.
    second_opinion_model: str | None = None
    tier_reason: str | None = None
    # The symbols the model judged vulnerable (all of a high record's symbols; in a low
    # record, the model's picks among every changed definition).
    evidence: tuple[SymbolEvidence, ...] = ()


def write(
    path: Path,
    records: Iterable[Record],
    aliases: dict[str, str],
    meta: dict[str, str],
    builds: Iterable[BuildEntry] = (),
    import_names: Iterable[ImportNames] = (),
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
        connection.executemany(
            "INSERT INTO builds VALUES (?, ?, ?)",
            sorted((b.vulnerability, b.input_hash, b.status) for b in builds),
        )
        connection.executemany(
            "INSERT INTO import_names VALUES (?, ?, ?)",
            sorted((n.package, json.dumps(list(n.names)), n.source) for n in import_names),
        )
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
            if record.second_opinion_model is not None or record.tier_reason is not None:
                connection.execute(
                    "INSERT INTO extraction VALUES (?, ?, ?, ?)",
                    (
                        record.vulnerability,
                        record.package,
                        record.second_opinion_model,
                        record.tier_reason,
                    ),
                )
            connection.executemany(
                "INSERT INTO evidence VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        record.vulnerability,
                        record.package,
                        e.qualified_name,
                        e.rationale,
                        json.dumps([h.model_dump() for h in e.hunks]),
                    )
                    for e in record.evidence
                ],
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
        tables = {
            name
            for (name,) in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self._has_extraction = "extraction" in tables
        self._has_evidence = "evidence" in tables
        self._has_builds = "builds" in tables
        self._has_import_names = "import_names" in tables

    def close(self) -> None:
        self._connection.close()

    def record_count(self) -> int:
        return int(self._connection.execute("SELECT COUNT(*) FROM records").fetchone()[0])

    def vulnerability_for(self, identifier: str) -> str | None:
        row = self._connection.execute(
            "SELECT vulnerability FROM aliases WHERE identifier = ?", (identifier,)
        ).fetchone()
        return str(row[0]) if row else None

    def all_records(self) -> list[Record]:
        """Every record, ordered by vulnerability and package."""
        return [r for v in self.vulnerabilities() for r in self.records_for(v)]

    def confidence_counts(self) -> dict[str, int]:
        """Records by confidence tier."""
        rows = self._connection.execute(
            "SELECT confidence, COUNT(*) FROM records GROUP BY confidence ORDER BY confidence"
        )
        return {str(r[0]): int(r[1]) for r in rows}

    def vulnerabilities(self) -> list[str]:
        """Every vulnerability that has at least one record."""
        rows = self._connection.execute(
            "SELECT DISTINCT vulnerability FROM records ORDER BY vulnerability"
        )
        return [str(r[0]) for r in rows]

    def alias_map(self) -> dict[str, str]:
        """Every advisory ID and alias, mapped to its vulnerability."""
        rows = self._connection.execute("SELECT identifier, vulnerability FROM aliases")
        return {str(r[0]): str(r[1]) for r in rows}

    def build_ledger(self) -> dict[str, BuildEntry]:
        """Every vulnerability the builder considered; empty for an older database."""
        if not self._has_builds:
            return {}
        rows = self._connection.execute("SELECT vulnerability, input_hash, status FROM builds")
        return {r[0]: BuildEntry(vulnerability=r[0], input_hash=r[1], status=r[2]) for r in rows}

    def import_names(self) -> dict[str, ImportNames]:
        """Import names read from wheels, by package; empty for an older database."""
        if not self._has_import_names:
            return {}
        rows = self._connection.execute("SELECT package, names, source FROM import_names")
        return {
            r[0]: ImportNames(package=r[0], names=tuple(json.loads(r[1])), source=r[2])
            for r in rows
        }

    def build_status(self, vulnerability: str) -> str | None:
        """Why the builder made a vulnerability's records, or none: its ledger status."""
        if not self._has_builds:
            return None
        row = self._connection.execute(
            "SELECT status FROM builds WHERE vulnerability = ?", (vulnerability,)
        ).fetchone()
        return str(row[0]) if row else None

    def identifiers_for(self, vulnerability: str) -> list[str]:
        """Every advisory ID and alias that points at this vulnerability."""
        rows = self._connection.execute(
            "SELECT identifier FROM aliases WHERE vulnerability = ? ORDER BY identifier",
            (vulnerability,),
        ).fetchall()
        return [str(r[0]) for r in rows]

    def records_for(self, vulnerability: str) -> list[Record]:
        """The vulnerability's records, one per affected package."""
        packages = self._connection.execute(
            "SELECT package FROM records WHERE vulnerability = ? ORDER BY package",
            (vulnerability,),
        ).fetchall()
        found = (self.record(vulnerability, str(p[0])) for p in packages)
        return [r for r in found if r is not None]

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
        provenance = (
            self._connection.execute(
                "SELECT second_opinion_model, tier_reason FROM extraction "
                "WHERE vulnerability = ? AND package = ?",
                (vulnerability, package),
            ).fetchone()
            if self._has_extraction
            else None
        )
        evidence = (
            self._connection.execute(
                "SELECT qualified_name, rationale, hunks FROM evidence "
                "WHERE vulnerability = ? AND package = ? ORDER BY qualified_name",
                (vulnerability, package),
            ).fetchall()
            if self._has_evidence
            else []
        )
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
            second_opinion_model=provenance[0] if provenance else None,
            tier_reason=provenance[1] if provenance else None,
            evidence=tuple(
                SymbolEvidence(
                    qualified_name=e[0],
                    rationale=e[1],
                    hunks=tuple(HunkLocation(**h) for h in json.loads(e[2])),
                )
                for e in evidence
            ),
        )
