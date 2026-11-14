"""Read the OSV PyPI dump and normalise each record.

Every record ends in exactly one of three states:

* ``Advisory``: an in-scope PyPI vulnerability, normalised.
* ``Excluded``: valid but out of scope, with the reason (withdrawn, malicious-package
  report, no PyPI package).
* ``Quarantined``: malformed, with the validation error. Never silently skipped.
"""

import json
import zipfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from patchsight.names import canonical_package_name
from patchsight.pipeline.ingest.references import (
    FixCandidate,
    candidate_from_git_range,
    classify_url,
)

# --- Raw OSV subset (only the fields PatchSight reads; others are ignored) -------------


class _Raw(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class OsvReference(_Raw):
    type: str
    url: str


class OsvEvent(_Raw):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None


class OsvRange(_Raw):
    type: str
    repo: str | None = None
    events: tuple[OsvEvent, ...] = ()


class OsvPackage(_Raw):
    ecosystem: str
    name: str
    purl: str | None = None


class OsvAffected(_Raw):
    package: OsvPackage
    ranges: tuple[OsvRange, ...] = ()
    versions: tuple[str, ...] = ()
    ecosystem_specific: dict[str, Any] | None = None


class OsvRecord(_Raw):
    id: str = Field(min_length=1)
    modified: datetime
    published: datetime | None = None
    withdrawn: datetime | None = None
    aliases: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    affected: tuple[OsvAffected, ...] = ()
    references: tuple[OsvReference, ...] = ()
    schema_version: str | None = None


# --- Normalised output -----------------------------------------------------------------


class VersionRange(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: str
    events: tuple[OsvEvent, ...]


class SymbolHint(BaseModel):
    """Symbol data an upstream database already attaches to an advisory."""

    model_config = ConfigDict(frozen=True)

    field: Literal["imports", "affected_functions"]
    package: str
    value: Any


class AffectedPackage(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    raw_name: str
    ranges: tuple[VersionRange, ...]
    versions: tuple[str, ...]


class Advisory(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    source: str
    aliases: tuple[str, ...]
    related: tuple[str, ...]
    published: datetime | None
    modified: datetime
    summary: str
    details: str
    packages: tuple[AffectedPackage, ...]
    references: tuple[OsvReference, ...]
    fix_candidates: tuple[FixCandidate, ...]
    symbol_hints: tuple[SymbolHint, ...]


ExclusionReason = Literal["withdrawn", "malicious_package", "no_pypi_package"]


class Excluded(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    reason: ExclusionReason


class Quarantined(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_name: str
    reason: str


NormaliseResult = Advisory | Excluded | Quarantined

_SYMBOL_FIELDS: tuple[Literal["imports", "affected_functions"], ...] = (
    "imports",
    "affected_functions",
)


def source_of(advisory_id: str) -> str:
    """The database prefix of an advisory ID, e.g. ``GHSA`` or ``PYSEC``."""
    return advisory_id.split("-", 1)[0].upper()


def _fix_candidates(record: OsvRecord) -> tuple[FixCandidate, ...]:
    found: dict[tuple[str, str, str | None, str | None, int | None], FixCandidate] = {}
    for affected in record.affected:
        for version_range in affected.ranges:
            if version_range.type != "GIT" or not version_range.repo:
                continue
            for event in version_range.events:
                if event.fixed and (c := candidate_from_git_range(version_range.repo, event.fixed)):
                    found.setdefault((c.origin, c.kind, c.repo, c.commit, c.number), c)
    for reference in record.references:
        if c := classify_url(reference.url, reference.type):
            found.setdefault((c.origin, c.kind, c.repo, c.commit or c.url, c.number), c)
    return tuple(found.values())


def _symbol_hints(record: OsvRecord) -> tuple[SymbolHint, ...]:
    hints = []
    for affected in record.affected:
        specific = affected.ecosystem_specific or {}
        for field in _SYMBOL_FIELDS:
            if specific.get(field):
                hints.append(
                    SymbolHint(
                        field=field,
                        package=canonical_package_name(affected.package.name),
                        value=specific[field],
                    )
                )
    return tuple(hints)


def normalise(raw: dict[str, Any], source_name: str) -> NormaliseResult:
    """Normalise one raw OSV record. Never raises on bad input; quarantines it instead."""
    try:
        record = OsvRecord.model_validate(raw)
    except ValidationError as error:
        first = error.errors()[0]
        location = ".".join(str(part) for part in first["loc"])
        return Quarantined(source_name=source_name, reason=f"{location}: {first['msg']}")

    if record.withdrawn is not None:
        return Excluded(id=record.id, reason="withdrawn")
    if source_of(record.id) == "MAL":
        return Excluded(id=record.id, reason="malicious_package")
    pypi = [a for a in record.affected if a.package.ecosystem == "PyPI"]
    if not pypi:
        return Excluded(id=record.id, reason="no_pypi_package")

    packages = tuple(
        AffectedPackage(
            name=canonical_package_name(a.package.name),
            raw_name=a.package.name,
            ranges=tuple(
                VersionRange(type=r.type, events=r.events) for r in a.ranges if r.type != "GIT"
            ),
            versions=a.versions,
        )
        for a in pypi
    )
    return Advisory(
        id=record.id,
        source=source_of(record.id),
        aliases=tuple(sorted(set(record.aliases))),
        related=tuple(sorted(set(record.related))),
        published=record.published,
        modified=record.modified,
        summary=record.summary,
        details=record.details,
        packages=packages,
        references=record.references,
        fix_candidates=_fix_candidates(record),
        symbol_hints=_symbol_hints(record),
    )


def iter_dump(zip_path: Path) -> Iterator[tuple[str, dict[str, Any] | None, str | None]]:
    """Yield ``(member name, parsed JSON or None, parse error or None)`` in name order."""
    with zipfile.ZipFile(zip_path) as archive:
        for name in sorted(archive.namelist()):
            if name.endswith("/"):
                continue
            try:
                data = json.loads(archive.read(name))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                yield name, None, f"invalid JSON: {error}"
                continue
            if not isinstance(data, dict):
                yield name, None, "top-level JSON value is not an object"
                continue
            yield name, data, None


def normalise_dump(zip_path: Path) -> Iterator[NormaliseResult]:
    """Normalise every record in an OSV dump, in deterministic order."""
    for name, data, error in iter_dump(zip_path):
        if data is None:
            yield Quarantined(source_name=name, reason=error or "unreadable")
        else:
            yield normalise(data, name)
