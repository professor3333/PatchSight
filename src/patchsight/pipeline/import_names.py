"""The names a distribution is imported as, read from the file lists of its wheels.

A record's import roots used to come from the fix commit's paths, through
``names.module_for_path``. Paths say what a *repository* holds, not what a wheel
installs, so that guess fails in monorepos (``libs/checkpoint-sqlite/langgraph/...``),
for packages kept under a ``src`` directory of their own (``keras/src/...``), and for
repository helpers that are never installed (``dummyserver``). A wrong root makes the
scanner miss ``CALLED`` evidence, or, with no right root at all, say ``NOT_IMPORTED`` for
code that imports the package.

A wheel's file list is the ground truth. Only the zip's central directory is read, with
two HTTP range requests to ``files.pythonhosted.org``, so no package is downloaded or
unpacked. The newest and the oldest release that have a wheel are both read, because a
package can rename its top-level module over time; their names are united.

Offline pipeline only. File lists are cached by the wheel's SHA-256, so re-runs make no
network calls. They hold file names only, never file contents.
"""

import json
import struct
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from patchsight.db import ImportNames, Record, Symbol, SymbolEvidence
from patchsight.names import canonical_package_name, module_for_path
from patchsight.pipeline.http import CacheMissError, HttpError, NotFoundError
from patchsight.pipeline.pypi import PyPIClient

FILES_HOST = "files.pythonhosted.org"
_TAIL = 65_536  # bytes read from the end of a wheel: the end-of-directory record and more
_EOCD = b"PK\x05\x06"
_EOCD64_LOCATOR = b"PK\x06\x07"
_CENTRAL = b"PK\x01\x02"
_EXTENSION_SUFFIXES = (".so", ".pyd")


def top_level_names(files: Iterable[str]) -> tuple[str, ...]:
    """Top-level importable names in a wheel's file list: packages, modules, extensions.

    >>> top_level_names(["yaml/__init__.py", "_yaml/__init__.py", "PyYAML-6.0.dist-info/RECORD"])
    ('_yaml', 'yaml')
    >>> top_level_names(["langgraph/store/sqlite/base.py", "six.py", "x.cpython-312-darwin.so"])
    ('langgraph', 'six', 'x')
    """
    names: set[str] = set()
    for raw in files:
        path = raw.replace("\\", "/").lstrip("/")
        first, _, rest = path.partition("/")
        if first.endswith(".dist-info") or not first:
            continue
        if first.endswith(".data"):
            kind, _, inner = rest.partition("/")
            if kind not in ("purelib", "platlib"):
                continue
            first, _, rest = inner.partition("/")
        if rest:
            if not rest.endswith((".py", ".pyi", *_EXTENSION_SUFFIXES)):
                continue
            candidate = first
        elif first.endswith((".py", ".pyi")):
            candidate = first.rsplit(".", 1)[0]
        elif first.endswith(_EXTENSION_SUFFIXES):
            candidate = first.split(".", 1)[0]
        else:
            continue
        if candidate.isidentifier() and candidate != "__pycache__":
            names.add(candidate)
    return tuple(sorted(names))


def central_directory_names(tail: bytes, size: int, fetch: Any) -> list[str]:
    """File names from a zip's central directory, given the last bytes of the file.

    ``fetch(start, end)`` returns bytes ``start..end`` inclusive, for a directory that
    starts before ``tail``.
    """
    at = tail.rfind(_EOCD)
    if at < 0:
        raise ValueError("no end-of-central-directory record")
    (entries, directory_size, directory_offset) = struct.unpack_from("<HII", tail, at + 10)
    if 0xFFFFFFFF in (directory_size, directory_offset) or entries == 0xFFFF:
        locator = tail.rfind(_EOCD64_LOCATOR, 0, at)
        if locator < 0:
            raise ValueError("zip64 without a locator")
        (record_offset,) = struct.unpack_from("<Q", tail, locator + 8)
        start_of_tail = size - len(tail)
        record = tail[record_offset - start_of_tail :] if record_offset >= start_of_tail else b""
        if len(record) < 56:
            record = fetch(record_offset, record_offset + 55)
        directory_size, directory_offset = struct.unpack_from("<QQ", record, 40)
    start_of_tail = size - len(tail)
    if directory_offset >= start_of_tail:
        start = directory_offset - start_of_tail
        directory = tail[start : start + directory_size]
    else:
        directory = fetch(directory_offset, directory_offset + directory_size - 1)
    names, position = [], 0
    while position + 46 <= len(directory) and directory[position : position + 4] == _CENTRAL:
        name_length, extra_length, comment_length = struct.unpack_from(
            "<HHH", directory, position + 28
        )
        start = position + 46
        names.append(directory[start : start + name_length].decode("utf-8", "replace"))
        position = start + name_length + extra_length + comment_length
    return names


class _Retryable(Exception):
    pass


class WheelIndex:
    """Reads and caches wheel file lists; package metadata comes through ``PyPIClient``."""

    def __init__(
        self,
        pypi: PyPIClient,
        cache_dir: Path,
        transport: httpx.BaseTransport | None = None,
        offline: bool = False,
    ) -> None:
        self.pypi = pypi
        self.cache_dir = cache_dir
        self.offline = offline
        self.network_requests = 0
        self._http = httpx.Client(
            headers={"User-Agent": "patchsight-pipeline"},
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            transport=transport,
        )

    def close(self) -> None:
        self._http.close()

    def _range(self, url: str, start: int, end: int) -> bytes:
        for attempt in Retrying(
            retry=retry_if_exception_type(_Retryable),
            stop=stop_after_attempt(4),
            wait=wait_exponential(multiplier=1, max=30),
            reraise=True,
        ):
            with attempt:
                self.network_requests += 1
                try:
                    response = self._http.get(url, headers={"Range": f"bytes={start}-{end}"})
                except httpx.TransportError as error:
                    raise _Retryable(str(error)) from error
                if response.status_code in (429, 500, 502, 503, 504):
                    raise _Retryable(f"HTTP {response.status_code}")
                if response.status_code != 206:
                    raise ValueError(f"{url}: HTTP {response.status_code} to a range request")
                return response.content
        raise AssertionError("unreachable")  # pragma: no cover

    def files(self, wheel: Mapping[str, Any]) -> list[str]:
        """File names in one wheel, from PyPI's file entry (``url``, ``size``, ``digests``)."""
        url, size = str(wheel["url"]), int(wheel["size"])
        if httpx.URL(url).host != FILES_HOST:
            raise ValueError(f"{url}: not on {FILES_HOST}")
        digest = str(wheel["digests"]["sha256"])
        cache_file = self.cache_dir / digest[:2] / f"{digest}.json"
        if cache_file.exists():
            cached: list[str] = json.loads(cache_file.read_text("utf-8"))["files"]
            return cached
        if self.offline:
            raise CacheMissError(f"{wheel.get('filename', url)}: not in the offline cache")
        start = max(0, size - _TAIL)
        tail = self._range(url, start, size - 1)
        names = central_directory_names(tail, size, lambda a, b: self._range(url, a, b))
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps({"files": names}), "utf-8")
        return names

    def import_names(self, package: str) -> ImportNames:
        canonical = canonical_package_name(package)
        try:
            data: dict[str, Any] = self.pypi.http.get_json(f"/pypi/{canonical}/json")
        except NotFoundError:
            return ImportNames(package=canonical, names=(), source="not on PyPI")
        wheels = _wheels_by_release(data)
        if not wheels:
            return ImportNames(package=canonical, names=(), source="no wheel on PyPI")
        chosen = [wheels[-1]] if len(wheels) == 1 else [wheels[-1], wheels[0]]
        names: set[str] = set()
        for wheel in chosen:
            names.update(top_level_names(self.files(wheel)))
        return ImportNames(
            package=canonical,
            names=tuple(sorted(names)),
            source=", ".join(str(w["filename"]) for w in chosen),
        )


def _wheels_by_release(data: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """One wheel per release that has one, oldest release first, yanked files skipped.
    A pure-Python wheel is preferred, then the smallest."""
    from packaging.version import InvalidVersion, Version

    releases: list[tuple[Version, Mapping[str, Any]]] = []
    for version, files in (data.get("releases") or {}).items():
        wheels = [
            f
            for f in files or []
            if f.get("packagetype") == "bdist_wheel" and not f.get("yanked") and f.get("url")
        ]
        if not wheels:
            continue
        try:
            parsed = Version(version)
        except InvalidVersion:
            continue
        wheels.sort(key=lambda f: ("-none-any" not in str(f["filename"]), int(f["size"])))
        releases.append((parsed, wheels[0]))
    releases.sort(key=lambda pair: pair[0])
    return [wheel for _, wheel in releases]


def module_under(path: str, roots: Iterable[str]) -> str | None:
    """The module a repository path defines, starting at the first part that is an import
    root, or None if no part is one.

    >>> module_under("libs/checkpoint-sqlite/langgraph/store/sqlite/base.py", ["langgraph"])
    'langgraph.store.sqlite.base'
    >>> module_under("keras/src/saving/saving_lib.py", ["keras"])
    'keras.src.saving.saving_lib'
    >>> module_under("lib/yaml/__init__.py", ["yaml"]) is None, module_under("x/y.py", ["z"])
    (False, None)
    """
    wanted = set(roots)
    if not path.endswith((".py", ".pyi", ".pyx")):
        return None
    parts = path.strip("/").rsplit(".", 1)[0].split("/")
    for index, part in enumerate(parts):
        if part in wanted:
            tail = parts[index:]
            if tail[-1] == "__init__":
                tail = tail[:-1]
            return ".".join(tail) if all(p.isidentifier() for p in tail) else None
    return None


def relabel(record: Record, names: ImportNames | None) -> Record:
    """The record with import roots from the wheel and symbol modules under those roots.

    Without wheel names the record is returned unchanged. Symbols outside every root
    (repository helpers that are not installed) keep their path-derived module. Entry
    points and model picks named after a path-derived module or symbol move with it,
    also when the record's symbols were relabelled before (a merge of new picks into a
    release that already has import names). Idempotent.
    """
    if names is None or not names.names:
        return record
    # From every symbol's path: its path-derived module, and its path-derived name, mapped to
    # the wheel's. Taken from all symbols, not only those still to move, so that picks and
    # entry points merged again into an already relabelled record move too.
    renamed: dict[str, str] = {}
    raw_names: dict[str, set[str]] = {}
    symbols = []
    for symbol in record.symbols:
        module = module_under(symbol.path, names.names)
        old = module_for_path(symbol.path)
        # A name must never move twice, so a module never maps to one that extends it.
        if module is not None and old is not None and not f"{module}.".startswith(f"{old}."):
            renamed[old] = module
        if module is None or module == symbol.module:
            moved = symbol
        else:
            moved = Symbol(
                qualified_name=f"{module}.{symbol.name}",
                module=module,
                name=symbol.name,
                kind=symbol.kind,
                path=symbol.path,
            )
        symbols.append(moved)
        raw = f"{old}.{symbol.name}" if old else symbol.name
        raw_names.setdefault(raw, set()).add(moved.qualified_name)
    # Paths only the picks still cite (a second path that installs as the same module, whose
    # symbol an earlier relabel merged into one) move the same way.
    for path in sorted({h.path for item in record.evidence for h in item.hunks}):
        module = module_under(path, names.names)
        old = module_for_path(path)
        if module is not None and old is not None and not f"{module}.".startswith(f"{old}."):
            renamed.setdefault(old, module)
    by_old_name = {raw: next(iter(new)) for raw, new in raw_names.items() if len(new) == 1}
    by_old_name.update(
        {
            old.qualified_name: new.qualified_name
            for old, new in zip(record.symbols, symbols, strict=True)
        }
    )

    def move(name: str) -> str:
        if name in by_old_name:
            return by_old_name[name]
        for old in sorted(renamed, key=len, reverse=True):
            if name.startswith(f"{old}."):
                return renamed[old] + name[len(old) :]
        return name

    # Two paths can install as one module (``python2/httplib2`` and ``python3/httplib2``):
    # one symbol per name, and its evidence keeps every cited hunk.
    unique: dict[str, Symbol] = {}
    for symbol in sorted(symbols, key=lambda s: (s.qualified_name, s.path)):
        unique.setdefault(symbol.qualified_name, symbol)
    evidence: dict[str, SymbolEvidence] = {}
    for item in record.evidence:
        name = move(item.qualified_name)
        if name in evidence:
            first = evidence[name]
            hunks = tuple(dict.fromkeys((*first.hunks, *item.hunks)))
            evidence[name] = first.model_copy(update={"hunks": hunks})
        else:
            evidence[name] = SymbolEvidence(
                qualified_name=name, rationale=item.rationale, hunks=item.hunks
            )
    return record.model_copy(
        update={
            "import_roots": names.names,
            "symbols": tuple(unique.values()),
            "entry_points": tuple(dict.fromkeys(move(e) for e in record.entry_points)),
            "evidence": tuple(evidence.values()),
        }
    )


class Annotation(BaseModel):
    """What one ``import-names`` run did."""

    model_config = ConfigDict(frozen=True)

    packages: int
    reused: int  # names carried from the previous release
    read: int  # names read from wheels in this run
    without_names: dict[str, str]  # package -> why no names (no wheel, not on PyPI, error)
    records_relabelled: int
    symbols_moved: int  # symbols under a new qualified name


def annotate(
    records: list[Record],
    index: WheelIndex,
    previous: Mapping[str, ImportNames] | None = None,
) -> tuple[list[Record], list[ImportNames], Annotation]:
    """Import names for every package with a record, and the records relabelled with them.

    Names already read for the previous release are reused, so a nightly run reads only
    new packages. A package with no names is asked again every run: it may gain a wheel.
    A failure for one package leaves its records as they were and is reported.
    """
    previous = previous or {}
    found: dict[str, ImportNames] = {}
    reused = read = 0
    for package in sorted({r.package for r in records}):
        earlier = previous.get(package)
        if earlier is not None and earlier.names:
            found[package], reused = earlier, reused + 1
            continue
        try:
            found[package] = index.import_names(package)
        except (HttpError, ValueError, httpx.HTTPError) as error:
            found[package] = ImportNames(
                package=package, names=(), source=f"error: {type(error).__name__}: {error}"[:300]
            )
        read += bool(found[package].names)
    relabelled = [relabel(r, found[r.package]) for r in records]
    moved = sum(
        len({s.qualified_name for s in new.symbols} - {s.qualified_name for s in old.symbols})
        for old, new in zip(records, relabelled, strict=True)
    )
    annotation = Annotation(
        packages=len(found),
        reused=reused,
        read=read,
        without_names={p: n.source for p, n in found.items() if not n.names},
        records_relabelled=sum(a != b for a, b in zip(records, relabelled, strict=True)),
        symbols_moved=moved,
    )
    return relabelled, [found[p] for p in sorted(found)], annotation
