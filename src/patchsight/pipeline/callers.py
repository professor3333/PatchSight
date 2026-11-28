"""Callers of each record's symbols, read from a release the record affects (issue #162).

A record lists the definitions the fix changed. Users often reach them through definitions
the fix left alone, which ``pipeline.callgraph`` finds from the package's own source. This
step chooses, for each record, the newest release its advisories list as affected that has
a file on PyPI, reads that file's Python source and stores the record's callers closure
(``db.Callers``), with one path towards a symbol per caller.

**Which file:** a pure-Python wheel first, then any wheel (its Python files are the same),
then an sdist, none over ``MAX_BYTES``. Files come only from ``files.pythonhosted.org``,
are checked against PyPI's SHA-256 and cached by it, outside git (rule 13). An archive is
read in memory, never unpacked: only regular ``.py`` members, each at most
``MAX_MEMBER_BYTES``, at most ``MAX_SOURCE_BYTES`` in all.

**Which version:** the advisories' explicit ``versions`` list, else their ``ECOSYSTEM``
ranges; among the releases with files, the newest final release, or the newest of any
kind if none is final.

Offline pipeline only; the scanner reads the stored callers and never package source.
"""

import hashlib
import io
import tarfile
import time
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from patchsight.db import Callers, Record
from patchsight.names import canonical_package_name
from patchsight.pipeline import callgraph
from patchsight.pipeline.http import CacheMissError, HttpError, NotFoundError
from patchsight.pipeline.ingest.osv import Advisory, AffectedPackage
from patchsight.pipeline.pypi import PyPIClient

FILES_HOST = "files.pythonhosted.org"
MAX_BYTES = 50_000_000  # largest file read
MAX_MEMBER_BYTES = 5_000_000  # largest .py file read from it
MAX_SOURCE_BYTES = 200_000_000  # Python source read from one file, in all
CACHE_SUFFIX = ".dist"
# A record whose callers are more than this many keeps none ("too many callers"): almost
# anything in such a package reaches its symbols, so the callers would sharpen no alert,
# and they would multiply the database. The same bound as a fix too broad to extract.
MAX_CALLERS = 500


def symbols_digest(record: Record) -> str:
    """Names the record symbols a closure was computed for."""
    names = "\n".join(sorted({s.qualified_name for s in record.symbols}))
    return hashlib.sha256(names.encode("utf-8")).hexdigest()


def _versions(packages: Iterable[AffectedPackage], releases: Iterable[str]) -> set[str]:
    """The releases the advisories call affected: listed, else inside a range."""
    listed: set[str] = set()
    ranges = []
    for p in packages:
        listed |= set(p.versions)
        ranges += [r for r in p.ranges if r.type == "ECOSYSTEM"]
    if listed:
        return listed
    affected = set()
    for release in releases:
        try:
            version = Version(release)
        except InvalidVersion:
            continue
        for r in ranges:
            inside = False
            for event in r.events:  # OSV events are ordered: introduced, then fixed, ...
                try:
                    if event.introduced is not None:
                        inside = (
                            inside
                            or event.introduced == "0"
                            or version >= Version(event.introduced)
                        )
                    if event.fixed is not None and version >= Version(event.fixed):
                        inside = False
                    if event.last_affected is not None and version > Version(event.last_affected):
                        inside = False
                except InvalidVersion:
                    continue
            if inside:
                affected.add(release)
    return affected


def vulnerable_release(
    packages: Sequence[AffectedPackage], releases: Mapping[str, Sequence[Mapping[str, Any]]]
) -> tuple[str, Sequence[Mapping[str, Any]]] | None:
    """The newest affected release with files (a final release if any), and its files."""
    affected = _versions(packages, releases)
    candidates: list[tuple[bool, Version, str]] = []
    for release, files in releases.items():
        if release not in affected or not [f for f in files if not f.get("yanked")]:
            continue
        try:
            version = Version(release)
        except InvalidVersion:
            continue
        candidates.append((not (version.is_prerelease or version.is_devrelease), version, release))
    if not candidates:
        return None
    _, _, chosen = max(candidates)
    return chosen, releases[chosen]


def choose_file(files: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """A pure wheel, else the smallest wheel, else an sdist; none over ``MAX_BYTES``."""
    usable = [
        f for f in files
        if not f.get("yanked") and int(f.get("size", 0)) <= MAX_BYTES and f.get("url")
        and (f.get("digests") or {}).get("sha256")
    ]  # fmt: skip
    wheels = sorted(
        (f for f in usable if f.get("packagetype") == "bdist_wheel"),
        key=lambda f: ("-none-any" not in str(f["filename"]), int(f["size"])),
    )
    sdists = sorted(
        (f for f in usable if f.get("packagetype") == "sdist"
         and str(f["filename"]).endswith((".tar.gz", ".tgz", ".zip"))),
        key=lambda f: int(f["size"]),
    )  # fmt: skip
    chosen = wheels or sdists
    return chosen[0] if chosen else None


def python_sources(data: bytes, filename: str) -> dict[str, bytes]:
    """The ``.py`` files in a wheel or sdist, by path inside the package (an sdist's top
    folder removed), read in memory within the size limits."""
    found: dict[str, bytes] = {}
    total = 0

    def add(name: str, size: int, read: Callable[[], bytes]) -> None:
        nonlocal total
        if not name.endswith(".py") or size > MAX_MEMBER_BYTES or total + size > MAX_SOURCE_BYTES:
            return
        content = read()[: MAX_MEMBER_BYTES + 1]
        if len(content) > MAX_MEMBER_BYTES:
            return
        total += len(content)
        found[name] = content

    sdist = not filename.endswith(".whl")
    if filename.endswith((".whl", ".zip")):
        with zipfile.ZipFile(io.BytesIO(data)) as zipped:
            for info in zipped.infolist():
                if not info.is_dir():
                    name = info.filename.split("/", 1)[-1] if sdist else info.filename
                    add(name, info.file_size, partial(zipped.read, info))
        return found
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tarred:
        for member in tarred:
            extracted = tarred.extractfile(member) if member.isreg() else None
            if extracted is not None:
                add(member.name.split("/", 1)[-1], member.size, extracted.read)
    return found


class _Retryable(Exception):
    pass


class DistFetcher:
    """Downloads release files from PyPI's file host, checked and cached by SHA-256."""

    def __init__(
        self,
        cache_dir: Any,
        transport: httpx.BaseTransport | None = None,
        offline: bool = False,
    ) -> None:
        self.cache_dir = cache_dir
        self.offline = offline
        self.downloads = 0
        self.bytes = 0
        self._http = httpx.Client(
            headers={"User-Agent": "patchsight-pipeline"},
            timeout=httpx.Timeout(120.0, connect=15.0),
            follow_redirects=False,
            transport=transport,
        )

    def close(self) -> None:
        self._http.close()

    def fetch(self, file: Mapping[str, Any]) -> bytes:
        url, digest = str(file["url"]), str(file["digests"]["sha256"])
        if httpx.URL(url).host != FILES_HOST:
            raise ValueError(f"{url}: not on {FILES_HOST}")
        cached = self.cache_dir / digest[:2] / f"{digest}{CACHE_SUFFIX}"
        if cached.exists():
            return bytes(cached.read_bytes())
        if self.offline:
            raise CacheMissError(f"{file.get('filename', url)}: not in the offline cache")
        for attempt in Retrying(
            retry=retry_if_exception_type(_Retryable), stop=stop_after_attempt(4),
            wait=wait_exponential(multiplier=1, max=30), reraise=True,
        ):  # fmt: skip
            with attempt:
                try:
                    response = self._http.get(url)
                except httpx.TransportError as error:
                    raise _Retryable(str(error)) from error
                if response.status_code in (429, 500, 502, 503, 504):
                    raise _Retryable(f"HTTP {response.status_code}")
                if response.status_code != 200:
                    raise ValueError(f"{url}: HTTP {response.status_code}")
                data = response.content
        if len(data) > MAX_BYTES:
            raise ValueError(f"{url}: {len(data):,} bytes, over the limit")
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"{url}: SHA-256 does not match PyPI's")
        self.downloads += 1
        self.bytes += len(data)
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
        return data


class CallersReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    records: int
    reused: int  # from the previous database: same symbols
    computed: int
    statuses: dict[str, int]
    records_with_callers: int
    callers: int
    callers_median: float
    callers_p90: int
    callers_max: int
    releases_read: int  # distinct files parsed
    downloads: int
    downloaded_bytes: int
    seconds: float
    slowest: tuple[tuple[str, float], ...] = ()  # release files, seconds to parse and close


def _packages_of(advisories: Iterable[Advisory], package: str) -> list[AffectedPackage]:
    return [p for a in advisories for p in a.packages
            if canonical_package_name(p.name) == package]  # fmt: skip


def annotate(
    records: Sequence[Record],
    advisories_for: Callable[[str], Sequence[Advisory]],
    pypi: PyPIClient,
    fetcher: DistFetcher,
    previous: Mapping[tuple[str, str], Callers] | None = None,
    progress: Callable[[int, int], None] | None = None,
    jobs: int = 1,
) -> tuple[list[Callers], CallersReport]:
    """Callers for every record, in record order. A previous database's are reused while
    the record's symbols are the same; a failure for one record is stored as its status.

    Records are planned first (which release file each needs), then each file is read and
    parsed once for all its records. With ``jobs`` above 1, files are handled in that many
    processes; every record's result is the same either way."""
    started = time.monotonic()
    previous = previous or {}
    found: list[Callers | None] = [None] * len(records)
    groups: dict[str, list[_Item]] = {}
    files: dict[str, Mapping[str, Any]] = {}
    reused = 0
    for index, record in enumerate(records):
        digest = symbols_digest(record)
        earlier = previous.get((record.vulnerability, record.package))
        if earlier is not None and earlier.symbols_digest == digest:
            found[index], reused = _capped(earlier), reused + 1
            continue
        planned = _plan(record, digest, advisories_for, pypi)
        if isinstance(planned, Callers):
            found[index] = planned
            continue
        file, base = planned
        sha = str(file["digests"]["sha256"])
        files[sha] = file
        groups.setdefault(sha, []).append(_Item(index=index, base=base, seeds=_seeds(record)))
    # The largest files first, so that a slow one does not finish last.
    order = sorted(groups, key=lambda sha: (-int(files[sha].get("size", 0)), sha))
    read = downloads = downloaded = 0
    timings: list[tuple[float, str]] = []
    if jobs <= 1:
        for done, sha in enumerate(order):
            if progress is not None:
                progress(done, len(order))
            results, was_read, took = _run_group(fetcher, files[sha], groups[sha])
            read += was_read
            timings.append((took, str(files[sha]["filename"])))
            for item, result in zip(groups[sha], results, strict=True):
                found[item.index] = result
        downloads, downloaded = fetcher.downloads, fetcher.bytes
    else:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            futures = {
                pool.submit(_worker, fetcher.cache_dir, fetcher.offline, dict(files[sha]),
                            groups[sha]): sha
                for sha in order
            }  # fmt: skip
            for done, future in enumerate(as_completed(futures)):
                if progress is not None:
                    progress(done, len(order))
                results, was_read, count, size, took = future.result()
                read, downloads, downloaded = read + was_read, downloads + count, downloaded + size
                timings.append((took, str(files[futures[future]]["filename"])))
                for item, result in zip(groups[futures[future]], results, strict=True):
                    found[item.index] = result
    stored = [c for c in found if c is not None]
    if len(stored) != len(records):  # pragma: no cover - every record is planned above
        raise RuntimeError("a record was left without a result")
    sizes = sorted(len(c.callers) for c in stored if c.status == "ok")
    report = CallersReport(
        records=len(records), reused=reused, computed=len(records) - reused,
        statuses=dict(sorted(Counter(c.status for c in stored).items())),
        records_with_callers=sum(1 for c in stored if c.callers),
        callers=sum(len(c.callers) for c in stored),
        callers_median=float(sizes[len(sizes) // 2]) if sizes else 0.0,
        callers_p90=sizes[int(0.9 * (len(sizes) - 1))] if sizes else 0,
        callers_max=sizes[-1] if sizes else 0,
        releases_read=read, downloads=downloads, downloaded_bytes=downloaded,
        seconds=round(time.monotonic() - started, 1),
        slowest=tuple((name, round(took, 1)) for took, name in sorted(timings, reverse=True)[:10]),
    )  # fmt: skip
    return stored, report


class _Item(BaseModel):
    """One record waiting for a release file: where it goes, and what it needs."""

    model_config = ConfigDict(frozen=True)

    index: int
    base: dict[str, Any]
    seeds: frozenset[str]


def _capped(found: Callers) -> Callers:
    if len(found.callers) <= MAX_CALLERS:
        return found
    return found.model_copy(update={"status": "too many callers", "callers": ()})


def _seeds(record: Record) -> frozenset[str]:
    return frozenset(s.qualified_name for s in record.symbols)


def _plan(
    record: Record,
    digest: str,
    advisories_for: Callable[[str], Sequence[Advisory]],
    pypi: PyPIClient,
) -> Callers | tuple[Mapping[str, Any], dict[str, Any]]:
    """The release file a record needs, or its result already when it needs none."""
    base: dict[str, Any] = {
        "vulnerability": record.vulnerability, "package": record.package,
        "symbols_digest": digest, "version": None, "filename": None, "sha256": None,
        "seeds": len(_seeds(record)), "seeds_found": 0,
    }  # fmt: skip
    packages = _packages_of(advisories_for(record.vulnerability), record.package)
    try:
        data: dict[str, Any] = pypi.http.get_json(f"/pypi/{record.package}/json")
    except NotFoundError:
        return Callers(**base, status="not on PyPI")
    except (HttpError, httpx.HTTPError) as error:
        return Callers(**base, status=f"error: {type(error).__name__}")
    chosen = vulnerable_release(packages, data.get("releases") or {})
    if chosen is None:
        return Callers(**base, status="no affected release with files")
    version, files = chosen
    file = choose_file(files)
    base["version"] = version
    if file is None:
        return Callers(**base, status="no file under the size limit")
    base.update(filename=str(file["filename"]), sha256=str(file["digests"]["sha256"]))
    return file, base


def _run_group(
    fetcher: DistFetcher, file: Mapping[str, Any], items: Sequence[_Item]
) -> tuple[list[Callers], bool, float]:
    """Read one release file and give each of its records its callers; whether the file
    could be read, and the seconds it took."""
    started = time.monotonic()
    graph: callgraph.Graph | str
    try:
        sources = python_sources(fetcher.fetch(file), str(file["filename"]))
        graph = callgraph.build(sources) if sources else "no Python source"
    except CacheMissError:
        graph = "not in the offline cache"
    except (ValueError, OSError, zipfile.BadZipFile, tarfile.TarError, httpx.HTTPError,
            HttpError) as error:  # fmt: skip
        graph = f"error: {type(error).__name__}"
    results = []
    for item in items:
        if isinstance(graph, str):
            results.append(Callers(**item.base, status=graph))
            continue
        seeds = item.seeds & set(graph.kinds)
        if not seeds:
            results.append(Callers(**{**item.base, "seeds_found": 0},
                                   status="symbols not in the release"))  # fmt: skip
            continue
        toward = callgraph.closure(graph, seeds)
        edges = tuple(sorted((c, t) for c, t in toward.items() if c not in seeds))
        results.append(_capped(Callers(**{**item.base, "seeds_found": len(seeds)}, status="ok",
                                       callers=edges)))  # fmt: skip
    return results, not isinstance(graph, str), time.monotonic() - started


def _worker(
    cache_dir: Any, offline: bool, file: Mapping[str, Any], items: Sequence[_Item]
) -> tuple[list[Callers], bool, int, int, float]:
    """``_run_group`` in a worker process, with its own fetcher."""
    fetcher = DistFetcher(cache_dir, offline=offline)
    try:
        results, read, took = _run_group(fetcher, file, items)
        return results, read, fetcher.downloads, fetcher.bytes, took
    finally:
        fetcher.close()
