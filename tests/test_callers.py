"""Callers of each record's symbols, read from a release the record affects."""

import hashlib
import io
import json
import sqlite3
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from patchsight import db
from patchsight.pipeline import callers
from patchsight.pipeline.http import CacheMissError
from patchsight.pipeline.ingest.osv import Advisory, AffectedPackage, OsvEvent, VersionRange
from patchsight.pipeline.pypi import PyPIClient

NOW = datetime(2026, 11, 27, tzinfo=UTC)
CORE = b"def _parse(data):\n    return data\ndef unrelated():\n    pass\n"
API = b"from .core import _parse\ndef load(stream):\n    return _parse(stream)\n"


def _record(*names: str, vulnerability: str = "GHSA-1") -> db.Record:
    return db.Record(
        vulnerability=vulnerability, package="pkg", confidence="low", source="fallback",
        import_roots=("pkg",), entry_points=(),
        symbols=tuple(db.Symbol(qualified_name=n, module=n.rsplit(".", 1)[0],
                                name=n.rsplit(".", 1)[1], kind="function", path="pkg/core.py")
                      for n in names),
        fix_commits=(db.FixCommitRef(repo="o/pkg", sha="a" * 40),), model=None,
        prompt_version=None, input_hash="h" * 64, advisory_modified=NOW, truncated=False,
        extracted_at=NOW,
    )  # fmt: skip


def _package(versions: tuple[str, ...] = (), events: tuple[OsvEvent, ...] = ()) -> AffectedPackage:
    ranges = (VersionRange(type="ECOSYSTEM", events=events),) if events else ()
    return AffectedPackage(name="pkg", raw_name="pkg", ranges=ranges, versions=versions)


def _advisory(package: AffectedPackage) -> Advisory:
    return Advisory.model_construct(id="GHSA-1", packages=(package,))


def _wheel(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _file(name: str, data: bytes, kind: str = "bdist_wheel") -> dict[str, Any]:
    return {"filename": name, "url": f"https://files.pythonhosted.org/p/{name}",
            "size": len(data), "packagetype": kind,
            "digests": {"sha256": hashlib.sha256(data).hexdigest()}}  # fmt: skip


def test_affected_versions_come_from_the_list_or_else_the_ranges() -> None:
    releases = ["0.9", "1.0", "1.5", "2.0", "2.1", "bad version"]
    assert callers._versions([_package(versions=("1.0", "1.5"))], releases) == {"1.0", "1.5"}
    ranged = _package(events=(OsvEvent(introduced="1.0"), OsvEvent(fixed="2.0")))
    assert callers._versions([ranged], releases) == {"1.0", "1.5"}
    open_ended = _package(events=(OsvEvent(introduced="0"), OsvEvent(last_affected="1.5")))
    assert callers._versions([open_ended], releases) == {"0.9", "1.0", "1.5"}


def test_the_newest_affected_final_release_with_files_is_read() -> None:
    package = _package(versions=("1.0", "1.1", "1.2rc1", "1.3"))
    releases = {
        "1.0": [{"filename": "a"}], "1.1": [{"filename": "b"}], "1.2rc1": [{"filename": "c"}],
        "1.3": [{"filename": "d", "yanked": True}], "2.0": [{"filename": "e"}],
    }  # fmt: skip
    chosen = callers.vulnerable_release([package], releases)
    assert chosen is not None
    assert chosen[0] == "1.1"  # 1.3's only file is yanked, 1.2rc1 is a pre-release, 2.0 is fixed
    only_pre = callers.vulnerable_release([_package(versions=("1.2rc1",))], releases)
    assert only_pre is not None
    assert only_pre[0] == "1.2rc1"
    assert callers.vulnerable_release([_package(versions=("9.9",))], releases) is None


def test_a_pure_wheel_is_preferred_then_any_wheel_then_an_sdist_under_the_limit() -> None:
    pure = _file("pkg-1.0-py3-none-any.whl", b"x" * 10)
    platform = _file("pkg-1.0-cp312-cp312-manylinux.whl", b"x" * 5)
    sdist = _file("pkg-1.0.tar.gz", b"x" * 3, "sdist")
    huge = _file("pkg-1.0-py2-none-any.whl", b"x")
    huge["size"] = callers.MAX_BYTES + 1
    assert callers.choose_file([sdist, platform, pure, huge]) == pure
    assert callers.choose_file([sdist, platform]) == platform
    assert callers.choose_file([sdist, _file("pkg-1.0.tar.bz2", b"x", "sdist")]) == sdist
    assert callers.choose_file([huge]) is None


def test_python_sources_are_read_in_memory_within_the_limits() -> None:
    big = b"#" * (callers.MAX_MEMBER_BYTES + 1)
    wheel = _wheel({"pkg/core.py": CORE, "pkg/data.json": b"{}", "pkg/big.py": big})
    assert set(callers.python_sources(wheel, "pkg-1.0-py3-none-any.whl")) == {"pkg/core.py"}
    zipped = _wheel({"pkg-1.0/src/pkg/core.py": CORE})
    assert set(callers.python_sources(zipped, "pkg-1.0.zip")) == {"src/pkg/core.py"}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("pkg-1.0/lib/pkg/core.py")
        info.size = len(CORE)
        archive.addfile(info, io.BytesIO(CORE))
        link = tarfile.TarInfo("pkg-1.0/lib/pkg/link.py")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        archive.addfile(link)
    assert callers.python_sources(buffer.getvalue(), "pkg-1.0.tar.gz") == {"lib/pkg/core.py": CORE}


def _fetcher(
    tmp_path: Path, served: dict[str, bytes], offline: bool = False
) -> callers.DistFetcher:
    def handler(request: httpx.Request) -> httpx.Response:
        name = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, content=served[name]) if name in served else \
            httpx.Response(404)  # fmt: skip

    return callers.DistFetcher(tmp_path / "dists", httpx.MockTransport(handler), offline)


def test_files_come_only_from_pypi_checked_and_cached_by_their_digest(tmp_path: Path) -> None:
    wheel = _wheel({"pkg/core.py": CORE})
    good = _file("pkg-1.0-py3-none-any.whl", wheel)
    fetcher = _fetcher(tmp_path, {good["filename"]: wheel})
    assert fetcher.fetch(good) == wheel
    assert fetcher.fetch(good) == wheel  # from the cache
    assert fetcher.downloads == 1
    with pytest.raises(ValueError, match=r"not on files\.pythonhosted\.org"):
        fetcher.fetch({**good, "url": "https://example.com/pkg.whl"})
    tampered = {**_file("pkg-2.0-py3-none-any.whl", wheel), "digests": {"sha256": "0" * 64}}
    with pytest.raises(ValueError, match="SHA-256"):
        _fetcher(tmp_path, {tampered["filename"]: wheel}).fetch(tampered)
    with pytest.raises(CacheMissError):
        _fetcher(tmp_path / "other", {}, offline=True).fetch(good)


def _pypi(tmp_path: Path, releases: dict[str, list[dict[str, Any]]]) -> PyPIClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"releases": releases})

    return PyPIClient(tmp_path / "pypi", transport=httpx.MockTransport(handler))


def test_each_record_gets_its_callers_and_unchanged_records_reuse_theirs(tmp_path: Path) -> None:
    old = _wheel({"pkg/__init__.py": b"", "pkg/core.py": CORE, "pkg/api.py": API})
    new = _wheel({"pkg/__init__.py": b"", "pkg/core.py": b"def _parse(d):\n    return 1\n"})
    files = {"1.0": [_file("pkg-1.0-py3-none-any.whl", old)],
             "2.0": [_file("pkg-2.0-py3-none-any.whl", new)]}  # fmt: skip
    advisory = _advisory(_package(versions=("1.0",)))
    records = [_record("pkg.core._parse"), _record("pkg.core.gone", vulnerability="GHSA-2"),
               _record("pkg.core.unrelated", vulnerability="GHSA-3")]  # fmt: skip
    pypi = _pypi(tmp_path, files)
    fetcher = _fetcher(tmp_path, {"pkg-1.0-py3-none-any.whl": old})
    found, report = callers.annotate(records, lambda v: [advisory], pypi, fetcher)
    first, missing, alone = found
    assert (first.status, first.version, first.seeds, first.seeds_found) == ("ok", "1.0", 1, 1)
    assert first.callers == (("pkg.api.load", "pkg.core._parse"),)
    assert missing.status == "symbols not in the release"
    assert (alone.status, alone.callers) == ("ok", ())
    assert (report.computed, report.releases_read, report.downloads) == (3, 1, 1)
    assert report.statuses == {"ok": 2, "symbols not in the release": 1}

    previous = {(c.vulnerability, c.package): c for c in found}
    again, report = callers.annotate(records, lambda v: [], pypi, fetcher, previous)
    assert again == found
    assert (report.reused, report.computed) == (3, 0)
    changed = [_record("pkg.core._parse", "pkg.core.unrelated")]
    recomputed, report = callers.annotate(changed, lambda v: [advisory], pypi, fetcher, previous)
    assert report.computed == 1  # its symbols changed, so its callers are computed again
    assert recomputed[0].seeds == 2


def test_a_record_with_no_affected_release_says_so(tmp_path: Path) -> None:
    pypi = _pypi(tmp_path, {"2.0": [_file("pkg-2.0-py3-none-any.whl", b"x")]})
    advisory = _advisory(_package(versions=("1.0",)))
    found, _ = callers.annotate([_record("pkg.core._parse")], lambda v: [advisory], pypi,
                                _fetcher(tmp_path, {}))  # fmt: skip
    assert found[0].status == "no affected release with files"


def test_the_database_keeps_callers_and_an_older_one_has_none(tmp_path: Path) -> None:
    stored = db.Callers(
        vulnerability="GHSA-1", package="pkg", symbols_digest="d" * 64, version="1.0",
        filename="pkg-1.0-py3-none-any.whl", sha256="s" * 64, status="ok", seeds=1,
        seeds_found=1, callers=(("pkg.api.load", "pkg.core._parse"),),
    )  # fmt: skip
    path = tmp_path / "db.sqlite"
    db.write(path, [_record("pkg.core._parse")], {"GHSA-1": "GHSA-1"}, {}, callers=[stored])
    assert db.SymbolDatabase(path).callers() == {("GHSA-1", "pkg"): stored}
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE callers")
        connection.execute("DROP TABLE callers_source")
    assert db.SymbolDatabase(path).callers() == {}
    assert json.dumps(stored.model_dump())  # plain data, no code


def test_a_database_without_callers_keeps_exactly_its_old_tables(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    db.write(path, [_record("pkg.core._parse")], {"GHSA-1": "GHSA-1"}, {})
    with sqlite3.connect(path) as connection:
        tables = {
            r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert tables == {"meta", "aliases", "records", "symbols", "extraction", "builds", "evidence",
                      "import_names"}  # fmt: skip
