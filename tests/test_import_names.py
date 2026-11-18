"""Import names from wheel file lists, and records relabelled with them."""

import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from tenacity import wait_none
from typer.testing import CliRunner

from patchsight import db
from patchsight.db import FixCommitRef, HunkLocation, ImportNames, Record, Symbol, SymbolEvidence
from patchsight.pipeline import gate, import_names
from patchsight.pipeline.__main__ import app
from patchsight.pipeline.http import CacheMissError
from patchsight.pipeline.import_names import (
    WheelIndex,
    central_directory_names,
    module_under,
    relabel,
    top_level_names,
)
from patchsight.pipeline.pypi import PyPIClient

NOW = datetime(2026, 11, 18, tzinfo=UTC)


def _zip(names: list[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"x" * 50)
    return buffer.getvalue()


def test_top_level_names_reads_packages_modules_and_extensions() -> None:
    files = [
        "keras/__init__.py", "keras/src/saving/saving_lib.py", "six.py", "_speedups.abi3.so",
        "langgraph/store/sqlite/base.py",  # a namespace package: no __init__.py
        "demo-1.0.dist-info/RECORD", "demo-1.0.data/purelib/extra/__init__.py",
        "demo-1.0.data/scripts/tool", "ansible-webui/aw/__init__.py",  # not importable
        "licenses/LICENSE.txt", "share/data/x.json", "__pycache__/x.cpython-312.pyc",
        "stubs/__init__.pyi",
    ]  # fmt: skip
    assert top_level_names(files) == (
        "_speedups", "extra", "keras", "langgraph", "six", "stubs",
    )  # fmt: skip


def test_the_central_directory_is_read_from_the_tail_or_fetched() -> None:
    names = [f"pkg/module_{i}.py" for i in range(40)] + ["pkg-1.0.dist-info/RECORD"]
    data = _zip(names)
    assert central_directory_names(data, len(data), None) == names
    fetched: list[tuple[int, int]] = []

    def fetch(start: int, end: int) -> bytes:
        fetched.append((start, end))
        return data[start : end + 1]

    tail = data[-30:]  # only the end-of-directory record
    assert central_directory_names(tail, len(data), fetch) == names
    assert len(fetched) == 1
    with pytest.raises(ValueError, match="end-of-central-directory"):
        central_directory_names(b"not a zip", 9, fetch)


def _wheel(name: str, version: str, data: bytes, kind: str = "py3-none-any") -> dict:
    filename = f"{name}-{version}-{kind}.whl"
    return {
        "filename": filename, "packagetype": "bdist_wheel", "yanked": False,
        "url": f"https://files.pythonhosted.org/packages/ab/{filename}", "size": len(data),
        "digests": {"sha256": f"{version}{kind}".encode().hex().ljust(64, "0")},
    }  # fmt: skip


def _index(tmp_path: Path, wheels: dict[str, bytes]) -> tuple[WheelIndex, list[str]]:
    """A PyPI with package ``demo``: 1.0 shipped module ``old_name``, 2.0 ``demo``."""
    releases = {
        "1.0": [_wheel("demo", "1.0", wheels["1.0"])],
        "2.0": [
            _wheel("demo", "2.0", wheels["2.0-win"], "cp312-cp312-win_amd64"),
            _wheel("demo", "2.0", wheels["2.0"]),
        ],
        "3.0rc1": [{**_wheel("demo", "3.0rc1", b""), "yanked": True}],
        "0.1": [{"packagetype": "sdist", "url": "https://files.pythonhosted.org/x.tar.gz"}],
    }
    by_url = {
        releases["1.0"][0]["url"]: wheels["1.0"],
        releases["2.0"][0]["url"]: wheels["2.0-win"],
        releases["2.0"][1]["url"]: wheels["2.0"],
    }
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "pypi.org":
            if request.url.path == "/pypi/demo/json":
                return httpx.Response(200, json={"releases": releases})
            return httpx.Response(404)
        data = by_url[str(request.url)]
        start, end = (int(x) for x in request.headers["Range"].removeprefix("bytes=").split("-"))
        return httpx.Response(206, content=data[start : end + 1])

    transport = httpx.MockTransport(handler)
    pypi = PyPIClient(tmp_path / "pypi", transport=transport, wait=wait_none())
    return WheelIndex(pypi, tmp_path / "wheels", transport=transport), seen


def test_names_come_from_the_newest_and_oldest_wheels_and_are_cached(tmp_path: Path) -> None:
    wheels = {
        "1.0": _zip(["old_name/__init__.py", "demo-1.0.dist-info/RECORD"]),
        "2.0": _zip(["demo/__init__.py", "demo/core.py", "demo-2.0.dist-info/RECORD"]),
        "2.0-win": _zip(["demo/__init__.py", "demo/_native.pyd"]),
    }
    index, seen = _index(tmp_path, wheels)
    names = index.import_names("Demo")
    assert names == ImportNames(
        package="demo", names=("demo", "old_name"),
        source="demo-2.0-py3-none-any.whl, demo-1.0-py3-none-any.whl",
    )  # fmt: skip
    assert not any("win_amd64" in u or "3.0rc1" in u for u in seen)  # pure wheel; no yanked
    requests = len(seen)
    assert index.import_names("demo") == names
    assert len(seen) == requests  # PyPI's answer and both file lists come from the cache
    assert index.import_names("missing").source == "not on PyPI"
    offline = WheelIndex(index.pypi, tmp_path / "elsewhere", offline=True)
    with pytest.raises(CacheMissError):
        offline.import_names("demo")


def test_only_pythonhosted_files_are_read(tmp_path: Path) -> None:
    index, _ = _index(tmp_path, {"1.0": b"", "2.0": b"", "2.0-win": b""})
    wheel = {"url": "https://example.org/demo.whl", "size": 10, "digests": {"sha256": "0" * 64}}
    with pytest.raises(ValueError, match=r"not on files\.pythonhosted\.org"):
        index.files(wheel)


def test_module_under_starts_at_the_first_import_root() -> None:
    assert module_under("airflow-core/src/airflow/models/dag.py", ["airflow"]) == (
        "airflow.models.dag"
    )
    assert module_under("lib/yaml/__init__.py", ["yaml"]) == "yaml"
    assert module_under("tests/test_x.py", ["yaml"]) is None
    assert module_under("docs/conf.txt", ["docs"]) is None


def _record(**update: object) -> Record:
    record = Record(
        vulnerability="GHSA-0001", package="keras", confidence="low", source="llm",
        import_roots=("saving",), entry_points=("saving.saving_lib.load_model", "keras.x"),
        symbols=(
            Symbol(qualified_name="saving.saving_lib.H5IOStore.get", module="saving.saving_lib",
                   name="H5IOStore.get", kind="method", path="keras/src/saving/saving_lib.py"),
            Symbol(qualified_name="integration_tests.helper", module="integration_tests",
                   name="helper", kind="function", path="integration_tests/__init__.py"),
        ),
        fix_commits=(FixCommitRef(repo="keras-team/keras", sha="a" * 40),), model="m",
        prompt_version="extract-v1", input_hash="h", advisory_modified=NOW, truncated=False,
        extracted_at=NOW,
        evidence=(SymbolEvidence(
            qualified_name="saving.saving_lib.H5IOStore.get", rationale="r",
            hunks=(HunkLocation(commit="a" * 40, path="keras/src/saving/saving_lib.py",
                                old_start=1, old_count=1, new_start=1, new_count=1),),
        ),),
    )  # fmt: skip
    return record.model_copy(update=update)


def test_relabel_moves_symbols_entry_points_and_evidence_under_the_wheel_roots() -> None:
    names = ImportNames(package="keras", names=("keras",), source="keras-3.15.1-py3-none-any.whl")
    record = relabel(_record(), names)
    assert record.import_roots == ("keras",)
    assert [s.qualified_name for s in record.symbols] == [
        "integration_tests.helper",  # not installed by the wheel: unchanged
        "keras.src.saving.saving_lib.H5IOStore.get",
    ]
    assert record.entry_points == ("keras.src.saving.saving_lib.load_model", "keras.x")
    assert record.evidence[0].qualified_name == "keras.src.saving.saving_lib.H5IOStore.get"
    assert relabel(record, names) == record  # idempotent
    assert relabel(_record(), None) == _record()
    unread = ImportNames(package="keras", names=(), source="no wheel on PyPI")
    assert relabel(_record(), unread) == _record()


def test_annotate_reuses_earlier_names_and_reports_failures(tmp_path: Path) -> None:
    asked: list[str] = []

    class Index:
        def import_names(self, package: str) -> ImportNames:
            asked.append(package)
            if package == "broken":
                raise import_names.HttpError("gave up")
            return ImportNames(package=package, names=("keras",), source="w.whl")

    records = [_record(), _record(package="broken"), _record(package="cached")]
    earlier = {"cached": ImportNames(package="cached", names=("keras",), source="old.whl")}
    relabelled, names, report = import_names.annotate(records, Index(), earlier)  # type: ignore[arg-type]
    assert asked == ["broken", "keras"]
    assert (report.packages, report.reused, report.read) == (3, 1, 1)
    assert report.without_names == {"broken": "error: HttpError: gave up"}
    assert relabelled[1] == records[1]
    assert (report.records_relabelled, report.symbols_moved) == (2, 2)
    assert [n.package for n in names] == ["broken", "cached", "keras"]


def test_the_command_annotates_in_place_and_the_gate_then_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "db.sqlite"
    builds = [db.BuildEntry(vulnerability="GHSA-0001", input_hash="h", status="built")]
    db.write(path, [_record()], {"GHSA-0001": "GHSA-0001"}, {"db_version": "2026.11.18.1"},
             builds=builds)  # fmt: skip
    before = db.SymbolDatabase(path)
    try:
        assert "import_names" in {c.name for c in gate.run(before, before).checks if not c.passed}
    finally:
        before.close()

    def fake(self: WheelIndex, package: str) -> ImportNames:
        return ImportNames(package=package, names=("keras",), source="keras-3.15.1.whl")

    monkeypatch.setattr(WheelIndex, "import_names", fake)
    result = CliRunner().invoke(app, ["import-names", "db.sqlite", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "1 packages: 0 reused, 1 read from wheels" in result.output
    after = db.SymbolDatabase(path)
    try:
        assert after.import_names()["keras"].names == ("keras",)
        assert after.all_records()[0].import_roots == ("keras",)
        assert after.meta["db_version"] == "2026.11.18.1"
        assert json.loads(after.meta["import_names"]) == {"packages": 1, "with_names": 1}
        assert after.build_ledger()  # carried over
        assert gate.run(after, after).passed
    finally:
        after.close()
    assert (tmp_path / "db-import-names.json").exists()


def test_two_paths_that_install_as_one_module_give_one_symbol() -> None:
    def symbol(tree: str) -> Symbol:
        return Symbol(
            qualified_name=f"{tree}.httplib2.Http.request",
            module=f"{tree}.httplib2",
            name="Http.request",
            kind="method",
            path=f"{tree}/httplib2/__init__.py",
        )

    def evidence(tree: str) -> SymbolEvidence:
        hunk = HunkLocation(commit="a" * 40, path=f"{tree}/httplib2/__init__.py",
                            old_start=1, old_count=1, new_start=1, new_count=1)  # fmt: skip
        return SymbolEvidence(qualified_name=f"{tree}.httplib2.Http.request", rationale="r",
                              hunks=(hunk,))  # fmt: skip

    record = _record(
        package="httplib2",
        symbols=(symbol("python2"), symbol("python3")),
        evidence=(evidence("python2"), evidence("python3")),
        entry_points=(),
    )
    names = ImportNames(package="httplib2", names=("httplib2",), source="httplib2.whl")
    relabelled = relabel(record, names)
    assert [s.path for s in relabelled.symbols] == ["python2/httplib2/__init__.py"]
    assert [len(e.hunks) for e in relabelled.evidence] == [2]
    assert relabel(relabelled, names) == relabelled
