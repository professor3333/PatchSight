"""Stored callers raise an alert to CALLED, with the call path as evidence (ADR 0017)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight import db
from patchsight.scan import ast_scanner, run
from patchsight.scan.ast_scanner import Location, Reference, Usage
from patchsight.scan.report import render_markdown, render_text
from patchsight.scan.sarif import render_sarif
from patchsight.scan.verdicts import NameIndex, call_path, decide, matches

NOW = datetime(2026, 11, 28, tzinfo=UTC)
SYMBOL = "yaml.constructor.FullConstructor.construct_object"


def _record(confidence: str = "low", entry_points: tuple[str, ...] = ()) -> db.Record:
    return db.Record(
        vulnerability="GHSA-0001-0001-0001", package="pyyaml",
        confidence=confidence,  # type: ignore[arg-type]
        source="fallback", import_roots=("yaml",), entry_points=entry_points,
        symbols=(
            db.Symbol(qualified_name=SYMBOL, module="yaml.constructor",
                      name="FullConstructor.construct_object", kind="method",
                      path="lib/yaml/constructor.py"),
        ),
        fix_commits=(db.FixCommitRef(repo="yaml/pyyaml", sha="a" * 40),),
        model=None, prompt_version=None, input_hash="h", advisory_modified=NOW,
        truncated=False, extracted_at=NOW,
    )  # fmt: skip


EDGES = (
    ("yaml.full_load", "yaml.load"),
    ("yaml.load", SYMBOL),
    ("yaml.loader.FullLoader", "yaml.constructor.FullConstructor"),
    ("yaml.constructor.FullConstructor", SYMBOL),
)


def _callers(record: db.Record, status: str = "ok", digest: str | None = None) -> db.Callers:
    return db.Callers(
        vulnerability=record.vulnerability, package=record.package,
        symbols_digest=digest or db.symbols_digest(record), version="5.3.1",
        filename="PyYAML-5.3.1.tar.gz", sha256="b" * 64, status=status, seeds=1,
        seeds_found=1, graph_revision=2, callers=EDGES if status == "ok" else (),
    )  # fmt: skip


def _usage(tmp_path: Path, code: str) -> Usage:
    (tmp_path / "app.py").write_text(code)
    return ast_scanner.scan(tmp_path)


def test_a_reference_to_a_caller_is_called_with_the_path(tmp_path: Path) -> None:
    usage = _usage(tmp_path, "import yaml\n\n\ndef read(f):\n    return yaml.full_load(f)\n")
    record = _record()
    alert = decide("GHSA-0001-0001-0001", "pyyaml", "5.3.1", record, usage, None, _callers(record))
    assert alert.verdict == "CALLED"
    assert alert.matched == ("yaml.full_load",)
    assert alert.path == ("yaml.full_load", "yaml.load", SYMBOL)
    assert [(e.path, e.line) for e in alert.evidence] == [("app.py", 5)]
    assert "yaml.full_load" in alert.reason
    assert "pyyaml 5.3.1" in alert.reason
    # Without callers, the same low-confidence record gives UNKNOWN.
    assert decide("GHSA-0001-0001-0001", "pyyaml", "5.3.1", record, usage).verdict == "UNKNOWN"


def test_a_re_exported_caller_matches_like_a_symbol(tmp_path: Path) -> None:
    # yaml.FullLoader is yaml.loader.FullLoader, re-exported by the package's __init__.
    usage = _usage(tmp_path, "import yaml\n\nyaml.load(open('x'), Loader=yaml.FullLoader)\n")
    record = _record()
    alert = decide("A", "pyyaml", "5.3.1", record, usage, None, _callers(record))
    assert alert.verdict == "CALLED"
    assert alert.matched == ("yaml.FullLoader", "yaml.load")
    assert alert.path[0] in {"yaml.load", "yaml.loader.FullLoader"}
    assert alert.path[-1] == SYMBOL


def test_a_symbol_hit_comes_before_a_caller(tmp_path: Path) -> None:
    usage = _usage(
        tmp_path, "import yaml\n\nyaml.full_load(x)\nyaml.constructor.FullConstructor()\n"
    )
    record = _record()
    alert = decide("A", "pyyaml", "5.3.1", record, usage, None, _callers(record))
    assert alert.verdict == "CALLED"
    assert alert.reason == "your code references a vulnerable symbol"
    assert alert.path == ()


@pytest.mark.parametrize(
    ("status", "digest"),
    [("ok", "0" * 64), ("too many callers", None), ("no affected release with files", None)],
)
def test_callers_for_other_symbols_or_none_are_not_used(
    tmp_path: Path, status: str, digest: str | None
) -> None:
    usage = _usage(tmp_path, "import yaml\n\nyaml.full_load(x)\n")
    record = _record()
    stored = _callers(record, status, digest)
    if status == "ok":  # stale: computed for other symbols, though the edges are there
        assert stored.callers
    assert decide("A", "pyyaml", "5.3.1", record, usage, None, stored).verdict == "UNKNOWN"


def test_only_references_into_the_package_reach_callers(tmp_path: Path) -> None:
    # A first-party module that happens to define the same name is not the package's.
    usage = _usage(tmp_path, "import yaml\nfrom mylib import full_load\n\nfull_load(x)\n")
    record = _record()
    assert decide("A", "pyyaml", "5.3.1", record, usage, None, _callers(record)).verdict == (
        "UNKNOWN"
    )


def test_callers_only_ever_raise() -> None:
    """Every verdict without callers either stays or becomes CALLED with them."""
    record = _record("high", entry_points=())
    stored = _callers(record)
    loc = Location(path="app.py", line=1)
    names = ["yaml.full_load", "yaml.safe_load", "yaml.dump", "yaml.FullLoader", "yaml.x.load"]
    for chosen in range(1 << len(names)):
        refs = tuple(
            Reference(name=n, location=loc) for i, n in enumerate(names) if chosen >> i & 1
        )
        usage = Usage(imports={"yaml": (loc,)}, references=refs)
        without = decide("A", "pyyaml", "5.3.1", record, usage).verdict
        with_callers = decide("A", "pyyaml", "5.3.1", record, usage, None, stored).verdict
        assert with_callers in {without, "CALLED"}


def test_call_path_stops_on_a_cycle() -> None:
    assert call_path("a", {"a": "b", "b": "c"}) == ("a", "b", "c")
    assert call_path("a", {"a": "b", "b": "a"}) == ("a", "b", "a")


_PART = st.sampled_from(["p", "q", "m", "f", "__init__", "load"])
_NAME = st.lists(_PART, min_size=1, max_size=4).map(".".join)


@given(st.lists(_NAME, max_size=8), _NAME)
def test_the_name_index_matches_exactly_as_matches_does(names: list[str], reference: str) -> None:
    found = NameIndex(names).match(reference)
    assert (found is not None) == any(matches(reference, n) for n in names)
    if found is not None:
        assert found in names
        assert matches(reference, found)


def test_callers_for_reads_one_record(tmp_path: Path) -> None:
    record = _record()
    with_callers = tmp_path / "with.sqlite"
    db.write(with_callers, [record], {record.vulnerability: record.vulnerability}, {},
             callers=[_callers(record)])  # fmt: skip
    without = tmp_path / "without.sqlite"
    db.write(without, [record], {record.vulnerability: record.vulnerability}, {})
    database = db.SymbolDatabase(with_callers)
    try:
        stored = database.callers_for(record.vulnerability, "pyyaml")
        assert stored is not None
        assert stored.callers == tuple(sorted(EDGES))
        assert stored == database.callers()[(record.vulnerability, "pyyaml")]
        assert database.callers_for(record.vulnerability, "other") is None
    finally:
        database.close()
    older = db.SymbolDatabase(without)
    try:
        assert older.callers_for(record.vulnerability, "pyyaml") is None
    finally:
        older.close()


def test_a_scan_shows_the_call_path_in_every_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "requirements.txt").write_text("PyYAML==5.3.1\n")
    (project / "app.py").write_text("import yaml\n\nyaml.full_load(open('c.yml'))\n")
    record = _record()
    database = tmp_path / "db.sqlite"
    db.write(database, [record], {record.vulnerability: record.vulnerability},
             {"built_at": datetime.now(UTC).isoformat()}, callers=[_callers(record)])  # fmt: skip
    monkeypatch.setattr(
        run.osv_client,
        "query",
        lambda packages, client=None: {key: [record.vulnerability] for key in packages},
    )
    alerts, dependencies, meta = run.run_scan(project, project / "requirements.txt", database)
    assert [a.verdict for a in alerts] == ["CALLED"]
    path = "yaml.full_load -> yaml.load -> " + SYMBOL
    assert f"call path: {path}" in render_text(alerts, dependencies, "requirements.txt", meta)
    markdown = render_markdown(alerts, dependencies, "requirements.txt", meta)
    assert f"`yaml.full_load`, which reaches `{SYMBOL}`" in markdown
    result = json.loads(render_sarif(alerts, dependencies, "requirements.txt", meta))
    found = result["runs"][0]["results"][0]
    assert found["properties"]["callPath"] == path.split(" -> ")
    assert f"Call path: {path}." in found["message"]["text"]
