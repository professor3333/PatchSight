"""Stored callers raise an alert to CALLED, with the call path as evidence (ADR 0017)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from patchsight import db
from patchsight.cli import app
from patchsight.scan import ast_scanner, explain, run
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
    ("yaml.loader.Loader.load_all", SYMBOL),
)
# The names PyYAML binds to them: re-exports from yaml/__init__.py, and an alias for the
# symbol itself.
NAMES = (
    ("yaml.FullLoader", "yaml.loader.FullLoader"),
    ("yaml.Loader", "yaml.loader.Loader"),
    ("yaml.construct", SYMBOL),
)


def _callers(record: db.Record, status: str = "ok", digest: str | None = None) -> db.Callers:
    return db.Callers(
        vulnerability=record.vulnerability, package=record.package,
        symbols_digest=digest or db.symbols_digest(record), version="5.3.1",
        filename="PyYAML-5.3.1.tar.gz", sha256="b" * 64, status=status, seeds=1,
        seeds_found=1, graph_revision=3, callers=EDGES if status == "ok" else (),
        names=NAMES if status == "ok" else (),
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


def test_a_name_the_package_binds_matches_what_it_names(tmp_path: Path) -> None:
    # yaml.FullLoader is yaml.loader.FullLoader, re-exported by the package's __init__.
    usage = _usage(tmp_path, "import yaml\n\nyaml.load(open('x'), Loader=yaml.FullLoader)\n")
    record = _record()
    alert = decide("A", "pyyaml", "5.3.1", record, usage, None, _callers(record))
    assert alert.verdict == "CALLED"
    assert alert.matched == ("yaml.FullLoader", "yaml.load")
    assert alert.path == ("yaml.load", SYMBOL)  # the shorter path


def test_a_re_exported_class_holds_its_methods(tmp_path: Path) -> None:
    # yaml.Loader is not a caller, but it is yaml.loader.Loader, whose load_all is one: the
    # scanner cannot type ``loader``, so using the class is what it can see.
    code = "import yaml\n\nloader = yaml.Loader(stream)\nloader.load_all()\n"
    record = _record()
    alert = decide("A", "pyyaml", "5.3.1", record, _usage(tmp_path, code), None, _callers(record))
    assert alert.verdict == "CALLED"
    assert alert.path == ("yaml.loader.Loader.load_all", SYMBOL)


def test_a_symbol_under_another_name_is_reached(tmp_path: Path) -> None:
    code = "import yaml\n\nyaml.construct(node)\n"
    record = _record()
    usage = _usage(tmp_path, code)
    assert decide("A", "pyyaml", "5.3.1", record, usage).verdict == "UNKNOWN"
    alert = decide("A", "pyyaml", "5.3.1", record, usage, None, _callers(record))
    assert alert.verdict == "CALLED"
    assert alert.path == (SYMBOL,)


def test_a_name_that_only_ends_like_a_caller_is_not_one(tmp_path: Path) -> None:
    # Same package and final name: the re-export rule would match yaml.cache.load to the
    # caller yaml.load, but the package binds no such name, so it is a collision of names.
    code = "import yaml\n\nyaml.cache.load(k)\nyaml.cache.Loader.load_all(k)\n"
    record = _record()
    alert = decide("A", "pyyaml", "5.3.1", record, _usage(tmp_path, code), None, _callers(record))
    assert alert.verdict == "UNKNOWN"
    assert NameIndex(["yaml.load"]).closest("yaml.x.load") == (3, "yaml.load")
    assert NameIndex(["yaml.load"], reexports=False).closest("yaml.x.load") is None


def test_the_path_shown_is_the_closest_then_the_shortest(tmp_path: Path) -> None:
    record = _record()
    # Two callers referenced by their own names: the shorter path is shown, wherever it is.
    code = "import yaml\n\nyaml.full_load(f)\nyaml.load(g)\n"
    alert = decide("A", "pyyaml", "5.3.1", record, _usage(tmp_path, code), None, _callers(record))
    assert alert.path == ("yaml.load", SYMBOL)
    assert "references yaml.load" in alert.reason
    # A caller's own name comes before a class that holds one, though its path is longer.
    code = "import yaml\n\nyaml.Loader(s)\nyaml.full_load(f)\n"
    alert = decide("A", "pyyaml", "5.3.1", record, _usage(tmp_path, code), None, _callers(record))
    assert alert.path == ("yaml.full_load", "yaml.load", SYMBOL)
    assert NameIndex(["yaml.load", "yaml.x.load"]).closest("yaml.x.load") == (0, "yaml.x.load")


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


@given(st.lists(_NAME, max_size=8), _NAME, st.booleans())
def test_the_name_index_matches_exactly_as_matches_does(
    names: list[str], reference: str, reexports: bool
) -> None:
    found = NameIndex(names, reexports).match(reference)
    assert (found is not None) == any(matches(reference, n, reexports) for n in names)
    if found is not None:
        assert found in names
        assert matches(reference, found, reexports)


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
        assert stored.names == tuple(sorted(NAMES))
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


def test_explain_says_which_callers_a_scan_uses(tmp_path: Path) -> None:
    record = _record()
    database = tmp_path / "db.sqlite"
    db.write(database, [record], {record.vulnerability: record.vulnerability},
             {"db_version": "t"}, callers=[_callers(record)])  # fmt: skip
    shown = CliRunner().invoke(app, ["explain", record.vulnerability, "--db", str(database)])
    assert shown.exit_code == 0
    assert (
        "callers (5, read from pyyaml 5.3.1): a reference to one marks an alert CALLED too: "
        "yaml.full_load, yaml.load, yaml.constructor.FullConstructor, yaml.loader.FullLoader, "
        "yaml.loader.Loader.load_all"
    ) in shown.output
    as_json = CliRunner().invoke(
        app, ["explain", record.vulnerability, "--db", str(database), "--format", "json"]
    )
    assert json.loads(as_json.output)["callers"]["pyyaml"]["version"] == "5.3.1"

    def line(stored: db.Callers) -> str:
        text = explain.render_text("A", "A", ["A"], [record], {}, None, {"pyyaml": stored})
        return next(t.strip() for t in text.splitlines() if t.strip().startswith("callers"))

    assert line(_callers(record, "too many callers")) == "callers: none stored (too many callers)"
    assert "so a scan does not use them" in line(_callers(record, digest="0" * 64))
    alone = _callers(record).model_copy(update={"callers": ()})
    assert line(alone) == (
        "callers: no other definition reaches these symbols (read from pyyaml 5.3.1)"
    )
