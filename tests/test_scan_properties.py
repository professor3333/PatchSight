"""Property tests for the scan path (Hypothesis): the requirements parser, the AST scanner
and the verdict rules. Each property is one a verdict's correctness rests on, so a
counterexample is a wrong or missing alert."""

import keyword
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from patchsight import db
from patchsight.names import canonical_package_name
from patchsight.scan import ast_scanner, lockfiles
from patchsight.scan.ast_scanner import DynamicUse, Location, Reference, Usage
from patchsight.scan.lockfiles import requirements
from patchsight.scan.verdicts import decide, matches

NOW = datetime(2026, 11, 24, tzinfo=UTC)
SETTINGS = settings(max_examples=150, deadline=None)


def _identifier(prefix: str) -> st.SearchStrategy[str]:
    """Names from disjoint namespaces (package parts p…, members m…, aliases a…,
    attributes x…, unrelated code z…), so a generated program never shadows by accident."""
    return st.from_regex(rf"{prefix}[a-z0-9_]{{0,6}}", fullmatch=True).filter(
        lambda s: not keyword.iskeyword(s) and not keyword.issoftkeyword(s)
    )


MODULES = st.lists(_identifier("p"), min_size=1, max_size=3).map(".".join)


def _scan(files: dict[str, str]) -> Usage:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        return ast_scanner.scan(root)


def _record(module: str, member: str, confidence: str) -> db.Record:
    return db.Record(
        vulnerability="GHSA-0000-0000-0000", package=module.split(".")[0],
        confidence=confidence,
        source="llm" if confidence == "high" else "fallback",
        import_roots=(module.split(".")[0],), entry_points=(),
        symbols=(db.Symbol(qualified_name=f"{module}.{member}", module=module, name=member,
                           kind="function", path=f"{module.replace('.', '/')}.py"),),
        fix_commits=(), model=None, prompt_version=None, input_hash="h",
        advisory_modified=NOW, truncated=False, extracted_at=NOW,
    )  # fmt: skip


# --- requirements.txt ----------------------------------------------------------------

NAMES = st.from_regex(r"[A-Za-z]([A-Za-z0-9._-]{0,10}[A-Za-z0-9])?", fullmatch=True)
VERSIONS = st.from_regex(r"[0-9]{1,3}(\.[0-9]{1,3}){0,3}", fullmatch=True)
BLANK = st.sampled_from([" ", "  ", "\t", " \t"])


@st.composite
def _pin(draw: st.DrawFn) -> tuple[str, str, str]:
    name, version = draw(NAMES), draw(VERSIONS)
    line = name + draw(st.sampled_from(["", "[extra]", "[a,b]"]))
    line += draw(st.sampled_from(["==", " == ", "=="])) + version
    if draw(st.booleans()):
        line += draw(st.sampled_from(["; python_version >= '3.8'", " ; sys_platform == 'linux'"]))
    if draw(st.booleans()):
        line += f"{draw(BLANK)}--hash=sha256:{'a' * 64}"
    if draw(st.booleans()):
        line += f" \\\n{draw(BLANK)}--hash=sha256:{'b' * 64}"
    if draw(st.booleans()):
        line += f"{draw(BLANK)}# {draw(st.sampled_from(['pinned', 'see #12', '==9.9']))}"
    return canonical_package_name(name), version, line


NOISE = st.sampled_from(["", "# a comment", "\t# indented comment",
                         "--index-url https://example.org/simple"])  # fmt: skip


@SETTINGS
@given(st.lists(_pin(), min_size=1, max_size=8, unique_by=lambda p: p[0]),
       st.lists(NOISE, max_size=4))  # fmt: skip
def test_every_exact_pin_is_read_whatever_its_decoration(
    pins: list[tuple[str, str, str]], noise: list[str]
) -> None:
    """An exact pin pip would install is read with its version, through extras, markers,
    hashes, continuations, comments and blank lines. One read as unpinned is never
    checked against OSV, so its alerts would be missing."""
    lines = [line for _, _, line in pins]
    for i, extra in enumerate(noise):
        lines.insert(i * 2 % (len(lines) + 1), extra)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "requirements.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        found = {d.name: d.version for d in requirements.parse(path)}
    assert found == {name: version for name, version, _ in pins}


# --- uv.lock and poetry.lock -----------------------------------------------------------

WORKSPACE = "the project itself or a workspace member"
UV_SOURCES = {"registry": ('{ registry = "https://pypi.org/simple" }', None),
              "git": ('{ git = "https://github.com/o/r?rev=1#1" }', "git source"),
              "url": ('{ url = "https://example.org/x.tar.gz" }', "URL source"),
              "path": ('{ path = "../x" }', "local path source"),
              "directory": ('{ directory = "../x" }', "local path source"),
              "editable": ('{ editable = "." }', WORKSPACE),
              "virtual": ('{ virtual = "." }', WORKSPACE)}  # fmt: skip
POETRY_SOURCES = {"pypi": (None, None), "legacy": ("legacy", None), "git": ("git", "git source"),
                  "url": ("url", "URL source"), "file": ("file", "local file source"),
                  "directory": ("directory", "local path source")}  # fmt: skip
HEADERS = st.sampled_from(["[[package]]", "[[package]]  # pinned", "[[ package ]]", "[[package]] "])


@st.composite
def _locked(draw: st.DrawFn) -> tuple[str, str, list[tuple[str, str | None, str | None, int]]]:
    """A uv.lock or poetry.lock, and per package: name, version if pinned, reason, line."""
    kind = draw(st.sampled_from(["uv.lock", "poetry.lock"]))
    names = draw(st.lists(NAMES, min_size=1, max_size=6, unique_by=canonical_package_name))
    lines = ["version = 1"] if kind == "uv.lock" else ["# This file is generated."]
    expected = []
    for name in names:
        version = draw(VERSIONS)
        lines.append("")
        expected_line = len(lines) + 1
        lines += [draw(HEADERS), f'name = "{name}"', f'version = "{version}"']
        if kind == "uv.lock":
            source, reason = UV_SOURCES[draw(st.sampled_from(sorted(UV_SOURCES)))]
            lines += [f"source = {source}", "[package.metadata]", "requires-dist = []"]
        else:
            kind_of_source, reason = POETRY_SOURCES[draw(st.sampled_from(sorted(POETRY_SOURCES)))]
            lines += ['description = ""', "", "[package.dependencies]", 'idna = ">=2.5"']
            if kind_of_source:
                lines += ["", "[package.source]", f'type = "{kind_of_source}"',
                          'url = "https://example.org"']  # fmt: skip
        expected.append((canonical_package_name(name), None if reason else version, reason,
                         expected_line))  # fmt: skip
    return kind, "\n".join(lines) + "\n", expected


@SETTINGS
@given(_locked())
def test_every_locked_package_is_read_with_its_version_and_line(
    locked: tuple[str, str, list[tuple[str, str | None, str | None, int]]],
) -> None:
    """Registry packages keep their exact version; git, URL, path and workspace packages are
    unpinned with the reason; each points at its own [[package]] header, however written."""
    kind, text, expected = locked
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / kind
        path.write_text(text, encoding="utf-8")
        found = [(d.name, d.version, d.unpinned_reason, d.line) for d in lockfiles.parse(path)]
    assert found == expected, text


# --- the AST scanner -----------------------------------------------------------------


def _import_forms(module: str, member: str, alias: str) -> list[tuple[str, str]]:
    """Ways to import ``module.member``, each with the expression that then names it."""
    forms = [
        (f"import {module}", f"{module}.{member}"),
        (f"import {module} as {alias}", f"{alias}.{member}"),
        (f"from {module} import {member}", member),
        (f"from {module} import {member} as {alias}", alias),
    ]
    if "." in module:
        parent, last = module.rsplit(".", 1)
        forms.append((f"from {parent} import {last}", f"{last}.{member}"))
    return forms


# A use of the expression E: the lines, which of them holds E, and what follows the name.
Use = Callable[[str, str], tuple[list[str], int, str]]
USES: dict[str, Use] = {
    "call": lambda e, x: ([f"{e}()"], 0, ""),
    "attribute": lambda e, x: ([f"{e}.{x}"], 0, f".{x}"),
    "argument": lambda e, x: ([f"use_it({e})"], 0, ""),
    "keyword argument": lambda e, x: ([f"use_it(Loader={e})"], 0, ""),
    "assignment": lambda e, x: ([f"value_ = {e}"], 0, ""),
    "function body": lambda e, x: (["def zf():", f"    return {e}"], 1, ""),
    "decorator": lambda e, x: ([f"@{e}", "def zg():", "    pass"], 0, ""),
    "base class": lambda e, x: ([f"class Zc({e}):", "    pass"], 0, ""),
    "f-string": lambda e, x: (["text_ = f'{" + e + "}'"], 0, ""),
    "lambda": lambda e, x: ([f"zl = lambda: {e}"], 0, ""),
    "comprehension": lambda e, x: ([f"zs = [{e} for _ in ()]"], 0, ""),
    "default value": lambda e, x: ([f"def zd(v={e}):", "    pass"], 0, ""),
}
# Where the import sits. The analysis is flow-insensitive: an import anywhere counts.
PLACES: dict[str, Callable[[str], list[str]]] = {
    "top level": lambda i: [i],
    "function": lambda i: ["def zi():", f"    {i}"],
    "try": lambda i: ["try:", f"    {i}", "except ImportError:", "    pass"],
    "if": lambda i: ["if zflag:", f"    {i}"],
    "class": lambda i: ["class Zi:", f"    {i}"],
}
UNRELATED = st.sampled_from(["zv = 1", "import zmod", "from zmod import zthing", "zv.attr",
                             "def zh():\n    return zv", "if zv:\n    pass", "zthing(zv)",
                             "for _ in zv:\n    break"])  # fmt: skip


@SETTINGS
@given(module=MODULES, member=_identifier("m"), alias=_identifier("a"),
       attribute=_identifier("x"), form=st.integers(0, 4), use=st.sampled_from(sorted(USES)),
       place=st.sampled_from(sorted(PLACES)), import_last=st.booleans(),
       before=st.lists(UNRELATED, max_size=3), after=st.lists(UNRELATED, max_size=3),
       confidence=st.sampled_from(["high", "low"]))  # fmt: skip
def test_every_resolvable_use_is_found_and_called(
    module: str, member: str, alias: str, attribute: str, form: int, use: str, place: str,
    import_last: bool, before: list[str], after: list[str], confidence: str,
) -> None:  # fmt: skip
    """However the name is imported and wherever it is used, the scanner resolves the use
    to the full dotted name at the right line, and the alert is CALLED at either
    confidence. Unrelated code around it changes nothing."""
    forms = _import_forms(module, member, alias)
    statement, expression = forms[form % len(forms)]
    use_lines, at, suffix = USES[use](expression, attribute)
    imports = PLACES[place](statement)
    head = "\n".join(before).splitlines()
    blocks = [use_lines, imports] if import_last else [imports, use_lines]
    lines = head + blocks[0] + blocks[1] + "\n".join(after).splitlines()
    line = len(head) + (0 if import_last else len(imports)) + at + 1

    usage = _scan({"app/main.py": "\n".join(lines) + "\n"})

    expected = Reference(name=f"{module}.{member}{suffix}",
                         location=Location(path="app/main.py", line=line))  # fmt: skip
    assert expected in usage.references, "\n".join(lines)
    alert = decide("GHSA-0000-0000-0000", module.split(".")[0], "1.0",
                   _record(module, member, confidence), usage)  # fmt: skip
    assert alert.verdict == "CALLED"
    assert expected.location in alert.evidence


TOKENS = st.sampled_from(["import ", "from ", " as ", "pa", "pb.mc", ".", ",", "(", ")", ":",
                          "getattr", "importlib.import_module", "__import__", "'s'", "*",
                          "{{ x }}", "#", "\n", "    ", "\t", "=", "lambda", "if ", "-", "+",
                          "\\", '"', "\x00", "é"])  # fmt: skip
SOURCES = st.one_of(
    st.lists(TOKENS, max_size=40).map("".join),
    st.text(alphabet=st.characters(codec="utf-8"), max_size=200),
)


@SETTINGS
@given(python=SOURCES, other=SOURCES)
def test_no_input_crashes_the_scan(python: str, other: str) -> None:
    """A scan finishes on any file: what does not parse is recorded as unparsable (which
    makes an alert naming it UNKNOWN), and every reference points at a real line."""
    files = {"app/main.py": python, "Dockerfile": other, "app/page.html": other}
    usage = _scan(files)
    assert usage.files == 1
    assert set(usage.unparsable) <= {"app/main.py"}
    with tempfile.TemporaryDirectory() as directory:  # the line count as the scanner reads it
        path = Path(directory) / "x.py"
        path.write_text(python, encoding="utf-8")
        last = path.read_text(encoding="utf-8", errors="replace").count("\n") + 1
    assert all(1 <= r.location.line <= last for r in usage.references)


COMPUTED = st.sampled_from(["name_", "'a' + name_", "f'{name_}'", "names_[0]", "pick_()"])


@SETTINGS
@given(module=MODULES, member=_identifier("m"), computed=COMPUTED, alias=st.booleans())
def test_a_computed_name_is_never_silent(
    module: str, member: str, computed: str, alias: bool
) -> None:
    """getattr with a computed name on an imported module, or a dynamic import of a
    computed name anywhere, is recorded, and no alert can then say 'not called' or
    'not imported': the scanner cannot tell what the name is."""
    local = "mod_" if alias else module
    importing = f"import {module} as mod_" if alias else f"import {module}"
    source = f"{importing}\nimport importlib\nvalue_ = getattr({local}, {computed})\n"
    dynamic_import = f"import importlib\nplugin_ = importlib.import_module({computed})\n"
    root = module.split(".")[0]
    for files in ({"app/main.py": source}, {"app/plugins.py": dynamic_import}):
        usage = _scan(files)
        assert any(d.root in (root, "?") for d in usage.dynamic)
        alert = decide("GHSA-0000-0000-0000", root, "1.0", _record(module, member, "high"), usage)
        assert alert.verdict in ("CALLED", "UNKNOWN"), files


# --- the OSV query --------------------------------------------------------------------


PAIRS = st.tuples(NAMES.map(canonical_package_name), VERSIONS)
IDS = st.sets(st.from_regex(r"GHSA-[a-z0-9]{4}", fullmatch=True), max_size=7)


@SETTINGS
@given(
    known=st.dictionaries(PAIRS, IDS, min_size=1, max_size=12),
    asked_twice=st.booleans(),
    page=st.integers(1, 4),
    batch=st.integers(1, 5),
    hiccups=st.lists(st.sampled_from([503, 429]), max_size=2),
)
def test_every_page_of_every_batch_is_read(
    known: dict[tuple[str, str], set[str]], asked_twice: bool, page: int, batch: int,
    hiccups: list[int],
) -> None:  # fmt: skip
    """However OSV pages its answers and the client splits its batches, each pair gets every
    ID OSV knows for it, and a transient refusal is retried. A dropped page would be an
    alert that never appears."""
    import json as json_module
    from unittest import mock

    import httpx

    from patchsight.scan import osv_client

    failures = list(hiccups)

    def serve(request: httpx.Request) -> httpx.Response:
        if failures:
            return httpx.Response(failures.pop())
        results = []
        for q in json_module.loads(request.content)["queries"]:
            ids = sorted(known.get((q["package"]["name"], q["version"]), set()))
            start = int(q.get("page_token") or 0)
            result: dict[str, object] = {"vulns": [{"id": i} for i in ids[start : start + page]]}
            if start + page < len(ids):
                result["next_page_token"] = str(start + page)
            results.append(result)
        return httpx.Response(200, json={"results": results})

    pairs = list(known) * (2 if asked_twice else 1)
    client = httpx.Client(transport=httpx.MockTransport(serve))
    no_wait = osv_client._post.retry_with(wait=lambda _: 0)
    with mock.patch.object(osv_client, "BATCH_SIZE", batch), \
            mock.patch.object(osv_client, "_post", no_wait):  # fmt: skip
        found = osv_client.query(pairs, client=client)
    assert found == {pair: sorted(ids) for pair, ids in known.items()}


# --- the verdict rules ---------------------------------------------------------------

DOTTED = st.lists(st.sampled_from(["pa", "pb", "mc", "md", "xe"]), min_size=1, max_size=4).map(
    ".".join
)


@SETTINGS
@given(reference=DOTTED, symbol=DOTTED, attribute=_identifier("x"))
def test_matching_never_crosses_packages(reference: str, symbol: str, attribute: str) -> None:
    """A name matches only names under the same top-level package; every name matches
    itself, and reaching into a vulnerable name matches it."""
    if matches(reference, symbol):
        assert reference.split(".")[0] == symbol.split(".")[0]
    assert matches(symbol, symbol)
    assert matches(f"{symbol}.{attribute}", symbol)


@st.composite
def _usage(draw: st.DrawFn) -> Usage:
    """Any mix of what a scan can find, in and around package pa."""
    here = Location(path="app/main.py", line=draw(st.integers(1, 50)))
    references = draw(st.lists(DOTTED.map(lambda n: Reference(name=n, location=here)),
                               max_size=6))  # fmt: skip
    dynamic = draw(st.lists(st.sampled_from(["pa", "pb", "?"]).map(
        lambda r: DynamicUse(root=r, reason="getattr(pa, <computed>)", location=here)),
        max_size=2))  # fmt: skip
    imports = draw(st.lists(st.sampled_from(["pa", "pa.mc", "pb"]), max_size=3, unique=True))
    names = st.sampled_from(["mc", "md", "xe", "pa"])
    return Usage(
        imports=dict.fromkeys(imports, (here,)), references=tuple(references),
        dynamic=tuple(dynamic), files=1,
        attributes=dict.fromkeys(draw(st.lists(names, max_size=2)), here),
        template_names=dict.fromkeys(draw(st.lists(names, max_size=1)), here),
        launched=dict.fromkeys(draw(st.lists(st.sampled_from(["pa", "gunicorn"]), max_size=1)),
                               here),
        unparsable=draw(st.sampled_from([{}, {"app/bad.py": "import pa\n"}])),
    )  # fmt: skip


@SETTINGS
@given(usage=_usage(), member=st.sampled_from(["mc", "md"]),
       confidence=st.sampled_from(["high", "low"]))  # fmt: skip
def test_the_verdict_rules_fail_towards_noise(usage: Usage, member: str, confidence: str) -> None:
    """Low-confidence data never lowers an alert: it never says 'imported, not called'. A
    reference to the vulnerable symbol always gives CALLED. 'Imported, not called' needs
    an import and no dynamic use of the package. And no alert is ever dropped."""
    record = _record("pa", member, confidence)
    alert = decide("GHSA-0000-0000-0000", "pa", "1.0", record, usage)
    assert (alert.advisory, alert.package, alert.version) == ("GHSA-0000-0000-0000", "pa", "1.0")
    if any(r.name == f"pa.{member}" for r in usage.references):
        assert alert.verdict == "CALLED"
    if confidence == "low":
        assert alert.verdict != "IMPORTED_NOT_CALLED"
    if alert.verdict == "IMPORTED_NOT_CALLED":
        assert usage.imported(("pa",))
        assert not any(d.root in ("pa", "?") for d in usage.dynamic)
        assert not usage.unparsable
    if alert.verdict == "NOT_IMPORTED":
        assert not usage.imported(("pa",))
        assert not usage.unparsable
        assert not any(d.root == "?" for d in usage.dynamic)
