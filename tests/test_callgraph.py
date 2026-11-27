"""The static reference graph of a Python package, and the callers of changed definitions."""

from collections import defaultdict

from hypothesis import given, settings
from hypothesis import strategies as st

from patchsight.pipeline import callgraph
from patchsight.pipeline.diffs.mapping import definitions


def _graph(files: dict[str, str]) -> callgraph.Graph:
    return callgraph.build({p: s.encode() for p, s in files.items()})


def _refers(files: dict[str, str], name: str) -> set[str]:
    return _graph(files).refers[name]


def test_names_are_the_databases_module_qualified_ones() -> None:
    source = (
        "def top():\n    def inner():\n        pass\n"
        "class Outer:\n    class Inner:\n        def m(self):\n            pass\n"
        "    async def a(self):\n        pass\n"
    )
    graph = _graph({"src/pkg/mod.py": source})
    found, _ = definitions(source.encode(), "python")
    assert {f"pkg.mod.{d.name}" for d in found} == set(graph.kinds)
    assert graph.kinds["pkg.mod.Outer.Inner.m"] == "method"
    assert "pkg.mod.top.inner" not in graph.kinds  # nested functions are part of top


def test_imports_relative_absolute_aliased_and_re_exported() -> None:
    files = {
        "pkg/__init__.py": "from .core import run\nfrom . import util\n",
        "pkg/core.py": "def run():\n    pass\n",
        "pkg/util.py": "def parse():\n    pass\n",
        "pkg/sub/__init__.py": "",
        "pkg/sub/a.py": (
            "import pkg\nimport pkg.util as pu\nfrom .. import util\nfrom ..core import run as go\n"
            "def via_package():\n    pkg.run()\n"
            "def via_alias():\n    pu.parse()\n"
            "def via_relative():\n    util.parse()\n"
            "def via_renamed():\n    go()\n"
        ),
    }
    graph = _graph(files)
    assert graph.refers["pkg.sub.a.via_package"] == {"pkg.core.run"}  # through the re-export
    assert graph.refers["pkg.sub.a.via_alias"] == {"pkg.util.parse"}
    assert graph.refers["pkg.sub.a.via_relative"] == {"pkg.util.parse"}
    assert graph.refers["pkg.sub.a.via_renamed"] == {"pkg.core.run"}


def test_star_imports_are_followed() -> None:
    files = {
        "pkg/a.py": "def f():\n    pass\n",
        "pkg/b.py": "from .a import *\ndef g():\n    f()\n",
    }
    assert _refers(files, "pkg.b.g") == {"pkg.a.f"}


def test_self_and_super_reach_the_class_hierarchy_only() -> None:
    files = {
        "pkg/m.py": (
            "class Base:\n    def step(self):\n        pass\n"
            "class Child(Base):\n    def run(self):\n        self.step()\n"
            "    def again(self):\n        super().step()\n"
            "class Other:\n    def step(self):\n        pass\n"
        )
    }
    graph = _graph(files)
    assert graph.refers["pkg.m.Child.run"] == {"pkg.m.Base.step"}
    assert graph.refers["pkg.m.Child.again"] == {"pkg.m.Base.step"}


def test_an_unknown_receiver_reaches_every_method_of_that_name() -> None:
    files = {
        "pkg/m.py": (
            "class A:\n    def close(self):\n        pass\n"
            "class B:\n    def close(self):\n        pass\n"
            "def shut(x):\n    x.close()\n    getattr(x, 'close')()\n"
        )
    }
    assert _refers(files, "pkg.m.shut") == {"pkg.m.A.close", "pkg.m.B.close"}


def test_another_packages_attributes_and_type_hints_are_not_references() -> None:
    files = {
        "pkg/m.py": (
            "import os\nfrom typing import Any\n"
            "class Path:\n    def join(self):\n        pass\n"
            "def f(p: Path, q: 'Path' = None) -> Path:\n"
            "    x: Path = os.path.join('a')\n    return x\n"
        )
    }
    assert _refers(files, "pkg.m.f") == set()


def test_a_class_reaches_its_constructor_and_bases_and_a_reference_reaches_the_class() -> None:
    files = {
        "pkg/m.py": (
            "def default():\n    pass\n"
            "class Base:\n    def __init__(self):\n        pass\n"
            "class Thing(Base):\n    handler = default\n"
            "    def __init__(self):\n        pass\n    def other(self):\n        pass\n"
            "def make():\n    return Thing()\n"
        )
    }
    graph = _graph(files)
    assert graph.refers["pkg.m.Thing"] == {"pkg.m.Thing.__init__", "pkg.m.Base", "pkg.m.default"}
    assert graph.refers["pkg.m.make"] == {"pkg.m.Thing"}
    reach = callgraph.closure(graph, ["pkg.m.Thing.__init__"])
    assert set(reach) == {"pkg.m.Thing.__init__", "pkg.m.Thing", "pkg.m.make"}
    # Through the base: building any subclass may run the base's constructor.
    inherited = callgraph.closure(graph, ["pkg.m.Base.__init__"])
    assert set(inherited) == {"pkg.m.Base.__init__", "pkg.m.Base", "pkg.m.Thing", "pkg.m.make"}


def test_inherited_methods_resolve_through_the_bases() -> None:
    files = {
        "pkg/m.py": (
            "class Base:\n    def parse(self):\n        pass\n"
            "class Sub(Base):\n    pass\n"
            "def f():\n    Sub.parse(None)\n"
        )
    }
    assert _refers(files, "pkg.m.f") == {"pkg.m.Base.parse"}


def test_both_branches_of_a_try_count_and_old_code_is_listed() -> None:
    files = {
        "pkg/m.py": (
            "def a():\n    pass\ndef b():\n    pass\n"
            "try:\n    def f():\n        a()\nexcept ImportError:\n    def f():\n        b()\n"
        ),
        "pkg/old.py": "print 'python 2'\n",
    }
    graph = _graph(files)
    assert graph.refers["pkg.m.f"] == {"pkg.m.a", "pkg.m.b"}
    assert graph.unparsed == ["pkg/old.py"]


def test_decorators_defaults_and_nested_code_belong_to_the_definition() -> None:
    files = {
        "pkg/m.py": (
            "def deco(f):\n    return f\ndef value():\n    pass\ndef inner_target():\n    pass\n"
            "@deco\ndef g(x=value()):\n"
            "    def inner():\n        inner_target()\n"
            "    class Local:\n        def m(self):\n            inner_target()\n"
            "    return inner\n"
        )
    }
    assert _refers(files, "pkg.m.g") == {"pkg.m.deco", "pkg.m.value", "pkg.m.inner_target"}


def test_the_closure_points_along_a_shortest_path() -> None:
    files = {
        "pkg/m.py": (
            "def seed():\n    pass\ndef near():\n    seed()\ndef far():\n    near()\n"
            "def both():\n    far()\n    seed()\ndef apart():\n    pass\n"
        )
    }
    graph = _graph(files)
    toward = callgraph.closure(graph, ["pkg.m.seed", "pkg.m.missing"])
    assert set(toward) == {"pkg.m.seed", "pkg.m.near", "pkg.m.far", "pkg.m.both"}
    assert callgraph.path(toward, "pkg.m.far") == ["pkg.m.far", "pkg.m.near", "pkg.m.seed"]
    assert callgraph.path(toward, "pkg.m.both") == ["pkg.m.both", "pkg.m.seed"]


STYLES = ("from_import", "module_import", "absolute_import", "renamed_import")


@st.composite
def packages(draw: st.DrawFn) -> tuple[dict[str, str], dict[str, str], set[tuple[int, int]]]:
    """A random call graph among functions spread over modules, rendered as a package with
    a random import style per call, and the module of each function."""
    count = draw(st.integers(min_value=1, max_value=8))
    modules = draw(st.lists(st.integers(0, 3), min_size=count, max_size=count))
    pairs = [(i, j) for i in range(count) for j in range(count) if i != j]
    edges = set(draw(st.lists(st.sampled_from(pairs), max_size=16))) if pairs else set()
    lines: dict[int, list[str]] = defaultdict(list)
    calls: dict[int, list[str]] = defaultdict(list)
    for i, j in sorted(edges):
        home, there = modules[i], modules[j]
        if home == there:
            calls[i].append(f"f{j}()")
            continue
        style = draw(st.sampled_from(STYLES))
        if style == "from_import":
            lines[home].append(f"from .m{there} import f{j}")
            calls[i].append(f"f{j}()")
        elif style == "module_import":
            lines[home].append(f"from . import m{there}")
            calls[i].append(f"m{there}.f{j}()")
        elif style == "absolute_import":
            lines[home].append(f"import pkg.m{there}")
            calls[i].append(f"pkg.m{there}.f{j}()")
        else:
            lines[home].append(f"from pkg.m{there} import f{j} as alias_{j}")
            calls[i].append(f"alias_{j}()")
    files = {"pkg/__init__.py": ""}
    for m in set(modules):
        body = [*sorted(set(lines[m]))]
        for i, home in enumerate(modules):
            if home == m:
                body.append(f"def f{i}():")
                body.extend(f"    {c}" for c in calls[i])
                body.append("    pass")
        files[f"pkg/m{m}.py"] = "\n".join(body) + "\n"
    names = {f"f{i}": f"pkg.m{modules[i]}.f{i}" for i in range(count)}
    return files, names, edges


@settings(max_examples=150, deadline=None)
@given(packages(), st.data())
def test_the_closure_is_exactly_reverse_reachability(
    package: tuple[dict[str, str], dict[str, str], set[tuple[int, int]]], data: st.DataObject
) -> None:
    files, names, edges = package
    graph = _graph(files)
    count = len(names)
    seeds = data.draw(st.sets(st.integers(0, count - 1), min_size=1))
    reach = set(seeds)
    changed = True
    while changed:
        changed = False
        for i, j in edges:
            if j in reach and i not in reach:
                reach.add(i)
                changed = True
    toward = callgraph.closure(graph, [names[f"f{s}"] for s in seeds])
    assert set(toward) == {names[f"f{i}"] for i in reach}
    for start in toward:  # every pointer path ends at a seed
        assert callgraph.path(toward, start)[-1] in {names[f"f{s}"] for s in seeds}


LOADERS = "class FullLoader:\n    pass\nclass SafeLoader:\n    pass\nclass Loader:\n    pass\n"


def _reached(source: str, seed: str = "pkg.m.FullLoader") -> set[str]:
    return set(callgraph.closure(_graph({"pkg/m.py": LOADERS + source}), [seed]))


def test_a_default_reaches_only_callers_that_leave_the_argument_out() -> None:
    reached = _reached(
        "def load(stream, Loader=FullLoader):\n    return Loader(stream)\n"
        "def safe_load(stream):\n    return load(stream, SafeLoader)\n"
        "def keyword_load(stream):\n    return load(stream, Loader=SafeLoader)\n"
        "def full_load(stream):\n    return load(stream)\n"
        "def unknown(*args, **kwargs):\n    return load(*args, **kwargs)\n"
        "def as_value():\n    return [load]\n"
    )
    assert reached == {"pkg.m.FullLoader", "pkg.m.load", "pkg.m.full_load", "pkg.m.unknown",
                       "pkg.m.as_value"}  # fmt: skip


def test_the_body_idioms_that_set_a_default_count_as_the_default() -> None:
    reached = _reached(
        "def load(stream, Loader=None):\n    if Loader is None:\n        Loader = FullLoader\n"
        "    return Loader(stream)\n"
        "def other(stream, Loader=None):\n    Loader = Loader or FullLoader\n    return Loader\n"
        "def safe_load(stream):\n    return load(stream, SafeLoader)\n"
        "def safe_other(stream):\n    return other(stream, Loader=SafeLoader)\n"
        "def full_load(stream):\n    return load(stream)\n"
    )
    assert reached == {"pkg.m.FullLoader", "pkg.m.load", "pkg.m.other", "pkg.m.full_load"}


def test_a_name_used_beside_the_default_reaches_every_caller() -> None:
    reached = _reached(
        "def load(stream, Loader=FullLoader):\n    FullLoader.check()\n    return Loader\n"
        "def safe_load(stream):\n    return load(stream, SafeLoader)\n"
    )
    assert reached == {"pkg.m.FullLoader", "pkg.m.load", "pkg.m.safe_load"}


def test_parameters_and_locals_shadow_module_names_but_not_in_the_signature() -> None:
    graph = _graph({"pkg/m.py": LOADERS + (
        "def scan(stream, Loader=Loader):\n    return Loader(stream)\n"
        "def local():\n    FullLoader = make()\n    return FullLoader()\n"
        "def make():\n    pass\n"
    )})  # fmt: skip
    assert graph.defaults["pkg.m.scan"] == {"Loader": {"pkg.m.Loader"}}  # the module's Loader
    assert graph.plain["pkg.m.scan"] == set()  # the body's Loader is the parameter
    assert graph.refers["pkg.m.local"] == {"pkg.m.make"}  # a local FullLoader, not the class


def test_builtin_receivers_stores_and_sibling_classes_are_not_references() -> None:
    files = {
        "pkg/m.py": (
            "class URL:\n    def join(self):\n        pass\n    def items(self):\n        pass\n"
            "class Base:\n    def request(self):\n        pass\n"
            "class Client(Base):\n    def request(self):\n        pass\n"
            "class Async(Base):\n    def request(self):\n        pass\n"
            "    def send(self):\n        self.stream\n        return self.request()\n"
            "def literal(parts):\n    return ''.join(parts) + str({}.items())\n"
            "def store(exc, req):\n    exc.request = req\n    del exc.join\n"
            "def typed_with():\n    with Client() as client:\n        return client.request()\n"
            "def typed_assign():\n    c = Client()\n    return c.request()\n"
            "def typed_hint(c: 'Client | None'):\n    return c.request()\n"
        )
    }
    graph = _graph(files)
    assert graph.refers["pkg.m.literal"] == set()
    assert graph.refers["pkg.m.store"] == set()
    # A typed receiver reaches its class's hierarchy: ancestors and descendants, no siblings.
    for name in ("typed_with", "typed_assign"):
        assert graph.refers[f"pkg.m.{name}"] == {"pkg.m.Client", "pkg.m.Client.request",
                                                 "pkg.m.Base.request"}  # fmt: skip
    assert graph.refers["pkg.m.typed_hint"] == {"pkg.m.Client.request", "pkg.m.Base.request"}
    # self.stream is an attribute (no such method): nothing; self.request is Async's own line.
    assert graph.refers["pkg.m.Async.send"] == {"pkg.m.Async.request", "pkg.m.Base.request"}
