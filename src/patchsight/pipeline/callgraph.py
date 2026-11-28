"""A static reference graph of one Python package, and the callers of a set of definitions.

A vulnerability's fix changes some definitions, but users often reach them through others
the fix left alone: ``yaml.load`` reaches the changed constructor without changing itself.
The *callers closure* of the changed definitions is every definition of the package that
reaches one of them through references a reader of the source can resolve. It is computed
here, offline, from the package's source at a vulnerable version; the scanner never parses
package source (design rule 1).

**Names** are the database's: module-level functions and classes, and the methods of
classes (nested classes too), qualified by their module as ``names.module_for_path`` gives
it, such as ``yaml.constructor.FullConstructor.construct_python_object``. A function nested
in another is part of it, as in the diff mapping.

**A definition refers to another** when its body, its decorators or its default values name
it in one of these ways:

* a bare name: a definition of the same module, or a name the module imports from another
  module of the package (``from .loader import Loader``), followed through re-exports;
* ``module.name``, through a module of the package bound by an import;
* ``self.m``, ``cls.m`` or ``super().m`` in a class: the method ``m`` an instance of that
  class runs, its own or the nearest ancestor's in the package (for ``super()``, the
  nearest ancestor's). With ``overrides=True`` (see ``build``), the methods ``m`` of the
  class, its ancestors and its descendants (not its siblings). None there: an instance
  attribute, or a method of another package's base, so nothing;
* ``x.m`` where ``x`` is known to hold a package class (``x = Cls(...)``, ``with Cls(...) as
  x``, or a parameter annotated ``x: Cls``): likewise, for that class;
* ``x.m`` on anything else: the type of ``x`` is not known. By default only the one class
  that defines ``m`` is linked, if exactly one does and ``m`` is no builtin type's method;
  with ``receivers="all"``, every method ``m`` (see ``build``). A literal receiver
  (``"".join``, ``{}.items``) is a builtin's, so nothing;
* ``getattr(x, "m")`` with a constant name, like ``x.m``.

A module-level alias (``connect = Connect``, ``decode = _obj.decode``) names what its value
names, and a module-level instance (``_obj = PyJWT()``) gives ``_obj.m`` the method its class
runs. ``Graph.names`` records every name a module binds to a definition other than its own,
through imports, star imports and these assignments: the names users write for it, such as
``requests.get`` for ``requests.api.get``.

Names bound in a function (its parameters and assignments) shadow the module's in its body,
but not in its decorators and defaults, which run in the enclosing scope. Type hints, and
names being assigned or deleted, are not references.

Referring to a class reaches its constructor (``__init__``, ``__new__``, ``__post_init__``;
a metaclass's ``__call__`` is not followed) and its bases. A class refers to what its body
names outside its methods.

**The argument rule** (``closure``): a function that names a definition only in a
parameter's default reaches it only when the parameter is left to its default, so
``yaml.safe_load``, which passes ``SafeLoader`` to ``load``, does not reach ``FullLoader``.

**What it cannot see:** names computed at run time (``getattr`` with a variable, ``importlib``),
callbacks a caller stores and another package calls, dispatch through other packages, and
code that runs on import. So the closure supports *raising* an alert, never lowering one by
itself.
"""

import ast
import io
import warnings
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Literal

from patchsight.names import module_for_path

# Bumped whenever a change alters what the graph links or what is stored from it: stored
# callers of another revision are computed again, never reused. 2: ``self.m`` no longer
# follows subclass overrides. 3: module-level aliases and instances resolve, and the
# package's own names for its definitions are recorded.
REVISION = 3
CONSTRUCTORS = ("__init__", "__new__", "__post_init__")
# Methods of builtin types and files: ``x.get()`` or ``x.read()`` on an unknown ``x`` is as
# likely a dict's or a file's as the package's, so a unique package method of that name is
# not evidence enough.
BUILTIN_METHODS = frozenset(
    name
    for kind in (dict, list, str, bytes, bytearray, set, frozenset, tuple, int, float,
                 io.IOBase, io.RawIOBase, io.BufferedIOBase, io.TextIOBase)
    for name in dir(kind)
    if not name.startswith("__")
)  # fmt: skip
Receivers = Literal["unique", "all"]
_LITERALS = (ast.Constant, ast.JoinedStr, ast.List, ast.Tuple, ast.Dict, ast.Set, ast.ListComp,
             ast.SetComp, ast.DictComp, ast.GeneratorExp)  # fmt: skip
_ALIAS_DEPTH = 10  # re-export chains longer than this are not followed


@dataclass
class _Scope:
    """What a module binds at its top level: definitions and imports."""

    module: str
    is_package: bool
    definitions: dict[str, str] = field(default_factory=dict)  # local name -> qualified
    imports: dict[str, str] = field(default_factory=dict)  # local name -> dotted target
    star: list[str] = field(default_factory=list)  # modules imported with *
    # Module-level assignments: ``connect = Connect`` or ``decode = _obj.decode`` (local name
    # -> the dotted name assigned, as written in the module), and ``_obj = PyJWT()`` (local
    # name -> the dotted name called, which makes it an instance if that is a class).
    assigned: dict[str, str] = field(default_factory=dict)
    instances: dict[str, str] = field(default_factory=dict)


@dataclass
class _Definition:
    qualified: str
    kind: str  # function, method or class
    node: ast.AST | None  # only while the definition is walked: trees are not kept
    module: str
    cls: str | None  # the qualified name of the enclosing class, for methods
    bases: list[ast.expr] = field(default_factory=list)
    others: list[ast.AST] = field(default_factory=list)  # the same name defined again


Passed = frozenset[str] | None  # the parameters a call passes; None: unknown (*args, **kwargs)


@dataclass
class Graph:
    """Definitions by qualified name, and what each one refers to.

    ``refers`` holds every reference. For the closure's argument rule it is split: ``plain``
    are the references outside a function's parameter defaults, ``calls`` the call sites
    among them with the parameters each passes, and ``values`` the references that are not
    calls. ``defaults`` holds, per module-level function and parameter, what only that
    parameter's default names."""

    kinds: dict[str, str] = field(default_factory=dict)
    refers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    plain: dict[str, set[str]] = field(default_factory=dict)
    calls: dict[str, dict[str, list[Passed]]] = field(default_factory=dict)
    values: dict[str, set[str]] = field(default_factory=dict)
    defaults: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    params: dict[str, tuple[str, ...]] = field(default_factory=dict)  # positional, in order
    unparsed: list[str] = field(default_factory=list)  # paths that did not parse
    # Names the package binds to its definitions other than their own (``Builder._names``):
    # ``requests.get`` -> ``requests.api.get``, ``jwt.decode`` -> ``jwt.api_jwt.PyJWT.decode``.
    names: dict[str, set[str]] = field(default_factory=dict)

    def callers(self) -> dict[str, set[str]]:
        reverse: dict[str, set[str]] = defaultdict(set)
        for caller, targets in self.refers.items():
            for target in targets:
                if target != caller:
                    reverse[target].add(caller)
        return reverse


def _package_of(module: str, is_package: bool) -> str:
    return module if is_package else module.rpartition(".")[0]


def _absolute(scope: _Scope, level: int, name: str | None) -> str:
    """The module a ``from ... import`` names, relative imports resolved."""
    if level == 0:
        return name or ""
    base = _package_of(scope.module, scope.is_package)
    for _ in range(level - 1):
        base = base.rpartition(".")[0]
    return f"{base}.{name}" if name and base else (name or base)


def _top_level(body: Iterable[ast.stmt]) -> Iterator[ast.stmt]:
    """Statements that run at module (or class) level, through if/try/with blocks."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, ast.If | ast.With | ast.AsyncWith):
            yield from _top_level(stmt.body)
            yield from _top_level(getattr(stmt, "orelse", []))
        elif isinstance(stmt, ast.Try | ast.TryStar):
            for block in (stmt.body, stmt.orelse, stmt.finalbody):
                yield from _top_level(block)
            for handler in stmt.handlers:
                yield from _top_level(handler.body)


def _bind_imports(scope: _Scope, statements: Iterable[ast.stmt]) -> None:
    for stmt in statements:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.asname:
                    scope.imports[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    scope.imports.setdefault(head, head)
        elif isinstance(stmt, ast.ImportFrom):
            source = _absolute(scope, stmt.level, stmt.module)
            for alias in stmt.names:
                if alias.name == "*":
                    scope.star.append(source)
                else:
                    scope.imports[alias.asname or alias.name] = f"{source}.{alias.name}"


def _private(dotted: str) -> bool:
    """Whether a part of a dotted name is private: ``_x``, though not a dunder."""
    return any(p.startswith("_") and not p.endswith("__") for p in dotted.split("."))


def _dotted(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return ".".join([node.id, *reversed(parts)]) if isinstance(node, ast.Name) else None


def _bind_assignments(scope: _Scope, statements: Iterable[ast.stmt]) -> None:
    for stmt in statements:
        if isinstance(stmt, ast.Assign):
            targets, value = stmt.targets, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        else:
            continue
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        if isinstance(value, ast.Call) and (called := _dotted(value.func)) is not None:
            scope.instances.update(dict.fromkeys(names, called))
        elif (assigned := _dotted(value)) is not None:
            scope.assigned.update(dict.fromkeys(names, assigned))


def _definitions(
    scope: _Scope, body: Iterable[ast.stmt], prefix: str, cls: str | None
) -> Iterator[_Definition]:
    for stmt in _top_level(body):
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            qualified = f"{prefix}.{stmt.name}"
            yield _Definition(qualified, "method" if cls else "function", stmt, scope.module, cls)
        elif isinstance(stmt, ast.ClassDef):
            qualified = f"{prefix}.{stmt.name}"
            yield _Definition(qualified, "class", stmt, scope.module, cls, list(stmt.bases))
            yield from _definitions(scope, stmt.body, qualified, qualified)


class _Builder:
    def __init__(
        self, files: Mapping[str, bytes], receivers: Receivers = "unique", overrides: bool = False
    ) -> None:
        self.receivers = receivers
        self.overrides = overrides
        self.graph = Graph()
        self.scopes: dict[str, _Scope] = {}
        self.defs: dict[str, _Definition] = {}
        self.methods: dict[str, set[str]] = defaultdict(set)  # leaf name -> methods
        self.class_methods: dict[str, dict[str, str]] = defaultdict(dict)  # class -> leaf
        # The first pass parses each file once and keeps only what resolution needs: each
        # module's imports and definitions, the classes' base expressions and the functions'
        # parameters. Syntax trees are dropped; build() parses one module at a time again.
        self.files = files
        self.module_paths: dict[str, str] = {}  # a module's file; a later path wins
        self.module_defs: dict[str, list[str]] = {}
        found: dict[str, list[_Definition]] = {}
        for path in sorted(files):
            module = module_for_path(path)
            if module is None:
                continue
            tree = self._parse(path)
            if tree is None:
                self.graph.unparsed.append(path)
                continue
            scope = _Scope(module, path.endswith("__init__.py"))
            _bind_imports(scope, _top_level(tree.body))
            _bind_assignments(scope, _top_level(tree.body))
            self.scopes[module] = scope
            self.module_paths[module] = path
            found[module] = []
            for d in _definitions(scope, tree.body, module, None):
                node = d.node
                if d.kind == "function" and isinstance(
                    node, ast.FunctionDef | ast.AsyncFunctionDef
                ):
                    self.graph.params[d.qualified] = tuple(
                        a.arg for a in (*node.args.posonlyargs, *node.args.args)
                    )
                d.node = None
                found[module].append(d)
        for module, definitions in found.items():
            scope = self.scopes[module]
            self.module_defs[module] = []
            for d in definitions:
                if d.qualified in self.defs:  # defined in both branches of a try or an if
                    continue
                self.defs[d.qualified] = d
                self.module_defs[module].append(d.qualified)
                self.graph.kinds[d.qualified] = d.kind
                local = d.qualified[len(module) + 1 :]
                if "." not in local:
                    scope.definitions[local] = d.qualified
                if d.cls is not None:
                    leaf = d.qualified.rsplit(".", 1)[1]
                    self.methods[leaf].add(d.qualified)
                    self.class_methods[d.cls][leaf] = d.qualified
        self.graph.params = {q: v for q, v in self.graph.params.items() if q in self.defs}
        self._resolved: dict[str, frozenset[str]] = {}
        self.star_names = self._star_names()
        self.roots = {m.split(".")[0] for m in self.scopes}
        self._locals: frozenset[str] = frozenset()  # the definition being walked shadows these
        self._types: dict[str, set[str]] = {}  # its local names known to hold these classes
        self._hierarchies: dict[str, set[str]] = {}
        self.bases: dict[str, set[str]] = {}
        for q, d in self.defs.items():
            if d.kind == "class":
                self.bases[q] = self._resolve_all(d.bases, d)
        self.subclasses: dict[str, set[str]] = defaultdict(set)
        for cls, bases in self.bases.items():
            for base in bases:
                self.subclasses[base].add(cls)
        # Names resolved while the bases were read could not yet see methods inherited
        # through them: resolve again from here on.
        self._resolved.clear()

    # Resolution -------------------------------------------------------------------------

    def _star_names(self) -> dict[str, dict[str, str]]:
        """Per module, the public names its ``import *`` statements bind and what each
        names, through chains of star imports: a fixed point, computed once, so that
        resolving a name never has to search the star imports again."""
        names: dict[str, dict[str, str]] = {m: {} for m in self.scopes}
        changed = True
        while changed:
            changed = False
            for module, scope in self.scopes.items():
                current = names[module]
                for star in scope.star:
                    source = self.scopes.get(star)
                    if source is None:
                        continue
                    offered = {**names[star], **source.imports, **source.definitions}
                    for name, target in offered.items():
                        if not name.startswith("_") and name not in current:
                            current[name] = target
                            changed = True
        return names

    def resolve_dotted(self, dotted: str, depth: int = 0) -> set[str]:
        """The definitions a dotted name of the package names, through re-exports. Each
        step follows one binding, so this is linear in the chain; results are kept."""
        if depth > _ALIAS_DEPTH or not dotted:
            return set()
        if dotted in self._resolved:
            return set(self._resolved[dotted])
        result = self._resolve(dotted, depth)
        if depth == 0:  # a chain cut short by the depth limit is not kept
            self._resolved[dotted] = frozenset(result)
        return result

    def _resolve(self, dotted: str, depth: int) -> set[str]:
        if dotted in self.defs:
            return {dotted}
        parts = dotted.split(".")
        for cut in range(len(parts) - 1, 0, -1):
            module, rest = ".".join(parts[:cut]), parts[cut:]
            scope = self.scopes.get(module)
            if scope is None:
                continue
            head, tail = rest[0], ".".join(rest[1:])
            if head in scope.definitions:
                return self.resolve_dotted(".".join(filter(None, (scope.definitions[head], tail))),
                                           depth + 1)  # fmt: skip
            if head in scope.imports:
                return self.resolve_dotted(".".join(filter(None, (scope.imports[head], tail))),
                                           depth + 1)  # fmt: skip
            starred = self.star_names.get(module, {})
            if head in starred:
                return self.resolve_dotted(".".join(filter(None, (starred[head], tail))),
                                           depth + 1)  # fmt: skip
            if head in scope.assigned:
                return self.resolve_dotted(
                    ".".join(filter(None, (module, scope.assigned[head], tail))), depth + 1
                )
            if head in scope.instances and tail and "." not in tail:
                return {m for c in self._classes_called(module, scope.instances[head], depth)
                        for m in self._runs(c, tail)}  # fmt: skip
            return set()
        return set()

    def _classes_called(self, module: str, called: str, depth: int) -> set[str]:
        """The package classes a module-level call such as ``PyJWT()`` constructs."""
        found = self.resolve_dotted(f"{module}.{called}", depth + 1)
        return {c for c in found if self.graph.kinds.get(c) == "class"}

    def _names(self) -> dict[str, set[str]]:
        """Every public name a module binds to a package definition other than its own:
        imports and star imports (re-exports), module-level aliases, and the methods of
        module-level instances (``django.conf.settings.configure``). A name with a private
        part (``pkg._compat.x``, ``pkg.api._helper``) is left out: users write a package's
        public names, and a definition's own name needs no other."""
        names: dict[str, set[str]] = {}
        for module, scope in sorted(self.scopes.items()):
            if _private(module):
                continue
            bound = {*scope.imports, *self.star_names.get(module, {}), *scope.assigned}
            for name in sorted(bound - set(scope.definitions)):
                dotted = f"{module}.{name}"
                if not _private(name) and (found := self.resolve_dotted(dotted) - {dotted}):
                    names[dotted] = found
            for name, called in sorted(scope.instances.items()):
                if name in scope.definitions or name in scope.imports or _private(name):
                    continue
                for cls in sorted(self._classes_called(module, called, 0)):
                    for leaf in sorted(self._leaves(cls)):
                        if not _private(leaf):
                            names.setdefault(f"{module}.{name}.{leaf}", set()).update(
                                self._runs(cls, leaf)
                            )
        return names

    def _leaves(self, cls: str) -> set[str]:
        """The method names an instance of ``cls`` has: its own and its ancestors'."""
        leaves: set[str] = set()
        seen, todo = set(), [cls]
        while todo:
            current = todo.pop()
            if current not in seen:
                seen.add(current)
                leaves |= set(self.class_methods.get(current, {}))
                todo.extend(self.bases.get(current, set()))
        return leaves

    def _bare(self, name: str, d: _Definition) -> set[str]:
        if name in self._locals:
            return set()  # a parameter or a local variable, not the module's name
        scope = self.scopes[d.module]
        if name in scope.definitions:
            return {scope.definitions[name]}
        if name in scope.imports:
            return self.resolve_dotted(scope.imports[name])
        starred = self.star_names.get(d.module, {})
        if name in starred:
            return self.resolve_dotted(starred[name])
        if name in scope.assigned:
            return self.resolve_dotted(f"{d.module}.{name}")
        return set()

    def _chain(self, node: ast.expr) -> list[str] | None:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            return [node.id, *reversed(parts)]
        return None

    def _hierarchy(self, cls: str) -> set[str]:
        """The class, its ancestors and its descendants in the package; not its siblings,
        whose methods ``self`` can never be."""
        if cls in self._hierarchies:
            return self._hierarchies[cls]
        seen = {cls}
        for links in (self.bases, self.subclasses):
            todo = [cls]
            while todo:
                for nxt in links.get(todo.pop(), set()):
                    if nxt not in seen:
                        seen.add(nxt)
                        todo.append(nxt)
        self._hierarchies[cls] = seen
        return seen

    def _inherited(self, cls: str, leaf: str) -> set[str]:
        """The method ``leaf`` of a class, looked up through its bases."""
        seen, todo = set(), [cls]
        while todo:
            current = todo.pop(0)
            if current in seen:
                continue
            seen.add(current)
            if leaf in self.class_methods.get(current, {}):
                return {self.class_methods[current][leaf]}
            todo.extend(sorted(self.bases.get(current, set())))
        return set()

    def _runs(self, cls: str, leaf: str) -> set[str]:
        """What ``x.leaf`` names for ``x`` an instance of ``cls``: the method it runs, or
        with ``overrides``, every method ``leaf`` of the class's hierarchy."""
        if not self.overrides:
            return self._inherited(cls, leaf)
        return {self.class_methods[c][leaf] for c in self._hierarchy(cls)
                if leaf in self.class_methods[c]}  # fmt: skip

    def _member(self, leaf: str, d: _Definition, receiver: str | None) -> set[str]:
        if receiver in ("self", "cls", "super") and d.cls is not None:
            # No such method in the hierarchy: an instance attribute, or a method of a base
            # from another package. Either way, not one of this package's methods.
            if receiver == "super" and not self.overrides:
                return {m for base in sorted(self.bases.get(d.cls, set()))
                        for m in self._inherited(base, leaf)}  # fmt: skip
            return self._runs(d.cls, leaf)
        found = self.methods.get(leaf, set())
        if self.receivers == "unique" and (
            leaf in BUILTIN_METHODS or len({m.rsplit(".", 1)[0] for m in found}) != 1
        ):
            return set()
        return set(found)

    def _expression(self, node: ast.expr, d: _Definition) -> set[str]:
        chain = self._chain(node) if isinstance(node, ast.Attribute | ast.Name) else None
        if chain is None and isinstance(node, ast.Attribute):
            value = node.value
            if isinstance(value, _LITERALS):
                return set()  # "".join, {}.items: a builtin's method, never the package's
            receiver = "super" if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                                   and value.func.id == "super") else None  # fmt: skip
            return self._member(node.attr, d, receiver)
        if chain is None:
            return set()
        head, rest = chain[0], chain[1:]
        targets = self._bare(head, d)
        if not rest:
            return targets
        if head in self._types and len(rest) == 1:
            return {m for t in self._types[head] for m in self._runs(t, rest[0])}
        if head in ("self", "cls") and d.cls is not None:
            return (
                self._member(rest[0], d, head)
                if len(rest) == 1
                else self._member(rest[-1], d, None)
            )
        if targets:
            found = set()
            for target in targets:
                found |= self.resolve_dotted(".".join((target, *rest)))
                if not found and len(rest) == 1 and self.graph.kinds.get(target) == "class":
                    found |= self._inherited(target, rest[0])
            return found or targets  # an attribute the package does not define: the definition
        scope = self.scopes[d.module]
        if head in scope.imports and head not in self._locals:
            target = scope.imports[head]
            found = self.resolve_dotted(".".join((target, *rest)))
            if found or target.split(".")[0] not in self.roots:
                return found  # another package's module: its attributes are not ours
        if head in scope.instances and head not in self._locals and len(rest) == 1:
            # A module-level instance (_obj = PyJWT()): the method its class runs, or none.
            return self.resolve_dotted(".".join((d.module, head, *rest)))
        return self._member(rest[-1], d, None)

    def _resolve_all(self, nodes: Iterable[ast.expr], d: _Definition) -> set[str]:
        found: set[str] = set()
        for node in nodes:
            found |= self._expression(node, d)
        return found

    # References -------------------------------------------------------------------------

    def _roots(self, d: _Definition) -> list[ast.AST]:
        """The parts of a definition that belong to it: a function's or method's whole
        node, nested definitions included, as in the diff mapping; a class's decorators,
        bases and body outside its methods and nested classes, which are definitions of
        their own."""
        node = d.node
        if isinstance(node, ast.ClassDef):
            roots: list[ast.AST] = [*node.decorator_list, *node.bases, *node.keywords]
            for stmt in _top_level(node.body):
                if isinstance(stmt, ast.If):
                    roots.append(stmt.test)  # its blocks come through _top_level
                elif isinstance(stmt, ast.With | ast.AsyncWith):
                    roots.extend(item.context_expr for item in stmt.items)
                elif not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
                                    | ast.Try | ast.TryStar):  # fmt: skip
                    roots.append(stmt)
            return roots
        return [node] if node is not None else []

    def _classes(self, node: ast.expr | None, d: _Definition) -> set[str]:
        """The package classes an expression names: ``Cls``, ``mod.Cls``, ``"Cls"``,
        ``Optional[Cls]``, ``Cls | None``."""
        found: set[str] = set()
        stack: list[ast.AST] = [node] if node is not None else []
        while stack:
            current = stack.pop()
            if isinstance(current, ast.Constant) and isinstance(current.value, str):
                try:
                    current = _annotation(current.value)
                except SyntaxError:
                    continue
            if isinstance(current, ast.Name | ast.Attribute) and self._chain(current) is not None:
                found |= {t for t in self._expression(current, d)
                          if self.graph.kinds.get(t) == "class"}  # fmt: skip
            if isinstance(current, ast.Subscript | ast.BinOp | ast.Tuple):
                stack.extend(ast.iter_child_nodes(current))
        return found

    def _annotated(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, d: _Definition
    ) -> dict[str, set[str]]:
        args = node.args
        found = {}
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            classes = self._classes(a.annotation, d)
            if classes:
                found[a.arg] = classes
        return found

    def _passed(self, call: ast.Call, target: str) -> Passed:
        if any(isinstance(a, ast.Starred) for a in call.args) or any(
            k.arg is None for k in call.keywords
        ):
            return None
        positional = self.graph.params.get(target, ())[: len(call.args)]
        return frozenset((*positional, *(k.arg for k in call.keywords if k.arg)))

    def _walk(
        self,
        roots: Iterable[ast.AST],
        d: _Definition,
        plain: set[str],
        calls: dict[str, list[Passed]],
        values: set[str],
        skip: frozenset[int] = frozenset(),
    ) -> None:
        stack = list(roots)
        while stack:
            node = stack.pop()
            if id(node) in skip:
                continue
            if isinstance(node, ast.Call):
                func = node.func
                if (isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2
                        and isinstance(node.args[1], ast.Constant)
                        and isinstance(node.args[1].value, str)):  # fmt: skip
                    found = self._member(node.args[1].value, d, None)
                    plain |= found
                    values |= found
                elif self._chain(func) is not None:
                    for target in self._expression(func, d):
                        plain.add(target)
                        calls.setdefault(target, []).append(self._passed(node, target))
                else:
                    stack.append(func)
                stack.extend(node.args)
                stack.extend(node.keywords)
                continue
            if isinstance(node, ast.Attribute | ast.Name) and not isinstance(node.ctx, ast.Load):
                if isinstance(node, ast.Attribute):
                    stack.append(node.value)  # x.y = ...: only x is read
                continue  # a target being stored or deleted is not a reference
            if isinstance(node, ast.Attribute):
                found = self._expression(node, d)
                plain |= found
                values |= found
                if self._chain(node) is not None:
                    continue  # the whole chain is resolved; its head is not a bare name
            elif isinstance(node, ast.Name):
                found = self._bare(node.id, d)
                plain |= found
                values |= found
            stack.extend(_children(node))

    def _record(self, d: _Definition) -> None:
        """Walk one definition and store its references in the graph."""
        plain: set[str] = set()
        calls: dict[str, list[Passed]] = {}
        values: set[str] = set()
        defaults: dict[str, set[str]] = {}
        nodes = [n for n in (d.node, *d.others) if n is not None]
        for node in nodes:
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self._locals = frozenset()
                roots = self._roots(_Definition(d.qualified, d.kind, node, d.module, d.cls))
                self._walk(roots, d, plain, calls, values)
                continue
            # Decorators and defaults run in the enclosing scope; the body in the function's
            # own, where its parameters and assignments shadow the module's names.
            args = node.args
            positional = [*args.posonlyargs, *args.args]
            signature: list[tuple[str, ast.expr]] = [
                *((a.arg, v) for a, v in zip(positional[len(positional) - len(args.defaults):],
                                             args.defaults, strict=True)),
                *((a.arg, k) for a, k in zip(args.kwonlyargs, args.kw_defaults, strict=True)
                  if k is not None),
            ]  # fmt: skip
            self._locals = frozenset()
            self._walk(node.decorator_list, d, plain, calls, values)
            if d.kind != "function":  # a method's defaults are plain references
                self._walk([v for _, v in signature], d, plain, calls, values)
            else:  # a module-level function's are kept per parameter (the argument rule)
                for name, default in signature:
                    named: set[str] = set()
                    self._walk([default], d, named, {}, set())
                    defaults.setdefault(name, set()).update(named)
            self._locals = frozenset()
            self._types = self._annotated(node, d)  # annotations name module-scope classes
            local_names, typed = _scope(node)
            self._locals = local_names
            assigned: dict[str, set[str]] = defaultdict(set)
            for name, func in typed:  # x = Cls(...), with Cls(...) as x
                assigned[name] |= self._classes(func, d)
            self._types = {**{k: v for k, v in assigned.items() if v}, **self._types}
            in_body: list[tuple[str, ast.expr]] = []
            if d.kind == "function":  # and the body idioms that set one: if p is None: p = X
                in_body = _body_defaults(node, {a.arg for a in (*positional, *args.kwonlyargs)})
                for name, default in in_body:
                    named = set()
                    self._walk([default], d, named, {}, set())
                    defaults.setdefault(name, set()).update(named)
            skip = frozenset(id(value) for _, value in in_body)
            self._walk(node.body, d, plain, calls, values, skip)
        self._locals = frozenset()
        self._types = {}
        if d.kind == "class":
            methods = self.class_methods[d.qualified]
            plain |= {methods[c] for c in CONSTRUCTORS if c in methods}
            plain |= self.bases.get(d.qualified, set())
        q = d.qualified
        only = {p: names - plain - {q} for p, names in defaults.items()}
        self.graph.plain[q] = plain - {q}
        self.graph.calls[q] = {t: sites for t, sites in calls.items() if t != q}
        self.graph.values[q] = values - {q}
        self.graph.defaults[q] = {p: names for p, names in only.items() if names}
        self.graph.refers[q] = self.graph.plain[q].union(*self.graph.defaults[q].values())

    def _parse(self, path: str) -> ast.Module | None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # invalid escapes in old code
                return ast.parse(self.files[path], filename=path)
        except (SyntaxError, ValueError):
            return None

    def build(self) -> Graph:
        for module, path in self.module_paths.items():
            tree = self._parse(path)
            if tree is None:  # pragma: no cover - it parsed in the first pass
                continue
            for d in _definitions(self.scopes[module], tree.body, module, None):
                known = self.defs[d.qualified]
                if known.node is None:
                    known.node = d.node
                elif d.node is not None:  # defined again in the module: its references count
                    known.others.append(d.node)
            for qualified in self.module_defs[module]:
                d = self.defs[qualified]
                self._record(d)
                d.node, d.others = None, []  # the module's tree can now be freed
        self.graph.names = self._names()
        return self.graph


def _scope(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[frozenset[str], list[tuple[str, ast.expr]]]:
    """In one walk of a function's own scope (not its nested functions, classes or
    lambdas): the names it binds (its parameters and assignments), which shadow the
    module's, and the local names bound to a call's result (``x = f(...)``, ``with f(...)
    as x``) with the called expression, which may name a class."""
    args = node.args
    names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    names |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
    typed: list[tuple[str, ast.expr]] = []
    stack: list[ast.AST] = list(node.body)
    while stack:
        current = stack.pop()
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(current.name)
            continue
        if isinstance(current, ast.Lambda | ast.Import | ast.ImportFrom):
            continue
        if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Store | ast.Del):
            names.add(current.id)
        elif isinstance(current, ast.ExceptHandler) and current.name:
            names.add(current.name)
        elif isinstance(current, ast.Assign):
            target = current.targets[0] if len(current.targets) == 1 else None
            if isinstance(target, ast.Name) and isinstance(current.value, ast.Call):
                typed.append((target.id, current.value.func))
        elif isinstance(current, ast.With | ast.AsyncWith):
            typed += [(i.optional_vars.id, i.context_expr.func) for i in current.items
                      if isinstance(i.optional_vars, ast.Name)
                      and isinstance(i.context_expr, ast.Call)]  # fmt: skip
        stack.extend(ast.iter_child_nodes(current))
    return frozenset(names), typed


@lru_cache(maxsize=4096)
def _annotation(text: str) -> ast.expr:
    """A string annotation, parsed once per text."""
    return ast.parse(text, mode="eval").body


def _is_unset(test: ast.expr, name: str) -> bool:
    """``name is None`` or ``not name``."""
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Is):
        return (isinstance(test.left, ast.Name) and test.left.id == name
                and isinstance(test.comparators[0], ast.Constant)
                and test.comparators[0].value is None)  # fmt: skip
    return (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
            and isinstance(test.operand, ast.Name) and test.operand.id == name)  # fmt: skip


def _body_defaults(
    node: ast.FunctionDef | ast.AsyncFunctionDef, params: set[str]
) -> list[tuple[str, ast.expr]]:
    """Defaults a function sets in its body, at its top level: ``if p is None: p = X``
    (or ``not p``), and ``p = p or X``. Each is a parameter and the expression."""
    found: list[tuple[str, ast.expr]] = []
    for stmt in node.body:
        if isinstance(stmt, ast.If):
            for inner in stmt.body:
                if (isinstance(inner, ast.Assign) and len(inner.targets) == 1
                        and isinstance(inner.targets[0], ast.Name)
                        and inner.targets[0].id in params
                        and _is_unset(stmt.test, inner.targets[0].id)):  # fmt: skip
                    found.append((inner.targets[0].id, inner.value))
        elif (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
              and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id in params
              and isinstance(stmt.value, ast.BoolOp) and isinstance(stmt.value.op, ast.Or)
              and isinstance(stmt.value.values[0], ast.Name)
              and stmt.value.values[0].id == stmt.targets[0].id):  # fmt: skip
            found.extend((stmt.targets[0].id, v) for v in stmt.value.values[1:])
    return found


def _children(node: ast.AST) -> list[ast.AST]:
    """A node's children, without type annotations: a hint is not a call."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        args = node.args
        defaults = [*args.defaults, *(k for k in args.kw_defaults if k is not None)]
        return [*node.decorator_list, *defaults, *node.body]
    if isinstance(node, ast.Lambda):
        return [*node.args.defaults, *(k for k in node.args.kw_defaults if k is not None),
                node.body]  # fmt: skip
    if isinstance(node, ast.AnnAssign):
        return [node.target, *([node.value] if node.value is not None else [])]
    return list(ast.iter_child_nodes(node))


def build(
    files: Mapping[str, bytes], receivers: Receivers = "unique", overrides: bool = False
) -> Graph:
    """The reference graph of a package from its source files, keyed by path (the paths
    give the module names, as in the database). The defaults are what the callers step
    stores: an alert raised on the closure should rest on a likely call.

    ``receivers`` decides what ``x.m`` means when the type of ``x`` is unknown. ``"unique"``
    (the default) links it only to the one class in the package that defines ``m``, and not
    at all when ``m`` is also a builtin type's method (``get``, ``read``, ``decode``).
    ``"all"`` links it to every method ``m``, which also follows dispatch through registries
    and plugins, as when ``Image.open(f).load()`` reaches whichever decoder the file selects;
    most of a large package can then reach one definition.

    ``overrides`` decides what ``self.m`` means. By default it is the method an instance of
    that very class runs, found through its ancestors. With ``True``, it is also every
    override of ``m`` in the class's descendants, since ``self`` may be an instance of one:
    a base's method calling ``self._open()`` then reaches every plugin's ``_open``, and a
    mixin calling ``self.process_response()`` every middleware's, including those a user's
    own subclass replaces. ``True`` misses fewer paths; ``False`` claims fewer that only a
    particular subclass would take (ADR 0017)."""
    return _Builder(files, receivers, overrides).build()


class _Unreached:
    pass


_UNREACHED = _Unreached()
Reach = frozenset[str] | None  # None: reached whatever the arguments; else only when one
#                                 of these parameters is left to its default


def _reach(graph: Graph, caller: str, target: str, condition: Reach) -> "Reach | _Unreached":
    """How ``caller`` reaches the vulnerable code through ``target``, if it does."""
    if target in graph.plain.get(caller, ()):
        if condition is None or graph.kinds.get(caller) != "function":
            return None
        if target in graph.values.get(caller, ()):
            return None  # used as a value: any call may omit the parameter
        sites = graph.calls.get(caller, {}).get(target, [])
        if not sites or any(s is None or not condition <= s for s in sites):
            return None  # a call that omits a parameter whose default reaches it
    named = frozenset(p for p, ts in graph.defaults.get(caller, {}).items() if target in ts)
    return named or _UNREACHED


def closure(graph: Graph, seeds: Iterable[str]) -> dict[str, str]:
    """Every definition that reaches a seed, mapped to the next definition on one path
    towards it (a seed maps to itself). Seeds the graph lacks are left out.

    **The argument rule:** a function that names a definition only in a parameter's
    default, such as ``def load(stream, Loader=FullLoader)``, reaches it when that parameter
    is left to its default. Its callers reach it only through a call that leaves it out:
    ``safe_load`` calling ``load(stream, SafeLoader)`` does not, ``full_load`` calling
    ``load(stream)`` does. A call with ``*args`` or ``**kwargs``, or a use as a value, is
    taken to leave it out."""
    callers = graph.callers()
    state: dict[str, Reach] = {}
    toward: dict[str, str] = {}
    queue: deque[str] = deque()
    for seed in sorted(set(seeds)):
        if seed in graph.kinds:
            state[seed], toward[seed] = None, seed
            queue.append(seed)
    while queue:
        target = queue.popleft()
        for caller in sorted(callers.get(target, ())):
            new = _reach(graph, caller, target, state[target])
            if isinstance(new, _Unreached):
                continue
            if caller in state:
                old = state[caller]
                merged = None if old is None or new is None else old | new
                if merged == old:
                    continue
                state[caller] = merged
            else:
                state[caller] = new
                toward[caller] = target
            queue.append(caller)
    return toward


def path(toward: Mapping[str, str], start: str) -> list[str]:
    """The definitions from ``start`` to its seed, along ``closure``'s pointers."""
    steps = [start]
    while toward[steps[-1]] != steps[-1]:
        steps.append(toward[steps[-1]])
    return steps
