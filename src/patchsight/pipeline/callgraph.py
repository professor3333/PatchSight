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
* ``self.m``, ``cls.m`` or ``super().m`` in a class: the methods ``m`` of that class, its
  ancestors and its descendants in the package (not its siblings). None there: an instance
  attribute, or a method of another package's base, so nothing;
* ``x.m`` where ``x`` is known to hold a package class (``x = Cls(...)``, ``with Cls(...) as
  x``, or a parameter annotated ``x: Cls``): the methods ``m`` of that class's hierarchy;
* ``x.m`` on anything else: every method ``m`` in the package. The type of ``x`` is not
  known, so this over-approximates, as design rule 3 prefers. A literal receiver
  (``"".join``, ``{}.items``) is a builtin's, so nothing;
* ``getattr(x, "m")`` with a constant name, like ``x.m``.

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
import warnings
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field

from patchsight.names import module_for_path

CONSTRUCTORS = ("__init__", "__new__", "__post_init__")
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


@dataclass
class _Definition:
    qualified: str
    kind: str  # function, method or class
    node: ast.AST
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
    def __init__(self, files: Mapping[str, bytes]) -> None:
        self.graph = Graph()
        self.scopes: dict[str, _Scope] = {}
        self.defs: dict[str, _Definition] = {}
        self.methods: dict[str, set[str]] = defaultdict(set)  # leaf name -> methods
        self.class_methods: dict[str, dict[str, str]] = defaultdict(dict)  # class -> leaf
        trees: dict[str, ast.Module] = {}
        for path in sorted(files):
            module = module_for_path(path)
            if module is None:
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")  # invalid escapes in old code
                    tree = ast.parse(files[path], filename=path)
            except (SyntaxError, ValueError):
                self.graph.unparsed.append(path)
                continue
            scope = _Scope(module, path.endswith("__init__.py"))
            _bind_imports(scope, _top_level(tree.body))
            self.scopes[module] = scope
            trees[module] = tree
        for module, tree in trees.items():
            scope = self.scopes[module]
            for d in _definitions(scope, tree.body, module, None):
                if d.qualified in self.defs:  # defined in both branches of a try or an if
                    self.defs[d.qualified].others.append(d.node)
                    continue
                self.defs[d.qualified] = d
                self.graph.kinds[d.qualified] = d.kind
                local = d.qualified[len(module) + 1 :]
                if "." not in local:
                    scope.definitions[local] = d.qualified
                if d.cls is not None:
                    leaf = d.qualified.rsplit(".", 1)[1]
                    self.methods[leaf].add(d.qualified)
                    self.class_methods[d.cls][leaf] = d.qualified
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

    # Resolution -------------------------------------------------------------------------

    def resolve_dotted(self, dotted: str, depth: int = 0) -> set[str]:
        """The definitions a dotted name of the package names, through re-exports."""
        if depth > _ALIAS_DEPTH or not dotted:
            return set()
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
            for star in scope.star:
                found = self.resolve_dotted(".".join((star, *rest)), depth + 1)
                if found:
                    return found
            return set()
        return set()

    def _bare(self, name: str, d: _Definition) -> set[str]:
        if name in self._locals:
            return set()  # a parameter or a local variable, not the module's name
        scope = self.scopes[d.module]
        if name in scope.definitions:
            return {scope.definitions[name]}
        if name in scope.imports:
            return self.resolve_dotted(scope.imports[name])
        for star in scope.star:
            found = self.resolve_dotted(f"{star}.{name}")
            if found:
                return found
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

    def _member(self, leaf: str, d: _Definition, receiver: str | None) -> set[str]:
        if receiver in ("self", "cls", "super") and d.cls is not None:
            # No such method in the hierarchy: an instance attribute, or a method of a base
            # from another package. Either way, not one of this package's methods.
            return {self.class_methods[c][leaf] for c in self._hierarchy(d.cls)
                    if leaf in self.class_methods[c]}  # fmt: skip
        return set(self.methods.get(leaf, ()))

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
            return {self.class_methods[c][rest[0]] for t in self._types[head]
                    for c in self._hierarchy(t) if rest[0] in self.class_methods[c]}  # fmt: skip
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
        return [node]  # fmt: skip

    def _classes(self, node: ast.expr | None, d: _Definition) -> set[str]:
        """The package classes an expression names: ``Cls``, ``mod.Cls``, ``"Cls"``,
        ``Optional[Cls]``, ``Cls | None``."""
        found: set[str] = set()
        stack: list[ast.AST] = [node] if node is not None else []
        while stack:
            current = stack.pop()
            if isinstance(current, ast.Constant) and isinstance(current.value, str):
                try:
                    current = ast.parse(current.value, mode="eval").body
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

    def _assigned(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, d: _Definition
    ) -> dict[str, set[str]]:
        """Local names bound to a new instance: ``x = Cls(...)``, ``with Cls(...) as x``."""
        found: dict[str, set[str]] = defaultdict(set)
        stack: list[ast.AST] = list(node.body)
        while stack:
            current = stack.pop()
            if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
                          | ast.Lambda):  # fmt: skip
                continue
            pairs: list[tuple[ast.expr, ast.expr | None]] = []
            if isinstance(current, ast.Assign) and len(current.targets) == 1:
                pairs.append((current.targets[0], current.value))
            elif isinstance(current, ast.With | ast.AsyncWith):
                pairs += [(i.optional_vars, i.context_expr) for i in current.items
                          if i.optional_vars is not None]  # fmt: skip
            for target, value in pairs:
                if isinstance(target, ast.Name) and isinstance(value, ast.Call):
                    found[target.id] |= self._classes(value.func, d)
            stack.extend(ast.iter_child_nodes(current))
        return {k: v for k, v in found.items() if v}

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
        nodes = [d.node, *d.others]
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
            self._locals = _local_names(node)
            self._types = {**self._assigned(node, d), **self._types}
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

    def build(self) -> Graph:
        for qualified, d in self.defs.items():
            node = d.node
            if d.kind == "function" and isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self.graph.params[qualified] = tuple(
                    a.arg for a in (*node.args.posonlyargs, *node.args.args)
                )
        for d in self.defs.values():
            self._record(d)
        return self.graph


def _local_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """The names a function binds in its own scope (its parameters and its assignments),
    which shadow the module's. Nested functions have their own scopes and are not read."""
    args = node.args
    names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    names |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
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
        stack.extend(ast.iter_child_nodes(current))
    return frozenset(names)


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


def build(files: Mapping[str, bytes]) -> Graph:
    """The reference graph of a package from its source files, keyed by path (the paths
    give the module names, as in the database)."""
    return _Builder(files).build()


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
