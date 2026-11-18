"""Find which imported names user code references, with Python's ``ast`` module. No LLM.

Two passes per file:

1. **Imports** build an alias table, wherever they appear in the file. ``import yaml as y``
   makes ``y`` mean ``yaml``, and ``from yaml import load as l`` makes ``l`` mean
   ``yaml.load``.
2. **References**: attribute chains and names in load context are resolved through the
   table to full dotted names such as ``yaml.load``. Only the longest chain is recorded,
   so ``y.constructor.FullConstructor`` yields one reference, not three.

Uses the scanner cannot resolve are recorded as *dynamic* and make a verdict UNKNOWN:

* ``getattr(module, <computed name>)`` (a string constant is resolved normally);
* ``importlib.import_module(...)`` and ``__import__(...)``;
* a module object used as a plain value (passed, stored or returned);
* ``from package import *``.

Three more things are recorded, because each can reach vulnerable code without a
reference the scanner can resolve. A verdict uses them only to withhold "not called":

* **Re-exports.** A ``from package import name`` that the file never uses is counted as a
  reference at the import, because another module can import the name from this one.
* **Untyped attributes.** Attribute names accessed on objects the scanner cannot type
  (``key.write_private_key_file(...)``), and on the project's own modules.
* **Template names.** Names inside ``{{ ... }}`` and ``{% ... %}`` tags, in Python strings
  and in template files (``.html``, ``.jinja``, ``.j2``, ...), because a template calls
  filters by name.

The analysis is flow-insensitive, so an import anywhere counts for the whole file. That
can over-report references, which only raises an alert's priority.
"""

import ast
import os
import re
from collections.abc import Iterator
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.names import module_for_path

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".nox",
        "node_modules",
        "site-packages",
        "__pycache__",
        "build",
        "dist",
        ".mypy_cache",
        ".pytest_cache",
    }
)
_DYNAMIC_IMPORTERS = ("__import__", "importlib.import_module")
TEMPLATE_SUFFIXES = frozenset({".html", ".htm", ".jinja", ".jinja2", ".j2", ".djhtml"})
_TEMPLATE_TAG = re.compile(r"\{[{%](.*?)[%}]\}", re.DOTALL)
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_TEMPLATE_BYTES = 2_000_000


class Location(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    line: int


class Reference(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    location: Location


class DynamicUse(BaseModel):
    model_config = ConfigDict(frozen=True)

    root: str
    reason: str
    location: Location


class Usage(BaseModel):
    """Everything the scanner found in a source tree."""

    imports: dict[str, tuple[Location, ...]] = {}
    references: tuple[Reference, ...] = ()
    dynamic: tuple[DynamicUse, ...] = ()
    unparsable: dict[str, str] = {}
    files: int = 0
    # Name -> the first place it is seen. Used only to withhold "not called".
    attributes: dict[str, Location] = {}
    template_names: dict[str, Location] = {}

    def imported(self, names: tuple[str, ...]) -> list[Location]:
        """Where any of ``names``, or a submodule of one, is imported."""
        hits = [
            location
            for module, locations in self.imports.items()
            if any(module == n or module.startswith(f"{n}.") for n in names)
            for location in locations
        ]
        return sorted(set(hits), key=lambda loc: (loc.path, loc.line))


def _files(root: Path, suffixes: frozenset[str]) -> Iterator[Path]:
    if root.is_file():
        if root.suffix in suffixes:
            yield root
        return
    found: list[Path] = []
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
        found.extend(Path(directory, n) for n in names if Path(n).suffix in suffixes)
    yield from sorted(found)


def python_files(root: Path) -> Iterator[Path]:
    return _files(root, frozenset({".py"}))


def template_words(text: str) -> Iterator[tuple[str, int]]:
    """Names inside template tags, each with the line it is on."""
    for tag in _TEMPLATE_TAG.finditer(text):
        line = text.count("\n", 0, tag.start()) + 1
        for word in _WORD.finditer(tag.group(1)):
            yield word.group(), line + tag.group(1).count("\n", 0, word.start())


class _File:
    """Scan state for one file."""

    def __init__(self, display: str) -> None:
        self.display = display
        self.aliases: dict[str, str] = {}
        self.module_aliases: set[str] = set()
        self.imports: dict[str, list[Location]] = {}
        self.references: list[Reference] = []
        self.dynamic: list[DynamicUse] = []
        self.from_imports: dict[str, tuple[str, Location]] = {}
        self.attributes: dict[str, Location] = {}
        self.template_names: dict[str, Location] = {}

    def loc(self, node: ast.AST) -> Location:
        return Location(path=self.display, line=getattr(node, "lineno", 0))

    def collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports.setdefault(alias.name, []).append(self.loc(node))
                    local = alias.asname or alias.name.split(".")[0]
                    self.aliases[local] = alias.name if alias.asname else local
                    self.module_aliases.add(local)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                self.imports.setdefault(node.module, []).append(self.loc(node))
                for alias in node.names:
                    if alias.name == "*":
                        self.dynamic.append(
                            DynamicUse(
                                root=node.module.split(".")[0],
                                reason=f"from {node.module} import *",
                                location=self.loc(node),
                            )
                        )
                    else:
                        local = alias.asname or alias.name
                        self.aliases[local] = f"{node.module}.{alias.name}"
                        self.from_imports[local] = (self.aliases[local], self.loc(node))

    def add_reexports(self, tree: ast.AST) -> None:
        """A from-import the file never uses may be re-exported: count it as a reference."""
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        for local, (target, location) in self.from_imports.items():
            if local not in used:
                self.references.append(Reference(name=target, location=location))


class _References(ast.NodeVisitor):
    def __init__(self, state: _File) -> None:
        self.state = state
        self.covered: set[int] = set()  # nodes already part of a recorded chain

    def visit_Import(self, node: ast.Import) -> None:
        return

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        return

    @staticmethod
    def _chain(node: ast.expr) -> tuple[list[str], list[ast.expr]] | None:
        parts: list[str] = []
        inner: list[ast.expr] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
            inner.append(node)
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return parts[::-1], inner
        return None

    def _resolve(self, parts: list[str]) -> str | None:
        target = self.state.aliases.get(parts[0])
        return ".".join([target, *parts[1:]]) if target else None

    def visit_Attribute(self, node: ast.Attribute) -> None:
        resolved = id(node) in self.covered
        if not resolved and (found := self._chain(node)) is not None:
            parts, inner = found
            if (target := self._resolve(parts)) is not None:
                self.state.references.append(Reference(name=target, location=self.state.loc(node)))
                self.covered.update(id(n) for n in inner)
                resolved = True
        if not resolved:
            # The receiver is not an import: a local, ``self``, a call result, ...
            self.state.attributes.setdefault(node.attr, self.state.loc(node))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and ("{{" in node.value or "{%" in node.value):
            for word, _ in template_words(node.value):
                self.state.template_names.setdefault(word, self.state.loc(node))

    def visit_Name(self, node: ast.Name) -> None:
        if id(node) in self.covered or not isinstance(node.ctx, ast.Load):
            return
        target = self.state.aliases.get(node.id)
        if target is None:
            return
        if node.id in self.state.module_aliases:
            self.state.dynamic.append(
                DynamicUse(
                    root=target.split(".")[0],
                    reason=f"module {target} used as a value",
                    location=self.state.loc(node),
                )
            )
        else:
            self.state.references.append(Reference(name=target, location=self.state.loc(node)))

    def visit_Call(self, node: ast.Call) -> None:
        function = node.func
        found = self._chain(function) if isinstance(function, ast.Attribute | ast.Name) else None
        called = self._resolve(found[0]) if found else None
        if isinstance(function, ast.Name) and function.id == "__import__":
            called = "__import__"
        elif isinstance(function, ast.Name) and function.id == "getattr":
            called = "getattr"

        if called in _DYNAMIC_IMPORTERS and node.args:
            first = node.args[0]
            target = (
                first.value
                if isinstance(first, ast.Constant) and isinstance(first.value, str)
                else "?"
            )
            self.state.dynamic.append(
                DynamicUse(
                    root=target.split(".")[0],
                    reason=f"{called}({target!r})",
                    location=self.state.loc(node),
                )
            )
            if target != "?":
                self.state.imports.setdefault(target, []).append(self.state.loc(node))
        elif called == "getattr" and len(node.args) >= 2 and isinstance(node.args[0], ast.Name):
            base = self.state.aliases.get(node.args[0].id)
            if base is not None:
                self.covered.add(id(node.args[0]))
                attribute = node.args[1]
                if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str):
                    self.state.references.append(
                        Reference(name=f"{base}.{attribute.value}", location=self.state.loc(node))
                    )
                else:
                    self.state.dynamic.append(
                        DynamicUse(
                            root=base.split(".")[0],
                            reason=f"getattr({node.args[0].id}, <computed>)",
                            location=self.state.loc(node),
                        )
                    )
        self.generic_visit(node)


def scan(root: Path) -> Usage:
    """Scan every Python file under ``root``, skipping virtualenvs, builds and VCS dirs."""
    imports: dict[str, list[Location]] = {}
    references: list[Reference] = []
    dynamic: list[DynamicUse] = []
    unparsable: dict[str, str] = {}
    attributes: dict[str, Location] = {}
    template_names: dict[str, Location] = {}
    files = 0
    first_party: set[str] = set()
    base = root if root.is_dir() else root.parent
    for path in python_files(root):
        files += 1
        display = path.relative_to(base).as_posix()
        first_party.add(display.split("/")[0].removesuffix(".py"))
        if (module := module_for_path(display)) is not None:
            first_party.add(module.split(".")[0])
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=display)
        except (SyntaxError, ValueError):
            unparsable[display] = source[:200_000]
            continue
        state = _File(display)
        state.collect_imports(tree)
        _References(state).visit(tree)
        state.add_reexports(tree)
        for module, locations in state.imports.items():
            imports.setdefault(module, []).extend(locations)
        references.extend(state.references)
        dynamic.extend(state.dynamic)
        for name, location in state.attributes.items():
            attributes.setdefault(name, location)
        for name, location in state.template_names.items():
            template_names.setdefault(name, location)
    # A name reached through the project's own modules (``helpers.yaml.full_load``) is
    # as untyped as an attribute of a local.
    for reference in references:
        if reference.name.split(".")[0] in first_party:
            attributes.setdefault(reference.name.split(".")[-1], reference.location)
    for path in _files(root, TEMPLATE_SUFFIXES):
        if path.stat().st_size > _MAX_TEMPLATE_BYTES:
            continue
        display = path.relative_to(base).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for word, line in template_words(text):
            template_names.setdefault(word, Location(path=display, line=line))
    return Usage(
        imports={
            m: tuple(sorted(set(v), key=lambda loc: (loc.path, loc.line)))
            for m, v in imports.items()
        },
        references=tuple(references),
        dynamic=tuple(dynamic),
        unparsable=unparsable,
        files=files,
        attributes=attributes,
        template_names=template_names,
    )
