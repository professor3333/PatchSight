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
* **Launched names.** Words in the files that start processes: Dockerfiles, Procfiles,
  Compose files, shell scripts and other scripts with a shebang, Makefiles, systemd and
  supervisor units, and CI workflows. ``exec gunicorn app.wsgi`` runs gunicorn's code
  without any import, so a package named there is never "not imported" or "not called".
  A word names a package when it is the distribution name, or the module after
  ``python -m``; a bare import name is too often an unrelated word (``git``, ``dns``).

The analysis is flow-insensitive, so an import anywhere counts for the whole file. That
can over-report references, which only raises an alert's priority.
"""

import ast
import os
import re
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path

from pydantic import BaseModel, ConfigDict, PrivateAttr

from patchsight.names import canonical_package_name, module_for_path

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
_MAX_LAUNCH_BYTES = 1_000_000
_LAUNCH_NAMES = frozenset({"makefile", "gnumakefile", "justfile", "entrypoint", "fly.toml",
                           "app.yaml", "render.yaml", ".gitlab-ci.yml"})  # fmt: skip
_LAUNCH_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".service", ".mk"})
_COMPOSE = re.compile(r"(docker-)?compose[\w.-]*\.ya?ml")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_RUN_MODULE = re.compile(r"(?<![\w-])-m\s+([A-Za-z_][A-Za-z0-9_.]*)")


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
    launched: dict[str, Location] = {}  # words in launch files
    launched_modules: dict[str, Location] = {}  # modules run with ``python -m``
    _by_root: dict[str, list[Reference]] | None = PrivateAttr(default=None)
    _launched_by_name: dict[str, tuple[str, Location]] | None = PrivateAttr(default=None)

    def launched_as(self, names: tuple[str, ...], package: str) -> tuple[str, Location] | None:
        """Where a launch file names the package: ``python -m`` with one of its import names
        (case-sensitive), or a word that is its distribution name (normalised, so
        ``python-dotenv`` matches ``python_dotenv``)."""
        for name in names:
            if name in self.launched_modules:
                return f"-m {name}", self.launched_modules[name]
        if self._launched_by_name is None:
            index: dict[str, tuple[str, Location]] = {}
            for word, location in self.launched.items():
                index.setdefault(canonical_package_name(word), (word, location))
            self._launched_by_name = index
        return self._launched_by_name.get(canonical_package_name(package))

    def references_into(self, roots: set[str]) -> list[Reference]:
        """References whose top-level name is one of ``roots``. Indexed once, because a
        scan asks for every alert."""
        if self._by_root is None:
            index: dict[str, list[Reference]] = {}
            for reference in self.references:
                index.setdefault(reference.name.split(".", 1)[0], []).append(reference)
            self._by_root = index
        return [r for root in sorted(roots) for r in self._by_root.get(root, ())]

    def imported(self, names: tuple[str, ...]) -> list[Location]:
        """Where any of ``names``, or a submodule of one, is imported."""
        hits = [
            location
            for module, locations in self.imports.items()
            if any(module == n or module.startswith(f"{n}.") for n in names)
            for location in locations
        ]
        return sorted(set(hits), key=lambda loc: (loc.path, loc.line))


def _walk(root: Path, keep: Callable[[Path], bool]) -> Iterator[Path]:
    if root.is_file():
        if keep(root):
            yield root
        return
    found: list[Path] = []
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
        found.extend(p for n in names if keep(p := Path(directory, n)))
    yield from sorted(found)


def _files(root: Path, suffixes: frozenset[str]) -> Iterator[Path]:
    return _walk(root, lambda p: p.suffix in suffixes)


def is_launch_file(path: Path) -> bool:
    """A file that starts processes. Lockfiles, requirements files and ``pyproject.toml``
    are not: they name every dependency, so they say nothing about what is run."""
    name = path.name.lower()
    if name in _LAUNCH_NAMES or path.suffix.lower() in _LAUNCH_SUFFIXES:
        return True
    if name.startswith(("dockerfile", "containerfile", "procfile")):
        return True
    if name.endswith((".dockerfile", ".containerfile")) or _COMPOSE.fullmatch(name):
        return True
    if "supervisor" in name and name.endswith(".conf"):
        return True
    parts = path.parts
    if (
        name.endswith((".yml", ".yaml"))
        and len(parts) >= 3
        and parts[-3:-1] == (".github", "workflows")
    ):
        return True
    if path.suffix:
        return False
    try:  # an extensionless script: bin/docker-server, scripts/start
        with path.open("rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return False


def launch_words(text: str) -> Iterator[tuple[str, str, int]]:
    """``("word" | "module", name, line)`` for each non-comment line. A dotted name also
    yields its first part, so ``gunicorn.conf.py`` names gunicorn and ``-m celery.bin``
    runs celery."""
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for kind, pattern in (("word", _TOKEN), ("module", _RUN_MODULE)):
            for match in pattern.finditer(line):
                name = match.group(match.lastindex or 0).rstrip(".-")
                yield kind, name, number
                if "." in name:
                    yield kind, name.split(".", 1)[0], number


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
        self.used: set[str] = set()  # every name the file reads or binds
        self.attributes: dict[str, Location] = {}
        self.template_names: dict[str, Location] = {}

    def loc(self, node: ast.AST) -> Location:
        return Location(path=self.display, line=getattr(node, "lineno", 0))

    def collect_imports(self, tree: ast.AST) -> None:
        for node in _statements(tree):
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

    def add_reexports(self) -> None:
        """A from-import the file never uses may be re-exported: count it as a reference.
        Run after the references pass, which records every name the file uses."""
        for local, (target, location) in self.from_imports.items():
            if local not in self.used:
                self.references.append(Reference(name=target, location=location))


_BODIES = ("body", "orelse", "finalbody", "handlers", "cases")


def _statements(tree: ast.AST) -> Iterator[ast.AST]:
    """Every statement, at any depth, without visiting expressions: imports are
    statements, so this finds them all at a fraction of ``ast.walk``'s cost."""
    stack = [tree]
    while stack:
        node = stack.pop()
        yield node
        for field in _BODIES:
            children = getattr(node, field, None)
            if isinstance(children, list):
                stack.extend(reversed(children))


class _References:
    """The references pass. Each ``visit_*`` handles one node and says whether to go on
    into its children; ``run`` walks the tree in ``ast.NodeVisitor``'s order (parent
    first, children in field order) with a stack of its own, because generated code can
    nest deeper than Python's recursion limit: a 500-branch ``elif`` chain does."""

    def __init__(self, state: _File) -> None:
        self.state = state
        self.covered: set[int] = set()  # nodes already part of a recorded chain

    def run(self, tree: ast.AST) -> None:
        stack = [tree]
        while stack:
            node = stack.pop()
            visit = getattr(self, f"visit_{type(node).__name__}", None)
            if visit is None or visit(node):
                stack.extend(reversed(list(ast.iter_child_nodes(node))))

    def visit_Import(self, node: ast.Import) -> bool:
        return False

    def visit_ImportFrom(self, node: ast.ImportFrom) -> bool:
        return False

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

    def visit_Attribute(self, node: ast.Attribute) -> bool:
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
        return True

    def visit_Constant(self, node: ast.Constant) -> bool:
        if isinstance(node.value, str) and ("{{" in node.value or "{%" in node.value):
            for word, _ in template_words(node.value):
                self.state.template_names.setdefault(word, self.state.loc(node))
        return False

    def visit_Name(self, node: ast.Name) -> bool:
        self.state.used.add(node.id)
        if id(node) in self.covered or not isinstance(node.ctx, ast.Load):
            return False
        target = self.state.aliases.get(node.id)
        if target is None:
            return False
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
        return False

    def visit_Call(self, node: ast.Call) -> bool:
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
        return True


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
            with warnings.catch_warnings():
                # Invalid escapes in the user's strings are their business, not the scan's.
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(source, filename=display)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            # RecursionError and MemoryError: nesting too deep for the parser itself.
            unparsable[display] = source[:200_000]
            continue
        state = _File(display)
        state.collect_imports(tree)
        _References(state).run(tree)
        state.add_reexports()
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
    launched: dict[str, dict[str, Location]] = {"word": {}, "module": {}}
    for path in _walk(root, is_launch_file):
        if path.stat().st_size > _MAX_LAUNCH_BYTES:
            continue
        display = path.relative_to(base).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for kind, name, line in launch_words(text):
            launched[kind].setdefault(name, Location(path=display, line=line))
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
        launched=launched["word"],
        launched_modules=launched["module"],
    )
