"""Map diff hunks to the functions, methods and classes they change, using tree-sitter.

This is the paper's ChangedFuncs step (Dunlap et al., Algorithm 1), for Python and Go:

* Every hunk is mapped on both sides. Removed lines are looked up in the pre-fix file and
  added lines in the post-fix file. A definition changed on either side counts once.
* A change belongs to the innermost *addressable* definition:
  * Python: a module-level function, a class, or a method, including methods of nested
    classes (``Outer.Inner.method``). Nested functions belong to their enclosing function,
    because user code cannot reference them directly. A change in a class body outside any
    method belongs to the class.
  * Go: a function (``Parse``) or a method, named ``Type.Method`` with pointers and type
    parameters removed. This matches the Go vulnerability database's symbol format.
    Function literals belong to their enclosing function.
* Changed lines outside any definition (imports, module constants, Go type
  declarations) are recorded as module-level changes. They are not function candidates.
  In Python, the definitions of the same file that those lines name are recorded as
  *referenced*: a fix made only of registration calls such as
  ``FullConstructor.add_multi_constructor(..., FullConstructor.construct_python_object_apply)``
  names the code it changes the behaviour of. Only a fallback record uses them, and only
  when the fix changes no definition at all.
"""

import re
from collections.abc import Iterable, Iterator, Sequence
from functools import cache
from typing import Literal

import tree_sitter_go
import tree_sitter_python
from pydantic import BaseModel, ConfigDict
from tree_sitter import Language, Node, Parser

from patchsight.pipeline.diffs.hunks import Hunk, text_lines

SourceLanguage = Literal["python", "go"]
DefinitionKind = Literal["function", "method", "class"]
Side = Literal["pre", "post"]

_LANGUAGE_BY_SUFFIX: dict[str, SourceLanguage] = {".py": "python", ".pyi": "python", ".go": "go"}
_STRING = re.compile(r"'(?:\\.|[^'\\])*'" + "|" + r'"(?:\\.|[^"\\])*"')
_CHAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")


class Definition(BaseModel):
    """A named definition with its 1-based, inclusive line range."""

    model_config = ConfigDict(frozen=True)

    name: str
    kind: DefinitionKind
    start_line: int
    end_line: int


class ChangedDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    name: str
    kind: DefinitionKind
    sides: tuple[Side, ...]
    hunks: tuple[int, ...]


class FileMapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    changed: tuple[ChangedDefinition, ...]
    module_level_hunks: tuple[int, ...]
    parse_errors: bool
    # Every definition name in either version of the file, for validating names.
    known_names: tuple[str, ...] = ()
    # Python definitions named by changed module-level lines (see the module docstring).
    referenced: tuple[ChangedDefinition, ...] = ()


def language_for(path: str) -> SourceLanguage | None:
    for suffix, language in _LANGUAGE_BY_SUFFIX.items():
        if path.endswith(suffix):
            return language
    return None


@cache
def _parser(language: SourceLanguage) -> Parser:
    grammar = tree_sitter_python if language == "python" else tree_sitter_go
    return Parser(Language(grammar.language()))


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def _lines(node: Node) -> tuple[int, int]:
    return node.start_point.row + 1, node.end_point.row + 1


def _python_definitions(node: Node, scope: tuple[str, ...], in_class: bool) -> Iterator[Definition]:
    for child in node.children:
        target, outer = child, child
        if child.type == "decorated_definition":
            target = child.child_by_field_name("definition") or child
        if target.type not in ("function_definition", "class_definition"):
            continue
        name = _text(target.child_by_field_name("name"))
        if not name:
            continue
        start, end = _lines(outer)  # decorators belong to the definition
        qualified = ".".join((*scope, name))
        if target.type == "class_definition":
            yield Definition(name=qualified, kind="class", start_line=start, end_line=end)
            body = target.child_by_field_name("body")
            if body is not None:
                yield from _python_definitions(body, (*scope, name), in_class=True)
        else:
            kind: DefinitionKind = "method" if in_class else "function"
            yield Definition(name=qualified, kind=kind, start_line=start, end_line=end)
            # Nested functions are part of this one: do not descend.


def assignments(source: bytes) -> list[tuple[int, int, set[str]]]:
    """Top-level assignments as (first line, last line, assigned names), without dunders
    such as ``__version__``: ``PATTERNS = [`` ... ``]`` spans many lines."""
    root = _parser("python").parse(source).root_node
    found: list[tuple[int, int, set[str]]] = []
    for node in root.children:
        statement = node.children[0] if node.type == "expression_statement" else node
        if statement.type not in ("assignment", "augmented_assignment"):
            continue
        names: set[str] = set()
        targets = [statement.child_by_field_name("left")]
        while targets:
            target = targets.pop()
            if target is None:
                continue
            if target.type == "identifier":
                names.add(_text(target))
            elif target.type in ("pattern_list", "tuple_pattern", "list_pattern"):
                targets.extend(target.children)
        names = {n for n in names if not (n.startswith("__") and n.endswith("__"))}
        if names:
            found.append((*_lines(node), names))
    return found


def users_of(names: Iterable[str], defs: Sequence[Definition], lines: Sequence[str]) -> set[str]:
    """The innermost definitions whose code uses any of ``names`` as a whole word."""
    patterns = [re.compile(rf"\b{re.escape(n)}\b") for n in names]
    found: set[str] = set()
    for definition in defs:
        for number in range(definition.start_line, definition.end_line + 1):
            text = lines[number - 1] if number <= len(lines) else ""
            if any(p.search(text) for p in patterns):
                inner = _innermost(defs, number)
                if inner is not None:
                    found.add(inner.name)
    return found


def _go_receiver_type(receiver: Node | None) -> str:
    if receiver is None:
        return ""
    stack = [receiver]
    while stack:
        current = stack.pop(0)
        if current.type == "type_identifier":
            return _text(current)
        stack.extend(current.children)
    return ""


def _go_definitions(root: Node) -> Iterator[Definition]:
    for child in root.children:
        if child.type == "function_declaration":
            name = _text(child.child_by_field_name("name"))
            kind: DefinitionKind = "function"
        elif child.type == "method_declaration":
            receiver = _go_receiver_type(child.child_by_field_name("receiver"))
            method = _text(child.child_by_field_name("name"))
            name = f"{receiver}.{method}" if receiver else method
            kind = "method"
        else:
            continue
        if name:
            start, end = _lines(child)
            yield Definition(name=name, kind=kind, start_line=start, end_line=end)


def definitions(source: bytes, language: SourceLanguage) -> tuple[list[Definition], bool]:
    """All addressable definitions in ``source``, and whether the parse had errors."""
    tree = _parser(language).parse(source)
    root = tree.root_node
    found = (
        list(_python_definitions(root, (), in_class=False))
        if language == "python"
        else list(_go_definitions(root))
    )
    return found, root.has_error


def _innermost(defs: Sequence[Definition], line: int) -> Definition | None:
    containing = [d for d in defs if d.start_line <= line <= d.end_line]
    if not containing:
        return None
    return min(containing, key=lambda d: (d.end_line - d.start_line, -d.start_line))


def referenced_names(line: str, defs: Sequence[Definition]) -> list[str]:
    """Definitions a line of code names: for each dotted name outside strings and comments,
    the longest prefix that is a definition (``Class.method``, else ``Class``).

    >>> defs = [Definition(name=n, kind="class", start_line=1, end_line=1)
    ...         for n in ("FullConstructor", "FullConstructor.construct_object")]
    >>> referenced_names("FullConstructor.add('x', FullConstructor.construct_object)  # y", defs)
    ['FullConstructor', 'FullConstructor.construct_object']
    """
    names = {d.name for d in defs}
    code = _STRING.sub(" ", line).split("#", 1)[0]
    found: list[str] = []
    for chain in _CHAIN.findall(code):
        parts = chain.split(".")
        for end in range(len(parts), 0, -1):
            name = ".".join(parts[:end])
            if name in names:
                found.append(name)
                break
    return list(dict.fromkeys(found))


def map_hunks(
    path: str,
    language: SourceLanguage,
    old_source: bytes | None,
    new_source: bytes | None,
    hunks: Iterable[Hunk],
) -> FileMapping:
    """Map each hunk's changed lines to the definitions they fall in."""
    old_defs, old_errors = definitions(old_source, language) if old_source else ([], False)
    new_defs, new_errors = definitions(new_source, language) if new_source else ([], False)
    changed: dict[str, tuple[DefinitionKind, set[Side], set[int]]] = {}
    module_level: set[int] = set()
    referenced: dict[str, tuple[DefinitionKind, set[Side], set[int]]] = {}
    old_lines = text_lines(old_source.decode("utf-8", "replace")) if old_source else []
    new_lines = text_lines(new_source.decode("utf-8", "replace")) if new_source else []

    module_lines: dict[Side, list[tuple[int, int]]] = {"pre": [], "post": []}

    def refer(name: str, defs: Sequence[Definition], side: Side, hunk: int) -> None:
        kind = next(d.kind for d in defs if d.name == name)
        _, sides, ids = referenced.setdefault(name, (kind, set(), set()))
        sides.add(side)
        ids.add(hunk)

    def note(definition: Definition | None, side: Side, hunk: int, line: int) -> None:
        if definition is None:
            module_level.add(hunk)
            if language == "python":
                module_lines[side].append((line, hunk))
                defs, lines = (old_defs, old_lines) if side == "pre" else (new_defs, new_lines)
                text = lines[line - 1] if 0 < line <= len(lines) else ""
                for name in referenced_names(text, defs):
                    refer(name, defs, side, hunk)
            return
        _, sides, hunk_ids = changed.setdefault(definition.name, (definition.kind, set(), set()))
        sides.add(side)
        hunk_ids.add(hunk)

    for hunk in hunks:
        for line in hunk.removed:
            note(_innermost(old_defs, line), "pre", hunk.index, line)
        for line in hunk.added:
            note(_innermost(new_defs, line), "post", hunk.index, line)

    # A changed module-level constant (a pattern list, a regex) changes the behaviour of
    # the definitions that use it.
    sides: tuple[tuple[Side, bytes | None, list[Definition], list[str]], ...] = (
        ("pre", old_source, old_defs, old_lines),
        ("post", new_source, new_defs, new_lines),
    )
    for side, source, defs, lines in sides:
        if language != "python" or not source or not module_lines[side]:
            continue
        top_level = assignments(source)
        for line, hunk_index in module_lines[side]:
            assigned = {n for first, last, ns in top_level if first <= line <= last for n in ns}
            for name in users_of(assigned, defs, lines):
                refer(name, defs, side, hunk_index)

    def as_changed(
        found: dict[str, tuple[DefinitionKind, set[Side], set[int]]],
    ) -> tuple[ChangedDefinition, ...]:
        return tuple(
            ChangedDefinition(
                path=path,
                name=name,
                kind=kind,
                sides=tuple(s for s in ("pre", "post") if s in sides),
                hunks=tuple(sorted(hunk_ids)),
            )
            for name, (kind, sides, hunk_ids) in sorted(found.items())
        )

    return FileMapping(
        path=path,
        changed=as_changed(changed),
        module_level_hunks=tuple(sorted(module_level)),
        parse_errors=old_errors or new_errors,
        known_names=tuple(sorted({d.name for d in (*old_defs, *new_defs)})),
        referenced=as_changed(referenced),
    )
