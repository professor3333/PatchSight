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
"""

from collections.abc import Iterable, Iterator, Sequence
from functools import cache
from typing import Literal

import tree_sitter_go
import tree_sitter_python
from pydantic import BaseModel, ConfigDict
from tree_sitter import Language, Node, Parser

from patchsight.pipeline.diffs.hunks import Hunk

SourceLanguage = Literal["python", "go"]
DefinitionKind = Literal["function", "method", "class"]
Side = Literal["pre", "post"]

_LANGUAGE_BY_SUFFIX: dict[str, SourceLanguage] = {".py": "python", ".pyi": "python", ".go": "go"}


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

    def note(definition: Definition | None, side: Side, hunk: int) -> None:
        if definition is None:
            module_level.add(hunk)
            return
        _, sides, hunk_ids = changed.setdefault(definition.name, (definition.kind, set(), set()))
        sides.add(side)
        hunk_ids.add(hunk)

    for hunk in hunks:
        for line in hunk.removed:
            note(_innermost(old_defs, line), "pre", hunk.index)
        for line in hunk.added:
            note(_innermost(new_defs, line), "post", hunk.index)

    return FileMapping(
        path=path,
        changed=tuple(
            ChangedDefinition(
                path=path,
                name=name,
                kind=kind,
                sides=tuple(s for s in ("pre", "post") if s in sides),
                hunks=tuple(sorted(hunk_ids)),
            )
            for name, (kind, sides, hunk_ids) in sorted(changed.items())
        ),
        module_level_hunks=tuple(sorted(module_level)),
        parse_errors=old_errors or new_errors,
    )
