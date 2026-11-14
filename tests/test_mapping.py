from hypothesis import given
from hypothesis import strategies as st

from patchsight.pipeline.diffs.hunks import Hunk, diff_hunks
from patchsight.pipeline.diffs.mapping import definitions, language_for, map_hunks

PYTHON = b"""import os

LIMIT = 10


@cache
def load(path):
    def helper():
        return 1
    return helper()


class Loader:
    mode = "safe"

    def read(self):
        return 1

    async def aread(self):
        return 2

    class Inner:
        def deep(self):
            return 3
"""

GO = b"""package p

import "io"

type Reader struct{ r io.Reader }

func Parse(b []byte) error {
	f := func() int { return 1 }
	_ = f
	return nil
}

func (r *Reader) Read(b []byte) (int, error) {
	return 0, nil
}

func (s Set[K]) Add(k K) {}

func (t T) Value() int { return 1 }
"""


def _hunk(index: int, removed: tuple[int, ...] = (), added: tuple[int, ...] = ()) -> Hunk:
    return Hunk(index=index, old_start=1, old_count=0, new_start=1, new_count=0,
                removed=removed, added=added)  # fmt: skip


def test_language_by_suffix() -> None:
    assert language_for("a/b.py") == "python"
    assert language_for("a/b.go") == "go"
    assert language_for("a/b.c") is None


def test_python_definitions() -> None:
    found, errors = definitions(PYTHON, "python")
    assert not errors
    assert [(d.name, d.kind) for d in found] == [
        ("load", "function"),
        ("Loader", "class"),
        ("Loader.read", "method"),
        ("Loader.aread", "method"),
        ("Loader.Inner", "class"),
        ("Loader.Inner.deep", "method"),
    ]
    load = found[0]
    assert (load.start_line, load.end_line) == (6, 10)  # includes the decorator


def test_go_definitions_use_vulndb_names() -> None:
    found, errors = definitions(GO, "go")
    assert not errors
    assert [(d.name, d.kind) for d in found] == [
        ("Parse", "function"),
        ("Reader.Read", "method"),
        ("Set.Add", "method"),
        ("T.Value", "method"),
    ]


def test_python_changes_go_to_the_innermost_addressable_definition() -> None:
    hunks = [
        _hunk(0, removed=(1,), added=(1,)),  # import: module level
        _hunk(1, added=(9,)),  # inside nested helper: belongs to load
        _hunk(2, removed=(14,)),  # class attribute: belongs to the class
        _hunk(3, added=(17, 24)),  # a method, and a method of a nested class
    ]
    mapping = map_hunks("pkg/loader.py", "python", PYTHON, PYTHON, hunks)
    assert {(c.name, c.sides, c.hunks) for c in mapping.changed} == {
        ("load", ("post",), (1,)),
        ("Loader", ("pre",), (2,)),
        ("Loader.read", ("post",), (3,)),
        ("Loader.Inner.deep", ("post",), (3,)),
    }
    assert mapping.module_level_hunks == (0,)


def test_go_closure_and_type_changes() -> None:
    hunks = [_hunk(0, added=(8,)), _hunk(1, removed=(5,)), _hunk(2, added=(14,))]
    mapping = map_hunks("p/reader.go", "go", GO, GO, hunks)
    assert {c.name for c in mapping.changed} == {"Parse", "Reader.Read"}
    assert mapping.module_level_hunks == (1,)


def test_added_and_deleted_definitions() -> None:
    old = b"def keep():\n    return 1\n\ndef gone():\n    return 2\n"
    new = b"def keep():\n    return 10\n\ndef fresh():\n    return 3\n"
    hunks = diff_hunks(old.decode(), new.decode())
    mapping = map_hunks("m.py", "python", old, new, hunks)
    assert {(c.name, c.sides) for c in mapping.changed} == {
        ("keep", ("pre", "post")),
        ("gone", ("pre",)),
        ("fresh", ("post",)),
    }


def test_new_file_maps_only_the_post_side() -> None:
    new = b"def created():\n    return 1\n"
    mapping = map_hunks("m.py", "python", None, new, diff_hunks(None, new.decode()))
    assert [(c.name, c.sides) for c in mapping.changed] == [("created", ("post",))]


def test_syntax_errors_are_flagged_not_fatal() -> None:
    broken = b"def ok():\n    return 1\n\ndef bad(:\n"
    found, errors = definitions(broken, "python")
    assert errors
    assert "ok" in {d.name for d in found}


@given(st.sets(st.integers(1, PYTHON.count(b"\n")), max_size=10))
def test_every_changed_line_is_accounted_for(lines: set[int]) -> None:
    found, _ = definitions(PYTHON, "python")
    hunks = [_hunk(i, added=(line,)) for i, line in enumerate(sorted(lines))]
    mapping = map_hunks("m.py", "python", PYTHON, PYTHON, hunks)
    names = {c.name for c in mapping.changed}
    for hunk in hunks:
        (line,) = hunk.added
        inside = [d for d in found if d.start_line <= line <= d.end_line]
        if inside:
            assert min(inside, key=lambda d: d.end_line - d.start_line).name in names
        else:
            assert hunk.index in mapping.module_level_hunks
