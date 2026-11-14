import difflib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight.pipeline.diffs.hunks import PatchParseError, diff_hunks, parse_patch


def test_parse_single_hunk() -> None:
    patch = "@@ -1,3 +1,4 @@ def f():\n a\n-b\n+B\n+C\n c"
    (hunk,) = parse_patch(patch)
    assert (hunk.old_start, hunk.old_count, hunk.new_start, hunk.new_count) == (1, 3, 1, 4)
    assert hunk.removed == (2,)
    assert hunk.added == (2, 3)


def test_parse_several_hunks_and_short_headers() -> None:
    patch = (
        "@@ -5 +5 @@\n-x\n+y\n@@ -20,2 +20,3 @@\n keep\n+new\n keep\n\\ No newline at end of file"
    )
    first, second = parse_patch(patch)
    assert (first.index, first.removed, first.added) == (0, (5,), (5,))
    assert (second.index, second.removed, second.added) == (1, (), (21,))


def test_empty_patch_has_no_hunks() -> None:
    assert parse_patch("") == []


@pytest.mark.parametrize("patch", ["not a patch", "@@ -1,1 +1,1 @@\n?weird"])
def test_malformed_patch_is_rejected(patch: str) -> None:
    with pytest.raises(PatchParseError):
        parse_patch(patch)


def test_diff_hunks_for_added_and_removed_files() -> None:
    (added,) = diff_hunks(None, "a\nb\n")
    assert (added.removed, added.added) == ((), (1, 2))
    (removed,) = diff_hunks("a\n", None)
    assert (removed.removed, removed.added) == ((1,), ())
    assert diff_hunks("same\n", "same\n") == []


_lines = st.lists(st.sampled_from(["a", "b", "c", "d", ""]), max_size=25)


@given(old=_lines, new=_lines, context=st.integers(0, 3))
def test_parsed_unified_diff_matches_computed_hunks(
    old: list[str], new: list[str], context: int
) -> None:
    """Parsing a real unified diff gives the same changed lines as computing it directly."""
    text = list(difflib.unified_diff(old, new, lineterm="", n=context))
    patch = "\n".join(line for line in text if not line.startswith(("---", "+++")))
    parsed = parse_patch(patch)
    # Files are newline-terminated lines, so a lone blank line is not an empty file.
    computed = diff_hunks("".join(f"{x}\n" for x in old), "".join(f"{x}\n" for x in new))
    assert {r for h in parsed for r in h.removed} == {r for h in computed for r in h.removed}
    assert {a for h in parsed for a in h.added} == {a for h in computed for a in h.added}
    for hunk in parsed:
        assert all(1 <= line <= len(old) for line in hunk.removed)
        assert all(1 <= line <= len(new) for line in hunk.added)
