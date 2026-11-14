"""Unified-diff hunks: which old and new line numbers a patch changes.

GitHub returns each file's patch as bare hunks (no file headers). When it omits the patch,
because the file is too large or binary, the changed lines are computed from the two full
file versions instead, and the result records that.
"""

import difflib
import re

from pydantic import BaseModel, ConfigDict

_HEADER = re.compile(r"^@@ -(?P<old>\d+)(?:,(?P<old_n>\d+))? \+(?P<new>\d+)(?:,(?P<new_n>\d+))? @@")


class Hunk(BaseModel):
    """One hunk. Line numbers are 1-based, in the old (pre-fix) and new (post-fix) file."""

    model_config = ConfigDict(frozen=True)

    index: int
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    removed: tuple[int, ...]
    added: tuple[int, ...]


class PatchParseError(ValueError):
    """The patch text is not a sequence of well-formed unified-diff hunks."""


def parse_patch(patch: str) -> list[Hunk]:
    """Parse GitHub's per-file ``patch`` text into hunks."""
    hunks: list[Hunk] = []
    lines = patch.splitlines()
    i = 0
    while i < len(lines):
        match = _HEADER.match(lines[i])
        if not match:
            if lines[i].strip():
                raise PatchParseError(f"expected a hunk header, got {lines[i][:60]!r}")
            i += 1
            continue
        old_start, new_start = int(match["old"]), int(match["new"])
        old_count = int(match["old_n"]) if match["old_n"] is not None else 1
        new_count = int(match["new_n"]) if match["new_n"] is not None else 1
        old_line, new_line = old_start, new_start
        removed: list[int] = []
        added: list[int] = []
        old_seen = new_seen = 0
        i += 1
        while i < len(lines) and (old_seen < old_count or new_seen < new_count):
            line = lines[i]
            if line.startswith("\\"):  # "\ No newline at end of file"
                i += 1
                continue
            marker = line[:1]
            if marker == "-":
                removed.append(old_line)
                old_line += 1
                old_seen += 1
            elif marker == "+":
                added.append(new_line)
                new_line += 1
                new_seen += 1
            elif marker in (" ", ""):
                old_line += 1
                new_line += 1
                old_seen += 1
                new_seen += 1
            else:
                raise PatchParseError(f"unexpected line in hunk: {line[:60]!r}")
            i += 1
        while i < len(lines) and lines[i].startswith("\\"):
            i += 1
        hunks.append(
            Hunk(
                index=len(hunks),
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                removed=tuple(removed),
                added=tuple(added),
            )
        )
    return hunks


def diff_hunks(old_text: str | None, new_text: str | None) -> list[Hunk]:
    """Compute hunks from two full file versions. ``None`` means the file does not exist."""
    old_lines = (old_text or "").splitlines()
    new_lines = (new_text or "").splitlines()
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    hunks: list[Hunk] = []
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag == "equal":
            continue
        hunks.append(
            Hunk(
                index=len(hunks),
                old_start=a0 + 1,
                old_count=a1 - a0,
                new_start=b0 + 1,
                new_count=b1 - b0,
                removed=tuple(range(a0 + 1, a1 + 1)),
                added=tuple(range(b0 + 1, b1 + 1)),
            )
        )
    return hunks
