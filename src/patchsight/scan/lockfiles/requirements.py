"""Parse ``requirements.txt`` files.

Only an exact ``==`` (or ``===``) pin gives a version that can be checked. Everything else
is reported as unpinned with the reason, never guessed. Includes (``-r``, ``-c``) are
followed relative to the including file; options, hashes and comments are ignored.
Environment markers are not evaluated, so a pin behind a marker is still checked.
"""

from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from patchsight.names import canonical_package_name
from patchsight.scan.lockfiles import Dependency

__all__ = ["Dependency", "parse"]


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations and strip comments, keeping the first line number."""
    lines: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        if buffer.strip():
            lines.append((start, buffer.strip()))
        buffer = ""
    if buffer.strip():
        lines.append((start, buffer.strip()))
    return lines


def _pin(requirement: Requirement) -> tuple[str | None, str | None]:
    specifiers = list(requirement.specifier)
    if len(specifiers) == 1 and specifiers[0].operator in ("==", "==="):
        version = specifiers[0].version
        if "*" in version:
            return None, f"wildcard pin {specifiers[0]}"
        return version, None
    if not specifiers:
        return None, "no version specified"
    return None, f"not an exact pin ({requirement.specifier})"


def parse(path: Path, _seen: frozenset[Path] = frozenset()) -> list[Dependency]:
    """Every dependency in ``path`` and the files it includes, in file order."""
    resolved = path.resolve()
    if resolved in _seen:
        return []
    seen = _seen | {resolved}
    source = path.as_posix()
    found: list[Dependency] = []
    for number, line in _logical_lines(path.read_text(encoding="utf-8")):
        if line.startswith(("-r ", "-c ", "--requirement", "--constraint")):
            target = line.split(maxsplit=1)[1] if " " in line else line.split("=", 1)[1]
            include = path.parent / target.strip()
            if include.exists():
                found.extend(parse(include, seen))
            continue
        editable = line.startswith(("-e ", "--editable"))
        if line.startswith("-") and not editable:
            continue  # --index-url, --hash continuation, --trusted-host and other options
        if editable or "://" in line.split(";")[0] or line.startswith(("git+", ".", "/")):
            found.append(
                Dependency(
                    name=line,
                    raw_name=line,
                    version=None,
                    source=source,
                    line=number,
                    unpinned_reason="URL, path or editable install",
                )
            )
            continue
        text = line.split(" --hash", 1)[0].strip()
        try:
            requirement = Requirement(text)
        except InvalidRequirement:
            found.append(
                Dependency(
                    name=text,
                    raw_name=text,
                    version=None,
                    source=source,
                    line=number,
                    unpinned_reason="could not parse this line",
                )
            )
            continue
        version, reason = _pin(requirement)
        found.append(
            Dependency(
                name=canonical_package_name(requirement.name),
                raw_name=requirement.name,
                version=version,
                source=source,
                line=number,
                unpinned_reason=reason,
            )
        )
    return found
