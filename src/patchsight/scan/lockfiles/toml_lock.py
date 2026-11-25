"""Shared reading for TOML lockfiles that list ``[[package]]`` tables."""

import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from patchsight.names import canonical_package_name
from patchsight.scan.lockfiles import Dependency

# A [[package]] header as TOML allows it: spaces inside the brackets, a quoted key, a comment.
_HEADER = re.compile(r"""^\s*\[\[\s*(?:package|"package"|'package')\s*\]\]\s*(?:#.*)?$""")


def parse(path: Path, unpinned_reason: Callable[[dict[str, Any]], str | None]) -> list[Dependency]:
    """Each ``[[package]]`` as a dependency; ``unpinned_reason`` says why one has no PyPI
    release version (None when it has one). Lines point at each package's header."""
    text = path.read_text(encoding="utf-8")
    try:
        packages = tomllib.loads(text).get("package", [])
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"{path} is not valid TOML: {error}") from None
    headers = [n for n, line in enumerate(text.splitlines(), 1) if _HEADER.match(line)]
    found: list[Dependency] = []
    for index, package in enumerate(packages):
        name = str(package.get("name", ""))
        version = package.get("version")
        reason = unpinned_reason(package)
        if reason is None and not version:
            reason = "no version in the lockfile"
        found.append(
            Dependency(
                name=canonical_package_name(name),
                raw_name=name,
                version=None if reason else str(version),
                source=path.as_posix(),
                line=headers[index] if index < len(headers) else 0,
                unpinned_reason=reason,
            )
        )
    return found
