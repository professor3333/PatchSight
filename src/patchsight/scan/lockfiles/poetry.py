"""Parse ``poetry.lock``: every package, with its source type when it is not PyPI.

Packages from a ``legacy`` (alternative) index keep their version. Git, URL, file and
directory sources have no PyPI release version, so they are listed as unpinned.
"""

from pathlib import Path
from typing import Any

from patchsight.scan.lockfiles import Dependency, toml_lock

_UNPINNED = {
    "git": "git source",
    "url": "URL source",
    "file": "local file source",
    "directory": "local path source",
}


def _reason(package: dict[str, Any]) -> str | None:
    source = package.get("source") or {}
    return _UNPINNED.get(str(source.get("type", "")))


def parse(path: Path) -> list[Dependency]:
    return toml_lock.parse(path, _reason)
