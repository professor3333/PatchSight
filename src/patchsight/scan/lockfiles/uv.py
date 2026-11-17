"""Parse ``uv.lock``: every package with its source.

Registry packages carry an exact release version. The project itself and workspace members
(``editable`` or ``virtual`` sources) are the user's own code; git, URL and path sources
have no PyPI release version. All of those are listed as unpinned, with the reason.
"""

from pathlib import Path
from typing import Any

from patchsight.scan.lockfiles import Dependency, toml_lock


def _reason(package: dict[str, Any]) -> str | None:
    source = package.get("source") or {}
    if "editable" in source or "virtual" in source:
        return "the project itself or a workspace member"
    if "git" in source:
        return "git source"
    if "url" in source:
        return "URL source"
    if "path" in source or "directory" in source:
        return "local path source"
    return None


def parse(path: Path) -> list[Dependency]:
    return toml_lock.parse(path, _reason)
