"""Lockfile parsers. Each returns the pinned dependencies, and the unpinned ones with why.

* ``uv.lock`` and ``poetry.lock``: TOML lockfiles that pin every package, direct and
  transitive. Packages from git, URLs or local paths are listed as unpinned, because no
  PyPI release version describes them.
* Any other file is read as a pip requirements file (``requirements``).

Without an explicit lockfile, the first of ``DISCOVERY_ORDER`` in the project is used.
``requirements.txt`` comes first so that existing projects keep scanning the same file.
"""

from pathlib import Path

from pydantic import BaseModel, ConfigDict

DISCOVERY_ORDER = ("requirements.txt", "uv.lock", "poetry.lock")


class Dependency(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    raw_name: str
    version: str | None
    source: str
    line: int
    unpinned_reason: str | None = None


def find(project: Path) -> Path | None:
    """The project's lockfile, by ``DISCOVERY_ORDER``, or None."""
    return next((project / n for n in DISCOVERY_ORDER if (project / n).is_file()), None)


def parse(path: Path) -> list[Dependency]:
    """Every dependency in the lockfile, in file order."""
    if path.name == "uv.lock":
        from patchsight.scan.lockfiles import uv

        return uv.parse(path)
    if path.name == "poetry.lock":
        from patchsight.scan.lockfiles import poetry

        return poetry.parse(path)
    from patchsight.scan.lockfiles import requirements

    return requirements.parse(path)
