"""Evaluation sets frozen by SHA-256 in git (ADR 0014), in place of DVC.

Every evaluation set is a small file or folder in the repository, with no third-party code
(rule 13). ``manifests/eval-sets.json`` pins each one's SHA-256, and CI recomputes them, so
no set can change without the change being seen (rule 17). Re-pinning is deliberate:
``eval-sets --repin <name>``, in the commit that says why.

A folder is pinned by the digest of its sorted ``<sha256>  <relative path>`` lines, so a file
added, removed, renamed or edited anywhere in it changes the pin. Byte-code caches and
editor files are ignored.
"""

import hashlib
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

MANIFEST = Path("manifests/eval-sets.json")
IGNORED = frozenset({"__pycache__", ".DS_Store", ".pytest_cache"})


class FrozenSet(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    path: str  # relative to the repository root, POSIX separators
    kind: Literal["file", "folder"]
    sha256: str
    frozen: date  # first committed
    what: str


class Manifest(BaseModel):
    model_config = ConfigDict(frozen=True)

    sets: tuple[FrozenSet, ...]


def _files(folder: Path) -> list[Path]:
    return sorted(
        p for p in folder.rglob("*")
        if p.is_file() and not IGNORED.intersection(p.relative_to(folder).parts)
    )  # fmt: skip


def digest(path: Path) -> str:
    """The SHA-256 of a file's bytes, or of a folder's sorted file list with their digests."""
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    lines = "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(path).as_posix()}\n"
        for p in _files(path)
    )
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def load(path: Path) -> Manifest:
    return Manifest.model_validate_json(path.read_text("utf-8"))


def check(root: Path, manifest: Manifest) -> list[str]:
    """What no longer matches its pin: one line per set, empty when all match."""
    problems = []
    for item in manifest.sets:
        target = root / item.path
        exists = target.is_file() if item.kind == "file" else target.is_dir()
        if not exists:
            problems.append(f"{item.name}: {item.path} is missing")
        elif (actual := digest(target)) != item.sha256:
            problems.append(f"{item.name}: {item.path} is {actual}, pinned {item.sha256}")
    names = [s.name for s in manifest.sets]
    problems += [f"{n}: listed twice" for n in sorted({n for n in names if names.count(n) > 1})]
    return problems


def repin(root: Path, manifest: Manifest, names: Iterable[str]) -> Manifest:
    """The manifest with the named sets pinned to their current contents; others untouched."""
    wanted = set(names)
    unknown = wanted - {s.name for s in manifest.sets}
    if unknown:
        raise KeyError(f"not in the manifest: {', '.join(sorted(unknown))}")
    return Manifest(
        sets=tuple(
            s.model_copy(update={"sha256": digest(root / s.path)}) if s.name in wanted else s
            for s in manifest.sets
        )
    )


def write(path: Path, manifest: Manifest) -> None:
    path.write_text(manifest.model_dump_json(indent=2) + "\n", "utf-8")
