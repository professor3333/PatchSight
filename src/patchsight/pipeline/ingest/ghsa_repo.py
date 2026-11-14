"""Partial, sparse clone of ``github/advisory-database``, limited to PyPI advisories.

The full repository is several gigabytes. GHSA files live at
``advisories/github-reviewed/<YYYY>/<MM>/<ID>/<ID>.json``, keyed by publication month, so
the PyPI subset can be checked out directly from the OSV records. Cone-mode sparse
checkout keeps this to seconds; non-cone patterns are matched against every path and are
orders of magnitude slower.
"""

import json
import subprocess
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.ingest.osv import Advisory

GHSA_REPO_URL = "https://github.com/github/advisory-database.git"


class GhsaScan(BaseModel):
    model_config = ConfigDict(frozen=True)

    expected: int
    found: int
    missing: tuple[str, ...]
    with_symbol_data: tuple[str, ...]


def ghsa_directory(advisory: Advisory) -> str | None:
    if advisory.source != "GHSA" or advisory.published is None:
        return None
    month = advisory.published.strftime("%Y/%m")
    return f"advisories/github-reviewed/{month}/{advisory.id}"


def _git(*args: str) -> None:
    subprocess.run(["git", *args], check=True)  # noqa: S603, S607 - fixed argv, no shell


def sparse_clone(dest: Path, advisories: Iterable[Advisory]) -> None:
    """Clone only the directories of the given GHSA advisories into ``dest``."""
    directories = sorted({d for a in advisories if (d := ghsa_directory(a))})
    if not (dest / ".git").exists():
        _git("clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout",
             GHSA_REPO_URL, str(dest))  # fmt: skip
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(dest), "sparse-checkout", "set", "--cone", "--stdin"],  # noqa: S607
        input="\n".join(directories),
        text=True,
        check=True,
    )
    _git("-C", str(dest), "checkout", "-q", "main")


def scan(repo: Path, advisories: Iterable[Advisory]) -> GhsaScan:
    """Check which GHSA advisories in the clone carry ``ecosystem_specific`` symbol data."""
    expected, missing, with_symbols = 0, [], []
    for advisory in advisories:
        directory = ghsa_directory(advisory)
        if directory is None:
            continue
        expected += 1
        path = repo / directory / f"{advisory.id}.json"
        if not path.exists():
            missing.append(advisory.id)
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        for affected in record.get("affected", []):
            specific = affected.get("ecosystem_specific") or {}
            if specific.get("affected_functions") or specific.get("imports"):
                with_symbols.append(advisory.id)
                break
    return GhsaScan(
        expected=expected,
        found=expected - len(missing),
        missing=tuple(sorted(missing)),
        with_symbol_data=tuple(sorted(with_symbols)),
    )
