"""The Dunlap et al. (DIMVA 2024) Go benchmark, from the authors' released data.

Source: https://github.com/s3c2/llm-vulnerable-functions (Apache-2.0), file
``data/patchparser-data.tar.gz`` → ``patchparser-data-2023-10-31.csv``. One row per git
hunk and changed function, for 280 GoVulnDB reports and their 298 fix commits. The row's
``symbol_name`` column holds the report's vulnerable symbols from GoVulnDB (cloned
2023-10-26), which are the ground truth.

The paper excludes "files containing the word 'test'" (§3), which its code implements as a
case-insensitive substring match on the path. ``paper_path_filter`` reproduces that rule.
"""

import ast
import csv
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

DUNLAP_REPO_URL = "https://github.com/s3c2/llm-vulnerable-functions.git"
DUNLAP_CSV = "data/patchparser-data/patchparser-data-2023-10-31.csv"

# Published in the paper, §5.1 and §5.2, for ChangedFuncs on these 280 reports.
PAPER_MODIFIED_FUNCTIONS = 2370
PAPER_VULNERABLE_FUNCTIONS = 528
PAPER_MISSED_FUNCTIONS = 61
PAPER_PRECISION = 0.22
PAPER_RECALL = 0.90
PAPER_F1 = 0.35
# Best open model in the paper: Mixtral 8x7B.
PAPER_BEST_PRECISION = 0.60
PAPER_BEST_RECALL = 0.74
PAPER_BEST_F1 = 0.66


class FixCommit(BaseModel):
    model_config = ConfigDict(frozen=True)

    github_repo: str
    sha: str
    googlesource: bool


class ReleasedCandidate(BaseModel):
    """One changed function in the authors' released data."""

    model_config = ConfigDict(frozen=True)

    sha: str
    path: str
    function: str
    vulnerable: bool


class DunlapReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    commits: tuple[FixCommit, ...]
    symbols: frozenset[str]
    released: tuple[ReleasedCandidate, ...]


def paper_path_filter(path: str) -> bool:
    """True if the paper keeps this path: Go source whose path does not contain "test"."""
    return path.endswith(".go") and "test" not in path.lower()


def github_repo(owner: str, name: str, repo_type: str) -> str:
    """Where a fix commit lives on GitHub. Go's own repos are mirrored under ``golang``."""
    if repo_type == "GoogleSource":
        return f"golang/{name}".lower()
    return f"{owner}/{name}".lower()


def _one(value: str) -> str:
    items = ast.literal_eval(value)
    if not isinstance(items, list) or len(items) != 1:
        raise ValueError(f"expected a one-element list, got {value[:60]!r}")
    return str(items[0])


def load(csv_path: Path) -> list[DunlapReport]:
    """All reports in the released data, sorted by ID."""
    csv.field_size_limit(1 << 30)
    commits: dict[str, dict[tuple[str, str], FixCommit]] = {}
    symbols: dict[str, set[str]] = {}
    released: dict[str, dict[tuple[str, str, str], bool]] = {}
    with csv_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            report = row["id"]
            repo = github_repo(row["repo_owner"], row["repo_name"], row["repo_type"])
            commit = FixCommit(
                github_repo=repo,
                sha=row["vfc_sha"],
                googlesource=row["repo_type"] == "GoogleSource",
            )
            commits.setdefault(report, {})[(repo, commit.sha)] = commit
            symbols.setdefault(report, set()).update(ast.literal_eval(row["symbol_name"]))
            key = (commit.sha, row["file_name"], _one(row["changed_combined_functions"]))
            label = _one(row["label_combined_unique"]) == "True"
            seen = released.setdefault(report, {})
            seen[key] = seen.get(key, False) or label
    return [
        DunlapReport(
            id=report,
            commits=tuple(commits[report][k] for k in sorted(commits[report])),
            symbols=frozenset(symbols[report]),
            released=tuple(
                ReleasedCandidate(sha=sha, path=path, function=function, vulnerable=label)
                for (sha, path, function), label in sorted(released[report].items())
            ),
        )
        for report in sorted(commits)
    ]


def released_candidates(report: DunlapReport, filtered: bool) -> set[str]:
    """The report's changed function names in the released data."""
    return {c.function for c in report.released if not filtered or paper_path_filter(c.path)}


def paper_unit_counts(reports: Iterable[DunlapReport]) -> tuple[int, int]:
    """(units, vulnerable units) under the paper code's unit: (report, commit, function).

    The authors' evaluation code drops paths containing "test" and then groups rows by
    report, commit and function. This counts the same units from the released data.
    """
    units: dict[tuple[str, str, str], bool] = {}
    for report in reports:
        for c in report.released:
            if paper_path_filter(c.path):
                key = (report.id, c.sha, c.function)
                units[key] = units.get(key, False) or c.vulnerable
    return len(units), sum(units.values())
