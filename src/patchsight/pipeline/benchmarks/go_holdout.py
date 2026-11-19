"""The Go temporal holdout: Go vulnerability reports the pinned models cannot have seen.

The Dunlap benchmark is from 2023, so the models may have read its reports, symbols
included, in training. ADR 0004 requires a new confidence rule to pass on data not used to
choose it, and this is that data: reviewed GoVulnDB reports **published after the newest
model's weights were released** (Qwen3.8-27B, 2026-08-13; gpt-oss is older), with
vulnerable symbols as ground truth and a fix commit on GitHub.

The selection is frozen once into ``benchmarks/go-holdout-v1/reports.json``: IDs, fix
commits, symbols, and the advisory text the prompt shows. The text comes from GoVulnDB
under CC BY 4.0, credited in the file; no code is stored. Pull-request fixes are resolved to
their merge commits at freeze time, so later runs make the same requests.

Excluded, and counted in the file: unreviewed reports (no curated symbols), reports with
no symbols, and reports whose only fix link is a Go code review (``go.dev/cl``), which does
not map reliably to a commit on the GitHub mirror.
"""

import json
import re
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.benchmarks.dunlap import DunlapReport, FixCommit
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.extract.prompt import AdvisoryText

NAME = "go-holdout-v1"
FROZEN = Path("benchmarks/go-holdout-v1/reports.json")
VULNDB_URL = "https://vuln.go.dev/vulndb.zip"
# The newest pinned model's weights: Qwen/Qwen3.8-27B, uploaded 2026-08-13 with no weight
# change since (Hugging Face commit history). A report published after this day is unseen.
CUTOFF = "2026-08-13"
ATTRIBUTION = (
    "Advisory IDs, summaries, details and vulnerable symbols are from the Go Vulnerability "
    "Database (https://vuln.go.dev), licensed CC BY 4.0. PatchSight selected reports, kept "
    "the fields its extractor reads, and resolved pull-request fixes to their merge commits."
)
_COMMIT = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})", re.IGNORECASE)
_PULL = re.compile(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)", re.IGNORECASE)


class HoldoutCommit(BaseModel):
    model_config = ConfigDict(frozen=True)

    github_repo: str
    sha: str


class HoldoutReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    published: str
    summary: str
    details: str
    symbols: tuple[str, ...]
    commits: tuple[HoldoutCommit, ...]


class Holdout(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    cutoff: str
    source: str
    source_sha256: str
    retrieved_at: str
    attribution: str
    considered: int  # reports published after the cutoff
    excluded: dict[str, int]
    reports: tuple[HoldoutReport, ...]


def symbols_of(record: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                s
                for affected in record.get("affected", [])
                for imp in (affected.get("ecosystem_specific") or {}).get("imports", [])
                for s in imp.get("symbols", [])
            }
        )
    )


def select(
    archive: Path,
    sha256: str,
    retrieved_at: datetime,
    github: GitHubClient,
    cutoff: str = CUTOFF,
) -> Holdout:
    """Every eligible report published after ``cutoff``, with fixes resolved to commits."""
    excluded: Counter[str] = Counter()
    chosen: list[HoldoutReport] = []
    with zipfile.ZipFile(archive) as z:
        records = [json.loads(z.read(n)) for n in sorted(z.namelist()) if n.startswith("ID/GO-")]
    after = [r for r in records if r["published"][:10] > cutoff]
    for record in after:
        if record.get("withdrawn"):
            excluded["withdrawn"] += 1
            continue
        if (record.get("database_specific") or {}).get("review_status") != "REVIEWED":
            excluded["unreviewed"] += 1
            continue
        symbols = symbols_of(record)
        if not symbols:
            excluded["no symbols"] += 1
            continue
        fixes = [r["url"] for r in record.get("references", []) if r.get("type") == "FIX"]
        commits: dict[tuple[str, str], None] = {}
        for url in fixes:
            if (m := _COMMIT.search(url)) is not None:
                commits.setdefault((f"{m[1]}/{m[2]}".lower(), m[3].lower()), None)
        if not commits:
            for url in fixes:
                if (m := _PULL.search(url)) is not None:
                    pull = github.pull(f"{m[1]}/{m[2]}".lower(), int(m[3]))
                    if pull.merged and pull.merge_commit_sha:
                        commits.setdefault((pull.repo, pull.merge_commit_sha), None)
        if not commits:
            only_cl = fixes and all("go.dev/cl" in u or "googlesource" in u for u in fixes)
            excluded["Go code review only" if only_cl else "no GitHub fix commit"] += 1
            continue
        chosen.append(
            HoldoutReport(
                id=record["id"],
                published=record["published"],
                summary=record.get("summary", ""),
                details=record.get("details", ""),
                symbols=symbols,
                commits=tuple(HoldoutCommit(github_repo=r, sha=s) for r, s in commits),
            )
        )
    return Holdout(
        name=NAME, cutoff=cutoff, source=VULNDB_URL, source_sha256=sha256,
        retrieved_at=retrieved_at.isoformat(), attribution=ATTRIBUTION, considered=len(after),
        excluded=dict(sorted(excluded.items())), reports=tuple(chosen),
    )  # fmt: skip


def load(path: Path) -> Holdout:
    return Holdout.model_validate_json(path.read_text("utf-8"))


def as_benchmark(holdout: Holdout) -> tuple[list[DunlapReport], dict[str, AdvisoryText]]:
    """The reports in the Dunlap benchmark's shape, so the same extraction and scoring run."""
    reports = [
        DunlapReport(
            id=r.id,
            commits=tuple(
                FixCommit(github_repo=c.github_repo, sha=c.sha, googlesource=False)
                for c in r.commits
            ),
            symbols=frozenset(r.symbols),
            released=(),
        )
        for r in holdout.reports
    ]
    advisories = {
        r.id: AdvisoryText(id=r.id, summary=r.summary, details=r.details) for r in holdout.reports
    }
    return reports, advisories
