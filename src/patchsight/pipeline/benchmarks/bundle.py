"""Benchmark bundles: what a stranger needs to recompute the benchmark scores.

The fix diffs cannot be redistributed, because they are other projects' code. The scores do
not need them, though: they need only which functions each fix changed. A bundle records
that metadata (commit SHAs, file paths, function names and kinds) together with each report's
ground-truth symbols, so ``reproduce`` recomputes the tables offline, with no API key.

Contents and licences: candidate metadata derived by PatchSight from public fix commits;
ground-truth symbols from GoVulnDB as released by Dunlap et al. (GoVulnDB is CC BY 4.0; the
Dunlap et al. data is Apache-2.0).
"""

import json
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.eval.metrics import SetScores, score
from patchsight.pipeline.benchmarks import dunlap
from patchsight.pipeline.diffs.commits import map_commit
from patchsight.pipeline.diffs.github import GitHubClient

BUNDLE_VERSION = 1


class BundleCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    commit: str
    path: str
    name: str
    kind: str


class BundleReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    symbols: tuple[str, ...]
    commits: tuple[str, ...]
    candidates: tuple[BundleCandidate, ...]

    def changed_functions(self) -> set[str]:
        """ChangedFuncs' prediction: every changed function or method, by name."""
        return {c.name for c in self.candidates if c.kind in ("function", "method")}


class Bundle(BaseModel):
    bundle_version: int
    benchmark: str
    source: dict[str, str]
    path_rule: str
    reports: tuple[BundleReport, ...]


def export(
    github: GitHubClient, reports: Sequence[dunlap.DunlapReport], source: dict[str, str]
) -> Bundle:
    """Map every report's fix commits (from the response cache when present)."""
    exported = []
    for report in reports:
        candidates: list[BundleCandidate] = []
        for commit in report.commits:
            mapping = map_commit(
                github, commit.github_repo, commit.sha, include=dunlap.paper_path_filter
            )
            candidates.extend(
                BundleCandidate(commit=commit.sha, path=f.mapping.path, name=c.name, kind=c.kind)
                for f in mapping.files
                for c in f.mapping.changed
            )
        exported.append(
            BundleReport(
                id=report.id,
                symbols=tuple(sorted(report.symbols)),
                commits=tuple(c.sha for c in report.commits),
                candidates=tuple(sorted(candidates, key=lambda c: (c.commit, c.path, c.name))),
            )
        )
    return Bundle(
        bundle_version=BUNDLE_VERSION,
        benchmark="dunlap-dimva24",
        source=source,
        path_rule='Go files whose path does not contain "test" (the paper\'s rule)',
        reports=tuple(exported),
    )


def save(bundle: Bundle, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle.model_dump(mode="json"), indent=1) + "\n", encoding="utf-8")


def load(path: Path) -> Bundle:
    bundle = Bundle.model_validate_json(path.read_text(encoding="utf-8"))
    if bundle.bundle_version != BUNDLE_VERSION:
        raise ValueError(f"{path} is bundle version {bundle.bundle_version}, not {BUNDLE_VERSION}")
    return bundle


def changedfuncs_scores(
    bundle: Bundle, ids: frozenset[str] | None = None, bootstrap: int = 0, seed: int = 0
) -> SetScores:
    chosen = [r for r in bundle.reports if ids is None or r.id in ids]
    predicted = {r.id: r.changed_functions() for r in chosen}
    truth = {r.id: set(r.symbols) for r in chosen}
    return score(predicted, truth, bootstrap, seed)
