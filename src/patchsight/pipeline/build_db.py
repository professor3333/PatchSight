"""Build the symbol database from normalised advisories.

This first builder writes *fallback* records: every function, method and class a fix
changed, at low confidence (proposal §6, step 5). LLM records replace them as extraction
runs. Low confidence is safe by construction: the scanner lets these symbols raise an alert
to CALLED, but never lower it to IMPORTED_NOT_CALLED.

Fix candidates are used only when they resolve on GitHub, sit on the package's declared
repository (when one is declared), and change Python source. Tag comparisons are not yet
resolved; the build report counts them. A fix that touches more than ``MAX_SYMBOLS``
definitions is reported as ``too_broad`` and gets no record.
"""

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime

from pydantic import BaseModel

from patchsight.db import FixCommitRef, Record, Symbol
from patchsight.names import module_for_path
from patchsight.pipeline.diffs.commits import map_commit
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.diffs.paths import classify_path
from patchsight.pipeline.fix_sample import package_repos
from patchsight.pipeline.http import HttpError, NotFoundError, RateLimitError
from patchsight.pipeline.ingest.aliases import AliasGroup
from patchsight.pipeline.ingest.osv import Advisory
from patchsight.pipeline.pypi import PyPIClient

# Above this many changed definitions a fallback record carries no location signal.
# Set well beyond the 99th percentile (214 in the first full build).
MAX_SYMBOLS = 500


class BuildOutcome(BaseModel):
    vulnerability: str
    status: str
    records: int = 0
    symbols: int = 0
    commits: int = 0


class BuildReport(BaseModel):
    db_version: str
    groups: int
    records: int
    symbols: int
    status: dict[str, int]
    outcomes: tuple[BuildOutcome, ...]


def input_hash(group: AliasGroup, by_id: dict[str, Advisory]) -> str:
    """SHA-256 over only the fields that feed extraction (ADR 0001)."""
    payload = []
    for advisory_id in group.advisory_ids:
        a = by_id[advisory_id]
        payload.append(
            {
                "id": a.id,
                "packages": [p.model_dump(mode="json") for p in a.packages],
                "fix_candidates": sorted(
                    [c.kind, c.repo, c.commit, c.number, c.base, c.head] for c in a.fix_candidates
                ),
                "summary": a.summary,
                "details": a.details,
            }
        )
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _python_source(path: str) -> bool:
    return classify_path(path) == "python"


def _fix_commits(
    group: AliasGroup, by_id: dict[str, Advisory], github: GitHubClient
) -> tuple[list[tuple[str, str]], int]:
    """(repo, sha) pairs to map, and how many tag comparisons were skipped."""
    found: dict[tuple[str, str], None] = {}
    comparisons = 0
    for advisory_id in group.advisory_ids:
        for c in by_id[advisory_id].fix_candidates:
            if c.kind == "github_commit" and c.repo and c.commit:
                found.setdefault((c.repo, c.commit), None)
            elif c.kind == "github_pull" and c.repo and c.number is not None:
                pull = github.pull(c.repo, c.number)
                if pull.merged and pull.merge_commit_sha:
                    found.setdefault((pull.repo, pull.merge_commit_sha), None)
            elif c.kind == "github_compare":
                comparisons += 1
    return list(found), comparisons


def fallback_records(
    group: AliasGroup,
    by_id: dict[str, Advisory],
    github: GitHubClient,
    pypi: PyPIClient,
    now: datetime,
) -> tuple[list[Record], BuildOutcome]:
    try:
        packages, repos = package_repos(group, by_id, github, pypi)
        commits, _ = _fix_commits(group, by_id, github)
    except RateLimitError:
        raise
    except (HttpError, KeyError, ValueError):
        return [], BuildOutcome(vulnerability=group.key, status="error")

    symbols: dict[str, Symbol] = {}
    used: list[FixCommitRef] = []
    module_level_only = False
    for repo, sha in commits:
        try:
            mapping = map_commit(github, repo, sha, include=_python_source)
        except RateLimitError:
            raise
        except (NotFoundError, HttpError, KeyError, ValueError):
            continue
        if repos and mapping.repo not in repos:
            continue
        changed = [(f.mapping.path, c) for f in mapping.files for c in f.mapping.changed]
        if not changed:
            # Python changed, but only at module level (for example registration calls):
            # the paper's "vulnerable function unchanged" case.
            module_level_only = module_level_only or any(
                f.mapping.module_level_hunks for f in mapping.files
            )
            continue
        used.append(FixCommitRef(repo=mapping.repo, sha=mapping.sha))
        for path, definition in changed:
            module = module_for_path(path)
            qualified = f"{module}.{definition.name}" if module else definition.name
            symbols.setdefault(
                qualified,
                Symbol(
                    qualified_name=qualified,
                    module=module,
                    name=definition.name,
                    kind=definition.kind,
                    path=path,
                ),
            )

    if not used:
        if module_level_only:
            status = "module_level_only"
        else:
            status = "no_python_fix" if commits else "no_resolvable_commit"
        return [], BuildOutcome(vulnerability=group.key, status=status, commits=len(commits))
    if len(symbols) > MAX_SYMBOLS:
        # A fix that touches thousands of functions (usually a refactor shipped with it)
        # says nothing about where the bug is. Publishing it would make almost any use of
        # the package CALLED; without a record the scanner says UNKNOWN, which is honest.
        return [], BuildOutcome(
            vulnerability=group.key, status="too_broad", symbols=len(symbols), commits=len(used)
        )
    roots = tuple(sorted({s.module.split(".")[0] for s in symbols.values() if s.module}))
    modified = max(by_id[i].modified for i in group.advisory_ids)
    digest = input_hash(group, by_id)
    records = [
        Record(
            vulnerability=group.key,
            package=package,
            confidence="low",
            source="fallback",
            import_roots=roots,
            entry_points=(),
            symbols=tuple(symbols[k] for k in sorted(symbols)),
            fix_commits=tuple(used),
            model=None,
            prompt_version=None,
            input_hash=digest,
            advisory_modified=modified,
            truncated=False,
            extracted_at=now,
        )
        for package in packages
    ]
    return records, BuildOutcome(
        vulnerability=group.key,
        status="built",
        records=len(records),
        symbols=len(symbols),
        commits=len(used),
    )


def build(
    groups: Sequence[AliasGroup],
    by_id: dict[str, Advisory],
    github: GitHubClient,
    pypi: PyPIClient,
    db_version: str,
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[Record], dict[str, str], BuildReport]:
    now = datetime.now(UTC)
    records: list[Record] = []
    aliases: dict[str, str] = {}
    outcomes: list[BuildOutcome] = []
    for number, group in enumerate(groups, 1):
        built, outcome = fallback_records(group, by_id, github, pypi, now)
        if progress is not None and (number % 100 == 0 or number == len(groups)):
            progress(number, len(groups))
        outcomes.append(outcome)
        if built:
            records.extend(built)
            aliases.update(dict.fromkeys(group.identifiers, group.key))
    return (
        records,
        aliases,
        BuildReport(
            db_version=db_version,
            groups=len(groups),
            records=len(records),
            symbols=sum(len(r.symbols) for r in records),
            status=dict(sorted(Counter(o.status for o in outcomes).items())),
            outcomes=tuple(outcomes),
        ),
    )


def jsonl(records: Iterable[Record]) -> str:
    return "".join(r.model_dump_json() + "\n" for r in records)
