"""Map a whole fix commit to the definitions it changes: fetch, filter, parse, map."""

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.diffs.github import ChangedFile, GitHubClient
from patchsight.pipeline.diffs.hunks import PatchParseError, diff_hunks, parse_patch
from patchsight.pipeline.diffs.mapping import (
    FileMapping,
    SourceLanguage,
    language_for,
    map_hunks,
)

DiffSource = Literal["github_patch", "computed"]
SkipReason = Literal["unsupported_language", "filtered"]
PathFilter = Callable[[str], bool]


class SkippedFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    reason: SkipReason


class MappedFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    mapping: FileMapping
    status: str
    previous_path: str | None
    diff_source: DiffSource


class CommitMapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo: str
    sha: str
    parent: str | None
    files: tuple[MappedFile, ...]
    skipped: tuple[SkippedFile, ...]
    truncated: bool

    def changed_names(self) -> set[str]:
        return {c.name for f in self.files for c in f.mapping.changed}


def _map_file(
    github: GitHubClient,
    repo: str,
    sha: str,
    parent: str | None,
    changed: ChangedFile,
    language: SourceLanguage,
) -> MappedFile:
    old_path = changed.previous_filename or changed.filename
    old = None
    if changed.status != "added" and parent is not None:
        old = github.file_content(repo, old_path, parent)
    new = None if changed.status == "removed" else github.file_content(repo, changed.filename, sha)

    source: DiffSource = "github_patch"
    try:
        if not changed.patch:
            raise PatchParseError("no patch")
        hunks = parse_patch(changed.patch)
    except PatchParseError:
        source = "computed"
        hunks = diff_hunks(
            old.decode("utf-8", "replace") if old is not None else None,
            new.decode("utf-8", "replace") if new is not None else None,
        )
    return MappedFile(
        mapping=map_hunks(changed.filename, language, old, new, hunks),
        status=changed.status,
        previous_path=changed.previous_filename,
        diff_source=source,
    )


def map_commit(github: GitHubClient, repo: str, sha: str, include: PathFilter) -> CommitMapping:
    """Map every included Python or Go file of a commit to its changed definitions."""
    change = github.commit(repo, sha)
    parent = change.parents[0] if change.parents else None
    files, skipped = [], []
    for changed in change.files:
        language = language_for(changed.filename)
        if language is None:
            skipped.append(SkippedFile(path=changed.filename, reason="unsupported_language"))
        elif not include(changed.filename):
            skipped.append(SkippedFile(path=changed.filename, reason="filtered"))
        else:
            files.append(
                _map_file(github, change.repo, change.commits[0], parent, changed, language)
            )
    return CommitMapping(
        repo=change.repo,
        sha=change.commits[0],
        parent=parent,
        files=tuple(files),
        skipped=tuple(skipped),
        truncated=change.truncated,
    )
