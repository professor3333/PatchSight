"""Read fix commits, pull requests and tag comparisons through the GitHub REST API.

Read-only, and limited to ``api.github.com``. Repository names come back canonical
(lower-cased ``owner/name``, after following renames), so they can be compared with the
package's declared repository.
"""

import base64
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict
from tenacity.wait import wait_base

from patchsight.pipeline.http import AuthError, CachedJsonClient, HttpError, NotFoundError

GITHUB_API = "https://api.github.com"


def check_token(token: str | None, client: httpx.Client | None = None) -> int:
    """GitHub's own answer to the token, never from the cache: the core requests it has left
    this hour. Raises AuthError when GitHub refuses it, so a long run can stop at once
    instead of reading nothing for hours. ``/rate_limit`` does not count against the limit."""
    http = client or httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0))
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = http.get(f"{GITHUB_API}/rate_limit", headers=headers)
    finally:
        if client is None:
            http.close()
    if response.status_code == 401:
        raise AuthError("GitHub refused the token (HTTP 401)")
    if response.status_code != 200:
        raise HttpError(f"GitHub's rate-limit check answered HTTP {response.status_code}")
    return int(response.json()["resources"]["core"]["remaining"])


COMMIT_FILES_PER_PAGE = 300  # fixed by the API for single-commit responses
MAX_COMMIT_PAGES = 10  # the API stops listing files at 3,000
PULL_FILES_PER_PAGE = 100
MAX_PULL_PAGES = 30
COMPARE_FILE_LIMIT = 300

_HTML_REPO = re.compile(r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/")


class ChangedFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    filename: str
    status: str
    previous_filename: str | None = None
    additions: int = 0
    deletions: int = 0
    patch: str | None = None


class ChangeSet(BaseModel):
    """The files a commit, merged pull request or comparison changed."""

    model_config = ConfigDict(frozen=True)

    repo: str
    commits: tuple[str, ...]
    parents: tuple[str, ...] = ()
    files: tuple[ChangedFile, ...]
    truncated: bool


class PullRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo: str
    number: int
    merged: bool
    merge_commit_sha: str | None


def _files(raw: list[dict[str, Any]]) -> list[ChangedFile]:
    return [ChangedFile.model_validate(item) for item in raw]


def _repo_from_html(url: str) -> str:
    match = _HTML_REPO.match(url)
    if not match:
        raise ValueError(f"unexpected html_url {url!r}")
    return f"{match['owner']}/{match['repo']}".lower()


class GitHubClient:
    def __init__(
        self,
        cache_dir: Path,
        token: str | None = None,
        transport: httpx.BaseTransport | None = None,
        wait: wait_base | None = None,
        wait_for_rate_limit: float = 0.0,
        offline: bool = False,
    ) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "patchsight-pipeline",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.http = CachedJsonClient(
            GITHUB_API,
            cache_dir,
            headers=headers,
            transport=transport,
            wait=wait,
            wait_for_rate_limit=wait_for_rate_limit,
            offline=offline,
        )

    def close(self) -> None:
        self.http.close()

    def canonical_repo(self, repo: str) -> str:
        """``owner/name`` as GitHub currently names it, lower-cased. Follows renames."""
        data = self.http.get_json(f"/repos/{repo}")
        return str(data["full_name"]).lower()

    def commit(self, repo: str, sha: str) -> ChangeSet:
        files: list[ChangedFile] = []
        first: dict[str, Any] = {}
        truncated = False
        for page in range(1, MAX_COMMIT_PAGES + 1):
            data = self.http.get_json(f"/repos/{repo}/commits/{sha}", {"page": page})
            first = first or data
            batch = data.get("files") or []
            files.extend(_files(batch))
            if len(batch) < COMMIT_FILES_PER_PAGE:
                break
        else:
            truncated = True
        return ChangeSet(
            repo=_repo_from_html(first["html_url"]),
            commits=(str(first["sha"]),),
            parents=tuple(str(p["sha"]) for p in first.get("parents") or []),
            files=tuple(files),
            truncated=truncated,
        )

    def pull(self, repo: str, number: int) -> PullRequest:
        data = self.http.get_json(f"/repos/{repo}/pulls/{number}")
        return PullRequest(
            repo=str(data["base"]["repo"]["full_name"]).lower(),
            number=number,
            merged=bool(data.get("merged")),
            merge_commit_sha=data.get("merge_commit_sha"),
        )

    def pull_files(self, repo: str, number: int) -> ChangeSet:
        pull = self.pull(repo, number)
        files: list[ChangedFile] = []
        truncated = False
        for page in range(1, MAX_PULL_PAGES + 1):
            batch = self.http.get_json(
                f"/repos/{repo}/pulls/{number}/files",
                {"page": page, "per_page": PULL_FILES_PER_PAGE},
            )
            files.extend(_files(batch))
            if len(batch) < PULL_FILES_PER_PAGE:
                break
        else:
            truncated = True
        commits = (pull.merge_commit_sha,) if pull.merge_commit_sha else ()
        return ChangeSet(repo=pull.repo, commits=commits, files=tuple(files), truncated=truncated)

    def compare(self, repo: str, base: str, head: str) -> ChangeSet:
        data = self.http.get_json(f"/repos/{repo}/compare/{base}...{head}")
        raw_files = data.get("files") or []
        return ChangeSet(
            repo=_repo_from_html(data["html_url"]),
            commits=tuple(str(c["sha"]) for c in data.get("commits") or []),
            files=tuple(_files(raw_files)),
            truncated=len(raw_files) >= COMPARE_FILE_LIMIT,
        )

    def file_content(self, repo: str, path: str, ref: str) -> bytes | None:
        """A file's bytes at ``ref``, or None if it does not exist there.

        The contents API inlines files up to 1 MB; larger ones are read as git blobs.
        """
        try:
            data = self.http.get_json(f"/repos/{repo}/contents/{quote(path)}", {"ref": ref})
        except NotFoundError:
            return None
        if not isinstance(data, dict) or data.get("type") != "file":
            return None
        if data.get("encoding") == "base64" and data.get("content"):
            return base64.b64decode(data["content"])
        blob = self.http.get_json(f"/repos/{repo}/git/blobs/{data['sha']}")
        return base64.b64decode(blob["content"]) if blob.get("content") else b""
