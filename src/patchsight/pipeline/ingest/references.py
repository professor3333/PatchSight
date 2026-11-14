"""Classify advisory reference URLs and git ranges into candidate fix commits.

A candidate is a pointer to code that may contain the fix: a commit, a pull request or a
tag comparison. Whether it is on the package's own repository, and whether it really is
the fix, is decided later, when the diff is fetched.
"""

import re
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict

CandidateKind = Literal[
    "github_commit",
    "github_pull",
    "github_compare",
    "gitlab_commit",
    "gitlab_merge_request",
    "bitbucket_commit",
    "other_commit",
]
CandidateOrigin = Literal["reference", "git_range"]

_SHA = r"[0-9a-fA-F]{7,40}"
_END = r"(?:[/.#?]|$)"
_GH_REPO = r"^/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
_GH_PR_COMMIT = re.compile(_GH_REPO + rf"/pull/\d+/commits/(?P<sha>{_SHA}){_END}")
_GH_COMMIT = re.compile(_GH_REPO + rf"/commits?/(?P<sha>{_SHA}){_END}")
_GH_PULL = re.compile(_GH_REPO + r"/pull/(?P<number>\d+)(?:[/#?]|$)")
_GH_COMPARE = re.compile(_GH_REPO + r"/compare/(?P<base>[^/?#]+?)\.{2,3}(?P<head>[^/?#]+)")
_GL_COMMIT = re.compile(rf"^/(?P<repo>.+?)/(?:-/)?commit/(?P<sha>{_SHA}){_END}")
_GL_MR = re.compile(r"^/(?P<repo>.+?)/(?:-/)?merge_requests/(?P<number>\d+)(?:[/#?]|$)")
_BB_COMMIT = re.compile(rf"^/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commits?/(?P<sha>{_SHA}){_END}")
_ANY_COMMIT_PATH = re.compile(rf"/(?:-/)?commits?/(?P<sha>{_SHA}){_END}")
_GITWEB_HASH = re.compile(r";h=(?P<sha>[0-9a-fA-F]{40})")
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


class FixCandidate(BaseModel):
    """A pointer to code that may contain the fix for an advisory."""

    model_config = ConfigDict(frozen=True)

    kind: CandidateKind
    origin: CandidateOrigin
    url: str
    host: str
    repo: str | None = None
    commit: str | None = None
    number: int | None = None
    base: str | None = None
    head: str | None = None
    reference_type: str | None = None


def _clean_repo(name: str) -> str:
    return name.removesuffix(".git").lower()


def _github(path: str) -> dict[str, object] | None:
    for kind, pattern in (
        ("github_commit", _GH_PR_COMMIT),
        ("github_commit", _GH_COMMIT),
        ("github_pull", _GH_PULL),
        ("github_compare", _GH_COMPARE),
    ):
        if match := pattern.match(path):
            fields = match.groupdict()
            result: dict[str, object] = {
                "kind": kind,
                "repo": f"{fields['owner'].lower()}/{_clean_repo(fields['repo'])}",
            }
            if sha := fields.get("sha"):
                result["commit"] = sha.lower()
            if number := fields.get("number"):
                result["number"] = int(number)
            if base := fields.get("base"):
                result["base"], result["head"] = base, fields["head"]
            return result
    return None


def _gitlab(path: str) -> dict[str, object] | None:
    if match := _GL_COMMIT.match(path):
        return {
            "kind": "gitlab_commit",
            "repo": _clean_repo(match["repo"]),
            "commit": match["sha"].lower(),
        }
    if match := _GL_MR.match(path):
        return {
            "kind": "gitlab_merge_request",
            "repo": _clean_repo(match["repo"]),
            "number": int(match["number"]),
        }
    return None


def _bitbucket(path: str) -> dict[str, object] | None:
    if match := _BB_COMMIT.match(path):
        return {
            "kind": "bitbucket_commit",
            "repo": f"{match['owner'].lower()}/{_clean_repo(match['repo'])}",
            "commit": match["sha"].lower(),
        }
    return None


def _self_hosted(url: str, path: str, query: str, host: str) -> dict[str, object] | None:
    """Self-hosted forges: ``/commit/<sha>`` paths, cgit ``?id=<sha>``, gitweb ``;h=<sha>``."""
    sha: str | None = None
    if match := _ANY_COMMIT_PATH.search(path):
        sha = match["sha"]
    else:
        params = parse_qs(query)
        for key in ("id", "h"):
            values = params.get(key, [])
            if values and _FULL_SHA.match(values[0]):
                sha = values[0]
                break
        if sha is None and (match := _GITWEB_HASH.search(url)):
            sha = match["sha"]
    if sha is None or ("commit" not in url and "git" not in host):
        return None
    return {"kind": "other_commit", "commit": sha.lower()}


def classify_url(url: str, reference_type: str | None = None) -> FixCandidate | None:
    """Return a fix candidate if ``url`` points at a commit, pull request or comparison."""
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None

    if host in ("github.com", "www.github.com"):
        fields = _github(parts.path)
    elif host == "gitlab.com" or host.startswith("gitlab."):
        fields = _gitlab(parts.path)
    elif host == "bitbucket.org":
        fields = _bitbucket(parts.path)
    else:
        fields = _self_hosted(url, parts.path, parts.query, host)
    if fields is None:
        return None
    return FixCandidate.model_validate(
        {
            **fields,
            "origin": "reference",
            "url": url,
            "host": host,
            "reference_type": reference_type,
        }
    )


def candidate_from_git_range(repo_url: str, fixed: str) -> FixCandidate | None:
    """Turn an OSV ``GIT`` range ``fixed`` event into a fix candidate."""
    if not _FULL_SHA.match(fixed):
        return None
    try:
        parts = urlsplit(repo_url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if not host:
        return None
    path = parts.path.strip("/")
    segments = path.split("/")
    if host in ("github.com", "www.github.com", "bitbucket.org") and len(segments) >= 2:
        kind = "bitbucket_commit" if host == "bitbucket.org" else "github_commit"
        repo: str | None = f"{segments[0].lower()}/{_clean_repo(segments[1])}"
    elif host == "gitlab.com" or host.startswith("gitlab."):
        kind, repo = "gitlab_commit", _clean_repo(path)
    else:
        kind, repo = "other_commit", (_clean_repo(path) or None)
    return FixCandidate.model_validate(
        {
            "kind": kind,
            "origin": "git_range",
            "url": repo_url,
            "host": host,
            "repo": repo,
            "commit": fixed.lower(),
        }
    )
