"""Find an advisory's fix commit without a fix link: the deterministic baseline.

The proposal's baseline for the fix-commit locator: compare the last vulnerable release's
tag with the first fixed release's tag on the package's own repository, and take the
first commit between them whose message says "CVE", "security" or "fix". The bounded
agent of rule 8 is measured against it.

Inputs are only what an advisory without a fix link still has:

* the package's repositories, from its PyPI metadata (never from the advisory's
  references or git ranges, which would leak the answer);
* the fixed versions in the advisory's version ranges;
* the advisory's own IDs (for the ``ranked`` variant).

A located commit is verified as rule 8 asks: it exists (it came from the comparison), it
sits between the two tags (by construction), and it touches non-test Python source.
Otherwise the next candidate is tried, and with none left the locator abstains.
"""

import re
from collections.abc import Iterable, Sequence
from typing import Any, Literal

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.diffs.paths import classify_path
from patchsight.pipeline.http import HttpError, NotFoundError
from patchsight.pipeline.pypi import PyPIClient

Variant = Literal["baseline", "ranked"]
VARIANTS: tuple[Variant, ...] = ("baseline", "ranked")
MAX_TAG_PAGES = 10  # 1,000 tags: enough for every package in the sample
MAX_VERIFIED = 5  # candidate commits verified per comparison before abstaining
_BASELINE = re.compile(r"cve-\d{4}-\d+|security|fix", re.IGNORECASE)
_SECURITY = re.compile(r"cve-\d{4}-\d+|ghsa-|security|vulnerab|exploit|injection", re.IGNORECASE)
_FIX = re.compile(r"\bfix", re.IGNORECASE)
_VERSION_TAIL = re.compile(r"(\d+(?:\.\d+)*(?:[._-]?(?:a|b|rc|post|dev)\.?\d+)*)$", re.IGNORECASE)


class Located(BaseModel):
    """What the locator found for one advisory, and what it cost."""

    model_config = ConfigDict(frozen=True)

    repo: str | None
    commit: str | None  # None: abstained
    reason: str  # why it abstained, or how it chose
    base: str | None = None
    head: str | None = None
    compared: int = 0  # commits between the tags
    requests: int = 0  # GitHub and PyPI requests this advisory needed, cached or not


def tag_version(tag: str, package: str) -> Version | None:
    """The release version a tag names, or None.

    Accepts ``1.2.3``, ``v1.2.3``, ``release-1.2.3`` and, in monorepos, tags that name the
    package (``langchain-core==0.3.1``, ``pkg-v1.2``).

    >>> tag_version("v4.2.3", "django"), tag_version("langchain-core==0.3.1", "langchain-core")
    (<Version('4.2.3')>, <Version('0.3.1')>)
    >>> tag_version("other-lib-1.0", "django") is None
    True
    """
    match = _VERSION_TAIL.search(tag)
    if match is None:
        return None
    prefix = tag[: match.start()].lower().rstrip("=-_/@ ")
    names = {package.lower(), package.lower().replace("-", "_"), package.lower().replace("_", "-")}
    allowed = prefix in ("", "v", "release", "rel", "version")
    if not allowed and prefix.removesuffix("v").rstrip("=-_/@ ") not in names:
        return None
    try:
        return Version(match.group(1))
    except InvalidVersion:
        return None


def fixed_versions(advisory: Any, package: str) -> list[Version]:
    """The advisory's fixed versions for ``package``, highest first."""
    found: set[Version] = set()
    for affected in advisory.packages:
        if affected.name != package:
            continue
        for version_range in affected.ranges:
            for event in version_range.events:
                if event.fixed:
                    try:
                        found.add(Version(event.fixed))
                    except InvalidVersion:
                        continue
    return sorted(found, reverse=True)


def tags(github: GitHubClient, repo: str) -> list[str]:
    names: list[str] = []
    for page in range(1, MAX_TAG_PAGES + 1):
        batch = github.http.get_json(f"/repos/{repo}/tags", {"per_page": 100, "page": page})
        names.extend(str(t["name"]) for t in batch)
        if len(batch) < 100:
            break
    return names


def bracket(versions: dict[Version, str], fixed: Version) -> tuple[str, str] | None:
    """(last tag before ``fixed``, ``fixed``'s tag), by version order, or None."""
    head = versions.get(fixed)
    if head is None:
        return None
    below = [v for v in versions if v < fixed and not v.is_prerelease]
    if not below:
        return None
    return versions[max(below)], head


def rank(message: str, ids: Iterable[str], variant: Variant) -> int | None:
    """Lower is better; None: not a candidate."""
    if variant == "baseline":
        return 0 if _BASELINE.search(message) else None
    text = message.lower()
    if any(i.lower() in text for i in ids):
        return 0
    if _SECURITY.search(message):
        return 1
    if _FIX.search(message):
        return 2
    return None


def _touches_python_source(github: GitHubClient, repo: str, sha: str) -> bool:
    try:
        change = github.commit(repo, sha)
    except (NotFoundError, HttpError):
        return False
    return any(classify_path(f.filename) == "python" for f in change.files)


def locate(
    advisory_ids: Sequence[str],
    advisories: Sequence[Any],
    package: str,
    github: GitHubClient,
    pypi: PyPIClient,
    variant: Variant = "baseline",
) -> Located:
    """The fix commit of one vulnerability in ``package``, from tags and messages only."""
    start = github.http.lookups + pypi.http.lookups

    def cost() -> int:
        return github.http.lookups + pypi.http.lookups - start

    declared = pypi.declared_github_repos(package) or ()
    repos = []
    for repo in declared:
        try:
            repos.append(github.canonical_repo(repo))
        except NotFoundError:
            continue
    if not repos:
        return Located(
            repo=None, commit=None, reason="no GitHub repository on PyPI", requests=cost()
        )
    wanted = sorted({v for a in advisories for v in fixed_versions(a, package)}, reverse=True)
    if not wanted:
        return Located(repo=repos[0], commit=None, reason="no fixed version", requests=cost())
    reason = "no tag for a fixed version"
    for repo in sorted(set(repos)):
        try:
            by_version: dict[Version, str] = {}
            for name in tags(github, repo):
                version = tag_version(name, package)
                if version is not None:
                    by_version.setdefault(version, name)
        except (NotFoundError, HttpError):
            continue
        for fixed in wanted:
            pair = bracket(by_version, fixed)
            if pair is None:
                continue
            base, head = pair
            try:
                data = github.http.get_json(f"/repos/{repo}/compare/{base}...{head}")
            except (NotFoundError, HttpError):
                reason = "comparison failed"
                continue
            commits = data.get("commits") or []
            ranked = sorted(
                (
                    (r, i, str(c["sha"]))
                    for i, c in enumerate(commits)
                    if (r := rank(str(c["commit"]["message"]), advisory_ids, variant)) is not None
                ),
            )
            if not ranked:
                reason = "no commit message matches"
                continue
            for _, _, sha in ranked[:MAX_VERIFIED]:
                if _touches_python_source(github, repo, sha):
                    return Located(
                        repo=repo, commit=sha, reason=f"{variant} match", base=base, head=head,
                        compared=len(commits), requests=cost(),
                    )  # fmt: skip
            reason = "no matching commit touches Python source"
    return Located(repo=sorted(repos)[0], commit=None, reason=reason, requests=cost())
