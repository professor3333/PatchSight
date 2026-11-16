"""Find a package's declared source repositories from its PyPI metadata.

Offline pipeline only, limited to ``pypi.org``. Used to check that a fix candidate sits on
the package's own repository rather than on a fork, a dependency or an unrelated project.
"""

import re
from pathlib import Path
from typing import Any

import httpx
from tenacity.wait import wait_base

from patchsight.pipeline.http import CachedJsonClient, NotFoundError

PYPI = "https://pypi.org"
_GITHUB_REPO = re.compile(
    r"github\.com[/:](?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)", re.IGNORECASE
)
# github.com/<these>/... are GitHub pages, not repositories.
_NOT_OWNERS = frozenset(
    {"sponsors", "orgs", "marketplace", "features", "topics", "apps", "about", "settings"}
)


def github_repos_in(urls: list[str]) -> tuple[str, ...]:
    """Every distinct ``owner/name`` GitHub repository mentioned in ``urls``, lower-cased."""
    found: set[str] = set()
    for url in urls:
        for match in _GITHUB_REPO.finditer(url):
            owner, repo = match["owner"].lower(), match["repo"].lower().removesuffix(".git")
            if owner not in _NOT_OWNERS and repo:
                found.add(f"{owner}/{repo}")
    return tuple(sorted(found))


class PyPIClient:
    def __init__(
        self,
        cache_dir: Path,
        transport: httpx.BaseTransport | None = None,
        wait: wait_base | None = None,
        offline: bool = False,
    ) -> None:
        self.http = CachedJsonClient(
            PYPI,
            cache_dir,
            headers={"Accept": "application/json", "User-Agent": "patchsight-pipeline"},
            transport=transport,
            wait=wait,
            offline=offline,
        )

    def close(self) -> None:
        self.http.close()

    def declared_github_repos(self, package: str) -> tuple[str, ...] | None:
        """GitHub repositories named in the package's metadata, or None if PyPI has no record."""
        try:
            data: dict[str, Any] = self.http.get_json(f"/pypi/{package}/json")
        except NotFoundError:
            return None
        info = data.get("info") or {}
        urls = [str(u) for u in (info.get("project_urls") or {}).values() if u]
        urls += [str(info[k]) for k in ("home_page", "download_url") if info.get(k)]
        return github_repos_in(urls)
