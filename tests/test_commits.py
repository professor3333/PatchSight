"""Commit-level mapping against a fake GitHub API (no network)."""

import base64
from pathlib import Path
from typing import Any

import httpx
from tenacity import wait_none

from patchsight.pipeline.diffs.commits import map_commit
from patchsight.pipeline.diffs.github import GitHubClient

SHA, PARENT = "f" * 40, "e" * 40
OLD_PY = "def load(path):\n    return open(path)\n"
NEW_PY = "def load(path):\n    return open(path, 'rb')\n"
NEW_GO = "package p\n\nfunc Parse() {}\n"
BIG_OLD = "def big():\n    return 1\n"
BIG_NEW = "def big():\n    return 2\n"


def _content(text: str) -> dict[str, Any]:
    return {
        "type": "file",
        "encoding": "base64",
        "content": base64.b64encode(text.encode()).decode(),
    }


ROUTES: dict[tuple[str, str | None], Any] = {
    (f"/repos/o/r/commits/{SHA}", "1"): {
        "sha": SHA,
        "html_url": f"https://github.com/O/R/commit/{SHA}",
        "parents": [{"sha": PARENT}],
        "files": [
            {"filename": "pkg/loader.py", "status": "modified",
             "patch": (
                 "@@ -1,2 +1,2 @@\n def load(path):\n"
                 "-    return open(path)\n+    return open(path, 'rb')"
             )},
            {"filename": "p/parse.go", "status": "added"},
            {"filename": "pkg/big.py", "status": "modified"},
            {"filename": "README.md", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"},
            {"filename": "tests/test_loader.py", "status": "modified",
             "patch": "@@ -1 +1 @@\n-a\n+b"},
        ],
    },
    ("/repos/o/r/contents/pkg/loader.py", PARENT): _content(OLD_PY),
    ("/repos/o/r/contents/pkg/loader.py", SHA): _content(NEW_PY),
    ("/repos/o/r/contents/p/parse.go", SHA): _content(NEW_GO),
    # A file over 1 MB: the contents API omits the body, so it is read as a blob.
    ("/repos/o/r/contents/pkg/big.py", PARENT): {"type": "file", "encoding": "none", "sha": "b1"},
    ("/repos/o/r/contents/pkg/big.py", SHA): {"type": "file", "encoding": "none", "sha": "b2"},
    ("/repos/o/r/git/blobs/b1", None): {"content": base64.b64encode(BIG_OLD.encode()).decode()},
    ("/repos/o/r/git/blobs/b2", None): {"content": base64.b64encode(BIG_NEW.encode()).decode()},
}  # fmt: skip


def _github(tmp_path: Path) -> GitHubClient:
    def handler(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        key = (request.url.path, params.get("page") or params.get("ref"))
        body = ROUTES.get(key)
        return httpx.Response(404) if body is None else httpx.Response(200, json=body)

    return GitHubClient(tmp_path, transport=httpx.MockTransport(handler), wait=wait_none())


def test_map_commit(tmp_path: Path) -> None:
    mapping = map_commit(
        _github(tmp_path), "o/r", SHA, include=lambda path: "test" not in path.lower()
    )
    assert (mapping.repo, mapping.sha, mapping.parent) == ("o/r", SHA, PARENT)
    by_path = {f.mapping.path: f for f in mapping.files}
    assert by_path["pkg/loader.py"].diff_source == "github_patch"
    assert [c.name for c in by_path["pkg/loader.py"].mapping.changed] == ["load"]
    assert by_path["p/parse.go"].diff_source == "computed"
    assert [(c.name, c.sides) for c in by_path["p/parse.go"].mapping.changed] == [
        ("Parse", ("post",))
    ]
    assert [c.name for c in by_path["pkg/big.py"].mapping.changed] == ["big"]
    assert {(s.path, s.reason) for s in mapping.skipped} == {
        ("README.md", "unsupported_language"),
        ("tests/test_loader.py", "filtered"),
    }
    assert mapping.changed_names() == {"load", "Parse", "big"}
