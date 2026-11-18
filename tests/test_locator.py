"""The fix-commit locator's baseline and its masked evaluation, offline."""

from pathlib import Path
from typing import Any

import httpx
import pytest
from packaging.version import Version
from tenacity import wait_none

from conftest import AdvisoryFactory
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.locator import masked
from patchsight.pipeline.locator.baseline import (
    Located,
    bracket,
    fixed_versions,
    locate,
    rank,
    tag_version,
)
from patchsight.pipeline.pypi import PyPIClient

FIX = "f" * 40
TEST_ONLY = "e" * 40
OTHER = "a" * 40


def test_tags_name_versions_with_common_and_monorepo_prefixes() -> None:
    assert tag_version("1.2.3", "pkg") == Version("1.2.3")
    assert tag_version("v2.0", "pkg") == Version("2.0")
    assert tag_version("release-3.1", "pkg") == Version("3.1")
    assert tag_version("some-pkg==0.3.1", "some-pkg") == Version("0.3.1")
    assert tag_version("some_pkg-v1.0", "some-pkg") == Version("1.0")
    assert tag_version("other-1.0", "pkg") is None
    assert tag_version("nightly", "pkg") is None


def test_the_bracket_is_the_last_release_before_the_fix() -> None:
    tags = {Version(v): f"v{v}" for v in ("4.1.9", "4.2.1", "4.2.2", "4.2.3", "5.0", "4.3rc1")}
    assert bracket(tags, Version("4.2.3")) == ("v4.2.2", "v4.2.3")
    assert bracket(tags, Version("4.1.10")) is None  # no tag for the fixed version
    assert bracket({Version("1.0"): "1.0"}, Version("1.0")) is None  # nothing before it


def test_ranking_prefers_the_advisorys_own_ids() -> None:
    ids = ["CVE-2099-1234", "GHSA-aaaa-bbbb-cccc"]
    assert rank("Bump version", ids, "baseline") is None
    assert rank("Fix typo in docs", ids, "baseline") == 0
    assert rank("Fixed CVE-2099-1234", ids, "ranked") == 0
    assert rank("Prevent SQL injection", ids, "ranked") == 1
    assert rank("fix: handle None", ids, "ranked") == 2
    assert rank("Refactor", ids, "ranked") is None


def test_fixed_versions_come_from_the_ranges(make_advisory: AdvisoryFactory) -> None:
    advisory = make_advisory()
    assert fixed_versions(advisory, "some-pkg") == [Version("1.2")]
    assert fixed_versions(advisory, "other") == []


def _clients(tmp_path: Path, commits: list[dict[str, Any]]) -> tuple[GitHubClient, PyPIClient]:
    files = {
        FIX: [{"filename": "src/some_pkg/loader.py", "status": "modified"}],
        TEST_ONLY: [{"filename": "tests/test_loader.py", "status": "modified"}],
        OTHER: [{"filename": "src/some_pkg/other.py", "status": "modified"}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == "pypi.org":
            urls = {"Source": "https://github.com/example/some-pkg"}
            return httpx.Response(200, json={"info": {"project_urls": urls}})
        if path == "/repos/example/some-pkg":
            return httpx.Response(200, json={"full_name": "example/some-pkg"})
        if path == "/repos/example/some-pkg/tags":
            names = ["v1.2", "v1.1", "v1.0", "nightly"]
            return httpx.Response(200, json=[{"name": n} for n in names])
        if path == "/repos/example/some-pkg/compare/v1.1...v1.2":
            return httpx.Response(200, json={"commits": commits, "html_url": "x"})
        if path.startswith("/repos/example/some-pkg/commits/"):
            sha = path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={
                "sha": sha, "html_url": f"https://github.com/example/some-pkg/commit/{sha}",
                "parents": [], "files": files[sha],
            })  # fmt: skip
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    github = GitHubClient(tmp_path / "gh", transport=transport, wait=wait_none())
    pypi = PyPIClient(tmp_path / "pypi", transport=transport, wait=wait_none())
    return github, pypi


def _commit(sha: str, message: str) -> dict[str, Any]:
    return {"sha": sha, "commit": {"message": message}}


def test_locate_takes_the_first_matching_commit_that_touches_python_source(
    tmp_path: Path, make_advisory: AdvisoryFactory
) -> None:
    commits = [
        _commit(OTHER, "Bump version"),
        _commit(TEST_ONLY, "Fix flaky test"),  # matches, but the verifier rejects it
        _commit(FIX, "Fix path traversal (CVE-2099-0001)"),
    ]
    github, pypi = _clients(tmp_path, commits)
    advisory = make_advisory()
    found = locate(["GHSA-0000-0000-0000", "CVE-2099-0001"], [advisory], "some-pkg", github, pypi)
    assert (found.commit, found.base, found.head, found.compared) == (FIX, "v1.1", "v1.2", 3)
    assert found.requests > 0
    ranked = locate(["CVE-2099-0001"], [advisory], "some-pkg", github, pypi, "ranked")
    assert ranked.commit == FIX


def test_locate_abstains_when_nothing_matches(
    tmp_path: Path, make_advisory: AdvisoryFactory
) -> None:
    github, pypi = _clients(tmp_path, [_commit(OTHER, "Bump version")])
    found = locate(["GHSA-0000-0000-0000"], [make_advisory()], "some-pkg", github, pypi)
    assert (found.commit, found.reason) == (None, "no commit message matches")


@pytest.mark.parametrize(
    ("located", "outcome"), [(FIX, "exact"), (OTHER, "wrong"), (None, "abstained")]
)
def test_scoring(located: str | None, outcome: str) -> None:
    case = masked.MaskedCase(
        vulnerability="GHSA-1", advisory_ids=("GHSA-1",), package="p", repo="o/p",
        fixed=("1.2",), truth=(FIX[:7],),  # an abbreviated link still matches
    )  # fmt: skip
    result = masked.score(case, Located(repo="o/p", commit=located, reason="r"))
    assert result.outcome == outcome


def test_the_report_gives_rates_with_intervals_and_abstain_reasons() -> None:
    def result(outcome: str, reason: str = "baseline match") -> masked.CaseResult:
        commit = None if outcome == "abstained" else FIX
        located = Located(repo="o/p", commit=commit, reason=reason, requests=4)
        return masked.CaseResult(vulnerability="v", package="p", located=located, outcome=outcome)

    results = [result("exact"), result("wrong"), result("abstained", "no tag for a fixed version")]
    scores = masked.summarise("baseline", results)
    assert (scores.exact, scores.wrong, scores.abstained) == (1, 1, 1)
    assert scores.abstain_reasons == {"no tag for a fixed version": 1}
    assert scores.wrong_linked_in_range == 0
    report = masked.LocatorReport(
        sample="masked-v1", seed=1, snapshot_sha256="0" * 64, eligible=10, scores=(scores,),
        results={"baseline": tuple(results)},
    )  # fmt: skip
    text = masked.render_markdown(report)
    assert "| `baseline` | 33.3% (1;" in text
    assert "| no tag for a fixed version | 1 |" in text
    assert "| `baseline` | 1 | 0 | 1 |" in text


def test_the_committed_report_renders_from_its_json() -> None:
    reports = Path(__file__).resolve().parents[1] / "docs" / "reports"
    source = reports / "locator-masked-v1.json"
    report = masked.LocatorReport.model_validate_json(source.read_text())
    assert masked.render_markdown(report) == source.with_suffix(".md").read_text()
    sample = Path(__file__).resolve().parents[1] / "benchmarks" / "locator" / "masked-v1.json"
    frozen = masked.MaskedSample.model_validate_json(sample.read_text())
    assert len(frozen.cases) == masked.SAMPLE_SIZE
    assert {c.vulnerability for c in frozen.cases} == {
        r.vulnerability for r in report.results["baseline"]
    }
