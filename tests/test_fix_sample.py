"""Fix-candidate resolution against fake GitHub and PyPI APIs (no network)."""

from datetime import date
from pathlib import Path
from typing import Any

import httpx
import pytest
from tenacity import wait_none

from conftest import SHA_A, SHA_B, AdvisoryFactory
from patchsight.pipeline import fix_sample
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.http import RateLimitError
from patchsight.pipeline.ingest.aliases import alias_groups
from patchsight.pipeline.pypi import PyPIClient, github_repos_in

SHA_C = "c" * 40


def _commit(repo: str, sha: str, files: list[str]) -> dict[str, Any]:
    return {
        "sha": sha,
        "html_url": f"https://github.com/{repo}/commit/{sha}",
        "files": [{"filename": f, "status": "modified", "additions": 1} for f in files],
    }


GITHUB_ROUTES: dict[str, Any] = {
    "/repos/example/some-pkg": {"full_name": "Example/Some-Pkg"},
    "/repos/old-owner/some-pkg": {"full_name": "Example/Some-Pkg"},
    f"/repos/example/some-pkg/commits/{SHA_A}": _commit(
        "Example/Some-Pkg", SHA_A, ["src/some_pkg/loader.py", "tests/test_loader.py"]
    ),
    f"/repos/example/some-pkg/commits/{SHA_B}": _commit("Example/Some-Pkg", SHA_B, ["docs/a.rst"]),
    f"/repos/fork/some-pkg/commits/{SHA_C}": _commit("Fork/Some-Pkg", SHA_C, ["src/x.py"]),
    "/repos/example/some-pkg/pulls/7": {
        "base": {"repo": {"full_name": "Example/Some-Pkg"}},
        "merged": False,
        "merge_commit_sha": None,
    },
    "/repos/example/some-pkg/pulls/8": {
        "base": {"repo": {"full_name": "Example/Some-Pkg"}},
        "merged": True,
        "merge_commit_sha": SHA_C,
    },
    "/repos/example/some-pkg/pulls/8/files": [{"filename": "src/_native.c", "status": "modified"}],
}
PYPI_ROUTES: dict[str, Any] = {
    "/pypi/some-pkg/json": {
        "info": {
            "project_urls": {
                "Source": "https://github.com/old-owner/some-pkg",
                "Funding": "https://github.com/sponsors/someone",
            },
            "home_page": None,
        }
    },
    "/pypi/no-repo/json": {"info": {"project_urls": None, "home_page": "https://example.org"}},
}


def _transport(routes: dict[str, Any]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        body = routes.get(request.url.path)
        return httpx.Response(404) if body is None else httpx.Response(200, json=body)

    return httpx.MockTransport(handler)


@pytest.fixture
def clients(tmp_path: Path) -> tuple[GitHubClient, PyPIClient]:
    github = GitHubClient(
        tmp_path / "gh", token="t", transport=_transport(GITHUB_ROUTES), wait=wait_none()
    )
    pypi = PyPIClient(tmp_path / "pypi", transport=_transport(PYPI_ROUTES), wait=wait_none())
    return github, pypi


def _refs(*urls: str) -> list[dict[str, str]]:
    return [{"type": "WEB", "url": u} for u in urls]


def test_github_repos_in_skips_non_repository_pages() -> None:
    urls = [
        "https://github.com/Owner/Repo.git",
        "https://github.com/sponsors/someone",
        "git@github.com:other/thing",
        "https://example.org",
    ]
    assert github_repos_in(urls) == ("other/thing", "owner/repo")


def test_real_fix_on_renamed_package_repo(
    clients: tuple[GitHubClient, PyPIClient], make_advisory: AdvisoryFactory
) -> None:
    github, pypi = clients
    advisory = make_advisory()  # one FIX link to example/some-pkg@SHA_A
    group = alias_groups([advisory])[0]
    check = fix_sample.check_group(group, {advisory.id: advisory}, github, pypi)
    # PyPI names old-owner/some-pkg; GitHub reports the renamed canonical repo.
    assert check.package_repos == ("example/some-pkg",)
    assert check.outcome == "fix_on_package_repo"
    assert check.fix_touches_python
    (candidate,) = check.candidates
    assert (candidate.files, candidate.python_files, candidate.on_package_repo) == (2, 1, True)


@pytest.mark.parametrize(
    ("references", "outcome"),
    [
        (_refs(f"https://github.com/example/some-pkg/commit/{SHA_B}"), "non_source_only"),
        (_refs(f"https://github.com/fork/some-pkg/commit/{SHA_C}"), "other_repo_only"),
        (_refs("https://github.com/example/some-pkg/pull/7"), "unmerged_pr_only"),
        (_refs("https://github.com/example/some-pkg/commit/deadbeef"), "unresolvable"),
        (
            _refs(
                "https://github.com/example/some-pkg/pull/7",
                f"https://github.com/example/some-pkg/commit/{SHA_A}",
            ),
            "fix_on_package_repo",
        ),
    ],
)
def test_group_outcomes(
    clients: tuple[GitHubClient, PyPIClient],
    make_advisory: AdvisoryFactory,
    references: list[dict[str, str]],
    outcome: str,
) -> None:
    github, pypi = clients
    advisory = make_advisory(references=references)
    group = alias_groups([advisory])[0]
    assert fix_sample.check_group(group, {advisory.id: advisory}, github, pypi).outcome == outcome


def test_merged_pull_request_with_native_fix(
    clients: tuple[GitHubClient, PyPIClient], make_advisory: AdvisoryFactory
) -> None:
    github, pypi = clients
    advisory = make_advisory(references=_refs("https://github.com/example/some-pkg/pull/8"))
    check = fix_sample.check_group(
        alias_groups([advisory])[0], {advisory.id: advisory}, github, pypi
    )
    assert check.outcome == "fix_on_package_repo"
    assert not check.fix_touches_python
    assert check.candidates[0].native_files == 1


def test_undeclared_package_repo_is_unconfirmed(
    clients: tuple[GitHubClient, PyPIClient], make_advisory: AdvisoryFactory
) -> None:
    github, pypi = clients
    affected = [{"package": {"ecosystem": "PyPI", "name": "no-repo"}}]
    advisory = make_advisory(affected=affected)
    check = fix_sample.check_group(
        alias_groups([advisory])[0], {advisory.id: advisory}, github, pypi
    )
    assert check.package_repos == ()
    assert check.outcome == "fix_repo_unconfirmed"


def test_rate_limit_stops_the_run(tmp_path: Path, make_advisory: AdvisoryFactory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers={"x-ratelimit-remaining": "0"})

    github = GitHubClient(tmp_path / "gh", transport=httpx.MockTransport(handler), wait=wait_none())
    pypi = PyPIClient(tmp_path / "pypi", transport=_transport(PYPI_ROUTES), wait=wait_none())
    advisory = make_advisory()
    with pytest.raises(RateLimitError):
        fix_sample.check_group(alias_groups([advisory])[0], {advisory.id: advisory}, github, pypi)


def test_sample_is_reproducible(make_advisory: AdvisoryFactory) -> None:
    advisories = [make_advisory(id=f"PYSEC-2099-{i}", aliases=[]) for i in range(20)]
    groups = alias_groups(advisories)
    first = fix_sample.draw_sample(groups, 5, seed=7)
    assert first == fix_sample.draw_sample(list(reversed(groups)), 5, seed=7)
    assert first != fix_sample.draw_sample(groups, 5, seed=8)
    assert len(fix_sample.draw_sample(groups, 50, seed=7)) == 20


def _group(outcome: str, python: bool = True) -> fix_sample.GroupCheck:
    resolved = fix_sample.CandidateCheck(
        kind="github_commit",
        url="u",
        status="resolved",
        on_package_repo=True,
        files=4,
        python_files=1 if python else 0,
        native_files=0 if python else 1,
    )
    return fix_sample.GroupCheck(
        key=f"G-{outcome}-{python}",
        advisory_ids=("G",),
        packages=("p",),
        package_repos=("o/r",),
        outcome=outcome,  # type: ignore[arg-type]
        fix_touches_python=python and outcome == "fix_on_package_repo",
        candidates=(resolved,),
    )


@pytest.mark.parametrize(
    ("fixed", "unconfirmed", "verdict"),
    [(70, 0, "met"), (50, 20, "inconclusive"), (30, 10, "not_met")],
)
def test_report_verdict(fixed: int, unconfirmed: int, verdict: str) -> None:
    checks = [_group("fix_on_package_repo") for _ in range(fixed)]
    checks += [_group("fix_repo_unconfirmed") for _ in range(unconfirmed)]
    checks += [_group("unresolvable") for _ in range(100 - fixed - unconfirmed)]
    # Gate share 0.675, as measured in Week 1.
    report = fix_sample.build_report(
        checks, as_of=date(2026, 11, 14), seed=1, vulnerabilities=1000, population=675
    )
    assert report.verdict == verdict
    assert report.estimated_share_strict.share == pytest.approx(0.675 * fixed / 100)
    text = fix_sample.render_markdown(report, [])
    assert "Condition" in text or "Inconclusive" in text


def test_report_counts_python_fixes() -> None:
    checks = [_group("fix_on_package_repo"), _group("fix_on_package_repo", python=False)]
    report = fix_sample.build_report(
        checks, as_of=date(2026, 11, 14), seed=1, vulnerabilities=2, population=2
    )
    assert (report.fixes_touching_python.count, report.fixes_touching_python.total) == (1, 2)
    assert report.files_per_fix_median == 4
