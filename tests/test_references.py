import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight.pipeline.ingest.references import candidate_from_git_range, classify_url

SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    ("url", "kind", "repo", "commit", "number"),
    [
        (f"https://github.com/Owner/Repo/commit/{SHA}", "github_commit", "owner/repo", SHA, None),
        (f"https://github.com/o/r/commit/{SHA}#diff-1", "github_commit", "o/r", SHA, None),
        ("https://github.com/o/r/commit/ABCDEF1.patch", "github_commit", "o/r", "abcdef1", None),
        (f"https://www.github.com/o/r.git/commit/{SHA}", "github_commit", "o/r", SHA, None),
        (f"https://github.com/o/r/commits/{SHA}", "github_commit", "o/r", SHA, None),
        (
            "https://github.com/o/r/pull/12/commits/abcdef12",
            "github_commit",
            "o/r",
            "abcdef12",
            None,
        ),
        ("https://github.com/o/r/pull/123", "github_pull", "o/r", None, 123),
        ("https://github.com/o/r/pull/123/files", "github_pull", "o/r", None, 123),
        (
            "https://gitlab.com/g/sub/p/-/commit/abcdef1234",
            "gitlab_commit",
            "g/sub/p",
            "abcdef1234",
            None,
        ),
        ("https://gitlab.com/g/p/-/merge_requests/7", "gitlab_merge_request", "g/p", None, 7),
        (
            "https://bitbucket.org/o/r/commits/abcdef1234",
            "bitbucket_commit",
            "o/r",
            "abcdef1234",
            None,
        ),
        (f"https://git.example.org/cgit/r.git/commit/?id={SHA}", "other_commit", None, SHA, None),
    ],
)
def test_classify_url_finds_candidates(
    url: str, kind: str, repo: str | None, commit: str | None, number: int | None
) -> None:
    candidate = classify_url(url, "FIX")
    assert candidate is not None
    assert (candidate.kind, candidate.repo, candidate.commit, candidate.number) == (
        kind,
        repo,
        commit,
        number,
    )
    assert candidate.origin == "reference"
    assert candidate.reference_type == "FIX"


def test_classify_url_reads_tag_comparisons() -> None:
    candidate = classify_url("https://github.com/o/r/compare/v1.0...v1.1")
    assert candidate is not None
    assert (candidate.kind, candidate.base, candidate.head) == ("github_compare", "v1.0", "v1.1")


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/o/r/issues/1",
        "https://github.com/o/r",
        "https://github.com/o/r/commits/main",
        "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
        "https://pypi.org/project/some-pkg/",
        f"ftp://github.com/o/r/commit/{SHA}",
        "not a url",
        "",
    ],
)
def test_classify_url_ignores_non_fix_links(url: str) -> None:
    assert classify_url(url) is None


@given(st.text())
def test_classify_url_never_raises(text: str) -> None:
    classify_url(text)
    classify_url(f"https://github.com/{text}")


@given(
    owner=st.from_regex(r"\A[A-Za-z0-9][A-Za-z0-9-]{0,20}\Z"),
    repo=st.from_regex(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,20}\Z"),
    sha=st.from_regex(r"\A[0-9a-f]{40}\Z"),
)
def test_any_github_commit_url_is_classified(owner: str, repo: str, sha: str) -> None:
    candidate = classify_url(f"https://github.com/{owner}/{repo}/commit/{sha}")
    assert candidate is not None
    assert candidate.kind == "github_commit"
    assert candidate.repo == f"{owner.lower()}/{repo.lower()}"
    assert candidate.commit == sha


def test_git_range_on_github() -> None:
    candidate = candidate_from_git_range("https://github.com/Example/Some-Pkg.git", SHA.upper())
    assert candidate is not None
    assert (candidate.kind, candidate.origin, candidate.repo, candidate.commit) == (
        "github_commit",
        "git_range",
        "example/some-pkg",
        SHA,
    )


@pytest.mark.parametrize(
    ("repo_url", "kind", "repo"),
    [
        ("https://gitlab.com/g/p", "gitlab_commit", "g/p"),
        ("https://bitbucket.org/o/r", "bitbucket_commit", "o/r"),
        ("https://git.example.org/r.git", "other_commit", "r"),
    ],
)
def test_git_range_on_other_hosts(repo_url: str, kind: str, repo: str) -> None:
    candidate = candidate_from_git_range(repo_url, SHA)
    assert candidate is not None
    assert (candidate.kind, candidate.repo) == (kind, repo)


@pytest.mark.parametrize("fixed", ["1.2.3", "abcdef1", "", "z" * 40])
def test_git_range_needs_a_full_sha(fixed: str) -> None:
    assert candidate_from_git_range("https://github.com/o/r", fixed) is None
