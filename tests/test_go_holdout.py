"""The Go temporal holdout: selection, freezing and the benchmark shape, offline."""

import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from patchsight.pipeline.benchmarks import go_holdout
from patchsight.pipeline.diffs.github import PullRequest

REPO = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def _record(identifier: str, published: str, **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": identifier, "published": published, "modified": published,
        "summary": f"Summary of {identifier}", "details": "Details.",
        "affected": [{"package": {"name": "example.com/mod"}, "ecosystem_specific": {
            "imports": [{"path": "example.com/mod/x", "symbols": ["Parse", "Conn.Read"]}]}}],
        "references": [{"type": "FIX", "url": f"https://github.com/Owner/Repo/commit/{SHA}"}],
        "database_specific": {"review_status": "REVIEWED"},
    }  # fmt: skip
    record.update(overrides)
    return record


class FakeGitHub:
    def pull(self, repo: str, number: int) -> PullRequest:
        return PullRequest(repo=repo, number=number, merged=True, merge_commit_sha="b" * 40)


def _archive(tmp_path: Path, records: list[dict[str, Any]]) -> Path:
    path = tmp_path / "vulndb.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("index/db.json", "{}")
        for r in records:
            z.writestr(f"ID/{r['id']}.json", json.dumps(r))
    return path


def test_only_reviewed_reports_after_the_cutoff_with_symbols_and_a_fix_are_kept(
    tmp_path: Path,
) -> None:
    pull = [{"type": "FIX", "url": "https://github.com/o/r/pull/7"}]
    cl = [{"type": "FIX", "url": "https://go.dev/cl/123"}]
    records = [
        _record("GO-2026-0001", "2026-08-13T23:00:00Z"),  # on the cutoff day: excluded
        _record("GO-2026-0002", "2026-08-14T01:00:00Z"),  # kept
        _record("GO-2026-0003", "2026-09-01T00:00:00Z", references=pull),  # kept, resolved
        _record("GO-2026-0004", "2026-09-02T00:00:00Z", references=cl),
        _record("GO-2026-0005", "2026-09-03T00:00:00Z",
                database_specific={"review_status": "UNREVIEWED"}),
        _record("GO-2026-0006", "2026-09-04T00:00:00Z", affected=[]),
        _record("GO-2026-0007", "2026-09-05T00:00:00Z", withdrawn="2026-09-06T00:00:00Z"),
        _record("GO-2026-0008", "2026-09-07T00:00:00Z", references=[]),
    ]  # fmt: skip
    holdout = go_holdout.select(
        _archive(tmp_path, records),
        "f" * 64,
        datetime(2026, 11, 19, tzinfo=UTC),
        FakeGitHub(),  # type: ignore[arg-type]
    )
    assert [r.id for r in holdout.reports] == ["GO-2026-0002", "GO-2026-0003"]
    assert holdout.considered == 7
    assert holdout.excluded == {
        "Go code review only": 1, "no GitHub fix commit": 1, "no symbols": 1,
        "unreviewed": 1, "withdrawn": 1,
    }  # fmt: skip
    first, second = holdout.reports
    assert first.commits[0].github_repo == "owner/repo"  # lower-cased, as GitHub canonicalises
    assert second.commits[0].sha == "b" * 40  # the pull request's merge commit
    assert first.symbols == ("Conn.Read", "Parse")
    assert "CC BY 4.0" in holdout.attribution


def test_the_holdout_runs_through_the_dunlap_shapes(tmp_path: Path) -> None:
    records = [_record("GO-2026-0002", "2026-08-14T01:00:00Z")]
    holdout = go_holdout.select(
        _archive(tmp_path, records),
        "f" * 64,
        datetime(2026, 11, 19, tzinfo=UTC),
        FakeGitHub(),  # type: ignore[arg-type]
    )
    reports, advisories = go_holdout.as_benchmark(holdout)
    assert reports[0].symbols == frozenset({"Parse", "Conn.Read"})
    assert reports[0].released == ()
    assert advisories["GO-2026-0002"].summary == "Summary of GO-2026-0002"


@pytest.mark.skipif(not (REPO / go_holdout.FROZEN).exists(), reason="not frozen yet")
def test_the_frozen_holdout_is_after_the_cutoff_and_complete() -> None:
    holdout = go_holdout.load(REPO / go_holdout.FROZEN)
    assert holdout.cutoff == go_holdout.CUTOFF
    assert all(r.published[:10] > holdout.cutoff for r in holdout.reports)
    assert all(r.symbols and r.commits for r in holdout.reports)
    assert holdout.considered == len(holdout.reports) + sum(holdout.excluded.values())
    assert len({r.id for r in holdout.reports}) == len(holdout.reports)


@pytest.mark.skipif(not (REPO / go_holdout.FROZEN).exists(), reason="not frozen yet")
def test_the_cli_loads_the_holdout_whole_with_its_provenance() -> None:
    from patchsight.pipeline.__main__ import _load_benchmark

    chosen = _load_benchmark(REPO, go_holdout.NAME, "dev")  # a part does not narrow it
    assert len(chosen.reports) == len(go_holdout.load(REPO / go_holdout.FROZEN).reports)
    assert chosen.ids is None
    assert (chosen.split, chosen.replay_name) == ("go-holdout-v1:all", "go-holdout-v1")
    assert chosen.bundle_dir == go_holdout.FROZEN.parent
    assert chosen.split_sha256
    assert chosen.split_sha256 in chosen.source
    with pytest.raises(Exception, match="unknown benchmark"):
        _load_benchmark(REPO, "nonsense", "all")
