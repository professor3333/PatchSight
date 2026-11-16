"""PyPI extraction (the backfill), with GitHub, PyPI and the model replaced by stubs."""

import json
from pathlib import Path
from typing import Any

import pytest

from conftest import SHA_A, AdvisoryFactory
from patchsight.pipeline import build_db, pypi_extract
from patchsight.pipeline.diffs.commits import CommitMapping, MappedFile
from patchsight.pipeline.diffs.hunks import Hunk
from patchsight.pipeline.diffs.mapping import ChangedDefinition, FileMapping
from patchsight.pipeline.extract.prompt import load_template
from patchsight.pipeline.ingest.aliases import alias_groups
from patchsight.pipeline.llm.client import LLMClient, LLMRequest, RateLimiter
from patchsight.pipeline.llm.config import LLMConfig
from patchsight.pipeline.llm.tokens import CharEstimate

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = load_template(ROOT / "prompts" / "extract_v1.md")
CONFIG = LLMConfig.model_validate(
    {
        "providers": {"p": {"base_url": "u", "api_key_env": "K", "tokens_per_minute": 100_000,
                            "requests_per_day": 100}},
        "models": {"m": {"provider": "p", "model": "fake-model", "max_output_tokens": 1500,
                         "seed": 1}},
        "budget": {"max_prompt_tokens": 4600, "max_hunk_lines": 80},
        "tokenizer": {"repo": "r", "revision": "v", "sha256": "s"},
    }
)  # fmt: skip


def _hunk(index: int) -> Hunk:
    return Hunk(index=index, old_start=1, old_count=1, new_start=1, new_count=1,
                removed=(1,), added=(1,), lines=("-old", "+new"))  # fmt: skip


def _mapping(files: dict[str, list[tuple[str, str]]]) -> CommitMapping:
    mapped = []
    for path, names in files.items():
        changed = tuple(
            ChangedDefinition(path=path, name=n, kind=k, sides=("pre",), hunks=(i,))  # type: ignore[arg-type]
            for i, (n, k) in enumerate(names)
        )
        mapped.append(
            MappedFile(
                mapping=FileMapping(
                    path=path,
                    changed=changed,
                    module_level_hunks=(),
                    parse_errors=False,
                    known_names=tuple(n for n, _ in names),
                ),
                status="modified",
                previous_path=None,
                diff_source="github_patch",
                hunks=tuple(_hunk(i) for i in range(len(names))),
            )
        )
    return CommitMapping(
        repo="example/some-pkg", sha=SHA_A, parent="p", files=tuple(mapped), skipped=(),
        truncated=False,
    )  # fmt: skip


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"mapping": None}
    monkeypatch.setattr(
        build_db, "package_repos", lambda g, b, gh, p: (("some-pkg",), {"example/some-pkg"})
    )
    monkeypatch.setattr(build_db, "map_commit", lambda gh, repo, sha, include: state["mapping"])
    return state


def _client(tmp_path: Path, answer: dict[str, Any]) -> tuple[LLMClient, list[LLMRequest]]:
    seen: list[LLMRequest] = []

    def backend(request: LLMRequest) -> tuple[str, int, int]:
        seen.append(request)
        return json.dumps(answer), 100, 20

    return LLMClient(backend, RateLimiter(100_000, 100), tmp_path), seen


def _run(make_advisory: AdvisoryFactory, client: LLMClient, **advisory: Any) -> Any:
    record = make_advisory(**advisory)
    group = alias_groups([record])[0]
    return pypi_extract.run(
        [group], {record.id: record}, None, None, client, CONFIG, "m", TEMPLATE,  # type: ignore[arg-type]
        CharEstimate(3.0),
    )  # fmt: skip


def _item(cid: str, vulnerable: bool, hunks: list[str]) -> dict[str, Any]:
    return {"candidate_id": cid, "is_vulnerable": vulnerable, "rationale": "Because.",
            "evidence_hunk_ids": hunks}  # fmt: skip


def test_classes_compete_and_vulnerable_symbols_are_module_qualified(
    stub: dict[str, Any], make_advisory: AdvisoryFactory, tmp_path: Path
) -> None:
    stub["mapping"] = _mapping(
        {"src/some_pkg/loader.py": [("FullLoader", "class"), ("load", "function")]}
    )
    answer = {"items": [_item("F1", True, ["H1"]), _item("F2", False, [])],
              "public_entry_points": []}  # fmt: skip
    client, seen = _client(tmp_path, answer)
    results, summary = _run(make_advisory, client)
    prompt = seen[0].messages[1]["content"]
    assert 'name="FullLoader" kind="class"' in prompt
    (result,) = results
    assert [s.qualified_name for s in result.vulnerable_symbols] == ["some_pkg.loader.FullLoader"]
    assert (result.vulnerable_symbols[0].kind, result.packages) == ("class", ("some-pkg",))
    assert result.outcome.vulnerable_locations == (("src/some_pkg/loader.py", "FullLoader"),)
    (evidence,) = result.evidence
    assert (evidence.qualified_name, evidence.rationale) == (
        "some_pkg.loader.FullLoader",
        "Because.",
    )
    assert [(h.commit, h.path) for h in evidence.hunks] == [(SHA_A, "src/some_pkg/loader.py")]
    assert [c.sha for c in result.fix_commits] == [SHA_A]
    assert (summary.status, summary.skipped) == ({"ok": 1}, {})


def test_candidates_match_the_fallback_record(
    stub: dict[str, Any], make_advisory: AdvisoryFactory, tmp_path: Path
) -> None:
    stub["mapping"] = _mapping(
        {"src/some_pkg/a.py": [("A", "class"), ("A.run", "method"), ("helper", "function")]}
    )
    answer = {"items": [_item(f"F{i}", False, []) for i in (1, 2, 3)], "public_entry_points": []}
    client, seen = _client(tmp_path, answer)
    _run(make_advisory, client)
    records, _ = build_db.fallback_records(
        alias_groups([make_advisory()])[0], {make_advisory().id: make_advisory()}, None, None,  # type: ignore[arg-type]
        build_db.datetime.now(build_db.UTC),
    )  # fmt: skip
    prompt = seen[0].messages[1]["content"]
    for symbol in records[0].symbols:
        assert f'name="{symbol.name}"' in prompt


def test_vulnerabilities_without_a_python_fix_are_skipped_without_a_call(
    stub: dict[str, Any], make_advisory: AdvisoryFactory, tmp_path: Path
) -> None:
    stub["mapping"] = _mapping({})
    client, seen = _client(tmp_path, {})
    results, summary = _run(make_advisory, client)
    assert (results, seen, summary.skipped) == ([], [], {"no_python_fix": 1})


def test_too_broad_fixes_are_skipped_without_a_call(
    stub: dict[str, Any], make_advisory: AdvisoryFactory, tmp_path: Path
) -> None:
    names = [(f"f{i}", "function") for i in range(build_db.MAX_SYMBOLS + 1)]
    stub["mapping"] = _mapping({"src/some_pkg/big.py": names})
    client, seen = _client(tmp_path, {})
    results, summary = _run(make_advisory, client)
    assert (results, seen, summary.skipped) == ([], [], {"too_broad": 1})


def test_advisory_text_prefers_the_longest_details(make_advisory: AdvisoryFactory) -> None:
    short = make_advisory(id="GHSA-aaaa-bbbb-cccc", aliases=["PYSEC-2099-1"], details="Short.")
    long_ = make_advisory(id="PYSEC-2099-1", aliases=["GHSA-aaaa-bbbb-cccc"],
                          summary="", details="A much longer description of the bug.")  # fmt: skip
    group = alias_groups([short, long_])[0]
    text = pypi_extract.advisory_text(group, {short.id: short, long_.id: long_})
    assert text.details == "A much longer description of the bug."
    assert text.summary == "Synthetic advisory"
    assert text.id == group.key


def test_plan_measures_prompts_without_a_model(
    stub: dict[str, Any], make_advisory: AdvisoryFactory
) -> None:
    stub["mapping"] = _mapping({"src/some_pkg/a.py": [(f"f{i}", "function") for i in range(6)]})
    record = make_advisory()
    group = alias_groups([record])[0]
    tight = CONFIG.model_copy(
        update={"budget": CONFIG.budget.model_copy(update={"output_tokens_per_candidate": 500})}
    )
    plan = pypi_extract.plan_vulnerability(
        group,
        {record.id: record},
        None,
        None,
        tight,
        "m",
        TEMPLATE,
        CharEstimate(3.0),  # type: ignore[arg-type]
    )
    assert not isinstance(plan, str)
    assert (plan.candidates, plan.kept, plan.truncated) == (6, 3, True)  # 1,500 // 500
    assert plan.full_prompt_tokens > 0


def test_offline_cache_misses_are_reported_not_mistaken_for_no_fix(
    monkeypatch: pytest.MonkeyPatch, make_advisory: AdvisoryFactory, tmp_path: Path
) -> None:
    from patchsight.pipeline.http import CacheMissError

    def missing(*args: object, **kwargs: object) -> None:
        raise CacheMissError("not in the offline cache")

    monkeypatch.setattr(
        build_db, "package_repos", lambda g, b, gh, p: (("some-pkg",), {"example/some-pkg"})
    )
    monkeypatch.setattr(build_db, "map_commit", missing)
    client, seen = _client(tmp_path, {})
    results, summary = _run(make_advisory, client)
    assert (results, seen, summary.skipped) == ([], [], {"cache_miss": 1})


def test_shards_partition_the_vulnerabilities() -> None:
    keys = [f"GHSA-{i:04d}" for i in range(200)]
    shards = [[k for k in keys if pypi_extract.in_shard(k, s, 4)] for s in (1, 2, 3, 4)]
    assert sorted(k for shard in shards for k in shard) == sorted(keys)
    assert all(shards)
    with pytest.raises(ValueError, match="between 1 and 4"):
        pypi_extract.in_shard("x", 5, 4)


def test_time_budget_stops_starting_new_work(
    stub: dict[str, Any], make_advisory: AdvisoryFactory, tmp_path: Path
) -> None:
    stub["mapping"] = _mapping({"src/some_pkg/a.py": [("f", "function")]})
    answer = {"items": [_item("F1", False, [])], "public_entry_points": []}
    client, _ = _client(tmp_path, answer)
    records = [make_advisory(id=f"GHSA-aaaa-bbbb-{c}{c}{c}{c}", aliases=[]) for c in "wxyz"]
    groups = alias_groups(records)
    ticks = iter([0.0, 1.0, 5.0, 9.0, 99.0])
    results, summary = pypi_extract.run(
        groups, {r.id: r for r in records}, None, None, client, CONFIG, "m", TEMPLATE,  # type: ignore[arg-type]
        CharEstimate(3.0), deadline=6.0, clock=lambda: next(ticks),
    )  # fmt: skip
    assert (summary.processed, summary.complete, len(results)) == (3, False, 3)


def test_download_rank_normalises_names_and_orders_by_downloads(tmp_path: Path) -> None:
    dump = tmp_path / "top.json"
    dump.write_text(json.dumps({"last_update": "2026-11-01", "rows": [
        {"download_count": 10, "project": "Small_Pkg"},
        {"download_count": 900, "project": "boto3"},
        {"download_count": 50, "project": "PyYAML"},
    ]}))  # fmt: skip
    assert pypi_extract.download_rank(dump) == {"boto3": 0, "pyyaml": 1, "small-pkg": 2}


def test_priority_puts_the_most_downloaded_package_first(make_advisory: AdvisoryFactory) -> None:
    def advisory(ghsa: str, package: str) -> Any:
        record = make_advisory(id=ghsa, aliases=[])
        affected = record.packages[0].model_copy(update={"name": package})
        return record.model_copy(update={"packages": (affected,)})

    records = [
        advisory("GHSA-aaaa-aaaa-aaaa", "unlisted"),
        advisory("GHSA-bbbb-bbbb-bbbb", "pyyaml"),
        advisory("GHSA-cccc-cccc-cccc", "boto3"),
        advisory("GHSA-dddd-dddd-dddd", "also-unlisted"),
    ]
    groups = alias_groups(records)
    ordered = pypi_extract.by_priority(
        groups, {r.id: r for r in records}, {"boto3": 0, "pyyaml": 1}
    )
    assert [g.key for g in ordered] == [
        "GHSA-cccc-cccc-cccc", "GHSA-bbbb-bbbb-bbbb", "GHSA-aaaa-aaaa-aaaa", "GHSA-dddd-dddd-dddd",
    ]  # fmt: skip


def test_run_keeps_a_given_order(
    stub: dict[str, Any], make_advisory: AdvisoryFactory, tmp_path: Path
) -> None:
    stub["mapping"] = _mapping({"src/some_pkg/a.py": [("f", "function")]})
    client, _ = _client(tmp_path, {"items": [_item("F1", False, [])], "public_entry_points": []})
    records = [make_advisory(id=f"GHSA-aaaa-bbbb-{c * 4}", aliases=[]) for c in "zyx"]
    groups = alias_groups(records)
    given = sorted(groups, key=lambda g: g.key, reverse=True)
    results, _ = pypi_extract.run(
        given, {r.id: r for r in records}, None, None, client, CONFIG, "m", TEMPLATE,  # type: ignore[arg-type]
        CharEstimate(3.0), keep_order=True,
    )  # fmt: skip
    assert [r.vulnerability for r in results] == [g.key for g in given]
