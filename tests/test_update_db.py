"""Incremental updates: unchanged vulnerabilities are carried, changed ones rebuilt."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import SHA_A, AdvisoryFactory
from patchsight import db
from patchsight.pipeline import build_db, update_db
from patchsight.pipeline.diffs.commits import CommitMapping, MappedFile
from patchsight.pipeline.diffs.mapping import ChangedDefinition, FileMapping
from patchsight.pipeline.ingest.aliases import alias_groups

NOW = datetime(2026, 11, 17, tzinfo=UTC)


def _mapping() -> CommitMapping:
    path = "src/some_pkg/loader.py"
    changed = (ChangedDefinition(path=path, name="load", kind="function", sides=("pre",),
                                 hunks=(0,)),)  # fmt: skip
    file = MappedFile(
        mapping=FileMapping(path=path, changed=changed, module_level_hunks=(), parse_errors=False),
        status="modified", previous_path=None, diff_source="github_patch",
    )  # fmt: skip
    return CommitMapping(repo="example/some-pkg", sha=SHA_A, parent="p", files=(file,),
                         skipped=(), truncated=False)  # fmt: skip


@pytest.fixture
def builds(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(
        build_db, "package_repos", lambda g, b, gh, p: (("some-pkg",), {"example/some-pkg"})
    )

    def mapped(gh: object, repo: str, sha: str, include: object) -> CommitMapping:
        calls.append(sha)
        return _mapping()

    monkeypatch.setattr(build_db, "map_commit", mapped)
    return calls


def _advisories(make_advisory: AdvisoryFactory, **changes: dict[str, Any]) -> list[Any]:
    found = []
    for ghsa in ("GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "GHSA-dddd-dddd-dddd"):
        fields: dict[str, Any] = {"id": ghsa, "aliases": []}
        fields.update(changes.get(ghsa, {}))
        if fields.pop("drop", False):
            continue
        found.append(make_advisory(**fields))
    for ghsa, fields in changes.items():
        if fields.get("new"):
            found.append(make_advisory(id=ghsa, aliases=fields.get("aliases", [])))
    return found


def _previous(tmp_path: Path, advisories: list[Any]) -> Path:
    by_id = {a.id: a for a in advisories}
    records, aliases, report = build_db.build(alias_groups(advisories), by_id, None, None, "v1")  # type: ignore[arg-type]
    upgraded = [
        r.model_copy(update={"confidence": "high", "source": "llm", "model": "qwen",
                             "tier_reason": "both models agree (subset)"})
        if r.vulnerability == "GHSA-aaaa-aaaa-aaaa" else r
        for r in records
    ]  # fmt: skip
    path = tmp_path / "previous.sqlite"
    db.write(path, upgraded, aliases, {"db_version": "v1", "builder": "llm-v1"},
             builds=build_db.ledger(report.outcomes))  # fmt: skip
    return path


def test_only_changed_and_new_vulnerabilities_are_rebuilt(
    tmp_path: Path, make_advisory: AdvisoryFactory, builds: list[str]
) -> None:
    previous = db.SymbolDatabase(_previous(tmp_path, _advisories(make_advisory)))
    old_a = previous.records_for("GHSA-aaaa-aaaa-aaaa")
    builds.clear()
    current = _advisories(
        make_advisory,
        **{
            "GHSA-bbbb-bbbb-bbbb": {"details": "Rewritten details."},  # inputs changed
            "GHSA-dddd-dddd-dddd": {"drop": True},  # withdrawn
            "GHSA-cccc-cccc-cccc": {"new": True},  # new
        },
    )
    records, aliases, ledger, report = update_db.update(
        previous, alias_groups(current), {a.id: a for a in current}, None, None, "v2", NOW,  # type: ignore[arg-type]
    )  # fmt: skip
    previous.close()
    assert (report.carried, report.rebuilt, report.new, report.removed) == (1, 1, 1, 1)
    assert report.to_extract == ("GHSA-bbbb-bbbb-bbbb", "GHSA-cccc-cccc-cccc")
    assert len(builds) == 2  # GitHub was asked only about the rebuilt and the new one
    by_vulnerability = {r.vulnerability: r for r in records}
    assert [by_vulnerability["GHSA-aaaa-aaaa-aaaa"]] == old_a  # carried exactly: still LLM
    assert by_vulnerability["GHSA-aaaa-aaaa-aaaa"].confidence == "high"
    assert by_vulnerability["GHSA-bbbb-bbbb-bbbb"].source == "fallback"
    assert "GHSA-dddd-dddd-dddd" not in by_vulnerability
    assert {e.vulnerability for e in ledger} == set(by_vulnerability)
    assert set(aliases.values()) == set(by_vulnerability)


def test_a_carried_vulnerability_gains_new_aliases(
    tmp_path: Path, make_advisory: AdvisoryFactory, builds: list[str]
) -> None:
    previous = db.SymbolDatabase(_previous(tmp_path, _advisories(make_advisory)))
    current = _advisories(make_advisory, **{"GHSA-aaaa-aaaa-aaaa": {"aliases": ["CVE-2099-0001"]}})
    _, aliases, _, report = update_db.update(
        previous, alias_groups(current), {a.id: a for a in current}, None, None, "v2", NOW,  # type: ignore[arg-type]
    )  # fmt: skip
    previous.close()
    assert report.carried == 3  # an alias is not an extraction input
    assert aliases["CVE-2099-0001"] == "GHSA-aaaa-aaaa-aaaa"
    assert (report.aliases_added, report.aliases_removed) == (1, 0)
    assert update_db.changed(report)  # a new alias is worth publishing


def test_a_database_without_a_ledger_cannot_be_updated(
    tmp_path: Path, make_advisory: AdvisoryFactory, builds: list[str]
) -> None:
    path = _previous(tmp_path, _advisories(make_advisory))
    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE builds")
    connection.commit()
    connection.close()
    previous = db.SymbolDatabase(path)
    with pytest.raises(update_db.NoLedgerError, match="build-db"):
        update_db.update(previous, [], {}, None, None, "v2", NOW)  # type: ignore[arg-type]
    previous.close()


def test_vulnerabilities_without_a_record_or_a_github_fix_keep_their_ids(
    tmp_path: Path,
    make_advisory: AdvisoryFactory,
    builds: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One alert per vulnerability, records or not: every vulnerability considered is
    ledgered and its IDs are mapped, including those with no GitHub fix candidate."""
    advisories = _advisories(make_advisory)
    unfixed = make_advisory(
        id="GHSA-eeee-eeee-eeee", aliases=["PYSEC-2099-1"],
        references=[{"type": "WEB", "url": "https://example.org/blog/post"}],
    )  # fmt: skip
    assert not unfixed.fix_candidates
    by_id = {a.id: a for a in [*advisories, unfixed]}
    no_python = alias_groups(advisories)[-1]  # GHSA-dddd: the fix changes no Python code
    monkeypatch.setattr(
        build_db, "fix_mappings",
        lambda g, b, gh, p: build_db.FixMappings(status="no_python_fix", commits=1)
        if g.key == no_python.key else build_db.FixMappings(
            status="mapped", packages=("some-pkg",), mappings=(_mapping(),), commits=1),
    )  # fmt: skip
    records, aliases, report = build_db.build(
        alias_groups(advisories), by_id, None, None, "v1",  # type: ignore[arg-type]
        unfixed=alias_groups([unfixed]),
    )  # fmt: skip
    assert no_python.key not in {r.vulnerability for r in records}
    assert aliases[no_python.key] == no_python.key  # mapped without a record
    assert aliases["PYSEC-2099-1"] == "GHSA-eeee-eeee-eeee"
    statuses = {o.vulnerability: o.status for o in report.outcomes}
    assert statuses["GHSA-eeee-eeee-eeee"] == build_db.NO_GITHUB_FIX
    assert report.groups == 4

    path = tmp_path / "previous.sqlite"
    db.write(path, records, aliases, {"db_version": "v1"}, builds=build_db.ledger(report.outcomes))
    previous = db.SymbolDatabase(path)
    assert previous.build_status("GHSA-eeee-eeee-eeee") == build_db.NO_GITHUB_FIX
    # The advisory gains a GitHub fix: its input hash changes, so it is built.
    fixed = make_advisory(id="GHSA-eeee-eeee-eeee", aliases=["PYSEC-2099-1"])
    current = [*advisories, fixed]
    _, again, ledger, update = update_db.update(
        previous, alias_groups(current), {a.id: a for a in current}, None, None, "v2", NOW,  # type: ignore[arg-type]
    )  # fmt: skip
    previous.close()
    assert update.new == 0
    assert update.rebuilt == 1  # only GHSA-eeee: ledgered before, now with a fix
    assert again["PYSEC-2099-1"] == "GHSA-eeee-eeee-eeee"
    assert {e.vulnerability: e.status for e in ledger}["GHSA-eeee-eeee-eeee"] == "built"


def _referencing() -> CommitMapping:
    path = "src/some_pkg/registry.py"
    referenced = (ChangedDefinition(path=path, name="Registry.load", kind="method",
                                    sides=("pre",), hunks=(0,)),)  # fmt: skip
    file = MappedFile(
        mapping=FileMapping(path=path, changed=(), module_level_hunks=(0,), parse_errors=False,
                            referenced=referenced),
        status="modified", previous_path=None, diff_source="github_patch",
    )  # fmt: skip
    return CommitMapping(repo="example/some-pkg", sha=SHA_A, parent="p", files=(file,),
                         skipped=(), truncated=False)  # fmt: skip


def test_a_module_level_only_fix_is_built_from_the_definitions_it_names(
    tmp_path: Path, make_advisory: AdvisoryFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        build_db, "package_repos", lambda g, b, gh, p: (("some-pkg",), {"example/some-pkg"})
    )
    monkeypatch.setattr(build_db, "map_commit", lambda gh, repo, sha, include: _referencing())
    advisories = [make_advisory(id="GHSA-aaaa-aaaa-aaaa", aliases=[])]
    by_id = {a.id: a for a in advisories}
    group = alias_groups(advisories)[0]
    fixes = build_db.fix_mappings(group, by_id, None, None)  # type: ignore[arg-type]
    assert fixes.status == "module_level_only"  # what extraction sees: no candidates
    assert fixes.mappings == ()
    assert len(fixes.referenced) == 1
    records, outcome = build_db.fallback_records(group, by_id, None, None, NOW)  # type: ignore[arg-type]
    assert outcome.status == build_db.MODULE_LEVEL_REFERENCES
    assert [s.qualified_name for s in records[0].symbols] == ["some_pkg.registry.Registry.load"]
    assert records[0].confidence == "low"

    # A database from before the builder could do this rebuilds those vulnerabilities once.
    old = tmp_path / "old.sqlite"
    ledger = [db.BuildEntry(vulnerability=group.key, input_hash=outcome.input_hash,
                            status="module_level_only")]  # fmt: skip
    db.write(old, [], {group.key: group.key}, {"db_version": "v1"}, builds=ledger)
    previous = db.SymbolDatabase(old)
    rebuilt, _, entries, report = update_db.update(
        previous, [group], by_id, None, None, "v2", NOW,  # type: ignore[arg-type]
    )  # fmt: skip
    previous.close()
    assert (report.rebuilt, len(rebuilt)) == (1, 1)
    assert entries[0].status == build_db.MODULE_LEVEL_REFERENCES
    current = tmp_path / "current.sqlite"
    meta = {"db_version": "v2", "builder_revision": str(build_db.BUILDER_REVISION)}
    db.write(current, [], {group.key: group.key}, meta, builds=ledger)
    previous = db.SymbolDatabase(current)
    _, _, _, again = update_db.update(
        previous, [group], by_id, None, None, "v3", NOW,  # type: ignore[arg-type]
    )  # fmt: skip
    previous.close()
    assert (again.rebuilt, again.carried) == (0, 1)  # at the current revision: not again


def test_statuses_to_rebuild_follow_the_revision() -> None:
    assert build_db.statuses_to_rebuild(1) == {"module_level_only"}
    assert build_db.statuses_to_rebuild(build_db.BUILDER_REVISION) == frozenset()
