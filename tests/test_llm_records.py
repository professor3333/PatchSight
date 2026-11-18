"""LLM extraction merged into database records, with confidence tiers (ADR 0004)."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight import db
from patchsight.db import FixCommitRef, HunkLocation, Record, Symbol, SymbolEvidence
from patchsight.pipeline import llm_records
from patchsight.pipeline.extract.extractor import ExtractionOutcome
from patchsight.pipeline.pypi_extract import PyPIExtraction, qualify_entry_points

NOW = datetime(2026, 11, 16, tzinfo=UTC)
NAMES = ("load", "Loader.read", "_helper", "dump")


def _symbol(name: str) -> Symbol:
    return Symbol(qualified_name=f"pkg.mod.{name}", module="pkg.mod", name=name,
                  kind="function", path="src/pkg/mod.py")  # fmt: skip


def _fallback(names: tuple[str, ...] = NAMES, digest: str = "h1") -> Record:
    return Record(
        vulnerability="GHSA-xxxx-yyyy-zzzz", package="pkg", confidence="low", source="fallback",
        import_roots=("pkg",), entry_points=(), symbols=tuple(_symbol(n) for n in names),
        fix_commits=(FixCommitRef(repo="o/pkg", sha="a" * 40),), model=None,
        prompt_version=None, input_hash=digest, advisory_modified=NOW, truncated=False,
        extracted_at=NOW,
    )  # fmt: skip


def _extraction(
    vulnerable: tuple[str, ...], *, status: str = "ok", model: str = "qwen",
    truncated: bool = False, entry: tuple[str, ...] = (), digest: str = "h1",
) -> PyPIExtraction:  # fmt: skip
    outcome: dict[str, Any] = {
        "advisory_id": "GHSA-xxxx-yyyy-zzzz",
        "status": status,
        "model": model,
        "prompt_version": "extract-v1",
        "candidates": len(NAMES),
        "vulnerable": vulnerable,
        "entry_points": (),
        "entry_points_dropped": 0,
        "invented_ids_first_attempt": 0,
        "errors": (),
        "truncated": truncated,
        "dropped_candidates": (),
        "estimated_prompt_tokens": 100,
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "calls": 1,
        "cached_calls": 0,
        "provider_rejections": 0,
    }
    return PyPIExtraction(
        vulnerability="GHSA-xxxx-yyyy-zzzz", packages=("pkg",), input_hash=digest,
        fix_commits=(), vulnerable_symbols=tuple(_symbol(n) for n in vulnerable),
        entry_points=entry, outcome=ExtractionOutcome(**outcome),
        evidence=tuple(_evidence(n, model) for n in vulnerable),
    )  # fmt: skip


def _evidence(name: str, model: str) -> SymbolEvidence:
    hunk = HunkLocation(commit="a" * 40, path="src/pkg/mod.py", old_start=10, old_count=3,
                        new_start=10, new_count=4)  # fmt: skip
    return SymbolEvidence(qualified_name=f"pkg.mod.{name}", rationale=f"{model} says so.",
                          hunks=(hunk,))  # fmt: skip


def _merge(
    primary: Any, secondary: Any = None, fallback: Record | None = None, publish_high: bool = True
) -> Any:
    """The rule's own mechanics, with the tier published (ADR 0008 withholds it by default)."""
    records, outcome = llm_records.merge(
        [fallback or _fallback()], primary, secondary, publish_high=publish_high
    )
    return records[0], outcome


def test_high_confidence_is_withheld_by_default() -> None:
    assert llm_records.PUBLISH_HIGH is False  # changing this needs a new ADR (ADR 0008)
    primary = _extraction(("load",), entry=("pkg.full_load",))
    secondary = _extraction(("load", "Loader.read"), model="gpt-oss")
    records, outcome = llm_records.merge([_fallback()], primary, secondary)
    (record,) = records
    reason = f"{llm_records.WITHHELD}: both models agree (subset)"
    assert outcome == f"low: {reason}"
    assert (record.confidence, record.source, record.tier_reason) == ("low", "llm", reason)
    assert record.symbols == _fallback().symbols  # every changed definition, as for any low
    assert record.second_opinion_model == "gpt-oss"
    assert record.entry_points == ("pkg.full_load",)
    merged, outcomes = llm_records.apply([_fallback()], {primary.vulnerability: primary},
                                         {secondary.vulnerability: secondary})  # fmt: skip
    assert [r.confidence for r in merged] == ["low"]
    assert outcomes == {f"low: {reason}": 1}


def test_no_extraction_keeps_the_fallback() -> None:
    record, outcome = _merge(None)
    assert (record, outcome) == (_fallback(), "fallback: no extraction")


@pytest.mark.parametrize(
    ("primary", "expected"),
    [
        (_extraction(("load",), digest="old"), "fallback: extraction made from older inputs"),
        (_extraction((), status="dead_letter"), "fallback: extraction failed validation"),
    ],
)
def test_unusable_extractions_keep_the_fallback(primary: PyPIExtraction, expected: str) -> None:
    record, outcome = _merge(primary)
    assert (record, outcome) == (_fallback(), expected)


def test_agreement_with_a_public_symbol_is_high_and_keeps_only_agreed_symbols() -> None:
    record, outcome = _merge(
        _extraction(("load",), entry=("pkg.full_load",)),
        _extraction(("load", "Loader.read"), model="gpt-oss"),
    )
    assert outcome == "high: both models agree (subset)"
    assert (record.confidence, record.source) == ("high", "llm")
    assert [s.name for s in record.symbols] == ["Loader.read", "load"]
    assert record.entry_points == ("pkg.full_load",)
    assert (record.model, record.second_opinion_model) == ("qwen", "gpt-oss")
    assert (record.prompt_version, record.tier_reason) == ("extract-v1", outcome[6:])


@pytest.mark.parametrize(
    ("primary", "secondary", "reason"),
    [
        (_extraction(("load",), entry=("pkg.full_load",)), None, "no valid second opinion"),
        (_extraction(("load",)), _extraction(("dump",), model="g"), "the two models disagree"),
        (_extraction(("_helper",)), _extraction(("_helper",), model="g"),
         "no public symbol among the agreed answers"),
        (_extraction(("load",), truncated=True), _extraction(("load",), model="g"),
         "prompt truncated to the token budget"),
        (_extraction(("load",)), _extraction(("load",), model="g", digest="old"),
         "no valid second opinion"),
    ],
)  # fmt: skip
def test_anything_else_is_low_with_every_changed_definition(
    primary: PyPIExtraction, secondary: PyPIExtraction | None, reason: str
) -> None:
    record, outcome = _merge(primary, secondary)
    assert outcome == f"low: {reason}"
    assert (record.confidence, record.source, record.tier_reason) == ("low", "llm", reason)
    assert record.symbols == _fallback().symbols  # never fewer than the fallback
    assert set(primary.entry_points) <= set(record.entry_points)


@given(
    st.frozensets(st.sampled_from(NAMES)),
    st.frozensets(st.sampled_from(NAMES)),
    st.booleans(),
    st.sampled_from(["ok", "repaired", "dead_letter"]),
)
def test_a_record_never_loses_a_symbol_unless_it_is_high(
    first: frozenset[str], second: frozenset[str], truncated: bool, status: str
) -> None:
    record, _ = _merge(
        _extraction(tuple(sorted(first)), status=status, truncated=truncated),
        _extraction(tuple(sorted(second)), model="g"),
    )
    if record.confidence == "low":
        assert set(_fallback().symbols) <= set(record.symbols)
    else:
        assert {s.name for s in record.symbols} == first | second


@pytest.mark.parametrize(
    ("extraction", "needed"),
    [
        (_extraction(("load",)), True),
        (_extraction(("_helper",), entry=("pkg.full_load",)), True),
        (_extraction(("_helper",)), False),
        (_extraction(()), False),
        (_extraction(("load",), truncated=True), False),
        (_extraction((), status="dead_letter"), False),
    ],
)
def test_second_opinion_only_where_it_can_lift_the_tier(
    extraction: PyPIExtraction, needed: bool
) -> None:
    assert llm_records.needs_second_opinion(extraction) is needed


def test_entry_points_are_module_qualified_by_their_defining_file() -> None:
    from patchsight.pipeline.diffs.commits import CommitMapping, MappedFile
    from patchsight.pipeline.diffs.mapping import FileMapping

    def file(path: str, names: tuple[str, ...]) -> MappedFile:
        mapping = FileMapping(path=path, changed=(), module_level_hunks=(), parse_errors=False,
                              known_names=names)  # fmt: skip
        return MappedFile(mapping=mapping, status="modified", previous_path=None,
                          diff_source="github_patch")  # fmt: skip

    mapping = CommitMapping(
        repo="o/r", sha="a" * 40, parent="p", skipped=(), truncated=False,
        files=(file("lib/yaml/__init__.py", ("full_load", "load")),
               file("scripts/run-me.py", ("main",))),
    )  # fmt: skip
    assert qualify_entry_points(["full_load", "main"], [mapping]) == ("main", "yaml.full_load")


def test_extraction_provenance_round_trips_and_old_files_still_read(tmp_path: Path) -> None:
    high, _ = _merge(_extraction(("load",)), _extraction(("load",), model="gpt-oss"))
    path = tmp_path / "db.sqlite"
    db.write(path, [high], {"GHSA-xxxx-yyyy-zzzz": "GHSA-xxxx-yyyy-zzzz"}, {"db_version": "x"})
    reader = db.SymbolDatabase(path)
    stored = reader.record("GHSA-xxxx-yyyy-zzzz", "pkg")
    reader.close()
    assert stored is not None
    assert (stored.second_opinion_model, stored.tier_reason) == ("gpt-oss", high.tier_reason)

    # A database written before the extraction table existed still reads, without provenance.
    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE extraction")
    connection.commit()
    connection.close()
    reader = db.SymbolDatabase(path)
    old = reader.record("GHSA-xxxx-yyyy-zzzz", "pkg")
    reader.close()
    assert old is not None
    assert (old.confidence, old.second_opinion_model, old.tier_reason) == ("high", None, None)


def test_high_records_keep_evidence_for_the_agreed_symbols() -> None:
    record, _ = _merge(_extraction(("load",)), _extraction(("load", "Loader.read"), model="g"))
    assert [(e.qualified_name, e.rationale) for e in record.evidence] == [
        ("pkg.mod.Loader.read", "g says so."),  # only the second model flagged it
        ("pkg.mod.load", "qwen says so."),  # the extractor's own rationale comes first
    ]


def test_low_records_keep_the_models_picks_as_evidence() -> None:
    record, _ = _merge(_extraction(("load",)))
    assert record.confidence == "low"
    assert [e.qualified_name for e in record.evidence] == ["pkg.mod.load"]
    assert {e.qualified_name for e in record.evidence} <= {s.qualified_name for s in record.symbols}


def test_evidence_round_trips_and_old_files_still_read(tmp_path: Path) -> None:
    record, _ = _merge(_extraction(("load",)), _extraction(("load",), model="g"))
    path = tmp_path / "db.sqlite"
    db.write(path, [record], {}, {"db_version": "x"})
    reader = db.SymbolDatabase(path)
    stored = reader.record(record.vulnerability, record.package)
    reader.close()
    assert stored is not None
    assert stored.evidence == record.evidence

    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE evidence")
    connection.commit()
    connection.close()
    reader = db.SymbolDatabase(path)
    old = reader.record(record.vulnerability, record.package)
    reader.close()
    assert old is not None
    assert old.evidence == ()


def test_a_high_record_is_never_re_merged() -> None:
    high, _ = _merge(_extraction(("load",)), _extraction(("load",), model="g"))
    again, outcome = llm_records.merge([high], _extraction(("dump",)), None)
    assert (again, outcome) == ([high], "kept: already high confidence")


def test_merge_llm_upgrades_a_published_database(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from patchsight.db import BuildEntry
    from patchsight.pipeline.__main__ import app

    other = _fallback().model_copy(update={"vulnerability": "GHSA-kept-high-0000",
                                           "confidence": "high", "source": "llm"})  # fmt: skip
    db.write(
        tmp_path / "current.sqlite", [_fallback(), other],
        {"GHSA-xxxx-yyyy-zzzz": "GHSA-xxxx-yyyy-zzzz", "CVE-1": "GHSA-xxxx-yyyy-zzzz",
         "GHSA-kept-high-0000": "GHSA-kept-high-0000"},
        {"db_version": "2026.11.17", "builder": "llm-v1", "updated_from": "2026.11.16"},
        builds=[BuildEntry(vulnerability="GHSA-xxxx-yyyy-zzzz", input_hash="h1", status="built"),
                BuildEntry(vulnerability="GHSA-kept-high-0000", input_hash="h1", status="built")],
    )  # fmt: skip
    (tmp_path / "shard.jsonl").write_text(_extraction(("load",)).model_dump_json() + "\n")
    (tmp_path / "second.jsonl").write_text(
        _extraction(("load",), model="gpt-oss").model_dump_json() + "\n"
    )
    result = CliRunner().invoke(app, [
        "merge-llm", "current.sqlite", "--version", "2026.11.17.1", "--llm", "shard.jsonl",
        "--second", "second.jsonl", "--root", str(tmp_path), "--out", "merged",
    ])  # fmt: skip
    assert result.exit_code == 0, result.output
    merged = db.SymbolDatabase(tmp_path / "merged.sqlite")
    try:
        assert merged.meta["db_version"] == "2026.11.17.1"
        assert merged.meta["merged_into"] == "2026.11.17"
        assert "updated_from" not in merged.meta  # the source's origin, not this build's
        upgraded = merged.record("GHSA-xxxx-yyyy-zzzz", "pkg")
        assert upgraded is not None
        # The pair agrees, but ADR 0008 withholds the tier: low, with the second opinion kept.
        assert (upgraded.confidence, upgraded.second_opinion_model) == ("low", "gpt-oss")
        assert (upgraded.tier_reason or "").startswith(llm_records.WITHHELD)
        before = db.SymbolDatabase(tmp_path / "current.sqlite")
        assert merged.record("GHSA-kept-high-0000", "pkg") == before.record(
            "GHSA-kept-high-0000", "pkg"
        )  # untouched
        before.close()
        assert merged.alias_map()["CVE-1"] == "GHSA-xxxx-yyyy-zzzz"
        assert set(merged.build_ledger()) == {"GHSA-xxxx-yyyy-zzzz", "GHSA-kept-high-0000"}
    finally:
        merged.close()
    report = llm_records.MergeReport.model_validate_json(
        (tmp_path / "merged-merge.json").read_text()
    )
    assert (report.previous_version, report.db_version) == ("2026.11.17", "2026.11.17.1")
    assert (report.models, report.second_opinion_models) == (("qwen",), ("gpt-oss",))
    assert report.prompt_versions == ("extract-v1",)
    assert report.before == llm_records.Picks(vulnerabilities=1, records=1)
    assert report.after == llm_records.Picks(vulnerabilities=2, records=2)
    assert report.tiers == {"high": 1, "low": 1}  # only the record that was already high
    assert sum(report.outcomes.values()) == 2  # one outcome per vulnerability
