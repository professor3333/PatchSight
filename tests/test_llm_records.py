"""LLM extraction merged into database records, with confidence tiers (ADR 0004)."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight import db
from patchsight.db import FixCommitRef, Record, Symbol
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
    )  # fmt: skip


def _merge(primary: Any, secondary: Any = None, fallback: Record | None = None) -> Any:
    records, outcome = llm_records.merge([fallback or _fallback()], primary, secondary)
    return records[0], outcome


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
