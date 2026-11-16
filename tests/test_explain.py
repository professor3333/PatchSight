"""``patchsight explain``: evidence and provenance for an advisory, from the local database."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchsight import db
from patchsight.cli import app
from patchsight.db import FixCommitRef, HunkLocation, Record, Symbol, SymbolEvidence
from patchsight.scan.explain import normalise_identifier

NOW = datetime(2026, 11, 16, tzinfo=UTC)
SHA = "5cd4f1a" + "0" * 33


def _symbol(name: str) -> Symbol:
    return Symbol(qualified_name=f"yaml.constructor.{name}", module="yaml.constructor",
                  name=name, kind="method", path="lib/yaml/constructor.py")  # fmt: skip


def _record(**update: object) -> Record:
    base = Record(
        vulnerability="GHSA-8q59-q68h-6hv4", package="pyyaml", confidence="high", source="llm",
        import_roots=("yaml",), entry_points=("yaml.full_load",),
        symbols=(_symbol("FullConstructor.find_python_name"),),
        fix_commits=(FixCommitRef(repo="yaml/pyyaml", sha=SHA),),
        model="qwen", prompt_version="extract-v1", input_hash="h", advisory_modified=NOW,
        truncated=False, extracted_at=NOW, second_opinion_model="gpt-oss",
        tier_reason="both models agree (subset)",
        evidence=(SymbolEvidence(
            qualified_name="yaml.constructor.FullConstructor.find_python_name",
            rationale="The fix stops arbitrary module imports.",
            hunks=(HunkLocation(commit=SHA, path="lib/yaml/constructor.py", old_start=530,
                                old_count=16, new_start=530, new_count=20),),
        ),),
    )  # fmt: skip
    return base.model_copy(update=update)


@pytest.fixture
def database(tmp_path: Path) -> Path:
    path = tmp_path / "db.sqlite"
    aliases = dict.fromkeys(("GHSA-8q59-q68h-6hv4", "CVE-2020-14343"), "GHSA-8q59-q68h-6hv4")
    db.write(path, [_record()], aliases, {"db_version": "2026.11.14", "builder": "llm-v1"})
    return path


def test_high_record_shows_symbols_rationale_lines_and_provenance(database: Path) -> None:
    result = CliRunner().invoke(app, ["explain", "GHSA-8q59-q68h-6hv4", "--db", str(database)])
    assert result.exit_code == 0, result.output
    out = result.output
    assert out.startswith("GHSA-8q59-q68h-6hv4 (also CVE-2020-14343)")
    assert "pyyaml: HIGH confidence (both models agree (subset))" in out
    assert "extracted by qwen, second opinion gpt-oss; prompt extract-v1" in out
    assert "yaml.constructor.FullConstructor.find_python_name" in out
    assert "why: The fix stops arbitrary module imports." in out
    assert "lib/yaml/constructor.py, lines 530-545 before the fix" in out
    assert f"https://github.com/yaml/pyyaml/commit/{SHA}" in out
    assert "entry points: yaml.full_load" in out
    assert "never IMPORTED, NOT CALLED" not in out  # only said of low confidence


def test_any_alias_in_any_case_finds_the_record(database: Path) -> None:
    result = CliRunner().invoke(app, ["explain", "cve-2020-14343", "--db", str(database)])
    assert result.exit_code == 0, result.output
    assert result.output.startswith("GHSA-8q59-q68h-6hv4")


def test_json_output_carries_the_full_record(database: Path) -> None:
    result = CliRunner().invoke(
        app, ["explain", "CVE-2020-14343", "--db", str(database), "--format", "json"]
    )
    payload = json.loads(result.output)
    assert payload["vulnerability"] == "GHSA-8q59-q68h-6hv4"
    (record,) = payload["records"]
    assert record["confidence"] == "high"
    assert record["evidence"][0]["hunks"][0]["old_start"] == 530


def test_low_fallback_record_says_it_cannot_lower_an_alert(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    fallback = _record(
        confidence="low", source="fallback", model=None, prompt_version=None, entry_points=(),
        second_opinion_model=None, tier_reason=None, evidence=(),
    )  # fmt: skip
    db.write(path, [fallback], {"GHSA-8q59-q68h-6hv4": "GHSA-8q59-q68h-6hv4"}, {})
    result = CliRunner().invoke(app, ["explain", "GHSA-8q59-q68h-6hv4", "--db", str(path)])
    assert "LOW confidence (fallback: every changed definition)" in result.output
    assert "never IMPORTED, NOT CALLED" in result.output
    assert "symbols (1): yaml.constructor.FullConstructor.find_python_name" in result.output


def test_unknown_advisory_exits_1_without_claiming_safety(database: Path) -> None:
    result = CliRunner().invoke(app, ["explain", "GHSA-0000-0000-0000", "--db", str(database)])
    assert result.exit_code == 1
    assert "no symbol data" in result.output
    assert "not evidence of safety" in result.output


def test_missing_database_exits_2(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["explain", "CVE-1", "--db", str(tmp_path / "none")])
    assert result.exit_code == 2


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [("ghsa-8Q59-Q68H-6hv4", "GHSA-8q59-q68h-6hv4"), (" cve-2020-14343 ", "CVE-2020-14343"),
     ("pysec-2021-142", "PYSEC-2021-142")],
)  # fmt: skip
def test_identifiers_are_normalised(raw: str, canonical: str) -> None:
    assert normalise_identifier(raw) == canonical
