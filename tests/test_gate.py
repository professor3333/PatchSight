"""The release gate: a candidate database passes only if every check holds."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchsight import db
from patchsight.db import BuildEntry, FixCommitRef, Record, Symbol
from patchsight.pipeline import gate
from patchsight.pipeline.__main__ import app

NOW = datetime(2026, 11, 17, tzinfo=UTC)


def _record(vulnerability: str, confidence: str = "low", symbols: int = 1) -> Record:
    return Record(
        vulnerability=vulnerability, package="pkg", confidence=confidence,  # type: ignore[arg-type]
        source="llm" if confidence == "high" else "fallback", import_roots=("pkg",),
        entry_points=(),
        symbols=tuple(Symbol(qualified_name=f"pkg.f{i}", module="pkg", name=f"f{i}",
                             kind="function", path="pkg/__init__.py") for i in range(symbols)),
        fix_commits=(FixCommitRef(repo="o/pkg", sha="a" * 40),), model=None,
        prompt_version=None, input_hash="h", advisory_modified=NOW, truncated=False,
        extracted_at=NOW,
    )  # fmt: skip


def _write(
    path: Path, records: list[Record], hashes: dict[str, str] | None = None,
    aliases: dict[str, str] | None = None, ledger: bool = True,
) -> Path:  # fmt: skip
    keys = {r.vulnerability for r in records}
    builds = [
        BuildEntry(vulnerability=k, input_hash=(hashes or {}).get(k, "h"), status="built")
        for k in sorted(keys)
    ]
    db.write(path, records, aliases if aliases is not None else {k: k for k in keys},
             {"db_version": path.stem}, builds=builds if ledger else ())  # fmt: skip
    return path


def _run(tmp_path: Path, new: list[Record], old: list[Record], **kw: object) -> gate.GateReport:
    candidate = db.SymbolDatabase(_write(tmp_path / "new.sqlite", new, **kw))  # type: ignore[arg-type]
    previous = db.SymbolDatabase(_write(tmp_path / "old.sqlite", old))
    try:
        return gate.run(candidate, previous)
    finally:
        candidate.close()
        previous.close()


def _failed(report: gate.GateReport) -> set[str]:
    return {c.name for c in report.checks if not c.passed}


def test_a_healthy_candidate_passes(tmp_path: Path) -> None:
    records = [_record(f"GHSA-{i:04d}") for i in range(20)]
    report = _run(tmp_path, records, records)
    assert report.passed
    assert _failed(report) == set()


def test_mass_loss_fails_but_a_few_withdrawals_pass(tmp_path: Path) -> None:
    before = [_record(f"GHSA-{i:04d}") for i in range(100)]
    assert _run(tmp_path, before[10:], before).passed  # 10 lost: the minimum allowed
    assert _failed(_run(tmp_path, before[11:], before)) == {"no_mass_loss"}


def test_records_without_ledger_entries_or_symbols_fail(tmp_path: Path) -> None:
    records = [_record("GHSA-0001"), _record("GHSA-0002", symbols=0)]
    assert _failed(_run(tmp_path, records, records)) == {"symbols"}
    assert "ledger" in _failed(_run(tmp_path, records[:1], records[:1], ledger=False))


def test_aliases_must_reach_every_record_and_nothing_else(tmp_path: Path) -> None:
    records = [_record("GHSA-0001")]
    report = _run(tmp_path, records, records, aliases={"CVE-1": "GHSA-0001", "CVE-2": "GHSA-9"})
    assert _failed(report) == {"aliases"}
    detail = next(c.detail for c in report.checks if c.name == "aliases")
    assert "GHSA-0001" in detail  # not found by its own ID
    assert "CVE-2" in detail  # points at nothing


def test_an_unchanged_high_record_must_stay_high(tmp_path: Path) -> None:
    old = [_record("GHSA-0001", confidence="high")]
    assert _failed(_run(tmp_path, [_record("GHSA-0001")], old)) == {"high_kept"}
    changed = _run(tmp_path, [_record("GHSA-0001")], old, hashes={"GHSA-0001": "new"})
    assert changed.passed  # its inputs changed, so a fallback record is expected


@pytest.mark.parametrize(("lost", "code"), [(0, 0), (20, 1)])
def test_gate_db_exit_code_and_report(tmp_path: Path, lost: int, code: int) -> None:
    before = [_record(f"GHSA-{i:04d}") for i in range(30)]
    _write(tmp_path / "old.sqlite", before)
    _write(tmp_path / "new.sqlite", before[lost:])
    result = CliRunner().invoke(app, [
        "gate-db", "new.sqlite", "--previous", "old.sqlite", "--root", str(tmp_path),
        "--out", "gate",
    ])  # fmt: skip
    assert result.exit_code == code, result.output
    assert (
        (tmp_path / "gate.md")
        .read_text()
        .startswith("# Release gate PASSED" if code == 0 else "# Release gate FAILED")
    )


def test_release_notes_carry_changes_gate_provenance_and_attribution(tmp_path: Path) -> None:
    import json

    from patchsight.pipeline.update_db import UpdateReport

    records = [_record("GHSA-0001", confidence="high"), _record("GHSA-0002")]
    path = tmp_path / "db.sqlite"
    db.write(path, records, {"GHSA-0001": "GHSA-0001", "GHSA-0002": "GHSA-0002"},
             {"db_version": "2026.11.18", "updated_from": "2026.11.17", "builder": "llm-v1",
              "code_commit": "abc", "snapshot_sha256": "def"})  # fmt: skip
    (tmp_path / "latest.json").write_text(json.dumps({
        "db_version": "2026.11.18", "schema_version": db.SCHEMA_VERSION, "url": "https://x/y.gz",
        "sha256": "f" * 64, "size": 1, "built_at": NOW.isoformat(), "records": 2,
    }))  # fmt: skip
    update = UpdateReport(previous_version="2026.11.17", db_version="2026.11.18", carried=1,
                          rebuilt=1, new=0, removed=0, status={"built": 1},
                          to_extract=("GHSA-0002",))  # fmt: skip
    (tmp_path / "update.json").write_text(update.model_dump_json())
    gate_report = _run(tmp_path, records, records)
    (tmp_path / "gate.json").write_text(gate_report.model_dump_json())
    result = CliRunner().invoke(app, [
        "release-notes", "db.sqlite", "--pointer", "latest.json", "--update", "update.json",
        "--gate", "gate.json", "--root", str(tmp_path), "--out", "notes.md",
    ])  # fmt: skip
    assert result.exit_code == 0, result.output
    notes = (tmp_path / "notes.md").read_text()
    assert notes.startswith("Symbol database **2026.11.18**, updated from 2026.11.17.")
    assert "1 high confidence, 1 low confidence" in notes
    assert "1 carried unchanged, 1 rebuilt, 0 new, 0 removed" in notes
    assert "## Release gate: passed" in notes
    assert f"Asset SHA-256: `{'f' * 64}`" in notes
    assert "CC BY 4.0" in notes
    assert "No third-party source code is included." in notes
