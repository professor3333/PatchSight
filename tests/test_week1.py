import json
import zipfile
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from conftest import SHA_A, AdvisoryFactory, RecordFactory
from patchsight.pipeline import week1
from patchsight.pipeline.__main__ import app
from patchsight.pipeline.ingest import ghsa_repo, snapshot
from patchsight.pipeline.ingest.osv import Excluded, Quarantined

AS_OF = datetime(2026, 11, 14, tzinfo=UTC)


def test_wilson_interval() -> None:
    assert week1.wilson(0, 0).share == 0.0
    half = week1.wilson(50, 100)
    assert half.share == 0.5
    assert half.ci95_low == pytest.approx(0.4038, abs=1e-3)
    assert half.ci95_high == pytest.approx(0.5962, abs=1e-3)


@given(st.integers(0, 500).flatmap(lambda n: st.tuples(st.integers(0, n), st.just(n))))
def test_wilson_bounds_contain_the_share(pair: tuple[int, int]) -> None:
    count, total = pair
    s = week1.wilson(count, total)
    assert 0.0 <= s.ci95_low <= s.share <= s.ci95_high <= 1.0


def test_daily_rate_counts_empty_days() -> None:
    start, end = date(2026, 1, 1), date(2026, 1, 11)
    days = [date(2026, 1, 2), date(2026, 1, 2), date(2026, 1, 5), date(2025, 12, 31)]
    rate = week1.daily_rate(days, start, end)
    assert (rate.days, rate.total, rate.max) == (10, 3, 2)
    assert rate.mean == pytest.approx(0.3)
    assert rate.median == 0


def _results(make_advisory: AdvisoryFactory) -> list[week1.Advisory | Excluded | Quarantined]:
    return [
        # One vulnerability with a GitHub fix link, reported twice.
        make_advisory(id="GHSA-0001-0001-0001", aliases=["CVE-2099-1"]),
        make_advisory(id="PYSEC-2099-1", aliases=["CVE-2099-1"], references=[]),
        # One with no fix link, carrying upstream symbol data.
        make_advisory(
            id="PYSEC-2099-2",
            aliases=[],
            references=[],
            affected=[
                {
                    "package": {"ecosystem": "PyPI", "name": "other"},
                    "ecosystem_specific": {"imports": [{"attribute": "f", "modules": ["m"]}]},
                }
            ],
        ),
        Excluded(id="MAL-2026-1", reason="malicious_package"),
        Quarantined(source_name="bad.json", reason="invalid JSON"),
    ]


def test_build_report_counts_per_vulnerability(make_advisory: AdvisoryFactory) -> None:
    report = week1.build_report(_results(make_advisory), as_of=AS_OF)
    assert report.records_total == 5
    assert report.records_by_source == {"GHSA": 1, "MAL": 1, "PYSEC": 2, "unreadable": 1}
    assert report.excluded == {"malicious_package": 1}
    assert report.quarantined == 1
    assert (report.advisories_in_scope, report.vulnerabilities, report.packages) == (3, 2, 2)
    assert (report.fix_link_github.count, report.fix_link_github.total) == (1, 2)
    assert report.fix_link_strong.count == 1
    assert report.fix_link_by_kind == {"github_commit": 1}
    assert report.symbol_data_osv_ids == ("PYSEC-2099-2",)
    assert report.gate_passed  # 50% >= 40%
    assert report.new_per_day_365.total == 2


def test_gate_fails_below_threshold(make_advisory: AdvisoryFactory) -> None:
    results = [make_advisory(id=f"PYSEC-2099-{i}", aliases=[], references=[]) for i in range(1, 4)]
    results.append(make_advisory(id="GHSA-0009-0009-0009", aliases=[]))
    report = week1.build_report(results, as_of=AS_OF)
    assert report.gate_metric.share == 0.25
    assert not report.gate_passed
    assert "**FAIL.**" in week1.render_markdown(report, [])


def test_markdown_reports_the_gate(make_advisory: AdvisoryFactory) -> None:
    report = week1.build_report(_results(make_advisory), as_of=AS_OF)
    text = week1.render_markdown(report, ["- `dump`: pinned"])
    assert "**PASS.**" in text
    assert "50.0% (1 / 2;" in text
    assert "- `dump`: pinned" in text
    assert "PYSEC-2099-2" in text


def test_ghsa_scan_finds_symbol_data(tmp_path: Path, make_advisory: AdvisoryFactory) -> None:
    with_data = make_advisory(id="GHSA-0001-0001-0001")
    without = make_advisory(id="GHSA-0002-0002-0002")
    missing = make_advisory(id="GHSA-0003-0003-0003")
    for advisory, specific in ((with_data, {"affected_functions": ["m.f"]}), (without, {})):
        directory = ghsa_repo.ghsa_directory(advisory)
        assert directory == f"advisories/github-reviewed/2026/10/{advisory.id}"
        path = tmp_path / directory / f"{advisory.id}.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"affected": [{"ecosystem_specific": specific}]}))
    pysec = make_advisory(id="PYSEC-2099-1")
    assert ghsa_repo.ghsa_directory(pysec) is None

    scan = ghsa_repo.scan(tmp_path, [with_data, without, missing, pysec])
    assert (scan.expected, scan.found) == (3, 2)
    assert scan.missing == ("GHSA-0003-0003-0003",)
    assert scan.with_symbol_data == ("GHSA-0001-0001-0001",)


def test_week1_report_command_end_to_end(tmp_path: Path, make_record: RecordFactory) -> None:
    dump = tmp_path / "data" / "raw" / "osv-pypi" / "all.zip"
    dump.parent.mkdir(parents=True)
    with zipfile.ZipFile(dump, "w") as archive:
        archive.writestr("GHSA-0001-0001-0001.json", json.dumps(make_record()))
        archive.writestr(
            "PYSEC-2099-1.json",
            json.dumps(make_record(id="PYSEC-2099-1", aliases=[], references=[])),
        )
    entry = snapshot.SourceFile(
        name="osv-pypi-all",
        url="https://example.org/all.zip",
        path="data/raw/osv-pypi/all.zip",
        sha256=snapshot.sha256_file(dump),
        size=dump.stat().st_size,
        last_modified=None,
        retrieved_at=AS_OF,
    )
    snapshot.save_manifest(
        snapshot.SnapshotManifest().with_file(entry), tmp_path / "manifests" / "snapshot.json"
    )

    result = CliRunner().invoke(app, ["week1-report", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "gate PASS: 50.0%" in result.output
    report = json.loads((tmp_path / "docs/reports/week1-data-gate.json").read_text())
    assert report["vulnerabilities"] == 2
    assert f"SHA-256 `{entry.sha256}`" in (tmp_path / "docs/reports/week1-data-gate.md").read_text()
    assert SHA_A not in (tmp_path / "docs/reports/week1-data-gate.md").read_text()


def test_week1_report_refuses_a_changed_dump(tmp_path: Path) -> None:
    dump = tmp_path / "data" / "raw" / "osv-pypi" / "all.zip"
    dump.parent.mkdir(parents=True)
    dump.write_bytes(b"changed")
    entry = snapshot.SourceFile(
        name="osv-pypi-all",
        url="https://example.org/all.zip",
        path="data/raw/osv-pypi/all.zip",
        sha256="0" * 64,
        size=7,
        last_modified=None,
        retrieved_at=AS_OF,
    )
    snapshot.save_manifest(
        snapshot.SnapshotManifest().with_file(entry), tmp_path / "manifests" / "snapshot.json"
    )
    result = CliRunner().invoke(app, ["week1-report", "--root", str(tmp_path)])
    assert result.exit_code != 0
    assert isinstance(result.exception, snapshot.SnapshotMismatchError)


def test_report_names_with_dots_keep_their_full_name(
    tmp_path: Path, make_record: RecordFactory
) -> None:
    dump = tmp_path / "data" / "raw" / "osv-pypi" / "all.zip"
    dump.parent.mkdir(parents=True)
    with zipfile.ZipFile(dump, "w") as archive:
        archive.writestr("a.json", json.dumps(make_record()))
    entry = snapshot.SourceFile(
        name="osv-pypi-all", url="u", path="data/raw/osv-pypi/all.zip",
        sha256=snapshot.sha256_file(dump), size=dump.stat().st_size, last_modified=None,
        retrieved_at=AS_OF,
    )  # fmt: skip
    snapshot.save_manifest(
        snapshot.SnapshotManifest().with_file(entry), tmp_path / "manifests" / "snapshot.json"
    )
    out = "docs/reports/run-qwen3.8-27b"
    result = CliRunner().invoke(app, ["week1-report", "--root", str(tmp_path), "--out", out])
    assert result.exit_code == 0, result.output
    assert (tmp_path / f"{out}.json").exists()
    assert (tmp_path / f"{out}.md").exists()
