import json
import zipfile
from pathlib import Path
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from conftest import SHA_A, SHA_B, RecordFactory
from patchsight.pipeline.ingest.osv import (
    Advisory,
    Excluded,
    Quarantined,
    normalise,
    normalise_dump,
)


def test_valid_record_is_normalised(make_record: RecordFactory) -> None:
    result = normalise(make_record(aliases=["CVE-2", "CVE-1", "CVE-2"]), "x.json")
    assert isinstance(result, Advisory)
    assert result.source == "GHSA"
    assert result.aliases == ("CVE-1", "CVE-2")
    assert [p.name for p in result.packages] == ["some-pkg"]
    assert result.packages[0].raw_name == "Some_Pkg"
    assert [(c.kind, c.repo, c.commit) for c in result.fix_candidates] == [
        ("github_commit", "example/some-pkg", SHA_A)
    ]
    assert result.symbol_hints == ()


def test_withdrawn_record_is_excluded(make_record: RecordFactory) -> None:
    result = normalise(make_record(withdrawn="2026-11-02T00:00:00Z"), "x.json")
    assert result == Excluded(id="GHSA-aaaa-bbbb-cccc", reason="withdrawn")


def test_malicious_package_report_is_excluded(make_record: RecordFactory) -> None:
    result = normalise(make_record(id="MAL-2026-1"), "x.json")
    assert result == Excluded(id="MAL-2026-1", reason="malicious_package")


def test_record_without_pypi_package_is_excluded(make_record: RecordFactory) -> None:
    affected = [{"package": {"ecosystem": "npm", "name": "left-pad"}}]
    result = normalise(make_record(affected=affected), "x.json")
    assert result == Excluded(id="GHSA-aaaa-bbbb-cccc", reason="no_pypi_package")


def test_missing_required_field_is_quarantined(make_record: RecordFactory) -> None:
    record = make_record()
    del record["modified"]
    result = normalise(record, "broken.json")
    assert isinstance(result, Quarantined)
    assert result.source_name == "broken.json"
    assert "modified" in result.reason


def test_wrong_type_is_quarantined(make_record: RecordFactory) -> None:
    result = normalise(make_record(affected="not a list"), "broken.json")
    assert isinstance(result, Quarantined)
    assert "affected" in result.reason


def test_git_range_fixed_commit_becomes_candidate(make_record: RecordFactory) -> None:
    affected = [
        {
            "package": {"ecosystem": "PyPI", "name": "some-pkg"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2"}]},
                {
                    "type": "GIT",
                    "repo": "https://github.com/example/some-pkg",
                    "events": [{"introduced": "0"}, {"fixed": SHA_B}],
                },
            ],
        }
    ]
    result = normalise(make_record(affected=affected, references=[]), "x.json")
    assert isinstance(result, Advisory)
    assert [(c.origin, c.commit) for c in result.fix_candidates] == [("git_range", SHA_B)]
    assert [r.type for r in result.packages[0].ranges] == ["ECOSYSTEM"]


def test_repeated_reference_is_deduplicated(make_record: RecordFactory) -> None:
    url = f"https://github.com/example/some-pkg/commit/{SHA_A}"
    references = [{"type": "FIX", "url": url}, {"type": "FIX", "url": url}]
    result = normalise(make_record(references=references), "x.json")
    assert isinstance(result, Advisory)
    assert len(result.fix_candidates) == 1


def test_upstream_symbol_data_is_kept(make_record: RecordFactory) -> None:
    imports = [{"attribute": "load", "modules": ["somepkg.loader"]}]
    affected = [
        {
            "package": {"ecosystem": "PyPI", "name": "Some_Pkg"},
            "ecosystem_specific": {"imports": imports},
        }
    ]
    result = normalise(make_record(affected=affected), "x.json")
    assert isinstance(result, Advisory)
    assert [(h.field, h.package, h.value) for h in result.symbol_hints] == [
        ("imports", "some-pkg", imports)
    ]


def test_only_pypi_packages_are_kept(make_record: RecordFactory) -> None:
    affected = [
        {"package": {"ecosystem": "npm", "name": "left-pad"}},
        {"package": {"ecosystem": "PyPI", "name": "Some_Pkg"}},
    ]
    result = normalise(make_record(affected=affected), "x.json")
    assert isinstance(result, Advisory)
    assert [p.name for p in result.packages] == ["some-pkg"]


def test_normalise_dump_handles_bad_members(tmp_path: Path, make_record: RecordFactory) -> None:
    dump = tmp_path / "all.zip"
    with zipfile.ZipFile(dump, "w") as archive:
        archive.writestr("c.json", json.dumps(make_record(id="PYSEC-2099-1")))
        archive.writestr("a.json", "{not json")
        archive.writestr("b.json", "[1, 2]")
    results = list(normalise_dump(dump))
    assert [type(r) for r in results] == [Quarantined, Quarantined, Advisory]
    assert isinstance(results[0], Quarantined)
    assert results[0].reason.startswith("invalid JSON")
    assert isinstance(results[1], Quarantined)
    assert results[1].reason == "top-level JSON value is not an object"


_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=10),
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=10), children, max_size=3)
    ),
    max_leaves=10,
)


@given(
    st.dictionaries(
        st.sampled_from(["id", "modified", "affected", "references", "aliases", "withdrawn"]),
        _json,
    )
)
def test_normalise_never_raises(raw: dict[str, Any]) -> None:
    assert isinstance(normalise(raw, "fuzz.json"), Advisory | Excluded | Quarantined)
