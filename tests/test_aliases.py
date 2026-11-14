from hypothesis import given
from hypothesis import strategies as st

from conftest import AdvisoryFactory
from patchsight.pipeline.ingest.aliases import alias_groups, first_published
from patchsight.pipeline.ingest.osv import Advisory


def _advisories(make_advisory: AdvisoryFactory) -> list[Advisory]:
    return [
        make_advisory(id="GHSA-0001-0001-0001", aliases=["CVE-2099-1"]),
        make_advisory(id="PYSEC-2099-1", aliases=["CVE-2099-1", "GHSA-0001-0001-0001"]),
        make_advisory(id="PYSEC-2099-2", aliases=["CVE-2099-2"], published="2026-01-01T00:00:00Z"),
        make_advisory(id="GHSA-0002-0002-0002", aliases=["CVE-2099-2", "CVE-2099-3"]),
        make_advisory(id="PYSEC-2099-3", aliases=["CVE-2099-3"]),
        make_advisory(id="GHSA-0003-0003-0003", aliases=[]),
    ]


def test_shared_identifiers_merge_transitively(make_advisory: AdvisoryFactory) -> None:
    groups = alias_groups(_advisories(make_advisory))
    assert [g.advisory_ids for g in groups] == [
        ("GHSA-0001-0001-0001", "PYSEC-2099-1"),
        ("GHSA-0002-0002-0002", "PYSEC-2099-2", "PYSEC-2099-3"),
        ("GHSA-0003-0003-0003",),
    ]
    assert [g.key for g in groups] == [g.advisory_ids[0] for g in groups]
    assert "CVE-2099-3" in groups[1].identifiers


def test_first_published_is_the_earliest(make_advisory: AdvisoryFactory) -> None:
    advisories = _advisories(make_advisory)
    by_id = {a.id: a for a in advisories}
    group = alias_groups(advisories)[1]
    published = first_published(group, by_id)
    assert published is not None
    assert published.isoformat() == "2026-01-01T00:00:00+00:00"


@given(st.randoms(use_true_random=False))
def test_grouping_is_independent_of_input_order(rng: object) -> None:
    # Built inline because Hypothesis cannot reuse function-scoped fixtures.
    from patchsight.pipeline.ingest.osv import normalise

    def advisory(advisory_id: str, aliases: list[str]) -> Advisory:
        record = {
            "id": advisory_id,
            "modified": "2026-11-01T00:00:00Z",
            "aliases": aliases,
            "affected": [{"package": {"ecosystem": "PyPI", "name": "p"}}],
        }
        result = normalise(record, "x.json")
        assert isinstance(result, Advisory)
        return result

    items = [
        advisory("GHSA-1", ["CVE-1"]),
        advisory("PYSEC-1", ["CVE-1"]),
        advisory("PYSEC-2", ["CVE-2"]),
        advisory("GHSA-2", ["CVE-2", "CVE-3"]),
        advisory("GHSA-3", []),
    ]
    expected = alias_groups(items)
    shuffled = list(items)
    rng.shuffle(shuffled)  # type: ignore[attr-defined]
    assert alias_groups(shuffled) == expected
