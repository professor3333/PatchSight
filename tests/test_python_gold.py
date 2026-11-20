"""The Python gold set: the sample, the label files and their checks."""

import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchsight.pipeline.benchmarks import python_gold as gold
from patchsight.pipeline.ingest.aliases import AliasGroup
from patchsight.pipeline.ingest.osv import (
    Advisory,
    AffectedPackage,
    OsvEvent,
    SymbolHint,
    VersionRange,
)
from patchsight.pipeline.ingest.references import FixCandidate

NOW = datetime(2026, 11, 14, tzinfo=UTC)


def _package(versions: tuple[str, ...] = (), **event: str) -> AffectedPackage:
    return AffectedPackage(
        name="pkg", raw_name="pkg", versions=versions,
        ranges=(VersionRange(type="ECOSYSTEM", events=(OsvEvent(introduced="0"),
                                                       OsvEvent(**event))),),
    )  # fmt: skip


def _advisory(key: str, upstream: bool = False) -> Advisory:
    fix = FixCandidate.model_validate({
        "kind": "github_commit", "origin": "reference", "url": f"https://github.com/o/pkg/commit/{key}",
        "host": "github.com", "repo": "o/pkg", "ref": key,
    })  # fmt: skip
    hints = (SymbolHint(field="imports", package="pkg", value=["pkg.load"]),) if upstream else ()
    return Advisory(
        id=key, source="ghsa", aliases=(), related=(), published=NOW, modified=NOW, summary="s",
        details="d", packages=(_package(("1.0", "1.2", "1.10"), fixed="1.11"),), references=(),
        fix_candidates=(fix,), symbol_hints=hints,
    )  # fmt: skip


def test_the_last_vulnerable_version_is_the_highest_listed_one() -> None:
    assert gold.package_versions(_package(("1.0", "1.10", "1.9"), fixed="1.11")).model_dump() == {
        "name": "pkg", "last_vulnerable": "1.10", "fixed": "1.11",
    }  # fmt: skip
    marked = gold.package_versions(_package(last_affected="2.3.1"))
    assert (marked.last_vulnerable, marked.fixed) == ("2.3.1", None)
    neither = gold.package_versions(_package(fixed="3.0"))
    assert (neither.last_vulnerable, neither.fixed) == (None, "3.0")


def test_the_sample_takes_every_upstream_label_then_a_seeded_draw() -> None:
    keys = [f"GHSA-{i:02d}" for i in range(30)]
    by_id = {k: _advisory(k, upstream=(k == "GHSA-29")) for k in keys}
    groups = [AliasGroup(key=k, advisory_ids=(k,), identifiers=(k,)) for k in keys]
    extractable = set(keys[:20])  # GHSA-29 is not extractable, but upstream-labelled
    sample = gold.draw(groups, by_id, extractable, "0" * 64, size=6, seed=1)
    chosen = [i.advisory for i in sample.items]
    assert len(chosen) == 6
    assert "GHSA-29" in chosen
    assert set(chosen) - {"GHSA-29"} <= extractable
    assert (sample.population, sample.upstream) == (20, 1)
    assert chosen == [
        i.advisory for i in gold.draw(groups, by_id, extractable, "0" * 64, 6, 1).items
    ]
    item = sample.items[0]
    assert item.packages[0].last_vulnerable == "1.10"
    assert item.fix_links == (f"https://github.com/o/pkg/commit/{item.advisory}",)


def _sample() -> gold.Sample:
    keys = ["GHSA-a", "GHSA-b"]
    by_id = {k: _advisory(k) for k in keys}
    groups = [AliasGroup(key=k, advisory_ids=(k,), identifiers=(k,)) for k in keys]
    return gold.draw(groups, by_id, keys, "0" * 64, size=2, seed=1)


def test_a_round_starts_as_todo_stubs_in_its_own_order(tmp_path: Path) -> None:
    sample = _sample()
    text = gold.stub_round(sample, 1)
    entries = tomllib.loads(text)["label"]
    assert {(e["advisory"], e["status"], e["round"], e["version"]) for e in entries} == {
        ("GHSA-a", "todo", 1, "1.10"), ("GHSA-b", "todo", 1, "1.10"),
    }  # fmt: skip
    path = tmp_path / "round1.toml"
    path.write_text(text)
    labels = gold.load_labels(path)
    problems = gold.check_labels(labels, sample, 1)
    assert sorted(problems) == ["GHSA-a pkg: still todo", "GHSA-b pkg: still todo"]


def test_label_checks_name_every_problem() -> None:
    sample = _sample()
    labels = [
        gold.Label(advisory="GHSA-a", package="pkg", version="1.10", symbols=("pkg.core:load",),
                   status="labelled", round=1),
        gold.Label(advisory="GHSA-a", package="pkg", version="1.10", status="no_fix", round=2),
        gold.Label(advisory="GHSA-z", package="pkg", version="1", status="labelled", round=1),
    ]  # fmt: skip
    problems = gold.check_labels(labels, sample, 1)
    assert "GHSA-a pkg: labelled twice" in problems
    assert "GHSA-a pkg: round 2, not 1" in problems
    assert "GHSA-z pkg: not in the sample" in problems
    assert "GHSA-z pkg: labelled with no symbol" in problems
    assert "GHSA-b pkg: missing" in problems
    assert labels[0].qualified == frozenset({"pkg.core.load"})


@pytest.mark.parametrize("symbol", ["pkg.core.load", ":load", "pkg:", "pkg: load"])
def test_a_symbol_is_written_module_colon_name(symbol: str) -> None:
    with pytest.raises(ValueError, match=r"module:Qualified\.name"):
        gold.Label(advisory="A", package="p", version="1", symbols=(symbol,), status="labelled",
                   round=1)  # fmt: skip


def test_the_worksheet_links_and_copies_no_advisory_text() -> None:
    text = gold.worksheet(_sample())
    assert "[GHSA-a](https://osv.dev/vulnerability/GHSA-a)" in text
    assert "[GHSA-a](https://github.com/o/pkg/commit/GHSA-a)" in text
    assert "| pkg 1.10 |" in text
    assert "details" not in text
