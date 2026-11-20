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
    bare = FixCandidate.model_validate({  # a repository link is not a fix
        "kind": "other_commit", "origin": "reference", "url": "https://github.com/o/pkg",
        "host": "github.com",
    })  # fmt: skip
    hints = (SymbolHint(field="imports", package="pkg", value=["pkg.load"]),) if upstream else ()
    return Advisory(
        id=key, source="ghsa", aliases=(), related=(), published=NOW, modified=NOW, summary="s",
        details="d", packages=(_package(("1.0", "1.2", "1.10"), fixed="1.11"),), references=(),
        fix_candidates=(fix, bare), symbol_hints=hints,
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
    assert item.packages[0].last_vulnerable == "1.10"  # a bare repository link is not a fix
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


def _label(advisory: str, round_: int, *symbols: str, status: str = "labelled",
           package: str = "pkg") -> gold.Label:  # fmt: skip
    entry = {"advisory": advisory, "package": package, "version": "1", "symbols": symbols,
             "status": status, "round": round_}  # fmt: skip
    return gold.Label.model_validate(entry)


def test_agreement_is_exact_match_and_jaccard_over_finished_entries() -> None:
    first = [_label("A", 1, "pkg.core:load"), _label("B", 1, "pkg:x", "pkg:y"),
             _label("C", 1, status="no_fix"), _label("D", 1, status="todo")]  # fmt: skip
    second = [_label("A", 2, "pkg.core:load"), _label("B", 2, "pkg:x"),
              _label("C", 2, status="no_fix"), _label("D", 2, "pkg:z")]  # fmt: skip
    result = gold.agreement(first, second, bootstrap=200)
    assert (result.compared, result.advisories) == (3, 3)  # D was not finished in round 1
    assert result.exact_match == pytest.approx(2 / 3)
    assert result.mean_jaccard == pytest.approx((1 + 0.5 + 1) / 3)
    assert result.exact_ci95.low <= result.exact_match <= result.exact_ci95.high
    (disagreement,) = result.disagreements
    assert (disagreement.advisory, disagreement.first, disagreement.second) == (
        "B", ("labelled", "pkg:x", "pkg:y"), ("labelled", "pkg:x"),
    )  # fmt: skip
    assert (
        gold.agreement([_label("A", 1, status="no_fix")], [_label("A", 2, "pkg:x")]).exact_match
        == 0
    )


def test_final_labels_take_agreement_or_the_recorded_resolution() -> None:
    first = [_label("A", 1, "pkg:load"), _label("B", 1, "pkg:x", "pkg:y"), _label("C", 1, "pkg:c")]
    second = [_label("A", 2, "pkg:load"), _label("B", 2, "pkg:x"), _label("C", 2, "pkg:d")]
    final, unresolved = gold.final_labels(first, second, [_label("B", 3, "pkg:x", "pkg:y")])
    assert [(f.advisory, f.round) for f in final] == [("A", 1), ("B", 3)]
    assert unresolved == [("C", "pkg")]


def test_systems_are_scored_strictly_and_on_a_dotted_boundary() -> None:
    labels = [_label("A", 1, "yaml.constructor:FullConstructor.construct_python_object"),
              _label("B", 1, "pkg:load"), _label("C", 1, status="no_python_symbol")]  # fmt: skip
    systems = {
        "extractor": {"A/pkg": {"lib.yaml.constructor.FullConstructor.construct_python_object"},
                      "B/pkg": {"pkg.load"}},
        "ChangedFuncs": {"A/pkg": {"yaml.constructor.FullConstructor.construct_python_object",
                                   "yaml.loader.Loader"}},
    }  # fmt: skip
    extractor, changed = gold.score_against(labels, systems, bootstrap=100)
    assert extractor.strict.reports == 2  # the no_python_symbol entry is not scored
    assert extractor.strict.true_positives == 1  # the src-layout module differs exactly...
    assert extractor.lenient.recall == 1.0  # ...but matches on a dotted boundary
    assert (changed.strict.true_positives, changed.strict.false_positives) == (1, 1)
    assert changed.lenient.miss_rate == 0.5  # B has no prediction at all


def test_the_commands_check_a_round_and_measure_agreement(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from patchsight.pipeline.__main__ import app

    directory = tmp_path / gold.DIRECTORY
    directory.mkdir(parents=True)
    sample = _sample()
    (tmp_path / gold.SAMPLE).write_text(sample.model_dump_json())
    (directory / "round1.toml").write_text(gold.stub_round(sample, 1))
    runner = CliRunner()
    todo = runner.invoke(app, ["gold-check", "--round", "1", "--root", str(tmp_path)])
    assert todo.exit_code == 1
    assert "round 1: {'todo': 2}" in todo.output
    for round_, symbols in ((1, '["pkg.core:load"]'), (2, '["pkg.core:load", "pkg:x"]')):
        text = gold.stub_round(sample, round_).replace("symbols = []", f"symbols = {symbols}")
        (directory / f"round{round_}.toml").write_text(text.replace('"todo"', '"labelled"'))
    done = runner.invoke(app, ["gold-check", "--round", "2", "--root", str(tmp_path)])
    assert done.exit_code == 0, done.output
    (tmp_path / "docs" / "reports").mkdir(parents=True)
    measured = runner.invoke(app, ["gold-agreement", "--root", str(tmp_path)])
    assert measured.exit_code == 0, measured.output
    assert "2 entries in both rounds: exact match 0.0%, mean Jaccard 0.500; 2 to resolve" in (
        measured.output
    )
    report = (tmp_path / "docs" / "reports" / f"{gold.NAME}-agreement.md").read_text()
    assert "**Exact match:** 0.0%" in report


def test_the_scores_report_names_each_system() -> None:
    labels = [_label("A", 1, "pkg:load")]
    scores = gold.score_against(labels, {"Extractor alone": {"A/pkg": {"pkg.load"}}}, 50)
    text = gold.render_scores(scores, labelled=1, unresolved=2)
    assert "| Extractor alone | 1.000 | 1.000 | 1.000" in text
    assert "still unresolved and not scored: 2" in text


def test_a_new_round_starts_fresh_and_round_three_holds_the_disagreements(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from patchsight.pipeline.__main__ import app

    directory = tmp_path / gold.DIRECTORY
    directory.mkdir(parents=True)
    sample = _sample()
    (tmp_path / gold.SAMPLE).write_text(sample.model_dump_json())
    labelled = {"GHSA-a": '["pkg:load"]', "GHSA-b": '["pkg:x"]'}
    for round_, changed in ((1, {}), (2, {"GHSA-b": '["pkg:y"]'})):
        entries = []
        for advisory, symbols in (labelled | changed).items():
            head = f'[[label]]\nadvisory = "{advisory}"\npackage = "pkg"\nversion = "1.10"\n'
            entries.append(head + f'symbols = {symbols}\nstatus = "labelled"\nround = {round_}\n')
        (directory / f"round{round_}.toml").write_text("\n".join(entries))
    runner = CliRunner()
    again = runner.invoke(app, ["gold-round", "--round", "2", "--root", str(tmp_path)])
    assert again.exit_code != 0  # never replaces a round's file
    third = runner.invoke(app, ["gold-round", "--round", "3", "--root", str(tmp_path)])
    assert third.exit_code == 0, third.output
    stubs = gold.load_labels(directory / "round3.toml")
    assert [(s.advisory, s.status, s.round) for s in stubs] == [("GHSA-b", "todo", 3)]


def test_the_committed_sample_and_rounds_are_consistent() -> None:
    root = Path(__file__).resolve().parents[1]
    if not (root / gold.SAMPLE).exists():
        pytest.skip("no sample yet")
    sample = gold.Sample.model_validate_json((root / gold.SAMPLE).read_text())
    assert (len(sample.items), sample.seed) == (120, gold.SEED)
    assert all(i.fix_links for i in sample.items)
    for round_ in (1, 2):
        path = root / gold.DIRECTORY / f"round{round_}.toml"
        if path.exists():  # unfinished entries are expected while a round is in progress
            problems = gold.check_labels(gold.load_labels(path), sample, round_)
            assert [p for p in problems if not p.endswith("still todo")] == []
