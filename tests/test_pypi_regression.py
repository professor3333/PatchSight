"""The PyPI regression set: recorded answers replayed through the live Python path."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchsight import db
from patchsight.pipeline.benchmarks import pypi_regression as regression
from patchsight.pipeline.extract.prompt import Candidate, HunkRef, RenderedPrompt
from patchsight.pipeline.llm.config import load_config

REPO = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 14, tzinfo=UTC)
PROMPT = RenderedPrompt(
    version="extract-v1", messages=(),
    candidates=(Candidate(id="F1", path="src/pkg/core.py", name="load", hunk_ids=("H1",)),
                Candidate(id="F2", path="src/pkg/core.py", name="Loader.read", hunk_ids=("H2",))),
    hunk_ids=("H1", "H2"),
    hunks=(HunkRef(id="H1", source="a" * 40, path="src/pkg/core.py", old_start=3, old_count=2,
                   new_start=3, new_count=3),
           HunkRef(id="H2", source="a" * 40, path="src/pkg/core.py", old_start=20, old_count=1,
                   new_start=21, new_count=1)),
    estimated_tokens=0, truncated=False, dropped=(),
)  # fmt: skip


def _answer(vulnerable: str = "F1", entry: tuple[str, ...] = ("full_load",)) -> str:
    return json.dumps({
        "items": [
            {"candidate_id": c, "is_vulnerable": c == vulnerable, "rationale": f"{c} reason",
             "evidence_hunk_ids": [h] if c == vulnerable else []}
            for c, h in (("F1", "H1"), ("F2", "H2"))
        ],
        "public_entry_points": list(entry),
    })  # fmt: skip


def _fallback() -> db.Record:
    symbols = tuple(db.Symbol(qualified_name=f"pkg.core.{n}", module="pkg.core", name=n,
                              kind=k, path="src/pkg/core.py")
                    for n, k in (("load", "function"), ("Loader.read", "method")))  # fmt: skip
    return db.Record(
        vulnerability="GHSA-1", package="pkg", confidence="low", source="fallback",
        import_roots=("pkg",), entry_points=(), symbols=symbols,
        fix_commits=(db.FixCommitRef(repo="o/pkg", sha="a" * 40),), model=None,
        prompt_version=None, input_hash="h", advisory_modified=NOW, truncated=False,
        extracted_at=NOW,
    )  # fmt: skip


def _case(answers: tuple[str | None, ...]) -> regression.Case:
    empty = regression.Expected(status="", calls=0, vulnerable_symbols=(), entry_points=(),
                                evidence=(), merge="", records=())  # fmt: skip
    return regression.Case(
        vulnerability="GHSA-1", stratum="ok", packages=("pkg",), input_hash="h",
        fix_commits=(db.FixCommitRef(repo="o/pkg", sha="a" * 40),), prompt=PROMPT,
        known_names=("full_load",), definitions={"full_load": ("src/pkg/__init__.py",)},
        kinds=(("src/pkg/core.py", "Loader.read", "method"),
               ("src/pkg/core.py", "load", "function")),
        answers=answers, fallback=(_fallback(),), expected=empty,
    )  # fmt: skip


def test_an_answer_is_replayed_into_symbols_entry_points_evidence_and_records() -> None:
    out = regression.replay(_case((_answer(),)), "m", dotted_entry_points=False)
    assert (out.status, out.calls) == ("ok", 1)
    assert out.vulnerable_symbols == ("pkg.core.load",)
    assert out.entry_points == ("pkg.full_load",)  # qualified by the file that defines it
    assert [e.qualified_name for e in out.evidence] == ["pkg.core.load"]
    (record,) = out.records
    assert (record.confidence, record.source) == ("low", "llm")
    assert record.tier_reason == "no valid second opinion"
    assert record.symbols == ("pkg.core.Loader.read", "pkg.core.load")  # every changed one
    assert record.entry_points == ("pkg.full_load",)


def test_a_rejection_then_an_answer_is_repaired_and_two_bad_answers_dead_letter() -> None:
    repaired = regression.replay(_case((None, _answer())), "m", dotted_entry_points=False)
    assert (repaired.status, repaired.calls) == ("repaired", 2)
    dead = regression.replay(_case(("{bad", "{still bad")), "m", dotted_entry_points=False)
    assert (dead.status, dead.vulnerable_symbols, dead.merge) == (
        "dead_letter", (), "fallback: extraction failed validation",
    )  # fmt: skip
    (record,) = dead.records
    assert record.source == "fallback"


def test_check_lists_every_pinned_field_that_moved() -> None:
    case = _case((_answer(),))
    pinned = case.model_copy(update={"expected": regression.replay(case, "m", False)})
    regression_set = regression.RegressionSet(
        name="t", model="m", prompt_version="extract-v1", source="s", seed=1, strata={"ok": 1},
        cases=(pinned,),
    )  # fmt: skip
    assert regression.check(regression_set, dotted_entry_points=False) == []
    moved = pinned.model_copy(update={"answers": (_answer(vulnerable="F2", entry=()),)})
    differences = regression.check(
        regression_set.model_copy(update={"cases": (moved,)}), dotted_entry_points=False
    )
    assert {d.field for d in differences} == {
        "vulnerable_symbols", "entry_points", "evidence", "records",
    }  # fmt: skip


def test_the_selection_takes_rare_outcomes_first_and_is_seeded() -> None:
    from patchsight.pipeline.extract.extractor import ExtractionOutcome
    from patchsight.pipeline.pypi_extract import PyPIExtraction

    def outcome(key: str, status: str, truncated: bool = False) -> PyPIExtraction:
        result = ExtractionOutcome(
            advisory_id=key, status=status, model="m", prompt_version="p", candidates=1,
            vulnerable=(), entry_points=(), entry_points_dropped=0,
            invented_ids_first_attempt=0, errors=(), truncated=truncated, dropped_candidates=(),
            estimated_prompt_tokens=0, prompt_tokens=0, completion_tokens=0, calls=1,
            cached_calls=1, provider_rejections=0,
        )  # fmt: skip
        return PyPIExtraction(vulnerability=key, packages=("p",), input_hash="h",
                              fix_commits=(), vulnerable_symbols=(), outcome=result)  # fmt: skip

    runs = {f"GHSA-{i:02d}": outcome(f"GHSA-{i:02d}", "ok") for i in range(40)}
    runs |= {"GHSA-dead": outcome("GHSA-dead", "dead_letter"),
             "GHSA-cut": outcome("GHSA-cut", "ok", truncated=True)}  # fmt: skip
    chosen = regression.select(runs, size=10, seed=3)
    assert len(chosen) == 10
    assert ("GHSA-dead", "dead_letter") in chosen
    assert ("GHSA-cut", "ok, truncated") in chosen
    assert chosen == regression.select(runs, size=10, seed=3)
    assert chosen != regression.select(runs, size=10, seed=4)


def test_a_file_that_is_not_the_pinned_set_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "cases.json"
    path.write_text("{}")
    with pytest.raises(ValueError, match="not the pinned regression set"):
        regression.load(path)


def test_the_committed_set_replays_with_no_difference() -> None:
    path = REPO / regression.FROZEN
    if not path.exists():
        pytest.skip("the regression set is not frozen yet")
    frozen = regression.load(path)
    assert len(frozen.cases) == 50
    assert all(not c.prompt.messages for c in frozen.cases)  # no advisory text, no diffs
    # Under the configuration in force, as regression-check runs it: switching an option on
    # that moves a pinned output must fail here, and be re-pinned on purpose.
    dotted = load_config(REPO / "configs" / "llm.toml").validation.dotted_entry_points
    assert regression.check(frozen, dotted_entry_points=dotted) == []
