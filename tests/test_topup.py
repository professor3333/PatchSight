"""The prompts a configuration change alters, for a top-up run."""

from pathlib import Path

from patchsight.pipeline import topup
from patchsight.pipeline.diffs.hunks import Hunk
from patchsight.pipeline.extract import prompt as prompts
from patchsight.pipeline.llm.tokens import CharEstimate

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = prompts.load_template(ROOT / "prompts" / "extract_v1.md")
ADVISORY = prompts.AdvisoryText(id="GHSA-x", summary="Header parsing reads too far",
                                details="parse_header over-reads.")  # fmt: skip


def _input(name: str, lines: int) -> prompts.CandidateInput:
    hunk = Hunk(index=0, old_start=1, old_count=1, new_start=1, new_count=1, removed=(1,),
                added=(1,), lines=tuple(f"+line {n} of {name}" for n in range(lines)))  # fmt: skip
    return prompts.CandidateInput(path=f"pkg/{name}.py", name=name, kind="function",
                                  hunks=(hunk,), source="s")  # fmt: skip


INPUTS = [_input("parse_header", 40), _input("helper", 2), _input("format_docs", 3)]


def _render(
    budget: int, order: prompts.CandidateOrder, cap: int | None = None
) -> prompts.RenderedPrompt:
    return prompts.render(TEMPLATE, ADVISORY, INPUTS, budget, CharEstimate(3.0), 80, cap, order)


def test_a_prompt_that_fits_is_unchanged_whatever_the_order() -> None:
    assert topup.compare("GHSA-x", _render(10**6, "bm25"), _render(10**6, "smallest_first")) is None


def test_a_cut_prompt_changes_when_other_candidates_are_kept() -> None:
    plan = prompts.budget_plan(TEMPLATE, ADVISORY, INPUTS, CharEstimate(3.0), 80)
    budget = plan.base_tokens + sorted(plan.costs)[0] + sorted(plan.costs)[1]  # two small ones fit
    change = topup.compare("GHSA-x", _render(budget, "bm25"), _render(budget, "smallest_first"))
    assert change is not None
    assert (change.candidates, change.truncated_before, change.truncated_after) == (3, True, True)
    assert change.reason == "cut either way, other candidates kept"
    capped = topup.compare("GHSA-x", _render(10**6, "bm25"), _render(10**6, "bm25", cap=2))
    assert capped is not None
    assert capped.reason == "newly cut by the candidate cap"
    part = topup.part("pypi", 3, ["no_python_fix"], [None, change, capped])
    assert part.reasons() == {"cut either way, other candidates kept": 1,
                              "newly cut by the candidate cap": 1}  # fmt: skip
    assert part.skipped == {"no_python_fix": 1}
