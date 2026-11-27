"""Live drift check (ADR 0016): decisions compared with pinned answers, and the verdict."""

import json
from pathlib import Path

import pytest

from patchsight.pipeline import drift
from patchsight.pipeline.drift import CaseResult, Decisions, PinnedCase
from patchsight.pipeline.extract.prompt import Candidate, RenderedPrompt
from patchsight.pipeline.llm.client import LLMRequest

REPO = Path(__file__).resolve().parents[1]


def _answer(vulnerable: set[str], ids: list[str], entry: list[str] | None = None) -> str:
    return json.dumps({
        "items": [{"candidate_id": i, "is_vulnerable": i in vulnerable,
                   "rationale": "free text", "evidence_hunk_ids": ["H1"]} for i in ids],
        "public_entry_points": entry or [],
    })  # fmt: skip


def _prompt(ids: list[str]) -> RenderedPrompt:
    return RenderedPrompt(
        version="extract-v1", messages=(), estimated_tokens=10, truncated=False, dropped=(),
        candidates=tuple(Candidate(id=i, path="pkg/m.py", name=f"f_{i}", hunk_ids=("H1",))
                         for i in ids),
        hunk_ids=("H1",),
    )  # fmt: skip


def _case(vulnerable: tuple[str, ...], entry: tuple[str, ...] = (), n: int = 3) -> PinnedCase:
    return PinnedCase(vulnerability="GHSA-x", request_key="k" * 64, candidates=n,
                      expected=Decisions(vulnerable=vulnerable, entry_points=entry),
                      names={i: f"pkg/m.py:f_{i}" for i in vulnerable})  # fmt: skip


def test_decisions_are_ids_in_number_order_and_entry_points_once_each() -> None:
    ids = [f"F{i}" for i in range(1, 12)]
    got = drift.decisions(_answer({"F10", "F2", "F11"}, ids, ["b.run", "a.load", "b.run"]))
    assert got == Decisions(vulnerable=("F2", "F10", "F11"), entry_points=("a.load", "b.run"))
    assert drift.decisions("not json") is None
    assert drift.decisions(json.dumps({"items": []})) is None  # entry points missing


def test_wording_and_cited_hunks_are_not_compared() -> None:
    """E13: the same prompt can come back reworded with the same decisions."""
    case = _case(("F1",), ("pkg.load",))
    reworded = json.loads(_answer({"F1"}, ["F1", "F2", "F3"], ["pkg.load"]))
    reworded["items"][0]["rationale"] = "said another way"
    reworded["items"][0]["evidence_hunk_ids"] = ["H1", "H2"]
    result = drift.compare(case, json.dumps(reworded), _prompt(["F1", "F2", "F3"]))
    assert result.status == "same"
    assert result.names == {}


def test_a_changed_decision_names_the_candidates_of_both_answers() -> None:
    case = _case(("F1",))
    result = drift.compare(case, _answer({"F2"}, ["F1", "F2", "F3"]), _prompt(["F1", "F2", "F3"]))
    assert result.status == "changed"
    assert result.got == Decisions(vulnerable=("F2",), entry_points=())
    assert result.names == {"F1": "pkg/m.py:f_F1", "F2": "pkg/m.py:f_F2"}
    entry = drift.compare(case, _answer({"F1"}, ["F1"], ["pkg.new"]), _prompt(["F1"]))
    assert entry.status == "changed"  # an entry point alone is a decision too
    assert drift.compare(case, "{", _prompt(["F1"])).status == "invalid"


def test_an_answer_must_judge_every_candidate_once_to_be_pinned() -> None:
    prompt = _prompt(["F1", "F2"])
    assert drift.answers_every_candidate(_answer({"F1"}, ["F2", "F1"]), prompt)
    assert not drift.answers_every_candidate(_answer({"F1"}, ["F1"]), prompt)
    assert not drift.answers_every_candidate(_answer({"F1"}, ["F1", "F1", "F2"]), prompt)


def _results(*statuses: drift.CaseStatus) -> list[CaseResult]:
    return [CaseResult(vulnerability=f"V{i}", status=s) for i, s in enumerate(statuses)]


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (("same",) * 10, "ok"),
        (("same",) * 4 + ("changed",), "note"),
        (("same",) * 8 + ("changed", "invalid"), "drift"),
        (("changed", "changed") + ("not_run",) * 8, "drift"),  # 2 changes are enough
        (("same",) * 4 + ("input_changed", "rejected", "no_prompt", "not_run"), "inconclusive"),
        (("same", "same", "same", "changed") + ("rejected",) * 6, "inconclusive"),
    ],
)
def test_the_declared_verdict(statuses: tuple[drift.CaseStatus, ...], expected: str) -> None:
    assert drift.verdict(_results(*statuses)) == expected


def test_the_draw_is_seeded_and_skips_one_candidate_prompts() -> None:
    pool = [_case(("F1",), n=n).model_copy(update={"vulnerability": f"V{i:02}"})
            for i, n in enumerate([1, 2, 3, 1, 5, 9, 2, 4, 1, 6, 7, 8])]  # fmt: skip
    first = drift.draw(pool, size=5, seed=1)
    assert first == drift.draw(list(reversed(pool)), size=5, seed=1)
    assert [c.vulnerability for c in first] == sorted(c.vulnerability for c in first)
    assert all(c.candidates >= drift.MIN_CANDIDATES for c in first)
    assert len(drift.draw(pool, size=50)) == 9  # every prompt with 2 or more candidates


def test_the_committed_pins_hold_decisions_and_names_only() -> None:
    """Rule 13: no code, no advisory text, no rationale in the pinned file."""
    raw = (REPO / drift.PINNED).read_text()
    pinned = drift.Pinned.model_validate_json(raw)
    assert pinned.name == "drift-pypi-extractor-v1"
    assert len(pinned.cases) == drift.SIZE
    assert all(c.candidates >= drift.MIN_CANDIDATES for c in pinned.cases)
    assert pinned.cases == tuple(sorted(pinned.cases, key=lambda c: c.vulnerability))
    assert "rationale" not in raw
    assert "evidence_hunk_ids" not in raw
    for case in pinned.cases:
        assert set(case.names) == set(case.expected.vulnerable)
        assert len(case.request_key) == 64


def test_the_report_shows_both_answers_for_a_change() -> None:
    pinned = drift.Pinned(name="drift-t", role="extractor", model="m", prompt_version="v",
                          config_sha256="0" * 64, seed=1, pool=1,
                          cases=(_case(("F1",)),))  # fmt: skip
    changed = drift.compare(pinned.cases[0], _answer({"F2"}, ["F1", "F2"]), _prompt(["F1", "F2"]))
    report = drift.report(pinned, "a" * 64, "2026-11-28", [changed])
    assert report.verdict == "inconclusive"
    assert report.counts == {"changed": 1}
    text = drift.render_markdown(report, pinned)
    assert "pinned vulnerable: F1 `pkg/m.py:f_F1`" in text
    assert "tonight vulnerable: F2 `pkg/m.py:f_F2`" in text


def _request(prompt: RenderedPrompt) -> LLMRequest:
    return LLMRequest(model="m", prompt_version=prompt.version,
                      messages=({"role": "user", "content": ",".join(prompt.hunk_ids)},),
                      schema_name="s", response_schema={}, max_tokens=10, seed=0)  # fmt: skip


def _pinned_for(prompt: RenderedPrompt, vulnerability: str) -> PinnedCase:
    return _case(("F1",)).model_copy(
        update={"vulnerability": vulnerability, "request_key": _request(prompt).cache_key()}
    )


def test_check_asks_only_unchanged_prompts_and_stops_at_the_cap(tmp_path: Path) -> None:
    """Each branch, with a fake provider: same, changed input, refusal, no prompt, cap."""
    from patchsight.pipeline.llm.client import (
        LLMClient,
        ProviderRejectedError,
        QuotaExhaustedError,
        RateLimiter,
    )

    # Each pin has its own prompt (one request key each); V1's was edited since.
    prompts = [_prompt(["F1", "F2"]).model_copy(update={"hunk_ids": (f"H{i}",)}) for i in range(6)]
    cases = [_pinned_for(p, f"V{i}") for i, p in enumerate(prompts)]
    edited = prompts[1].model_copy(update={"hunk_ids": ("H1", "H9")})
    asked: list[str] = []

    def backend(request: LLMRequest) -> tuple[str, int, int]:
        asked.append(request.messages[0]["content"])
        if len(asked) == 2:
            raise ProviderRejectedError("Failed to generate JSON; org_123")
        if len(asked) == 3:
            raise QuotaExhaustedError("daily cap")
        return _answer({"F1"}, ["F1", "F2"]), 5, 5

    tonight: dict[str, RenderedPrompt | str] = {
        "V0": prompts[0], "V1": edited, "V2": prompts[2], "V3": "no_python_fix",
        "V4": prompts[4], "V5": prompts[5],
    }  # fmt: skip
    llm = LLMClient(backend, RateLimiter(100_000, 100), tmp_path / "llm")
    results, stopped = drift.check(cases, tonight.__getitem__, _request, llm)
    assert [r.status for r in results] == [
        "same", "input_changed", "rejected", "no_prompt", "not_run", "not_run",
    ]  # fmt: skip
    assert stopped
    assert len(asked) == 3  # the edited prompt is never sent; nothing after the cap
    assert results[3].detail == "no python fix"
    assert "org_123" not in json.dumps([r.model_dump() for r in results])
