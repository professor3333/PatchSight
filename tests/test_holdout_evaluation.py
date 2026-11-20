"""The declared holdout evaluation (ADR 0010): criterion, misses by cause, and coverage."""

from patchsight.eval import holdout
from patchsight.eval.confidence import Answer
from patchsight.eval.metrics import score
from patchsight.eval.safety import safety


def _ok(*names: str, entry: tuple[str, ...] = ()) -> Answer:
    return Answer(status="ok", vulnerable=frozenset(names), entry_points=frozenset(entry))


CHANGED = {
    "GO-1": {"Parse", "helper"},  # high, covers every label
    "GO-2": {"Parse", "Decode"},  # high, covers one of two labels: not covered, not a miss
    "GO-3": {"Parse"},  # high, misses: the label was changed, so a model error
    "GO-4": {"Render"},  # high, misses: the label was never changed, the patch ceiling
    "GO-5": {"Open"},  # low: the models disagree
}
TRUTH = {
    "GO-1": {"Parse"},
    "GO-2": {"Parse", "Client.Get"},
    "GO-3": {"Parse"},
    "GO-4": {"Serve"},
    "GO-5": {"Open"},
}
PRIMARY = {
    "GO-1": _ok("Parse"), "GO-2": _ok("Parse"), "GO-3": _ok("Other"), "GO-4": _ok("Render"),
    "GO-5": _ok("Open"),
}  # fmt: skip
SECONDARY = {
    "GO-1": _ok("Parse"), "GO-2": _ok("Parse"), "GO-3": _ok("Other"), "GO-4": _ok("Render"),
    "GO-5": _ok("helper"),
}  # fmt: skip


def test_the_criterion_misses_by_cause_and_coverage() -> None:
    result = holdout.evaluate("exact", PRIMARY, SECONDARY, CHANGED, TRUTH)
    assert (result.reports, result.high_reports, result.high_misses) == (5, 4, 2)
    assert result.high_miss_rate == 0.5
    assert not result.passes
    assert {m.report: m.cause for m in result.misses} == {"GO-3": "model", "GO-4": "patch ceiling"}
    assert result.covered_reports == 1  # only GO-1 holds every labelled symbol
    assert {u.report: (u.labelled, u.missing) for u in result.uncovered} == {
        "GO-2": (2, 1), "GO-3": (1, 1), "GO-4": (1, 1),
    }  # fmt: skip
    assert result.ci95_low < 0.5 < result.ci95_high


def test_an_entry_point_can_cover_an_exported_caller() -> None:
    primary = {**PRIMARY, "GO-2": _ok("Parse", entry=("Client.Get",))}
    result = holdout.evaluate("dotted", primary, SECONDARY, CHANGED, TRUTH)
    assert "GO-2" not in {u.report for u in result.uncovered}


def test_a_rule_passes_only_with_high_confidence_and_few_misses() -> None:
    good = {r: _ok(*TRUTH[r]) for r in ("GO-1", "GO-3")}
    result = holdout.evaluate("exact", good, good, CHANGED, TRUTH)
    assert (result.high_reports, result.high_misses, result.passes) == (2, 0, True)
    nothing = holdout.evaluate("exact", {"GO-5": _ok("Open")}, {"GO-5": _ok("x")}, CHANGED, TRUTH)
    assert (nothing.high_reports, nothing.passes) == (0, False)  # no evidence is not a pass


def test_the_report_states_the_result_and_every_miss() -> None:
    result = holdout.evaluate("exact", PRIMARY, SECONDARY, CHANGED, TRUTH)
    evaluation = holdout.HoldoutEvaluation(
        holdout="go-holdout-v1", holdout_sha256="0" * 64, primary="p", primary_model="pm",
        secondary="s", secondary_model="sm", changedfuncs=score(CHANGED, TRUTH),
        changedfuncs_safety=safety(CHANGED, TRUTH), results=(result,),
    )  # fmt: skip
    text = holdout.render_markdown(evaluation)
    assert "| exact | 4 of 5 | 2 | 50.0% (" in text
    assert "**fails**" in text
    assert "`GO-4` (patch ceiling)" in text
    assert "| exact | 4 | 1 | 3 |" in text
