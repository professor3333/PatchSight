"""The declared holdout evaluation (ADR 0010): criterion, misses by cause, and coverage."""

from pathlib import Path

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


def test_the_command_scores_both_runs_from_their_committed_files(tmp_path: Path) -> None:
    import json

    from typer.testing import CliRunner

    from patchsight.pipeline.__main__ import app
    from patchsight.pipeline.benchmarks import go_holdout
    from patchsight.pipeline.benchmarks.replay import REPLAY_VERSION, ReplayBundle, ReplayReport
    from patchsight.pipeline.extract.prompt import Candidate

    frozen = go_holdout.Holdout(
        name=go_holdout.NAME, cutoff=go_holdout.CUTOFF, source="s", source_sha256="0" * 64,
        retrieved_at="2026-11-19T00:00:00+00:00", attribution="a", considered=1, excluded={},
        reports=(go_holdout.HoldoutReport(
            id="GO-2026-0001", published="2026-09-01T00:00:00Z", summary="s", details="d",
            symbols=("Parse",),
            commits=(go_holdout.HoldoutCommit(github_repo="o/r", sha="a" * 40),),
        ),),
    )  # fmt: skip
    (tmp_path / go_holdout.FROZEN).parent.mkdir(parents=True)
    (tmp_path / go_holdout.FROZEN).write_text(frozen.model_dump_json())
    answer = json.dumps({"items": [
        {"candidate_id": "F1", "is_vulnerable": True, "rationale": "r",
         "evidence_hunk_ids": ["H1"]},
        {"candidate_id": "F2", "is_vulnerable": False, "rationale": "r", "evidence_hunk_ids": []},
    ], "public_entry_points": []})  # fmt: skip
    candidates = (Candidate(id="F1", path="p.go", name="Parse", hunk_ids=("H1",)),
                  Candidate(id="F2", path="p.go", name="helper", hunk_ids=("H2",)))  # fmt: skip
    reports = tmp_path / "docs" / "reports"
    reports.mkdir(parents=True)
    for tag, model in (("one", "m1"), ("two", "m2")):
        bundle = ReplayBundle(
            replay_version=REPLAY_VERSION, benchmark=go_holdout.NAME, model=model,
            prompt_version="extract-v1",
            reports=(ReplayReport(id="GO-2026-0001", candidates=candidates, answers=(answer,),
                                  truncated=False, dropped=()),),
        )  # fmt: skip
        (tmp_path / go_holdout.FROZEN.parent / f"extraction-{tag}.json").write_text(
            bundle.model_dump_json()
        )
        outcomes = {"outcomes": [{"advisory_id": "GO-2026-0001", "entry_points": []}]}
        (reports / f"extraction-go-holdout-v1-{tag}.json").write_text(json.dumps(outcomes))
    result = CliRunner().invoke(
        app, ["holdout-report", "--primary", "one", "--secondary", "two", "--root", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert "exact: 1 of 1 high, 0 misses (0.0%), passes; covered 1 of 1" in result.output
    assert "dotted variant not computed" in result.output
    text = (reports / "holdout-go-holdout-v1-one-vs-two.md").read_text()
    assert "| exact | 1 of 1 | 0 | 0.0% (" in text
