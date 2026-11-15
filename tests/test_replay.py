"""Offline replay of LLM answers with the live extractor's own rules."""

import json
from pathlib import Path

import pytest

from patchsight.pipeline.benchmarks import bundle, extraction, replay, splits
from patchsight.pipeline.extract.prompt import Candidate

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = (
    Candidate(id="F1", path="a.go", name="Parse", hunk_ids=("H1",)),
    Candidate(id="F2", path="a.go", name="helper", hunk_ids=("H2",)),
)


def _answer(vulnerable: dict[str, bool]) -> str:
    items = [
        {"candidate_id": cid, "is_vulnerable": v, "rationale": "Because.",
         "evidence_hunk_ids": [f"H{cid[1:]}"] if v else []}
        for cid, v in vulnerable.items()
    ]  # fmt: skip
    return json.dumps({"items": items, "public_entry_points": []})


GOOD = _answer({"F1": True, "F2": False})
INVALID = _answer({"F1": True})  # misses F2


@pytest.mark.parametrize(
    ("answers", "status", "predicted"),
    [
        ((GOOD,), "ok", {"Parse"}),
        ((INVALID, GOOD), "repaired", {"Parse"}),
        ((None, GOOD), "repaired", {"Parse"}),
        ((INVALID, INVALID), "dead_letter", set()),
        ((None, None), "dead_letter", set()),
        ((GOOD[:40],), "dead_letter", set()),  # output cut off at the token limit
    ],
)
def test_replay_follows_the_extractor_rules(
    answers: tuple[str | None, ...], status: str, predicted: set[str]
) -> None:
    report = replay.ReplayReport(
        id="R", candidates=CANDIDATES, answers=answers, truncated=False, dropped=()
    )
    assert replay.replay_report(report, "extract-v1") == (status, predicted)


def test_no_candidates() -> None:
    report = replay.ReplayReport(id="R", candidates=(), answers=(), truncated=False, dropped=())
    assert replay.replay_report(report, "extract-v1") == ("no_candidates", set())


def test_committed_replay_reproduces_the_committed_reports() -> None:
    """The check CI runs: the published LLM scores follow from the published answers."""
    truth = {
        r.id: set(r.symbols)
        for r in bundle.load(ROOT / "benchmarks/dunlap-v1/candidates.json").reports
    }
    frozen = splits.load_split(ROOT / "splits/dunlap-v1.json")
    tag = "extract-v1-qwen3.8-27b-q4km"
    run = replay.load(ROOT / f"benchmarks/dunlap-v1/extraction-{tag}.json")
    for part in ("all", "dev", "test"):
        scores, statuses = replay.replay(run, truth, frozen.split.ids(part))
        published = extraction.ExtractionRun.model_validate_json(
            (ROOT / f"docs/reports/extraction-dunlap-{part}-{tag}.json").read_text()
        )
        assert (scores.true_positives, scores.false_positives, scores.false_negatives) == (
            published.extraction.true_positives,
            published.extraction.false_positives,
            published.extraction.false_negatives,
        )
        assert statuses == published.status
