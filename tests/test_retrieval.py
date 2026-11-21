"""Retrieval at the prompt budget: which candidates a cut prompt keeps, under each order."""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight.pipeline.benchmarks import retrieval
from patchsight.pipeline.benchmarks.retrieval import Bundle, Case, Item

REPO = Path(__file__).resolve().parents[1]


def _case(costs: list[int], vulnerable: set[int], bm25: list[int], names: list[str] | None = None,
          split: str = "dev", scores: list[float] | None = None,
          named: set[int] = frozenset()) -> Case:  # fmt: skip
    names = names or [f"F{i}" for i in range(len(costs))]
    scores = scores or [0.0] * len(costs)
    items = tuple(
        Item(name=names[i], path="x.go", tokens=c, vulnerable=i in vulnerable,
             bm25_score=scores[i], named=i in named)
        for i, c in enumerate(costs)
    )  # fmt: skip
    return Case(report=f"GO-{len(costs)}-{split}", split=split, base_tokens=100, items=items,
                bm25=tuple(bm25))  # fmt: skip


def _bundle(*cases: Case, budget: int = 400) -> Bundle:
    return Bundle(benchmark="t", split_sha256="0" * 64, prompt_version="extract-v1",
                  tokenizer="t@1", budget_tokens=budget, max_candidates=None,
                  cases=cases)  # fmt: skip


def test_each_order_keeps_what_fits_and_bm25_can_lose_to_file_order() -> None:
    # BM25 ranks a large decoy (last in file order) first: it is always kept and fills the room.
    case = _case([100, 100, 100, 280], vulnerable={1, 2}, bm25=[3, 0, 1, 2])
    other = _case([50, 50], vulnerable={0}, bm25=[0, 1], split="test")
    bundle = _bundle(case, other, budget=300)
    assert [c.report for c in bundle.truncated()] == [case.report]  # the other one fits
    assert retrieval.kept_true(bundle, case, "bm25") == (0, 2)
    assert retrieval.kept_true(bundle, case, "file_order") == (1, 2)
    assert retrieval.kept_true(bundle, case, "oracle") == (2, 2)
    dev = retrieval.score_split(bundle, "dev")
    assert (dev.reports, dev.truncated, dev.true_functions) == (1, 1, 2)
    recall = {g.ranking: g.recall for g in dev.rankings}
    assert (recall["bm25"], recall["file_order"], recall["oracle"]) == (0.0, 0.5, 1.0)
    assert dev.rankings[0].reports_with_none_kept == 1
    file_order = next(d for d in dev.against_bm25 if d.first == "file_order")
    assert (file_order.recall_difference, file_order.first_keeps_more) == (0.5, 1)
    assert retrieval.score_split(bundle, "test").truncated == 0


def test_a_true_name_counts_once_so_the_oracle_takes_its_cheapest_candidate() -> None:
    case = _case([150, 60, 60], vulnerable={0, 1, 2}, bm25=[0, 1, 2], names=["A", "A", "B"])
    bundle = _bundle(case, budget=230)
    assert retrieval.kept_true(bundle, case, "oracle") == (2, 2)  # A by its cheaper copy, and B
    assert retrieval.kept_true(bundle, case, "file_order") == (1, 2)


@given(
    st.lists(st.tuples(st.integers(1, 300), st.booleans()), min_size=1, max_size=12),
    st.randoms(use_true_random=False),
    st.integers(150, 900),
)
def test_no_order_keeps_more_true_functions_than_the_oracle(
    items: list[tuple[int, bool]], rng: object, budget: int
) -> None:
    costs = [c for c, _ in items]
    vulnerable = {i for i, (_, v) in enumerate(items) if v}
    bm25 = list(range(len(items)))
    rng.shuffle(bm25)  # type: ignore[attr-defined]
    names = [f"F{i % 4}" for i in range(len(items))]  # repeated names, as across commits
    case = _case(costs, vulnerable, bm25, names)
    bundle = _bundle(case, budget=budget)
    best, _ = retrieval.kept_true(bundle, case, "oracle")
    for ranking in ("bm25", "file_order"):
        assert retrieval.kept_true(bundle, case, ranking)[0] <= best


@pytest.mark.parametrize("benchmark", ["dunlap-v1", "go-holdout-v1"])
def test_the_committed_report_regenerates_exactly(tmp_path: Path, benchmark: str) -> None:
    """CI recomputes each report from its frozen bundle alone: no diffs, no model."""
    from typer.testing import CliRunner

    from patchsight.pipeline.__main__ import app

    (tmp_path / "benchmarks").symlink_to(REPO / "benchmarks")
    result = CliRunner().invoke(
        app, ["retrieval-report", "--benchmark", benchmark, "--root", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    for suffix in (".md", ".json"):
        name = f"retrieval-{benchmark}{suffix}"
        produced = (tmp_path / "docs" / "reports" / name).read_text()
        assert produced == (REPO / "docs" / "reports" / name).read_text()


def test_e10_chose_on_dev_and_passed_on_the_holdout() -> None:
    """The declared decision, recomputed from the committed reports."""
    reports = REPO / "docs" / "reports"
    dunlap = retrieval.Report.model_validate_json(
        (reports / "retrieval-dunlap-v1.json").read_text()
    )
    holdout = retrieval.Report.model_validate_json(
        (reports / "retrieval-go-holdout-v1.json").read_text()
    )
    chosen = retrieval.choose_on_dev(dunlap)
    assert chosen == "smallest_first"
    assert retrieval.holdout_verdict(holdout, chosen) == "pass"


def test_the_declared_orders() -> None:
    # Costs, BM25 scores and advisory mentions chosen so each order differs.
    case = _case([300, 50, 120, 80], vulnerable=set(), bm25=[0, 2, 3, 1],
                 scores=[9.0, 1.0, 6.0, 4.0], named={2})  # fmt: skip
    assert retrieval.order(case, "file_order") == [0, 1, 2, 3]
    assert retrieval.order(case, "smallest_first") == [1, 3, 2, 0]
    assert retrieval.order(case, "named_first") == [2, 0, 1, 3]
    # Per token: 0.05 and 0.05 (a tie, so file order), then 0.03, then 0.02.
    assert retrieval.order(case, "bm25_per_token") == [2, 3, 0, 1]
    assert retrieval.order(case, "bm25") == [0, 2, 3, 1]


def test_a_candidate_is_named_by_its_full_name_or_last_part_as_a_whole_word() -> None:
    text = "A crafted header makes ReadMIMEHeader loop; Writer.Flush is unaffected."
    assert retrieval.named_in("Reader.ReadMIMEHeader", text)
    assert retrieval.named_in("Writer.Flush", text)
    assert not retrieval.named_in("ReadMIME", text)  # part of a word
    assert not retrieval.named_in("readmimeheader", text)  # case-sensitive
    assert not retrieval.named_in("Loop", text)


def _report(dev: dict[str, tuple[float, int]], cut_with_truth: int = 12) -> retrieval.Report:
    def ranking(name: str, recall: float, none: int) -> retrieval.RankingScore:
        return retrieval.RankingScore(ranking=name, kept_true=0, recall=recall, recall_ci95=None,
                                      reports_with_none_kept=none, candidates_kept=0,
                                      recall_at_k={})  # fmt: skip

    def split(name: str, low: float) -> retrieval.SplitScore:
        rankings = tuple(ranking(r, *dev.get(r, (0.0, 0))) for r in retrieval.RANKINGS)
        against = tuple(
            retrieval.Difference(first=r, second="bm25", recall_difference=low + 0.1,
                                 ci95=retrieval.Interval(low=low, high=low + 0.2),
                                 first_keeps_more=0, second_keeps_more=0, tied=0)
            for r in retrieval.RANKINGS[1:]
        )  # fmt: skip
        return retrieval.SplitScore(split=name, reports=50, truncated=cut_with_truth,
                                    truncated_with_truth=cut_with_truth, true_functions=40,
                                    candidates=100, rankings=rankings,
                                    against_bm25=against)  # fmt: skip

    return retrieval.Report(benchmark="t", split_sha256="", prompt_version="v", tokenizer="t",
                            budget_tokens=1, max_candidates=None,
                            splits=(split("all", 0.05), split("dev", 0.05)))  # fmt: skip


def test_the_dev_choice_follows_the_declared_tie_breaks() -> None:
    assert retrieval.choose_on_dev(_report({"smallest_first": (0.8, 0)})) == "smallest_first"
    tied = {"named_first": (0.7, 1), "bm25_per_token": (0.7, 0)}
    assert retrieval.choose_on_dev(_report(tied)) == "bm25_per_token"  # fewer with none kept
    level = {"named_first": (0.7, 0), "bm25_per_token": (0.7, 0)}
    assert retrieval.choose_on_dev(_report(level)) == "named_first"  # earlier in the list


def test_the_holdout_verdict_needs_a_clear_gain_and_no_more_reports_lost() -> None:
    assert retrieval.holdout_verdict(_report({}), "smallest_first") == "pass"
    assert retrieval.holdout_verdict(_report({}, cut_with_truth=9), "smallest_first") == (
        "inconclusive"
    )
    worse = _report({"smallest_first": (0.9, 3), "bm25": (0.5, 1)})
    assert retrieval.holdout_verdict(worse, "smallest_first") == "fail"
