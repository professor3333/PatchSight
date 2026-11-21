"""Retrieval at the prompt budget: which candidates a cut prompt keeps, under each order."""

from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from patchsight.pipeline.benchmarks import retrieval
from patchsight.pipeline.benchmarks.retrieval import Bundle, Case, Item

REPO = Path(__file__).resolve().parents[1]


def _case(costs: list[int], vulnerable: set[int], bm25: list[int], names: list[str] | None = None,
          split: str = "dev") -> Case:  # fmt: skip
    names = names or [f"F{i}" for i in range(len(costs))]
    items = tuple(
        Item(name=names[i], path="x.go", tokens=c, vulnerable=i in vulnerable)
        for i, c in enumerate(costs)
    )
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
    assert [g.recall for g in dev.rankings] == [0.0, 0.5, 1.0]
    assert dev.rankings[0].reports_with_none_kept == 1
    assert dev.bm25_vs_file_order is not None
    assert dev.bm25_vs_file_order.recall_difference == -0.5
    assert dev.bm25_vs_file_order.second_keeps_more == 1
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


def test_the_committed_report_regenerates_exactly(tmp_path: Path) -> None:
    """CI recomputes the report from the frozen bundle alone: no diffs, no model."""
    from typer.testing import CliRunner

    from patchsight.pipeline.__main__ import app

    (tmp_path / "benchmarks").symlink_to(REPO / "benchmarks")
    result = CliRunner().invoke(app, ["retrieval-report", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    for suffix in (".md", ".json"):
        produced = (tmp_path / "docs" / "reports" / f"retrieval-dunlap-v1{suffix}").read_text()
        assert produced == (REPO / "docs" / "reports" / f"retrieval-dunlap-v1{suffix}").read_text()
