import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight.eval.metrics import jaccard, score


def test_micro_scores_and_safety_metrics() -> None:
    truth = {"A": {"f", "g"}, "B": {"h"}, "C": {"k"}}
    predicted = {"A": {"f", "x", "y"}, "B": {"h"}}  # C has no prediction at all
    s = score(predicted, truth)
    assert (s.true_positives, s.false_positives, s.false_negatives) == (2, 2, 2)
    assert s.precision == pytest.approx(0.5)
    assert s.recall == pytest.approx(0.5)
    assert s.f1 == pytest.approx(0.5)
    assert s.miss_rate == pytest.approx(1 / 3)  # C missed entirely
    assert s.exact_match == pytest.approx(1 / 3)  # only B


def test_reports_outside_truth_are_ignored() -> None:
    s = score({"A": {"f"}, "Z": {"q"}}, {"A": {"f"}})
    assert (s.reports, s.false_positives, s.precision) == (1, 0, 1.0)


def test_empty_cases_do_not_divide_by_zero() -> None:
    s = score({}, {"A": set()})
    assert (s.precision, s.recall, s.f1, s.miss_rate) == (0.0, 0.0, 0.0, 0.0)


def test_bootstrap_is_seeded_and_brackets_the_estimate() -> None:
    truth = {f"R{i}": {"f", "g"} for i in range(40)}
    predicted = {f"R{i}": ({"f"} if i % 2 else {"f", "g", "x"}) for i in range(40)}
    first = score(predicted, truth, bootstrap=300, seed=1)
    again = score(predicted, truth, bootstrap=300, seed=1)
    assert first == again
    assert first.precision_ci95 is not None
    assert first.precision_ci95.low <= first.precision <= first.precision_ci95.high
    assert score(predicted, truth).precision_ci95 is None


@given(
    st.dictionaries(st.sampled_from("ABCDE"), st.sets(st.sampled_from("fghij"), max_size=4)),
    st.dictionaries(st.sampled_from("ABCDE"), st.sets(st.sampled_from("fghij"), max_size=4)),
)
def test_scores_are_bounded(predicted: dict[str, set[str]], truth: dict[str, set[str]]) -> None:
    s = score(predicted, truth)
    for value in (s.precision, s.recall, s.f1, s.miss_rate, s.exact_match):
        assert 0.0 <= value <= 1.0
    assert s.true_positives + s.false_negatives == sum(len(v) for v in truth.values())


def test_jaccard() -> None:
    assert jaccard(set(), set()) == 1.0
    assert jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)
