import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight.eval.parity import parity

TRUTH = {"A": {"f"}, "B": {"g"}, "C": {"h"}, "D": {"k"}}


def test_failed_reports_are_listed_and_left_out_of_the_paired_scores() -> None:
    reference = {"A": {"f"}, "B": {"g"}, "C": {"h"}, "D": None}
    candidate = {"A": {"f", "x"}, "B": {"g"}, "C": None, "D": {"k"}}
    p = parity(reference, candidate, TRUTH, bootstrap=200)
    assert (p.reference_failed, p.candidate_failed) == (("D",), ("C",))
    assert p.paired == 2
    assert p.reference.reports == p.candidate.reports == 2
    assert p.reference.f1 == pytest.approx(1.0)
    assert p.candidate.precision == pytest.approx(2 / 3)
    assert p.f1_difference == pytest.approx(1.0 - 0.8)


def test_containment_direction_of_differing_answers() -> None:
    reference = {"A": {"f"}, "B": {"g", "y"}, "C": {"h"}, "D": {"k"}}
    candidate = {"A": {"f", "x"}, "B": {"g"}, "C": {"z"}, "D": {"k"}}
    p = parity(reference, candidate, TRUTH, bootstrap=0)
    assert p.identical == 1
    assert p.differing == ("A", "B", "C")
    assert (p.candidate_adds_only, p.candidate_drops_only, p.both_add_and_drop) == (1, 1, 1)


def test_missing_report_counts_as_failed() -> None:
    p = parity({"A": {"f"}}, {"A": {"f"}}, {"A": {"f"}, "B": {"g"}}, bootstrap=0)
    assert p.reference_failed == p.candidate_failed == ("B",)
    assert p.paired == 1


def test_no_paired_reports_does_not_divide_by_zero() -> None:
    p = parity({"A": None}, {"A": {"f"}}, {"A": {"f"}}, bootstrap=100)
    assert (p.paired, p.f1_difference, p.f1_difference_ci95.low) == (0, 0.0, 0.0)


names = st.frozensets(st.sampled_from("abcdef"), max_size=4)


@given(st.dictionaries(st.sampled_from("PQRSTU"), st.tuples(names, names, names), min_size=1))
def test_identical_runs_have_zero_difference(rows: dict[str, tuple[frozenset[str], ...]]) -> None:
    truth = {r: t for r, (t, _, _) in rows.items()}
    answers = {r: a for r, (_, a, _) in rows.items()}
    p = parity(answers, answers, truth, bootstrap=50)
    assert p.f1_difference == 0.0
    assert p.differing == ()
    assert p.f1_difference_ci95.low == p.f1_difference_ci95.high == 0.0


@given(st.dictionaries(st.sampled_from("PQRSTU"), st.tuples(names, names, names), min_size=1))
def test_difference_is_antisymmetric(rows: dict[str, tuple[frozenset[str], ...]]) -> None:
    truth = {r: t for r, (t, _, _) in rows.items()}
    first = {r: a for r, (_, a, _) in rows.items()}
    second = {r: b for r, (_, _, b) in rows.items()}
    forward, backward = parity(first, second, truth, 0), parity(second, first, truth, 0)
    assert forward.f1_difference == pytest.approx(-backward.f1_difference)
    assert forward.candidate_adds_only == backward.candidate_drops_only
