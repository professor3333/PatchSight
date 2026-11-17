"""Failure causes: each missed symbol gets exactly one cause, in a fixed order."""

import pytest

from patchsight.eval.failures import ReportInput, breakdown, miss_cause


def _report(**fields: object) -> ReportInput:
    base: dict[str, object] = {
        "truth": frozenset({"Conn.decryptTicket"}),
        "changed": frozenset({"Conn.decryptTicket", "helper"}),
        "shown": frozenset({"Conn.decryptTicket", "helper"}),
        "status": "ok",
        "predicted": frozenset({"helper"}),
    }
    base.update(fields)
    return ReportInput.model_validate(base)


@pytest.mark.parametrize(
    ("fields", "cause"),
    [
        ({"changed": frozenset({"helper"})}, "not_changed"),
        ({"changed": frozenset(), "status": "no_candidates"}, "not_changed"),
        ({"truth": frozenset({"decryptTicket"})}, "name_format"),
        ({"status": "dead_letter", "predicted": frozenset()}, "dead_letter"),
        ({"shown": frozenset({"helper"})}, "truncated"),
        ({}, "model_missed"),
    ],
)
def test_each_miss_gets_one_cause_in_order(fields: dict[str, object], cause: str) -> None:
    report = _report(**fields)
    (symbol,) = report.truth
    assert miss_cause(symbol, report) == cause


def test_breakdown_counts_symbols_reports_and_false_positives() -> None:
    result = breakdown(
        {
            "A": _report(),  # missed although shown; "helper" is a false positive
            "B": _report(predicted=frozenset({"Conn.decryptTicket"})),  # found
            "C": _report(
                truth=frozenset({"decryptTicket", "Other.run"}),
                predicted=frozenset({"Conn.decryptTicket"}),
            ),
        }
    )
    assert result.truth_symbols == 4
    assert result.false_negatives["model_missed"] == 1
    assert result.false_negatives["name_format"] == 1  # C: decryptTicket vs Conn.decryptTicket
    assert result.false_negatives["not_changed"] == 1  # C: Other.run
    assert result.false_positives == {"name_format": 1, "model_false_positive": 1}
    assert sum(result.report_misses.values()) == 2  # A and C found no exact true symbol
    assert result.report_misses["model_missed"] == 1
    assert result.examples["model_missed"] == ("A",)
