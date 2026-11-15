import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight.eval.confidence import Answer, decide, evaluate


def _a(*names: str, status: str = "ok", truncated: bool = False) -> Answer:
    return Answer(status=status, vulnerable=frozenset(names), truncated=truncated)


@pytest.mark.parametrize(
    ("primary", "secondary", "rule", "tier", "agreed"),
    [
        (_a("f"), _a("f"), "identical", "high", {"f"}),
        (_a("f"), _a("f", "g"), "identical", "low", set()),
        (_a("f"), _a("f", "g"), "subset", "high", {"f", "g"}),
        (_a("f", "g"), _a("g", "h"), "subset", "low", set()),
        (_a("f", "g"), _a("f", "g", "h"), "overlap", "high", {"f", "g", "h"}),
        (_a("f"), _a("g"), "overlap", "low", set()),
    ],
)
def test_agreement_rules(
    primary: Answer, secondary: Answer, rule: str, tier: str, agreed: set[str]
) -> None:
    decision = decide(primary, secondary, rule, require_public=False)  # type: ignore[arg-type]
    assert (decision.tier, set(decision.agreed)) == (tier, agreed)


@pytest.mark.parametrize(
    ("primary", "secondary", "reason"),
    [
        (_a(status="dead_letter"), _a("f"), "extractor answer failed validation"),
        (_a("f"), None, "no valid second opinion"),
        (_a("f"), _a("f", status="dead_letter"), "no valid second opinion"),
        (_a("f", truncated=True), _a("f"), "prompt truncated to the token budget"),
        (_a(), _a(), "an empty symbol set"),  # agreeing on "nothing" is never high
    ],
)
def test_conditions_that_force_low_confidence(
    primary: Answer, secondary: Answer | None, reason: str
) -> None:
    for rule in ("identical", "subset", "overlap"):
        decision = decide(primary, secondary, rule, require_public=False)  # type: ignore[arg-type]
        assert (decision.tier, decision.reason) == ("low", reason)


def test_fallback_replaces_low_confidence_with_every_changed_function() -> None:
    primary = {"A": _a("f"), "B": _a("x")}
    secondary = {"A": _a("f"), "B": _a("y")}  # B disagrees
    changed = {"A": {"f", "g"}, "B": {"x", "y", "z"}}
    truth = {"A": {"f"}, "B": {"z"}}
    with_fallback = evaluate(primary, secondary, changed, truth, "identical", fallback=True)
    without = evaluate(primary, secondary, changed, truth, "identical", fallback=False)
    assert (with_fallback.high_reports, with_fallback.high.miss_rate) == (1, 0.0)
    assert with_fallback.overall.miss_rate == 0.0  # B's true z comes back through the fallback
    assert without.overall.miss_rate == 0.5
    assert with_fallback.low_reasons == {"the two models disagree": 1}


_names = st.frozensets(st.sampled_from("abcdef"), max_size=4)


@given(primary=_names, secondary=_names, changed=_names)
def test_fallback_never_lowers_recall(
    primary: frozenset[str], secondary: frozenset[str], changed: frozenset[str]
) -> None:
    """Uncertainty can only add symbols: the fallback never recovers fewer true ones."""
    truth = {"R": set("abc")}
    candidates = {"R": set(changed | primary | secondary)}
    for rule in ("identical", "subset", "overlap"):
        on = evaluate(
            {"R": Answer(status="ok", vulnerable=primary)},
            {"R": Answer(status="ok", vulnerable=secondary)},
            candidates,
            truth,
            rule,
            True,
        )  # type: ignore[arg-type]
        off = evaluate(
            {"R": Answer(status="ok", vulnerable=primary)},
            {"R": Answer(status="ok", vulnerable=secondary)},
            candidates,
            truth,
            rule,
            False,
        )  # type: ignore[arg-type]
        assert on.overall.true_positives >= off.overall.true_positives


def test_a_public_symbol_is_required_for_high_confidence() -> None:
    private = decide(_a("normalizePath"), _a("normalizePath"))
    assert (private.tier, private.reason) == ("low", "no public symbol among the agreed answers")
    via_entry_point = decide(
        Answer(status="ok", vulnerable=frozenset({"normalizePath"}),
               entry_points=frozenset({"NewRequestHandler"})),
        _a("normalizePath"),
    )  # fmt: skip
    assert via_entry_point.tier == "high"
    assert set(via_entry_point.symbols) == {"normalizePath", "NewRequestHandler"}


@pytest.mark.parametrize(
    ("name", "language", "public"),
    [
        ("Reader.Read", "go", True), ("Reader.init", "go", False), ("ParseHeader", "go", True),
        ("pkg.loader.load", "python", True), ("pkg.loader._load", "python", False),
        ("pkg.Loader.__init__", "python", True),
    ],
)  # fmt: skip
def test_is_public(name: str, language: str, public: bool) -> None:
    from patchsight.eval.confidence import is_public

    assert is_public(name, language) is public  # type: ignore[arg-type]


def test_safety_view_counts_entry_points_and_lenient_names() -> None:
    from patchsight.eval.safety import lenient_match, safety

    assert lenient_match("Conn.decryptTicket", "decryptTicket")
    assert lenient_match("syscall.ForkExec", "ForkExec")
    assert not lenient_match("forkExec", "ForkExec")
    s = safety(
        {"A": {"Conn.decryptTicket"}, "B": {"helper"}}, {"A": {"decryptTicket"}, "B": {"Run"}}
    )
    assert (s.truth_found, s.miss_rate) == (1, 0.5)
