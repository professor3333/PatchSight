"""Confidence tiers from two-model agreement, and the fallback union (proposal §6, step 5).

For each report, the extractor (primary) and a model of a different family (secondary)
answer independently. A report is **high** confidence only when all of these hold:

* both answers passed validation;
* the prompt was not truncated to the token budget;
* the symbol set is not empty, because "nothing is vulnerable" must never turn into
  "not called" for every user;
* the two answers agree under the chosen rule;
* at least one agreed function or entry point is **public** (an exported Go name, or a
  Python name without a leading underscore). A record whose symbols are all private
  helpers cannot support "not called": users reach a helper only through public APIs
  the record does not name.

Everything else is **low** confidence and, with the fallback union, predicts every changed
function. Uncertainty can therefore only add symbols, never remove them.

Agreement rules (open question 1). ``subset`` with the public-symbol condition was chosen on
the dev split (ADR 0004) and is the default:

* ``identical``: the same set; predicts it.
* ``subset``: one set contains the other; predicts their union.
* ``overlap``: Jaccard similarity of at least 0.5; predicts their union.
"""

from collections import Counter
from collections.abc import Mapping, Set
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.eval.metrics import SetScores, jaccard, score
from patchsight.eval.safety import SafetyScores, safety

AgreementRule = Literal["identical", "subset", "overlap"]
RULES: tuple[AgreementRule, ...] = ("identical", "subset", "overlap")
Tier = Literal["high", "low"]
VALID = frozenset({"ok", "repaired"})
CHOSEN_RULE: AgreementRule = "subset"
Language = Literal["go", "python"]


def is_public(name: str, language: Language) -> bool:
    """Whether users can call this name directly: an exported Go identifier, or a Python
    name without a leading underscore (dunder methods such as ``__init__`` count)."""
    leaf = name.split(".")[-1]
    if language == "go":
        return leaf[:1].isupper()
    return not leaf.startswith("_") or (leaf.startswith("__") and leaf.endswith("__"))


class Answer(BaseModel):
    """One model's validated outcome for one report."""

    model_config = ConfigDict(frozen=True)

    status: str
    vulnerable: frozenset[str]
    truncated: bool = False
    entry_points: frozenset[str] = frozenset()


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True)

    tier: Tier
    reason: str
    agreed: frozenset[str]
    # Agreed functions plus both models' entry points: what the scanner would match.
    symbols: frozenset[str] = frozenset()


def decide(
    primary: Answer,
    secondary: Answer | None,
    rule: AgreementRule = CHOSEN_RULE,
    require_public: bool = True,
    language: Language = "go",
) -> Decision:
    empty: frozenset[str] = frozenset()
    if primary.status not in VALID:
        return Decision(tier="low", reason="extractor answer failed validation", agreed=empty)
    if secondary is None or secondary.status not in VALID:
        return Decision(tier="low", reason="no valid second opinion", agreed=empty)
    if primary.truncated or secondary.truncated:
        return Decision(tier="low", reason="prompt truncated to the token budget", agreed=empty)
    a, b = primary.vulnerable, secondary.vulnerable
    if not a or not b:
        return Decision(tier="low", reason="an empty symbol set", agreed=empty)
    if rule == "identical":
        agrees, agreed = a == b, a
    elif rule == "subset":
        agrees, agreed = a <= b or b <= a, a | b
    else:
        agrees, agreed = jaccard(a, b) >= 0.5, a | b
    if not agrees:
        return Decision(tier="low", reason="the two models disagree", agreed=empty)
    symbols = agreed | primary.entry_points | secondary.entry_points
    if require_public and not any(is_public(name, language) for name in symbols):
        return Decision(
            tier="low", reason="no public symbol among the agreed answers", agreed=empty
        )
    return Decision(
        tier="high", reason=f"both models agree ({rule})", agreed=agreed, symbols=symbols
    )


class TierScores(BaseModel):
    rule: AgreementRule
    require_public: bool
    fallback: bool
    overall: SetScores
    high_reports: int
    high_share: float
    high: SetScores
    safety_overall: SafetyScores
    safety_high: SafetyScores
    low_reasons: dict[str, int]


def evaluate(
    primary: Mapping[str, Answer],
    secondary: Mapping[str, Answer],
    changed: Mapping[str, Set[str]],
    truth: Mapping[str, Set[str]],
    rule: AgreementRule,
    fallback: bool,
    require_public: bool = False,
    language: Language = "go",
) -> TierScores:
    """Score one configuration in two views.

    * **Benchmark view** (``overall``, ``high``): functions only, exact names. Without the
      fallback, low-confidence reports keep the extractor's own set.
    * **Safety view** (``safety_*``): functions plus entry points, lenient names. High
      confidence keeps the agreed symbols; low confidence keeps every changed function plus
      both models' entry points.
    """
    predicted: dict[str, set[str]] = {}
    high: dict[str, set[str]] = {}
    product: dict[str, set[str]] = {}
    product_high: dict[str, set[str]] = {}
    reasons: Counter[str] = Counter()
    for report, answer in primary.items():
        other = secondary.get(report)
        decision = decide(answer, other, rule, require_public, language)
        entry = set(answer.entry_points) | (set(other.entry_points) if other else set())
        if decision.tier == "high":
            predicted[report] = high[report] = set(decision.agreed)
            product[report] = product_high[report] = set(decision.symbols)
        else:
            reasons[decision.reason] += 1
            predicted[report] = set(changed[report]) if fallback else set(answer.vulnerable)
            product[report] = (set(changed[report]) if fallback else set(answer.vulnerable)) | entry
    reports = list(primary)
    truth_of = {r: set(truth[r]) for r in reports}
    return TierScores(
        rule=rule,
        require_public=require_public,
        fallback=fallback,
        overall=score(predicted, truth_of),
        high_reports=len(high),
        high_share=len(high) / len(reports) if reports else 0.0,
        high=score(high, {r: truth_of[r] for r in high}),
        safety_overall=safety(product, truth_of),
        safety_high=safety(product_high, {r: truth_of[r] for r in product_high}),
        low_reasons=dict(reasons.most_common()),
    )
