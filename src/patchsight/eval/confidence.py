"""Confidence tiers from two-model agreement, and the fallback union (proposal §6, step 5).

For each report, the extractor (primary) and a model of a different family (secondary)
answer independently. A report is **high** confidence only when all of these hold:

* both answers passed validation;
* the prompt was not truncated to the token budget;
* the symbol set is not empty, because "nothing is vulnerable" must never turn into
  "not called" for every user;
* the two answers agree under the chosen rule.

Everything else is **low** confidence and, with the fallback union, predicts every changed
function. Uncertainty can therefore only add symbols, never remove them.

Agreement rules (open question 1, chosen on the dev split only):

* ``identical``: the same set; predicts it.
* ``subset``: one set contains the other; predicts their union.
* ``overlap``: Jaccard similarity of at least 0.5; predicts their union.
"""

from collections import Counter
from collections.abc import Mapping, Set
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.eval.metrics import SetScores, jaccard, score

AgreementRule = Literal["identical", "subset", "overlap"]
RULES: tuple[AgreementRule, ...] = ("identical", "subset", "overlap")
Tier = Literal["high", "low"]
VALID = frozenset({"ok", "repaired"})


class Answer(BaseModel):
    """One model's validated outcome for one report."""

    model_config = ConfigDict(frozen=True)

    status: str
    vulnerable: frozenset[str]
    truncated: bool = False


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True)

    tier: Tier
    reason: str
    agreed: frozenset[str]


def decide(primary: Answer, secondary: Answer | None, rule: AgreementRule) -> Decision:
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
    return Decision(tier="high", reason=f"both models agree ({rule})", agreed=agreed)


class TierScores(BaseModel):
    rule: AgreementRule
    fallback: bool
    overall: SetScores
    high_reports: int
    high_share: float
    high: SetScores
    low_reasons: dict[str, int]


def evaluate(
    primary: Mapping[str, Answer],
    secondary: Mapping[str, Answer],
    changed: Mapping[str, Set[str]],
    truth: Mapping[str, Set[str]],
    rule: AgreementRule,
    fallback: bool,
) -> TierScores:
    """Score one rule. Without the fallback, low-confidence reports keep the extractor's set."""
    predicted: dict[str, set[str]] = {}
    high: dict[str, set[str]] = {}
    reasons: Counter[str] = Counter()
    for report, answer in primary.items():
        decision = decide(answer, secondary.get(report), rule)
        if decision.tier == "high":
            predicted[report] = set(decision.agreed)
            high[report] = set(decision.agreed)
        else:
            reasons[decision.reason] += 1
            predicted[report] = set(changed[report]) if fallback else set(answer.vulnerable)
    reports = list(primary)
    return TierScores(
        rule=rule,
        fallback=fallback,
        overall=score(predicted, {r: set(truth[r]) for r in reports}),
        high_reports=len(high),
        high_share=len(high) / len(reports) if reports else 0.0,
        high=score(high, {r: set(truth[r]) for r in high}),
        low_reasons=dict(reasons.most_common()),
    )
