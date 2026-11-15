# ADR 0004: Fall back to every changed function unless confidence is high

- **Status:** accepted. The rule was chosen on the dev split; the test-split evaluation is declared below.
- **Date:** 2026-11-16

## Context

Errors here have asymmetric costs. A wrong "imported, not called" can hide a real vulnerability, while a wrong "called" only costs a developer some time. The naive baseline, ChangedFuncs (every function the fix changed), is noisy but rarely silent.

The first full LLM run (`docs/reports/extraction-dunlap-all-extract-v1-qwen3.8-27b-q4km.md`) shows both sides:

- **Precise:** precision 0.751 against ChangedFuncs' 0.225.
- **But it misses more:** the miss rate (reports where no true symbol was found) is 17.1%, against 9.6%.

The extractor can't be trusted alone to *lower* an alert.

## Decision

Every record in the symbol database is either **high** or **low** confidence (`eval/confidence.py`).

A record is **high confidence** only if all of these hold:

1. the extractor's answer and the second opinion's answer (ADR 0005) both passed validation;
2. the prompt was not truncated to the token budget;
3. the symbol set is not empty;
4. the two answers agree under the **`subset`** rule: one model's set contains the other's, and the record keeps their union;
5. **at least one public symbol** is among the agreed functions or either model's entry points: an exported Go name, or a Python name without a leading underscore.

Condition 5 was added after the dev measurements below. When every agreed symbol is a private helper, users reach the bug only through public APIs the record does not name, so the record cannot support "not called".

A **low-confidence** record stores every changed function, plus any entry points. The scanner lets a low-confidence record make an alert CALLED, but never IMPORTED_NOT_CALLED (`scan/verdicts.py`).

## Evidence (dev split only, 60 reports)

From `docs/reports/confidence-dunlap-dev-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-gpt-oss-120b.md`. The safety view counts validated entry points, and matches names on a dotted boundary, so `Conn.decryptTicket` matches GoVulnDB's `decryptTicket`.

| Configuration | Recall | Miss rate | High-confidence reports | High-confidence miss rate |
|---|---|---|---|---|
| ChangedFuncs | 0.831 | 13.3% | none | n/a |
| Agreement only (`subset`) | 0.831 | 10.0% | 49 (82%) | 8.2% (4 of 49) |
| **`subset` + public symbol (chosen)** | **0.864** | **8.3%** | 27 (45%) | **3.7% (1 of 27)** |

- **Agreement alone is not safe.** The two model families often agree on a private helper that the fix changed, while GoVulnDB lists the exported caller: the "vulnerable function unchanged, callee changed" failure.
- **The public-symbol condition removes those cases from high confidence.** It also raises overall recall, because the demoted reports fall back to every changed function.
- **One miss remains** (`GO-2023-1623`). gpt-oss named the entry point `SetValue`, but the validator only accepts exact definition names, and the definition is `Paved.SetValue`, so the correct answer was dropped. Resolving entry points by dotted suffix is a planned validator change. It is not tuned into this decision.

## Target status

The proposal targets a high-confidence miss rate of **2% or less**. On dev it is 3.7% (1 of 27). With so few reports the interval is wide: 0.7% to 18.3% (Wilson 95%). **The target is not yet met**, and this ADR does not claim it.

## Declared test evaluation

The rule above is now frozen, and these steps are fixed before any test result exists:

1. Run the same second opinion (`openai/gpt-oss-120b`, prompt `extract-v1`) on the 220 test reports.
2. Run `confidence-report` once on the test split with the chosen configuration, and report the result as it stands, even if it is worse.
3. Any change to the rule after that is a new decision, chosen on dev, with a new declared test evaluation.

## Consequences

- **Coverage.** About 45% of records are high confidence, so many alerts will be UNKNOWN rather than IMPORTED_NOT_CALLED. That is the intended trade.
- **No lowering by low confidence.** A low-confidence record is never worse than the naive baseline at finding the vulnerable symbol, because it contains every changed function (a Hypothesis property in `tests/test_confidence.py`).
- **Unfixable by this design.** A vulnerable function that the fix did not change at all is still missed. Only entry points recover it, and the miss-rate floor is set by the patch, not by the model.
