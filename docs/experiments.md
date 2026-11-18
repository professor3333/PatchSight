# Experiments

Every controlled experiment on the extraction system, including the ones that lost
(proposal §10). The rules:

- **One factor per experiment.** Everything else (prompt `extract-v1`, token budget, validator,
  candidate sets) stays fixed unless it is the factor.
- **Dev split only** (`splits/dunlap-v1.json`, 60 reports). The test split is used once per
  declared decision, never to choose between variants.
- **Every number links to a generated report** in `docs/reports/`. Reports are regenerated from
  cached answers, so re-running an experiment costs no model calls.
- **Selection rule:** among configurations within 2 F1 points of the best, choose the cheapest
  (tokens and seconds per report).

| # | Factor | Variants | Outcome | Status |
|---|---|---|---|---|
| E1 | Serving: 4-bit self-hosted against hosted | Qwen3.8-27B Q4_K_M on Kaggle; `qwen/qwen3.8-27b` on Groq | Kaggle not worse; Groq less reliable | Decided: Kaggle for the backfill |
| E2 | Extractor model family | Qwen3.8-27B; gpt-oss-120b | Qwen F1 0.676, gpt-oss 0.626 | Decided: Qwen extracts, gpt-oss is the second opinion |
| E3 | Confidence rule | 3 agreement rules, with and without a public symbol | `subset` + public symbol | Decided on dev; declared test evaluation: high-confidence miss 7.0%, target 2% **not met** ([ADR 0004](adr/0004-fall-back-to-the-baseline.md)) |
| E4 | Output-capacity cap | none; 105 output tokens per candidate | F1 unchanged; 1 more truncated report | Measured; adopt after the test evaluation |
| E5 | Run-to-run determinism (self-hosted) | two full Kaggle runs, two days apart | 277 of 277 answers identical | Confirmed |

## E1: 4-bit self-hosted against hosted serving

**Question.** Does the 4-bit model served with llama.cpp on Kaggle extract as well as the hosted
model on Groq? The backfill depends on it.

**Factor.** Serving: weights quantised to Q4_K_M with grammar-constrained decoding (Kaggle),
against Groq's hosted model with strict JSON-schema output. Same prompt, budget and validator.

| Dev, 60 reports | Precision | Recall | F1 (95% CI) | Miss rate | Answers valid | Provider rejections |
|---|---|---|---|---|---|---|
| Kaggle, Q4_K_M | 0.710 | 0.644 | 0.676 (0.57 to 0.78) | 21.7% | 59 of 59 | 0 |
| Groq, hosted | 0.625 | 0.636 | 0.630 (0.52 to 0.74) | 25.0% | 55 of 59 | 10 |

On the 55 reports both answered, F1 is 0.705 (Kaggle) against 0.670 (Groq): a difference of
+0.036, with a paired 95% interval of −0.003 to +0.079. 47 of 55 answers are identical, and in
all 8 that differ Groq's set contains Kaggle's: Groq is more inclusive.

Reports: [Kaggle](reports/extraction-dunlap-dev-extract-v1-qwen3.8-27b-q4km.md),
[Groq](reports/extraction-dunlap-dev-extract-v1-qwen3.8-27b.md),
[parity](reports/parity-dunlap-dev-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-qwen3.8-27b.md).

**Decision.** The 4-bit model shows no sign of being worse, so the Kaggle backfill uses it. No
tolerance was declared before the run, so the parity report gives no pass or fail. Groq
rejected 10 generations and dead-lettered 4 reports, against none on Kaggle, which argues for
grammar-constrained serving for nightly extraction too.

## E2: Extractor model family

**Question.** Which model family should extract, and which should give the second opinion?

**Factor.** The model: Qwen3.8-27B (Kaggle, Q4_K_M) against `openai/gpt-oss-120b` (Groq,
reasoning effort low, which cannot be switched off).

| Dev, 60 reports | Precision | Recall | F1 (95% CI) | Miss rate | Output tokens per report |
|---|---|---|---|---|---|
| Qwen3.8-27B | 0.710 | 0.644 | **0.676** (0.57 to 0.78) | 21.7% | 313 |
| gpt-oss-120b | 0.710 | 0.559 | 0.626 (0.52 to 0.73) | 23.3% | 368 |

Reports: [Qwen](reports/extraction-dunlap-dev-extract-v1-qwen3.8-27b-q4km.md),
[gpt-oss](reports/extraction-dunlap-dev-extract-v1-gpt-oss-120b.md).

**Decision.** Same precision; Qwen finds more and costs fewer output tokens, so Qwen extracts.
gpt-oss lost as an extractor but, as a different family, is the second opinion
([ADR 0005](adr/0005-two-model-families.md)).

**On test.** Both models later ran the 220 test reports, for the confidence evaluation (E3). The
ordering held:

| Test, 220 reports | Precision | Recall | F1 (95% CI) | Miss rate | Output tokens per report |
|---|---|---|---|---|---|
| Qwen3.8-27B | 0.763 | 0.615 | **0.681** (0.61 to 0.75) | 15.9% | 289 |
| gpt-oss-120b | 0.691 | 0.589 | 0.636 (0.57 to 0.71) | 16.8% | 357 |

Reports: [Qwen](reports/extraction-dunlap-test-extract-v1-qwen3.8-27b-q4km.md),
[gpt-oss](reports/extraction-dunlap-test-extract-v1-gpt-oss-120b.md).

## E3: Confidence rule

**Question.** When may a record be high confidence, so that "imported, not called" can be
claimed? The safety target is a high-confidence miss rate of 2% or less.

**Factor.** The rule combining the two models' answers: `identical`, `subset` or `overlap`
agreement, each with and without requiring a public symbol among the agreed answers. Anything
not high falls back to every changed function.

| Dev, 60 reports | Recall (safety view) | Miss rate | High-confidence reports | High-confidence miss rate |
|---|---|---|---|---|
| `identical` | 0.831 | 10.0% | 36 (60%) | 8.3% |
| `subset` | 0.831 | 10.0% | 49 (82%) | 8.2% |
| `overlap` | 0.831 | 10.0% | 45 (75%) | 6.7% |
| `identical` + public symbol | 0.864 | 8.3% | 18 (30%) | 5.6% |
| **`subset` + public symbol** | **0.864** | **8.3%** | **27 (45%)** | **3.7%** (1 of 27) |
| `overlap` + public symbol | 0.864 | 8.3% | 25 (42%) | 4.0% |

Report: [confidence tiers](reports/confidence-dunlap-dev-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-gpt-oss-120b.md).
The benchmark-view F1 of every configuration is about 0.38 to 0.40, because low-confidence
reports deliberately predict every changed function.

**Decision.** `subset` with a public symbol: the lowest high-confidence miss rate and the
highest recall. Agreement alone is not safe: both families often agree on a private helper the
fix changed while the true symbol is its exported caller. The 2% target is **not met**
(3.7%; Wilson 95% interval 0.7% to 18.3%). The rule is frozen, and its single test evaluation is
declared in ADR 0004.

**Test result (declared, run once).** On the 220 test reports the chosen rule makes 115 reports
(52%) high confidence, and 8 of them miss: **7.0%** (Wilson 95% interval 3.6% to 13.1%), so
the target is not met. Six of the eight are patch-ceiling cases (the labelled symbol is not
among the changed definitions), one is a model error and one is a label that differs only in
letter case. The public-symbol condition again halves the misses (16 of 183 without it). Report:
[confidence tiers, test](reports/confidence-dunlap-test-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-gpt-oss-120b.md);
every miss is listed in ADR 0004.

## E4: Output-capacity cap

**Question.** The token budget caps the prompt, not the answer. Does capping the number of
candidates, so that the answer always fits the 1,500-token output limit, cost accuracy?

**Factor.** `budget.output_tokens_per_candidate = 105`, so at most 14 candidates per prompt
(the dev maximum was 103 output tokens per answered candidate). Config:
[`configs/experiments/llm-output-cap-105.toml`](../configs/experiments/llm-output-cap-105.toml).
Run on Groq's Qwen, whose dev answers were already cached.

| Dev, 60 reports | Precision | Recall | F1 | Truncated prompts | Output tokens per report |
|---|---|---|---|---|---|
| No cap | 0.625 | 0.636 | 0.630 | 7 | 236 |
| Cap of 14 candidates | 0.625 | 0.636 | 0.630 | 8 | 232 |

Reports: [no cap](reports/extraction-dunlap-dev-extract-v1-qwen3.8-27b.md),
[cap](reports/extraction-dunlap-dev-extract-v1-qwen3.8-27b-cap105.md).

Two prompts changed (`GO-2021-0085`: 16 to 14 candidates; `GO-2023-2101`: 18 to 14), and both
answers named the same vulnerable symbols as before. `GO-2021-0085` is newly truncated, so it
could no longer be high confidence.

**Decision.** Adopt it: it removes the failure behind the Kaggle run's only dead letter
(`GO-2021-0053`, 24 candidates, both answers cut off at the output limit) at the cost of one
more truncated dev report. It is switched on only after the declared test evaluation, so that
evaluation keeps the setup it started with. In the PyPI backfill it changes 82 of 3,505 prompts.

## E5: Run-to-run determinism of self-hosted extraction

**Question.** Does the self-hosted pipeline give the same answers when run again (rule 12)?
Temperature 0, a fixed seed and grammar-constrained decoding should make it deterministic, but
GPU arithmetic does not guarantee that.

**Factor.** Only time and code version: two full runs of all 280 Dunlap reports on Kaggle
(Qwen3.8-27B Q4_K_M, llama.cpp `b12024`, two T4s). The first ran on 2026-11-15 at commit
`319b753`, the second on 2026-11-17 at commit `9a002a1`. Between them the BM25 ranking was made
deterministic, which changes no Dunlap prompt.

**Result.** **277 of 277 model answers are byte-for-byte identical**, and every score matches:
P 0.751, R 0.621, F1 0.680 and miss rate 17.1% on all reports, and the same on dev and test.

Provenance: [first run](reports/kaggle-run-extract-v1-qwen3.8-27b-q4km.json),
[second run](reports/kaggle-rerun-extract-v1-qwen3.8-27b-q4km.json).

**Decision.** None needed: self-hosted extraction is reproducible, so cached answers and
re-runs agree. Hosted serving (Groq) was not tested for this.

## Failure analysis

The causes of every benchmark error are in the failure reports
([all](reports/failures-dunlap-all-extract-v1-qwen3.8-27b-q4km.md),
[dev](reports/failures-dunlap-dev-extract-v1-qwen3.8-27b-q4km.md)). On dev, Qwen missed 42 true
symbols: 20 the fix never changed (the patch ceiling), 12 shown but judged not vulnerable,
8 dropped to fit the budget and 2 that differ only in name format. Next experiments are chosen
from the dev breakdown.

## Not run yet

- Prompt style, and 0, 3 or 5 examples (the Dunlap study found examples raise recall and lower
  precision).
- One call per advisory against one per function.
- A larger prompt budget on self-hosted serving (truncation causes 8 of 42 dev misses).
- gpt-oss-20b, self-hosted, as a faster second opinion for the PyPI backfill.
