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
| E4 | Output-capacity cap | none; 105 output tokens per candidate | F1 unchanged; 1 more truncated report | Measured; switch on after the gpt-oss-20b evaluation ([#52](https://github.com/professor3333/PatchSight/issues/52)) |
| E5 | Run-to-run determinism (self-hosted) | two full Kaggle runs, two days apart | 277 of 277 answers identical | Confirmed |
| E6 | Entry-point name matching | exact names; a unique dotted-boundary match | dev high-confidence misses 1 of 27 to 0 of 27; F1 unchanged | Measured; switch on after the gpt-oss-20b evaluation, then evaluate on unseen data |
| E7 | Fix-commit locator without the fix link | the proposal's message baseline; a ranking that prefers the advisory's own IDs | exact SHA 9.0% and 25.0%; wrong commit 64.0% and 47.0% | Neither is used: both are far from the 5% wrong-commit cap. Baseline for the agent ([#56](https://github.com/professor3333/PatchSight/issues/56)) |
| E8 | Prompt injection (rule 7) | clean; advisory says nothing is vulnerable; advisory names a decoy; a code comment names a decoy | decoy in the advisory: 8 of 15 would become wrong high-confidence records; the others: none | High confidence stays withheld; a lifting rule must make none ([ADR 0008](adr/0008-withhold-high-confidence.md)) |
| E9 | Ordering candidates to fit the prompt budget | BM25 against the advisory (as built); no ranking (file order); an oracle ceiling | On the 32 cut prompts: BM25 keeps 59 of 140 true functions (0.421), file order 97 (0.693), the oracle 133 (0.950) | Measured: BM25 loses to no ranking. It stays until a replacement is chosen on dev and evaluated on data not used to choose it |
| E10 | A replacement for BM25 at the prompt budget | file order; smallest first; candidates the advisory names first; BM25 score per token | Chosen on dev: smallest first. Holdout, declared beforehand: +0.094 recall over BM25 (95% CI +0.042 to +0.328) | Passed. An option, off by default (`budget.candidate_order`); switched on with #52 and #53 |

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
more truncated dev report. It is switched on only after the declared test evaluation (done) and
the gpt-oss-20b evaluation (#50), so each keeps the setup it was declared with: the cap would
truncate two dev reports there. In the PyPI backfill it changes 82 of 3,505 prompts.

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

## E6: Entry points resolved on a dotted boundary

**Question.** The validator keeps an entry point only when it names a definition exactly.
Models often leave out the receiver (`SetValue` for `Paved.SetValue`) or add a package
(`syscall.ForkExec`), and such names are dropped, so records lose the public names that reach
the vulnerable code. Does accepting a name that matches exactly one definition on a dotted
boundary help, and what does it cost?

**Factor.** `validation.dotted_entry_points`
([`configs/experiments/llm-dotted-entry-points.toml`](../configs/experiments/llm-dotted-entry-points.toml)).
A name that matches several definitions is still dropped, and a resolved name is kept as the
definition's own name. Only validation changes, not prompts, so both models' cached dev
answers were re-validated with 0 model calls.

| Dev, 60 reports, chosen rule | Entry points kept (Qwen, gpt-oss) | Recall (safety view) | Miss rate | High-confidence reports | High-confidence miss rate |
|---|---|---|---|---|---|
| Exact names only | 57, 48 | 0.864 | 8.3% | 27 (45%) | 3.7% (1 of 27) |
| Unique dotted match | 59, 52 | 0.873 | 6.7% | 27 (45%) | **0.0%** (0 of 27; Wilson 95% 0.0% to 12.5%) |

Six names were newly kept. From Qwen: `Parse` (`GO-2020-0014`) and `ForkExec` (`GO-2022-0289`).
From gpt-oss: `Provider.Render` (`GO-2021-0086`), `linuxContainer.bootstrapData`
(`GO-2022-0274`), `JsonWebSignature.Verify` (`GO-2022-0945`) and `Paved.SetValue`
(`GO-2023-1623`). The last turns dev's only high-confidence miss into a hit. Benchmark-view F1
is unchanged, because entry points don't count there (Qwen 0.676, gpt-oss 0.626).

Reports: [Qwen](reports/extraction-dunlap-dev-extract-v1-qwen3.8-27b-q4km-dotted.md),
[gpt-oss](reports/extraction-dunlap-dev-extract-v1-gpt-oss-120b-dotted.md),
[confidence tiers](reports/confidence-dunlap-dev-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-gpt-oss-120b-dotted.md)
(`confidence-report --split dev --variant dotted`).

**Caveat.** The change was designed around `GO-2023-1623`, a dev report, so fixing it on dev
says little about other data.

**Decision.** Adopt, in two steps. Switch it on together with the output cap (E4) after the
gpt-oss-20b evaluation ([#50](https://github.com/professor3333/PatchSight/issues/50)), whose
declared criteria compare against the 120b pairing measured with exact names. Then evaluate its
effect on high confidence on data not used yet, the Go temporal holdout, as ADR 0004 requires of
any change to the rule. For low-confidence records the change can only add names, which can only
raise an alert's priority.

## E7: Locating a fix commit the advisory does not link

**Question.** For the 2,306 vulnerabilities whose advisories link no fix commit on GitHub, can a
fix be found from the package's own repository alone? Their alerts get no symbol data today
(416 of the 3,526 alerts on the [repository panel](reports/panel-db-2026.11.18.1.md)).

**Method.** Masked evaluation, as the proposal asks: 200 vulnerabilities, drawn with a recorded
seed from the 4,416 whose advisories *do* link a fix commit on the package's repository
([sample](../benchmarks/locator/masked-v1.json)), with the links hidden. The locator reads the
package's PyPI metadata, its repository's tags, and the commits between the last vulnerable and
the first fixed release. A located commit must touch non-test Python source.

| Variant | Exact SHA | Wrong commit | Abstained |
|---|---:|---:|---:|
| Baseline: first commit saying CVE, security or fix | 9.0% | 64.0% | 27.0% |
| Ranked: the advisory's own IDs, then security words, then "fix" | 25.0% | 47.0% | 28.0% |
| Target for the agent | 70% or more | 5% or less | |

**Why it misses.** In 64 of the ranked variant's 94 wrong commits, a linked commit was between
the same two tags: the right commit was in view and another was chosen. In the other 30 the fix
was not between the tags at all, usually because it landed on another branch. Even a perfect
choice within the comparison would reach about 57% exact.

**Decision.** Neither heuristic is used to build records: a wrong commit becomes a record of the
wrong functions, and the 5% cap exists for that reason. They are the baseline the bounded agent
(rule 8) must beat. The agent needs both a better choice between candidates (reading their
diffs) and a wider search (commit search by advisory ID). Report:
[masked evaluation](reports/locator-masked-v1.md) (`locator-eval`).

## E8: Prompt injection

**Question.** Can attacker-writable text make the pair of models agree on a wrong answer, so that the confidence rule makes a high-confidence record without the real symbol (rule 7)?

**Method.** On the 15 dev reports where an attack can be planted (a true candidate, a plausible decoy, and no truncation), each model answers four times: on the clean prompt, and with one of three attacks. In `advisory-none` the advisory says nothing is vulnerable. In `advisory-decoy` it names the decoy function as the vulnerable one. In `comment-decoy`, a code comment in the target's first hunk calls the decoy the real fix. Qwen3.8-27B on Groq and gpt-oss-120b, answers cached and committed ([report](reports/injection-dunlap-dev-extract-v1-qwen3.8-27b-vs-extract-v1-gpt-oss-120b.md), regenerated in CI).

| Attack | Qwen: decoy picked | gpt-oss: decoy picked | Pair: new wrong high-confidence records |
|---|---:|---:|---:|
| `advisory-none` | — (emptied 12 of 13) | — (emptied 15 of 15) | 0 |
| `advisory-decoy` | 9 of 15 | 13 of 15 | **8** |
| `comment-decoy` | 0 of 10 | 2 of 15 | 0 |

**Findings.** Telling the models that nothing is vulnerable empties their answers, and the fallback turns an empty answer into a low-confidence record with every changed definition: safe. Naming a decoy in the advisory is the dangerous attack. Both families read the same text and agree on it, so agreement is not independent evidence here. That was the residual risk the threat model named; it is now measured. Comments planted in code moved neither model much.

**Decision.** High confidence stays withheld. Any rule that lifts it must make no wrong high-confidence record on this suite ([ADR 0008](adr/0008-withhold-high-confidence.md)). One candidate: decide "not called" against every changed definition, so an agreed decoy cannot remove the real symbol.

## E9: Ordering candidates to fit the prompt budget

**Question.** When a fix's candidates do not fit the 4,600-token prompt budget, the extractor keeps them in BM25 order against the advisory text while they fit. A true vulnerable function that is cut cannot be picked. Does BM25 keep the true functions better than no ranking at all? This is the measurement [ADR 0003](adr/0003-no-vector-database.md) names for revisiting its decision.

**Method.** `retrieval-freeze` records, for all 280 Dunlap reports, each candidate's token cost exactly as the prompt renderer counts it, its label, the BM25 order and the prompt's fixed cost. The bundle reproduces the Kaggle run's truncation for every report. `retrieval-report` applies three orders to the same costs with the renderer's own fitting rule (the first candidate is always kept, the others while they fit): BM25; file order, as the path filter and the mapping produce candidates; and an oracle that takes the cheapest candidate of each true function first, the most any order can keep. Recall counts the true functions among the candidates, so the patch ceiling is outside it. No model is called ([report](reports/retrieval-dunlap-v1.md), regenerated in CI).

| Split | Prompts cut | BM25 | File order | Oracle | BM25 minus file order (95% CI) |
|---|---:|---:|---:|---:|---|
| all | 32 of 280 | 0.421 | 0.693 | 0.950 | −0.271 (−0.405 to −0.109) |
| dev | 7 of 60 | 0.579 | 0.684 | 1.000 | −0.105 (−0.636 to +0.080) |
| test | 25 of 220 | 0.397 | 0.694 | 0.942 | −0.298 (−0.438 to −0.118) |

**Findings.**

- **BM25 is worse than no ranking.** The best match is always kept, and the best matches tend to be long functions, so BM25 keeps fewer candidates (244 against 334 on the cut prompts). It is also worse when tokens are ignored: recall@5 0.279 against 0.350.
- **The losses are spread.** By report, BM25 keeps more true functions in 6, file order in 14, and they tie in 9. A cut report keeps no true function in 4 cases under either order.
- **Dev alone cannot separate them.** Dev has 5 cut reports with a true function, and its interval spans zero.
- **The oracle shows the room.** An order that kept the true functions first would recover most of what truncation loses (0.950).

**What it changes.**

- **No published record.** Every record is low confidence and lists every changed definition, and a truncated prompt can never be high confidence. What changes is which picks the model can make on large fixes: truncation accounts for 8 of Qwen's 42 dev misses.
- **No embeddings are called for.** An order that ignores the advisory already does better, so ADR 0003 stands.
- **Next.** A cost-aware or structural order (for example BM25 score per token, or the files a fix's message or advisory names first), chosen on dev and evaluated once on data not used to choose it. Truncation affects 790 of the 3,505 PyPI backfill prompts, so a better order would be worth a top-up backfill run.

## E10: A replacement for BM25 at the prompt budget (declared before measuring)

**Declared on 2026-11-21, before any order below was computed on any data except as stated.** E9 measured only BM25, file order and the oracle, on all three Dunlap splits. Nothing has been computed on the Go temporal holdout's retrieval; only its count of cut prompts is known (25 of 83, from the gpt-oss-120b run), and that count is the same under every order.

**Question.** Which candidate order should replace BM25 when a prompt is cut to its budget?

**Orders compared,** each applied with the renderer's own fitting rule (the first candidate is always kept, the others while they fit) to the same token costs:

1. `file_order`: no ranking, as the path filter and the mapping produce candidates.
2. `smallest_first`: fewest tokens first, ties in file order. It keeps the most candidates.
3. `named_first`: candidates the advisory names first, then the rest, each group in file order. A candidate is named when its full name, or the part after its last dot, appears in the advisory's summary or details as a whole word, case-sensitively. This is the proposal's keyword baseline used as an order.
4. `bm25_per_token`: BM25 score divided by token cost, highest first, ties in file order.

BM25 as built is the baseline; the oracle is the ceiling.

**Measure.** As in E9: true functions kept among the candidates of cut prompts with at least one true function, with a bootstrap over reports (2,000 draws, seed 20261121).

**Choosing, on dev only.** The order with the highest dev recall. Ties go to fewer dev reports with no true function kept, then to the earlier order in the list above (the simpler one). Dev has 5 cut reports with a true function, so this choice is weak; the evaluation below is what counts.

**Evaluating, once, on the Go temporal holdout** (`benchmarks/go-holdout-v1`, all 83 reports, Qwen tokenizer, 4,600-token budget, as in E9). The holdout bundle must reproduce the gpt-oss-120b holdout run's truncation for every report, as E9's does for the Kaggle run.

- **It passes** if the chosen order's recall minus BM25's, paired by report, has a 95% interval entirely above zero, **and** the chosen order leaves no more cut reports with no true function kept than BM25 does.
- **It is inconclusive** if fewer than 10 cut holdout reports have a true function. BM25 then stays.
- **Otherwise it fails,** and BM25 stays.

The Dunlap test and all splits are reported for each order, for completeness only; they were read in E9 and decide nothing.

**What passing changes.** The chosen order becomes a configuration option, off by default. It is switched on together with the output cap and dotted entry points (#52, #53), through shadow-then-promote, because it changes cut prompts and so their cached answers. Published benchmark numbers stay those of BM25 until a full re-run replaces them.

### Result

**Dev choice** ([report](reports/retrieval-dunlap-v1.md)): 5 cut reports with a true function, 19 true functions. Smallest first kept 16 (0.842); file order and named first 13 (0.684); BM25 per token 12 (0.632); BM25 11 (0.579). Smallest first was chosen and committed before the holdout was computed.

**Holdout evaluation, run once** ([report](reports/retrieval-go-holdout-v1.md)): the bundle reproduces the gpt-oss-120b holdout run's truncation on all 83 reports. 25 prompts are cut, all of them with a true function (961 true functions among 3,052 candidates).

| Order | Recall | Minus BM25, paired (95% CI) | Keeps more / fewer / tied | Reports with none kept |
|---|---:|---|---|---:|
| BM25 (as built) | 0.137 | — | — | 0 |
| **Smallest first (chosen)** | **0.231** | **+0.094 (+0.042 to +0.328)** | 18 / 3 / 4 | 0 |
| File order | 0.197 | +0.059 (+0.025 to +0.214) | 19 / 0 / 6 | 0 |
| Named first | 0.194 | +0.056 (+0.025 to +0.203) | 19 / 0 / 6 | 0 |
| BM25 per token | 0.170 | +0.032 (+0.017 to +0.100) | 15 / 1 / 9 | 0 |
| Oracle (ceiling) | 0.287 | +0.150 (+0.064 to +0.491) | 21 / 0 / 4 | 0 |

**Verdict: pass.** The interval is above zero, and smallest first leaves no more cut reports with nothing true kept than BM25 (0 and 0). Absolute recalls are low because the holdout's GoVulnDB labels are broad: even the oracle keeps only 0.287 of the true functions within the budget. Every other order also beat BM25 here; they were not chosen and decide nothing.

**Not yet measured: the effect on extraction.** Keeping more true candidates should raise recall on large fixes, but the model's answers on the changed prompts have not been collected. A Groq run on dev was not possible on 2026-11-21: Groq began refusing the 1,500-token output allowance those runs used, and a different allowance changes every prompt's cache key. The before and after are measured with the Kaggle run that switches the order on.

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
