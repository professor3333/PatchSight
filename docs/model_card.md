# Model card: PatchSight's symbol extractor

PatchSight trains no model. This card describes the **extraction system**: open-weight models, a versioned prompt and deterministic validators that read a public fix commit and name the functions and classes that carry a vulnerability. Its output is the [symbol database](dataset_card.md). Every number below was measured in this repository; the reports are linked.

## Intended use

Given a public PyPI advisory and its fix commit, name the vulnerable functions, methods and classes and the public entry points that reach them, each citing the diff hunks it rests on, with a confidence tier. The database built from this ranks dependency alerts by static call-site evidence: `patchsight scan` checks whether your code references those names.

## Not for

- **Declaring an application not vulnerable,** or suppressing, closing or deprioritising alerts without human review.
- **Reading "not imported", "unknown" or missing symbol data as "not affected".**
- **Writing VEX statements** without explicit human approval.
- **Private advisories or private code.** The models see only public advisories and public diffs; user code never reaches a model.
- **Other ecosystems,** until they are measured. The benchmark is Go and the database is PyPI.
- **Replacing version matching** (OSV-Scanner, pip-audit). PatchSight sits on top of it.

## Models

| Role | Model | Serving | Licence |
|---|---|---|---|
| Extractor (backfill and benchmark) | Qwen3.8-27B, `ggml-org/Qwen3.8-27B-GGUF@c1869413`, Q4_K_M (SHA-256 `d15d4b6d…`) | llama.cpp `b12024` (official CUDA 12.8 build), two T4 GPUs on Kaggle | Apache 2.0 |
| Extractor (dev parity check) | `qwen/qwen3.8-27b` | Groq, `reasoning_effort: none` | Apache 2.0 |
| Second opinion | `openai/gpt-oss-120b` | Groq, `reasoning_effort: low` (it can't be switched off) | Apache 2.0 |
| Proposed second opinion ([ADR 0007](adr/0007-self-hosted-second-opinion.md), not adopted) | `ggml-org/gpt-oss-20b-GGUF@41e8a94d`, MXFP4 | llama.cpp on Kaggle | Apache 2.0 |

Licences as listed on each model's Hugging Face page, checked 2026-11-18. Exact model IDs, revisions and quantisation are in [`configs/llm.toml`](../configs/llm.toml) and in every report.

**Decoding:** temperature 0, seed `20261114`, at most 1,500 output tokens, no chain-of-thought. Output is held to a JSON schema: Groq's strict schema mode, and grammar-constrained decoding on llama.cpp.

**Prompt:** [`prompts/extract_v1.md`](../prompts/extract_v1.md), version `extract-v1`. The advisory text and the numbered candidates (`F1`…), each with its hunks (`H1`…), sit inside labelled delimiters as untrusted data. At most 4,600 prompt tokens, counted with the model's own tokenizer; beyond that, candidates are ranked with BM25 against the advisory text and the prompt is marked truncated.

**Provenance on every record:** model ID, second-opinion model, prompt version, input hash, the advisory's `modified` time, truncation flag and extraction time. Each release also records the code commit and the snapshot's SHA-256.

## Data

- **Inputs:** the advisory's summary and details, and the fix diff after the path filter (tests, docs, changelogs and vendored code removed), mapped to changed definitions with tree-sitter.
- **Evaluation data:** the Dunlap et al. Go benchmark, 280 reports with GoVulnDB's curated vulnerable symbols, split into dev (60 reports) and test (220) in [`splits/dunlap-v1.json`](../splits/dunlap-v1.json), frozen and SHA-checked before any prompt work. Reports that share a fix commit stay in one split.
- **No few-shot examples,** so no evaluation report can leak into a prompt.
- **Go temporal holdout** ([ADR 0010](adr/0010-go-temporal-holdout.md)): 83 GoVulnDB reports published after 2026-08-13, the day the extractor's weights were released, so neither model can have seen them. Frozen, with its evaluation declared before any model run. ChangedFuncs on it: [baseline](reports/changedfuncs-go-holdout-v1.md). Its labels are broader than the 2023 benchmark's (exported callers are listed too), so its scores do not compare with the Dunlap ones.
- **Python gold set, in progress** ([#54](https://github.com/professor3333/PatchSight/issues/54)): 60 declared entries from a seeded sample of 120 PyPI advisories, labelled twice by one annotator. Round 1 is done; its scores are reported after round 2, with self-agreement. The [PyPI regression set](../benchmarks/pypi-regression-v1/README.md) replays 50 recorded answers through the live code on every push, to catch changes in validation, naming and record building. Neither model card states a knowledge cutoff, so the 2023 benchmark may be in the models' training data; the holdout controls for that.

## Metrics

### Extraction (Dunlap Go benchmark, function level)

| System | Split | Precision | Recall | F1 (95% CI) | Miss rate |
|---|---|---|---|---|---|
| ChangedFuncs (every changed function) | all | 0.225 | 0.893 | 0.360 | 9.6% |
| Best open model in Dunlap et al. (Mixtral 8x7B), as published | all | 0.60 | 0.74 | 0.66 | n/a |
| **Qwen3.8-27B Q4_K_M** | all | **0.751** | **0.621** | **0.680** (0.62 to 0.74) | 17.1% |
| Qwen3.8-27B Q4_K_M | test | 0.763 | 0.615 | 0.681 (0.61 to 0.75) | 15.9% |
| gpt-oss-120b | test | 0.691 | 0.589 | 0.636 (0.57 to 0.71) | 16.8% |

Intervals are bootstrapped over reports. The miss rate is the share of reports where no labelled symbol was returned. Reports: [Qwen, all](reports/extraction-dunlap-all-extract-v1-qwen3.8-27b-q4km.md), [Qwen, test](reports/extraction-dunlap-test-extract-v1-qwen3.8-27b-q4km.md), [gpt-oss, test](reports/extraction-dunlap-test-extract-v1-gpt-oss-120b.md). Rebuild the table with `make reproduce`.

### Reliability (Qwen on Kaggle, all 280 reports)

- **Schema-valid after one repair:** 275 of the 276 reports that had candidates (99.6%; target 99%). The one dead letter had 24 candidates, and both answers hit the output limit.
- **Invented candidate IDs before validation:** 0. **Entry points:** 242 of the 251 named resolved to a definition (96.4%); the other 9 were dropped.
- **Citations after validation:** every cited hunk exists and lies inside its symbol, enforced by the validator.
- **Provider rejections:** 0 on llama.cpp. On Groq, the same model's dev run had 10 rejected generations and 4 dead letters out of 60 reports ([E1](experiments.md#e1-4-bit-self-hosted-against-hosted-serving)).
- **Determinism:** a second Kaggle run gave byte-identical answers for 277 of 277 calls ([E5](experiments.md#e5-run-to-run-determinism-of-self-hosted-extraction)).

### Confidence tiers (safety view)

High confidence needs both families valid, an untruncated prompt, `subset` agreement and a public symbol ([ADR 0004](adr/0004-fall-back-to-the-baseline.md)). The rule was chosen on dev and evaluated once on test, as declared beforehand.

| Split | High-confidence reports | High-confidence miss rate | Target |
|---|---|---|---|
| dev | 27 of 60 (45%) | 3.7% (1 of 27; Wilson 95% 0.7% to 18.3%) | 2% or less |
| test | 115 of 220 (52%) | **7.0%** (8 of 115; Wilson 95% 3.6% to 13.1%) | 2% or less |

**The target is not met.** Six of the eight test misses are fixes that never touched the labelled symbol. Releases therefore withhold the high tier until a rule meets the target on unseen data ([ADR 0008](adr/0008-withhold-high-confidence.md)). Reports: [dev](reports/confidence-dunlap-dev-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-gpt-oss-120b.md), [test](reports/confidence-dunlap-test-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-gpt-oss-120b.md).

### Cost

- **Benchmark:** about 31 seconds per report on two T4 GPUs.
- **PyPI backfill:** about 38 seconds per call, with prompts averaging about 2,400 input and 370 output tokens (shard 1: 913 calls in 9.7 hours).
- **Scan time:** 0 LLM tokens.

### Quantisation

On the 55 dev reports both hosts answered, the 4-bit Kaggle model scored F1 0.705 and Groq's hosted model 0.670 (difference +0.036, 95% CI −0.003 to +0.079); 47 of 55 answers were identical. No tolerance was declared beforehand, so this is evidence, not a pass ([parity report](reports/parity-dunlap-dev-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-qwen3.8-27b.md)).

## Known failure modes

Measured in the [failure-cause breakdown](reports/failures-dunlap-all-extract-v1-qwen3.8-27b-q4km.md) and the confidence analysis:

- **Patch ceiling.** The labelled function is unchanged and only its callee or caller changed, so it is not a candidate. This is the main cause of high-confidence misses.
- **Truncation.** The budget drops the vulnerable function before the model sees it.
- **Model error.** A refactored or helper function is picked instead, and the two families can agree on the same wrong answer: agreement is not correctness.
- **Internal symbol found, public entry point missed** (or the reverse). Entry points must match a definition name exactly, so `SetValue` is dropped when the definition is `Paved.SetValue` ([#53](https://github.com/professor3333/PatchSight/issues/53)).
- **Output limit.** Very large candidate sets can exhaust the 1,500 output tokens. A cap of 14 candidates per prompt is measured ([E4](experiments.md#e4-output-capacity-cap)) and waits to be switched on ([#52](https://github.com/professor3333/PatchSight/issues/52)).
- **Not yet measured:** prompt injection through advisory text, commit messages or code comments, and robustness to huge, squashed, renamed or non-English fixes ([#55](https://github.com/professor3333/PatchSight/issues/55)). Their defences are in place (delimited untrusted text, ID-only answers, validation, fallback), but the suites are not built.
- **Argument-dependent vulnerabilities** such as `yaml.load` with an unsafe `Loader` are matched on the bare name, which errs towards CALLED.

## Release process

- The confidence rule and the gate are chosen on dev data, never on test.
- A database release passes the [release gate](architecture.md#releases-and-operations) and records its code commit, builder, snapshot hash and the release it replaces.
- A change of prompt or model needs a full evaluation, with before-and-after reports, before any release uses it. Rollback moves `latest.json` back by one commit.
