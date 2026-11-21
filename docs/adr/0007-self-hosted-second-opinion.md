# ADR 0007: A self-hosted second opinion for the PyPI backfill

- **Status:** rejected on 2026-11-21 by its declared dev evaluation (see the result below). The adoption criteria were declared before any measurement.
- **Date:** 2026-11-17

## Context

High confidence needs a second model family to agree (ADRs 0004 and 0005). The second
opinion, `openai/gpt-oss-120b`, runs on Groq's free tier, and that is now the bottleneck of
the PyPI backfill:

- **Work.** In Kaggle shard 1, 582 of 904 extractions (64%) can still become high confidence
  and need a second opinion; the others already fail a condition that does not depend on it.
  Across four shards that is about 2,300 calls.
- **Quota.** Groq allows 200,000 tokens a day per model, about 85 gpt-oss calls a day, shared
  with the declared test evaluation. The backfill's second opinion would take about a month.
- **Hardware.** gpt-oss-120b does not fit Kaggle's two T4 GPUs. gpt-oss-20b does:
  `ggml-org/gpt-oss-20b-GGUF`, MXFP4, 12.1 GB, Apache-2.0. It is the same family as the
  current second opinion and a different family from the extractor, Qwen.

## Proposal

Run gpt-oss-20b on Kaggle as the second opinion for the PyPI backfill. The role
`kaggle_second_opinion` in `configs/llm.toml` has the same prompt budget as the Groq second
opinion, so both see identical prompts. Groq's gpt-oss-120b stays the second opinion for nightly
extraction, which needs only a few calls a day.

## Declared evaluation

On the Dunlap **dev** split (60 reports), run gpt-oss-20b once on Kaggle (notebook:
`MODE = "dunlap"`, `MODEL = "gpt-oss-20b"`, `SPLIT = "dev"`). Then run `confidence-report` with
Kaggle Qwen as the extractor and the frozen rule (`subset` plus a public symbol, ADR 0004), and
compare with the gpt-oss-120b pairing on the same reports.

Adopt gpt-oss-20b only if **all** of these hold:

1. **Reliable output:** valid answers for at least 58 of the 59 dev reports that have
   candidates (gpt-oss-120b: 59 of 59).
2. **No more high-confidence misses** in the safety view than the 120b pairing: at most 1.
3. **No higher overall miss rate** in the safety view than the 120b pairing: at most 8.3%.

If adopted, run the test split once, report it as it stands, and record the decision here
with the numbers. If any criterion fails, keep the Groq second opinion and record the result in
`docs/experiments.md` as an experiment that lost.

## Consequences if adopted

- **Two second-opinion models in one database.** Backfill records name gpt-oss-20b; nightly
  records name gpt-oss-120b. Every record stores its second-opinion model (rule 11), so they
  can be told apart and re-evaluated separately.
- **Days instead of a month.** About 2,300 calls of a 20B mixture-of-experts model on two T4s
  fit in one or two Kaggle sessions.
- **The pypi mode of the notebook** needs the list of vulnerabilities to check (those where the
  extractor alone could reach high confidence). That path is built only after adoption.

## Result, 2026-11-21: not adopted

The declared run: gpt-oss-20b (`ggml-org/gpt-oss-20b-GGUF@41e8a94d`, MXFP4) on Kaggle, llama.cpp `b12024`, PatchSight `752bbdd`, Dunlap dev split, scored with Kaggle Qwen as the extractor and the frozen rule (`subset` plus a public symbol) in the safety view ([report](../reports/confidence-dunlap-dev-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-gpt-oss-20b-mxfp4.md)).

| Criterion | Required | gpt-oss-120b pairing | gpt-oss-20b pairing | Result |
|---|---|---|---|---|
| Valid answers, dev reports with candidates | at least 58 of 59 | 59 of 59 | 59 of 59 | pass |
| High-confidence misses | at most 1 | 1 of 27 | 1 of 25 | pass |
| Overall miss rate | at most 8.3% | 8.3% (5 of 60) | 10.0% (6 of 60) | **fail** |

The one report between them is GO-2022-0289. Its vulnerable symbol is the public `ForkExec`, which the fix did not change; the fix changed the private `forkExec`. gpt-oss-120b named `ForkExec` as an entry point and gpt-oss-20b did not, so the 20b pairing's low-confidence record misses it. Alone, gpt-oss-20b scored F1 0.602 on dev (120b: 0.626).

**Decision:** the Groq gpt-oss-120b stays the second opinion. While ADR 0008 withholds high confidence, a second opinion changes no published record, so the backfill's second opinion is not urgent; it runs on Groq when a lifting rule needs it.

**The test split was also run, by mistake, and is not used.** The notebook's `dunlap` mode ran every other split after the chosen one, which was meant only for `SPLIT = "all"` (replays from the cache), so it also called the model on the test split. Their accuracy was not scored and decides nothing; the operations dashboard lists the session's calls and answer statuses, as it does for every traced run. The notebook now runs only the chosen split.
