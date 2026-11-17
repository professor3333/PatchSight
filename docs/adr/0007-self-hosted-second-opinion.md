# ADR 0007: A self-hosted second opinion for the PyPI backfill

- **Status:** proposed. The adoption criteria below are declared before any measurement.
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
