# ADR 0005: Two model families decide confidence

- **Status:** accepted
- **Date:** 2026-11-16

## Context

A single model's answer carries no reliable measure of its own correctness. The proposal (§6, §9) uses agreement between two different model families as a cheap confidence signal: errors that come from one family's training or quirks are less likely to be repeated by another.

## Decision

- **Extractor:** Qwen3.8-27B (Alibaba). It runs self-hosted on Kaggle (4-bit GGUF, llama.cpp) for full runs, and on Groq for small increments. Same base weights, compared by the quantisation parity check.
- **Second opinion:** `openai/gpt-oss-120b` (OpenAI), on Groq's free tier, which has its own daily quota.

Both get the same prompt (`extract-v1`), the same token budget (4,600 tokens, enforced by a test) and the same validator, so they differ only by model. Confidence then follows ADR 0004.

## Evidence (dev split, 60 reports)

| Model | Precision | Recall | F1 | Valid at the first attempt |
|---|---|---|---|---|
| Qwen3.8-27B Q4_K_M (Kaggle) | 0.710 | 0.644 | 0.676 | 59 of 60 (1 report has no candidates) |
| gpt-oss-120b (Groq) | 0.710 | 0.559 | 0.626 | 59 of 60 (1 report has no candidates) |

Agreement:
- Both answers were valid in 59 reports. 38 had identical vulnerable sets, and under `subset` only 1 disagreed.
- **Shared blind spots exist.** In several reports both families chose the same private helper while the ground truth names its exported caller (ADR 0004). Agreement is therefore necessary but not sufficient, which is why ADR 0004 adds the public-symbol condition.

Practical differences:
- **Rejections:** on Groq, Qwen's constrained JSON was rejected on 24% of calls in the first dev run; gpt-oss had none. llama.cpp's grammar-constrained decoding gave 0 rejections for Qwen on Kaggle.
- **Cost:** gpt-oss can't switch reasoning off, so it spends more output tokens: 22,100 completion tokens on dev, against about 12,700 for Qwen on Groq.

## Consequences

- Two models double the offline LLM cost of every extraction, which is still free within the providers' daily quotas.
- `gpt-oss-120b` is too large for Kaggle's T4s, so the second opinion depends on a hosted free tier. If Groq retires it, a replacement must be another family, and must go through the full evaluation before use.
- A replacement second opinion changes which records are high confidence, so it is a release-gated change, like any model swap.
