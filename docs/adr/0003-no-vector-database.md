# ADR 0003: No vector database or RAG

- **Status:** accepted
- **Date:** 2026-11-15

## Context

LLM projects often add a vector database and retrieval-augmented generation by default. The question is whether PatchSight needs either.

What the extractor has to look up:

- **The advisory, by its ID.** OSV and the alias table give exact keys, so there is nothing to search.
- **The fix diff, by commit SHA.** Again an exact key.
- **Which changed functions to show the model.** This set is small and fixed per advisory.

On the Dunlap benchmark, PatchSight's pipeline found 2,330 candidate functions across 280 reports (`docs/reports/changedfuncs-baseline.md`). The median report has 2 candidates. (This ADR first said the largest has 24; the retrieval bundle shows 353, in GO-2021-0100. See the measurement below.)

## Decision

No vector database and no embedding model in the MVP (proposal §7, §13).

When a prompt would exceed the token budget, candidates are ranked with BM25 against the advisory text, and only the best-matching ones that fit are kept (`pipeline/extract/prompt.py`). Every truncation is recorded, and a truncated prompt can never be high confidence.

## Consequences

- **Fewer moving parts.** No embedding model to host or version, and no index to rebuild when advisories change.
- **Explainable ranking.** Lexical matches between advisory text and function names and code can be inspected.
- **A known limitation.** On the full Dunlap run, 32 of 280 prompts were truncated (`docs/reports/extraction-dunlap-all-extract-v1-qwen3.8-27b-q4km.md`). If a true vulnerable function is cut, the model can't find it, and only the low-confidence fallback recovers it.

## When to revisit

Add an embedding ranker only if a measurement shows BM25 losing recall. The measurement is the recall of true vulnerable functions among the candidates kept at the budget's cut-off, on truncated reports (proposal §10, "Retrieval"). Record that measurement in a new ADR if it changes this decision.

## Measured, 2026-11-21

The measurement above was run on the Dunlap benchmark ([E9](../experiments.md#e9-ordering-candidates-to-fit-the-prompt-budget), [report](../reports/retrieval-dunlap-v1.md)). On the 32 of 280 prompts that are cut, BM25 keeps 0.421 of the true vulnerable functions among the candidates, against 0.693 with no ranking at all (paired difference −0.271, 95% CI −0.405 to −0.109) and 0.950 for an oracle order.

So BM25 loses recall, but to no ranking, not to a missing embedding model. The decision stands: no vector database and no embeddings. The ranker itself is the next thing to change, chosen on dev and evaluated on data not used to choose it.

A replacement was then chosen on dev and evaluated once on the Go temporal holdout ([E10](../experiments.md#e10-a-replacement-for-bm25-at-the-prompt-budget-declared-before-measuring)): keeping the smallest candidates first beat BM25 by +0.094 recall (95% CI +0.042 to +0.328). It needs no embeddings either. It is the configuration option `budget.candidate_order`, and it stays off: switched on through shadow-then-promote, it let more true candidates into the prompt, but the model's picks were no better ([E12](../experiments.md#e12-the-switch-on-batch-before-and-after)). Better retrieval at the budget did not become better extraction, so the measured need for anything heavier, embeddings included, is not there either.
