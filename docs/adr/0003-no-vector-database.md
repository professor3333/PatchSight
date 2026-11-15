# ADR 0003: No vector database or RAG

- **Status:** accepted
- **Date:** 2026-11-15

## Context

LLM projects often add a vector database and retrieval-augmented generation by default. The question is whether PatchSight needs either.

What the extractor has to look up:

- **The advisory, by its ID.** OSV and the alias table give exact keys, so there is nothing to search.
- **The fix diff, by commit SHA.** Again an exact key.
- **Which changed functions to show the model.** This set is small and fixed per advisory.

On the Dunlap benchmark, PatchSight's pipeline found 2,330 candidate functions across 280 reports (`docs/reports/changedfuncs-baseline.md`). The median report has 2 candidates and the largest has 24 (`benchmarks/dunlap-v1/`).

## Decision

No vector database and no embedding model in the MVP (proposal §7, §13).

When a prompt would exceed the token budget, candidates are ranked with BM25 against the advisory text, and only the best-matching ones that fit are kept (`pipeline/extract/prompt.py`). Every truncation is recorded, and a truncated prompt can never be high confidence.

## Consequences

- **Fewer moving parts.** No embedding model to host or version, and no index to rebuild when advisories change.
- **Explainable ranking.** Lexical matches between advisory text and function names and code can be inspected.
- **A known limitation.** On the full Dunlap run, 32 of 280 prompts were truncated (`docs/reports/extraction-dunlap-all-extract-v1-qwen3.8-27b-q4km.md`). If a true vulnerable function is cut, the model can't find it, and only the low-confidence fallback recovers it.

## When to revisit

Add an embedding ranker only if a measurement shows BM25 losing recall. The measurement is the recall of true vulnerable functions among the candidates kept at the budget's cut-off, on truncated reports (proposal §10, "Retrieval"). Record that measurement in a new ADR if it changes this decision.
