# ADR 0013: LLM extraction in the nightly

- **Status:** accepted
- **Date:** 2026-11-21

## Context

[ADR 0006](0006-nightly-pipeline.md) started the nightly pipeline fallback-only: no model call and no secret. Model picks came only from the Kaggle backfill, merged by hand. So:

- **New advisories get no picks** until someone runs an extraction by hand. About 8 PyPI vulnerabilities a day are new or change (week 1 measured 7.7 new ones a day).
- **Picks go stale.** When an advisory's inputs change, the nightly rebuilds its record and the old picks no longer apply. 26 picks were set aside this way by 2026-11-21.
- **The pipeline the proposal describes runs only in part.** Its nightly extracts, and the target "nightly dead-letter rate after retries below 2%" cannot be measured without it.

## Decision

After `update-db`, the nightly extracts the night's changed vulnerabilities and merges the picks into that night's release, before the import names and the gate.

- **What is extracted:** `nightly-targets` reads the update report and lists the rebuilt or new vulnerabilities that have a record, sorted, **at most 25 a night**. At about 2,800 tokens a prompt, with repairs, that is roughly a third of Groq's 200,000-token daily cap for the model, so other work keeps the rest. Anything over the cap keeps the fallback record until a later run.
- **The model:** the `extractor` role, Qwen3.8-27B on Groq, with prompt `extract-v1`: the same prompt as the backfill. Groq does not publish the precision it serves the weights at. The [parity check](../reports/parity-dunlap-dev-extract-v1-qwen3.8-27b-q4km-vs-extract-v1-qwen3.8-27b.md) found it the more inclusive of the two, and every record names the model that made its picks.
- **No second opinion yet.** While [ADR 0008](0008-withhold-high-confidence.md) withholds high confidence, a second opinion changes no published record; it would only spend the other model's quota. It is turned on with the rule that lifts ADR 0008.
- **A quota stop loses nothing.** Groq's daily cap can be reached mid-run, since its ledger also counts work done elsewhere. The live pass then stops cleanly, and a second, cache-only pass collects every answer that did come back. The merge takes those; the rest keep the fallback.
- **The merge stays an update.** `merge-llm` merges into the night's own version, so the release keeps "updated from" the previous one, and its notes gain a "Model picks extracted for this release" section.
- **The secret:** `GROQ_API_KEY`, a repository secret read only by the extraction step of `nightly.yml`. No workflow that runs on pull requests sees it. **Without it, the step is skipped** and the nightly is exactly the fallback-only pipeline of ADR 0006.
- **Traced.** The extraction writes its trace (`pipeline/trace.py`), kept with the night's reports. The dead-letter rate is read from it.

## Consequences

- A release can hold picks from two servings of the same model: the Kaggle backfill (Q4_K_M, llama.cpp) and the nightly (Groq). The two agreed on 47 of 55 dev reports; where they differed, Groq's set contained Kaggle's.
- Groq's JSON rejections (24% of calls on the first dev run) cost repair calls and some dead letters. Each one keeps the fallback, which is the safe direction.
- The nightly's runtime grows by about 30 seconds a vulnerability, so 15 minutes at most for 25, within its 330-minute limit.
- The owner adds the secret. Until then, nothing changes.
