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

- **What is extracted:** `nightly-targets` lists the night's rebuilt or new vulnerabilities that have a record, sorted, then the backlog (see the amendment below), **at most 25 a night**. At about 2,800 tokens a prompt, with repairs, that is roughly a third of Groq's 200,000-token daily cap for the model, so other work keeps the rest. Anything over the cap keeps the fallback record until a later night's backlog reaches it.
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

## Amendment, 2026-11-21: the backlog

As first built, `nightly-targets` offered only the night's own changes. A vulnerability over the cap, or left unanswered by a quota stop, was carried unchanged the next night and never offered again, so the decision's "until a later run" did not hold. On the nights a builder revision rebuilt 84 to 89 vulnerabilities, about 60 would have kept the fallback until the next backfill.

- **The backlog.** After the night's changes, the targets continue with the vulnerabilities in the night's database whose records hold no model picks, whose fix changes definitions (ledger status `built`), and that the extracting model and prompt have not already failed on, **newest advisory first**. On db-2026.11.21 that was 994, of which 892 are in backfill shard 4; once shard 4 is merged, about a hundred remain.
- **Failed attempts are recorded in the release.** A dead letter, or a prompt with no candidates, keeps the fallback symbols, and the record's tier reason names the model and prompt that tried, for example `fallback: extraction by <model> (prompt extract-v1) failed: no valid answer after one repair`. The backlog skips it, so the quota is not spent on the same attempt every night. A rebuilt record starts without the note, and a new model or prompt tries again (ADR 0001: those are extraction inputs).
- **Only a release that will be published spends quota.** A run on a UTC date whose release already exists (a second run, or a rehearsal by dispatch) publishes nothing, so it skips extraction.
- **A night with no change extracts nothing.** The backlog waits for the next night that publishes; at 7.7 new vulnerabilities a day, that is almost every night.
- The run's reports keep `nightly-targets.json`: the night's changes, the backlog and the targets chosen.
