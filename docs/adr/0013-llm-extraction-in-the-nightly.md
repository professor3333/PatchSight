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
- The nightly's runtime grows by about 30 seconds a vulnerability, so 15 minutes at most for 25, within its 330-minute limit. (Since Groq's output limit, about a minute each: see the amendment below.)
- The owner adds the secret. Until then, nothing changes.

## Amendment, 2026-11-21: the backlog

As first built, `nightly-targets` offered only the night's own changes. A vulnerability over the cap, or left unanswered by a quota stop, was carried unchanged the next night and never offered again, so the decision's "until a later run" did not hold. On the nights a builder revision rebuilt 84 to 89 vulnerabilities, about 60 would have kept the fallback until the next backfill.

- **The backlog.** After the night's changes, the targets continue with the vulnerabilities in the night's database whose records hold no model picks, whose fix changes definitions (ledger status `built`), and that the extracting model and prompt have not already failed on, **newest advisory first**. On db-2026.11.21 that was 994, of which 892 are in backfill shard 4; once shard 4 is merged, about a hundred remain.
- **Failed attempts are recorded in the release.** A dead letter, or a prompt with no candidates, keeps the fallback symbols, and the record's tier reason names the model and prompt that tried, for example `fallback: extraction by <model> (prompt extract-v1) failed: no valid answer after one repair`. The backlog skips it, so the quota is not spent on the same attempt every night. A rebuilt record starts without the note, and a new model or prompt tries again (ADR 0001: those are extraction inputs).
- **Only a release that will be published spends quota.** A run on a UTC date whose release already exists (a second run, or a rehearsal by dispatch) publishes nothing, so it skips extraction.
- **A night with no change in OSV still extracts the backlog, and publishes if it merged new picks.** This first said such a night extracts nothing, expecting a change almost every night (7.7 new vulnerabilities a day). But OSV's PyPI feed had no change from 2026-11-21 03:27 to 2026-11-22 11:14 UTC apart from four malicious-package reports, and two quiet nights left about a hundred vulnerabilities waiting. New picks are a change users can see, so they are published like one.
- The run's reports keep `nightly-targets.json`: the night's changes, the backlog and the targets chosen.

## Amendment, 2026-11-21: Groq's output limit

On 2026-11-21 Groq began enforcing **1,000 output tokens per minute** for `qwen/qwen3.8-27b`. A request whose output allowance is 1,500 tokens, as the extractor's was, is refused outright as "too large", even when its answer would be two tokens; an allowance of 1,000 is accepted (measured that day). The first night with extraction would have been refused on its first request. `gpt-oss-120b` still accepted 1,500.

- **The extractor asks for at most 1,000 output tokens.** `output_tokens_per_minute` on the model's config records the limit, and a config whose allowance exceeds it is refused at load. The prompt budget stays 4,600 tokens for every role, so prompts, and the Kaggle backfill's, are unchanged.
- **The client paces output.** Each request reserves its allowance in a 60-second window until its answer's real size is known. On this model that is about one request a minute, so a night of 25 takes about half an hour, well within the job's limit. Checked live: two extractions, 2 calls, 65 seconds, no refusal.
- **Longer answers would fail.** 3.2% of the backfill's answers (84 of 2,609) were over 1,000 tokens. Cut off, such an answer and its repair fail, and the record keeps the fallback with the failure named on it. That alone would put the nightly's dead-letter rate above the 2% target. It would also leave the record stuck, because the backlog does not retry a failure by the same model and prompt.
- **So the nightly's extractor is capped at 9 candidates a prompt.** This is the output-capacity cap of experiment E4 (105 output tokens per candidate, so 1,000 // 105 = 9), set on the Groq extractor role alone. In the backfill, 83 of the 84 long answers came from prompts with more than 9 candidates, and only 1 of 2,387 smaller prompts ran over. The cost: planned offline over all 3,505 PyPI vulnerabilities, 167 more prompts are cut (957 against 790), every one with more than 9 candidates. In the backfill so far, 43 of the newly cut prompts would have fitted. The 9 kept are chosen by BM25. Prompts that fit are identical under both roles. A cut prompt still gets the model's picks among what it shows, and the record still lists every changed definition. The Kaggle roles stay uncapped until #52, so the backfill and the benchmark runs are unchanged.

## Amendment, 2026-11-23: the night's answers are kept

The nightly kept its reports and trace but not its model answers, so a record it extracted could not be replayed anywhere: re-validating it under a new configuration, as a shadow database does, meant calling Groq again (design rule 12 asks for re-runs that are free and repeatable). The first shadow built without them carried the nightly's 50 records unchanged.

- **The night's response files go into its artifact** (`.cache/llm/<ab>/<key>.json`; never the usage ledger). They hold the model's answers, which the database already publishes as picks and rationales, and no prompt or third-party code.
- **`fetch-nightly` adds them to the local response cache**, taking only files whose name is their own cache key and whose content is an answer or a rejection, and never overwriting one already there.
- Artifacts expire after 90 days, so answers needed for longer are kept by fetching them in time.
