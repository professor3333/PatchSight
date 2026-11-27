# ADR 0016: A live drift check on the nightly model

- **Status:** accepted
- **Date:** 2026-11-27

## Context

The nightly extractor is a hosted model: `qwen/qwen3.8-27b` on Groq ([ADR 0013](0013-llm-extraction-in-the-nightly.md)). The provider can change what serves that model ID without notice, for example new weights, another quantisation or another decoding path. The proposal asks for the regression set to run nightly against live models (§10), and names drift as a signal to watch (§11).

Nothing measured drift so far:

- **The regression suite** (`regression-check`) replays cached answers, so it tests the code, not the model.
- **The nightly's own outcomes** cannot show it either. Each night's prompts are new, so there is nothing to compare them with.

[E13](../experiments.md) asked Groq the same prompts again from an empty cache. 5 of 7 answers came back byte-identical and 2 reworded their rationales. The decisions were identical in all 5 vulnerabilities: the picks, the entry points and the cited hunks. So the same prompt gives the same decisions, and only the wording varies.

Since 2026-11-27 the nightly backlog is empty, so the nightly extracts only new or rebuilt vulnerabilities. Most of the daily quota is now free.

## Decision

Every night, after the release steps, the nightly asks the extractor 10 pinned prompts again, live, and compares its decisions with the pinned answers (`drift-check`).

**The pinned prompts** (`benchmarks/drift/pypi-extractor-v1.json`, pinned in [`manifests/eval-sets.json`](../../manifests/eval-sets.json)) were drawn by `drift-freeze` with seed 20261127, offline, from the nightly's own Groq answers:

- **The pool:** the vulnerabilities in db-2026.11.27 with picks from the nightly model. 39 of the 58 in the pinned snapshot have a first answer that judges every candidate, and whose prompt renders again to the same request key.
- **The draw:** 10 of the 34 prompts with 2 or more candidates. A one-candidate prompt leaves only its entry points free to change.
- **What is kept:** the request key, the candidate IDs the model marked vulnerable, those candidates' paths and names, and the entry points it named. No code, advisory text or rationale (rule 13).

**What is compared:** the candidate IDs the model marks vulnerable and the entry points it names, as it returned them, before validation.

- Validation is left out so that a validator change, such as dotted entry points (#53), is not mistaken for drift.
- Wording and cited hunks are left out because, as E13 showed, they are not decisions.
- A pinned prompt is compared only when tonight's rendering of it has the pinned request key: the same model, decoding parameters, prompt version and rendered text. Otherwise the case is reported as `input_changed`, for example when an advisory was edited or the config changed.
- A refusal by the provider, or a stop at the daily cap, is reported and not compared.

**The verdict, declared before the first live check:**

| Verdict | When |
|---|---|
| `drift` | 2 or more compared prompts changed decisions or gave an answer that is not the schema's JSON |
| `inconclusive` | otherwise, fewer than 5 prompts could be compared |
| `note` | otherwise, 1 prompt changed |
| `ok` | otherwise |

**What happens on drift:** the run opens an issue labelled `drift` with the report. The check never blocks or delays a release. Its step runs after the release, the pointer and the Hugging Face upload, and a failure in it does not fail the run. It also runs on a second run the same UTC day, which publishes and extracts nothing, so a dispatch can check again. The report (`nightly-drift.json` and `.md`) is kept in the run's artifact, and the operations dashboard shows each night's verdict.

## Consequences

- **The cost** is 10 requests a night, at Groq's pace of about one a minute. The first run took 34,311 tokens (30,226 in, 4,085 out) and 9 minutes, about a sixth of the daily cap. The check runs after the night's extraction, so it never takes extraction's quota.
- **The threshold rests on little evidence.** E13 saw no decision change in 5 prompts, which cannot say how often one flips by chance. One change is therefore a note, not drift. The threshold may change by amendment once nights of results exist, never by editing past reports.
- **The pins age.** An advisory that is edited, or a change to the prompt or to the decoding parameters, takes its prompt out of the comparison. When fewer than 5 can be compared, every night is inconclusive. `drift-freeze` then draws a new set (`-v2`) from the nights' answers, pinned like any other evaluation set.
- **It measures stability, not quality.** A provider change that alters decisions shows up here. Whether the new decisions are better or worse needs the labelled benchmarks.
- **Only the nightly model is checked.** The Kaggle backfill model runs from pinned weights and is deterministic ([E5](../experiments.md)), so it needs no such check.

## First live run, 2026-11-27

Run locally, from an empty model cache, after this decision was committed:

- **Verdict `ok`:** all 10 prompts were compared, and all 10 got the same decisions.
- **Wording:** 8 of the 10 answers were byte-identical to the pinned ones. The other 2 reworded a rationale, as in E13.
- **Cost:** 10 calls and 34,311 tokens over 542 seconds.

## First run in the nightly runner, 2026-11-27

A same-day dispatch of the nightly (run 46008895967) published and extracted nothing, because db-2026.11.27 already existed, and asked each prompt 13 minutes after the local run had:

- **Verdict `note`.** All 10 prompts had the pinned request key. 9 kept their decisions.
- **One changed.** `GHSA-4vqv-7265-gm2w` (pypdf, 9 candidates) came back with only F9 vulnerable, where the pinned answer and the local re-ask both marked all 9.
- **So an identical request can change a decision on Groq.** Across the first 20 re-asks, 1 did. This is the case the one-change threshold was set for: a note, with no issue opened.
- **No published record changes.** The record keeps the night's answer, and while no record is high confidence (ADR 0008), a low-confidence record lists every changed definition anyway.
