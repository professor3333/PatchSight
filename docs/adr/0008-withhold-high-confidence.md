# ADR 0008: Withhold high confidence until a rule meets its target on unseen data

- **Status:** accepted
- **Date:** 2026-11-18

## Context

The confidence rule of [ADR 0004](0004-fall-back-to-the-baseline.md) (`subset` agreement between two model families, plus a public symbol) was chosen on the dev split and evaluated once on the test split, as declared beforehand. On test, **8 of 115 high-confidence reports missed the labelled symbol: 7.0%** (Wilson 95% interval 3.6% to 13.1%), against the proposal's target of 2% or less.

Six of the eight misses are the patch ceiling: the labelled symbol is not among the definitions the fix changed, so no agreement between models that read only the diff can catch them.

A high-confidence record is the only kind that lets the scanner say IMPORTED, NOT CALLED. A miss there can hide a vulnerable symbol the user's code reaches, which design rule 3 forbids. No published record is high confidence today, because no second opinion has been merged.

## Decision

- **Published databases hold no high-confidence records.** A record the rule would make high is kept **low**: every changed definition, plus the models' picks, rationales and entry points. Its tier reason reads `high confidence withheld (ADR 0008)` followed by the rule's own reason, so `patchsight explain` shows that the models agreed.
- **Enforced twice:**
  - `llm_records.PUBLISH_HIGH = False`, on every build and merge path;
  - the release gate's `high_withheld` check, which fails any candidate that holds a high-confidence record, however it was built.
- **Lifting it takes a new ADR,** not a flag.

## When to lift it

A revised rule, chosen on dev, passes a declared evaluation on data not used to choose it: the Go temporal holdout, or the Python gold set. It passes when the high-confidence miss rate is at or below 2%, every miss is analysed, and the interval is reported.

Candidates:

- entry points resolved by a unique dotted match ([E6](../experiments.md#e6-entry-points-resolved-on-a-dotted-boundary)), already measured on dev;
- a larger budget, so fewer prompts are truncated;
- adding the unchanged callers and callees of changed definitions, aimed at the patch ceiling.

## Consequences

- **The scanner gives CALLED, NOT IMPORTED or UNKNOWN** until this is lifted, never IMPORTED, NOT CALLED. Fewer alerts can be deprioritised, but none is wrongly lowered.
- **Second opinions are still worth collecting.** Their answers are cached and validated, and any future rule needs them. They no longer change what users get, so they rank behind the extractor backfill.
- **The gpt-oss-20b evaluation ([ADR 0007](0007-self-hosted-second-opinion.md)) keeps its purpose:** it decides which second opinion the backfill collects.
