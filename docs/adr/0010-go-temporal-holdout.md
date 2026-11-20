# ADR 0010: The Go temporal holdout, and its declared evaluation

- **Status:** accepted, before any model has seen the holdout
- **Date:** 2026-11-19

## Context

High-confidence records are withheld ([ADR 0008](0008-withhold-high-confidence.md)) because the confidence rule of [ADR 0004](0004-fall-back-to-the-baseline.md) missed the labelled symbol in 7.0% of high-confidence test reports, against a target of 2%. To lift that, a rule chosen on dev must pass on data not used to choose it. Two things rule out the existing data:

- **The Dunlap test split has been read.** Its misses were analysed for ADR 0004, so any new rule would be fitted to it.
- **The benchmark is from 2023.** The pinned models may have seen its reports, symbols included, in training.

## Decision

### The holdout

[`benchmarks/go-holdout-v1/reports.json`](../../benchmarks/go-holdout-v1/reports.json), frozen once with `holdout-freeze` from GoVulnDB. It contains:

- **Reports published after 2026-08-13.** On that day the newest pinned model's weights, `Qwen/Qwen3.8-27B`, were uploaded to Hugging Face, and the repository has no weight change since (its later commits are model-card and template edits). The pinned GGUF is a conversion of those weights. gpt-oss was released in August 2025. Neither model card states a knowledge cutoff, so the release date is the strictest bound that can be shown: a report published later cannot be in either model's training data.
- **Reviewed reports with vulnerable symbols**, which are the ground truth, and a fix commit on GitHub. A pull-request fix is resolved to its merge commit at freeze time.
- **83 reports** of the 646 published after the cutoff. The rest are excluded, each reason counted in the file: unreviewed (500), no symbols (26), only a Go code review link (22, all standard library), no GitHub fix commit (7), withdrawn (8).

The file holds IDs, fix commits, symbols, and the advisory text the prompt shows. GoVulnDB is CC BY 4.0 and the file credits it. No code is stored.

### The evaluation, declared now

It is run once and reported as it comes out. Resuming an interrupted run from the response cache is allowed. Changing anything after seeing results is not.

- **Extractor:** Qwen3.8-27B Q4_K_M on Kaggle (role `kaggle_extractor`, prompt `extract-v1`), with the configuration in `configs/llm.toml` when this ADR was accepted: no output cap, exact entry-point names.
- **Second opinion:** gpt-oss-120b on Groq (role `second_opinion`), the pairing the rule was chosen with on dev and evaluated with on test. If [ADR 0007](0007-self-hosted-second-opinion.md) adopts gpt-oss-20b, that pairing is reported alongside, but it does not decide.
- **Rules,** both fixed before this evaluation:
  1. the ADR 0004 rule: `subset` agreement, plus a public symbol;
  2. the same rule with entry points matched on a unique dotted boundary ([E6](../experiments.md#e6-entry-points-resolved-on-a-dotted-boundary)), computed from the same answers.
- **A rule passes** when its high-confidence miss rate is at or below 2%, with every miss analysed by cause and the Wilson 95% interval reported, as ADR 0008 asks. Recall, F1 and the overall safety-view miss rate are reported too, next to ChangedFuncs on the same reports (`holdout-baseline`).
- **Coverage is reported as well, and must be analysed before any lift.** For each high-confidence report, coverage asks whether *every* labelled symbol is covered by the record's symbols and entry points, matched as the safety view matches them. The next section explains why this matters here.

### The labels on this data are broader

Current GoVulnDB reports list the **exported functions that reach the vulnerable code**, not only the vulnerable functions themselves:

- The holdout has a median of **8 symbols per report**, a mean of 36.5, and a maximum of 680 (`GO-2026-6910`, every method of a client type).
- The 2023 Dunlap labels average about 2.
- On the holdout, ChangedFuncs finds at least one labelled symbol in 82 of 83 reports, but only 35% of the symbols ([baseline](../reports/changedfuncs-go-holdout-v1.md)).

This has two consequences:

- **Precision, recall and F1 do not compare with the Dunlap numbers.** They are compared only with ChangedFuncs on the same reports.
- **The ADR 0008 miss rate is lenient here.** A high-confidence record avoids a "miss" if it holds any one of the labelled symbols. But a record that leaves out an exported caller is what would make the scanner wrongly say "not called" for code that calls it. So coverage, not the miss rate, is the closer measure of that risk. It is declared now, before the run, so that it cannot be chosen after seeing results.

### What a pass would mean

The holdout is small. If about half the reports are high confidence, about 40 carry the target. Then a pass means zero misses, and even zero misses has a 95% upper bound near 9%. So:

- **A failure is decisive:** the rule does not meet the target on unseen data, and ADR 0008 stands.
- **A pass is necessary but not enough.** Lifting ADR 0008 still takes a new ADR. It weighs this interval and the coverage result, and may add the Python gold set ([#54](https://github.com/professor3333/PatchSight/issues/54)) as further unseen data.

## Consequences

- **Two runs are needed:** the holdout on Kaggle (`MODE = "holdout"`, `MODEL = "qwen"`, about an hour), and the second opinion on Groq (`dunlap-extract --benchmark go-holdout-v1 --role second_opinion`, about a day of the free quota).
- **Scoring takes no model calls.** After both runs:
  1. `export-replay <tag> --benchmark go-holdout-v1 --role <role>` writes each run's replay bundle to `benchmarks/go-holdout-v1/`;
  2. `dunlap-extract --benchmark go-holdout-v1 --role <role> --out docs/reports/extraction-go-holdout-v1-<tag>` writes each run's validated entry points, and the same with `--config configs/experiments/llm-dotted-entry-points.toml` and `--out …-<tag>-dotted` gives rule 2's;
  3. `holdout-report --primary <Qwen tag> --secondary <gpt-oss tag>` writes `docs/reports/holdout-go-holdout-v1-<primary>-vs-<secondary>.md`: the criterion with its interval, every miss by cause (patch ceiling or model), coverage, and ChangedFuncs alongside.
- **The holdout is never used to choose anything.** Later rules need a later holdout: `go-holdout-v2`, published after this one was frozen.
- **The cutoff is a release date, not a measured knowledge cutoff.** If either model's provider publishes an earlier knowledge cutoff, this holdout stays valid; a later one would not exist, because weights cannot know data published after their release.
