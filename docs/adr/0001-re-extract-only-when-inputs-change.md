# ADR 0001: Re-extract an advisory only when its extraction inputs change

- **Status:** accepted
- **Date:** 2026-11-14

## Context

The nightly pipeline picks up new and modified advisories from OSV's `modified_id.csv`. The proposal says OSV `modified` timestamps drive re-extraction (§9). The Week 1 measurements (`docs/reports/week1-data-gate.md`, snapshot of 2026-11-14) show this does not fit the budget:

- **Modifications:** 771 in-scope advisories were modified in the last 30 days, about 26 a day. That is a lower bound, because each record shows only its latest modification.
- **New arrivals:** a mean of 5.0 new vulnerabilities a day with a GitHub fix link, with p90 12 and a maximum of 46.
- **Budget:** one free-tier model handles about 33 extractions a day, at about 6,000 input tokens against a reported 200,000-token daily cap.

Many OSV modifications don't touch anything the extractor reads: a severity score, a CWE, an added alias, a reformatted reference. Re-running the LLM on those spends quota for an identical answer.

## Decision

Each advisory gets an **extraction input hash**. It is a SHA-256 over the canonical JSON of only the fields that feed extraction:

- the affected PyPI package names, with their version ranges and versions;
- the fix candidates (kind, repository, commit, number, base, head);
- the summary and details text.

An advisory is queued for extraction only when at least one of these holds:
1. it has no extraction yet;
2. its extraction input hash changed;
3. the prompt version or model ID that produced its row changed. A swap follows the evaluated release process anyway.

When only other fields change, the row's stored advisory `modified` timestamp is updated with no LLM call, so the staleness check stays accurate.

The nightly queue is ordered: new advisories first, then changed inputs, then everything else. Work beyond the day's budget carries over to the next run instead of failing.

## Consequences

- Nightly LLM work tracks real input changes, which keeps it inside free-tier quotas on typical days. Peak days (up to 46 arrivals) spill into a backlog. The backlog length becomes a monitored metric.
- An attacker who edits advisory text still triggers re-extraction, because the text is part of the hash. So injection defences keep applying to edited advisories.
- A change in a field outside the hash cannot change the extracted symbols. If a new field later starts to matter, it must be added to the hash, and that addition is itself a versioned change that triggers re-extraction.
- The hash is computed from the normalised advisory, so it relies on normalisation being deterministic. The ingest tests already check this.

## Amendment (2026-11-18): builder revisions

A builder change can make a vulnerability buildable without any input changing. Builder revision 2 builds fixes that change only module-level code, from the definitions those changes name or use. So each database records the `builder_revision` that made it, and `build_db.REBUILT_AT_REVISION` names the ledger statuses each revision handles better. An update from an older revision rebuilds the vulnerabilities with those statuses **once**; the next update carries them as usual.

This rebuilds fallback records only. Records from LLM extraction still follow the rules above, and `pypi-extract` gives the same prompts as before.

## Alternatives considered

- **Re-extract on every `modified` change.** Simple, but at about 26 modifications a day plus new arrivals it exceeds one model's budget. It would also spend most of the quota on no-op changes.
- **Never re-extract.** It saves quota but leaves rows stale when a fix link or affected range is corrected. The proposal treats stale information as a risk to handle, not to accept (§9).
