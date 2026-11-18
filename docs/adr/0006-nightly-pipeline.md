# ADR 0006: The nightly pipeline publishes through a pointer branch

- **Status:** accepted
- **Date:** 2026-11-17

## Context

The Definition of Done asks for the offline pipeline to run unattended every night for at
least 14 days. The measurements:

- **Change rate.** The OSV PyPI snapshot changes by a median of 15 records a day (p90 136,
  maximum 265 on bulk re-import days), most of them malicious-package reports that are
  excluded anyway.
- **Cost of a full build.** A full build reads about 36,000 GitHub responses. With the
  workflow's own token (about 1,000 requests an hour) that takes longer than a job may run.
- **Branch protection.** `main` requires the `ci` check on every commit, so a workflow cannot
  push the database pointer `releases/latest.json` there unattended.
- **Model quota.** Groq's free daily quota is shared with the second-opinion work for the
  backfill.

## Decision

`nightly.yml` runs every night and on manual dispatch:

1. **Snapshot.** Download today's OSV PyPI dump in the runner and pin it in the runner's copy
   of the manifest. The committed manifest does not change, so the Kaggle backfill keeps
   working against its pinned snapshot.
2. **Update.** `update-db` starts from the current release's database and rebuilds only the
   vulnerabilities whose extraction inputs changed (ADR 0001). Unchanged ones keep their
   records exactly, LLM tiers and evidence included.
3. **Gate.** `gate-db` runs deterministic checks against the previous release (ledger,
   symbol counts, aliases, no mass loss, unchanged high-confidence records stay high). A
   failure publishes nothing and opens a GitHub issue with the gate report.
4. **Publish.** A dated release `db-YYYY.MM.DD`, immutable and never marked "Latest" (the CLI
   release keeps that), carrying the compressed database.
5. **Point.** Commit the new `latest.json` to the **`db-pointer` branch**, as
   `github-actions[bot]`.

Choices made by the owner on 2026-11-17:

- **A separate pointer branch.** `db-pointer` is not protected and holds only `latest.json`.
  It keeps rollback a single commit without weakening `main`'s protection. The CLI reads it
  first, from version 0.3.0, and falls back to `main`'s `releases/latest.json`; older CLIs
  keep reading `main`, which moves with each CLI release.
- **Bot identity for pointer commits.** They are honest automation, on a branch other than
  the default, so `main`'s history stays the owner's alone.
- **Fallback-only to start.** The first nightly runs call no model and need no secret.
  Changed advisories get fallback records, and LLM records from the backfill are carried.
  Nightly extraction with Groq comes later, with its own per-night token cap.

**Re-runs are safe.** A night with no changes publishes nothing. A release for a date that
already exists is not created again, and the pointer is only committed when it changes.

## Rollback

Revert the pointer commit on `db-pointer`: one commit, after which every CLI from 0.3.0
downloads the previous release on its next `patchsight db update`. Releases are never deleted
or overwritten. The rollback is to be rehearsed and timed once (Definition of Done).

## Consequences

- **The gate blocks bad builds.** Rehearsed on 2026-11-18 with a deliberately damaged copy of a
  real release: three faults, three failed checks, exit status 1
  ([report](../reports/gate-rehearsal-2026-11-18.md)).
- **Bootstrap.** Databases published before the `builds` ledger cannot be updated
  incrementally. The first ledgered release is built locally, where the full HTTP cache
  exists, and the nightly starts from it.
- **Two pointers during the transition.** CLIs older than 0.3.0 follow `main`'s pointer,
  which is updated at each CLI release rather than nightly.
- **No live benchmark in the nightly yet.** Running the Dunlap benchmark on live models every
  night does not fit the free quota. The nightly gate checks the database itself; benchmark
  regressions are caught by `make reproduce` in CI and by the release process for prompt or
  model changes (proposal §10).
