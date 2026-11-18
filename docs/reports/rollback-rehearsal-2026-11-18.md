# Rollback rehearsal: the pointer moved back and forward, timed

- **Date:** 2026-11-18, 06:29 to 06:35 UTC (the nightly runs at 03:17, so it could not interfere)
- **Procedure:** [ADR 0006](../adr/0006-nightly-pipeline.md#rollback). Revert the pointer commit on `db-pointer`; releases are never deleted or overwritten.
- **Releases:** the current one was `db-2026.11.18`, published by the nightly, with pointer commit `4a0182e` by `github-actions[bot]`. The rehearsal rolled back to `db-2026.11.17.1`.
- **User:** a clean install of `patchsight` 0.3.0 from PyPI that already had `db-2026.11.18`, running `patchsight db update` every 10 seconds

## Timeline

| Step | UTC | Elapsed |
|---|---|---|
| Decide to roll back | 06:29:35 | |
| Revert commit pushed (`17a4d1c`, "Roll back to db-2026.11.17.1") | 06:29:37 | 2 s |
| The user's `db update` downloads `db-2026.11.17.1` | 06:29:48 | **11 s after the push** (first check) |
| Decide to roll forward | 06:29:59 | |
| Roll-forward commit pushed (`4f08289`, restoring the nightly's pointer) | 06:30:01 | 2 s |
| The user's `db update` downloads `db-2026.11.18` | 06:34:51 | **4 min 50 s after the push** (28 checks) |

## What it shows

- **A rollback is one commit and takes seconds of work.** Each move was a single `git revert` on `db-pointer`, pushed within 2 seconds of the decision. The roll-forward left `latest.json` byte-identical to the nightly's commit.
- **Users get it on their next `db update`, within about 5 minutes.** `raw.githubusercontent.com` serves the pointer with `Cache-Control: max-age=300`, so a cached edge can keep the old pointer for up to 300 seconds. The rollback happened to reach a fresh edge (11 s). The roll-forward waited out an edge that had just cached the rolled-back pointer (4 min 50 s).
- **Moving back works for users who already have the newer database.** `db update` compares the pointer's SHA-256 with the local file, not the version order, so it replaces a newer database with the older release the pointer names (`scan/dbcache.py`).
- **Nothing was lost.** Both releases stayed published and unchanged, and the next nightly builds on whatever the pointer names, which is `db-2026.11.18` again.

## Limits

- **One user and one network location.** Other CDN edges may lag by up to the same 300 seconds.
- **CLIs older than 0.3.0** follow `releases/latest.json` on `main` instead. Rolling them back is a commit on `main`, through a pull request, so it takes as long as CI does.
- **A user who never runs `db update`** keeps whatever database they have. The scanner warns when it is more than 7 days old.
