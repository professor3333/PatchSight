# db-pointer

This branch holds only `latest.json`: the pointer that names the current PatchSight symbol
database release, with its SHA-256. `patchsight db update` (version 0.3.0 and later) reads it
from here first, and falls back to `releases/latest.json` on `main`.

The nightly pipeline (`.github/workflows/nightly.yml`, ADR 0006 on `main`) commits a new
pointer here after each release passes the release gate.

**Rollback:** revert the commit that moved the pointer. Every CLI then downloads the previous
release on its next update. Releases themselves are never deleted or overwritten.
