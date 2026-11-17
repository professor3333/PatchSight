# Security policy

## Reporting a vulnerability

Please report security problems **privately**, through GitHub's private vulnerability
reporting: open the [Security tab](https://github.com/professor3333/PatchSight/security) and
choose **Report a vulnerability**. Please do not open a public issue for a security problem.

Include what you found, how to reproduce it, and which version you used
(`patchsight --version`, and `patchsight db info` for the database).

## Supported versions

| Component | Supported |
|---|---|
| CLI | the latest release on [PyPI](https://pypi.org/project/patchsight/) |
| Symbol database | the release the pointer currently names (`patchsight db info`) |

## What is in scope

- **The CLI:** `patchsight scan`, `explain` and `db update`, including how a downloaded
  database is verified (HTTPS only, SHA-256 checked, schema checked, then swapped in).
- **Untrusted text in the offline pipeline:** advisory text, commit messages, code comments and
  diffs can contain instructions aimed at the model. A way to make the pipeline mark a used,
  vulnerable symbol as safe is a security problem.
- **The published database and its pointer:** anything that could make users download a
  database other than the one the pointer names.

## What is not a security problem

**Wrong or missing symbol data for an advisory** is a data-quality issue: please use the
[wrong symbol data](https://github.com/professor3333/PatchSight/issues/new?template=wrong_symbols.yml)
issue form. By design, low-confidence data can raise an alert but never hide one, and every
alert is always shown.

## Design safeguards

- The scan runs locally and sends only package names and versions to OSV. No user code leaves
  the machine, and no model runs at scan time.
- Model answers are restricted to numbered candidates and checked by code; anything uncertain
  falls back to every changed function.
- Database releases are immutable, verified by SHA-256, and published only after a release gate.
