# ADR 0002: No LLM at scan time

- **Status:** accepted
- **Date:** 2026-11-15

## Context

A scan has to rank a project's dependency alerts. Two designs could do it:

1. **Ask a model during the scan.** Send it the alerts and the relevant user code, and let it judge reachability.
2. **Ask a model once per advisory, offline.** Store which functions carry the bug, and let the scan be a lookup plus static analysis.

The scan runs in developers' terminals and in CI on every pull request, so it is the path that runs most often.

## Decision

No model runs at scan time. The LLM runs only in the offline pipeline, once per advisory (proposal §8). The symbol database is the only artefact that crosses from the pipeline to the scan.

The scan is:
1. a lockfile parse;
2. one OSV batch query, which receives package names and versions only;
3. a database lookup;
4. static analysis of the user's code with Python's `ast` module.

The boundary is enforced, not just documented:

- **Import-boundary test:** `tests/test_import_boundary.py` fails if any scan-path module imports the pipeline, the evaluation harness, or an LLM, tracing or diff-parsing library. It checks statically, and also by importing the CLI in a clean interpreter.
- **Packaging:** the published CLI declares no LLM dependency. The pipeline's dependencies live in the optional `pipeline` extra. A clean `pip install` from GitHub was checked to pull in neither `openai` nor `tree-sitter`, and `release.yml` fails a release if the installed wheel does.

## Consequences

- **No cost or latency per scan.** A scan costs 0 tokens, and its speed depends only on parsing and one HTTP call.
- **Privacy by construction.** User code never leaves the machine and is never shown to a model. The offline model sees only public advisories and public diffs.
- **Deterministic results.** The same code, lockfile and database always give the same verdicts, which a model call could not guarantee.
- **Limited by static analysis.** Use the scanner can't resolve (dynamic imports, `getattr` with a computed name, modules passed as values) becomes UNKNOWN rather than being judged by a model. That is the intended trade: unknown is safe, while a model's confident "not called" would not be auditable.
- **Freshness matters.** Results are only as current as the database, so the scanner warns when its database is more than 7 days old.

## Alternatives considered

- **A model call per scan.** Rejected because it costs money per scan, sends user code to a third party, can't be reproduced, and makes "not called" an unverifiable claim.
- **A hosted lookup API.** It would avoid shipping a database file, but it adds a server to run and a privacy question about which packages a project uses. The database download is a single file, with no server to run.
