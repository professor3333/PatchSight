# PyPI regression set (v1)

`cases.json` pins the output of PatchSight's Python extraction path for 50 PyPI
vulnerabilities, so that a change to validation, evidence, symbol naming, entry-point
qualification or the record merge cannot alter results unnoticed. CI replays it on every
push and pull request, offline and with no model call (`python -m patchsight.pipeline
regression-check`).

## Contents

For each vulnerability, chosen by `regression-freeze` (seed 20261120) from the answers of
backfill shards 1 to 3:

- the rendered prompt's **metadata**: candidate IDs, file paths, names, hunk IDs and hunk line
  ranges, and whether the prompt was truncated. The prompt's messages are not stored, because
  they contain the advisory text and the fix diffs;
- the names defined in the changed files that a proposed entry point can resolve to, and the
  files that define them;
- the model's **recorded answers**, in order (`null` where the provider rejected one);
- the vulnerability's fallback records: package, symbol names, paths and commit SHAs;
- the **expected output**: status, calls, vulnerable symbols, entry points, evidence, the merge
  outcome and the resulting records.

The cases are stratified so that every path of the extraction loop is covered: 5 dead letters,
the one repaired answer, 8 truncated prompts, 10 answers with entry points, 6 fixes spanning
several packages or commits, and 20 ordinary answers.

No source code is included. The file's SHA-256 is pinned in
`src/patchsight/pipeline/benchmarks/pypi_regression.py` and in `manifests/eval-sets.json`:
re-freezing changes both on purpose (`eval-sets --repin pypi-regression-v1`), in a commit that
says why.

## What it does not check

How prompts are rendered (that needs the diffs), and how good the model is. Extraction quality is
measured on the Dunlap benchmark and the Go temporal holdout.

## Sources and licences

- **Advisories:** the OSV PyPI dump (snapshot in `manifests/snapshot.json`), with content from the
  GitHub Advisory Database and the PyPA Advisory Database, both CC BY 4.0. Only identifiers,
  package names and derived symbol data are stored here; no advisory text.
- **Answers:** `ggml-org/Qwen3.8-27B-GGUF@c1869413` (Q4_K_M, Apache 2.0) on Kaggle, prompt
  `extract-v1`.
- **Changes made:** fix commits were located from the advisories' references, mapped to the
  Python definitions they change, and offered to the model as numbered candidates; the records
  are PatchSight's derived symbol data, released under CC BY 4.0 like the database.
