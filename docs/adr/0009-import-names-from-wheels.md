# ADR 0009: Read import names from wheels, not from repository paths

- **Status:** accepted
- **Date:** 2026-11-18

## Context

The scanner needs two names for each record:

- the package's **import names**, to tell whether your code imports it;
- each symbol's **module**, to match your references against it.

Both came from the fix commit's paths, through `names.module_for_path`. A path describes the repository, not what a wheel installs. In `db-2026.11.18`, which holds 3,687 records:

- **40 records (26 packages) had no import root at all.** Their paths don't map to a module: monorepos such as `libs/checkpoint-sqlite/langgraph/...`.
- **1,144 more (368 packages) had roots that don't include the distribution's own name.** Some are right, such as `git` for GitPython. Others are repository directories, such as `libs`, `backend` and `web`, or a package's internal `src` (keras's `keras/src/saving/` became `saving`).

**A wrong module costs CALLED evidence.** `keras.models.load_model` can never match `saving.saving_lib.…`. **No right import name at all makes the scanner say NOT IMPORTED for code that imports the package.** The [reachability fixtures](../reports/reachability-fixtures-db-2026.11.18.md) found one such case: `from langgraph.store.sqlite import SqliteStore`, against a record whose only guessed name was `langgraph_checkpoint_sqlite`.

## Decision

- **The names come from the package's wheels on PyPI.**
  - Two wheels are read: from the newest and the oldest release that has one, because a package can rename its top-level module.
  - Only each wheel's zip central directory is read, with two HTTP range requests to `files.pythonhosted.org`. No package is downloaded or unpacked.
  - The top-level packages, modules and extension modules become the record's import roots.
- **Symbols move under those roots.** Each symbol's path is re-anchored at its first part that is an import root. Entry points and evidence move with their symbols. Symbols outside every root keep their old module, because the wheel doesn't install them (`dummyserver` in urllib3's repository is one).
- **It is a pipeline step of its own,** `import-names`, run after `build-db`, `update-db` or `merge-llm` and before the gate.
  - The release gate's `import_names` check fails any build that skipped it.
  - The names are kept per package in the additive `import_names` table, with the wheels read, or why none could be.
  - The previous release's names are reused, so a nightly reads only new packages. A package with no names is asked again every run.
- **Extraction does not change.** Prompts keep the path-derived names, so cached model answers and replays stay valid ([ADR 0001](0001-re-extract-only-when-inputs-change.md)).

## Measured

On `db-2026.11.18`, with the lookup run once over every package:

- **920 of 993 packages (92.6%) have names from a wheel,** covering 3,531 of the 3,687 records (95.8%). Of the other 73, 65 publish no wheel, 3 are not on PyPI, and 5 have wheels with no importable top-level name, such as a top-level `ansibleguy-webui/` directory.
- **1,100 of 3,687 records were relabelled, and 4,215 symbols moved to a new qualified name.**
  - Records with no import root fell from 40 to 1.
  - Symbols with no module fell from 929 to 567.
  - httplib2's two trees (`python2/` and `python3/`) merged into one symbol per name: 129 symbols became 89.
- **The release gate passed,** including the new check.
- **The lookup took about 2,000 range requests and 8 minutes.** A second run made none.
- **Released CLI 0.4.0 improves on the reachability fixtures:** its false suppressions fell from 1 to 0, with no new CLI. On a small project that uses `langgraph.store.sqlite` and `keras.models.load_model`:
  - 5 NOT IMPORTED alerts for `langgraph-checkpoint-sqlite` became UNKNOWN;
  - 3 keras alerts became CALLED, with the call as evidence.

## Consequences

- **Released CLIs benefit without an upgrade.** The scanner reads `import_roots` and symbol modules as before; only their values improve. CLI 0.4.0 reads a database with the new table.
- **Namespace packages are matched by their top-level name.** `protobuf` installs into `google`, so importing any `google.*` package counts as importing protobuf. That removes some NOT IMPORTED verdicts; it never gives a wrong one.
- **Packages without a readable wheel keep path-derived names.** The release notes say how many. The next CLI also never says NOT IMPORTED for a record with no import root.
- **A new host for the pipeline:** `files.pythonhosted.org`, PyPI's file host. Only file names are read, and they are cached by the wheel's SHA-256.
