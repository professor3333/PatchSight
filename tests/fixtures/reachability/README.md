# Reachability fixtures

Small Python programs, each written for one advisory and one affected version of its package, whose use of the vulnerable code is known. They test the scanner, end to end from source files to verdict, without the network.

- `cases.toml` lists the advisories and the cases.
  - **Each advisory** has its pinned version and a hand-written record: the vulnerable symbols (`module:qualname`) and the public entry points that reach them.
  - **Each case** names its directory, whether the program **calls** the vulnerable code, the **form** of that use, and the **expected** verdict.
- Each directory holds the program: one or more `.py` files, and sometimes a template.

## What the labels mean

- **`calls`** is the truth: the program's own code uses the vulnerable code. That use can be direct, or go through an alias, a re-export, a subclass, a template filter or an object the program holds. Use only through another package does not count: the scanner does not analyse transitive use, and `NOT_IMPORTED` does not mean safe.
- **`expected`** is the verdict the documented rules (`src/patchsight/scan/verdicts.py`) give when the record is right and high confidence:
  - `CALLED` for use the scanner can resolve, including a class or a name that is only referenced, which is noise but never silence;
  - `UNKNOWN` for use it cannot follow;
  - `IMPORTED_NOT_CALLED` or `NOT_IMPORTED` otherwise.
- **A false suppression** is a case that calls the vulnerable code but gets `IMPORTED_NOT_CALLED` or `NOT_IMPORTED`. The target is zero.

## Running them

```bash
uv run python -m patchsight.pipeline reachability-report               # labelled records
uv run python -m patchsight.pipeline reachability-report --db <sqlite> # a published database
```

The reports go to `docs/reports/reachability-fixtures-*.md`. CI regenerates the labelled report and fails if it changes. A live test checks with OSV that every pinned version is affected by its advisory.

## Rules for new cases

- Keep each program a few lines long, with functions that take their inputs as arguments. No file, network or user input is read.
- Never install or run the programs. They exist only to be scanned.
- Pins live only in `cases.toml`, never in a `requirements.txt`, so the repository's dependency graph does not list these deliberately vulnerable versions.
- Copy no advisory text: IDs, versions and symbol names only.
- Labels come from the advisory and its fix commit. Record why in the advisory's `note`.
