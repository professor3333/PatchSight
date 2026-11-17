# Contributing to PatchSight

Thanks for helping. Bug reports, wrong symbol data and pull requests are all welcome.

## Reporting problems

- **A bug in the CLI or pipeline:** use the
  [bug report form](https://github.com/professor3333/PatchSight/issues/new?template=bug_report.yml).
- **Wrong or missing symbols for an advisory:** use the
  [wrong symbol data form](https://github.com/professor3333/PatchSight/issues/new?template=wrong_symbols.yml).
  Paste the output of `patchsight explain <advisory-id>`; confirmed corrections become test
  cases and database overrides.
- **A security problem:** report it privately, as described in [SECURITY.md](SECURITY.md).

## Development setup

```bash
uv sync --all-extras    # the offline pipeline needs the 'pipeline' extra
make check              # ruff, mypy (strict) and the offline tests: no network, no keys
make reproduce          # rebuild the benchmark tables from committed files
```

Tests never call a model or a live API. Mark a test that needs the network or a model
`@pytest.mark.live`, and a long-running one `@pytest.mark.slow`.

## Design rules a change must keep

The full list is in [docs/proposal.md](docs/proposal.md); the ones changes most often touch:

- **No model at scan time.** Code under `src/patchsight/scan/` and the CLI must never import the
  offline pipeline or an LLM client. `tests/test_import_boundary.py` enforces this.
- **Fail towards noise, never towards silence.** Uncertain data may raise an alert, never lower
  one, and every alert is shown.
- **The model answers with IDs, not names**, and code checks every answer.
- **No third-party source code in the repository.** Store commit SHAs, paths, line ranges and
  names; fetched code lives in ignored caches.
- **Only measured numbers.** A change to a prompt, model, validator or ranker comes with
  evaluation numbers before and after (see [docs/experiments.md](docs/experiments.md)).
  Choices people will question get a short record in [docs/adr/](docs/adr/).

## Pull requests

- Keep one change per pull request, with tests.
- `make check` must pass; the `ci` check is required before merging.
- Describe what changed and how you verified it.
