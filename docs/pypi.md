# PatchSight

**Know which vulnerable Python dependencies your code actually calls.**

[![PyPI](https://img.shields.io/pypi/v/patchsight?color=4338CA)](https://pypi.org/project/patchsight/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://pypi.org/project/patchsight/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/professor3333/PatchSight/blob/main/LICENSE)
[![ci](https://github.com/professor3333/PatchSight/actions/workflows/ci.yml/badge.svg)](https://github.com/professor3333/PatchSight/actions/workflows/ci.yml)

Dependency scanners flag a package *version* as vulnerable. PatchSight checks whether your code references the vulnerable *functions*.

An LLM reads each PyPI security fix offline and records which functions carry the bug. Your scan looks those functions up and checks your code with static analysis: **no LLM, no server, and your code never leaves your machine.** Only package names and versions are sent to [OSV](https://osv.dev).

## Quick start

```bash
pip install patchsight

patchsight db update      # download the latest symbol database (SHA-256 verified)
patchsight scan .         # scan the lockfile and the code under .
```

| Option | What it does |
|:---|:---|
| `--lockfile PATH` | Scan a specific lockfile: `requirements.txt`, `uv.lock` or `poetry.lock` (default: the first found, in that order) |
| `--format json` | Machine-readable output |
| `--format sarif` | SARIF 2.1.0 for GitHub code scanning and other SARIF readers |
| `--format markdown` | Every alert, for a pull-request comment or a CI job summary |
| `--fail-on called` | Exit 1 if any alert is CALLED: a CI gate (`unknown` also fails on UNKNOWN) |
| `--db PATH` | Use a specific database file (or set `PATCHSIGHT_DB`) |
| `patchsight explain ID` | Why the database lists an advisory's symbols: confidence, models, rationale and the changed lines; or why it has none |
| `patchsight report ID` | Draft a GitHub issue saying an advisory's symbols look wrong, filled with the `explain` output. Nothing is sent: you review and submit it |
| `patchsight db info` | Show which database a scan uses, and its age |

In GitHub Actions, the [PatchSight action](https://github.com/professor3333/PatchSight#in-ci-the-github-action) scans, uploads the SARIF report to code scanning, writes the full report to the job summary and, with `comment: "true"` (and `pull-requests: write`), keeps one pull-request comment up to date:

```yaml
- uses: professor3333/PatchSight@v0.8.0
  with:
    fail-on: called
    comment: "true"
```

## Verdicts

| | Verdict | Meaning |
|:---:|:---|:---|
| 🔴 | **CALLED** | A reference in your code resolves to a vulnerable function, its class, or an entry point that reaches it. **Fix these first.** |
| 🟢 | **IMPORTED, NOT CALLED** | The package is imported, but no vulnerable symbol is referenced. Given only for high-confidence data, which is [withheld for now](https://github.com/professor3333/PatchSight/blob/main/docs/adr/0008-withhold-high-confidence.md). |
| ⚪ | **NOT IMPORTED** | Your code never imports the package directly, and no file that starts processes names it (a Dockerfile, Procfile, start script or CI workflow). It may still be used through other dependencies. |
| 🟡 | **UNKNOWN** | No symbol data (the alert says why, for example "the fix changes no Python code"), only low-confidence data, or code the scanner can't follow: dynamic imports, a vulnerable method called on an object of unknown type, a template filter, a package whose import name isn't known, or a package your project runs as a command (`exec gunicorn app.wsgi`). |

**Fail towards noise, never towards silence.** Every alert is shown. Low-confidence data can raise an alert to CALLED but never lower it, and "not called" covers only direct use that can be resolved statically. PatchSight supports triage; it doesn't judge whether your deployment is vulnerable.

## Results

On the Go benchmark of Dunlap et al. (DIMVA 2024), 280 vulnerability reports:

| System | Precision | Recall | F1 |
|:---|:---:|:---:|:---:|
| Every changed function (naive baseline, reproduced) | 0.225 | 0.893 | 0.360 |
| Best open model in the paper (Mixtral 8x7B) | 0.60 | 0.74 | 0.66 |
| **PatchSight: Qwen3.8-27B, 4-bit** | **0.751** | **0.621** | **0.680** |

The F1 95% interval is 0.62 to 0.74. The reports and a one-command offline reproduction are [in the repository](https://github.com/professor3333/PatchSight#results-at-a-glance).

On 20 real projects pinned to their May 2024 lockfiles, **75.6% of 3,544 alerts have symbol data**, and a scan of a project with 200 or more dependencies takes **2.23 s at the median and 5.29 s at p95**, OSV query included ([report](https://github.com/professor3333/PatchSight/blob/main/docs/reports/panel-db-2026.11.20.md)). On 58 small programs with a known answer, no program that uses the vulnerable code is labelled "not called" or "not imported" ([fixtures](https://github.com/professor3333/PatchSight/blob/main/docs/reports/reachability-fixtures-labelled.md)).

## Status: early release

- Reads `requirements.txt` (exact `==` pins only), `uv.lock` and `poetry.lock`. Packages without a PyPI release version (unpinned requirements, git, URL or local sources) are listed, not guessed.
- The [symbol database](https://github.com/professor3333/PatchSight/releases) is updated every night and covers about 3,500 PyPI vulnerabilities, all at **low confidence** so far: every function the fix changed, plus the model's picks where the backfill has reached. High-confidence records are withheld until the confidence rule meets its safety target, so expect UNKNOWN where a later release may say IMPORTED, NOT CALLED.
- Transitive use and dynamic code (`getattr` with a computed name, `importlib`, star imports) aren't analysed. They give UNKNOWN or NOT IMPORTED, never a false "not called".

## Links

- [Source, design and benchmark reports](https://github.com/professor3333/PatchSight)
- [Symbol database releases](https://github.com/professor3333/PatchSight/releases)
- [Issues](https://github.com/professor3333/PatchSight/issues)

Code: Apache-2.0. Advisory data: [OSV.dev](https://osv.dev), the [GitHub Advisory Database](https://github.com/github/advisory-database) and the [PyPA Advisory Database](https://github.com/pypa/advisory-database), all CC BY 4.0. No third-party source code is redistributed.
