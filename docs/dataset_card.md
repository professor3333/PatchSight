# Dataset card: PatchSight symbol database

A versioned SQLite database that maps PyPI security advisories to the functions, methods and classes their fix commits changed, and, where a language model has read the fix, to the ones it judged vulnerable. `patchsight scan` joins it with your lockfile and your code. It is built offline and published as [GitHub Releases](https://github.com/professor3333/PatchSight/releases) tagged `db-*`.

```bash
patchsight db update   # follows the release pointer, verifies SHA-256 and schema version
patchsight db info
```

Figures on this card describe release **`db-2026.11.17.1`** unless stated otherwise. Each release's notes give its own counts.

## Sources

| Source | Used for | Licence |
|---|---|---|
| [OSV.dev](https://osv.dev) PyPI dump (`PyPI/all.zip`) | advisories, aliases, references to fix commits | CC BY 4.0 (GitHub Advisory Database and PyPA Advisory Database content) |
| GitHub REST API | fix commits, their diffs and file contents | each repository's own licence; no code is kept |
| PyPI JSON API | each package's declared source repository | public metadata |

The dump is pinned by SHA-256 in every release (`snapshot_sha256` in `patchsight db info`). For `db-2026.11.17.1` it is `6b73630d52e79c45ddc993de802dd5cda2f9042cec006b81f987b81a0345f32a`, downloaded on 2026-11-17. The nightly pipeline takes a fresh snapshot each night.

## Filters and counts

- **Kept:** advisories in the PyPI ecosystem. **Dropped:** malicious-package reports and withdrawn records. On the 2026-11-14 snapshot that left 7,105 PyPI vulnerabilities, after excluding 12,021 malicious-package reports and 640 withdrawn records ([week 1 report](reports/week1-data-gate.md)).
- **Aliases** (GHSA, PYSEC, CVE and others) are grouped, so one vulnerability is one entry however many IDs it has. The release holds 10,620 identifiers.
- **Vulnerabilities with a fix candidate on GitHub:** 4,820, every one recorded in the `builds` ledger with its outcome:

| Outcome | Vulnerabilities | Meaning |
|---|---|---|
| `built` | 3,525 | a record exists |
| `no_python_fix` | 1,084 | the fix changes no Python definition after the path filter |
| `module_level_only` | 121 | the fix changes only module-level code, such as registration calls |
| `no_resolvable_commit` | 64 | the referenced commit or pull request could not be resolved |
| `too_broad` | 15 | the fix changes more than 500 definitions |
| `error` | 11 | fetching or parsing failed |

The 3,525 built vulnerabilities give 3,685 records (one per vulnerability and package) across 991 packages, with 33,675 symbols: 17,324 methods, 11,839 functions and 4,512 classes.

## How fix commits are found

A reference is a fix candidate when it is a commit or pull-request URL on GitHub. It is used only when it resolves, sits on the package's declared repository (from PyPI's project URLs, when one is declared) and changes Python source. Pull requests are resolved to their commits. Tests, docs, changelogs and vendored code are removed by path, and each remaining hunk is mapped with tree-sitter to the innermost function, method or class that contains it, before and after the fix. Fixes referenced only by a tag range, or hosted outside GitHub, are not resolved yet.

## Extraction

- **Fallback records** list every changed definition. They need no model.
- **LLM records** add the model's picks among those definitions, each with a one-sentence rationale and the hunks it cites, plus public entry points that resolve to a definition. They come from Qwen3.8-27B (4-bit, `ggml-org/Qwen3.8-27B-GGUF@c1869413:Q4_K_M`) with prompt `extract-v1`, run on Kaggle in four shards. The method, its validation and its measured accuracy are in the [model card](model_card.md).
- In `db-2026.11.17.1`, **1,855 records (1,770 vulnerabilities) carry model picks** from shards 1 and 2 of 4. The other 1,830 records are fallback only.

## Confidence tiers

| Tier | What the record holds | What the scanner may conclude |
|---|---|---|
| **low** | every changed definition, plus any entry points and model picks | CALLED on a match; otherwise UNKNOWN, never "imported, not called" |
| **high** | only the symbols two model families agree on, including a public one, from an untruncated prompt | CALLED on a match; otherwise IMPORTED_NOT_CALLED |

**Every published record is low confidence, by policy.** On the Go benchmark's test split, the high-confidence rule missed the vulnerable symbol in 7.0% of high-confidence reports, against a target of 2% or less ([ADR 0004](adr/0004-fall-back-to-the-baseline.md#test-result-2026-11-18)). So the tier is withheld from releases until a rule meets the target on unseen data ([ADR 0008](adr/0008-withhold-high-confidence.md)). A record the rule would have made high stays low, and its tier reason says so.

## Fields

Each record carries: vulnerability ID and aliases, package (PEP 503 name) and its import names, fix commits (repository and SHA), symbols (qualified name, module, name, kind, file path), entry points, confidence, source (`llm`, `fallback` or `override`), model and second-opinion model, prompt version, input hash, the advisory's `modified` time, truncation flag and extraction time. Model picks add their rationale and cited hunk locations (commit, path and line ranges). The full schema is in the [architecture doc](architecture.md#the-symbol-database).

**Not included:**

- **Third-party source code.** Only names, paths, line ranges and commit SHAs.
- **Affected version ranges.** Version matching is left to OSV at scan time.
- **Line ranges for fallback symbols.** Only model-picked symbols record the hunks they rest on.

## Evaluation

The database itself has no labelled split. The extraction method is evaluated on the Dunlap et al. Go benchmark (dev 60 reports, test 220, frozen in [`splits/dunlap-v1.json`](../splits/dunlap-v1.json)); see the [model card](model_card.md#metrics). A Python gold set, with a labelling guideline and repeat-annotation agreement, is not built yet ([#54](https://github.com/professor3333/PatchSight/issues/54)).

## Known limitations and biases

- **GitHub-hosted fixes only.** Advisories whose fix lives elsewhere, or is referenced only by a tag range, have no record, and their alerts stay UNKNOWN.
- **The patch ceiling.** A vulnerable function the fix did not change cannot be found from the patch. Low-confidence records still contain every changed definition, so they are never worse than that baseline.
- **Concentration.** The ten packages with the most vulnerabilities (Django, Apache Airflow, vLLM, pypdf, Pillow, Open WebUI, MLflow, aiohttp, NLTK, rdiffweb) hold 20.8% of the records; 576 of the 991 packages have one.
- **Advisory quality varies.** The model reads the advisory text, and short or vague advisories give it less to go on.
- **Missing data is not evidence of safety.** A vulnerability without a record is not a vulnerability without risk.

## Licence and attribution

Advisory identifiers and affected-package data come from [OSV.dev](https://osv.dev), which aggregates the [GitHub Advisory Database](https://github.com/github/advisory-database) and the [PyPA Advisory Database](https://github.com/pypa/advisory-database), all licensed CC BY 4.0.

**Changes made:** PatchSight resolved each advisory's fix commit on GitHub, mapped the changed lines to function names with tree-sitter, and, where shown, had language models choose the vulnerable ones. It stores those names with file paths, line ranges and commit SHAs. No third-party source code is included.

**Licence:** the PatchSight symbol database is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). If you share it, or data derived from it, credit "PatchSight symbol database" with the release, keep the attribution above, and say what you changed.

Every release repeats this notice and the licence in its release notes. The repository's code is licensed separately, under Apache 2.0.
