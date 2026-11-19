# Threat model

PatchSight reads text that attackers can write: advisories, and the code, comments and file layout of fix commits. Its output tells developers which alerts matter. The attack worth worrying about is therefore concrete: **make the scanner say "imported, not called" about a vulnerability the user's code does reach.** A wrong CALLED only costs a developer some time, so every defence below pushes uncertainty towards noise rather than silence.

This page names the attackers and the paths, says what happens on each path today, and links the tests that hold it. It also says what is not covered yet.

## What is protected

| Asset | Why it matters |
|---|---|
| The **"imported, not called"** verdict | It is the only verdict that lowers an alert's priority. A false one hides a real vulnerability. |
| **User code** | It must never leave the user's machine. |
| The **published database and its pointer** | Every scan trusts them. |
| **Secrets and third-party code** | API keys, and the source code of other projects, which PatchSight may read but not redistribute. |

## Attackers

| Attacker | Controls | Plausible goal |
|---|---|---|
| Advisory author or editor | advisory text, and which commits the advisory references as the fix | hide a vulnerability, or point at a decoy fix |
| Maintainer or contributor of the affected package | the fix commit: code, comments, strings, names, which files change and how many | make the vulnerable function look harmless, or bury it |
| Someone with access to the release channel | the GitHub account, a token, or the network path | ship a database that hides vulnerabilities |

## The main path: a crafted fix becomes a false "not called"

A false IMPORTED_NOT_CALLED needs **all** of these at once:

1. The record is **high confidence**. That needs both model families to give a valid answer to an untruncated prompt, the two answers to agree (one set contains the other), and a public symbol among them ([ADR 0004](adr/0004-fall-back-to-the-baseline.md)).
2. The agreed set **leaves out** the symbol the user's code reaches.
3. The user's code imports the package, references none of the agreed symbols or entry points, and makes no dynamic use the scanner cannot follow.

Anything short of condition 1 gives a low-confidence record. That holds every changed definition, and the scanner never turns it into IMPORTED_NOT_CALLED.

| Attack | What happens today | Held by |
|---|---|---|
| Text in the advisory or a code comment tells the model that nothing is vulnerable | An empty set is low confidence, so the record keeps every changed definition. | `test_conditions_that_force_low_confidence`, `test_low_confidence_never_lowers_an_alert` |
| Text steers the model towards a harmless decoy function | **Residual risk once high confidence is published.** If both families pick the same public decoy, the rule makes the record high confidence without the real symbol. Both models read the same injected text, so their agreement is not independent evidence against injection. **Closed for now:** releases withhold high confidence ([ADR 0008](adr/0008-withhold-high-confidence.md)). | the injection suite, [#55](https://github.com/professor3333/PatchSight/issues/55) |
| Untrusted text closes its delimiter tag to escape the data block | A closing tag inside untrusted text is escaped (`<\/advisory>`) before rendering, and the prompt says that everything inside the tags is data. | `test_untrusted_text_cannot_close_its_tag` |
| The answer names functions instead of IDs, invents candidates or skips some | Rejected by the strict schema and the validator, then one repair attempt, then the dead-letter table. Either failure leaves the fallback record. | `test_invalid_answers_are_rejected`, `test_extract_dead_letters_after_a_failed_repair`, `test_unusable_extractions_keep_the_fallback` |
| The answer cites a hunk from another function to justify its pick | Rejected: every citation must be a hunk shown under that candidate. | `test_invalid_answers_are_rejected` |
| The answer adds invented entry points | Dropped unless they resolve to a definition in the fix. One that resolves only adds matches, which can only raise priority. | `test_unknown_entry_points_are_dropped` |
| A huge fix buries the vulnerable function | Over 500 changed definitions gives no record, so the alert is UNKNOWN. Over the token budget, the prompt is truncated and the record can only be low confidence. | `test_tight_budget_keeps_the_best_bm25_match_and_records_drops`, the `symbols` gate check |
| The fix is hidden in test, doc or vendored paths | Those paths are filtered out, so the advisory gets no record and its alert stays UNKNOWN. | `test_classify_path` |
| The advisory points at a decoy commit | The fallback record lists the decoy's definitions, which is low confidence, so CALLED or UNKNOWN only. To reach high confidence, both models must also agree on a public decoy: the same residual risk as above. | the planned fix-commit verifier, [#56](https://github.com/professor3333/PatchSight/issues/56) |

**A sharply reduced set.** The design asks for the fallback whenever the model's set is empty or sharply reduced. Today every result that is not high keeps every changed definition, so a reduction matters only at high confidence. There is no separate reduction threshold (open question 2 of the design).

**Measured weakness, unrelated to attackers.** On the Go benchmark's test split, 7.0% of high-confidence reports missed the labelled symbol, mostly because the fix never touched it. Honest data already defeats the 2% target, so releases withhold high confidence ([ADR 0008](adr/0008-withhold-high-confidence.md)), enforced in the merge code and by the release gate's `high_withheld` check.

## Release channel

| Threat | Defence | Held by |
|---|---|---|
| A download corrupted or altered in transit or in a cache | The pointer carries the asset's SHA-256. The CLI verifies it and the schema version before swapping the file in atomically, so a bad file never replaces a working database. Downloads use HTTPS only. | `test_tampered_download_never_replaces_a_working_database`, `test_a_file_that_is_not_a_database_is_refused`, `test_pointer_checks` |
| A published release altered afterwards | Releases are immutable: never deleted or overwritten. A new database is a new dated tag. | process, [ADR 0006](adr/0006-nightly-pipeline.md) |
| A bad build published by the pipeline itself | The release gate blocks it, and the nightly opens an issue instead. | `tests/test_gate.py`, the [recorded rehearsal](reports/gate-rehearsal-2026-11-18.md) |
| A compromised workflow | Actions are pinned by commit SHA. Every workflow defaults to read-only, and only the jobs that publish get more: the nightly job (releases, the pointer and failure issues), and the CLI release's PyPI and GitHub Release jobs. No workflow that runs on pull requests sees a secret. PyPI publishing uses Trusted Publishing and waits for the owner's approval. | the workflow files |
| A compromised GitHub account | **Not defended by the checksum.** The pointer and the asset live in the same repository, so whoever controls the account controls both. This rests on the account's own security. | out of scope |

## Scan-time privacy

- **User code never leaves the machine.** The scan sends package names and versions to OSV, and downloads the database from GitHub, which sees the user's IP address. There is no telemetry.
- **No model at scan time.** Hot-path modules may not import the pipeline, `openai` or `tree-sitter` ([ADR 0002](adr/0002-no-llm-at-scan-time.md)). Held by `tests/test_import_boundary.py`.
- **A malformed project cannot hide use.** Files that don't parse, dynamic imports and star imports make the verdict UNKNOWN, never "not called". Held by `test_dynamic_use_is_unknown` and `test_scanner_skips_virtualenvs_and_records_unparsable_files`.

## Offline secrets and third-party code

- **API keys** are read from the environment (the macOS Keychain locally). Errors and cached rejections are redacted of account IDs and keys before they are written. Held by `test_redact_removes_account_ids_and_keys` and `test_rejections_are_cached_and_redacted`.
- **Third-party code** reaches only the local cache and the Kaggle input bundle, which lives in a private dataset. Releases and committed benchmark files hold names, paths, line ranges and SHAs only.
- **Archives from Kaggle** are untrusted input. Imports accept only expected paths and refuse absolute paths, `..` and anything outside the expected folders. Held by `test_import_refuses_unexpected_paths` and `test_unexpected_or_unsafe_members_are_refused`.

## Not covered yet

- **The injection suite** ([#55](https://github.com/professor3333/PatchSight/issues/55)): plant instructions in advisory text, code comments and identifiers, and check that the extracted set is unchanged from the clean version. This is the measurement behind the decoy risk above.
- **The robustness suite, model side** ([#55](https://github.com/professor3333/PatchSight/issues/55)): how the extractor answers on these inputs. The deterministic side runs in CI (`tests/test_robustness.py`):
  - **Very large diffs:** a commit beyond the API's file pages is marked truncated; a fix of more than 500 definitions gets no record; an over-budget prompt is cut by rank and marked truncated, so its record is low confidence at best.
  - **Squashed fixes:** a fix squashed with a refactor keeps every changed definition in the fallback.
  - **Add-only fixes:** a fix that adds a helper also changes its caller.
  - **Renamed files:** a renamed file's old side is read from its old path, and its old code keeps the old module.
  - **Commit messages:** no message, in any language, reaches a prompt or a record, and non-ASCII advisory text and code render as written.
- **The fix-commit agent's accuracy** ([#56](https://github.com/professor3333/PatchSight/issues/56)): the agent is built ([ADR 0011](adr/0011-fix-commit-locator-agent.md)) but not yet evaluated, and builds no records until it meets its targets. Its bounds are held by `tests/test_locator_agent.py`: four read-only tools, `api.github.com` and `pypi.org` only (no action takes a URL), the package's own repositories only, eight steps, a verifier that discards out-of-range or test-only commits, and observations that cannot close their tag.
