# ADR 0017: A reference to a stored caller marks an alert CALLED

- **Status:** accepted
- **Date:** 2026-11-28

## Context

A record lists the definitions a fix changed. Every published record is low confidence ([ADR 0008](0008-withhold-high-confidence.md)), so it lists all of them. Users rarely call those definitions directly. They call the package's public functions, which reach the changed code without changing themselves.

- CVE-2020-14343 is the standard case. Its fix changes PyYAML's `FullConstructor`, while users call `yaml.full_load` or `yaml.load`.
- On db-2026.11.27 a project that calls `yaml.full_load` on PyYAML 5.3.1 gets UNKNOWN ("symbol data is low confidence"), though it uses the vulnerable code in the most direct way there is.
- Model entry points cover some of these cases, but only when the model offered the name and it passed validation.

The callers step (#165 to #168, `pipeline/callers.py`) stores, for each record, the definitions of the package that reach its symbols through references a reader of the source can resolve (`pipeline/callgraph.py`). They are read from the newest release the advisories call affected. Each caller carries the next definition on one path towards a symbol. A record with more than 500 callers keeps none.

## Decision

**When no reference matches a vulnerable symbol or entry point, a reference that matches one of the record's stored callers gives CALLED** (rule 2a in `scan/verdicts.py`).

- **The graph behind the callers claims only likely calls.** Two choices make it so:
  - An unknown receiver `x.m` is linked only to the one package class that defines `m`, and never for a builtin type's method name. This was #164.
  - `self.m` is the method an instance of that very class runs, its own or the nearest ancestor's, and never a subclass's override. A base method calling `self.process_response()` runs a subclass's override only for an instance of that subclass, and a user's own subclass replaces it. `callgraph.build(overrides=True)` keeps the wider graph for measuring what static analysis could miss.
- **Each stored entry records the graph revision it was computed with** (`callgraph.REVISION`, now 2). An entry from another revision is computed again, never reused.
- **Matching** is the rule that matches symbols, unchanged:
  - the same name;
  - the containing class or module;
  - a name inside it;
  - a re-export: the same package and final name. For a dunder, the class must agree too ([ADR 0015](0015-a-dunder-name-alone-is-not-a-re-export.md)).

  Callers are definition names such as `requests.api.get`, while users write the names packages re-export, such as `requests.get`. So the re-export rule is needed here as much as for symbols. `NameIndex` applies the rule to hundreds of callers at once, and a property test checks that it agrees with `matches` name by name.
- **Evidence:**
  - The reason names the reference and the release the callers were read from.
  - The alert's new `path` field runs from the caller matched to a vulnerable symbol, such as `yaml.full_load -> yaml.loader.FullLoader -> yaml.constructor.FullConstructor`.
  - The text report prints the path on its own line, the markdown report names the symbol it reaches, and SARIF carries the path in the message and as the `callPath` property.
  - When several references match, the path shown starts at the closest match: the same name, then a member, then a name inside it, then a re-export, which a plain collision of names can also give. Ties go to the shortest path, which rests on the fewest links, and then to the first reference in the code.
- **When callers count:** only with status `ok`, and only while they were computed for the record's current symbols. The pipeline and the scanner compute the same digest of the symbol names (`db.symbols_digest`). Stale callers, or callers that could not be computed, change nothing.
- **They only raise.** A caller can turn an alert into CALLED and nothing else. Without a match, the verdict is what it would have been without callers. A test checks this on every combination of a set of references, so design rule 3 holds.
- **`patchsight explain`** says how many callers a record has and the release they were read from, and names a few, public ones first. If there are none, it says why.

## Evidence

Measured on a shadow copy of db-2026.11.27 with callers stored, against db-2026.11.27 itself.

**The stored callers.**
- The step read 2,226 release files from the cache in 18 minutes with 4 workers.
- 2,280 of 3,814 records have callers: 85,105 in all, a median of 6 per record, p90 88.
- 85 records have more than 500 and keep none.
- The others have none for these reasons: the symbols are not in the release read (418), no affected release has files (220), no file under 50 MB (155), no Python source (93), not on PyPI (7).
- The database grows from 17.0 MB to 38.2 MB, and the gzip asset from 4.3 MB to 8.2 MB.

**Reachability fixtures** ([before](../reports/reachability-fixtures-db-2026.11.27.md), [after](../reports/reachability-fixtures-db-2026.11.27-shadow-callers.md)):
- 0 false suppressions in both.
- Programs given the verdict the rules expect rise from 22 to 31 of 58.
- The 9 that change all go from UNKNOWN to CALLED, and each is labelled CALLED:
  - five PyYAML programs that call it: `yaml.full_load`, `yaml.load` with an aliased loader, `getattr` with a constant name, and two re-exports;
  - a PyYAML program that uses the loader only in an annotation, which the rules count as a reference;
  - the werkzeug, requests and paramiko programs.

**Repository panel** ([before](../reports/panel-db-2026.11.27.md), [after](../reports/panel-db-2026.11.27-shadow-callers.md)):
- **CALLED rises from 163 to 428 of 3,545 alerts.** All 265 changes are from UNKNOWN, and no other verdict moves.
- By package: aiohttp 39, Django 38, GitPython 37, requests 27, PyJWT 27, pypdf 16, sqlparse 14, Pillow 9, urllib3 9, tornado 8, and 41 across 13 others.
- The closest match behind each new alert: the caller's own name 70, a member of a referenced class or module 37, and a re-export alone 158.
- Scan time for the 5 repositories with 200 or more dependencies stays within run-to-run variation: p50 1.94 → 2.10 s, p95 6.86 → 5.74 s.

**A sample of 40 new alerts** (seed 20261128). Each path was read against the package's code. This is design data, not a labelled evaluation.

| Verdict | Alerts |
|---|---:|
| Genuine: the project uses a caller and the path is real | 35 (Wilson 74–95%) |
| Doubtful: the only match is a reference to `PIL.Image.Image`, whose private method is the caller | 2 |
| False: `default_storage.save` matched an unrelated `save` (2); a `requests` exception class whose constructor the graph links to `Session.request` through an attribute named `request` (1) | 3 |

- The shown path is real in 30 of the 40.
- In 3 more, the first link names a sibling of the method the package binds. For example, `jwt.decode`, which is `PyJWT.decode`, starts at `PyJWS.decode`.

**What following overrides did.** The first version of this change kept the wider graph that follows overrides.
- On it, CALLED rose to 546.
- Its paths included `MiddlewareMixin.__acall__ -> UpdateCacheMiddleware.process_response` for any Django middleware.
- They also included `Image.new -> … -> TiffImageFile.load_end` for a new image.
- Rebuilding those 383 alerts' graphs without overrides kept 240.
- Also dropping unknown-receiver links kept 221. The 19 that this dropped were mostly genuine (sqlparse's lexer, tornado's body parsing, aiohttp's response parser), so unknown receivers stay as #164 left them.

**A narrower re-export rule, measured and not taken.** Packages re-export functions and classes, not methods, so a re-export of a method could be required to name its class too (`git.Repo.clone_from`). Simulated on the 265 alerts:
- Strictly, the rule loses 32 alerts, nearly all genuine `jwt.decode` uses. `jwt.decode` is a module-level name bound to a method of a module-level instance, which the graph does not hold.
- Exempting two-part names like `jwt.decode`, it loses 7: 2 Django collisions, and 5 genuine or dispatch uses (snowflake's `connect` alias, authlib, dnspython).

The rule would also need each caller's kind stored. The better fix is the follow-up below.

## Consequences

- **More alerts carry their real priority.** An alert whose project calls the vulnerable code through the package's public functions now comes first, with the path that shows why. Before, it had UNKNOWN.
- **Some new CALLED alerts are noise:** 3 to 5 in the sample of 40.
  - **Collisions of names under the re-export rule,** such as `default_storage.save` against `LayerMapping.save` or `django.db.backends.postgresql.base.DatabaseWrapper` against GeoDjango's MySQL one.
  - **The graph does not see arguments.** `yaml.load(f, Loader=yaml.SafeLoader)` is CALLED, because `yaml.load` reaches `FullConstructor` with its default loader. This is how the scanner already treats vulnerabilities that depend on arguments: it matches the bare name.
  - **The callers come from one affected release,** not necessarily the user's version. A path can differ at that version, which again errs towards noise.
- **What it misses changes nothing.** These are not followed:
  - dispatch through registries and plugins (`Image.open` choosing a decoder);
  - callbacks another package calls;
  - names computed at run time;
  - a subclass's override.

  Nor does it match a reference to a re-exported class against callers that are its methods: `urllib3.PoolManager` does not match `urllib3.poolmanager.PoolManager.urlopen`. Symbols have the same gap. An alert these would have raised keeps its verdict.
- **Follow-up: store real re-exports.** The callers step already resolves each package's imports, re-exports and star imports. Storing the public names a caller is reachable by would make a name-based re-export guess unnecessary for callers, removing the collisions and the re-exported class gap together. That covers `requests.get` for `requests.api.get`, and module-level aliases such as `jwt.decode`. It is the source-reading approach #141 proposed for symbols.
- **Users see this only once a published database stores callers.** The nightly's database rewrites (`update-db`, `merge-llm`, `import-names`) do not carry the tables yet. Carrying them, and adding the callers step to the nightly, changes the nightly path, so it waits until the 14-night count ends on 2026-12-02. The published CLI 0.9.0 reads a database with the tables normally and ignores them.
- **Not decided here:** using callers to *lower* an alert. "No stored caller is referenced" would be part of a rule for IMPORTED_NOT_CALLED, which is the lifting of ADR 0008 (#162). That needs the wider graph (`overrides=True`, unknown receivers to every method), its own rule chosen on design data, and one evaluation on unseen data.
