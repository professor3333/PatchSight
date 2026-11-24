# ADR 0015: A dunder name alone is not a re-export

- **Status:** accepted
- **Date:** 2026-11-24

## Context

The scanner matches a reference in user code to a vulnerable symbol in four ways (`scan/verdicts.py`, `matches`). The last is the **re-export rule**: same top-level package and same final name. It catches names a package re-exports from its `__init__`, such as `git.Repo` for `git.repo.base.Repo`, which the scanner cannot otherwise see, because it does not read package source.

On the [repository panel](../reports/panel-db-2026.11.23.md) (db-2026.11.23), 123 of the 186 CALLED alerts rest on this rule alone. Each match was checked by resolving the reference through the package's own imports, at the version the project pins ([measurement on #141](https://github.com/professor3333/PatchSight/issues/141)):

| What the match is | Alerts |
|---|---:|
| A genuine re-export | 82 |
| Another genuine use: the same class moved between versions, a use through an object of the symbol's class, or a call that dispatches to it | 8 |
| A name collision only | 33 |

**23 of the 33 collisions share only a dunder name.** Every class has an `__init__`, so `django.test.TestCase.__init__` matched every vulnerable `__init__` in Django, including `HttpResponseRedirectBase.__init__` and `GEOSGeometry.__init__`. werkzeug and Django REST framework had the same pattern. None of the 90 genuine matches ends in a dunder.

A false CALLED errs towards noise, as design rule 3 allows, but it puts the wrong alerts at the top of the report.

## Decision

When the shared final name is a dunder (`__init__`, `__get__`, …), the re-export rule also requires the part before it, the class, to agree. `git.Repo.__init__` still matches `git.repo.base.Repo.__init__`; `django.test.TestCase.__init__` no longer matches `HttpResponseRedirectBase.__init__`.

The other three rules are unchanged:

- the same name;
- the containing class or module of a vulnerable member;
- reaching into a vulnerable class.

So are re-exports of any other name.

## Evidence

- **Reachability fixtures:** both reports regenerate unchanged.
  - With the labelled records: 0 false suppressions, 58 of 58 as expected.
  - With db-2026.11.23: 0 false suppressions.
- **Repository panel, db-2026.11.23:** exactly the 23 dunder-only alerts change, all from CALLED to UNKNOWN. That is 17 Django, 4 werkzeug and 2 Django REST framework alerts. No other alert changes, and none becomes NOT_IMPORTED or IMPORTED_NOT_CALLED. CALLED goes from 186 to 163.

## Consequences

- **The 23 alerts now give their real reason.** These are low-confidence records, so they fall to UNKNOWN with the reason that applies, such as dynamic use the scanner cannot follow.
- **What this can miss:** an explicit `Subclass.__init__(…)` call on a subclass that inherits a vulnerable `__init__`. The scanner does not follow inheritance anyway: `Subclass(…)` was never matched, so the old rule caught that case only by accident.
  - Once high-confidence records are published, a missed match could become IMPORTED_NOT_CALLED. Lifting [ADR 0008](0008-withhold-high-confidence.md) takes its own evaluation, which would measure this.
- **Not done here: a wider rule** that requires the last two parts to agree for every method. It would remove most of the other 10 collisions (such as `flask.request.args.get` against `SecureCookieSession.get`). But it would also drop genuine uses through an object (`flask.session.get`, `default_storage.save`) and through dispatch.
- **Not done here: resolving real re-exports from package source,** which needs pipeline work and its own decision (#141). That resolution would have to run at the user's version, not only at the fix commit: the moved mistune class is the case.
