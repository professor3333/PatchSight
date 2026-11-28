# ADR 0018: A name the package defines otherwise is not a re-export

- **Status:** accepted
- **Date:** 2026-11-28

## Context

The scanner matches a reference to a vulnerable symbol or entry point in four ways (`scan/verdicts.py`, `matches`). The last is the **re-export rule**: same top-level package and same final name. It is a guess at a re-export the scanner cannot see, because the scanner does not read package source. [ADR 0015](0015-a-dunder-name-alone-is-not-a-re-export.md) narrowed it for dunders. It still matches names that only end alike.

- **Pillow.** The dotted entry point `PIL.GdImageFile.open` matches every project's `PIL.Image.open`, though Pillow does not register its GD reader with `Image.open`. That was 7 of the panel's new CALLED alerts in the dotted and cap-dotted shadows (E12), and the owner's review marked the record worse in both.
- **TensorFlow.** `tensorflow.python.ops.ragged.ragged_factory_ops.constant` matches `tf.constant` in the same way; the owner marked those records worse too.

The callers step now reads each record's package source at an affected release ([ADR 0017](0017-stored-callers-mark-an-alert-called.md)). It already stores the names the package binds to its definitions, which rule 2a uses to match callers without the guess. Applying the same strictness to symbols was measured first, and it lost genuine matches:

- On the panel, with callers stored on db-2026.11.27, 21 alerts went from CALLED to UNKNOWN.
  - 8 were collisions, such as `django.core.mail.send_mail` against `PasswordResetForm.send_mail`.
  - 3 were uses through dispatch.
  - **10 were genuine:** `werkzeug.utils.safe_join` against the entry point `werkzeug.security.safe_join`, in 5 advisories and 2 projects.
- The Werkzeug function moved between versions. The projects pin a Werkzeug that still has it in `werkzeug.utils`, while the release read, the newest affected one, defines it only in `werkzeug.security`. The stored names know nothing of the old location, so only the guess finds it.

The guess is wrong only when the reference names **a different definition that exists** in the package. `PIL.Image.open` and `django.core.mail.send_mail` are functions of their own. `werkzeug.utils.safe_join` is not defined in the release read.

## Decision

**For a record with stored callers, the re-export rule does not match an entry point to a name the package defines as another definition.**

- **What the callers step stores.** For each record, the package's definitions that the re-export rule would match to one of its entry points (`callers_collisions`). The test is the scanner's own (`verdicts.guessed_reexport`), so the two cannot drift apart.
  - The stored digest now names the entry points too, so collisions computed for other entry points are stale.
  - Graph revision 5.
- **Why entry points only.** An entry point is the model's claim about a name users write, so a false match there is a false claim. A low-confidence record's symbols are every changed definition, and noise there is what design rule 3 accepts. Counting both, the shadow stored 50,830 collisions and the asset grew by 1.8 MB. Counting entry points alone, it stores 7,502 and grows by 0.35 MB. On the panel, with the cap-dotted entry points, it still takes 13 of the 14 alerts that counting both takes out of CALLED.
- **What rule 2 does.**
  1. It rewrites the reference through the names the package binds, as rule 2a does.
  2. It matches the result to a symbol or entry point by the same name, a member, or a name inside one.
  3. It applies the re-export rule last, and not to a rewritten reference that is one of the stored collisions.
- **Records without stored callers keep the rule as it was.** That covers stale callers too, and every published database until the nightly carries callers.

## Evidence

Measured with callers stored on a copy of db-2026.11.27 (graph revision 5), against the re-export rule as before ([ADR 0017's amendment](0017-stored-callers-mark-an-alert-called.md#amendment-2026-11-28-the-packages-own-names)):

| | Re-export rule | This rule |
|---|---:|---:|
| Panel CALLED, of 3,545 ([report](../reports/panel-db-2026.11.27-shadow-callers.md)) | 474 | 468 |
| Fixtures: false suppressions; as expected, of 58 ([report](../reports/reachability-fixtures-db-2026.11.27-shadow-callers.md)) | 0; 34 | 0; 34 |
| Gzip asset (db-2026.11.27 alone: 4.3 MB) | 9.0 MB | 9.36 MB |

- **6 alerts leave CALLED:**
  - Django's `django.core.mail.send_mail`, against the entry point `PasswordResetForm.send_mail`, in 3 projects;
  - PyJWT's `RSAAlgorithm.from_jwk`, against `HMACAlgorithm.from_jwk`, in 2 projects;
  - dnspython's `dns.rrset.from_text`, against `WKS.from_text`, in 1 project. This is a use through dispatch that the call graph does not follow.
- **With the cap-dotted shadow's entry points** (E12), the 7 alerts that matched `PIL.Image.open` to `PIL.GdImageFile.open` leave CALLED too.
- **The 10 `werkzeug.utils.safe_join` alerts stay CALLED.**
- **Still matched, because only entry points have stored collisions:** defectdojo's `django.core.serializers.deserialize`, against GeoDjango's `BaseGeometryWidget.deserialize`, a symbol.
- **One fixture's reason changes and its verdict does not.** `langgraph-store-search` now matches its symbol under the package's own name for it (rule 2), instead of through a caller.
- **Scan time** for the 5 repositories with 200 or more dependencies: p50 2.43 s, p95 6.08 s. That is within the targets, but above the 1.95 to 2.25 s p50 of the earlier shadow runs on this machine.

## Consequences

- **Fewer false CALLED alerts, and no genuine one lost.** A reference the package's own source shows to be something else no longer matches by name, and every other match stands.
- **Uses through dispatch that only a collision caught are lost**, such as authlib's `JsonWebKey.import_key`, which dispatches to `OctKey.import_key`. The call graph does not follow registry dispatch (ADR 0017), so these come back only if it learns to.
- **The guess stays for names the release read does not define.** Some of those will still be collisions in another version of the package. The names come from one affected release, not the user's version.
- **TensorFlow is not fixed.** Its wheels are larger than the 50 MB the callers step reads, so its records have no stored callers and keep the rule as it was. Raising that limit for a few large packages is a separate decision.
- **This changes only what a scan matches,** so it reaches users with the CLI release that ships it, once published databases carry callers.
