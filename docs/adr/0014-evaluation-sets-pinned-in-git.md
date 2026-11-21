# ADR 0014: Evaluation sets pinned in git, not DVC

- **Status:** accepted
- **Date:** 2026-11-21

## Context

Design rule 17 and the proposal (§10, §13) say to freeze the evaluation sets in DVC before tuning prompts. The point is that no set can change after results have been read from it, and that anyone can get the exact sets back.

What the evaluation sets turned out to be:

- **Small.** Ten files and one folder, 2.0 MB together. The largest is the PyPI regression set at 740 KB.
- **Free of third-party code** (rule 13). They hold IDs, names, paths, line ranges, token counts, commit SHAs and labels, so all of them can be public.
- **Already committed.** `make reproduce`, the injection, retrieval and regression replays and the gold-set tooling all read them from the repository, so a clone has everything.

The large inputs are a different kind of thing. The OSV dump, the Dunlap CSVs and the top-packages list are pinned by URL and SHA-256 in `manifests/snapshot.json`. The GoVulnDB zip behind the holdout is pinned by SHA-256 in the holdout file itself. All of them can be downloaded again and checked, so none needs storing.

DVC would add a remote to host for no gain (§19, open question 7) and a second tool for contributors to learn. Meanwhile only two sets refused edits: the Dunlap split, which hashes itself, and the regression set, whose SHA-256 is in code. The Go holdout, the gold sample and round 1 labels, the reachability fixtures, the locator sample, the panel, the injection plans and the retrieval bundle could all change without anything noticing.

## Decision

The evaluation sets stay in git, and **`manifests/eval-sets.json` pins every one by SHA-256**. CI runs `python -m patchsight.pipeline eval-sets` on every push, and it fails if any set has changed. This gives the guarantee rule 17 asks of DVC, with no remote.

- **A folder** (the reachability fixtures) is pinned by the digest of its sorted file list with each file's SHA-256. A file added, removed, renamed or edited anywhere in it changes the pin. Byte-code caches and editor files are ignored.
- **Re-pinning is deliberate:** `eval-sets --repin <name>`, in the commit that says why. The PyPI regression set keeps its pin in code too, and a test holds the two equal.
- **A new set joins the manifest in the pull request that adds it.** That covers each gold-set round once it is complete (the [labelling guideline](../labelling-guideline.md) says so).
- **Recorded model answers** (the replay bundles) are not listed. They are pinned through the reports they regenerate, which CI already checks byte for byte.

## Consequences

- No DVC, no remote and no `dvc pull`. `.gitignore` drops its DVC entries.
- Git history is the version history of every set, and a set's first commit is its freeze date, recorded in the manifest.
- **When to revisit:** if a set must hold third-party code, or grows past what git handles comfortably (tens of megabytes). Such a set would need DVC with a private remote, recorded in a new ADR.
