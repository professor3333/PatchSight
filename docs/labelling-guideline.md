# Labelling guideline: the Python gold set

One page, for one annotator. It says what a label is, how to find it, and how to record it, so that a label can be checked by someone else and repeated by the same person a week later.

## What a label is

For one PyPI advisory, a label names:

- **the vulnerable symbols**: the functions, methods or classes, at the **last vulnerable version**, whose code holds the flaw;
- **the public entry points**: names a user of the package calls that reach a vulnerable symbol, such as `yaml.full_load` for a flaw in `FullConstructor`.

It is a claim about the package's code, never about any application that uses it.

## How to find it

1. **Read the advisory** for what goes wrong and under which input.
2. **Read the fix commit**, then the code at the last vulnerable version. Never label from the diff alone: the flaw is in the old code.
3. **Label where the flaw is, not where the fix is.**
   - A fix that adds a check to a caller labels the **caller**, because that is where unchecked input was used.
   - A fix that adds a new helper labels the **functions that now call it**, not the helper.
   - A refactor, rename or test change that ships with the fix is **not** labelled.
   - A flaw the fix never touched, such as an unchanged function whose callee changed, **is** labelled. This is what a patch-only extractor cannot find, and the gold set must show it.
4. **Entry points** are public names, as a user writes them (`requests.get`, `jinja2.Environment`). List the few that a typical user reaches the flaw through, not every path.
5. **Conditions** go in the note, such as "only with `Loader=FullLoader`" or "only on Windows". The symbol is still labelled.

## When to stop

- **Unsure** between two symbols: label both and write why in the note. Do not guess one.
- **No Python code holds the flaw**, for example a bundled C library or a packaging problem: label it `no_python_symbol`.
- **The fix cannot be found** or is not public: label it `no_fix` and stop.
- **Allow about 15 minutes per advisory.** Past that, label what is clear and record the rest as unsure.

## How to record it

One TOML entry per advisory in `annotations/`, with IDs and names only. Copy no advisory text and no code.

```toml
[[label]]
advisory = "GHSA-xxxx-xxxx-xxxx"
package = "example"
version = "1.2.3"                      # the last vulnerable version read
symbols = ["example.module:Class.method"]
entry_points = ["example.public_function"]
status = "labelled"                    # labelled | no_python_symbol | no_fix
note = "Only reached when strict=False."
round = 1                              # 1, or 2 for the repeat a week later
```

## Rules that protect the labels

- **Never look at a model's answer, a database record or an earlier round** while labelling. The second round is done blind to the first.
- **Choose the advisories before labelling,** by a recorded random seed, and keep them out of every prompt and few-shot example.
- **A label joins the gold set only after review,** through a pull request (design rule 9).
- **Self-agreement is reported per advisory,** comparing the two rounds as the exact-match share and the mean Jaccard overlap of the symbol sets, with a bootstrap interval. Disagreements are resolved in a third pass, and the resolution is recorded.
