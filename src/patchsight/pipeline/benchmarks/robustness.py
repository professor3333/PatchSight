"""The extractor on hard real inputs: the Dunlap reports whose fix spans several commits, is
large, renames a file, only adds code, or adds a new definition.

The deterministic robustness suite (``tests/test_robustness.py``) checks how the pipeline
handles such fixes. This measures what the model then makes of them, from the committed
answers, with no model call. ``robustness-freeze`` records each report's properties from
the HTTP cache (counts and flags only: no code, no advisory text), so CI can regenerate the
report offline.

Non-English commit messages are not measured here: no commit message reaches a prompt
(``tests/test_robustness.py``). Nothing here chooses anything; it describes.
"""

from collections.abc import Callable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict

from patchsight.eval.metrics import SetScores, score
from patchsight.pipeline.benchmarks.replay import ReplayBundle, replay_report
from patchsight.pipeline.diffs.commits import CommitMapping
from patchsight.pipeline.diffs.mapping import definitions, language_for
from patchsight.pipeline.week1 import Share, wilson

NAME = "dunlap-v1-robustness"
LARGE = 15  # candidates: more than E4's output cap keeps (14), so a prompt is cut


class Case(BaseModel):
    """One report's fix, described by what makes it hard."""

    model_config = ConfigDict(frozen=True)

    report: str
    split: str
    commits: int
    files: int  # files the fix commits change, before the path filter
    candidates: int  # changed functions and methods: the prompt's candidates before the cut
    renamed: bool  # a mapped file was renamed
    add_only: bool  # no changed definition lost a line: the fix only adds code
    adds_definition: bool  # a candidate is new: absent from the file before the fix


class Bundle(BaseModel):
    model_config = ConfigDict(frozen=True)

    benchmark: str
    split_sha256: str
    cases: tuple[Case, ...]


def describe(
    report: str,
    split: str,
    mappings: Sequence[CommitMapping],
    candidates: Sequence[tuple[str, str]],
    before: Callable[[CommitMapping, str, str | None], bytes | None],
) -> Case:
    """``candidates``: the prompt's (path, name) pairs. ``before(mapping, path, previous)``
    returns a file's content at the fix commit's parent, or None if it did not exist."""
    names_before: dict[tuple[str, str], set[str]] = {}
    for mapping in mappings:
        for file in mapping.files:
            path = file.mapping.path
            language = language_for(path)
            old = None if file.status == "added" or language is None else (
                before(mapping, path, file.previous_path)
            )  # fmt: skip
            found = definitions(old, language)[0] if old is not None and language else []
            names_before[(mapping.sha, path)] = {d.name for d in found}
    changed = [(m.sha, f.mapping.path, c) for m in mappings for f in m.files
               for c in f.mapping.changed]  # fmt: skip
    wanted = set(candidates)
    shown = [(sha, path, c) for sha, path, c in changed if (path, c.name) in wanted]
    return Case(
        report=report,
        split=split,
        commits=len(mappings),
        files=sum(len(m.files) + len(m.skipped) for m in mappings),
        candidates=len(candidates),
        renamed=any(f.previous_path for m in mappings for f in m.files),
        add_only=bool(shown) and all("pre" not in c.sides for _, _, c in shown),
        adds_definition=any(c.name not in names_before.get((sha, path), set())
                            for sha, path, c in shown),
    )  # fmt: skip


SLICES: tuple[tuple[str, Callable[[Case, bool], bool]], ...] = (
    ("Every report", lambda c, cut: True),
    ("The fix spans several commits", lambda c, cut: c.commits > 1),
    (f"{LARGE} or more candidates", lambda c, cut: c.candidates >= LARGE),
    ("The prompt was cut to fit the budget", lambda c, cut: cut),
    ("A file is renamed", lambda c, cut: c.renamed),
    ("The fix only adds code", lambda c, cut: c.add_only),
    ("The fix adds a new definition", lambda c, cut: c.adds_definition),
)


class SliceScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    reports: int
    extractor: SetScores | None
    changedfuncs: SetScores | None
    misses: Share  # reports where the extractor returned no true symbol


class Report(BaseModel):
    model_config = ConfigDict(frozen=True)

    bundle_sha256: str
    model: str
    prompt_version: str
    largest_fix_files: int
    slices: tuple[SliceScore, ...]


def evaluate(
    bundle: Bundle, answers: ReplayBundle, truth: Mapping[str, set[str]],
    changedfuncs: Mapping[str, set[str]], bundle_sha256: str,
) -> Report:  # fmt: skip
    """Each slice: the extractor's replayed answers and ChangedFuncs on the same reports."""
    replayed = {r.id: r for r in answers.reports}
    predicted = {k: replay_report(r, answers.prompt_version)[1] for k, r in replayed.items()}
    slices = []
    for name, member in SLICES:
        ids = [c.report for c in bundle.cases if member(c, replayed[c.report].truncated)]
        if not ids:
            slices.append(SliceScore(name=name, reports=0, extractor=None, changedfuncs=None,
                                     misses=wilson(0, 0)))  # fmt: skip
            continue
        extractor = score({k: predicted[k] for k in ids}, {k: truth[k] for k in ids})
        baseline = score({k: changedfuncs[k] for k in ids}, {k: truth[k] for k in ids})
        missed = round(extractor.miss_rate * extractor.reports)
        slices.append(SliceScore(name=name, reports=len(ids), extractor=extractor,
                                 changedfuncs=baseline,
                                 misses=wilson(missed, len(ids))))  # fmt: skip
    return Report(bundle_sha256=bundle_sha256, model=answers.model,
                  prompt_version=answers.prompt_version,
                  largest_fix_files=max(c.files for c in bundle.cases),
                  slices=tuple(slices))  # fmt: skip


def render_markdown(report: Report, bundle_path: str, answers_path: str) -> str:
    lines = [
        "# Robustness on real inputs: Dunlap Go benchmark",
        "",
        "Generated by `python -m patchsight.pipeline robustness-report`; do not edit by hand. "
        "The extractor's committed answers, replayed with the live validator (no model call), "
        "on the reports whose fixes have each property. Report properties come from "
        f"[`{bundle_path}`](../../{bundle_path}) (SHA-256 `{report.bundle_sha256}`), frozen "
        "from the fix commits; the answers from "
        f"[`{answers_path}`](../../{answers_path}).",
        "",
        f"- Extractor: `{report.model}`, prompt `{report.prompt_version}`",
        "- A report is a miss when the extractor returned none of its labelled symbols. "
        "ChangedFuncs marks every changed function on the same reports.",
        f"- The largest fix changes {report.largest_fix_files} files. Commit messages never "
        "reach a prompt, so their language is not measured.",
        "",
        "| Reports whose fix… | Reports | Precision | Recall | F1 | Miss rate (95% CI) | "
        "ChangedFuncs F1 | ChangedFuncs miss rate |",
        "|---|---:|---:|---:|---:|---|---:|---:|",
    ]
    for s in report.slices:
        if s.extractor is None or s.changedfuncs is None:
            lines.append(f"| {s.name} | 0 | — | — | — | — | — | — |")
            continue
        e, b, m = s.extractor, s.changedfuncs, s.misses
        lines.append(
            f"| {s.name} | {s.reports} | {e.precision:.3f} | {e.recall:.3f} | {e.f1:.3f} | "
            f"{m.share:.1%} ({m.count}; {m.ci95_low:.1%} to {m.ci95_high:.1%}) | {b.f1:.3f} | "
            f"{b.miss_rate:.1%} |"
        )
    lines += [
        "",
        "Slices overlap, and small ones have wide intervals: read them as where the extractor "
        "struggles, not as rates to compare closely.",
        "",
        "A low-confidence record lists every changed definition ([ADR 0004]"
        "(../adr/0004-fall-back-to-the-baseline.md)), and every published record is low "
        "confidence for now ([ADR 0008](../adr/0008-withhold-high-confidence.md)). So a scan "
        "matches against every changed definition, as ChangedFuncs does: a miss above leaves "
        "the extractor's picks short, not what a scan can find.",
        "",
    ]
    return "\n".join(lines)
