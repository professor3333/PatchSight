"""The Python gold set (proposal §10, dataset 3; ``docs/labelling-guideline.md``).

Three parts, in the order the guideline asks for them:

1. **The sample**, chosen before any labelling by a recorded seed: PyPI vulnerabilities whose
   fix commits the pipeline maps to Python definitions (the ones extraction can be scored
   on), plus every one whose upstream advisory already carries symbol data.
2. **The labels**, one TOML entry per advisory and package, written by the annotator in two
   blind rounds a week apart (``annotations/python-gold-v1/round<N>.toml``). Each round's
   file starts as stubs with status ``todo``; nothing in it comes from a model.
3. **Agreement and scoring**: the two rounds against each other, then the extraction
   against the agreed labels.

Labels hold IDs, names and versions only: no advisory text and no code.
"""

import random
import tomllib
from collections.abc import Iterable, Mapping, Sequence, Set
from pathlib import Path
from typing import Literal

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, field_validator

from patchsight.eval.metrics import Interval, SetScores, jaccard, score
from patchsight.eval.safety import SafetyScores, safety
from patchsight.pipeline.ingest.aliases import AliasGroup
from patchsight.pipeline.ingest.osv import Advisory, AffectedPackage

NAME = "python-gold-v1"
DIRECTORY = Path("annotations/python-gold-v1")
SAMPLE = DIRECTORY / "sample.json"
SEED = 20261120
SIZE = 120  # the guideline's 100 to 150, with room for advisories that turn out unlabellable
# Declared on 2026-11-20, before any labelling: the first DECLARED entries of round 1's seeded
# order are labelled in both rounds, and only they are scored. Extending the set (to 120) must
# be decided before any score is run, in a commit that says so.
DECLARED = 60


class PackageVersions(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    last_vulnerable: str | None  # the version to read the code at, when OSV lists it
    fixed: str | None  # the first fixed version, when OSV gives one


class SampleItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisory: str
    identifiers: tuple[str, ...]
    packages: tuple[PackageVersions, ...]
    fix_links: tuple[str, ...]  # GitHub commit and pull-request URLs from the references
    upstream: bool  # the advisory already carries affected_functions or imports


class Sample(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    seed: int
    snapshot_sha256: str
    population: int
    upstream: int
    items: tuple[SampleItem, ...]


def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def package_versions(package: AffectedPackage) -> PackageVersions:
    """The last version OSV lists as affected (or a ``last_affected`` event), and the first
    ``fixed`` event. Either can be missing: then the annotator reads the fix's parent."""
    listed = [v for v in (_version(t) for t in package.versions) if v is not None]
    events = [e for r in package.ranges for e in r.events]
    last = max(listed) if listed else None
    if last is None:
        marked = [v for v in (_version(e.last_affected or "") for e in events) if v is not None]
        last = max(marked) if marked else None
    fixed = sorted(v for v in (_version(e.fixed or "") for e in events) if v is not None)
    return PackageVersions(
        name=package.name, last_vulnerable=None if last is None else str(last),
        fixed=str(fixed[0]) if fixed else None,
    )  # fmt: skip


def sample_item(group: AliasGroup, by_id: Mapping[str, Advisory]) -> SampleItem:
    advisories = [by_id[i] for i in group.advisory_ids]
    packages: dict[str, PackageVersions] = {}
    for advisory in advisories:
        for package in advisory.packages:
            packages.setdefault(package.name, package_versions(package))
    links = sorted({
        c.url for a in advisories for c in a.fix_candidates
        if c.host == "github.com" and any(p in c.url for p in ("/commit/", "/pull/", "/compare/"))
    })  # fmt: skip
    return SampleItem(
        advisory=group.key, identifiers=tuple(sorted(group.identifiers)),
        packages=tuple(packages[n] for n in sorted(packages)), fix_links=tuple(links),
        upstream=any(a.symbol_hints for a in advisories),
    )  # fmt: skip


def draw(
    groups: Sequence[AliasGroup],
    by_id: Mapping[str, Advisory],
    extractable: Iterable[str],
    snapshot_sha256: str,
    size: int = SIZE,
    seed: int = SEED,
) -> Sample:
    """Every upstream-labelled vulnerability, then a seeded sample of the extractable rest."""
    eligible = set(extractable)
    upstream = sorted(g.key for g in groups if any(by_id[i].symbol_hints for i in g.advisory_ids))
    pool = sorted(g.key for g in groups if g.key in eligible and g.key not in set(upstream))
    chosen = set(upstream) | set(
        random.Random(seed).sample(pool, max(0, min(size - len(upstream), len(pool))))  # noqa: S311 - a reproducible sample, not a secret
    )
    by_key = {g.key: g for g in groups}
    return Sample(
        name=NAME, seed=seed, snapshot_sha256=snapshot_sha256, population=len(pool),
        upstream=len(upstream), items=tuple(sample_item(by_key[k], by_id) for k in sorted(chosen)),
    )  # fmt: skip


# --- Labels -------------------------------------------------------------------------------

Status = Literal["todo", "labelled", "no_python_symbol", "no_fix"]


class Label(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    advisory: str
    package: str
    version: str
    symbols: tuple[str, ...] = ()
    entry_points: tuple[str, ...] = ()
    status: Status
    note: str = ""
    round: int

    @field_validator("symbols")
    @classmethod
    def _module_and_name(cls, symbols: tuple[str, ...]) -> tuple[str, ...]:
        for symbol in symbols:
            module, colon, name = symbol.partition(":")
            if not colon or not module or not name or " " in symbol:
                raise ValueError(f"{symbol!r}: write a symbol as module:Qualified.name")
        return symbols

    @property
    def qualified(self) -> frozenset[str]:
        """Symbols as the database names them: ``module.Qualified.name``."""
        return frozenset(s.replace(":", ".", 1) for s in self.symbols)


def load_labels(path: Path) -> list[Label]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return [Label.model_validate(entry) for entry in data.get("label", [])]


Entry = tuple[str, str]  # (advisory, package)


def round_order(sample: Sample, round_: int) -> list[tuple[SampleItem, PackageVersions]]:
    """Every entry in a round's own order, shuffled by the round's seed, so the second round
    is not read in the first one's order."""
    entries = [(i, p) for i in sample.items for p in i.packages]
    random.Random(sample.seed + round_).shuffle(entries)  # noqa: S311 - an order, not a secret
    return entries


def declared(sample: Sample, size: int = DECLARED) -> frozenset[Entry]:
    """The entries labelled and scored: the first ``size`` of round 1's order."""
    return frozenset((i.advisory, p.name) for i, p in round_order(sample, 1)[:size])


def check_labels(
    labels: Sequence[Label], sample: Sample, round_: int, scope: Set[Entry] | None = None
) -> list[str]:
    """Problems that keep a round's file from being reviewed: none means it is complete.
    Only entries in ``scope`` (default: all) must be finished; the rest are not checked."""
    problems = []
    every = {(i.advisory, p.name) for i in sample.items for p in i.packages}
    expected = every if scope is None else set(scope)
    seen: set[tuple[str, str]] = set()
    for label in labels:
        key = (label.advisory, label.package)
        if key not in every:
            problems.append(f"{label.advisory} {label.package}: not in the sample")
            continue
        if key not in expected:
            continue
        if key in seen:
            problems.append(f"{label.advisory} {label.package}: labelled twice")
        seen.add(key)
        if label.round != round_:
            problems.append(f"{label.advisory} {label.package}: round {label.round}, not {round_}")
        if label.status == "todo":
            problems.append(f"{label.advisory} {label.package}: still todo")
        if label.status == "labelled" and not label.symbols:
            problems.append(f"{label.advisory} {label.package}: labelled with no symbol")
        if label.status != "labelled" and label.symbols:
            problems.append(f"{label.advisory} {label.package}: {label.status} but lists symbols")
    problems += [f"{a} {p}: missing" for a, p in sorted(expected - seen)]
    return problems


def _toml_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def stub_round(sample: Sample, round_: int, only: Set[Entry] | None = None) -> str:
    """A round's starting file: one ``todo`` entry per advisory and package (or per entry in
    ``only``), in the round's own order. Round 1's file marks where the declared set ends."""
    entries = [(i, p) for i, p in round_order(sample, round_)
               if only is None or (i.advisory, p.name) in only]  # fmt: skip
    lines = [
        f"# Python gold set, round {round_}. Follow docs/labelling-guideline.md.",
        "# Fill each entry, then set status: labelled, no_python_symbol or no_fix.",
        "# Never look at a model's answer, a database record or another round while labelling.",
        "",
    ]
    for index, (item, package) in enumerate(entries):
        if round_ == 1 and only is None and index == DECLARED:
            lines += [
                f"# ---- The declared {DECLARED} end here. The entries below stay todo unless the",
                "# ---- set is extended, which is decided before any score is run.",
                "",
            ]
        version = package.last_vulnerable or (
            f"before {package.fixed}" if package.fixed else "unknown"
        )
        lines += [
            "[[label]]",
            f"advisory = {_toml_string(item.advisory)}",
            f"package = {_toml_string(package.name)}",
            f"version = {_toml_string(version)}",
            "symbols = []",
            "entry_points = []",
            'status = "todo"',
            'note = ""',
            f"round = {round_}",
            "",
        ]
    return "\n".join(lines)


def worksheet(sample: Sample) -> str:
    """Links for each advisory: where to read it and its fix. No advisory text is copied."""
    lines = [
        f"# Python gold set worksheet (`{sample.name}`)",
        "",
        "Generated by `python -m patchsight.pipeline gold-sample`; do not edit by hand. Each row "
        "links the advisory and its fix commits; read them there, then record the label in the "
        "round's TOML file, as [the labelling guideline](../../docs/labelling-guideline.md) says.",
        "",
        f"- {len(sample.items)} advisories, seed {sample.seed}, drawn from {sample.population:,} "
        f"whose fixes change Python definitions, plus the {sample.upstream} that carry upstream "
        "symbol data",
        f"- Snapshot SHA-256 `{sample.snapshot_sha256}`",
        "",
        f"- **Declared {DECLARED}:** the entries labelled and scored are the first {DECLARED} "
        "of `round1.toml`, marked here",
        "",
        "| # | Advisory | Packages (last vulnerable version) | Fix links | Declared |",
        "|---:|---|---|---|:---:|",
    ]
    chosen = declared(sample)
    for number, item in enumerate(sample.items, 1):
        packages = ", ".join(
            f"{p.name} {p.last_vulnerable or (f'< {p.fixed}' if p.fixed else '?')}"
            for p in item.packages
        )
        commits = (
            ", ".join(
                f"[{url.rstrip('/').rsplit('/', 1)[-1][:10]}]({url})" for url in item.fix_links
            )
            or "none linked"
        )
        mark = " (upstream symbols)" if item.upstream else ""
        flag = "✓" if any((item.advisory, p.name) in chosen for p in item.packages) else ""
        lines.append(
            f"| {number} | [{item.advisory}](https://osv.dev/vulnerability/{item.advisory}){mark} "
            f"| {packages} | {commits} | {flag} |"
        )
    return "\n".join(lines) + "\n"


# --- Agreement between rounds, and the final labels ----------------------------------------


class Disagreement(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisory: str
    package: str
    first: tuple[str, ...]  # status, then symbols
    second: tuple[str, ...]


class Agreement(BaseModel):
    model_config = ConfigDict(frozen=True)

    compared: int  # entries finished in both rounds
    advisories: int
    exact_match: float
    exact_ci95: Interval
    mean_jaccard: float
    jaccard_ci95: Interval
    disagreements: tuple[Disagreement, ...]


def _overlap(a: Label, b: Label) -> float:
    if a.status != b.status:
        return 0.0
    if a.status != "labelled":
        return 1.0
    return jaccard(a.qualified, b.qualified)


def _summary(label: Label) -> tuple[str, ...]:
    return (label.status, *sorted(label.symbols))


def agreement(
    first: Sequence[Label],
    second: Sequence[Label],
    bootstrap: int = 2000,
    seed: int = SEED,
    scope: Set[Entry] | None = None,
) -> Agreement:
    """Self-agreement over the entries both rounds finished: the exact-match share and the
    mean Jaccard overlap of the symbol sets, each with a bootstrap interval that resamples
    advisories (the guideline's measure)."""
    later = {(b.advisory, b.package): b for b in second if b.status != "todo"}
    by_advisory: dict[str, list[float]] = {}
    disagreements = []
    for a in first:
        b = later.get((a.advisory, a.package))
        if a.status == "todo" or b is None:
            continue
        if scope is not None and (a.advisory, a.package) not in scope:
            continue
        overlap = _overlap(a, b)
        by_advisory.setdefault(a.advisory, []).append(overlap)
        if overlap < 1.0:
            disagreements.append(Disagreement(
                advisory=a.advisory, package=a.package, first=_summary(a), second=_summary(b),
            ))  # fmt: skip
    groups = [by_advisory[k] for k in sorted(by_advisory)]

    def measures(chosen: Sequence[list[float]]) -> tuple[float, float]:
        values = [v for g in chosen for v in g]
        if not values:
            return 0.0, 0.0
        return sum(v == 1.0 for v in values) / len(values), sum(values) / len(values)

    exact, mean = measures(groups)
    rng = random.Random(seed)  # noqa: S311 - statistical resampling, not security
    draws = [
        measures([rng.choice(groups) for _ in groups]) for _ in range(bootstrap if groups else 0)
    ]

    def interval(index: int) -> Interval:
        values = sorted(d[index] for d in draws) or [0.0]
        return Interval(low=values[int(0.025 * (len(values) - 1))],
                        high=values[int(0.975 * (len(values) - 1))])  # fmt: skip

    return Agreement(
        compared=sum(len(g) for g in groups), advisories=len(groups), exact_match=exact,
        exact_ci95=interval(0), mean_jaccard=mean, jaccard_ci95=interval(1),
        disagreements=tuple(disagreements),
    )  # fmt: skip


def final_labels(
    first: Sequence[Label],
    second: Sequence[Label],
    resolved: Sequence[Label] = (),
    scope: Set[Entry] | None = None,
) -> tuple[list[Label], list[tuple[str, str]]]:
    """The gold labels: an entry both rounds agree on exactly, or its recorded resolution
    (round 3) when they do not. Returns the labels and the entries still unresolved."""
    later = {(b.advisory, b.package): b for b in second}
    resolutions = {(r.advisory, r.package): r for r in resolved if r.status != "todo"}
    final, unresolved = [], []
    for a in first:
        key = (a.advisory, a.package)
        if scope is not None and key not in scope:
            continue
        b = later.get(key)
        if a.status == "todo" or b is None or b.status == "todo":
            unresolved.append(key)
        elif _overlap(a, b) == 1.0:
            final.append(a)
        elif key in resolutions:
            final.append(resolutions[key])
        else:
            unresolved.append(key)
    return final, unresolved


# --- Scoring the extraction against the labels --------------------------------------------


class GoldScores(BaseModel):
    model_config = ConfigDict(frozen=True)

    system: str
    strict: SetScores  # exact names, as the database writes them
    lenient: SafetyScores  # names matched on a dotted boundary (module layouts differ)


def score_against(
    labels: Sequence[Label], systems: Mapping[str, Mapping[str, Set[str]]], bootstrap: int = 2000
) -> list[GoldScores]:
    """Each system's symbols per ``advisory/package`` against the labelled entries (entries
    whose flaw is in no Python symbol, or whose fix was not found, are not scored)."""
    truth = {
        f"{lb.advisory}/{lb.package}": set(lb.qualified) for lb in labels if lb.status == "labelled"
    }
    results = []
    for name, predicted in systems.items():
        guesses = {k: set(predicted.get(k, ())) for k in truth}
        results.append(GoldScores(
            system=name, strict=score(guesses, truth, bootstrap=bootstrap, seed=SEED),
            lenient=safety(guesses, truth),
        ))  # fmt: skip
    return results


def render_agreement(result: Agreement) -> str:
    lines = [
        f"# Python gold set: self-agreement between rounds 1 and 2 (`{NAME}`)",
        "",
        "Generated by `python -m patchsight.pipeline gold-agreement`; do not edit by hand. The "
        "same annotator labelled each advisory twice, a week apart and blind to the first "
        "round, as [the labelling guideline](../labelling-guideline.md) asks.",
        "",
        f"- Entries finished in both rounds: {result.compared} ({result.advisories} advisories)",
        f"- **Exact match:** {result.exact_match:.1%} (95% interval {result.exact_ci95.low:.1%} "
        f"to {result.exact_ci95.high:.1%})",
        f"- **Mean Jaccard overlap:** {result.mean_jaccard:.3f} (95% interval "
        f"{result.jaccard_ci95.low:.3f} to {result.jaccard_ci95.high:.3f})",
        "",
        f"## Disagreements ({len(result.disagreements)}), resolved in a third pass",
        "",
        "| Advisory | Package | Round 1 | Round 2 |",
        "|---|---|---|---|",
        *(
            f"| {d.advisory} | {d.package} | {', '.join(d.first)} | {', '.join(d.second)} |"
            for d in result.disagreements
        ),
        "",
    ]
    return "\n".join(lines)


def render_scores(scores: Sequence[GoldScores], labelled: int, unresolved: int) -> str:
    lines = [
        f"# Python gold set: extraction against the labels (`{NAME}`)",
        "",
        "Generated by `python -m patchsight.pipeline gold-eval`; do not edit by hand.",
        "",
        f"- Labelled entries scored: {labelled}; still unresolved and not scored: {unresolved}",
        "- *Strict* compares names exactly, as the database writes them, with an "
        "advisory-level bootstrap. *Lenient* matches names on a dotted boundary.",
        "",
        "| System | Precision | Recall | F1 (95% interval) | Miss rate | Lenient recall | "
        "Lenient miss rate |",
        "|---|---:|---:|---|---:|---:|---:|",
    ]
    for s in scores:
        ci = s.strict.f1_ci95
        f1 = f"{s.strict.f1:.3f}" + (f" ({ci.low:.2f} to {ci.high:.2f})" if ci else "")
        lines.append(
            f"| {s.system} | {s.strict.precision:.3f} | {s.strict.recall:.3f} | {f1} | "
            f"{s.strict.miss_rate:.1%} | {s.lenient.recall:.3f} | {s.lenient.miss_rate:.1%} |"
        )
    return "\n".join([*lines, ""])
