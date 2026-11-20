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
    links = sorted({c.url for a in advisories for c in a.fix_candidates if c.host == "github.com"})
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


def check_labels(labels: Sequence[Label], sample: Sample, round_: int) -> list[str]:
    """Problems that keep a round's file from being reviewed: none means it is complete."""
    problems = []
    expected = {(i.advisory, p.name) for i in sample.items for p in i.packages}
    seen: set[tuple[str, str]] = set()
    for label in labels:
        key = (label.advisory, label.package)
        if key not in expected:
            problems.append(f"{label.advisory} {label.package}: not in the sample")
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


def stub_round(sample: Sample, round_: int) -> str:
    """A round's starting file: one ``todo`` entry per advisory and package, in a shuffled
    order (seeded by the round), so the second round is not read in the first one's order."""
    entries = [(i, p) for i in sample.items for p in i.packages]
    random.Random(sample.seed + round_).shuffle(entries)  # noqa: S311 - an order, not a secret
    lines = [
        f"# Python gold set, round {round_}. Follow docs/labelling-guideline.md.",
        "# Fill each entry, then set status: labelled, no_python_symbol or no_fix.",
        "# Never look at a model's answer, a database record or another round while labelling.",
        "",
    ]
    for item, package in entries:
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
        "| # | Advisory | Packages (last vulnerable version) | Fix links |",
        "|---:|---|---|---|",
    ]
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
        lines.append(
            f"| {number} | [{item.advisory}](https://osv.dev/vulnerability/{item.advisory}){mark} "
            f"| {packages} | {commits} |"
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
    first: Sequence[Label], second: Sequence[Label], bootstrap: int = 2000, seed: int = SEED
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
    first: Sequence[Label], second: Sequence[Label], resolved: Sequence[Label] = ()
) -> tuple[list[Label], list[tuple[str, str]]]:
    """The gold labels: an entry both rounds agree on exactly, or its recorded resolution
    (round 3) when they do not. Returns the labels and the entries still unresolved."""
    later = {(b.advisory, b.package): b for b in second}
    resolutions = {(r.advisory, r.package): r for r in resolved if r.status != "todo"}
    final, unresolved = [], []
    for a in first:
        key = (a.advisory, a.package)
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
