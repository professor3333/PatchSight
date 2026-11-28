"""Reachability fixtures: small programs whose use of a vulnerable symbol is known.

Each case is a directory of Python (and sometimes template) files under
``tests/fixtures/reachability``, written for one advisory and one pinned version of its
package. ``calls`` is the truth: whether the program's own code uses the vulnerable code
directly, through an alias, a re-export, a subclass, a template or an object it holds.
Use only through another package does not count; the scanner does not claim to analyse
it (``NOT_IMPORTED`` does not mean safe).

``expected`` is the verdict the documented rules give when the symbol data is right:
``CALLED`` for use the scanner can resolve, ``UNKNOWN`` for use it cannot, and the
two "not" verdicts otherwise. A **false suppression** is a case that calls the vulnerable
code but gets ``IMPORTED_NOT_CALLED`` or ``NOT_IMPORTED``. The target is zero.

Two kinds of symbol data are scored:

* **labelled**: the hand-written record in ``cases.toml``, at high confidence. This
  measures the scanner alone.
* **a published database**: what users get today.

No network: the advisory is named in the manifest, so OSV is not asked. The pins are
checked against OSV by a live test.
"""

import tomllib
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, computed_field

from patchsight.db import Callers, FixCommitRef, Record, Symbol, SymbolDatabase
from patchsight.names import canonical_package_name
from patchsight.scan.ast_scanner import scan
from patchsight.scan.verdicts import DISPLAY_ORDER, Verdict, decide

FIXTURES = Path("tests/fixtures/reachability")
MANIFEST = "cases.toml"
SUPPRESSING: frozenset[Verdict] = frozenset({"IMPORTED_NOT_CALLED", "NOT_IMPORTED"})
_LABELLED_AT = datetime(2026, 11, 18, tzinfo=UTC)


class Advisory(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    package: str
    version: str
    import_roots: tuple[str, ...]
    symbols: tuple[str, ...]  # module:qualname
    entry_points: tuple[str, ...]
    note: str


class Case(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    advisory: str
    calls: bool
    form: str
    expected: Verdict


class Fixtures(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisories: dict[str, Advisory]
    cases: tuple[Case, ...]

    @property
    def packages(self) -> set[str]:
        return {a.package for a in self.advisories.values()}


def load(directory: Path) -> Fixtures:
    data = tomllib.loads((directory / MANIFEST).read_text(encoding="utf-8"))
    advisories = [Advisory.model_validate(a) for a in data["advisory"]]
    cases = tuple(Case.model_validate(c) for c in data["case"])
    return Fixtures(advisories={a.id: a for a in advisories}, cases=cases)


def labelled_record(advisory: Advisory) -> Record:
    """The hand-written symbol data as a high-confidence override record."""
    symbols = []
    for written in advisory.symbols:
        module, qualname = written.split(":")
        if module.split(".")[0] not in advisory.import_roots:
            raise ValueError(f"{written} is not under {advisory.import_roots}")
        symbols.append(
            Symbol(
                qualified_name=f"{module}.{qualname}",
                module=module,
                name=qualname,
                kind="method" if "." in qualname else "function",
                path=f"{module.replace('.', '/')}.py",
            )
        )
    return Record(
        vulnerability=advisory.id,
        package=canonical_package_name(advisory.package),
        confidence="high",
        source="override",
        import_roots=advisory.import_roots,
        entry_points=advisory.entry_points,
        symbols=tuple(symbols),
        fix_commits=(FixCommitRef(repo="fixtures/reachability", sha="0" * 40),),
        model=None,
        prompt_version=None,
        input_hash="fixture",
        advisory_modified=_LABELLED_AT,
        truncated=False,
        extracted_at=_LABELLED_AT,
    )


class Outcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    case: str
    advisory: str
    package: str
    calls: bool
    form: str
    expected: Verdict
    verdict: Verdict
    reason: str
    confidence: str | None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def false_suppression(self) -> bool:
        return self.calls and self.verdict in SUPPRESSING

    @computed_field  # type: ignore[prop-decorator]
    @property
    def as_expected(self) -> bool:
        return self.verdict == self.expected


class FixtureRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: str  # "labelled", or "database <version>"
    outcomes: tuple[Outcome, ...]

    @property
    def false_suppressions(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.false_suppression]


def run(
    fixtures: Fixtures,
    directory: Path,
    records: Callable[[Advisory], Record | None],
    data: str,
    callers: Callable[[Advisory], Callers | None] = lambda _: None,
) -> FixtureRun:
    outcomes = []
    for case in fixtures.cases:
        advisory = fixtures.advisories[case.advisory]
        record = records(advisory)
        package = canonical_package_name(advisory.package)
        usage = scan(directory / case.name)
        found = callers(advisory) if record else None
        alert = decide(advisory.id, package, advisory.version, record, usage, callers=found)
        outcomes.append(
            Outcome(
                case=case.name,
                advisory=advisory.id,
                package=package,
                calls=case.calls,
                form=case.form,
                expected=case.expected,
                verdict=alert.verdict,
                reason=alert.reason,
                confidence=record.confidence if record else None,
            )
        )
    return FixtureRun(data=data, outcomes=tuple(outcomes))


def run_labelled(fixtures: Fixtures, directory: Path) -> FixtureRun:
    return run(fixtures, directory, labelled_record, "labelled")


def run_database(fixtures: Fixtures, directory: Path, database: Path) -> FixtureRun:
    symbols = SymbolDatabase(database)
    try:

        def lookup(advisory: Advisory) -> Record | None:
            key = symbols.vulnerability_for(advisory.id)
            package = canonical_package_name(advisory.package)
            return symbols.record(key, package) if key else None

        def stored(advisory: Advisory) -> Callers | None:
            key = symbols.vulnerability_for(advisory.id)
            package = canonical_package_name(advisory.package)
            return symbols.callers_for(key, package) if key else None

        version = symbols.meta.get("db_version", "?")
        return run(fixtures, directory, lookup, f"database {version}", stored)
    finally:
        symbols.close()


def _confusion(outcomes: Iterable[Outcome]) -> list[str]:
    counts = Counter((o.calls, o.verdict) for o in outcomes)
    lines = [
        "| Program | " + " | ".join(f"`{v}`" for v in DISPLAY_ORDER) + " |",
        "|---|" + "---:|" * len(DISPLAY_ORDER),
    ]
    for calls, label in ((True, "calls the vulnerable code"), (False, "does not")):
        cells = []
        for verdict in DISPLAY_ORDER:
            n = counts[(calls, verdict)]
            bold = calls and verdict in SUPPRESSING and n
            cells.append(f"**{n}**" if bold else str(n))
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return lines


def render_markdown(fixtures: Fixtures, result: FixtureRun, labelled: FixtureRun | None) -> str:
    """One run, with the labelled run's verdicts alongside when ``result`` is a database."""
    outcomes = result.outcomes
    calling = sum(o.calls for o in outcomes)
    expected = sum(o.as_expected for o in outcomes)
    noisy = [o for o in outcomes if not o.calls and o.verdict == "CALLED"]
    suppressed = result.false_suppressions
    lines = [
        f"# Reachability fixtures: {result.data} symbol data",
        "",
        "Generated by `python -m patchsight.pipeline reachability-report`; do not edit by hand. "
        "Computed offline from `tests/fixtures/reachability`: the scanner reads each program, "
        "and the verdict comes from the same code `patchsight scan` runs.",
        "",
        f"- **{len(outcomes)} programs** for {len(fixtures.advisories)} advisories in "
        f"{len(fixtures.packages)} packages, each pinned to an affected version (checked "
        "against OSV by a live test)",
        f"- {calling} use the vulnerable code directly, {len(outcomes) - calling} do not",
    ]
    if result.data == "labelled":
        lines.append(
            "- Symbol data: the hand-written record for each advisory, at **high confidence**. "
            "This measures the scanner alone, as if every record were right and high."
        )
    else:
        tiers = Counter(o.confidence or "none" for o in outcomes)
        lines += [
            f"- Symbol data: the published {result.data}, as users get it, read by the scanner "
            "in this commit. Since [ADR 0008](../adr/0008-withhold-high-confidence.md) no "
            "record is high confidence, so `IMPORTED_NOT_CALLED` cannot occur.",
            f"- Programs whose advisory has a low-confidence record: {tiers['low']}; no record: "
            f"{tiers['none']}; high: {tiers['high']}",
        ]
    lines += [
        "",
        "## Result",
        "",
        f"- **False suppressions: {len(suppressed)}** (target 0). A false suppression is a "
        "program that uses the vulnerable code but gets `IMPORTED_NOT_CALLED` or "
        "`NOT_IMPORTED`.",
        (
            f"- Verdict as the rules intend: {expected} of {len(outcomes)}."
            if result.data == "labelled"
            else f"- Same verdict as with correct, high-confidence data: {expected} of "
            f"{len(outcomes)}."
            + (
                " The rest are `UNKNOWN` where a correct record would decide."
                if all(o.as_expected or o.verdict == "UNKNOWN" for o in outcomes)
                else ""
            )
        ),
        f"- `CALLED` for a program that does not use the vulnerable code: {len(noisy)}. "
        "Noise, which only raises an alert's priority.",
        "",
        *_confusion(outcomes),
        "",
    ]
    if suppressed:
        lines += ["### False suppressions", ""]
        lines += [f"- `{o.case}` ({o.form}): `{o.verdict}`, {o.reason}" for o in suppressed]
        lines.append("")
    if noisy:
        lines += ["### Noise", ""]
        lines += [f"- `{o.case}` ({o.form}): {o.reason}" for o in noisy]
        lines.append("")
    by_case = {o.case: o for o in labelled.outcomes} if labelled else {}
    header = "| Case | Package | Form | Calls | Expected | Verdict |"
    rule = "|---|---|---|---|---|---|"
    if labelled:
        header = header.replace("| Verdict |", "| Labelled data | This database |")
        rule += "---|"
    lines += ["## Every case", "", header, rule]
    for o in outcomes:
        mark = "" if o.as_expected else " ✗"
        mark = " **(false suppression)**" if o.false_suppression else mark
        cells = [f"`{o.case}`", o.package, o.form, "yes" if o.calls else "no", f"`{o.expected}`"]
        if labelled:
            cells.append(f"`{by_case[o.case].verdict}`")
        cells.append(f"`{o.verdict}`{mark}")
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)
