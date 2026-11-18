"""The release gate: checks a candidate database must pass before it is published.

Every check is deterministic and reads only the candidate and the previous release, so the
gate gives the same answer from the same inputs. A failure stops publishing; the nightly
workflow then opens an issue with this report instead.

* ``ledger``: the builds ledger exists and covers every vulnerability with a record, so the
  next incremental update can run.
* ``symbols``: every record names at least one symbol and no more than ``MAX_SYMBOLS``.
* ``aliases``: every vulnerability with a record is found by its own ID, and every alias
  points at a vulnerability with a record.
* ``no_mass_loss``: few vulnerabilities lose their records at once (at most
  ``MAX_LOST_SHARE`` of the previous ones, or ``MIN_LOST_ALLOWED``, whichever is larger).
  A bigger drop means a broken snapshot or builder, not real withdrawals.
* ``high_kept``: a high-confidence record whose extraction inputs did not change stays high.
* ``high_withheld``: no record is high confidence while ADR 0008 withholds the tier, however
  the database was built.
"""

from pydantic import BaseModel, ConfigDict

from patchsight.db import SymbolDatabase
from patchsight.pipeline.build_db import MAX_SYMBOLS
from patchsight.pipeline.llm_records import PUBLISH_HIGH

MAX_LOST_SHARE = 0.02
MIN_LOST_ALLOWED = 10
EXAMPLES = 10


class Check(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    passed: bool
    detail: str


class GateReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidate_version: str
    previous_version: str
    passed: bool
    checks: tuple[Check, ...]


def _sample(items: list[str]) -> str:
    shown = ", ".join(items[:EXAMPLES])
    return shown + (f" and {len(items) - EXAMPLES} more" if len(items) > EXAMPLES else "")


def run(candidate: SymbolDatabase, previous: SymbolDatabase) -> GateReport:
    checks: list[Check] = []
    ledger = candidate.build_ledger()
    vulnerabilities = candidate.vulnerabilities()
    records = {v: candidate.records_for(v) for v in vulnerabilities}

    unledgered = [v for v in vulnerabilities if v not in ledger]
    checks.append(
        Check(
            name="ledger",
            passed=bool(ledger) and not unledgered,
            detail=f"{len(ledger)} entries"
            + (f"; records without an entry: {_sample(unledgered)}" if unledgered else "")
            + ("" if ledger else "; no ledger"),
        )
    )

    bad = [
        f"{r.vulnerability}/{r.package} ({len(r.symbols)})"
        for rs in records.values()
        for r in rs
        if not 1 <= len(r.symbols) <= MAX_SYMBOLS
    ]
    checks.append(
        Check(
            name="symbols",
            passed=not bad,
            detail=f"{sum(len(rs) for rs in records.values())} records"
            + (f"; outside 1 to {MAX_SYMBOLS} symbols: {_sample(bad)}" if bad else ""),
        )
    )

    aliases = candidate.alias_map()
    unreachable = [v for v in vulnerabilities if aliases.get(v) != v]
    dangling = sorted(i for i, v in aliases.items() if v not in records)
    checks.append(
        Check(
            name="aliases",
            passed=not unreachable and not dangling,
            detail=f"{len(aliases)} identifiers"
            + (
                f"; vulnerabilities not found by their ID: {_sample(unreachable)}"
                if unreachable
                else ""
            )
            + (f"; aliases without a record: {_sample(dangling)}" if dangling else ""),
        )
    )

    before = previous.vulnerabilities()
    lost = [v for v in before if v not in records]
    allowed = max(MIN_LOST_ALLOWED, int(MAX_LOST_SHARE * len(before)))
    checks.append(
        Check(
            name="no_mass_loss",
            passed=len(lost) <= allowed,
            detail=f"{len(lost)} of {len(before)} vulnerabilities lost their records "
            f"(at most {allowed} allowed)" + (f": {_sample(lost)}" if lost else ""),
        )
    )

    old_ledger = previous.build_ledger()
    demoted = [
        f"{r.vulnerability}/{r.package}"
        for v in before
        if v in records and v in old_ledger and v in ledger
        and old_ledger[v].input_hash == ledger[v].input_hash
        for r in previous.records_for(v)
        if r.confidence == "high"
        and not any(c.package == r.package and c.confidence == "high" for c in records[v])
    ]  # fmt: skip
    checks.append(
        Check(
            name="high_kept",
            passed=not demoted,
            detail="unchanged high-confidence records stay high"
            + (f"; demoted: {_sample(demoted)}" if demoted else ""),
        )
    )

    high = [f"{r.vulnerability}/{r.package}" for rs in records.values() for r in rs
            if r.confidence == "high"]  # fmt: skip
    checks.append(
        Check(
            name="high_withheld",
            passed=PUBLISH_HIGH or not high,
            detail=f"{len(high)} high-confidence records"
            + (
                ""
                if PUBLISH_HIGH
                else " (ADR 0008 withholds the tier)"
                if not high
                else f" while ADR 0008 withholds the tier: {_sample(high)}"
            ),
        )
    )
    return GateReport(
        candidate_version=candidate.meta.get("db_version", "?"),
        previous_version=previous.meta.get("db_version", "?"),
        passed=all(c.passed for c in checks),
        checks=tuple(checks),
    )


def render_markdown(report: GateReport) -> str:
    verdict = "PASSED" if report.passed else "FAILED"
    lines = [
        f"# Release gate {verdict}: database {report.candidate_version}",
        "",
        f"Candidate `{report.candidate_version}` against the previous release "
        f"`{report.previous_version}`. Checks are described in `src/patchsight/pipeline/gate.py`.",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
        *(
            f"| `{c.name}` | {'pass' if c.passed else '**FAIL**'} | {c.detail} |"
            for c in report.checks
        ),
        "",
    ]
    return "\n".join(lines)
