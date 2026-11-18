"""``patchsight explain``: why the database lists the symbols it does for an advisory.

Read-only and local, like the scan: no model and no network. It shows each record's
confidence and the reason for it, which models and prompt produced it, the symbols the
model flagged with their one-sentence rationale and the changed lines they cite, and links
to the fix commits. Line ranges and commit links stand in for code, which the database
never holds.
"""

import json

from patchsight.db import HunkLocation, Record, SymbolDatabase
from patchsight.scan.verdicts import no_data_reason

LOW_NOTE = "A low-confidence record can mark an alert CALLED, but never IMPORTED, NOT CALLED."


def normalise_identifier(identifier: str) -> str:
    """Canonical OSV spelling: ``GHSA-`` with a lower-case suffix; CVE and PYSEC upper case."""
    text = identifier.strip()
    if text.lower().startswith("ghsa-"):
        return "GHSA-" + text[5:].lower()
    return text.upper()


def lookup(database: SymbolDatabase, identifier: str) -> tuple[str, list[str], list[Record]]:
    """(vulnerability, its identifiers, its records); records are empty when unknown."""
    canonical = normalise_identifier(identifier)
    vulnerability = database.vulnerability_for(canonical)
    if vulnerability is None:
        return canonical, [], []
    return (
        vulnerability,
        database.identifiers_for(vulnerability),
        database.records_for(vulnerability),
    )


def _lines(hunk: HunkLocation) -> str:
    if hunk.old_count:
        end = hunk.old_start + hunk.old_count - 1
        return f"lines {hunk.old_start}-{end} before the fix"
    end = hunk.new_start + max(hunk.new_count, 1) - 1
    return f"lines {hunk.new_start}-{end} after the fix (added)"


def _commit_url(record: Record, sha: str) -> str:
    repo = next((c.repo for c in record.fix_commits if c.sha == sha), None)
    return f"https://github.com/{repo}/commit/{sha}" if repo else sha


def _record_text(record: Record) -> list[str]:
    reason = record.tier_reason or (
        "fallback: every changed definition" if record.source == "fallback" else record.source
    )
    lines = [f"{record.package}: {record.confidence.upper()} confidence ({reason})"]
    if record.model:
        second = (
            f", second opinion {record.second_opinion_model}" if record.second_opinion_model else ""
        )
        lines.append(f"  extracted by {record.model}{second}; prompt {record.prompt_version}")
    if record.truncated:
        lines.append("  the prompt was truncated to the token budget")
    if record.confidence == "low":
        lines.append(f"  {LOW_NOTE}")
    flagged = {e.qualified_name: e for e in record.evidence}
    if flagged:
        title = "vulnerable symbols" if record.confidence == "high" else "the model flagged"
        lines.append(f"  {title} ({len(flagged)}):")
        for name, item in sorted(flagged.items()):
            lines.append(f"    {name}")
            lines.append(f"      why: {item.rationale}")
            for hunk in item.hunks:
                link = _commit_url(record, hunk.commit)
                lines.append(f"      changed: {hunk.path}, {_lines(hunk)} ({link})")
    others = sorted(s.qualified_name for s in record.symbols if s.qualified_name not in flagged)
    if others:
        label = "symbols" if not flagged else "other changed definitions"
        lines.append(f"  {label} ({len(others)}): {', '.join(others)}")
    if record.entry_points:
        lines.append(f"  entry points: {', '.join(record.entry_points)}")
    lines.append("  fix commits:")
    lines.extend(f"    https://github.com/{c.repo}/commit/{c.sha}" for c in record.fix_commits)
    return lines


def render_text(
    identifier: str, vulnerability: str, identifiers: list[str], records: list[Record],
    meta: dict[str, str], status: str | None = None,
) -> str:  # fmt: skip
    db = f"database {meta.get('db_version', '?')} ({meta.get('builder', '?')})"
    if not records:
        why = no_data_reason(identifier, status).removeprefix("no symbol data")
        why = why.removeprefix(" for this advisory").removeprefix(": ")
        also = [i for i in identifiers if i != identifier]
        return (
            f"{identifier}: no symbol data in {db}"
            + (f" (also {', '.join(also)})" if also else "")
            + "."
            + (f" Why: {why}." if why else "")
            + " A scan reports its alerts as UNKNOWN; missing data is not evidence of safety."
        )
    also = [i for i in identifiers if i != vulnerability]
    header = f"{vulnerability}" + (f" (also {', '.join(also)})" if also else "")
    lines = [header, db]
    for record in records:
        lines += ["", *_record_text(record)]
    return "\n".join(lines)


def render_json(
    identifier: str, vulnerability: str, identifiers: list[str], records: list[Record],
    meta: dict[str, str], status: str | None = None,
) -> str:  # fmt: skip
    payload = {
        "identifier": identifier,
        "vulnerability": vulnerability if records else None,
        "identifiers": identifiers,
        "build_status": status,
        "database": {k: meta.get(k) for k in ("db_version", "builder", "schema_version")},
        "records": [r.model_dump(mode="json") for r in records],
    }
    return json.dumps(payload, indent=2)
