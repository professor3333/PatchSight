"""Render scan results for the terminal and as JSON."""

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from patchsight.scan.lockfiles import Dependency
from patchsight.scan.verdicts import DISPLAY_ORDER, Alert, order

STALE_AFTER = timedelta(days=7)
_HEADINGS = {
    "CALLED": "CALLED (fix first)",
    "IMPORTED_NOT_CALLED": "IMPORTED, NOT CALLED",
    "NOT_IMPORTED": "NOT IMPORTED (transitive only)",
    "UNKNOWN": "UNKNOWN (no symbol data, low confidence, or dynamic use)",
}
FOOTNOTE = (
    "'Not called' covers direct, statically resolvable use in your code only. Transitive "
    "use through other dependencies is not analysed, and no alert is hidden."
)


def stale_warning(db_meta: dict[str, str], now: datetime | None = None) -> str | None:
    built = db_meta.get("built_at")
    if not built:
        return "the database has no build date; it may be stale"
    age = (now or datetime.now(UTC)) - datetime.fromisoformat(built)
    if age > STALE_AFTER:
        return f"the database is {age.days} days old; download a newer one"
    return None


def render_text(
    alerts: Sequence[Alert],
    dependencies: Sequence[Dependency],
    lockfile: str,
    db_meta: dict[str, str],
    now: datetime | None = None,
) -> str:
    pinned = [d for d in dependencies if d.version]
    unpinned = [d for d in dependencies if not d.version]
    lines = [
        f"Lockfile: {lockfile} ({len(pinned)} pinned, {len(unpinned)} unpinned)   "
        f"Alerts: {len(alerts)} ({sum(1 + len(a.aliases) for a in alerts)} advisory IDs)   "
        f"DB: {db_meta.get('db_version', '?')} "
        f"({db_meta.get('builder', '?')})",
    ]
    if warning := stale_warning(db_meta, now):
        lines.append(f"Warning: {warning}")
    ordered = order(alerts)
    for verdict in DISPLAY_ORDER:
        group = [a for a in ordered if a.verdict == verdict]
        lines += ["", f"{_HEADINGS[verdict]}  {len(group)}"]
        for alert in group:
            also = f" (also {', '.join(alert.aliases)})" if alert.aliases else ""
            lines.append(f"  {alert.advisory}{also}  {alert.package} {alert.version}")
            lines.append(f"    {alert.reason}")
            if alert.matched:
                lines.append(f"    matched: {', '.join(alert.matched)}")
            if verdict != "CALLED" and alert.referenced:
                lines.append(f"    your code uses: {', '.join(alert.referenced[:8])}")
            if alert.evidence:
                shown = ", ".join(f"{e.path}:{e.line}" for e in alert.evidence[:5])
                more = f" (+{len(alert.evidence) - 5} more)" if len(alert.evidence) > 5 else ""
                lines.append(f"    at: {shown}{more}")
            if alert.confidence:
                lines.append(f"    symbol data: {alert.confidence} confidence")
    if unpinned:
        lines += ["", f"Not checked (no exact pin)  {len(unpinned)}"]
        lines += [f"  {d.raw_name}: {d.unpinned_reason} ({d.source}:{d.line})" for d in unpinned]
    lines += ["", FOOTNOTE]
    return "\n".join(lines)


def render_json(
    alerts: Sequence[Alert],
    dependencies: Sequence[Dependency],
    lockfile: str,
    db_meta: dict[str, str],
) -> str:
    return json.dumps(
        {
            "lockfile": lockfile,
            "database": db_meta,
            "alerts": [a.model_dump(mode="json") for a in order(alerts)],
            "unpinned": [d.model_dump(mode="json") for d in dependencies if not d.version],
            "note": FOOTNOTE,
        },
        indent=2,
    )


# The first line of every markdown report: the Action finds its own comment by it.
MARKDOWN_MARKER = "<!-- patchsight -->"
# GitHub refuses a comment over 65,536 characters; leave room for the closing lines.
MARKDOWN_LIMIT = 60_000
_MARKS = {"CALLED": "🔴", "IMPORTED_NOT_CALLED": "🟢", "NOT_IMPORTED": "⚪", "UNKNOWN": "🟡"}


def _cell(text: str) -> str:
    """Safe inside a markdown table cell: no pipe, no line break, no HTML."""
    return " ".join(text.split()).replace("|", "\\|").replace("<", "&lt;")


def _row(alert: Alert) -> str:
    also = f" ({', '.join(alert.aliases)})" if alert.aliases else ""
    where = ", ".join(f"`{_cell(e.path)}:{e.line}`" for e in alert.evidence[:3])
    if len(alert.evidence) > 3:
        where += f" +{len(alert.evidence) - 3}"
    if alert.verdict == "CALLED":
        detail = ", ".join(f"`{_cell(m)}`" for m in alert.matched[:4]) or "—"
    else:
        detail = _cell(alert.reason)
    return (
        f"| {_cell(alert.advisory + also)} | {_cell(alert.package)} {_cell(alert.version)} | "
        f"{detail} | {where or '—'} |"
    )


def render_markdown(
    alerts: Sequence[Alert],
    dependencies: Sequence[Dependency],
    lockfile: str,
    db_meta: dict[str, str],
    now: datetime | None = None,
    limit: int = MARKDOWN_LIMIT,
) -> str:
    """A report for a pull-request comment or a job summary. Every verdict is counted; if
    the list would pass ``limit`` characters, the least urgent rows are left out and the
    report says how many, so no alert disappears without a trace."""
    pinned = [d for d in dependencies if d.version]
    unpinned = [d for d in dependencies if not d.version]
    ordered = order(alerts)
    groups = {v: [a for a in ordered if a.verdict == v] for v in DISPLAY_ORDER}
    head = [
        MARKDOWN_MARKER,
        f"## PatchSight: {len(alerts)} dependency alert{'s' if len(alerts) != 1 else ''}",
        "",
        "| | Verdict | Alerts |",
        "|:---:|:---|---:|",
        *(f"| {_MARKS[v]} | {_HEADINGS[v]} | {len(groups[v])} |" for v in DISPLAY_ORDER),
        "",
        f"Lockfile `{_cell(lockfile)}` ({len(pinned)} pinned, {len(unpinned)} unpinned) · "
        f"symbol database {_cell(db_meta.get('db_version', '?'))}",
    ]
    if warning := stale_warning(db_meta, now):
        head += ["", f"> [!WARNING]\n> {warning}"]
    tail = ["", f"*{FOOTNOTE}*", ""]
    body: list[str] = []
    # Room for the head, the tail and the closing notes; rows fill what is left.
    used = sum(len(line) + 1 for line in head + tail) + 600
    left_out = 0
    for verdict in DISPLAY_ORDER:
        group = groups[verdict]
        if not group:
            continue
        title = f"{_MARKS[verdict]} {_HEADINGS[verdict]}: {len(group)}"
        opening = f"### {title}" if verdict == "CALLED" else f"<details><summary>{title}</summary>"
        second = "Matched" if verdict == "CALLED" else "Why"
        section = ["", opening, "", f"| Advisory | Package | {second} | Your code |",
                   "|---|---|---|---|"]  # fmt: skip
        used += sum(len(line) + 1 for line in section) + 20
        rows = 0
        for alert in group:
            row = _row(alert)
            if used + len(row) + 1 > limit:
                break
            section.append(row)
            used += len(row) + 1
            rows += 1
        if rows < len(group):
            section.append(f"| … | {len(group) - rows} more | | |")
            left_out += len(group) - rows
        if verdict != "CALLED":
            section += ["", "</details>"]
        body += section
    if unpinned:
        names = ", ".join(_cell(d.raw_name) for d in unpinned[:30])
        more = f" and {len(unpinned) - 30} more" if len(unpinned) > 30 else ""
        body += ["", f"Not checked, no exact pin: {names}{more}"]
    if left_out:
        note = (
            f"{left_out} alerts are counted above but not listed, to fit GitHub's comment "
            "limit. Every alert is in the SARIF report and in `patchsight scan`."
        )
        body += ["", note]
    return "\n".join(head + body + tail)
