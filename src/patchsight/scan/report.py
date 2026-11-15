"""Render scan results for the terminal and as JSON."""

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from patchsight.scan.lockfiles.requirements import Dependency
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
