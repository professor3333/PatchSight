"""One scan: lockfile, then OSV, then the database, then the code. No LLM and no server."""

from pathlib import Path

import httpx

from patchsight.db import SymbolDatabase
from patchsight.scan import lockfiles, osv_client
from patchsight.scan.ast_scanner import scan
from patchsight.scan.verdicts import Alert, decide


def run_scan(
    code: Path,
    lockfile: Path,
    database: Path,
    client: httpx.Client | None = None,
) -> tuple[list[Alert], list[lockfiles.Dependency], dict[str, str]]:
    dependencies = lockfiles.parse(lockfile)
    pinned = [(d.name, d.version) for d in dependencies if d.version]
    matches = osv_client.query([(n, v) for n, v in pinned if v], client=client)
    usage = scan(code)
    symbols = SymbolDatabase(database)
    try:
        alerts: list[Alert] = []
        for (package, version), advisory_ids in sorted(matches.items()):
            # OSV returns every ID of a vulnerability (GHSA, PYSEC, ...): one alert per
            # vulnerability. IDs the database does not know stay separate.
            groups: dict[str, list[str]] = {}
            for advisory in advisory_ids:
                groups.setdefault(symbols.vulnerability_for(advisory) or advisory, []).append(
                    advisory
                )
            for key, ids in sorted(groups.items()):
                ordered = sorted(ids, key=lambda i: (not i.startswith("GHSA-"), i))
                known = symbols.vulnerability_for(ids[0]) is not None
                record = symbols.record(key, package) if known else None
                alert = decide(ordered[0], package, version, record, usage)
                alerts.append(alert.model_copy(update={"aliases": tuple(ordered[1:])}))
        return alerts, dependencies, symbols.meta
    finally:
        symbols.close()
