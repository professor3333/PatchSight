"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF readers. No LLM.

Every alert becomes one result, so nothing is hidden. The level ranks it:

* CALLED: ``error``, located at the first reference in your code;
* UNKNOWN: ``warning``, located at the dependency's line in the lockfile;
* IMPORTED_NOT_CALLED and NOT_IMPORTED: ``note``, also at the lockfile line.

Each vulnerability is one rule, identified by the alert's advisory ID. A partial fingerprint
over the advisory and the package keeps an alert's identity when line numbers or the pinned
version change, so code scanning tracks it across scans.
"""

import hashlib
import json
import posixpath
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from patchsight import __version__
from patchsight.scan.lockfiles import Dependency
from patchsight.scan.report import FOOTNOTE, stale_warning
from patchsight.scan.verdicts import Alert, Verdict, order

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/professor3333/PatchSight"
LEVELS: dict[Verdict, str] = {
    "CALLED": "error",
    "UNKNOWN": "warning",
    "IMPORTED_NOT_CALLED": "note",
    "NOT_IMPORTED": "note",
}
LABELS: dict[Verdict, str] = {
    "CALLED": "Called",
    "UNKNOWN": "Unknown",
    "IMPORTED_NOT_CALLED": "Imported, not called",
    "NOT_IMPORTED": "Not imported",
}
FINGERPRINT = "patchsight/v1"
MAX_RELATED = 20


def uri(path: str, base: str = "") -> str:
    """A result path as a SARIF URI: relative paths stay relative, joined under ``base``."""
    joined = posixpath.normpath(posixpath.join(base, path)) if base else posixpath.normpath(path)
    pure = PurePosixPath(joined)
    return Path(joined).as_uri() if pure.is_absolute() else joined


def _location(path: str, line: int, base: str = "", message: str | None = None) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri(path, base)},
            "region": {"startLine": max(1, line)},
        }
    }
    if message:
        location["message"] = {"text": message}
    return location


def _message(alert: Alert) -> str:
    also = f" (also {', '.join(alert.aliases)})" if alert.aliases else ""
    text = (
        f"{LABELS[alert.verdict]}: {alert.package} {alert.version} is affected by "
        f"{alert.advisory}{also}. {alert.reason}"
    )
    if alert.matched:
        text += f" Matched: {', '.join(alert.matched)}."
    if alert.confidence:
        text += f" Symbol data: {alert.confidence} confidence."
    return text


def render_sarif(
    alerts: Sequence[Alert],
    dependencies: Sequence[Dependency],
    lockfile: str,
    db_meta: Mapping[str, str],
    code_base: str = "",
) -> str:
    """One SARIF run. ``code_base`` is the scanned directory, which code paths are relative to."""
    ordered = order(alerts)
    pins = {(d.name, d.version): d for d in dependencies if d.version}
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for alert in ordered:
        if alert.advisory not in index:
            index[alert.advisory] = len(rules)
            rules.append(
                {
                    "id": alert.advisory,
                    "shortDescription": {"text": f"Vulnerable dependency: {alert.advisory}"},
                    "helpUri": f"https://osv.dev/vulnerability/{alert.advisory}",
                    "help": {
                        "text": f"{alert.advisory} affects {alert.package}. Upgrade to a fixed "
                        "version, or check whether your code reaches the vulnerable code."
                    },
                    "properties": {"tags": ["security", "dependency"]},
                }
            )
        dependency = pins.get((alert.package, alert.version))
        manifest = _location(
            dependency.source if dependency else lockfile,
            dependency.line if dependency else 1,
            message=f"{alert.package}=={alert.version}",
        )
        if alert.verdict == "CALLED" and alert.evidence:
            first, *rest = alert.evidence
            primary = _location(first.path, first.line, code_base)
            related = [
                _location(e.path, e.line, code_base, "another reference")
                for e in rest[: MAX_RELATED - 1]
            ] + [manifest]
        else:
            primary, related = manifest, []
        result: dict[str, Any] = {
            "ruleId": alert.advisory,
            "ruleIndex": index[alert.advisory],
            "level": LEVELS[alert.verdict],
            "message": {"text": _message(alert)},
            "locations": [primary],
            "partialFingerprints": {
                FINGERPRINT: hashlib.sha256(
                    f"{alert.advisory}|{alert.package}".encode()
                ).hexdigest()[:32]
            },
            "properties": {
                "verdict": alert.verdict,
                "package": alert.package,
                "version": alert.version,
                "aliases": list(alert.aliases),
                "matched": list(alert.matched),
                "confidence": alert.confidence,
            },
        }
        if related:
            for number, location in enumerate(related, 1):
                location["id"] = number
            result["relatedLocations"] = related
        results.append(result)
    notifications = [
        {"level": "warning", "message": {"text": warning}}
        for warning in [stale_warning(dict(db_meta))]
        if warning
    ]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "PatchSight",
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
        "results": results,
        "properties": {
            "database": {
                k: db_meta[k] for k in ("db_version", "builder", "built_at") if k in db_meta
            },
            "unpinned": [
                {
                    "name": d.raw_name,
                    "reason": d.unpinned_reason,
                    "source": d.source,
                    "line": d.line,
                }
                for d in dependencies
                if not d.version
            ],
            "note": FOOTNOTE,
        },
    }
    return json.dumps({"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2)
