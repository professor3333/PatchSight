"""Decide one verdict per alert. Uncertainty always lands on UNKNOWN, never on "not called".

Rules, in order:

1. No record in the database: UNKNOWN.
2. A reference in user code matches a vulnerable symbol or entry point: CALLED. This holds
   at any confidence; low-confidence data may raise an alert's priority.
3. The package is never imported: NOT_IMPORTED (transitive use is not analysed), unless an
   unparsable file mentions it or a dynamic import has a computed name: UNKNOWN.
4. Dynamic use of the package (``getattr`` with a computed name, ``importlib``, a module
   used as a value, a star import): UNKNOWN.
5. Low-confidence symbol data, no symbols, or an unparsable file that mentions the
   package: UNKNOWN. Low confidence can never lower an alert.
6. Otherwise: IMPORTED_NOT_CALLED, a claim about statically resolvable use only.

A reference matches a symbol when it is the same name; when it names the class or module
that directly contains the symbol; when it reaches into the symbol (``yaml.Loader.x`` for
``yaml.Loader``); or when it has the same top-level package and the same final name, which
catches re-exports such as ``pkg.load`` for ``pkg.loader.load``. False matches only raise
priority.
"""

import re
from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.db import Record
from patchsight.names import import_names
from patchsight.scan.ast_scanner import Location, Usage

Verdict = Literal["CALLED", "IMPORTED_NOT_CALLED", "NOT_IMPORTED", "UNKNOWN"]
DISPLAY_ORDER: tuple[Verdict, ...] = ("CALLED", "IMPORTED_NOT_CALLED", "NOT_IMPORTED", "UNKNOWN")


class Alert(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisory: str
    aliases: tuple[str, ...] = ()
    package: str
    version: str
    verdict: Verdict
    reason: str
    evidence: tuple[Location, ...] = ()
    matched: tuple[str, ...] = ()
    referenced: tuple[str, ...] = ()
    confidence: str | None = None
    vulnerable: tuple[str, ...] = ()


def matches(reference: str, symbol: str) -> bool:
    r, s = reference.split("."), symbol.split(".")
    if r == s:
        return True
    if len(r) >= 2 and len(s) == len(r) + 1 and s[: len(r)] == r:
        return True  # the containing class or module of a vulnerable member
    if len(r) > len(s) and r[: len(s)] == s:
        return True  # reaching into a vulnerable class
    return len(r) >= 2 and r[0] == s[0] and r[-1] == s[-1]  # re-exported name


def _mentions(sources: dict[str, str], roots: set[str]) -> list[str]:
    return sorted(
        path
        for path, text in sources.items()
        if any(re.search(rf"\b{re.escape(root)}\b", text) for root in roots)
    )


def decide(advisory: str, package: str, version: str, record: Record | None, usage: Usage) -> Alert:
    base = {"advisory": advisory, "package": package, "version": version}
    if record is None:
        return Alert(**base, verdict="UNKNOWN", reason="no symbol data for this advisory")

    names = import_names(package, record.import_roots)
    roots = {n.split(".")[0] for n in names}
    targets = [s.qualified_name for s in record.symbols if s.module] + list(record.entry_points)
    bare = [s.name.split(".")[-1] for s in record.symbols if not s.module]
    context = {"confidence": record.confidence, "vulnerable": tuple(sorted(set(targets + bare)))}

    into_package = [r for r in usage.references if r.name.split(".")[0] in roots]
    hits = [
        r
        for r in into_package
        if any(matches(r.name, t) for t in targets) or r.name.split(".")[-1] in bare
    ]
    if hits:
        return Alert(
            **base,
            **context,
            verdict="CALLED",
            reason="your code references a vulnerable symbol",
            evidence=tuple(
                sorted({h.location for h in hits}, key=lambda loc: (loc.path, loc.line))
            ),
            matched=tuple(sorted({h.name for h in hits})),
        )

    unparsable = _mentions(usage.unparsable, roots)
    computed = [d for d in usage.dynamic if d.root == "?"]
    imported = usage.imported(names)
    if not imported:
        if unparsable:
            return Alert(
                **base,
                **context,
                verdict="UNKNOWN",
                reason=f"could not parse {', '.join(unparsable)}, which mention {package}",
            )
        if computed:
            return Alert(
                **base,
                **context,
                verdict="UNKNOWN",
                reason="a dynamic import with a computed name could load it",
                evidence=tuple(d.location for d in computed),
            )
        return Alert(
            **base,
            **context,
            verdict="NOT_IMPORTED",
            reason=f"your code never imports {' or '.join(names)}; transitive use is not analysed",
        )

    referenced = tuple(sorted({r.name for r in into_package}))
    dynamic = [d for d in usage.dynamic if d.root in roots] + computed
    if dynamic:
        first = dynamic[0]
        return Alert(
            **base,
            **context,
            verdict="UNKNOWN",
            reason=f"dynamic use the scanner cannot follow: {first.reason}",
            evidence=tuple(d.location for d in dynamic),
            referenced=referenced,
        )
    if record.confidence == "low":
        return Alert(
            **base,
            **context,
            verdict="UNKNOWN",
            reason="symbol data is low confidence, so 'not called' cannot be claimed",
            evidence=tuple(imported),
            referenced=referenced,
        )
    if not targets and not bare:
        return Alert(
            **base,
            **context,
            verdict="UNKNOWN",
            reason="the record lists no symbols",
            evidence=tuple(imported),
            referenced=referenced,
        )
    if unparsable:
        return Alert(
            **base,
            **context,
            verdict="UNKNOWN",
            reason=f"could not parse {', '.join(unparsable)}, which mention {package}",
            evidence=tuple(imported),
            referenced=referenced,
        )
    return Alert(
        **base,
        **context,
        verdict="IMPORTED_NOT_CALLED",
        reason="imported, but no vulnerable symbol is referenced (static, direct use only)",
        evidence=tuple(imported),
        referenced=referenced,
    )


def order(alerts: Sequence[Alert]) -> list[Alert]:
    rank = {v: i for i, v in enumerate(DISPLAY_ORDER)}
    return sorted(alerts, key=lambda a: (rank[a.verdict], a.package, a.advisory))
