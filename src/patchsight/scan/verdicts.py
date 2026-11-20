"""Decide one verdict per alert. Uncertainty always lands on UNKNOWN, never on "not called".

Rules, in order:

1. No record in the database: UNKNOWN.
2. A reference in user code matches a vulnerable symbol or entry point: CALLED. This holds
   at any confidence; low-confidence data may raise an alert's priority.
3. The package is never imported: NOT_IMPORTED (transitive use is not analysed), unless an
   unparsable file mentions it, a file that starts processes names it (``exec gunicorn
   app.wsgi`` in a start script runs gunicorn's code without an import), a dynamic import
   has a computed name, or the package's import name is not known (the record has no
   import roots and the package is not a known exception): UNKNOWN.
4. Dynamic use of the package (``getattr`` with a computed name, ``importlib``, a module
   used as a value, a star import), or a file that starts processes names it: UNKNOWN.
5. Low-confidence symbol data, no symbols, or an unparsable file that mentions the
   package: UNKNOWN. Low confidence can never lower an alert.
6. A vulnerable symbol's name is used where the scanner cannot tell what it belongs to:
   an attribute of an untyped object (``key.write_private_key_file()``), a name reached
   through the project's own modules, or a name inside a template tag
   (``{{ text|urlize }}``): UNKNOWN.
7. Otherwise: IMPORTED_NOT_CALLED, a claim about statically resolvable use only.

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
from patchsight.names import KNOWN_IMPORT_NAMES, canonical_package_name, import_names
from patchsight.scan.ast_scanner import Location, Usage

Verdict = Literal["CALLED", "IMPORTED_NOT_CALLED", "NOT_IMPORTED", "UNKNOWN"]

# Why a vulnerability has no record, by the builder's ledger status.
NO_DATA = {
    "no_python_fix": "the fix changes no Python code",
    "module_level_only": "the fix changes only module-level code, so no function can be named",
    "no_github_fix": "the advisory links no fix commit on GitHub",
    "no_resolvable_commit": "the fix commit could not be found",
    "too_broad": "the fix changes too many definitions to single any out",
    "error": "building the record failed",
    "built": "the record covers another affected package",
}


def no_data_reason(advisory: str, status: str | None) -> str:
    """Why an alert has no symbol data. Every reason starts "no symbol data"."""
    if advisory.startswith("MAL-"):
        return "no symbol data: a malicious-package report, so the whole package is the problem"
    if status is None:
        return "no symbol data for this advisory"
    return f"no symbol data: {NO_DATA.get(status, status.replace('_', ' '))}"


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


def decide(
    advisory: str,
    package: str,
    version: str,
    record: Record | None,
    usage: Usage,
    status: str | None = None,
) -> Alert:
    """``status``: the vulnerability's ledger status, which says why ``record`` is missing."""
    base = {"advisory": advisory, "package": package, "version": version}
    if record is None:
        return Alert(**base, verdict="UNKNOWN", reason=no_data_reason(advisory, status))

    names = import_names(package, record.import_roots)
    roots = {n.split(".")[0] for n in names}
    targets = [s.qualified_name for s in record.symbols if s.module] + list(record.entry_points)
    bare = [s.name.split(".")[-1] for s in record.symbols if not s.module]
    context = {"confidence": record.confidence, "vulnerable": tuple(sorted(set(targets + bare)))}

    into_package = usage.references_into(roots)
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
    launched = usage.launched_as(names, package)
    imported = usage.imported(names)
    if not imported:
        if unparsable:
            return Alert(
                **base,
                **context,
                verdict="UNKNOWN",
                reason=f"could not parse {', '.join(unparsable)}, which "
                f"{'mentions' if len(unparsable) == 1 else 'mention'} {package}",
            )
        if launched:
            return Alert(
                **base,
                **context,
                verdict="UNKNOWN",
                reason=f"your project may run {package} as a command ({launched[1].path} "
                f"names {launched[0]}); its code then runs without an import",
                evidence=(launched[1],),
            )
        if computed:
            return Alert(
                **base,
                **context,
                verdict="UNKNOWN",
                reason="a dynamic import with a computed name could load it",
                evidence=tuple(d.location for d in computed),
            )
        if not record.import_roots and canonical_package_name(package) not in KNOWN_IMPORT_NAMES:
            return Alert(
                **base,
                **context,
                verdict="UNKNOWN",
                reason=f"the import name of {package} is not known; your code never imports "
                f"{' or '.join(names)}, but it may import the package under another name",
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
    if launched:
        return Alert(
            **base,
            **context,
            verdict="UNKNOWN",
            reason=f"your project may run {package} as a command ({launched[1].path} "
            f"names {launched[0]}); that runs its code without a reference",
            evidence=(launched[1], *imported),
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
            reason=f"could not parse {', '.join(unparsable)}, which "
            f"{'mentions' if len(unparsable) == 1 else 'mention'} {package}",
            evidence=tuple(imported),
            referenced=referenced,
        )
    leaves = sorted({t.split(".")[-1] for t in targets} | set(bare))
    leaves = [n for n in leaves if not (n.startswith("__") and n.endswith("__"))]
    untyped = [n for n in leaves if n in usage.attributes]
    if untyped:
        return Alert(
            **base,
            **context,
            verdict="UNKNOWN",
            reason=f"your code uses .{untyped[0]} on an object the scanner cannot type; it "
            "may be the vulnerable symbol",
            evidence=tuple(usage.attributes[n] for n in untyped),
            referenced=referenced,
        )
    templated = [n for n in leaves if n in usage.template_names]
    if templated:
        return Alert(
            **base,
            **context,
            verdict="UNKNOWN",
            reason=f"a template uses {templated[0]}, the name of a vulnerable symbol; "
            "template calls cannot be followed",
            evidence=tuple(usage.template_names[n] for n in templated),
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
