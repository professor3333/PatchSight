"""Decide one verdict per alert. Uncertainty always lands on UNKNOWN, never on "not called".

Rules, in order:

1. No record in the database: UNKNOWN.
2. A reference in user code matches a vulnerable symbol or entry point: CALLED. This holds
   at any confidence; low-confidence data may raise an alert's priority. Where the
   database stores the package's names and definitions for the record (ADR 0018), the
   reference is first rewritten through the names, and the re-export rule below does not
   match a name the package defines as another definition.
2a. Otherwise, a reference matches one of the record's stored callers, a definition of the
   package that reaches a symbol through calls in the source of a release the record
   affects, or matches a symbol under a name the package binds to it: CALLED, with the
   call path as evidence (ADR 0017). The reference is first rewritten through the names
   the package binds (``requests.get`` is ``requests.api.get``), then matched without the
   re-export rule, which those names make unnecessary. Callers count only while they were
   computed for the record's current symbols.
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
catches re-exports such as ``pkg.load`` for ``pkg.loader.load``. When that final name is a
dunder such as ``__init__``, the class before it must agree too, since every class has one
(ADR 0015). False matches only raise priority. That last rule is a guess at a re-export; where
the database stores the package's definitions, it is not applied to a reference that names
another of them.
"""

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.db import Callers, Record, symbols_digest
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
    # CALLED through a stored caller: the definition matched, then each next one on a
    # static call path, ending at a vulnerable symbol.
    path: tuple[str, ...] = ()


def matches(reference: str, symbol: str, reexports: bool = True) -> bool:
    r, s = reference.split("."), symbol.split(".")
    if r == s:
        return True
    if len(r) >= 2 and len(s) == len(r) + 1 and s[: len(r)] == r:
        return True  # the containing class or module of a vulnerable member
    if len(r) > len(s) and r[: len(s)] == s:
        return True  # reaching into a vulnerable class
    if not reexports or len(r) < 2 or r[0] != s[0] or r[-1] != s[-1]:
        return False
    # A re-exported name. A dunder alone says nothing about which code is reached:
    # django.test.TestCase.__init__ is not HttpResponseRedirectBase.__init__ (ADR 0015).
    return not _is_dunder(r[-1]) or (len(r) >= 3 and len(s) >= 3 and r[-2] == s[-2])


def guessed_reexport(reference: str, symbol: str) -> bool:
    """Whether the two match only by the re-export rule: a guess, which a package that
    defines ``reference`` as a different definition proves wrong."""
    return matches(reference, symbol) and not matches(reference, symbol, reexports=False)


def _is_dunder(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def targets(record: Record) -> tuple[list[str], list[str]]:
    """The names a reference is matched against: qualified symbols and entry points, and the
    bare names of symbols whose module is unknown (matched on their last part)."""
    qualified = [s.qualified_name for s in record.symbols if s.module] + list(record.entry_points)
    bare = [s.name.split(".")[-1] for s in record.symbols if not s.module]
    return qualified, bare


def hit(reference: str, qualified: Sequence[str], bare: Sequence[str]) -> bool:
    return any(matches(reference, t) for t in qualified) or reference.split(".")[-1] in bare


class NameIndex:
    """Matches references against many names at once, exactly as ``matches`` would one by
    one, and says which name matched: a record can have hundreds of callers, and a project
    hundreds of references into one package."""

    def __init__(self, names: Iterable[str], reexports: bool = True) -> None:
        self.names = set(names)
        self.reexports = reexports
        self._members: dict[str, list[str]] = defaultdict(list)
        self._same_end: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._same_class_end: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        for name in sorted(self.names):
            s = name.split(".")
            self._same_end[(s[0], s[-1])].append(name)
            if len(s) >= 3:
                self._members[".".join(s[:-1])].append(name)
                self._same_class_end[(s[0], s[-2], s[-1])].append(name)

    def match(self, reference: str) -> str | None:
        found = self.closest(reference)
        return found[1] if found else None

    def closest(self, reference: str) -> tuple[int, str] | None:
        """The closest name the reference matches, with how close: 0 itself, 1 a member of
        it, 2 a name it reaches into (the longest), 3 a re-export, which is the only one a
        mere collision of names can give; the first in sorted order on a tie."""
        if reference in self.names:
            return 0, reference
        r = reference.split(".")
        if len(r) >= 2 and (members := self._members.get(reference)):
            return 1, members[0]
        for k in range(len(r) - 1, 0, -1):
            if (prefix := ".".join(r[:k])) in self.names:
                return 2, prefix
        if not self.reexports or len(r) < 2:
            return None
        if _is_dunder(r[-1]):
            found = self._same_class_end.get((r[0], r[-2], r[-1])) if len(r) >= 3 else None
        else:
            found = self._same_end.get((r[0], r[-1]))
        return (3, found[0]) if found else None


@dataclass(frozen=True)
class Reach:
    """A record's stored callers, ready to match references against."""

    toward: dict[str, str]  # each caller -> the next definition towards a symbol
    names: dict[str, tuple[str, ...]]  # a name the package binds -> what it names
    targets: frozenset[str]  # the callers and the record's symbols
    version: str | None  # the release they were read from
    # The package's definitions that the re-export rule would match to an entry point but
    # that are other definitions (PIL.Image.open for PIL.GdImageFile.open).
    collisions: frozenset[str] = frozenset()

    def canonical(self, reference: str) -> list[str]:
        """The reference as the package's definitions name it: its longest prefix that is a
        name the package binds, replaced by each definition it names. ``urllib3.PoolManager
        .urlopen`` becomes ``urllib3.poolmanager.PoolManager.urlopen``."""
        parts = reference.split(".")
        for k in range(len(parts), 1, -1):
            if found := self.names.get(".".join(parts[:k])):
                return [".".join((target, *parts[k:])) for target in found]
        return [reference]


def reaching(record: Record, callers: Callers | None) -> Reach | None:
    """The record's stored callers; none when they could not be computed, or were computed
    for other symbols."""
    if callers is None or callers.status != "ok":
        return None
    if callers.symbols_digest != symbols_digest(record):
        return None
    names: dict[str, list[str]] = defaultdict(list)
    for name, target in callers.names:
        names[name].append(target)
    symbols = {s.qualified_name for s in record.symbols if s.module}
    toward = dict(callers.callers)
    return Reach(
        toward,
        {n: tuple(t) for n, t in names.items()},
        frozenset({*toward, *symbols}),
        callers.version,
        frozenset(callers.collisions),
    )


def call_path(caller: str, toward: Mapping[str, str]) -> tuple[str, ...]:
    """From a caller to a vulnerable symbol, following each next definition."""
    path = [caller]
    while (step := toward.get(path[-1])) is not None and step not in path:
        path.append(step)
    if path[-1] in toward:  # a cycle: a malformed table, shown as far as it goes
        path.append(toward[path[-1]])
    return tuple(path)


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
    callers: Callers | None = None,
) -> Alert:
    """``status``: the vulnerability's ledger status, which says why ``record`` is missing.
    ``callers``: the record's stored callers, if the database has them."""
    base = {"advisory": advisory, "package": package, "version": version}
    if record is None:
        return Alert(**base, verdict="UNKNOWN", reason=no_data_reason(advisory, status))

    names = import_names(package, record.import_roots)
    roots = {n.split(".")[0] for n in names}
    qualified, bare = targets(record)
    context = {"confidence": record.confidence, "vulnerable": tuple(sorted(set(qualified + bare)))}

    into_package = usage.references_into(roots)
    reach = reaching(record, callers)
    if reach is not None:
        # The package's names and definitions are stored (ADR 0018): a reference is
        # rewritten through the names, and the re-export rule is not applied to a name the
        # package defines as something else.
        index = NameIndex(qualified, reexports=False)
        hits = [r for r in into_package
                if any(index.match(c) or (c not in reach.collisions and hit(c, qualified, bare))
                       for c in reach.canonical(r.name))]  # fmt: skip
    else:
        hits = [r for r in into_package if hit(r.name, qualified, bare)]
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
    if reach is not None:
        index = NameIndex(reach.targets, reexports=False)
        through = []
        for r in into_package:
            found = [f for name in reach.canonical(r.name) if (f := index.closest(name))]
            if found:
                through.append((r, *min(found)))
        if through:
            # The path shown starts at the closest match (the name itself, a member of it,
            # then a name inside it), then the shortest path, which rests on the fewest
            # links, then the first in the code.
            paths = {caller: call_path(caller, reach.toward) for _, _, caller in through}
            nearest, _, caller = min(
                through,
                key=lambda h: (h[1], len(paths[h[2]]), h[0].location.path, h[0].location.line),
            )
            return Alert(
                **base,
                **context,
                verdict="CALLED",
                reason=f"your code references {nearest.name}, which reaches a vulnerable symbol "
                f"(static call path in the source of {package} {reach.version})",
                evidence=tuple(
                    sorted({h[0].location for h in through}, key=lambda loc: (loc.path, loc.line))
                ),
                matched=tuple(sorted({h[0].name for h in through})),
                path=paths[caller],
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
    if not qualified and not bare:
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
    leaves = sorted({t.split(".")[-1] for t in qualified} | set(bare))
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
