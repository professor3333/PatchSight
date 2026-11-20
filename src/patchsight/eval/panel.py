"""The repository panel: real projects pinned to old lockfiles, scanned as a user would.

Each project in ``benchmarks/panel-v1.toml`` is fetched at its pinned commit into an
ignored cache, with a partial, sparse clone that holds only what the scanner reads:
Python files, templates and lockfiles. Then ``run_scan`` runs on it exactly as
``patchsight scan`` does, OSV query included, and is timed.

It measures two targets of the proposal:

* **coverage**: the share of alerts whose advisory has symbol data (target 50% or more);
* **scan latency** with a warm cache, meaning the database is already local
  (targets: p50 under 5 s and p95 under 15 s for a 200-dependency repository).

No third-party code is stored or published: the report holds counts and timings only.
"""

import os
import platform
import statistics
import subprocess
import time
import tomllib
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.scan import ast_scanner
from patchsight.scan.ast_scanner import TEMPLATE_SUFFIXES
from patchsight.scan.run import run_scan
from patchsight.scan.verdicts import DISPLAY_ORDER

PANEL = Path("benchmarks/panel-v1.toml")
SPARSE = (
    "*.py",
    *(f"*{s}" for s in sorted(TEMPLATE_SUFFIXES)),
    "*.txt",
    "*.in",
    "*.lock",
    "*.toml",
    # Files that start processes (``ast_scanner.is_launch_file``). The scanner also reads
    # extensionless scripts with a shebang anywhere; the panel fetches those from bin/ and
    # scripts/ directories only.
    "Dockerfile*", "*.Dockerfile", "*.dockerfile", "Containerfile*", "*.containerfile",
    "Procfile*", "*compose*.yml", "*compose*.yaml", "*.sh", "*.bash", "*.zsh", "*.service",
    "*.mk", "Makefile", "GNUmakefile", "justfile", "entrypoint", "app.yaml", "render.yaml",
    ".gitlab-ci.yml", "*supervisor*.conf", ".github/workflows/*", "**/bin/*", "**/scripts/*",
)  # fmt: skip


class Repo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    url: str
    commit: str
    lockfile: str


def load(path: Path) -> list[Repo]:
    return [Repo.model_validate(r) for r in tomllib.loads(path.read_text("utf-8"))["repo"]]


def _git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(  # noqa: S603 - fixed git argv, no shell
        ["git", *args],  # noqa: S607
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    return result.stdout.strip()


def checkout(repo: Repo, cache: Path, partial: bool = True) -> Path:
    """The project at its pinned commit, fetched once. ``partial`` fetches only the files
    the scanner reads; local test repositories may not support it."""
    target = cache / repo.name
    if (target / ".git").exists():
        try:
            if _git("rev-parse", "HEAD", cwd=target) == repo.commit:
                return target
        except subprocess.CalledProcessError:
            pass
    target.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", cwd=target)
    remotes = _git("remote", cwd=target).split()
    if "origin" not in remotes:
        _git("remote", "add", "origin", repo.url, cwd=target)
    if partial:
        _git("sparse-checkout", "set", "--no-cone", *SPARSE, cwd=target)
        _git("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", repo.commit, cwd=target)
    else:
        _git("fetch", "-q", "--depth", "1", "origin", repo.commit, cwd=target)
    _git("checkout", "-q", "--detach", "FETCH_HEAD", cwd=target)
    return target


# Why an alert is UNKNOWN, by the start of its reason (``scan/verdicts.py``).
UNKNOWN_REASONS = (
    ("no symbol data", "no symbol data for the advisory"),
    ("symbol data is low confidence", "low-confidence record, no reference"),
    ("a dynamic import with a computed name", "a computed dynamic import somewhere in the code"),
    ("dynamic use the scanner cannot follow", "dynamic use of the package"),
    ("could not parse", "a file that does not parse mentions the package"),
    ("the import name of", "import name not known"),
    ("your code uses .", "a vulnerable name on an untyped object"),
    ("a template uses", "a vulnerable name in a template"),
    ("the record lists no symbols", "a record with no symbols"),
    ("your project may run", "the project runs the package as a command"),
)


def unknown_reason(reason: str) -> str:
    return next((label for start, label in UNKNOWN_REASONS if reason.startswith(start)), "other")


class RepoResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    commit: str
    lockfile: str
    dependencies: int
    pinned: int
    python_files: int
    alerts: int
    with_data: int  # alerts whose advisory has a record in the database
    verdicts: dict[str, int]
    unknown_reasons: dict[str, int] = {}
    seconds: tuple[float, ...]  # each full scan, OSV query included
    code_scan_seconds: float  # the local part alone: reading and resolving the code


def measure(repo: Repo, path: Path, database: Path, runs: int) -> RepoResult:
    seconds = []
    for _ in range(runs):
        start = time.perf_counter()
        alerts, dependencies, _ = run_scan(path, path / repo.lockfile, database)
        seconds.append(round(time.perf_counter() - start, 3))
    start = time.perf_counter()
    usage = ast_scanner.scan(path)
    code_scan = round(time.perf_counter() - start, 3)
    verdicts = Counter(a.verdict for a in alerts)
    return RepoResult(
        name=repo.name,
        commit=repo.commit,
        lockfile=repo.lockfile,
        dependencies=len(dependencies),
        pinned=sum(1 for d in dependencies if d.version),
        python_files=usage.files,
        alerts=len(alerts),
        with_data=sum(1 for a in alerts if a.confidence is not None),
        verdicts={v: verdicts[v] for v in DISPLAY_ORDER},
        unknown_reasons=dict(
            Counter(unknown_reason(a.reason) for a in alerts if a.verdict == "UNKNOWN")
        ),
        seconds=tuple(seconds),
        code_scan_seconds=code_scan,
    )


def machine() -> str:
    """The machine, without host or user names."""
    return (
        f"{platform.system()} {platform.release()} {platform.machine()}, "
        f"{os.cpu_count()} CPUs, Python {platform.python_version()}"
    )


class PanelReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    panel: str
    db_version: str
    machine: str
    measured_at: str
    runs: int
    results: tuple[RepoResult, ...]

    @property
    def alerts(self) -> int:
        return sum(r.alerts for r in self.results)

    @property
    def with_data(self) -> int:
        return sum(r.with_data for r in self.results)

    def latency(self, minimum_dependencies: int = 0) -> tuple[float, float, int]:
        """p50 and p95 over every timed scan of the repositories with at least this many
        dependencies, and how many scans that is."""
        times = sorted(
            t for r in self.results if r.dependencies >= minimum_dependencies for t in r.seconds
        )
        if not times:
            return 0.0, 0.0, 0
        if len(times) == 1:
            return times[0], times[0], 1
        p95 = statistics.quantiles(times, n=20, method="inclusive")[-1]
        return statistics.median(times), p95, len(times)


def render_markdown(report: PanelReport) -> str:
    share = report.with_data / report.alerts if report.alerts else 0.0
    p50, p95, _ = report.latency()
    big50, big95, big_scans = report.latency(200)
    big_repos = [r.name for r in report.results if r.dependencies >= 200]
    totals = Counter[str]()
    reasons = Counter[str]()
    for r in report.results:
        totals.update(r.verdicts)
        reasons.update(r.unknown_reasons)
    lines = [
        f"# Repository panel: database {report.db_version}",
        "",
        "Generated by `python -m patchsight.pipeline panel-report`; do not edit by hand. Each "
        f"project in [`{report.panel}`](../../{report.panel}) is fetched at its pinned commit "
        "and scanned exactly as `patchsight scan` does, OSV query included.",
        "",
        f"- **{len(report.results)} repositories**, {sum(r.dependencies for r in report.results):,}"
        f" dependencies ({sum(r.pinned for r in report.results):,} pinned), "
        f"{sum(r.python_files for r in report.results):,} Python files",
        f"- Machine: {report.machine}. Measured {report.measured_at}, {report.runs} scans per "
        "repository, with the database already downloaded.",
        "",
        "## Result",
        "",
        "| Metric | Measured | Target |",
        "|---|---:|---|",
        f"| Alerts with symbol data | **{share:.1%}** ({report.with_data:,} of "
        f"{report.alerts:,}) | 50% or more |",
        f"| Scan time, every repository: p50 / p95 | {p50:.2f} s / {p95:.2f} s | — |",
        f"| Scan time, {len(big_repos)} repositories with 200 or more dependencies: p50 / p95 | "
        + (f"**{big50:.2f} s / {big95:.2f} s**" if big_scans else "none in the panel")
        + " | under 5 s / under 15 s |",
        "",
        "A version-only scanner reports every alert below as affected. PatchSight shows every "
        "one too, ranked:",
        "",
        "| Verdict | Alerts |",
        "|---|---:|",
        *(f"| `{v}` | {totals[v]:,} |" for v in DISPLAY_ORDER),
        "",
        "### Why alerts are `UNKNOWN`",
        "",
        "Each alert counts under the first reason the rules give, in the order of "
        "`scan/verdicts.py`; later ones may apply too. Every record is low confidence for now "
        "([ADR 0008](../adr/0008-withhold-high-confidence.md)), so an alert without a reference "
        "would be `UNKNOWN` whichever reason came first.",
        "",
        "| Reason | Alerts | Repositories |",
        "|---|---:|---:|",
        *(
            f"| {label} | {reasons[label]:,} | "
            f"{sum(1 for r in report.results if r.unknown_reasons.get(label))} |"
            for label in sorted(reasons, key=lambda k: -reasons[k])
        ),
        "",
        "## Every repository",
        "",
        "| Repository | Lockfile | Dependencies | Alerts | With data | "
        + " | ".join(f"`{v}`" for v in DISPLAY_ORDER)
        + " | Scan (median) | Code only |",
        "|---|---|---:|---:|---:|" + "---:|" * len(DISPLAY_ORDER) + "---:|---:|",
    ]
    for r in report.results:
        lines.append(
            f"| {r.name} (`{r.commit[:8]}`) | `{r.lockfile}` | {r.dependencies} | {r.alerts} | "
            f"{r.with_data} | "
            + " | ".join(str(r.verdicts[v]) for v in DISPLAY_ORDER)
            + f" | {statistics.median(r.seconds):.2f} s | {r.code_scan_seconds:.2f} s |"
        )
    lines += [
        "",
        "Scan time is wall-clock for the whole scan: parsing the lockfile, one OSV batch query "
        "over the network, reading the database and scanning the code. *Code only* is the local "
        "part: reading and resolving the Python files.",
        "",
    ]
    return "\n".join(lines)
