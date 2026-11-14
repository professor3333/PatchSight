"""Offline pipeline commands: ``python -m patchsight.pipeline <command>``."""

import os
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import httpx
import typer

from patchsight.pipeline import fix_sample, week1
from patchsight.pipeline.benchmarks import changedfuncs, dunlap
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.ingest import ghsa_repo, snapshot
from patchsight.pipeline.ingest.aliases import alias_groups
from patchsight.pipeline.ingest.osv import Advisory, Excluded, Quarantined, normalise_dump
from patchsight.pipeline.pypi import PyPIClient

app = typer.Typer(name="patchsight-pipeline", no_args_is_help=True, add_completion=False)

Root = Annotated[Path, typer.Option(help="Repository root.")]
DUMP = "osv-pypi-all"
MODIFIED = "osv-pypi-modified-id"
GHSA = "github-advisory-database"
MANIFEST = Path("manifests/snapshot.json")
RAW = Path("data/raw")


def _load_verified(root: Path) -> tuple[snapshot.SnapshotManifest, Path]:
    manifest = snapshot.load_manifest(root / MANIFEST)
    return manifest, snapshot.verify(manifest.file(DUMP), root)


@app.command("snapshot")
def snapshot_command(root: Root = Path()) -> None:
    """Download the OSV PyPI dump and modified index, and pin their hashes."""
    manifest = snapshot.load_manifest(root / MANIFEST)
    timeout = httpx.Timeout(60.0, connect=15.0)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        for name, url, filename in (
            (DUMP, snapshot.OSV_PYPI_DUMP_URL, "all.zip"),
            (MODIFIED, snapshot.OSV_PYPI_MODIFIED_URL, "modified_id.csv"),
        ):
            entry = snapshot.download(client, name, url, root / RAW / "osv-pypi" / filename, root)
            manifest = manifest.with_file(entry)
            typer.echo(f"{name}: {entry.size:,} bytes, sha256 {entry.sha256}")
    snapshot.save_manifest(manifest, root / MANIFEST)


@app.command("clone-ghsa")
def clone_ghsa_command(root: Root = Path()) -> None:
    """Sparse-clone the PyPI subset of github/advisory-database and pin its commit."""
    manifest, dump = _load_verified(root)
    advisories = [r for r in normalise_dump(dump) if isinstance(r, Advisory)]
    dest = root / RAW / "advisory-database"
    ghsa_repo.sparse_clone(dest, advisories)
    entry = snapshot.record_repo(
        GHSA, ghsa_repo.GHSA_REPO_URL, dest, root, note="sparse: PyPI GHSA advisories only"
    )
    snapshot.save_manifest(manifest.with_repo(entry), root / MANIFEST)
    typer.echo(f"{GHSA}: {entry.commit}")


@app.command("normalise")
def normalise_command(
    root: Root = Path(),
    out: Annotated[Path, typer.Option(help="Output directory.")] = Path("data/interim"),
) -> None:
    """Normalise the pinned dump into advisories, exclusions and quarantine (JSONL)."""
    _, dump = _load_verified(root)
    target = root / out
    target.mkdir(parents=True, exist_ok=True)
    files = {
        Advisory: (target / "advisories.jsonl").open("w", encoding="utf-8"),
        Excluded: (target / "excluded.jsonl").open("w", encoding="utf-8"),
        Quarantined: (target / "quarantine.jsonl").open("w", encoding="utf-8"),
    }
    counts = dict.fromkeys(files, 0)
    try:
        for result in normalise_dump(dump):
            files[type(result)].write(result.model_dump_json() + "\n")
            counts[type(result)] += 1
    finally:
        for handle in files.values():
            handle.close()
    typer.echo(", ".join(f"{kind.__name__}: {n:,}" for kind, n in counts.items()))


@app.command("week1-report")
def week1_report_command(
    root: Root = Path(),
    out: Annotated[Path, typer.Option(help="Report path, without extension.")] = Path(
        "docs/reports/week1-data-gate"
    ),
) -> None:
    """Measure the Week 1 data gate and write the report as Markdown and JSON."""
    manifest, dump = _load_verified(root)
    results = list(normalise_dump(dump))
    dump_entry = manifest.file(DUMP)

    ghsa_scan = None
    lines = [
        f"- `{dump_entry.name}`: {dump_entry.url}, SHA-256 `{dump_entry.sha256}`, "
        f"retrieved {dump_entry.retrieved_at:%Y-%m-%d %H:%M} UTC "
        f"(Last-Modified: {dump_entry.last_modified})"
    ]
    for repo in manifest.repos:
        if repo.name == GHSA and (root / repo.path / ".git").exists():
            ghsa_scan = ghsa_repo.scan(
                root / repo.path, [r for r in results if isinstance(r, Advisory)]
            )
        lines.append(
            f"- `{repo.name}`: {repo.url}, commit `{repo.commit}` "
            f"({repo.committed_at:%Y-%m-%d}; {repo.note})"
        )

    report = week1.build_report(results, as_of=dump_entry.retrieved_at, ghsa_scan=ghsa_scan)
    target = root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_suffix(".json").write_text(report.model_dump_json(indent=2) + "\n", "utf-8")
    target.with_suffix(".md").write_text(week1.render_markdown(report, lines), "utf-8")
    verdict = "PASS" if report.gate_passed else "FAIL"
    typer.echo(f"gate {verdict}: {report.gate_metric.share:.1%} with a GitHub fix link")


@app.command("fix-sample")
def fix_sample_command(
    root: Root = Path(),
    size: Annotated[int, typer.Option(help="Vulnerabilities to sample.")] = 100,
    seed: Annotated[int, typer.Option(help="Random seed, recorded in the report.")] = 20261114,
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
    out: Annotated[Path, typer.Option(help="Report path, without extension.")] = Path(
        "docs/reports/fix-candidate-sample"
    ),
) -> None:
    """Check a random sample of fix candidates against GitHub (needs GITHUB_TOKEN)."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise typer.BadParameter("set GITHUB_TOKEN; unauthenticated GitHub allows 60 requests/h")
    manifest, dump = _load_verified(root)
    advisories = [r for r in normalise_dump(dump) if isinstance(r, Advisory)]
    by_id = {a.id: a for a in advisories}
    groups = alias_groups(advisories)
    population = [
        g
        for g in groups
        if any(
            c.kind in week1.GITHUB_KINDS for i in g.advisory_ids for c in by_id[i].fix_candidates
        )
    ]
    sample = fix_sample.draw_sample(population, size, seed)

    github = GitHubClient(root / cache / "github", token=token)
    pypi = PyPIClient(root / cache / "pypi")
    try:
        checks = []
        for number, group in enumerate(sample, 1):
            checks.append(fix_sample.check_group(group, by_id, github, pypi))
            if number % 10 == 0:
                typer.echo(f"checked {number}/{len(sample)}", err=True)
    finally:
        github.close()
        pypi.close()

    dump_entry = manifest.file(DUMP)
    report = fix_sample.build_report(
        checks,
        as_of=dump_entry.retrieved_at.date(),
        seed=seed,
        vulnerabilities=len(groups),
        population=len(population),
    )
    lines = [
        f"- `{dump_entry.name}`: SHA-256 `{dump_entry.sha256}` (see `manifests/snapshot.json`)"
    ]
    target = root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_suffix(".json").write_text(report.model_dump_json(indent=2) + "\n", "utf-8")
    target.with_suffix(".md").write_text(fix_sample.render_markdown(report, lines), "utf-8")
    typer.echo(
        f"{report.verdict}: strict estimate {report.estimated_share_strict.share:.1%}, "
        f"lenient {report.estimated_share_lenient.share:.1%} "
        f"({github.http.network_requests} GitHub and {pypi.http.network_requests} PyPI requests)"
    )


DUNLAP = "dunlap-llm-vulnerable-functions"
DUNLAP_DATA = "dunlap-patchparser-csv"


def _github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise typer.BadParameter("set GITHUB_TOKEN; unauthenticated GitHub allows 60 requests/h")
    return token


@app.command("fetch-dunlap")
def fetch_dunlap_command(root: Root = Path()) -> None:
    """Clone the Dunlap et al. dataset, extract its CSV, and pin both in the manifest."""
    dest = root / RAW / "llm-vulnerable-functions"
    if not (dest / ".git").exists():
        ghsa_repo._git("clone", "-q", "--depth", "1", dunlap.DUNLAP_REPO_URL, str(dest))
    target = dest / "data" / "patchparser-data"
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest / "data" / "patchparser-data.tar.gz") as archive:
        archive.extractall(target, filter="data")
    csv_path = dest / dunlap.DUNLAP_CSV
    manifest = snapshot.load_manifest(root / MANIFEST)
    repo = snapshot.record_repo(DUNLAP, dunlap.DUNLAP_REPO_URL, dest, root, note="Apache-2.0")
    entry = snapshot.SourceFile(
        name=DUNLAP_DATA,
        url=f"{dunlap.DUNLAP_REPO_URL.removesuffix('.git')}/blob/{repo.commit}/"
        "data/patchparser-data.tar.gz",
        path=csv_path.relative_to(root).as_posix(),
        sha256=snapshot.sha256_file(csv_path),
        size=csv_path.stat().st_size,
        last_modified=None,
        retrieved_at=datetime.now(UTC),
    )
    snapshot.save_manifest(manifest.with_repo(repo).with_file(entry), root / MANIFEST)
    typer.echo(f"{DUNLAP}: {repo.commit}; {DUNLAP_DATA} sha256 {entry.sha256}")


@app.command("dunlap-baseline")
def dunlap_baseline_command(
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
    out: Annotated[Path, typer.Option(help="Report path, without extension.")] = Path(
        "docs/reports/changedfuncs-baseline"
    ),
) -> None:
    """Reproduce ChangedFuncs on the Dunlap benchmark (needs GITHUB_TOKEN)."""
    token = _github_token()
    manifest = snapshot.load_manifest(root / MANIFEST)
    entry = manifest.file(DUNLAP_DATA)
    reports = dunlap.load(snapshot.verify(entry, root))
    repo = next(r for r in manifest.repos if r.name == DUNLAP)
    github = GitHubClient(root / cache / "github", token=token)
    try:
        report = changedfuncs.run(github, reports, as_of=entry.retrieved_at.date())
    finally:
        github.close()
    lines = [
        f"- `{repo.name}`: {repo.url}, commit `{repo.commit}`",
        f"- `{entry.name}`: `{dunlap.DUNLAP_CSV}`, SHA-256 `{entry.sha256}`",
        "- Fix commits and file contents: GitHub REST API (Go's own repositories through "
        "their `github.com/golang` mirrors)",
    ]
    target = root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_suffix(".json").write_text(report.model_dump_json(indent=2) + "\n", "utf-8")
    target.with_suffix(".md").write_text(changedfuncs.render_markdown(report, lines), "utf-8")
    o = report.ours
    typer.echo(
        f"ours: P {o.precision:.3f} R {o.recall:.3f} F1 {o.f1:.3f}; "
        f"identical to released {report.identical_reports}/{report.reports}; "
        f"{github.http.network_requests} GitHub requests"
    )


if __name__ == "__main__":
    app()
