"""Offline pipeline commands: ``python -m patchsight.pipeline <command>``."""

import json
import os
import subprocess
import tarfile
import time
import zipfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import httpx
import typer

from patchsight import db
from patchsight.eval.metrics import SetScores, score
from patchsight.pipeline import build_db, fix_sample, week1
from patchsight.pipeline.benchmarks import (
    bundle,
    changedfuncs,
    dunlap,
    extraction,
    replay,
    splits,
)
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.extract.prompt import load_template
from patchsight.pipeline.ingest import ghsa_repo, snapshot
from patchsight.pipeline.ingest.aliases import AliasGroup, alias_groups
from patchsight.pipeline.ingest.osv import Advisory, Excluded, Quarantined, normalise_dump
from patchsight.pipeline.llm.client import (
    QuotaExhaustedError,
    RateLimitedError,
    cache_only_client,
    client_for,
)
from patchsight.pipeline.llm.config import load_config
from patchsight.pipeline.llm.tokens import HfTokenizer
from patchsight.pipeline.pypi import PyPIClient
from patchsight.scan import dbcache

app = typer.Typer(name="patchsight-pipeline", no_args_is_help=True, add_completion=False)

Root = Annotated[Path, typer.Option(help="Repository root.")]
DUMP = "osv-pypi-all"
MODIFIED = "osv-pypi-modified-id"
TOP_PACKAGES = "top-pypi-packages"
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


@app.command("fetch-top-packages")
def fetch_top_packages_command(root: Root = Path()) -> None:
    """Download the most-downloaded PyPI packages list and pin its hash.

    Used only to order quota-limited work (pypi-extract --priority). The list is not
    redistributed: it stays in data/raw, and the manifest records only its URL and hash.
    """
    manifest = snapshot.load_manifest(root / MANIFEST)
    timeout = httpx.Timeout(60.0, connect=15.0)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        entry = snapshot.download(
            client, TOP_PACKAGES, snapshot.TOP_PYPI_PACKAGES_URL,
            root / RAW / "top-pypi-packages" / "top-pypi-packages.min.json", root,
        )  # fmt: skip
    snapshot.save_manifest(manifest.with_file(entry), root / MANIFEST)
    typer.echo(f"{TOP_PACKAGES}: {entry.size:,} bytes, sha256 {entry.sha256}")


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
    target.with_name(target.name + ".json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    target.with_name(target.name + ".md").write_text(week1.render_markdown(report, lines), "utf-8")
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
    target.with_name(target.name + ".json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    target.with_name(target.name + ".md").write_text(
        fix_sample.render_markdown(report, lines), "utf-8"
    )
    typer.echo(
        f"{report.verdict}: strict estimate {report.estimated_share_strict.share:.1%}, "
        f"lenient {report.estimated_share_lenient.share:.1%} "
        f"({github.http.network_requests} GitHub and {pypi.http.network_requests} PyPI requests)"
    )


DUNLAP = "dunlap-llm-vulnerable-functions"
DUNLAP_DATA = "dunlap-patchparser-csv"
DUNLAP_ADVISORIES = "dunlap-govulndb-advisories-csv"
DUNLAP_SPLIT = Path("splits/dunlap-v1.json")
DUNLAP_BUNDLE = Path("benchmarks/dunlap-v1/candidates.json")
BASELINE_REPORT = Path("docs/reports/changedfuncs-baseline.json")
DUNLAP_DEV_SIZE = 60


def _github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise typer.BadParameter("set GITHUB_TOKEN; unauthenticated GitHub allows 60 requests/h")
    return token


@app.command("fetch-dunlap")
def fetch_dunlap_command(root: Root = Path()) -> None:
    """Clone the Dunlap et al. dataset and extract its CSVs.

    If the manifest already pins the dataset, the pinned commit is checked out and both CSVs
    are verified against their pinned hashes; nothing in the manifest changes. Only the
    first run records new pins.
    """
    dest = root / RAW / "llm-vulnerable-functions"
    manifest = snapshot.load_manifest(root / MANIFEST)
    pinned = next((r for r in manifest.repos if r.name == DUNLAP), None)
    if not (dest / ".git").exists():
        ghsa_repo._git("clone", "-q", dunlap.DUNLAP_REPO_URL, str(dest))
    if pinned is not None:
        ghsa_repo._git("-C", str(dest), "checkout", "-q", pinned.commit)
    target = dest / "data" / "patchparser-data"
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest / "data" / "patchparser-data.tar.gz") as archive:
        archive.extractall(target, filter="data")

    if pinned is not None:
        for name in (DUNLAP_DATA, DUNLAP_ADVISORIES):
            snapshot.verify(manifest.file(name), root)
        typer.echo(f"{DUNLAP}: pinned commit {pinned.commit} checked out; CSV hashes verified")
        return

    repo = snapshot.record_repo(DUNLAP, dunlap.DUNLAP_REPO_URL, dest, root, note="Apache-2.0")
    base = f"{dunlap.DUNLAP_REPO_URL.removesuffix('.git')}/blob/{repo.commit}/"
    entries = []
    for name, relative, published in (
        (DUNLAP_DATA, dunlap.DUNLAP_CSV, "data/patchparser-data.tar.gz"),
        (DUNLAP_ADVISORIES, extraction.DUNLAP_ADVISORIES, extraction.DUNLAP_ADVISORIES),
    ):
        path = dest / relative
        entries.append(
            snapshot.SourceFile(
                name=name,
                url=base + published,
                path=path.relative_to(root).as_posix(),
                sha256=snapshot.sha256_file(path),
                size=path.stat().st_size,
                last_modified=None,
                retrieved_at=datetime.now(UTC),
            )
        )
    manifest = manifest.with_repo(repo)
    for entry in entries:
        manifest = manifest.with_file(entry)
    snapshot.save_manifest(manifest, root / MANIFEST)
    typer.echo(f"{DUNLAP}: pinned {repo.commit}")


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
    target.with_name(target.name + ".json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    target.with_name(target.name + ".md").write_text(
        changedfuncs.render_markdown(report, lines), "utf-8"
    )
    o = report.ours
    typer.echo(
        f"ours: P {o.precision:.3f} R {o.recall:.3f} F1 {o.f1:.3f}; "
        f"identical to released {report.identical_reports}/{report.reports}; "
        f"{github.http.network_requests} GitHub requests"
    )


@app.command("dunlap-extract")
def dunlap_extract_command(
    root: Root = Path(),
    role: Annotated[str, typer.Option(help="Model role in the LLM config.")] = "extractor",
    split: Annotated[str, typer.Option(help="Split part: dev, test or all.")] = "dev",
    sample: Annotated[int | None, typer.Option(help="Run on a seeded sample of N reports.")] = None,
    seed: Annotated[int, typer.Option(help="Sample seed.")] = extraction.SEED,
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    cache: Annotated[Path, typer.Option(help="Response cache root.")] = Path(".cache"),
    out: Annotated[Path, typer.Option(help="Report path, without extension.")] = Path(
        "docs/reports/extraction-dunlap"
    ),
) -> None:
    """Run LLM extraction on the Dunlap benchmark (needs GITHUB_TOKEN and the model's key)."""
    token = _github_token()
    manifest = snapshot.load_manifest(root / MANIFEST)
    data = manifest.file(DUNLAP_DATA)
    reports = dunlap.load(snapshot.verify(data, root))
    advisories = extraction.load_advisories(snapshot.verify(manifest.file(DUNLAP_ADVISORIES), root))
    frozen = splits.load_split(root / DUNLAP_SPLIT)
    llm_config = load_config(root / config)
    template = load_template(root / prompt)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    llm, model_id = client_for(llm_config, role, root / cache / "llm", counter)
    github = GitHubClient(root / cache / "http" / "github", token=token)
    try:
        result = extraction.run(
            github, llm, llm_config, role, template, counter, reports, advisories,
            as_of=data.retrieved_at.date(), sample_size=sample, seed=seed,
            ids=frozen.split.ids(split), split=f"{frozen.split.name}:{split}",
            split_sha256=frozen.sha256,
            progress=lambda done, total: typer.echo(f"extracted {done}/{total}", err=True),
        )  # fmt: skip
    except (QuotaExhaustedError, RateLimitedError) as stopped:
        typer.echo(f"stopped: {stopped}", err=True)
        typer.echo(
            "Every answer so far is cached. Re-run the same command later to resume.", err=True
        )
        raise typer.Exit(code=2) from None
    finally:
        github.close()
    lines = [
        f"- Benchmark: `{DUNLAP_DATA}` SHA-256 `{data.sha256}` (see `manifests/snapshot.json`)",
        f"- Prompt: `{prompt.as_posix()}` (`{template.version}`); config: `{config.as_posix()}`",
        f"- Model: `{model_id}` via role `{role}`",
    ]
    target = root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_name(target.name + ".json").write_text(
        result.model_dump_json(indent=2) + "\n", "utf-8"
    )
    target.with_name(target.name + ".md").write_text(
        extraction.render_markdown(result, lines), "utf-8"
    )
    e, n = result.extraction, result.changedfuncs
    typer.echo(
        f"{result.reports} reports: extraction P {e.precision:.3f} R {e.recall:.3f} F1 {e.f1:.3f}; "
        f"ChangedFuncs P {n.precision:.3f} R {n.recall:.3f} F1 {n.f1:.3f}; "
        f"status {result.status}; {llm.network_calls} model calls"
    )


@app.command("dunlap-split")
def dunlap_split_command(root: Root = Path()) -> None:
    """Freeze the Dunlap dev/test split once. Refuses to overwrite an existing split."""
    manifest = snapshot.load_manifest(root / MANIFEST)
    reports = dunlap.load(snapshot.verify(manifest.file(DUNLAP_DATA), root))
    split = splits.make_split(reports, "dunlap-v1", DUNLAP_DEV_SIZE, extraction.SEED)
    record = splits.save_split(split, root / DUNLAP_SPLIT)
    typer.echo(
        f"{DUNLAP_SPLIT}: dev {len(split.dev)}, test {len(split.test)}, sha256 {record.sha256}"
    )


KAGGLE_RUN_PREFIXES = (
    ".cache/llm/", "docs/reports/", "pypi-run/", "run-info.json", "llama-server.log",
)  # fmt: skip
KAGGLE_INPUTS_MANIFEST = "patchsight-pypi-inputs.json"


@app.command("import-kaggle-run")
def import_kaggle_run_command(
    archive: Annotated[Path, typer.Argument(help="The zip downloaded from the Kaggle run.")],
    root: Root = Path(),
) -> None:
    """Import a Kaggle run: model responses into the cache, its files into data/interim.

    Only expected paths are accepted; anything absolute, containing "..", or outside the
    expected prefixes is refused. Regenerate the reports afterwards with dunlap-extract
    --role kaggle_extractor, which then replays from the cache with no model calls.
    """
    inbox = root / "data" / "interim" / "kaggle" / archive.stem
    with zipfile.ZipFile(archive) as bundle:
        members = [m for m in bundle.infolist() if not m.is_dir()]
        for member in members:
            name = member.filename
            if (
                name.startswith("/")
                or ".." in Path(name).parts
                or not name.startswith(KAGGLE_RUN_PREFIXES)
            ):
                raise typer.BadParameter(f"unexpected path in archive: {name!r}")
        responses = 0
        for member in members:
            # Responses go into the shared cache; the run's usage ledger does not, so it can
            # never overwrite this machine's daily-quota ledger.
            if member.filename.startswith(".cache/llm/") and not member.filename.startswith(
                ".cache/llm/usage/"
            ):
                target = root / member.filename
                responses += member.filename.endswith(".json")
            else:
                target = inbox / member.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(member))
    typer.echo(f"imported {responses} cached responses; run files in {inbox.relative_to(root)}")


def _github_fix_groups(
    dump: Path, ids: str | None, sample: int | None, seed: int
) -> tuple[dict[str, Advisory], list[AliasGroup]]:
    """Vulnerabilities with a GitHub fix candidate, optionally narrowed to IDs or a sample."""
    advisories = [r for r in normalise_dump(dump) if isinstance(r, Advisory)]
    by_id = {a.id: a for a in advisories}
    groups = [
        g
        for g in alias_groups(advisories)
        if any(
            c.kind in week1.GITHUB_KINDS for i in g.advisory_ids for c in by_id[i].fix_candidates
        )
    ]
    if ids:
        wanted = {i.strip() for i in ids.split(",") if i.strip()}
        groups = [g for g in groups if wanted & set(g.identifiers)]
    elif sample is not None:
        groups = fix_sample.draw_sample(groups, sample, seed)
    return by_id, groups


@app.command("build-db")
def build_db_command(
    root: Root = Path(),
    ids: Annotated[str | None, typer.Option(help="Comma-separated advisory IDs.")] = None,
    sample: Annotated[int | None, typer.Option(help="Seeded sample of N vulnerabilities.")] = None,
    seed: Annotated[int, typer.Option(help="Sample seed.")] = 20261114,
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
    out: Annotated[Path, typer.Option(help="Output path, without extension.")] = Path(
        "data/build/patchsight"
    ),
    llm: Annotated[
        Path | None, typer.Option(help="Extractor outcomes (pypi-extract JSONL) to merge.")
    ] = None,
    second: Annotated[
        Path | None, typer.Option(help="Second-opinion outcomes (pypi-extract JSONL).")
    ] = None,
) -> None:
    """Build the symbol database: fallback records, upgraded by LLM extraction when given
    (needs GITHUB_TOKEN)."""
    from patchsight.pipeline import llm_records

    if second is not None and llm is None:
        raise typer.BadParameter("--second needs --llm")
    token = _github_token()
    manifest, dump = _load_verified(root)
    by_id, groups = _github_fix_groups(dump, ids, sample, seed)
    dump_entry = manifest.file(DUMP)
    version = dump_entry.retrieved_at.strftime("%Y.%m.%d")
    # A full build takes hours: wait out GitHub's hourly limit instead of failing.
    github = GitHubClient(root / cache / "github", token=token, wait_for_rate_limit=3900)
    pypi = PyPIClient(root / cache / "pypi")
    try:
        records, aliases, report = build_db.build(
            groups, by_id, github, pypi, version,
            progress=lambda done, total: typer.echo(f"built {done}/{total}", err=True),
        )  # fmt: skip
    finally:
        github.close()
        pypi.close()
    merged: dict[str, int] = {}
    if llm is not None:
        primaries = llm_records.load(root / llm)
        secondaries = llm_records.load(root / second) if second is not None else {}
        records, merged = llm_records.apply(records, primaries, secondaries)
    commit = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True, text=True, check=False,
    ).stdout.strip()  # fmt: skip
    meta = {
        "db_version": version,
        "built_at": datetime.now(UTC).isoformat(),
        "builder": "llm-v1" if llm is not None else "fallback-v1",
        "snapshot_sha256": dump_entry.sha256,
        "code_commit": commit,
    }
    if llm is not None:
        meta["records_by_tier"] = json.dumps(dict(Counter(r.confidence for r in records)))
    target = root / out
    db.write(
        target.with_name(target.name + ".sqlite"), records, aliases, meta,
        builds=build_db.ledger(report.outcomes),
    )  # fmt: skip
    target.with_name(target.name + ".jsonl").write_text(build_db.jsonl(records), "utf-8")
    target.with_name(target.name + "-build.json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(
        f"db {version}: {len(records)} records, {sum(len(r.symbols) for r in records)} symbols "
        f"from {report.groups} vulnerabilities; {report.status}"
    )
    if merged:
        typer.echo(f"LLM merge: {merged}")


@app.command("export-dunlap-bundle")
def export_dunlap_bundle_command(
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
) -> None:
    """Write the benchmark bundle: candidate metadata and truth, no code (needs GITHUB_TOKEN)."""
    token = _github_token()
    manifest = snapshot.load_manifest(root / MANIFEST)
    data = manifest.file(DUNLAP_DATA)
    repo = next(r for r in manifest.repos if r.name == DUNLAP)
    reports = dunlap.load(snapshot.verify(data, root))
    github = GitHubClient(root / cache / "github", token=token)
    try:
        exported = bundle.export(
            github, reports, {"dataset_commit": repo.commit, "dataset_csv_sha256": data.sha256}
        )
    finally:
        github.close()
    bundle.save(exported, root / DUNLAP_BUNDLE)
    count = sum(len(r.candidates) for r in exported.reports)
    typer.echo(f"{DUNLAP_BUNDLE}: {len(exported.reports)} reports, {count} candidates")


@app.command("export-replay")
def export_replay_command(
    tag: Annotated[str, typer.Argument(help="Report tag, e.g. extract-v1-qwen3.8-27b-q4km.")],
    root: Root = Path(),
    role: Annotated[str, typer.Option(help="Model role the run used.")] = "kaggle_extractor",
    part: Annotated[str, typer.Option("--split", help="Split part the run covered.")] = "all",
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    cache: Annotated[Path, typer.Option(help="Cache root.")] = Path(".cache"),
) -> None:
    """Write a replay bundle from the response cache only (never calls a model)."""
    token = _github_token()
    manifest = snapshot.load_manifest(root / MANIFEST)
    ids = splits.load_split(root / DUNLAP_SPLIT).split.ids(part)
    reports = [
        r for r in dunlap.load(snapshot.verify(manifest.file(DUNLAP_DATA), root)) if r.id in ids
    ]
    advisories = extraction.load_advisories(snapshot.verify(manifest.file(DUNLAP_ADVISORIES), root))
    llm_config = load_config(root / config)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    github = GitHubClient(root / cache / "http" / "github", token=token)
    try:
        exported = replay.export(
            github, root / cache / "llm", llm_config, role, load_template(root / prompt), counter,
            reports, advisories, split=part,
        )  # fmt: skip
    finally:
        github.close()
    target = root / DUNLAP_BUNDLE.parent / f"extraction-{tag}.json"
    replay.save(exported, target)
    answers = sum(len(r.answers) for r in exported.reports)
    typer.echo(f"{target.relative_to(root)}: {len(exported.reports)} reports, {answers} answers")


@app.command("confidence-report")
def confidence_report_command(
    primary: Annotated[str, typer.Option(help="Extractor run tag (replay bundle).")],
    secondary: Annotated[str, typer.Option(help="Second-opinion run tag (replay bundle).")],
    part: Annotated[str, typer.Option("--split", help="Split part: dev, test or all.")] = "dev",
    root: Root = Path(),
) -> None:
    """Compare confidence rules, in the benchmark and safety views, from committed files."""
    from patchsight.eval import confidence
    from patchsight.eval.safety import safety

    data = bundle.load(root / DUNLAP_BUNDLE)
    frozen = splits.load_split(root / DUNLAP_SPLIT)
    ids = frozen.split.ids(part)
    truth = {r.id: set(r.symbols) for r in data.reports if r.id in ids}
    changed = {r.id: r.changed_functions() for r in data.reports if r.id in ids}
    reports_dir = root / "docs" / "reports"
    runs = {}
    for tag in (primary, secondary):
        run = replay.load(root / DUNLAP_BUNDLE.parent / f"extraction-{tag}.json")
        # Validated entry points come from the run's committed report (any part that has them).
        entry: dict[str, frozenset[str]] = {}
        for source in sorted(reports_dir.glob(f"extraction-dunlap-*-{tag}.json")):
            for outcome in extraction.ExtractionRun.model_validate_json(
                source.read_text("utf-8")
            ).outcomes:
                entry.setdefault(outcome.advisory_id, frozenset(outcome.entry_points))
        answers = {}
        for report in run.reports:
            if report.id in ids:
                status, names = replay.replay_report(report, run.prompt_version)
                answers[report.id] = confidence.Answer(
                    status=status, vulnerable=frozenset(names), truncated=report.truncated,
                    entry_points=entry.get(report.id, frozenset()),
                )  # fmt: skip
        runs[tag] = (run.model, answers)
    first, second = runs[primary][1], runs[secondary][1]
    results = [
        confidence.evaluate(first, second, changed, truth, rule, True, require_public=public)
        for public in (False, True)
        for rule in confidence.RULES
    ]
    alone = score({r: set(a.vulnerable) for r, a in first.items()}, truth)
    naive = score(changed, truth)
    naive_safety = safety(changed, truth)
    alone_safety = safety(
        {r: set(a.vulnerable) | set(a.entry_points) for r, a in first.items()}, truth
    )

    def strict(label: str, s: SetScores) -> str:
        return f"| {label} | {s.precision:.3f} | {s.recall:.3f} | {s.f1:.3f} | {s.miss_rate:.1%} |"

    def chosen(r: confidence.TierScores) -> str:
        return " **(chosen)**" if r.rule == confidence.CHOSEN_RULE and r.require_public else ""

    lines = [
        f"# Confidence tiers on the Dunlap `{part}` split",
        "",
        "Generated by `python -m patchsight.pipeline confidence-report`; do not edit by hand. "
        "Computed offline from committed replay bundles and reports.",
        "",
        f"- Extractor: `{runs[primary][0]}` (`{primary}`)",
        f"- Second opinion: `{runs[secondary][0]}` (`{secondary}`)",
        f"- Split `{frozen.split.name}:{part}` (SHA-256 `{frozen.sha256}`), {len(first)} reports",
        "",
        "Two views. The **benchmark view** compares function names exactly and ignores entry "
        "points, so it stays comparable with Dunlap et al. The **safety view** scores what the "
        "scanner matches: functions plus validated entry points, with names matched on a dotted "
        "boundary (`Conn.decryptTicket` matches `decryptTicket`). Low confidence always falls "
        "back to every changed function (plus entry points in the safety view).",
        "",
        "## Benchmark view",
        "",
        "| System | Precision | Recall | F1 | Miss rate |",
        "|---|---|---|---|---|",
        strict("ChangedFuncs", naive),
        strict(f"Extractor alone ({runs[primary][0]})", alone),
    ]
    lines += [
        strict(
            f"Tiers: `{r.rule}`{', public symbol required' if r.require_public else ''}{chosen(r)}",
            r.overall,
        )
        for r in results
    ]
    lines += [
        "",
        "## Safety view",
        "",
        "The high-confidence miss rate is the number the proposal targets at 2% or less: a miss "
        'there is what could turn into a wrong "not called".',
        "",
        "| System | Recall | Miss rate | High-confidence reports | High-confidence miss rate |",
        "|---|---|---|---|---|",
        f"| ChangedFuncs | {naive_safety.recall:.3f} | {naive_safety.miss_rate:.1%} | none | n/a |",
        f"| Extractor alone, with entry points | {alone_safety.recall:.3f} | "
        f"{alone_safety.miss_rate:.1%} | none | n/a |",
    ]
    for r in results:
        missed = round(r.safety_high.miss_rate * r.safety_high.reports)
        label = (
            f"Tiers: `{r.rule}`{', public symbol required' if r.require_public else ''}{chosen(r)}"
        )
        lines.append(
            f"| {label} | {r.safety_overall.recall:.3f} | {r.safety_overall.miss_rate:.1%} | "
            f"{r.high_reports} ({r.high_share:.0%}) | {r.safety_high.miss_rate:.1%} "
            f"({missed} of {r.safety_high.reports}) |"
        )
    lines += ["", "Why reports were low confidence:", ""]
    for r in results:
        reasons = ", ".join(f"{k} {v}" for k, v in r.low_reasons.items())
        lines.append(f"- `{r.rule}`{', public' if r.require_public else ''}: {reasons}")
    lines.append("")
    target = reports_dir / f"confidence-dunlap-{part}-{primary}-vs-{secondary}"
    target.with_name(target.name + ".md").write_text("\n".join(lines), "utf-8")
    target.with_name(target.name + ".json").write_text(
        json.dumps([r.model_dump(mode="json") for r in results], indent=2) + "\n", "utf-8"
    )
    typer.echo("\n".join(lines[10:]))


@app.command("parity-report")
def parity_report_command(
    reference: Annotated[str, typer.Option(help="Reference run tag, e.g. the self-hosted run.")],
    candidate: Annotated[str, typer.Option(help="Run tag compared against the reference.")],
    part: Annotated[str, typer.Option("--split", help="Split part: dev, test or all.")] = "dev",
    root: Root = Path(),
) -> None:
    """Compare two extraction runs of the same prompt, from their committed reports."""
    from patchsight.eval.parity import VALID, parity

    data = bundle.load(root / DUNLAP_BUNDLE)
    frozen = splits.load_split(root / DUNLAP_SPLIT)
    ids = frozen.split.ids(part)
    truth = {r.id: set(r.symbols) for r in data.reports if r.id in ids}
    reports_dir = root / "docs" / "reports"
    runs: dict[str, extraction.ExtractionRun] = {}
    for tag in (reference, candidate):
        source = reports_dir / f"extraction-dunlap-{part}-{tag}.json"
        run = extraction.ExtractionRun.model_validate_json(source.read_text("utf-8"))
        if run.split_sha256 != frozen.sha256 or run.sample_size is not None:
            raise typer.BadParameter(f"{source} is not a full run of the frozen split")
        runs[tag] = run
    if runs[reference].prompt_version != runs[candidate].prompt_version:
        raise typer.BadParameter("the two runs used different prompt versions")
    answers = {
        tag: {
            o.advisory_id: (set(o.vulnerable) if o.status in VALID else None) for o in run.outcomes
        }
        for tag, run in runs.items()
    }
    p = parity(answers[reference], answers[candidate], truth)
    ref_model, cand_model = runs[reference].model, runs[candidate].model

    def row(label: str, s: SetScores) -> str:
        return f"| {label} | {s.precision:.3f} | {s.recall:.3f} | {s.f1:.3f} | {s.miss_rate:.1%} |"

    def failed(names: tuple[str, ...]) -> str:
        return ", ".join(f"`{n}`" for n in names) if names else "none"

    lines = [
        f"# Parity on the Dunlap `{part}` split: `{reference}` and `{candidate}`",
        "",
        "Generated by `python -m patchsight.pipeline parity-report`; do not edit by hand. "
        "Computed offline from the two committed extraction reports.",
        "",
        f"- Reference: `{ref_model}` (`{reference}`)",
        f"- Candidate: `{cand_model}` (`{candidate}`)",
        f"- Prompt `{runs[reference].prompt_version}`; split `{frozen.split.name}:{part}` "
        f"(SHA-256 `{frozen.sha256}`), {p.reports} reports",
        "",
        "## Reliability",
        "",
        f"- Reference without a valid answer ({len(p.reference_failed)}): "
        f"{failed(p.reference_failed)}",
        f"- Candidate without a valid answer ({len(p.candidate_failed)}): "
        f"{failed(p.candidate_failed)}",
        "",
        f"## Quality on the {p.paired} reports both runs answered",
        "",
        "| Run | Precision | Recall | F1 | Miss rate |",
        "|---|---|---|---|---|",
        row(f"Reference ({ref_model})", p.reference),
        row(f"Candidate ({cand_model})", p.candidate),
        "",
        f"F1 difference, reference minus candidate: **{p.f1_difference:+.3f}** (95% CI "
        f"{p.f1_difference_ci95.low:+.3f} to {p.f1_difference_ci95.high:+.3f}; paired bootstrap "
        "over reports).",
        "",
        "## Agreement",
        "",
        f"- Identical vulnerable sets: {p.identical} of {p.paired}.",
        f"- Of the {len(p.differing)} that differ: the candidate only adds symbols in "
        f"{p.candidate_adds_only}, only drops symbols in {p.candidate_drops_only}, and does both "
        f"in {p.both_add_and_drop}.",
        f"- Differing reports: {failed(p.differing)}",
        "",
    ]
    target = reports_dir / f"parity-dunlap-{part}-{reference}-vs-{candidate}"
    target.with_name(target.name + ".md").write_text("\n".join(lines), "utf-8")
    target.with_name(target.name + ".json").write_text(p.model_dump_json(indent=2) + "\n", "utf-8")
    typer.echo("\n".join(lines[9:]))


@app.command("failure-report")
def failure_report_command(
    tag: Annotated[str, typer.Argument(help="Run tag of a committed replay bundle.")],
    part: Annotated[str, typer.Option("--split", help="Split part: dev, test or all.")] = "all",
    root: Root = Path(),
) -> None:
    """Tag every extraction error with a cause, from committed files (no network)."""
    from patchsight.eval import failures

    data = bundle.load(root / DUNLAP_BUNDLE)
    frozen = splits.load_split(root / DUNLAP_SPLIT)
    ids = frozen.split.ids(part)
    run = replay.load(root / DUNLAP_BUNDLE.parent / f"extraction-{tag}.json")
    answered = {r.id: r for r in run.reports if r.id in ids}
    truth = {r.id: set(r.symbols) for r in data.reports if r.id in ids}
    changed = {r.id: r.changed_functions() for r in data.reports if r.id in ids}
    shown = {rid: {c.name for c in r.candidates} for rid, r in answered.items()}
    status: dict[str, str] = {}
    predicted: dict[str, set[str]] = {}
    for rid, report in answered.items():
        status[rid], predicted[rid] = replay.replay_report(report, run.prompt_version)
    result = failures.breakdown(failures.as_inputs(truth, changed, shown, status, predicted))
    fn_total = sum(result.false_negatives.values())
    fp_total = sum(result.false_positives.values())
    miss_total = sum(result.report_misses.values())
    labels = {
        "dead_letter": "Extraction failed (dead letter)",
        "not_changed": "Not changed by the fix (patch ceiling)",
        "name_format": "Name format only (dotted-boundary match)",
        "truncated": "Dropped to fit the token budget",
        "model_missed": "Shown to the model, judged not vulnerable",
        "model_false_positive": "Judged vulnerable, not in the ground truth",
    }

    def share(n: int, total: int) -> str:
        return f"{n} ({n / total:.0%})" if total else "0"

    lines = [
        f"# Failure causes on the Dunlap `{part}` split: `{tag}`",
        "",
        "Generated by `python -m patchsight.pipeline failure-report`; do not edit by hand. "
        "Computed offline from the committed candidate and replay bundles.",
        "",
        f"- Model: `{run.model}`, prompt `{run.prompt_version}`",
        f"- Split `{frozen.split.name}:{part}` (SHA-256 `{frozen.sha256}`): {result.reports} "
        f"reports, {result.truth_symbols} true symbols",
        "",
        "Causes are assigned in a fixed order; see `src/patchsight/eval/failures.py`. "
        '"The fix adds a new helper" cannot be separated from this data and falls under '
        "false positives.",
        "",
        f"## Missed true symbols ({fn_total})",
        "",
        "| Cause | Symbols |",
        "|---|---|",
        *(f"| {labels[c]} | {share(n, fn_total)} |" for c, n in result.false_negatives.items()),
        "",
        f"## Reports with no true symbol found ({miss_total}): the safety metric",
        "",
        "Each is attributed to its most actionable cause.",
        "",
        "| Cause | Reports |",
        "|---|---|",
        *(f"| {labels[c]} | {share(n, miss_total)} |" for c, n in result.report_misses.items()),
        "",
        f"## False positives ({fp_total})",
        "",
        "| Cause | Symbols |",
        "|---|---|",
        *(f"| {labels[c]} | {share(n, fp_total)} |" for c, n in result.false_positives.items()),
        "",
        "## Reports by cause",
        "",
        *(
            f"- {labels.get(k.removeprefix('fp:'), k)}"
            f"{' (false positive)' if k.startswith('fp:') else ''}: "
            + ", ".join(f"`{r}`" for r in v)
            for k, v in result.examples.items()
        ),
        "",
    ]
    target = root / "docs" / "reports" / f"failures-dunlap-{part}-{tag}"
    target.with_name(target.name + ".md").write_text("\n".join(lines), "utf-8")
    target.with_name(target.name + ".json").write_text(
        result.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo("\n".join(lines[10:36]))


@app.command("reproduce")
def reproduce_command(root: Root = Path()) -> None:
    """Recompute the benchmark tables offline from committed files. No network, no API key."""
    data = bundle.load(root / DUNLAP_BUNDLE)
    frozen = splits.load_split(root / DUNLAP_SPLIT)
    lines = ["ChangedFuncs on the Dunlap Go benchmark (unit: report, function)", ""]
    lines.append(f"{'part':<6} {'reports':>7} {'cand.':>6} {'TP':>4} {'P':>6} {'R':>6} {'F1':>6}")
    results = {}
    for part in ("all", "dev", "test"):
        s = bundle.changedfuncs_scores(data, frozen.split.ids(part))
        results[part] = s
        lines.append(
            f"{part:<6} {s.reports:>7} {s.true_positives + s.false_positives:>6} "
            f"{s.true_positives:>4} {s.precision:>6.3f} {s.recall:>6.3f} {s.f1:>6.3f}"
        )
    lines += ["", "Paper (Dunlap et al., DIMVA 2024): P 0.22, R 0.90, F1 0.35 on 2,370 candidates"]
    typer.echo("\n".join(lines))

    committed = changedfuncs.BaselineReport.model_validate_json(
        (root / BASELINE_REPORT).read_text(encoding="utf-8")
    ).ours
    mine = results["all"]
    same = (mine.true_positives, mine.false_positives, mine.false_negatives) == (
        committed.true_positives, committed.false_positives, committed.false_negatives,
    )  # fmt: skip
    if not same:
        typer.echo(f"MISMATCH with {BASELINE_REPORT}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"\nMatches {BASELINE_REPORT} exactly.")

    truth = {r.id: set(r.symbols) for r in data.reports}
    for path in sorted((root / DUNLAP_BUNDLE.parent).glob("extraction-*.json")):
        tag = path.stem.removeprefix("extraction-")
        run = replay.load(path)
        typer.echo(f"\nLLM extraction, {run.model}, {run.prompt_version} (replayed offline)\n")
        typer.echo(f"{'part':<6} {'reports':>7} {'TP':>4} {'P':>6} {'R':>6} {'F1':>6}  outcomes")
        for part in ("all", "dev", "test"):
            report_path = root / "docs" / "reports" / f"extraction-dunlap-{part}-{tag}.json"
            if not report_path.exists():
                continue  # this run did not cover that part
            s, statuses = replay.replay(run, truth, frozen.split.ids(part))
            outcomes = ", ".join(f"{k} {v}" for k, v in statuses.items())
            typer.echo(
                f"{part:<6} {s.reports:>7} {s.true_positives:>4} {s.precision:>6.3f} "
                f"{s.recall:>6.3f} {s.f1:>6.3f}  {outcomes}"
            )
            published = extraction.ExtractionRun.model_validate_json(
                report_path.read_text(encoding="utf-8")
            )
            expected = (published.extraction.true_positives, published.extraction.false_positives,
                        published.extraction.false_negatives, published.status)  # fmt: skip
            if (s.true_positives, s.false_positives, s.false_negatives, statuses) != expected:
                typer.echo(f"MISMATCH with {report_path.relative_to(root)}", err=True)
                raise typer.Exit(code=1)
        typer.echo(f"\nMatches docs/reports/extraction-dunlap-*-{tag}.json exactly.")


@app.command("update-db")
def update_db_command(
    previous: Annotated[Path, typer.Argument(help="The previous database (SQLite).")],
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
    out: Annotated[Path, typer.Option(help="Output path, without extension.")] = Path(
        "data/build/patchsight-update"
    ),
    llm: Annotated[
        Path | None, typer.Option(help="Extractor outcomes for the rebuilt vulnerabilities.")
    ] = None,
    second: Annotated[Path | None, typer.Option(help="Second-opinion outcomes for them.")] = None,
) -> None:
    """Update a database from the pinned snapshot, rebuilding only changed vulnerabilities
    (needs GITHUB_TOKEN)."""
    from patchsight.pipeline import llm_records, update_db

    token = _github_token()
    manifest, dump = _load_verified(root)
    by_id, groups = _github_fix_groups(dump, None, None, 0)
    dump_entry = manifest.file(DUMP)
    version = dump_entry.retrieved_at.strftime("%Y.%m.%d")
    prior = db.SymbolDatabase(root / previous)
    prior_meta = dict(prior.meta)
    github = GitHubClient(root / cache / "github", token=token, wait_for_rate_limit=3900)
    pypi = PyPIClient(root / cache / "pypi")
    try:
        records, aliases, builds, report = update_db.update(
            prior, groups, by_id, github, pypi, version,
            progress=lambda done, total: typer.echo(f"rebuilt {done}/{total}", err=True),
        )  # fmt: skip
    except update_db.NoLedgerError as error:
        raise typer.BadParameter(str(error)) from None
    finally:
        prior.close()
        github.close()
        pypi.close()
    merged: dict[str, int] = {}
    if llm is not None:
        fresh = set(report.to_extract)
        primaries = llm_records.load(root / llm)
        secondaries = llm_records.load(root / second) if second is not None else {}
        upgraded, merged = llm_records.apply(
            [r for r in records if r.vulnerability in fresh], primaries, secondaries
        )
        records = [r for r in records if r.vulnerability not in fresh] + upgraded
    commit = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True, text=True, check=False,
    ).stdout.strip()  # fmt: skip
    meta = {
        "db_version": version,
        "built_at": datetime.now(UTC).isoformat(),
        "builder": prior_meta.get("builder", "fallback-v1") if llm is None else "llm-v1",
        "snapshot_sha256": dump_entry.sha256,
        "code_commit": commit,
        "updated_from": prior_meta.get("db_version", "?"),
    }
    target = root / out
    db.write(target.with_name(target.name + ".sqlite"), records, aliases, meta, builds=builds)
    target.with_name(target.name + "-update.json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(
        f"db {version} from {report.previous_version}: carried {report.carried}, "
        f"rebuilt {report.rebuilt}, new {report.new}, removed {report.removed}; "
        f"{len(records)} records; to extract {len(report.to_extract)}; {report.status}"
    )
    if merged:
        typer.echo(f"LLM merge: {merged}")


@app.command("merge-llm")
def merge_llm_command(
    database: Annotated[Path, typer.Argument(help="The database to merge into.")],
    version: Annotated[str, typer.Option(help="Version of the result, e.g. 2026.11.17.1.")],
    llm: Annotated[
        list[Path], typer.Option(help="Extractor outcomes (pypi-extract JSONL); repeatable.")
    ],
    second: Annotated[
        list[Path] | None, typer.Option(help="Second-opinion outcomes; repeatable.")
    ] = None,
    root: Root = Path(),
    out: Annotated[Path, typer.Option(help="Output path, without extension.")] = Path(
        "data/build/patchsight-merged"
    ),
) -> None:
    """Merge new LLM extractions into an existing database (the backfill, shard by shard)."""
    from patchsight.pipeline import llm_records, pypi_extract

    source = db.SymbolDatabase(root / database)
    try:
        records, aliases = source.all_records(), source.alias_map()
        builds, meta = list(source.build_ledger().values()), dict(source.meta)
    finally:
        source.close()
    if not builds:
        raise typer.BadParameter("the database has no builds ledger; build it with build-db")
    primaries: dict[str, pypi_extract.PyPIExtraction] = {}
    for path in llm:
        primaries.update(llm_records.load(root / path))
    secondaries: dict[str, pypi_extract.PyPIExtraction] = {}
    for path in second or []:
        secondaries.update(llm_records.load(root / path))
    merged, outcomes = llm_records.apply(records, primaries, secondaries)
    report = llm_records.merge_report(
        records, merged, primaries, secondaries, outcomes, meta.get("db_version", "?"), version
    )
    commit = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True, text=True, check=False,
    ).stdout.strip()  # fmt: skip
    meta.pop("updated_from", None)  # the source's own origin; this build is a merge
    meta.update(
        {
            "db_version": version,
            "built_at": datetime.now(UTC).isoformat(),
            "builder": "llm-v1",
            "code_commit": commit,
            "merged_into": meta.get("db_version", "?"),
            "records_by_tier": json.dumps(dict(Counter(r.confidence for r in merged))),
        }
    )
    meta.pop("schema_version", None)  # db.write sets it
    target = root / out
    db.write(target.with_name(target.name + ".sqlite"), merged, aliases, meta, builds=builds)
    target.with_name(target.name + "-merge.json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(
        f"db {version} merged into {meta['merged_into']}: {len(merged)} records; "
        f"{dict(Counter(r.confidence for r in merged))}; {outcomes}"
    )


@app.command("gate-db")
def gate_db_command(
    candidate: Annotated[Path, typer.Argument(help="The candidate database.")],
    previous: Annotated[Path, typer.Option(help="The previous release's database.")],
    root: Root = Path(),
    out: Annotated[Path, typer.Option(help="Report path, without extension.")] = Path(
        "data/build/gate"
    ),
) -> None:
    """Run the release gate on a candidate database; exit 1 if any check fails."""
    from patchsight.pipeline import gate

    new, old = db.SymbolDatabase(root / candidate), db.SymbolDatabase(root / previous)
    try:
        report = gate.run(new, old)
    finally:
        new.close()
        old.close()
    target = root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    markdown = gate.render_markdown(report)
    target.with_name(target.name + ".md").write_text(markdown, "utf-8")
    target.with_name(target.name + ".json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(markdown)
    if not report.passed:
        raise typer.Exit(code=1)


ATTRIBUTION = """## Attribution and licence

Advisory identifiers and affected-package data come from [OSV.dev](https://osv.dev), which \
aggregates the [GitHub Advisory Database](https://github.com/github/advisory-database) and the \
[PyPA Advisory Database](https://github.com/pypa/advisory-database). All three are licensed \
CC BY 4.0.

**Changes made:** PatchSight resolved each advisory's fix commit on GitHub, mapped the changed \
lines to function names with tree-sitter, and, where shown, had language models choose the \
vulnerable ones. It stores those names with file paths, line ranges and commit SHAs. No \
third-party source code is included.
"""


@app.command("release-notes")
def release_notes_command(
    database: Annotated[Path, typer.Argument(help="The database being released.")],
    pointer: Annotated[Path, typer.Option(help="Its pointer (package-db output).")] = Path(
        "releases/latest.json"
    ),
    update: Annotated[Path | None, typer.Option(help="The update-db report, if any.")] = None,
    merge: Annotated[Path | None, typer.Option(help="The merge-llm report, if any.")] = None,
    gate: Annotated[Path | None, typer.Option(help="The gate-db report, if any.")] = None,
    root: Root = Path(),
    out: Annotated[Path, typer.Option(help="Notes file to write.")] = Path(
        "data/build/release-notes.md"
    ),
) -> None:
    """Write release notes for a database release, with provenance and attribution."""
    from patchsight.pipeline.gate import GateReport
    from patchsight.pipeline.llm_records import MergeReport
    from patchsight.pipeline.update_db import UpdateReport

    opened = db.SymbolDatabase(root / database)
    try:
        meta, tiers, total = dict(opened.meta), opened.confidence_counts(), opened.record_count()
        vulnerabilities = len(opened.vulnerabilities())
    finally:
        opened.close()
    published = dbcache.Pointer.model_validate_json((root / pointer).read_text("utf-8"))
    version = meta.get("db_version", "?")
    origin = (
        f", updated from {meta['updated_from']}"
        if "updated_from" in meta
        else f", {meta['merged_into']} with new model picks"
        if "merged_into" in meta
        else ""
    )
    lines = [
        f"Symbol database **{version}**{origin}.",
        "",
        "```bash",
        "patchsight db update   # downloads this release and verifies its SHA-256",
        "```",
        "",
    ]
    if merge is not None:
        merged = MergeReport.model_validate_json((root / merge).read_text("utf-8"))
        second = (
            "; second opinion " + ", ".join(f"`{m}`" for m in merged.second_opinion_models)
            if merged.second_opinion_models
            else ""
        )
        lines += [
            f"## Changes since {merged.previous_version}",
            "",
            "- Merges model picks from "
            + ", ".join(f"`{m}`" for m in merged.models)
            + " (prompt "
            + ", ".join(f"`{p}`" for p in merged.prompt_versions)
            + f"){second}.",
            f"- {merged.after.vulnerabilities:,} vulnerabilities ({merged.after.records:,} "
            "records) now carry model picks with a rationale and cited hunks, up from "
            f"{merged.before.vulnerabilities:,} ({merged.before.records:,} records).",
            "- No record is high confidence yet, so matching still uses every changed "
            "definition. `patchsight explain <id>` shows the picks."
            if not merged.tiers.get("high")
            else f"- {merged.tiers['high']:,} "
            + ("record is" if merged.tiers["high"] == 1 else "records are")
            + " high confidence. `patchsight explain <id>` shows the picks and why each tier "
            "was chosen.",
            "",
        ]
    lines += [
        "## Contents",
        "",
        f"- **{vulnerabilities:,} PyPI vulnerabilities**, {total:,} records: "
        + ", ".join(f"{n:,} {tier} confidence" for tier, n in sorted(tiers.items())),
        "- Low-confidence records list every definition the fix changed; they can mark an "
        "alert CALLED, never IMPORTED, NOT CALLED.",
    ]
    if update is not None:
        report = UpdateReport.model_validate_json((root / update).read_text("utf-8"))
        lines += [
            f"- **Changes since {report.previous_version}:** {report.carried:,} carried "
            f"unchanged, {report.rebuilt} rebuilt, {report.new} new, {report.removed} removed"
            + (f"; {report.aliases_added} aliases added" if report.aliases_added else "")
            + (f", {report.aliases_removed} removed" if report.aliases_removed else ""),
        ]
    if gate is not None:
        result = GateReport.model_validate_json((root / gate).read_text("utf-8"))
        lines += [
            "",
            f"## Release gate: {'passed' if result.passed else 'FAILED'}",
            "",
            *(f"- `{c.name}`: {c.detail}" for c in result.checks),
        ]
    lines += [
        "",
        "## Provenance",
        "",
        f"- OSV PyPI dump SHA-256: `{meta.get('snapshot_sha256', '?')}`",
        f"- Built by PatchSight commit `{meta.get('code_commit', '?')}` "
        f"(builder `{meta.get('builder', '?')}`, schema version {meta.get('schema_version', '?')})",
        f"- Asset SHA-256: `{published.sha256}`",
        "",
        ATTRIBUTION,
    ]
    target = root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines), "utf-8")
    typer.echo(f"wrote {target}")


@app.command("pypi-extract")
def pypi_extract_command(
    root: Root = Path(),
    role: Annotated[str, typer.Option(help="Model role in the LLM config.")] = "extractor",
    ids: Annotated[str | None, typer.Option(help="Comma-separated advisory IDs.")] = None,
    sample: Annotated[int | None, typer.Option(help="Seeded sample of N vulnerabilities.")] = None,
    seed: Annotated[int, typer.Option(help="Sample seed.")] = 20261114,
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    cache: Annotated[Path, typer.Option(help="Cache root (HTTP and LLM).")] = Path(".cache"),
    out: Annotated[Path, typer.Option(help="Output path prefix; the role is appended.")] = Path(
        "data/interim/pypi-extract"
    ),
    plan: Annotated[
        bool, typer.Option("--plan", help="Only measure prompt sizes; no model calls.")
    ] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="Use only cached GitHub and PyPI responses.")
    ] = False,
    shard: Annotated[str | None, typer.Option(help="Run one shard, as K/N (e.g. 2/4).")] = None,
    max_minutes: Annotated[
        float | None, typer.Option(help="Start no new vulnerability after this many minutes.")
    ] = None,
    eligible_from: Annotated[
        Path | None,
        typer.Option(help="Extractor outcomes: run only where a second opinion can help."),
    ] = None,
    priority: Annotated[
        bool,
        typer.Option(
            "--priority", help="Most-downloaded packages first (needs fetch-top-packages)."
        ),
    ] = False,
    cache_only: Annotated[
        bool,
        typer.Option(
            "--cache-only", help="Answer only from the response cache; never call a model."
        ),
    ] = False,
) -> None:
    """Run LLM extraction on PyPI vulnerabilities (needs the model's key, and GITHUB_TOKEN
    unless --offline)."""
    from patchsight.pipeline import pypi_extract

    started = time.monotonic()
    token = None if offline else _github_token()
    _, dump = _load_verified(root)
    by_id, groups = _github_fix_groups(dump, ids, sample, seed)
    suffix = ""
    if eligible_from is not None:
        from patchsight.pipeline import llm_records

        primaries = llm_records.load(root / eligible_from)
        eligible = {k for k, e in primaries.items() if llm_records.needs_second_opinion(e)}
        groups = [g for g in groups if g.key in eligible]
        typer.echo(f"{len(groups)} of {len(primaries)} extractions can use a second opinion")
    if priority:
        top = snapshot.verify(snapshot.load_manifest(root / MANIFEST).file(TOP_PACKAGES), root)
        groups = pypi_extract.by_priority(groups, by_id, pypi_extract.download_rank(top))
    if shard is not None:
        k, _, n = shard.partition("/")
        if not (k.isdigit() and n.isdigit()):
            raise typer.BadParameter(f"--shard must look like 2/4, not {shard!r}")
        groups = [g for g in groups if pypi_extract.in_shard(g.key, int(k), int(n))]
        suffix = f"-shard{k}of{n}"
    llm_config = load_config(root / config)
    template = load_template(root / prompt)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    github = GitHubClient(
        root / cache / "http" / "github", token=token, wait_for_rate_limit=3900, offline=offline
    )
    pypi = PyPIClient(root / cache / "http" / "pypi", offline=offline)
    if plan:
        try:
            plans = [
                pypi_extract.plan_vulnerability(
                    g, by_id, github, pypi, llm_config, role, template, counter
                )
                for g in sorted(groups, key=lambda g: g.key)
            ]
        finally:
            github.close()
            pypi.close()
        target = root / out
        target.parent.mkdir(parents=True, exist_ok=True)
        target.with_name(f"{target.name}-{role}-plan.jsonl").write_text(
            "".join(p.model_dump_json() + "\n" for p in plans if not isinstance(p, str)), "utf-8"
        )
        sized = [p for p in plans if not isinstance(p, str)]
        typer.echo(
            f"{len(sized)} prompts; truncated under the {role} budget: "
            f"{sum(p.truncated for p in sized)}"
        )
        return
    make_client = cache_only_client if cache_only else client_for
    llm, model_id = make_client(llm_config, role, root / cache / "llm", counter)
    try:
        results, summary = pypi_extract.run(
            groups, by_id, github, pypi, llm, llm_config, role, template, counter,
            progress=lambda done, total: typer.echo(f"extracted {done}/{total}", err=True),
            deadline=None if max_minutes is None else started + 60 * max_minutes,
            keep_order=priority,
        )  # fmt: skip
    except (QuotaExhaustedError, RateLimitedError) as stopped:
        typer.echo(f"stopped: {stopped}", err=True)
        typer.echo(
            "Every answer so far is cached. Re-run the same command later to resume.", err=True
        )
        raise typer.Exit(code=2) from None
    finally:
        github.close()
        pypi.close()
    target = root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    stem = f"{target.name}-{role}{suffix}"
    target.with_name(stem + ".jsonl").write_text(
        "".join(r.model_dump_json() + "\n" for r in results), "utf-8"
    )
    target.with_name(stem + "-summary.json").write_text(
        summary.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(
        f"{model_id}: {len(results)} of {summary.vulnerabilities} vulnerabilities extracted"
        f"{'' if summary.complete else f' (time budget reached after {summary.processed})'}; "
        f"status {summary.status}; skipped {summary.skipped}; truncated {summary.truncated}; "
        f"{llm.network_calls} model calls"
    )


@app.command("export-kaggle-inputs")
def export_kaggle_inputs_command(
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="Cache root.")] = Path(".cache"),
    out: Annotated[Path, typer.Option(help="Bundle to write.")] = Path(
        "data/build/patchsight-pypi-inputs.zip"
    ),
) -> None:
    """Bundle what the PyPI backfill reads, for an offline Kaggle run.

    The bundle holds the pinned OSV dump and the cached GitHub and PyPI responses that
    pypi-extract reads. Those responses include third-party source code: upload the bundle
    only as a PRIVATE Kaggle dataset, never publicly (rule 13).
    """
    from patchsight.pipeline import kaggle_inputs

    manifest, dump = _load_verified(root)
    by_id, groups = _github_fix_groups(dump, None, None, 0)
    github = GitHubClient(root / cache / "http" / "github", offline=True)
    pypi = PyPIClient(root / cache / "http" / "pypi", offline=True)
    try:
        statuses = kaggle_inputs.walk(groups, by_id, github, pypi)
    finally:
        github.close()
        pypi.close()
    if statuses.get("cache_miss"):
        raise typer.BadParameter(
            f"{statuses['cache_miss']} vulnerabilities miss cached responses; run build-db first"
        )
    used = github.http.cache_files_used | pypi.http.cache_files_used
    entry = manifest.file(DUMP)
    info = kaggle_inputs.write_bundle(
        root / out, dump, entry.sha256, used, root / cache / "http", statuses
    )
    typer.echo(
        f"{root / out}: {info.files:,} cached responses, "
        f"{(root / out).stat().st_size / 1e6:.0f} MB, "
        f"sha256 {kaggle_inputs.sha256_file(root / out)}; vulnerabilities {statuses}"
    )
    typer.echo("Upload it as a PRIVATE Kaggle dataset: it contains third-party source code.")


@app.command("restore-kaggle-inputs")
def restore_kaggle_inputs_command(
    source: Annotated[Path, typer.Argument(help="The bundle zip, or its extracted directory.")],
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="Cache root.")] = Path(".cache"),
) -> None:
    """Restore an export-kaggle-inputs bundle (on Kaggle), then verify the OSV dump."""
    from patchsight.pipeline import kaggle_inputs

    entry = snapshot.load_manifest(root / MANIFEST).file(DUMP)
    try:
        info = kaggle_inputs.restore(source, root, entry.path, root / cache)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None
    if info.dump_sha256 != entry.sha256:
        raise typer.BadParameter("the bundle was made from a different OSV snapshot")
    _load_verified(root)  # raises unless the restored dump matches the pinned SHA-256
    typer.echo(f"restored {info.files:,} cached responses and the OSV dump (SHA-256 verified)")


@app.command("package-db")
def package_db_command(
    database: Annotated[Path, typer.Argument(help="A database built by build-db.")],
    root: Root = Path(),
    repo: Annotated[str, typer.Option(help="GitHub repository the release lives in.")] = (
        "professor3333/PatchSight"
    ),
    pointer: Annotated[Path, typer.Option(help="Pointer file to write.")] = Path(
        "releases/latest.json"
    ),
) -> None:
    """Compress a database for release and write the pointer the CLI downloads it by."""
    import gzip
    import shutil

    opened = db.SymbolDatabase(database)
    meta = dict(opened.meta)
    records = opened.record_count()
    opened.close()
    version = meta["db_version"]
    tag = f"db-{version}"
    asset = root / "data" / "build" / "release" / f"patchsight-db-{version}.sqlite.gz"
    asset.parent.mkdir(parents=True, exist_ok=True)
    # mtime=0 keeps the archive byte-identical for the same database, so its hash is stable.
    with (
        database.open("rb") as source,
        asset.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as sink,
    ):
        shutil.copyfileobj(source, sink)
    record = {
        "db_version": version,
        "schema_version": int(meta["schema_version"]),
        "url": f"https://github.com/{repo}/releases/download/{tag}/{asset.name}",
        "sha256": snapshot.sha256_file(asset),
        "size": asset.stat().st_size,
        "built_at": meta["built_at"],
        "records": records,
    }
    (root / pointer).parent.mkdir(parents=True, exist_ok=True)
    (root / pointer).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    typer.echo(f"{asset.relative_to(root)}: {record['size']:,} bytes, sha256 {record['sha256']}")
    # --latest=false keeps the CLI release as the repository's "Latest" release.
    typer.echo(
        f"wrote {pointer}; publish with: "
        f"gh release create {tag} {asset.relative_to(root)} --latest=false"
    )


if __name__ == "__main__":
    app()
