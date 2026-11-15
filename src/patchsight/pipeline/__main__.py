"""Offline pipeline commands: ``python -m patchsight.pipeline <command>``."""

import json
import os
import subprocess
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import httpx
import typer

from patchsight import db
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
from patchsight.pipeline.ingest.aliases import alias_groups
from patchsight.pipeline.ingest.osv import Advisory, Excluded, Quarantined, normalise_dump
from patchsight.pipeline.llm.client import QuotaExhaustedError, RateLimitedError, client_for
from patchsight.pipeline.llm.config import load_config
from patchsight.pipeline.llm.tokens import HfTokenizer
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


KAGGLE_RUN_PREFIXES = (".cache/llm/", "docs/reports/", "run-info.json", "llama-server.log")


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
) -> None:
    """Build a symbol database of fallback records (needs GITHUB_TOKEN)."""
    token = _github_token()
    manifest, dump = _load_verified(root)
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
    dump_entry = manifest.file(DUMP)
    version = dump_entry.retrieved_at.strftime("%Y.%m.%d")
    github = GitHubClient(root / cache / "github", token=token)
    pypi = PyPIClient(root / cache / "pypi")
    try:
        records, aliases, report = build_db.build(groups, by_id, github, pypi, version)
    finally:
        github.close()
        pypi.close()
    commit = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True, text=True, check=False,
    ).stdout.strip()  # fmt: skip
    meta = {
        "db_version": version,
        "built_at": datetime.now(UTC).isoformat(),
        "builder": "fallback-v1",
        "snapshot_sha256": dump_entry.sha256,
        "code_commit": commit,
    }
    target = root / out
    db.write(target.with_name(target.name + ".sqlite"), records, aliases, meta)
    target.with_name(target.name + ".jsonl").write_text(build_db.jsonl(records), "utf-8")
    target.with_name(target.name + "-build.json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(
        f"db {version}: {report.records} records, {report.symbols} symbols from "
        f"{report.groups} vulnerabilities; {report.status}"
    )


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
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    cache: Annotated[Path, typer.Option(help="Cache root.")] = Path(".cache"),
) -> None:
    """Write a replay bundle from the response cache only (never calls a model)."""
    token = _github_token()
    manifest = snapshot.load_manifest(root / MANIFEST)
    reports = dunlap.load(snapshot.verify(manifest.file(DUNLAP_DATA), root))
    advisories = extraction.load_advisories(snapshot.verify(manifest.file(DUNLAP_ADVISORIES), root))
    llm_config = load_config(root / config)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    github = GitHubClient(root / cache / "http" / "github", token=token)
    try:
        exported = replay.export(
            github, root / cache / "llm", llm_config, role, load_template(root / prompt), counter,
            reports, advisories,
        )  # fmt: skip
    finally:
        github.close()
    target = root / DUNLAP_BUNDLE.parent / f"extraction-{tag}.json"
    replay.save(exported, target)
    answers = sum(len(r.answers) for r in exported.reports)
    typer.echo(f"{target.relative_to(root)}: {len(exported.reports)} reports, {answers} answers")


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
            s, statuses = replay.replay(run, truth, frozen.split.ids(part))
            outcomes = ", ".join(f"{k} {v}" for k, v in statuses.items())
            typer.echo(
                f"{part:<6} {s.reports:>7} {s.true_positives:>4} {s.precision:>6.3f} "
                f"{s.recall:>6.3f} {s.f1:>6.3f}  {outcomes}"
            )
            report_path = root / "docs" / "reports" / f"extraction-dunlap-{part}-{tag}.json"
            published = extraction.ExtractionRun.model_validate_json(
                report_path.read_text(encoding="utf-8")
            )
            expected = (published.extraction.true_positives, published.extraction.false_positives,
                        published.extraction.false_negatives, published.status)  # fmt: skip
            if (s.true_positives, s.false_positives, s.false_negatives, statuses) != expected:
                typer.echo(f"MISMATCH with {report_path.relative_to(root)}", err=True)
                raise typer.Exit(code=1)
        typer.echo(f"\nMatches docs/reports/extraction-dunlap-*-{tag}.json exactly.")


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
    typer.echo(f"wrote {pointer}; publish with: gh release create {tag} {asset.relative_to(root)}")


if __name__ == "__main__":
    app()
