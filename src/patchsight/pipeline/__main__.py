"""Offline pipeline commands: ``python -m patchsight.pipeline <command>``."""

import contextlib
import json
import os
import subprocess
import tarfile
import time
import tomllib
import zipfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Any, NamedTuple

import httpx
import typer

from patchsight import db
from patchsight.eval.metrics import SetScores, score
from patchsight.pipeline import build_db, fix_sample, week1
from patchsight.pipeline.attribution import ATTRIBUTION
from patchsight.pipeline.benchmarks import (
    bundle,
    changedfuncs,
    dunlap,
    extraction,
    replay,
    splits,
)
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.extract.prompt import AdvisoryText, load_template
from patchsight.pipeline.ingest import ghsa_repo, snapshot
from patchsight.pipeline.ingest.aliases import AliasGroup, alias_groups
from patchsight.pipeline.ingest.osv import Advisory, Excluded, Quarantined, normalise_dump
from patchsight.pipeline.llm.client import (
    LLMClient,
    QuotaExhaustedError,
    RateLimitedError,
    cache_only_client,
    client_for,
)
from patchsight.pipeline.llm.config import load_config
from patchsight.pipeline.llm.tokens import HfTokenizer
from patchsight.pipeline.pypi import PyPIClient
from patchsight.pipeline.trace import TRACE_DIR, Tracer, code_commit, trace_path
from patchsight.scan import dbcache

app = typer.Typer(name="patchsight-pipeline", no_args_is_help=True, add_completion=False)

Root = Annotated[Path, typer.Option(help="Repository root.")]


@contextmanager
def _run_trace(
    root: Path, name: str, command: str, llm: LLMClient, **fields: object
) -> Iterator[dict[str, object]]:
    """Trace one model run to ``data/interim/traces/<name>-<start>.jsonl``: ``run_start``,
    then the client's calls, then ``run_end``. The caller adds end fields to the dict it gets.
    A quota stop or a crash is recorded before the exception goes on."""
    tracer = Tracer(trace_path(root, name))
    llm.tracer = tracer
    started = time.monotonic()
    tracer.emit("run_start", command=command, code_commit=code_commit(root), **fields)
    end: dict[str, object] = {}

    def finish(outcome: str, **extra: object) -> None:
        tracer.emit(
            "run_end", outcome=outcome, seconds=round(time.monotonic() - started, 1),
            network_calls=llm.network_calls, **extra,
        )  # fmt: skip

    try:
        yield end
    except (QuotaExhaustedError, RateLimitedError) as stopped:
        finish("stopped", reason=type(stopped).__name__)
        raise
    except BaseException as error:
        finish("crashed", reason=type(error).__name__)
        raise
    finish(str(end.pop("outcome", "complete")), **end)


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


class _Benchmark(NamedTuple):
    """A benchmark's reports and advisory text, narrowed to one part, with its provenance."""

    reports: list[dunlap.DunlapReport]
    advisories: dict[str, AdvisoryText]
    ids: frozenset[str] | None
    split: str
    split_sha256: str | None
    as_of: date
    source: str  # the report line naming the data
    bundle_dir: Path  # where its replay bundles live
    replay_name: str  # the benchmark name a replay bundle records


def _load_benchmark(root: Path, name: str, part: str) -> _Benchmark:
    """``dunlap-v1`` (one split part) or ``go-holdout-v1`` (always all of it)."""
    import hashlib

    from patchsight.pipeline.benchmarks import go_holdout

    if name == go_holdout.NAME:
        frozen_file = root / go_holdout.FROZEN
        holdout = go_holdout.load(frozen_file)
        reports, advisories = go_holdout.as_benchmark(holdout)
        digest = hashlib.sha256(frozen_file.read_bytes()).hexdigest()
        return _Benchmark(
            reports, advisories, None, f"{go_holdout.NAME}:all", digest,
            datetime.fromisoformat(holdout.retrieved_at).date(),
            f"- Benchmark: `{go_holdout.FROZEN.as_posix()}` SHA-256 `{digest}`",
            go_holdout.FROZEN.parent, go_holdout.NAME,
        )  # fmt: skip
    if name != "dunlap-v1":
        raise typer.BadParameter(f"unknown benchmark {name!r}")
    manifest = snapshot.load_manifest(root / MANIFEST)
    data = manifest.file(DUNLAP_DATA)
    frozen = splits.load_split(root / DUNLAP_SPLIT)
    return _Benchmark(
        dunlap.load(snapshot.verify(data, root)),
        extraction.load_advisories(snapshot.verify(manifest.file(DUNLAP_ADVISORIES), root)),
        frozen.split.ids(part), f"{frozen.split.name}:{part}", frozen.sha256,
        data.retrieved_at.date(),
        f"- Benchmark: `{DUNLAP_DATA}` SHA-256 `{data.sha256}` (see `manifests/snapshot.json`)",
        DUNLAP_BUNDLE.parent, "dunlap-dimva24",
    )  # fmt: skip


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
    benchmark: Annotated[
        str, typer.Option(help="dunlap-v1, or go-holdout-v1 (the temporal holdout, all reports).")
    ] = "dunlap-v1",
    topup: Annotated[
        Path | None,
        typer.Option(help="A topup-plan file: extract only the Dunlap prompts it lists."),
    ] = None,
) -> None:
    """Run LLM extraction on the Dunlap benchmark or the Go temporal holdout (needs
    GITHUB_TOKEN and the model's key)."""
    token = _github_token()
    chosen = _load_benchmark(root, benchmark, split)
    if topup is not None:
        from patchsight.pipeline import topup as topups

        if benchmark != "dunlap-v1":
            raise typer.BadParameter("--topup lists Dunlap prompts; use it with dunlap-v1")
        listed = topups.Plan.model_validate_json((root / topup).read_text("utf-8"))
        wanted = frozenset(listed.part("dunlap-v1").ids())
        chosen = chosen._replace(ids=wanted if chosen.ids is None else chosen.ids & wanted)
        typer.echo(f"top-up: {len(chosen.ids or ())} of the plan's {len(wanted)} prompts")
    llm_config = load_config(root / config)
    template = load_template(root / prompt)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    llm, model_id = client_for(llm_config, role, root / cache / "llm", counter)
    github = GitHubClient(root / cache / "http" / "github", token=token)
    try:
        with _run_trace(
            root, f"dunlap-extract-{benchmark}-{split}-{role}", "dunlap-extract", llm,
            role=role, model=model_id, prompt_version=template.version, benchmark=benchmark,
            split=chosen.split, sample=sample, reports=len(chosen.reports),
        ) as end:  # fmt: skip
            result = extraction.run(
                github, llm, llm_config, role, template, counter, chosen.reports,
                chosen.advisories, as_of=chosen.as_of, sample_size=sample, seed=seed,
                ids=chosen.ids, split=chosen.split, split_sha256=chosen.split_sha256,
                progress=lambda done, total: typer.echo(f"extracted {done}/{total}", err=True),
            )  # fmt: skip
            end.update(reports=result.reports, status=result.status)
    except (QuotaExhaustedError, RateLimitedError) as stopped:
        typer.echo(f"stopped: {stopped}", err=True)
        typer.echo(
            "Every answer so far is cached. Re-run the same command later to resume.", err=True
        )
        raise typer.Exit(code=2) from None
    finally:
        github.close()
    lines = [
        chosen.source,
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


@app.command("eval-sets")
def eval_sets_command(
    root: Root = Path(),
    repin: Annotated[
        list[str] | None,
        typer.Option(help="Pin this set to its current contents (deliberate; say why)."),
    ] = None,
) -> None:
    """Check every frozen evaluation set against its SHA-256 in manifests/eval-sets.json
    (ADR 0014). Exits 1 if any set changed. CI runs it on every push."""
    from patchsight.pipeline.benchmarks import frozen

    manifest = frozen.load(root / frozen.MANIFEST)
    if repin:
        try:
            manifest = frozen.repin(root, manifest, repin)
        except KeyError as error:
            raise typer.BadParameter(str(error.args[0])) from None
        frozen.write(root / frozen.MANIFEST, manifest)
        typer.echo(f"re-pinned {', '.join(repin)} in {frozen.MANIFEST}")
    problems = frozen.check(root, manifest)
    for problem in problems:
        typer.echo(f"changed: {problem}", err=True)
    if problems:
        raise typer.Exit(code=1)
    typer.echo(f"{len(manifest.sets)} evaluation sets match their pins in {frozen.MANIFEST}")


# Each benchmark's retrieval bundle, its report, and the run whose truncation it must match.
RETRIEVAL = {
    "dunlap-v1": (
        Path("benchmarks/dunlap-v1/retrieval.json"),
        Path("docs/reports/retrieval-dunlap-v1"),
        Path("docs/reports/extraction-dunlap-all-extract-v1-qwen3.8-27b-q4km.json"),
    ),
    "go-holdout-v1": (
        Path("benchmarks/go-holdout-v1/retrieval.json"),
        Path("docs/reports/retrieval-go-holdout-v1"),
        Path("docs/reports/extraction-go-holdout-v1-extract-v1-gpt-oss-120b.json"),
    ),
}


def _retrieval_paths(benchmark: str) -> tuple[Path, Path, Path]:
    if benchmark not in RETRIEVAL:
        raise typer.BadParameter(f"--benchmark must be one of {', '.join(RETRIEVAL)}")
    return RETRIEVAL[benchmark]


@app.command("topup-plan")
def topup_plan_command(
    after: Annotated[Path, typer.Option(help="The configuration being switched on.")],
    before: Annotated[Path, typer.Option(help="The configuration in use.")] = Path(
        "configs/llm.toml"
    ),
    role: Annotated[str, typer.Option(help="Model role the top-up run uses.")] = (
        "kaggle_extractor"
    ),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    cache: Annotated[Path, typer.Option(help="Cache root (HTTP and tokenizer).")] = Path(".cache"),
    out: Annotated[Path, typer.Option(help="Plan to write.")] = Path(
        "configs/experiments/llm-switch-on-topup.json"
    ),
    root: Root = Path(),
) -> None:
    """List the prompts a configuration change alters, on the PyPI backfill and the Dunlap
    benchmark, offline from the HTTP cache: a top-up run re-extracts only these, and every
    other prompt replays from the cache. IDs and counts only, no prompt text."""
    import hashlib

    from patchsight.pipeline import pypi_extract, topup
    from patchsight.pipeline.diffs.commits import map_commit
    from patchsight.pipeline.extract.prompt import render

    configs = [load_config(root / before), load_config(root / after)]
    template = load_template(root / prompt)
    counter = HfTokenizer(configs[0].tokenizer, root / cache / "tokenizer")
    github = GitHubClient(root / cache / "http" / "github", offline=True)
    pypi = PyPIClient(root / cache / "http" / "pypi", offline=True)
    parts = []
    try:
        _, dump = _load_verified(root)
        by_id, groups = _github_fix_groups(dump, None, None, 0)
        skipped, changes, considered = [], [], 0
        for group in sorted(groups, key=lambda g: g.key):
            prompts = pypi_extract.rendered_prompts(
                group, by_id, github, pypi, configs, role, template, counter
            )
            if isinstance(prompts, str):
                skipped.append(prompts)
                continue
            considered += 1
            changes.append(topup.compare(group.key, *prompts))
        parts.append(topup.part("pypi", considered, skipped, changes))
        chosen = _load_benchmark(root, "dunlap-v1", "all")
        dunlap_changes = []
        for report in sorted(chosen.reports, key=lambda r: r.id):
            mappings = [
                map_commit(github, c.github_repo, c.sha, include=dunlap.paper_path_filter)
                for c in report.commits
            ]
            inputs, _ = extraction.candidate_inputs(mappings)
            rendered = [
                render(
                    template,
                    chosen.advisories[report.id],
                    inputs,
                    c.prompt_budget(role),
                    counter,
                    c.budget.max_hunk_lines,
                    c.candidate_limit(role),
                    c.budget.candidate_order,
                )
                for c in configs
            ]
            dunlap_changes.append(topup.compare(report.id, *rendered))
        parts.append(topup.part("dunlap-v1", len(chosen.reports), (), dunlap_changes))
    finally:
        github.close()
        pypi.close()

    def digest(path: Path) -> str:
        return hashlib.sha256((root / path).read_bytes()).hexdigest()

    plan = topup.Plan(
        role=role, prompt_version=template.version, before=before.as_posix(),
        before_sha256=digest(before), after=after.as_posix(), after_sha256=digest(after),
        parts=tuple(parts),
    )  # fmt: skip
    (root / out).write_text(plan.model_dump_json(indent=1) + "\n", "utf-8")
    for p in plan.parts:
        typer.echo(
            f"{p.benchmark}: {len(p.changed)} of {p.considered} prompts change; {p.reasons()}"
        )


@app.command("retrieval-freeze")
def retrieval_freeze_command(
    root: Root = Path(),
    benchmark: Annotated[str, typer.Option(help="dunlap-v1 or go-holdout-v1.")] = "dunlap-v1",
    role: Annotated[str, typer.Option(help="Model role whose budget is measured.")] = (
        "kaggle_extractor"
    ),
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    cache: Annotated[Path, typer.Option(help="Cache root (HTTP and tokenizer).")] = Path(".cache"),
    against: Annotated[
        Path | None,
        typer.Option(help="An extraction report whose truncation the bundle must reproduce."),
    ] = None,
) -> None:
    """Freeze a benchmark's retrieval bundle, offline from the HTTP cache: each candidate's
    name, path, token cost, label, BM25 score and whether the advisory names it, the BM25
    order and the prompt's fixed cost. No code and no advisory text are stored. Nothing is
    written unless it reproduces the truncation of a recorded run on every report."""
    from patchsight.pipeline.benchmarks import retrieval
    from patchsight.pipeline.diffs.commits import map_commit
    from patchsight.pipeline.extract.prompt import budget_plan, fit

    out, _, recorded_run = _retrieval_paths(benchmark)
    against = against or recorded_run
    chosen = _load_benchmark(root, benchmark, "all")
    dev: frozenset[str] = frozenset()
    if benchmark == "dunlap-v1":
        dev = splits.load_split(root / DUNLAP_SPLIT).split.ids("dev")
    llm_config = load_config(root / config)
    template = load_template(root / prompt)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    budget, cap = llm_config.prompt_budget(role), llm_config.candidate_limit(role)
    lines = llm_config.budget.max_hunk_lines
    github = GitHubClient(root / cache / "http" / "github", offline=True)
    cases = []
    try:
        for report in sorted(chosen.reports, key=lambda r: r.id):
            if chosen.ids is not None and report.id not in chosen.ids:
                continue
            mappings = [
                map_commit(github, c.github_repo, c.sha, include=dunlap.paper_path_filter)
                for c in report.commits
            ]
            inputs, _ = extraction.candidate_inputs(mappings)
            advisory = chosen.advisories[report.id]
            plan = budget_plan(template, advisory, inputs, counter, lines)
            text = f"{advisory.summary}\n{advisory.details}"
            truth = set(report.symbols)
            split = "holdout" if benchmark != "dunlap-v1" else "dev" if report.id in dev else "test"
            items = tuple(
                retrieval.Item(
                    name=i.name, path=i.path, tokens=cost, vulnerable=i.name in truth,
                    bm25_score=score, named=retrieval.named_in(i.name, text),
                )
                for i, cost, score in zip(inputs, plan.costs, plan.scores, strict=True)
            )  # fmt: skip
            cases.append(
                retrieval.Case(
                    report=report.id,
                    split=split,
                    base_tokens=plan.base_tokens,
                    bm25=plan.order,
                    items=items,
                )
            )
    finally:
        github.close()
    bundle = retrieval.Bundle(
        benchmark=benchmark, split_sha256=chosen.split_sha256 or "",
        prompt_version=template.version,
        tokenizer=f"{llm_config.tokenizer.repo}@{llm_config.tokenizer.revision}",
        budget_tokens=budget, max_candidates=cap, cases=tuple(cases),
    )  # fmt: skip
    run = extraction.ExtractionRun.model_validate_json((root / against).read_text("utf-8"))
    by_id = {o.advisory_id: o for o in run.outcomes}
    for case in bundle.cases:
        kept = fit(case.bm25, [i.tokens for i in case.items], case.base_tokens, budget, cap)
        dropped = tuple(case.items[i].name for i in range(len(case.items)) if i not in kept)
        outcome = by_id[case.report]
        if dropped != tuple(outcome.dropped_candidates):
            raise typer.BadParameter(
                f"{case.report}: the bundle drops {dropped}, the run dropped "
                f"{outcome.dropped_candidates}; nothing written"
            )
    typer.echo(f"truncation matches {against} for all {len(bundle.cases)} reports")
    (root / out).write_text(bundle.model_dump_json(indent=1) + "\n", "utf-8")
    typer.echo(f"{out}: {len(bundle.cases)} reports, {len(bundle.truncated())} cut at {budget}")


@app.command("retrieval-report")
def retrieval_report_command(
    root: Root = Path(),
    benchmark: Annotated[str, typer.Option(help="dunlap-v1 or go-holdout-v1.")] = "dunlap-v1",
) -> None:
    """Score retrieval at the prompt budget from a frozen bundle: BM25, file order, E10's
    candidate orders and the oracle ceiling, on the reports whose prompts are cut. Offline,
    no model call."""
    import hashlib

    from patchsight.pipeline.benchmarks import retrieval

    bundle, out, _ = _retrieval_paths(benchmark)
    raw = (root / bundle).read_bytes()
    report = retrieval.score(retrieval.Bundle.model_validate_json(raw))
    source = f"Bundle: `{bundle.as_posix()}` SHA-256 `{hashlib.sha256(raw).hexdigest()}`"
    target = root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_name(target.name + ".json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    target.with_name(target.name + ".md").write_text(
        retrieval.render_markdown(report, source), "utf-8"
    )
    for split in report.splits:
        recalls = ", ".join(f"{g.ranking} {g.recall:.3f}" for g in split.rankings)
        typer.echo(f"{split.split}: {split.truncated}/{split.reports} cut; recall {recalls}")


@app.command("holdout-freeze")
def holdout_freeze_command(
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
) -> None:
    """Download GoVulnDB and freeze the Go temporal holdout (needs GITHUB_TOKEN)."""
    import hashlib

    from patchsight.pipeline.benchmarks import go_holdout

    archive = root / RAW / "go-vulndb" / "vulndb.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=True) as http:
        response = http.get(go_holdout.VULNDB_URL)
        response.raise_for_status()
    archive.write_bytes(response.content)
    digest = hashlib.sha256(response.content).hexdigest()
    github = GitHubClient(root / cache / "github", token=_github_token())
    try:
        holdout = go_holdout.select(archive, digest, datetime.now(UTC), github)
    finally:
        github.close()
    target = root / go_holdout.FROZEN
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(holdout.model_dump_json(indent=2) + "\n", "utf-8")
    typer.echo(
        f"{len(holdout.reports)} reports of {holdout.considered} published after "
        f"{holdout.cutoff}; excluded {holdout.excluded} -> {target}"
    )


@app.command("holdout-baseline")
def holdout_baseline_command(
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
) -> None:
    """ChangedFuncs on the frozen Go temporal holdout: no model (needs GITHUB_TOKEN)."""
    import statistics

    from patchsight.pipeline.benchmarks import go_holdout
    from patchsight.pipeline.diffs.commits import map_commit

    holdout = go_holdout.load(root / go_holdout.FROZEN)
    reports, _ = go_holdout.as_benchmark(holdout)
    github = GitHubClient(root / cache / "github", token=_github_token())
    truth: dict[str, set[str]] = {}
    naive: dict[str, set[str]] = {}
    empty: list[str] = []
    try:
        for report in reports:
            mappings = [
                map_commit(github, c.github_repo, c.sha, include=dunlap.paper_path_filter)
                for c in report.commits
            ]
            inputs, _ = extraction.candidate_inputs(mappings)
            truth[report.id] = set(report.symbols)
            naive[report.id] = {i.name for i in inputs}
            if not inputs:
                empty.append(report.id)
    finally:
        github.close()
    scores = score(naive, truth, extraction.BOOTSTRAP, extraction.SEED)
    ci = scores.f1_ci95
    interval = f" ({ci.low:.2f} to {ci.high:.2f})" if ci else ""
    lines = [
        f"# ChangedFuncs on the Go temporal holdout (`{holdout.name}`)",
        "",
        "Generated by `python -m patchsight.pipeline holdout-baseline`; no model is involved.",
        "",
        f"- **{len(reports)} reports** published after {holdout.cutoff}, frozen in "
        f"[`{go_holdout.FROZEN.as_posix()}`](../../{go_holdout.FROZEN.as_posix()}) from "
        f"GoVulnDB (SHA-256 `{holdout.source_sha256[:12]}…`, retrieved "
        f"{holdout.retrieved_at[:10]}); {holdout.considered} were considered, excluded: "
        + ", ".join(f"{k} {v}" for k, v in holdout.excluded.items()),
        f"- {sum(len(t) for t in truth.values())} vulnerable symbols (median "
        f"{statistics.median(len(t) for t in truth.values()):g} per report, at most "
        f"{max(len(t) for t in truth.values())}): current GoVulnDB lists the exported "
        "functions that reach the vulnerable code, so these labels are broader than the 2023 "
        "Dunlap ones ([ADR 0010](../adr/0010-go-temporal-holdout.md))",
        f"- {sum(len(n) for n in naive.values())} changed functions; {len(empty)} reports "
        "whose fix changes no Go function outside tests",
        "",
        "| System | Precision | Recall | F1 (95% CI) | Report miss rate |",
        "|---|---:|---:|---:|---:|",
        f"| ChangedFuncs (every changed function) | {scores.precision:.3f} | {scores.recall:.3f} "
        f"| {scores.f1:.3f}{interval} | "
        f"{scores.miss_rate:.1%} |",
        "",
        "The recall here is the patch ceiling for this data: a symbol the fix never changed "
        "cannot be found from the patch.",
        "",
        holdout.attribution,
        "",
    ]
    target = root / "docs" / "reports" / f"changedfuncs-{holdout.name}"
    target.with_name(target.name + ".md").write_text("\n".join(lines), "utf-8")
    target.with_name(target.name + ".json").write_text(
        scores.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(
        f"ChangedFuncs on {len(reports)} reports: P {scores.precision:.3f} R {scores.recall:.3f} "
        f"F1 {scores.f1:.3f}, miss {scores.miss_rate:.1%}"
    )


INJECTION_DIR = Path("benchmarks/dunlap-v1")


def _injection_paths(root: Path, part: str, tag: str) -> tuple[Path, Path]:
    base = root / INJECTION_DIR / f"injection-{part}-{tag}"
    return base.with_name(base.name + ".json"), base.with_name(base.name + "-entry-points.json")


def _write_injection_report(root: Path, part: str, primary: str, secondary: str) -> str:
    from patchsight.pipeline.benchmarks import injection

    plans = [
        injection.Plan.model_validate(p)
        for p in json.loads((root / INJECTION_DIR / f"injection-plans-{part}.json").read_text())
    ]
    data = bundle.load(root / DUNLAP_BUNDLE)
    truth = {r.id: set(r.symbols) for r in data.reports}
    found, labels = {}, {}
    for tag in (primary, secondary):
        answers_path, entry_path = _injection_paths(root, part, tag)
        run = replay.load(answers_path)
        found[tag] = injection.cases(run, injection.load_entry_points(entry_path))
        labels[tag] = run.model
    report = injection.InjectionReport(
        split=part, primary=primary, secondary=secondary, plans=tuple(plans),
        models={tag: injection.score_model(found[tag], plans, truth) for tag in found},
        pair=injection.score_pair(found[primary], found[secondary], plans, truth),
    )  # fmt: skip
    target = root / "docs" / "reports" / f"injection-dunlap-{part}-{primary}-vs-{secondary}"
    target.parent.mkdir(parents=True, exist_ok=True)
    markdown = injection.render_markdown(report, labels)
    target.with_name(target.name + ".md").write_text(markdown, "utf-8")
    target.with_name(target.name + ".json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    return markdown


@app.command("injection-suite")
def injection_suite_command(
    root: Root = Path(),
    split: Annotated[str, typer.Option(help="Split part to attack (dev only).")] = "dev",
    sample: Annotated[int, typer.Option(help="Seeded sample of N attackable reports.")] = 20,
    primary_role: Annotated[str, typer.Option(help="Extractor role.")] = "extractor",
    primary_tag: Annotated[str, typer.Option(help="Extractor run tag.")] = "extract-v1-qwen3.8-27b",
    secondary_role: Annotated[str, typer.Option(help="Second-opinion role.")] = "second_opinion",
    secondary_tag: Annotated[
        str, typer.Option(help="Second-opinion run tag.")
    ] = "extract-v1-gpt-oss-120b",
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    cache: Annotated[Path, typer.Option(help="Response cache root.")] = Path(".cache"),
) -> None:
    """Plant instructions in untrusted fields and measure what changes (needs both models' keys).

    Resumable: answers are cached, so after a quota stop the same command continues.
    """
    from patchsight.pipeline.benchmarks import injection

    if split != "dev":
        raise typer.BadParameter(
            "the injection suite runs on dev only; test is for declared decisions"
        )
    token = _github_token()
    manifest = snapshot.load_manifest(root / MANIFEST)
    reports = dunlap.load(snapshot.verify(manifest.file(DUNLAP_DATA), root))
    advisories = extraction.load_advisories(snapshot.verify(manifest.file(DUNLAP_ADVISORIES), root))
    frozen = splits.load_split(root / DUNLAP_SPLIT)
    chosen = [r for r in reports if r.id in frozen.split.ids(split)]
    llm_config = load_config(root / config)
    template = load_template(root / prompt)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    github = GitHubClient(root / cache / "http" / "github", token=token)
    plans_path = root / INJECTION_DIR / f"injection-plans-{split}.json"
    try:
        if plans_path.exists():
            plans = [injection.Plan.model_validate(p) for p in json.loads(plans_path.read_text())]
        else:
            plans = injection.select(
                github, llm_config, primary_role, template, counter, chosen, advisories, sample
            )
            plans_path.parent.mkdir(parents=True, exist_ok=True)
            plans_path.write_text(
                json.dumps([p.model_dump() for p in plans], indent=1) + "\n", "utf-8"
            )
        typer.echo(f"{len(plans)} attackable reports", err=True)
        # Each model has its own quota: one stopping does not stop the other.
        unfinished: list[str] = []
        for role, tag in ((primary_role, primary_tag), (secondary_role, secondary_tag)):
            llm, model_id = client_for(llm_config, role, root / cache / "llm", counter)

            def progress(done: int, total: int, role: str = role) -> None:
                typer.echo(f"{role}: {done}/{total}", err=True)

            try:
                run, entry = injection.run(
                    github, llm, root / cache / "llm", llm_config, role, template, counter,
                    chosen, advisories, plans, f"{frozen.split.name}:{split}", progress=progress,
                )  # fmt: skip
            except (QuotaExhaustedError, RateLimitedError) as stopped:
                typer.echo(f"{role} stopped: {stopped}", err=True)
                unfinished.append(role)
                continue
            answers_path, entry_path = _injection_paths(root, split, tag)
            replay.save(run, answers_path)
            injection.save_entry_points(entry, entry_path)
            typer.echo(f"{model_id}: {llm.network_calls} model calls", err=True)
    finally:
        github.close()
    if unfinished:
        typer.echo(
            f"unfinished: {', '.join(unfinished)}. Every answer so far is cached; re-run the "
            "same command to resume.",
            err=True,
        )
        raise typer.Exit(code=2)
    typer.echo(_write_injection_report(root, split, primary_tag, secondary_tag))


@app.command("injection-report")
def injection_report_command(
    root: Root = Path(),
    split: Annotated[str, typer.Option(help="Split part.")] = "dev",
    primary: Annotated[str, typer.Option(help="Extractor run tag.")] = "extract-v1-qwen3.8-27b",
    secondary: Annotated[
        str, typer.Option(help="Second-opinion run tag.")
    ] = "extract-v1-gpt-oss-120b",
) -> None:
    """Recompute the injection report offline from the committed replay bundles."""
    typer.echo(_write_injection_report(root, split, primary, secondary))


def _entry_points(reports_dir: Path, name: str) -> dict[str, frozenset[str]]:
    """Validated entry points per report, from a committed extraction report."""
    path = reports_dir / f"{name}.json"
    outcomes = json.loads(path.read_text("utf-8"))["outcomes"]
    return {o["advisory_id"]: frozenset(o.get("entry_points") or ()) for o in outcomes}


@app.command("holdout-report")
def holdout_report_command(
    primary: Annotated[str, typer.Option(help="Extractor run tag (replay bundle).")],
    secondary: Annotated[str, typer.Option(help="Second-opinion run tag (replay bundle).")],
    root: Root = Path(),
) -> None:
    """The declared evaluation on the Go temporal holdout (ADR 0010), offline, from the
    committed replay bundles and extraction reports of both models."""
    import hashlib

    from patchsight.eval import confidence, holdout
    from patchsight.eval.safety import safety
    from patchsight.pipeline.benchmarks import go_holdout

    frozen_file = root / go_holdout.FROZEN
    labels = {r.id: set(r.symbols) for r in go_holdout.load(frozen_file).reports}
    reports_dir = root / "docs" / "reports"
    runs: dict[str, tuple[str, Any]] = {}
    for tag in (primary, secondary):
        run = replay.load(root / go_holdout.FROZEN.parent / f"extraction-{tag}.json")
        runs[tag] = (run.model, run)
    # Every function each fix changed, as holdout-baseline maps it: from the retrieval bundle,
    # not the replay bundle, whose candidates are only those a cut prompt kept. Checked
    # against the committed ChangedFuncs baseline before anything is scored.
    from patchsight.pipeline.benchmarks import retrieval

    mapped = retrieval.Bundle.model_validate_json(
        (root / RETRIEVAL[go_holdout.NAME][0]).read_text("utf-8")
    )
    changed = {c.report: {i.name for i in c.items} for c in mapped.cases if c.report in labels}
    baseline = score(changed, {r: labels[r] for r in changed})
    committed = SetScores.model_validate_json(
        (reports_dir / "changedfuncs-go-holdout-v1.json").read_text("utf-8")
    )
    counts = ("true_positives", "false_positives", "false_negatives", "reports")
    if any(getattr(baseline, c) != getattr(committed, c) for c in counts):
        raise typer.BadParameter(
            "the changed functions do not reproduce docs/reports/changedfuncs-go-holdout-v1.json"
        )
    results = []
    for variant, suffix in (("exact", ""), ("dotted", "-dotted")):
        names = {t: f"extraction-{go_holdout.NAME}-{t}{suffix}" for t in (primary, secondary)}
        if not all((reports_dir / f"{n}.json").exists() for n in names.values()):
            if variant == "exact":
                raise typer.BadParameter(f"missing extraction reports: {sorted(names.values())}")
            typer.echo(
                "dotted variant not computed: replay both runs with --config "
                "configs/experiments/llm-dotted-entry-points.toml and --out ...-dotted",
                err=True,
            )
            continue
        answers = {}
        for tag in (primary, secondary):
            entry = _entry_points(reports_dir, names[tag])
            run = runs[tag][1]
            by_report = {}
            for report in run.reports:
                if report.id in labels:
                    status, picked = replay.replay_report(report, run.prompt_version)
                    by_report[report.id] = confidence.Answer(
                        status=status, vulnerable=frozenset(picked), truncated=report.truncated,
                        entry_points=entry.get(report.id, frozenset()),
                    )  # fmt: skip
            answers[tag] = by_report
        results.append(
            holdout.evaluate(variant, answers[primary], answers[secondary], changed, labels)
        )
    digest = hashlib.sha256(frozen_file.read_bytes()).hexdigest()
    evaluation = holdout.HoldoutEvaluation(
        holdout=go_holdout.NAME, holdout_sha256=digest,
        primary=primary, primary_model=runs[primary][0],
        secondary=secondary, secondary_model=runs[secondary][0],
        changedfuncs=baseline,
        changedfuncs_safety=safety(changed, {r: labels[r] for r in changed}),
        results=tuple(results),
    )  # fmt: skip
    target = reports_dir / f"holdout-{go_holdout.NAME}-{primary}-vs-{secondary}"
    target.with_name(target.name + ".md").write_text(holdout.render_markdown(evaluation), "utf-8")
    target.with_name(target.name + ".json").write_text(
        evaluation.model_dump_json(indent=2) + "\n", "utf-8"
    )
    for r in results:
        typer.echo(
            f"{r.variant}: {r.high_reports} of {r.reports} high, {r.high_misses} misses "
            f"({r.high_miss_rate:.1%}), {'passes' if r.passes else 'fails'}; covered "
            f"{r.covered_reports} of {r.high_reports}"
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
    ".cache/llm/", ".cache/http/github/", "docs/reports/", "pypi-run/", "run-info.json",
    "llama-server.log", "data/interim/traces/",
)  # fmt: skip
# Imported into the shared cache: model answers, and the GitHub answers a locator run fetched.
KAGGLE_CACHE_PREFIXES = (".cache/llm/", ".cache/http/github/")
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
            name = member.filename
            if name.startswith(KAGGLE_CACHE_PREFIXES) and not name.startswith(".cache/llm/usage/"):
                target = root / name
                responses += name.startswith(".cache/llm/") and name.endswith(".json")
            else:
                target = inbox / member.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(member))
    typer.echo(f"imported {responses} cached responses; run files in {inbox.relative_to(root)}")


def _fix_groups(
    dump: Path,
) -> tuple[dict[str, Advisory], list[AliasGroup], list[AliasGroup]]:
    """Every vulnerability, split into those with a GitHub fix candidate and the rest."""
    advisories = [r for r in normalise_dump(dump) if isinstance(r, Advisory)]
    by_id = {a.id: a for a in advisories}
    fixed: list[AliasGroup] = []
    unfixed: list[AliasGroup] = []
    for g in alias_groups(advisories):
        has_fix = any(
            c.kind in week1.GITHUB_KINDS for i in g.advisory_ids for c in by_id[i].fix_candidates
        )
        (fixed if has_fix else unfixed).append(g)
    return by_id, fixed, unfixed


def _github_fix_groups(
    dump: Path, ids: str | None, sample: int | None, seed: int
) -> tuple[dict[str, Advisory], list[AliasGroup]]:
    """Vulnerabilities with a GitHub fix candidate, optionally narrowed to IDs or a sample."""
    by_id, groups, _ = _fix_groups(dump)
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
    # A full build also ledgers the vulnerabilities with no GitHub fix candidate, so their
    # IDs are mapped too. A narrowed build (IDs or a sample) leaves them out.
    unfixed = _fix_groups(dump)[2] if ids is None and sample is None else []
    dump_entry = manifest.file(DUMP)
    version = dump_entry.retrieved_at.strftime("%Y.%m.%d")
    # A full build takes hours: wait out GitHub's hourly limit instead of failing.
    github = GitHubClient(root / cache / "github", token=token, wait_for_rate_limit=3900)
    pypi = PyPIClient(root / cache / "pypi")
    try:
        records, aliases, report = build_db.build(
            groups, by_id, github, pypi, version,
            progress=lambda done, total: typer.echo(f"built {done}/{total}", err=True),
            unfixed=unfixed,
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
        "builder_revision": str(build_db.BUILDER_REVISION),
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
    benchmark: Annotated[str, typer.Option(help="dunlap-v1 or go-holdout-v1.")] = "dunlap-v1",
) -> None:
    """Write a replay bundle from the response cache only (never calls a model)."""
    token = _github_token()
    chosen = _load_benchmark(root, benchmark, part)
    reports = [r for r in chosen.reports if chosen.ids is None or r.id in chosen.ids]
    advisories = chosen.advisories
    llm_config = load_config(root / config)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    github = GitHubClient(root / cache / "http" / "github", token=token)
    try:
        exported = replay.export(
            github, root / cache / "llm", llm_config, role, load_template(root / prompt), counter,
            reports, advisories, split=part, benchmark=chosen.replay_name,
        )  # fmt: skip
    finally:
        github.close()
    target = root / chosen.bundle_dir / f"extraction-{tag}.json"
    replay.save(exported, target)
    answers = sum(len(r.answers) for r in exported.reports)
    typer.echo(f"{target.relative_to(root)}: {len(exported.reports)} reports, {answers} answers")


@app.command("confidence-report")
def confidence_report_command(
    primary: Annotated[str, typer.Option(help="Extractor run tag (replay bundle).")],
    secondary: Annotated[str, typer.Option(help="Second-opinion run tag (replay bundle).")],
    part: Annotated[str, typer.Option("--split", help="Split part: dev, test or all.")] = "dev",
    variant: Annotated[
        str | None,
        typer.Option(
            help="Experiment variant: read entry points from the reports ending in -VARIANT, "
            "and write the report under that suffix."
        ),
    ] = None,
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
        suffix = f"{tag}-{variant}" if variant else tag
        entry: dict[str, frozenset[str]] = {}
        for source in sorted(reports_dir.glob(f"extraction-dunlap-*-{suffix}.json")):
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
        *(
            [f"- Variant `{variant}`: entry points from the `-{variant}` extraction reports"]
            if variant
            else []
        ),
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
    name = f"confidence-dunlap-{part}-{primary}-vs-{secondary}" + (f"-{variant}" if variant else "")
    target = reports_dir / name
    target.with_name(target.name + ".md").write_text("\n".join(lines), "utf-8")
    target.with_name(target.name + ".json").write_text(
        json.dumps([r.model_dump(mode="json") for r in results], indent=2) + "\n", "utf-8"
    )
    typer.echo("\n".join(lines[10 + bool(variant) :]))


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


@app.command("reachability-report")
def reachability_report_command(
    database: Annotated[
        Path | None,
        typer.Option(
            "--db",
            help="Score a symbol database (a published release) instead of the labelled data.",
        ),
    ] = None,
    root: Root = Path(),
) -> None:
    """Score the reachability fixtures, offline: false suppressions and verdicts per case."""
    from patchsight.eval import reachability

    directory = root / reachability.FIXTURES
    fixtures = reachability.load(directory)
    labelled = reachability.run_labelled(fixtures, directory)
    if database is None:
        result, stem, beside = labelled, "labelled", None
    else:
        result = reachability.run_database(fixtures, directory, database)
        stem, beside = f"db-{result.data.removeprefix('database ')}", labelled
    target = root / "docs" / "reports" / f"reachability-fixtures-{stem}"
    text = reachability.render_markdown(fixtures, result, beside)
    target.with_name(target.name + ".md").write_text(text, "utf-8")
    target.with_name(target.name + ".json").write_text(
        result.model_dump_json(indent=2) + "\n", "utf-8"
    )
    suppressed = result.false_suppressions
    typer.echo(
        f"{result.data}: {len(result.outcomes)} programs, {len(suppressed)} false suppressions, "
        f"{sum(o.as_expected for o in result.outcomes)} as expected -> {target}.md"
    )
    if suppressed:
        raise typer.Exit(1)


@app.command("fetch-nightly")
def fetch_nightly_command(
    root: Root = Path(),
    repo: Annotated[str, typer.Option(help="The repository.")] = "professor3333/PatchSight",
    limit: Annotated[int, typer.Option(help="The latest runs to look at.")] = 30,
) -> None:
    """Download the reports of nightly runs not fetched yet (needs GITHUB_TOKEN)."""
    from patchsight.pipeline import nightly_runs

    fetched = nightly_runs.fetch(_github_token(), repo, root, limit)
    typer.echo(f"{len(fetched)} nightly runs fetched into {nightly_runs.DIRECTORY}")


@app.command("operations-report")
def operations_report_command(
    database: Annotated[
        Path | None, typer.Option("--db", help="A published database to describe.")
    ] = None,
    root: Root = Path(),
    kaggle: Annotated[Path, typer.Option(help="Imported Kaggle runs.")] = Path(
        "data/interim/kaggle"
    ),
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    cache: Annotated[Path, typer.Option(help="Cache root.")] = Path(".cache"),
    pricing: Annotated[Path, typer.Option(help="Published prices, for the cost at paid rates.")] = (
        Path("configs/pricing.toml")
    ),
) -> None:
    """The operations dashboard (#60): Kaggle sessions, quota use and the database, offline."""
    from patchsight.pipeline import nightly_runs, operations, sessions

    found = sessions.load_sessions(root / kaggle)
    llm_config = load_config(root / config)
    hosted = []
    for model in sorted({m.model: m for m in llm_config.models.values()}.values(),
                        key=lambda m: m.model):  # fmt: skip
        cap = llm_config.providers[model.provider].tokens_per_day
        ledger = root / cache / "llm" / "usage" / f"{model.model.replace('/', '__')}.jsonl"
        if cap is None or not ledger.exists():
            continue  # self-hosted, or never called here
        days = sessions.daily_use(sessions.load_ledger(ledger), cap)
        hosted.append(
            operations.HostedModel(model=model.model, tokens_per_day=cap, days=tuple(days))
        )
    prices = (
        operations.Pricing.model_validate(tomllib.loads((root / pricing).read_text("utf-8")))
        if (root / pricing).exists()
        else None
    )
    nights = tuple(nightly_runs.load_runs(root))
    report = operations.OperationsReport(
        generated_at=datetime.now(UTC).replace(microsecond=0),
        sessions=tuple(found), weeks=tuple(sessions.gpu_weeks(found)), hosted=tuple(hosted),
        database=None if database is None else operations.database_view(database),
        local_runs=tuple(sessions.load_traces(root / TRACE_DIR)),
        nightly=nights, pricing_source=prices.source if prices else None,
        pricing_retrieved=prices.retrieved if prices else None,
        costs=tuple(operations.costs(found, nights, prices)) if prices else (),
    )  # fmt: skip
    target = root / "docs" / "reports" / "operations"
    target.with_name("operations.md").write_text(operations.render_markdown(report), "utf-8")
    target.with_name("operations.json").write_text(report.model_dump_json(indent=2) + "\n", "utf-8")
    typer.echo(
        f"{len(found)} Kaggle sessions, {sum(s.hours for s in found):.1f} hours; "
        f"{len(hosted)} hosted models -> docs/reports/operations.md"
    )


@app.command("panel-report")
def panel_report_command(
    database: Annotated[Path, typer.Option("--db", help="The symbol database to scan with.")],
    runs: Annotated[int, typer.Option(help="Timed scans per repository.")] = 5,
    only: Annotated[
        list[str] | None, typer.Option(help="Scan only these repositories; repeatable.")
    ] = None,
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="Where the projects are fetched.")] = Path(
        ".cache/panel"
    ),
) -> None:
    """Scan the repository panel: coverage of symbol data and scan time (network)."""
    from patchsight.eval import panel

    repos = [r for r in panel.load(root / panel.PANEL) if not only or r.name in only]
    opened = db.SymbolDatabase(root / database)
    try:
        version = opened.meta.get("db_version", "?")
    finally:
        opened.close()
    results = []
    for repo in repos:
        path = panel.checkout(repo, root / cache)
        result = panel.measure(repo, path, root / database, runs)
        results.append(result)
        typer.echo(
            f"{repo.name}: {result.dependencies} dependencies, {result.alerts} alerts, "
            f"{result.with_data} with data, median {sorted(result.seconds)[runs // 2]:.2f} s",
            err=True,
        )
    report = panel.PanelReport(
        panel=panel.PANEL.as_posix(),
        db_version=version,
        machine=panel.machine(),
        measured_at=datetime.now(UTC).strftime("%Y-%m-%d"),
        runs=runs,
        results=tuple(results),
    )
    target = root / "docs" / "reports" / f"panel-db-{version}"
    target.with_name(target.name + ".md").write_text(panel.render_markdown(report), "utf-8")
    target.with_name(target.name + ".json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    p50, p95, _ = report.latency()
    typer.echo(
        f"{report.with_data} of {report.alerts} alerts with symbol data; scan p50 {p50:.2f} s, "
        f"p95 {p95:.2f} s -> {target}.md"
    )


LOCATOR_SAMPLE = Path("benchmarks/locator/masked-v1.json")


@app.command("locator-sample")
def locator_sample_command(
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
) -> None:
    """Draw and freeze the masked sample for the fix-commit locator (needs GITHUB_TOKEN)."""
    from patchsight.pipeline.locator import masked

    manifest, dump = _load_verified(root)
    by_id, groups, _ = _fix_groups(dump)
    github = GitHubClient(root / cache / "github", token=_github_token(), wait_for_rate_limit=3900)
    pypi = PyPIClient(root / cache / "pypi")
    try:
        sample = masked.draw(groups, by_id, github, pypi, manifest.file(DUMP).sha256)
    finally:
        github.close()
        pypi.close()
    target = root / LOCATOR_SAMPLE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(sample.model_dump_json(indent=2) + "\n", "utf-8")
    typer.echo(f"{len(sample.cases)} cases from {sample.eligible:,} eligible -> {target}")


@app.command("locator-eval")
def locator_eval_command(
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
) -> None:
    """Score the fix-commit locator's variants on the frozen masked sample (needs
    GITHUB_TOKEN unless every response is cached)."""
    from patchsight.pipeline.locator import baseline, masked

    sample = masked.MaskedSample.model_validate_json((root / LOCATOR_SAMPLE).read_text("utf-8"))
    manifest, dump = _load_verified(root)
    if manifest.file(DUMP).sha256 != sample.snapshot_sha256:
        raise typer.BadParameter(
            "the pinned snapshot is not the one the sample was drawn from; restore it first"
        )
    by_id = {r.id: r for r in normalise_dump(dump) if isinstance(r, Advisory)}
    github = GitHubClient(
        root / cache / "github", token=os.environ.get("GITHUB_TOKEN"), wait_for_rate_limit=3900
    )
    pypi = PyPIClient(root / cache / "pypi")
    try:
        results = {v: tuple(masked.run(sample, by_id, github, pypi, v)) for v in baseline.VARIANTS}
    finally:
        github.close()
        pypi.close()
    report = masked.LocatorReport(
        sample=sample.name, seed=sample.seed, snapshot_sha256=sample.snapshot_sha256,
        eligible=sample.eligible,
        scores=tuple(masked.summarise(v, r) for v, r in results.items()),
        results=results,
    )  # fmt: skip
    target = root / "docs" / "reports" / f"locator-{sample.name}"
    target.with_name(target.name + ".md").write_text(masked.render_markdown(report), "utf-8")
    target.with_name(target.name + ".json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    for scores in report.scores:
        typer.echo(
            f"{scores.variant}: exact {scores.exact}, wrong {scores.wrong}, abstained "
            f"{scores.abstained} of {scores.cases}"
        )


@app.command("locator-agent-eval")
def locator_agent_eval_command(
    tag: Annotated[str, typer.Option(help="Run tag, e.g. locate-v1-qwen3.8-27b-q4km.")],
    role: Annotated[str, typer.Option(help="Model role in the LLM config.")] = "extractor",
    limit: Annotated[int | None, typer.Option(help="Only the first N cases (a smoke run).")] = None,
    cache_only: Annotated[
        bool, typer.Option(help="Replay from the response cache; call no model.")
    ] = False,
    root: Root = Path(),
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/locate_v1.md"),
    cache: Annotated[Path, typer.Option(help="Cache root.")] = Path(".cache"),
    max_minutes: Annotated[
        float | None,
        typer.Option(help="Start no new case after this many minutes; resume by running again."),
    ] = None,
) -> None:
    """Score the fix-commit locator agent on the frozen masked sample (needs GITHUB_TOKEN unless
    every GitHub response is cached, and the model's key unless --cache-only). A run stopped by
    --max-minutes writes no report: every answer is cached, and the same command resumes."""
    started = time.monotonic()
    from patchsight.pipeline.llm.client import cache_only_client
    from patchsight.pipeline.locator import masked

    sample = masked.MaskedSample.model_validate_json((root / LOCATOR_SAMPLE).read_text("utf-8"))
    manifest, dump = _load_verified(root)
    if manifest.file(DUMP).sha256 != sample.snapshot_sha256:
        raise typer.BadParameter("the pinned snapshot is not the one the sample was drawn from")
    by_id = {r.id: r for r in normalise_dump(dump) if isinstance(r, Advisory)}
    llm_config = load_config(root / config)
    template = load_template(root / prompt)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    llm, model_id = (
        cache_only_client(llm_config, role, root / cache / "llm", counter)
        if cache_only
        else client_for(llm_config, role, root / cache / "llm", counter)
    )
    github = GitHubClient(
        root / cache / "http" / "github", token=os.environ.get("GITHUB_TOKEN"),
        wait_for_rate_limit=3900,
    )  # fmt: skip
    pypi = PyPIClient(root / cache / "http" / "pypi")
    try:
        results, runs = masked.run_agent(
            sample, by_id, github, pypi, llm, llm_config.models[role], template,
            transcripts=root / "data" / "interim" / "locator" / tag, limit=limit,
            budget=llm_config.prompt_budget(role),
            deadline=None if max_minutes is None else started + max_minutes * 60,
        )  # fmt: skip
    except (QuotaExhaustedError, RateLimitedError) as stopped:
        typer.echo(f"stopped: {stopped}; every answer so far is cached, re-run to resume", err=True)
        raise typer.Exit(code=2) from None
    finally:
        github.close()
        pypi.close()
    wanted = len(sample.cases[:limit])
    if len(results) < wanted:
        typer.echo(
            f"incomplete: {len(results)} of {wanted} cases within {max_minutes} minutes; no report "
            "written. Every answer is cached: run the same command again to resume."
        )
        return
    scores = masked.summarise("agent", results)
    report = masked.LocatorReport(
        sample=sample.name, seed=sample.seed, snapshot_sha256=sample.snapshot_sha256,
        eligible=sample.eligible, scores=(scores,), results={"agent": tuple(results)},
    )  # fmt: skip
    summary = masked.summarise_agent(runs, model_id, template.version)
    committed = root / "docs" / "reports" / f"locator-{sample.name}.json"
    baselines: tuple[masked.VariantScores, ...] = ()
    if committed.exists():
        heuristics = masked.LocatorReport.model_validate_json(committed.read_text("utf-8"))
        # On a smoke run, the heuristics on the same first cases: like with like.
        baselines = tuple(
            masked.summarise(variant, list(rows[:limit]))
            for variant, rows in heuristics.results.items()
        )
    target = root / "docs" / "reports" / f"locator-{sample.name}-{tag}"
    target.with_name(target.name + ".md").write_text(
        masked.render_agent_markdown(report, summary, baselines), "utf-8"
    )
    target.with_name(target.name + ".json").write_text(
        json.dumps({"report": report.model_dump(mode="json"),
                    "agent": summary.model_dump(mode="json"),
                    "runs": [r.model_dump(mode="json") for r in runs]}, indent=2) + "\n",
        "utf-8",
    )  # fmt: skip
    typer.echo(
        f"agent on {scores.cases}: exact {scores.exact}, wrong {scores.wrong}, abstained "
        f"{scores.abstained}; {summary.outcomes}; {llm.network_calls} model calls -> {target}.md"
    )


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
    rebuild_status: Annotated[
        list[str] | None,
        typer.Option(
            help="Build again the vulnerabilities with this ledger status, although their "
            "inputs are unchanged (after a builder change); repeatable."
        ),
    ] = None,
) -> None:
    """Update a database from the pinned snapshot, rebuilding only changed vulnerabilities
    (needs GITHUB_TOKEN)."""
    from patchsight.pipeline import llm_records, update_db

    token = _github_token()
    manifest, dump = _load_verified(root)
    by_id, groups, unfixed = _fix_groups(dump)
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
            unfixed=unfixed, rebuild=frozenset(rebuild_status or ()),
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
        "builder_revision": str(build_db.BUILDER_REVISION),
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
    # Merging into a new version makes a new build, so the source's origin no longer applies.
    # Merging into the database's own version (the nightly: picks for the night's changes)
    # keeps it: the release is still that night's update.
    in_place = meta.get("db_version") == version
    if not in_place:
        meta.pop("updated_from", None)
        meta["merged_into"] = meta.get("db_version", "?")
    meta.update(
        {
            "db_version": version,
            "built_at": datetime.now(UTC).isoformat(),
            "builder": "llm-v1",
            "code_commit": commit,
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
        f"db {version} merged into {meta.get('merged_into', version)}: {len(merged)} records; "
        f"{dict(Counter(r.confidence for r in merged))}; {outcomes}"
    )


@app.command("nightly-targets")
def nightly_targets_command(
    update: Annotated[Path, typer.Argument(help="The update-db report.")],
    database: Annotated[
        Path | None,
        typer.Option(
            "--db", help="The night's database: its records still without model picks follow."
        ),
    ] = None,
    limit: Annotated[int, typer.Option(help="At most this many vulnerabilities a night.")] = 25,
    role: Annotated[str, typer.Option(help="Model role that will extract.")] = "extractor",
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    report: Annotated[
        Path | None, typer.Option(help="Also write the counts and targets here (JSON).")
    ] = None,
    root: Root = Path(),
) -> None:
    """Print the vulnerabilities to extract tonight, comma-separated (ADR 0013): the night's
    rebuilt or new vulnerabilities that have a record, then, with --db, those still on
    fallback records that this model and prompt have not failed on, newest first; capped so
    other work keeps its quota. Prints nothing when there are none."""
    from patchsight.pipeline import llm_records, update_db

    changes = update_db.UpdateReport.model_validate_json((root / update).read_text("utf-8"))
    waiting: list[str] = []
    if database is not None:
        model = load_config(root / config).models[role].model
        version = load_template(root / prompt).version
        night = db.SymbolDatabase(root / database)
        try:
            waiting = llm_records.backlog(night.all_records(), night.build_ledger(), model, version)
        finally:
            night.close()
    targets = update_db.extraction_targets(changes, limit, waiting)
    if report is not None:
        (root / report).write_text(targets.model_dump_json(indent=2) + "\n", "utf-8")
    typer.echo(",".join(targets.targets))
    left = targets.fresh + targets.backlog - len(targets.targets)
    typer.echo(
        f"{len(targets.targets)} to extract tonight ({targets.fresh} changed tonight, "
        f"{targets.backlog} waiting from before); {left} left for a later run",
        err=True,
    )


@app.command("import-names")
def import_names_command(
    database: Annotated[Path, typer.Argument(help="The database to annotate, in place.")],
    previous: Annotated[
        Path | None,
        typer.Option(help="The previous release, whose import names are reused."),
    ] = None,
    root: Root = Path(),
    cache: Annotated[Path, typer.Option(help="HTTP response cache.")] = Path(".cache/http"),
    offline: Annotated[bool, typer.Option(help="Answer only from the cache.")] = False,
) -> None:
    """Read each package's import names from its wheels, and relabel its records with them.
    Run after build-db, update-db or merge-llm, before gate-db."""
    from patchsight.pipeline import import_names

    target = root / database
    source = db.SymbolDatabase(target)
    try:
        records, aliases = source.all_records(), source.alias_map()
        builds, meta = list(source.build_ledger().values()), dict(source.meta)
    finally:
        source.close()
    earlier: dict[str, db.ImportNames] = {}
    if previous is not None:
        prior = db.SymbolDatabase(root / previous)
        try:
            earlier = prior.import_names()
        finally:
            prior.close()
    pypi = PyPIClient(root / cache / "pypi", offline=offline)
    index = import_names.WheelIndex(pypi, root / cache / "wheels", offline=offline)
    try:
        relabelled, names, report = import_names.annotate(records, index, earlier)
    finally:
        index.close()
        pypi.close()
    meta.pop("schema_version", None)  # db.write sets it
    meta["import_names"] = json.dumps(
        {"packages": report.packages, "with_names": report.packages - len(report.without_names)}
    )
    staged = target.with_name(target.name + ".tmp")
    db.write(staged, relabelled, aliases, meta, builds=builds, import_names=names)
    staged.replace(target)
    target.with_name(target.stem + "-import-names.json").write_text(
        report.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(
        f"{report.packages} packages: {report.reused} reused, {report.read} read from wheels, "
        f"{len(report.without_names)} without names; {report.records_relabelled} records "
        f"relabelled, {report.symbols_moved} symbols moved ({index.network_requests} range "
        f"requests, {pypi.http.network_requests} PyPI requests)"
    )


@app.command("db-diff")
def db_diff_command(
    production: Annotated[Path, typer.Argument(help="The production database.")],
    shadow: Annotated[Path, typer.Argument(help="The shadow database built with the change.")],
    name: Annotated[str, typer.Option(help="Report name: docs/reports/shadow-<name>.md.")],
    purpose: Annotated[str, typer.Option(help="One sentence: what the change is.")],
    root: Root = Path(),
    review: Annotated[int, typer.Option(help="Changed records to review by hand.")] = 20,
) -> None:
    """Compare a shadow database with production, and draw the records to review before
    the change is promoted."""
    from patchsight.pipeline import db_diff

    result = db_diff.diff(production, shadow, review=review)
    target = root / "docs" / "reports" / f"shadow-{name}"
    target.parent.mkdir(parents=True, exist_ok=True)
    # with_name, not with_suffix: a name such as "cap-2026.11.22" has dots of its own.
    target.with_name(target.name + ".md").write_text(
        db_diff.render_markdown(result, purpose), "utf-8"
    )
    target.with_name(target.name + ".json").write_text(
        result.model_dump_json(indent=2) + "\n", "utf-8"
    )
    typer.echo(
        f"{result.production} -> {result.shadow}: {result.unchanged:,} unchanged, "
        f"{result.kinds or 'no change'}; fields {result.fields}; "
        f"{len(result.review)} to review -> {target.relative_to(root)}.md"
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


@app.command("hf-publish")
def hf_publish_command(
    asset: Annotated[
        Path, typer.Argument(help="A release asset, patchsight-db-<version>.sqlite.gz.")
    ],
    tag: Annotated[str, typer.Option(help="Its GitHub release tag, e.g. db-2026.11.21.1.")],
    expect_sha256: Annotated[
        str, typer.Option(help="The asset's SHA-256 as its GitHub release states it.")
    ],
    repo: Annotated[str, typer.Option(help="Hugging Face dataset repository.")] = "",
    out: Annotated[Path, typer.Option(help="Where to build the dataset folder.")] = Path(
        "data/build/hf"
    ),
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Build the folder only; upload nothing.")
    ] = False,
    root: Root = Path(),
) -> None:
    """Publish one database release to the Hugging Face dataset: records and aliases as JSONL,
    the asset itself and the dataset card, as one commit tagged like the release. Needs
    HF_TOKEN unless --dry-run. A tag that already exists is left as it is."""
    import os

    from patchsight.pipeline import hf_dataset

    source = root / asset
    actual = hf_dataset.asset_sha256(source)
    if actual != expect_sha256.strip().lower():
        raise typer.BadParameter(
            f"{asset.name} has SHA-256 {actual}, not the release's {expect_sha256}; "
            "nothing published"
        )
    summary = hf_dataset.build(source, tag, root / out)
    typer.echo(
        f"{summary.tag}: {summary.records:,} records, {summary.vulnerabilities:,} vulnerabilities, "
        f"{summary.identifiers:,} IDs -> {out} ({', '.join(summary.files)})"
    )
    if dry_run:
        return
    token = os.environ.get("HF_TOKEN")
    if not token:
        raise typer.BadParameter("set HF_TOKEN to publish (or pass --dry-run)")
    from huggingface_hub import HfApi
    from huggingface_hub.errors import RepositoryNotFoundError

    target = repo or hf_dataset.REPO
    api = HfApi(token=token)
    try:
        published = hf_dataset.publish(api, root / out, summary, target)
    except RepositoryNotFoundError as missing:
        # Hugging Face says "not found" both for a missing repository and for one the token
        # may not see, so say what the token may do (never the token itself).
        typer.echo(
            f"Hugging Face cannot find dataset {target} with this token "
            f"({hf_dataset.describe_error(missing)}).",
            err=True,
        )
        try:
            typer.echo(hf_dataset.describe_token(api.whoami()), err=True)
        except Exception as error:  # a diagnosis only: any failure is reported
            typer.echo(f"whoami failed too: {hf_dataset.describe_error(error)}", err=True)
        raise typer.Exit(code=1) from None
    if published:
        typer.echo(f"published {summary.tag} to https://huggingface.co/datasets/{target}")
    else:
        typer.echo(f"{summary.tag} is already on {target}; it is not published again")


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
        considered = len(opened.build_ledger())
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
        title = (
            "## Model picks extracted for this release"
            if merged.previous_version == version
            else f"## Changes since {merged.previous_version}"
        )
        lines += [
            title,
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
    if considered > vulnerabilities:
        lines.append(
            f"- **{considered:,} vulnerabilities' IDs**, including the "
            f"{considered - vulnerabilities:,} without symbol data, so a scan shows one alert per "
            "vulnerability, with or without symbol data."
        )
    if "import_names" in meta:
        counts = json.loads(meta["import_names"])
        lines.append(
            f"- **Import names** come from the packages' wheels on PyPI for "
            f"{counts['with_names']:,} of {counts['packages']:,} packages. The rest keep names "
            "derived from the fix commit's paths."
            if counts["with_names"] < counts["packages"]
            else f"- **Import names** come from the packages' wheels on PyPI, for all "
            f"{counts['packages']:,} packages."
        )
    if update is not None:
        report = UpdateReport.model_validate_json((root / update).read_text("utf-8"))
        lines += [
            f"- **Changes since {report.previous_version}:** {report.carried:,} carried "
            f"unchanged, {report.rebuilt} rebuilt, {report.new} new, {report.removed} removed"
            + (f"; {report.aliases_added:,} aliases added" if report.aliases_added else "")
            + (f", {report.aliases_removed:,} removed" if report.aliases_removed else ""),
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
    topup: Annotated[
        Path | None,
        typer.Option(help="A topup-plan file: extract only the PyPI prompts it lists."),
    ] = None,
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
    if topup is not None:
        from patchsight.pipeline import topup as topups

        wanted = set(topups.Plan.model_validate_json((root / topup).read_text("utf-8"))
                     .part("pypi").ids())  # fmt: skip
        groups = [g for g in groups if g.key in wanted]
        typer.echo(f"top-up: {len(groups)} of the plan's {len(wanted)} prompts")
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
        with _run_trace(
            root, f"pypi-extract-{role}{suffix}", "pypi-extract", llm, role=role, model=model_id,
            prompt_version=template.version, shard=shard, offline=offline,
            cache_only=cache_only, max_minutes=max_minutes, priority=priority,
            second_opinion=eligible_from is not None, vulnerabilities=len(groups),
        ) as end:  # fmt: skip
            results, summary = pypi_extract.run(
                groups, by_id, github, pypi, llm, llm_config, role, template, counter,
                progress=lambda done, total: typer.echo(f"extracted {done}/{total}", err=True),
                deadline=None if max_minutes is None else started + 60 * max_minutes,
                keep_order=priority,
            )  # fmt: skip
            end.update(
                outcome="complete" if summary.complete else "time budget",
                processed=summary.processed, status=summary.status,
                truncated=summary.truncated, skipped=summary.skipped,
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


@app.command("gold-sample")
def gold_sample_command(
    database: Annotated[
        Path,
        typer.Option(
            "--db",
            help="A database whose build ledger says which vulnerabilities "
            "extraction can be scored on.",
        ),
    ],
    root: Root = Path(),
    size: Annotated[int, typer.Option(help="Advisories in the sample.")] = 120,
    seed: Annotated[int, typer.Option(help="Sample seed.")] = 20261120,
) -> None:
    """Choose the Python gold set before any labelling, and write its round-1 file and
    worksheet. Refuses to replace an existing sample."""
    import sqlite3

    from patchsight.pipeline.benchmarks import python_gold as gold

    target = root / gold.SAMPLE
    if target.exists():
        raise typer.BadParameter(f"{gold.SAMPLE} exists: the sample is chosen once")
    manifest, dump = _load_verified(root)
    by_id, fixed, unfixed = _fix_groups(dump)
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        rows = connection.execute("SELECT vulnerability FROM builds WHERE status = 'built'")
        built = {key for (key,) in rows}
    sample = gold.draw(fixed + unfixed, by_id, built, manifest.file(DUMP).sha256, size, seed)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(sample.model_dump_json(indent=1) + "\n", "utf-8")
    (target.parent / "round1.toml").write_text(gold.stub_round(sample, 1), "utf-8")
    (target.parent / "worksheet.md").write_text(gold.worksheet(sample), "utf-8")
    labels = sum(len(i.packages) for i in sample.items)
    typer.echo(
        f"{gold.SAMPLE}: {len(sample.items)} advisories ({sample.upstream} with upstream "
        f"symbols) from {sample.population:,}; {labels} entries in round1.toml"
    )


def _gold_round(root: Path, round_: int) -> Path:
    from patchsight.pipeline.benchmarks import python_gold as gold

    return root / gold.DIRECTORY / f"round{round_}.toml"


@app.command("gold-round")
def gold_round_command(
    round_: Annotated[int, typer.Option("--round", help="The round to start: 2, or 3.")],
    root: Root = Path(),
) -> None:
    """Start a round's file: fresh todo stubs, in that round's own order. Round 3 holds
    only the disagreements between rounds 1 and 2, to resolve. Never replaces a file."""
    from patchsight.pipeline.benchmarks import python_gold as gold

    target = _gold_round(root, round_)
    if target.exists():
        raise typer.BadParameter(f"{target.relative_to(root)} exists")
    sample = gold.Sample.model_validate_json((root / gold.SAMPLE).read_text("utf-8"))
    scope = gold.declared(sample)
    if round_ == 3:
        result = gold.agreement(gold.load_labels(_gold_round(root, 1)),
                                gold.load_labels(_gold_round(root, 2)), scope=scope)  # fmt: skip
        scope = frozenset((d.advisory, d.package) for d in result.disagreements)
    target.write_text(gold.stub_round(sample, round_, only=scope), "utf-8")
    typer.echo(f"{target.relative_to(root)}: {len(scope)} entries to label")


@app.command("gold-check")
def gold_check_command(
    round_: Annotated[int, typer.Option("--round", help="1, 2, or 3 for resolutions.")] = 1,
    root: Root = Path(),
) -> None:
    """Show a round's progress and every problem in it; exit 1 while any remains."""
    from patchsight.pipeline.benchmarks import python_gold as gold

    sample = gold.Sample.model_validate_json((root / gold.SAMPLE).read_text("utf-8"))
    labels = gold.load_labels(_gold_round(root, round_))
    scope = gold.declared(sample)
    mine = [lb for lb in labels if (lb.advisory, lb.package) in scope]
    done = Counter(label.status for label in mine)
    finished = len(mine) - done.get("todo", 0)
    typer.echo(f"round {round_}: {finished} of {len(mine)} declared entries finished; "
               f"{dict(sorted(done.items()))}")  # fmt: skip
    problems = gold.check_labels(labels, sample, round_, scope)
    if round_ == 3:  # resolutions cover the disagreements only
        problems = [p for p in problems if not p.endswith(": missing")]
    for problem in problems:
        typer.echo(f"  {problem}")
    if problems:
        raise typer.Exit(code=1)


@app.command("gold-agreement")
def gold_agreement_command(root: Root = Path()) -> None:
    """Self-agreement between rounds 1 and 2, written to docs/reports."""
    from patchsight.pipeline.benchmarks import python_gold as gold

    sample = gold.Sample.model_validate_json((root / gold.SAMPLE).read_text("utf-8"))
    result = gold.agreement(gold.load_labels(_gold_round(root, 1)),
                            gold.load_labels(_gold_round(root, 2)),
                            scope=gold.declared(sample))  # fmt: skip
    target = root / "docs" / "reports" / f"{gold.NAME}-agreement"
    target.with_suffix(".md").write_text(gold.render_agreement(result), "utf-8")
    target.with_suffix(".json").write_text(result.model_dump_json(indent=2) + "\n", "utf-8")
    typer.echo(
        f"{result.compared} entries in both rounds: exact match {result.exact_match:.1%}, "
        f"mean Jaccard {result.mean_jaccard:.3f}; {len(result.disagreements)} to resolve"
    )


@app.command("gold-eval")
def gold_eval_command(
    extractions: Annotated[list[Path], typer.Argument(help="pypi-extract outcome files.")],
    database: Annotated[Path, typer.Option("--db", help="The published database to score.")],
    root: Root = Path(),
) -> None:
    """Score the extractor and the published records against the final gold labels."""
    from patchsight.pipeline import llm_records
    from patchsight.pipeline.benchmarks import python_gold as gold

    third = _gold_round(root, 3)
    sample = gold.Sample.model_validate_json((root / gold.SAMPLE).read_text("utf-8"))
    final, unresolved = gold.final_labels(
        gold.load_labels(_gold_round(root, 1)), gold.load_labels(_gold_round(root, 2)),
        gold.load_labels(third) if third.exists() else [], scope=gold.declared(sample),
    )  # fmt: skip
    extractor: dict[str, set[str]] = {}
    for source in extractions:
        for key, run in llm_records.load(root / source).items():
            for package in run.packages:
                extractor[f"{key}/{package}"] = {s.qualified_name for s in run.vulnerable_symbols}
    published: dict[str, set[str]] = {}
    for record in db.SymbolDatabase(database).all_records():
        published[f"{record.vulnerability}/{record.package}"] = {
            s.qualified_name for s in record.symbols
        } | set(record.entry_points)
    scores = gold.score_against(final, {"Extractor alone": extractor,
                                        "Published records": published})  # fmt: skip
    labelled = sum(label.status == "labelled" for label in final)
    target = root / "docs" / "reports" / f"{gold.NAME}-eval"
    target.with_suffix(".md").write_text(
        gold.render_scores(scores, labelled, len(unresolved)), "utf-8"
    )
    target.with_suffix(".json").write_text(
        json.dumps([s.model_dump(mode="json") for s in scores], indent=2) + "\n", "utf-8"
    )
    for s in scores:
        typer.echo(f"{s.system}: F1 {s.strict.f1:.3f}, lenient recall {s.lenient.recall:.3f}")


@app.command("regression-freeze")
def regression_freeze_command(
    sources: Annotated[list[Path], typer.Argument(help="pypi-extract outcome files (JSONL).")],
    root: Root = Path(),
    role: Annotated[str, typer.Option(help="Model role the runs used.")] = "kaggle_extractor",
    size: Annotated[int, typer.Option(help="Vulnerabilities in the set.")] = 50,
    seed: Annotated[int, typer.Option(help="Sample seed.")] = 20261120,
    config: Annotated[Path, typer.Option(help="LLM config the runs used.")] = Path(
        "configs/llm.toml"
    ),
    prompt: Annotated[Path, typer.Option(help="Prompt template.")] = Path("prompts/extract_v1.md"),
    cache: Annotated[Path, typer.Option(help="Cache root (HTTP and LLM).")] = Path(".cache"),
) -> None:
    """Freeze the PyPI regression set from finished runs, offline, from the caches only.

    Each case's replay must reproduce the run's own outcome, or nothing is written."""
    from patchsight.eval.safety import lenient_match
    from patchsight.pipeline import llm_records, pypi_extract
    from patchsight.pipeline.benchmarks import pypi_regression as regression
    from patchsight.pipeline.benchmarks.extraction import candidate_inputs
    from patchsight.pipeline.benchmarks.replay import _Recorder
    from patchsight.pipeline.extract.extractor import extract_prompt
    from patchsight.pipeline.extract.prompt import render

    outcomes = {k: v for source in sources for k, v in llm_records.load(root / source).items()}
    chosen = regression.select(outcomes, size, seed)
    manifest, dump = _load_verified(root)
    by_id, groups = _github_fix_groups(dump, ",".join(k for k, _ in chosen), None, 0)
    by_key = {g.key: g for g in groups}
    llm_config = load_config(root / config)
    model = llm_config.models[role]
    template = load_template(root / prompt)
    counter = HfTokenizer(llm_config.tokenizer, root / cache / "tokenizer")
    github = GitHubClient(root / cache / "http" / "github", offline=True)
    pypi = PyPIClient(root / cache / "http" / "pypi", offline=True)
    frozen_at = manifest.file(DUMP).retrieved_at
    cases = []
    try:
        for key, stratum in chosen:
            group, run = by_key[key], outcomes[key]
            fixes = build_db.fix_mappings(group, by_id, github, pypi)
            inputs, known = candidate_inputs(fixes.mappings, pypi_extract.PYTHON_KINDS)
            rendered = render(
                template, pypi_extract.advisory_text(group, by_id), inputs,
                llm_config.prompt_budget(role), counter, llm_config.budget.max_hunk_lines,
                llm_config.candidate_limit(role), llm_config.budget.candidate_order,
            )  # fmt: skip
            recorder = _Recorder(root / cache / "llm", counter)
            extract_prompt(recorder, model, key, rendered, known,
                           llm_config.validation.dotted_entry_points)  # fmt: skip
            proposed: set[str] = set()
            for answer in recorder.answers:
                with contextlib.suppress(json.JSONDecodeError, AttributeError, TypeError):
                    proposed |= set(json.loads(answer or "{}").get("public_entry_points") or ())
            paths = pypi_extract.defining_paths(fixes.mappings)
            in_prompt = {(c.path, c.name) for c in rendered.candidates}
            # Only names a proposal can resolve to matter: those it matches exactly or, with
            # dotted entry points on, on a dotted boundary. Keeping every such name keeps the
            # "exactly one match" rule exact in both modes.
            relevant = {k for k in known if any(lenient_match(p, k) for p in proposed)}
            resolvable = relevant | {c.name for c in rendered.candidates}
            fallback, _ = build_db.fallback_records(group, by_id, github, pypi, frozen_at)
            draft = regression.Case(
                vulnerability=key, stratum=stratum, packages=run.packages,
                input_hash=run.input_hash, fix_commits=run.fix_commits,
                prompt=rendered.model_copy(update={"messages": ()}),
                known_names=tuple(sorted(relevant)),
                definitions={n: tuple(sorted(paths[n])) for n in sorted(resolvable) if n in paths},
                kinds=tuple(sorted((i.path, i.name, i.kind) for i in inputs
                                   if (i.path, i.name) in in_prompt)),
                answers=tuple(recorder.answers), fallback=tuple(fallback),
                expected=regression.Expected(status="", calls=0, vulnerable_symbols=(),
                                             entry_points=(), evidence=(), merge="", records=()),
            )  # fmt: skip
            expected = regression.replay(
                draft, model.model, llm_config.validation.dotted_entry_points
            )
            ran = (
                run.outcome.status,
                tuple(sorted(s.qualified_name for s in run.vulnerable_symbols)),
                run.entry_points,
                run.evidence,
            )
            again = (expected.status, expected.vulnerable_symbols, expected.entry_points,
                     expected.evidence)  # fmt: skip
            if ran != again:
                raise typer.BadParameter(f"{key}: the replay does not reproduce the run's outcome")
            cases.append(draft.model_copy(update={"expected": expected}))
    finally:
        github.close()
        pypi.close()
    strata = Counter(c.stratum for c in cases)
    regression_set = regression.RegressionSet(
        name=regression.NAME, model=model.model, prompt_version=template.version,
        source=", ".join(sorted(str(s) for s in sources)), seed=seed,
        strata=dict(sorted(strata.items())), cases=tuple(cases),
    )  # fmt: skip
    regression.save(regression_set, root / regression.FROZEN)
    typer.echo(f"{regression.FROZEN}: {len(cases)} cases; {dict(sorted(strata.items()))}")


@app.command("regression-check")
def regression_check_command(
    root: Root = Path(),
    config: Annotated[Path, typer.Option(help="LLM config.")] = Path("configs/llm.toml"),
) -> None:
    """Replay the PyPI regression set through the live code; exit 1 on any difference."""
    from patchsight.pipeline.benchmarks import pypi_regression as regression

    frozen = regression.load(root / regression.FROZEN)
    dotted = load_config(root / config).validation.dotted_entry_points
    differences = regression.check(frozen, dotted)
    for d in differences:
        typer.echo(f"{d.vulnerability} {d.field}: expected {d.expected}, got {d.actual}")
    typer.echo(
        f"{frozen.name}: {len(frozen.cases)} cases, {len(differences)} differences"
        f" ({', '.join(f'{k} {v}' for k, v in frozen.strata.items())})"
    )
    if differences:
        raise typer.Exit(code=1)


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

    database = root / database  # like every other command; an absolute path is kept
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
