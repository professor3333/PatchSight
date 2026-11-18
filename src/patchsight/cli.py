"""User-facing command-line interface.

This module is on the hot path: it must never import ``patchsight.pipeline``,
``patchsight.eval`` or any LLM client. ``tests/test_import_boundary.py`` enforces this.
"""

from pathlib import Path
from typing import Annotated

import typer

from patchsight import __version__

app = typer.Typer(
    name="patchsight",
    help="Symbol-level vulnerability triage for Python dependencies.",
    no_args_is_help=True,
    add_completion=False,
)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"patchsight {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_print_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Symbol-level vulnerability triage for Python dependencies."""


db_app = typer.Typer(help="Download and inspect the symbol database.", no_args_is_help=True)
app.add_typer(db_app, name="db")


@db_app.command("update")
def db_update() -> None:
    """Download the latest published database if it is newer, verifying its SHA-256."""
    from patchsight.db import DatabaseError
    from patchsight.scan import dbcache

    try:
        status, pointer = dbcache.update()
    except (DatabaseError, OSError) as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(code=2) from None
    verb = "Downloaded" if status == "updated" else "Already have"
    typer.echo(
        f"{verb} database {pointer.db_version} ({pointer.records:,} records) "
        f"at {dbcache.default_db_path()}"
    )


@db_app.command("info")
def db_info(
    database: Annotated[Path | None, typer.Option("--db", help="Database to describe.")] = None,
) -> None:
    """Show which database a scan would use."""
    from patchsight.db import DatabaseError, SymbolDatabase
    from patchsight.scan import dbcache
    from patchsight.scan.report import stale_warning

    path = database or dbcache.default_db_path()
    try:
        opened = SymbolDatabase(path)
    except DatabaseError as error:
        typer.echo(f"error: {error}; run 'patchsight db update'", err=True)
        raise typer.Exit(code=2) from None
    meta = opened.meta
    opened.close()
    typer.echo(f"{path}")
    for key in ("db_version", "schema_version", "builder", "built_at", "snapshot_sha256"):
        typer.echo(f"  {key}: {meta.get(key, '?')}")
    if warning := stale_warning(meta):
        typer.echo(f"  warning: {warning}")


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Project directory to scan.")] = Path(),
    lockfile_option: Annotated[
        Path | None,
        typer.Option(
            "--lockfile",
            "--requirements",
            help="requirements.txt, uv.lock or poetry.lock (default: the first found, in "
            "that order).",
        ),
    ] = None,
    database: Annotated[
        Path | None,
        typer.Option("--db", help="Symbol database (default: the one 'db update' downloaded)."),
    ] = None,
    output: Annotated[
        str, typer.Option("--format", help="text, json, or sarif (for code scanning).")
    ] = "text",
    fail_on: Annotated[
        str, typer.Option(help="Exit 1 when an alert is: called, unknown (or called), or never.")
    ] = "never",
) -> None:
    """Label every dependency alert as called, imported but not called, not imported, or unknown."""
    from patchsight.db import DatabaseError
    from patchsight.scan.dbcache import default_db_path
    from patchsight.scan.lockfiles import DISCOVERY_ORDER, find
    from patchsight.scan.osv_client import OsvError
    from patchsight.scan.report import render_json, render_text
    from patchsight.scan.run import run_scan

    lockfile = lockfile_option or find(path)
    if lockfile is None or not lockfile.is_file():
        looked = lockfile if lockfile is not None else f"{path} ({', '.join(DISCOVERY_ORDER)})"
        typer.echo(f"error: no lockfile at {looked}; pass --lockfile", err=True)
        raise typer.Exit(code=2)
    try:
        alerts, dependencies, meta = run_scan(path, lockfile, database or default_db_path())
    except DatabaseError as error:
        typer.echo(f"error: {error}; run 'patchsight db update' or pass --db", err=True)
        raise typer.Exit(code=2) from None
    except (OsvError, ValueError) as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(code=2) from None
    shown = lockfile.as_posix()
    if output == "json":
        typer.echo(render_json(alerts, dependencies, shown, meta))
    elif output == "sarif":
        import os

        from patchsight.scan.sarif import render_sarif

        # Code locations are relative to the scanned directory; SARIF wants them relative to
        # where the scan runs (the repository root, in CI).
        root = path if path.is_dir() else path.parent
        base = os.path.relpath(root.resolve(), Path.cwd().resolve())
        typer.echo(render_sarif(alerts, dependencies, shown, meta, base))
    else:
        typer.echo(render_text(alerts, dependencies, shown, meta))
    failing = {"called": {"CALLED"}, "unknown": {"CALLED", "UNKNOWN"}}.get(fail_on, set())
    if any(a.verdict in failing for a in alerts):
        raise typer.Exit(code=1)


@app.command()
def explain(
    identifier: Annotated[str, typer.Argument(help="Advisory ID: GHSA, PYSEC or CVE.")],
    database: Annotated[
        Path | None,
        typer.Option("--db", help="Symbol database (default: the one 'db update' downloaded)."),
    ] = None,
    output: Annotated[str, typer.Option("--format", help="text or json.")] = "text",
) -> None:
    """Show why the database lists the symbols it does for an advisory, with evidence."""
    from patchsight.db import DatabaseError, SymbolDatabase
    from patchsight.scan import explain as explaining
    from patchsight.scan.dbcache import default_db_path

    try:
        opened = SymbolDatabase(database or default_db_path())
    except DatabaseError as error:
        typer.echo(f"error: {error}; run 'patchsight db update' or pass --db", err=True)
        raise typer.Exit(code=2) from None
    try:
        vulnerability, identifiers, records = explaining.lookup(opened, identifier)
        status = opened.build_status(vulnerability)
        meta = opened.meta
    finally:
        opened.close()
    canonical = explaining.normalise_identifier(identifier)
    render = explaining.render_json if output == "json" else explaining.render_text
    typer.echo(render(canonical, vulnerability, identifiers, records, meta, status))
    if not records:
        raise typer.Exit(code=1)


@app.command()
def report(
    identifier: Annotated[str, typer.Argument(help="Advisory ID: GHSA, PYSEC or CVE.")],
    database: Annotated[
        Path | None,
        typer.Option("--db", help="Symbol database (default: the one 'db update' downloaded)."),
    ] = None,
    open_browser: Annotated[
        bool, typer.Option("--open/--no-open", help="Open the draft issue in a browser.")
    ] = True,
) -> None:
    """Draft a GitHub issue saying an advisory's symbol data is wrong. Nothing is sent: the
    browser opens a pre-filled form you review, complete and submit."""
    import webbrowser

    from patchsight.db import DatabaseError, SymbolDatabase
    from patchsight.scan import explain as explaining
    from patchsight.scan.dbcache import default_db_path
    from patchsight.scan.feedback import issue_url

    try:
        opened = SymbolDatabase(database or default_db_path())
    except DatabaseError as error:
        typer.echo(f"error: {error}; run 'patchsight db update' or pass --db", err=True)
        raise typer.Exit(code=2) from None
    try:
        vulnerability, identifiers, records = explaining.lookup(opened, identifier)
        status = opened.build_status(vulnerability)
        meta = opened.meta
    finally:
        opened.close()
    canonical = explaining.normalise_identifier(identifier)
    text = explaining.render_text(canonical, vulnerability, identifiers, records, meta, status)
    url = issue_url(canonical, text)
    typer.echo(f"Draft issue for {canonical} (review it before submitting):\n{url}")
    if open_browser:
        webbrowser.open(url)
