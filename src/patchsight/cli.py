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
    requirements_file: Annotated[
        Path | None, typer.Option("--requirements", help="Lockfile (default: requirements.txt).")
    ] = None,
    database: Annotated[
        Path | None,
        typer.Option("--db", help="Symbol database (default: the one 'db update' downloaded)."),
    ] = None,
    output: Annotated[str, typer.Option("--format", help="text or json.")] = "text",
    fail_on: Annotated[
        str, typer.Option(help="Exit 1 when an alert is: called, unknown (or called), or never.")
    ] = "never",
) -> None:
    """Label every dependency alert as called, imported but not called, not imported, or unknown."""
    from patchsight.db import DatabaseError
    from patchsight.scan.dbcache import default_db_path
    from patchsight.scan.osv_client import OsvError
    from patchsight.scan.report import render_json, render_text
    from patchsight.scan.run import run_scan

    lockfile = requirements_file or path / "requirements.txt"
    if not lockfile.exists():
        typer.echo(f"error: no lockfile at {lockfile}; pass --requirements", err=True)
        raise typer.Exit(code=2)
    try:
        alerts, dependencies, meta = run_scan(path, lockfile, database or default_db_path())
    except DatabaseError as error:
        typer.echo(f"error: {error}; run 'patchsight db update' or pass --db", err=True)
        raise typer.Exit(code=2) from None
    except OsvError as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(code=2) from None
    shown = lockfile.as_posix()
    if output == "json":
        typer.echo(render_json(alerts, dependencies, shown, meta))
    else:
        typer.echo(render_text(alerts, dependencies, shown, meta))
    failing = {"called": {"CALLED"}, "unknown": {"CALLED", "UNKNOWN"}}.get(fail_on, set())
    if any(a.verdict in failing for a in alerts):
        raise typer.Exit(code=1)
