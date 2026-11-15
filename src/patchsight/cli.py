"""User-facing command-line interface.

This module is on the hot path: it must never import ``patchsight.pipeline``,
``patchsight.eval`` or any LLM client. ``tests/test_import_boundary.py`` enforces this.
"""

import os
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


def _default_db() -> Path:
    configured = os.environ.get("PATCHSIGHT_DB")
    return (
        Path(configured)
        if configured
        else Path.home() / ".cache" / "patchsight" / "patchsight.sqlite"
    )


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Project directory to scan.")] = Path(),
    requirements_file: Annotated[
        Path | None, typer.Option("--requirements", help="Lockfile (default: requirements.txt).")
    ] = None,
    database: Annotated[
        Path | None, typer.Option("--db", help="Symbol database (default: $PATCHSIGHT_DB).")
    ] = None,
    output: Annotated[str, typer.Option("--format", help="text or json.")] = "text",
    fail_on: Annotated[
        str, typer.Option(help="Exit 1 when an alert is: called, unknown (or called), or never.")
    ] = "never",
) -> None:
    """Label every dependency alert as called, imported but not called, not imported, or unknown."""
    from patchsight.db import DatabaseError
    from patchsight.scan.osv_client import OsvError
    from patchsight.scan.report import render_json, render_text
    from patchsight.scan.run import run_scan

    lockfile = requirements_file or path / "requirements.txt"
    if not lockfile.exists():
        typer.echo(f"error: no lockfile at {lockfile}; pass --requirements", err=True)
        raise typer.Exit(code=2)
    try:
        alerts, dependencies, meta = run_scan(path, lockfile, database or _default_db())
    except (DatabaseError, OsvError) as error:
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
