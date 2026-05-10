"""CLI entry point for nac-sanitizer."""

from typing import Annotated

import typer

from nac_sanitizer import __version__

app = typer.Typer(add_completion=False)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"nac-sanitizer {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """Sanitize sensitive values in nac-collector JSON output."""


@app.command()
def sanitize() -> None:
    """Sanitize nac-collector JSON output."""
    typer.echo("Not yet implemented.")
    raise typer.Exit(1)


@app.command()
def validate_config() -> None:
    """Validate a sanitizer configuration file."""
    typer.echo("Not yet implemented.")
    raise typer.Exit(1)


profiles_app = typer.Typer(help="Manage product profiles.")
app.add_typer(profiles_app, name="profiles")


@profiles_app.command("list")
def profiles_list() -> None:
    """List available product profiles and redaction packs."""
    typer.echo("Not yet implemented.")
    raise typer.Exit(1)
