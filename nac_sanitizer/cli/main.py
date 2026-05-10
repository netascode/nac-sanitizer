"""CLI entry point for nac-sanitizer."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from nac_sanitizer import __version__

app = typer.Typer(add_completion=False)
console = Console(stderr=True)


class VerbosityLevel(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


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
def sanitize(
    input_path: Annotated[
        Path,
        typer.Argument(help="Input JSON file or directory", exists=True),
    ],
    output: Annotated[
        Path,
        typer.Option("-o", "--output", help="Output directory for sanitized files"),
    ],
    config: Annotated[
        Path | None,
        typer.Option(
            "-c",
            "--config",
            help="User configuration file",
            envvar="NAC_SANITIZER_CONFIG",
        ),
    ] = None,
    profile: Annotated[
        list[str] | None,
        typer.Option("-p", "--profile", help="Product profile(s) to activate"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run", help="Show what would be redacted without writing files"
        ),
    ] = False,
) -> None:
    """Sanitize nac-collector JSON output."""
    from nac_sanitizer.config.loader import ConfigurationError, load_config
    from nac_sanitizer.engine.ip_allocator import PoolExhaustedError
    from nac_sanitizer.sanitizer import Sanitizer

    try:
        cfg = load_config(
            config_path=config,
            profile_names=profile,
        )
    except ConfigurationError as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        raise typer.Exit(1) from e

    sanitizer = Sanitizer(cfg)

    if dry_run:
        try:
            summary = sanitizer.run_dry(input_path)
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1) from e

        console.print("\n[bold]Dry run summary[/bold]")
        console.print(f"  Files scanned: {summary['files_scanned']}")
        console.print(f"  Total matches: {summary['total_matches']}")
        if summary["by_category"]:
            console.print("  By category:")
            for cat, count in sorted(summary["by_category"].items()):
                console.print(f"    {cat}: {count}")
        raise typer.Exit(0)

    try:
        rosetta_path = sanitizer.run(input_path, output)
    except PoolExhaustedError as e:
        console.print(f"[bold red]Pool exhausted:[/bold red] {e}")
        raise typer.Exit(1) from e
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1) from e

    console.print("[green]Sanitization complete.[/green]")
    console.print(f"  Output: {output}")
    console.print(f"  Rosetta Stone: {rosetta_path}")


@app.command()
def validate_config(
    config_path: Annotated[
        Path,
        typer.Argument(help="Configuration file to validate", exists=True),
    ],
) -> None:
    """Validate a sanitizer configuration file."""
    from nac_sanitizer.config.loader import ConfigurationError, load_config

    try:
        cfg = load_config(config_path=config_path)
    except ConfigurationError as e:
        console.print(f"[bold red]Invalid configuration:[/bold red] {e}")
        raise typer.Exit(1) from e

    console.print("[green]Configuration is valid.[/green]")
    console.print(f"  Profiles: {cfg.profiles or '(none)'}")
    console.print(f"  Packs enabled: {cfg.packs.enable or '(none)'}")
    console.print(f"  Packs disabled: {cfg.packs.disable or '(none)'}")
    console.print(f"  Custom rules: {len(cfg.custom_rules)}")
    console.print(f"  Overrides: {len(cfg.overrides)}")


profiles_app = typer.Typer(help="Manage product profiles.")
app.add_typer(profiles_app, name="profiles")


@profiles_app.command("list")
def profiles_list() -> None:
    """List available product profiles and redaction packs."""
    from nac_sanitizer.profiles.registry import ProfileRegistry

    available = ProfileRegistry.available()
    if not available:
        console.print("[yellow]No profiles available.[/yellow]")
        raise typer.Exit(0)

    console.print("[bold]Available profiles:[/bold]")
    for name in available:
        console.print(f"  - {name}")
