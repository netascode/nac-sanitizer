# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""CLI entry point for nac-sanitizer."""

import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler

from nac_sanitizer import __version__

app = typer.Typer(add_completion=False)
console = Console(stderr=True)


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
    log_file: Annotated[
        Path | None,
        typer.Option("--log-file", help="Write diagnostic logs to this file"),
    ] = None,
) -> None:
    """Sanitize sensitive values in nac-collector JSON output."""
    root = logging.getLogger()
    root.handlers.clear()

    stderr_handler = RichHandler(console=console, show_path=False, markup=False)
    stderr_handler.setLevel(logging.WARNING)
    root.addHandler(stderr_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, mode="w")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        root.addHandler(file_handler)

    root.setLevel(logging.DEBUG if log_file else logging.WARNING)


@app.command()
def sanitize(
    input_path: Annotated[
        Path,
        typer.Argument(help="Input JSON file, directory, or .zip archive", exists=True),
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
    no_zip: Annotated[
        bool,
        typer.Option(
            "--no-zip",
            help="Output sanitized files uncompressed instead of re-zipping",
        ),
    ] = False,
    skip_large_subnets: Annotated[
        bool,
        typer.Option(
            "--skip-large-subnets/--no-skip-large-subnets",
            help="Preserve IPv4 subnets with prefix length /4 or shorter without sanitizing",
        ),
    ] = True,
) -> None:
    """Sanitize nac-collector JSON output."""
    from nac_sanitizer.config.loader import ConfigurationError, load_config
    from nac_sanitizer.engine.ip_allocator import PoolExhaustedError
    from nac_sanitizer.profiles.registry import ProfileNotFoundError
    from nac_sanitizer.sanitizer import Sanitizer
    from nac_sanitizer.zip_handler import (
        cleanup_temp_dir,
        create_zip,
        extract_zip,
        is_zip_file,
    )

    cli_overrides: dict = {}
    if not skip_large_subnets:
        cli_overrides["settings"] = {"ip_pools": {"skip_large_ipv4_subnets": False}}

    try:
        cfg = load_config(
            config_path=config,
            profile_names=profile,
            cli_overrides=cli_overrides if cli_overrides else None,
        )
    except ConfigurationError as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        raise typer.Exit(1) from e

    sanitizer = Sanitizer(cfg)
    zip_input = is_zip_file(input_path)
    tmp_dir = None

    try:
        effective_input = input_path
        if zip_input:
            tmp_dir = extract_zip(input_path)
            effective_input = tmp_dir

        if dry_run:
            try:
                summary = sanitizer.run_dry(effective_input)
            except ProfileNotFoundError as e:
                console.print(f"[bold red]Profile error:[/bold red] {e}")
                raise typer.Exit(1) from e
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
            rosetta_path = sanitizer.run(effective_input, output)
        except ProfileNotFoundError as e:
            console.print(f"[bold red]Profile error:[/bold red] {e}")
            raise typer.Exit(1) from e
        except PoolExhaustedError as e:
            console.print(f"[bold red]Pool exhausted:[/bold red] {e}")
            raise typer.Exit(1) from e
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1) from e

        if zip_input and not no_zip:
            output_zip = output.with_suffix(".zip")
            rosetta_path.rename(output.parent / rosetta_path.name)
            rosetta_path = output.parent / rosetta_path.name
            create_zip(output, output_zip)
            import shutil

            shutil.rmtree(output)
            console.print("[green]Sanitization complete.[/green]")
            console.print(f"  Output: {output_zip}")
            console.print(f"  Rosetta Stone: {rosetta_path}")
        else:
            console.print("[green]Sanitization complete.[/green]")
            console.print(f"  Output: {output}")
            console.print(f"  Rosetta Stone: {rosetta_path}")
    finally:
        if tmp_dir:
            cleanup_temp_dir(tmp_dir)


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
