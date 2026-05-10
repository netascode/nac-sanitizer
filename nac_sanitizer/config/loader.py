"""Configuration loading and layer merging."""

from pathlib import Path
from typing import Any

from pydantic import ValidationError
from ruamel.yaml import YAML

from nac_sanitizer.config.models import SanitizerConfig


class ConfigurationError(Exception):
    """Raised when configuration is invalid or cannot be loaded."""


def load_config(
    config_path: Path | None = None,
    profile_names: list[str] | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> SanitizerConfig:
    """Load and merge configuration from all layers.

    Merge order (lowest to highest precedence):
    1. Built-in defaults (SanitizerConfig with no arguments)
    2. User configuration file (if provided)
    3. CLI overrides (if provided)
    """
    config_data: dict[str, Any] = {}

    if config_path:
        config_data = _parse_yaml_file(config_path)

    if profile_names:
        config_data.setdefault("profiles", [])
        for name in profile_names:
            if name not in config_data["profiles"]:
                config_data["profiles"].append(name)

    if cli_overrides:
        config_data = _merge_cli_overrides(config_data, cli_overrides)

    try:
        return SanitizerConfig.model_validate(config_data)
    except ValidationError as e:
        raise ConfigurationError(
            f"Invalid configuration: {e.error_count()} validation error(s)\n{e}"
        ) from e


def _parse_yaml_file(path: Path) -> dict[str, Any]:
    """Parse a YAML configuration file."""
    if not path.exists():
        raise ConfigurationError(f"Configuration file not found: {path}")

    if not path.is_file():
        raise ConfigurationError(f"Configuration path is not a file: {path}")

    yaml = YAML(typ="safe")
    try:
        data = yaml.load(path)
    except Exception as e:
        raise ConfigurationError(
            f"Failed to parse YAML configuration: {path}\n{e}"
        ) from e

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"Configuration file must contain a YAML mapping, got {type(data).__name__}: {path}"
        )

    return data


def _merge_cli_overrides(
    config_data: dict[str, Any], overrides: dict[str, Any]
) -> dict[str, Any]:
    """Merge CLI overrides into config data."""
    for key, value in overrides.items():
        if value is not None:
            config_data[key] = value
    return config_data
