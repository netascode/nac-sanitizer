# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Profile discovery and loading from bundled resources."""

import importlib.resources

from ruamel.yaml import YAML

from nac_sanitizer.config.models import RedactionRule


class ProfileNotFoundError(Exception):
    """Raised when a requested profile does not exist."""


class ProfileRegistry:
    """Discovers and loads bundled product profiles."""

    @staticmethod
    def available() -> list[str]:
        """List all available profile names."""
        resources = importlib.resources.files("nac_sanitizer.resources.profiles")
        names = []
        for item in resources.iterdir():
            if hasattr(item, "name") and item.name.endswith(".yaml"):
                names.append(item.name.removesuffix(".yaml"))
        return sorted(names)

    @staticmethod
    def load(name: str) -> dict:
        """Load a profile by name."""
        resources = importlib.resources.files("nac_sanitizer.resources.profiles")
        profile_file = resources.joinpath(f"{name}.yaml")

        try:
            content = profile_file.read_text()
        except (FileNotFoundError, TypeError) as e:
            available = ", ".join(ProfileRegistry.available())
            raise ProfileNotFoundError(
                f"'{name}' is not a recognized profile. "
                f"Check your --profile argument. "
                f"Available profiles: {available}"
            ) from e

        yaml = YAML(typ="safe")
        return yaml.load(content)

    @staticmethod
    def load_rules(name: str) -> list[RedactionRule]:
        """Load and flatten a profile into a list of RedactionRule objects."""
        profile = ProfileRegistry.load(name)
        rules: list[RedactionRule] = []

        for pack_name, pack_def in profile.get("packs", {}).items():
            for path in pack_def.get("paths", []):
                rules.append(
                    RedactionRule(
                        path=path,
                        strategy=pack_def["strategy"],
                        tier=pack_def.get("tier", "default"),
                        category=pack_name.upper(),
                    )
                )

        for rule_def in profile.get("rules", []):
            rules.append(RedactionRule(**rule_def))

        return rules
