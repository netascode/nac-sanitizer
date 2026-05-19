# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Core orchestrator that wires all components into the sanitization pipeline."""

import json
from pathlib import Path

from nac_sanitizer import __version__
from nac_sanitizer.config.models import RedactionRule, SanitizerConfig
from nac_sanitizer.engine.ip_allocator import IPAllocator
from nac_sanitizer.engine.ip_scanner import IPScanner
from nac_sanitizer.engine.resolver import PathResolver
from nac_sanitizer.engine.strategies import StrategyRegistry
from nac_sanitizer.rosetta.writer import RosettaWriter


class Sanitizer:
    """Drives the end-to-end sanitization pipeline."""

    def __init__(self, config: SanitizerConfig) -> None:
        self._config = config
        self._resolver = PathResolver()
        self._ip_allocator = IPAllocator(
            ipv4_pools=config.settings.ip_pools.ipv4_pools,
            ipv6_pools=config.settings.ip_pools.ipv6_pools,
            preserve_prefix_length=config.settings.ip_pools.preserve_prefix_length,
            default_ipv4_prefix=config.settings.ip_pools.default_ipv4_prefix,
            default_ipv6_prefix=config.settings.ip_pools.default_ipv6_prefix,
        )
        self._ip_scanner = IPScanner(self._ip_allocator)
        self._strategies = self._build_strategy_registry()
        self._rosetta = RosettaWriter(tool_version=__version__)

    def _build_strategy_registry(self) -> StrategyRegistry:
        registry = StrategyRegistry()
        return registry

    def run(self, input_path: Path, output_path: Path) -> Path:
        """Execute the sanitization pipeline.

        Returns the path to the Rosetta Stone file.
        """
        rules = self._build_rule_set()
        input_files = self._discover_input_files(input_path)

        output_path.mkdir(parents=True, exist_ok=True)

        for file in input_files:
            self._rosetta.add_source_file(str(file))
            data = self._load_json(file)
            data = self._ip_scanner.scan(data)
            data = self._sanitize_data(data, rules)
            self._write_output(data, file, input_path, output_path)

        for original, sanitized in self._ip_scanner.mappings.items():
            self._rosetta.record(original, sanitized, "IP_ADDRESSES")

        return self._rosetta.write(output_path)

    def run_dry(self, input_path: Path) -> dict:
        """Execute a dry run - report what would be redacted without writing files.

        Returns a summary of what would be redacted.
        """
        from nac_sanitizer.engine.ip_scanner import is_ip_like

        rules = self._build_rule_set()
        input_files = self._discover_input_files(input_path)

        summary: dict[str, int] = {}
        total_matches = 0

        for file in input_files:
            data = self._load_json(file)

            ip_count = self._count_ip_values(data)
            if ip_count:
                summary["IP_ADDRESSES"] = summary.get("IP_ADDRESSES", 0) + ip_count
                total_matches += ip_count

            for rule in rules:
                matches = self._resolver.find_matches(rule.path, data)
                non_null = [
                    m
                    for m in matches
                    if isinstance(m.value, (str, int, float))
                    and m.value != ""
                    and not is_ip_like(str(m.value))
                ]
                if non_null:
                    category = rule.category or rule.strategy
                    summary[category] = summary.get(category, 0) + len(non_null)
                    total_matches += len(non_null)

        return {
            "files_scanned": len(input_files),
            "total_matches": total_matches,
            "by_category": summary,
        }

    def _count_ip_values(self, node: object) -> int:
        """Count IP-like string values in a JSON tree."""
        from nac_sanitizer.engine.ip_scanner import is_ip_like

        count = 0
        if isinstance(node, dict):
            for value in node.values():
                if isinstance(value, str) and value and is_ip_like(value):
                    count += 1
                elif isinstance(value, (dict, list)):
                    count += self._count_ip_values(value)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, str) and item and is_ip_like(item):
                    count += 1
                elif isinstance(item, (dict, list)):
                    count += self._count_ip_values(item)
        return count

    def _build_rule_set(self) -> list[RedactionRule]:
        """Assemble the final rule set from config layers."""
        from nac_sanitizer.profiles.registry import ProfileRegistry

        rules: list[RedactionRule] = []

        for profile_name in self._config.profiles:
            profile_rules = ProfileRegistry.load_rules(profile_name)
            rules.extend(self._filter_by_packs(profile_rules))

        rules.extend(self._config.custom_rules)
        return self._apply_overrides(rules)

    def _filter_by_packs(self, rules: list[RedactionRule]) -> list[RedactionRule]:
        """Filter profile rules based on pack enable/disable configuration."""
        packs_enable = set(self._config.packs.enable)
        packs_disable = set(self._config.packs.disable)

        filtered: list[RedactionRule] = []
        for rule in rules:
            category_lower = (rule.category or "").lower()

            if category_lower in packs_disable:
                continue

            if rule.tier == "optional" and category_lower not in packs_enable:
                continue

            filtered.append(rule)
        return filtered

    def _apply_overrides(self, rules: list[RedactionRule]) -> list[RedactionRule]:
        """Apply user overrides to the rule set."""
        skip_paths = {o.path for o in self._config.overrides if o.tier == "skip"}
        filtered = [r for r in rules if r.path not in skip_paths]

        for override in self._config.overrides:
            if override.tier == "skip":
                continue
            filtered.append(
                RedactionRule(
                    path=override.path,
                    strategy=override.strategy or "token",
                    tier=override.tier,
                )
            )

        return filtered

    def _sanitize_data(self, data: object, rules: list[RedactionRule]) -> object:
        """Apply all rules to a JSON data structure."""
        for rule in rules:
            matches = self._resolver.find_matches(rule.path, data)
            for match in matches:
                original = match.value
                if not isinstance(original, (str, int, float)):
                    continue
                if original == "" or original is None:
                    continue
                try:
                    sanitized = self._strategies.apply(
                        rule.strategy, original, rule.category
                    )
                except (ValueError, KeyError):
                    continue
                self._rosetta.record(str(original), sanitized, rule.category)
                self._resolver.update_value(match, data, sanitized)
        return data

    def _discover_input_files(self, path: Path) -> list[Path]:
        """Find all JSON files to process."""
        if path.is_file():
            return [path]
        return sorted(path.rglob("*.json"))

    def _load_json(self, path: Path) -> object:
        """Load a JSON file."""
        return json.loads(path.read_text())

    def _write_output(
        self, data: object, source_file: Path, input_path: Path, output_path: Path
    ) -> None:
        """Write sanitized JSON preserving relative path structure."""
        if input_path.is_file():
            relative = source_file.name
        else:
            relative = source_file.relative_to(input_path)

        dest = output_path / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(data, indent=2, ensure_ascii=False))
