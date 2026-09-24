# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Core orchestrator that wires all components into the sanitization pipeline."""

import json
import logging
import re
from pathlib import Path
from typing import Any

from nac_sanitizer import __version__
from nac_sanitizer.config.models import RedactionRule, SanitizerConfig
from nac_sanitizer.engine.ip_allocator import IPAllocator
from nac_sanitizer.engine.ip_scanner import IPScanner, is_ip_like
from nac_sanitizer.engine.resolver import PathResolver
from nac_sanitizer.engine.strategies import StrategyRegistry
from nac_sanitizer.rosetta.writer import RosettaWriter

logger = logging.getLogger(__name__)


class Sanitizer:
    """Drives the end-to-end sanitization pipeline."""

    def __init__(self, config: SanitizerConfig) -> None:
        self._config = config
        self._resolver = PathResolver()
        self._ip_allocator = IPAllocator(
            ipv4_pools=config.settings.ip_pools.ipv4_pools,
            ipv4_multicast_pools=config.settings.ip_pools.ipv4_multicast_pools,
            ipv6_pools=config.settings.ip_pools.ipv6_pools,
            preserve_prefix_length=config.settings.ip_pools.preserve_prefix_length,
            default_ipv4_prefix=config.settings.ip_pools.default_ipv4_prefix,
            default_ipv6_prefix=config.settings.ip_pools.default_ipv6_prefix,
            skip_large_ipv4_subnets=config.settings.ip_pools.skip_large_ipv4_subnets,
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

        skipped = 0
        for file in input_files:
            logger.debug("Processing file: %s", file)
            data = self._load_json(file)
            if data is None:
                skipped += 1
                continue
            self._rosetta.add_source_file(str(file))
            unwrapped = self._unwrap_json_strings(data)
            data = self._ip_scanner.scan(data)
            data = self._sanitize_data(data, rules)
            if unwrapped:
                self._rewrap_json_strings(unwrapped)
            self._write_output(data, file, input_path, output_path)

        for original, sanitized in self._ip_scanner.mappings.items():
            self._rosetta.record(original, sanitized, "IP_ADDRESSES")

        processed = len(input_files) - skipped
        logger.info(
            "Sanitization complete: %d files processed, %d skipped",
            processed,
            skipped,
        )
        return self._rosetta.write(output_path)

    def run_dry(self, input_path: Path) -> dict:
        """Execute a dry run - report what would be redacted without writing files.

        Returns a summary of what would be redacted.
        """
        rules = self._build_rule_set()
        input_files = self._discover_input_files(input_path)

        summary: dict[str, int] = {}
        total_matches = 0

        for file in input_files:
            data = self._load_json(file)
            if data is None:
                continue

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
            filtered = self._filter_by_packs(profile_rules)
            logger.debug(
                "Loaded %d rules from profile '%s' (%d after pack filtering)",
                len(profile_rules),
                profile_name,
                len(filtered),
            )
            rules.extend(filtered)

        rules.extend(self._config.custom_rules)
        final = self._apply_overrides(rules)
        logger.debug("Final rule set: %d rules", len(final))
        return final

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

    # Minimum length for a candidate stringified-JSON value. Shortest useful
    # JSON container is "{}" or "[]" (len 2), but we require a bit more to
    # avoid wasting a json.loads() call on trivially empty containers.
    _MIN_STRINGIFIED_JSON_LEN = 2

    def _unwrap_json_strings(self, data: object) -> list[tuple[dict | list, Any]]:
        """Walk the JSON tree and unwrap strings that are themselves JSON.

        Some vManage exports store a nested JSON document as a string (e.g.
        ``feature_device_template[*].data.deviceTemplateVariables``). That
        opaque string can't be traversed by JSONPath rules, so bare IPs get
        caught by the embedded-IP regex but non-IP sensitive fields (hostnames,
        device IDs, etc.) inside it pass through untouched.

        This unwraps any string value that parses as JSON *and* decodes to a
        dict or list (not a bare string/number/bool/null - those aren't
        "stringified JSON objects", they're just primitives that happen to be
        valid JSON), replacing the string in-place with the parsed structure
        so the normal IP scan and rule pipeline can traverse into it.

        Returns a list of (container, key) locations that were unwrapped, so
        :meth:`_rewrap_json_strings` can re-serialize only those locations
        back to strings after sanitization runs.
        """
        unwrapped: list[tuple[dict | list, Any]] = []
        self._walk_and_unwrap(data, unwrapped)
        if unwrapped:
            logger.debug("Unwrapped %d stringified JSON value(s)", len(unwrapped))
        return unwrapped

    def _walk_and_unwrap(
        self, node: object, unwrapped: list[tuple[dict | list, Any]]
    ) -> None:
        """Recursively find and unwrap stringified JSON dicts/lists in-place."""
        if isinstance(node, dict):
            items: Any = node.items()
        elif isinstance(node, list):
            items = enumerate(node)
        else:
            return

        for key, value in list(items):
            if isinstance(value, str):
                parsed = self._try_parse_json_container(value)
                if parsed is not None:
                    node[key] = parsed
                    unwrapped.append((node, key))
                    self._walk_and_unwrap(parsed, unwrapped)
            elif isinstance(value, (dict, list)):
                self._walk_and_unwrap(value, unwrapped)

    def _try_parse_json_container(self, value: str) -> dict | list | None:
        """Try to parse a string as a JSON object/array.

        Uses a cheap pre-check before calling ``json.loads()`` to avoid the
        parsing cost on the vast majority of strings that are obviously not
        JSON. Only returns a result for values that decode to a ``dict`` or
        ``list`` - strings that happen to be valid JSON primitives (e.g.
        ``"true"``, ``"123"``, ``'"quoted"'``) are intentionally left alone.
        """
        if len(value) < self._MIN_STRINGIFIED_JSON_LEN:
            return None
        first, last = value[0], value[-1]
        if not ((first == "{" and last == "}") or (first == "[" and last == "]")):
            return None
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, (dict, list)):
            return parsed
        return None

    def _rewrap_json_strings(self, unwrapped: list[tuple[dict | list, Any]]) -> None:
        """Re-serialize previously unwrapped locations back to JSON strings.

        Processed in reverse (deepest-first) order so that a location nested
        inside another unwrapped location is re-serialized before its parent
        string is rebuilt from the now-sanitized structure.
        """
        for container, key in reversed(unwrapped):
            value = container[key]
            container[key] = json.dumps(value, separators=(",", ":"))

    _SIMPLE_DESCENT_RE = re.compile(r"^\$\.\.([a-zA-Z_][a-zA-Z0-9_-]*)$")

    def _sanitize_data(self, data: object, rules: list[RedactionRule]) -> object:
        """Apply all rules to a JSON data structure."""
        simple_rules: dict[str, RedactionRule] = {}
        complex_rules: list[RedactionRule] = []

        for rule in rules:
            match = self._SIMPLE_DESCENT_RE.match(rule.path)
            if match:
                simple_rules[match.group(1)] = rule
            else:
                complex_rules.append(rule)

        if simple_rules:
            self._apply_simple_rules(data, simple_rules)

        for rule in complex_rules:
            self._apply_jsonpath_rule(data, rule)

        return data

    def _apply_simple_rules(
        self, data: object, rules: dict[str, RedactionRule]
    ) -> None:
        """Apply all $..field rules in a single tree walk."""
        applied: dict[str, int] = {}
        self._walk_and_redact(data, rules, applied)
        for field, count in applied.items():
            rule = rules[field]
            logger.debug(
                "Rule '$..%s' (%s): %d values redacted",
                field,
                rule.strategy,
                count,
            )

    def _walk_and_redact(
        self,
        node: Any,
        rules: dict[str, RedactionRule],
        applied: dict[str, int],
    ) -> None:
        """Recursively walk JSON and redact matching field names in-place."""
        if isinstance(node, dict):
            for key in node:
                value = node[key]
                if key in rules and isinstance(value, (str, int, float)):
                    if value != "" and value is not None and not is_ip_like(str(value)):
                        rule = rules[key]
                        try:
                            sanitized = self._strategies.apply(
                                rule.strategy, value, rule.category
                            )
                        except (ValueError, KeyError) as e:
                            logger.warning(
                                "Strategy '%s' failed for '$..%s' value '%s': %s",
                                rule.strategy,
                                key,
                                value,
                                e,
                            )
                            continue
                        self._rosetta.record(str(value), sanitized, rule.category)
                        node[key] = sanitized
                        applied[key] = applied.get(key, 0) + 1
                elif key in rules and isinstance(value, list):
                    rule = rules[key]
                    for i, elem in enumerate(value):
                        if isinstance(elem, (str, int, float)) and elem != "":
                            try:
                                sanitized = self._strategies.apply(
                                    rule.strategy, elem, rule.category
                                )
                            except (ValueError, KeyError) as e:
                                logger.warning(
                                    "Strategy '%s' failed for '$..%s[%d]' value '%s': %s",
                                    rule.strategy,
                                    key,
                                    i,
                                    elem,
                                    e,
                                )
                                continue
                            self._rosetta.record(str(elem), sanitized, rule.category)
                            value[i] = sanitized
                            applied[key] = applied.get(key, 0) + 1
                        elif isinstance(elem, (dict, list)):
                            self._walk_and_redact(elem, rules, applied)
                elif isinstance(value, (dict, list)):
                    self._walk_and_redact(value, rules, applied)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, (dict, list)):
                    self._walk_and_redact(item, rules, applied)

    def _apply_jsonpath_rule(self, data: object, rule: RedactionRule) -> None:
        """Apply a single complex JSONPath rule using the resolver."""
        matches = self._resolver.find_matches(rule.path, data)
        applied = 0
        total = len(matches)
        for match in matches:
            original = match.value
            if not isinstance(original, (str, int, float)):
                continue
            if original == "" or original is None:
                continue
            if is_ip_like(str(original)):
                continue
            try:
                sanitized = self._strategies.apply(
                    rule.strategy, original, rule.category
                )
            except (ValueError, KeyError) as e:
                logger.warning(
                    "Strategy '%s' failed for path '%s' value '%s': %s",
                    rule.strategy,
                    rule.path,
                    original,
                    e,
                )
                continue
            self._rosetta.record(str(original), sanitized, rule.category)
            self._resolver.update_value(match, data, sanitized)
            applied += 1
            if applied % 1000 == 0:
                logger.debug(
                    "Rule '%s' (%s): %d/%d matches processed",
                    rule.path,
                    rule.strategy,
                    applied,
                    total,
                )
        if applied:
            logger.debug(
                "Rule '%s' (%s): %d values redacted",
                rule.path,
                rule.strategy,
                applied,
            )

    def _discover_input_files(self, path: Path) -> list[Path]:
        """Find all JSON files to process."""
        if path.is_file():
            return [path]
        files = sorted(path.rglob("*.json"))
        logger.debug("Discovered %d input files in %s", len(files), path)
        return files

    def _load_json(self, path: Path) -> object | None:
        """Load a JSON file, returning None if the file contains invalid JSON."""
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning("Skipping %s: malformed JSON (%s)", path, exc)
            return None

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
        dest.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
