# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Tests for product profile loading and integration."""

import json

import pytest

from nac_sanitizer.config.models import PackConfig, RedactionRule, SanitizerConfig
from nac_sanitizer.engine.resolver import PathResolver
from nac_sanitizer.profiles.registry import ProfileNotFoundError, ProfileRegistry
from nac_sanitizer.sanitizer import Sanitizer


@pytest.mark.unit
class TestProfileRegistry:
    def test_sdwan_profile_available(self) -> None:
        available = ProfileRegistry.available()
        assert "sdwan" in available

    def test_load_sdwan_profile(self) -> None:
        profile = ProfileRegistry.load("sdwan")
        assert profile["name"] == "sdwan"
        assert "packs" in profile

    def test_load_nonexistent_raises_error(self) -> None:
        with pytest.raises(ProfileNotFoundError, match="not a recognized profile"):
            ProfileRegistry.load("nonexistent_profile")

    def test_load_rules_returns_redaction_rules(self) -> None:
        rules = ProfileRegistry.load_rules("sdwan")
        assert len(rules) > 0
        assert all(isinstance(r, RedactionRule) for r in rules)

    def test_sdwan_rules_have_valid_paths(self) -> None:
        """All paths in the SD-WAN profile should be parseable by jsonpath_ng."""
        rules = ProfileRegistry.load_rules("sdwan")
        resolver = PathResolver()
        for rule in rules:
            resolver.parse(rule.path)

    def test_sdwan_rules_have_valid_strategies(self) -> None:
        """All strategies referenced in the profile should be known."""
        valid_strategies = {
            "token",
            "ip_map",
            "hostname_map",
            "constant",
            "hash",
            "preserve_format",
        }
        rules = ProfileRegistry.load_rules("sdwan")
        for rule in rules:
            assert rule.strategy in valid_strategies, (
                f"Unknown strategy '{rule.strategy}' in path {rule.path}"
            )

    def test_sdwan_credentials_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("sdwan")
        cred_rules = [r for r in rules if r.category == "CREDENTIALS"]
        assert len(cred_rules) > 0
        assert all(r.tier == "default" for r in cred_rules)

    def test_sdwan_hostnames_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("sdwan")
        host_rules = [r for r in rules if r.category == "HOSTNAMES"]
        assert len(host_rules) > 0
        assert all(r.tier == "optional" for r in host_rules)


@pytest.mark.unit
class TestProfileIntegration:
    def test_sanitize_with_sdwan_profile(self, tmp_path) -> None:
        """End-to-end: SD-WAN profile redacts known sensitive fields."""
        data = {
            "device": [
                {
                    "data": {
                        "host-name": "vEdge-01",
                        "system-ip": "10.255.0.1",
                        "vipPasskey": "cisco123",
                    }
                }
            ]
        }
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["sdwan"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        raw = json.dumps(sanitized)
        assert "cisco123" not in raw
        assert "10.255.0.1" not in raw

    def test_optional_packs_excluded_by_default(self, tmp_path) -> None:
        """Optional-tier packs (hostnames, etc.) are not applied unless enabled."""
        data = {"device": {"host-name": "my-router", "system-ip": "10.1.1.1"}}
        input_file = tmp_path / "test.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["sdwan"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "test.json").read_text())
        # Hostname is optional tier - should NOT be redacted
        assert sanitized["device"]["host-name"] == "my-router"
        # IP addresses is default tier - should be redacted
        assert sanitized["device"]["system-ip"] != "10.1.1.1"

    def test_optional_packs_included_when_enabled(self, tmp_path) -> None:
        """Optional-tier packs are applied when explicitly enabled."""
        data = {"device": {"host-name": "my-router", "system-ip": "10.1.1.1"}}
        input_file = tmp_path / "test.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["sdwan"],
            packs=PackConfig(enable=["hostnames"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "test.json").read_text())
        # Hostname should now be redacted (optional pack enabled)
        assert sanitized["device"]["host-name"] != "my-router"

    def test_default_packs_disabled_when_specified(self, tmp_path) -> None:
        """Default-tier packs can be disabled by the user."""
        data = {"device": {"vipPasskey": "admin", "system-ip": "10.1.1.1"}}
        input_file = tmp_path / "test.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["sdwan"],
            packs=PackConfig(disable=["credentials"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "test.json").read_text())
        # Credentials disabled - vipPasskey should NOT be redacted
        assert sanitized["device"]["vipPasskey"] == "admin"
        # IP addresses still default - should be redacted
        assert sanitized["device"]["system-ip"] != "10.1.1.1"

    def test_profiles_list_shows_sdwan(self) -> None:
        """CLI profiles list should show sdwan."""
        from typer.testing import CliRunner

        from nac_sanitizer.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["profiles", "list"])
        assert result.exit_code == 0
        assert "sdwan" in result.output
