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
class TestISEProfileRegistry:
    def test_ise_profile_available(self) -> None:
        available = ProfileRegistry.available()
        assert "ise" in available

    def test_load_ise_profile(self) -> None:
        profile = ProfileRegistry.load("ise")
        assert profile["name"] == "ise"
        assert "packs" in profile

    def test_ise_rules_have_valid_paths(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        resolver = PathResolver()
        for rule in rules:
            resolver.parse(rule.path)

    def test_ise_rules_have_valid_strategies(self) -> None:
        valid_strategies = {
            "token",
            "ip_map",
            "hostname_map",
            "constant",
            "hash",
            "preserve_format",
        }
        rules = ProfileRegistry.load_rules("ise")
        for rule in rules:
            assert rule.strategy in valid_strategies, (
                f"Unknown strategy '{rule.strategy}' in path {rule.path}"
            )

    def test_ise_credentials_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        cred_rules = [r for r in rules if r.category == "CREDENTIALS"]
        assert len(cred_rules) > 0
        assert all(r.tier == "default" for r in cred_rules)

    def test_ise_snmp_communities_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        snmp_rules = [r for r in rules if r.category == "SNMP_COMMUNITIES"]
        assert len(snmp_rules) > 0
        assert all(r.tier == "default" for r in snmp_rules)

    def test_ise_usernames_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        user_rules = [r for r in rules if r.category == "USERNAMES"]
        assert len(user_rules) > 0
        assert all(r.tier == "optional" for r in user_rules)


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

    def test_sanitize_with_ise_profile_redacts_credentials(self, tmp_path) -> None:
        """ISE profile default-tier credentials pack redacts RADIUS shared secrets."""
        data = {
            "network_device": [
                {
                    "data": {
                        "NetworkDevice": {
                            "name": "lab-switch-01",
                            "authenticationSettings": {
                                "networkProtocol": "RADIUS",
                                "radiusSharedSecret": "S3cur3R@dius!",
                                "enableKeyWrap": False,
                            },
                            "profileName": "Cisco",
                            "coaPort": 1700,
                        }
                    },
                    "endpoint": "/ers/config/networkdevice/abc-123",
                }
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        raw = json.dumps(sanitized)
        assert "S3cur3R@dius!" not in raw
        # Non-sensitive fields preserved
        assert (
            sanitized["network_device"][0]["data"]["NetworkDevice"]["name"]
            == "lab-switch-01"
        )
        assert (
            sanitized["network_device"][0]["data"]["NetworkDevice"]["coaPort"] == 1700
        )

    def test_sanitize_with_ise_profile_redacts_snmp_communities(self, tmp_path) -> None:
        """ISE profile default-tier snmp_communities pack redacts RO/RW community strings."""
        data = {
            "network_device": [
                {
                    "data": {
                        "NetworkDevice": {
                            "name": "lab-router-02",
                            "snmpsettings": {
                                "version": "TWO_C",
                                "roCommunity": "pub1ic-str1ng",
                                "rwCommunity": "priv@te-str1ng",
                                "pollingInterval": 3600,
                                "linkTrapQuery": True,
                            },
                        }
                    },
                    "endpoint": "/ers/config/networkdevice/def-456",
                }
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        raw = json.dumps(sanitized)
        assert "pub1ic-str1ng" not in raw
        assert "priv@te-str1ng" not in raw
        # Non-sensitive SNMP settings preserved
        nd = sanitized["network_device"][0]["data"]["NetworkDevice"]
        assert nd["snmpsettings"]["pollingInterval"] == 3600
        assert nd["snmpsettings"]["linkTrapQuery"] is True

    def test_sanitize_with_ise_profile_redacts_all_secret_variants(
        self, tmp_path
    ) -> None:
        """ISE profile redacts sharedSecret and previousSharedSecret in addition to radiusSharedSecret."""
        data = {
            "network_device": [
                {
                    "data": {
                        "NetworkDevice": {
                            "name": "lab-wlc-03",
                            "authenticationSettings": {
                                "radiusSharedSecret": "Current$ecret",
                                "previousSharedSecret": "Old$ecret123",
                            },
                            "tacacsSettings": {
                                "sharedSecret": "T@cacs$ecret",
                            },
                        }
                    },
                    "endpoint": "/ers/config/networkdevice/ghi-789",
                }
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        raw = json.dumps(sanitized)
        assert "Current$ecret" not in raw
        assert "Old$ecret123" not in raw
        assert "T@cacs$ecret" not in raw

    def test_sanitize_with_ise_profile_redacts_internal_user_passwords(
        self, tmp_path
    ) -> None:
        """ISE profile default-tier credentials pack redacts password and enablePassword from InternalUser."""
        data = {
            "internal_user": [
                {
                    "data": {
                        "InternalUser": {
                            "id": "950ef99a-7a1a-4806-87f1-e4a0373df036",
                            "name": "jsmith",
                            "enabled": True,
                            "password": "Cl3@rT3xt!",
                            "enablePassword": "En@bl3P@ss!",
                            "changePassword": False,
                            "identityGroups": "b73e0f80-42a9-11f1-8113-00505685e554",
                            "passwordNeverExpires": False,
                        }
                    },
                    "endpoint": "/ers/config/internaluser/950ef99a-7a1a-4806-87f1-e4a0373df036",
                }
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        raw = json.dumps(sanitized)
        assert "Cl3@rT3xt!" not in raw
        assert "En@bl3P@ss!" not in raw
        user = sanitized["internal_user"][0]["data"]["InternalUser"]
        assert user["name"] == "jsmith"
        assert user["enabled"] is True
        assert user["identityGroups"] == "b73e0f80-42a9-11f1-8113-00505685e554"

    def test_ise_optional_packs_excluded_by_default(self, tmp_path) -> None:
        """ISE optional-tier packs (usernames, mac_addresses, domains) are not applied by default."""
        data = {
            "endpoint": [
                {
                    "data": {
                        "ERSEndPoint": {
                            "id": "aaaa-bbbb-cccc",
                            "name": "AA:BB:CC:DD:EE:FF",
                            "mac": "AA:BB:CC:DD:EE:FF",
                            "staticProfileAssignment": False,
                        }
                    },
                    "endpoint": "/ers/config/endpoint/aaaa-bbbb-cccc",
                }
            ],
            "internal_user": [
                {
                    "data": {
                        "InternalUser": {
                            "name": "jsmith",
                            "userName": "jsmith",
                            "domain": "corp.example.com",
                        }
                    },
                    "endpoint": "/ers/config/internaluser/dddd-eeee",
                }
            ],
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        # Optional packs should NOT be redacted by default
        ers = sanitized["endpoint"][0]["data"]["ERSEndPoint"]
        assert ers["mac"] == "AA:BB:CC:DD:EE:FF"
        user = sanitized["internal_user"][0]["data"]["InternalUser"]
        assert user["userName"] == "jsmith"
        assert user["domain"] == "corp.example.com"

    def test_ise_optional_packs_applied_when_enabled(self, tmp_path) -> None:
        """ISE optional-tier packs redact when explicitly enabled."""
        data = {
            "endpoint": [
                {
                    "data": {
                        "ERSEndPoint": {
                            "id": "aaaa-bbbb-cccc",
                            "mac": "AA:BB:CC:DD:EE:FF",
                        }
                    },
                    "endpoint": "/ers/config/endpoint/aaaa-bbbb-cccc",
                }
            ],
            "internal_user": [
                {
                    "data": {
                        "InternalUser": {
                            "userName": "jsmith",
                            "domain": "corp.example.com",
                        }
                    },
                    "endpoint": "/ers/config/internaluser/dddd-eeee",
                }
            ],
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["usernames", "mac_addresses", "domains"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        ers = sanitized["endpoint"][0]["data"]["ERSEndPoint"]
        assert ers["mac"] != "AA:BB:CC:DD:EE:FF"
        user = sanitized["internal_user"][0]["data"]["InternalUser"]
        assert user["userName"] != "jsmith"
        assert user["domain"] != "corp.example.com"
