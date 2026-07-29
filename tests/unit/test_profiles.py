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

    def test_sdwan_policy_object_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("sdwan")
        policy_object_rules = [r for r in rules if r.category == "POLICY_OBJECT_NAMES"]
        assert len(policy_object_rules) > 0
        assert all(r.tier == "optional" for r in policy_object_rules)


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

    def test_ise_tacacs_profiles_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        tacacs_rules = [r for r in rules if r.category == "TACACS_PROFILES"]
        assert len(tacacs_rules) > 0
        assert all(r.tier == "optional" for r in tacacs_rules)

    def test_ise_tacacs_profiles_pack_is_token_strategy(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        tacacs_rules = [r for r in rules if r.category == "TACACS_PROFILES"]
        assert len(tacacs_rules) > 0
        assert all(r.strategy == "token" for r in tacacs_rules)

    def test_ise_tacacs_profiles_pack_paths(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        tacacs_paths = {r.path for r in rules if r.category == "TACACS_PROFILES"}
        assert tacacs_paths == {
            "$.tacacs_profile[*].data.name",
            "$.tacacs_profile[*].data.description",
            "$.tacacs_profile[*].data.sessionAttributes.sessionAttributeList[*].name",
            "$.tacacs_profile[*].data.sessionAttributes.sessionAttributeList[*].value",
            "$.tacacs_command_set[*].data.name",
            "$.tacacs_command_set[*].data.description",
        }


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

    @staticmethod
    def _tacacs_data() -> dict:
        return {
            "tacacs_profile": [
                {
                    "data": {
                        "id": "73d232c0-f351-11ee-8954-a21daf388194",
                        "name": "Aruba-Root-Shell",
                        "description": "Root Level Privileges for Aruba Controllers Admins",
                        "sessionAttributes": {
                            "sessionAttributeList": [
                                {
                                    "type": "MANDATORY",
                                    "name": "service-type",
                                    "value": "root",
                                }
                            ]
                        },
                        "link": {
                            "rel": "self",
                            "href": "https://10.0.0.140/ers/config/tacacsprofile/73d232c0-f351-11ee-8954-a21daf388194",
                            "type": "application/json",
                        },
                    },
                    "endpoint": "/ers/config/tacacsprofile/73d232c0-f351-11ee-8954-a21daf388194",
                },
                {
                    "data": {
                        "id": "9bad4c20-f36b-11ee-8954-a21daf388194",
                        "name": "AirWaves-Admin-Profile",
                        "description": "Administrator Privileges for AirWaves Admins",
                        "sessionAttributes": {
                            "sessionAttributeList": [
                                {
                                    "type": "MANDATORY",
                                    "name": "priv-lvl",
                                    "value": "15",
                                }
                            ]
                        },
                        "link": {
                            "rel": "self",
                            "href": "https://10.0.0.140/ers/config/tacacsprofile/9bad4c20-f36b-11ee-8954-a21daf388194",
                            "type": "application/json",
                        },
                    },
                    "endpoint": "/ers/config/tacacsprofile/9bad4c20-f36b-11ee-8954-a21daf388194",
                },
            ],
            "tacacs_command_set": [
                {
                    "data": {
                        "id": "96373ea0-9f5a-11ee-94be-faa732630355",
                        "name": "DNAC-Full-Admin",
                        "description": "DNAC Admin",
                        "permitUnmatched": True,
                        "commands": {"commandList": []},
                        "link": {
                            "rel": "self",
                            "href": "https://10.0.0.140/ers/config/tacacscommandsets/96373ea0-9f5a-11ee-94be-faa732630355",
                            "type": "application/json",
                        },
                    },
                    "endpoint": "/ers/config/tacacscommandsets/96373ea0-9f5a-11ee-94be-faa732630355",
                },
                {
                    "data": {
                        "id": "b672bd70-9f5a-11ee-94be-faa732630355",
                        "name": "DNAC-ReadOnly",
                        "description": "DNAC Observer (Read Only)",
                        "permitUnmatched": False,
                        "commands": {"commandList": []},
                        "link": {
                            "rel": "self",
                            "href": "https://10.0.0.140/ers/config/tacacscommandsets/b672bd70-9f5a-11ee-94be-faa732630355",
                            "type": "application/json",
                        },
                    },
                    "endpoint": "/ers/config/tacacscommandsets/b672bd70-9f5a-11ee-94be-faa732630355",
                },
            ],
        }

    def test_ise_tacacs_profiles_pack_excluded_by_default(self, tmp_path) -> None:
        """ISE tacacs_profiles pack (optional tier) is not applied unless enabled."""
        data = self._tacacs_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        profile = sanitized["tacacs_profile"][0]["data"]
        assert profile["name"] == "Aruba-Root-Shell"
        assert (
            profile["description"]
            == "Root Level Privileges for Aruba Controllers Admins"
        )
        attr = profile["sessionAttributes"]["sessionAttributeList"][0]
        assert attr["name"] == "service-type"
        assert attr["value"] == "root"
        cmd_set = sanitized["tacacs_command_set"][0]["data"]
        assert cmd_set["name"] == "DNAC-Full-Admin"
        assert cmd_set["description"] == "DNAC Admin"

    def test_ise_tacacs_profiles_pack_applied_when_enabled(self, tmp_path) -> None:
        """ISE tacacs_profiles pack redacts names/descriptions/session attrs when enabled."""
        data = self._tacacs_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["tacacs_profiles"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        raw = json.dumps(sanitized)

        # Sensitive fields redacted
        assert "Aruba-Root-Shell" not in raw
        assert "AirWaves-Admin-Profile" not in raw
        assert "Root Level Privileges for Aruba Controllers Admins" not in raw
        assert "Administrator Privileges for AirWaves Admins" not in raw
        assert "service-type" not in raw
        assert "priv-lvl" not in raw
        assert "DNAC-Full-Admin" not in raw
        assert "DNAC-ReadOnly" not in raw
        assert "DNAC Admin" not in raw
        assert "DNAC Observer (Read Only)" not in raw

        profile_0 = sanitized["tacacs_profile"][0]["data"]
        profile_1 = sanitized["tacacs_profile"][1]["data"]
        attr_0 = profile_0["sessionAttributes"]["sessionAttributeList"][0]
        attr_1 = profile_1["sessionAttributes"]["sessionAttributeList"][0]

        # Non-sensitive fields preserved
        assert profile_0["id"] == "73d232c0-f351-11ee-8954-a21daf388194"
        assert profile_1["id"] == "9bad4c20-f36b-11ee-8954-a21daf388194"
        assert attr_0["type"] == "MANDATORY"
        assert attr_1["type"] == "MANDATORY"
        assert (
            profile_0["link"]["href"]
            == "https://10.0.0.140/ers/config/tacacsprofile/73d232c0-f351-11ee-8954-a21daf388194"
        )

        cmd_set_0 = sanitized["tacacs_command_set"][0]["data"]
        cmd_set_1 = sanitized["tacacs_command_set"][1]["data"]
        assert cmd_set_0["id"] == "96373ea0-9f5a-11ee-94be-faa732630355"
        assert cmd_set_1["id"] == "b672bd70-9f5a-11ee-94be-faa732630355"
        assert cmd_set_0["permitUnmatched"] is True
        assert cmd_set_1["permitUnmatched"] is False
        assert cmd_set_0["commands"] == {"commandList": []}

    @staticmethod
    def _policy_object_data() -> dict:
        return {
            "vpn_list_policy_object": [
                {
                    "data": {
                        "listId": "vpn-001",
                        "name": "CLASSIFIED",
                        "type": "vpn",
                        "entries": [{"vpn": "200"}],
                        "readOnly": False,
                        "referenceCount": 5,
                    },
                    "endpoint": "/template/policy/list/vpn//CLASSIFIED",
                },
                {
                    "data": {
                        "listId": "vpn-002",
                        "name": "CORPORATE-VPN",
                        "type": "vpn",
                        "entries": [{"vpn": "1100"}],
                        "readOnly": False,
                        "referenceCount": 3,
                    },
                    "endpoint": "/template/policy/list/vpn//CORPORATE-VPN",
                },
            ],
            "site_list_policy_object": [
                {
                    "data": {
                        "listId": "site-001",
                        "name": "ALL-DATACENTERS",
                        "type": "site",
                        "entries": [{"siteId": "1-9"}],
                        "readOnly": False,
                        "referenceCount": 0,
                    },
                    "endpoint": "/template/policy/list/site//ALL-DATACENTERS",
                }
            ],
            "ipv4_prefix_list_policy_object": [
                {
                    "data": {
                        "listId": "pfx-001",
                        "name": "DC-MGMT-PREFIXES",
                        "type": "dataPrefix",
                        "entries": [{"ipPrefix": "10.10.0.0/16"}],
                        "readOnly": False,
                    },
                    "endpoint": "/template/policy/list/dataprefix//DC-MGMT-PREFIXES",
                }
            ],
            "data_ipv4_prefix_list_policy_object": [
                {
                    "data": {
                        "listId": "dpfx-001",
                        "name": "BRANCH-SUBNETS",
                        "type": "dataPrefix",
                        "entries": [{"ipPrefix": "172.16.20.0/24"}],
                        "readOnly": False,
                    },
                    "endpoint": "/template/policy/list/dataprefix//BRANCH-SUBNETS",
                }
            ],
            "preferred_color_group_policy_object": [
                {
                    "data": {
                        "listId": "pcg-001",
                        "name": "PREFER-MPLS-BKUP-INET",
                        "type": "preferredColorGroup",
                        "entries": [
                            {
                                "primaryColor": "mpls",
                                "secondaryColor": "biz-internet",
                            }
                        ],
                        "readOnly": False,
                    },
                    "endpoint": "/template/policy/list/preferredcolorgroup//PREFER-MPLS-BKUP-INET",
                }
            ],
            "standard_community_list_policy_object": [
                {
                    "data": {
                        "listId": "comm-001",
                        "name": "BACKBONE-COMMUNITIES",
                        "type": "community",
                        "entries": [{"community": "65000:100"}],
                        "readOnly": False,
                    },
                    "endpoint": "/template/policy/list/community//BACKBONE-COMMUNITIES",
                }
            ],
        }

    def test_sdwan_policy_object_names_excluded_by_default(self, tmp_path) -> None:
        """SD-WAN policy_object_names pack (optional tier) is not applied by default."""
        data = self._policy_object_data()
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["sdwan"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        for key, expected in data.items():
            for expected_item, actual_item in zip(
                expected, sanitized[key], strict=True
            ):
                assert actual_item["data"]["name"] == expected_item["data"]["name"]
                assert actual_item["endpoint"] == expected_item["endpoint"]

    def test_sdwan_policy_object_names_redacts_when_enabled(self, tmp_path) -> None:
        """SD-WAN policy_object_names pack redacts names/endpoints when enabled."""
        data = self._policy_object_data()
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["sdwan"],
            packs=PackConfig(enable=["policy_object_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        raw = json.dumps(sanitized)

        # All object names redacted
        assert "CLASSIFIED" not in raw
        assert "CORPORATE-VPN" not in raw
        assert "ALL-DATACENTERS" not in raw
        assert "DC-MGMT-PREFIXES" not in raw
        assert "BRANCH-SUBNETS" not in raw
        assert "PREFER-MPLS-BKUP-INET" not in raw
        assert "BACKBONE-COMMUNITIES" not in raw

        expected_names = {
            "vpn_list_policy_object": [
                "POLICY_OBJECT_NAMES-001",
                "POLICY_OBJECT_NAMES-002",
            ],
            "site_list_policy_object": ["POLICY_OBJECT_NAMES-003"],
            "ipv4_prefix_list_policy_object": ["POLICY_OBJECT_NAMES-004"],
            "data_ipv4_prefix_list_policy_object": ["POLICY_OBJECT_NAMES-005"],
            "preferred_color_group_policy_object": ["POLICY_OBJECT_NAMES-006"],
            "standard_community_list_policy_object": ["POLICY_OBJECT_NAMES-007"],
        }
        expected_endpoints = {
            "vpn_list_policy_object": [
                "POLICY_OBJECT_NAMES-008",
                "POLICY_OBJECT_NAMES-009",
            ],
            "site_list_policy_object": ["POLICY_OBJECT_NAMES-010"],
            "ipv4_prefix_list_policy_object": ["POLICY_OBJECT_NAMES-011"],
            "data_ipv4_prefix_list_policy_object": ["POLICY_OBJECT_NAMES-012"],
            "preferred_color_group_policy_object": ["POLICY_OBJECT_NAMES-013"],
            "standard_community_list_policy_object": ["POLICY_OBJECT_NAMES-014"],
        }
        for key in data:
            for i, actual_item in enumerate(sanitized[key]):
                assert actual_item["data"]["name"] == expected_names[key][i]
                assert actual_item["endpoint"] == expected_endpoints[key][i]

        # Non-sensitive fields preserved
        vpn_0 = sanitized["vpn_list_policy_object"][0]["data"]
        assert vpn_0["listId"] == "vpn-001"
        assert vpn_0["type"] == "vpn"
        assert vpn_0["entries"] == [{"vpn": "200"}]
        assert vpn_0["readOnly"] is False
        assert vpn_0["referenceCount"] == 5

        site_0 = sanitized["site_list_policy_object"][0]["data"]
        assert site_0["listId"] == "site-001"
        assert site_0["type"] == "site"
        assert site_0["entries"] == [{"siteId": "1-9"}]

        # Note: the "ipPrefix" entry values are IP-shaped strings, so the
        # sanitizer's separate, always-on IP scanner redacts them too. That
        # is expected, unrelated behavior - independent of the
        # policy_object_names pack under test here. We only assert that the
        # entries structure (keys) is preserved, not the literal IP value.
        pfx_0 = sanitized["ipv4_prefix_list_policy_object"][0]["data"]
        assert pfx_0["listId"] == "pfx-001"
        assert pfx_0["type"] == "dataPrefix"
        assert list(pfx_0["entries"][0].keys()) == ["ipPrefix"]

        dpfx_0 = sanitized["data_ipv4_prefix_list_policy_object"][0]["data"]
        assert dpfx_0["listId"] == "dpfx-001"
        assert dpfx_0["type"] == "dataPrefix"
        assert list(dpfx_0["entries"][0].keys()) == ["ipPrefix"]

        pcg_0 = sanitized["preferred_color_group_policy_object"][0]["data"]
        assert pcg_0["listId"] == "pcg-001"
        assert pcg_0["type"] == "preferredColorGroup"
        assert pcg_0["entries"] == [
            {"primaryColor": "mpls", "secondaryColor": "biz-internet"}
        ]

        comm_0 = sanitized["standard_community_list_policy_object"][0]["data"]
        assert comm_0["listId"] == "comm-001"
        assert comm_0["type"] == "community"
        assert comm_0["entries"] == [{"community": "65000:100"}]


@pytest.mark.unit
class TestFMCProfileRegistry:
    def test_fmc_profile_available(self) -> None:
        available = ProfileRegistry.available()
        assert "fmc" in available

    def test_load_fmc_profile(self) -> None:
        profile = ProfileRegistry.load("fmc")
        assert profile["name"] == "fmc"
        assert "packs" in profile

    def test_fmc_rules_have_valid_paths(self) -> None:
        rules = ProfileRegistry.load_rules("fmc")
        resolver = PathResolver()
        for rule in rules:
            resolver.parse(rule.path)

    def test_fmc_rules_have_valid_strategies(self) -> None:
        valid_strategies = {
            "token",
            "ip_map",
            "hostname_map",
            "constant",
            "hash",
            "preserve_format",
        }
        rules = ProfileRegistry.load_rules("fmc")
        for rule in rules:
            assert rule.strategy in valid_strategies, (
                f"Unknown strategy '{rule.strategy}' in path {rule.path}"
            )

    def test_fmc_usernames_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("fmc")
        user_rules = [r for r in rules if r.category == "USERNAMES"]
        assert len(user_rules) > 0
        assert all(r.tier == "default" for r in user_rules)

    def test_fmc_object_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("fmc")
        name_rules = [r for r in rules if r.category == "OBJECT_NAMES"]
        assert len(name_rules) > 0
        assert all(r.tier == "optional" for r in name_rules)

    def test_fmc_descriptions_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("fmc")
        desc_rules = [r for r in rules if r.category == "DESCRIPTIONS"]
        assert len(desc_rules) > 0
        assert all(r.tier == "optional" for r in desc_rules)

    def test_fmc_fqdns_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("fmc")
        fqdn_rules = [r for r in rules if r.category == "FQDNS"]
        assert len(fqdn_rules) > 0
        assert all(r.tier == "optional" for r in fqdn_rules)

    def test_fmc_device_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("fmc")
        device_rules = [r for r in rules if r.category == "DEVICE_NAMES"]
        assert len(device_rules) > 0
        assert all(r.tier == "optional" for r in device_rules)


@pytest.mark.unit
class TestFMCProfileIntegration:
    def test_sanitize_with_fmc_profile_redacts_usernames_and_urls(
        self, tmp_path
    ) -> None:
        """FMC profile default-tier packs redact usernames and API URLs."""
        data = {
            "access_control_policy": [
                {
                    "data": {
                        "type": "AccessPolicy",
                        "name": "ACP-Production",
                        "id": "005056BB-0B24-0ed3-0000-004294967565",
                        "links": {
                            "self": "https://198.51.100.10/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056BB-0B24-0ed3-0000-004294967565"
                        },
                        "metadata": {
                            "lastUser": {"name": "camschae"},
                            "timestamp": 1700000000,
                        },
                    },
                    "endpoint": "/api/fmc_config/v1/domain/e276abec/policy/accesspolicies",
                }
            ]
        }
        input_file = tmp_path / "fmc.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["fmc"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "fmc.json").read_text())
        raw = json.dumps(sanitized)
        assert "camschae" not in raw
        assert "198.51.100.10" not in raw
        acp = sanitized["access_control_policy"][0]["data"]
        assert acp["type"] == "AccessPolicy"
        assert acp["id"] == "005056BB-0B24-0ed3-0000-004294967565"
        assert acp["metadata"]["timestamp"] == 1700000000

    def test_fmc_optional_packs_excluded_by_default(self, tmp_path) -> None:
        """FMC optional-tier packs (object_names, descriptions, fqdns, device_names) not applied by default."""
        data = {
            "network": [
                {
                    "data": {
                        "name": "Internal-Servers-Subnet",
                        "value": "10.1.0.0/24",
                        "description": "Production server subnet in Building A",
                        "type": "Network",
                        "metadata": {"lastUser": {"name": "admin"}},
                        "links": {
                            "self": "https://198.51.100.10/api/fmc_config/v1/domain/abc/object/networks/123"
                        },
                    },
                    "endpoint": "/api/fmc_config/v1/domain/abc/object/networks",
                }
            ],
            "device": [
                {
                    "data": {
                        "name": "FTD-4100-A-1",
                        "hostName": "fw-prod-01.example.com",
                        "type": "Device",
                        "metadata": {"lastUser": {"name": "admin"}},
                        "links": {
                            "self": "https://198.51.100.10/api/fmc_config/v1/domain/abc/devices/devicerecords/456"
                        },
                    },
                    "endpoint": "/api/fmc_config/v1/domain/abc/devices/devicerecords",
                }
            ],
        }
        input_file = tmp_path / "fmc.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["fmc"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "fmc.json").read_text())
        net = sanitized["network"][0]["data"]
        assert net["name"] == "Internal-Servers-Subnet"
        assert net["description"] == "Production server subnet in Building A"
        dev = sanitized["device"][0]["data"]
        assert dev["name"] == "FTD-4100-A-1"
        assert dev["hostName"] == "fw-prod-01.example.com"
        # Default packs should be redacted
        assert "admin" not in json.dumps(sanitized)
        assert "198.51.100.10" not in json.dumps(sanitized)
        # IP scanner catches standalone IP values
        assert net["value"] != "10.1.0.0/24"

    def test_fmc_optional_packs_applied_when_enabled(self, tmp_path) -> None:
        """FMC optional-tier packs redact when explicitly enabled."""
        data = {
            "fqdn": [
                {
                    "data": {
                        "name": "Azure-ODS",
                        "value": "customer.ods.opinsights.azure.com",
                        "type": "FQDN",
                        "metadata": {"lastUser": {"name": "netops"}},
                        "links": {
                            "self": "https://198.51.100.10/api/fmc_config/v1/domain/abc/object/fqdns/789"
                        },
                    },
                    "endpoint": "/api/fmc_config/v1/domain/abc/object/fqdns",
                }
            ],
            "device": [
                {
                    "data": {
                        "name": "FW-PROD-01",
                        "hostName": "fw-prod-01.corp.local",
                        "type": "Device",
                        "metadata": {"lastUser": {"name": "netops"}},
                        "links": {
                            "self": "https://198.51.100.10/api/fmc_config/v1/domain/abc/devices/devicerecords/111"
                        },
                    },
                    "endpoint": "/api/fmc_config/v1/domain/abc/devices/devicerecords",
                }
            ],
        }
        input_file = tmp_path / "fmc.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["fmc"],
            packs=PackConfig(enable=["fqdns", "device_names", "object_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "fmc.json").read_text())
        fqdn = sanitized["fqdn"][0]["data"]
        assert fqdn["value"] != "customer.ods.opinsights.azure.com"
        dev = sanitized["device"][0]["data"]
        assert dev["name"] != "FW-PROD-01"
        assert dev["hostName"] != "fw-prod-01.corp.local"
        assert fqdn["name"] != "Azure-ODS"

    def test_profiles_list_shows_fmc(self) -> None:
        """CLI profiles list should show fmc."""
        from typer.testing import CliRunner

        from nac_sanitizer.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["profiles", "list"])
        assert result.exit_code == 0
        assert "fmc" in result.output
