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

    def test_ise_repository_config_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        repo_rules = [r for r in rules if r.category == "REPOSITORY_CONFIG"]
        assert len(repo_rules) > 0
        assert all(r.tier == "optional" for r in repo_rules)

    def test_ise_policy_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        policy_rules = [r for r in rules if r.category == "POLICY_NAMES"]
        assert len(policy_rules) > 0
        assert all(r.tier == "optional" for r in policy_rules)

    def test_ise_downloadable_acl_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        acl_rules = [r for r in rules if r.category == "DOWNLOADABLE_ACL_NAMES"]
        assert len(acl_rules) > 0
        assert all(r.tier == "optional" for r in acl_rules)

    def test_ise_identity_sources_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        src_rules = [r for r in rules if r.category == "IDENTITY_SOURCES"]
        assert len(src_rules) > 0
        assert all(r.tier == "optional" for r in src_rules)

    def test_ise_license_tier_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        lic_rules = [r for r in rules if r.category == "LICENSE_TIER_NAMES"]
        assert len(lic_rules) > 0
        assert all(r.tier == "optional" for r in lic_rules)

    def test_ise_security_groups_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        sg_rules = [r for r in rules if r.category == "SECURITY_GROUPS"]
        assert len(sg_rules) > 0
        assert all(r.tier == "optional" for r in sg_rules)

    def test_ise_sxp_config_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        sxp_rules = [r for r in rules if r.category == "SXP_CONFIG"]
        assert len(sxp_rules) > 0
        assert all(r.tier == "optional" for r in sxp_rules)

    def test_ise_device_trustsec_credentials_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        trustsec_rules = [
            r for r in rules if r.category == "DEVICE_TRUSTSEC_CREDENTIALS"
        ]
        assert len(trustsec_rules) > 0
        assert all(r.tier == "default" for r in trustsec_rules)

    def test_ise_network_device_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        name_rules = [r for r in rules if r.category == "NETWORK_DEVICE_NAMES"]
        assert len(name_rules) > 0
        assert all(r.tier == "optional" for r in name_rules)

    def test_ise_network_device_groups_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        group_rules = [r for r in rules if r.category == "NETWORK_DEVICE_GROUPS"]
        assert len(group_rules) > 0
        assert all(r.tier == "optional" for r in group_rules)

    def test_ise_authorization_profiles_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        authz_rules = [r for r in rules if r.category == "AUTHORIZATION_PROFILES"]
        assert len(authz_rules) > 0
        assert all(r.tier == "optional" for r in authz_rules)


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

    def test_ise_repository_config_excluded_by_default(self, tmp_path) -> None:
        """ISE repository_config pack (name, path) NOT redacted by default."""
        data = {
            "repository": [
                {
                    "data": {
                        "name": "ISE-Backup-SFTP",
                        "protocol": "SFTP",
                        "serverName": "10.0.0.206",
                        "path": "/backups/ise/nightly",
                        "enablePki": False,
                        "userName": "backup-svc",
                        "password": "",
                    },
                    "endpoint": "/api/v1/repository/ISE-Backup",
                },
                {
                    "data": {
                        "name": "Config-Archive-FTP",
                        "protocol": "FTP",
                        "serverName": "10.0.0.171",
                        "path": "/archive/configs",
                        "userName": "ftpuser",
                        "password": "",
                    },
                    "endpoint": "/api/v1/repository/WIN-19",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        assert sanitized["repository"][0]["data"]["name"] == "ISE-Backup-SFTP"
        assert sanitized["repository"][0]["data"]["path"] == "/backups/ise/nightly"
        assert sanitized["repository"][1]["data"]["name"] == "Config-Archive-FTP"
        assert sanitized["repository"][1]["data"]["path"] == "/archive/configs"

    def test_ise_repository_config_redacts_when_enabled(self, tmp_path) -> None:
        """ISE repository_config pack redacts name/path when enabled; other fields preserved."""
        data = {
            "repository": [
                {
                    "data": {
                        "name": "ISE-Backup-SFTP",
                        "protocol": "SFTP",
                        "serverName": "10.0.0.206",
                        "path": "/backups/ise/nightly",
                        "enablePki": False,
                        "userName": "backup-svc",
                        "password": "",
                    },
                    "endpoint": "/api/v1/repository/ISE-Backup",
                },
                {
                    "data": {
                        "name": "Config-Archive-FTP",
                        "protocol": "FTP",
                        "serverName": "10.0.0.171",
                        "path": "/archive/configs",
                        "userName": "ftpuser",
                        "password": "",
                    },
                    "endpoint": "/api/v1/repository/WIN-19",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["repository_config"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        assert sanitized["repository"][0]["data"]["name"] == "REPOSITORY_CONFIG-001"
        assert sanitized["repository"][1]["data"]["name"] == "REPOSITORY_CONFIG-002"
        assert sanitized["repository"][0]["data"]["path"] == "REPOSITORY_CONFIG-003"
        assert sanitized["repository"][1]["data"]["path"] == "REPOSITORY_CONFIG-004"
        assert sanitized["repository"][0]["data"]["protocol"] == "SFTP"
        assert sanitized["repository"][0]["data"]["enablePki"] is False
        assert sanitized["repository"][1]["data"]["protocol"] == "FTP"

    def test_ise_policy_names_excluded_by_default(self, tmp_path) -> None:
        """ISE policy_names pack (optional tier) is not redacted by default."""
        data = {
            "allowed_protocols": [
                {
                    "data": {
                        "id": "926901b0-8c01-11e6-996c-525400b48521",
                        "name": "Default-Device-Admin-Protocols",
                        "description": "Default Allowed Protocol Service Device Admin",
                        "allowPapAscii": True,
                        "allowChap": True,
                        "allowMsChapV1": True,
                    },
                    "endpoint": "/ers/config/allowedprotocols/926901b0-8c01-11e6-996c-525400b48521",
                },
                {
                    "data": {
                        "id": "92613980-8c01-11e6-996c-525400b48521",
                        "name": "EAP-TLS-Corp-Wireless",
                        "description": "Default Allowed Protocol Service",
                        "allowPapAscii": False,
                        "allowEapTls": True,
                    },
                    "endpoint": "/ers/config/allowedprotocols/92613980-8c01-11e6-996c-525400b48521",
                },
            ],
            "allowed_protocols_tacacs": [
                {
                    "data": {
                        "id": "a1b2c3d4-1234-5678-9abc-def012345678",
                        "name": "TACACS-Default-Protocols",
                        "description": "Default TACACS Protocol Service",
                        "allowPapAscii": True,
                        "allowChap": True,
                    },
                    "endpoint": "/ers/config/allowedprotocolstacacs/a1b2c3d4-1234-5678-9abc-def012345678",
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
        # Policy names should NOT be redacted by default (optional tier)
        assert (
            sanitized["allowed_protocols"][0]["data"]["name"]
            == "Default-Device-Admin-Protocols"
        )
        assert (
            sanitized["allowed_protocols"][1]["data"]["name"] == "EAP-TLS-Corp-Wireless"
        )
        assert (
            sanitized["allowed_protocols_tacacs"][0]["data"]["name"]
            == "TACACS-Default-Protocols"
        )
        # But other fields should remain
        assert (
            sanitized["allowed_protocols"][0]["data"]["id"]
            == "926901b0-8c01-11e6-996c-525400b48521"
        )
        assert (
            sanitized["allowed_protocols"][0]["data"]["description"]
            == "Default Allowed Protocol Service Device Admin"
        )
        assert sanitized["allowed_protocols"][0]["data"]["allowPapAscii"] is True

    def test_ise_policy_names_redacts_when_enabled(self, tmp_path) -> None:
        """ISE policy_names pack redacts policy names when explicitly enabled."""
        data = {
            "allowed_protocols": [
                {
                    "data": {
                        "id": "926901b0-8c01-11e6-996c-525400b48521",
                        "name": "Default-Device-Admin-Protocols",
                        "description": "Default Allowed Protocol Service Device Admin",
                        "allowPapAscii": True,
                        "allowChap": True,
                        "allowMsChapV1": True,
                    },
                    "endpoint": "/ers/config/allowedprotocols/926901b0-8c01-11e6-996c-525400b48521",
                },
                {
                    "data": {
                        "id": "92613980-8c01-11e6-996c-525400b48521",
                        "name": "EAP-TLS-Corp-Wireless",
                        "description": "Default Allowed Protocol Service",
                        "allowPapAscii": False,
                        "allowEapTls": True,
                    },
                    "endpoint": "/ers/config/allowedprotocols/92613980-8c01-11e6-996c-525400b48521",
                },
            ],
            "allowed_protocols_tacacs": [
                {
                    "data": {
                        "id": "a1b2c3d4-1234-5678-9abc-def012345678",
                        "name": "TACACS-Default-Protocols",
                        "description": "Default TACACS Protocol Service",
                        "allowPapAscii": True,
                        "allowChap": True,
                    },
                    "endpoint": "/ers/config/allowedprotocolstacacs/a1b2c3d4-1234-5678-9abc-def012345678",
                }
            ],
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["policy_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        # Policy names should be redacted
        assert sanitized["allowed_protocols"][0]["data"]["name"] == "POLICY_NAMES-001"
        assert sanitized["allowed_protocols"][1]["data"]["name"] == "POLICY_NAMES-002"
        assert (
            sanitized["allowed_protocols_tacacs"][0]["data"]["name"]
            == "POLICY_NAMES-003"
        )
        # But other fields should be preserved
        assert (
            sanitized["allowed_protocols"][0]["data"]["id"]
            == "926901b0-8c01-11e6-996c-525400b48521"
        )
        assert (
            sanitized["allowed_protocols"][0]["data"]["description"]
            == "Default Allowed Protocol Service Device Admin"
        )
        assert sanitized["allowed_protocols"][0]["data"]["allowPapAscii"] is True
        assert sanitized["allowed_protocols"][1]["data"]["allowEapTls"] is True
        assert sanitized["allowed_protocols_tacacs"][0]["data"]["allowChap"] is True

    def test_ise_downloadable_acl_names_excluded_by_default(self, tmp_path) -> None:
        """ISE downloadable_acl_names pack is not applied by default."""
        data = {
            "downloadable_acl": [
                {
                    "data": {
                        "id": "9825aa40-8c01-11e6-996c-525400b48521",
                        "name": "DENY_ALL_IPV4",
                        "description": "Deny all ipv4 traffic",
                        "dacl": "deny ip any any",
                        "daclType": "IPV4",
                    },
                    "endpoint": "/ers/config/downloadableacl/9825aa40-8c01-11e6-996c-525400b48521",
                },
                {
                    "data": {
                        "id": "d51e3b40-f945-11eb-953e-0050568fa723",
                        "name": "QUARANTINE_ACL",
                        "description": "Deny all ipv6 traffic",
                        "dacl": "deny ipv6 any any",
                        "daclType": "IPV6",
                    },
                    "endpoint": "/ers/config/downloadableacl/d51e3b40-f945-11eb-953e-0050568fa723",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        # Names should NOT be redacted by default (optional tier)
        assert sanitized["downloadable_acl"][0]["data"]["name"] == "DENY_ALL_IPV4"
        assert sanitized["downloadable_acl"][1]["data"]["name"] == "QUARANTINE_ACL"
        # Other fields should be preserved
        assert (
            sanitized["downloadable_acl"][0]["data"]["id"]
            == "9825aa40-8c01-11e6-996c-525400b48521"
        )
        assert (
            sanitized["downloadable_acl"][0]["data"]["description"]
            == "Deny all ipv4 traffic"
        )
        assert sanitized["downloadable_acl"][0]["data"]["dacl"] == "deny ip any any"
        assert sanitized["downloadable_acl"][0]["data"]["daclType"] == "IPV4"

    def test_ise_downloadable_acl_names_redacts_when_enabled(self, tmp_path) -> None:
        """ISE downloadable_acl_names pack redacts ACL names when explicitly enabled."""
        data = {
            "downloadable_acl": [
                {
                    "data": {
                        "id": "9825aa40-8c01-11e6-996c-525400b48521",
                        "name": "DENY_ALL_IPV4",
                        "description": "Deny all ipv4 traffic",
                        "dacl": "deny ip any any",
                        "daclType": "IPV4",
                    },
                    "endpoint": "/ers/config/downloadableacl/9825aa40-8c01-11e6-996c-525400b48521",
                },
                {
                    "data": {
                        "id": "d51e3b40-f945-11eb-953e-0050568fa723",
                        "name": "QUARANTINE_ACL",
                        "description": "Deny all ipv6 traffic",
                        "dacl": "deny ipv6 any any",
                        "daclType": "IPV6",
                    },
                    "endpoint": "/ers/config/downloadableacl/d51e3b40-f945-11eb-953e-0050568fa723",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["downloadable_acl_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        # Names should be redacted when enabled
        assert (
            sanitized["downloadable_acl"][0]["data"]["name"]
            == "DOWNLOADABLE_ACL_NAMES-001"
        )
        assert (
            sanitized["downloadable_acl"][1]["data"]["name"]
            == "DOWNLOADABLE_ACL_NAMES-002"
        )
        # Other sensitive fields should NOT be redacted (id, description, dacl, daclType)
        assert (
            sanitized["downloadable_acl"][0]["data"]["id"]
            == "9825aa40-8c01-11e6-996c-525400b48521"
        )
        assert (
            sanitized["downloadable_acl"][0]["data"]["description"]
            == "Deny all ipv4 traffic"
        )
        assert sanitized["downloadable_acl"][0]["data"]["dacl"] == "deny ip any any"
        assert sanitized["downloadable_acl"][0]["data"]["daclType"] == "IPV4"
        assert (
            sanitized["downloadable_acl"][1]["data"]["id"]
            == "d51e3b40-f945-11eb-953e-0050568fa723"
        )
        assert (
            sanitized["downloadable_acl"][1]["data"]["description"]
            == "Deny all ipv6 traffic"
        )
        assert sanitized["downloadable_acl"][1]["data"]["dacl"] == "deny ipv6 any any"
        assert sanitized["downloadable_acl"][1]["data"]["daclType"] == "IPV6"

    def test_ise_identity_sources_excluded_by_default(self, tmp_path) -> None:
        """ISE identity_sources optional pack is not applied by default."""
        data = {
            "certificate_authentication_profile": [
                {
                    "data": {
                        "id": "167942e0-dbea-11ee-94be-faa732630355",
                        "name": "Azure-TLS-Cert-Profile",
                        "description": "Azure_TLS_Certificate_Profile",
                        "externalIdentityStoreName": "[not applicable]",
                        "certificateAttributeName": "SUBJECT_COMMON_NAME",
                        "allowedAsUserName": False,
                        "matchMode": "NEVER",
                        "usernameFrom": "CERTIFICATE",
                    },
                    "endpoint": "/ers/config/certificateprofile/167942e0-dbea-11ee-94be-faa732630355",
                },
                {
                    "data": {
                        "id": "d59cd630-985d-11ee-94be-faa732630355",
                        "name": "Corp-Machine-Cert-Profile",
                        "description": "",
                        "externalIdentityStoreName": "CORP_AD_wan.example.com",
                        "certificateAttributeName": "SUBJECT_ALTERNATIVE_NAME",
                        "allowedAsUserName": False,
                        "matchMode": "RESOLVE_IDENTITY_AMBIGUITY",
                        "usernameFrom": "CERTIFICATE",
                    },
                    "endpoint": "/ers/config/certificateprofile/d59cd630-985d-11ee-94be-faa732630355",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        # Optional pack NOT enabled - names and externalIdentityStoreName should NOT be redacted
        cert1 = sanitized["certificate_authentication_profile"][0]["data"]
        assert cert1["name"] == "Azure-TLS-Cert-Profile"
        assert cert1["externalIdentityStoreName"] == "[not applicable]"
        cert2 = sanitized["certificate_authentication_profile"][1]["data"]
        assert cert2["name"] == "Corp-Machine-Cert-Profile"
        assert cert2["externalIdentityStoreName"] == "CORP_AD_wan.example.com"
        # Other fields should still be preserved
        assert cert1["id"] == "167942e0-dbea-11ee-94be-faa732630355"
        assert cert1["certificateAttributeName"] == "SUBJECT_COMMON_NAME"

    def test_ise_identity_sources_redacts_when_enabled(self, tmp_path) -> None:
        """ISE identity_sources pack redacts name and externalIdentityStoreName when enabled."""
        data = {
            "certificate_authentication_profile": [
                {
                    "data": {
                        "id": "167942e0-dbea-11ee-94be-faa732630355",
                        "name": "Azure-TLS-Cert-Profile",
                        "description": "Azure_TLS_Certificate_Profile",
                        "externalIdentityStoreName": "[not applicable]",
                        "certificateAttributeName": "SUBJECT_COMMON_NAME",
                        "allowedAsUserName": False,
                        "matchMode": "NEVER",
                        "usernameFrom": "CERTIFICATE",
                    },
                    "endpoint": "/ers/config/certificateprofile/167942e0-dbea-11ee-94be-faa732630355",
                },
                {
                    "data": {
                        "id": "d59cd630-985d-11ee-94be-faa732630355",
                        "name": "Corp-Machine-Cert-Profile",
                        "description": "",
                        "externalIdentityStoreName": "CORP_AD_wan.example.com",
                        "certificateAttributeName": "SUBJECT_ALTERNATIVE_NAME",
                        "allowedAsUserName": False,
                        "matchMode": "RESOLVE_IDENTITY_AMBIGUITY",
                        "usernameFrom": "CERTIFICATE",
                    },
                    "endpoint": "/ers/config/certificateprofile/d59cd630-985d-11ee-94be-faa732630355",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["identity_sources"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        # identity_sources enabled - names and externalIdentityStoreName should be redacted
        cert1 = sanitized["certificate_authentication_profile"][0]["data"]
        assert cert1["name"] == "IDENTITY_SOURCES-003"
        assert cert1["externalIdentityStoreName"] == "IDENTITY_SOURCES-001"
        cert2 = sanitized["certificate_authentication_profile"][1]["data"]
        assert cert2["name"] == "IDENTITY_SOURCES-004"
        assert cert2["externalIdentityStoreName"] == "IDENTITY_SOURCES-002"
        # Non-identity_sources fields should be preserved
        assert cert1["id"] == "167942e0-dbea-11ee-94be-faa732630355"
        assert cert1["description"] == "Azure_TLS_Certificate_Profile"
        assert cert1["certificateAttributeName"] == "SUBJECT_COMMON_NAME"
        assert cert1["allowedAsUserName"] is False
        assert cert1["matchMode"] == "NEVER"
        assert cert2["id"] == "d59cd630-985d-11ee-94be-faa732630355"
        assert cert2["description"] == ""
        assert cert2["certificateAttributeName"] == "SUBJECT_ALTERNATIVE_NAME"

    def test_ise_license_tier_names_excluded_by_default(self, tmp_path) -> None:
        """ISE optional-tier license_tier_names pack is not applied by default."""
        data = {
            "license_tier_state": [
                {
                    "data": [
                        {
                            "name": "ESSENTIAL",
                            "status": "ENABLED",
                            "compliance": "COMPLIANT",
                            "consumptionCounter": 25664,
                            "daysOutOfCompliance": "-",
                            "lastAuthorization": "May 27,2026 19:38:38 PM",
                        },
                        {
                            "name": "ADVANTAGE",
                            "status": "ENABLED",
                            "compliance": "COMPLIANT",
                            "consumptionCounter": 9243,
                            "daysOutOfCompliance": "-",
                            "lastAuthorization": "May 27,2026 19:38:38 PM",
                        },
                        {
                            "name": "PREMIER",
                            "status": "ENABLED",
                            "compliance": "COMPLIANT",
                            "consumptionCounter": 2856,
                            "daysOutOfCompliance": "-",
                            "lastAuthorization": "May 27,2026 19:38:38 PM",
                        },
                    ]
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
        # Optional pack should NOT be redacted by default
        assert sanitized["license_tier_state"][0]["data"][0]["name"] == "ESSENTIAL"
        assert sanitized["license_tier_state"][0]["data"][1]["name"] == "ADVANTAGE"
        assert sanitized["license_tier_state"][0]["data"][2]["name"] == "PREMIER"

    def test_ise_license_tier_names_redacts_when_enabled(self, tmp_path) -> None:
        """ISE license_tier_names pack redacts names when explicitly enabled."""
        data = {
            "license_tier_state": [
                {
                    "data": [
                        {
                            "name": "ESSENTIAL",
                            "status": "ENABLED",
                            "compliance": "COMPLIANT",
                            "consumptionCounter": 25664,
                            "daysOutOfCompliance": "-",
                            "lastAuthorization": "May 27,2026 19:38:38 PM",
                        },
                        {
                            "name": "ADVANTAGE",
                            "status": "ENABLED",
                            "compliance": "COMPLIANT",
                            "consumptionCounter": 9243,
                            "daysOutOfCompliance": "-",
                            "lastAuthorization": "May 27,2026 19:38:38 PM",
                        },
                        {
                            "name": "PREMIER",
                            "status": "ENABLED",
                            "compliance": "COMPLIANT",
                            "consumptionCounter": 2856,
                            "daysOutOfCompliance": "-",
                            "lastAuthorization": "May 27,2026 19:38:38 PM",
                        },
                    ]
                }
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["license_tier_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        # All tier names should be redacted
        assert (
            sanitized["license_tier_state"][0]["data"][0]["name"]
            == "LICENSE_TIER_NAMES-001"
        )
        assert (
            sanitized["license_tier_state"][0]["data"][1]["name"]
            == "LICENSE_TIER_NAMES-002"
        )
        assert (
            sanitized["license_tier_state"][0]["data"][2]["name"]
            == "LICENSE_TIER_NAMES-003"
        )
        # But other fields should be preserved
        assert sanitized["license_tier_state"][0]["data"][0]["status"] == "ENABLED"
        assert (
            sanitized["license_tier_state"][0]["data"][0]["compliance"] == "COMPLIANT"
        )
        assert (
            sanitized["license_tier_state"][0]["data"][0]["consumptionCounter"] == 25664
        )
        assert (
            sanitized["license_tier_state"][0]["data"][0]["daysOutOfCompliance"] == "-"
        )
        assert (
            sanitized["license_tier_state"][0]["data"][0]["lastAuthorization"]
            == "May 27,2026 19:38:38 PM"
        )

    def test_ise_security_groups_excluded_by_default(self, tmp_path) -> None:
        """ISE security_groups optional-tier pack is not applied by default."""
        data = {
            "trustsec_security_group": [
                {
                    "data": {
                        "id": "fba9f273-839e-4b95-9764-61b24315132e",
                        "name": "Aruba_Wireless_APs",
                        "description": "Aruba Wireless Access Points",
                        "value": 902,
                        "generationId": "10",
                        "propogateToApic": False,
                    },
                    "endpoint": "/ers/config/sgt/fba9f273-839e-4b95-9764-61b24315132e",
                }
            ],
            "trustsec_security_group_acl": [
                {
                    "data": {
                        "id": "e05e3fb0-0a18-11ee-adf3-76129057aa4e",
                        "name": "Allow_DHCP_DNS",
                        "description": "Sample contract to allow DHCP and DNS",
                        "generationId": "0",
                        "aclcontent": "permit udp dst eq 67\npermit udp dst eq 68\npermit tcp dst eq 53\ndeny ip",
                    },
                    "endpoint": "/ers/config/sgacl/e05e3fb0-0a18-11ee-adf3-76129057aa4e",
                }
            ],
            "trustsec_egress_matrix_cell": [
                {
                    "data": {
                        "id": "92c1a900-8c01-11e6-996c-525400b48521",
                        "name": "Auditors-to-Servers",
                        "description": "Default egress rule",
                        "sourceSgtId": "92bb1950-8c01-11e6-996c-525400b48521",
                        "destinationSgtId": "92bb1950-8c01-11e6-996c-525400b48521",
                        "matrixCellStatus": "ENABLED",
                        "defaultRule": "PERMIT_IP",
                        "sgacls": ["92951ac0-8c01-11e6-996c-525400b48521"],
                    },
                    "endpoint": "/ers/config/egressmatrixcell/92c1a900-8c01-11e6-996c-525400b48521",
                }
            ],
            "trustsec_egress_matrix_cell_default": [
                {
                    "data": {
                        "id": "09543131-192d-11ef-91f1-4a5b331df49b",
                        "name": "Default-Cell-Deny",
                        "sourceSgtId": "fba9f273-839e-4b95-9764-61b24315132e",
                        "destinationSgtId": "63860f29-2aac-4759-a3e6-260d3d227ef5",
                        "matrixCellStatus": "ENABLED",
                        "defaultRule": "DENY_IP",
                        "sgacls": ["92919850-8c01-11e6-996c-525400b48521"],
                    },
                    "endpoint": "/ers/config/egressmatrixcell/09543131-192d-11ef-91f1-4a5b331df49b",
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
        sg = sanitized["trustsec_security_group"][0]["data"]
        assert sg["name"] == "Aruba_Wireless_APs"
        assert sg["description"] == "Aruba Wireless Access Points"
        acl = sanitized["trustsec_security_group_acl"][0]["data"]
        assert acl["name"] == "Allow_DHCP_DNS"
        cell = sanitized["trustsec_egress_matrix_cell"][0]["data"]
        assert cell["name"] == "Auditors-to-Servers"
        default_cell = sanitized["trustsec_egress_matrix_cell_default"][0]["data"]
        assert default_cell["name"] == "Default-Cell-Deny"

    def test_ise_security_groups_redacts_when_enabled(self, tmp_path) -> None:
        """ISE security_groups pack redacts SGT/SGACL/matrix cell names when enabled."""
        data = {
            "trustsec_security_group": [
                {
                    "data": {
                        "id": "fba9f273-839e-4b95-9764-61b24315132e",
                        "name": "Aruba_Wireless_APs",
                        "description": "Aruba Wireless Access Points",
                        "value": 902,
                        "generationId": "10",
                        "propogateToApic": False,
                    },
                    "endpoint": "/ers/config/sgt/fba9f273-839e-4b95-9764-61b24315132e",
                }
            ],
            "trustsec_security_group_acl": [
                {
                    "data": {
                        "id": "e05e3fb0-0a18-11ee-adf3-76129057aa4e",
                        "name": "Allow_DHCP_DNS",
                        "description": "Sample contract to allow DHCP and DNS",
                        "generationId": "0",
                        "aclcontent": "permit udp dst eq 67\npermit udp dst eq 68\npermit tcp dst eq 53\ndeny ip",
                    },
                    "endpoint": "/ers/config/sgacl/e05e3fb0-0a18-11ee-adf3-76129057aa4e",
                }
            ],
            "trustsec_egress_matrix_cell": [
                {
                    "data": {
                        "id": "92c1a900-8c01-11e6-996c-525400b48521",
                        "name": "Auditors-to-Servers",
                        "description": "Default egress rule",
                        "sourceSgtId": "92bb1950-8c01-11e6-996c-525400b48521",
                        "destinationSgtId": "92bb1950-8c01-11e6-996c-525400b48521",
                        "matrixCellStatus": "ENABLED",
                        "defaultRule": "PERMIT_IP",
                        "sgacls": ["92951ac0-8c01-11e6-996c-525400b48521"],
                    },
                    "endpoint": "/ers/config/egressmatrixcell/92c1a900-8c01-11e6-996c-525400b48521",
                }
            ],
            "trustsec_egress_matrix_cell_default": [
                {
                    "data": {
                        "id": "09543131-192d-11ef-91f1-4a5b331df49b",
                        "name": "Default-Cell-Deny",
                        "sourceSgtId": "fba9f273-839e-4b95-9764-61b24315132e",
                        "destinationSgtId": "63860f29-2aac-4759-a3e6-260d3d227ef5",
                        "matrixCellStatus": "ENABLED",
                        "defaultRule": "DENY_IP",
                        "sgacls": ["92919850-8c01-11e6-996c-525400b48521"],
                    },
                    "endpoint": "/ers/config/egressmatrixcell/09543131-192d-11ef-91f1-4a5b331df49b",
                }
            ],
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["security_groups"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        sg = sanitized["trustsec_security_group"][0]["data"]
        assert sg["name"] == "SECURITY_GROUPS-001"
        assert sg["description"] == "SECURITY_GROUPS-002"
        assert sg["id"] == "fba9f273-839e-4b95-9764-61b24315132e"
        assert sg["value"] == 902
        assert sg["generationId"] == "10"

        acl = sanitized["trustsec_security_group_acl"][0]["data"]
        assert acl["name"] == "SECURITY_GROUPS-003"
        assert (
            acl["aclcontent"]
            == "permit udp dst eq 67\npermit udp dst eq 68\npermit tcp dst eq 53\ndeny ip"
        )

        cell = sanitized["trustsec_egress_matrix_cell"][0]["data"]
        assert cell["name"] == "SECURITY_GROUPS-004"
        assert cell["sgacls"] == ["92951ac0-8c01-11e6-996c-525400b48521"]
        assert cell["matrixCellStatus"] == "ENABLED"
        assert cell["defaultRule"] == "PERMIT_IP"

        default_cell = sanitized["trustsec_egress_matrix_cell_default"][0]["data"]
        assert default_cell["name"] == "SECURITY_GROUPS-005"
        assert default_cell["sgacls"] == ["92919850-8c01-11e6-996c-525400b48521"]
        assert default_cell["matrixCellStatus"] == "ENABLED"
        assert default_cell["defaultRule"] == "DENY_IP"

    def test_ise_sxp_config_excluded_by_default(self, tmp_path) -> None:
        """ISE sxp_config optional-tier pack is not applied by default."""
        data = {
            "sxp_domain_filter": [
                {
                    "data": {
                        "id": "25cae136-f670-46bc-8e6f-14badb95b94b",
                        "subnet": "",
                        "domains": "sda-infra-vn",
                        "sgt": "",
                        "vn": "INFRA_VN",
                    },
                    "endpoint": "/ers/config/filterpolicy/25cae136-f670-46bc-8e6f-14badb95b94b",
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
        filt = sanitized["sxp_domain_filter"][0]["data"]
        assert filt["vn"] == "INFRA_VN"
        assert filt["domains"] == "sda-infra-vn"

    def test_ise_sxp_config_redacts_when_enabled(self, tmp_path) -> None:
        """ISE sxp_config pack redacts vn and domains when enabled."""
        data = {
            "sxp_domain_filter": [
                {
                    "data": {
                        "id": "25cae136-f670-46bc-8e6f-14badb95b94b",
                        "subnet": "",
                        "domains": "sda-infra-vn",
                        "sgt": "",
                        "vn": "INFRA_VN",
                    },
                    "endpoint": "/ers/config/filterpolicy/25cae136-f670-46bc-8e6f-14badb95b94b",
                }
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["sxp_config"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        filt = sanitized["sxp_domain_filter"][0]["data"]
        assert filt["vn"] == "SXP_CONFIG-001"
        assert filt["domains"] == "SXP_CONFIG-002"
        assert filt["id"] == "25cae136-f670-46bc-8e6f-14badb95b94b"
        assert filt["subnet"] == ""
        assert filt["sgt"] == ""

    @staticmethod
    def _network_device_fixture() -> dict:
        """Fixture mirroring real ISE network_device/network_device_group collector output."""
        return {
            "network_device": [
                {
                    "data": {
                        "id": "d9c6e490-34b9-11f0-b6a6-96c23bf9c01f",
                        "name": "core-switch-01.example.com",
                        "description": "",
                        "authenticationSettings": {
                            "networkProtocol": "RADIUS",
                            "radiusSharedSecret": "RadiusSecret123",
                        },
                        "NetworkDeviceGroupList": [
                            "Location#All Locations#Building-A#Floor-3",
                            "Device Type#All Device Types#Switch#Catalyst",
                        ],
                        "trustsecsettings": {
                            "sgaNotificationAndUpdates": {
                                "downlaodEnvironmentDataEveryXSeconds": 86400,
                                "otherSGADevicesToTrustThisDevice": True,
                                "sendConfigurationToDevice": True,
                                "coaSourceHost": "ise-pan-01.corp.local",
                            },
                            "deviceConfigurationDeployment": {
                                "includeWhenDeployingSGTUpdates": True,
                                "enableModePassword": "En@bl3Secret!",
                                "execModePassword": "Ex3cSecret!",
                                "execModeUsername": "ise-deploy-svc",
                            },
                        },
                        "profileName": "Cisco",
                        "coaPort": 1700,
                    },
                    "endpoint": "/ers/config/networkdevice/d9c6e490-34b9-11f0-b6a6-96c23bf9c01f",
                }
            ],
            "network_device_group": [
                {
                    "data": {
                        "id": "394f7b70-08d2-11f0-b6a6-96c23bf9c01f",
                        "name": "Location#All Locations#Building-A",
                        "description": "Network Device Group for Building A devices",
                        "othername": "Location",
                    },
                    "endpoint": "/ers/config/networkdevicegroup/394f7b70-08d2-11f0-b6a6-96c23bf9c01f",
                },
                {
                    "data": {
                        "id": "70c79c30-8bff-11e6-996c-525400b48521",
                        "name": "Device Type#All Device Types",
                        "description": "All Device Types",
                        "othername": "Device Type",
                    },
                    "endpoint": "/ers/config/networkdevicegroup/70c79c30-8bff-11e6-996c-525400b48521",
                },
            ],
        }

    def test_ise_trustsec_credentials_redacted_by_default(self, tmp_path) -> None:
        """TrustSec device deployment credentials are redacted by default (default tier)."""
        data = self._network_device_fixture()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        raw = json.dumps(sanitized)
        # TrustSec device deployment credentials redacted
        assert "En@bl3Secret!" not in raw
        assert "Ex3cSecret!" not in raw
        assert "ise-deploy-svc" not in raw
        # Existing credentials pack still redacts RADIUS shared secret
        assert "RadiusSecret123" not in raw

        device = sanitized["network_device"][0]["data"]
        deploy = device["trustsecsettings"]["deviceConfigurationDeployment"]
        assert deploy["enableModePassword"] == "DEVICE_TRUSTSEC_CREDENTIALS-001"
        assert deploy["execModePassword"] == "DEVICE_TRUSTSEC_CREDENTIALS-002"
        assert deploy["execModeUsername"] == "DEVICE_TRUSTSEC_CREDENTIALS-003"
        # Non-sensitive fields preserved
        assert device["profileName"] == "Cisco"
        assert device["coaPort"] == 1700
        assert deploy["includeWhenDeployingSGTUpdates"] is True

    def test_ise_network_device_names_excluded_by_default(self, tmp_path) -> None:
        """Device name and CoA source host are optional-tier and untouched by default."""
        data = self._network_device_fixture()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        device = sanitized["network_device"][0]["data"]
        assert device["name"] == "core-switch-01.example.com"
        assert (
            device["trustsecsettings"]["sgaNotificationAndUpdates"]["coaSourceHost"]
            == "ise-pan-01.corp.local"
        )

    def test_ise_network_device_names_redacts_when_enabled(self, tmp_path) -> None:
        """Enabling network_device_names maps device name and coaSourceHost via hostname_map."""
        data = self._network_device_fixture()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["network_device_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        device = sanitized["network_device"][0]["data"]
        assert device["name"] == "DEVICE-001"
        coa_host = device["trustsecsettings"]["sgaNotificationAndUpdates"][
            "coaSourceHost"
        ]
        assert coa_host == "DEVICE-002"

    def test_ise_network_device_groups_redacts_when_enabled(self, tmp_path) -> None:
        """Enabling network_device_groups redacts group list entries, name, and description."""
        data = self._network_device_fixture()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["network_device_groups"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        device = sanitized["network_device"][0]["data"]
        assert device["NetworkDeviceGroupList"] == [
            "NETWORK_DEVICE_GROUPS-001",
            "NETWORK_DEVICE_GROUPS-002",
        ]

        groups = sanitized["network_device_group"]
        assert groups[0]["data"]["name"] == "NETWORK_DEVICE_GROUPS-003"
        assert groups[0]["data"]["description"] == "NETWORK_DEVICE_GROUPS-005"
        # Non-sensitive identifiers preserved
        assert groups[0]["data"]["id"] == "394f7b70-08d2-11f0-b6a6-96c23bf9c01f"
        assert groups[0]["data"]["othername"] == "Location"
        assert groups[1]["data"]["id"] == "70c79c30-8bff-11e6-996c-525400b48521"
        assert groups[1]["data"]["othername"] == "Device Type"

    def test_ise_authorization_profiles_excluded_by_default(self, tmp_path) -> None:
        """ISE authorization_profiles pack (optional tier) is not applied unless enabled."""
        data = {
            "authorization_profile": [
                {
                    "data": {
                        "id": "a1b2c3d4-1234-5678-abcd-111111111111",
                        "name": "VLAN1210-Employee-Access",
                        "description": "Standard employee network access with VLAN 1210",
                        "accessType": "ACCESS_ACCEPT",
                        "authzProfileType": "SWITCH",
                        "vlan": {
                            "nameID": "EMPLOYEE_VLAN_1210",
                            "tagID": 1,
                        },
                        "trackMovement": False,
                        "agentlessPosture": False,
                    },
                    "endpoint": "/ers/config/authorizationprofile/a1b2c3d4-1234-5678-abcd-111111111111",
                },
                {
                    "data": {
                        "id": "e5f6g7h8-9012-3456-efgh-222222222222",
                        "name": "VPN-IPSec-Pool-Profile",
                        "description": "Remote access VPN authorization",
                        "accessType": "ACCESS_ACCEPT",
                        "authzProfileType": "SWITCH",
                        "advancedAttributes": [
                            {
                                "leftHandSideDictionaryAttribue": {
                                    "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                                    "dictionaryName": "Cisco",
                                    "attributeName": "cisco-av-pair",
                                },
                                "rightHandSideAttribueValue": {
                                    "AdvancedAttributeValueType": "AttributeValue",
                                    "value": "ipsec:addr-pool=CORP_VPN_POOL",
                                },
                            }
                        ],
                        "trackMovement": False,
                    },
                    "endpoint": "/ers/config/authorizationprofile/e5f6g7h8-9012-3456-efgh-222222222222",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        # Optional pack NOT applied by default - sensitive fields preserved
        profile = sanitized["authorization_profile"][0]["data"]
        assert profile["name"] == "VLAN1210-Employee-Access"
        assert (
            profile["description"] == "Standard employee network access with VLAN 1210"
        )
        assert profile["vlan"]["nameID"] == "EMPLOYEE_VLAN_1210"

        profile2 = sanitized["authorization_profile"][1]["data"]
        assert profile2["name"] == "VPN-IPSec-Pool-Profile"
        attr = profile2["advancedAttributes"][0]
        assert (
            attr["rightHandSideAttribueValue"]["value"]
            == "ipsec:addr-pool=CORP_VPN_POOL"
        )

    def test_ise_authorization_profiles_redacts_when_enabled(self, tmp_path) -> None:
        """ISE authorization_profiles pack redacts names, descriptions, vlan names, and attributes when enabled."""
        data = {
            "authorization_profile": [
                {
                    "data": {
                        "id": "a1b2c3d4-1234-5678-abcd-111111111111",
                        "name": "VLAN1210-Employee-Access",
                        "description": "Standard employee network access with VLAN 1210",
                        "accessType": "ACCESS_ACCEPT",
                        "authzProfileType": "SWITCH",
                        "vlan": {
                            "nameID": "EMPLOYEE_VLAN_1210",
                            "tagID": 1,
                        },
                        "trackMovement": False,
                        "agentlessPosture": False,
                    },
                    "endpoint": "/ers/config/authorizationprofile/a1b2c3d4-1234-5678-abcd-111111111111",
                },
                {
                    "data": {
                        "id": "e5f6g7h8-9012-3456-efgh-222222222222",
                        "name": "VPN-IPSec-Pool-Profile",
                        "description": "Remote access VPN authorization",
                        "accessType": "ACCESS_ACCEPT",
                        "authzProfileType": "SWITCH",
                        "advancedAttributes": [
                            {
                                "leftHandSideDictionaryAttribue": {
                                    "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                                    "dictionaryName": "Cisco",
                                    "attributeName": "cisco-av-pair",
                                },
                                "rightHandSideAttribueValue": {
                                    "AdvancedAttributeValueType": "AttributeValue",
                                    "value": "ipsec:addr-pool=CORP_VPN_POOL",
                                },
                            }
                        ],
                        "trackMovement": False,
                    },
                    "endpoint": "/ers/config/authorizationprofile/e5f6g7h8-9012-3456-efgh-222222222222",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["authorization_profiles"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        profile = sanitized["authorization_profile"][0]["data"]
        profile2 = sanitized["authorization_profile"][1]["data"]
        attr = profile2["advancedAttributes"][0]

        # Sensitive fields redacted
        assert profile["name"] == "AUTHORIZATION_PROFILES-001"
        assert profile["description"] == "AUTHORIZATION_PROFILES-003"
        assert profile["vlan"]["nameID"] == "AUTHORIZATION_PROFILES-005"
        assert profile2["name"] == "AUTHORIZATION_PROFILES-002"
        assert profile2["description"] == "AUTHORIZATION_PROFILES-004"
        assert (
            attr["rightHandSideAttribueValue"]["value"] == "AUTHORIZATION_PROFILES-006"
        )

        # Non-sensitive fields preserved
        assert profile["id"] == "a1b2c3d4-1234-5678-abcd-111111111111"
        assert profile["accessType"] == "ACCESS_ACCEPT"
        assert profile["authzProfileType"] == "SWITCH"
        assert profile["vlan"]["tagID"] == 1
        assert profile["trackMovement"] is False
        assert profile["agentlessPosture"] is False

        assert profile2["id"] == "e5f6g7h8-9012-3456-efgh-222222222222"
        assert profile2["accessType"] == "ACCESS_ACCEPT"
        assert profile2["trackMovement"] is False
        assert (
            attr["leftHandSideDictionaryAttribue"]["AdvancedAttributeValueType"]
            == "AdvancedDictionaryAttribute"
        )


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
