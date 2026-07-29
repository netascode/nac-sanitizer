# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Tests for product profile loading and integration."""

import json
import re

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

    def test_sdwan_url_filter_patterns_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("sdwan")
        url_rules = [r for r in rules if r.category == "URL_FILTER_PATTERNS"]
        assert len(url_rules) > 0
        assert all(r.tier == "default" for r in url_rules)

    def test_sdwan_configuration_group_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("sdwan")
        config_group_rules = [
            r for r in rules if r.category == "CONFIGURATION_GROUP_NAMES"
        ]
        assert len(config_group_rules) > 0
        assert all(r.tier == "optional" for r in config_group_rules)

    def test_sdwan_configuration_group_names_excluded_by_default(
        self, tmp_path
    ) -> None:
        """Configuration group descriptions should NOT be redacted by default."""
        data = {
            "configuration_group": [
                {
                    "data": {
                        "id": "b4add882-52df-4d6d-af52-76302dfe7d7b",
                        "name": "GOLD-BRANCHTYPE2",
                        "description": "Gold tier branch type 2 configuration for ACME Corp",
                        "source": None,
                        "solution": "sdwan",
                        "lastUpdatedBy": "admin@example.com",
                        "lastUpdatedOn": 1779119653498,
                        "profiles": [
                            {
                                "id": "cdd24eec-a424-4867-9890-6b9b5dd47270",
                                "name": "GOLD-SERVICE-BT2-PROFILE",
                                "type": "service",
                            }
                        ],
                    },
                    "endpoint": "/dataservice/v1/config-group/b4add882-52df-4d6d-af52-76302dfe7d7b",
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
        # Optional tier pack - should NOT be redacted by default
        assert (
            sanitized["configuration_group"][0]["data"]["description"]
            == "Gold tier branch type 2 configuration for ACME Corp"
        )

    def test_sdwan_configuration_group_names_redacts_when_enabled(
        self, tmp_path
    ) -> None:
        """Configuration group descriptions should be redacted when pack is enabled."""
        data = {
            "configuration_group": [
                {
                    "data": {
                        "id": "b4add882-52df-4d6d-af52-76302dfe7d7b",
                        "name": "GOLD-BRANCHTYPE2",
                        "description": "Gold tier branch type 2 configuration for ACME Corp",
                        "source": None,
                        "solution": "sdwan",
                        "lastUpdatedBy": "admin@example.com",
                        "lastUpdatedOn": 1779119653498,
                        "profiles": [
                            {
                                "id": "cdd24eec-a424-4867-9890-6b9b5dd47270",
                                "name": "GOLD-SERVICE-BT2-PROFILE",
                                "type": "service",
                            }
                        ],
                    },
                    "endpoint": "/dataservice/v1/config-group/b4add882-52df-4d6d-af52-76302dfe7d7b",
                },
                {
                    "data": {
                        "id": "a1234567-89ab-cdef-0123-456789abcdef",
                        "name": "SILVER-REMOTE",
                        "description": "Silver tier remote office configuration",
                        "source": None,
                        "solution": "sdwan",
                        "lastUpdatedBy": "netops@example.com",
                        "lastUpdatedOn": 1779119653499,
                        "profiles": [],
                    },
                    "endpoint": "/dataservice/v1/config-group/a1234567-89ab-cdef-0123-456789abcdef",
                },
            ]
        }
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["sdwan"],
            packs=PackConfig(enable=["configuration_group_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        # Description should be redacted to a deterministic token
        assert (
            sanitized["configuration_group"][0]["data"]["description"]
            == "CONFIGURATION_GROUP_NAMES-001"
        )
        assert (
            sanitized["configuration_group"][1]["data"]["description"]
            == "CONFIGURATION_GROUP_NAMES-002"
        )
        # Other fields should be preserved
        assert (
            sanitized["configuration_group"][0]["data"]["id"]
            == "b4add882-52df-4d6d-af52-76302dfe7d7b"
        )
        assert sanitized["configuration_group"][0]["data"]["name"] == "GOLD-BRANCHTYPE2"
        assert sanitized["configuration_group"][0]["data"]["source"] is None
        assert sanitized["configuration_group"][0]["data"]["solution"] == "sdwan"
        assert sanitized["configuration_group"][0]["data"]["profiles"] == [
            {
                "id": "cdd24eec-a424-4867-9890-6b9b5dd47270",
                "name": "GOLD-SERVICE-BT2-PROFILE",
                "type": "service",
            }
        ]


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

    def test_ise_identity_source_sequences_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        seq_rules = [r for r in rules if r.category == "IDENTITY_SOURCE_SEQUENCES"]
        assert len(seq_rules) > 0
        assert all(r.tier == "optional" for r in seq_rules)

    def test_ise_active_directory_groups_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        ad_rules = [r for r in rules if r.category == "ACTIVE_DIRECTORY_GROUPS"]
        assert len(ad_rules) > 0
        assert all(r.tier == "optional" for r in ad_rules)

    def test_ise_personal_info_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        pi_rules = [r for r in rules if r.category == "PERSONAL_INFO"]
        assert len(pi_rules) > 0
        assert all(r.tier == "default" for r in pi_rules)

    def test_ise_user_personal_info_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        personal_info_rules = [r for r in rules if r.category == "USER_PERSONAL_INFO"]
        assert len(personal_info_rules) > 0
        assert all(r.tier == "default" for r in personal_info_rules)

    def test_ise_user_identity_groups_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        identity_group_rules = [
            r for r in rules if r.category == "USER_IDENTITY_GROUPS"
        ]
        assert len(identity_group_rules) > 0
        assert all(r.tier == "optional" for r in identity_group_rules)

    def test_ise_endpoint_identities_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        identity_rules = [r for r in rules if r.category == "ENDPOINT_IDENTITIES"]
        assert len(identity_rules) > 0
        assert all(r.tier == "optional" for r in identity_rules)

    def test_ise_endpoint_custom_pii_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        pii_rules = [r for r in rules if r.category == "ENDPOINT_CUSTOM_PII"]
        assert len(pii_rules) > 0
        assert all(r.tier == "default" for r in pii_rules)

    def test_ise_device_admin_policy_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        policy_name_rules = [
            r for r in rules if r.category == "DEVICE_ADMIN_POLICY_NAMES"
        ]
        assert len(policy_name_rules) > 0
        assert all(r.tier == "optional" for r in policy_name_rules)
        assert all(r.strategy == "token" for r in policy_name_rules)

    def test_ise_device_admin_condition_values_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        condition_rules = [
            r for r in rules if r.category == "DEVICE_ADMIN_CONDITION_VALUES"
        ]
        assert len(condition_rules) > 0
        assert all(r.tier == "optional" for r in condition_rules)
        assert all(r.strategy == "token" for r in condition_rules)

    def test_ise_device_admin_authz_refs_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("ise")
        authz_rules = [r for r in rules if r.category == "DEVICE_ADMIN_AUTHZ_REFS"]
        assert len(authz_rules) > 0
        assert all(r.tier == "optional" for r in authz_rules)
        assert all(r.strategy == "token" for r in authz_rules)


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

    def test_sdwan_url_filter_patterns_redacted_by_default(self, tmp_path) -> None:
        """SD-WAN profile default-tier url_filter_patterns pack redacts URL patterns."""
        data = {
            "allow_url_list_policy_object": [
                {
                    "data": {
                        "name": "Corp-Allow-List",
                        "type": "urlWhiteList",
                        "entries": [
                            {"pattern": "*.internal.corp.example.com"},
                            {"pattern": "sharepoint.example.com"},
                        ],
                    },
                    "endpoint": "/dataservice/template/policy/list/urlwhitelist/abc-123",
                }
            ],
            "block_url_list_policy_object": [
                {
                    "data": {
                        "name": "Security-Block-List",
                        "type": "urlBlackList",
                        "entries": [
                            {"pattern": "*.malware-domain.com"},
                            {"pattern": "phishing-site.net"},
                        ],
                    },
                    "endpoint": "/dataservice/template/policy/list/urlblacklist/def-456",
                }
            ],
        }
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["sdwan"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        # URL patterns should be redacted to deterministic tokens
        allow_entries = sanitized["allow_url_list_policy_object"][0]["data"]["entries"]
        block_entries = sanitized["block_url_list_policy_object"][0]["data"]["entries"]
        assert allow_entries[0]["pattern"] == "URL_FILTER_PATTERNS-001"
        assert allow_entries[1]["pattern"] == "URL_FILTER_PATTERNS-002"
        assert block_entries[0]["pattern"] == "URL_FILTER_PATTERNS-003"
        assert block_entries[1]["pattern"] == "URL_FILTER_PATTERNS-004"
        # But names, types, and endpoints should be preserved
        assert (
            sanitized["allow_url_list_policy_object"][0]["data"]["name"]
            == "Corp-Allow-List"
        )
        assert (
            sanitized["allow_url_list_policy_object"][0]["data"]["type"]
            == "urlWhiteList"
        )
        assert (
            sanitized["allow_url_list_policy_object"][0]["endpoint"]
            == "/dataservice/template/policy/list/urlwhitelist/abc-123"
        )
        assert (
            sanitized["block_url_list_policy_object"][0]["data"]["name"]
            == "Security-Block-List"
        )

    def test_sdwan_url_filter_patterns_can_be_disabled(self, tmp_path) -> None:
        """SD-WAN url_filter_patterns can be disabled via PackConfig."""
        data = {
            "allow_url_list_policy_object": [
                {
                    "data": {
                        "name": "Corp-Allow-List",
                        "entries": [
                            {"pattern": "*.internal.corp.example.com"},
                            {"pattern": "sharepoint.example.com"},
                        ],
                    },
                    "endpoint": "/dataservice/template/policy/list/urlwhitelist/abc-123",
                }
            ]
        }
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["sdwan"],
            packs=PackConfig(disable=["url_filter_patterns"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        # URL patterns should NOT be redacted when disabled
        assert (
            sanitized["allow_url_list_policy_object"][0]["data"]["entries"][0][
                "pattern"
            ]
            == "*.internal.corp.example.com"
        )
        assert (
            sanitized["allow_url_list_policy_object"][0]["data"]["entries"][1][
                "pattern"
            ]
            == "sharepoint.example.com"
        )

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

    def test_ise_identity_source_sequences_excluded_by_default(self, tmp_path) -> None:
        """ISE identity_source_sequences pack (optional tier) is not applied unless enabled."""
        data = {
            "identity_source_sequence": [
                {
                    "data": {
                        "id": "93246270-8c01-11e6-996c-525400b48521",
                        "name": "All_User_ID_Stores",
                        "description": "A built-in Identity Sequence to include all User Identity Stores",
                        "idSeqItem": [
                            {"idstore": "Internal Users", "order": 1},
                            {"idstore": "CORP_AD_wan.example.com", "order": 2},
                            {"idstore": "RSA SecurID", "order": 3},
                        ],
                        "certificateAuthenticationProfile": "Preloaded_Certificate_Profile",
                        "breakOnStoreFail": False,
                    },
                    "endpoint": "/ers/config/idstoresequence/93246270-8c01-11e6-996c-525400b48521",
                },
                {
                    "data": {
                        "id": "9c6fb000-8c01-11e6-996c-525400b48521",
                        "name": "Certificate-Request-Sequence",
                        "description": "A built-in Identity Sequence for Certificate Request APIs",
                        "idSeqItem": [
                            {"idstore": "Internal Users", "order": 1},
                            {"idstore": "All_AD_Join_Points", "order": 2},
                        ],
                        "certificateAuthenticationProfile": "",
                        "breakOnStoreFail": False,
                    },
                    "endpoint": "/ers/config/idstoresequence/9c6fb000-8c01-11e6-996c-525400b48521",
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
        seq_0 = sanitized["identity_source_sequence"][0]["data"]
        seq_1 = sanitized["identity_source_sequence"][1]["data"]

        # Sensitive fields should NOT be redacted by default
        assert seq_0["name"] == "All_User_ID_Stores"
        assert (
            seq_0["description"]
            == "A built-in Identity Sequence to include all User Identity Stores"
        )
        assert seq_0["idSeqItem"][0]["idstore"] == "Internal Users"
        assert seq_0["idSeqItem"][1]["idstore"] == "CORP_AD_wan.example.com"
        assert seq_0["idSeqItem"][2]["idstore"] == "RSA SecurID"

        assert seq_1["name"] == "Certificate-Request-Sequence"
        assert (
            seq_1["description"]
            == "A built-in Identity Sequence for Certificate Request APIs"
        )
        assert seq_1["idSeqItem"][0]["idstore"] == "Internal Users"
        assert seq_1["idSeqItem"][1]["idstore"] == "All_AD_Join_Points"

    def test_ise_identity_source_sequences_redacts_when_enabled(self, tmp_path) -> None:
        """ISE identity_source_sequences pack redacts names, descriptions, and idstore when enabled."""
        data = {
            "identity_source_sequence": [
                {
                    "data": {
                        "id": "93246270-8c01-11e6-996c-525400b48521",
                        "name": "All_User_ID_Stores",
                        "description": "A built-in Identity Sequence to include all User Identity Stores",
                        "idSeqItem": [
                            {"idstore": "Internal Users", "order": 1},
                            {"idstore": "CORP_AD_wan.example.com", "order": 2},
                            {"idstore": "RSA SecurID", "order": 3},
                        ],
                        "certificateAuthenticationProfile": "Preloaded_Certificate_Profile",
                        "breakOnStoreFail": False,
                    },
                    "endpoint": "/ers/config/idstoresequence/93246270-8c01-11e6-996c-525400b48521",
                },
                {
                    "data": {
                        "id": "9c6fb000-8c01-11e6-996c-525400b48521",
                        "name": "Certificate-Request-Sequence",
                        "description": "A built-in Identity Sequence for Certificate Request APIs",
                        "idSeqItem": [
                            {"idstore": "Internal Users", "order": 1},
                            {"idstore": "All_AD_Join_Points", "order": 2},
                        ],
                        "certificateAuthenticationProfile": "",
                        "breakOnStoreFail": False,
                    },
                    "endpoint": "/ers/config/idstoresequence/9c6fb000-8c01-11e6-996c-525400b48521",
                },
            ]
        }
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["identity_source_sequences"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        seq_0 = sanitized["identity_source_sequence"][0]["data"]
        seq_1 = sanitized["identity_source_sequence"][1]["data"]

        # Sensitive fields should be redacted
        assert seq_0["name"] == "IDENTITY_SOURCE_SEQUENCES-001"
        assert seq_1["name"] == "IDENTITY_SOURCE_SEQUENCES-002"
        assert seq_0["description"] == "IDENTITY_SOURCE_SEQUENCES-003"
        assert seq_1["description"] == "IDENTITY_SOURCE_SEQUENCES-004"
        assert seq_0["idSeqItem"][0]["idstore"] == "IDENTITY_SOURCE_SEQUENCES-005"
        assert seq_0["idSeqItem"][1]["idstore"] == "IDENTITY_SOURCE_SEQUENCES-006"
        assert seq_0["idSeqItem"][2]["idstore"] == "IDENTITY_SOURCE_SEQUENCES-007"
        assert seq_1["idSeqItem"][0]["idstore"] == "IDENTITY_SOURCE_SEQUENCES-005"
        assert seq_1["idSeqItem"][1]["idstore"] == "IDENTITY_SOURCE_SEQUENCES-008"

        # Non-sensitive fields should be preserved
        assert seq_0["id"] == "93246270-8c01-11e6-996c-525400b48521"
        assert seq_1["id"] == "9c6fb000-8c01-11e6-996c-525400b48521"
        assert seq_0["idSeqItem"][0]["order"] == 1
        assert seq_0["idSeqItem"][1]["order"] == 2
        assert seq_0["idSeqItem"][2]["order"] == 3
        assert seq_1["idSeqItem"][0]["order"] == 1
        assert seq_1["idSeqItem"][1]["order"] == 2
        assert (
            seq_0["certificateAuthenticationProfile"] == "Preloaded_Certificate_Profile"
        )
        assert seq_1["certificateAuthenticationProfile"] == ""
        assert seq_0["breakOnStoreFail"] is False
        assert seq_1["breakOnStoreFail"] is False

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

    @staticmethod
    def _active_directory_data() -> dict:
        return {
            "active_directory_join_point": [
                {
                    "data": {
                        "id": "ae1e4320-8d6b-11ee-8e9d-c6c118414b7e",
                        "name": "CORP_AD_wan.example.com",
                        "description": "",
                        "domain": "wan.example.com",
                        "enableDomainAllowedList": True,
                        "adgroups": {
                            "groups": [
                                {"name": "IT-Admins-NYC", "sid": "S-1-5-32-555"},
                                {
                                    "name": "VPN-Users-Remote",
                                    "sid": "S-1-5-21-309816-515",
                                },
                                {
                                    "name": "Finance-Dept-All",
                                    "sid": "S-1-5-21-309816-516",
                                },
                            ]
                        },
                        "advancedSettings": {
                            "enablePassChange": True,
                            "enableMachineAuth": True,
                            "firstName": "givenName",
                            "lastName": "sn",
                            "email": "mail",
                            "department": "department",
                        },
                    },
                    "endpoint": "/ers/config/activedirectory/ae1e4320-8d6b-11ee-8e9d-c6c118414b7e",
                }
            ]
        }

    def test_ise_personal_info_redacted_by_default(self, tmp_path) -> None:
        """ISE personal_info pack (default tier) redacts firstName/lastName under advancedSettings."""
        data = self._active_directory_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        settings = sanitized["active_directory_join_point"][0]["data"][
            "advancedSettings"
        ]
        assert settings["firstName"] == "PERSONAL_INFO-001"
        assert settings["lastName"] == "PERSONAL_INFO-002"
        assert settings["enablePassChange"] is True
        assert settings["enableMachineAuth"] is True
        assert settings["department"] == "department"
        # "email" maps to the AD attribute name "mail", not actual PII here
        assert settings["email"] == "mail"

    def test_ise_active_directory_groups_excluded_by_default(self, tmp_path) -> None:
        """ISE active_directory_groups pack (optional tier) is not applied unless enabled."""
        data = self._active_directory_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        join_point = sanitized["active_directory_join_point"][0]["data"]
        assert join_point["name"] == "CORP_AD_wan.example.com"
        groups = join_point["adgroups"]["groups"]
        assert {g["name"] for g in groups} == {
            "IT-Admins-NYC",
            "VPN-Users-Remote",
            "Finance-Dept-All",
        }

    def test_ise_active_directory_groups_redacts_when_enabled(self, tmp_path) -> None:
        """ISE active_directory_groups pack redacts join point name and AD group names when enabled."""
        data = self._active_directory_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["active_directory_groups"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        join_point = sanitized["active_directory_join_point"][0]["data"]
        assert join_point["name"] == "ACTIVE_DIRECTORY_GROUPS-001"
        groups = join_point["adgroups"]["groups"]
        assert groups[0]["name"] == "ACTIVE_DIRECTORY_GROUPS-002"
        assert groups[1]["name"] == "ACTIVE_DIRECTORY_GROUPS-003"
        assert groups[2]["name"] == "ACTIVE_DIRECTORY_GROUPS-004"

        assert join_point["id"] == "ae1e4320-8d6b-11ee-8e9d-c6c118414b7e"
        assert join_point["domain"] == "wan.example.com"
        assert join_point["enableDomainAllowedList"] is True
        assert join_point["description"] == ""
        assert {g["sid"] for g in groups} == {
            "S-1-5-32-555",
            "S-1-5-21-309816-515",
            "S-1-5-21-309816-516",
        }

    @staticmethod
    def _user_identity_data() -> dict:
        return {
            "internal_user": [
                {
                    "data": {
                        "id": "f49babbd-5a20-4fdb-9c58-9ab1477162ca",
                        "name": "jsmith",
                        "description": "Network Operations Engineer",
                        "enabled": True,
                        "email": "john.smith@example.com",
                        "firstName": "John",
                        "lastName": "Smith",
                        "changePassword": False,
                        "identityGroups": "bd6d88b0-679e-11ee-8e9d-c6c118414b7e",
                        "expiryDateEnabled": False,
                        "passwordIDStore": "Internal Users",
                    },
                    "endpoint": "/ers/config/internaluser/f49babbd-5a20-4fdb-9c58-9ab1477162ca",
                },
                {
                    "data": {
                        "id": "32147735-ec63-4829-acbf-00854d66baeb",
                        "name": "mjones",
                        "description": "",
                        "enabled": True,
                        "email": "mary.jones@example.com",
                        "firstName": "Mary",
                        "lastName": "Jones",
                        "changePassword": False,
                        "identityGroups": "46f8f460-1eb1-11ef-91f1-4a5b331df49b",
                        "expiryDateEnabled": False,
                        "passwordIDStore": "Internal Users",
                    },
                    "endpoint": "/ers/config/internaluser/32147735-ec63-4829-acbf-00854d66baeb",
                },
            ],
            "user_identity_group": [
                {
                    "data": {
                        "id": "a176c430-8c01-11e6-996c-525400b48521",
                        "name": "ALL_ACCOUNTS",
                        "description": "Default ALL_ACCOUNTS (default) User Group",
                        "parent": "NAC Group:NAC:IdentityGroups:User Identity Groups",
                    },
                    "endpoint": "/ers/config/identitygroup/a176c430-8c01-11e6-996c-525400b48521",
                },
                {
                    "data": {
                        "id": "043f1380-f8d1-11ee-8954-a21daf388194",
                        "name": "Aruba_Helpdesk",
                        "description": "Aruba helpdesk operators group",
                        "parent": "NAC Group:NAC:IdentityGroups:User Identity Groups",
                    },
                    "endpoint": "/ers/config/identitygroup/043f1380-f8d1-11ee-8954-a21daf388194",
                },
            ],
        }

    def test_ise_user_personal_info_redacted_by_default(self, tmp_path) -> None:
        """ISE user_personal_info pack (default tier) redacts internal user PII."""
        data = self._user_identity_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        user_0 = sanitized["internal_user"][0]["data"]
        user_1 = sanitized["internal_user"][1]["data"]

        # Personal info redacted by default
        assert user_0["name"] == "USER_PERSONAL_INFO-001"
        assert user_1["name"] == "USER_PERSONAL_INFO-002"
        assert user_0["firstName"] == "USER_PERSONAL_INFO-003"
        assert user_1["firstName"] == "USER_PERSONAL_INFO-004"
        assert user_0["lastName"] == "USER_PERSONAL_INFO-005"
        assert user_1["lastName"] == "USER_PERSONAL_INFO-006"
        assert user_0["email"] == "USER_PERSONAL_INFO-007"
        assert user_1["email"] == "USER_PERSONAL_INFO-008"

        # Non-personal-info fields preserved
        assert user_0["id"] == "f49babbd-5a20-4fdb-9c58-9ab1477162ca"
        assert user_1["id"] == "32147735-ec63-4829-acbf-00854d66baeb"
        assert user_0["enabled"] is True
        assert user_0["identityGroups"] == "bd6d88b0-679e-11ee-8e9d-c6c118414b7e"
        assert user_1["identityGroups"] == "46f8f460-1eb1-11ef-91f1-4a5b331df49b"
        assert user_0["expiryDateEnabled"] is False
        assert user_0["passwordIDStore"] == "Internal Users"
        assert user_1["passwordIDStore"] == "Internal Users"

    def test_ise_user_identity_groups_excluded_by_default(self, tmp_path) -> None:
        """ISE user_identity_groups pack (optional tier) is not applied unless enabled."""
        data = self._user_identity_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        group_0 = sanitized["user_identity_group"][0]["data"]
        group_1 = sanitized["user_identity_group"][1]["data"]
        assert group_0["name"] == "ALL_ACCOUNTS"
        assert group_0["description"] == "Default ALL_ACCOUNTS (default) User Group"
        assert group_1["name"] == "Aruba_Helpdesk"
        assert group_1["description"] == "Aruba helpdesk operators group"

        user_0 = sanitized["internal_user"][0]["data"]
        assert user_0["description"] == "Network Operations Engineer"

    def test_ise_user_identity_groups_redacts_when_enabled(self, tmp_path) -> None:
        """ISE user_identity_groups pack redacts group names/descriptions and internal user description when enabled."""
        data = self._user_identity_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["user_identity_groups"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        group_0 = sanitized["user_identity_group"][0]["data"]
        group_1 = sanitized["user_identity_group"][1]["data"]

        # Sensitive fields redacted
        assert group_0["name"] == "USER_IDENTITY_GROUPS-002"
        assert group_1["name"] == "USER_IDENTITY_GROUPS-003"
        assert group_0["description"] == "USER_IDENTITY_GROUPS-004"
        assert group_1["description"] == "USER_IDENTITY_GROUPS-005"
        assert (
            sanitized["internal_user"][0]["data"]["description"]
            == "USER_IDENTITY_GROUPS-001"
        )

        # Non-sensitive fields preserved
        assert group_0["id"] == "a176c430-8c01-11e6-996c-525400b48521"
        assert group_1["id"] == "043f1380-f8d1-11ee-8954-a21daf388194"
        assert group_0["parent"] == "NAC Group:NAC:IdentityGroups:User Identity Groups"
        assert group_1["parent"] == "NAC Group:NAC:IdentityGroups:User Identity Groups"

    @staticmethod
    def _endpoint_identity_data() -> dict:
        return {
            "endpoint": [
                {
                    "data": {
                        "id": "aabb-ccdd-eeff-0011",
                        "name": "AA:BB:CC:DD:EE:FF",
                        "description": "",
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "staticProfileAssignment": False,
                        "identityStore": "Internal Users",
                        "customAttributes": {
                            "customAttributes": {
                                "UserEmail": "jsmith@example.com",
                                "MDAVCompliant": "Yes",
                            }
                        },
                    },
                    "endpoint": "/ers/config/endpoint/aabb-ccdd-eeff-0011",
                },
                {
                    "data": {
                        "id": "1122-3344-5566-7788",
                        "name": "11:22:33:44:55:66",
                        "description": "",
                        "mac": "11:22:33:44:55:66",
                        "staticProfileAssignment": True,
                        "identityStore": "",
                    },
                    "endpoint": "/ers/config/endpoint/1122-3344-5566-7788",
                },
            ],
            "endpoint_identity_group": [
                {
                    "data": {
                        "id": "a176c430-8c01-11e6-996c-525400b48521",
                        "name": "Profiled",
                        "description": "Endpoint Identity Group for profiled endpoints",
                        "systemDefined": True,
                        "parent": "NAC Group:NAC:IdentityGroups:Endpoint Identity Groups",
                    },
                    "endpoint": "/ers/config/endpointgroup/a176c430-8c01-11e6-996c-525400b48521",
                },
                {
                    "data": {
                        "id": "b287d541-9d02-22f7-aa7d-636622c49622",
                        "name": "BYOD-Registered",
                        "description": "Endpoints registered through BYOD portal",
                        "systemDefined": False,
                        "parent": "NAC Group:NAC:IdentityGroups:Endpoint Identity Groups",
                    },
                    "endpoint": "/ers/config/endpointgroup/b287d541-9d02-22f7-aa7d-636622c49622",
                },
            ],
        }

    def test_ise_endpoint_custom_pii_redacted_by_default(self, tmp_path) -> None:
        """ISE endpoint_custom_pii pack (default tier) redacts UserEmail custom attribute."""
        data = self._endpoint_identity_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        custom_attrs = sanitized["endpoint"][0]["data"]["customAttributes"][
            "customAttributes"
        ]
        assert custom_attrs["UserEmail"] == "ENDPOINT_CUSTOM_PII-001"
        # Non-PII custom attributes preserved
        assert custom_attrs["MDAVCompliant"] == "Yes"

    def test_ise_endpoint_identities_excluded_by_default(self, tmp_path) -> None:
        """ISE endpoint_identities pack (optional tier) is not applied unless enabled."""
        data = self._endpoint_identity_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())
        endpoints = sanitized["endpoint"]
        assert endpoints[0]["data"]["name"] == "AA:BB:CC:DD:EE:FF"
        assert endpoints[1]["data"]["name"] == "11:22:33:44:55:66"

        groups = sanitized["endpoint_identity_group"]
        assert groups[0]["data"]["name"] == "Profiled"
        assert (
            groups[0]["data"]["description"]
            == "Endpoint Identity Group for profiled endpoints"
        )
        assert groups[1]["data"]["name"] == "BYOD-Registered"
        assert (
            groups[1]["data"]["description"]
            == "Endpoints registered through BYOD portal"
        )

    def test_ise_endpoint_identities_redacts_when_enabled(self, tmp_path) -> None:
        """ISE endpoint_identities pack redacts endpoint/group names when enabled."""
        data = self._endpoint_identity_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["endpoint_identities"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        endpoint_0 = sanitized["endpoint"][0]["data"]
        endpoint_1 = sanitized["endpoint"][1]["data"]
        group_0 = sanitized["endpoint_identity_group"][0]["data"]
        group_1 = sanitized["endpoint_identity_group"][1]["data"]

        # Sensitive fields redacted to deterministic preserve_format tokens
        # (name is targeted by the pack; mac is not)
        assert endpoint_0["name"] == "00:00:00:00:00:01"
        assert endpoint_1["name"] == "00:00:00:00:00:02"
        assert group_0["name"] == "00000000"
        assert group_1["name"] == "0000-00000004xx"
        assert (
            group_0["description"] == "00000000 0005xxxx Xxxxx xxx xxxxxxxx xxxxxxxxx"
        )
        assert group_1["description"] == "000000000 006xxxxxxx xxxxxxx XXXX xxxxxx"

        # preserve_format strategy: MAC-formatted names keep their delimiter pattern
        assert re.fullmatch(
            r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:"
            r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}",
            endpoint_0["name"],
        )
        assert re.fullmatch(
            r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:"
            r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}",
            endpoint_1["name"],
        )

        # Non-sensitive fields preserved
        assert endpoint_0["id"] == "aabb-ccdd-eeff-0011"
        assert endpoint_0["mac"] == "AA:BB:CC:DD:EE:FF"
        assert endpoint_0["staticProfileAssignment"] is False
        assert endpoint_0["identityStore"] == "Internal Users"
        assert endpoint_1["id"] == "1122-3344-5566-7788"
        assert endpoint_1["mac"] == "11:22:33:44:55:66"
        assert endpoint_1["staticProfileAssignment"] is True
        assert endpoint_1["identityStore"] == ""

        assert group_0["id"] == "a176c430-8c01-11e6-996c-525400b48521"
        assert group_0["systemDefined"] is True
        assert (
            group_0["parent"] == "NAC Group:NAC:IdentityGroups:Endpoint Identity Groups"
        )
        assert group_1["id"] == "b287d541-9d02-22f7-aa7d-636622c49622"
        assert group_1["systemDefined"] is False
        assert (
            group_1["parent"] == "NAC Group:NAC:IdentityGroups:Endpoint Identity Groups"
        )

    @staticmethod
    def _device_admin_data() -> dict:
        return {
            "device_admin_policy_set": [
                {
                    "data": {
                        "default": False,
                        "id": "8d4c8d67-53c2-477a-bd8d-4803f3604529",
                        "name": "WLC-Admin-Access",
                        "hitCounts": 163,
                        "rank": 0,
                        "state": "enabled",
                        "condition": {
                            "conditionType": "ConditionAttributes",
                            "isNegate": False,
                            "dictionaryName": "DEVICE",
                            "attributeName": "Device Type",
                            "operator": "equals",
                            "attributeValue": "WLC-Controllers",
                        },
                        "serviceName": "Default Device Admin",
                    },
                    "endpoint": "/api/v1/policy/device-admin/policy-set/8d4c8d67",
                    "children": {
                        "device_admin_authentication_rule": [
                            {
                                "data": {
                                    "rule": {
                                        "default": False,
                                        "id": "e981e926-40e9-43ff-94d2-30fb1e0a7233",
                                        "name": "AD-Auth-Rule",
                                        "hitCounts": 91,
                                        "rank": 0,
                                        "state": "enabled",
                                        "condition": {
                                            "conditionType": "ConditionAttributes",
                                            "isNegate": False,
                                            "dictionaryName": "DEVICE",
                                            "attributeName": "Location",
                                            "operator": "equals",
                                            "attributeValue": "Building-A",
                                        },
                                    },
                                    "identitySourceName": "All_User_ID_Stores",
                                    "ifAuthFail": "REJECT",
                                    "ifUserNotFound": "REJECT",
                                    "ifProcessFail": "DROP",
                                },
                                "endpoint": "/authentication/e981e926",
                            }
                        ],
                        "device_admin_authorization_rule": [
                            {
                                "data": {
                                    "rule": {
                                        "default": False,
                                        "id": "f123g456-78hi-90jk-lmno-pqrstuvwxyz",
                                        "name": "Admin-Priv15-Rule",
                                        "hitCounts": 50,
                                        "rank": 0,
                                        "state": "enabled",
                                        "condition": {
                                            "conditionType": "ConditionAttributes",
                                            "isNegate": False,
                                            "dictionaryName": "IdentityGroup",
                                            "attributeName": "Name",
                                            "operator": "equals",
                                            "attributeValue": "Network-Admins",
                                        },
                                    },
                                    "profile": "Priv15-Shell-Profile",
                                    "commands": ["PermitAll-Commands"],
                                },
                                "endpoint": "/authorization/f123g456",
                            }
                        ],
                    },
                }
            ],
            "device_admin_condition": [
                {
                    "data": {
                        "id": "cond-001",
                        "name": "Is-Wireless-Controller",
                        "conditionType": "LibraryConditionAttributes",
                        "dictionaryName": "DEVICE",
                        "attributeName": "Device Type",
                        "operator": "equals",
                        "attributeValue": "Wireless-LAN-Controller",
                    },
                    "endpoint": "/api/v1/policy/device-admin/condition/cond-001",
                }
            ],
        }

    def test_ise_device_admin_policy_names_excluded_by_default(self, tmp_path) -> None:
        """ISE device_admin_policy_names pack (optional tier) is not applied unless enabled."""
        data = self._device_admin_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["ise"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        policy_set = sanitized["device_admin_policy_set"][0]["data"]
        assert policy_set["name"] == "WLC-Admin-Access"

        condition = sanitized["device_admin_condition"][0]["data"]
        assert condition["name"] == "Is-Wireless-Controller"

        children = sanitized["device_admin_policy_set"][0]["children"]
        authn_rule = children["device_admin_authentication_rule"][0]["data"]["rule"]
        authz_rule = children["device_admin_authorization_rule"][0]["data"]["rule"]
        assert authn_rule["name"] == "AD-Auth-Rule"
        assert authz_rule["name"] == "Admin-Priv15-Rule"

    def test_ise_device_admin_policy_names_redacts_when_enabled(self, tmp_path) -> None:
        """ISE device_admin_policy_names pack redacts policy set/rule/condition names when enabled."""
        data = self._device_admin_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["device_admin_policy_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        policy_set = sanitized["device_admin_policy_set"][0]["data"]
        children = sanitized["device_admin_policy_set"][0]["children"]
        authn_rule = children["device_admin_authentication_rule"][0]["data"]["rule"]
        authz_rule = children["device_admin_authorization_rule"][0]["data"]["rule"]
        condition_entry = sanitized["device_admin_condition"][0]["data"]

        # Sensitive names redacted to deterministic tokens
        assert policy_set["name"] == "DEVICE_ADMIN_POLICY_NAMES-001"
        assert condition_entry["name"] == "DEVICE_ADMIN_POLICY_NAMES-002"
        assert authn_rule["name"] == "DEVICE_ADMIN_POLICY_NAMES-003"
        assert authz_rule["name"] == "DEVICE_ADMIN_POLICY_NAMES-004"

        # Non-sensitive fields preserved
        assert policy_set["id"] == "8d4c8d67-53c2-477a-bd8d-4803f3604529"
        assert policy_set["hitCounts"] == 163
        assert policy_set["rank"] == 0
        assert policy_set["state"] == "enabled"
        assert policy_set["serviceName"] == "Default Device Admin"
        assert policy_set["condition"]["operator"] == "equals"
        assert authn_rule["id"] == "e981e926-40e9-43ff-94d2-30fb1e0a7233"
        assert authn_rule["hitCounts"] == 91
        assert authn_rule["state"] == "enabled"
        assert authz_rule["id"] == "f123g456-78hi-90jk-lmno-pqrstuvwxyz"
        assert authz_rule["hitCounts"] == 50
        assert authz_rule["state"] == "enabled"

    def test_ise_device_admin_condition_values_redacts_when_enabled(
        self, tmp_path
    ) -> None:
        """ISE device_admin_condition_values pack redacts condition attributes when enabled."""
        data = self._device_admin_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["device_admin_condition_values"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        policy_set = sanitized["device_admin_policy_set"][0]["data"]
        children = sanitized["device_admin_policy_set"][0]["children"]
        authn_rule = children["device_admin_authentication_rule"][0]["data"]["rule"]
        authz_rule = children["device_admin_authorization_rule"][0]["data"]["rule"]

        # Values that occur only within a "condition" wrapper are redacted to
        # deterministic tokens. (Device Type / DEVICE also appear unwrapped in
        # device_admin_condition, which this pack intentionally does not
        # target, so they are checked per-field below.)
        assert (
            policy_set["condition"]["attributeValue"]
            == "DEVICE_ADMIN_CONDITION_VALUES-001"
        )
        assert (
            policy_set["condition"]["attributeName"]
            == "DEVICE_ADMIN_CONDITION_VALUES-004"
        )
        assert (
            policy_set["condition"]["dictionaryName"]
            == "DEVICE_ADMIN_CONDITION_VALUES-007"
        )
        assert (
            authn_rule["condition"]["attributeValue"]
            == "DEVICE_ADMIN_CONDITION_VALUES-002"
        )
        assert (
            authn_rule["condition"]["attributeName"]
            == "DEVICE_ADMIN_CONDITION_VALUES-005"
        )
        assert (
            authn_rule["condition"]["dictionaryName"]
            == "DEVICE_ADMIN_CONDITION_VALUES-007"
        )
        assert (
            authz_rule["condition"]["attributeValue"]
            == "DEVICE_ADMIN_CONDITION_VALUES-003"
        )
        assert (
            authz_rule["condition"]["dictionaryName"]
            == "DEVICE_ADMIN_CONDITION_VALUES-008"
        )

        # Non-sensitive fields preserved
        assert policy_set["condition"]["conditionType"] == "ConditionAttributes"
        assert policy_set["condition"]["isNegate"] is False
        assert policy_set["condition"]["operator"] == "equals"
        assert authn_rule["condition"]["conditionType"] == "ConditionAttributes"
        assert authn_rule["condition"]["isNegate"] is False
        assert authn_rule["condition"]["operator"] == "equals"

        # device_admin_condition entries are not wrapped in a "condition" key,
        # so this pack does not touch them.
        condition_entry = sanitized["device_admin_condition"][0]["data"]
        assert condition_entry["attributeValue"] == "Wireless-LAN-Controller"
        assert condition_entry["attributeName"] == "Device Type"
        assert condition_entry["dictionaryName"] == "DEVICE"

    def test_ise_device_admin_authz_refs_redacts_when_enabled(self, tmp_path) -> None:
        """ISE device_admin_authz_refs pack redacts authorization profile/commands when enabled."""
        data = self._device_admin_data()
        input_file = tmp_path / "ise.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["ise"],
            packs=PackConfig(enable=["device_admin_authz_refs"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "ise.json").read_text())

        children = sanitized["device_admin_policy_set"][0]["children"]
        authz_data = children["device_admin_authorization_rule"][0]["data"]
        authz_rule = authz_data["rule"]

        # Sensitive authorization references redacted to deterministic tokens
        assert authz_data["profile"] == "DEVICE_ADMIN_AUTHZ_REFS-001"
        assert authz_data["commands"][0] == "DEVICE_ADMIN_AUTHZ_REFS-002"

        # Non-sensitive fields preserved
        assert authz_rule["id"] == "f123g456-78hi-90jk-lmno-pqrstuvwxyz"
        assert authz_rule["hitCounts"] == 50
        assert authz_rule["state"] == "enabled"
        assert authz_rule["name"] == "Admin-Priv15-Rule"


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


@pytest.mark.unit
class TestCatalystCenterProfileRegistry:
    def test_cc_profile_available(self) -> None:
        available = ProfileRegistry.available()
        assert "catalyst_center" in available

    def test_load_cc_profile(self) -> None:
        profile = ProfileRegistry.load("catalyst_center")
        assert profile["name"] == "catalyst_center"
        assert "packs" in profile

    def test_cc_rules_have_valid_paths(self) -> None:
        rules = ProfileRegistry.load_rules("catalyst_center")
        resolver = PathResolver()
        for rule in rules:
            resolver.parse(rule.path)

    def test_cc_rules_have_valid_strategies(self) -> None:
        valid_strategies = {
            "token",
            "ip_map",
            "hostname_map",
            "constant",
            "hash",
            "preserve_format",
        }
        rules = ProfileRegistry.load_rules("catalyst_center")
        for rule in rules:
            assert rule.strategy in valid_strategies, (
                f"Unknown strategy '{rule.strategy}' in path {rule.path}"
            )

    def test_cc_transit_network_names_pack_is_optional_tier(self) -> None:
        """Catalyst Center transit_network_names pack should be optional tier."""
        rules = ProfileRegistry.load_rules("catalyst_center")
        transit_rules = [r for r in rules if r.category == "TRANSIT_NETWORK_NAMES"]
        assert len(transit_rules) > 0
        assert all(r.tier == "optional" for r in transit_rules)

    def test_cc_authentication_descriptions_pack_is_optional_tier(self) -> None:
        """Load catalyst_center profile, filter by AUTHENTICATION_DESCRIPTIONS category, verify tier is optional."""
        rules = ProfileRegistry.load_rules("catalyst_center")
        auth_rules = [r for r in rules if r.category == "AUTHENTICATION_DESCRIPTIONS"]
        assert len(auth_rules) > 0
        assert all(r.tier == "optional" for r in auth_rules)

    def test_cc_image_names_pack_is_optional_tier(self) -> None:
        rules = ProfileRegistry.load_rules("catalyst_center")
        image_rules = [r for r in rules if r.category == "IMAGE_NAMES"]
        assert len(image_rules) > 0
        assert all(r.tier == "optional" for r in image_rules)

    def test_cc_user_pii_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("catalyst_center")
        user_pii_rules = [r for r in rules if r.category == "USER_PII"]
        assert len(user_pii_rules) > 0
        assert all(r.tier == "default" for r in user_pii_rules)

    def test_cc_credential_descriptions_pack_is_default_tier(self) -> None:
        rules = ProfileRegistry.load_rules("catalyst_center")
        cred_desc_rules = [r for r in rules if r.category == "CREDENTIAL_DESCRIPTIONS"]
        assert len(cred_desc_rules) > 0
        assert all(r.tier == "default" for r in cred_desc_rules)

    def test_cc_credential_descriptions_redacted_by_default(self, tmp_path) -> None:
        """Default tier credential_descriptions pack redacts descriptions in all credential types."""
        data = {
            "credentials_cli": [
                {
                    "data": [
                        {
                            "cliCredential": [
                                {
                                    "password": "secret123",
                                    "username": "netadmin",
                                    "enablePassword": "enable123",
                                    "description": "Primary network device CLI access for Building A switches",
                                    "instanceUuid": "1a8f70b3-984d-438e-896e-2bb199040427",
                                    "id": "1a8f70b3-984d-438e-896e-2bb199040427",
                                }
                            ],
                            "snmpV3": [
                                {
                                    "username": "snmpuser",
                                    "authPassword": "authpass",
                                    "authType": "SHA",
                                    "privacyPassword": "privpass",
                                    "privacyType": "AES128",
                                    "snmpMode": "AUTHPRIV",
                                    "description": "SNMPv3 credentials for core infrastructure monitoring",
                                    "instanceUuid": "63cd4759-5b92-4195-b96e-c64661a8152d",
                                    "id": "63cd4759-5b92-4195-b96e-c64661a8152d",
                                }
                            ],
                            "netconfCredential": [
                                {
                                    "netconfPort": "830",
                                    "description": "NETCONF access for automated config management",
                                    "instanceUuid": "caeb7cae-8329-4bad-b49b-d1a7e0b25eeb",
                                    "id": "caeb7cae-8329-4bad-b49b-d1a7e0b25eeb",
                                }
                            ],
                        }
                    ],
                    "endpoint": "/dna/intent/api/v2/global-credential",
                }
            ]
        }
        input_file = tmp_path / "cc.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["catalyst_center"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "cc.json").read_text())

        # Descriptions should be redacted (default tier)
        cred_data = sanitized["credentials_cli"][0]["data"][0]
        assert (
            cred_data["cliCredential"][0]["description"]
            == "CREDENTIAL_DESCRIPTIONS-001"
        )
        assert cred_data["snmpV3"][0]["description"] == "CREDENTIAL_DESCRIPTIONS-002"
        assert (
            cred_data["netconfCredential"][0]["description"]
            == "CREDENTIAL_DESCRIPTIONS-003"
        )

        # Non-sensitive fields should be preserved
        assert (
            cred_data["cliCredential"][0]["instanceUuid"]
            == "1a8f70b3-984d-438e-896e-2bb199040427"
        )
        assert (
            cred_data["cliCredential"][0]["id"]
            == "1a8f70b3-984d-438e-896e-2bb199040427"
        )
        assert cred_data["snmpV3"][0]["authType"] == "SHA"
        assert cred_data["snmpV3"][0]["snmpMode"] == "AUTHPRIV"
        assert cred_data["netconfCredential"][0]["netconfPort"] == "830"

    def test_cc_credential_descriptions_can_be_disabled(self, tmp_path) -> None:
        """credential_descriptions pack can be disabled to preserve descriptions."""
        data = {
            "credentials_cli": [
                {
                    "data": [
                        {
                            "cliCredential": [
                                {
                                    "password": "secret123",
                                    "username": "netadmin",
                                    "description": "Primary network device CLI access for Building A switches",
                                    "instanceUuid": "1a8f70b3-984d-438e-896e-2bb199040427",
                                }
                            ],
                            "snmpV3": [
                                {
                                    "username": "snmpuser",
                                    "description": "SNMPv3 credentials for core infrastructure monitoring",
                                    "instanceUuid": "63cd4759-5b92-4195-b96e-c64661a8152d",
                                }
                            ],
                            "netconfCredential": [
                                {
                                    "description": "NETCONF access for automated config management",
                                    "instanceUuid": "caeb7cae-8329-4bad-b49b-d1a7e0b25eeb",
                                }
                            ],
                        }
                    ],
                    "endpoint": "/dna/intent/api/v2/global-credential",
                }
            ]
        }
        input_file = tmp_path / "cc.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["catalyst_center"],
            packs=PackConfig(disable=["credential_descriptions"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "cc.json").read_text())

        # Descriptions should NOT be redacted when disabled
        cred_data = sanitized["credentials_cli"][0]["data"][0]
        assert (
            cred_data["cliCredential"][0]["description"]
            == "Primary network device CLI access for Building A switches"
        )
        assert (
            cred_data["snmpV3"][0]["description"]
            == "SNMPv3 credentials for core infrastructure monitoring"
        )
        assert (
            cred_data["netconfCredential"][0]["description"]
            == "NETCONF access for automated config management"
        )

    def test_cc_transit_network_names_excluded_by_default(self, tmp_path) -> None:
        """Transit network names should NOT be redacted by default (optional tier)."""
        data = {
            "transit_network": [
                {
                    "data": [
                        {
                            "id": "02db99e6-e565-4419-b9fe-8dd7f2bbe244",
                            "name": "DC-Core-Transit",
                            "type": "IP_BASED_TRANSIT",
                            "ipTransitSettings": {
                                "routingProtocolName": "BGP",
                                "autonomousSystemNumber": "1000",
                            },
                        },
                        {
                            "id": "04f1a0f9-98c3-469e-8c34-1b8d10c48910",
                            "name": "Campus-Edge-Transit",
                            "type": "IP_BASED_TRANSIT",
                            "ipTransitSettings": {
                                "routingProtocolName": "BGP",
                                "autonomousSystemNumber": "5009",
                            },
                        },
                    ],
                    "endpoint": "/dna/intent/api/v1/business/sda/transit-networks",
                }
            ]
        }
        input_file = tmp_path / "catalyst_center.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["catalyst_center"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "catalyst_center.json").read_text())
        # Transit network names should NOT be redacted by default (optional tier)
        assert sanitized["transit_network"][0]["data"][0]["name"] == "DC-Core-Transit"
        assert (
            sanitized["transit_network"][0]["data"][1]["name"] == "Campus-Edge-Transit"
        )

    def test_cc_transit_network_names_redacts_when_enabled(self, tmp_path) -> None:
        """Transit network names should be redacted when explicitly enabled."""
        data = {
            "transit_network": [
                {
                    "data": [
                        {
                            "id": "02db99e6-e565-4419-b9fe-8dd7f2bbe244",
                            "name": "DC-Core-Transit",
                            "type": "IP_BASED_TRANSIT",
                            "ipTransitSettings": {
                                "routingProtocolName": "BGP",
                                "autonomousSystemNumber": "1000",
                            },
                        },
                        {
                            "id": "04f1a0f9-98c3-469e-8c34-1b8d10c48910",
                            "name": "Campus-Edge-Transit",
                            "type": "IP_BASED_TRANSIT",
                            "ipTransitSettings": {
                                "routingProtocolName": "BGP",
                                "autonomousSystemNumber": "5009",
                            },
                        },
                    ],
                    "endpoint": "/dna/intent/api/v1/business/sda/transit-networks",
                }
            ]
        }
        input_file = tmp_path / "catalyst_center.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["catalyst_center"],
            packs=PackConfig(enable=["transit_network_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "catalyst_center.json").read_text())
        # Transit network names should be redacted
        assert (
            sanitized["transit_network"][0]["data"][0]["name"]
            == "TRANSIT_NETWORK_NAMES-001"
        )
        assert (
            sanitized["transit_network"][0]["data"][1]["name"]
            == "TRANSIT_NETWORK_NAMES-002"
        )
        # But other fields should be preserved
        assert (
            sanitized["transit_network"][0]["data"][0]["id"]
            == "02db99e6-e565-4419-b9fe-8dd7f2bbe244"
        )

    def test_cc_authentication_descriptions_excluded_by_default(self, tmp_path) -> None:
        """With profiles=['catalyst_center'], verify authentication descriptions NOT redacted by default."""
        data = {
            "authentication_policy_server": [
                {
                    "data": [
                        {
                            "ipAddress": "10.0.0.140",
                            "protocol": "RADI_TACACS",
                            "role": "primary",
                            "port": 49,
                            "isIseEnabled": True,
                            "ciscoIseDtos": [
                                {
                                    "description": "Primary ISE PAN node",
                                    "fqdn": "ise-pan-01.corp.example.com",
                                    "ipAddress": "10.0.0.140",
                                    "subscriberName": "ise-pan-01",
                                    "userName": "admin",
                                }
                            ],
                            "state": "ACTIVE",
                        }
                    ],
                    "endpoint": "/dna/intent/api/v1/authentication-policy-servers",
                }
            ],
            "update_authentication_profile": [
                {
                    "data": [
                        {
                            "siteNameHierarchy": "Global/US/Building-A",
                            "preAuthAcl": {
                                "description": "Pre-auth ACL for guest captive portal redirect",
                                "enabled": True,
                            },
                            "dot1xToMabFallbackTimeout": 21,
                        }
                    ],
                    "endpoint": "/dna/intent/api/v1/authentication-profile",
                }
            ],
        }
        input_file = tmp_path / "catalyst_center.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["catalyst_center"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "catalyst_center.json").read_text())
        # Descriptions and FQDNs should NOT be redacted (optional tier, not enabled)
        assert (
            sanitized["authentication_policy_server"][0]["data"][0]["ciscoIseDtos"][0][
                "description"
            ]
            == "Primary ISE PAN node"
        )
        assert (
            sanitized["authentication_policy_server"][0]["data"][0]["ciscoIseDtos"][0][
                "fqdn"
            ]
            == "ise-pan-01.corp.example.com"
        )
        assert (
            sanitized["update_authentication_profile"][0]["data"][0]["preAuthAcl"][
                "description"
            ]
            == "Pre-auth ACL for guest captive portal redirect"
        )

    def test_cc_authentication_descriptions_redacts_when_enabled(
        self, tmp_path
    ) -> None:
        """With PackConfig(enable=['authentication_descriptions']), verify descriptions/fqdns are redacted but other fields preserved."""
        data = {
            "authentication_policy_server": [
                {
                    "data": [
                        {
                            "ipAddress": "10.0.0.140",
                            "protocol": "RADI_TACACS",
                            "role": "primary",
                            "port": 49,
                            "isIseEnabled": True,
                            "ciscoIseDtos": [
                                {
                                    "description": "Primary ISE PAN node",
                                    "fqdn": "ise-pan-01.corp.example.com",
                                    "ipAddress": "10.0.0.140",
                                    "subscriberName": "ise-pan-01",
                                    "userName": "admin",
                                }
                            ],
                            "state": "ACTIVE",
                        }
                    ],
                    "endpoint": "/dna/intent/api/v1/authentication-policy-servers",
                }
            ],
            "update_authentication_profile": [
                {
                    "data": [
                        {
                            "siteNameHierarchy": "Global/US/Building-A",
                            "preAuthAcl": {
                                "description": "Pre-auth ACL for guest captive portal redirect",
                                "enabled": True,
                            },
                            "dot1xToMabFallbackTimeout": 21,
                        }
                    ],
                    "endpoint": "/dna/intent/api/v1/authentication-profile",
                }
            ],
        }
        input_file = tmp_path / "catalyst_center.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["catalyst_center"],
            packs=PackConfig(enable=["authentication_descriptions"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "catalyst_center.json").read_text())

        # Descriptions and FQDNs should be redacted
        auth_server = sanitized["authentication_policy_server"][0]["data"][0]
        assert (
            auth_server["ciscoIseDtos"][0]["description"]
            == "AUTHENTICATION_DESCRIPTIONS-001"
        )
        assert (
            auth_server["ciscoIseDtos"][0]["fqdn"] == "AUTHENTICATION_DESCRIPTIONS-002"
        )
        auth_profile = sanitized["update_authentication_profile"][0]["data"][0]
        assert (
            auth_profile["preAuthAcl"]["description"]
            == "AUTHENTICATION_DESCRIPTIONS-003"
        )

        # But non-sensitive fields should be preserved
        assert auth_server["ipAddress"] == "10.0.0.140"
        assert auth_server["protocol"] == "RADI_TACACS"
        assert auth_server["role"] == "primary"
        assert auth_server["port"] == 49
        assert auth_server["state"] == "ACTIVE"
        assert auth_server["isIseEnabled"] is True

        assert auth_profile["preAuthAcl"]["enabled"] is True
        assert auth_profile["dot1xToMabFallbackTimeout"] == 21
        assert auth_profile["siteNameHierarchy"] == "Global/US/Building-A"

    @staticmethod
    def _image_data() -> dict:
        return {
            "image": [
                {
                    "data": [
                        {
                            "imageUuid": "fe242a27-92a9-4bc9-856b-645c4cd9cc73",
                            "name": "cat9k_iosxe.17.09.03.SPA.bin",
                            "family": "CAT9K",
                            "version": "17.09.03.0.4111",
                            "imageType": "SYSTEM_SW",
                            "fileSize": "1246984471 bytes",
                            "isTaggedGolden": False,
                        },
                        {
                            "imageUuid": "ab123456-78cd-90ef-1234-567890abcdef",
                            "name": "cat9k_iosxe.17.12.01.SPA.bin",
                            "family": "CAT9K",
                            "version": "17.12.01.0.5678",
                            "imageType": "SYSTEM_SW",
                            "fileSize": "1398765432 bytes",
                            "isTaggedGolden": True,
                        },
                    ],
                    "endpoint": "/dna/intent/api/v1/image/importation",
                }
            ]
        }

    def test_cc_image_names_excluded_by_default(self, tmp_path) -> None:
        """Image names are optional tier - should NOT be redacted by default."""
        data = self._image_data()
        input_file = tmp_path / "cc.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["catalyst_center"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "cc.json").read_text())
        img1 = sanitized["image"][0]["data"][0]
        img2 = sanitized["image"][0]["data"][1]
        # Optional pack not enabled - names should be preserved
        assert img1["name"] == "cat9k_iosxe.17.09.03.SPA.bin"
        assert img2["name"] == "cat9k_iosxe.17.12.01.SPA.bin"

    def test_cc_image_names_redacts_when_enabled(self, tmp_path) -> None:
        """With PackConfig(enable=['image_names']), image names are redacted."""
        data = self._image_data()
        input_file = tmp_path / "cc.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["catalyst_center"],
            packs=PackConfig(enable=["image_names"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "cc.json").read_text())
        img1 = sanitized["image"][0]["data"][0]
        img2 = sanitized["image"][0]["data"][1]

        # Sensitive fields redacted
        assert img1["name"] == "IMAGE_NAMES-001"
        assert img2["name"] == "IMAGE_NAMES-002"

        # Non-sensitive fields preserved
        assert img1["imageUuid"] == "fe242a27-92a9-4bc9-856b-645c4cd9cc73"
        assert img1["family"] == "CAT9K"
        assert img1["version"] == "17.09.03.0.4111"
        assert img1["imageType"] == "SYSTEM_SW"
        assert img1["fileSize"] == "1246984471 bytes"
        assert img1["isTaggedGolden"] is False

        assert img2["imageUuid"] == "ab123456-78cd-90ef-1234-567890abcdef"
        assert img2["family"] == "CAT9K"
        assert img2["version"] == "17.12.01.0.5678"
        assert img2["imageType"] == "SYSTEM_SW"
        assert img2["fileSize"] == "1398765432 bytes"
        assert img2["isTaggedGolden"] is True

    def test_cc_user_pii_redacted_by_default(self, tmp_path) -> None:
        """Catalyst Center profile default-tier user_pii pack redacts email, firstName, lastName."""
        data = {
            "user": [
                {
                    "data": [
                        {
                            "users": [
                                {
                                    "username": "admin",
                                    "email": "john.admin@example.com",
                                    "firstName": "John",
                                    "lastName": "Admin",
                                    "roleList": ["SUPER-ADMIN-ROLE"],
                                    "userId": "abc-123-def",
                                },
                                {
                                    "username": "netops",
                                    "email": "mary.netops@example.com",
                                    "firstName": "Mary",
                                    "lastName": "NetOps",
                                    "roleList": ["NETWORK-ADMIN-ROLE"],
                                    "userId": "ghi-456-jkl",
                                },
                            ]
                        }
                    ],
                    "endpoint": "/dna/system/api/v1/user",
                }
            ]
        }
        input_file = tmp_path / "catalyst_center.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(profiles=["catalyst_center"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "catalyst_center.json").read_text())

        # PII fields should be redacted to deterministic tokens
        assert sanitized["user"][0]["data"][0]["users"][0]["email"] == "USER_PII-001"
        assert sanitized["user"][0]["data"][0]["users"][1]["email"] == "USER_PII-002"
        assert (
            sanitized["user"][0]["data"][0]["users"][0]["firstName"] == "USER_PII-003"
        )
        assert (
            sanitized["user"][0]["data"][0]["users"][1]["firstName"] == "USER_PII-004"
        )
        assert sanitized["user"][0]["data"][0]["users"][0]["lastName"] == "USER_PII-005"
        assert sanitized["user"][0]["data"][0]["users"][1]["lastName"] == "USER_PII-006"

        # Non-PII fields should be preserved
        assert sanitized["user"][0]["data"][0]["users"][0]["username"] == "admin"
        assert sanitized["user"][0]["data"][0]["users"][0]["roleList"] == [
            "SUPER-ADMIN-ROLE"
        ]
        assert sanitized["user"][0]["data"][0]["users"][0]["userId"] == "abc-123-def"
        assert sanitized["user"][0]["data"][0]["users"][1]["username"] == "netops"
        assert sanitized["user"][0]["data"][0]["users"][1]["roleList"] == [
            "NETWORK-ADMIN-ROLE"
        ]
        assert sanitized["user"][0]["data"][0]["users"][1]["userId"] == "ghi-456-jkl"

    def test_cc_user_pii_can_be_disabled(self, tmp_path) -> None:
        """Catalyst Center user_pii pack fields NOT redacted when disabled."""
        data = {
            "user": [
                {
                    "data": [
                        {
                            "users": [
                                {
                                    "username": "admin",
                                    "email": "john.admin@example.com",
                                    "firstName": "John",
                                    "lastName": "Admin",
                                    "roleList": ["SUPER-ADMIN-ROLE"],
                                    "userId": "abc-123-def",
                                }
                            ]
                        }
                    ],
                    "endpoint": "/dna/system/api/v1/user",
                }
            ]
        }
        input_file = tmp_path / "catalyst_center.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            profiles=["catalyst_center"],
            packs=PackConfig(disable=["user_pii"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "catalyst_center.json").read_text())
        user = sanitized["user"][0]["data"][0]["users"][0]
        assert user["email"] == "john.admin@example.com"
        assert user["firstName"] == "John"
        assert user["lastName"] == "Admin"
