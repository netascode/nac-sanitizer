# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Tests for configuration loading and merging."""

import pytest

from nac_sanitizer.config.loader import ConfigurationError, load_config
from nac_sanitizer.config.models import SanitizerConfig


@pytest.mark.unit
class TestLoadConfigDefaults:
    def test_no_arguments_returns_defaults(self) -> None:
        config = load_config()
        assert config == SanitizerConfig()
        assert config.profiles == []
        assert config.packs.enable == []
        assert config.packs.disable == []
        assert config.overrides == []
        assert config.custom_rules == []

    def test_default_ip_pools_populated(self) -> None:
        config = load_config()
        assert len(config.settings.ip_pools.ipv4_pools) == 7
        assert len(config.settings.ip_pools.ipv6_pools) == 2
        assert config.settings.ip_pools.preserve_prefix_length is True


@pytest.mark.unit
class TestLoadConfigFromFile:
    def test_valid_yaml_config(self, tmp_path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            """
profiles:
  - sdwan

packs:
  enable:
    - snmp_communities
    - hostnames
  disable:
    - usernames

overrides:
  - path: "$.devices[*].location"
    tier: default
    strategy: token

custom_rules:
  - path: "$.devices[*].custom_field"
    strategy: token
    category: "CUSTOM"

settings:
  ip_pools:
    preserve_prefix_length: false
"""
        )
        config = load_config(config_path=config_file)
        assert config.profiles == ["sdwan"]
        assert config.packs.enable == ["snmp_communities", "hostnames"]
        assert config.packs.disable == ["usernames"]
        assert len(config.overrides) == 1
        assert config.overrides[0].path == "$.devices[*].location"
        assert config.overrides[0].tier == "default"
        assert len(config.custom_rules) == 1
        assert config.custom_rules[0].category == "CUSTOM"
        assert config.settings.ip_pools.preserve_prefix_length is False

    def test_empty_yaml_returns_defaults(self, tmp_path) -> None:
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        config = load_config(config_path=config_file)
        assert config == SanitizerConfig()

    def test_minimal_yaml(self, tmp_path) -> None:
        config_file = tmp_path / "minimal.yaml"
        config_file.write_text("profiles:\n  - catalyst_center\n")
        config = load_config(config_path=config_file)
        assert config.profiles == ["catalyst_center"]

    def test_missing_file_raises_error(self, tmp_path) -> None:
        missing = tmp_path / "nonexistent.yaml"
        with pytest.raises(ConfigurationError, match="not found"):
            load_config(config_path=missing)

    def test_directory_path_raises_error(self, tmp_path) -> None:
        with pytest.raises(ConfigurationError, match="not a file"):
            load_config(config_path=tmp_path)

    def test_invalid_yaml_raises_error(self, tmp_path) -> None:
        config_file = tmp_path / "bad.yaml"
        config_file.write_text("  :\n    - [invalid\n")
        with pytest.raises(ConfigurationError, match="Failed to parse"):
            load_config(config_path=config_file)

    def test_non_mapping_yaml_raises_error(self, tmp_path) -> None:
        config_file = tmp_path / "list.yaml"
        config_file.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigurationError, match="must contain a YAML mapping"):
            load_config(config_path=config_file)


@pytest.mark.unit
class TestLoadConfigWithProfileNames:
    def test_profile_names_added(self) -> None:
        config = load_config(profile_names=["sdwan", "ise"])
        assert config.profiles == ["sdwan", "ise"]

    def test_profile_names_merged_with_file(self, tmp_path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("profiles:\n  - sdwan\n")
        config = load_config(config_path=config_file, profile_names=["ise"])
        assert "sdwan" in config.profiles
        assert "ise" in config.profiles

    def test_duplicate_profiles_not_repeated(self, tmp_path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("profiles:\n  - sdwan\n")
        config = load_config(config_path=config_file, profile_names=["sdwan"])
        assert config.profiles.count("sdwan") == 1


@pytest.mark.unit
class TestLoadConfigWithCLIOverrides:
    def test_cli_overrides_applied(self) -> None:
        config = load_config(cli_overrides={"profiles": ["sdwan"]})
        assert config.profiles == ["sdwan"]

    def test_cli_overrides_none_values_ignored(self) -> None:
        config = load_config(cli_overrides={"profiles": None})
        assert config.profiles == []


@pytest.mark.unit
class TestConfigValidation:
    def test_invalid_override_missing_required_field(self, tmp_path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            """
overrides:
  - path: "$.some.path"
"""
        )
        with pytest.raises(ConfigurationError, match="validation error"):
            load_config(config_path=config_file)
