"""Tests for the JSONPath resolution engine."""

import pytest

from nac_sanitizer.engine.resolver import PathResolutionError, PathResolver


@pytest.fixture
def resolver() -> PathResolver:
    return PathResolver()


@pytest.fixture
def sample_data() -> dict:
    return {
        "devices": [
            {
                "hostname": "core-rtr-01",
                "mgmt_ip": "10.50.1.1",
                "interfaces": [
                    {"name": "GigabitEthernet0/0", "ip_address": "10.50.1.1"},
                    {"name": "GigabitEthernet0/1", "ip_address": "10.50.2.1"},
                ],
                "config": {
                    "snmp": {"community": "pr1vat3"},
                    "aaa": {"password": "secret123"},
                },
            },
            {
                "hostname": "dist-sw-01",
                "mgmt_ip": "10.50.1.2",
                "interfaces": [
                    {"name": "Vlan100", "ip_address": "10.50.3.1"},
                ],
                "config": {
                    "snmp": {"community": "publ1c"},
                    "aaa": {"password": "other456"},
                },
            },
        ]
    }


@pytest.mark.unit
class TestParse:
    def test_simple_path(self, resolver) -> None:
        expr = resolver.parse("$.devices[0].hostname")
        assert expr is not None

    def test_cached_expression(self, resolver) -> None:
        expr1 = resolver.parse("$.devices[*].hostname")
        expr2 = resolver.parse("$.devices[*].hostname")
        assert expr1 is expr2

    def test_invalid_path_raises_error(self, resolver) -> None:
        with pytest.raises(PathResolutionError, match="Invalid JSONPath"):
            resolver.parse("$.[[[invalid")


@pytest.mark.unit
class TestFindMatches:
    def test_simple_dot_path(self, resolver, sample_data) -> None:
        matches = resolver.find_matches("$.devices[0].hostname", sample_data)
        assert len(matches) == 1
        assert matches[0].value == "core-rtr-01"

    def test_wildcard_path(self, resolver, sample_data) -> None:
        matches = resolver.find_matches("$.devices[*].hostname", sample_data)
        assert len(matches) == 2
        values = [m.value for m in matches]
        assert "core-rtr-01" in values
        assert "dist-sw-01" in values

    def test_nested_wildcard(self, resolver, sample_data) -> None:
        matches = resolver.find_matches(
            "$.devices[*].interfaces[*].ip_address", sample_data
        )
        assert len(matches) == 3
        values = [m.value for m in matches]
        assert "10.50.1.1" in values
        assert "10.50.2.1" in values
        assert "10.50.3.1" in values

    def test_recursive_descent(self, resolver, sample_data) -> None:
        matches = resolver.find_matches("$..password", sample_data)
        assert len(matches) == 2
        values = [m.value for m in matches]
        assert "secret123" in values
        assert "other456" in values

    def test_no_matches_returns_empty(self, resolver, sample_data) -> None:
        matches = resolver.find_matches("$.nonexistent.path", sample_data)
        assert matches == []

    def test_null_value_matched(self, resolver) -> None:
        data = {"device": {"hostname": None}}
        matches = resolver.find_matches("$.device.hostname", data)
        assert len(matches) == 1
        assert matches[0].value is None

    def test_empty_array(self, resolver) -> None:
        data = {"devices": []}
        matches = resolver.find_matches("$.devices[*].hostname", data)
        assert matches == []


@pytest.mark.unit
class TestUpdateValue:
    def test_update_simple_value(self, resolver, sample_data) -> None:
        matches = resolver.find_matches("$.devices[0].hostname", sample_data)
        resolver.update_value(matches[0], sample_data, "DEVICE-001")
        assert sample_data["devices"][0]["hostname"] == "DEVICE-001"

    def test_update_preserves_structure(self, resolver, sample_data) -> None:
        matches = resolver.find_matches("$.devices[0].mgmt_ip", sample_data)
        resolver.update_value(matches[0], sample_data, "192.0.2.1")
        assert sample_data["devices"][0]["mgmt_ip"] == "192.0.2.1"
        assert sample_data["devices"][0]["hostname"] == "core-rtr-01"
        assert sample_data["devices"][1]["mgmt_ip"] == "10.50.1.2"

    def test_update_nested_value(self, resolver, sample_data) -> None:
        matches = resolver.find_matches(
            "$.devices[*].config.snmp.community", sample_data
        )
        for i, match in enumerate(matches):
            resolver.update_value(match, sample_data, f"REDACTED-SNMP-{i:03d}")
        assert (
            sample_data["devices"][0]["config"]["snmp"]["community"]
            == "REDACTED-SNMP-000"
        )
        assert (
            sample_data["devices"][1]["config"]["snmp"]["community"]
            == "REDACTED-SNMP-001"
        )

    def test_update_all_with_recursive_descent(self, resolver, sample_data) -> None:
        matches = resolver.find_matches("$..password", sample_data)
        for match in matches:
            resolver.update_value(match, sample_data, "***REDACTED***")
        assert (
            sample_data["devices"][0]["config"]["aaa"]["password"] == "***REDACTED***"
        )
        assert (
            sample_data["devices"][1]["config"]["aaa"]["password"] == "***REDACTED***"
        )
