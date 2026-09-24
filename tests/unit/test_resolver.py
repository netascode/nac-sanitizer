# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

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


@pytest.mark.unit
class TestUpdateCoercedSliceMatches:
    """Regression tests for issue #137: ``[*]`` over a scalar coerces it to a list.

    jsonpath_ng's ``Slice`` wraps non-list values in a temporary one-element
    list, so writing into ``match.context.value`` never touched the document.
    """

    @staticmethod
    def _redact_all(resolver: PathResolver, path: str, data: object) -> int:
        matches = resolver.find_matches(path, data)
        for match in matches:
            resolver.update_value(match, data, "REDACTED")
        return len(matches)

    def test_scalar_under_dict_key(self, resolver) -> None:
        data = {"x": {"siteNames": "Global/A", "id": "keep"}}
        assert self._redact_all(resolver, "$..siteNames[*]", data) == 1
        assert data == {"x": {"siteNames": "REDACTED", "id": "keep"}}

    def test_scalar_under_list_element(self, resolver) -> None:
        data = {"profiles": [{"siteNames": "Global/A"}, {"siteNames": "Global/B"}]}
        assert self._redact_all(resolver, "$..siteNames[*]", data) == 2
        assert data == {
            "profiles": [{"siteNames": "REDACTED"}, {"siteNames": "REDACTED"}]
        }

    def test_scalar_list_element_via_double_slice(self, resolver) -> None:
        """Scalars sitting directly inside a real list, reached via ``[*][*]``."""
        data = {"a": ["x", ["y", "z"]]}
        assert self._redact_all(resolver, "$.a[*][*]", data) == 3
        assert data == {"a": ["REDACTED", ["REDACTED", "REDACTED"]]}

    def test_real_list_unchanged_behavior(self, resolver) -> None:
        inner = ["Global/A", "Global/B"]
        data = {"x": {"siteNames": inner}}
        assert self._redact_all(resolver, "$..siteNames[*]", data) == 2
        assert data == {"x": {"siteNames": ["REDACTED", "REDACTED"]}}
        # Elements are rewritten in place; the list object itself is preserved.
        assert data["x"]["siteNames"] is inner

    def test_single_dict_through_slice_unchanged(self, resolver) -> None:
        data = {"users": {"email": "solo@example.com", "name": "keep"}}
        assert self._redact_all(resolver, "$..users[*].email", data) == 1
        assert data == {"users": {"email": "REDACTED", "name": "keep"}}

    def test_nested_slice_chain_with_scalar_leaf(self, resolver) -> None:
        data = {
            "device_admin_authorization_rule": [
                {"data": {"commands": "PermitShow", "profile": "keep"}},
                {"data": {"commands": ["CmdA", "CmdB"]}},
            ]
        }
        path = "$..device_admin_authorization_rule[*].data.commands[*]"
        assert self._redact_all(resolver, path, data) == 3
        rules = data["device_admin_authorization_rule"]
        assert rules[0]["data"] == {"commands": "REDACTED", "profile": "keep"}
        assert rules[1]["data"] == {"commands": ["REDACTED", "REDACTED"]}

    def test_nested_slice_chain_over_single_dict_with_scalar_leaf(
        self, resolver
    ) -> None:
        """Both ``[*]`` selectors coerce: a lone dict, then a scalar leaf."""
        data = {"device_admin_authorization_rule": {"data": {"commands": "Cmd"}}}
        path = "$..device_admin_authorization_rule[*].data.commands[*]"
        assert self._redact_all(resolver, path, data) == 1
        assert data == {
            "device_admin_authorization_rule": {"data": {"commands": "REDACTED"}}
        }

    def test_consecutive_slices_over_single_scalar(self, resolver) -> None:
        """``[*][*]`` over a scalar nests two coerced wrappers."""
        data = {"a": {"b": "secret"}}
        assert self._redact_all(resolver, "$.a.b[*][*]", data) == 1
        assert data == {"a": {"b": "REDACTED"}}

    def test_filtered_parent_with_scalar_leaf(self, resolver) -> None:
        data = {"a": [{"n": "k", "v": "secret"}, {"n": "other", "v": "keep"}]}
        assert self._redact_all(resolver, "$.a[?(@.n=='k')].v[*]", data) == 1
        assert data == {"a": [{"n": "k", "v": "REDACTED"}, {"n": "other", "v": "keep"}]}

    def test_scalar_at_explicit_index_through_slice(self, resolver) -> None:
        data = {"a": ["secret", "other"]}
        assert self._redact_all(resolver, "$.a[0][*]", data) == 1
        assert data == {"a": ["REDACTED", "other"]}

    def test_numeric_scalar_is_replaced(self, resolver) -> None:
        data = {"x": {"vlan": 42}}
        assert self._redact_all(resolver, "$..vlan[*]", data) == 1
        assert data == {"x": {"vlan": "REDACTED"}}

    def test_root_scalar_through_slice(self, resolver) -> None:
        """A coerced root has no real parent, so fall back to update_or_create."""
        data = {"k": "v"}
        matches = resolver.find_matches("$[*].k", data)
        assert len(matches) == 1
        resolver.update_value(matches[0], data, "REDACTED")
        assert data == {"k": "REDACTED"}
