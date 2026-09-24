# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Contract tests pinning the jsonpath_ng semantics that profiles rely on.

The built-in profiles (``nac_sanitizer/resources/profiles/*.yaml``) contain
many ``[*]`` paths written against jsonpath_ng's behavior, which differs
from RFC 9535 on purpose (see the ``Slice`` docstring in
``jsonpath_ng.jsonpath``; refs #137):

* ``[*]`` on a list iterates its elements.
* ``[*]`` on a dict or scalar coerces it into a one-element list, so
  ``$.users[*].email`` matches whether ``users`` is a list of dicts or a
  single dict.
* ``.*`` on a list does not iterate its elements; ``.*`` on a dict yields
  its values.

These tests go through ``PathResolver`` so they exercise the same parser
(``ExtentedJsonPathParser``) used at runtime. If any of them fail after a
jsonpath-ng upgrade, redaction may silently stop matching data: review the
profile paths against the new semantics before accepting the upgrade.

Only ``find`` behavior is asserted here; write-back is covered elsewhere.
"""

import pytest

from nac_sanitizer.engine.resolver import PathResolver

SDWAN_HOST_NAME_FILTER_PATH = (
    '$.configuration_group_devices[*].data.variables[?(@.name == "host_name")].value'
)
SDWAN_CKT_ID_REGEX_FILTER_PATH = (
    '$.configuration_group_devices[*].data.variables[?(@.name =~ ".*_ckt_id$")].value'
)


@pytest.fixture
def resolver() -> PathResolver:
    return PathResolver()


@pytest.mark.unit
class TestBracketWildcardOnList:
    def test_bracket_wildcard_iterates_list_of_dicts(self, resolver) -> None:
        data = {"users": [{"email": "a@example.com"}, {"email": "b@example.com"}]}
        matches = resolver.find_matches("$.users[*].email", data)
        assert len(matches) == 2
        assert [m.value for m in matches] == ["a@example.com", "b@example.com"]

    def test_bracket_wildcard_yields_list_elements_themselves(self, resolver) -> None:
        data = {"users": [{"email": "a"}, {"email": "b"}, {"email": "c"}]}
        matches = resolver.find_matches("$.users[*]", data)
        assert len(matches) == 3
        assert [m.value for m in matches] == data["users"]

    def test_nested_bracket_wildcards_iterate_each_level(self, resolver) -> None:
        data = {
            "site": [
                {"data": [{"name": "s1-a"}, {"name": "s1-b"}]},
                {"data": [{"name": "s2-a"}]},
            ]
        }
        matches = resolver.find_matches("$.site[*].data[*].name", data)
        assert [m.value for m in matches] == ["s1-a", "s1-b", "s2-a"]


@pytest.mark.unit
class TestBracketWildcardCoercion:
    def test_bracket_wildcard_on_dict_yields_single_match(self, resolver) -> None:
        data = {"users": {"email": "solo@example.com"}}
        matches = resolver.find_matches("$.users[*]", data)
        assert len(matches) == 1
        assert matches[0].value == {"email": "solo@example.com"}

    def test_bracket_wildcard_field_reaches_into_single_dict(self, resolver) -> None:
        data = {"users": {"email": "solo@example.com"}}
        matches = resolver.find_matches("$.users[*].email", data)
        assert len(matches) == 1
        assert matches[0].value == "solo@example.com"

    def test_same_path_matches_list_and_dict_shapes(self, resolver) -> None:
        path = "$.users[*].email"
        as_list = {"users": [{"email": "x@example.com"}]}
        as_dict = {"users": {"email": "x@example.com"}}
        assert [m.value for m in resolver.find_matches(path, as_list)] == [
            "x@example.com"
        ]
        assert [m.value for m in resolver.find_matches(path, as_dict)] == [
            "x@example.com"
        ]

    def test_bracket_wildcard_on_scalar_yields_scalar(self, resolver) -> None:
        data = {"hostname": "core-rtr-01"}
        matches = resolver.find_matches("$.hostname[*]", data)
        assert len(matches) == 1
        assert matches[0].value == "core-rtr-01"


@pytest.mark.unit
class TestDotWildcard:
    def test_dot_wildcard_on_list_of_dicts_does_not_iterate(self, resolver) -> None:
        data = {"users": [{"email": "a@example.com"}, {"email": "b@example.com"}]}
        matches = resolver.find_matches("$.users.*.email", data)
        assert matches == []

    def test_dot_wildcard_on_dict_returns_values(self, resolver) -> None:
        data = {"config": {"a": 1, "b": "two", "c": [3]}}
        matches = resolver.find_matches("$.config.*", data)
        assert len(matches) == 3
        assert sorted(map(repr, (m.value for m in matches))) == sorted(
            map(repr, [1, "two", [3]])
        )


@pytest.mark.unit
class TestRecursiveDescentWithWildcard:
    def test_recursive_descent_bracket_wildcard_across_nesting(self, resolver) -> None:
        data = {
            "neighbors": [{"password": "top-1"}],
            "vrfs": [
                {
                    "name": "blue",
                    "neighbors": [{"password": "blue-1"}, {"password": "blue-2"}],
                },
                {"name": "red", "nested": {"neighbors": {"password": "red-1"}}},
            ],
        }
        matches = resolver.find_matches("$..neighbors[*].password", data)
        assert len(matches) == 4
        assert sorted(m.value for m in matches) == [
            "blue-1",
            "blue-2",
            "red-1",
            "top-1",
        ]


@pytest.mark.unit
class TestExtFilterExpressions:
    @pytest.fixture
    def sdwan_data(self) -> dict:
        return {
            "configuration_group_devices": [
                {
                    "data": {
                        "variables": [
                            {"name": "host_name", "value": "edge-01"},
                            {"name": "site_id", "value": "100"},
                            {"name": "wan1_ckt_id", "value": "CKT-A"},
                            {"name": "wan2_ckt_id", "value": "CKT-B"},
                        ]
                    }
                },
                {
                    "data": {
                        "variables": [
                            {"name": "host_name", "value": "edge-02"},
                            {"name": "ckt_id_note", "value": "not-matched"},
                        ]
                    }
                },
            ]
        }

    def test_equality_filter_from_sdwan_profile_matches(
        self, resolver, sdwan_data
    ) -> None:
        matches = resolver.find_matches(SDWAN_HOST_NAME_FILTER_PATH, sdwan_data)
        assert [m.value for m in matches] == ["edge-01", "edge-02"]

    def test_regex_filter_from_sdwan_profile_matches(
        self, resolver, sdwan_data
    ) -> None:
        matches = resolver.find_matches(SDWAN_CKT_ID_REGEX_FILTER_PATH, sdwan_data)
        assert [m.value for m in matches] == ["CKT-A", "CKT-B"]
