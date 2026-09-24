# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Tests for the orchestration layer."""

import json
from pathlib import Path
from typing import Any

import pytest

from nac_sanitizer.config.models import PackConfig, RedactionRule, SanitizerConfig
from nac_sanitizer.sanitizer import Sanitizer

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def basic_config() -> SanitizerConfig:
    return SanitizerConfig(
        custom_rules=[
            RedactionRule(path="$..password", strategy="token", category="CREDENTIAL"),
            RedactionRule(path="$..hostname", strategy="hostname_map", category="HOST"),
        ]
    )


@pytest.fixture
def sample_input(tmp_path) -> dict:
    data = {
        "devices": [
            {
                "hostname": "core-rtr-01",
                "mgmt_ip": "10.50.1.1",
                "config": {"password": "secret123"},
            },
            {
                "hostname": "dist-sw-01",
                "mgmt_ip": "10.50.1.2",
                "config": {"password": "other456"},
            },
        ]
    }
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(data))
    return {"path": input_file, "data": data}


@pytest.mark.unit
class TestSingleFileSanitization:
    def test_produces_sanitized_output(
        self, basic_config, sample_input, tmp_path
    ) -> None:
        sanitizer = Sanitizer(basic_config)
        output_dir = tmp_path / "output"
        sanitizer.run(sample_input["path"], output_dir)

        output_file = output_dir / "input.json"
        assert output_file.exists()

        sanitized = json.loads(output_file.read_text())
        raw = json.dumps(sanitized)
        assert "secret123" not in raw
        assert "other456" not in raw
        assert "10.50.1.1" not in raw
        assert "core-rtr-01" not in raw

    def test_produces_rosetta_stone(self, basic_config, sample_input, tmp_path) -> None:
        sanitizer = Sanitizer(basic_config)
        output_dir = tmp_path / "output"
        rosetta_path = sanitizer.run(sample_input["path"], output_dir)

        assert rosetta_path.exists()
        assert rosetta_path.name.startswith("nac-sanitizer-rosetta-")

        rosetta = json.loads(rosetta_path.read_text())
        assert "metadata" in rosetta
        assert "mappings" in rosetta
        assert rosetta["metadata"]["total_mappings"] > 0

    def test_preserves_json_structure(
        self, basic_config, sample_input, tmp_path
    ) -> None:
        sanitizer = Sanitizer(basic_config)
        output_dir = tmp_path / "output"
        sanitizer.run(sample_input["path"], output_dir)

        output_file = output_dir / "input.json"
        sanitized = json.loads(output_file.read_text())

        assert "devices" in sanitized
        assert len(sanitized["devices"]) == 2
        assert "hostname" in sanitized["devices"][0]
        assert "mgmt_ip" in sanitized["devices"][0]
        assert "config" in sanitized["devices"][0]
        assert "password" in sanitized["devices"][0]["config"]

    def test_consistency_within_run(self, basic_config, sample_input, tmp_path) -> None:
        """Same value appearing multiple times gets same sanitized value."""
        data = {
            "primary": {"ip": "10.1.1.1"},
            "secondary": {"ip": "10.1.1.1"},
        }
        input_file = tmp_path / "consistent.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(custom_rules=[])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "consistent.json").read_text())
        assert sanitized["primary"]["ip"] == sanitized["secondary"]["ip"]


@pytest.mark.unit
class TestArrayOfStringRedaction:
    """$..field simple-descent rules must redact array-of-string values (#179)."""

    def test_simple_descent_redacts_array_of_strings(self, tmp_path) -> None:
        data = {
            "profiles": [
                {
                    "siteNames": ["Global/US/Site1", "Global/EU/Site2"],
                    "id": "prof-001",
                }
            ]
        }
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            custom_rules=[
                RedactionRule(path="$..siteNames", strategy="token", category="SITES"),
            ]
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "input.json").read_text())
        assert sanitized["profiles"][0]["siteNames"] == [
            "SITES-001",
            "SITES-002",
        ]
        assert sanitized["profiles"][0]["id"] == "prof-001"

    def test_simple_descent_handles_mixed_array(self, tmp_path) -> None:
        """Array containing strings, nested dicts with matching keys, and empty strings."""
        data = {
            "items": [
                {
                    "tags": [
                        "sensitive-tag",
                        "",
                        {"nested": True, "tags": "inner-tag"},
                    ]
                }
            ]
        }
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            custom_rules=[
                RedactionRule(path="$..tags", strategy="token", category="TAGS"),
            ]
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "input.json").read_text())
        tags = sanitized["items"][0]["tags"]
        assert tags[0] == "TAGS-001"
        assert tags[1] == ""
        assert tags[2]["nested"] is True
        assert tags[2]["tags"] == "TAGS-002"

    def test_simple_descent_scalar_still_works(self, tmp_path) -> None:
        """Scalar string values continue to be redacted (no regression)."""
        data = {"device": {"siteNameHierarchy": "Global/US/NYC"}}
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps(data))

        config = SanitizerConfig(
            custom_rules=[
                RedactionRule(
                    path="$..siteNameHierarchy",
                    strategy="token",
                    category="LOC",
                ),
            ]
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "input.json").read_text())
        assert sanitized["device"]["siteNameHierarchy"] == "LOC-001"


@pytest.mark.unit
class TestDirectorySanitization:
    def test_processes_all_json_files(self, basic_config, tmp_path) -> None:
        input_dir = tmp_path / "input"
        input_dir.mkdir()

        for name in ["file1.json", "file2.json", "file3.json"]:
            (input_dir / name).write_text(
                json.dumps(
                    {
                        "device": {
                            "hostname": f"host-{name}",
                            "config": {"password": "pw"},
                        }
                    }
                )
            )

        sanitizer = Sanitizer(basic_config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_dir, output_dir)

        assert (output_dir / "file1.json").exists()
        assert (output_dir / "file2.json").exists()
        assert (output_dir / "file3.json").exists()

    def test_cross_file_consistency(self, tmp_path) -> None:
        """Same value in different files maps to same sanitized value."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()

        (input_dir / "a.json").write_text(json.dumps({"device": {"ip": "10.1.1.1"}}))
        (input_dir / "b.json").write_text(json.dumps({"device": {"ip": "10.1.1.1"}}))

        config = SanitizerConfig(custom_rules=[])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_dir, output_dir)

        a = json.loads((output_dir / "a.json").read_text())
        b = json.loads((output_dir / "b.json").read_text())
        assert a["device"]["ip"] == b["device"]["ip"]

    def test_preserves_subdirectory_structure(self, basic_config, tmp_path) -> None:
        input_dir = tmp_path / "input"
        (input_dir / "subdir").mkdir(parents=True)

        (input_dir / "top.json").write_text(
            json.dumps({"device": {"hostname": "h1", "config": {"password": "pw"}}})
        )
        (input_dir / "subdir" / "nested.json").write_text(
            json.dumps({"device": {"hostname": "h2", "config": {"password": "pw"}}})
        )

        sanitizer = Sanitizer(basic_config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_dir, output_dir)

        assert (output_dir / "top.json").exists()
        assert (output_dir / "subdir" / "nested.json").exists()

    def test_ignores_non_json_files(self, basic_config, tmp_path) -> None:
        input_dir = tmp_path / "input"
        input_dir.mkdir()

        (input_dir / "data.json").write_text(
            json.dumps({"device": {"hostname": "h1", "config": {"password": "pw"}}})
        )
        (input_dir / "readme.txt").write_text("not json")

        sanitizer = Sanitizer(basic_config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_dir, output_dir)

        assert (output_dir / "data.json").exists()
        assert not (output_dir / "readme.txt").exists()


@pytest.mark.unit
class TestDryRun:
    def test_dry_run_returns_summary(
        self, basic_config, sample_input, tmp_path
    ) -> None:
        sanitizer = Sanitizer(basic_config)
        summary = sanitizer.run_dry(sample_input["path"])

        assert summary["files_scanned"] == 1
        assert summary["total_matches"] > 0
        assert "CREDENTIAL" in summary["by_category"]
        assert "IP_ADDRESSES" in summary["by_category"]
        assert "HOST" in summary["by_category"]

    def test_dry_run_writes_no_files(
        self, basic_config, sample_input, tmp_path
    ) -> None:
        sanitizer = Sanitizer(basic_config)
        sanitizer.run_dry(sample_input["path"])

        output_dir = tmp_path / "output"
        assert not output_dir.exists()


@pytest.mark.unit
class TestOverrides:
    def test_skip_override_excludes_path(self, sample_input, tmp_path) -> None:
        from nac_sanitizer.config.models import OverrideRule

        config = SanitizerConfig(
            custom_rules=[
                RedactionRule(path="$..password", strategy="token", category="CRED"),
                RedactionRule(
                    path="$..hostname", strategy="hostname_map", category="HOST"
                ),
            ],
            overrides=[OverrideRule(path="$..hostname", tier="skip")],
        )

        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(sample_input["path"], output_dir)

        sanitized = json.loads((output_dir / "input.json").read_text())
        # Hostname should NOT be redacted (skipped)
        assert sanitized["devices"][0]["hostname"] == "core-rtr-01"
        # Password should still be redacted
        assert sanitized["devices"][0]["config"]["password"] != "secret123"


@pytest.mark.unit
class TestMalformedJson:
    def test_malformed_file_skipped_in_run(self, basic_config, tmp_path) -> None:
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "good.json").write_text(json.dumps({"password": "secret"}))
        (input_dir / "bad.json").write_text("{not valid json")

        sanitizer = Sanitizer(basic_config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_dir, output_dir)

        assert (output_dir / "good.json").exists()
        assert not (output_dir / "bad.json").exists()

    def test_malformed_file_skipped_in_dry_run(self, basic_config, tmp_path) -> None:
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "good.json").write_text(json.dumps({"password": "secret"}))
        (input_dir / "bad.json").write_text("{not valid json")

        sanitizer = Sanitizer(basic_config)
        summary = sanitizer.run_dry(input_dir)

        assert summary["total_matches"] > 0


@pytest.mark.unit
class TestStringifiedJsonUnwrapping:
    """Tests for unwrapping/re-wrapping JSON-encoded string values (issue #170)."""

    def test_ips_inside_stringified_json_are_replaced(self, tmp_path) -> None:
        """Bare IPs embedded in a stringified JSON blob get sanitized."""
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(
            (FIXTURES_DIR / "sdwan_stringified_json.json").read_text(encoding="utf-8")
        )

        config = SanitizerConfig(profiles=["sdwan"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        raw = json.dumps(sanitized)
        assert "10.50.1.1" not in raw

    def test_hostnames_inside_stringified_json_are_redacted(self, tmp_path) -> None:
        """Non-IP sensitive fields (hostnames) inside the blob get redacted
        when a profile rule matches, since unwrapping makes them traversable."""
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(
            (FIXTURES_DIR / "sdwan_stringified_json.json").read_text(encoding="utf-8")
        )

        config = SanitizerConfig(
            profiles=["sdwan"],
            packs=PackConfig(enable=["hostnames"]),
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        raw = json.dumps(sanitized)
        assert "test-router-01" not in raw

    def test_rewrapped_value_is_valid_json_matching_compact_format(
        self, tmp_path
    ) -> None:
        """The re-wrapped string is still valid JSON, compact (no whitespace),
        and its structure still matches the original."""
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(
            (FIXTURES_DIR / "sdwan_stringified_json.json").read_text(encoding="utf-8")
        )

        config = SanitizerConfig(profiles=["sdwan"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        variables_str = sanitized["feature_device_template"][0]["data"][
            "deviceTemplateVariables"
        ]
        assert isinstance(variables_str, str)

        # Must still be valid JSON.
        parsed = json.loads(variables_str)
        assert isinstance(parsed, dict)
        assert "device" in parsed
        assert isinstance(parsed["device"], list)
        assert parsed["templateId"] == "tmpl-001"
        assert parsed["isEdited"] is True

        # Must be compact (no spaces after separators), matching vManage's
        # original json.dumps(..., separators=(",", ":")) style formatting.
        assert " " not in variables_str

    def test_non_json_strings_are_left_untouched(self, tmp_path) -> None:
        """A plain string value should never be parsed/unwrapped."""
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(
            (FIXTURES_DIR / "sdwan_stringified_json.json").read_text(encoding="utf-8")
        )

        config = SanitizerConfig(profiles=["sdwan"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        assert sanitized["device"][0]["data"]["normal_field"] == "this is not JSON"

    def test_normal_non_stringified_json_still_works(self, tmp_path) -> None:
        """Ordinary (non-stringified) fields elsewhere in the same document
        continue to be sanitized normally alongside the unwrap logic."""
        input_file = tmp_path / "sdwan.json"
        input_file.write_text(
            (FIXTURES_DIR / "sdwan_stringified_json.json").read_text(encoding="utf-8")
        )

        config = SanitizerConfig(profiles=["sdwan"])
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "sdwan.json").read_text())
        raw = json.dumps(sanitized)
        # The top-level device[*].data["system-ip"] IP should also be redacted.
        assert "10.50.1.1" not in raw
        # host-name field on the top-level device entry (not inside the
        # stringified blob) should also have been sanitized when the
        # hostnames pack is disabled by default it stays, but confirm the
        # structure survived intact.
        assert sanitized["device"][0]["data"]["device-type"] == "vedge"
        assert sanitized["device"][0]["data"]["reachability"] == "reachable"


@pytest.mark.unit
class TestUnwrapJsonStringsUnit:
    """Direct unit tests for Sanitizer._unwrap_json_strings/_rewrap_json_strings."""

    def _sanitizer(self) -> Sanitizer:
        return Sanitizer(SanitizerConfig(custom_rules=[]))

    def test_unwraps_dict_stringified_json(self) -> None:
        sanitizer = self._sanitizer()
        data = {"blob": '{"a": 1, "b": "x"}'}
        unwrapped = sanitizer._unwrap_json_strings(data)

        assert isinstance(data["blob"], dict)
        assert data["blob"] == {"a": 1, "b": "x"}
        assert len(unwrapped) == 1

    def test_unwraps_list_stringified_json(self) -> None:
        sanitizer = self._sanitizer()
        data = {"blob": "[1, 2, 3]"}
        unwrapped = sanitizer._unwrap_json_strings(data)

        assert data["blob"] == [1, 2, 3]
        assert len(unwrapped) == 1

    def test_does_not_unwrap_plain_string(self) -> None:
        sanitizer = self._sanitizer()
        data = {"note": "just a normal string"}
        unwrapped = sanitizer._unwrap_json_strings(data)

        assert data["note"] == "just a normal string"
        assert unwrapped == []

    def test_does_not_unwrap_json_primitives(self) -> None:
        """Strings that are valid JSON but decode to a primitive (bool, int,
        str, None) must not be unwrapped - only dict/list containers count."""
        sanitizer = self._sanitizer()
        data = {
            "bool_str": "true",
            "int_str": "123",
            "float_str": "1.5",
            "null_str": "null",
            "quoted_str": '"hello"',
        }
        unwrapped = sanitizer._unwrap_json_strings(data)

        assert data["bool_str"] == "true"
        assert data["int_str"] == "123"
        assert data["float_str"] == "1.5"
        assert data["null_str"] == "null"
        assert data["quoted_str"] == '"hello"'
        assert unwrapped == []

    def test_does_not_unwrap_malformed_json_looking_string(self) -> None:
        sanitizer = self._sanitizer()
        data = {"blob": "{not valid json"}
        unwrapped = sanitizer._unwrap_json_strings(data)

        assert data["blob"] == "{not valid json"
        assert unwrapped == []

    def test_rewrap_restores_compact_json_string(self) -> None:
        sanitizer = self._sanitizer()
        original = '{"a":1,"b":[1,2,3]}'
        data = {"blob": original}
        unwrapped = sanitizer._unwrap_json_strings(data)
        assert isinstance(data["blob"], dict)

        sanitizer._rewrap_json_strings(unwrapped)

        assert data["blob"] == original

    def test_rewrap_reflects_mutations_made_while_unwrapped(self) -> None:
        """If the unwrapped structure is mutated (as the sanitization
        pipeline would do), the re-wrapped string reflects those changes."""
        sanitizer = self._sanitizer()
        data: dict[str, Any] = {"blob": '{"host_name":"secret-host","other":"kept"}'}
        unwrapped = sanitizer._unwrap_json_strings(data)

        # Simulate a redaction rule mutating the unwrapped dict in-place.
        blob = data["blob"]
        assert isinstance(blob, dict)
        blob["host_name"] = "REDACTED-001"

        sanitizer._rewrap_json_strings(unwrapped)

        assert data["blob"] == '{"host_name":"REDACTED-001","other":"kept"}'
        # Round-trips back to valid JSON with the mutation intact.
        assert json.loads(data["blob"]) == {
            "host_name": "REDACTED-001",
            "other": "kept",
        }

    def test_nested_stringified_json_unwrapped_recursively(self) -> None:
        """A dict/list value nested inside a stringified JSON blob (which
        itself may contain further stringified JSON) is also unwrapped."""
        sanitizer = self._sanitizer()
        inner = '{"deep":"value"}'
        outer = json.dumps({"nested_blob": inner}, separators=(",", ":"))
        data = {"blob": outer}

        unwrapped = sanitizer._unwrap_json_strings(data)

        assert isinstance(data["blob"], dict)
        assert isinstance(data["blob"]["nested_blob"], dict)
        assert data["blob"]["nested_blob"] == {"deep": "value"}
        assert len(unwrapped) == 2

        sanitizer._rewrap_json_strings(unwrapped)
        assert data["blob"] == outer
        assert json.loads(data["blob"]) == {"nested_blob": inner}
