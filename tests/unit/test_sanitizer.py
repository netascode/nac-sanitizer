"""Tests for the orchestration layer."""

import json

import pytest

from nac_sanitizer.config.models import RedactionRule, SanitizerConfig
from nac_sanitizer.sanitizer import Sanitizer


@pytest.fixture
def basic_config() -> SanitizerConfig:
    return SanitizerConfig(
        custom_rules=[
            RedactionRule(path="$..password", strategy="token", category="CREDENTIAL"),
            RedactionRule(path="$..mgmt_ip", strategy="ip_map", category="IP"),
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

        config = SanitizerConfig(
            custom_rules=[RedactionRule(path="$..ip", strategy="ip_map", category="IP")]
        )
        sanitizer = Sanitizer(config)
        output_dir = tmp_path / "output"
        sanitizer.run(input_file, output_dir)

        sanitized = json.loads((output_dir / "consistent.json").read_text())
        assert sanitized["primary"]["ip"] == sanitized["secondary"]["ip"]


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

        config = SanitizerConfig(
            custom_rules=[RedactionRule(path="$..ip", strategy="ip_map", category="IP")]
        )
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
        assert "IP" in summary["by_category"]
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
