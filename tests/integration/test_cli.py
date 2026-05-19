"""Integration tests for the CLI layer."""

import json

import pytest
from typer.testing import CliRunner

from nac_sanitizer.cli.main import app

runner = CliRunner()


@pytest.fixture
def sample_input_file(tmp_path):
    data = {
        "devices": [
            {
                "hostname": "core-rtr-01",
                "mgmt_ip": "10.50.1.1",
                "config": {"password": "secret123"},
            }
        ]
    }
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(data))
    return input_file


@pytest.fixture
def sample_config(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
custom_rules:
  - path: "$..password"
    strategy: token
    category: "CREDENTIAL"
  - path: "$..hostname"
    strategy: hostname_map
    category: "HOST"
"""
    )
    return config_file


@pytest.mark.integration
class TestVersion:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "nac-sanitizer" in result.output
        assert "0.1.0" in result.output


@pytest.mark.integration
class TestSanitizeCommand:
    def test_basic_sanitize(self, sample_input_file, sample_config, tmp_path) -> None:
        output_dir = tmp_path / "output"
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(sample_input_file),
                "-o",
                str(output_dir),
                "-c",
                str(sample_config),
            ],
        )
        assert result.exit_code == 0
        assert "Sanitization complete" in result.output

        output_file = output_dir / "input.json"
        assert output_file.exists()

        sanitized = json.loads(output_file.read_text())
        raw = json.dumps(sanitized)
        assert "secret123" not in raw
        assert "10.50.1.1" not in raw
        assert "core-rtr-01" not in raw

    def test_rosetta_stone_created(
        self, sample_input_file, sample_config, tmp_path
    ) -> None:
        output_dir = tmp_path / "output"
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(sample_input_file),
                "-o",
                str(output_dir),
                "-c",
                str(sample_config),
            ],
        )
        assert result.exit_code == 0

        rosetta_files = list(output_dir.glob("nac-sanitizer-rosetta-*.json"))
        assert len(rosetta_files) == 1

        rosetta = json.loads(rosetta_files[0].read_text())
        assert "metadata" in rosetta
        assert "mappings" in rosetta

    def test_dry_run(self, sample_input_file, sample_config, tmp_path) -> None:
        output_dir = tmp_path / "output"
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(sample_input_file),
                "-o",
                str(output_dir),
                "-c",
                str(sample_config),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        assert "Dry run summary" in result.output
        assert "Files scanned: 1" in result.output
        assert not output_dir.exists()

    def test_missing_input_file(self, tmp_path) -> None:
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(tmp_path / "nonexistent.json"),
                "-o",
                str(tmp_path / "output"),
            ],
        )
        assert result.exit_code != 0

    def test_invalid_config(self, sample_input_file, tmp_path) -> None:
        bad_config = tmp_path / "bad.yaml"
        bad_config.write_text("  :\n  - [invalid\n")
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(sample_input_file),
                "-o",
                str(tmp_path / "output"),
                "-c",
                str(bad_config),
            ],
        )
        assert result.exit_code == 1
        assert "Configuration error" in result.output

    def test_directory_input(self, sample_config, tmp_path) -> None:
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "file1.json").write_text(
            json.dumps({"device": {"hostname": "h1", "config": {"password": "pw"}}})
        )
        (input_dir / "file2.json").write_text(
            json.dumps({"device": {"hostname": "h2", "config": {"password": "pw"}}})
        )

        output_dir = tmp_path / "output"
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(input_dir),
                "-o",
                str(output_dir),
                "-c",
                str(sample_config),
            ],
        )
        assert result.exit_code == 0
        assert (output_dir / "file1.json").exists()
        assert (output_dir / "file2.json").exists()


@pytest.mark.integration
class TestValidateConfigCommand:
    def test_valid_config(self, sample_config) -> None:
        result = runner.invoke(app, ["validate-config", str(sample_config)])
        assert result.exit_code == 0
        assert "Configuration is valid" in result.output

    def test_invalid_config(self, tmp_path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("overrides:\n  - path: '$.x'\n")
        result = runner.invoke(app, ["validate-config", str(bad)])
        assert result.exit_code == 1
        assert "Invalid configuration" in result.output

    def test_empty_config(self, tmp_path) -> None:
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        result = runner.invoke(app, ["validate-config", str(empty)])
        assert result.exit_code == 0


@pytest.mark.integration
class TestProfilesListCommand:
    def test_no_profiles_available(self) -> None:
        result = runner.invoke(app, ["profiles", "list"])
        # May show "No profiles available" or list profiles depending on state
        assert result.exit_code == 0
