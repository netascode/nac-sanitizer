"""Tests for the Rosetta Stone writer."""

import json
import os
import stat

import pytest

from nac_sanitizer.rosetta.writer import RosettaWriter


@pytest.fixture
def writer() -> RosettaWriter:
    return RosettaWriter(tool_version="0.1.0")


@pytest.mark.unit
class TestRecordMappings:
    def test_record_single_mapping(self, writer) -> None:
        writer.record("secret123", "REDACTED-001", "credentials")
        assert writer.mapping_count == 1

    def test_record_multiple_same_category(self, writer) -> None:
        writer.record("secret1", "REDACTED-001", "credentials")
        writer.record("secret2", "REDACTED-002", "credentials")
        assert writer.mapping_count == 2

    def test_record_multiple_categories(self, writer) -> None:
        writer.record("secret1", "REDACTED-001", "credentials")
        writer.record("10.1.1.1", "192.0.2.1", "ip_addresses")
        assert writer.mapping_count == 2
        assert set(writer.categories) == {"credentials", "ip_addresses"}

    def test_record_none_category_uses_general(self, writer) -> None:
        writer.record("value", "REDACTED-001", None)
        assert "general" in writer.categories

    def test_overwrite_same_original(self, writer) -> None:
        writer.record("secret", "FIRST", "cred")
        writer.record("secret", "SECOND", "cred")
        assert writer.mapping_count == 1
        data = writer.to_dict()
        assert data["mappings"]["cred"]["secret"] == "SECOND"


@pytest.mark.unit
class TestSourceFiles:
    def test_add_source_file(self, writer) -> None:
        writer.add_source_file("input/sdwan.json")
        assert writer.source_files == ["input/sdwan.json"]

    def test_multiple_source_files(self, writer) -> None:
        writer.add_source_file("file1.json")
        writer.add_source_file("file2.json")
        assert len(writer.source_files) == 2


@pytest.mark.unit
class TestGenerateFilename:
    def test_filename_has_prefix(self, writer) -> None:
        filename = writer.generate_filename()
        assert filename.startswith("nac-sanitizer-rosetta-")

    def test_filename_has_json_extension(self, writer) -> None:
        filename = writer.generate_filename()
        assert filename.endswith(".json")

    def test_filename_contains_timestamp(self, writer) -> None:
        filename = writer.generate_filename()
        # Should contain date-like pattern
        assert "202" in filename
        assert "T" in filename


@pytest.mark.unit
class TestToDict:
    def test_structure(self, writer) -> None:
        writer.add_source_file("test.json")
        writer.record("secret", "REDACTED-001", "credentials")
        data = writer.to_dict()

        assert "metadata" in data
        assert "mappings" in data
        assert data["metadata"]["tool_version"] == "0.1.0"
        assert data["metadata"]["source_files"] == ["test.json"]
        assert data["metadata"]["total_mappings"] == 1
        assert "created" in data["metadata"]

    def test_empty_writer(self, writer) -> None:
        data = writer.to_dict()
        assert data["mappings"] == {}
        assert data["metadata"]["total_mappings"] == 0
        assert data["metadata"]["source_files"] == []


@pytest.mark.unit
class TestWrite:
    def test_write_creates_file(self, writer, tmp_path) -> None:
        writer.record("secret", "REDACTED-001", "credentials")
        output = writer.write(tmp_path)
        assert output.exists()

    def test_write_uses_generated_filename(self, writer, tmp_path) -> None:
        output = writer.write(tmp_path)
        assert output.name.startswith("nac-sanitizer-rosetta-")

    def test_write_custom_filename(self, writer, tmp_path) -> None:
        output = writer.write(tmp_path, filename="custom.json")
        assert output.name == "custom.json"

    def test_write_valid_json(self, writer, tmp_path) -> None:
        writer.record("10.1.1.1", "192.0.2.1", "ip_addresses")
        output = writer.write(tmp_path)
        data = json.loads(output.read_text())
        assert data["mappings"]["ip_addresses"]["10.1.1.1"] == "192.0.2.1"

    def test_write_restrictive_permissions(self, writer, tmp_path) -> None:
        output = writer.write(tmp_path)
        file_stat = os.stat(output)
        mode = stat.S_IMODE(file_stat.st_mode)
        assert mode == 0o600

    def test_write_returns_path(self, writer, tmp_path) -> None:
        output = writer.write(tmp_path)
        assert output.parent == tmp_path

    def test_write_with_multiple_categories(self, writer, tmp_path) -> None:
        writer.record("secret1", "CRED-001", "credentials")
        writer.record("10.1.1.1", "192.0.2.1", "ip_addresses")
        writer.record("core-rtr", "DEVICE-001", "hostnames")
        output = writer.write(tmp_path)
        data = json.loads(output.read_text())
        assert len(data["mappings"]) == 3
