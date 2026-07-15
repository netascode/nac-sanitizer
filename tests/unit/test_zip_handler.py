# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Unit tests for zip_handler module."""

import json
import zipfile

import pytest

from nac_sanitizer.zip_handler import (
    cleanup_temp_dir,
    create_zip,
    extract_zip,
    is_zip_file,
)


@pytest.mark.unit
class TestIsZipFile:
    def test_zip_suffix(self, tmp_path) -> None:
        zip_file = tmp_path / "test.zip"
        zip_file.write_bytes(b"")
        assert is_zip_file(zip_file) is True

    def test_uppercase_zip_suffix(self, tmp_path) -> None:
        zip_file = tmp_path / "test.ZIP"
        zip_file.write_bytes(b"")
        assert is_zip_file(zip_file) is True

    def test_json_suffix(self, tmp_path) -> None:
        json_file = tmp_path / "test.json"
        json_file.write_text("{}")
        assert is_zip_file(json_file) is False

    def test_directory(self, tmp_path) -> None:
        assert is_zip_file(tmp_path) is False

    def test_nonexistent_path(self, tmp_path) -> None:
        assert is_zip_file(tmp_path / "missing.zip") is False


@pytest.mark.unit
class TestExtractZip:
    def test_extract_single_file(self, tmp_path) -> None:
        zip_path = tmp_path / "input.zip"
        data = {"hostname": "router-01"}
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("device.json", json.dumps(data))

        extracted = extract_zip(zip_path)
        try:
            assert (extracted / "device.json").exists()
            loaded = json.loads((extracted / "device.json").read_text())
            assert loaded == data
        finally:
            cleanup_temp_dir(extracted)

    def test_extract_nested_structure(self, tmp_path) -> None:
        zip_path = tmp_path / "input.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("site-a/switch.json", json.dumps({"name": "sw1"}))
            zf.writestr("site-b/router.json", json.dumps({"name": "rtr1"}))

        extracted = extract_zip(zip_path)
        try:
            assert (extracted / "site-a" / "switch.json").exists()
            assert (extracted / "site-b" / "router.json").exists()
        finally:
            cleanup_temp_dir(extracted)

    def test_extract_multiple_files(self, tmp_path) -> None:
        zip_path = tmp_path / "input.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("a.json", json.dumps({"a": 1}))
            zf.writestr("b.json", json.dumps({"b": 2}))
            zf.writestr("c.json", json.dumps({"c": 3}))

        extracted = extract_zip(zip_path)
        try:
            json_files = sorted(extracted.glob("*.json"))
            assert len(json_files) == 3
        finally:
            cleanup_temp_dir(extracted)


@pytest.mark.unit
class TestCreateZip:
    def test_create_from_directory(self, tmp_path) -> None:
        source = tmp_path / "source"
        source.mkdir()
        (source / "file1.json").write_text(json.dumps({"x": 1}))
        (source / "file2.json").write_text(json.dumps({"y": 2}))

        output_zip = tmp_path / "output.zip"
        result = create_zip(source, output_zip)

        assert result == output_zip
        assert output_zip.exists()

        with zipfile.ZipFile(output_zip, "r") as zf:
            names = sorted(zf.namelist())
            assert names == ["file1.json", "file2.json"]

    def test_create_preserves_subdirs(self, tmp_path) -> None:
        source = tmp_path / "source"
        (source / "sub").mkdir(parents=True)
        (source / "top.json").write_text("{}")
        (source / "sub" / "nested.json").write_text("{}")

        output_zip = tmp_path / "output.zip"
        create_zip(source, output_zip)

        with zipfile.ZipFile(output_zip, "r") as zf:
            names = sorted(zf.namelist())
            assert "top.json" in names
            assert "sub/nested.json" in names

    def test_exclude_patterns(self, tmp_path) -> None:
        source = tmp_path / "source"
        source.mkdir()
        (source / "data.json").write_text("{}")
        (source / "rosetta.json").write_text("{}")

        output_zip = tmp_path / "output.zip"
        create_zip(source, output_zip, exclude_patterns=["rosetta.json"])

        with zipfile.ZipFile(output_zip, "r") as zf:
            names = zf.namelist()
            assert "data.json" in names
            assert "rosetta.json" not in names


@pytest.mark.unit
class TestCleanupTempDir:
    def test_cleanup_removes_directory(self, tmp_path) -> None:
        temp = tmp_path / "temp_extract"
        temp.mkdir()
        (temp / "file.json").write_text("{}")

        cleanup_temp_dir(temp)
        assert not temp.exists()

    def test_cleanup_nonexistent_is_safe(self, tmp_path) -> None:
        cleanup_temp_dir(tmp_path / "nonexistent")
