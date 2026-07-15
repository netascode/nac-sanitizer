# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Zip file handling for nac-sanitizer."""

import shutil
import tempfile
import zipfile
from pathlib import Path


def is_zip_file(path: Path) -> bool:
    """Check if a path points to a zip file based on suffix."""
    return path.is_file() and path.suffix.lower() == ".zip"


def extract_zip(zip_path: Path) -> Path:
    """Extract a zip file to a temporary directory.

    Returns the path to the temporary directory containing extracted files.
    Caller is responsible for cleanup (e.g. shutil.rmtree).
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="nac-sanitizer-"))
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(tmp_dir)
    return tmp_dir


def create_zip(
    source_dir: Path, output_zip: Path, exclude_patterns: list[str] | None = None
) -> Path:
    """Create a zip file from the contents of a directory.

    Args:
        source_dir: Directory whose contents will be zipped.
        output_zip: Path for the output zip file.
        exclude_patterns: Optional list of glob patterns to exclude.

    Returns the path to the created zip file.
    """
    exclude = set(exclude_patterns or [])

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(source_dir.rglob("*")):
            if file_path.is_file():
                relative = file_path.relative_to(source_dir)
                if any(relative.match(pat) for pat in exclude):
                    continue
                zf.write(file_path, relative)
    return output_zip


def cleanup_temp_dir(tmp_dir: Path) -> None:
    """Remove a temporary directory created by extract_zip."""
    shutil.rmtree(tmp_dir, ignore_errors=True)
