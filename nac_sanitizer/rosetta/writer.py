# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Rosetta Stone writer for recording sanitization mappings."""

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from nac_sanitizer.constants import DEFAULT_ROSETTA_PERMISSIONS, ROSETTA_FILENAME_PREFIX


@dataclass
class RosettaWriter:
    """Accumulates original-to-sanitized mappings and writes the Rosetta Stone file."""

    tool_version: str
    source_files: list[str] = field(default_factory=list)
    _mappings: dict[str, dict[str, str]] = field(default_factory=dict, init=False)
    _created_at: datetime = field(init=False)

    def __post_init__(self) -> None:
        self._created_at = datetime.now(UTC)

    def record(self, original: str, sanitized: str, category: str | None) -> None:
        """Record a single original-to-sanitized mapping."""
        bucket = category or "general"
        if bucket not in self._mappings:
            self._mappings[bucket] = {}
        self._mappings[bucket][original] = sanitized

    def add_source_file(self, path: str) -> None:
        """Register an input file that was processed."""
        self.source_files.append(path)

    @property
    def mapping_count(self) -> int:
        """Total number of recorded mappings across all categories."""
        return sum(len(v) for v in self._mappings.values())

    @property
    def categories(self) -> list[str]:
        """List of categories with recorded mappings."""
        return list(self._mappings.keys())

    def generate_filename(self) -> str:
        """Generate a timestamped filename for the Rosetta Stone."""
        timestamp = self._created_at.strftime("%Y-%m-%dT%H-%M-%S")
        return f"{ROSETTA_FILENAME_PREFIX}-{timestamp}.json"

    def to_dict(self) -> dict:
        """Serialize the Rosetta Stone to a dictionary."""
        return {
            "metadata": {
                "created": self._created_at.isoformat(),
                "tool_version": self.tool_version,
                "source_files": self.source_files,
                "total_mappings": self.mapping_count,
            },
            "mappings": self._mappings,
        }

    def write(self, output_dir: Path, filename: str | None = None) -> Path:
        """Write the Rosetta Stone to a JSON file with restrictive permissions.

        Returns the path to the written file.
        """
        if filename is None:
            filename = self.generate_filename()

        output_path = output_dir / filename
        content = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        output_path.write_text(content)
        os.chmod(output_path, DEFAULT_ROSETTA_PERMISSIONS)
        return output_path
