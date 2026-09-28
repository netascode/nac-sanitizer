# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Infer which product profile applies to nac-collector output."""

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from nac_sanitizer.profiles.registry import ProfileRegistry

logger = logging.getLogger(__name__)

# Fingerprint keys include generic words (e.g. "site", "host"), so one hit alone
# is not enough evidence. Real collector output carries every endpoint key.
MIN_KEY_MATCHES = 2


class ProfileDetectionError(Exception):
    """Raised when the input cannot be matched to exactly one profile."""


@dataclass(frozen=True)
class Fingerprint:
    """Signals that identify one profile's collector output."""

    profile: str
    filenames: frozenset[str]
    keys: frozenset[str]


@dataclass(frozen=True)
class Detection:
    """The profile detected for one input file, and why."""

    profile: str
    source: Path
    reason: str


def load_fingerprints() -> list[Fingerprint]:
    """Read the detect block from every bundled profile."""
    fingerprints = []
    for name in ProfileRegistry.available():
        detect = ProfileRegistry.load(name).get("detect") or {}
        fingerprints.append(
            Fingerprint(
                profile=name,
                filenames=frozenset(f.lower() for f in detect.get("filenames", [])),
                keys=frozenset(detect.get("keys", [])),
            )
        )
    return fingerprints


def detect_file(path: Path, data: object, fingerprints: list[Fingerprint]) -> Detection:
    """Identify the profile for one parsed input file."""
    by_name = [fp for fp in fingerprints if path.name.lower() in fp.filenames]
    if len(by_name) == 1:
        return Detection(by_name[0].profile, path, "by filename")

    if not isinstance(data, dict):
        raise ProfileDetectionError(
            f"Could not detect a profile for {path.name}: "
            "expected a JSON object at the top level."
        )

    top_level = set(data)
    scores = sorted(
        ((len(fp.keys & top_level), fp.profile) for fp in fingerprints),
        reverse=True,
    )
    candidates = [(score, name) for score, name in scores if score >= MIN_KEY_MATCHES]

    if not candidates:
        raise ProfileDetectionError(
            f"Could not detect a profile for {path.name}: its top-level keys "
            "do not match any known product."
        )
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        tied = ", ".join(
            sorted(name for score, name in candidates if score == candidates[0][0])
        )
        raise ProfileDetectionError(
            f"Could not detect a profile for {path.name}: it matches more than "
            f"one profile equally ({tied})."
        )

    score, name = candidates[0]
    return Detection(name, path, f"{score} matching keys")


def detect_profiles(input_files: list[Path]) -> list[Detection]:
    """Detect a profile for every parseable input file.

    Malformed JSON files are skipped here because the sanitizer skips them too.
    """
    fingerprints = load_fingerprints()
    detections = []
    for path in input_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        detection = detect_file(path, data, fingerprints)
        logger.debug(
            "Detected profile '%s' for %s (%s)",
            detection.profile,
            path,
            detection.reason,
        )
        detections.append(detection)

    if not detections:
        raise ProfileDetectionError("Could not detect a profile: no JSON input found.")
    return detections
