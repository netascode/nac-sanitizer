# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Tests for inferring the product profile from collector output."""

import json
from pathlib import Path

import pytest

from nac_sanitizer.profiles.detect import (
    Fingerprint,
    ProfileDetectionError,
    detect_file,
    detect_profiles,
    load_fingerprints,
)
from nac_sanitizer.profiles.registry import ProfileRegistry

COLLECTOR_FILENAMES = {
    "catalyst_center": "catalystcenter.json",
    "ise": "ise.json",
    "fmc": "fmc.json",
    "sdwan": "sdwan.json",
}


def _write(tmp_path: Path, name: str, data: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _keys_for(profile: str) -> dict:
    fp = next(f for f in load_fingerprints() if f.profile == profile)
    return {key: [] for key in sorted(fp.keys)}


@pytest.mark.unit
class TestFingerprints:
    def test_every_profile_has_a_fingerprint(self) -> None:
        profiles = {fp.profile for fp in load_fingerprints()}
        assert profiles == set(ProfileRegistry.available())

    def test_every_fingerprint_has_filenames_and_keys(self) -> None:
        for fp in load_fingerprints():
            assert fp.filenames, fp.profile
            assert len(fp.keys) >= 2, fp.profile

    def test_fingerprint_keys_do_not_overlap_between_profiles(self) -> None:
        fingerprints = load_fingerprints()
        for a in fingerprints:
            for b in fingerprints:
                if a.profile < b.profile:
                    assert not a.keys & b.keys, (a.profile, b.profile)

    def test_fingerprint_filenames_do_not_overlap_between_profiles(self) -> None:
        fingerprints = load_fingerprints()
        for a in fingerprints:
            for b in fingerprints:
                if a.profile < b.profile:
                    assert not a.filenames & b.filenames, (a.profile, b.profile)


@pytest.mark.unit
class TestDetectFile:
    @pytest.mark.parametrize(("profile", "filename"), COLLECTOR_FILENAMES.items())
    def test_detects_collector_filename(self, profile, filename) -> None:
        detection = detect_file(Path(filename), {}, load_fingerprints())
        assert detection.profile == profile
        assert detection.reason == "by filename"

    def test_detects_cdfmc_filename_as_fmc(self) -> None:
        assert detect_file(Path("cdfmc.json"), {}, load_fingerprints()).profile == "fmc"

    def test_filename_match_is_case_insensitive(self) -> None:
        detection = detect_file(Path("ISE.JSON"), {}, load_fingerprints())
        assert detection.profile == "ise"

    @pytest.mark.parametrize("profile", sorted(COLLECTOR_FILENAMES))
    def test_detects_from_top_level_keys(self, profile) -> None:
        detection = detect_file(
            Path("export.json"), _keys_for(profile), load_fingerprints()
        )
        assert detection.profile == profile
        assert detection.reason.endswith("matching keys")

    def test_filename_wins_over_keys(self) -> None:
        detection = detect_file(
            Path("ise.json"), _keys_for("sdwan"), load_fingerprints()
        )
        assert detection.profile == "ise"

    def test_single_key_match_is_not_enough(self) -> None:
        with pytest.raises(ProfileDetectionError, match="do not match"):
            detect_file(Path("export.json"), {"site": []}, load_fingerprints())

    def test_shared_endpoint_names_do_not_count(self) -> None:
        data = {"device": [], "network": []}
        with pytest.raises(ProfileDetectionError, match="do not match"):
            detect_file(Path("export.json"), data, load_fingerprints())

    def test_unknown_keys_raise(self) -> None:
        with pytest.raises(ProfileDetectionError, match="export.json"):
            detect_file(Path("export.json"), {"foo": 1, "bar": 2}, load_fingerprints())

    def test_tie_between_profiles_raises(self) -> None:
        fingerprints = [
            Fingerprint("alpha", frozenset(), frozenset({"a", "b"})),
            Fingerprint("beta", frozenset(), frozenset({"c", "d"})),
        ]
        data = {"a": 1, "b": 1, "c": 1, "d": 1}
        with pytest.raises(ProfileDetectionError, match="alpha, beta"):
            detect_file(Path("export.json"), data, fingerprints)

    def test_clear_leader_wins_over_weaker_match(self) -> None:
        fingerprints = [
            Fingerprint("alpha", frozenset(), frozenset({"a", "b", "c"})),
            Fingerprint("beta", frozenset(), frozenset({"d", "e"})),
        ]
        data = {"a": 1, "b": 1, "c": 1, "d": 1, "e": 1}
        assert detect_file(Path("x.json"), data, fingerprints).profile == "alpha"

    def test_non_object_json_raises(self) -> None:
        with pytest.raises(ProfileDetectionError, match="JSON object"):
            detect_file(Path("export.json"), [1, 2, 3], load_fingerprints())


@pytest.mark.unit
class TestDetectProfiles:
    def test_detects_each_file(self, tmp_path) -> None:
        files = [
            _write(tmp_path, "ise.json", {}),
            _write(tmp_path, "other.json", _keys_for("sdwan")),
        ]
        detections = detect_profiles(files)
        assert [d.profile for d in detections] == ["ise", "sdwan"]
        assert [d.source for d in detections] == files

    def test_skips_malformed_json(self, tmp_path) -> None:
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")
        good = _write(tmp_path, "ise.json", {})
        detections = detect_profiles([bad, good])
        assert [d.profile for d in detections] == ["ise"]

    def test_one_undetectable_file_fails_the_run(self, tmp_path) -> None:
        files = [
            _write(tmp_path, "ise.json", {}),
            _write(tmp_path, "mystery.json", {"foo": 1}),
        ]
        with pytest.raises(ProfileDetectionError, match="mystery.json"):
            detect_profiles(files)

    def test_no_parseable_files_raises(self, tmp_path) -> None:
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(ProfileDetectionError, match="no JSON input"):
            detect_profiles([bad])

    def test_empty_input_raises(self) -> None:
        with pytest.raises(ProfileDetectionError, match="no JSON input"):
            detect_profiles([])
