# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Verify package metadata."""

import pytest

from nac_sanitizer import __version__


@pytest.mark.unit
def test_version_is_set() -> None:
    assert __version__ == "0.1.0"
