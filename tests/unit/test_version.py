# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Verify package metadata."""

import re

import pytest

from nac_sanitizer import __version__


@pytest.mark.unit
def test_version_is_set() -> None:
    assert isinstance(__version__, str)
    assert len(__version__) > 0


@pytest.mark.unit
def test_version_format() -> None:
    assert re.match(r"\d+\.\d+", __version__)
