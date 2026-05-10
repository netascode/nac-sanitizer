"""Verify package metadata."""

import pytest

from nac_sanitizer import __version__


@pytest.mark.unit
def test_version_is_set() -> None:
    assert __version__ == "0.1.0"
