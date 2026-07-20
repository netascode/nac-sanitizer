# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""nac-sanitizer: Sanitize sensitive values in nac-collector JSON output."""

try:
    from nac_sanitizer._version import __version__
except ModuleNotFoundError:
    __version__ = "0.0.0.dev0"
