# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Value-pattern scanner that identifies and redacts IPs/prefixes across an entire JSON tree."""

import logging
import re
from typing import Any

from nac_sanitizer.engine.ip_allocator import IPAllocator

logger = logging.getLogger(__name__)

_IPV4_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?$")

_IPV6_PATTERN = re.compile(r"^([0-9a-fA-F:]{2,39})(/\d{1,3})?$")


def _is_ipv4(value: str) -> bool:
    """Check if a string looks like an IPv4 address or prefix."""
    match = _IPV4_PATTERN.match(value)
    if not match:
        return False
    octets = match.group(1).split(".")
    if not all(0 <= int(o) <= 255 for o in octets):
        return False
    prefix = match.group(2)
    if prefix and not (0 <= int(prefix[1:]) <= 32):
        return False
    return True


def _is_ipv6(value: str) -> bool:
    """Check if a string looks like an IPv6 address or prefix."""
    match = _IPV6_PATTERN.match(value)
    if not match:
        return False
    addr_part = match.group(1)
    if ":" not in addr_part:
        return False
    prefix = match.group(2)
    if prefix and not (0 <= int(prefix[1:]) <= 128):
        return False
    # Basic structural validation
    parts = addr_part.split(":")
    if len(parts) > 8:
        return False
    if "::" in addr_part:
        if addr_part.count("::") > 1:
            return False
    else:
        if len(parts) != 8:
            return False
    for part in parts:
        if part == "":
            continue
        if len(part) > 4:
            return False
        try:
            int(part, 16)
        except ValueError:
            return False
    return True


_EXCLUDED_VALUES = frozenset(
    {
        "0.0.0.0",
        "0.0.0.0/0",
        "255.255.255.255",
        "255.255.255.0",
        "255.255.0.0",
        "255.0.0.0",
        "::",
        "::0",
        "::/0",
    }
)


def is_ip_like(value: str) -> bool:
    """Determine if a string value looks like an IP address or prefix."""
    if value in _EXCLUDED_VALUES:
        return False
    return _is_ipv4(value) or _is_ipv6(value)


class IPScanner:
    """Walks a JSON tree and redacts all values matching IP/prefix patterns."""

    def __init__(self, allocator: IPAllocator) -> None:
        self._allocator = allocator
        self._mappings: dict[str, str] = {}

    @property
    def mappings(self) -> dict[str, str]:
        """All original-to-sanitized IP mappings recorded by the scanner."""
        return self._mappings

    def scan(self, data: Any) -> Any:
        """Walk the JSON tree and redact IP-like values in-place."""
        self._walk(data)
        return data

    def _walk(self, node: Any) -> None:
        if isinstance(node, dict):
            for key in node:
                value = node[key]
                if isinstance(value, str) and value and is_ip_like(value):
                    node[key] = self._redact(value)
                elif isinstance(value, (dict, list)):
                    self._walk(value)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                if isinstance(item, str) and item and is_ip_like(item):
                    node[i] = self._redact(item)
                elif isinstance(item, (dict, list)):
                    self._walk(item)

    def _redact(self, value: str) -> str:
        if value in self._mappings:
            return self._mappings[value]
        try:
            sanitized = self._allocator.allocate(value)
        except ValueError:
            logger.debug("IP allocation failed for '%s', keeping original", value)
            return value
        logger.debug("Redacted IP: %s → %s", value, sanitized)
        self._mappings[value] = sanitized
        return sanitized
