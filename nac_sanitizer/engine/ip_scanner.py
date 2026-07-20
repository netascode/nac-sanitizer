# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Value-pattern scanner that identifies and redacts IPs/prefixes across an entire JSON tree."""

import logging
import re
from typing import Any

from nac_sanitizer.engine.ip_allocator import IPAllocator

logger = logging.getLogger(__name__)

_IPV4_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?$")

_EMBEDDED_IPV4_PATTERN = re.compile(
    r"(?<![0-9a-fA-F.:])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d{1,2}))?(?![0-9.])"
)

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
    if ":" not in value:
        return False
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


_MIN_IPV4_LEN = 7  # shortest possible: "1.2.3.4"
_DIGITS = frozenset("0123456789")
_MAX_IP_LEN = 43  # longest possible: full IPv6 + "/128" (39 + 4)


def _could_contain_ipv4(value: str) -> bool:
    """Fast pre-check: can this string possibly contain an embedded IPv4?"""
    if len(value) < _MIN_IPV4_LEN or "." not in value:
        return False
    # IPv4 addresses always contain digits; skip strings that are purely
    # alphabetic/symbolic (e.g., "some.hostname.example.com" without digits
    # won't match the embedded pattern anyway, but the regex is expensive)
    for ch in value:
        if ch in _DIGITS:
            return True
    return False


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
    if len(value) > _MAX_IP_LEN:
        return False
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

    def _walk(self, root: Any) -> None:
        stack: list[Any] = [root]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key in node:
                    value = node[key]
                    if isinstance(value, str) and value:
                        if is_ip_like(value):
                            node[key] = self._redact(value)
                        elif _could_contain_ipv4(value):
                            replaced = self._redact_embedded(value)
                            if replaced is not value:
                                node[key] = replaced
                    elif isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    if isinstance(item, str) and item:
                        if is_ip_like(item):
                            node[i] = self._redact(item)
                        elif _could_contain_ipv4(item):
                            replaced = self._redact_embedded(item)
                            if replaced is not item:
                                node[i] = replaced
                    elif isinstance(item, (dict, list)):
                        stack.append(item)

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

    def _redact_embedded(self, value: str) -> str:
        """Replace IP addresses found within a longer string (e.g., URLs)."""

        def _replace_match(match: re.Match) -> str:
            ip_str = match.group(0)
            addr = match.group(1)
            octets = addr.split(".")
            if not all(0 <= int(o) <= 255 for o in octets):
                return ip_str
            prefix = match.group(2)
            if prefix and not (0 <= int(prefix) <= 32):
                return ip_str
            if ip_str in _EXCLUDED_VALUES or addr in _EXCLUDED_VALUES:
                return ip_str
            return self._redact(ip_str)

        result = _EMBEDDED_IPV4_PATTERN.sub(_replace_match, value)
        return result if result != value else value
