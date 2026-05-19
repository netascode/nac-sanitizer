# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Redaction strategies for sanitizing values."""

import hashlib
from typing import Any, Protocol


class RedactionStrategy(Protocol):
    """Protocol defining the interface for all redaction strategies."""

    def redact(self, value: str, category: str | None = None) -> str: ...


class TokenStrategy:
    """Replace values with category-prefixed sequential tokens."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._seen: dict[str, str] = {}

    def redact(self, value: str, category: str | None = None) -> str:
        if value in self._seen:
            return self._seen[value]
        prefix = category or "REDACTED"
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        token = f"{prefix}-{self._counters[prefix]:03d}"
        self._seen[value] = token
        return token


class HostnameMapStrategy:
    """Map hostnames to generic sequential identifiers."""

    def __init__(self) -> None:
        self._counter = 0
        self._seen: dict[str, str] = {}

    def redact(self, value: str, category: str | None = None) -> str:
        if value in self._seen:
            return self._seen[value]
        self._counter += 1
        sanitized = f"DEVICE-{self._counter:03d}"
        self._seen[value] = sanitized
        return sanitized


class ConstantStrategy:
    """Replace all matched values with a fixed string."""

    def __init__(self, replacement: str = "***REDACTED***") -> None:
        self._replacement = replacement

    def redact(self, value: str, category: str | None = None) -> str:
        return self._replacement


class HashStrategy:
    """One-way hash preserving equality checks."""

    def __init__(self, length: int = 8) -> None:
        self._length = length

    def redact(self, value: str, category: str | None = None) -> str:
        digest = hashlib.sha256(value.encode()).hexdigest()
        return digest[: self._length]


class PreserveFormatStrategy:
    """Replace characters while preserving structural patterns."""

    def __init__(self) -> None:
        self._counter = 0
        self._seen: dict[str, str] = {}

    def redact(self, value: str, category: str | None = None) -> str:
        if value in self._seen:
            return self._seen[value]
        self._counter += 1
        sanitized = self._replace_preserving_format(value, self._counter)
        self._seen[value] = sanitized
        return sanitized

    def _replace_preserving_format(self, value: str, seq: int) -> str:
        seq_hex = f"{seq:012x}"
        seq_idx = 0
        result: list[str] = []
        for char in value:
            if char.isalnum():
                if seq_idx < len(seq_hex):
                    if char.isupper():
                        result.append(seq_hex[seq_idx].upper())
                    else:
                        result.append(seq_hex[seq_idx])
                    seq_idx += 1
                else:
                    result.append("X" if char.isupper() else "x")
            else:
                result.append(char)
        return "".join(result)


class StrategyRegistry:
    """Registry for looking up and applying redaction strategies by name."""

    def __init__(self) -> None:
        self._strategies: dict[str, RedactionStrategy] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self._strategies["token"] = TokenStrategy()
        self._strategies["hostname_map"] = HostnameMapStrategy()
        self._strategies["constant"] = ConstantStrategy()
        self._strategies["hash"] = HashStrategy()
        self._strategies["preserve_format"] = PreserveFormatStrategy()

    def get(self, name: str) -> RedactionStrategy:
        """Get a strategy by name."""
        if name not in self._strategies:
            raise KeyError(f"Unknown redaction strategy: '{name}'")
        return self._strategies[name]

    def register(self, name: str, strategy: RedactionStrategy) -> None:
        """Register a custom strategy."""
        self._strategies[name] = strategy

    def apply(self, strategy_name: str, value: Any, category: str | None) -> str:
        """Apply a named strategy to a value."""
        strategy = self.get(strategy_name)
        return strategy.redact(str(value), category)
