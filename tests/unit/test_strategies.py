# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Tests for redaction strategies."""

import pytest

from nac_sanitizer.engine.strategies import (
    ConstantStrategy,
    HashStrategy,
    HostnameMapStrategy,
    PreserveFormatStrategy,
    StrategyRegistry,
    TokenStrategy,
)


@pytest.mark.unit
class TestTokenStrategy:
    def test_basic_redaction(self) -> None:
        s = TokenStrategy()
        result = s.redact("secret123", "CREDENTIAL")
        assert result == "CREDENTIAL-001"

    def test_default_category(self) -> None:
        s = TokenStrategy()
        result = s.redact("value")
        assert result == "REDACTED-001"

    def test_consistency(self) -> None:
        s = TokenStrategy()
        first = s.redact("secret123", "CRED")
        second = s.redact("secret123", "CRED")
        assert first == second

    def test_uniqueness(self) -> None:
        s = TokenStrategy()
        a = s.redact("value_a", "TOKEN")
        b = s.redact("value_b", "TOKEN")
        assert a != b

    def test_sequential_numbering(self) -> None:
        s = TokenStrategy()
        s.redact("a", "X")
        s.redact("b", "X")
        s.redact("c", "X")
        assert s.redact("c", "X") == "X-003"

    def test_separate_counters_per_category(self) -> None:
        s = TokenStrategy()
        a = s.redact("val1", "CAT_A")
        b = s.redact("val2", "CAT_B")
        assert a == "CAT_A-001"
        assert b == "CAT_B-001"


@pytest.mark.unit
class TestHostnameMapStrategy:
    def test_basic_mapping(self) -> None:
        s = HostnameMapStrategy()
        result = s.redact("core-rtr-01")
        assert result == "DEVICE-001"

    def test_consistency(self) -> None:
        s = HostnameMapStrategy()
        first = s.redact("core-rtr-01")
        second = s.redact("core-rtr-01")
        assert first == second

    def test_uniqueness(self) -> None:
        s = HostnameMapStrategy()
        a = s.redact("core-rtr-01")
        b = s.redact("dist-sw-02")
        assert a != b
        assert a == "DEVICE-001"
        assert b == "DEVICE-002"

    def test_ignores_category(self) -> None:
        s = HostnameMapStrategy()
        result = s.redact("host1", "IGNORED")
        assert result == "DEVICE-001"


@pytest.mark.unit
class TestConstantStrategy:
    def test_default_replacement(self) -> None:
        s = ConstantStrategy()
        assert s.redact("anything") == "***REDACTED***"

    def test_custom_replacement(self) -> None:
        s = ConstantStrategy(replacement="[REMOVED]")
        assert s.redact("anything") == "[REMOVED]"

    def test_always_same_output(self) -> None:
        s = ConstantStrategy()
        assert s.redact("a") == s.redact("b")


@pytest.mark.unit
class TestHashStrategy:
    def test_produces_fixed_length(self) -> None:
        s = HashStrategy(length=8)
        result = s.redact("some_value")
        assert len(result) == 8

    def test_custom_length(self) -> None:
        s = HashStrategy(length=16)
        result = s.redact("value")
        assert len(result) == 16

    def test_consistency(self) -> None:
        s = HashStrategy()
        assert s.redact("same") == s.redact("same")

    def test_different_inputs_different_outputs(self) -> None:
        s = HashStrategy()
        assert s.redact("input_a") != s.redact("input_b")

    def test_hex_characters_only(self) -> None:
        s = HashStrategy()
        result = s.redact("test")
        assert all(c in "0123456789abcdef" for c in result)


@pytest.mark.unit
class TestPreserveFormatStrategy:
    def test_mac_address_format(self) -> None:
        s = PreserveFormatStrategy()
        result = s.redact("AB:CD:EF:12:34:56")
        assert result.count(":") == 5
        assert len(result) == len("AB:CD:EF:12:34:56")

    def test_preserves_delimiters(self) -> None:
        s = PreserveFormatStrategy()
        result = s.redact("192.168.1.1")
        assert result.count(".") == 3

    def test_preserves_case_pattern(self) -> None:
        s = PreserveFormatStrategy()
        result = s.redact("AB:cd:EF")
        parts = result.split(":")
        assert parts[0] == parts[0].upper()
        assert parts[1] == parts[1].lower()
        assert parts[2] == parts[2].upper()

    def test_consistency(self) -> None:
        s = PreserveFormatStrategy()
        first = s.redact("AA:BB:CC:DD:EE:FF")
        second = s.redact("AA:BB:CC:DD:EE:FF")
        assert first == second

    def test_uniqueness(self) -> None:
        s = PreserveFormatStrategy()
        a = s.redact("AA:BB:CC:DD:EE:FF")
        b = s.redact("11:22:33:44:55:66")
        assert a != b


@pytest.mark.unit
class TestStrategyRegistry:
    def test_all_defaults_registered(self) -> None:
        r = StrategyRegistry()
        for name in ["token", "hostname_map", "constant", "hash", "preserve_format"]:
            assert r.get(name) is not None

    def test_unknown_strategy_raises_error(self) -> None:
        r = StrategyRegistry()
        with pytest.raises(KeyError, match="Unknown redaction strategy"):
            r.get("nonexistent")

    def test_apply_dispatches_correctly(self) -> None:
        r = StrategyRegistry()
        result = r.apply("constant", "anything", None)
        assert result == "***REDACTED***"

    def test_apply_with_category(self) -> None:
        r = StrategyRegistry()
        result = r.apply("token", "secret", "SNMP")
        assert result == "SNMP-001"

    def test_register_custom_strategy(self) -> None:
        r = StrategyRegistry()

        class Custom:
            def redact(self, value: str, category: str | None = None) -> str:
                return "CUSTOM"

        r.register("custom", Custom())
        assert r.apply("custom", "x", None) == "CUSTOM"
