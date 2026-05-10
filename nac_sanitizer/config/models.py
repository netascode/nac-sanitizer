"""Pydantic models for nac-sanitizer configuration."""

from pydantic import BaseModel

from nac_sanitizer.constants import (
    DEFAULT_IPV4_POOLS,
    DEFAULT_IPV4_PREFIX,
    DEFAULT_IPV6_POOLS,
    DEFAULT_IPV6_PREFIX,
)


class RedactionRule(BaseModel):
    """A single redaction rule mapping a JSONPath to a strategy."""

    path: str
    strategy: str
    tier: str = "default"
    category: str | None = None


class PackConfig(BaseModel):
    """User-specified pack activation and deactivation."""

    enable: list[str] = []
    disable: list[str] = []


class OverrideRule(BaseModel):
    """User override for a specific path's tier or strategy."""

    path: str
    tier: str
    strategy: str | None = None


class IPPoolSettings(BaseModel):
    """Configuration for IP address sanitization pools."""

    ipv4_pools: list[str] = list(DEFAULT_IPV4_POOLS)
    ipv6_pools: list[str] = list(DEFAULT_IPV6_POOLS)
    preserve_prefix_length: bool = True
    default_ipv4_prefix: int = DEFAULT_IPV4_PREFIX
    default_ipv6_prefix: int = DEFAULT_IPV6_PREFIX


class RosettaSettings(BaseModel):
    """Configuration for Rosetta Stone output."""

    format: str = "json"
    encrypt: bool = False


class GlobalSettings(BaseModel):
    """Top-level settings block."""

    ip_pools: IPPoolSettings = IPPoolSettings()
    rosetta: RosettaSettings = RosettaSettings()


class SanitizerConfig(BaseModel):
    """Complete sanitizer configuration assembled from all layers."""

    profiles: list[str] = []
    packs: PackConfig = PackConfig()
    overrides: list[OverrideRule] = []
    custom_rules: list[RedactionRule] = []
    settings: GlobalSettings = GlobalSettings()
