"""Shared constants for nac-sanitizer."""

ROSETTA_FILENAME_PREFIX = "nac-sanitizer-rosetta"
DEFAULT_ROSETTA_PERMISSIONS = 0o600

DEFAULT_IPV4_POOLS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "100.64.0.0/10",
]

DEFAULT_IPV6_POOLS = [
    "2001:db8::/32",
    "fc00::/7",
]

DEFAULT_IPV4_PREFIX = 24
DEFAULT_IPV6_PREFIX = 64
