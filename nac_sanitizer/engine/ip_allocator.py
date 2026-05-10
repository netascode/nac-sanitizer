"""IP address and prefix allocation with subnet topology preservation."""

import ipaddress
import re
from dataclasses import dataclass, field

from nac_sanitizer.constants import (
    DEFAULT_IPV4_POOLS,
    DEFAULT_IPV4_PREFIX,
    DEFAULT_IPV6_POOLS,
    DEFAULT_IPV6_PREFIX,
)

IPv4Or6Network = ipaddress.IPv4Network | ipaddress.IPv6Network
IPv4Or6Address = ipaddress.IPv4Address | ipaddress.IPv6Address

_CIDR_PATTERN = re.compile(r".+/\d+$")


class PoolExhaustedError(Exception):
    """Raised when an IP address pool has no remaining addresses to allocate."""


@dataclass
class SubnetMapping:
    """Maps an original subnet to its sanitized counterpart."""

    original: IPv4Or6Network
    sanitized: IPv4Or6Network


@dataclass
class IPAllocator:
    """Allocates sanitized IP addresses from configured pools.

    Guarantees:
    - Uniqueness: no two distinct originals map to the same sanitized value
    - Topology preservation: hosts sharing a subnet stay grouped
    - Prefix-length preservation (configurable)
    """

    ipv4_pools: list[str] = field(default_factory=lambda: list(DEFAULT_IPV4_POOLS))
    ipv6_pools: list[str] = field(default_factory=lambda: list(DEFAULT_IPV6_POOLS))
    preserve_prefix_length: bool = True
    default_ipv4_prefix: int = DEFAULT_IPV4_PREFIX
    default_ipv6_prefix: int = DEFAULT_IPV6_PREFIX

    _host_map: dict[str, str] = field(default_factory=dict, init=False)
    _subnet_mappings: list[SubnetMapping] = field(default_factory=list, init=False)
    _ipv4_pool_networks: list[ipaddress.IPv4Network] = field(
        default_factory=list, init=False
    )
    _ipv6_pool_networks: list[ipaddress.IPv6Network] = field(
        default_factory=list, init=False
    )
    _ipv4_offset: int = field(default=0, init=False)
    _ipv6_offset: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._ipv4_pool_networks = [ipaddress.IPv4Network(p) for p in self.ipv4_pools]
        self._ipv6_pool_networks = [ipaddress.IPv6Network(p) for p in self.ipv6_pools]

    def allocate(self, value: str) -> str:
        """Allocate a sanitized IP/prefix for the given original value."""
        if value in self._host_map:
            return self._host_map[value]

        is_network = _CIDR_PATTERN.match(value) is not None

        if is_network:
            result = self._allocate_network(value)
        else:
            result = self._allocate_host(value)

        self._host_map[value] = result
        return result

    def _allocate_network(self, value: str) -> str:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as e:
            raise ValueError(f"Cannot parse as network: {value}") from e

        for mapping in self._subnet_mappings:
            if network == mapping.original:
                return str(mapping.sanitized)

        prefix_len = network.prefixlen
        sanitized_network = self._next_available_network(network.version, prefix_len)
        self._subnet_mappings.append(SubnetMapping(network, sanitized_network))
        return str(sanitized_network)

    def _allocate_host(self, value: str) -> str:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as e:
            raise ValueError(f"Cannot parse as IP address: {value}") from e

        for mapping in self._subnet_mappings:
            if addr in mapping.original:
                offset = int(addr) - int(mapping.original.network_address)
                sanitized_addr = mapping.sanitized.network_address + offset
                return str(sanitized_addr)

        default_prefix = (
            self.default_ipv4_prefix if addr.version == 4 else self.default_ipv6_prefix
        )
        original_network = ipaddress.ip_network(
            f"{addr}/{default_prefix}", strict=False
        )

        # Check if this inferred network overlaps an existing mapping
        for mapping in self._subnet_mappings:
            if mapping.original.overlaps(original_network):
                original_network = mapping.original
                offset = int(addr) - int(mapping.original.network_address)
                sanitized_addr = mapping.sanitized.network_address + offset
                return str(sanitized_addr)

        sanitized_network = self._next_available_network(addr.version, default_prefix)
        self._subnet_mappings.append(SubnetMapping(original_network, sanitized_network))

        offset = int(addr) - int(original_network.network_address)
        sanitized_addr = sanitized_network.network_address + offset
        return str(sanitized_addr)

    def _next_available_network(self, version: int, prefix_len: int) -> IPv4Or6Network:
        """Allocate the next available network of the given prefix length from pools."""
        if version == 4:
            return self._next_from_pools(self._ipv4_pool_networks, prefix_len, version)
        else:
            return self._next_from_pools(self._ipv6_pool_networks, prefix_len, version)

    def _next_from_pools(
        self,
        pools: list,
        prefix_len: int,
        version: int,
    ) -> IPv4Or6Network:
        """Find the next non-overlapping network from the configured pools."""
        for pool in pools:
            if pool.prefixlen > prefix_len:
                continue

            for subnet in pool.subnets(new_prefix=prefix_len):
                if not self._overlaps_existing(subnet):
                    return subnet

        raise PoolExhaustedError(
            f"No available IPv{version} /{prefix_len} networks remaining in configured pools. "
            f"Total mappings allocated: {len(self._subnet_mappings)}"
        )

    def _overlaps_existing(self, candidate: IPv4Or6Network) -> bool:
        """Check if a candidate network overlaps any already-allocated network."""
        for mapping in self._subnet_mappings:
            if mapping.sanitized.overlaps(candidate):
                return True
        return False
