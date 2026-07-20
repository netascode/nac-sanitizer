# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""IP address and prefix allocation with subnet topology preservation."""

import bisect
import ipaddress
import logging
import re
from dataclasses import dataclass, field

from nac_sanitizer.constants import (
    DEFAULT_IPV4_POOLS,
    DEFAULT_IPV4_PREFIX,
    DEFAULT_IPV6_POOLS,
    DEFAULT_IPV6_PREFIX,
)

logger = logging.getLogger(__name__)

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

    # O(1) exact network lookup (keyed by network object)
    _network_exact_map: dict[IPv4Or6Network, int] = field(
        default_factory=dict, init=False
    )
    # Sorted list of (network_address_int, broadcast_address_int, mapping_index)
    # for O(log n) host containment queries
    _sorted_originals: list[tuple[int, int, int]] = field(
        default_factory=list, init=False
    )

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

        logger.debug("Allocated %s → %s", value, result)
        self._host_map[value] = result
        return result

    def _allocate_network(self, value: str) -> str:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as e:
            raise ValueError(f"Cannot parse as network: {value}") from e

        idx = self._network_exact_map.get(network)
        if idx is not None:
            return str(self._subnet_mappings[idx].sanitized)

        prefix_len = network.prefixlen
        sanitized_network = self._next_available_network(network.version, prefix_len)
        idx = len(self._subnet_mappings)
        self._subnet_mappings.append(SubnetMapping(network, sanitized_network))
        self._network_exact_map[network] = idx
        self._register_original_range(network, idx)
        return str(sanitized_network)

    def _allocate_host(self, value: str) -> str:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as e:
            raise ValueError(f"Cannot parse as IP address: {value}") from e

        addr_int = int(addr)

        # O(log n) containment check
        mapping_idx = self._find_containing_mapping(addr_int)
        if mapping_idx is not None:
            mapping = self._subnet_mappings[mapping_idx]
            offset = addr_int - int(mapping.original.network_address)
            sanitized_addr = mapping.sanitized.network_address + offset
            return str(sanitized_addr)

        default_prefix = (
            self.default_ipv4_prefix if addr.version == 4 else self.default_ipv6_prefix
        )
        original_network = ipaddress.ip_network(
            f"{addr}/{default_prefix}", strict=False
        )

        # Check if the inferred network overlaps an existing mapping (O(log n))
        overlap_idx = self._find_overlapping_mapping(original_network)
        if overlap_idx is not None:
            mapping = self._subnet_mappings[overlap_idx]
            offset = addr_int - int(mapping.original.network_address)
            sanitized_addr = mapping.sanitized.network_address + offset
            return str(sanitized_addr)

        sanitized_network = self._next_available_network(addr.version, default_prefix)
        idx = len(self._subnet_mappings)
        self._subnet_mappings.append(SubnetMapping(original_network, sanitized_network))
        self._network_exact_map[original_network] = idx
        self._register_original_range(original_network, idx)

        offset = addr_int - int(original_network.network_address)
        sanitized_addr = sanitized_network.network_address + offset
        return str(sanitized_addr)

    def _register_original_range(self, network: IPv4Or6Network, idx: int) -> None:
        """Insert the network's address range into the sorted lookup structure."""
        net_int = int(network.network_address)
        bcast_int = int(network.broadcast_address)
        entry = (net_int, bcast_int, idx)
        pos = bisect.bisect_left(self._sorted_originals, (net_int,))
        self._sorted_originals.insert(pos, entry)

    def _find_containing_mapping(self, addr_int: int) -> int | None:
        """O(log n) lookup: find which mapping's original network contains addr_int."""
        pos = bisect.bisect_right(self._sorted_originals, (addr_int,)) - 1
        while pos >= 0:
            net_int, bcast_int, idx = self._sorted_originals[pos]
            if net_int <= addr_int <= bcast_int:
                return idx
            if addr_int - net_int > bcast_int - net_int:
                break
            pos -= 1
        return None

    def _find_overlapping_mapping(self, network: IPv4Or6Network) -> int | None:
        """O(log n) lookup: find a mapping whose original overlaps the given network."""
        net_int = int(network.network_address)
        bcast_int = int(network.broadcast_address)

        pos = bisect.bisect_right(self._sorted_originals, (bcast_int,)) - 1
        while pos >= 0:
            entry_net, entry_bcast, idx = self._sorted_originals[pos]
            if entry_net <= bcast_int and net_int <= entry_bcast:
                return idx
            if entry_bcast < net_int:
                break
            pos -= 1
        return None

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

        pool_cidrs = ", ".join(str(p) for p in pools)
        raise PoolExhaustedError(
            f"Ran out of IPv{version} /{prefix_len} address space for sanitization. "
            f"All {len(self._subnet_mappings)} allocated subnets have consumed the "
            f"configured pools ({pool_cidrs}). "
            f"Add larger or additional pools under 'ip_pools.ipv{version}' "
            f"in your configuration file to increase capacity."
        )

    def _overlaps_existing(self, candidate: IPv4Or6Network) -> bool:
        """Check if a candidate network overlaps any already-allocated network."""
        for mapping in self._subnet_mappings:
            if mapping.sanitized.overlaps(candidate):
                return True
        return False
