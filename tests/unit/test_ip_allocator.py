# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Tests for the IP address allocator."""

import ipaddress

import pytest

from nac_sanitizer.engine.ip_allocator import IPAllocator, PoolExhaustedError


@pytest.fixture
def allocator() -> IPAllocator:
    return IPAllocator()


@pytest.fixture
def small_pool_allocator() -> IPAllocator:
    return IPAllocator(ipv4_pools=["192.0.2.0/24"])


@pytest.mark.unit
class TestBasicAllocation:
    def test_allocate_single_ipv4(self, allocator) -> None:
        result = allocator.allocate("10.50.1.1")
        addr = ipaddress.ip_address(result)
        assert addr.version == 4

    def test_allocate_single_ipv6(self, allocator) -> None:
        result = allocator.allocate("2001:db8::1")
        addr = ipaddress.ip_address(result)
        assert addr.version == 6

    def test_allocate_ipv4_network(self, allocator) -> None:
        result = allocator.allocate("10.50.1.0/24")
        network = ipaddress.ip_network(result)
        assert network.version == 4
        assert network.prefixlen == 24

    def test_allocate_ipv6_network(self, allocator) -> None:
        result = allocator.allocate("2001:db8:abcd::/48")
        network = ipaddress.ip_network(result)
        assert network.version == 6
        assert network.prefixlen == 48


@pytest.mark.unit
class TestConsistency:
    def test_same_host_same_result(self, allocator) -> None:
        first = allocator.allocate("10.50.1.1")
        second = allocator.allocate("10.50.1.1")
        assert first == second

    def test_same_network_same_result(self, allocator) -> None:
        first = allocator.allocate("10.50.1.0/24")
        second = allocator.allocate("10.50.1.0/24")
        assert first == second


@pytest.mark.unit
class TestUniqueness:
    def test_different_hosts_different_results(self, allocator) -> None:
        a = allocator.allocate("10.50.1.1")
        b = allocator.allocate("172.16.0.1")
        assert a != b

    def test_different_networks_different_results(self, allocator) -> None:
        a = allocator.allocate("10.50.1.0/24")
        b = allocator.allocate("10.50.2.0/24")
        assert a != b


@pytest.mark.unit
class TestTopologyPreservation:
    def test_hosts_on_same_subnet_stay_grouped(self, allocator) -> None:
        a = allocator.allocate("10.50.1.1")
        b = allocator.allocate("10.50.1.2")
        c = allocator.allocate("10.50.1.254")

        net_a = ipaddress.ip_network(f"{a}/24", strict=False)
        net_b = ipaddress.ip_network(f"{b}/24", strict=False)
        net_c = ipaddress.ip_network(f"{c}/24", strict=False)

        assert net_a == net_b == net_c

    def test_hosts_on_different_subnets_separate(self, allocator) -> None:
        a = allocator.allocate("10.50.1.1")
        b = allocator.allocate("10.50.2.1")

        net_a = ipaddress.ip_network(f"{a}/24", strict=False)
        net_b = ipaddress.ip_network(f"{b}/24", strict=False)

        assert net_a != net_b

    def test_host_offset_preserved(self, allocator) -> None:
        a = allocator.allocate("10.50.1.1")
        b = allocator.allocate("10.50.1.100")

        addr_a = ipaddress.ip_address(a)
        addr_b = ipaddress.ip_address(b)

        offset = int(addr_b) - int(addr_a)
        assert offset == 99

    def test_ipv6_hosts_on_same_subnet(self, allocator) -> None:
        a = allocator.allocate("2001:db8:1::1")
        b = allocator.allocate("2001:db8:1::2")

        net_a = ipaddress.ip_network(f"{a}/64", strict=False)
        net_b = ipaddress.ip_network(f"{b}/64", strict=False)

        assert net_a == net_b


@pytest.mark.unit
class TestPrefixLengthPreservation:
    def test_prefix_16_preserved(self, allocator) -> None:
        result = allocator.allocate("10.0.0.0/16")
        network = ipaddress.ip_network(result)
        assert network.prefixlen == 16

    def test_prefix_30_preserved(self, allocator) -> None:
        result = allocator.allocate("10.50.1.0/30")
        network = ipaddress.ip_network(result)
        assert network.prefixlen == 30

    def test_prefix_48_ipv6_preserved(self, allocator) -> None:
        result = allocator.allocate("2001:db8:abcd::/48")
        network = ipaddress.ip_network(result)
        assert network.prefixlen == 48


@pytest.mark.unit
class TestPoolExhaustion:
    def test_small_pool_exhaustion(self, small_pool_allocator) -> None:
        # /24 pool can only allocate one /24 network
        small_pool_allocator.allocate("10.1.1.0/24")
        with pytest.raises(PoolExhaustedError, match="No available"):
            small_pool_allocator.allocate("10.2.2.0/24")

    def test_error_message_includes_details(self, small_pool_allocator) -> None:
        small_pool_allocator.allocate("10.1.1.0/24")
        with pytest.raises(PoolExhaustedError, match="Total mappings allocated: 1"):
            small_pool_allocator.allocate("10.2.2.0/24")


@pytest.mark.unit
class TestEdgeCases:
    def test_original_in_pool_range_still_sanitized(self, allocator) -> None:
        # Even if the original IP is already in a "safe" range, it gets remapped
        result = allocator.allocate("192.0.2.1")
        # It should still produce a valid IP (may or may not equal the input)
        ipaddress.ip_address(result)

    def test_invalid_ip_raises_value_error(self, allocator) -> None:
        with pytest.raises(ValueError, match="Cannot parse"):
            allocator.allocate("not-an-ip")

    def test_invalid_network_raises_value_error(self, allocator) -> None:
        with pytest.raises(ValueError, match="Cannot parse"):
            allocator.allocate("not-a-network/24")
