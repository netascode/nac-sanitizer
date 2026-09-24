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
        with pytest.raises(
            PoolExhaustedError, match="Ran out of IPv4 /24 address space"
        ):
            small_pool_allocator.allocate("10.2.2.0/24")

    def test_error_message_includes_details(self, small_pool_allocator) -> None:
        small_pool_allocator.allocate("10.1.1.0/24")
        with pytest.raises(PoolExhaustedError, match="ip_pools.ipv4"):
            small_pool_allocator.allocate("10.2.2.0/24")


@pytest.mark.unit
class TestSkipLargeSubnets:
    def test_slash_0_preserved(self, allocator) -> None:
        assert allocator.allocate("0.0.0.0/0") == "0.0.0.0/0"

    def test_slash_1_preserved(self, allocator) -> None:
        assert allocator.allocate("0.0.0.0/1") == "0.0.0.0/1"

    def test_slash_1_alternate_preserved(self, allocator) -> None:
        assert allocator.allocate("128.0.0.0/1") == "128.0.0.0/1"

    def test_slash_2_preserved(self, allocator) -> None:
        assert allocator.allocate("192.0.0.0/2") == "192.0.0.0/2"

    def test_slash_3_preserved(self, allocator) -> None:
        assert allocator.allocate("224.0.0.0/3") == "224.0.0.0/3"

    def test_slash_4_preserved(self, allocator) -> None:
        assert allocator.allocate("240.0.0.0/4") == "240.0.0.0/4"

    def test_slash_5_still_sanitized(self) -> None:
        alloc = IPAllocator(ipv4_pools=["0.0.0.0/0"])
        result = alloc.allocate("10.0.0.0/5")
        assert result != "10.0.0.0/5"
        network = ipaddress.ip_network(result)
        assert network.prefixlen == 5

    def test_slash_8_still_sanitized(self, allocator) -> None:
        result = allocator.allocate("44.0.0.0/8")
        assert result != "44.0.0.0/8"
        network = ipaddress.ip_network(result)
        assert network.prefixlen == 8

    def test_disabled_flag_sanitizes_large_subnets(self) -> None:
        alloc = IPAllocator(
            ipv4_pools=["0.0.0.0/0"],
            skip_large_ipv4_subnets=False,
        )
        result = alloc.allocate("10.0.0.0/4")
        assert result != "10.0.0.0/4"
        network = ipaddress.ip_network(result)
        assert network.prefixlen == 4

    def test_ipv6_large_prefixes_still_sanitized(self) -> None:
        alloc = IPAllocator(ipv6_pools=["::/0"])
        result = alloc.allocate("2000::/3")
        assert result != "2000::/3"
        network = ipaddress.ip_network(result)
        assert network.prefixlen == 3

    def test_consistency_when_skipped(self, allocator) -> None:
        first = allocator.allocate("128.0.0.0/1")
        second = allocator.allocate("128.0.0.0/1")
        assert first == second == "128.0.0.0/1"


@pytest.mark.unit
class TestSelfMappingPrevention:
    def test_host_at_pool_base_not_selfmapped(self, allocator) -> None:
        result = allocator.allocate("10.0.0.1")
        assert result != "10.0.0.1"

    def test_network_at_pool_base_not_selfmapped(self, allocator) -> None:
        result = allocator.allocate("10.0.0.0/24")
        assert result != "10.0.0.0/24"

    def test_hosts_across_pool_bases(self, allocator) -> None:
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.0.1"]:
            result = allocator.allocate(ip)
            assert result != ip, f"{ip} self-mapped"

    def test_sequential_allocations_no_selfmap(self, allocator) -> None:
        for i in range(50):
            original = f"10.0.{i}.0/24"
            result = allocator.allocate(original)
            assert result != original, f"{original} self-mapped"

    def test_selfmap_guard_preserves_topology(self, allocator) -> None:
        a = allocator.allocate("10.0.0.1")
        b = allocator.allocate("10.0.0.100")

        net_a = ipaddress.ip_network(f"{a}/24", strict=False)
        net_b = ipaddress.ip_network(f"{b}/24", strict=False)
        assert net_a == net_b

        offset = int(ipaddress.ip_address(b)) - int(ipaddress.ip_address(a))
        assert offset == 99


@pytest.mark.unit
class TestEdgeCases:
    def test_original_in_pool_range_still_sanitized(self, allocator) -> None:
        result = allocator.allocate("192.0.2.1")
        assert result != "192.0.2.1"

    def test_invalid_ip_raises_value_error(self, allocator) -> None:
        with pytest.raises(ValueError, match="Cannot parse"):
            allocator.allocate("not-an-ip")

    def test_invalid_network_raises_value_error(self, allocator) -> None:
        with pytest.raises(ValueError, match="Cannot parse"):
            allocator.allocate("not-a-network/24")


@pytest.mark.unit
class TestMulticastAllocation:
    def test_multicast_host_maps_to_multicast(self, allocator) -> None:
        result = allocator.allocate("239.1.1.1")
        assert ipaddress.ip_address(result).is_multicast

    def test_multicast_network_maps_to_multicast(self, allocator) -> None:
        result = allocator.allocate("239.1.0.0/24")
        net = ipaddress.ip_network(result)
        assert net.network_address.is_multicast
        assert net.prefixlen == 24

    def test_multicast_result_in_default_pool(self, allocator) -> None:
        result = allocator.allocate("239.1.1.1")
        addr = ipaddress.ip_address(result)
        assert addr in ipaddress.ip_network("239.0.0.0/8")

    def test_multicast_consistency(self, allocator) -> None:
        first = allocator.allocate("239.1.1.1")
        second = allocator.allocate("239.1.1.1")
        assert first == second

    def test_multicast_uniqueness(self, allocator) -> None:
        a = allocator.allocate("239.1.1.1")
        b = allocator.allocate("239.2.2.2")
        assert a != b

    def test_multicast_topology_preserved(self, allocator) -> None:
        a = allocator.allocate("239.1.1.1")
        b = allocator.allocate("239.1.1.2")
        net_a = ipaddress.ip_network(f"{a}/24", strict=False)
        net_b = ipaddress.ip_network(f"{b}/24", strict=False)
        assert net_a == net_b

    def test_multicast_prefix_16_preserved(self, allocator) -> None:
        result = allocator.allocate("239.0.0.0/16")
        net = ipaddress.ip_network(result)
        assert net.prefixlen == 16
        assert net.network_address.is_multicast

    def test_multicast_does_not_collide_with_unicast(self, allocator) -> None:
        unicast = allocator.allocate("10.1.1.1")
        multicast = allocator.allocate("239.1.1.1")
        assert unicast != multicast
        assert not ipaddress.ip_address(unicast).is_multicast
        assert ipaddress.ip_address(multicast).is_multicast

    def test_unicast_unaffected_by_multicast_pools(self, allocator) -> None:
        result = allocator.allocate("10.1.1.1")
        assert not ipaddress.ip_address(result).is_multicast

    def test_multicast_self_mapping_prevention(self, allocator) -> None:
        result = allocator.allocate("239.0.0.1")
        assert result != "239.0.0.1"

    def test_custom_multicast_pool(self) -> None:
        alloc = IPAllocator(ipv4_multicast_pools=["232.0.0.0/8"])
        result = alloc.allocate("239.1.1.1")
        addr = ipaddress.ip_address(result)
        assert addr in ipaddress.ip_network("232.0.0.0/8")

    def test_multicast_host_offset_preserved(self, allocator) -> None:
        a = allocator.allocate("239.1.1.1")
        b = allocator.allocate("239.1.1.100")
        offset = int(ipaddress.ip_address(b)) - int(ipaddress.ip_address(a))
        assert offset == 99
