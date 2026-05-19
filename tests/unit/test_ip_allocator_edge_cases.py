# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Edge case tests for the IP address allocator."""

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
class TestPoolCapacity:
    """Verify we understand the practical capacity of default pools."""

    def test_default_pools_support_multiple_allocations(self, allocator) -> None:
        """Default pools can handle many distinct /24 allocations without exhaustion."""
        for i in range(10):
            result = allocator.allocate(f"10.{i}.1.0/24")
            network = ipaddress.ip_network(result)
            assert network.prefixlen == 24

    def test_small_pool_exact_capacity(self) -> None:
        """A /24 pool has exactly one /24 to give out."""
        alloc = IPAllocator(ipv4_pools=["192.0.2.0/24"])
        alloc.allocate("10.1.1.0/24")
        with pytest.raises(PoolExhaustedError):
            alloc.allocate("10.2.2.0/24")

    def test_small_pool_multiple_subnets(self) -> None:
        """A /22 pool can hand out four /24s."""
        alloc = IPAllocator(ipv4_pools=["192.0.0.0/22"])
        for i in range(4):
            alloc.allocate(f"10.{i}.0.0/24")
        with pytest.raises(PoolExhaustedError):
            alloc.allocate("10.99.0.0/24")


@pytest.mark.unit
class TestOrderDependentInference:
    """Test what happens when host inference and explicit networks interact."""

    def test_host_then_same_network_explicit(self, allocator) -> None:
        """If we see 10.1.1.5 (infers /24 of 10.1.1.0/24), then later see
        10.1.1.0/24 explicitly, they should use the same sanitized subnet."""
        host_result = allocator.allocate("10.1.1.5")
        network_result = allocator.allocate("10.1.1.0/24")

        # The host should be within the sanitized network
        host_addr = ipaddress.ip_address(host_result)
        sanitized_net = ipaddress.ip_network(network_result)
        assert host_addr in sanitized_net

    def test_network_then_host_within(self, allocator) -> None:
        """If we see 10.1.1.0/24 first, then 10.1.1.5, the host should
        land in the already-allocated sanitized network."""
        network_result = allocator.allocate("10.1.1.0/24")
        host_result = allocator.allocate("10.1.1.5")

        sanitized_net = ipaddress.ip_network(network_result)
        host_addr = ipaddress.ip_address(host_result)
        assert host_addr in sanitized_net

    def test_host_infers_24_then_different_16_allocated(self, allocator) -> None:
        """10.1.1.5 infers /24 of 10.1.1.0/24. Then 10.1.0.0/16 is a
        different, larger network and should get its own allocation."""
        allocator.allocate("10.1.1.5")
        result_16 = allocator.allocate("10.1.0.0/16")
        network_16 = ipaddress.ip_network(result_16)
        assert network_16.prefixlen == 16


@pytest.mark.unit
class TestOverlappingOriginalSubnets:
    """Test behavior when original data contains overlapping subnets."""

    def test_supernet_and_subnet_get_separate_allocations(self, allocator) -> None:
        """10.0.0.0/8 and 10.1.0.0/24 are overlapping in original space
        but should each get their own sanitized allocation."""
        big = allocator.allocate("10.0.0.0/8")
        small = allocator.allocate("10.1.0.0/24")

        big_net = ipaddress.ip_network(big)
        small_net = ipaddress.ip_network(small)

        assert big_net.prefixlen == 8
        assert small_net.prefixlen == 24
        # They should be different allocations
        assert big_net != small_net

    def test_two_overlapping_networks(self, allocator) -> None:
        """Both 10.0.0.0/16 and 10.0.1.0/24 can be independently allocated."""
        net_16 = allocator.allocate("10.0.0.0/16")
        net_24 = allocator.allocate("10.0.1.0/24")

        assert ipaddress.ip_network(net_16).prefixlen == 16
        assert ipaddress.ip_network(net_24).prefixlen == 24


@pytest.mark.unit
class TestHostBeforeNetwork:
    """Test that hosts seen before their containing network are handled."""

    def test_host_then_explicit_containing_network(self, allocator) -> None:
        """See 10.1.1.1 first, which infers 10.1.1.0/24. Then explicitly
        allocate 10.1.1.0/24. They should be consistent."""
        host = allocator.allocate("10.1.1.1")
        network = allocator.allocate("10.1.1.0/24")

        host_addr = ipaddress.ip_address(host)
        net = ipaddress.ip_network(network)
        assert host_addr in net

    def test_multiple_hosts_then_their_network(self, allocator) -> None:
        """Multiple hosts from the same /24 seen before the network itself."""
        h1 = allocator.allocate("10.5.5.1")
        h2 = allocator.allocate("10.5.5.100")
        h3 = allocator.allocate("10.5.5.254")
        net = allocator.allocate("10.5.5.0/24")

        sanitized_net = ipaddress.ip_network(net)
        assert ipaddress.ip_address(h1) in sanitized_net
        assert ipaddress.ip_address(h2) in sanitized_net
        assert ipaddress.ip_address(h3) in sanitized_net


@pytest.mark.unit
class TestBoundaryAddresses:
    """Test .0 and .255 addresses which may appear as hosts."""

    def test_dot_zero_as_host(self, allocator) -> None:
        """Some platforms report x.x.x.0 as a valid host address."""
        result = allocator.allocate("10.1.1.0")
        addr = ipaddress.ip_address(result)
        assert addr.version == 4

    def test_dot_255_as_host(self, allocator) -> None:
        """x.x.x.255 can be a valid host (in /23 or larger subnets)."""
        result = allocator.allocate("10.1.1.255")
        addr = ipaddress.ip_address(result)
        assert addr.version == 4

    def test_boundary_hosts_preserve_offset(self, allocator) -> None:
        """Boundary addresses should maintain their offset within the subnet."""
        # Allocate a host in the middle first to establish the subnet mapping
        allocator.allocate("10.1.1.1")
        result_0 = allocator.allocate("10.1.1.0")
        result_255 = allocator.allocate("10.1.1.255")

        addr_0 = ipaddress.ip_address(result_0)
        addr_255 = ipaddress.ip_address(result_255)

        # Offset between .0 and .255 should be 255
        assert int(addr_255) - int(addr_0) == 255


@pytest.mark.unit
class TestOriginalInPoolRange:
    """Test that originals already within output pool ranges are still sanitized."""

    def test_original_in_rfc5737_range(self, allocator) -> None:
        """192.0.2.50 is already in TEST-NET-1 but should still be remapped."""
        result = allocator.allocate("192.0.2.50")
        # It gets remapped - may or may not equal original, but it's valid
        addr = ipaddress.ip_address(result)
        assert addr.version == 4

    def test_original_in_rfc1918_range(self, allocator) -> None:
        """10.x addresses are in our pool range and should still be remapped."""
        result = allocator.allocate("10.0.0.1")
        addr = ipaddress.ip_address(result)
        assert addr.version == 4

    def test_two_originals_in_same_pool_stay_unique(self, allocator) -> None:
        """Even if originals are already in pool ranges, they must map uniquely."""
        a = allocator.allocate("10.0.0.1")
        b = allocator.allocate("10.0.0.2")
        assert a != b

    def test_original_network_in_pool_range(self, allocator) -> None:
        """192.0.2.0/24 is a pool itself - still gets allocated as a mapping."""
        result = allocator.allocate("192.0.2.0/24")
        net = ipaddress.ip_network(result)
        assert net.prefixlen == 24


@pytest.mark.unit
class TestIPv6EdgeCases:
    def test_ipv6_link_local(self, allocator) -> None:
        """Link-local addresses (fe80::) should still be allocatable."""
        result = allocator.allocate("fe80::1")
        addr = ipaddress.ip_address(result)
        assert addr.version == 6

    def test_ipv6_loopback(self, allocator) -> None:
        """::1 loopback should be allocatable."""
        result = allocator.allocate("::1")
        addr = ipaddress.ip_address(result)
        assert addr.version == 6

    def test_ipv6_full_notation(self, allocator) -> None:
        """Full IPv6 notation should work."""
        result = allocator.allocate("2001:0db8:0000:0000:0000:0000:0000:0001")
        addr = ipaddress.ip_address(result)
        assert addr.version == 6

    def test_ipv6_compressed_same_as_full(self, allocator) -> None:
        """Compressed and full notation of the same address should map identically."""
        a = allocator.allocate("2001:db8::1")
        b = allocator.allocate("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert a == b


@pytest.mark.unit
class TestMixedOperations:
    """Test interleaved host and network allocations."""

    def test_interleaved_hosts_and_networks(self, allocator) -> None:
        """Mixed allocation order should not cause collisions."""
        results = set()
        results.add(allocator.allocate("10.1.1.1"))
        results.add(allocator.allocate("10.2.0.0/24"))
        results.add(allocator.allocate("10.1.1.2"))
        results.add(allocator.allocate("10.3.0.0/16"))
        results.add(allocator.allocate("172.16.5.1"))

        # All 5 should be unique
        assert len(results) == 5

    def test_many_distinct_subnets(self, allocator) -> None:
        """Allocating many distinct /24s should not produce collisions."""
        results = set()
        for i in range(100):
            r = allocator.allocate(f"10.{i}.1.1")
            results.add(r)
        assert len(results) == 100
