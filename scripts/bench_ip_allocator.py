#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Benchmark for IPAllocator performance.

Generates realistic workloads simulating SDWAN/Catalyst Center backups
and measures wall-clock allocation time at various scales.

Usage:
    python scripts/bench_ip_allocator.py
"""

import random
import time

from nac_sanitizer.engine.ip_allocator import IPAllocator


def generate_workload(
    n_subnets: int,
    hosts_per_subnet: int,
    cidr_ratio: float = 0.1,
    ipv6_ratio: float = 0.2,
    seed: int = 42,
) -> list[str]:
    """Generate a list of IPs simulating a real deployment.

    Creates n_subnets distinct subnets with hosts_per_subnet addresses each.
    Interleaves subnets to simulate non-sequential discovery order.
    """
    rng = random.Random(seed)  # nosec B311 - deterministic seed for benchmarks
    items: list[str] = []

    n_ipv4_subnets = int(n_subnets * (1 - ipv6_ratio))
    n_ipv6_subnets = n_subnets - n_ipv4_subnets

    # Generate IPv4 workload
    for i in range(n_ipv4_subnets):
        octet2 = (i // 256) % 256
        octet3 = i % 256
        base = f"10.{octet2}.{octet3}"

        for h in range(hosts_per_subnet):
            host_octet = (h % 254) + 1
            if rng.random() < cidr_ratio:
                items.append(f"{base}.0/24")
            else:
                items.append(f"{base}.{host_octet}")

    # Generate IPv6 workload
    for i in range(n_ipv6_subnets):
        hex_segment = f"{i:04x}"
        prefix = f"2001:db8:{hex_segment}::"

        for h in range(hosts_per_subnet):
            if rng.random() < cidr_ratio:
                items.append(f"{prefix}/64")
            else:
                items.append(f"{prefix}{h + 1:x}")

    rng.shuffle(items)
    return items


def bench(label: str, workload: list[str]) -> float:
    """Run allocation benchmark, return elapsed seconds."""
    allocator = IPAllocator()

    start = time.perf_counter()
    for value in workload:
        allocator.allocate(value)
    elapsed = time.perf_counter() - start

    unique_count = len(set(workload))
    rate = unique_count / elapsed if elapsed > 0 else float("inf")

    print(f"  {label}")
    print(f"    Total items:    {len(workload):,}")
    print(f"    Unique items:   {unique_count:,}")
    print(f"    Elapsed:        {elapsed:.4f}s")
    print(f"    Per allocation: {elapsed / unique_count * 1000:.4f}ms")
    print(f"    Rate:           {rate:,.0f} allocs/sec")
    print()
    return elapsed


def main() -> None:
    print("=" * 60)
    print("IPAllocator Performance Benchmark")
    print("=" * 60)
    print()

    scenarios = [
        ("Small  (50 subnets, 10 hosts)", 50, 10),
        ("Medium (200 subnets, 20 hosts)", 200, 20),
        ("Large  (1000 subnets, 50 hosts)", 1000, 50),
    ]

    for label, n_subnets, hosts_per_subnet in scenarios:
        workload = generate_workload(n_subnets, hosts_per_subnet)
        bench(label, workload)

    # Stress test: many distinct subnets (worst case for linear scan)
    print("-" * 60)
    print("Stress test: subnet allocation scaling")
    print("-" * 60)
    print()

    for n in [100, 500, 1000, 5000]:
        allocator = IPAllocator()
        networks = [f"10.{i // 256}.{i % 256}.0/24" for i in range(n)]

        start = time.perf_counter()
        for net in networks:
            allocator.allocate(net)
        elapsed = time.perf_counter() - start

        print(f"  {n:>5} network allocs: {elapsed:.4f}s ({n / elapsed:,.0f}/sec)")

    print()


if __name__ == "__main__":
    main()
