# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""Tests for the value-pattern IP scanner."""

import pytest

from nac_sanitizer.engine.ip_allocator import IPAllocator
from nac_sanitizer.engine.ip_scanner import IPScanner, is_ip_like


@pytest.mark.unit
class TestIsIpLike:
    def test_ipv4_address(self) -> None:
        assert is_ip_like("10.1.1.1") is True

    def test_ipv4_prefix(self) -> None:
        assert is_ip_like("192.168.1.0/24") is True

    def test_ipv6_address(self) -> None:
        assert is_ip_like("2001:db8::1") is True

    def test_ipv6_prefix(self) -> None:
        assert is_ip_like("2001:db8::/32") is True

    def test_ipv6_full(self) -> None:
        assert is_ip_like("2001:0db8:0000:0000:0000:0000:0000:0001") is True

    def test_not_ip_plain_string(self) -> None:
        assert is_ip_like("hello") is False

    def test_not_ip_interface_name(self) -> None:
        assert is_ip_like("GigabitEthernet0/0") is False

    def test_not_ip_hostname(self) -> None:
        assert is_ip_like("core-rtr-01") is False

    def test_not_ip_mac_address(self) -> None:
        assert is_ip_like("00:50:56:9D:A8:63") is False

    def test_not_ip_number_string(self) -> None:
        assert is_ip_like("12345") is False

    def test_not_ip_version_string(self) -> None:
        assert is_ip_like("20.15.4.1") is True  # Looks like an IP

    def test_not_ip_empty(self) -> None:
        assert is_ip_like("") is False

    def test_not_ip_url(self) -> None:
        assert is_ip_like("https://10.1.1.1") is False

    def test_ipv4_with_invalid_octet(self) -> None:
        assert is_ip_like("999.1.1.1") is False

    def test_ipv4_prefix_invalid_mask(self) -> None:
        assert is_ip_like("10.1.1.0/33") is False

    def test_ipv4_range_not_ip(self) -> None:
        assert is_ip_like("9.1.1.134-135") is False

    def test_ipv6_loopback(self) -> None:
        assert is_ip_like("::1") is True

    def test_not_ip_uuid(self) -> None:
        assert is_ip_like("ef66f799-2217-42a3-92a0-557d5424d5dd") is False


@pytest.mark.unit
class TestIPScanner:
    def test_scan_simple_dict(self) -> None:
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {"device": {"ip": "10.1.1.1", "name": "router"}}
        scanner.scan(data)
        assert data["device"]["ip"] != "10.1.1.1"
        assert data["device"]["name"] == "router"

    def test_scan_nested_structure(self) -> None:
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {
            "devices": [
                {"mgmt_ip": "10.50.1.1", "hostname": "rtr1"},
                {"mgmt_ip": "10.50.1.2", "hostname": "rtr2"},
            ]
        }
        scanner.scan(data)
        assert data["devices"][0]["mgmt_ip"] != "10.50.1.1"
        assert data["devices"][1]["mgmt_ip"] != "10.50.1.2"
        assert data["devices"][0]["hostname"] == "rtr1"

    def test_scan_preserves_consistency(self) -> None:
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {
            "primary": {"ip": "10.1.1.1"},
            "secondary": {"ip": "10.1.1.1"},
        }
        scanner.scan(data)
        assert data["primary"]["ip"] == data["secondary"]["ip"]

    def test_scan_handles_prefixes(self) -> None:
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {"route": {"prefix": "192.168.1.0/24"}}
        scanner.scan(data)
        assert data["route"]["prefix"] != "192.168.1.0/24"
        assert "/24" in data["route"]["prefix"]

    def test_scan_skips_non_ip_strings(self) -> None:
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {
            "config": {
                "interface": "GigabitEthernet0/0",
                "description": "uplink",
                "ip": "10.1.1.1",
                "password": "secret",
            }
        }
        scanner.scan(data)
        assert data["config"]["interface"] == "GigabitEthernet0/0"
        assert data["config"]["description"] == "uplink"
        assert data["config"]["password"] == "secret"
        assert data["config"]["ip"] != "10.1.1.1"

    def test_scan_handles_lists_with_ips(self) -> None:
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {"connectedVManages": ["100.0.0.1", "100.0.0.2"]}
        scanner.scan(data)
        assert data["connectedVManages"][0] != "100.0.0.1"
        assert data["connectedVManages"][1] != "100.0.0.2"

    def test_scan_deeply_nested_vipvalue(self) -> None:
        """Simulates SD-WAN template structure with IPs in vipValue."""
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {
            "feature_templates": [
                {
                    "data": {
                        "ip": {
                            "address": {
                                "vipValue": "192.168.1.1/24",
                                "vipType": "constant",
                            }
                        },
                        "description": {
                            "vipValue": "Management interface",
                            "vipType": "constant",
                        },
                    }
                }
            ]
        }
        scanner.scan(data)
        assert (
            data["feature_templates"][0]["data"]["ip"]["address"]["vipValue"]
            != "192.168.1.1/24"
        )
        assert (
            data["feature_templates"][0]["data"]["description"]["vipValue"]
            == "Management interface"
        )

    def test_scan_records_mappings(self) -> None:
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {"ip": "10.1.1.1"}
        scanner.scan(data)
        assert "10.1.1.1" in scanner.mappings
        assert scanner.mappings["10.1.1.1"] == data["ip"]

    def test_scan_ipv6(self) -> None:
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {"device": {"ipv6": "2600:1f18:abcd::1"}}
        scanner.scan(data)
        assert data["device"]["ipv6"] != "2600:1f18:abcd::1"

    def test_scan_embedded_ip_in_url(self) -> None:
        """IPs embedded in URLs are replaced while preserving the URL structure."""
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {
            "links": {
                "self": "https://198.51.100.10:52283/api/fmc_config/v1/domain/abc/object/hosts/123"
            }
        }
        scanner.scan(data)
        url = data["links"]["self"]
        assert "198.51.100.10" not in url
        assert "/api/fmc_config/v1/domain/abc/object/hosts/123" in url
        assert url.startswith("https://")
        assert ":52283" in url

    def test_scan_embedded_ip_consistency(self) -> None:
        """Same IP in a standalone field and a URL receives the same sanitized value."""
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {
            "mgmt_ip": "198.51.100.10",
            "links": {"self": "https://198.51.100.10:443/api/v1/objects"},
        }
        scanner.scan(data)
        sanitized_ip = data["mgmt_ip"]
        assert f"https://{sanitized_ip}:443/api/v1/objects" == data["links"]["self"]

    def test_scan_embedded_ip_preserves_non_ip_strings(self) -> None:
        """Strings without IPs are not modified."""
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {
            "description": "This is a normal description without IPs",
            "path": "/api/v1/domain/abc-123/objects",
            "uuid": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
        }
        scanner.scan(data)
        assert data["description"] == "This is a normal description without IPs"
        assert data["path"] == "/api/v1/domain/abc-123/objects"
        assert data["uuid"] == "e276abec-e0f2-11e3-8169-6d9ed49b625f"

    def test_scan_embedded_ip_skips_excluded(self) -> None:
        """Excluded IPs (0.0.0.0, 255.255.255.255) in strings are not replaced."""
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {"msg": "default route via 0.0.0.0 is unreachable"}
        scanner.scan(data)
        assert data["msg"] == "default route via 0.0.0.0 is unreachable"

    def test_scan_embedded_multiple_ips_in_one_string(self) -> None:
        """Multiple IPs in a single string are each replaced."""
        allocator = IPAllocator()
        scanner = IPScanner(allocator)
        data = {"range": "from 10.1.1.1 to 10.1.1.254"}
        scanner.scan(data)
        assert "10.1.1.1" not in data["range"]
        assert "10.1.1.254" not in data["range"]
        assert "from " in data["range"]
        assert " to " in data["range"]
