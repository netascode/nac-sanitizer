# IP Address Sanitization

IP addresses and prefixes receive special treatment. Rather than relying on JSONPath rules to target specific field names, nac-sanitizer uses a tree-walking scanner that identifies and redacts any value matching an IP/prefix pattern regardless of where it appears in the JSON structure.

## Why a Scanner Instead of Path Rules

Network device configurations store IP addresses in unpredictable locations. SD-WAN feature templates, for example, nest IPs inside generic `vipValue` fields mixed with non-IP values like interface names and descriptions. A path-based approach cannot reliably distinguish these without product-specific logic for every possible template type.

The scanner approach solves this by examining every string value in the data and determining whether it looks like an IP address or prefix.

## What Gets Detected

The scanner matches:

- IPv4 addresses: `10.1.1.1`
- IPv4 prefixes: `192.168.1.0/24`
- IPv6 addresses: `2001:db8::1`
- IPv6 prefixes: `2001:db8::/32`
- IPv4 addresses embedded in longer strings (e.g., URLs): `https://10.1.1.1:443/api/v1` → `https://10.0.0.1:443/api/v1`

When an IP is found within a longer string value, only the IP portion is replaced and the surrounding text is preserved. This handles cases like FMC API URLs where the management IP is embedded in endpoint references.

The scanner does **not** match:

- Hostnames: `core-rtr-01`
- MAC addresses: `00:50:56:9D:A8:63`
- Interface names: `GigabitEthernet0/0`
- IP ranges: `9.1.1.134-135`
- UUIDs: `ef66f799-2217-42a3-92a0-557d5424d5dd`

## Excluded Values

Certain well-known addresses are never redacted because they represent protocol constants rather than customer-specific data:

- `0.0.0.0` and `0.0.0.0/0` (default route)
- `255.255.255.255` and subnet masks (`255.255.255.0`, `255.255.0.0`, `255.0.0.0`)
- `::` and `::/0` (IPv6 equivalents)

## Allocation Pools

Sanitized IPs are allocated from configurable pools. Defaults:

**IPv4:**

| Range             | Purpose                |
| ----------------- | ---------------------- |
| `10.0.0.0/8`      | RFC 1918 private       |
| `172.16.0.0/12`   | RFC 1918 private       |
| `192.168.0.0/16`  | RFC 1918 private       |
| `192.0.2.0/24`    | RFC 5737 documentation |
| `198.51.100.0/24` | RFC 5737 documentation |
| `203.0.113.0/24`  | RFC 5737 documentation |
| `100.64.0.0/10`   | RFC 6598 CGNAT         |

**IPv6:**

| Range           | Purpose                |
| --------------- | ---------------------- |
| `2001:db8::/32` | RFC 3849 documentation |
| `fc00::/7`      | RFC 4193 ULA           |

The sanitized output will contain IP addresses drawn from the pools listed above. If your organization happens to use addresses within these same ranges internally, you may see sanitized values that coincidentally match real addresses in your environment. This does not mean your real addresses leaked into the output - it simply means the allocator chose an address from the pool that happens to overlap with something you use elsewhere.

The Rosetta Stone is the authoritative record of what each sanitized value corresponds to. If you see `10.0.0.5` in the sanitized output and your network also has a `10.0.0.5`, check the Rosetta Stone - it will tell you which original address was mapped to that value. The sanitized output has no relationship to your live network; the addresses are assigned sequentially from the pool and carry no meaning beyond being unique placeholders.

If this overlap is a concern, you can configure the tool to use a narrower set of pools that does not conflict with your internal addressing. See the [IP Pool Configuration](configuration.md#ip-pool-configuration) section for an example of restricting pools to only RFC 5737 documentation ranges.

## Subnet Topology Preservation

Hosts that share a subnet in the original data are placed within the same sanitized subnet. If `10.50.1.1`, `10.50.1.2`, and `10.50.1.254` all belong to `10.50.1.0/24`, their sanitized equivalents will also share a common `/24`.

This preserves the logical readability of the sanitized output - an engineer can still see which devices are on the same network segment.

## Prefix Length Preservation

By default, a `/24` maps to a `/24`, a `/16` to a `/16`, and so on. This is configurable via the `preserve_prefix_length` setting.

## Default Grouping

When a host address appears without an explicit prefix (e.g., `10.1.1.5` rather than `10.1.1.5/24`), the scanner infers a containing subnet using:

- `/24` for IPv4
- `/64` for IPv6

This ensures hosts with adjacent addresses are grouped correctly even when prefix information is not explicitly present in the data.

## Configuration

Override IP pool settings in your configuration file:

```yaml
settings:
  ip_pools:
    ipv4_pools:
      - "192.0.2.0/24"
      - "198.51.100.0/24"
      - "203.0.113.0/24"
    ipv6_pools:
      - "2001:db8::/32"
    preserve_prefix_length: true
```
