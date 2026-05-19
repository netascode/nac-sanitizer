# Configuration

nac-sanitizer uses a layered configuration system. Each layer can override values set by the layer below it.

## Configuration Hierarchy

From lowest to highest precedence:

1. **Built-in defaults** - Shipped with the tool
2. **Product profile** - Loaded from bundled profiles (e.g., `--profile sdwan`)
3. **Redaction packs** - Enabled/disabled via configuration
4. **User configuration file** - YAML file specified via `--config`
5. **CLI flags** - Direct argument overrides

## Configuration File Format

Configuration files use YAML. All fields are optional.

```yaml
# Which product profiles to activate
profiles:
  - sdwan
  - ise

# Enable or disable redaction packs
packs:
  enable:
    - snmp_communities
    - hostnames
    - serial_numbers
  disable:
    - location_data

# Override sensitivity tier for specific paths
overrides:
  - path: "$..site-name"
    tier: default
    strategy: token

  - path: "$..host-name"
    tier: skip

# Additional custom rules
custom_rules:
  - path: "$..custom_field"
    strategy: token
    category: "CUSTOM"

# Global settings
settings:
  ip_pools:
    ipv4_pools:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    ipv6_pools:
      - "2001:db8::/32"
      - "fc00::/7"
    preserve_prefix_length: true
  rosetta:
    format: json
    encrypt: false
```

## Sensitivity Tiers

| Tier       | Behavior                                                        |
| ---------- | --------------------------------------------------------------- |
| `default`  | Always redacted unless explicitly skipped by user               |
| `optional` | Not redacted unless user opts in (via pack enable or override)  |
| `skip`     | Never redacted (user override to preserve a default-tier field) |

## Redaction Packs

A redaction pack is a named bundle of JSONPath expressions grouped by a common sensitivity concern. Packs are defined within product profiles and can be toggled with a single line in your configuration.

Example: enabling the `hostnames` pack activates all hostname-related paths across the active profiles without needing to specify each path individually.

```yaml
packs:
  enable:
    - hostnames
    - serial_numbers
```

Packs classified as `default` are active unless explicitly disabled. Packs classified as `optional` are inactive unless explicitly enabled.

## Validating Configuration

Use the `validate-config` command to check a configuration file for errors:

```bash
nac-sanitizer validate-config my-config.yaml
```

## IP Pool Configuration

By default, sanitized IP addresses are drawn from a broad set of RFC 1918, RFC 5737, and RFC 6598 ranges. If your organization uses addresses within these ranges internally and you want to avoid any visual overlap between sanitized output and your real addressing, you can restrict the pools to a narrower set.

For example, to use only the RFC 5737 documentation ranges (which are never routable and unlikely to conflict with production networks):

```yaml
settings:
  ip_pools:
    ipv4_pools:
      - "192.0.2.0/24"
      - "198.51.100.0/24"
      - "203.0.113.0/24"
    ipv6_pools:
      - "2001:db8::/32"
```

Note that narrower pools have less address space available. The three RFC 5737 ranges provide 762 total host addresses across three /24 subnets. If your collector output contains more unique IPs than the pools can accommodate, the tool will report a pool exhaustion error.

For more detail on how IP sanitization works, see [IP Sanitization](ip_sanitization.md).

## Environment Variables

| Variable               | Description                                            |
| ---------------------- | ------------------------------------------------------ |
| `NAC_SANITIZER_CONFIG` | Path to configuration file (alternative to `--config`) |
