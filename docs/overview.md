# How nac-sanitizer Works

nac-sanitizer takes JSON output from [nac-collector](https://github.com/netascode/nac-collector) and removes sensitive information so the data can be safely shared with third parties. It produces two outputs:

1. Sanitized JSON (structurally identical to the input, with sensitive values replaced)
2. A "Rosetta Stone" translation key that maps every original value to its sanitized counterpart.

The intent is for users to share the sanitized JSON with third parties while securely retaining the Rosetta Stone for future reference and reverse lookups.

## The Two Redaction Mechanisms

Under the hood, nac-sanitizer uses two complementary mechanisms to identify and redact sensitive data.

### Heuristic Pattern Scanning

The tool walks the entire JSON tree and examines every string value against known sensitive patterns using regular expressions. If a value matches a pattern, it is automatically redacted regardless of where it appears in the data structure or what key name it's stored under.

Currently, the only heuristic scanner targets **IP addresses and prefixes**. The scanner recognizes IPv4 and IPv6 addresses in any position - whether they appear in a device inventory field, buried inside a feature template, or nested within a policy object. This approach was chosen because network configurations store IP addresses in highly dynamic, unpredictable locations that cannot be reliably enumerated with static path expressions.

For more detail, see [IP Sanitization](ip_sanitization.md).

### Path-Based Redaction Rules

For sensitive data that is identified by its field name rather than its value pattern (passwords, SNMP community strings, hostnames, serial numbers), nac-sanitizer uses JSONPath expressions to target specific locations in the JSON structure. These paths are grouped into named **redaction packs** and bundled into **product profiles** that ship with the tool.

For example, the ISE profile knows that RADIUS shared secrets live at `$..radiusSharedSecret` and SNMP read communities live at `$..roCommunity`. When you activate the ISE profile, all paths in its default-tier packs are automatically applied.

Each redaction pack is assigned a **sensitivity tier** that controls whether it is active by default or requires explicit opt-in from the user:

- **`default`** - The pack is always active unless the user explicitly disables it. Used for data that is almost universally considered sensitive, such as passwords and RADIUS shared secrets.
- **`optional`** - The pack is inactive unless the user explicitly enables it. Used for data that may or may not be sensitive depending on context, such as hostnames, serial numbers, or site names. Some organizations consider these identifying details sensitive, while others do not.

This tiered approach gives users control over what gets redacted without requiring them to manually enumerate every path. They can simply enable or disable packs by name in their configuration file.

For more detail, see [Profiles](profiles.md) and [Configuration](configuration.md).

## Execution Flow

When you run `nac-sanitizer sanitize`, the following happens in order:

1. **Configuration assembly** - The tool loads your configuration file (if any), activates the requested profiles, enables/disables packs, and merges user overrides into a final rule set.
2. **File discovery** - The input path is scanned for JSON files. If it's a single file, just that file is processed. If it's a directory, all `.json` files are collected recursively.
3. **For each file:**
   - The heuristic scanner walks the JSON tree and redacts all IP-like values, recording each mapping.
   - Path-based rules are applied in order. Each rule's JSONPath expression locates matching values, and the appropriate redaction strategy transforms them.
4. **Output** - Sanitized JSON is written to the output directory, preserving the original file/directory structure. The Rosetta Stone is written alongside it.

All mappings are shared across files in a single run. If the same IP address appears in three different files, it receives the same sanitized value in all three, maintaining cross-file referential consistency.

## Redaction Strategies

When a sensitive value is identified (by either mechanism), it is transformed using one of several strategies:

| Strategy          | What it does                                                            | Used for                                          |
| ----------------- | ----------------------------------------------------------------------- | ------------------------------------------------- |
| `token`           | Replaces with a sequential identifier like `CREDENTIAL-001`             | Passwords, secrets, SNMP strings                  |
| `hostname_map`    | Replaces with `DEVICE-001`, `DEVICE-002`, etc.                          | Device hostnames                                  |
| `preserve_format` | Replaces characters while keeping delimiters and length                 | MAC addresses                                     |
| `constant`        | Replaces with a fixed string like `***REDACTED***`                      | Catch-all redaction                               |
| `hash`            | One-way SHA-256 hash (preserves equality checks)                        | Values where identity matters but content doesn't |
| IP allocator      | Maps to a new address from configured pools, preserving subnet topology | All IP addresses and prefixes                     |

For more on how strategies work, see the [Development](development.md) guide.

## What To Read Next

- [Configuration](configuration.md) - How to configure the tool, override defaults, and add custom rules
- [Profiles](profiles.md) - What each built-in profile covers and how to enable optional packs
- [Rosetta Stone](rosetta_stone.md) - How to use the translation key for lookups
- [IP Sanitization](ip_sanitization.md) - Details on the IP scanner, allocation pools, and topology preservation
