# nac-sanitizer

Sanitize sensitive values in [nac-collector](https://github.com/netascode/nac-collector) JSON output with reversible mappings.

## Overview

nac-sanitizer redacts sensitive data (passwords, IP addresses, SNMP community strings, hostnames, and more) from nac-collector JSON output. It produces sanitized JSON that is safe to share with third parties, alongside a Rosetta Stone translation key that enables bidirectional lookup between original and sanitized values.

## Key Features

- **Path-based redaction** - JSONPath expressions target specific fields in structured JSON data
- **Rosetta Stone** - Bidirectional translation key mapping original values to sanitized values and vice versa
- **Product profiles** - Built-in redaction rules for SD-WAN, Catalyst Center, and ISE
- **Redaction packs** - Named bundles of paths grouped by sensitivity concern (credentials, IP addresses, hostnames, etc.)
- **IP topology preservation** - Sanitized IP addresses maintain subnet relationships for logical readability
- **Configurable sensitivity tiers** - Default (always redacted), optional (user-electable), and skip (user override)

## Installation

```bash
pip install nac-sanitizer
```

## Usage

```bash
# Sanitize a single file
nac-sanitizer sanitize input.json -o sanitized/

# Sanitize with a product profile
nac-sanitizer sanitize input.json --profile sdwan -o sanitized/

# Sanitize with a user config
nac-sanitizer sanitize input.json --config my-config.yaml -o sanitized/

# Sanitize an entire collector output directory
nac-sanitizer sanitize ./collector-output/ -o sanitized/

# Show what would be redacted without writing files
nac-sanitizer sanitize input.json --dry-run

# Validate a configuration file
nac-sanitizer validate-config my-config.yaml

# List available profiles
nac-sanitizer profiles list
```

## Development

Requires Python 3.11+.

```bash
# Clone and install in development mode
git clone git@github.com:ChristopherJHart/nac-sanitizer.git
cd nac-sanitizer
uv sync --group dev

# Run checks
uv run ruff check .
uv run ty check
uv run bandit -r nac_sanitizer/
uv run pytest
```

## License

MPL-2.0
