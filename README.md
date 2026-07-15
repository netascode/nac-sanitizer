[![Tests](https://github.com/netascode/nac-sanitizer/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/nac-sanitizer/actions/workflows/test.yml)
![Python Support](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-informational "Python Support: 3.11, 3.12, 3.13")

# nac-sanitizer

A CLI tool to sanitize sensitive values in [nac-collector](https://github.com/netascode/nac-collector) JSON output, producing redacted data safe to share alongside a Rosetta Stone translation key.

## Installation

```bash
uv tool install git+https://github.com/netascode/nac-sanitizer.git
```

Or with pip:

```bash
pip install git+https://github.com/netascode/nac-sanitizer.git
```

## Updating

```bash
uv tool install --reinstall git+https://github.com/netascode/nac-sanitizer.git
```

## Quick Start

```bash
# Sanitize with a product profile
nac-sanitizer sanitize collector-output.json --profile sdwan -o sanitized/

# Sanitize FMC collector output
nac-sanitizer sanitize fmc-backup.json --profile fmc -o sanitized/

# Sanitize an entire directory
nac-sanitizer sanitize ./collector-output/ --profile ise -o sanitized/

# Preview what would be redacted
nac-sanitizer sanitize collector-output.json --profile sdwan --dry-run -o sanitized/

# Write diagnostic logs to a file
nac-sanitizer --log-file sanitizer.log sanitize collector-output.json --profile sdwan -o sanitized/

# List available profiles
nac-sanitizer profiles list
```

## Documentation

See the [docs/](docs/) directory for detailed guides:

- [Overview](docs/overview.md) - How the tool works, the two redaction mechanisms, and execution flow
- [Configuration](docs/configuration.md) - Configuration file format, profiles, packs, and overrides
- [Profiles](docs/profiles.md) - Built-in product profiles and how they work
- [Rosetta Stone](docs/rosetta_stone.md) - The translation key and how to use it
- [IP Sanitization](docs/ip_sanitization.md) - How IP addresses and prefixes are handled
- [Development](docs/development.md) - Contributing, testing, and project structure

## License

MPL-2.0
