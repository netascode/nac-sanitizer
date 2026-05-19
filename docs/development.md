# Development

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Setup

```bash
git clone git@github.com:netascode/nac-sanitizer.git
cd nac-sanitizer
uv sync --group dev
```

## Running Checks

```bash
# Lint and format
uv run ruff check .
uv run ruff format --check .

# Type checking
uv run ty check

# Security scan
uv run bandit -r nac_sanitizer/

# Tests
uv run pytest

# All pre-commit hooks
uv run pre-commit run --all-files
```

## Project Structure

```
nac_sanitizer/
├── cli/                 # Typer CLI layer
│   └── main.py
├── config/              # Configuration loading and models
│   ├── loader.py
│   └── models.py
├── engine/              # Core sanitization logic
│   ├── ip_allocator.py  # IP/prefix allocation with topology preservation
│   ├── ip_scanner.py    # Tree-walking IP pattern detection
│   ├── resolver.py      # JSONPath resolution
│   └── strategies.py    # Redaction strategy implementations
├── profiles/            # Profile discovery and loading
│   └── registry.py
├── resources/           # Bundled product profiles
│   └── profiles/
│       ├── sdwan.yaml
│       ├── ise.yaml
│       └── catalyst_center.yaml
├── rosetta/             # Rosetta Stone writer
│   └── writer.py
├── constants.py
└── sanitizer.py         # Orchestrator
```

## Architecture

The tool is composed of five layers:

1. **CLI** - Argument parsing, environment variable resolution, user-facing output
2. **Configuration** - YAML loading, layer merging, pydantic model validation
3. **Engine** - IP scanning, path resolution, strategy dispatch
4. **Rosetta** - Mapping accumulation and output generation
5. **Profiles** - Bundled product-specific path definitions and redaction packs

The orchestrator (`sanitizer.py`) wires these together:

1. Load configuration (file + CLI flags + profiles)
2. Build rule set from profiles + packs + overrides + custom rules
3. For each input file:
   - Run IP scanner (tree walk, redacts all IP-like values)
   - Apply path-based rules (credentials, hostnames, etc.)
4. Write sanitized output preserving directory structure
5. Write Rosetta Stone with all mappings

## Testing

Tests are organized into:

- `tests/unit/` - Individual module tests
- `tests/integration/` - CLI end-to-end tests via typer CliRunner
- `tests/fixtures/` - Test data files

Run a specific test file:

```bash
uv run pytest tests/unit/test_ip_scanner.py -v
```

## Adding a New Profile

1. Create `nac_sanitizer/resources/profiles/<product>.yaml`
2. Define packs with paths, strategies, and tiers
3. Validate paths against real collector output
4. Add tests in `tests/unit/test_profiles.py`

Profile YAML structure:

```yaml
name: product_name
description: "Description"
version: "1.0"

packs:
  pack_name:
    tier: default  # or optional
    strategy: token  # or hostname_map, constant, hash, preserve_format
    paths:
      - "$..field_name"
      - "$..nested.field"
```

## Adding a New Redaction Strategy

1. Implement the strategy class in `nac_sanitizer/engine/strategies.py`
2. Register it in `StrategyRegistry._register_defaults()`
3. Add tests in `tests/unit/test_strategies.py`

Strategy protocol:

```python
class MyStrategy:
    def redact(self, value: str, category: str | None = None) -> str:
        ...
```

## Related Tools

- [nac-collector](https://github.com/netascode/nac-collector) - Collects data from network infrastructure (produces the input for nac-sanitizer)
- [nac-validate](https://github.com/netascode/nac-validate) - Validates Network as Code YAML data models
- [nac-test](https://github.com/netascode/nac-test) - Tests Network as Code deployments
