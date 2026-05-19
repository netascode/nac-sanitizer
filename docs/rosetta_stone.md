# Rosetta Stone

The Rosetta Stone is the translation key generated during each sanitization run. It records the bidirectional mapping between original and sanitized values, enabling anyone with the key to translate in either direction.

## Purpose

When you share sanitized output with a third party, **you keep the Rosetta Stone**. During troubleshooting, you can look up any sanitized value to find what it originally was, or vice versa.

## Output Location

By default, the Rosetta Stone is written to the output directory with a timestamped filename:

```
output/nac-sanitizer-rosetta-2026-05-12T14-30-00.json
```

## File Structure

```json
{
  "metadata": {
    "created": "2026-05-12T14:30:00.123456+00:00",
    "tool_version": "0.1.0",
    "source_files": [
      "/path/to/sdwan.json"
    ],
    "total_mappings": 45
  },
  "mappings": {
    "CREDENTIALS": {
      "admin": "CREDENTIALS-001"
    },
    "SNMP_COMMUNITIES": {
      "pr1vat3Str!ng": "SNMP_COMMUNITIES-001"
    },
    "IP_ADDRESSES": {
      "10.50.1.1": "10.0.0.1",
      "10.50.1.2": "10.0.0.2",
      "192.168.1.0/24": "10.0.1.0/24"
    },
    "HOSTNAMES": {
      "core-rtr-01": "DEVICE-001"
    }
  }
}
```

## Security

The Rosetta Stone contains all original values in cleartext. It must be treated with the same security controls as the original data.

- File is created with restrictive permissions (0600 - owner read/write only)
- Never share the Rosetta Stone alongside sanitized output
- Store it securely for later reference and reverse lookups

## Using the Rosetta Stone

The Rosetta Stone is standard JSON. You can search it with any JSON tool:

```bash
# Find what an original IP was mapped to
jq '.mappings.IP_ADDRESSES["10.50.1.1"]' rosetta-stone.json

# Find all credential mappings
jq '.mappings.CREDENTIALS' rosetta-stone.json

# Reverse lookup - find original from sanitized value
jq '.mappings.IP_ADDRESSES | to_entries[] | select(.value == "10.0.0.1")' rosetta-stone.json
```

## Consistency Guarantees

Within a single sanitization run:

- The same original value always maps to the same sanitized value
- Two distinct original values never map to the same sanitized value
- Cross-file consistency is maintained when processing a directory of JSON files
