# Product Profiles

Product profiles are built-in collections of redaction rules specific to a product's nac-collector output structure. They define which fields contain sensitive data and how to sanitize them.

## Available Profiles

| Profile           | Product                  | Default Packs                      | Optional Packs                                                      |
| ----------------- | ------------------------ | ---------------------------------- | ------------------------------------------------------------------- |
| `sdwan`           | SD-WAN (vManage)         | credentials                        | hostnames, serial numbers, location data, VPN service names          |
| `ise`             | Identity Services Engine | credentials, SNMP communities, TrustSec device credentials | usernames, MAC addresses, domains, network device names, network device groups |
| `catalyst_center` | Catalyst Center (DNAC)   | (none - credentials masked by API) | usernames, hostnames, serial numbers, MAC addresses, location data, virtual network names, VLAN names, IP pool names, security group names, site names, physical addresses, domain names, IP pool context |
| `fmc`             | Firewall Management Center | usernames                        | object names, descriptions, FQDNs, device names                     |

List available profiles:

```bash
nac-sanitizer profiles list
```

## Using Profiles

Activate one or more profiles via CLI:

```bash
nac-sanitizer sanitize input.json --profile sdwan -o output/
nac-sanitizer sanitize input.json --profile ise --profile catalyst_center -o output/
```

Or in a configuration file:

```yaml
profiles:
  - sdwan
  - ise
```

## How Profiles Work

Each profile defines redaction **packs** - groups of JSONPath expressions that target related sensitive fields. For example, the SD-WAN profile's `credentials` pack targets `$..vipPasskey`, while its `hostnames` pack targets `$..host-name`.

When a profile is activated:

1. All packs with `default` tier are automatically applied
2. Packs with `optional` tier are skipped unless explicitly enabled
3. The user can disable any pack (including default-tier) via configuration

## IP Address Handling

IP addresses are handled separately from profiles by a global [tree-walking scanner](ip_sanitization.md) that identifies and redacts IPs regardless of where they appear in the data. This means you do not need to specify IP-related paths in profiles - they are always caught.

## SD-WAN Profile Details

The SD-WAN profile handles vManage collector output, which stores data in two forms:

- **Device inventory** - Plain string values (hostnames, system IPs, serial numbers)
- **Feature templates** - Values wrapped in `{"vipValue": "...", "vipType": "..."}` objects

The IP scanner handles both forms. Path-based packs target specific device inventory fields.

| Pack               | Tier     | Fields Targeted                                                                                                          |
| ------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| credentials        | default  | `vipPasskey`                                                                                                             |
| hostnames          | optional | `host-name`                                                                                                              |
| serial numbers     | optional | `board-serial`, `serialNumber`, `chasisNumber`, `uuid`                                                                   |
| location data      | optional | `latitude`, `longitude`, `site-name`, `site-id`                                                                          |
| VPN service names  | optional | `payload.name`, `payload.description`, `payload.data.name.value`, `payload.data.description.value`, `payload.data.entries[*].vpn.value` (feature profile parcel payloads) |

## ISE Profile Details

| Pack                          | Tier     | Fields Targeted                                              |
| ----------------------------- | -------- | ------------------------------------------------------------ |
| credentials                   | default  | `radiusSharedSecret`, `sharedSecret`, `previousSharedSecret`, `password`, `enablePassword` |
| SNMP communities              | default  | `roCommunity`, `rwCommunity`                                 |
| TrustSec device credentials   | default  | `deviceConfigurationDeployment.enableModePassword`, `deviceConfigurationDeployment.execModePassword`, `deviceConfigurationDeployment.execModeUsername` |
| usernames                     | optional | `userName`                                                   |
| MAC addresses                 | optional | `mac`                                                        |
| domains                       | optional | `domain`                                                     |
| network device names          | optional | `network_device[*].data.name`, `sgaNotificationAndUpdates.coaSourceHost` |
| network device groups         | optional | `network_device[*].data.NetworkDeviceGroupList[*]`, `network_device_group[*].data.name`, `network_device_group[*].data.description` |

The TrustSec device credentials pack redacts plaintext enable-mode and exec-mode credentials used to push TrustSec/SGA configuration to network devices (`trustsecsettings.deviceConfigurationDeployment`). Because these are plaintext service-account passwords, they are default tier like the other credential packs.

## Catalyst Center Profile Details

Catalyst Center's API masks credential values as `NO!$DATA!$`, so no credential redaction is needed.

| Pack             | Tier     | Fields Targeted                           |
| ---------------- | -------- | ----------------------------------------- |
| usernames        | optional | `username`                                |
| hostnames        | optional | `hostname`                                |
| serial numbers   | optional | `serialNumber`                            |
| MAC addresses    | optional | `macAddress`, `apEthernetMacAddress`      |
| location data    | optional | `siteNameHierarchy`, `groupNameHierarchy` |
| IP pool context  | optional | `ipPoolName`, `groupName`, `siteHierarchy` (in `ip_pool`, `ip_pool_reservation`, `ip_pools`, `lan_automation`) |

## FMC Profile Details

FMC collector output is gathered via the FMC REST API. The exported data contains no plaintext credentials (the API does not expose them), so there is no credentials pack. The primary default-tier target is usernames embedded in object metadata.

FMC backups can be very large (1 GB+) because they include the full Snort intrusion rule database and MITRE ATT&CK group hierarchy. This content is system-defined (identical across all FMC deployments) and contains no customer-sensitive data beyond the management IP in URL fields.

The FMC management IP embedded in `links.self`, `links.parent`, and similar URL fields is handled automatically by the IP scanner's embedded-IP detection — the IP is replaced while the rest of the URL structure is preserved.

| Pack             | Tier     | Fields Targeted                                                |
| ---------------- | -------- | -------------------------------------------------------------- |
| usernames        | default  | `metadata.lastUser.name`                                       |
| object names     | optional | `data.name`                                                    |
| descriptions     | optional | `data.description`                                             |
| FQDNs            | optional | `fqdn[*].data.value`, `fqdns[*].data.value`                   |
| device names     | optional | `device[*].data.name`, `device[*].data.hostName`               |
