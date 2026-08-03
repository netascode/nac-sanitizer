# Product Profiles

Product profiles are built-in collections of redaction rules specific to a product's nac-collector output structure. They define which fields contain sensitive data and how to sanitize them.

## Available Profiles

- **`ise`** — Identity Services Engine (6 default packs, 25 optional packs)
- **`catalyst_center`** — Catalyst Center / DNA Center (3 default packs, 22 optional packs)
- **`sdwan`** — SD-WAN / vManage (4 default packs, 11 optional packs)
- **`fmc`** — Firewall Management Center (1 default pack, 4 optional packs)

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

Each profile defines redaction **packs** — groups of JSONPath expressions that target related sensitive fields. For example, the SD-WAN profile's `credentials` pack targets `$..vipPasskey`, while its `hostnames` pack targets `$..host-name`.

When a profile is activated:

1. All packs with `default` tier are automatically applied
2. Packs with `optional` tier are skipped unless explicitly enabled
3. The user can disable any pack (including default-tier) via configuration

## IP Address Handling

IP addresses are handled separately from profiles by a global [tree-walking scanner](ip_sanitization.md) that identifies and redacts IPs regardless of where they appear in the data. This means you do not need to specify IP-related paths in profiles — they are always caught.

---

## ISE Profile

### Default Tier (always applied)

- **credentials** — RADIUS shared secrets (`radiusSharedSecret`, `sharedSecret`, `previousSharedSecret`), passwords (`password`, `enablePassword`)
- **snmp_communities** — SNMP read/write community strings (`roCommunity`, `rwCommunity`)
- **device_trustsec_credentials** — TrustSec device deployment credentials (`enableModePassword`, `execModePassword`, `execModeUsername` inside `deviceConfigurationDeployment`)
- **personal_info** — AD advanced settings first/last name attributes (`advancedSettings.firstName`, `advancedSettings.lastName`)
- **user_personal_info** — Internal ISE user PII (`internal_user[*].data.name`, `.firstName`, `.lastName`, `.email`)
- **endpoint_custom_pii** — User email in endpoint custom attributes (`customAttributes.customAttributes.UserEmail`)

### Optional Tier (enable with `packs.enable`)

**Policy and Access Control:**

- **policy_names** — Allowed protocol configuration names (`allowed_protocols[*].data.name`, `allowed_protocols_tacacs[*].data.name`)
- **downloadable_acl_names** — Downloadable ACL names (`downloadable_acl[*].data.name`)
- **authorization_profiles** — Authorization profile names, descriptions, VLAN assignments, and advanced attribute values
- **device_admin_policy_names** — Device admin policy set names, condition names, and nested rule names (`$..rule.name`)
- **device_admin_condition_values** — Device admin condition matching criteria (`condition.attributeValue`, `.attributeName`, `.dictionaryName`, including nested `children`)
- **device_admin_authz_refs** — Device admin authorization rule profile and command set references
- **network_access_policy_names** — Network access policy set names, condition names, and dictionary names/descriptions
- **network_access_condition_values** — Network access condition matching criteria (same structure as device admin)
- **network_access_authz_refs** — Network access authorization profile references, security group assignments, and identity source names
- **network_access_api_links** — API URLs with embedded object names (`network_access_dictionary[*].data.link.href`)

**Identity and Directory:**

- **identity_sources** — Certificate authentication profile names and external identity store references (`externalIdentityStoreName`)
- **identity_source_sequences** — Identity source sequence names, descriptions, and referenced identity stores (`idSeqItem[*].idstore`)
- **active_directory_groups** — AD join point names and imported AD group names (`adgroups.groups[*].name`)
- **user_identity_groups** — User identity group names/descriptions and internal user descriptions

**Network Infrastructure:**

- **network_device_names** — Network device hostnames and CoA source hosts (uses `hostname_map` strategy for DEVICE-001 style output)
- **network_device_groups** — Device group hierarchy names and descriptions (e.g., `Location#All Locations#Building-A`)
- **repository_config** — Backup repository names and paths

**TrustSec and Segmentation:**

- **security_groups** — TrustSec SGT names/descriptions, SGACL names, and egress matrix cell names
- **sxp_config** — SXP virtual network names and domain filter values

**Endpoints:**

- **endpoint_identities** — Endpoint names and identity group names/descriptions (uses `preserve_format` strategy to maintain MAC address structure)

**TACACS Administration:**

- **tacacs_profiles** — TACACS+ shell profile names/descriptions, session attribute names/values, and command set names/descriptions

**Other:**

- **license_tier_names** — ISE license tier state names
- **usernames** — Username fields (`userName`)
- **mac_addresses** — MAC address fields (`mac`, uses `preserve_format`)
- **domains** — Domain fields (`domain`)

---

## Catalyst Center Profile

### Default Tier (always applied)

- **credential_descriptions** — Descriptions adjacent to CLI, SNMPv3, and NETCONF credentials (`cliCredential[*].description`, `snmpV3[*].description`, `netconfCredential[*].description`)
- **user_pii** — User email, first name, and last name (`users[*].email`, `.firstName`, `.lastName`)
- **template_content** — Configuration template bodies that may embed secrets (`templateContent`)

### Optional Tier (enable with `packs.enable`)

**Site and Location:**

- **site_names** — Area, building, and site names, name hierarchies, site hierarchies, and IP pool reservation group names
- **physical_addresses** — Street addresses and country values in area/building/site objects
- **domain_names** — DNS domain names and FQDNs (uses `preserve_format` to maintain dot structure)
- **location_data** — Site name hierarchies and group name hierarchies (`siteNameHierarchy`, `groupNameHierarchy`)

**Network Overlay:**

- **virtual_network_names** — Virtual network overlay names and associated L3 VN names (`virtualNetworkName`, `associatedLayer3VirtualNetworkName`)
- **vlan_names** — VLAN names and data VLAN names (`vlanName`, `dataVlanName`)
- **ip_pool_names** — IP pool names across anycast gateway, pools, reservations, and LAN automation (`ipPoolName`)
- **ip_pool_context** — IP pool reservation site context (group names, site hierarchies, pool names across `ip_pool`, `ip_pool_reservation`, `ip_pools`, `lan_automation`)
- **security_group_names** — TrustSec security group and scalable group names (`securityGroupName`, `scalableGroupNames[*]`)

**Devices:**

- **hostnames** — Device hostnames (`hostname`)
- **serial_numbers** — Device serial numbers (`serialNumber`)
- **mac_addresses** — MAC addresses (`macAddress`, `apEthernetMacAddress`, uses `preserve_format`)
- **device_names** — Device FQDNs in non-hostname fields like replacements and LAN automation (uses `hostname_map`)
- **device_descriptions** — Device descriptions and management address descriptions

**Fabric:**

- **interface_descriptions** — Port assignment interface descriptions (`interfaceDescription`)
- **fabric_descriptions** — Fabric authentication profile descriptions, virtual network descriptions, and scalable group name arrays
- **transit_network_names** — Transit/underlay network names
- **authentication_descriptions** — Authentication policy server descriptions, pre-auth ACL descriptions, and ISE DTO descriptions/FQDNs

**Templates:**

- **template_metadata** — Template/project names, descriptions, parameter descriptions, version notes, and tag names across `template`, `extended_templates`, `template_version`, and `project` objects
- **template_authors** — Template author fields and version info author fields (PII)
- **image_names** — Software image filenames

---

## SD-WAN Profile

The SD-WAN profile handles vManage collector output, which stores data in two forms:

- **Device inventory** — Plain string values (hostnames, system IPs, serial numbers)
- **Feature templates** — Values wrapped in `{"vipValue": "...", "vipType": "..."}` objects

The IP scanner handles both forms. Path-based packs target specific device inventory and template fields.

### Default Tier (always applied)

- **credentials** — Template passkeys (`vipPasskey`)
- **url_filter_patterns** — URL allow/block list patterns that may reveal internal domains (`allow_url_list_policy_object[*].data.entries[*].pattern`, `block_url_list_policy_object[*].data.entries[*].pattern`)
- **user_identity** — Audit trail fields across all objects (`owner`, `createdBy`, `lastUpdatedBy`)
- **organization_names** — Service provider and tenant organization names (`sp-org-name`, `tenant-org-name`)

### Optional Tier (enable with `packs.enable`)

**Templates and Profiles:**

- **template_names** — Template and profile names/descriptions (`templateName`, `templateDescription`, `profileName`)
- **cli_template_configs** — Full CLI configuration blobs (`templateConfiguration`, `templateConfigurationEdited`, `templateDefinition.config.vipValue`)
- **template_definition_values** — VPN names, descriptions, and ACL references inside template definitions (`templateDefinition.name.vipValue`, `.description.vipValue`, `pim.rp-addr.vipValue[*].access-list.vipValue`)
- **configuration_group_names** — Configuration group descriptions
- **policy_profile_descriptions** — Policy object feature profile and parcel descriptions

**Policies and Objects:**

- **policy_definition_names** — Custom control, traffic data, and zone-based firewall policy names/descriptions plus sequence names and zone list names
- **policy_object_names** — VPN list, site list, prefix list, preferred color group, and community list names plus their API endpoint URLs
- **vpn_service_names** — Parcel payload names, descriptions, and VPN reference values within feature profiles

**Device Inventory:**

- **hostnames** — Device hostnames (`host-name`, `csv-host-name`, `//system/host-name`)
- **serial_numbers** — Serial numbers and UUIDs (`board-serial`, `serialNumber`, `chasisNumber`, `uuid`)
- **location_data** — GPS coordinates and site identifiers (`latitude`, `longitude`, `site-name`, `site-id`, `//system/gps-location/latitude`, `//system/gps-location/longitude`)

---

## FMC Profile

FMC collector output is gathered via the FMC REST API. The exported data contains no plaintext credentials (the API does not expose them), so there is no credentials pack. The primary default-tier target is usernames embedded in object metadata.

FMC backups can be very large (1 GB+) because they include the full Snort intrusion rule database and MITRE ATT&CK group hierarchy. This content is system-defined (identical across all FMC deployments) and contains no customer-sensitive data beyond the management IP in URL fields.

The FMC management IP embedded in `links.self`, `links.parent`, and similar URL fields is handled automatically by the IP scanner's embedded-IP detection — the IP is replaced while the rest of the URL structure is preserved.

### Default Tier (always applied)

- **usernames** — User identity in object metadata (`metadata.lastUser.name`)

### Optional Tier (enable with `packs.enable`)

- **object_names** — Object names (`data.name`)
- **descriptions** — Object descriptions (`data.description`)
- **fqdns** — FQDN object values (`fqdn[*].data.value`, `fqdns[*].data.value`)
- **device_names** — Device names and hostnames (`device[*].data.name`, `device[*].data.hostName`)
