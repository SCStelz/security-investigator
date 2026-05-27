# Defender EASM — Asset Inventory & Risk Exploration

**Created:** 2026-05-27  
**Platform:** Microsoft Sentinel (Log Analytics — custom `_CL` tables ingested by the Defender EASM → Log Analytics data connection)  
**Tables:** `EasmAsset_CL`, `EasmAssetBanner_CL`, `EasmAssetWebComponent_CL`, `EasmContactAsset_CL`, `EasmDomainAsset_CL`, `EasmHostAsset_CL`, `EasmIpAddressAsset_CL`, `EasmPageAsset_CL`, `EasmRisk_CL`, `EasmSslCertAsset_CL`  
**Keywords:** EASM, external attack surface, attack surface management, asset inventory, web components, CVE exposure, SSL certificate, WHOIS, domain, port exposure, banner, security policy, CSP, HSTS, perimeter, internet-facing  
**MITRE:** T1595 (Active Scanning), T1592 (Gather Victim Host Information), T1590 (Gather Victim Network Information), T1589 (Gather Victim Identity Information)  
**Domains:** exposure, cloud  
**Timeframe:** Last 90 days (configurable)

---

## About this data

Microsoft Defender EASM continuously discovers internet-exposed assets attributed to your organization and exports periodic snapshots to Log Analytics via the [EASM data connection](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/inventory-via-azure-data-connections). The export cadence is configurable per data connection — **daily, weekly, or monthly** (see [Defender EASM Data Connections](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/data-connections#access-data-connections)). Each row carries the snapshot timestamp in `SnapshotDateTime_t` plus the asset's `AssetFirstSeen_t` / `AssetLastSeen_t` lifecycle dates. Because rows repeat per snapshot, **every query must deduplicate to the latest snapshot** (`arg_max(SnapshotDateTime_t, *) by AssetUuid_g`) or counts will multiply by the snapshot count in the lookback window.

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Asset inventory by type](#query-1-asset-inventory-by-type) | Posture | `EasmAsset_CL` |
| 2 | [Newly discovered assets (30/60/90d)](#query-2-newly-discovered-assets-306090d) | Investigation | `EasmAsset_CL` |
| 3 | [Snapshot cadence](#query-3-snapshot-cadence) | Investigation | `EasmAsset_CL` |
| 4 | [Risks by category and metric](#query-4-risks-by-category-and-metric) | Investigation | `EasmRisk_CL` |
| 5 | [Risks by asset type and severity](#query-5-risks-by-asset-type-and-severity) | Investigation | `EasmRisk_CL` |
| 6 | [Top affected assets](#query-6-top-affected-assets) | Triage | `EasmRisk_CL` |
| 7 | [Web components with known CVEs](#query-7-web-components-with-known-cves) | Investigation | `EasmAssetWebComponent_CL` |
| 8 | [Top web components by prevalence](#query-8-top-web-components-by-prevalence) | Triage | `EasmAssetWebComponent_CL` |
| 9 | [Critical CVE expansion (CVSS ≥ 9.0)](#query-9-critical-cve-expansion-cvss--90) | Investigation | `EasmAssetWebComponent_CL` |
| 10 | [SSL certificate expiry buckets](#query-10-ssl-certificate-expiry-buckets) | Investigation | `EasmSslCertAsset_CL` |
| 11 | [SSL issuers and signature algorithms](#query-11-ssl-issuers-and-signature-algorithms) | Investigation | `EasmSslCertAsset_CL` |
| 12 | [Domain WHOIS inventory](#query-12-domain-whois-inventory) | Posture | `EasmDomainAsset_CL` |
| 13 | [Host assets — ports, IPs, components](#query-13-host-assets--ports-ips-components) | Investigation | `EasmHostAsset_CL` |
| 14 | [IP addresses by ASN and location](#query-14-ip-addresses-by-asn-and-location) | Investigation | `EasmIpAddressAsset_CL` |
| 15 | [Open ports / banner exposure](#query-15-open-ports--banner-exposure) | Investigation | `EasmAssetBanner_CL` |
| 16 | [Page inventory and HTTP status](#query-16-page-inventory-and-http-status) | Posture | `EasmPageAsset_CL` |
| 17 | [Pages missing security headers](#query-17-pages-missing-security-headers) | Investigation | `EasmPageAsset_CL` |
| 18 | [Contact inventory](#query-18-contact-inventory) | Posture | `EasmContactAsset_CL` |
| 19 | [Asset state via Labels](#query-19-asset-state-via-labels) | Investigation | `EasmAsset_CL` |
| 20 | [Asset discovery timeline](#query-20-asset-discovery-timeline) | Investigation | `EasmAsset_CL` |


## Query 1: Asset inventory by type

Current confirmed asset count per type (latest snapshot only).

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory/posture query — not an alertable detection. Use for dashboards or scheduled reports, not Custom Detections.
-->

```kql
EasmAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| summarize Assets = count() by AssetType_s
| order by Assets desc
```

## Query 2: Newly discovered assets (30/60/90d)

Assets first observed by EASM within the trailing window — indicates organic attack surface growth.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory delta query for reporting. For an alertable "new asset discovered" detection, filter EasmAsset_CL where AssetFirstSeen_t > ago(1d) and emit per-row alerts.
-->

```kql
EasmAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| summarize
    Last30d = countif(AssetFirstSeen_t > ago(30d)),
    Last60d = countif(AssetFirstSeen_t > ago(60d)),
    Last90d = countif(AssetFirstSeen_t > ago(90d)),
    Total = count()
    by AssetType_s
| order by Total desc
```

## Query 3: Snapshot cadence

Confirm EASM is publishing on its configured schedule (daily / weekly / monthly) and that no snapshots are missing.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Operational health query for the EASM connector pipeline. Not a security detection.
-->

```kql
EasmAsset_CL
| where TimeGenerated > ago(90d)
| summarize Assets = dcount(AssetUuid_g) by SnapshotDate = bin(SnapshotDateTime_t, 1d)
| order by SnapshotDate asc
```

## Query 4: Risks by category and metric

EASM groups findings into `CategoryName_s` (e.g., `High Severity`, `Medium Severity`, `Low Severity`, `Asset Performance`, `CVSS3 Score`) and a specific `MetricDisplayName_s` (e.g., `[Potential] CVE-2024-53677 Apache Struts2...`).

<!-- cd-metadata
cd_ready: false
adaptation_notes: Posture summary. For an alertable detection, scope to CategoryName_s in ("High Severity", "Critical Severity") and emit per-asset alerts on first appearance.
-->

```kql
EasmRisk_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g, MetricDisplayName_s
| summarize AffectedAssets = dcount(AssetUuid_g) by CategoryName_s, MetricDisplayName_s
| order by CategoryName_s asc, AffectedAssets desc
```

## Query 5: Risks by asset type and severity

`CategoryName_s` is the authoritative severity field (NOT inferred from `MetricDisplayName_s`).

<!-- cd-metadata
cd_ready: false
adaptation_notes: Posture pivot. Same severity model as Query 4.
-->

```kql
EasmRisk_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g, MetricDisplayName_s
| extend Severity = case(
    CategoryName_s has "Critical", "Critical",
    CategoryName_s has "High", "High",
    CategoryName_s has "Medium", "Medium",
    CategoryName_s has "Low", "Low",
    CategoryName_s)
| summarize Risks = count(), Assets = dcount(AssetUuid_g) by AssetType_s, Severity
| order by Severity asc, Risks desc
```

## Query 6: Top affected assets

Assets carrying the most open EASM findings — prioritize these for remediation.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Aggregated top-N report. Not an alertable per-asset detection.
-->

```kql
EasmRisk_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g, MetricDisplayName_s
| summarize RiskCount = count(), Risks = make_set(MetricDisplayName_s), Categories = make_set(CategoryName_s) by AssetName_s, AssetType_s
| order by RiskCount desc
| take 25
```

## Query 7: Web components with known CVEs

Each row in `EasmAssetWebComponent_CL` represents a detected component on a given asset. `WebComponentCves_s` is a **JSON-string** array of `{Cve, Cwe, CvssScore, Cvss3Score}` objects — parse with `parse_json()` before expanding.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory CVE summary. For alerting on a NEW CVE appearance, filter WebComponentFirstSeen_t > ago(1d) and emit per (AssetUuid_g, WebComponentName_s, WebComponentVersion_s) alerts.
-->

```kql
EasmAssetWebComponent_CL
| where TimeGenerated > ago(90d)
| where isnotempty(WebComponentCves_s) and WebComponentCves_s != "[]"
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g, WebComponentName_s, WebComponentVersion_s
| extend Cves = parse_json(WebComponentCves_s)
| extend CveCount = array_length(Cves)
| summarize AffectedAssets = dcount(AssetUuid_g), TotalCves = sum(CveCount), Sample = any(WebComponentCves_s)
    by WebComponentCategory_s, WebComponentName_s, WebComponentVersion_s
| order by AffectedAssets desc, TotalCves desc
| take 25
```

## Query 8: Top web components by prevalence

Identifies your most-deployed external technology stack and which versions carry CVE flags.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory / posture roll-up.
-->

```kql
EasmAssetWebComponent_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g, WebComponentName_s, WebComponentVersion_s
| summarize
    Assets = dcount(AssetUuid_g),
    Versions = dcount(WebComponentVersion_s),
    HasCves = countif(isnotempty(WebComponentCves_s) and WebComponentCves_s != "[]")
    by WebComponentCategory_s, WebComponentName_s
| order by Assets desc
| take 25
```

## Query 9: Critical CVE expansion (CVSS ≥ 9.0)

Expands the CVE JSON to a per-CVE row, surfacing critical-severity issues across the external estate.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Detection-ready logic for "external asset has critical CVE-flagged component". To convert to a Custom Detection: change ago(90d) → ago(1d), keep the mv-expand, emit alert per (AssetName_s, Cve). Trigger frequency: 24h. Entity mapping: AssetName_s → IPAddress or Url depending on AssetType_s.
-->

```kql
EasmAssetWebComponent_CL
| where TimeGenerated > ago(90d)
| where isnotempty(WebComponentCves_s) and WebComponentCves_s != "[]"
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g, WebComponentName_s, WebComponentVersion_s
| mv-expand CveObj = parse_json(WebComponentCves_s)
| extend Cve = tostring(CveObj.Cve), Cvss3 = todouble(CveObj.Cvss3Score)
| where Cvss3 >= 9.0
| project AssetName_s, AssetType_s, WebComponentName_s, WebComponentVersion_s, Cve, Cvss3, Cwe = tostring(CveObj.Cwe)
| order by Cvss3 desc, AssetName_s asc
```

## Query 10: SSL certificate expiry buckets

Surfaces expired and soon-to-expire certificates, self-signed certs, and CA certificates on external endpoints.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Posture snapshot. For an alertable "cert expiring in <14d" detection, filter datetime_diff('day', InvalidAfter_t, now()) between (0..14) and emit per cert.
-->

```kql
EasmSslCertAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| extend DaysToExpiry = datetime_diff('day', InvalidAfter_t, now())
| summarize
    Total = count(),
    Expired = countif(DaysToExpiry < 0),
    ExpiringIn30d = countif(DaysToExpiry between (0 .. 30)),
    ExpiringIn90d = countif(DaysToExpiry between (0 .. 90)),
    SelfSigned = countif(IsSelfSigned_b == true),
    CertAuthorities = countif(IsCertificateAuthority_b == true)
```

## Query 11: SSL issuers and signature algorithms

Auditing cert issuance hygiene — flags weak algorithms (SHA-1) and unexpected issuers.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Compliance posture query. Not a security detection.
-->

```kql
EasmSslCertAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| extend Issuer = tostring(parse_json(IssuerOrganizations_s)[0])
| summarize Certs = count() by Issuer, SignatureAlgorithm_s
| order by Certs desc
```

## Query 12: Domain WHOIS inventory

WHOIS metadata per registered domain (registrar, expiry, registrant contacts) — useful for domain takeover monitoring.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory view. RegistrarExpiresAt_s contains epoch-ms strings inside a JSON array — parse with parse_json() and divide by 1000 for unixtime_seconds_todatetime().
-->

```kql
EasmDomainAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| extend
    Registrar = tostring(parse_json(RegistrarNames_s)[0]),
    ExpiresEpochMs = tolong(parse_json(RegistrarExpiresAt_s)[0]),
    Registrant = tostring(parse_json(RegistrantNamesLastSeen_s)[0])
| extend ExpiresAt = iff(ExpiresEpochMs > 0, unixtime_seconds_todatetime(ExpiresEpochMs / 1000), datetime(null))
| project Domain_s, Registrar, Registrant, ExpiresAt, AssetFirstSeen_t, AssetLastSeen_t
| order by Domain_s asc
```

## Query 13: Host assets — ports, IPs, components

Per-host fan-out — number of open ports, resolved IPs, and detected web components.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory query. The Ports_s array on this table may be empty even when banners exist — cross-reference with EasmAssetBanner_CL for accurate port exposure.
-->

```kql
EasmHostAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| extend
    Ports = array_length(parse_json(Ports_s)),
    IPs = array_length(parse_json(IpAddresses_s)),
    Components = array_length(parse_json(WebComponents_s)),
    SslCerts = array_length(parse_json(SslCerts_s))
| project Host_s, Domain_s, Ports, IPs, Components, SslCerts, AssetFirstSeen_t
| order by Components desc, IPs desc
```

## Query 14: IP addresses by ASN and location

Hosting providers and geographic distribution of external IPs.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Asns_s and Locations_s structures vary by EASM source; verify with `EasmIpAddressAsset_CL | take 1 | project Asns_s` before customizing. In sparse data sets parsed values may be empty.
-->

```kql
EasmIpAddressAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| extend
    AsnsArr = parse_json(Asns_s),
    LocationsArr = parse_json(Locations_s)
| extend
    AsnName = tostring(AsnsArr[0].name),
    AsnNumber = tostring(AsnsArr[0].value),
    Country = tostring(LocationsArr[0].country),
    City = tostring(LocationsArr[0].city)
| summarize IPs = dcount(IPAddress), Sample = make_set(IPAddress, 5) by AsnName, AsnNumber, Country
| order by IPs desc
```

## Query 15: Open ports / banner exposure

Confirmed open services with banner scan type (`http_raw`, `ehlo`, `rdp`, `telnet`, `xssh`, `udp`, etc.).

<!-- cd-metadata
cd_ready: false
adaptation_notes: Detection-ready logic for "new high-risk port detected externally". To alert: filter on Port_d in (22, 23, 445, 3389, 5985, 5986) and BannerFirstSeen_t > ago(1d). Entity: AssetName_s.
-->

```kql
EasmAssetBanner_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g, Port_d
| summarize Assets = dcount(AssetUuid_g), Sample = make_set(AssetName_s, 5)
    by Port = toint(Port_d), ScanType_s
| order by Assets desc, Port asc
```

## Query 16: Page inventory and HTTP status

`SiteStatus_s` (`ACTIVE`/`INACTIVE`) + first HTTP response code per discovered page.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory / health query.
-->

```kql
EasmPageAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| extend StatusCode = tostring(parse_json(HttpResponseCodes_s)[0])
| summarize Pages = count() by SiteStatus_s, StatusCode
| order by Pages desc
```

## Query 17: Pages missing security headers

Counts pages lacking common defensive HTTP response headers. `SecurityPolicies_s` is a JSON-string blob of observed headers.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Compliance posture query. Detection variant: filter to a single high-value site list and alert on regressions (current missing > prior snapshot missing).
-->

```kql
EasmPageAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| extend Policies = tolower(tostring(SecurityPolicies_s))
| summarize
    TotalPages = count(),
    MissingCSP = countif(Policies !contains "content-security-policy"),
    MissingHSTS = countif(Policies !contains "strict-transport-security"),
    MissingXFrame = countif(Policies !contains "x-frame-options"),
    MissingXCTO = countif(Policies !contains "x-content-type-options"),
    MissingReferrer = countif(Policies !contains "referrer-policy")
```

## Query 18: Contact inventory

Public WHOIS / registration contacts attributed to the org's assets — useful for phishing-target awareness.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory.
-->

```kql
EasmContactAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| extend Name = tostring(parse_json(Names_s)[0]), Org = tostring(parse_json(Organizations_s)[0])
| project Email_s, Name, Org, AssetFirstSeen_t, AssetLastSeen_t
| order by AssetFirstSeen_t desc
```

## Query 19: Asset state via Labels

`Labels_s` is a JSON-string array. Defender EASM uses labels (e.g., custom tags, `Approved Inventory`, business-unit markers) to scope assets — empty `[]` means no labels applied.

<!-- cd-metadata
cd_ready: false
adaptation_notes: Inventory hygiene query — surfaces tagging coverage gaps.
-->

```kql
EasmAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| summarize Assets = count() by Labels_s
| order by Assets desc
```

## Query 20: Asset discovery timeline

Histogram of `AssetFirstSeen_t` showing when EASM first attributed each asset (multi-year trail).

<!-- cd-metadata
cd_ready: false
adaptation_notes: Historical reporting. Bin width can be adjusted (1d / 7d / 30d).
-->

```kql
EasmAsset_CL
| where TimeGenerated > ago(90d)
| summarize arg_max(SnapshotDateTime_t, *) by AssetUuid_g
| summarize FirstSeen = count() by Year = bin(AssetFirstSeen_t, 365d)
| order by Year asc
```

---

## Known pitfalls

| Pitfall | Detail |
|---------|--------|
| **Snapshot duplication** | Every table emits one row per asset per snapshot. Cadence is configurable on the EASM [data connection](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/data-connections#access-data-connections) (daily / weekly / monthly). Always dedupe with `arg_max(SnapshotDateTime_t, *) by AssetUuid_g` before aggregating. |
| **Severity location** | Severity lives on `EasmRisk_CL.CategoryName_s` (`High Severity` / `Medium Severity` / `Low Severity`), NOT in `MetricDisplayName_s`. The metric name starts with `[Potential] CVE-...` or similar — inferring severity from it returns "Other" for every row. |
| **JSON-as-string columns** | `*_s` suffix columns containing arrays (`WebComponentCves_s`, `Ports_s`, `IpAddresses_s`, `Asns_s`, `Locations_s`, `SecurityPolicies_s`, `RegistrarNames_s`, etc.) are **strings**, not native dynamic. Use `parse_json()` before `mv-expand` / dot-access / `array_length`. |
| **WHOIS expiry encoding** | `RegistrarExpiresAt_s` is a JSON array of **epoch-millisecond strings**. Convert with `unixtime_seconds_todatetime(epochMs / 1000)`. |
| **Empty SSL table** | `EasmSslCertAsset_CL` exists but has no rows in this lab. EASM only populates it when discovered pages serve TLS certs — if all pages are `INACTIVE`, expect zero certs. |

---

## References

- [Defender EASM overview](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/)
- [EASM data connection (Log Analytics + Azure Data Explorer)](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/inventory-via-azure-data-connections)
- [Understanding asset details](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-asset-details)
- [Understanding inventory assets](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-inventory-assets)
