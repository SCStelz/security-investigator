# Key Vault & Storage Account Access Monitoring

**Created:** 2026-04-12  
**Platform:** Both  
**Tables:** AzureDiagnostics, StorageBlobLogs, ExposureGraphNodes, ExposureGraphEdges, SecurityAlert, SecurityIncident  
**Keywords:** Key Vault, Storage Account, secret access, credential theft, data exfiltration, lateral movement, service principal, managed identity, ExposureGraph, critical assets, MDC recommendations, permission sprawl  
**MITRE:** T1552.001, T1528, T1530, T1078.004, T1098.001, T1021.007, TA0006, TA0009, TA0003  
**Domains:** cloud, exposure  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This file covers **three investigation surfaces** for Azure Key Vault and Storage Account security:

| Section | Queries | Purpose |
|---------|---------|---------- |
| **Part A: Key Vault Data Plane** | Q1–Q6 | Secret/key/certificate access baseline, anomaly detection, sensitive write operations |
| **Part B: Storage Account Data Plane** | Q7–Q9 | Blob access patterns, auth failures, SAS token usage |
| **Part C: Exposure Graph — Critical Asset Correlation** | Q10–Q14 | Permission sprawl, MDC recommendations, critical asset access, identity-to-resource mapping |
| **Part D: SecurityAlert — MDC Incident Correlation** | Q15–Q15b | KV/Storage alerts from MDC & Defender XDR with incident join — covers vaults/storage WITHOUT diagnostic logging |

### ⚠️ Diagnostic Settings Coverage Gap — Critical

> **AzureDiagnostics only covers resources with diagnostic settings explicitly configured to ship logs to THIS Log Analytics workspace.** Vaults and storage accounts without diagnostic settings are **invisible** to Q1–Q10 — queries return 0 results even when activity occurred. This is the #1 false-negative risk in KV/Storage investigations.
>
> **MDC/Defender for Cloud alerts fire independently** — they operate at the subscription level via the Defender connector, NOT per-resource diagnostic settings. A vault can have ZERO diagnostic logs in AzureDiagnostics but still generate TOR access, anomalous operation, and secret exfiltration alerts in SecurityAlert (Q15/Q15b).
>
> **Always run Q15/Q15b alongside Q1–Q6** when investigating specific identities or incidents. If AzureDiagnostics returns 0 for a vault that appears in SecurityAlert, the vault's diagnostic settings are the gap — not the absence of activity.
>
> **To check coverage:** `AzureDiagnostics | where ResourceType == "VAULTS" | summarize Vaults = make_set(Resource, 50) by SubscriptionId` — any vault NOT in this list is a blind spot for Q1–Q10.

### ⚠️ Table Access Notes

| Table | AH (`RunAdvancedHuntingQuery`) | Data Lake (`query_lake`) | Azure MCP (`workspace_log_query`) | Notes |
|-------|------|-----------|-----------|-------|
| `AzureDiagnostics` | ✅ (30d) | ❌ Legacy — `SemanticError` | ✅ (90d+) | Use AH for ≤30d; Azure MCP `workspace_log_query` for >30d |
| `StorageBlobLogs` | ✅ (30d) | ✅ (90d+) | ✅ (90d+) | Resource-specific table — works in all three tools |
| `ExposureGraphNodes` | ✅ (snapshot) | ❌ | ❌ | AH-only; no timestamp filter needed |
| `ExposureGraphEdges` | ✅ (snapshot) | ❌ | ❌ | AH-only; no timestamp filter needed |

**Key Column Aliases (AzureDiagnostics — Key Vault):**

| Short Name | Actual Column | Description |
|-----------|---------------|-------------|
| `CallerAppId` | `identity_claim_appid_g` | Entra application (client) ID of caller |
| `CallerUPN` | `identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s` | User UPN (empty for SPN/MI) |
| `CallerObjectId` | `identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g` | Entra object ID |
| `CallerIPAddress` | `CallerIPAddress` | Source IP address |
| `VaultName` | `Resource` | Key Vault resource name (uppercase in AH) |
| `SecretURI` | `id_s` | Full URI including version (e.g., `https://vault.vault.azure.net/secrets/name/version`) |
| `RequestURI` | `requestUri_s` | Request URI without version |
| `ClientInfo` | `clientInfo_s` | User-agent/SDK info (e.g., Terraform, Azure CLI, Python SDK) |

---

## Quick Reference — Query Index

**Investigation shortcuts:**
- **KV/Storage access by compromised identity** (TP Q3, Q9, incident follow-up): **Q15b** (entity-scoped MDC/XDR alerts — catches vaults without diagnostic settings) → **Q1** (data plane baseline for vaults WITH diagnostics) → **Q3** (auth failures) → **Q10** (critical vault access)
- **Fleet-wide KV/Storage incident posture** (TP Q1, posture review): **Q15** (all KV/Storage incidents) → **Q13** (KV MDC recommendations) → **Q14** (Storage MDC recommendations) → **Q11** (permission sprawl)
- **Storage account compromise** (TP Q11, incident follow-up): **Q15b** (entity-scoped) → **Q7** (blob ops summary) → **Q8** (auth failures) → **Q9** (SAS/anonymous) → **Q14** (recommendations)
- **Key Vault secret exfiltration** (incident follow-up): **Q15b** (entity-scoped — TOR/anomaly alerts) → **Q1** (baseline — if diagnostics exist) → **Q2** (new caller detection) → **Q5** (volume anomaly)
- **Diagnostic coverage audit**: `AzureDiagnostics | where ResourceType == "VAULTS" | summarize make_set(Resource, 50) by SubscriptionId` — compare against Q15 `CompromisedEntity` to find unmonitored vaults

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Secret & Key Access Baseline — Per-Caller Per-Vault Summary](#query-1-secret--key-access-baseline--per-caller-per-vault-summary) | Dashboard | `AzureDiagnostics` |
| 2 | [New Caller Detection — First-Time Access to Vault](#query-2-new-caller-detection--first-time-access-to-vault) | Detection | `AzureDiagnostics` + `ClientInfo` |
| 3 | [Key Vault Authentication Failures](#query-3-key-vault-authentication-failures) | Investigation | `AzureDiagnostics` |
| 4 | [Sensitive Key Vault Write Operations](#query-4-sensitive-key-vault-write-operations) | Investigation | `AzureDiagnostics` |
| 5 | [Key Vault Access Volume Anomaly Detection](#query-5-key-vault-access-volume-anomaly-detection) | Dashboard | `AzureDiagnostics` + `DaysWithActivity` |
| 6 | [Key Vault Access — Hourly Heat Pattern](#query-6-key-vault-access--hourly-heat-pattern) | Investigation | `AzureDiagnostics` |
| 7 | [Storage Blob Operations Summary](#query-7-storage-blob-operations-summary) | Dashboard | `StorageBlobLogs` |
| 8 | [Storage Account Authorization Failures](#query-8-storage-account-authorization-failures) | Investigation | `StorageBlobLogs` |
| 9 | [Storage SAS Token and Anonymous Access Detection](#query-9-storage-sas-token-and-anonymous-access-detection) | Detection | `StorageBlobLogs` |
| 10 | [Key Vault Data Plane Access to Critical Vaults (ExposureGraph Join)](#query-10-key-vault-data-plane-access-to-critical-vaults-exposuregraph-join) | Investigation | `AzureDiagnostics` + `ExposureGraphNodes` |
| 11 | [Identity Permission Sprawl — KV + Storage Access Breadth](#query-11-identity-permission-sprawl--kv--storage-access-breadth) | Investigation | `ExposureGraphEdges` + `ExposureGraphNodes` |
| 12 | [Key Vault Broad Permission Holders (3+ Vaults)](#query-12-key-vault-broad-permission-holders-3-vaults) | Investigation | `ExposureGraphEdges` + `ExposureGraphNodes` |
| 13 | [Key Vault Security Recommendations (MDC via ExposureGraph)](#query-13-key-vault-security-recommendations-mdc-via-exposuregraph) | Investigation | `ExposureGraphEdges` + `ExposureGraphNodes` |
| 14 | [Storage Account Security Recommendations (MDC via ExposureGraph)](#query-14-storage-account-security-recommendations-mdc-via-exposuregraph) | Investigation | `ExposureGraphEdges` + `ExposureGraphNodes` |
| 15 | [KV & Storage — MDC/XDR Alerts with Incident Correlation (Fleet)](#query-15-kv--storage--mdcxdr-alerts-with-incident-correlation-fleet) | Detection | `AzureDiagnostics` + multi |
| 15 | [b: KV & Storage — Entity-Scoped Alert Drill-Down](#query-15b-kv--storage--entity-scoped-alert-drill-down) | Detection | `ClientInfo` + `SecurityAlert` |


## Part A: Key Vault Data Plane Monitoring

### Query 1: Secret & Key Access Baseline — Per-Caller Per-Vault Summary

**Purpose:** Establish a baseline of who/what accesses each vault, how often, from how many IPs, and which secrets they read. Use this to identify normal patterns before hunting anomalies.

**MITRE:** T1552.001 (Credentials In Files), T1528 (Steal Application Access Token) | **Tactic:** Credential Access

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline summary query. Returns aggregated access patterns per CallerAppId per Vault. Not alertable — use for establishing normal access patterns."
-->
```kql
// Key Vault Secret & Key Access Baseline
// Platform: AH (30d) or Azure MCP workspace_log_query (90d+)
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "KeyList", 
    "CertificateGet", "CertificateList")
| extend 
    CallerAppId = tostring(identity_claim_appid_g),
    CallerUPN = tostring(identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s),
    VaultName = Resource
| summarize 
    AccessCount = count(),
    DistinctSecrets = dcount(id_s),
    DistinctIPs = dcount(CallerIPAddress),
    IPs = make_set(CallerIPAddress, 5),
    Operations = make_set(OperationName, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by VaultName, CallerAppId, CallerUPN
| order by AccessCount desc
| take 50
```

**Output columns:** `VaultName`, `CallerAppId`, `CallerUPN` (empty for SPN/MI), `AccessCount`, `DistinctSecrets`, `DistinctIPs`, `IPs`, `Operations`, `FirstSeen`, `LastSeen`.

**What to look for:**
- **High `DistinctSecrets`:** Identity reading many different secrets — potential credential harvesting
- **High `DistinctIPs`:** Caller accessing vault from many sources — may indicate token reuse/theft
- **`CallerUPN` populated:** Human user accessing data plane directly (vs SPN/MI) — review if expected
- **Short-lived callers:** `FirstSeen` ≈ `LastSeen` with high `AccessCount` — burst access pattern

---

### Query 2: New Caller Detection — First-Time Access to Vault

**Purpose:** Identify application/service principals that accessed a Key Vault in the **last 1 day** but were NOT seen in the **prior 29 days**. New callers on production vaults are high-signal — they may indicate compromised credentials, rogue automation, or attacker lateral movement.

**MITRE:** T1078.004 (Cloud Accounts), T1552.001 (Credentials In Files) | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "New Key Vault Caller: {{CallerAppId}} first-time access to {{Resource}} ({{AccessCount}} ops)"
impactedAssets:
  - type: "other"
    identifier: "deviceName"
adaptation_notes: "Baseline-vs-recent anti-join pattern. Uses extended CallerAppId alias. Requires 30d data. Remove `order by` for CD."
-->
```kql
// New Key Vault Caller Detection (1d vs prior 29d baseline)
// Platform: AH (30d)
let BaselineCallers = AzureDiagnostics
| where TimeGenerated between (ago(30d) .. ago(1d))
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| extend CallerAppId = tostring(identity_claim_appid_g)
| distinct CallerAppId, Resource;
AzureDiagnostics
| where TimeGenerated > ago(1d)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| extend CallerAppId = tostring(identity_claim_appid_g)
| summarize 
    AccessCount = count(),
    Operations = make_set(OperationName, 5),
    IPs = make_set(CallerIPAddress, 5),
    Secrets = make_set(id_s, 5),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    ClientInfo = take_any(clientInfo_s)
    by CallerAppId, Resource
| join kind=leftanti BaselineCallers on CallerAppId, Resource
| order by AccessCount desc
```

**Tuning:**
- **Expand baseline:** Change `ago(30d)` to `ago(90d)` when using Azure MCP `workspace_log_query`
- **Reduce noise:** Exclude known deployment SPNs: `| where CallerAppId !in ("<TerraformSPNAppId>", "<ADOPipelineAppId>")`
- **Focus on critical vaults:** Add `| where Resource in~ ("<ProdVault1>", "<ProdVault2>")`

---

### Query 3: Key Vault Authentication Failures

**Purpose:** Detect failed data plane access attempts — 401/403 errors indicate unauthorized callers attempting to read secrets. May indicate credential stuffing, misconfigured SPNs, or an attacker probing with stolen tokens.

**MITRE:** T1552.001, T1078.004 | **Tactic:** Credential Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Key Vault Auth Failure: {{CallerAppId}} → {{Resource}} ({{FailedOps}} failures)"
impactedAssets:
  - type: "other"
    identifier: "deviceName"
adaptation_notes: "Filters ResultType != Success and excludes AzurePolicyEvaulation (always fails with 403 but is expected). Remove `order by` for CD."
-->
```kql
// Key Vault Authentication & Authorization Failures
// Platform: AH (30d) or Azure MCP (90d+)
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceType == "VAULTS"
| where ResultType != "Success"
| where OperationName != "AzurePolicyEvaulation"  // Expected policy check failures
| extend 
    CallerAppId = tostring(identity_claim_appid_g),
    CallerUPN = tostring(identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s),
    HttpStatus = toint(httpStatusCode_d)
| summarize 
    FailedOps = count(),
    Operations = make_set(OperationName, 5),
    StatusCodes = make_set(HttpStatus, 5),
    Results = make_set(ResultSignature, 3),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by Resource, CallerIPAddress, CallerAppId, CallerUPN
| order by FailedOps desc
| take 25
```

**Verdict guidance:**
- **401 (Unauthorized):** Authentication failure — invalid/expired token, wrong tenant
- **403 (Forbidden):** Valid identity but insufficient permissions — access policy or RBAC denial
- **429 (Throttled):** Rate limiting — may indicate brute-force enumeration
- **User UPN + 403 on prod vault:** Human attempting unauthorized secret access — investigate

---

### Query 4: Sensitive Key Vault Write Operations

**Purpose:** Surface all modification operations — secret creation/deletion, key management, access policy changes, vault configuration updates. These are rarely needed in production and should be tightly controlled.

**MITRE:** T1098.001 (Additional Cloud Credentials), T1485 (Data Destruction) | **Tactic:** Persistence, Impact

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Key Vault Write Op: {{OperationName}} on {{Resource}} by {{CallerAppId}}"
impactedAssets:
  - type: "other"
    identifier: "deviceName"
adaptation_notes: "Monitors all modification operations. High-fidelity — each row is a write event. Remove `order by` for CD."
-->
```kql
// Key Vault Sensitive Write Operations
// Platform: AH (30d) or Azure MCP (90d+)
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretSet", "SecretDelete", "SecretPurge", "SecretRestore",
    "KeyCreate", "KeyDelete", "KeyPurge", "KeyRestore", "KeyImport",
    "CertificateCreate", "CertificateDelete", "CertificateImport", "CertificatePurge",
    "VaultPatch", "VaultPut", "SetAccessPolicy", "RemoveAccessPolicy")
| extend 
    CallerAppId = tostring(identity_claim_appid_g),
    CallerUPN = tostring(identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s),
    CallerObjectId = tostring(identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g)
| project TimeGenerated, Resource, ResourceGroup, OperationName, CallerIPAddress,
    ResultType, toint(httpStatusCode_d), CallerAppId, CallerUPN, CallerObjectId,
    requestUri_s, clientInfo_s
| order by TimeGenerated desc
```

**High-priority operations:**
- `SecretSet` on production vaults — new credential injection
- `SecretDelete` / `SecretPurge` — credential destruction (ransomware, insider threat)
- `SetAccessPolicy` / `RemoveAccessPolicy` — permission escalation or denial-of-service
- `VaultPatch` — vault configuration changes (e.g., disabling soft delete, purge protection)
- `CertificateImport` — potential rogue certificate installation

---

### Query 5: Key Vault Access Volume Anomaly Detection

**Purpose:** Compute per-vault daily access volume statistics over 30 days and identify days where access exceeds the 3σ threshold. Detects credential harvesting bursts, runaway automation, or attacker bulk secret enumeration.

**MITRE:** T1552.001, T1530 | **Tactic:** Credential Access, Collection

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical anomaly detection using stdev. Returns per-vault baseline statistics with computed threshold. Use for baselining and manual anomaly review."
-->
```kql
// Key Vault Access Volume Anomaly — Daily Statistics with 3σ Threshold
// Platform: AH (30d) or Azure MCP (90d+)
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "KeyGet", "CertificateGet")
| summarize DailyAccess = count() by Resource, bin(TimeGenerated, 1d)
| summarize 
    AvgDaily = round(avg(DailyAccess), 1),
    StdDev = round(stdev(DailyAccess), 1),
    MaxDaily = max(DailyAccess),
    MinDaily = min(DailyAccess),
    DaysWithActivity = count()
    by Resource
| extend Threshold = round(AvgDaily + 3 * StdDev, 0)
| order by AvgDaily desc
```

**Companion detection query** — flag specific days above threshold:

```kql
// Key Vault Volume Anomaly — Flag Anomalous Days
let VaultBaselines = AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "KeyGet", "CertificateGet")
| summarize DailyAccess = count() by Resource, bin(TimeGenerated, 1d)
| summarize AvgDaily = avg(DailyAccess), StdDev = stdev(DailyAccess) by Resource
| extend Threshold = AvgDaily + 3 * StdDev;
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "KeyGet", "CertificateGet")
| summarize DailyAccess = count() by Resource, Day = bin(TimeGenerated, 1d)
| join kind=inner VaultBaselines on Resource
| where DailyAccess > Threshold
| project Day, Resource, DailyAccess, Threshold = round(Threshold, 0), 
    AvgDaily = round(AvgDaily, 0), Deviation = round((DailyAccess - AvgDaily) / StdDev, 1)
| order by Deviation desc
```

---

### Query 6: Key Vault Access — Hourly Heat Pattern

**Purpose:** Visualize when Key Vault access happens by hour-of-day and weekday/weekend. Useful for identifying off-hours access, timezone-mismatched callers, or detecting access from a different geography than expected.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Heatmap data generation query. Returns hourly access counts split by weekday/weekend. Partner with heatmap-visualization skill for rendering."
-->
```kql
// Key Vault Access — Hourly Pattern (Weekday vs Weekend)
// Platform: AH (30d)
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretList", "KeyGet")
| extend HourOfDay = hourofday(TimeGenerated), DayOfWeek = dayofweek(TimeGenerated) / 1d
| extend IsWeekend = DayOfWeek >= 5
| summarize 
    AccessCount = count(),
    DistinctCallers = dcount(identity_claim_appid_g),
    DistinctVaults = dcount(Resource)
    by bin(HourOfDay, 1), IsWeekend
| order by IsWeekend desc, HourOfDay asc
```

**What to look for:**
- **Weekend access from human UPNs:** Unexpected — investigate why users access KV outside business hours
- **Night-time spikes (0200–0500 UTC):** If not cron/automation, may indicate attacker activity
- **Flat 24/7 pattern:** Expected for managed identities / automation — baseline the volume

---

## Part B: Storage Account Data Plane Monitoring

### Query 7: Storage Blob Operations Summary

**Purpose:** Baseline all storage blob operations — read vs write vs delete, auth types (OAuth, SAS, Anonymous), and success/failure rates. Identifies anonymous access, SAS token usage, and auth failures.

**MITRE:** T1530 (Data from Cloud Storage Object), T1021.007 (Cloud Services) | **Tactic:** Collection, Lateral Movement

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline summary query. Aggregates all operations across storage accounts. Not alertable — use for establishing normal patterns."
-->
```kql
// Storage Blob Operations Summary
// Platform: AH (30d), Data Lake (90d+), or Azure MCP (90d+)
StorageBlobLogs
| where TimeGenerated > ago(30d)
| summarize 
    TotalOps = count(),
    DistinctAccounts = dcount(AccountName),
    DistinctCallers = dcount(RequesterObjectId),
    DistinctIPs = dcount(CallerIpAddress),
    AuthTypes = make_set(AuthenticationType, 5),
    FailedOps = countif(StatusCode !in ("200", "201", "202", "204", "206")),
    Categories = make_set(Category, 5)
    by OperationName
| extend FailureRate = round(100.0 * FailedOps / TotalOps, 1)
| order by TotalOps desc
```

**⚠️ Column name difference:** StorageBlobLogs uses `CallerIpAddress` (lowercase p), NOT `CallerIPAddress` (AzureDiagnostics pattern). Using the wrong casing returns `Failed to resolve scalar expression`.

**Key patterns:**
- **`AuthenticationType == "Anonymous"`:** Public blob access — verify if intentional (static website hosting) or misconfiguration
- **`AuthenticationType == "SAS"`:** Shared Access Signature usage — check `SasExpiryStatus` for overly long-lived tokens
- **High `FailureRate` on ListContainers/GetBlob:** Possible enumeration or misconfigured automation

---

### Query 8: Storage Account Authorization Failures

**Purpose:** Detect unauthorized access attempts (403 AuthorizationPermissionMismatch, 401 errors) to storage accounts. High volume from a single identity may indicate credential misuse or attacker probing.

**MITRE:** T1530, T1078.004 | **Tactic:** Collection, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Collection"
title: "Storage Auth Failure: {{RequesterAppId}} → {{AccountName}} ({{FailedOps}} ops, {{StatusText}})"
impactedAssets:
  - type: "other"
    identifier: "deviceName"
adaptation_notes: "Filters for non-2xx status codes. Remove `order by` for CD."
-->
```kql
// Storage Account Authorization Failures
// Platform: AH (30d) or Data Lake (90d+)
StorageBlobLogs
| where TimeGenerated > ago(30d)
| where StatusCode !in ("200", "201", "202", "204", "206")
| where StatusCode in ("401", "403", "404", "409")
| summarize 
    FailedOps = count(),
    Operations = make_set(OperationName, 5),
    StatusTexts = make_set(StatusText, 3),
    DistinctIPs = dcount(CallerIpAddress),
    IPs = make_set(CallerIpAddress, 5),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by AccountName, RequesterObjectId, RequesterAppId, StatusCode
| order by FailedOps desc
| take 25
```

---

### Query 9: Storage SAS Token and Anonymous Access Detection

**Purpose:** Identify storage operations using SAS tokens or anonymous (keyless) authentication — both are high-risk access methods that bypass Entra identity auditing. SAS tokens with long expiry or anonymous access to sensitive containers warrant investigation.

**MITRE:** T1528, T1530 | **Tactic:** Credential Access, Collection

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Storage Non-OAuth Access: {{AuthenticationType}} to {{AccountName}} ({{AccessCount}} ops)"
impactedAssets:
  - type: "other"
    identifier: "deviceName"
adaptation_notes: "Detects SAS and Anonymous auth types. Remove `order by` for CD."
-->
```kql
// Storage SAS Token and Anonymous Access
// Platform: AH (30d) or Data Lake (90d+)
StorageBlobLogs
| where TimeGenerated > ago(30d)
| where AuthenticationType in ("SAS", "Anonymous", "AnonymousPreflight")
| summarize 
    AccessCount = count(),
    DistinctIPs = dcount(CallerIpAddress),
    IPs = make_set(CallerIpAddress, 5),
    Operations = make_set(OperationName, 5),
    SampleObjects = make_set(ObjectKey, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AccountName, AuthenticationType
| order by AccessCount desc
```

**What to look for:**
- **`Anonymous` access to non-`$web` containers:** Likely misconfigured public access
- **`SAS` access from unexpected IPs:** Potential token leakage or sharing
- **`SAS` access to sensitive named containers** (e.g., `backups`, `exports`, `configs`): Data exfiltration risk

---

## Part C: Exposure Graph — Critical Asset Correlation

### Query 10: Key Vault Data Plane Access to Critical Vaults (ExposureGraph Join)

**Purpose:** Cross-references AzureDiagnostics data plane access logs with ExposureGraph critical asset classification. Surfaces who is accessing vaults that Exposure Management considers CriticalityLevel 0–3 (business-critical). Enables prioritization of data plane monitoring by asset criticality.

**MITRE:** T1552.001, T1528 | **Tactic:** Credential Access

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-source join between AzureDiagnostics (Analytics-tier, timestamped) and ExposureGraphNodes (AH-only, snapshot). Both require AH. Tolower() normalization needed — AzureDiagnostics stores Resource in UPPERCASE, ExposureGraph uses mixed case."
-->
```kql
// Key Vault Data Plane Access — Critical Vaults Only (ExposureGraph Join)
// Platform: AH only (both tables require Advanced Hunting)
let CriticalVaults = ExposureGraphNodes
| where NodeLabel =~ "microsoft.keyvault/vaults"
| extend rawData = parse_json(tostring(NodeProperties.rawData))
| extend critLevel = toint(rawData.criticalityLevel.criticalityLevel)
| where critLevel < 4
| project VaultName = tolower(NodeName), VaultCritLevel = critLevel;
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| extend VaultName = tolower(Resource)
| join kind=inner CriticalVaults on VaultName
| extend 
    CallerAppId = tostring(identity_claim_appid_g),
    CallerUPN = tostring(identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s)
| summarize 
    SecretAccessCount = count(),
    DistinctSecrets = dcount(id_s),
    DistinctIPs = dcount(CallerIPAddress),
    Operations = make_set(OperationName, 5),
    LastAccess = max(TimeGenerated)
    by VaultName, VaultCritLevel, CallerAppId, CallerUPN
| order by VaultCritLevel asc, SecretAccessCount desc
| take 30
```

**Join pitfall:** `AzureDiagnostics.Resource` is stored in **UPPERCASE** (e.g., `MYAPP-KV-PROD`), while `ExposureGraphNodes.NodeName` uses mixed/lowercase (e.g., `MyApp-kv-prod`). The `tolower()` on both sides is required for the join to match.

---

### Query 11: Identity Permission Sprawl — KV + Storage Access Breadth

**Purpose:** Identify identities (users, SPNs, managed identities) with permissions to **both** Key Vault and Storage Account resources, ranked by breadth. Identities with access to many vaults AND many storage accounts represent high blast-radius targets — compromising one identity grants broad secret + data access.

**MITRE:** T1078.004, T1552.001, T1530 | **Tactic:** Credential Access, Collection, Lateral Movement

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph-only query (AH). Uses multi-join pattern across edges and nodes. Snapshot data — no timestamp filter. High-value for posture assessment."
-->
```kql
// Identity Permission Sprawl — KV + Storage Access Breadth
// Platform: AH only (ExposureGraph tables)
let KVPermissions = ExposureGraphEdges
| where TargetNodeLabel =~ "microsoft.keyvault/vaults"
| where EdgeLabel == "has permissions to"
| distinct SourceNodeId;
let StoragePermissions = ExposureGraphEdges
| where TargetNodeLabel =~ "microsoft.storage/storageaccounts"
| where EdgeLabel == "has permissions to"
| distinct SourceNodeId;
KVPermissions
| join kind=inner StoragePermissions on SourceNodeId
| join kind=inner (
    ExposureGraphNodes 
    | where NodeLabel in~ ("user", "serviceprincipal", "managedidentity")
    | project SourceNodeId = NodeId, IdentityName = NodeName, IdentityType = NodeLabel
) on SourceNodeId
| join kind=leftouter (
    ExposureGraphEdges
    | where TargetNodeLabel =~ "microsoft.keyvault/vaults" and EdgeLabel == "has permissions to"
    | summarize KVCount = dcount(TargetNodeId) by SourceNodeId
) on SourceNodeId
| join kind=leftouter (
    ExposureGraphEdges
    | where TargetNodeLabel =~ "microsoft.storage/storageaccounts" and EdgeLabel == "has permissions to"
    | summarize StorageCount = dcount(TargetNodeId) by SourceNodeId
) on SourceNodeId
| project IdentityName, IdentityType, KVCount, StorageCount,
    TotalResources = KVCount + StorageCount
| order by TotalResources desc, KVCount desc
| take 25
```

**What to look for:**
- **Users with KVCount > 5 AND StorageCount > 10:** Over-provisioned — review RBAC assignments
- **Managed identities with broad access:** May be automation accounts with unnecessary cross-resource permissions
- **Service principals with both KV + Storage:** Validate if the application genuinely needs both secret access and data access

---

### Query 12: Key Vault Broad Permission Holders (3+ Vaults)

**Purpose:** Find identities with permissions to 3 or more Key Vaults, with critical vault count highlighted. Cross-reference with Q1 (data plane baseline) to identify identities with permissions that DON'T match their actual access — potential dormant over-provisioning.

**MITRE:** T1078.004 | **Tactic:** Persistence, Lateral Movement

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph-only query (AH). Identifies permission sprawl across vaults. Snapshot data."
-->
```kql
// Key Vault Permission Sprawl — Identities with 3+ Vault Access
// Platform: AH only (ExposureGraph tables)
ExposureGraphEdges
| where TargetNodeLabel =~ "microsoft.keyvault/vaults"
| where EdgeLabel == "has permissions to"
| join kind=inner (
    ExposureGraphNodes 
    | where NodeLabel in~ ("user", "serviceprincipal", "managedidentity", "group")
    | project SourceNodeId = NodeId, SourceName = NodeName, SourceType = NodeLabel
) on $left.SourceNodeId == $right.SourceNodeId
| join kind=inner (
    ExposureGraphNodes 
    | where NodeLabel =~ "microsoft.keyvault/vaults"
    | extend rawData = parse_json(tostring(NodeProperties.rawData))
    | extend critLevel = toint(rawData.criticalityLevel.criticalityLevel)
    | project TargetNodeId = NodeId, VaultName = NodeName, VaultCritLevel = critLevel
) on $left.TargetNodeId == $right.TargetNodeId
| summarize 
    VaultCount = dcount(VaultName),
    Vaults = make_set(VaultName, 10),
    CriticalVaults = dcountif(VaultName, VaultCritLevel < 4)
    by SourceName, SourceType
| where VaultCount >= 3
| order by CriticalVaults desc, VaultCount desc
| take 25
```

---

### Query 13: Key Vault Security Recommendations (MDC via ExposureGraph)

**Purpose:** Surface Microsoft Defender for Cloud security recommendations affecting Key Vaults — identifying misconfigured vaults (no firewall, no private link, no purge protection, no secret expiry, legacy access policies). Aggregated by recommendation type with affected vault list.

**MITRE:** TA0005 (Defense Evasion) | **Tactic:** Defense Evasion

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph-only query (AH). Joins recommendation nodes with vault nodes via 'affecting' edges. Snapshot data."
-->
```kql
// Key Vault MDC Security Recommendations
// Platform: AH only (ExposureGraph tables)
ExposureGraphEdges
| where TargetNodeLabel =~ "microsoft.keyvault/vaults"
| where EdgeLabel == "affecting"
| join kind=inner (
    ExposureGraphNodes 
    | where NodeLabel in~ ("mdcSecurityRecommendation", "mdcAuditingRecommendation")
    | project SourceNodeId = NodeId, RecommendationName = NodeName
) on $left.SourceNodeId == $right.SourceNodeId
| join kind=inner (
    ExposureGraphNodes 
    | where NodeLabel =~ "microsoft.keyvault/vaults"
    | project TargetNodeId = NodeId, VaultName = NodeName
) on $left.TargetNodeId == $right.TargetNodeId
| summarize 
    AffectedVaults = dcount(VaultName),
    Vaults = make_set(VaultName, 10)
    by RecommendationName
| order by AffectedVaults desc
```

**Priority recommendations by risk:**
- 🔴 **"Firewall should be enabled on Key Vault"** — vault accepts requests from any IP
- 🔴 **"Key vaults should have deletion protection enabled"** — vulnerable to ransomware/insider purge
- 🟠 **"Azure Key Vaults should use private link"** — data plane traffic traverses public internet
- 🟠 **"Role-Based Access Control should be used"** — still using legacy access policies instead of RBAC
- 🟡 **"Key Vault secrets should have an expiration date"** — long-lived secrets without rotation

---

### Query 14: Storage Account Security Recommendations (MDC via ExposureGraph)

**Purpose:** Same pattern as Q13 but for Storage Accounts — identifies storage misconfigurations like public network access, missing encryption, disabled logging.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph-only query (AH). Same pattern as Q13. Snapshot data."
-->
```kql
// Storage Account MDC Security Recommendations
// Platform: AH only (ExposureGraph tables)
ExposureGraphEdges
| where TargetNodeLabel =~ "microsoft.storage/storageaccounts"
| where EdgeLabel == "affecting"
| join kind=inner (
    ExposureGraphNodes 
    | where NodeLabel in~ ("mdcSecurityRecommendation", "mdcAuditingRecommendation")
    | project SourceNodeId = NodeId, RecommendationName = NodeName
) on $left.SourceNodeId == $right.SourceNodeId
| join kind=inner (
    ExposureGraphNodes 
    | where NodeLabel =~ "microsoft.storage/storageaccounts"
    | project TargetNodeId = NodeId, StorageAccount = NodeName
) on $left.TargetNodeId == $right.TargetNodeId
| summarize 
    AffectedAccounts = dcount(StorageAccount),
    Accounts = make_set(StorageAccount, 10)
    by RecommendationName
| order by AffectedAccounts desc
```

---

## Investigation Workflow

### Key Vault Secret Theft Investigation

When investigating potential Key Vault compromise:

1. **Scope the attack:** Run Q1 to establish who normally accesses the vault
2. **Detect anomalies:** Run Q2 for new callers, Q5 for volume anomalies
3. **Check failures:** Run Q3 for auth failures that preceded successful access
4. **Review modifications:** Run Q4 for write operations (access policy changes, secret set)
5. **Assess blast radius:** Run Q10 + Q12 for critical vault access and permission sprawl
6. **Enrich caller identity:** Resolve `CallerAppId` → application name via Graph API (`GET /v1.0/applications?$filter=appId eq '<CallerAppId>'`)

### Storage Account Data Exfiltration Investigation

When investigating potential data exfiltration via storage:

1. **Baseline activity:** Run Q7 for normal operation patterns
2. **Check auth failures:** Run Q8 for unauthorized access attempts
3. **Review SAS/Anonymous access:** Run Q9 for non-OAuth access patterns
4. **Assess exposure:** Run Q11 for identities with both KV + Storage access (credential + data)
5. **Review recommendations:** Run Q14 for storage misconfigurations

---

## Known Pitfalls

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| **AzureDiagnostics only covers vaults WITH diagnostic settings** | Vaults without diagnostic settings configured to this workspace return 0 results in Q1–Q6 — silent false-negative | Always run Q15/Q15b alongside Q1–Q6; MDC alerts (SecurityAlert) fire independently of diagnostic settings |
| **MDC KV alerts: `CallerUPN` is empty** | `ExtendedProperties["User Principal Name"]` is blank even for human callers on TOR/anomaly alerts | Filter by `Client Object ID` (ObjectId), NOT UPN. Resolve ObjectId→UPN via Graph if needed |
| **Defender XDR KV alerts: no `ExtendedProperties` detail** | "Suspicious activities related to Azure Key Vault by a risky user" has NO ops/target/IP in ExtendedProperties — it's a behavioral alert based on user risk state + Azure ARM activity | Pair with MDC alerts (Q15 joins both); MDC "Access from TOR exit node" has the operational detail |
| `AzureDiagnostics` not in Data Lake | Data Lake MCP returns `SemanticError` | Use `RunAdvancedHuntingQuery` (30d) or Azure MCP `workspace_log_query` (90d+) |
| `Resource` column is UPPERCASE in AzureDiagnostics | Joins with ExposureGraph fail silently (case mismatch) | Always `tolower()` both sides when joining |
| `identity_claim_appid_g` is application (client) ID, NOT object ID | Wrong Graph API lookups | Use `/applications?$filter=appId eq` NOT `/servicePrincipals/{id}` |
| `StorageBlobLogs.CallerIpAddress` (lowercase p) | Typo using `CallerIPAddress` returns `Failed to resolve scalar expression` | Copy column name exactly: `CallerIpAddress` |
| `StorageBlobLogs` only exists if diagnostic logging is configured per-storage-account | Missing accounts in results ≠ no access | Check diagnostic settings — not all storage accounts may be logging |
| ExposureGraph data is snapshot (no timestamp) | Can't trend permissions over time | Combine with `AuditLogs` role assignment events for historical context |
| `AzurePolicyEvaulation` always returns 403 | Inflates auth failure queries | Exclude with `where OperationName != "AzurePolicyEvaulation"` |

---

---

## Part D: SecurityAlert — MDC Incident Correlation

> **Why this section exists:** Parts A–B rely on `AzureDiagnostics` and `StorageBlobLogs`, which only contain data for resources with diagnostic settings configured to ship to this Log Analytics workspace. MDC (Microsoft Defender for Cloud) alerts fire at the **subscription level** via the Defender connector — independent of per-resource diagnostic settings. A Key Vault or Storage Account can have **zero diagnostic logs** in this workspace but still generate TOR access, anomalous operation, and malicious upload alerts in SecurityAlert. These queries close that gap.

### Query 15: KV & Storage — MDC/XDR Alerts with Incident Correlation (Fleet)

**Purpose:** Fleet-wide summary of all Key Vault and Storage Account SecurityAlerts with incident correlation. Surfaces TOR access, anomalous callers, malicious uploads, and behavioral risk alerts — including resources that have NO diagnostic logging configured. Use as a first-pass scan to identify KV/Storage incidents across all subscriptions connected to Sentinel.

**MITRE:** T1552.001 (Credentials In Files), T1530 (Data from Cloud Storage), T1078.004 (Cloud Accounts) | **Tactic:** Credential Access, Collection

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet-wide summary with incident join. Not suitable for CD — use for investigation/posture review."
-->
```kql
// Key Vault & Storage — SecurityAlert with Incident Correlation (Fleet)
// Platform: AH (30d)
// Covers MDC + Defender XDR alerts for KV/Storage data plane.
// ⚠️ This catches resources WITHOUT diagnostic logging — AzureDiagnostics queries miss these.
let KVStorageAlerts = SecurityAlert
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| where ProductComponentName in ("KeyVault", "StorageAccounts", "Storage")
    or AlertName has_any ("key vault", "storage account", "blob", "storage container")
| extend Props = parse_json(ExtendedProperties)
| extend
    CallerObjectId = tostring(Props["Client Object ID"]),
    CallerIP = tostring(Props["Client IP Address"]),
    Target = tostring(Props["Target"]),
    AllOps = tostring(Props["All vault operations in last 24 hours"]),
    SuspiciousOps = tostring(Props["Suspicious Operations"]),
    ResultSig = tostring(Props["Result Signature"]),
    ClientInfo = tostring(Props["Client Information"]),
    StartTimeUTC = tostring(Props["Start Time UTC"]),
    EndTimeUTC = tostring(Props["End Time UTC"]),
    AlertReasons = tostring(Props["Alert Reasons"])
| project SystemAlertId, TimeGenerated, AlertName, AlertSeverity, CompromisedEntity,
    ProductName, ProductComponentName, Tactics, Techniques,
    CallerObjectId, CallerIP, Target, AllOps, SuspiciousOps,
    ResultSig, ClientInfo, StartTimeUTC, EndTimeUTC, AlertReasons;
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where array_length(AlertIds) > 0
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=inner KVStorageAlerts on $left.AlertId == $right.SystemAlertId
| summarize
    AlertNames = make_set(AlertName, 5),
    AlertCount = dcount(SystemAlertId),
    Components = make_set(ProductComponentName, 3),
    Entities = make_set(CompromisedEntity, 5),
    CallerObjectIds = make_set(CallerObjectId, 3),
    CallerIPs = make_set(CallerIP, 5),
    Targets = make_set(Target, 3),
    AllOps = take_any(AllOps),
    AlertReasons = take_any(AlertReasons)
    by ProviderIncidentId, Title, Severity, Status, Classification, CreatedTime
| extend Entities = set_difference(Entities, dynamic([""]))
| extend CallerObjectIds = set_difference(CallerObjectIds, dynamic([""]))
| extend CallerIPs = set_difference(CallerIPs, dynamic([""]))
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId)
| order by CreatedTime desc
```

**Output columns:** `ProviderIncidentId` (linked via `PortalUrl`), `Title`, `Severity`, `Status`, `Classification`, `AlertNames`, `AlertCount`, `Components`, `Entities` (vault/storage names), `CallerObjectIds`, `CallerIPs`, `Targets` (full resource URI + secret path), `AllOps` (operation breakdown), `AlertReasons`.

**Alert type detail map:**

| Alert Source | Alert Name | ExtendedProperties Detail | Identity Field |
|---|---|---|---|
| MDC (Azure Security Center) | "Access from a TOR exit node to a key vault" | Rich: ops, target secret, IPs, client info, result, time window | `Client Object ID` (ObjectId — UPN is empty) |
| MDC (Azure Security Center) | "Malicious blob uploaded to storage account" | Minimal: entity name only | — |
| Defender XDR (M365D) | "Suspicious activities related to Azure Key Vault by a risky user" | Empty: behavioral alert based on user risk state + ARM activity | In `Entities` JSON blob |

**What to look for:**
- **TOR exit node alerts with `ResultSig: OK`:** Confirmed data plane access from anonymized source — secret exfiltration likely
- **Same `CallerObjectId` across multiple incidents:** Persistent compromise — attacker retains access across remediation cycles
- **Storage `Malicious blob uploaded` on critical assets:** Cross-reference `CompromisedEntity` with ExposureGraph criticality (Q10)
- **Incident status `Closed/Undetermined`:** May indicate unresolved threats auto-closed without classification

---

### Query 15b: KV & Storage — Entity-Scoped Alert Drill-Down

**Purpose:** Drill-down variant of Q15 scoped to a specific identity (ObjectId or UPN). Use during user/SPN investigations to find KV/Storage alerts that AzureDiagnostics queries missed due to absent diagnostic settings. Dual identity filter catches both MDC alerts (ObjectId in ExtendedProperties) and Defender XDR alerts (identity in Entities blob).

**MITRE:** T1552.001, T1530, T1078.004 | **Tactic:** Credential Access, Collection

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Entity-scoped investigation query. Requires ObjectId or UPN substitution. Not suitable for CD."
-->
```kql
// Key Vault & Storage — Entity-Scoped MDC/XDR Alert Drill-Down
// Platform: AH (30d)
// Substitute TargetObjectId AND/OR TargetUPN below.
// Dual filter catches MDC alerts (ObjectId in ExtendedProperties)
// AND Defender XDR behavioral alerts (identity in Entities JSON).
let TargetObjectId = "<ObjectId>";
let TargetUPN = "<UPN>";
let EntityAlerts = SecurityAlert
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| where ProductComponentName in ("KeyVault", "StorageAccounts", "Storage")
    or AlertName has_any ("key vault", "storage account", "blob", "storage container")
// Dual identity filter: ExtendedProperties (MDC) + Entities blob (XDR)
| where tostring(parse_json(ExtendedProperties)["Client Object ID"]) == TargetObjectId
    or Entities has TargetObjectId
    or Entities has TargetUPN
| extend Props = parse_json(ExtendedProperties)
| extend
    CallerObjectId = tostring(Props["Client Object ID"]),
    CallerIP = tostring(Props["Client IP Address"]),
    Target = tostring(Props["Target"]),
    AllOps = tostring(Props["All vault operations in last 24 hours"]),
    SuspiciousOps = tostring(Props["Suspicious Operations"]),
    ResultSig = tostring(Props["Result Signature"]),
    ClientInfo = tostring(Props["Client Information"]),
    StartTimeUTC = tostring(Props["Start Time UTC"]),
    EndTimeUTC = tostring(Props["End Time UTC"]),
    AlertReasons = tostring(Props["Alert Reasons"])
| project SystemAlertId, TimeGenerated, AlertName, AlertSeverity, CompromisedEntity,
    ProductName, ProductComponentName, Tactics, Techniques,
    CallerObjectId, CallerIP, Target, AllOps, SuspiciousOps,
    ResultSig, ClientInfo, StartTimeUTC, EndTimeUTC, AlertReasons;
// Join to SecurityIncident for status/classification
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where array_length(AlertIds) > 0
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=inner EntityAlerts on $left.AlertId == $right.SystemAlertId
| project
    ProviderIncidentId, IncidentTitle = Title, IncidentStatus = Status,
    Classification, CreatedTime,
    PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId),
    AlertName, AlertSeverity, CompromisedEntity, ProductComponentName,
    CallerObjectId, CallerIP, Target, AllOps, SuspiciousOps,
    ResultSig, ClientInfo, StartTimeUTC, EndTimeUTC, AlertReasons
| order by CreatedTime desc
```

**Entity substitution notes:**
- **From Threat Pulse Q3:** Use `AccountObjectId` from IdentityInfo results as `TargetObjectId`, `AccountUpn` as `TargetUPN`
- **From user-investigation:** ObjectId from Graph API `GET /v1.0/users/<UPN>?$select=id`
- **From incident-investigation:** Extract ObjectId from SecurityAlert Entities JSON: `parse_json(Entities) | mv-expand Entity | where Entity.Type == "account" | project tostring(Entity.AadUserId)`
- **For SPN/managed identity:** Use the ServicePrincipalId as `TargetObjectId`, leave `TargetUPN` as empty string `""`

**Why dual filter is required:**

| Alert Type | Where Identity Lives | `ExtendedProperties` filter catches? | `Entities has` catches? |
|---|---|---|---|
| MDC "TOR exit node to KV" | `ExtendedProperties["Client Object ID"]` | ✅ | ❌ (ObjectId not always in Entities) |
| XDR "Suspicious KV by risky user" | `Entities` JSON array → account entity | ❌ (ExtendedProperties empty) | ✅ |
| MDC "Malicious blob uploaded" | Neither (no caller identity) | ❌ | ❌ — filter by `CompromisedEntity` instead |

---

## Additional Resources

- [Azure Key Vault logging](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)
- [StorageBlobLogs schema](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference)
- [Exposure Management graph queries](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph)
- [MITRE T1552.001 — Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
