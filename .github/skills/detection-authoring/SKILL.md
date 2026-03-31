---
name: detection-authoring
description: "Create, deploy, update, and manage custom detection rules in Microsoft Defender XDR via the Graph API (/beta/security/rules/detectionRules). Covers query adaptation from Sentinel KQL to custom detection format, deployment via PowerShell (Invoke-MgGraphRequest), manifest-driven batch deployment, and lifecycle management (list, enable/disable, delete). Companion script: Deploy-CustomDetections.ps1."
---

# Custom Detection Authoring — Instructions

## Purpose

This skill deploys **custom detection rules** to Microsoft Defender XDR via the Microsoft Graph API (`/beta/security/rules/detectionRules`). It handles:

- **Query adaptation** — Converting Sentinel KQL queries into custom detection format
- **Single-rule deployment** — Creating one rule via Graph API
- **Batch deployment** — Deploying multiple rules from a JSON manifest
- **Lifecycle management** — Listing, updating, enabling/disabling, and deleting rules
- **Validation** — Dry-run queries in Advanced Hunting before deployment

**Entity Type:** Custom detection rules (Defender XDR)

---

## 📑 TABLE OF CONTENTS

1. **[Prerequisites](#prerequisites)** — Auth, scopes, PowerShell modules
2. **[Critical Rules](#-critical-rules---read-first-)** — Mandatory constraints (includes query adaptation checklist)
3. **[API Reference](#api-reference)** — Graph API schema and field values
4. **[Frequency & Lookback](#frequency--lookback)** — Schedule periods, lookback windows, NRT constraints
5. **[Deployment Workflow](#deployment-workflow)** — Step-by-step process
6. **[Batch Deployment](#batch-deployment)** — Manifest-driven multi-rule deployment
7. **[Lifecycle Management](#lifecycle-management)** — CRUD operations
8. **[Existing Rule Discovery](#existing-rule-discovery)** — Search Analytic Rules & Custom Detections by table, EventID, or keyword
9. **[Known Pitfalls](#known-pitfalls)** — Lessons learned (13 pitfalls documented)
10. **[CD Metadata Contract](#cd-metadata-contract)** — Schema for query file ↔ detection skill coordination

---

## Prerequisites

### Required PowerShell Module

```powershell
# Microsoft.Graph.Authentication — provides Invoke-MgGraphRequest
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Required Graph API Scopes

| Operation | Scope | Type |
|-----------|-------|------|
| List / Get rules | `CustomDetection.Read.All` | Delegated |
| Create / Update / Delete | `CustomDetection.ReadWrite.All` | Delegated |

### Authentication

```powershell
# Read-only
Connect-MgGraph -Scopes "CustomDetection.Read.All" -NoWelcome

# Full CRUD
Connect-MgGraph -Scopes "CustomDetection.ReadWrite.All" -NoWelcome
```

> **Why `Invoke-MgGraphRequest`?** The Graph MCP server and `az rest` both return 403 for custom detection endpoints — they lack the `CustomDetection.*` scopes. `Invoke-MgGraphRequest` uses interactive delegated auth with consent, which works.

### Companion Script

[Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) — PowerShell script for manifest-driven batch deployment. See [Batch Deployment](#batch-deployment).

---

## ⚠️ CRITICAL RULES — READ FIRST ⚠️

### Mandatory Query Requirements

Custom detection queries have strict requirements that differ from Sentinel analytic rules:

| Requirement | Detail |
|-------------|--------|
| **Timestamp column must be projected as-is** | The query MUST project the timestamp column **exactly as it appears in the source table** — `TimeGenerated` for Sentinel/LA tables, `Timestamp` for XDR-native tables. Do not alias one to the other (e.g., `Timestamp = TimeGenerated` causes `400 Bad Request`). See [Pitfall 1](#pitfall-1-timestamp-vs-timegenerated). |
| **Event-unique columns (per table type)** | Required columns that uniquely identify the event differ by table family. A bare `summarize count()` or `make_set()` loses these columns and fails. `summarize` with `arg_max` IS allowed — see [Pitfall 3](#pitfall-3-summarize--allowed-only-with-row-level-output). See table below for per-type requirements. |
| **Impacted asset identifier column** | The query must project at least one column whose name matches a valid `impactedAssets` identifier (e.g., `AccountUpn`, `DeviceName`, `DeviceId`). See [Impacted Asset Types](#impacted-asset-types) and [Pitfall 9](#pitfall-9-impactedassets-identifier-must-be-a-predefined-api-value). Queries without `project` or `summarize` typically return these columns automatically. |
| **`impactedAssets` must be non-empty** | The `impactedAssets` array must contain **at least 1 element**. An empty array (`[]`) is rejected with `400 BadRequest`: *"The field ImpactedAssets must be a string or array type with a minimum length of '1'."* Every detection must declare which entity it impacts. See [Pitfall 13](#pitfall-13-impactedassets-must-be-non-empty). |
| **No `let` statements (NRT)** | **NRT rules (`schedule: "0"`) reject `let` entirely** — the API returns a generic `400 Bad Request`. This is **not documented by Microsoft** (empirically discovered Feb 2026) but consistently reproducible. Inline all dynamic arrays/lists directly in `where` clauses. Non-NRT rules (1H+) tolerate `let`. |
| **Unique `displayName` AND `title`** | Both the rule `displayName` and the alert `title` must be unique across all custom detections. Duplicate `displayName` returns `409 Conflict`. Duplicate `title` returns `400 Bad Request`. |
| **150 alerts per run** | Each rule generates a maximum of 150 alerts per execution. Tune the query to avoid alerting on normal day-to-day activity. |
| **🔴 No response actions** | All rules deployed by this skill MUST use `"responseActions": []`. Automated response actions (isolate device, disable user, block file, etc.) are **PROHIBITED** — they must only be configured manually by a human operator in the Defender portal after the rule is validated. Never populate `responseActions` in manifests or API calls. |
| **First run = 30-day backfill** | When a new rule is saved, it immediately runs against the past 30 days of data. Expect a burst of initial alerts if the query has broad coverage. |

**Required event-unique columns by table type** ([MS Learn source](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#required-columns-in-the-query-results)):

| Table Family | Required Columns (besides timestamp) |
|-------------|---------------------------------------|
| **MDE tables** (Device\*) | `DeviceId` AND `ReportId` |
| **Alert\* tables** | None (just timestamp) |
| **Observation\* tables** | `ObservationId` |
| **All other XDR tables** | `ReportId` |
| **Sentinel/LA tables** (AuditLogs, SigninLogs, SecurityEvent, OfficeActivity, etc.) | `ReportId` recommended (use proxy: `CorrelationId`, `OfficeObjectId`, `CallerProcessId`) but not strictly mandated by the docs |

### Query Adaptation Checklist

When converting a Sentinel query to custom detection format:

1. ✅ Remove bare `summarize` — project raw rows instead. Exception: `summarize` with `arg_max` is allowed for threshold-based detections (see [Pitfall 3](#pitfall-3-summarize--allowed-only-with-row-level-output))
2. ✅ Project the timestamp column as-is: `TimeGenerated = TimeGenerated` for Sentinel/LA tables, `Timestamp` for XDR tables. Never alias one to the other.
3. ✅ Project the **impacted asset identifier column** — the column name must match a valid identifier from [Impacted Asset Types](#impacted-asset-types). Examples: `DeviceName = Computer` for device-focused detections, `AccountUpn = UserId` for user-focused. See [Pitfall 9](#pitfall-9-impactedassets-identifier-must-be-a-predefined-api-value).
4. ✅ Project **event-unique columns** per table type — `DeviceId` + `ReportId` for MDE tables; `ReportId` for other XDR tables; recommended proxy `ReportId` for Sentinel tables (e.g., `ReportId = CorrelationId`). **Caveat:** proxy columns may contain empty strings for some events — acceptable but means those rows won't be individually identifiable in alert details.
5. ✅ Add a time filter as the first `where` clause — prefer `ingestion_time() > ago(1h)` over `Timestamp > ago(1h)` (see tip below). **NRT exception:** For NRT rules (`schedule: "0"`), omit the time filter entirely — events are processed as they stream in, and the platform pre-filters automatically.
6. ✅ Remove `let` variables for NRT rules — **NRT rejects `let` entirely** (generic 400 error, undocumented). Inline all dynamic arrays directly in `where` clauses. Non-NRT rules tolerate `let`.
7. ✅ Validate via Advanced Hunting dry-run before deployment
8. ✅ For NRT rules: avoid `tostring()` on dynamic columns — use native string columns instead (e.g., `Properties` instead of `tostring(Properties_d)`). See [Pitfall 11](#pitfall-11-tostring-on-dynamic-columns-rejected-in-nrt-mode).
9. ✅ For NRT rules: verify the table's ingestion lag justifies NRT. See [Pitfall 12](#pitfall-12-nrt-supported--nrt-practical--check-ingestion-lag).
10. ✅ Count unique `{{Column}}` references across `title` AND `description` combined — **max 3 unique columns total** (shared across both fields, not per-field). Exceeding this returns `400 Bad Request`: *"Dynamic properties in alertTitle and alertDescription must not exceed 3 fields"*. See [Pitfall 14](#pitfall-14-max-3-unique-dynamic-columns-across-title--description).

> **Performance tip (from MS Learn):** "Avoid filtering custom detections by using the `Timestamp` column. The data used for custom detections is prefiltered based on the detection frequency." Use `ingestion_time()` instead — it aligns with the platform's pre-filtering for better performance. For scheduled rules, match the time filter to the run frequency (`ingestion_time() > ago(1h)` for 1H rules). For NRT rules, no time filter is needed. **⚠️ PowerShell note:** When building `queryText` containing backslashes (file paths, regex), always use single-quoted here-strings (`@'...'@`) to avoid escape sequence mangling — see [Pitfall 15](#pitfall-15-powershell-double-quoted-here-strings-mangle-kql-backslashes).

### Example Adaptation

**Before (Sentinel KQL — uses summarize):**
```kql
let _Lookback = 7d;
SecurityEvent
| where TimeGenerated > ago(_Lookback)
| where EventID == 4799
| where TargetSid == "S-1-5-32-544"
| where SubjectUserSid != "S-1-5-18"
| where AccountType != "Machine"
| where not(SubjectUserSid endswith "-500")
| project TimeGenerated, Computer, Actor = SubjectUserName, ...
| summarize EnumerationCount = count(), Processes = make_set(CallerProcess)
    by Actor, ActorDomain, ActorSID
```

**After (Custom Detection — row-level, mandatory columns):**
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4799
| where TargetSid == "S-1-5-32-544"
| where SubjectUserSid != "S-1-5-18"
| where AccountType != "Machine"
| where not(SubjectUserSid endswith "-500")
| project
    TimeGenerated = TimeGenerated,
    DeviceName = Computer,
    AccountName = SubjectUserName,
    AccountDomain = SubjectDomainName,
    AccountSid = SubjectUserSid,
    CallerProcess = CallerProcessName,
    ReportId = CallerProcessId
```

**Key changes:**
- Removed `let _Lookback` → hardcoded `ago(1h)`
- Removed `summarize` → raw `project`
- Added `TimeGenerated = TimeGenerated` (identity projection — mandatory)
- Added `DeviceName = Computer` (impacted asset identifier — device-focused detection)
- Added `ReportId = CallerProcessId` (proxy ReportId — event-unique identifier)

---

## API Reference

### Endpoint

```
POST   /beta/security/rules/detectionRules          — Create
GET    /beta/security/rules/detectionRules           — List all
GET    /beta/security/rules/detectionRules/{id}      — Get by ID
PATCH  /beta/security/rules/detectionRules/{id}      — Update
DELETE /beta/security/rules/detectionRules/{id}      — Delete
```

### Schedule Periods

| Value | Meaning | Notes |
|-------|---------|-------|
| `"0"` | NRT (Near Real-Time / Continuous) | Runs continuously. See [NRT Constraints](#nrt-constraints). |
| `"1H"` | Every 1 hour | Most common for custom detections |
| `"3H"` | Every 3 hours | |
| `"12H"` | Every 12 hours | |
| `"24H"` | Every 24 hours | Daily |

### Alert Severity Values

| Value | Use Case |
|-------|----------|
| `"informational"` | Baseline queries, low-noise canaries |
| `"low"` | Suspicious but may be benign |
| `"medium"` | Likely malicious, needs investigation |
| `"high"` | High-confidence detection, immediate response |

### Alert Category Values

Valid MITRE ATT&CK tactic names (title case):

`InitialAccess`, `Execution`, `Persistence`, `PrivilegeEscalation`, `DefenseEvasion`, `CredentialAccess`, `Discovery`, `LateralMovement`, `Collection`, `Exfiltration`, `CommandAndControl`, `Impact`, `Reconnaissance`, `ResourceDevelopment`

### Impacted Asset Types

**Device asset:**
```json
{
    "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
    "identifier": "<identifier>"
}
```

Valid device identifiers: `deviceId`, `deviceName`, `remoteDeviceName`, `targetDeviceName`, `destinationDeviceName`

**User asset:**
```json
{
    "@odata.type": "#microsoft.graph.security.impactedUserAsset",
    "identifier": "<identifier>"
}
```

Valid user identifiers: `accountObjectId`, `accountSid`, `accountUpn`, `accountName`, `accountDomain`, `accountId`, `requestAccountSid`, `requestAccountName`, `requestAccountDomain`, `recipientObjectId`, `processAccountObjectId`, `initiatingAccountSid`, `initiatingProcessAccountUpn`, `initiatingAccountName`, `initiatingAccountDomain`, `servicePrincipalId`, `servicePrincipalName`, `targetAccountUpn`

**Mailbox asset:**
```json
{
    "@odata.type": "#microsoft.graph.security.impactedMailboxAsset",
    "identifier": "<identifier>"
}
```

Valid mailbox identifiers: `recipientEmailAddress`, `senderFromAddress`, `senderMailFromAddress`, `senderEmailAddress`, `senderObjectId`

### Minimal Valid POST Body

```json
{
    "displayName": "Rule Name",
    "isEnabled": true,
    "queryCondition": {
        "queryText": "SecurityEvent\r\n| where TimeGenerated > ago(1h)\r\n| ..."
    },
    "schedule": {
        "period": "1H"
    },
    "detectionAction": {
        "alertTemplate": {
            "title": "Alert Title",
            "description": "Alert description text.",
            "severity": "medium",
            "category": "Discovery",
            "recommendedActions": null,
            "mitreTechniques": ["T1069.001"],
            "impactedAssets": [
                {
                    "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                    "identifier": "deviceName"
                }
            ]
        },
        "responseActions": []
    }
}
```

> **`impactedAssets`**: **Must contain at least 1 element** — an empty array causes `400 BadRequest`. Every detection must map to at least one impacted entity (device, user, or mailbox). See [Pitfall 13](#pitfall-13-impactedassets-must-be-non-empty).

> **`recommendedActions`**: Can be `null` or a string. The portal sets it to `null` by default.

> **`responseActions`**: **Must always be `[]`** — response actions are prohibited in LLM-authored detections (see [Critical Rules](#-critical-rules---read-first-)). Must be `[]`, not `null` — sending `null` causes `400 Bad Request`. See [Pitfall 10](#pitfall-10-powershell-empty-array-swallowing--organizationalscope).

> **`organizationalScope`**: Omit this field entirely for tenant-wide rules (the API default). Including `"organizationalScope": null` explicitly may cause `400 Bad Request` in some API versions.

> **Custom details (not shown above):** The API also supports a `customDetails` array of key-value pairs surfaced in the alert side panel. Each rule supports up to 20 KVPs with a combined 4KB size limit. Keys are display labels; values are query column names. See [MS Learn](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#add-custom-details-preview).

> **Related evidence (not shown above):** Beyond `impactedAssets`, the entity mapping also supports linking **related evidence** entities (Process, File, Registry value, IP, OAuth application, DNS, Security group, URL, Mail cluster, Mail message). These provide correlation context but are not impacted assets. See [MS Learn](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#link-entities).

### Dynamic Alert Titles and Descriptions

Alert titles and descriptions can reference query result columns using `{{ColumnName}}` syntax, making alerts self-descriptive:

```json
{
    "title": "Admin Group Enumeration by {{AccountName}} on {{DeviceName}}",
    "description": "User {{AccountName}} enumerated group {{TargetGroupName}} on the device."
}
```

| Constraint | Limit |
|------------|-------|
| Max unique dynamic columns | **3 unique `{{Column}}` references TOTAL across `title` AND `description` combined** — NOT per field.  E.g., the example above uses `AccountName` + `DeviceName` in title and `AccountName` + `TargetGroupName` in description = 3 unique columns (AccountName is reused). Exceeding this returns `400 Bad Request` with "Dynamic properties in alertTitle and alertDescription must not exceed 3 fields". |
| | **⚠️ Discrepancy with MS Learn docs:** The [official documentation](https://learn.microsoft.com/defender-xdr/custom-detection-rules) states "The number of columns you can reference in each field is limited to three" (i.e., 3 per field). However, the Graph API empirically enforces **3 unique columns total** across both fields combined (confirmed Feb 2026). The portal UI may enforce the per-field limit differently than the API. Use 3 unique total as the safe limit for Graph API deployments. |
| Format | `{{ExactColumnName}}` — must match a column in query output |
| Markup | Plain text only — HTML, Markdown, and code are sanitized |
| URLs | Must use percent-encoding format |

---

## Frequency & Lookback

### Lookback Windows by Frequency

Each frequency has a built-in lookback window. Results outside this window are ignored even if the query requests them:

| Frequency | Lookback Period | Query Filter Recommendation |
|-----------|----------------|-----------------------------|
| NRT (Continuous) | Streaming | No time filter needed — events processed as collected |
| Every 1 hour | Past **4 hours** | `ago(4h)` or `ago(1h)` |
| Every 3 hours | Past **12 hours** | `ago(12h)` or `ago(3h)` |
| Every 12 hours | Past **48 hours** | `ago(48h)` or `ago(12h)` |
| Every 24 hours | Past **30 days** | `ago(30d)` or `ago(24h)` |
| Custom (Sentinel only) | 4× frequency (<daily) or 30d (≥daily) | Match lookback |

> **Tip:** Match the query time filter to the run frequency (`ago(1h)` for 1H rules), not the full lookback window. The lookback ensures late-arriving data is caught, but your filter should target the detection window.

### NRT Constraints

NRT (Continuous, `period: "0"`) rules have stricter requirements than scheduled rules:

| Constraint | Detail |
|------------|--------|
| **Single table only** | Query must reference exactly one table — no joins or unions |
| **No `let` statements** | `let` variables are silently rejected — the API returns a generic `400 Bad Request` with no useful error message. **Always inline dynamic arrays/lists directly in `where` clauses.** This constraint is **not listed in the [official NRT docs](https://learn.microsoft.com/defender-xdr/custom-detection-rules#queries-you-can-run-continuously)** (which list only 4 constraints) but is consistently reproducible via Graph API (empirically confirmed Feb 2026). |
| **No `externaldata`** | Cannot use the `externaldata` operator |
| **No comments** | Query text must not contain any comment lines (`//`) |
| **Supported operators only** | Limited to [supported KQL features](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-transformations-structure#supported-kql-features). **`tostring()` on dynamic columns is rejected** — use native string columns instead (e.g., `Properties` instead of `tostring(Properties_d)`). See [Pitfall 11](#pitfall-11-tostring-on-dynamic-columns-rejected-in-nrt-mode). |
| **No time filter needed** | NRT processes events as they stream in. The platform pre-filters automatically. Adding a time filter (e.g., `TimeGenerated > ago(1h)`) is unnecessary but harmless. |

### NRT-Supported Tables

Not all tables support NRT frequency. Use NRT only with these tables:

**Defender XDR tables:**
`AlertEvidence`, `CloudAppEvents`, `DeviceEvents`, `DeviceFileCertificateInfo`, `DeviceFileEvents`, `DeviceImageLoadEvents`, `DeviceLogonEvents`, `DeviceNetworkEvents`, `DeviceNetworkInfo`, `DeviceInfo`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `EmailAttachmentInfo`, `EmailEvents`\*, `EmailPostDeliveryEvents`, `EmailUrlInfo`, `IdentityDirectoryEvents`, `IdentityLogonEvents`, `IdentityQueryEvents`, `UrlClickEvents`

\* `EmailEvents`: `LatestDeliveryLocation` and `LatestDeliveryAction` columns are excluded from NRT.

**Sentinel tables (Preview):**
`ABAPAuditLog_CL`, `AuditLogs`, `AWSCloudTrail`, `AWSGuardDuty`, `AzureActivity`, `Cisco_Umbrella_dns_CL`, `Cisco_Umbrella_proxy_CL`, `CommonSecurityLog`, `GCPAuditLogs`, `MicrosoftGraphActivityLogs`, `OfficeActivity`, `Okta_CL`, `OktaV2_CL`, `ProofpointPOD`, `ProofPointTAPClicksPermitted_CL`, `ProofPointTAPMessagesDelivered_CL`, `SecurityAlert`, `SecurityEvent`, `SigninLogs`

> **Important:** `SecurityEvent` and `SigninLogs` support NRT — our Event ID 4799/4702 queries can run as NRT if they meet the single-table/no-joins constraint.

### Ingestion Lag Consideration — NRT Suitability

A table being NRT-supported means the API **accepts** NRT rules — not that NRT is the right choice. If a table's ingestion lag exceeds the detection frequency benefit, NRT adds overhead with no detection speed improvement. See [Pitfall 12](#pitfall-12-nrt-supported--nrt-practical--check-ingestion-lag) for a per-table ingestion lag assessment and recommendation matrix. **Rule of thumb: if ingestion lag > 30 min, use 1H scheduled instead.**

### Custom Frequency (Sentinel Data Only)

For rules based entirely on Sentinel-ingested data, a custom frequency is available (Preview):
- **Range:** 5 minutes to 14 days
- **Lookback:** Automatically calculated — 4× frequency for sub-daily, 30 days for daily or longer
- **Requirement:** Data must be available in Microsoft Sentinel (not XDR-only tables)

---

## Deployment Workflow

### Single Rule Deployment

**Step 1: Validate the query in Advanced Hunting**

Run the adapted query with a 1h lookback to validate schema:

```
Use RunAdvancedHuntingQuery with the adapted KQL query.
Confirm: 0 or more results, correct column schema (TimeGenerated, DeviceName, AccountName, etc.)
```

Then run with 30d lookback to confirm it returns real data:

```
Change ago(1h) to ago(30d) for the validation run.
Verify results contain expected columns and realistic data.
```

**Step 2: Check for duplicates, then build and POST the rule**

```powershell
Connect-MgGraph -Scopes "CustomDetection.ReadWrite.All" -NoWelcome

# Pre-flight: check if rule name already exists
$ruleName = "Rule Name"
$existing = (Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/security/rules/detectionRules" -OutputType PSObject).value `
    | Where-Object { $_.displayName -eq $ruleName }
if ($existing) {
    Write-Host "Rule '$ruleName' already exists (ID: $($existing.id)). Skipping POST."
    return
}

$body = @{
    displayName = $ruleName
    isEnabled = $true
    queryCondition = @{
        queryText = "SecurityEvent`r`n| where TimeGenerated > ago(1h)`r`n| ..."
    }
    schedule = @{ period = "1H" }
    detectionAction = @{
        alertTemplate = @{
            title = "Alert Title"
            description = "Description"
            severity = "medium"
            category = "Discovery"
            recommendedActions = $null
            mitreTechniques = @("T1069.001")
            impactedAssets = @(
                @{
                    "@odata.type" = "#microsoft.graph.security.impactedDeviceAsset"
                    identifier = "deviceName"
                }
            )
        }
        responseActions = @()
    }
} | ConvertTo-Json -Depth 10

$result = Invoke-MgGraphRequest -Method POST `
    -Uri "/beta/security/rules/detectionRules" `
    -Body $body -ContentType "application/json" -OutputType PSObject
```

**Step 3: Verify creation**

```powershell
$rules = Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/security/rules/detectionRules" -OutputType PSObject
$rules.value | Select-Object id, displayName, isEnabled,
    @{N='Schedule';E={$_.schedule.period}},
    @{N='Status';E={$_.lastRunDetails.status}} | Format-Table -AutoSize
```

---

## Batch Deployment

Use the companion script [Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) for manifest-driven batch deployment.

> **Manifest storage:** Save manifest JSON files in the `temp/` folder (gitignored). Manifests are deployment artifacts, not versioned query definitions.

### Manifest Format

See [example-manifest.json](example-manifest.json) for a complete 2-rule reference covering NRT and scheduled (with `summarize`/`arg_max`) patterns.

The script reads a JSON file containing an array of rule definitions:

```json
[
    {
        "displayName": "Admin Group Enumeration by Non-Admin User",
        "title": "Admin Group Enumeration by {{AccountName}} on {{DeviceName}}",
        "queryText": "SecurityEvent\r\n| where TimeGenerated > ago(1h)\r\n| ...",
        "schedule": "0",
        "severity": "medium",
        "category": "Discovery",
        "mitreTechniques": ["T1069.001", "T1087.001"],
        "description": "User {{AccountName}} enumerated the local Administrators group.",
        "recommendedActions": "Verify whether the user has a legitimate reason to enumerate admin group membership.",
        "impactedAssets": [
            { "type": "device", "identifier": "deviceName" },
            { "type": "user", "identifier": "accountSid" }
        ],
        "responseActions": []
    }
]
```

### Usage

```powershell
# Dry-run — validate all queries in Advanced Hunting without creating rules
.\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json -DryRun

# Deploy all rules from manifest (skips existing rules by default)
.\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json

# Deploy and overwrite — attempt POST even if rule name exists (may cause 409)
.\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json -Force
```

---

## Lifecycle Management

### List All Rules

```powershell
$rules = Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/security/rules/detectionRules" -OutputType PSObject
$rules.value | Select-Object id, displayName, isEnabled,
    @{N='Schedule';E={$_.schedule.period}},
    @{N='LastRun';E={$_.lastRunDetails.status}},
    @{N='Created';E={$_.createdDateTime}} | Format-Table -AutoSize
```

### Get Rule by ID

```powershell
$rule = Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/security/rules/detectionRules/5632" -OutputType PSObject
$rule | ConvertTo-Json -Depth 10
```

### Update Rule (PATCH)

```powershell
$update = @{
    isEnabled = $false
    schedule = @{ period = "24H" }
} | ConvertTo-Json -Depth 10

Invoke-MgGraphRequest -Method PATCH `
    -Uri "/beta/security/rules/detectionRules/5632" `
    -Body $update -ContentType "application/json"
```

### Delete Rule

```powershell
Invoke-MgGraphRequest -Method DELETE `
    -Uri "/beta/security/rules/detectionRules/5632"
```

> **⚠️ Deletion propagation delay:** After deleting a rule, the name remains reserved for ~30-60 seconds. Creating a rule with the same `displayName` during this window returns `409 Conflict` — but the rule may still be created despite the error. Always verify with a GET after creation.

### Enable/Disable Without Deleting

```powershell
# Disable
Invoke-MgGraphRequest -Method PATCH `
    -Uri "/beta/security/rules/detectionRules/5632" `
    -Body '{"isEnabled": false}' -ContentType "application/json"

# Enable
Invoke-MgGraphRequest -Method PATCH `
    -Uri "/beta/security/rules/detectionRules/5632" `
    -Body '{"isEnabled": true}' -ContentType "application/json"
```

---

## Existing Rule Discovery

Before authoring new custom detections, check what Analytic Rules (Sentinel) and Custom Detection rules (Defender XDR) already exist for the same table, EventID, or keyword. This avoids duplicating coverage and helps identify gaps.

### Step 0: Construct the Analytic Rules URL (once per session)

```powershell
$cfg = Get-Content config.json | ConvertFrom-Json
$sub = $cfg.subscription_id
$rg  = $cfg.azure_mcp.resource_group
$ws  = $cfg.azure_mcp.workspace_name
$arUrl = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-09-01"

# Verify (should return rule count)
az rest --method get --url $arUrl --query "length(value)" -o tsv 2>$null
```

> All patterns below reuse `$arUrl`. The Sentinel REST API returns the full KQL query text for every rule — there is no server-side content filtering, so we pull all rules in one call and filter client-side with JMESPath `contains()`.

### Search Analytic Rules by Table Name or Keyword

```powershell
# Which rules reference a specific table? (e.g., SecurityEvent)
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, 'SecurityEvent')].{name: properties.displayName, severity: properties.severity, enabled: properties.enabled}" `
  -o table 2>$null
```

### Search Analytic Rules by EventID

```powershell
# Which rules reference a specific EventID?
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, '<EventID>')].{name: properties.displayName, severity: properties.severity, enabled: properties.enabled}" `
  -o table 2>$null
```

To see the surrounding KQL context of a match:

```powershell
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, '<EventID>')].properties.query" `
  -o tsv 2>$null | Select-String -Pattern '<EventID>' -Context 1,1
```

### Search Analytic Rules for ASIM Parser Dependencies

```powershell
$rules = az rest --method get --url $arUrl `
  --query "value[?properties.enabled==``true`` && properties.query].{displayName: properties.displayName, query: properties.query}" `
  -o json 2>$null | ConvertFrom-Json

$asimRules = $rules | Where-Object { $_.query -match '_Im_|_ASim_' }
$asimRules | ForEach-Object {
    $schemas = [regex]::Matches($_.query, '_Im_(\w+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    Write-Host "$($_.displayName): $($schemas -join ', ')"
}
```

### Dump All Enabled Rule Queries for Local Search

```powershell
az rest --method get --url $arUrl `
  --query "value[?properties.enabled==``true`` && properties.query].{name: properties.displayName, query: properties.query}" `
  -o json > temp/analytic_rule_queries.json

# Then search locally for any pattern
Get-Content temp/analytic_rule_queries.json | Select-String -Pattern 'EventID\s*(==|in\s*\(|has|contains)' -AllMatches
```

### Search Custom Detection Rules (Graph API)

**⚠️ Important:** The Graph MCP server returns 403 for the Custom Detection endpoint. Always use `Invoke-MgGraphRequest` via the terminal.

```powershell
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$ctx = Get-MgContext
if (-not $ctx -or $ctx.Scopes -notcontains 'CustomDetection.Read.All') {
    Connect-MgGraph -Scopes 'CustomDetection.Read.All' -NoWelcome
}

$response = Invoke-MgGraphRequest -Method GET `
    -Uri '/beta/security/rules/detectionRules?$select=id,displayName,isEnabled,queryCondition,schedule,lastRunDetails,createdDateTime,lastModifiedDateTime' `
    -OutputType PSObject
```

Then filter by table name or keyword:

```powershell
# Which CD rules reference SecurityEvent?
$response.value | Where-Object { $_.queryCondition.queryText -match 'SecurityEvent' } |
    Select-Object displayName, isEnabled, @{N='Query';E={$_.queryCondition.queryText}}

# Which CD rules reference a specific EventID?
$response.value | Where-Object { $_.queryCondition.queryText -match '4688|ProcessCreate' } |
    Select-Object displayName, isEnabled, @{N='Query';E={$_.queryCondition.queryText}}
```

Identify stale rules (no run in 90 days):

```powershell
$cutoff = (Get-Date).AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
$response.value | Where-Object {
    $_.lastRunDetails.lastRunDateTime -and $_.lastRunDetails.lastRunDateTime -lt $cutoff
} | Select-Object displayName, isEnabled,
    @{N='LastRun';E={$_.lastRunDetails.lastRunDateTime}},
    @{N='Status';E={$_.lastRunDetails.status}}
```

### Key API Fields for Rule Discovery

| Source | Field Path | Content |
|--------|------------|---------|
| **Analytic Rules** (REST) | `properties.displayName` | Rule name |
| | `properties.query` | Full KQL query text |
| | `properties.severity` | High / Medium / Low / Informational |
| | `properties.enabled` | `true` / `false` |
| **Custom Detections** (Graph) | `displayName` | Rule name |
| | `queryCondition.queryText` | Full KQL query (AH syntax) |
| | `schedule.period` | `PT1H`, `PT24H`, `PT0S` (continuous) |
| | `lastRunDetails.lastRunDateTime` | Last execution timestamp |
| | `lastRunDetails.status` | `completed`, `failed`, `running` |
| | `isEnabled` | `true` / `false` |

> **Tip:** JMESPath `contains()` (used in `az rest --query`) is case-sensitive. For case-insensitive search, dump to JSON and use PowerShell `-match` instead.

---

## Known Pitfalls

### Pitfall 1: `Timestamp` vs `TimeGenerated` — Project As-Is

The query must project the timestamp column **exactly as it appears in the source table**. Do NOT alias one to the other.

| Source Table Type | Correct | Wrong |
|-------------------|---------|-------|
| Sentinel/LA tables (SecurityEvent, SigninLogs, AuditLogs, etc.) | `TimeGenerated = TimeGenerated` | `Timestamp = TimeGenerated` |
| XDR-native tables (DeviceEvents, DeviceProcessEvents, etc.) | `Timestamp` (native) | `TimeGenerated = Timestamp` |

The MS Learn docs confirm: "`Timestamp` or `TimeGenerated` — This column sets the timestamp for generated alerts. The query shouldn't manipulate this column and should return it exactly as it appears in the raw event." Aliasing across types causes `400 Bad Request`.

### Pitfall 2: Silent Rule Creation on Error Responses (400 AND 409)

**The API can silently create a rule even when it returns an error.** This applies to both `400 Bad Request` and `409 Conflict` responses.

**Cause A — 400 with partial validation:** A POST may pass structural validation (creating the rule) but fail a secondary check (e.g., `let` variable in NRT query, >3 dynamic fields). The API returns `400 Bad Request` — but the rule was already created. A subsequent retry with a fixed query then hits `409 Conflict` because the rule exists.

**Cause B — Deletion propagation delay:** Deleting a rule leaves a name reservation for ~30-60 seconds. POSTing a rule with the same `displayName` in this window returns `409 Conflict` — but the API may still create the rule.

**Cause C — Silent success + accidental retry:** When running `Invoke-MgGraphRequest` in a terminal, the POST may succeed but the output buffer splits across calls, making it look like nothing happened. Re-running the same POST produces a 409 because the rule was already created seconds earlier.

**Prevention:**
1. **Always run a GET before POST** to check if the rule name already exists (see [Step 2](#single-rule-deployment))
2. **Always verify with GET after ANY error response (400 or 409)** — the rule may have been created despite the error
3. **Never re-run a POST** without first checking via GET whether the previous attempt succeeded
4. **If a rule was silently created with a bad query**, use PATCH to update the `queryCondition.queryText` rather than deleting and re-creating

### Pitfall 3: `summarize` — Allowed Only With Row-Level Output

Custom detection queries must return row-level results with required columns (`TimeGenerated`, `DeviceName`, `ReportId`). A bare `summarize count()` or `make_set()` as the final operator fails validation because the output lacks these columns.

**However, `summarize` with `arg_max` IS allowed** when used to return the required columns alongside aggregation:

```kql
// ✅ ALLOWED — uses arg_max to preserve row-level columns
DeviceEvents
| where ingestion_time() > ago(1d)
| where ActionType == "AntivirusDetection"
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 5
```

This pattern counts by entity but still returns `Timestamp`, `ReportId`, and `DeviceId` per row — satisfying the requirement. Use this for threshold-based detections ("alert when count > N").

### Pitfall 4: Graph MCP and `az rest` Cannot Access This API

Both the Graph MCP server and `az rest` lack the `CustomDetection.ReadWrite.All` scope. Only `Invoke-MgGraphRequest` with interactive delegated auth works.

### Pitfall 5: `recommendedActions` Type

The `recommendedActions` field is a `String` (not an array). Set to `null` if not needed. The portal always sets it to `null`.

### Pitfall 6: Query Newlines in JSON

The `queryText` JSON field requires `\r\n` (CRLF) line breaks on the wire. **When using `ConvertTo-Json` on a PowerShell hashtable** (the recommended approach), this is handled automatically — multiline here-string content in the hashtable value is serialized with correct CRLF encoding. No manual newline insertion is needed.

If manually constructing a raw JSON string body (not recommended), use PowerShell backtick escapes `` `r`n `` to produce CRLF in the output.

### Pitfall 7: Duplicate Name AND Title Check

The API enforces unique `displayName` AND unique `title` (alert title) across all custom detections. Duplicate `displayName` returns `409 Conflict`. Duplicate `title` returns `400 Bad Request`. The batch deployment script checks for `displayName` duplicates by default — use `-Force` to override. The MS Learn docs state both should be unique: "Detection name... make it unique" and "Alert title... make it unique".

### Pitfall 8: Alert Deduplication

Custom detections automatically deduplicate alerts. If a detection fires twice on events with the **same entities, custom details, and dynamic details**, only one alert is created. This can happen when the lookback period is longer than the run frequency (e.g., 1H frequency with 4H lookback means 3 hours of overlap). Different events on the same entity produce separate alert entries under the same alert.

### Pitfall 9: `impactedAssets` Identifier Must Be a Predefined API Value

**The `identifier` field in `impactedAssets` must use one of the predefined values from the [Impacted Asset Types](#impacted-asset-types) section — NOT arbitrary query column names.** Using a custom column name (e.g., `"identifier": "TargetComputer"` or `"identifier": "Actor"`) causes a silent `400 InvalidInput` with an **empty error message**.

This aligns with the [MS Learn docs](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#required-columns-in-the-query-results) which list specific "strong identifier" columns for impacted assets. The portal wizard enforces this via a dropdown; the Graph API rejects non-matching values silently.

**Identifier values must use camelCase** as listed in the [Impacted Asset Types](#impacted-asset-types) section (e.g., `recipientEmailAddress`, not `RecipientEmailAddress`). The API treats identifier values as case-sensitive when matching to the predefined list.

Additionally, the query MUST project a column whose name matches the chosen identifier. If you use `"identifier": "accountUpn"`, the query must project an `AccountUpn` column (alias if needed: `AccountUpn = UserId`). The column name match is case-insensitive — `AccountUpn` in the query matches `accountUpn` in the identifier.

| Wrong | Correct |
|-------|---------|
| `"identifier": "UserId"` | `"identifier": "accountUpn"` + project `AccountUpn = UserId` |
| `"identifier": "Actor"` | `"identifier": "accountUpn"` + rename `Actor` → `AccountUpn` |
| `"identifier": "TargetComputer"` | `"identifier": "deviceName"` + project `DeviceName = Computer` |
| `"identifier": "TargetUPN"` | `"identifier": "accountUpn"` + rename `TargetUPN` → `AccountUpn` |

> **DeviceId requirement:** For XDR-native tables (Device\*, Email\*, CloudAppEvents) with a device-type impactedAsset, the query must project `DeviceId` (not just `DeviceName`). Sentinel/LA tables (SecurityEvent, AuditLogs) do not require `DeviceId`.

### Pitfall 10: PowerShell Empty Array Swallowing & `organizationalScope`

**Root cause (Feb 2026):** When using PowerShell `if/else` expressions to assign empty arrays, PowerShell swallows `@()` and produces `$null` instead:

```powershell
# ❌ BUG — $x becomes $null, NOT an empty array
$x = if ($false) { @($items) } else { @() }
# Result: $null

# ✅ CORRECT — assign first, then overwrite conditionally
$x = @()
if ($condition) { $x = @($items) }
# Result: empty Object[] (serializes to [])
```

This caused array fields like `responseActions` and `mitreTechniques` to serialize as `null` instead of `[]`, which the API rejects with `400 Bad Request`.

**Combined with `organizationalScope: null`** — including this field explicitly (even as `null`) was also rejected. The fix: omit `organizationalScope` entirely and use direct assignment for array fields.

**Symptoms:** All rules in a batch return `400 Bad Request`, but some may be silently created (see [Pitfall 2](#pitfall-2-silent-rule-creation-on-error-responses-400-and-409)). Manual deployment of the same rule body (without the null fields) succeeds.

**Fixed in:** [Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) — array fields now use direct assignment, `organizationalScope` removed from body.

### Pitfall 11: `tostring()` on Dynamic Columns Rejected in NRT Mode

**Root cause (Feb 2026):** NRT rules (`schedule: "0"`) reject `tostring()` wrapping dynamic-typed columns. The API returns a generic `400 Bad Request` with no useful error message — similar to the `let` rejection described in [NRT Constraints](#nrt-constraints). The same query deploys successfully as a scheduled rule (1H+).

**Example — AzureActivity table:**

```kql
// ❌ FAILS in NRT mode — tostring() on dynamic column
AzureActivity
| where OperationNameValue =~ "MICROSOFT.SECURITY/PRICINGS/WRITE"
| where tostring(Properties_d.pricings_pricingTier) == "Free"

// ✅ WORKS — use the native string column instead
AzureActivity
| where OperationNameValue =~ "MICROSOFT.SECURITY/PRICINGS/WRITE"
| where Properties has '"pricingTier":"Free"'
```

**Workarounds:**
1. **Prefer native string columns** — many Sentinel tables have both a dynamic column (e.g., `Properties_d`) and a string column (e.g., `Properties`). Use the string column with `has` or `contains` for NRT.
2. **Switch to 1H schedule** — if `tostring()` is required for precise extraction, use a scheduled rule where it works reliably.

**Ingestion lag consideration:** Even when a table is NRT-supported, check whether ingestion lag makes NRT impractical — see [Ingestion Lag Consideration](#ingestion-lag-consideration--nrt-suitability).

### Pitfall 12: NRT-Supported ≠ NRT-Practical — Check Ingestion Lag

A table appearing in the [NRT-Supported Tables](#nrt-supported-tables) list means the API **accepts** NRT rules for that table — it does NOT mean NRT adds value. Tables with significant ingestion lag negate the benefit of continuous detection.

| Table | Typical Ingestion Lag | NRT Practical? | Recommendation |
|-------|-----------------------|----------------|----------------|
| `DeviceEvents`, `DeviceProcessEvents` | < 5 min | ✅ Yes | NRT is effective |
| `SigninLogs`, `AuditLogs` | 5-15 min | ⚠️ Marginal | 1H is usually sufficient |
| `AzureActivity` | 3-20 min ([docs](https://learn.microsoft.com/azure/azure-monitor/logs/data-ingestion-time)) | ⚠️ Marginal | Evaluate per use case |
| `SecurityEvent` | < 5 min | ✅ Yes | NRT is effective |
| `OfficeActivity` | 15-60 min | ⚠️ Marginal | Evaluate per use case |

**Rule of thumb:** If the table's ingestion lag exceeds 30 minutes, use a 1H scheduled rule instead of NRT. The detection latency is dominated by ingestion lag, not rule frequency.

### Pitfall 13: `impactedAssets` Must Be Non-Empty

**Root cause (Feb 2026):** The Graph API requires `impactedAssets` to contain **at least 1 element**. Sending an empty array (`"impactedAssets": []`) returns `400 BadRequest` with `InvalidInput` code and the message: *"The field ImpactedAssets must be a string or array type with a minimum length of '1'."*

This error is particularly difficult to diagnose because:
- The error message only appears in some response formats — when using `Invoke-MgGraphRequest` with raw JSON strings, the `"message"` field is often **empty** (`""`)
- The actual error text only surfaced when using `ConvertTo-Json` on a PowerShell hashtable body
- All other fields in the payload may be valid, making it seem like a server-side issue

**Every custom detection must declare at least one impacted entity.** Choose the most relevant asset type for the detection:

| Detection Focus | Asset Type | Example Identifier |
|----------------|------------|--------------------|
| Email-based threats | `impactedMailboxAsset` | `recipientEmailAddress`, `senderFromAddress` |
| User activity | `impactedUserAsset` | `accountUpn`, `accountObjectId` |
| Endpoint/device | `impactedDeviceAsset` | `deviceId`, `deviceName` |

**Prevention:**
- Always include at least one `impactedAssets` entry in manifests and API payloads
- The companion script [Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) validates this at manifest load time and rejects rules with empty `impactedAssets` before calling the API
- Review the [Impacted Asset Types](#impacted-asset-types) section for the full list of valid identifiers per asset type

### Pitfall 14: Max 3 Unique Dynamic Columns Across Title + Description

The Graph API enforces **3 unique `{{Column}}` references** across `title` and `description` **combined** (not per field). Exceeding this returns `400 Bad Request` — often with an empty error message via `Invoke-MgGraphRequest`.

**⚠️ MS Learn discrepancy:** Docs say 3 per field; the API empirically enforces 3 unique total across both fields (confirmed Mar 2026).

| Scenario | Unique Columns | Result |
|----------|---------------|--------|
| `title`: `{{A}} {{B}}`, `description`: `{{A}} {{C}}` | A, B, C = 3 | ✅ Accepted |
| `title`: `{{A}} {{B}}`, `description`: `{{C}} {{D}}` | A, B, C, D = 4 | ❌ 400 Bad Request |

**Counting:** Reuse across fields is free (`{{A}}` in both = 1). Count distinct names, not occurrences.

**Workaround:** Replace excess `{{Column}}` refs with static text, or use `customDetails` (up to 20 KVPs) to surface extra columns in the alert side panel. [Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) validates this at manifest load time.

### Pitfall 15: PowerShell Double-Quoted Here-Strings — Variable Interpolation & Escaping Traps

**When building `queryText` in PowerShell, always use single-quoted here-strings (`@'...'@`), NEVER double-quoted (`@"..."@`).** Two distinct failure modes make double-quoted here-strings unreliable for KQL:

**Risk 1 — `$variable` interpolation:** PowerShell double-quoted strings interpolate `$var` references. KQL uses `$left` and `$right` in join syntax and `$` as a dynamic property prefix. Inside `@"..."@`, PowerShell replaces these with empty strings (undefined variables → `$null` → empty), silently producing broken KQL with no compile-time warning.

**Risk 2 — LLM/human escaping confusion (confirmed Mar 2026):** When writing KQL inside a double-quoted context, an LLM (or human) instinctively adapts backslash escaping — writing `\skills` (single backslash) instead of `\\skills` (double backslash), because most languages interpret `\\` → `\` in double-quoted strings. **PowerShell does NOT do this** (backtick `` ` `` is the escape character, not backslash), so the single `\` passes through literally to the KQL parser, which rejects `\s` as an invalid escape sequence → `400 Bad Request: "syntax errors"`.

**Byte-level proof (Mar 2026):** When identical `\\skills` content is deliberately placed in both here-string types, PowerShell produces identical bytes — confirming PowerShell itself does not mangle backslashes. The difference arises from what gets *written into* the string (by the LLM or human), not from PowerShell processing it. This makes the bug extremely hard to diagnose: the query looks correct in terminal output, and the root cause is an invisible content difference between attempts.

| Here-String Type | `$left` / `$right` | Backslash Content | Practical Safety |
|-----------------|---------------------|-------------------|------------------|
| `@'...'@` (single-quoted) | Literal `$left` ✅ | What you write is what you get | ✅ Safe — no interpretation |
| `@"..."@` (double-quoted) | Interpolated → empty ❌ | What you write is what you get — but LLMs write different content | ❌ Fragile — two failure modes |

**Rule:** For ANY `queryText`, **always use `@'...'@`**. This eliminates both `$` interpolation bugs and escaping confusion. Applies to inline PowerShell, the batch deployment script, and any LLM-generated deployment commands.

**Additional validated finding:** `ingestion_time()` IS accepted by the CD API (tested and confirmed Mar 2026, despite MS Learn documentation ambiguity). The CD query validator accepts all functions that Advanced Hunting accepts for scheduled (non-NRT) rules.

### Pitfall 16: StrictMode `.Count` on Pipeline Scalars — Array Unwrapping

**Root cause (Mar 2026):** With `Set-StrictMode -Version Latest`, calling `.Count` on an object that doesn't have the property throws a terminating error. PowerShell pipelines that return exactly **1 result** unwrap the array to a scalar — and scalars (e.g., `[string]`) don't have `.Count`.

**Concrete trigger in Deploy-CustomDetections.ps1:** The dynamic column validation extracted unique `{{Column}}` references from `title` + `description`. When only 1 unique column existed (e.g., `{{DeviceName}}` in both title and description), `Sort-Object -Unique` returned a scalar string `"DeviceName"` instead of `@("DeviceName")`. The subsequent `$dynamicCols.Count` check threw:

```
The property 'Count' cannot be found on this object. Verify that the property exists.
```

Rules with 2+ unique dynamic columns worked fine because the pipeline returned an `Object[]`, which has `.Count`.

**The pattern affects ANY pipeline where the result count varies:**

```powershell
# ❌ BUG — returns scalar string when 1 match, Object[] when 2+
$items = Get-ChildItem *.log | ForEach-Object { $_.Name } | Sort-Object -Unique
$items.Count  # 💥 StrictMode error if exactly 1 .log file

# ✅ FIX — @() forces array regardless of result count
$items = @(Get-ChildItem *.log | ForEach-Object { $_.Name } | Sort-Object -Unique)
$items.Count  # Always works: 0, 1, or N
```

**Also affects `ConvertFrom-Json`:** A JSON file containing a single-element array (`[{...}]`) is deserialized as a scalar `PSCustomObject`, not an `Object[]`. Wrapping in `@()` is required:

```powershell
# ❌ BUG — single-rule manifest: $manifest is PSCustomObject, .Count fails
$manifest = Get-Content manifest.json -Raw | ConvertFrom-Json

# ✅ FIX — always an array
$manifest = @(Get-Content manifest.json -Raw | ConvertFrom-Json)
```

**Rule:** In any PowerShell script using `Set-StrictMode -Version Latest`, wrap **every** pipeline or `ConvertFrom-Json` call in `@()` if you'll later access `.Count`, `.Length`, or iterate with `foreach`. The cost is zero (wrapping an existing array in `@()` is a no-op), and it prevents the scalar unwrapping trap.

**Fixed in:** [Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) — all pipeline results that use `.Count` are now wrapped in `@()`.

---

## CD Metadata Contract

Query files in `queries/` can include per-query **cd-metadata blocks** that provide structured data for the detection authoring skill. This is the producer/consumer contract between the **KQL Query Authoring** skill (producer) and the **Detection Authoring** skill (consumer).

### When cd-metadata is present

When a query in `queries/` includes a cd-metadata block, the detection authoring skill uses it to:
- Pre-populate manifest fields (`schedule`, `severity`, `category`, `title`, `impactedAssets`, etc.)
- Skip manual CD-readiness assessment — the block declares readiness explicitly
- Generate the adapted CD query by applying the [Query Adaptation Checklist](#query-adaptation-checklist) to the Sentinel query in the same section

### Schema

The cd-metadata block is an HTML comment with YAML content, placed immediately after the per-query metadata fields (`Severity`, `MITRE`, `Tuning Notes`) and before the KQL code block:

```markdown
### Query N: [Title]

**Purpose:** ...
**Severity:** High
**MITRE:** T1053.005, T1059.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Encoded PowerShell in Scheduled Task on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Investigate the scheduled task XML. Decode the base64 payload and check for malicious content."
adaptation_notes: "Straightforward — already row-level, add mandatory columns"
-->

```kql
// Query code...
```
```

### Field Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `cd_ready` | Yes | `true` / `false` | Whether this query can be adapted for custom detection deployment |
| `schedule` | If cd_ready | `"0"` / `"1H"` / `"3H"` / `"12H"` / `"24H"` | Detection frequency. `"0"` = NRT (single-table, no joins/unions) |
| `category` | If cd_ready | string | Alert category (see [API Reference](#api-reference) for valid values) |
| `title` | No | string | Dynamic alert title with `{{ColumnName}}` placeholders. Falls back to query heading if omitted. **Limit: max 3 unique `{{Column}}` references across `title` AND `description` combined** (see [Pitfall 14](#pitfall-14-max-3-unique-dynamic-columns-across-title--description)) |
| `impactedAssets` | If cd_ready | array | Asset entities to extract. Each entry: `type` (`device`/`user`/`mailbox`) + `identifier` (predefined API value, e.g., `accountUpn`, `deviceName` — see [Impacted Asset Types](#impacted-asset-types)) |
| `recommendedActions` | No | string | Triage guidance shown in the alert. Omit if not needed |
| `responseActions` | No | array | **PROHIBITED** — must always be omitted or empty `[]`. Response actions must only be configured manually in the Defender portal |
| `adaptation_notes` | No | string | Human-readable notes on what adaptation is needed (for the summary table) |

### Queries NOT suitable for CD

For queries that cannot be adapted (baseline queries, statistical aggregations), use:

```markdown
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical baseline query — requires summarize with dcount, not suitable for CD"
-->
```

This explicitly documents the assessment so the detection skill doesn't re-evaluate it each time.

### How the detection skill consumes cd-metadata

1. **User says "deploy query 8 as a custom detection"** → Skill reads the query file, finds the cd-metadata block for Query 8
2. **Pre-populates manifest entry** from cd-metadata fields (schedule, category, severity, title, impactedAssets)
3. **Applies [Query Adaptation Checklist](#query-adaptation-checklist)** to the Sentinel KQL query in that section
4. **Deploys** via Graph API or generates manifest JSON for batch deployment

If a query file has **no cd-metadata blocks**, the skill assesses CD-readiness manually based on the query structure and the [Query Adaptation Checklist](#query-adaptation-checklist).
