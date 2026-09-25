# Storm-3168 (JADEPUFFER) — Agentic Azure Destruction via Compromised Service Principals — Threat Hunts

**Created:** 2026-09-25  
**Platform:** Both  
**Tables:** AzureActivity, EntraIdSpnSignInEvents, AADServicePrincipalSignInLogs, EntraIdSignInEvents, CloudAuditEvents, AppServiceHTTPLogs, DeviceNetworkEvents, AlertInfo, AlertEvidence  
**Keywords:** Storm-3168, JADEPUFFER, agentic ransomware, AI-orchestrated attack, compromised service principal, workload identity, client secret exposure, GitHub issue edit history, python-requests, ARM destruction, Azure Resource Manager, mass deletion, storage account deletion, STORAGEACCOUNTS/DELETE, SQL database deletion, Key Vault deletion, Function App deletion, App Service plan deletion, resource lock, CannotDelete lock, ScopeLocked, Azure Site Recovery, Azure Backup protection lock, inhibit recovery, ListKeys, storage account keys, credential collection, InvalidApiVersionParameter, cloud service discovery, LangFlow validate code, /api/v1/validate/code, PHP-CGI, WordPress probing, App Service probing, Defender for Resource Manager  
**MITRE:** T1078.004, T1526, T1580, T1485, T1490, T1552.001, T1552, T1530, T1098.001, T1190, T1595.002, TA0001, TA0006, TA0007, TA0040  
**Domains:** cloud, spn, identity  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Storm-3168: Agentic-driven cloud attacks using compromised service principals (2026-09-25)](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)

---

## Threat Overview

Microsoft Security Research attributes a destructive, Azure-focused intrusion to **Storm-3168** — Microsoft's designation for **JADEPUFFER**, the actor Sysdig reported in July 2026 as the first documented *agentic ransomware* operation. The actor used **two compromised service principals in the same tenant**: one spent ~15.5 hours enumerating subscriptions, resource groups, resources and VMs (300+ successful reads); the second enumerated VMs/resource groups across two subscriptions in five seconds, later inventoried App Service configuration stores (and failed to find OpenSearch), then — **less than one second after a failed `ListKeys` against a non-existent storage account** — launched a **~7-minute destructive sequence**: 100+ storage-account deletion attempts, deletion of a Key Vault, Function App and App Service plan, parallel (failed) Azure SQL database deletions using an unsupported API version, and failed attempts to delete Azure Site Recovery and Azure Backup protection locks. About 30 minutes later the same identity inventoried storage accounts and issued **30+ successful `ListKeys` requests**, including against Site Recovery storage.

Both identities used Storm-3168-linked infrastructure, a shared network fingerprint, and the user agent **`python-requests/2.34.2`**. Five distinct tokens were issued to the destructive SPN, two active concurrently for deletion — strong evidence of scripted/agentic parallelism. Every operation followed the SPN's **existing RBAC** (group-granted Storage Account Contributor, direct Contributor, direct SQL DB Contributor). The likely initial access was a **client ID/secret/tenant ID pasted into a public GitHub issue** whose edit history kept the secret after redaction; Storm-3168 infrastructure has also probed Azure App Service apps for WordPress admin, PHP-CGI and **LangFlow `/api/v1/validate/code`** paths since early 2026. Resource locks and storage deletion protection blocked some deletions — independent guardrails worked even against an over-privileged identity. No ransom note or confirmed exfiltration was observed.

### TTP Summary

| Capability | TTP |
|---|---|
| Initial access (suspected) | Exposed SPN client secret in a public GitHub issue edit history (T1552.001 → T1078.004) |
| Initial access (probing) | App Service probing for WordPress admin, PHP-CGI, LangFlow `/api/v1/validate/code`, web-shell paths (T1190) |
| Valid cloud accounts | Two compromised service principals authenticating from actor infrastructure with `python-requests/2.34.2` (T1078.004) |
| Discovery | Long, broad enumeration of subscriptions/RGs/resources/VMs; App Service config stores; OpenSearch lookup (T1526, T1580) |
| Parallel automation | Five tokens on one SPN, two concurrent deletion streams, work split across two SPNs |
| Impact — destruction | 100+ `STORAGEACCOUNTS/DELETE` in ~7 min; Key Vault, Function App, App Service plan deleted; SQL DB deletes attempted (T1485) |
| Impact — recovery inhibition | Deletion attempts against Site Recovery and Azure Backup protection locks; backup/terraform-themed storage targeted (T1490) |
| Credential access | 30+ `STORAGEACCOUNTS/LISTKEYS/ACTION` after destruction, incl. Site Recovery storage (T1552 — cloud credential collection) |
| Tell-tale failures | `ListKeys` on a non-existent account; SQL deletes rejected for unsupported API version; `ScopeLocked` on locked resources |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **The Azure Activity Log does not record ARM read (GET) operations** | The 300+ read enumeration phase is invisible in `AzureActivity`. Only write/delete/action (POST — including `listKeys`) operations are logged. Detect discovery via Defender for Resource Manager alerts (Query 10) or ARM diagnostic telemetry; the hunts here start at the first write/action. |
| **`AzureActivity` has no user-agent column** | The `python-requests` fingerprint is only visible in the SPN sign-in (token acquisition) logs — `EntraIdSpnSignInEvents` / `AADServicePrincipalSignInLogs` (Query 2). Correlate sign-in IP → `CallerIpAddress` (Query 8). |
| **`python-requests/2.34.2` is just a current library release** | Legitimate SOC/devops automation uses the same version. Never alert on the UA alone; weight it only when combined with ARM as the resource, a new IP, and destructive/key-read operations. |
| **`CloudAuditEvents` (Azure) is a sparse subset** | It carries a subset of Azure control-plane events and its `UserAgent` is empty for Azure rows. Use `AzureActivity` as the primary source; `CloudAuditEvents` only in the IOC sweep. |
| **`_ResourceId` / `ResourceId` are absent from `AzureActivity` in the Sentinel Data Lake** | Derive the target from `tolower(tostring(parse_json(Authorization).scope))` — it works identically in Advanced Hunting and Data Lake, so queries port unchanged. |
| **Each ARM operation emits multiple rows** (`Start`, `Accept`, `Success`/`Failure`) | Filter `ActivityStatusValue in~ ("Success","Failure")` and count **distinct targets**, not rows, or counts inflate 2–3×. |
| **Microsoft first-party services legitimately delete recovery artifacts and read keys** | *Backup Management Service* prunes restore points by retention; *Azure Machine Learning* and *Hyper-V Recovery Manager* (Site Recovery) read storage keys. Exclude by the `appid` claim (`parse_json(Claims).appid`), never by object ID, which differs per tenant. |
| **IaC (Terraform/Bicep) teardown looks like destruction** | `terraform destroy` removes locks, VMs, role assignments and reads keys in bursts. Allowlist dedicated IaC service principals by appId after verifying their pipeline ownership — but keep them in scope for Query 8 (new IP) since a stolen IaC credential is exactly this attack. |
| **`Caller` is a GUID for SPNs but a UPN for users** | Queries test `Caller` against a GUID regex to separate workload identities from humans. |
| **Published IOC activity (early June 2026) may predate retention** | Advanced Hunting covers 30 days; many Data Lake workspaces retain ~90 days. Absence of IOC hits is not proof of absence for June activity — extend retention or check archived logs if exposure is suspected. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Storm-3168 infrastructure sweep across cloud, identity, web and end...](#query-1-storm-3168-infrastructure-sweep-across-cloud-identity-web-and-endpoint-telemetry-direct-ioc) | Investigation | `AppServiceHTTPLogs` + multi |
| 2 | [Service principals authenticating with raw scripting HTTP clients (...](#query-2-service-principals-authenticating-with-raw-scripting-http-clients-python-requests-fingerprint) | Investigation | `EntraIdSpnSignInEvents` |
| 3 | [Bulk destructive ARM burst across data and application resources](#query-3-bulk-destructive-arm-burst-across-data-and-application-resources) | Investigation | `AzureActivity` |
| 4 | [Resource-lock and backup/recovery protection tampering](#query-4-resource-lock-and-backuprecovery-protection-tampering) | Investigation | `AzureActivity` |
| 5 | [Storage account key harvesting burst (ListKeys across many accounts)](#query-5-storage-account-key-harvesting-burst-listkeys-across-many-accounts) | Investigation | `AzureActivity` |
| 6 | [Destruction-then-harvest chain by the same workload identity](#query-6-destruction-then-harvest-chain-by-the-same-workload-identity) | Investigation | `AzureActivity` + `ChainScore` |
| 7 | [Guardrail-blocked destructive attempts (locks, deletion protection,...](#query-7-guardrail-blocked-destructive-attempts-locks-deletion-protection-bad-api-versions-non-existent-targets) | Investigation | `AzureActivity` |
| 8 | [Service principal used from a new IP, followed by destructive or se...](#query-8-service-principal-used-from-a-new-ip-followed-by-destructive-or-secret-retrieval-arm-operations) | Investigation | `AzureActivity` + `EntraIdSpnSignInEvents` |
| 9 | [App Service probing for LangFlow, PHP-CGI, WordPress and web-shell ...](#query-9-app-service-probing-for-langflow-php-cgi-wordpress-and-web-shell-paths) | Investigation | `AppServiceHTTPLogs` |
| 10 | [Defender for Cloud alerts matching the Storm-3168 detection set](#query-10-defender-for-cloud-alerts-matching-the-storm-3168-detection-set) | Detection | `AlertInfo` |


## IOC Reference

> Published indicators from the Microsoft Security Research article (defanged here; queries use plain forms). IP infrastructure rotates quickly — refresh from current Microsoft Defender Threat Intelligence / `ThreatIntelIndicators` before relying on Query 1. The behavioral hunts (Queries 3–8) survive infrastructure rotation.

| Indicator | Type | Description |
|---|---|---|
| 45.131.66[.]106 | IPv4 | App Service probing and malicious ARM requests |
| 34.153.223[.]102 | IPv4 | App Service probing |
| 64.20.53[.]230 | IPv4 | App Service probing |

**Non-table indicators cited in the article narrative:**

| Indicator | Type | Description |
|---|---|---|
| `python-requests/2.34.2` | User agent | Shared by both compromised service principals (weak alone — see Hunt Pitfalls) |
| `/api/v1/validate/code` | URI path | LangFlow code-validation endpoint probed on Azure App Service |

---

## Query 1: Storm-3168 infrastructure sweep across cloud, identity, web and endpoint telemetry (direct IOC)

**Purpose:** Direct match of the three published IPs across ARM control-plane activity, SPN and user sign-ins, Azure `CloudAuditEvents`, App Service HTTP logs and Defender for Endpoint network events. A clean environment returns 0 rows; any hit from `AzureActivity` or `EntraIdSpnSignInEvents` means a workload identity is being operated from actor infrastructure — treat as confirmed compromise.  
**Severity:** High  
**MITRE:** T1078.004, T1190

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table summarized IOC sweep for hunting. Promotion path: deploy the AzureActivity (CallerIpAddress) and EntraIdSpnSignInEvents (IPAddress) branches as separate single-table NRT rules without the final summarize, projecting TimeGenerated/Timestamp, a ReportId (CorrelationId for AzureActivity), and ServicePrincipalId as a user asset (servicePrincipalId). IPs rotate - source from ThreatIntelIndicators instead of a static list for durable coverage."
-->

```kql
let IOC_IPs = dynamic(["45.131.66.106", "34.153.223.102", "64.20.53.230"]);
let lookback = 30d;
union
(AzureActivity | where TimeGenerated > ago(lookback) | where CallerIpAddress in (IOC_IPs)
 | project Timestamp=TimeGenerated, Source="AzureActivity", IP=CallerIpAddress, Identity=Caller, Detail=OperationNameValue, Status=ActivityStatusValue),
(CloudAuditEvents | where Timestamp > ago(lookback) | where AuditSource == "Azure" and IPAddress in (IOC_IPs)
 | project Timestamp, Source="CloudAuditEvents", IP=IPAddress, Identity=Account, Detail=OperationName, Status=ActionType),
(EntraIdSpnSignInEvents | where Timestamp > ago(lookback) | where IPAddress in (IOC_IPs)
 | project Timestamp, Source="EntraIdSpnSignInEvents", IP=IPAddress, Identity=strcat(ServicePrincipalName, " (", ApplicationId, ")"), Detail=strcat(ResourceDisplayName, " | UA=", UserAgent), Status=tostring(ErrorCode)),
(EntraIdSignInEvents | where Timestamp > ago(lookback) | where IPAddress in (IOC_IPs)
 | project Timestamp, Source="EntraIdSignInEvents", IP=IPAddress, Identity=AccountUpn, Detail=Application, Status=tostring(ErrorCode)),
(AppServiceHTTPLogs | where TimeGenerated > ago(lookback) | where CIp in (IOC_IPs)
 | project Timestamp=TimeGenerated, Source="AppServiceHTTPLogs", IP=CIp, Identity=CsHost, Detail=CsUriStem, Status=tostring(ScStatus)),
(DeviceNetworkEvents | where Timestamp > ago(lookback) | where RemoteIP in (IOC_IPs)
 | project Timestamp, Source="DeviceNetworkEvents", IP=RemoteIP, Identity=DeviceName, Detail=strcat(ActionType, " ", InitiatingProcessFileName, ":", LocalPort), Status=ActionType)
| summarize Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Identities=make_set(Identity, 20), Details=make_set(Detail, 20) by Source, IP
| order by Events desc
```

**Expected results:** 0 rows in an unaffected tenant. For retrospective coverage beyond 30 days, run the same logic in the Sentinel Data Lake against `AzureActivity`, `AADServicePrincipalSignInLogs`, `SigninLogs`, `AADNonInteractiveUserSignInLogs` and `DeviceNetworkEvents` (all `TimeGenerated`).

---

## Query 2: Service principals authenticating with raw scripting HTTP clients (python-requests fingerprint)

**Purpose:** Inventories non-managed-identity service principals that successfully obtained tokens with a raw scripting client UA (`python-requests`, `Python-urllib`, `httpx`, `aiohttp`, Go, curl), flags ARM as the resource, and highlights the exact Storm-3168 UA. Both compromised SPNs in the article used `python-requests/2.34.2`. This is a **triage inventory** — legitimate automation uses the same libraries — used to decide which workload identities to review for secret exposure and least privilege.  
**Severity:** Medium  
**MITRE:** T1078.004

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Triage inventory. Scripting user agents are common for legitimate SOC, DevOps and integration automation, and python-requests/2.34.2 is simply a current library version, so the UA is not detection-grade on its own. Promotion path: baseline (SPN, UA family, IP) over 30 days and alert only on a first-seen combination where the resource is Azure Resource Manager (ResourceId 797f4846-ba00-4fd7-ba43-dac1f8f63013), then correlate with Query 8."
-->

```kql
let lookback = 30d;
let ScriptUAs = dynamic(["python-requests", "Python-urllib", "python-httpx", "aiohttp", "Go-http-client", "curl/", "libcurl"]);
EntraIdSpnSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| where UserAgent has_any (ScriptUAs)
| where IsManagedIdentity == false
| extend IsARM = ResourceId == "797f4846-ba00-4fd7-ba43-dac1f8f63013" or ResourceDisplayName has "Service Management"
| extend ExactStormUA = UserAgent =~ "python-requests/2.34.2"
| summarize SignIns=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Resources=make_set(ResourceDisplayName, 10), ARMSignIns=countif(IsARM),
    IPs=make_set(IPAddress, 20), IPCount=dcount(IPAddress), Countries=make_set(Country, 10),
    UAs=make_set(UserAgent, 10), ExactStormUA=max(toint(ExactStormUA)), Tokens=dcount(UniqueTokenId)
    by ServicePrincipalName, ApplicationId, ServicePrincipalId
| extend RiskHint = case(ExactStormUA == 1 and ARMSignIns > 0, "HIGH: exact Storm-3168 UA to ARM",
                         ARMSignIns > 0 and IPCount > 3, "MEDIUM: scripting UA to ARM from multiple IPs",
                         ARMSignIns > 0, "MEDIUM: scripting UA to ARM",
                         "LOW: scripting UA, non-ARM resource")
| order by ExactStormUA desc, ARMSignIns desc, SignIns desc
```

**Expected results:** A short list of automation identities. Prioritize rows with `ARMSignIns > 0` and an IP/country set that does not match where the workload is hosted. For each ARM-capable SPN, confirm the owner, where its secret is stored, and whether its RBAC scope is justified. For >30 days, use `AADServicePrincipalSignInLogs` in the Data Lake (`UserAgent`, `IPAddress`, `ServicePrincipalId`, `ResultType`, `UniqueTokenIdentifier`).

---

## Query 3: Bulk destructive ARM burst across data and application resources

**Purpose:** Detects a single caller deleting many data/application/recovery resources in a short window — the core of the Storm-3168 impact phase (100+ storage deletes plus Key Vault, Function App, App Service plan and SQL in ~7 minutes). Counts **distinct targets** per 10-minute window, including failed attempts, since locks and API-version errors blocked part of the real attack.  
**Severity:** High  
**MITRE:** T1485, T1490

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Impact"
title: "Bulk Azure resource destruction by {{Caller}}"
impactedAssets:
  - type: user
    identifier: servicePrincipalId
    column: Caller
recommendedActions: "A single identity attempted to delete many Azure data/application/recovery resources within minutes. If the caller is a service principal, immediately disable it or remove its credentials, revoke its role assignments, and review AADServicePrincipalSignInLogs for the source IP and user agent. Check resource locks and soft-delete/recovery options for deleted storage accounts and Key Vaults. Hunt Queries 5-8 for key harvesting and new-IP sign-ins by the same identity."
adaptation_notes: "Threshold detection on AzureActivity (supported CD Sentinel table). Replace the final summarize with a variant that returns row-level columns, e.g. summarize (TimeGenerated, ReportId)=arg_max(TimeGenerated, CorrelationId), ResourcesTargeted=dcount(TargetResource) ... by Caller, bin(TimeGenerated, 10m), then filter on the threshold. For user callers, map Caller to accountUpn instead of servicePrincipalId. Validated: 0 rows at threshold 5 in a live tenant over 30d (AH) and ~80d (Data Lake), where the highest legitimate burst was 4 targets per window. Allowlist dedicated IaC principals by appId if teardown pipelines exceed the threshold."
-->

```kql
let lookback = 30d;
let window = 10m;
let minResources = 5;
let DestructiveOps = dynamic([
  "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE", "MICROSOFT.SQL/SERVERS/DATABASES/DELETE", "MICROSOFT.SQL/SERVERS/DELETE",
  "MICROSOFT.KEYVAULT/VAULTS/DELETE", "MICROSOFT.WEB/SITES/DELETE", "MICROSOFT.WEB/SERVERFARMS/DELETE",
  "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE", "MICROSOFT.COMPUTE/DISKS/DELETE", "MICROSOFT.COMPUTE/SNAPSHOTS/DELETE",
  "MICROSOFT.DOCUMENTDB/DATABASEACCOUNTS/DELETE", "MICROSOFT.DBFORPOSTGRESQL/FLEXIBLESERVERS/DELETE", "MICROSOFT.DBFORMYSQL/FLEXIBLESERVERS/DELETE",
  "MICROSOFT.AUTHORIZATION/LOCKS/DELETE", "MICROSOFT.RECOVERYSERVICES/VAULTS/DELETE",
  "MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPFABRICS/PROTECTIONCONTAINERS/PROTECTEDITEMS/DELETE",
  "MICROSOFT.DATAPROTECTION/BACKUPVAULTS/DELETE", "MICROSOFT.DATAPROTECTION/BACKUPVAULTS/BACKUPINSTANCES/DELETE",
  "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"]);
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue in~ (DestructiveOps)
| where ActivityStatusValue in~ ("Success", "Failure")
| extend TargetResource = tolower(tostring(parse_json(Authorization).scope))
| extend IsSPN = Caller matches regex @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
| summarize
    ResourcesTargeted = dcount(TargetResource),
    ResourceTypes = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Succeeded = dcountif(TargetResource, ActivityStatusValue =~ "Success"),
    Failed = dcountif(TargetResource, ActivityStatusValue =~ "Failure"),
    Subscriptions = dcount(SubscriptionId),
    ResourceGroups = dcount(ResourceGroup),
    CallerIPs = make_set(CallerIpAddress, 10),
    FirstOp = min(TimeGenerated), LastOp = max(TimeGenerated)
    by Caller, IsSPN, bin(TimeGenerated, window)
| where ResourcesTargeted >= minResources
| extend DurationMin = datetime_diff("second", LastOp, FirstOp) / 60.0
| extend Severity = case(ResourceTypes >= 3 or ResourcesTargeted >= 20, "High", IsSPN and ResourcesTargeted >= 10, "High", "Medium")
| project-away TimeGenerated
| order by ResourcesTargeted desc
```

**Expected results:** 0 rows in normal operation. A hit with `IsSPN == true`, `ResourceTypes >= 2`, and a mix of `Succeeded`/`Failed` is the Storm-3168 pattern. Lower `minResources` to 3 for small estates; raise it or allowlist IaC appIds if planned teardown pipelines exceed it.

---

## Query 4: Resource-lock and backup/recovery protection tampering

**Purpose:** Surfaces deletion (successful or blocked) of resource locks, Recovery Services / Backup vaults, protected items, backup policies, Site Recovery replication items, snapshots and restore points — the T1490 recovery-inhibition behavior Storm-3168 attempted against Site Recovery and Azure Backup protection locks. Microsoft first-party services (Backup Management Service, Hyper-V Recovery Manager, Azure Machine Learning) are excluded by `appid` claim because they prune recovery artifacts by retention.  
**Severity:** High  
**MITRE:** T1490

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Impact"
title: "Azure recovery protection tampering by {{Caller}}"
impactedAssets:
  - type: user
    identifier: servicePrincipalId
    column: Caller
recommendedActions: "An identity deleted or attempted to delete resource locks or backup/Site Recovery protection. Confirm with the resource owner whether this was a planned change. If not, disable the identity, restore the lock, verify Recovery Services soft delete and immutability are enabled, and hunt Query 3 and Query 5 for the same caller in the surrounding hours."
adaptation_notes: "Low-volume, high-value operations - suitable as a scheduled rule. For CD, keep row-level output (project TimeGenerated, Caller, OperationNameValue, TargetResource, CallerIpAddress, ActivityStatusValue, ReportId = CorrelationId) instead of the hunting summarize. In the validation tenant, excluding the Backup Management Service appId removed ~360 restore-point retention deletions per month; the residual hits were planned administrative lock removals, so expect to review occasional change-window activity. Map user callers to accountUpn."
-->

```kql
let lookback = 30d;
// Microsoft first-party services (global appIds): Backup Management Service, Hyper-V Recovery Manager (Site Recovery), Azure Machine Learning
let FirstPartyAppIds = dynamic(["262044b1-e2ce-469f-a196-69ab7ada62d3", "b8340c3b-9267-498f-b21a-15d5547fd85e", "0736f41a-0425-4b46-bdb5-1563eff02385"]);
let RecoveryTamperOps = dynamic([
  "MICROSOFT.AUTHORIZATION/LOCKS/DELETE",
  "MICROSOFT.RECOVERYSERVICES/VAULTS/DELETE",
  "MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPCONFIG/WRITE",
  "MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPFABRICS/PROTECTIONCONTAINERS/PROTECTEDITEMS/DELETE",
  "MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPPOLICIES/DELETE",
  "MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPRESOURCEGUARDPROXIES/DELETE",
  "MICROSOFT.RECOVERYSERVICES/VAULTS/REPLICATIONFABRICS/REPLICATIONPROTECTIONCONTAINERS/REPLICATIONPROTECTEDITEMS/DELETE",
  "MICROSOFT.DATAPROTECTION/BACKUPVAULTS/DELETE",
  "MICROSOFT.DATAPROTECTION/BACKUPVAULTS/BACKUPINSTANCES/DELETE",
  "MICROSOFT.DATAPROTECTION/BACKUPVAULTS/BACKUPPOLICIES/DELETE",
  "MICROSOFT.COMPUTE/SNAPSHOTS/DELETE",
  "MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/DELETE",
  "MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/RESTOREPOINTS/DELETE"]);
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue in~ (RecoveryTamperOps)
| where ActivityStatusValue in~ ("Success", "Failure")
| extend AppId = tostring(parse_json(Claims).appid), TargetResource = tolower(tostring(parse_json(Authorization).scope))
| where AppId !in (FirstPartyAppIds)
| extend ErrCode = tostring(parse_json(tostring(parse_json(Properties).statusMessage)).error.code)
| extend RecoveryThemed = TargetResource has_any ("backup", "recovery", "asr", "siterecovery", "terraform", "tfstate", "vault")
| summarize Attempts = count(),
    Succeeded = countif(ActivityStatusValue =~ "Success"),
    Failed = countif(ActivityStatusValue =~ "Failure"),
    DistinctTargets = dcount(TargetResource),
    RecoveryThemedTargets = dcountif(TargetResource, RecoveryThemed),
    ErrorCodes = make_set_if(ErrCode, isnotempty(ErrCode), 5),
    SampleTargets = make_set(TargetResource, 10),
    CallerIPs = make_set(CallerIpAddress, 10),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Caller, AppId, OperationNameValue
| extend IsSPN = Caller matches regex @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
| extend Priority = case(Failed > 0 and IsSPN, "High", RecoveryThemedTargets > 0 or DistinctTargets >= 3, "Medium", "Low")
| order by Failed desc, DistinctTargets desc
```

**Expected results:** A small number of rows. Planned lock removals during change windows appear as `Succeeded` from known administrators or IaC principals. Escalate any **failed** attempt by a service principal (`Priority == "High"`), and any Recovery Services / Data Protection deletion not tied to a change ticket.

---

## Query 5: Storage account key harvesting burst (ListKeys across many accounts)

**Purpose:** Detects one identity retrieving access keys (`listKeys`, `regenerateKey`, `listAccountSas`) for many storage accounts within an hour — Storm-3168's credential-collection phase (30+ successful `ListKeys`, including Site Recovery storage). Failed attempts are kept: the actor's destruction began immediately after a `ListKeys` against a **non-existent** account.  
**Severity:** High  
**MITRE:** T1552, T1530

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Storage key harvesting across many accounts by {{Caller}}"
impactedAssets:
  - type: user
    identifier: servicePrincipalId
    column: Caller
recommendedActions: "An identity retrieved access keys for many storage accounts in a short window. Rotate the keys of every listed storage account, disable shared-key authorization where possible, disable or rotate the caller's credentials, and review StorageBlobLogs for data access using account keys from unfamiliar IPs."
adaptation_notes: "Threshold detection on AzureActivity. For CD, use summarize (TimeGenerated, ReportId)=arg_max(TimeGenerated, CorrelationId), AccountsTargeted=dcount(StorageAccount) by Caller, AppId, bin(TimeGenerated, 1h) and filter AccountsTargeted >= threshold. Validated: 0 rows at threshold 5 over 30d (AH) and ~80d (Data Lake) in a live tenant whose highest legitimate automation read keys for 4 accounts per hour. Microsoft first-party appIds are excluded."
-->

```kql
let lookback = 30d;
let window = 1h;
let minAccounts = 5;
// Microsoft first-party services (global appIds): Backup Management Service, Hyper-V Recovery Manager (Site Recovery), Azure Machine Learning
let FirstPartyAppIds = dynamic(["262044b1-e2ce-469f-a196-69ab7ada62d3", "b8340c3b-9267-498f-b21a-15d5547fd85e", "0736f41a-0425-4b46-bdb5-1563eff02385"]);
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue in~ ("MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION", "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTACCOUNTSAS/ACTION")
| where ActivityStatusValue in~ ("Success", "Failure")
| extend AppId = tostring(parse_json(Claims).appid), IdType = tostring(parse_json(Claims).idtyp)
| where AppId !in (FirstPartyAppIds)
| extend TargetResource = tolower(tostring(parse_json(Authorization).scope))
| extend StorageAccount = tostring(split(TargetResource, "/")[8])
| summarize KeyRequests = count(),
    AccountsTargeted = dcount(StorageAccount),
    Succeeded = countif(ActivityStatusValue =~ "Success"),
    Failed = countif(ActivityStatusValue =~ "Failure"),
    ResourceGroups = dcount(ResourceGroup),
    Subscriptions = dcount(SubscriptionId),
    RecoveryThemed = dcountif(StorageAccount, StorageAccount has_any ("asr", "backup", "recovery", "tfstate", "terraform")),
    SampleAccounts = make_set(StorageAccount, 15),
    CallerIPs = make_set(CallerIpAddress, 10),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Caller, AppId, IdType, bin(TimeGenerated, window)
| where AccountsTargeted >= minAccounts
| project-away TimeGenerated
| order by AccountsTargeted desc
```

**Expected results:** 0 rows normally. Any hit where `IdType == "app"`, `Subscriptions > 1` or `RecoveryThemed > 0` warrants immediate key rotation. Some storage-management tools legitimately enumerate keys; allowlist their appIds only after confirming ownership.

---

## Query 6: Destruction-then-harvest chain by the same workload identity

**Purpose:** Correlates a service principal's destructive burst with credential/secret retrieval (storage, Cosmos DB, App Service publishing profiles and settings) by the same identity within ±2 hours — the article's sequence of deletion followed ~30 minutes later by mass `ListKeys`. The chain is higher-fidelity than either stage alone.  
**Severity:** High  
**MITRE:** T1485, T1552

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Two-stage correlation (self-join on AzureActivity with a time window) - better as a scheduled hunt or Sentinel analytics rule than a Defender custom detection. Validated before tuning it surfaced an IaC service principal whose VM teardown and key reads co-occurred (3 destroy targets, 5 harvest targets); the minDestroyTargets = 5 / minHarvestTargets = 3 thresholds removed it. Queries 3 and 5 provide the CD-ready single-stage coverage."
-->

```kql
let lookback = 30d;
let chainWindow = 2h;
let minDestroyTargets = 5;
let minHarvestTargets = 3;
let FirstPartyAppIds = dynamic(["262044b1-e2ce-469f-a196-69ab7ada62d3", "b8340c3b-9267-498f-b21a-15d5547fd85e", "0736f41a-0425-4b46-bdb5-1563eff02385"]);
let Base = AzureActivity
| where TimeGenerated > ago(lookback)
| where ActivityStatusValue in~ ("Success", "Failure")
| extend AppId = tostring(parse_json(Claims).appid), TargetResource = tolower(tostring(parse_json(Authorization).scope))
| where AppId !in (FirstPartyAppIds)
| where Caller matches regex @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
let Destroy = Base
| where OperationNameValue endswith "/DELETE"
| where OperationNameValue has_any ("STORAGEACCOUNTS/DELETE", "SERVERS/DATABASES/DELETE", "KEYVAULT/VAULTS/DELETE", "WEB/SITES/DELETE", "WEB/SERVERFARMS/DELETE", "AUTHORIZATION/LOCKS/DELETE", "RECOVERYSERVICES/VAULTS", "DATAPROTECTION/BACKUPVAULTS", "VIRTUALMACHINES/DELETE", "RESOURCEGROUPS/DELETE")
| summarize DestroyStart = min(TimeGenerated), DestroyEnd = max(TimeGenerated), DestroyTargets = dcount(TargetResource),
            DestroyFailed = dcountif(TargetResource, ActivityStatusValue =~ "Failure"), DestroyOps = make_set(OperationNameValue, 10)
    by Caller, AppId, Day = bin(TimeGenerated, 1d)
| where DestroyTargets >= minDestroyTargets or DestroyFailed >= minHarvestTargets;
let Harvest = Base
| where OperationNameValue has_any ("/LISTKEYS/ACTION", "/LISTACCOUNTSAS/ACTION", "/LISTCONNECTIONSTRINGS/ACTION", "/CONFIG/LIST/ACTION", "/PUBLISHXML/ACTION")
| project HarvestTime = TimeGenerated, Caller, HarvestTarget = TargetResource, HarvestOp = OperationNameValue;
Destroy
| join kind=inner Harvest on Caller
| where HarvestTime between ((DestroyStart - chainWindow) .. (DestroyEnd + chainWindow))
| summarize HarvestTargets = dcount(HarvestTarget), HarvestOps = make_set(HarvestOp, 10), FirstHarvest = min(HarvestTime), LastHarvest = max(HarvestTime)
    by Caller, AppId, DestroyStart, DestroyEnd, DestroyTargets, DestroyFailed, DestroyOpsText = tostring(DestroyOps)
| where HarvestTargets >= minHarvestTargets
| extend HarvestAfterDestroy = FirstHarvest > DestroyEnd, ChainScore = DestroyTargets + HarvestTargets + DestroyFailed
| order by ChainScore desc
```

**Expected results:** 0 rows normally. `HarvestAfterDestroy == true` with recovery-themed harvest targets is a near-exact match to the article's sequence. Lower both thresholds to 1 for an exploratory review of every SPN that both deletes and reads secrets.

---

## Query 7: Guardrail-blocked destructive attempts (locks, deletion protection, bad API versions, non-existent targets)

**Purpose:** Storm-3168's automation produced distinctive failures: `ScopeLocked` / deletion-protection rejections on locked storage accounts and recovery locks, SQL deletes rejected for an **unsupported API version**, and a `ListKeys` against a **non-existent** storage account. A burst of such failures from one identity against data or recovery resources is a strong sign of automated, poorly-targeted destruction — and proof that guardrails are doing their job.  
**Severity:** High  
**MITRE:** T1485, T1490

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Impact"
title: "Guardrail-blocked destructive Azure attempts by {{Caller}}"
impactedAssets:
  - type: user
    identifier: servicePrincipalId
    column: Caller
recommendedActions: "Multiple destructive or key-retrieval operations by one identity were blocked by locks, deletion protection, invalid API versions, or non-existent targets. This indicates automated destruction attempts. Disable the caller, review which attempts succeeded in the same window (Query 3), and verify that locks and soft delete remain in place on the targeted resources."
adaptation_notes: "Threshold detection on AzureActivity failures. For CD, return arg_max(TimeGenerated, CorrelationId) as (TimeGenerated, ReportId) per Caller/window. Role-assignment deletions are excluded because Terraform teardown routinely hits ScopeLocked on them - in the validation tenant this exclusion removed the only pre-tuning hit (an IaC principal's lock-blocked teardown). Error codes are parsed from Properties.statusMessage."
-->

```kql
let lookback = 30d;
let window = 1h;
let minFailedTargets = 3;
let FirstPartyAppIds = dynamic(["262044b1-e2ce-469f-a196-69ab7ada62d3", "b8340c3b-9267-498f-b21a-15d5547fd85e", "0736f41a-0425-4b46-bdb5-1563eff02385"]);
let GuardrailErrors = dynamic(["ScopeLocked", "ResourceDeletionProtected", "DeleteProtectionEnabled", "InvalidApiVersionParameter", "NoRegisteredProviderFound", "InvalidResourceType", "ResourceNotFound", "StorageAccountNotFound", "AuthorizationFailed", "LinkedAuthorizationFailed", "UserErrorSoftDeleteStateCannotBeChanged"]);
let DataAndRecoveryTypes = dynamic(["MICROSOFT.STORAGE/STORAGEACCOUNTS", "MICROSOFT.SQL/SERVERS", "MICROSOFT.KEYVAULT/VAULTS", "MICROSOFT.WEB/SITES", "MICROSOFT.WEB/SERVERFARMS", "MICROSOFT.COMPUTE/VIRTUALMACHINES", "MICROSOFT.COMPUTE/DISKS", "MICROSOFT.COMPUTE/SNAPSHOTS", "MICROSOFT.DOCUMENTDB/DATABASEACCOUNTS/DELETE", "MICROSOFT.AUTHORIZATION/LOCKS", "MICROSOFT.RECOVERYSERVICES", "MICROSOFT.DATAPROTECTION", "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS"]);
AzureActivity
| where TimeGenerated > ago(lookback)
| where ActivityStatusValue =~ "Failure"
| where OperationNameValue endswith "/DELETE" or OperationNameValue has "/LISTKEYS/ACTION" or OperationNameValue has "BACKUPCONFIG/WRITE"
| where OperationNameValue has_any (DataAndRecoveryTypes)
| where OperationNameValue !has "ROLEASSIGNMENTS"
| extend AppId = tostring(parse_json(Claims).appid), TargetResource = tolower(tostring(parse_json(Authorization).scope))
| where AppId !in (FirstPartyAppIds)
| extend P = parse_json(Properties)
| extend ErrCode = tostring(parse_json(tostring(P.statusMessage)).error.code), HttpStatus = tostring(P.statusCode)
| where ErrCode in~ (GuardrailErrors) or HttpStatus in~ ("Conflict", "NotFound", "Forbidden")
| summarize FailedTargets = dcount(TargetResource), Attempts = count(),
    ErrorCodes = make_set(ErrCode, 10), Operations = make_set(OperationNameValue, 10),
    ResourceGroups = dcount(ResourceGroup), SampleTargets = make_set(TargetResource, 10),
    CallerIPs = make_set(CallerIpAddress, 10), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Caller, AppId, bin(TimeGenerated, window)
| where FailedTargets >= minFailedTargets
| extend LockHits = set_has_element(ErrorCodes, "ScopeLocked"),
         ApiVersionFail = set_has_element(ErrorCodes, "InvalidApiVersionParameter") or set_has_element(ErrorCodes, "NoRegisteredProviderFound"),
         NotFoundProbe = set_has_element(ErrorCodes, "ResourceNotFound") or set_has_element(ErrorCodes, "StorageAccountNotFound")
| project-away TimeGenerated
| order by FailedTargets desc
```

**Expected results:** 0 rows normally. `LockHits` plus `ApiVersionFail` from one SPN in the same hour is highly characteristic of Storm-3168-style scripted destruction. The exact ARM error code for an unsupported API version can vary by provider — review `ErrorCodes` on any hit.

---

## Query 8: Service principal used from a new IP, followed by destructive or secret-retrieval ARM operations

**Purpose:** Models the suspected initial access — a leaked client secret used from attacker infrastructure. Finds service principals that signed in successfully from an IP not seen for that SPN in the prior baseline window, then performed deletes, key/secret retrieval, or role-assignment writes against ARM **from that same IP**. This bridges the identity plane (where the UA/IP live) and the control plane (where the damage happens).  
**Severity:** High  
**MITRE:** T1078.004, T1552.001, T1485, T1098.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline (leftanti on 30d history) plus cross-table join - not expressible as a Defender custom detection. Run as a scheduled hunt or Sentinel analytics rule. Pre-tuning it matched a weekly scheduled automation SPN hosted on rotating Azure consumption-plan egress IPs performing one ListKeys; the 'Deletes > 0 or KeyReads >= 3 or ArmTargets >= 3' filter removes that class. SPNs on serverless/rotating egress will always look 'new-IP' - consider excluding by appId after owner verification, or enrich IP ownership (ASN) and ignore Microsoft-owned egress only for identities whose workload is known to run in Azure."
-->

```kql
let lookback = 7d;
let baseline = 30d;
let FirstPartyAppIds = dynamic(["262044b1-e2ce-469f-a196-69ab7ada62d3", "b8340c3b-9267-498f-b21a-15d5547fd85e", "0736f41a-0425-4b46-bdb5-1563eff02385"]);
let KnownSpnIPs = EntraIdSpnSignInEvents
| where Timestamp between (ago(baseline) .. ago(lookback))
| where ErrorCode == 0
| distinct ServicePrincipalId, IPAddress;
let NewIpSignIns = EntraIdSpnSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0 and IsManagedIdentity == false
| join kind=leftanti KnownSpnIPs on ServicePrincipalId, IPAddress
| summarize FirstNewIpSignIn = min(Timestamp), SignIns = count(), Tokens = dcount(UniqueTokenId), UAs = make_set(UserAgent, 5), Countries = make_set(Country, 5)
    by ServicePrincipalId, ServicePrincipalName, ApplicationId, IPAddress;
let RiskyArm = AzureActivity
| where TimeGenerated > ago(lookback)
| where ActivityStatusValue in~ ("Success", "Failure")
| extend AppId = tostring(parse_json(Claims).appid), TargetResource = tolower(tostring(parse_json(Authorization).scope))
| where AppId !in (FirstPartyAppIds)
| where OperationNameValue endswith "/DELETE" or OperationNameValue has_any ("/LISTKEYS/ACTION", "/LISTACCOUNTSAS/ACTION", "/LISTCONNECTIONSTRINGS/ACTION", "/CONFIG/LIST/ACTION", "/PUBLISHXML/ACTION", "ROLEASSIGNMENTS/WRITE")
| summarize ArmOps = count(), ArmTargets = dcount(TargetResource),
            Deletes = dcountif(TargetResource, OperationNameValue endswith "/DELETE"),
            KeyReads = dcountif(TargetResource, OperationNameValue contains "/LIST" or OperationNameValue contains "PUBLISHXML"),
            Failed = countif(ActivityStatusValue =~ "Failure"),
            OpTypes = make_set(OperationNameValue, 10), FirstArm = min(TimeGenerated), LastArm = max(TimeGenerated)
    by Caller, CallerIpAddress;
NewIpSignIns
| join kind=inner RiskyArm on $left.ServicePrincipalId == $right.Caller, $left.IPAddress == $right.CallerIpAddress
| where Deletes > 0 or KeyReads >= 3 or ArmTargets >= 3
| project FirstNewIpSignIn, ServicePrincipalName, ApplicationId, ServicePrincipalId, IPAddress, Countries, UAs, SignIns, Tokens,
          ArmOps, ArmTargets, Deletes, KeyReads, Failed, OpTypes, FirstArm, LastArm
| order by Deletes desc, KeyReads desc
```

**Expected results:** 0 rows normally. A hit with a non-cloud-provider or unexpected-country IP, a scripting UA, multiple `Tokens`, and deletes/key reads is the Storm-3168 pattern — disable the SPN, remove all its credentials (secrets **and** certificates/federated credentials), and search code repositories and issue trackers for the leaked client ID. For >30d baselines, use `AADServicePrincipalSignInLogs` in the Data Lake.

---

## Query 9: App Service probing for LangFlow, PHP-CGI, WordPress and web-shell paths

**Purpose:** Storm-3168 infrastructure has probed Azure App Service apps for LangFlow's code-validation endpoint (`/api/v1/validate/code`, an unauthenticated-RCE class of target), PHP-CGI argument injection, WordPress administration and web-shell-like paths. Groups by client IP, flags each probe family and any **2xx responses**, and marks the published IOC IPs.  
**Severity:** Medium  
**MITRE:** T1190, T1595.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Requires App Service diagnostic settings streaming AppServiceHTTPLogs to the workspace; in the validation workspace the table exists but contained 0 rows, so the query was executed for syntax only and could not be fidelity-tuned. Internet-facing apps receive constant opportunistic scanning for these paths, so treat as hunting: the actionable signal is a 2xx on /api/v1/validate/code or php-cgi, or any request from the published IOC IPs. If WAF (Front Door / Application Gateway) is used instead, port the path list to those logs."
-->

```kql
let lookback = 30d;
let IOC_IPs = dynamic(["45.131.66.106", "34.153.223.102", "64.20.53.230"]);
let ProbePaths = dynamic(["/api/v1/validate/code", "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/wp-config", "/php-cgi", "/cgi-bin/php", "php-cgi.exe", "/vendor/phpunit", "/.env", "/shell.php", "/cmd.php", "/wso.php", "/c99.php", "/r57.php", "/alfa.php"]);
AppServiceHTTPLogs
| where TimeGenerated > ago(lookback)
| where CsUriStem has_any (ProbePaths) or CsUriQuery has_any ("allow_url_include", "auto_prepend_file", "-d+allow_url_include") or CIp in (IOC_IPs)
| extend IsLangflowRCE = CsUriStem has "/api/v1/validate/code",
         IsPhpCgi = CsUriStem has_any ("php-cgi", "/cgi-bin/php") or CsUriQuery has_any ("allow_url_include", "auto_prepend_file"),
         IsWordPress = CsUriStem has_any ("/wp-admin", "/wp-login.php", "/xmlrpc.php", "/wp-config"),
         IsIOC = CIp in (IOC_IPs)
| summarize Requests = count(), Paths = make_set(CsUriStem, 20), Methods = make_set(CsMethod, 5),
    StatusCodes = make_set(ScStatus, 10), SuccessHits = countif(ScStatus between (200 .. 299)),
    Apps = make_set(CsHost, 10), UAs = make_set(UserAgent, 5),
    LangflowProbe = max(toint(IsLangflowRCE)), PhpCgiProbe = max(toint(IsPhpCgi)), WordPressProbe = max(toint(IsWordPress)), IOCMatch = max(toint(IsIOC)),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by CIp
| extend ProbeFamilies = LangflowProbe + PhpCgiProbe + WordPressProbe
| order by IOCMatch desc, ProbeFamilies desc, SuccessHits desc, Requests desc
```

**Expected results:** Background scanning noise on most internet-facing apps. Escalate `IOCMatch == 1`, and any `SuccessHits > 0` on the LangFlow or PHP-CGI paths (check whether the app actually runs LangFlow/PHP). The article found no App Service → ARM credential path in the victim, but a compromised app's managed identity or app settings could provide one — pivot to Query 8 for that app's identity.

---

## Query 10: Defender for Cloud alerts matching the Storm-3168 detection set

**Purpose:** Pulls alerts whose titles match the Defender for Cloud detections Microsoft lists for this campaign (Defender for Resource Manager, Storage, Key Vault, Databases, App Service, DNS), plus ARM/Key Vault/workload-identity keyword matches, with their evidence entities — flagging any that include the published IOC IPs. This is the only coverage for the read-only discovery phase that the Activity Log does not record.  
**Severity:** Medium  
**MITRE:** T1526, T1078.004, T1530

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Alert-correlation triage query over existing alerts - the underlying Defender for Cloud detections already alert; re-alerting would duplicate. Coverage depends on enabling Defender for Resource Manager, Storage, Key Vault, App Service and Databases plans. Validated: executed cleanly; 0 matching alerts in the validation tenant's 30-day window (Defender for Cloud alerts of other types were present, confirming the table was populated)."
-->

```kql
let lookback = 30d;
let ArticleAlertTitles = dynamic([
  "Azure Resource Manager operation from suspicious proxy IP address", "Unusual operation pattern in a key vault", "High volume of operations in a key vault",
  "Unusual application accessed a key vault", "Access from a suspicious IP address", "Access from a known suspicious IP address to a sensitive blob container",
  "Access from a known suspicious IP address to a sensitive storage file share", "Unusual amount of data extracted from a storage blob container",
  "Unusual number of blobs extracted from a storage blob container", "Unusual amount of data extracted from a sensitive blob container",
  "Unusual amount of data extracted from a storage file share", "Unusual number of files extracted from a storage file share",
  "Possible data exfiltration detected", "An abnormally large number of rows were extracted from an SQL server",
  "Communication with suspicious domain identified by threat intelligence", "Access from an unusual location"]);
let ArmKeywords = dynamic(["Resource Manager", "mass deletion", "Suspicious resource deletion", "ListKeys", "storage account keys", "key vault", "Workload identity"]);
let IOC_IPs = dynamic(["45.131.66.106", "34.153.223.102", "64.20.53.230"]);
AlertInfo
| where Timestamp > ago(lookback)
| where Title has_any (ArticleAlertTitles) or Title has_any (ArmKeywords)
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | summarize Entities = make_set(strcat(EntityType, ":", coalesce(AccountName, AccountObjectId, RemoteIP, DeviceName, CloudResource, tostring(ApplicationId))), 15),
                IPs = make_set_if(RemoteIP, isnotempty(RemoteIP), 10)
        by AlertId
  ) on AlertId
| extend IOCMatch = array_length(set_intersect(IPs, IOC_IPs)) > 0
| summarize Alerts = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Severities = make_set(Severity),
    SampleEntities = make_set(Entities, 10), IOCMatch = max(toint(IOCMatch))
    by Title, ServiceSource, Category
| order by IOCMatch desc, Alerts desc
```

**Expected results:** Ideally 0. Any "Azure Resource Manager operation from suspicious proxy IP address" or Key Vault anomaly naming a service principal should be pivoted into Queries 3–8 for that identity. A 0 result is only meaningful if the relevant Defender for Cloud plans are enabled.

---

## General Tuning Notes

1. **IOC refresh.** The three IPs are the only published indicators and actor infrastructure rotates. Treat Query 1 as a point-in-time sweep; for durable coverage join `AzureActivity.CallerIpAddress` / `EntraIdSpnSignInEvents.IPAddress` to `ThreatIntelIndicators` rather than maintaining a static list.

2. **The Activity Log is write-only.** Discovery (ARM GET) is not logged in `AzureActivity`; Queries 3–8 begin at the first write/action. Enable Defender for Resource Manager (Query 10) for read-phase anomaly coverage.

3. **Exclude first-party services by `appid` claim.** Backup Management Service (`262044b1-…`), Hyper-V Recovery Manager (`b8340c3b-…`) and Azure Machine Learning (`0736f41a-…`) are global Microsoft appIds; their per-tenant object IDs differ. Add other first-party services you observe, but never allowlist a customer-owned SPN without confirming its owner.

4. **IaC principals need a decision, not a blanket allowlist.** Terraform/Bicep pipelines tear down locks, VMs and role assignments and read keys. Allowlisting them in Queries 3–7 is reasonable after verification, but a leaked IaC secret is precisely this attack — keep them in scope for Query 8 (new IP) and Query 2 (UA inventory).

5. **Portable resource IDs.** All queries derive the target from `parse_json(Authorization).scope` because `_ResourceId`/`ResourceId` are absent from `AzureActivity` in the Sentinel Data Lake. The queries run unchanged in both tools; swap `EntraIdSpnSignInEvents` for `AADServicePrincipalSignInLogs` (and `Timestamp` → `TimeGenerated`, `ErrorCode == 0` → `ResultType == "0"`) for Data Lake runs beyond 30 days.

6. **Thresholds.** Queries 3, 5 and 7 default to 5 / 5 / 3 distinct targets per window. The real attack exceeded these by an order of magnitude (100+ deletes, 30+ key reads), so thresholds can be raised in large estates without losing the pattern.

7. **Prevention matters more than detection here.** The attack succeeded on existing RBAC and completed in minutes. Locks and storage deletion protection demonstrably stopped part of it. Prioritize: rotate/remove long-lived SPN secrets (prefer managed identities or federated credentials), least-privilege RBAC, `CanNotDelete` locks and soft delete/immutability on backup and recovery resources, and secret scanning for public repositories and issue histories.

8. **CD-readiness summary.** **Queries 3, 4, 5 and 7 are `cd_ready: true`** (single-table `AzureActivity` threshold/low-volume rules, scheduled 1H; adapt the final `summarize` to `arg_max(TimeGenerated, CorrelationId)` for row-level output). **Queries 1, 2, 6, 8, 9 and 10 are `cd_ready: false`** — multi-table IOC sweep (split per table to promote), UA inventory, cross-stage joins, a telemetry-dependent web-log hunt, and alert correlation. All ten queries were executed against live Advanced Hunting during authoring; the Query 3 and Query 5 thresholds were additionally sanity-checked with a simplified per-hour variant over ~80 days of `AzureActivity` in the Sentinel Data Lake. **Query 9 is syntax-validated only** — `AppServiceHTTPLogs` held no data in the validation workspace.

---

## References

- Microsoft Security Research — [Storm-3168: Agentic-driven cloud attacks using compromised service principals (2026-09-25)](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
- MITRE ATT&CK — [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- MITRE ATT&CK — [T1526 Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)
- MITRE ATT&CK — [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/)
- MITRE ATT&CK — [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- MITRE ATT&CK — [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- MITRE ATT&CK — [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) / [T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- MITRE ATT&CK — [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- Microsoft Learn — [Lock resources to prevent deletion (Azure Storage)](https://learn.microsoft.com/en-us/azure/storage/common/lock-account-resource?tabs=portal)
- Microsoft Learn — [Microsoft Defender for Cloud overview](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)
- Microsoft Learn — [Microsoft Entra Workload ID](https://learn.microsoft.com/en-us/entra/workload-id/)
- Microsoft Learn — [Azure Backup data protection best practices](https://learn.microsoft.com/en-us/azure/backup/azure-backup-data-protection-best-practices)
- Companion files: [`queries/identity/service_principal_scope_drift.md`](../../identity/service_principal_scope_drift.md), [`queries/identity/app_registration_abuse_chains.md`](../../identity/app_registration_abuse_chains.md), [`queries/cloud/azure_blob_storage_defense_program.md`](../../cloud/azure_blob_storage_defense_program.md)
