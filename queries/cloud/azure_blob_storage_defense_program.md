# Azure Blob Storage — Defensive Program & Threat Hunting Campaign

**Created:** 2026-02-12  
**Platform:** Both  
**Tables:** StorageBlobLogs, AzureActivity, StorageMalwareScanningResults, CloudStorageAggregatedEvents, SecurityAlert, SecurityIncident, AuditLogs, SigninLogs, AADNonInteractiveUserSignInLogs  
**Keywords:** blob storage, Azure Storage, exfiltration, credential access, SAS token, storage account key, AzCopy, reconnaissance, data destruction, ransomware, malware upload, anonymous access, container enumeration, lateral movement, defense evasion, data poisoning, C2, command and control, phishing hosting  
**MITRE:** T1593.002, T1594, T1595.003, T1596, T1596.001, T1583.004, T1566.001, T1566.002, T1078.004, T1098.001, T1562.001, T1562.007, T1528, T1003, T1040, T1580, T1619, T1021.007, T1074.002, T1530, T1105, T1567.002, T1030, T1020, T1537, T1485, T1486, T1565  
**Timeframe:** Last 30 days (configurable)

---

## Executive Summary

Microsoft Threat Intelligence published an [in-depth analysis](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/) of threat activity targeting Azure Blob Storage across the **full MITRE ATT&CK kill chain** — from reconnaissance through impact. Azure Blob Storage is a high-value target due to its role in storing massive amounts of unstructured data for AI, HPC, analytics, media, backup, and IoT workloads. Threat actors actively seek opportunities to compromise environments that host downloadable media or maintain large-scale data repositories.

This document synthesizes that intelligence with official Microsoft security recommendations and Defender for Cloud detection capabilities to deliver:

1. **A prioritized defensive program** mapped to the attack chain
2. **Detection & alerting configuration** via Defender for Storage
3. **KQL hunting queries** for proactive threat hunting across Sentinel Data Lake and Defender XDR Advanced Hunting
4. **Posture assessment checklist** for organizational readiness

**Source:** [Inside the attack chain: Threat activity targeting Azure Blob Storage](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/) — Microsoft Threat Intelligence, October 2025

---

## Part 1: Attack Chain Summary

### Attack Flow — Azure Blob Storage

```
1. 🔍 Reconnaissance — DNS/HTTP probing for *.blob.core.windows.net, brute-force storage names
2. 🏗️ Resource Development — Host phishing pages, malicious executables on misconfigured containers
3. 🚪 Initial Access — Exploit blob-triggered Functions/Logic Apps, compromised SAS/keys
4. 🔗 Persistence — RBAC manipulation, long-lived SAS, anonymous access, SFTP backdoors
5. 🛡️ Defense Evasion — Disable logging, modify firewall rules, add permissive IP ranges
6. 🔑 Credential Access — Token/key extraction, Cloud Shell abuse, network sniffing
7. 🗺️ Discovery — Enumerate subscriptions, containers, blobs, metadata, policies
8. ↔️ Lateral Movement — Trigger Functions via blob events, inject into data pipelines
9. 📦 Collection — Copy/export data to staging containers using AzCopy/REST API
10. 📡 C2 — Blob metadata as covert beacon channel, object replication for payload distribution
11. 📤 Exfiltration — Static website $web container, cross-subscription transfer, AzCopy at scale
12. 💥 Impact — Mass DeleteBlob/DeleteContainer, ransomware encryption, data manipulation
```

### MITRE ATT&CK Mapping

| Phase | Techniques |
|-------|-----------|
| **Reconnaissance** | T1593.002 (Search Engines), T1594 (Victim Websites), T1595.003 (Wordlist Scanning), T1596 (Open Technical DBs), T1596.001 (DNS/Passive DNS) |
| **Resource Development** | T1583.004 (Acquire Infrastructure: Server) |
| **Initial Access** | T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link), T1078.004 (Valid Accounts: Cloud) |
| **Persistence** | T1098.001 (Account Manipulation: Additional Cloud Credentials) |
| **Defense Evasion** | T1562.001 (Impair Defenses: Disable Tools), T1562.007 (Disable Cloud Firewall) |
| **Credential Access** | T1528 (Steal Application Access Token), T1003 (OS Credential Dumping), T1040 (Network Sniffing) |
| **Discovery** | T1580 (Cloud Infrastructure Discovery), T1619 (Cloud Storage Object Discovery) |
| **Lateral Movement** | T1021.007 (Remote Services: Cloud Services) |
| **Collection** | T1074.002 (Remote Data Staging), T1530 (Data from Cloud Storage) |
| **C2** | T1105 (Ingress Tool Transfer) |
| **Exfiltration** | T1567.002 (Exfiltration to Cloud Storage), T1030 (Data Transfer Size Limits), T1020 (Automated Exfiltration), T1537 (Transfer Data to Cloud Account) |
| **Impact** | T1485 (Data Destruction), T1486 (Data Encrypted for Impact), T1565 (Data Manipulation) |

---

## Part 2: Defensive Program — Prioritized Actions

### 🔴 Tier 1 — Critical (Prevent Core Attack Vectors)

#### 1.1 Disable Anonymous/Public Access to Blob Containers

**Impact:** Eliminates the most exploited misconfiguration — publicly accessible containers  
**MITRE:** T1530, T1593.002, T1595.003

| Action | Detail | Reference |
|--------|--------|-----------|
| Disable anonymous read access at account level | Storage Account → Configuration → Allow Blob anonymous access → **Disabled** | [Prevent anonymous read access](https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent) |
| Audit existing containers for public access | Check all containers for "Container" or "Blob" public access level | [Remediate anonymous read access](https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent) |
| Use Azure Policy to enforce | Built-in policy: "Storage accounts should prevent public access" | [Azure Policy for Storage](https://learn.microsoft.com/azure/storage/common/storage-network-security) |
| Monitor compliance via Defender for Cloud | Security recommendation surfaces non-compliant accounts | [Review security recommendations](https://learn.microsoft.com/azure/defender-for-cloud/review-security-recommendations) |

> ⚠️ **Critical caveat:** The `$web` container used for static website hosting [always remains publicly accessible](https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent) regardless of account-level settings. Threat actors exploit this for exfiltration.

#### 1.2 Transition from Shared Keys to Microsoft Entra ID (RBAC)

**Impact:** Eliminates full data-plane access via compromised keys  
**MITRE:** T1078.004, T1528

| Action | Detail | Reference |
|--------|--------|-----------|
| Disallow shared key authorization | Storage Account → Configuration → Allow storage account key access → **Disabled** | [Prevent shared key authorization](https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent) |
| Migrate to Entra ID RBAC for data-plane access | Assign `Storage Blob Data Reader/Contributor/Owner` roles | [Authorize with Entra ID](https://learn.microsoft.com/azure/storage/blobs/authorize-access-azure-active-directory) |
| Use Managed Identities for application access | Eliminates secret/key management entirely | [Managed identities for Storage](https://learn.microsoft.com/azure/storage/common/storage-auth-aad-msi) |
| If keys must be used: store in Key Vault, rotate regularly | Automate key rotation via Key Vault | [Manage storage account keys](https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage) |
| Enable Azure ABAC for fine-grained access | Attribute-based conditions on role assignments | [ABAC conditions](https://learn.microsoft.com/azure/storage/blobs/storage-auth-abac) |

#### 1.3 Restrict Network Access

**Impact:** Prevents external threat actors from reaching storage endpoints  
**MITRE:** T1595.003, T1530, T1567.002

| Action | Detail | Reference |
|--------|--------|-----------|
| Default deny: Set "Public network access" to **Disabled** | Block all public endpoint traffic | [Configure firewalls and virtual networks](https://learn.microsoft.com/azure/storage/common/storage-network-security) |
| Create private endpoints for Azure workloads | All internal access via Private Link | [Private endpoints for Storage](https://learn.microsoft.com/azure/private-link/tutorial-private-endpoint-storage-portal) |
| If public access needed: restrict to specific VNets/IPs | Firewall rules with explicit allow lists | Same |
| Allow trusted Microsoft services | Enable exception for Azure Backup, Defender, etc. | [Trusted Microsoft services](https://learn.microsoft.com/azure/storage/common/storage-network-security#grant-access-to-trusted-azure-services) |
| Require secure transfer (HTTPS only) | Prevents credential interception on HTTP | [Require secure transfer](https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer) |

#### 1.4 Enable Microsoft Defender for Storage

**Impact:** Provides AI-powered threat detection across the full attack chain  
**MITRE:** All phases

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable Defender for Storage (per-account or subscription) | Provides behavioral analytics + threat intelligence alerts | [Enable Defender for Storage](https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-storage-plan) |
| Enable malware scanning add-on | Near real-time scan on upload + on-demand scanning | [Malware scanning](https://learn.microsoft.com/azure/defender-for-cloud/on-upload-malware-scanning) |
| Enable sensitive data threat detection | Prioritizes alerts on resources containing sensitive data | [Sensitive data detection](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-data-sensitivity) |
| Deploy via built-in Azure Policy | Ensures new accounts get protection automatically | [Policy enablement](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-policy-enablement) |
| Monitor compliance state | Detect attacker attempts to disable Defender for Storage | [Compliance states](https://learn.microsoft.com/azure/governance/policy/concepts/compliance-states) |

---

### 🟠 Tier 2 — High (Limit Blast Radius & Accelerate Detection)

#### 2.1 Implement Data Protection Controls

**Impact:** Prevents data destruction and enables recovery  
**MITRE:** T1485, T1486, T1565

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable soft delete for blobs | 7-365 day retention for deleted blobs | [Soft delete for blobs](https://learn.microsoft.com/azure/storage/blobs/soft-delete-blob-overview) |
| Enable soft delete for containers | Recover deleted containers | [Soft delete for containers](https://learn.microsoft.com/azure/storage/blobs/soft-delete-container-overview) |
| Enable blob versioning | Automatic version history on overwrites | [Blob versioning](https://learn.microsoft.com/azure/storage/blobs/versioning-overview) |
| Apply immutability policies for critical data | WORM (Write Once, Read Many) for compliance/legal data | [Immutable storage](https://learn.microsoft.com/azure/storage/blobs/immutable-storage-overview) |
| Apply Azure Resource Manager lock | Prevent accidental account deletion | [Lock storage account](https://learn.microsoft.com/azure/storage/common/lock-account-resource) |
| Configure Azure Backup for critical storage accounts | Operational backup with point-in-time restore | [Azure Backup for blobs](https://learn.microsoft.com/azure/backup/blob-backup-overview) |

#### 2.2 Secure SAS Token Usage

**Impact:** Limits exposure from compromised or leaked SAS tokens  
**MITRE:** T1078.004, T1098.001, T1528

| Action | Detail | Reference |
|--------|--------|-----------|
| Use user delegation SAS (Entra-backed) instead of account-key SAS | Scoped to user permissions, revocable | [User delegation SAS](https://learn.microsoft.com/azure/storage/blobs/storage-blob-user-delegation-sas-create-dotnet) |
| Set short expiration periods | Minutes/hours, not days/months | [SAS best practices](https://learn.microsoft.com/azure/storage/common/storage-sas-overview#best-practices-for-using-sas) |
| Define stored access policies for service SAS | Enables revocation without key rotation | [Stored access policies](https://learn.microsoft.com/azure/storage/common/storage-stored-access-policy-define-dotnet) |
| Restrict SAS to HTTPS only | Prevents token exposure in transit | Same |
| Monitor SAS expiry status via StorageBlobLogs | `SasExpiryStatus` column tracks near-expiry tokens | Schema: `StorageBlobLogs.SasExpiryStatus` |

#### 2.3 Enable Diagnostic Logging & Monitoring

**Impact:** Provides visibility for detection and forensic investigation  
**MITRE:** T1562.001 (defense evasion via disabling logging)

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable Storage Analytics logging for blob service | Captures all read/write/delete operations | [Storage Analytics logging](https://learn.microsoft.com/azure/storage/common/storage-analytics-logging) |
| Send diagnostic logs to Log Analytics workspace | Enables KQL hunting on `StorageBlobLogs` | [Monitor Blob Storage](https://learn.microsoft.com/azure/storage/blobs/monitor-blob-storage) |
| Enable Azure Activity Log collection | Captures control-plane operations (key rotation, access changes) | [Activity Log](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log) |
| Create alerts for diagnostic settings changes | Detect attacker disabling logging | [Azure Monitor alerts](https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-overview) |
| Stream alerts to Sentinel | Correlate storage alerts with identity, endpoint, and email telemetry | [Sentinel data connectors](https://learn.microsoft.com/azure/sentinel/data-connectors-reference) |

#### 2.4 Harden Storage Account Configuration

**Impact:** Reduces attack surface across multiple vectors  

| Action | Detail | Reference |
|--------|--------|-----------|
| Enforce minimum TLS 1.2 | Prevent downgrade attacks | [Enforce TLS version](https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version) |
| Disable SFTP if not needed | Prevents SFTP-based backdoors (a persistence technique) | [SFTP support](https://learn.microsoft.com/azure/storage/blobs/secure-file-transfer-protocol-support) |
| Disable blob public access (account level) | Defense-in-depth for anonymous access prevention | [Prevent anonymous access](https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent) |
| Review and restrict CORS rules | Prevent cross-origin abuse from attacker-controlled domains | [CORS rules](https://learn.microsoft.com/azure/storage/blobs/quickstart-blobs-javascript-browser#create-a-cors-rule) |
| Enable infrastructure encryption (double encryption) | 256-bit AES at both service and infrastructure level | [Infrastructure encryption](https://learn.microsoft.com/azure/storage/common/infrastructure-encryption-enable) |

---

### 🟡 Tier 3 — Important (Defense-in-Depth & Hardening)

#### 3.1 Secure Automation & Pipeline Integration

**Impact:** Prevents lateral movement via blob-triggered compute  
**MITRE:** T1021.007, T1105

| Action | Detail | Reference |
|--------|--------|-----------|
| Use Managed Identities for Functions/Logic Apps | Not storage keys or SAS tokens | [Managed identity for Functions](https://learn.microsoft.com/azure/azure-functions/functions-identity-based-connections-tutorial) |
| Apply least-privilege RBAC to pipeline identities | `Storage Blob Data Reader` for read-only pipelines | [RBAC for Storage](https://learn.microsoft.com/azure/storage/blobs/assign-azure-role-data-access) |
| Validate input in blob-triggered Functions | Sanitize/validate all blob content before processing | [Blob trigger](https://learn.microsoft.com/azure/azure-functions/functions-bindings-storage-blob-trigger) |
| Restrict Event Grid subscriptions | Limit which principals can create/modify event subscriptions | [Event Grid security](https://learn.microsoft.com/azure/event-grid/security-authorization) |
| Enable Defender for Cloud threat protection for AI services | Protect ML training datasets from data poisoning | [Threat protection for AI](https://learn.microsoft.com/azure/defender-for-cloud/ai-onboarding) |

#### 3.2 Enable Defender CSPM

**Impact:** Provides attack path analysis and sensitive data discovery

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable Defender Cloud Security Posture Management | Cloud security explorer + attack path analysis | [Enable CSPM](https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-cspm-plan) |
| Enable sensitive data discovery component | Discovers and classifies sensitive data in storage | [Sensitive data discovery](https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-cspm-plan#enable-the-components-of-the-defender-cspm-plan) |
| Review attack paths involving storage accounts | Identify exploitable paths from internet-facing resources to storage | [Attack path analysis](https://learn.microsoft.com/azure/defender-for-cloud/concept-attack-path) |

#### 3.3 Apply Zero Trust Principles

| Action | Detail | Reference |
|--------|--------|-----------|
| Follow Azure Storage Zero Trust guide | Comprehensive zero trust architecture for storage | [Zero Trust for Azure Storage](https://learn.microsoft.com/security/zero-trust/azure-infrastructure-storage) |
| Use the cloud security checklist | Structured approach for securing Azure cloud estate | [Cloud security checklist](https://learn.microsoft.com/azure/cloud-adoption-framework/secure/overview) |
| Review the Azure security baseline for Storage | Benchmark compliance against MCSB recommendations | [Storage security baseline](https://learn.microsoft.com/security/benchmark/azure/baselines/storage-security-baseline) |
| Apply the Well-Architected Framework security checklist | Design review for storage workloads | [WAF security checklist](https://learn.microsoft.com/azure/well-architected/security/checklist) |

---

## Part 3: Defender for Cloud Alert Coverage

When Defender for Storage is enabled, these alerts detect activity across the attack chain:

### Reconnaissance
| Alert | Description |
|-------|------------|
| Publicly accessible storage containers successfully discovered | Container enumeration detected |
| Publicly accessible storage containers unsuccessfully scanned | Failed enumeration attempt |
| Access from a known suspicious IP address to a sensitive blob container | Threat-intel-correlated IP access |
| Access from a Tor exit node to a sensitive blob container | Tor-based anonymous access |
| Access from a suspicious IP address | IP reputation-based detection |
| Unusual data exploration in a storage account | Anomalous data browsing patterns |

### Resource Development
| Alert | Description |
|-------|------------|
| Phishing content hosted on a storage account | Phishing page hosted on blob |
| Suspicious external access with overly permissive SAS token | Broad SAS token used externally |
| Suspicious external operation with overly permissive SAS token | Write/delete operations via broad SAS |
| Unusual SAS token used from a public IP address | Anomalous SAS token usage pattern |

### Initial Access
| Alert | Description |
|-------|------------|
| Access from a known suspicious application | Application reputation-based detection |
| Access from a suspicious application | Anomalous application access |
| Access from an unusual location to a sensitive blob container | Geographic anomaly on sensitive data |
| Access from an unusual location to a storage account | Geographic anomaly on any account |
| Authenticated access from a Tor exit node | Tor-based authenticated access |
| Unusual unauthenticated access to a storage container | Anonymous access anomaly |

### Discovery
| Alert | Description |
|-------|------------|
| Unusual access inspection in a storage account | Anomalous metadata/ACL inspection |

### Lateral Movement
| Alert | Description |
|-------|------------|
| Unusual application accessed a storage account | Cross-service lateral movement indicator |
| Malicious blob was downloaded from a storage account | Malware distribution (requires malware scanning) |

### Collection
| Alert | Description |
|-------|------------|
| Access level changed to allow unauthenticated public access (sensitive container) | Public access enabled on sensitive data |
| Access level changed to allow unauthenticated public access | Public access enabled |

### C2
| Alert | Description |
|-------|------------|
| Potential malware uploaded to a storage account | Malware staging |
| Malicious file uploaded to storage account | Confirmed malware upload (requires malware scanning) |

### Exfiltration
| Alert | Description |
|-------|------------|
| Unusual amount of data extracted from a sensitive blob container | Volume-based exfiltration |
| Unusual amount of data extracted from a storage account | Volume-based exfiltration |
| Unusual number of blobs extracted from a sensitive container | Count-based exfiltration |

### Impact
| Alert | Description |
|-------|------------|
| Unusual deletion in a storage account | Mass deletion / ransomware indicator |

---

## Part 4: Threat Hunting Queries

> **Schema Compatibility Notes:**
> - **StorageBlobLogs / StorageMalwareScanningResults:** Require Azure Storage diagnostic logs to be routed to the Log Analytics workspace. If these tables don't exist, enable diagnostic settings on storage accounts first.
> - **AzureActivity:** The Sentinel Data Lake may expose a reduced column set compared to standard Log Analytics. Columns like `Resource`, `ResourceId`, and `ResourceProvider` may not be available — these queries use the portable columns `ResourceGroup`, `ResourceProviderValue`, `OperationNameValue`, and `Properties_d` which are guaranteed to exist in both environments.
> - **CloudStorageAggregatedEvents:** Requires Defender for Storage to be enabled. Available in Advanced Hunting only (use `Timestamp`, not `TimeGenerated`).

### Query 1: Reconnaissance — External Enumeration of Blob Containers

Detects external IPs performing container/blob list operations — classic reconnaissance pattern using tools like Goblob or QuickAZ.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per CallerIpAddress with threshold (>50 requests or >3 distinct accounts). Statistical hunting query for reconnaissance patterns. For CD, consider a fixed threshold on a narrower time window."
-->
```kql
// Reconnaissance: External enumeration of blob containers
// Platform: Sentinel Data Lake
// MITRE: T1593.002, T1595.003, T1619
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("ListContainers", "ListBlobs", "GetContainerProperties",
    "GetContainerMetadata", "GetBlobServiceProperties")
| where AuthenticationType == "Anonymous" or AuthenticationType == "SAS"
| where StatusCode startswith "2" or StatusCode == "403" or StatusCode == "404"
| extend IsSuccess = StatusCode startswith "2"
| summarize
    TotalRequests = count(),
    SuccessCount = countif(IsSuccess),
    FailCount = countif(not(IsSuccess)),
    DistinctAccounts = dcount(AccountName),
    Accounts = make_set(AccountName, 10),
    Operations = make_set(OperationName),
    UserAgents = make_set(UserAgentHeader, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIpAddress
| where TotalRequests > 50 or DistinctAccounts > 3
| extend SuccessRate = round(todouble(SuccessCount) / TotalRequests * 100, 1)
| order by TotalRequests desc
```

### Query 2: Reconnaissance — DNS/Subdomain Brute-Force (High-Volume 404s)

Identifies IPs generating high volumes of 404/403 errors — indicative of brute-force storage account discovery.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per IP per hour with threshold (>100 failed requests or >20 distinct URIs). Statistical hunting query. For CD, simplify to a fixed threshold per hour."
-->
```kql
// Reconnaissance: Brute-force container/blob discovery via 404/403 errors
// Platform: Sentinel Data Lake
// MITRE: T1595.003, T1596.001
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where StatusCode in ("403", "404")
| where AuthenticationType == "Anonymous"
| summarize 
    FailedRequests = count(),
    DistinctUris = dcount(Uri),
    DistinctAccounts = dcount(AccountName),
    SampleUris = make_set(Uri, 5),
    Operations = make_set(OperationName),
    UserAgents = make_set(UserAgentHeader, 3)
    by CallerIpAddress, bin(TimeGenerated, 1h)
| where FailedRequests > 100 or DistinctUris > 20
| order by FailedRequests desc
```

### Query 3: Credential Access — Storage Account Key Listing via Management API

Detects `listKeys` operations on storage accounts — threat actors use this to extract primary/secondary keys for full data-plane access.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per Caller over 30 days for key listing summary. Investigation/audit query. For CD, remove summarize and project individual listKeys events with `ago(1d)` lookback."
-->
```kql
// Credential Access: Storage account key listing via ARM API
// Platform: Sentinel Data Lake
// MITRE: T1528
// Table: AzureActivity
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue =~ "Microsoft.Storage/storageAccounts/listKeys/action"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress,
    ResourceGroup, SubscriptionId,
    Claims = tostring(Claims_d),
    Authorization = tostring(Authorization_d),
    Properties = tostring(Properties_d)
| extend CallerType = iff(Caller has "@", "User", "ServicePrincipal")
| summarize 
    KeyListCount = count(),
    IPs = make_set(CallerIpAddress),
    ResourceGroups = make_set(ResourceGroup, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerType
| order by KeyListCount desc
```

### Query 4: Credential Access — SAS Token Generation Events

Detects SAS token generation — especially broadscope tokens that could be used for persistence.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per IP/account over 30 days for SAS usage summary. Investigation/audit query. StorageBlobLogs is Sentinel-only, not available in AH."
-->
```kql
// Credential Access: SAS token generation or usage with broad permissions
// Platform: Sentinel Data Lake
// MITRE: T1098.001, T1528
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(30d)
| where AuthenticationType == "SAS"
| where SasExpiryStatus != ""
| summarize
    SASOperations = count(),
    DistinctOperations = dcount(OperationName),
    Operations = make_set(OperationName),
    DistinctContainers = dcount(ObjectKey),
    UserAgents = make_set(UserAgentHeader, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIpAddress, AccountName, SasExpiryStatus
| order by SASOperations desc
```

### Query 5: Persistence — RBAC Role Assignment Changes on Storage Accounts

Detects role assignments granting data-plane access to storage accounts — persistence via RBAC manipulation.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: Persistence
title: "Storage RBAC change: {{Action}} by {{Caller}} in {{ResourceGroup}}"
impactedAssets:
  - type: user
    identifier: Caller
adaptation_notes: "AzureActivity table — available in AH as well. Reduce lookback from 30d to `ago(1d)` for scheduled detection. Filter `Properties_d` further for specific high-privilege role definitions (e.g., Storage Blob Data Owner)."
-->
```kql
// Persistence: RBAC role changes on storage accounts
// Platform: Sentinel Data Lake
// MITRE: T1098.001
// Table: AzureActivity
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has "Microsoft.Authorization/roleAssignments"
| where ActivityStatusValue == "Success"
| where tostring(Properties_d) has "Microsoft.Storage/storageAccounts"
| project TimeGenerated, Caller, CallerIpAddress,
    OperationNameValue, ResourceGroup, SubscriptionId,
    Properties = tostring(Properties_d)
| extend Action = case(
    OperationNameValue has "write", "Assigned",
    OperationNameValue has "delete", "Removed",
    "Other")
| order by TimeGenerated desc
```

### Query 6: Persistence — Anonymous Access Level Changes

Detects changes to container access level that enable anonymous/public access — key persistence and collection technique.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: Persistence
title: "Container ACL changed on {{AccountName}} by {{RequesterUpn}}"
impactedAssets:
  - type: user
    identifier: RequesterUpn
adaptation_notes: "StorageBlobLogs is Sentinel-only. For AH-based CD, adapt to use AzureActivity with OperationName matching container ACL operations. Reduce lookback from 30d to `ago(1d)`."
-->
```kql
// Persistence/Collection: Container access level changed to public
// Platform: Sentinel Data Lake
// MITRE: T1098.001, T1530
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(30d)
| where OperationName == "SetContainerACL"
| project TimeGenerated, AccountName, ObjectKey, CallerIpAddress,
    AuthenticationType, RequesterUpn, RequesterAppId,
    UserAgentHeader, StatusCode, Uri
| order by TimeGenerated desc
```

### Query 7: Defense Evasion — Firewall Rule Modifications

Detects modifications to storage account network rules — threat actors loosen firewall rules to enable external access.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: DefenseEvasion
title: "Storage firewall/network rule modified by {{Caller}} in {{ResourceGroup}}"
impactedAssets:
  - type: user
    identifier: Caller
adaptation_notes: "Reduce lookback from 30d to `ago(1d)` for scheduled detection. Review Properties_d to distinguish between tightening vs loosening of firewall rules."
-->
```kql
// Defense Evasion: Storage account firewall/network rule modifications
// Platform: Sentinel Data Lake
// MITRE: T1562.007
// Table: AzureActivity
AzureActivity
| where TimeGenerated > ago(30d)
| where ResourceProviderValue =~ "Microsoft.Storage"
    or OperationNameValue has "Microsoft.Storage"
| where OperationNameValue has_any (
    "networkRuleSet", "firewallRules",
    "Microsoft.Storage/storageAccounts/write",
    "privateEndpointConnections")
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress,
    OperationNameValue, ResourceGroup,
    Properties = tostring(Properties_d)
| order by TimeGenerated desc
```

### Query 8: Defense Evasion — Diagnostic Logging Disabled

Detects deletion or modification of diagnostic settings — attackers disable logging to operate in blind spots.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: DefenseEvasion
title: "Diagnostic settings {{Action}} on storage by {{Caller}}"
impactedAssets:
  - type: user
    identifier: Caller
adaptation_notes: "Reduce lookback from 30d to `ago(1d)`. Filter specifically for deletion events (`diagnosticSettings/delete`) as high-severity, modifications as medium."
-->
```kql
// Defense Evasion: Diagnostic settings modified or deleted on storage
// Platform: Sentinel Data Lake
// MITRE: T1562.001
// Table: AzureActivity
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has_any (
    "diagnosticSettings/delete",
    "diagnosticSettings/write")
| where tostring(Properties_d) has "Microsoft.Storage"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress,
    OperationNameValue, ResourceGroup,
    Properties = tostring(Properties_d),
    Action = iff(OperationNameValue has "delete", "🔴 Deleted", "🟡 Modified")
| order by TimeGenerated desc
```

### Query 9: Defense Evasion — Defender for Storage Disabled

Detects attempts to disable Defender for Storage — critical defense evasion indicator.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: DefenseEvasion
title: "Defender for Storage pricing change by {{Caller}}"
impactedAssets:
  - type: user
    identifier: Caller
adaptation_notes: "Reduce lookback from 30d to `ago(1d)`. High-severity detection — disabling Defender for Storage is a strong indicator of defense evasion."
responseActions:
  - "Re-enable Defender for Storage immediately"
  - "Investigate the caller identity for compromise"
-->
```kql
// Defense Evasion: Microsoft Defender for Storage disabled
// Platform: Sentinel Data Lake
// MITRE: T1562.001
// Table: AzureActivity
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has_any (
    "Microsoft.Security/pricings/write",
    "Microsoft.Security/pricings/delete")
| where Properties has "StorageAccounts" or Properties has "Storage"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress,
    OperationNameValue, ResourceGroup,
    Properties = tostring(Properties_d)
| order by TimeGenerated desc
```

### Query 10: Discovery — Unusual Container/Blob Enumeration Patterns

Detects authenticated principals performing unusual levels of list/get operations — post-compromise discovery.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per principal with threshold (>500 ops or >50 containers). Statistical hunting query. StorageBlobLogs is Sentinel-only."
-->
```kql
// Discovery: Authenticated principal performing unusual enumeration
// Platform: Sentinel Data Lake
// MITRE: T1580, T1619
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("ListContainers", "ListBlobs", "GetBlob",
    "GetBlobProperties", "GetContainerProperties",
    "GetBlobMetadata", "GetContainerMetadata",
    "GetAccountInformation", "GetBlobServiceProperties")
| where AuthenticationType != "Anonymous"
| summarize
    DiscoveryOps = count(),
    DistinctContainers = dcount(ObjectKey),
    DistinctAccounts = dcount(AccountName),
    Accounts = make_set(AccountName, 10),
    Operations = make_set(OperationName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RequesterUpn, RequesterAppId, CallerIpAddress
| where DiscoveryOps > 500 or DistinctContainers > 50
| extend Duration = LastSeen - FirstSeen
| order by DiscoveryOps desc
```

### Query 11: Lateral Movement — Blob-Triggered Function Execution Anomalies

Detects unusual blob operations followed by function invocations — potential lateral movement via blob-triggered compute.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Keyword matching on AccountName/ObjectKey for function/logic app storage is extremely noisy with legitimate Azure Functions operations. Requires environment-specific tuning. StorageBlobLogs is Sentinel-only."
-->
```kql
// Lateral Movement: Blob operations correlated with compute triggers
// Platform: Sentinel Data Lake
// MITRE: T1021.007
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("PutBlob", "PutBlock", "CopyBlob",
    "PutBlockList", "AppendBlock")
| where AccountName has_any ("function", "func", "webjob", "logic")
    or ObjectKey has_any ("azure-webjobs", "function", "workflow")
| project TimeGenerated, AccountName, OperationName, ObjectKey,
    CallerIpAddress, AuthenticationType, RequesterUpn,
    RequesterAppId, UserAgentHeader, ResponseBodySize
| order by TimeGenerated desc
```

### Query 12: Collection — Large-Scale Data Staging via Copy Operations

Detects bulk copy operations (StartCopy, SyncCopy, CopyBlob) — attackers stage data before exfiltration.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per account/requester with threshold (>50 copies or >1GB). Statistical hunting query. StorageBlobLogs is Sentinel-only."
-->
```kql
// Collection: Large-scale data staging via copy operations
// Platform: Sentinel Data Lake
// MITRE: T1074.002, T1530
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("CopyBlob", "StartCopyBlob",
    "CopyBlobFromUrl", "SyncCopyBlob",
    "StartCopyBlobFromUri")
| summarize
    CopyCount = count(),
    TotalBytesTransferred = sum(ResponseBodySize),
    DistinctSources = dcount(SourceUri),
    DistinctDestinations = dcount(DestinationUri),
    SampleSources = make_set(SourceUri, 5),
    SampleDestinations = make_set(DestinationUri, 5),
    IPs = make_set(CallerIpAddress),
    UserAgents = make_set(UserAgentHeader, 3),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AccountName, RequesterUpn, RequesterAppId
| where CopyCount > 50 or TotalBytesTransferred > 1073741824 // > 1 GB
| extend TotalGB = round(todouble(TotalBytesTransferred) / 1073741824, 2)
| order by TotalBytesTransferred desc
```

### Query 13: Exfiltration — AzCopy or Azure Storage Explorer Usage

Detects usage of AzCopy or Azure Storage Explorer for bulk data transfer — tools abused by ransomware gangs for exfiltration.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per IP/account with threshold (>100 ops or >1GB). Statistical hunting query. StorageBlobLogs is Sentinel-only."
-->
```kql
// Exfiltration: AzCopy/Storage Explorer bulk transfer detection
// Platform: Sentinel Data Lake
// MITRE: T1567.002
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where UserAgentHeader has_any ("AzCopy", "Azure-Storage", 
    "StorageExplorer", "azcopy", "azure-storage-cpp",
    "azure-storage-java", "azure-storage-python")
| summarize
    Operations = count(),
    DataVolume = sum(ResponseBodySize),
    DistinctBlobs = dcount(ObjectKey),
    OperationTypes = make_set(OperationName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIpAddress, AccountName, UserAgentHeader,
    RequesterUpn, RequesterAppId
| extend DataGB = round(todouble(DataVolume) / 1073741824, 2)
| where Operations > 100 or DataGB > 1
| order by DataVolume desc
```

### Query 14: Exfiltration — Static Website ($web Container) Abuse

Detects operations on the `$web` container used for static website hosting — threat actors copy sensitive data here because it's always publicly accessible.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: Exfiltration
title: "$web container write on {{AccountName}} by {{RequesterUpn}} from {{CallerIpAddress}}"
impactedAssets:
  - type: user
    identifier: RequesterUpn
adaptation_notes: "StorageBlobLogs is Sentinel-only. For AH-based CD, use AzureActivity or CloudStorageAggregatedEvents. Reduce lookback from 30d to `ago(1d)`. High-value detection — $web container is always publicly accessible."
recommendedActions: "Verify the upload is legitimate. $web container content is publicly accessible and may expose sensitive data."
-->
```kql
// Exfiltration: $web container abuse (static website hosting)
// Platform: Sentinel Data Lake
// MITRE: T1567.002
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(30d)
| where ObjectKey has "$web"
| where OperationName in ("PutBlob", "PutBlock", "PutBlockList",
    "CopyBlob", "CopyBlobFromUrl", "SetBlobProperties")
| project TimeGenerated, AccountName, OperationName, ObjectKey,
    CallerIpAddress, AuthenticationType, RequesterUpn,
    RequesterAppId, UserAgentHeader, ResponseBodySize
| order by TimeGenerated desc
```

### Query 15: Exfiltration — Cross-Subscription/Cross-Tenant Data Transfer

Detects copy operations where source and destination are in different accounts — potential cross-subscription exfiltration.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: Exfiltration
title: "Cross-account blob copy: {{SourceAccount}} → {{DestAccount}} by {{RequesterUpn}}"
impactedAssets:
  - type: user
    identifier: RequesterUpn
adaptation_notes: "StorageBlobLogs is Sentinel-only. For AH-based CD, adapt to CloudStorageAggregatedEvents or use as Sentinel analytic rule."
recommendedActions: "Verify the cross-account copy is authorized. Check if source or destination accounts are external to the organization."
-->
```kql
// Exfiltration: Cross-account blob copy (potential cross-subscription transfer)
// Platform: Sentinel Data Lake
// MITRE: T1537
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("CopyBlob", "CopyBlobFromUrl",
    "StartCopyBlobFromUri", "StartCopyBlob")
| where isnotempty(SourceUri)
| extend SourceAccount = extract(@"https://([^.]+)\.blob", 1, SourceUri)
| extend DestAccount = AccountName
| where SourceAccount != DestAccount and isnotempty(SourceAccount)
| project TimeGenerated, DestAccount, SourceAccount, SourceUri,
    DestinationUri, CallerIpAddress, RequesterUpn,
    RequesterAppId, UserAgentHeader
| order by TimeGenerated desc
```

### Query 16: C2 — Blob Metadata Manipulation (Covert Channel)

Detects unusual metadata operations — threat actors embed C2 commands in blob metadata fields.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per IP with threshold (>100 metadata ops) and GetSet ratio calculation. Statistical hunting for C2 beacon patterns. StorageBlobLogs is Sentinel-only."
-->
```kql
// C2: Unusual blob metadata manipulation (covert channel indicator)
// Platform: Sentinel Data Lake
// MITRE: T1105
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("SetBlobMetadata", "GetBlobMetadata",
    "SetBlobProperties", "GetBlobProperties")
| summarize
    MetadataOps = count(),
    GetOps = countif(OperationName has "Get"),
    SetOps = countif(OperationName has "Set"),
    DistinctBlobs = dcount(ObjectKey),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIpAddress, AccountName, RequesterAppId
| where MetadataOps > 100
// High metadata ops with periodic polling pattern may indicate C2 beacon
| extend GetSetRatio = round(todouble(GetOps) / iff(SetOps == 0, 1, SetOps), 2)
| extend Duration = LastSeen - FirstSeen
| order by MetadataOps desc
```

### Query 17: Impact — Mass Deletion Events (Ransomware/Destruction)

Detects bulk blob or container deletion — ransomware or destructive attack indicator.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per IP/requester with threshold (>50 deletes) and rate calculation. Statistical hunting for mass deletion patterns. StorageBlobLogs is Sentinel-only."
-->
```kql
// Impact: Mass blob/container deletion (ransomware/data destruction)
// Platform: Sentinel Data Lake
// MITRE: T1485
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("DeleteBlob", "DeleteContainer",
    "PermanentDeleteBlob", "UndeleteBlob")
| summarize
    DeleteCount = count(),
    DistinctContainers = dcount(ObjectKey),
    Accounts = make_set(AccountName),
    Operations = make_set(OperationName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIpAddress, RequesterUpn, RequesterAppId
| where DeleteCount > 50
| extend DeletionDuration = LastSeen - FirstSeen
| extend DeleteRate = round(todouble(DeleteCount) / 
    iff(DeletionDuration == 0s, 1s, DeletionDuration) * 60, 1) // per minute
| order by DeleteCount desc
```

### Query 18: Impact — Data Overwrite/Encryption (Ransomware Pattern)

Detects rapid PutBlob operations on existing blobs — ransomware encrypting/overwriting data.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per IP per hour with threshold (>200 writes, >100 distinct blobs). Statistical hunting for ransomware encryption patterns. StorageBlobLogs is Sentinel-only."
-->
```kql
// Impact: Rapid blob overwrite (potential ransomware encryption)
// Platform: Sentinel Data Lake
// MITRE: T1486, T1565
// Table: StorageBlobLogs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("PutBlob", "PutBlockList", "PutBlock")
| where StatusCode startswith "2"
| summarize
    WriteCount = count(),
    TotalBytesWritten = sum(RequestBodySize),
    DistinctBlobs = dcount(ObjectKey),
    DistinctAccounts = dcount(AccountName),
    Accounts = make_set(AccountName),
    UserAgents = make_set(UserAgentHeader, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIpAddress, RequesterUpn, RequesterAppId, bin(TimeGenerated, 1h)
| where WriteCount > 200 and DistinctBlobs > 100
| extend WriteGB = round(todouble(TotalBytesWritten) / 1073741824, 2)
| order by WriteCount desc
```

### Query 19: Malware Scanning Results — Malicious Uploads

Detects malware uploads to storage accounts using Defender for Storage malware scanning results.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "StorageMalwareScanningResults is Sentinel-only (diagnostic log table), not available in AH. Defender for Storage already fires built-in alerts for malware detections. Use as Sentinel analytic rule or for investigation."
-->
```kql
// C2/Resource Development: Malware uploaded to storage
// Platform: Sentinel Data Lake
// MITRE: T1105, T1583.004
// Table: StorageMalwareScanningResults
StorageMalwareScanningResults
| where TimeGenerated > ago(30d)
| where ScanResultType == "Malicious"
| extend ScanDetails = parse_json(ScanResultDetails)
| extend MalwareName = tostring(ScanDetails.malwareName)
| extend MalwareCategory = tostring(ScanDetails.malwareCategory)
| project TimeGenerated, StorageAccountName, BlobUri,
    ScanResultType, MalwareName, MalwareCategory,
    ScanFinishedTimeUtc
| order by TimeGenerated desc
```

### Query 20: Anomalous Storage Access — Suspicious Activity Patterns (Advanced Hunting)

Uses CloudStorageAggregatedEvents from Defender XDR to detect unusual access patterns including anonymous access probing and high-volume operations from uncommon locations.

<!-- cd-metadata
cd_ready: true
schedule: "12H"
category: Reconnaissance
title: "Suspicious storage access pattern on {{StorageAccount}} from {{IPAddress}}"
impactedAssets:
  - type: user
    identifier: AccountUpn
adaptation_notes: "CloudStorageAggregatedEvents is AH-native. Reduce lookback from 30d to `ago(1d)` for scheduled detection. The built-in filters (FailedOperationsCount > 10, AnonymousSuccessfulOperations > 50) provide good signal."
-->
```kql
// Reconnaissance/Initial Access: Suspicious storage access patterns
// Platform: Defender XDR Advanced Hunting
// MITRE: T1078.004, T1530
// Table: CloudStorageAggregatedEvents
CloudStorageAggregatedEvents
| where Timestamp > ago(30d)
| where FailedOperationsCount > 10
    or HasAnonymousResourceNotFoundFailures == true
    or AnonymousSuccessfulOperations > 50
| project Timestamp, StorageAccount, StorageContainer,
    IPAddress, AccountUpn, AccountApplicationId,
    AuthenticationType, OperationsCount,
    SuccessfulOperationsCount, FailedOperationsCount,
    AnonymousSuccessfulOperations,
    HasAnonymousResourceNotFoundFailures,
    TotalResponseLength, Location,
    UserAgentHeader, OperationNamesList
| order by Timestamp desc
```

### Query 21: Anomalous Anonymous Access Patterns (Advanced Hunting)

Detects unusual anonymous access activity that may indicate credential-free data exfiltration.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation per StorageAccount with threshold (>100 anonymous ops). Statistical hunting for anonymous access patterns. CloudStorageAggregatedEvents is AH-native."
-->
```kql
// Initial Access: Anomalous anonymous access to blob storage
// Platform: Defender XDR Advanced Hunting
// MITRE: T1530
// Table: CloudStorageAggregatedEvents
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| where AnonymousSuccessfulOperations > 0
| summarize
    TotalAnonymousOps = sum(AnonymousSuccessfulOperations),
    TotalResponseBytes = sum(TotalResponseLength),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 10),
    Locations = make_set(Location),
    Containers = make_set(StorageContainer, 10)
    by StorageAccount
| where TotalAnonymousOps > 100
| extend DataGB = round(todouble(TotalResponseBytes) / 1073741824, 2)
| order by TotalAnonymousOps desc
```

### Query 22: Security Alerts — All Blob Storage Related Incidents

Summarizes all Defender for Cloud alerts related to Azure Storage correlated with incidents.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "SOC triage summary — multi-join SecurityAlert→SecurityIncident aggregation for dashboard use. Not a detection."
-->
```kql
// Alert Summary: All storage-related alerts with incident correlation
// Platform: Sentinel Data Lake
// Table: SecurityAlert, SecurityIncident
let StorageAlerts = SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertName has_any ("storage", "blob", "container",
    "SAS token", "unauthenticated", "malware uploaded",
    "data extracted", "unusual deletion", "suspicious application",
    "Tor exit node", "phishing content")
    or ProductName has "Storage"
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity,
    ProviderName, ProductName, Tactics;
SecurityIncident
| where CreatedTime > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner StorageAlerts on $left.AlertId == $right.SystemAlertId
| summarize
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    AlertNames = make_set(AlertName),
    AlertCount = dcount(SystemAlertId),
    CreatedTime = any(CreatedTime)
    by IncidentNumber
| order by CreatedTime desc
```

### Query 23: Full Chain — Identity → Storage Correlation

Correlates identity sign-in anomalies with subsequent storage operations — detects compromised accounts accessing storage.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table correlation (SigninLogs + StorageBlobLogs) with aggregation. Dynamic risky identity list as `let` block makes this unsuitable for CD. StorageBlobLogs is Sentinel-only."
-->
```kql
// Full Chain: Risky sign-in → Blob storage access
// Platform: Sentinel Data Lake
// MITRE: T1078.004, T1530
// Tables: SigninLogs, StorageBlobLogs
let RiskySignIns = SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium")
    or RiskState == "atRisk"
| distinct UserPrincipalName, IPAddress;
let RiskyUPNs = RiskySignIns | distinct UserPrincipalName;
let RiskyIPs = RiskySignIns | distinct IPAddress;
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where RequesterUpn in~ (RiskyUPNs)
    or CallerIpAddress in (RiskyIPs)
| summarize
    StorageOps = count(),
    Operations = make_set(OperationName),
    Accounts = make_set(AccountName),
    DataVolume = sum(ResponseBodySize)
    by RequesterUpn, CallerIpAddress
| extend DataGB = round(todouble(DataVolume) / 1073741824, 2)
| order by StorageOps desc
```

### Query 24: Posture Check — Storage Accounts with Shared Key Access Enabled

Audits control-plane for storage accounts where shared key authorization is still permitted.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture check/audit query — identifies configuration drift, not a threat detection. Reduce lookback from 30d to `ago(1d)` if used for change monitoring."
-->
```kql
// Posture: Identify storage accounts with key-based auth enabled
// Platform: Sentinel Data Lake
// Table: AzureActivity
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue =~ "Microsoft.Storage/storageAccounts/write"
| where ActivityStatusValue == "Success"
| extend Props = parse_json(tostring(Properties_d))
| extend RequestBody = tostring(Props.requestbody)
| where RequestBody has "allowSharedKeyAccess"
| project TimeGenerated, ResourceGroup, Caller,
    CallerIpAddress, RequestBody,
    Properties = tostring(Properties_d)
| order by TimeGenerated desc
```

### Query 25: Posture Check — Storage Account Key Rotation History

Reviews storage account key rotation cadence — keys that haven't been rotated are high risk if compromised.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture check with 90-day lookback and aggregation per ResourceGroup. Investigation/audit query, not event-driven detection."
-->
```kql
// Posture: Storage account key rotation events
// Platform: Sentinel Data Lake
// Table: AzureActivity
AzureActivity
| where TimeGenerated > ago(90d)
| where OperationNameValue =~ "Microsoft.Storage/storageAccounts/regenerateKey/action"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress,
    ResourceGroup
| summarize
    LastRotation = max(TimeGenerated),
    RotationCount = count(),
    Callers = make_set(Caller)
    by ResourceGroup
| extend DaysSinceLastRotation = datetime_diff("day", now(), LastRotation)
| order by DaysSinceLastRotation desc
```

---

## Part 5: Posture Assessment Checklist

Use this checklist to assess your organization's Azure Blob Storage defense maturity:

### Level 1 — Basic (High Risk)
- [ ] Defender for Storage enabled on all storage accounts
- [ ] Anonymous/public access disabled at account level
- [ ] Secure transfer (HTTPS) required
- [ ] Storage Analytics/diagnostic logs enabled and sent to Log Analytics
- [ ] Azure Activity Log collected in Sentinel

### Level 2 — Intermediate (Moderate Risk)
- [ ] Shared key authorization disabled — Entra ID RBAC only
- [ ] Private endpoints deployed for all internal-facing storage accounts
- [ ] Firewall rules: default deny with explicit allow lists
- [ ] Soft delete enabled for blobs and containers
- [ ] SAS tokens use user delegation SAS with short expiration
- [ ] Malware scanning add-on enabled in Defender for Storage
- [ ] Storage account keys stored in Key Vault with rotation automation
- [ ] Resource Manager locks on production storage accounts

### Level 3 — Advanced (Low Risk)
- [ ] Sensitive data threat detection enabled in Defender for Storage
- [ ] Defender CSPM with sensitive data discovery and attack path analysis
- [ ] Immutability policies on compliance/legal data
- [ ] Azure Backup configured for critical storage accounts
- [ ] SFTP disabled on all accounts (unless business-justified)
- [ ] Managed Identities for all application/pipeline access
- [ ] Event Grid subscriptions restricted to authorized principals
- [ ] Blob versioning enabled for critical containers
- [ ] Minimum TLS 1.2 enforced
- [ ] Infrastructure encryption (double encryption) enabled

### Level 4 — Optimal (Minimal Risk)
- [ ] Zero shared key / zero SAS token usage across all accounts
- [ ] ABAC (attribute-based access control) for fine-grained permissions
- [ ] Active threat hunting with queries from this playbook (weekly cadence)
- [ ] Automated response playbooks in Sentinel for storage alerts
- [ ] Security alerts from Defender for Storage streamed to Sentinel
- [ ] Regular posture reviews via cloud security checklist
- [ ] Supply chain security: validated inputs for all blob-triggered automation
- [ ] Network security perimeter deployed for storage resources
- [ ] Cross-subscription data transfer monitoring and alerting

---

## Part 6: Response Playbook — Confirmed Blob Storage Compromise

### Immediate Actions (0-30 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Rotate storage account keys** | Regenerate both primary and secondary keys immediately |
| 2 | **Revoke compromised SAS tokens** | Rotate underlying key or delete stored access policy |
| 3 | **Block attacker IPs** | Add to storage account firewall deny rules |
| 4 | **Disable compromised identity** | Revoke Entra ID sessions + disable account |
| 5 | **Isolate the storage account** | Set public network access to Disabled |

### Investigation (30-120 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 6 | **Review StorageBlobLogs** | Run hunting queries 1-18 to identify scope of compromise |
| 7 | **Check Azure Activity Log** | Review RBAC changes, key listings, firewall modifications |
| 8 | **Identify all accessed blobs** | List all blobs accessed/copied/deleted by attacker identity/IP |
| 9 | **Check for data exfiltration** | Review copy operations, $web container writes, cross-account transfers |
| 10 | **Check for malware uploads** | Review StorageMalwareScanningResults for malicious uploads |
| 11 | **Review downstream automation** | Check if blob-triggered Functions/Logic Apps were exploited |
| 12 | **Enrich attacker IPs** | Run `python enrich_ips.py <attacker_IPs>` |

### Remediation (2-24 hours)

| Step | Action | Detail |
|------|--------|--------|
| 13 | **Remove attacker persistence** | Remove unauthorized RBAC assignments, SAS tokens, SFTP accounts |
| 14 | **Restore deleted/modified data** | Use soft delete, versioning, or Azure Backup |
| 15 | **Harden configuration** | Apply Tier 1-2 defensive controls from this document |
| 16 | **Enable/verify Defender for Storage** | Ensure attacker didn't disable threat detection |
| 17 | **Re-enable diagnostic logging** | Ensure attacker didn't disable logging for evasion |
| 18 | **Update firewall rules** | Remove any permissive rules added by attacker |

### Post-Incident (1-7 days)

| Step | Action |
|------|--------|
| 19 | Assess data breach impact — determine what sensitive data was accessed/exfiltrated |
| 20 | Complete posture assessment checklist and implement gaps |
| 21 | Review all storage accounts in the subscription for similar misconfigurations |
| 22 | Document lessons learned and update detection rules |
| 23 | Schedule recurring threat hunting using queries in this document |

---

## References

### Microsoft Official Documentation
- [Inside the attack chain: Threat activity targeting Azure Blob Storage](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/) — Microsoft Threat Intelligence (October 2025)
- [Security recommendations for Blob Storage](https://learn.microsoft.com/azure/storage/blobs/security-recommendations)
- [Azure security baseline for Storage](https://learn.microsoft.com/security/benchmark/azure/baselines/storage-security-baseline)
- [Architecture best practices for Azure Blob Storage — Security](https://learn.microsoft.com/azure/well-architected/service-guides/azure-blob-storage#security)
- [Apply Zero Trust principles to Azure Storage](https://learn.microsoft.com/security/zero-trust/azure-infrastructure-storage)
- [Microsoft Defender for Storage introduction](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-introduction)
- [Understand security threats and alerts in Defender for Storage](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-threats-alerts)
- [Enable Defender for Storage](https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-storage-plan)
- [Malware scanning in Defender for Storage](https://learn.microsoft.com/azure/defender-for-cloud/on-upload-malware-scanning)
- [Prevent anonymous read access to containers and blobs](https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent)
- [Prevent shared key authorization](https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent)
- [Monitoring Azure Blob Storage](https://learn.microsoft.com/azure/storage/blobs/monitor-blob-storage)
- [Azure Storage firewalls and virtual networks](https://learn.microsoft.com/azure/storage/common/storage-network-security)
- [Cloud security checklist](https://learn.microsoft.com/azure/cloud-adoption-framework/secure/overview)
- [Defender CSPM — Attack path analysis](https://learn.microsoft.com/azure/defender-for-cloud/concept-attack-path)

### Microsoft Threat Intelligence
- [Threat matrix for cloud-based storage services](https://www.microsoft.com/security/blog/2021/04/08/threat-matrix-for-storage/)
- [Threats targeting or leveraging Azure Blob Storage — MDTI report](https://security.microsoft.com/threatanalytics3/8d8a9fa0-4408-47be-8a07-7ce3d21eb827/analystreport)
- [Protect your storage resources against blob hunting](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/protect-your-storage-resources-against-blob-hunting/3735238)
