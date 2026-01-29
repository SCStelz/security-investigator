---
name: ioc-investigation
description: Use this skill when asked to investigate an Indicator of Compromise (IoC) such as an IP address, DNS domain, URL, or file hash. Triggers on keywords like "investigate IP", "check domain", "IoC investigation", "threat intel", "is this malicious", "suspicious URL", or when an IP/domain/URL/hash is mentioned with investigation context. This skill provides comprehensive IoC analysis using Microsoft Defender Threat Intelligence, Sentinel Threat Intel tables, Advanced Hunting, organizational exposure assessment, CVE correlation, and affected device enumeration.
---

# IoC (Indicator of Compromise) Investigation - Instructions

## Purpose

This skill performs comprehensive security investigations on Indicators of Compromise (IoCs) including:
- **IP Addresses**: Network connections, threat intel matches, geographic analysis, organizational exposure
- **DNS Domains**: Domain reputation, connection events, email-based threats, URL analysis
- **URLs**: URL reputation, phishing detection, email delivery, browser activity
- **File Hashes**: Malware analysis, file prevalence, related alerts, affected devices

The investigation correlates IoCs with Microsoft Defender Threat Intelligence, identifies associated CVEs, and enumerates organizational assets affected by those vulnerabilities.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Investigation Types](#available-investigation-types)** - By IoC type
3. **[Quick Start](#quick-start-tldr)** - 5-step investigation pattern
4. **[Execution Workflow](#execution-workflow)** - Complete process
5. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns
6. **[Defender API Queries](#defender-api-queries)** - Threat Intel & Vulnerability Management
7. **[JSON Export Structure](#json-export-structure)** - Required fields
8. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY IoC investigation:**

1. **ALWAYS identify the IoC type FIRST** (IP, Domain, URL, or File Hash)
2. **ALWAYS normalize the IoC** (lowercase domains, validate IP format, extract domain from URL)
3. **ALWAYS calculate date ranges correctly** (use current date from context - see Date Range section)
4. **ALWAYS track and report time after each major step** (mandatory)
5. **ALWAYS run independent queries in parallel** (drastically faster execution)
6. **ALWAYS use `create_file` for JSON export** (NEVER use PowerShell terminal commands)
7. **⛔ ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)

---

## ⛔ MANDATORY: Sentinel Workspace Selection

**This skill requires a Sentinel workspace to execute queries. Follow these rules STRICTLY:**

### When invoked from incident-investigation skill:
- Inherit the workspace selection from the parent investigation context
- If no workspace was selected in parent context: **STOP and ask user to select**
- Use the `SELECTED_WORKSPACE_IDS` passed from the parent skill

### When invoked standalone (direct user request):
1. **ALWAYS call `list_sentinel_workspaces` MCP tool FIRST**
2. **If 1 workspace exists:** Auto-select, display to user, proceed
3. **If multiple workspaces exist:**
   - Display all workspaces with Name and ID
   - ASK: "Which Sentinel workspace should I use for this investigation?"
   - **⛔ STOP AND WAIT** for user response
   - **⛔ DO NOT proceed until user explicitly selects**
4. **If a query fails on the selected workspace:**
   - **⛔ DO NOT automatically try another workspace**
   - STOP and report the error
   - Display available workspaces
   - ASK user to select a different workspace
   - WAIT for user response

### Workspace Failure Handling

```
IF query returns "Failed to resolve table" or similar error:
    - STOP IMMEDIATELY
    - Report: "⚠️ Query failed on workspace [NAME] ([ID]). Error: [ERROR_MESSAGE]"
    - Display: "Available workspaces: [LIST_ALL_WORKSPACES]"
    - ASK: "Which workspace should I use instead?"
    - WAIT for explicit user response
    - DO NOT retry with a different workspace automatically
```

**🔴 PROHIBITED ACTIONS:**
- ❌ Selecting a workspace without user consent when multiple exist
- ❌ Switching to another workspace after a failure without asking
- ❌ Proceeding with investigation if workspace selection is ambiguous
- ❌ Assuming a workspace based on previous sessions

---

**IoC Type Detection Rules:**
| Pattern | IoC Type | Normalization |
|---------|----------|---------------|
| `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | IPv4 Address | Validate octets ≤255 |
| `[a-fA-F0-9:]+` (with multiple colons) | IPv6 Address | Lowercase, expand if needed |
| `[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}` | Domain | Lowercase, remove trailing dot |
| `https?://.*` or starts with `www.` | URL | Extract domain for separate analysis |
| 32 hex chars | MD5 Hash | Lowercase |
| 40 hex chars | SHA1 Hash | Lowercase |
| 64 hex chars | SHA256 Hash | Lowercase |

**Date Range Rules:**
- **Real-time/recent searches:** Add +2 days to current date for end range
- **Historical ranges:** Add +1 day to user's specified end date
- **Example:** Current date = Jan 23; "Last 7 days" → `datetime(2026-01-16)` to `datetime(2026-01-25)`

---

## Available Investigation Types

### IP Address Investigation
**When to use:** Suspicious inbound/outbound connections, firewall alerts, sign-in anomalies

**Example prompts:**
- "Investigate IP 203.0.113.42"
- "Is 198.51.100.10 malicious?"
- "Check threat intel for 192.0.2.1"

**Data sources:**
- Defender Threat Intelligence (IP alerts, statistics)
- DeviceNetworkEvents (connection history)
- ThreatIntelIndicators (Sentinel TI table)
- SigninLogs (if used for authentication)
- Defender IOC list (custom indicators)

### Domain Investigation
**When to use:** Suspicious DNS queries, phishing domains, C2 communication

**Example prompts:**
- "Investigate domain malware-c2.example.com"
- "Is evil.com in our threat intel?"
- "Check if any devices connected to suspicious.net"

**Data sources:**
- DeviceNetworkEvents (DNS queries, HTTP connections)
- EmailUrlInfo (email-delivered URLs)
- ThreatIntelIndicators (domain indicators)
- Defender IOC list (blocked domains)
- UrlClickEvents (user clicks on domain)

### URL Investigation
**When to use:** Phishing links, malicious downloads, suspicious redirects

**Example prompts:**
- "Investigate URL https://phishing.example.com/login"
- "Was this URL clicked by anyone?"
- "Check threat intel for http://malware.site/payload.exe"

**Data sources:**
- EmailUrlInfo (URLs in emails)
- UrlClickEvents (click tracking)
- DeviceNetworkEvents (HTTP/HTTPS connections)
- DeviceFileEvents (downloads from URL)
- ThreatIntelIndicators (URL patterns)

### File Hash Investigation
**When to use:** Malware analysis, suspicious executables, file reputation

**Example prompts:**
- "Investigate hash a1b2c3d4e5f6..."
- "Is this SHA256 known malware?"
- "Which devices have this file?"

**Data sources:**
- Defender File Info & Statistics
- Defender File Alerts
- Defender File Related Machines
- DeviceFileEvents (file creation/modification)
- ThreatIntelIndicators (file hash indicators)

---

## Quick Start (TL;DR)

When a user requests an IoC investigation:

1. **Identify & Normalize IoC:**
   ```
   - Detect IoC type (IP/Domain/URL/Hash)
   - Normalize format (lowercase, validate)
   - Extract embedded IoCs (domain from URL)
   ```

2. **Run Parallel Queries (Batch 1 - Threat Intel):**
   - Sentinel ThreatIntelIndicators query
   - Defender Indicators lookup (ListDefenderIndicators)
   - Defender IP/File alerts (GetDefenderIpAlerts or GetDefenderFileAlerts)
   - Defender IP/File statistics

3. **Run Parallel Queries (Batch 2 - Activity):**
   - DeviceNetworkEvents (connections involving IoC)
   - AlertEvidence (alerts with IoC as evidence)
   - SecurityAlert (alerts mentioning IoC)
   - EmailUrlInfo (if domain/URL)

4. **CVE & Vulnerability Correlation:**
   - Extract CVE IDs from threat intel results
   - For each CVE: ListDefenderMachinesByVulnerability
   - Aggregate affected devices

5. **Export to JSON & Generate Summary:**
   ```
   temp/ioc_investigation_{ioc_normalized}_{timestamp}.json
   ```

---

## Execution Workflow

### 🚨 MANDATORY: Time Tracking Pattern

**YOU MUST TRACK AND REPORT TIME AFTER EVERY MAJOR STEP:**

```
[MM:SS] ✓ Step description (XX seconds)
```

**Required Reporting Points:**
1. After IoC normalization and type detection
2. After threat intelligence lookup
3. After activity/connection analysis
4. After CVE correlation and device enumeration
5. After JSON file creation
6. Final: Total elapsed time

---

### Phase 1: IoC Identification and Normalization (REQUIRED FIRST)

**Step 1.1: Detect IoC Type**
```python
# Regex patterns for IoC detection
IPv4: r'^(\d{1,3}\.){3}\d{1,3}$'
IPv6: r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
Domain: r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
URL: r'^https?://'
MD5: r'^[a-fA-F0-9]{32}$'
SHA1: r'^[a-fA-F0-9]{40}$'
SHA256: r'^[a-fA-F0-9]{64}$'
```

**Step 1.2: Normalize IoC**
- **IP Address:** Validate octets, detect IPv4 vs IPv6
- **Domain:** Lowercase, remove trailing dots, extract from URL if needed
- **URL:** Keep full URL, also extract domain for parallel investigation
- **Hash:** Lowercase

**Step 1.3: Create Investigation Context**
```json
{
  "ioc_type": "ip|domain|url|hash",
  "ioc_value": "<normalized_value>",
  "ioc_original": "<user_provided_value>",
  "extracted_domain": "<if_url>",
  "investigation_start": "<timestamp>",
  "date_range_start": "<StartDate>",
  "date_range_end": "<EndDate>"
}
```

---

### Phase 2: Parallel Threat Intelligence Collection

**CRITICAL:** Run ALL threat intel queries in parallel for speed!

#### Batch 1: Threat Intelligence APIs (Run ALL in parallel)

| Query | Tool/API | IoC Types |
|-------|----------|-----------|
| Defender IOC List | `ListDefenderIndicators` | IP, Domain, URL |
| Defender IP Alerts | `GetDefenderIpAlerts` | IP |
| Defender IP Statistics | `GetDefenderIpStatistics` | IP |
| Defender File Alerts | `GetDefenderFileAlerts` | Hash |
| Defender File Info | `GetDefenderFileInfo` | Hash |
| Defender File Statistics | `GetDefenderFileStatistics` | Hash |
| Defender File Machines | `GetDefenderFileRelatedMachines` | Hash |

#### Batch 2: Sentinel KQL Queries (Run ALL in parallel)

| Query | Table | IoC Types |
|-------|-------|-----------|
| TI Indicators Match | ThreatIntelIndicators | All |
| Network Connections | DeviceNetworkEvents | IP, Domain, URL |
| Alert Evidence | AlertEvidence | All |
| Security Alerts | SecurityAlert | All |
| Email URLs | EmailUrlInfo | Domain, URL |

---

### Phase 3: CVE Correlation and Vulnerability Management

**Step 3.1: Extract CVE IDs from Threat Intel**
- Parse threat intel results for CVE references (pattern: `CVE-\d{4}-\d{4,}`)
- Extract from: alert descriptions, threat family info, MITRE techniques

**Step 3.2: Query Affected Devices per CVE**
```
For each CVE_ID found:
  → ListDefenderMachinesByVulnerability(cveId: CVE_ID)
  → Collect: deviceId, deviceName, osPlatform, exposureLevel
```

**Step 3.3: Aggregate Device Exposure**
```json
{
  "cve_correlation": {
    "cve_ids_found": ["CVE-2024-1234", "CVE-2024-5678"],
    "affected_devices_by_cve": {
      "CVE-2024-1234": [
        {"deviceId": "...", "deviceName": "...", "osPlatform": "..."}
      ]
    },
    "total_unique_affected_devices": 15,
    "critical_cves": 2,
    "high_cves": 3
  }
}
```

---

### Phase 4: Activity and Connection Analysis

**For IP Address IoCs:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == '<IP_ADDRESS>' or LocalIP == '<IP_ADDRESS>'
| summarize 
    ConnectionCount = count(),
    UniqueDevices = dcount(DeviceId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Ports = make_set(RemotePort),
    Protocols = make_set(Protocol)
    by ActionType
| order by ConnectionCount desc
```

**For Domain IoCs:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has '<DOMAIN>'
| summarize 
    ConnectionCount = count(),
    UniqueDevices = dcount(DeviceId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    UniqueURLs = make_set(RemoteUrl, 10)
    by DeviceName
| order by ConnectionCount desc
```

**For File Hash IoCs:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA1 == '<HASH>' or SHA256 == '<HASH>' or MD5 == '<HASH>'
| summarize 
    EventCount = count(),
    UniqueDevices = dcount(DeviceId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    FileNames = make_set(FileName),
    FolderPaths = make_set(FolderPath, 5)
    by ActionType
| order by EventCount desc
```

---

### Phase 5: Export to JSON

Create single JSON file: `temp/ioc_investigation_{ioc_type}_{ioc_normalized}_{timestamp}.json`

---

## Sample KQL Queries

Use these exact patterns with appropriate MCP tools. Replace `<IOC_VALUE>`, `<StartDate>`, `<EndDate>`.

**⚠️ CRITICAL: START WITH THESE EXACT QUERY PATTERNS**
**These queries have been tested and validated. Use them as your PRIMARY reference.**

---

### 📅 Date Range Quick Reference

**🔴 STEP 0: GET CURRENT DATE FIRST (MANDATORY) 🔴**
- **ALWAYS check the current date from the context header BEFORE calculating date ranges**
- **NEVER use hardcoded years** - the year changes and you WILL query the wrong timeframe

**RULE 1: Real-Time/Recent Searches (Current Activity)**
- **Add +2 days to current date for end range**
- **Why +2?** +1 for timezone offset + +1 for inclusive end-of-day
- **Pattern**: Today is Jan 23 → Use `datetime(2026-01-25)` as end date

**RULE 2: Historical Searches (User-Specified Dates)**
- **Add +1 day to user's specified end date**
- **Why +1?** To include all 24 hours of the final day

---

### 1. Threat Intelligence Indicator Match (Sentinel)
```kql
let ioc_value = '<IOC_VALUE>';
ThreatIntelIndicators
| where TimeGenerated > ago(90d)
| where IsActive == true and Revoked == false
| where ObservableValue =~ ioc_value
    or Pattern has ioc_value
| project 
    TimeGenerated,
    Id,
    ObservableKey,
    ObservableValue,
    Pattern,
    Confidence,
    ValidFrom,
    ValidUntil,
    Tags,
    Data
| order by TimeGenerated desc
| take 20
```

### 2. IP Address - Network Connection Activity (Advanced Hunting)
```kql
let target_ip = '<IP_ADDRESS>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteIP == target_ip or LocalIP == target_ip
| summarize 
    TotalConnections = count(),
    UniqueDevices = dcount(DeviceId),
    UniquePorts = dcount(RemotePort),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 10),
    Ports = make_set(RemotePort, 20),
    Protocols = make_set(Protocol),
    ActionTypes = make_set(ActionType),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 10)
| extend Direction = iff(RemoteIP == target_ip, "Outbound", "Inbound")
```

### 3. IP Address - Detailed Connection Timeline
```kql
let target_ip = '<IP_ADDRESS>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteIP == target_ip or LocalIP == target_ip
| project 
    Timestamp,
    DeviceName,
    DeviceId,
    ActionType,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    LocalIP,
    LocalPort,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
| take 100
```

### 4. Domain - DNS and HTTP Connection Activity
```kql
let target_domain = '<DOMAIN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteUrl has target_domain
| summarize 
    TotalConnections = count(),
    UniqueDevices = dcount(DeviceId),
    UniqueUsers = dcount(InitiatingProcessAccountName),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 10),
    URLs = make_set(RemoteUrl, 20),
    Ports = make_set(RemotePort),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 10)
```

### 5. Domain - Detailed Connection Timeline
```kql
let target_domain = '<DOMAIN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteUrl has target_domain
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    ActionType,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
| take 100
```

### 6. URL - Email Delivery Analysis
```kql
let target_url = '<URL>';
let target_domain = '<DOMAIN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
EmailUrlInfo
| where TimeGenerated between (start .. end)
| where Url == target_url or Url has target_domain or UrlDomain =~ target_domain
| summarize 
    EmailCount = dcount(NetworkMessageId),
    UniqueURLs = make_set(Url, 10),
    UrlLocations = make_set(UrlLocation),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UrlDomain
| order by EmailCount desc
```

### 7. File Hash - Device File Events
```kql
let target_hash = '<HASH>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceFileEvents
| where Timestamp between (start .. end)
| where SHA1 =~ target_hash or SHA256 =~ target_hash or MD5 =~ target_hash
| summarize 
    EventCount = count(),
    UniqueDevices = dcount(DeviceId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 10),
    FileNames = make_set(FileName, 10),
    FolderPaths = make_set(FolderPath, 10),
    ActionTypes = make_set(ActionType)
| extend HashType = case(
    isnotempty(target_hash) and strlen(target_hash) == 32, "MD5",
    isnotempty(target_hash) and strlen(target_hash) == 40, "SHA1",
    isnotempty(target_hash) and strlen(target_hash) == 64, "SHA256",
    "Unknown")
```

### 8. Alert Evidence - IoC in Alerts
```kql
let ioc_value = '<IOC_VALUE>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
AlertEvidence
| where Timestamp between (start .. end)
| where RemoteIP == ioc_value 
    or RemoteUrl has ioc_value 
    or SHA1 =~ ioc_value 
    or SHA256 =~ ioc_value
    or FileName has ioc_value
| project 
    Timestamp,
    AlertId,
    Title,
    Severity,
    Categories,
    ServiceSource,
    EntityType,
    EvidenceRole,
    RemoteIP,
    RemoteUrl,
    FileName,
    SHA1,
    SHA256,
    DeviceName,
    AccountName
| order by Timestamp desc
| take 50
```

### 9. Security Alerts Mentioning IoC
```kql
let ioc_value = '<IOC_VALUE>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
AlertInfo
| where Timestamp between (start .. end)
| where Title has ioc_value or Category has ioc_value
| join kind=inner (
    AlertEvidence
    | where RemoteIP == ioc_value 
        or RemoteUrl has ioc_value 
        or SHA1 =~ ioc_value 
        or SHA256 =~ ioc_value
) on AlertId
| summarize 
    AlertCount = dcount(AlertId),
    Alerts = make_set(Title, 10),
    Severities = make_set(Severity),
    Categories = make_set(Category),
    AttackTechniques = make_set(AttackTechniques),
    AffectedDevices = make_set(DeviceName, 10)
```

### 10. Defender Custom IOC List Match
```kql
// Use Defender API: ListDefenderIndicators with filters
// indicatorType: "IpAddress" | "DomainName" | "Url" | "FileSha1" | "FileSha256" | "FileMd5"
// indicatorValue: "<IOC_VALUE>"
```

### 11. IP Address - Sign-in Analysis (Azure AD)
```kql
let target_ip = '<IP_ADDRESS>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where IPAddress == target_ip
| summarize 
    SignInCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    SuccessCount = countif(ResultType == '0'),
    FailureCount = countif(ResultType != '0'),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Users = make_set(UserPrincipalName, 10),
    Apps = make_set(AppDisplayName, 10),
    ResultTypes = make_set(ResultType)
| extend SuccessRate = round(100.0 * SuccessCount / SignInCount, 2)
```

### 12. CVE Extraction from Alerts
```kql
let ioc_value = '<IOC_VALUE>';
AlertInfo
| where Title has ioc_value or Category has ioc_value
| extend CVEs = extract_all(@"(CVE-\d{4}-\d{4,})", tostring(AttackTechniques))
| mv-expand CVE = CVEs
| where isnotempty(CVE)
| summarize 
    CVECount = dcount(tostring(CVE)),
    CVEs = make_set(tostring(CVE)),
    AlertCount = dcount(AlertId),
    Alerts = make_set(Title, 5)
```

---

## Defender API Queries

### IP Address Investigation

**Get Alerts for IP:**
```
Tool: GetDefenderIpAlerts (MCP)
Parameter: ipAddress = "<IP_ADDRESS>"
Returns: All security alerts associated with the IP
```

**Get IP Statistics:**
```
Tool: activate_file_and_ip_statistics_tools → GetDefenderIpStatistics
Parameter: ipAddress = "<IP_ADDRESS>"
Returns: Organization prevalence, device count, communication stats
```

**Find Devices by IP:**
```
Tool: FindDefenderMachinesByIp (MCP)
Parameters: 
  ipAddress = "<IP_ADDRESS>"
  timestamp = "<DATETIME>" (ISO 8601 format)
Returns: Devices that communicated with IP ±15 minutes of timestamp
```

### File Hash Investigation

**Get File Info:**
```
Tool: activate_file_and_ip_statistics_tools → GetDefenderFileInfo
Parameter: fileHash = "<SHA1_OR_SHA256>"
Returns: File details, global prevalence, threat determination
```

**Get File Statistics:**
```
Tool: activate_file_and_ip_statistics_tools → GetDefenderFileStatistics
Parameter: fileHash = "<SHA1_OR_SHA256>"
Returns: Organization statistics, device count, global stats
```

**Get File Alerts:**
```
Tool: GetDefenderFileAlerts (MCP)
Parameter: fileHash = "<SHA1_OR_SHA256>"
Returns: All alerts associated with the file
```

**Get Devices with File:**
```
Tool: GetDefenderFileRelatedMachines (MCP)
Parameter: fileHash = "<SHA1_OR_SHA256>"
Returns: All devices where file was observed
```

### Vulnerability Management

**List Devices Affected by CVE:**
```
Tool: ListDefenderMachinesByVulnerability (MCP)
Parameter: cveId = "CVE-YYYY-NNNNN"
Returns: All devices vulnerable to the CVE with exposure details
```

**Get Device Vulnerabilities:**
```
Tool: GetDefenderMachineVulnerabilities (MCP)
Parameter: id = "<DEVICE_ID>"
Returns: All CVEs affecting the specific device
```

### Custom IOC Management

**Search Existing IOCs:**
```
Tool: ListDefenderIndicators (MCP)
Parameters (all optional):
  indicatorType = "IpAddress" | "DomainName" | "Url" | "FileSha1" | "FileSha256" | "FileMd5"
  indicatorValue = "<IOC_VALUE>"
  action = "Alert" | "Block" | "Allow"
  severity = "Informational" | "Low" | "Medium" | "High"
Returns: Matching custom indicators in tenant
```

---

## JSON Export Structure

Create file: `temp/ioc_investigation_{ioc_type}_{ioc_normalized}_{timestamp}.json`

```json
{
  "investigation_metadata": {
    "ioc_type": "ip|domain|url|hash",
    "ioc_value": "<normalized_value>",
    "ioc_original": "<user_input>",
    "investigation_timestamp": "<ISO8601>",
    "date_range_start": "<StartDate>",
    "date_range_end": "<EndDate>",
    "elapsed_time_seconds": 45
  },
  "threat_intelligence": {
    "sentinel_ti_matches": [],
    "defender_ioc_matches": [],
    "defender_alerts": [],
    "threat_families": [],
    "confidence_score": 0-100,
    "verdict": "Malicious|Suspicious|Clean|Unknown"
  },
  "activity_analysis": {
    "network_connections": {
      "total_connections": 0,
      "unique_devices": 0,
      "unique_users": 0,
      "first_seen": "<datetime>",
      "last_seen": "<datetime>",
      "top_devices": [],
      "top_ports": [],
      "top_processes": []
    },
    "email_delivery": {
      "email_count": 0,
      "unique_urls": [],
      "delivery_locations": []
    },
    "file_activity": {
      "event_count": 0,
      "unique_devices": 0,
      "file_names": [],
      "folder_paths": [],
      "action_types": []
    },
    "signin_activity": {
      "signin_count": 0,
      "unique_users": 0,
      "success_rate": 0,
      "affected_users": []
    }
  },
  "alert_correlation": {
    "total_alerts": 0,
    "severity_breakdown": {
      "high": 0,
      "medium": 0,
      "low": 0,
      "informational": 0
    },
    "alert_titles": [],
    "attack_techniques": [],
    "affected_entities": []
  },
  "cve_correlation": {
    "cve_ids_found": [],
    "affected_devices_by_cve": {},
    "total_unique_affected_devices": 0,
    "cve_severity_breakdown": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    }
  },
  "organizational_exposure": {
    "total_affected_devices": 0,
    "affected_device_list": [],
    "exposure_level": "High|Medium|Low|None",
    "recommended_actions": []
  },
  "risk_assessment": {
    "overall_risk": "Critical|High|Medium|Low|Informational",
    "risk_factors": [],
    "mitigating_factors": [],
    "confidence": "High|Medium|Low"
  }
}
```

---

## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **No TI matches found** | IoC may be unknown; proceed with activity analysis |
| **Defender API returns 404** | IoC not in organization's scope; check Sentinel data |
| **Empty DeviceNetworkEvents** | Expand date range or check if MDE is deployed |
| **CVE not found in vulnerability DB** | CVE may be too new or not applicable to org assets |
| **Multiple IoC types detected** | Investigate each separately, correlate results |
| **Rate limiting on API calls** | Add delays between API calls, batch where possible |

### Required Field Defaults

If queries return no results, use these defaults:

```json
{
  "threat_intelligence": {
    "sentinel_ti_matches": [],
    "defender_alerts": [],
    "verdict": "Unknown",
    "confidence_score": 0
  },
  "activity_analysis": {
    "network_connections": {
      "total_connections": 0,
      "unique_devices": 0
    }
  },
  "cve_correlation": {
    "cve_ids_found": [],
    "affected_devices_by_cve": {},
    "total_unique_affected_devices": 0
  }
}
```

---

## Example Workflows

### Example 1: IP Address Investigation

**User says:** "Investigate IP 203.0.113.42 for the last 7 days"

**Workflow:**
1. **Identify IoC:** IPv4 Address, normalized: `203.0.113.42`
2. **Phase 1 - Threat Intel (parallel):**
   - `GetDefenderIpAlerts(ipAddress: "203.0.113.42")`
   - Sentinel ThreatIntelIndicators query
   - `ListDefenderIndicators(indicatorType: "IpAddress", indicatorValue: "203.0.113.42")`
3. **Phase 2 - Activity Analysis (parallel):**
   - DeviceNetworkEvents query for IP
   - SigninLogs query for IP
   - AlertEvidence query for IP
4. **Phase 3 - CVE Correlation:**
   - Extract CVEs from alerts
   - For each CVE: `ListDefenderMachinesByVulnerability`
5. **Export JSON and summarize findings**

### Example 2: Domain Investigation

**User says:** "Is evil-malware.com in our environment?"

**Workflow:**
1. **Identify IoC:** Domain, normalized: `evil-malware.com`
2. **Phase 1 - Threat Intel (parallel):**
   - Sentinel ThreatIntelIndicators query
   - `ListDefenderIndicators(indicatorType: "DomainName", indicatorValue: "evil-malware.com")`
3. **Phase 2 - Activity Analysis (parallel):**
   - DeviceNetworkEvents query for domain
   - EmailUrlInfo query for domain
   - AlertEvidence query for domain
4. **Phase 3 - Exposure Assessment:**
   - List all devices that connected
   - Identify affected users
5. **Export JSON and summarize findings**

### Example 3: File Hash Investigation with CVE Correlation

**User says:** "Investigate SHA256 a1b2c3... and check which devices are vulnerable"

**Workflow:**
1. **Identify IoC:** SHA256 Hash, normalized: `a1b2c3...`
2. **Phase 1 - Threat Intel (parallel):**
   - `GetDefenderFileInfo(fileHash: "a1b2c3...")`
   - `GetDefenderFileAlerts(fileHash: "a1b2c3...")`
   - `GetDefenderFileStatistics(fileHash: "a1b2c3...")`
3. **Phase 2 - Device Exposure:**
   - `GetDefenderFileRelatedMachines(fileHash: "a1b2c3...")`
   - DeviceFileEvents query
4. **Phase 3 - CVE Correlation:**
   - Extract CVEs from file threat family info
   - For each CVE: `ListDefenderMachinesByVulnerability`
   - Cross-reference with devices that have the file
5. **Export JSON and summarize with remediation priorities**

---

## Security Notes

- All investigations are logged for audit purposes
- IoC values may be sensitive - handle with care
- Follow organizational data classification policies
- Consider threat actor attribution implications
- Document investigation actions for incident timeline

---

## Integration with Other Skills

This skill can be combined with:
- **user-investigation**: When IoC is found in user's sign-in logs
- **computer-investigation**: When IoC is found on specific device
- **authentication-tracing**: When IoC IP appears in auth anomalies
- **ca-policy-investigation**: When IoC triggers conditional access events

**Cross-skill pivot example:**
"Investigate IP 203.0.113.42" → Found in user sign-ins → "Investigate user@domain.com" using user-investigation skill
