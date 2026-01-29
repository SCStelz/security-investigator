---
name: user-investigation
description: Use this skill when asked to investigate a user account for security issues, suspicious activity, or compliance review. Triggers on keywords like "investigate user", "security investigation", "user investigation", "check user activity", "analyze sign-ins", or when a UPN/email is mentioned with investigation context. This skill provides comprehensive Entra ID user security analysis including sign-in anomalies, MFA status, device compliance, audit logs, security incidents, Identity Protection risk, and automated HTML reports.
---

# User Security Investigation - Instructions

## Purpose

This skill performs comprehensive security investigations on Entra ID user accounts, analyzing sign-in patterns, anomalies, MFA status, device compliance, audit logs, Office 365 activity, security incidents, and Identity Protection risk signals.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Investigation Types](#available-investigation-types)** - Standard/Quick/Comprehensive
3. **[Quick Start](#quick-start-tldr)** - 5-step investigation pattern
4. **[Execution Workflow](#execution-workflow)** - Complete process
5. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns
6. **[Microsoft Graph Queries](#microsoft-graph-identity-protection-queries)** - Identity Protection integration
7. **[JSON Export Structure](#json-export-structure)** - Required fields
8. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY user investigation:**

1. **ALWAYS get User Object ID FIRST** (required for SecurityIncident and Identity Protection queries)
2. **ALWAYS calculate date ranges correctly** (use current date from context - see Date Range section)
3. **ALWAYS track and report time after each major step** (mandatory)
4. **ALWAYS run independent queries in parallel** (drastically faster execution)
5. **ALWAYS use `create_file` for JSON export** (NEVER use PowerShell terminal commands)
6. **⛔ ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)

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

**Date Range Rules:**
- **Real-time/recent searches:** Add +2 days to current date for end range
- **Historical ranges:** Add +1 day to user's specified end date
- **Example:** Current date = Nov 25; "Last 7 days" → `datetime(2025-11-18)` to `datetime(2025-11-27)`

---

## Available Investigation Types

### Standard Investigation (7 days)
**When to use:** General security reviews, routine investigations

**Example prompts:**
- "Investigate user@contoso.com for the last 7 days"
- "Run security investigation for user@domain.com from 2025-11-14 to 2025-11-21"

### Quick Investigation (1 day)
**When to use:** Urgent cases, recent suspicious activity

**Example prompts:**
- "Quick investigate suspicious.user@domain.com"
- "Run quick security check on admin@company.com"

### Comprehensive Investigation (30 days)
**When to use:** Deep-dive analysis, compliance reviews, thorough forensics

**Example prompts:**
- "Full investigation for compromised.user@domain.com"
- "Do a deep dive investigation on external.user@partner.com"

**All types include:** Anomaly detection, sign-in analysis, IP enrichment, Graph identity data, device compliance, audit logs, Office 365 activity, security alerts, threat intelligence, risk assessment, and automated recommendations.

---

## Quick Start (TL;DR)

When a user requests a security investigation:

1. **Get User ID:**
   ```
   mcp_microsoft_mcp_microsoft_graph_suggest_queries("get user by email")
   mcp_microsoft_mcp_microsoft_graph_get("/v1.0/users/<UPN>?$select=id,onPremisesSecurityIdentifier")
   ```

2. **Run Parallel Queries:**
   - Batch 1: 10 Sentinel queries (anomalies, IP extraction, sign-ins, IP counts, audit logs, incidents, etc.)
   - Batch 2: 6 Graph queries (profile, MFA, devices, Identity Protection)
   - Batch 3: Threat intel enrichment (after extracting IPs from batch 1)

3. **Export to JSON:**
   ```
   create_file("temp/investigation_<upn_prefix>_<timestamp>.json", json_content)
   ```

4. **Generate Report:**
   ```powershell
   $env:PYTHONPATH = "<WORKSPACE_ROOT>"
   .venv\Scripts\python.exe generate_report_from_json.py temp/investigation_<upn_prefix>_<timestamp>.json
   ```

5. **Track time after each major step** and report to user

---

## Execution Workflow

### 🚨 MANDATORY: Time Tracking Pattern

**YOU MUST TRACK AND REPORT TIME AFTER EVERY MAJOR STEP:**

```
[MM:SS] ✓ Step description (XX seconds)
```

**Required Reporting Points:**
1. After User ID retrieval
2. After parallel data collection
3. After JSON file creation
4. After report generation
5. Final: Total elapsed time

---

### Phase 1: Get User ID and SID (REQUIRED FIRST)

```
- Get user Object ID (Entra ID) and onPremisesSecurityIdentifier (Windows SID) from Microsoft Graph
- Query: /v1.0/users/<UPN>?$select=id,onPremisesSecurityIdentifier
```

**Why this is required:**
- User ID needed for SecurityIncident queries (alerts use User ID, not UPN)
- User ID needed for Identity Protection queries
- Windows SID needed for on-premises incident matching
- Missing User ID = missed incidents (e.g., "Device Code Authentication Flow Detected")

---

### Phase 2: Parallel Data Collection

**CRITICAL:** Use `create_file` tool to create JSON - NEVER use PowerShell terminal commands!

#### Batch 1: Sentinel Queries (Run ALL in parallel)
- IP selection query (Query 1) - Returns up to 15 prioritized IPs
- Anomalies query (Query 2)
- Sign-in by application (Query 3)
- Sign-in by location (Query 3b)
- Sign-in failures (Query 3c)
- Audit logs (Query 4)
- Office 365 activity (Query 5)
- DLP events (Query 10)
- Security incidents (Query 6)

#### After Batch 1 completes: Extract IP Array from Query 1 Results
- Extract IPAddress column into array: `["ip1", "ip2", "ip3", ...]`
- Build dynamic array for next batch: `let target_ips = dynamic(["ip1", "ip2", "ip3", ...]);`

#### Batch 2: IP Enrichment + Graph Queries (Run ALL in parallel)
- Threat Intel query (Query 11) - Uses IPs from Query 1
- IP frequency query (Query 3d) - Uses IPs from Query 1
- User profile (Graph)
- MFA methods (Graph)
- Registered devices (Graph)
- User risk profile (Graph)
- Risk detections (Graph)
- Risky sign-ins (Graph)

#### IP Selection Strategy (Query 1 - Deterministic KQL with Risky IPs):
- **Priority 1**: Anomaly IPs (from Signinlogs_Anomalies_KQL_CL where AnomalyType endswith "IP") - **8 slots**
- **Priority 2**: Risky IPs (from AADUserRiskEvents - Identity Protection flagged IPs) - **4 slots**
- **Priority 3**: Frequent IPs (top sign-in count for baseline context) - **3 slots**
- **Deduplication**: Anomaly IPs exclude from risky; Anomaly+Risky exclude from frequent (no duplicates)
- **Result**: Up to 15 unique IPs (8 anomaly + 4 risky-only + 3 frequent-only)

---

### Phase 3: Export to JSON

Create single JSON file: `temp/investigation_{upn_prefix}_{timestamp}.json`

Merge all results into one dict structure (see JSON Export Structure section below).

---

### Phase 4: Generate Report

```powershell
$env:PYTHONPATH = "<WORKSPACE_ROOT>"
cd "<WORKSPACE_ROOT>"
.\.venv\Scripts\python.exe generate_report_from_json.py temp/investigation_<upn_prefix>_<timestamp>.json
```

**The report generator handles:**
- Dataclass transformation logic
- IP enrichment (prioritized: anomaly IPs first, then frequent sign-in IPs, cap at 10)
- Dynamic risk assessment (NO hardcoded text - all metrics calculated from data)
- KQL query template population
- Result counts calculation
- HTML report generation with modern, streamlined design

---

## Required Field Specifications

### User Profile Query
```
/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,mail,userType,jobTitle,department,officeLocation,accountEnabled,onPremisesSecurityIdentifier
```
- All fields REQUIRED for report generation
- Default null values: `department="Unknown"`, `officeLocation="Unknown"`
- `onPremisesSecurityIdentifier` returns Windows SID (format: `S-1-5-21-...`) - REQUIRED for on-premises incident matching

### Device Query
```
/v1.0/users/<USER_ID>/ownedDevices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,registrationDateTime,isCompliant,isManaged,trustType,approximateLastSignInDateTime&$orderby=approximateLastSignInDateTime desc&$top=5&$count=true
```
- All fields REQUIRED for report generation
- Default null values: `trustType="Workplace"`, `approximateLastSignInDateTime="2025-01-01T00:00:00Z"`

### MFA Methods Query
```
/v1.0/users/<USER_ID>/authentication/methods?$top=5
```

---

## Sample KQL Queries

Use these exact patterns with `mcp_sentinel-data_query_lake`. Replace `<UPN>`, `<StartDate>`, `<EndDate>`.

**⚠️ CRITICAL: START WITH THESE EXACT QUERY PATTERNS**
**These queries have been tested and validated. Use them as your PRIMARY reference.**

---

### 📅 Date Range Quick Reference

**🔴 STEP 0: GET CURRENT DATE FIRST (MANDATORY) 🔴**
- **ALWAYS check the current date from the context header BEFORE calculating date ranges**
- **NEVER use hardcoded years** - the year changes and you WILL query the wrong timeframe

**RULE 1: Real-Time/Recent Searches (Current Activity)**
- **Add +2 days to current date for end range**
- **Why +2?** +1 for timezone offset (PST behind UTC) + +1 for inclusive end-of-day
- **Pattern**: Today is Nov 25 (PST) → Use `datetime(2025-11-27)` as end date

**RULE 2: Historical Searches (User-Specified Dates)**
- **Add +1 day to user's specified end date**
- **Why +1?** To include all 24 hours of the final day

**Examples Table (Assuming Current Date = November 27, 2025):**

| User Request | `<StartDate>` | `<EndDate>` | Rule Applied |
|--------------|---------------|-------------|--------------|
| "Last 7 days" | `2025-11-20` | `2025-11-29` | Rule 1 (+2) |
| "Last 30 days" | `2025-10-28` | `2025-11-29` | Rule 1 (+2) |
| "Nov 21 to Nov 23" | `2025-11-21` | `2025-11-24` | Rule 2 (+1) |

---

**🚨 CRITICAL - SIGN-IN QUERIES REQUIREMENT 🚨**
**You MUST run ALL THREE sign-in queries (3, 3b, 3c) to populate the `signin_events` dict!**

---

### 1. Extract Top Priority IPs (Deterministic IP Selection with Risky IPs)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let upn = '<UPN>';

// Priority 1: Anomaly IPs (top 8 by anomaly count)
let anomaly_ips = 
    Signinlogs_Anomalies_KQL_CL
    | where DetectedDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where AnomalyType endswith "IP"
    | summarize AnomalyCount = count(), FirstSeen = min(DetectedDateTime) by IPAddress = Value
    | order by AnomalyCount desc, FirstSeen asc
    | take 8
    | extend Priority = 1, Source = "Anomaly";

// Priority 2: Risky IPs from Identity Protection (top 10 for selection pool)
let risky_ips_pool = 
    AADUserRiskEvents
    | where ActivityDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where isnotempty(IpAddress)
    | summarize RiskCount = count(), FirstSeen = min(ActivityDateTime) by IPAddress = IpAddress
    | order by RiskCount desc, FirstSeen asc
    | take 10
    | extend Priority = 2, Source = "RiskyIP";

// Priority 3: Frequent Sign-in IPs (top 10 for selection pool)
let frequent_ips_pool =
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ upn
    | summarize SignInCount = count(), FirstSeen = min(TimeGenerated) by IPAddress
    | order by SignInCount desc, FirstSeen asc
    | take 10
    | extend Priority = 3, Source = "Frequent";

// Get anomaly IP list for exclusion from risky slot
let anomaly_ip_list = anomaly_ips | project IPAddress;

// Get anomaly + risky IP list for exclusion from frequent slot
let priority_ip_list = 
    union anomaly_ips, risky_ips_pool
    | project IPAddress;

// Reserve slots with deduplication: 8 anomaly + 4 risky + 3 frequent
let anomaly_slot = anomaly_ips | extend Count = AnomalyCount;
let risky_slot = risky_ips_pool 
    | join kind=anti anomaly_ip_list on IPAddress
    | order by RiskCount desc, FirstSeen asc
    | take 4
    | extend Count = RiskCount;
let frequent_slot = frequent_ips_pool 
    | join kind=anti priority_ip_list on IPAddress
    | order by SignInCount desc, FirstSeen asc
    | take 3
    | extend Count = SignInCount;

union anomaly_slot, risky_slot, frequent_slot
| project IPAddress, Priority, Count, Source
| order by Priority asc, Count desc
| project IPAddress
```

### 2. Anomalies (Signinlogs_Anomalies_KQL_CL)
```kql
Signinlogs_Anomalies_KQL_CL
| where DetectedDateTime between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserPrincipalName =~ '<UPN>'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10, "Medium",
    (CountryNovelty or CityNovelty or StateNovelty), "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| extend SeverityOrder = case(Severity == 'High', 1, Severity == 'Medium', 2, Severity == 'Low', 3, 4)
| project
    DetectedDateTime,
    UserPrincipalName,
    AnomalyType,
    Value,
    Severity,
    SeverityOrder,
    Country,
    City,
    State,
    CountryNovelty,
    CityNovelty,
    StateNovelty,
    ArtifactHits,
    FirstSeenRecent,
    BaselineSize,
    OS,
    BrowserFamily,
    RawBrowser
| order by SeverityOrder asc, DetectedDateTime desc
| take 10
```

### 3. Interactive & Non-Interactive Sign-ins (Summary by Application)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| summarize 
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress),
    UniqueLocations=dcount(Location)
    by AppDisplayName
| order by SignInCount desc
| take 5
```

### 3b. Sign-ins Summary by Location
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where isnotempty(Location)
| summarize 
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress),
    Applications=make_set(AppDisplayName, 5)
    by Location
| order by SignInCount desc
| take 5
```

### 3c. Sign-in Failures (Detailed)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where ResultType != '0'
| summarize 
    FailureCount=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Applications=make_set(AppDisplayName, 3),
    Locations=make_set(Location, 3)
    by ResultType, ResultDescription
| order by FailureCount desc
| take 5
```

### 3d. Sign-in Counts by IP Address
```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>", ...]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let most_recent_signins = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where IPAddress in (target_ips)
| summarize arg_max(TimeGenerated, *) by IPAddress;
most_recent_signins
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend HasAuthDetails = array_length(AuthDetails) > 0
| extend AuthDetailsToExpand = iif(HasAuthDetails, AuthDetails, dynamic([{"authenticationStepResultDetail": ""}]))
| mv-expand AuthDetailsToExpand
| extend AuthStepResultDetail = tostring(AuthDetailsToExpand.authenticationStepResultDetail)
| extend AuthPriority = case(
    AuthStepResultDetail has "MFA requirement satisfied", 1,
    AuthStepResultDetail has "Correct password", 2,
    AuthStepResultDetail has "Passkey", 2,
    AuthStepResultDetail has "Phone sign-in", 2,
    AuthStepResultDetail has "SMS verification", 2,
    AuthStepResultDetail has "First factor requirement satisfied", 3,
    AuthStepResultDetail has "MFA required", 4,
    999)
| summarize 
    MostRecentTime = any(TimeGenerated),
    MostRecentResultType = any(ResultType),
    HasAuthDetails = any(HasAuthDetails),
    MinPriority = min(AuthPriority),
    AllAuthDetails = make_set(AuthStepResultDetail)
    by IPAddress
| extend LastAuthResultDetail = case(
    MostRecentResultType != "0", "Authentication failed",
    not(HasAuthDetails) and MostRecentResultType == "0", "Token",
    MinPriority == 1 and AllAuthDetails has "MFA requirement satisfied", "MFA requirement satisfied by claim in the token",
    MinPriority == 2 and AllAuthDetails has "Correct password", "Correct password",
    MinPriority == 2 and AllAuthDetails has "Passkey (device-bound)", "Passkey (device-bound)",
    MinPriority == 3 and AllAuthDetails has "First factor requirement satisfied by claim in the token", "First factor requirement satisfied by claim in the token",
    MinPriority == 4 and AllAuthDetails has "MFA required in Entra ID", "MFA required in Entra ID",
    tostring(AllAuthDetails[0]))
| join kind=inner (
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ '<UPN>'
    | where IPAddress in (target_ips)
    | summarize 
        SignInCount = count(),
        SuccessCount = countif(ResultType == '0'),
        FailureCount = countif(ResultType != '0'),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by IPAddress
) on IPAddress
| project IPAddress, SignInCount, SuccessCount, FailureCount, FirstSeen, LastSeen, LastAuthResultDetail
| order by SignInCount desc
```

### 4. Entra ID Audit Log Activity (Aggregated Summary)
```kql
AuditLogs
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'
| summarize 
    Count=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Operations=make_set(OperationName, 10)
    by Category, Result
| order by Count desc
| take 10
```

### 5. Office 365 (Email / Teams / SharePoint) Activity Distribution
```kql
OfficeActivity
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserId =~ '<UPN>'
| summarize ActivityCount = count() by RecordType, Operation
| order by ActivityCount desc
| take 5
```

### 6. Security Incidents with Alerts Correlated to User
```kql
let targetUPN = "<UPN>";
let targetUserId = "<USER_OBJECT_ID>";  // REQUIRED: Get from Microsoft Graph API
let targetSid = "<WINDOWS_SID>";  // REQUIRED: Get from Microsoft Graph API
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has targetUPN or Entities has targetUserId or Entities has targetSid
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where not(tostring(Labels) has "Redirected")
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| extend ProviderIncidentUrl = tostring(AdditionalData.providerIncidentUrl)
| extend OwnerUPN = tostring(Owner.userPrincipalName)
| extend LastModifiedTime = todatetime(LastModifiedTime)
| summarize 
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    CreatedTime = any(CreatedTime),
    LastModifiedTime = any(LastModifiedTime),
    OwnerUPN = any(OwnerUPN),
    ProviderIncidentUrl = any(ProviderIncidentUrl),
    AlertCount = count()
    by ProviderIncidentId
| order by LastModifiedTime desc
| take 10
```

**CRITICAL:** ALL THREE identifiers are REQUIRED (`targetUPN`, `targetUserId`, `targetSid`) - different alert types use different entity formats.

### 10. DLP Events (Data Loss Prevention)
```kql
let upn = '<UPN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
CloudAppEvents
| where TimeGenerated between (start .. end)
| where ActionType in ("FileCopiedToRemovableMedia", "FileUploadedToCloud", "FileCopiedToNetworkShare")
| extend DlpAudit = parse_json(RawEventData)["DlpAuditEventMetadata"]
| extend File = parse_json(RawEventData)["ObjectId"]
| extend UserId = parse_json(RawEventData)["UserId"]
| extend DeviceName = parse_json(RawEventData)["DeviceName"]
| extend ClientIP = parse_json(RawEventData)["ClientIP"]
| extend RuleName = parse_json(RawEventData)["PolicyMatchInfo"]["RuleName"]
| extend Operation = parse_json(RawEventData)["Operation"]
| extend TargetDomain = parse_json(RawEventData)["TargetDomain"]
| extend TargetFilePath = parse_json(RawEventData)["TargetFilePath"]
| where isnotnull(DlpAudit)
| where UserId == upn
| summarize by TimeGenerated, tostring(UserId), tostring(DeviceName), tostring(ClientIP), tostring(RuleName), tostring(File), tostring(Operation), tostring(TargetDomain), tostring(TargetFilePath)
| order by TimeGenerated desc
| take 5
```

### 11. Threat Intelligence IP Enrichment (Bulk IP Query)
```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>"]);
ThreatIntelIndicators
| extend IndicatorType = replace_string(replace_string(replace_string(tostring(split(ObservableKey, ":", 0)), "[", ""), "]", ""), "\"", "")
| where IndicatorType in ("ipv4-addr", "ipv6-addr", "network-traffic")
| extend NetworkSourceIP = toupper(ObservableValue)
| where NetworkSourceIP in (target_ips)
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| extend TrafficLightProtocolLevel = tostring(parse_json(AdditionalFields).TLPLevel)
| extend ActivityGroupNames = extract(@"ActivityGroup:(\S+)", 1, tostring(parse_json(Data).labels))
| summarize arg_max(TimeGenerated, *) by NetworkSourceIP
| project 
    TimeGenerated,
    IPAddress = NetworkSourceIP,
    ThreatDescription = Description,
    ActivityGroupNames,
    Confidence,
    ValidUntil,
    TrafficLightProtocolLevel,
    IsActive
| order by Confidence desc, TimeGenerated desc
```

---

## Microsoft Graph Identity Protection Queries

**CRITICAL: Always query Identity Protection data in Phase 2 (Batch 2) of investigation workflow**

### Step 1: Get User Object ID and Windows SID
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,onPremisesSecurityIdentifier")
```

### Step 2: Get User Risk Profile
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/identityProtection/riskyUsers/<USER_ID>")
```
Returns: riskLevel (low/medium/high/none), riskState (atRisk/confirmedCompromised/dismissed/remediated)

### Step 3: Get Risk Detections
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/identityProtection/riskDetections?$filter=userId eq '<USER_ID>'&$select=id,detectedDateTime,riskEventType,riskLevel,riskState,riskDetail,ipAddress,location,activity,activityDateTime&$orderby=detectedDateTime desc&$top=10")
```
Returns: Array of risk events with riskEventType (unlikelyTravel, unfamiliarFeatures, anonymizedIPAddress, etc.)

### Step 4: Get Risky Sign-ins
```
mcp_microsoft_mcp_microsoft_graph_get("/beta/auditLogs/signIns?$filter=userId eq '<USER_ID>' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&$select=id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,location,riskState,riskLevelDuringSignIn,riskEventTypes_v2,riskDetail,status&$orderby=createdDateTime desc&$top=5")
```
**NOTE**: Risky sign-ins are ONLY available in `/beta` endpoint, not `/v1.0`

### Common Risk Event Types
- **unlikelyTravel**: User traveled impossible distance between sign-ins
- **unfamiliarFeatures**: Sign-in from unfamiliar location/device/IP
- **anonymizedIPAddress**: Sign-in from Tor, VPN, or proxy
- **maliciousIPAddress**: Sign-in from known malicious IP
- **leakedCredentials**: User credentials found in leak databases

---

## JSON Export Structure

Export MCP query results to a single JSON file with these required keys:

```json
{
  "upn": "user@domain.com",
  "user_id": "<USER_OBJECT_ID>",
  "user_sid": "<WINDOWS_SID>",
  "investigation_date": "2025-11-23",
  "start_date": "2025-11-15",
  "end_date": "2025-11-24",
  "timestamp": "20251123_164532",
  "anomalies": [...],
  "signin_apps": [...],
  "signin_locations": [...],
  "signin_failures": [...],
  "signin_ip_counts": [...],
  "audit_events": [...],
  "office_events": [...],
  "dlp_events": [...],
  "incidents": [...],
  "user_profile": {
    "id": "...",
    "displayName": "...",
    "userPrincipalName": "...",
    "mail": "...",
    "userType": "...",
    "jobTitle": "...",
    "department": "...",
    "officeLocation": "...",
    "accountEnabled": true
  },
  "mfa_methods": {...},
  "devices": [...],
  "risk_profile": {...},
  "risk_detections": [...],
  "risky_signins": [...],
  "threat_intel_ips": [...]
}
```

---

## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Missing `department` or `officeLocation`** | Use `"Unknown"` as default value |
| **No anomalies found** | Export empty array: `"anomalies": []` |
| **Graph API returns 404 for user** | Verify UPN is correct |
| **Sentinel query timeout** | Reduce date range or add `| take 5` |
| **Missing `trustType` in device query** | Use default: `"Workplace"` |
| **No results from SecurityIncident query** | Ensure using ALL THREE identifiers (UPN, UserID, SID) |
| **Risky sign-ins query fails** | Must use `/beta` endpoint |

### Required Field Defaults

```json
{
  "department": "Unknown",
  "officeLocation": "Unknown",
  "trustType": "Workplace",
  "approximateLastSignInDateTime": "2025-01-01T00:00:00Z"
}
```

### Empty Result Handling

```json
{
  "anomalies": [],
  "signin_apps": [],
  "signin_locations": [],
  "signin_failures": [],
  "audit_events": [],
  "office_events": [],
  "dlp_events": [],
  "incidents": [],
  "risk_detections": [],
  "risky_signins": [],
  "threat_intel_ips": []
}
```

---

## Integration with Main Copilot Instructions

This skill follows all patterns from the main `copilot-instructions.md`:
- **Date range handling:** Uses +2 day rule for real-time searches
- **Parallel execution:** Runs independent queries simultaneously
- **Time tracking:** Mandatory reporting after each phase
- **Token management:** Uses `create_file` for all output
- **Follow-up analysis:** Reference `copilot-instructions.md` for authentication tracing workflows

**Example invocations:**
- "Investigate user@domain.com for the last 7 days"
- "Quick security check on admin@company.com"
- "Full investigation for compromised.user@domain.com last 30 days"

---

*Last Updated: January 12, 2026*
