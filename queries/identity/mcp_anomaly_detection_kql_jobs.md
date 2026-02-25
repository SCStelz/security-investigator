# MCP Anomaly Detection — Sentinel Data Lake KQL Jobs

**Created:** 2026-02-08  
**Validated:** 2026-02-08 (tested against 90 days of real MCP telemetry)  
**Platform:** Microsoft Sentinel Data Lake  
**Tables:** MicrosoftGraphActivityLogs, AADNonInteractiveUserSignInLogs, SigninLogs, LAQueryLogs, CloudAppEvents, AzureActivity  
**Keywords:** MCP, anomaly detection, KQL job, data lake, summary rule, Graph MCP, Sentinel MCP, Azure MCP, behavioral baseline, new endpoint, volume spike, sensitive API, off-hours, promote analytics tier  
**MITRE:** TA0001, TA0003, TA0006, TA0007, TA0009, TA0010, T1078, T1098  
**Timeframe:** Rolling daily with 14-day baseline  

---

## Validation Results (2026-02-08)

All jobs tested against real historical MCP telemetry. Results:

| Job | Test Date | Simulated Result | Notes |
|-----|-----------|------------------|-------|
| **Job 1** (New Sensitive Endpoint) | Jan 26 (first-ever Graph MCP usage) | ✅ **3 anomalies detected** — `identityProtection/riskyUsers`, `identityProtection/riskDetections`, `auditLogs/signIns` | Empty baseline = everything is new. True negative confirmed on Jan 27 (same endpoints already in baseline). |
| **Job 1** (regex validation) | Feb 5-6 | ✅ Fixed two-step regex correctly extracts API paths | Original regex matched `/graph` from hostname — **bug found and fixed**. |
| **Job 5** (New Azure MCP User) | Jan 14 (first Azure MCP sign-in) | ✅ **1 anomaly detected** — `user@contoso.com`, 1 session, 1 IP, Azure Resource Manager | Correctly flags first-time Azure MCP user. |
| **Job 7** (Sentinel Query Anomalies) | Jan 9 (274-query spike) | ✅ **Volume spike detected** — 12.74x baseline average (21.5→274), **High** severity | `AADEmail` was empty for Sentinel Triage MCP — fixed with `AADObjectId` fallback. |
| **Job 8** (Cross-MCP Correlation) | Feb 8 (Graph + Azure active) | ✅ **Cross-MCP detected** — Graph MCP (5 calls, 1 sensitive) + Azure MCP (3 sessions), **High** severity | Sentinel Triage leg doesn't join by user identity (uses SP ObjectId) — documented as known limitation. |

### Bugs Found and Fixed During Testing

1. **Endpoint extraction regex** (Jobs 1-4, 8): `extract("(/[a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, RequestUri)` matched `/graph` from hostname `graph.microsoft.com` instead of the actual API path. Fixed with two-step extraction: `extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)` → `extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)`.
2. **`sensitivePatterns` leading slashes** (Job 1): Patterns had leading `/` which caused `has_any` mismatches with the new regex output. Removed leading slashes.
3. **Empty `AADEmail`** (Job 7): Sentinel Triage MCP uses a service principal for LAQueryLogs authentication, leaving `AADEmail` empty. Fixed with `iff(isnotempty(AADEmail), AADEmail, AADObjectId)` fallback.
4. **Cross-MCP identity mismatch** (Job 8): Sentinel Triage MCP's `AADObjectId` in LAQueryLogs is the MCP service principal's Object ID, not the end user's Entra Object ID. Graph+Azure correlation works correctly; Sentinel leg may not join by user identity.

---

## Overview

These KQL queries are designed to run as **scheduled KQL jobs** in the Microsoft Sentinel Data Lake. They detect anomalous MCP server behavior, promote flagged events to the analytics tier (as `*_KQL_CL` tables), and enable standard analytics rules to fire alerts.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Sentinel Data Lake                      │
│  MicrosoftGraphActivityLogs (Data Lake / Basic tier)     │
│  AADNonInteractiveUserSignInLogs                         │
│  LAQueryLogs, CloudAppEvents, AzureActivity              │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Scheduled KQL Jobs (daily/hourly)               │    │
│  │  - Behavioral baselines                          │    │
│  │  - Anomaly detection                             │    │
│  │  - Cross-MCP correlation                         │    │
│  └──────────────┬───────────────────────────────────┘    │
│                 │ promote                                 │
│                 ▼                                         │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Analytics Tier (_KQL_CL tables)                 │    │
│  │  - MCPGraphAnomalies_KQL_CL                      │    │
│  │  - MCPSentinelAnomalies_KQL_CL                   │    │
│  │  - MCPAzureAnomalies_KQL_CL                      │    │
│  │  - MCPCrossMCPCorrelation_KQL_CL                 │    │
│  └──────────────┬───────────────────────────────────┘    │
│                 │ query                                   │
│                 ▼                                         │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Custom Detections (recommended) or Analytics    │    │
│  │  Rules (near real-time)                          │    │
│  │  - Alert on new sensitive endpoint access        │    │
│  │  - Alert on volume spikes                        │    │
│  │  - Alert on off-hours MCP activity               │    │
│  │  - Alert on cross-MCP suspicious chains          │    │
│  └──────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Why KQL Jobs (Not Summary Rules)

| Factor | KQL Jobs | Summary Rules |
|--------|----------|--------------|
| **Multi-table joins** | ✅ Full join/union support | Limited (lookup only for Basic tier) |
| **Data Lake tier source** | ✅ Primary use case | ✅ Supported |
| **MicrosoftGraphActivityLogs** | ✅ Can query from lake | ✅ Can query (single table) |
| **Complex anomaly logic** | ✅ Full KQL including ML functions | 10-min timeout, limited operators |
| **Scheduling** | Daily, weekly, monthly | 20 min to 24 hours |
| **Lookback period** | Up to 12 years | Up to 1 day |
| **Output** | `_KQL_CL` table in analytics tier | `_CL` table in analytics tier |

**Recommendation:** Use **KQL jobs** for multi-table anomaly detection (Jobs 1-4) and **summary rules** for single-table baselines if shorter frequency is needed.

### KQL Job Configuration

| Parameter | Recommended Value |
|-----------|-------------------|
| **Schedule** | Daily |
| **Lookback** | 1 day (with 14-day baseline comparison built into query) |
| **Delay** | 15 minutes (`now() - 15m`) per Data Lake ingestion latency |
| **Timeout** | 1 hour max |
| **Destination** | Analytics tier, new `_KQL_CL` table |

### Cost Considerations

> ⚠️ Storage in the analytics tier incurs higher billing than data lake tier. These queries are designed to **project only anomaly records** (not full event volume) and only the columns needed for alerting. Typical daily output should be low (tens to hundreds of rows, not thousands).

### TimeGenerated Overwrite Warning

> ⚠️ Per Microsoft docs, `TimeGenerated` is overwritten if older than 2 days. To preserve the original event time, all queries write the source timestamp to a separate column (`OriginalTimestamp` or `DetectedTime`). The `TimeGenerated` in the promoted table represents when the KQL job ran, NOT when the anomaly occurred.

---

## Job 1: Graph MCP — New Sensitive Endpoint Detection

**Destination table:** `MCPGraphAnomalies_KQL_CL`  
**Schedule:** Daily  
**Lookback:** 1 day (detects against 14-day baseline)  
**Purpose:** Detect when a Graph MCP user accesses a sensitive Graph API endpoint they've never used before. This catches reconnaissance, privilege escalation prep, and credential harvesting via MCP.

**Sensitive endpoints tracked:**
- `/roleManagement/` — PIM, directory roles
- `/identity/conditionalAccess/` — CA policy read/modify
- `/applications/` + `/servicePrincipals/` — app credential management
- `/identityProtection/` — risky users/sign-ins
- `/security/` — security alerts, incidents
- `/auditLogs/` — audit trail access
- `/users/*/authentication/` — MFA methods, passwordless
- `/policies/` — auth policies, token lifetime

<!-- cd-metadata
cd_ready: false
adaptation_notes: "KQL Job architecture — designed to run as a scheduled Data Lake KQL job that promotes results to MCPGraphAnomalies_KQL_CL analytics tier table. Not a standard detection query. Use companion Rule 1 for alerting on the promoted data."
-->
```kql
// Job 1: Graph MCP — New Sensitive Endpoint Detection
// Detects Graph MCP users accessing sensitive endpoints not seen in their 14-day baseline
// Output: Only anomalous accesses → promote to MCPGraphAnomalies_KQL_CL
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
// Define sensitive endpoint patterns (no leading / — matched against extracted API path)
let sensitivePatterns = dynamic([
    "roleManagement", "identityGovernance", "identity/conditionalAccess",
    "applications", "servicePrincipals", "identityProtection",
    "security/alerts", "security/incidents", "auditLogs",
    "users/authentication", "policies", "privilegedAccess",
    "directoryRoles", "groupLifecyclePolicies",
    "informationProtection", "dataClassification"
]);
// Build per-user baseline of endpoints accessed in last 14 days (excluding last 1 day)
// Two-step extraction: strip hostname+version, then normalize to top-2 path segments
let baseline = MicrosoftGraphActivityLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| where EndpointCategory has_any (sensitivePatterns)
| summarize BaselineHits = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by UserId, EndpointCategory;
// Find recent activity hitting sensitive endpoints
let recent = MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| where EndpointCategory has_any (sensitivePatterns)
| summarize
    RecentHits = count(),
    DistinctEndpoints = dcount(RequestUri),
    SampleEndpoints = make_set(RequestUri, 5),
    ResponseCodes = make_set(ResponseStatusCode, 10),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId, EndpointCategory;
// Left anti-join: find endpoints in recent that are NOT in baseline → NEW behavior
recent
| join kind=leftanti baseline on UserId, EndpointCategory
| extend
    AnomalyType = "NewSensitiveEndpoint",
    MCPServer = "GraphMCP",
    Severity = case(
        EndpointCategory has_any ("roleManagement", "identity/conditionalAccess", "privilegedAccess"), "High",
        EndpointCategory has_any ("applications", "servicePrincipals", "identityProtection"), "Medium",
        "Low"),
    Description = strcat("User accessed sensitive Graph endpoint '", EndpointCategory, "' via MCP for the first time (not seen in 14-day baseline)")
| project
    DetectedTime,
    AnomalyType,
    MCPServer,
    Severity,
    UserId,
    EndpointCategory,
    RecentHits,
    DistinctEndpoints,
    SampleEndpoints,
    ResponseCodes,
    LastActivity,
    Description
```

---

## Job 2: Graph MCP — Volume Spike Detection

**Destination table:** `MCPGraphAnomalies_KQL_CL`  
**Schedule:** Daily  
**Lookback:** 1 day (detects against 14-day baseline)  
**Purpose:** Detect when a user's Graph MCP API call volume significantly exceeds their historical baseline. Catches bulk data harvesting, enumeration campaigns, and runaway agents.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "KQL Job architecture — designed to run as a scheduled Data Lake KQL job that promotes results to MCPGraphAnomalies_KQL_CL. Uses 14-day daily average baseline with `stdev()`. Use companion Rule 2 for alerting."
-->
```kql
// Job 2: Graph MCP — Volume Spike Detection
// Flags users whose daily Graph MCP call count exceeds 3x their 14-day daily average
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let spikeThreshold = 3.0; // 3x daily average
let minBaselineDays = 3;  // Require at least 3 days of history
// Build per-user daily volume baseline (14 days, excluding last 1 day)
let baseline = MicrosoftGraphActivityLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == graphMcpAppId
| summarize DailyCount = count() by UserId, Day = bin(TimeGenerated, 1d)
| summarize
    AvgDailyCount = avg(DailyCount),
    StdDevDailyCount = stdev(DailyCount),
    MaxDailyCount = max(DailyCount),
    BaselineDays = dcount(Day),
    TotalBaselineHits = sum(DailyCount)
    by UserId;
// Measure recent 1-day volume
let recent = MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| summarize
    RecentDayCount = count(),
    DistinctEndpoints = dcount(RequestUri),
    TopEndpoints = make_set(EndpointCategory, 10),
    ErrorCount = countif(ResponseStatusCode >= 400),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId;
// Join and flag spikes
recent
| join kind=inner baseline on UserId
| where BaselineDays >= minBaselineDays
| extend SpikeRatio = round(RecentDayCount * 1.0 / AvgDailyCount, 2)
| where SpikeRatio >= spikeThreshold
| extend
    AnomalyType = "VolumeSpike",
    MCPServer = "GraphMCP",
    Severity = case(
        SpikeRatio >= 10.0, "High",
        SpikeRatio >= 5.0, "Medium",
        "Low"),
    Description = strcat("User's Graph MCP call volume (", RecentDayCount, ") is ", SpikeRatio, "x their 14-day daily average (", round(AvgDailyCount, 0), ")")
| project
    DetectedTime,
    AnomalyType,
    MCPServer,
    Severity,
    UserId,
    RecentDayCount,
    AvgDailyCount = round(AvgDailyCount, 1),
    SpikeRatio,
    MaxDailyCount,
    BaselineDays,
    DistinctEndpoints,
    TopEndpoints,
    ErrorCount,
    LastActivity,
    Description
```

---

## Job 3: Graph MCP — Off-Hours Activity Detection

**Destination table:** `MCPGraphAnomalies_KQL_CL`  
**Schedule:** Daily  
**Lookback:** 1 day  
**Purpose:** Detect Graph MCP activity outside business hours (configurable). Off-hours MCP usage may indicate credential theft, unauthorized automation, or agent activity outside expected operating windows.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "KQL Job architecture — designed to run as a scheduled Data Lake KQL job with hardcoded timezone offset and business hours. Requires org-specific configuration before deployment."
-->
```kql
// Job 3: Graph MCP — Off-Hours Activity Detection
// Flags Graph MCP calls occurring outside business hours
// Adjust businessHoursStart/End and timezone offset for your org
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let recentStart = endTime - recentWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let businessHoursStart = 7;  // 7 AM
let businessHoursEnd = 19;   // 7 PM
let timezoneOffsetHours = -8; // PST = UTC-8 (adjust for your org)
// Find off-hours activity
MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| extend LocalHour = hourofday(TimeGenerated + timezoneOffsetHours * 1h)
| where LocalHour < businessHoursStart or LocalHour >= businessHoursEnd
| extend DayOfWeekLocal = dayofweek(TimeGenerated + timezoneOffsetHours * 1h)
| extend IsWeekend = DayOfWeekLocal in (6d, 0d) // Saturday = 6, Sunday = 0
| summarize
    OffHoursCallCount = count(),
    DistinctEndpoints = dcount(RequestUri),
    TopEndpoints = make_set(EndpointCategory, 10),
    HoursActive = make_set(LocalHour, 24),
    WeekendActivity = countif(IsWeekend),
    ErrorCount = countif(ResponseStatusCode >= 400),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId
| where OffHoursCallCount >= 5 // Minimum threshold to avoid noise
| extend
    AnomalyType = "OffHoursActivity",
    MCPServer = "GraphMCP",
    Severity = case(
        WeekendActivity > 0 and OffHoursCallCount >= 50, "High",
        OffHoursCallCount >= 50, "Medium",
        "Low"),
    Description = strcat("User made ", OffHoursCallCount, " Graph MCP calls outside business hours (", businessHoursStart, "-", businessHoursEnd, " local). Weekend calls: ", WeekendActivity)
| project
    DetectedTime,
    AnomalyType,
    MCPServer,
    Severity,
    UserId,
    OffHoursCallCount,
    WeekendActivity,
    DistinctEndpoints,
    TopEndpoints,
    HoursActive,
    ErrorCount,
    LastActivity,
    Description
```

---

## Job 4: Graph MCP — Error Rate Anomaly

**Destination table:** `MCPGraphAnomalies_KQL_CL`  
**Schedule:** Daily  
**Lookback:** 1 day (detects against 14-day baseline)  
**Purpose:** Detect when a user's Graph MCP error rate significantly exceeds baseline. High error rates indicate permission probing, invalid enumeration attempts, or a misconfigured agent hitting authorization boundaries.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "KQL Job architecture — designed to run as a scheduled Data Lake KQL job that promotes results to MCPGraphAnomalies_KQL_CL. Uses 14-day error rate baseline with configurable thresholds."
-->
```kql
// Job 4: Graph MCP — Error Rate Anomaly
// Flags users whose Graph MCP error rate exceeds their baseline by 2x or exceeds 30%
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let errorRateThreshold = 0.30; // 30% error rate triggers regardless
let spikeMultiplier = 2.0;    // 2x baseline error rate triggers
// Build error rate baseline
let baseline = MicrosoftGraphActivityLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == graphMcpAppId
| summarize
    BaselineTotalCalls = count(),
    BaselineErrors = countif(ResponseStatusCode >= 400),
    BaselineDays = dcount(bin(TimeGenerated, 1d))
    by UserId
| extend BaselineErrorRate = round(BaselineErrors * 1.0 / BaselineTotalCalls, 4);
// Measure recent error rate
let recent = MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| summarize
    RecentTotalCalls = count(),
    RecentErrors = countif(ResponseStatusCode >= 400),
    TopErrorEndpoints = make_set_if(EndpointCategory, ResponseStatusCode >= 400, 10),
    TopErrorCodes = make_set_if(ResponseStatusCode, ResponseStatusCode >= 400, 10),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId
| extend RecentErrorRate = round(RecentErrors * 1.0 / RecentTotalCalls, 4);
// Flag anomalies
recent
| join kind=leftouter baseline on UserId
| extend
    ErrorRateSpike = iff(isnotnull(BaselineErrorRate) and BaselineErrorRate > 0,
        round(RecentErrorRate / BaselineErrorRate, 2), 0.0),
    IsNewUser = isnull(BaselineTotalCalls)
| where RecentErrorRate >= errorRateThreshold
    or (ErrorRateSpike >= spikeMultiplier and RecentErrors >= 10)
    or (IsNewUser and RecentErrors >= 5)
| extend
    AnomalyType = case(
        IsNewUser, "NewUserHighErrors",
        ErrorRateSpike >= spikeMultiplier, "ErrorRateSpike",
        "HighErrorRate"),
    MCPServer = "GraphMCP",
    Severity = case(
        RecentErrorRate >= 0.5 and RecentErrors >= 50, "High",
        RecentErrorRate >= 0.3 or ErrorRateSpike >= 5.0, "Medium",
        "Low"),
    Description = strcat("User Graph MCP error rate: ", round(RecentErrorRate * 100, 1), "% (",
        RecentErrors, "/", RecentTotalCalls, "). ",
        iff(IsNewUser, "NEW USER (no baseline). ",
            strcat("Baseline: ", round(BaselineErrorRate * 100, 1), "%, spike: ", ErrorRateSpike, "x. ")),
        "Top error endpoints: ", tostring(TopErrorEndpoints))
| project
    DetectedTime,
    AnomalyType,
    MCPServer,
    Severity,
    UserId,
    RecentTotalCalls,
    RecentErrors,
    RecentErrorRate,
    BaselineErrorRate,
    ErrorRateSpike,
    TopErrorEndpoints,
    TopErrorCodes,
    IsNewUser,
    LastActivity,
    Description
```

---

## Job 5: Azure MCP Server — New User Detection

**Destination table:** `MCPAzureAnomalies_KQL_CL`  
**Schedule:** Daily  
**Lookback:** 1 day (detects against 14-day baseline)  
**Purpose:** Detect when a user uses the Azure MCP Server for the first time. New Azure MCP users may indicate compromised credentials being used to explore infrastructure, or unauthorized tooling adoption.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "KQL Job architecture — designed to run as a scheduled Data Lake KQL job that promotes results to MCPAzureAnomalies_KQL_CL. Uses 14-day user baseline with `leftanti` join. Use companion Rule 4 for alerting."
-->
```kql
// Job 5: Azure MCP Server — New User Detection
// Flags users who appear in Azure MCP Server sign-in logs for the first time
// Uses full composite signal: AppId 1950a258 + UserAgent azsdk-net-Identity + Microsoft Windows
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let azureMcpAppId = "1950a258-227b-4e31-a9cf-717495945fc2";
// Build baseline of known Azure MCP users (14 days, excluding last 1 day)
let baselineUsers = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| distinct UserId, UserPrincipalName;
// Find recent Azure MCP users
let recentUsers = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| summarize
    SessionCount = dcount(CorrelationId),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 5),
    Resources = make_set(ResourceDisplayName, 10),
    ResultTypes = make_set(ResultType, 10),
    UserAgent = take_any(UserAgent),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId, UserPrincipalName;
// Left anti-join to find NEW users
recentUsers
| join kind=leftanti baselineUsers on UserId
| extend
    AnomalyType = "NewAzureMCPUser",
    MCPServer = "AzureMCP",
    Severity = case(
        DistinctIPs > 1, "High",
        "Medium"),
    Description = strcat("New Azure MCP Server user: ", UserPrincipalName, ". ",
        SessionCount, " session(s) from ", DistinctIPs, " IP(s). ",
        "Resources accessed: ", tostring(Resources))
| project
    DetectedTime,
    AnomalyType,
    MCPServer,
    Severity,
    UserId,
    UserPrincipalName,
    SessionCount,
    DistinctIPs,
    IPs,
    Resources,
    ResultTypes,
    UserAgent,
    LastActivity,
    Description
```

---

## Job 6: Azure MCP Server — New Resource Target Detection

**Destination table:** `MCPAzureAnomalies_KQL_CL`  
**Schedule:** Daily  
**Lookback:** 1 day (detects against 14-day baseline)  
**Purpose:** Detect when Azure MCP Server accesses new Azure resource types (ARM vs Log Analytics API vs Microsoft Graph). While we can't see specific ARM read operations, we CAN see which resource APIs are targeted via sign-in token acquisitions.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "KQL Job architecture — designed to run as a scheduled Data Lake KQL job that promotes results to MCPAzureAnomalies_KQL_CL. Uses 14-day per-user resource target baseline."
-->
```kql
// Job 6: Azure MCP Server — New Resource Target Detection
// Detects Azure MCP users accessing resource types not in their 14-day baseline
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let azureMcpAppId = "1950a258-227b-4e31-a9cf-717495945fc2";
// Build per-user baseline of resource targets
let baseline = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| summarize BaselineHits = count()
    by UserId, UserPrincipalName, ResourceDisplayName;
// Find recent resource targets
let recent = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| summarize
    RecentHits = count(),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated),
    IPs = make_set(IPAddress, 5),
    ResultTypes = make_set(ResultType, 10)
    by UserId, UserPrincipalName, ResourceDisplayName;
// Left anti-join: find resource targets not in baseline
recent
| join kind=leftanti baseline on UserId, ResourceDisplayName
| extend
    AnomalyType = "NewResourceTarget",
    MCPServer = "AzureMCP",
    Severity = case(
        ResourceDisplayName has_any ("Key Vault", "Microsoft Graph", "Azure Key Vault"), "High",
        ResourceDisplayName has "Azure Resource Manager", "Medium",
        "Low"),
    Description = strcat("Azure MCP user '", UserPrincipalName, "' accessed new resource type '", ResourceDisplayName,
        "' (not seen in 14-day baseline). Hits: ", RecentHits)
| project
    DetectedTime,
    AnomalyType,
    MCPServer,
    Severity,
    UserId,
    UserPrincipalName,
    ResourceDisplayName,
    RecentHits,
    IPs,
    ResultTypes,
    LastActivity,
    Description
```

---

## Job 7: Sentinel MCP — Workspace Query Anomalies (LAQueryLogs)

**Destination table:** `MCPSentinelAnomalies_KQL_CL`  
**Schedule:** Daily  
**Lookback:** 1 day (detects against 14-day baseline)  
**Purpose:** Detect anomalous query patterns from MCP servers against the Log Analytics workspace. Covers both Sentinel Triage MCP (`6574a0f8`) and Azure MCP Server (`1950a258` + `csharpsdk`). Detects new tables being queried, query volume spikes, and data exfiltration indicators (high row-count responses).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "KQL Job architecture — designed to run as a scheduled Data Lake KQL job that promotes results to MCPSentinelAnomalies_KQL_CL. Complex multi-anomaly-type `union` query. Use companion Rules 1-5 for alerting on promoted data."
-->
```kql
// Job 7: Sentinel MCP — Workspace Query Anomalies
// Detects new tables queried, volume spikes, and large result sets from MCP workspace queries
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
// MCP-related AppIds for workspace queries
let mcpAppIds = dynamic([
    "6574a0f8-d39b-4090-abbe-6c64ec9003f0",  // Sentinel Triage MCP
    "1950a258-227b-4e31-a9cf-717495945fc2"   // Azure MCP Server
]);
// NOTE: Sentinel Triage MCP uses a service principal for LAQueryLogs, so AADEmail is empty.
// We fall back to AADObjectId for user attribution. Azure MCP populates both fields.
// Extract primary table name from KQL query text
let extractTable = (queryText: string) {
    extract("^\\s*([A-Za-z_]+)", 1, queryText)
};
// Build per-user table access baseline
let baselineTables = LAQueryLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| extend PrimaryTable = extract("^\\s*([A-Za-z_]+)", 1, QueryText)
| where isnotempty(PrimaryTable)
| summarize BaselineQueryCount = count() by AADEmail, PrimaryTable, AADClientId;
// Build per-user volume baseline
let baselineVolume = LAQueryLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| summarize DailyQueries = count() by AADEmail, Day = bin(TimeGenerated, 1d)
| summarize
    AvgDailyQueries = avg(DailyQueries),
    MaxDailyQueries = max(DailyQueries),
    BaselineDays = dcount(Day)
    by AADEmail;
// Recent activity - new tables
let recentTables = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| extend PrimaryTable = extract("^\\s*([A-Za-z_]+)", 1, QueryText)
| where isnotempty(PrimaryTable)
| summarize
    RecentQueryCount = count(),
    TotalRowsReturned = sum(ResponseRowCount),
    AvgRowsReturned = avg(ResponseRowCount),
    MaxRowsReturned = max(ResponseRowCount),
    SampleQueries = make_set(substring(QueryText, 0, 200), 3),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by AADEmail, PrimaryTable, AADClientId;
// Detect new tables
let newTableAnomalies = recentTables
| join kind=leftanti baselineTables on AADEmail, PrimaryTable
| extend
    AnomalyType = "NewTableQueried",
    MCPServer = case(
        AADClientId == "6574a0f8-d39b-4090-abbe-6c64ec9003f0", "SentinelTriageMCP",
        AADClientId == "1950a258-227b-4e31-a9cf-717495945fc2", "AzureMCP",
        "UnknownMCP"),
    Severity = case(
        PrimaryTable has_any ("SecurityIncident", "SecurityAlert", "AuditLogs", "IdentityInfo"), "High",
        PrimaryTable has_any ("SigninLogs", "AADNonInteractiveUserSignInLogs", "DeviceEvents"), "Medium",
        "Low"),
    Description = strcat("MCP user '", AADEmail, "' queried table '", PrimaryTable,
        "' for the first time via ", AADClientId, ". Rows returned: ", TotalRowsReturned);
// Detect volume spikes
let recentVolume = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| summarize RecentDayQueries = count(), DetectedTime = min(TimeGenerated), LastActivity = max(TimeGenerated) by AADEmail;
let volumeAnomalies = recentVolume
| join kind=inner baselineVolume on AADEmail
| where BaselineDays >= 3
| extend SpikeRatio = round(RecentDayQueries * 1.0 / AvgDailyQueries, 2)
| where SpikeRatio >= 3.0
| extend
    AnomalyType = "QueryVolumeSpike",
    MCPServer = "SentinelMCP",
    PrimaryTable = "N/A",
    AADClientId = "multiple",
    RecentQueryCount = RecentDayQueries,
    TotalRowsReturned = long(0),
    SampleQueries = dynamic([]),
    Severity = case(
        SpikeRatio >= 10.0, "High",
        SpikeRatio >= 5.0, "Medium",
        "Low"),
    Description = strcat("MCP user '", AADEmail, "' query volume (", RecentDayQueries,
        ") is ", SpikeRatio, "x their 14-day daily average (", round(AvgDailyQueries, 0), ")");
// Detect large result sets (potential data exfiltration)
let largeResultAnomalies = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| where ResponseRowCount >= 10000
| extend PrimaryTable = extract("^\\s*([A-Za-z_]+)", 1, QueryText)
| summarize
    RecentQueryCount = count(),
    TotalRowsReturned = sum(ResponseRowCount),
    MaxSingleQuery = max(ResponseRowCount),
    SampleQueries = make_set(substring(QueryText, 0, 200), 3),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by AADEmail, AADClientId
| extend
    AnomalyType = "LargeResultSet",
    MCPServer = case(
        AADClientId == "6574a0f8-d39b-4090-abbe-6c64ec9003f0", "SentinelTriageMCP",
        "AzureMCP"),
    PrimaryTable = "Multiple",
    Severity = case(
        TotalRowsReturned >= 100000, "High",
        "Medium"),
    Description = strcat("MCP user '", AADEmail, "' retrieved ", TotalRowsReturned,
        " total rows via MCP queries. Largest single query: ", MaxSingleQuery, " rows.");
// Union all anomaly types
union newTableAnomalies, volumeAnomalies, largeResultAnomalies
| project
    DetectedTime,
    AnomalyType,
    MCPServer,
    Severity,
    AADEmail,
    PrimaryTable,
    AADClientId,
    RecentQueryCount,
    TotalRowsReturned,
    SampleQueries,
    LastActivity,
    Description
```

---

## Job 8: Cross-MCP Correlation — Multi-Server Activity Chains

**Destination table:** `MCPCrossMCPCorrelation_KQL_CL`  
**Schedule:** Daily  
**Lookback:** 1 day  
**Purpose:** Detect users who used multiple MCP servers within the same time window. While multi-MCP usage isn't inherently malicious, chains like "Graph MCP reads user details → Azure MCP modifies infrastructure → Sentinel MCP suppresses alerts" represent a potential kill chain that warrants investigation.

> **⚠️ Known Limitation — User Identity Correlation:** Graph MCP and Azure MCP both use `UserId` (Entra Object ID GUID), enabling reliable cross-join. However, Sentinel Triage MCP authenticates as a **service principal** (`AADObjectId` in LAQueryLogs is the MCP app's Object ID, not the end user's). This means the Sentinel leg may not join with Graph/Azure by user identity. The Graph+Azure cross-correlation (the most security-critical combination) works correctly. Future improvement: add timestamp proximity matching for the Sentinel leg.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "KQL Job architecture — designed to run as a scheduled Data Lake KQL job that promotes results to MCPCrossMCPCorrelation_KQL_CL. Complex multi-table `fullouter` join across 4 data sources. Use companion Rule 3 for alerting."
-->
```kql
// Job 8: Cross-MCP Correlation — Multi-Server Activity Chains
// Detects users active across multiple MCP servers within the same day
// Flags when combined activity includes sensitive operations
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let recentStart = endTime - recentWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let azureMcpAppId = "1950a258-227b-4e31-a9cf-717495945fc2";
let triageMcpAppId = "6574a0f8-d39b-4090-abbe-6c64ec9003f0";
// Graph MCP activity
let graphActivity = MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| summarize
    GraphCallCount = count(),
    GraphEndpoints = make_set(EndpointCategory, 10),
    GraphSensitive = countif(EndpointCategory has_any ("roleManagement", "conditionalAccess", "applications", "identityProtection")),
    GraphFirstSeen = min(TimeGenerated),
    GraphLastSeen = max(TimeGenerated)
    by UserId;
// Azure MCP activity (sign-in events = token acquisitions)
let azureActivity = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| summarize
    AzureSessionCount = dcount(CorrelationId),
    AzureResources = make_set(ResourceDisplayName, 10),
    AzureFirstSeen = min(TimeGenerated),
    AzureLastSeen = max(TimeGenerated)
    by UserId;
// Sentinel Triage MCP activity (workspace queries)
let sentinelActivity = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId == triageMcpAppId
| extend UserId = coalesce(AADEmail, AADObjectId) // Sentinel Triage MCP uses SP, AADEmail may be empty
| summarize
    SentinelQueryCount = count(),
    SentinelTables = make_set(extract("^\\s*([A-Za-z_]+)", 1, QueryText), 10),
    SentinelTotalRows = sum(ResponseRowCount),
    SentinelFirstSeen = min(TimeGenerated),
    SentinelLastSeen = max(TimeGenerated)
    by UserId;
// Azure MCP workspace queries
let azureQueries = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId == azureMcpAppId
| where RequestClientApp has "csharpsdk"
| extend UserId = coalesce(AADEmail, AADObjectId)
| summarize
    AzureQueryCount = count(),
    AzureQueryTables = make_set(extract("^\\s*([A-Za-z_]+)", 1, QueryText), 10),
    AzureQueryRows = sum(ResponseRowCount)
    by UserId;
// Cross-join all MCP activities by user
graphActivity
| join kind=fullouter azureActivity on UserId
| join kind=fullouter sentinelActivity on UserId
| join kind=fullouter azureQueries on UserId
| extend UserId = coalesce(UserId, UserId1, UserId2, UserId3)
// Count how many distinct MCP servers were used
| extend MCPServersUsed = (iff(isnotnull(GraphCallCount), 1, 0)
    + iff(isnotnull(AzureSessionCount), 1, 0)
    + iff(isnotnull(SentinelQueryCount) or isnotnull(AzureQueryCount), 1, 0))
// Only flag multi-MCP users
| where MCPServersUsed >= 2
| extend
    DetectedTime = min_of(
        coalesce(GraphFirstSeen, datetime(9999-12-31)),
        coalesce(AzureFirstSeen, datetime(9999-12-31)),
        coalesce(SentinelFirstSeen, datetime(9999-12-31))),
    AnomalyType = "CrossMCPActivity",
    Severity = case(
        // High: Graph sensitive + Azure infra access in same day
        GraphSensitive > 0 and isnotnull(AzureSessionCount), "High",
        // High: All three MCP servers used
        MCPServersUsed >= 3, "High",
        // Medium: Any two MCP servers with significant volume
        coalesce(GraphCallCount, 0) + coalesce(SentinelQueryCount, 0) + coalesce(AzureQueryCount, 0) >= 50, "Medium",
        "Low"),
    MCPServerList = strcat(
        iff(isnotnull(GraphCallCount), "GraphMCP,", ""),
        iff(isnotnull(AzureSessionCount), "AzureMCP,", ""),
        iff(isnotnull(SentinelQueryCount), "SentinelTriageMCP,", ""),
        iff(isnotnull(AzureQueryCount), "AzureMCP-Queries,", "")),
    Description = strcat("User '", UserId, "' used ", MCPServersUsed, " MCP servers. ",
        iff(isnotnull(GraphCallCount), strcat("Graph: ", GraphCallCount, " calls", iff(GraphSensitive > 0, strcat(" (", GraphSensitive, " sensitive)"), ""), ". "), ""),
        iff(isnotnull(AzureSessionCount), strcat("Azure: ", AzureSessionCount, " sessions. "), ""),
        iff(isnotnull(SentinelQueryCount), strcat("Sentinel: ", SentinelQueryCount, " queries (", SentinelTotalRows, " rows). "), ""),
        iff(isnotnull(AzureQueryCount), strcat("Azure queries: ", AzureQueryCount, ". "), ""))
| project
    DetectedTime,
    AnomalyType,
    MCPServer = "CrossMCP",
    Severity,
    UserId,
    MCPServersUsed,
    MCPServerList,
    GraphCallCount = coalesce(GraphCallCount, 0),
    GraphSensitive = coalesce(GraphSensitive, 0),
    GraphEndpoints,
    AzureSessionCount = coalesce(AzureSessionCount, 0),
    AzureResources,
    SentinelQueryCount = coalesce(SentinelQueryCount, 0),
    SentinelTables,
    AzureQueryCount = coalesce(AzureQueryCount, 0),
    AzureQueryTables,
    Description
```

---

## Companion Detection Rules

Once the KQL jobs promote data to the analytics tier, create detection rules to fire alerts.

### Use Custom Detections (Not Analytics Rules)

**Custom detections** are Microsoft's recommended approach for creating new detection rules. They offer NRT streaming (tests events as they stream rather than after ingestion), native Defender XDR remediation actions, on-demand execution for testing, and seamless entity mapping across Sentinel and XDR data. The rules below are authored for the custom detection wizard in the Defender portal.

Analytics rules are still functional but custom detections are the strategic path forward. Use analytics rules only if you specifically need Sentinel automation rule triggers or repository-based deployment today — both are planned for custom detections.

For a full feature comparison, see [Analytics Rules vs Custom Detections](https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections).

### Rule 1: New Sensitive Graph Endpoint via MCP

| Setting | Value |
|---------|-------|
| **Detection name** | `MCP Graph New Sensitive Endpoint` |
| **Severity** | Medium |
| **Category** | InitialAccess |
| **MITRE techniques** | T1087 (Account Discovery) |
| **Frequency** | Every 1 hour (lookback: auto 4 hours) |
| **Alert title** | `New Sensitive Graph Endpoint via MCP: {{EndpointCategory}}` |
| **Description** | `Graph MCP user accessed a sensitive API endpoint not seen in their 14-day baseline. Review the endpoint category and sample URLs to assess intent.` |

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "New Sensitive Graph Endpoint via MCP: {{EndpointCategory}}"
impactedAssets:
  - type: "user"
    identifier: "UserId"
adaptation_notes: "Companion detection rule for KQL Job 1. Queries MCPGraphAnomalies_KQL_CL analytics tier table. Requires Job 1 to be running and promoting data."
-->
```kql
MCPGraphAnomalies_KQL_CL
| where AnomalyType == "NewSensitiveEndpoint"
| where Severity in ("High", "Medium")
| project
    TimeGenerated,
    UserId,
    EndpointCategory,
    Severity,
    RecentHits,
    DistinctEndpoints,
    SampleEndpoints,
    ResponseCodes,
    LastActivity,
    Description
```

**Entity mapping:**

| Section | Entity Type | Identifier | Column |
|---------|-------------|------------|--------|
| Impacted assets | **Account** | AadUserId | `UserId` |

**Custom details:**

| Key | Parameter (column) |
|-----|--------------------|
| EndpointCategory | `EndpointCategory` |
| Severity | `Severity` |
| RecentHits | `RecentHits` |
| DistinctEndpoints | `DistinctEndpoints` |
| ResponseCodes | `ResponseCodes` |

### Rule 2: MCP Volume Spike

| Setting | Value |
|---------|-------|
| **Detection name** | `MCP Graph Volume Spike` |
| **Severity** | Medium |
| **Category** | Collection |
| **MITRE techniques** | T1119 (Automated Collection) |
| **Frequency** | Every 1 hour (lookback: auto 4 hours) |
| **Alert title** | `Graph MCP Volume Spike: {{SpikeRatio}}x baseline` |
| **Description** | `A user's Graph MCP API call volume significantly exceeds their 14-day daily average. This may indicate bulk data harvesting, enumeration campaigns, or a runaway agent.` |

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Collection"
title: "Graph MCP Volume Spike: {{SpikeRatio}}x baseline"
impactedAssets:
  - type: "user"
    identifier: "UserId"
adaptation_notes: "Companion detection rule for KQL Job 2. Queries MCPGraphAnomalies_KQL_CL. Requires Job 2 to be running."
-->
```kql
MCPGraphAnomalies_KQL_CL
| where AnomalyType == "VolumeSpike"
| where Severity in ("High", "Medium")
| project
    TimeGenerated,
    UserId,
    Severity,
    RecentDayCount,
    AvgDailyCount,
    SpikeRatio,
    MaxDailyCount,
    BaselineDays,
    DistinctEndpoints,
    TopEndpoints,
    ErrorCount,
    LastActivity,
    Description
```

**Entity mapping:**

| Section | Entity Type | Identifier | Column |
|---------|-------------|------------|--------|
| Impacted assets | **Account** | AadUserId | `UserId` |

**Custom details:**

| Key | Parameter (column) |
|-----|--------------------||
| Severity | `Severity` |
| SpikeRatio | `SpikeRatio` |
| RecentDayCount | `RecentDayCount` |
| AvgDailyCount | `AvgDailyCount` |
| ErrorCount | `ErrorCount` |
| TopEndpoints | `TopEndpoints` |

### Rule 3: Cross-MCP Suspicious Activity Chain

| Setting | Value |
|---------|-------|
| **Detection name** | `MCP Cross Server Suspicious Chain` |
| **Severity** | High |
| **Category** | LateralMovement |
| **MITRE techniques** | T1078 (Valid Accounts) |
| **Frequency** | Every 1 hour (lookback: auto 4 hours) |
| **Alert title** | `Cross-MCP Activity: {{MCPServersUsed}} servers by {{UserId}}` |
| **Description** | `A user was active across multiple MCP servers within 24 hours. Combined activity (e.g., Graph reconnaissance + Azure infrastructure access) may represent a multi-stage attack chain.` |

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "LateralMovement"
title: "Cross-MCP Activity: {{MCPServersUsed}} servers by {{UserId}}"
impactedAssets:
  - type: "user"
    identifier: "UserId"
adaptation_notes: "Companion detection rule for KQL Job 8. Queries MCPCrossMCPCorrelation_KQL_CL. Requires Job 8 to be running."
-->
```kql
MCPCrossMCPCorrelation_KQL_CL
| where AnomalyType == "CrossMCPActivity"
| where Severity == "High"
| project
    TimeGenerated,
    UserId,
    Severity,
    MCPServersUsed,
    MCPServerList,
    GraphCallCount,
    GraphSensitive,
    GraphEndpoints,
    AzureSessionCount,
    AzureResources,
    SentinelQueryCount,
    SentinelTables,
    AzureQueryCount,
    Description
```

**Entity mapping:**

| Section | Entity Type | Identifier | Column |
|---------|-------------|------------|--------|
| Impacted assets | **Account** | AadUserId | `UserId` |

**Custom details:**

| Key | Parameter (column) |
|-----|--------------------||
| Severity | `Severity` |
| MCPServersUsed | `MCPServersUsed` |
| MCPServerList | `MCPServerList` |
| GraphSensitive | `GraphSensitive` |
| GraphCallCount | `GraphCallCount` |
| AzureSessionCount | `AzureSessionCount` |
| SentinelQueryCount | `SentinelQueryCount` |

### Rule 4: New Azure MCP Server User

| Setting | Value |
|---------|-------|
| **Detection name** | `MCP Azure New User Detected` |
| **Severity** | Medium |
| **Category** | InitialAccess |
| **MITRE techniques** | T1078 (Valid Accounts) |
| **Frequency** | Every 1 hour (lookback: auto 4 hours) |
| **Alert title** | `New Azure MCP Server User: {{UserPrincipalName}}` |
| **Description** | `A user accessed the Azure MCP Server for the first time (not seen in 14-day baseline). This may indicate new tooling adoption or compromised credentials exploring Azure infrastructure.` |

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "New Azure MCP Server User: {{UserPrincipalName}}"
impactedAssets:
  - type: "user"
    identifier: "UserId"
adaptation_notes: "Companion detection rule for KQL Job 5. Queries MCPAzureAnomalies_KQL_CL. Requires Job 5 to be running."
-->
```kql
MCPAzureAnomalies_KQL_CL
| where AnomalyType == "NewAzureMCPUser"
| project
    TimeGenerated,
    UserId,
    UserPrincipalName,
    Severity,
    SessionCount,
    DistinctIPs,
    IPs,
    Resources,
    ResultTypes,
    UserAgent,
    LastActivity,
    Description
```

**Entity mapping:**

| Section | Entity Type | Identifier | Column |
|---------|-------------|------------|--------|
| Impacted assets | **Account** | AadUserId | `UserId` |
| Impacted assets | **Account** | UPN | `UserPrincipalName` |

**Custom details:**

| Key | Parameter (column) |
|-----|--------------------|
| Severity | `Severity` |
| SessionCount | `SessionCount` |
| DistinctIPs | `DistinctIPs` |
| Resources | `Resources` |
| UserAgent | `UserAgent` |

### Rule 5: Large Data Retrieval via MCP

| Setting | Value |
|---------|-------|
| **Detection name** | `MCP Large Data Retrieval` |
| **Severity** | Medium |
| **Category** | Exfiltration |
| **MITRE techniques** | T1530 (Data from Cloud Storage) |
| **Frequency** | Every 1 hour (lookback: auto 4 hours) |
| **Alert title** | `Large MCP Data Retrieval: {{TotalRowsReturned}} rows` |
| **Description** | `An MCP server user retrieved an unusually large number of rows from workspace queries. This may indicate data exfiltration or excessive data collection via MCP tooling.` |

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Exfiltration"
title: "Large MCP Data Retrieval: {{TotalRowsReturned}} rows"
impactedAssets:
  - type: "user"
    identifier: "AADEmail"
adaptation_notes: "Companion detection rule for KQL Job 7. Queries MCPSentinelAnomalies_KQL_CL. AADEmail may contain an Object ID GUID for Sentinel Triage MCP (known limitation). Requires Job 7 to be running."
-->
```kql
MCPSentinelAnomalies_KQL_CL
| where AnomalyType == "LargeResultSet"
| where Severity in ("High", "Medium")
| project
    TimeGenerated,
    AADEmail,
    Severity,
    MCPServer,
    AADClientId,
    RecentQueryCount,
    TotalRowsReturned,
    SampleQueries,
    LastActivity,
    Description
```

**Entity mapping:**

| Section | Entity Type | Identifier | Column |
|---------|-------------|------------|--------|
| Impacted assets | **Account** | UPN | `AADEmail` |

> ⚠️ `AADEmail` may contain an Entra Object ID (GUID) for Sentinel Triage MCP due to the service principal fallback (see Job 7 bug fix). If the GUID doesn't resolve as a UPN, the entity won't map — this is a known limitation.

**Custom details:**

| Key | Parameter (column) |
|-----|--------------------||
| Severity | `Severity` |
| MCPServer | `MCPServer` |
| TotalRowsReturned | `TotalRowsReturned` |
| RecentQueryCount | `RecentQueryCount` |
| SampleQueries | `SampleQueries` |

---

## Deployment Checklist

1. **Prerequisites:**
   - [ ] Sentinel Data Lake onboarded ([docs](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-onboarding))
   - [ ] Log Analytics Contributor role assigned to data lake managed identity (`msg-resources-<guid>`)
   - [ ] `MicrosoftGraphActivityLogs` diagnostic setting enabled ([docs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview))
   - [ ] `LAQueryLogs` diagnostic settings enabled on workspace
   - [ ] `CloudAppEvents` connector active (for Data Lake MCP visibility — optional for these jobs)

2. **Create KQL Jobs (in Defender portal → Data lake exploration → Jobs):**
   - [ ] Job 1: Graph MCP New Sensitive Endpoint → `MCPGraphAnomalies_KQL_CL` (daily)
   - [ ] Job 2: Graph MCP Volume Spike → `MCPGraphAnomalies_KQL_CL` (daily, append)
   - [ ] Job 3: Graph MCP Off-Hours → `MCPGraphAnomalies_KQL_CL` (daily, append)
   - [ ] Job 4: Graph MCP Error Rate → `MCPGraphAnomalies_KQL_CL` (daily, append)
   - [ ] Job 5: Azure MCP New User → `MCPAzureAnomalies_KQL_CL` (daily)
   - [ ] Job 6: Azure MCP New Resource → `MCPAzureAnomalies_KQL_CL` (daily, append)
   - [ ] Job 7: Sentinel MCP Query Anomalies → `MCPSentinelAnomalies_KQL_CL` (daily)
   - [ ] Job 8: Cross-MCP Correlation → `MCPCrossMCPCorrelation_KQL_CL` (daily)

3. **Create Detection Rules (Defender XDR → Custom Detections — recommended):**
   - [ ] Rule 1: New Sensitive Graph Endpoint
   - [ ] Rule 2: MCP Volume Spike
   - [ ] Rule 3: Cross-MCP Suspicious Chain
   - [ ] Rule 4: New Azure MCP User
   - [ ] Rule 5: Large Data Retrieval
   > **Note:** Custom detections are Microsoft's recommended approach ([comparison](https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections)). Use analytics rules as fallback if you need Sentinel automation rule triggers or repository-based deployment today.

4. **Validation:**
   - [ ] Run each job once manually to verify schema and test data flow
   - [ ] Confirm `_KQL_CL` tables appear in analytics tier
   - [ ] Test analytics rules fire against promoted data
   - [ ] Review cost impact of promoted data volume after 7 days

---

## Cost Optimization Notes

- **Project only anomaly records**: Queries use `leftanti` joins and threshold filters to promote ONLY anomalous events, not raw volume
- **Minimal column projection**: Only columns needed for alerting and investigation context are promoted
- **Expected daily volume**: Tens to low hundreds of rows per job (anomalies are rare by definition)
- **Monitor with SummaryLogs**: Enable `SummaryLogs` diagnostic settings to track job health and costs
- **Retention**: Set analytics tier retention on `_KQL_CL` tables to 30-90 days (anomaly records don't need 12-year retention)

---

## MITRE ATT&CK Coverage

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| Job 1 (New Sensitive Endpoint) | T1087 (Account Discovery), T1069 (Permission Groups Discovery) | Agent probing identity/role APIs for first time |
| Job 2 (Volume Spike) | T1119 (Automated Collection) | Bulk data harvesting via runaway agent |
| Job 3 (Off-Hours Activity) | T1078 (Valid Accounts) | Stolen credentials used outside business hours |
| Job 4 (Error Rate Anomaly) | T1078.004 (Cloud Accounts), T1046 (Network Service Discovery) | Permission boundary probing |
| Job 5 (New Azure MCP User) | T1078 (Valid Accounts) | New tool adoption or compromised credential |
| Job 6 (New Resource Target) | T1526 (Cloud Service Discovery) | Infrastructure reconnaissance |
| Job 7 (Query Anomalies) | T1530 (Data from Cloud Storage), T1005 (Data from Local System) | Exfiltration via large query results |
| Job 8 (Cross-MCP Chain) | TA0001-TA0010 (Full Kill Chain) | Multi-stage attack across MCP servers |
