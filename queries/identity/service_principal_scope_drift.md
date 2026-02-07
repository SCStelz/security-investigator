# Service Principal Scope Drift Detection

**Created:** 2026-02-06  
**Platform:** Both  
**Tables:** AADServicePrincipalSignInLogs, AuditLogs, DeviceNetworkEvents, SecurityAlert  
**Keywords:** service principal, scope drift, behavioral baseline, drift score, anomaly, automation account, credential, permission escalation, resource access, lateral movement  
**MITRE:** T1078.004, T1098.001, T1550.001, T1071, TA0003, TA0004, TA0008  
**Timeframe:** 90-day baseline vs last 7 days (configurable)

---

## Overview

Service principals and automation accounts start with a defined scope — specific resources, APIs, IP ranges, and operational cadence. Over time, compromised or misconfigured principals can **gradually expand** their access patterns beyond this baseline, a technique known as **scope drift**. This is harder to detect than a sudden lateral movement event because each individual change may appear benign.

**This collection detects scope drift by:**
1. Building a 90-day behavioral baseline per service principal
2. Comparing the last 7 days against that baseline across multiple dimensions
3. Computing a composite **Drift Score** per principal
4. Flagging any entity exceeding **150% of baseline deviation** (configurable threshold)

**Dimensions tracked per principal:**

| Dimension | Source Table | What It Measures |
|-----------|-------------|------------------|
| Resource targets | AADServicePrincipalSignInLogs | Distinct APIs/resources accessed |
| IP diversity | AADServicePrincipalSignInLogs | Distinct IP addresses used |
| Geographic spread | AADServicePrincipalSignInLogs | Distinct locations (country/city) |
| Error rate shift | AADServicePrincipalSignInLogs | Authentication failure rate change |
| Permission changes | AuditLogs | Credential adds, consent grants, role assignments |
| Network destinations | DeviceNetworkEvents | New remote IPs/URLs contacted |
| Alert correlation | SecurityAlert | Security alerts referencing the principal |

**Drift Score formula:**
$$\text{DriftScore} = \frac{1}{N} \sum_{i=1}^{N} \frac{\text{Recent}_i - \text{Baseline}_i}{\max(\text{Baseline}_i, 1)} \times 100$$

Where each dimension contributes a deviation percentage and the final score is the average. A score > 150 means the principal's recent behavior exceeds 150% deviation from its 90-day norm.

---

## Query 1: Composite Drift Score — Full Detection (PRIMARY)

**Purpose:** Single query that builds the 90-day baseline, compares with last 7 days across all sign-in dimensions, and computes a Drift Score per service principal. Flags entities exceeding the threshold.

**Use this query to:**
- Detect service principals gradually expanding their resource access
- Identify automation accounts reaching new APIs or IP ranges
- Flag principals whose authentication behavior has shifted significantly
- Triage scope drift before it becomes a full compromise

```kql
// Service Principal Scope Drift Detection — Composite Drift Score
// Builds 90-day baseline vs 7-day recent window across multiple dimensions
// Flags entities with DriftScore > 150 (configurable threshold)
let BaselineStart = ago(97d);  // 90-day window ending 7 days ago
let BaselineEnd = ago(7d);
let RecentStart = ago(7d);
let RecentEnd = now();
let DriftThreshold = 150;  // Flag if drift exceeds 150% of baseline deviation
// --- Step 1: Baseline metrics per principal (90-day window) ---
let Baseline = AADServicePrincipalSignInLogs
| where TimeGenerated between (BaselineStart .. BaselineEnd)
| summarize
    BL_ResourceCount     = dcount(ResourceDisplayName),
    BL_IPCount           = dcount(IPAddress),
    BL_LocationCount     = dcount(strcat(Location, "-", tostring(LocationDetails))),
    BL_TotalSignIns      = count(),
    BL_FailedSignIns     = countif(ResultType != "0" and ResultType != 0),
    BL_DistinctResults   = dcount(ResultType),
    BL_Resources         = make_set(ResourceDisplayName, 50),
    BL_IPs               = make_set(IPAddress, 50)
    by ServicePrincipalId, ServicePrincipalName
| extend BL_FailRate = round(iff(BL_TotalSignIns > 0, (BL_FailedSignIns * 100.0) / BL_TotalSignIns, 0.0), 2)
// Normalize baseline to weekly rate for fair comparison
| extend BL_WeeklySignIns = round((BL_TotalSignIns * 7.0) / 90.0, 1);
// --- Step 2: Recent metrics per principal (last 7 days) ---
let Recent = AADServicePrincipalSignInLogs
| where TimeGenerated between (RecentStart .. RecentEnd)
| summarize
    RC_ResourceCount     = dcount(ResourceDisplayName),
    RC_IPCount           = dcount(IPAddress),
    RC_LocationCount     = dcount(strcat(Location, "-", tostring(LocationDetails))),
    RC_TotalSignIns      = count(),
    RC_FailedSignIns     = countif(ResultType != "0" and ResultType != 0),
    RC_DistinctResults   = dcount(ResultType),
    RC_Resources         = make_set(ResourceDisplayName, 50),
    RC_IPs               = make_set(IPAddress, 50)
    by ServicePrincipalId, ServicePrincipalName
| extend RC_FailRate = round(iff(RC_TotalSignIns > 0, (RC_FailedSignIns * 100.0) / RC_TotalSignIns, 0.0), 2);
// --- Step 3: Compute drift per dimension ---
Baseline
| join kind=inner Recent on ServicePrincipalId
| extend
    // Resource target drift: how many new resources vs baseline
    ResourceDrift = round(iff(BL_ResourceCount > 0,
        ((RC_ResourceCount - BL_ResourceCount) * 100.0) / BL_ResourceCount,
        iff(RC_ResourceCount > 0, 100.0 * RC_ResourceCount, 0.0)), 1),
    // IP diversity drift: new source IPs
    IPDrift = round(iff(BL_IPCount > 0,
        ((RC_IPCount - BL_IPCount) * 100.0) / BL_IPCount,
        iff(RC_IPCount > 0, 100.0 * RC_IPCount, 0.0)), 1),
    // Location drift: new geolocations
    LocationDrift = round(iff(BL_LocationCount > 0,
        ((RC_LocationCount - BL_LocationCount) * 100.0) / BL_LocationCount,
        iff(RC_LocationCount > 0, 100.0 * RC_LocationCount, 0.0)), 1),
    // Volume drift: sign-in volume change (normalized to weekly)
    VolumeDrift = round(iff(BL_WeeklySignIns > 0,
        ((RC_TotalSignIns - BL_WeeklySignIns) * 100.0) / BL_WeeklySignIns,
        iff(RC_TotalSignIns > 0, 100.0 * RC_TotalSignIns, 0.0)), 1),
    // Failure rate drift: shift in error rates
    FailRateDrift = round(iff(BL_FailRate > 0,
        ((RC_FailRate - BL_FailRate) * 100.0) / max_of(BL_FailRate, 1.0),
        iff(RC_FailRate > 0, RC_FailRate, 0.0)), 1),
    // New resources not seen in baseline
    NewResources = set_difference(RC_Resources, BL_Resources),
    // New IPs not seen in baseline
    NewIPs = set_difference(RC_IPs, BL_IPs)
// --- Step 4: Composite Drift Score ---
| extend DriftScore = round((
    max_of(ResourceDrift, 0.0) +
    max_of(IPDrift, 0.0) +
    max_of(LocationDrift, 0.0) +
    max_of(VolumeDrift, 0.0) +
    max_of(FailRateDrift, 0.0)
    ) / 5.0, 1)
| extend DriftSeverity = case(
    DriftScore >= 300, "🔴 Critical",
    DriftScore >= 150, "🟠 High",
    DriftScore >= 75, "🟡 Medium",
    "🟢 Low")
| where DriftScore >= DriftThreshold
| project
    ServicePrincipalName,
    ServicePrincipalId,
    DriftScore,
    DriftSeverity,
    ResourceDrift,
    IPDrift,
    LocationDrift,
    VolumeDrift,
    FailRateDrift,
    NewResourceCount = array_length(NewResources),
    NewIPCount = array_length(NewIPs),
    NewResources,
    NewIPs,
    BL_ResourceCount,
    RC_ResourceCount,
    BL_IPCount,
    RC_IPCount,
    BL_WeeklySignIns,
    RC_TotalSignIns,
    BL_FailRate,
    RC_FailRate
| order by DriftScore desc
```

**Expected Results:**
- `DriftScore`: Composite deviation metric (0 = no change, 150+ = flagged)
- `DriftSeverity`: Color-coded severity based on score thresholds
- `NewResources`: Resources accessed in last 7 days that were NEVER accessed in 90-day baseline
- `NewIPs`: Source IPs seen in last 7 days that are new vs baseline
- Per-dimension drift percentages for granular triage

**Drift Score Interpretation:**

| Score Range | Severity | Meaning |
|-------------|----------|---------|
| 0–74 | 🟢 Low | Normal operational variance |
| 75–149 | 🟡 Medium | Notable behavior change — review during routine audit |
| 150–299 | 🟠 High | Significant scope drift — investigate within 24 hours |
| 300+ | 🔴 Critical | Extreme deviation — possible compromise, investigate immediately |

**Tuning:**
- Adjust `DriftThreshold` to change flagging sensitivity
- Change `BaselineStart`/`BaselineEnd` for different baseline windows
- Add `| where BL_TotalSignIns > 100` to exclude low-activity principals with noisy baselines

---

## Query 2: New Resource Access — Resource Expansion Detail

**Purpose:** Identify exactly which resources/APIs each service principal started accessing in the last 7 days that it never touched during the 90-day baseline. This is the highest-fidelity signal for scope drift.

```kql
// Service Principal Resource Expansion — New targets not in 90-day baseline
let BaselineStart = ago(97d);
let BaselineEnd = ago(7d);
let RecentStart = ago(7d);
let RecentEnd = now();
// Resources accessed during baseline
let BaselineResources = AADServicePrincipalSignInLogs
| where TimeGenerated between (BaselineStart .. BaselineEnd)
| summarize BaselineResources = make_set(ResourceDisplayName, 100) by ServicePrincipalId, ServicePrincipalName;
// Resources accessed recently
let RecentResources = AADServicePrincipalSignInLogs
| where TimeGenerated between (RecentStart .. RecentEnd)
| summarize
    RecentResources = make_set(ResourceDisplayName, 100),
    SignInCount = count(),
    DistinctIPs = dcount(IPAddress),
    FailedCount = countif(ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName, ResourceDisplayName;
// Find new resources
RecentResources
| join kind=leftouter BaselineResources on ServicePrincipalId
| where BaselineResources !has ResourceDisplayName or isempty(BaselineResources)
| project
    ServicePrincipalName,
    ServicePrincipalId,
    NewResource = ResourceDisplayName,
    SignInCount,
    DistinctIPs,
    FailedCount,
    FailRate = round(iff(SignInCount > 0, (FailedCount * 100.0) / SignInCount, 0.0), 1)
| order by SignInCount desc
```

**What to Look For:**
- 🔴 **High-privilege resources** newly accessed (Microsoft Graph, Key Vault, Azure Management)
- 🟠 **Multiple new resources** by same principal — systematic expansion
- 🟡 **High failure rate on new resources** — possible permission probing
- Service principal accessing resources in a different tenant or subscription

---

## Query 3: IP and Location Drift — Geographic Anomaly Detection

**Purpose:** Detect service principals authenticating from new IP ranges or geographies not seen in their 90-day behavioral baseline. Automation accounts typically have very stable IP profiles — new IPs signal compromise or misconfiguration.

```kql
// Service Principal IP & Location Drift — New origins not in baseline
let BaselineStart = ago(97d);
let BaselineEnd = ago(7d);
let RecentStart = ago(7d);
let RecentEnd = now();
// Baseline IP/location profile per SP
let BaselineProfile = AADServicePrincipalSignInLogs
| where TimeGenerated between (BaselineStart .. BaselineEnd)
| summarize
    BL_IPs = make_set(IPAddress, 200),
    BL_Locations = make_set(Location, 50),
    BL_TotalSignIns = count()
    by ServicePrincipalId, ServicePrincipalName;
// Recent new IPs
AADServicePrincipalSignInLogs
| where TimeGenerated between (RecentStart .. RecentEnd)
| join kind=inner BaselineProfile on ServicePrincipalId
| where BL_IPs !has IPAddress
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SignInCount = count(),
    ResourcesAccessed = make_set(ResourceDisplayName, 20),
    ResultTypes = make_set(ResultType, 10)
    by ServicePrincipalName, ServicePrincipalId, IPAddress, Location,
       BL_TotalSignIns, BL_IPCount = array_length(BL_IPs)
| extend
    IsNewLocation = iff(BL_IPs !has IPAddress, true, false),
    BaselineIPCount = BL_IPCount
| project
    ServicePrincipalName,
    ServicePrincipalId,
    NewIP = IPAddress,
    Location,
    FirstSeen,
    LastSeen,
    SignInCount,
    ResourcesAccessed,
    ResultTypes,
    BaselineIPCount,
    BL_TotalSignIns
| order by SignInCount desc
```

**Indicators of Compromise:**
- 🔴 **Automation account appearing from a consumer ISP/VPN** — should originate from known infra
- 🔴 **New country not in baseline** — geographic impossible travel for automation
- 🟠 **Many new IPs in short period** — token theft or credential sharing
- Correlate new IPs with `enrich_ips.py` for threat intel context

---

## Query 4: Permission & Credential Escalation — AuditLogs Correlation

**Purpose:** Detect service principals that received new credentials, permissions, or role assignments in the last 7 days. Cross-reference with the drift score to identify principals that expanded both access AND permissions simultaneously — a strong compromise indicator.

```kql
// Service Principal Permission & Credential Changes (Last 7 Days)
// Correlated with 90-day baseline activity level
let RecentStart = ago(7d);
let RecentEnd = now();
let BaselineStart = ago(97d);
let BaselineEnd = ago(7d);
// Get permission/credential changes from AuditLogs
let PermissionChanges = AuditLogs
| where TimeGenerated between (RecentStart .. RecentEnd)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Add service principal credentials",
    "Remove service principal credentials",
    "Update application – Certificates and secrets management ",
    "Add app role assignment to service principal",
    "Remove app role assignment from service principal",
    "Add delegated permission grant",
    "Consent to application",
    "Add owner to service principal",
    "Add member to role"
  )
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetName = tostring(Target.displayName)
| extend TargetId = tostring(Target.id)
| extend TargetType = tostring(Target.type)
| extend ModifiedProps = tostring(Target.modifiedProperties)
| summarize
    PermissionChangeCount = count(),
    Operations = make_set(OperationName),
    Actors = make_set(Actor, 10),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated)
    by TargetName, TargetId, TargetType;
// Get baseline sign-in activity level for the same principals
let BaselineActivity = AADServicePrincipalSignInLogs
| where TimeGenerated between (BaselineStart .. BaselineEnd)
| summarize
    BL_SignIns = count(),
    BL_Resources = dcount(ResourceDisplayName),
    BL_IPs = dcount(IPAddress)
    by ServicePrincipalId, ServicePrincipalName;
// Join: Permission changes with baseline context
PermissionChanges
| join kind=leftouter BaselineActivity on $left.TargetId == $right.ServicePrincipalId
| extend RiskLevel = case(
    PermissionChangeCount >= 5 and BL_SignIns > 0, "🔴 High — multiple changes to active SP",
    PermissionChangeCount >= 3, "🟠 Medium — several permission changes",
    isempty(BL_SignIns) and PermissionChangeCount >= 1, "🟡 Low — changes to inactive/new SP",
    "🔵 Informational")
| project
    TargetName,
    TargetId,
    TargetType,
    PermissionChangeCount,
    Operations,
    Actors,
    FirstChange,
    LastChange,
    RiskLevel,
    BL_SignIns = coalesce(BL_SignIns, 0),
    BL_Resources = coalesce(BL_Resources, 0),
    BL_IPs = coalesce(BL_IPs, 0),
    ServicePrincipalName = coalesce(ServicePrincipalName, TargetName)
| order by PermissionChangeCount desc
```

**What to Look For:**
- 🔴 **Credential added + new resource access in same 7-day window** — classic persistence escalation
- 🔴 **Role assignment + consent grant on same SP** — permission chain attack
- 🟠 **Permission changes by an unexpected actor** — compromised admin or lateral movement
- Cross-reference with Query 1 drift score — high drift + permission changes = critical alert

---

## Query 5: Network Behavior Drift — DeviceNetworkEvents Correlation

**Purpose:** For service principals that run on endpoints (managed identity, SCCM, automation hosts), detect new network destinations contacted in the last 7 days vs the 90-day baseline. Requires matching the service principal's process identity to DeviceNetworkEvents.

**Important:** DeviceNetworkEvents uses `Timestamp` (Advanced Hunting) or `TimeGenerated` (Sentinel Data Lake). This query is written for Advanced Hunting via `RunAdvancedHuntingQuery`. Adjust if running against Data Lake.

```kql
// Network Destination Drift — New endpoints contacted by automation processes
// Run via Advanced Hunting (RunAdvancedHuntingQuery)
let BaselineStart = ago(97d);
let BaselineEnd = ago(7d);
let RecentStart = ago(7d);
let RecentEnd = now();
// Known automation/service account names — customize for your environment
let AutomationAccounts = dynamic([
    "system", "local service", "network service",
    // Add your service account names here:
    // "svc_automation", "svc_backup", "svc_monitoring"
]);
// Baseline network destinations per automation account
let BaselineNetwork = DeviceNetworkEvents
| where Timestamp between (BaselineStart .. BaselineEnd)
| where InitiatingProcessAccountName in~ (AutomationAccounts)
    or InitiatingProcessAccountName startswith "svc_"
    or InitiatingProcessAccountName startswith "sa-"
| summarize
    BL_RemoteIPs = make_set(RemoteIP, 500),
    BL_RemoteUrls = make_set(RemoteUrl, 500),
    BL_RemotePorts = make_set(RemotePort, 100),
    BL_TotalConnections = count()
    by InitiatingProcessAccountName, DeviceName;
// Recent network activity
let RecentNetwork = DeviceNetworkEvents
| where Timestamp between (RecentStart .. RecentEnd)
| where InitiatingProcessAccountName in~ (AutomationAccounts)
    or InitiatingProcessAccountName startswith "svc_"
    or InitiatingProcessAccountName startswith "sa-"
| summarize
    RC_RemoteIPs = make_set(RemoteIP, 500),
    RC_RemoteUrls = make_set(RemoteUrl, 500),
    RC_RemotePorts = make_set(RemotePort, 100),
    RC_TotalConnections = count(),
    RC_DistinctRemoteIPs = dcount(RemoteIP),
    RC_DistinctRemoteUrls = dcount(RemoteUrl)
    by InitiatingProcessAccountName, DeviceName;
// Compute network drift
RecentNetwork
| join kind=inner BaselineNetwork on InitiatingProcessAccountName, DeviceName
| extend
    NewIPs = set_difference(RC_RemoteIPs, BL_RemoteIPs),
    NewUrls = set_difference(RC_RemoteUrls, BL_RemoteUrls),
    NewPorts = set_difference(RC_RemotePorts, BL_RemotePorts)
| extend
    NewIPCount = array_length(NewIPs),
    NewUrlCount = array_length(NewUrls),
    NewPortCount = array_length(NewPorts),
    NetworkDrift = round(iff(array_length(BL_RemoteIPs) > 0,
        (array_length(set_difference(RC_RemoteIPs, BL_RemoteIPs)) * 100.0) / array_length(BL_RemoteIPs),
        iff(RC_DistinctRemoteIPs > 0, 100.0 * RC_DistinctRemoteIPs, 0.0)), 1)
| where NewIPCount > 0 or NewUrlCount > 0 or NewPortCount > 0
| project
    InitiatingProcessAccountName,
    DeviceName,
    NetworkDrift,
    NewIPCount,
    NewUrlCount,
    NewPortCount,
    NewIPs = iff(NewIPCount > 20, strcat("[", NewIPCount, " IPs - truncated]"), tostring(NewIPs)),
    NewUrls = iff(NewUrlCount > 20, strcat("[", NewUrlCount, " URLs - truncated]"), tostring(NewUrls)),
    NewPorts,
    BL_TotalConnections,
    RC_TotalConnections
| order by NetworkDrift desc
```

**Customization Required:**
- Update `AutomationAccounts` with your environment's service account naming conventions
- Add prefixes like `svc_`, `sa-`, `auto-`, or your org's naming pattern
- Consider joining on `InitiatingProcessAccountSid` for more precise matching

**What to Look For:**
- 🔴 **Automation account contacting new external IPs** — possible C2 or data exfiltration
- 🔴 **New ports (4444, 8080, high ephemeral)** — reverse shell or non-standard communication
- 🟠 **New URLs/domains not in baseline** — new API endpoints or suspicious destinations
- Cross-reference new IPs with threat intelligence (`enrich_ips.py`)

---

## Query 6: Security Alert Correlation — Alerts Involving Drifting Principals

**Purpose:** Find security alerts from the last 30 days that reference any service principal exhibiting scope drift. Joins SecurityAlert entities with drifting principals to surface alerts that may be related to the drift behavior.

```kql
// Security Alerts Correlated with Service Principal Scope Drift
// NOTE: SecurityAlert.Status is IMMUTABLE. Join with SecurityIncident for real status.
let RecentStart = ago(7d);
let BaselineStart = ago(97d);
let BaselineEnd = ago(7d);
// Identify drifting principals (simplified — resource count drift)
let DriftingPrincipals = AADServicePrincipalSignInLogs
| where TimeGenerated between (BaselineStart .. BaselineEnd)
| summarize BL_Resources = dcount(ResourceDisplayName), BL_IPs = dcount(IPAddress) by ServicePrincipalId, ServicePrincipalName
| join kind=inner (
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (RecentStart .. now())
    | summarize RC_Resources = dcount(ResourceDisplayName), RC_IPs = dcount(IPAddress) by ServicePrincipalId, ServicePrincipalName
) on ServicePrincipalId
| extend ResourceDrift = iff(BL_Resources > 0, ((RC_Resources - BL_Resources) * 100.0) / BL_Resources, 0.0)
| extend IPDrift = iff(BL_IPs > 0, ((RC_IPs - BL_IPs) * 100.0) / BL_IPs, 0.0)
| where ResourceDrift > 50 or IPDrift > 50
| project ServicePrincipalId, ServicePrincipalName, ResourceDrift, IPDrift;
// Get alerts mentioning these principals (by name or ID)
let AlertLookback = ago(30d);
let RelevantAlerts = SecurityAlert
| where TimeGenerated > AlertLookback
| where isnotempty(Entities)
| mv-apply Entity = parse_json(Entities) on (
    where tostring(Entity) has_any (toscalar(DriftingPrincipals | summarize make_set(ServicePrincipalName, 100)))
       or tostring(Entity) has_any (toscalar(DriftingPrincipals | summarize make_set(ServicePrincipalId, 100)))
    | project EntityMatch = tostring(Entity)
)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics, TimeGenerated;
// Join alerts with incidents for real status
SecurityIncident
| where CreatedTime > AlertLookback
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner RelevantAlerts on $left.AlertId == $right.SystemAlertId
| join kind=inner DriftingPrincipals on $left.Title == $right.ServicePrincipalName
   or $left.Title has $right.ServicePrincipalName
| project
    IncidentNumber,
    IncidentTitle = Title,
    Severity,
    Status,
    Classification,
    AlertName,
    AlertSeverity,
    ProviderName,
    Tactics,
    ServicePrincipalName,
    ResourceDrift = round(ResourceDrift, 1),
    IPDrift = round(IPDrift, 1),
    AlertTime = RelevantAlerts.TimeGenerated,
    IncidentCreated = CreatedTime
| order by IncidentCreated desc
```

**Limitations & Alternatives:**
- Entity matching in SecurityAlert is text-based — may miss principals referenced only by GUID
- If the above returns sparse results, use this simpler fallback that searches alert entities directly:

```kql
// Fallback: Direct SecurityAlert entity search for a specific SP
let SPName = "<ServicePrincipalName>";
let SPId = "<ServicePrincipalId>";
SecurityAlert
| where TimeGenerated > ago(30d)
| where Entities has SPName or Entities has SPId
    or CompromisedEntity has SPName
    or ExtendedProperties has SPName
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    ProviderName,
    Tactics,
    Description,
    CompromisedEntity,
    SystemAlertId
| order by TimeGenerated desc
```

---

## Query 7: Drift Timeline — Weekly Trend per Principal

**Purpose:** Show week-over-week behavioral trend for a specific service principal over 90 days. Useful for investigating flagged principals to understand when the drift started and whether it's gradual or sudden.

```kql
// Weekly Behavioral Trend for Specific Service Principal (90 Days)
let TargetSP = "<ServicePrincipalName>";  // Replace with the SP to investigate
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(97d)
| where ServicePrincipalName =~ TargetSP
| summarize
    SignInCount = count(),
    DistinctResources = dcount(ResourceDisplayName),
    DistinctIPs = dcount(IPAddress),
    DistinctLocations = dcount(Location),
    FailedCount = countif(ResultType != "0" and ResultType != 0),
    Resources = make_set(ResourceDisplayName, 20),
    IPs = make_set(IPAddress, 20)
    by Week = startofweek(TimeGenerated)
| extend FailRate = round(iff(SignInCount > 0, (FailedCount * 100.0) / SignInCount, 0.0), 1)
| order by Week asc
```

**Use this to:**
- Visualize the drift trajectory — is it gradual escalation or a sudden jump?
- Identify the exact week when new resources/IPs appeared
- Determine if the drift correlates with a specific event (credential rotation, deployment, compromise)
- Compare with AuditLog permission changes to find the root cause

**Follow-Up — Heatmap Visualization:**
Convert the output for heatmap display using the `show-signin-heatmap` MCP tool:
```kql
// Heatmap format: Resource access per week
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(97d)
| where ServicePrincipalName =~ "<ServicePrincipalName>"
| summarize value = count()
    by row = ResourceDisplayName, column = format_datetime(startofweek(TimeGenerated), "yyyy-MM-dd")
| order by column asc
```

---

## Query 8: Cross-Table Unified Drift Dashboard

**Purpose:** Unified view combining sign-in drift, permission changes, and security alerts into a single summary per service principal. This is the executive-level overview for SOC triage.

```kql
// Unified Service Principal Drift Dashboard
let BaselineStart = ago(97d);
let BaselineEnd = ago(7d);
let RecentStart = ago(7d);
let RecentEnd = now();
// Sign-in drift scores
let SignInDrift = AADServicePrincipalSignInLogs
| where TimeGenerated between (BaselineStart .. BaselineEnd)
| summarize BL_Res = dcount(ResourceDisplayName), BL_IPs = dcount(IPAddress), BL_Vol = count()
    by ServicePrincipalId, ServicePrincipalName
| join kind=inner (
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (RecentStart .. RecentEnd)
    | summarize RC_Res = dcount(ResourceDisplayName), RC_IPs = dcount(IPAddress), RC_Vol = count()
        by ServicePrincipalId, ServicePrincipalName
) on ServicePrincipalId
| extend BL_WeeklyVol = round((BL_Vol * 7.0) / 90.0, 1)
| extend
    ResourceDrift = round(iff(BL_Res > 0, ((RC_Res - BL_Res) * 100.0) / BL_Res, 0.0), 1),
    IPDrift = round(iff(BL_IPs > 0, ((RC_IPs - BL_IPs) * 100.0) / BL_IPs, 0.0), 1),
    VolumeDrift = round(iff(BL_WeeklyVol > 0, ((RC_Vol - BL_WeeklyVol) * 100.0) / BL_WeeklyVol, 0.0), 1)
| extend DriftScore = round((max_of(ResourceDrift, 0.0) + max_of(IPDrift, 0.0) + max_of(VolumeDrift, 0.0)) / 3.0, 1)
| project ServicePrincipalId, ServicePrincipalName, DriftScore, ResourceDrift, IPDrift, VolumeDrift,
    BL_Res, RC_Res, BL_IPs, RC_IPs, BL_WeeklyVol, RC_Vol;
// Permission changes in last 7 days
let PermChanges = AuditLogs
| where TimeGenerated between (RecentStart .. RecentEnd)
| where Category == "ApplicationManagement"
| where OperationName has_any ("credentials", "role assignment", "permission", "consent", "owner")
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetId = tostring(Target.id)
| summarize PermissionChanges = count(), PermOps = make_set(OperationName) by TargetId;
// Security alerts in last 30 days
let AlertCounts = SecurityAlert
| where TimeGenerated > ago(30d)
| extend EntitiesStr = tostring(Entities)
| summarize AlertCount = dcount(SystemAlertId), AlertNames = make_set(AlertName, 5) by EntitiesStr
| where isnotempty(EntitiesStr);
// Combine
SignInDrift
| join kind=leftouter PermChanges on $left.ServicePrincipalId == $right.TargetId
| extend PermissionChanges = coalesce(PermissionChanges, 0)
| extend PermOps = coalesce(PermOps, dynamic([]))
// Alert correlation via entity name search
| extend HasAlerts = iff(
    toscalar(SecurityAlert | where TimeGenerated > ago(30d) | where Entities has ServicePrincipalName | count) > 0,
    true, false)
| extend OverallRisk = case(
    DriftScore >= 150 and PermissionChanges > 0, "🔴 Critical — drift + permission changes",
    DriftScore >= 150, "🟠 High — significant behavioral drift",
    DriftScore >= 75 and PermissionChanges > 0, "🟠 High — moderate drift + permission changes",
    DriftScore >= 75, "🟡 Medium — moderate behavioral drift",
    PermissionChanges >= 3, "🟡 Medium — multiple permission changes",
    "🟢 Low")
| where DriftScore >= 75 or PermissionChanges > 0
| project
    ServicePrincipalName,
    ServicePrincipalId,
    OverallRisk,
    DriftScore,
    ResourceDrift,
    IPDrift,
    VolumeDrift,
    PermissionChanges,
    PermOps,
    BL_Res,
    RC_Res,
    BL_IPs,
    RC_IPs,
    BL_WeeklyVol,
    RC_Vol
| order by DriftScore desc
```

---

## Query 9: Managed Identity Drift — AADManagedIdentitySignInLogs

**Purpose:** Extend drift detection to Managed Identities, which have even more predictable behavioral patterns than application service principals. Any deviation is more significant.

```kql
// Managed Identity Scope Drift Detection
let BaselineStart = ago(97d);
let BaselineEnd = ago(7d);
let RecentStart = ago(7d);
let DriftThreshold = 100;  // Lower threshold for managed identities (more stable)
// Baseline
let BL = AADManagedIdentitySignInLogs
| where TimeGenerated between (BaselineStart .. BaselineEnd)
| summarize
    BL_Resources = dcount(ResourceDisplayName),
    BL_IPs = dcount(IPAddress),
    BL_Locations = dcount(Location),
    BL_Volume = count(),
    BL_ResourceList = make_set(ResourceDisplayName, 50),
    BL_IPList = make_set(IPAddress, 50)
    by ServicePrincipalId, ServicePrincipalName
| extend BL_WeeklyVolume = round((BL_Volume * 7.0) / 90.0, 1);
// Recent
let RC = AADManagedIdentitySignInLogs
| where TimeGenerated > RecentStart
| summarize
    RC_Resources = dcount(ResourceDisplayName),
    RC_IPs = dcount(IPAddress),
    RC_Locations = dcount(Location),
    RC_Volume = count(),
    RC_ResourceList = make_set(ResourceDisplayName, 50),
    RC_IPList = make_set(IPAddress, 50)
    by ServicePrincipalId, ServicePrincipalName;
// Drift calculation
BL
| join kind=inner RC on ServicePrincipalId
| extend NewResources = set_difference(RC_ResourceList, BL_ResourceList)
| extend NewIPs = set_difference(RC_IPList, BL_IPList)
| extend
    ResourceDrift = round(iff(BL_Resources > 0, ((RC_Resources - BL_Resources) * 100.0) / BL_Resources, 0.0), 1),
    IPDrift = round(iff(BL_IPs > 0, ((RC_IPs - BL_IPs) * 100.0) / BL_IPs, 0.0), 1),
    VolumeDrift = round(iff(BL_WeeklyVolume > 0, ((RC_Volume - BL_WeeklyVolume) * 100.0) / BL_WeeklyVolume, 0.0), 1)
| extend DriftScore = round((max_of(ResourceDrift, 0.0) + max_of(IPDrift, 0.0) + max_of(VolumeDrift, 0.0)) / 3.0, 1)
| where DriftScore >= DriftThreshold
| project
    ServicePrincipalName,
    ServicePrincipalId,
    DriftScore,
    ResourceDrift,
    IPDrift,
    VolumeDrift,
    NewResources,
    NewIPs,
    BL_Resources,
    RC_Resources,
    BL_IPs,
    RC_IPs,
    BL_WeeklyVolume,
    RC_Volume
| order by DriftScore desc
```

**Why a lower threshold (100) for Managed Identities:**
- Managed identities are tightly scoped by design — they run on a specific Azure resource
- Their IP profile should be the Azure datacenter IP range and rarely change
- Any new resource access is more suspicious than for multi-purpose application SPs

---

## Investigation Workflow

When a service principal is flagged with a high Drift Score:

### Triage Steps

1. **Identify the principal and its purpose:**
   - What does this SP do? (Check app registration in Azure Portal)
   - Who owns it? (Query 4 from `app_credential_management.md` in `queries/identity/`)
   - Is it a managed identity or an application SP?

2. **Analyze the drift dimensions:**
   - **Resource drift**: Which new resources were accessed? Are they higher privilege? (Query 2)
   - **IP drift**: Where are the new IPs? Run `enrich_ips.py` for threat intel (Query 3)
   - **Volume drift**: Is this a new deployment or a compromise sign?

3. **Check for concurrent permission changes:**
   - Were credentials, roles, or consent grants modified? (Query 4)
   - Did an ownership change precede the drift? (See `app_credential_management.md` Query 4 in `queries/identity/`)

4. **Correlate with security alerts:**
   - Are there active alerts for this SP? (Query 6)
   - Check incident status to see if already investigated

5. **Review the weekly trend:**
   - Was the drift gradual or sudden? (Query 7)
   - Does it correlate with a known deployment window?

### Response Matrix

| Finding | Risk | Recommended Action |
|---------|------|--------------------|
| New high-privilege resource access + credential added | 🔴 Critical | Disable SP immediately, rotate all credentials, investigate actor |
| New IPs from suspicious locations | 🔴 Critical | Revoke tokens, check for token theft, block IPs via CA policy |
| Gradual resource expansion, no permission changes | 🟠 High | Review with SP owner, verify if intentional scope change |
| Volume spike only, same resources/IPs | 🟡 Medium | Likely normal — verify with deployment calendar |
| Managed identity drift of any kind | 🟠 High | Investigate immediately — these should be ultra-stable |

### Remediation Actions

1. **Immediate containment:**
   - Disable the service principal: `Update-MgServicePrincipal -ServicePrincipalId <ID> -AccountEnabled:$false`
   - Revoke all tokens: New credentials invalidate existing ones

2. **Credential rotation:**
   - Remove suspicious credentials via Azure Portal or Graph API
   - Generate new secret/certificate and distribute to legitimate consumer

3. **Scope reduction:**
   - Review and remove unnecessary API permissions
   - Implement Conditional Access workload identity policies
   - Apply IP restrictions via Named Locations

4. **Monitoring:**
   - Create a Sentinel Scheduled Rule from Query 1 to run daily
   - Set up automated enrichment for new IPs
   - Configure alert for any new resource access by critical SPs

---

## Detection Rule Deployment

### Recommended Scheduled Analytics Rules

**Rule 1: Service Principal Scope Drift — High Score**

- **Query:** Query 1 with `DriftThreshold = 150`
- **Schedule:** Every 24 hours, lookup last 7 days
- **Severity:** High
- **Entity Mappings:** CloudApplication → ServicePrincipalName
- **Tactics:** Persistence (T1078.004), Lateral Movement (TA0008)

**Rule 2: Managed Identity Drift — Any Score**

- **Query:** Query 9 with `DriftThreshold = 100`
- **Schedule:** Every 12 hours, lookup last 7 days
- **Severity:** High
- **Entity Mappings:** CloudApplication → ServicePrincipalName
- **Tactics:** Persistence (T1078.004)

**Rule 3: New Resource Access by Service Principal**

- **Query:** Query 2
- **Schedule:** Every 6 hours, lookup last 7 days
- **Severity:** Medium
- **Entity Mappings:** CloudApplication → ServicePrincipalName, CloudApplication → NewResource
- **Tactics:** Discovery (TA0007), Lateral Movement (TA0008)

**Rule 4: Permission Escalation + Drift Correlation**

- **Query:** Query 8 filtered to `OverallRisk has "Critical"`
- **Schedule:** Every 1 hour, lookup last 7 days
- **Severity:** High
- **Entity Mappings:** CloudApplication → ServicePrincipalName, Account → Actors
- **Tactics:** Privilege Escalation (TA0004), Persistence (TA0003)

---

## Tuning Recommendations

### Reducing False Positives

1. **Exclude known noisy principals:**
   ```kql
   | where ServicePrincipalName !in~ (
       "Microsoft App Access Panel",
       "Office 365 Exchange Online",
       "Microsoft Teams Services"
   )
   ```

2. **Require minimum baseline activity:**
   ```kql
   | where BL_TotalSignIns > 100  // Only flag principals with established baselines
   ```

3. **Ignore volume-only drift:**
   ```kql
   | where ResourceDrift > 0 or IPDrift > 0  // Only flag when scope (not just volume) changes
   ```

### Increasing Detection Sensitivity

1. **Lower threshold for critical applications:**
   ```kql
   | extend AdjustedThreshold = iff(ServicePrincipalName has_any ("graph", "vault", "management"), 75, 150)
   | where DriftScore >= AdjustedThreshold
   ```

2. **Track hourly patterns (detect time-based drift):**
   ```kql
   | extend HourOfDay = hourofday(TimeGenerated)
   | summarize ... by ServicePrincipalId, HourOfDay
   // Compare baseline hours vs recent hours
   ```

---

## Additional Resources

**Microsoft Documentation:**
- [Workload identity protection](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview)
- [Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity)
- [Monitor service principal sign-ins](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins#service-principal-sign-ins)

**MITRE ATT&CK:**
- [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [T1098.001 - Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [T1550.001 - Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)

---

## Version History

- **v1.0 (2026-02-06):** Initial query collection created
  - 9 queries covering composite drift scoring, resource expansion, IP/location anomalies, permission correlation, network behavior, alert correlation, trend analysis, unified dashboard, and managed identity drift
  - Drift Score formula: average of per-dimension deviation percentages
  - Default threshold: 150% for application SPs, 100% for managed identities
  - Cross-table correlation: AADServicePrincipalSignInLogs × AuditLogs × DeviceNetworkEvents × SecurityAlert
  - Schema verified: ServicePrincipalId, ResourceDisplayName, IPAddress, Location columns confirmed
  - Known pitfall documented: SecurityAlert.Status immutability — join with SecurityIncident
