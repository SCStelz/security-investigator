---
name: scope-drift-detection
description: 'Use this skill when asked to detect scope drift, behavioral expansion, or gradual privilege/access creep in service principals, automation accounts, or user accounts. Triggers on keywords like "scope drift", "service principal drift", "SPN behavioral change", "user drift", "user behavioral change", "automation account drift", "baseline deviation", "access expansion", "behavioral anomaly", or when investigating whether an entity has gradually expanded beyond its intended purpose. This skill builds a 90-day behavioral baseline per entity, compares it with recent activity, computes a weighted Drift Score across multiple dimensions, and correlates with AuditLogs, DeviceNetworkEvents, SecurityAlert, and Identity Protection for corroborating evidence. Supports two entity types - Service Principals (SPNs) and User Accounts (UPNs).'
---

# Scope Drift Detection — Instructions

## Purpose

> **Credit:** The scope drift detection concept for service principals was inspired by [Iftekhar Hussain](https://techcommunity.microsoft.com/users/iftekhar%20hussain/20243)'s article *[The Agentic SOC Era: How Sentinel MCP Enables Autonomous Security Reasoning](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-agentic-soc-era-how-sentinel-mcp-enables-autonomous-security-reasoning/4491003)* (Feb 2026), which demonstrated multi-source correlation across AADServicePrincipalSignInLogs, AuditLogs, DeviceNetworkEvents, and SecurityAlert to build 90-day behavioral baselines and surface drift via weighted scoring. This skill operationalizes and extends that vision to include user accounts.

This skill detects **scope drift** — the gradual, often imperceptible expansion of access or behavior beyond an established baseline — in **Entra ID service principals** and **user accounts**. Unlike sudden compromise (which triggers alerts), scope drift is a slow-burn pattern that evades threshold-based detections.

**Supported Entity Types:**

| Entity Type | Identifier | Primary Sign-In Table(s) | Use Case |
|-------------|-----------|--------------------------|----------|
| **Service Principal** | ServicePrincipalName / ServicePrincipalId | `AADServicePrincipalSignInLogs` | App registrations, automation accounts, managed identities |
| **User Account** | UserPrincipalName (UPN) | `SigninLogs` + `AADNonInteractiveUserSignInLogs` | Human users, admin accounts, shared mailboxes |

**What this skill detects:**
- Volume spikes in sign-in activity relative to historical baseline
- New target resources (APIs, services) not previously accessed
- New applications accessed (user accounts)
- New device/OS/browser combinations (user accounts)
- New source IP addresses or geographic locations
- Increased failure rates indicating probing or misconfiguration
- Credential/permission changes correlated with behavioral shifts
- Security alerts involving the drifting entities
- Identity Protection risk events (user accounts)

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
3. **[Quick Start](#quick-start-tldr)** - 7-step investigation pattern
4. **[Drift Score Formula](#drift-score-formula)** - Weighted composite scoring
5. **[Execution Workflow](#execution-workflow)** - Complete 4-phase process
6. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns
7. **[Report Template](#report-template)** - Output format specification
8. **[Known Pitfalls](#known-pitfalls)** - Edge cases and false positives
9. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY scope drift analysis:**

1. **ALWAYS detect entity type FIRST** — determine if the target is a Service Principal or User Account (see [Entity Type Detection](#entity-type-detection))
2. **ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)
3. **ALWAYS ask the user for output mode** if not specified: inline chat summary or markdown file report (or both)
4. **ALWAYS build baseline FIRST** before comparing recent activity
5. **ALWAYS apply the low-volume denominator floor** to prevent false-positive drift scores on sparse baselines
6. **ALWAYS correlate across all required data sources** (see entity-specific data sources below)
7. **ALWAYS run independent queries in parallel** for performance
8. **NEVER report a drift flag without corroborating evidence** from at least one secondary data source

### Entity Type Detection

**Determine the entity type from the user's request:**

| Signal | Entity Type | Action |
|--------|-------------|--------|
| UPN / email address provided | **User Account** | Use SigninLogs + AADNonInteractiveUserSignInLogs |
| SPN name, app registration, or "service principal" mentioned | **Service Principal** | Use AADServicePrincipalSignInLogs |
| "All service principals" / no specific entity | **Service Principal (all)** | Use AADServicePrincipalSignInLogs for all SPNs |
| Ambiguous (e.g., "check drift for X") | **ASK user** | "Is X a service principal or a user account?" |

### Data Sources by Entity Type

| Data Source | SPN | User | Purpose |
|-------------|-----|------|---------|
| `AADServicePrincipalSignInLogs` | ✅ Primary | ❌ | SPN sign-in behavioral baseline |
| `SigninLogs` | ❌ | ✅ Primary | User interactive sign-in baseline |
| `AADNonInteractiveUserSignInLogs` | ❌ | ✅ Primary | User non-interactive (token refresh) baseline |
| `AuditLogs` | ✅ | ✅ | Permission/credential/role changes |
| `SecurityAlert` | ✅ | ✅ | Corroborating alert evidence |
| `DeviceNetworkEvents` | ✅ | ✅ | Network activity correlation |
| `Signinlogs_Anomalies_KQL_CL` | ❌ | ✅ | Pre-computed anomaly detection (custom table) |
| `SigninLogs` (risk fields) | ❌ | ✅ | Identity Protection risk events |

---

## ⛔ MANDATORY: Sentinel Workspace Selection

**This skill requires a Sentinel workspace to execute queries. Follow these rules STRICTLY:**

### When invoked from incident-investigation skill:
- Inherit the workspace selection from the parent investigation context
- If no workspace was selected in parent context: **STOP and ask user to select**

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
   - STOP and report the error, display available workspaces, ASK user to select

**🔴 PROHIBITED ACTIONS:**
- ❌ Selecting a workspace without user consent when multiple exist
- ❌ Switching to another workspace after a failure without asking
- ❌ Proceeding with investigation if workspace selection is ambiguous

---

## Output Modes

This skill supports two output modes. **ASK the user which they prefer** if not explicitly specified. Both may be selected.

### Mode 1: Inline Chat Summary (Default)
- Render the full drift analysis directly in the chat response
- Includes ASCII tables, Pareto chart, drift dimension bars, and security assessment
- Best for quick review and interactive follow-up questions

### Mode 2: Markdown File Report
- Save a comprehensive report to `reports/scope_drift_<entity>_<timestamp>.md`
- All ASCII visualizations render correctly inside markdown code fences (` ``` `)
- Includes all data from inline mode plus additional detail sections
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename pattern:** `reports/scope_drift_<entity>_YYYYMMDD_HHMMSS.md`
  - **User:** `scope_drift_<username>_YYYYMMDD_HHMMSS.md` (extract username from UPN, e.g., `officechris` from `officechris@stelznet.com`)
  - **SPN (single):** `scope_drift_<spn_short_name>_YYYYMMDD_HHMMSS.md` (use display name, sanitized: lowercase, spaces/special chars replaced with hyphens)
  - **SPN (all):** `scope_drift_all_spns_YYYYMMDD_HHMMSS.md` (tenant-wide scan of all service principals)

### Markdown Rendering Notes
- ✅ ASCII tables, box-drawing characters, and bar charts render perfectly in markdown code blocks
- ✅ Unicode block characters (▓░█) display correctly in monospaced fonts
- ✅ Emoji indicators (🔴🟢🟡⚠️✅) render natively in GitHub-flavored markdown
- ✅ Standard markdown tables (`| col |`) render as formatted tables
- **Tip:** Wrap all ASCII art in triple-backtick code fences for consistent rendering

---

## Quick Start (TL;DR)

When a user requests scope drift detection:

1. **Detect Entity Type** → Is target a Service Principal or User Account? (see Entity Type Detection)
2. **Select Workspace** → `list_sentinel_workspaces`, auto-select or ask
3. **Determine Output Mode** → Ask if not specified: inline, markdown file, or both
4. **Run Phase 1** → Baseline vs. Recent behavioral comparison (entity-specific query)
5. **Run Phases 2-3 in Parallel** → AuditLogs + SecurityAlert + entity-specific corroboration
6. **Compute Drift Scores** → Apply entity-specific formula, flag entities >150%, assess with corroborating evidence
7. **Output Results** → Render in selected mode(s)

### Entity-Specific Quick Start

**Service Principal:**
- Phase 1: Query 1 (AADServicePrincipalSignInLogs baseline vs recent)
- Phase 2-3: Queries 2-5 (AuditLogs for credential/permission changes + SecurityAlert + DeviceNetworkEvents)
- Formula: 5 dimensions (Volume, Resources, IPs, Locations, Failure Rate)

**User Account:**
- Phase 1: Query 6 (SigninLogs interactive) + Query 7 (AADNonInteractiveUserSignInLogs)
- Phase 2-3: Queries 8-11 (AuditLogs for user changes + SecurityAlert + Anomaly table + Identity Protection risk)
- Formula: 7 dimensions for interactive (Volume, Apps, Resources, IPs, Locations, Devices, Failure Rate), 6 for non-interactive (no Devices)

---

## Drift Score Formula

The Drift Score is a weighted composite of behavioral dimensions, normalized so that **100 = identical to baseline**. The formula varies by entity type.

### Service Principal Formula (5 Dimensions)

$$
\text{DriftScore}_{SPN} = 0.30V + 0.25R + 0.20IP + 0.15L + 0.10F
$$

| Dimension | Weight | Metric | Why |
|-----------|--------|--------|-----|
| **Volume** | 30% | Daily avg sign-ins (recent / baseline) | Sudden activity surges indicate misuse or compromise |
| **Resources** | 25% | Distinct target resources accessed | New resource targets = lateral expansion |
| **IPs** | 20% | Distinct source IP addresses | New IPs = infrastructure changes, credential theft |
| **Locations** | 15% | Distinct geographic locations | New geos = impossible travel or proxy rotation |
| **Failure Rate** | 10% | Failure rate delta (recent − baseline) | Rising failures = probing or brute-force |

### User Account Formula — Interactive (7 Dimensions)

$$
\text{DriftScore}_{Interactive} = 0.25V + 0.20A + 0.10R + 0.15IP + 0.10L + 0.10D + 0.10F
$$

| Dimension | Weight | Metric | Why |
|-----------|--------|--------|-----|
| **Volume** | 25% | Daily avg interactive sign-ins | Reduced weight vs SPN — user volume is naturally more variable |
| **Applications** | 20% | Distinct apps accessed | New apps = potential unauthorized access or shadow IT |
| **Resources** | 10% | Distinct target resources accessed | Reduced weight — apps are a better user-level signal |
| **IPs** | 15% | Distinct source IP addresses | New IPs = different network, VPN, or credential theft |
| **Locations** | 10% | Distinct geographic locations | New geos = travel or impossible travel |
| **Devices** | 10% | Distinct device types (OS + browser) | New devices = potential unauthorized device |
| **Failure Rate** | 10% | Failure rate delta | Rising failures = password spray target or lockout |

### User Account Formula — Non-Interactive (6 Dimensions)

$$
\text{DriftScore}_{NonInteractive} = 0.30V + 0.20A + 0.15R + 0.15IP + 0.10L + 0.10F
$$

| Dimension | Weight | Metric | Why |
|-----------|--------|--------|-----|
| **Volume** | 30% | Daily avg non-interactive sign-ins | Higher weight — non-interactive volume is more predictable |
| **Applications** | 20% | Distinct apps with token refreshes | New apps = potential token theft or rogue app consent |
| **Resources** | 15% | Distinct resources targeted | New resources = lateral expansion via token reuse |
| **IPs** | 15% | Distinct source IPs | New IPs = session hijack or AiTM proxy |
| **Locations** | 10% | Distinct geographic locations | Geographic shifts in token usage |
| **Failure Rate** | 10% | Failure rate delta | Rising failures = expired/revoked token churn |

**Note:** Devices dimension is excluded from non-interactive because token refreshes don't generate reliable device telemetry.

### Interpretation Scale

| Score | Meaning | Action |
|-------|---------|--------|
| **< 80** | Contracting scope | ✅ Normal — entity is doing less than usual |
| **80–120** | Stable / normal variance | ✅ No action required |
| **120–150** | Moderate deviation | 🟡 Monitor — check for legitimate reasons |
| **> 150** | Significant drift | 🔴 FLAG — investigate with corroborating evidence |
| **> 250** | Extreme drift | 🔴 CRITICAL — immediate investigation required |

### Low-Volume Denominator Floor

**CRITICAL:** For entities with sparse baselines (< 10 daily sign-ins), the volume ratio is artificially inflated. Apply a floor:

```
IF BL_DailyAvg < 10:
    AdjustedVolumeRatio = RC_DailyAvg / max(BL_DailyAvg, 10) * 100
    Flag the score with: "⚠️ Low-volume baseline — ratio may be inflated"
```

This prevents an entity averaging 1 sign-in/day from triggering at 6 sign-ins/day (600% ratio but trivial absolute volume).

**User-specific note:** Non-interactive sign-ins often have very high volume (thousands/day) from background token refreshes. The floor is less likely to trigger for non-interactive, but always check interactive separately.

---

## Execution Workflow

### Phase 0: Entity Type Detection

Before executing any queries, determine the entity type:

1. Parse user request for entity signals (see Entity Type Detection table above)
2. If ambiguous, ask the user: "Are you investigating a service principal/app or a user account?"
3. Select the appropriate query set and formula based on entity type

### Phase 1: Behavioral Baseline vs. Recent Comparison

**Baseline window:** 90 days (days 8–97 ago)  
**Recent window:** 7 days (last 7 days)

This is the primary query that computes per-entity behavioral profiles and drift metrics.

| Entity Type | Data Source | Query | Notes |
|-------------|-------------|-------|-------|
| **Service Principal** | `AADServicePrincipalSignInLogs` | Query 1 | Single query, 5 dimensions |
| **User — Interactive** | `SigninLogs` | Query 6 | 7 dimensions (adds Apps, Devices) |
| **User — Non-Interactive** | `AADNonInteractiveUserSignInLogs` | Query 7 | 6 dimensions (adds Apps, no Devices) |

**User accounts produce TWO drift scores** (interactive + non-interactive). Both must be computed and reported.

### Phase 2: Permission & Configuration Change Audit

**Data source:** `AuditLogs`  
**Correlation:** Same 97-day window, filtered to the entity from Phase 1

| Entity Type | Operations to Look For |
|-------------|------------------------|
| **Service Principal** | `Add/Remove service principal credentials`, `Update application – Certificates and secrets management`, `Consent to application`, `Add delegated permission grant`, `Add app role assignment to service principal`, `Add application`, `Add service principal`, any operation containing: "permission", "role", "consent", "oauth", "credential", "certificate", "secret" |
| **User Account** | `Reset user password`, `Change user password`, `Update user`, `Add member to group`, `Add member to role`, `Register security info`, `Delete security info`, `Update StsRefreshTokenValidFrom`, any operation containing: "password", "MFA", "role", "group", "conditional", "auth" (Query 8) |

### Phase 3: Corroborating Signal Collection (Run in Parallel)

**All entity types:**
- **SecurityAlert + SecurityIncident:** Check for alerts referencing entity IDs or names, joined with SecurityIncident for real status/classification. **Never read SecurityAlert.Status directly** — it's always "New". Queries 4 (SPN) and 11 (User).
- **DeviceNetworkEvents:** Check for anomalous network activity (SPN: service accounts; User: user-associated devices)

**User accounts only (additional sources):**
- **Signinlogs_Anomalies_KQL_CL:** Pre-computed anomaly detection (new IPs, new device combos, geographic novelty). Query 9.
- **Identity Protection risk fields:** `RiskLevelDuringSignIn`, `RiskState`, `RiskEventTypes_V2` from `SigninLogs`. Query 10.

### Phase 4: Score Computation & Report Generation

1. Compute DriftScore per entity using the entity-specific formula
2. Apply the low-volume denominator floor
3. Flag any entity exceeding 150% threshold
4. For flagged entities: assess corroborating evidence (permission changes, alerts, network anomalies, anomaly table, Identity Protection)
5. Generate risk assessment with emoji-coded findings
6. Render output in the user's selected mode

---

## Sample KQL Queries

### Query 1: Baseline vs. Recent Behavioral Comparison

```kql
// Build 90-day baseline (days 8-97 ago) vs recent 7 days per service principal
let baselineStart = ago(97d);
let baselineEnd = ago(7d);
let recentStart = ago(7d);
// Baseline period: per-SPN behavioral profile
let baseline = AADServicePrincipalSignInLogs
| where TimeGenerated between (baselineStart .. baselineEnd)
| summarize
    BL_TotalSignIns = count(),
    BL_Days = dcount(bin(TimeGenerated, 1d)),
    BL_DistinctResources = dcount(ResourceDisplayName),
    BL_DistinctIPs = dcount(IPAddress),
    BL_DistinctLocations = dcount(Location),
    BL_FailRate = round(1.0 * countif(ResultType != "0" and ResultType != 0) / count() * 100, 2),
    BL_Resources = make_set(ResourceDisplayName, 50),
    BL_IPs = make_set(IPAddress, 50),
    BL_Locations = make_set(Location, 50)
    by ServicePrincipalName, ServicePrincipalId;
// Recent period: last 7 days
let recent = AADServicePrincipalSignInLogs
| where TimeGenerated >= recentStart
| summarize
    RC_TotalSignIns = count(),
    RC_Days = dcount(bin(TimeGenerated, 1d)),
    RC_DistinctResources = dcount(ResourceDisplayName),
    RC_DistinctIPs = dcount(IPAddress),
    RC_DistinctLocations = dcount(Location),
    RC_FailRate = round(1.0 * countif(ResultType != "0" and ResultType != 0) / count() * 100, 2),
    RC_Resources = make_set(ResourceDisplayName, 50),
    RC_IPs = make_set(IPAddress, 50),
    RC_Locations = make_set(Location, 50)
    by ServicePrincipalName, ServicePrincipalId;
// Join and compute drift metrics
baseline
| join kind=inner recent on ServicePrincipalId
| extend
    BL_DailyAvg = round(1.0 * BL_TotalSignIns / BL_Days, 1),
    RC_DailyAvg = round(1.0 * RC_TotalSignIns / RC_Days, 1)
| extend
    VolumeRatio = iff(BL_DailyAvg > 0, round(RC_DailyAvg / BL_DailyAvg * 100, 1), 999.0),
    ResourceRatio = iff(BL_DistinctResources > 0, round(1.0 * RC_DistinctResources / BL_DistinctResources * 100, 1), 999.0),
    IPRatio = iff(BL_DistinctIPs > 0, round(1.0 * RC_DistinctIPs / BL_DistinctIPs * 100, 1), 999.0),
    LocationRatio = iff(BL_DistinctLocations > 0, round(1.0 * RC_DistinctLocations / BL_DistinctLocations * 100, 1), 999.0),
    FailRateDelta = RC_FailRate - BL_FailRate,
    NewResources = set_difference(RC_Resources, BL_Resources),
    NewIPs = set_difference(RC_IPs, BL_IPs),
    NewLocations = set_difference(RC_Locations, BL_Locations)
| extend
    NewResourceCount = array_length(NewResources),
    NewIPCount = array_length(NewIPs),
    NewLocationCount = array_length(NewLocations)
| extend
    // Composite Drift Score (weighted)
    DriftScore = round(
        (VolumeRatio * 0.30) +
        (ResourceRatio * 0.25) +
        (IPRatio * 0.20) +
        (LocationRatio * 0.15) +
        (iff(FailRateDelta > 0, 100.0 + FailRateDelta * 10, 100.0) * 0.10)
    , 1)
| project ServicePrincipalName, ServicePrincipalId,
    BL_Days, BL_TotalSignIns, BL_DailyAvg, BL_DistinctResources, BL_DistinctIPs, BL_DistinctLocations, BL_FailRate,
    RC_Days, RC_TotalSignIns, RC_DailyAvg, RC_DistinctResources, RC_DistinctIPs, RC_DistinctLocations, RC_FailRate,
    VolumeRatio, ResourceRatio, IPRatio, LocationRatio, FailRateDelta, DriftScore,
    NewResourceCount, NewIPCount, NewLocationCount,
    NewResources, NewIPs, NewLocations,
    BL_Resources, RC_Resources
| order by DriftScore desc
```

### Query 2: AuditLog Permission & Credential Changes

```kql
// Permission/credential/role changes for service principals
// Substitute <SPN_IDS> with comma-separated SPN IDs from Query 1
// Substitute <SPN_NAMES> with SPN display names from Query 1
AuditLogs
| where TimeGenerated > ago(97d)
| where OperationName has_any ("service principal", "application", "credential", "certificate",
    "secret", "permission", "role", "consent", "oauth")
| where tostring(TargetResources) has_any (<SPN_IDS>)
    or tostring(InitiatedBy) has_any (<SPN_IDS>)
| extend InBaseline = TimeGenerated < ago(7d)
| summarize
    BaselineOps = countif(InBaseline),
    RecentOps = countif(not(InBaseline)),
    Operations = make_set(OperationName, 20),
    RecentOperations = make_set_if(OperationName, not(InBaseline), 20)
    by bin(TimeGenerated, 7d), OperationName
| order by TimeGenerated desc
| take 50
```

### Query 3: Detailed Recent AuditLog Changes

```kql
// Detailed drill-down for the recent 7-day window
// Substitute <SPN_IDS> with SPN IDs from Query 1
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("service principal", "application", "credential", "certificate",
    "secret", "permission", "role", "consent", "oauth", "update")
| where tostring(TargetResources) has_any (<SPN_IDS>)
| project TimeGenerated, OperationName, Result,
    InitiatedBy = tostring(parse_json(tostring(InitiatedBy)).app.displayName),
    TargetName = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).displayName),
    TargetId = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).id),
    ModifiedProperties = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).modifiedProperties)
| order by TimeGenerated desc
```

### Query 4: SecurityAlert + SecurityIncident Correlation

```kql
// Security alerts referencing any of the service principals, joined with SecurityIncident for real status
// IMPORTANT: SecurityAlert.Status is immutable (always "New") — MUST join SecurityIncident for real Status/Classification
// Substitute <SPN_IDS> and <SPN_NAMES> with values from Query 1
let relevantAlerts = SecurityAlert
| where TimeGenerated > ago(97d)
| where Entities has_any (<SPN_IDS>) or Entities has_any (<SPN_NAMES>)
    or CompromisedEntity has_any (<SPN_NAMES>)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics, TimeGenerated;
SecurityIncident
| where CreatedTime > ago(97d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| summarize
    AlertCount = count(),
    AlertNames = make_set(AlertName, 15),
    Severities = make_set(AlertSeverity, 5),
    Tactics = make_set(Tactics, 10),
    LatestAlert = max(TimeGenerated1),
    IncidentStatuses = make_set(Status, 5),
    Classifications = make_set(Classification, 5),
    IncidentCount = dcount(IncidentNumber)
    by ProductName
| order by AlertCount desc
```

**Interpreting Incident Status in Drift Context:**
| Incident Status | Classification | Impact on Drift Assessment |
|-----------------|----------------|----------------------------|
| Closed | TruePositive | 🔴 Confirmed threat — significantly increases drift risk |
| Closed | FalsePositive | 🟢 False alarm — discount from drift risk, note as noise |
| Closed | BenignPositive | 🟡 Expected behavior — note but don't escalate |
| Active/New | Any | 🟠 Unresolved — flag for attention, may indicate ongoing threat |

**Product Name Mapping (Legacy → Current Branding):**

The `ProductName` field in `SecurityAlert` uses legacy names. When rendering reports, translate to current Microsoft branding:

| SecurityAlert.ProductName (raw) | Report Display Name |
|--------------------------------|---------------------|
| Microsoft Defender Advanced Threat Protection | **Microsoft Defender for Endpoint** |
| Microsoft Cloud App Security | **Microsoft Defender for Cloud Apps** |
| Microsoft Data Loss Prevention | **Microsoft Purview Data Loss Prevention** |
| Azure Sentinel | **Microsoft Sentinel** |
| Microsoft 365 Defender | **Microsoft Defender XDR** |
| Office 365 Advanced Threat Protection | **Microsoft Defender for Office 365** |
| Azure Advanced Threat Protection | **Microsoft Defender for Identity** |

Group alerts by product in the report, using the current name as the section header, with individual alert names as rows within each product section.

### Query 5: DeviceNetworkEvents Correlation

```kql
// Network activity from service accounts targeting SPN-associated resources
// Focus on system/service accounts and connections to Microsoft service endpoints
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessAccountName has_any ("service", "system")
    or RemoteUrl has_any ("graph.microsoft.com", "management.azure.com",
        "vault.azure.net", "storage.azure.net")
| summarize
    ConnectionCount = count(),
    DistinctDevices = dcount(DeviceName),
    Devices = make_set(DeviceName, 10),
    DistinctRemoteIPs = dcount(RemoteIP),
    RemoteUrls = make_set(RemoteUrl, 10),
    Ports = make_set(RemotePort, 10)
    by InitiatingProcessFileName, InitiatingProcessAccountName
| where ConnectionCount > 0
| order by ConnectionCount desc
| take 20
```

### Query 6: User Interactive Sign-In Baseline vs. Recent

```kql
// Build 90-day baseline vs 7-day recent for user interactive sign-ins
// Substitute <UPN> with user's UPN
let baselineStart = ago(97d);
let baselineEnd = ago(7d);
let recentStart = ago(7d);
SigninLogs
| where UserPrincipalName =~ '<UPN>'
| where TimeGenerated >= baselineStart
| extend Period = iff(TimeGenerated < baselineEnd, "Baseline", "Recent")
| summarize
    TotalSignIns = count(),
    Days = dcount(bin(TimeGenerated, 1d)),
    DistinctApps = dcount(AppDisplayName),
    DistinctResources = dcount(ResourceDisplayName),
    DistinctIPs = dcount(IPAddress),
    DistinctLocations = dcount(Location),
    DistinctDevices = dcount(strcat(tostring(DeviceDetail.operatingSystem), "|", tostring(DeviceDetail.browser))),
    FailRate = round(1.0 * countif(ResultType != "0" and ResultType != 0) / count() * 100, 2),
    Apps = make_set(AppDisplayName, 50),
    Resources = make_set(ResourceDisplayName, 50),
    IPs = make_set(IPAddress, 50),
    Locations = make_set(Location, 50),
    Devices = make_set(strcat(tostring(DeviceDetail.operatingSystem), "|", tostring(DeviceDetail.browser)), 50)
    by Period
| order by Period asc
```

**Post-processing:** Compare Baseline vs Recent rows. Compute ratios per dimension. Calculate `set_difference()` equivalents in the assessment to identify new apps, IPs, locations, and devices appearing only in the Recent period.

### Query 7: User Non-Interactive Sign-In Baseline vs. Recent

```kql
// Build 90-day baseline vs 7-day recent for user non-interactive sign-ins
// Substitute <UPN> with user's UPN
let baselineStart = ago(97d);
let baselineEnd = ago(7d);
let recentStart = ago(7d);
AADNonInteractiveUserSignInLogs
| where UserPrincipalName =~ '<UPN>'
| where TimeGenerated >= baselineStart
| extend Period = iff(TimeGenerated < baselineEnd, "Baseline", "Recent")
| summarize
    TotalSignIns = count(),
    Days = dcount(bin(TimeGenerated, 1d)),
    DistinctApps = dcount(AppDisplayName),
    DistinctResources = dcount(ResourceDisplayName),
    DistinctIPs = dcount(IPAddress),
    DistinctLocations = dcount(Location),
    FailRate = round(1.0 * countif(ResultType != "0" and ResultType != 0) / count() * 100, 2),
    Apps = make_set(AppDisplayName, 50),
    Resources = make_set(ResourceDisplayName, 50),
    IPs = make_set(IPAddress, 50),
    Locations = make_set(Location, 50)
    by Period
| order by Period asc
```

**Note:** Devices dimension is excluded from non-interactive queries — token refreshes don't generate reliable device telemetry.

**KQL Pattern Note:** Uses single-pass `extend Period = iff(...)` pattern instead of separate baseline/recent subqueries joined with `join kind=inner on 1==1`. The cross-join pattern is NOT supported in KQL — always use the Period flag approach for user queries.

### Query 8: User AuditLog Configuration Changes

```kql
// User account configuration changes (password, MFA, roles, groups)
// Substitute <UPN> with user's UPN
AuditLogs
| where TimeGenerated > ago(97d)
| where OperationName has_any ("password", "MFA", "role", "group", "conditional", "auth",
    "user", "member", "security info")
| where tostring(TargetResources) has '<UPN>'
    or tostring(InitiatedBy) has '<UPN>'
    or Identity =~ '<UPN>'
| extend InBaseline = TimeGenerated < ago(7d)
| summarize
    BaselineOps = countif(InBaseline),
    RecentOps = countif(not(InBaseline)),
    Operations = make_set(OperationName, 30)
    by OperationName
| order by RecentOps desc
```

### Query 9: SigninLogs Anomaly Table (Custom)

```kql
// Pre-computed anomalies from Signinlogs_Anomalies_KQL_CL
// Substitute <UPN> with user's UPN
// Note: This table may not exist in all workspaces — handle gracefully
Signinlogs_Anomalies_KQL_CL
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ '<UPN>'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10 or CountryNovelty or CityNovelty or StateNovelty, "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| where Severity in ("High", "Medium", "Low")
| project DetectedDateTime, AnomalyType, Value, Severity, Country, City,
    ArtifactHits, CountryNovelty, CityNovelty, OS, BrowserFamily
| order by DetectedDateTime desc
| take 20
```

### Query 10: Identity Protection Risk Events

```kql
// Identity Protection risk signals from SigninLogs
// Substitute <UPN> with user's UPN
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ '<UPN>'
| where RiskLevelDuringSignIn != "none" and RiskLevelDuringSignIn != ""
| project TimeGenerated, RiskLevelDuringSignIn, RiskState, RiskEventTypes_V2,
    IPAddress, Location, AppDisplayName,
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    ConditionalAccessStatus
| order by TimeGenerated desc
| take 20
```

**Note:** Identity Protection events supplement the drift analysis. Any `atRisk` or `confirmedCompromised` risk states in the recent window should be flagged prominently, regardless of drift score.

### Query 11: User SecurityAlert + SecurityIncident Correlation

```kql
// Security alerts and incidents referencing the user
// IMPORTANT: SecurityAlert.Status is immutable (always "New") — MUST join SecurityIncident for real Status/Classification
// Substitute <UPN> with user's UPN
let relevantAlerts = SecurityAlert
| where TimeGenerated > ago(97d)
| where Entities has '<UPN>' or CompromisedEntity has '<UPN>'
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics, TimeGenerated;
SecurityIncident
| where CreatedTime > ago(97d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| summarize
    AlertCount = count(),
    AlertNames = make_set(AlertName, 15),
    Severities = make_set(AlertSeverity, 5),
    Tactics = make_set(Tactics, 10),
    LatestAlert = max(TimeGenerated1),
    IncidentStatuses = make_set(Status, 5),
    Classifications = make_set(Classification, 5),
    IncidentCount = dcount(IncidentNumber)
    by ProductName
| order by AlertCount desc
```

**Interpreting Incident Status in Drift Context:**
| Incident Status | Classification | Impact on Drift Assessment |
|-----------------|----------------|----------------------------|
| Closed | TruePositive | 🔴 Confirmed threat — significantly increases drift risk |
| Closed | FalsePositive | 🟢 False alarm — discount from drift risk, note as noise |
| Closed | BenignPositive | 🟡 Expected behavior — note but don't escalate |
| Active/New | Any | 🟠 Unresolved — flag for attention, may indicate ongoing threat |

---

## Report Template

### Inline Chat Report Structure

The inline report MUST include these sections in order:

1. **Header** — Workspace, analysis period, drift threshold, data sources
2. **Ranked Drift Score Table** — All SPNs sorted by DriftScore descending, with per-dimension ratios
3. **Flagged Entity Deep Dive** (for each SPN > 150%) — Baseline vs. recent comparison, dimension bar chart, new IPs/resources, corroborating evidence
4. **Correlated Signal Summary** — Findings from all 4 data sources in a single table
5. **Behavioral Baseline Chart** — ASCII bar chart showing all SPNs' daily avg vs. baseline
6. **Security Assessment** — Emoji-coded findings table with evidence citations
7. **Verdict Box** — Overall risk level, root cause analysis, recommendations

### Markdown File Report Structure

When outputting to markdown file, include everything from the inline format PLUS:

```markdown
# Service Principal Scope Drift Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Workspace:** <workspace_name>
**Baseline Period:** <start> → <end> (90 days)
**Recent Period:** <start> → <end> (7 days)
**Drift Threshold:** 150%
**Data Sources:** AADServicePrincipalSignInLogs, AuditLogs, DeviceNetworkEvents, SecurityAlert

---

## Executive Summary

<1-3 sentence summary: how many SPNs analyzed, how many flagged, overall risk level>

---

## Drift Score Ranking

<ASCII table with all SPNs, per-dimension ratios, flag status>
<!-- Wrap in code fence for consistent rendering -->

---

## Flagged Entities

### <SPN Name> — Drift Score <score>

<Deep dive: baseline vs recent table, dimension bars, new resources/IPs/locations>
<Corroborating evidence from AuditLogs, SecurityAlert, DeviceNetworkEvents>

---

## Pareto Analysis

<ASCII Pareto chart of drift dimensions or categories>
<80/20 analysis text>

---

## Correlated Signals

| Data Source | Finding | Incident Status |
|-------------|---------|-----------------|
| AADServicePrincipalSignInLogs | ... | N/A |
| AuditLogs | ... | N/A |
| DeviceNetworkEvents | ... | N/A |
| SecurityAlert / SecurityIncident | <Group by ProductName, translate to current branding> | <Status: New/Active/Closed, Classification: TP/FP/BP> |

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| 🔴/🟢/🟡 **Factor** | Evidence-based finding |

---

## Verdict

<Overall risk assessment with root cause analysis and recommendations>

---

## Appendix: Query Details

<All KQL queries used, with timestamps and result counts>
```

---

## Known Pitfalls

### Pitfalls for All Entity Types

#### SecurityAlert.Status Is Immutable — Always Join SecurityIncident
**Problem:** The `Status` field on `SecurityAlert` is set to `"New"` at creation time and **never changes**. It does NOT reflect whether the alert has been investigated, closed, or classified. Reading `SecurityAlert.Status` as current investigation status will always show "New" regardless of actual state.  
**Solution:** MUST join with `SecurityIncident` to get real `Status` (New/Active/Closed) and `Classification` (TruePositive/FalsePositive/BenignPositive). See Queries 4 and 11 which implement this join. When assessing drift risk from alerts, differentiate: Closed-FalsePositive alerts are noise (discount), Closed-TruePositive alerts are confirmed threats (escalate), Active/New incidents need attention (flag).

#### Low-Volume Statistical Inflation
**Problem:** Entities with very low baseline activity (e.g., 1 sign-in/day) will show extreme volume ratios even with minor changes.  
**Solution:** Apply the denominator floor (minimum 10 sign-ins/day for volume ratio calculation). Always flag low-volume baselines in the report.

#### Seasonal/Cyclical Baselines
**Problem:** Some entities have weekly patterns (lower on weekends) or monthly cycles (month-end batch jobs).  
**Solution:** Note if the 7-day recent window falls on an atypical portion of the cycle. The 90-day baseline smooths most cyclical patterns, but edge cases exist.

### Service Principal-Specific Pitfalls

#### IPv6 Fabric Address Churn
**Problem:** Microsoft first-party SPNs (MCAS, Defender, etc.) rotate through `fd00:` internal fabric IPv6 addresses automatically. This inflates the IP ratio without representing actual infrastructure changes.  
**Solution:** When all new IPs share the same `fd00:` prefix, note this as "Microsoft internal fabric rotation" and downgrade the IP dimension's contribution to the drift score assessment. Do NOT flag IPv6 churn from Microsoft fabric addresses as suspicious.

#### Credential Rotation False Positives
**Problem:** Automated certificate/secret rotation creates regular `Add/Remove service principal credentials` audit entries.  
**Solution:** Check if credential operations follow a regular cadence (weekly/monthly). If rotation is periodic and consistent with baseline, classify as operational — not drift.

#### SPNs Without Baseline Data
**Problem:** Newly provisioned SPNs have no baseline to compare against.  
**Solution:** These are excluded from the `join kind=inner` and will not appear in results. If the user asks about a specific SPN with no baseline, report: "No baseline data available — SPN was provisioned within the recent window or has no sign-in history in the 90-day baseline period."

### User Account-Specific Pitfalls

#### 90-Day IP/App Contraction
**Problem:** The 90-day baseline captures ISP address rotations, travel IPs, and occasional app usage that won't naturally recur in a 7-day window. This makes user accounts appear to be "contracting" (score < 80) when they are actually stable.  
**Solution:** For user accounts showing contraction, check if the absolute numbers are reasonable. If the user had 30 IPs over 90 days but only 2 in 7 days, this is expected — note it as "natural IP diversity compression" rather than genuine scope reduction.

#### Non-Interactive Volume Inflation
**Problem:** Non-interactive sign-ins (token refreshes, background app activity) can number in the thousands per day. A brief outage or token cache flush can cause dramatic volume swings.  
**Solution:** Weight non-interactive drift scores lower in the overall assessment unless corroborated by new apps or IPs. Volume-only drift in non-interactive is rarely meaningful without other signals.

#### Cross-Join KQL Error
**Problem:** `join kind=inner on 1==1` (cross-join) is NOT supported in KQL Sentinel Data Lake. The SPN query uses separate subqueries joined on `ServicePrincipalId`, but user queries target a single UPN and cannot use this pattern.  
**Solution:** User queries MUST use the single-pass `extend Period = iff(TimeGenerated < baselineEnd, "Baseline", "Recent")` pattern with `summarize ... by Period`. See Queries 6 and 7.

#### Identity Protection Risk States Lingering
**Problem:** Risk events (e.g., `unfamiliarFeatures`, `anonymizedIPAddress`) may show `RiskState == "atRisk"` for days/weeks after the triggering event if no admin action is taken.  
**Solution:** Check `RiskState` carefully. `"atRisk"` doesn't mean ongoing compromise — it means the risk was never remediated or dismissed. Flag these for admin review but don't automatically escalate drift score.

#### Device Telemetry Gaps
**Problem:** `DeviceDetail` in `SigninLogs` may be empty or `{}` for some sign-in types (SSO, mobile apps, headless clients).  
**Solution:** If `DistinctDevices` is very low (0-1) despite many sign-ins, note the gap rather than treating low device count as meaningful.

#### Custom Anomaly Table Availability
**Problem:** `Signinlogs_Anomalies_KQL_CL` is a custom table that may not exist in all workspaces. **CRITICAL:** The table name uses lowercase 'l' in "logs" — `Signinlogs` not `SigninLogs`. KQL custom table names are case-sensitive.  
**Solution:** If the table is not found, skip Query 9 gracefully and note: "⚠️ Custom anomaly table not available in this workspace — skipping pre-computed anomaly check." Do not fail the entire analysis.

---

## Error Handling

### Common Issues

| Issue | Entity Type | Solution |
|-------|-------------|----------|
| `AADServicePrincipalSignInLogs` table not found | SPN | This table may not exist in all workspaces. Check if it's available with `search_tables`. Try Advanced Hunting as fallback. |
| `SigninLogs` table not found | User | Rare but possible in workspaces without Entra ID P1/P2 logging enabled. Report as blocker. |
| `AADNonInteractiveUserSignInLogs` table not found | User | Check workspace configuration. Non-interactive logs require diagnostic settings. Skip non-interactive analysis and note the gap. |
| `Signinlogs_Anomalies_KQL_CL` table not found | User | Custom table — may not exist. Note: table name uses lowercase 'l' in "logs". Skip Query 9 gracefully with a note; do not fail the analysis. |
| Zero entities in results | Both | Verify the workspace has sign-in data for the entity type. Check if logging is enabled. For user: verify UPN spelling. |
| Query timeout | Both | Reduce the baseline window from 90 to 60 days, or add `\| take 100` to intermediate results. |
| AuditLogs `has_any` not matching | Both | Ensure IDs are quoted strings in the `dynamic()` array. Use `tostring()` on dynamic fields. |
| Very large number of SPNs | SPN | Add `\| where BL_TotalSignIns > 10` to filter out extremely low-activity SPNs that add noise. |
| `join kind=inner on 1==1` error | User | Cross-join not supported in KQL. Use single-pass `extend Period = iff(...)` pattern instead. See Queries 6-7. |
| Identity Protection fields empty | User | `RiskLevelDuringSignIn` may be "none" for all records if Identity Protection is not licensed. Note the gap; don't treat as "no risk." |

### Validation Checklist

Before presenting results, verify:

**All entity types:**
- [ ] All applicable data sources were queried (even if some returned 0 results)
- [ ] Low-volume denominator floor was applied to any entity with BL_DailyAvg < 10
- [ ] Corroborating evidence was checked for every flagged entity
- [ ] Empty results are explicitly reported with ✅ (not silently omitted)
- [ ] The report includes the drift score formula and threshold for transparency
- [ ] SecurityAlert was joined with SecurityIncident for real Status/Classification (never read SecurityAlert.Status directly)
- [ ] Incident classifications (TP/FP/BP) were factored into risk assessment — FalsePositive alerts discounted, TruePositive alerts escalated

**Service Principal:**
- [ ] IPv6 `fd00:` addresses were identified as Microsoft fabric (not adversary infrastructure)
- [ ] Credential rotation cadence was assessed for AuditLog findings

**User Account:**
- [ ] Both interactive AND non-interactive drift scores were computed
- [ ] IP/app contraction was contextualized (90-day diversity vs 7-day window)
- [ ] Identity Protection risk states were checked and reported
- [ ] Custom anomaly table was queried (or gap noted if unavailable)
- [ ] Device telemetry gaps were noted if DeviceDetail was sparse
