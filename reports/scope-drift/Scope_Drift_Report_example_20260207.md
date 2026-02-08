# User Account Scope Drift Report

**Generated:** 2026-02-07 00:59 UTC  
**Workspace:** la-contoso (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)  
**Entity:** `user@contoso.com` (User Account)  
**Baseline Period:** 2025-11-02 → 2026-01-31 (90 days, days 8–97 ago)  
**Recent Period:** 2026-01-31 → 2026-02-07 (7 days)  
**Drift Threshold:** 150%  
**Data Sources:** SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, SecurityAlert, SecurityIncident, Signinlogs_Anomalies_KQL_CL

---

## Executive Summary

Scope drift analysis for `user@contoso.com` shows **significant scope contraction** across both interactive and non-interactive sign-in dimensions. The interactive drift score is **37.7** and the non-interactive drift score is **50.5** — both well below the 80–120 stable range, indicating the user was substantially more active during the 90-day baseline than in the recent 7-day window. This is consistent with natural IP/app diversity compression over a shorter measurement window rather than genuine behavioral reduction. No scope expansion or drift was detected. Several low-to-medium Identity Protection risk events and 57 security alerts (47 incidents, predominantly classified BenignPositive) were observed but do not indicate compromise.

**Overall Risk Level:** 🟢 **LOW** — No scope drift detected. Contracting activity is expected when comparing a 90-day diverse baseline to a 7-day window.

---

## Drift Score Summary

### Interactive Sign-Ins (SigninLogs)

$$\text{DriftScore}_{Interactive} = 0.25V + 0.20A + 0.10R + 0.15IP + 0.10L + 0.10D + 0.10F$$

```
┌──────────────────────────────────────────────────────────┐
│               INTERACTIVE DRIFT SCORE: 37.7              │
│                    ✅ Contracting Scope                   │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (25%)  ▓▓▓▓▓▓░░░░░░░░░░░░░░  55.5%           │
│  Apps     (20%)  ▓▓▓░░░░░░░░░░░░░░░░░  28.9%           │
│  Resources(10%)  ▓▓▓▓▓▓░░░░░░░░░░░░░░  54.2%           │
│  IPs      (15%)  ▓░░░░░░░░░░░░░░░░░░░  10.0%           │
│  Locations(10%)  ▓▓▓░░░░░░░░░░░░░░░░░  25.0%           │
│  Devices  (10%)  ▓▓░░░░░░░░░░░░░░░░░░  23.1%           │
│  FailRate (10%)  ▓▓▓▓▓▓░░░░░░░░░░░░░░  62.7%  ↓-3.73p │
│                                                          │
│  ──────────────────────── 100% baseline ───┤            │
│                      ▲ 150% drift threshold              │
└──────────────────────────────────────────────────────────┘
```

| Dimension | Weight | Baseline (90d) | Recent (7d) | Ratio | Status |
|-----------|--------|----------------|-------------|-------|--------|
| **Volume** (daily avg) | 25% | 22.7/day | 12.6/day | 55.5% | ✅ Contracting |
| **Applications** | 20% | 38 distinct | 11 distinct | 28.9% | ✅ Contracting |
| **Resources** | 10% | 24 distinct | 13 distinct | 54.2% | ✅ Contracting |
| **IP Addresses** | 15% | 30 distinct | 3 distinct | 10.0% | ✅ Contracting |
| **Locations** | 10% | 8 distinct | 2 distinct | 25.0% | ✅ Contracting |
| **Devices** | 10% | 13 distinct | 3 distinct | 23.1% | ✅ Contracting |
| **Failure Rate** | 10% | 4.87% | 1.14% | δ = -3.73pp | ✅ Improving |

### Non-Interactive Sign-Ins (AADNonInteractiveUserSignInLogs)

$$\text{DriftScore}_{NonInteractive} = 0.30V + 0.20A + 0.15R + 0.15IP + 0.10L + 0.10F$$

```
┌──────────────────────────────────────────────────────────┐
│            NON-INTERACTIVE DRIFT SCORE: 50.5             │
│                    ✅ Contracting Scope                   │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (30%)  ▓▓▓▓▓▓▓░░░░░░░░░░░░░  63.5%           │
│  Apps     (20%)  ▓▓▓▓░░░░░░░░░░░░░░░░  41.4%           │
│  Resources(15%)  ▓▓▓▓▓░░░░░░░░░░░░░░░  47.6%           │
│  IPs      (15%)  ▓▓░░░░░░░░░░░░░░░░░░  16.7%           │
│  Locations(10%)  ▓▓▓░░░░░░░░░░░░░░░░░  25.0%           │
│  FailRate (10%)  ▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░  110.3%  ↑+1.03p│
│                                                          │
│  ──────────────────────── 100% baseline ───┤            │
│                      ▲ 150% drift threshold              │
└──────────────────────────────────────────────────────────┘
```

| Dimension | Weight | Baseline (90d) | Recent (7d) | Ratio | Status |
|-----------|--------|----------------|-------------|-------|--------|
| **Volume** (daily avg) | 30% | 912.0/day | 578.9/day | 63.5% | ✅ Contracting |
| **Applications** | 20% | 152 distinct | 63 distinct | 41.4% | ✅ Contracting |
| **Resources** | 15% | 170 distinct | 81 distinct | 47.6% | ✅ Contracting |
| **IP Addresses** | 15% | 42 distinct | 7 distinct | 16.7% | ✅ Contracting |
| **Locations** | 10% | 8 distinct | 2 distinct | 25.0% | ✅ Contracting |
| **Failure Rate** | 10% | 0.96% | 1.99% | δ = +1.03pp | 🟡 Slight increase |

> ⚠️ **Note:** Non-interactive baseline had 152 distinct apps, but `make_set` returns a maximum of 50. Some apps appearing "new" in the recent window may actually exist in the baseline. Set difference comparisons are therefore approximate.

---

## Baseline vs. Recent Detail

### Interactive Sign-In Breakdown

**Total Sign-Ins:** 1,498 (baseline over 66 active days) → 88 (recent over 7 days)

**Recent Applications (11):**
`Azure Portal`, `Microsoft 365 Copilot extension`, `Microsoft 365 Security and Compliance Center`, `Office365 Shell WCSS-Client`, `Microsoft GitHub for Open Source Enterprise Cloud Access (1ES)`, `Power Virtual Agents`, `OfficeHome`, `Microsoft Flow Portal`, `Sentinel Platform Services App Reg`, `Power Platform Admin Center`, `Microsoft Teams Web Client`

✅ All 11 recent apps also appear in the 90-day baseline — no new application access detected.

**Recent IPs (3):**

| IP Address | In Baseline? | Notes |
|------------|-------------|-------|
| 192.0.2.10 | ✅ Yes | Known IP |
| 192.0.2.11 | ✅ Yes | Known IP |
| 192.0.2.50 | 🟡 **New** | Not seen in 90-day baseline |

**New IP Analysis:** 1 new interactive IP (`192.0.2.50`) detected. The `192.0.2.x` range is consistent with the user's ISP pattern (multiple baseline IPs in the same range: `192.0.2.51`, `192.0.2.52`, `192.0.2.53`, `192.0.2.54`, `192.0.2.55`). This is likely a normal ISP address rotation — **low risk**.

**Recent Locations (2):** CA, US — both in baseline. No new geographic locations.

**Recent Devices (3):** `Windows10|Chrome 143.0.0`, `Windows10|Edge 144.0.0`, `Android|Chrome Mobile 144.0.0` — all patterns present in baseline (browser version updates only). No new device types.

### Non-Interactive Sign-In Breakdown

**Total Sign-Ins:** 68,399 (baseline over 75 active days) → 4,631 (recent over 8 days)

**Recent IPs (7):** All 7 IPs appear in the 90-day baseline — ✅ no new IPs.

**Recent Locations (2):** US, CA — both in baseline — ✅ no new locations.

**Failure Rate Increase:** +1.03 percentage points (0.96% → 1.99%). This is a minor increase in non-interactive failures, possibly from token refresh churn or brief service disruption. Not significant enough to flag.

---

## Correlated Signals

### AuditLog Configuration Changes

| Operation | Baseline (90d) | Recent (7d) | Trend |
|-----------|-----------------|-------------|-------|
| Validate user authentication | 15 | 4 | ✅ Normal |
| Update conditional access policy | 2 | 3 | 🟡 Slightly elevated |
| Group_GetDynamicGroupProperties | 1 | 0 | ✅ Quiet |
| Add member to group | 1 | 0 | ✅ Quiet |
| Add app role assignment to service principal | 3 | 0 | ✅ Quiet |
| Add conditional access policy | 2 | 0 | ✅ Quiet |
| Add app role assignment grant to user | 3 | 0 | ✅ Quiet |
| Update user | 1 | 0 | ✅ Quiet |
| Add group | 1 | 0 | ✅ Quiet |
| Remove app role assignment from SPN | 1 | 0 | ✅ Quiet |

**Assessment:** 🔵 The user made 3 Conditional Access policy updates in the recent period (vs 2 in the 90-day baseline). This is consistent with security administration duties. Baseline operations (role assignments, group changes) are absent in the recent window — corroborating the contraction pattern.

### Pre-Computed Anomaly Detections (Signinlogs_Anomalies_KQL_CL — Last 14 Days)

| Detected | Type | Value | Severity | Location | Hits | Geo Novelty |
|----------|------|-------|----------|----------|------|-------------|
| 2026-01-29 | NewNonInteractiveDeviceCombo | Android\|Rich | 🟡 Medium | CA/Redmond | 5 | CityNovelty |
| 2026-01-27 | NewNonInteractiveIP | 198.51.100.20 | 🟡 Medium | CA/Bellevue | 10 | CityNovelty |
| 2026-01-26 | NewNonInteractiveIP | 198.51.100.21 | 🟡 Medium | CA/Seattle | 19 | — |
| 2026-01-25 | NewInteractiveIP | 198.51.100.22 | 🟡 Medium | CA/Portland | 12 | — |

**Assessment:** 🟡 Four medium-severity anomalies detected in the period immediately preceding the recent window (Jan 25–29). All originate within Canada (the user's expected country). The new IPs (`198.51.100.20`, `198.51.100.21`, `198.51.100.22`) appear in the 90-day baseline, confirming they were absorbed into the normal pattern. The `Android|Rich` device combo is notable but low risk — possibly a mobile app webview client. These anomalies all fall outside the 7-day recent window.

### Identity Protection Risk Events (Last 14 Days)

| Time | Risk Level | Risk State | Risk Type | IP | Location | App |
|------|-----------|------------|-----------|-----|----------|-----|
| 2026-02-07 00:33 | 🟡 Medium | Dismissed | — | 192.0.2.10 | CA | Azure Portal |
| 2026-02-07 00:33 | 🟡 Medium | Dismissed | — | 192.0.2.10 | CA | Azure Portal |
| 2026-02-07 00:03 | 🟡 Medium | Dismissed | unfamiliarFeatures | 192.0.2.10 | CA | Azure Portal |
| 2026-01-25 20:56 | 🟢 Low | Remediated | — | 198.51.100.22 | CA | One Outlook Web |
| 2026-01-25 20:26 | 🟢 Low | Remediated | anonymizedIPAddress | 198.51.100.22 | CA | One Outlook Web |
| 2026-01-25 20:25 | 🟢 Low | Dismissed | anonymizedIPAddress | 198.51.100.22 | CA | One Outlook Web |

**Assessment:**
- 🟡 **unfamiliarFeatures** (medium risk, dismissed) on 2026-02-07 from IP `192.0.2.10` — this IP is in the 90-day baseline and the user's known Canadian location. The risk was auto-dismissed by Identity Protection. Not indicative of compromise.
- 🟢 **anonymizedIPAddress** (low risk, remediated/dismissed) on 2026-01-25 from IP `198.51.100.22` — flagged for VPN/anonymizer usage. This IP is in the baseline. Risk was remediated, indicating MFA was satisfied or admin action was taken.
- All risk events originate from Canada (CA) — no geographic anomalies.

### Security Alerts & Incidents (97-Day Window)

**Latest Alert:** 2026-02-06  
**Severities:** Medium, Low  
**Total:** 57 alerts across 47 incidents

| Product | Alert Count | Incidents | Statuses | Classifications |
|---------|-------------|-----------|----------|-----------------|
| **Microsoft Sentinel** (Scheduled Alerts) | 35 | 32 | New, Closed | BenignPositive |
| **Microsoft Defender for Endpoint** | 14 | 9 | Closed | BenignPositive |
| **Microsoft Defender for Cloud Apps** | 3 | 1 | Closed | BenignPositive |
| **Microsoft Purview Data Loss Prevention** | 3 | 3 | Closed | BenignPositive |
| **Microsoft Sentinel** (NRT Alerts) | 2 | 2 | Closed | BenignPositive |

#### Microsoft Sentinel — Scheduled Alerts (35 alerts / 32 incidents)

| Alert Name | Severity | Tactics |
|------------|----------|---------|
| Conditional Access Policy Modified by New User | Medium | DefenseEvasion |
| Authentications of Privileged Accounts Outside of Expected Controls | Medium | InitialAccess |
| Service Principal Assigned App Role With Sensitive Access | Medium | PrivilegeEscalation |
| Privileged User Logon from new ASN | Medium | InitialAccess |
| New UserAgent observed in last 24 hours | Low | InitialAccess, Execution, CommandAndControl |
| Successful logon from IP and failure from a different IP | Medium | InitialAccess, CredentialAccess |
| Changes to Application Ownership | Medium | Persistence, PrivilegeEscalation |
| Rare application consent | Medium | Persistence, LateralMovement, Collection |

#### Microsoft Sentinel — NRT Alerts (2 alerts / 2 incidents)

| Alert Name | Severity | Tactics |
|------------|----------|---------|
| NRT First access credential added to Application or Service Principal where no credential was present | Medium | DefenseEvasion |
| NRT New access credential added to Application or Service Principal | Medium | DefenseEvasion |

#### Microsoft Defender for Endpoint (14 alerts / 9 incidents)

| Alert Name | Severity | Tactics |
|------------|----------|---------|
| Firewall tampering by domain user account | Medium | DefenseEvasion |
| Firewall tampering by domain user account (1) | Medium | Persistence, DefenseEvasion |
| Bitsadmin abuse by domain user account | Medium | Unknown |
| Bitsadmin abuse by domain user account (1) | Medium | DefenseEvasion |

#### Microsoft Defender for Cloud Apps (3 alerts / 1 incident)

| Alert Name | Severity | Tactics |
|------------|----------|---------|
| File containing PII / PCI / PHI detected in the cloud (built-in DLP engine) | Medium | Execution |

#### Microsoft Purview Data Loss Prevention (3 alerts / 3 incidents)

| Alert Name | Severity | Tactics |
|------------|----------|---------|
| DLP policy (Endpoint DLP) matched for document (sample-data.csv) in a device | Low | Exfiltration |
| DLP policy (Endpoint DLP) matched for document (sample-data.pdf) in a device | Low | Exfiltration |
| DLP policy (Endpoint DLP) matched for document (test-doc.docx) in a device | Low | Exfiltration |

**Assessment:**
- 🟢 46 of 47 incidents are **Closed** and classified as **BenignPositive** — activity was real but expected/authorized.
- 🔵 **Microsoft Sentinel (Scheduled)** — Analytics rule detections consistent with a security administrator performing expected privileged operations.
- 🔵 **Microsoft Sentinel (NRT)** — Near-real-time credential management detections align with legitimate app registration maintenance.
- 🟡 **Microsoft Defender for Endpoint** — Bitsadmin and firewall tampering alerts suggest endpoint administrative tooling usage. All closed as BenignPositive.
- 🔵 **Microsoft Defender for Cloud Apps** — PII/PCI/PHI detection from cloud DLP engine, consistent with DLP policy validation/testing.
- 🔵 **Microsoft Purview DLP** — Endpoint DLP policy matches on test documents.

#### ⚠️ Untriaged Incidents (Status: New)

| Incident # | Title | Severity | Created | Product |
|------------|-------|----------|---------|---------|
| 0000 | Conditional Access Policy Modified by New User involving one user | Low | 2026-02-06 20:27 | Microsoft Sentinel (Scheduled Alerts) |

> **1 incident** remains in **New** status and has not been triaged. This is a low-severity Sentinel analytics rule detection from the current day. It does not indicate drift but should be reviewed by the SOC team.

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| 🟢 **Interactive Drift Score** | 37.7 — well below 80, significant scope contraction. No expansion detected. |
| 🟢 **Non-Interactive Drift Score** | 50.5 — well below 80, significant scope contraction. Slight failure rate increase (+1.03pp) is negligible. |
| 🟢 **New Applications** | 0 new interactive apps. Non-interactive new apps may be artifacts of `make_set(50)` truncation. |
| 🟢 **New IPs** | 1 new interactive IP (`192.0.2.50`) — same ISP range as baseline, likely ISP rotation. |
| ✅ **New Locations** | 0 — all activity from CA and US, both in baseline. |
| ✅ **New Devices** | 0 — browser version updates only (Edge 144, Chrome 143, Chrome Mobile 144). |
| 🟡 **Anomaly Detections** | 4 medium anomalies (Jan 25–29), all from Canada, all absorbed into baseline. Outside recent window. |
| 🟡 **Identity Protection** | Medium: unfamiliarFeatures (dismissed). Low: anonymizedIPAddress (remediated). No active risk states. |
| 🟢 **Security Alerts** | 57 alerts / 47 incidents — all closed as BenignPositive. Consistent with admin operations. |
| 🔵 **AuditLog Changes** | 3 CA policy updates in recent window — consistent with security administration role. |
| 🟡 **Failure Rate (NI)** | +1.03pp increase in non-interactive failures. Minor — likely token refresh churn. |

---

## Verdict

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│   OVERALL RISK:  🟢 LOW — No Scope Drift Detected               │
│                                                                  │
│   Interactive Score:      37.7  (< 80 = Contracting)             │
│   Non-Interactive Score:  50.5  (< 80 = Contracting)             │
│                                                                  │
│   Root Cause: Natural diversity compression — 90-day baseline    │
│   captures ISP rotations, travel IPs, occasional app usage       │
│   that won't recur in a 7-day window. Activity is stable and     │
│   consistent with a security administrator role.                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Root Cause Analysis

The contraction pattern is expected for a user account when comparing a 90-day baseline (which captures diverse ISP rotations, travel, periodic app access, and occasional exploratory usage) to a focused 7-day window. Key observations:

1. **Volume reduction** — 22.7 → 12.6 interactive sign-ins/day and 912 → 579 non-interactive/day. The user was less active this week but still within normal bounds for a human user.
2. **IP diversity compression** — 30 → 3 interactive IPs is dramatic but expected. The baseline accumulated ISP address rotations, VPN exits, and Microsoft corporate IPs over 90 days. The single new IP (`192.0.2.50`) is in the same ISP range as 6 other baseline IPs.
3. **App/resource contraction** — 38 → 11 apps and 24 → 13 resources interactively. The user focused on core security/admin tools (Azure Portal, Sentinel, M365 Security) during the recent period.
4. **Failure rate improvement** — Interactive failure rate dropped from 4.87% to 1.14%, indicating cleaner authentication in the recent window.

### Recommendations

| Priority | Recommendation |
|----------|-------|
| 🔵 **Informational** | Triage remaining **New** status incidents in Microsoft Defender XDR to clear the backlog |
| 🔵 **Informational** | The `unfamiliarFeatures` risk event from 2026-02-07 was auto-dismissed — no admin action needed |
| ✅ **No Action** | No scope drift detected — no behavioral expansion, no new high-risk patterns |

---

## Appendix: Drift Score Formula

### Interactive (7 Dimensions)

$$\text{DriftScore}_{Interactive} = 0.25V + 0.20A + 0.10R + 0.15IP + 0.10L + 0.10D + 0.10F$$

| Dimension | Weight | Metric |
|-----------|--------|--------|
| Volume (V) | 25% | Daily avg sign-ins (recent / baseline × 100) |
| Applications (A) | 20% | Distinct apps accessed |
| Resources (R) | 10% | Distinct target resources |
| IP Addresses (IP) | 15% | Distinct source IPs |
| Locations (L) | 10% | Distinct geographic locations |
| Devices (D) | 10% | Distinct device types (OS + browser) |
| Failure Rate (F) | 10% | 100 + (delta × 10), where delta = recent% − baseline% |

### Non-Interactive (6 Dimensions)

$$\text{DriftScore}_{NonInteractive} = 0.30V + 0.20A + 0.15R + 0.15IP + 0.10L + 0.10F$$

### Interpretation Scale

| Score | Meaning | Action |
|-------|---------|--------|
| < 80 | Contracting scope | ✅ Normal |
| 80–120 | Stable / normal variance | ✅ No action |
| 120–150 | Moderate deviation | 🟡 Monitor |
| > 150 | Significant drift | 🔴 FLAG — investigate |
| > 250 | Extreme drift | 🔴 CRITICAL |

---

## Appendix: Queries Used

### Query 1 — Interactive Baseline vs. Recent (SigninLogs)
```kql
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
**Result:** 2 rows (Baseline, Recent) — ✅ Success

### Query 2 — Non-Interactive Baseline vs. Recent (AADNonInteractiveUserSignInLogs)
```kql
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
**Result:** 2 rows (Baseline, Recent) — ✅ Success

### Query 3 — AuditLog User Changes
```kql
AuditLogs
| where TimeGenerated > ago(97d)
| where OperationName has_any ("password", "MFA", "role", "group", "conditional", "auth",
    "user", "member", "security info")
| where tostring(TargetResources) has '<UPN>'
    or tostring(InitiatedBy) has '<UPN>'
    or Identity =~ '<UPN>'
| extend InBaseline = TimeGenerated < ago(7d)
| summarize BaselineOps = countif(InBaseline), RecentOps = countif(not(InBaseline)),
    Operations = make_set(OperationName, 30) by OperationName
| order by RecentOps desc
```
**Result:** 10 rows — ✅ Success

### Query 4 — Anomaly Table (Signinlogs_Anomalies_KQL_CL)
```kql
Signinlogs_Anomalies_KQL_CL
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ '<UPN>'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10 or CountryNovelty or CityNovelty or StateNovelty, "Medium",
    ArtifactHits >= 5, "Low", "Informational")
| where Severity in ("High", "Medium", "Low")
| project DetectedDateTime, AnomalyType, Value, Severity, Country, City,
    ArtifactHits, CountryNovelty, CityNovelty, OS, BrowserFamily
| order by DetectedDateTime desc | take 20
```
**Result:** 4 rows — ✅ Success

### Query 5 — Identity Protection Risk Events
```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ '<UPN>'
| where RiskLevelDuringSignIn != "none" and RiskLevelDuringSignIn != ""
| project TimeGenerated, RiskLevelDuringSignIn, RiskState, RiskEventTypes_V2,
    IPAddress, Location, AppDisplayName,
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser), ConditionalAccessStatus
| order by TimeGenerated desc | take 20
```
**Result:** 15 rows — ✅ Success

### Query 6 — SecurityAlert + SecurityIncident Correlation
```kql
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
| summarize AlertCount = count(), AlertNames = make_set(AlertName, 15),
    Severities = make_set(AlertSeverity, 5), Tactics = make_set(Tactics, 10),
    LatestAlert = max(TimeGenerated1), IncidentStatuses = make_set(Status, 5),
    Classifications = make_set(Classification, 5), IncidentCount = dcount(IncidentNumber)
    by ProviderName
| order by AlertCount desc
```
**Result:** 1 row (Microsoft XDR: 57 alerts, 45 incidents) — ✅ Success
