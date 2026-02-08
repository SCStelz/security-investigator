# Service Principal Scope Drift Report

**Generated:** 2026-02-07 04:39 UTC  
**Workspace:** la-contoso (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)  
**Baseline Period:** 2025-11-02 → 2026-01-30 (90 days)  
**Recent Period:** 2026-01-30 → 2026-02-06 (7 days)  
**Drift Threshold:** 150%  
**Data Sources:** AADServicePrincipalSignInLogs, AuditLogs, DeviceNetworkEvents, SecurityAlert, SecurityIncident  

---

## Executive Summary

**7 service principals** were analyzed with sign-in activity across both baseline and recent periods. **1 SPN** (Microsoft Cloud App Security) exceeded the raw 150% drift threshold at 228.5, however after applying the **low-volume denominator floor** (baseline < 10 sign-ins/day) and identifying all new IPs as **Microsoft `fd00:` internal fabric addresses**, the adjusted score drops to **90.2 (Stable)**. No security alerts, no confirmed threats, and no anomalous permission changes were detected across any SPN. **Overall risk: ✅ Low**.

---

## Drift Score Formula

$$
\text{DriftScore}_{SPN} = 0.30V + 0.25R + 0.20IP + 0.15L + 0.10F
$$

| Dimension | Weight | Metric |
|-----------|--------|--------|
| **Volume (V)** | 30% | Daily avg sign-ins ratio (recent / baseline × 100) |
| **Resources (R)** | 25% | Distinct target resources ratio |
| **IPs (IP)** | 20% | Distinct source IP addresses ratio |
| **Locations (L)** | 15% | Distinct geographic locations ratio |
| **Failure Rate (F)** | 10% | Failure rate delta (100 + delta×10 if positive) |

**Interpretation:** 100 = identical to baseline | >150 = significant drift (investigate) | >250 = critical

---

## Drift Score Ranking

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ #  │ Service Principal                         │ Drift  │ Vol%   │ Res%  │ IP%    │ Loc%  │ ΔFail │ Flag │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1  │ Microsoft Cloud App Security (Internal)   │ 228.5  │ 518.2  │ 100.0 │ 115.4  │ 100.0 │  0.00 │ ⚠️¹  │
│ 2  │ ConfigMgrService-CloudMgmt                │  97.2  │  90.5  │ 100.0 │ 100.0  │ 100.0 │  0.00 │  ✅  │
│ 3  │ ConfigMgrSvc_xxxxxxxx-xxxx-xxxx-xxxx...   │  96.9  │  89.8  │ 100.0 │ 100.0  │ 100.0 │  0.00 │  ✅  │
│ 4  │ AADPasswordProtectionProxy                │  88.9  │  88.0  │ 100.0 │ 100.0  │  50.0 │  0.00 │  ✅  │
│ 5  │ LogicApp-GraphAPI                         │  83.6  │  89.0  │  83.3 │  80.0  │  66.7 │ +0.03 │  ✅  │
│ 6  │ ConnectSyncProvisioning_CONTOSO-DC1       │  72.2  │  88.0  │  33.3 │ 100.0  │  50.0 │  0.00 │  ✅  │
│ 7  │ Copilot Security Integration - Production │  59.4  │  26.3  │ 100.0 │   7.7  │ 100.0 │  0.00 │  ⚠️¹ │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
¹ Low-volume baseline — score inflated/deflated by sparse data. See adjusted scores below.
```

### Low-Volume Adjusted Scores

Two SPNs have baseline daily averages below the 10 sign-in/day floor. Adjusted scores use `max(BL_DailyAvg, 10)` as the volume denominator:

```
┌──────────────────────────────────────────────────────────────────────┐
│ Service Principal                         │ Raw    │ Adjusted │ Flag │
├──────────────────────────────────────────────────────────────────────┤
│ Microsoft Cloud App Security (Internal)   │ 228.5  │   90.2   │  ✅  │
│   └─ BL_DailyAvg=1.1 → floor=10 → AdjVol=57.0%                    │
│   └─ All 15 new IPs are fd00: fabric → AdjIP=100%                  │
│                                                                      │
│ Copilot Security Integration - Production │  59.4  │   54.5   │  ✅  │
│   └─ BL_DailyAvg=3.8 → floor=10 → AdjVol=10.0%                    │
└──────────────────────────────────────────────────────────────────────┘
```

**Result: After adjustments, NO service principals exceed the 150% drift threshold.**

---

## Detailed Entity Analysis

### 1. Microsoft Cloud App Security (Internal) — Raw 228.5 → Adjusted 90.2 ✅

| Metric | Baseline (90d) | Recent (7d) | Ratio | Note |
|--------|----------------|-------------|-------|------|
| Total Sign-Ins | 13 | 17 | — | |
| Active Days | 12 | 3 | — | |
| Daily Avg | 1.1 | 5.7 | 518.2% | ⚠️ Low-volume inflation (floor applied → 57.0%) |
| Distinct Resources | 1 | 1 | 100.0% | Microsoft Rights Management Services (unchanged) |
| Distinct IPs | 13 | 15 | 115.4% | ⚠️ See below |
| Distinct Locations | 1 | 1 | 100.0% | No geographic change |
| Failure Rate | 0.00% | 0.00% | Δ 0.00 | No failures |

**New IP Addresses (15):**
```
All 15 new IPs share the fd00:abcd:1234:5678:ef01:200:a00:* prefix
├── fd00:abcd:1234:5678:ef01:200:a00:33f1
├── fd00:abcd:1234:5678:ef01:200:a00:505a
├── fd00:abcd:1234:5678:ef01:200:a00:6d51
├── fd00:abcd:1234:5678:ef01:200:a00:6626
├── fd00:abcd:1234:5678:ef01:200:a00:4afb
├── fd00:abcd:1234:5678:ef01:200:a00:2f68
├── fd00:abcd:1234:5678:ef01:200:a00:17dd
├── fd00:abcd:1234:5678:ef01:200:a00:2fbe
├── fd00:abcd:1234:5678:ef01:200:a00:5e60
├── fd00:abcd:1234:5678:ef01:200:a00:39ba
├── fd00:abcd:1234:5678:ef01:200:a00:39d4
├── fd00:abcd:1234:5678:ef01:200:a00:052c
├── fd00:abcd:1234:5678:ef01:200:a00:705c
├── fd00:abcd:1234:5678:ef01:200:a00:07e0
└── fd00:abcd:1234:5678:ef01:200:a00:438b
```

🟢 **Assessment:** All new IPs are `fd00:` Microsoft internal fabric IPv6 addresses — automatic rotation by the MCAS service infrastructure. This is expected behavior, not adversary infrastructure. The volume spike from 1.1 → 5.7 sign-ins/day is trivial in absolute terms. **No drift.**

**Dimension Bars (Adjusted):**
```
Volume     [███░░░░░░░░░░░░░░░░░]  57.0%  ⚠️ Adjusted (floor)
Resources  [██████████░░░░░░░░░░] 100.0%  ── No change
IPs        [██████████░░░░░░░░░░] 100.0%  ── Adjusted (fd00: fabric)
Locations  [██████████░░░░░░░░░░] 100.0%  ── No change
Fail Rate  [██████████░░░░░░░░░░] 100.0%  ── No change
```

---

### 2. ConfigMgrService-CloudMgmt — 97.2 ✅

| Metric | Baseline (90d) | Recent (7d) | Ratio |
|--------|----------------|-------------|-------|
| Total Sign-Ins | 10,885 | 945 | — |
| Active Days | 73 | 7 | — |
| Daily Avg | 149.1 | 135.0 | 90.5% |
| Distinct Resources | 1 | 1 | 100.0% |
| Distinct IPs | 1 | 1 | 100.0% |
| Distinct Locations | 1 | 1 | 100.0% |
| Failure Rate | 0.00% | 0.00% | Δ 0.00 |

🟢 **Assessment:** Highly stable. Accesses only Microsoft Graph from a single IP. Slight volume contraction (−9.5%) is within normal variance.

---

### 3. ConfigMgrSvc_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx — 96.9 ✅

| Metric | Baseline (90d) | Recent (7d) | Ratio |
|--------|----------------|-------------|-------|
| Total Sign-Ins | 145,282 | 12,337 | — |
| Active Days | 74 | 7 | — |
| Daily Avg | 1,963.3 | 1,762.4 | 89.8% |
| Distinct Resources | 1 | 1 | 100.0% |
| Distinct IPs | 1 | 1 | 100.0% |
| Distinct Locations | 2 | 2 | 100.0% |
| Failure Rate | 0.00% | 0.00% | Δ 0.00 |

🟢 **Assessment:** Highest volume SPN in the tenant. Exclusively accesses Configuration Manager Microservice. Extremely stable behavioral pattern with minor volume contraction (−10.2%).

---

### 4. AADPasswordProtectionProxy — 88.9 ✅

| Metric | Baseline (90d) | Recent (7d) | Ratio |
|--------|----------------|-------------|-------|
| Total Sign-Ins | 2,383 | 201 | — |
| Active Days | 73 | 7 | — |
| Daily Avg | 32.6 | 28.7 | 88.0% |
| Distinct Resources | 1 | 1 | 100.0% |
| Distinct IPs | 2 | 2 | 100.0% |
| Distinct Locations | 2 | 1 | 50.0% |
| Failure Rate | 0.00% | 0.00% | Δ 0.00 |

🟢 **Assessment:** Stable. Accesses Device Registration Service only. Location contraction (2→1) is natural IP diversity compression over 90 days vs 7 days. Credential rotation observed in baseline (Add/Remove credentials on Jan 26) — consistent with regular operational cadence.

---

### 5. LogicApp-GraphAPI — 83.6 ✅

| Metric | Baseline (90d) | Recent (7d) | Ratio |
|--------|----------------|-------------|-------|
| Total Sign-Ins | 37,923 | 3,175 | — |
| Active Days | 85 | 8 | — |
| Daily Avg | 446.2 | 396.9 | 89.0% |
| Distinct Resources | 6 | 5 | 83.3% |
| Distinct IPs | 10 | 8 | 80.0% |
| Distinct Locations | 3 | 2 | 66.7% |
| Failure Rate | 0.00% | 0.03% | Δ +0.03 |

**Resource Comparison:**
```
Baseline Resources (6):                    Recent Resources (5):
├── Office 365 Management APIs             ├── Office 365 Management APIs
├── Microsoft Graph                        ├── Microsoft Graph
├── Azure Monitor Control Service          ├── Azure Monitor Control Service
├── WindowsDefenderATP                     ├── WindowsDefenderATP
├── Azure Resource Manager                 ├── Azure Resource Manager
└── Sentinel Platform Services             └── (not accessed in recent)
```

🟢 **Assessment:** Slight contraction — "Sentinel Platform Services" not accessed in recent 7 days. This is expected variability for a Logic App with multiple resource targets. The +0.03% failure rate increase is negligible (1 failure out of 3,175 sign-ins). Two `Update service principal` operations detected in recent period (Feb 2) — likely operational configuration updates.

---

### 6. ConnectSyncProvisioning_CONTOSO-DC1 — 72.2 ✅ (Contracting)

| Metric | Baseline (90d) | Recent (7d) | Ratio |
|--------|----------------|-------------|-------|
| Total Sign-Ins | 4,677 | 395 | — |
| Active Days | 73 | 7 | — |
| Daily Avg | 64.1 | 56.4 | 88.0% |
| Distinct Resources | 3 | 1 | 33.3% |
| Distinct IPs | 1 | 1 | 100.0% |
| Distinct Locations | 2 | 1 | 50.0% |
| Failure Rate | 0.00% | 0.00% | Δ 0.00 |

**Resource Comparison:**
```
Baseline Resources (3):                             Recent Resources (1):
├── Microsoft Entra AD Synchronization Service      ├── Microsoft Entra AD Synchronization Service
├── Microsoft Graph                                 └── (not accessed)
└── Microsoft password reset service                └── (not accessed)
```

🔵 **Assessment:** The Entra Connect sync provisioning service has contracted from 3 to 1 target resource. Microsoft Graph and password reset service access absent in the 7-day window. Credential rotation observed in baseline (7 operations each for Update application, Certs/secrets management through Jan 27) — consistent with Entra Connect's automated certificate rotation cadence. **No concern — resource contraction indicates the sync service may have consolidated or reduced scope.**

---

### 7. Copilot Security Integration - Production — Raw 59.4 → Adjusted 54.5 ✅ (Contracting)

| Metric | Baseline (90d) | Recent (7d) | Ratio | Note |
|--------|----------------|-------------|-------|------|
| Total Sign-Ins | 15 | 1 | — | |
| Active Days | 4 | 1 | — | |
| Daily Avg | 3.8 | 1.0 | 26.3% | ⚠️ Low-volume (floor applied → 10.0%) |
| Distinct Resources | 1 | 1 | 100.0% | MDA LCNC Power Platform Security Webhooks |
| Distinct IPs | 13 | 1 | 7.7% | |
| Distinct Locations | 1 | 1 | 100.0% | |
| Failure Rate | 0.00% | 0.00% | Δ 0.00 | |

🔵 **Assessment:** Very low activity SPN that was provisioned relatively recently (Add service principal on Jan 12). Only 15 sign-ins across 4 days in the baseline. The contraction to 1 sign-in on 1 day in the recent window is expected for a lightly-used integration. The single new `fd00:` IP is Microsoft fabric rotation. **No concern.**

---

## Behavioral Baseline Chart

```
Daily Avg Sign-Ins: Baseline (90d) vs Recent (7d)

                                                          BL Avg    RC Avg
ConfigMgrSvc_xxxxxxxx...  █████████████████████████████ 1,963.3   1,762.4  ▼10%
                           ██████████████████████████
LogicApp-GraphAPI          ██████                          446.2     396.9  ▼11%
                           █████
ConfigMgrService-CloudMgmt ██                              149.1     135.0  ▼ 9%
                           ██
ConnectSyncProvision...    █                                64.1      56.4  ▼12%
                           █
AADPasswordProtection      ▏                                32.6      28.7  ▼12%
                           ▏
MCAS (Internal)            ▏                                 1.1       5.7  ▲418% ⚠️
                           ▏
Copilot Security           ▏                                 3.8       1.0  ▼74%  ⚠️
                           ▏

█ = Baseline    █ = Recent    ⚠️ = Low-volume baseline (<10/day)
```

---

## Correlated Signals

### AuditLogs — Permission & Credential Changes

| Operation | Target SPN | Baseline (90d) | Recent (7d) | Assessment |
|-----------|-----------|:---:|:---:|---|
| Update service principal | LogicApp-GraphAPI | 0 | 2 | 🔵 New activity — operational update |
| Update service principal | ConnectSyncProvisioning | 7 | 0 | 🟢 Regular cadence (baseline only) |
| Update application – Certs/secrets | ConnectSyncProvisioning | 7 | 0 | 🟢 Automated cert rotation |
| Update application | ConnectSyncProvisioning | 7 | 0 | 🟢 Automated maintenance |
| Remove SP credentials | AADPasswordProtectionProxy | 2 | 0 | 🟢 Regular credential rotation |
| Add SP credentials | AADPasswordProtectionProxy | 2 | 0 | 🟢 Regular credential rotation |
| Update service principal | AADPasswordProtectionProxy | 2 | 0 | 🟢 Operational |
| Add service principal | Copilot Security Integration | 1 | 0 | 🔵 Initial provisioning (Jan 12) |
| Update service principal | Copilot Security Integration | 1 | 0 | 🔵 Initial configuration |

**Summary:** All audit operations are consistent with normal operational patterns — automated certificate rotation (ConnectSync, AADPasswordProtection), initial provisioning (Copilot Security), and configuration updates (LogicApp). No suspicious permission grants, consent operations, or privilege escalation patterns detected.

### SecurityAlert + SecurityIncident

✅ **No security alerts or incidents** referencing any of the 7 service principals in the last 97 days.

- Checked: SecurityAlert filtered by SPN IDs and display names (0 matches)
- Checked: SecurityIncident join with SecurityAlert (0 matches)

### DeviceNetworkEvents

Network activity from system/service accounts across 6 domain-joined devices shows **expected operational traffic**:

| Process | Account | Connections | Devices | Assessment |
|---------|---------|:---:|:---:|---|
| svchost.exe | system | 3,627 | 6 | 🟢 Windows Update, AD, WinRM — normal |
| svchost.exe | network service | 1,362 | 6 | 🟢 CTL downloads, Defender updates — normal |
| fluent-bit.exe | system | 726 | 2 | 🟢 Log forwarding agent — expected |
| mpdefendercoreservice.exe | system | 718 | 6 | 🟢 Defender telemetry — normal |
| sensecm.exe | system | 574 | 5 | 🟢 Defender for Endpoint sensor — normal |
| lsass.exe | system | 571 | 6 | 🟢 Authentication, AD, certificate validation — normal |
| smsexec.exe | system | 261 | 1 | 🟢 SCCM client operations — normal |
| azureadpasswordprotectionproxy.exe | system | 152 | 2 | 🟢 AAD Password Protection — correlates with SPN |

✅ No anomalous network destinations, unexpected ports, or suspicious lateral movement detected.

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| ✅ **Drift Detection** | No service principals exceed the 150% threshold after low-volume adjustments |
| 🟢 **Volume Trends** | 5 of 7 SPNs show slight volume contraction (8-12%) — healthy and stable |
| 🟢 **Resource Access** | No new target resources across any SPN. 2 SPNs show resource contraction |
| 🟢 **IP Addresses** | Only new IPs are `fd00:` Microsoft internal fabric addresses (MCAS) — not adversary |
| 🟢 **Geographic Locations** | No new geographic locations. Minor contractions due to 90d→7d window compression |
| 🟢 **Failure Rates** | Near-zero across all SPNs. Only LogicApp-GraphAPI shows +0.03% (1 failure/3,175 sign-ins) |
| 🟢 **Credential Operations** | All credential changes follow regular rotation cadence or initial provisioning |
| ✅ **Security Alerts** | Zero security alerts or incidents involving any SPN in 97 days |
| ✅ **Network Activity** | All service-level network traffic is to expected Microsoft/domain endpoints |
| ⚠️ **Low-Volume SPNs** | MCAS (1.1/day) and Copilot Security (3.8/day) have sparse baselines — ratios unreliable without floor |

---

## Verdict

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   Overall Risk Level:  ✅ LOW                                               │
│                                                                             │
│   Root Cause Analysis:                                                      │
│   • No genuine scope drift detected across any service principal            │
│   • The only threshold exceedance (MCAS at 228.5) is entirely explained     │
│     by low-volume baseline inflation and Microsoft IPv6 fabric rotation     │
│   • All SPNs maintain consistent resource access patterns                   │
│   • Credential operations follow expected rotation cadences                 │
│   • Zero corroborating threat signals from SecurityAlert,                   │
│     SecurityIncident, or DeviceNetworkEvents                                │
│                                                                             │
│   Recommendations:                                                          │
│   • No immediate action required                                            │
│   • Continue monitoring MCAS and Copilot Security SPNs as they              │
│     accumulate more baseline data for meaningful trend analysis              │
│   • Review ConnectSyncProvisioning resource contraction (3→1 resources)     │
│     to confirm this is intentional scope reduction                          │
│   • Schedule next scope drift review in 30 days                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Appendix: Query Details

### Query 1 — Baseline vs Recent Behavioral Comparison
**Table:** `AADServicePrincipalSignInLogs`  
**Period:** ago(97d) → now  
**Results:** 7 SPNs with both baseline and recent data  
**Execution:** 2026-02-07 04:38 UTC  

### Query 2 — AuditLog Permission & Credential Changes
**Table:** `AuditLogs`  
**Period:** ago(97d) → now  
**Filter:** SPN IDs in TargetResources or InitiatedBy  
**Results:** 9 operations across 4 SPNs (2 recent, 7 baseline-only)  
**Execution:** 2026-02-07 04:39 UTC  

### Query 3 — SecurityAlert + SecurityIncident Correlation
**Tables:** `SecurityAlert` → `SecurityIncident` (inner join on AlertId)  
**Period:** ago(97d) → now  
**Filter:** SPN IDs and display names in Entities/CompromisedEntity  
**Results:** 0 alerts, 0 incidents  
**Execution:** 2026-02-07 04:39 UTC  

### Query 4 — DeviceNetworkEvents
**Table:** `DeviceNetworkEvents`  
**Period:** ago(7d) → now  
**Filter:** system/service accounts + Microsoft service endpoints  
**Results:** 20 process/account combinations across 6 devices  
**Execution:** 2026-02-07 04:39 UTC  
