# Sentinel Ingestion Analysis Report

**Generated:** 2026-02-22  
**Workspace:** la-contoso-sentinel  
**Workspace ID:** 12345678-abcd-ef01-2345-6789abcdef01  
**Report Period:** 2025-11-24 to 2026-02-21 (90 days)

*This report presents data-driven recommendations based on automated analysis of ingestion patterns, detection coverage, and tier classification. All recommendations require human review and validation before implementation. Verify findings against your operational context, retention requirements, and compliance obligations before making changes.*

---

## 1. Executive Summary

### 📊 Workspace at a Glance

| | Metric | Value |
|---|--------|-------|
| 📦 | Active Tables (ingesting) | 104 |
| 📦 | Billable Tables | 96 |
| 🕒 | Report Period | 2025-11-24 to 2026-02-21 (90 days) |
| 📏 | Avg Daily Ingestion | 0.712 GB/day |
| 📈 | Peak Day | 1.270 GB (2026-02-13 — Fri) |
| 📉 | Min Day | 0.307 GB (2026-01-03 — Sat) |
| 🔄 | Trend | Stable — consistent weekday/weekend cycle with no sustained growth |

### 💰 Cost Waterfall

```
                                    90-Day (GB)    Avg/Day (GB)
  Total Ingestion                      64.802            0.712
  - Non-Billable                     -  1.413         -  0.016
  ──────────────────────────────────────────────────────────────
  Gross Billable                       63.389            0.697
  - Est. E5/XDR Benefit              -  8.802         -  0.097
  - Est. DfS P2 Benefit              -  1.296         -  0.014
  ──────────────────────────────────────────────────────────────
  🎯 Est. Net Billable               ~ 54.812         ~  0.602
```

> ⚠️ Benefit estimates assume all applicable licenses are activated and connectors are streaming. E5 line shows total E5-eligible volume — actual grant depends on license count (see §6b).
>
> 💡 **Commitment Tier Planning:** Sentinel commitment tiers start at 100 GB/day. At **0.602 GB/day net billable**, this workspace is well below the lowest commitment threshold — **Pay-As-You-Go pricing** is the appropriate tier.

### 🛡️ Detection Posture

| Metric | Value |
|--------|-------|
| 🛡 Enabled Analytic Rules | 225 (223 Scheduled, 2 NRT) |
| 🛡 Enabled Custom Detections | 8 |
| 🟡 Disabled Rules (AR + CD) | 59 + 1 |
| 🟡 Tables with Rules (top-20) | 12 of 20 |
| 🟠 Tables with Zero Rules (top-20) | 8 of 20 |
| 🔵 Tables on Basic Tier | 3 |
| 🔵 Tables on Data Lake Tier | 8 |

### Overall Assessment

- 📈 **Ingestion pattern:** Clear weekday/weekend cycle — weekday average **0.81 GB** vs weekend average **0.47 GB** (~42% drop). Stable over the 90-day window with no sustained growth trend. Peak of **1.270 GB** on 2026-02-13 (Fri).
- 🔴 **Detection gap:** **AADNonInteractiveUserSignInLogs** is on Data Lake tier with **5 active analytic rules** silently failing — these rules cannot execute against Data Lake tables. Immediate remediation required.
- 🔴 **NRT rule failures:** 2 NRT credential-monitoring rules have accumulated **154 combined failures** this period, degrading visibility into application/service principal credential changes.
- 🟠 **8 of 20 top tables** have zero detection rules on Analytics tier — potential cost optimization candidates or detection coverage gaps depending on data purpose.
- 🟢 **Strong detection foundation:** 233 combined enabled rules (225 AR + 8 CD) covering 28 tables with **99.9% execution success rate** across 209,896 executions.

### 🎯 Top 3 Recommendations

| # | Severity | Recommendation | Table/Scope | Impact | Risk |
|---|----------|----------------|-------------|--------|------|
| 1 | 🔴 | **Fix detection gap:** move AADNonInteractiveUserSignInLogs back to Analytics tier, or remove/disable the 5 rules referencing it | AADNonInteractiveUserSignInLogs | **5 analytic rules silently failing** — sign-in anomaly, log4j, guest invitation, and external PowerShell detections blind | High — active detection blind spot for non-interactive sign-in threats |
| 2 | 🟠 | **Fix failing NRT rules:** investigate and remediate 2 NRT credential-monitoring rules with persistent failures | AuditLogs (NRT rules) | **154 combined failures** — credential addition events unmonitored when rules fail | Medium — credential change monitoring degraded |
| 3 | 🟠 | **Migrate zero-rule DL-eligible tables to Data Lake:** LAQueryLogs, DeviceNetworkInfo, DeviceFileCertificateInfo, MDfEVulnerabilitiesList_CL | 4 Analytics-tier tables | **LAQueryLogs 0.310 GB (90d)** + 3 smaller tables — reduced cost on Data Lake with no detection impact | Low — cost optimization only, no security impact |

---

## 2. Ingestion Overview

### 2a. Top Tables by Volume

| Volume | # | DataType | BillableGB (90d) | Avg/Day (GB) | % | Rules | Current Tier |
|--------|---|----------|------------------|--------------|---|-------|--------------|
| 🟡 | 1 | SecurityEvent_Aux_CL | 23.532 | 0.331 | 37.1% | 0 | Data Lake |
| 🟡 | 2 | ThreatIntelIndicators | 13.757 | 0.151 | 21.7% | 🟢 33 | Analytics |
| 🟢 | 3 | MicrosoftGraphActivityLogs | 4.56 | 0.123 | 7.2% | 0 | Data Lake |
| 🟢 | 4 | SecurityEvent_SPLT_CL | 3.434 | 0.382 | 5.4% | 0 | Data Lake |
| 🟢 | 5 | AWSCloudTrail | 3.191 | 0.035 | 5% | 🟢 14 | Analytics |
| 🟢 | 6 | DeviceProcessEvents | 2.18 | 0.027 | 3.4% | 🟢 10 | Analytics |
| 🟢 | 7 | AADNonInteractiveUserSignInLogs | 2.126 | 0.023 | 3.4% | 🟡 5 | Data Lake |
| 🟢 | 8 | SecurityEvent | 1.266 | 0.016 | 2% | 🟢 41 | Analytics |
| 🟢 | 9 | DeviceFileEvents | 1.073 | 0.013 | 1.7% | 🟡 6 | Analytics |
| 🟢 | 10 | DeviceEvents | 1.019 | 0.013 | 1.6% | 🟡 3 | Analytics |
| 🟢 | 11 | AzureDiagnostics | 0.969 | 0.011 | 1.5% | 🟢 14 | Analytics |
| 🟢 | 12 | AppDependencies | 0.836 | 0.009 | 1.3% | ⚠️ 0 | Analytics |
| 🟢 | 13 | Syslog_Aux_CL | 0.728 | 0.014 | 1.1% | 0 | Data Lake |
| 🟢 | 14 | AuditLogs | 0.678 | 0.007 | 1.1% | 🟢 47 | Analytics |
| 🟢 | 15 | SecurityRecommendation | 0.446 | 0.005 | 0.7% | ⚠️ 0 | Analytics |
| 🟢 | 16 | AzureMetrics | 0.357 | 0.004 | 0.6% | ⚠️ 0 | Analytics |
| 🟢 | 17 | DeviceRegistryEvents | 0.347 | 0.004 | 0.5% | 🟠 1 | Analytics |
| 🟢 | 18 | CloudAppEvents | 0.326 | 0.004 | 0.5% | 🟡 7 | Analytics |
| 🟢 | 19 | LAQueryLogs | 0.31 | 0.003 | 0.5% | ⚠️ 0 | Analytics |
| 🟢 | 20 | Syslog | 0.286 | 0.004 | 0.5% | 🟢 15 | Analytics |

**Totals (all 104 tables, 90d):** 64.802 GB total, 63.389 GB billable (97.8%), 1.413 GB non-billable, 0.712 GB avg/day

🔴 ≥500 GB · 🟠 100–499 GB · 🟡 10–99 GB · 🟢 <10 GB  |  🟣 50+ rules · 🟢 10-49 · 🟡 3-9 · 🟠 1-2 · ⚠️ 0 (no detections — Analytics/Basic only)

### 2b. Tier Classification

| Tier | Table Count | BillableGB (90d) | % of Total |
|------|-------------|------------------|------------|
| Data Lake | 7 | 34.409 | 53.1% |
| Analytics | 97 | 28.980 | 46.9% |

**Data Lake tier** accounts for the majority of volume, driven by SecurityEvent_Aux_CL (23.532 GB), MicrosoftGraphActivityLogs (4.560 GB), and SecurityEvent_SPLT_CL (3.434 GB) — these are custom Data Lake tables used for split ingestion and archival.

**Analytics tier** is led by ThreatIntelIndicators (13.757 GB), AWSCloudTrail (3.191 GB), and DeviceProcessEvents (2.180 GB) — all with active detection rules justifying Analytics placement.

**Basic tier:** 3 tables (ApacheAccess_CL, Syslog_CL, SecurityEvent_CL) — not in top 20, minimal volume.

*Data gathered: 2026-02-22T10:40:21Z*

---

## 3. Deep Dives

### 3a. SecurityEvent

**By Computer:**

| Volume | Computer | Event Count | Est. GB (30d) | % |
|--------|----------|-------------|---------------|---|
| 🟢 | LAB-VD-0.contoso.com | 117,339 | 0.19 | 40.9% |
| 🟢 | LAB-DC2.contoso.com | 188,697 | 0.16 | 33.9% |
| 🟢 | LAB-UTIL.contoso.com | 21,511 | 0.03 | 6.3% |
| 🟢 | LAB-SCCM.contoso.com | 21,362 | 0.03 | 6.2% |
| 🟢 | LAB-DC1.contoso.com | 20,210 | 0.03 | 5.5% |
| 🟢 | LAB-ADMIN | 18,454 | 0.02 | 4.3% |
| 🟢 | LAB-2012R2.contoso.com | 8,823 | 0.01 | 2.9% |

ServerCount: 7

🔴 ≥20 GB · 🟠 10–19 GB · 🟡 5–9 GB · 🟢 <5 GB

🔍 **Optimization insight:** LAB-VD-0 (40.9%) and LAB-DC2 (33.9%) together produce ~75% of SecurityEvent volume. LAB-DC2 generates the highest event count (188,697 events) despite lower byte volume — domain controllers produce many small authentication events. The fleet of 7 servers generates a modest 0.42 GB/30d total, well within the DfS P2 pool of 3.5 GB/day (see §6a).

**By EventID:**

| Volume | EventID | Description | Event Count | Est. GB (30d) | % | Rules Referencing |
|--------|---------|-------------|-------------|---------------|---|---|
| 🟢 | 4663 | Object access attempt | 130,308 | 0.21 | 45.1% | 🟠 1 — HAFNIUM UM Service writing suspicious file |
| 🟢 | 4624 | Successful logon | 180,963 | 0.14 | 29.4% | 🟡 7 — Failed AzureAD logons but success logon to host; Multiple RDP connections from Single System; Rare RDP Connections; +4 more |
| 🟢 | 4799 | Security group membership enumerated | 56,524 | 0.07 | 15.7% | ⚠️ 0 rules |
| 🟢 | 4702 | Scheduled task updated | 7,632 | 0.03 | 5.8% | ⚠️ 0 rules |
| 🟢 | 4688 | New process created | 12,151 | 0.01 | 2.3% | 🟢 11 — Malware in the recycle bin; Powershell Empire cmdlets seen in command line; Process executed from binary hidden in Base64 encoded file; +8 more |
| 🟢 | 4719 | System audit policy changed | 2,435 | < 0.01 | 0.6% | ⚠️ 0 rules |
| 🟢 | 4948 | Firewall exception rule deleted | 1,494 | < 0.01 | 0.3% | ⚠️ 0 rules |
| 🟢 | 4946 | Firewall exception rule added | 1,538 | < 0.01 | 0.3% | ⚠️ 0 rules |
| 🟢 | 4625 | Failed logon | 1,449 | < 0.01 | 0.2% | 🟡 5 — Failed host logons but success logon to AzureAD; Failed logon attempts within 10 mins; Excessive Windows logon failures; +2 more |
| 🟢 | 8001 |  | 1,463 | < 0.01 | 0.2% | ⚠️ 0 rules |
| 🟢 | 8005 |  | 161 | < 0.01 | 0.1% | 🟠 1 — TI map File Hash to Security Event |
| 🟢 | 4700 | Scheduled task enabled | 58 | < 0.01 | 0.0% | ⚠️ 0 rules |
| 🟢 | 8222 |  | 42 | 0.00 | 0.0% | ⚠️ 0 rules |
| 🟢 | 5024 | Windows Firewall started | 63 | 0.00 | 0.0% | ⚠️ 0 rules |
| 🟢 | 4956 |  | 55 | 0.00 | 0.0% | ⚠️ 0 rules |
| 🟢 | 5033 |  | 54 | 0.00 | 0.0% | ⚠️ 0 rules |
| 🟢 | 4732 | Member added to local group | 6 | 0.00 | 0.0% | 🟡 4 — New user created and added to the built-in administrators group; Account added and removed from privileged groups; User account added to built in domain local or global group; +1 more |

🔴 ≥50 GB · 🟠 10–49 GB · 🟡 1–9 GB · 🟢 <1 GB  |  🟣 50+ rules · 🟢 10-49 · 🟡 3-9 · 🟠 1-2 · ⚠️ 0 rules

📋 **EventID optimization potential:**

| EventID | Optimization | Rationale |
|---------|-------------|-----------|
| 4663 | 🟡 Medium | 45.1% of volume, but referenced by 1 HAFNIUM detection rule. Consider narrowing SACL on servers to reduce object access audit noise while retaining the rule. Not filterable via DCR without breaking the rule |
| 4624 | 🟡 Medium | 29.4% of volume. Referenced by 7 rules (RDP, logon correlation). Strong split ingestion candidate — route to Data Lake for forensic retention, keep in Analytics for rule coverage |
| 4799 | 🔴 High | 15.7% of volume with 0 rules. Security group enumeration events are noisy on domain controllers. Strong candidate for DCR filter or severity-based filtering |
| 4702 | 🟡 Medium | 5.8% with 0 rules. Scheduled task update events — review if persistence detection rules (T1053) should be enabled from Content Hub |
| 4688 | 🟢 Low | 2.3% with 11 rules. Critical for process execution detection — keep as-is. Consider MDE DeviceProcessEvents as primary source if overlap exists |

### 3b. Syslog

**By Source Host:**

| Source Host | Event Count | Est. GB (30d) | % | Facilities | Severity Levels |
|-------------|-------------|---------------|---|------------|-----------------|
| LAB-LINUX | 420,942 | 0.14 | 104.1% | daemon, cron, authpriv, kern, auth, user | warning, notice, error, critical, info |

🔍 **Single host:** All Syslog data originates from one Linux server. No forwarding architecture detected.

**By Facility:**

| Badge | Facility | Event Count | Est. GB (30d) | % | Rules |
|-------|----------|-------------|---------------|---|-------|
| ⚙️ | daemon | 414,200 | 0.13 | 100.0% | ⚠️ 0 rules |
| 🔒 | auth | 20 | 0.00 | 0.0% | 🟡 4 — Multiple Password Reset by user; Failed host logons but success logon to AzureAD; Failed AzureAD logons but success logon to host; +1 more |
| 🔒 | authpriv | 2,807 | 0.00 | 0.0% | 🟠 2 — Multiple Password Reset by user; Failed logon attempts |
| ⏰ | cron | 429 | 0.00 | 0.0% | ⚠️ 0 rules |
| ⚙️ | kern | 1,029 | 0.00 | 0.0% | ⚠️ 0 rules |
| 📝 | user | 2,457 | 0.00 | 0.0% | 🟡 9 — Squid proxy events for ToR proxies; Squid proxy events related to mining pools; Failed logon attempts; +6 more |

🔒 Security-critical · ⚙️ System operational · 📡 Network/appliance · ⏰ Scheduler · 📬 Messaging · 📝 General/legacy

📋 **Facility optimization potential:**

| Facility | Current | Recommended Min | Rationale |
|----------|---------|-----------------|-----------|
| daemon | All severities | **Warning** | 97.9% systemd — remove notice-level messages. Saves ~20% of daemon volume |
| auth | All severities | **Debug** (collect all) | Security-critical — never filter |
| authpriv | All severities | **Debug** (collect all) | Security-critical (sudo, CRON) — never filter |
| cron | All severities | **Warning** | Negligible volume, but notice-level cron job execution data is low-value |
| kern | All severities | **Notice** | Keep kern.notice for kernel module loads (T1547.006) |
| user | All severities | **Warning** | mstunnel-agent dominates — keep warning+ only |

**By Facility × SeverityLevel:**

| Badge | Facility | Severity Level | Event Count | Est. GB (30d) | % |
|-------|----------|----------------|-------------|---------------|---|
| ⚙️ | daemon | 🟡 warning | 249,289 | 0.08 | 59.2% |
| ⚙️ | daemon | 🔵 notice | 81,146 | 0.03 | 20.0% |
| ⚙️ | daemon | 🟠 error | 83,762 | 0.02 | 18.8% |
| 📝 | user | ⚪ info | 2,312 | < 0.01 | 0.8% |
| 🔒 | authpriv | 🔵 notice | 1,845 | < 0.01 | 0.6% |
| 🔒 | authpriv | ⚪ info | 962 | < 0.01 | 0.2% |
| ⚙️ | kern | 🔵 notice | 884 | < 0.01 | 0.2% |
| ⏰ | cron | 🔵 notice | 429 | < 0.01 | 0.1% |
| 🔒 | auth | 🔵 notice | 17 | 0.00 | 0.0% |
| 🔒 | auth | ⚪ info | 3 | 0.00 | 0.0% |
| ⚙️ | kern | 🟡 warning | 104 | 0.00 | 0.0% |
| ⚙️ | kern | ⚪ info | 24 | 0.00 | 0.0% |
| ⚙️ | kern | 🟠 error | 17 | 0.00 | 0.0% |
| 📝 | user | 🟡 warning | 120 | 0.00 | 0.0% |
| 📝 | user | 🔵 notice | 25 | 0.00 | 0.0% |
| ⚙️ | daemon | ⚪ critical | 3 | 0.00 | 0.0% |

🔴 Critical · 🟠 Error · 🟡 Warning · 🔵 Notice · ⚪ Info · ⚫ Debug

**Top ProcessName by Facility:**

| Facility | Process Name | Event Count | Est. GB (30d) | % | Rules |
|----------|--------------|-------------|---------------|---|-------|
| daemon | systemd | 413,813 | 0.13 | 97.9% | ⚠️ 0 rules |
| authpriv | sudo | 2,291 | < 0.01 | 0.8% | 🟡 3 — Failed host logons but success logon to AzureAD; Failed AzureAD logons but success logon to host; SSH newly internet-exposed endpoints |
| user | mstunnel-agent | 2,303 | < 0.01 | 0.7% | ⚠️ 0 rules |
| kern | kernel | 1,029 | < 0.01 | 0.3% | ⚠️ 0 rules |
| authpriv | CRON | 464 | < 0.01 | 0.1% | ⚠️ 0 rules |
| cron | anacron | 429 | < 0.01 | 0.1% | ⚠️ 0 rules |
| daemon | systemd-udevd | 111 | 0.00 | 0.0% | ⚠️ 0 rules |
| daemon | dhclient | 91 | 0.00 | 0.0% | ⚠️ 0 rules |
| daemon | systemd-networkd | 64 | 0.00 | 0.0% | ⚠️ 0 rules |
| daemon | kernel | 60 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | (empty) | 60 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | gnome-shell | 42 | 0.00 | 0.0% | ⚠️ 0 rules |
| authpriv | (empty) | 24 | 0.00 | 0.0% | ⚠️ 0 rules |
| daemon | gnome-session-binary | 20 | 0.00 | 0.0% | ⚠️ 0 rules |
| daemon | systemd-resolved | 17 | 0.00 | 0.0% | ⚠️ 0 rules |
| auth | dbus-daemon | 17 | 0.00 | 0.0% | ⚠️ 0 rules |
| daemon | NetworkManager | 16 | 0.00 | 0.0% | ⚠️ 0 rules |
| authpriv | userdel | 15 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | org.gnome.Shell.desktop | 12 | 0.00 | 0.0% | ⚠️ 0 rules |
| daemon | wpa_supplicant | 8 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | gsd-sharing | 8 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | gsd-media-keys | 8 | 0.00 | 0.0% | ⚠️ 0 rules |
| authpriv | useradd | 6 | 0.00 | 0.0% | ⚠️ 0 rules |
| authpriv | usermod | 6 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | xbrlapi.desktop | 4 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | gsd-color | 4 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | KVP | 4 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | gnome-session | 3 | 0.00 | 0.0% | ⚠️ 0 rules |
| auth | systemd-logind | 3 | 0.00 | 0.0% | ⚠️ 0 rules |
| user | colord | 2 | 0.00 | 0.0% | ⚠️ 0 rules |

📋 **ProcessName analysis:** `systemd` accounts for **97.9%** of all Syslog volume (413,813 events / 0.13 GB in 30 days) with **zero detection rules**. This is the primary Syslog cost driver. Security-critical processes (`sudo`, `kernel`) are minimal volume. Setting `daemon` facility to Warning+ in the DCR would filter ~20% of daemon volume (the notice-level systemd events).

🟣 **Split ingestion candidate:** If Syslog volume were to grow, route `daemon` facility (or specifically `systemd` process) to Data Lake while keeping `auth`, `authpriv`, and `user` facilities on Analytics for detection coverage.

> ⚠️ **ASIM dependency note:** `_Im_` ASIM parser patterns detected in 4 rules (including "Possible AiTM Phishing Attempt Against Microsoft Entra ID"). ASIM Authentication parsers may consume `sshd`/`sudo` from Syslog `authpriv` — verify ASIM parser dependency before applying Syslog facility filters.

### 3c. CommonSecurityLog

**Volume:** No CommonSecurityLog data recorded in the report period.

No CSL data — no deep dive applicable. No DCR optimization needed at this time.

---

## 4. Anomaly Detection

### 4a. Per-Table Anomaly Summary (24h + WoW)

| DataType | Last 24h (GB) | 30d Avg (GB) | 24h Deviation | This Month (GB) | Last Month (GB) | MoM Change | Severity |
|----------|---------------|-------------|---------------|----------------|----------------|------------|----------|
| ThreatIntelIndicators | 0.52 | 0.24 | +116.7% | — | — | — | 🟠 |
| AzureMetrics | 0 | 0.01 | -100% | 0.19 | 0.08 | +137.5% | 🟡 |
| MicrosoftGraphActivityLogs | — | — | — | 3.58 | 0.98 | +265.3% | 🟠 |
| StorageBlobLogs | — | — | — | 0.15 | 0 | +100% | 🟡 |
| SigninLogs | — | — | — | 0.01 | 0 | +100% | 🟠 |
| DeviceFileCertificateInfo | — | — | — | 0.02 | 0.01 | +100% | 🟡 |
| Syslog_SPLT_CL | — | — | — | 0.02 | 0 | +100% | 🟡 |
| AzureActivity | — | — | — | 0.04 | 0.02 | +100% | 🟡 |
| SecurityEvent_SPLT_CL | — | — | — | 3.43 | 0 | +100% | 🟡 |
| MicrosoftServicePrincipalSignInLogs | — | — | — | 0.05 | 0 | +100% | 🟡 |
| Syslog_Aux_CL | — | — | — | 0.01 | 0.32 | -96.9% | 🟠 |
| BehaviorAnalytics | — | — | — | 0.03 | 0.14 | -78.6% | ⚪ |
| DeviceRegistryEvents | — | — | — | 0.15 | 0.1 | +50% | ⚪ |
| CloudAppEvents | — | — | — | 0.11 | 0.08 | +37.5% | ⚪ |
| SecurityEvent_Aux_CL | — | — | — | 5.32 | 7.79 | -31.7% | ⚪ |
| AADNonInteractiveUserSignInLogs | — | — | — | 0.8 | 0.61 | +31.1% | ⚪ |
| SecurityRecommendation | — | — | — | 0.13 | 0.18 | -27.8% | ⚪ |
| Syslog | — | — | — | 0.08 | 0.11 | -27.3% | ⚪ |
| DeviceFileEvents | — | — | — | 0.42 | 0.33 | +27.3% | ⚪ |
| DeviceImageLoadEvents | — | — | — | 0.05 | 0.04 | +25% | ⚪ |
| AppTraces | — | — | — | 0.03 | 0.04 | -25% | ⚪ |

**Narrative highlights:**

- 🟠 **ThreatIntelIndicators** (+116.7% 24h): Significant spike in the last 24 hours relative to 30-day weekday average. With 33 active rules, this triggers the high-rule-count anomaly override. Likely a TI feed refresh or indicator expansion — verify the threat intelligence data connector for unexpected volume or provider changes.
- 🟠 **MicrosoftGraphActivityLogs** (+265.3% MoM): Substantial month-over-month increase (0.98 → 3.58 GB). Already on Data Lake tier, so no cost concern at Analytics rates. Investigate whether new Graph API integrations or MCP server usage increased activity.
- 🟠 **Syslog_Aux_CL** (−96.9% MoM): Near-complete signal loss (0.32 → 0.01 GB). Combined with **SecurityEvent_SPLT_CL** (+100%, new table at 3.43 GB) and **Syslog_SPLT_CL** (+100%, new), this pattern indicates a **split ingestion reconfiguration** occurred — data previously routed to `_Aux_CL` tables is now flowing to `_SPLT_CL` tables. Verify the DCR transformation was intentional.
- 🟡 **New tables appearing:** StorageBlobLogs, SigninLogs, MicrosoftServicePrincipalSignInLogs, and the `_SPLT_CL` tables all show +100% MoM (from 0 → data). These indicate new connectors or collection scope expansion this month.

### 4b. Daily Trend (90 Days)

```
Daily Ingestion — la-contoso-sentinel (2025-11-24 to 2026-02-22)
Date          GB     Trend (max = 1.27 GB)
─────────────────────────────────────────────────────────────────
2025-11-24 │  0.495  ███████████████████
2025-11-25 │  0.793  ███████████████████████████████
2025-11-26 │  0.841  █████████████████████████████████
2025-11-27 │  0.933  █████████████████████████████████████
2025-11-28 │  0.831  █████████████████████████████████
2025-11-29 │  0.442  █████████████████
2025-11-30 │  0.403  ████████████████
2025-12-01 │  0.788  ███████████████████████████████
2025-12-02 │  0.778  ███████████████████████████████
2025-12-03 │  0.799  ███████████████████████████████
2025-12-04 │  0.745  █████████████████████████████
2025-12-05 │  0.837  █████████████████████████████████
2025-12-06 │  0.434  █████████████████
2025-12-07 │  0.672  ██████████████████████████
2025-12-08 │  1.045  █████████████████████████████████████████
2025-12-09 │  0.883  ███████████████████████████████████
2025-12-10 │  0.958  ██████████████████████████████████████
2025-12-11 │  0.822  ████████████████████████████████
2025-12-12 │  0.813  ████████████████████████████████
2025-12-13 │  0.451  ██████████████████
2025-12-14 │  0.381  ███████████████
2025-12-15 │  0.896  ███████████████████████████████████
2025-12-16 │  0.784  ███████████████████████████████
2025-12-17 │  0.748  █████████████████████████████
2025-12-18 │  0.760  ██████████████████████████████
2025-12-19 │  0.747  █████████████████████████████
2025-12-20 │  0.389  ███████████████
2025-12-21 │  0.392  ███████████████
2025-12-22 │  0.816  ████████████████████████████████
2025-12-23 │  0.751  ██████████████████████████████
2025-12-24 │  0.764  ██████████████████████████████
2025-12-25 │  0.711  ████████████████████████████
2025-12-26 │  0.719  ████████████████████████████
2025-12-27 │  0.351  ██████████████
2025-12-28 │  0.346  ██████████████
2025-12-29 │  0.775  ███████████████████████████████
2025-12-30 │  0.708  ████████████████████████████
2025-12-31 │  0.584  ███████████████████████
2026-01-01 │  0.596  ███████████████████████
2026-01-02 │  0.593  ███████████████████████
2026-01-03 │  0.307  ████████████ ← min
2026-01-04 │  0.410  ████████████████
2026-01-05 │  0.723  ████████████████████████████
2026-01-06 │  0.717  ████████████████████████████
2026-01-07 │  0.696  ███████████████████████████
2026-01-08 │  0.652  ██████████████████████████
2026-01-09 │  0.854  ██████████████████████████████████
2026-01-10 │  0.392  ███████████████
2026-01-11 │  0.417  ████████████████
2026-01-12 │  0.777  ███████████████████████████████
2026-01-13 │  0.912  ████████████████████████████████████
2026-01-14 │  0.904  ████████████████████████████████████
2026-01-15 │  0.639  █████████████████████████
2026-01-16 │  0.706  ████████████████████████████
2026-01-17 │  0.527  █████████████████████
2026-01-18 │  0.661  ██████████████████████████
2026-01-19 │  0.908  ████████████████████████████████████
2026-01-20 │  0.837  █████████████████████████████████
2026-01-21 │  0.749  █████████████████████████████
2026-01-22 │  0.695  ███████████████████████████
2026-01-23 │  0.773  ██████████████████████████████
2026-01-24 │  0.487  ███████████████████
2026-01-25 │  0.517  ████████████████████
2026-01-26 │  1.054  █████████████████████████████████████████
2026-01-27 │  0.753  ██████████████████████████████
2026-01-28 │  0.865  ██████████████████████████████████
2026-01-29 │  0.830  █████████████████████████████████
2026-01-30 │  0.851  ██████████████████████████████████
2026-01-31 │  0.477  ███████████████████
2026-02-01 │  0.467  ██████████████████
2026-02-02 │  0.928  █████████████████████████████████████
2026-02-03 │  0.728  █████████████████████████████
2026-02-04 │  0.711  ████████████████████████████
2026-02-05 │  0.735  █████████████████████████████
2026-02-06 │  0.708  ████████████████████████████
2026-02-07 │  0.507  ████████████████████
2026-02-08 │  0.543  █████████████████████
2026-02-09 │  0.873  ██████████████████████████████████
2026-02-10 │  0.906  ████████████████████████████████████
2026-02-11 │  1.037  █████████████████████████████████████████
2026-02-12 │  0.801  ████████████████████████████████
2026-02-13 │  1.270  ██████████████████████████████████████████████████ ← peak
2026-02-14 │  0.574  ███████████████████████
2026-02-15 │  0.527  █████████████████████
2026-02-16 │  1.041  █████████████████████████████████████████
2026-02-17 │  0.766  ██████████████████████████████
2026-02-18 │  0.994  ███████████████████████████████████████
2026-02-19 │  0.835  █████████████████████████████████
2026-02-20 │  0.959  ██████████████████████████████████████
2026-02-21 │  0.534  █████████████████████
2026-02-22 │  0.694  ███████████████████████████ ← partial
─────────────────────────────────────────────────────────────────
Avg: 0.712 GB/day  Peak: 1.270 GB (2026-02-13)  Min: 0.307 GB (2026-01-03)
Weekday Avgs: Mon 0.86 | Tue 0.79 | Wed 0.82 | Thu 0.75 | Fri 0.82 | Sat 0.45 | Sun 0.48
```

**Pattern description:** The workspace exhibits a pronounced weekday/weekend cycle. Monday is the highest-volume weekday (0.86 GB avg), driven by accumulated weekend activity processing. Saturdays and Sundays consistently drop to ~0.45–0.48 GB (~45% reduction). The peak day of 1.270 GB on 2026-02-13 (Friday) appears to be an outlier driven by the ThreatIntelIndicators spike and MicrosoftGraphActivityLogs growth seen in §4a. The minimum of 0.307 GB on 2026-01-03 (Saturday) reflects a holiday weekend trough. No sustained upward or downward growth trend across the 90-day window — the pattern is cyclically stable.

---

## 5. Detection Coverage

### 5a. Rule Inventory & Table Cross-Reference

| Metric | Count |
|--------|-------|
| Total Scheduled/NRT rules (AR) | 284 |
| Enabled AR | 225 (223 Scheduled, 2 NRT) |
| Disabled AR | 59 |
| Total Custom Detection rules (CD) | 9 |
| Enabled CD | 8 |
| Disabled CD | 1 |
| **Combined enabled rules** | **233** |

**Table-to-Rule Cross-Reference:**

| Coverage | Table | AR Rules | CD Rules | Total | Key Rule Names |
|----------|-------|----------|----------|-------|----------------|
| 🟢 | AuditLogs | 47 | 0 | 47 | Multiple Password Reset by user; Rare application consent; Suspicious application consent similar to O365 Attack Toolkit; +44 more |
| 🟢 | SecurityEvent | 41 | 0 | 41 | Multiple Password Reset by user; Failed host logons but success logon to AzureAD; Failed AzureAD logons but success logon to host; +38 more |
| 🟢 | ThreatIntelIndicators | 32 | 1 | 33 | TI map IP entity to AWSCloudTrail; TI map URL entity to Cloud App Events; TI Map IP Entity to W3CIISLog; +30 more |
| 🟢 | SigninLogs | 32 | 0 | 32 | Multiple Password Reset by user; Failed host logons but success logon to AzureAD; Failed AzureAD logons but success logon to host; +29 more |
| 🟢 | Syslog | 15 | 0 | 15 | Multiple Password Reset by user; Failed host logons but success logon to AzureAD; Failed AzureAD logons but success logon to host; +12 more |
| 🟢 | AWSCloudTrail | 14 | 0 | 14 | MFA disabled for a user; Known IRIDIUM IP; New UserAgent observed in last 24 hours; +11 more |
| 🟢 | AzureDiagnostics | 14 | 0 | 14 | Azure Key Vault access TimeSeries anomaly; Known GALLIUM domains and hashes; Known IRIDIUM IP; +11 more |
| 🟢 | W3CIISLog | 12 | 0 | 12 | High count of failed attempts from same client IP; High count of failed logons by a user; Malicious web application requests linked with MDATP alerts; +9 more |
| 🟢 | Perf | 11 | 0 | 11 | Powershell Empire Cmdlets Executed in Command Line; TI Map IP Entity to SigninLogs; TI Map IP Entity to AzureActivity; +8 more |
| 🟢 | DeviceProcessEvents | 8 | 2 | 10 | Security Service Registry ACL Modification; Email access via active sync; Known ZINC Comebacker and Klackring malware hashes; +7 more |
| 🟡 | DeviceNetworkEvents | 7 | 0 | 7 | Solorigate Network Beacon; Known ZINC Comebacker and Klackring malware hashes; NOBELIUM - Domain and IP IOCs - March 2021; +4 more |
| 🟡 | CloudAppEvents | 4 | 3 | 7 | TI map URL entity to Cloud App Events; TI map IP entity to Cloud App Events; TI map Domain entity to Cloud App Events; +4 more |
| 🟡 | IdentityInfo | 7 | 0 | 7 | Authentication Methods Changed for Privileged Account; MFA Rejected by User; Addition of a Temporary Access Pass to a Privileged Account; +4 more |
| 🟡 | DeviceFileEvents | 5 | 1 | 6 | Known ZINC Comebacker and Klackring malware hashes; SUNBURST and SUPERNOVA backdoor hashes; HAFNIUM UM Service writing suspicious file; +3 more |
| 🟡 | AADNonInteractiveUserSignInLogs | 5 | 0 | 5 | Malformed user agent; User agent search for log4j exploitation attempt; External guest invitation followed by Azure AD PowerShell signin; +2 more |
| 🟡 | EmailEvents | 4 | 0 | 4 | TI map Domain entity to EmailEvents; TI map Domain entity to EmailUrlInfo; TI map Email entity to EmailEvents; +1 more |
| 🟡 | Anomalies | 4 | 0 | 4 | Process execution frequency anomaly; Azure Key Vault access TimeSeries anomaly; Exchange workflow MailItemsAccessed operation anomaly; +1 more |
| 🟡 | DeviceEvents | 3 | 0 | 3 | TEARDROP memory-only dropper; SUNSPOT malware hashes; SOURGUM Actor IOC - July 2021 |
| 🟠 | EmailUrlInfo | 2 | 0 | 2 | TI map Domain entity to EmailUrlInfo; TI Map URL Entity to EmailUrlInfo |
| 🟠 | BehaviorAnalytics | 2 | 0 | 2 | Azure VM Run Command operation executed during suspicious login window; MFA Rejected by User |
| 🟠 | AADServicePrincipalSignInLogs | 2 | 0 | 2 | Suspicious Service Principal creation activity; Service Principal Authentication Attempt from New Country |
| 🟠 | UrlClickEvents | 1 | 1 | 2 | TI Map URL Entity to UrlClickEvents; Threat Intelligence Match on URL from URLClick Events |
| 🟠 | DeviceInfo | 1 | 1 | 2 | Solorigate Defender Detections; Defender for Endpoint Unhealthy |
| 🟠 | DeviceRegistryEvents | 1 | 0 | 1 | SOURGUM Actor IOC - July 2021 |
| 🟠 | DeviceImageLoadEvents | 1 | 0 | 1 | SUNSPOT malware hashes |
| 🟠 | AuxCommonSecLogTI_CL | 1 | 0 | 1 | Threat intelligence indicators matched from summarized Fortinet firewall Logs |
| 🟠 | StorageBlobLogs | 1 | 0 | 1 | Linked Malicious Storage Artifacts |
| 🟠 | Watchlist | 1 | 0 | 1 | (Preview) Insider Risk - High User Security Incidents Correlation |

**ASIM Parser Dependencies:** 6 rules use ASIM parser abstraction patterns — `_Im_` patterns appear in 4 rules (User agent search for log4j exploitation attempt; Possible AiTM Phishing Attempt Against Microsoft Entra ID; Potential beaconing activity; TI map Domain entity to Dns Events) and `imFileEvent` patterns in 2 rules (HAFNIUM UM Service writing suspicious file; Dev-0228 File Path Hashes). These rules may query additional tables beyond those captured in the cross-reference above, as ASIM parsers resolve table references dynamically at query execution time.

### 5b. Rule Health & Alerts

**Cross-validation:** SentinelHealth tracks 218 distinct rules vs 225 enabled ARs from REST API inventory — a gap of **3.1%** (7 rules). This is within normal tolerance and may reflect recently deployed rules that haven't executed yet or rules configured with very long intervals.

#### Alert-Producing Rules (90d)
| Volume | Rule Name | Alert Count | Severity | Product Component |
|--------|-----------|-------------|----------|-------------------|
| 📊 | TI Map IP Entity to DeviceNetworkEvents | 43 | 🟠 Medium | Scheduled Alerts |
| 📊 | TI Map IP Entity to W3CIISLog | 34 | 🟠 Medium | Scheduled Alerts |
| 📊 | Changes to Application Ownership | 27 | 🟠 Medium | Scheduled Alerts |
| 📊 | Privileged User Logon from new ASN | 13 | 🟠 Medium | Scheduled Alerts |
| 📊 | Rare and potentially high-risk Office operations | 12 | 🟡 Low | Scheduled Alerts |
| 📊 | Excessive failed login attempts to an IIS Web Server from unknown IP Addresses | 12 | 🔴 High | Scheduled Alerts |
| 💤 | Rare RDP Connections | 7 | 🟠 Medium | Scheduled Alerts |
| 💤 | RDP Nesting | 6 | 🟠 Medium | Scheduled Alerts |
| 💤 | New UserAgent observed in last 24 hours | 6 | 🟡 Low | Scheduled Alerts |
| 💤 | Anomalous User Agent connection attempt | 5 | 🟡 Low | Scheduled Alerts |
| 💤 | Authentications of Privileged Accounts Outside of Expected Controls | 5 | 🟠 Medium | Scheduled Alerts |
| 💤 | Excessive Windows logon failures | 4 | 🟡 Low | Scheduled Alerts |
| 💤 | Azure Portal sign in by user1@contoso.com from another Azure Tenant with IP Address 198.51.100.10 | 4 | 🟠 Medium | Scheduled Alerts |
| 💤 | Azure Portal sign in by user2@contoso.com from another Azure Tenant with IP Address 198.51.100.20 | 3 | 🟠 Medium | Scheduled Alerts |
| 💤 | Azure Diagnostic settings removed from a resource | 2 | 🟠 Medium | Scheduled Alerts |
| 💤 | Conditional Access Policy Modified by New User | 2 | 🟠 Medium | Scheduled Alerts |
| 💤 | Failed logon attempts within 10 mins | 2 | 🟡 Low | Scheduled Alerts |
| 💤 | Service Principal Assigned App Role With Sensitive Access | 1 | 🟠 Medium | Scheduled Alerts |
| 💤 | Azure Portal sign in by user3@contoso.com from another Azure Tenant with IP Address 198.51.100.20 | 1 | 🟠 Medium | Scheduled Alerts |
| 💤 | Device Code Authentication Flow Detected | 1 | 🟠 Medium | Scheduled Alerts |
| 💤 | Successful logon from IP and failure from a different IP | 1 | 🟠 Medium | Scheduled Alerts |

Total: 191 alerts from 21 rules

SentinelHealth tracked **218 distinct rules** across **209,896 executions** with an overall success rate of **99.9%** (156 total failures). 4 rules experienced failures during the period — details below. NRT rules execute approximately 10,080 times per 30-day deep-dive window (~once per minute), which explains the higher failure counts on NRT rules despite a low failure rate.

#### Failing Rules
| Rule Name | Kind | Failures | Last Failure | Status |
|-----------|------|----------|--------------|--------|
| NRT First access credential added to Application or Service Principal where no credential was present | NRT | 84 | 02/22/2026 | 🟠 Failing |
| NRT New access credential added to Application or Service Principal | NRT | 70 | 02/18/2026 | 🟠 Failing |
| Possible AiTM Phishing Attempt Against Microsoft Entra ID | Scheduled | 1 | 02/10/2026 | 🟠 Failing |
| HoneyTokens: KeyVault HoneyToken diagnostic settings deleted or changed | Scheduled | 1 | 01/26/2026 | 🟠 Failing |

**Remediation notes:**
- The two **NRT rules** (credential monitoring) have the highest failure counts (84 + 70 = 154 combined). NRT rules execute once per minute, so even a low failure rate accumulates. Investigate whether these rules hit query timeouts or encounter schema issues. If the failures are due to query complexity, consider converting them to Scheduled rules with 5-minute intervals.
- **"Possible AiTM Phishing Attempt"** uses ASIM `_Im_` parser patterns — the single failure may be related to parser resolution. Verify that ASIM workspace parsers are deployed and current.
- **"HoneyTokens: KeyVault HoneyToken"** had a single failure on 01/26 — likely a transient issue. Monitor for recurrence.

---

## 6. License Benefit Analysis

| Category | Avg Daily (GB) | Est. 90-Day (GB) | License Required |
|----------|---------------|-------------------|------------------|
| DfS P2-Eligible | 0.014 | 1.296 | Defender for Servers P2 |
| E5-Eligible | 0.097 | 8.802 | M365 E5 / E5 Security |
| **Remaining (truly billable)** | **0.602** | **54.812** | **Paid ingestion** |

### 6a. Defender for Servers P2 Pool Detail

Pool calculation: 7 servers × 500 MB/day = 3.500 GB/day ([benefit details](https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-ingestion-benefit))

| Metric | Value |
|--------|-------|
| Eligible Table | SecurityEvent |
| Detected Server Count | 7 |
| Pool Size (500 MB/server/day) | 7 × 500 MB = **3.500 GB/day** |
| Actual Eligible Daily Ingestion | **0.014 GB/day** |
| Pool Utilization | **0.4%** |
| 90-Day DfS P2 Deduction | **1.296 GB** |

**Scenario: Pool far exceeds usage.** If DfS P2 is enabled, the pool of 3.500 GB/day far exceeds actual eligible ingestion of 0.014 GB/day — significant headroom exists. Consider increasing SecurityEvent logging levels (e.g., collecting "All Events" instead of "Common" or "Minimal" via the Windows Security Events data connector) to broaden detection coverage at no additional ingestion cost. Note: increased retention volume may affect long-term storage costs depending on workspace retention settings.

### 6b. E5 / Defender XDR Pool Detail

Pool calculation: E5 data grant = (number of E5 licenses) × 5 MB/day ([offer details](https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer))

> **Note:** Ask the user for E5 license count — this is not discoverable from Sentinel telemetry alone. If M365 E5 / E5 Security licenses are active, the data grant covers up to the pool limit. Overage above the grant is billed at standard rates. The grant appears as `Free Benefit - M365 Defender Data Ingestion` on the bill.

| Table | Volume (90d GB) | Tier |
|-------|----------------|------|
| DeviceProcessEvents | 2.180 | Analytics |
| AADNonInteractiveUserSignInLogs | 2.126 | Data Lake |
| DeviceFileEvents | 1.073 | Analytics |
| DeviceEvents | 1.019 | Analytics |
| AuditLogs | 0.678 | Analytics |
| DeviceRegistryEvents | 0.347 | Analytics |
| CloudAppEvents | 0.326 | Analytics |
| DeviceNetworkEvents | 0.265 | Analytics |
| AADServicePrincipalSignInLogs | 0.254 | Analytics |
| DeviceImageLoadEvents | 0.123 | Analytics |
| DeviceNetworkInfo | 0.057 | Analytics |
| DeviceFileCertificateInfo | 0.041 | Analytics |
| DeviceLogonEvents | 0.033 | Analytics |
| AADManagedIdentitySignInLogs | 0.021 | Analytics |
| IdentityQueryEvents | 0.018 | Analytics |
| SigninLogs | 0.014 | Analytics |
| EmailUrlInfo | 0.009 | Analytics |
| DeviceInfo | 0.005 | Analytics |
| AlertEvidence | 0.004 | Analytics |
| IdentityLogonEvents | 0.002 | Analytics |
| EmailEvents | 0.001 | Analytics |
| **Total (21 tables)** | **8.596** | |

**Break-even:** 0.097 GB/day (99.1 MB/day) — requires **20 E5 licenses** to fully cover (at 5 MB/license/day)

*Per-table sum (8.596 GB) differs from aggregate (8.802 GB) due to rounding in daily averaging.*

---

## 7. Optimization Recommendations

### 7a. Data Lake Migration Candidates

🔴 DL candidate (zero rules, eligible) · 🟠 Not eligible/unknown · 🟢 Keep Analytics (has rules) · 🟣 Split candidate · ❗ Detection gap — XDR (CD-convertible) or non-XDR (must move back/disable) · 🔵 Already on DL · 📕 KQL Job output

#### Sub-table 1: 🔴 DL Migration Candidates

| DataType | 30d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |
|----------|-------|----------|----------|-------------|------|-------------|----------|
| MDfEVulnerabilitiesList_CL | 🟢 0.06 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| LAQueryLogs | 🟢 0.04 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| DeviceNetworkInfo | 🟢 0.02 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| DeviceFileCertificateInfo | 🟢 0.02 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |

These 4 tables have zero detection rules and are confirmed DL-eligible. Combined volume is small (~0.14 GB/30d), but migration aligns tier with usage pattern. Evaluate DCR filtering for any unnecessary data before migrating — see [Manage data tiers](https://learn.microsoft.com/azure/sentinel/manage-data-overview).

> 💡 Before migrating, review the [SOC Optimization dashboard](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-access?tabs=defender-portal) in the Defender portal — it may recommend Content Hub rule templates for these tables, which would convert them from migration candidates into detection sources.

#### Sub-table 2: 🟠 Zero-Rule Tables — Not Eligible or Unknown

| DataType | 30d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |
|----------|-------|----------|----------|-------------|------|-------------|----------|
| AppDependencies | 🟢 0.29 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| AzureMetrics | 🟢 0.19 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| SecurityRecommendation | 🟢 0.13 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| AppPerformanceCounters | 🟢 0.06 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| MicrosoftServicePrincipalSignInLogs | 🟢 0.05 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| AppMetrics | 🟢 0.04 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| AppTraces | 🟢 0.03 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |

These tables are not DL-eligible. Consider [DCR filtering](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations) to reduce volume, or evaluate whether the data belongs in this Sentinel workspace (see §7c for non-security telemetry routing).

#### Sub-table 3: 🟢 Tables with Rules — Keep on Analytics

| DataType | 30d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |
|----------|-------|----------|----------|-------------|------|-------------|----------|
| ThreatIntelIndicators | 🟠 4.27 | 32 | 1 | 🟢 33 | Analytics | ❌ No | 🟢 Keep (33 rules) |
| AWSCloudTrail | 🟡 1.00 | 14 | 0 | 🟢 14 | Analytics | ✅ Yes | 🟢 Keep (14 rules) |
| AADNonInteractiveUserSignInLogs | 🟡 0.80 | 5 | 0 | 🟡 5 | Data Lake | ✅ Yes | 🔴 Detection gap (non-XDR) |
| DeviceProcessEvents | 🟡 0.72 | 8 | 2 | 🟢 10 | Analytics | ✅ Yes | 🟢 Keep (10 rules) |
| SecurityEvent | 🟡 0.42 | 41 | 0 | 🟢 41 | Analytics | ✅ Yes | 🟢 Keep (41 rules) |
| DeviceFileEvents | 🟡 0.42 | 5 | 1 | 🟡 6 | Analytics | ✅ Yes | 🟢 Keep (6 rules) |
| DeviceEvents | 🟡 0.36 | 3 | 0 | 🟡 3 | Analytics | ✅ Yes | 🟢 Keep (3 rules) |
| AzureDiagnostics | 🟡 0.31 | 14 | 0 | 🟢 14 | Analytics | ✅ Yes | 🟢 Keep (14 rules) |
| AuditLogs | 🟢 0.23 | 47 | 0 | 🟢 47 | Analytics | ✅ Yes | 🟢 Keep (47 rules) |
| StorageBlobLogs | 🟢 0.15 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| DeviceRegistryEvents | 🟢 0.15 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| CloudAppEvents | 🟢 0.11 | 4 | 3 | 🟡 7 | Analytics | ✅ Yes | 🟢 Keep (7 rules) |
| DeviceNetworkEvents | 🟢 0.10 | 7 | 0 | 🟡 7 | Analytics | ✅ Yes | 🟢 Keep (7 rules) |
| AADServicePrincipalSignInLogs | 🟢 0.09 | 2 | 0 | 🟠 2 | Analytics | ✅ Yes | 🟢 Keep (2 rules) |
| Syslog | 🟢 0.08 | 15 | 0 | 🟢 15 | Analytics | ✅ Yes | 🟢 Keep (15 rules) |
| DeviceImageLoadEvents | 🟢 0.05 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| BehaviorAnalytics | 🟢 0.03 | 2 | 0 | 🟠 2 | Analytics | ❓ Unknown | 🟢 Keep (2 rules) |

> ❗ **Detection gap — AADNonInteractiveUserSignInLogs:** This table is on **Data Lake tier** with **5 active analytic rules** — these rules are silently failing because analytic rules cannot execute against Data Lake tables. This is a **non-XDR table**, so Custom Detections will also NOT work (non-XDR tables are invisible to Advanced Hunting on Data Lake). **Remediation options:** (1) Move AADNonInteractiveUserSignInLogs back to Analytics tier, or (2) remove/disable the 5 rules referencing this table if the detection is no longer needed (accepting the gap). See [Manage data tiers](https://learn.microsoft.com/azure/sentinel/manage-data-overview).

> ⚠️ **Execution issues — AuditLogs:** 2 NRT rules targeting AuditLogs ("NRT First access credential added..." and "NRT New access credential added...") have persistent failures — see §5b for details and remediation.

#### Sub-table 4: 🔵 Already on Data Lake

| DataType | 30d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |
|----------|-------|----------|----------|-------------|------|-------------|----------|
| SecurityEvent_Aux_CL | 🟠 5.32 | 0 | 0 |  0 | Data Lake | ✅ Yes | 🔵 Already DL |
| MicrosoftGraphActivityLogs | 🟠 3.58 | 0 | 0 |  0 | Data Lake | ✅ Yes | 🔵 Already DL |
| SecurityEvent_SPLT_CL | 🟠 3.43 | 0 | 0 |  0 | Data Lake | ✅ Yes | 🔵 Already DL |
| Syslog_SPLT_CL | 🟢 0.02 | 0 | 0 |  0 | Data Lake | ✅ Yes | 🔵 Already DL |

These tables are already on Data Lake tier with zero rules — no changes recommended. SecurityEvent_Aux_CL and SecurityEvent_SPLT_CL serve as archival/split destinations for SecurityEvent data.

### 7b. ⚡ Quick Wins

- 🔴 **Detection gap remediation — AADNonInteractiveUserSignInLogs:** 5 analytic rules are silently failing because the table is on Data Lake tier. This is a non-XDR table, so Custom Detections also cannot access it. **Options:** (1) Move the table back to Analytics tier to restore rule execution, or (2) remove/disable the 5 rules referencing the table if non-interactive sign-in detection is no longer required. See [Manage data tiers](https://learn.microsoft.com/azure/sentinel/manage-data-overview).

- 🟠 **NRT rule remediation:** The 2 NRT credential-monitoring rules have **154 combined failures** this period. Investigate query timeouts or schema mismatches. If failures persist, consider converting to Scheduled rules with 5-minute intervals — this provides near-real-time detection while reducing execution frequency from ~1,440/day to ~288/day, lowering the failure surface.

- 🟠 **Data Lake migration:** 4 zero-rule DL-eligible tables (LAQueryLogs, DeviceNetworkInfo, DeviceFileCertificateInfo, MDfEVulnerabilitiesList_CL) on Analytics tier can be moved to Data Lake at reduced cost with no detection impact. Before migrating, review the [SOC Optimization dashboard](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-access?tabs=defender-portal) for any recommended Content Hub rule templates for these tables. See [Manage data tiers](https://learn.microsoft.com/azure/sentinel/manage-data-overview).

- 🟠 **SecurityEvent DfS P2 headroom:** Pool utilization is only 0.4% (0.014 GB/day actual vs 3.500 GB/day pool). If DfS P2 is enabled, consider increasing SecurityEvent collection to "All Events" to improve detection coverage at no additional ingestion cost.

### 7c. 🔧 Medium-Term Optimizations

- **Failing rule remediation:** The 2 NRT credential rules ("NRT First access credential added..." and "NRT New access credential added...") show persistent failures (84 and 70 respectively). Investigate query complexity and consider: (a) adding `take` limits or narrower datetime filters to reduce query scope, (b) converting to Scheduled rules with 5-minute intervals if near-real-time execution is not critical. For the "Possible AiTM Phishing Attempt" rule, verify that ASIM workspace parsers are deployed and current. See [ASIM parsers list](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list).

- **Non-security telemetry routing:** AppDependencies (0.836 GB/90d), AzureMetrics (0.357 GB), AppPerformanceCounters, AppMetrics, and AppTraces together contribute ~1.3 GB to billable ingestion with zero detection rules. Evaluate whether this Application Insights and performance telemetry belongs in the Sentinel workspace — routing to a dedicated Application Insights or Log Analytics workspace would remove unnecessary Sentinel billing.

- **Security-relevant zero-rule tables:** MicrosoftServicePrincipalSignInLogs (0.05 GB/30d) is ingesting with zero detection rules. Consider activating Content Hub rule templates for service principal sign-in monitoring — this table carries security telemetry (SPN authentication anomalies, geographic anomalies) that should have detection coverage.

- **SecurityEvent EventID filtering:** EventID 4799 (security group enumeration) consumes 15.7% of SecurityEvent volume with zero detection rules. Consider a DCR transformation to drop or route this EventID to Data Lake. EventID 4624 (successful logon, 29.4%) is referenced by 7 rules, but the specific rules may filter on a narrow subset of logon types — a DCR split routing common Type 3/5/7 logons to Data Lake while keeping Type 2/10/11 on Analytics could reduce volume while preserving detection. See [DCR transformations](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations).

- **Syslog daemon optimization:** `systemd` accounts for 97.9% of daemon facility volume (0.13 GB/30d) with zero rules. Setting daemon minimum severity to Warning+ in the DCR would filter ~20% of daemon events (notice-level messages). Given total Syslog volume is small (0.286 GB/90d), the savings are modest but the configuration is straightforward.

- **Unknown DL eligibility — BehaviorAnalytics:** This table is classified as `❓ Unknown` for DL eligibility. It has 2 active rules, so it remains on Analytics regardless, but check [Manage data tiers](https://learn.microsoft.com/azure/sentinel/manage-data-overview) for current eligibility status.

### 7d. 🔄 Ongoing Maintenance

- **Weekly anomaly monitoring:** Review ingestion anomalies (§4a) weekly. Prioritize investigation when high-rule-count tables (ThreatIntelIndicators with 33 rules, SecurityEvent with 41 rules) show significant drops — a sudden decline signals potential connector failures causing detection blind spots.

- **Automated ingestion anomaly alerting:** Create a scheduled analytic rule on the `Usage` table to detect >100% daily deviations for high-rule-count tables. This automates the weekly monitoring cadence and provides near-real-time alerting when a critical data source stops flowing. Example pattern:
  ```kql
  Usage
  | where TimeGenerated > ago(1d)
  | summarize TodayMB = sum(Quantity) by DataType
  | join kind=inner (
      Usage
      | where TimeGenerated between (ago(8d) .. ago(1d))
      | summarize AvgMB = avg(Quantity) by DataType
  ) on DataType
  | where TodayMB < AvgMB * 0.5 or TodayMB > AvgMB * 3
  ```

- **Rule health monitoring:** Check SentinelHealth weekly for failing rules. The 2 NRT credential rules should be tracked until resolved or converted. Persistent NRT failures (>20 failures/week) should be escalated.

- **Quarterly tier review:** Re-run this ingestion report quarterly to catch new zero-rule tables, verify tier assignments, and update license benefit analysis. Monitor the `_SPLT_CL` tables (SecurityEvent_SPLT_CL, Syslog_SPLT_CL) now appearing in the workspace — these are new split ingestion destinations that should stabilize in volume.

- **License benefit utilization monitoring:** Track DfS P2 and E5 benefit utilization via [Azure Cost Analysis](https://learn.microsoft.com/azure/azure-monitor/fundamentals/cost-usage#view-data-allocation-benefits). Verify that `Free Benefit - M365 Defender Data Ingestion` and `Free Benefit - Defender for Servers` line items appear on the bill if licenses are active.

- **SOC Optimization review cadence:** Review the [SOC Optimization dashboard](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-access?tabs=defender-portal) monthly for new data value and threat-based coverage recommendations. As Content Hub grows, previously zero-rule tables may gain detection templates.

---

## 8. Appendix

### 8a. Query Reference

*Data gathered: 2026-02-22T10:40:21Z | 23 queries executed*

| Phase | Query ID | File | Description |
|-------|----------|------|-------------|
| 1 | Q1 | phase1/Q1-UsageByDataType.yaml | Usage by DataType |
| 1 | Q2 | phase1/Q2-DailyIngestionTrend.yaml | Daily ingestion trend |
| 1 | Q3 | phase1/Q3-WorkspaceSummary.yaml | Workspace aggregate metrics |
| 2 | Q4 | phase2/Q4-SecurityEventByComputer.yaml | SecurityEvent by Computer |
| 2 | Q5 | phase2/Q5-SecurityEventByEventID.yaml | SecurityEvent by EventID |
| 2 | Q6a | phase2/Q6a-SyslogByHost.yaml | Syslog by source host |
| 2 | Q6b | phase2/Q6b-SyslogByFacilitySeverity.yaml | Syslog by Facility×Severity |
| 2 | Q6c | phase2/Q6c-SyslogByProcess.yaml | Syslog by ProcessName |
| 2 | Q7 | phase2/Q7-CSLByVendor.yaml | CommonSecurityLog by vendor |
| 2 | Q8 | phase2/Q8-CSLByActivity.yaml | CommonSecurityLog by activity |
| 3 | Q9 | phase3/Q9-AnalyticRuleInventory.yaml | AR inventory (REST API) |
| 3 | Q9b | phase3/Q9b-CustomDetectionRules.yaml | CD inventory (Graph API) |
| 3 | Q10 | phase3/Q10-TableTierClassification.yaml | Table tier (Azure CLI) |
| 3 | Q10b | phase3/Q10b-TierSummary.yaml | Per-tier volume summary |
| 4 | Q11 | phase4/Q11-RuleHealthSummary.yaml | SentinelHealth overview |
| 4 | Q11d | phase4/Q11d-FailingRuleDetail.yaml | Failing rule details |
| 4 | Q12 | phase4/Q12-SecurityAlertFiring.yaml | Alert-producing rules |
| 4 | Q13 | phase4/Q13-AllTablesWithData.yaml | Active tables (for CrossRef) |
| 5 | Q14 | phase5/Q14-IngestionAnomaly24h.yaml | 24h anomaly detection |
| 5 | Q15 | phase5/Q15-WeekOverWeek.yaml | Week-over-week changes |
| 5 | Q16 | phase5/Q16-MigrationCandidates.yaml | Migration candidate volumes |
| 5 | Q17 | phase5/Q17-LicenseBenefitAnalysis.yaml | License benefit analysis |
| 5 | Q17b | phase5/Q17b-E5PerTableBreakdown.yaml | E5 per-table breakdown |

Plus non-KQL operations: REST API (Q9 — Sentinel analytic rule inventory), Graph API (Q9b — Custom Detection rules via `Invoke-MgGraphRequest`), Azure CLI (Q10 — table tier classification via `az monitor log-analytics workspace table list`), and automated post-processing (Phase 4: table cross-reference, ASIM parser detection, value-level rule verification, detection gap identification; Phase 5: anomaly severity classification, DL eligibility classification, migration table assembly, license benefit computation).

### 8b. Data Freshness

- **Usage table:** Updated every ~6 hours (batch processing). Most recent data may reflect partial-day ingestion.
- **SentinelHealth:** Near real-time — rule execution health data is current to within minutes.
- **Tier classification:** Azure CLI snapshot taken at data gathering time (2026-02-22T10:40:21Z). Table tier changes after this timestamp are not reflected.
- **Scratchpad timestamp:** All data in this report was gathered in a single 23.2-second run anchored to the timestamp above.

### 8c. Methodology

- **Volume calculations** use the `Quantity` field from the Usage table (in MB, converted to GB). Billable volume excludes non-billable data types.
- **Anomaly detection** uses >50% deviation threshold with a 10 MB volume floor — tables where both periods are <10 MB are excluded as noise. 24h anomalies compare against same-weekday averages (29-day lookback, ≥3 data points, flat 7-day fallback) to avoid weekday/weekend false positives. Severity is pre-computed by Invoke-IngestionScan.ps1 using Rule A thresholds: 🟠 (≥200% deviation AND ≥0.05 GB), 🟡 (≥100% AND ≥0.01 GB), ⚪ (≥50% AND ≥0.01 GB). Overrides: tables with ≥5 rules AND ≥40% change → 🟠; tables with ≤−95% AND ≥0.05 GB → 🟠.
- **Analytic rule inventory** uses the Sentinel REST API as the authoritative source for enabled Scheduled and NRT analytic rules. Rule-to-table mapping uses reverse cross-reference: for each ingested table name from Q1 Usage, regex-search all enabled rule query texts for that table name. This catches multi-table rules (TI unions, joins, CTEs) that forward-parsing would miss. All cross-references are computed deterministically by Invoke-IngestionScan.ps1.
- **Analytic rule execution health** uses SentinelHealth (Q11 for health overview, Q11d for failing rule details) + SecurityAlert (Q12) for alert firing counts.
- **Migration candidates** are classified by Invoke-IngestionScan.ps1 by cross-referencing the verified table-to-rule mapping with tier data (Azure CLI) and DL eligibility (scripted classification against known-eligible/ineligible table lists). The 9-column Migration table in the scratchpad contains the pre-computed categorization.

### 8d. Limitations

1. **Usage table vs billing:** `Quantity` values may not exactly match billing due to rounding, batch processing delays, and partial-day aggregation differences.
2. **GB not dollars:** All cost estimates are expressed in GB, not dollar amounts. Actual cost depends on workspace pricing tier (Pay-As-You-Go vs commitment), region, and any negotiated pricing.
3. **Custom Detection availability:** CD rules are fetched via Microsoft Graph API (Q9b). If the `Microsoft.Graph.Authentication` PowerShell module is not installed or consent for `CustomDetection.Read.All` scope is not granted, the report shows AR-only analysis.
4. **SentinelHealth AR-only coverage:** SentinelHealth tracks only Analytic Rule (Scheduled + NRT) executions. Custom Detection execution health is available only via the `lastRunDetails` field in the Graph API response (Q9b). Section 5b health metrics cover ARs only.
5. **ASIM parser resolution:** ASIM parser rules call abstraction functions (e.g., `_Im_WebSession()`). Target tables cannot be determined from query text alone. The automated ASIM detection maps known parser patterns but may not cover custom workspace-specific parsers. See [ASIM parsers list](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list).
6. **Tier data CLI dependency:** Table tier classification requires Azure CLI (`az monitor log-analytics workspace table list`) — not queryable via KQL. The data is a point-in-time snapshot and does not reflect tier changes made after the report generation timestamp.

---

*Report generated: 2026-02-22T10:40:21Z | Skill: sentinel-ingestion-report v2 | Mode: 90-day markdown*
