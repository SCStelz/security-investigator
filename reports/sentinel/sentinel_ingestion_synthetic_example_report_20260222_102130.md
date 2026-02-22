# Sentinel Ingestion Report — la-contoso-prod

**Workspace:** la-contoso-prod (`a1b2c3d4-e5f6-7890-abcd-ef1234567890`)
**Period:** 2026-02-01 to 2026-05-02 (91 days)
**Deep-Dive Window:** 30 days
**Generated:** 2026-02-22T10:21:30Z

> ⚠️ **Advisory:** This report is based on synthetic test data. Volume figures, rule inventories, and license calculations reflect simulated values for demonstration purposes. Do not use these findings for production cost or security decisions without re-running against live workspace data.

---

## 1. Executive Summary

### 📊 Workspace at a Glance

| Metric | Value |
|--------|-------|
| **Total Ingestion (90d)** | 19,511.55 GB |
| **Billable Ingestion (90d)** | 18,110.55 GB (92.8%) |
| **Non-Billable (90d)** | 1,401.00 GB |
| **Average Daily** | 214.41 GB/day |
| **Peak Day** | 240.02 GB (2026-04-28, Tue) |
| **Minimum Day** | 156.65 GB (2026-03-14, Sat) |
| **Total Tables** | 65 (61 billable) |
| **Enabled Rules** | 261 (249 AR + 12 CD) |

### 💰 Cost Waterfall

```
                                    90-Day (GB)    Avg/Day (GB)
  Total Ingestion                     19511.550          214.413
  - Non-Billable                     -1401.000         - 15.396
  ──────────────────────────────────────────────────────────────
  Gross Billable                      18110.550          199.017
  - Est. E5/XDR Benefit              -6669.140         - 73.287
  - Est. DfS P2 Benefit              -1957.470         - 21.511
  ──────────────────────────────────────────────────────────────
  🎯 Est. Net Billable               ~9723.068         ~106.847
```

### 🛡️ Detection Posture

| Metric | Value |
|--------|-------|
| 🛡 Enabled Analytic Rules | 249 (236 Scheduled, 13 NRT) |
| 🛡 Enabled Custom Detections | 12 |
| 🟡 Disabled Rules (AR + CD) | 22 + 2 |
| 🟢 Tables with Rules (top-20) | 17 of 20 |
| 🟡 Tables with Zero Rules (top-20) | 3 of 20 |
| 🔵 Tables on Basic Tier | 1 |
| 🔵 Tables on Data Lake Tier | 4 |

### Overall Assessment

The workspace ingests an average of **214.41 GB/day** across 65 tables with a stable weekday/weekend oscillation pattern (weekday average ~212 GB vs weekend ~174 GB). Three tables — CommonSecurityLog (20.7%), Syslog (15.2%), and SecurityEvent (11.3%) — account for **47.2%** of all ingestion, making them the primary optimization targets.

Detection coverage is strong: **261 enabled rules** with a **99.9% execution success rate** and **0% cross-validation gap** between SentinelHealth and the AR inventory. However, two critical issues require immediate attention:

- 🔴 **OfficeActivity volume dropped 84.3% month-over-month** (184.8 GB → 29.06 GB), with 10 active analytic rules dependent on this table — potential connector failure creating a silent detection blind spot.
- 🔴 **AWSCloudTrail sits on Data Lake tier with 3 active AR rules** that cannot execute against Data Lake tables — a confirmed detection gap.

License benefits (DfS P2 + E5) could offset an estimated **8,626 GB** of the 90-day billable volume, reducing net billable ingestion to approximately **9,723 GB** (~106.85 GB/day). The DfS P2 pool is significantly underutilized at 9.6% (21.5 GB/day actual vs 225 GB/day pool).

### 🎯 Top 3 Recommendations

| Priority | Severity | Recommendation | Impact | Risk if Not Addressed |
|----------|----------|----------------|--------|-----------------------|
| 1 | 🔴 | **Investigate OfficeActivity connector failure** — Volume dropped 84.3% MoM (184.8 → 29.06 GB). Verify the Office 365 data connector health, check for DCR changes, and validate data flow. 10 active rules (including "Mailbox forwarding rule created") are losing coverage. | 10 rules at risk of silent failure | High — active detection rules producing no alerts on a table that should be ingesting ~6 GB/day |
| 2 | 🔴 | **Resolve AWSCloudTrail detection gap** — 3 AR rules ("AWS root account login", "AWS IAM policy changed", "AWS S3 bucket made public") target a table on Data Lake tier where AR rules cannot execute. Move AWSCloudTrail back to Analytics tier, or disable the 3 rules if cloud trail monitoring is handled by an external SIEM. | 3 rules silently non-functional | High — rules appear enabled but produce no detections; false sense of coverage for AWS threat monitoring |
| 3 | 🟠 | **Filter zero-rule SecurityEvent EventIDs via DCR** — 7 EventIDs with 0 detection rules consume ~1,067 GB/month (21% of SecurityEvent volume): 4689 (Process exited), 4634 (Logoff), 5156/5158 (WFP), 4627 (Group membership), 4662/4658 (Object handle). Apply a DCR transformation to exclude or route these to Data Lake. | ~1,067 GB/month ingestion reduction | Medium — cost reduction with no detection impact; EventIDs can be re-enabled if future rules require them |

---

## 2. Ingestion Overview

### 2a. Top Tables by Volume

| Volume | # | DataType | BillableGB (90d) | Avg/Day (GB) | % | Rules | Current Tier |
|--------|---|----------|------------------|--------------|---|-------|--------------|
| 🔴 | 1 | CommonSecurityLog | 3750 | 41.209 | 20.7% | 🟢 10 | Analytics |
| 🔴 | 2 | Syslog | 2760 | 30.33 | 15.2% | 🟢 12 | Analytics |
| 🔴 | 3 | SecurityEvent | 2040 | 22.418 | 11.3% | 🟢 45 | Analytics |
| 🔴 | 4 | SigninLogs | 1560 | 17.143 | 8.6% | 🟢 30 | Analytics |
| 🔴 | 5 | AADNonInteractiveUserSignInLogs | 1170 | 12.857 | 6.5% | 🟡 3 | Analytics |
| 🔴 | 6 | DeviceProcessEvents | 855 | 9.396 | 4.7% | 🟢 28 | Analytics |
| 🔴 | 7 | AzureActivity | 750 | 8.242 | 4.1% | 🟡 8 | Analytics |
| 🔴 | 8 | DeviceNetworkEvents | 705 | 7.747 | 3.9% | 🟢 18 | Analytics |
| 🔴 | 9 | AuditLogs | 585 | 6.429 | 3.2% | 🟢 26 | Analytics |
| 🔴 | 10 | DeviceFileEvents | 510 | 5.604 | 2.8% | 🟢 20 | Analytics |
| 🟠 | 11 | OfficeActivity | 435 | 4.78 | 2.4% | 🟢 10 | Analytics |
| 🟠 | 12 | AWSCloudTrail | 390 | 4.286 | 2.2% | 🟡 3 | Data Lake |
| 🟠 | 13 | CloudAppEvents | 324 | 3.56 | 1.8% | 🟡 9 | Analytics |
| 🟠 | 14 | DeviceEvents | 285 | 3.132 | 1.6% | 🟡 9 | Analytics |
| 🟠 | 15 | StorageBlobLogs | 234 | 2.571 | 1.3% | ⚠️ 0 | Analytics |
| 🟠 | 16 | AzureDiagnostics | 195 | 2.143 | 1.1% | ⚠️ 0 | Basic |
| 🟠 | 17 | EmailEvents | 174 | 1.912 | 1% | 🟢 10 | Analytics |
| 🟠 | 18 | DeviceRegistryEvents | 144 | 1.582 | 0.8% | 🟡 7 | Analytics |
| 🟠 | 19 | AADManagedIdentitySignInLogs | 114 | 1.253 | 0.6% | ⚠️ 0 | Analytics |
| 🟡 | 20 | DeviceLogonEvents | 96 | 1.055 | 0.5% | 🟡 6 | Analytics |

**Totals (all 65 tables, 90d):** 19511.55 GB total, 18110.55 GB billable (92.8%), 1401 GB non-billable, 214.413 GB avg/day

🔴 ≥500 GB · 🟠 100–499 GB · 🟡 10–99 GB · 🟢 <10 GB  |  🟣 50+ rules · 🟢 10-49 · 🟡 3-9 · 🟠 1-2 · ⚠️ 0 (no detections — Analytics/Basic only)

**Key observations:**
- **3 tables with zero rules in the top 20** — StorageBlobLogs (234 GB), AzureDiagnostics (195 GB), and AADManagedIdentitySignInLogs (114 GB) are ingested on Analytics or Basic tier with no detection rules. All three are DL-eligible and strong migration candidates.
- **AWSCloudTrail on Data Lake** with 3 rules creates a detection gap (expanded in §7a).
- The top 6 tables account for **67.0%** of all ingestion (13,135 GB / 19,512 GB).

### 2b. Tier Classification

| Tier | Tables | Billable GB (90d) | % of Total |
|------|--------|-------------------|------------|
| Analytics | 60 | 17,450.55 | 96.6% |
| Data Lake | 4 | 465.00 | 2.4% |
| Basic | 1 | 195.00 | 1.0% |

**Data Lake tables:** AWSCloudTrail, SecurityEvent_Aux_CL, SecurityEvent_SPLT_CL, Signinlogs_Anomalies_KQL_CL

**Basic tables:** AzureDiagnostics

The workspace is overwhelmingly on the Analytics tier (96.6%). The 4 Data Lake tables include 2 legitimate split-ingestion tables (SecurityEvent_Aux_CL, SecurityEvent_SPLT_CL) and 1 KQL job output table (Signinlogs_Anomalies_KQL_CL). AWSCloudTrail is the exception — it has 3 active rules that cannot execute on Data Lake, making it a detection gap requiring remediation.

---

## 3. Deep Dives

### 3a. SecurityEvent

**450 servers** detected across the 30-day deep-dive window. The top 25 emitters are domain controllers, Exchange servers, SQL servers, and Hyper-V hosts — consistent with typical enterprise infrastructure.

#### Top 25 Computers by Volume

| Volume | Computer | Event Count | Est. GB (30d) | % |
|--------|----------|-------------|---------------|---|
| 🔴 | DC-002.contoso.com | 140,076,011 | 106.73 | 2.1% |
| 🔴 | DC-006.contoso.com | 115,047,912 | 100.64 | 2.0% |
| 🔴 | DC-003.fabrikam.local | 114,086,951 | 96.82 | 1.9% |
| 🔴 | DC-005.fabrikam.local | 98,347,073 | 87.70 | 1.7% |
| 🔴 | DC-004.northwind.com | 104,195,593 | 81.08 | 1.6% |
| 🔴 | DC-001.fabrikam.local | 85,374,809 | 74.88 | 1.5% |
| 🔴 | EXCH-001.contoso.com | 53,814,087 | 58.18 | 1.2% |
| 🔴 | EXCH-003.northwind.com | 69,729,903 | 56.22 | 1.1% |
| 🔴 | SQL-003.fabrikam.local | 64,988,734 | 54.07 | 1.1% |
| 🔴 | SQL-010.fabrikam.local | 51,819,282 | 53.82 | 1.1% |
| 🔴 | SQL-002.northwind.com | 49,685,465 | 48.82 | 1.0% |
| 🔴 | SQL-004.northwind.com | 48,838,456 | 46.99 | 0.9% |
| 🔴 | EXCH-004.contoso.com | 61,989,882 | 46.95 | 0.9% |
| 🔴 | SQL-007.fabrikam.local | 59,122,485 | 44.71 | 0.9% |
| 🔴 | SQL-005.fabrikam.local | 45,211,151 | 44.55 | 0.9% |
| 🔴 | SQL-008.contoso.com | 53,391,916 | 43.30 | 0.9% |
| 🔴 | EXCH-002.fabrikam.local | 51,538,167 | 40.39 | 0.8% |
| 🔴 | SQL-001.northwind.com | 46,842,817 | 39.88 | 0.8% |
| 🔴 | WEB-006.northwind.com | 41,827,231 | 39.15 | 0.8% |
| 🔴 | HV-004.fabrikam.local | 41,674,607 | 38.17 | 0.8% |
| 🔴 | HV-012.fabrikam.local | 48,088,481 | 37.11 | 0.7% |
| 🔴 | HV-007.contoso.com | 47,329,611 | 36.96 | 0.7% |
| 🔴 | WEB-010.contoso.com | 44,226,794 | 36.83 | 0.7% |
| 🔴 | HV-001.fabrikam.local | 35,797,382 | 36.70 | 0.7% |
| 🔴 | HV-008.contoso.com | 38,178,963 | 35.63 | 0.7% |

ServerCount: 450

🔴 ≥20 GB · 🟠 10–19 GB · 🟡 5–9 GB · 🟢 <5 GB

**Observations:**
- Domain controllers (DC-*) dominate, contributing the most audit events (logon, Kerberos, group membership).
- Multi-forest environment detected: `contoso.com`, `fabrikam.local`, `northwind.com`.
- All top-25 servers exceed 35 GB/month — these are the primary candidates for EventID-level filtering via DCR.

#### Top 25 EventIDs by Volume

| Volume | EventID | Description | Event Count | Est. GB (30d) | % | Rules Referencing |
|--------|---------|-------------|-------------|---------------|---|---|
| 🔴 | 4624 | Successful logon | 1,716,090,589 | 1415.99 | 27.9% | 🟠 2 — Successful logon from rare IP; Possible pass-the-hash activity |
| 🔴 | 4625 | Failed logon | 580,332,699 | 606.85 | 11.9% | 🟠 2 — Multiple failed logon attempts; Brute force attack against user |
| 🔴 | 4672 | Special privileges assigned | 465,469,846 | 404.57 | 8.0% | 🟠 1 — Special privileges assigned to new logon |
| 🔴 | 4688 | New process created | 449,515,752 | 379.28 | 7.5% | 🟠 1 — New process created - suspicious |
| 🔴 | 4689 | Process exited | 373,871,880 | 354.00 | 7.0% | ⚠️ 0 rules |
| 🔴 | 4634 | Logoff | 295,519,817 | 303.43 | 6.0% | ⚠️ 0 rules |
| 🔴 | 4663 | Object access attempt | 364,697,695 | 278.14 | 5.5% | 🟠 1 — Object access attempt |
| 🔴 | 4648 | Logon using explicit credentials | 244,658,573 | 202.28 | 4.0% | 🟠 1 — Logon with explicit credentials |
| 🔴 | 4776 | NTLM credential validation | 231,785,259 | 177.00 | 3.5% | 🟠 1 — NTLM authentication detected |
| 🔴 | 4768 | Kerberos TGT requested | 201,783,973 | 151.71 | 3.0% | 🟠 2 — Kerberos TGT request anomaly; Possible pass-the-ticket activity |
| 🔴 | 4769 | Kerberos service ticket requested | 163,766,736 | 126.43 | 2.5% | 🟠 2 — Kerberos service ticket anomaly; Golden ticket activity detected |
| 🔴 | 5156 | WFP connection allowed | 121,355,243 | 126.43 | 2.5% | ⚠️ 0 rules |
| 🔴 | 5158 | WFP bind permitted | 120,987,484 | 101.14 | 2.0% | ⚠️ 0 rules |
| 🔴 | 4627 | Group membership information | 114,277,557 | 101.14 | 2.0% | ⚠️ 0 rules |
| 🔴 | 4703 | Token right adjusted | 70,475,737 | 75.86 | 1.5% | 🟠 1 — Token right adjustment |
| 🔴 | 4656 | Handle to object requested | 79,506,015 | 75.86 | 1.5% | 🟠 1 — Handle to sensitive object |
| 🔴 | 4670 | Permissions on object changed | 53,685,143 | 50.57 | 1.0% | 🟠 1 — Permissions on object changed |
| 🟠 | 4662 | Operation performed on object | 49,981,327 | 40.46 | 0.8% | ⚠️ 0 rules |
| 🟠 | 4658 | Handle to object closed | 40,466,957 | 40.46 | 0.8% | ⚠️ 0 rules |
| 🟠 | 4740 | User account locked out | 33,659,357 | 25.29 | 0.5% | 🟠 1 — Account lockout detected |
| 🟠 | 4720 | User account created | 14,944,329 | 15.17 | 0.3% | 🟠 1 — User account created |
| 🟠 | 4798 | Local group membership enumerated | 18,878,878 | 15.17 | 0.3% | 🟠 1 — Security group enumeration |
| 🟠 | 4726 | User account deleted | 10,546,707 | 10.11 | 0.2% | 🟠 1 — User account deleted |
| 🟡 | 1102 | Audit log cleared | 2,855,863 | 2.53 | 0.0% | 🟠 1 — Audit log cleared |
| 🟡 | 4719 | System audit policy changed | 2,889,086 | 2.53 | 0.0% | 🟠 1 — Audit policy changed |

🔴 ≥50 GB · 🟠 10–49 GB · 🟡 1–9 GB · 🟢 <1 GB  |  🟣 50+ rules · 🟢 10-49 · 🟡 3-9 · 🟠 1-2 · ⚠️ 0 rules

**Zero-rule EventIDs — DCR filter candidates:**

| EventID | Description | Est. GB (30d) | % of SecurityEvent |
|---------|-------------|---------------|-------------------|
| 4689 | Process exited | 354.00 | 7.0% |
| 4634 | Logoff | 303.43 | 6.0% |
| 5156 | WFP connection allowed | 126.43 | 2.5% |
| 5158 | WFP bind permitted | 101.14 | 2.0% |
| 4627 | Group membership information | 101.14 | 2.0% |
| 4662 | Operation performed on object | 40.46 | 0.8% |
| 4658 | Handle to object closed | 40.46 | 0.8% |
| **Total** | | **~1,067 GB/month** | **~21%** |

These 7 EventIDs contribute ~1,067 GB/month with zero detection rules referencing them. Filtering via DCR or routing to Data Lake would reduce SecurityEvent ingestion by approximately 21% with no impact on current detection coverage. The DfS P2 pool (225 GB/day) provides ample headroom for the remaining EventIDs.

#### DfS P2 Pool Status

The **Defender for Servers P2** benefit provides 500 MB/server/day for SecurityEvent ingestion:

- **Server count:** 450
- **Pool size:** 450 × 500 MB = **225 GB/day**
- **Actual eligible daily ingestion:** 21.511 GB/day
- **Pool utilization:** 9.6%

The pool far exceeds actual SecurityEvent ingestion. Consider increasing SecurityEvent logging levels (e.g., collecting "All Events" instead of "Common" or "Minimal") to broaden detection coverage at no additional ingestion cost. Note that increased retention volume may affect long-term storage costs.

### 3b. Syslog

#### Top 20 Source Hosts

| Source Host | Event Count | Est. GB (30d) | % | Facilities | Severity Levels |
|-------------|-------------|---------------|---|------------|-----------------|
| lnx-k8s-master-01 | 467,276,364 | 127.09 | 7.6% | local0, mail, daemon | info, crit, notice, err |
| lnx-jump-01 | 440,648,874 | 119.44 | 7.1% | daemon, auth, user, local3, local0 | warning, err, info, crit |
| lnx-web-01 | 464,504,730 | 116.44 | 7.0% | auth, local0, local3, user, authpriv, kern | info, warning |
| lnx-dns-01 | 425,939,272 | 105.86 | 6.3% | mail, local1, auth, daemon | warning, info |
| lnx-k8s-worker-02 | 376,000,317 | 102.27 | 6.1% | mail, local0, cron, auth, local1 | err, info, crit, notice |
| fw-edge-01 | 294,797,441 | 100.70 | 6.0% | kern, user, local1, local3, local0, daemon | crit, err, notice |
| lnx-monitor-01 | 348,476,894 | 98.71 | 5.9% | authpriv, local1, auth, cron | notice, warning |
| lnx-docker-02 | 386,839,276 | 98.53 | 5.9% | local0, user, daemon, local1, mail, kern | crit, info, notice |
| lnx-db-01 | 296,146,031 | 95.47 | 5.7% | daemon, authpriv, local3, user, auth, cron | crit, notice, warning, info |
| fw-core-01 | 343,135,240 | 91.94 | 5.5% | local1, local3, daemon, local0, auth | err, info |
| lnx-db-02 | 230,353,825 | 87.69 | 5.2% | user, cron, auth, syslog, local0, local3 | warning, notice, info |
| lnx-web-02 | 226,291,002 | 86.92 | 5.2% | syslog, user, daemon | notice, info |
| lnx-k8s-worker-01 | 263,707,282 | 86.08 | 5.1% | cron, local1, local0, daemon, user | info, err, notice |
| lnx-web-03 | 335,592,240 | 84.55 | 5.1% | daemon, local1, mail, auth, local3, local0 | warning, crit, info |
| fw-edge-02 | 291,719,953 | 76.47 | 4.6% | cron, auth, local1, user | notice, crit, warning, err |
| lnx-docker-01 | 180,090,881 | 57.94 | 3.5% | syslog, user, cron | info, err |
| lnx-ntp-01 | 134,163,655 | 43.05 | 2.6% | mail, daemon, local1 | info, err, notice |
| lnx-app-02 | 98,237,571 | 36.98 | 2.2% | mail, local3, auth, kern, user, authpriv | err, notice, info |
| lnx-app-01 | 135,911,649 | 33.94 | 2.0% | authpriv, cron, kern, mail, auth, local0 | err, crit |
| lnx-ci-01 | 83,553,405 | 21.31 | 1.3% | cron, local3, local0, local1, daemon | warning, info |

**Observations:**
- Kubernetes infrastructure (k8s-master, k8s-worker) contributes ~315 GB/month (~19%) across 3 hosts.
- **Firewall hosts** (fw-edge-01, fw-core-01, fw-edge-02) contribute ~269 GB/month (~16%). These hosts also send local0/local1/local3 facility data — investigate potential overlap with CommonSecurityLog (CEF-formatted data from the same appliances).
- Docker hosts (lnx-docker-01, lnx-docker-02) contribute ~157 GB/month (~9%).

#### Facility Breakdown

| Badge | Facility | Event Count | Est. GB (30d) | % | Rules |
|-------|----------|-------------|---------------|---|-------|
| 🔒 | auth | 1,370,032,887 | 422.70 | 25.3% | 🟡 4 — SSH brute force attack; Authentication failure burst; PAM authentication error; +1 more |
| ⚙️ | daemon | 1,438,153,001 | 388.44 | 23.2% | 🟠 1 — Syslog daemon restart |
| ⚙️ | kern | 707,954,223 | 197.64 | 11.8% | 🟠 2 — Kernel module loaded; SELinux denial detected |
| 🔒 | authpriv | 598,095,982 | 171.37 | 10.3% | 🟡 3 — Root privilege escalation; Linux user created; Linux user deleted |
| 📡 | local0 | 402,885,605 | 114.24 | 6.8% | ⚠️ 0 rules |
| 📝 | user | 353,147,092 | 102.81 | 6.2% | ⚠️ 0 rules |
| ⏰ | cron | 263,026,095 | 68.55 | 4.1% | 🟠 1 — Suspicious cron job created |
| 📡 | local3 | 264,093,626 | 68.55 | 4.1% | ⚠️ 0 rules |
| 📡 | local1 | 180,755,371 | 57.12 | 3.4% | ⚠️ 0 rules |
| 📝 | syslog | 158,977,445 | 45.69 | 2.7% | 🟢 12 — SSH brute force attack; Root privilege escalation; Syslog daemon restart; +9 more |
| 📬 | mail | 118,834,804 | 34.27 | 2.1% | ⚠️ 0 rules |

🔒 Security-critical · ⚙️ System operational · 📡 Network/appliance · ⏰ Scheduler · 📬 Messaging · 📝 General/legacy

**Zero-rule facilities** (local0, user, local3, local1, mail) contribute ~377 GB/month (~22.6% of Syslog). The local0/local1/local3 facilities (~240 GB/month) likely originate from firewall appliances (see SyslogHost data for fw-* hosts). If these duplicate CEF data in CommonSecurityLog, they could be filtered at the DCR level.

#### Facility × Severity Matrix

| Badge | Facility | Severity Level | Event Count | Est. GB (30d) | % |
|-------|----------|----------------|-------------|---------------|---|
| 🔒 | auth | 🔵 notice | 707,721,228 | 205.64 | 12.3% |
| ⚙️ | daemon | 🟡 warning | 624,016,832 | 171.37 | 10.3% |
| 🔒 | auth | ⚪ info | 434,776,417 | 137.09 | 8.2% |
| ⚙️ | daemon | ⚪ info | 467,310,148 | 114.25 | 6.8% |
| 🔒 | authpriv | 🔵 notice | 304,030,037 | 91.40 | 5.5% |
| ⚙️ | kern | 🟡 warning | 353,695,239 | 91.40 | 5.5% |
| ⚙️ | daemon | 🔵 notice | 248,547,833 | 68.55 | 4.1% |
| 📡 | local0 | ⚪ info | 258,696,798 | 68.55 | 4.1% |
| 🔒 | auth | 🟡 warning | 168,133,301 | 57.12 | 3.4% |
| 🔒 | authpriv | ⚪ info | 226,386,262 | 57.12 | 3.4% |
| ⚙️ | kern | ⚪ info | 161,381,283 | 57.12 | 3.4% |
| 📝 | user | ⚪ info | 215,871,023 | 57.12 | 3.4% |
| ⏰ | cron | ⚪ info | 179,552,299 | 45.70 | 2.7% |
| 📡 | local3 | ⚪ info | 187,151,575 | 45.70 | 2.7% |
| ⚙️ | daemon | ⚪ err | 98,278,188 | 34.27 | 2.1% |
| ⚙️ | kern | 🔵 notice | 140,239,881 | 34.27 | 2.1% |
| 📝 | user | 🔵 notice | 94,129,005 | 34.27 | 2.1% |
| 📡 | local0 | 🟡 warning | 106,739,036 | 34.27 | 2.1% |
| 📡 | local1 | ⚪ info | 119,955,409 | 34.27 | 2.1% |
| 📝 | syslog | ⚪ info | 121,555,272 | 34.27 | 2.1% |
| 🔒 | auth | ⚪ err | 59,401,941 | 22.85 | 1.4% |
| 🔒 | authpriv | 🟡 warning | 67,679,683 | 22.85 | 1.4% |
| ⏰ | cron | 🔵 notice | 83,473,796 | 22.85 | 1.4% |
| 📡 | local1 | 🔵 notice | 60,799,962 | 22.85 | 1.4% |
| 📡 | local3 | 🟡 warning | 76,942,051 | 22.85 | 1.4% |
| 📬 | mail | ⚪ info | 87,388,007 | 22.85 | 1.4% |
| ⚙️ | kern | ⚪ err | 40,967,086 | 11.42 | 0.7% |
| 📝 | user | 🟡 warning | 43,147,064 | 11.42 | 0.7% |
| 📡 | local0 | ⚪ err | 37,449,771 | 11.42 | 0.7% |
| 📬 | mail | 🟡 warning | 31,446,797 | 11.42 | 0.7% |
| 📝 | syslog | 🔵 notice | 37,422,173 | 11.42 | 0.7% |
| ⚙️ | kern | 🔴 crit | 11,670,734 | 3.43 | 0.2% |

🔴 Critical · 🟠 Error · 🟡 Warning · 🔵 Notice · ⚪ Info · ⚫ Debug

#### Top 30 Processes

| Facility | Process Name | Event Count | Est. GB (30d) | % | Rules |
|----------|--------------|-------------|---------------|---|-------|
| auth | sshd | 773,846,590 | 280.67 | 16.8% | 🟠 1 — SSH key authentication from new IP |
| daemon | systemd | 944,567,159 | 252.60 | 15.1% | 🟠 1 — Syslog daemon restart |
| authpriv | sudo | 362,010,144 | 112.27 | 6.7% | 🟠 1 — Root privilege escalation |
| daemon | dockerd | 303,693,749 | 98.24 | 5.9% | ⚠️ 0 rules |
| daemon | kubelet | 331,298,453 | 84.20 | 5.0% | ⚠️ 0 rules |
| cron | cron | 323,081,267 | 84.20 | 5.0% | 🟠 1 — Suspicious cron job created |
| local0 | nginx | 206,639,738 | 70.17 | 4.2% | ⚠️ 0 rules |
| authpriv | auditd | 197,086,474 | 70.17 | 4.2% | ⚠️ 0 rules |
| daemon | containerd | 216,350,464 | 56.13 | 3.4% | ⚠️ 0 rules |
| auth | pam_unix | 197,000,162 | 56.13 | 3.4% | 🟠 1 — PAM authentication error |
| syslog | rsyslogd | 156,898,452 | 56.13 | 3.4% | ⚠️ 0 rules |
| mail | postfix | 147,510,426 | 42.10 | 2.5% | ⚠️ 0 rules |
| local0 | httpd | 127,011,507 | 42.10 | 2.5% | ⚠️ 0 rules |
| daemon | named | 115,871,824 | 42.10 | 2.5% | ⚠️ 0 rules |
| daemon | kube-apiserver | 113,029,897 | 42.10 | 2.5% | ⚠️ 0 rules |
| authpriv | systemd-logind | 108,992,413 | 28.07 | 1.7% | ⚠️ 0 rules |
| daemon | etcd | 107,429,673 | 28.07 | 1.7% | ⚠️ 0 rules |
| daemon | coredns | 99,923,690 | 28.07 | 1.7% | ⚠️ 0 rules |
| daemon | NetworkManager | 97,366,249 | 28.07 | 1.7% | ⚠️ 0 rules |
| kern | iptables | 93,519,182 | 28.07 | 1.7% | 🟠 1 — Firewall rule change on Linux |
| auth | login | 93,323,667 | 28.07 | 1.7% | ⚠️ 0 rules |
| daemon | journald | 91,875,298 | 28.07 | 1.7% | ⚠️ 0 rules |
| authpriv | polkitd | 59,425,600 | 21.05 | 1.3% | ⚠️ 0 rules |
| mail | dovecot | 50,768,065 | 14.03 | 0.8% | ⚠️ 0 rules |
| auth | su | 49,761,311 | 14.03 | 0.8% | ⚠️ 0 rules |
| daemon | dbus-daemon | 45,400,696 | 14.03 | 0.8% | ⚠️ 0 rules |
| daemon | apt-get | 24,500,780 | 7.02 | 0.4% | ⚠️ 0 rules |
| authpriv | useradd | 23,167,437 | 7.02 | 0.4% | 🟠 1 — Linux user created |
| daemon | rpm | 17,084,756 | 4.21 | 0.3% | ⚠️ 0 rules |
| authpriv | passwd | 15,525,202 | 4.21 | 0.3% | ⚠️ 0 rules |

**Key observations:**
- **Container orchestration** processes (dockerd 98 GB, kubelet 84 GB, containerd 56 GB, kube-apiserver 42 GB, etcd 28 GB, coredns 28 GB) collectively contribute ~336 GB/month with zero detection rules. These are strong candidates for volume reduction via DCR process filtering or routing to Data Lake.
- **sshd** (281 GB, 16.8%) is the single largest process — only 1 rule references it. Consider whether all info/notice-level SSH messages need Analytics-tier retention.
- **systemd** (253 GB, 15.1%) generates high-volume operational logs with only 1 rule.

### 3c. CommonSecurityLog

#### Vendor Breakdown

| Volume | Device Vendor | Device Product | Event Count | Est. GB (30d) | % | Rules |
|--------|---------------|----------------|-------------|---------------|---|-------|
| 🔴 | Palo Alto Networks | PAN-OS | 1,773,250,228 | 655.70 | 45.0% | 🟠 1 — Data loss prevention alert |
| 🔴 | Fortinet | FortiGate | 847,672,289 | 364.28 | 25.0% | 🟠 1 — VPN connection from unusual country |
| 🔴 | Cisco | ASA | 297,090,031 | 174.85 | 12.0% | ⚠️ 0 rules |
| 🔴 | Zscaler | ZIA | 222,331,922 | 116.57 | 8.0% | 🟠 1 — Malware detected by proxy |
| 🔴 | Check Point | SmartDefense | 125,616,936 | 72.86 | 5.0% | ⚠️ 0 rules |
| 🟠 | F5 | BIG-IP ASM | 97,330,225 | 43.71 | 3.0% | ⚠️ 0 rules |
| 🟠 | Barracuda | WAF | 51,067,394 | 29.14 | 2.0% | ⚠️ 0 rules |

🔴 ≥50 GB · 🟠 20–49 GB · 🟡 5–19 GB · 🟢 <5 GB

**Observations:**
- **Cisco ASA** (175 GB/month, 12%), **Check Point** (73 GB), **F5** (44 GB), and **Barracuda** (29 GB) have **zero detection rules**. Combined: ~321 GB/month (22% of CSL) with no security analytics. Evaluate whether these vendors need Analytics-tier ingestion or can be migrated to Data Lake / filtered.
- **Palo Alto** dominates at 45% of CSL volume but has only 1 rule. The "Anomalous firewall traffic pattern" rule covers TRAFFIC activity broadly but no THREAT-specific detections exist.

#### Activity Breakdown

| Volume | Activity | Log Severity | Device Action | Event Count | Est. GB (30d) | % | Rules |
|--------|----------|--------------|---------------|-------------|---------------|---|-------|
| 🔴 | TRAFFIC | informational | allow | 705,409,486 | 437.13 | 30.0% | 🟠 1 — Anomalous firewall traffic pattern |
| 🔴 | TRAFFIC | informational | deny | 653,097,807 | 218.57 | 15.0% | 🟠 1 — Anomalous firewall traffic pattern |
| 🔴 | TRAFFIC | informational | drop | 417,219,443 | 145.71 | 10.0% | 🟠 1 — Anomalous firewall traffic pattern |
| 🔴 | THREAT | medium | alert | 340,606,851 | 116.57 | 8.0% | ⚠️ 0 rules |
| 🔴 | URL-FILTERING | informational | allow | 259,675,758 | 87.43 | 6.0% | ⚠️ 0 rules |
| 🔴 | THREAT | high | alert | 158,697,786 | 72.86 | 5.0% | ⚠️ 0 rules |
| 🔴 | GLOBALPROTECT | informational | success | 129,737,371 | 72.86 | 5.0% | ⚠️ 0 rules |
| 🔴 | SYSTEM | informational | n/a | 162,350,697 | 58.28 | 4.0% | ⚠️ 0 rules |
| 🔴 | URL-FILTERING | warning | block | 154,083,162 | 58.28 | 4.0% | ⚠️ 0 rules |
| 🟠 | THREAT | critical | block | 131,780,616 | 43.71 | 3.0% | ⚠️ 0 rules |
| 🟠 | AUTHENTICATION | informational | success | 98,486,367 | 43.71 | 3.0% | ⚠️ 0 rules |
| 🟠 | CONFIG | informational | n/a | 53,258,759 | 29.14 | 2.0% | ⚠️ 0 rules |
| 🟠 | GLOBALPROTECT | warning | fail | 89,342,584 | 29.14 | 2.0% | ⚠️ 0 rules |
| 🟠 | AUTHENTICATION | warning | failed | 84,110,245 | 29.14 | 2.0% | ⚠️ 0 rules |
| 🟡 | WILDFIRE | high | alert | 33,513,392 | 14.57 | 1.0% | ⚠️ 0 rules |

🔴 ≥50 GB · 🟠 20–49 GB · 🟡 5–19 GB · 🟢 <5 GB

**Key findings:**
- **TRAFFIC (allow/deny/drop)** consumes ~801 GB/month (55% of CSL) with only 1 broad rule. The high-volume `TRAFFIC allow` activity alone is 437 GB/month — strong candidate for DCR filtering or sampling, since "allow" events are typically low-value for detection.
- **THREAT events** (medium, high, critical) total ~233 GB/month with **zero explicit rules** referencing the THREAT activity value. Note: the 10 rules at the CommonSecurityLog table level (e.g., "IDS alert - critical severity") may still match these events based on other field criteria — the zero here reflects activity-value-level cross-referencing, not necessarily a detection gap.
- **GLOBALPROTECT success** (73 GB/month, 0 rules) and **AUTHENTICATION success** (44 GB/month, 0 rules) are operational logs with no analytic value — prime filter candidates.

---

## 4. Anomaly Detection

### 4a. Per-Table Anomaly Summary (24h + WoW)

| DataType | Last 24h (GB) | 30d Avg (GB) | 24h Deviation | This Month (GB) | Last Month (GB) | MoM Change | Severity |
|----------|---------------|-------------|---------------|----------------|----------------|------------|----------|
| GCPAuditLogs | 0.27 | 0.06 | +352% | 8.19 | 1.8 | +355.8% | 🟠 |
| AppTraces | 4.29 | 1.42 | +202% | — | — | — | 🟠 |
| StorageBlobLogs | 5.08 | 2.34 | +117% | 77.44 | 34.33 | +125.6% | 🟡 |
| OfficeActivity | 0.94 | 4.68 | -80% | 29.06 | 184.8 | -84.3% | 🟠 |
| AWSCloudTrail | 1.76 | 4.1 | -57% | 52.71 | 76.16 | -30.8% | ⚪ |
| DeviceRegistryEvents | 2.05 | 1.51 | +35% | 45.21 | 39.77 | +13.7% | ⚪ |
| AzureDiagnostics | 1.37 | 2.05 | -33% | 41.01 | 61.54 | -33.3% | ⚪ |
| SecurityEvent_Aux_CL | 0.41 | 0.47 | -12% | — | — | — | ⚪ |
| DeviceNetworkEvents | 8.3 | 7.42 | +12% | — | — | — | ⚪ |
| AzureActivity | — | — | — | 259.5 | 225.99 | +14.8% | ⚪ |
| CloudAppEvents | — | — | — | 102.56 | 92.06 | +11.4% | ⚪ |
| SentinelHealth | — | — | — | 2.61 | 2.44 | +6.9% | ⚪ |

**🟠 Anomalies requiring investigation:**

1. **GCPAuditLogs (+352% 24h, +355.8% MoM)** — Sustained spike over the full month, not just a 24h burst. Low absolute volume (0.27 GB/day) but the magnitude of change warrants investigation. Check for GCP project additions, new audit logging policies, or API abuse. 1 rule ("GCP privilege escalation") covers this table but is itself among the failing rules.

2. **AppTraces (+202% 24h)** — Short-term spike in application telemetry. No MoM data available. 0 rules and not DL-eligible. Check application deployments or verbose logging changes.

3. **OfficeActivity (-80% 24h, -84.3% MoM)** — **Critical: sustained volume decline**. From 184.8 GB last month to 29.06 GB this month, with only 0.94 GB in the last 24 hours. This table has **10 active rules** including mailbox forwarding, Teams, and SharePoint detections. Investigate: Office 365 data connector health, DCR modifications, licensing changes, or tenant-level configuration. This is the highest-priority anomaly due to detection coverage impact.

**🟡 Anomaly to monitor:**

4. **StorageBlobLogs (+117% 24h, +125.6% MoM)** — Doubling in storage access logging. 0 rules and DL-eligible, so the cost impact is more relevant than detection. Investigate: new storage accounts, backup operations, or data migration activity driving additional logging.

### 4b. Daily Trend (90 Days)

```
Daily Ingestion — la-contoso-prod (2026-02-01 to 2026-05-02)
Date          GB     Trend (max = 240.02 GB)
─────────────────────────────────────────────────────────────────
2026-02-01 │ 181.702  ██████████████████████████████████████
2026-02-02 │ 189.970  ████████████████████████████████████████
2026-02-03 │ 202.836  ██████████████████████████████████████████
2026-02-04 │ 200.170  ██████████████████████████████████████████
2026-02-05 │ 226.582  ███████████████████████████████████████████████
2026-02-06 │ 223.506  ███████████████████████████████████████████████
2026-02-07 │ 192.367  ████████████████████████████████████████
2026-02-08 │ 158.389  █████████████████████████████████
2026-02-09 │ 210.395  ████████████████████████████████████████████
2026-02-10 │ 190.217  ████████████████████████████████████████
2026-02-11 │ 199.934  ██████████████████████████████████████████
2026-02-12 │ 214.689  █████████████████████████████████████████████
2026-02-13 │ 190.049  ████████████████████████████████████████
2026-02-14 │ 163.111  ██████████████████████████████████
2026-02-15 │ 182.143  ██████████████████████████████████████
2026-02-16 │ 216.726  █████████████████████████████████████████████
2026-02-17 │ 200.027  ██████████████████████████████████████████
2026-02-18 │ 219.007  ██████████████████████████████████████████████
2026-02-19 │ 230.336  ████████████████████████████████████████████████
2026-02-20 │ 189.018  ███████████████████████████████████████
2026-02-21 │ 188.723  ███████████████████████████████████████
2026-02-22 │ 184.179  ██████████████████████████████████████ ← partial
2026-02-23 │ 206.192  ███████████████████████████████████████████
2026-02-24 │ 196.684  █████████████████████████████████████████
2026-02-25 │ 237.941  ██████████████████████████████████████████████████
2026-02-26 │ 206.004  ███████████████████████████████████████████
2026-02-27 │ 193.456  ████████████████████████████████████████
2026-02-28 │ 158.802  █████████████████████████████████
2026-03-01 │ 190.482  ████████████████████████████████████████
2026-03-02 │ 219.751  ██████████████████████████████████████████████
2026-03-03 │ 230.218  ████████████████████████████████████████████████
2026-03-04 │ 226.235  ███████████████████████████████████████████████
2026-03-05 │ 216.277  █████████████████████████████████████████████
2026-03-06 │ 238.759  ██████████████████████████████████████████████████
2026-03-07 │ 170.693  ████████████████████████████████████
2026-03-08 │ 178.015  █████████████████████████████████████
2026-03-09 │ 231.364  ████████████████████████████████████████████████
2026-03-10 │ 220.512  ██████████████████████████████████████████████
2026-03-11 │ 233.026  █████████████████████████████████████████████████
2026-03-12 │ 218.393  █████████████████████████████████████████████
2026-03-13 │ 224.940  ███████████████████████████████████████████████
2026-03-14 │ 156.654  █████████████████████████████████ ← min
2026-03-15 │ 164.337  ██████████████████████████████████
2026-03-16 │ 203.575  ██████████████████████████████████████████
2026-03-17 │ 192.789  ████████████████████████████████████████
2026-03-18 │ 200.663  ██████████████████████████████████████████
2026-03-19 │ 193.881  ████████████████████████████████████████
2026-03-20 │ 202.988  ██████████████████████████████████████████
2026-03-21 │ 181.544  ██████████████████████████████████████
2026-03-22 │ 170.115  ███████████████████████████████████
2026-03-23 │ 207.733  ███████████████████████████████████████████
2026-03-24 │ 199.464  ██████████████████████████████████████████
2026-03-25 │ 202.422  ██████████████████████████████████████████
2026-03-26 │ 236.883  █████████████████████████████████████████████████
2026-03-27 │ 222.031  ██████████████████████████████████████████████
2026-03-28 │ 180.424  ██████████████████████████████████████
2026-03-29 │ 161.942  ██████████████████████████████████
2026-03-30 │ 226.204  ███████████████████████████████████████████████
2026-03-31 │ 197.092  █████████████████████████████████████████
2026-04-01 │ 208.210  ███████████████████████████████████████████
2026-04-02 │ 239.603  ██████████████████████████████████████████████████
2026-04-03 │ 221.617  ██████████████████████████████████████████████
2026-04-04 │ 178.222  █████████████████████████████████████
2026-04-05 │ 183.609  ██████████████████████████████████████
2026-04-06 │ 232.056  ████████████████████████████████████████████████
2026-04-07 │ 228.616  ████████████████████████████████████████████████
2026-04-08 │ 200.470  ██████████████████████████████████████████
2026-04-09 │ 190.335  ████████████████████████████████████████
2026-04-10 │ 204.916  ███████████████████████████████████████████
2026-04-11 │ 166.018  ███████████████████████████████████
2026-04-12 │ 163.623  ██████████████████████████████████
2026-04-13 │ 237.205  █████████████████████████████████████████████████
2026-04-14 │ 233.781  █████████████████████████████████████████████████
2026-04-15 │ 204.876  ███████████████████████████████████████████
2026-04-16 │ 222.412  ██████████████████████████████████████████████
2026-04-17 │ 209.042  ████████████████████████████████████████████
2026-04-18 │ 193.311  ████████████████████████████████████████
2026-04-19 │ 174.082  ████████████████████████████████████
2026-04-20 │ 202.314  ██████████████████████████████████████████
2026-04-21 │ 201.375  ██████████████████████████████████████████
2026-04-22 │ 217.571  █████████████████████████████████████████████
2026-04-23 │ 202.204  ██████████████████████████████████████████
2026-04-24 │ 218.766  ██████████████████████████████████████████████
2026-04-25 │ 192.605  ████████████████████████████████████████
2026-04-26 │ 171.574  ████████████████████████████████████
2026-04-27 │ 199.969  ██████████████████████████████████████████
2026-04-28 │ 240.016  ██████████████████████████████████████████████████ ← peak
2026-04-29 │ 214.903  █████████████████████████████████████████████
2026-04-30 │ 193.362  ████████████████████████████████████████
2026-05-01 │ 191.108  ████████████████████████████████████████
2026-05-02 │ 159.347  █████████████████████████████████
─────────────────────────────────────────────────────────────────
Avg: 201.839 GB/day  Peak: 240.016 GB (2026-04-28)  Min: 156.654 GB (2026-03-14)
Weekday Avgs: Mon 214.11 | Tue 210.28 | Wed 212.73 | Thu 214.69 | Fri 210.02 | Sat 175.52 | Sun 173.33
```

The daily trend shows a stable oscillation pattern with clear weekday/weekend differentiation (~212 GB weekday average vs ~174 GB weekend). No sustained upward trend. The peak-to-min ratio of 1.53 (240/157) is within normal range for an enterprise workspace. Partial days (first and last) may undercount.

---

## 5. Detection Coverage

### 5a. Rule Inventory & Table Cross-Reference

**Rule inventory:** 271 AR total (249 enabled, 22 disabled) + 14 CD total (12 enabled, 2 disabled) = **261 combined enabled rules**.

| Coverage | Table | AR Rules | CD Rules | Total | Key Rule Names |
|----------|-------|----------|----------|-------|----------------|
| 🟢 | SecurityEvent | 45 | 0 | 45 | Multiple failed logon attempts; Brute force attack against user; Account lockout detected; +42 more |
| 🟢 | SigninLogs | 28 | 2 | 30 | Sign-in from unknown IP; Multiple failed sign-ins single user; Sign-in from blocked country; +27 more |
| 🟢 | DeviceProcessEvents | 26 | 2 | 28 | Suspicious process execution; LOLBIN execution detected; Process injection detected; +25 more |
| 🟢 | AuditLogs | 26 | 0 | 26 | Multiple password resets by user; Risky sign-in followed by MFA change; Suspicious consent grant; +23 more |
| 🟢 | DeviceFileEvents | 18 | 2 | 20 | DLL sideloading detected; Ransomware indicators detected; Ransomware file extension detected; +17 more |
| 🟢 | DeviceNetworkEvents | 16 | 2 | 18 | Cobalt Strike beacon indicator; C2 beaconing pattern detected; DNS tunneling detected; +15 more |
| 🟢 | Syslog | 12 | 0 | 12 | SSH brute force attack; Root privilege escalation; Syslog daemon restart; +9 more |
| 🟢 | CommonSecurityLog | 10 | 0 | 10 | IDS alert - critical severity; Firewall deny from internal to external; Data loss prevention alert; +7 more |
| 🟢 | EmailEvents | 8 | 2 | 10 | Phishing email delivered; Malware attachment detected; Email from spoofed sender; +7 more |
| 🟢 | OfficeActivity | 10 | 0 | 10 | Mailbox forwarding rule created; Suspicious Teams meeting created; Mass file download from SharePoint; +7 more |
| 🟡 | DeviceEvents | 9 | 0 | 9 | Antivirus detection; Exploit guard block; Tamper protection triggered; +6 more |
| 🟡 | CloudAppEvents | 8 | 1 | 9 | Suspicious OAuth app consent; Mass download from cloud storage; Cloud app high severity alert; +6 more |
| 🟡 | Operation | 8 | 0 | 8 | Mailbox forwarding rule created; Mass file download from SharePoint; External sharing enabled; +5 more |
| 🟡 | AzureActivity | 8 | 0 | 8 | Resource group deleted; Key vault access anomaly; Subscription-level role assignment; +5 more |
| 🟡 | DeviceRegistryEvents | 7 | 0 | 7 | Persistence via registry run key; Registry run key modification; AMSI bypass registry change; +4 more |
| 🟡 | DeviceLogonEvents | 5 | 1 | 6 | RDP brute force on endpoint; New local admin logon; Interactive logon at unusual hour; +3 more |
| 🟡 | SecurityAlert | 5 | 0 | 5 | High severity alert correlation; Multi-stage attack detected; Alert-to-incident correlation; +2 more |
| 🟡 | IdentityLogonEvents | 5 | 0 | 5 | LDAP brute force detected; NTLM relay attack pattern; Kerberoasting pattern detected; +2 more |
| 🟡 | AWSCloudTrail | 3 | 0 | 3 | AWS root account login; AWS IAM policy changed; AWS S3 bucket made public |
| 🟡 | AADNonInteractiveUserSignInLogs | 3 | 0 | 3 | Managed identity anomalous sign-in; Non-interactive sign-in from new IP; Non-interactive sign-in burst |
| 🟠 | GCPAuditLogs | 1 | 0 | 1 | GCP privilege escalation |
| 🟠 | ConfigurationChange | 1 | 0 | 1 | Config change on managed server |
| 🟠 | ThreatIntelligenceIndicator | 1 | 0 | 1 | Threat intelligence match |
| 🟠 | LAQueryLogs | 1 | 0 | 1 | LA query exfiltration pattern |
| 🟠 | UrlClickEvents | 1 | 0 | 1 | URL click to malicious site |
| 🟠 | MicrosoftGraphActivityLogs | 1 | 0 | 1 | Graph API anomaly detected |
| 🟠 | IdentityDirectoryEvents | 1 | 0 | 1 | Identity directory change anomaly |
| 🟠 | IdentityQueryEvents | 1 | 0 | 1 | Unusual identity query pattern |
| 🟠 | EmailAttachmentInfo | 0 | 1 | 1 | Phishing email with attachment |
| 🟠 | SecurityIncident | 1 | 0 | 1 | Multi-stage attack detected |
| 🟠 | AADServicePrincipalSignInLogs | 1 | 0 | 1 | Service principal sign-in failure spike |
| 🟠 | EmailPostDeliveryEvents | 1 | 0 | 1 | Email post-delivery action |
| 🟠 | EmailUrlInfo | 1 | 0 | 1 | Email with suspicious URL |

**32 zero-rule tables** (not shown above): These are tables with data ingestion but no detection rules referencing them. See §7a for migration candidates.

**Detection gaps on non-Analytics tiers:**

| Table | Tier | Rules | Issue |
|-------|------|-------|-------|
| AWSCloudTrail | Data Lake | 3 AR | ❗ Rules cannot execute on Data Lake — confirmed detection gap |

**ASIM parsers:** None detected in the current rule set.

**Cross-validation:** Q11 (SentinelHealth) reports 249 distinct rules; Q9 (AR inventory) reports 249 enabled — **0% gap**. The rule telemetry is fully consistent.

### 5b. Rule Health & Alerts

**Overall health:** 249 rules tracked in SentinelHealth, 147,159 total executions, **99.9% success rate**, 201 total failures across 4 rules.

#### Alert-Producing Rules (90d)

| Volume | Rule Name | Alert Count | Severity | Product Component |
|--------|-----------|-------------|----------|-------------------|
| 🔥 | Brute force attack against user | 426 | 🟠 Medium | Scheduled Alerts |
| 🔥 | Sign-in from unknown IP | 267 | 🟠 Medium | Scheduled Alerts |
| 🔥 | Multiple failed sign-ins single user | 228 | 🟡 Low | Scheduled Alerts |
| 🔥 | Application credential added | 192 | 🟡 Low | Scheduled Alerts |
| 🔥 | Password spray attack detection | 159 | 🟡 Low | Scheduled Alerts |
| 🔥 | Mailbox forwarding rule created | 123 | 🔴 High | Scheduled Alerts |
| 🔥 | SSH brute force attack | 114 | 🟠 Medium | Scheduled Alerts |
| 🔥 | Suspicious process execution | 105 | 🔴 High | Scheduled Alerts |
| 📊 | IDS alert - critical severity | 84 | 🔴 High | Scheduled Alerts |
| 📊 | Obfuscated PowerShell command | 66 | 🔴 High | Scheduled Alerts |
| 📊 | Conditional Access policy modified | 57 | 🟡 Low | Scheduled Alerts |
| 📊 | Application ownership change | 45 | 🟡 Low | Scheduled Alerts |
| 📊 | C2 beaconing pattern detected | 36 | 🔴 High | Scheduled Alerts |
| 📊 | Ransomware indicators detected | 24 | 🔴 High | NRT Alerts |
| 📊 | Privileged service called | 18 | 🔵 Informational | NRT Alerts |
| 📊 | Event logging shut down | 12 | 🔴 High | NRT Alerts |
| 💤 | Directory role member added | 9 | 🔵 Informational | NRT Alerts |
| 💤 | Token replay attack detection | 6 | 🔴 High | NRT Alerts |

Total: 1971 alerts from 18 rules

🔥 100+ alerts · 📊 10–99 alerts · 💤 1–9 alerts  |  🔴 High · 🟠 Medium · 🟡 Low · 🔵 Informational

**Alert distribution:** 18 of 261 enabled rules (6.9%) produced alerts in the 90-day window. The top 3 alert-producing rules (Brute force, Unknown IP, Failed sign-ins) account for 921 alerts (46.7%) — review thresholds if these create excessive incident noise.

#### Failing Rules

| Rule Name | Kind | Failures | Last Failure | Status |
|-----------|------|----------|--------------|--------|
| NRT First access credential added to Application or Service Principal where no credential was present | NRT | 23 | 2026-02-18 | 🟠 Failing |
| Suspicious process execution | Scheduled | 12 | 2026-02-19 | 🟠 Failing |
| GCP privilege escalation | Scheduled | 8 | 2026-02-20 | 🟠 Failing |
| Deprecated - Old brute force detection v1 | Scheduled | 4 | 2026-02-17 | 🟠 Failing |

**Remediation notes:**
- **"NRT First access credential..."** (23 failures) — Most frequent failure. Investigate KQL syntax or table availability. NRT rules fail silently without producing alerts.
- **"Suspicious process execution"** (12 failures) — Also an active alert producer (105 alerts). Intermittent failures suggest transient query timeouts or workspace load issues.
- **"GCP privilege escalation"** (8 failures) — Correlates with GCPAuditLogs anomaly (+352%); the volume spike may be causing query timeouts.
- **"Deprecated - Old brute force detection v1"** (4 failures) — This rule is explicitly marked "Deprecated." Disable it and ensure the replacement rule (v2/v3) is active.

---

## 6. License Benefit Analysis

| Category | Avg Daily (GB) | Est. 90-Day (GB) | License Required |
|----------|---------------|-------------------|------------------|
| DfS P2-Eligible | 21.511 | 1957.470 | Defender for Servers P2 |
| E5-Eligible | 73.287 | 6669.140 | M365 E5 / E5 Security |
| **Remaining (truly billable)** | **106.847** | **9,723.068** | **Paid ingestion** |

License benefits could offset an estimated **8,626.61 GB** (47.6% of gross billable) over the 90-day period. The remaining ~9,723 GB (~106.85 GB/day) represents the truly billable ingestion not covered by pooled license benefits.

### 6a. Defender for Servers P2 Pool Detail

Pool calculation: 450 servers × 500 MB/day = 225.000 GB/day ([benefit details](https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-ingestion-benefit))

| Metric | Value |
|--------|-------|
| Eligible Table | SecurityEvent |
| Detected Server Count | 450 |
| Pool Size (500 MB/server/day) | 450 × 500 MB = **225.000 GB/day** |
| Actual Eligible Daily Ingestion | **21.511 GB/day** |
| Pool Utilization | **9.6%** |
| 90-Day DfS P2 Deduction | **1957.470 GB** |

**Scenario: Pool far exceeds usage.** If DfS P2 is enabled, the pool of 225.000 GB/day far exceeds actual eligible ingestion of 21.511 GB/day — significant headroom exists. Consider increasing SecurityEvent logging levels (e.g., collecting "All Events" instead of "Common" or "Minimal" via the Windows Security Events data connector) to broaden detection coverage at no additional ingestion cost. Note: increased retention volume may affect long-term storage costs depending on workspace retention settings.

### 6b. E5 / Defender XDR Pool Detail

| Table | Volume (90d GB) | Tier |
|-------|----------------|------|
| SigninLogs | 1560.000 | Analytics |
| AADNonInteractiveUserSignInLogs | 1170.000 | Analytics |
| DeviceProcessEvents | 855.000 | Analytics |
| DeviceNetworkEvents | 705.000 | Analytics |
| AuditLogs | 585.000 | Analytics |
| DeviceFileEvents | 510.000 | Analytics |
| CloudAppEvents | 324.000 | Analytics |
| DeviceEvents | 285.000 | Analytics |
| EmailEvents | 174.000 | Analytics |
| DeviceRegistryEvents | 144.000 | Analytics |
| AADManagedIdentitySignInLogs | 114.000 | Analytics |
| DeviceLogonEvents | 96.000 | Analytics |
| AADServicePrincipalSignInLogs | 66.000 | Analytics |
| IdentityLogonEvents | 54.000 | Analytics |
| DeviceInfo | 48.000 | Analytics |
| EmailAttachmentInfo | 36.000 | Analytics |
| DeviceNetworkInfo | 33.000 | Analytics |
| EmailUrlInfo | 30.000 | Analytics |
| IdentityQueryEvents | 28.500 | Analytics |
| IdentityDirectoryEvents | 25.500 | Analytics |
| DeviceImageLoadEvents | 24.000 | Analytics |
| AlertEvidence | 22.500 | Analytics |
| AADProvisioningLogs | 16.500 | Analytics |
| DeviceFileCertificateInfo | 15.000 | Analytics |
| EmailPostDeliveryEvents | 13.500 | Analytics |
| McasShadowItReporting | 3.600 | Analytics |
| ADFSSignInLogs | 3.000 | Analytics |
| DynamicEventCollection | 2.400 | Analytics |
| **Total (28 tables)** | **6943.500** | |

**Break-even:** 73.287 GB/day (75,046.2 MB/day) — requires **15,010 E5 licenses** to fully cover (at 5 MB/license/day)
*Per-table sum (6943.500 GB) differs from aggregate (6669.140 GB) due to rounding in daily averaging.*

> ⚠️ **Action required:** Verify your organization's actual E5 license count. If below 15,010, the E5 benefit deduction shown here is overstated. The actual benefit is `min(license_count × 5 MB/day, 73.287 GB/day)`.

---

## 7. Optimization Recommendations

### 7a. Data Lake Migration Candidates

#### 🔴 DL Migration Candidates (Zero Rules, DL-Eligible)

| DataType | 30d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |
|----------|-------|----------|----------|-------------|------|-------------|----------|
| StorageBlobLogs | 🟠 18.20 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| AzureDiagnostics | 🟠 15.17 | 0 | 0 | ⚠️ 0 | Basic | ✅ Yes | 🔴 Strong (DL-eligible) |
| AADManagedIdentitySignInLogs | 🟠 8.87 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| Perf | 🟠 4.20 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| DeviceInfo | 🟠 3.73 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| DeviceNetworkInfo | 🟡 2.57 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| DeviceImageLoadEvents | 🟡 1.87 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| AADProvisioningLogs | 🟡 1.28 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| DeviceFileCertificateInfo | 🟡 1.17 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| SentinelHealth | 🟡 0.65 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| AADUserRiskEvents | 🟡 0.51 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| WindowsFirewall | 🟡 0.42 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| W3CIISLog | 🟡 0.35 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| McasShadowItReporting | 🟢 0.28 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| WindowsEvent | 🟢 0.12 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |
| Event | 🟢 0.05 | 0 | 0 | ⚠️ 0 | Analytics | ✅ Yes | 🔴 Strong (DL-eligible) |

**Combined potential:** ~59.44 GB/month across 16 tables. The top 3 candidates (StorageBlobLogs, AzureDiagnostics, AADManagedIdentitySignInLogs) account for 42.24 GB/month.

> ⚠️ **Note on DeviceInfo and DeviceNetworkInfo:** These tables are commonly used for ad-hoc threat hunting even without persistent AR rules. Confirm with the SOC team before migrating to Data Lake, as Data Lake queries have different performance characteristics and per-query costs.

#### 🟠 Zero-Rule Tables — Not Eligible or Unknown

| DataType | 30d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |
|----------|-------|----------|----------|-------------|------|-------------|----------|
| AppTraces | 🟠 10.50 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| AppDependencies | 🟠 5.13 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| AppPerformanceCounters | 🟡 2.33 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| AppRequests | 🟡 1.87 | 0 | 0 | ⚠️ 0 | Analytics | ❓ Unknown | 🟠 Not eligible/unknown |
| AlertEvidence | 🟡 1.75 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| AlertInfo | 🟡 1.40 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| Signinlogs_Anomalies_KQL_CL | 🟡 0.47 | 0 | 0 |  0 | Data Lake | 📕 KQL | 🔵 KQL Job |
| ADFSSignInLogs | 🟢 0.23 | 0 | 0 | ⚠️ 0 | Analytics | ❓ Unknown | 🟠 Not eligible/unknown |
| DynamicEventCollection | 🟢 0.19 | 0 | 0 | ⚠️ 0 | Analytics | ❓ Unknown | 🟠 Not eligible/unknown |
| SecurityRecommendation | 🟢 0.09 | 0 | 0 | ⚠️ 0 | Analytics | ❌ No | 🟠 Not eligible/unknown |
| ContainerLogV2 | 🟢 0.04 | 0 | 0 | ⚠️ 0 | Analytics | ❓ Unknown | 🟠 Not eligible/unknown |

**Application Insights tables** (AppTraces, AppDependencies, AppPerformanceCounters, AppRequests) total ~19.83 GB/month. These are not DL-eligible. Evaluate whether Application Insights data is needed in the Sentinel workspace or if it should be routed to a dedicated Application Insights resource instead.

#### 🟢 Tables with Rules — Keep on Analytics

| DataType | 30d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |
|----------|-------|----------|----------|-------------|------|-------------|----------|
| CommonSecurityLog | 🔴 291.67 | 10 | 0 | 🟢 10 | Analytics | ✅ Yes | 🟢 Keep (10 rules) |
| Syslog | 🔴 214.67 | 12 | 0 | 🟢 12 | Analytics | ✅ Yes | 🟢 Keep (12 rules) |
| SecurityEvent | 🔴 158.67 | 45 | 0 | 🟢 45 | Analytics | ✅ Yes | 🟢 Keep (45 rules) |
| SigninLogs | 🔴 121.33 | 28 | 2 | 🟢 30 | Analytics | ✅ Yes | 🟢 Keep (30 rules) |
| AADNonInteractiveUserSignInLogs | 🔴 91.00 | 3 | 0 | 🟡 3 | Analytics | ✅ Yes | 🟢 Keep (3 rules) |
| DeviceProcessEvents | 🔴 66.50 | 26 | 2 | 🟢 28 | Analytics | ✅ Yes | 🟢 Keep (28 rules) |
| AzureActivity | 🔴 58.33 | 8 | 0 | 🟡 8 | Analytics | ❌ No | 🟢 Keep (8 rules) |
| DeviceNetworkEvents | 🔴 54.83 | 16 | 2 | 🟢 18 | Analytics | ✅ Yes | 🟢 Keep (18 rules) |
| AuditLogs | 🔴 45.50 | 26 | 0 | 🟢 26 | Analytics | ✅ Yes | 🟢 Keep (26 rules) |
| DeviceFileEvents | 🔴 39.67 | 18 | 2 | 🟢 20 | Analytics | ✅ Yes | 🟢 Keep (20 rules) |
| OfficeActivity | 🔴 33.83 | 10 | 0 | 🟢 10 | Analytics | ✅ Yes | 🟢 Keep (10 rules) |
| AWSCloudTrail | 🔴 30.33 | 3 | 0 | 🟡 3 | Data Lake | ✅ Yes | 🔴 Detection gap (non-XDR) |
| CloudAppEvents | 🟠 25.20 | 8 | 1 | 🟡 9 | Analytics | ✅ Yes | 🟢 Keep (9 rules) |
| DeviceEvents | 🟠 22.17 | 9 | 0 | 🟡 9 | Analytics | ✅ Yes | 🟢 Keep (9 rules) |
| EmailEvents | 🟠 13.53 | 8 | 2 | 🟢 10 | Analytics | ✅ Yes | 🟢 Keep (10 rules) |
| DeviceRegistryEvents | 🟠 11.20 | 7 | 0 | 🟡 7 | Analytics | ✅ Yes | 🟢 Keep (7 rules) |
| DeviceLogonEvents | 🟠 7.47 | 5 | 1 | 🟡 6 | Analytics | ✅ Yes | 🟢 Keep (6 rules) |
| SecurityAlert | 🟠 6.53 | 5 | 0 | 🟡 5 | Analytics | ✅ Yes | 🟢 Keep (5 rules) |
| AADServicePrincipalSignInLogs | 🟠 5.13 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟣 Split candidate |
| IdentityLogonEvents | 🟠 4.20 | 5 | 0 | 🟡 5 | Analytics | ❌ No | 🟢 Keep (5 rules) |
| SecurityIncident | 🟠 3.27 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| EmailAttachmentInfo | 🟡 2.80 | 0 | 1 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| EmailUrlInfo | 🟡 2.33 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| IdentityQueryEvents | 🟡 2.22 | 1 | 0 | 🟠 1 | Analytics | ❌ No | 🟢 Keep (1 rules) |
| IdentityDirectoryEvents | 🟡 1.98 | 1 | 0 | 🟠 1 | Analytics | ❌ No | 🟢 Keep (1 rules) |
| EmailPostDeliveryEvents | 🟡 1.05 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| MicrosoftGraphActivityLogs | 🟡 0.93 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| UrlClickEvents | 🟡 0.89 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| LAQueryLogs | 🟡 0.82 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |
| ThreatIntelligenceIndicator | 🟡 0.70 | 1 | 0 | 🟠 1 | Analytics | ❌ No | 🟢 Keep (1 rules) |
| ConfigurationChange | 🟡 0.58 | 1 | 0 | 🟠 1 | Analytics | ❌ No | 🟢 Keep (1 rules) |
| GCPAuditLogs | 🟡 0.47 | 1 | 0 | 🟠 1 | Analytics | ✅ Yes | 🟢 Keep (1 rules) |

**🔴 Detection gap — AWSCloudTrail:** This table is on Data Lake tier with 3 active AR rules. AR rules cannot execute against Data Lake tables. This is a **non-XDR** table, so Custom Detection rules are also not an option. Remediation: move AWSCloudTrail back to Analytics tier, or disable the 3 rules if AWS monitoring is handled externally.

**🟣 Split candidate — AADServicePrincipalSignInLogs:** 1 rule, 5.13 GB/month, DL-eligible. A split ingestion configuration could route non-rule-matched rows to Data Lake while keeping rule-relevant rows on Analytics — but at this volume the complexity may not be justified.

#### 🔵 Already on Data Lake

| DataType | 30d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |
|----------|-------|----------|----------|-------------|------|-------------|----------|
| SecurityEvent_Aux_CL | 🟠 3.50 | 0 | 0 |  0 | Data Lake | ✅ Yes | 🔵 Already DL |
| SecurityEvent_SPLT_CL | 🟡 1.87 | 0 | 0 |  0 | Data Lake | ✅ Yes | 🔵 Already DL |

These are legitimate split-ingestion tables for SecurityEvent. SecurityEvent_Aux_CL and SecurityEvent_SPLT_CL receive the long-retention/lower-priority subset of SecurityEvent data on Data Lake tier.

🔴 DL candidate (zero rules, eligible) · 🟠 Not eligible/unknown · 🟢 Keep Analytics (has rules) · 🟣 Split candidate · ❗ Detection gap — XDR (CD-convertible) or non-XDR (must move back/disable) · 🔵 Already on DL · 📕 KQL Job output

### 7b. ⚡ Quick Wins

| # | Action | Table | Est. Savings | Effort |
|---|--------|-------|-------------|--------|
| 1 | **Disable "Deprecated - Old brute force detection v1"** — Explicitly marked deprecated, 4 failures in 90d. Ensure replacement rule is active. | SecurityEvent | Reduced noise | Minutes |
| 2 | **Move StorageBlobLogs to Data Lake** — 18.20 GB/month, 0 rules, DL-eligible. Pure storage telemetry with no detections. | StorageBlobLogs | ~18 GB/month | Minutes (portal) |
| 3 | **Move AzureDiagnostics to Data Lake** — Already on Basic (lower cost), but DL would further reduce costs. 15.17 GB/month, 0 rules. | AzureDiagnostics | ~15 GB/month | Minutes (portal) |
| 4 | **Move AADManagedIdentitySignInLogs to Data Lake** — 8.87 GB/month, 0 rules, DL-eligible. Managed identity sign-ins are background system activity. | AADManagedIdentitySignInLogs | ~9 GB/month | Minutes (portal) |
| 5 | **Investigate OfficeActivity connector** — Verify data connector health in the Sentinel portal. Check for DCR changes, Office 365 license changes, or tenant-level audit configuration modifications. | OfficeActivity | Detection coverage restoration | <1 hour |

### 7c. 🔧 Medium-Term Optimizations

| # | Action | Table | Est. Savings | Effort |
|---|--------|-------|-------------|--------|
| 1 | **Apply DCR to filter zero-rule SecurityEvent EventIDs** — Create a DCR transformation to exclude EventIDs 4689, 4634, 5156, 5158, 4627, 4662, 4658. These 7 EventIDs contribute ~1,067 GB/month with 0 detection rules. Route filtered events to SecurityEvent_Aux_CL (Data Lake) if long-term retention is needed. | SecurityEvent | ~1,067 GB/month | DCR deployment |
| 2 | **Filter CSL TRAFFIC allow events** — TRAFFIC allow contributes 437 GB/month (30% of CSL) with only 1 broad rule. Apply a DCR transformation to sample or exclude routine allow events while preserving deny/drop for the "Anomalous firewall traffic pattern" rule. Alternatively, route TRAFFIC allow to Data Lake via split ingestion. | CommonSecurityLog | Up to ~437 GB/month | DCR + rule validation |
| 3 | **Filter Syslog container orchestration processes** — dockerd (98 GB), kubelet (84 GB), containerd (56 GB), kube-apiserver (42 GB), etcd (28 GB), coredns (28 GB) total ~336 GB/month with 0 rules. Apply DCR process-name filter or route Kubernetes daemon logs to a dedicated workspace. | Syslog | ~336 GB/month | DCR deployment |
| 4 | **Investigate Syslog/CSL firewall overlap** — Firewall hosts (fw-edge-01, fw-core-01, fw-edge-02) send ~269 GB/month to Syslog (local0/local1/local3 facilities) and CSL receives CEF-formatted data from Palo Alto/Fortinet/Cisco. If both streams originate from the same appliances, the Syslog stream may be redundant. Audit firewall logging configuration to eliminate duplication. | Syslog + CSL | Up to ~269 GB/month | Investigation + config |
| 5 | **Resolve AWSCloudTrail tier mismatch** — Move back to Analytics tier to restore detection capability for 3 active rules, or disable the rules if AWS monitoring is handled by a dedicated cloud SIEM. | AWSCloudTrail | Detection coverage restoration | Tier change |
| 6 | **Resolve "GCP privilege escalation" rule failures** — 8 failures correlating with GCPAuditLogs volume spike (+352%). Investigate whether the volume increase causes query timeouts. Optimize the rule query or increase the query timeout. | GCPAuditLogs | Rule reliability | Query optimization |

### 7d. 🔄 Ongoing Maintenance

| # | Action | Frequency |
|---|--------|-----------|
| 1 | **Review alert-producing rule thresholds** — Top 3 rules (Brute force, Unknown IP, Failed sign-ins) generated 921 alerts (47% of total). Evaluate if thresholds need tuning to reduce alert fatigue. | Monthly |
| 2 | **Monitor OfficeActivity ingestion recovery** — After connector investigation, set up a monitoring alert for sustained drops >40% on tables with ≥5 rules. | Weekly until resolved |
| 3 | **Audit disabled rules** — 24 disabled rules (22 AR + 2 CD). Review whether these should be re-enabled, updated, or deleted. | Quarterly |
| 4 | **Re-evaluate DL migration candidates** — As new detection rules are authored, re-check that migrated tables don't gain rule dependencies. | Quarterly |
| 5 | **Validate E5 license count** — Verify actual E5 license count against the 15,010 break-even threshold. Adjust benefit calculations accordingly. | On license renewal |

---

## 8. Appendix

### 8a. Query Reference

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

### 8b. Data Freshness

- **Scratchpad generated:** 2026-02-22T10:21:30Z
- **Data source:** Synthetic test data (`.github/skills/sentinel-ingestion-report/test-data/enterprise`)
- **Query execution time:** 0 seconds (synthetic mode — no Azure API calls)
- **Total queries executed:** 23

### 8c. Methodology

1. **Phase 1 (Usage Summary):** Aggregated `Usage` table data by DataType over the 90-day window. Daily trend computed from per-day rollups. Non-billable tables identified by IsBillable flag.

2. **Phase 2 (Deep Dives):** SecurityEvent broken down by Computer and EventID over the 30-day deep-dive window. Syslog analyzed by source host, facility, facility×severity, and process name. CommonSecurityLog broken down by DeviceVendor/DeviceProduct and Activity/LogSeverity/DeviceAction.

3. **Phase 3 (Rules & Tiers):** Analytic Rule inventory retrieved via Azure REST API. Custom Detection rules retrieved via Microsoft Graph API. Table tier classification obtained via Azure CLI (`az monitor log-analytics workspace table show`).

4. **Phase 4 (Detection Coverage):** Cross-referenced rule queries against table names and deep-dive values (EventIDs, Activities, Vendors) to determine per-table and per-value rule coverage. SentinelHealth queried for rule execution success/failure rates. SecurityAlert queried for alert-producing rule statistics.

5. **Phase 5 (Anomalies & Cost):** 24-hour anomaly detection compared last 24h volume against 7-day average. Week-over-week comparison used rolling 7-day windows. DL eligibility checked against Microsoft documentation and `az` CLI. License benefits estimated using DfS P2 pool (500 MB/server/day) and E5 data grant (5 MB/license/day).

### 8d. Limitations

- **Synthetic data:** All values in this report are derived from synthetic test data and do not reflect actual production workspace metrics.
- **E5 license count unknown:** The E5 benefit calculation assumes sufficient licenses exist. Verify actual license count.
- **DfS P2 activation unknown:** The DfS P2 benefit requires an active Defender for Servers P2 plan. Verify plan status.
- **Cross-reference precision:** Table-level and value-level rule cross-referencing uses string matching against rule query text. Rules using dynamic table references, functions, or ASIM parsers may not be captured.
- **WoW comparison sensitivity:** Week-over-week changes can be amplified by partial weeks at the window boundaries.
- **Deep-dive window:** The 30-day deep-dive uses the most recent 30 days of the 90-day window. Volume patterns may differ in earlier periods.

---

*Report generated: 2026-02-22T10:21:30Z | Skill: sentinel-ingestion-report v2 | Mode: 90-day markdown*
