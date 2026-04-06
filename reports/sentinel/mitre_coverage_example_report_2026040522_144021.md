# MITRE ATT&CK Coverage Report

**Generated:** 2026-04-05
**Workspace:** Contoso SOC
**Workspace ID:** a1b2c3d4-e5f6-7890-abcd-ef1234567890
**ATT&CK Version:** Enterprise v16.1 (216 techniques, 475 sub-techniques)
**Alert/Incident Lookback:** 30 days

*This report analyzes detection coverage against the MITRE ATT&CK Enterprise framework based on rule MITRE tagging and operational alert data. Coverage percentages reflect enabled rules with MITRE tags — actual detection efficacy depends on data source availability, rule quality, and adversary behavior. All recommendations require human review and validation against organizational threat priorities before implementation.*

> *Why this report?* The built-in [Sentinel MITRE ATT&CK dashboard](https://security.microsoft.com/sentinel/mitre) ([docs](https://learn.microsoft.com/en-us/azure/sentinel/mitre-coverage?tabs=defender-portal)) only shows coverage for active Analytic Rules and Hunting Queries — it does **not** account for product-native platform alerts (MDE, MDI, MDCA, etc.), Custom Detection rules, or inherent Defender XDR coverage capabilities. This report fills that gap by combining rule-based coverage with platform alert evidence (Tier 1/2/3) and [SOC Optimization](https://security.microsoft.com/sentinel/precision) threat scenario alignment to provide a comprehensive view of actual detection posture.
>
> *Custom Detections migration:* Microsoft is [unifying detection authoring](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/custom-detections-are-now-the-unified-experience-for-creating-detections-in-micr/4463875) around Custom Detections as the preferred rule type — offering unlimited real-time detections, lower ingestion costs, and seamless Defender XDR integration. This report already inventories Custom Detections alongside Analytic Rules to ensure coverage tracking remains accurate as the migration progresses.

---

## 1. Executive Summary

### 🎯 MITRE Coverage Score: **45.1/100** — 🟡 Moderate

| Dimension | Score | Weight | Interpretation |
|-----------|-------|--------|----------------|
| **Breadth** | 31/100 | 25% | 40/250 rule-based (17.6% readiness-weighted) · 128/250 combined (51.2%) — blended 60/40 |
| **Balance** | 85.7/100 | 10% | 12/14 tactics have ≥1 enabled rule |
| **Operational** | 20/100 | 30% | 21 unique MITRE-tagged rules produced alerts in 30d (out of 107 MITRE-tagged enabled rules) |
| **Tagging** | 95.4/100 | 15% | 124/130 total rules (enabled + disabled) have MITRE ATT&CK tags |
| **SOC Alignment** | 42.1/100 | 20% | SOC coverage scenarios partially addressed |

ℹ️ Breadth scores are naturally low — the ATT&CK framework contains 216+ techniques, many of which are endpoint-specific or pre-compromise with limited Sentinel visibility. Breadth uses a blended formula (60% rule-based + 40% combined) to credit platform detections and purple team TTP testing while maintaining pressure on custom rule investment. Prioritize coverage by threat scenario relevance (see §4) rather than pursuing raw percentage.

⚠️ Breadth adjusted: 1 phantom technique subtracted from rule coverage — T1537 is only covered by rules targeting AWSCloudTrail on Data Lake tier (analytics rules structurally cannot query). Raw rule coverage: 40/250. Effective rule coverage: 39/250 (15.6%). Phantom techniques: T1537.

### 📊 Detection Inventory

| Metric | Count |
|--------|-------|
| Total Analytic Rules | 120 |
| Enabled AR (tagged / untagged) | 98 (96 tagged / 2 untagged) |
| Disabled AR | 22 |
| Custom Detections (total) | 10 |
| Enabled CD (MITRE-tagged / untagged) | 9 (9 tagged / 0 untagged) |
| Disabled CD | 1 |
| **Combined Enabled Rules** | **107** |
| Rules with MITRE tags | 124/130 total rules (inc. disabled) |
| Untagged rules | 6 |
| Techniques covered (rule-based) | 40/250 (16%) |
| Tactics with ≥1 rule | 12/14 |
| Data readiness | 75/84 enabled rules have all table dependencies flowing (89.3%). 2 rules target non-Analytics tier tables (phantom coverage). Connector health: 16 monitored, 0 failing, 1 degraded (from SentinelHealth M8) |

### 🛡️ Platform Coverage

Beyond custom rules, Defender XDR products provide built-in detection capabilities mapped by the [Center for Threat-Informed Defense (CTID)](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/).

| Layer | Techniques | Description |
|-------|-----------|-------------|
| 🟢 **Tier 1: Alert-Proven** | 67 | Platform products triggered SecurityAlerts with MITRE attribution in the last 30d |
| 🔵 **Tier 2: Deployed Capability** | 30 | Active products claim detection capability per CTID mapping, but no alerts in window |
| ⬜ **Tier 3: Catalog Capability** | 7 | CTID maps coverage, but the product has no alert evidence in this workspace |
| **Rule-Based** | 40 | Enabled analytic rules + custom detections with MITRE tags |
| **Combined (Rule-Based + T1 + T2)** | **128/250 (51.2%)** | Unique techniques covered by any active detection source |

**Active products detected:** Microsoft Entra ID Protection, Microsoft Defender for Cloud, Microsoft Defender XDR, Microsoft 365 Insider Risk Management, Microsoft Application Protection, Microsoft Defender for Cloud Apps, Microsoft Purview DLP, Microsoft Defender for Endpoint, Microsoft Defender for Identity, Microsoft Defender for Office 365

> *CTID Mapping v07/18/2025 (ATT&CK v16.1). Platform coverage is supplementary — custom rules provide tailored, environment-specific detections that platform-native coverage cannot replace.*

### 🎯 Top 3 Recommendations

| # | Priority | Recommendation | Impact |
|---|----------|----------------|--------|
| 1 | 🔴 | **Address Credential Exploitation gap** — SOC Optimization shows 3.8% completion rate (23/609 active detections) | Largest absolute gap (586 missing); key tactic gaps in Collection, Exfiltration, Impact |
| 2 | 🔴 | **Address Network Infiltration gap** — SOC Optimization shows 3.7% completion rate (9/245 active detections) | 236 missing detections; key gaps in Defense Evasion, Execution, Credential Access |
| 3 | 🟠 | **Reduce paper tiger rules** — 85 enabled MITRE-tagged rules produced 0 alerts in 30 days (Operational score: 20/100) | Validate rule logic, check data source availability, or decommission stale Content Hub templates |

---

## 2. Tactic Coverage Matrix

> ℹ️ Compare with the built-in [Sentinel MITRE ATT&CK dashboard](https://security.microsoft.com/sentinel/mitre) which shows Analytic Rule and Hunting Query coverage only. This table adds Custom Detection (CD) rules for a complete rule-based view; see §5.1 for combined rule + platform coverage.

| # | Badge | Tactic | Enabled Rules | Framework Techniques | Covered Techniques | Coverage % |
|---|-------|--------|---------------|---------------------|--------------------|------------|
| 1 | 🔴 | Reconnaissance | 0 | 11 | 0 | 0% |
| 2 | 🟠 | Resource Development | 1 | 8 | 1 | 12.5% |
| 3 | 🔵 | Initial Access | 25 | 11 | 5 | 45.5% |
| 4 | 🟡 | Execution | 7 | 17 | 3 | 17.6% |
| 5 | 🟡 | Persistence | 11 | 23 | 6 | 26.1% |
| 6 | 🟡 | Privilege Escalation | 16 | 14 | 4 | 28.6% |
| 7 | 🟠 | Defense Evasion | 11 | 47 | 7 | 14.9% |
| 8 | 🟡 | Credential Access | 9 | 17 | 3 | 17.6% |
| 9 | 🟠 | Discovery | 9 | 34 | 3 | 8.8% |
| 10 | 🔵 | Lateral Movement | 3 | 9 | 3 | 33.3% |
| 11 | 🔴 | Collection | 0 | 17 | 0 | 0% |
| 12 | 🟠 | Command and Control | 27 | 18 | 1 | 5.6% |
| 13 | 🟡 | Exfiltration | 4 | 9 | 2 | 22.2% |
| 14 | 🟠 | Impact | 5 | 15 | 2 | 13.3% |
| | | **TOTAL** | **128** | **250** | **40** | **16%** |

> ℹ️ **TOTAL row note:** The "Enabled Rules" column in the TOTAL row sums per-tactic rule counts. Because a single rule can be tagged with multiple tactics (e.g., T1078 appears under InitialAccess, Persistence, PrivilegeEscalation, DefenseEvasion), this sum is higher than the Combined Enabled Rules count (107) in §1. The per-tactic counts are correct for assessing each tactic's depth.

Two tactics have zero rule-based coverage: **Reconnaissance** and **Collection**. Reconnaissance is a pre-compromise phase with inherently limited Sentinel visibility (⬜ inherent blind spot). Collection, however, is a post-compromise tactic where detections are feasible — platform coverage fills some of this gap (8/17 techniques combined, see §5.1), but custom rules targeting T1114 (Email Collection) and T1213 (Data from Information Repositories) would add valuable Sentinel-native alerting. Command and Control has the most rules (27), but they are heavily concentrated on a single technique (T1071 Application Layer Protocol via TI-mapping templates), covering only 1/18 C2 techniques (5.6%).

📊 **Combined Coverage (Rule-Based + Platform Tier 1/2):** 128/250 techniques (51.2%). Platform-native detections add 88 techniques beyond custom rules alone.

---

## 3. Technique Deep Dive

### Per-Tactic Technique Tables

#### Reconnaissance (0/11 rules — 0% · 1/11 combined — 9.1%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| 🔵 T1598 Phishing for Information | 4 | 0 | — | Tier 2: MDO |
| ❌ T1589 Gather Victim Identity Information | 3 | 0 | — | — |
| ❌ T1590 Gather Victim Network Information | 6 | 0 | — | — |
| ❌ T1591 Gather Victim Org Information | 4 | 0 | — | — |
| ❌ T1592 Gather Victim Host Information | 4 | 0 | — | — |
| ❌ T1593 Search Open Websites/Domains | 3 | 0 | — | — |
| ❌ T1594 Search Victim-Owned Websites | 0 | 0 | — | — |
| ❌ T1595 Active Scanning | 3 | 0 | — | — |
| ❌ T1596 Search Open Technical Databases | 5 | 0 | — | — |
| ❌ T1597 Search Closed Sources | 2 | 0 | — | — |
| ❌ T1681 Search Threat Vendor Data | 0 | 0 | — | — |

<!-- ZERO_COVERAGE -->
Reconnaissance is an inherent blind spot for SIEM-based detection — all 11 techniques describe attacker activity that occurs *outside* the monitored environment (scanning, OSINT gathering, social engineering research). The only platform signal is T1598 (Phishing for Information) via MDO's Tier 2 deployed capability. Compensating controls include threat intelligence feeds and brand monitoring services.

#### Resource Development (1/8 rules — 12.5% · 2/8 combined — 25%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1584 Compromise Infrastructure | 8 | 1 | [AR] Custom BTP - Malware detected in app dev space | — |
| 🟢 T1586 Compromise Accounts | 3 | 0 | [MDE] Possible logon from unmanaged or untrusted endpoint | Tier 1: MDE |
| ⬜ T1585 Establish Accounts | 3 | 0 | — | ⬜ Tier 3 |
| ❌ T1583 Acquire Infrastructure | 8 | 0 | — | — |
| ❌ T1587 Develop Capabilities | 4 | 0 | — | — |
| ❌ T1588 Obtain Capabilities | 7 | 0 | — | — |
| ❌ T1608 Stage Capabilities | 6 | 0 | — | — |
| ❌ T1650 Acquire Access | 0 | 0 | — | — |

#### Initial Access (5/11 rules — 45.5% · 6/11 combined — 54.5%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1078 Valid Accounts | 4 | 12 | [AR] Bulk Changes to Privileged Account Permissions; [AR] Admin promotion after Role Management Application Permission Grant; [AR] Attempt to bypass conditional access rule in Microsoft Entra ID; [AR] Anomalous sign-in location by user account and authenticating application; [AR] Correlate Unfamiliar sign-in properties & atypical travel alerts; +7 rules, 10 platform | Tier 1: MDE, AADIP, MDCA, MXDR, MDI |
| ✅ T1566 Phishing | 4 | 8 | [AR] TI map Domain entity to EmailUrlInfo; [AR] TI map Domain entity to EmailEvents; [AR] TI map Email entity to EmailEvents; [AR] TI map Email entity to SecurityEvent; [AR] Dataverse - TI map URL to DataverseActivity; +3 rules, 10 platform | Tier 1: MDO, MXDR, MDE |
| ✅ T1133 External Remote Services | 0 | 3 | [AR] Claroty - Login to uncommon location; [AR] Dataverse - TI map IP to DataverseActivity; [AR] Detect threat information in web requests (ASIM Web Session); [MDE] Possible logon from unmanaged or untrusted endpoint; [MDE] Suspicious logon from remote device | Tier 1: MDE |
| ✅ T1190 Exploit Public-Facing Application | 0 | 3 | [AR] Claroty - Login to uncommon location; [AR] App Gateway WAF - SQLi Detection; [AR] Detect threat information in web requests (ASIM Web Session) | — |
| ✅ T1199 Trusted Relationship | 0 | 2 | [AR] Azure Portal sign in from another Azure Tenant; [AR] Dataverse - TI map IP to DataverseActivity | Tier 2: MDCA |
| 🔵 T1189 Drive-by Compromise | 0 | 0 | — | Tier 2: MDCA, MDO |
| ❌ T1091 Replication Through Removable Media | 0 | 0 | — | — |
| ❌ T1195 Supply Chain Compromise | 3 | 0 | — | — |
| ❌ T1200 Hardware Additions | 0 | 0 | — | — |
| ❌ T1659 Content Injection | 0 | 0 | — | — |
| ❌ T1669 Wi-Fi Networks | 0 | 0 | — | — |

Initial Access is the strongest rule-based tactic at 45.5%, with T1078 (Valid Accounts) driving much of the coverage depth (12 rules). Combined with platform Tier 1/2, this reaches 54.5%.

#### Execution (3/17 rules — 17.6% · 9/17 combined — 52.9%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1204 User Execution | 5 | 2 | [AR] Dataverse - TI map URL to DataverseActivity; [AR] Insider Risk_Microsoft Purview Insider Risk Management Alert Observed; [MDE] Suspicious file similar to known attacker malware; [MDE] Suspicious file or content ingress; [MDE] Suspicious script launched; +4 platform | Tier 1: MDE |
| ✅ T1059 Command and Scripting Interpreter | 13 | 1 | [AR] App Gateway WAF - SQLi Detection; [MDE] Powershell execution detected; [MXDR] Suspicious script-driven DLL creation; [MDE] Suspicious script launched; [MDE] Suspicious shell command execution; +3 platform | Tier 1: MDE, MXDR |
| ✅ T1072 Software Deployment Tools | 0 | 1 | [AR] Custom BTP - Malware detected in app dev space | ⬜ Tier 3 |
| 🟢 T1047 Windows Management Instrumentation | 0 | 0 | [MDE] Suspicious remote activity; [MDE] Suspicious WMI process creation | Tier 1: MDE |
| 🟢 T1053 Scheduled Task/Job | 5 | 0 | [MDE] Suspicious scheduled task | Tier 1: MDE |
| 🟢 T1106 Native API | 0 | 0 | [MDE] LSASS process memory modified; [MDE] Possible pass-the-hash authentication; [MDE] Potential human-operated malicious activity; [MDE] Compromised account conducting hands-on-keyboard attack | Tier 1: MDE |
| 🟢 T1559 Inter-Process Communication | 3 | 0 | [MDE] Suspicious piped command launched; [MDE] Suspicious process collected data from local system | Tier 1: MDE |
| 🟢 T1569 System Services | 3 | 0 | [MDE] PsExec launched a command on a remote device; [MDE] Suspicious remote activity; [MDE] Suspicious service launched; [MDE] Suspicious file registered as a service; [MDE] Potential human-operated malicious activity | Tier 1: MDE |
| 🟢 T1651 Cloud Administration Command | 0 | 0 | [MDC] Suspicious Run Command usage was detected on your virtual machine (Preview); [MXDR] Azure VM extension activity followed by ransomware or hands-on-keyboard attack | Tier 1: MDC, MXDR |
| ❌ T1129 Shared Modules | 0 | 0 | — | — |
| ❌ T1203 Exploitation for Client Execution | 0 | 0 | — | — |
| ❌ T1609 Container Administration Command | 0 | 0 | — | — |
| ❌ T1610 Deploy Container | 0 | 0 | — | — |
| ❌ T1648 Serverless Execution | 0 | 0 | — | — |
| ❌ T1674 Input Injection | 0 | 0 | — | — |
| ❌ T1675 ESXi Administration Command | 0 | 0 | — | — |
| ❌ T1677 Poisoned Pipeline Execution | 0 | 0 | — | — |

Platform coverage is strong here — MDE covers 6 additional Execution techniques beyond custom rules, lifting combined coverage from 17.6% to 52.9%.

#### Persistence (6/23 rules — 26.1% · 13/23 combined — 56.5%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1078 Valid Accounts | 4 | 12 | [AR] Bulk Changes to Privileged Account Permissions; [AR] Admin promotion after Role Management Application Permission Grant; [AR] Attempt to bypass conditional access rule in Microsoft Entra ID; [AR] Anomalous sign-in location by user account and authenticating application; [AR] Correlate Unfamiliar sign-in properties & atypical travel alerts; +7 rules, 10 platform | Tier 1: MDE, AADIP, MDCA, MXDR, MDI |
| ✅ T1098 Account Manipulation | 7 | 4 | [AR] Mail.Read Permissions Granted to Application; [AR] Admin promotion after Role Management Application Permission Grant; [AR] Attempt to bypass conditional access rule in Microsoft Entra ID; [AR] Malicious Inbox Rule; [MDE] Suspicious addition of an SSH key; +2 platform | Tier 1: MDE, MXDR, MDCA |
| ✅ T1133 External Remote Services | 0 | 3 | [AR] Claroty - Login to uncommon location; [AR] Dataverse - TI map IP to DataverseActivity; [AR] Detect threat information in web requests (ASIM Web Session); [MDE] Possible logon from unmanaged or untrusted endpoint; [MDE] Suspicious logon from remote device | Tier 1: MDE |
| ✅ T1136 Create Account | 3 | 1 | [AR] Cross-tenant Access Settings Organization Inbound Collaboration Settings Changed; [MDE] Suspicious account creation | Tier 1: MDE |
| ✅ T1197 BITS Jobs | 0 | 1 | [CD] Bitsadmin Abuse by Domain User Account | — |
| ✅ T1574 Hijack Execution Flow | 12 | 1 | [AR] Dataverse - TI map URL to DataverseActivity | Tier 2: MDCA |
| 🟢 T1053 Scheduled Task/Job | 5 | 0 | [MDE] Suspicious scheduled task | Tier 1: MDE |
| 🟢 T1112 Modify Registry | 0 | 0 | [MDE] Suspicious registry modification | Tier 1: MDE |
| 🟢 T1543 Create or Modify System Process | 5 | 0 | [MDE] Suspicious remote activity; [MDE] 'Kekeo' malware was detected during lateral movement; [MDE] Hands-on-keyboard attack involving multiple devices; [MDE] Suspicious file registered as a service; [MDE] Potential human-operated malicious activity | Tier 1: MDE |
| 🟢 T1547 Boot or Logon Autostart Execution | 14 | 0 | [MDE] LSASS process memory modified; [MDE] Possible pass-the-hash authentication; [MXDR] Suspicious persistence through registry modification; [MDE] Potential human-operated malicious activity; [MDE] Compromised account conducting hands-on-keyboard attack | Tier 1: MDE, MXDR |
| 🔵 T1546 Event Triggered Execution | 18 | 0 | — | Tier 2: DLP |
| 🔵 T1554 Compromise Host Software Binary | 0 | 0 | — | Tier 2: MDC |
| 🔵 T1556 Modify Authentication Process | 9 | 0 | — | Tier 2: MDCA, MDI, MXDR |
| ⬜ T1137 Office Application Startup | 6 | 0 | — | ⬜ Tier 3 |
| ❌ T1037 Boot or Logon Initialization Scripts | 5 | 0 | — | — |
| ❌ T1176 Software Extensions | 2 | 0 | — | — |
| ❌ T1205 Traffic Signaling | 2 | 0 | — | — |
| ❌ T1505 Server Software Component | 6 | 0 | — | — |
| ❌ T1525 Implant Internal Image | 0 | 0 | — | — |
| ❌ T1542 Pre-OS Boot | 5 | 0 | — | — |
| ❌ T1653 Power Settings | 0 | 0 | — | — |
| ❌ T1668 Exclusive Control | 0 | 0 | — | — |
| ❌ T1671 Cloud Application Integration | 0 | 0 | — | — |

#### Privilege Escalation (4/14 rules — 28.6% · 12/14 combined — 85.7%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1078 Valid Accounts | 4 | 12 | [AR] Bulk Changes to Privileged Account Permissions; [AR] Admin promotion after Role Management Application Permission Grant; [AR] Attempt to bypass conditional access rule in Microsoft Entra ID; [AR] Anomalous sign-in location by user account and authenticating application; [AR] Correlate Unfamiliar sign-in properties & atypical travel alerts; +7 rules, 10 platform | Tier 1: MDE, AADIP, MDCA, MXDR, MDI |
| ✅ T1484 Domain or Tenant Policy Modification | 2 | 10 | [AR] Creation of Glue policy and then privilege escalation; [AR] CloudFormation policy created then used for privilege escalation; [AR] Creation of CRUD DynamoDB policy and then privilege escalation.; [AR] Creation of CRUD KMS policy and then privilege escalation; [AR] Creation of CRUD Lambda policy and then privilege escalation; +5 rules | Tier 2: MDCA, MXDR |
| ✅ T1098 Account Manipulation | 7 | 4 | [AR] Mail.Read Permissions Granted to Application; [AR] Admin promotion after Role Management Application Permission Grant; [AR] Attempt to bypass conditional access rule in Microsoft Entra ID; [AR] Malicious Inbox Rule; [MDE] Suspicious addition of an SSH key; +2 platform | Tier 1: MDE, MXDR, MDCA |
| ✅ T1574 Hijack Execution Flow | 12 | 1 | [AR] Dataverse - TI map URL to DataverseActivity | Tier 2: MDCA |
| 🟢 T1053 Scheduled Task/Job | 5 | 0 | [MDE] Suspicious scheduled task | Tier 1: MDE |
| 🟢 T1055 Process Injection | 12 | 0 | [MDE] Suspicious file or content ingress; [MDE] Meterpreter post-exploitation tool | Tier 1: MDE |
| 🟢 T1134 Access Token Manipulation | 5 | 0 | [MDE] Possible pass-the-hash authentication; [MDE] Malicious credential theft tool execution detected; [MDE] Compromised account conducting hands-on-keyboard attack; [MDE] Potential human-operated malicious activity; [MDE] SID history injection | Tier 1: MDE |
| 🟢 T1543 Create or Modify System Process | 5 | 0 | [MDE] Suspicious remote activity; [MDE] 'Kekeo' malware was detected during lateral movement; [MDE] Hands-on-keyboard attack involving multiple devices; [MDE] Suspicious file registered as a service; [MDE] Potential human-operated malicious activity | Tier 1: MDE |
| 🟢 T1547 Boot or Logon Autostart Execution | 14 | 0 | [MDE] LSASS process memory modified; [MDE] Possible pass-the-hash authentication; [MXDR] Suspicious persistence through registry modification; [MDE] Potential human-operated malicious activity; [MDE] Compromised account conducting hands-on-keyboard attack | Tier 1: MDE, MXDR |
| 🟢 T1548 Abuse Elevation Control Mechanism | 6 | 0 | [MDE] Suspicious execution of elevated process | Tier 1: MDE |
| 🔵 T1068 Exploitation for Privilege Escalation | 0 | 0 | — | Tier 2: MDI, MXDR |
| 🔵 T1546 Event Triggered Execution | 18 | 0 | — | Tier 2: DLP |
| ❌ T1037 Boot or Logon Initialization Scripts | 5 | 0 | — | — |
| ❌ T1611 Escape to Host | 0 | 0 | — | — |

Privilege Escalation has the highest combined coverage (85.7%) — only 2 techniques lack any detection source. MDE provides excellent Tier 1 coverage across 6 techniques, and MDCA/MXDR add Tier 2 for 2 more.

#### Defense Evasion (7/47 rules — 14.9% · 24/47 combined — 51.1%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1078 Valid Accounts | 4 | 12 | [AR] Bulk Changes to Privileged Account Permissions; [AR] Admin promotion after Role Management Application Permission Grant; [AR] Attempt to bypass conditional access rule in Microsoft Entra ID; [AR] Anomalous sign-in location by user account and authenticating application; [AR] Correlate Unfamiliar sign-in properties & atypical travel alerts; +7 rules, 10 platform | Tier 1: MDE, AADIP, MDCA, MXDR, MDI |
| ✅ T1484 Domain or Tenant Policy Modification | 2 | 10 | [AR] Creation of Glue policy and then privilege escalation; [AR] CloudFormation policy created then used for privilege escalation; [AR] Creation of CRUD DynamoDB policy and then privilege escalation.; [AR] Creation of CRUD KMS policy and then privilege escalation; [AR] Creation of CRUD Lambda policy and then privilege escalation; +5 rules | Tier 2: MDCA, MXDR |
| ✅ T1197 BITS Jobs | 0 | 1 | [CD] Bitsadmin Abuse by Domain User Account | — |
| ✅ T1211 Exploitation for Defense Evasion | 0 | 1 | [AR] App Gateway WAF - SQLi Detection | ⬜ Tier 3 |
| ✅ T1562 Impair Defenses | 12 | 1 | [CD] Defender for Endpoint Unhealthy; [MDE] Microsoft Defender Antivirus tampering; [MDE] Risk of tampering using Safe Mode reboot as part of an ongoing human operated attack (attack disruption); [MDE] Risk of tampering using Safe Mode reboot as part of a Ransomware attack (attack disruption); [MDE] Attempt to modify Safe Mode registry; +2 platform | Tier 1: MDE |
| ✅ T1574 Hijack Execution Flow | 12 | 1 | [AR] Dataverse - TI map URL to DataverseActivity | Tier 2: MDCA |
| ✅ T1578 Modify Cloud Compute Infrastructure | 5 | 1 | [AR] Creation of expensive computes in Azure | Tier 2: MDCA |
| 🟢 T1027 Obfuscated Files or Information | 17 | 0 | [MDE] Potential human-operated malicious activity | Tier 1: MDE |
| 🟢 T1036 Masquerading | 12 | 0 | [MDE] Hands-on-keyboard attack involving multiple devices; [MDE] Ransomware behavior detected in the file system; [MDE] Suspicious '' behavior was ; [MDE] Suspicious 'Ransomware' behavior was blocked | Tier 1: MDE |
| 🟢 T1055 Process Injection | 12 | 0 | [MDE] Suspicious file or content ingress; [MDE] Meterpreter post-exploitation tool | Tier 1: MDE |
| 🟢 T1112 Modify Registry | 0 | 0 | [MDE] Suspicious registry modification | Tier 1: MDE |
| 🟢 T1134 Access Token Manipulation | 5 | 0 | [MDE] Possible pass-the-hash authentication; [MDE] Malicious credential theft tool execution detected; [MDE] Compromised account conducting hands-on-keyboard attack; [MDE] Potential human-operated malicious activity; [MDE] SID history injection | Tier 1: MDE |
| 🟢 T1222 File and Directory Permissions Modification | 2 | 0 | [MDE] Executable permission added to file or directory | Tier 1: MDE |
| 🟢 T1497 Virtualization/Sandbox Evasion | 3 | 0 | [MDE] Suspicious WMI process creation | Tier 1: MDE |
| 🟢 T1548 Abuse Elevation Control Mechanism | 6 | 0 | [MDE] Suspicious execution of elevated process | Tier 1: MDE |
| 🟢 T1550 Use Alternate Authentication Material | 4 | 0 | [MDE] Possible pass-the-hash authentication; [MDE] Suspicious access to LSASS service; [MDE] Possible lateral movement using pass-the-hash; [MDI] Possible overpass-the-hash attack; [MDE] Potential human-operated malicious activity; +4 platform | Tier 1: MDE, MDI, MXDR |
| 🟢 T1564 Hide Artifacts | 14 | 0 | [MDE] Suspicious access of sensitive files; [MDCA] Suspicious inbox manipulation rule; [MXDR] Suspicious inbox rule created from a risky login or known malicious ISP | Tier 1: MDE, MDCA, MXDR |
| 🔵 T1202 Indirect Command Execution | 0 | 0 | — | Tier 2: MXDR |
| 🔵 T1207 Rogue Domain Controller | 0 | 0 | — | Tier 2: MDI |
| 🔵 T1535 Unused/Unsupported Cloud Regions | 0 | 0 | — | Tier 2: MDCA |
| 🔵 T1553 Subvert Trust Controls | 6 | 0 | — | Tier 2: MDC |
| 🔵 T1556 Modify Authentication Process | 9 | 0 | — | Tier 2: MDCA, MDI, MXDR |
| 🔵 T1656 Impersonation | 0 | 0 | — | Tier 2: MDO |
| 🔵 T1666 Modify Cloud Resource Hierarchy | 0 | 0 | — | Tier 2: MDCA |
| ⬜ T1070 Indicator Removal | 10 | 0 | — | ⬜ Tier 3 |
| ❌ T1006 Direct Volume Access | 0 | 0 | — | — |
| ❌ T1014 Rootkit | 0 | 0 | — | — |
| ❌ T1127 Trusted Developer Utilities Proxy Execution | 3 | 0 | — | — |
| ❌ T1140 Deobfuscate/Decode Files or Information | 0 | 0 | — | — |
| ❌ T1205 Traffic Signaling | 2 | 0 | — | — |
| ❌ T1216 System Script Proxy Execution | 2 | 0 | — | — |
| ❌ T1218 System Binary Proxy Execution | 14 | 0 | — | — |
| ❌ T1220 XSL Script Processing | 0 | 0 | — | — |
| ❌ T1221 Template Injection | 0 | 0 | — | — |
| ❌ T1480 Execution Guardrails | 2 | 0 | — | — |

...and 12 additional uncovered techniques (endpoint/physical access focused).

Defense Evasion is the largest tactic (47 techniques) and platform coverage is critical here — MDE provides Tier 1 for 12 techniques beyond custom rules, bringing combined coverage from 14.9% to 51.1%.

#### Credential Access (3/17 rules — 17.6% · 13/17 combined — 76.5%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1110 Brute Force | 4 | 4 | [AR] Brute force attack against a Cloud PC; [AR] Brute force attack against Azure Portal; [AR] Cross-Cloud Password Spray detection; [AR] MFA Spamming followed by Successful login; [MXDR] Malicious sign-in from a known AiTM attack infrastructure; +7 platform | Tier 1: MXDR, MDI |
| ✅ T1003 OS Credential Dumping | 8 | 1 | [AR] Azure Key Vault access TimeSeries anomaly; [MDE] LSASS process memory modified; [MDE] Malicious credential theft tool execution detected; [MDE] Possible pass-the-hash authentication; [MDE] Suspicious access to LSASS service; +6 platform | Tier 1: MDE |
| ✅ T1528 Steal Application Access Token | 0 | 1 | [AR] Suspicious Service Principal creation activity; [MDI] User identity risk elevated based on defender risk assessment; [MDE] Unix credentials were illegitimately accessed; [MDI] Anomalous OAuth device code authentication activity; [MDE] Possible attempt to access Primary Refresh Token (PRT) | Tier 1: MDI, MDE |
| 🟢 T1212 Exploitation for Credential Access | 0 | 0 | [MXDR] Compromised user account in a recognized attack pattern; [MXDR] Potential user account compromise identified through attack analysis | Tier 1: MXDR |
| 🟢 T1539 Steal Web Session Cookie | 0 | 0 | [MXDR] Malicious sign-in from a known AiTM attack infrastructure; [MXDR] Compromised user account in a recognized attack pattern; [MXDR] Malicious sign in from an IP address associated with recognized AiTM attack infrastructure; [MDI] User identity risk elevated based on defender risk assessment; [MXDR] Potential user account compromise identified through attack analysis | Tier 1: MXDR, MDI |
| 🟢 T1552 Unsecured Credentials | 8 | 0 | [MDE] Suspicious access of sensitive files; [MDE] Unix credentials were illegitimately accessed; [MDE] Enumeration of files with sensitive data; [MDE] Suspicious process collected data from local system; [MDE] Malicious credential theft tool execution detected | Tier 1: MDE |
| 🟢 T1555 Credentials from Password Stores | 6 | 0 | [MDE] Multiple dual-purpose tools were dropped; [MDE] Suspicious remote session; [MDE] Suspicious access of sensitive files; [MDE] Unix credentials were illegitimately accessed; [MDE] Potential human-operated malicious activity; +3 platform | Tier 1: MDE |
| 🟢 T1557 Adversary-in-the-Middle | 4 | 0 | [MXDR] Malicious sign-in from a known AiTM attack infrastructure; [MXDR] Compromised user account in a recognized attack pattern; [MXDR] Malicious sign in from an IP address associated with recognized AiTM attack infrastructure; [MDE] Possible logon from unmanaged or untrusted endpoint | Tier 1: MXDR, MDE |
| 🟢 T1558 Steal or Forge Kerberos Tickets | 5 | 0 | [MDE] Possible use of the Rubeus kerberoasting tool; [MDE] Multiple dual-purpose tools were dropped; [MDE] Suspicious remote session; [MDE] Potential human-operated malicious activity; [MDE] Hands-on-keyboard attack involving multiple devices | Tier 1: MDE |
| 🔵 T1187 Forced Authentication | 0 | 0 | — | Tier 2: MDCA, MXDR |
| 🔵 T1556 Modify Authentication Process | 9 | 0 | — | Tier 2: MDCA, MDI, MXDR |
| 🔵 T1606 Forge Web Credentials | 2 | 0 | — | Tier 2: MDCA, MXDR, AADIP |
| 🔵 T1621 Multi-Factor Authentication Request Generation | 0 | 0 | — | Tier 2: MDCA |
| ❌ T1040 Network Sniffing | 0 | 0 | — | — |
| ❌ T1056 Input Capture | 4 | 0 | — | — |
| ❌ T1111 Multi-Factor Authentication Interception | 0 | 0 | — | — |
| ❌ T1649 Steal or Forge Authentication Certificates | 0 | 0 | — | — |

Credential Access has excellent combined coverage (76.5%) — only 4 techniques are true gaps. Platform products (MXDR, MDE, MDI) cover AiTM, Kerberoasting, and credential dumping techniques with proven alert-generating capability.

#### Discovery (3/34 rules — 8.8% · 15/34 combined — 44.1%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1087 Account Discovery | 4 | 2 | [AR] Anomalous sign-in failure spikes; [AR] Cross-tenant Access Settings Organization Inbound Collaboration Settings Changed; [MDE] Anomalous account lookups; [MDI] Honeytoken authentication activity; [AADIP] Suspicious API Traffic; +3 platform | Tier 1: MDE, MDI, AADIP |
| ✅ T1526 Cloud Service Discovery | 0 | 1 | [AR] Dataverse - TI map IP to DataverseActivity | Tier 2: MDCA |
| ✅ T1580 Cloud Infrastructure Discovery | 0 | 1 | [AR] Dataverse - TI map IP to DataverseActivity | — |
| 🟢 T1016 System Network Configuration Discovery | 2 | 0 | [MDE] Hands-on-keyboard attack involving multiple devices | Tier 1: MDE |
| 🟢 T1018 Remote System Discovery | 0 | 0 | [MDE] Suspicious access of sensitive files | Tier 1: MDE |
| 🟢 T1033 System Owner/User Discovery | 0 | 0 | [MDE] Anomalous account lookups; [MDE] Hands-on-keyboard attack involving multiple devices | Tier 1: MDE |
| 🟢 T1049 System Network Connections Discovery | 0 | 0 | [MDI] Suspicious Server Message Block (SMB) enumeration from untrusted host; [MDE] A remote resource was accessed suspiciously | Tier 1: MDI, MDE |
| 🟢 T1069 Permission Groups Discovery | 3 | 0 | [MDE] Anomalous account lookups; [MDI] User and group membership reconnaissance (SAMR); [MDE] Hands-on-keyboard attack involving multiple devices | Tier 1: MDE, MDI |
| 🟢 T1083 File and Directory Discovery | 0 | 0 | [MDE] Suspicious access of sensitive files; [MDE] Enumeration of files with sensitive data; [MDE] Unix credentials were illegitimately accessed; [MDE] Suspicious process collected data from local system | Tier 1: MDE |
| 🟢 T1135 Network Share Discovery | 0 | 0 | [MDE] A remote resource was accessed suspiciously | Tier 1: MDE |
| 🟢 T1497 Virtualization/Sandbox Evasion | 3 | 0 | [MDE] Suspicious WMI process creation | Tier 1: MDE |
| 🔵 T1046 Network Service Discovery | 0 | 0 | — | Tier 2: MXDR |
| 🔵 T1201 Password Policy Discovery | 0 | 0 | — | Tier 2: MDI |
| 🔵 T1482 Domain Trust Discovery | 0 | 0 | — | Tier 2: MDI |
| 🔵 T1538 Cloud Service Dashboard | 0 | 0 | — | Tier 2: MDCA |
| ❌ T1007 System Service Discovery | 0 | 0 | — | — |
| ❌ T1010 Application Window Discovery | 0 | 0 | — | — |
| ❌ T1012 Query Registry | 0 | 0 | — | — |
| ❌ T1040 Network Sniffing | 0 | 0 | — | — |
| ❌ T1057 Process Discovery | 0 | 0 | — | — |
| ❌ T1082 System Information Discovery | 0 | 0 | — | — |
| ❌ T1120 Peripheral Device Discovery | 0 | 0 | — | — |
| ❌ T1124 System Time Discovery | 0 | 0 | — | — |
| ❌ T1217 Browser Information Discovery | 0 | 0 | — | — |
| ❌ T1518 Software Discovery | 2 | 0 | — | — |

...and 9 additional uncovered techniques (endpoint/physical access focused).

Discovery has the largest framework surface (34 techniques) — many are endpoint-focused local enumeration techniques with limited cloud/identity relevance. The 3 custom rules plus 12 platform-detected techniques provide reasonable coverage for the cloud-relevant subset.

#### Lateral Movement (3/9 rules — 33.3% · 7/9 combined — 77.8%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1021 Remote Services | 8 | 1 | [AR] Dataverse - TI map IP to DataverseActivity; [MDE] PsExec launched a command on a remote device; [MDE] Hands-on-keyboard attack involving multiple devices; [MDE] File dropped and launched from remote location; [MDE] Suspicious remote activity; +6 platform | Tier 1: MDE, MXDR |
| ✅ T1072 Software Deployment Tools | 0 | 1 | [AR] Custom BTP - Malware detected in app dev space | ⬜ Tier 3 |
| ✅ T1210 Exploitation of Remote Services | 0 | 1 | [AR] Dataverse - TI map IP to DataverseActivity | Tier 2: MDI, MXDR |
| 🟢 T1080 Taint Shared Content | 0 | 0 | [MDE] 'Kekeo' malware was detected during lateral movement; [MDE] Hands-on-keyboard attack involving multiple devices; [MDE] Suspicious file registered as a service; [MDE] A remote resource was accessed suspiciously; [MDE] Potential human-operated malicious activity | Tier 1: MDE |
| 🟢 T1534 Internal Spearphishing | 0 | 0 | [MXDR] Internal phishing campaign | Tier 1: MXDR |
| 🟢 T1550 Use Alternate Authentication Material | 4 | 0 | [MDE] Possible pass-the-hash authentication; [MDE] Suspicious access to LSASS service; [MDE] Possible lateral movement using pass-the-hash; [MDI] Possible overpass-the-hash attack; [MDE] Potential human-operated malicious activity; +4 platform | Tier 1: MDE, MDI, MXDR |
| 🟢 T1570 Lateral Tool Transfer | 0 | 0 | [MDE] File dropped and launched from remote location; [MDE] 'Kekeo' malware was detected during lateral movement; [MDE] Hands-on-keyboard attack involving multiple devices; [MDE] Possible lateral movement involving a suspicious file transfer over SMB; [MDE] Multiple dual-purpose tools were dropped; +5 platform | Tier 1: MDE |
| ❌ T1091 Replication Through Removable Media | 0 | 0 | — | — |
| ❌ T1563 Remote Service Session Hijacking | 2 | 0 | — | — |

#### Collection (0/17 rules — 0% · 8/17 combined — 47.1%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| 🟢 T1005 Data from Local System | 0 | 0 | [MDE] Suspicious access of sensitive files; [MDE] Enumeration of files with sensitive data; [MDE] Unix credentials were illegitimately accessed; [MDE] Suspicious process collected data from local system; [MDE] Suspicious piped command launched; +1 platform | Tier 1: MDE |
| 🟢 T1039 Data from Network Shared Drive | 0 | 0 | [MDE] Possible compromised user account delivering ransomware-related files; [MDE] Potentially compromised assets exhibiting ransomware-like behavior; [MDE] Risk of tampering using Safe Mode reboot as part of a Ransomware attack (attack disruption); [MDE] Possible ransomware activity based on a known malicious extension | Tier 1: MDE |
| 🟢 T1074 Data Staged | 2 | 0 | [MDE] 'Kekeo' malware was detected during lateral movement; [MDE] Hands-on-keyboard attack involving multiple devices; [MDE] Suspicious file registered as a service; [MDE] Potential human-operated malicious activity | Tier 1: MDE |
| 🟢 T1114 Email Collection | 3 | 0 | [MDCA] Suspicious Outlook rules; [MXDR] Potential user account compromise identified through attack analysis | Tier 1: MDCA, MXDR |
| 🟢 T1119 Automated Collection | 0 | 0 | [MDE] Suspicious access of sensitive files; [MDE] Unix credentials were illegitimately accessed; [MDE] Suspicious process collected data from local system; [MDE] Suspicious piped command launched; [MDCA] Suspicious interaction with Copilot for Microsoft 365 - Finance related file access | Tier 1: MDE, MDCA |
| 🟢 T1557 Adversary-in-the-Middle | 4 | 0 | [MXDR] Malicious sign-in from a known AiTM attack infrastructure; [MXDR] Compromised user account in a recognized attack pattern; [MXDR] Malicious sign in from an IP address associated with recognized AiTM attack infrastructure; [MDE] Possible logon from unmanaged or untrusted endpoint | Tier 1: MXDR, MDE |
| 🔵 T1213 Data from Information Repositories | 6 | 0 | — | Tier 2: MDCA, MDI |
| 🔵 T1530 Data from Cloud Storage | 0 | 0 | — | Tier 2: MDCA, MDI, DLP |
| ❌ T1025 Data from Removable Media | 0 | 0 | — | — |
| ❌ T1056 Input Capture | 4 | 0 | — | — |
| ❌ T1113 Screen Capture | 0 | 0 | — | — |
| ❌ T1115 Clipboard Data | 0 | 0 | — | — |
| ❌ T1123 Audio Capture | 0 | 0 | — | — |
| ❌ T1125 Video Capture | 0 | 0 | — | — |
| ❌ T1185 Browser Session Hijacking | 0 | 0 | — | — |
| ❌ T1560 Archive Collected Data | 3 | 0 | — | — |
| ❌ T1602 Data from Configuration Repository | 2 | 0 | — | — |

<!-- ZERO_COVERAGE -->
Collection has zero custom rules but substantial platform coverage (8/17 combined). T1114 (Email Collection) is a high-priority cloud detection opportunity — MDCA/MXDR provide Tier 1 platform alerts, but deploying Sentinel analytic rules targeting OfficeActivity mailbox forwarding/inbox rule changes would add Sentinel-native alerting and correlation. T1213 (Data from Information Repositories) has Tier 2 coverage from MDCA/MDI.

#### Command and Control (1/18 rules — 5.6% · 6/18 combined — 33.3%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1071 Application Layer Protocol | 5 | 27 | [AR] Cisco Umbrella - Crypto Miner User-Agent Detected; [AR] TI map URL entity to Cloud App Events; [AR] TI Map URL Entity to DeviceNetworkEvents; [AR] TI Map IP Entity to CommonSecurityLog; [AR] TI map Domain entity to Syslog; +22 rules, 5 platform | Tier 1: MDE |
| 🟢 T1090 Proxy | 4 | 0 | [MDCA] Activity from a TOR IP address | Tier 1: MDCA |
| 🟢 T1102 Web Service | 3 | 0 | [MDE] Suspicious connection to legitimate web service | Tier 1: MDE |
| 🟢 T1105 Ingress Tool Transfer | 0 | 0 | [MDE] File dropped and launched from remote location; [MDE] Suspicious remote activity; [MDE] Multiple dual-purpose tools were dropped; [MDE] Suspicious remote session; [MDE] Suspicious file or content ingress; +2 platform | Tier 1: MDE |
| 🟢 T1132 Data Encoding | 2 | 0 | [MDE] Potential human-operated malicious activity | Tier 1: MDE |
| 🟢 T1219 Remote Access Tools | 3 | 0 | [MDE] Suspicious remote session; [MDE] Potential human-operated malicious activity; [MDE] Possible logon from unmanaged or untrusted endpoint; [MDE] Suspicious logon from remote device | Tier 1: MDE |
| ⬜ T1665 Hide Infrastructure | 0 | 0 | — | ⬜ Tier 3 |
| ❌ T1001 Data Obfuscation | 3 | 0 | — | — |
| ❌ T1008 Fallback Channels | 0 | 0 | — | — |
| ❌ T1092 Communication Through Removable Media | 0 | 0 | — | — |
| ❌ T1095 Non-Application Layer Protocol | 0 | 0 | — | — |
| ❌ T1104 Multi-Stage Channels | 0 | 0 | — | — |
| ❌ T1205 Traffic Signaling | 2 | 0 | — | — |
| ❌ T1568 Dynamic Resolution | 3 | 0 | — | — |
| ❌ T1571 Non-Standard Port | 0 | 0 | — | — |
| ❌ T1572 Protocol Tunneling | 0 | 0 | — | — |
| ❌ T1573 Encrypted Channel | 2 | 0 | — | — |

...and 1 additional uncovered techniques (endpoint/physical access focused).

C2 coverage is heavily concentrated: all 27 custom rules target T1071 (Application Layer Protocol) — these are TI-mapping rules matching threat intelligence indicators against network logs. While this provides deep T1071 coverage, the remaining 17 C2 techniques have zero custom rules. Platform Tier 1 adds 5 more techniques via MDE and MDCA.

#### Exfiltration (2/9 rules — 22.2% · 6/9 combined — 66.7%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1041 Exfiltration Over C2 Channel | 0 | 1 | [AR] Cisco Umbrella - Crypto Miner User-Agent Detected; [MDE] Remote exfiltration activity | Tier 1: MDE |
| ✅ T1537 Transfer Data to Cloud Account | 0 | 1 | [AR] S3 object publicly exposed; [MXDR] Suspicious mass file renaming in cloud storage | Tier 1: MXDR |
| 🟢 T1020 Automated Exfiltration | 1 | 0 | [MDE] Remote exfiltration activity | Tier 1: MDE |
| 🟢 T1048 Exfiltration Over Alternative Protocol | 3 | 0 | [MDE] Remote exfiltration activity | Tier 1: MDE |
| 🟢 T1567 Exfiltration Over Web Service | 4 | 0 | [MDE] Remote exfiltration activity | Tier 1: MDE |
| 🔵 T1011 Exfiltration Over Other Network Medium | 1 | 0 | — | Tier 2: MXDR |
| ❌ T1029 Scheduled Transfer | 0 | 0 | — | — |
| ❌ T1030 Data Transfer Size Limits | 0 | 0 | — | — |
| ❌ T1052 Exfiltration Over Physical Medium | 1 | 0 | — | — |

⚠️ Note: T1537 (Transfer Data to Cloud Account) is covered by the "S3 object publicly exposed" rule, but this rule targets AWSCloudTrail which is on Data Lake tier — it is **tier-blocked** and structurally cannot fire. The MXDR Tier 1 platform alert provides the actual detection for this technique.

#### Impact (2/15 rules — 13.3% · 6/15 combined — 40%)

| Technique | Sub-Techs | Rules | Detections | Platform |
|-----------|-----------|-------|------------|----------|
| ✅ T1496 Resource Hijacking | 4 | 2 | [AR] Cisco Umbrella - Crypto Miner User-Agent Detected; [AR] Chia_Crypto_Mining IOC - June 2021; [MXDR] Suspicious Azure Resource Management activities by a risky user; [MXDR] Suspicious activities related to Azure Key Vault by a risky user | Tier 1: MXDR |
| ✅ T1498 Network Denial of Service | 2 | 1 | [AR] DDoS Attack IP Addresses - Percent Threshold | — |
| 🟢 T1486 Data Encrypted for Impact | 0 | 0 | [MXDR] Suspicious file renaming with ransomware extension; [MDE] Possible compromised user account delivering ransomware-related files; [MDE] Ransomware behavior detected in the file system; [MDE] Possible ransomware activity based on a known malicious extension | Tier 1: MXDR, MDE |
| 🟢 T1490 Inhibit System Recovery | 0 | 0 | [MDE] System recovery setting tampering; [MDE] Hands-on-keyboard attack involving multiple devices; [MDE] File backups were deleted; [MDE] Compromised account conducting hands-on-keyboard attack; [MDE] Potential human-operated malicious activity | Tier 1: MDE |
| 🔵 T1485 Data Destruction | 1 | 0 | — | Tier 2: MDCA |
| 🔵 T1531 Account Access Removal | 0 | 0 | — | Tier 2: MDCA |
| ⬜ T1657 Financial Theft | 0 | 0 | — | ⬜ Tier 3 |
| ❌ T1489 Service Stop | 0 | 0 | — | — |
| ❌ T1491 Defacement | 2 | 0 | — | — |
| ❌ T1495 Firmware Corruption | 0 | 0 | — | — |
| ❌ T1499 Endpoint Denial of Service | 4 | 0 | — | — |
| ❌ T1529 System Shutdown/Reboot | 0 | 0 | — | — |
| ❌ T1561 Disk Wipe | 2 | 0 | — | — |
| ❌ T1565 Data Manipulation | 3 | 0 | — | — |
| ❌ T1667 Email Bombing | 0 | 0 | — | — |

Ransomware-related Impact techniques (T1486, T1490) are well-covered by MDE/MXDR platform alerts despite having zero custom rules.

### Untagged Rules (6 rules without MITRE tags)

| Rule Name | Rule ID | Enabled | Kind | Severity | Source |
|-----------|---------|---------|------|----------|--------|
| Custom Proxy URL TI match | a1b2c3d4-0001-4a0a-b001-000000000001 | True | Scheduled | High | AR |
| Firewall: Anomaly in transferred bytes | a1b2c3d4-0002-4a0a-b002-000000000002 | False | Scheduled | Medium | AR |
| [Migrated] ESCU - Windows Proxy Via Registry - Rule | a1b2c3d4-0003-4a0a-b003-000000000003 | False | Scheduled | Medium | AR |
| Test Rule (unnamed) | a1b2c3d4-0004-4a0a-b004-000000000004 | False | Scheduled | Medium | AR |
| IOC historical match | a1b2c3d4-0005-4a0a-b005-000000000005 | True | Scheduled | Medium | AR |
| Attack Surface Reduction Rule Triggered | 15 | False | CustomDetection | N/A | CD |

> ⚠️ These rules have no MITRE ATT&CK tactics or techniques assigned. They cannot be included in coverage gap analysis. See §6 for AI-suggested MITRE tags from SOC Optimization.

### ICS/OT Technique Coverage

| Technique | Rules | Detections |
|-----------|-------|------------|
| T0806 | 1 | Excessive Login Attempts (Microsoft Defender for IoT) |
| T0814 | 1 | Denial of Service (Microsoft Defender for IoT) |
| T0819 | 1 | Dataverse - TI map URL to DataverseActivity |
| T0839 | 1 | Unauthorized PLC changes (Microsoft Defender for IoT) |
| T0842 | 4 | Multiple scans in the network; Unauthorized DHCP configuration; High bandwidth in the network |
| T0855 | 1 | Illegal Function Codes for ICS traffic (Microsoft Defender for IoT) |
| T0857 | 1 | Firmware Updates (Microsoft Defender for IoT) |
| T0858 | 2 | PLC unsecure key state; PLC Stop Command |
| T0859 | 2 | Dataverse - TI map IP to DataverseActivity; BTP - User added to sensitive privileged role collection |
| T0862 | 1 | Dataverse - TI map URL to DataverseActivity |
| T0863 | 1 | Dataverse - TI map URL to DataverseActivity |
| T0865 | 1 | Dataverse - TI map URL to DataverseActivity |
| T0873 | 2 | Dataverse - TI map URL to DataverseActivity; BTP - Malware detected in app dev space |
| T0881 | 1 | No traffic on Sensor Detected (Microsoft Defender for IoT) |
| T0882 | 1 | Suspicious malware found in the network (Microsoft Defender for IoT) |
| T0886 | 3 | Unauthorized remote access; Internet Access; Dataverse - TI map IP |
| T0890 | 1 | App Gateway WAF - SQLi Detection |

> ℹ️ ICS/OT techniques use the ATT&CK for ICS framework (T0xxx) and are tracked separately from Enterprise ATT&CK. These are not included in the MITRE Coverage Score.

---

## 4. Coverage Gap Analysis

### Actionable Gaps (0% Coverage — Detectable Tactics)

| Tactic | Framework Techniques | True Gaps | Platform-Covered (T1+T2) | Cloud Relevance | Key True Gap Techniques |
|--------|---------------------|-----------|--------------------------|-----------------|------------------------|
| Collection | 17 | 9 | 8 | 🟠 Medium | T1560 Archive Collected Data, T1056 Input Capture, T1185 Browser Session Hijacking |

Collection is the only detectable tactic with zero custom rules. Platform coverage covers 8/17 techniques (47.1%), including the high-priority T1114 (Email Collection) via MDCA/MXDR Tier 1 alerts. However, deploying Sentinel-native rules would add alert correlation, automated incident response, and OfficeActivity-based inbox rule change detection that platform alerts don't provide. The 9 true gaps are mostly endpoint-focused (Screen Capture, Video Capture, Audio Capture) with limited cloud applicability.

### Inherent Blind Spots (0% Coverage — Pre-Compromise Tactics)

| Tactic | Framework Techniques | CTID Protect/Respond | Note |
|--------|---------------------|---------------------|------|
| Reconnaissance | 11 | T1598 (Tier 2: MDO) | Attacker information gathering occurs outside the tenant. Compensating controls: threat intel feeds, honeypots, brand monitoring |

> ℹ️ Reconnaissance is excluded from the Top Recommendations and Coverage Priority Matrix. Zero coverage here is an accepted limitation of SIEM-based detection, not an actionable gap. Resource Development (12.5% coverage) is borderline — one rule covers T1584, and platform detects T1586 (Tier 1).

### Threat Scenario Alignment

[SOC Optimization](https://security.microsoft.com/sentinel/precision) is a Microsoft Sentinel feature that analyzes your workspace's ingested logs and enabled analytics rules, then compares them to the detections needed to address specific attack scenarios. Each threat scenario below represents a known attack pattern (e.g., ransomware, credential exploitation, BEC) with a recommended set of detections. The "Rate" column shows what percentage of recommended detections are active — this is the primary progress indicator. The "Gap" column shows the absolute count of missing detections.

> ℹ️ **Interpreting recommendation counts:** The "Rec." column reflects the **full Content Hub template catalogue** for each scenario — including templates for vendor products not deployed in your environment (e.g., Palo Alto, Cisco, Fortinet firewalls in a Microsoft-only stack). A realistic implementation target is **30–50%** of the recommended count, focusing on templates whose required data sources are already ingested. Use the Rate column and priority badges to track proportional progress rather than chasing the absolute gap to zero.

#### Active Gaps

| Priority | Scenario | Active | Rec. | Rate | Gap | Platform | Sentinel | Sentinel Gap | State | Key Tactic Gaps |
|----------|----------|--------|------|------|-----|----------|----------|--------------|-------|-----------------|
| 🔴 | Credential Exploitation | 23 | 609 | 3.8% | 586 | 0 | 23 | 586 | Active | Collection, Exfiltration, Impact |
| 🔴 | Network Infiltration | 9 | 245 | 3.7% | 236 | 0 | 9 | 236 | Active | Defense Evasion, Execution, Credential Access |
| 🟡 | IaaS Resource Theft | 51 | 119 | 42.9% | 68 | 26 | 25 | 68 | Active | Execution, Lateral Movement, Collection |
| 🟠 | Human Operated Ransomware | 25 | 89 | 28.1% | 64 | 25 | 0 | 64 | InProgress | Command and Control, Impact, Execution |
| ✅ | AiTM (Adversary in the Middle) | 36 | 59 | 61% | 23 | 33 | 3 | 23 | Active | Exfiltration, Command and Control, Credential Access |
| ✅ | BEC (Mass Credential Harvest) | 70 | 91 | 76.9% | 21 | 67 | 3 | 21 | Active | Command and Control, Exfiltration, Credential Access |
| ✅ | ERP (SAP) Financial Process Manipulation | 43 | 60 | 71.7% | 17 | 41 | 2 | 17 | Active | Command and Control, Exfiltration, Credential Access |
| ✅ | BEC (Financial Fraud) | 37 | 47 | 78.7% | 10 | 35 | 2 | 10 | Active | Exfiltration |
| ✅ | Okta Identity Provider | 16 | 25 | 64% | 9 | 16 | 0 | 9 | Active | Credential Access |
| ✅ | X-Cloud Attacks | 22 | 29 | 75.9% | 7 | 21 | 1 | 7 | Active | Discovery, Execution, Lateral Movement |

The two highest-gap scenarios — **Credential Exploitation** (3.8% rate, 586 gap) and **Network Infiltration** (3.7% rate, 236 gap) — both have very large recommendation sets reflecting the full vendor catalogue. Given the Microsoft-centric deployment, a realistic target is 15–25% (activating templates for Microsoft data sources). Human Operated Ransomware is In Progress at 28.1% — platform detections provide 25 additional rules contributing to ransomware coverage. The compound gap between the C2 tactic's low rule-based coverage (5.6% — §2) and multiple threat scenarios listing "Command and Control" as a key tactic gap reinforces the need to diversify beyond T1071 TI-mapping rules.

> 💡 **Recommended workflow for large-gap scenarios (>100 recommended rules):** In the [SOC Optimization portal](https://security.microsoft.com/sentinel/precision), mark the scenario **In Progress**. Review the recommended Content Hub templates and activate the 15–25 most relevant to your deployed data connectors. Once your environment-appropriate subset is active, mark the scenario **Complete**. This report will then track it in the "Reviewed & Addressed" section with your actual completion rate — giving credit for deliberate, environment-tailored coverage rather than penalizing against the full vendor catalogue.

### AI-Suggested MITRE Tags for Untagged Rules

SOC Optimization has identified 7 rules that should be tagged with MITRE ATT&CK metadata:

| Rule ID | Suggested Tactics | Suggested Techniques |
|---------|-------------------|---------------------|
| a1b2c3d4-0001-4a0a-b001-000000000001 | CommandAndControl | (none) |
| a1b2c3d4-0005-4a0a-b005-000000000005 | CredentialAccess | (none) |
| a1b2c3d4-0006-4a0a-b006-000000000006 | DefenseEvasion, Exfiltration, Persistence | T1098 |
| a1b2c3d4-0007-4a0a-b007-000000000007 | CredentialAccess, Discovery, InitialAccess | T1078 |
| a1b2c3d4-0008-4a0a-b008-000000000008 | CredentialAccess, Discovery, InitialAccess | T1078 |
| a1b2c3d4-0009-4a0a-b009-000000000009 | DefenseEvasion, PrivilegeEscalation | T1134 |
| a1b2c3d4-0010-4a0a-b010-000000000010 | Execution | T1204 |

> 💡 **Action:** Apply these MITRE tags via the Sentinel portal (Analytics > [Rule] > Edit > General tab > Tactics and techniques). This immediately improves the Tagging dimension of the MITRE Coverage Score and enables these rules to contribute to gap analysis. Applying the suggested T1078/T1098/T1134/T1204 tags would increase technique coverage for InitialAccess, Persistence, CredentialAccess, DefenseEvasion, PrivilegeEscalation, and Execution.

---

## 5. Operational MITRE Correlation

### 5.1 Platform-Native Detection Coverage (30d)

**Active Detection Sources** (from SecurityAlert with MITRE attribution):
- Microsoft Entra ID Protection: 2 techniques
- Microsoft Defender for Cloud: 13 techniques
- Microsoft Defender XDR: 18 techniques
- Microsoft Defender for Cloud Apps: 6 techniques
- Microsoft Defender for Endpoint: 58 techniques
- Microsoft Defender for Identity: 8 techniques
- Microsoft Defender for Office 365: 1 technique
- Analytic Rules (AR): 16 techniques *(alert-firing AR rules with MITRE tags)*

> **Note:** Technique counts overlap between sources — one technique may be covered by multiple products AND rules. The total unique count is in the Combined row below.

**CTID Tier Classification** (v07/18/2025):

| Tier | Techniques | Description |
|------|-----------|-------------|
| 🟢 Tier 1: Alert-Proven | 67 | Platform alerts with MITRE techniques in 30d |
| 🔵 Tier 2: Deployed Capability | 30 | Active product + CTID detect mapping, no alerts |
| ⬜ Tier 3: Catalog Capability | 7 | CTID mapping only, product not detected as active |

**Combined Tactic Coverage (Rule-Based + Platform):**

| Tactic | Rule-Based | T1 | T2 | T3 | Combined | Framework | Coverage |
|--------|--------|----|----|----|---------|-----------|---------|
| 🟠 Reconnaissance | 0 | 0 | 1 | 0 | 1 | 11 | 9.1% |
| 🟡 Resource Development | 1 | 1 | 0 | 1 | 2 | 8 | 25% |
| 🟢 Initial Access | 5 | 3 | 2 | 0 | 6 | 11 | 54.5% |
| 🟢 Execution | 3 | 8 | 0 | 1 | 9 | 17 | 52.9% |
| 🟢 Persistence | 6 | 8 | 4 | 1 | 13 | 23 | 56.5% |
| 🟢 Privilege Escalation | 4 | 8 | 4 | 0 | 12 | 14 | 85.7% |
| 🟢 Defense Evasion | 7 | 12 | 10 | 2 | 24 | 47 | 51.1% |
| 🟢 Credential Access | 3 | 9 | 4 | 0 | 13 | 17 | 76.5% |
| 🟡 Discovery | 3 | 9 | 5 | 0 | 15 | 34 | 44.1% |
| 🟢 Lateral Movement | 3 | 5 | 1 | 1 | 7 | 9 | 77.8% |
| 🟡 Collection | 0 | 6 | 2 | 0 | 8 | 17 | 47.1% |
| 🟡 Command and Control | 1 | 6 | 0 | 1 | 6 | 18 | 33.3% |
| 🟢 Exfiltration | 2 | 5 | 1 | 0 | 6 | 9 | 66.7% |
| 🟡 Impact | 2 | 3 | 2 | 1 | 6 | 15 | 40% |
| **TOTAL** | **40** | **83** | **36** | **8** | **128** | **250** | **51.2%** |

Platform coverage transforms the landscape: custom rules cover 40/250 techniques (16%), but combined with Tier 1+2 platform detections, coverage reaches 128/250 (51.2%) — an uplift of 88 techniques. The greatest platform impact is in Privilege Escalation (28.6% → 85.7%), Credential Access (17.6% → 76.5%), and Lateral Movement (33.3% → 77.8%). MDE is the dominant contributor (58 techniques at Tier 1), confirming the importance of endpoint telemetry in the detection stack.

### 5.2 27 Alert-Producing Rules

| Alert | Tactics | Techniques | Alerts | Severity |
|-------|---------|------------|--------|----------|
| 🔴 [CD] Powershell execution detected | Execution | — | 1539 | M:1539 |
| 🔴 [AR] TI Map IP Entity to DeviceNetworkEvents | Command And Control | T1071 | 356 | M:356 |
| 🔴 [AR] Suspicious volume of logins to computer with elevated token | Discovery, Credential Access, Initial Access | — | 141 | M:141 |
| 🔴 [AR] Test Rule (unnamed) | — | — | 127 | M:127 |
| 🔴 [AR] Insider Risk_Microsoft Purview Insider Risk Management Alert Observed | Execution | T1204 | 115 | H:115 |
| 🟠 [CD] SAPXPG called a Potentially Dangerous External Command.  Contact SAP BASIS team | Unknown | — | 44 | H:44 |
| 🟠 [AR] TI map IP entity to Cloud App Events | Command And Control | T1071 | 41 | M:41 |
| 🟠 [AR] SAP - Transaction SM49 started by user JSMITH in a production system | Execution | — | 24 | H:24 |
| [AR] IOC historical match | — | — | 18 | M:18 |
| [AR] TI Map IP Entity to SigninLogs | Command And Control | T1071 | 17 | M:17 |
| [AR] TI map Domain entity to EmailUrlInfo | Initial Access | T1566 | 7 | M:7 |
| [AR] User JSMITH has downloaded 13400 bytes of potentially sensitive data  | Exfiltration | — | 7 | H:7 |
| [AR] User JSMITH has downloaded 8619 bytes of potentially sensitive data  | Exfiltration | — | 6 | H:6 |
| [AR] Mail.Read Permissions Granted to Application | Persistence | T1098 | 4 | M:4 |
| [AR] BTP - Malware detected in app development space | Resource Development, Execution, Persistence | T1584, T1072, T0873 | 2 | M:2 |
| [AR] (MDIoT) Unauthorized PLC Programming | Impair Process Control | T0855 | 2 | H:2 |
| [AR] (MDIoT) Modbus Exception | Impair Process Control | T0855 | 2 | M:2 |
| [AR] (MDIoT) Unauthorized PLC Programming | Persistence | T0839 | 2 | H:2 |
| [AR] Test cleanup rule | — | — | 1 | M:1 |
| [AR] (MDIoT) Unauthorized Internet Connectivity Detected | Lateral Movement | T0886 | 1 | H:1 |
| [AR] (MDIoT) Port Scan Detected | Discovery | T0842 | 1 | H:1 |
| [AR] (MDIoT) Suspicion of Malicious Activity (Name Queries) | Impact | T0882 | 1 | M:1 |
| [AR] Privileged Accounts - Sign in Failure Spikes | Initial Access | T1078 | 1 | H:1 |
| [AR] (MDIoT) An S7 Stop PLC Command was Sent | Defense Evasion | T0858 | 1 | L:1 |
| [AR] DDoS Attack IP Addresses - Percent Threshold | Impact | T1498 | 1 | M:1 |
| [AR] Access Token Manipulation - Create Process with Token [Migrated from QRadar] | Privilege Escalation, Defense Evasion | — | 1 | M:1 |
| [AR] Custom BTP - User added to sensitive privileged role collection | Lateral Movement, Privilege Escalation | T0859, T1078 | 1 | L:1 |

**Summary:** 27 alert-producing rules (25 AR, 2 CD) generated alerts in the 30-day window.
3 AR rule(s) fired alerts but could not be cross-referenced with the M1 rule inventory (rule may have been deleted or modified since alert generation).
CD = Custom Detection rules (identified by AlertType == CustomDetection in SecurityAlert). Tactic data from SecurityAlert Tactics column; technique-level detail not available.

The most active tactics are Execution (1,539 alerts from the PowerShell CD rule), Command and Control (414 alerts from TI-mapping AR rules), and Discovery/Credential Access (141 alerts from elevated token sign-in detection). Two untagged rules are generating significant alert volumes: "Test Rule (unnamed)" (127 alerts, no MITRE) and "IOC historical match" (18 alerts, no MITRE) — tagging these would improve Operational coverage attribution.

### 5.3 Active vs Tagged Tactic Coverage

| Tactic | Tagged Rules | Firing | Silent | Active (Alerts) | Status |
|--------|-------------|--------|--------|-----------------|--------|
| Reconnaissance | 0 | 0 | 0 | 0 | 🔴 No coverage |
| Resource Development | 1 | 1 | 0 | 2 | ✅ Validated |
| Initial Access | 25 | 3 | 22 | 149 | 🟡 Mostly silent |
| Execution | 7 | 3 | 4 | 1680 | 🟡 Mostly silent |
| Persistence | 11 | 3 | 8 | 8 | 🟡 Mostly silent |
| Privilege Escalation | 16 | 2 | 14 | 2 | 🟡 Mostly silent |
| Defense Evasion | 11 | 2 | 9 | 2 | 🟡 Mostly silent |
| Credential Access | 9 | 1 | 8 | 141 | 🟡 Mostly silent |
| Discovery | 9 | 2 | 7 | 142 | 🟡 Mostly silent |
| Lateral Movement | 3 | 2 | 1 | 2 | ✅ Validated |
| Collection | 0 | 0 | 0 | 0 | 🔴 No coverage |
| Command and Control | 27 | 3 | 24 | 414 | 🟡 Mostly silent |
| Exfiltration | 4 | 1 | 3 | 13 | 🟡 Mostly silent |
| Impact | 5 | 2 | 3 | 2 | 🟡 Mostly silent |

#### SilentRules

| Rule | Source | Tactics | Techniques |
|------|--------|---------|------------|
| Command and Control / T1071 rules (×23) | AR+CD | Command and Control | T1071 |
| Suspicious Service Principal creation activity | AR | Credential Access, Privilege Escalation, Initial Access | T1078, T1528 |
| SAP - (Preview) Trusted RFC connection created or modified in SAP NetWeaver [CVE-2023-0014]  | AR | Credential Access | — |
| Azure Key Vault access TimeSeries anomaly | AR | Credential Access | T1003 |
| Credential Access / T1110 rules (×4) | AR | Credential Access | T1110 |
| App Gateway WAF - SQLi Detection | AR | Defense Evasion, Execution, Initial Access, Privilege Escalation | T1211, T1059, T1190, T0890 |
| [Migrated] ESCU - Windows Rasautou DLL Execution - Rule | AR | Defense Evasion | — |
| Azure AD Rare UserAgent App Sign-in | AR | Defense Evasion | — |
| Bitsadmin Abuse by Domain User Account | CD | Defense Evasion | T1197 |
| Defender for Endpoint Unhealthy | CD | Defense Evasion | T1562, T1562.001 |
| Firewall Tampering by Domain User Account | CD | Defense Evasion | T1562.004 |
| Creation of expensive computes in Azure | AR | Defense Evasion | T1578 |
| UEBA Anomalies Rule | AR | Discovery, Credential Access, Initial Access | — |
| Discovery / T0842 rules (×3) | AR | Discovery | T0842 |
| Suspicious Process Injection from Office application [Migrated from QRadar] | AR | Execution | — |
| PLC unsecure key state (Microsoft Defender for IoT) | AR | Execution | T0858 |
| SAP - Deactivation of Security Audit Log | AR | Exfiltration, Defense Evasion, Persistence | — |
| S3 object publicly exposed | AR | Exfiltration | T1537 |
| Cisco Umbrella - Crypto Miner User-Agent Detected | AR | Impact, Command and Control, Exfiltration | T1496, T1071, T1041 |
| TI Map IP Entity to NetworkPatterns | AR | Impact | — |
| Chia_Crypto_Mining IOC - June 2021 | AR | Impact | T1496 |
| Excessive Login Attempts (Microsoft Defender for IoT) | AR | ImpairProcessControl | T0806 |
| Denial of Service (Microsoft Defender for IoT) | AR | InhibitResponseFunction | T0814 |
| No traffic on Sensor Detected (Microsoft Defender for IoT) | AR | InhibitResponseFunction | T0881 |
| Anomalous sign-in failure spikes | AR | Initial Access, Discovery | T1078, T1087 |
| Dataverse - TI map URL to DataverseActivity | AR | Initial Access, Execution, Persistence | T1566, T1456, T1474, T0819, T0865, T0862, T0863, T1204, T1574, T0873 |
| Dataverse - TI map IP to DataverseActivity | AR | Initial Access, Lateral Movement, Discovery | T1078, T1199, T1133, T0886, T0859, T1428, T1021, T1210, T1526, T1580 |
| Cross-tenant Access Settings Organization Inbound Collaboration Settings Changed | AR | Initial Access, Persistence, Discovery | T1078, T1136, T1087 |
| Attempt to bypass conditional access rule in Microsoft Entra ID | AR | Initial Access, Persistence | T1078, T1098 |
| Log4J - Possible Malicious Indicators in Cloud Application Events | CD | Initial Access |  |
| SAP - Login from unexpected network | AR | Initial Access | — |
| Unauthorized remote access to the network (Microsoft Defender for IoT) | AR | Initial Access | T0886 |
| Anomalous sign-in location by user account and authenticating application | AR | Initial Access | T1078 |
| Correlate Unfamiliar sign-in properties & atypical travel alerts | AR | Initial Access | T1078 |
| Claroty - Login to uncommon location | AR | Initial Access | T1190, T1133 |
| Detect threat information in web requests (ASIM Web Session) | AR | Initial Access | T1190, T1133 |
| Azure Portal sign in from another Azure Tenant | AR | Initial Access | T1199 |
| Initial Access / T1566 rules (×6) | AR | Initial Access | T1566 |
| Malicious Inbox Rule | AR | Persistence, Defense Evasion | T1098, T1078 |
| Firmware Updates (Microsoft Defender for IoT) | AR | Persistence | T0857 |
| OpenClaw Persistence Mechanism Detection | CD | Persistence | T1053.005, T1547.001, T1059.001 |
| Admin promotion after Role Management Application Permission Grant | AR | Privilege Escalation, Persistence | T1098, T1078 |
| Bulk Changes to Privileged Account Permissions | AR | Privilege Escalation | T1078 |
| Privilege Escalation / T1484 rules (×10) | AR | Privilege Escalation | T1484 |

The most significant silent cluster is **Command and Control**: 24/27 tagged rules are silent, all targeting T1071. These are TI-mapping rules that only fire when threat intelligence indicators match network traffic — they may be structurally waiting for TI matches that haven't occurred. The 4 silent Credential Access T1110 (Brute Force) rules may overlap with the one firing rule in that group. Cross-referencing with §5.5 Data Readiness: "TI Map IP Entity to NetworkPatterns" (NoData), "S3 object publicly exposed" (TierBlocked), and rules depending on CommonSecurityLog/Syslog (Partial) have confirmed data source gaps as root cause — these rules are not detection logic failures.

Total: **85 enabled MITRE-tagged rules with 0 alerts** in the 30-day window. Review these for data source gaps (cross-ref §5.5), decommission stale Content Hub templates that don't match deployed data connectors, and consider purple team exercises for operationally critical rules.

### 5.4 Incidents by Tactic

| Tactic | Incidents | High | Medium | Low | Info | TP | FP | BP |
|--------|-----------|------|--------|-----|------|----|----|----|
| Reconnaissance | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| Resource Development | 3 | 2 | 1 | 0 | 0 | 0 | 0 | 0 |
| 🔴 Initial Access | 166 | 72 | 10 | 68 | 16 | 11 | 0 | 11 |
| 🟠 Execution | 34 | 25 | 8 | 1 | 0 | 4 | 0 | 0 |
| Persistence | 24 | 19 | 4 | 1 | 0 | 4 | 0 | 0 |
| 🟠 Privilege Escalation | 26 | 17 | 7 | 2 | 0 | 4 | 0 | 1 |
| 🟠 Defense Evasion | 29 | 17 | 7 | 2 | 3 | 5 | 0 | 1 |
| 🔴 Credential Access | 916 | 11 | 2 | 1 | 902 | 3 | 0 | 0 |
| 🔴 Discovery | 111 | 12 | 99 | 0 | 0 | 4 | 0 | 0 |
| 🟠 Lateral Movement | 29 | 25 | 2 | 2 | 0 | 3 | 0 | 0 |
| Collection | 14 | 14 | 0 | 0 | 0 | 4 | 0 | 0 |
| 🔴 Command and Control | 150 | 18 | 127 | 1 | 4 | 5 | 0 | 1 |
| 🔴 Exfiltration | 1015 | 842 | 29 | 144 | 0 | 3 | 1 | 0 |
| Impact | 8 | 6 | 2 | 0 | 0 | 3 | 0 | 0 |
| Inhibit Response Function | 2 | 0 | 1 | 1 | 0 | 0 | 0 | 0 |
| Impair Process Control | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| 🔴 Pre-Attack | 1134 | 105 | 856 | 68 | 108 | 3 | 0 | 0 |
| **TOTAL** | **3663** | **1186** | **1155** | **292** | **1033** | **56** | **1** | **14** |

Exfiltration dominates incident volume (1,015 incidents, 842 High severity) — indicating active data exfiltration signatures firing. Credential Access has 916 incidents but 902 are Informational severity — likely automated Identity Protection risk detections. Pre-Attack shows 1,134 incidents, primarily Medium severity, suggesting high-volume TI-matching activity. The nearly-zero FP rate across all tactics (1 total FP) suggests rules are well-tuned but possibly under-classified — only 56/3,663 incidents (1.5%) have been classified as TP.

### 5.5 Data Readiness (Table Ingestion Validation)

Detection rules can only fire if their underlying data sources are actively ingesting events. This analysis extracts KQL table dependencies from each enabled analytic rule and validates them against the 7-day ingestion volume from the Usage table.

| Status | Rules | Description |
|--------|-------|-------------|
| ✅ Ready | 75 | All referenced tables have active ingestion |
| ⚠️ Partial | 4 | Some tables have data, others do not (multi-table rules) |
| 🔴 No Data | 3 | Primary table(s) have zero ingestion -- rule cannot fire |
| 🚫 Tier Blocked | 2 | Table on Basic/Data Lake tier -- analytics rules structurally cannot query |
| **Data Readiness** | **89.3%** | Ready / (Ready + Partial + NoData + TierBlocked) |

#### Rules with Missing Data Sources

| Rule Name | Tables | Status | Missing Tables | Available Volumes |
|-----------|--------|--------|----------------|-------------------|
| TI Map IP Entity to NetworkPatterns | NetworkPatterns_CL, ThreatIntelligenceIndicator | 🔴 NoData | NetworkPatterns_CL, ThreatIntelligenceIndicator | — |
| TI Map IP Entity to CommonSecurityLog | CommonSecurityLog, ThreatIntelIndicators | ⚠️ Partial | CommonSecurityLog | ThreatIntelIndicators=55.73MB |
| TI map Domain entity to Syslog | Syslog, ThreatIntelIndicators | ⚠️ Partial | Syslog | ThreatIntelIndicators=55.73MB |
| TI map File Hash to CommonSecurityLog Event | CommonSecurityLog, ThreatIntelIndicators | ⚠️ Partial | CommonSecurityLog | ThreatIntelIndicators=55.73MB |
| TI map Domain entity to DnsEvents | DnsEvents, ThreatIntelIndicators | ⚠️ Partial | DnsEvents | ThreatIntelIndicators=55.73MB |
| TI Map URL Entity to PaloAlto Data | RequestURL, CommonSecurityLog | 🔴 NoData | CommonSecurityLog | — |
| TI Map URL Entity to Syslog Data | Syslog | 🔴 NoData | Syslog | — |
| Creation of CRUD DynamoDB policy and then privilege escalation. | StartTime, AWSCloudTrail | 🚫 TierBlocked | — | — |
| S3 object publicly exposed | AWSCloudTrail | 🚫 TierBlocked | — | — |

#### Missing Tables — Impact Summary

| Table | Rules Affected |
|-------|----------------|
| CommonSecurityLog | 3 |
| Syslog | 2 |
| NetworkPatterns_CL | 1 |
| ThreatIntelligenceIndicator | 1 |
| DnsEvents | 1 |

**Likely causes:**
- **CommonSecurityLog** — CEF forwarder not connected or Log Analytics agent not deployed for CEF sources. 3 TI-mapping rules depend on this table.
- **Syslog** — Linux agent/forwarder not configured. Affects 2 TI-mapping rules.
- **NetworkPatterns_CL** — Custom table (`_CL` suffix) — connector may be disconnected or logic app stopped.
- **ThreatIntelligenceIndicator** — Threat intelligence connector not enabled or feeds expired.
- **DnsEvents** — DNS Analytics solution not deployed or Windows DNS server agent not installed.

#### Phantom Coverage — Tier-Blocked Tables

| Table | Tier | Rules Affected |
|-------|------|----------------|
| AWSCloudTrail | Data Lake | 2 |

TierBlocked is a stronger signal than NoData — the AWSCloudTrail table is on Data Lake tier, meaning the 2 rules targeting it (including "S3 object publicly exposed" covering T1537) are **structurally** unable to fire regardless of data volume. The AmazonWebServicesS3-CloudTrail connector shows as "Degraded" (50% health) in §5.6 — however, even if it were healthy, the tier classification prevents analytics rule execution. These rules represent phantom coverage that inflates the technique count without providing actual detection capability.

> ℹ️ *Some "Partial" rules may show false-positive missing tables where KQL column names, `let` variable names, or enrichment function identifiers were misidentified as table names by the extraction logic (e.g., "RequestURL", "StartTime"). These rules likely have all required tables flowing and are effectively Ready. Similarly, SAP Solution rules may show enrichment function names (SAPSystems, SAPUsersGetVIP) as missing tables — if the rule appears in AlertFiring, the primary table is ingesting.*

> *Data readiness validates table-level ingestion presence, not event-level completeness. A table with active volume may still lack specific event types a rule requires. Complete detection validation requires purple team exercises such as Atomic Red Team tests mapped to ATT&CK technique IDs.*

### 5.6 Connector Health (SentinelHealth Enrichment)

SentinelHealth provides proactive connector failure detection — catching failures before they degrade 7-day ingestion averages. Only supported connectors are tracked (AWS CloudTrail/S3, Office 365, Dynamics 365, MDE, TI-TAXII/TIP, Codeless Connector Framework). CEF/Syslog agents, custom `_CL` tables, and many first-party connectors are NOT covered.

| Status | Connectors | Description |
|--------|------------|-------------|
| ✅ Healthy | 15 | Last fetch succeeded, >90% success rate |
| ⚠️ Degraded | 1 | Last fetch succeeded but <90% success rate (intermittent failures) |
| 🔴 Failing | 0 | Last fetch status is Failure |

#### Connectors with Health Issues

| Connector | Last Status | Success | Failure | Health % |
|-----------|-------------|---------|---------|----------|
| AmazonWebServicesS3-CloudTrail | Success | 612 | 612 | 50% |

The **AmazonWebServicesS3-CloudTrail** connector shows a 50% success rate (612 successes, 612 failures) — indicating intermittent ingestion failures. This feeds the AWSCloudTrail table, which is on Data Lake tier (§5.5) — so while the data flow issue compounds with the tier-blocking, even fixing the connector won't enable the 2 analytics rules targeting AWSCloudTrail. Office 365, MDE/MTP, Purview, GCP, and SAP connectors are all healthy at 100%.

> ℹ️ SentinelHealth covers supported connectors only. The missing CommonSecurityLog/Syslog/DnsEvents detected in §5.5 are not tracked by SentinelHealth (CEF/Syslog agents require separate monitoring).

---

## 6. Recommendations

### ⚡ Quick Wins

1. **Apply AI-suggested MITRE tags** — 7 rules can be tagged via the Sentinel portal with SOC Optimization-recommended tactics/techniques. Immediate improvement to Tagging score (currently 95.4%). Two enabled untagged rules generate alerts: "Custom Proxy URL TI match" and "IOC historical match" — tagging these adds operationally-validated coverage to gap analysis. "Test Rule (unnamed)" (currently disabled but generated 127 alerts during the lookback period) should also be reviewed — if it's a valid detection, enable and tag it.
2. **Tag the 2 firing but unmatched CD rules** — The PowerShell Execution and SAPXPG Custom Detection rules are generating alerts but their MITRE tactic attribution comes from SecurityAlert metadata, not rule configuration. Verify their MITRE tags are applied in the Defender portal for consistent coverage tracking.
3. **Enable Content Hub templates for Collection** — Deploy T1114 (Email Collection) rules targeting OfficeActivity for inbox rule/forwarding detection. This adds Sentinel-native alerting to complement existing MDCA/MXDR Tier 1 platform coverage.

### 🔧 Medium-Term Improvements

1. **Address Credential Exploitation and Network Infiltration scenarios** — Both at <4% completion rate. Review the SOC Optimization portal, filter by data sources already ingested (SigninLogs, AuditLogs, DeviceEvents, etc.), and activate the 15–25 most relevant Content Hub templates per scenario. Mark these scenarios In Progress to track incremental coverage.
2. **Continue Human Operated Ransomware deployment** — Currently In Progress at 28.1%. Platform detections provide 25 additional rules. Focus on C2, Impact, and Execution tactic gaps identified in the scenario.
3. **Diversify C2 coverage** — All 27 custom C2 rules target T1071 (TI-mapping). Consider deploying rules for T1090 (Proxy), T1105 (Ingress Tool Transfer), T1219 (Remote Access Tools) — platform has Tier 1 coverage but custom rules add Sentinel incident correlation.
4. **Review 85 silent rules** — Prioritize rules with data source gaps (cross-ref §5.5). Disable TI-mapping rules for disconnected data sources (CommonSecurityLog, Syslog) to reduce noise and improve Operational score.
5. **Address AWSCloudTrail tier alignment** — 2 rules are tier-blocked because AWSCloudTrail is on Data Lake. Consider migrating to Custom Detection rules (which can query Data Lake) or migrating the table to Analytics tier if these detections are business-critical.

### 🔄 Ongoing Maintenance

- **Quarterly MITRE coverage review** — re-run this report quarterly to track coverage improvements and catch regressions
- **New rule MITRE tagging** — when deploying new analytic rules, always assign appropriate MITRE tactics and techniques
- **ATT&CK framework updates** — when MITRE publishes new ATT&CK versions, update `mitre-attck-enterprise.json` and re-run
- **SOC Optimization monitoring** — review SOC Optimization recommendations monthly for new coverage suggestions
- **Connector health monitoring** — investigate the AmazonWebServicesS3-CloudTrail 50% failure rate

### Coverage Priority Matrix

| Priority | Tactic/Scenario | Current State | Recommended Action | Effort |
|----------|----------------|---------------|-------------------|--------|
| 🔴 1 | Credential Exploitation | 3.8% rate (23/609) | Activate 15-25 environment-relevant Content Hub templates | Medium |
| 🔴 2 | Network Infiltration | 3.7% rate (9/245) | Enable Defense Evasion, Execution, Credential Access templates | Medium |
| 🟠 3 | Human Operated Ransomware | 28.1% rate (In Progress) | Continue deployment — focus on C2, Impact, Execution gaps | Medium |
| 🟠 4 | Collection tactic | 0% rule-based, 47.1% combined | Deploy T1114 Email Collection + T1213 Data from Repos rules | Low |
| 🟠 5 | C2 technique diversification | 1/18 techniques covered | Add rules for T1090, T1105, T1219 beyond TI-mapping | Medium |
| 🟡 6 | Silent rule remediation | 85 silent rules | Review data sources, decommission stale templates | Low |
| 🟡 7 | MITRE tag remediation | 6 untagged rules | Apply SOC Optimization suggestions | Low |

---

## Appendix

### A. Query Reference

| Phase | Query | Type | Description | Status |
|-------|-------|------|-------------|--------|
| 1 | M1 | REST | Analytic Rule MITRE Extraction | OK |
| 1 | M2 | Graph | Custom Detection MITRE Extraction | OK |
| 2 | M3 | REST | SOC Optimization Coverage | OK |
| 3 | M4 | KQL | Alert Firing by MITRE | OK |
| 3 | M5 | KQL | Incidents by Tactic | OK |
| 3 | M6 | KQL | Platform Alert MITRE Coverage | OK |
| 3 | M7 | KQL | Table Ingestion Volume (Data Readiness) | OK |
| 3 | M8 | KQL | Data Connector Health (SentinelHealth) | OK |
| 3 | M9 | CLI | Table Tier Classification | OK |

**Generated:** 2026-04-05T13:49:38Z | **Execution Time:** 44.1s | **Phases:** 1,2,3

### B. MITRE Coverage Score Methodology

The MITRE Coverage Score is a composite metric (0–100) computed from 5 weighted dimensions. It is designed to reward **operationally validated** detection coverage — teams that purple-team their rules and confirm they fire score higher than teams that deploy rules without validating them.

#### Dimensions & Weights

| # | Dimension | Weight | What It Measures |
|---|-----------|--------|-----------------|
| 1 | **Breadth** | 25% | Readiness-weighted technique coverage across the ATT&CK framework |
| 2 | **Balance** | 10% | Kill chain phase distribution — are all 14 tactics represented? |
| 3 | **Operational** | 30% | % of MITRE-tagged rules that actually produced alerts in the lookback period |
| 4 | **Tagging** | 15% | % of all rules (enabled + disabled) with at least 1 MITRE tag |
| 5 | **SOC Alignment** | 20% | Completion rate of Microsoft SOC Optimization coverage recommendations |

**Why Operational is the heaviest weight (30%):** A rule that has never fired is unvalidated — it *might* detect an attack, or it might have a broken query, wrong data source, or logic error. Teams that run purple team exercises, atomic tests, or otherwise trigger their detections prove their rules work. This score rewards that effort directly.

#### Breadth: Readiness-Weighted Credit

| Rule's Best Status | Credit | Meaning |
|-------------------|--------|---------|
| **Fired** (produced alerts) | 1.00 | Validated by real or simulated attack — highest confidence |
| **Ready** (data exists, 0 alerts) | 0.75 | Rule *can* fire — data pipeline is healthy |
| **Partial** (some tables missing) | 0.50 | Rule partially functional |
| **NoData** (zero ingestion) | 0.25 | Paper tiger — technique in matrix but rule cannot fire |
| **TierBlocked** (table on wrong tier) | 0.00 | Structurally impossible — rule can never execute |

#### Score Interpretation

| Score Range | Assessment | Typical Profile |
|-------------|------------|-----------------|
| 80–100 | 🟢 **Strong** | Broad coverage, balanced tactics, operationally validated, well-tagged, SOC-aligned |
| 60–79 | 🔵 **Good** | Solid coverage with some gaps; may have clustering or unvalidated rules |
| 40–59 | 🟡 **Moderate** | Significant gaps in breadth or operational validation; improvement opportunities |
| 20–39 | 🟠 **Developing** | Limited coverage across the framework; many uncovered tactics |
| 0–19 | 🔴 **Critical** | Minimal detection coverage; urgent investment needed |

### C. Limitations

1. **Coverage ≠ detection:** Having a rule tagged with a technique does not guarantee detection — rule quality, data source availability, and adversary TTPs vary
2. **Operational dimension requires Phase 3:** If KQL queries fail, Operational score defaults to 0
3. **Custom Detection availability:** Graph API requires `CustomDetection.Read.All` admin consent
4. **Sub-technique granularity:** Coverage is measured at the parent technique level
5. **ATT&CK framework currency:** The reference JSON reflects ATT&CK Enterprise v16.1
6. **SOC Optimization scope:** Coverage recommendations are based on deployed data sources and available Content Hub templates
7. **Paper tiger detection** depends on the lookback window — a rule that fires infrequently may appear as a paper tiger in a 30-day window

---

**Report generated:** 2026-04-05T13:49:38Z | **Skill:** mitre-coverage-report v1 | **Mode:** markdown file
