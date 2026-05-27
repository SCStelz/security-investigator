# SAP Threat Hunting — Microsoft Sentinel Queries

**Created:** 2026-04-14  
**Platform:** Both  
**Tables:** ABAPAuditLog, SAPBTPAuditLog_CL, ABAPUserDetails, ABAPChangeDocsLog, SecurityAlert  
**Keywords:** SAP, ABAP, BTP, RFC, logon, brute force, sensitive table, transaction code, dynamic ABAP, audit evasion, data exfiltration, privilege escalation, role collection, SAPXPG, SM49, SM69, SE16, SU01, PFCG, lateral movement, RFC trust  
**MITRE:** T1078, T1078.004, T1110, T1059, T1562.001, T1048, T1021, T1068, TA0001, TA0003, TA0005, TA0006, TA0008, TA0009, TA0010  
**Domains:** cloud, admin  
**Timeframe:** Last 7–30 days (configurable)

---

## Overview

Comprehensive threat hunting queries for **SAP environments** monitored by the Microsoft Sentinel for SAP solution. Covers both **SAP NetWeaver ABAP** (via `ABAPAuditLog`) and **SAP Business Technology Platform** (via `SAPBTPAuditLog_CL`).

These queries are adapted from the 9 production analytic rules deployed in the workspace, enhanced with additional hunting scenarios, and **validated against live data** (2.5M+ ABAPAuditLog rows, 57K+ BTP events).

**SAP Tables in This Workspace:**

| Table | Rows (30d) | Description |
|-------|-----------|-------------|
| `ABAPAuditLog` | ~2.5M | SAP Security Audit Log (SAL) — primary detection source |
| `SAPBTPAuditLog_CL` | ~57K | SAP BTP audit events (security, data access, configuration) |
| `ABAPUserDetails` | ~152 | User master data snapshots (roles, lock status, type) |
| `ABAPChangeDocsLog` | 0 | Change document logs (not currently collected) |

### ⚠️ Critical Schema Notes — Legacy vs Data Lake Column Names

The built-in SAP analytic rules use **legacy function-based table names** (`SAPAuditLog`, `SAPTableDataLog`) that resolve to different underlying tables. When writing Data Lake or Advanced Hunting queries, use the **actual table names** with **correct column casing**:

| Legacy (Analytic Rules) | Data Lake / AH Table | Column Mapping |
|------------------------|---------------------|----------------|
| `SAPAuditLog` (function) | `ABAPAuditLog` | `SystemID` → `SystemId`, `MessageID` → `MessageId`, `TerminalIPv6` → `TerminalIpV6`, `ABAPProgramName` → `AbapProgramName`, `ClientID` → `ClientId` |
| `SAPTableDataLog` (function) | `ABAPTableDataLog_CL` | `SystemID` → `SystemId` |
| `SAPSystems()` | N/A | Custom function — filter `SystemRole` directly on `ABAPAuditLog` |
| `SAPUsersGetVIP()` | N/A | Custom function — use manual exclusion lists instead |

### SAP Audit Log MessageId Quick Reference

| MessageId | Event | MITRE | Severity |
|-----------|-------|-------|----------|
| AU1 | Dialog logon successful | T1078 | Info |
| AU2 | Dialog logon failed | T1110 | Medium |
| AU3 | Transaction started | T1059 | Info |
| AU5 | RFC/CPIC logon successful | T1021 | Info |
| AU6 | RFC/CPIC logon failed | T1110 | Medium |
| AU9 | User locked | — | Info |
| AUA | User unlocked | — | Info |
| AUC | User logoff | — | Info |
| AUE | Audit configuration changed | T1562.001 | High |
| AUF | Audit slot configuration | T1562.001 | Medium |
| AUG | Application server started | — | Info |
| AUI | Audit slot status (active/inactive) | T1562.001 | Medium |
| AUJ | Audit active status changed | T1562.001 | High |
| AUK | Successful RFC call | — | Info |
| AUW | Report/program started | T1059 | Info |
| AUY | File download | T1048 | High |
| BU4 | Dynamic ABAP code execution | T1059 | High |
| BUJ | Non-encrypted SAPGUI communication | — | Medium |
| BUK | Signed assertion used (SAML) | T1078.004 | Info |
| CUI | Application started | — | Info |
| CUZ | Generic table access via RFC | T1005 | Medium |
| DU9 | Generic table access call | T1005 | Medium |
| FU0 | Audit log medium changed | T1562.001 | High |
| FU9 | Virus scan profile not active | — | Medium |

---

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [SAP System Landscape Overview](#query-1-sap-system-landscape-overview) | Dashboard | `ABAPAuditLog` + `TotalEvents` |
| 2 | [Failed Logon Detection — Brute Force](#query-2-failed-logon-detection--brute-force) | Detection | `ABAPAuditLog` |
| 3 | [Critical Default Account Usage](#query-3-critical-default-account-usage) | Investigation | `ABAPAuditLog` |
| 4 | [Sensitive Transaction Code Execution](#query-4-sensitive-transaction-code-execution) | Investigation | `ABAPAuditLog` |
| 5 | [Dynamic ABAP Code Execution](#query-5-dynamic-abap-code-execution) | Investigation | `ABAPAuditLog` |
| 6 | [Audit Log Deactivation and Tampering](#query-6-audit-log-deactivation-and-tampering) | Investigation | `ABAPAuditLog` |
| 7 | [Sensitive Table Access via RFC](#query-7-sensitive-table-access-via-rfc) | Investigation | `ABAPAuditLog` + `AccessActivity` |
| 8 | [File Download — Data Exfiltration](#query-8-file-download--data-exfiltration) | Investigation | `ABAPAuditLog` |
| 9 | [Off-Hours Logon Anomalies](#query-9-off-hours-logon-anomalies) | Detection | `ABAPAuditLog` + `RiskIndicator` |
| 10 | [User Lock/Unlock Patterns](#query-10-user-lockunlock-patterns) | Investigation | `ABAPAuditLog` |
| 11 | [RFC Lateral Movement Detection](#query-11-rfc-lateral-movement-detection) | Detection | `ABAPAuditLog` |
| 12 | [Non-Encrypted SAPGUI Communication](#query-12-non-encrypted-sapgui-communication) | Investigation | `ABAPAuditLog` |
| 13 | [OS Command Execution via SM49/SM69](#query-13-os-command-execution-via-sm49sm69) | Investigation | `ABAPAuditLog` |
| 14 | [SAP User Master Data Hygiene](#query-14-sap-user-master-data-hygiene) | Posture | — |
| 15 | [BTP Privileged Role Collection Assignments](#query-15-btp-privileged-role-collection-assignments) | Investigation | `SAPBTPAuditLog_CL` |
| 16 | [BTP Malware Detection in Dev Spaces](#query-16-btp-malware-detection-in-dev-spaces) | Detection | `SAPBTPAuditLog_CL` |
| 17 | [BTP Security Event Overview](#query-17-btp-security-event-overview) | Dashboard | `SAPBTPAuditLog_CL` + `SampleEvents` |
| 18 | [SAP Alerts Correlation — Sentinel Integration](#query-18-sap-alerts-correlation--sentinel-integration) | Detection | `SecurityAlert` + `SecurityIncident` |


## Query 1: SAP System Landscape Overview

**Purpose:** Baseline discovery of the SAP system landscape, user counts, and event distribution across systems and roles.

**Use Case:** Understand the scope of SAP monitoring before hunting. Identifies which SAP systems (by SystemId and SystemRole) are reporting, how many users exist, and the distribution of key security events.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation query — summarizes landscape-wide event counts with no row-level alert logic or impacted entity."
-->
```kql
// SAP System Landscape Overview (configurable lookback)
let Lookback = 7d;
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| summarize 
    TotalEvents = count(),
    UniqueUsers = dcount(User),
    SuccessLogons = countif(MessageId in ("AU1", "AU5")),
    FailedLogons = countif(MessageId in ("AU2", "AU6")),
    SensitiveTableAccess = countif(MessageId == "CUZ"),
    TransactionStarts = countif(MessageId == "AU3"),
    Downloads = countif(MessageId == "AUY"),
    DynamicABAP = countif(MessageId == "BU4"),
    UserLocks = countif(MessageId == "AU9"),
    UserUnlocks = countif(MessageId == "AUA"),
    AuditConfigChanges = countif(MessageId == "AUE")
    by SystemId, SystemRole
| order by TotalEvents desc
```

**Expected Results:**

| Column | Description |
|--------|-------------|
| `SystemId` | SAP System ID (SID) |
| `SystemRole` | `P` = Production, `D` = Development, `Q` = QA/Test |
| `TotalEvents` | Total audit log entries |
| `UniqueUsers` | Distinct SAP usernames active |
| `SuccessLogons` / `FailedLogons` | Authentication outcome distribution |

**What to Look For:**
- 🔴 Failed logons on Production systems — may indicate brute force
- 🟠 High `DynamicABAP` counts — potential code injection
- 🟡 `AuditConfigChanges > 0` — verify legitimate configuration activity
- ✅ Validate all expected SAP systems are reporting

---

## Query 2: Failed Logon Detection — Brute Force

**Purpose:** Detect brute force or credential stuffing attacks against SAP systems by identifying concentrated failed logon attempts from a single source IP.

**Use Case:** MITRE T1110 — Brute Force. Identifies IPs with 5+ failed dialog or RFC logon attempts within the lookback window, including attack duration and targeted user accounts.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Detection uses summarize with threshold — suitable for scheduled analytics rule but not CD format (no row-level impacted entity without redesign)."
-->
```kql
// SAP Brute Force / Credential Stuffing Detection
let Lookback = 7d;
let FailThreshold = 5;
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId in ("AU2", "AU6") // Dialog / RFC logon failures
| summarize 
    FailCount = count(),
    UniqueUsers = dcount(User),
    TargetUsers = make_set(User, 10),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by TerminalIpV6, SystemId, ClientId
| where FailCount >= FailThreshold
| extend AttackDurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| extend RiskLevel = case(
    FailCount >= 50 and UniqueUsers >= 5, "High — Multi-user spray",
    FailCount >= 20, "Medium — Targeted brute force",
    "Low — Threshold breach")
| order by FailCount desc
```

**What to Look For:**
- 🔴 Multi-user spray from a single IP (UniqueUsers ≥ 5) — credential stuffing attack
- 🟠 High fail count over short duration — automated tool
- 🟡 Failed logons against service/system accounts (DDIC, SAP*, TMSADM)
- 🔵 Check `TerminalIpV6` — external IPs are higher risk than internal RFC connections

---

## Query 3: Critical Default Account Usage

**Purpose:** Monitor logon activity for SAP default and critical system accounts that should have restricted or no interactive usage in production.

**Use Case:** MITRE T1078 — Valid Accounts. Default SAP accounts (SAP*, DDIC, TMSADM, EARLYWATCH, SAPCPIC) are high-value targets. Interactive logons with these accounts in production systems are a red flag.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Monitoring query — summarizes logon activity for hardcoded critical user list. Would need refactoring to per-event row output for CD."
-->
```kql
// Critical/Default SAP Account Logon Monitoring
let Lookback = 7d;
let CriticalUsers = dynamic(["DDIC", "TMSADM", "EARLYWATCH", "SAPCPIC", "SAPSYS"]);
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId in ("AU1", "AU5") // successful logons
| where User in~ (CriticalUsers) or User startswith "SAP"
| summarize 
    LogonCount = count(),
    UniqueIPs = dcount(TerminalIpV6),
    IPs = make_set(TerminalIpV6, 5),
    LogonTypes = make_set(Variable1, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by User, SystemId, SystemRole
| order by LogonCount desc
```

**SAP Logon Type Reference (Variable1):**

| Code | Type | Risk Context |
|------|------|-------------|
| `A` | Dialog (interactive) | High risk for system accounts in production |
| `B` | Background | Normal for scheduled jobs |
| `C` | CPIC | Inter-system communication |
| `F` | RFC Internal | Internal RFC calls |
| `R` | RFC External | External RFC — verify source |
| `H` | HTTP | Web-based access |
| `S` | SRFC (Secure RFC) | Secure RFC connection |

**What to Look For:**
- 🔴 Dialog logons (`A`) with DDIC or SAP* on Production (`P`) systems
- 🟠 External RFC (`R`) from unexpected IP addresses
- 🟡 High logon count for TMSADM from non-transport IPs
- ✅ Background (`B`) logons for DDIC are typically normal (batch jobs)

---

## Query 4: Sensitive Transaction Code Execution

**Purpose:** Detect execution of high-risk SAP transaction codes that can modify system configuration, manage users, execute OS commands, or access sensitive data.

**Use Case:** MITRE T1059 — Command and Scripting Interpreter. Sensitive tcodes like SM49 (OS commands), SE16 (table browser), SU01 (user management), and STMS (transport management) are frequently abused in SAP attacks.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Detection query with lookup against static tcode list. Aggregates by tcode — would need per-event refactoring for CD."
-->
```kql
// Sensitive SAP Transaction Code Execution
let Lookback = 7d;
let SensitiveTcodes = dynamic([
    // OS Command Execution
    "SM49", "SM69",
    // Data Browser / Table Access
    "SE16", "SE16N", "SE16H", "SE11", "SE14", "SE17", "SM30", "SM31",
    // User/Role Management
    "SU01", "SU10", "SU53", "PFCG", "SU25",
    // Program Execution / Development
    "SE38", "SE80", "SA38", "SE37",
    // Transport / System Configuration  
    "STMS", "SE06", "SCC4",
    // Job Scheduling
    "SM36", "SM37",
    // System Configuration
    "RZ10", "RZ11", "SPAM", "SAINT",
    // RFC Destination Management
    "SM59",
    // System Monitoring / Debug
    "SM21", "ST01", "ST22", "SE30",
    // Database Access
    "DB01", "DB02"
]);
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId == "AU3" // Transaction Started
| where TransactionCode in (SensitiveTcodes) or Variable1 in (SensitiveTcodes)
| extend TCode = coalesce(Variable1, TransactionCode)
| where TCode in (SensitiveTcodes) // final filter on resolved tcode
| project TimeGenerated, User, SystemId, SystemRole, ClientId,
    TCode, AbapProgramName, MessageText, TerminalIpV6
| extend TCodeCategory = case(
    TCode in ("SM49", "SM69"), "OS Command Execution",
    TCode in ("SE16", "SE16N", "SE16H", "SE11", "SE14", "SE17", "SM30", "SM31"), "Data Browser / Table Access",
    TCode in ("SU01", "SU10", "SU53", "PFCG", "SU25"), "User/Role Management",
    TCode in ("SE38", "SE80", "SA38", "SE37"), "Development / Program Execution",
    TCode in ("STMS", "SE06", "SCC4"), "Transport / System Config",
    TCode in ("SM59"), "RFC Destination Management",
    "Other Sensitive")
| order by TimeGenerated desc
```

**What to Look For:**
- 🔴 SM49/SM69 execution by non-BASIS users — OS command injection (CVE-2023-0014 context)
- 🔴 SE16/SE16N in Production — direct table access bypassing application controls
- 🟠 SU01/PFCG changes — unauthorized user/role modifications
- 🟠 SM59 changes — RFC destination manipulation for lateral movement
- 🟡 Development tcodes (SE38, SE80) in Production — should be locked

---

## Query 5: Dynamic ABAP Code Execution

**Purpose:** Detect dynamic ABAP code execution events that may indicate code injection, unauthorized custom logic, or post-exploitation activities.

**Use Case:** MITRE T1059 — Dynamic ABAP execution allows runtime code generation, which can be abused for data theft, backdoor insertion, or privilege escalation. MessageId BU4 captures these events.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Low-volume detection — row-level output suitable for investigation. However, dynamic ABAP events have variable payload structure in MessageText/Variable fields making standardized CD entity mapping unreliable."
-->
```kql
// Dynamic ABAP Code Execution Detection
let Lookback = 7d;
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId == "BU4" // Dynamic ABAP code
| project TimeGenerated, User, SystemId, SystemRole, ClientId,
    TransactionCode, AbapProgramName, MessageText, 
    TerminalIpV6, Variable1, Variable2
| extend EventDetail = strcat("Event=", Variable1, " | Type=", Variable2)
| order by TimeGenerated desc
```

**What to Look For:**
- 🔴 Dynamic ABAP on Production systems — should be extremely rare
- 🔴 Execution by non-development users
- 🟠 High frequency of BU4 events in short timeframes — potential automated attack
- 🔵 `AbapProgramName` and `TransactionCode` provide context on which program triggered the dynamic code

---

## Query 6: Audit Log Deactivation and Tampering

**Purpose:** Detect attempts to disable, modify, or tamper with the SAP Security Audit Log — a critical defense evasion technique.

**Use Case:** MITRE T1562.001 — Disable or Modify Tools. Attackers disable audit logging to hide subsequent malicious activity. This query catches all audit configuration change MessageIds.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Defense evasion detection with multi-MessageId union. Low volume, high fidelity — but audit config events lack standard entity fields for CD entity mapping."
-->
```kql
// SAP Audit Log Deactivation / Tampering Detection
let Lookback = 30d;
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId in ("AUE", "AUI", "AUJ", "FU0")
| extend EventType = case(
    MessageId == "AUE", "Audit Configuration Changed",
    MessageId == "AUI", "Audit Slot Status Changed",
    MessageId == "AUJ", "Audit Active Status Changed",
    MessageId == "FU0", "Audit Log Medium Changed",
    "Unknown Audit Event")
| extend RiskLevel = case(
    MessageId == "AUJ" and Variable1 == "0", "CRITICAL — Audit Deactivated",
    MessageId == "AUI" and MessageText has "Inactive", "HIGH — Audit Slot Disabled",
    MessageId == "FU0", "HIGH — Audit Log Medium Changed",
    MessageId == "AUE", "MEDIUM — Configuration Modified",
    "INFO")
| project TimeGenerated, User, SystemId, SystemRole, MessageId, EventType, 
    RiskLevel, MessageText, TerminalIpV6, TransactionCode, Variable1
| order by TimeGenerated desc
```

**What to Look For:**
- 🔴 `AUJ` with `Variable1 == "0"` — audit log completely deactivated (maps to existing rule "SAP - Deactivation of Security Audit Log")
- 🔴 Multiple audit slots set to Inactive — systematic audit coverage reduction
- 🟠 Audit configuration changes by non-BASIS users
- 🟡 Audit medium changes — potential evidence destruction
- 🔵 Correlate timestamps with other suspicious activity (data downloads, tcode execution)

---

## Query 7: Sensitive Table Access via RFC

**Purpose:** Detect direct access to security-sensitive SAP tables via RFC connections, bypassing normal application-layer access controls.

**Use Case:** MITRE T1005 — Data from Local System. RFC-based table access (MessageId CUZ) allows direct reading of sensitive data like user credentials, authorization objects, and financial records. Maps to existing rule "SAP - Sensitive Tables Direct Access By RFC Logon".

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Volume depends heavily on AGENTLESSRFC — built-in Sentinel connector generates high CUZ volume for legitimate data collection. Exclude system users before alerting."
-->
```kql
// Sensitive Table Access via RFC — Excluding System Accounts
let Lookback = 7d;
let SystemAccounts = dynamic(["AGENTLESSRFC", "SAPSYS", "DDIC"]);
// Known sensitive SAP tables — extend this list per your environment
let SensitiveTables = dynamic([
    "USR02",      // User password hashes
    "USR04",      // User authorizations
    "USR10",      // User authorization profiles
    "USR40",      // Password restrictions
    "AGR_USERS",  // Role to user assignments 
    "AGR_1251",   // Role authorizations
    "AGR_DEFINE", // Role definitions
    "RFCTRUST",   // RFC trust relationships
    "RFCSYSACL",  // RFC system ACL
    "T000",       // Client table
    "USRSTAMP",   // User change timestamps
    "PA0002",     // HR personal data
    "PA0008",     // HR compensation
    "BSEG",       // Financial document segments
    "BKPF"        // Financial document headers
]);
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId == "CUZ" // Generic table access via RFC
| where User !in~ (SystemAccounts)
| extend TableAccessed = Variable1, AccessActivity = Variable2
| where TableAccessed in (SensitiveTables)
| summarize 
    AccessCount = count(),
    Activities = make_set(AccessActivity, 5),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by User, SystemId, SystemRole, ClientId, TableAccessed, TerminalIpV6
| order by AccessCount desc
```

**Access Activity Codes (Variable2):**

| Code | Meaning |
|------|---------|
| `02` | Change |
| `03` | Display |
| `16` | Execute |

**What to Look For:**
- 🔴 Access to `USR02` (password hashes) or `RFCTRUST` (trust relationships)
- 🔴 Change activity (`02`) on authorization tables (`AGR_USERS`, `AGR_1251`)
- 🟠 Display of HR tables (`PA0002`, `PA0008`) by non-HR users
- 🟡 Bulk access (high `AccessCount`) to financial tables

---

## Query 8: File Download — Data Exfiltration

**Purpose:** Detect file downloads from SAP systems, which may indicate data exfiltration via table export, report output, or spool downloads.

**Use Case:** MITRE T1048 — Exfiltration Over Alternative Protocol. Downloads from SAP transaction codes like SE16N are tracked by MessageId AUY. Maps to the existing rule "SAP - High volume of potentially sensitive data exported".

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Low-volume detection event — each AUY row is a discrete download. ByteCount parsing uses locale-aware string replacement. Suitable for investigation but file path + tcode context needed for CD entity mapping."
-->
```kql
// SAP File Download / Data Exfiltration Detection
let Lookback = 30d;
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId == "AUY" // File download event
| extend ByteCount = toint(replace_string(replace_string(Variable1, ".", ""), ",", ""))
| extend FilePath = Variable3
| project TimeGenerated, User, SystemId, SystemRole, ClientId,
    TransactionCode, AbapProgramName, ByteCount, FilePath, 
    MessageText, TerminalIpV6
| extend DownloadSizeKB = round(todouble(ByteCount) / 1024, 2)
| extend RiskLevel = case(
    ByteCount >= 1000000, "HIGH — Large download (1MB+)",
    ByteCount >= 100000, "MEDIUM — Significant download (100KB+)",
    "LOW — Small download")
| order by ByteCount desc
```

**What to Look For:**
- 🔴 Downloads > 1MB from production systems — potential bulk data theft
- 🔴 Downloads via SE16/SE16N — direct table export
- 🟠 Downloads to external/removable paths (non-standard drive letters)
- 🟡 Multiple downloads by the same user in a short window — staging for exfiltration
- 🔵 Correlate with preceding CUZ (sensitive table access) events for the same user/session

---

## Query 9: Off-Hours Logon Anomalies

**Purpose:** Identify interactive SAP logons occurring outside normal business hours or on weekends, which may indicate unauthorized access or compromised credentials.

**Use Case:** MITRE T1078 — Valid Accounts. Attackers often operate during off-hours to avoid detection. This query filters out system/service accounts that legitimately run 24/7.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Anomaly detection — uses hourly/weekday filtering on summarized user data. Off-hours definition is hardcoded and would need timezone parameterization for CD."
-->
```kql
// Off-Hours SAP Logon Anomaly Detection
let Lookback = 7d;
// Exclude system/service accounts that run 24/7
let SystemAccounts = dynamic(["SAPSYS", "DDIC", "TMSADM", "AGENTLESSRFC"]);
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId == "AU1" // Dialog logon successful only
| where User !in~ (SystemAccounts)
| extend HourOfDay = hourofday(TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated) / 1d
| extend IsOffHours = HourOfDay < 6 or HourOfDay > 22
| extend IsWeekend = DayOfWeek >= 5
| where IsOffHours or IsWeekend
| summarize 
    OffHoursLogons = count(),
    Hours = make_set(HourOfDay, 10),
    IPs = make_set(TerminalIpV6, 5),
    Systems = make_set(SystemId, 5),
    WeekendLogons = countif(IsWeekend),
    NightLogons = countif(IsOffHours and not(IsWeekend))
    by User
| extend RiskIndicator = case(
    NightLogons >= 10 and WeekendLogons >= 5, "HIGH — Persistent off-hours pattern",
    OffHoursLogons >= 10, "MEDIUM — Frequent off-hours access",
    "LOW — Occasional off-hours logon")
| order by OffHoursLogons desc
```

**What to Look For:**
- 🔴 Users with persistent off-hours patterns (night + weekend) who are not in on-call roles
- 🟠 Off-hours access from new/unfamiliar IPs
- 🟡 Correlate with Query 4 (sensitive tcode execution) during the same off-hours windows
- 🔵 Adjust hour thresholds based on your organization's timezone and work patterns

---

## Query 10: User Lock/Unlock Patterns

**Purpose:** Track user account lock and unlock events to detect potential account takeover sequences (brute force → lock → admin unlock → abuse).

**Use Case:** An attacker brute-forces an account (AU2), causes a lock (AU9), then social-engineers or compromises an admin to unlock it (AUA), followed by successful logon. This query surfaces the timeline.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation timeline query — projects raw events chronologically. No summarization or threshold for CD alerting."
-->
```kql
// SAP User Lock/Unlock Timeline  
let Lookback = 30d;
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId in ("AU9", "AUA", "AU2") // lock, unlock, failed logon
| extend EventType = case(
    MessageId == "AU9", "🔒 User Locked",
    MessageId == "AUA", "🔓 User Unlocked",
    MessageId == "AU2", "❌ Failed Logon",
    "Unknown")
| extend AffectedUser = case(
    MessageId in ("AU9", "AUA"), extract("User (\\w+)", 1, MessageText),
    User)
| project TimeGenerated, EventType, MessageId, User, AffectedUser, 
    SystemId, SystemRole, MessageText, TerminalIpV6
| order by TimeGenerated asc
```

**What to Look For:**
- 🔴 Sequence: Multiple AU2 (failed) → AU9 (locked) → AUA (unlocked by different user) → AU1 (success)
- 🟠 Unlock by a user who doesn't normally perform admin functions
- 🟡 Rapid lock/unlock cycles on the same account
- 🔵 `AffectedUser` (extracted from MessageText) is the target — `User` is who performed the lock/unlock action

---

## Query 11: RFC Lateral Movement Detection

**Purpose:** Profile RFC logon patterns across SAP systems to detect anomalous cross-system access that may indicate lateral movement.

**Use Case:** MITRE T1021 — Remote Services. RFC connections enable cross-system communication that attackers exploit for lateral movement. This query baselines RFC patterns and highlights deviations.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation — RFC logon profiling with user-level summarization. No row-level alerting; would need per-event refactoring for CD."
-->
```kql
// RFC Lateral Movement Profiling
let Lookback = 7d;
let SystemAccounts = dynamic(["AGENTLESSRFC", "SAPSYS", "TMSADM"]);
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId == "AU5" // RFC/CPIC logon successful
| where User !in~ (SystemAccounts)
| extend LogonType = Variable1
| summarize 
    RFCLogons = count(),
    UniqueIPs = dcount(TerminalIpV6),
    SourceIPs = make_set(TerminalIpV6, 5),
    LogonTypes = make_set(LogonType, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    ActiveHours = dcount(bin(TimeGenerated, 1h))
    by User, SystemId, SystemRole
| extend LogonVelocity = round(todouble(RFCLogons) / todouble(ActiveHours), 1)
| order by RFCLogons desc
```

**What to Look For:**
- 🔴 Human users (non-system) with RFC logons to Production from unexpected IPs
- 🟠 RFC logon type `R` (External RFC) from IPs outside the SAP landscape
- 🟡 Sudden increase in RFC activity for a user (compare to baseline)
- 🔵 Cross-reference with Query 7 (sensitive table access) — RFC logon followed by CUZ events

---

## Query 12: Non-Encrypted SAPGUI Communication

**Purpose:** Identify SAP GUI connections that are not encrypted (SNC disabled), exposing credentials and data in transit.

**Use Case:** Security posture assessment. Non-encrypted SAPGUI (MessageId BUJ) connections are a compliance concern and can be exploited for credential sniffing on the network.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture assessment query — low frequency event, not suitable for scheduled CD detection."
-->
```kql
// Non-Encrypted SAPGUI Communication Detection
let Lookback = 30d;
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where MessageId == "BUJ" // Non-encrypted SAPGUI
| project TimeGenerated, User, SystemId, SystemRole, ClientId,
    MessageText, TerminalIpV6, TransactionCode
| summarize 
    OccurrenceCount = count(),
    UniqueIPs = dcount(TerminalIpV6),
    IPs = make_set(TerminalIpV6, 5),
    LastSeen = max(TimeGenerated)
    by SystemId, SystemRole
| order by OccurrenceCount desc
```

**What to Look For:**
- 🟠 Any non-encrypted connections to Production systems
- 🟡 Connections from external network segments (non-RFC IPs)
- ⚠️ Recommend enabling SNC (Secure Network Communication) for all SAPGUI connections

---

## Query 13: OS Command Execution via SM49/SM69

**Purpose:** Detect execution of external operating system commands through SAP's SAPXPG interface (transactions SM49/SM69), a high-risk attack vector for post-exploitation.

**Use Case:** MITRE T1059 — Command Execution. SM49 lists/executes external commands, SM69 defines new ones. Attackers who gain SAP access can execute arbitrary OS commands on the underlying server. Related CVE-2023-0014.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-condition detection — combines AU3 tcode starts with broader SAPXPG text matching. SM49/SM69 events are sparse and variable in MessageText structure."
-->
```kql
// OS Command Execution via SM49/SM69 (SAPXPG)
let Lookback = 30d;
ABAPAuditLog
| where TimeGenerated > ago(Lookback)
| where (MessageId == "AU3" and (Variable1 in ("SM49", "SM69") or TransactionCode in ("SM49", "SM69")))
    or MessageText has "SAPXPG"
    or MessageText has "external command"
| extend ThreatCategory = case(
    MessageText has "SAPXPG", "SAPXPG External Command Execution",
    Variable1 == "SM69" or TransactionCode == "SM69", "External Command Definition (SM69)",
    Variable1 == "SM49" or TransactionCode == "SM49", "External Command Execution (SM49)",
    "Related External Command Activity")
| project TimeGenerated, User, SystemId, SystemRole, ClientId,
    ThreatCategory, TransactionCode, AbapProgramName, 
    MessageText, TerminalIpV6, Variable1, Variable2
| order by TimeGenerated desc
```

**What to Look For:**
- 🔴 SAPXPG command execution on Production systems — immediate investigation required
- 🔴 SM69 usage — new external command definitions indicate attacker setting up persistent access
- 🟠 SM49 by non-BASIS users — verify authorization
- 🔵 Cross-reference with SecurityAlert for "SAPXPG called a Potentially Dangerous External Command" alerts

---

## Query 14: SAP User Master Data Hygiene

**Purpose:** Audit SAP user master data for security hygiene issues: default accounts, unlocked service accounts, user type misconfigurations.

**Use Case:** MITRE T1078 — Valid Accounts. Identifies stale/misconfigured accounts that could be exploited for initial access.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture/hygiene assessment from snapshot data. ABAPUserDetails is a point-in-time table, not event-driven."
-->
```kql
// SAP User Master Data Hygiene Report
ABAPUserDetails
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by User, SystemId
| extend UserTypeLabel = case(
    UserType == "A", "Dialog (Interactive)",
    UserType == "B", "System (Non-Dialog)",
    UserType == "C", "Communication",
    UserType == "L", "Reference",
    UserType == "S", "Service",
    strcat("Unknown (", UserType, ")"))
| extend IsDefaultAccount = User in ("DDIC", "SAP*", "SAPCPIC", "EARLYWATCH", "TMSADM")
| extend RiskFlag = case(
    IsDefaultAccount and LockedStatus == "Unlocked" and UserType == "A", "🔴 HIGH — Default dialog account unlocked",
    IsDefaultAccount and LockedStatus == "Unlocked", "🟠 MEDIUM — Default system account unlocked",
    LockedStatus == "Locked" and UserType == "B", "🟡 INFO — System account locked (verify if intentional)",
    "✅ Normal")
| project User, SystemId, UserTypeLabel, LockedStatus, Email, UserGroup, RiskFlag
| order by RiskFlag asc
```

**What to Look For:**
- 🔴 Default accounts (DDIC, SAP*) unlocked with Dialog (type A) access
- 🟠 Service accounts (type S) without email — no owner accountability
- 🟡 Locked system accounts — may indicate brute force lockout
- ⚠️ Accounts with no `UserGroup` — may lack proper authorization governance

---

## Query 15: BTP Privileged Role Collection Assignments

**Purpose:** Detect assignments of privileged role collections in SAP Business Technology Platform, which could indicate privilege escalation or unauthorized access grants.

**Use Case:** MITRE T1068 — Privilege Escalation. BTP role collections like "Subaccount Administrator" and "Cloud Connector Administrator" grant broad platform access. Maps to existing rule "BTP - User added to sensitive privileged role collection".

<!-- cd-metadata
cd_ready: false
adaptation_notes: "BTP detection — requires dynamic JSON parsing of Message.object.id. SAPBTPAuditLog_CL is a custom table not supported in CD."
-->
```kql
// BTP Privileged Role Collection Assignments
let Lookback = 30d;
let SensitiveRoleCollections = dynamic([
    "Subaccount Service Administrator",
    "Subaccount Administrator", 
    "Connectivity and Destination Administrator",
    "Destination Administrator",
    "Cloud Connector Administrator",
    "Global Account Administrator",
    "Security Administrator"
]);
SAPBTPAuditLog_CL
| where TimeGenerated > ago(Lookback)
| extend MsgData = parse_json(tostring(Message))
| where tostring(MsgData.object) has "xs_rolecollection2user"
| extend ObjectId = parse_json(tostring(MsgData.object.id))
| extend ActionType = tostring(ObjectId.crudType)
| extend RoleCollection = tostring(ObjectId.rolecollection_name)
| extend TargetUser = tostring(ObjectId.user_id)
| extend RiskLevel = iff(RoleCollection in (SensitiveRoleCollections), "HIGH", "MEDIUM")
| project TimeGenerated, UserName, RoleCollection, TargetUser, ActionType, 
    RiskLevel, SubaccountName, Tenant
| order by TimeGenerated desc
```

**What to Look For:**
- 🔴 `CREATE` actions for Subaccount/Global Administrator roles
- 🔴 Self-assignment (UserName resolves to same identity as TargetUser)
- 🟠 Role assignments by service bindings (`sb-*` users) — should be automated, verify pipeline
- 🟡 `DELETE` actions — verify authorized deprovisioning

---

## Query 16: BTP Malware Detection in Dev Spaces

**Purpose:** Surface malware detections in SAP Business Application Studio (BAS) development spaces, indicating a compromised developer environment.

**Use Case:** MITRE T1059, T1588 — Code development environments are targets for supply chain attacks. Maps to existing rule "BTP - Malware detected in BAS dev space".

<!-- cd-metadata
cd_ready: false
adaptation_notes: "BTP custom table — SAPBTPAuditLog_CL not available in CD. Malware event structure requires multi-level JSON parsing."
-->
```kql
// BTP Malware Detection in Dev Spaces
let Lookback = 30d;
SAPBTPAuditLog_CL
| where TimeGenerated > ago(Lookback)
| where tostring(Message) has "malware"
| extend MessageData = parse_json(tostring(parse_json(tostring(Message)).data))
| extend MalwareData = parse_json(tostring(MessageData.message))
| extend
    ClusterID = tostring(MessageData.clusterID),
    WorkspaceID = tostring(MessageData.wsID),
    DevSpaceId = tostring(MalwareData.dev_space_id),
    DetectedUser = tostring(MalwareData.user),
    Malware = tostring(MalwareData.findings),
    AlertMessage = tostring(MalwareData.message)
| project TimeGenerated, DetectedUser, Malware, AlertMessage,
    ClusterID, WorkspaceID, DevSpaceId, SubaccountName, Tenant, Category
| order by TimeGenerated desc
```

**What to Look For:**
- 🔴 Any malware finding — investigate the dev space immediately
- 🟠 Recurring malware detections for the same user/workspace — persistent compromise
- 🔵 Check if the developer has access to production deployment pipelines

---

## Query 17: BTP Security Event Overview

**Purpose:** Baseline BTP security event categories and volume, filtering out service binding noise to focus on human user activity.

**Use Case:** Establish a baseline of BTP security events for anomaly detection. Identifies the most active human users and event patterns.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation — BTP custom table, no row-level alerting."
-->
```kql
// BTP Security Event Baseline (human users)
let Lookback = 7d;
SAPBTPAuditLog_CL
| where TimeGenerated > ago(Lookback)
| where Category == "audit.security-events"
| where UserName !startswith "sb-" // exclude service bindings
| extend MsgData = parse_json(tostring(Message))
| extend DataPayload = parse_json(tostring(MsgData.data))
| extend EventMessage = tostring(DataPayload.message)
| extend EventLevel = tostring(DataPayload.level)
| summarize 
    EventCount = count(),
    UniqueSubaccounts = dcount(SubaccountName),
    EventLevels = make_set(EventLevel, 5),
    SampleEvents = make_set(substring(EventMessage, 0, 80), 3)
    by UserName
| order by EventCount desc
```

**What to Look For:**
- 🟠 High volume of security events from a single user — potential compromise or misconfiguration
- 🟡 Events with `level = "WARNING"` or `level = "ERROR"` — authentication failures or policy violations
- ✅ `TokenIssuedEvent` and `UserAuthenticationSuccess` are normal IAM flow events

---

## Query 18: SAP Alerts Correlation — Sentinel Integration

**Purpose:** Surface all SAP-related security alerts joined with their XDR-correlated incidents, providing the full alert-to-incident mapping with status, classification, and portal links.

**Use Case:** Investigation starting point — what SAP threats has Defender XDR already correlated into incidents? Shows alert distribution per incident, closure status, and which incidents need attention.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "SecurityAlert→SecurityIncident join aggregation — not adapted for CD. Use for investigation context."
-->
```kql
// SAP Security Alerts — XDR Incident Correlation
let Lookback = 30d;
let SAPAlerts = SecurityAlert
| where TimeGenerated > ago(Lookback)
| where AlertName has "SAP" or AlertName has "BTP" or ProviderName has "SAP"
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, TimeGenerated;
SecurityIncident
| where CreatedTime > ago(Lookback)
| where array_length(AlertIds) > 0
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner SAPAlerts on $left.AlertId == $right.SystemAlertId
| summarize 
    AlertCount = count(),
    AlertTypes = make_set(AlertName, 10),
    Severities = make_set(AlertSeverity),
    Status = any(Status),
    Classification = any(Classification),
    CreatedTime = any(CreatedTime)
    by ProviderIncidentId, Title
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId)
| order by AlertCount desc
```

**What to Look For:**
- 🔴 Frequent SAPXPG alerts — active OS command abuse
- 🔴 "Risky EntraID sign-in to SAP" — compromised credentials used against SAP
- 🟠 "Sensitive data exported" alerts — exfiltration in progress
- 🟡 "BTP Malware" alerts — developer environment compromise
- 🔵 Use alert timestamps to scope deeper hunting queries above (narrow `Lookback` to incident window)

---

## Investigation Workflow

When a SAP-related threat is detected, follow this sequence:

```
1. Run Q1 (Landscape Overview) → understand scope
2. Run Q18 (Alert Correlation) → existing detections
3. Based on alert type, drill into:
   ├─ Credential attack → Q2 (Brute Force) + Q10 (Lock/Unlock) + Q9 (Off-Hours)
   ├─ Privilege abuse → Q3 (Default Accounts) + Q4 (Sensitive TCodes) + Q14 (User Hygiene)
   ├─ Data theft → Q7 (Table Access) + Q8 (Downloads)
   ├─ Defense evasion → Q6 (Audit Tampering) + Q5 (Dynamic ABAP)
   ├─ Lateral movement → Q11 (RFC Profiling) + Q13 (OS Commands)
   └─ BTP threats → Q15 (Role Assignments) + Q16 (Malware) + Q17 (BTP Baseline)
4. Cross-correlate SAP user → Entra ID (via Email field) → user-investigation skill
5. Enrich source IPs via enrich_ips.py
```
