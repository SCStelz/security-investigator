# RDP Lateral Movement Detection Queries

**Created:** 2026-01-28  
**Platform:** Both  
**Tables:** SecurityEvent, DeviceLogonEvents  
**Keywords:** RDP, lateral movement, brute force, password spray, credential stuffing, failed logon, remote desktop, EventID 4624, EventID 4625, LogonType 10, RemoteInteractive, external RDP, internet-facing  
**MITRE:** T1021.001, T1110.001, T1110.003, T1133, TA0008  
**Domains:** endpoint, identity  
**Timeframe:** Last 7 days (configurable)

---

## Overview

This file covers **two RDP threat scenarios** with queries for both `SecurityEvent` and `DeviceLogonEvents`:

| Scenario | Section | Queries | Source Filter |
|----------|---------|---------|---------------|
| **Internal Lateral Movement** | [Part A](#part-a-internal-lateral-movement-securityevent) | Q1–Q6 | RFC 1918 IPs only |
| **External Brute-Force / Initial Access** | [Part B](#part-b-external-rdp-brute-force-securityevent) | Q7–Q9 | Non-RFC 1918 IPs only |
| **External (MDE alternative)** | [Part C](#part-c-external-rdp-devicelogonevents-mde) | Q10–Q12 | Non-RFC 1918 via DeviceLogonEvents |

**Scenario selection for LLM agents:** If the investigation target is an **internet-facing device** (e.g., Threat Pulse Q11 finding, or device with `IsInternetFacing == true`), use **Part B** (SecurityEvent) or **Part C** (DeviceLogonEvents). If the investigation is about **post-compromise movement between internal systems**, use **Part A**.

### ⚠️ Table Coverage — Read Before Executing

**Two tables, three parts:**
- **Parts A & B** use `SecurityEvent` (EventID 4624/4625) — the authoritative source for RDP authentication events including SubStatus failure codes.
- **Part C** uses `DeviceLogonEvents` (MDE) — richer context (`IsLocalAdmin`, `Protocol`) but less granular failure detail.

| Table | Strengths | Limitations |
|-------|-----------|-------------|
| `SecurityEvent` (Parts A & B) | Granular Win Security log: SubStatus codes, failure reasons, Kerberos/NTLM detail | Requires Windows Security Event connector; may not exist for all devices |
| `DeviceLogonEvents` (Part C) | MDE-normalized, `IsLocalAdmin` flag, works in AH without connector | Less granular failure detail; may not capture all 4625 events |

**🔴 RULE:** When this file is referenced for a query file hunt, prefer the `SecurityEvent`-based queries (Part A or B) with entity substitution. Part C is an alternative when SecurityEvent data is unavailable.

**Key Detection Patterns:**
- Multiple failed authentication attempts from same source before success (Q2/Q9/Q12)
- External brute-force against internet-facing RDP — dictionary usernames, high failure counts (Q7/Q10)
- Successful external RDP logon from non-VPN/non-Bastion IP (Q8/Q11)
- Rapid sequential RDP connections to multiple internal systems from one source (Q4)
- High failure rates indicating credential guessing or enumeration (Q3/Q5)

**Detection Scope:**
- **Part A (Internal):** Filters for RFC 1918 private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **Part B & C (External):** Filters for non-RFC 1918 IPs (excludes private, loopback, and 0.0.0.0 broker IPs)
- **RDP-specific:** LogonType 10 (RemoteInteractive) for successes; LogonType 3 or 10 for failures

### ⚠️ NLA LogonType Pitfall — Critical

**Network Level Authentication (NLA)** — enabled by default on all modern Windows — authenticates RDP connections via CredSSP/NTLM *before* the RDP session is established. This changes how Windows logs the events:

| Event | Without NLA | With NLA (default) |
|-------|-------------|--------------------|
| **Failed RDP auth** (4625) | LogonType **10** (RemoteInteractive) | LogonType **3** (Network) |
| **Successful RDP session** (4624) | LogonType **10** | LogonType **10** (after NLA succeeds, the session upgrade is still LT10) |

**Impact:** Queries filtering `LogonType == 10` for failed logons will return **0 results** on NLA-enabled devices, silently missing all RDP brute-force attempts. This is the #1 false-negative source for RDP lateral movement detection.

**Fix applied in all queries below:** Failed logon detection uses `LogonType in (3, 10)` to catch both NLA and non-NLA failures. Successful logon detection keeps `LogonType == 10` (RDP session establishment). LogonType 3 for failures may include non-RDP network logons (SMB, WinRM) — correlate with `DeviceNetworkEvents` port 3389 for RDP-specific confirmation.

---

## Part A: Internal Lateral Movement (SecurityEvent)

> **Source filter:** RFC 1918 private IPs only. For external/internet-facing RDP, skip to [Part B](#part-b-external-rdp-brute-force-securityevent).

### Query 1: Successful RDP Authentications (Baseline)

**Purpose:** Identify all successful internal RDP connections to establish baseline activity

**Use this query to:**
- Understand normal RDP usage patterns in your environment
- Identify which systems have RDP enabled and are being accessed
- Verify query is returning data before running detection logic

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline verification query. Returns raw events with `take 100` for data validation, not detection logic."
-->
```kql
// Successful Internal RDP Connections (Last 7 Days)
// Use this query first to verify SecurityEvent data is available
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624  // Successful logon
| where LogonType == 10  // RemoteInteractive (RDP)
| extend SourceIP = IpAddress
| where SourceIP startswith "10." or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or SourceIP startswith "192.168."  // Internal IPs only
| project TimeGenerated, Computer, Account, SourceIP, LogonType, WorkstationName
| order by TimeGenerated desc
| take 100
```

**Expected Results:**
- `TimeGenerated`: When the RDP logon occurred
- `Computer`: Target system that was accessed via RDP
- `Account`: User account that logged on
- `SourceIP`: Internal IP address of the source system
- `WorkstationName`: Name of the source system

**Tuning:**
- Adjust timeframe: Change `ago(7d)` to desired lookback period
- Increase results: Change `take 100` to see more events
- Focus on specific systems: Add `| where Computer has "server-name"`

---

### Query 2: RDP Lateral Movement - Failed Attempts Before Success (PRIMARY DETECTION)

**Purpose:** Detect potential credential stuffing or brute force attacks on internal RDP connections where multiple failed attempts precede a successful logon

**Thresholds:**
- Minimum 3 failed attempts
- Within 10-minute window before successful logon
- From same source IP to same target computer

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "LateralMovement"
title: "RDP Brute Force Success: {{FailedAttempts}} failures then logon on {{TargetComputer}} from {{SourceIP}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Multi-let correlation query. CD supports `let` blocks. Remove `order by` for CD. Thresholds (failureThreshold=3, windowTime=10m) are tunable."
-->
```kql
// RDP Lateral Movement Detection - Multiple Failed Attempts Before Success
// Detects internal RDP connections with 3+ failed auth attempts within 10 minutes before successful logon
let timeframe = 7d;
let failureThreshold = 3;  // Minimum number of failed attempts to flag
let windowTime = 10m;      // Time window to correlate failures with success

// Get failed RDP logon attempts (internal IPs only)
// NLA-aware: LogonType 3 (Network/NLA) captures NLA-blocked RDP failures; LogonType 10 captures non-NLA failures
let FailedLogons = SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where EventID == 4625  // Failed logon
    | where LogonType in (3, 10)  // Network (NLA) or RemoteInteractive (non-NLA)
    | extend SourceIP = IpAddress
    | where SourceIP startswith "10." or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or SourceIP startswith "192.168."
    | project FailureTime = TimeGenerated, TargetComputer = Computer, TargetAccount = Account, SourceIP, WorkstationName;

// Get successful RDP logons (internal IPs only)
let SuccessfulLogons = SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where EventID == 4624  // Successful logon
    | where LogonType == 10  // RemoteInteractive (RDP)
    | extend SourceIP = IpAddress
    | where SourceIP startswith "10." or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or SourceIP startswith "192.168."
    | project SuccessTime = TimeGenerated, TargetComputer = Computer, TargetAccount = Account, SourceIP, WorkstationName;

// Correlate: Find successful logons that had failed attempts from same source within time window
SuccessfulLogons
| join kind=inner (
    FailedLogons
) on TargetComputer, SourceIP
| where FailureTime < SuccessTime  // Failure happened before success
| where SuccessTime - FailureTime <= windowTime  // Within time window
| summarize 
    FailedAttempts = count(),
    FirstFailure = min(FailureTime),
    LastFailure = max(FailureTime),
    FailedAccounts = make_set(TargetAccount1),
    SuccessfulAccount = any(TargetAccount)
    by TargetComputer, SourceIP, WorkstationName, SuccessTime
| where FailedAttempts >= failureThreshold
| extend TimeToSuccess = SuccessTime - FirstFailure
| project-reorder SuccessTime, TargetComputer, SourceIP, SuccessfulAccount, FailedAttempts, FailedAccounts, FirstFailure, TimeToSuccess
| order by FailedAttempts desc, SuccessTime desc
```

**Expected Results:**
- `SuccessTime`: When successful logon occurred after failures
- `TargetComputer`: System that was accessed
- `SourceIP`: Source IP that attempted the connections
- `SuccessfulAccount`: Account that successfully logged on
- `FailedAttempts`: Count of failed attempts in window
- `FailedAccounts`: List of accounts that failed authentication
- `FirstFailure`: When failed attempts began
- `TimeToSuccess`: How long from first failure to success

**Indicators of Lateral Movement:**
- **High failure count (10+):** Likely automated credential stuffing
- **Multiple failed accounts:** Attacker trying different credentials
- **Short time to success (<5 minutes):** Rapid brute force succeeded
- **After-hours activity:** RDP connections outside business hours
- **Server-to-server:** Unusual RDP from one server to another

**Tuning:**
- **More sensitive:** Decrease `failureThreshold` to 2
- **Less noise:** Increase `failureThreshold` to 5
- **Tighter window:** Decrease `windowTime` to 5m
- **Broader detection:** Increase `windowTime` to 30m

**False Positives:**
- Users who repeatedly mistype passwords
- Password expiration causing lockouts
- Service accounts with incorrect cached credentials

---

### Query 3: RDP Activity Summary with Failure Rates

**Purpose:** Aggregate view of all RDP activity showing success/failure patterns for baselining and anomaly identification

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation query. Summarizes all RDP activity per Computer/SourceIP pair for pattern analysis, not alertable detection."
-->
```kql
// RDP Activity Summary by Computer and Source
// Shows all internal RDP activity (successes and failures) for baselining
let timeframe = 7d;

// NLA-aware: Includes both LogonType 3 (NLA failures) and LogonType 10 (non-NLA + successful RDP sessions)
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where (EventID == 4625 and LogonType in (3, 10))  // Failed: NLA (LT3) or non-NLA (LT10)
    or (EventID == 4624 and LogonType == 10)          // Success: RDP session established (always LT10)
| extend SourceIP = IpAddress
| where SourceIP startswith "10." or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or SourceIP startswith "192.168."
| extend LogonStatus = case(
    EventID == 4624, "Success",
    EventID == 4625, "Failed",
    "Unknown")
| summarize 
    TotalAttempts = count(),
    SuccessfulLogons = countif(LogonStatus == "Success"),
    FailedLogons = countif(LogonStatus == "Failed"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    UniqueAccounts = dcount(Account),
    Accounts = make_set(Account)
    by Computer, SourceIP, WorkstationName
| extend FailureRate = round((FailedLogons * 100.0) / TotalAttempts, 2)
| where FailedLogons > 0  // Only show entries with at least one failure
| project-reorder Computer, SourceIP, TotalAttempts, SuccessfulLogons, FailedLogons, FailureRate, UniqueAccounts, FirstSeen, LastSeen
| order by FailedLogons desc, TotalAttempts desc
```

**Expected Results:**
- `Computer`: Target system
- `SourceIP`: Source system IP
- `TotalAttempts`: Total RDP authentication attempts
- `SuccessfulLogons`: Count of successful authentications
- `FailedLogons`: Count of failed authentications
- `FailureRate`: Percentage of failed attempts
- `UniqueAccounts`: Number of different accounts attempted
- `FirstSeen` / `LastSeen`: Time range of activity
- `Accounts`: List of all accounts involved

**Indicators of Suspicious Activity:**
- **High failure rate (>50%):** Possible credential guessing
- **Many unique accounts:** Attacker testing multiple credentials
- **Persistent failures:** Repeated failures over days/hours
- **100% failure rate:** Reconnaissance or failed attack
- **Zero successes + high attempts:** Blocked attack attempt

**Use Cases:**
- Identify systems under sustained RDP attack
- Find compromised credentials (low failure rate = valid creds stolen)
- Baseline normal RDP patterns per system
- Detect unusual source-to-target relationships

---

### Query 4: RDP Spray Detection - One Source, Many Targets

**Purpose:** Detect attackers using a compromised system to RDP into multiple other systems (common post-exploitation behavior)

**Thresholds:**
- Minimum 5 unique target systems
- Within 1-hour window
- From single source IP

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "LateralMovement"
title: "RDP Spray: {{SourceIP}} targeted {{UniqueTargets}} systems"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Threshold-based spray detection. Each row = one spray instance from a source IP. Remove `order by` for CD. Thresholds (targetThreshold=5, windowTime=1h) are tunable."
-->
```kql
// RDP Spray Detection - One Source Connecting to Many Targets
// Identifies single internal source attempting RDP to multiple systems (possible lateral movement)
let timeframe = 7d;
let targetThreshold = 5;  // Minimum number of unique targets to flag
let windowTime = 1h;      // Time window for spray activity

// NLA-aware: LogonType 3 (NLA failures) + LogonType 10 (non-NLA + successful RDP sessions)
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where (EventID == 4625 and LogonType in (3, 10))
    or (EventID == 4624 and LogonType == 10)
| extend SourceIP = IpAddress
| where SourceIP startswith "10." or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or SourceIP startswith "192.168."
| extend LogonStatus = iff(EventID == 4624, "Success", "Failed")
| summarize 
    TotalAttempts = count(),
    SuccessCount = countif(LogonStatus == "Success"),
    FailCount = countif(LogonStatus == "Failed"),
    UniqueTargets = dcount(Computer),
    TargetSystems = make_set(Computer),
    Accounts = make_set(Account),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by SourceIP, bin(TimeGenerated, windowTime)
| where UniqueTargets >= targetThreshold
| extend TimeSpan = LastAttempt - FirstAttempt
| project-reorder TimeGenerated, SourceIP, UniqueTargets, SuccessCount, FailCount, TotalAttempts, TimeSpan
| order by UniqueTargets desc, TimeGenerated desc
```

**Expected Results:**
- `TimeGenerated`: Start of time window
- `SourceIP`: Source system performing the spray
- `UniqueTargets`: Number of different systems targeted
- `SuccessCount`: Successful RDP connections
- `FailCount`: Failed RDP attempts
- `TotalAttempts`: Total connection attempts
- `TimeSpan`: Duration of spray activity
- `TargetSystems`: List of all systems targeted
- `Accounts`: Accounts used in attempts

**Indicators of Lateral Movement:**
- **Many targets + high success rate:** Active lateral movement
- **Many targets + all failures:** Reconnaissance phase
- **After-hours timing:** Attacker activity
- **Short time span (<30 min):** Automated/scripted activity
- **Server IPs as source:** Compromised server being used as pivot

**Tuning:**
- **More sensitive:** Decrease `targetThreshold` to 3
- **Large environments:** Increase `targetThreshold` to 10
- **Detect rapid sprays:** Decrease `windowTime` to 30m
- **Slower campaigns:** Increase `windowTime` to 4h

---

### Query 5: Failed RDP Attempts by Failure Reason

**Purpose:** Understand why RDP authentications are failing to distinguish between legitimate issues and attacks

**Sub-Status Codes (Common):**
- `0xC000006A`: Bad username or password (most common)
- `0xC000006D`: Bad username or password (alternate)
- `0xC0000064`: User name does not exist
- `0xC000006E`: Account restriction (disabled, locked, expired)
- `0xC0000072`: Account disabled
- `0xC000006F`: User logon outside authorized hours
- `0xC0000070`: Workstation restriction
- `0xC0000193`: Account expired
- `0xC0000071`: Password expired
- `0xC0000224`: User must change password

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summary aggregation by FailureReason/SubStatus. Intended for failure reason analysis and baselining, not per-event alerting."
-->
```kql
// Failed RDP Attempts - Categorized by Failure Reason
// Helps distinguish legitimate failures from malicious activity
let timeframe = 7d;

// NLA-aware: LogonType 3 (NLA failures) + LogonType 10 (non-NLA failures)
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4625  // Failed logon
| where LogonType in (3, 10)  // Network (NLA) or RemoteInteractive (non-NLA)
| extend SourceIP = IpAddress
| where SourceIP startswith "10." or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or SourceIP startswith "192.168."
| extend FailureReason = case(
    SubStatus == "0xC000006A", "Bad username or password",
    SubStatus == "0xC000006D", "Bad username or password (alternate)",
    SubStatus == "0xC0000064", "User name does not exist",
    SubStatus == "0xC000006E", "Account restriction",
    SubStatus == "0xC0000072", "Account disabled",
    SubStatus == "0xC000006F", "Logon outside authorized hours",
    SubStatus == "0xC0000070", "Workstation restriction",
    SubStatus == "0xC0000193", "Account expired",
    SubStatus == "0xC0000071", "Password expired",
    SubStatus == "0xC0000224", "User must change password",
    strcat("Unknown: ", SubStatus))
| summarize 
    FailureCount = count(),
    UniqueAccounts = dcount(TargetAccount),
    UniqueSources = dcount(SourceIP),
    Accounts = make_set(TargetAccount),
    SourceIPs = make_set(SourceIP),
    TargetComputers = make_set(Computer),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by FailureReason, SubStatus
| project-reorder FailureReason, FailureCount, UniqueAccounts, UniqueSources, FirstSeen, LastSeen
| order by FailureCount desc
```

**Expected Results:**
- `FailureReason`: Human-readable failure reason
- `FailureCount`: Total failures with this reason
- `UniqueAccounts`: Number of different accounts affected
- `UniqueSources`: Number of different source IPs
- `Accounts`: List of accounts that failed
- `SourceIPs`: List of source IPs
- `TargetComputers`: Systems where failures occurred

**Indicators of Malicious Activity:**
- **High "Bad password" count:** Credential guessing/brute force
- **"User does not exist" errors:** Username enumeration
- **"Account disabled" spikes:** Attacker testing old/disabled accounts
- **Multiple failure reasons from same source:** Systematic probing
- **After-hours + "Outside authorized hours":** Policy bypass attempts

**Legitimate Patterns:**
- **"Password expired":** Routine IT maintenance
- **"Account disabled":** Expected after offboarding
- **Low counts across reasons:** Normal user errors

---

### Query 6: RDP Timeline - Visualize Attack Progression

**Purpose:** Create a timeline view of RDP activity from a specific source to understand attack progression

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation/timeline query requiring manual IP parameter (`<SOURCE_IP>`). Intended for ad-hoc forensic analysis after suspicious source is identified."
-->
```kql
// RDP Attack Timeline - Detailed View
// Shows chronological progression of RDP attempts from a specific source IP
// Replace <SOURCE_IP> with IP address under investigation
let timeframe = 7d;
let sourceIPFilter = "<SOURCE_IP>";  // CHANGE THIS to IP under investigation

SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID in (4624, 4625)  // Both success and failure
| where (EventID == 4625 and LogonType in (3, 10)) or (EventID == 4624 and LogonType == 10)  // NLA-aware
| extend SourceIP = IpAddress
| where SourceIP == sourceIPFilter or sourceIPFilter == "<SOURCE_IP>"  // Remove filter if default value
| extend 
    EventType = iff(EventID == 4624, "✅ Success", "❌ Failed"),
    FailureReason = case(
        EventID == 4625 and SubStatus == "0xC000006A", "Bad password",
        EventID == 4625 and SubStatus == "0xC0000064", "User not exist",
        EventID == 4625 and SubStatus == "0xC000006E", "Account restriction",
        EventID == 4624, "Successful logon",
        "Other")
| project 
    TimeGenerated, 
    EventType, 
    SourceIP, 
    TargetComputer = Computer, 
    Account, 
    FailureReason,
    WorkstationName
| order by TimeGenerated asc
```

**Usage:**
1. **First:** Run Query 2 to identify suspicious source IPs
2. **Then:** Replace `<SOURCE_IP>` with the IP from Query 2
3. **Analyze:** Look for patterns in the timeline

**What to look for:**
- **Multiple failed attempts followed by success:** Brute force succeeded
- **Systematic progression through accounts:** Enumeration
- **Sudden burst of activity:** Automated attack
- **Success on multiple systems:** Active lateral movement
- **Failures stopping after success:** Attacker moved on

---

## Part B: External RDP Brute-Force (SecurityEvent)

> **Source filter:** Non-RFC 1918 IPs only. Use for internet-facing devices flagged by Threat Pulse Q11, `DeviceInfo.IsInternetFacing`, or exposure investigations. NLA-aware (LogonType 3 for failures).

### Query 7: External RDP Brute-Force Summary (SecurityEvent)

**Purpose:** Identify external IPs brute-forcing RDP on a specific device or fleet-wide. Aggregates failed logon attempts by source IP with failure reason breakdown and timeline.

**MITRE:** T1110.001, T1110.003, T1133 | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External RDP Brute-Force: {{SourceIP}} → {{Computer}} ({{FailedAttempts}} failures, {{UniqueAccounts}} accounts)"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "NLA-aware. No minimum threshold — every external RDP failure surfaces. For CD deployment, consider adding `| where FailedAttempts >= 5` to reduce alert volume. Entity substitution: add `| where Computer == 'HOSTNAME'` to scope to a specific device. Remove the Computer filter for fleet-wide scan."
-->
```kql
// External RDP Brute-Force Summary (SecurityEvent)
// NLA-aware: LogonType 3 (NLA) + LogonType 10 (non-NLA) for failures
let timeframe = 7d;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4625
| where LogonType in (3, 10)
| extend SourceIP = IpAddress
| where isnotempty(SourceIP)
| where not(SourceIP startswith "10." or SourceIP startswith "192.168."
    or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    or SourceIP in ("127.0.0.1", "::1", "0.0.0.0", "-"))
| extend FailureReason = case(
    SubStatus == "0xC000006A", "Bad password",
    SubStatus == "0xC0000064", "User does not exist",
    SubStatus == "0xC000006D", "Bad password (alt)",
    SubStatus == "0xC0000072", "Account disabled",
    SubStatus == "0xC000006E", "Account restriction",
    SubStatus == "0xC0000234", "Account locked out",
    strcat("Other: ", SubStatus))
| summarize
    FailedAttempts = count(),
    UniqueAccounts = dcount(Account),
    SampleAccounts = make_set(Account, 5),
    TopFailureReasons = make_set(FailureReason, 3),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, Computer
| order by FailedAttempts desc
| take 25
```

**Entity substitution:** Add `| where Computer == "<HOSTNAME>"` after the `EventID` filter to scope to a specific internet-facing device.

**Verdict guidance:**
- **`FailedAttempts >= 50`:** Automated brute-force — consider IP block
- **`FailedAttempts 5–49`:** Sustained probing — enrich IP via threat intel
- **`FailedAttempts 1–4`:** Low-volume probe or short uptime window — still noteworthy on internet-facing devices
- **`UniqueAccounts >= 5` + "User does not exist":** Username enumeration / dictionary spray
- **`FailureReason == "Bad password"` + low account count:** Targeted password guessing
- **`Account locked out` events:** Brute-force successfully triggered lockout policy

**Why no threshold:** Any external failed RDP attempt is suspicious — even 1 failure from a public IP is a signal. Internal queries (Part A) use thresholds because internal failed logons are common (password typos, expired creds). External queries intentionally have no minimum to avoid silently dropping low-volume attacks on devices with short uptime or low attacker traffic.

---

### Query 8: External RDP Successful Access (SecurityEvent)

**Purpose:** Detect successful RDP logons from external IPs. High-severity — any external RDP success on a non-VPN/non-Bastion host is suspicious.

**MITRE:** T1021.001, T1133 | **Tactic:** Initial Access, Lateral Movement

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External RDP Access: {{Account}} from {{SourceIP}} on {{Computer}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "High-severity alert. Exclude known VPN/Bastion IPs via allowlist. Entity substitution: add `| where Computer == 'HOSTNAME'` for device-specific scoping."
-->
```kql
// Successful External RDP Access (SecurityEvent)
let timeframe = 7d;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4624
| where LogonType == 10
| extend SourceIP = IpAddress
| where isnotempty(SourceIP)
| where not(SourceIP startswith "10." or SourceIP startswith "192.168."
    or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    or SourceIP in ("127.0.0.1", "::1", "0.0.0.0", "-"))
| project TimeGenerated, Computer, Account, SourceIP, LogonType, WorkstationName
| order by TimeGenerated desc
```

**Tuning:** Exclude known VPN/Bastion egress IPs: `| where SourceIP !in ("1.2.3.4", "5.6.7.8")`

---

### Query 9: External RDP Failed-Then-Success Correlation (SecurityEvent)

**Purpose:** Highest-fidelity external breach detection — correlates failed external RDP attempts with a subsequent success from the same IP. This means an attacker guessed correct credentials.

**MITRE:** T1110.001, T1021.001 | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External RDP Breach: {{SourceIP}} brute-forced {{TargetComputer}} ({{FailedAttempts}} failures then success as {{SuccessfulAccount}})"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Multi-let correlation query. CD supports `let` blocks. Remove `order by` for CD. Thresholds (failureThreshold=3, windowTime=30m) are tunable."
-->
```kql
// External RDP Failed-Then-Success (SecurityEvent)
// NLA-aware: failures use LogonType in (3, 10); successes use LogonType == 10
let timeframe = 7d;
let failureThreshold = 3;
let windowTime = 30m;
let ExternalFailed = SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where EventID == 4625
    | where LogonType in (3, 10)
    | extend SourceIP = IpAddress
    | where isnotempty(SourceIP)
    | where not(SourceIP startswith "10." or SourceIP startswith "192.168."
        or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
        or SourceIP in ("127.0.0.1", "::1", "0.0.0.0", "-"))
    | summarize
        FailedAttempts = count(),
        FailedAccounts = make_set(Account, 5),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by SourceIP, TargetComputer = Computer;
let ExternalSuccess = SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where EventID == 4624
    | where LogonType == 10
    | extend SourceIP = IpAddress
    | where isnotempty(SourceIP)
    | where not(SourceIP startswith "10." or SourceIP startswith "192.168."
        or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
        or SourceIP in ("127.0.0.1", "::1", "0.0.0.0", "-"))
    | project SuccessTime = TimeGenerated, TargetComputer = Computer,
        SuccessfulAccount = Account, SourceIP;
ExternalFailed
| where FailedAttempts >= failureThreshold
| join kind=inner ExternalSuccess on SourceIP, TargetComputer
| where SuccessTime between (FirstFailure .. (LastFailure + windowTime))
| project SourceIP, TargetComputer, FailedAttempts, FailedAccounts,
    FirstFailure, LastFailure, SuccessTime, SuccessfulAccount
| order by FailedAttempts desc
```

**Entity substitution:** Add `| where Computer == "<HOSTNAME>"` inside both `let` blocks after the `EventID` filter.

---

## Detection Rule Deployment

### Recommended Scheduled Analytics Rules

| Priority | Query | Scenario | Severity |
|----------|-------|----------|----------|
| 1 | **Q9** (External Failed-Then-Success) | External brute-force succeeded | High |
| 2 | **Q8** (External RDP Success) | Any external RDP logon | High |
| 3 | **Q2** (Internal Failed-Then-Success) | Internal lateral movement | Medium |
| 4 | **Q7** (External Brute-Force Summary) | External brute-force in progress | Medium |
| 5 | **Q4** (Internal RDP Spray) | Internal spray across targets | Medium |

### Configuration (applies to all rules)

**Schedule:**
- Run every: 5 minutes
- Lookup data from last: 15 minutes

**Alert threshold:**
- Generate alert when number of query results: Is greater than 0

**Severity:** Medium (High if FailedAttempts > 10)

**Entity Mappings:**
- Account → SuccessfulAccount
- Host → TargetComputer
- IP → SourceIP

**Tactics & Techniques:**
- Tactic: Lateral Movement
- Technique: T1021.001 - Remote Services: Remote Desktop Protocol

**Custom Details:**
- FailedAttempts
- TimeToSuccess
- FirstFailure

**Incident Configuration:**
- Create incidents: Enabled
- Group related alerts: By TargetComputer and SourceIP
- Re-open closed matching incidents: Enabled
- Lookback: 2 hours

---

## Tuning Recommendations

### Reducing False Positives

1. **Exclude known admin workstations:**
   ```kql
   | where SourceIP !in ("10.0.0.100", "10.0.0.101")  // Admin jump boxes
   ```

2. **Exclude expected server-to-server RDP:**
   ```kql
   | where not (SourceIP has "10.0.1." and Computer has "APP-SERVER")
   ```

3. **Filter out single-character typos:**
   ```kql
   | where FailedAttempts >= 3  // Increase threshold
   ```

4. **Business hours only:**
   ```kql
   | extend Hour = hourofday(TimeGenerated)
   | where Hour < 6 or Hour > 18  // After hours only
   ```

### Increasing Detection Sensitivity

1. **Lower failure threshold:**
   ```kql
   let failureThreshold = 2;  // Was 3
   ```

2. **Expand time window:**
   ```kql
   let windowTime = 30m;  // Was 10m
   ```

---

## Investigation Workflow

### Internal Lateral Movement (Part A alerts)

1. **Context gathering:** Run Q3 for the source IP's overall activity profile
2. **Timeline analysis:** Run Q6 with the suspicious source IP
3. **Failure reason analysis:** Run Q5 — "User does not exist" = enumeration, "Bad password" = credential guessing
4. **Spray confirmation:** Run Q4 to check if the source is targeting multiple systems
5. **Response:** Isolate source, reset credentials, review target for post-compromise activity

### External Brute-Force (Part B/C alerts)

1. **Scope the attack:** Run Q7/Q10 to see all external IPs targeting the device
2. **Check for breach:** Run Q9/Q12 — any failed-then-success correlation is critical
3. **Verify successful access:** Run Q8/Q11 — any external RDP success warrants immediate investigation
4. **Enrich attacker IPs:** Use `ioc-investigation` skill or `enrich_ips.py` for threat intel on source IPs
5. **Response:** Block IPs at NSG/firewall, restrict RDP to VPN/Bastion/JIT, investigate device for post-compromise activity

---

## Prerequisites

### Required Data

- **SecurityEvent table** populated from Windows Security Event logs
- **Event ID 4624** (Successful Logon) collection enabled
- **Event ID 4625** (Failed Logon) collection enabled
- **Audit Logon Events** enabled in Windows Security Policy

### Log Analytics Configuration

Enable Security Event collection via:
- Legacy Security Events connector (Common/All Events)
- Windows Security Events via AMA (Azure Monitor Agent)
- Ensure LogonType field is captured

### Test Data Availability

Run this query to verify data collection:
```kql
// NLA-aware test: checks both LogonType 3 (NLA failures) and LogonType 10 (RDP sessions)
SecurityEvent
| where TimeGenerated > ago(24h)
| where (EventID == 4625 and LogonType in (3, 10))
    or (EventID == 4624 and LogonType == 10)
| summarize Count = count() by EventID, LogonType
```

Expected results:
- EventID 4624, LogonType 10: Successful RDP sessions
- EventID 4625, LogonType 10: Failed RDP (non-NLA / legacy)
- EventID 4625, LogonType 3: Failed RDP via NLA (most common on modern Windows)
- **⚠️ If you only see LogonType 10 failures but not LogonType 3:** NLA is enabled and the old `LogonType == 10` filter is silently missing brute-force attempts

---

## Additional Resources

**Microsoft Documentation:**
- [Event ID 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) - An account was successfully logged on
- [Event ID 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) - An account failed to log on
- [LogonType Values](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)

**MITRE ATT&CK:**
- [T1021.001 - Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [TA0008 - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

**Security Best Practices:**
- Enable Network Level Authentication (NLA)
- Use Azure Bastion for RDP access
- Implement MFA for privileged accounts
- Disable RDP on systems that don't require it
- Use jump boxes/bastion hosts for administrative access

---

## Part C: External RDP — DeviceLogonEvents (MDE)

> **When to use:** These queries use the `DeviceLogonEvents` table from Microsoft Defender for Endpoint. Use them in environments with MDE onboarded devices — they provide richer context (`RemoteIP`, `Protocol`, `IsLocalAdmin`) without requiring SecurityEvent log forwarding. Available in both Advanced Hunting (30d) and Sentinel Data Lake (90d+).

### Query 10: External RDP Brute-Force Detection (DeviceLogonEvents)

**Purpose:** Detect external IPs performing RDP brute-force against MDE-enrolled devices. Covers both password spray (1 IP → many users) and brute-force (1 IP → many attempts) patterns on internet-facing RDP endpoints.

**MITRE:** T1110.001, T1110.003 | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External RDP Brute-Force: {{RemoteIP}} targeted {{TargetUsers}} users on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "DeviceLogonEvents alternative to Q7. No minimum threshold — every external RDP failure surfaces. For CD deployment, consider adding `| where FailedAttempts >= 5` to reduce alert volume. Entity substitution: add `| where DeviceName == 'HOSTNAME'` to scope. "
-->

```kql
// External RDP Brute-Force Detection (DeviceLogonEvents)
// Platform: Both (AH uses Timestamp, Data Lake uses TimeGenerated)
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| where LogonType in ("RemoteInteractive", "Network")
| where isnotempty(RemoteIP)
| where not(RemoteIP startswith "10." or RemoteIP startswith "192.168."
    or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    or RemoteIP in ("127.0.0.1", "::1"))
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(AccountName),
    SampleTargets = make_set(AccountName, 5),
    TargetDevices = make_set(DeviceName, 3),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP
| order by TargetUsers desc, FailedAttempts desc
```

**Tuning:**
- Add `| where FailedAttempts >= 10` for noisy internet-facing honeypots with high scan volume
- Add `| where DeviceName in ("server1", "server2")` to scope to known internet-facing assets

**Why no threshold:** Same rationale as Q7 — any external failed RDP attempt is noteworthy. Add a threshold back only if the query returns excessive noise in high-traffic honeypot environments.

---

### Query 11: Successful External RDP Access (DeviceLogonEvents)

**Purpose:** Detect successful RDP logons from external (non-RFC1918) IP addresses. Critical for identifying successful breaches on internet-facing RDP endpoints and unauthorized external access. Filters out `0.0.0.0` (RDP Gateway/AVD broker sessions where source IP is stripped).

**MITRE:** T1021.001, T1133 | **Tactic:** Lateral Movement, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External RDP Success: {{AccountName}} from {{RemoteIP}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "DeviceLogonEvents alternative to Q8. High-severity. Exclude known VPN/Bastion IPs via allowlist. For Data Lake: replace Timestamp with TimeGenerated."
-->

```kql
// Successful External RDP Access (DeviceLogonEvents)
// Platform: Both (AH uses Timestamp, Data Lake uses TimeGenerated)
// Filters: Excludes RFC1918 (internal), 0.0.0.0 (RDP Gateway/AVD broker), loopback
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where isnotempty(RemoteIP)
| where RemoteIP != "0.0.0.0" and RemoteIP != "::1" and RemoteIP != "127.0.0.1"
| where not(RemoteIP startswith "10." or RemoteIP startswith "192.168."
    or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.")
| project Timestamp, DeviceName, AccountName, AccountDomain, RemoteIP,
    LogonType, Protocol, IsLocalAdmin
| order by Timestamp desc
```

**Why filter `0.0.0.0`?** Windows Cloud PC, Azure Virtual Desktop, and RDP Gateway sessions route through a broker that strips the original source IP before the logon event is recorded. These appear as `RemoteIP = 0.0.0.0` and are legitimate broker-mediated sessions — not direct external RDP connections.

**Tuning:**
- Add known admin IPs to an exclusion list: `| where RemoteIP !in ("1.2.3.4", "5.6.7.8")`
- Scope to specific critical assets: `| where DeviceName in ("dc01", "sql-prod")`
- For Data Lake (90d+): replace `Timestamp` with `TimeGenerated`

---

### Query 12: External RDP Failed-Then-Success Correlation (DeviceLogonEvents)

**Purpose:** Correlate failed external RDP attempts with subsequent successful logons from the same IP — the highest-fidelity indicator of a successful external brute-force attack.

**MITRE:** T1110.001, T1021.001 | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External RDP Breach: {{RemoteIP}} brute-forced {{DeviceName}} ({{FailedAttempts}} failures then success)"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "DeviceLogonEvents alternative to Q9. Uses `invoke ExternalFilter()` function. Thresholds (failureThreshold=3, windowTime=30m) are tunable. For Data Lake: replace Timestamp with TimeGenerated."
-->

```kql
// External RDP Failed-Then-Success (DeviceLogonEvents)
// Platform: Both (AH uses Timestamp, Data Lake uses TimeGenerated)
let timeframe = 7d;
let failureThreshold = 3;
let windowTime = 30m;
let ExternalFilter = (T:(RemoteIP:string)) {
    T
    | where isnotempty(RemoteIP)
    | where RemoteIP != "0.0.0.0" and RemoteIP != "::1" and RemoteIP != "127.0.0.1"
    | where not(RemoteIP startswith "10." or RemoteIP startswith "192.168."
        or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.")
};
let Failed = DeviceLogonEvents
    | where Timestamp > ago(timeframe)
    | where ActionType == "LogonFailed"
    | where LogonType in ("RemoteInteractive", "Network")
    | invoke ExternalFilter()
    | summarize
        FailedAttempts = count(),
        FailedAccounts = make_set(AccountName, 5),
        FirstFailure = min(Timestamp),
        LastFailure = max(Timestamp)
        by RemoteIP, DeviceName;
let Success = DeviceLogonEvents
    | where Timestamp > ago(timeframe)
    | where ActionType == "LogonSuccess"
    | where LogonType in ("RemoteInteractive", "Network")
    | invoke ExternalFilter()
    | project SuccessTime = Timestamp, DeviceName, SuccessAccount = AccountName,
        RemoteIP, IsLocalAdmin;
Failed
| where FailedAttempts >= failureThreshold
| join kind=inner Success on RemoteIP, DeviceName
| where SuccessTime between (FirstFailure .. (LastFailure + windowTime))
| project RemoteIP, DeviceName, FailedAttempts, FailedAccounts,
    FirstFailure, LastFailure, SuccessTime, SuccessAccount, IsLocalAdmin
| order by FailedAttempts desc
```

**Tuning:**
- `failureThreshold`: Minimum failed attempts before flagging (default: 3)
- `windowTime`: Time window after last failure to check for success (default: 30m)
- For Data Lake: replace `Timestamp` with `TimeGenerated`

---

## Version History

- **v1.0 (2026-01-28):** Initial query collection created
  - 6 core detection queries
  - Tested against Microsoft Sentinel SecurityEvent table
- **v1.1 (2026-04-11):** Added DeviceLogonEvents (MDE) queries
  - Query 10: External RDP brute-force detection
  - Query 11: Successful external RDP access (with 0.0.0.0 RDP Gateway filter)
  - Query 12: External RDP failed-then-success correlation
  - Validated against live DeviceLogonEvents data (180d lookback)
  - All queries validated for syntax and performance
- **v1.2 (2026-04-11):** Restructured file into Parts A/B/C + NLA fix + external SecurityEvent queries
  - Fixed NLA LogonType pitfall across all queries (LogonType 3 for failed RDP via NLA)
  - Added Part B: External RDP brute-force via SecurityEvent (Q7–Q9) — mirrors Part A patterns for internet-facing devices
  - Restructured overview with scenario selection table for LLM agents
  - Renumbered DeviceLogonEvents queries to Q10–Q12 (Part C)

---

## Support & Feedback

For questions, improvements, or additional use cases, please update this document or consult your security operations team.
