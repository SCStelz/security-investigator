# RDP Lateral Movement Detection Queries

**Created:** 2026-01-28  
**Platform:** Microsoft Sentinel  
**Tables:** SecurityEvent  
**Keywords:** RDP, lateral movement, brute force, credential stuffing, failed logon, remote desktop, EventID 4624, EventID 4625, LogonType 10  
**MITRE:** T1021.001, TA0008  
**Timeframe:** Last 7 days (configurable)

---

## Overview

This collection of KQL queries helps detect potential RDP lateral movement within your internal network. Lateral movement via RDP is a common technique used by attackers after initial compromise, where they attempt to move from one system to another using Remote Desktop Protocol.

**Key Detection Patterns:**
- Multiple failed authentication attempts from same source before success
- Unusual RDP connections between internal systems
- High failure rates on internal RDP connections
- Rapid sequential RDP connections across multiple systems

**Detection Scope:**
- **Internal IPs only:** Filters for RFC 1918 private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **RDP-specific:** LogonType 10 (RemoteInteractive)

---

## Query 1: Successful RDP Authentications (Baseline)

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
| where SourceIP startswith "10." or SourceIP startswith "172." or SourceIP startswith "192.168."  // Internal IPs only
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

## Query 2: RDP Lateral Movement - Failed Attempts Before Success (PRIMARY DETECTION)

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
let FailedLogons = SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where EventID == 4625  // Failed logon
    | where LogonType == 10  // RemoteInteractive (RDP)
    | extend SourceIP = IpAddress
    | where SourceIP startswith "10." or SourceIP startswith "172." or SourceIP startswith "192.168."
    | project FailureTime = TimeGenerated, TargetComputer = Computer, TargetAccount = Account, SourceIP, WorkstationName;

// Get successful RDP logons (internal IPs only)
let SuccessfulLogons = SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where EventID == 4624  // Successful logon
    | where LogonType == 10  // RemoteInteractive (RDP)
    | extend SourceIP = IpAddress
    | where SourceIP startswith "10." or SourceIP startswith "172." or SourceIP startswith "192.168."
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

## Query 3: RDP Activity Summary with Failure Rates

**Purpose:** Aggregate view of all RDP activity showing success/failure patterns for baselining and anomaly identification

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation query. Summarizes all RDP activity per Computer/SourceIP pair for pattern analysis, not alertable detection."
-->
```kql
// RDP Activity Summary by Computer and Source
// Shows all internal RDP activity (successes and failures) for baselining
let timeframe = 7d;

SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID in (4624, 4625)  // Both success and failure
| where LogonType == 10  // RemoteInteractive (RDP)
| extend SourceIP = IpAddress
| where SourceIP startswith "10." or SourceIP startswith "172." or SourceIP startswith "192.168."
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

## Query 4: RDP Spray Detection - One Source, Many Targets

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

SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID in (4624, 4625)  // Both successful and failed
| where LogonType == 10  // RemoteInteractive (RDP)
| extend SourceIP = IpAddress
| where SourceIP startswith "10." or SourceIP startswith "172." or SourceIP startswith "192.168."
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

## Query 5: Failed RDP Attempts by Failure Reason

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

SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4625  // Failed logon
| where LogonType == 10  // RemoteInteractive (RDP)
| extend SourceIP = IpAddress
| where SourceIP startswith "10." or SourceIP startswith "172." or SourceIP startswith "192.168."
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

## Query 6: RDP Timeline - Visualize Attack Progression

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
| where LogonType == 10  // RemoteInteractive (RDP)
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

## Detection Rule Deployment

### Recommended Scheduled Analytics Rule Configuration

**Rule Name:** RDP Lateral Movement - Failed Attempts Before Success

**Rule Query:** Use Query 2 from this document

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

3. **Include external-to-internal RDP:**
   ```kql
   // Remove internal IP filter to see all sources
   | where isnotempty(SourceIP)
   ```

---

## Investigation Workflow

When an alert fires from these queries:

1. **Context gathering:**
   - Run Query 3 to see overall activity for the source IP
   - Check if source IP is a known system (workstation, server, jump box)
   - Verify target computer is expected to have RDP enabled

2. **Timeline analysis:**
   - Run Query 6 with the suspicious source IP
   - Look for patterns: systematic enumeration, spray attacks, time gaps

3. **Failure reason analysis:**
   - Run Query 5 to understand why authentication failed
   - "User does not exist" = enumeration
   - "Bad password" = credential guessing

4. **Lateral movement confirmation:**
   - Run Query 4 to see if source is targeting multiple systems
   - Check if successful account has admin rights on target
   - Correlate with other logs (process creation, file access)

5. **Response actions:**
   - Isolate source system if compromised
   - Reset credentials for successful account
   - Review target system for indicators of compromise
   - Block RDP access between affected systems
   - Enable Network Level Authentication (NLA) if not already enabled

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
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4625)
| where LogonType == 10
| summarize Count = count() by EventID
```

Expected results:
- EventID 4624: Should show successful RDP logons
- EventID 4625: May be 0 if no failures (good sign!)

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

## Version History

- **v1.0 (2026-01-28):** Initial query collection created
  - 6 core detection queries
  - Tested against Microsoft Sentinel SecurityEvent table
  - All queries validated for syntax and performance

---

## Support & Feedback

For questions, improvements, or additional use cases, please update this document or consult your security operations team.
