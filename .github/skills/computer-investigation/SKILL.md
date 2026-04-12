---
name: computer-investigation
description: Use this skill when asked to investigate a computer, device, endpoint, or machine for security issues, suspicious activity, malware, or compliance review. Triggers on keywords like "investigate computer", "investigate device", "investigate endpoint", "check machine", "device security", "endpoint investigation", or when a device name/hostname is mentioned with investigation context. This skill provides comprehensive device security analysis including Defender alerts, sign-in patterns, logged-on users, vulnerabilities, software inventory, compliance status, network activity, and automated investigation tracking for Entra Joined, Hybrid Joined, and Entra Registered devices.
threat_pulse_domains: [endpoint]
drill_down_prompt: 'Investigate device {entity} — Defender alerts, process activity, vulnerabilities, compliance'
---

# Computer Security Investigation - Instructions

## Purpose

This skill performs comprehensive security investigations on Windows, macOS, and Linux devices registered in Microsoft Entra ID and/or managed by Microsoft Defender for Endpoint. It analyzes Defender alerts, device compliance, sign-in patterns, logged-on users, installed software, vulnerabilities, network connections, and automated investigation results for:

- **Entra Joined Devices**: Cloud-only devices joined directly to Microsoft Entra ID
- **Hybrid Joined Devices**: Devices joined to both on-premises Active Directory and Microsoft Entra ID
- **Entra Registered Devices**: Personal devices (BYOD) registered with Microsoft Entra ID

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Investigation Types](#available-investigation-types)** - Standard/Quick/Comprehensive
3. **[Output Modes](#output-modes)** - Inline / Markdown file / JSON export
4. **[Quick Start](#quick-start-tldr)** - 5-step investigation pattern
5. **[Execution Workflow](#execution-workflow)** - Complete process
6. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns
7. **[Microsoft Graph Queries](#microsoft-graph-device-queries)** - Entra ID device data
8. **[Defender for Endpoint Queries](#defender-for-endpoint-queries)** - MDE API integration
9. **[Markdown Report Template](#markdown-report-template)** - Full markdown report structure
10. **[JSON Export Structure](#json-export-structure)** - Required fields
11. **[Error Handling](#error-handling)** - Troubleshooting guide
12. **[SVG Dashboard Generation](#svg-dashboard-generation)** - Visual dashboard from report data

**Investigation shortcuts:**
- **Device with behavioral drift** (TP Q6): **Q3** (suspicious processes) → **Q11** (logon events) → **Q7** (incidents) → **Q8** (device info)
- **Internet-facing critical asset** (TP Q11): **Q8** (device info + internet-facing) → **Q4** (outbound connections) → **Q10** (vulnerabilities) → **Q11** (logon events)
- **Device in active incident** (TP Q1): **Q2** (security alerts) → **Q3** (process execution) → **Q5** (file events) → **Q6** (registry persistence) → **Q7** (incidents)
- **Brute-forced endpoint** (TP Q4): **Q11** (logon events) → **Q4** (outbound connections) → **Q12** (TI IP matches)
- **Vulnerability assessment** (TP Q12): **Q9** (software inventory) → **Q10** (CVEs on device) → **Q8** (exposure score)

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY computer investigation:**

1. **ALWAYS get Device ID FIRST** (required for Defender API and Graph queries - multiple IDs exist!)
2. **ALWAYS determine device type** (Entra Joined, Hybrid Joined, or Entra Registered)
3. **ALWAYS calculate date ranges correctly** (use current date from context - see Date Range section)
4. **ALWAYS ask the user for output mode** if not specified: inline chat summary, markdown file report, or JSON export (see [Output Modes](#output-modes))
5. **ALWAYS track and report time after each major step** (mandatory)
6. **ALWAYS run independent queries in parallel** (drastically faster execution)
7. **ALWAYS use `create_file` for JSON export and markdown reports** (NEVER use PowerShell terminal commands)
8. **⛔ ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)

---

## ⛔ MANDATORY: Sentinel Workspace Selection

**This skill requires a Sentinel workspace to execute queries. Follow these rules STRICTLY:**

### When invoked from a parent skill (incident-investigation, threat-pulse, etc.):
- Inherit the workspace selection from the parent investigation context
- If no workspace was selected in parent context: **STOP and ask user to select**
- Use the `SELECTED_WORKSPACE_IDS` passed from the parent skill
- **Skip output mode prompts** — default to inline chat (the parent skill controls the final output format)

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
   - STOP and report the error
   - Display available workspaces
   - ASK user to select a different workspace
   - WAIT for user response

### Workspace Failure Handling

```
IF query returns "Failed to resolve table" or similar error:
    - STOP IMMEDIATELY
    - Report: "⚠️ Query failed on workspace [NAME] ([ID]). Error: [ERROR_MESSAGE]"
    - Display: "Available workspaces: [LIST_ALL_WORKSPACES]"
    - ASK: "Which workspace should I use instead?"
    - WAIT for explicit user response
    - DO NOT retry with a different workspace automatically
```

**🔴 PROHIBITED ACTIONS:**
- ❌ Selecting a workspace without user consent when multiple exist
- ❌ Switching to another workspace after a failure without asking
- ❌ Proceeding with investigation if workspace selection is ambiguous
- ❌ Assuming a workspace based on previous sessions

---

**Device ID Types:**
- **Entra Device ID** (Azure AD Object ID): Used for Graph API queries - GUID format
- **Defender Device ID**: Used for MDE API queries - GUID format (different from Entra ID!)
- **Device Name/Hostname**: Human-readable name, use for initial search
- **Intune Device ID**: Used for Intune management queries

**Date Range Rules:**
- **Real-time/recent searches:** Add +2 days to current date for end range
- **Historical ranges:** Add +1 day to user's specified end date
- **Example:** Current date = Jan 23; "Last 7 days" → `datetime(2026-01-16)` to `datetime(2026-01-25)`

---

## Device Types Reference

### Entra Joined Devices
- **trustType**: `AzureAd`
- **Characteristics**: Cloud-only, no on-premises AD connection
- **Identity**: Uses Entra ID for authentication
- **Common scenarios**: Cloud-native organizations, Windows Autopilot deployments

### Hybrid Joined Devices
- **trustType**: `ServerAd` (indicates hybrid join with on-premises AD)
- **Characteristics**: Joined to both on-premises AD and Entra ID
- **Identity**: Uses both on-premises AD and Entra ID
- **Common scenarios**: Traditional enterprise environments migrating to cloud

### Entra Registered Devices
- **trustType**: `Workplace`
- **Characteristics**: Personal/BYOD devices, user adds work account
- **Identity**: User authenticates with Entra ID, device not fully managed
- **Common scenarios**: BYOD policies, personal device access to corporate resources

---

## Available Investigation Types

### Standard Investigation (7 days)
**When to use:** General security reviews, routine investigations

**Example prompts:**
- "Investigate device WORKSTATION-001 for the last 7 days"
- "Run security investigation for computer LAP-JSMITH from 2026-01-16 to 2026-01-23"
- "Check endpoint security for DESKTOP-ABC123"

### Quick Investigation (1 day)
**When to use:** Urgent cases, active malware alerts, recent suspicious activity

**Example prompts:**
- "Quick investigate infected device SRV-SQL01"
- "Run quick security check on machine WKS-FINANCE02"
- "Urgent: check device LAPTOP-EXEC-01 for compromise"

### Comprehensive Investigation (30 days)
**When to use:** Deep-dive analysis, lateral movement detection, thorough forensics

**Example prompts:**
- "Full investigation for potentially compromised device SRV-DC01"
- "Do a deep dive investigation on endpoint WORKSTATION-IT03 last 30 days"
- "Comprehensive security analysis for hybrid joined device DESKTOP-HR01"

**All types include:** Defender alerts, device compliance, sign-in patterns from device, logged-on users, software inventory, vulnerabilities, network connections, file activities, automated investigation status, and security recommendations.

---

## Output Modes

This skill supports three output modes. **ASK the user which they prefer** if not explicitly specified. Multiple modes may be selected simultaneously.

### Mode 1: Inline Chat Summary (Default)
- Render the full investigation analysis directly in the chat response
- Includes device profile, risk assessment, alerts, vulnerabilities, logged-on users, and recommendations
- Best for quick review and interactive follow-up questions
- No file output — results stay in the chat context

### Mode 2: Markdown File Report
- Save a comprehensive investigation report to `reports/computer-investigations/computer_investigation_<device_name>_<YYYYMMDD_HHMMSS>.md`
- All sections from inline mode plus additional detail (full vulnerability tables, process event samples, network connection details, query appendix)
- Uses the [Markdown Report Template](#markdown-report-template) defined below
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename pattern:** `computer_investigation_<device_name>_YYYYMMDD_HHMMSS.md` (lowercase device name, replace spaces/special chars with underscores)

### Mode 3: JSON Export (Legacy)
- Export investigation data to JSON for downstream processing or archival
- Uses the [JSON Export Structure](#json-export-structure) defined below
- Best for programmatic consumption or integration with other tools

### Markdown Rendering Notes
- ✅ ASCII tables, box-drawing characters, and bar charts render perfectly in markdown code blocks
- ✅ Unicode block characters (`█` full block, `─` box-drawing horizontal) display correctly in monospaced fonts
- ✅ Emoji indicators (🔴🟢🟡⚠️✅) render natively in GitHub-flavored markdown
- ✅ Standard markdown tables (`| col |`) render as formatted tables
- **Tip:** Wrap all ASCII art in triple-backtick code fences for consistent rendering

---

## Quick Start (TL;DR)

When a user requests a computer security investigation:

1. **Get Device IDs:**
   ```
   # First, find the device and get both Entra ID and Defender ID
   mcp_microsoft_mcp_microsoft_graph_get("/v1.0/devices?$filter=displayName eq '<DEVICE_NAME>'&$select=id,deviceId,displayName,operatingSystem,trustType,isCompliant,isManaged")
   # Then get Defender device ID from MDE
   Use Defender `ListDefenderMachines` or Advanced Hunting to find by device name
   ```

2. **Run Parallel Queries:**
   - Batch 1: 8 Sentinel/Advanced Hunting queries (device sign-ins, alerts, process events, network, files, incidents)
   - Batch 2: 5 Defender API queries (machine details, logged-on users, alerts, vulnerabilities, recommendations)
   - Batch 3: 3 Graph queries (device details, compliance, BitLocker keys if needed)

3. **Export & Report (Mode-Dependent):**
   - **Mode 1 (Inline):** Render analysis directly in chat using the [Markdown Report Template](#markdown-report-template) as a guide
   - **Mode 2 (Markdown):** Build full report using the [Markdown Report Template](#markdown-report-template), save to `reports/computer-investigations/`
   - **Mode 3 (JSON):** Export to `temp/investigation_device_<device_name>_<timestamp>.json`

4. **Generate Summary Report:**
   Provide investigation summary with key findings, risk assessment, and recommendations.

5. **Track time after each major step** and report to user

---

## Execution Workflow

### 🚨 MANDATORY: Time Tracking Pattern

**YOU MUST TRACK AND REPORT TIME AFTER EVERY MAJOR STEP:**

```
[MM:SS] ✓ Step description (XX seconds)
```

**Required Reporting Points:**
1. After Device ID retrieval
2. After parallel data collection
3. After JSON file creation
4. After summary generation
5. Final: Total elapsed time

---

### Phase 1: Get Device IDs (REQUIRED FIRST)

**Step 1a: Get Entra Device ID from Microsoft Graph**
```
/v1.0/devices?$filter=displayName eq '<DEVICE_NAME>'&$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,registrationDateTime,approximateLastSignInDateTime,mdmAppId,profileType
```

**Step 1b: Get Defender Device ID**
Use Advanced Hunting or Defender API to find the MDE device ID:
```kql
DeviceInfo
| where DeviceName startswith '<DEVICE_NAME>'  // Use startswith to match both hostname and FQDN
| summarize arg_max(TimeGenerated, *) by DeviceName
| project DeviceId, DeviceName, OSPlatform, OSVersion, MachineGroup, OnboardingStatus, ExposureLevel, SensorHealthState, MachineTags
```
**Note:** RiskScore is NOT in DeviceInfo - use `GetDefenderMachine` API to get riskScore and exposureLevel.

**Why BOTH IDs are required:**
- **Entra Device ID**: Used for Graph API (compliance, registration, BitLocker, Intune)
- **Defender Device ID**: Used for MDE API (alerts, vulnerabilities, logged-on users, investigations)
- **IDs are DIFFERENT**: The same device has different GUIDs in Entra ID vs Defender for Endpoint

**Device Type Determination:**
- Check `trustType` field from Graph API response:
  - `AzureAd` = Entra Joined
  - `ServerAd` = Hybrid Joined
  - `Workplace` = Entra Registered

---

### Phase 2: Parallel Data Collection

**CRITICAL:** Use `create_file` tool to create JSON - NEVER use PowerShell terminal commands!

#### Batch 1: Sentinel/Advanced Hunting Queries (Run ALL in parallel)
- Device sign-in events (Query 1) - Who signed into this device
- Device alerts (Query 2) - SecurityAlert filtered by device
- Process execution events (Query 3) - Suspicious process activity
- Network connection events (Query 4) - Outbound connections
- File events (Query 5) - File creation/modification/deletion
- Registry events (Query 6) - Registry modifications
- Security incidents (Query 7) - Incidents containing this device
- Device inventory changes (Query 8) - Configuration changes

#### Batch 2: Defender for Endpoint API (Run ALL in parallel)
- Machine details (`GetDefenderMachine`) - Device info from MDE
- Logged-on users (`GetDefenderMachineLoggedOnUsers`) - Recent users
- Device alerts (`GetDefenderMachineAlerts`) - MDE alerts
- Device vulnerabilities (Advanced Hunting) - CVEs on device
- Installed software (Advanced Hunting) - Software inventory

#### Batch 3: Graph API Queries (Run ALL in parallel)
- Device details (Graph) - Full device properties
- Compliance policies (Graph) - Applied compliance policies
- Intune device status (if MDM enrolled) - Intune management data

---

### Phase 3: Export & Generate Report (Mode-Dependent)

#### Mode 1 — Inline Chat Summary
- No file export needed
- Render the full investigation analysis directly in chat using the section structure from the [Markdown Report Template](#markdown-report-template) as a guide
- Include: Device Profile, Alert Summary, Logged-On Users, Vulnerability Overview, Process Activity, Network Connections, Risk Assessment, Recommendations
- Use emoji-coded tables for risk factors and mitigating factors

#### Mode 2 — Markdown File Report

1. **Assess IP enrichment needs:**
   - Extract public IPs from network connection events and sign-in data
   - Run `python enrich_ips.py <ip1> <ip2> ...` for threat intelligence enrichment
   - Parse the output to populate IP Intelligence tables in the report

2. **Build the markdown report** using the [Markdown Report Template](#markdown-report-template) below
   - Populate ALL sections with actual query data
   - For sections with no data: use the explicit absence confirmation pattern (e.g., "✅ No alerts detected...")
   - Calculate risk score and assessment dynamically

3. **Save the report:**
   ```
   create_file("reports/computer-investigations/computer_investigation_<device_name>_YYYYMMDD_HHMMSS.md", markdown_content)
   ```
   - Use `create_file` tool — NEVER use terminal commands for file output
   - Lowercase device name, replace spaces/special chars with underscores

#### Mode 3 — JSON Export (Legacy)

1. **Export to JSON:**
   ```
   create_file("temp/investigation_device_<device_name>_<timestamp>.json", json_content)
   ```

2. Merge all results into one dict structure (see [JSON Export Structure](#json-export-structure) section below)

---

## Required Field Specifications

### Device Query (Graph API)
```
/v1.0/devices?$filter=displayName eq '<DEVICE_NAME>'&$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,registrationDateTime,approximateLastSignInDateTime,mdmAppId,profileType,manufacturer,model,enrollmentType,deviceOwnership
```
- All fields REQUIRED for investigation
- `trustType` determines device join type
- `isCompliant` and `isManaged` indicate MDM status

### Defender Machine Details
Use the Defender `GetDefenderMachine` MCP tool with Defender Device ID:
- Returns: healthStatus, riskScore, exposureLevel, onboardingStatus, lastSeen, osPlatform, osVersion

---

## Sample KQL Queries

Use these exact patterns with the appropriate MCP tool. Replace `<DEVICE_NAME>`, `<DEVICE_ID>`, `<StartDate>`, `<EndDate>`.

**⚠️ CRITICAL: START WITH THESE EXACT QUERY PATTERNS**
**These queries have been tested and validated. Use them as your PRIMARY reference.**

---

### 🔧 MCP Tool Invocation Reference

**CRITICAL: Use the correct parameter names for each tool!**

#### Sentinel Data Lake MCP (query_lake tool)
- **Tool:** Use the Sentinel Data Lake MCP's `query_lake` tool
- **Parameter name:** `query`
- **Time column:** `TimeGenerated`
- **Use for:** Native Sentinel tables (SigninLogs, SecurityAlert, SecurityIncident, AuditLogs) AND MDE tables ingested into Sentinel (DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, etc.)

**Example invocation:**
```
query_lake(
    query="DeviceInfo | where DeviceName startswith 'DEVICENAME' | summarize arg_max(TimeGenerated, *) by DeviceId",
    workspaceId="<WORKSPACE_ID>"
)
```

#### Defender XDR Advanced Hunting (RunAdvancedHuntingQuery tool)
- **Tool:** Use the Sentinel Triage MCP's `RunAdvancedHuntingQuery` tool
- **Parameter name:** `kqlQuery` (NOT `query`!)
- **Time column:** `Timestamp`
- **Use for:** TVM tables (DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities) that are NOT ingested into Sentinel Data Lake

**Example invocation:**
```
RunAdvancedHuntingQuery(
    kqlQuery="DeviceTvmSoftwareVulnerabilities | where DeviceName startswith 'DEVICENAME' | take 30"
)
```

#### Tool Selection Guide

| Table Type | Primary Tool | Time Column | Notes |
|------------|--------------|-------------|-------|
| SigninLogs, AuditLogs | Sentinel Data Lake | TimeGenerated | Native Sentinel tables |
| SecurityAlert, SecurityIncident | Sentinel Data Lake | TimeGenerated | Native Sentinel tables |
| DeviceInfo, DeviceProcessEvents | Sentinel Data Lake | TimeGenerated | MDE tables in Sentinel |
| DeviceNetworkEvents, DeviceFileEvents | Sentinel Data Lake | TimeGenerated | MDE tables in Sentinel |
| DeviceLogonEvents, DeviceRegistryEvents | Sentinel Data Lake | TimeGenerated | MDE tables in Sentinel |
| **DeviceTvmSoftwareInventory** | **Advanced Hunting** | Timestamp | Snapshot table, NOT in Sentinel |
| **DeviceTvmSoftwareVulnerabilities** | **Advanced Hunting** | Timestamp | Snapshot table, NOT in Sentinel |

**Schema Differences:**
- Some MDE columns (e.g., `SentBytes`, `ReceivedBytes` in DeviceNetworkEvents) may not be available in Sentinel Data Lake
- Always test queries against the target tool's schema

---

### 📅 Date Range Quick Reference

**🔴 STEP 0: GET CURRENT DATE FIRST (MANDATORY) 🔴**
- **ALWAYS check the current date from the context header BEFORE calculating date ranges**
- **NEVER use hardcoded years** - the year changes and you WILL query the wrong timeframe

**RULE 1: Real-Time/Recent Searches (Current Activity)**
- **Add +2 days to current date for end range**
- **Why +2?** +1 for timezone offset (PST behind UTC) + +1 for inclusive end-of-day
- **Pattern**: Today is Jan 23 (PST) → Use `datetime(2026-01-25)` as end date

**RULE 2: Historical Searches (User-Specified Dates)**
- **Add +1 day to user's specified end date**
- **Why +1?** To include all 24 hours of the final day

**Examples Table (Assuming Current Date = January 23, 2026):**

| User Request | `<StartDate>` | `<EndDate>` | Rule Applied |
|--------------|---------------|-------------|--------------|
| "Last 7 days" | `2026-01-16` | `2026-01-25` | Rule 1 (+2) |
| "Last 30 days" | `2025-12-24` | `2026-01-25` | Rule 1 (+2) |
| "Jan 15 to Jan 20" | `2026-01-15` | `2026-01-21` | Rule 2 (+1) |

---

### 1. Device Sign-In Events (Who authenticated on this device)

**Note:** DeviceDetail is `dynamic` in SigninLogs but `string` in AADNonInteractiveUserSignInLogs. Query SigninLogs only for device context (interactive sign-ins contain device info). Do NOT use `union` with DeviceDetail filtering - causes schema conflicts in Sentinel Data Lake.

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
SigninLogs
| where TimeGenerated between (start .. end)
| extend DeviceDetailStr = tostring(DeviceDetail)
| where DeviceDetailStr has deviceName
| extend ParsedDevice = parse_json(DeviceDetailStr)
| extend DeviceName = tostring(ParsedDevice.displayName)
| extend DeviceId = tostring(ParsedDevice.deviceId)
| extend DeviceOS = tostring(ParsedDevice.operatingSystem)
| extend DeviceTrustType = tostring(ParsedDevice.trustType)
| extend DeviceCompliant = tostring(ParsedDevice.isCompliant)
| summarize 
    SignInCount = count(),
    SuccessCount = countif(ResultType == '0'),
    FailureCount = countif(ResultType != '0'),
    UniqueUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 10),
    Applications = make_set(AppDisplayName, 10),
    IPAddresses = make_set(IPAddress, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, DeviceOS, DeviceTrustType, DeviceCompliant
| order by SignInCount desc
```

### 2. Device Security Alerts (SecurityAlert table)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has deviceName or CompromisedEntity has deviceName
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project 
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Status,
    Description,
    ProviderName,
    Tactics,
    Techniques,
    CompromisedEntity,
    RemediationSteps
| order by TimeGenerated desc
| take 20
```

### 3. Process Execution Events (Suspicious processes)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| where ActionType in ("ProcessCreated", "ProcessCreatedUsingWmiQuery")
| extend CommandLineLength = strlen(ProcessCommandLine)
| extend IsSuspicious = case(
    ProcessCommandLine has_any ("powershell", "cmd", "wscript", "cscript") and ProcessCommandLine has_any ("-enc", "-e ", "bypass", "hidden", "downloadstring", "invoke-expression", "iex"), true,
    ProcessCommandLine has_any ("certutil", "bitsadmin") and ProcessCommandLine has_any ("download", "transfer", "urlcache"), true,
    ProcessCommandLine has_any ("reg", "registry") and ProcessCommandLine has_any ("add", "delete") and ProcessCommandLine has_any ("run", "runonce"), true,
    FileName in~ ("mimikatz.exe", "procdump.exe", "psexec.exe", "cobaltstrike", "beacon.exe"), true,
    CommandLineLength > 500, true,
    false)
| summarize 
    ProcessCount = count(),
    SuspiciousCount = countif(IsSuspicious),
    UniqueProcesses = dcount(FileName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleCommands = make_set(ProcessCommandLine, 5)
    by FileName, FolderPath, AccountName, AccountDomain
| where SuspiciousCount > 0 or ProcessCount > 50
| order by SuspiciousCount desc, ProcessCount desc
| take 20
```

### 4. Network Connection Events (Outbound connections)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Private" // Focus on public IPs
| summarize 
    ConnectionCount = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    UniqueRemotePorts = dcount(RemotePort),
    Protocols = make_set(Protocol, 5),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP, RemotePort, RemoteUrl
| order by ConnectionCount desc
| take 30
```

### 5. File Events (File creation/modification/deletion)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| where ActionType in ("FileCreated", "FileModified", "FileDeleted", "FileRenamed")
| extend FileExtension = tostring(split(FileName, ".")[-1])
| extend IsSuspicious = case(
    FileExtension in~ ("exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "hta", "scr", "pif"), true,
    FolderPath has_any ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\programdata\\", "\\users\\public\\"), true,
    false)
| summarize 
    FileEventCount = count(),
    SuspiciousCount = countif(IsSuspicious),
    CreatedCount = countif(ActionType == "FileCreated"),
    ModifiedCount = countif(ActionType == "FileModified"),
    DeletedCount = countif(ActionType == "FileDeleted"),
    UniqueFiles = dcount(FileName),
    FileExtensions = make_set(FileExtension, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by FolderPath, InitiatingProcessFileName
| where SuspiciousCount > 0 or FileEventCount > 100
| order by SuspiciousCount desc, FileEventCount desc
| take 20
```

### 6. Registry Events (Registry modifications)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceRegistryEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| extend IsPersistence = case(
    RegistryKey has_any ("\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce", "\\CurrentVersion\\RunServices"), true,
    RegistryKey has_any ("\\Policies\\Explorer\\Run", "\\Active Setup\\Installed Components"), true,
    RegistryKey has_any ("\\Image File Execution Options\\", "\\Winlogon\\", "\\BootExecute"), true,
    RegistryKey has_any ("\\Services\\", "\\Drivers\\"), true,
    false)
| summarize 
    RegistryEventCount = count(),
    PersistenceCount = countif(IsPersistence),
    UniqueKeys = dcount(RegistryKey),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RegistryKey, RegistryValueName, InitiatingProcessFileName
| where PersistenceCount > 0
| order by PersistenceCount desc, RegistryEventCount desc
| take 20
```

### 7. Security Incidents Containing Device
```kql
let deviceName = '<DEVICE_NAME>';
let deviceId = '<DEVICE_ID>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has deviceName or Entities has deviceId or CompromisedEntity has deviceName
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where not(tostring(Labels) has "Redirected")
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| extend ProviderIncidentUrl = tostring(AdditionalData.providerIncidentUrl)
| extend OwnerUPN = tostring(Owner.userPrincipalName)
| summarize 
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    CreatedTime = any(CreatedTime),
    LastModifiedTime = any(LastModifiedTime),
    OwnerUPN = any(OwnerUPN),
    ProviderIncidentUrl = any(ProviderIncidentUrl),
    AlertCount = count(),
    Tactics = make_set(Tactics)
    by ProviderIncidentId
| order by LastModifiedTime desc
| take 10
```

### 8. Device Inventory and Configuration Changes

**Note:** RiskScore is NOT in DeviceInfo - use GetDefenderMachine API for risk/exposure scores.

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceInfo
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| summarize arg_max(TimeGenerated, *) by DeviceId
| project 
    TimeGenerated,
    DeviceId,
    DeviceName,
    OSPlatform,
    OSVersion,
    OSBuild,
    OSArchitecture,
    LoggedOnUsers,
    MachineGroup,
    DeviceCategory,
    OnboardingStatus,
    SensorHealthState,
    ExposureLevel,
    IsAzureADJoined,
    IsInternetFacing,
    JoinType,
    PublicIP,
    MachineTags
```

### 9. Software Inventory on Device

**⚠️ DO NOT use Sentinel Data Lake MCP (`query_lake`) for this query.** The `DeviceTvmSoftwareInventory` table is NOT available in the Sentinel Data Lake. Use Advanced Hunting MCP (`RunAdvancedHuntingQuery`) only. TVM tables use snapshot ingestion with no TimeGenerated filtering.

```kql
let deviceName = '<DEVICE_NAME>';
DeviceTvmSoftwareInventory
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| project 
    DeviceName,
    SoftwareVendor,
    SoftwareName,
    SoftwareVersion,
    EndOfSupportStatus,
    EndOfSupportDate
| summarize by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate
| order by NumberOfWeaknesses desc
| take 30
```

### 10. Vulnerabilities on Device

**⚠️ DO NOT use Sentinel Data Lake MCP (`query_lake`) for this query.** The `DeviceTvmSoftwareVulnerabilities` table is NOT available in the Sentinel Data Lake. Use Advanced Hunting MCP (`RunAdvancedHuntingQuery`) only. TVM tables use snapshot ingestion with no TimeGenerated filtering.

```kql
let deviceName = '<DEVICE_NAME>';
DeviceTvmSoftwareVulnerabilities
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| project
    CveId,
    VulnerabilitySeverityLevel,
    SoftwareVendor,
    SoftwareName,
    SoftwareVersion,
    RecommendedSecurityUpdate,
    RecommendedSecurityUpdateId
| summarize by CveId, VulnerabilitySeverityLevel, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by case(VulnerabilitySeverityLevel == "Critical", 1, VulnerabilitySeverityLevel == "High", 2, VulnerabilitySeverityLevel == "Medium", 3, 4) asc
| take 30
```

### 11. Logon Events on Device
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceLogonEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| summarize 
    LogonCount = count(),
    SuccessCount = countif(ActionType == "LogonSuccess"),
    FailureCount = countif(ActionType == "LogonFailed"),
    UniqueAccounts = dcount(AccountName),
    LogonTypes = make_set(LogonType, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    RemoteIPs = make_set(RemoteIP, 10)
    by AccountName, AccountDomain, LogonType
| order by LogonCount desc
| take 20
```

### 12. Threat Intelligence IP Matches (Device Network Traffic)

**Performance notes:** ThreatIntelIndicators can be large (100K+ rows). Filter `IsActive`/`ValidUntil` **before** string transformations per [KQL best practices](https://learn.microsoft.com/en-us/kusto/query/best-practices) — reduce data first, transform later. The triple `replace_string` was replaced with direct array indexing `split(...)[0]` which returns a clean string.

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
let device_ips = DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName  // Use startswith to match both hostname and FQDN
| where RemoteIPType != "Private"
| distinct RemoteIP;
ThreatIntelIndicators
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| where tostring(split(ObservableKey, ":")[0]) in ("ipv4-addr", "ipv6-addr", "network-traffic")
| where ObservableValue in (device_ips)
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| summarize arg_max(TimeGenerated, *) by ObservableValue
| project 
    TimeGenerated,
    IPAddress = ObservableValue,
    ThreatDescription = Description,
    Confidence,
    ValidUntil,
    IsActive
| order by Confidence desc
| take 20
```


---

## Microsoft Graph Device Queries

**Use these Graph API queries in Phase 2 (Batch 3) of investigation workflow**

### Step 1: Find Device by Name
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/devices?$filter=displayName eq '<DEVICE_NAME>'&$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,registrationDateTime,approximateLastSignInDateTime,mdmAppId,profileType,manufacturer,model,enrollmentType,deviceOwnership")
```

### Step 2: Get Device Owners
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/devices/<DEVICE_OBJECT_ID>/registeredOwners?$select=id,displayName,userPrincipalName")
```

### Step 3: Get Device Users
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/devices/<DEVICE_OBJECT_ID>/registeredUsers?$select=id,displayName,userPrincipalName")
```

### Step 4: Get BitLocker Recovery Keys (if needed)
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/informationProtection/bitlocker/recoveryKeys?$filter=deviceId eq '<DEVICE_ID>'")
```
**NOTE**: Requires `BitLockerKey.Read.All` permission

### Step 5: Get Intune Device Details (if MDM enrolled)
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/deviceManagement/managedDevices?$filter=deviceName eq '<DEVICE_NAME>'&$select=id,deviceName,managedDeviceOwnerType,complianceState,managementAgent,lastSyncDateTime,osVersion,azureADRegistered,azureADDeviceId,deviceEnrollmentType,deviceCategoryDisplayName,serialNumber,userPrincipalName")
```

---

## Defender for Endpoint Queries

**Use these MDE API queries in Phase 2 (Batch 2) of investigation workflow**

### Get Machine Details
```
GetDefenderMachine(id="<DEFENDER_DEVICE_ID>")
```
Returns: id, computerDnsName, osPlatform, osVersion, healthStatus, onboardingStatus, riskScore, exposureLevel, lastSeen, lastIpAddress, lastExternalIpAddress, rbacGroupName, machineTags

### Get Logged-On Users
```
GetDefenderMachineLoggedOnUsers(id="<DEFENDER_DEVICE_ID>")
```
Returns: Array of users with accountName, accountDomain, firstSeen, lastSeen, logonTypes

### Get Machine Alerts (via API)
Use the `ListAlerts` MCP tool filtered by device:
```
ListAlerts with machineId filter
```

### Get Automated Investigations
```
ListDefenderInvestigations
```
Filter results by machineId to find investigations related to the device

### Get Remediation Activities
```
ListDefenderRemediationActivities
```
Filter results by machineId to find remediation tasks for the device

---

## Markdown Report Template

When outputting to markdown file (Mode 2), use this template. Populate ALL sections with actual query data. For sections with no data, use the explicit absence confirmation pattern.

**Filename pattern:** `reports/computer-investigations/computer_investigation_<device_name>_YYYYMMDD_HHMMSS.md`

````markdown
# Computer Security Investigation Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Workspace:** <workspace_name>
**Device:** `<DEVICE_NAME>`
**OS:** <operating_system> <os_version>
**Trust Type:** <Entra Joined / Hybrid Joined / Entra Registered> (`<trustType>`)
**Compliance:** <Compliant/Non-Compliant> | **Managed:** <Yes/No> | **MDM:** <Intune/None>
**Investigation Period:** <start_date> → <end_date> (<N> days)
**Investigation Type:** <Standard (7d) / Quick (1d) / Comprehensive (30d)>
**Data Sources:** DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, SigninLogs, SecurityAlert, SecurityIncident, DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareInventory, ThreatIntelIndicators, Microsoft Graph API, Defender for Endpoint API

---

## Executive Summary

<2-4 sentence summary: overall device risk level, key findings, most significant alerts or vulnerabilities, and primary recommendation. Ground every claim in evidence from query results.>

**Overall Risk Level:** 🔴 CRITICAL / 🔴 HIGH / 🟠 MEDIUM / 🟡 LOW / 🟢 INFORMATIONAL

---

## Device Profile

| Property | Value |
|----------|-------|
| **Device Name** | `<device_name>` |
| **OS** | <os_platform> <os_version> (<os_build>) |
| **Architecture** | <os_architecture> |
| **Trust Type** | <Entra Joined / Hybrid Joined / Entra Registered> |
| **Compliant** | 🟢 Yes / 🔴 No |
| **Managed** | 🟢 Yes / 🔴 No |
| **Manufacturer** | <manufacturer> |
| **Model** | <model> |
| **Registration Date** | <datetime> |
| **Last Sign-in** | <datetime> |
| **Internet Facing** | 🔴 Yes / 🟢 No |

### Defender for Endpoint Status

| Property | Value |
|----------|-------|
| **Onboarding Status** | 🟢 Onboarded / 🔴 Not Onboarded |
| **Sensor Health** | 🟢 Active / 🟠 Inactive / 🔴 Misconfigured |
| **Health Status** | <health_status> |
| **Risk Score** | 🔴/🟠/🟡/🟢 <None/Low/Medium/High> |
| **Exposure Level** | 🔴/🟠/🟡/🟢 <None/Low/Medium/High> |
| **Last Seen** | <datetime> |
| **Last Internal IP** | <ip_address> |
| **Last External IP** | <ip_address> |
| **Machine Group** | <group_name> |
| **Device Tags** | <comma-separated list from machineTags, or "None"> |

### Device Owners & Registered Users

<If owners/users found:>

| User | UPN | Role |
|------|-----|------|
| <display_name> | <upn> | Owner / Registered User |

<If no owners/users:>
✅ No registered owners or users found for this device.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| **Security Alerts** | <count> (Critical: <n>, High: <n>, Medium: <n>, Low: <n>) |
| **Security Incidents** | <count> (Open: <n>, Closed: <n>) |
| **Logged-On Users** | <count> unique users |
| **Sign-ins from Device** | <count> (Success: <n>, Failed: <n>) |
| **Vulnerabilities** | <count> (Critical: <n>, High: <n>, Medium: <n>) |
| **Suspicious Processes** | <count> flagged |
| **Network Connections** | <count> external IPs |
| **TI Matches** | <count> threat intel hits |
| **End-of-Support Software** | <count> |

---

## Security Alerts

<If alerts found:>

| Time | Alert Name | Severity | Status | Provider | Tactics | Compromised Entity |
|------|-----------|----------|--------|----------|---------|---------------------|
| <datetime> | <alert_name> | 🔴/🟠/🟡 <severity> | <status> | <provider> | <tactics> | <entity> |

**Alert Summary:**
- <X> total alerts (<breakdown by severity>)
- <Brief description of most critical alert(s)>
- Remediation steps: <summary of recommended actions from alert data>

<If no alerts:>
✅ No security alerts detected for this device in the investigation period.
- Checked: SecurityAlert filtered by device name and device ID (0 matches)

---

## Security Incidents

<If incidents found:>

| ID | Title | Severity | Status | Classification | Created | Owner | Alerts | Link |
|----|-------|----------|--------|----------------|---------|-------|--------|------|
| <provider_incident_id> | <title> | 🔴/🟠/🟡 <severity> | <New/Active/Closed> | <TP/FP/BP/—> | <date> | <owner_upn> | <count> | [View](<url>) |

**Incident Summary:**
- <X> total incidents (<Y> open, <Z> closed)
- Highest severity: <level>
- <Brief description of most critical incident>

<If no incidents:>
✅ No security incidents involving this device in the investigation period.
- Checked: SecurityAlert → SecurityIncident join on device name and device ID (0 matches)

---

## Logged-On Users

<If users found:>

| Account | Domain | Logon Type | Logon Count | Success | Failed | First Seen | Last Seen |
|---------|--------|------------|:-----------:|:-------:|:------:|------------|-----------|
| <account_name> | <domain> | <Interactive/RemoteInteractive/Network/etc.> | <count> | <count> | <count> | <date> | <date> |

**User Analysis:**
- <X> unique accounts authenticated on this device
- <Summary of logon patterns — expected vs unexpected accounts, after-hours logons, remote IPs>

<If no logon data:>
✅ No logon events detected for this device in the investigation period.

### Defender Logged-On Users (API)

<If MDE logged-on users found:>

| Account | Domain | First Seen | Last Seen | Logon Types |
|---------|--------|------------|-----------|-------------|
| <account_name> | <domain> | <date> | <date> | <types> |

<If no MDE data:>
✅ No logged-on user data returned from Defender for Endpoint API.

---

## Sign-in Activity (From Device)

<If sign-in events found:>

| Device Name | OS | Trust Type | Compliant | Users | Applications | IPs | Sign-ins | Success | Failed | First Seen | Last Seen |
|-------------|-----|------------|-----------|:-----:|:------------:|:---:|:--------:|:-------:|:------:|------------|-----------|
| <name> | <os> | <trust> | 🟢/🔴 | <count> | <count> | <count> | <count> | <count> | <count> | <date> | <date> |

**Top Users:** <list of UPNs>
**Top Applications:** <list of apps>
**Top IPs:** <list of IPs>

<If no sign-in events:>
✅ No sign-in events found for this device in the investigation period.

---

## Process Activity

<If suspicious processes found:>

| Process | Path | Account | Process Count | Suspicious | Sample Command Lines |
|---------|------|---------|:------------:|:----------:|----------------------|
| <filename> | <folder_path> | <account_name> | <count> | 🔴 <count> | <truncated_command> |

**Process Analysis:**
- <X> suspicious process executions detected
- <Summary of suspicious patterns — encoded commands, LOLBins, credential dumping tools, long command lines>

<If no suspicious processes:>
✅ No suspicious process activity detected on this device in the investigation period.
- Checked: DeviceProcessEvents filtered for suspicious indicators (0 flagged)

---

## Network Connections

<If external connections found:>

| Remote IP | Remote Port | URL | Connections | Unique Ports | Protocols | Initiating Processes | First Seen | Last Seen |
|-----------|:-----------:|-----|:-----------:|:------------:|-----------|----------------------|------------|-----------|
| <ip> | <port> | <url> | <count> | <count> | <protocols> | <process_list> | <date> | <date> |

**Network Summary:**
- <X> unique external IPs contacted
- <Y> unique remote ports
- <Top initiating processes>

<If no external connections:>
✅ No external network connections detected for this device in the investigation period.

### Threat Intelligence Matches

<If TI matches found:>

| IP Address | Threat Description | Confidence | Valid Until | Active |
|------------|-------------------|:----------:|------------|:------:|
| <ip> | <description> | <score> | <date> | ✅/❌ |

<If no TI matches:>
✅ No threat intelligence matches found for device network traffic.
- Checked: ThreatIntelIndicators joined with device external IPs (0 matches)

---

## File Activity

<If suspicious file events found:>

| Folder Path | Initiating Process | Total Events | Suspicious | Created | Modified | Deleted | Extensions | First Seen | Last Seen |
|-------------|-------------------|:------------:|:----------:|:-------:|:--------:|:-------:|------------|------------|-----------|
| <path> | <process> | <count> | 🔴 <count> | <count> | <count> | <count> | <ext_list> | <date> | <date> |

**File Activity Analysis:**
- <X> suspicious file operations detected
- <Summary — executable drops in temp folders, script creation, mass file modifications>

<If no suspicious file events:>
✅ No suspicious file activity detected on this device in the investigation period.
- Checked: DeviceFileEvents for suspicious extensions and temp folder activity (0 flagged)

---

## Registry Modifications

<If persistence-related registry events found:>

| Registry Key | Value Name | Initiating Process | Total Events | Persistence | First Seen | Last Seen |
|-------------|------------|-------------------|:------------:|:-----------:|------------|-----------|
| <key> | <value_name> | <process> | <count> | 🔴 <count> | <date> | <date> |

**Registry Analysis:**
- <X> persistence-related registry modifications detected
- <Summary — Run keys, services, Winlogon, IFEO modifications>

<If no persistence registry events:>
✅ No persistence-related registry modifications detected on this device in the investigation period.
- Checked: DeviceRegistryEvents for Run/RunOnce/Services/Winlogon/IFEO keys (0 flagged)

---

## Vulnerabilities

<If vulnerabilities found:>

| CVE ID | Severity | Vendor | Software | Version | Security Update |
|--------|----------|--------|----------|---------|-----------------|
| <cve_id> | 🔴/🟠/🟡 <severity> | <vendor> | <software> | <version> | <update_id> |

**Vulnerability Summary:**
- <X> total vulnerabilities (Critical: <n>, High: <n>, Medium: <n>, Low: <n>)
- <Most critical CVEs and their remediation status>

<If no vulnerabilities:>
✅ No known vulnerabilities detected on this device.
- Checked: DeviceTvmSoftwareVulnerabilities (0 records)

---

## Software Inventory

<If notable software found:>

| Vendor | Software | Version | End of Support | EOS Date |
|--------|----------|---------|:--------------:|----------|
| <vendor> | <software> | <version> | 🔴 Yes / 🟢 No | <date> |

**Software Summary:**
- <X> total software packages installed
- <Y> end-of-support software detected
- <Notable findings — outdated browsers, deprecated runtimes, risky applications>

<If no software data:>
✅ No software inventory data available for this device.
- Checked: DeviceTvmSoftwareInventory (0 records)

---

## Device Configuration

<If configuration data available:>

| Property | Value |
|----------|-------|
| **Public IP** | <ip> |
| **Machine Group** | <group> |
| **Device Category** | <category> |
| **Onboarding Status** | <status> |
| **Sensor Health** | <health> |
| **Exposure Level** | <level> |
| **Azure AD Joined** | <Yes/No> |
| **Internet Facing** | <Yes/No> |
| **Join Type** | <type> |

---

## IP Intelligence

<Table of external IPs from network connections and sign-in data. Run `enrich_ips.py` for top IPs.>

| IP Address | Source | Location | ISP/Org | VPN | Abuse Score | Reports | Risk |
|------------|--------|----------|---------|-----|-------------|---------|------|
| <ip> | 🔵 Network / 🔵 Sign-in / 🔴 TI Match | <city, country> | <org> | 🟢 No / 🔴 Yes | <score>% | <count> | HIGH/MED/LOW |

---

## Risk Assessment

### Risk Score: <XX>/100 — 🔴 CRITICAL / 🔴 HIGH / 🟠 MEDIUM / 🟡 LOW / 🟢 INFORMATIONAL

### Risk Factors

| Factor | Finding |
|--------|---------|
| 🔴/🟠/🟡 **<Factor Name>** | <Evidence-grounded finding with specific numbers> |

### Mitigating Factors

| Factor | Finding |
|--------|---------|
| 🟢 **<Factor Name>** | <Evidence-grounded finding with specific numbers> |

---

## Recommendations

### Critical Actions
<Numbered list of critical actions with evidence. Only include if critical findings exist.>

### High Priority Actions
<Numbered list of high-priority actions with evidence.>

### Monitoring Actions (14-Day Follow-Up)
<Bulleted list of ongoing monitoring recommendations.>

---

## Appendix: Query Details

| # | Query | Table(s) | Tool | Records | Execution |
|---|-------|----------|------|--------:|----------:|
| 1 | Device Sign-In Events | SigninLogs | Data Lake | <count> | <time> |
| 2 | Security Alerts | SecurityAlert | Data Lake | <count> | <time> |
| 3 | Process Events | DeviceProcessEvents | Data Lake | <count> | <time> |
| 4 | Network Connections | DeviceNetworkEvents | Data Lake | <count> | <time> |
| 5 | File Events | DeviceFileEvents | Data Lake | <count> | <time> |
| 6 | Registry Events | DeviceRegistryEvents | Data Lake | <count> | <time> |
| 7 | Security Incidents | SecurityAlert, SecurityIncident | Data Lake | <count> | <time> |
| 8 | Device Inventory | DeviceInfo | Data Lake | <count> | <time> |
| 9 | Software Inventory | DeviceTvmSoftwareInventory | Advanced Hunting | <count> | <time> |
| 10 | Vulnerabilities | DeviceTvmSoftwareVulnerabilities | Advanced Hunting | <count> | <time> |
| 11 | Logon Events | DeviceLogonEvents | Data Lake | <count> | <time> |
| 12 | Threat Intelligence | ThreatIntelIndicators, DeviceNetworkEvents | Data Lake | <count> | <time> |
| — | Device Profile | Microsoft Graph API | Graph | 1 | <time> |
| — | Device Owners/Users | Microsoft Graph API | Graph | <count> | <time> |
| — | Machine Details | Defender for Endpoint API | MDE | 1 | <time> |
| — | Logged-On Users | Defender for Endpoint API | MDE | <count> | <time> |

*Query definitions: see the Sample KQL Queries section in this SKILL.md file.*

**Do NOT include full KQL text in the appendix** — the canonical queries are already documented in this SKILL.md file. The appendix serves as an audit trail only.

---

**Investigation Timeline:**
- [MM:SS] ✓ Phase 1: Device ID retrieval (<X>s)
- [MM:SS] ✓ Phase 2: Parallel data collection (<X>s)
- [MM:SS] ✓ IP Enrichment (<X>s)
- [MM:SS] ✓ Phase 3: Report generation (<X>s)
- **Total Investigation Time:** <duration>
````

### Markdown Report Authoring Guidelines

1. **Populate every section** — even if data is empty. Use the `✅ No <X> detected...` pattern for empty sections.
2. **Never invent data** — follow the [Evidence-Based Analysis](#-evidence-based-analysis---global-rule) global rule strictly. Every number in the report must come from a query result.
3. **Risk assessment is dynamic** — calculate risk score using the weighted framework in the [Risk Assessment Framework](#risk-assessment-framework) section (Defender Risk Score 25%, Active Alerts 25%, Vulnerabilities 20%, Compliance Status 15%, Sign-in Anomalies 15%).
4. **IP enrichment** — run `enrich_ips.py` for external IPs from network connections and sign-in data. If `enrich_ips.py` is unavailable, use Sentinel ThreatIntelIndicators data as fallback.
5. **PII-Free** — the report file is saved to `reports/` which is gitignored. However, exercise caution with any files that may be shared externally.
6. **Emoji consistency** — follow the [Emoji Formatting](#emoji-formatting-for-investigation-output) table from `copilot-instructions.md` for all risk/status indicators.
7. **Query appendix** — include record counts and execution times but NOT full KQL text. Reference the SKILL.md query numbers.
8. **Trust type context** — always reference the device trust type in the Executive Summary and Risk Assessment, as it affects the security implications.

---

## JSON Export Structure

Export MCP query results to a single JSON file with these required keys:

```json
{
  "device_name": "WORKSTATION-001",
  "device_id_entra": "<ENTRA_DEVICE_OBJECT_ID>",
  "device_id_defender": "<DEFENDER_DEVICE_ID>",
  "device_type": "HybridJoined",
  "investigation_date": "2026-01-23",
  "start_date": "2026-01-16",
  "end_date": "2026-01-25",
  "timestamp": "20260123_143200",
  
  "device_profile": {
    "displayName": "WORKSTATION-001",
    "operatingSystem": "Windows",
    "operatingSystemVersion": "10.0.22621.3007",
    "trustType": "ServerAd",
    "isCompliant": true,
    "isManaged": true,
    "registrationDateTime": "2025-06-15T10:30:00Z",
    "approximateLastSignInDateTime": "2026-01-23T14:00:00Z",
    "manufacturer": "Dell Inc.",
    "model": "Latitude 5520"
  },
  
  "defender_profile": {
    "healthStatus": "Active",
    "riskScore": "Medium",
    "exposureLevel": "Low",
    "onboardingStatus": "Onboarded",
    "sensorHealthState": "Active",
    "lastSeen": "2026-01-23T14:30:00Z",
    "lastIpAddress": "10.0.1.50",
    "lastExternalIpAddress": "203.0.113.42"
  },
  
  "device_owners": [...],
  "device_users": [...],
  "signin_events": [...],
  "security_alerts": [...],
  "process_events": [...],
  "network_events": [...],
  "file_events": [...],
  "registry_events": [...],
  "incidents": [...],
  "logged_on_users": [...],
  "software_inventory": [...],
  "vulnerabilities": [...],
  "automated_investigations": [...],
  "remediation_activities": [...],
  "threat_intel_matches": [...],
  
  "summary": {
    "total_alerts": 5,
    "critical_alerts": 1,
    "high_alerts": 2,
    "medium_alerts": 2,
    "low_alerts": 0,
    "total_vulnerabilities": 15,
    "critical_vulnerabilities": 2,
    "unique_logged_on_users": 3,
    "suspicious_processes": 4,
    "threat_intel_hits": 1
  }
}
```

---

## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Device not found in Graph API** | Try searching by deviceId instead of displayName, check case sensitivity |
| **Defender Device ID not matching** | Use Advanced Hunting to find correct Defender ID by device name |
| **DeviceName query returns empty** | Use `startswith` instead of `=~` - DeviceName often contains FQDN (e.g., `hostname.domain.com`) |
| **SigninLogs DeviceDetail fails with union** | DeviceDetail is `dynamic` in SigninLogs but `string` in AADNonInteractiveUserSignInLogs - query tables separately, don't use `union isfuzzy=true` with DeviceDetail filtering |
| **RiskScore column not found** | RiskScore is NOT in DeviceInfo table - use `GetDefenderMachine` API for riskScore |
| **Missing compliance data** | Device may not be MDM enrolled - check `isManaged` field |
| **No process events** | Device may not be onboarded to Defender for Endpoint |
| **Trust type is null** | Device may be partially registered - check registrationDateTime |
| **Query timeout on DeviceEvents** | Reduce date range or add more specific filters |
| **BitLocker query fails** | Verify permissions and that BitLocker is enabled on device |

### Required Field Defaults

```json
{
  "trustType": "Workplace",
  "isCompliant": false,
  "isManaged": false,
  "approximateLastSignInDateTime": "1970-01-01T00:00:00Z",
  "riskScore": "Unknown",
  "exposureLevel": "Unknown",
  "healthStatus": "Unknown"
}
```

### Empty Result Handling

```json
{
  "signin_events": [],
  "security_alerts": [],
  "process_events": [],
  "network_events": [],
  "file_events": [],
  "registry_events": [],
  "incidents": [],
  "logged_on_users": [],
  "software_inventory": [],
  "vulnerabilities": [],
  "automated_investigations": [],
  "remediation_activities": [],
  "threat_intel_matches": []
}
```

---

## Device Trust Type Analysis

### Security Implications by Trust Type

#### Entra Joined (`trustType: AzureAd`)
- **Pros**: Full cloud management, Conditional Access enforcement, BitLocker key escrow
- **Cons**: No access to on-premises resources without VPN/Azure AD Application Proxy
- **Investigation Focus**: Cloud sign-in patterns, Intune compliance, Conditional Access logs

#### Hybrid Joined (`trustType: ServerAd`)
- **Pros**: Access to both cloud and on-premises resources, GPO support
- **Cons**: Complex identity, dual token handling, potential for on-prem compromise to affect cloud
- **Investigation Focus**: BOTH cloud and on-premises sign-ins, AD replication, Kerberos tickets

#### Entra Registered (`trustType: Workplace`)
- **Pros**: BYOD support, minimal device management overhead
- **Cons**: Limited compliance enforcement, device not fully controlled
- **Investigation Focus**: User activity on device, data access patterns, potential data exfiltration

---

## Risk Assessment Framework

### Device Risk Scoring

| Factor | Weight | High Risk Indicators |
|--------|--------|---------------------|
| Defender Risk Score | 25% | "High" or "Critical" |
| Active Alerts | 25% | Any Critical/High severity alerts |
| Vulnerabilities | 20% | Critical CVEs, end-of-support software |
| Compliance Status | 15% | Non-compliant, not managed |
| Sign-in Anomalies | 15% | Multiple users, unusual hours, new IPs |

### Risk Level Determination

- **Critical**: Active critical alert OR critical vulnerability being exploited
- **High**: High severity alerts OR critical unpatched vulnerabilities OR compromised user logged on
- **Medium**: Medium alerts OR high vulnerabilities OR non-compliance
- **Low**: Minor alerts OR low vulnerabilities, device is compliant and healthy
- **Informational**: No alerts, compliant, healthy sensor

---

## Integration with Main Copilot Instructions

This skill follows all patterns from the main `copilot-instructions.md`:
- **Date range handling:** Uses +2 day rule for real-time searches
- **Parallel execution:** Runs independent queries simultaneously
- **Time tracking:** Mandatory reporting after each phase
- **Token management:** Uses `create_file` for all output
- **Follow-up analysis:** Reference `copilot-instructions.md` for cross-entity correlation

**Example invocations:**
- "Investigate device WORKSTATION-001 for the last 7 days"
- "Quick security check on computer LAP-JSMITH01"
- "Full investigation for potentially compromised endpoint SRV-DC01 last 30 days"
- "Check hybrid joined device DESKTOP-HR01 for malware"
- "Analyze BYOD device iPad-John for suspicious activity"

---

## SVG Dashboard Generation

After generating a computer investigation report (markdown file output), an SVG dashboard can be created using the shared SVG rendering skill.

**Trigger:** User asks "generate an SVG dashboard from the report" or "visualize this report"

**Workflow:**
1. Read this skill's `svg-widgets.yaml` (widget manifest — defines layout, colors, field mapping)
2. Read `.github/skills/svg-dashboard/SKILL.md` (rendering rules — component library, quality standards)
3. Extract data from the completed report using `data_sources.field_mapping_notes`
4. Render SVG → save as `{report_basename}_dashboard.svg` in the same directory

**Layout:** 5 rows — title banner, risk score card + KPI cards (alerts/incidents/vulnerabilities/users/EOS software), alerts by MITRE tactic bar chart + vulnerabilities by severity bar chart, incidents table + risk/mitigating factors table, assessment banner + recommendations.

---

*Last Updated: March 24, 2026*
