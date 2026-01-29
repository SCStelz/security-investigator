---
name: computer-investigation
description: Use this skill when asked to investigate a computer, device, endpoint, or machine for security issues, suspicious activity, malware, or compliance review. Triggers on keywords like "investigate computer", "investigate device", "investigate endpoint", "check machine", "device security", "endpoint investigation", or when a device name/hostname is mentioned with investigation context. This skill provides comprehensive device security analysis including Defender alerts, sign-in patterns, logged-on users, vulnerabilities, software inventory, compliance status, network activity, and automated investigation tracking for Entra Joined, Hybrid Joined, and Entra Registered devices.
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
3. **[Quick Start](#quick-start-tldr)** - 5-step investigation pattern
4. **[Execution Workflow](#execution-workflow)** - Complete process
5. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns
6. **[Microsoft Graph Queries](#microsoft-graph-device-queries)** - Entra ID device data
7. **[Defender for Endpoint Queries](#defender-for-endpoint-queries)** - MDE API integration
8. **[JSON Export Structure](#json-export-structure)** - Required fields
9. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY computer investigation:**

1. **ALWAYS get Device ID FIRST** (required for Defender API and Graph queries - multiple IDs exist!)
2. **ALWAYS determine device type** (Entra Joined, Hybrid Joined, or Entra Registered)
3. **ALWAYS calculate date ranges correctly** (use current date from context - see Date Range section)
4. **ALWAYS track and report time after each major step** (mandatory)
5. **ALWAYS run independent queries in parallel** (drastically faster execution)
6. **ALWAYS use `create_file` for JSON export** (NEVER use PowerShell terminal commands)
7. **⛔ ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)

---

## ⛔ MANDATORY: Sentinel Workspace Selection

**This skill requires a Sentinel workspace to execute queries. Follow these rules STRICTLY:**

### When invoked from incident-investigation skill:
- Inherit the workspace selection from the parent investigation context
- If no workspace was selected in parent context: **STOP and ask user to select**
- Use the `SELECTED_WORKSPACE_IDS` passed from the parent skill

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

3. **Export to JSON:**
   ```
   create_file("temp/investigation_device_<device_name>_<timestamp>.json", json_content)
   ```

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
| where DeviceName =~ '<DEVICE_NAME>'
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform, OSVersion, MachineGroup, OnboardingStatus, RiskScore
```

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

### Phase 3: Export to JSON

Create single JSON file: `temp/investigation_device_{device_name}_{timestamp}.json`

Merge all results into one dict structure (see JSON Export Structure section below).

---

### Phase 4: Generate Summary Report

Provide comprehensive summary including:
- Device profile and trust type
- Alert summary by severity
- Logged-on users analysis
- Vulnerability count by severity
- Compliance status
- Risk assessment
- Recommended actions

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

Use these exact patterns with the Sentinel Data Lake `query_lake` MCP tool for Sentinel or Advanced Hunting tools for Defender XDR tables. Replace `<DEVICE_NAME>`, `<DEVICE_ID>`, `<StartDate>`, `<EndDate>`.

**⚠️ CRITICAL: START WITH THESE EXACT QUERY PATTERNS**
**These queries have been tested and validated. Use them as your PRIMARY reference.**

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
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| extend DeviceTrustType = tostring(DeviceDetail.trustType)
| extend DeviceCompliant = tostring(DeviceDetail.isCompliant)
| where DeviceName =~ deviceName or DeviceId =~ '<DEVICE_ID>'
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
| where Timestamp between (start .. end)
| where DeviceName =~ deviceName
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
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
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
| where Timestamp between (start .. end)
| where DeviceName =~ deviceName
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Private" // Focus on public IPs
| summarize 
    ConnectionCount = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    UniqueRemotePorts = dcount(RemotePort),
    BytesSent = sum(tolong(SentBytes)),
    BytesReceived = sum(tolong(ReceivedBytes)),
    Protocols = make_set(Protocol, 5),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
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
| where Timestamp between (start .. end)
| where DeviceName =~ deviceName
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
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
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
| where Timestamp between (start .. end)
| where DeviceName =~ deviceName
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
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
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
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceInfo
| where Timestamp between (start .. end)
| where DeviceName =~ deviceName
| summarize arg_max(Timestamp, *) by DeviceId
| project 
    Timestamp,
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
    PublicIP
```

### 9. Software Inventory on Device
```kql
let deviceName = '<DEVICE_NAME>';
DeviceTvmSoftwareInventory
| where DeviceName =~ deviceName
| summarize arg_max(Timestamp, *) by DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| project 
    SoftwareVendor,
    SoftwareName,
    SoftwareVersion,
    EndOfSupportStatus,
    EndOfSupportDate,
    NumberOfWeaknesses,
    DiskPaths
| order by NumberOfWeaknesses desc
| take 30
```

### 10. Vulnerabilities on Device
```kql
let deviceName = '<DEVICE_NAME>';
DeviceTvmSoftwareVulnerabilities
| where DeviceName =~ deviceName
| summarize arg_max(Timestamp, *) by DeviceId, CveId
| project
    CveId,
    VulnerabilitySeverityLevel,
    SoftwareVendor,
    SoftwareName,
    SoftwareVersion,
    RecommendedSecurityUpdate,
    RecommendedSecurityUpdateId
| order by case(VulnerabilitySeverityLevel == "Critical", 1, VulnerabilitySeverityLevel == "High", 2, VulnerabilitySeverityLevel == "Medium", 3, 4) asc
| take 30
```

### 11. Logon Events on Device
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceLogonEvents
| where Timestamp between (start .. end)
| where DeviceName =~ deviceName
| summarize 
    LogonCount = count(),
    SuccessCount = countif(ActionType == "LogonSuccess"),
    FailureCount = countif(ActionType == "LogonFailed"),
    UniqueAccounts = dcount(AccountName),
    LogonTypes = make_set(LogonType, 5),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    RemoteIPs = make_set(RemoteIP, 10)
    by AccountName, AccountDomain, LogonType
| order by LogonCount desc
| take 20
```

### 12. Threat Intelligence IP Matches (Device Network Traffic)
```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
let device_ips = DeviceNetworkEvents
| where Timestamp between (start .. end)
| where DeviceName =~ deviceName
| where RemoteIPType != "Private"
| distinct RemoteIP;
ThreatIntelIndicators
| extend IndicatorType = replace_string(replace_string(replace_string(tostring(split(ObservableKey, ":", 0)), "[", ""), "]", ""), "\"", "")
| where IndicatorType in ("ipv4-addr", "ipv6-addr", "network-traffic")
| extend NetworkSourceIP = toupper(ObservableValue)
| where NetworkSourceIP in (device_ips)
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| summarize arg_max(TimeGenerated, *) by NetworkSourceIP
| project 
    TimeGenerated,
    IPAddress = NetworkSourceIP,
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
Returns: id, computerDnsName, osPlatform, osVersion, healthStatus, onboardingStatus, riskScore, exposureLevel, lastSeen, lastIpAddress, lastExternalIpAddress, rbacGroupName

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

*Last Updated: January 23, 2026*
