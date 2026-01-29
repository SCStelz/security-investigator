---
name: incident-investigation
description: Use this skill when asked to investigate a security incident by ID from Microsoft Defender XDR or Microsoft Sentinel. Triggers on keywords like "investigate incident", "incident ID", "incident investigation", "analyze incident", "triage incident", or when an incident number/ID is mentioned with investigation context. This skill provides comprehensive incident analysis including metadata retrieval, alert listing, asset enumeration, evidence filtering, and deep entity investigation using Sentinel MCP tools and specialized skills.
---

# Incident Investigation - Instructions

## Purpose

This skill performs comprehensive security investigations on incidents from **Microsoft Defender XDR** and **Microsoft Sentinel**. It retrieves incident details, lists alerts, enumerates assets and evidences, and then performs deep investigation on user-selected entities using appropriate tools and specialized skills.

**Investigation Flow:**
1. **Phase 1: Incident Description** - Retrieve metadata, alerts, assets, and evidences
2. **Phase 2: Incident Investigation Menu** - Ask the user to select the incident assets and entities that should be investigated.
3. **Phase 2-A: User Investigation** - Follow user-investigation skill workflow
4. **Phase 2-B: Device Investigation** - Follow computer-investigation skill workflow
5. **Phase 2-C: IoC Investigation** - Follow ioc-investigation skill workflow for IPs, URLs, Files, Domains, Hashes
6. **Phase 3: Looping to Phase 2** - Ask the user to select the further assets and entities that should be investigated.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Phase 1: Incident Description](#phase-1-incident-description)** - Metadata, Alerts, Assets, Evidences
3. **[Phase 2: Incident Investigation Menu](#phase-2-incident-investigation-menu)** - Presenting the options
4. **[Phase 2-A: User Investigation](#phase-2-A-user-investigation)** - Using user-investigation skill
5. **[Phase 2-B: Device Investigation](#phase-2-B-device-investigation)** - Using computer-investigation skill
6. **[Phase 2-C: IoC Investigation](#phase-2-C-ioc-investigation)** - Using ioc-investigation skill (IPs, URLs, Files, Domains, Hashes)
7. **[Phase 3: Post Incident Investigation](#phase-3-go-back-to-phase-2)** - Looping to phase 2
8. **[JSON Export Structure](#json-export-structure)** - Required fields
9. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY incident investigation:**

1. **ALWAYS complete Phase 1 first** - Retrieve full incident description before any deep investigation
2. **ALWAYS list Sentinel workspaces at the START of Phase 2** - Call `list_sentinel_workspaces` MCP tool BEFORE presenting the investigation menu
3. **⛔ ALWAYS complete workspace selection BEFORE any investigation** - This is a MANDATORY CHECKPOINT:
   - If 1 workspace: auto-select and display to user
   - If multiple workspaces: ASK USER to select and WAIT for response
   - **DO NOT proceed to any entity investigation without a workspace selected**
4. **ALWAYS present extracted entities to user** - After workspace selection, ask user which entities to investigate
5. **ALWAYS wait for user confirmation** - Do not proceed with deep investigation until user selects entities
6. **ALWAYS use the correct tools for each entity type:**
   - **Users** → Follow `.github/skills/user-investigation/SKILL.md`
   - **Devices** → Follow `.github/skills/computer-investigation/SKILL.md`
   - **IPs/URLs/Files/Domains/Hashes** → Follow `.github/skills/ioc-investigation/SKILL.md`
7. **ALWAYS track and report time** after each major step
8. **ALWAYS filter evidences** - Remove internal IPs (RFC1918) and tenant domains from investigation scope. Also remove all public IPs from the devices listed as assets involved in the incident.
9. **ALWAYS defang malicious/suspicious URLs and IPs** - NEVER return them as clickable links. Use defang format: `hxxps://evil[.]com`, `203[.]0[.]113[.]42`
10. **⛔ NEVER auto-select a Sentinel workspace when multiple exist** - Workspace selection is MANDATORY:
    - ❌ DO NOT select a workspace on behalf of the user when multiple exist
    - ❌ DO NOT switch to another workspace if a query fails
    - ❌ DO NOT proceed with investigation without explicit user selection
    - ✅ If query fails: STOP, report error, ask user to select different workspace
    - ✅ If multiple workspaces: STOP, list all, WAIT for user selection
    - ✅ Only auto-select if exactly ONE workspace exists

**Incident ID Patterns:**
| Pattern | Source | Tool to Use |
|---------|--------|-------------|
| Numeric (e.g., `12345`, `98765`) | Defender XDR / Sentinel | `GetIncidentById` |
| GUID format | Sentinel (internal) | Sentinel `query_lake` MCP tool |
| `INxx-xxxxx` format | Defender XDR | `GetIncidentById` |

**Date Range Rules:**
- **Default analysis window:** 7 days before current date to current date (Standard)
- **Investigation depth options:**
  - **Comprehensive:** 30 days window (for thorough analysis)
  - **Standard:** 7 days window (default)
  - **Quick:** 1 day window (for rapid triage)
- **Format:** ISO 8601 (e.g., `2026-01-17T00:00:00Z` to `2026-01-24T00:00:00Z`)

---

## Phase 1: Incident Description

**This phase retrieves and presents all incident information. Follow the exact structure below.**

### 1.1 Incident Metadata

Retrieve and list the incident's metadata using `GetIncidentById`:

| Field | Description |
|-------|-------------|
| **Title** | Incident display name |
| **Description** | Detailed incident description |
| **Status** | Active, Resolved, Redirected |
| **Severity** | High, Medium, Low, Informational |
| **Priority assessment** | If available from incident data |
| **Classification** | TruePositive, FalsePositive, BenignPositive, etc. |
| **Determination** | Malware, Phishing, etc. |
| **Created Date** | When incident was created |
| **First Activity Date** | First malicious activity timestamp |
| **Last Updated Date** | Most recent modification |
| **Assigned To** | Analyst assigned to incident |
| **MITRE Categories** | Tactics and techniques involved |
| **Tags** | Labels applied to incident |

### 1.2 Incident Alerts

Retrieve and list the **top 30** incident alerts. For each alert, retrieve:
- Alert name
- Tags
- Severity
- Investigation state
- Status
- Impacted assets
- Correlation reason
- Detection source
- First activity
- Last activity

**Presentation Rules:**
1. Return as a table (exclude Alert ID column from display)
2. Order by last activity date descending
3. Add row numbers starting from 1
4. If more than 30 alerts exist, note this after the table and provide a Defender portal link
5. NEVER calculate and write the total number of alerts 

### 1.3 Incident Assets

Retrieve and list ALL assets involved in the incident by type:

**Device Assets:**
| Field | Description |
|-------|-------------|
| Name | Device hostname |
| Domain | AD domain |
| Risk Level | Device risk assessment |
| Exposure Level | Vulnerability exposure |
| OS Platform | Operating system |

**User Assets:**
| Field | Description |
|-------|-------------|
| Display Name | User's full name |
| UPN | User Principal Name |
| User Status | Account status |
| Domain | User's domain |
| Department | Organizational department |

**App Assets:**
| Field | Description |
|-------|-------------|
| App Name | Application name |
| App Client ID | OAuth client ID |
| Risk | Application risk level |
| Publisher | App publisher |

**Cloud Resource Assets:**
| Field | Description |
|-------|-------------|
| Resource Name | Cloud resource identifier |
| Status | Resource status |
| Cloud Environment | Azure, AWS, GCP, etc. |
| Type | Resource type |

**Count assets by type ONLY after retrieving complete lists.**

### 1.4 Incident Evidences

Retrieve evidences classified as **malicious or suspicious** only:

**Processes (Top 10):**
- Get ALL malicious/suspicious processes
- Return only the **10 most probable signs of malicious activity** (use judgment)

**Files (Top 10):**
- Get ALL malicious/suspicious files
- Return only the **10 most probable signs of malicious activity** (use judgment)

**IP Addresses (Top 10, Filtered):**
- Get ALL malicious/suspicious IPs
- **Filter out RFC1918 internal IPs:** 10.x.x.x, 172.16-31.x.x, 192.168.x.x
- **Filter out public IPs associated to the devices listed as assets involved in the incident**
- Return only the first 10 from filtered list
- DEFANG ALL IPs:** When presenting IPs and domains to the user, ALWAYS use defanged format: `203[.]0[.]113[.]42`, `evil[.]com`. NEVER output clickable malicious indicators.

**URLs and DNS Domains (Top 10, Filtered):**
- Get ALL malicious/suspicious URLs and DNS Domains
- **Filter out tenant domain URLs** (DNS domains associated with the organization)
- Return only the first 10 from filtered list
- DEFANG ALL URLs AND DNS DOMAINS:** When presenting URLs to the user, ALWAYS use defanged format: `hxxps://evil[.]com/path`, `hxxp://malware[.]net`. NEVER output clickable malicious URLs.

**AD Domains:**
- Return ALL malicious/suspicious AD domains (no limit)

**For each evidence type:** If more than 10 exist, note this after the table and provide Defender portal link.

---

## Phase 2: Incident Investigation Menu

### ⛔ MANDATORY CHECKPOINT: Workspace Selection

**This checkpoint MUST be completed before ANY entity investigation can proceed.**

#### Step 2.1: List Sentinel Workspaces

**ALWAYS execute this step first, regardless of any other considerations:**

```
list_sentinel_workspaces (MCP tool)
```

Store the result. This determines the workflow for Step 2.3.

#### Step 2.2: Present Entity Summary

Show a summary of the incident entities and assets from Phase 1:
- Users (with UPN and display name)
- Devices (with hostname and risk level)
- URLs (defanged)
- IPs (defanged, filtered)
- File hashes
- Domains (defanged)

**🔴 DEFANG ALL URLs AND DOMAINS:** When presenting URLs and DNS Domains to the user, ALWAYS use defanged format: `hxxps://evil[.]com/path`, `hxxp://malware[.]net`, `evil[.]com`. NEVER output clickable malicious URLs.

**🔴 DEFANG ALL IPs:** When presenting IPs to the user, ALWAYS use defanged format: `203[.]0[.]113[.]42`. NEVER output clickable malicious indicators.

#### Step 2.3: Workspace Selection Gate

```
IF workspace_count == 1:
    - Auto-select the single workspace
    - Display: "Using Sentinel workspace: [NAME] ([ID])"
    - Set SESSION_WORKSPACE_SELECTED = true
    
ELSE IF workspace_count > 1 AND SESSION_WORKSPACE_SELECTED == false:
    - Display all workspaces with Name and ID
    - ASK USER: "Which Sentinel workspace should I run my searches in? Select one or more, or choose 'all'."
    - WAIT for user response
    - Set SESSION_WORKSPACE_SELECTED = true after selection
    
ELSE IF workspace_count > 1 AND SESSION_WORKSPACE_SELECTED == true:
    - Display: "Continuing with previously selected workspace: [NAME] ([ID])"
    - DO NOT ask again
```

### ⛔ DO NOT PROCEED PAST THIS POINT WITHOUT A WORKSPACE SELECTED

**If `SESSION_WORKSPACE_SELECTED == false` after Step 2.3, STOP and ask the user to select a workspace.**

#### Step 2.4: Ask User to Select Entities

Ask the user:

> "Which assets and entities involved in the incident should be investigated in depth? Please select them by providing their numbers or names, or simply ask to analyze all of them. The more entities you select, the longer the analysis will take."

**🔴 DO NOT OFFER OTHER OPTIONS:** Only ask the user whether they want to investigate one or more of the incident entities and assets listed above in more depth. 

Read the response.
- If they do not want to proceed with the proposed investigations, ask them what they want to do.
- If they want to proceed with one or more of the proposed investigations, continue with Step 2.5.

#### Step 2.5: Start Investigations 

**Pre-flight check:** Confirm `SESSION_WORKSPACE_SELECTED == true` before proceeding.

Proceed in accordance with the instructions described below for Phase 2-A, Phase 2-B, and Phase 2-C.
When multiple investigation types are selected (users, devices, IoCs) run them in parallel as much as possible.

---

## Phase 2-A: User Investigation

### Pre-requisites (MANDATORY)

**⛔ VERIFY BEFORE PROCEEDING:**
- ✅ `SESSION_WORKSPACE_SELECTED == true` (workspace explicitly selected by user)
- ✅ `SELECTED_WORKSPACE_IDS` array is populated with user's selection
- ✅ User has explicitly selected which user(s) to investigate

**If any pre-requisite is FALSE:** STOP and return to Phase 2.3 Workspace Selection Gate.

### User Investigation Workflow

**⚡ PARALLEL EXECUTION:** When multiple users are selected, execute user investigations in parallel as much as possible.

**📦 WORKSPACE CONTEXT:** Pass the selected workspace(s) to all child skill invocations:
- Use `SELECTED_WORKSPACE_IDS` from Phase 2.3 for all Sentinel queries
- If a query fails with table/workspace error: STOP, report error, ask user to select different workspace
- **⛔ DO NOT automatically retry with a different workspace**

For EACH user selected by the user:

**🔴 REFERENCE THE SKILL FILE:** Read and follow the complete workflow defined in:
```
.github/skills/user-investigation/SKILL.md
```

**Key Steps (summary - see skill file for full details):**
1. Get User Object ID from Microsoft Graph
2. Calculate date ranges based on investigation type (Standard/Quick/Comprehensive)
3. Run parallel data collection:
   - Sign-in anomalies (SigninLogs_Anomalies_KQL_CL)
   - Sign-in statistics (apps, locations, IPs)
   - Audit log events
   - Office 365 activity
   - Security incidents involving user
   - Identity Protection risk detections
   - MFA and authentication methods
   - Device compliance status
4. IP enrichment for flagged addresses
5. Compile and present findings
6. Generate HTML report (if requested)

**DO NOT copy the full workflow here - always read the skill file for the most current instructions.**

---

## Phase 2-B: Device Investigation

### Device Investigation Workflow

**⚡ PARALLEL EXECUTION:** When multiple devices are selected, execute device data collection queries in parallel for ALL devices simultaneously. Run Defender alerts, compliance, logged-on users, vulnerabilities, network/process/file events queries concurrently.

For EACH device selected by the user:

**🔴 REFERENCE THE SKILL FILE:** Read and follow the complete workflow defined in:
```
.github/skills/computer-investigation/SKILL.md
```

**Key Steps (summary - see skill file for full details):**
1. Get Device IDs (Entra Device ID + Defender Device ID)
2. Determine device type (Entra Joined, Hybrid Joined, Entra Registered)
3. Run parallel data collection:
   - Defender alerts for device
   - Device compliance status
   - Logged-on users
   - Software vulnerabilities
   - Network connections
   - Process events
   - File events
   - Automated investigations
4. Compile and present findings

**DO NOT copy the full workflow here - always read the skill file for the most current instructions.**

---

## Phase 2-C: IoC Investigation

### IoC Investigation Workflow

**⚡ PARALLEL EXECUTION:** When multiple IoCs are selected, execute ALL IoC investigation queries in parallel. Run threat intel lookups, Sentinel queries, and organizational exposure queries concurrently for all IoCs.

For EACH IoC selected by the user:

**🔴 REFERENCE THE SKILL FILE:** Read and follow the complete workflow defined in:
```
.github/skills/ioc-investigation/SKILL.md
```

**Supported IoC Types:**
| IoC Type | Detection Pattern | Key Investigation Points |
|----------|-------------------|-------------------------|
| **URL** | `https?://` or domain pattern | Malicious indicators, phishing, threat intel, organizational exposure |
| **IPv4 Address** | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | Threat intel, network connections, geographic analysis |
| **IPv6 Address** | Contains multiple colons | Same as IPv4 |
| **Domain** | `[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}` | DNS queries, email threats, reputation |
| **MD5 Hash** | 32 hex characters | File prevalence, malware analysis |
| **SHA1 Hash** | 40 hex characters | File prevalence, malware analysis |
| **SHA256 Hash** | 64 hex characters | File prevalence, malware analysis |

**Key Steps (summary - see skill file for full details):**
1. Identify IoC type and normalize
2. Query Defender Threat Intelligence
3. Check Sentinel ThreatIntelIndicators table
4. Analyze organizational exposure (devices, connections)
5. Correlate with CVEs if applicable
6. Present findings with risk assessment

**DO NOT copy the full workflow here - always read the skill file for the most current instructions.**

---

## Phase 3: Post-Investigation Loop (MANDATORY)

### ⛔ CRITICAL: DO NOT END THE RESPONSE WITHOUT COMPLETING THIS PHASE

**After completing ALL selected entity investigations in Phase 2, you MUST:**

1. **List remaining uninvestigated entities** - Show all entities from Phase 1 that were NOT yet investigated
2. **Ask the user to select additional entities** - Prompt user to continue or conclude
3. **Wait for user response** - Do not assume the investigation is complete

### Phase 3 Checklist (Execute After Every Phase 2 Completion)

```
☐ Step 3.1: Compile list of UNINVESTIGATED entities (exclude already-investigated items)
☐ Step 3.2: Present remaining entities to user with numbered list
☐ Step 3.3: Ask: "Would you like to investigate any of the remaining entities? Select by number/name, or say 'done' to conclude."
☐ Step 3.4: Wait for user response before concluding
```

### Required Prompt Format

After presenting investigation findings, ALWAYS end with:

> **📋 Remaining Uninvestigated Entities:**
> 
> | # | Type | Entity | Notes |
> |---|------|--------|-------|
> | 1 | Device | [DEVICE_NAME] | [Risk level or relevant context] |
> | 2 | File | [FILENAME] | [Hash or detection status] |
> | 3 | URL | [DEFANGED_URL] | [Threat assessment] |
> | ... | ... | ... | ... |
>
> **Would you like to investigate any of these remaining entities?** Select by number/name, type "all" to investigate everything, or say "done" to conclude the investigation.

### Rules

- **DO NOT** include entities that were already investigated in the list
- **DO NOT** ask the user to select Sentinel workspaces again (use previously selected workspace)
- **DO NOT** provide a final summary or recommendations until the user explicitly says "done" or declines further investigation
- **DO NOT** assume the investigation is complete just because selected entities were analyzed

### Loop Behavior

```
IF user selects additional entities:
    → Return to Phase 2 (2-A, 2-B, or 2-C based on entity type)
    → After completion, return to Phase 3 again
    
ELSE IF user says "done" or declines:
    → Proceed to Final Summary
    → Provide recommendations
    → Offer to generate consolidated report
``` 

---

## Sentinel MCP Tools Reference

### analyze_user_entity

**Purpose:** Starts asynchronous security analysis of a user entity.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `userId` | string | Yes | User's Azure AD Object ID (GUID) |
| `startTime` | string | Yes | ISO 8601 format start time |
| `endTime` | string | Yes | ISO 8601 format end time |
| `workspaceId` | string | No | Sentinel workspace GUID (optional if only one workspace) |

**Time Window Options:** 30 days (Comprehensive), 7 days (Standard), 1 day (Quick)

**Returns:** `202 Accepted` with `analysisId`

### get_entity_analysis

**Purpose:** Retrieves results of an asynchronous entity analysis.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `analysisId` | string | Yes | Analysis ID returned from analyze_*_entity |

**Returns:** `200 OK` with analysis results when complete, or status if still processing

---

## Quick Start (TL;DR)

When a user requests an incident investigation:

1. **Phase 1 - Incident Description:**
   - Retrieve incident metadata using `GetIncidentById`
   - List top 30 alerts as a table
   - Enumerate all assets by type (devices, users, apps, cloud resources)
   - List filtered evidences (processes, files, IPs, URLs, domains)

2. **⛔ Phase 2 - Mandatory Workspace Selection:**
   - Call `list_sentinel_workspaces` MCP tool FIRST
   - Present entity summary from Phase 1
   - If 1 workspace: auto-select and display
   - If multiple workspaces: ASK USER to select before proceeding
   - **DO NOT proceed to investigations without a workspace selected**

3. **Phase 2-A - User Investigation:**
   - For each selected user: Follow `.github/skills/user-investigation/SKILL.md`
   - Present findings

4. **Phase 2-B - Device Investigation:**
   - For each selected device: Follow `.github/skills/computer-investigation/SKILL.md`
   - Present findings

5. **Phase 2-C - IoC Investigation:**
   - For each selected IoC (IPs, URLs, Files, Domains, Hashes): Follow `.github/skills/ioc-investigation/SKILL.md`
   - Present findings

6. **Export & Summary:**
   - Create consolidated JSON file
   - Present investigation summary with recommendations
---

## JSON Export Structure

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `investigation_metadata` | object | Incident ID, timestamp, investigation phases completed |
| `incident_details` | object | Metadata, alerts, assets, evidences from Phase 1 |
| `user_investigations` | array | Results from Phase 2-A (user-investigation skill) |
| `device_investigations` | array | Results from Phase 2-B (computer-investigation skill) |
| `ioc_investigations` | array | Results from Phase 2-C (ioc-investigation skill - includes IPs, URLs, Files, Domains, Hashes) |
| `summary` | object | Key findings, risk assessment, recommendations |

### Example JSON Structure

```json
{
  "investigation_metadata": {
    "incident_id": "<INCIDENT_ID>",
    "investigation_timestamp": "<ISO_TIMESTAMP>",
    "phases_completed": ["incident_description", "user_investigation", "device_investigation", "ioc_investigation"],
    "total_elapsed_time_seconds": 300
  },
  "incident_details": {
    "metadata": {
      "title": "<INCIDENT_TITLE>",
      "description": "<DESCRIPTION>",
      "severity": "<SEVERITY>",
      "status": "<STATUS>",
      "classification": "<CLASSIFICATION>",
      "determination": "<DETERMINATION>",
      "created_date": "<TIMESTAMP>",
      "first_activity_date": "<TIMESTAMP>",
      "last_updated_date": "<TIMESTAMP>",
      "assigned_to": "<ANALYST>",
      "mitre_categories": ["<TACTIC1>", "<TACTIC2>"],
      "tags": ["<TAG1>", "<TAG2>"]
    },
    "alerts": [
      {
        "name": "<ALERT_NAME>",
        "severity": "<SEVERITY>",
        "status": "<STATUS>",
        "first_activity": "<TIMESTAMP>",
        "last_activity": "<TIMESTAMP>"
      }
    ],
    "assets": {
      "devices": [...],
      "users": [...],
      "apps": [...],
      "cloud_resources": [...]
    },
    "evidences": {
      "processes": [...],
      "files": [...],
      "ip_addresses": [...],
      "urls": [...],
      "ad_domains": [...]
    }
  },
  "user_investigations": [
    {
      "upn": "user@domain.com",
      "user_id": "<GUID>",
      "analysis_id": "<ANALYSIS_ID>",
      "time_window": {
        "start": "<ISO_TIMESTAMP>",
        "end": "<ISO_TIMESTAMP>"
      },
      "findings": {...},
      "risk_level": "High"
    }
  ],
  "device_investigations": [
    {
      "hostname": "<DEVICE_NAME>",
      "device_id": "<GUID>",
      "findings": {...}
    }
  ],
  "ioc_investigations": [
    {
      "ioc_type": "IP",
      "value": "203.0.113.42",
      "findings": {...}
    },
    {
      "ioc_type": "URL",
      "value": "https://example.com",
      "findings": {...},
      "threat_assessment": "Malicious"
    }
  ],
  "summary": {
    "risk_assessment": "High",
    "key_findings": [...],
    "recommendations": [...]
  }
}
```

---

## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Incident not found** | Verify incident ID format; try Sentinel query if Defender fails |
| **User Object ID not found** | Verify UPN is correct; check if user exists in Entra ID |
| **analyze_user_entity returns error** | Check userId is GUID format; verify time window ≤ 30 days |
| **get_entity_analysis still processing** | Poll again after 5-10 seconds; max 2 minutes |
| **No workspace found** | Use `list_sentinel_workspaces` MCP tool to get workspace ID |
| **Device investigation fails** | Verify device exists in Defender; check device ID type |
| **IoC investigation timeout** | Reduce date range; check IoC format |

### Workspace ID Retrieval

If workspace ID is unknown, retrieve it first:
```
list_sentinel_workspaces (MCP tool)
```

Returns: List of workspace name/ID pairs


### Workspace ID Selection

If there is more than one Sentinel workspace (as retrieved from `list_sentinel_workspaces` MCP tool), present the list - in terms of workspace names and IDs - to the user so that the user can select which workspace to use for the investigation. 
Offer also to the user the possibility to use all existing workspaces. 

If only one workspace is selected by the user, use the workspaceId of that workspace when calling investigation tools.

If the user asks to consider more than one workspace, use one by one the workspaceId of all of them when calling investigation tools.


### Time Window Limits

| Tool | Time Window Options |
|------|---------------------|
| User Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |
| Computer Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |
| IoC Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |

---

## Example Investigation Workflow

**User Request:** "Investigate incident 12345"

### Phase 1: Incident Description
```
[00:00] Starting incident investigation for ID: 12345

### Incident Metadata
- **Title:** Multi-stage attack with credential theft
- **Severity:** High
- **Status:** Active
- **Classification:** TruePositive
- **Created:** 2026-01-20T10:30:00Z
- **MITRE Categories:** Initial Access, Credential Access, Lateral Movement

### Incident Alerts 
| # | Alert Name | Severity | Status | Last Activity |
|---|------------|----------|--------|---------------|
| 1 | Suspicious sign-in from unusual location | High | New | 2026-01-23 |
| 2 | Credential theft attempt detected | High | InProgress | 2026-01-22 |
| ... | ... | ... | ... | ... |

### Incident Assets
**Devices:**
| Name | Domain | Risk Level | OS |
|------|--------|------------|-----|
| WORKSTATION-01 | contoso.com | High | Windows 11 |
| LAPTOP-EXEC | contoso.com | Medium | Windows 11 |
| SERVER-DC01 | contoso.com | Low | Windows Server 2022 |

**Users:**
| Display Name | UPN | Status | Department |
|--------------|-----|--------|------------|
| John Smith | jsmith@contoso.com | Active | Finance |
| Admin Account | admin@contoso.com | Active | IT |
| Jane Doe | jdoe@contoso.com | Active | HR |
| Service Account | svc-backup@contoso.com | Active | IT |

### Incident Evidences
**IPs (after filtering - excluded private IPs):**
- `203[.]0[.]113[.]42` (Malicious - C2 communication)
- `198[.]51[.]100[.]10` (Suspicious - Data exfiltration)
- `192[.]0[.]2[.]50` (Suspicious - Unusual connection)
...

**URLs (after filtering - excluded managed domains):**
- `hxxps://evil-site[.]com/payload[.]exe` (Malicious)
- `hxxps://phishing[.]example[.]com/login` (Suspicious)
...

[01:30] Phase 1 completed (90 seconds)
```

### Phase 2-A: User Investigation
```
Which users from the incident assets should be investigated deeply?
Available users:
1. jsmith@contoso.com (Finance)
2. admin@contoso.com (IT)
3. jdoe@contoso.com (HR)
4. svc-backup@contoso.com (IT)
```

**User selects:** "1, 2"

```
[01:35] Starting parallel user analysis for 2 users...
- Getting user Object IDs from Graph API (parallel)
- Starting analyze_user_entity for jsmith@contoso.com (Analysis ID: abc123-def456)
- Starting analyze_user_entity for admin@contoso.com (Analysis ID: xyz789-ghi012)
- Polling for results (parallel)...
[02:15] All analyses complete

### User Analysis: jsmith@contoso.com
**Risk Level:** High
**Key Findings:**
1. Sign-in from unusual location (IP: `203[.]0[.]113[.]42`, Country: Russia)
2. Multiple failed MFA attempts followed by success
3. Unusual file access pattern detected
...

### User Analysis: admin@contoso.com
**Risk Level:** Medium
**Key Findings:**
1. Service account usage from new device
...

[02:20] Phase 2-A completed (45 seconds - parallel execution)
```

### Phase 2-B: Device Investigation
```
Which devices from the incident assets should be investigated deeply?
Available devices:
1. WORKSTATION-01 (High risk)
2. LAPTOP-EXEC (Medium risk)
3. SERVER-DC01 (Low risk)
```

**User selects:** "1"

```
[03:10] Starting device investigation for WORKSTATION-01...
- Following computer-investigation skill workflow
- Getting device IDs (Entra + Defender)
- Running parallel queries...
[04:30] Device investigation complete

### Device Analysis: WORKSTATION-01
**Key Findings:**
1. Malware execution detected (sha256: abc123...)
2. Outbound C2 communication to 203.0.113.42
3. Credential dumping tool found
...

[04:35] Phase 2-B completed (85 seconds)
```

### Phase 2-C: IoC Investigation
```
Which IPs, URLs, Files, Domains, or Hashes should be investigated deeply?
Available IoCs:
1. 203[.]0[.]113[.]42 (IP - C2 communication)
2. 198[.]51[.]100[.]10 (IP - Data exfiltration)
3. hxxps://evil-site[.]com/payload[.]exe (URL - Malicious)
4. hxxps://phishing[.]example[.]com/login (URL - Suspicious)
5. abc123def456... (Hash - Malware)
```

**User selects:** "1, 3, 4, 5"

```
[04:40] Starting parallel IoC investigation for 4 IoCs...
- Following ioc-investigation skill workflow
- Running threat intel, Sentinel, and exposure queries in parallel for all IoCs
[05:30] All IoC analyses complete

### IP Analysis: 203[.]0[.]113[.]42
**Threat Assessment:** Malicious
**Key Findings:**
1. Known C2 infrastructure
2. Associated with threat actor APT-XYZ
...

### URL Analysis: hxxps://evil-site[.]com/payload[.]exe
**Threat Assessment:** Malicious
**Key Findings:**
1. Known malware distribution domain
2. 3 devices in organization accessed this URL
...

### URL Analysis: hxxps://phishing[.]example[.]com/login
**Threat Assessment:** Suspicious
**Key Findings:**
1. Phishing page mimicking corporate login
...

### Hash Analysis: abc123def456...
**Threat Assessment:** Malicious
**Key Findings:**
1. Known malware sample
...

[05:35] Phase 2-C completed (55 seconds - parallel execution)

[05:45] Investigation Summary
=========================
**Incident:** 12345 - Multi-stage attack with credential theft
**Total Investigation Time:** 4 minutes 10 seconds (optimized with parallel execution)

**Key Findings:**
1. Compromised user account (jsmith@contoso.com) used for initial access
2. Malware deployed on WORKSTATION-01 establishing C2 channel
3. Credential theft attempt targeting admin account
4. Data exfiltration attempts detected

**Recommendations:**
1. 🔴 CRITICAL: Isolate WORKSTATION-01 immediately
2. 🔴 CRITICAL: Reset credentials for jsmith@contoso.com and admin@contoso.com
3. 🟠 HIGH: Block IP `203[.]0[.]113[.]42` at firewall
4. 🟠 HIGH: Block domain `evil-site[.]com`
5. 🟡 MEDIUM: Review all sign-ins for affected users in past 30 days

**Export:** temp/incident_investigation_12345_20260124.json
```

---

## Integration with Skill Files

This skill orchestrates investigations by referencing specialized skills:

| Investigation Phase | Skill/Tool | Location/Reference |
|--------------------|------------|-------------------|
| Phase 1: Incident Description | Built-in workflow | This file (see Phase 1 section) |
| Phase 2-A: User Investigation | user-investigation skill | `.github/skills/user-investigation/SKILL.md` |
| Phase 2-B: Device Investigation | computer-investigation skill | `.github/skills/computer-investigation/SKILL.md` |
| Phase 2-C: IoC Investigation | ioc-investigation skill | `.github/skills/ioc-investigation/SKILL.md` (IPs, URLs, Files, Domains, Hashes) |

**🔴 ALWAYS read the referenced skill file before executing that phase to ensure proper workflow execution.**
