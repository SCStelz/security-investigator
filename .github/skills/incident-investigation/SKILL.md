---
name: incident-investigation
description: Use this skill when asked to investigate a security incident by ID from Microsoft Defender XDR or Microsoft Sentinel. Triggers on keywords like "investigate incident", "incident ID", "incident investigation", "analyze incident", "triage incident", or when an incident number/ID is mentioned with investigation context. This skill provides comprehensive incident analysis including metadata retrieval, alert listing, asset enumeration, evidence filtering, and deep entity investigation using Sentinel MCP tools and specialized skills.
threat_pulse_domains: [incidents]
drill_down_prompt: 'Investigate incident {entity} — alert cohesion sweep, entity investigation, verdict gates'
---

# Incident Investigation - Instructions

## Purpose

This skill performs comprehensive security investigations on incidents from **Microsoft Defender XDR** and **Microsoft Sentinel**. It retrieves incident details, lists alerts, enumerates assets and evidences, and then performs deep investigation on user-selected entities using appropriate tools and specialized skills.

**Investigation Flow:**
1. **Phase 1: Incident Description** - Retrieve metadata, alerts, assets, and evidences
2. **Phase 1.5: Alert Cohesion & Adjacent-Alert Sweep** - Verify the incident's alerts belong together, and sweep for related alerts left outside it
3. **Phase 2: Incident Investigation Menu** - Ask the user to select the incident assets and entities that should be investigated.
4. **Phase 2-A: User Investigation** - Follow user-investigation skill workflow
5. **Phase 2-B: Device Investigation** - Follow computer-investigation skill workflow
6. **Phase 2-C: IoC Investigation** - Follow ioc-investigation skill workflow for IPs, URLs, Files, Domains, Hashes
7. **Phase 3: Post-Investigation Loop** - Offer any remaining entities; skip straight to Phase 4 when nothing material remains
8. **Phase 4: Final Summary & Verdict Gates** - Pass all four verdict gates before writing any classification

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Phase 1: Incident Description](#phase-1-incident-description)** - Metadata, Alerts, Assets, Evidences
3. **[Phase 1.5: Alert Cohesion & Adjacent-Alert Sweep](#15-alert-cohesion--adjacent-alert-sweep)** - Scope correction before investigating
4. **[Phase 2: Incident Investigation Menu](#phase-2-incident-investigation-menu)** - Presenting the options
5. **[Phase 2-A: User Investigation](#phase-2-a-user-investigation)** - Using user-investigation skill
6. **[Phase 2-B: Device Investigation](#phase-2-b-device-investigation)** - Using computer-investigation skill
7. **[Phase 2-C: IoC Investigation](#phase-2-c-ioc-investigation)** - Using ioc-investigation skill (IPs, URLs, Files, Domains, Hashes)
8. **[Phase 3: Post-Investigation Loop](#phase-3-post-investigation-loop-mandatory)** - Offer remaining entities, or skip to Phase 4
9. **[Phase 4: Final Summary & Verdict Gates](#phase-4-final-summary--verdict-gates)** - Baseline, alternatives, attribution, negative findings
10. **[JSON Export Structure](#json-export-structure)** - Required fields
11. **[Error Handling](#error-handling)** - Troubleshooting guide

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
   - **Validate infrastructure IPs empirically, not by rule.** A CIDR range alone is a hypothesis; cross-account prevalence is evidence. Run the [IP Prevalence Check](#ip-prevalence-check) before dismissing any IP as shared infrastructure, CGNAT, VPN egress, or a proxy — and state which method you used.
9. **ALWAYS defang malicious/suspicious URLs and IPs** - NEVER return them as clickable links. Use defang format: `hxxps://evil[.]com`, `203[.]0[.]113[.]42`
10. **⛔ NEVER auto-select a Sentinel workspace when multiple exist** - Workspace selection is MANDATORY:
    - ❌ DO NOT select a workspace on behalf of the user when multiple exist
    - ❌ DO NOT switch to another workspace if a query fails
    - ❌ DO NOT proceed with investigation without explicit user selection
    - ✅ If query fails: STOP, report error, ask user to select different workspace
    - ✅ If multiple workspaces: STOP, list all, WAIT for user selection
    - ✅ Only auto-select if exactly ONE workspace exists
11. **ALWAYS run the alert cohesion check before Phase 2** - Incidents can fuse unrelated activity. Verify the alerts share entities; if they form disjoint clusters, investigate and verdict each cluster **separately**. **De-correlated ≠ dismissed** (see Phase 1.5)
12. **ALWAYS establish a baseline before labelling behaviour anomalous** - No entity may be described as anomalous, unusual, or compromised without a stated 14–30 day baseline (see Phase 4 Gate 1)
13. **ALWAYS pass all four Verdict Gates before writing a classification** - Baseline, alternative hypotheses, attribution evidence, negative findings (see Phase 4)

**Incident ID Patterns:**
| Pattern | Source | Tool to Use |
|---------|--------|-------------|
| Numeric (e.g., `12345`, `98765`) | Defender XDR / Sentinel | `GetIncidentById` |
| GUID format | Sentinel (internal) | Sentinel `query_lake` MCP tool |
| `INxx-xxxxx` format | Defender XDR | `GetIncidentById` |

**⚠️ Sentinel → Defender XDR ID Mapping (Critical):**

When an incident is discovered via Sentinel KQL (e.g., `SecurityIncident` or `SecurityAlert` tables), its IDs are **Sentinel-local** and will NOT work with the Triage MCP:

| Sentinel Field | Triage MCP Accepts? | Correct Field to Use |
|---------------|---------------------|---------------------|
| `SecurityIncident.IncidentNumber` | ❌ Returns "not found" | Use `SecurityIncident.ProviderIncidentId` |
| `SecurityAlert.SystemAlertId` | ❌ Returns "not found" | Extract `parse_json(ExtendedProperties).IncidentId` |
| `SecurityIncident.ProviderIncidentId` | ✅ | Pass directly to `GetIncidentById` |

**Rule:** When querying `SecurityIncident` for later Triage MCP drill-down, **always project `ProviderIncidentId`** alongside `IncidentNumber`. Use `ProviderIncidentId` for all `GetIncidentById` calls.

**Date Range Rules:**
- **Default analysis window:** 7 days before current date to current date (Standard)
- **Investigation depth options:**
  - **Comprehensive:** 30 days window (for thorough analysis)
  - **Standard:** 7 days window (default)
  - **Quick:** 1 day window (for rapid triage)
- **Format:** ISO 8601 (e.g., `2026-01-17T00:00:00Z` to `2026-01-24T00:00:00Z`)

### IP Prevalence Check

Confirm whether an IP appears across **many unrelated accounts** in the window. This is the empirical test behind Critical Rule 8.

```kql
let TargetIPs = dynamic(["<ip1>","<ip2>"]);
EntraIdSignInEvents
| where Timestamp between (datetime(<start>) .. datetime(<end>))
| where IPAddress in (TargetIPs)
| summarize DistinctAccounts = dcount(AccountUpn), SignIns = count(),
            Days = dcount(bin(Timestamp, 1d)), SampleAccounts = make_set(AccountUpn, 5)
          by IPAddress
| order by DistinctAccounts desc
```

[Run in Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting?tid=<tenant_id>)

| Result | Interpretation |
|--------|----------------|
| High `DistinctAccounts` across many `Days` | **Shared infrastructure — proven.** Overrides a Defender `roles: ["attacker"]` tag and beats an ASN lookup or a 0% AbuseIPDB score, which only describe the IP's *owner*, not its use in **this** tenant |
| `DistinctAccounts == 1` | **Singleton — NOT shared infrastructure.** The "corporate egress / shared jump host / VPN pool" benign hypothesis is **eliminated**, not unresolved (Gate 2) |
| **No row returned** | The IP was never seen in sign-in telemetry. Find which source *did* observe it (`AlertEvidence`, `CloudAppEvents`) before citing it as a session IP |

Feed each result into Gate 1 — an entity whose baseline is mostly singleton IPs behaves differently from one that lives on shared infrastructure.

**Report only the counts this query returned.** Never supplement, substitute, or "remember" which accounts share an IP — a co-occurrence recalled from cached context is a hypothesis, and writing it into a column labelled as query output converts it into false evidence.

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

#### 🔴 Tool Selection for Alert Retrieval

**Use `GetIncidentById` with `includeAlertsData=true`** to retrieve incident-specific alerts. This returns only alerts correlated to the incident.

**⛔ DO NOT use `ListAlerts` to retrieve alerts for a specific incident.** `ListAlerts` has NO `incidentId` parameter — it can only filter by `createdAfter`, `createdBefore`, `severity`, `status`. Calling it returns **all tenant alerts** (up to page size 10,000), not incident-specific ones. Any unsupported parameter (e.g., `incidentId`) is silently ignored.

**If `GetIncidentById(includeAlertsData=true)` returns a truncated or excessively large response** (e.g., incident has hundreds of correlated alerts from noise sources like Purview IRM or DLP), use `RunAdvancedHuntingQuery` as the fallback:

```kql
// Get alerts linked to the incident's primary user/entity
AlertInfo
| where Timestamp > datetime(<incident_created_minus_7d>)
| join kind=inner (
    AlertEvidence
    | where Timestamp > datetime(<incident_created_minus_7d>)
    | where EntityType == "User"
    | where AccountUpn =~ "<primary_user_upn>" or AccountObjectId == "<user_object_id>"
    | distinct AlertId
) on AlertId
| project Timestamp, AlertId, Title, Severity, Category, AttackTechniques, DetectionSource, ServiceSource
| order by Timestamp asc
```

This approach bypasses the Triage MCP's alert cap and gives full control over date range and entity filtering.

#### Alert Fields to Retrieve

For each alert, retrieve:
- Alert name
- Tags
- Severity
- Investigation state
- Status
- **Classification** (TruePositive / FalsePositive / BenignPositive / unknown)
- **Determination** (Malware, Phishing, SecurityTesting, NotMalicious, etc.)
- Impacted assets
- Correlation reason
- Detection source
- First activity
- Last activity

**🔴 Surface pre-existing determinations.** `Classification` and `Determination` are often already populated by a prior analyst or by automated investigation. Show them in the alert table and **treat them as evidence** — an alert already marked `notMalicious` materially changes the weight of that alert. Do not silently re-litigate a closed determination; either corroborate it or state explicitly why you disagree.

**Presentation Rules:**
1. Return as a table (exclude the Alert ID column from display — but **retain the IDs**, Phase 1.5's sweep needs them)
2. Order by last activity date descending
3. Add row numbers starting from 1
4. If more than 30 alerts exist, note this after the table and provide a Defender portal link
5. NEVER calculate and write the total number of alerts
6. **Add a `Disposition` column** and fill it in once Phase 2 completes. Every alert must exit the investigation with exactly one of:

| Disposition | Meaning |
|-------------|---------|
| `Supports verdict` | Investigated; corroborates the cluster verdict |
| `Ruled out — <reason>` | Investigated; explained by a benign cause. State the reason inline |
| `Not investigated` | Outside the selected scope. **Must also appear in Phase 3's remaining-entities list** |

   No alert may be silently dropped. An alert missing from the final table is an unaccounted-for detection.

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
- **DEFANG ALL IPs:** When presenting IPs and domains to the user, ALWAYS use defanged format: `203[.]0[.]113[.]42`, `evil[.]com`. NEVER output clickable malicious indicators.

**URLs and DNS Domains (Top 10, Filtered):**
- Get ALL malicious/suspicious URLs and DNS Domains
- **Filter out tenant domain URLs** (DNS domains associated with the organization)
- Return only the first 10 from filtered list
- **DEFANG ALL URLs AND DNS DOMAINS:** When presenting URLs to the user, ALWAYS use defanged format: `hxxps://evil[.]com/path`, `hxxp://malware[.]net`. NEVER output clickable malicious URLs.

**AD Domains:**
- Return ALL malicious/suspicious AD domains (no limit)

**For each evidence type:** If more than 10 exist, note this after the table and provide Defender portal link.

---

### 1.5 Alert Cohesion & Adjacent-Alert Sweep

Incident correlation is fallible in **both** directions: it can **fuse unrelated activity** into one incident, and it can **leave related alerts outside** it. Run both checks before Phase 2 so the investigation scope is correct from the start.

#### (a) Cohesion Check — do these alerts belong together?

Group the incident's alerts by shared entity (user, device, IP, session/correlation ID) and present the clusters:

| Cluster | Alerts | Shared Entities | Time Span |
|---------|--------|-----------------|-----------|
| A | 4 | user1@contoso.com, `203[.]0[.]113[.]42` | 2026-01-20 04:07 → 04:15 |
| B | 7 | user2@contoso.com, `198[.]51[.]100[.]10` | 2026-01-14 08:00 → 08:01 |

- **Single cluster** (all alerts share ≥1 entity) → proceed normally, one verdict for the incident.
- **≥2 disjoint clusters** (zero shared entities) **AND** >24h gap between them → ⚠️ flag **probable spurious correlation**. Investigate each cluster independently and issue a **separate verdict per cluster** in Phase 4.

**🔴 De-correlated ≠ dismissed.** A cluster found not to relate to the seed alert is **never** dropped — it either receives its own verdict in this report or is explicitly handed off as a new investigation. **Report the correlation defect itself** as a finding: it is actionable detection-engineering feedback regardless of whether the underlying activity was malicious.

#### (b) Adjacent-Alert Sweep — is anything missing?

The incident's alert list is **not** the full picture of what its entities did. Sweep for alerts that touch an incident entity but were **not** correlated into the incident:

```kql
let IncidentAlertIds = dynamic(["<alertId1>", "<alertId2>"]);   // from GetIncidentById
let IncidentEntities = dynamic(["user1@contoso.com", "203.0.113.42", "HOST-01"]);
let IncidentObjectIds = dynamic(["<userObjectId1>"]);           // more reliable than UPN
let WindowStart = datetime(<incident_created_minus_7d>);
let WindowEnd   = datetime(<incident_last_activity_plus_1d>);
AlertEvidence
| where Timestamp between (WindowStart .. WindowEnd)
| where AccountUpn in~ (IncidentEntities)
    or AccountObjectId in (IncidentObjectIds)
    or RemoteIP in (IncidentEntities)
    or DeviceName in~ (IncidentEntities)
| where AlertId !in (IncidentAlertIds)
| distinct AlertId
| join kind=inner (
    AlertInfo
    | where Timestamp between (WindowStart .. WindowEnd)
) on AlertId
| project Timestamp, Title, Severity, Category, DetectionSource, ServiceSource, AttackTechniques
| order by Timestamp asc
```

[Run in Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting?tid=<tenant_id>)

**Tool:** `RunAdvancedHuntingQuery` — the default 7d window is well within the 30d AH limit. For windows >30d use `mcp_sentinel-data_query_lake` and swap `Timestamp` → `TimeGenerated`.

**⛔ Mandatory — no substitutes.** Prior investigations, cached context, or a high-confidence early verdict tell you how to *interpret* what this sweep returns; none of them tell you what it *would have returned*. Run it every time and state the row count, including zero.

**Report either outcome:**
- **Alerts found** → add them to scope, present in a table, and note that the platform did **not** correlate them into the incident.
- **None found** → state it explicitly: "✅ No additional alerts involving incident entities in [window]."
- **Query not executed** → the result line MUST read "⚠️ Not executed — sweep incomplete". ✅ asserts a zero row count you do not have.

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

**🔴 Defang every URL, domain, and IP** (Critical Rule 9) — `hxxps://evil[.]com/path`, `evil[.]com`, `203[.]0[.]113[.]42`. Never output clickable malicious indicators.

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

#### Evidence Capture Standard (applies to ALL Phase 2 investigations)

Per-event detail is what makes a verdict defensible and a cluster separation provable. For every event cited as evidence, capture:

| Telemetry | Capture |
|-----------|---------|
| **Sign-in** | `CorrelationId`/`RequestId`, `SessionId`, `ResultType`/`ErrorCode`, `RiskLevelDuringSignIn`, `RiskEventTypes`, device **managed + compliant** state and `DeviceId`, user agent, `ClientAppUsed`, `AuthenticationRequirement` |
| **Graph / API** | Operation, **HTTP method**, `ResponseStatusCode`, **response size** where the platform exposes it (`MicrosoftGraphActivityLogs.ResponseSizeBytes`), request URI, calling app/SPN identity |
| **Cloud app** | `ActionType`, `AccountObjectId`, `IPAddress`, user agent, and the specific `RawEventData` fields cited (parse once into a variable — never `tostring(RawEventData) has ...`) |
| **Device / process** | `DeviceId`, initiating-process chain, `SHA256`, signer/publisher, `FolderPath`, command line |

**Why these specifically:**
- **HTTP method + response size** discriminate *enumeration* from a single UI lookup. A small, single-object read is not reconnaissance no matter which API served it — do not map it to a discovery technique without volume or response-size support.
- **Managed/compliant state + risk level** are prerequisites for any compromise verdict. An unfamiliar IP on a compliant, managed device with no risk detection is a materially different finding from the same IP on an unmanaged one.
- **Correlation / request / session IDs** are what make cross-table pivots and the cluster separation in §1.5 *provable* rather than asserted.
- **Success/failure ratio** across the whole event set — always record it. High-volume access with **zero** authentication failures argues strongly against credential guessing or brute force.

**🔴 Validate the central artefact at its source.** When an alert's premise rests on a specific artefact, query the authoritative table for that artefact directly. Never infer its nature from the alert title.

| Artefact | Authoritative source | Report verbatim |
|----------|---------------------|-----------------|
| **Email** | `EmailEvents` by `NetworkMessageId` | `ThreatTypes`, `DetectionMethods`, `DeliveryAction`, `DeliveryLocation`, `EmailDirection`, `AuthenticationDetails` |
| **URL click** | `UrlClickEvents` by `Url` / `NetworkMessageId` | `ActionType`, `IsClickedThrough`, `UrlChain` |
| **File** | `DeviceFileEvents` or `GetDefenderFileInfo` by hash | `GlobalPrevalence`, signer, `FirstSeen` |
| **Sign-in** | `SigninLogs` / `EntraIdSignInEvents` by `CorrelationId` | `ResultType`, `RiskLevelDuringSignIn`, CA outcome |

**The platform's own disposition outranks the alert title.** An alert named "phish delivered" whose `EmailEvents` row shows empty `ThreatTypes`, empty `DetectionMethods`, and `DeliveryAction: Delivered` was **not** a detected phish. Say so, and record the discrepancy itself as a finding.

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
   - Sign-in anomalies (Signinlogs_Anomalies_KQL_CL — note lowercase 'l' in "logs")
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

**After completing ALL selected entity investigations in Phase 2, first check whether the loop is needed at all:**

| Condition | Action |
|-----------|--------|
| Material entities remain uninvestigated | Run the loop below |
| **No material entities remain** — all investigated, or the remainder were filtered out in §1.4 as internal/tenant-owned | ⏭️ **Skip to Phase 4.** Never present an empty "remaining entities" table |
| User requested a **complete / one-shot investigation** (e.g. *"investigate incident X and write the report"*, *"investigate everything"*) | ⏭️ **Skip to Phase 4.** The loop exists to confirm scope, **not** to withhold the verdict |

**When the loop IS needed, you MUST:**

1. **List remaining uninvestigated entities** - Show all entities from Phase 1 that were NOT yet investigated
2. **Ask the user to select additional entities** - Prompt user to continue or conclude
3. **Wait for user response** - Do not assume the investigation is complete

### Phase 3 Checklist (when the loop is needed)

```
☐ Step 3.1: Compile list of UNINVESTIGATED entities (exclude already-investigated items)
☐ Step 3.2: Present remaining entities to user with numbered list
☐ Step 3.3: Ask: "Would you like to investigate any of the remaining entities? Select by number/name, or say 'done' to conclude."
☐ Step 3.4: Wait for user response before concluding
```

### Required Prompt Format

When the loop **is** needed, end the findings with:

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
- **DO NOT** conclude while **material** entities remain unoffered — but this is a **scoping** gate, not a requirement that the user utter a magic word. When nothing material remains, proceed to Phase 4 on your own initiative
- **DO NOT** assume the investigation is complete just because selected entities were analyzed

### Loop Behavior

```
IF no material entities remain
   OR a complete / one-shot investigation was requested:
    → Proceed to Phase 4 directly — do NOT present the list, do NOT ask first

ELSE present the remaining-entities list, then:

    IF user selects additional entities:
        → Return to Phase 2 (2-A, 2-B, or 2-C based on entity type)
        → After completion, return to Phase 3 again

    ELSE IF user says "done" or declines:
        → Proceed to Phase 4 (Final Summary & Verdict Gates)
```

---

## Phase 4: Final Summary & Verdict Gates

**Entry condition — reached by ANY of the following:**

- The user says "done" or declines further investigation in Phase 3
- **No material entities remain** uninvestigated (Phase 3 loop skipped)
- The user requested a **complete or one-shot investigation** up front (e.g. *"investigate incident X and write me the report"*)
- The user asks for a verdict, classification, summary, or report at any point

**🔴 Phase 4 is never optional and never waits for permission.** Any output that states a classification — inline in chat, in a report file, or in a recorded finding — must have passed these gates first.

### ⛔ Four Gates — ALL must pass before writing any classification

#### Gate 1 · Baseline

For **every entity** you are about to call anomalous, unusual, or compromised, pull **14–30 days of prior activity** and diff it against the flagged activity across: **application set, source IPs/geography, operation mix, volume, and success/failure ratio**.

**State the baseline explicitly in the report** — including when it is absent (new account, no prior telemetry, retention exceeded).

> 💡 A source IP that is new to an entity is *novelty*. A source IP that is new **and** carries operations absent from the baseline **and** breaks the normal volume envelope is *anomaly*. Only the second justifies escalation.

**Diff the pattern, not only the value.** When a value is new, also ask **how often this entity acquires new values of that attribute**. If the baseline shows a recurring acquisition rate — a fresh short-lived source IP every 7–10 days, a new device each month — then the next new value is **baseline-consistent, not novel**. A correct value-level diff still yields a wrong verdict when the rate of change is itself the norm. Classify each baseline value by prevalence (Rule 8) so the pattern is described accurately.

| Action | Status |
|--------|--------|
| Calling behaviour "reconnaissance", "anomalous", "unusual", or "malicious" with no stated baseline | ❌ **PROHIBITED** |
| Labelling a value "novel" without checking how often the entity acquires new values of that attribute | ❌ **PROHIBITED** |
| A baseline diff before any behavioural verdict | ✅ **REQUIRED** |

#### Gate 2 · Alternative Hypotheses

State **at least one** competing benign explanation and resolve it with evidence:

| Hypothesis | Supporting Evidence | Contradicting Evidence | Verdict |
|------------|--------------------|-----------------------|---------|
| Automation / service workload | Same user agent present on baseline activity | — | ✅ Accepted |
| Credential compromise | Source IP new to this entity | 0 auth failures; compliant managed device; no risk detection | ❌ Rejected |

Include this table **even when the malicious hypothesis wins** — it demonstrates the alternative was tested rather than ignored.

#### Gate 3 · Attribution Evidence

Words like **"attacker"**, **"threat actor"**, **"adversary"**, **"malicious"**, and **"compromised"** require at least one of:

1. A threat-intel / reputation hit on the indicator
2. An observed malicious **action** — write, exfiltration, persistence, privilege change
3. Independent corroboration from a second telemetry source

**Unfamiliarity is not attribution.** A new IP, a new user agent, or a first-seen app is *novelty*, not adversary presence.

**Attribution confidence must never exceed overall verdict confidence.** If the verdict is "inconclusive", the infrastructure cannot be described as "attacker-controlled".

#### Gate 4 · Negative Findings

Explicitly enumerate what was searched for and **not** found. Silence is not evidence of absence — state what you checked:

- Persistence (app registrations, credential adds, role grants, scheduled tasks)
- Privilege escalation (role assignments, consent grants, PIM activations)
- Mailbox manipulation (forwarding rules, inbox rules, delegation)
- Exfiltration (bulk download/export, unusual data access volume)
- Control-plane writes (resource creation/deletion, policy changes)
- Lateral movement (new device or resource access)
- Endpoint execution (process, file, script events)

Also state **telemetry gaps** — tables unavailable, licences absent, retention exceeded — so a reader can distinguish "checked and clean" from "could not check".

### Verdict Block Format

Emit **one block per cluster** identified in §1.5 — not one blended verdict for the whole incident.

Use plain headings and bullets, matching the rest of the report. **Do not wrap verdict blocks in blockquotes or code fences** — Gate 2's hypothesis table and any supporting evidence tables must nest beneath the block without a `>` prefix on every row.

```markdown
#### Cluster A — `<entity>` · `<verdict>` 🟢 / 🟡 / 🟠 / 🔴

- **Classification:** TruePositive / BenignPositive / FalsePositive / Inconclusive
- **Confidence:** High / Medium / Low
- **Baseline:** *one line — what normal looks like for this entity*
- **Decisive evidence:** *1–3 bullets*
- **Not found:** *negative-findings summary*
- **Recommendation:** *action, or "no action required"*
```

After the last cluster block, close with an `#### Overall Assessment` heading in the same idiom — not a loose bold line — carrying the cross-cluster risk statement. Then provide consolidated recommendations across clusters and offer the JSON export.

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
   - List top 30 alerts as a table (include `Classification` / `Determination`)
   - Enumerate all assets by type (devices, users, apps, cloud resources)
   - List filtered evidences (processes, files, IPs, URLs, domains)

2. **Phase 1.5 - Alert Cohesion & Adjacent Sweep:**
   - Cluster the incident's alerts by shared entity; flag spurious correlation if disjoint
   - Sweep for related alerts left **outside** the incident
   - **De-correlated ≠ dismissed** — each cluster gets its own verdict

3. **⛔ Phase 2 - Mandatory Workspace Selection:**
   - Call `list_sentinel_workspaces` MCP tool FIRST
   - Present entity summary from Phase 1
   - If 1 workspace: auto-select and display
   - If multiple workspaces: ASK USER to select before proceeding
   - **DO NOT proceed to investigations without a workspace selected**

4. **Phase 2-A - User Investigation:**
   - For each selected user: Follow `.github/skills/user-investigation/SKILL.md`
   - Present findings

5. **Phase 2-B - Device Investigation:**
   - For each selected device: Follow `.github/skills/computer-investigation/SKILL.md`
   - Present findings

6. **Phase 2-C - IoC Investigation:**
   - For each selected IoC (IPs, URLs, Files, Domains, Hashes): Follow `.github/skills/ioc-investigation/SKILL.md`
   - Present findings
   - Apply the **Evidence Capture Standard** to every cited event (IDs, device posture, HTTP method + response size, success/failure ratio)

7. **Phase 3 - Post-Investigation Loop:**
   - List uninvestigated entities and ask whether to continue
   - **Skip straight to Phase 4** if nothing material remains, or a complete/one-shot investigation was requested

8. **Phase 4 - Final Summary & Verdict Gates:**
   - Gate 1 Baseline · Gate 2 Alternative hypotheses · Gate 3 Attribution evidence · Gate 4 Negative findings
   - Emit **one verdict block per cluster**, then consolidated recommendations
   - Create consolidated JSON file
---

## JSON Export Structure

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `investigation_metadata` | object | Incident ID, timestamp, phases completed, elapsed time |
| `incident_details` | object | Metadata, alerts (each with `disposition`), assets, evidences from Phase 1 |
| `clusters` | array | Phase 1.5 output — one entry per cohesion cluster, with member alert IDs, shared entities, and separation evidence |
| `user_investigations` | array | Results from Phase 2-A (includes the stated baseline) |
| `device_investigations` | array | Results from Phase 2-B |
| `ioc_investigations` | array | Results from Phase 2-C (IPs, URLs, files, domains, hashes) |
| `verdicts` | array | Phase 4 — **one verdict block per cluster**, each carrying its four gate results |
| `summary` | object | Overall risk assessment, consolidated recommendations, negative findings |

### Example JSON Structure

```json
{
  "investigation_metadata": {
    "incident_id": "<INCIDENT_ID>",
    "investigation_timestamp": "<ISO_TIMESTAMP>",
    "phases_completed": ["incident_description", "cohesion_check", "user_investigation", "ioc_investigation", "verdict"],
    "total_elapsed_time_seconds": 300
  },
  "incident_details": {
    "metadata": {
      "title": "<TITLE>", "severity": "<SEVERITY>", "status": "<STATUS>",
      "classification": "<CLASSIFICATION>", "determination": "<DETERMINATION>",
      "created_date": "<TIMESTAMP>", "first_activity_date": "<TIMESTAMP>",
      "mitre_categories": ["<TACTIC>"], "tags": ["<TAG>"]
    },
    "alerts": [
      {
        "id": "<ALERT_ID>", "name": "<ALERT_NAME>", "severity": "<SEVERITY>",
        "classification": "<PRE_EXISTING_CLASSIFICATION>", "determination": "<PRE_EXISTING_DETERMINATION>",
        "first_activity": "<TIMESTAMP>", "last_activity": "<TIMESTAMP>",
        "cluster": "A",
        "disposition": "Ruled out — mailbox is a lab honeypot; no click, no credential entry"
      }
    ],
    "assets": { "devices": [], "users": [], "apps": [], "cloud_resources": [] },
    "evidences": { "processes": [], "files": [], "ip_addresses": [], "urls": [], "ad_domains": [] }
  },
  "clusters": [
    {
      "id": "A", "label": "<SHORT_LABEL>", "alert_ids": ["<ALERT_ID>"],
      "shared_entities": ["user@contoso.com"],
      "time_span": { "start": "<TIMESTAMP>", "end": "<TIMESTAMP>" },
      "linked_to_other_clusters": false,
      "separation_evidence": "No shared UPN, IP, DeviceId, or SessionId with cluster B; 6 days apart",
      "sweep_performed": true,
      "uncorrelated_adjacent_alerts": 3
    }
  ],
  "user_investigations": [
    {
      "upn": "user@contoso.com", "user_id": "<GUID>",
      "time_window": { "start": "<ISO_TIMESTAMP>", "end": "<ISO_TIMESTAMP>" },
      "baseline": {
        "window_days": 30, "typical_ips": [], "typical_countries": [],
        "typical_apps": [], "typical_devices": []
      },
      "findings": {}, "risk_level": "Low"
    }
  ],
  "device_investigations": [
    { "hostname": "<DEVICE_NAME>", "device_id": "<GUID>", "findings": {} }
  ],
  "ioc_investigations": [
    {
      "ioc_type": "IP", "value": "203.0.113.42",
      "prevalence": { "distinct_accounts": 553, "days": 30 },
      "threat_assessment": "Shared infrastructure — not attacker-controlled",
      "findings": {}
    }
  ],
  "verdicts": [
    {
      "cluster": "A",
      "classification": "BenignPositive",
      "determination": "SecurityTesting",
      "confidence": "High",
      "gates": {
        "baseline": "30-day baseline established; all observed IPs and apps fall within it",
        "alternatives_considered": [
          {
            "hypothesis": "Credential theft via phish",
            "status": "Eliminated",
            "evidence": "No click in UrlClickEvents; no sign-in from sender infrastructure"
          }
        ],
        "attribution_evidence": "EmailEvents shows empty ThreatTypes and DetectionMethods — no platform detection backs the alert title",
        "negative_findings": ["No mailbox rule creation", "No OAuth consent grant", "No sign-in risk detection"]
      },
      "recommendations": []
    }
  ],
  "summary": {
    "risk_assessment": "Low",
    "key_findings": [],
    "negative_findings": [],
    "recommendations": []
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

### Workspace Selection

See [Phase 2 Step 2.3](#step-23-workspace-selection-gate). Do not restate or re-derive the rule — and never re-ask once `SESSION_WORKSPACE_SELECTED == true`.

---

## Example Investigation Workflow

**User Request:** "Investigate incident 12345"

⚠️ This example is deliberately abbreviated. It exists to show the **shape** of a compliant investigation — specifically the Phase 1.5 clustering table and the Phase 4 verdict blocks. Do not copy findings or phrasing from it.

### Phase 1 — Incident Description

Retrieve metadata via `GetIncidentById`, then present alerts, assets, and filtered evidences per §1.1–§1.4. The alert table carries `Classification`, `Determination`, and the `Disposition` column (completed at the end of Phase 2).

### Phase 1.5 — Alert Cohesion & Adjacent Alert Sweep

```
[01:30] Cohesion check — 7 alerts

| Cluster | Alerts | Shared entities                     | Time span                   |
|---------|--------|-------------------------------------|-----------------------------|
| A       | 5      | jsmith@contoso.com, WORKSTATION-01  | Jan 20 10:30 – Jan 20 14:05 |
| B       | 2      | svc-backup@contoso.com              | Jan 14 03:12 – Jan 14 03:14 |

Separation evidence: no shared UPN, IP, DeviceId, or SessionId between A and B; 6 days apart.
→ Investigate and verdict A and B SEPARATELY. De-correlated ≠ dismissed.

Sweep: 3 further alerts on cluster-A entities in the ±7d window were NOT correlated into
the incident (2 × Purview DLP, 1 × sign-in risk). Both clusters' entity sets swept.
```

### Phase 2 — Investigation

Workspace gate → entity selection → run 2-A / 2-B / 2-C in parallel, applying the **Evidence Capture Standard** to every cited event. Validate central artefacts at source: `EmailEvents` by `NetworkMessageId`, hash prevalence via `GetDefenderFileInfo`, and IPs via the [IP Prevalence Check](#ip-prevalence-check).

A cited event carries its identifiers, not just its label — e.g. *"`GET /v1.0/me/messages?$search=…` → `200`, `ResponseSizeBytes` 1,204,880, 312 calls in 4 min by app `<AppDisplayName>`"*, not *"mail enumeration detected"*. The same rule governs the negative: **"no exfiltration found" requires showing the operations you looked at**, otherwise it is an assumption.

### Phase 3 — Post-Investigation Loop

Two entities remained uninvestigated (`SERVER-DC01`, `jdoe@contoso.com`); neither was material to either cluster, so the loop was skipped and the reason stated. Both are recorded with `disposition: "Not investigated"`.

### Phase 4 — Verdict Blocks (one per cluster)

```
━━━ Cluster A — WORKSTATION-01 / jsmith@contoso.com ━━━
Classification: TruePositive   Determination: Malware   Confidence: High

Gate 1 — Baseline (30d): jsmith signs in from 2 IPs, both AS12345 corporate egress,
  always from WORKSTATION-01, always compliant + managed. The Jan 20 session came from a
  singleton IP (DistinctAccounts = 1), an unmanaged device, ClientAppUsed = Other.
Gate 2 — Alternatives: VPN/travel ELIMINATED (no travel record; device unmanaged).
  Shared egress ELIMINATED (prevalence = 1 account). Admin tooling ELIMINATED (no PIM activation).
Gate 3 — Attribution: SHA256 abc123… GlobalPrevalence = 4, unsigned, written to %TEMP%;
  DeviceNetworkEvents shows 42 outbound beacons to 203[.]0[.]113[.]42 at 60s intervals.
Gate 4 — Negative findings: no lateral movement; no LSASS access events; no mailbox rule
  creation; no OAuth consent grant.

━━━ Cluster B — svc-backup@contoso.com ━━━
Classification: BenignPositive   Determination: SecurityTesting   Confidence: High

Gate 1 — Baseline (30d): identical ~3-minute burst at 03:12 every weekday, same IP, same app.
Gate 2 — Alternatives: compromise ELIMINATED (100% success ratio, zero auth failures,
  no off-schedule activity across the full 30d window).
Gate 3 — Attribution: scheduled backup job; user agent and app ID match documented automation.
Gate 4 — Negative findings: no scope expansion; no new credentials added to the SPN.
```

**Consolidated recommendations** follow the verdict blocks, each tagged with its cluster and severity.

**Export:** `temp/incident_investigation_12345_<date>.json`

---

## Integration with Skill Files

This skill orchestrates investigations by referencing specialized skills:

| Investigation Phase | Skill/Tool | Location/Reference |
|--------------------|------------|-------------------|
| Phase 1: Incident Description | Built-in workflow | This file (see Phase 1 section) |
| Phase 1.5: Alert Cohesion & Sweep | Built-in workflow | This file (see §1.5) |
| Phase 2-A: User Investigation | user-investigation skill | `.github/skills/user-investigation/SKILL.md` |
| Phase 2-B: Device Investigation | computer-investigation skill | `.github/skills/computer-investigation/SKILL.md` |
| Phase 2-C: IoC Investigation | ioc-investigation skill | `.github/skills/ioc-investigation/SKILL.md` (IPs, URLs, Files, Domains, Hashes) |
| Phase 4: Verdict Gates | Built-in workflow | This file (see Phase 4 section) |

**🔴 ALWAYS read the referenced skill file before executing that phase to ensure proper workflow execution.**
