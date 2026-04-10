---
name: threat-pulse
description: 'Recommended starting point for new users and daily SOC operations. Quick 15-minute security posture scan across 9 domains: active incidents, identity (human + NonHuman), device process drift, rare process chains, email threats, admin & cloud ops, critical asset exposure, and exploitable CVEs. 13 queries executed in parallel batches, producing a prioritized Threat Pulse Dashboard with color-coded verdicts (🔴 Escalate / 🟠 Investigate / 🟡 Monitor / ✅ Clear) and drill-down recommendations pointing to specialized skills. Trigger on getting-started questions like "what can you do", "where do I start", "help me investigate". Supports inline chat and markdown file output'
---

# Threat Pulse — Instructions

## Purpose

The Threat Pulse skill is a rapid, broad-spectrum security scan designed for the "if you only had 15 minutes" scenario. It executes 13 queries across 9 security domains in parallel, producing a prioritized dashboard of findings with drill-down recommendations to specialized investigation skills.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔴 **Incidents** | What high-severity incidents are open and unresolved? How old are they? Who owns them? What was recently resolved — TP rate, MITRE tactics, severity distribution? |
| 🔐 **Identity (Human)** | Which users have the most anomalous sign-in patterns this week? How many risky sign-ins? Are there password spray / brute-force patterns? |
| 🤖 **Identity (NonHuman)** | Which service principals expanded their resource/IP/location footprint? |
| 💻 **Endpoint** | Which endpoints deviated most from their process behavioral baseline? What singleton process chains exist? |
| 📧 **Email Threats** | What's the phishing/spam/malware breakdown? Were any phishing emails delivered? |
| 🔑 **Admin & Cloud Ops** | What mailbox rules, OAuth consents, transport rules, or mailbox permission changes occurred? Who performed high-impact admin operations? |
| 🛡️ **Exposure** | Are any critical assets internet-facing with RCE vulnerabilities? What exploitable CVEs (CVSS ≥ 8) are present across the fleet? |

**Data sources:** `SecurityIncident`, `SecurityAlert`, `Signinlogs_Anomalies_KQL_CL` (custom, fallback: `SigninLogs`), `SigninLogs`, `EntraIdSignInEvents`, `DeviceProcessEvents`, `DeviceLogonEvents`, `ExposureGraphNodes`, `AADServicePrincipalSignInLogs`, `EmailEvents`, `CloudAppEvents`, `AuditLogs`, `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB`

**References:**
- [Microsoft Sentinel — SecurityIncident](https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference#securityincident)
- [Microsoft Sentinel — SecurityAlert](https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference#securityalert)
- [Defender XDR — Advanced Hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [Defender TVM — Software Vulnerabilities](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table)
- [Exposure Management — ExposureGraphNodes](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph)

### 🔴 URL Registry — Canonical Links for Report Generation

**MANDATORY:** When generating reports, copy URLs **verbatim** from this registry. NEVER construct, guess, or paraphrase a URL.

| Label | Canonical URL |
|-------|---------------|
| `DOCS_SECURITY_INCIDENT` | `https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference#securityincident` |
| `DOCS_ADVANCED_HUNTING` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview` |
| `DOCS_IDENTITY_PROTECTION` | `https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection` |
| `DOCS_EXPOSURE_MANAGEMENT` | `https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph` |
| `DOCS_TVM` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table` |
| `DOCS_EMAIL_EVENTS` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table` |
| `DOCS_CLOUD_APP_EVENTS` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table` |
| `XDR_INCIDENT_BASE` | `https://security.microsoft.com/incidents/` |

**Usage in reports:** When referencing incidents, always construct portal links as `XDR_INCIDENT_BASE` + `ProviderIncidentId`. When referencing documentation, use the appropriate `DOCS_*` label.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** — Mandatory execution requirements
2. **[Execution Workflow](#execution-workflow)** — Phased query plan with parallel groups
3. **[Sample KQL Queries](#sample-kql-queries)** — All 13 verified queries with fallback logic
4. **[Post-Processing](#post-processing)** — Device drift score computation, cross-query correlation
5. **[Query File Recommendations](#query-file-recommendations)** — Dynamic hunting follow-up from findings
6. **[Output Modes](#output-modes)** — Inline, markdown file, or both
7. **[Inline Report Template](#inline-report-template)** — Dashboard format with verdicts
8. **[Markdown File Report Template](#markdown-file-report-template)** — Extended format with appendices
9. **[Known Pitfalls](#known-pitfalls)** — Table-specific gotchas
10. **[Quality Checklist](#quality-checklist)** — Pre-output validation
11. **[SVG Dashboard Generation](#svg-dashboard-generation)** — Optional visual dashboard

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Workspace selection** — Follow the SENTINEL WORKSPACE SELECTION rule from `copilot-instructions.md`. Call `list_sentinel_workspaces()` before first query.

2. **Read `config.json`** — Load workspace ID, tenant, subscription, and Azure MCP parameters before execution.

3. **ASK the user** for output preferences before executing queries:
   - **Output mode:** Inline chat / Markdown file / Both
   - **Lookback override:** Default is 7d for most queries; user may want 14d or 30d
   - If user says "just run it" or similar, default to **inline chat** with **7d lookback**.

4. **⛔ MANDATORY: Evidence-based analysis only** — Every finding must cite query results. Every "clear" verdict must cite 0 results. Follow the Evidence-Based Analysis rule from `copilot-instructions.md`.

5. **Parallel execution** — Run all Data Lake queries in parallel (Q1, Q1b, Q2/Q2b, Q3, Q5, Q10). Run all Advanced Hunting queries in parallel (Q4, Q6, Q7, Q8, Q9, Q11, Q12). The two groups can overlap.

6. **Graceful fallback for Q2** — `Signinlogs_Anomalies_KQL_CL` is a custom table that may not exist in all workspaces. If query returns `SemanticError: Failed to resolve table`, immediately execute **Q2b** (Identity Protection fallback) instead. Do NOT report the custom table failure as an error — silently fall back and note the data source in the report.

7. **Cross-query correlation** — After all queries complete, check for correlated findings:
   - User appearing in **both** Q2/Q2b anomalies AND Q3 risky sign-ins → escalate priority
   - SPN drift (Q5) + unusual credential/consent activity (Q9) → escalate priority
   - Device in rare process chains (Q7) + device in CVE list (Q12) → escalate priority
   - Incident entities (Q1) matching users in Q2/Q3 → link findings

8. **SecurityIncident output rule** — Every incident MUST include a clickable Defender XDR portal URL: `https://security.microsoft.com/incidents/{ProviderIncidentId}`.

9. **⛔ MANDATORY: Query File Recommendations (tiered)** — After assigning verdicts and BEFORE rendering the final report, execute the [Query File Recommendations](#query-file-recommendations) procedure. Skip only when ALL verdicts are ✅.

| Highest Verdict | Query Files | Proactive Skills | Report Section |
|----------------|-------------|-----------------|----------------|
| 🔴 or 🟠 | Top 3–5, entity-specific prompts | — | `📂 Recommended Query Files` |
| 🟡 (no 🔴/🟠) | Top 1–2, broader prompts | Up to 3 posture skills | `📂 Proactive Hunting Suggestions` |
| All ✅ | Skip | Skip | Omit entirely |

---

## Execution Workflow

### Phase 0: Prerequisites

1. Read `config.json` for workspace ID and Azure MCP parameters
2. Call `list_sentinel_workspaces()` to enumerate available workspaces
3. Ask user for output mode and lookback preference (or use defaults)
4. **Display scan summary** — Before executing any queries, output the following brief to the user:

```
🔍 Threat Pulse — Scan Plan

Workspace: <WorkspaceName> (<WorkspaceId>)
Lookback: <N>d (user-selected or default 7d)
Output: <Inline / Markdown file / Both>

Executing 13 queries across 9 domains:
  🔴 Incidents      — Open high-severity + 7d closed summary (Q1, Q1b)
  🔐 Identity       — Sign-in anomalies, risky sign-ins, auth spray (Q2, Q3, Q4)
  🤖 NonHuman ID    — Service principal behavioral drift (Q5)
  💻 Endpoint       — Device process drift, rare process chains (Q6, Q7)
  📧 Email          — Inbound threat snapshot (Q8)
  🔑 Admin & Cloud  — Cloud app ops, privileged operations (Q9, Q10)
  🛡️ Exposure       — Critical assets, exploitable CVEs (Q11, Q12)

Data Lake: 6 queries in parallel | Advanced Hunting: 7 queries in parallel
Estimated time: ~2–4 minutes
```

### Phase 1: Data Lake Queries (Q1, Q1b, Q2, Q3, Q5, Q10)

**Run all 6 in parallel — no dependencies between queries.**

| Query | Domain | Purpose | Tool |
|-------|--------|---------|------|
| Q1 | 🔴 Incidents | Open High/Critical incidents with MITRE tactics | `query_lake` |
| Q1b | 🔴 Incidents | 7-day closed incident summary (classification, MITRE, severity) | `query_lake` |
| Q2 | 🔐 Identity (Human) | Fleet-wide sign-in anomalies (High/Medium) | `query_lake` |
| Q3 | 🔐 Identity (Human) | Risky sign-ins / Identity Protection summary | `query_lake` |
| Q5 | 🤖 Identity (NonHuman) | Service principal behavioral drift (90d vs 7d) | `query_lake` |
| Q10 | 🔑 Admin & Cloud Ops | High-impact admin operations (AuditLogs) | `query_lake` |

**Fallback:** If Q2 fails with table resolution error, execute Q2b in its place.

### Phase 2: Advanced Hunting Queries (Q4, Q6, Q7, Q8, Q9, Q11, Q12)

**Run all 7 in parallel — no dependencies between queries.**

| Query | Domain | Purpose | Tool |
|-------|--------|---------|------|
| Q4 | 🔐 Identity (Human) | Password spray / brute-force across Entra ID + RDP/SSH | `RunAdvancedHuntingQuery` |
| Q6 | 💻 Endpoint | Fleet device process drift (7d baseline vs 1d) | `RunAdvancedHuntingQuery` |
| Q7 | 💻 Endpoint | Rare process chain singletons (90d) | `RunAdvancedHuntingQuery` |
| Q8 | 📧 Email | Inbound email threat snapshot | `RunAdvancedHuntingQuery` |
| Q9 | 🔑 Admin & Cloud Ops | Cloud app suspicious activity (CloudAppEvents) | `RunAdvancedHuntingQuery` |
| Q11 | 🛡️ Exposure | Internet-facing critical assets | `RunAdvancedHuntingQuery` |
| Q12 | 🛡️ Exposure | Exploitable CVEs (CVSS ≥ 8) across fleet | `RunAdvancedHuntingQuery` |

### Phase 3: Post-Processing & Report

1. Interpret device drift scores from Q6 results (see [Post-Processing](#post-processing))
2. Run cross-query correlation checks (see rule 7 above)
3. Assign verdicts to each domain (🔴 Escalate / 🟠 Investigate / 🟡 Monitor / ✅ Clear)
4. Generate prioritized recommendations with drill-down skill references
5. **⛔ STOP — Recommendation Gate:** Before proceeding to step 6, run the [Query File Recommendations](#query-file-recommendations) procedure matching the highest verdict tier (see Rule 9 table). Skip only when all verdicts are ✅. **Do NOT proceed to step 6 until this gate is resolved.**
6. Render output in requested mode (report MUST include the recommendations section if step 5 triggered it)

### Phase 4: Interactive Follow-Up Loop

**After rendering the report, present the user with a selectable list of follow-up actions — skill investigations, query file hunts, and IOC lookups.** Runs when at least one 🔴, 🟠, or 🟡 verdict exists (skip only when ALL verdicts are ✅).

**This is a loop, not a one-shot.** After each action completes, re-present the selection list with the prompt pool updated.

**🟡 Monitor-only environments:** When the highest verdict is 🟡, the prompt pool emphasizes broader posture/assessment skills rather than entity-specific deep-dives. This gives smaller environments actionable next steps even when no finding crosses the escalation threshold.

**Prompt types (three categories, one unified list):**

| Type | Icon | Source | Example |
|------|------|--------|---------|
| **Skill investigation** | 🔍 | Per-query `Drill-down:` skill + entities from findings | `🔍 Investigate user jsmith@contoso.com` → `user-investigation` |
| **Query file hunt** | 📄 | Keyword extraction → `grep_search` → `queries/**` | `📄 Hunt for RDP lateral movement from 10.0.0.50` → `queries/endpoint/rdp_lateral_movement.md` |
| **IOC lookup** | 🎯 | Suspicious IPs, domains, hashes surfaced in findings | `🎯 Enrich and investigate IP 203.0.113.42` → `ioc-investigation` |

**Skill matching rules — derive from findings:**

| Finding Type | Skill | Prompt Pattern |
|-------------|-------|---------------|
| Username/UPN in Q2–Q4, Q9, Q10 | `user-investigation` | `Investigate <UPN>` |
| IP address in Q4 (spray source) | `ioc-investigation` | `Investigate IP <address>` |
| SPN in Q5 | `scope-drift-detection/spn` | `Analyze drift for <SPN>` |
| Device in Q6, Q7, Q11, Q12 | `computer-investigation` | `Investigate device <hostname>` |
| Email threats in Q8 | `email-threat-posture` | `Run email threat posture report` |
| CVE in Q12 | `exposure-investigation` | `Run vulnerability report for <CVE>` |
| Incident in Q1 | `incident-investigation` | `Investigate incident <ProviderIncidentId>` |

**Procedure:**
1. Build the **initial prompt pool** by combining:
   - Skill prompts: one per unique entity + matching skill from the table above
   - Query file prompts: from Phase 3 step 5 keyword extraction
   - IOC prompts: any suspicious IPs/domains from non-✅ findings not already covered by a skill prompt
   - Deduplicate: if a skill prompt and IOC prompt target the same entity, keep only the skill prompt
2. Present the pool using the interactive question tool:
   - **Header:** `Follow-Up Investigation`
   - **Question:** `Select an action to launch (or skip):`
   - **Options:** One per prompt — **Label:** `<icon> <dynamic prompt text>`, **Description:** `Q<N>: <finding> → <skill or query file>`
   - Penultimate option: **Label:** `💾 Save full investigation report` / **Description:** `Save the complete Threat Pulse session (scan + all drill-downs) as a markdown file`
   - Final option: **Label:** `Skip` / **Description:** `No follow-up — investigation complete`
   - **multiSelect:** `false`
3. If user selects **Skip** or pool is empty: end skill execution
4. If user selects **💾 Save full investigation report:**
   a. Compile the original Threat Pulse dashboard + all drill-down investigation results accumulated during this session into a single markdown file
   b. Save to `reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md` using the [Markdown File Report Template](#markdown-file-report-template)
   c. Append a `## Drill-Down Investigation Results` section containing the findings from each follow-up action completed during this session, in the order they were executed
   d. Return to step 2 — the save option is removed from the pool (report already saved), remaining prompts stay available
5. If user selects an action:
   a. **Skill prompt:** load the skill's SKILL.md, execute the investigation with the target entity
   b. **Query file prompt:** read the query file, add as context, execute the hunt
   c. **IOC prompt:** load `ioc-investigation` skill, execute with the target indicator
   d. Remove the completed prompt from the pool
   e. Scan results for **new evidence** (entities, IOCs, TTPs not in original Threat Pulse results) — generate new prompts if found, prepend to pool with `🆕` tag
   f. **Return to step 2 — call the interactive question tool again.** Every loop iteration MUST use `vscode_askQuestions` to present the updated pool as a selectable list. Do NOT render a markdown table/numbered list as a substitute.

**Prompt pool rules:**
- Completed prompts are removed — never re-offered
- New evidence prompts are prepended (freshest leads first), tagged `🆕`
- Loop ends when user selects Skip or pool empties (`✅ All follow-up actions completed.`)
- **🔴 PROHIBITED:** Rendering the prompt pool as a markdown table, numbered list, or plain text instead of calling `vscode_askQuestions`. Every iteration — including after the first follow-up completes — MUST use the interactive question tool so options are clickable. This is the #1 loop-breaking mistake.

---

## Sample KQL Queries

> **All queries below are verified against live Sentinel/Defender XDR schemas. Use them exactly as written. Lookback periods use `ago(Nd)` — substitute the user's preferred lookback where noted.**

### Query 1: Open High-Severity Incidents with MITRE Techniques

🔴 **Incident hygiene** — Surfaces unresolved High/Critical incidents with age, owner, alert count, and MITRE tactics.

**Tool:** `mcp_sentinel-data_query_lake`

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active")
| where Severity in ("High", "Critical")
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project SystemAlertId, Tactics, AlertName, AlertSeverity
) on $left.AlertId == $right.SystemAlertId
| summarize 
    Tactics = make_set(Tactics),
    AlertNames = make_set(AlertName, 5),
    AlertCount = dcount(AlertId)
    by ProviderIncidentId, Title, Severity, Status, CreatedTime,
       OwnerUPN = tostring(Owner.userPrincipalName)
| extend AgeDays = datetime_diff('day', now(), CreatedTime)
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId)
| order by Severity asc, AgeDays desc
| take 15
```

**Purpose:** Identifies the top 15 open high-severity incidents, ranked by age. Joins SecurityAlert for MITRE tactic visibility. Flags unassigned incidents (empty OwnerUPN) and incident age debt (>30 days old).

**Verdict logic:**
- 🔴 Escalate: Any incident with `AgeDays > 30` AND empty `OwnerUPN`
- 🟠 Investigate: Any incident with `AgeDays > 14` or `AlertCount > 10`
- 🟡 Monitor: Open incidents exist but are assigned and recently triaged
- ✅ Clear: 0 open High/Critical incidents (Q1b closed summary still renders as context)

---

### Query 1b: Closed Incident Summary (7-Day Lookback)

🔴 **Threat landscape context** — Even when all incidents are resolved, the classification breakdown, MITRE tactic distribution, and severity mix from recent closures provide actionable signals for cross-correlation and query file recommendations.

**Tool:** `mcp_sentinel-data_query_lake`

**Always runs in parallel with Q1 — not conditional on Q1 results.**

```kql
SecurityIncident
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project SystemAlertId, Tactics
) on $left.AlertId == $right.SystemAlertId
| summarize
    Total = dcount(IncidentNumber),
    TruePositive = dcountif(IncidentNumber, Classification == "TruePositive"),
    BenignPositive = dcountif(IncidentNumber, Classification == "BenignPositive"),
    FalsePositive = dcountif(IncidentNumber, Classification == "FalsePositive"),
    Undetermined = dcountif(IncidentNumber, Classification == "Undetermined"),
    HighCritical = dcountif(IncidentNumber, Severity in ("High", "Critical")),
    MediumLow = dcountif(IncidentNumber, Severity in ("Medium", "Low")),
    Tactics = make_set(Tactics)
```

**Purpose:** Provides a 7-day closed incident summary with classification breakdown (TP/BP/FP/Undetermined), severity distribution, and aggregated MITRE tactics. This data feeds three downstream uses:
1. **TP rate signal** — High TruePositive ratio indicates an active threat environment
2. **MITRE tactic context** — Tactics from closed TPs identify the current threat landscape for cross-correlation with Q2/Q3/Q7/Q8 findings
3. **Query file recommendation fuel** — Tactic keywords from Q1b feed the keyword extraction rules for the `queries/` library search

**Verdict logic:**
- 🟠 Investigate: `TruePositive / Total > 0.5` (majority of closures are real threats — active threat environment)
- 🟡 Monitor: Any TruePositive closures exist, or `Undetermined > 0` (some incidents lack classification)
- ✅ Clear: 0 TruePositive closures; all closures are BenignPositive or FalsePositive
- 🔵 Informational: 0 closed incidents in 7d

**Rendering rules:**
- **Always render** Q1b results in the report, regardless of Q1 verdict
- Present as a compact summary block under the Q1 section (not a separate dashboard row)
- Flatten the `Tactics` array and report only distinct tactic names from TruePositive incidents
- If 0 closed incidents in 7d, display: "No incidents closed in the last 7 days"

---

### Query 2: Fleet-Wide Sign-In Anomalies (Primary — Custom Table)

🔐 **Anomaly detection** — Queries the pre-computed `Signinlogs_Anomalies_KQL_CL` table for High/Medium anomalies across ALL users.

**Tool:** `mcp_sentinel-data_query_lake`

**⚠️ CUSTOM TABLE — may not exist in all workspaces. If `SemanticError: Failed to resolve table`, silently execute Q2b instead.**

```kql
Signinlogs_Anomalies_KQL_CL
| where TimeGenerated > ago(7d)
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10, "Medium",
    CountryNovelty or CityNovelty or StateNovelty, "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| where Severity in ("High", "Medium")
| summarize 
    AnomalyCount = count(),
    HighCount = countif(Severity == "High"),
    TopAnomalyTypes = make_set(AnomalyType, 5),
    TopCountries = make_set(Country, 5),
    LatestDetection = max(DetectedDateTime)
    by UserPrincipalName
| order by HighCount desc, AnomalyCount desc
| take 15
```

**Purpose:** Surfaces top 15 users with the most High/Medium sign-in anomalies in the past 7 days. Geographic novelty (new countries/cities) combined with high hit counts indicates potential account compromise or token theft.

**Verdict logic:**
- 🔴 Escalate: Any user with `HighCount > 0` (High-severity anomalies with geo-novelty + high hit counts)
- 🟠 Investigate: `AnomalyCount > 5` for any single user, or users with `NewInteractiveIP` / `NewInteractiveDeviceCombo` anomaly types
- 🟡 Monitor: Only Medium-severity `NewNonInteractive*` anomalies with low hit counts
- ✅ Clear: 0 High/Medium anomalies across the fleet

---

### Query 2b: Fleet-Wide Sign-In Anomalies (Fallback — Identity Protection)

🔐 **Identity Protection fallback** — Used when `Signinlogs_Anomalies_KQL_CL` does not exist. Queries `SigninLogs` risk detections and `AADUserRiskEvents` for equivalent anomaly coverage.

**Tool:** `mcp_sentinel-data_query_lake`

**⚠️ EXECUTE ONLY if Q2 fails with table resolution error.**

```kql
let RiskySignins = SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium", "low") or RiskState in ("atRisk", "confirmedCompromised")
| where isnotempty(RiskEventTypes_V2)
| extend RiskEvents = parse_json(RiskEventTypes_V2)
| mv-expand RiskEvent = RiskEvents
| extend RiskEventType = tostring(RiskEvent)
| summarize
    AnomalyCount = count(),
    HighCount = countif(RiskLevelDuringSignIn == "high"),
    MediumCount = countif(RiskLevelDuringSignIn == "medium"),
    TopRiskEvents = make_set(RiskEventType, 5),
    TopCountries = make_set(Location, 5),
    TopIPs = make_set(IPAddress, 5),
    LatestDetection = max(TimeGenerated)
    by UserPrincipalName
| order by HighCount desc, AnomalyCount desc
| take 15;
RiskySignins
```

**Purpose:** Fallback that achieves similar anomaly coverage via Identity Protection risk detections (unfamiliarFeatures, impossibleTravel, maliciousIPAddress, etc.) when the custom anomaly table is unavailable. Results are formatted to match Q2's output shape for consistent report rendering.

**Verdict logic:**
- 🔴 Escalate: Any user with `HighCount > 3` or multiple users with `HighCount > 0`
- 🟠 Investigate: `HighCount > 0` for any user, or `AnomalyCount > 5` with risk events indicating `impossibleTravel` or `maliciousIPAddress`
- 🟡 Monitor: Only `MediumCount > 0` with low-severity risk event types (e.g., `unfamiliarFeatures`)
- ✅ Clear: 0 risky sign-in anomalies across the fleet

**Report note:** When Q2b is used instead of Q2, include this in the report header: `📊 Data Source: Identity Protection (SigninLogs risk events) — custom anomaly table not available in this workspace.`

---

### Query 3: Risky Sign-Ins & Identity Protection Summary

🔐 **Risk posture snapshot** — Fleet-level summary of Identity Protection risk signals.

**Tool:** `mcp_sentinel-data_query_lake`

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium") or RiskState in ("atRisk", "confirmedCompromised")
| summarize 
    RiskySignIns = count(),
    DistinctUsers = dcount(UserPrincipalName),
    HighRisk = countif(RiskLevelDuringSignIn == "high"),
    MediumRisk = countif(RiskLevelDuringSignIn == "medium"),
    AtRisk = countif(RiskState == "atRisk"),
    Compromised = countif(RiskState == "confirmedCompromised"),
    TopUsers = make_set(UserPrincipalName, 10),
    TopRiskEvents = make_set(RiskEventTypes_V2, 10)
| project RiskySignIns, DistinctUsers, HighRisk, MediumRisk, 
    AtRisk, Compromised, TopUsers, TopRiskEvents
```

**Purpose:** Single-row summary of risky sign-in activity — how many, how severe, who's affected. Surfaces users in `atRisk` or `confirmedCompromised` states that need immediate admin attention.

**Verdict logic:**
- 🔴 Escalate: `Compromised > 0` or `HighRisk > 10`
- 🟠 Investigate: `AtRisk > 0` or `HighRisk > 0`
- 🟡 Monitor: `MediumRisk > 0` only
- ✅ Clear: 0 risky sign-ins

---

### Query 4: Password Spray / Brute-Force Detection

🔐 **Auth spray detection (T1110.003 / T1110.001)** — Identifies IPs targeting multiple users with failed auth across Entra ID cloud sign-ins AND RDP/SSH/network logons on endpoints.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let EntraSpray = EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode in (50126, 50053, 50057)
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(AccountUpn),
    SampleTargets = make_set(AccountUpn, 5),
    Protocols = make_set(Application, 3),
    Countries = make_set(Country, 3)
    by SourceIP = IPAddress
| where TargetUsers >= 5
| extend Surface = "Entra ID";
let EndpointBrute = DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| where LogonType in ("RemoteInteractive", "Network")
| where isnotempty(RemoteIP)
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(AccountName),
    SampleTargets = make_set(AccountName, 5),
    Protocols = make_set(strcat(LogonType, " → ", DeviceName), 3),
    Countries = dynamic(["—"])
    by SourceIP = RemoteIP
| where FailedAttempts >= 10
| extend Surface = "Endpoint (RDP/SSH)";
union EntraSpray, EndpointBrute
| order by TargetUsers desc, FailedAttempts desc
| take 15
```

**Purpose:** Detects password spray (1 IP → many users, MITRE T1110.003) and brute-force (1 IP → high failure count, T1110.001) across two surfaces:
- **Entra ID:** Uses `EntraIdSignInEvents` (Advanced Hunting) which merges interactive + non-interactive sign-ins into a single table, providing broader coverage than SigninLogs alone. Error codes: 50126=bad password, 50053=locked account, 50057=disabled account. An IP targeting ≥5 distinct users with these errors is a strong spray signal. `Protocols` reveals if legacy auth (POP/IMAP/SMTP) is being targeted.
- **Endpoint:** RDP (`RemoteInteractive`) and SSH/SMB (`Network`) failed logons on MDE-enrolled devices. Threshold of ≥10 failures catches brute-force against exposed endpoints.

**Verdict logic:**
- 🔴 Escalate: Any IP targeting >25 Entra users OR >100 endpoint failures from a single IP
- 🟠 Investigate: Any spray/brute-force pattern detected (meets thresholds)
- 🟡 Monitor: Spray activity detected but below thresholds (e.g., single IP with 3–4 target users, or <10 endpoint failures)
- ✅ Clear: 0 results — no spray/brute-force patterns detected

**Drill-down:** Use `user-investigation` skill for targeted users, `ioc-investigation` for source IPs.

---

### Query 5: SPN Behavioral Drift (90d Baseline vs 7d Recent)

🤖 **Automation monitoring** — Composite drift score across 5 dimensions for service principals.

**Tool:** `mcp_sentinel-data_query_lake` (needs >30d lookback)

```kql
let BL_Start = ago(97d); let BL_End = ago(7d);
let RC_Start = ago(7d); let RC_End = now();
let BL = AADServicePrincipalSignInLogs
| where TimeGenerated between (BL_Start .. BL_End)
| summarize 
    BL_Vol = count(),
    BL_Res = dcount(ResourceDisplayName),
    BL_IPs = dcount(IPAddress),
    BL_Loc = dcount(Location),
    BL_Fail = dcountif(ResultType, ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName;
let RC = AADServicePrincipalSignInLogs
| where TimeGenerated between (RC_Start .. RC_End)
| summarize 
    RC_Vol = count(),
    RC_Res = dcount(ResourceDisplayName),
    RC_IPs = dcount(IPAddress),
    RC_Loc = dcount(Location),
    RC_Fail = dcountif(ResultType, ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName;
RC | join kind=inner BL on ServicePrincipalId
| extend 
    VolDrift = round(RC_Vol * 100.0 / max_of(BL_Vol, 10), 0),
    ResDrift = round(RC_Res * 100.0 / max_of(BL_Res, 3), 0),
    IPDrift = round(RC_IPs * 100.0 / max_of(BL_IPs, 3), 0),
    LocDrift = round(RC_Loc * 100.0 / max_of(BL_Loc, 2), 0),
    FailDrift = round(RC_Fail * 100.0 / max_of(BL_Fail, 5), 0)
| extend DriftScore = round((VolDrift*0.20 + ResDrift*0.25 + IPDrift*0.25 + LocDrift*0.15 + FailDrift*0.15), 0)
| where DriftScore > 120
| order by DriftScore desc
| take 10
```

**Purpose:** Identifies service principals with significant behavioral changes from their 90-day baseline. The weighted drift score combines Volume (20%), Resources (25%), IPs (25%), Locations (15%), and Failure Rate (15%). Scores above 150 are flagged, above 250 are critical.

**Verdict logic:**
- 🔴 Escalate: Any SPN with `DriftScore > 250` or `IPDrift > 400%`
- 🟠 Investigate: `DriftScore > 150`
- 🟡 Monitor: `DriftScore 120–150` (minor expansion)
- ✅ Clear: No SPNs above threshold

**Drill-down:** Use `scope-drift-detection/spn` skill for full investigation of flagged SPNs.

---

### Query 6: Fleet-Wide Device Process Drift

💻 **Endpoint behavioral baseline** — Per-device drift scores computed in-query (7d baseline vs 1d recent), returned pre-ranked.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| extend IsRecent = Timestamp >= ago(1d)
| summarize
    BL_Events = countif(not(IsRecent)),
    RC_Events = countif(IsRecent),
    BL_Procs = dcountif(FileName, not(IsRecent)),
    RC_Procs = dcountif(FileName, IsRecent),
    BL_Accts = dcountif(AccountName, not(IsRecent)),
    RC_Accts = dcountif(AccountName, IsRecent),
    BL_Chains = dcountif(strcat(InitiatingProcessFileName, "→", FileName), not(IsRecent)),
    RC_Chains = dcountif(strcat(InitiatingProcessFileName, "→", FileName), IsRecent),
    BL_Comps = dcountif(ProcessVersionInfoCompanyName, not(IsRecent)),
    RC_Comps = dcountif(ProcessVersionInfoCompanyName, IsRecent)
    by DeviceName
| where RC_Events > 0 and BL_Events > 0
| extend
    VolDrift = round(RC_Events * 600.0 / max_of(BL_Events, 1), 0),
    ProcDrift = round(RC_Procs * 100.0 / max_of(BL_Procs, 1), 0),
    AcctDrift = round(RC_Accts * 100.0 / max_of(BL_Accts, 1), 0),
    ChainDrift = round(RC_Chains * 100.0 / max_of(BL_Chains, 1), 0),
    CompDrift = round(RC_Comps * 100.0 / max_of(BL_Comps, 1), 0)
| extend DriftScore = round(VolDrift * 0.30 + ProcDrift * 0.25 + AcctDrift * 0.15 + ChainDrift * 0.20 + CompDrift * 0.10, 0)
| order by DriftScore desc
| take 10
| project DeviceName, DriftScore, VolDrift, ProcDrift, AcctDrift, ChainDrift, CompDrift
```

**Purpose:** Returns the top 10 devices ranked by composite drift score, pre-computed in KQL. No LLM-side math required — just interpret the returned scores.

**Drift formula notes:**
- **Volume (`VolDrift`):** `RC_Events * 600 / BL_Events` — multiplies recent by 600 (= 100 × 6 baseline days) to normalize to a per-day rate before computing the percentage. This is the only metric that needs time normalization because event counts scale linearly with time.
- **Dcount metrics (`ProcDrift`, `AcctDrift`, `ChainDrift`, `CompDrift`):** `RC_Dim * 100 / BL_Dim` — compared directly WITHOUT dividing baseline by 6. Distinct counts do NOT scale linearly with time (seeing 4 unique accounts over 6 days ≠ 0.67 accounts/day). The 6-day baseline captures the "universe" of distinct values; a single day shows what fraction was active. 100% = normal, >100% = new values appeared.
- **Weights:** Volume 30%, Processes 25%, Chains 20%, Accounts 15%, Companies 10%.

**Verdict logic:**
- 🔴 Escalate: Any device with `DriftScore > 250` (major anomaly)
- 🟠 Investigate: Any device with `DriftScore 150–250` (significant deviation)
- 🟡 Monitor: Any device with `DriftScore 120–150` (minor behavioral expansion)
- ✅ Clear: All devices within 80–120 (stable), or fleet is uniform (all scores within 20 points of each other — downgrade one level per fleet-uniformity rule)
- 🔵 Informational: Any device with `DriftScore < 80` (contracting activity — may be idle/decommissioned)

---

### Query 7: Rare Process Chain Singletons

💻 **Threat hunting** — Parent→child process combinations appearing fewer than 3 times in 90 days.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| summarize 
    Count = count(),
    UniqueDevices = dcount(DeviceName),
    SampleDevice = take_any(DeviceName),
    SampleUser = strcat(take_any(AccountDomain), "\\", take_any(AccountName)),
    SampleChildCmd = take_any(ProcessCommandLine),
    GrandparentProcess = take_any(InitiatingProcessParentFileName),
    LastSeen = max(Timestamp)
    by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| where Count < 3
| order by Count asc, UniqueDevices asc
| take 20
```

**Purpose:** Surfaces the 20 rarest process chains — singletons and near-singletons. Effective for spotting LOLBin abuse, malware execution, or novel attack tooling. Review `SampleChildCmd` for suspicious command-line patterns.

**Verdict logic:**
- 🟠 Investigate: Any singleton with suspicious parent (cmd.exe, powershell.exe, wscript.exe, mshta.exe, rundll32.exe) or child running from temp/user profile directories
- 🟡 Monitor: Rare chains from system/update processes (version-stamped binaries, Azure VM agents)
- ✅ Clear: All rare chains are explainable infrastructure artifacts

---

### Query 8: Inbound Email Threat Snapshot

📧 **Email posture** — Single-row summary of inbound email volume, threat breakdown, and delivered threats.

**Tool:** `RunAdvancedHuntingQuery`

```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| summarize
    TotalInbound = count(),
    Clean = countif(isempty(ThreatTypes)),
    Phish = countif(ThreatTypes has "Phish"),
    Malware = countif(ThreatTypes has "Malware"),
    Spam = countif(ThreatTypes has "Spam"),
    HighConfPhish = countif(ConfidenceLevel has "High" and ThreatTypes has "Phish"),
    Blocked = countif(DeliveryAction == "Blocked"),
    Delivered = countif(DeliveryAction == "Delivered"),
    PhishDelivered = countif(ThreatTypes has "Phish" and DeliveryAction == "Delivered"),
    DistinctSenders = dcount(SenderFromAddress),
    DistinctRecipients = dcount(RecipientEmailAddress)
```

**Purpose:** Instant C-level email posture briefing. The key escalation metric is `PhishDelivered` — phishing emails that bypassed all protections and reached mailboxes.

**Verdict logic:**
- 🔴 Escalate: `PhishDelivered > 5` or `Malware > 0` delivered
- 🟠 Investigate: `PhishDelivered > 0` (any phishing reached mailboxes)
- 🟡 Monitor: Phishing detected but 100% blocked/junked
- ✅ Clear: 0 phishing, 0 malware

**Drill-down:** Use `email-threat-posture` skill for full email security analysis including ZAP, Safe Links, and authentication breakdown.

---

### Query 9: Cloud App Suspicious Activity

🔑 **Cloud ops monitoring** — Detects mailbox rule manipulation, transport rule changes, mailbox delegation, and programmatic mailbox access via CloudAppEvents.

**Tool:** `RunAdvancedHuntingQuery`

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "New-InboxRule", "Set-InboxRule",
    "Set-Mailbox",
    "Add-MailboxPermission",
    "New-TransportRule", "Set-TransportRule",
    "New-Mailbox"
)
| summarize
    Count = count(),
    LatestTime = max(Timestamp),
    SampleTargets = make_set(ObjectName, 3)
    by ActionType, AccountDisplayName
| order by Count desc
| take 20
```

**Purpose:** Surfaces cloud app activity that Q10 (AuditLogs) cannot see — mailbox rule creation/modification (T1114.003 email exfiltration via forwarding), transport rule changes (org-wide mail routing manipulation), mailbox permission grants (delegate access abuse), and new mailbox creation.

**Verdict logic:**
- 🔴 Escalate: `New-InboxRule` or `Set-InboxRule` with forwarding targets to external domains
- 🟠 Investigate: Any `New-TransportRule` / `Set-TransportRule` (org-wide impact); `Add-MailboxPermission` from non-admin accounts
- 🟡 Monitor: `Set-Mailbox` changes
- ✅ Clear: 0 results — none of these high-signal operations occurred

**Drill-down:** Use `user-investigation` skill for actors performing suspicious mailbox operations.

---

### Query 10: High-Impact Privileged Operations

🔑 **Admin activity monitoring** — Recent high-privilege operations: role assignments, credential additions, consent grants, CA policy changes, password resets.

**Tool:** `mcp_sentinel-data_query_lake`

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("role", "credential", "consent", "Conditional Access", "password", "certificate")
| where Result == "success"
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend Target = tostring(parse_json(tostring(TargetResources[0])).displayName)
| summarize 
    Count = count(),
    Operations = make_set(OperationName, 5),
    Targets = make_set(Target, 5),
    LatestTime = max(TimeGenerated)
    by Actor
| order by Count desc
| take 15
```

**Purpose:** Shows who's been performing privileged admin operations. Unexpected actors or unusual volume (e.g., 36 password resets from one user in a week) warrant investigation. System-initiated operations (empty Actor) are normal PIM lifecycle events.

**Verdict logic:**
- � Escalate: Credential/consent/CA policy changes from unexpected actors, or bulk password resets from a single user
- �🟠 Investigate: Unexpected user appearing as Actor; high-volume single-user operations
- 🟡 Monitor: Normal PIM/system operations; expected admin activity
- ✅ Clear: Only system-driven operations with expected volume

---

### Query 11: Internet-Facing Critical Assets with Vulnerability Exposure

🛡️ **Attack surface** — ExposureGraph snapshot of critical assets, flagging internet exposure and RCE/PrivEsc vulnerabilities.

**Tool:** `RunAdvancedHuntingQuery`

```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| extend rawData = parse_json(tostring(parse_json(tostring(NodeProperties)).rawData))
| extend critLevel = toint(rawData.criticalityLevel.criticalityLevel)
| where isnotnull(critLevel) and critLevel < 4
| extend IsInternetFacing = tobool(rawData.IsInternetFacing) or tobool(rawData.exposedToInternet)
| extend VulnRCE = tobool(rawData.highRiskVulnerabilityInsights.vulnerableToRemoteCodeExecution)
| extend VulnPrivEsc = tobool(rawData.highRiskVulnerabilityInsights.VulnerableToPrivilegeEscalation)
| project 
    DeviceName = NodeName,
    CriticalityLevel = critLevel,
    IsInternetFacing,
    VulnRCE,
    VulnPrivEsc,
    NodeLabel
| order by IsInternetFacing desc, CriticalityLevel asc
| take 25
```

**Purpose:** Returns the critical asset inventory (criticality 0–3) with internet-facing status and vulnerability flags. An internet-facing critical asset with RCE vulnerability is the highest-priority finding in this entire skill.

**Verdict logic:**
- 🔴 Escalate: Any `IsInternetFacing == true` AND (`VulnRCE == true` or `VulnPrivEsc == true`)
- 🟠 Investigate: Any `IsInternetFacing == true` (without known vulns)
- 🟡 Monitor: Critical assets exist but none internet-facing
- ✅ Clear: All critical assets properly segmented, no internet exposure

---

### Query 12: Exploitable CVEs (CVSS ≥ 8.0) Across Fleet

🛡️ **Vulnerability patch priority** — Top exploitable critical CVEs with affected device count.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner DeviceTvmSoftwareVulnerabilitiesKB on CveId
| where IsExploitAvailable == true
| where CvssScore >= 8.0
| summarize 
    AffectedDevices = dcount(DeviceName),
    SampleDevices = make_set(DeviceName, 3),
    Software = make_set(SoftwareName, 3)
    by CveId, VulnerabilitySeverityLevel, CvssScore
| order by AffectedDevices desc, CvssScore desc
| take 15
```

**Purpose:** Instant "what should we patch today" list. Ranks exploitable CVEs by fleet impact (devices affected × CVSS severity). Focus on CVEs with public exploits affecting the most devices.

**Verdict logic:**
- 🔴 Escalate: Any CVE with `CvssScore >= 9.0` AND `AffectedDevices > 10`
- 🟠 Investigate: CVE with `CvssScore >= 8.0` AND `AffectedDevices > 5`
- 🟡 Monitor: Exploitable CVEs exist but affect < 5 devices
- ✅ Clear: No exploitable CVEs with CVSS ≥ 8.0 (unlikely but possible in small environments)

**Drill-down:** Use `exposure-investigation` skill for full vulnerability posture assessment.

---

## Post-Processing

### Device Drift Score Interpretation (Q6)

Q6 returns pre-computed drift scores directly from KQL — **no LLM-side math is needed**. Simply present the returned table and apply verdicts using this scale:

| DriftScore | Interpretation | Verdict |
|------------|---------------|--------|
| < 80 | Contracting activity (device may be idle/decommissioned) | 🔵 Informational |
| 80–120 | Stable (normal operating range) | ✅ Clear |
| 120–150 | Minor behavioral expansion | 🟡 Monitor |
| 150–250 | Significant deviation | 🟠 Investigate |
| 250+ | Major anomaly — immediate investigation | 🔴 Escalate |

**Fleet-wide context:** If ALL devices show similar scores (e.g., all between 80–120 or all between 120–150), the fleet is behaving uniformly and the verdict should be downgraded one level. Drift is most meaningful when individual devices diverge from the fleet average.

**⛔ DO NOT manually recompute drift scores.** The KQL query handles Volume normalization (÷6 baseline days) and dcount comparison (direct ratio). Trust the returned `DriftScore` column.

### Cross-Query Correlation

After all queries complete, check these correlation patterns and escalate priority when found:

| Pattern | Queries | Implication | Action |
|---------|---------|-------------|--------|
| Same user in anomalies AND risky sign-ins | Q2 + Q3 | Corroborated identity compromise signal | Escalate to 🔴 |
| SPN drift AND unusual credential/consent activity | Q5 + Q9 | App credential abuse / persistence | Escalate to 🔴 |
| Device with rare process chain AND exploitable CVE | Q7 + Q12 | Potential active exploitation | Escalate to 🔴 |
| Incident entity matches anomaly/risk user | Q1 + Q2/Q3 | Known incident may be expanding | Link findings in report |
| Closed TP tactics match active findings | Q1b + Q2/Q3/Q7/Q8 | Same attack pattern recurring despite recent closures | Escalate to 🟠, note recurrence |
| Spray IP overlaps with anomaly/risk user | Q4 + Q2/Q3 | Spray target already flagged by Identity Protection | Escalate to 🔴 |
| Mailbox rule manipulation AND email threats | Q9 + Q8 | Potential email exfiltration setup following phishing | Escalate to 🔴 |

---

## Query File Recommendations

Search the `queries/` library for hunting campaigns targeting TTPs surfaced by today's scan. Tier depth follows the Rule 9 table — skip entirely when all verdicts are ✅.

### Keyword Extraction Rules

Extract search keywords from findings in domains that received a non-✅ verdict. For 🔴/🟠 use all listed keywords; for 🟡-only use the **bold** domain keyword.

| Finding Source | Keywords |
|---------------|---------|
| Q1/Q1b (Incidents) | **"incident"**, MITRE tactic names, alert titles |
| Q2/Q2b (Identity) | **"identity"**, "anomaly", "sign-in", "phishing" if geo-novelty |
| Q3 (Identity Protection) | **"risky sign-in"**, "token", "aitm", "phishing" if in risk detail |
| Q4 (Auth Spray) | **"password spray"**, "brute force", "RDP", "credential" |
| Q5 (SPN Drift) | **"service principal"**, "app registration", "credential" |
| Q6/Q7 (Endpoint) | **"process"**, singleton process names (mimikatz, rclone, psexec), "rare process" |
| Q8 (Email) | **"phishing"**, "email", "spam", "malware" if delivered threats > 0 |
| Q9/Q10 (Admin & Cloud) | **"admin"**, ActionType values (New-InboxRule, New-TransportRule, etc.) |
| Q11/Q12 (Exposure) | **"vulnerability"**, specific CVE IDs, software names |

### Proactive Skill Suggestions (🟡-only supplement)

When the highest verdict is 🟡, supplement query file results with up to **3** posture skill suggestions from the most relevant 🟡 domains:

| Domain | Skill | Prompt |
|--------|-------|--------|
| Q1/Q1b (Incidents) | `incident-investigation` | "Triage the oldest open incident to review classification" |
| Q2/Q2b, Q3 (Identity) | `identity-posture` | "Run identity posture report for account hygiene and privilege review" |
| Q4 (Auth Spray) | `ioc-investigation` | "Enrich the top spray source IP for threat intel context" |
| Q5 (SPN Drift) | `app-registration-posture` | "Run app registration posture audit for SPN hygiene and overprivilege detection" |
| Q6, Q7 (Endpoint) | `computer-investigation` | "Investigate the top drifting device for process and network activity" |
| Q8 (Email) | `email-threat-posture` | "Run full email threat posture report for delivery and protection gaps" |
| Q9, Q10 (Admin & Cloud) | `user-investigation` | "Investigate the most active admin user for full activity review" |
| Q11, Q12 (Exposure) | `exposure-investigation` | "Run org-wide vulnerability report" |

### Search Procedure

1. Collect keywords from non-✅ domains using the extraction rules above (🔴/🟠: all keywords; 🟡-only: bold domain keywords)
2. Run `grep_search` with each keyword (or combined with `|` alternation) scoped to `queries/**`
3. Deduplicate matched files — a file matching multiple keywords ranks higher
4. Read the first 10 lines of each matched file to extract the `# Title` from line 1 of the metadata header — this becomes the clickable link display text
5. Select the **top N most relevant** files (🔴/🟠: 3–5 files; 🟡-only: 1–2 files), ranked by keyword matches
6. **Format each file as a clickable markdown link:** `[<Title from step 4>](queries/<subfolder>/<filename>.md)` — plain text or backtick-wrapped paths are PROHIBITED
7. **🟡-only:** Also select up to 3 proactive skill suggestions from the table above for the most relevant 🟡 domains

### Report Output Block

Insert this section between **Recommended Actions** and **Appendix** in both inline and file reports.

**⛔ CRITICAL: Use numbered list format, NOT a table.** Markdown links inside table cells do not render as clickable in VS Code chat. The numbered list format below is the ONLY permitted layout.

```markdown
## 📂 Recommended Query Files for Follow-Up Hunting

<If matching query files found:>

Based on today's findings, these query files contain pre-built hunting campaigns targeting related TTPs:

1. **[<Title>](queries/<subfolder>/<filename>.md)**
   — Q<N>: <finding summary>
   — 💡 *"<Dynamic prompt derived from the specific finding — reference the entity, TTP, or IOC from the query results>"*

2. **[<Title>](queries/<subfolder>/<filename>.md)**
   — Q<N>: <finding summary>
   — 💡 *"<Dynamic prompt derived from the specific finding>"*

...

> **After the report renders, you will be presented with a selectable list of these campaigns to launch directly.**

<If no matching query files found:>

📂 No matching query files found for today's findings. Consider authoring new hunting queries:
> *"Read this threat intel article: <URL> — extract TTPs and IOCs, then write, test, and tune a queries file for reusable threat hunts"*
```

**Dynamic prompt generation rules:**
- Each follow-up prompt MUST reference specific entities, IOCs, or TTPs from the Threat Pulse findings that triggered the query file match
- Use the actual values from query results (usernames, IPs, CVE IDs, process names, SPN names, ActionTypes) — not generic placeholders
- The prompt should ask for a focused investigation, not a broad sweep

**Examples of dynamic prompts (for reference — do NOT use these verbatim):**

| Finding Source | Example Dynamic Prompt |
|---------------|----------------------|
| Q4 found spray from 203.0.113.42 | *"Hunt for all activity from IP 203.0.113.42 — check lateral movement, successful auth, and any post-compromise behavior"* |
| Q7 found singleton `wscript.exe→certutil.exe` | *"Hunt for certutil.exe abuse patterns — LOLBin download, encode/decode, and any files written to temp directories"* |
| Q9 found `New-InboxRule` by user@domain.com | *"Hunt for email exfiltration patterns by user@domain.com — forwarding rules, mailbox delegation, and OAuth app grants"* |
| Q12 found CVE-2024-1234 on 15 devices | *"Run the vulnerability hunting queries against CVE-2024-1234 — check for active exploitation attempts and lateral movement from affected devices"* |

### 🔴 MANDATORY: Clickable File Links

**Every query file reference in this section MUST be a clickable markdown link using workspace-relative paths.** The user needs to click the link to instantly add the file as context in a follow-up chat.

**⛔ NEVER use a markdown table for this section.** Links inside table cells do not render as clickable in VS Code chat. Always use a **numbered list** with bold link text and a description line underneath.

| Requirement | Example |
|-------------|---------|
| **Correct** — numbered list with bold link | `1. **[Rare Parent–Child Process Chain Detection](queries/endpoint/rare_process_chains.md)**` followed by `   — Q5: singleton process chains` on next line |
| ❌ **PROHIBITED** — table with link | `\| [Title](path) \| relevance \| findings \|` |
| ❌ **PROHIBITED** — plain text file name | `queries/endpoint/rare_process_chains.md` |
| ❌ **PROHIBITED** — backtick-wrapped file name | `` `queries/endpoint/rare_process_chains.md` `` |
| ❌ **PROHIBITED** — title without link | `Rare Parent–Child Process Chain Detection` |

**Rules:**
- Link display text = the file's `# Title` from line 1 of the metadata header
- Link target = workspace-relative path (e.g., `queries/endpoint/rare_process_chains.md`)
- Use forward slashes `/` only — no backslashes
- The link MUST render as clickable in VS Code chat so the user can open the file in one click
- If Step 4 of the Search Procedure reads the file title, use that exact title as the display text

---

## Output Modes

### Mode 1: Inline Chat Summary

Render the full Threat Pulse Dashboard directly in the chat response. Best for quick daily checks, SOC standup briefings, or when you need a quick status scan.

### Mode 2: Markdown File Report

Save a comprehensive report to disk at:
```
reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md
```

### Mode 3: Both

Generate the markdown file AND provide an inline summary in chat.

**Always ask the user which mode before generating output. Default to Mode 1 (inline) if user says "just run it".**

---

## Inline Report Template

Render the following sections in order. Omit sections only if explicitly noted as conditional.

> **🔴 URL Rule:** All hyperlinks in the report MUST be copied verbatim from the [URL Registry](#-url-registry--canonical-links-for-report-generation) above. Do NOT generate, recall from memory, or paraphrase any URL.

````markdown
# 🔍 Threat Pulse — <WorkspaceName> | <YYYY-MM-DD>

**Generated:** <YYYY-MM-DD HH:MM> UTC
**Workspace:** <WorkspaceName> (`<WorkspaceId>`)
**Scan Duration:** ~<N>s | **Queries:** 13 | **Domains:** 9

---

## Dashboard Summary

| # | Domain | Status | Key Finding |
|---|--------|--------|-------------|
| Q1 | 🔴 **Incidents** | <verdict> | <1-line finding — includes Q1b closed summary context> |
| Q2 | 🔐 **Sign-In Anomalies** | <verdict> | <1-line finding> |
| Q3 | 🔐 **Identity Protection** | <verdict> | <1-line finding> |
| Q4 | 🔐 **Auth Spray** | <verdict> | <1-line finding> |
| Q5 | 🤖 **SPN Drift** | <verdict> | <1-line finding> |
| Q6 | 💻 **Device Drift** | <verdict> | <1-line finding> |
| Q7 | 💻 **Rare Processes** | <verdict> | <1-line finding> |
| Q8 | 📧 **Email Threats** | <verdict> | <1-line finding> |
| Q9 | 🔑 **Cloud App Ops** | <verdict> | <1-line finding> |
| Q10 | 🔑 **Privileged Ops** | <verdict> | <1-line finding> |
| Q11 | 🛡️ **Critical Assets** | <verdict> | <1-line finding> |
| Q12 | 🛡️ **Exploitable CVEs** | <verdict> | <1-line finding> |

<Where verdict is one of: 🔴 Escalate | 🟠 Investigate | 🟡 Monitor | ✅ Clear | ❓ No Data>

---

## Detailed Findings

<For each query with results (skip empty sections is PROHIBITED — every query gets a section):>

### <emoji> Q<N> — <Domain Name> (<lookback>)

<If results found:>

| <columns from query> |
|---|
| <data rows, max 10 for inline> |

**Q1 column format (mandatory):**

| Incident | Title | Age (days) | Alerts | Owner | Tactics |

Where **Incident** renders the XDR portal link: `[XDR #<ProviderIncidentId>](https://security.microsoft.com/incidents/<ProviderIncidentId>)`. Do NOT use raw `ProviderIncidentId` as a column header — always display as `Incident`. Unassigned incidents show `⚠️ Unassigned` in the Owner column.

**Q1b closed summary (always render after Q1 results, even when Q1 is ✅ Clear):**

**7-Day Closed Incident Summary** (<Total> closed)

| Classification | Count |
|---|---|
| TruePositive | <N> |
| BenignPositive | <N> |
| FalsePositive | <N> |
| Undetermined | <N> |

**Severity:** <HighCritical> High/Critical, <MediumLow> Medium/Low
**Active MITRE Tactics (from TP closures):** <comma-separated tactic names, or "None" if 0 TPs>

<If 0 closed incidents in 7d:>
No incidents closed in the last 7 days.

<Contextual analysis with emoji-coded risk assessment>

<If 0 results:>

✅ No <finding type> detected in the last <lookback>.
- Checked: <table name> (0 matches)

---

## Cross-Query Correlations

<If correlations found between queries per the Post-Processing rules:>

| Pattern | Evidence | Escalation |
|---------|----------|------------|
| <description> | Q<N> user X also in Q<M> | 🔴 Priority upgraded |

<If no correlations:>

✅ No cross-domain correlations detected across query results.

---

## 🎯 Recommended Actions

| Priority | Action | Trigger | Deep-Dive Skill |
|----------|--------|---------|-----------------|
| 🔴 **1** | <action> | Q<N>: <evidence> | `<skill-name>` |
| 🟠 **2** | <action> | Q<N>: <evidence> | `<skill-name>` |
| 🟡 **3** | <action> | Q<N>: <evidence> | `<skill-name>` |

<Recommendations MUST reference specific query findings and name the skill for drill-down.>

---

## 📂 Recommended Query Files for Follow-Up Hunting

<If any 🔴/🟠 verdicts exist: Render the full section per the Query File Recommendations procedure.>

<If highest verdict is 🟡 (no 🔴/🟠): Render a lighter section titled "📂 Proactive Hunting Suggestions" instead:>

📂 Proactive Hunting Suggestions

No findings crossed escalation thresholds today, but these domains showed activity worth a broader look:

1. **Proactive skill:** `<skill-name>` — *"<prompt from Proactive Skill Mapping table>"*
2. **[<Query File Title>](queries/<subfolder>/<filename>.md)** — *"<broader hunting prompt based on 🟡 domain keywords>"*

> **Smaller environments often benefit from running posture assessments proactively** — the skills above provide full-domain visibility even when individual signals stay below alert thresholds.

<If all verdicts are ✅: Omit the section entirely.>

---

## Appendix: Query Execution Summary

| Query | Domain | Records | Data Source | Notes |
|-------|--------|---------|-------------|-------|
| Q1 | Incidents (open) | <N> | Data Lake | |
| Q1b | Incidents (closed 7d) | <N> | Data Lake | Classification: <TP/BP/FP/Undetermined counts> |
| Q2/Q2b | Identity Anomalies | <N> | Data Lake | <"Custom table" or "Identity Protection fallback"> |
| Q3 | Identity Protection | <N> | Data Lake | |
| Q4 | Auth Spray | <N> | Advanced Hunting | Entra ID + Endpoint surfaces |
| Q5 | SPN Drift | <N> | Data Lake | <N SPNs above threshold> |
| Q6 | Device Drift | 10 | Advanced Hunting | Pre-ranked top 10 by DriftScore |
| Q7 | Rare Processes | <N> | Advanced Hunting | |
| Q8 | Email Threats | 1 | Advanced Hunting | Single-row aggregate |
| Q9 | Cloud App Ops | <N> | Advanced Hunting | CloudAppEvents suspicious activity |
| Q10 | Privileged Ops | <N> | Data Lake | |
| Q11 | Critical Assets | <N> | Advanced Hunting | <N internet-facing> |
| Q12 | Exploitable CVEs | <N> | Advanced Hunting | |
````

---

## Markdown File Report Template

When outputting to markdown file, use the same structure as the Inline Report Template above, saved to:

```
reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md
```

Include the following additional sections in the file report that are omitted from inline:

1. **Full data tables** — No row limits (inline caps at 10 rows per table; file includes all results)
2. **Device Drift Score Table** — Full ranked list of all devices with computed drift scores
3. **Rare Process Chain Details** — Full command-line samples for all 20 singletons
4. **CVE Detail Table** — All 15 CVEs with affected device lists

---

## Known Pitfalls

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| `Signinlogs_Anomalies_KQL_CL` doesn't exist | Q2 fails | Silently fall back to Q2b (Identity Protection) |
| `SecurityAlert.Status` is always "New" | Misleading incident triage | Q1 joins SecurityIncident for real Status |
| `BehaviorInfo` / `BehaviorEntities` trigger AH MCP safety filter | Q9 query cancelled by tool | Replaced with `CloudAppEvents` query — BehaviorInfo tables removed from skill |
| `ExposureGraphNodes.NodeProperties` requires double `parse_json()` | Null values if single parse | Q11 uses `parse_json(tostring(parse_json(...)))` pattern |
| Q5 (SPN drift) takes ~35s due to 97d lookback | Slow query | Acceptable — runs in parallel with other Data Lake queries |
| `DeviceTvmSoftwareVulnerabilities` is AH-only | Data Lake returns "table not found" | Q12 must use `RunAdvancedHuntingQuery` |
| `EmailEvents` uses `Timestamp` not `TimeGenerated` | SemanticError if wrong column | Q8 uses `Timestamp` (XDR-native table) |
| `CloudAppEvents` uses `Timestamp` in AH, `TimeGenerated` in Data Lake | SemanticError if wrong column | Q9 uses `Timestamp` (AH execution) |
| `AuditLogs.InitiatedBy` is a dynamic field | `has` operator fails without `tostring()` | Q10 uses `parse_json(tostring(...))` pattern |
| Q6 drift scores | Previously required LLM-side math, causing reasoning overhead | Drift scores now computed in-query; LLM only interprets returned `DriftScore` column |

---

## Quality Checklist

Before rendering the final report, verify:

- [ ] All 13 queries executed (Q1 + Q1b + Q2–Q12, or fallback used for Q2)
- [ ] Every domain has a verdict row in the Dashboard Summary (no omissions)
- [ ] Every ✅ Clear verdict cites the specific table queried and "0 results"
- [ ] Every 🔴/🟠 verdict cites specific evidence (counts, names, scores)
- [ ] All incidents include clickable `https://security.microsoft.com/incidents/{ProviderIncidentId}` URLs
- [ ] Cross-query correlations checked (minimum: Q2+Q3 user overlap, Q5+Q9 SPN+CloudApp overlap, Q9+Q8 mailbox+email overlap, Q1b tactics vs active findings)
- [ ] Recommended Actions table includes at least 1 item per 🔴/🟠 domain
- [ ] Each recommendation references a specific drill-down skill
- [ ] Q2b fallback noted in report if custom table was unavailable
- [ ] No fabricated data — all findings trace to actual query results
- [ ] **⛔ Query file recommendations:** If ANY verdict is 🔴 or 🟠, the `📂 Recommended Query Files` section MUST appear in the report with at least one matched file or the "no matching files" template. If highest verdict is 🟡, the `📂 Proactive Hunting Suggestions` section MUST appear. Rendering a report with non-✅ verdicts but NO recommendations section is **PROHIBITED**.
- [ ] **⛔ Query file links are clickable:** Every query file in the `📂 Recommended Query Files` table MUST be a clickable markdown link `[Title](queries/subfolder/file.md)` — NOT plain text, NOT backtick-wrapped. The user must be able to click the link to open the file and add it as context to a follow-up chat.

---

## SVG Dashboard Generation

After completing the Threat Pulse report, the user may request an SVG visualization. Use the `svg-dashboard` skill in **manifest mode** — the widget manifest is at `.github/skills/threat-pulse/svg-widgets.yaml`.

### Execution

1. Read `svg-widgets.yaml` (widget manifest)
2. Read the `svg-dashboard` SKILL.md for component rendering rules
3. Map manifest `field` values to the Threat Pulse report data already in context (or read the saved report file)
4. Render SVG → save to `temp/threat_pulse_{date}_dashboard.svg`
