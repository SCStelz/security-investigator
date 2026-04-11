---
name: threat-pulse
description: 'Recommended starting point for new users and daily SOC operations. Quick 15-minute security posture scan across 9 domains: active incidents, identity (human + NonHuman), device process drift, rare process chains, email threats, admin & cloud ops, critical asset exposure, and exploitable CVEs. 12 queries executed in parallel batches, producing a prioritized Threat Pulse Dashboard with color-coded verdicts (🔴 Escalate / 🟠 Investigate / 🟡 Monitor / ✅ Clear) and drill-down recommendations pointing to specialized skills. Trigger on getting-started questions like "what can you do", "where do I start", "help me investigate". Supports inline chat and markdown file output'
---

# Threat Pulse — Instructions

## Purpose

The Threat Pulse skill is a rapid, broad-spectrum security scan designed for the "if you only had 15 minutes" scenario. It executes 12 queries across 9 security domains in parallel, producing a prioritized dashboard of findings with drill-down recommendations to specialized investigation skills.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔴 **Incidents** | What high-severity incidents are open and unresolved? How old are they? Who owns them? What was recently resolved — TP rate, MITRE tactics, severity distribution? |
| 🔐 **Identity (Human)** | Which users are flagged as risky by Identity Protection? What risk events (sign-in-level and user-level AI signals) are driving the risk? Are there password spray / brute-force patterns? |
| 🤖 **Identity (NonHuman)** | Which service principals expanded their resource/IP/location footprint? |
| 💻 **Endpoint** | Which endpoints deviated most from their process behavioral baseline? What singleton process chains exist? |
| 📧 **Email Threats** | What's the phishing/spam/malware breakdown? Were any phishing emails delivered? |
| 🔑 **Admin & Cloud Ops** | What mailbox rules, OAuth consents, transport rules, or mailbox permission changes occurred? Who performed high-impact admin operations? |
| 🛡️ **Exposure** | Are any critical assets internet-facing with RCE vulnerabilities? What exploitable CVEs (CVSS ≥ 8) are present across the fleet? |

**Data sources:** `SecurityIncident`, `SecurityAlert`, `IdentityInfo`, `AADUserRiskEvents`, `EntraIdSignInEvents`, `DeviceProcessEvents`, `DeviceLogonEvents`, `ExposureGraphNodes`, `AADServicePrincipalSignInLogs`, `EmailEvents`, `CloudAppEvents`, `AuditLogs`, `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB`

### 🔴 URL Registry

**MANDATORY:** Copy URLs verbatim. NEVER construct or paraphrase.

| Label | URL |
|-------|-----|
| `XDR_INCIDENT_BASE` | `https://security.microsoft.com/incidents/` |
| `DOCS_SECURITY_INCIDENT` | `https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference#securityincident` |
| `DOCS_ADVANCED_HUNTING` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview` |
| `DOCS_IDENTITY_PROTECTION` | `https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection` |
| `DOCS_EXPOSURE_MANAGEMENT` | `https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph` |
| `DOCS_TVM` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table` |
| `DOCS_EMAIL_EVENTS` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table` |
| `DOCS_CLOUD_APP_EVENTS` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table` |

Incidents: `XDR_INCIDENT_BASE` + `ProviderIncidentId`.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)**
2. **[Execution Workflow](#execution-workflow)**
3. **[Sample KQL Queries](#sample-kql-queries)** — 12 queries
4. **[Post-Processing](#post-processing)** — Drift scores, cross-query correlation
5. **[Query File Recommendations](#query-file-recommendations)**
6. **[Report Template](#report-template)** — Dashboard format
7. **[Known Pitfalls](#known-pitfalls)**
8. **[SVG Dashboard Generation](#svg-dashboard-generation)**

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Workspace selection** — Follow the SENTINEL WORKSPACE SELECTION rule from `copilot-instructions.md`. Call `list_sentinel_workspaces()` before first query.

2. **Read `config.json`** — Load workspace ID, tenant, subscription, and Azure MCP parameters before execution.

3. **Output defaults** — Default to **inline chat** with **7d lookback**. Only ask the user for output preferences if they explicitly mention a different mode (e.g., "save to file", "markdown report", "30 day lookback"). If the user just says "threat pulse", "run a scan", or similar — proceed immediately with defaults, do not prompt.

4. **⛔ MANDATORY: Evidence-based analysis only** — Every finding must cite query results. Every "clear" verdict must cite 0 results. Follow the Evidence-Based Analysis rule from `copilot-instructions.md`.

5. **Parallel execution** — Run the Data Lake query (Q5) and all Advanced Hunting queries (Q1, Q1b, Q2, Q4, Q6, Q7, Q8, Q9, Q10, Q11, Q12) simultaneously.

6. **Cross-query correlation** — After all queries complete, check for correlated findings:
   - SPN drift (Q5) + unusual credential/consent activity (Q9) → escalate priority
   - Device in rare process chains (Q7) + device in CVE list (Q12) → escalate priority
   - Incident entities (Q1) matching users in Q2 → link findings

7. **SecurityIncident output rule** — Every incident MUST include a clickable Defender XDR portal URL: `https://security.microsoft.com/incidents/{ProviderIncidentId}`.

8. **⛔ MANDATORY: Query File Recommendations (tiered)** — After assigning verdicts and BEFORE rendering the final report, execute the [Query File Recommendations](#query-file-recommendations) procedure. Skip only when ALL verdicts are ✅.

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

Executing 12 queries across 9 domains:
  🔴 Incidents      — Open high-severity + 7d closed summary (Q1, Q1b)
  🔐 Identity       — Identity risk posture, risk event enrichment, auth spray (Q2, Q4)
  🤖 NonHuman ID    — Service principal behavioral drift (Q5)
  💻 Endpoint       — Device process drift, rare process chains (Q6, Q7)
  📧 Email          — Inbound threat snapshot (Q8)
  🔑 Admin & Cloud  — Cloud app ops, privileged operations (Q9, Q10)
  🛡️ Exposure       — Critical assets, exploitable CVEs (Q11, Q12)

Data Lake: 1 query | Advanced Hunting: 11 queries in parallel
Estimated time: ~2–4 minutes
```

### Phase 1: Data Lake Query (Q5)

> **Why only 1 query on Data Lake?** Q5 requires a 97-day lookback for SPN baseline computation — AH Graph API caps at 30 days. All other queries use ≤30d lookback on Analytics-tier tables accessible via AH.

| Query | Domain | Purpose | Tool |
|-------|--------|---------|------|
| Q5 | 🤖 Identity (NonHuman) | Service principal behavioral drift (90d vs 7d) | `query_lake` |

### Phase 2: Advanced Hunting Queries (Q1, Q1b, Q2, Q4, Q6, Q7, Q8, Q9, Q10, Q11, Q12)

**Run all 11 in parallel — no dependencies between queries.**

> **Design rationale:** The connected LA workspace makes all Sentinel tables (SecurityIncident, IdentityInfo, AADUserRiskEvents, AuditLogs, etc.) queryable via AH. AH is preferred: it's free for Analytics-tier tables and avoids per-query Data Lake billing.

| Query | Domain | Purpose | Tool |
|-------|--------|---------|------|
| Q1 | 🔴 Incidents | Open High/Critical incidents with MITRE tactics | `RunAdvancedHuntingQuery` |
| Q1b | 🔴 Incidents | 7-day closed incident summary (classification, MITRE, severity) | `RunAdvancedHuntingQuery` |
| Q2 | 🔐 Identity (Human) | Identity risk posture (IdentityInfo) + risk event enrichment (AADUserRiskEvents) | `RunAdvancedHuntingQuery` |
| Q4 | 🔐 Identity (Human) | Password spray / brute-force across Entra ID + RDP/SSH | `RunAdvancedHuntingQuery` |
| Q6 | 💻 Endpoint | Fleet device process drift (7d baseline vs 1d) | `RunAdvancedHuntingQuery` |
| Q7 | 💻 Endpoint | Rare process chain singletons (30d) | `RunAdvancedHuntingQuery` |
| Q8 | 📧 Email | Inbound email threat snapshot | `RunAdvancedHuntingQuery` |
| Q9 | 🔑 Admin & Cloud Ops | Cloud app suspicious activity (CloudAppEvents) | `RunAdvancedHuntingQuery` |
| Q10 | 🔑 Admin & Cloud Ops | High-impact admin operations (AuditLogs) | `RunAdvancedHuntingQuery` |
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
| **Query file hunt** | 📄 | Manifest domain + MITRE matching → query file | `📄 Hunt for RDP lateral movement from 10.0.0.50` → `queries/endpoint/rdp_lateral_movement.md` |
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
   - Skill prompts: one per unique entity + matching skill from the table above. If the same entity appears in multiple queries (e.g., Q2 and Q9), create ONE skill prompt for that entity — the correlation context goes in the Description, not in the Label.
   - Query file prompts: from Phase 3 step 5 keyword extraction. Each query file is its OWN separate prompt — never merge a query file prompt with a skill prompt.
   - IOC prompts: any suspicious IPs/domains from non-✅ findings not already covered by a skill prompt
   - Deduplicate: if a skill prompt and IOC prompt target the same entity, keep only the skill prompt
   - **🔴 NEVER merge a skill prompt (🔍) with a query file prompt (📄) into a single option.** They are different action types with different execution paths.
2. **⛔ VALIDATION GATE — before building options, verify each option is atomic:**
   - Count the action icons (🔍, 📄, 🎯) in each option's Label. If a Label contains **more than one icon**, it is bundled — **split it into separate options immediately**.
   - Count the skill/query file references (→ arrows) in each option. If an option references **more than one skill or query file**, it is bundled — split it.
   - Each Label MUST start with exactly ONE icon and describe exactly ONE action targeting ONE entity or ONE query file. No commas separating multiple actions. No multiple `→` targets.

   Present the pool using the interactive question tool:
   - **Header:** `Follow-Up Investigation`
   - **Question:** `Select an action to launch (or skip):`
   - **Options:** One per prompt — each option is exactly ONE atomic action (one skill + one entity, or one query file + one hunt). Cross-query correlation context goes in the Description, never in the Label.
     - **Label format:** `<ONE icon> <ONE action>` — nothing else. Examples: `🔍 Investigate user jsmith@contoso.com`, `📄 Hunt delivered phishing emails`, `🎯 Investigate IP 203.0.113.42`
     - **Description format:** `Q<N>: <finding summary> → <ONE skill or query file>` (correlation context like `Q2+Q9:` is fine here — it explains WHY, not WHAT to do)
     - **🔴 HARD RULE:** If you find yourself writing a comma or a second icon in a Label, STOP — you are bundling. Split into two options.
   - Penultimate option: **Label:** `💾 Save full investigation report` / **Description:** `Save the complete Threat Pulse session (scan + all drill-downs) as a markdown file`
   - Final option: **Label:** `Skip` / **Description:** `No follow-up — investigation complete`
   - **multiSelect:** `true`
3. If user selects **Skip** (alone) or pool is empty: end skill execution
4. If user's selection includes **💾 Save full investigation report:**
   a. Compile the original Threat Pulse dashboard + all drill-down investigation results accumulated during this session into a single markdown file
   b. Save to `reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md` using the [Markdown File Report Template](#markdown-file-report-template)
   c. Append a `## Drill-Down Investigation Results` section containing the findings from each follow-up action completed during this session, in the order they were executed
   d. Remove the save option from the pool (report already saved). If no other actions were selected alongside it, return to step 2. Otherwise continue to step 5 with the remaining selections.
5. If user selects one or more actions:
   a. Build a **todo list** with one item per selected action, all `not-started`
   b. Execute each action **sequentially** in selection order:
      - **Skill prompt:** load the skill's SKILL.md, execute the investigation with the target entity
      - **Query file prompt:** read the query file, add as context, execute the hunt
      - **IOC prompt:** load `ioc-investigation` skill, execute with the target indicator
      - Mark each todo `completed` as it finishes
   c. Remove all completed prompts from the pool
   d. Scan results for **new evidence** (entities, IOCs, TTPs not in original Threat Pulse results) — generate new prompts if found, prepend to pool with `🆕` tag
   e. **Return to step 2 — call the interactive question tool again.** Every loop iteration MUST use `vscode_askQuestions` to present the updated pool as a selectable list. Do NOT render a markdown table/numbered list as a substitute.

**Prompt pool rules:**
- Completed prompts are removed — never re-offered
- New evidence prompts are prepended (freshest leads first), tagged `🆕`
- Loop ends when user selects Skip or pool empties (`✅ All follow-up actions completed.`)
- **🔴 PROHIBITED:** Rendering the prompt pool as a markdown table, numbered list, or plain text instead of calling `vscode_askQuestions`. Every iteration — including after the first follow-up completes — MUST use the interactive question tool so options are clickable. This is the #1 loop-breaking mistake.
- **🔴 ATOMIC OPTIONS — ONE action per selectable item.** Each option Label MUST contain exactly ONE icon (🔍, 📄, or 🎯) and map to exactly ONE executable action: one skill + one entity, OR one query file + one hunt prompt. When cross-query correlations link multiple findings (e.g., Q2+Q9 correlating a user with both risky identity and inbox rule manipulation), generate **separate options** for each distinct action — do NOT bundle them into a single option. Note the correlation in the **Description** field to preserve context, but keep the Label and action singular.

  **Self-check before presenting:** For each option, verify: (1) the Label has exactly ONE icon prefix, (2) there is NO comma separating a second action, (3) the Description has exactly ONE `→` pointing to ONE skill or query file. If any check fails, split the option.

  **❌ PROHIBITED — bundled multi-action option (this is the #1 follow-up mistake):**
  `🔍 Investigate user cameron@contoso.com - Q2+Q9: mcasSuspiciousInboxManipulationRules + anonymizedIPAddress (5 high) + New-InboxRule creation — potential email exfiltration → user-investigation, 📄 Hunt delivered phishing emails → queries/email/email_threat_detection.md`

  **❌ ALSO PROHIBITED — multiple skills/query files in Description:**
  Description: `Q2+Q9: ... → user-investigation, queries/email/email_threat_detection.md`

  **✅ CORRECT — one action per option, correlation context in Description only:**
  - Option 1 — Label: `🔍 Investigate user cameron@contoso.com` / Description: `Q2+Q9: Identity risk (AtRisk, aiCompoundAccountRisk + anonymizedIPAddress) + inbox rule manipulation — potential email exfiltration → user-investigation`
  - Option 2 — Label: `📄 Hunt delivered phishing emails and recipients` / Description: `Q8: Trace the 4 delivered phishing emails → queries/email/email_threat_detection.md`

---

## Sample KQL Queries

> **All queries below are verified against live Sentinel/Defender XDR schemas. Use them exactly as written. Lookback periods use `ago(Nd)` — substitute the user's preferred lookback where noted.**

### Query 1: Open High-Severity Incidents with MITRE Techniques

🔴 **Incident hygiene** — Surfaces unresolved High/Critical incidents with age, owner, alert count, MITRE tactics, and MITRE technique IDs.

**Tool:** `RunAdvancedHuntingQuery`

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
    | project SystemAlertId, Tactics, Techniques, AlertName, AlertSeverity
) on $left.AlertId == $right.SystemAlertId
| mv-expand Technique = parse_json(Techniques)
| extend Technique = tostring(Technique)
| extend TacticsSplit = split(Tactics, ", ")
| mv-expand Tactic = TacticsSplit
| extend Tactic = tostring(Tactic)
| summarize 
    Tactics = make_set(Tactic),
    Techniques = make_set(Technique),
    AlertNames = make_set(AlertName, 5),
    AlertCount = dcount(AlertId)
    by ProviderIncidentId, Title, Severity, Status, CreatedTime,
       OwnerUPN = tostring(Owner.userPrincipalName)
| extend Techniques = set_difference(Techniques, dynamic([""]))
| extend Tactics = set_difference(Tactics, dynamic([""]))
| extend AgeDays = datetime_diff('day', now(), CreatedTime)
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId)
| order by Severity asc, AgeDays desc
| take 15
```

**Purpose:** Identifies the top 15 open high-severity incidents, ranked by age. Joins SecurityAlert for MITRE tactic and technique ID visibility. Flags unassigned incidents (empty OwnerUPN) and incident age debt (>30 days old).

**Verdict logic:**
- 🔴 Escalate: Any incident with `AgeDays > 30` AND empty `OwnerUPN`
- 🟠 Investigate: Any incident with `AgeDays > 14` or `AlertCount > 10`
- 🟡 Monitor: Open incidents exist but are assigned and recently triaged
- ✅ Clear: 0 open High/Critical incidents (Q1b closed summary still renders as context)

---

### Query 1b: Closed Incident Summary (7-Day Lookback)

🔴 **Threat landscape context** — Even when all incidents are resolved, the classification breakdown, MITRE tactic distribution, and severity mix from recent closures provide actionable signals for cross-correlation and query file recommendations.

**Tool:** `RunAdvancedHuntingQuery`

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
    | project SystemAlertId, Tactics, Techniques
) on $left.AlertId == $right.SystemAlertId
| mv-expand Technique = parse_json(Techniques)
| extend Technique = tostring(Technique)
| extend TacticsSplit = split(Tactics, ", ")
| mv-expand Tactic = TacticsSplit
| extend Tactic = tostring(Tactic)
| summarize
    Total = dcount(IncidentNumber),
    TruePositive = dcountif(IncidentNumber, Classification == "TruePositive"),
    BenignPositive = dcountif(IncidentNumber, Classification == "BenignPositive"),
    FalsePositive = dcountif(IncidentNumber, Classification == "FalsePositive"),
    Undetermined = dcountif(IncidentNumber, Classification == "Undetermined"),
    HighCritical = dcountif(IncidentNumber, Severity in ("High", "Critical")),
    MediumLow = dcountif(IncidentNumber, Severity in ("Medium", "Low")),
    Tactics = make_set(Tactic),
    Techniques = make_set(Technique)
| extend Techniques = set_difference(Techniques, dynamic([""]))
| extend Tactics = set_difference(Tactics, dynamic([""]))
```

**Purpose:** Provides a 7-day closed incident summary with classification breakdown (TP/BP/FP/Undetermined), severity distribution, aggregated MITRE tactics, and aggregated MITRE technique IDs. This data feeds three downstream uses:
1. **TP rate signal** — High TruePositive ratio indicates an active threat environment
2. **MITRE tactic context** — Tactics from closed TPs identify the current threat landscape for cross-correlation with Q2/Q7/Q8 findings
3. **Manifest MITRE matching** — The `Techniques` array contains ATT&CK technique IDs (e.g., `T1566`, `T1078`, `T1059`) directly matchable against manifest entry `mitre` fields. No tactic→technique mapping needed — the technique IDs are the primary matching key for query file recommendations

**Verdict logic:**
- 🟠 Investigate: `TruePositive / Total > 0.5` (majority of closures are real threats — active threat environment)
- 🟡 Monitor: Any TruePositive closures exist, or `Undetermined > 0` (some incidents lack classification)
- ✅ Clear: 0 TruePositive closures; all closures are BenignPositive or FalsePositive
- 🔵 Informational: 0 closed incidents in 7d

**Rendering rules:**
- **Always render** Q1b results in the report, regardless of Q1 verdict
- Present as a compact summary block under the Q1 section (not a separate dashboard row)
- Flatten the `Tactics` and `Techniques` arrays and report distinct values from TruePositive incidents
- The `Techniques` array feeds directly into the [Query File Recommendations](#query-file-recommendations) manifest MITRE matching (no tactic→technique translation needed)
- If 0 closed incidents in 7d, display: "No incidents closed in the last 7 days"

---

### Query 2: Identity Risk Posture & Risk Event Enrichment

🔐 **Identity risk posture** — Two-layer query: `IdentityInfo` identifies users needing attention (High/Medium risk, AtRisk/ConfirmedCompromised, or high criticality), then `AADUserRiskEvents` enriches with the specific risk detections explaining *why* they're flagged. Covers both sign-in-level detections (e.g., `anonymizedIPAddress`, `unfamiliarFeatures`) AND user-level AI-driven signals (e.g., `aiCompoundAccountRisk`, `adminConfirmedUserCompromised`) that never appear in sign-in tables.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let lookback = 7d;
// Layer 1: IdentityInfo — filtered to users needing attention
let IdentityPosture = IdentityInfo
| where Timestamp > ago(lookback)
| summarize arg_max(Timestamp, *) by AccountUpn
| where RiskLevel in ("High", "Medium") 
    or RiskStatus in ("AtRisk", "ConfirmedCompromised") 
    or CriticalityLevel >= 3
| project AccountUpn, AccountObjectId, AccountName, AccountDomain, OnPremSid,
    AccountDisplayName, IdP_RiskLevel = RiskLevel, IdP_RiskStatus = RiskStatus, CriticalityLevel;
// Layer 2: AADUserRiskEvents — enrichment (the why)
let UserRiskEvents = AADUserRiskEvents
| where TimeGenerated > ago(lookback)
| extend Country = tostring(parse_json(Location).countryOrRegion)
| summarize
    RiskDetections = count(),
    HighCount = countif(RiskLevel == "high"),
    TopRiskEventTypes = make_set(RiskEventType, 8),
    TopCountries = make_set(Country, 5),
    LatestDetection = max(TimeGenerated)
    by UserPrincipalName;
// IdentityInfo drives, AADUserRiskEvents enriches
IdentityPosture
| join kind=leftouter (UserRiskEvents) on $left.AccountUpn == $right.UserPrincipalName
| extend 
    DisplayName = coalesce(AccountDisplayName, AccountName, AccountUpn),
    RiskSummary = strcat(IdP_RiskLevel, " / ", IdP_RiskStatus),
    PortalUrl = strcat("https://security.microsoft.com/user?",
        case(
            isnotempty(AccountObjectId), strcat("aad=", AccountObjectId, "&upn=", AccountUpn),
            isnotempty(OnPremSid), strcat("sid=", OnPremSid, "&accountName=", AccountName,
                                         "&accountDomain=", AccountDomain),
            isnotempty(AccountUpn), strcat("upn=", AccountUpn),
            ""),
        "&tab=overview")
| project DisplayName, PortalUrl, RiskSummary, CriticalityLevel,
    RiskDetections = coalesce(RiskDetections, long(0)),
    HighCount = coalesce(HighCount, long(0)),
    TopRiskEventTypes, TopCountries, LatestDetection
| order by HighCount desc, RiskDetections desc, CriticalityLevel desc
| take 15
```

**Purpose:** Surfaces up to 15 users with the highest identity risk — combining Entra ID risk posture (`IdentityInfo`) with specific risk detection events (`AADUserRiskEvents`). The two-layer approach catches users flagged by:
- **Sign-in-level detections:** `anonymizedIPAddress`, `unfamiliarFeatures`, `impossibleTravel`, `mcasSuspiciousInboxManipulationRules`, `suspiciousAuthAppApproval`
- **User-level AI signals:** `aiCompoundAccountRisk` (cross-signal composite from MDE alerts + sign-in patterns + MCAS activity), `adminConfirmedUserCompromised`, `suspiciousAPITraffic`
- **High-criticality accounts:** `CriticalityLevel >= 3` (Exposure Management) — surfaced even without active risk detections

**Output columns:** `DisplayName` (linked to Defender XDR Identity page via `PortalUrl`), `RiskSummary` (e.g., "High / AtRisk"), `CriticalityLevel`, `RiskDetections` (count), `HighCount`, `TopRiskEventTypes` (human-readable strings), `TopCountries`, `LatestDetection`.

**Portal URL resolution:** Three-tier fallback for identity environment coverage:
- Cloud/Hybrid (has Entra ObjectId): `aad=<ObjectId>&upn=<UPN>`
- On-prem AD (SID only, no Entra sync): `sid=<SID>&accountName=<Name>&accountDomain=<Domain>`
- External IdP (UPN only, e.g., CyberArk/Okta): `upn=<UPN>`

**Report rendering:** Show top 10 users in the dashboard table. Use `DisplayName` as clickable link text with `PortalUrl` as the target. If >10 results, note `"+N more — drill down with user-investigation skill"`. For each user, render `TopRiskEventTypes` as the key risk indicators.

**Verdict logic:**
- 🔴 Escalate: Any user with `ConfirmedCompromised` status, or `HighCount > 3`, or multiple users with `HighCount > 0`
- 🟠 Investigate: `HighCount > 0` for any user, or any user `AtRisk` with risk events indicating `aiCompoundAccountRisk`, `impossibleTravel`, or `maliciousIPAddress`
- 🟡 Monitor: Only `Medium` risk users with low-severity risk event types (e.g., `unfamiliarFeatures`)
- ✅ Clear: 0 users matching the IdentityInfo risk/criticality filter

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

💻 **Threat hunting** — Parent→child process combinations appearing fewer than 3 times in 30 days.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
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

**Purpose:** Surfaces the 20 rarest process chains — singletons and near-singletons within the 30-day AH window. Effective for spotting LOLBin abuse, malware execution, or novel attack tooling. Review `SampleChildCmd` for suspicious command-line patterns.

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

**Tool:** `RunAdvancedHuntingQuery`

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
| SPN drift AND unusual credential/consent activity | Q5 + Q9 | App credential abuse / persistence | Escalate to 🔴 |
| Device with rare process chain AND exploitable CVE | Q7 + Q12 | Potential active exploitation | Escalate to 🔴 |
| Incident entity matches risky identity | Q1 + Q2 | Known incident involves user already flagged AtRisk/Compromised | Link findings in report |
| Closed TP tactics match active findings | Q1b + Q2/Q7/Q8 | Same attack pattern recurring despite recent closures | Escalate to 🟠, note recurrence |
| Spray IP target already flagged as risky | Q4 + Q2 | Spray target has active Identity Protection risk | Escalate to 🔴 |
| Mailbox rule manipulation AND email threats | Q9 + Q8 | Potential email exfiltration setup following phishing | Escalate to 🔴 |

---

## Query File Recommendations

Use the **discovery manifest** (`.github/manifests/discovery-manifest.yaml`) to match findings to downstream query files and skills. Contains `title`, `path`, `domains`, `mitre`, and `prompt` only (~500 lines). Auto-generated by `python .github/manifests/build_manifest.py`.

Tier depth follows the Rule 9 table — skip entirely when all verdicts are ✅.

### Domain-to-Query Mapping

Each threat-pulse query group maps to a domain tag. Non-✅ domains drive manifest lookups:

| Query Group | Domain Tag |
|-------------|-----------|
| Q1, Q1b (Incidents) | `incidents` |
| Q2, Q4 (Identity) | `identity` |
| Q5 (SPN Drift) | `spn` |
| Q6, Q7 (Endpoint) | `endpoint` |
| Q8 (Email) | `email` |
| Q9, Q10 (Admin & Cloud) | `admin`, `cloud` |
| Q11, Q12 (Exposure) | `exposure` |

### Search Procedure (Manifest-Based)

1. **Read the manifest:** Load `.github/manifests/discovery-manifest.yaml`
2. **Collect active domains:** For each non-✅ verdict, note the domain tag(s) from the table above
3. **Filter query files:** From `manifest.queries`, select entries where `domains` contains ANY of the active domain tags
4. **Rank results (three-tier):**
   - **Primary:** Number of matching domain tags (multi-domain match ranks higher)
   - **Secondary:** MITRE technique overlap — compare technique IDs from Q1/Q1b `Techniques` arrays (e.g., `T1566`, `T1078`) directly against the manifest entry's `mitre` field. Exact string match — no tactic-to-technique translation needed
   - **Tertiary:** Keyword overlap — match entity names, process names, CVE IDs, or ActionTypes from findings against manifest entry titles and paths
5. **Select top N:** 🔴/🟠 verdicts: 3–5 files. 🟡-only: 1–2 files
6. **Format links:** Use the `title` and `path` from the manifest entry to build clickable links (see [Link Format Rules](#-mandatory-clickable-file-links) below)

### Skill Suggestions (Manifest-Based)

For **all non-✅ tiers** (not just 🟡), the manifest also provides skill drill-down suggestions:

1. **Filter skills:** From `manifest.skills`, select entries where `domains` contains ANY of the active domain tags
2. **Use prompt template:** Each skill has a `prompt` field with `{entity}` placeholder — substitute the actual entity value from findings (username, device name, SPN, IP, CVE ID)
3. **Tier limits:** 🔴/🟠: include all matching skills as drill-down options. 🟡-only: limit to 3 skills

**Skills without `domains`** (tooling/visualization) are never auto-suggested — they are invoked explicitly by other skill workflows.

### Adding New Query Files or Skills

When you create a new query file or skill, the manifest self-maintains:

1. Add `**Domains:** <tag1>, <tag2>` to the query file metadata header (after `**MITRE:**`)
2. Add `threat_pulse_domains: [<tag1>]` and `drill_down_prompt: '<prompt>'` to skill YAML frontmatter
3. Run `python .github/manifests/build_manifest.py` to regenerate + validate the manifest
4. The validator flags missing fields — no silent failures

Valid domain tags: `incidents`, `identity`, `spn`, `endpoint`, `email`, `admin`, `cloud`, `exposure`

### Report Output Block

Insert `📂 Recommended Query Files` section after **Recommended Actions** in the report.

**⛔ Use numbered list format, NOT a table** — links inside table cells don't render clickable in VS Code chat.

**Format:** `1. **[<Title>](queries/<subfolder>/<file>.md)** — Q<N>: <finding> — 💡 *"<entity-specific prompt>"*`

**Rules:**
- Each prompt MUST reference specific entities/IOCs/TTPs from findings — no generic placeholders
- Link display text = manifest `title`, link target = manifest `path` (forward slashes only)
- When no matching files found, suggest authoring new queries
- Include `🔧 Suggested Skill Drill-Downs` sub-section with manifest skill prompts (substitute `{entity}` with actual values)

---

## Report Template

**Output modes:** Inline chat (default), markdown file (`reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md`), or both. Default to inline unless user requests otherwise.

**Report structure (all modes):**

1. **Header:** `# 🔍 Threat Pulse — <Workspace> | <Date>` with workspace ID, scan duration, query count
2. **Dashboard Summary:** 10-row table — one row per query (Q1, Q1b, Q2, Q4–Q12), columns: `#`, `Domain`, `Status` (verdict emoji), `Key Finding` (1-line). Verdicts: 🔴 Escalate | 🟠 Investigate | 🟡 Monitor | ✅ Clear | ❓ No Data
3. **Detailed Findings:** One section per query — EVERY query gets a section (no skipping). Data tables (max 10 rows inline, unlimited in file). Q1 incidents must include `[XDR #<id>](https://security.microsoft.com/incidents/<ProviderIncidentId>)` links. Q1b closed summary always renders after Q1.
4. **Cross-Query Correlations:** Table of correlated findings per Post-Processing rules, or `✅ No correlations detected`.
5. **🎯 Recommended Actions:** Prioritized table with action, trigger query, and drill-down skill.
6. **📂 Recommended Query Files:** Per the Report Output Block procedure above. For 🟡-only verdicts, use "📂 Proactive Hunting Suggestions" header instead. Omit entirely when all ✅.

**Q1 column format:** `| Incident | Title | Age (days) | Alerts | Owner | Tactics | Techniques |` — Unassigned shows `⚠️ Unassigned`.

**Q1b closed summary:** Classification breakdown table + severity + MITRE tactics/techniques from TP closures. Always render even when Q1 is ✅.

**Zero results format:** `✅ No <type> detected in the last <N>d. Checked: <table> (0 matches)`

**Markdown file extras:** Full data tables (no row limits), full command-line samples, full CVE lists.

---

## Known Pitfalls

| Pitfall | Mitigation |
|---------|------------|
| Q5 takes ~35s (97d lookback) | Acceptable — runs in parallel. Only query needing Data Lake |
| Q7 capped at `ago(30d)` | AH Graph API limit. Use `queries/endpoint/rare_process_chains.md` via Data Lake for 90d |
| Q6 drift scores | Computed in-query — do NOT recompute LLM-side |

> **Schema pitfalls** (column names, dynamic fields, `parse_json` patterns) are covered in `copilot-instructions.md` Known Table Pitfalls. Refer there for `SecurityAlert.Status`, `ExposureGraphNodes.NodeProperties`, timestamp columns, and `AuditLogs.InitiatedBy`.

---

## Quality Checklist

- [ ] All 12 queries executed
- [ ] Every query has a verdict row — no omissions, no skipped "clear" sections
- [ ] ✅ verdicts cite table + "0 results"; 🔴/🟠 cite specific evidence
- [ ] All incidents have clickable XDR portal URLs
- [ ] Cross-query correlations checked
- [ ] `📂 Recommended Query Files` section present when any non-✅ verdict exists (clickable links, not tables)
- [ ] No fabricated data

---

## SVG Dashboard Generation

After completing the Threat Pulse report, the user may request an SVG visualization. Use the `svg-dashboard` skill in **manifest mode** — the widget manifest is at `.github/skills/threat-pulse/svg-widgets.yaml`.

### Execution

1. Read `svg-widgets.yaml` (widget manifest)
2. Read the `svg-dashboard` SKILL.md for component rendering rules
3. Map manifest `field` values to the Threat Pulse report data already in context (or read the saved report file)
4. Render SVG → save to `temp/threat_pulse_{date}_dashboard.svg`
