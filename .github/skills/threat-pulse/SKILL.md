---
name: threat-pulse
description: 'Recommended starting point for new users and daily SOC operations. Quick 15-minute security posture scan across 7 domains: active incidents, identity (human + NonHuman), endpoint, email threats, admin & cloud ops, and exposure. 12 queries executed in parallel batches, producing a prioritized Threat Pulse Dashboard with color-coded verdicts (🔴 Escalate / 🟠 Investigate / 🟡 Monitor / ✅ Clear) and drill-down recommendations pointing to specialized skills. Trigger on getting-started questions like "what can you do", "where do I start", "help me investigate". Supports inline chat and markdown file output'
---

# Threat Pulse — Instructions

## Purpose

The Threat Pulse skill is a rapid, broad-spectrum security scan designed for the "if you only had 15 minutes" scenario. It executes 12 queries across 7 security domains in parallel, producing a prioritized dashboard of findings with drill-down recommendations to specialized investigation skills.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔴 **Incidents** | What high-severity incidents are open and unresolved? How old are they? Who owns them? What was recently resolved — TP rate, MITRE tactics, severity distribution? |
| 🔐 **Identity (Human)** | Which users have the highest Defender XDR Risk Score (0-100)? Which are flagged by Identity Protection (RiskLevel/RiskStatus)? What risk events are driving the signals? Are there password spray / brute-force patterns? |
| 🤖 **Identity (NonHuman)** | Which service principals expanded their resource/IP/location footprint? |
| 💻 **Endpoint** | Which endpoints deviated most from their process behavioral baseline? What singleton process chains exist? |
| 📧 **Email Threats** | What's the phishing/spam/malware breakdown? Were any phishing emails delivered? |
| 🔑 **Admin & Cloud Ops** | What mailbox rules, OAuth consents, transport rules, or mailbox permission changes occurred? Is there programmatic mailbox access via API? Any MCAS-flagged compromised sign-ins? Human-initiated CA policy changes? Who performed high-impact admin operations — role assignments, MFA registration, app registration, ownership grants? |
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
| `XDR_NHI_INVENTORY` | `https://security.microsoft.com/identity-inventory?tab=NonHumanIdentities` |
| `DOCS_NHI_INVESTIGATION` | `https://learn.microsoft.com/en-us/defender-xdr/investigate-non-human-identities` |

Incidents: `XDR_INCIDENT_BASE` + `ProviderIncidentId`.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)**
2. **[Execution Workflow](#execution-workflow)** — Phase 0–3
3. **[Phase 4: Interactive Follow-Up Loop](#phase-4-interactive-follow-up-loop)**
4. **[Take Action](#-take-action--portal-ready-remediation-blocks)** — Portal links, AH queries, defanging
5. **[Sample KQL Queries](#sample-kql-queries)** — 12 queries
6. **[Post-Processing](#post-processing)** — Drift scores, cross-query correlation
7. **[Query File Recommendations](#query-file-recommendations)**
8. **[Report Template](#report-template)** — Dashboard format
9. **[Markdown File Report Template](#markdown-file-report-template)** — Full report structure
10. **[Known Pitfalls](#known-pitfalls)**
11. **[SVG Dashboard Generation](#svg-dashboard-generation)**

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Workspace selection** — Follow the SENTINEL WORKSPACE SELECTION rule from `copilot-instructions.md`. Call `list_sentinel_workspaces()` before first query.

2. **Read `config.json`** — Load workspace ID, tenant, subscription, and Azure MCP parameters before execution.

3. **Output defaults** — Default to **inline chat** with **7d lookback**. Only ask the user for output preferences if they explicitly mention a different mode (e.g., "save to file", "markdown report", "30 day lookback"). If the user just says "threat pulse", "run a scan", or similar — proceed immediately with defaults, do not prompt.

4. **⛔ MANDATORY: Evidence-based analysis only** — Every finding must cite query results. Every "clear" verdict must cite 0 results. Follow the Evidence-Based Analysis rule from `copilot-instructions.md`.

5. **Parallel execution** — Run the Data Lake query (Q5) and all Advanced Hunting queries (Q1, Q2, Q3, Q4, Q6, Q7, Q8, Q9, Q10, Q11, Q12) simultaneously.

6. **Cross-query correlation** — After all queries complete, check for correlated findings per the [Cross-Query Correlation](#cross-query-correlation) table in Post-Processing. Escalate priority when patterns match.

7. **SecurityIncident output rule** — Every incident MUST include a clickable Defender XDR portal URL: `https://security.microsoft.com/incidents/{ProviderIncidentId}`.

8. **⛔ MANDATORY: Query File Recommendations (tiered)** — After assigning verdicts and BEFORE rendering the final report, execute the [Query File Recommendations](#query-file-recommendations) procedure. Skip only when ALL verdicts are ✅.

9. **⛔ MANDATORY: 30d drill-down lookback** — ALL Phase 4 drill-down queries use **30d (AH)** or **90d (Data Lake)** lookback, regardless of the Threat Pulse scan window. Entity-scoped queries (filtered by UPN/IP/device) have negligible performance difference between 7d and 30d, and attacks routinely predate the pulse window. AH caps at 30d anyway. Substitute `ago(7d)` → `ago(30d)` in all query file and skill queries during drill-downs.

| Highest Verdict | Query Files | Proactive Skills | Report Section |
|----------------|-------------|-----------------|----------------|
| 🔴 or 🟠 | Top 3–5, entity-specific prompts | All matching skills | `📂 Recommended Query Files` |
| 🟡 (no 🔴/🟠) | Top 1–2, broader prompts | Up to 3 posture skills | `📂 Proactive Hunting Suggestions` |
| All ✅ | Skip | Skip | Omit entirely |

---

## Execution Workflow

### Phase 0: Prerequisites

1. Read `config.json` for workspace ID and Azure MCP parameters
2. Call `list_sentinel_workspaces()` to enumerate available workspaces
3. Use defaults (inline chat, 7d) unless user specified otherwise
4. **Display scan summary** — Before executing any queries, output the following brief to the user:

```
🔍 Threat Pulse — Scan Plan

Workspace: <WorkspaceName> (<WorkspaceId>)
Lookback: <N>d (user-selected or default 7d)
Output: <Inline / Markdown file / Both>

Executing 12 queries across 7 domains:
  🔴 Incidents      — Open high-severity + 7d closed summary (Q1, Q2)
  🔐 Identity       — Identity risk posture, risk event enrichment, auth spray (Q3, Q4)
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

### Phase 2: Advanced Hunting Queries (Q1, Q2, Q3, Q4, Q6, Q7, Q8, Q9, Q10, Q11, Q12)

**Run all 11 in parallel — no dependencies between queries.**

> **Design rationale:** The connected LA workspace makes all Sentinel tables (SecurityIncident, IdentityInfo, AADUserRiskEvents, AuditLogs, etc.) queryable via AH. AH is preferred: it's free for Analytics-tier tables and avoids per-query Data Lake billing.

| Query | Domain | Purpose | Tool |
|-------|--------|---------|------|
| Q1 | 🔴 Incidents | Open High/Critical incidents with MITRE tactics | `RunAdvancedHuntingQuery` |
| Q2 | 🔴 Incidents | 7-day closed incident summary (classification, MITRE, severity) | `RunAdvancedHuntingQuery` |
| Q3 | 🔐 Identity (Human) | Identity risk posture (IdentityInfo) + risk event enrichment (AADUserRiskEvents) | `RunAdvancedHuntingQuery` |
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
2. Run cross-query correlation checks (see rule 6 above)
3. Assign verdicts to each domain (🔴 Escalate / 🟠 Investigate / 🟡 Monitor / ✅ Clear)
4. Generate prioritized recommendations with drill-down skill references
5. **⛔ STOP — Recommendation Gate:** Before proceeding to step 6, run the [Query File Recommendations](#query-file-recommendations) procedure matching the highest verdict tier (see Rule 8 table). Skip only when all verdicts are ✅. **Do NOT proceed to step 6 until this gate is resolved.**
6. Render output in requested mode (report MUST include the recommendations section if step 5 triggered it)

### Phase 4: Interactive Follow-Up Loop

**After rendering the report, present the user with a selectable list of follow-up actions — skill investigations, query file hunts, and IOC lookups.** Runs when at least one 🔴, 🟠, or 🟡 verdict exists (skip only when ALL verdicts are ✅).

**This is a loop, not a one-shot.** After each action completes, re-present the selection list with the prompt pool updated.

**🟡 Monitor-only environments:** When the highest verdict is 🟡, the prompt pool emphasizes broader posture/assessment skills rather than entity-specific deep-dives. This gives smaller environments actionable next steps even when no finding crosses the escalation threshold.

**Prompt types (three categories, one unified list):**

| Type | Icon | Source | Example |
|------|------|--------|---------|
| **Skill investigation** | 🔍 | Per-query `Drill-down:` skill + entities from findings | `🔍 Investigate user jsmith@contoso.com` → `user-investigation` |
| **Query file hunt** | 📄 | Manifest domain + MITRE matching → query file | `📄 Hunt for RDP lateral movement from 10.0.0.50` → `queries/endpoint/rdp_threat_detection.md` |
| **IOC lookup** | 🎯 | Suspicious IPs, domains, hashes surfaced in findings | `🎯 Enrich and investigate IP 203.0.113.42` → `ioc-investigation` |

**Skill matching rules — derive from findings:**

| Query | Trigger | Skill | Prompt |
|:-----:|---------|-------|--------|
| Q1 | Incident surfaced | `incident-investigation` | `Investigate incident <ProviderIncidentId>` |
| Q1 | Incident with Exfiltration tactic or DLP/Insider Risk in AlertNames | `data-security-analysis` | `Analyze data security events for <entity>` |
| Q2 | `TruePositive > 0` with non-empty `Techniques` array | `mitre-coverage-report` | `Run MITRE coverage report` |
| Q3–Q4 | Username/UPN in findings | `user-investigation` | `Investigate <UPN>` |
| Q3 | 3+ risky users, or any ConfirmedCompromised | `identity-posture` | `Run identity posture report` |
| Q3 | User with `anonymizedIPAddress`, `impossibleTravel`, or `anomalousToken` in TopRiskEventTypes | `authentication-tracing` | `Trace authentication chain for <UPN>` |
| Q3 | User with `unfamiliarFeatures` or `suspiciousAPITraffic` in TopRiskEventTypes | `scope-drift-detection/user` | `Analyze user behavioral drift for <UPN>` |
| Q3+Q4 | 🟡-only identity verdicts (no 🔴/🟠) | `identity-posture` | `Run identity posture report` |
| Q4 | Spray source IP | `ioc-investigation` | `Investigate IP <address>` |
| Q4 | Spray targeting 5+ users | `identity-posture` | `Run identity posture report` |
| Q5 | SPN with drift | `scope-drift-detection/spn` | `Analyze drift for <SPN>` |
| Q6 | Device with DriftScore > 150 | `scope-drift-detection/device` | `Analyze device process drift for <hostname>` |
| Q6–Q7 | Device in findings | `computer-investigation` | `Investigate device <hostname>` |
| Q8 | Phishing delivered or malware detected | `email-threat-posture` | `Run email threat posture report` |
| Q8+Q3 | Phishing recipient appears in Q3 risky users | `authentication-tracing` | `Trace authentication chain for <UPN>` |
| Q9 | `Compromised Sign-In` user surfaced | `user-investigation` | `Investigate <UPN>` |
| Q9 | `Compromised Sign-In` user surfaced | `authentication-tracing` | `Trace authentication chain for <UPN>` |
| Q9 | `Mailbox Read (API)` or `Mail Send (API)` actors | `user-investigation` | `Investigate <UPN>` |
| Q9 | `Mailbox Read (API)` with Count > 500 | `data-security-analysis` | `Analyze data security events for <actor>` |
| Q9 | `Conditional Access Change` by human actor | `ca-policy-investigation` | `Investigate CA policy changes by <UPN>` |
| Q9 | `Exchange Admin/Rule Change` actors | `user-investigation` | `Investigate <UPN>` |
| Q10 | `MFA-Registration` — user registering/deleting security info | `user-investigation` | `Investigate <UPN>` |
| Q10 | `AppRegistration` — app create/consent/secret operations | `app-registration-posture` | `Run app registration posture report` |
| Q10 | `AppRegistration` targets containing AI/Agent/Copilot keywords | `ai-agent-posture` | `Run AI agent security audit` |
| Q10 | `Ownership` — ownership grants on apps/groups/SPNs | `app-registration-posture` | `Run app registration posture report` |
| Q10 | `RoleManagement` targeting Global/Security Admin roles | `identity-posture` | `Run identity posture report` |
| Q10 | Bulk `Password` resets from single actor | `identity-posture` | `Run identity posture report` |
| Q10 | 3+ categories with same actor in TopActors | `user-investigation` | `Investigate <UPN>` |
| Q11 | Any `IsVerifiedExposed == true` asset | `exposure-investigation` | `Run exposure report for <hostname>` |
| Q11–Q12 | Device in findings | `computer-investigation` | `Investigate device <hostname>` |
| Q12 | CVE with fleet impact | `exposure-investigation` | `Run vulnerability report for <CVE>` |

#### ⛔ MANDATORY: 30d Drill-Down Lookback

ALL drill-down queries use **30d for AH** and **90d for Data Lake** — no conditional checks needed. Rationale:

- Entity-scoped queries (filtered by UPN, IP, or device) scan negligible data regardless of lookback window
- AH Graph API caps at 30d anyway — requesting 30d costs nothing extra
- Attacks routinely predate the pulse window (e.g., the Cameron V AiTM chain started 14 days before admin confirmation)
- The previous context-aware conditional logic was error-prone — LLMs frequently defaulted to 7d and missed critical evidence

For query file prompts, substitute `ago(7d)` with `ago(30d)`. For Data Lake queries, use `ago(90d)`.

**Procedure:**
1. Build the **initial prompt pool** by combining:
   - Skill prompts: one per unique entity + matching skill from the table above. If the same entity appears in multiple queries (e.g., Q3 and Q9), create ONE skill prompt for that entity — the correlation context goes in the Description, not in the Label.
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
     - **Label format:** `<ONE icon> <ONE action>` — e.g., `🔍 Investigate user jsmith@contoso.com`, `📄 Hunt delivered phishing emails`
     - **Description format:** `Q<N>: <finding summary> → <skill or query file>`
     - **Allowed emojis:** `🔍` `📄` `🎯` `💾` `🆕` `🔄` only. Verdict emojis (🔴🟠🟡🟢✅) render as `��` in VS Code Quick Pick — use plain text like `[Escalate]` instead.
     - One icon per Label, one action per option. If tempted to add a comma or second icon, split into two options.
   - **Label:** `💾 Save full investigation report` / **Description:** `Save the complete Threat Pulse session (scan + all drill-downs) as a markdown file`
   - **Label:** `🔄 Refresh recommendations` / **Description:** `Regenerate the prompt pool based on all findings so far (pulse + drill-downs)`
   - **Label:** `Skip` / **Description:** `No follow-up — investigation complete` *(always last)*
   - **multiSelect:** `true`
3. If user selects **Skip** (alone) or pool is empty: end skill execution. Ignore any freeform text if Skip is selected.
4. **Freeform input routing** — If user types freeform text instead of (or alongside) selecting options, route by matching intent to validated sources. Do NOT write ad-hoc KQL — find the right skill or query file first. Classified actions feed into step 7 alongside any selected options.
   1. **Skill match** — Check the request against copilot-instructions.md Available Skills trigger keywords. "Check vulnerabilities on that device" → `exposure-investigation` or `computer-investigation`. Route as 🔍 — the `read_file` gate in step 7 applies.
   2. **Query file match** — `grep_search` the request's key terms (table names, operations, attack types) against `queries/**`. "Check forwarding rules" → `queries/email/email_threat_detection.md`. Route as 📄.
   3. **Contextual question** — If answerable from data already in context (e.g., "is that IP in other alerts?"), answer directly. If a query is needed, loop back to sub-steps 1–2 to find the right source.
   4. **No match** — If no skill or query file covers the request, follow the KQL Pre-Flight Checklist from copilot-instructions.md (schema validation, table pitfalls, existing query search) before writing any KQL. Never skip the pre-flight for freeform requests.
5. If user's selection includes **💾 Save full investigation report:**
   - If no drill-downs have been executed yet, the saved report contains only the Threat Pulse scan results (omit the `Drill-Down Investigation Results` and `Cross-Investigation Correlation` sections; note: "No drill-down investigations were performed in this session.")
   - Otherwise, read `/memories/session/threat-pulse-drilldowns.md` to recover all accumulated drill-down findings (critical after context compaction)
   - Compile the complete session — original Threat Pulse dashboard + all drill-down investigation results — into a single markdown file using the [Markdown File Report Template](#markdown-file-report-template)
   - Save to `reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md`
   - **Weave drill-down insights into the main report** — do NOT simply append raw drill-down output. See the [Markdown File Report Template](#markdown-file-report-template) for the exact structure, including the `## Drill-Down Investigation Results` section format and the `## Cross-Investigation Correlation` section.
   - Remove the save option from the pool (report already saved). If no other actions were selected alongside it, **end the loop** — the investigation is complete. Otherwise continue to step 7 with the remaining selections.
6. If user selects **🔄 Refresh recommendations:**
   - Read `/memories/session/threat-pulse-drilldowns.md` to gather all accumulated drill-down findings
   - **Discard the current prompt pool entirely.** Rebuild from scratch by re-running the [Query File Recommendations](#query-file-recommendations) procedure AND the [Phase 4 skill matching table](#phase-4-interactive-follow-up-loop) against the **combined** pulse findings + all drill-down findings. New entities, TTPs, and cross-investigation connections discovered during drill-downs drive the new pool — not just the original 12 pulse queries.
   - **Why refresh vs incremental `🆕`:** The step 7 New Evidence Scan already adds new IOCs/entities incrementally after each drill-down. Refresh is for **re-ranking and re-matching** — e.g., new MITRE techniques discovered in drill-downs may surface different query files from the manifest, or new entities may now match skill triggers that weren't relevant at initial pool build time.
   - Deduplicate against completed prompts (never re-offer an already-executed drill-down)
   - Present the regenerated pool via `vscode_askQuestions` (same format as step 2). The 🔄 option itself stays in the pool — it can be used again after more drill-downs.
   - If selected alongside other actions, execute the refresh FIRST (to rebuild the pool), then present the new pool — do NOT execute the other selections from the stale pool.
7. If user selects one or more actions:
   - Build a **todo list** with one item per selected action, all `not-started`
   - Execute each action **sequentially** in selection order:
      - **🔍 Skill prompt — ⛔ `read_file` the child SKILL.md BEFORE writing ANY query.** Load SKILL.md → find Investigation shortcuts → match TP Q# trigger → execute that chain with entity substitution. Writing KQL without a prior `read_file` on the child SKILL.md = schema hallucination. See [🔍 Skill Drill-Down Execution Rule](#-skill-drill-down-execution-rule).
      - **📄 Query file prompt:** read the query file, then **execute the queries from the file verbatim** with entity value substitution. See [📄 Query File Execution Rule](#-query-file-execution-rule) below.
      - **IOC prompt:** load `ioc-investigation` skill, execute with the target indicator
      - Mark each todo `completed` as it finishes
      - **⛔ MANDATORY session state capture:** After each drill-down completes, append a structured summary to `/memories/session/threat-pulse-drilldowns.md`. Create the file on first drill-down. Append one entry per drill-down:
        ```
        ### <N>. <Prompt Label> (<skill-name>, <YYYY-MM-DD HH:MM>)
        - **Entity:** <target entity>
        - **Trigger:** Q<N> — <original finding from pulse>
        - **Key Findings:**
          - <finding 1 — specific, evidence-cited>
          - <finding 2>
          - ...(max 8 bullet points — prioritize high-risk and novel discoveries)
        - **Risk Assessment:** <emoji> <level> — <1-line justification with evidence>
        - **Cross-References:** <entities/IOCs that overlap with other drill-downs or original pulse queries>
        - **Recommendations:** <top 1-3 action items from this drill-down>
        ```
        This ensures drill-down insights survive context compaction and are available when the user requests `💾 Save full investigation report`.
   - Remove all completed prompts from the pool
   - **⛔ MANDATORY: New Evidence Scan.** Before returning to step 2, review the drill-down results for entities (IPs, users, devices, domains, hashes, CVEs) or MITRE techniques that were **not present in any prior query result or drill-down**. For each new item, assess whether it warrants follow-up — not every new entity is actionable. Add `🆕`-tagged prompts only for items that represent a **meaningful investigative lead** (e.g., a new attacker IP with high abuse score, a critical CVE on an exposed device, a previously unknown compromised account). Prepend `🆕` prompts above existing pool items. If nothing warrants follow-up, proceed — but note: "No actionable new evidence from this drill-down."
   - **Return to step 2 — call the interactive question tool again.** Every loop iteration MUST use `vscode_askQuestions` to present the updated pool as a selectable list. Do NOT render a markdown table/numbered list as a substitute.

**Prompt pool rules:**
- Completed prompts are removed — never re-offered
- New evidence prompts are prepended (freshest leads first), tagged `🆕`
- Loop ends when user selects Skip or pool empties (`✅ All follow-up actions completed.`)
- **🔴 PROHIBITED:** Rendering the prompt pool as a markdown table, numbered list, or plain text instead of calling `vscode_askQuestions`. Every iteration — including after the first follow-up completes — MUST use the interactive question tool so options are clickable. This is the #1 loop-breaking mistake.
- **🔴 PROHIBITED:** Returning to step 2 after a drill-down without executing the New Evidence Scan (step 7, "New Evidence Scan" bullet). Skipping this scan is the #1 reason drill-down leads go uninvestigated — new IPs, CVEs, and devices discovered during drill-downs silently disappear from the pool.
- **🔴 ATOMIC OPTIONS — ONE action per selectable item.** Each option Label MUST contain exactly ONE icon (🔍, 📄, or 🎯) and map to exactly ONE executable action: one skill + one entity, OR one query file + one hunt prompt. When cross-query correlations link multiple findings (e.g., Q3+Q9 correlating a user with both risky identity and inbox rule manipulation), generate **separate options** for each distinct action — do NOT bundle them into a single option. Note the correlation in the **Description** field to preserve context, but keep the Label and action singular.

  **Self-check before presenting:** For each option, verify: (1) the Label has exactly ONE icon prefix, (2) there is NO comma separating a second action, (3) the Description has exactly ONE `→` pointing to ONE skill or query file. If any check fails, split the option.

  **❌ PROHIBITED — bundled multi-action option (this is the #1 follow-up mistake):**
  `🔍 Investigate user cameron@contoso.com - Q3+Q9: mcasSuspiciousInboxManipulationRules + anonymizedIPAddress (5 high) + New-InboxRule creation — potential email exfiltration → user-investigation, 📄 Hunt delivered phishing emails → queries/email/email_threat_detection.md`

  **❌ ALSO PROHIBITED — multiple skills/query files in Description:**
  Description: `Q3+Q9: ... → user-investigation, queries/email/email_threat_detection.md`

  **✅ CORRECT — one action per option, correlation context in Description only:**
  - Option 1 — Label: `🔍 Investigate user cameron@contoso.com` / Description: `Q3+Q9: Identity risk (AtRisk, aiCompoundAccountRisk + anonymizedIPAddress) + inbox rule manipulation — potential email exfiltration → user-investigation`
  - Option 2 — Label: `📄 Hunt delivered phishing emails and recipients` / Description: `Q8: Trace the 4 delivered phishing emails → queries/email/email_threat_detection.md`

### 📄 Query File Execution Rule

**⛔ MANDATORY — applies to ALL `📄` query file prompt executions in Phase 4.**

When executing a `📄` prompt, use the queries **from the file verbatim** with entity substitution. Do NOT rewrite queries against different tables than the file specifies.

1. Read the query file and check its **Investigation shortcuts** section at the top — match the `(TP Q#)` annotation to the triggering Threat Pulse query to identify the recommended query chain. Follow that chain for the hunt
2. Substitute entity values (hostnames, IPs, UPNs) and adjust `ago(Nd)` lookback if context-aware expansion applies
3. **⚠️ Hostname-safe substitution:** Device names vary across tables (short hostname vs FQDN vs uppercase). NEVER use `==` for device/computer filters — use `startswith` (default, case-insensitive, matches both short name and FQDN), or `in~` (multi-device). Override `==` in query file entity substitution notes with `startswith`.
4. Execute using the file's exact tables, columns, and filters
5. If supplementing with additional tables, execute the file's queries **first**, then add your own — clearly label which are from the file vs. supplementary

| Action | Status |
|--------|--------|
| Reading a query file then writing queries against a different table | ❌ **PROHIBITED** |
| Using the query file as "inspiration" and rewriting from scratch | ❌ **PROHIBITED** |
| Executing the file's queries verbatim with entity substitution | ✅ **REQUIRED** |

### 🔍 Skill Drill-Down Execution Rule

**⛔ MANDATORY — applies to ALL `🔍` skill drill-down executions in Phase 4.**

When executing a skill drill-down, **load the child skill's SKILL.md** and use its validated queries. Do NOT write ad-hoc queries from memory — schema hallucination (wrong column names, wrong table) is the #1 drill-down failure mode.

1. Load the child skill's SKILL.md
2. Match the trigger context (TP Q number) against the skill's **Investigation shortcuts** section to identify the relevant query chain
3. Execute the shortcut query chain — substitute **only** entity placeholders and date ranges. Do NOT add columns, change `project`/`summarize by`, or restructure. Column names vary across Device* tables; the SKILL.md queries already use the correct ones.
4. For quick triage: run only the shortcut chain. For deep investigation: run the full skill workflow

| Action | Status |
|--------|--------|
| Writing ad-hoc KQL without loading the child SKILL.md | ❌ **PROHIBITED** |
| Loading SKILL.md then modifying its queries (adding/changing columns, restructuring) | ❌ **PROHIBITED** |
| Using SKILL.md queries verbatim with entity substitution | ✅ **REQUIRED** |

---

### 🎬 Take Action — Portal-Ready Remediation Blocks

> ⚠️ **AI-generated content may be incorrect. Always review Take Action queries and portal links for accuracy before executing remediation actions.**

After every non-✅ drill-down that surfaces actionable entities, append a **`🎬 Take Action`** section with **direct portal links** (single entities) or **Advanced Hunting queries** (bulk entities). Ref: [Take action on AH results](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-take-action)

**⛔ MANDATORY:** Every `🎬 Take Action` heading in the output MUST be immediately followed by this warning blockquote:

```
> ⚠️ **AI-generated content may be incorrect. Always review Take Action queries and portal links for accuracy before executing remediation actions.**
```

Never omit this warning. It must appear below EVERY `🎬 Take Action` heading, not just the first one.

**Skip when:** verdict is ✅/🔵, or the action was already taken (e.g., ZAP purged emails).

#### Single Entity vs Bulk Entity Decision Rule

**The remediation format depends on how many entities need action.**

| Scenario | Format |
|----------|--------|
| **1 entity** (user, device, IP, domain, hash) | Direct Defender XDR portal link (see [Portal Links](#defender-xdr-portal-links--all-entity-types) table for URL patterns) |
| **2+ emails** | AH query with `NetworkMessageId in (...)` → Take actions |
| **2+ devices** | AH query with `DeviceName in~ (...)` → Take actions |
| **2+ IPs/domains/hashes** | AH query → click value in results → Add Indicator (allow/warn/block) |

**⛔ PROHIBITED:** Generating an AH query for a single entity when a direct portal link would suffice. AH Take Action is for **bulk remediation** — for a single entity, link directly to the portal page where the analyst can act.

**Where to get the IDs for single-entity links:**
- **User ObjectId (OID):** From Graph API (`/v1.0/users/<UPN>?$select=id`) or IdentityInfo `AccountObjectId` column — already retrieved during drill-down
- **MDE DeviceId:** From `DeviceInfo` table (`DeviceId` column) or `GetDefenderMachine` API — already retrieved during computer-investigation drill-down

#### Required Columns per Entity Type

**Missing a required column silently disables the action menu.** Always include these:

| Entity | Required Columns | Actions | Notes |
|--------|-----------------|---------|-------|
| **📧 Email** | `NetworkMessageId`, `RecipientEmailAddress` | Soft/hard delete, move to folder, submit to Microsoft, initiate investigation | **Do NOT use `project`** — *Submit to Microsoft* and *Initiate Automated Investigation* require undocumented columns that `project` strips, silently greying out those options. The portal's *Show empty columns* toggle only works when columns exist in the result schema. Return all columns; use `where` to scope results. |
| **💻 Device** | `DeviceId` | Isolate, collect investigation package, AV scan, initiate investigation, restrict app execution | Use `summarize arg_max(Timestamp, *) by DeviceId` for latest state |
| **📁 File** | `SHA1` or `SHA256` + `DeviceId` | Quarantine file | Both hash and device required |
| **🔗 Indicator** | IP, URL/domain, or SHA hash column | Add indicator: allow, warn, or block | **An AH query is still required** to surface the values as clickable — there is no *Take actions* dropdown button. Instead, click any IP/URL/hash value directly in the AH results → *Add indicator* to create a Defender for Endpoint custom indicator |
| **🔐 Identity** | *(No AH Take Action)* | Confirm compromised, revoke sessions, suspend in app | **Single user:** Direct Defender XDR Identity page link. **Never** generate an AH query for identity remediation |

#### Template Queries

**📧 Email — by NetworkMessageId:** *(no `project` — see Email row above)*
```kql
EmailEvents
| where Timestamp > ago(7d)
| where NetworkMessageId in ("<id1>", "<id2>")
```
→ *Take actions →* Move to mailbox folder, Delete email (soft/hard), Submit to Microsoft, Initiate automated investigation

**📧 Email — by compromised sender domain:**
```kql
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromDomain =~ "<domain>" and ThreatTypes has "Phish" and DeliveryAction == "Delivered"
| take 500
```
→ *Take actions →* Move to mailbox folder, Delete email (soft/hard), Submit to Microsoft, Initiate automated investigation

**💻 Single Device — direct portal link:**
When acting on a **single device**, link directly to its Defender XDR machine page. The `DeviceId` comes from the `DeviceInfo` table or `GetDefenderMachine` API (already retrieved during `computer-investigation` drill-down).

`[<DeviceName>](https://security.microsoft.com/machines/v2/<MDE_DeviceId>)`

→ Machine page → *Response actions* → Isolate device, Collect investigation package, Run antivirus scan, Initiate investigation, Restrict app execution

**💻 Bulk Devices (2+) — AH query:**
```kql
DeviceInfo
| where Timestamp > ago(1d)
| where DeviceName in~ ("<device1>", "<device2>")
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform, MachineGroup
```
→ *Take actions →* Isolate device, Collect investigation package, Run antivirus scan, Initiate investigation, Restrict app execution

**📁 File — by hash:**

> **Source-aware table selection.** SHA hashes appear across many tables (`DeviceProcessEvents`, `DeviceImageLoadEvents`, `DeviceFileEvents`, `AlertEvidence`). Use `DeviceFileEvents` as the default — it captures file writes and has the columns needed for Quarantine. If the hash was only observed via process execution (no separate file write event), substitute or union with `DeviceProcessEvents`. The Quarantine action requires `DeviceId` + `SHA1`/`SHA256` regardless of source table.

**File write events** (default — `DeviceFileEvents`):
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA1 == "<hash>" or SHA256 == "<hash>"
| project DeviceId, DeviceName, SHA1, SHA256, FileName, FolderPath
```

**Process execution events** (when file write not captured — `DeviceProcessEvents`):
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA1 == "<hash>" or SHA256 == "<hash>"
| project DeviceId, DeviceName, SHA1, SHA256, FileName, FolderPath, ProcessCommandLine
```

→ *Take actions →* Quarantine file

**🔗 Bulk Indicators (2+ IPs/domains/hashes) — AH query for Add Indicator:**

When blocking multiple IPs, domains, or hashes, provide an AH query that surfaces the values as clickable columns. There is no *Take actions* dropdown — the analyst clicks each value directly in results → *Add indicator*.

> **Source-aware table selection.** The table MUST match where the IPs were originally discovered. `DeviceNetworkEvents` is the default for network-layer IPs (endpoint connections, firewall events). However, IPs from authentication-layer sources (`AADUserRiskEvents`, `EntraIdSignInEvents`, `SigninLogs`, `AADServicePrincipalSignInLogs`) may never appear in endpoint network events — querying `DeviceNetworkEvents` for those returns 0 results. Use the originating table so the analyst sees the IPs in context and can click to add indicators.

**Network-layer IPs** (from `DeviceNetworkEvents`, `DeviceLogonEvents`, firewall logs):
```kql
// Surface attacker IPs as clickable values for Add Indicator
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("<ip1>", "<ip2>", "<ip3>")
| summarize Connections = count(), Ports = make_set(LocalPort) by RemoteIP
| order by Connections desc
```

**Auth-layer IPs** (from `AADUserRiskEvents`, `EntraIdSignInEvents`, `SigninLogs`):
```kql
// Surface attacker IPs from sign-in/risk events for Add Indicator
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where IPAddress in ("<ip1>", "<ip2>", "<ip3>")
| summarize SignIns = count(), Users = dcount(AccountUpn), Countries = make_set(Country, 5) by IPAddress
| order by SignIns desc
```

→ Click any IP value in results → *Add indicator* → Block and remediate

**Variant — domains/URLs:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("<domain1>", "<domain2>")
| summarize Connections = count() by RemoteUrl
| order by Connections desc
```
→ Click any `RemoteUrl` value → *Add indicator* → Block and remediate

#### Defender XDR Portal Links — All Entity Types

**🔴 Every entity (user, domain, URL, IP, file hash) in action/recommendation tables MUST be a clickable Defender XDR portal link — the entity name IS the link.** Do NOT add a separate "Portal" column or leave entities as plain text. VS Code renders bare UPNs as `mailto:` and bare URLs/IPs as broken links.

| Entity | URL Pattern | Example |
|--------|------------|---------|
| **User** | `https://security.microsoft.com/user?aad=<OID>&upn=<UPN>&tab=overview` | `[user@contoso.com](https://security.microsoft.com/user?aad=<OID>&upn=user@contoso.com&tab=overview)` |
| **Domain** | `https://security.microsoft.com/domains/overview?urlDomain=<domain>` | `[contoso.com](https://security.microsoft.com/domains/overview?urlDomain=contoso.com)` |
| **URL** | `https://security.microsoft.com/url/overview?url=<url-encoded-URL>` | `[example.com/path](https://security.microsoft.com/url/overview?url=http%3A%2F%2Fexample.com%2Fpath)` |
| **IP** | `https://security.microsoft.com/ip/<IP>/overview` | `[<IP>](https://security.microsoft.com/ip/<IP>/overview)` |
| **File Hash** | `https://security.microsoft.com/file/<SHA1-or-SHA256>/` | `[da5e459...b1bb1e](https://security.microsoft.com/file/da5e45915354850261cf0e87dc7af19597b1bb1e/)` |
| **Device** | `https://security.microsoft.com/machines/v2/<MDE_DeviceId>` | `[alpine-srv1](https://security.microsoft.com/machines/v2/6b02befec5724a3b79184d006ac417eda6fb05a6)` |
| **SPN / Non-Human Identity** | `https://security.microsoft.com/identity-inventory?tab=NonHumanIdentities` | `[Non-Human Identities Inventory](https://security.microsoft.com/identity-inventory?tab=NonHumanIdentities)` |

**User fallbacks:** `?upn=<UPN>` when ObjectId is unavailable; `?sid=<SID>&accountName=<Name>&accountDomain=<Domain>` for on-prem AD.

**Device ID source:** `DeviceId` from the `DeviceInfo` AH table or the `id` field from `GetDefenderMachine` API. This is the MDE machine identifier — NOT the Entra Device Object ID (which is different). The computer-investigation skill retrieves this in Step 1b.

#### Entity Display Decision — Portal Link vs Defang

**Defanging and portal linking are MUTUALLY EXCLUSIVE. For every malicious domain, URL, or IP in a table, apply exactly ONE treatment:**

| Context | Treatment | Example |
|---------|-----------|----------|
| **Action / recommendation / Take Action table** | Wrap entity name in Defender XDR portal link. Do NOT defang. | `[evil.com](https://security.microsoft.com/domains/overview?urlDomain=evil.com)` |
| **Data / results table showing raw query output** | Defang the entity. Do NOT link to portal. | `evil[.]com` |

⛔ **Action tables: use portal links, NOT defanging.** Writing `evil[.]com` in an action table is wrong — write `[evil.com](https://security.microsoft.com/domains/overview?urlDomain=evil.com)` instead. The markdown link target points to `security.microsoft.com`, so VS Code won't auto-linkify to the malicious domain. If you see `[.]` in an Entity cell, you applied the wrong rule.

⛔ **Data tables: use defanging, NOT portal links.** Writing bare `evil.com` in a results table is wrong — VS Code auto-linkifies it. Write `evil[.]com` instead.

#### URL Defanging — Prevent Accidental Clicks

**When displaying URLs/domains as plain text (not wrapped in a Defender XDR portal link), DEFANG them** to prevent VS Code from rendering them as clickable links. VS Code auto-linkifies anything that looks like a URL — including malicious phishing URLs in investigation results.

| Original | Defanged |
|----------|----------|
| `http://` | `hxxp://` |
| `https://` | `hxxps://` |
| `.` in domain | `[.]` |

**Example:** `robiox.com.py/users/page` → `robiox[.]com[.]py/users/page`

**When to defang:** Data tables showing threat URLs/domains from query results (e.g., UrlClickEvents, EmailEvents phishing URLs, CloudAppEvents suspicious domains) where the value is displayed as-is, not linked to a Defender XDR portal page.

**When NOT to defang:** When the entity appears in an **action or recommendation table** — these MUST use clickable Defender XDR portal links instead (see Portal Links table above). Defanging a portal-linked entity breaks the link. The two treatments are mutually exclusive.

#### Rules

| Rule | Status |
|------|--------|
| Non-✅ drill-down surfaces actionable entities but no Take Action block | ❌ **PROHIBITED** |
| Take Action query missing a required column | ❌ **PROHIBITED** |
| Email Take Action query using `project` (strips columns needed by Submit to Microsoft / Initiate Automated Investigation) | ❌ **PROHIBITED** |
| AH query for a single user when ObjectId is known (use direct portal links instead) | ❌ **PROHIBITED** |
| AH query for a single device when MDE DeviceId is known (use direct machine page link instead) | ❌ **PROHIBITED** |
| AH query for a single IP/domain/hash when a direct portal link suffices | ❌ **PROHIBITED** |
| Action table with plain-text entities (UPNs, domains, URLs, IPs, hashes) instead of clickable Defender XDR portal links | ❌ **PROHIBITED** |
| Defanging entities (`[.]`) in action/recommendation tables instead of wrapping in portal links | ❌ **PROHIBITED** |
| Adding a separate "Portal" column instead of making the entity name itself the clickable link | ❌ **PROHIBITED** |
| Displaying raw (non-defanged) malicious URLs/domains as plain text in results tables | ❌ **PROHIBITED** |
| Single user/device: direct portal link + PowerShell commands | ✅ **REQUIRED** |
| Bulk entities (2+ emails, devices, indicators): AH query with Take actions | ✅ **REQUIRED** |
| Every `🎬 Take Action` heading followed by the warning: `> ⚠️ **AI-generated content may be incorrect. Always review Take Action queries and portal links for accuracy before executing remediation actions.**` | ✅ **REQUIRED** |
| Rendering a `🎬 Take Action` section without the AI-generated content warning immediately below the heading | ❌ **PROHIBITED** |
| Bulk indicator (2+ IPs/domains/hashes) Take Action block includes AH query that surfaces values as clickable columns | ✅ **REQUIRED** |
| Describing "Add indicator" action without providing the AH query that surfaces the values in results | ❌ **PROHIBITED** |

---

## Sample KQL Queries

> **All queries below are verified against live Sentinel/Defender XDR schemas. Use them exactly as written. Lookback periods use `ago(Nd)` — substitute the user's preferred lookback where noted.**

### Query 1: Open High-Severity Incidents with MITRE Techniques & Entities

🔴 **Incident hygiene** — Surfaces unresolved High/Critical incidents with age, owner, alert count, MITRE tactics, MITRE technique IDs, and extracted entity names (accounts + devices) for cross-query correlation.

**Tool:** `RunAdvancedHuntingQuery`

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active")
| where Severity in ("High", "Critical")
| extend ParsedLabels = parse_json(Labels)
| mv-apply Label = ParsedLabels on (
    summarize Tags = make_set(tostring(Label.labelName), 5)
)
| extend Tags = set_difference(Tags, dynamic([""]))
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, Entities, Tactics, Techniques, AlertName, AlertSeverity) by SystemAlertId
    | extend ParsedEntities = parse_json(Entities)
    | mv-expand Entity = ParsedEntities
    | extend EntityType = tostring(Entity.Type),
        AccountUPN = case(
            tostring(Entity.Type) == "account" and isnotempty(tostring(Entity.UPNSuffix)),
            tolower(strcat(tostring(Entity.Name), "@", tostring(Entity.UPNSuffix))),
            tostring(Entity.Type) == "account" and isnotempty(tostring(Entity.AadUserId)),
            tostring(Entity.AadUserId),
            ""),
        HostName = iff(tostring(Entity.Type) == "host", tolower(tostring(Entity.HostName)), "")
    | project SystemAlertId, Tactics, Techniques, AlertName, AlertSeverity, AccountUPN, HostName
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
    AlertCount = dcount(AlertId),
    Accounts = make_set(AccountUPN, 5),
    Devices = make_set(HostName, 5),
    Tags = take_any(Tags)
    by ProviderIncidentId, Title, Severity, Status, CreatedTime,
       OwnerUPN = tostring(Owner.userPrincipalName)
| extend Techniques = set_difference(Techniques, dynamic([""]))
| extend Tactics = set_difference(Tactics, dynamic([""]))
| extend Accounts = set_difference(Accounts, dynamic([""]))
| extend Devices = set_difference(Devices, dynamic([""]))
| extend AgeDisplay = case(
    datetime_diff('minute', now(), CreatedTime) < 60, strcat(datetime_diff('minute', now(), CreatedTime), "m ago"),
    datetime_diff('hour', now(), CreatedTime) < 24, strcat(datetime_diff('hour', now(), CreatedTime), "h ago"),
    strcat(datetime_diff('day', now(), CreatedTime), "d ago"))
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId)
| project ProviderIncidentId, Title, Severity, AgeDisplay, AlertCount, 
    OwnerUPN, Tactics, Techniques, Accounts, Devices, Tags, PortalUrl, AlertNames, CreatedTime
| order by bin(CreatedTime, 1d) desc, AlertCount desc
| take 10
```

**Purpose:** Identifies the top 10 newest open high-severity incidents, sorted by day (newest first) then by alert count (highest complexity first within each day). Joins SecurityAlert for MITRE tactic and technique ID visibility, plus extracts `Accounts` (UPNs or AAD ObjectIds) and `Devices` (hostnames) from alert entities for cross-query correlation with Q3 (identity risk), Q6/Q7 (endpoint drift/rare processes), Q4 (spray targets), and Q12 (CVE exposure). Extracts `Tags` from incident labels (both AutoAssigned ML classifications like `Credential Phish`, `BEC Fraud`, `Defender Experts` and User-applied SOC workflow tags). Flags unassigned incidents (empty OwnerUPN).

**Sort logic:** `bin(CreatedTime, 1d) desc, AlertCount desc` — groups incidents by calendar day (newest day first), then ranks by correlated alert count within each day. This ensures the most complex recent incidents surface first, while older backlog naturally drops off.

**Entity extraction rules:**
- **Accounts:** Prefers `Name@UPNSuffix` (lowercased); falls back to `AadUserId` (GUID) when no UPN suffix. Service accounts without domains naturally drop.
- **Devices:** `HostName` (lowercased) for case-insensitive matching against Q6/Q7 `DeviceName`.
- **Tags:** Extracted from `Labels` (dynamic array of `{labelName, labelType}` objects). Includes both `AutoAssigned` (Defender ML) and `User` (SOC analyst/automation rule) tags.
- Accounts, Devices, and Tags each capped at 5 per incident to limit output size.

**Output columns:** `ProviderIncidentId` (linked via `PortalUrl`), `Title`, `Severity`, `AgeDisplay` (relative time: "3m ago", "2h ago", "1d ago"), `AlertCount`, `OwnerUPN`, `Tactics`, `Techniques`, `Accounts`, `Devices`, `Tags`. `AlertNames` and `CreatedTime` are projected for LLM context but not rendered as table columns.

**Verdict logic:**
- 🔴 Escalate: 5+ new High/Critical incidents in 24h, or any incident with `AlertCount > 50`, or any unassigned incident with CredentialAccess/LateralMovement tactics
- 🟠 Investigate: Any unassigned incident, or `AlertCount > 10`, or multiple incidents in <6h
- 🟡 Monitor: Open incidents exist but are assigned and low alert count
- ✅ Clear: 0 open High/Critical incidents (Q2 closed summary still renders as context)

---

### Query 2: Closed Incident Summary (7-Day Lookback)

🔴 **Threat landscape context** — Even when all incidents are resolved, the classification breakdown, MITRE tactic distribution, and severity mix from recent closures provide actionable signals for cross-correlation and query file recommendations.

**Tool:** `RunAdvancedHuntingQuery`

**Always runs in parallel with Q1 — not conditional on Q1 results.**

```kql
SecurityIncident
| where CreatedTime > ago(7d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| where array_length(AlertIds) > 0
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, Tactics, Techniques) by SystemAlertId
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

**Purpose:** Provides a 7-day closed incident summary with classification breakdown (TP/BP/FP/Undetermined), severity distribution, aggregated MITRE tactics, and aggregated MITRE technique IDs. Uses `CreatedTime` (not `TimeGenerated`) to match portal "created in last 7 days" semantics — `TimeGenerated` captures any incident *updated* in the window, inflating counts with old incidents. Filters `array_length(AlertIds) > 0` to exclude phantom incidents — the SecurityIncident table contains hundreds of records synced from XDR with empty AlertIds that never surface in the Defender XDR portal queue (see copilot-instructions.md Known Table Pitfalls). This data feeds three downstream uses:
1. **TP rate signal** — High TruePositive ratio indicates an active threat environment
2. **MITRE tactic context** — Tactics from closed TPs identify the current threat landscape for cross-correlation with Q3/Q7/Q8 findings
3. **Manifest MITRE matching** — The `Techniques` array contains ATT&CK technique IDs (e.g., `T1566`, `T1078`, `T1059`) directly matchable against manifest entry `mitre` fields. No tactic→technique mapping needed — the technique IDs are the primary matching key for query file recommendations

**Verdict logic:**
- 🟠 Investigate: `TruePositive / Total > 0.5` (majority of closures are real threats — active threat environment)
- 🟡 Monitor: Any TruePositive closures exist, or `Undetermined > 0` (some incidents lack classification)
- ✅ Clear: 0 TruePositive closures; all closures are BenignPositive or FalsePositive
- 🔵 Informational: 0 closed incidents in 7d

**Rendering rules:**
- **Always render** Q2 results in the report, regardless of Q1 verdict
- In the Dashboard Summary, Q2 gets its own row. In Detailed Findings, render Q2 immediately after Q1 as a compact summary block
- Flatten the `Tactics` and `Techniques` arrays and report distinct values from TruePositive incidents
- The `Techniques` array feeds directly into the [Query File Recommendations](#query-file-recommendations) manifest MITRE matching (no tactic→technique translation needed)
- If 0 closed incidents in 7d, display: "No incidents closed in the last 7 days"

---

### Query 3: Identity Risk Posture & Risk Event Enrichment

🔐 **Identity risk posture** — Hybrid two-signal query: `IdentityInfo.RiskScore` (Defender XDR composite, 0-100) captures alert-chain and MITRE-stage risk, while `RiskLevel`/`RiskStatus` (Identity Protection) captures sign-in anomalies and AI-driven signals. Uses both because **they are independent engines** — a user can have RiskScore=93 with Remediated IdP status, or RiskScore=0 with High/AtRisk IdP status. `AADUserRiskEvents` enriches with the specific detections explaining *why* they're flagged.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let lookback = 7d;
// Layer 1: IdentityInfo — hybrid filter (Defender RiskScore + IdP RiskLevel/Status + Criticality)
let IdentityPosture = IdentityInfo
| where Timestamp > ago(lookback)
| summarize arg_max(Timestamp, *) by AccountUpn
| where RiskScore >= 71
    or RiskLevel in ("High", "Medium")
    or RiskStatus in ("AtRisk", "ConfirmedCompromised")
    or CriticalityLevel >= 3;
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
| join hint.strategy=broadcast kind=leftouter (UserRiskEvents) 
    on $left.AccountUpn == $right.UserPrincipalName
| extend 
    DisplayName = coalesce(AccountDisplayName, AccountName, AccountUpn),
    PortalUrl = strcat("https://security.microsoft.com/user?",
        case(
            isnotempty(AccountObjectId), strcat("aad=", AccountObjectId, "&upn=", AccountUpn),
            isnotempty(OnPremSid), strcat("sid=", OnPremSid, "&accountName=", AccountName,
                                         "&accountDomain=", AccountDomain),
            isnotempty(AccountUpn), strcat("upn=", AccountUpn),
            ""),
        "&tab=overview")
| project DisplayName, PortalUrl, RiskScore, RiskLevel, RiskStatus, CriticalityLevel,
    RiskDetections = coalesce(RiskDetections, long(0)),
    HighCount = coalesce(HighCount, long(0)),
    TopRiskEventTypes, TopCountries, LatestDetection
| order by RiskScore desc, HighCount desc, RiskDetections desc, CriticalityLevel desc
| take 15
```

**Purpose:** `RiskScore` (int, 0-100) is the Defender XDR composite score on `IdentityInfo` — factors include alert chains, MITRE stage progression, and asset criticality. Portal thresholds: 71-90 = High, 91-100 = Critical. `RiskLevel`/`RiskStatus` are Identity Protection signals (sign-in anomalies, leaked creds, AI signals) — a separate engine that doesn't always agree with RiskScore. The hybrid `OR` filter ensures users flagged by either engine surface. Users with both signals firing are highest priority (corroborated).

**Output columns:** `DisplayName` (linked to Defender XDR Identity page via `PortalUrl`), `RiskScore` (0-100, primary sort), `RiskLevel`, `RiskStatus`, `CriticalityLevel`, `RiskDetections` (count), `HighCount`, `TopRiskEventTypes`, `TopCountries`, `LatestDetection`.

**Portal URL resolution:** Three-tier fallback for identity environment coverage:
- Cloud/Hybrid (has Entra ObjectId): `aad=<ObjectId>&upn=<UPN>`
- On-prem AD (SID only, no Entra sync): `sid=<SID>&accountName=<Name>&accountDomain=<Domain>`
- External IdP (UPN only, e.g., CyberArk/Okta): `upn=<UPN>`

**Report rendering:** Show top 10 users in the dashboard table. Use `DisplayName` as clickable link text with `PortalUrl` as the target. If >10 results, note `"+N more — drill down with user-investigation skill"`. For each user, render `RiskScore` and `TopRiskEventTypes` as the key risk indicators.

**Verdict logic:**
- 🔴 Escalate: Any user with `RiskScore >= 91`, or `ConfirmedCompromised` status, or `HighCount > 3`, or multiple users with `HighCount > 0`
- 🟠 Investigate: `RiskScore >= 71`, or `HighCount > 0` for any user, or any user `AtRisk` with risk events indicating `aiCompoundAccountRisk`, `impossibleTravel`, or `maliciousIPAddress`
- 🟡 Monitor: Only `Medium` risk users with low-severity risk event types (e.g., `unfamiliarFeatures`)
- ✅ Clear: 0 users matching the hybrid filter

**⚠️ Risk Event Type Routing Guard (Phase 4 drill-down):**
- `suspiciousAuthAppApproval` → **T1621 MFA Fatigue** (suspicious Authenticator push approval patterns), **NOT** OAuth app consent. Route to `user-investigation` or `authentication-tracing`. **NEVER** recommend `app-registration-posture` based on this risk event alone
- `mcasSuspiciousInboxManipulationRules` → T1114.003 email exfiltration via inbox rules. Route to `user-investigation` with OfficeActivity drill-down

---

### Query 4: Password Spray / Brute-Force Detection

🔐 **Auth spray detection (T1110.003 / T1110.001)** — Identifies IPs targeting multiple users with failed auth across Entra ID cloud sign-ins AND RDP/SSH/network logons on endpoints.

**Tool:** `RunAdvancedHuntingQuery`

```kql
// Step 1: Count spray-specific failures per IP (materialized — referenced twice)
let SprayFailures = materialize(EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode in (50126, 50053, 50057)
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(AccountUpn),
    SampleTargets = make_set(AccountUpn, 5),
    FailedApps = make_set(Application, 3),
    Countries = make_set(Country, 3)
    by SourceIP = IPAddress
| where TargetUsers >= 5);
// Step 2: Get full traffic profile for flagged IPs (success context)
let IPTrafficProfile = EntraIdSignInEvents
| where Timestamp > ago(7d)
| where IPAddress in ((SprayFailures | project SourceIP))
| summarize
    TotalSignIns = count(),
    Successes = countif(ErrorCode == 0),
    TotalDistinctUsers = dcount(AccountUpn),
    TotalDistinctApps = dcount(Application)
    by SourceIP = IPAddress;
// Step 3: Join and filter — eliminate shared infrastructure false positives
let EntraResults = SprayFailures
| join kind=inner IPTrafficProfile on SourceIP
| extend 
    SprayRatio = round(FailedAttempts * 100.0 / max_of(TotalSignIns, 1), 1),
    SuccessRate = round(Successes * 100.0 / max_of(TotalSignIns, 1), 1)
| where SprayRatio >= 1.0 and TotalDistinctApps < 50
| extend Surface = "Entra ID"
| project SourceIP, FailedAttempts, TargetUsers, SampleTargets, 
    Protocols = FailedApps, Countries, Surface,
    TotalSignIns, Successes, SprayRatio, SuccessRate, TotalDistinctApps;
// Endpoint brute-force (unchanged — no success context available)
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
| extend Surface = "Endpoint (RDP/SSH)",
    TotalSignIns = FailedAttempts, Successes = long(0), 
    SprayRatio = 100.0, SuccessRate = 0.0, TotalDistinctApps = long(0);
union EntraResults, EndpointBrute
| order by SprayRatio desc, TargetUsers desc, FailedAttempts desc
| take 15
```

**Purpose:** Detects password spray (1 IP → many users, MITRE T1110.003) and brute-force (1 IP → high failure count, T1110.001) across two surfaces, with **shared infrastructure false-positive filtering**:
- **Entra ID:** Uses `EntraIdSignInEvents` (Advanced Hunting) which merges interactive + non-interactive sign-ins into a single table. Error codes: 50126=bad password, 50053=locked account, 50057=disabled account. The query enriches failure data with the IP's full traffic profile to compute `SprayRatio` (spray failures ÷ total sign-ins) and `TotalDistinctApps`. Two filters eliminate corporate proxies, VPN concentrators, and Azure gateways:
  - **`SprayRatio >= 1.0`** — spray failures must be ≥1% of the IP's total sign-in volume. A proxy with 500K sign-ins and 77 spray errors → 0.01% → filtered. A pure attacker with 77 failures and 0 successes → 100% → kept.
  - **`TotalDistinctApps < 50`** — IPs serving 50+ distinct applications are shared infrastructure. Real spray targets 1–3 apps.
- **Endpoint:** RDP (`RemoteInteractive`) and SSH/SMB (`Network`) failed logons on MDE-enrolled devices. Threshold of ≥10 failures. No success context available in DeviceLogonEvents for filtering.

**Output columns:** `SourceIP`, `FailedAttempts`, `TargetUsers`, `SampleTargets`, `Protocols`, `Countries`, `Surface`, `TotalSignIns`, `Successes`, `SprayRatio`, `SuccessRate`, `TotalDistinctApps`. The `SprayRatio` and `TotalDistinctApps` columns provide immediate false-positive triage context.

**Verdict logic:**
- 🔴 Escalate: Any IP targeting >25 Entra users OR >100 endpoint failures from a single IP
- 🟠 Investigate: Any spray/brute-force pattern detected (meets thresholds)
- 🟡 Monitor: Spray activity detected but below thresholds (e.g., single IP with 3–4 target users, or <10 endpoint failures)
- ✅ Clear: 0 results — no spray/brute-force patterns detected

**Drill-down:** Use `user-investigation` skill for targeted users, `ioc-investigation` for source IPs.

---

### Query 5: SPN Behavioral Drift (90d Baseline vs 7d Recent)

🤖 **Automation monitoring** — Composite drift score across 5 dimensions for service principals, with IPv6 subnet normalization and IPDrift cap.

**Tool:** `mcp_sentinel-data_query_lake` (needs >30d lookback)

```kql
let BL_Start = ago(97d); let BL_End = ago(7d);
let RC_Start = ago(7d); let RC_End = now();
let BL = AADServicePrincipalSignInLogs
| where TimeGenerated between (BL_Start .. BL_End)
| extend NormalizedIP = case(
    IPAddress has ":", strcat_array(array_slice(split(IPAddress, ":"), 0, 3), ":"),
    IPAddress)
| summarize 
    BL_Vol = count(),
    BL_Res = dcount(ResourceDisplayName),
    BL_IPs = dcount(NormalizedIP),
    BL_Loc = dcount(Location),
    BL_Fail = dcountif(ResultType, ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName;
let RC = AADServicePrincipalSignInLogs
| where TimeGenerated between (RC_Start .. RC_End)
| extend NormalizedIP = case(
    IPAddress has ":", strcat_array(array_slice(split(IPAddress, ":"), 0, 3), ":"),
    IPAddress)
| summarize 
    RC_Vol = count(),
    RC_Res = dcount(ResourceDisplayName),
    RC_IPs = dcount(NormalizedIP),
    RC_Loc = dcount(Location),
    RC_Fail = dcountif(ResultType, ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName;
RC | join kind=inner BL on ServicePrincipalId
| extend 
    VolDrift = round(RC_Vol * 100.0 / max_of(BL_Vol, 10), 0),
    ResDrift = round(RC_Res * 100.0 / max_of(BL_Res, 3), 0),
    IPDriftRaw = round(RC_IPs * 100.0 / max_of(BL_IPs, 3), 0),
    IPDrift = min_of(round(RC_IPs * 100.0 / max_of(BL_IPs, 3), 0), 300),
    LocDrift = round(RC_Loc * 100.0 / max_of(BL_Loc, 2), 0),
    FailDrift = round(RC_Fail * 100.0 / max_of(BL_Fail, 5), 0)
| extend DriftScore = round((VolDrift*0.20 + ResDrift*0.25 + IPDrift*0.25 + LocDrift*0.15 + FailDrift*0.15), 0)
| where DriftScore > 120
| order by DriftScore desc
| take 10
```

**Purpose:** Identifies service principals with significant behavioral changes from their 90-day baseline.

**Tuning notes:**
- **IPv6 /64 normalization:** IPv6 addresses are collapsed to their /64 prefix before counting. Azure PaaS services (Copilot Studio, Playbook Automation) rotate through dozens of `fd00:` ULA pod addresses within the same cluster — without normalization, each pod IP inflates IPDrift by hundreds of percent.
- **IPDrift cap (300%):** `IPDriftRaw` shows the true ratio; `IPDrift` is capped to prevent IP-only spikes from dominating. Transparent when IPv4-only SPNs have genuine expansion.
- **Weights:** Volume 20%, Resources 25%, IPs 25%, Locations 15%, Failure Rate 15%.

**Verdict logic:**
- 🔴 Escalate: Any SPN with `DriftScore > 250` or `IPDriftRaw > 400%`
- 🟠 Investigate: `DriftScore > 150`
- 🟡 Monitor: `DriftScore 120–150`
- ✅ Clear: No SPNs above threshold

**Drill-down:** Use `scope-drift-detection/spn` skill for full investigation of flagged SPNs.

---

### Query 6: Fleet-Wide Device Process Drift

💻 **Endpoint behavioral baseline** — Per-device drift scores computed in-query (7d baseline vs 1d recent), with infrastructure noise filtering and VolDrift cap to prevent automation-driven false positives.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where not(
    InitiatingProcessFileName in ("gc_worker", "gc_linux_service", "dsc_host")
    or (InitiatingProcessFileName == "dash" and InitiatingProcessParentFileName in ("gc_worker", "gc_linux_service"))
  )
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
    VolDriftRaw = round(RC_Events * 600.0 / max_of(BL_Events, 1), 0),
    VolDrift = min_of(round(RC_Events * 600.0 / max_of(BL_Events, 1), 0), 300),
    ProcDrift = round(RC_Procs * 100.0 / max_of(BL_Procs, 1), 0),
    AcctDrift = round(RC_Accts * 100.0 / max_of(BL_Accts, 1), 0),
    ChainDrift = round(RC_Chains * 100.0 / max_of(BL_Chains, 1), 0),
    CompDrift = round(RC_Comps * 100.0 / max_of(BL_Comps, 1), 0)
| extend DriftScore = round(VolDrift * 0.30 + ProcDrift * 0.25 + ChainDrift * 0.20 + AcctDrift * 0.15 + CompDrift * 0.10, 0)
| order by DriftScore desc
| take 10
| project DeviceName, DriftScore, VolDriftRaw, VolDrift, ProcDrift, AcctDrift, ChainDrift, CompDrift
```

**Purpose:** Returns the top 10 devices ranked by composite drift score, pre-computed in KQL. No LLM-side math required — just interpret the returned scores.

**Tuning notes:**
- **GC filter:** Excludes Azure Guest Configuration (`gc_worker`, `gc_linux_service`, `dsc_host`) and their child shell chains. Transparent on Windows (<1% impact).
- **VolDrift cap (300%):** `VolDriftRaw` shows the true ratio; `VolDrift` is capped via `min_of()` so volume-only spikes don't dominate. When `VolDriftRaw` ≫ 300 but diversity metrics are ~100, it's infrastructure noise. When both are elevated, high-confidence anomaly.
- **Volume (`VolDrift`):** `RC * 600 / BL` normalizes to per-day rate (100 × 6 baseline days), then caps at 300%.
- **Dcount metrics:** `RC_Dim * 100 / BL_Dim` — compared directly (distinct counts don't scale linearly with time). 100% = normal, >100% = new values appeared.
- **Weights:** Volume 30%, Processes 25%, Chains 20%, Accounts 15%, Companies 10%.

**Verdict logic:** See [Device Drift Score Interpretation](#device-drift-score-interpretation-q6) in Post-Processing for the full scale, VolDrift cap context, and fleet-uniformity rule.

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

🔑 **Cloud ops monitoring** — Detects mailbox rule manipulation, transport rule changes, mailbox delegation, programmatic mailbox access (API), MCAS-flagged compromised sign-ins, and human-initiated Conditional Access policy changes via CloudAppEvents.

**Tool:** `RunAdvancedHuntingQuery`

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    // Exchange — Mail flow manipulation
    "New-InboxRule", "Set-InboxRule", "Set-Mailbox",
    "Add-MailboxPermission", "New-TransportRule", "Set-TransportRule", "New-Mailbox",
    // Exchange — Anti-forensic & Data Access
    "Remove-MailboxPermission", "Remove-InboxRule",
    "MailItemsAccessed", "Send",
    // Conditional Access manipulation (human-initiated only)
    "Set-ConditionalAccessPolicy", "New-ConditionalAccessPolicy",
    // Compromise signals
    "CompromisedSignIn"
)
// Filter out system/automation-driven CA changes (CA agent, backup policies)
| where not(ActionType in ("Set-ConditionalAccessPolicy", "New-ConditionalAccessPolicy") 
            and isempty(AccountDisplayName))
// Extract client context for Exchange data access events
| extend ParsedData = parse_json(RawEventData)
| extend ClientInfo = tostring(ParsedData.ClientInfoString)
// Filter out Exchange Online system-level REST operations (first-party backend mail flow/compliance)
// RESTSystem = Microsoft internal service identity; Client=REST without System = user/app API access
| where not(ActionType in ("MailItemsAccessed", "Send") and ClientInfo has "RESTSystem")
| extend Category = case(
    ActionType == "MailItemsAccessed" and ClientInfo has "Client=REST", "Mailbox Read (API)",
    ActionType == "Send" and ClientInfo has "Client=REST", "Mail Send (API)",
    ActionType == "MailItemsAccessed", "Mailbox Read (Client)",
    ActionType == "Send", "Mail Send (Client)",
    ActionType in ("New-InboxRule", "Set-InboxRule", "Remove-InboxRule",
                   "Set-Mailbox", "Add-MailboxPermission", "Remove-MailboxPermission",
                   "New-TransportRule", "Set-TransportRule", "New-Mailbox"),
    "Exchange Admin/Rule Change",
    ActionType in ("Set-ConditionalAccessPolicy", "New-ConditionalAccessPolicy"),
    "Conditional Access Change",
    ActionType == "CompromisedSignIn",
    "Compromised Sign-In",
    "Other")
| summarize
    Count = count(),
    UniqueActors = dcount(AccountDisplayName),
    TopActors = make_set(AccountDisplayName, 5),
    Actions = make_set(ActionType, 5),
    LatestTime = max(Timestamp)
    by Category
| order by Count desc
```

**Purpose:** Five-category view of cloud app activity invisible to Q10 (AuditLogs). Key non-obvious details: `ClientInfoString` in `RawEventData` distinguishes API access (`Client=REST` = Graph API programmatic) from interactive clients (MAPI-RPC, OWA) — API-driven mailbox reads by human accounts = potential BEC. `CompromisedSignIn` is an MCAS signal independent from Q3's Identity Protection risk events — dual-source corroboration when both fire. CA changes with empty `AccountDisplayName` are system/agent-driven and filtered out.

**Verdict logic:**
- 🔴 Escalate: `Compromised Sign-In` with 5+ users, OR `Mailbox Read (API)` from non-service-accounts, OR `Conditional Access Change` by any human actor, OR `Exchange Admin/Rule Change` with forwarding-related rules (`New-InboxRule`, `Set-InboxRule`, `New-TransportRule`)
- 🟠 Investigate: `Compromised Sign-In` (any count), OR `Mail Send (API)` from unexpected actors, OR `Remove-InboxRule` / `Remove-MailboxPermission` (anti-forensic cleanup signals)
- 🟡 Monitor: Only `Mailbox Read (Client)` or `Mail Send (Client)` activity, OR low-count `Set-Mailbox` from system actors
- ✅ Clear: 0 results across all categories

**Drill-down:** Use `user-investigation` skill for actors in `Compromised Sign-In`, `Mailbox Read (API)`, or `Mail Send (API)` categories. Use `ca-policy-investigation` skill for `Conditional Access Change` findings. **⚠️ When drilling down on ANY Exchange-related Q9 finding, ALWAYS also query `OfficeActivity` (Exchange workload)** — CloudAppEvents and OfficeActivity are **complementary, not alternatives**. CloudAppEvents captures ActionType-based summaries and `AccountDisplayName`, but OfficeActivity provides the full `Parameters` JSON (forwarding targets: `ForwardTo`, `RedirectTo`, `ForwardingSmtpAddress`), per-operation `ClientIP`, and a broader set of Exchange audit operations — including `MoveToDeletedItems` (evidence destruction), `SoftDelete`/`HardDelete`, and `MailboxLogin` — that reveal post-compromise persistence, exfiltration, and lateral phishing patterns CloudAppEvents alone cannot surface. Query pattern: `OfficeActivity | where TimeGenerated > ago(Nd) | where OfficeWorkload == "Exchange" | where UserId =~ '<UPN>' | project TimeGenerated, Operation, ClientIP, Parameters, SessionId | order by TimeGenerated desc`. See `queries/email/email_threat_detection.md` for verified OfficeActivity query patterns.

---

### Query 10: High-Impact Privileged Operations

🔑 **Admin activity monitoring** — Category-aggregated view of privileged operations: role assignments, PIM activations, credential lifecycle, consent grants, CA policy changes, password management, MFA registration, app registration, and ownership grants.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let PrivOps = AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any (
    "role", "credential", "consent", "Conditional Access", "password", "certificate",
    "security info", "owner", "application"
)
| where Result == "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
// Exclude system-driven CA policy additions (empty actor = CA agent)
| where not(OperationName has "conditional access" and isempty(Actor))
| extend Target = tostring(TargetResources[0].displayName)
| extend Category = case(
    OperationName has "security info", "MFA-Registration",
    OperationName has "owner", "Ownership",
    OperationName has "application", "AppRegistration",
    OperationName has "role", "RoleManagement",
    OperationName has "credential" or OperationName has "certificate", "Credentials",
    OperationName has "consent", "Consent",
    OperationName has "Conditional Access", "ConditionalAccess",
    OperationName has "password", "Password",
    "Other");
PrivOps
| summarize 
    Count = count(),
    UniqueActors = dcount(Actor),
    TopActors = make_set(Actor, 5),
    Operations = make_set(OperationName, 5),
    Targets = make_set(Target, 5),
    LatestTime = max(TimeGenerated)
    by Category
| order by Count desc
```

**Purpose:** Category-level aggregation ensures all 8 privilege domains surface regardless of volume distribution (previous per-actor aggregation was truncated at 15 rows, hiding MFA-Registration, Ownership, and AppRegistration). Key non-obvious details: `MFA-Registration` deletion + re-registration by same user = credential takeover (T1556.006). `Ownership` grants to external accounts = persistence (T1098). System-driven CA additions (empty Actor) are filtered out. `Password` category is high-volume by nature — flag single-actor bulk resets, not self-service.

**Verdict logic:**
- 🔴 Escalate: `MFA-Registration` deletions + registrations for same user (method swap attack), OR `Consent` grants from unexpected actors, OR `Ownership` grants to external accounts, OR `ConditionalAccess` changes by non-admin actors, OR `AppRegistration` with secrets management from external domains
- 🟠 Investigate: `MFA-Registration` from CTF/external accounts, OR `RoleManagement` targeting Global Admin / Security Admin roles, OR `AppRegistration` consent operations, OR `Password` with bulk admin resets (single actor, 10+ targets)
- 🟡 Monitor: Normal PIM activations and expirations, self-service password resets, credential lifecycle (WHfB/passkey registration)
- ✅ Clear: 0 results or only system-driven operations with expected volume

---

### Query 11: Critical Assets with Verified Internet Exposure

🛡️ **Attack surface** — Combines ExposureGraph critical asset inventory with MDE's authoritative `DeviceInfo.IsInternetFacing` classification to identify verified internet-exposed critical assets.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let InternetFacing = DeviceInfo
    | where Timestamp > ago(7d)
    | where IsInternetFacing == true
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceName,
        Reason = extractjson("$.InternetFacingReason", AdditionalFields, typeof(string)),
        PublicIP = extractjson("$.InternetFacingPublicScannedIp", AdditionalFields, typeof(string)),
        ExposedPort = extractjson("$.InternetFacingLocalPort", AdditionalFields, typeof(int));
let CriticalAssets = ExposureGraphNodes
    | where set_has_element(Categories, "device")
    | where isnotnull(NodeProperties.rawData.criticalityLevel)
    | extend critLevel = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
    | where critLevel < 4
    | project DeviceName = NodeName, CriticalityLevel = critLevel,
        ExposureScore = tostring(NodeProperties.rawData.exposureScore);
CriticalAssets
| join kind=leftouter InternetFacing on DeviceName
| extend IsVerifiedExposed = isnotempty(PublicIP) or isnotempty(Reason)
| project DeviceName, CriticalityLevel, IsVerifiedExposed,
    Reason, PublicIP, ExposedPort, ExposureScore
| order by IsVerifiedExposed desc, CriticalityLevel asc
| take 25
```

**Purpose:** Returns the critical asset inventory (criticality 0–3) enriched with MDE's authoritative internet-facing classification. `DeviceInfo.IsInternetFacing` is confirmed via Microsoft external scans or observed inbound connections and auto-expires after 48h — far more reliable than ExposureGraph properties like `isCustomerFacing` (business flag) or `rawData.IsInternetFacing` (not populated in many environments). See [MS Docs](https://learn.microsoft.com/en-us/defender-endpoint/internet-facing-devices#use-advanced-hunting) and `queries/network/internet_exposure_analysis.md` Query 1 for the canonical reference.

**`IsVerifiedExposed` logic:** Checks BOTH `PublicIP` (populated for `PublicScan` — Microsoft external scanner) AND `Reason` (populated for `ExternalNetworkConnection` — observed inbound traffic). The original `isnotempty(PublicIP)` missed `ExternalNetworkConnection` exposures where MDE confirms inbound connections but doesn't populate the scanned public IP field.

**Verdict logic:**
- 🔴 Escalate: Any `IsVerifiedExposed == true` with `CriticalityLevel == 0` (internet-facing domain controller/CA)
- 🟠 Investigate: Any `IsVerifiedExposed == true` (internet-facing critical asset)
- 🟡 Monitor: Critical assets exist but none verified internet-facing
- ✅ Clear: All critical assets properly segmented, no internet exposure

---

### Query 12: Exploitable CVEs (CVSS ≥ 8.0) Across Fleet

🛡️ **Vulnerability patch priority** — Top exploitable critical CVEs with affected device count.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where IsExploitAvailable == true
    | where CvssScore >= 8.0
) on CveId
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
| 80–120 | Stable (fleet median range — validated across 90d in 2 environments) | ✅ Clear |
| 120–150 | Minor behavioral expansion (2-17% of fleet weekly) | 🟡 Monitor |
| 150–200 | Significant deviation (0-5% of fleet weekly) | 🟠 Investigate |
| 200+ | Major anomaly (<1% of fleet weekly across 90d validation) | 🔴 Escalate |

**VolDrift cap context:** `VolDriftRaw` is projected alongside the capped `VolDrift`. When interpreting results:
- If `VolDriftRaw` ≫ 300 but ProcDrift/ChainDrift/AcctDrift are near 100: **infrastructure volume spike** (GC, patching, agent restart) — low concern despite high raw volume.
- If `VolDriftRaw` > 300 AND ProcDrift/ChainDrift/AcctDrift are also elevated: **genuine multi-dimensional anomaly** — high confidence finding.
- If `VolDriftRaw` ≤ 300: cap was not triggered — score reflects true proportions.

**Fleet-uniformity rule:** If ALL top-10 devices cluster within 20 points of each other, the fleet is behaving uniformly and the verdict should be downgraded one level. Drift is most meaningful when individual devices diverge from the fleet cluster.

**⛔ DO NOT manually recompute drift scores.** The KQL query handles Volume normalization (÷6 baseline days), VolDrift capping (at 300%), GC infrastructure filtering, and dcount comparison (direct ratio). Trust the returned `DriftScore` column.

### Cross-Query Correlation

After all queries complete, check these correlation patterns and escalate priority when found:

| Pattern | Queries | Implication | Action |
|---------|---------|-------------|--------|
| Incident account matches risky identity | Q1 `Accounts` ∩ Q3 `AccountUpn` | Incident involves user already flagged AtRisk/Compromised — corroborated signal | Escalate to 🔴 |
| Incident device matches drifting endpoint | Q1 `Devices` ∩ Q6 `DeviceName` | Incident target has behavioral anomalies on endpoint | Escalate to 🔴 |
| Incident device has exploitable CVE | Q1 `Devices` ∩ Q12 `DeviceName` | Incident device is vulnerable to active exploitation | Escalate to 🔴 |
| Spray target already in incident | Q4 targets ∩ Q1 `Accounts` | Spray target is already involved in an active incident | Escalate to 🔴 |
| SPN drift AND unusual credential/consent activity | Q5 + Q10 | App credential abuse / persistence | Escalate to 🔴 |
| Device with rare process chain AND exploitable CVE | Q7 + Q12 | Potential active exploitation | Escalate to 🔴 |
| Spray IP target already flagged as risky | Q4 + Q3 | Spray target has active Identity Protection risk | Escalate to 🔴 |
| Closed TP tactics match active findings | Q2 + Q3/Q7/Q8 | Same attack pattern recurring despite recent closures | Escalate to 🟠, note recurrence |
| Mailbox rule manipulation AND email threats | Q9 + Q8 | Potential email exfiltration setup following phishing | Escalate to 🔴 |
| Compromised Sign-In user matches risky identity | Q9 `Compromised Sign-In` ∩ Q3 `AccountUpn` | MCAS compromise + Identity Protection risk — dual-signal corroboration | Escalate to 🔴 |
| Compromised Sign-In user has Mailbox Read (API) | Q9 `Compromised Sign-In` ∩ Q9 `Mailbox Read (API)` | Compromised account actively exfiltrating email via API — BEC kill chain | Escalate to 🔴 |
| Compromised Sign-In user in open incident | Q9 `Compromised Sign-In` ∩ Q1 `Accounts` | MCAS compromise detection overlaps active incident entities | Escalate to 🔴 |
| MFA registration from spray target | Q10 `MFA-Registration` ∩ Q4 spray targets | Attacker completing MFA enrollment after successful spray — T1556.006 | Escalate to 🔴 |
| MFA registration from risky user | Q10 `MFA-Registration` ∩ Q3 `AccountUpn` | Risky user registering new auth methods — potential credential takeover | Escalate to 🔴 |
| App registration + SPN drift | Q10 `AppRegistration` ∩ Q5 SPN drift | New app + expanding SPN footprint = T1098.001 app-based persistence | Escalate to 🔴 |
| CA policy change + spray/compromise activity | Q9 `Conditional Access Change` + Q4 or Q9 `Compromised Sign-In` | Defense weakened during active attack | Escalate to 🔴 |
| Mailbox Read (API) user has inbox rule changes | Q9 `Mailbox Read (API)` ∩ Q9 `Exchange Admin/Rule Change` | Programmatic read + forwarding rule = full exfiltration chain (T1114.003) | Escalate to 🔴 |
| Phishing recipient is risky user | Q8 delivered phishing ∩ Q3 `AccountUpn` | Credential harvesting targeting already-compromised or at-risk user — AiTM chain indicator | Escalate to 🔴 |
| DLP/exfiltration incident + API mailbox access | Q1 Exfiltration tactic ∩ Q9 `Mailbox Read (API)` | Incident-level exfiltration alert + active API data access — data loss in progress | Escalate to 🔴 |
| Role management + SPN drift by same actor | Q10 `RoleManagement` same actor ∩ Q5 SPN drift | Role escalation + expanding app footprint = app-based persistence (T1098) | Escalate to 🔴 |

---

## Query File Recommendations

Use the **discovery manifest** (`.github/manifests/discovery-manifest.yaml`) to match findings to downstream query files and skills. Contains `title`, `path`, `domains`, `mitre`, and `prompt` only (~500 lines). Auto-generated by `python .github/manifests/build_manifest.py`.

Tier depth follows the Rule 8 table — skip entirely when all verdicts are ✅.

### Domain-to-Query Mapping

Each threat-pulse query group maps to a domain tag. Non-✅ domains drive manifest lookups:

| Query Group | Domain Tag |
|-------------|-----------|
| Q1, Q2 (Incidents) | `incidents` |
| Q3, Q4 (Identity) | `identity` |
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
   - **Secondary:** MITRE technique overlap — compare technique IDs from Q1/Q2 `Techniques` arrays (e.g., `T1566`, `T1078`) directly against the manifest entry's `mitre` field. Exact string match — no tactic-to-technique translation needed
   - **Tertiary:** Keyword overlap — match entity names, process names, CVE IDs, or ActionTypes from findings against manifest entry titles and paths
5. **Select top N:** 🔴/🟠 verdicts: 3–5 files. 🟡-only: 1–2 files
6. **Format links:** Use the `title` and `path` from the manifest entry to build clickable links (see [Report Output Block](#report-output-block) below for format)

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
2. **Dashboard Summary:** 12-row table — one row per query (Q1, Q2, Q3, Q4–Q12), columns: `#`, `Domain`, `Status` (verdict emoji), `Key Finding` (1-line). Verdicts: 🔴 Escalate | 🟠 Investigate | 🟡 Monitor | ✅ Clear | 🔵 Informational | ❓ No Data
3. **Detailed Findings:** One section per query — EVERY query gets a section (no skipping). Data tables (max 10 rows inline, unlimited in file). Q1 incidents must include `[#<id>](https://security.microsoft.com/incidents/<ProviderIncidentId>)` links. Q2 closed summary always renders after Q1.
4. **Cross-Query Correlations:** Table of correlated findings per Post-Processing rules, or `✅ No correlations detected`.
5. **🎯 Recommended Actions:** Prioritized table with action, trigger query, and drill-down skill.
6. **📂 Recommended Query Files:** Per the Report Output Block procedure above. For 🟡-only verdicts, use "📂 Proactive Hunting Suggestions" header instead. Omit entirely when all ✅.

**Q1 column format:** `| Incident | Title | Age | Alerts | Owner | Tactics | Accounts | Devices | Tags |` — Unassigned shows `⚠️ Unassigned`. `Age` uses relative time from `AgeDisplay` (e.g., "3m ago", "2h ago", "1d ago"). `Accounts`, `Devices`, and `Tags` are entity/label arrays (max 5 each) — render inline as comma-separated values.

**Q2 closed summary:** Classification breakdown table + severity + MITRE tactics/techniques from TP closures. Always render even when Q1 is ✅.

**Zero results format:** `✅ No <type> detected in the last <N>d. Checked: <table> (0 matches)`

**❓ No Data verdict:** Assigned when a query returns a table resolution error (table doesn't exist in workspace) or the query times out. Report the error message and the table that failed. Treat as an investigation gap — the domain is unmonitored.

**🔵 Informational verdict:** Used by Q2 (0 closed incidents) and Q6 (DriftScore < 80, contracting activity). Maps to a neutral row in the Dashboard Summary — no action needed but context is included.

**Markdown file extras:** Full data tables (no row limits), full command-line samples, full CVE lists.

---

## Markdown File Report Template

**This template is used when the user selects `💾 Save full investigation report` in Phase 4.** It produces a single markdown file that weaves together the initial Threat Pulse scan AND all subsequent drill-down investigations into a cohesive narrative.

**Source data:** Original pulse query results (from context) + `/memories/session/threat-pulse-drilldowns.md` (accumulated drill-down findings). If context was compacted and drill-down details are lost, the session memory file is the authoritative source for drill-down findings.

### File Structure

```markdown
# 🔍 Threat Pulse — Full Investigation Report
**Workspace:** <name> (`<id>`)  
**Scan Date:** <YYYY-MM-DD HH:MM UTC>  
**Report Generated:** <YYYY-MM-DD HH:MM UTC>  
**Scan Duration:** <N>min | **Queries:** 12 | **Drill-Downs:** <N>  

---

## Executive Summary

<2-4 sentence narrative synthesizing the OVERALL investigation — pulse findings + all drill-down discoveries. 
Highlight the most critical finding, whether it came from the initial scan or a drill-down.
State the final risk posture incorporating all evidence gathered.>

## Dashboard Summary

<Same 12-row verdict table as inline report — Q1, Q2, Q3, Q4-Q12>

## Detailed Findings

<Same per-query sections as inline report — every query gets a section>

## Cross-Query Correlations

<Same as inline report — correlations from the 12 pulse queries>

## Drill-Down Investigation Results

<One subsection per drill-down, in execution order. NOT raw dumps — structured summaries 
that reference back to the triggering pulse query and forward to other drill-downs.>

### 1. <Drill-Down Title> — <Skill Name>

**Triggered by:** Q<N> — <original finding from pulse>  
**Entity:** <target>  
**Lookback:** <timerange, note if expanded beyond 7d>  
**Risk Assessment:** <emoji> <level>

**Key Findings:**
- <Most important finding — specific, evidence-cited>
- <Second finding>
- ...(prioritized, max 8)

**Evidence Summary:**
<1-2 paragraph narrative of what was discovered, with specific numbers and identifiers.
Link back to pulse queries where findings corroborate or expand on initial data.>

**Recommendations:**
1. <Action item from this drill-down>
2. ...

---

### 2. <Next Drill-Down Title> — <Skill Name>
...(same structure)

## Cross-Investigation Correlation

<This section is the KEY differentiator from individual reports. Synthesize connections 
discovered ACROSS drill-downs — patterns that only become visible when looking at the 
full investigation as a whole.>

| Connection | Evidence | Drill-Downs | Implication |
|-----------|----------|-------------|-------------|
| <pattern> | <specific data points from 2+ investigations> | #1 + #3 | <what this means> |

<Narrative paragraph explaining the most significant cross-investigation insight.
Example: "The device investigation (#1) revealed 31 inbound RDP connections from 15 unique IPs, 
while the IoC investigation (#3) confirmed IP 20.114.11.113 as an automated brute-force source. 
The exposure investigation (#2) showed the device has 102 unpatched CVEs including critical OpenSSL 
vulnerabilities in Azure extensions, meaning a successful RDP compromise could leverage these 
for lateral movement.">

If no cross-investigation connections exist: `✅ No cross-investigation correlations identified — each finding is independent.`

## Consolidated Recommendations

<Merge and deduplicate recommendations from ALL sources — pulse + drill-downs.
Prioritize by risk level and actionability. Group by theme (e.g., Identity, Endpoint, Exposure).>

| Priority | Recommendation | Source | Risk |
|----------|---------------|--------|------|
| 🔴 1 | <action> | Q<N> + Drill-Down #<N> | <level> |
| 🟠 2 | <action> | Drill-Down #<N> | <level> |
| ... | ... | ... | ... |

## 📂 Recommended Query Files

<Same as inline report — manifest-driven query file recommendations>

## Appendix: Investigation Timeline

| Time | Action | Key Result |
|------|--------|-----------|
| <HH:MM> | Threat Pulse scan started | 12 queries across 7 domains |
| <HH:MM> | Scan complete | <N> 🔴, <N> 🟠, <N> 🟡, <N> ✅ |
| <HH:MM> | Drill-Down #1: <title> | <1-line result> |
| ... | ... | ... |
| <HH:MM> | Report saved | reports/threat-pulse/<filename>.md |
```

### Template Rules

1. **Executive Summary is mandatory** — it must synthesize across ALL investigations, not just the pulse. If drill-downs changed the risk picture, the executive summary must reflect that.
2. **Drill-Down sections are NOT raw dumps.** Each must be a structured summary with back-references to the triggering pulse query (`Triggered by: Q<N>`) and forward-references to related drill-downs.
3. **Cross-Investigation Correlation is the critical section.** This is where patterns that span multiple investigations are surfaced — connections only visible from the full investigation. If no connections exist, state that explicitly.
4. **Consolidated Recommendations deduplicates.** If the pulse and a drill-down both recommend the same action, it appears ONCE with both sources cited.
5. **Investigation Timeline provides audit trail.** Chronological log of every action taken during the session.
6. **Drill-down data priority:** Use session memory (`/memories/session/threat-pulse-drilldowns.md`) as the primary source for drill-down findings. Supplement with conversation context where available.

### Quality Checklist (Combined Report)

- [ ] Executive Summary references findings from both pulse AND drill-downs
- [ ] Every drill-down has a structured subsection (not raw output)
- [ ] Each drill-down subsection has `Triggered by: Q<N>` back-reference
- [ ] Cross-Investigation Correlation section exists (either with connections or explicit "none found")
- [ ] Consolidated Recommendations are deduplicated across all sources
- [ ] Investigation Timeline is chronologically accurate
- [ ] No fabricated data — all findings cite specific evidence

---

## Known Pitfalls

| Pitfall | Mitigation |
|---------|------------|
| Q5 takes ~35s (97d lookback) | Acceptable — runs in parallel. Only query needing Data Lake |
| Q7 capped at `ago(30d)` | AH Graph API limit. Use `queries/endpoint/rare_process_chains.md` via Data Lake for 90d |
| Q6 drift scores | Computed in-query — do NOT recompute LLM-side |
| Q9 drill-down: CloudAppEvents identity filtering | `AccountId` and `AccountObjectId` are **Entra ObjectId GUIDs**, NOT UPNs. Filtering by UPN returns 0 results silently. Use `AccountDisplayName` for display-name matching, or resolve UPN→ObjectId via Graph API first. NEVER use `tostring(RawEventData) has "UPN"` — it causes query cancellation on this high-volume table |
| Q9: `RESTSystem` false positives | Exchange Online first-party backend services use `Client=RESTSystem` in `ClientInfoString` and appear as **AppId GUIDs** in `AccountDisplayName`. These are NOT user/app API access — they are system-level mail flow, compliance scanning, or connector ingestion. Q9 filters these out; if investigating Q9 results and see GUID actors with `RESTSystem`, they are benign Microsoft internal operations |
| **🔍 Skill drill-down: ad-hoc KQL instead of loading SKILL.md** | **#1 drill-down failure mode.** Step 7 requires `read_file` of the child SKILL.md BEFORE writing any query. If no `read_file` call on a SKILL.md preceded your KQL in the current drill-down, you are hallucinating schema — stop and load the file |
| **🔍 Skill drill-down: loaded SKILL.md but rewrote queries** | **#2 failure mode.** Use SKILL.md queries **verbatim** (entity substitution only). Adding/changing columns or restructuring = schema hallucination with extra steps |
| **Drill-down query error → silent skip** | **⛔ NEVER skip.** On `SemanticError`/`Failed to resolve`: diagnose → fix → re-execute → present corrected results. Partial results with silently omitted failures are **PROHIBITED** |

> **Schema pitfalls** (column names, dynamic fields, `parse_json` patterns) are covered in `copilot-instructions.md` Known Table Pitfalls. Refer there for `SecurityAlert.Status`, `ExposureGraphNodes.NodeProperties`, timestamp columns, and `AuditLogs.InitiatedBy`.

---

## Quality Checklist

- [ ] All 12 queries executed
- [ ] Every query has a verdict row — no omissions, no skipped "clear" sections
- [ ] ✅ verdicts cite table + "0 results"; 🔴/🟠 cite specific evidence
- [ ] All incidents have clickable XDR portal URLs
- [ ] Cross-query correlations checked
- [ ] Every non-✅ drill-down has a `🎬 Take Action` block with portal-ready KQL (correct required columns per entity type)
- [ ] Every `🎬 Take Action` block includes the `⚠️ AI-generated content` warning immediately below the heading
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
