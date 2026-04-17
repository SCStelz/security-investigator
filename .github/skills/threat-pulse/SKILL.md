---
name: threat-pulse
description: 'Recommended starting point for new users and daily SOC operations. 15-minute broad security scan across 7 domains (incidents, identity, NHI, endpoint, email, admin/cloud, exposure) producing a Threat Pulse Dashboard with drill-down recommendations to specialized skills. Trigger on getting-started questions like "where do I start", "what can you do", "help me investigate".'
---

# Threat Pulse — Instructions

## Purpose

The Threat Pulse skill is a rapid, broad-spectrum security scan designed for the "if you only had 15 minutes" scenario. It executes 12 queries across 7 security domains in parallel, producing a prioritized dashboard of findings with drill-down recommendations to specialized investigation skills.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔴 **Incidents** | What incidents are open and unresolved? Prioritizes High/Critical, backfills with Medium/Low in smaller environments. How old are they? Who owns them? What was recently resolved — TP rate, MITRE tactics, severity distribution? |
| 🔐 **Identity (Human)** | Which users have the highest Defender XDR Risk Score (0-100)? Which are flagged by Identity Protection (RiskLevel/RiskStatus)? What risk events are driving the signals? Are there password spray / brute-force patterns? |
| 🤖 **Identity (NonHuman)** | Which service principals expanded their resource/IP/location footprint? |
| 💻 **Endpoint** | Which endpoints deviated most from their process behavioral baseline? What singleton process chains exist? |
| 📧 **Email Threats** | What's the phishing/spam/malware breakdown? Were any phishing emails delivered? |
| 🔑 **Admin & Cloud Ops** | What mailbox rules, OAuth consents, transport rules, or mailbox permission changes occurred? Is there programmatic mailbox access via API? Any MCAS-flagged compromised sign-ins? Human-initiated CA policy changes? Who performed high-impact admin operations — role assignments, MFA registration, app registration, ownership grants? |
| 🛡️ **Exposure** | Are any critical assets internet-facing with RCE vulnerabilities? What exploitable CVEs (CVSS ≥ 8) are present across the fleet? |

**Data sources:** `SecurityIncident`, `SecurityAlert`, `IdentityInfo`, `AADUserRiskEvents`, `EntraIdSignInEvents`, `DeviceProcessEvents`, `DeviceLogonEvents`, `ExposureGraphNodes`, `AADServicePrincipalSignInLogs`, `EmailEvents`, `CloudAppEvents`, `AuditLogs`, `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB`

**Portal URL patterns** are defined in the [Defender XDR Portal Links](#defender-xdr-portal-links--all-entity-types) table in the Take Action section. Append `tid=<tenant_id>` (from `config.json`) to ALL `security.microsoft.com` URLs — use `?tid=` or `&tid=` depending on existing query params. Omit if `tenant_id` is not configured.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)**
2. **[Execution Workflow](#execution-workflow)** — Phase 0–3
3. **[Phase 4: Interactive Follow-Up Loop](#phase-4-interactive-follow-up-loop)**
4. **[Take Action](#-take-action--portal-ready-remediation-blocks)** — Portal links, AH queries, defanging
5. **[Sample KQL Queries](#sample-kql-queries)** — 12 queries
6. **[Post-Processing](#post-processing)** — Drift scores, cross-query correlation
7. **[Query File Recommendations](#query-file-recommendations)**
8. **[Report Template](#report-template)** — Inline + full markdown file structure
9. **[Known Pitfalls](#known-pitfalls)**
10. **[Quality Checklist](#quality-checklist)**
11. **[SVG Dashboard Generation](#svg-dashboard-generation)**

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Workspace selection** — Follow the SENTINEL WORKSPACE SELECTION rule from `copilot-instructions.md`. Call `list_sentinel_workspaces()` before first query.

2. **Read `config.json`** — Load workspace ID, tenant, subscription, and Azure MCP parameters before execution.

3. **Output defaults** — Default to **inline chat** with **7d lookback**. Only ask the user for output preferences if they explicitly mention a different mode (e.g., "save to file", "markdown report", "30 day lookback"). If the user just says "threat pulse", "run a scan", or similar — proceed immediately with defaults, do not prompt.

4. **⛔ MANDATORY: Evidence-based analysis only** — Every finding must cite query results. Every "clear" verdict must cite 0 results. Follow the Evidence-Based Analysis rule from `copilot-instructions.md`.

5. **Parallel execution** — Run the Data Lake query (Q5) and all Advanced Hunting queries (Q1, Q2, Q3, Q4, Q6, Q7, Q8, Q9, Q10, Q11, Q12) simultaneously.

6. **Cross-query correlation** — After all queries complete, check for correlated findings per the [Cross-Query Correlation](#cross-query-correlation) table in Post-Processing. Escalate priority when patterns match.

7. **SecurityIncident output rule** — Every incident MUST include a clickable Defender XDR portal URL: `https://security.microsoft.com/incidents/{ProviderIncidentId}?tid=<tenant_id>`. See [Tenant ID in Portal URLs](#tenant-id-in-portal-urls--global-rule).

8. **⛔ MANDATORY: Query File Recommendations (tiered)** — After rendering the main report body (Dashboard Summary through Recommended Actions), append the [Query File Recommendations](#query-file-recommendations) section. This runs AFTER the report is visible to the user — not as a blocking gate. Skip only when ALL verdicts are ✅.

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
4. **⛔ MANDATORY: Display scan summary** — Before executing any queries, output the following brief to the user **as plain markdown text** (NOT inside a fenced code block, NOT as inline code). Use the exact heading, line breaks, and emoji-prefixed bullet items shown below. Substitute `<WorkspaceName>`, `<WorkspaceId>`, lookback, and output format. Never skip this step — it sets analyst expectations for what's about to run.

   🔍 Threat Pulse — Scan Plan

   Workspace: \<WorkspaceName\> (\<WorkspaceId\>)
   Lookback: \<N\>d
   Output: \<Inline / Markdown file / Both\>

   Executing 12 queries across 7 domains:

   🔴 Incidents — Open incidents (severity-ranked) + 7d closed summary (Q1, Q2)
   🔐 Identity — Identity risk posture, risk event enrichment, auth spray (Q3, Q4)
   🤖 NonHuman ID — Service principal behavioral drift (Q5)
   💻 Endpoint — Device process drift, rare process chains (Q6, Q7)
   📧 Email — Inbound threat snapshot (Q8)
   🔑 Admin & Cloud — Cloud app ops, privileged operations (Q9, Q10)
   🛡️ Exposure — Critical assets, exploitable CVEs (Q11, Q12)

   Data Lake: 1 query | Advanced Hunting: 11 queries in parallel
   Estimated time: ~2–4 minutes

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
| Q1 | 🔴 Incidents | Open incidents (severity-ranked backfill) with MITRE tactics | `RunAdvancedHuntingQuery` |
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
5. **Render the report immediately** — output the Dashboard Summary, Detailed Findings, Cross-Query Correlations, and 🎯 Recommended Actions. Do NOT block on the manifest or prompt pool building.
6. **After the report is rendered**, run the [Query File Recommendations](#query-file-recommendations) procedure and append the `📂 Recommended Query Files` section. This happens while the user is already reading the report — no perceived delay. Skip entirely when all verdicts are ✅.

> **Performance note:** The Recommendation Gate was previously a blocking step (Phase 3.5) that loaded the ~500-line manifest YAML and ranked entries before the report could render. By moving it after the report output, the user sees findings immediately while recommendations load in the background. The Phase 4 prompt pool building also benefits — it reuses the recommendations already computed in step 6 rather than re-scanning all 12 query results independently.

### Phase 4: Interactive Follow-Up Loop

**After rendering the report, present the user with a selectable list of follow-up actions — skill investigations, query file hunts, and IOC lookups.** Runs when at least one 🔴, 🟠, or 🟡 verdict exists (skip only when ALL verdicts are ✅).

**This is a loop, not a one-shot.** After each action completes, re-present the selection list with the prompt pool updated. Tier depth (🔴/🟠 vs 🟡-only vs all ✅) follows Rule 8.

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
| Q9 | `Compromised Sign-In` user surfaced | `user-investigation` + `authentication-tracing` | `Investigate <UPN>` / `Trace authentication chain for <UPN>` |
| Q9 | `Conditional Access Change` by human actor | `ca-policy-investigation` | `Investigate CA policy changes by <UPN>` |
| Q9 | `Exchange Admin/Rule Change` actors | `user-investigation` | `Investigate <UPN>` |
| Q10 | `MFA-Registration` user | `user-investigation` | `Investigate <UPN>` |
| Q10 | `AppRegistration` or `Ownership` operations | `app-registration-posture` | `Run app registration posture report` |
| Q10 | `AppRegistration` targets containing AI/Agent/Copilot keywords | `ai-agent-posture` | `Run AI agent security audit` |
| Q10 | `RoleManagement` Global/Security Admin OR bulk `Password` resets from single actor | `identity-posture` | `Run identity posture report` |
| Q10 | 3+ categories with same actor in TopActors | `user-investigation` | `Investigate <UPN>` |
| Q11 | Any `IsVerifiedExposed == true` asset | `exposure-investigation` | `Run exposure report for <hostname>` |
| Q11–Q12 | Device in findings | `computer-investigation` | `Investigate device <hostname>` |
| Q12 | CVE with fleet impact | `exposure-investigation` | `Run vulnerability report for <CVE>` |

> **Drill-down lookback** — Per Rule 9, substitute `ago(7d)` → `ago(30d)` (AH) or `ago(90d)` (Data Lake) in all drill-down queries.

**Procedure:**
1. Build the **initial prompt pool** by combining:
   - Skill prompts: one per unique entity + matching skill from the table above. If the same entity appears in multiple queries (e.g., Q3 and Q9), create ONE skill prompt for that entity — the correlation context goes in the Description, not in the Label.
   - Query file prompts: from Phase 3 step 5 keyword extraction. Each query file is its OWN separate prompt — never merge a query file prompt with a skill prompt.
   - IOC prompts: any suspicious IPs/domains from non-✅ findings not already covered by a skill prompt
   - Deduplicate: if a skill prompt and IOC prompt target the same entity, keep only the skill prompt
   - **🔴 NEVER merge a skill prompt (🔍) with a query file prompt (📄) into a single option.** They are different action types with different execution paths.
   - **⛔ Persist the pool.** Write the final pool to `/memories/session/threat-pulse-drilldowns.md` using the **exact template below**. The format banner is mandatory — it makes the ` — ` delimiter contract visible to every iteration and every LLM that edits the file. This memory block is the single source of truth; conversation history is not.

   ### Memory File Template (write on first pool creation)

   ````markdown
   # Threat Pulse Session — <YYYY-MM-DD>

   **Workspace:** <name> (<id>)
   **Lookback:** <7d|30d|90d>
   **Scan Start:** <YYYY-MM-DD HH:MM UTC>

   ## Active Prompt Pool

   <!-- FORMAT: `- <ICON> <action> <entity> — Q<N>: <finding> → <skill-or-query-file>` -->
   <!-- ` — ` (space-emdash-space) is the REQUIRED label/description split delimiter. -->
   <!-- One icon per line. Order = file position (no numbering). Do not edit this comment block. -->

   - 🔍 Investigate incident #<IncidentId> — Q1: <brief finding>, <N> alerts, <MITRE-ID> → incident-investigation
   - 🎯 Enrich and investigate IP <IP> — Q4: <N> spray attempts / <N> users → ioc-investigation
   ...

   ## Pulse Key Findings (quick reference)

   ...

   ## Completed Drill-Downs

   _(none yet)_
   ````
2. **Call `vscode_askQuestions` using the Quick Pick Call Contract below.** Apply identically on every iteration.

   ### Quick Pick Call Contract

   - `header`: `Follow-Up Investigation`
   - `question`: `Select one or more actions to launch (or skip):`
   - `options`: entity prompts (from memory), then `📋` (if truncated), then `💾 / 🔄 / Skip` as the final three — in that order, every iteration. 🆕 prompts prepend to the entity portion only.
     1. `💾 Save full investigation report` — *Save the complete Threat Pulse session (scan + all drill-downs) as a markdown file*
     2. `🔄 Refresh prompt pool` — *Rebuild the follow-up prompt list from existing pulse + drill-down findings (does NOT re-run the 12 pulse queries)*
     3. `Skip` — *No follow-up — investigation complete*
   - Allowed Label icons: `🔍 📄 🎯 💾 🆕 🔄 📋`. Verdict emoji (🔴🟠🟡🟢✅) are banned from Labels (render as `��` in VS Code quick picks) but fine in Descriptions. Drop 💾 after report is saved; 🔄 and Skip always remain.

   ### 🔴 Pre-Flight Checklist — run mechanically before EVERY `vscode_askQuestions` call

   ```
   □ 1. memory view → read `## Active Prompt Pool` just now (not earlier)
   □ 2. Count entity prompts (exclude 💾/🔄/📋/Skip) = N
   □ 3. Format integrity: every entity line starts with `- ` followed by exactly ONE icon. Any legacy `<N>.` prefix → migrate to `- ` first, re-read, then continue.
   □ 4. If N > 12: render top 12 (🆕 first, then memory order) + append `📋 Show full prompt pool (N items)`
   □ 5. For each rendered option: split memory line at FIRST ` — ` → label = text after `- ` up to delimiter, description = right, BYTE-FOR-BYTE (no paraphrasing; if something is missing, edit memory first then re-read)
   □ 6. Atomic check: each option Label has exactly ONE icon; Description has at most ONE `→ target`
   □ 7. `multiSelect: true` in call args
   □ 8. ZERO `recommended` keys anywhere in options[]
   □ 9. Tail = 💾 / 🔄 / Skip (or 📋 / 💾 / 🔄 / Skip if truncated)
   □ 10. Print the Pool Receipt line to chat BEFORE invoking the tool
   ```

   **Pool Receipt** (box 10) — one-liner printed to chat so contract violations are user-visible:

   ```
   📊 Pool: <N> total / rendering <R> (🆕×<a>, 🔍×<b>, 📄×<c>, 🎯×<d>) / truncated <✔|—> | multiSelect=true ✔ | recommended=0 ✔
   ```

   If user selects `📋`: re-invoke with all entity prompts (drop `📋`, keep 💾/🔄/Skip tail).
3. If user selects **Skip** (alone) or pool is empty: end skill execution. Ignore any freeform text if Skip is selected.
4. **Freeform input routing** — If user types freeform text instead of (or alongside) selecting options, route by matching intent to validated sources. Do NOT write ad-hoc KQL — find the right skill or query file first. Classified actions feed into step 7 alongside any selected options.
   1. **Skill match** — Check the request against copilot-instructions.md Available Skills trigger keywords. "Check vulnerabilities on that device" → `exposure-investigation` or `computer-investigation`. Route as 🔍 — the `read_file` gate in step 7 applies.
   2. **Query file match** — `grep_search` the request's key terms (table names, operations, attack types) against `queries/**`. "Check forwarding rules" → `queries/email/email_threat_detection.md`. Route as 📄.
   3. **Contextual question** — If answerable from data already in context (e.g., "is that IP in other alerts?"), answer directly. If a query is needed, loop back to sub-steps 1–2 to find the right source.
   4. **No match** — If no skill or query file covers the request, follow the KQL Pre-Flight Checklist from copilot-instructions.md (schema validation, table pitfalls, existing query search) before writing any KQL. Never skip the pre-flight for freeform requests.
5. **💾 Save full investigation report selected:**
   - Read `/memories/session/threat-pulse-drilldowns.md` (critical after context compaction) and compile pulse dashboard + all drill-down findings into a single markdown file using the [Report Template](#report-template) (file mode). Weave drill-down insights into the main report — do NOT just append raw output.
   - If no drill-downs were executed yet, omit the `Drill-Down Investigation Results` and `Cross-Investigation Correlation` sections with note: "No drill-down investigations were performed in this session."
   - Save to `reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md`. Drop 💾 from subsequent pool iterations.
6. **🔄 Refresh prompt pool selected — prompt list ONLY, no KQL execution.** Refresh rebuilds the follow-up list; it does NOT re-run Q1–Q12 and does NOT re-run drill-downs. Discard the current pool, rebuild by re-applying [Query File Recommendations](#query-file-recommendations) and the [skill matching table](#phase-4-interactive-follow-up-loop) against pulse findings + all drill-down findings in memory. Deduplicate against completed prompts. If selected alongside other actions, refresh FIRST, then present the new pool before executing the others.
7. **One or more actions selected — execute sequentially.** Build a todo list (one item per action). For each:
   - **🔍 Skill prompt:** ⛔ `read_file` the child SKILL.md BEFORE writing ANY query → find Investigation shortcut → match TP Q# trigger → execute with entity substitution. Writing KQL without the prior `read_file` = schema hallucination. See [🔍 Skill Drill-Down Execution Rule](#-skill-drill-down-execution-rule).
   - **📄 Query file prompt:** read the file and execute its queries **verbatim** with entity substitution. See [📄 Query File Execution Rule](#-query-file-execution-rule).
   - **🎯 IOC prompt:** load `ioc-investigation` skill with the target indicator.

   After each drill-down, append a session-state entry to `/memories/session/threat-pulse-drilldowns.md` under `## Completed Drill-Downs`:
   ```
   ### <N>. <Prompt Label> (<skill-name>, <YYYY-MM-DD HH:MM>)
   - **Entity:** <target entity>
   - **Trigger:** Q<N> — <original finding>
   - **Key Findings:** <1–8 bullets, evidence-cited>
   - **Risk Assessment:** <emoji> <level> — <1-line justification>
   - **Cross-References:** <overlaps with other drill-downs or pulse queries>
   - **Recommendations:** <top 1–3 actions>
   ```
   This survives context compaction and feeds the `💾 Save` report.

   **Before returning to step 2 — MANDATORY, in order:**
   1. **New Evidence Scan** — review drill-down results for entities/TTPs not present in prior findings. Add 🆕 prompts only for meaningful leads (new attacker IP with high abuse, new critical CVE on exposed device, etc.). If nothing warrants follow-up, note: *"No actionable new evidence."*
   2. **Manifest check** — for each 🆕 item, consult `.github/manifests/discovery-manifest.yaml` (match by `domains`, `mitre`, or `title`). Only fall back to ad-hoc KQL if nothing matches.
   3. **Reload → mutate → write back** — `memory view` `## Active Prompt Pool` → delete the completed bullet line(s) → prepend 🆕 prompts as new bullet lines (`- <ICON> ...`) → `memory str_replace`. Every entity line is a bullet — no ordinals, so adding/removing items never requires renumbering. **Never reconstruct the pool from conversation history.**
   4. **Return to step 2.** Never render the pool as a markdown table/list instead of calling `vscode_askQuestions`.

**Atomic options — ONE action per option.** Each option maps to ONE skill + ONE entity, OR ONE query file. When correlations link findings (e.g., Q3+Q9 same user), generate **separate options**, put the correlation in the Description. Bundling multiple actions/arrows in a single option is the #1 follow-up mistake.

✅ Correct: `🔍 Investigate user cameron@contoso.com` / desc `Q3+Q9: identity risk + inbox rule manipulation → user-investigation`
❌ Wrong: `🔍 Investigate cameron ... → user-investigation, 📄 Hunt phishing → queries/email/...`

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

Every `🎬 Take Action` heading in the output — this one and every subsequent one — MUST be immediately followed by the AI-content warning blockquote above.

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

**ID sources (agent retrieves silently — never ask the user):**
- **User OID:** Graph `/v1.0/users/<UPN>?$select=id` or `IdentityInfo.AccountObjectId`
- **MDE DeviceId:** `DeviceInfo.DeviceId` or `GetDefenderMachine` API
- **SHA / NetworkMessageId / etc.:** from the originating AH table

⛔ Never emit prompts like *"Retrieve the DeviceId"* — run the lookup and emit the finished link in the same turn.

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
Link to the Defender XDR machine page. If `DeviceId` isn't in context, look it up yourself:

```kql
DeviceInfo | where DeviceName startswith '<name>' | summarize arg_max(Timestamp, *) by DeviceId | project DeviceId
```

Then emit: `[<DeviceName>](https://security.microsoft.com/machines/v2/<DeviceId>?tid=<tenant_id>)`. Never fabricate URLs with `?DeviceName=`, `/machines?`, or bare hostnames.

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
| **User** | `https://security.microsoft.com/user?aad=<OID>&upn=<UPN>&tab=overview&tid=<tenant_id>` | `[user@contoso.com](https://security.microsoft.com/user?aad=<OID>&upn=user@contoso.com&tab=overview&tid=<tenant_id>)` |
| **Domain** | `https://security.microsoft.com/domains/overview?urlDomain=<domain>&tid=<tenant_id>` | `[contoso.com](https://security.microsoft.com/domains/overview?urlDomain=contoso.com&tid=<tenant_id>)` |
| **URL** | `https://security.microsoft.com/url/overview?url=<url-encoded-URL>&tid=<tenant_id>` | `[example.com/path](https://security.microsoft.com/url/overview?url=http%3A%2F%2Fexample.com%2Fpath&tid=<tenant_id>)` |
| **IP** | `https://security.microsoft.com/ip/<IP>/overview?tid=<tenant_id>` | `[<IP>](https://security.microsoft.com/ip/<IP>/overview?tid=<tenant_id>)` |
| **File Hash** | `https://security.microsoft.com/file/<SHA1-or-SHA256>/?tid=<tenant_id>` | `[da5e459...b1bb1e](https://security.microsoft.com/file/da5e45915354850261cf0e87dc7af19597b1bb1e/?tid=<tenant_id>)` |
| **Device** | `https://security.microsoft.com/machines/v2/<MDE_DeviceId>?tid=<tenant_id>` | `[<DeviceName>](https://security.microsoft.com/machines/v2/<MDE_DeviceId>?tid=<tenant_id>)` |
| **SPN / Non-Human Identity** | `https://security.microsoft.com/identity-inventory?tab=NonHumanIdentities&tid=<tenant_id>` | `[Non-Human Identities Inventory](https://security.microsoft.com/identity-inventory?tab=NonHumanIdentities&tid=<tenant_id>)` |

**User fallbacks:** `?upn=<UPN>` when ObjectId is unavailable; `?sid=<SID>&accountName=<Name>&accountDomain=<Domain>` for on-prem AD.

**Device ID source:** `DeviceId` from the `DeviceInfo` AH table or the `id` field from `GetDefenderMachine` API. This is the MDE machine identifier — NOT the Entra Device Object ID (which is different). The computer-investigation skill retrieves this in Step 1b.

**🔴 Portal URL Allowlist — No Invented Paths.** The 7 patterns above plus `/v2/advanced-hunting?tid=<tenant_id>` are the ONLY `security.microsoft.com` URLs you may emit. For any other action (Custom Indicators, Safe Links policy, Email Explorer, CA policy editor, Secure Score, etc.), write a textual breadcrumb — e.g., *"Defender XDR → Settings → Endpoints → Indicators → URLs/Domains → Add item"*. Never guess a path from memory.

#### Entity Display — Portal Link vs Defang (Mutually Exclusive)

| Context | Treatment | Example |
|---------|-----------|---------|
| **Action / Take Action / recommendation tables** | Wrap entity name in portal link (from table above). Never defang. | `[evil.com](https://security.microsoft.com/domains/overview?urlDomain=evil.com&tid=<tenant_id>)` |
| **Data / results tables (raw query output)** | Defang entity as plain text. Never portal-link. | `hxxps://evil[.]com/path` |

Defang rules: `http://` → `hxxp://`, `https://` → `hxxps://`, `.` in domain → `[.]`. VS Code auto-linkifies anything URL-shaped, which is why defanging is required in data tables. Conversely, a portal-linked entity has the portal URL as the link target, so linkification is safe \u2014 defanging would just break the link.

#### Rules Summary

| Rule | Status |
|------|--------|
| Every `🎬 Take Action` heading immediately followed by the AI-content warning blockquote | ✅ **REQUIRED** |
| Single entity \u2192 direct portal link (never an AH query) | ✅ **REQUIRED** |
| 2+ entities \u2192 AH query with Take Actions, all required columns present, no `project` on emails | ✅ **REQUIRED** |
| Every AH query includes BOTH a ` ```kql ` code block AND a plain `[Run in Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting?tid=<tenant_id>)` link below it | ✅ **REQUIRED** |
| Action tables: entity = clickable portal link (from the 7 approved patterns). No separate "Portal" column, no defanging. | ✅ **REQUIRED** |
| Data tables: entity = defanged plain text. No portal linking. | ✅ **REQUIRED** |
| Textual breadcrumb (*"Defender XDR → …"*) when no approved portal URL pattern covers the action | ✅ **REQUIRED** |
| Emitting any `security.microsoft.com` URL outside the 7 approved patterns + `/v2/advanced-hunting` | ❌ **PROHIBITED** |
| Generating gzip/base64-encoded AH deep links via `kql_to_ah_url.py` for output | ❌ **PROHIBITED** |
| Non-✅ drill-down surfaces actionable entities but no Take Action block | ❌ **PROHIBITED** |

---

## Sample KQL Queries

> **All queries below are verified against live Sentinel/Defender XDR schemas. Use them exactly as written. Lookback periods use `ago(Nd)` — substitute the user's preferred lookback where noted.**

### Query 1: Open Incidents with Severity-Ranked Backfill & MITRE Techniques

🔴 **Incident hygiene** — Surfaces unresolved incidents prioritized by severity (Critical → High → Medium → Low), with age, owner, alert count, MITRE tactics, MITRE technique IDs, and extracted entity names (accounts + devices) for cross-query correlation. In large environments, all 10 slots fill with High/Critical. In smaller environments, Medium/Low backfill remaining slots automatically.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let OpenIncidents = SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active");
let TotalHighCritical = toscalar(OpenIncidents | where Severity in ("High", "Critical") | count);
let TotalAll = toscalar(OpenIncidents | count);
OpenIncidents
| extend SevRank = case(Severity == "Critical", 0, Severity == "High", 1, Severity == "Medium", 2, Severity == "Low", 3, 4)
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
    by ProviderIncidentId, Title, Severity, SevRank, Status, CreatedTime,
       OwnerUPN = tostring(Owner.userPrincipalName)
| extend Techniques = set_difference(Techniques, dynamic([""]))
| extend Tactics = set_difference(Tactics, dynamic([""]))
| extend Accounts = set_difference(Accounts, dynamic([""]))
| extend Devices = set_difference(Devices, dynamic([""]))
| extend AgeDisplay = case(
    datetime_diff('minute', now(), CreatedTime) < 60, strcat(datetime_diff('minute', now(), CreatedTime), "m ago"),
    datetime_diff('hour', now(), CreatedTime) < 24, strcat(datetime_diff('hour', now(), CreatedTime), "h ago"),
    strcat(datetime_diff('day', now(), CreatedTime), "d ago"))
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId, "?tid=<TENANT_ID>")
| extend TotalHighCritical = TotalHighCritical, TotalAll = TotalAll
| project TotalHighCritical, TotalAll, ProviderIncidentId, Title, Severity, SevRank, AgeDisplay, AlertCount, 
    OwnerUPN, Tactics, Techniques, Accounts, Devices, Tags, PortalUrl, AlertNames, CreatedTime
| order by SevRank asc, bin(CreatedTime, 1d) desc, AlertCount desc
| take 10
```

**Purpose:** Top 10 open incidents with severity-ranked backfill (Critical→High→Medium→Low). In large envs, all slots fill with High/Critical; small envs backfill with Medium/Low. `TotalHighCritical` and `TotalAll` drive the adaptive report header ("Showing 10 of {TotalAll} open incidents ({TotalHighCritical} High/Critical)"). Joins SecurityAlert for MITRE tactics/techniques and extracts `Accounts` (UPN or AAD ObjectId, lowercased), `Devices` (hostname, lowercased), and `Tags` (from `Labels` — both AutoAssigned ML classifications and User-applied SOC tags) — each capped at 5 per incident — for cross-query correlation with Q3/Q4/Q6/Q7/Q12. Flags unassigned incidents (empty `OwnerUPN`).

**Sort:** `SevRank asc, bin(CreatedTime, 1d) desc, AlertCount desc` — severity tier first, then calendar day (newest first), then complexity within each day.

**Verdict logic:**
- 🔴 Escalate: 5+ new High/Critical in 24h, OR any incident with `AlertCount > 50`, OR any unassigned High/Critical with CredentialAccess/LateralMovement tactics
- 🟠 Investigate: Any unassigned High/Critical, OR `AlertCount > 10`, OR multiple High/Critical in <6h
- 🟡 Monitor: Only Medium/Low incidents exist (no High/Critical), OR High/Critical assigned with low alert count
- ✅ Clear: 0 open incidents of any severity (Q2 closed summary still renders as context)

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
        "&tab=overview&tid=<TENANT_ID>")
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
// Endpoint brute-force — Surface label by LogonType
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
    Countries = dynamic(["—"]),
    LogonTypes = make_set(LogonType)
    by SourceIP = RemoteIP
| where FailedAttempts >= 10
| extend Surface = iff(array_length(LogonTypes) == 1 and LogonTypes[0] == "RemoteInteractive", "Endpoint (RDP)", "Endpoint (Network Logon)"),
    TotalSignIns = FailedAttempts, Successes = long(0), 
    SprayRatio = 100.0, SuccessRate = 0.0, TotalDistinctApps = long(0)
| project-away LogonTypes;
union EntraResults, EndpointBrute
| order by SprayRatio desc, TargetUsers desc, FailedAttempts desc
| take 15
```

**Purpose:** Detects password spray (1 IP → many users, MITRE T1110.003) and brute-force (1 IP → high failure count, T1110.001) across two surfaces, with **shared infrastructure false-positive filtering**:
- **Entra ID:** Uses `EntraIdSignInEvents` (Advanced Hunting) which merges interactive + non-interactive sign-ins into a single table. Error codes: 50126=bad password, 50053=locked account, 50057=disabled account. The query enriches failure data with the IP's full traffic profile to compute `SprayRatio` (spray failures ÷ total sign-ins) and `TotalDistinctApps`. Two filters eliminate corporate proxies, VPN concentrators, and Azure gateways:
  - **`SprayRatio >= 1.0`** — spray failures must be ≥1% of the IP's total sign-in volume. A proxy with 500K sign-ins and 77 spray errors → 0.01% → filtered. A pure attacker with 77 failures and 0 successes → 100% → kept.
  - **`TotalDistinctApps < 50`** — IPs serving 50+ distinct applications are shared infrastructure. Real spray targets 1–3 apps.
- **Endpoint:** RDP (`RemoteInteractive`) and Network Logon (`Network`) failed logons on MDE-enrolled devices. Surface labels: `Endpoint (RDP)` for pure RemoteInteractive, `Endpoint (Network Logon)` for anything involving Network logon type. **NLA caveat:** RDP with Network Level Authentication generates `LogonType == "Network"` (not `RemoteInteractive`), so `Endpoint (Network Logon)` may be RDP-via-NLA or SMB — the manifest surfaces both `rdp_threat_detection.md` and `smb_threat_detection.md` for drill-down. Threshold of ≥10 failures. No success context available in DeviceLogonEvents for filtering.

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

🔑 **Cloud ops monitoring** — Detects mailbox rule manipulation, transport rule changes, mailbox delegation, MCAS-flagged compromised sign-ins, and human-initiated Conditional Access policy changes via CloudAppEvents. **Focuses on rule/permission/CA mutations** — the lower-confidence signals not duplicated by Q1's incident roll-up.

**Tool:** `RunAdvancedHuntingQuery`

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    // Exchange — Mail flow manipulation
    "New-InboxRule", "Set-InboxRule", "Set-Mailbox",
    "Add-MailboxPermission", "New-TransportRule", "Set-TransportRule", "New-Mailbox",
    // Exchange — Anti-forensic
    "Remove-MailboxPermission", "Remove-InboxRule",
    // Conditional Access manipulation (human-initiated only)
    "Set-ConditionalAccessPolicy", "New-ConditionalAccessPolicy",
    // Compromise signals
    "CompromisedSignIn"
)
// Filter out system/automation-driven CA changes (CA agent, backup policies)
| where not(ActionType in ("Set-ConditionalAccessPolicy", "New-ConditionalAccessPolicy") 
            and isempty(AccountDisplayName))
| extend Category = case(
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

**Purpose:** Three-category view of cloud app activity invisible to Q10 (AuditLogs). `CompromisedSignIn` is an MCAS signal independent from Q3's Identity Protection risk events — dual-source corroboration when both fire. CA changes with empty `AccountDisplayName` are system/agent-driven and filtered out. Inbox rule, transport rule, and mailbox permission changes are the primary BEC persistence/exfil mechanisms — even when no rule has a forwarding payload, rule creation by a previously-flagged user is a strong follow-up signal.

**Verdict logic:**
- 🔴 Escalate: `Compromised Sign-In` with 5+ users, OR `Conditional Access Change` by any human actor, OR `Exchange Admin/Rule Change` with forwarding-related rules (`New-InboxRule`, `Set-InboxRule`, `New-TransportRule`)
- 🟠 Investigate: `Compromised Sign-In` (any count), OR `Remove-InboxRule` / `Remove-MailboxPermission` (anti-forensic cleanup signals)
- 🟡 Monitor: Low-count `Set-Mailbox` from system actors
- ✅ Clear: 0 results across all categories

**Drill-down:** Use `user-investigation` for actors in `Compromised Sign-In` category. Use `ca-policy-investigation` for `Conditional Access Change`. **For any Exchange-related Q9 finding, also query `OfficeActivity | where OfficeWorkload == "Exchange"`** — CloudAppEvents only surfaces ActionType summaries; OfficeActivity carries the full `Parameters` JSON (`ForwardTo` / `RedirectTo` / `ForwardingSmtpAddress`), per-operation `ClientIP`, and ops like `MoveToDeletedItems` / `SoftDelete` / `HardDelete` / `MailboxLogin` that reveal post-compromise forensics. See `queries/email/email_threat_detection.md` and the CloudAppEvents / OfficeActivity entries in `copilot-instructions.md` Known Table Pitfalls.

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

Use `.github/manifests/discovery-manifest.yaml` (auto-generated by `python .github/manifests/build_manifest.py`) to match findings to downstream query files and skills. Contains `title`, `path`, `domains`, `mitre`, `prompt`.

**Skip entirely when all verdicts are ✅.** Tier depth follows the Rule 8 table.

### Query-to-Domain Map

| Query Group | Domain Tag(s) |
|-------------|---------------|
| Q1, Q2 (Incidents) | `incidents` |
| Q3, Q4 (Identity) | `identity` |
| Q5 (SPN Drift) | `spn` |
| Q6, Q7 (Endpoint) | `endpoint` |
| Q8 (Email) | `email` |
| Q9, Q10 (Admin & Cloud) | `admin`, `cloud` |
| Q11, Q12 (Exposure) | `exposure` |

Valid tags: `incidents`, `identity`, `spn`, `endpoint`, `email`, `admin`, `cloud`, `exposure`.

### Procedure

For each non-✅ verdict, collect its domain tag(s), then:

1. **Query files** — filter `manifest.queries` where `domains` contains ANY active tag. Rank by (a) number of matching tags, (b) MITRE technique overlap with Q1/Q2 `Techniques` (exact string match on `mitre` field), (c) keyword overlap (entities, process names, CVE IDs, ActionTypes) against title/path. Select top 3–5 files for 🔴/🟠, 1–2 for 🟡-only.
2. **Skills** — filter `manifest.skills` where `domains` matches. Substitute actual entity values into the `prompt` template's `{entity}` placeholder. 🔴/🟠: include all matches as drill-down options; 🟡-only: limit to 3. Skills without `domains` (tooling/visualization) are never auto-suggested.

### Report Output

Insert `📂 Recommended Query Files` after **🎯 Recommended Actions**. Include a `🔧 Suggested Skill Drill-Downs` sub-section with manifest skill prompts (entity-substituted).

**⛔ Numbered list, NOT table** — links inside table cells don't render clickable in VS Code chat.

**Format:** `1. **[<Title>](queries/<subfolder>/<file>.md)** — Q<N>: <finding> — 💡 *"<entity-specific prompt>"*`

- Link text = manifest `title`, target = manifest `path` (forward slashes).
- Prompts MUST reference specific entities/IOCs/TTPs from findings — no generic placeholders.
- When no matching files: suggest authoring new queries.

### Adding New Query Files or Skills

1. Query files: add `**Domains:** <tag1>, <tag2>` to metadata header (after `**MITRE:**`).
2. Skills: add `threat_pulse_domains: [<tag>]` and `drill_down_prompt: '<prompt>'` to YAML frontmatter.
3. Run `python .github/manifests/build_manifest.py` — validator flags missing fields.

---

## Report Template

**Output modes:**
- **Inline chat** (default) — render in chat. Truncate data tables to 10 rows; omit Drill-Down, Cross-Investigation, and Investigation Timeline sections when no drill-downs have executed.
- **Markdown file** — triggered by `💾 Save full investigation report` in Phase 4. Full data tables, no row limits. Path: `reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md`. Source data: pulse results from context + `/memories/session/threat-pulse-drilldowns.md` (authoritative after context compaction).

**Verdicts:** 🔴 Escalate | 🟠 Investigate | 🟡 Monitor | ✅ Clear | 🔵 Informational | ❓ No Data

- **❓ No Data** — query returned table resolution error or timeout. Report the error and table. Treat as monitoring gap.
- **🔵 Informational** — neutral context (e.g., Q2 with 0 closures, Q6 with DriftScore < 80). No action needed.
- **Zero results format:** `✅ No <type> detected in the last <N>d. Checked: <table> (0 matches)`

### Structure

```markdown
# 🔍 Threat Pulse — <Workspace> | <Date>
**Workspace:** <name> (`<id>`)  
**Scan Date:** <YYYY-MM-DD HH:MM UTC>  
**Scan Duration:** <N>min | **Queries:** 12 | **Drill-Downs:** <N>  (file mode only)

## Executive Summary
<2–4 sentences synthesizing pulse + drill-down findings. State final risk posture incorporating all evidence.>

## Dashboard Summary
<12-row table (Q1, Q2, Q3, Q4–Q12) — columns: #, Domain, Status (verdict emoji), Key Finding (1-line).>

## Detailed Findings
<One section per query — EVERY query gets a section (no skipping). Q2 closed summary always renders after Q1 even when Q1 is ✅.>

## Cross-Query Correlations
<Table per Post-Processing rules, or `✅ No correlations detected`.>

## 🎯 Recommended Actions
<Prioritized table: action, trigger query, drill-down skill.>

## 📂 Recommended Query Files
<Per Report Output Block procedure. For 🟡-only verdicts use "📂 Proactive Hunting Suggestions" header. Omit when all ✅.>

## Drill-Down Investigation Results       (file mode, when drill-downs executed)
### 1. <Title> — <Skill Name>
**Triggered by:** Q<N> — <finding>  
**Entity:** <target> | **Lookback:** <timerange> | **Risk:** <emoji> <level>

**Key Findings:** <max 8 evidence-cited bullets>

**Evidence Summary:** <1–2 paragraph narrative with specific numbers/identifiers. Back-reference pulse queries.>

**Recommendations:** <numbered actions>

### 2. <Next Title> — <Skill Name>
...

## Cross-Investigation Correlation        (file mode, when drill-downs executed)
| Connection | Evidence | Drill-Downs | Implication |
|-----------|----------|-------------|-------------|
<Patterns only visible across multiple investigations. If none: `✅ No cross-investigation correlations identified — each finding is independent.`>

## Consolidated Recommendations           (file mode)
| Priority | Recommendation | Source | Risk |
<Deduplicated across pulse + drill-downs. If same action appears in both, cite both sources on one row.>

## Appendix: Investigation Timeline       (file mode)
| Time | Action | Key Result |
```

### Column / Format Rules

- **Q1:** `| Incident | Sev | Title | Age | Alerts | Owner | Tactics | Accounts | Devices | Tags |` — `Sev` = incident severity, Unassigned → `⚠️ Unassigned`, `Age` uses relative `AgeDisplay`, entity/tag columns render max 5 comma-separated.
  - When `TotalAll > 10`: prepend `**Showing 10 of {TotalAll} open incidents ({TotalHighCritical} High/Critical)** (sorted by severity, then newest, most complex first)`
  - When `TotalHighCritical == 0`: prepend `**No High/Critical incidents — showing top Medium/Low from {TotalAll} open**`
- **Q1 incidents** must include `[#<id>](https://security.microsoft.com/incidents/<ProviderIncidentId>?tid=<tenant_id>)` links.
- **Q2:** Classification breakdown + severity + MITRE tactics/techniques from TP closures. Always render even when Q1 is ✅.

### Rules

| Rule | Status |
|------|--------|
| Executive Summary synthesizes across pulse AND drill-downs (when present) | ✅ **REQUIRED** |
| Every query has a verdict row — no omissions, no skipped "clear" sections | ✅ **REQUIRED** |
| Drill-down subsections are structured summaries, not raw dumps, with `Triggered by: Q<N>` | ✅ **REQUIRED** |
| Cross-Investigation Correlation explicitly states "none found" if no connections exist | ✅ **REQUIRED** |
| Consolidated Recommendations are deduplicated (same action + multiple sources → one row) | ✅ **REQUIRED** |
| Fabricated data | ❌ **PROHIBITED** |

---

## Known Pitfalls

| Pitfall | Mitigation |
|---------|------------|
| Q5 takes ~35s (97d lookback) | Acceptable — runs in parallel. Only query needing Data Lake |
| Q7 capped at `ago(30d)` | AH Graph API limit. Use `queries/endpoint/rare_process_chains.md` via Data Lake for 90d |
| Q6 drift scores | Computed in-query — do NOT recompute LLM-side |
| Q9 drill-down: CloudAppEvents identity filtering | `AccountId` and `AccountObjectId` are **Entra ObjectId GUIDs**, NOT UPNs. Filtering by UPN returns 0 results silently. Use `AccountDisplayName` for display-name matching, or resolve UPN→ObjectId via Graph API first. NEVER use `tostring(RawEventData) has "UPN"` — it causes query cancellation on this high-volume table |
| Q9: `RESTSystem` false positives | Exchange Online first-party backend services use `Client=RESTSystem` in `ClientInfoString` and appear as **AppId GUIDs** in `AccountDisplayName`. These are NOT user/app API access — they are system-level mail flow, compliance scanning, or connector ingestion. Q9 filters these out; if investigating Q9 results and see GUID actors with `RESTSystem`, they are benign Microsoft internal operations |
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
