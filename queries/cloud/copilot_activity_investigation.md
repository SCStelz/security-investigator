# Copilot & AI Activity Investigation — Reconstructing AI Usage in IR

**Created:** 2026-06-10  
**Platform:** Both  
**Tables:** CopilotActivity, DataSecurityEvents, CloudAppEvents  
**Keywords:** CopilotActivity, AI activity, Copilot interaction, prompt injection, jailbreak, JailbreakDetected, AccessedResources, Contexts, AppHost, autonomous agent, agentic, MCP tool, connector, Defender runtime protection, SecurityWebhook, plugin lifecycle, PromptBook, AI model, data exposure, grounding data, declarative agent, Copilot Studio, hunt playbook, broad sweep, compliance violation, DLP, sensitivity label downgrade, risky prompt, sensitive response, DataSecurityEvents, SharePoint site access, agent knowledge source, Power Virtual Agents, Enterprise Copilot Platform, ClientAppName, SiteUrl, CloudAppEvents  
**MITRE:** T1078.004, T1213, T1530, T1567.002, T1114.002, T1071.001, T1087, TA0007, TA0009, TA0010, T1213.002  
**Domains:** cloud, admin, identity  
**Timeframe:** Last 7–30 days (Advanced Hunting) or 30 Days + (Data Lake)

---
## Overview

`CopilotActivity` is the **all-surface AI activity table** — a unified audit record of every Microsoft Copilot and AI interaction across the tenant: M365 Copilot (Teams, Outlook, Word, Excel, PowerPoint, SharePoint, Loop), Security Copilot, Copilot Studio declarative agents, autonomous (agentic) flows, Edge/Bing, and admin-center plugin/PromptBook management. Populated by the **Microsoft Copilot** connector.

This file reconstructs AI activity for incident response using the **scope → context → signal** methodology described in the Microsoft Security blog [Reconstructing AI activity in investigations](https://www.microsoft.com/en-us/security/blog/2026/06/09/reconstructing-ai-activity-investigations/) (2026-06-09):

| Phase | Question | Queries |
|-------|----------|---------|
| **Scope** | *Who* used AI, *when*, on *which surface*, with *which model*? | Q1–Q3 |
| **Context** | *What data* did Copilot read, and *what tools/connectors* did agents invoke? | Q4–Q7 |
| **Signal** | What is *suspicious* — jailbreaks, anomalous volume, plugin/agent tampering? | Q8–Q11 |
| **Pivot** | Reconstruct a *single actor or agent* timeline end-to-end | Q12 |

### How `CopilotActivity` relates to the other AI tables

| Table | Scope | Platform | Use when |
|-------|-------|----------|----------|
| **`CopilotActivity`** (this file) | **All** Copilot/AI surfaces (M365, Security Copilot, Studio agents, autonomous) | AH ≤30d / Data Lake 90d | General AI-activity reconstruction, jailbreak/data-exposure hunting |
| `AgentsInfo` | Static **configuration** snapshots of declarative agents | AH only | Agent posture audit (access, data sources, tools as *configured*) — see `ai-agent-posture` skill |
| `UnifiedAgentObservability` | Agent 365 / A365 runtime tool-call telemetry | Data Lake only (`workspaceId: "default"`) | Deep agentic tool-call forensics — see `agent365_observability.md` |
| `CloudAppEvents` (`CopilotInteraction`) | Security Copilot subset via unified audit | AH / Data Lake | Security-Copilot-only views — see `security_copilot_utilization.md` |

**Decision rule:** Start here (`CopilotActivity`) for breadth across all AI surfaces. Drill into `AgentsInfo` for configuration posture, `UnifiedAgentObservability` for agentic tool-call depth.

---

### ⚠️ Critical Table Pitfalls

| Pitfall | Detail |
|---------|--------|
| **Table name is `CopilotActivity`, NOT `LLMActivity`** | Microsoft Learn sample queries reference the table as `LLMActivity` (the Azure Monitor reference alias). In **Advanced Hunting and the Sentinel workspace the table is `CopilotActivity`** — querying `LLMActivity` returns `Failed to resolve table`. Substitute the name when adapting Learn samples. |
| **`TimeGenerated`, not `Timestamp`** | This is a Sentinel/LA table. Use `TimeGenerated` in **both** Advanced Hunting and Data Lake. Using `Timestamp` returns `Failed to resolve column`. |
| **AH ≤30d / Data Lake >30d** | For ≤30 days use `RunAdvancedHuntingQuery` (free). For >30 days use `query_lake` (Data Lake, 90d). AH silently truncates to 30d. |
| **`LLMEventData` must be parsed in AH before `mv-expand`** | `LLMEventData` is a dynamic column. In Advanced Hunting, sub-arrays (`Messages`, `AccessedResources`, `Contexts`, `Resource`) come through as strings — wrap with `parse_json(tostring(LLMEventData.X))` **before** `mv-expand`, or you get `expanded expression expected to have dynamic type`. |
| **Schema differs by `RecordType` / `AppHost`** | The shape of `LLMEventData.AccessedResources` depends on the record type: **`CopilotInteraction`** → file/data reads (`SiteUrl`, `Type` = `docx`/`pdf`/`xlsx`/`EmailMessage`/`CITATION`) AND Defender runtime-protection evaluations (`Type` = `SecurityWebhook`). **`Autonomous`** (agentic) → connector/MCP tool invocations (`Type` = `Connector`). Always filter by `RecordType`/`AppHost` first, then extract the shape you expect. |
| **`Contexts.Type` is frequently EMPTY** | For many `CopilotInteraction` records (notably Security Copilot), `Contexts[]` contains only `Id` (e.g. the app origin URL) with an empty `Type`. **Real resource/data access lives in `AccessedResources[]`, not `Contexts[]`.** Do not rely on `Contexts.Type` for data-exposure analysis. |
| **`AgentId`/`AgentName` only populated for declarative agents** | These are the join keys to `AgentsInfo.AgentId` (a guid). They are empty for plain M365 Copilot chat. Filter `isnotempty(AgentId)` when correlating to configured agents. `AgentsInfo` also exposes `ObservabilityID` for runtime correlation. |
| **Synthetic service identities & egress IPs dominate volume** | Security Copilot generates high-volume synthetic actors (e.g. `SecurityCopilotAgentUser-*` UPNs) and on-behalf-of egress from fixed Azure IPs. These dwarf human activity in count-based queries. **Filter them out** before anomaly/volume analysis (see Q9) or they produce false positives. |
| **Compliance violations live in `DataSecurityEvents`, not `CopilotActivity`** | `CopilotActivity` records *that* an interaction happened and *what resources* it touched, but it does not classify content sensitivity or policy violations. Purview-derived signals — risky prompts, sensitive responses, DLP alerts, label downgrades, inappropriate/regulated content — are emitted to **`DataSecurityEvents`** (AH-only, requires Insider Risk Management opt-in). The Hunt Playbook below pairs the two tables; see Q13 and the `data-security-analysis` skill. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [AI Surface Overview](#query-1-ai-surface-overview) | Dashboard | `CopilotActivity` |
| 2 | [Copilot Interactions by User](#query-2-copilot-interactions-by-user) | Investigation | `CopilotActivity` |
| 3 | [AI Model Usage Statistics](#query-3-ai-model-usage-statistics) | Investigation | `CopilotActivity` |
| 4 | [Data Accessed by Copilot](#query-4-data-accessed-by-copilot) | Investigation | `CopilotActivity` |
| 5 | [Autonomous Agent Runtime Tool Invocations](#query-5-autonomous-agent-runtime-tool-invocations) | Investigation | `CopilotActivity` |
| 6 | [Defender Runtime Protection — Tool Evaluations](#query-6-defender-runtime-protection--tool-evaluations) | Investigation | `CopilotActivity` |
| 7 | [Declarative Agent Adoption](#query-7-declarative-agent-adoption) | Investigation | `CopilotActivity` |
| 8 | [Jailbreak / Prompt Injection Detection](#query-8-jailbreak--prompt-injection-detection) | Detection | `CopilotActivity` |
| 9 | [Anomalous Copilot Volume per User-Hour](#query-9-anomalous-copilot-volume-per-user-hour) | Dashboard | `CopilotActivity` |
| 10 | [Plugin Lifecycle Management Activity](#query-10-plugin-lifecycle-management-activity) | Investigation | `CopilotActivity` |
| 11 | [PromptBook Management Activity](#query-11-promptbook-management-activity) | Investigation | `CopilotActivity` |
| 12 | [Single-Actor AI Activity Timeline](#query-12-single-actor-ai-activity-timeline) | Investigation | `CopilotActivity` |
| 13 | [Copilot Compliance Violations](#query-13-copilot-compliance-violations) | Posture | `DataSecurityEvents` |
| 14 | [SharePoint Sites Accessed by Declarative Agents](#query-14-sharepoint-sites-accessed-by-declarative-agents) | Investigation | `CopilotActivity` |
| 15 | [Agent-Driven SharePoint Access — Full Audit Trail](#query-15-agent-driven-sharepoint-access--full-audit-trail) | Investigation | `CloudAppEvents` |
| 16 | [Pivot — Correlate Agent Identity to SharePoint Audit Events](#query-16-pivot--correlate-agent-identity-to-sharepoint-audit-events) | Investigation | `CloudAppEvents` + `CopilotActivity` |


## 🎯 Hunt Playbook — 7-Day Broad Sweep

**Trigger:** *"Hunt Copilot activity over the last Nd and surface any threats or violations to look into."* Run the steps below in order — steps 1–6 are the broad sweep; the pivot reconstructs any actor or agent that trips a trigger. All steps default to a 7-day window in Advanced Hunting (≤30d); for >30d switch to Data Lake.

| Step | Query | What it surfaces | Escalate when | Pivot |
|------|-------|------------------|---------------|-------|
| 0 | Q1 | Baseline — where AI activity is concentrated (surface × workload) | Orientation only | — |
| 1 | **Q8** | Jailbreak / prompt injection attempts | **Any row** | Q12 + Q4 on the actor |
| 2 | **Q13** | Compliance violations (risky prompts, sensitive responses, DLP, label downgrade, regulated/inappropriate content) | Label-downgrade, financial/regulatory, or inappropriate-content rows; any single user spiking | `data-security-analysis` skill; Q12 on the user |
| 3 | **Q9** | Anomalous interaction volume per user (scripted abuse / exfil-via-AI) | Burst above tuned threshold; use off-hours variant for after-hours activity | Q4 + Q12 on the actor |
| 4 | **Q10** | Plugin / agent lifecycle tampering (enable/disable/delete) | Change by an unexpected actor, or a security plugin disabled | `ai-agent-posture` skill on the `AgentId` |
| 5 | **Q11** | PromptBook tampering | Any unexpected create/update/delete | Confirm against admin change records |
| 6 | **Q6** | Runtime tool-protection gaps (`FailClose = False`) | A sensitive tool evaluated but not fail-close | Q5 + `ai-agent-posture` skill |

**Pivot (any trigger):** Q12 reconstructs the actor's full AI timeline; Q4 shows what data their interactions accessed; for a flagged `AgentId`, cross to the `ai-agent-posture` skill to compare runtime behavior against configuration.

**What "clean" looks like:** Q8 returns 0 rows; Q13 shows only baseline risky-prompt / sensitive-response volume with no label-downgrade or regulated-content hits; Q9 shows no bursts above baseline; Q10/Q11 show only changes by known makers/admins; Q6 shows fail-close enforced on sensitive tools.

**Noise to expect:** `SecurityCopilotAgentUser-*` synthetic actors and on-behalf-of Security Copilot egress dominate raw counts — already filtered in Q9; apply the same filter when adapting other steps. `DataSecurityEvents` is dominated by high-volume *Risky prompt entered in Copilot* / *Sensitive response received in Copilot* events — focus on the rarer, higher-signal ActionTypes (label downgrade, regulated content, inappropriate content, agent generating sensitive responses).

---

## Queries

### Query 1: AI Surface Overview

**Purpose:** Baseline of all AI activity across surfaces — the first query in any AI investigation. Shows volume by record type, hosting app, and workload so you know where activity is concentrated before drilling in.  
**Severity:** Informational  
**MITRE:** TA0007

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical posture overview (summarize by surface) — not a detection."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(30d)
| summarize
    Events = count(),
    Actors = dcount(ActorName),
    Agents = dcountif(AgentId, isnotempty(AgentId)),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RecordType, AppHost, Workload
| order by Events desc
```

---

### Query 2: Copilot Interactions by User

**Purpose:** Per-user interaction counts and activity window — establishes who is using Copilot and how heavily. Adapted from the Microsoft Learn sample (table renamed `LLMActivity` → `CopilotActivity`).  
**Severity:** Informational  
**MITRE:** TA0007

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-user aggregation baseline — not a detection."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(7d)
| where RecordType == "CopilotInteraction"
| summarize
    InteractionCount = count(),
    Surfaces = make_set(AppHost, 10),
    FirstInteraction = min(TimeGenerated),
    LastInteraction = max(TimeGenerated)
    by ActorName, ActorUserId, ActorUserType
| order by InteractionCount desc
```

---

### Query 3: AI Model Usage Statistics

**Purpose:** Which AI models/versions are in use, and by how many distinct users — useful for governance and for spotting an unexpected model appearing in the tenant. Adapted from the Microsoft Learn sample.  
**Severity:** Informational  
**MITRE:** TA0007

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Model inventory aggregation — not a detection."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(30d)
| where RecordType == "CopilotInteraction"
| where isnotempty(AIModelName)
| summarize
    InteractionCount = count(),
    UniqueUsers = dcount(ActorUserId),
    FirstUsed = min(TimeGenerated),
    LastUsed = max(TimeGenerated)
    by AIModelName, AIModelVersion
| order by InteractionCount desc
```

---

### Query 4: Data Accessed by Copilot

**Purpose:** **The data-exposure dimension.** Reconstructs which files, documents, and messages Copilot read on behalf of users (OneDrive/SharePoint files, emails, citations). Critical for "what could the AI have seen?" during an IR. Note `AccessedResources` holds the real resource access — `Contexts` is unreliable (see pitfalls).  
**Severity:** Low  
**MITRE:** T1213, T1530

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated data-access inventory by resource type — investigation pivot, not a row-level detection."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(7d)
| where RecordType == "CopilotInteraction"
| extend AR = parse_json(tostring(LLMEventData.AccessedResources))
| mv-expand AR
| where isnotempty(tostring(AR.SiteUrl)) or tostring(AR.Type) in ("EmailMessage", "CITATION")
| extend
    ResourceType = tostring(AR.Type),
    Action = tostring(AR.Action),
    ResourceUrl = tostring(AR.SiteUrl)
| where ResourceType != "SecurityWebhook"   // runtime-protection evals handled in Q6
| summarize
    AccessCount = count(),
    Users = dcount(ActorName),
    Surfaces = make_set(AppHost, 5)
    by ResourceType, Action
| order by AccessCount desc
```

> To pivot to a specific user's accessed files, add `| where ActorName =~ "user@contoso.com"` after the first `where`, and project `ResourceUrl` instead of summarizing.

---

### Query 5: Autonomous Agent Runtime Tool Invocations

**Purpose:** For **agentic / autonomous** Copilot flows, `AccessedResources` records each connector/MCP tool the agent invoked at runtime (`Type = Connector`). This reveals the *actual* capabilities an autonomous agent exercised — e.g. mail, calendar, SharePoint, OneDrive, Teams MCP servers — as opposed to what it was merely *configured* with (`AgentsInfo`).  
**Severity:** Low  
**MITRE:** T1530, T1071.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated runtime tool inventory for autonomous agents — investigation pivot."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(30d)
| where AppHost == "Autonomous"
| extend AR = parse_json(tostring(LLMEventData.AccessedResources))
| mv-expand AR
| extend
    ToolName = tostring(AR.Name),
    ToolAction = tostring(AR.Action),
    ResourceType = tostring(AR.Type)
| where isnotempty(ToolName) or isnotempty(ToolAction)
| summarize
    Invocations = count(),
    Actors = dcount(ActorName),
    Agents = make_set(AgentName, 10)
    by ToolName, ToolAction, ResourceType
| order by Invocations desc
```

---

### Query 6: Defender Runtime Protection — Tool Evaluations

**Purpose:** When **Defender Runtime Protection** is enabled, each agent tool invocation is evaluated by a security webhook, and the evaluation is recorded in `AccessedResources` with `Type = SecurityWebhook`. This query parses the evaluation string to surface **which tools were inspected, their tool type, and the fail-close posture** — the runtime counterpart to the `ai-agent-posture` skill's configuration audit. A tool evaluated but *not* fail-close is an exposure gap.  
**Severity:** Low  
**MITRE:** TA0009, T1071.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Parses runtime-protection evaluation strings into a tool inventory — investigation/posture, not a row-level detection."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(30d)
| where RecordType == "CopilotInteraction"
| extend AR = parse_json(tostring(LLMEventData.AccessedResources))
| mv-expand AR
| where tostring(AR.Type) == "SecurityWebhook"
| extend EvalText = tostring(AR.Action)
| extend
    ToolName = extract(@"Evaluated tool name: ([^,]+)", 1, EvalText),
    ToolType = extract(@"Evaluated tool type: ([^,]+)", 1, EvalText),
    FailClose = extract(@"Fail close configuration is set to: (\w+)", 1, EvalText),
    Reason = extract(@"Reason: ([^,]+)", 1, EvalText)
| summarize
    Evaluations = count(),
    Actors = dcount(ActorName),
    Agents = make_set(AgentName, 10)
    by ToolName, ToolType, FailClose
| order by Evaluations desc
```

> `ToolType` values observed: `PrebuiltToolDefinition`, `DynamicServerToolDefinition` (MCP server tools), `ToolDefinition`. `FailClose = False` means the agent would proceed even if the security evaluation could not complete — review these tools.

---

### Query 7: Declarative Agent Adoption

**Purpose:** Bridges configuration and runtime. Lists declarative agents (by `AgentId`/`AgentName`) that actually produced activity, with their user reach and surfaces. Join `AgentId` to `AgentsInfo.AgentId` to find **configured-but-dormant** agents (in `AgentsInfo`, absent here) and **active** agents (present here) — see the `ai-agent-posture` skill Phase 5.  
**Severity:** Informational  
**MITRE:** TA0007

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Agent adoption posture aggregation — not a detection."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(30d)
| where isnotempty(AgentId)
| summarize
    Events = count(),
    Users = dcount(ActorName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Surfaces = make_set(AppHost, 5),
    RecordTypes = make_set(RecordType, 5)
    by AgentName, AgentId
| order by Events desc
```

---

### Query 8: Jailbreak / Prompt Injection Detection

**Purpose:** Surfaces interactions where the platform flagged a **jailbreak / prompt-injection attempt** (`Messages[].JailbreakDetected == true`). This is the highest-value security signal in `CopilotActivity`. Row-level and suitable for a scheduled custom detection. Adapted from the Microsoft Learn sample with the AH `parse_json(tostring(...))` fix.  
**Severity:** High  
**MITRE:** T1078.004, T1059  
**Tuning Notes:** True positives are rare (often single-digit per month in normal tenants). Each hit warrants review of the full prompt and the actor's broader activity (Q12).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Copilot jailbreak / prompt injection detected for {{ActorName}}"
impactedAssets:
  - type: user
    identifier: ActorName
recommendedActions: "Review the flagged Copilot message and the user's surrounding AI activity (see copilot_activity_investigation.md Q12). Confirm whether the prompt was an intentional jailbreak attempt, and check the agent/surface involved for data exposure."
adaptation_notes: "Row-level security signal. Filter to JailbreakDetected == true; already one row per flagged message."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(7d)
| where RecordType == "CopilotInteraction"
| extend Messages = parse_json(tostring(LLMEventData.Messages))
| mv-expand Messages
| where tobool(Messages.JailbreakDetected) == true
| project
    TimeGenerated,
    ActorName,
    ActorUserId,
    AgentName,
    AppHost,
    Workload,
    SrcIpAddr,
    MessageId = tostring(Messages.Id),
    JailbreakDetected = tobool(Messages.JailbreakDetected)
| order by TimeGenerated desc
```

---

### Query 9: Anomalous Copilot Volume per User-Hour

**Purpose:** Detects a single human actor generating an unusually high burst of Copilot interactions in one hour — possible scripted abuse, data-harvesting via Copilot, or a compromised account exfiltrating through AI. **Filters out synthetic Security Copilot service identities** which otherwise dominate (see pitfalls).  
**Severity:** Medium  
**MITRE:** TA0009, T1530  
**Tuning Notes:** Tune the `> 50` threshold to the tenant's baseline. Heavy legitimate Copilot users may approach it; combine with `Q12` to confirm intent.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Exfiltration"
title: "Anomalous Copilot interaction burst from {{ActorName}}"
impactedAssets:
  - type: user
    identifier: ActorName
recommendedActions: "Review the user's Copilot timeline (copilot_activity_investigation.md Q12) and accessed resources (Q4) for that hour. Determine whether the burst is scripted/automated and whether sensitive data was accessed."
adaptation_notes: "Hourly summarize with threshold. Exclude synthetic service identities. Scheduled (not NRT) due to aggregation."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(1d)
| where RecordType == "CopilotInteraction"
| where ActorUserType !~ "System"
| where ActorName !startswith "SecurityCopilotAgentUser-"
| summarize EventCount = count(), Surfaces = make_set(AppHost, 5) by ActorName, ActorUserId, Hour = bin(TimeGenerated, 1h)
| where EventCount > 50
| order by EventCount desc
```

> **Off-hours variant (Hunt Playbook step 3):** to surface after-hours bursts specifically, swap the per-hour summarize for an off-hours per-day window. Tune the hour boundary and `> 30` threshold to the tenant. (`ActorUserType` is `Regular` for all rows in many tenants, so do **not** rely on it for a guest filter.)
>
> ```kql
> CopilotActivity
> | where TimeGenerated > ago(7d)
> | where RecordType == "CopilotInteraction"
> | where ActorUserType !~ "System"
> | where ActorName !startswith "SecurityCopilotAgentUser-"
> | extend HourOfDay = datetime_part("Hour", TimeGenerated)
> | where HourOfDay >= 19 or HourOfDay < 6
> | summarize EventCount = count(), Surfaces = make_set(AppHost, 5) by ActorName, Day = bin(TimeGenerated, 1d)
> | where EventCount > 30
> | order by EventCount desc
> ```

---

### Query 10: Plugin Lifecycle Management Activity

**Purpose:** Tracks creation, update, enable, disable, and deletion of Copilot plugins/agents — a governance and tampering signal. An attacker (or rogue maker) enabling a high-privilege plugin or disabling a security plugin shows up here. Adapted from the Microsoft Learn sample.  
**Severity:** Medium  
**MITRE:** T1078.004, TA0003  
**Tuning Notes:** Correlate the actor against expected Copilot Studio makers/admins.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "Persistence"
title: "Copilot plugin {{RecordType}} by {{ActorName}}"
impactedAssets:
  - type: user
    identifier: ActorName
recommendedActions: "Confirm the actor is an authorized Copilot Studio maker/admin and the plugin/agent change was expected. Review the agent's configuration in the ai-agent-posture skill."
adaptation_notes: "Row-level admin/governance events. Already one row per lifecycle action."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(30d)
| where RecordType in ("CreateCopilotPlugin", "UpdateCopilotPlugin", "EnableCopilotPlugin", "DisableCopilotPlugin", "DeleteCopilotPlugin", "CopilotAgentManagement")
| project TimeGenerated, ActorName, ActorUserType, RecordType, AgentName, AgentId, SrcIpAddr, AppHost
| order by TimeGenerated desc
```

---

### Query 11: PromptBook Management Activity

**Purpose:** Tracks creation, update, and deletion of Security Copilot PromptBooks. PromptBooks codify multi-step prompt workflows; unexpected changes can indicate tampering with automated security workflows. Adapted from the Microsoft Learn sample with the AH `parse_json(tostring(...))` fix.  
**Severity:** Low  
**MITRE:** TA0003  
**Tuning Notes:** Low-volume in most tenants; review each change against expected admin activity.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Low-volume governance log; review-oriented rather than a standalone detection."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(30d)
| where RecordType in ("CreateCopilotPromptBook", "UpdateCopilotPromptBook", "DeleteCopilotPromptBook")
| extend Resource = parse_json(tostring(LLMEventData.Resource))
| extend PromptBookId = tostring(Resource[0].Property)
| project TimeGenerated, ActorName, RecordType, PromptBookId, SrcIpAddr, AppHost
| order by TimeGenerated desc
```

---

### Query 12: Single-Actor AI Activity Timeline

**Purpose:** **The pivot query.** Reconstructs one actor's complete AI activity timeline across all surfaces — interactions, agents used, models, source IPs, and jailbreak flags — for a focused investigation. Substitute the target UPN.  
**Severity:** Informational  
**MITRE:** TA0007, TA0009

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-actor timeline reconstruction with a parameterized UPN — investigation pivot, not a detection."
-->

```kql
let target = "user@contoso.com";   // <-- substitute the actor UPN
CopilotActivity
| where TimeGenerated > ago(30d)
| where ActorName =~ target
| extend Messages = parse_json(tostring(LLMEventData.Messages))
| extend JailbreakFlagged = tobool(Messages[0].JailbreakDetected)
| project
    TimeGenerated,
    RecordType,
    AppHost,
    Workload,
    AgentName,
    AIModelName,
    SrcIpAddr,
    ClientRegion,
    JailbreakFlagged
| order by TimeGenerated asc
```

---

### Query 13: Copilot Compliance Violations

**Purpose:** **The compliance/violation dimension** of the Hunt Playbook. `CopilotActivity` does not classify content sensitivity — Purview emits Copilot policy signals to **`DataSecurityEvents`**. This query triages those signals by ActionType so you can spot the high-value violations (sensitivity-label downgrade then Copilot access, regulated/financial content, inappropriate content, agents generating sensitive responses) above the baseline risky-prompt / sensitive-response noise. For deep DLP/SIT/label analysis, hand off to the `data-security-analysis` skill.  
**Severity:** Medium (varies by ActionType — label downgrade and regulated content are higher)  
**MITRE:** T1213, T1567.002, TA0010  
**Tuning Notes:** *Risky prompt entered in Copilot* and *Sensitive response received in Copilot* are extremely high-volume baseline events — keep them for trend context but focus triage on the rarer ActionTypes. Requires Insider Risk Management opt-in; returns 0 rows if not enabled.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table (DataSecurityEvents) compliance-violation triage aggregation. Orientation pivot into the data-security-analysis skill, not a standalone row-level detection."
-->

```kql
DataSecurityEvents
| where TimeGenerated > ago(7d)
| where ActionType has "Copilot"
    or ActionType has "Agent generating"
    or ActionType has "inappropriate content"
    or ActionType has "regulatory compliance"
    or ActionType has "Label on file"
    or ActionType has "connected AI apps"
| summarize
    Events = count(),
    Users = dcount(AccountUpn),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ActionType
| order by Events asc   // rarest (highest-signal) violations first
```

> **Per-user drill-down:** to pivot to who is generating a specific violation, add `| where ActionType has "Label on file"` (or the ActionType of interest) and `summarize ... by AccountUpn` instead. Then run Q12 on that UPN for the full AI timeline.

---

### Query 14: SharePoint Sites Accessed by Declarative Agents

**Purpose:** Answers *"which SharePoint sites/files has this agent read?"* directly from `CopilotActivity.AccessedResources`, scoped to interactions where `AgentId` is populated (i.e., a named declarative agent, not plain M365 Copilot chat). This is the runtime counterpart to `AgentsInfo.DeclaredDataSources` (`ai-agent-posture` skill Q7) — what the agent actually read, not just what it was configured with.  
**Severity:** Low  
**MITRE:** T1213, T1530

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated per-agent SharePoint site inventory — investigation pivot, not a row-level detection."
-->

```kql
CopilotActivity
| where TimeGenerated > ago(30d)
| where isnotempty(AgentId)
| extend AR = parse_json(tostring(LLMEventData.AccessedResources))
| mv-expand AR
| extend SiteUrl = tostring(AR.SiteUrl)
| where SiteUrl has ".sharepoint.com"
| summarize
    AccessCount = count(),
    Users = dcount(ActorName),
    Sites = make_set(SiteUrl, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AgentName, AgentId
| order by AccessCount desc
```

> **Filter note:** `AR.SiteUrl` is also populated for non-SharePoint resources (e.g. Outlook OWA deep links for `Untitled Notebook`-style agents) — the `has ".sharepoint.com"` filter is required to exclude that noise. To pivot to individual files instead of the site-level rollup, project `tostring(AR.Name)` / `ObjectId` alongside `SiteUrl` and drop the `summarize`.

---

### Query 15: Agent-Driven SharePoint Access — Full Audit Trail

**Purpose:** `CopilotActivity.AccessedResources` only records `SiteUrl` and an action verb — it has **no client IP, no exact item ID, and no per-request detail**. `CloudAppEvents` carries the full SharePoint unified-audit trail (validated fingerprint: agent-driven access via **Copilot Studio** surfaces with `ApplicationDisplayName` / `AppAccessContext.ClientAppName` = **`Power Virtual Agents`** (Copilot Studio's legacy platform name — note the trailing space in some raw records, hence `trim()`) or **`Enterprise Copilot Platform`**, as opposed to human client apps like `Files`, `Browser`, `Microsoft Office`, `OfficeHome`). This query surfaces the same knowledge-source access with the fuller audit detail (`ClientIP`, per-file `ObjectName`, `ActionType` granularity including `FileDownloaded`).  
**Severity:** Low (Medium if `FileDownloaded` on a sensitive file)  
**MITRE:** T1213, T1530, T1567.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated per-actor SharePoint audit-trail inventory filtered to the Copilot Studio client-app fingerprint — investigation pivot, not a standalone row-level detection. A row-level variant scoped to ActionType == 'FileDownloaded' plus a sensitive-file allowlist could be promoted to a detection."
-->

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "SharePoint"
| where ActionType in ("FileAccessed", "FilePreviewed", "FileDownloaded", "FileModified", "PageViewed")
| extend ClientApp = trim(" ", tostring(coalesce(RawEventData.AppAccessContext.ClientAppName, RawEventData.ApplicationDisplayName)))
| where ClientApp in ("Power Virtual Agents", "Enterprise Copilot Platform")
| extend SiteUrl = tostring(RawEventData.SiteUrl), ClientIP = tostring(RawEventData.ClientIP)
| summarize
    Events = count(),
    Actions = make_set(ActionType, 10),
    Sites = make_set(SiteUrl, 20),
    Files = make_set(ObjectName, 20),
    ClientIPs = make_set(ClientIP, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by ClientApp, AccountDisplayName, AccountObjectId
| order by Events desc
```

> **Important caveat:** This is OBO (on-behalf-of) access — `AccountDisplayName`/`AccountObjectId` is the **impersonated human user**, not the agent's own identity. The `ClientApp` fingerprint tells you *a Copilot Studio agent* touched SharePoint on that user's behalf, but not *which* agent. Cross-reference with Q16 (or `AgentId`-scoped Q14 + matching `ActorUserId`/time window) to attribute a specific `AgentName`. Discover other client-app fingerprints in your tenant first with: `CloudAppEvents | where Application has "SharePoint" | extend ClientApp = trim(" ", tostring(coalesce(RawEventData.AppAccessContext.ClientAppName, RawEventData.ApplicationDisplayName))) | summarize count() by ClientApp | order by count_ desc` — new Copilot/agent platforms may introduce additional fingerprint values over time.

---

### Query 16: Pivot — Correlate Agent Identity to SharePoint Audit Events

**Purpose:** **The definitive answer to "which SharePoint sites did Agent X access."** Joins `CopilotActivity` agent interactions (which know `AgentName`/`AgentId` but not `ClientIP`/exact file detail) to `CloudAppEvents` SharePoint audit records (which know the full detail but not which agent) on `ActorUserId == AccountObjectId` within a tight time window, attributing the full audit trail back to a named agent.  
**Severity:** Low  
**MITRE:** T1213, T1530

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table join/correlation pivot with a time-proximity match — investigation tooling, not a standalone row-level detection."
-->

```kql
let lookback = 30d;
let agentInteractions = CopilotActivity
    | where TimeGenerated > ago(lookback)
    | where isnotempty(AgentId)
    | project InteractionTime = TimeGenerated, ActorUserId, AgentName, AgentId;
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application has "SharePoint"
| extend ClientApp = trim(" ", tostring(coalesce(RawEventData.AppAccessContext.ClientAppName, RawEventData.ApplicationDisplayName)))
| where ClientApp in ("Power Virtual Agents", "Enterprise Copilot Platform")
| extend SiteUrl = tostring(RawEventData.SiteUrl), ClientIP = tostring(RawEventData.ClientIP)
| join kind=inner agentInteractions on $left.AccountObjectId == $right.ActorUserId
| where abs(datetime_diff('minute', Timestamp, InteractionTime)) <= 5
| summarize
    Events = count(),
    Sites = make_set(SiteUrl, 20),
    Files = make_set(ObjectName, 20),
    Actions = make_set(ActionType, 10),
    ClientIPs = make_set(ClientIP, 10)
    by AgentName, AgentId, AccountDisplayName, AccountObjectId
| order by Events desc
```

> **Tuning notes:** the 5-minute window is conservative for interactive Copilot Studio sessions; widen if an agent's tool-call chain runs longer before touching SharePoint. Pre-filtering both sides (`isnotempty(AgentId)` on the CopilotActivity side, `Application has "SharePoint"` + `ClientApp` fingerprint on the CloudAppEvents side) keeps the join inputs small and avoids the `CloudAppEvents` fleet-wide-join timeout documented in the `ai-agent-posture` skill. Join key is a plain string (`AccountObjectId`/`ActorUserId`), not dynamic — safe for `join`.

---

## Investigation Workflow

1. **Scope** — Run Q1 to map where AI activity is concentrated, then Q2/Q3 to identify heavy users and models in play.
2. **Context** — Run Q4 to see what data Copilot read; Q5 for autonomous-agent tool invocations; Q6 for Defender runtime-protection evaluations; Q7 to map active declarative agents.
3. **Signal** — Run Q8 (jailbreak) as the priority security signal, Q13 for compliance violations, Q9 for volume anomalies, Q10/Q11 for plugin/PromptBook tampering.
4. **Pivot** — For any flagged actor, run Q12 to reconstruct their full AI timeline, then cross-reference accessed resources (Q4 scoped to the actor).
5. **Correlate to configuration** — For any flagged `AgentId`, pivot to the `ai-agent-posture` skill (`AgentsInfo`) to compare runtime behavior against configured access, data sources, and tools.

> **Just want the broad sweep?** Use the [Hunt Playbook — 7-Day Broad Sweep](#-hunt-playbook--7-day-broad-sweep) near the top — it sequences the signal queries (Q8 → Q13 → Q9 → Q10/Q11 → Q6) with escalation triggers and pivots.

## Related

- **[Reconstructing AI activity in investigations](https://www.microsoft.com/en-us/security/blog/2026/06/09/reconstructing-ai-activity-investigations/)** (Microsoft Security blog, 2026-06-09) — source of the scope → context → signal methodology this file is structured on.
- **`ai-agent-posture` skill** — static configuration audit of declarative agents (`AgentsInfo`); see its Phase 5 for runtime correlation back to this file.
- **`data-security-analysis` skill** — deep DLP / sensitive-information-type / sensitivity-label analysis over `DataSecurityEvents` (the table behind Q13).
- **`agent365_observability.md`** — deeper agentic tool-call telemetry (`UnifiedAgentObservability`, Data Lake only).
- **[`../network/gsa_generative_ai_insights.md`](../network/gsa_generative_ai_insights.md)** — network-layer AI view via Global Secure Access: consumer GenAI prompts (ChatGPT/Gemini) with allow/block verdicts, plus agent MCP egress incl. shadow/unsanctioned MCP servers. Complements this application-layer table.
- **`security_copilot_utilization.md`** — Security-Copilot-specific utilization via `CloudAppEvents`.
