# Global Secure Access — Generative AI Insights (Client GenAI + Agent MCP)

**Created:** 2026-06-17  
**Platform:** Microsoft Sentinel / Microsoft Defender XDR (Advanced Hunting)  
**Tables:** NetworkAccessGenerativeAIInsights, NetworkAccessTraffic, NetworkAccessConnectionEvents, NetworkSessions  
**Keywords:** Global Secure Access, GSA, Entra Internet Access, Generative AI Insights, GenAI, prompt injection, prompt logging, AI prompt inspection, ChatGPT, Gemini, shadow AI, shadow MCP, Model Context Protocol, MCP server, MCP tool call, tools/call, Copilot Studio agent, agentic egress, CloudAppName, TransactionId correlation, AI web category, data exfiltration via AI  
**MITRE:** T1071.001, T1567.002, T1078.004, T1530, T1213, TA0001, TA0009, TA0010, TA0011  
**Domains:** cloud, identity  
**Timeframe:** Last 30 days (Advanced Hunting; configurable)

---

## Overview

**Microsoft Global Secure Access (GSA / Entra Internet Access)** inspects user and agent web traffic at the network edge and emits a dedicated **Generative AI Insights** stream. This gives the SOC a **network-layer** view of AI usage that is **application-agnostic** — it sees consumer and third-party GenAI apps (ChatGPT, Gemini, Claude, etc.) and **any** MCP server reached over the wire, including shadow/unsanctioned servers that app-layer telemetry (`CopilotActivity`, `UnifiedAgentObservability`) never observes.

This file covers the **two sides** of GSA GenAI telemetry:

| Side | What it captures | Anchor table | Star field |
|------|------------------|--------------|------------|
| 🔵 **Client / Prompt** | A user typing prompts into ChatGPT / Gemini through GSA — full prompt text, plus the **allow/block** verdict of AI-prompt-inspection policies | `NetworkAccessGenerativeAIInsights` (`Activity == "Prompt"`) ⋈ `NetworkAccessTraffic` | `Content` (plaintext prompt) |
| 🔵 **Agent / MCP** | A Copilot Studio (or other) agent making **Model Context Protocol** calls to MCP servers — the JSON-RPC handshake and every `tools/call` with the tool name | `NetworkAccessGenerativeAIInsights` (`Activity == "Mcp"`) ⋈ `NetworkAccessTraffic` | `Content` (JSON-RPC payload) |

> **The block verdict is NOT in the GenAI Insights table.** `NetworkAccessGenerativeAIInsights` records *what* was sent (prompt / MCP payload). The **policy decision** (`Action`, `PolicyName`, `RuleName`, `ResponseCode`) lives in `NetworkAccessTraffic`. The two are correlated on **`TransactionId`** — this join is the backbone of nearly every detection below.

### How GSA GenAI Insights relates to the other AI tables

GSA gives the **network view**; the existing AI query files give the **application view**. They are complementary — for a Copilot Studio agent, GSA sees the **same MCP `tools/call` egress** that Agent 365 sees from the runtime SDK side.

| Table / file | Layer | Sees | Use when |
|--------------|-------|------|----------|
| **`NetworkAccessGenerativeAIInsights`** (this file) | **Network** (GSA edge) | **Any** GenAI app + **any** MCP server on the wire (incl. shadow/3rd-party); prompt text; allow/block policy verdict | Shadow-AI / shadow-MCP discovery, prompt-injection blocking, network-side agent egress |
| [`copilot_activity_investigation.md`](../cloud/copilot_activity_investigation.md) (`CopilotActivity`) | Application | All **Microsoft** Copilot surfaces (M365, Security Copilot, Studio agents) — interaction records, jailbreak verdicts, accessed resources | Microsoft-Copilot AI-activity reconstruction |
| [`agent365_observability.md`](../cloud/agent365_observability.md) (`UnifiedAgentObservability`) | Application (agent runtime) | Copilot Studio / A365 agent **runtime** tool calls with full request + response arguments | Deep agentic tool-call forensics (the SDK side of the same MCP calls GSA sees on the wire) |

**Decision rule:** Start **here** to discover *which* AI apps and MCP servers are reached over the network and *whether policy blocked them*. Pivot to `CopilotActivity` / `UnifiedAgentObservability` for the in-app interaction record and tool-call arguments. For a Copilot Studio agent, **correlate by tool name + time window** across this file and `agent365_observability.md`.

---

### ⚠️ Critical Table Pitfalls

| Pitfall | Detail |
|---------|--------|
| **Queryable in both Advanced Hunting and Data Lake** | These are GSA connector tables surfaced into the connected workspace — **not** Data-Lake-only. Prefer **Advanced Hunting** (`RunAdvancedHuntingQuery`, free, ≤30d). For >30d use `query_lake` (Data Lake, 90d). |
| **`TimeGenerated`, not `Timestamp`** | All four tables are network/connector (Sentinel/LA) tables. Use **`TimeGenerated`** in **both** AH and Data Lake. `Timestamp` returns `Failed to resolve column`. |
| **Block verdict is in `NetworkAccessTraffic`, not the GenAI table** | `NetworkAccessGenerativeAIInsights` has **no** `Action` / `PolicyName` / `RuleName` / `CloudAppName` / `ResponseCode` columns. Join to `NetworkAccessTraffic` on **`TransactionId`** to get the policy decision and the app name. |
| **`Content` can be large (up to ~65 KB)** | The prompt / JSON-RPC payload. **Never** `tostring(Content) has "x"` to filter — `parse_json(Content)` once and extract the specific field (`.params.name`, `.method`), or `substring()` a preview. Filtering with `matches regex` on the materialized string is acceptable for keyword hunts. |
| **Prompt rows have `SubActivity` empty and `EventType == "Request"` only** | `Activity == "Prompt"` rows carry the prompt in `Content` with `SubActivity == ""`. There is no paired Response row. |
| **MCP `Request` + `Response` share an `EventId`** | `Activity == "Mcp"` operations emit two rows (`EventType` = `Request` / `Response`) with the **same `EventId`**. Filter `EventType == "Request"` to get one row per operation and to read the outbound payload (`tools/call` arguments). |
| **`SessionId` is frequently EMPTY** | On `Prompt` rows `SessionId` is empty; on many `Mcp` rows too. **`TransactionId` is the reliable correlation key** to `NetworkAccessTraffic` (and across Request/Response use `EventId`). |
| **`McpServerName` / `McpClientName` are often EMPTY** | Use **`DestinationUrl`** as the reliable MCP server identifier (e.g. `http://sentinel.microsoft.com/mcp/custom/data-exploration`). `McpClientName == "mcs"` indicates Copilot Studio when populated. |
| **Deployed schema lags the published reference** | The Azure Monitor reference for `NetworkAccessTraffic` lists newer agentic columns (`IsAgentic`, `IsTokenAgentic`, `AIDetectionConfidence`, `AIDetectionEvidence`). These are **not deployed in all tenants** — filtering them returns `SemanticError`. The deployed table **does** have `AIAgentId` / `AIAgentName` (the agent's **schema name**, e.g. `copilots_header_xxxxx`), but they may be **empty**. **Verify with `getschema` before relying on agentic columns**; identify Copilot Studio agent traffic via `HttpUserAgent startswith "CopilotStudio"` as the robust fallback. |
| **`NetworkAccessConnectionEvents` has no `TransactionId` / `Action`** | It is **connection-level** (one row per L3/L4 connection). Join to `NetworkAccessTraffic` on **`ConnectionId`** to reach the transaction, then to the GenAI table on `TransactionId`. It carries device + source-geo context (`ClientDeviceName`, `DeviceOperatingSystem`, `SourceIpCity`, `SourceIpCountryCode`) and the evaluating `SecurityProfileName` / `SecurityPolicyName`. **Always `where isnotempty(ConnectionId)` on both sides** — empty `ConnectionId` causes loose joins. |
| **`NetworkSessions` is an ASIM table — may be empty** | The normalized `NetworkSessions` (ASIM Network Session schema) resolves in Advanced Hunting but is **not populated by GSA in every tenant** (returns 0 rows where the ASIM normalization isn't enabled). Treat it as an **optional** correlation layer — skip gracefully if empty. The authoritative GSA data is in the three `NetworkAccess*` tables. |
| **`CloudAppCategory` / `SecurityProfileName` may be blank** | In lab / lightly-configured tenants these enrichment fields are empty. Do not depend on them as filters; use `CloudAppName` and `PolicyName` / `RuleName` instead. |

---

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [GSA GenAI Activity Overview](#query-1-gsa-genai-activity-overview) | Dashboard | `NetworkAccessGenerativeAIInsights` |
| 2 | [Prompt Inventory by User & App](#query-2-prompt-inventory-by-user--app) | Posture | `NetworkAccessGenerativeAIInsights` |
| 3 | [Prompt-Injection Blocks](#query-3-prompt-injection-blocks) | Investigation | `NetworkAccessGenerativeAIInsights` + `NetworkAccessTraffic` |
| 4 | [Prompt Policy Coverage — Allowed vs Blocked by App](#query-4-prompt-policy-coverage--allowed-vs-blocked-by-app) | Investigation | `NetworkAccessGenerativeAIInsights` + `NetworkAccessTraffic` |
| 5 | [GenAI App Inventory — Shadow-AI Discovery](#query-5-genai-app-inventory--shadow-ai-discovery) | Posture | `NetworkAccessGenerativeAIInsights` + `NetworkAccessTraffic` |
| 6 | [MCP Operation Overview](#query-6-mcp-operation-overview) | Dashboard | `NetworkAccessGenerativeAIInsights` |
| 7 | [MCP Tool-Call Inventory](#query-7-mcp-tool-call-inventory) | Posture | `NetworkAccessGenerativeAIInsights` |
| 8 | [Copilot Studio Agent — Attribute MCP Calls to the Agent](#query-8-copilot-studio-agent--attribute-mcp-calls-to-the-agent) | Investigation | `NetworkAccessGenerativeAIInsights` + `NetworkAccessTraffic` |
| 9 | [New MCP Server / Tool First-Seen vs 30-Day Baseline](#query-9-new-mcp-server--tool-first-seen-vs-30-day-baseline) | Dashboard | `NetworkAccessGenerativeAIInsights` |
| 10 | [Prompt Content — Jailbreak Keyword Hunt](#query-10-prompt-content--jailbreak-keyword-hunt) | Investigation | `NetworkAccessGenerativeAIInsights` |
| 11 | [Connection-Level Context & Security Profile](#query-11-connection-level-context--security-profile) | Investigation | `NetworkAccessConnectionEvents` + multi |
| 12 | [End-to-End Session Reconstruction](#query-12-end-to-end-session-reconstruction) | Investigation | `NetworkAccessGenerativeAIInsights` + `NetworkAccessTraffic` |


## Queries

### Query 1: GSA GenAI Activity Overview

**Purpose:** First-look orientation — splits all GSA GenAI telemetry by `Activity` (Prompt vs Mcp), `SubActivity` (MCP method), and `EventType` (Request/Response). Establishes the volume and shape of client-prompt vs agent-MCP activity in the tenant.  
**Severity:** Informational  
**MITRE:** TA0009

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical posture overview (summarize by activity/subactivity) — not a detection."
-->

```kql
NetworkAccessGenerativeAIInsights
| where TimeGenerated > ago(30d)
| summarize
    Events = count(),
    Users = dcount(UserPrincipalName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Activity, SubActivity, EventType
| order by Events desc
```

---

### Query 2: Prompt Inventory by User & App

**Purpose:** Who is sending prompts to which consumer GenAI app, and how many. `DestinationUrl` distinguishes the app (Gemini vs ChatGPT vs others); `parse_url().Host` normalizes it to the app host. Baseline of GenAI adoption per user.  
**Severity:** Informational  
**MITRE:** TA0009

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-user/app prompt-volume baseline — not a detection."
-->

```kql
NetworkAccessGenerativeAIInsights
| where TimeGenerated > ago(30d)
| where Activity == "Prompt"
| extend DestHost = tostring(parse_url(DestinationUrl).Host)
| summarize
    Prompts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, DestHost
| order by Prompts desc
```

---

### Query 3: Prompt-Injection Blocks

**Purpose:** **The flagship client-side detection.** Surfaces prompts that a GSA AI-prompt-inspection policy **blocked** — joins the prompt text (`NetworkAccessGenerativeAIInsights`, `Activity == "Prompt"`) to the blocking verdict (`NetworkAccessTraffic`, `Action == "Block"`) on `TransactionId`. Reveals the user, the app, the enforcing policy/rule, and a preview of the malicious prompt.  
**Severity:** High  
**MITRE:** T1078.004, TA0001  
**Tuning Notes:** True positives are users attempting jailbreak / prompt-injection against consumer GenAI. Review the full `Content` and the user's surrounding activity. Blocks are driven by the AI-prompt-inspection policy (e.g. `PolicyName == "Inspect AI Prompts"`, `RuleName == "Block Malicious Prompts"`); confirm the policy is attached to **all** sanctioned GenAI apps (see Q4 for the coverage gap).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "GSA blocked a malicious AI prompt from {{AccountUpn}} to {{CloudAppName}}"
impactedAssets:
  - type: user
    identifier: AccountUpn
recommendedActions: "Review the blocked prompt (Content) and the user's broader GenAI activity (gsa_generative_ai_insights.md Q2/Q12). Confirm whether the prompt was an intentional jailbreak/prompt-injection attempt. Verify the AI-prompt-inspection policy covers all sanctioned GenAI apps (Q4)."
adaptation_notes: "Row-level security signal. Join is required (Prompt rows ⋈ NetworkAccessTraffic on TransactionId) — scheduled (1H+), not NRT. Projects AccountUpn for impactedAssets."
-->

```kql
let prompts = NetworkAccessGenerativeAIInsights
    | where TimeGenerated > ago(7d)
    | where Activity == "Prompt"
    | project TransactionId, PromptTime = TimeGenerated,
              AccountUpn = UserPrincipalName,
              PromptText = tostring(parse_json(Content));
NetworkAccessTraffic
| where TimeGenerated > ago(7d)
| where Action == "Block"
| where isnotempty(TransactionId)
| project TransactionId, CloudAppName, PolicyName, RuleName, ResponseCode, ThreatType
| join kind=inner prompts on TransactionId
| project PromptTime, AccountUpn, CloudAppName, PolicyName, RuleName, ResponseCode, ThreatType,
          PromptPreview = substring(PromptText, 0, 200)
| order by PromptTime desc
```

---

### Query 4: Prompt Policy Coverage — Allowed vs Blocked by App

**Purpose:** **Surfaces the coverage gap.** For every GenAI app that received prompts, compares how many were allowed vs blocked and which policies/rules applied. A common finding: the AI-prompt-inspection policy is attached to one app (e.g. Gemini) but **not** another (e.g. ChatGPT) — so identical injection prompts are blocked on one and pass on the other.  
**Severity:** Medium  
**MITRE:** TA0001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated allow/block coverage comparison by app — posture/gap analysis, not a row-level detection."
-->

```kql
let prompts = NetworkAccessGenerativeAIInsights
    | where TimeGenerated > ago(30d)
    | where Activity == "Prompt"
    | distinct TransactionId;
NetworkAccessTraffic
| where TimeGenerated > ago(30d)
| where isnotempty(TransactionId)
| join kind=inner (prompts) on TransactionId
| summarize
    Prompts = count(),
    Blocked = countif(Action == "Block"),
    Allowed = countif(Action == "Allow"),
    Policies = make_set(PolicyName, 5),
    Rules = make_set(RuleName, 5)
    by CloudAppName
| extend BlockRatePct = round(100.0 * Blocked / Prompts, 1)
| order by Prompts desc
```

> **Reading the gap:** an app with `Prompts > 0` but `Blocked == 0` and `Policies` containing only `"All websites"` / `RuleName == "*"` has **no AI-prompt-inspection policy attached** — a coverage gap. Attach the AI-prompt policy to that app in the GSA portal.

---

### Query 5: GenAI App Inventory — Shadow-AI Discovery

**Purpose:** Inventories every GenAI app GSA classified as carrying prompt traffic, with user reach and the allow/block actions seen. Because GSA inspects at the network edge, this discovers **shadow / unsanctioned** GenAI apps in use that no app-layer connector reports.  
**Severity:** Low  
**MITRE:** TA0009, T1567.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated GenAI app inventory (shadow-AI discovery) — posture, not a row-level detection."
-->

```kql
let genaiTx = NetworkAccessGenerativeAIInsights
    | where TimeGenerated > ago(30d)
    | where Activity == "Prompt"
    | distinct TransactionId;
NetworkAccessTraffic
| where TimeGenerated > ago(30d)
| where isnotempty(TransactionId)
| join kind=inner (genaiTx) on TransactionId
| summarize
    Requests = count(),
    Users = dcount(UserPrincipalName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Actions = make_set(Action, 3)
    by CloudAppName, CloudAppCategory
| order by Requests desc
```

> `CloudAppCategory` may be empty in lightly-configured tenants — rely on `CloudAppName`. A newly-appearing `CloudAppName` (low `FirstSeen` recency, see Q9 pattern) is a candidate shadow-AI app to triage.

---

### Query 6: MCP Operation Overview

**Purpose:** The agent-side orientation. Breaks down MCP protocol activity by server (`DestinationUrl`), method (`SubActivity` = `initialize` / `tools/list` / `notifications/initialized` / `tools/call`), and direction (`EventType`). Shows which MCP servers agents are talking to and how heavily.  
**Severity:** Informational  
**MITRE:** TA0009, T1071.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "MCP protocol activity aggregation by server/method — not a detection."
-->

```kql
NetworkAccessGenerativeAIInsights
| where TimeGenerated > ago(30d)
| where Activity == "Mcp"
| summarize
    Events = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DestinationUrl, SubActivity, EventType
| order by DestinationUrl asc, Events desc
```

---

### Query 7: MCP Tool-Call Inventory

**Purpose:** **The agent capability inventory.** Parses each `tools/call` request payload (`Content.params.name`) to enumerate exactly which MCP tools agents invoked, on which server. This is the *actual* tool usage on the wire — e.g. custom Sentinel data-exploration tools and Microsoft Learn tools.  
**Severity:** Low  
**MITRE:** T1530, T1071.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated MCP tool-call inventory (parses Content.params.name) — investigation/posture pivot."
-->

```kql
NetworkAccessGenerativeAIInsights
| where TimeGenerated > ago(30d)
| where Activity == "Mcp" and SubActivity == "tools/call" and EventType == "Request"
| extend P = parse_json(Content)
| extend ToolName = tostring(P.params.name), Method = tostring(P.method)
| summarize
    Calls = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Clients = make_set(McpClientName, 5)
    by DestinationUrl, ToolName
| order by Calls desc
```

> `Clients` may contain `"mcs"` (Copilot Studio) or empty strings. Use `DestinationUrl` as the authoritative server identifier — `McpServerName` is frequently empty.

---

### Query 8: Copilot Studio Agent — Attribute MCP Calls to the Agent

**Purpose:** Ties agent-side MCP `tools/call` activity (`NetworkAccessGenerativeAIInsights`) to the **traffic record** that identifies the agent (`NetworkAccessTraffic`), joined on `TransactionId`. Copilot Studio agent egress is identified by `HttpUserAgent startswith "CopilotStudio"`; the agent's schema name surfaces in `AIAgentName` (when populated). Produces an attributed timeline of which agent called which tool on which server.  
**Severity:** Low  
**MITRE:** T1078.004, T1071.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table agent attribution join (CopilotStudio user-agent ⋈ MCP tools/call on TransactionId) — investigation pivot."
-->

```kql
let mcpTx = NetworkAccessGenerativeAIInsights
    | where TimeGenerated > ago(30d)
    | where Activity == "Mcp" and SubActivity == "tools/call" and EventType == "Request"
    | project TransactionId, GaiTime = TimeGenerated,
              McpServerUrl = DestinationUrl,
              ToolName = tostring(parse_json(Content).params.name);
NetworkAccessTraffic
| where TimeGenerated > ago(30d)
| where HttpUserAgent startswith "CopilotStudio"
| project TransactionId, TrafficTime = TimeGenerated,
          AgentName = AIAgentName, AgentId = AIAgentId,
          DestinationFqdn, Action, HttpUserAgent
| join kind=inner mcpTx on TransactionId
| project TrafficTime, AgentName, ToolName, McpServerUrl, DestinationFqdn, Action, HttpUserAgent
| order by TrafficTime desc
```

> `AIAgentName` holds the agent's **schema name** (e.g. `copilots_header_xxxxx`); it may be empty in some tenants, in which case `HttpUserAgent` is the reliable agent fingerprint. **This is the network-side view of the same tool calls** that [`agent365_observability.md`](../cloud/agent365_observability.md) sees from the agent runtime SDK — correlate by `ToolName` + time window to pair the two.

---

### Query 9: New MCP Server / Tool First-Seen vs 30-Day Baseline

**Purpose:** **Agent scope-drift / shadow-MCP detection.** Flags any (MCP server `DestinationUrl`, tool name) pair seen in the last day that was **absent** from the prior 30-day baseline. Catches a new MCP server appearing (every tool is new) and a new tool added on an existing server — possible unauthorized capability addition, agent drift, or a benign deployment change.  
**Severity:** Medium  
**MITRE:** T1071.001, TA0011  
**Tuning Notes:** After legitimate agent/tool deployments, expect a transient first-seen spike. Maintain an allow-list join or temporarily lower severity after announced changes. Returns 0 rows in a steady-state tenant (no drift) — that is the expected clean result.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Discovery"
title: "GSA: new MCP tool {{ToolName}} first-seen on {{DestinationUrl}}"
impactedAssets:
  - type: user
    identifier: AccountUpn
recommendedActions: "Confirm whether the new MCP server/tool was an approved deployment. If unexpected, investigate the calling agent (gsa_generative_ai_insights.md Q8) and the MCP server endpoint. Compare against agent365_observability.md (runtime SDK tool inventory) for the same agent."
adaptation_notes: "First-seen baseline detection. UserPrincipalName is often EMPTY on agent-initiated MCP rows (calls run under the agent identity) — AccountUpn is best-effort; the true entity is the MCP server URL (DestinationUrl), which is not an impactedAssets type. Schedule daily; uses a 30d baseline let-join (scheduled, not NRT)."
-->

```kql
let Baseline = NetworkAccessGenerativeAIInsights
    | where TimeGenerated between (ago(31d) .. ago(1d))
    | where Activity == "Mcp" and SubActivity == "tools/call" and EventType == "Request"
    | extend ToolName = tostring(parse_json(Content).params.name)
    | distinct DestinationUrl, ToolName;
NetworkAccessGenerativeAIInsights
| where TimeGenerated > ago(1d)
| where Activity == "Mcp" and SubActivity == "tools/call" and EventType == "Request"
| extend ToolName = tostring(parse_json(Content).params.name)
| join kind=leftanti Baseline on DestinationUrl, ToolName
| summarize
    Calls = count(),
    FirstSeen = min(TimeGenerated),
    Users = make_set(UserPrincipalName, 5)
    by DestinationUrl, ToolName
| extend AccountUpn = tostring(Users[0])
| project FirstSeen, DestinationUrl, ToolName, Calls, AccountUpn
```

---

### Query 10: Prompt Content — Jailbreak Keyword Hunt

**Purpose:** Hunts prompt text for jailbreak / prompt-injection language **regardless of whether GSA blocked it** — catching attempts on apps that have no AI-prompt-inspection policy attached (the Q4 coverage gap). Row-level and suitable for a scheduled custom detection. Pair with Q3 (blocked) to separate *attempted-and-blocked* from *attempted-and-allowed*.  
**Severity:** High  
**MITRE:** T1078.004, T1567.002  
**Tuning Notes:** The regex covers common jailbreak phrasings (`ignore your instructions`, `system prompt`, `jailbreak`, `developer mode`, `do anything now`, etc.). Tune the pattern to your environment; expect occasional benign matches (security researchers, red-teamers). Each hit warrants reviewing the full `Content` and whether traffic was allowed (cross-ref Q3).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "GSA: jailbreak-style AI prompt from {{AccountUpn}}"
impactedAssets:
  - type: user
    identifier: AccountUpn
recommendedActions: "Review the full prompt (Content) and determine whether GSA blocked it (cross-reference gsa_generative_ai_insights.md Q3). If the destination app had no AI-prompt-inspection policy, the prompt was allowed — attach the policy (Q4). Investigate the user's broader GenAI activity (Q2/Q12)."
adaptation_notes: "Single-table row-level keyword hunt. Materializes Content then regex — acceptable. Projects AccountUpn for impactedAssets. Tune the regex per environment."
-->

```kql
NetworkAccessGenerativeAIInsights
| where TimeGenerated > ago(7d)
| where Activity == "Prompt"
| extend PromptText = tostring(parse_json(Content))
| where PromptText matches regex @"(?i)(ignore (your |all |previous )?instructions|system prompt|jailbreak|developer mode|bypass.{0,15}(filter|guardrail|safety)|reveal.{0,15}(prompt|instruction)|do anything now)"
| project TimeGenerated, AccountUpn = UserPrincipalName, DestinationUrl, TransactionId,
          PromptPreview = substring(PromptText, 0, 300)
| order by TimeGenerated desc
```

---

### Query 11: Connection-Level Context & Security Profile

**Purpose:** Enriches GenAI activity with **device and source-geo context** from `NetworkAccessConnectionEvents` (which has no `TransactionId`, so it is reached via `ConnectionId` → `NetworkAccessTraffic` → GenAI). Answers "from which device, OS, and location did this user reach the GenAI app, and which GSA security profile evaluated it?"  
**Severity:** Low  
**MITRE:** TA0009

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table device/geo enrichment join (ConnectionEvents ⋈ Traffic on ConnectionId, scoped to GenAI apps) — investigation context, not a detection."
-->

```kql
let genaiTx = NetworkAccessGenerativeAIInsights
    | where TimeGenerated > ago(30d)
    | distinct TransactionId;
let genaiConns = NetworkAccessTraffic
    | where TimeGenerated > ago(30d)
    | where isnotempty(ConnectionId)
    | join kind=inner (genaiTx) on TransactionId
    | where CloudAppName has_any ("Gemini", "ChatGPT")   // scope to GenAI apps of interest
    | distinct ConnectionId, CloudAppName;
NetworkAccessConnectionEvents
| where TimeGenerated > ago(30d)
| where isnotempty(ConnectionId)
| join kind=inner (genaiConns) on ConnectionId
| summarize
    Connections = count(),
    Cities = make_set(SourceIpCity, 5),
    Countries = make_set(SourceIpCountryCode, 5)
    by UserPrincipalName, ClientDeviceName, DeviceOperatingSystem, CloudAppName, SecurityProfileName
| order by Connections desc
```

> `SecurityProfileName` may be empty if no GSA security profile is assigned to the matching rule. Broaden the `has_any` app filter to cover your sanctioned GenAI apps.

---

### Query 12: End-to-End Session Reconstruction

**Purpose:** Builds a single chronological timeline merging client prompts and agent MCP operations, each annotated with the `NetworkAccessTraffic` policy verdict (`Action` / `PolicyName` / `RuleName`). The IR pivot — reconstructs everything GSA saw for AI activity in the window. Scope to a user (`UserPrincipalName`) or a `TransactionId` for a focused timeline.  
**Severity:** Informational  
**MITRE:** TA0009

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Union of prompt + MCP events with traffic-verdict leftouter join — investigation timeline, not a detection."
-->

```kql
let prompts = NetworkAccessGenerativeAIInsights
    | where TimeGenerated > ago(7d)
    | where Activity == "Prompt"
    | project TimeGenerated, TransactionId, UserPrincipalName,
              Detail = substring(tostring(parse_json(Content)), 0, 200), Kind = "Prompt";
let mcp = NetworkAccessGenerativeAIInsights
    | where TimeGenerated > ago(7d)
    | where Activity == "Mcp" and EventType == "Request"
    | project TimeGenerated, TransactionId, UserPrincipalName,
              Detail = strcat(SubActivity, " ", tostring(parse_json(Content).params.name)), Kind = "MCP";
union prompts, mcp
| join kind=leftouter (
    NetworkAccessTraffic
    | where TimeGenerated > ago(7d)
    | distinct TransactionId, CloudAppName, Action, PolicyName, RuleName
  ) on TransactionId
| project TimeGenerated, Kind, UserPrincipalName, CloudAppName, Action, PolicyName, RuleName, Detail, TransactionId
| order by TimeGenerated asc
```

> Add `| where UserPrincipalName =~ "user@contoso.com"` (client prompts) or `| where TransactionId == "<id>"` to focus the timeline. Agent MCP rows have an empty `UserPrincipalName` (calls run under the agent identity) — filter by `CloudAppName` / `DestinationUrl` instead.

---

## Investigation Workflow

1. **Orient** — Q1 (activity split: prompts vs MCP), Q6 (MCP servers in use).
2. **Client / Prompt side** — Q2 (who prompts which app) → Q3 (blocked malicious prompts, the priority signal) → Q10 (jailbreak attempts incl. *allowed* ones) → Q4 (which apps lack a prompt-inspection policy) → Q5 (shadow-AI discovery).
3. **Agent / MCP side** — Q7 (tool-call inventory) → Q8 (attribute calls to the Copilot Studio agent) → Q9 (new MCP server/tool drift).
4. **Enrich & reconstruct** — Q11 (device + geo + security profile) → Q12 (end-to-end timeline for the flagged user/transaction).
5. **Correlate to the application layer** — for a flagged agent, pivot to [`agent365_observability.md`](../cloud/agent365_observability.md) for the runtime tool-call arguments; for Microsoft Copilot surfaces pivot to [`copilot_activity_investigation.md`](../cloud/copilot_activity_investigation.md).

## Related

- [`copilot_activity_investigation.md`](../cloud/copilot_activity_investigation.md) — application-layer AI activity across all Microsoft Copilot surfaces (`CopilotActivity`), incl. jailbreak verdicts and accessed resources. GSA is the network-layer complement.
- [`agent365_observability.md`](../cloud/agent365_observability.md) — Copilot Studio / A365 agent **runtime** tool-call telemetry (`UnifiedAgentObservability`). GSA Q7/Q8 are the network-side view of the same MCP `tools/call`; correlate by tool name + time.
- **Global Secure Access — Generative AI Insights** (Microsoft Learn): GSA traffic logs, AI web category, and AI-prompt-inspection policy reference.
- **`ai-agent-posture` skill** — declarative agent configuration audit (`AgentsInfo`); pairs with Q8/Q9 to compare configured vs network-observed agent tool usage.
- [`local_ai_agent_discovery.md`](../endpoint/local_ai_agent_discovery.md) — **endpoint/host** inventory of local AI agents installed on devices (ChatGPT Desktop, Claude Code, Cline, Copilot, etc.) via `AgentsInfo` (`Platform == "LocalAgents"`) + exposure graph. GSA sees the AI **egress on the wire**; this file sees the **runtime installed on the device** — pair them for shadow-AI discovery (which local agent is generating the GenAI/MCP traffic GSA observes) and to map agent → device → identity → reachable assets.
- **NetworkSessions (ASIM)** — optional normalized correlation layer; not populated by GSA in every tenant (verify with a `count` before use).
