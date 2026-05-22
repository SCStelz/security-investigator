# Agent 365 Observability — AI Agent Telemetry Hunting

**Created:** 2026-05-22  
**Platform:** Microsoft Sentinel (Data Lake + Analytics tier for promoted tables)  
**Tables:** UnifiedAgentObservability, CloudAppEvents, A365_JailbreakIncidents_KQL_CL, A365_QueryLakeAudit_KQL_CL, A365_AgentToolDaily_KQL_CL, A365_AgentToolFailuresDaily_KQL_CL  
**Keywords:** Agent 365, A365, AI agent, Copilot Studio, prompt injection, jailbreak, Prompt Shield, XPIA, MCP tool, Power Platform Connector, agent telemetry, conversation, tool call, prompt forensics, agent observability, CloudAppEvents CopilotInteraction  
**MITRE:** T1078.004, T1059, T1087, T1530, T1071.001, TA0001, TA0007, TA0009  
**Domains:** cloud, identity  
**Timeframe:** Last 7 days to 12 years (Data Lake retention; KQL Jobs support up to 12-year lookback)

---

## Overview

`UnifiedAgentObservability` is a Sentinel **Data Lake system table** populated by the **Agent 365 / A365 Observability** connector. It captures end-to-end telemetry for AI agents built on Copilot Studio and Microsoft 365 Copilot — including user prompts, agent-to-tool MCP calls, channel context, and session correlation.

### ⚠️ Critical Access Pattern

This table lives in the **Sentinel Data Lake system scope**, not a specific workspace. Querying it with a workspace GUID returns `SemanticError: Failed to resolve table`. You **must** pass `workspaceId: "default"` to `mcp_sentinel-data_query_lake`. This matches the portal's "Workspace Scope" → "default" dropdown.

- ❌ Not queryable via Advanced Hunting (`RunAdvancedHuntingQuery`)
- ❌ Not queryable via Triage MCP
- ❌ Not indexed by `mcp_sentinel-data_search_tables`
- ✅ Data Lake only, via `workspaceId: "default"`

### Event Shapes — Two Distinct Telemetry Types

Telemetry splits sharply by `EventOriginalType`:

| `EventOriginalType` | What It Captures | Key Populated Fields | Key Empty Fields (Preview) |
|---|---|---|---|
| **`InvokeAgent`** | User-to-agent conversation turn (the user's side) | `EventOriginalRequestDetails` = full plaintext user prompt; `ActorUsername`; `EventSessionId`; `AdditionalFields.ChannelName` / `ConversationId` | `EventOriginalResultDetails` (agent response), `EventThoughtProcessDetails`, `ModelName`, `InputTokensUsed`, `OutputTokensUsed`, `EventFinishReasons` — typically empty in current preview |
| **`ExecuteToolBySDK`** | Agent-to-tool MCP / connector call (full request + response) | `EventOriginalRequestDetails` = JSON-RPC payload (`method`, `params.name`, `params.arguments`); `EventOriginalResultDetails` = full tool response; `ToolName`, `ToolId`, `ToolOriginalType`; `EventRequestId` / `EventResponseId` | `ActorUsername` = `"N/A"` (connector runs under agent identity, not user) |

Both event types share `EventSessionId`, which is the join key for reconstructing a conversation turn together with the tool calls it triggered.

### ⚠️ Table Pitfalls

| Pitfall | Detail |
|---------|--------|
| **`workspaceId: "default"` required** | See above — workspace GUID returns table-not-found. |
| `AdditionalFields` is **dynamic** | Always `parse_json(tostring(AdditionalFields))` before dot-access. Common keys: `ChannelName`, `ConversationId`, `ConversationLink`, `OpId`, `ParentId`. |
| `EventFinishReasons` is **dynamic** | Same parse requirement. Often empty in preview. |
| `EventOriginalRequestDetails` / `EventOriginalResultDetails` are **strings**, not dynamic | Use `parse_json()` to extract structured fields. Raw payloads can be large (KB–MB per row); avoid `tostring(col) has "x"` patterns — extract specific JSON fields instead. |
| `ActorUsername == "N/A"` on tool-call rows | Tool calls execute under the agent's identity. To attribute tool calls to the originating user, join on `EventSessionId` to a sibling `InvokeAgent` row. |
| **Agent identity is blank on `InvokeAgent` rows** | `SrcAgentId`, `SrcAgentName`, and `SrcAgentOriginalType` are populated only on `ExecuteToolBySDK` rows. User prompt rows arrive with `SrcAgentId == "00000000-0000-0000-0000-000000000000"` and empty `SrcAgentName`. To attribute a prompt to an agent, join on `EventSessionId` to a sibling `ExecuteToolBySDK` row in the same session and pull `SrcAgentName` from there. Queries that group prompts by `SrcAgentName` will produce a single empty-agent bucket if this enrichment is skipped. |
| `EventEndTime` may be `0001-01-01T00:00:00Z` | Treat as null — use `EventStartTime` / `TimeGenerated` for time analysis. |
| Agent response not captured | Current preview ingests user prompts only — the agent's reply is not in `EventOriginalResultDetails` for `InvokeAgent` events. For agent reasoning, inspect downstream `ExecuteToolBySDK` rows in the same session. |
| No content-safety verdict | No Prompt Shield outcome, XPIA flag, or groundedness score lives in this table. Pair with `AIAgentsInfo` (AH-only) for agent posture and Defender for AI alerts for safety signals. |

### Related Tables

| Table | Platform | Purpose |
|-------|----------|---------|
| `AIAgentsInfo` | Advanced Hunting | Agent **inventory & configuration** (auth mode, tools registered, knowledge sources, creators). Companion to this table's runtime telemetry. |
| `CloudAppEvents` (`ActionType == "CopilotInteraction"`) | Workspace (Analytics tier) | M365 Copilot / Copilot Studio prompt + response events with **Prompt Shield / XPIA / jailbreak verdicts** in `CopilotEventData.Messages[]`. Joinable to this table on **agent SPN GUID** — see [Query 9](#query-9-cross-source-correlation-with-cloudappevents). |
| `GraphAPIAuditEvents` | Advanced Hunting | When agents call Graph API via MCP, those calls also surface here under the agent's SPN. |
| `MicrosoftGraphActivityLogs` | Data Lake | Same as above, with token/session correlation for >30d. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Agent & Actor Inventory](#query-1-agent--actor-inventory) | Posture | — |
| 2 | [Prompt Injection / Jailbreak Detection](#query-2-prompt-injection--jailbreak-detection) | Detection | — |
| 3 | [Session Reconstruction — Prompts + Tool Calls](#query-3-session-reconstruction--prompts--tool-calls) | Investigation | — |
| 4 | [Tool Invocation Inventory per Agent](#query-4-tool-invocation-inventory-per-agent) | Posture | — |
| 5 | [MCP `query_lake` Argument Audit](#query-5-mcp-querylake-argument-audit) | Investigation | — |
| 6 | [Tool Call Failures & Errors](#query-6-tool-call-failures--errors) | Investigation | — |
| 7 | [New Tool First-Seen — Baseline Deviation](#query-7-new-tool-first-seen--baseline-deviation) | Dashboard | — |
| 8 | [Channel & User Activity Distribution](#query-8-channel--user-activity-distribution) | Investigation | — |
| 9 | [a: Cross-Source Base Correlation — prompts ↔ tool calls](#query-9a-cross-source-base-correlation--prompts--tool-calls) | Investigation | `CloudAppEvents` |
| 9 | [b: Cross-Source High-Signal — prompt injection → downstream tool calls](#query-9b-cross-source-high-signal--prompt-injection--downstream-tool-calls) | Investigation | `CloudAppEvents` |
| 9 | [c: Cross-Source Per-Session Rollup — safety + tool-use](#query-9c-cross-source-per-session-rollup--safety--tool-use) | Investigation | `CloudAppEvents` |
| 9 | [d: Cross-Source Safety Audit — every flagged prompt with prompt tex...](#query-9d-cross-source-safety-audit--every-flagged-prompt-with-prompt-text--tool-activity) | Investigation | `CloudAppEvents` |
| — | [Job 1 — Hourly Jailbreak Incident Promotion (CAE-anchored)](#job-1--hourly-jailbreak-incident-promotion-cae-anchored) | Investigation | `CloudAppEvents` |
| — | [Job 2 — Hourly `query_lake` Argument Audit](#job-2--hourly-querylake-argument-audit) | Investigation | — |
| — | [Job 3 — Daily Agent Tool Inventory Snapshot](#job-3--daily-agent-tool-inventory-snapshot) | Posture | — |
| — | [Job 4 — Daily Agent Tool Failure Rollup](#job-4--daily-agent-tool-failure-rollup) | Investigation | — |
| — | [Detection 1 — AI Agent: Prompt Injection / Jailbreak Incident](#detection-1--ai-agent-prompt-injection--jailbreak-incident) | Detection | — |
| — | [Detection 2 — AI Agent: KQL Access to Sensitive Tables](#detection-2--ai-agent-kql-access-to-sensitive-tables) | Detection | — |
| — | [Detection 3 — AI Agent: New Tool First-Seen vs 30-Day Baseline](#detection-3--ai-agent-new-tool-first-seen-vs-30-day-baseline) | Dashboard | — |


## Queries

### Query 1: Agent & Actor Inventory

**Purpose:** High-level inventory of every agent emitting telemetry, the users invoking them, the channels in use, and per-agent activity volumes. Use as the entry point for any A365 hunt.  
**Severity:** Informational  
**MITRE:** —  

```kql
// Pull agent identity from ExecuteToolBySDK rows (where it's populated) and use
// EventSessionId to enrich the InvokeAgent rows (where SrcAgent* is blank).
let SessionAgent = UnifiedAgentObservability
    | where TimeGenerated > ago(30d)
    | where EventOriginalType == "ExecuteToolBySDK" and isnotempty(SrcAgentName)
    | summarize arg_max(TimeGenerated, SrcAgentId, SrcAgentName, SrcAgentOriginalType) by EventSessionId;
UnifiedAgentObservability
| where TimeGenerated > ago(30d)
| extend Channel = tostring(parse_json(tostring(AdditionalFields)).ChannelName)
| join kind=leftouter SessionAgent on EventSessionId
| extend
    AgentId   = iff(isnotempty(SrcAgentName), SrcAgentId, SrcAgentId1),
    AgentName = iff(isnotempty(SrcAgentName), SrcAgentName, SrcAgentName1),
    AgentType = iff(isnotempty(SrcAgentOriginalType), SrcAgentOriginalType, SrcAgentOriginalType1)
| summarize
    Events           = count(),
    UserPrompts      = countif(EventOriginalType == "InvokeAgent"),
    ToolCalls        = countif(EventOriginalType == "ExecuteToolBySDK"),
    Sessions         = dcount(EventSessionId),
    Conversations    = dcount(tostring(parse_json(tostring(AdditionalFields)).ConversationId)),
    DistinctUsers    = dcountif(ActorUsername, ActorUsername != "N/A" and isnotempty(ActorUsername)),
    Channels         = make_set(Channel, 10),
    FirstSeen        = min(TimeGenerated),
    LastSeen         = max(TimeGenerated)
    by AgentId, AgentName, AgentType, EventProduct
| order by Events desc
```

**Expected results:** One row per agent. `UserPrompts` and `ToolCalls` should both be non-zero for actively-used agents. Agents with `ToolCalls > 0` but `UserPrompts == 0` may be invoked headlessly (automation, scheduled triggers). The session-level join is required because `SrcAgent*` columns are blank on `InvokeAgent` rows — without it, all user prompts collapse into a single empty-agent bucket. Prompts in sessions that never invoked a tool will still appear under a blank `AgentName` row.

**Tuning:** Filter to a single `SrcAgentName` for drill-down. Replace `ago(30d)` with `ago(7d)` for recent activity only.

---

### Query 2: Prompt Injection / Jailbreak Detection

**Purpose:** Detect user prompts attempting to override system instructions, extract metaprompts, or bypass safety guidelines. Captures the full plaintext prompt for forensic review.  
**Severity:** Medium  
**MITRE:** T1078.004 (Cloud Account abuse), TA0001  

```kql
let JailbreakPatterns = @"(?i)\b(ignore\s+(all\s+)?(your\s+|previous\s+)?(prior\s+)?instructions|disregard\s+(your\s+|all\s+)?(prior\s+|previous\s+)?(safety|guidelines|instructions|rules)|system\s+(override|prompt|instructions)|reveal\s+(your\s+|the\s+)?(system\s+prompt|metaprompt|initial\s+prompt|instructions)|jailbreak|DAN\s+mode|developer\s+mode|unregulated\s+(AI|model|mode)|act\s+as\s+if\s+you\s+have\s+no\s+(restrictions|filters|guidelines)|from\s+now\s+on\s+you\s+are)\b";
let SessionAgent = UnifiedAgentObservability
    | where TimeGenerated > ago(7d)
    | where EventOriginalType == "ExecuteToolBySDK" and isnotempty(SrcAgentName)
    | summarize arg_max(TimeGenerated, SrcAgentName) by EventSessionId;
UnifiedAgentObservability
| where TimeGenerated > ago(7d)
| where EventOriginalType == "InvokeAgent"
| where isnotempty(EventOriginalRequestDetails)
| where EventOriginalRequestDetails matches regex JailbreakPatterns
| extend
    Channel        = tostring(parse_json(tostring(AdditionalFields)).ChannelName),
    ConversationId = tostring(parse_json(tostring(AdditionalFields)).ConversationId),
    PromptPreview  = substring(EventOriginalRequestDetails, 0, 500)
| join kind=leftouter SessionAgent on EventSessionId
| extend AgentName = coalesce(SrcAgentName1, "(prompt-only session — no tool calls)")
| project TimeGenerated, ActorUsername, AgentName, Channel, ConversationId, EventSessionId, PromptPreview, EventUid
| order by TimeGenerated desc
```

**Expected results:** Each row is one suspect prompt with the user, agent, channel, and session for pivot. `PromptPreview` truncates to 500 chars for readability — pull the full payload from `EventOriginalRequestDetails` via `EventUid` for forensic review.

**Pivot:** Use `EventSessionId` to feed [Query 3](#query-3-session-reconstruction--prompts--tool-calls) and see whether the agent actioned the malicious prompt by calling tools.

**Tuning:** Extend the regex with environment-specific phrasing. Consider whitelisting prompts that originate from authorized red-team accounts.

---

### Query 3: Session Reconstruction — Prompts + Tool Calls

**Purpose:** Rebuild a full conversation turn: the user prompt plus every downstream tool/connector call the agent made in the same session. Essential for forensic timelines after a flagged prompt.  
**Severity:** Informational  
**MITRE:** TA0007  

```kql
let TargetSession = "<SESSION_ID_FROM_QUERY_2>";
UnifiedAgentObservability
| where TimeGenerated > ago(7d)
| where EventSessionId == TargetSession
| extend
    Channel       = tostring(parse_json(tostring(AdditionalFields)).ChannelName),
    Req           = parse_json(EventOriginalRequestDetails),
    ToolMethod    = tostring(parse_json(EventOriginalRequestDetails).method),
    ToolName_Call = tostring(parse_json(EventOriginalRequestDetails).params.name)
| project
    TimeGenerated,
    EventOriginalType,
    Actor          = iff(ActorUsername == "N/A" or isempty(ActorUsername), SrcAgentName, ActorUsername),
    Channel,
    ToolMethod,
    ToolName_Call,
    PromptOrPayload = substring(EventOriginalRequestDetails, 0, 500),
    EventUid
| order by TimeGenerated asc
```

**Expected results:** Chronological event stream. `InvokeAgent` rows show the user prompt; `ExecuteToolBySDK` rows show JSON-RPC method (`initialize`, `tools/list`, `tools/call`) and the called tool name. A jailbreak that the agent ignored will have `InvokeAgent` rows with no downstream `tools/call` activity touching sensitive tools.

**Tuning:** Replace `TargetSession` with the session ID from Query 2 or 6. Pull full payloads from `EventOriginalRequestDetails` / `EventOriginalResultDetails` via `EventUid`.

---

### Query 4: Tool Invocation Inventory per Agent

**Purpose:** Catalog every MCP tool / connector each agent calls, with call counts and time bounds. Use to validate that agents are only invoking expected tools and to detect new tool usage.  
**Severity:** Informational  
**MITRE:** TA0007  

```kql
UnifiedAgentObservability
| where TimeGenerated > ago(30d)
| where EventOriginalType == "ExecuteToolBySDK"
| extend
    Method      = tostring(parse_json(EventOriginalRequestDetails).method),
    ToolCalled  = tostring(parse_json(EventOriginalRequestDetails).params.name)
| where Method == "tools/call"
| summarize
    Calls       = count(),
    Sessions    = dcount(EventSessionId),
    FirstCall   = min(TimeGenerated),
    LastCall    = max(TimeGenerated)
    by SrcAgentName, ToolName, ToolCalled, ToolOriginalType
| order by SrcAgentName asc, Calls desc
```

**Expected results:** One row per (agent, tool, called-method). `ToolName` is the connector/MCP server identifier; `ToolCalled` is the specific tool/function inside it (e.g., `query_lake`, `Pulse_OpenIncidents_Top10`).

**Tuning:** Filter to `where SrcAgentName == "<AgentName>"` for per-agent drill-down.

---

### Query 5: MCP `query_lake` Argument Audit

**Purpose:** Inspect every KQL `query_lake` invocation the agent made, including the actual KQL text and target workspace. Critical for spotting data-egress patterns or queries that touch sensitive tables.  
**Severity:** Low  
**MITRE:** T1530, TA0009  

```kql
UnifiedAgentObservability
| where TimeGenerated > ago(7d)
| where EventOriginalType == "ExecuteToolBySDK"
| extend Req = parse_json(EventOriginalRequestDetails)
| where tostring(Req.method) == "tools/call"
| where tostring(Req.params.name) == "query_lake"
| extend
    Args             = parse_json(tostring(Req.params.arguments)),
    KqlText          = tostring(parse_json(tostring(Req.params.arguments)).query),
    TargetWorkspace  = tostring(parse_json(tostring(Req.params.arguments)).workspaceId)
| project TimeGenerated, SrcAgentName, EventSessionId, TargetWorkspace, KqlText, EventUid
| order by TimeGenerated desc
```

**Expected results:** Each row exposes the full KQL the agent submitted plus the target workspace. Look for: queries against unexpected workspaces, queries that read PII-heavy tables (`IdentityInfo`, `EmailEvents`), or queries with very large `take` / `limit` values.

**Tuning:** Replace `query_lake` with `RunAdvancedHuntingQuery` or any tool you want to audit. Use `where TargetWorkspace !in ("<expected-ws-1>", "<expected-ws-2>")` to spot cross-workspace queries.

---

### Query 6: Tool Call Failures & Errors

**Purpose:** Surface tool invocations that returned errors or empty responses. Useful for spotting probing behavior (agent trying tools it lacks permission for) and for separating "agent ignored the prompt" from "agent tried but failed".  
**Severity:** Low  
**MITRE:** TA0007  

```kql
UnifiedAgentObservability
| where TimeGenerated > ago(7d)
| where EventOriginalType == "ExecuteToolBySDK"
| extend
    Method     = tostring(parse_json(EventOriginalRequestDetails).method),
    ToolCalled = tostring(parse_json(EventOriginalRequestDetails).params.name),
    HasError   = isnotempty(EventErrorDetails)
        or tostring(EventOriginalResultDetails) contains "\"error\""
        or tostring(EventOriginalResultDetails) contains "\"isError\":true"
| where Method == "tools/call"
| where HasError
| project TimeGenerated, SrcAgentName, EventSessionId, ToolCalled,
          ErrorSnippet = substring(coalesce(EventErrorDetails, tostring(EventOriginalResultDetails)), 0, 400),
          EventUid
| order by TimeGenerated desc
| take 100
```

**Expected results:** Rows where the agent's tool call failed. A spike in failures from a previously-stable agent may indicate permission revocation, broken MCP server, or the agent exploring tools it shouldn't.

**Tuning:** Adjust the `contains` patterns to match the error shape your MCP servers return. Group by `ToolCalled` to find consistently-failing tools.

---

### Query 7: New Tool First-Seen — Baseline Deviation

**Purpose:** Detect tools an agent invoked for the first time in the recent window that weren't part of its 30-day baseline. New tool usage is a strong signal for either (a) intentional agent expansion or (b) unauthorized tool registration.  
**Severity:** Medium  
**MITRE:** T1078.004  

```kql
let Baseline = UnifiedAgentObservability
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where EventOriginalType == "ExecuteToolBySDK"
    | extend ToolCalled = tostring(parse_json(EventOriginalRequestDetails).params.name)
    | where isnotempty(ToolCalled)
    | distinct SrcAgentId, ToolCalled;
UnifiedAgentObservability
| where TimeGenerated > ago(1d)
| where EventOriginalType == "ExecuteToolBySDK"
| extend ToolCalled = tostring(parse_json(EventOriginalRequestDetails).params.name)
| where isnotempty(ToolCalled)
| summarize FirstSeenRecent = min(TimeGenerated), Calls = count() by SrcAgentId, SrcAgentName, ToolCalled
| join kind=leftanti Baseline on SrcAgentId, ToolCalled
| order by FirstSeenRecent desc
```

**Expected results:** One row per (agent, tool) combination that is new in the last 24 hours vs the prior 30-day baseline. Each row should be triaged: is the tool sanctioned? Was it added intentionally?

**Tuning:** Adjust the baseline window (`30d`) and recent window (`1d`) for your environment. Add `where Calls > <N>` to suppress one-off invocations.

---

### Query 8: Channel & User Activity Distribution

**Purpose:** Dashboard view of how agents are being used — which channels carry the prompts, which users are most active, and whether channel mix shifts over time.  
**Severity:** Informational  
**MITRE:** —  

```kql
let SessionAgent = UnifiedAgentObservability
    | where TimeGenerated > ago(30d)
    | where EventOriginalType == "ExecuteToolBySDK" and isnotempty(SrcAgentName)
    | summarize arg_max(TimeGenerated, SrcAgentName) by EventSessionId;
UnifiedAgentObservability
| where TimeGenerated > ago(30d)
| where EventOriginalType == "InvokeAgent"
| where isnotempty(ActorUsername) and ActorUsername != "N/A"
| extend Channel = tostring(parse_json(tostring(AdditionalFields)).ChannelName)
| join kind=leftouter SessionAgent on EventSessionId
| summarize
    Prompts       = count(),
    Sessions      = dcount(EventSessionId),
    Conversations = dcount(tostring(parse_json(tostring(AdditionalFields)).ConversationId)),
    Agents        = make_set(SrcAgentName1, 10),
    FirstPrompt   = min(TimeGenerated),
    LastPrompt    = max(TimeGenerated)
    by ActorUsername, Channel
| order by Prompts desc
```

**Expected results:** One row per (user, channel) combination, ranked by prompt volume. Useful for capacity planning and for spotting users invoking agents from unexpected channels (e.g., Teams when policy restricts to M365 Copilot only).

**Tuning:** Pivot to `by Channel, bin(TimeGenerated, 1d)` for a time-series view of channel adoption.

---

### Query 9: Cross-Source Correlation with CloudAppEvents

**Purpose:** Pair `UnifiedAgentObservability` (agent invocation + tool-call trail) with `CloudAppEvents` `CopilotInteraction` rows (prompt text + Prompt Shield / XPIA / jailbreak verdicts). This gives a unified per-turn view: what the user typed (CAE), whether the content-safety layer flagged it (CAE `Messages[].JailbreakDetected`), and which tools the agent then invoked (UAO `ExecuteToolBySDK`). Split into three variants below: **9a** base correlation, **9b** high-signal prompt-injection → tool-call chain (detection candidate), **9c** per-session safety + tool-use rollup (dashboard).

**Severity:** Medium (when flagged-prompt ↔ tool-call rows surface)  
**MITRE:** T1059 (Command Execution), T1071.001 (Application Layer Protocol), TA0001 (Initial Access via prompt injection)

#### Why join these tables

Each table answers half of the AI-agent-abuse question. Together they answer the whole thing:

| Question the join answers | CAE alone | UAO alone | CAE ⋈ UAO |
|---|---|---|---|
| What did the user type, verbatim? | ✅ | ❌ | ✅ |
| Did Prompt Shield / XPIA / jailbreak detection fire? | ✅ | ❌ | ✅ |
| Which agent answered the prompt? | partial (`AgentId`) | ✅ (`SrcAgentId` + `SrcAgentName`) | ✅ |
| Which tools did the agent invoke in response? | ❌ | ✅ (`ExecuteToolBySDK`) | ✅ |
| What arguments were passed to those tools? | ❌ | ✅ (`AdditionalFields`) | ✅ |
| Which user triggered the tool call? | ✅ (`UserId` UPN) | ❌ (`ActorUsername = "N/A"` on tool rows) | ✅ |
| Did the verdict-flagged prompt actually touch sensitive data? | ❌ | ❌ | ✅ |

**Operational benefits:**

- **Content-safety overlay on agent telemetry.** UAO has no Prompt Shield / XPIA / jailbreak verdict; the join attaches one to every tool-call chain.
- **High-signal detection composition.** A Prompt Shield hit alone is noisy. A Prompt Shield hit **+ a UAO tool call against sensitive surfaces in the same session** is a near-certain incident — see [Query 9b](#query-9b-cross-source-high-signal--prompt-injection--downstream-tool-calls).
- **Forensic chain-of-events per turn.** Reconstruct end-to-end: prompt text → verdict → agent → every tool call recorded by UAO, in one row set.
- **Recovers user identity that UAO loses.** CAE has authoritative `UserId` (UPN) + `AccountObjectId` (Entra GUID) for the same turn UAO marks `N/A`.
- **Foundation for cross-source Custom Detections.** Both sides can be promoted through KQL Jobs and joined in an Analytics-tier CD — not yet built; would extend the D1–D3 set in this file.

#### Cross-scope mechanics (read before running)

- `CloudAppEvents` lives in the **workspace** scope; `UnifiedAgentObservability` lives in the **lake `default`** system scope. The MCP `workspaceId` parameter accepts one ID only — comma/semicolon lists return `Kusto database name not found`.
- **The only working direction:** set `workspaceId` to the **workspace GUID**, then reach into the lake via `workspace("default").UnifiedAgentObservability`. The reverse (`workspaceId: "default"` + `workspace("<guid>").CloudAppEvents`) is denied with `WorkspaceNotAvailable`.
- In the Defender portal **KQL queries** page, this same query runs as-is when the workspace selector includes both the workspace and **System tables**.

#### Joinable identifiers

| CloudAppEvents (CopilotInteraction) | UnifiedAgentObservability | Notes |
|---|---|---|
| `tostring(split(parse_json(tostring(RawEventData)).AgentId, ".")[1])` (agent SPN GUID) | `SrcAgentId` | ✅ **Primary join key.** AgentId is formatted `T_<TargetPlatformAgentId>.<servicePrincipalId>`; the second segment is the SPN GUID that matches UAO. |
| `tostring(parse_json(tostring(RawEventData)).UserId)` (UPN) | `ActorUsername` | ⚠️ UAO sets `ActorUsername = "N/A"` on `ExecuteToolBySDK` rows. Only `InvokeAgent` rows carry the real user UPN. **Do not add as a join-equality filter** when correlating to tool calls. |
| `Timestamp` | `TimeGenerated` | ✅ Tie-breaker — use a `±5–10 min` window per (agent, user) tuple. Lab observation: CAE timestamps trail UAO tool calls by ~10s–10min (CAE writes at prompt completion; UAO writes per tool call mid-flight). Use `abs(datetime_diff(...))` — sign of the delta varies. |
| `parse_json(tostring(RawEventData)).CopilotEventData.ThreadId` (Teams `19:…@thread.v2`) | `AdditionalFields.ConversationId` (GUID) | ❌ Different namespaces — not joinable. |

#### Field-name pitfalls (validated in tested tenants)

- **`UnifiedAgentObservability.ToolName` is a top-level column**, NOT inside `AdditionalFields`. `AF.ToolName` returns null silently — every `ToolsUsed` aggregate looks empty. Also top-level: `ToolId`, `ToolDescription`, `ToolOriginalType`.
- **`AdditionalFields` on `ExecuteToolBySDK` rows** contains: `ConversationId`, `ConversationLink`, `ChannelName`, `ChannelLink`, `OpId`, `ParentId`, `AdministratorUserKey`, `CorrelationIdentity`, `ThreadId`, `ExecutionType`, `InvokeSource`, `UserType`. **No tool name, no tool arguments** — tool args are not currently exposed in this schema version.
- **`CloudAppEvents` `CopilotEventData.Messages[]` schema is minimal in current tenants.** Observed keys: `Id`, `JailbreakDetected` (**PascalCase**, NOT `jailbreakDetected`), `isPrompt`. Documented fields `xpiaDetected`, `indirectPromptInjectionDetected`, `classifications`, `promptShieldDetections`, `text` were **not present** in tested tenants — `tobool(Msg.xpiaDetected)` silently returns `null` (→ `false`). Use `coalesce(Msg.JailbreakDetected, Msg.jailbreakDetected, …)` for forward compat, but rely on `JailbreakDetected` today.
- **`InvokeAgent` rows have `SrcAgentId = "00000000-0000-0000-0000-000000000000"`.** Any filter that excludes the zero-GUID drops all `InvokeAgent` rows — `countif(EventOriginalType == "InvokeAgent")` will be 0 after that filter. To keep both event types in a per-session rollup, summarize by `EventSessionId` first and look up the agent name from the `ExecuteToolBySDK` rows.

### Query 9a: Cross-Source Base Correlation — prompts ↔ tool calls

Foundation query. Returns one row per (CAE prompt × UAO event) pair inside the time window.

```kql
// Cross-source correlation — CloudAppEvents Copilot prompts ↔ UAO agent tool calls
// Run from Defender portal with workspace + System tables selected,
// OR via query_lake with workspaceId = <workspace-guid>.
let WindowSec = 600;
let UAO =
    workspace("default").UnifiedAgentObservability
    | where TimeGenerated > ago(7d)
    | where EventOriginalType in ("InvokeAgent", "ExecuteToolBySDK")
    | where isnotempty(SrcAgentId) and SrcAgentId != "00000000-0000-0000-0000-000000000000"
    | extend AF = parse_json(tostring(AdditionalFields))
    | project UAO_Time = TimeGenerated,
              UAO_Actor = ActorUsername,
              SrcAgentId,
              SrcAgentName,
              EventSessionId,
              EventOriginalType,
              ToolName,                                 // top-level column, NOT inside AF
              ConversationId  = tostring(AF.ConversationId),
              ChannelName     = tostring(AF.ChannelName);
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType == "CopilotInteraction"
| extend P = parse_json(tostring(RawEventData))
| extend AgentSpnId = tostring(split(tostring(P.AgentId), ".")[1])
| extend UserUpn    = tostring(P.UserId)
| extend AppHost    = tostring(P.CopilotEventData.AppHost)
| extend ThreadId   = tostring(P.CopilotEventData.ThreadId)
| extend AgentName  = tostring(coalesce(P.AgentName, P.CopilotEventData.TargetAgentName))
| where isnotempty(AgentSpnId)
| project CAE_Time = TimeGenerated, UserUpn, AgentSpnId, AgentName, AppHost, ThreadId
| join kind=inner UAO on $left.AgentSpnId == $right.SrcAgentId
| where abs(datetime_diff('second', UAO_Time, CAE_Time)) <= WindowSec
| project CAE_Time, UAO_Time, UserUpn, AgentName, AgentSpnId, AppHost,
          EventOriginalType, ToolName, ConversationId, ChannelName, ThreadId, EventSessionId
| order by CAE_Time desc
```

**Expected results:** For each user prompt, every `InvokeAgent` + `ExecuteToolBySDK` event for the same agent SPN within ±10 minutes. *(Note: in current schema, `InvokeAgent` rows get filtered out by the zero-GUID `SrcAgentId` exclusion — practical output is prompts ↔ `ExecuteToolBySDK` only. Remove that filter if you want both.)*

**Tuning:**
- `WindowSec = 600` (10 min) is the practical default. Observed `DeltaSec` can range several minutes in either direction — the sign varies because UAO writes per tool call mid-flight while CAE finalizes at prompt completion. Always use `abs(datetime_diff(...))` for the window check. Do **not** tighten below ~120s without verifying your tenant's lag distribution; for autonomous-agent loops the same agent may produce tool calls 8–10 min before its companion CAE prompt finalizes.
- To attribute a tool call back to its triggering user without trusting `ActorUsername`, group by `(EventSessionId, SrcAgentId)` inside UAO so each session inherits the UPN from CAE.
- Filter `AppHost` to scope to a channel: `Office` (Copilot Studio in M365 apps), `m365copilot` (Microsoft 365 Copilot), `Teams`.
- 9a defaults to `ago(7d)`; 9b and 9c use `ago(30d)` because flagged-prompt density is typically low. Adjust per-query lookback to your jailbreak rate.
- **One agent SPN may front multiple `AgentName` personas in CAE** — a single SPN GUID can serve several distinct custom Copilot Studio agents. Pivot by `AgentName` (from CAE) for human-readable triage and `AgentSpnId` for identity attribution.

---

### Query 9b: Cross-Source High-Signal — prompt injection → downstream tool calls

Restricts 9a to (1) prompts that tripped Prompt Shield / jailbreak detection in CAE **and** (2) every tool call UAO recorded for the same agent within the time window. This is the highest-confidence dual-source signal for confirmed AI agent abuse — and the most-likely candidate for a future cross-source Custom Detection (would extend D1–D3).

```kql
let WindowSec = 600;
// Optional sensitive-surface allowlist — tool names vary by environment.
// Common shapes seen: `<customermcp>:<method>`, `crd90-5f<hex-encoded-mcp-name>…:InvokeServer`
// (Copilot Studio MCP shim), `<publicmcp>:<method>`.
// ⚠️ KQL TOKENIZER PITFALL: `has` / `has_any` are term-based and split on `-` `_` `:`.
//    `has_any (["sentinel-2dmcp"])` does NOT match `crd90-5fsentinel-2dmcp-2dtools-...`
//    because the surrounding `5f` / `2dtools` prefixes break term adjacency.
//    Use `matches regex` instead so we get true substring matching across encoded names.
//    Set SensitiveToolPattern = "" (or comment out the regex filter) to surface EVERY
//    tool call after a flagged prompt — useful when first mapping sensitive tools.
let SensitiveToolPattern = @"(?i)(query_lake|runadvancedhuntingquery|sentinel-?2?d-?mcp|secret|keyvault|sendmail|send_email|createmessage|uploadfile|drive_item|graph_post|graph_patch|graph_put|create_user|add_member|role_assign)";
let UAOSensitive =
    workspace("default").UnifiedAgentObservability
    | where TimeGenerated > ago(30d)
    | where EventOriginalType == "ExecuteToolBySDK"
    | where isnotempty(SrcAgentId) and SrcAgentId != "00000000-0000-0000-0000-000000000000"
    | where isempty(SensitiveToolPattern) or ToolName matches regex SensitiveToolPattern
    | extend AF = parse_json(tostring(AdditionalFields))
    | project UAO_Time = TimeGenerated, SrcAgentId, SrcAgentName, EventSessionId,
              ToolName, ConversationId = tostring(AF.ConversationId),
              ChannelName = tostring(AF.ChannelName);
let CAEFlagged =
    CloudAppEvents
    | where TimeGenerated > ago(30d)
    | where ActionType == "CopilotInteraction"
    | where RawEventData has_any ("JailbreakDetected", "jailbreakDetected", "xpiaDetected", "promptShield", "indirectPromptInjection", "classifications")
    | extend P = parse_json(tostring(RawEventData))
    | mv-expand Msg = P.CopilotEventData.Messages
    | extend Jb   = tobool(coalesce(Msg.JailbreakDetected, Msg.jailbreakDetected, Msg.containsJailbreak)),
             Xpia = tobool(coalesce(Msg.xpiaDetected, Msg.indirectPromptInjectionDetected)),
             PSD  = tostring(Msg.promptShieldDetections),
             Cls  = tostring(Msg.classifications)
    | where Jb == true
         or Xpia == true
         or (isnotempty(PSD) and PSD != "[]" and PSD != "null")
         or Cls has_any ("jailbreak", "xpia", "prompt_injection")
    | extend SafetyVerdict = case(Jb, "jailbreak",
                                  Xpia, "xpia/indirect_prompt_injection",
                                  isnotempty(PSD), "promptShield",
                                  Cls)
    | extend AgentSpnId = tostring(split(tostring(P.AgentId), ".")[1])
    | extend UserUpn    = tostring(P.UserId)
    | extend AppHost    = tostring(P.CopilotEventData.AppHost)
    | extend AgentName  = tostring(coalesce(P.AgentName, P.CopilotEventData.TargetAgentName))
    | extend ThreadId   = tostring(P.CopilotEventData.ThreadId)
    | where isnotempty(AgentSpnId)
    | project CAE_Time = TimeGenerated, UserUpn, AgentSpnId, AgentName, AppHost, ThreadId, SafetyVerdict;
CAEFlagged
| join kind=inner UAOSensitive on $left.AgentSpnId == $right.SrcAgentId
| where abs(datetime_diff('second', UAO_Time, CAE_Time)) <= WindowSec
| project CAE_Time, UAO_Time,
          DeltaSec = datetime_diff('second', UAO_Time, CAE_Time),
          UserUpn, AgentName, AgentSpnId, AppHost,
          SafetyVerdict, ToolName, ChannelName, ConversationId, ThreadId, EventSessionId
| order by CAE_Time desc, UAO_Time asc
```

**Expected results:** One row per (CAE flagged-prompt message × UAO sensitive tool call) within `WindowSec`. Each CAE event fans out via `mv-expand Msg` (typically 3 messages per prompt), so a single jailbreak prompt can produce multiple paired rows. Add a `summarize` step (group by `(CAE_Time, UAO_Time, ConversationId, ToolName)`) for deduplicated incident counts, or use **Query 9c** for the per-session rollup.

`DeltaSec` is `UAO_Time - CAE_Time`. Negative values mean UAO recorded the tool call *before* CAE finalized the prompt — expected for autonomous-agent loops (UAO writes per tool call mid-flight; CAE writes at completion). Positive values are the more intuitive "prompt then tool" order.

**⚠️ Lessons learned during validation:**
1. **Hex-encoded `crd90-…:InvokeServer` tool names are invisible to `has` / `has_any`.** KQL `has` is term-tokenized and `-` / `_` boundaries break the match — `has_any (["sentinel-2dmcp"])` silently drops them. Use `matches regex` (as above). If you change the pattern list, sanity-check with `where ToolName matches regex <pattern> | distinct ToolName | take 50`.
2. **Per-message fan-out overstates analyst workload** — a single autonomous-agent session can produce many `InvokeServer` rows. For triage use **Query 9c** which collapses to one row per (user × agent × session) and is the right grain for a Custom Detection candidate.
3. **A flagged prompt that produces zero Q9b rows is meaningful too** — it implies Prompt Shield blocked and the agent didn't execute a sensitive tool within the window. To audit blocked-but-not-acted-on prompts as a separate signal, query `CloudAppEvents | where ActionType == "CopilotInteraction"` for `JailbreakDetected=true` and `anti-join` to Q9b on `(AgentSpnId, CAE_Time)`.

**Tuning:**
- Extend `SensitiveToolPattern` with internal MCP tool names specific to your environment (regex alternation, lowercase — the `(?i)` flag handles case). Avoid using `has` / `has_any` on hex-encoded MCP shim names — use regex.
- Set `SensitiveToolPattern = ""` (empty string) to surface every tool call after a flagged prompt — useful when first mapping which MCP tools are sensitive.
- Drop the `CAEFlagged` arm entirely to surface "abnormal tool-call pattern without a safety hit" — catches jailbreaks the safety layer missed.
- **`ToolArgs` is not in current `AdditionalFields` schema** — the tool input/output is not currently exposed. For tool argument inspection, fall back to vendor-specific telemetry (e.g., Defender MCP audit logs if the agent uses an MCP server with its own audit channel).

---

### Query 9c: Cross-Source Per-Session Rollup — safety + tool-use

Collapses 9a to one row per (user × agent × session) with safety-hit count and the full tool list. Good for triage dashboards and weekly executive summaries — "which sessions had both a safety hit and tool activity?"

```kql
let LookbackDays = 30d;
let UAOSession =
    workspace("default").UnifiedAgentObservability
    | where TimeGenerated > ago(LookbackDays)
    | where EventOriginalType == "ExecuteToolBySDK"   // InvokeAgent uses zero-GUID SrcAgentId — drop here, fold in via session join if needed
    | where isnotempty(SrcAgentId) and SrcAgentId != "00000000-0000-0000-0000-000000000000"
    | summarize SessionStart   = min(TimeGenerated),
                SessionEnd     = max(TimeGenerated),
                ToolCallCount  = count(),
                ToolsUsed      = make_set_if(ToolName, isnotempty(ToolName), 30)
                by SrcAgentId, SrcAgentName, EventSessionId;
let CAESession =
    CloudAppEvents
    | where TimeGenerated > ago(LookbackDays)
    | where ActionType == "CopilotInteraction"
    | extend P = parse_json(tostring(RawEventData))
    | extend AgentSpnId = tostring(split(tostring(P.AgentId), ".")[1])
    | extend UserUpn    = tostring(P.UserId)
    | extend AppHost    = tostring(P.CopilotEventData.AppHost)
    | extend AgentName  = tostring(coalesce(P.AgentName, P.CopilotEventData.TargetAgentName))
    | mv-apply Msg = P.CopilotEventData.Messages on (
        extend SafetyHit = tobool(coalesce(Msg.JailbreakDetected, Msg.jailbreakDetected))   // PascalCase observed; lowercase kept for forward compat
                        or tobool(coalesce(Msg.xpiaDetected, Msg.indirectPromptInjectionDetected)))
    | where isnotempty(AgentSpnId)
    | summarize CAEStart        = min(TimeGenerated),
                CAEEnd          = max(TimeGenerated),
                PromptCount     = count(),
                SafetyHits      = countif(SafetyHit),
                Channels        = make_set(AppHost)
                by UserUpn, AgentSpnId, AgentName;
CAESession
| join kind=inner UAOSession on $left.AgentSpnId == $right.SrcAgentId
| where SessionEnd between (CAEStart - 10m .. CAEEnd + 10m)
| project UserUpn, AgentName, AgentSpnId, EventSessionId,
          SessionStart, SessionEnd,
          PromptCount, SafetyHits, ToolCallCount,
          Channels, ToolsUsed
| extend RiskFlag = case(SafetyHits > 0 and ToolCallCount > 0, "🔴 safety hit + tool use",
                         SafetyHits > 0, "🟠 safety hit only",
                         ToolCallCount > 10, "🟡 high tool volume",
                         "✅ normal")
| order by SafetyHits desc, ToolCallCount desc
```

**Expected results:** One row per session-grouping. Sort by `SafetyHits` desc — the `🔴 safety hit + tool use` rows are the priority queue. The `ToolsUsed` array tells you exactly what the agent did during a flagged session without opening individual rows. Lab validation (30d window) returned ~30 sessions with 2 `🔴 safety hit + tool use` rows surfacing the same 3 jailbreak incidents 9b found.

**Tuning:**
- Replace the time-overlap join with `EventSessionId == ConversationId`-equivalent matching if your environment populates `AdditionalFields.ConversationId` reliably.
- Add `| where SafetyHits > 0` to scope the rollup to flagged sessions only.

---

### Query 9d: Cross-Source Safety Audit — every flagged prompt with prompt text + tool activity

Variant of 9b that keeps **every** CAE-flagged prompt regardless of whether a downstream tool call followed, **and surfaces the actual prompt content** by joining to `UnifiedAgentObservability.InvokeAgent` rows. CAE itself never logs prompt body (only `{Id, JailbreakDetected, isPrompt}` metadata) — but UAO `InvokeAgent.EventOriginalRequestDetails` IS the raw user message string. This query correlates both sides so a single row tells you (a) the safety verdict, (b) **what the user actually typed**, and (c) what tools the agent then invoked.

**Join logic:** Two separate `leftouter` joins against UAO — `InvokeAgent` on `ActorUsername == UserUpn`, `ExecuteToolBySDK` on `SrcAgentId == AgentSpnId` — both filtered to the same ±`WindowSec` window around the CAE flag time, then merged on a synthetic `FlaggedId`. Necessary because the two UAO event types use different join keys (UPN vs Agent SPN GUID).

```kql
let WindowSec = 600;
let CAEFlagged =
    CloudAppEvents
    | where TimeGenerated > ago(30d)
    | where ActionType == "CopilotInteraction"
    | where RawEventData has_any ("JailbreakDetected", "jailbreakDetected", "xpiaDetected", "promptShield", "indirectPromptInjection", "classifications")
    | extend P = parse_json(tostring(RawEventData))
    | mv-expand Msg = P.CopilotEventData.Messages
    | extend Jb   = tobool(coalesce(Msg.JailbreakDetected, Msg.jailbreakDetected, Msg.containsJailbreak)),
             Xpia = tobool(coalesce(Msg.xpiaDetected, Msg.indirectPromptInjectionDetected)),
             PSD  = tostring(Msg.promptShieldDetections),
             Cls  = tostring(Msg.classifications)
    | where Jb == true
         or Xpia == true
         or (isnotempty(PSD) and PSD != "[]" and PSD != "null")
         or Cls has_any ("jailbreak", "xpia", "prompt_injection")
    | extend SafetyVerdict = case(Jb, "jailbreak",
                                  Xpia, "xpia/indirect_prompt_injection",
                                  isnotempty(PSD), "promptShield",
                                  Cls)
    | extend AgentSpnId = tostring(split(tostring(P.AgentId), ".")[1])
    | extend UserUpn    = tostring(P.UserId)
    | extend AgentName  = tostring(coalesce(P.AgentName, P.CopilotEventData.TargetAgentName))
    | extend ThreadId   = tostring(P.CopilotEventData.ThreadId)
    | where isnotempty(AgentSpnId)
    // Collapse mv-expand fan-out: one row per unique flagged prompt
    | summarize CAE_Time = min(TimeGenerated), SafetyVerdicts = make_set(SafetyVerdict, 5)
                by AgentSpnId, AgentName, UserUpn, ThreadId
    | extend FlaggedId = strcat(tostring(CAE_Time), "|", UserUpn, "|", AgentSpnId, "|", ThreadId);
// UAO side 1: actual prompt text (InvokeAgent rows have EventOriginalRequestDetails = raw user message)
let UAOInvoke =
    workspace("default").UnifiedAgentObservability
    | where TimeGenerated > ago(30d)
    | where EventOriginalType == "InvokeAgent"
    | extend JoinUpn = tolower(ActorUsername)
    | project IA_Time = TimeGenerated, JoinUpn, IA_Session = EventSessionId,
              Prompt = tostring(EventOriginalRequestDetails);
// UAO side 2: tool calls
let UAOTool =
    workspace("default").UnifiedAgentObservability
    | where TimeGenerated > ago(30d)
    | where EventOriginalType == "ExecuteToolBySDK"
    | where isnotempty(SrcAgentId) and SrcAgentId != "00000000-0000-0000-0000-000000000000"
    | extend JoinSpn = tolower(SrcAgentId)
    | project TC_Time = TimeGenerated, JoinSpn, TC_Session = EventSessionId, ToolName;
// Join 1: prompts by UPN
let WithPrompts =
    CAEFlagged
    | extend JoinUpn = tolower(UserUpn)
    | join kind=leftouter UAOInvoke on JoinUpn
    | extend InWin = isnotnull(IA_Time) and abs(datetime_diff('second', IA_Time, CAE_Time)) <= WindowSec
    | summarize Prompts        = make_set_if(Prompt, InWin, 10),
                PromptSessions = make_set_if(IA_Session, InWin, 10),
                PromptCount    = countif(InWin)
                by FlaggedId, CAE_Time, UserUpn, AgentName, AgentSpnId, tostring(SafetyVerdicts);
// Join 2: tool calls by Agent SPN
let WithTools =
    CAEFlagged
    | extend JoinSpn = tolower(AgentSpnId)
    | join kind=leftouter UAOTool on JoinSpn
    | extend InWin = isnotnull(TC_Time) and abs(datetime_diff('second', TC_Time, CAE_Time)) <= WindowSec
    | summarize Tools        = make_set_if(ToolName, InWin, 20),
                ToolSessions = make_set_if(TC_Session, InWin, 10),
                ToolCalls    = countif(InWin)
                by FlaggedId;
WithPrompts
| join kind=leftouter WithTools on FlaggedId
| extend Outcome = case(PromptCount == 0 and ToolCalls == 0, "🟢 blocked (no UAO activity)",
                        ToolCalls == 0,                       "🟡 prompt seen, no tool calls (blocked downstream)",
                        ToolCalls <= 3,                       "🟠 acted on (low)",
                                                              "🔴 acted on (high)")
| project CAE_Time, UserUpn, AgentName, SafetyVerdicts, Outcome,
          PromptCount, ToolCalls, Prompts, Tools, PromptSessions, ToolSessions
| order by CAE_Time desc
```

**Expected results:** One row per (flagged prompt × agent × thread), with the actual jailbreak attempt visible in `Prompts`. Outcomes range from 🟢 blocked (no UAO activity) to 🔴 acted on (high) based on tool-call volume within `WindowSec`. `PromptSessions` and `ToolSessions` are typically identical GUIDs per row when correlation is clean — confirming the time-window join is picking up the right session on both sides without needing an explicit `EventSessionId` join.

**Outcome semantics:**

| Outcome | PromptCount | ToolCalls | Meaning |
|---|---|---|---|
| 🟢 blocked (no UAO activity) | 0 | 0 | CAE fired but no UAO trace at all — likely an autonomous-agent flagged turn with no follow-on action, or a session outside the time window |
| 🟡 prompt seen, no tool calls | ≥1 | 0 | User typed the prompt, the safety layer fired, agent invoked zero tools — **strongest "safety layer worked" signal** |
| 🟠 acted on (low) | ≥1 | 1–3 | Agent ran a small number of tools despite the flag |
| 🔴 acted on (high) | ≥1 | >3 | Agent fully executed despite the flag |

**How this differs from 9b:**

| Aspect | 9b (high-signal detection) | 9d (audit complement) |
|---|---|---|
| Join kind | `inner` — drops blocked prompts | `leftouter` ×2 — keeps every flagged prompt |
| Tool filter | `SensitiveToolPattern` regex | None — counts ALL tool activity |
| Prompt text | ❌ not surfaced | ✅ from UAO `InvokeAgent.EventOriginalRequestDetails` |
| Grain | one row per (CAE_Msg × UAO event) — fan-out | one row per (flagged prompt × agent × thread) |
| Use case | Custom Detection candidate | Safety-layer KPI / weekly audit / triage report |

**Tuning:**
- The `Prompts` array contains ALL user messages from that UPN within ±`WindowSec` — including benign follow-ups (e.g., *"What can you do?"*, *"Check for rare processes"*). To narrow to only the flagged message specifically, join on `EventSessionId == ConversationId`-equivalent (requires `AdditionalFields.ConversationId` parsing on the UAO side).
- For triage workflows where prompt text is the priority, swap the `make_set_if` cap from 10 to 1 and prefer `take_any` to capture only the first prompt.
- Add a per-day rollup downstream (`| summarize Blocked = countif(Outcome startswith "🟢"), DownstreamBlocked = countif(Outcome startswith "🟡"), ActedOn = countif(Outcome !startswith "🟢" and Outcome !startswith "🟡") by bin(CAE_Time, 1d)`) as a safety-layer KPI time-series.
- Set `WindowSec` to your largest observed lag from Q9a (`abs(DeltaSec)` max).
- **Privacy note:** Prompt text may contain PII or sensitive content. Restrict access to this query and any KQL Job (J5 candidate) materializing it.

---

## KQL Jobs — Promote Summarized Data to Analytics Tier

`UnifiedAgentObservability` is a **Data Lake-only system table**, so Analytics-tier detection rules (Sentinel scheduled analytics, NRT, Defender XDR Custom Detections) cannot be written directly against it. Use **[KQL Jobs](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-jobs)** to summarize and promote the high-value subsets into custom Analytics-tier tables (auto-suffixed `_KQL_CL`), then build paired Custom Detections on those tables.

### Job design constraints (from MS Learn)

| Constraint | Value |
|---|---|
| Query time range | Up to **12 years** |
| Job execution timeout | 1 hour |
| Concurrent jobs per tenant | 3 |
| Enabled jobs per tenant | 100 |
| Output tables per job | 1 |
| Schedule frequency | By minute / Hourly / Daily / Weekly / Monthly |
| Ingestion latency | ~15 min for new lake data |
| `TimeGenerated` | Overwritten by ingestion if older than 2 days — preserve source event time in a separate column (`EventTime` in the jobs below) |
| Job names | Up to 256 chars; no `#` or `-` |
| Not supported | `adx()`, `arg()`, `externaldata()`, `ingestion_time()`, user-defined functions |

**Common pattern:** Use `let endTime = now() - 15m;` (delay) and an overlapping lookback (e.g., 1h15m for an hourly job) so late-arriving rows aren't missed. **Project a stable schema** (the destination `_KQL_CL` table is created from the first run's columns) and **avoid dynamic columns** in the output — cast to `string` / `long` / `bool` first.

**Prerequisite:** The data lake managed identity (`msg-resources-<guid>`) needs the **Log Analytics Contributor** role on the destination LA workspace to create the `_KQL_CL` table on first run. See [permissions setup](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-jobs#permissions).

### Job 1 — Hourly Jailbreak Incident Promotion (CAE-anchored)

**Job name:** `A365_JailbreakIncidents_Hourly`  
**Destination:** `A365_JailbreakIncidents_KQL_CL` (new table, Analytics tier)  
**Schedule:** Hourly, repeat every 1 hour  
**Purpose:** Materialize **Query 9c** as an Analytics-tier table. Anchors on Azure Prompt Shield's `JailbreakDetected` verdict in `CloudAppEvents` (Microsoft's ML classifier, the authoritative signal) and enriches with the actual prompt text from UAO `InvokeAgent` plus downstream tool calls from UAO `ExecuteToolBySDK` within `WindowSec`. Output is one row per (user × agent × session) with a derived `Severity` based on tool-call count — the right grain for a Custom Detection.

> **Why not regex on prompt text?** Earlier drafts of this job ran a regex (`ignore previous instructions`, `DAN mode`, etc.) against UAO `EventOriginalRequestDetails`. That approach reinvents Prompt Shield with worse coverage (misses obfuscation, multilingual attacks, novel phrasings) and generates false positives on benign prompts like *"ignore the previous results"*. The CAE join below uses Microsoft's classifier as the source of truth.

```kql
let lookback  = 1h;
let delay     = 15m;
let endTime   = now() - delay;
let startTime = endTime - lookback - 15m;  // 15 min overlap for late arrivals
let WindowSec = 600;                       // ±10 min CAE↔UAO correlation window
let CAEFlagged =
    CloudAppEvents
    | where TimeGenerated between (startTime .. endTime)
    | where ActionType == "CopilotInteraction"
    | extend P = parse_json(tostring(RawEventData))
    | mv-expand Msg = P.CopilotEventData.Messages
    | extend Jb         = tobool(coalesce(Msg.JailbreakDetected, Msg.jailbreakDetected, Msg.containsJailbreak)),
             Xpia       = tobool(coalesce(Msg.xpiaDetected, Msg.indirectPromptInjectionDetected)),
             PSD        = tostring(Msg.promptShieldDetections),
             Cls        = tostring(Msg.classifications)
    | where Jb == true or Xpia == true
         or (isnotempty(PSD) and PSD != "[]" and PSD != "null")
         or Cls has_any ("jailbreak", "xpia", "prompt_injection")
    | extend AgentSpnId = tostring(split(tostring(P.AgentId), ".")[1]),
             UserUpn    = tolower(tostring(P.UserId)),
             AgentName  = tostring(coalesce(P.AgentName, P.CopilotEventData.TargetAgentName)),
             AppHost    = tostring(P.CopilotEventData.AppHost),
             ThreadId   = tostring(P.CopilotEventData.ThreadId)
    | where isnotempty(AgentSpnId)
    | summarize CAE_Time            = min(TimeGenerated),
                FlaggedMessageCount = count(),
                SafetyVerdicts      = make_set(pack("Jb", Jb, "Xpia", Xpia, "PSD", PSD, "Cls", Cls), 10)
          by AgentSpnId, AgentName, AppHost, UserUpn, ThreadId
    | extend FlaggedId = strcat(UserUpn, "|", AgentSpnId, "|", ThreadId);
let UAOInvoke =
    workspace("default").UnifiedAgentObservability
    | where TimeGenerated between (startTime .. endTime)
    | where EventOriginalType == "InvokeAgent"
    | where isnotempty(EventOriginalRequestDetails)
    | extend JoinUpn = tolower(ActorUsername),
             IA_Time = TimeGenerated,
             Prompt  = tostring(EventOriginalRequestDetails)
    | project IA_Time, JoinUpn, Prompt;
let UAOTool =
    workspace("default").UnifiedAgentObservability
    | where TimeGenerated between (startTime .. endTime)
    | where EventOriginalType == "ExecuteToolBySDK"
    | where SrcAgentId != "00000000-0000-0000-0000-000000000000"
    | extend JoinSpn = tolower(SrcAgentId),
             TT_Time = TimeGenerated,
             Tool    = tostring(parse_json(EventOriginalRequestDetails).params.name)
    | project TT_Time, JoinSpn, Tool;
let WithPrompts =
    CAEFlagged
    | join kind=leftouter UAOInvoke on $left.UserUpn == $right.JoinUpn
    | where isnull(IA_Time) or abs(datetime_diff('second', IA_Time, CAE_Time)) <= WindowSec
    | summarize PromptPreview = take_any(substring(Prompt, 0, 1000)),
                PromptLength  = take_any(strlen(Prompt)),
                PromptHash    = take_any(hash_sha256(Prompt)),
                PromptCount   = countif(isnotempty(Prompt))
          by FlaggedId, CAE_Time, UserUpn, AgentName, AgentSpnId, AppHost,
             ThreadId, FlaggedMessageCount, tostring(SafetyVerdicts);
let WithTools =
    CAEFlagged
    | join kind=leftouter UAOTool on $left.AgentSpnId == $right.JoinSpn
    | where isnull(TT_Time) or abs(datetime_diff('second', TT_Time, CAE_Time)) <= WindowSec
    | summarize ToolList  = tostring(make_set(Tool, 25)),
                ToolCount = countif(isnotempty(Tool))
          by FlaggedId;
WithPrompts
| join kind=leftouter WithTools on FlaggedId
| extend Severity = case(ToolCount == 0 and PromptCount == 0, "Informational",
                         ToolCount == 0,                       "Low",
                         ToolCount <= 3,                       "Medium",
                                                               "High"),
         EventTime = CAE_Time,
         EventId   = hash_sha256(FlaggedId)
| project EventTime, UserUpn, AgentName, AgentSpnId, AppHost, ThreadId,
          SafetyVerdicts, FlaggedMessageCount,
          PromptPreview, PromptLength, PromptHash, PromptCount,
          ToolList, ToolCount, Severity, EventId
```

**Output schema:** `EventTime:datetime, UserUpn:string, AgentName:string, AgentSpnId:string, AppHost:string, ThreadId:string, SafetyVerdicts:string, FlaggedMessageCount:long, PromptPreview:string, PromptLength:long, PromptHash:string, PromptCount:long, ToolList:string, ToolCount:long, Severity:string, EventId:string`.

**Severity semantics:**

| Severity | PromptCount | ToolCount | Meaning |
|---|---|---|---|
| Informational | 0 | 0 | CAE fired but no UAO trace within ±`WindowSec` — likely autonomous-agent flagged turn with no follow-on action, or session outside the window |
| Low | ≥1 | 0 | Prompt seen, safety layer blocked downstream — **strongest "safety layer worked" signal** |
| Medium | ≥1 | 1–3 | Agent ran a small number of tools despite the flag |
| High | ≥1 | >3 | Agent fully executed despite the flag |

**⚠️ Privacy note:** `PromptPreview` may contain PII or sensitive content. Restrict access to this table and any downstream detections.

---

### Job 2 — Hourly `query_lake` Argument Audit

**Job name:** `A365_QueryLake_Audit_Hourly`  
**Destination:** `A365_QueryLakeAudit_KQL_CL` (new table, Analytics tier)  
**Schedule:** Hourly, repeat every 1 hour  
**Purpose:** Promote every `query_lake` MCP invocation — including the full KQL text submitted by the agent — plus a precomputed `TouchesSensitive` flag for fast detection. Pair with Detection 2.  

```kql
let lookback = 1h;
let delay    = 15m;
let endTime  = now() - delay;
let startTime = endTime - lookback - 15m;
let SensitiveTablePattern = @"(?i)\b(identityinfo|identitylogonevents|emailevents|emailurlinfo|emailattachmentinfo|urlclickevents|datasecurityevents|behavioranalytics|aadriskyusers|aaduserriskevents|azurediagnostics|signinlogs|officeactivity|cloudappevents)\b";
UnifiedAgentObservability
| where TimeGenerated between (startTime .. endTime)
| where EventOriginalType == "ExecuteToolBySDK"
| extend Req = parse_json(EventOriginalRequestDetails)
| where tostring(Req.method) == "tools/call"
| where tostring(Req.params.name) == "query_lake"
| extend
    Args            = parse_json(tostring(Req.params.arguments)),
    KqlText         = tostring(parse_json(tostring(Req.params.arguments)).query),
    TargetWorkspace = tostring(parse_json(tostring(Req.params.arguments)).workspaceId)
| extend
    EventTime           = TimeGenerated,
    AgentName           = SrcAgentName,
    AgentId             = SrcAgentId,
    SessionId           = EventSessionId,
    KqlLength           = strlen(KqlText),
    TouchesSensitive    = iff(KqlText matches regex SensitiveTablePattern, true, false),
    SensitiveTablesJson = tostring(extract_all(SensitiveTablePattern, KqlText)),
    EventId             = EventUid
| project EventTime, AgentName, AgentId, SessionId, TargetWorkspace, KqlText,
          KqlLength, TouchesSensitive, SensitiveTablesJson, EventId
```

**Output schema:** `EventTime:datetime, AgentName:string, AgentId:string, SessionId:string, TargetWorkspace:string, KqlText:string, KqlLength:long, TouchesSensitive:bool, SensitiveTablesJson:string, EventId:string`.

**Test result:** Surfaces `query_lake` invocations parsed cleanly with `TouchesSensitive` evaluated against `SensitiveTablePattern`.

**Tuning:** Extend `SensitiveTablePattern` with any tables your environment treats as crown-jewel (e.g., HR systems via custom `*_CL` tables).

---

### Job 3 — Daily Agent Tool Inventory Snapshot

**Job name:** `A365_AgentTool_Inventory_Daily`  
**Destination:** `A365_AgentToolDaily_KQL_CL` (new table, Analytics tier)  
**Schedule:** Daily, run at 01:00 UTC  
**Purpose:** Promote per-(agent, tool, date) daily call counts so Detection 3 can do baseline-vs-recent first-seen analysis entirely in Analytics tier without re-scanning the lake daily.  

```kql
let lookback = 1d;
let delay    = 15m;
let endTime  = now() - delay;
let startTime = endTime - lookback - 1h;  // small overlap
UnifiedAgentObservability
| where TimeGenerated between (startTime .. endTime)
| where EventOriginalType == "ExecuteToolBySDK"
| extend
    Method     = tostring(parse_json(EventOriginalRequestDetails).method),
    ToolCalled = tostring(parse_json(EventOriginalRequestDetails).params.name)
| where Method == "tools/call"
| where isnotempty(SrcAgentId)
| summarize
    Calls       = count(),
    Sessions    = dcount(EventSessionId),
    FirstCall   = min(TimeGenerated),
    LastCall    = max(TimeGenerated)
    by SnapshotDate = bin(TimeGenerated, 1d), AgentId = SrcAgentId, AgentName = SrcAgentName,
       ToolName, ToolCalled, ToolOriginalType
| extend EventTime = SnapshotDate
| project EventTime, SnapshotDate, AgentId, AgentName, ToolName, ToolCalled, ToolOriginalType,
          Calls, Sessions, FirstCall, LastCall
```

**Output schema:** `EventTime:datetime, SnapshotDate:datetime, AgentId:string, AgentName:string, ToolName:string, ToolCalled:string, ToolOriginalType:string, Calls:long, Sessions:long, FirstCall:datetime, LastCall:datetime`.

**Test result:** Produces one row per (agent, tool, day) showing recurring tool usage — typically a few rows per day per active agent.

---

### Job 4 — Daily Agent Tool Failure Rollup

**Job name:** `A365_AgentTool_Failures_Daily`  
**Destination:** `A365_AgentToolFailuresDaily_KQL_CL` (new table, Analytics tier)  
**Schedule:** Daily, run at 01:15 UTC  
**Purpose:** Daily per-(agent, tool, error-category) failure counts — trend signal for probing behavior, broken MCP servers, or permission revocations.  

```kql
let lookback = 1d;
let delay    = 15m;
let endTime  = now() - delay;
let startTime = endTime - lookback - 1h;
UnifiedAgentObservability
| where TimeGenerated between (startTime .. endTime)
| where EventOriginalType == "ExecuteToolBySDK"
| extend
    Method     = tostring(parse_json(EventOriginalRequestDetails).method),
    ToolCalled = tostring(parse_json(EventOriginalRequestDetails).params.name),
    ResultText = tostring(EventOriginalResultDetails),
    HasError   = isnotempty(EventErrorDetails)
        or tostring(EventOriginalResultDetails) contains "\"error\""
        or tostring(EventOriginalResultDetails) contains "\"isError\":true"
| where Method == "tools/call"
| where HasError
| extend
    ErrorCategory = case(
        ResultText contains "\"errorCode\":\"InvalidField\"",        "InvalidField",
        ResultText contains "\"errorCategory\":\"Client\"",          "ClientError",
        ResultText contains "\"errorCategory\":\"Server\"",          "ServerError",
        ResultText contains "Forbidden" or ResultText contains "403", "Forbidden",
        ResultText contains "Unauthorized" or ResultText contains "401", "Unauthorized",
        ResultText contains "timeout" or ResultText contains "Timeout", "Timeout",
        "Other"),
    ErrorSnippet = substring(coalesce(EventErrorDetails, ResultText), 0, 500)
| summarize
    Failures    = count(),
    Sessions    = dcount(EventSessionId),
    FirstError  = min(TimeGenerated),
    LastError   = max(TimeGenerated),
    SampleError = any(ErrorSnippet)
    by SnapshotDate = bin(TimeGenerated, 1d), AgentId = SrcAgentId, AgentName = SrcAgentName,
       ToolName, ToolCalled, ErrorCategory
| extend EventTime = SnapshotDate
| project EventTime, SnapshotDate, AgentId, AgentName, ToolName, ToolCalled, ErrorCategory,
          Failures, Sessions, FirstError, LastError, SampleError
```

**Output schema:** `EventTime:datetime, SnapshotDate:datetime, AgentId:string, AgentName:string, ToolName:string, ToolCalled:string, ErrorCategory:string, Failures:long, Sessions:long, FirstError:datetime, LastError:datetime, SampleError:string`.

**Test result:** Produces one row per (agent, tool, error category, day) for failed tool calls — zero rows when no failures occurred in the window.

---

## Custom Detections (paired with the promoted `_KQL_CL` tables)

These rules run against the Analytics-tier tables produced by the KQL Jobs above. Custom `_CL` tables are fully CD-eligible (including NRT for short-lookback rules) — see the [detection-authoring skill](../../.github/skills/detection-authoring/SKILL.md).

> **Deployment ordering:** Create and run each KQL Job at least once before deploying its paired detection — the destination `_KQL_CL` table is created on the job's first execution.

### Detection 1 — AI Agent: Prompt Injection / Jailbreak Incident

**Pairs with:** Job 1 → `A365_JailbreakIncidents_KQL_CL`  
**Severity:** Medium (with dynamic override based on `Severity` column)  
**MITRE:** T1078.004, T1059  

<!-- cd-metadata
cd_ready: true
recommended_frequency: "1 hour"
recommended_period: "1 hour"
mitre_techniques: ["T1078.004", "T1059"]
mitre_tactics: ["InitialAccess", "Execution"]
impacted_entities:
  - entity_type: "User"
    column: "UserUpn"
  - entity_type: "CloudApplication"
    column: "AgentSpnId"
severity: "Medium"
title: "AI Agent — Prompt Injection / Jailbreak Incident"
description: "Azure Prompt Shield flagged a prompt-injection or jailbreak attempt against an Agent 365 / Copilot Studio agent, with downstream tool-call context. Source: A365_JailbreakIncidents_KQL_CL (populated hourly by KQL Job A365_JailbreakIncidents_Hourly, anchored on CloudAppEvents JailbreakDetected verdict)."
adaptation_notes: "NRT-eligible if 5-min lookback is preferred. Severity column is precomputed (Informational/Low/Medium/High) based on downstream tool-call count — filter `where Severity in ('Medium','High')` to suppress 'safety-layer-worked' rows, or alert on all rows for full audit coverage. PromptHash supports dedup of repeat attempts."
-->

```kql
A365_JailbreakIncidents_KQL_CL
| where TimeGenerated > ago(1h)
| where Severity in ("Medium", "High")   // drop to surface only acted-on incidents; remove for full audit
| project EventTime, UserUpn, AgentName, AgentSpnId, AppHost, ThreadId,
          SafetyVerdicts, FlaggedMessageCount,
          PromptPreview, PromptLength, PromptHash, PromptCount,
          ToolList, ToolCount, Severity, EventId
```

**Tuning:** 
- For lower-latency alerting, deploy as an NRT rule with `where TimeGenerated > ago(5m)` and a 5-min period.
- Remove the `Severity in ("Medium", "High")` filter to also alert on 🟡 Low ("safety layer blocked downstream") rows — useful as a weekly safety-KPI feed but noisy as a per-event alert.
- Use `PromptHash` for deduplication of repeated attempts from the same user.
- To alert only when **sensitive** tools were called, join to `A365_QueryLakeAudit_KQL_CL` on `ThreadId` and require `TouchesSensitive == true`.

---

### Detection 2 — AI Agent: KQL Access to Sensitive Tables

**Pairs with:** Job 2 → `A365_QueryLakeAudit_KQL_CL`  
**Severity:** Low (informational — may be expected for SOC agents; tighten as needed)  
**MITRE:** T1530, TA0009  

<!-- cd-metadata
cd_ready: true
recommended_frequency: "1 hour"
recommended_period: "1 hour"
mitre_techniques: ["T1530"]
mitre_tactics: ["Collection"]
impacted_entities:
  - entity_type: "CloudApplication"
    column: "AgentId"
severity: "Low"
title: "AI Agent — KQL Query Against Sensitive Tables"
description: "An AI agent executed an MCP query_lake call against one or more sensitive tables (identity, email, DLP, sign-in, or behavior analytics). Source: A365_QueryLakeAudit_KQL_CL (populated hourly by KQL Job A365_QueryLake_Audit_Hourly)."
adaptation_notes: "For SOC-purpose agents that legitimately query identity/sign-in data, scope by AgentId allow-list (where AgentId !in ('<sanctioned-agent-id>')) or remove tables from the SensitiveTablePattern in Job 2."
-->

```kql
A365_QueryLakeAudit_KQL_CL
| where TimeGenerated > ago(1h)
| where TouchesSensitive == true
| project EventTime, AgentName, AgentId, SessionId, TargetWorkspace, KqlText, KqlLength,
          SensitiveTablesJson, EventId
```

**Tuning:** Add `| where AgentId !in ("<sanctioned-agent-id-1>", "<sanctioned-agent-id-2>")` to suppress agents that legitimately need this access. For tighter control, raise severity to Medium and filter on specific sensitive tables only (e.g., `SensitiveTablesJson has "IdentityInfo"`).

---

### Detection 3 — AI Agent: New Tool First-Seen vs 30-Day Baseline

**Pairs with:** Job 3 → `A365_AgentToolDaily_KQL_CL`  
**Severity:** Medium  
**MITRE:** T1078.004  

<!-- cd-metadata
cd_ready: true
recommended_frequency: "1 day"
recommended_period: "1 day"
mitre_techniques: ["T1078.004"]
mitre_tactics: ["InitialAccess", "Persistence"]
impacted_entities:
  - entity_type: "CloudApplication"
    column: "AgentId"
severity: "Medium"
title: "AI Agent — New Tool Invocation First-Seen vs 30-Day Baseline"
description: "An AI agent invoked an MCP tool / connector that was not present in its prior 30-day baseline. Possible unauthorized tool addition, agent scope drift, or a benign deployment change. Source: A365_AgentToolDaily_KQL_CL (populated daily by KQL Job A365_AgentTool_Inventory_Daily)."
adaptation_notes: "After legitimate agent changes, expect a transient spike. Suppress benign new-tool events by maintaining an allow-list join, or temporarily lower severity to Low after announced deployments."
-->

```kql
let Baseline = A365_AgentToolDaily_KQL_CL
    | where SnapshotDate between (ago(31d) .. ago(1d))
    | distinct AgentId, ToolCalled;
A365_AgentToolDaily_KQL_CL
| where TimeGenerated > ago(1d)
| where SnapshotDate > ago(1d)
| join kind=leftanti Baseline on AgentId, ToolCalled
| project EventTime = SnapshotDate, AgentId, AgentName, ToolName, ToolCalled, ToolOriginalType,
          Calls, Sessions, FirstCall, LastCall
```

**Tuning:** Increase the baseline window (`31d` → `60d`) for more stable agents. To suppress one-off invocations, add `| where Calls >= 2`.

---

## Notes & Caveats

- **Preview schema** — `UnifiedAgentObservability` is part of the Agent 365 / A365 Observability connector preview. Columns may be added, renamed, or populated differently as the feature evolves. Re-validate field availability before promoting any query to production.
- **Lab-light environments** — In environments with a single agent and low traffic, several columns (`ModelName`, token counts, `EventThoughtProcessDetails`) may always be empty. These queries are designed to degrade gracefully (using `coalesce` / null-safe checks).
- **Pair with `AIAgentsInfo`** — For agent configuration posture (auth mode, registered tools, knowledge sources), join logically to the AH-only `AIAgentsInfo` table by `SrcAgentId == AIAgentId`. Cross-platform joins are not directly supported — run queries side-by-side and correlate in analysis.
- **PII in prompts** — `EventOriginalRequestDetails` contains raw user input, which may include sensitive data. Handle query exports with appropriate care and consider applying row-level security if exposing this table to non-SOC users.
