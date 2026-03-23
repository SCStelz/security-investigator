# Security Copilot Utilization Tracking

**Created:** 2026-03-19  
**Platform:** Microsoft Defender XDR (Advanced Hunting)  
**Tables:** CloudAppEvents  
**Keywords:** Security Copilot, SCU, security compute units, analyst usage, prompt tracking, session analysis, capacity planning, agent usage, plugin management, promptbook, CopilotInteraction  
**MITRE:** TA0043  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This query collection tracks Microsoft Security Copilot utilization via the `CloudAppEvents` table in Advanced Hunting. It provides analyst-level prompt counts, session patterns, autonomous agent activity, plugin management tracking, and capacity planning data.

### What CloudAppEvents Captures for Security Copilot

Security Copilot activity flows into CloudAppEvents with `AppIdentity = "Copilot.Security.SecurityCopilot"`. The key data fields are:

| Field | Location | Description |
|-------|----------|-------------|
| `ActionType` | Top-level | `CopilotInteraction` for prompts/responses; `EnablePlugin`, `DisablePlugin`, `CreatePlugin`, `DeletePlugin` for plugin mgmt; `CreatePromptBook`, `UpdatePromptBook`, `DeletePromptBook` for promptbooks; `CreateCopilotAgent`, `UpdateCopilotAgent`, `DeleteCopilotAgent` for agents; `UpdateTenantSettings` for admin config |
| `AppIdentity` | `RawEventData.AppIdentity` | Always `Copilot.Security.SecurityCopilot` for Security Copilot |
| `ApplicationName` | `RawEventData.ApplicationName` | `Security Copilot` |
| `ThreadId` | `RawEventData.CopilotEventData.ThreadId` | Unique per session/conversation |
| `AppHost` | `RawEventData.CopilotEventData.AppHost` | Identifies the Copilot experience (standalone portal, embedded, etc.) |
| `Messages` | `RawEventData.CopilotEventData.Messages` | Array with `isPrompt` boolean — `true` = user prompt, `false` = Copilot response |
| `Contexts` | `RawEventData.CopilotEventData.Contexts` | URL context (e.g., `securitycopilot.microsoft.com`, `security.microsoft.com`) |
| Agent identity | `AccountDisplayName` | Autonomous agents appear as `SecurityCopilotAgentUser-<agent-guid>` |
| Setting changes | `RawEventData.CopilotSettingsEventData.Resource` | JSON array with `Property`, `NewValue`, `OriginalValue` for plugin enable/disable |

### What CloudAppEvents Does NOT Capture

| Data | Where to Find It |
|------|-------------------|
| **SCU consumption per prompt** | Security Copilot Usage Monitoring Dashboard (Owner Settings → Usage monitoring) or exported Excel via the dashboard. Not available in any log table. |
| **Prompt/response text content** | Microsoft Purview DSPM for AI (requires opt-in). Not in CloudAppEvents. |
| **Plugin invoked per prompt** | Security Copilot Usage Dashboard (`Plugin used` column). Not reliably in CloudAppEvents. |
| **Provisioned vs overage SCU breakdown** | Azure Cost Management or Security Copilot Usage Dashboard. |
| **Session-level SCU totals** | Security Copilot Usage Dashboard (`Units used` column per session). |

> **SCU Estimation Guidance:** While per-prompt SCU data is not in CloudAppEvents, you can use prompt counts as a **proxy metric** for SCU consumption. Microsoft documentation shows typical prompts consume ~0.5–3+ SCUs each. Multiply prompt counts by an estimated average (e.g., 1.5 SCU/prompt) for rough capacity planning, then validate against the Usage Dashboard export.

### Distinguishing Human Analysts from Autonomous Agents

Security Copilot autonomous agents generate their own `CopilotInteraction` events with synthetic identities:
- **Agent accounts:** `AccountDisplayName` starts with `SecurityCopilotAgentUser-` followed by an agent GUID
- **Human accounts:** Normal user display names (e.g., `John Smith`)
- **Both produce prompt/response pairs** — agents can generate substantial volume

All queries below use `IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"` to separate these.

---

## Query 1: Security Copilot Activity Overview — All ActionTypes

**Purpose:** Get a complete picture of all Security Copilot operations in the environment — interactions, plugin management, promptbook lifecycle, agent management, and admin settings.

```kql
// Security Copilot — complete activity breakdown (last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| extend AppName = tostring(RawEventData.ApplicationName)
| where AppIdentity == "Copilot.Security.SecurityCopilot" or AppName == "Security Copilot"
| summarize
    Events = count(),
    UniqueUsers = dcount(AccountObjectId),
    FirstEvent = min(Timestamp),
    LastEvent = max(Timestamp)
    by ActionType
| order by Events desc
```

**Expected Results:**
- `ActionType`: Event type (CopilotInteraction, EnablePlugin, CreatePromptBook, etc.)
- `Events`: Total occurrences
- `UniqueUsers`: Distinct users performing this action
- `FirstEvent` / `LastEvent`: Time range of activity

**What to Look For:**
- ✅ `CopilotInteraction` should dominate — this is normal prompt/response activity
- ⚠️ High `EnablePlugin` / `DisablePlugin` volume may indicate users toggling plugins per session (normal but worth monitoring)
- ⚠️ `UpdateTenantSettings` changes — audit trail for admin configuration changes

---

## Query 2: Top Analysts by Prompt Volume

**Purpose:** Identify the most active Security Copilot users, their session counts, and average prompts per session to understand analyst adoption and usage depth.

```kql
// Security Copilot — top analysts by prompt volume (human users only, last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| where IsAgent == false
| extend ThreadId = tostring(RawEventData.CopilotEventData.ThreadId)
| extend Messages = RawEventData.CopilotEventData.Messages
| mv-expand msg = Messages
| extend IsPrompt = tobool(parse_json(tostring(msg)).isPrompt)
| summarize
    TotalInteractions = count(),
    Prompts = countif(IsPrompt == true),
    Responses = countif(IsPrompt == false),
    Sessions = dcount(ThreadId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountDisplayName, AccountObjectId
| extend AvgPromptsPerSession = round(todouble(Prompts) / todouble(Sessions), 1)
| project AccountDisplayName, Prompts, Sessions, AvgPromptsPerSession, Responses, FirstSeen, LastSeen
| order by Prompts desc
```

**Expected Results:**
- `AccountDisplayName`: Analyst name
- `Prompts`: Total prompts submitted
- `Sessions`: Unique ThreadIds (conversations)
- `AvgPromptsPerSession`: Average depth of engagement per session

**What to Look For:**
- ✅ Power users with high prompt counts and deep sessions (3+ avg) — these analysts derive most value
- ⚠️ Users with many sessions but only 1 prompt each — may indicate frustration or shallow adoption
- 🔵 Compare against SCU Dashboard export to correlate prompt volume with actual SCU spend

---

## Query 3: Human vs Agent Activity Split

**Purpose:** Separate human analyst usage from autonomous agent consumption. Critical for understanding true analyst adoption vs automated SCU burn.

```kql
// Security Copilot — human vs agent activity split (last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| extend Messages = RawEventData.CopilotEventData.Messages
| mv-expand msg = Messages
| extend IsPrompt = tobool(parse_json(tostring(msg)).isPrompt)
| summarize
    TotalEvents = count(),
    Prompts = countif(IsPrompt == true),
    Responses = countif(IsPrompt == false),
    UniqueUsers = dcount(AccountObjectId),
    UniqueSessions = dcount(tostring(RawEventData.CopilotEventData.ThreadId))
    by UserType = iff(IsAgent, "Autonomous Agent", "Human Analyst")
| extend EstimatedSCU_Low = Prompts * 0.5
| extend EstimatedSCU_High = Prompts * 3.0
| order by Prompts desc
```

**Expected Results:**
- `UserType`: "Human Analyst" or "Autonomous Agent"
- `Prompts` / `Responses`: Count of each
- `EstimatedSCU_Low` / `EstimatedSCU_High`: Rough SCU range (0.5–3.0 SCU/prompt)

**What to Look For:**
- 🔴 If agent prompts greatly exceed human prompts, agents may be burning SCUs disproportionately
- ✅ Balanced split suggests healthy human adoption alongside automation
- ⚠️ Cross-reference with SCU Dashboard — agents may use simpler prompts (lower SCU) than complex human queries

---

## Query 4: Autonomous Agent Inventory and Volume

**Purpose:** Enumerate all Security Copilot autonomous agents, their prompt volume, session counts, and activity windows.

```kql
// Security Copilot — autonomous agent breakdown (last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| where IsAgent == true
| extend AgentId = extract(@"SecurityCopilotAgentUser-(.+)", 1, AccountDisplayName)
| extend ThreadId = tostring(RawEventData.CopilotEventData.ThreadId)
| extend Messages = RawEventData.CopilotEventData.Messages
| mv-expand msg = Messages
| extend IsPrompt = tobool(parse_json(tostring(msg)).isPrompt)
| summarize
    TotalEvents = count(),
    Prompts = countif(IsPrompt == true),
    Sessions = dcount(ThreadId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    ActiveDays = dcount(bin(Timestamp, 1d))
    by AgentId
| extend AvgPromptsPerDay = round(todouble(Prompts) / todouble(ActiveDays), 0)
| extend EstDailySCU_Mid = round(AvgPromptsPerDay * 1.5, 0)
| order by Prompts desc
```

**Expected Results:**
- `AgentId`: Agent GUID (correlate with Security Copilot Agent Management)
- `Prompts`: Total prompts
- `Sessions`: Unique conversations
- `AvgPromptsPerDay`: Average daily prompt volume
- `EstDailySCU_Mid`: Estimated daily SCU at 1.5 SCU/prompt

**What to Look For:**
- 🔴 Agents with thousands of daily prompts — major SCU consumers, verify ROI
- ✅ Stale agents (`LastSeen` far in the past) — may have been decommissioned
- ⚠️ Agents with 1-day activity window may be test agents

---

## Query 5: Daily Usage Trend — Human vs Agent

**Purpose:** Track daily prompt volume split between human analysts and agents. Essential for understanding adoption trajectory and identifying usage spikes.

```kql
// Security Copilot — daily prompt trend, human vs agent (last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| extend Messages = RawEventData.CopilotEventData.Messages
| mv-expand msg = Messages
| extend IsPrompt = tobool(parse_json(tostring(msg)).isPrompt)
| where IsPrompt == true
| summarize
    HumanPrompts = countif(IsAgent == false),
    AgentPrompts = countif(IsAgent == true),
    TotalPrompts = count(),
    UniqueHumanUsers = dcountif(AccountObjectId, IsAgent == false),
    UniqueSessions = dcount(tostring(RawEventData.CopilotEventData.ThreadId))
    by Day = bin(Timestamp, 1d)
| extend HumanPct = round(100.0 * HumanPrompts / TotalPrompts, 1)
| order by Day asc
```

**Expected Results:**
- `Day`: Date
- `HumanPrompts` / `AgentPrompts`: Split by source
- `UniqueHumanUsers`: Daily active analysts
- `HumanPct`: Percentage of human-driven prompts

**What to Look For:**
- ✅ Upward trend in `UniqueHumanUsers` — growing analyst adoption
- 🔴 Days where `AgentPrompts` >> `HumanPrompts` — agents dominating SCU spend
- ⚠️ Weekend/holiday usage patterns — agents run 24/7, humans don't

---

## Query 6: Hourly Capacity Planning — Peak Usage Windows

**Purpose:** Identify peak usage hours for SCU capacity planning. Shows when to expect maximum concurrent demand.

```kql
// Security Copilot — hourly prompt statistics for capacity planning (last 14 days)
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| where IsAgent == false
| extend Messages = RawEventData.CopilotEventData.Messages
| mv-expand msg = Messages
| extend IsPrompt = tobool(parse_json(tostring(msg)).isPrompt)
| where IsPrompt == true
| summarize HourlyPrompts = count() by Hour = bin(Timestamp, 1h)
| summarize
    AvgPromptsPerHour = round(avg(HourlyPrompts), 1),
    MedianPromptsPerHour = percentile(HourlyPrompts, 50),
    P95PromptsPerHour = percentile(HourlyPrompts, 95),
    MaxPromptsPerHour = max(HourlyPrompts),
    TotalHours = count()
| project AvgPromptsPerHour, MedianPromptsPerHour, P95PromptsPerHour, MaxPromptsPerHour, TotalHours
```

**Expected Results:**
- Median / P95 / Max prompts per hour
- Use P95 × estimated SCU/prompt to right-size provisioned SCUs

**SCU Capacity Planning Formula:**
```
Provisioned SCUs needed ≈ P95_Prompts_Per_Hour × Avg_SCU_Per_Prompt
Example: 490 × 1.5 SCU = 735 SCUs provisioned capacity at P95
```

---

## Query 7: Hour-of-Day × Day-of-Week Usage Heatmap

**Purpose:** Visualize analyst usage patterns by hour and weekday. Reveals shift patterns ands helps right-size SCU allocation.

```kql
// Security Copilot — hour/day usage pattern (human analysts, last 14 days)
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| where IsAgent == false
| extend Messages = RawEventData.CopilotEventData.Messages
| mv-expand msg = Messages
| extend IsPrompt = tobool(parse_json(tostring(msg)).isPrompt)
| where IsPrompt == true
| extend HourUTC = hourofday(Timestamp)
| extend DayOfWeek = dayofweek(Timestamp) / 1d
| extend DayName = case(
    DayOfWeek == 0, "Sun",
    DayOfWeek == 1, "Mon",
    DayOfWeek == 2, "Tue",
    DayOfWeek == 3, "Wed",
    DayOfWeek == 4, "Thu",
    DayOfWeek == 5, "Fri",
    DayOfWeek == 6, "Sat",
    "Unk")
| summarize Prompts = count() by DayName, DayOfWeek, HourUTC
| order by DayOfWeek asc, HourUTC asc
| project DayName, HourUTC, Prompts
```

**Expected Results:**
- Row per DayName + HourUTC combination with prompt count
- Can be fed into `show-signin-heatmap` MCP tool for visualization

**What to Look For:**
- ✅ Clear business-hours peak — normal SOC pattern
- ⚠️ Heavy off-hours usage — may indicate agents or analysts in different time zones
- 🔵 Zero-usage windows — opportunities to reduce provisioned SCU during these hours

---

## Query 8: Session Depth Distribution

**Purpose:** Understand how deeply analysts interact per session (conversation). Deeper sessions consume more SCUs and indicate complex investigations.

```kql
// Security Copilot — session depth distribution (human analysts, last 14 days)
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| where IsAgent == false
| extend ThreadId = tostring(RawEventData.CopilotEventData.ThreadId)
| extend Messages = RawEventData.CopilotEventData.Messages
| mv-expand msg = Messages
| extend IsPrompt = tobool(parse_json(tostring(msg)).isPrompt)
| where IsPrompt == true
| summarize PromptsInSession = count() by ThreadId
| summarize
    TotalSessions = count(),
    AvgDepth = round(avg(PromptsInSession), 1),
    MedianDepth = percentile(PromptsInSession, 50),
    P90Depth = percentile(PromptsInSession, 90),
    MaxDepth = max(PromptsInSession),
    SinglePromptSessions = countif(PromptsInSession == 1),
    DeepSessions_5plus = countif(PromptsInSession >= 5),
    DeepSessions_10plus = countif(PromptsInSession >= 10)
| extend SinglePromptPct = round(100.0 * SinglePromptSessions / TotalSessions, 1)
| extend Deep5Pct = round(100.0 * DeepSessions_5plus / TotalSessions, 1)
| extend Deep10Pct = round(100.0 * DeepSessions_10plus / TotalSessions, 1)
```

**Expected Results:**
- Session depth percentiles (median, P90, max)
- Percentage of single-prompt vs deep (5+, 10+) sessions

**What to Look For:**
- ✅ Median of 2–3 prompts is typical for investigation workflows
- 🔴 High `SinglePromptPct` — analysts may be testing but not adopting for real work
- ✅ Sessions with 10+ prompts — complex investigations where Copilot provides most value

---

## Query 9: Copilot Experience Type Breakdown (Standalone vs Embedded)

**Purpose:** Determine where analysts access Security Copilot — standalone portal, embedded in Defender XDR, Entra, Intune, or Purview.

```kql
// Security Copilot — experience type breakdown (last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| extend Contexts = tostring(RawEventData.CopilotEventData.Contexts)
| extend ContextUrl = extract(@"""Id"":""([^""]+)""", 1, Contexts)
| extend ExperienceType = case(
    IsAgent, "Autonomous Agent",
    ContextUrl has "securitycopilot.microsoft.com", "Standalone Portal",
    ContextUrl has "security.microsoft.com", "Embedded - Defender XDR",
    ContextUrl has "intune", "Embedded - Intune",
    ContextUrl has "entra", "Embedded - Entra",
    ContextUrl has "purview", "Embedded - Purview",
    isnotempty(ContextUrl), strcat("Other - ", ContextUrl),
    "Unknown")
| summarize
    Events = count(),
    UniqueUsers = dcount(AccountObjectId),
    Sessions = dcount(tostring(RawEventData.CopilotEventData.ThreadId))
    by ExperienceType
| extend PctOfTotal = round(100.0 * Events / toscalar(
    CloudAppEvents
    | where Timestamp > ago(30d)
    | where ActionType == "CopilotInteraction"
    | extend AppIdentity = tostring(RawEventData.AppIdentity)
    | where AppIdentity == "Copilot.Security.SecurityCopilot"
    | count
    ), 1)
| order by Events desc
```

**Expected Results:**
- `ExperienceType`: Standalone Portal, Embedded, Agent, etc.
- `Events` / `UniqueUsers` / `Sessions`: Usage per experience

**What to Look For:**
- ✅ Embedded usage in Defender XDR — analysts using Copilot in their natural workflow
- ⚠️ 100% standalone usage — opportunity to promote embedded experiences for faster triage
- 🔵 Agent volume as % of total — understand automation's share of capacity

---

## Query 10: Plugin and Setting Change Audit Trail

**Purpose:** Track Security Copilot configuration changes — plugin enables/disables, tenant setting modifications. Important for governance and change management.

```kql
// Security Copilot — plugin and setting change audit trail (last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("EnablePlugin", "DisablePlugin", "UpdateTenantSettings")
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend Resources = RawEventData.CopilotSettingsEventData.Resource
| mv-expand res = Resources
| extend SettingJson = parse_json(tostring(res))
| extend Property = tostring(SettingJson.Property)
| extend NewValue = tostring(SettingJson.NewValue)
| extend OldValue = tostring(SettingJson.OriginalValue)
| project Timestamp, ActionType, AccountDisplayName, IPAddress, CountryCode, Property, OldValue, NewValue
| order by Timestamp desc
```

**Expected Results:**
- Chronological audit trail of every plugin enable/disable and setting change
- Includes who made the change, from where (IP/country), and what changed

**What to Look For:**
- 🔴 `UpdateTenantSettings` — admin-level configuration changes, verify authorized
- ⚠️ Plugins being disabled/enabled in bulk — may indicate user confusion or policy compliance
- 🔵 Track which plugins are most commonly enabled (Entra, Defender XDR, Threat Intelligence, etc.)

---

## Query 11: Promptbook and Agent Lifecycle Activity

**Purpose:** Track creation, modification, and deletion of Security Copilot promptbooks and agents for governance.

```kql
// Security Copilot — promptbook and agent lifecycle (last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in (
    "CreatePromptBook", "UpdatePromptBook", "DeletePromptBook",
    "CreateCopilotAgent", "UpdateCopilotAgent", "DeleteCopilotAgent",
    "CreateCopilotforSecurityAgentTrigger", "UpdateCopilotforSecurityAgentTrigger",
    "DeleteCopilotforSecurityAgentTrigger")
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| project Timestamp, ActionType, AccountDisplayName, IPAddress, CountryCode,
    City, ObjectName, ObjectType
| order by Timestamp desc
```

**Expected Results:**
- Chronological record of promptbook/agent create/update/delete events
- Shows who created what and when

**What to Look For:**
- ✅ Healthy promptbook creation indicates team building reusable workflows
- ⚠️ Frequent agent trigger changes may indicate instability or misconfiguration
- 🔴 Unauthorized agent creation — verify against approved Security Copilot agent list

---

## Query 12: Weekly Adoption Dashboard — Executive Summary

**Purpose:** High-level weekly adoption metrics suitable for executive reporting. Shows week-over-week growth in users, sessions, and prompt volume.

```kql
// Security Copilot — weekly adoption summary (last 30 days)
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend AppIdentity = tostring(RawEventData.AppIdentity)
| where AppIdentity == "Copilot.Security.SecurityCopilot"
| extend IsAgent = AccountDisplayName startswith "SecurityCopilotAgentUser"
| where IsAgent == false
| extend ThreadId = tostring(RawEventData.CopilotEventData.ThreadId)
| extend Messages = RawEventData.CopilotEventData.Messages
| mv-expand msg = Messages
| extend IsPrompt = tobool(parse_json(tostring(msg)).isPrompt)
| where IsPrompt == true
| summarize
    ActiveAnalysts = dcount(AccountObjectId),
    TotalPrompts = count(),
    TotalSessions = dcount(ThreadId)
    by Week = startofweek(Timestamp)
| extend AvgPromptsPerAnalyst = round(todouble(TotalPrompts) / todouble(ActiveAnalysts), 1)
| extend AvgSessionsPerAnalyst = round(todouble(TotalSessions) / todouble(ActiveAnalysts), 1)
| order by Week asc
```

**Expected Results:**
- Weekly active analysts, total prompts, sessions
- Per-analyst averages for intensity tracking

**What to Look For:**
- ✅ Week-over-week growth in `ActiveAnalysts` — adoption spreading
- ✅ Rising `AvgPromptsPerAnalyst` — deepening engagement
- ⚠️ Plateau or decline — may need training or champion identification

---

## SCU Estimation Reference

Since CloudAppEvents does not include per-prompt SCU consumption, use these reference benchmarks from Microsoft documentation for rough estimation:

| Scenario | Typical SCU per prompt | Source |
|----------|----------------------|--------|
| Single standalone prompt | ~1.0–3.0 SCU | Microsoft SCU documentation |
| Embedded experience (e.g., incident summary) | ~0.5 SCU | Microsoft SCU billing example |
| Promptbook (multi-prompt) | ~3.7 SCU per promptbook run | Microsoft SCU billing example |
| Agent autonomous prompt | ~0.5–2.0 SCU (varies) | Estimated from dashboard observations |

**To get actual SCU data:**
1. **Security Copilot Portal** → Owner Settings → Usage Monitoring
2. **Export to Excel** for per-session SCU data (SessionId, Date, Units Used, Initiated By, Category, Type, Plugin Used)
3. Consider joining the exported CSV with CloudAppEvents ThreadId for enriched analysis

**References:**
- [Manage SCU Usage](https://learn.microsoft.com/copilot/security/manage-usage)
- [Security Compute Units and Capacity](https://learn.microsoft.com/copilot/security/security-compute-units-capacity)
- [Security Copilot Audit Log](https://learn.microsoft.com/copilot/security/audit-log)
- [Purview Audit Log Activities — Security Copilot](https://learn.microsoft.com/purview/audit-log-activities#microsoft-security-copilot-platform-management)
