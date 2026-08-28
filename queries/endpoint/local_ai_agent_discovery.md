# Local AI Agent Discovery — Hunting & Posture Queries

**Created:** 2026-08-27  
**Platform:** Microsoft Defender XDR  
**Tables:** AgentsInfo, ExposureGraphNodes, ExposureGraphEdges  
**Keywords:** local AI agent, MCP server, model context protocol, shadow AI, ChatGPT desktop, GitHub Copilot, Claude Code, Cline, Codex, Gemini Code Assist, auto-approve, trusted process, agent inventory, LocalAgents, localAgentMetadata, agent risk, critical device, blast radius, OpenClaw  
**MITRE:** T1059, T1204, T1072, T1082, TA0002, TA0007  
**Domains:** endpoint, exposure  
**Timeframe:** Current inventory snapshot (AgentsInfo is a point-in-time profile table)

---

## Overview

This collection inventories and assesses **local AI agents** and their **MCP (Model Context Protocol) servers** discovered on onboarded Windows and macOS endpoints by Microsoft Defender for Endpoint. Local AI agents are AI assistants and coding tools that run *on the device* — ChatGPT Desktop, GitHub Copilot (App/CLI/VSCode), Claude Code, Cline, Roo Code, Codex, Gemini Code Assist, and similar — as opposed to cloud-hosted agents (Copilot Studio, Agent Builder, Microsoft Foundry).

Discovery is automatic once a device is onboarded to MDE Plan 2 with Defender Antivirus in active mode + real-time protection. No extra deployment is required.

**Reference:** [Discover local AI agents with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)

### Why this matters (security lens)

- **Shadow AI** — Unauthorized AI runtimes (e.g., self-hosted agents like OpenClaw) establish persistence, reach external endpoints, and can execute arbitrary commands. Inventory surfaces what is actually installed vs. what is approved.
- **Auto-approving agents** — An agent that acts *without prompting the user* runs tools and reaches resources unsupervised. Its blast radius equals the account + device it runs on.
- **Untrusted host process** — An agent hosted in a process that Defender does not trust is a stronger signal of an unsanctioned or tampered runtime.
- **Critical exposure** — A local agent on a business-critical device, or used by a highly-privileged identity, concentrates risk. The exposure graph links agents → devices → identities → reachable assets.

### Licensing note

| Capability | Minimum license |
| --- | --- |
| Discover local agents, view inventory, query `AgentsInfo` in Advanced Hunting | Defender for Endpoint **Plan 2** |
| Risk level, risk indicators, security recommendations | Microsoft **365 E7** or **Agent 365** + MDE P2 |

> Without E7 / Agent 365, the inventory and configuration detail in these queries still work; only the pre-computed risk *scoring* fields are absent. The risky-configuration and critical-device q*ueries below derive risk from raw config + exposure graph, so they work on MDE P2 alone.*

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
| --- | --- | --- | --- |
| 1 | [Local AI Agent Inventory](#query-1-local-ai-agent-inventory) | Posture | `AgentsInfo` + `RawAgentInfo` |
| 2 | [Vendor & Platform Footprint](#query-2-vendor--platform-footprint) | Investigation | `AgentsInfo` + `RawAgentInfo` |
| 3 | [Local Agent Configuration Detail](#query-3-local-agent-configuration-detail) | Investigation | `AgentsInfo` + `RawAgentInfo` |
| 4 | [MCP Servers & Tools Configured for Local Agents](#query-4-mcp-servers--tools-configured-for-local-agents) | Investigation | `AgentsInfo` + `RawAgentInfo` |
| 5 | [Risky Local Agent Configurations](#query-5-risky-local-agent-configurations) | Investigation | `AgentsInfo` + `RawAgentInfo` |
| 6 | [Recently Removed / Uninstalled Local Agents](#query-6-recently-removed--uninstalled-local-agents) | Investigation | `AgentsInfo` + `RawAgentInfo` |
| 7 | [Local Agents Mapped to Devices & Identities (Exposure Graph)](#query-7-local-agents-mapped-to-devices--identities-exposure-graph) | Investigation | `ExposureGraphEdges` + `ExposureGraphNodes` |
| 8 | [Risky Local Agents on Critical Devices](#query-8-risky-local-agents-on-critical-devices) | Investigation | `AgentsInfo` + multi |
| 9 | [Rank Users Whose Local Agents Reach Critical or Sensitive Assets](#query-9-rank-users-whose-local-agents-reach-critical-or-sensitive-assets) | Investigation | `ExposureGraphEdges` + `ExposureGraphNodes` |


## Data model

### `AgentsInfo` — what an agent *is*

Filter local agents with `Platform == "LocalAgents"`. The table adds a new record every time a profile updates, so **deduplicate with `arg_max(Timestamp, *) by AgentId`**. `LifecycleStatus` reports whether the agent is still present — filter out `Deleted` / `Uninstalled` for a current inventory (active agents may report an **empty** `LifecycleStatus`).

Most `AgentsInfo` columns describe cloud agents and are empty for local agents. The columns that carry local-agent data are `AgentId`, `Name`, `Version`, `PublishedStatus`, `LifecycleStatus`, `LastUpdatedDateTime`, `McpServers`, `DeclaredTools`, and `RawAgentInfo`.

**The rich local-agent posture is nested in `RawAgentInfo.localAgentMetadata`:**

| Property | Description |
| --- | --- |
| `vendor` | Publisher (OpenAI, Anthropic, Google, GitHub, …) |
| `relatedProcess` | Host process (`code.exe`, `ChatGPT.exe`, `copilot.exe`, …) |
| `trustedProcess` | Whether the host process is trusted — **string** `"true"`/`"false"` |
| `autoApprove` | Whether the agent acts without user approval — **string** `"true"`/`"false"` |
| `deviceName`, `aadDeviceId` | Device where the agent was discovered |
| `accountName`, `accountDomain`, `accountSid` | Account the agent runs under |
| `osPlatform`, `osVersion`, `deviceType` | Device context |
| `localMcps` | Local MCP servers, including the command that starts each |

> ⚠️ **`trustedProcess` and `autoApprove` are strings, not booleans.** Compare to `"true"`/`"false"` — do **not** use `tobool()`.
>
> ⚠️ **MCP/tool columns are frequently empty for local agents.** In many tenants `McpServers`, `DeclaredTools`, and `localMcps` are unpopulated even when the agent supports MCP. A zero result from the MCP query (Query 4) is a **telemetry-coverage note**, not proof that no MCP servers are configured.

### `ExposureGraphNodes` / `ExposureGraphEdges` — what an agent can *reach*

AI agents appear as nodes with `NodeLabel == "ai-agent"`. Filter local ones on the node property:

```kusto
ExposureGraphNodes
| where NodeLabel == "ai-agent"
| where tostring(NodeProperties.rawData.aiAgentMetadata.platform) == "LocalAgents"
```

> ⚠️ **`ExposureGraphEdges` has no property that identifies local agents.** Filtering only on `SourceNodeLabel == "ai-agent"` returns edges for *every* AI agent (including cloud). **Always resolve the local set from `ExposureGraphNodes` first, then join to edges on the node ID.**

**Joining the two data sources** — an agent has two identifiers:

| From | To | Match on |
| --- | --- | --- |
| `AgentsInfo` | `ExposureGraphNodes` | `tostring(AgentId)` ↔ `tostring(NodeProperties.rawData.aiAgentMetadata.id)` |
| `ExposureGraphNodes` | `ExposureGraphEdges` | `NodeId` ↔ `SourceNodeId` / `TargetNodeId` |

> `AgentId` is a `guid` in `AgentsInfo` but a **string** in the graph. Cast both sides with `tostring()` — a cross-type join matches nothing.

**Local-agent edges:**

| Edge label | Target | Meaning |
| --- | --- | --- |
| `runs on` | `device`, `ec2.instance`, `microsoft.compute/virtualmachines` | The device the agent runs on |
| `uses` | `mcp/server` | An MCP server configured for the agent |
| `used by` | `user` | The identity that uses the agent |

Asset criticality lives in `ExposureGraphNodes` at `NodeProperties.rawData.criticalityLevel.criticalityLevel` where **`0` = Very high** and **`3` = Low**; `ruleNames` lists the classification rules that made the asset critical.

---

## Query 1: Local AI Agent Inventory

Lists every discovered local AI agent with publisher, host process, versions, and how widely each is deployed. Primary discovery query — start here.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Inventory/posture query — aggregates across the fleet with dcount/make_set, so it is not row-level. Not suitable as a scheduled custom detection. Use interactively for AI agent asset inventory."
-->

```kql
AgentsInfo
| where Platform == "LocalAgents"
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in~ ("Deleted", "Uninstalled")
| extend M = RawAgentInfo.localAgentMetadata
| extend Vendor  = tostring(M.vendor),
         Process = tostring(M.relatedProcess),
         Device  = tostring(M.deviceName),
         Account = tostring(M.accountName)
| summarize Installations = count(),
            DeviceCount   = dcount(Device),
            Devices       = make_set(Device, 100),
            Versions      = make_set(Version, 20),
            Accounts      = make_set_if(Account, isnotempty(Account), 50)
    by Agent = Name, Vendor, Process
| sort by DeviceCount desc, Installations desc
```

Each `AgentId` is one agent, on one device, for one account — so an agent two people use on the same device counts twice under `Installations` but once under `DeviceCount`.

---

## Query 2: Vendor & Platform Footprint

Rolls the inventory up by publisher so you can see which AI vendors have a local footprint and how concentrated usage is.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture summary with dcount aggregation — interactive reporting only, not a row-level detection."
-->

```kql
AgentsInfo
| where Platform == "LocalAgents"
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in~ ("Deleted", "Uninstalled")
| extend M = RawAgentInfo.localAgentMetadata
| extend Vendor = tostring(M.vendor), Device = tostring(M.deviceName), Account = tostring(M.accountName)
| summarize Agents        = dcount(AgentId),
            DistinctNames  = dcount(Name),
            AgentNames     = make_set(Name, 30),
            Devices        = dcount(Device),
            Users          = dcountif(Account, isnotempty(Account))
    by Vendor
| sort by Agents desc
```

---

## Query 3: Local Agent Configuration Detail

Row-per-agent view of the fields that matter for triage: host process, trust, auto-approve, device, account, and OS. Use this to eyeball anything unexpected.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Row-level per agent, but keyed on AgentId (not a standard DeviceId/DeviceName column) — the device/account identifiers live inside RawAgentInfo.localAgentMetadata. Custom detection impactedAssets mapping would require projecting DeviceName/AccountName from the parsed metadata. Provided here for interactive triage."
-->

```kql
AgentsInfo
| where Platform == "LocalAgents"
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in~ ("Deleted", "Uninstalled")
| extend M = RawAgentInfo.localAgentMetadata
| project Agent      = Name,
          Vendor     = tostring(M.vendor),
          Version,
          Process    = tostring(M.relatedProcess),
          TrustedProcess = tostring(M.trustedProcess),
          AutoApprove    = tostring(M.autoApprove),
          Device     = tostring(M.deviceName),
          Account    = tostring(M.accountName),
          Domain     = tostring(M.accountDomain),
          OS         = tostring(M.osPlatform),
          DeviceType = tostring(M.deviceType),
          LastSeen   = Timestamp
| sort by Device asc, Agent asc
```

---

## Query 4: MCP Servers & Tools Configured for Local Agents

Enumerates the remote MCP servers, declared tools, and local MCP servers configured for local agents, unified into one view. `Origin` distinguishes: a **remote MCP server** (network endpoint in `Location`), a **local MCP server** (start command in `Location`, reported only in `AgentsInfo`), and a **declared tool** (advertised capability, may lack an endpoint).

> ⚠️ **Telemetry-coverage caveat:** `McpServers`, `DeclaredTools`, and `localMcps` are often empty for local agents. If this returns 0 rows, it means no MCP/tool config was reported — **not** necessarily that none exists. Note the gap rather than asserting absence.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-step let/union with mv-expand and summarize — inventory query, not a row-level detection. MCP columns are sparsely populated in many tenants."
-->

```kql
let localAgentProfiles =
    AgentsInfo
    | where Platform == "LocalAgents"
    | extend M = RawAgentInfo.localAgentMetadata
    | project Timestamp,
              Agent   = Name,
              Device  = tostring(M.deviceName),
              Account = tostring(M.accountName),
              McpServers,
              DeclaredTools,
              LocalServers = M.localMcps;
let remoteMcpServers =
    localAgentProfiles
    | mv-expand Server = McpServers
    | project Timestamp, Agent, Device, Account,
              McpServer = tostring(Server.name),
              Origin    = "Remote MCP server",
              Transport = tostring(Server.type),
              Location  = tostring(Server.endpoint);
let agentDeclaredTools =
    localAgentProfiles
    | mv-expand Tool = DeclaredTools
    | project Timestamp, Agent, Device, Account,
              McpServer = tostring(Tool.name),
              Origin    = "Declared tool",
              Transport = tostring(Tool.type),
              Location  = tostring(Tool.endpoint);
let localMcpServers =
    localAgentProfiles
    | mv-expand Server = LocalServers
    | project Timestamp, Agent, Device, Account,
              McpServer = tostring(Server.name),
              Origin    = "Local MCP server",
              Transport = tostring(Server.transportType),
              Location  = tostring(Server.commandName);
remoteMcpServers
| union agentDeclaredTools, localMcpServers
| where isnotempty(McpServer)
| summarize LastSeen = max(Timestamp),
            Agents   = make_set(Agent, 20),
            Devices  = make_set(Device, 20),
            Accounts = make_set_if(Account, isnotempty(Account), 20)
    by McpServer, Origin, Transport, Location
| sort by McpServer asc, Origin asc
```

---

## Query 5: Risky Local Agent Configurations

Returns local agents that **act without approval** (`autoApprove == "true"`) or run in an **untrusted host process** (`trustedProcess == "false"`). These are the highest-signal configuration risks. A clean run (0 rows) is a valid, reportable result — state it explicitly.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Detection-worthy logic, but AgentsInfo lacks standard DeviceId/DeviceName/ReportId columns and the device/account identifiers are nested in RawAgentInfo. To convert to a custom detection, project DeviceName/AccountName from RawAgentInfo.localAgentMetadata and map them as impactedAssets. AgentsInfo is a snapshot/profile table, so validate detection cadence against its update frequency before deploying."
-->

```kql
AgentsInfo
| where Platform == "LocalAgents"
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in~ ("Deleted", "Uninstalled")
| extend M = RawAgentInfo.localAgentMetadata
| extend AutoApprove    = tostring(M.autoApprove),
         TrustedProcess = tostring(M.trustedProcess),
         Vendor  = tostring(M.vendor),
         Process = tostring(M.relatedProcess),
         Device  = tostring(M.deviceName),
         Account = tostring(M.accountName)
| where AutoApprove =~ "true" or TrustedProcess =~ "false"
| extend RiskReason = case(
    AutoApprove =~ "true" and TrustedProcess =~ "false",
        "Acts without approval, and the host process isn't trusted",
    AutoApprove =~ "true",
        "Acts without approval",
    "The host process isn't trusted")
| project Agent = Name, Vendor, Version, Process, Device, Account,
          AutoApprove, TrustedProcess, RiskReason, LastSeen = Timestamp
| sort by Device asc, Agent asc
```

---

## Query 6: Recently Removed / Uninstalled Local Agents

Surfaces local agents whose latest profile is `Deleted` or `Uninstalled`. Useful for two reasons: (1) an agent reinstalled with a new `AgentId` leaves the old record `Deleted`, and (2) a **removed shadow-AI runtime** (e.g., a self-hosted agent) is worth confirming was intentional and checking for residual persistence. Pair with the `openclaw_shadow_ai_hunting` query file when a self-hosted agent appears here.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Row-level per removed agent, but keyed on AgentId with device/account nested in RawAgentInfo (no standard DeviceName column). For a custom detection, project DeviceName/AccountName from localAgentMetadata and map as impactedAssets, and confirm the removal event cadence matches AgentsInfo update frequency."
-->

```kql
AgentsInfo
| where Platform == "LocalAgents"
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus in~ ("Deleted", "Uninstalled")
| extend M = RawAgentInfo.localAgentMetadata
| project Agent   = Name,
          Vendor  = tostring(M.vendor),
          Version,
          Device  = tostring(M.deviceName),
          Account = tostring(M.accountName),
          LifecycleStatus,
          LastSeen = Timestamp
| sort by LastSeen desc
```

---

## Query 7: Local Agents Mapped to Devices & Identities (Exposure Graph)

Uses the exposure graph to link each local agent to the device it `runs on` and the identity that `used by` it — resolving friendly device and user display names. This is the "who runs what, where" map.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Exposure-graph join across ExposureGraphNodes/Edges producing a relationship map — inventory/posture, not a row-level detection."
-->

```kql
let localAgents =
    ExposureGraphNodes
    | where NodeLabel == "ai-agent"
    | where tostring(NodeProperties.rawData.aiAgentMetadata.platform) == "LocalAgents"
    | project AgentNodeId = NodeId, AIAgent = NodeName;
let runsOn =
    ExposureGraphEdges
    | where SourceNodeLabel == "ai-agent" and EdgeLabel =~ "runs on"
    | project AgentNodeId = SourceNodeId, DeviceId = TargetNodeId,
              Device = TargetNodeName, DeviceType = TargetNodeLabel;
let usedBy =
    ExposureGraphEdges
    | where SourceNodeLabel == "ai-agent" and EdgeLabel =~ "used by"
    | project AgentNodeId = SourceNodeId, User = TargetNodeName;
localAgents
| join kind=leftouter runsOn on AgentNodeId
| join kind=leftouter usedBy on AgentNodeId
| project AIAgent, Device, DeviceType, User
| sort by Device asc, AIAgent asc
```

---

## Query 8: Risky Local Agents on Critical Devices

Combines the risky-configuration set from `AgentsInfo` with asset criticality from the exposure graph, so you can start with the agents that both act unsupervised and run on business-critical devices. To review **every** local agent on a critical device (not only the risky ones), remove the `where AutoApprove =~ "true" or TrustedProcess =~ "false"` line in the first `let`.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-source join (AgentsInfo + exposure graph) with criticality classification — posture prioritization query, not a row-level detection."
-->

```kql
let deviceLabels = dynamic(["device", "ec2.instance", "microsoft.compute/virtualmachines"]);
let riskyAgentProfiles =
    AgentsInfo
    | where Platform == "LocalAgents"
    | summarize arg_max(Timestamp, *) by AgentId
    | where LifecycleStatus !in~ ("Deleted", "Uninstalled")
    | extend M = RawAgentInfo.localAgentMetadata
    | extend AutoApprove = tostring(M.autoApprove), TrustedProcess = tostring(M.trustedProcess)
    | where AutoApprove =~ "true" or TrustedProcess =~ "false"
    | project AgentId = tostring(AgentId),
              Agent   = Name,
              Version,
              Vendor  = tostring(M.vendor),
              Account = tostring(M.accountName),
              AutoApprove,
              TrustedProcess;
let localAgentNodes =
    ExposureGraphNodes
    | where NodeLabel == "ai-agent"
    | where tostring(NodeProperties.rawData.aiAgentMetadata.platform) == "LocalAgents"
    | project AgentNodeId = NodeId,
              AgentId = tostring(NodeProperties.rawData.aiAgentMetadata.id);
let agentDeviceEdges =
    ExposureGraphEdges
    | where SourceNodeLabel == "ai-agent"
    | where EdgeLabel =~ "runs on"
    | where TargetNodeLabel in (deviceLabels)
    | project AgentNodeId = SourceNodeId, DeviceId = TargetNodeId,
              Device = TargetNodeName, DeviceType = TargetNodeLabel;
let criticalDevices =
    ExposureGraphNodes
    | where NodeLabel in (deviceLabels)
    | where NodeProperties has "criticalityLevel"
    | extend CriticalityLevel = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
    | where CriticalityLevel between (0 .. 3)
    | extend Criticality = case(
        CriticalityLevel == 0, "Very high",
        CriticalityLevel == 1, "High",
        CriticalityLevel == 2, "Medium",
        "Low")
    | project DeviceId = NodeId, CriticalityLevel, Criticality,
              CriticalityReason = tostring(NodeProperties.rawData.criticalityLevel.ruleNames);
riskyAgentProfiles
| join kind=inner localAgentNodes on AgentId
| join kind=inner agentDeviceEdges on AgentNodeId
| join kind=inner criticalDevices on DeviceId
| project Device, DeviceType, Criticality, CriticalityReason,
          Agent, Vendor, Version, Account, AutoApprove, TrustedProcess,
          CriticalityLevel
| sort by CriticalityLevel asc, Device asc, Agent asc
| project-away CriticalityLevel
```

---

## Query 9: Rank Users Whose Local Agents Reach Critical or Sensitive Assets

Ranks the identities that use local agents by how many critical or sensitive resources they can reach — prioritizing the users with the widest blast radius. `UserCriticality` shows whether the identity is itself a critical asset (e.g., a Global Administrator).

> ⚠️ This is the heaviest query in the file (multiple exposure-graph joins). Keep the local-agent set small (it already is) and avoid widening the `userReach` edges.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-join exposure-graph blast-radius ranking — posture/prioritization analysis, not a row-level detection. Computationally heavy; run interactively."
-->

```kql
let deviceLabels = dynamic(["device", "ec2.instance", "microsoft.compute/virtualmachines"]);
let localAgents =
    ExposureGraphNodes
    | where NodeLabel == "ai-agent"
    | where tostring(NodeProperties.rawData.aiAgentMetadata.platform) == "LocalAgents"
    | project AgentNodeId = NodeId, AIAgent = NodeName;
let agentDeviceEdges =
    ExposureGraphEdges
    | where SourceNodeLabel == "ai-agent"
    | where EdgeLabel =~ "runs on"
    | where TargetNodeLabel in (deviceLabels)
    | project AgentNodeId = SourceNodeId, DeviceId = TargetNodeId, Device = TargetNodeName;
let agentUserEdges =
    ExposureGraphEdges
    | where SourceNodeLabel == "ai-agent"
    | where EdgeLabel =~ "used by"
    | project AgentNodeId = SourceNodeId, UserId = TargetNodeId, User = TargetNodeName;
let userReach =
    ExposureGraphEdges
    | where EdgeLabel in~ ("has permissions to", "has role on")
    | project UserId = SourceNodeId, AssetId = TargetNodeId
    | union (
        ExposureGraphNodes
        | where NodeLabel == "user"
        | project UserId = NodeId, AssetId = NodeId
    );
let sensitiveAssets =
    ExposureGraphNodes
    | where NodeProperties has "criticalityLevel" or NodeProperties has "containsSensitiveData"
    | extend CriticalityLevel = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel),
             SensitiveDataRaw = tostring(NodeProperties.rawData.containsSensitiveData)
    | extend HasSensitiveData = iff(isnotempty(SensitiveDataRaw) and SensitiveDataRaw !~ "false", "Yes", "No")
    | where CriticalityLevel between (0 .. 3) or HasSensitiveData == "Yes"
    | extend CriticalityRank = iff(CriticalityLevel between (0 .. 3), CriticalityLevel, 4)
    | project AssetId = NodeId, AssetName = NodeName, CriticalityRank, HasSensitiveData;
let agentUsers =
    localAgents
    | join kind=inner agentDeviceEdges on AgentNodeId
    | join kind=inner agentUserEdges on AgentNodeId
    | project AIAgent, Device, UserId, User;
agentUsers
| join kind=inner userReach on UserId
| join kind=inner sensitiveAssets on AssetId
| summarize AIAgents         = make_set(AIAgent, 20),
            Devices          = make_set(Device, 20),
            ReachableAssets  = dcountif(AssetId, AssetId != UserId),
            SensitiveAssets  = dcountif(AssetId, AssetId != UserId and HasSensitiveData == "Yes"),
            Assets           = make_set_if(AssetName, AssetId != UserId, 50),
            UserRank         = minif(CriticalityRank, AssetId == UserId),
            AssetRank        = minif(CriticalityRank, AssetId != UserId)
    by User
| extend UserCriticality = case(
             UserRank == 0, "Very high",
             UserRank == 1, "High",
             UserRank == 2, "Medium",
             UserRank == 3, "Low",
             "Not classified"),
         HighestAssetCriticality = case(
             AssetRank == 0, "Very high",
             AssetRank == 1, "High",
             AssetRank == 2, "Medium",
             AssetRank == 3, "Low",
             AssetRank == 4, "Sensitive data",
             "None")
| extend SortRank = coalesce(AssetRank, 99)
| project User, UserCriticality, ReachableAssets, SensitiveAssets,
          HighestAssetCriticality, AIAgents, Devices, Assets, SortRank
| sort by SortRank asc, ReachableAssets desc
| project-away SortRank
```

---

## Related

- **`queries/endpoint/openclaw_shadow_ai_hunting.md`** — deep-dive process/network/file hunting for the OpenClaw self-hosted agent runtime; pair with Query 6 when a self-hosted agent appears as removed/installed.
- **`.github/skills/ai-agent-posture/SKILL.md`** — full posture assessment for *cloud* agents (Copilot Studio, Agent Builder, Foundry) via the same `AgentsInfo` table (different `Platform` values, `RawAgentInfo` structure, and scoring model).
- **`queries/cloud/exposure_graph_attack_paths.md`** — broader exposure-graph tooling and attack-path queries.
- **`queries/network/gsa_generative_ai_insights.md`** — the **network-layer** complement: Global Secure Access GenAI Insights (`NetworkAccessGenerativeAIInsights`) sees AI-app and MCP egress **on the wire** plus prompt text and allow/block policy verdicts. This file sees the **runtime installed on the device**; pair them to attribute observed GenAI/MCP traffic to the local agent generating it.
