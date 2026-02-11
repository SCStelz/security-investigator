---
name: mcp-usage-monitoring
description: 'Use this skill when asked to monitor, audit, or analyze MCP (Model Context Protocol) server usage in the environment. Triggers on keywords like "MCP usage", "MCP server monitoring", "MCP activity", "Graph MCP", "Sentinel MCP", "Azure MCP", "AI agent monitoring", "MCP audit", "tool usage monitoring", "MCP breakdown", "who is using MCP", or when investigating AI agent access patterns, Graph API calls from MCP servers, or workspace query governance. This skill provides comprehensive MCP server telemetry analysis across Graph MCP, Sentinel MCP, and Azure MCP servers including usage trends, endpoint access patterns, user attribution, sensitive API detection, workspace query governance, and security risk assessment with inline and markdown file reporting.'
---

# MCP Server Usage Monitoring — Instructions

## Purpose

This skill monitors and audits **Model Context Protocol (MCP) server usage** across your Microsoft Sentinel and Defender XDR environment. MCP servers are AI-powered tools that enable language models to interact with Microsoft security services — and like any privileged access channel, they require monitoring.

**What this skill tracks:**

| MCP Server | Telemetry Source | Key Identifier |
|------------|-----------------|----------------|
| **Microsoft Graph MCP Server** | `MicrosoftGraphActivityLogs` | AppId = `e8c77dc2-69b3-43f4-bc51-3213c9d915b4` |
| **Sentinel Data Lake MCP** | `CloudAppEvents` | RecordType 403, Interface = `IMcpToolTemplate` |
| **Sentinel Triage MCP** | `MicrosoftGraphActivityLogs` + `SigninLogs` | Graph Security API endpoints (`/security/incidents`, `/security/alerts_v2`, `/security/runHuntingQuery`) — **shared surface** (Triage MCP calls cannot be isolated from other consumers of same endpoints) |
| **Azure MCP Server** | `AzureActivity` | No dedicated AppId — uses `DefaultAzureCredential` |
| **Sentinel Data Lake — Direct KQL** | `CloudAppEvents` | RecordType 379, Operation = `KQLQueryCompleted` |
| **Workspace Query Sources (Analytics Tier)** | `LAQueryLogs` | All clients querying Log Analytics workspace |

**What this skill detects:**
- Graph API call volume, trends, and endpoint diversity via MCP
- Sensitive/high-risk Graph endpoint access (PIM, credentials, Identity Protection)
- Sentinel workspace query patterns by client application
- **User vs. Service Principal vs. Agent Identity attribution** across all MCP channels
- **Entra Agent ID detection** — distinguishes AI agent identities from standard SPNs and human users (see [Agent Identity Detection](#agent-identity-detection))
- Azure ARM operations potentially originating from Azure MCP Server
- Non-MCP platform query sources for governance context (Sentinel Engine, Logic Apps)
- **Sentinel Data Lake MCP tool usage** — tool call breakdown (`query_lake`, `list_sentinel_workspaces`, `search_tables`, etc.), success/failure rates, execution duration, tables accessed via `CloudAppEvents` (Purview unified audit)
- **MCP-driven vs Direct KQL delineation** — distinguishes Data Lake queries initiated via MCP tools (RecordType 403, Interface `IMcpToolTemplate`) from direct KQL queries (RecordType 379) and Analytics tier queries (`LAQueryLogs`)
- Anomalous access patterns: new users, new endpoints, volume spikes, error surges
- MCP server usage as a proportion of total workspace activity

**Extended landscape awareness:** Beyond these four actively monitored MCP servers, Microsoft's MCP ecosystem includes 30+ additional servers (Copilot Studio built-in catalog, Power BI, Fabric RTI, Playwright, Security Copilot Agent Creation, and more). See [Extended Microsoft MCP Server Landscape](#extended-microsoft-mcp-server-landscape-reference) for the full catalog, telemetry surfaces, and monitoring expansion priorities.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Agent Identity Detection](#agent-identity-detection)** - Entra Agent ID vs SPN vs User
3. **[Extended MCP Server Landscape](#extended-microsoft-mcp-server-landscape-reference)** - Full Microsoft MCP ecosystem catalog
4. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
5. **[Scalability & Token Management](#scalability--token-management)** - Guidance for large environments
6. **[Quick Start](#quick-start-tldr)** - 8-step investigation pattern
7. **[MCP Usage Score Formula](#mcp-usage-score-formula)** - Composite health & risk scoring
8. **[Execution Workflow](#execution-workflow)** - Complete 6-phase process
9. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns
10. **[Report Template](#report-template)** - Output format specification
11. **[Proactive Alerting — KQL Data Lake Jobs](#proactive-alerting--kql-data-lake-jobs)** - Scheduled anomaly detection
12. **[Known Pitfalls](#known-pitfalls)** - Edge cases and false positives
13. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY MCP usage monitoring analysis:**

1. **ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)
2. **ALWAYS ask the user for output mode** if not specified: inline chat summary or markdown file report (or both)
3. **ALWAYS ask the user for time range** if not specified: default to 30 days, configurable
4. **ALWAYS query all MCP telemetry surfaces** — do not skip any MCP server type
5. **ALWAYS include non-MCP workspace context** (Sentinel Engine, Logic Apps) for governance proportion analysis
6. **ALWAYS run independent queries in parallel** for performance
7. **ALWAYS attribute activity to specific users** — never present anonymous aggregates
8. **NEVER conflate non-MCP platform activity with MCP activity** — clearly label categories
9. **ALWAYS check for Agent Identity (Entra Agent ID) callers** — distinguish AI agents from human users and standard SPNs (see [Agent Identity Detection](#agent-identity-detection))

---

## Agent Identity Detection

**Microsoft Entra Agent ID** (public preview) introduces a **new first-class identity type** for AI agents, distinct from traditional service principals and user accounts. MCP servers may be called by human users, standard SPNs, or Agent Identities — and the telemetry to distinguish them varies by table.

> **Reference:** [What are agent identities](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/what-is-agent-id) | [Agent sign-in and audit logs](https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/sign-in-audit-logs-agents) | [Agent OAuth protocols](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-oauth-protocols)

### Entra Identity Taxonomy

| Identity Category | Types | MCP Usage Pattern |
|---|---|---|
| **Human identities** | User accounts (workforce, external) | User signs into VS Code → MCP server acts on behalf of user (delegated) |
| **Workload identities** | App registrations, service principals, managed identities | Standard SPN authenticates to MCP (client credentials / app-only) |
| **🆕 Agent identities** | Agent Identity, Agent Identity Blueprint, Agent User | AI agent uses MCP via Agent OBO, Autonomous App, or Agent User flow |

### Agent ID Object Types

| Object | What It Is | Analogy |
|---|---|---|
| **Agent Identity Blueprint** | Reusable template defining a *class* of agent (e.g., "SOC Triage Agent") | Like an app registration |
| **Agent Identity Blueprint Principal** | SPN created when a blueprint is instantiated in a tenant | Like the SPN for an app registration |
| **Agent Identity** | Special SPN with subtype `agent` — represents a single agent instance | Like a service principal, but agent-specific |
| **Agent User** | Optional user account paired 1:1 with an agent identity (for mailbox, Teams, etc.) | Like a user account, but non-human |

**Architectural detail:** Agent identities are modeled as **single-tenant service principals with an "agent" subtype**. The `objectId` and `appId` always have the **same value** (unlike regular app registrations where they differ).

### Agent Authentication Flows

| Flow | Pattern | When Used | Telemetry Impact |
|---|---|---|---|
| **Agent On-Behalf-Of (OBO)** | Delegated — agent acts on behalf of a signed-in user | User-initiated agents, copilots | `UserId` = human user, `ServicePrincipalId` = agent SPN |
| **Autonomous App Flow** | App-only — agent acts under its own authority (`client_credentials`) | Background agents, scheduled tasks | `ServicePrincipalId` = agent SPN, `UserId` empty |
| **Agent User Flow** | Agent uses its paired agent user account | Agents needing mailbox, Teams access | `UserId` = Agent User (non-human with UPN) |

### How to Detect Agent Identities in Telemetry

**⚠️ Known Limitation (Preview):** `MicrosoftGraphActivityLogs` does NOT yet distinguish Agent IDs from regular SPNs. Requests from agent identities appear as regular applications with the agent identity in the `AppId` column. Requests from agent users appear as regular users with the agent user ID in `UserId`.

**Detection Strategy:**

| Telemetry Source | Detection Method | Reliability | Status |
|---|---|---|---|
| **Graph API `/beta` `tags`** | Query `/beta/servicePrincipals/{id}?$select=tags` — check for `AgenticApp`, `AIAgentBuilder`, `AgentCreatedBy:CopilotStudio` tags | 🟢 **Most reliable** | ✅ Available now |
| **`AuditLogs`** | Agent lifecycle CRUD operations — filter `OperationName has "agent"` or `InitiatedBy` = `Power Virtual Agents Service` | 🟢 High | ✅ Available now |
| **`AADServicePrincipalSignInLogs`** | Agent sign-ins to resources like `Bot Framework` from Azure internal IPs (`fd00:*`) | 🟢 High | ✅ Available now |
| **`MicrosoftGraphActivityLogs`** | Join with sign-in logs to identify agent callers by `AppId`/`ServicePrincipalId` | 🟡 Requires cross-ref | ⚠️ Workaround needed |
| **`SigninLogs`** | New `agentSignIn` resource type; filter by `agent/agentType` | 🟡 Preview-dependent | ✅ Available in preview |
| **Graph API `servicePrincipalType`** | `GET /servicePrincipals?$filter=servicePrincipalType eq 'Agent'` | 🔴 **Not yet reliable** — Copilot Studio agents still show `"Application"` | ⚠️ Preview gap |

> 🔵 **Field-tested finding:** The `servicePrincipalType` property does NOT yet show `"Agent"` for Copilot Studio-created agents — they still return `"Application"` on both `/v1.0` and `/beta`. The **`tags` array on `/beta`** is currently the only reliable programmatic indicator. Key tags: `AgenticApp`, `AIAgentBuilder`, `AgentCreatedBy:CopilotStudio`, `AgenticInstance`.

**Sign-in log filters for agents:**
- Portal: Filter by **Agent type** = `Agent Identity` or `Agent ID user` and **Is Agent** = `Yes`
- Graph API: `$filter=signInEventTypes/any(t: t eq 'servicePrincipal') and agent/agentType eq 'AgentIdentity'`

### MicrosoftGraphActivityLogs — User vs SPN vs Agent Attribution

The `MicrosoftGraphActivityLogs` table has two identity fields that determine "who" is calling Graph APIs:

| Field | Populated When | Identity Type |
|---|---|---|
| `UserId` | A **human user** (or Agent User) made the request via delegated permissions | User / Agent User |
| `ServicePrincipalId` | A **service principal** (or Agent Identity) made the request via app-only permissions | SPN / Agent Identity |
| `ClientAuthMethod` | Always populated — indicates how the caller authenticated | 0 = public client (user), 1 = client secret (SPN), 2 = certificate (SPN) |
| `Roles` | Populated when app-only (application permissions) | App-only flow indicator |
| `Scopes` | Populated when delegated (user context) | Delegated flow indicator |

**Decision tree for caller attribution:**
```
IF ServicePrincipalId is populated AND UserId is empty:
   → App-only flow: SPN or Agent Identity is the autonomous caller
   → Check ClientAuthMethod: 1 = secret, 2 = certificate
   → Cross-reference ServicePrincipalId with Entra to determine if Agent Identity

IF UserId is populated AND ServicePrincipalId is populated:
   → Delegated flow: User (or Agent User) signed in, SPN is the client app
   → Agent OBO: Agent acts on behalf of user — both fields populated

IF UserId is populated AND ServicePrincipalId is empty:
   → Direct user-delegated flow (e.g., VS Code → Graph MCP)
   → Check if UserId maps to an Agent User (non-human account with UPN)
```

### Products Already Using Agent ID

| Product | Agent ID Usage | Telemetry Fingerprint (Field-Tested) |
|---|---|---|
| **Copilot Studio agents** | Each created agent gets an SPN with agentic tags automatically. Initiated by `Power Virtual Agents Service`. Your user gets added as owner. | AuditLogs: `InitiatedBy` = `Power Virtual Agents Service`, `TargetType` = `ServicePrincipal`. SPN sign-ins to `Bot Framework` from Azure internal IPv6 (`fd00:34f2:*`). Tags: `AgenticApp`, `AgentCreatedBy:CopilotStudio`, `AgenticInstance` |
| **Entra CA Optimization Agent** | Microsoft first-party agent identity | May appear in tenant sign-in logs |
| **Custom AI agents** | Developers can register agents via Agent Identity Blueprint | Will appear as SPNs with agent subtype |

> ⚠️ **Name ambiguity warning:** An SPN named with "Agent" in its display name does NOT mean it's an Agent Identity. Example: "Agent 365 Tools" is a standard `GitCreatedApp` with `servicePrincipalType: Application` and no agentic tags. Always verify via `/beta` `tags` — never rely on display name alone.

### Impact on This Skill

When running MCP usage monitoring:

1. **Phase 1 (Graph MCP):** Check BOTH `UserId` and `ServicePrincipalId` in Query 1 results — if `ServicePrincipalId` is populated with a non-empty value, an SPN or Agent Identity is calling Graph MCP autonomously
2. **New Phase (Agent Detection):** Run Query 17 to identify Agent Identities in the tenant and cross-reference against MCP callers
3. **Report section:** Include a dedicated "Agent vs User Attribution" breakdown showing how many MCP calls originated from humans, standard SPNs, and Agent Identities
4. **Security flag:** Agent Identities calling sensitive Graph endpoints autonomously (without user OBO context) should be flagged 🟠 — verify authorization

---

### Known AppIds Reference

#### MCP Servers & AI Agents

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `e8c77dc2-69b3-43f4-bc51-3213c9d915b4` | Microsoft Graph MCP Server for Enterprise | `MicrosoftGraphActivityLogs` | Read-only Graph API proxy |
| `6574a0f8-d39b-4090-abbe-6c64ec9003f0` | Sentinel Triage MCP (registered AppId) | `LAQueryLogs` (environment-dependent) | Microsoft first-party AppId, same across all tenants. **Primary detection** is via Graph Security API endpoint patterns in `MicrosoftGraphActivityLogs` (Query 7). 🔴 **Field-tested Feb 2026 (two environments):** AppId `6574a0f8` appears in `LAQueryLogs` in **some** environments (1,086 queries in production) but NOT in others (0 in lab). When present, it has **no user attribution** (empty `AADEmail`, empty `RequestClientApp`). The **bulk** of AH downstream queries appear under AppId `fc780465` / `RequestClientApp = "M365D_AdvancedHunting"` with full user attribution (162K queries). Query 7b checks both AppIds. Does NOT appear in `SigninLogs`, `MicrosoftGraphActivityLogs`, or `CloudAppEvents`. |
| `253895df-6bd8-4eaf-b101-1381ec4306eb` | Sentinel Platform Services App Reg | `SigninLogs` | Sentinel-hosted MCP platform |
| `1950a258-227b-4e31-a9cf-717495945fc2` | Azure MCP Server (local stdio via DefaultAzureCredential) | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | Shared AppId with Azure PowerShell. **Detectable** via UserAgent `azsdk-net-Identity/1.x (.NET 9.x)` in sign-in logs and `csharpsdk,LogAnalyticsPSClient` in LAQueryLogs. Read-only ARM ops don't appear in AzureActivity. |
| *(none — uses DefaultAzureCredential)* | Azure MCP Server (local stdio) | `AzureActivity` | ARM **write** operations only; read ops not logged. Claims.appid = `1950a258`. Inherits cred from Azure CLI/VS Code |
| *(no AppId — Purview unified audit)* | Sentinel Data Lake MCP | `CloudAppEvents` | RecordType 403; Interface `IMcpToolTemplate`; tools: `query_lake`, `list_sentinel_workspaces`, `search_tables` |

#### Sentinel MCP Collection Endpoints

| Endpoint URL | Collection | Monitored |
|-------------|------------|----------|
| `https://sentinel.microsoft.com/mcp/data-exploration` | Data Exploration (Data Lake MCP) | ✅ Phase 3 |
| `https://sentinel.microsoft.com/mcp/triage` | Triage (Triage MCP) | ✅ Phase 2 |
| `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` | Security Copilot Agent Creation | ❌ See [Landscape](#extended-microsoft-mcp-server-landscape-reference) |

#### Client Applications

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `aebc6443-996d-45c2-90f0-388ff96faa56` | Visual Studio Code | `SigninLogs` | VS Code as MCP client → Sentinel |
| `9ba5f2e4-6bbf-4df2-b19b-7f1bcb926818` | PowerPlatform-sentinelmcp-Connector | `SigninLogs` | Copilot Studio → Sentinel MCP |
| `04b07795-ee44-4684-983e-0d77d14f7b38` | Azure CLI | `SigninLogs` | Used by Azure MCP Server when cred source is `az login` |\n| `1950a258-227b-4e31-a9cf-717495945fc2` | Microsoft Azure PowerShell (DefaultAzureCredential) | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | Used by Azure MCP Server when cred resolves to `AzurePowerShellCredential`. Disambiguate from actual PowerShell via UserAgent `azsdk-net-Identity` |

#### Portal & Platform Applications (Non-MCP — for context)

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `80ccca67-54bd-44ab-8625-4b79c4dc7775` | M365 Security & Compliance Center (Sentinel Portal) | `LAQueryLogs` | `ASI_Portal`, `ASI_Portal_Connectors` — Sentinel Portal backend, NOT an MCP server |
| `95a5d94c-a1a0-40eb-ac6d-48c5bdee96d5` | Azure Portal — AppInsightsPortalExtension | `LAQueryLogs` | Azure Portal blade for Log Analytics Usage dashboards/workbooks. `RequestClientApp` = `AppInsightsPortalExtension`. Executes billing/usage queries (e.g., `Usage \| where IsBillable`). NOT MCP, NOT VS Code — runs when user opens Workspace Usage Dashboard in browser. No SPN or app registration in tenant (platform-level first-party app). Not in merill/microsoft-info known apps list. |
| `de8c33bb-995b-4d4a-9d04-8d8af5d59601` | PowerPlatform-AzureMonitorLogs-Connector | `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | Logic Apps → Log Analytics (NOT MCP) |
| `fc780465-2017-40d4-a0c5-307022471b92` | Sentinel Engine (analytics rules, UEBA, Advanced Hunting backend) | `LAQueryLogs` | Built-in scheduled query engine (NOT MCP). Also serves as the **execution backend for Advanced Hunting** — `RequestClientApp = "M365D_AdvancedHunting"` indicates AH queries from Triage MCP or Defender portal that hit connected LA tables (see Query 7b). Separate from analytics rules (`RequestClientApp` empty or other values). |

---

## Extended Microsoft MCP Server Landscape (Reference)

Beyond the four MCP servers actively monitored by this skill, Microsoft's MCP ecosystem includes many additional servers. This section catalogs them for awareness, threat modeling, and future monitoring expansion.

### Sentinel MCP Collections (Microsoft-Hosted)

Microsoft Sentinel exposes **three official MCP collections**, each at a distinct endpoint:

| Collection | Endpoint URL | Purpose | Monitored by This Skill |
|------------|-------------|---------|-------------------------|
| **Data Exploration** | `https://sentinel.microsoft.com/mcp/data-exploration` | `query_lake`, `search_tables`, `list_sentinel_workspaces`, entity analyzer | ✅ Phase 3 (CloudAppEvents) |
| **Triage** | `https://sentinel.microsoft.com/mcp/triage` | Incident triage, Advanced Hunting, entity investigation | ✅ Phase 2 (MicrosoftGraphActivityLogs — Graph Security API endpoints) |
| **Security Copilot Agent Creation** | `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` | Create Microsoft Security Copilot agents for complex workflows | ❌ Not yet monitored |

**Sentinel Custom MCP Tools:** Organizations can create their own MCP tools by exposing saved KQL queries from Advanced Hunting as MCP tools. These execute through the same Sentinel MCP infrastructure and are audited in `CloudAppEvents` (RecordType 403) alongside built-in tools. See [Create custom Sentinel MCP tools](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-create-custom-tool).

> 🔵 **Monitoring note:** Custom MCP tools appear in CloudAppEvents with the same RecordType 403 and `IMcpToolTemplate` interface as built-in tools. The `ToolName` field will show the custom tool name, making them visible in Query 21 without modification.

### Power BI MCP Servers

| Server | Type | Endpoint / Repo | Purpose | Telemetry Surface |
|--------|------|----------------|---------|-------------------|
| **Power BI Remote MCP** | Microsoft-hosted | `https://api.fabric.microsoft.com/v1/mcp/powerbi` | Query Power BI datasets, reports, and workspaces remotely via SSE transport | 🟡 `PowerBIActivity` table (if ingested into Sentinel), Fabric audit logs |
| **Power BI Modeling MCP** | Local (stdio) | [microsoft/powerbi-modeling-mcp](https://github.com/microsoft/powerbi-modeling-mcp) | Local Power BI model operations (DAX queries, schema exploration) | ❌ Local only — no Azure telemetry |

> ⚠️ **Data exfiltration risk:** Power BI Remote MCP provides API-based access to organizational datasets. If an AI agent connects to this endpoint, it can query sensitive business data. Monitor `PowerBIActivity` for unusual access patterns if this table is available in your Sentinel workspace.

### Fabric & Azure Data Explorer MCP Servers

| Server | Type | Endpoint / Repo | Purpose | Telemetry Surface |
|--------|------|----------------|---------|-------------------|
| **Fabric RTI MCP Server** | Local (stdio) | [microsoft/fabric-rti-mcp](https://github.com/microsoft/fabric-rti-mcp/) | Query Azure Data Explorer clusters and Fabric Real-Time Intelligence Eventhouses via KQL | 🟡 ADX audit logs, Fabric audit events |
| **Azure MCP Server — Kusto namespace** | Local (stdio) | Part of Azure MCP Server (`azmcp --namespace kusto`) | Manage ADX clusters, databases, tables, and queries via ARM | ✅ Already covered (Azure ARM operations — Phase 4) |
| **Kusto Query MCP** | Copilot Studio built-in | Copilot Studio catalog | KQL query execution from Copilot Studio agents | 🟡 CloudAppEvents (Copilot Studio workload) |

> 🔵 **Note:** The Fabric RTI MCP Server is open-source and runs locally. It authenticates to ADX/Eventhouse using the user's credentials. If your org uses ADX, queries from this MCP would appear in ADX audit logs (`.show queries` / diagnostic logs), NOT in Sentinel `LAQueryLogs`.

### Developer & Productivity MCP Servers

| Server | Type | Repo | Purpose | Telemetry Surface |
|--------|------|------|---------|-------------------|
| **Playwright MCP** | Local (stdio) | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) (26.9k ⭐) | Browser automation via accessibility tree — enables LLMs to interact with web pages | ❌ Local only — no Azure telemetry |
| **GitHub MCP Server** | Local (stdio) | [github/github-mcp-server](https://github.com/github/github-mcp-server) | GitHub repo operations (issues, PRs, code search) via PAT | ❌ GitHub audit logs only, not in Sentinel |
| **Microsoft Learn Docs MCP** | Cloud-hosted | Certified Copilot Studio connector | Search and fetch official Microsoft Learn documentation | ❌ Public docs, no security data |

### Copilot Studio Built-in MCP Servers (19+ servers)

Microsoft Copilot Studio provides a catalog of built-in MCP servers for agent development. These are Microsoft-managed, cloud-hosted servers that agents can connect to.

**Source:** [Built-in MCP servers catalog](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-microsoft-mcp-servers)

| Category | MCP Servers | Security Relevance |
|----------|-------------|--------------------|
| **Microsoft 365** | Outlook Mail, Outlook Calendar, 365 User Profile, Teams, Word, 365 Copilot (Search) | 🔴 High — email, calendar, user profile access |
| **SharePoint & OneDrive** | SharePoint and OneDrive, SharePoint Lists | 🟠 Medium — file and data access |
| **Administration** | 365 Admin Center | 🔴 High — administrative control plane |
| **Dataverse** | Dataverse MCP | 🟠 Medium — business data access |
| **Dynamics 365** | Sales, Finance, Supply Chain, Service, ERP, Contact Center (6 sub-variants) | 🟡 Low-Medium — business application data |
| **Fabric** | Fabric MCP | 🟠 Medium — analytics data access |
| **Office 365 Outlook** | Contact Management, Email Management, Meeting Management | 🔴 High — email and contact data |
| **Meta-Server** | MCP Management MCP | 🟠 Medium — manages other MCP servers via Dataverse/Graph |

> ⚠️ **Telemetry gap:** Copilot Studio built-in MCP servers are NOT directly visible in `LAQueryLogs` or `MicrosoftGraphActivityLogs`. Their activity may appear in:
> - `CloudAppEvents` — under Copilot Studio workload (if Purview unified audit is configured)
> - M365 unified audit log — as Copilot Studio agent actions
> - `AuditLogs` — agent identity lifecycle events (creation, modification via `Power Virtual Agents Service`)
> - `AADServicePrincipalSignInLogs` — agent SPN sign-ins to `Bot Framework` from Azure internal IPs (`fd00:*`)
>
> To monitor Copilot Studio agent activity touching these MCP servers, use the **Agent Identity Detection** workflow (Phase 6) to identify agent SPNs, then trace their sign-in and audit activity.

### Azure MCP Server — Full Tool Surface

The Azure MCP Server (already tracked in Phase 4) has a much broader tool surface than just ARM operations. The complete namespace catalog:

| Category | Namespaces | Security-Relevant Tools |
|----------|-----------|------------------------|
| **AI & ML** | `foundry`, `search`, `speech` | AI Foundry model access, Search index queries |
| **Identity** | `role` | ⚠️ RBAC role assignments — view and manage |
| **Security** | `keyvault`, `appconfig`, `confidentialledger` | 🔴 Key Vault secrets/keys/certs, App Configuration |
| **Databases** | `cosmos`, `mysql`, `postgres`, `redis`, `sql` | Database access and management |
| **Storage** | `storage`, `fileshares`, `storagesync`, `managedlustre` | Blob, file, and storage account access |
| **Compute** | `appservice`, `functionapp`, `aks` | App Service, Functions, Kubernetes |
| **Networking** | `eventhubs`, `servicebus`, `eventgrid`, `communication`, `signalr` | Messaging and event services |
| **DevOps** | `bicepschema`, `deploy`, `monitor`, `workbooks`, `grafana` | Infrastructure deployment, monitoring |
| **Governance** | `policy`, `quota`, `resourcehealth`, `cloudarchitect` | Policy management, resource health |
| **Other** | `marketplace`, `virtualdesktop`, `loadtesting`, `acr` | VDI, container registry, load testing |

> 🔵 **Key Vault access via MCP** is particularly security-sensitive. The Azure MCP Server implements **elicitation** (user confirmation prompts) before returning secrets. However, this can be bypassed with the `--insecure-disable-user-confirmation` flag. Monitor `AzureActivity` for Key Vault operations correlated with MCP usage patterns.

### Monitoring Expansion Priorities

If expanding this skill's coverage, prioritize based on data access risk:

| Priority | Server | Why | How to Monitor |
|----------|--------|-----|----------------|
| 🔴 **P1** | Copilot Studio built-in M365 MCPs | Email, Teams, admin center access | Agent Identity Detection (Phase 6) + CloudAppEvents |
| 🔴 **P1** | Security Copilot Agent Creation | Creates autonomous security agents | CloudAppEvents for agent creation events |
| 🟠 **P2** | Power BI Remote MCP | Dataset query access via API | `PowerBIActivity` table if available |
| 🟠 **P2** | Sentinel Custom MCP Tools | User-defined tools, same audit surface | Already visible in Phase 3 CloudAppEvents |
| 🟡 **P3** | Fabric RTI MCP | ADX/Eventhouse data access | ADX diagnostic logs |
| 🟡 **P3** | Kusto Query MCP (Copilot Studio) | KQL from Copilot Studio agents | CloudAppEvents (Copilot Studio workload) |
| ⚪ **P4** | Playwright, GitHub, Learn Docs MCPs | Local/public, minimal telemetry | Not monitorable from Sentinel |

> **Note:** This catalog reflects the Microsoft MCP ecosystem as of February 2026. The [Copilot Studio MCP catalog](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-microsoft-mcp-servers) notes: *"This list isn't exhaustive. New MCP connectors are added regularly."*

---

## ⛔ MANDATORY: Sentinel Workspace Selection

**This skill requires a Sentinel workspace to execute queries. Follow these rules STRICTLY:**

### When invoked from another skill (e.g., incident-investigation):
- Inherit the workspace selection from the parent investigation context
- If no workspace was selected in parent context: **STOP and ask user to select**

### When invoked standalone (direct user request):
1. **ALWAYS call `list_sentinel_workspaces` MCP tool FIRST**
2. **If 1 workspace exists:** Auto-select, display to user, proceed
3. **If multiple workspaces exist:**
   - Display all workspaces with Name and ID
   - ASK: "Which Sentinel workspace should I use for this analysis?"
   - **⛔ STOP AND WAIT** for user response
   - **⛔ DO NOT proceed until user explicitly selects**
4. **If a query fails on the selected workspace:**
   - **⛔ DO NOT automatically try another workspace**
   - STOP and report the error, display available workspaces, ASK user to select

**🔴 PROHIBITED ACTIONS:**
- ❌ Selecting a workspace without user consent when multiple exist
- ❌ Switching to another workspace after a failure without asking
- ❌ Proceeding with analysis if workspace selection is ambiguous

---

## Output Modes

This skill supports two output modes. **ASK the user which they prefer** if not explicitly specified. Both may be selected.

### Mode 1: Inline Chat Summary (Default)
- Render the full MCP usage analysis directly in the chat response
- Includes ASCII tables, trend charts, endpoint breakdowns, and security assessment
- Best for quick review and interactive follow-up questions

### Mode 2: Markdown File Report
- Save a comprehensive report to `reports/mcp-usage/MCP_Usage_Report_<timestamp>.md`
- All ASCII visualizations render correctly inside markdown code fences (` ``` `)
- Includes all data from inline mode plus additional detail sections
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename pattern:** `reports/mcp-usage/MCP_Usage_Report_YYYYMMDD_HHMMSS.md`

### Markdown Rendering Notes
- ✅ ASCII tables, box-drawing characters, and bar charts render perfectly in markdown code blocks
- ✅ Unicode block characters (▓░█) display correctly in monospaced fonts
- ✅ Emoji indicators (🔴🟢🟡⚠️✅) render natively in GitHub-flavored markdown
- ✅ Standard markdown tables (`| col |`) render as formatted tables
- **Tip:** Wrap all ASCII art in triple-backtick code fences for consistent rendering

---

## Scalability & Token Management

This skill was developed in a small lab environment (1–2 users, single workspace). In larger tenants with many users, MCP servers, and higher query volumes, the **query complexity is not a concern** — all queries use `summarize`, `dcount`, `make_set(..., N)`, and `take` operators, so result sets remain bounded regardless of raw table size. Execution time will increase but output shape stays the same.

The **primary risk in large environments is LLM token exhaustion** during report generation. All query results accumulate in conversation context before the report is written, and this skill file itself consumes significant context. In a large tenant, richer result sets (more users, endpoints, error categories, AppIds) can push past token limits before the report is complete.

### Guardrails for Large Environments

**1. Tighten result set limits in queries:**

| Parameter | Small Env (default) | Large Env |
|-----------|--------------------|-----------|
| `make_set(..., N)` for users | 10 | 5 |
| `make_set(..., N)` for endpoints | 20–30 | 10 |
| `make_set(..., N)` for errors | 5 | 3 |
| `take` on governance tables | 25 | 15 |
| `take` on endpoint rankings | 25 | 15 |
| `take` on error analysis | 50 | 20 |

**2. Incremental file writes (markdown mode):**

Instead of composing the entire report in memory and writing it in one `create_file` call:
- Write the report header and executive summary first with `create_file`
- Append each section (Graph MCP, Sentinel Triage, Data Lake, etc.) using `replace_string_in_file` to insert content at the end of the file
- This allows earlier query results to fall out of active context after being written

**3. Two-pass approach for very large tenants:**

- **Pass 1 (Summary):** Run all queries with aggressive limits (`take 10`, `make_set(..., 3)`). Generate a summary report with top-level numbers only.
- **Pass 2 (Drill-down):** If the user wants detail on a specific section (e.g., "show me the full Data Lake error breakdown"), run targeted queries for that section only.

**4. Parallel query batching:**

Phases 1–5 contain independent queries — always run them in parallel. But avoid running all ~16 queries simultaneously; batch them into 2–3 groups of 5–6 queries. This balances throughput against context accumulation.

**5. Omit raw query appendix for large reports:**

The "Appendix: Query Details" section listing every KQL query used can be omitted in large environments to save tokens. The queries are documented in this skill file and don't need to be repeated in the report.

### Indicators You're Hitting Token Limits

- Report generation starts but cuts off mid-section
- The agent switches to a new conversation turn unexpectedly during report writing
- Sections become progressively less detailed toward the end of the report
- The agent summarizes findings in chat instead of writing the full markdown file

If any of these occur, ask the agent to: "Continue writing the report from where you left off" — the incremental file write approach ensures partial progress is saved.

---

## Quick Start (TL;DR)

When a user requests MCP usage monitoring:

1. **Select Workspace** → `list_sentinel_workspaces`, auto-select or ask
2. **Determine Output Mode** → Ask if not specified: inline, markdown file, or both
3. **Determine Time Range** → Ask if not specified; default 30 days
4. **Run Phase 1 (Graph MCP)** → Daily usage summary, top endpoints, sensitive API access
5. **Run Phase 2 (Sentinel Triage MCP)** → Auth events, client app breakdown, LAQueryLogs query volume
6. **Run Phase 3 (Sentinel Data Lake MCP)** → CloudAppEvents tool usage, error analysis, MCP vs Direct KQL
7. **Run Phase 4 (Azure MCP & ARM)** → ARM operations, resource provider breakdown
8. **Run Phase 5 (Workspace Governance)** → All query sources (Analytics + Data Lake tiers), MCP proportion
9. **Run Phase 6 (Agent Identity)** → Entra Agent ID detection, caller attribution
10. **Run Phase 7 (Assessment)** → Compute MCP Usage Score, security assessment, render report

**Parallel execution:** Phases 1-5 contain independent queries — run all of them in parallel for performance. Phases 6-7 depend on results from 1-5.

---

## MCP Usage Score Formula

The MCP Usage Score is a composite health and risk indicator that summarizes MCP server activity. Unlike the Drift Score (which is a ratio), this is an absolute assessment based on multiple dimensions.

### Scoring Dimensions

$$
\text{MCPUsageScore} = \sum_{i} \text{DimensionScore}_i
$$

Each dimension contributes 0–20 points to a maximum of 100:

| Dimension | Max Points | Green (0-5) | Yellow (6-12) | Red (13-20) |
|-----------|-----------|-------------|---------------|-------------|
| **User Diversity** | 20 | 1-2 known users | 3-5 users or 1 unknown | >5 users or unknown users |
| **Endpoint Sensitivity** | 20 | 0% sensitive endpoints | 1-30% sensitive | >30% calls to sensitive APIs |
| **Error Rate** | 20 | <1% errors | 1-5% errors | >5% errors |
| **Volume Anomaly** | 20 | Within ±50% of daily avg | 50-200% spike | >200% spike vs avg |
| **Off-Hours Activity** | 20 | <5% off-hours | 5-20% off-hours | >20% calls outside business hours |

### Interpretation Scale

| Score | Meaning | Action |
|-------|---------|--------|
| **0–25** | Healthy | ✅ Normal MCP usage, no concerns |
| **26–50** | Elevated | 🟡 Review — minor anomalies detected |
| **51–75** | Concerning | 🟠 Investigate — multiple risk signals present |
| **76–100** | Critical | 🔴 Immediate review — significant security risk |

### Sensitivity Classification

**Sensitive Graph API endpoints** — flag any MCP calls to these patterns:

```
roleManagement, roleAssignments, roleEligibility,
authentication/methods, identityProtection, riskyUsers,
riskDetections, conditionalAccess, servicePrincipals,
appRoleAssignments, oauth2PermissionGrants,
auditLogs, directoryRoles, privilegedAccess,
security/alerts, security/incidents
```

### Off-Hours Definition

Business hours: **08:00–18:00 local time** (derive from user's primary sign-in timezone, or use UTC if unknown). Weekends count as off-hours for all 24 hours.

---

## Execution Workflow

### Phase 1: Graph MCP Server Analysis

**Data source:** `MicrosoftGraphActivityLogs`  
**Filter:** `AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"`

Collect:
- Daily usage summary with user count, success/error breakdown, avg duration (Query 1)
- Top 25 Graph API endpoints accessed with call counts and last-used timestamps (Query 2)
- Sensitive/high-risk endpoint access with user and scope details (Query 3)
- All distinct AppIds calling Graph API for MCP discovery (Query 4)

### Phase 2: Sentinel Triage MCP Analysis

**Data sources:** `SigninLogs`, `MicrosoftGraphActivityLogs`  
**Filter:** ResourceDisplayName = `Sentinel Platform Services` (SigninLogs); Graph Security API endpoints in `MicrosoftGraphActivityLogs`

**Detection Method (Field-Tested Feb 2026):**

The Sentinel Triage MCP uses **delegated authentication** — Graph API calls carry the **client application's AppId** (e.g., VS Code `aebc6443`, Security Copilot API `bb3d68c2`), NOT the Triage MCP server's registered AppId (`6574a0f8`). AppId `6574a0f8` does NOT appear in `MicrosoftGraphActivityLogs`, `SigninLogs`, or `CloudAppEvents`. In `LAQueryLogs`, **two AppIds carry AH downstream queries** (field-tested Feb 2026 across two environments):

1. **`fc780465` / `M365D_AdvancedHunting`** — Primary path. Carries ~99% of AH query volume with full user attribution. Present in all environments.
2. **`6574a0f8`** — Secondary path. Environment-dependent (appeared in production, absent in lab). No user or client app attribution (empty `AADEmail`, empty `RequestClientApp`). ~0.7% of total AH volume when present.

Query 7b checks both AppIds. See [Known Pitfalls](#triage-mcp-appid-in-laquerylogsdual-appid-behavior-field-tested-feb-2026) for cross-environment comparison data.

> 🔴 **ATTRIBUTION LIMITATION:** Because Triage MCP calls are indistinguishable from other consumers of the same Graph Security API endpoints, **Query 7 measures the shared API surface activity, NOT Triage MCP specifically.** The same `/security/incidents`, `/security/alerts_v2`, and `/security/runHuntingQuery` endpoints are also called by Sentinel Engine, Security Copilot, SOAR platforms, ticketing integrations, custom scripts, and the Defender portal. There is currently no telemetry field that isolates Triage MCP's share of this traffic.

The detection approach searches `MicrosoftGraphActivityLogs` for **Graph Security API endpoint patterns** to confirm the API surface is active:
- `/security/incidents` — `ListIncidents`, `GetIncidentById`
- `/security/alerts_v2` — `ListAlerts`, `GetAlertById`
- `/security/runHuntingQuery` — `RunAdvancedHuntingQuery`

These endpoints are shared across multiple consumers. Known client AppIds and their likely source:

| AppId | Client | Source Category |
|-------|--------|----------------|
| `bb3d68c2` | Security Copilot API | May include Triage MCP calls OR native Copilot operations |
| `7b7b3966` | Custom/Third-party | May include Triage MCP calls OR custom scripts |
| `aebc6443` | Visual Studio Code | Most likely Triage MCP (VS Code MCP extension) |
| `98785600` | Automated poller | Likely SOAR/ticketing integration (not MCP) |
| `9ee7b58d` | Automated poller | Likely SOAR/ticketing integration (not MCP) |
| `fc780465` | Sentinel Engine | Microsoft platform automation (not MCP) |

> ⚠️ **Disambiguation guidance:** Use AppId + call pattern heuristics to estimate which calls *may* originate from Triage MCP vs. other consumers. High-volume single-user polling (e.g., 40K GET calls/30d) = automated integration. Multi-user POST-heavy hunting queries = more likely interactive MCP or Copilot usage. But **definitive attribution is not possible** with current telemetry.

> 🔵 **`MicrosoftGraphActivityLogs` retention** varies by environment (depends on Log Analytics workspace configuration and diagnostic settings). Do not assume a fixed retention period — check with a baseline row count query first.

Collect:
- Authentication events by client app (VS Code, Copilot Studio, browser) with user, IP, OS, country (Query 5)
- Client app usage breakdown with distinct user counts and last-seen timestamps (Query 6)
- Graph Security API endpoint usage from `MicrosoftGraphActivityLogs` — incident/alert/hunting calls by AppId (Query 7)
- LAQueryLogs for Advanced Hunting downstream queries (Query 7b). Checks **two AppIds**: `fc780465` / `M365D_AdvancedHunting` (bulk of AH queries, full user attribution) and `6574a0f8` (Triage MCP direct path, environment-dependent, no user attribution). Captures queries from any `RunAdvancedHuntingQuery` consumer (Triage MCP, Defender portal, Security Copilot) that hit connected LA tables. XDR-native tables (DeviceEvents, EmailEvents) don't appear here.
- Portal/Platform query volume from LAQueryLogs for governance context (Query 7c)

### Phase 3: Sentinel Data Lake MCP Analysis

**Data source:** `CloudAppEvents` (Purview unified audit log)  
**Filter:** `ActionType contains "Sentinel"` or `ActionType contains "KQL"`, RecordType 403 (MCP tools) / 379 (Direct KQL)

**Audit Path:** Sentinel Data Lake MCP tools are NOT audited via `LAQueryLogs` — they are tracked through Purview unified audit log, surfaced in the `CloudAppEvents` table. RecordType 403 = Sentinel AI Tool activities, RecordType 379 = KQL activities.

**MCP vs Direct KQL Delineation:**

| Access Pattern | RecordType | Interface | Operation | What It Represents |
|---|---|---|---|---|
| **MCP Server-driven** | 403 | `IMcpToolTemplate` | `SentinelAIToolRunStarted`, `SentinelAIToolRunCompleted` | Tool calls via Sentinel Data Lake MCP (e.g., `query_lake`, `list_sentinel_workspaces`, `search_tables`) |
| **Direct KQL** | 379 | `Microsoft.SentinelGraph.AIPrimitives.Core.Services.KqsService` | `KQLQueryCompleted` | KQL queries executed directly via Sentinel Graph / Data Lake Explorer (no MCP intermediary) |

**Key `RawEventData` Fields:**

| Field | Description | Example |
|---|---|---|
| `ToolName` | MCP tool invoked | `query_lake`, `list_sentinel_workspaces`, `search_tables`, `analyze_url_entity` |
| `Interface` | Execution interface — distinguishes MCP from direct | `IMcpToolTemplate` (MCP) vs `KqsService` (direct) |
| `ExecutionDuration` | Duration in seconds (as string) | `"2.4731712"` |
| `FailureReason` | Error message if failed | `"SemanticError: 'DeviceDetail' column does not exist"` |
| `TablesRead` | Tables accessed by the query | `"SigninLogs"` |
| `DatabasesRead` | Log Analytics workspace name | `"la-yourworkspace"` |
| `TotalRows` | Rows returned | `100` |
| `InputParameters` | Full tool input including KQL query text and workspaceId | JSON string with `query` and `workspaceId` keys |

Collect:
- Data Lake MCP tool usage summary with success/failure breakdown (Query 20)
- Tool-level breakdown with call counts and avg execution duration (Query 21)
- Error analysis for failed Data Lake MCP tool calls (Query 22)
- Daily activity trend across MCP and Direct KQL (Query 23)
- MCP vs Direct KQL delineation summary (Query 24)

### Phase 4: Azure MCP Server & ARM Operations

**Data sources:** `AzureActivity`, `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs`  
**Filter:** Caller = user UPN (AzureActivity), AppId = `1950a258-227b-4e31-a9cf-717495945fc2` (sign-in logs, LAQueryLogs)

Collect:
- ARM operations by hour/IP with operation counts and resource provider sets (Query 8)
- Resource provider breakdown with top operations per provider (Query 9)
- **Azure MCP Server authentication events** from SigninLogs/AADNonInteractiveUserSignInLogs — filter by AppId `1950a258` AND UserAgent containing `azsdk-net-Identity` AND `.NET` (Query 25)
- **Azure MCP Server workspace queries** from LAQueryLogs — filter by AADClientId `1950a258` AND RequestClientApp `csharpsdk` (Query 26)

**Detection Method (Field-Tested Feb 2026):**

The Azure MCP Server runs as a local .NET process (stdio mode) and authenticates via `DefaultAzureCredential`, which resolves to `AzurePowerShellCredential` in the credential chain. This produces AppId `1950a258-227b-4e31-a9cf-717495945fc2` ("Microsoft Azure PowerShell") — the same AppId as Azure PowerShell.

**Disambiguation from Azure PowerShell AND other Azure SDK services:**

🔴 **CRITICAL (Field-Tested Feb 2026):** The `azsdk-net-Identity` UserAgent prefix is NOT unique to Azure MCP Server. It is shared by ANY Azure service using the Azure Identity SDK for .NET, including Security Copilot API (`bb3d68c2`), and potentially others. You MUST use the full composite signal to isolate Azure MCP Server:

| Signal | Azure MCP Server (Local) | Azure PowerShell | Security Copilot API (Cloud) | Other Azure SDK Services |
|--------|--------------------------|------------------|------------------------------|-------------------------|
| **AppId** | `1950a258` | `1950a258` | `bb3d68c2` | Varies |
| **UserAgent** (SigninLogs) | `azsdk-net-Identity/1.x (.NET 9.x; **Microsoft Windows** ...)` | PowerShell-specific UA patterns | `azsdk-net-Identity/1.x (.NET 8.x; **CBL-Mariner/Linux**)` | `azsdk-net-Identity` + various OS |
| **OS in UserAgent** | `Microsoft Windows 10.x` | `Microsoft Windows` (different UA prefix) | `CBL-Mariner/Linux` or `Microsoft Azure Linux` | Platform-dependent |
| **RequestClientApp** (LAQueryLogs) | `csharpsdk,LogAnalyticsPSClient` | `PSClient,LogAnalyticsPSClient` | N/A | Varies |
| **Auth pattern** | Non-interactive + occasional 700082 MFA step-up | Direct interactive or cached token | Non-interactive (server-to-server) | Varies |
| **Resource targets** | ARM + Log Analytics API | Varies by cmdlet | Microsoft Graph, Azure Purview | Service-specific |

**Reliable detection filter** (use ALL conditions):
```kql
| where AppId == "1950a258-227b-4e31-a9cf-717495945fc2"
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
```

**Authentication Sequence Observed:**
1. Azure MCP Server attempts non-interactive token acquisition via `AzurePowerShellCredential`
2. If MFA claim is missing from cached token → ResultType `700082` (MFA not completed, single-factor auth insufficient)
3. `DefaultAzureCredential` falls back to `InteractiveBrowserCredential` → opens Edge for MFA
4. After MFA completion, non-interactive tokens succeed with cached MFA claim
5. Subsequent calls reuse the cached token until expiry (~1 hour)

**🔴 Token Caching Behavior (Field-Tested Feb 2026):**
- Sign-in events appear at **token acquisition time**, NOT at each individual API call time
- Once a token is cached, subsequent Azure MCP calls (list resources, get configs, etc.) do NOT generate new sign-in events
- You will see 1-3 sign-in events per token lifecycle, not one per API call
- To count actual API calls, correlate with AzureActivity (write ops) or LAQueryLogs (`monitor_workspace_log_query` calls)
- The ~1hr token lifetime means at most ~24 sign-in event clusters per day of continuous use

**AzureActivity visibility:** Only ARM **write/action/delete** operations appear in AzureActivity (Administrative category). Azure MCP Server read-only operations (list subscriptions, list resource groups, list clusters) do NOT appear. Claims.appid = `1950a258` when write operations do occur. AzureActivity has a ~2-4 hour ingestion lag.

**Note:** While the shared AppId means Azure MCP Server is not UNIQUELY identifiable by AppId alone, the composite signal (AppId + UserAgent containing `Microsoft Windows` + RequestClientApp `csharpsdk`) provides reliable detection. Present findings as "Azure MCP Server" when all signals match, or "Azure MCP Server / PowerShell (shared AppId)" if UserAgent data is unavailable.

### Phase 5: Workspace Query Governance

**Data source:** `LAQueryLogs` (Analytics tier), `CloudAppEvents` (Data Lake tier)  
**Filter:** All AADClientIds (LAQueryLogs), All Sentinel operations (CloudAppEvents)

Collect:
- All clients querying the Analytics tier workspace with query counts, user counts, CPU usage (Query 10)
- Data Lake tier query volume from Phase 3 results (Queries 20-24)
- MCP proportion calculation: combined MCP query volume (Analytics + Data Lake tiers) / total query volume
- Non-MCP platform context (Sentinel Engine, Logic Apps, Sentinel Portal volumes)

### Phase 6: Agent Identity Detection

**Data sources:** `MicrosoftGraphActivityLogs`, `AADServicePrincipalSignInLogs`, `AuditLogs`, Microsoft Graph API

Collect:
- Graph MCP caller attribution — User vs SPN vs Agent breakdown (Query 17)
- Agent Identity inventory via Graph API — `GET /servicePrincipals?$filter=servicePrincipalType eq 'Agent'` (via Graph MCP `microsoft_graph_suggest_queries` → `microsoft_graph_get`)
- Agent Identity sign-in events from `AADServicePrincipalSignInLogs` where applicable (Query 18)
- Agent Identity CRUD operations from `AuditLogs` — creation, modification, deletion of agent identities (Query 19)

**Note:** This phase depends on Entra Agent ID (preview) being available in the tenant. If no agent identities exist, report: "✅ No Entra Agent Identities detected in tenant — all MCP callers are standard users or service principals." and skip Queries 18-19.

### Phase 7: Score Computation & Report Generation

1. **Compute per-dimension scores** from Phase 1-6 data:
   - **User Diversity:** Count distinct users AND distinct Agent Identities across all MCP channels
   - **Endpoint Sensitivity:** % of Graph MCP calls to sensitive patterns (Phase 1 Query 3 vs Query 1)
   - **Error Rate:** % of non-2xx responses across all MCP channels
   - **Volume Anomaly:** Compare most recent day vs rolling average (Phase 1 Query 1 daily data)
   - **Off-Hours Activity:** % of MCP calls outside 08:00-18:00 (derive from TimeGenerated)
2. **Sum dimension scores** for composite MCP Usage Score
3. **Include Agent Identity attribution** in report if any agent callers detected (Phase 6)
4. **Generate security assessment** with emoji-coded findings
5. **Render output** in the user's selected mode

---

## Sample KQL Queries

### Query 1: Graph MCP — Daily Usage Summary

```kql
// Graph MCP daily usage trend with success/error breakdown
// Configurable: replace ago(30d) with desired lookback
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| summarize 
    Requests = count(),
    DistinctUsers = dcount(UserId),
    SuccessCount = countif(ResponseStatusCode >= 200 and ResponseStatusCode < 300),
    ErrorCount = countif(ResponseStatusCode >= 400),
    AvgDurationMs = avg(DurationMs)
    by bin(TimeGenerated, 1d)
| extend ErrorRate = round(100.0 * ErrorCount / Requests, 1)
| order by TimeGenerated desc
```

### Query 2: Graph MCP — Top Endpoints Accessed

```kql
// Most-called Graph API endpoints via MCP, with user and recency info
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| extend Endpoint = tostring(split(RequestUri, "?")[0])
| summarize 
    CallCount = count(),
    DistinctUsers = dcount(UserId),
    LastUsed = max(TimeGenerated),
    Methods = make_set(RequestMethod, 5)
    by Endpoint
| order by CallCount desc
| take 25
```

### Query 3: Graph MCP — Sensitive API Access

```kql
// Flag MCP calls to high-risk Graph endpoints (PIM, credentials, Identity Protection)
let sensitive_patterns = dynamic([
    "roleManagement", "roleAssignments", "roleEligibility",
    "authentication/methods", "identityProtection", "riskyUsers",
    "riskDetections", "conditionalAccess", "servicePrincipals",
    "appRoleAssignments", "oauth2PermissionGrants",
    "auditLogs", "directoryRoles", "privilegedAccess",
    "security/alerts", "security/incidents"
]);
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| where RequestUri has_any (sensitive_patterns)
| project TimeGenerated, UserId, RequestMethod, RequestUri, 
    ResponseStatusCode, IPAddress, Scopes
| order by TimeGenerated desc
```

### Query 4: All Graph API AppIds — Discovery

```kql
// Discover all apps calling Graph APIs — find unknown MCP servers or AI agents
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| summarize 
    RequestCount = count(),
    DistinctUsers = dcount(UserId),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleEndpoints = make_set(tostring(split(RequestUri, "?")[0]), 3)
    by AppId
| order by RequestCount desc
```

### Query 5: Sentinel MCP — Authentication Events

```kql
// Who is authenticating to Sentinel MCP (via VS Code, Copilot Studio, browser)
SigninLogs
| where TimeGenerated >= ago(30d)
| where ResourceDisplayName =~ "Sentinel Platform Services"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    ResourceDisplayName, IPAddress, 
    tostring(Status.errorCode) as ErrorCode,
    ConditionalAccessStatus, AuthenticationRequirement, ClientAppUsed,
    tostring(parse_json(DeviceDetail).operatingSystem) as OS,
    tostring(parse_json(LocationDetails).countryOrRegion) as Country
| order by TimeGenerated desc
```

### Query 6: Sentinel MCP — Client App Breakdown

```kql
// Which client apps (VS Code, Copilot Studio, browser) are accessing Sentinel MCP
SigninLogs
| where TimeGenerated >= ago(30d)
| where ResourceDisplayName =~ "Sentinel Platform Services"
| summarize 
    SignInCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 10),
    LastSeen = max(TimeGenerated)
    by AppDisplayName, AppId, ClientAppUsed
| order by SignInCount desc
```

### Query 7: Graph Security API Surface Activity (Shared — includes but is not limited to Triage MCP)

```kql
// Measure Graph Security API endpoint activity from MicrosoftGraphActivityLogs.
// ATTRIBUTION LIMITATION: This query captures ALL consumers of these endpoints,
// not just Triage MCP. The same endpoints are called by Sentinel Engine, Security Copilot,
// SOAR platforms, ticketing integrations, custom scripts, and the Defender portal.
// Triage MCP's share cannot be isolated — it uses delegated auth and its registered
// AppId (6574a0f8) does NOT appear in any telemetry table.
//
// What this query DOES tell you:
//   - Whether the API surface that Triage MCP depends on is active
//   - Which client AppIds are calling security endpoints
//   - Volume/pattern heuristics to estimate interactive vs automated usage
//
// What this query DOES NOT tell you:
//   - How many calls specifically came through Triage MCP vs other consumers
//
// Field-tested Feb 2026: Confirmed shared-surface behavior across environments.
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where RequestUri has "/security/incidents" 
    or RequestUri has "/security/alerts" 
    or RequestUri has "/security/runHuntingQuery"
| extend Endpoint = extract(@"/v\d\.\d/(.+?)(\?|$)", 1, RequestUri)
| summarize 
    Calls = count(),
    DistinctUsers = dcount(UserId),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AppId, RequestMethod, Endpoint
| order by Calls desc
| take 25
```

### Query 7b: LAQueryLogs — Advanced Hunting Downstream Queries (Supplementary Signal)

```kql
// SUPPLEMENTARY detection: Advanced Hunting queries (from Triage MCP, Defender portal,
// Security Copilot, or any Graph Security API consumer calling RunAdvancedHuntingQuery)
// that hit connected Log Analytics workspace tables.
//
// 🔴 FIELD-TESTED Feb 2026 (two environments):
// Advanced Hunting downstream queries appear under TWO AppIds in LAQueryLogs:
//
//   1. fc780465 (Sentinel Engine) + RequestClientApp "M365D_AdvancedHunting"
//      - Carries the BULK of AH queries (~150x more volume)
//      - Full user attribution (AADEmail populated)
//      - Present in ALL environments tested
//
//   2. 6574a0f8 (Sentinel Triage MCP registered AppId)
//      - Environment-dependent: present in production, absent in lab
//      - NO user attribution (AADEmail = empty, RequestClientApp = empty)
//      - Appears to be a separate backend execution path
//      - When present, represents ~0.7% of total AH query volume
//
// This query checks BOTH AppIds to capture all AH downstream activity.
//
// This is a DOWNSTREAM signal — it only fires when RunAdvancedHuntingQuery targets
// Sentinel-connected LA tables (SigninLogs, AuditLogs, SecurityAlert, etc.).
// Queries hitting XDR-native tables (DeviceEvents, EmailEvents, etc.) stay in the
// Defender XDR backend and never appear here.
//
// Use alongside Query 7 (MicrosoftGraphActivityLogs) for complete Triage MCP coverage:
//   - Query 7 = PRIMARY: catches ALL API surface calls (ListIncidents, ListAlerts,
//     RunAdvancedHuntingQuery) via Graph Security API endpoints
//   - Query 7b = SUPPLEMENTARY: catches downstream query execution when AH hits LA tables
//
// ATTRIBUTION LIMITATION: Cannot distinguish Triage MCP AH queries from Defender portal
// AH queries or Security Copilot AH queries. fc780465 entries all show as
// M365D_AdvancedHunting; 6574a0f8 entries have no client app or user attribution.
LAQueryLogs
| where TimeGenerated >= ago(30d)
| where (AADClientId == "fc780465-2017-40d4-a0c5-307022471b92" and RequestClientApp == "M365D_AdvancedHunting")
    or AADClientId == "6574a0f8-d39b-4090-abbe-6c64ec9003f0"
| extend AppLabel = case(
    AADClientId == "fc780465-2017-40d4-a0c5-307022471b92", "AH Backend (fc780465)",
    AADClientId == "6574a0f8-d39b-4090-abbe-6c64ec9003f0", "Triage MCP Direct (6574a0f8)",
    "Unknown")
| summarize 
    QueryCount = count(),
    DistinctUsers = dcount(AADEmail),
    Users = make_set(AADEmail, 10),
    AvgCPUMs = avg(StatsCPUTimeMs),
    TotalRowsReturned = sum(ResponseRowCount),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AppLabel, AADClientId, RequestClientApp
| order by QueryCount desc
```

### Query 7c: LAQueryLogs — Portal & Platform Query Volume (Non-MCP Governance)

```kql
// Query volume for Portal/Platform AppIds in LAQueryLogs (governance context).
// NOTE: These are NOT MCP servers — included for workspace query governance baseline.
// 80ccca67 = M365 Security & Compliance Center (Sentinel Portal backend)
// 95a5d94c = Azure Portal AppInsightsPortalExtension (Usage dashboards)
let portal_appids = dynamic([
    "80ccca67-54bd-44ab-8625-4b79c4dc7775",  // M365 Security & Compliance Center (Sentinel Portal)
    "95a5d94c-a1a0-40eb-ac6d-48c5bdee96d5"   // Azure Portal — AppInsightsPortalExtension (Usage dashboards)
]);
LAQueryLogs
| where TimeGenerated >= ago(30d)
| where AADClientId in (portal_appids)
| extend Category = "Portal/Platform"
| summarize 
    QueryCount = count(),
    DistinctUsers = dcount(AADEmail),
    AvgCPUMs = avg(StatsCPUTimeMs),
    AvgRowsPerQuery = avg(ResponseRowCount),
    TotalRowsReturned = sum(ResponseRowCount),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AADClientId, Category
| order by QueryCount desc
```

### Query 8: Azure MCP — ARM Operations

```kql
// Azure ARM operations (may include Azure MCP Server — no dedicated AppId)
// Substitute <UPN> with the user's UPN
AzureActivity
| where TimeGenerated >= ago(30d)
| where Caller =~ '<UPN>'
| where CategoryValue == "Administrative"
| summarize
    OperationCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    ResourceProviders = make_set(ResourceProviderValue, 10)
    by bin(TimeGenerated, 1d), CallerIpAddress
| order by TimeGenerated desc
```

### Query 9: Azure MCP — Resource Provider Breakdown

```kql
// Azure resource types being accessed — detect unexpected resource access
// Substitute <UPN> with the user's UPN
AzureActivity
| where TimeGenerated >= ago(30d)
| where Caller =~ '<UPN>'
| where CategoryValue == "Administrative"
| summarize
    CallCount = count(),
    Operations = make_set(OperationNameValue, 5),
    DistinctResources = dcount(ResourceGroup)
    by ResourceProviderValue
| order by CallCount desc
```

### Query 10: All Workspace Query Sources — Complete Governance View

```kql
// Every client querying the workspace — MCP and non-MCP combined
LAQueryLogs
| where TimeGenerated >= ago(30d)
| summarize 
    QueryCount = count(),
    DistinctUsers = dcount(AADEmail),
    AvgCPUMs = avg(StatsCPUTimeMs),
    TotalRowsReturned = sum(ResponseRowCount)
    by AADClientId
| order by QueryCount desc
```

### Query 11: Graph MCP — Off-Hours Activity Detection

```kql
// Identify MCP calls outside business hours (08:00-18:00 UTC)
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated) / 1d
| extend IsOffHours = HourOfDay < 8 or HourOfDay >= 18 or DayOfWeek >= 5
| summarize
    TotalCalls = count(),
    OffHoursCalls = countif(IsOffHours),
    BusinessHoursCalls = countif(not(IsOffHours)),
    OffHoursUsers = make_set_if(UserId, IsOffHours, 10)
    by bin(TimeGenerated, 1d)
| extend OffHoursPct = round(100.0 * OffHoursCalls / TotalCalls, 1)
| order by TimeGenerated desc
```

### Query 12: Graph MCP — New User Detection (Baseline Comparison)

```kql
// Detect users who started using Graph MCP in the recent window but weren't in baseline
let baselineStart = ago(60d);
let baselineEnd = ago(7d);
let recentStart = ago(7d);
let baseline_users = MicrosoftGraphActivityLogs
| where TimeGenerated between (baselineStart .. baselineEnd)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| distinct UserId;
MicrosoftGraphActivityLogs
| where TimeGenerated >= recentStart
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| where UserId !in (baseline_users)
| summarize
    CallCount = count(),
    FirstSeen = min(TimeGenerated),
    Endpoints = make_set(tostring(split(RequestUri, "?")[0]), 10),
    IPs = make_set(IPAddress, 5)
    by UserId
| order by CallCount desc
```

### Query 13: Sentinel MCP — Query Content Audit

```kql
// Audit actual KQL queries executed by MCP servers and Portal/Platform apps (sample)
let mcp_server_appids = dynamic([
    "6574a0f8-d39b-4090-abbe-6c64ec9003f0"   // Sentinel Triage MCP (server)
]);
let portal_appids = dynamic([
    "80ccca67-54bd-44ab-8625-4b79c4dc7775",  // M365 Security & Compliance Center (Sentinel Portal)
    "95a5d94c-a1a0-40eb-ac6d-48c5bdee96d5"   // Azure Portal — AppInsightsPortalExtension (Usage dashboards)
]);
LAQueryLogs
| where TimeGenerated >= ago(7d)
| where AADClientId in (mcp_server_appids) or AADClientId in (portal_appids)
| extend Category = case(
    AADClientId in (mcp_server_appids), "MCP Server",
    "Portal/Platform")
| project TimeGenerated, AADEmail, AADClientId, Category,
    QueryTextTruncated = substring(QueryText, 0, 200),
    ResponseCode, ResponseRowCount, StatsCPUTimeMs
| order by TimeGenerated desc
| take 50
```

### Query 14: Unified MCP + Non-MCP Dashboard

```kql
// Combined MCP vs non-MCP view for workspace governance (Analytics tier)
let mcp_graph = MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| summarize Count = count() by Source = "Graph MCP", Category = "MCP", bin(TimeGenerated, 1d);
let mcp_triage = MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where RequestUri has "/security/incidents" or RequestUri has "/security/alerts" or RequestUri has "/security/runHuntingQuery"
| summarize Count = count() by Source = "Sentinel Triage MCP (Graph Security API)", Category = "MCP", bin(TimeGenerated, 1d);
let sentinel_portal = LAQueryLogs
| where TimeGenerated >= ago(30d)
| where AADClientId == "80ccca67-54bd-44ab-8625-4b79c4dc7775"
| summarize Count = count() by Source = "Sentinel Portal", Category = "Portal", bin(TimeGenerated, 1d);
let portal_appinsights = LAQueryLogs
| where TimeGenerated >= ago(30d)
| where AADClientId == "95a5d94c-a1a0-40eb-ac6d-48c5bdee96d5"
| summarize Count = count() by Source = "Azure Portal (AppInsightsPortalExtension)", Category = "Portal", bin(TimeGenerated, 1d);
let platform_logic_apps = LAQueryLogs
| where TimeGenerated >= ago(30d)
| where AADClientId == "de8c33bb-995b-4d4a-9d04-8d8af5d59601"
| summarize Count = count() by Source = "Logic Apps Connector", Category = "Platform", bin(TimeGenerated, 1d);
let platform_sentinel_engine = LAQueryLogs
| where TimeGenerated >= ago(30d)
| where AADClientId == "fc780465-2017-40d4-a0c5-307022471b92"
| summarize Count = count() by Source = "Sentinel Engine", Category = "Platform", bin(TimeGenerated, 1d);
union mcp_graph, mcp_triage, sentinel_portal, portal_appinsights, platform_logic_apps, platform_sentinel_engine
| summarize TotalQueries = sum(Count) by Source, Category, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

> **Note:** This query covers the **Analytics tier** (LAQueryLogs + MicrosoftGraphActivityLogs). For **Data Lake tier** query governance, combine with Query 24 results from `CloudAppEvents`.

### Query 15: Sentinel Audit — Configuration Changes

```kql
// Sentinel workspace configuration changes (analytics rules, connectors, etc.)
SentinelAudit
| where TimeGenerated >= ago(30d)
| summarize 
    ChangeCount = count(),
    OperationTypes = make_set(OperationName)
    by SentinelResourceType
| order by ChangeCount desc
```

### Query 16: Logic Apps — Non-MCP Query Monitoring

```kql
// Track automated queries from Logic Apps (standard connector, NOT MCP)
LAQueryLogs
| where TimeGenerated >= ago(30d)
| where AADClientId == "de8c33bb-995b-4d4a-9d04-8d8af5d59601"
| summarize
    QueryCount = count(),
    DistinctQueries = dcount(QueryText),
    AvgCPUMs = avg(StatsCPUTimeMs),
    TotalRows = sum(ResponseRowCount),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AADEmail, RequestClientApp
| order by QueryCount desc
```

### Query 17: Graph MCP — Caller Attribution (User vs SPN vs Agent)

```kql
// Attribute Graph MCP calls to User, Service Principal, or Agent Identity
// Key: UserId populated = delegated (user), ServicePrincipalId populated = app-only (SPN/Agent)
// ClientAuthMethod: 0 = public client (user), 1 = client secret (SPN), 2 = certificate (SPN)
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| extend CallerType = case(
    isnotempty(ServicePrincipalId) and isempty(UserId), "ServicePrincipal/Agent (App-Only)",
    isnotempty(UserId) and isnotempty(ServicePrincipalId), "Delegated (User+SPN/Agent OBO)",
    isnotempty(UserId) and isempty(ServicePrincipalId), "User (Delegated)",
    "Unknown")
| extend AuthMethod = case(
    ClientAuthMethod == 0, "Public Client",
    ClientAuthMethod == 1, "Client Secret",
    ClientAuthMethod == 2, "Client Certificate",
    "Unknown")
| summarize
    CallCount = count(),
    DistinctEndpoints = dcount(tostring(split(RequestUri, "?")[0])),
    SuccessRate = round(100.0 * countif(ResponseStatusCode >= 200 and ResponseStatusCode < 300) / count(), 1),
    SampleEndpoints = make_set(tostring(split(RequestUri, "?")[0]), 5),
    IPs = make_set(IPAddress, 5)
    by CallerType, AuthMethod, UserId, ServicePrincipalId
| order by CallCount desc
```

**Post-processing:** For any rows where `CallerType` = "ServicePrincipal/Agent (App-Only)", cross-reference the `ServicePrincipalId` with Entra via Graph API:

1. **Primary method (most reliable):** Query `/beta/servicePrincipals/{id}?$select=id,appId,displayName,servicePrincipalType,tags` — check `tags` array for agentic indicators:
   - `AgenticApp` — confirms this is an agent application
   - `AIAgentBuilder` — agent was created by an AI agent builder platform
   - `AgentCreatedBy:CopilotStudio` — specifically created by Copilot Studio
   - `AgenticInstance` — runtime instance of an agent
   - `power-virtual-agents-*` — Copilot Studio internal tracking tag
2. **Fallback:** Check `servicePrincipalType` — if it equals `"Agent"`, it is a registered Agent Identity. Note: as of Feb 2026, Copilot Studio agents still show `"Application"` here despite being true agents.
3. **Name-based filtering is UNRELIABLE** — SPNs with "Agent" in display name may be standard app registrations (e.g., "Agent 365 Tools" = `GitCreatedApp`).

Use `microsoft_graph_suggest_queries` → `microsoft_graph_get` for the Graph API calls. Query multiple SPNs in one call: `/beta/servicePrincipals?$count=true&$filter=id in ('id1','id2')&$select=id,appId,displayName,servicePrincipalType,tags`.

### Query 18: Agent Identity Sign-In Events

```kql
// Agent Identity sign-ins — look for Copilot Studio agent SPNs
// Field-tested: Copilot Studio agents sign in to "Bot Framework" from Azure internal IPv6 (fd00:34f2:*)
// Also check for Graph, Sentinel resources in case agents expand scope
// Cross-reference ServicePrincipalId values from Query 19 AuditLogs results
// Substitute <AGENT_SPN_IDS> with confirmed agent SPN IDs (or remove filter for broad discovery)
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(30d)
// Uncomment the next line if you have confirmed agent SPN IDs from Query 19 / Graph API:
// | where ServicePrincipalId in (<AGENT_SPN_IDS>)
| where ResourceDisplayName has_any ("Graph", "Sentinel", "Microsoft Graph", "Bot Framework")
| summarize
    SignInCount = count(),
    SuccessCount = countif(ResultType == "0" or ResultType == 0),
    FailCount = countif(ResultType != "0" and ResultType != 0),
    DistinctResources = dcount(ResourceDisplayName),
    Resources = make_set(ResourceDisplayName, 10),
    IPs = make_set(IPAddress, 5),
    Locations = make_set(Location, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ServicePrincipalName, ServicePrincipalId, AppId
| order by SignInCount desc
```

**Telemetry patterns for Copilot Studio agents (field-tested):**
- **Resource:** `Bot Framework` (NOT `Microsoft Graph` — agents talk to Bot Framework runtime)
- **IP addresses:** Azure internal IPv6 (`fd00:34f2:*`) — these are Azure infrastructure IPs, not user IPs
- **Sign-in volume:** Low (single-digit sign-ins typical for idle agents)
- **Correlation:** Match `ServicePrincipalId` here with `TargetId` from Query 19 AuditLogs to confirm the same agent

### Query 19: Agent Identity CRUD Operations in AuditLogs

```kql
// Track creation, modification, and deletion of Agent Identities
// These operations indicate agent lifecycle management in the tenant
// Key insight: Copilot Studio agents are created by "Power Virtual Agents Service"
// and have display names like "Agent (Microsoft Copilot Studio)" or "<Name> (Microsoft Copilot Studio)"
AuditLogs
| where TimeGenerated >= ago(30d)
| where OperationName has_any ("agent", "Agent")
    or Category == "AgentIdentity"
    or (OperationName has_any ("service principal") and (
        tostring(TargetResources) has "agent"
        or tostring(TargetResources) has "Copilot Studio"
        or tostring(InitiatedBy) has "Power Virtual Agents"
    ))
| project TimeGenerated, OperationName, Result,
    InitiatedBy = coalesce(
        tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName),
        tostring(parse_json(tostring(InitiatedBy)).app.displayName)),
    TargetName = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).displayName),
    TargetId = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).id),
    TargetType = tostring(parse_json(tostring(parse_json(tostring(TargetResources))[0])).type)
| extend IsAgenticSPN = iff(
    InitiatedBy == "Power Virtual Agents Service"
    or TargetName has "Copilot Studio"
    or TargetName has "AgenticApp", true, false)
| order by TimeGenerated desc
| take 50
```

**Interpreting results:**
- `InitiatedBy` = `Power Virtual Agents Service` → Copilot Studio created/modified this agent SPN automatically
- `InitiatedBy` = `user@domain.com` → Human manually created/modified this SPN (may or may not be an agent)
- `OperationName` = `Hard delete service principal` shortly after `Add service principal` → Testing/experimentation pattern
- Multiple operations (`Add SPN` → `Add owner` → `Update SPN`) within seconds → Copilot Studio automated provisioning sequence

### Query 20: Data Lake MCP — Tool Usage Summary

```kql
// Sentinel Data Lake MCP tool usage from CloudAppEvents (Purview unified audit)
// RecordType 403 = Sentinel AI Tool activities (MCP), RecordType 379 = KQL activities (direct)
// IMPORTANT: Use 'contains' (not 'has') for ActionType — CamelCase values have no word boundaries
CloudAppEvents
| where TimeGenerated >= ago(30d)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| extend 
    Operation = tostring(RawData.Operation),
    RecordType = toint(RawData.RecordType),
    ToolName = tostring(RawData.ToolName),
    Interface = tostring(RawData.Interface),
    ExecutionDuration = todouble(RawData.ExecutionDuration),
    FailureReason = tostring(RawData.FailureReason),
    TablesRead = tostring(RawData.TablesRead),
    DatabasesRead = tostring(RawData.DatabasesRead),
    TotalRows = toint(RawData.TotalRows),
    UserId_raw = tostring(RawData.UserId)
| extend 
    AccessPattern = case(
        RecordType == 403 and Interface == "IMcpToolTemplate", "MCP Server-Driven",
        RecordType == 379, "Direct KQL",
        "Other"),
    IsSuccess = isempty(FailureReason) or FailureReason == ""
| where Operation contains "Completed" or RecordType == 379  // Focus on completed events; use 'contains' not 'has' — CamelCase has no word boundaries
| summarize
    TotalCalls = count(),
    SuccessCount = countif(IsSuccess),
    FailureCount = countif(not(IsSuccess)),
    DistinctTools = dcount(ToolName),
    DistinctTables = dcount(TablesRead),
    AvgDurationSec = round(avg(ExecutionDuration), 2),
    TotalRowsReturned = sum(TotalRows),
    DistinctUsers = dcount(UserId_raw),
    Users = make_set(UserId_raw, 10)
    by AccessPattern
| extend ErrorRate = round(100.0 * FailureCount / TotalCalls, 1)
| order by TotalCalls desc
```

### Query 21: Data Lake MCP — Tool Breakdown

```kql
// Breakdown of individual MCP tool usage from CloudAppEvents
// Shows which Data Lake MCP tools are being called most frequently
CloudAppEvents
| where TimeGenerated >= ago(30d)
| where ActionType contains "SentinelAITool"
| extend RawData = parse_json(tostring(RawEventData))
| extend 
    Operation = tostring(RawData.Operation),
    ToolName = tostring(RawData.ToolName),
    ExecutionDuration = todouble(RawData.ExecutionDuration),
    FailureReason = tostring(RawData.FailureReason),
    TablesRead = tostring(RawData.TablesRead)
| where Operation == "SentinelAIToolRunCompleted"  // Only count completions to avoid double-counting
| extend IsSuccess = isempty(FailureReason) or FailureReason == ""
| summarize
    CallCount = count(),
    SuccessCount = countif(IsSuccess),
    FailureCount = countif(not(IsSuccess)),
    AvgDurationSec = round(avg(ExecutionDuration), 2),
    MaxDurationSec = round(max(ExecutionDuration), 2),
    TablesAccessed = make_set(TablesRead, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ToolName
| extend ErrorRate = round(100.0 * FailureCount / CallCount, 1)
| order by CallCount desc
```

### Query 22: Data Lake MCP — Error Analysis

```kql
// Analyze failed Data Lake MCP tool calls — identify schema errors, permission issues, etc.
CloudAppEvents
| where TimeGenerated >= ago(30d)
| where ActionType contains "SentinelAITool"
| extend RawData = parse_json(tostring(RawEventData))
| extend 
    Operation = tostring(RawData.Operation),
    ToolName = tostring(RawData.ToolName),
    FailureReason = tostring(RawData.FailureReason),
    TablesRead = tostring(RawData.TablesRead),
    UserId_raw = tostring(RawData.UserId)
| where Operation == "SentinelAIToolRunCompleted"
| where isnotempty(FailureReason) and FailureReason != ""
| extend ErrorCategory = case(
    FailureReason has "SemanticError", "Schema/Semantic Error",
    FailureReason has "SyntaxError", "KQL Syntax Error",
    FailureReason has "Unauthorized" or FailureReason has "403", "Permission Denied",
    FailureReason has "Timeout", "Query Timeout",
    FailureReason has "NotFound", "Table/Resource Not Found",
    "Other Error")
| summarize
    ErrorCount = count(),
    Tools = make_set(ToolName, 10),
    Tables = make_set(TablesRead, 10),
    Users = make_set(UserId_raw, 10),
    SampleErrors = make_set(substring(FailureReason, 0, 150), 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ErrorCategory
| order by ErrorCount desc
```

### Query 23: Data Lake MCP — Daily Activity Trend

```kql
// Daily activity trend for Data Lake MCP tools and Direct KQL
// Use this for volume anomaly detection and trend analysis
CloudAppEvents
| where TimeGenerated >= ago(30d)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| extend 
    Operation = tostring(RawData.Operation),
    RecordType = toint(RawData.RecordType),
    Interface = tostring(RawData.Interface),
    FailureReason = tostring(RawData.FailureReason)
| extend 
    AccessPattern = case(
        RecordType == 403 and Interface == "IMcpToolTemplate", "MCP Server-Driven",
        RecordType == 379, "Direct KQL",
        "Other"),
    IsSuccess = isempty(FailureReason) or FailureReason == ""
| where Operation contains "Completed" or RecordType == 379  // 'contains' not 'has' — CamelCase
| summarize
    Calls = count(),
    SuccessCount = countif(IsSuccess),
    FailureCount = countif(not(IsSuccess))
    by AccessPattern, bin(TimeGenerated, 1d)
| extend ErrorRate = round(100.0 * FailureCount / Calls, 1)
| order by TimeGenerated desc, AccessPattern asc
```

### Query 24: MCP vs Direct KQL — Access Pattern Delineation

```kql
// Comprehensive delineation of MCP-driven vs Direct KQL access to Sentinel Data Lake
// Combines RecordType, Interface, and Operation to classify every Data Lake interaction
// This is the key governance query for understanding WHO is querying the Data Lake and HOW
CloudAppEvents
| where TimeGenerated >= ago(30d)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| extend 
    Operation = tostring(RawData.Operation),
    RecordType = toint(RawData.RecordType),
    ToolName = tostring(RawData.ToolName),
    Interface = tostring(RawData.Interface),
    ExecutionDuration = todouble(RawData.ExecutionDuration),
    FailureReason = tostring(RawData.FailureReason),
    TablesRead = tostring(RawData.TablesRead),
    DatabasesRead = tostring(RawData.DatabasesRead),
    TotalRows = toint(RawData.TotalRows),
    UserId_raw = tostring(RawData.UserId),
    InputParams = tostring(RawData.InputParameters)
| extend 
    AccessPattern = case(
        RecordType == 403 and Interface == "IMcpToolTemplate", "MCP Server-Driven",
        RecordType == 379, "Direct KQL",
        "Other"),
    IsSuccess = isempty(FailureReason) or FailureReason == "",
    HasKQLQuery = InputParams has "query"
| where Operation contains "Completed" or RecordType == 379  // 'contains' not 'has' — CamelCase
| summarize
    TotalCalls = count(),
    SuccessCount = countif(IsSuccess),
    FailureCount = countif(not(IsSuccess)),
    DistinctTools = dcount(ToolName),
    Tools = make_set(ToolName, 20),
    DistinctTables = dcount(TablesRead),
    Tables = make_set(TablesRead, 30),
    Workspaces = make_set(DatabasesRead, 5),
    AvgDurationSec = round(avg(ExecutionDuration), 2),
    TotalRowsReturned = sum(TotalRows),
    DistinctUsers = dcount(UserId_raw),
    Users = make_set(UserId_raw, 10),
    KQLQueryCount = countif(HasKQLQuery),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AccessPattern
| extend ErrorRate = round(100.0 * FailureCount / TotalCalls, 1)
| order by TotalCalls desc
```

**Post-processing for Query 24:**
- **MCP Server-Driven** rows represent tool calls via the Sentinel Data Lake MCP (GitHub Copilot → MCP Server → Data Lake)
- **Direct KQL** rows represent queries executed via Sentinel Graph / Data Lake Explorer (human or service principal → KQL query → Data Lake)
- Combine this with Query 14 (Analytics tier) for a **complete two-tier governance view**:

| Tier | Data Source | MCP Sources | Non-MCP Sources |
|------|------------|-------------|-----------------|
| **Analytics Tier** | `LAQueryLogs` | AH backend `fc780465` / `M365D_AdvancedHunting` + Triage MCP direct `6574a0f8` *(supplementary — captures AH queries from Triage MCP, Defender portal, Security Copilot that hit connected LA tables; dual-AppId, see Query 7b)* | Sentinel Portal (`80ccca67`), Sentinel Engine analytics (`fc780465`, non-AH), Logic Apps (`de8c33bb`) |
| **Data Lake Tier** | `CloudAppEvents` | Data Lake MCP (RecordType 403, `IMcpToolTemplate`) | Direct KQL (RecordType 379, `KqsService`) |
| **Graph API** | `MicrosoftGraphActivityLogs` | Graph MCP (`e8c77dc2`) | — |
| **Azure MCP** | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | Azure MCP Server (`1950a258` + UA `azsdk-net-Identity`) | Azure PowerShell (same AppId, different UA) |

### Query 25: Azure MCP Server — Authentication Events (SigninLogs)

```kql
// Detect Azure MCP Server authentication events by FULL composite signal:
// AppId 1950a258 (shared with Azure PowerShell) + UserAgent 'azsdk-net-Identity' + OS 'Microsoft Windows'
//
// 🔴 CRITICAL: 'azsdk-net-Identity' alone is NOT sufficient! This UserAgent prefix is shared by:
//   - Azure MCP Server (local, .NET 9.x, Microsoft Windows)
//   - Security Copilot API (AppId bb3d68c2, .NET 8.x, CBL-Mariner/Linux)
//   - Other Azure SDK services running on various platforms
// The 'Microsoft Windows' OS filter isolates local Azure MCP Server from cloud-hosted services.
//
// NOTE: Sign-in events represent TOKEN ACQUISITIONS, not individual API calls.
// A cached token (~1hr) serves many Azure MCP calls with no additional sign-in events.
// FIX (Feb 2026): Explicit tostring() casts on ResultType, ResultDescription,
// ConditionalAccessStatus, AuthenticationRequirement to prevent union type mismatches
// between SigninLogs and AADNonInteractiveUserSignInLogs. Removed ResourceId (inconsistent
// across tables). Use parse_json() wrapper on DeviceDetail and LocationDetails — these
// columns may be stored as string (not dynamic) in Data Lake workspaces, causing
// SemanticError on dot-notation access without parse_json().
let azure_mcp_appid = "1950a258-227b-4e31-a9cf-717495945fc2";
let signinlogs_interactive = SigninLogs
| where TimeGenerated >= ago(90d)
| where AppId == azure_mcp_appid
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| extend SignInType = "Interactive"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    ResourceDisplayName, IPAddress, 
    ResultType = tostring(ResultType),
    ResultDescription = tostring(ResultDescription),
    UserAgent, SignInType,
    ConditionalAccessStatus = tostring(ConditionalAccessStatus),
    AuthenticationRequirement = tostring(AuthenticationRequirement),
    OS = tostring(parse_json(DeviceDetail).operatingSystem),
    Country = tostring(parse_json(LocationDetails).countryOrRegion);
let signinlogs_noninteractive = AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| where AppId == azure_mcp_appid
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| extend SignInType = "Non-Interactive"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    ResourceDisplayName, IPAddress,
    ResultType = tostring(ResultType),
    ResultDescription = tostring(ResultDescription),
    UserAgent, SignInType,
    ConditionalAccessStatus = tostring(ConditionalAccessStatus),
    AuthenticationRequirement = tostring(AuthenticationRequirement),
    OS = tostring(parse_json(DeviceDetail).operatingSystem),
    Country = tostring(parse_json(LocationDetails).countryOrRegion);
union signinlogs_interactive, signinlogs_noninteractive
| order by TimeGenerated desc
```

### Query 26: Azure MCP Server — Workspace Queries (LAQueryLogs)

```kql
// Detect Azure MCP Server workspace queries via LAQueryLogs
// Azure MCP Server uses RequestClientApp = 'csharpsdk,LogAnalyticsPSClient'
// while Azure PowerShell uses 'PSClient,LogAnalyticsPSClient'
// FIX (Feb 2026): Removed StatsDataProcessedKB — column does not exist in LAQueryLogs.
// Use StatsCPUTimeMs and ResponseRowCount for performance context.
let azure_mcp_appid = "1950a258-227b-4e31-a9cf-717495945fc2";
LAQueryLogs
| where TimeGenerated >= ago(90d)
| where AADClientId == azure_mcp_appid
| where RequestClientApp has "csharpsdk"  // Distinguishes from PowerShell's 'PSClient'
| project TimeGenerated, AADEmail, AADClientId,
    RequestClientApp,
    QueryTextTruncated = substring(QueryText, 0, 300),
    ResponseCode, ResponseRowCount,
    StatsCPUTimeMs,
    RequestTarget
| order by TimeGenerated desc
```

### Query 27: Azure MCP Server — AzureActivity Claims Correlation

```kql
// Check AzureActivity for Azure MCP Server write operations (read ops not logged)
// Parse Claims.appid to identify the source application
AzureActivity
| where TimeGenerated >= ago(90d)
| where CategoryValue == "Administrative"
| extend ClaimsData = parse_json(Claims)
| extend ClaimsAppId = tostring(ClaimsData.appid)
| where ClaimsAppId == "1950a258-227b-4e31-a9cf-717495945fc2"
| project TimeGenerated, Caller, CallerIpAddress,
    OperationNameValue, ResourceProviderValue,
    ActivityStatusValue, ClaimsAppId,
    ResourceGroup, _ResourceId
| order by TimeGenerated desc
```

---

## Report Template

### Inline Chat Report Structure

The inline report MUST include these sections in order:

1. **Header** — Workspace, analysis period, data sources checked, MCP servers detected
2. **Executive Summary** — 2-3 sentence overview of MCP usage posture
3. **Graph MCP Server Analysis**
   - Daily usage trend (ASCII bar chart showing requests/day over the period)
   - Top endpoints table (endpoint, call count, % of total, last used)
   - Sensitive API access summary with user attribution
4. **Sentinel Triage MCP Analysis**
   - Authentication events by client app (Sentinel Platform Services sign-ins)
   - Graph Security API surface activity from `MicrosoftGraphActivityLogs` — shared endpoint usage (incidents, alerts, hunting queries by AppId)
   - ⚠️ Attribution limitation note: calls cannot be isolated to Triage MCP vs other consumers
   - User attribution table with source category estimates
5. **Sentinel Data Lake MCP Analysis**
   - MCP tool usage summary (success/failure, avg duration)
   - Tool breakdown table (query_lake, list_sentinel_workspaces, search_tables, etc.)
   - Error analysis with error categories and sample failure reasons
   - Daily activity trend (ASCII bar chart)
   - MCP vs Direct KQL delineation table
6. **Azure MCP & ARM Analysis**
   - Azure MCP Server authentication events (detected via AppId `1950a258` + UserAgent `azsdk-net-Identity`)
   - Azure MCP Server workspace queries from LAQueryLogs (detected via `csharpsdk,LogAnalyticsPSClient`)
   - ARM operation volume and resource providers accessed
   - Source attribution via Claims.appid (Azure Portal, AI Studio, Power Platform connectors, etc.)
7. **Workspace Query Governance (Two-Tier)**
   - **Analytics Tier** (LAQueryLogs): All query sources table with MCP vs Portal vs Platform breakdown
   - **Data Lake Tier** (CloudAppEvents): MCP-driven vs Direct KQL breakdown
   - Combined MCP proportion across both tiers
   - Pareto analysis of query sources
8. **MCP Usage Score** — Per-dimension breakdown with scoring rationale
9. **Security Assessment** — Emoji-coded findings table with evidence citations
10. **Recommendations** — Prioritized action items based on findings

### Report Visualization Patterns

#### Daily Usage Trend (ASCII)
```
Graph MCP Usage — Last 30 Days
Day         Calls  Trend
─────────────────────────────────────
2026-02-07  │ 23   ████████████
2026-02-06  │  0   
2026-02-05  │ 45   ██████████████████████
2026-02-04  │ 12   ██████
...
─────────────────────────────────────
Avg: 15.2/day  Peak: 45  Total: 152
```

#### Workspace Query Proportion (ASCII)
```
Analytics Tier Query Sources — Last 30d (LAQueryLogs)
──────────────────────────────────────────
Sentinel Engine    ████████████████████████████████████ 88.4%  (10,354)
Logic Apps         ████                                  7.0%     (821)
Triage MCP (Graph)  █                                    4.1%     (481)
Sentinel Portal                                          0.4%      (48)
──────────────────────────────────────────
MCP Servers: 4.1% │ Portal: 0.4% │ Platform: 95.4%

Data Lake Tier Query Sources — Last 30d (CloudAppEvents)
──────────────────────────────────────────
Data Lake MCP      ████████████████████████████████████ 97.1%  (1,028)
Direct KQL                                               2.9%      (34)
──────────────────────────────────────────
MCP Server-Driven: 97.1% │ Direct KQL: 2.9%
```

#### Endpoint Access Distribution (ASCII)
```
Top Graph MCP Endpoints — 30d
─────────────────────────────────────────────────────
conditionalAccess/policies    ████████████  27  (17.8%)
users                         ██████████    22  (14.5%)
roleManagement/directory      ████████      18  (11.8%)
servicePrincipals             ██████        14   (9.2%)
groups                        █████         11   (7.2%)
...
─────────────────────────────────────────────────────
🔴 Sensitive: 82/152 (53.9%)  │  ✅ Standard: 70/152 (46.1%)
```

#### MCP Usage Score Card (ASCII)
```
┌──────────────────────────────────────────────────────┐
│               MCP USAGE SCORE: 22/100                │
│                 Rating: ✅ HEALTHY                    │
├──────────────────────────────────────────────────────┤
│ User Diversity     [██░░░░░░░░] 3/20  (1-2 users)   │
│ Endpoint Sensitiv  [████████░░] 14/20 (54% sensitive)│
│ Error Rate         [░░░░░░░░░░] 0/20  (<1% errors)  │
│ Volume Anomaly     [██░░░░░░░░] 3/20  (within norm)  │
│ Off-Hours Activity [█░░░░░░░░░] 2/20  (<5% off-hrs)  │
└──────────────────────────────────────────────────────┘
```

### Markdown File Report Structure

When outputting to markdown file, include everything from the inline format PLUS:

```markdown
# MCP Server Usage Monitoring Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Workspace:** <workspace_name>
**Analysis Period:** <start> → <end> (<N> days)
**Data Sources:** MicrosoftGraphActivityLogs, SigninLogs, LAQueryLogs, CloudAppEvents, AzureActivity, SentinelAudit

---

## Executive Summary

<2-3 sentence summary: MCP servers detected, total usage volume, risk level, key findings>

---

## Graph MCP Server

### Daily Usage Trend
<ASCII bar chart — requests per day>

### Top Endpoints
| Rank | Endpoint | Calls | % Total | Users | Last Used |
|------|----------|-------|---------|-------|-----------|
| 1 | ... | ... | ... | ... | ... |

### Sensitive API Access
| Endpoint | Calls | Users | Methods | Risk |
|----------|-------|-------|---------|------|
| roleManagement/... | 18 | 1 | GET | 🟠 Read access to PIM |
| ... | ... | ... | ... | ... |

**Summary:** X of Y calls (Z%) targeted sensitive endpoints. <Risk assessment>.

---

## Sentinel Triage MCP

### Authentication Events by Client (Sentinel Platform Services)
| Client App | AppId | Sign-Ins | Users | Last Seen |
|------------|-------|----------|-------|-----------|
| ... | ... | ... | ... | ... |

### Graph Security API Surface Activity (MicrosoftGraphActivityLogs)

> ⚠️ **Attribution limitation:** These calls represent ALL consumers of Graph Security API endpoints — not exclusively Triage MCP. Sentinel Engine, Security Copilot, SOAR platforms, and other integrations share the same endpoints. Triage MCP's specific share cannot be isolated.

| AppId | Endpoint | Method | Calls | Users | Source Estimate | First Seen | Last Seen |
|-------|----------|--------|-------|-------|-----------------|------------|-----------|
| ... | ... | ... | ... | ... | ... | ... |

---

## Sentinel Data Lake MCP

> **Audit Source:** `CloudAppEvents` (Purview unified audit log)  
> **Classification:** RecordType 403 + Interface `IMcpToolTemplate` = MCP-driven | RecordType 379 = Direct KQL

### MCP vs Direct KQL Delineation
| Access Pattern | Total Calls | Success | Failures | Error Rate | Avg Duration | Users |
|---------------|-------------|---------|----------|------------|-------------|-------|
| 🤖 MCP Server-Driven | ... | ... | ... | ...% | ...s | ... |
| 👤 Direct KQL | ... | ... | ... | ...% | ...s | ... |

### MCP Tool Breakdown
| Tool Name | Calls | Success | Failures | Error Rate | Avg Duration | Last Seen |
|-----------|-------|---------|----------|------------|-------------|-----------|
| `query_lake` | ... | ... | ... | ...% | ...s | ... |
| `list_sentinel_workspaces` | ... | ... | ... | ...% | ...s | ... |
| `search_tables` | ... | ... | ... | ...% | ...s | ... |
| ... | ... | ... | ... | ... | ... | ... |

### Error Analysis
| Error Category | Count | % of Failures | Sample Error | Affected Tools |
|---------------|-------|---------------|--------------|----------------|
| Schema/Semantic Error | ... | ...% | `column 'X' does not exist` | ... |
| ... | ... | ... | ... | ... |

### Daily Activity Trend
<ASCII bar chart — MCP + Direct KQL calls per day>

---

## Azure MCP Server

> **Detection Method:** Composite signal analysis — AppId `1950a258` + UserAgent `azsdk-net-Identity (.NET 9.x)` in SigninLogs + `csharpsdk,LogAnalyticsPSClient` in LAQueryLogs.

### Authentication Timeline
| Timestamp | Resource | Result | Auth Type | UserAgent | Notes |
|-----------|----------|--------|-----------|-----------|-------|\n| ... | ... | ... | ... | ... | ... |

### Workspace Queries (LAQueryLogs)
| Timestamp | Query (truncated) | Response | CPU (ms) | Source App |
|-----------|-------------------|----------|----------|------------|\n| ... | ... | ... | ... | ... |

### AzureActivity Write Operations
| Timestamp | Operation | Resource Provider | Status | Claims.appid |
|-----------|-----------|-------------------|--------|-------------|\n| ... | ... | ... | ... | `1950a258` |

---

## Azure ARM Operations (All Sources)

> **Source Attribution:** ARM operations attributed via `Claims.appid` in AzureActivity.\n> Azure MCP Server read-only operations NOT logged in AzureActivity.

### ARM Source Attribution
| AppId | App Name | Calls | Operations |
|-------|----------|-------|------------|
| ... | ... | ... | ... |

### Operations by Resource Provider
| Resource Provider | Calls | Top Operations | Distinct Resources |
|-------------------|-------|----------------|-------------------|
| ... | ... | ... | ... |

---

## Workspace Query Governance (Two-Tier)

### Analytics Tier (LAQueryLogs)
| Rank | AppId | Source | Category | Queries | % Total | Users |
|------|-------|--------|----------|---------|---------|-------|
| 1 | ... | Sentinel Engine | Platform | ... | ... | ... |
| 2 | ... | Sentinel Triage MCP | MCP Server | ... | ... | ... |
| 3 | ... | Sentinel Portal | Portal | ... | ... | ... |
| ... | ... | ... | ... | ... | ... | ... |

### Data Lake Tier (CloudAppEvents)
| Access Pattern | Calls | % Total | Users | Tables Accessed |
|---------------|-------|---------|-------|-----------------|
| 🤖 MCP Server-Driven | ... | ...% | ... | ... |
| 👤 Direct KQL | ... | ...% | ... | ... |

### Combined MCP Proportion
<ASCII proportion bar — Analytics + Data Lake tiers combined>

MCP queries represent X% of combined query volume:
- Analytics tier: X of Y queries via Sentinel Triage MCP (Z%)
- Data Lake tier: X of Y queries via Data Lake MCP (Z%)
- Graph API: X calls via Graph MCP

---

## Agent Identity Attribution

### Caller Type Breakdown (Graph MCP)
| Caller Type | Distinct Callers | Total Calls | % of Graph MCP |
|-------------|-----------------|-------------|----------------|
| 👤 Human User | ... | ... | ...% |
| 🤖 Service Principal | ... | ... | ...% |
| 🤖🔵 Agent Identity (SPN subtype) | ... | ... | ...% |
| 👤🔵 Agent User | ... | ... | ...% |

### Agent Identity Inventory (from AuditLogs + Graph API `/beta` tags)
| Agent Name | SPN ID | AppId | Tags | Created By | Created | Status | Sign-In Resource |
|------------|--------|-------|------|-----------|---------|--------|------------------|
| ... | ... | ... | `AgenticApp`, `AgentCreatedBy:CopilotStudio` | Power Virtual Agents Service | YYYY-MM-DD | Active/Deleted | Bot Framework |

### Agent Lifecycle Timeline
```
<Date> <Time>  ── <Agent Name> ── <Operation> (by <InitiatedBy>)
                   └── <Context notes>
```

> **Detection Method (Field-Tested):**
> 1. `AuditLogs` → filter for `OperationName has "agent"` or `InitiatedBy = "Power Virtual Agents Service"` or `TargetResources has "Copilot Studio"`
> 2. Graph API → `GET /beta/servicePrincipals?$filter=id in (...)&$select=id,appId,displayName,servicePrincipalType,tags`
> 3. **Primary classifier:** `/beta` `tags` array — look for `AgenticApp`, `AIAgentBuilder`, `AgentCreatedBy:CopilotStudio`
> 4. **DO NOT** rely on `servicePrincipalType` (still shows `"Application"` for agents) or display name (unreliable)
> 5. If no Agent Identities exist in tenant: "✅ No Entra Agent Identities detected in this tenant."

---

## MCP Usage Score

<ASCII score card>

### Dimension Breakdown
| Dimension | Score | Evidence |
|-----------|-------|----------|
| User Diversity | X/20 | N distinct users across M MCP channels |
| Endpoint Sensitivity | X/20 | N% of Graph MCP calls to sensitive endpoints |
| Error Rate | X/20 | N% error rate across all channels |
| Volume Anomaly | X/20 | Peak day was N% of rolling average |
| Off-Hours Activity | X/20 | N% of calls outside 08:00-18:00 UTC |

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| 🔴/🟢/🟡/🟠 **Factor** | Evidence-based finding |

---

## Recommendations

1. ⚠️/🟢 <Prioritized action item with evidence>
2. ...

---

## Appendix: Query Details

Render a single markdown table summarizing all queries executed. **Do NOT include full KQL text** — the canonical queries are already documented in this SKILL.md file. The appendix serves as an audit trail only.

| Query | Table(s) | Records Scanned | Results | Execution |
|-------|----------|----------------:|--------:|----------:|
| Q1 — Graph MCP Daily Usage | MicrosoftGraphActivityLogs | X,XXX | N rows | X.XXs |
| Q2 — Top Graph Endpoints | MicrosoftGraphActivityLogs | X,XXX | N rows | X.XXs |
| ... | ... | ... | ... | ... |

*Query definitions: see the Sample KQL Queries section in this SKILL.md file.*
```

---

## Proactive Alerting — KQL Data Lake Jobs

This skill provides **on-demand visibility** (Phases 1-7 above). For **continuous, scheduled anomaly detection** that feeds Sentinel analytics rules, use the companion KQL Data Lake Jobs defined in:

📄 **`queries/identity/mcp_anomaly_detection_kql_jobs.md`**

### Maturity Model

| Tier | Capability | Implementation |
|------|-----------|----------------|
| **1. Visibility** (current skill) | On-demand MCP usage reports via Copilot chat | This SKILL.md — Phases 1-7, Queries 1-27 |
| **2. Baselining** | 14-day behavioral baselines per user per MCP server | KQL Jobs 1-8 build baselines automatically |
| **3. Alerting** | Automated anomaly detection → Sentinel incidents | KQL Jobs promote to `_KQL_CL` tables → Analytics Rules fire |
| **4. Enforcement** | Real-time guardrails, scope limits (future) | Not yet available — requires MCP protocol-level controls |

### KQL Job Inventory

| Job | Anomaly Type | Source Table(s) | Destination Table | Schedule |
|-----|-------------|-----------------|-------------------|----------|
| **1** | New sensitive Graph endpoint | `MicrosoftGraphActivityLogs` | `MCPGraphAnomalies_KQL_CL` | Daily |
| **2** | Graph MCP volume spike (3x baseline) | `MicrosoftGraphActivityLogs` | `MCPGraphAnomalies_KQL_CL` | Daily |
| **3** | Off-hours Graph MCP activity | `MicrosoftGraphActivityLogs` | `MCPGraphAnomalies_KQL_CL` | Daily |
| **4** | Graph MCP error rate anomaly | `MicrosoftGraphActivityLogs` | `MCPGraphAnomalies_KQL_CL` | Daily |
| **5** | New Azure MCP Server user | `AADNonInteractiveUserSignInLogs` | `MCPAzureAnomalies_KQL_CL` | Daily |
| **6** | New Azure MCP resource target | `AADNonInteractiveUserSignInLogs` | `MCPAzureAnomalies_KQL_CL` | Daily |
| **7** | Sentinel workspace query anomalies | `LAQueryLogs` | `MCPSentinelAnomalies_KQL_CL` | Daily |
| **8** | Cross-MCP activity chains | Multiple (join) | `MCPCrossMCPCorrelation_KQL_CL` | Daily |

### Why KQL Jobs (Not Summary Rules)

KQL jobs support **multi-table joins** — critical for Job 7 (LAQueryLogs + baseline) and Job 8 (Graph + Azure + Sentinel cross-correlation). Summary rules are limited to single-table with `lookup()` joins to analytics-tier tables only.

### Architecture

```
Data Lake ──[KQL Jobs (daily)]──► _KQL_CL tables (analytics tier) ──[Analytics Rules]──► Incidents
```

Key design constraints:
- **15-minute delay**: All queries use `now() - 15m` to account for Data Lake ingestion latency
- **Anomaly-only promotion**: Only flagged records are written to analytics tier (cost optimization)
- **Separate timestamp**: `DetectedTime` preserves original event time; `TimeGenerated` reflects job execution time
- **3 concurrent job limit**: Per tenant — prioritize Jobs 1, 7, 8 for highest-value detections

For full query definitions, deployment checklist, and companion analytics rule templates, see `queries/identity/mcp_anomaly_detection_kql_jobs.md`.

---

## Known Pitfalls

### Agent Identity vs Standard SPN Ambiguity
**Problem:** `MicrosoftGraphActivityLogs` does NOT yet distinguish Agent Identities from standard SPNs. Both appear in the `ServicePrincipalId` field with no subtype indicator. Agent Users appear in `UserId` indistinguishably from human users. Additionally, `servicePrincipalType` still returns `"Application"` even for confirmed Copilot Studio agents — the `"Agent"` subtype is not yet populated (as of Feb 2026). This is a [documented known limitation](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/preview-known-issues#monitoring-and-logs) of the Entra Agent ID preview.  
**Solution (Field-Tested):** Use the **`/beta` `tags` property** as the primary detection method. Query: `GET /beta/servicePrincipals/{id}?$select=id,appId,displayName,servicePrincipalType,tags`. Confirmed Copilot Studio agents will have tags including `AgenticApp`, `AIAgentBuilder`, `AgentCreatedBy:CopilotStudio`, and `AgenticInstance`. Standard app registrations (even those with "Agent" in the display name) will NOT have these tags — they may have tags like `GitCreatedApp` or `disableLegacyUserImpersonation*` instead. For `UserId` values, check against the tenant's agent user inventory. If no Agent Identities exist in the tenant, note this and skip agent-specific analysis.

### Agent Display Name Unreliable for Classification
**Problem:** An SPN with "Agent" in its display name is NOT necessarily an Agent Identity. Example from live testing: "Agent 365 Tools" is a standard app registration (`servicePrincipalType: Application`, tags: `GitCreatedApp`) — NOT a Copilot Studio agent despite the name. Conversely, a generic name like "Agent (Microsoft Copilot Studio)" IS a real agent.  
**Solution:** NEVER classify SPNs as agents based on display name alone. Always check the `/beta` `tags` array for agentic indicators (`AgenticApp`, `AgentCreatedBy:CopilotStudio`). In AuditLogs, check `InitiatedBy` — agents created by `Power Virtual Agents Service` are Copilot Studio agents, while those created by a `user@domain.com` are manual app registrations.

### Azure MCP Server Detection (Updated Feb 2026)
**Problem:** Azure MCP Server uses `DefaultAzureCredential` and shares AppId `1950a258-227b-4e31-a9cf-717495945fc2` with Azure PowerShell. Additionally, the `azsdk-net-Identity` UserAgent prefix is shared with OTHER Azure SDK services (e.g., Security Copilot API `bb3d68c2`). ARM read operations (the majority of MCP calls) do not appear in `AzureActivity`.  
**Solution (Field-Tested):** Azure MCP Server IS detectable through composite signal analysis. The FULL composite signal is required — no single field is sufficient:

| Signal Source | Detection Fields | Azure MCP Server Fingerprint | False Positives to Exclude |
|---------------|-----------------|------------------------------|---------------------------|
| **SigninLogs / AADNonInteractiveUserSignInLogs** | AppId + UserAgent (incl. OS) | AppId `1950a258` + UA `azsdk-net-Identity` + OS `Microsoft Windows` | Security Copilot API (`bb3d68c2`, OS `CBL-Mariner/Linux`), other cloud-hosted Azure SDK services |
| **LAQueryLogs** | AADClientId + RequestClientApp | `1950a258` + `csharpsdk,LogAnalyticsPSClient` | Azure PowerShell uses `PSClient,LogAnalyticsPSClient` |
| **AzureActivity** | Claims.appid | `1950a258` (write operations only — reads not logged) | Azure PowerShell write ops share same Claims.appid |

**Key disambiguation:** Three entities share the `azsdk-net-Identity` UserAgent pattern:
1. **Azure MCP Server** — AppId `1950a258`, OS `Microsoft Windows`, `.NET 9.x` (local desktop process)
2. **Azure PowerShell** — AppId `1950a258`, different UA prefix (no `azsdk-net-Identity`)
3. **Cloud services** (Security Copilot API, etc.) — Different AppIds (`bb3d68c2`), OS `CBL-Mariner/Linux` or `Microsoft Azure Linux`

**Token caching behavior:** Sign-in events appear at token acquisition time, NOT per API call. A cached token (~1hr lifetime) serves multiple Azure MCP calls with no additional sign-in events. This means sign-in event counts represent ACCESS SESSIONS, not individual tool invocations.

**Limitations:**
- ARM read operations (list subscriptions, list resource groups, list clusters) produce sign-in events but NOT AzureActivity records
- If the user also runs actual Azure PowerShell with the same account, their sign-in events will share the same AppId — filter by UserAgent containing BOTH `azsdk-net-Identity` AND `Microsoft Windows` to disambiguate
- When Azure MCP Server is deployed in remote HTTP mode (e.g., Azure Container Apps), a dedicated Entra app registration provides a unique AppId — check if one is configured
- The `DefaultAzureCredential` chain may resolve to different credential types depending on environment (Azure CLI, VS Code, managed identity), but the .NET runtime UserAgent is always present
- AzureActivity has a ~2-4 hour ingestion lag; SigninLogs has ~1-2 hour lag; LAQueryLogs and AADNonInteractiveUserSignInLogs are near-real-time (~5-15 min)

### Triage MCP AppId in LAQueryLogs — Dual-AppId Behavior (Field-Tested Feb 2026)
**Problem:** AppId `6574a0f8-d39b-4090-abbe-6c64ec9003f0` (Sentinel Triage MCP) was originally expected to appear in `LAQueryLogs` as the primary downstream signal for Advanced Hunting queries. Cross-environment testing revealed inconsistent and dual-AppId behavior:  

| Environment | `6574a0f8` (Triage MCP) | `fc780465` / `M365D_AdvancedHunting` |
|-------------|------------------------|-------------------------------------|
| **Production** | ✅ 1,086 queries (30d) — but **no user attribution** (empty `AADEmail`, empty `RequestClientApp`) | ✅ 162,642 queries (30d) — full user attribution, 4 distinct users |
| **Lab (CyberSOC)** | ❌ 0 queries (30d) | ✅ 439 queries (4h window) — full user attribution |

**Root Cause:** Two execution paths exist for AH queries hitting connected LA tables:
1. **Primary path** (`fc780465` / `M365D_AdvancedHunting`): The Advanced Hunting execution backend processes the query and logs it under its own identity. Carries ~99% of volume with full user attribution.
2. **Secondary path** (`6574a0f8`): The Triage MCP registered AppId appears in some environments via a separate backend execution path. No user or client app attribution. Environment-dependent — may relate to workspace configuration or tenant feature flags.

**Solution:** Query 7b now checks BOTH AppIds: `fc780465` with `RequestClientApp == "M365D_AdvancedHunting"` (primary) and `6574a0f8` (secondary). This captures all AH downstream activity regardless of environment. Note the shared-surface attribution limitation — cannot distinguish Triage MCP from Defender portal or Security Copilot AH queries.

### MicrosoftGraphActivityLogs Availability
**Problem:** Graph activity logs are NOT enabled by default. If the table is empty or doesn't exist, Graph MCP analysis cannot proceed.  
**Solution:** If `MicrosoftGraphActivityLogs` returns 0 results or table-not-found error, report: "⚠️ Microsoft Graph activity logs are not enabled in this tenant. Enable them at: https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview". Skip Graph MCP analysis gracefully and proceed with other MCP channels.

### LAQueryLogs Diagnostic Settings
**Problem:** `LAQueryLogs` requires diagnostic settings to be configured on the Log Analytics workspace. Without it, workspace query governance analysis is impossible.  
**Solution:** If `LAQueryLogs` returns empty, report: "⚠️ LAQueryLogs not available — enable Log Analytics workspace diagnostic settings to monitor query activity." Skip workspace governance analysis and note the gap.

### AppId Misclassification History (Field-Tested Feb 2026)

**`80ccca67`** — Previously assumed to be a Graph MCP variant. Actually the **M365 Security & Compliance Center** (Sentinel Portal backend, `RequestClientApp` = `ASI_Portal`). Categorize as "Sentinel Portal (Non-MCP)". Graph MCP has only ONE AppId: `e8c77dc2`.

**`95a5d94c`** — Previously assumed to be "VS Code Copilot" (MCP Client). Actually the **Azure Portal — AppInsightsPortalExtension** blade, executing Usage dashboard/workbook queries in the browser. No SPN or app registration in tenant; not in merill/microsoft-info known apps list. Categorize as "Portal/Platform (Non-MCP)".

> 📘 **Takeaway:** When encountering an unknown AppId in `LAQueryLogs`, check the `RequestClientApp` field first — it reliably reveals the actual source (e.g., `AppInsightsPortalExtension`, `ASI_Portal`). Do not assume an AppId is MCP-related without verifying via Graph API SPN lookup, sign-in logs, and query content analysis.

### CloudAppEvents CamelCase Matching (`ActionType` AND `Operation`)
**Problem:** Both `ActionType` and `RawEventData.Operation` values in `CloudAppEvents` for Sentinel operations use CamelCase without word boundaries (e.g., `SentinelAIToolRunCompleted`, `KQLQueryCompleted`). The `has` operator requires word boundaries and will **NOT** match these values. **Field-tested Feb 2026:** `has "Completed"` returns `false` for ALL Operation values including `KQLQueryCompleted` — the `has` operator fails on substrings within CamelCase tokens.  
**Solution:** Always use `contains` (not `has`) when filtering `ActionType` or `Operation` for Sentinel/KQL operations:
```kql
// ✅ CORRECT — 'contains' works with CamelCase
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| where Operation contains "Completed"

// ❌ WRONG — 'has' requires word boundaries, fails on CamelCase
| where ActionType has "Sentinel" or ActionType has "KQL"
| where Operation has "Completed"  // Returns 0 rows — silently drops ALL MCP events!
```
**Impact if missed:** Query 20 (MCP vs Direct KQL delineation) will show 0 MCP events and ONLY Direct KQL — because MCP events (RecordType 403) are filtered out by `Operation has "Completed"`, while Direct KQL events (RecordType 379) survive via the `OR RecordType == 379` fallback. This creates a false impression that no MCP-driven queries exist.

### CloudAppEvents RawEventData Parsing
**Problem:** `RawEventData` in `CloudAppEvents` is a dynamic column but often contains nested JSON that requires double-parsing. Direct property access (e.g., `RawEventData.ToolName`) may return empty.  
**Solution:** Always parse explicitly with `parse_json(tostring(RawEventData))`:
```kql
| extend RawData = parse_json(tostring(RawEventData))
| extend ToolName = tostring(RawData.ToolName)
```

### Data Lake MCP Has No AppId
**Problem:** Unlike Graph MCP (`e8c77dc2`) and Sentinel Triage MCP (`6574a0f8`), the Sentinel Data Lake MCP has **no dedicated AppId** in any telemetry table. It is not visible in `LAQueryLogs`, `SigninLogs`, or `MicrosoftGraphActivityLogs`.  
**Solution:** Data Lake MCP activity is audited exclusively via `CloudAppEvents` (Purview unified audit log). Filter by `RecordType == 403` and `Interface == "IMcpToolTemplate"`. If `CloudAppEvents` is not available (no E5 license or Purview not configured), Data Lake MCP monitoring is impossible — report this gap explicitly.

### CloudAppEvents Double-Counting Prevention
**Problem:** Each Data Lake MCP tool call generates TWO events: `SentinelAIToolRunStarted` (RecordType 403) and `SentinelAIToolRunCompleted` (RecordType 403). Counting both will double the actual call count.  
**Solution:** Always filter on `Operation == "SentinelAIToolRunCompleted"` for call counts, duration analysis, and error analysis. Use `SentinelAIToolRunStarted` only when investigating specific timing sequences or queue behavior.

### Data Lake MCP ExecutionDuration Format
**Problem:** The `ExecutionDuration` field in `RawEventData` is stored as a **string** (e.g., `"2.4731712"`), not a numeric type. Aggregation functions (`avg`, `max`) will fail without conversion.  
**Solution:** Use `todouble(RawData.ExecutionDuration)` to convert before aggregation.

### Sentinel Engine False Association
**Problem:** The Sentinel analytics engine (`fc780465-2017-40d4-a0c5-307022471b92`) generates the highest query volume in most workspaces but is NOT an MCP server. Including it in MCP totals would massively inflate the numbers.  
**Solution:** ALWAYS label Sentinel Engine and Logic Apps Connector as "Platform (Non-MCP)" in reports. The MCP proportion calculation MUST exclude these from the MCP numerator.

### Non-Interactive Sign-In Noise
**Problem:** `AADNonInteractiveUserSignInLogs` may contain Logic Apps connector activity (`de8c33bb`) that looks like user activity but is automated.  
**Solution:** When reporting Sentinel MCP auth events from SigninLogs, distinguish interactive (user-initiated) from non-interactive (automated) sources. The LogicApps connector is NOT MCP — exclude it from MCP auth counts.

### Off-Hours Timezone Uncertainty
**Problem:** `TimeGenerated` is always UTC, but "off-hours" has different meaning depending on the user's timezone. A UTC 06:00 call might be 22:00 local or 14:00 local.  
**Solution:** Default to UTC for off-hours calculation. If the user's timezone is known from sign-in data (`LocationDetails`), adjust. Always state the timezone assumption in the report.

### Multi-Tenant Token Confusion
**Problem:** Azure MCP Server uses `DefaultAzureCredential` and may authenticate against the wrong tenant if multiple credentials are cached, causing queries to fail or return data from an unexpected tenant.  
**Solution:** Read `config.json` for the `azure_mcp.tenant` parameter. When making Azure MCP Server calls, always pass the `tenant` parameter explicitly. Note this risk in the report.

### Agent User UPNs Masquerading as Human Users
**Problem:** Agent Users are assigned UPNs and appear in `UserId` fields identically to human users. Without checking the account type, an agent user's MCP activity would be reported as human activity.  
**Solution:** When the MCP Usage Score flags unexpected user diversity or new users (Query 12), cross-reference the `UserId` with Entra to check if the user object is an Agent User (`userType` and account metadata). Agent Users created by Copilot Studio or Agent Identity Blueprints will have specific metadata distinguishing them from workforce accounts.

### Rate Limiting Not Visible in Logs
**Problem:** Graph MCP Server is capped at 100 calls/min/user. If throttled, calls may not appear in logs (no log entry = no visibility).  
**Solution:** If daily call counts show sudden drops to 0 after a high-volume period, note possible throttling. Check for `429 Too Many Requests` response codes in Query 1 raw data.

### SentinelAudit Table Availability
**Problem:** `SentinelAudit` requires Sentinel auditing and health monitoring to be enabled. It may not exist in all workspaces.  
**Solution:** If `SentinelAudit` returns table-not-found, skip Query 15 gracefully. Report: "⚠️ Sentinel auditing not enabled — cannot check configuration changes."

---

## Error Handling

### Common Issues

| Issue | Solution |
|-------|----------|
| `MicrosoftGraphActivityLogs` table not found | Graph activity logs not enabled. Report gap, skip Graph MCP analysis, provide enablement link. |
| `LAQueryLogs` table not found | Diagnostic settings not configured on LA workspace. Report gap, skip governance analysis. |
| `SentinelAudit` table not found | Sentinel health monitoring not enabled. Report gap, skip config change analysis. |
| `AzureActivity` returns 0 results | No ARM operations in the time range, or no administrative actions by the specified user. |
| Agent Identity query returns empty | Entra Agent ID not enabled or no agents registered. Report gap as "✅ No Agent Identities detected", skip Queries 18-19. |
| `AADServicePrincipalSignInLogs` missing agent subtype | Agent ID preview may not be active. Agent SPNs will appear as regular SPNs. Note limitation. |
| SPN `servicePrincipalType` shows `Application` for known agents | Expected behavior as of Feb 2026. Copilot Studio agents still report as `Application`. Use `/beta` `tags` array instead (`AgenticApp`, `AgentCreatedBy:CopilotStudio`). |
| Agent sign-ins show Azure internal IPv6 (`fd00:*`) | Expected for Copilot Studio agents — they authenticate from Azure infrastructure. Not a concern. |
| Agent SPN hard-deleted shortly after creation | Testing/experimentation pattern. AuditLogs show `Add service principal` → `Hard delete service principal` within minutes. Report duration and flag if unexpected. |
| SigninLogs returns 0 for Sentinel Platform Services | No one authenticated to Sentinel MCP in the time range. Report as "✅ No Sentinel MCP authentication events detected." |
| `CloudAppEvents` table not found | Purview unified audit not available (requires E5 license). Report gap: "⚠️ CloudAppEvents not available — cannot monitor Data Lake MCP usage. Requires Microsoft 365 E5 or Purview audit." Skip Phase 3 (Data Lake MCP). |
| CloudAppEvents returns 0 for Sentinel operations | No Data Lake MCP or Direct KQL activity in the time range. Report as "✅ No Sentinel Data Lake activity detected in CloudAppEvents." |
| `ActionType has "Sentinel"` returns 0 but data exists | CamelCase bug — use `contains` instead of `has` for ActionType matching. See Known Pitfalls. |
| `Operation has "Completed"` drops MCP events silently | Same CamelCase bug — `has "Completed"` returns false for ALL CamelCase operations (`SentinelAIToolRunCompleted`, `KQLQueryCompleted`). MCP events (RecordType 403) are silently dropped; Direct KQL survives only via `OR RecordType == 379` fallback. Use `contains "Completed"`. See Known Pitfalls. |
| `RawEventData.ToolName` returns empty | Double-parse required: use `parse_json(tostring(RawEventData))` then extract fields. See Known Pitfalls. |
| Query timeout | Reduce lookback from 30d to 7d, or add `| take 100` to intermediate results. |
| Unknown AppId in LAQueryLogs | Cross-reference with Entra ID > App Registrations. May be a custom MCP server or third-party tool. |
| Multiple workspaces available | Follow workspace selection rules — STOP, list all, ASK user, WAIT. |
| Azure MCP calls indistinguishable from CLI | Partially resolved: AppId `1950a258` + UserAgent `azsdk-net-Identity (.NET 9.x)` reliably distinguishes Azure MCP Server from Azure PowerShell in SigninLogs. ARM read ops still don't appear in AzureActivity. |

### Validation Checklist

Before presenting results, verify:

- [ ] All MCP telemetry surfaces were queried (Graph, Sentinel Triage, Sentinel Data Lake, Azure ARM, LAQueryLogs, CloudAppEvents)
- [ ] Tables that don't exist are reported as gaps, not silent omissions
- [ ] Non-MCP sources (Sentinel Engine, Logic Apps, Sentinel Portal) are clearly labeled as "Platform/Portal (Non-MCP)"
- [ ] `80ccca67` is classified as "M365 Security & Compliance Center (Sentinel Portal)" — NOT as an MCP server
- [ ] `95a5d94c` is classified as "Azure Portal — AppInsightsPortalExtension" — NOT as MCP Client or VS Code Copilot. Verify via `RequestClientApp` field.
- [ ] MCP proportion calculation excludes non-MCP platform sources from the MCP numerator
- [ ] Two-tier governance view included: Analytics tier (LAQueryLogs) + Data Lake tier (CloudAppEvents)
- [ ] Data Lake MCP vs Direct KQL delineation is clearly presented (RecordType 403 vs 379)
- [ ] CloudAppEvents queries use `contains` (not `has`) for ActionType matching
- [ ] CloudAppEvents queries use `contains` (not `has`) for `Operation` field matching (same CamelCase issue)
- [ ] CloudAppEvents RawEventData is parsed with `parse_json(tostring(RawEventData))` pattern
- [ ] Data Lake MCP tool call counts use `SentinelAIToolRunCompleted` only (not Started) to avoid double-counting
- [ ] All user attribution is based on actual query results, not assumptions
- [ ] Azure MCP Server data includes detection via composite signal (AppId `1950a258` + UserAgent `azsdk-net-Identity` + RequestClientApp `csharpsdk`)
- [ ] Graph MCP sensitive endpoint percentage is calculated from actual data
- [ ] Off-hours analysis states the timezone assumption (default: UTC)
- [ ] Empty results are explicitly reported with ✅ (not silently omitted)
- [ ] AppId cross-reference table is included for any unknown AppIds discovered
- [ ] The MCP Usage Score calculation is transparent with per-dimension evidence
- [ ] All ASCII visualizations are wrapped in code fences for markdown compatibility
- [ ] Agent Identity detection was attempted (Query 17 for caller attribution, Query 19 for CRUD lifecycle, Graph API `/beta` tags for classification)
- [ ] Graph API cross-reference used `/beta` endpoint with `tags` property — NOT `servicePrincipalType` alone (which is unreliable)
- [ ] Agent classification based on tags (`AgenticApp`, `AgentCreatedBy:CopilotStudio`), NOT display name
- [ ] If Agent Identities found: reported separately from human users and standard SPNs, with lifecycle timeline
- [ ] If no Agent Identities: confirmed with "✅ No Entra Agent Identities detected in tenant"

---

## Prerequisites

For complete MCP server monitoring, ensure these data sources are enabled:

| Data Source | Enabling Documentation | Required For |
|-------------|----------------------|--------------|
| **Microsoft Graph activity logs** | [Enable Graph activity logs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview) | Graph MCP analysis (Queries 1-4, 11-12, 17) |
| **CloudAppEvents (Purview unified audit)** | Requires M365 E5 license; enable [Sentinel Data Lake auditing](https://learn.microsoft.com/en-us/azure/sentinel/datalake/auditing-lake-activities) | Data Lake MCP analysis (Queries 20-24) |
| **Sentinel auditing and health monitoring** | [Enable Sentinel monitoring](https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring) | Config change detection (Query 15) |
| **LAQueryLogs (diagnostic settings)** | Configure diagnostic settings on LA workspace | Workspace governance (Queries 7, 10, 13-14, 16) |
| **AzureActivity** | Enabled by default for ARM operations | Azure MCP analysis (Queries 8-9) |
| **SigninLogs** | Entra ID diagnostic settings | Sentinel MCP auth events (Queries 5-6) |
| **Purview audit logs** | Included with E5 license | CloudAppEvents ingestion — required for Data Lake MCP monitoring (Queries 20-24). RecordType 403 (AI Tool) and 379 (KQL) |

If any prerequisite is not met, the skill will report the gap and skip the affected analysis sections.

---

## Cross-References

- **KQL Jobs for proactive alerting:** `queries/identity/mcp_anomaly_detection_kql_jobs.md` — Scheduled Data Lake jobs that promote MCP anomalies to analytics tier for automated Sentinel alerting
- **Main skill registry:** `.github/copilot-instructions.md` — Skill detection and global rules
- **Scope drift analysis:** `.github/skills/scope-drift-detection/SKILL.md` — Can be run on MCP-related service principals for behavioral drift detection
- **Sentinel Data Lake auditing:** [Auditing lake activities](https://learn.microsoft.com/en-us/azure/sentinel/datalake/auditing-lake-activities) — Official docs on RecordType 403/379 audit events in CloudAppEvents
- **Sentinel MCP tool collections:** [Tool collection overview](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-tools-overview) — Data Exploration, Triage, and Security Copilot Agent Creation collections
- **Sentinel MCP custom tools:** [Create custom MCP tools](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-create-custom-tool) — Expose saved KQL queries as MCP tools
- **Copilot Studio MCP catalog:** [Built-in MCP servers](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-microsoft-mcp-servers) — 19+ Microsoft-managed MCP servers for agent development
- **Azure MCP Server tools:** [Available tools](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/tools/) — Full Azure MCP Server tool catalog (40+ namespaces)
- **Power BI MCP:** Remote endpoint at `https://api.fabric.microsoft.com/v1/mcp/powerbi`, Modeling at [microsoft/powerbi-modeling-mcp](https://github.com/microsoft/powerbi-modeling-mcp)
- **Fabric RTI MCP:** [Fabric RTI MCP overview](https://learn.microsoft.com/en-us/fabric/real-time-intelligence/mcp-overview) | [GitHub](https://github.com/microsoft/fabric-rti-mcp/)
- **Playwright MCP:** [GitHub](https://github.com/microsoft/playwright-mcp) — Browser automation MCP (26.9k ⭐, local only)
- **Entra Agent ID docs:** [What are agent identities](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/what-is-agent-id) | [Agent sign-in logs](https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/sign-in-audit-logs-agents) | [Agent OAuth protocols](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-oauth-protocols) | [Known issues](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/preview-known-issues)
