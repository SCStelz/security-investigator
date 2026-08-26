---
name: ai-agent-posture
description: 'Audit or report on AI agent security posture across Copilot Studio, Microsoft 365 Copilot, Microsoft Foundry, and third-party agents. Triggers on "AI agent posture", "agent security audit", "Copilot Studio agents", "agent inventory", "broadly accessible agents", "agent tools", "MCP tools on agents", "XPIA risk", "agent sprawl", "agent governance", "agent identity", "dormant agents", "ownerless agents", or investigating agent configs, access posture, tool permissions, credential exposure, or Entra agent identities. Queries the AgentsInfo table in Advanced Hunting to assess agent inventory, access posture, broadly-accessible exposure, MCP tool proliferation, knowledge source exposure, XPIA email exfiltration risk, hard-coded credentials, external endpoints, creator governance, and sprawl. When Sentinel Data Lake is present, enriches with the Entra agent identity model (EntraAgentIdentities, blueprints, agentic-user accounts) for lifecycle, governance, and dormant-agent detection. Inline or markdown output.'
threat_pulse_domains: [admin, cloud]
drill_down_prompt: 'Run AI agent security audit — agent inventory, authentication gaps, tool permissions'
---

# AI Agent Security Posture — Instructions

## Purpose

This skill audits the **security posture of AI agents** (Copilot Studio, Microsoft 365 Copilot / Agent Builder, Microsoft Foundry, and third-party platforms) across your organization using the `AgentsInfo` table in Microsoft Defender XDR Advanced Hunting.

> **🔄 Table migration (AIAgentsInfo → AgentsInfo):** This skill was migrated from the deprecated `AIAgentsInfo` table to the unified multi-platform `AgentsInfo` table. `AIAgentsInfo` remains queryable until **July 1, 2026**, but it is Copilot Studio-only and uses a different schema. All queries in this skill target `AgentsInfo`. The new table is a **different data model**, not a rename — see [Table Schema Reference](#table-schema-reference) and [Known Pitfalls](#known-pitfalls) for the differences that shaped these queries.

AI agents are autonomous or semi-autonomous applications that can access organizational data, send emails, call external APIs, and use MCP tools. Misconfigured agents — missing authentication, overly broad access, AI-controlled email sending, hard-coded credentials — represent a growing attack surface. This skill systematically evaluates that surface.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔍 **Agent Inventory** | How many agents exist? What's their status, platform, environment? |
| 🔐 **Access Posture** | Which agents are broadly accessible (`allowForAllUsers`)? How are agents shared (`appType`: lob/shared)? |
| 🛠️ **Tools & MCP** | Which agents have MCP tools? What operations can they perform? |
| 📚 **Knowledge Sources** | What data sources are agents connected to? |
| 📧 **XPIA Email Risk** | Which agents can send email (data exfil precondition)? |
| 🔑 **Credential Exposure** | Are credentials hard-coded in agent instructions or connector metadata? |
| 🌐 **External Endpoint Risk** | What external hosts do agent connectors reach? Any insecure schemes or non-standard ports? |
| 👥 **Creator Governance** | Who creates agents? Is there naming hygiene? Abandoned agents? |

**Data source:** `AgentsInfo` table (Advanced Hunting) — currently in **Preview**.

**References:**
- [Microsoft Docs — AgentsInfo table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-agentsinfo-table)
- [From runtime risk to real-time defense: Securing AI agents](https://www.microsoft.com/en-us/security/blog/2026/01/23/runtime-risk-realtime-defense-securing-ai-agents/) — Microsoft Defender Security Research blog detailing three attack scenarios this skill detects
- [Microsoft Agent 365: The control plane for AI agents](https://www.microsoft.com/en-us/microsoft-365/blog/2025/11/18/microsoft-agent-365-the-control-plane-for-ai-agents/) — Enterprise governance platform for agent lifecycle management (Registry, Access Control, Visualization, Interoperability, Security)
- [Securing Copilot Studio agents with Microsoft Defender](https://learn.microsoft.com/en-us/defender-cloud-apps/ai-agent-protection)
- [Real-time agent protection during runtime (Preview)](https://learn.microsoft.com/en-us/defender-cloud-apps/real-time-agent-protection-during-runtime)

### 🔴 URL Registry — Canonical Links for Report Generation

**MANDATORY:** When generating reports, copy URLs **verbatim** from this registry. NEVER construct, guess, or paraphrase a URL. If a URL is not in this registry, omit the hyperlink entirely and use plain text.

| Label | Canonical URL |
|-------|---------------|
| `BLOG_RUNTIME_RISK` | `https://www.microsoft.com/en-us/security/blog/2026/01/23/runtime-risk-realtime-defense-securing-ai-agents/` |
| `BLOG_AGENT_365` | `https://www.microsoft.com/en-us/microsoft-365/blog/2025/11/18/microsoft-agent-365-the-control-plane-for-ai-agents/` |
| `DOCS_AGENTSINFO` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-agentsinfo-table` |
| `DOCS_AGENT_PROTECTION` | `https://learn.microsoft.com/en-us/defender-cloud-apps/ai-agent-protection` |
| `DOCS_RUNTIME_PROTECTION` | `https://learn.microsoft.com/en-us/defender-cloud-apps/real-time-agent-protection-during-runtime` |

**Usage in reports:** When referencing attack scenarios, link to `BLOG_RUNTIME_RISK`. When referencing Agent 365 governance, link to `BLOG_AGENT_365`. When referencing runtime protection, link to `DOCS_RUNTIME_PROTECTION`.

---

## Threat Landscape: Why AI Agent Posture Matters

Microsoft Defender Security Research has identified that AI agents represent a **fundamentally new attack surface** where the agent's capabilities are effectively equivalent to code execution. When a tool is invoked, it can read/write data, send emails, update records, or trigger workflows — and an attacker who can influence the agent's plan can indirectly cause the execution of unintended operations within the agent's capability sandbox.

The core risk: **the agent's orchestrator depends on natural language input to determine which tools to use and how to use them.** This creates exposure to prompt injection and reprogramming failures, where malicious prompts, embedded instructions, or crafted documents can manipulate the decision-making process.

This skill's queries map directly to three attack scenarios documented by Microsoft:

### Attack Scenario 1: Malicious Instruction Injection via Event-Triggered Workflow

| Element | Detail |
|---------|--------|
| **Vector** | Crafted email sent to an agent-monitored mailbox (event trigger) |
| **Mechanism** | Email contains hidden instructions telling the agent to search knowledge base for sensitive data and exfiltrate via email to attacker |
| **Preconditions** | Agent can send email (email connector) + has an event/email trigger + a knowledge source |
| **Detection** | Q5 (XPIA Email Risk) detects email-capable agents via connector operations; Q7 (Knowledge Sources) identifies data exposure |
| **Skill Signal** | Agents with an email-send operation (e.g., `Office 365 Outlook Send an email (V2)`) + knowledge sources, especially if broadly accessible (`allowForAllUsers == "true"`) = highest risk |

### Attack Scenario 2: Prompt Injection via Shared Document → Email Exfiltration (XPIA)

| Element | Detail |
|---------|--------|
| **Vector** | Malicious insider edits a SharePoint document with crafted instructions |
| **Mechanism** | Agent processing the document is tricked into reading a sensitive file on a different SharePoint site (that the agent has access to but the attacker doesn't) and emailing contents to attacker-controlled domain |
| **Preconditions** | Agent has a knowledge/data source + an email-send connector operation |
| **Detection** | Q5 (XPIA) + Q7 (Knowledge Sources) identifies the attack surface |
| **Skill Signal** | A declared data source + an email-send operation (e.g., `Send an email (V2)`) on the same agent = classic XPIA vector |

### Attack Scenario 3: Capability Reconnaissance on Unauthenticated Agent

| Element | Detail |
|---------|--------|
| **Vector** | Attacker interacts with publicly accessible chatbot (no authentication required) |
| **Mechanism** | Series of crafted prompts to probe and enumerate the agent's tools and knowledge sources, then exploit them to extract sensitive data |
| **Preconditions** | Agent is broadly accessible (`allowForAllUsers == "true"`, e.g., shared tenant-wide or website embed) |
| **Detection** | Q4 (Broadly-Accessible Agents) identifies exposed agents; cross-reference with Q7 (knowledge sources with customer data) |
| **Skill Signal** | `allowForAllUsers == "true"` + knowledge sources containing sensitive data = reconnaissance target |

> **⚠️ Authentication-type telemetry gap:** The deprecated `AIAgentsInfo` table exposed `UserAuthenticationType` (`None`/`Integrated`/`Custom`), which let this skill directly flag *unauthenticated* agents. The new `AgentsInfo` table has **no populated authentication-type column** in current telemetry (`ToolsAuthenticationType` is empty). The closest available exposure signal is `RawAgentInfo.allowForAllUsers == "true"` (broadly accessible to all tenant users). This is a **proxy, not an equivalent** — it measures broad reach, not absence of authentication. Treat broadly-accessible agents as the highest-exposure cohort and recommend Entra-based access policies (Agent 365) to close the gap.

### Mitigation: Defender Runtime Protection

Microsoft Defender provides **webhook-based runtime inspection** for Copilot Studio agents. Before every tool, topic, or knowledge action is executed, the generative orchestrator sends a webhook to Defender containing the planned invocation context. Defender analyzes intent and destination in real time and can **allow or block** the action before execution.

This is the primary runtime defense against all three scenarios above. When reviewing posture findings from this skill, **always recommend enabling Defender Runtime Protection** for agents flagged as high-risk. See [Real-time agent protection during runtime](https://learn.microsoft.com/en-us/defender-cloud-apps/real-time-agent-protection-during-runtime).

### Governance Framework: Microsoft Agent 365

[Microsoft Agent 365](https://www.microsoft.com/en-us/microsoft-365/blog/2025/11/18/microsoft-agent-365-the-control-plane-for-ai-agents/) is the enterprise **control plane** for AI agents — the platform-level answer to the governance gaps this skill detects. It provides five capabilities that directly map to this skill's risk dimensions:

| Agent 365 Capability | What It Does | Skill Dimensions Addressed |
|---------------------|-------------|---------------------------|
| **1. Registry** | Single source of truth for all agents (Entra agent ID). IT can quarantine unsanctioned agents and detect shadow agents. Agent Store for governed discovery. | Agent Inventory (Q1), Creator Governance (Q10), Agent Sprawl (Q11) |
| **2. Access Control** | Unique agent IDs via Entra. Agent Policy Templates enforce security from day one. Adaptive, risk-based access policies. Least-privilege enforcement. | Broadly-Accessible Agents (Q4), Access Posture (Q3) |
| **3. Visualization** | Unified dashboard mapping agents ↔ users ↔ resources. Role-based reporting. Compliance logging, e-discovery, and audit trail. | MCP Tool Exposure (Q6), Knowledge Sources (Q7), Creator Governance (Q10) |
| **4. Interoperability** | Agents access Work IQ (org data, relationships, context). Works across Copilot Studio, Microsoft Foundry, Agent Framework, Agent 365 SDK, and partner platforms. | Knowledge Source Risk (Q7), Tools Inventory (Q12) |
| **5. Security** | Defense-in-depth via Microsoft Defender (posture + threat detection + runtime protection), Entra (real-time blocking), and Purview (data exposure risk, sensitive data leak prevention, compliance). | XPIA Email Risk (Q5), Credential Hygiene (Q8), External Endpoint Risk (Q9) |

**How to reference Agent 365 in reports:** When this skill identifies governance gaps (sprawl, missing authentication, uncontrolled tool access), recommend Agent 365 as the strategic platform to address them. Specific mappings:

- **Agent sprawl / no naming conventions** → Agent 365 Registry + quarantine for unsanctioned agents
- **Missing access controls / broadly-accessible agents** → Agent 365 Access Control + Entra agent IDs + Policy Templates
- **No visibility into agent-resource connections** → Agent 365 Visualization dashboard
- **Uncontrolled MCP/tool proliferation** → Agent 365 Security + Defender posture management
- **XPIA / data exfiltration risk** → Agent 365 Security + Purview for real-time data leak prevention

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** — Mandatory rules
2. **[Data Plane Detection & Selection](#data-plane-detection--selection)** — baseline (AgentsInfo) + optional Entra identity enrichment
3. **[Table Schema Reference](#table-schema-reference)** — AgentsInfo columns and data types
4. **[Agent Security Score Formula](#agent-security-score-formula)** — Composite risk scoring
5. **[Execution Workflow](#execution-workflow)** — Phase-by-phase query plan
6. **[Sample KQL Queries](#sample-kql-queries)** — All queries (Q1–Q15)
7. **[Output Modes](#output-modes)** — Inline vs Markdown report
8. **[Inline Report Template](#inline-report-template)** — Chat-rendered format
9. **[Markdown File Report Template](#markdown-file-report-template)** — Disk-saved format
10. **[Known Pitfalls](#known-pitfalls)** — Schema quirks and edge cases
11. **[Quality Checklist](#quality-checklist)** — Pre-delivery validation
12. **[SVG Dashboard Generation](#svg-dashboard-generation)** — Visual dashboard from report

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **ALWAYS use `RunAdvancedHuntingQuery`** — The `AgentsInfo` table is an Advanced Hunting table. It is NOT available in Sentinel Data Lake (`query_lake`). All queries in this skill MUST use `RunAdvancedHuntingQuery`.

2. **ALWAYS deduplicate agents with `arg_max`** — The table contains multiple records per agent (state snapshots over time). Every query that analyzes current agent state MUST use `| summarize arg_max(Timestamp, *) by AgentId` to get the latest record per agent. Note `AgentId` is a **guid**.

3. **ALWAYS exclude deleted agents** (unless specifically auditing deletions) — Add `| where LifecycleStatus != "Deleted"` after deduplication. `LifecycleStatus` is blank for active agents and only set to `Deleted` for removed ones, so this filter keeps active agents.

4. **ASK the user for output format** before generating the report:
   - **Inline chat summary** (quick review in chat)
   - **Markdown file report** (detailed, archived to `reports/ai-agent-posture/`)
   - **Both** (markdown + inline summary)

5. **⛔ MANDATORY: Evidence-based analysis only** — Report ONLY what query results show. Use the explicit absence pattern (`✅ No [finding] detected`) when queries return 0 results. Never guess or assume.

6. **🔴 The rich agent detail lives in `RawAgentInfo` (dynamic), not in flat columns** — Governance signals (`creatorId`, `allowForAllUsers`, `appType`, `scope`) and deep tool/connector detail (`declarativeCopilotMetadata`) are nested inside the `RawAgentInfo` dynamic column. The normalized columns (`DeclaredTools`, `McpServers`, `DeclaredDataSources`) are sparse and flat. Parse `RawAgentInfo` with `mv-expand`/dot-notation — never assume a flat column holds the value. See [Known Pitfalls](#known-pitfalls).

7. **Run queries in parallel batches** where possible — Phase 1 queries (Q1–Q3) are independent and can run in parallel. Phase 2 queries (Q4–Q9) are independent and can run in parallel. Phase 3 (Q10–Q12) can run in parallel.

8. **Time tracking** — Report elapsed time after each phase completion.

9. **🔴 DATA PLANE AWARENESS** — This skill's **baseline** is `AgentsInfo` (Advanced Hunting), available to **every Defender XDR tenant** — Phases 1–5 depend only on it. When **Microsoft Sentinel Data Lake** is present, an **optional enrichment tier** (the `EntraAgent*` identity tables, Phase 6) adds lifecycle state, blueprint governance, agentic-user accounts, and clean dormant-agent detection. **Probe for the enrichment plane before using it and skip gracefully if absent** — never block or degrade the baseline assessment for a Defender-only tenant, and never change the /100 score based on enrichment availability. See [Data Plane Detection & Selection](#data-plane-detection--selection).

---

## Data Plane Detection & Selection

Agent posture spans three planes. Only the **baseline** is required; detect and use the others when present.

| Plane | Table(s) | Query tool | Availability | Role |
|-------|----------|-----------|--------------|------|
| **Baseline — config posture** | `AgentsInfo` | `RunAdvancedHuntingQuery` | **All Defender XDR tenants** | Inventory, tools/MCP, knowledge, **owner/creator**, Entra linkage. Drives Phases 1–5 and the /100 score. |
| **Enrichment — Entra identity** | `EntraAgentIdentities`, `EntraAgentIdentityBlueprints`, `EntraAgentUsers` | `mcp_sentinel-data_query_lake` (`workspaceId:"default"`) | **Sentinel Data Lake only** | Lifecycle/compliance, blueprint app-reg governance, agentic-user accounts, duplicate/dormant identities (Phase 6). |
| **Runtime** | `CopilotActivity` (AH) / `UnifiedAgentObservability` (Data Lake) | AH / `query_lake` | AH everywhere; UAO Data-Lake-only | Which flagged agents are actually active (Phase 5). |

**Enrichment-plane probe (run once, before Phase 6):**
```kql
// mcp_sentinel-data_query_lake, workspaceId: "default"
EntraAgentIdentities | where TimeGenerated > ago(7d) | summarize Rows = count()
```
- Returns rows → **enrichment plane available**, run Phase 6.
- `SemanticError: Failed to resolve table` or 0 rows → **Defender-only tenant**, skip Phase 6 and state the gap in the report banner.

> **🔴 MANDATORY report banner:** State which planes were available, e.g. *"Baseline: AgentsInfo ✅ · Entra identity enrichment: ✅ (14 identities) · Runtime: CopilotActivity ✅"* or *"…Entra identity enrichment: ❌ not available (no Sentinel Data Lake) — lifecycle, blueprint governance, agentic-user, and identity-based dormancy findings were not assessed."*

> **Full enrichment query library:** [`queries/cloud/entra_agent_identity.md`](../../../queries/cloud/entra_agent_identity.md) — Queries 1–6, the validated cross-plane join map, and the Defender-only fallback. Phase 6 references it rather than duplicating the KQL.

---

## Table Schema Reference

The `AgentsInfo` table (Preview) contains configuration snapshots of AI agents across Copilot Studio, Microsoft 365 Copilot (Agent Builder), Microsoft Foundry, and third-party platforms. The schema below reflects the **live table** (which differs from the published docs in several places — column casing, types, and which columns are actually populated).

### Top-level columns

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | Last recorded date/time for this agent snapshot |
| `AgentId` | guid | Unique agent identifier (dedup key) |
| `Name` | string | Display name of the agent |
| `Description` | string | Agent description |
| `Platform` | string | `Copilot Studio`, `Agent Builder in Microsoft 365 Copilot`, `Microsoft Foundry`, `Other`, `SharePoint`, `Amazon Bedrock`, `LocalAgents` |
| `Version` | string | Agent version |
| `PublishedStatus` | string | `Published`, `Draft` |
| `LifecycleStatus` | string | Blank for active agents; `Deleted` for removed agents |
| `CreatedDateTime` | datetime | When the agent was created |
| `LastUpdatedDateTime` | datetime | When last updated |
| `LastPublishedDateTime` | datetime | When last published |
| `Owners` | dynamic | Owner identities (sparse) |
| `SharedWith` | dynamic | Sharing targets (sparse) |
| `InstanceCount` | int | Blueprint instance count |
| `Instructions` | string | System prompt / agent instructions (well populated) |
| `Model` | string | Backing LLM model (sparse) |
| `Capabilities` | dynamic | Declared capabilities (sparse) |
| `DeclaredDataSources` | dynamic | Knowledge/data sources — array of filename/source strings (sparse) |
| `DeclaredTools` | dynamic | Declared tools — array of `{type, name}` (sparse, flat) |
| `McpServers` | dynamic | MCP servers — array of `{name, description}` (sparse) |
| `Skills`, `ConnectedAgents`, `Memory`, `Guardrails` | dynamic | Additional declared config (sparse) |
| `EntraAgentID` / `EntraBlueprintID` / `ObservabilityID` | string | Entra + observability linkage (note capital `ID`) |
| `RawAgentInfo` | dynamic | **Primary detail source** — full governance + connector manifest (populated for ~all agents). See nested keys below |
| `TenantId`, `Type`, `SourceSystem` | string | Standard envelope columns |

### ⚠️ Columns that are EMPTY / unreliable in current telemetry

These columns exist but are **not populated** in observed data — do NOT build detections on them without first confirming population:

`ToolsAuthenticationType` (auth-type gap — see below), `Availability`, `Endpoints`, `Triggers`, `Permissions`, `Model` (mostly), and most of `Owners`/`SharedWith`.

> **🔴 Authentication-type gap:** The deprecated `AIAgentsInfo.UserAuthenticationType` (`None`/`Integrated`/`Custom`) has **no populated equivalent** in `AgentsInfo`. There is no reliable way to flag "unauthenticated" agents from this table. Use `RawAgentInfo.allowForAllUsers == "true"` as a broad-exposure proxy (Q4) and document the gap.

### `RawAgentInfo` nested keys (the rich data)

For Copilot Studio agents, `RawAgentInfo` is a marketplace/governance manifest. Key fields the queries below rely on:

| Path | Meaning |
|------|---------|
| `RawAgentInfo.creatorId` | Creator **GUID** (resolve to UPN via `IdentityInfo` join). Replaces `CreatorAccountUpn`. Sparse |
| `RawAgentInfo.allowForAllUsers` | `"true"` = broadly accessible to all tenant users (exposure signal). Replaces `AccessControlPolicy == "Any"` |
| `RawAgentInfo.appType` | `lob` (line-of-business, owner-scoped), `shared`, `thirdParty`, `firstParty` |
| `RawAgentInfo.scope` | Sharing scope (e.g., `tenant`) |
| `RawAgentInfo.declarativeCopilotMetadata` | **Deep connector/tool detail** (DCM). Present only for the connector-sourced subset (~10% of Copilot Studio agents) |

**DCM nesting** (recovers deep tool, operation, and endpoint detail):

```
RawAgentInfo.declarativeCopilotMetadata[]
  .actions[]
    .apis[]            // .type = OpenApi | RemoteMCPServer | api_action
      .serverUrls[]    // populated for OpenApi + RemoteMCPServer (external hosts)
      .operations[]
        .operationId   // e.g., "Office 365 Outlook Send an email (V2)"
```

DCM siblings also carry `instructions`, `llmModels` (model), and `sourceIds` (incl. `EnvironmentId`, `SourceAgentId`).

---

## Agent Security Score Formula

The Agent Security Score is a composite risk indicator that summarizes the security posture of an organization's AI agent fleet. Higher scores indicate greater risk.

### Scoring Dimensions

$$
\text{AgentSecurityScore} = \sum_{i} \text{DimensionScore}_i
$$

Each dimension contributes 0–20 points to a maximum of 100:

| Dimension | Max | 🟢 Low (0–5) | 🟡 Medium (6–12) | 🔴 High (13–20) |
|-----------|-----|--------------|-------------------|------------------|
| **Broadly-Accessible Agents** | 20 | 0 agents with `allowForAllUsers == "true"` | 1–2 broadly-accessible agents | ≥3 broadly-accessible agents, especially if Published with knowledge sources or email capability |
| **XPIA Email Risk** | 20 | 0 email-capable agents | 1–2 email-capable agents (scoped access) | ≥1 email-capable agent that is also broadly accessible or has knowledge sources |
| **Tool & Endpoint Exposure** | 20 | 0–2 MCP agents, known creators, no external endpoints | 3–10 MCP agents, external endpoints all HTTPS/standard-port | >10 MCP agents, OR MCP/endpoint agents that are broadly accessible, OR any insecure-scheme / non-standard-port external endpoint (Q9 escalators) |
| **Knowledge Source Risk** | 20 | 0 agents with data sources + broad access | 1–3 agents with data sources + scoped access | Agents with data sources + `allowForAllUsers == "true"`. **Compounding rule:** When agents have data sources + an email-send operation + broad access (the full XPIA chain from Q5 + Q7), score at maximum (20) for this dimension AND score XPIA Email Risk at maximum (20) — the combination is the documented attack pattern |
| **Credential Hygiene** | 20 | 0 credential patterns detected | Patterns found but agent is Draft (unpublished) | Patterns found in Published agents |

### Interpretation Scale

| Score | Rating | Action |
|-------|--------|--------|
| **0–20** | ✅ Healthy | Normal posture, no immediate concerns |
| **21–45** | 🟡 Elevated | Review — minor misconfigurations detected |
| **46–70** | 🟠 Concerning | Investigate — multiple risk signals present |
| **71–100** | 🔴 Critical | Immediate remediation — significant agent security risk |

> The **Tool & Endpoint Exposure** dimension folds external-endpoint risk (Q9) into the MCP exposure signal: an insecure scheme, a non-standard port, or an external endpoint on a broadly-accessible agent each escalates this dimension to its High tier regardless of MCP count.

### Supplementary Indicators (not summed into the /100 score)

These indicators are reported **alongside** the composite score for added context. They are intentionally **not** added to the /100 total — they enrich interpretation and feed the dimensions above as evidence.

| Indicator | Source | What it tells you |
|-----------|--------|-------------------|
| **Capability Privilege Index** | Q13 | Count of agents holding ≥1 *sensitive* operation (mail-send, directory-write, data-write, messaging). Split by broad access. A high count of broadly-accessible + sensitive-op agents is the strongest privilege-abuse signal and should justify maxing the Broad Access and/or XPIA dimensions. |
| **Deep-Manifest Coverage** | Q14 | Percentage of the fleet carrying `declarativeCopilotMetadata` (DCM). Because the XPIA, endpoint, and capability queries depend on DCM, this is the fraction of the estate that was *fully* inspectable. Every report MUST surface this so the analyst knows what was **not** inspected. |
| **Ownership Governance — Orphaned Agents** *(baseline — all tenants)* | Q16 | Count of agents whose **assigned owner has left the org** (`Owners[]` GUID no longer resolves in `IdentityInfo`) — the telemetry equivalent of the Agent 365 *"Agents without owners"* registry card, but **cross-platform**. Validated: telemetry surfaced **~30× more** orphaned agents than the admin-center card (which is Agent-Builder-scoped). A live, credentialed, Published agent with no accountable human = **MITRE T1098** governance risk. **AH-native — reported for every tenant**, unlike the Data-Lake-only indicators below. Canonical cross-platform version: [`entra_agent_identity.md` Query 7](../../../queries/cloud/entra_agent_identity.md). |
| **Lifecycle Hygiene** *(Phase 6, Data Lake only)* | Queries 1 & 5a ([`entra_agent_identity.md`](../../../queries/cloud/entra_agent_identity.md)) | Count of agent identities that are disabled-but-present, lifecycle-expired, or **dormant** (enabled SPN with no runtime activity). In a validated lab, 11 of 14 provisioned identities were dormant. High dormancy = credentialed attack surface with no operational value; feed to decommissioning recommendations. Omitted entirely for Defender-only tenants. |
| **Agent-User / Blueprint Sprawl** *(Phase 6, Data Lake only)* | Queries 2, 3 & 6 ([`entra_agent_identity.md`](../../../queries/cloud/entra_agent_identity.md)) | Agentic-user accounts (orphaned SP/blueprint links), duplicate/re-provisioned identities (same name, multiple SPNs), and multi-tenant blueprints with no verified publisher. Contextualizes the baseline sprawl signal (Q11) with Entra-identity evidence. Omitted for Defender-only tenants. |

---

## Execution Workflow

### Phase 0: Prerequisites

1. Confirm `RunAdvancedHuntingQuery` is available (AgentsInfo is AH-only)
2. Ask user for output format (inline / markdown / both)

### Phase 1: Inventory & Overview (Q1–Q3)

**Run in parallel — no dependencies between queries.**

| Query | Purpose |
|-------|---------|
| Q1 | Global inventory summary (counts, date range, platforms, creators) |
| Q2 | Status and platform breakdown |
| Q3 | Access posture distribution (`appType` / `allowForAllUsers`) |

### Phase 2: Security Risk Analysis (Q4–Q9)

**Run in parallel — no dependencies between queries.**

| Query | Purpose |
|-------|---------|
| Q4 | Broadly-accessible agents (`allowForAllUsers == "true"` detail) |
| Q5 | XPIA email exfiltration risk (email-send connector operations) |
| Q6 | MCP tool inventory across agents |
| Q7 | Knowledge / data source audit |
| Q8 | Hard-coded credential scan |
| Q9 | External endpoint & HTTP risk (connector `serverUrls`) |

### Phase 3: Governance & Trends (Q10–Q16)

**Run in parallel — no dependencies between queries.**

| Query | Purpose |
|-------|---------|
| Q10 | Top creators and naming hygiene |
| Q11 | Agent creation trend over time |
| Q12 | Capability / tools inventory (all operation types) |
| Q13 | Operation-level privilege mapping (sensitive-operation matrix → Capability Privilege Index) |
| Q14 | Deep-manifest coverage (% of fleet with DCM → report coverage banner) |
| Q16 | Orphaned agents — owner departed (`Owners[]` ∖ `IdentityInfo`) → Ownership Governance indicator |

### Phase 4: Score Computation & Report Generation

1. **Compute per-dimension scores** from Phase 1–3 data
2. **Sum dimension scores** for composite Agent Security Score
3. **Generate report** in requested output mode
4. **Report total elapsed time**

### Phase 5: Runtime Correlation (Optional)

`AgentsInfo` describes how agents are **configured**; it does not show whether they are actually **used** or what they do at runtime. To close that gap, correlate the *flagged* configuration set against the `CopilotActivity` table (all-surface AI activity log, available in Advanced Hunting).

**When to run:** After Phase 4, when the user wants to know which *flagged* agents are actually active, which are dormant, or whether a high-risk agent shows runtime behavior.

**🔴 Use a SCOPED lookup, never a fleet-wide join.** A `leftouter`/`inner` join of the full `AgentsInfo` fleet (~15k agents, heavy `RawAgentInfo` dynamic) against `CopilotActivity` (100k+ rows) **times out** the Advanced Hunting endpoint. Instead:

1. **Phase 4 produces a small flagged-agent NAME list** (broadly-accessible from Q4 + sensitive-op agents from Q13 — typically <50 names).
2. **Filter `CopilotActivity` to that name set** with `where AgentName in (FlaggedNames)` — light, no join. See Query 15.

**Join-key pitfall:** `CopilotActivity.AgentId` is a **composite/prefixed string** (e.g., `T_<tenant>.<guid>`, `CopilotStudio.Declarative.T_….gpt.<guid>`, or literals like `AgentBuilder`) — it does **not** equal the clean `AgentsInfo.AgentId` GUID, so ID-based joins return 0 matches. **`AgentName` is the reliable correlation key.** Also note most `CopilotActivity` rows have an **empty** `AgentId`/`AgentName` (general M365 Copilot usage, not declarative-agent-attributed), so runtime attribution is inherently low-coverage — absence from `CopilotActivity` does NOT prove an agent is dormant.

**Two high-value correlations:**
- **Active-and-dangerous** — a flagged agent (broadly accessible / XPIA-exposed / sensitive ops) that ALSO appears in `CopilotActivity` with real interactions → **highest remediation priority** (Query 15).
- **Configured-but-dormant** — a flagged agent absent from `CopilotActivity` over the window → lower urgency, candidate for decommissioning (caveat: attribution gaps above).

> **🔴 Do NOT present a fleet-wide Defender dormancy table.** `CloudAppEvents`/`CopilotActivity` attribute only ~0.3% of the fleet at runtime (validated: **45 of 15,038** agents), so a fleet-wide `AgentsInfo ∖ runtime` leftanti reports ~99% "dormant" as a **telemetry artifact**, not a finding. Fleet-wide dormancy is only valid on the **Data Lake** plane ([`entra_agent_identity.md`](../../../queries/cloud/entra_agent_identity.md) Query 5a, via `UnifiedAgentObservability.SrcAgentId`). On Defender, present the **positive** runtime-attributed set (that file's Query 5b) plus the scoped flagged-list check above — never an inverted fleet-wide dormancy count.

For deeper runtime reconstruction (data accessed, tools invoked, jailbreak detections), hand off to the dedicated query library **`queries/cloud/copilot_activity_investigation.md`** rather than duplicating queries here.

> Keep this phase thin and scoped: the posture skill owns *configuration* assessment; `copilot_activity_investigation.md` owns *runtime* reconstruction. Reference, don't duplicate.

### Phase 6: Entra Agent Identity Enrichment (Optional — Sentinel Data Lake only)

`AgentsInfo` describes how agents are *configured* and *owned*; it does not carry the **Entra identity model** — the service-principal lifecycle, the app-registration (blueprint) governance, or the agentic-user accounts. When Sentinel Data Lake is present, this phase adds that layer.

**When to run:** After the [enrichment-plane probe](#data-plane-detection--selection) returns rows. If the probe fails (Defender-only tenant), **skip this phase entirely** and record the gap in the report banner — the baseline assessment and /100 score are unaffected.

**🔴 All queries here are Data Lake — use `mcp_sentinel-data_query_lake` with `workspaceId: "default"`.** Full tested KQL lives in [`queries/cloud/entra_agent_identity.md`](../../../queries/cloud/entra_agent_identity.md); reference it, don't duplicate.

| Query | Purpose | Feeds |
|-------|---------|-------|
| Query 1 | Agent identity state & lifecycle (enabled, compliance, expiration, provisioning source) | Lifecycle Hygiene indicator |
| Query 2 | Agent user account audit (agentic UPNs, orphaned SP/blueprint links) | Agent-User / Blueprint Sprawl indicator |
| Query 3 | Blueprint app-registration governance (verified publisher, multi-tenant audience, OAuth2 scopes/app-roles) | Agent-User / Blueprint Sprawl indicator |
| Query 4 | Identity graph — Blueprint → Identity → Agent User (Mermaid) | Report visualization |
| Query 5a | 🔴 Dormant / provisioned-but-inactive agents (identity ∖ `UnifiedAgentObservability`) | Lifecycle Hygiene indicator; decommissioning recommendations |
| Query 6 | Duplicate / re-provisioned identities (same name, multiple SPNs) | Agent-User / Blueprint Sprawl indicator |

**Cross-plane enrichment:** join the identity plane back to the baseline on `EntraAgentIdentities.appId == AgentsInfo.EntraAgentID` to attach the **owner/creator** (from `AgentsInfo`, which the Entra tables lack) to each identity finding. This makes a dormant or duplicate identity **actionable** — you can name who owns it.

**Score impact:** Phase 6 feeds the **Lifecycle Hygiene** and **Agent-User / Blueprint Sprawl** [supplementary indicators](#supplementary-indicators-not-summed-into-the-100-score) only — it does **NOT** change the composite /100 score, so a Defender-only tenant receives the same maximum score and comparable ratings.

> The dedicated hunting library **`entra_agent_identity.md`** owns the full identity-plane query set + the Defender-only coverage notes; this phase orchestrates it. Reference, don't duplicate.

---

## Sample KQL Queries

> **All queries below are validated against the live `AgentsInfo` table. Use them exactly as written, substituting only where noted.** Because the rich agent detail lives in the `RawAgentInfo` dynamic column, several queries parse `RawAgentInfo.declarativeCopilotMetadata` (DCM). DCM is present only for the connector-sourced subset of agents — queries that depend on it carry a **coverage caveat**.

### Query 1: Global Inventory Summary

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| extend CreatorId = tostring(RawAgentInfo.creatorId)
| summarize
    UniqueAgents = dcount(AgentId),
    EarliestRecord = min(Timestamp),
    LatestRecord = max(Timestamp),
    Published = countif(PublishedStatus == "Published"),
    Draft = countif(PublishedStatus == "Draft"),
    Deleted = countif(LifecycleStatus == "Deleted"),
    UniquePlatforms = dcount(Platform),
    UniqueCreators = dcount(CreatorId)
```

> **Note:** `UniqueCreators` counts only agents with a populated `RawAgentInfo.creatorId` (the connector-sourced subset). It under-counts true creators; treat it as a lower bound.

### Query 2: Status & Platform Breakdown

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| summarize AgentCount = count() by Platform, PublishedStatus
| order by AgentCount desc
```

> **⚠️ Authentication-type gap:** The deprecated `AIAgentsInfo` table broke this down by `UserAuthenticationType`. `AgentsInfo` has no populated authentication-type column, so this query reports status by **platform** instead. For exposure, use Q3 (access posture) and Q4 (broadly-accessible agents).

### Query 3: Access Posture Distribution

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend AppType = tostring(RawAgentInfo.appType),
         AllowAllUsers = tostring(RawAgentInfo.allowForAllUsers)
| summarize AgentCount = count() by Platform, AppType, AllowAllUsers
| order by AgentCount desc
```

**Interpretation:** `appType == "lob"` (line-of-business) agents are owner-scoped; `appType == "shared"` are shared more widely. `allowForAllUsers == "true"` (any platform) is the broad-exposure signal — these reach every tenant user. This replaces the old `AccessControlPolicy` distribution.

### Query 4: Broadly-Accessible Agents

🔴 **Security-critical query** — agents with `allowForAllUsers == "true"` are accessible to all tenant users. This is the closest available proxy for the old "unauthenticated / Any access" exposure signal (see the [authentication-type gap](#-columns-that-are-empty--unreliable-in-current-telemetry)).

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend AllowAllUsers = tostring(RawAgentInfo.allowForAllUsers),
         AppType = tostring(RawAgentInfo.appType),
         CreatorId = tostring(RawAgentInfo.creatorId)
| where AllowAllUsers == "true"
| project Name, Platform, PublishedStatus, AppType, CreatorId, AgentId, CreatedDateTime, Description
| order by PublishedStatus asc, CreatedDateTime desc
```

**Post-processing:** For each broadly-accessible agent, note:
- Is it Published (active) or Draft?
- Cross-reference with Q5 (email-capable) and Q7 (knowledge sources) for compounding XPIA / reconnaissance risk.

**🔴 Capability Reconnaissance Risk ([Attack Scenario 3](#attack-scenario-3-capability-reconnaissance-on-unauthenticated-agent)):** Broadly-accessible agents are prime targets for adversarial probing. Published agents with knowledge sources containing customer/internal data are the highest-priority findings.

### Query 5: XPIA Email Exfiltration Risk (Email-Capable Agents)

🔴 **Security-critical query** — agents that can send email via a connector operation. A successful prompt-injection (XPIA) attack could direct the agent to exfiltrate data to arbitrary recipients.

> **Coverage caveat:** Detects email-send operations declared in `RawAgentInfo.declarativeCopilotMetadata` (DCM). DCM is present only for the connector-sourced agent subset. The old `IsGenerativeOrchestrationEnabled` flag and action-level `inputs` (AI-controlled vs hardcoded recipient) are **not available** in `AgentsInfo` — this query identifies *capability*, not orchestration mode.

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(tostring(RawAgentInfo.declarativeCopilotMetadata))
| mv-expand DCM = RawAgentInfo.declarativeCopilotMetadata
| mv-expand Action = DCM.actions
| mv-expand Api = Action.apis
| mv-expand Op = Api.operations
| extend OperationId = tostring(Op.operationId)
| where OperationId has "Send an email" or OperationId has "SendEmail"
| extend AllowAllUsers = tostring(RawAgentInfo.allowForAllUsers),
         CreatorId = tostring(RawAgentInfo.creatorId)
| summarize EmailOperations = make_set(OperationId)
    by AgentId, Name, Platform, PublishedStatus, AllowAllUsers, CreatorId
| order by AllowAllUsers desc, PublishedStatus asc
```

**Post-processing:**
- `AllowAllUsers == "true"` → email-capable **and** broadly accessible = **highest XPIA risk** (any tenant user can trigger the chain).
- **Cross-reference with Q7:** an email-capable agent that also has knowledge/data sources is the **documented XPIA exfiltration pattern** ([Attack Scenario 2](#attack-scenario-2-prompt-injection-via-shared-document--email-exfiltration-xpia)). Prioritize these for Defender Runtime Protection.

**🔴 Attack Scenario Mapping:** This query detects the agent-configuration precondition (email-send capability) for two documented scenarios — [Malicious Instruction Injection via Event Trigger](#attack-scenario-1-malicious-instruction-injection-via-event-triggered-workflow) and [Prompt Injection via Shared Document](#attack-scenario-2-prompt-injection-via-shared-document--email-exfiltration-xpia). Broadly-accessible email-capable agents (no access restriction + email) are the most dangerous.

### Query 6: MCP Tool Inventory Across Agents

🟠 **Governance query** — MCP servers give agents access to external systems, Graph API, Sentinel data, and more. Uncontrolled MCP proliferation increases the attack surface. `AgentsInfo` exposes a dedicated `McpServers` column (cleaner than the old tool-detail parse).

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where array_length(McpServers) > 0
| mv-expand Mcp = McpServers
| extend McpName = tostring(Mcp.name)
| extend CreatorId = tostring(RawAgentInfo.creatorId),
         AllowAllUsers = tostring(RawAgentInfo.allowForAllUsers)
| summarize McpServerList = make_set(McpName), McpToolCount = dcount(McpName)
    by AgentId, Name, Platform, CreatorId, AllowAllUsers
| order by McpToolCount desc
```

**MCP server distribution** (which servers appear on the most agents):

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where array_length(McpServers) > 0
| mv-expand Mcp = McpServers
| summarize AgentCount = dcount(AgentId) by McpServer = tostring(Mcp.name)
| order by AgentCount desc
```

> **Note:** `McpServers` is flat (`{name, description}` only) — no server URLs or credential config. For external MCP **endpoint** detail (host/scheme/port), use Q9, which parses `RemoteMCPServer` `serverUrls` from DCM.

### Query 7: Knowledge / Data Source Audit

🟡 **Data exposure query** — identifies what data sources agents declare. In `AgentsInfo`, declared sources appear in the `DeclaredDataSources` column as an array of source/filename strings.

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where array_length(DeclaredDataSources) > 0
| mv-expand DS = DeclaredDataSources
| extend DataSource = tostring(DS)
| extend AllowAllUsers = tostring(RawAgentInfo.allowForAllUsers),
         CreatorId = tostring(RawAgentInfo.creatorId)
| summarize DataSources = make_set(DataSource), SourceCount = dcount(DataSource)
    by AgentId, Name, Platform, AllowAllUsers, CreatorId
| order by SourceCount desc
```

**Post-processing — flag high-risk combinations:**
- Data sources + `allowForAllUsers == "true"` → internal data potentially exposed broadly.
- Any data source on an agent that is also email-capable (Q5) → XPIA exfiltration chain.

> **Coverage caveat:** `DeclaredDataSources` is sparse and stores source **names/filenames** (e.g., `Priority-Banking-Policy.docx`), not the richer `$kind`/site structure the old `KnowledgeDetails` column held. Source *type* classification (SharePoint vs public site vs federated) is not reliably available — report the declared source names and flag broadly-accessible agents that carry any.
>
> **For actual (runtime) SharePoint sites accessed by agents — not just declared config —** see `copilot_activity_investigation.md` Queries 14–16: `CopilotActivity.AccessedResources.SiteUrl` gives the agent-attributed site list, and `CloudAppEvents` (filtered to the validated `Power Virtual Agents` / `Enterprise Copilot Platform` client-app fingerprint) gives the full SharePoint audit trail (`ClientIP`, exact file, `FileDownloaded` granularity) for the same OBO access.

**🔴 Document Injection Risk ([Attack Scenario 2](#attack-scenario-2-prompt-injection-via-shared-document--email-exfiltration-xpia)):** Data sources are the primary vector for indirect prompt injection (XPIA). **Cross-reference with Q5:** agents that combine declared data sources with an email-send operation are the textbook XPIA exfiltration pattern — flag these as **highest priority** in the Knowledge Source Risk dimension.

### Query 8: Hard-Coded Credential Scan

🔴 **Security-critical query** — scans agent `Instructions` and the connector metadata in `RawAgentInfo` for patterns matching API keys, JWTs, Basic auth headers, and embedded credentials.

```kql
let suspicious_patterns = @"(AKIA[0-9A-Z]{16})|(AIza[0-9A-Za-z_\-]{35})|(xox[baprs]-[0-9a-zA-Z]{10,48})|(ghp_[A-Za-z0-9]{36,59})|(sk_(live|test)_[A-Za-z0-9]{24})|(SG\.[A-Za-z0-9]{22}\.[A-Za-z0-9]{43})|(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)|(Authorization\s*:\s*Basic\s+[A-Za-z0-9=:+]+)|([A-Za-z]+:\/\/[^\/\s]+:[^\/\s]+@[^\/\s]+)";
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend Haystack = strcat(tostring(Instructions), " ", tostring(RawAgentInfo.declarativeCopilotMetadata))
| where Haystack matches regex suspicious_patterns
| project Name, Platform, PublishedStatus,
          CreatorId = tostring(RawAgentInfo.creatorId), AgentId
```

**Post-processing:**
- Published agents with credential matches = **immediate remediation required**.
- Recommend Azure Key Vault + environment variables instead of hard-coded secrets.
- The JWT (`eyJ...`) and `url://user:pass@host` patterns can false-positive on example payloads — manually review each match.

### Query 9: External Endpoint & HTTP Risk

🟠 **Network risk query** — inventories the external hosts that agent connectors reach, and flags insecure schemes or non-standard ports. External endpoints are declared in DCM `apis[].serverUrls` for `OpenApi` and `RemoteMCPServer` connector types (these are populated; `api_action` Power Platform connectors abstract the URL and are not covered).

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(tostring(RawAgentInfo.declarativeCopilotMetadata))
| mv-expand DCM = RawAgentInfo.declarativeCopilotMetadata
| mv-expand Action = DCM.actions
| mv-expand Api = Action.apis
| extend ApiType = tostring(Api.type)
| where ApiType in ("OpenApi", "RemoteMCPServer")
| mv-expand Url = Api.serverUrls
| extend Url = tostring(Url)
| where isnotempty(Url)
| extend Host = tostring(parse_url(Url).Host),
         Port = tostring(parse_url(Url).Port),
         Scheme = tostring(parse_url(Url).Scheme)
| extend NonStandardPort = isnotempty(Port) and Port !in ("443", "80", ""),
         InsecureScheme = Scheme != "https"
| project Name, Platform, ApiType, Scheme, Host, Port, Url,
          NonStandardPort, InsecureScheme,
          AllowAllUsers = tostring(RawAgentInfo.allowForAllUsers)
| order by NonStandardPort desc, InsecureScheme desc, Host asc
```

**Post-processing:**
- `InsecureScheme == true` (non-HTTPS) or `NonStandardPort == true` → review the connector; data may transit insecurely.
- Unfamiliar external hosts on broadly-accessible agents (`AllowAllUsers == "true"`) → highest priority.

> **Coverage caveat:** Only `OpenApi` + `RemoteMCPServer` connectors declare `serverUrls`. Power Platform `api_action` connectors (the majority) do not expose a URL here, so their destinations are not inventoried by this query. The old topic-level `HttpRequestAction` parsing is not applicable to `AgentsInfo`.

### Query 10: Top Creators & Naming Hygiene

👥 **Governance query** — identifies prolific agent creators and names lacking descriptiveness. Creator is a GUID in `RawAgentInfo.creatorId`; resolve to UPN via an `IdentityInfo` join.

```kql
let IdMap = materialize(IdentityInfo
    | where isnotempty(AccountObjectId) and isnotempty(AccountUpn)
    | distinct AccountObjectId, AccountUpn);
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend CreatorId = tostring(RawAgentInfo.creatorId)
| where isnotempty(CreatorId)
| join kind=leftouter IdMap on $left.CreatorId == $right.AccountObjectId
| extend CreatorUpn = coalesce(AccountUpn, CreatorId)
| summarize
    AgentCount = count(),
    PublishedCount = countif(PublishedStatus == "Published"),
    GenericNameCount = countif(Name in~ ("Agent", "agent", "Test", "test", "New Agent")),
    NoDescriptionCount = countif(isempty(Description)),
    AgentNames = make_set(Name, 10)
    by CreatorUpn
| order by AgentCount desc
| take 20
```

> **Coverage caveat:** Only agents with a populated `RawAgentInfo.creatorId` are attributed. Creators whose GUID does not resolve in `IdentityInfo` fall back to the raw GUID. A single creator with a very high `AgentCount` is a sprawl signal worth investigating.

### Query 11: Agent Creation Trend

📈 **Trend query** — shows agent creation velocity over time to detect sprawl acceleration.

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(CreatedDateTime)
| summarize AgentsCreated = count() by bin(CreatedDateTime, 7d)
| order by CreatedDateTime asc
```

### Query 12: Full Capability / Tools Inventory

🛠️ **Tools governance query** — catalogs the operations agents can invoke across all connector types, to understand the full capability surface. Parses DCM operations (`operationId` + API `type`).

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(tostring(RawAgentInfo.declarativeCopilotMetadata))
| mv-expand DCM = RawAgentInfo.declarativeCopilotMetadata
| mv-expand Action = DCM.actions
| mv-expand Api = Action.apis
| mv-expand Op = Api.operations
| extend OperationId = tostring(Op.operationId), ApiType = tostring(Api.type)
| where isnotempty(OperationId)
| summarize AgentCount = dcount(AgentId), Agents = make_set(Name, 5) by OperationId, ApiType
| order by AgentCount desc
```

**Alternative for non-DCM agents** — the flat `DeclaredTools` column (`{type, name}`) covers agents without DCM:

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where array_length(DeclaredTools) > 0
| mv-expand Tool = DeclaredTools
| summarize AgentCount = dcount(AgentId)
    by ToolType = tostring(Tool.type), ToolName = tostring(Tool.name)
| order by AgentCount desc
```

> **Coverage caveat:** The DCM query yields deep operation-level detail but only for the connector-sourced subset. The `DeclaredTools` fallback is broader but flatter (tool name/type only, no operation IDs). Run both for the fullest picture.

### Query 13: Operation-Level Privilege Mapping

🔐 **Privilege query** — buckets every declared operation into a **sensitivity category** (mail-send, directory-write, data-write, messaging, security-tooling, read/other) to surface where write/exfiltration capability concentrates. Feeds the **Capability Privilege Index** supplementary indicator.

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(tostring(RawAgentInfo.declarativeCopilotMetadata))
| mv-expand DCM = RawAgentInfo.declarativeCopilotMetadata
| mv-expand Action = DCM.actions
| mv-expand Api = Action.apis
| mv-expand Op = Api.operations
| extend OperationId = tostring(Op.operationId)
| where isnotempty(OperationId)
| extend PrivilegeCategory = case(
    OperationId has_any ("Send an email", "SendEmail", "Send email"), "Mail-Send",
    OperationId has_any ("AddUserToGroup", "RemoveMember", "UpdatePerson", "UpdateOrganisation", "Create user", "Delete user", "Update user", "Assign"), "Directory-Write",
    OperationId has_any ("unbound action", "Create a row", "Update a row", "Delete a row", "Create record", "Update record"), "Data-Write",
    OperationId has_any ("Post message", "Post a message", "Send message", "Create chat", "post in a chat"), "Messaging",
    OperationId has_any ("Security Copilot", "Sentinel"), "Security-Tooling",
    "Other/Read")
| summarize AgentCount = dcount(AgentId) by PrivilegeCategory
| order by AgentCount desc
```

**Capability Privilege Index** — distinct agents holding ≥1 *sensitive* (write/send) operation, split by broad access:

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(tostring(RawAgentInfo.declarativeCopilotMetadata))
| extend AllowAllUsers = tostring(RawAgentInfo.allowForAllUsers)
| mv-expand DCM = RawAgentInfo.declarativeCopilotMetadata
| mv-expand Action = DCM.actions
| mv-expand Api = Action.apis
| mv-expand Op = Api.operations
| extend OperationId = tostring(Op.operationId)
| where OperationId has_any ("Send an email", "SendEmail", "AddUserToGroup", "RemoveMember", "UpdatePerson", "UpdateOrganisation", "unbound action", "Create a row", "Update a row", "Delete a row", "Post message", "post in a chat")
| summarize SensitiveAgents = dcount(AgentId),
            BroadAndSensitive = dcountif(AgentId, AllowAllUsers == "true")
```

> **Interpretation:** `BroadAndSensitive > 0` is a direct privilege-abuse signal — a broadly-accessible agent that can write to the directory, write data, or send mail. These agents justify maxing the Broad Access and/or XPIA dimensions. Tune the operation keyword lists to your tenant's connector set.

### Query 14: Deep-Manifest Coverage (Report Banner)

📊 **Coverage query** — reports what fraction of the fleet carries the deep `declarativeCopilotMetadata` (DCM) that the XPIA, endpoint, and capability queries depend on. **Run this every report** and surface the result as a banner so the analyst knows what was *not* fully inspected.

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| summarize Total = count(),
            WithDCM = countif(isnotempty(tostring(RawAgentInfo.declarativeCopilotMetadata))),
            WithInstructions = countif(isnotempty(Instructions)),
            WithObservabilityID = countif(isnotempty(ObservabilityID)),
            WithEntraAgentID = countif(isnotempty(EntraAgentID))
| extend DcmCoveragePct = round(100.0 * WithDCM / Total, 1),
         InstrCoveragePct = round(100.0 * WithInstructions / Total, 1),
         ObsIdPct = round(100.0 * WithObservabilityID / Total, 1),
         EntraIdPct = round(100.0 * WithEntraAgentID / Total, 1)
```

> **Why both ID columns:** `ObservabilityID` is near-universally populated (~100%) and is the natural runtime-correlation handle; `EntraAgentID` is sparse (only agents provisioned with an Entra Agent ID). Report both so the analyst knows which runtime/identity correlations are feasible.

### Query 15: Runtime Correlation — Active-and-Dangerous (Scoped)

🎯 **Runtime query (Phase 5)** — confirms which *flagged* agents are actually active. **Scoped by name list — no fleet-wide join** (see Phase 5 for why a full join times out). Populate `FlaggedNames` from the Q4 broadly-accessible and Q13 sensitive-op results.

```kql
let FlaggedNames = dynamic(["<broadly-accessible or sensitive-op agent names from Q4/Q13>"]);
CopilotActivity
| where TimeGenerated > ago(7d)
| where AgentName in (FlaggedNames)
| summarize Interactions = count(),
            DistinctUsers = dcount(ActorUserId),
            LastSeen = max(TimeGenerated),
            SrcIPs = dcount(SrcIpAddr) by AgentName
| order by Interactions desc
```

> **Interpretation:** A flagged agent appearing here with real `Interactions` is **active-and-dangerous** — prioritize for remediation over dormant flagged agents. **Join key is `AgentName`** (`CopilotActivity.AgentId` is a composite prefixed string that does NOT equal `AgentsInfo.AgentId`). Absence here does not prove dormancy — most `CopilotActivity` rows are unattributed (empty `AgentName`). `AIModelName` is sparse in this table; do not rely on it for model inventory.

---

### Query 16: Orphaned Agents — Owner Departed

👥 **Governance query (Phase 3)** — agents whose assigned **owner has left the organization**. Telemetry equivalent of the Agent 365 **"Agents without owners"** registry card, but **cross-platform** (the admin-center card is Agent-Builder-scoped and materially under-reports). AH-native — runs for **every tenant**. Feeds the **Ownership Governance** supplementary indicator.

```kql
// Owner lives in AgentsInfo.Owners[] (populated for shared agents); "departed" = GUID no longer a current directory user.
let CurrentUsers = IdentityInfo | where isnotempty(AccountObjectId) | distinct AccountObjectId;
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| mv-expand OwnerGuid = parse_json(tostring(Owners)) to typeof(string)
| where isnotempty(OwnerGuid)
| where OwnerGuid !in (CurrentUsers)          // owner no longer in directory = departed
| summarize OrphanedAgents = dcount(AgentId), DepartedOwners = dcount(OwnerGuid),
            PublishedOrphans = countif(PublishedStatus == "Published") by Platform
| order by OrphanedAgents desc
```

> **Interpretation:** Each row is a platform's count of agents whose owner has departed. Prioritize `PublishedOrphans` (live + unowned). **`IdentityInfo`-absence is a proxy for "departed"** — it reliably catches hard-deleted creators but may also include disabled/external/unsynced identities, so corroborate a specific owner before blocking/deleting. Keys on `Owners[]` (shared agents); it does **not** attempt "no owner assigned at all" — `AgentsInfo.Owners`/`creatorId` are too sparse for that (blank ≠ no owner; use the Agent Registry / Graph `/servicePrincipals/{id}/owners` for that signal). Canonical cross-platform detail + caveats: [`entra_agent_identity.md` Query 7](../../../queries/cloud/entra_agent_identity.md).

---

## Output Modes

### Mode 1: Inline Chat Summary

Render the full analysis directly in the chat response. Best for quick review.

### Mode 2: Markdown File Report

Save a comprehensive report to disk at:
```
reports/ai-agent-posture/AI_Agent_Posture_Report_YYYYMMDD_HHMMSS.md
```

### Mode 3: Both

Generate the markdown file AND provide an inline summary in chat.

**Always ask the user which mode before generating output.**

---

## Inline Report Template

Render the following sections in order. Omit sections only if explicitly noted as conditional.

> **🔴 URL Rule:** All hyperlinks in the report MUST be copied verbatim from the [URL Registry](#-url-registry--canonical-links-for-report-generation) above. Do NOT generate, recall from memory, or paraphrase any URL. If a needed URL is not in the registry, use plain text (no hyperlink).

````markdown
# 🤖 AI Agent Security Posture Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Data Source:** AgentsInfo (Advanced Hunting)
**Analysis Period:** <EarliestRecord> → <LatestRecord>
**Platforms:** <list discovered Platform values>

---

> 📊 **Deep-Manifest Coverage (Q14):** `<WithDCM>/<Total>` agents (**<DcmCoveragePct>%**) carry `declarativeCopilotMetadata` — the XPIA, external-endpoint, and capability findings below cover **only this subset**. Instructions present on **<InstrCoveragePct>%**, ObservabilityID on **<ObsIdPct>%** (runtime-correlation handle), EntraAgentID on **<EntraIdPct>%**. The remaining `<Total - WithDCM>` agents were inventoried but not deeply inspected.

---

## Executive Summary

<2-3 sentences: total agents, key risk findings, overall score>

**Overall Risk Rating:** 🔴/🟠/🟡/✅ <RATING> (<Score>/100)

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Total Agents (non-deleted) | <N> |
| Published Agents | <N> |
| Draft Agents | <N> |
| Platforms Represented | <N> |
| Resolved Creators (lower bound) | <N> |
| Broadly-Accessible Agents (allowForAllUsers) | <N> |
| Agents with MCP Servers | <N> |
| Agents with Declared Data Sources | <N> |
| Email-Capable Agents (XPIA Risk) | <N> |

> ℹ️ **Coverage note:** Creator and capability metrics are derived from `RawAgentInfo` and `declarativeCopilotMetadata`, which are sparsely populated. Counts marked "lower bound" reflect only agents with the relevant field present — see per-section caveats.

---

## 🔓 Access Posture

> **Authentication-type gap:** `AgentsInfo` has no equivalent to the old `UserAuthenticationType` (None/Microsoft/Custom). The `ToolsAuthenticationType` column is effectively empty in practice. Access exposure is assessed via the `RawAgentInfo.allowForAllUsers` governance signal instead — a **proxy for broad exposure, not an authentication state**.

### Access Distribution (Q3)
| App Type | Allow-All-Users | Count |
|----------|-----------------|-------|
| <appType> | <true/false> | <N> |

### 🔴 Broadly-Accessible Agents (Q4)

<If Q4 returns results:>
| Agent Name | Platform | App Type | Published | Created |
|------------|----------|----------|-----------|---------|
| <name> | <platform> | <appType> | <status> | <date> |

<If Q4 returns 0:>
✅ No broadly-accessible agents (`allowForAllUsers == "true"`) detected.

---

## 📧 XPIA Email Exfiltration Risk

<If Q5 returns results:>
| Agent Name | Platform | Email Operation | Broadly Accessible |
|------------|----------|-----------------|--------------------|
| <name> | <platform> | <operationId> | 🔴 Yes / 🟢 No |

**Risk Assessment:**
- 🔴 Email-capable agents can be exploited via XPIA to exfiltrate data, especially when combined with declared data sources (Q7).
- ⚠️ Recommendation: Review recipient controls; apply Power Platform DLP and Defender Runtime Protection.

> **Coverage caveat:** Email capability is detected from DCM `operations[].operationId` (e.g., "Send an email", "SendEmail"). There is no longer a GenAI-orchestration flag or an `inputs` field, so AI-controlled-vs-hardcoded recipient distinction is **not available** — treat all email-capable agents as candidates. Only the DCM-bearing subset is covered.

<If Q5 returns 0:>
✅ No email-capable agents detected in the DCM-bearing subset.

---

## 🛠️ MCP Server Exposure

<If Q6 returns results:>
| Agent Name | Platform | MCP Servers | Broadly Accessible |
|------------|----------|-------------|--------------------|
| <name> | <platform> | <server list> | <yes/no> |

**MCP Server Distribution:**
| MCP Server | Agent Count |
|------------|-------------|
| <server> | <N> |

<If Q6 returns 0:>
✅ No agents with MCP servers detected.

> **Coverage caveat:** The `McpServers` column is flat (`{name, description}` only) — no server URLs, credential config, or transport detail. Non-HTTPS/hardcoded-cred MCP detection from the old schema is not possible here.

> **Dimension note:** MCP exposure and the External Endpoint findings (below) both feed the single **Tool & Endpoint Exposure** score dimension. Any insecure scheme, non-standard port, or external endpoint on a broadly-accessible agent escalates that dimension to High regardless of MCP count.

---

## 📚 Declared Data Source Exposure

<If Q7 returns results:>
| Agent Name | Platform | Data Sources | Broadly Accessible |
|------------|----------|--------------|--------------------|
| <name> | <platform> | <source names> | <yes/no> |

**⚠️ High-Risk Combinations:**
<List agents with declared data sources + allowForAllUsers == "true", and agents combining data sources with email capability (Q5)>

<If Q7 returns 0:>
✅ No declared data sources found on any agents.

> **Coverage caveat:** `DeclaredDataSources` stores source **names/filenames** only — source *type* classification (SharePoint vs public site vs federated) is not available.

---

## 🔑 Credential Hygiene

<If Q8 returns results:>
🔴 **Hard-coded credential patterns detected in <N> agent(s):**
| Agent Name | Platform | Status | Creator |
|------------|----------|--------|---------|
| <name> | <platform> | <status> | <creatorId/upn> |

⚠️ **Recommendation:** Move secrets to Azure Key Vault; use environment variables at runtime.

<If Q8 returns 0:>
✅ No hard-coded credential patterns detected in agent instructions or connector metadata.

---

## 🌐 External Endpoint & HTTP Risk

<If Q9 returns results:>
| Agent | API Type | Scheme | Host | Port | Insecure | Non-Standard Port |
|-------|----------|--------|------|------|----------|-------------------|
| <name> | <OpenApi/RemoteMCPServer> | <scheme> | <host> | <port> | 🔴/🟢 | 🔴/🟢 |

<If Q9 returns 0:>
✅ No external endpoints with insecure schemes or non-standard ports detected.

> **Coverage caveat:** Only `OpenApi` + `RemoteMCPServer` connectors declare `serverUrls`. Power Platform `api_action` connectors do not expose destination URLs.

---

## 👥 Creator Governance

### Top Creators
| Creator | Agents | Published | Generic Names | No Description |
|---------|--------|-----------|---------------|----------------|
| <upn/creatorId> | <N> | <N> | <N> | <N> |

### Naming Hygiene
- Agents with generic names ("Agent", "Test"): <N>
- Agents with no description: <N>

> **Coverage caveat:** Only agents with a populated `RawAgentInfo.creatorId` are attributed; GUIDs unresolved in `IdentityInfo` fall back to the raw GUID.

### Ownerless / Orphaned Agents (Q16)
- **Owner departed** (assigned owner left the org): **<N>** agents across **<P>** platforms (**<PublishedN>** Published)
- Most affected platform: **<Platform>** (<N>)

> The Agent 365 admin-center *"Agents without owners"* card is Agent-Builder-scoped; this telemetry view is **cross-platform** and typically surfaces materially more orphaned agents (validated ~30× in one large tenant). Owner-departed = **MITRE T1098** governance risk (live, credentialed, unowned). Corroborate `IdentityInfo`-absence (may include disabled/external identities) before blocking or reassigning.

---

## 📈 Agent Creation Trend

<ASCII bar chart or summary table of Q11 results — weekly agent creation counts>

---

## 🛠️ Full Capability / Tools Inventory

| Operation / Tool | API / Tool Type | Agent Count | Example Agents |
|------------------|-----------------|-------------|----------------|
| <operationId/name> | <type> | <N> | <agent names> |

---

## 🔐 Capability Privilege Index (Supplementary — not summed into score)

**Operation sensitivity distribution (Q13):**
| Privilege Category | Agent Count |
|--------------------|-------------|
| Mail-Send | <N> |
| Directory-Write | <N> |
| Data-Write | <N> |
| Messaging | <N> |
| Security-Tooling | <N> |
| Other/Read | <N> |

**Index:** <SensitiveAgents> agent(s) hold ≥1 sensitive (write/send) operation; **<BroadAndSensitive>** of those are also broadly accessible (`allowForAllUsers == "true"`).

<If BroadAndSensitive > 0:>
🔴 **<BroadAndSensitive> broadly-accessible agent(s) with sensitive write/send capability** — direct privilege-abuse exposure. These justify maxing the Broad Access and/or XPIA dimensions.

<If BroadAndSensitive == 0:>
✅ No broadly-accessible agents hold sensitive write/send operations (within the DCM-bearing subset).

> Supplementary indicator — provides privilege context but is **not** added to the /100 composite. Coverage limited to the DCM-bearing subset (see banner).

---

## 🎯 Runtime Correlation — Active-and-Dangerous (Q15, Optional)

<If Phase 5 was run — flagged agents correlated against CopilotActivity:>
| Agent Name | Interactions | Distinct Users | Source IPs | Last Seen |
|------------|--------------|----------------|------------|-----------|
| <name> | <N> | <N> | <N> | <date> |

🔴 **Active-and-dangerous:** Flagged agents (broadly accessible / sensitive ops) confirmed active at runtime — prioritize for remediation over dormant flagged agents.

<If no flagged agents appear in CopilotActivity:>
✅ No flagged agents showed runtime activity in the window. *(Caveat: most `CopilotActivity` rows are unattributed — absence does not prove dormancy.)*

> Scoped name-based lookup (`AgentName` key). Runtime attribution is inherently low-coverage; this section confirms presence, not absence.

---

## Agent Security Score Card

```
┌──────────────────────────────────────────────────────┐
│          AGENT SECURITY SCORE: <NN>/100              │
│              Rating: <EMOJI> <RATING>                │
├──────────────────────────────────────────────────────┤
│ Broad Access     [<bar>] <N>/20  (<detail>)          │
│ XPIA Email Risk  [<bar>] <N>/20  (<detail>)          │
│ Tool & Endpt Expo[<bar>] <N>/20  (<detail>)          │
│ Data Source Risk [<bar>] <N>/20  (<detail>)          │
│ Credential Hygn  [<bar>] <N>/20  (<detail>)          │
├──────────────────────────────────────────────────────┤
│ Supplementary (not scored):                          │
│  Capability Privilege Index: <S> sensitive / <B> broad│
│  Deep-Manifest Coverage:     <DcmCoveragePct>%        │
└──────────────────────────────────────────────────────┘
```

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| <emoji> **<Factor>** | <Evidence-based finding> |

---

## Recommendations

> **Key mitigation — Runtime:** For all high-risk agents, recommend enabling **Microsoft Defender Runtime Protection** — webhook-based real-time inspection that can block malicious tool invocations before execution. See [Real-time agent protection during runtime](https://learn.microsoft.com/en-us/defender-cloud-apps/real-time-agent-protection-during-runtime).

> **Key mitigation — Governance:** For fleet-wide governance gaps (sprawl, missing auth, uncontrolled tools), recommend adopting **[Microsoft Agent 365](https://www.microsoft.com/en-us/microsoft-365/blog/2025/11/18/microsoft-agent-365-the-control-plane-for-ai-agents/)** as the enterprise control plane — providing centralized Registry (inventory + quarantine), Access Control (Entra agent IDs + Policy Templates), Visualization (agent ↔ resource mapping), and Security (Defender + Purview integration).

1. <emoji> **<Priority action>** — <evidence and rationale>
2. ...

---

## Appendix: Query Execution Summary

| Query | Description | Records | Time |
|-------|-------------|---------|------|
| Q1 | Global Inventory | <N> | <time> |
| Q2 | Status & Auth Breakdown | <N> | <time> |
| ... | ... | ... | ... |
| Q13 | Operation-Level Privilege Mapping | <N> | <time> |
| Q14 | Deep-Manifest Coverage | <N> | <time> |
| Q15 | Runtime Correlation (scoped, optional) | <N> | <time> |
````

---

## Markdown File Report Template

When outputting to markdown file, use the same structure as the Inline Report Template above, saved to:

```
reports/ai-agent-posture/AI_Agent_Posture_Report_YYYYMMDD_HHMMSS.md
```

Include the following additional sections in the file report that are omitted from inline:

1. **Full agent detail table** (all non-deleted agents with key fields)
2. **Per-platform breakdown** (agent counts and creators by `Platform`)
3. **Complete data source listing** (every declared source name, not just examples)
4. **Complete MCP agent listing** (every MCP agent with full server list)
5. **Raw query references** — note that full query definitions are in this SKILL.md file

### File Report Header

```markdown
# AI Agent Security Posture Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Data Source:** AgentsInfo (Advanced Hunting)
**Analysis Period:** <EarliestRecord> → <LatestRecord> (<N> days)
**Platforms:** <list discovered Platform values>
**Total Agents:** <N> (Published: <N>, Draft: <N>)

---

> 📊 **Deep-Manifest Coverage (Q14):** `<WithDCM>/<Total>` agents (**<DcmCoveragePct>%**) carry `declarativeCopilotMetadata`; XPIA/endpoint/capability findings cover only this subset. ObservabilityID **<ObsIdPct>%**, EntraAgentID **<EntraIdPct>%**.

---
```

Include the **Capability Privilege Index** and (if Phase 5 ran) **Runtime Correlation** sections from the inline template in the file report as well.

---

## Known Pitfalls

### 1. AgentsInfo Is Advanced Hunting Only

**Problem:** The `AgentsInfo` table does NOT exist in Sentinel Data Lake. Querying via `mcp_sentinel-data_query_lake` returns `SemanticError: Failed to resolve table`.

**Solution:** Always use `RunAdvancedHuntingQuery`. The table has 30-day retention in AH.

### 2. Multiple Records Per Agent (State Snapshots)

**Problem:** The table logs configuration snapshots over time. Querying without deduplication returns inflated counts and duplicate agent entries.

**Solution:** Always use `| summarize arg_max(Timestamp, *) by AgentId` to get the latest state per agent before any analysis. Note `AgentId` is a **guid** and the column is `Name`/`Description` (not `AgentName`/`AgentDescription` as some docs state).

### 3. RawAgentInfo Is the Real Detail Source

**Problem:** The normalized columns (`DeclaredTools`, `McpServers`, `DeclaredDataSources`, `Owners`, `Capabilities`) are **sparsely populated and flat**. The rich governance/configuration detail lives in the `RawAgentInfo` dynamic column (populated for ~all agents) and, for the connector-sourced subset, in `RawAgentInfo.declarativeCopilotMetadata` (DCM).

**Solution:** For creator (`RawAgentInfo.creatorId`), broad access (`RawAgentInfo.allowForAllUsers`), app type (`RawAgentInfo.appType`), and deep capability/endpoint detail, parse `RawAgentInfo`. `RawAgentInfo` is dynamic — no double-parse needed; access nested keys directly with `tostring(RawAgentInfo.key)`.

### 4. Entra Identity Enrichment Is Data Lake Only (Phase 6)

**Problem:** The `EntraAgentIdentities` / `EntraAgentIdentityBlueprints` / `EntraAgentUsers` tables are **Sentinel Data Lake system tables** — they do NOT exist in Advanced Hunting. A Defender-only tenant has no access to them, and querying them via `RunAdvancedHuntingQuery` or with a workspace GUID fails.

**Solution:** Always [probe first](#data-plane-detection--selection) and query with `mcp_sentinel-data_query_lake` + `workspaceId: "default"`. Skip Phase 6 gracefully when absent and note it in the report banner. Additional Entra-table pitfalls (snapshot dedup with `arg_max(TimeGenerated,*) by id`, `id == appId`, dynamic `lifecycle`/`tags`, blueprint table containing non-agent platform apps, no native owner field) are documented in [`queries/cloud/entra_agent_identity.md`](../../../queries/cloud/entra_agent_identity.md). Owner/creator is NOT in these tables — cross-reference `AgentsInfo` (`EntraAgentIdentities.appId == AgentsInfo.EntraAgentID`) or Graph `/servicePrincipals/{id}/owners`.

### 4. declarativeCopilotMetadata (DCM) Covers Only a Subset

**Problem:** Deep capability queries (Q5 email, Q9 endpoints, Q12 operations) depend on `RawAgentInfo.declarativeCopilotMetadata`, which is present for only ~10% of Copilot Studio agents (the connector-sourced subset). The majority have only a shallow manifest.

**Solution:** Always state the coverage caveat in reports. DCM path: `declarativeCopilotMetadata[].actions[].apis[]` with `.type` (OpenApi/RemoteMCPServer/api_action), `.serverUrls[]`, and `.operations[].operationId`. Results from these queries are a **floor, not a complete inventory**.

### 5. Authentication-Type Detection Has No Equivalent

**Problem:** The old `UserAuthenticationType` (None/Microsoft/Custom) is gone. The `ToolsAuthenticationType` column exists in schema but is effectively empty (~100% blank). There is **no way** to classify agents as "unauthenticated" the way the old skill did.

**Solution:** Use `RawAgentInfo.allowForAllUsers == "true"` as a **broad-exposure proxy** (documented as a proxy, NOT an authentication state). Never claim an agent is "unauthenticated" — say "broadly accessible".

### 6. Many Schema Columns Are Empty in Practice

**Problem:** `ToolsAuthenticationType`, `Availability`, `Endpoints`, `Triggers`, `Permissions`, and `Model` are present in the schema but empty/null in practice. Queries built on them silently return 0 rows.

**Solution:** Do not build core logic on these columns. Validate population with a quick `summarize countif(isnotempty(<col>))` before relying on a column. `LifecycleStatus` is blank for active agents (only `Deleted` is populated) — `LifecycleStatus != "Deleted"` correctly passes blanks.

### 7. creatorId Is a GUID — Join IdentityInfo for UPN

**Problem:** `RawAgentInfo.creatorId` is an Entra object GUID, not a UPN. There is no `CreatorAccountUpn`, `LastModifiedByUpn`, or `LastPublishedByUpn` equivalent.

**Solution:** Resolve via `leftouter` join to `IdentityInfo` on `AccountObjectId`, then `coalesce(AccountUpn, CreatorId)`. Creator attribution is a lower bound — `creatorId` is sparse.

### 8. serverUrls Only Populated for OpenApi & RemoteMCPServer

**Problem:** External endpoint URLs in DCM `apis[].serverUrls` are populated for `OpenApi` and `RemoteMCPServer` connector types, but **not** for `api_action` (Power Platform connectors, the majority). Filtering all API types yields mostly empty URLs.

**Solution:** Filter `ApiType in ("OpenApi", "RemoteMCPServer")` before expanding `serverUrls`. State that `api_action` destinations are not inventoried.

### 9. McpServers Is Flat (Name/Description Only)

**Problem:** The dedicated `McpServers` column contains only `{name, description}` — no server URLs, credential configuration, or transport detail. Non-HTTPS MCP detection and hardcoded-cred-in-MCP detection from the old design are not possible.

**Solution:** Use `McpServers` for inventory/exposure counts only. For MCP server endpoints, fall back to the DCM `RemoteMCPServer` API type (Q9).

### 10. AH Booleans Are Textual True/False (Feb 25, 2026)

**Problem:** Since Feb 25, 2026, Advanced Hunting boolean results render as textual `True`/`False`, not `1`/`0`. Governance flags from `RawAgentInfo` (e.g., `allowForAllUsers`) are JSON strings (`"true"`/`"false"`).

**Solution:** Compare against the string form: `tostring(RawAgentInfo.allowForAllUsers) == "true"`. Avoid `== 1` / `== true` numeric/bool comparisons on parsed JSON values.

### 11. CopilotActivity Correlation — Composite AgentId & Fleet-Join Timeouts

**Problem:** Phase 5 runtime correlation against `CopilotActivity` has three traps: (1) `CopilotActivity.AgentId` is a **composite/prefixed string** (e.g., `T_<tenant>.<guid>`, `CopilotStudio.Declarative.T_….gpt.<guid>`, or literals like `AgentBuilder`) that does **not** equal the clean `AgentsInfo.AgentId` GUID — ID joins return 0 matches. (2) A fleet-wide `AgentsInfo` ↔ `CopilotActivity` join (~15k agents × 100k+ rows, heavy `RawAgentInfo`) **times out** the AH endpoint. (3) Most `CopilotActivity` rows have an **empty** `AgentName`/`AgentId` (general M365 Copilot usage), so runtime attribution is low-coverage.

**Solution:** Use a **scoped name-based lookup** (Query 15): build a small flagged-name list from Q4/Q13, then `CopilotActivity | where AgentName in (FlaggedNames)` — no join. **`AgentName` is the reliable cross-table key.** Never join the full fleet. Treat absence from `CopilotActivity` as *unconfirmed*, not proof of dormancy. `AIModelName` is sparse here — do not use it for model inventory.

---

## Quality Checklist

Before delivering the report, verify:

- [ ] All queries used `arg_max(Timestamp, *) by AgentId` for deduplication
- [ ] All queries filtered `LifecycleStatus != "Deleted"` (unless auditing deletions)
- [ ] All queries ran via `RunAdvancedHuntingQuery` (not Data Lake)
- [ ] Zero-result queries are reported with explicit absence confirmation (✅ pattern)
- [ ] The Agent Security Score calculation is transparent with per-dimension evidence
- [ ] Broadly-accessible agents are described as a proxy (NOT "unauthenticated"); the auth-type gap is stated
- [ ] DCM-dependent sections (XPIA email, external endpoints, capability inventory) include the coverage caveat
- [ ] **Deep-Manifest Coverage banner (Q14) is present at the top of the report** (DCM %, ObservabilityID %, EntraAgentID %)
- [ ] **Capability Privilege Index (Q13) is reported** as a supplementary indicator, explicitly noted as NOT summed into the /100 score
- [ ] **If Phase 5 ran, runtime correlation is SCOPED by `AgentName` (Query 15) — never a fleet-wide join**; absence is described as unconfirmed, not dormant
- [ ] Score card uses the **Tool & Endpoint Exposure** dimension label (not "MCP Server Expo") and shows the two supplementary indicators
- [ ] MCP server inventory includes server names, not just counts
- [ ] Declared data sources note that source-type classification is unavailable
- [ ] Creator governance resolves `creatorId` GUIDs via `IdentityInfo` and notes the lower-bound caveat
- [ ] Recommendations are prioritized and evidence-based
- [ ] All hyperlinks in the report are copied verbatim from the URL Registry — no fabricated or recalled-from-memory URLs
- [ ] No PII from live environments in the SKILL.md file itself

---

## SVG Dashboard Generation

> 📊 **Optional post-report step.** After an AI Agent Security Posture report is generated, the user can request a visual SVG dashboard.

**Trigger phrases:** "generate SVG dashboard", "create a visual dashboard", "visualize this report", "SVG from the report"

### How to Request a Dashboard

- **Same chat:** "Generate an SVG dashboard from the report" — data is already in context.
- **New chat:** Attach or reference the report file, e.g. `#file:reports/ai-agent-posture/AI_Agent_Posture_Report_<org>_<date>.md`
- **Customization:** Edit [svg-widgets.yaml](svg-widgets.yaml) before requesting — the renderer reads it at generation time.

### Execution

```
Step 1:  Read svg-widgets.yaml (this skill's widget manifest)
Step 2:  Read .github/skills/svg-dashboard/SKILL.md (rendering rules — Manifest Mode)
Step 3:  Read the completed report file (data source)
Step 4:  Render SVG → save to reports/ai-agent-posture/{report_name}_dashboard.svg
```

The YAML manifest is the single source of truth for layout, widgets, field mappings, colors, and data source documentation. All customization happens there.
