---
name: ai-agent-posture
description: 'Use this skill when asked to audit, assess, or report on AI agent security posture across Copilot Studio and Microsoft 365 Copilot agents. Triggers on keywords like "AI agent posture", "agent security audit", "Copilot Studio agents", "agent inventory", "agent authentication", "unauthenticated agents", "agent tools", "MCP tools on agents", "agent knowledge sources", "XPIA risk", "agent sprawl", "AI agent risk", "agent governance", or when investigating AI agent configurations, access policies, tool permissions, or credential exposure. This skill queries the AIAgentsInfo table in Advanced Hunting to produce a comprehensive security posture assessment covering agent inventory, authentication gaps, access control misconfigurations, MCP tool proliferation, knowledge source exposure, XPIA email exfiltration risk, hard-coded credential detection, HTTP request risks, creator governance, and agent sprawl analysis. Supports inline chat and markdown file output.'
---

# AI Agent Security Posture — Instructions

## Purpose

This skill audits the **security posture of AI agents** (Copilot Studio / Microsoft 365 Copilot) across your organization using the `AIAgentsInfo` table in Microsoft Defender XDR Advanced Hunting.

AI agents are autonomous or semi-autonomous applications that can access organizational data, send emails, call external APIs, and use MCP tools. Misconfigured agents — missing authentication, overly broad access, AI-controlled email sending, hard-coded credentials — represent a growing attack surface. This skill systematically evaluates that surface.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔍 **Agent Inventory** | How many agents exist? What's their status, platform, environment? |
| 🔐 **Authentication & Access** | Which agents lack authentication? What access control policies are in use? |
| 🛠️ **Tools & MCP** | Which agents have MCP tools? What operations can they perform? |
| 📚 **Knowledge Sources** | What data sources are agents connected to (SharePoint, public sites, federated)? |
| 📧 **XPIA Email Risk** | Which agents combine generative orchestration with email sending (data exfil risk)? |
| 🔑 **Credential Exposure** | Are credentials hard-coded in agent topics or actions? |
| 🌐 **HTTP Request Risk** | Do agents make HTTP requests to non-standard ports or sensitive endpoints? |
| 👥 **Creator Governance** | Who creates agents? Is there naming hygiene? Abandoned agents? |

**Data source:** `AIAgentsInfo` table (Advanced Hunting) — currently in **Preview**.

**References:**
- [Microsoft Docs — AIAgentsInfo table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aiagentsinfo-table)
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
| `DOCS_AIAGENTSINFO` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aiagentsinfo-table` |
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
| **Preconditions** | Agent uses generative orchestration + email trigger + email-sending tool + knowledge source |
| **Detection** | Q5 (XPIA Email Risk) detects GenAI + SendEmailV2 agents; Q7 (Knowledge Sources) identifies data exposure |
| **Skill Signal** | Agents with `IsGenerativeOrchestrationEnabled == true` + `SendEmailV2` tool + event triggers = highest risk |

### Attack Scenario 2: Prompt Injection via Shared Document → Email Exfiltration (XPIA)

| Element | Detail |
|---------|--------|
| **Vector** | Malicious insider edits a SharePoint document with crafted instructions |
| **Mechanism** | Agent processing the document is tricked into reading a sensitive file on a different SharePoint site (that the agent has access to but the attacker doesn't) and emailing contents to attacker-controlled domain |
| **Preconditions** | Agent has SharePoint knowledge source + email-sending tool + generative orchestration |
| **Detection** | Q5 (XPIA) + Q7 (Knowledge Sources with SharePoint) identifies the attack surface |
| **Skill Signal** | `SharePointSearchSource` + `SendEmailV2` + `IsGenerativeOrchestrationEnabled == true` = classic XPIA vector |

### Attack Scenario 3: Capability Reconnaissance on Unauthenticated Agent

| Element | Detail |
|---------|--------|
| **Vector** | Attacker interacts with publicly accessible chatbot (no authentication required) |
| **Mechanism** | Series of crafted prompts to probe and enumerate the agent's tools and knowledge sources, then exploit them to extract sensitive data |
| **Preconditions** | Agent has `UserAuthenticationType == "None"` + publicly accessible (e.g., website embed) |
| **Detection** | Q4 (Unauthenticated Agents) identifies exposed agents; cross-reference with Q7 (knowledge sources with customer data) |
| **Skill Signal** | `UserAuthenticationType == "None"` + knowledge sources containing sensitive data = reconnaissance target |

### Mitigation: Defender Runtime Protection

Microsoft Defender provides **webhook-based runtime inspection** for Copilot Studio agents. Before every tool, topic, or knowledge action is executed, the generative orchestrator sends a webhook to Defender containing the planned invocation context. Defender analyzes intent and destination in real time and can **allow or block** the action before execution.

This is the primary runtime defense against all three scenarios above. When reviewing posture findings from this skill, **always recommend enabling Defender Runtime Protection** for agents flagged as high-risk. See [Real-time agent protection during runtime](https://learn.microsoft.com/en-us/defender-cloud-apps/real-time-agent-protection-during-runtime).

### Governance Framework: Microsoft Agent 365

[Microsoft Agent 365](https://www.microsoft.com/en-us/microsoft-365/blog/2025/11/18/microsoft-agent-365-the-control-plane-for-ai-agents/) is the enterprise **control plane** for AI agents — the platform-level answer to the governance gaps this skill detects. It provides five capabilities that directly map to this skill's risk dimensions:

| Agent 365 Capability | What It Does | Skill Dimensions Addressed |
|---------------------|-------------|---------------------------|
| **1. Registry** | Single source of truth for all agents (Entra agent ID). IT can quarantine unsanctioned agents and detect shadow agents. Agent Store for governed discovery. | Agent Inventory (Q1), Creator Governance (Q10), Agent Sprawl (Q11) |
| **2. Access Control** | Unique agent IDs via Entra. Agent Policy Templates enforce security from day one. Adaptive, risk-based access policies. Least-privilege enforcement. | Unauthenticated Agents (Q4), Access Control Policies (Q3) |
| **3. Visualization** | Unified dashboard mapping agents ↔ users ↔ resources. Role-based reporting. Compliance logging, e-discovery, and audit trail. | MCP Tool Exposure (Q6), Knowledge Sources (Q7), Creator Governance (Q10) |
| **4. Interoperability** | Agents access Work IQ (org data, relationships, context). Works across Copilot Studio, Microsoft Foundry, Agent Framework, Agent 365 SDK, and partner platforms. | Knowledge Source Risk (Q7), Tools Inventory (Q12) |
| **5. Security** | Defense-in-depth via Microsoft Defender (posture + threat detection + runtime protection), Entra (real-time blocking), and Purview (data exposure risk, sensitive data leak prevention, compliance). | XPIA Email Risk (Q5), Credential Hygiene (Q8), HTTP Risk (Q9) |

**How to reference Agent 365 in reports:** When this skill identifies governance gaps (sprawl, missing authentication, uncontrolled tool access), recommend Agent 365 as the strategic platform to address them. Specific mappings:

- **Agent sprawl / no naming conventions** → Agent 365 Registry + quarantine for unsanctioned agents
- **Missing authentication** → Agent 365 Access Control + Entra agent IDs + Policy Templates
- **No visibility into agent-resource connections** → Agent 365 Visualization dashboard
- **Uncontrolled MCP/tool proliferation** → Agent 365 Security + Defender posture management
- **XPIA / data exfiltration risk** → Agent 365 Security + Purview for real-time data leak prevention

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** — Mandatory rules
2. **[Table Schema Reference](#table-schema-reference)** — AIAgentsInfo columns and data types
3. **[Agent Security Score Formula](#agent-security-score-formula)** — Composite risk scoring
4. **[Execution Workflow](#execution-workflow)** — Phase-by-phase query plan
5. **[Sample KQL Queries](#sample-kql-queries)** — All queries (Q1–Q12)
6. **[Output Modes](#output-modes)** — Inline vs Markdown report
7. **[Inline Report Template](#inline-report-template)** — Chat-rendered format
8. **[Markdown File Report Template](#markdown-file-report-template)** — Disk-saved format
9. **[Known Pitfalls](#known-pitfalls)** — Schema quirks and edge cases
10. **[Quality Checklist](#quality-checklist)** — Pre-delivery validation
11. **[SVG Dashboard Generation](#svg-dashboard-generation)** — Visual dashboard from report

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **ALWAYS use `RunAdvancedHuntingQuery`** — The `AIAgentsInfo` table is an Advanced Hunting table. It is NOT available in Sentinel Data Lake (`query_lake`). All queries in this skill MUST use `RunAdvancedHuntingQuery`.

2. **ALWAYS deduplicate agents with `arg_max`** — The table contains multiple records per agent (state snapshots over time). Every query that analyzes current agent state MUST use `| summarize arg_max(Timestamp, *) by AIAgentId` to get the latest record per agent.

3. **ALWAYS exclude deleted agents** (unless specifically auditing deletions) — Add `| where AgentStatus != "Deleted"` after deduplication.

4. **ASK the user for output format** before generating the report:
   - **Inline chat summary** (quick review in chat)
   - **Markdown file report** (detailed, archived to `reports/ai-agent-posture/`)
   - **Both** (markdown + inline summary)

5. **⛔ MANDATORY: Evidence-based analysis only** — Report ONLY what query results show. Use the explicit absence pattern (`✅ No [finding] detected`) when queries return 0 results. Never guess or assume.

6. **🔴 PROHIBITED: Do NOT filter `AgentToolsDetails` or `AgentTopicsDetails` with direct dot-notation on string columns** — These are `dynamic` type columns. Use `mv-expand` then access properties. See [Known Pitfalls](#known-pitfalls).

7. **Run queries in parallel batches** where possible — Phase 1 queries (Q1–Q3) are independent and can run in parallel. Phase 2 queries (Q4–Q9) are independent and can run in parallel. Phase 3 (Q10–Q12) can run in parallel.

8. **Time tracking** — Report elapsed time after each phase completion.

---

## Table Schema Reference

The `AIAgentsInfo` table (Preview) contains configuration snapshots of AI agents from Copilot Studio.

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | Last recorded date/time for this agent snapshot |
| `AIAgentId` | guid | Unique agent identifier |
| `AIAgentName` | string | Display name of the agent |
| `AgentCreationTime` | datetime | When the agent was created |
| `CreatorAccountUpn` | string | UPN of the creator |
| `OwnerAccountUpns` | string | UPNs of all owners |
| `LastModifiedByUpn` | string | UPN of last modifier |
| `LastModifiedTime` | datetime | When last modified |
| `LastPublishedTime` | datetime | When last published |
| `LastPublishedByUpn` | string | UPN of last publisher |
| `AgentDescription` | string | Agent description |
| `AgentStatus` | string | `Created`, `Published`, `Deleted` |
| `UserAuthenticationType` | string | `None`, `Integrated`, `Custom` |
| `AgentUsers` | string | UPNs/group IDs that can use the agent |
| `KnowledgeDetails` | string | Knowledge sources (JSON array as string) |
| `AgentActionTriggers` | string | Triggers for autonomous actions |
| `RawAgentInfo` | string | Raw JSON config blob |
| `AuthenticationTrigger` | string | `As Needed`, `Always` |
| `AccessControlPolicy` | string | `Any`, `Agent readers`, `Group membership`, `Any (multitenant)` |
| `AuthorizedSecurityGroupIds` | dynamic | Allowed AAD group IDs |
| `AgentTopicsDetails` | dynamic | Topic specifications |
| `AgentToolsDetails` | dynamic | Tool specifications |
| `EnvironmentId` | string | Power Platform environment ID |
| `Platform` | string | `Copilot Studio` |
| `IsGenerativeOrchestrationEnabled` | bool | Uses dynamic AI orchestration |
| `AgentAppId` | string | Entra app registration ID |
| `ConnectedAgentsSchemaNames` | dynamic | Linked agent schemas |
| `ChildAgentsSchemaNames` | dynamic | Child agent schemas |

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
| **Unauthenticated Agents** | 20 | 0 no-auth agents | 1 no-auth agent | ≥2 no-auth agents, especially if Published |
| **XPIA Email Risk** | 20 | 0 agents with GenAI + email | 1 agent with GenAI + email (inputs hardcoded) | ≥1 agent with GenAI + email (inputs AI-controlled) |
| **MCP Tool Exposure** | 20 | 0–2 MCP agents, known creators | 3–10 MCP agents | >10 MCP agents or agents with `invokemcpgraph` + broad access |
| **Knowledge Source Risk** | 20 | 0 agents with SharePoint/internal sources + broad access | 1–3 agents with internal sources + scoped access | Agents with internal data sources + `AccessControlPolicy == "Any"`. **Compounding rule:** When agents have SharePoint sources + GenAI + SendEmailV2 + "Any" access (the full XPIA chain from Q5 + Q7), score at maximum (20) for this dimension AND score XPIA Email Risk at maximum (20) — the combination is the documented attack pattern |
| **Credential Hygiene** | 20 | 0 credential patterns detected | Patterns found but agent is unpublished (Created) | Patterns found in Published agents |

### Interpretation Scale

| Score | Rating | Action |
|-------|--------|--------|
| **0–20** | ✅ Healthy | Normal posture, no immediate concerns |
| **21–45** | 🟡 Elevated | Review — minor misconfigurations detected |
| **46–70** | 🟠 Concerning | Investigate — multiple risk signals present |
| **71–100** | 🔴 Critical | Immediate remediation — significant agent security risk |

---

## Execution Workflow

### Phase 0: Prerequisites

1. Confirm `RunAdvancedHuntingQuery` is available (AIAgentsInfo is AH-only)
2. Ask user for output format (inline / markdown / both)

### Phase 1: Inventory & Overview (Q1–Q3)

**Run in parallel — no dependencies between queries.**

| Query | Purpose |
|-------|---------|
| Q1 | Global inventory summary (counts, date range, environments) |
| Q2 | Status and authentication type breakdown |
| Q3 | Access control policy distribution |

### Phase 2: Security Risk Analysis (Q4–Q9)

**Run in parallel — no dependencies between queries.**

| Query | Purpose |
|-------|---------|
| Q4 | Unauthenticated agents (no-auth detail) |
| Q5 | XPIA email exfiltration risk (GenAI + SendEmailV2) |
| Q6 | MCP tool inventory across agents |
| Q7 | Knowledge source audit |
| Q8 | Hard-coded credential scan |
| Q9 | HTTP request risk (non-standard ports / sensitive endpoints) |

### Phase 3: Governance & Trends (Q10–Q12)

**Run in parallel — no dependencies between queries.**

| Query | Purpose |
|-------|---------|
| Q10 | Top creators and naming hygiene |
| Q11 | Agent creation trend over time |
| Q12 | Tools inventory (all tool types, not just MCP) |

### Phase 4: Score Computation & Report Generation

1. **Compute per-dimension scores** from Phase 1–3 data
2. **Sum dimension scores** for composite Agent Security Score
3. **Generate report** in requested output mode
4. **Report total elapsed time**

---

## Sample KQL Queries

> **All queries below are verified against the AIAgentsInfo table schema. Use them exactly as written, substituting only where noted.**

### Query 1: Global Inventory Summary

```kql
AIAgentsInfo
| summarize 
    TotalRecords = count(),
    UniqueAgents = dcount(AIAgentId),
    EarliestRecord = min(Timestamp),
    LatestRecord = max(Timestamp),
    UniqueCreators = dcount(CreatorAccountUpn),
    UniquePlatforms = dcount(Platform),
    UniqueEnvironments = dcount(EnvironmentId)
```

### Query 2: Status & Authentication Breakdown

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| summarize AgentCount = count() by AgentStatus, UserAuthenticationType
| order by AgentCount desc
```

### Query 3: Access Control Policy Distribution

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| summarize Count = count() by AccessControlPolicy
| order by Count desc
```

### Query 4: Unauthenticated Agents (No-Auth Detail)

🔴 **Security-critical query** — agents with `UserAuthenticationType == "None"` have no user authentication and may be publicly accessible.

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where UserAuthenticationType == "None"
| project 
    AIAgentName, 
    AgentStatus,
    CreatorAccountUpn, 
    OwnerAccountUpns,
    AccessControlPolicy,
    IsGenerativeOrchestrationEnabled,
    AgentCreationTime,
    LastModifiedTime,
    AgentDescription,
    EnvironmentId
| order by AgentStatus desc, AgentCreationTime desc
```

**Post-processing:** For each unauthenticated agent, note:
- Is it Published (active) or just Created (draft)?
- Does it have generative orchestration enabled (higher risk)?
- What is its access control policy (Any = highest risk)?
- Cross-reference with Q5 (email tools) and Q6 (MCP tools) for compounding risk.

**🔴 Capability Reconnaissance Risk ([Attack Scenario 3](#attack-scenario-3-capability-reconnaissance-on-unauthenticated-agent)):** Unauthenticated agents are prime targets for adversarial probing. Attackers can interact with the agent using crafted prompts to enumerate available tools and knowledge sources, then exploit discovered capabilities to extract sensitive data. Published agents with `AccessControlPolicy == "Any"` + knowledge sources containing customer/internal data are the highest-priority findings.

### Query 5: XPIA Email Exfiltration Risk (GenAI + SendEmailV2)

🔴 **Security-critical query** — agents combining generative orchestration with email-sending tools. A successful Cross-Plugin Injection Attack (XPIA) could use the AI orchestrator to exfiltrate data to arbitrary email recipients.

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where IsGenerativeOrchestrationEnabled == true
| mv-expand Action = AgentToolsDetails
| extend OperationId = tostring(Action.action.operationId)
| where OperationId == "SendEmailV2"
| extend InputsPopulated = isnotempty(Action.inputs)
| project 
    AIAgentName,
    AIAgentId,
    CreatorAccountUpn,
    OperationId,
    InputsPopulated,
    AccessControlPolicy,
    UserAuthenticationType,
    AgentStatus
```

**Post-processing:**
- `InputsPopulated == false` → All email inputs (recipient, subject, body) are AI-controlled = **highest XPIA risk**
- `InputsPopulated == true` → Some inputs hardcoded (e.g., fixed recipient) = **reduced but not eliminated risk**. Note: `InputsPopulated` only checks the action-level `inputs` field in `AgentToolsDetails` — it does NOT detect topic-level validation (which is invisible to this query and unreliable for GenAI agents anyway; see [Pitfall #9](#9-genai-orchestrator-bypasses-topics-for-tool-invocation)).
- Cross-reference with Q4: if agent also has `UserAuthenticationType == "None"`, flag as **double risk**.
- **Cross-reference with Q7:** if agent also has `SharePointSearchSource` knowledge sources, flag as the **documented XPIA exfiltration pattern** ([Attack Scenario 2](#attack-scenario-2-prompt-injection-via-shared-document--email-exfiltration-xpia)). The triple combination of GenAI orchestration + SendEmailV2 + SharePoint knowledge source is the textbook attack chain — prioritize these agents for Defender Runtime Protection.

**🔴 Attack Scenario Mapping:** This query detects the agent configuration preconditions for two documented attack scenarios:

1. **[Malicious Instruction Injection via Event Trigger](#attack-scenario-1-malicious-instruction-injection-via-event-triggered-workflow):** An agent monitoring a mailbox (event trigger) with GenAI + SendEmailV2 can be tricked by a crafted inbound email into searching its knowledge base for sensitive data and exfiltrating it via email. The attack operates entirely within the agent's allowed permissions. If `InputsPopulated == false` (AI-controlled recipients), the agent can be directed to send to any attacker-controlled address.

2. **[Prompt Injection via Shared Document](#attack-scenario-2-prompt-injection-via-shared-document--email-exfiltration-xpia):** An agent with SharePoint knowledge sources + email tools can be exploited by a malicious insider who embeds crafted instructions in a document. The agent reads a sensitive file it has connector-level access to (but the attacker doesn't) and exfiltrates the contents via email. Cross-reference with Q7 to identify agents that have both SharePoint sources and email capability.

**Triple-risk agents** (no auth + GenAI + email) are the most dangerous: any external user can trigger the XPIA chain without authentication.

### Query 6: MCP Tool Inventory Across Agents

🟠 **Governance query** — MCP tools give agents access to external servers, Graph API, Sentinel data, and more. Uncontrolled MCP proliferation increases the attack surface.

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| mv-expand Action = AgentToolsDetails
| where Action.action.operationDetails["$kind"] == "ModelContextProtocolMetadata"
| extend MCPName = tostring(Action.action.operationDetails["operationId"])
| extend MCPDisplayName = tostring(Action.modelDisplayName)
| summarize 
    MCPTools = make_set(MCPName),
    MCPToolCount = dcount(MCPName)
    by AIAgentName, AIAgentId, CreatorAccountUpn, AccessControlPolicy, UserAuthenticationType
| order by MCPToolCount desc
```

### Query 7: Knowledge Source Audit

🟡 **Data exposure query** — identifies what data sources agents can access, including SharePoint sites, public websites, and federated data connectors.

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where isnotempty(KnowledgeDetails)
| mv-expand KnowledgeRaw = parse_json(KnowledgeDetails)
| extend KnowledgeJson = parse_json(tostring(KnowledgeRaw))
| extend SourceKind = tostring(KnowledgeJson.source["$kind"])
| extend SourceSite = tostring(KnowledgeJson.source.site.literalValue)
| project 
    AIAgentName,
    AIAgentId,
    CreatorAccountUpn,
    AccessControlPolicy,
    UserAuthenticationType,
    SourceKind,
    SourceSite
| order by SourceKind asc, AIAgentName asc
```

**Post-processing — flag high-risk combinations:**
- `SharePointSearchSource` + `AccessControlPolicy == "Any"` → internal data exposed broadly
- `PublicSiteSearchSource` to sensitive domains (government, financial)
- `FederatedStructuredSearchSource` → check if connected to internal databases/APIs
- Any knowledge source on an agent with `UserAuthenticationType == "None"`

**🔴 Document Injection Risk ([Attack Scenario 2](#attack-scenario-2-prompt-injection-via-shared-document--email-exfiltration-xpia)):** SharePoint knowledge sources are the primary vector for indirect prompt injection (XPIA). A malicious insider with write access to any SharePoint site connected to an agent can embed crafted instructions in a document. When the agent processes the document, it follows the injected instructions — potentially reading files from other SharePoint sites the agent has connector-level access to (but the attacker doesn't). **Cross-reference with Q5:** agents that combine SharePoint knowledge sources with email-sending tools are the textbook XPIA exfiltration pattern. Flag these as **highest priority** in the Knowledge Source Risk dimension.

**Reconnaissance amplifier ([Attack Scenario 3](#attack-scenario-3-capability-reconnaissance-on-unauthenticated-agent)):** Agents with `UserAuthenticationType == "None"` + knowledge sources containing sensitive data (customer info, internal contacts, financial records) are prime targets for capability reconnaissance. Attackers can enumerate the knowledge sources via probing prompts, then extract all accessible data.

### Query 8: Hard-Coded Credential Scan

🔴 **Security-critical query** — scans agent Topics and Actions for patterns matching API keys, JWTs, Basic auth headers, and other credential formats.

```kql
let suspicious_patterns = @"(AKIA[0-9A-Z]{16})|(AIza[0-9A-Za-z_\-]{35})|(xox[baprs]-[0-9a-zA-Z]{10,48})|(ghp_[A-Za-z0-9]{36,59})|(sk_(live|test)_[A-Za-z0-9]{24})|(SG\.[A-Za-z0-9]{22}\.[A-Za-z0-9]{43})|(\d{8}:[\w\-]{35})|(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)|(Authorization\s*:\s*Basic\s+[A-Za-z0-9=:+]+)|([A-Za-z]+:\/\/[^\/\s]+:[^\/\s]+@[^\/\s]+)";
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| mv-expand tool = AgentToolsDetails
| mv-expand topic = AgentTopicsDetails
| where isnotempty(tool) and isnotempty(topic)
| where tool matches regex suspicious_patterns or topic matches regex suspicious_patterns
| project 
    AIAgentName,
    AIAgentId,
    AgentStatus,
    CreatorAccountUpn,
    OwnerAccountUpns
```

**Post-processing:**
- Published agents with credential matches = **immediate remediation required**
- Recommend Azure Key Vault + environment variables instead of hard-coded secrets

### Query 9: HTTP Request Risk (Non-Standard Ports & Sensitive Endpoints)

🟠 **Network risk query** — identifies agents making HTTP requests to non-standard ports or to sensitive API endpoints that should use built-in connectors.

```kql
// Part A: Non-standard ports
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| mv-expand Topic = AgentTopicsDetails
| where Topic has "HttpRequestAction"
| extend TopicActions = Topic.beginDialog.actions
| mv-expand action = TopicActions
| where action['$kind'] == "HttpRequestAction"
| extend Url = tostring(action.url.literalValue)
| extend ParsedUrl = parse_url(Url)
| extend Host = tostring(ParsedUrl["Host"]), Port = tostring(ParsedUrl["Port"])
| where isnotempty(Port) and Port != "443" and Port != "80"
| project AIAgentName, CreatorAccountUpn, Host, Port, Url, AgentStatus, AccessControlPolicy
```

```kql
// Part B: Sensitive endpoint detection (Graph, ARM)
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| mv-expand Topic = AgentTopicsDetails
| where Topic has "HttpRequestAction"
| extend TopicActions = Topic.beginDialog.actions
| mv-expand action = TopicActions
| where action['$kind'] == "HttpRequestAction"
| extend Url = tostring(action.url.literalValue)
| extend ParsedUrl = parse_url(Url)
| extend Host = tostring(ParsedUrl["Host"])
| where Host has_any ("graph.microsoft.com", "management.azure.com", "vault.azure.net", "login.microsoftonline.com")
| project AIAgentName, CreatorAccountUpn, Host, Url, AgentStatus, AccessControlPolicy
```

### Query 10: Top Creators & Naming Hygiene

👥 **Governance query** — identifies prolific agent creators and names lacking descriptiveness (e.g., generic "Agent" names).

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| summarize 
    AgentCount = count(),
    PublishedCount = countif(AgentStatus == "Published"),
    GenericNameCount = countif(AIAgentName in~ ("Agent", "agent", "Test", "test")),
    NoDescriptionCount = countif(isempty(AgentDescription)),
    AgentNames = make_set(AIAgentName, 10)
    by CreatorAccountUpn
| order by AgentCount desc
| take 20
```

### Query 11: Agent Creation Trend

📈 **Trend query** — shows agent creation velocity over time to detect sprawl acceleration.

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| summarize AgentsCreated = count() by bin(AgentCreationTime, 7d)
| order by AgentCreationTime asc
```

### Query 12: Full Tools Inventory (All Tool Types)

🛠️ **Tools governance query** — catalogs all tools (not just MCP) across agents to understand the full capability surface.

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where isnotempty(AgentToolsDetails)
| mv-expand Tool = AgentToolsDetails
| extend 
    ToolKind = tostring(Tool.action.operationDetails["$kind"]),
    ToolDisplayName = tostring(Tool.modelDisplayName),
    OperationId = tostring(Tool.action.operationId)
| summarize AgentCount = dcount(AIAgentId), Agents = make_set(AIAgentName, 5) by ToolKind, OperationId, ToolDisplayName
| order by AgentCount desc
```

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
**Data Source:** AIAgentsInfo (Advanced Hunting)
**Analysis Period:** <EarliestRecord> → <LatestRecord>
**Platform:** Copilot Studio

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
| Created (Draft) Agents | <N> |
| Unique Creators | <N> |
| Environments | <N> |
| Agents with No Authentication | <N> |
| Agents with MCP Tools | <N> |
| Agents with Knowledge Sources | <N> |
| Agents with GenAI + Email (XPIA Risk) | <N> |

---

## 🔐 Authentication & Access Control

### Authentication Types
| Type | Count |
|------|-------|
| Integrated | <N> |
| None | <N> |
| Custom | <N> |

### Access Control Policies
| Policy | Count |
|--------|-------|
| Agent readers | <N> |
| Group membership | <N> |
| Any | <N> |
| Any (multitenant) | <N> |

### 🔴 Unauthenticated Agents

<If Q4 returns results:>
| Agent Name | Status | Creator | Access Policy | GenAI Enabled | Created |
|------------|--------|---------|---------------|---------------|---------|
| <name> | <status> | <upn> | <policy> | <yes/no> | <date> |

<If Q4 returns 0:>
✅ No unauthenticated agents detected.

---

## 📧 XPIA Email Exfiltration Risk

<If Q5 returns results:>
| Agent Name | Creator | Inputs AI-Controlled | Auth Type | Access Policy |
|------------|---------|---------------------|-----------|---------------|
| <name> | <upn> | 🔴 Yes / 🟢 No | <type> | <policy> |

**Risk Assessment:**
- 🔴 Agents with AI-controlled email inputs can be exploited via XPIA to exfiltrate data
- ⚠️ Recommendation: Hardcode email recipients or remove SendEmailV2 from GenAI agents

<If Q5 returns 0:>
✅ No agents combine generative orchestration with email tools.

---

## 🛠️ MCP Tool Exposure

<If Q6 returns results:>
| Agent Name | Creator | MCP Tools | Access Policy | Auth Type |
|------------|---------|-----------|---------------|-----------|
| <name> | <upn> | <tool list> | <policy> | <type> |

**MCP Tool Distribution:**
| MCP Tool | Agent Count |
|----------|-------------|
| <tool> | <N> |

<If Q6 returns 0:>
✅ No agents with MCP tools detected.

---

## 📚 Knowledge Source Exposure

<If Q7 returns results:>
| Source Type | Count | Example |
|-------------|-------|---------|
| SharePointSearchSource | <N> | <sample site> |
| PublicSiteSearchSource | <N> | <sample site> |
| FederatedStructuredSearchSource | <N> | <sample> |

**⚠️ High-Risk Combinations:**
<List agents with internal data sources + broad access policies>

<If Q7 returns 0:>
✅ No knowledge sources configured on any agents.

---

## 🔑 Credential Hygiene

<If Q8 returns results:>
🔴 **Hard-coded credential patterns detected in <N> agent(s):**
| Agent Name | Status | Creator |
|------------|--------|---------|
| <name> | <status> | <upn> |

⚠️ **Recommendation:** Move secrets to Azure Key Vault; use environment variables at runtime.

<If Q8 returns 0:>
✅ No hard-coded credential patterns detected in agent topics or actions.

---

## 🌐 HTTP Request Risk

<If Q9 returns results:>
**Non-Standard Ports:**
| Agent | Host | Port | URL |
|-------|------|------|-----|

**Sensitive Endpoints:**
| Agent | Host | URL |
|-------|------|-----|

<If Q9 returns 0:>
✅ No HTTP requests to non-standard ports or sensitive endpoints detected.

---

## 👥 Creator Governance

### Top Creators
| Creator | Agents | Published | Generic Names | No Description |
|---------|--------|-----------|---------------|----------------|
| <upn> | <N> | <N> | <N> | <N> |

### Naming Hygiene
- Agents with generic names ("Agent", "Test"): <N>
- Agents with no description: <N>

---

## 📈 Agent Creation Trend

<ASCII bar chart or summary table of Q11 results — weekly agent creation counts>

---

## 🛠️ Full Tools Inventory

| Tool Kind | Operation | Agent Count | Example Agents |
|-----------|-----------|-------------|----------------|
| <kind> | <operationId> | <N> | <agent names> |

---

## Agent Security Score Card

```
┌──────────────────────────────────────────────────────┐
│          AGENT SECURITY SCORE: <NN>/100              │
│              Rating: <EMOJI> <RATING>                │
├──────────────────────────────────────────────────────┤
│ Unauth Agents    [<bar>] <N>/20  (<detail>)          │
│ XPIA Email Risk  [<bar>] <N>/20  (<detail>)          │
│ MCP Tool Exposure[<bar>] <N>/20  (<detail>)          │
│ Knowledge Risk   [<bar>] <N>/20  (<detail>)          │
│ Credential Hygn  [<bar>] <N>/20  (<detail>)          │
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
````

---

## Markdown File Report Template

When outputting to markdown file, use the same structure as the Inline Report Template above, saved to:

```
reports/ai-agent-posture/AI_Agent_Posture_Report_YYYYMMDD_HHMMSS.md
```

Include the following additional sections in the file report that are omitted from inline:

1. **Full agent detail table** (all non-deleted agents with key fields)
2. **Per-environment breakdown** (agent counts and creators by EnvironmentId)
3. **Complete knowledge source listing** (every source URL, not just examples)
4. **Complete MCP agent listing** (every MCP agent with full tool list)
5. **Raw query references** — note that full query definitions are in this SKILL.md file

### File Report Header

```markdown
# AI Agent Security Posture Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Data Source:** AIAgentsInfo (Advanced Hunting — Preview)
**Analysis Period:** <EarliestRecord> → <LatestRecord> (<N> days)
**Platform:** Copilot Studio
**Environments:** <N> (<list environment IDs>)
**Total Agents:** <N> (Published: <N>, Created: <N>)

---
```

---

## Known Pitfalls

### 1. AIAgentsInfo Is Advanced Hunting Only

**Problem:** The `AIAgentsInfo` table does NOT exist in Sentinel Data Lake. Querying via `mcp_sentinel-data_query_lake` returns `SemanticError: Failed to resolve table`.

**Solution:** Always use `RunAdvancedHuntingQuery`. The table has 30-day retention in AH.

### 2. Multiple Records Per Agent (State Snapshots)

**Problem:** The table logs configuration snapshots over time. Querying without deduplication returns inflated counts and duplicate agent entries.

**Solution:** Always use `| summarize arg_max(Timestamp, *) by AIAgentId` to get the latest state per agent before any analysis.

### 3. AgentToolsDetails and AgentTopicsDetails Are Dynamic

**Problem:** `AgentToolsDetails` and `AgentTopicsDetails` are `dynamic` type columns containing arrays of objects. You must `mv-expand` before accessing nested properties.

**Solution:** Always `mv-expand` first:
```kql
| mv-expand Tool = AgentToolsDetails
| extend OperationId = tostring(Tool.action.operationId)
```

### 4. KnowledgeDetails Is a String Containing JSON

**Problem:** Despite containing structured data, `KnowledgeDetails` is a `string` column. The string contains a JSON array where each element is itself a JSON string.

**Solution:** Double-parse:
```kql
| mv-expand KnowledgeRaw = parse_json(KnowledgeDetails)
| extend KnowledgeJson = parse_json(tostring(KnowledgeRaw))
| extend SourceKind = tostring(KnowledgeJson.source["$kind"])
```

### 5. Table Is in Preview

**Problem:** `AIAgentsInfo` is currently in Preview. Schema may change, columns may be added/removed, and data population depends on Copilot Studio and Defender XDR deployment.

**Impact:** If the table returns 0 results, confirm that the organization has Copilot Studio agents and that the Defender XDR service is deployed.

### 6. CreatorAccountUpn May Be Empty

**Problem:** Some agents (e.g., system-created `Copilot in Power Apps`) have an empty `CreatorAccountUpn`.

**Solution:** Handle empty creators gracefully in governance analysis. Filter or group them separately.

### 7. Hard-Coded Credential Regex May Produce False Positives

**Problem:** The Q8 credential scan regex matches patterns like JWT tokens (`eyJ...`), which may appear legitimately in topic definitions (e.g., example payloads in documentation topics).

**Solution:** Always manually review matches. Flag Published agents as higher risk than Created (draft) agents.

### 8. IsGenerativeOrchestrationEnabled May Be Null

**Problem:** Some agents have `null` for `IsGenerativeOrchestrationEnabled` rather than `true`/`false`.

**Solution:** Treat `null` as unknown. In Q5 (XPIA risk), filter explicitly on `== true` to avoid false positives.

### 9. GenAI Orchestrator Bypasses Topics for Tool Invocation

**Problem:** When `IsGenerativeOrchestrationEnabled == true`, the AI orchestrator invokes tools (e.g., `SendEmailV2`) directly based on its plan — it does NOT route through authored topic flows in `AgentTopicsDetails`. This means topic-level validation logic (e.g., domain checks, recipient restrictions added to a topic) is **not a defense** against XPIA attacks on GenAI agents.

**Impact:** Do not recommend topic-level controls as an XPIA mitigation for generative agents. The attack surface is entirely in the `AgentToolsDetails` layer (tools the orchestrator can invoke). The documented mitigations are: (1) Hardcode email inputs at the action level, (2) Power Platform DLP connector policies, (3) Microsoft Defender Runtime Protection (webhook-based real-time tool invocation inspection).

**Telemetry note:** Q5 inspects `AgentToolsDetails.inputs` (action-level hardcoded values). Topic-level conditions are invisible to this query and unreliable as a control for GenAI agents.

### 10. AgentTopicsDetails Contains System-Default Boilerplate

**Problem:** `AgentTopicsDetails` for most agents contains only system-default topics (~8–13 per agent): Greeting, Goodbye, Escalate, Error, CSAT Survey, OnSignIn, ConversationStart, OnUnknownIntent. The `displayName` field is typically empty. Conditions within these topics are system boilerplate (survey yes/no, error handling), not custom business logic.

**Impact:** Do not expect `AgentTopicsDetails` to contain actionable security controls or custom domain validation. For GenAI agents, the real capability surface is `AgentToolsDetails` — topics are scripted dialog fallbacks that the orchestrator largely bypasses.

---

## Quality Checklist

Before delivering the report, verify:

- [ ] All queries used `arg_max(Timestamp, *) by AIAgentId` for deduplication
- [ ] All queries filtered `AgentStatus != "Deleted"` (unless auditing deletions)
- [ ] All queries ran via `RunAdvancedHuntingQuery` (not Data Lake)
- [ ] Zero-result queries are reported with explicit absence confirmation (✅ pattern)
- [ ] The Agent Security Score calculation is transparent with per-dimension evidence
- [ ] Unauthenticated agents are flagged with specific risk context (Published vs Created, GenAI, access policy)
- [ ] XPIA email risk distinguishes AI-controlled vs hardcoded inputs
- [ ] MCP tool inventory includes tool names, not just counts
- [ ] Knowledge sources include source type and URL/site reference
- [ ] Creator governance includes naming hygiene and abandoned agent analysis
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
