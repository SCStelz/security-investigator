# 🔒 Security Investigation Automation System

**Comprehensive, automated security investigations powered by Microsoft Sentinel, Defender XDR, Graph API, and threat intelligence — with 21 specialized Agent Skills**

> 📺 **Video Walkthrough:** See this project in action — [Watch on YouTube](https://youtu.be/3UFqWA4cmoE?t=1470) (starts at the Security Investigator demo). Covers the end-to-end workflow: natural language investigations, MCP server integration, KQL query execution, threat intelligence enrichment, and automated report generation.

An investigation automation framework that combines **GitHub Copilot**, **VS Code Agent Skills**, and **Model Context Protocol (MCP) servers** to enable natural language security investigations. Ask questions like *"Investigate this user for the last 7 days"* or *"Is this IP malicious?"* and get comprehensive analysis with KQL queries, threat intelligence correlation, and professional reports.

### Quick Start (TL;DR)

```powershell
# 1. Clone and open in VS Code
git clone https://github.com/SCStelz/security-investigator.git
code security-investigator

# 2. Set up Python environment
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows
# source .venv/bin/activate          # macOS/Linux
pip install -r requirements.txt

# 3. Configure environment
copy config.json.template config.json
# Edit config.json → add your Sentinel workspace ID, tenant ID
copy .env.template .env
# Edit .env → add your API tokens (ipinfo, AbuseIPDB, vpnapi, Shodan)

# 4. Configure MCP servers
copy .vscode\mcp.json.template .vscode\mcp.json
# All platform servers are pre-configured — just needs a GitHub PAT on first use

# 5. Open Copilot Chat (Ctrl+Shift+I) in Agent mode and ask:
#    "What skills do you have access to?"
#    "Investigate user@domain.com for the last 7 days"
```

**For detailed workflows and KQL queries:**
→ [.github/copilot-instructions.md](.github/copilot-instructions.md) (universal patterns, skill detection)
→ [.github/skills/](.github/skills/) (21 specialized investigation workflows)
→ [queries/](queries/) (verified KQL query library)

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                     GitHub Copilot (VS Code)                       │
├────────────────────────────────────────────────────────────────────┤
│                  .github/copilot-instructions.md                   │
│            (Skill detection, universal patterns, routing)          │
├────────────────────────────────────────────────────────────────────┤
│                     .github/skills/*.md                            │
│       (21 specialized workflows with KQL, risk assessment)         │
├────────────────────────────────────────────────────────────────────┤
│                     MCP Servers (Platform)                         │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ Sentinel    │  │ Graph API    │  │ Sentinel Triage (XDR)     │  │
│  │ Data Lake   │  │ (Identity)   │  │ (Advanced Hunting)        │  │
│  └─────────────┘  └──────────────┘  └───────────────────────────┘  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ KQL Search  │  │ Microsoft    │  │ Azure MCP Server          │  │
│  │ (Schema)    │  │ Learn (Docs) │  │ (ARM + Monitor)           │  │
│  └─────────────┘  └──────────────┘  └───────────────────────────┘  │
│  ┌─────────────┐                                                   │
│  │ Sentinel    │                                                   │
│  │ Graph (Rel) │                                                   │
│  └─────────────┘                                                   │
├────────────────────────────────────────────────────────────────────┤
│               MCP Apps (Local Custom Servers)                      │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ Geomap      │  │ Heatmap      │  │ Incident Comment          │  │
│  │ (Attack Map)│  │ (Patterns)   │  │ (Sentinel Integration)    │  │
│  └─────────────┘  └──────────────┘  └───────────────────────────┘  │
├────────────────────────────────────────────────────────────────────┤
│                      Python Utilities                              │
│ generate_report_from_json.py  │  enrich_ips.py  │  report_generator│
└────────────────────────────────────────────────────────────────────┘
```

**Key Components:**
- **21 Agent Skills** — Modular investigation workflows for incidents, users, devices, IoCs, authentication, scope drift (SPN/User/Device), MCP monitoring, exposure management, AI agent posture, data security analysis, email threat posture, ingestion analysis, detection authoring, SVG dashboards, and more
- **7 MCP Server Integrations** — Sentinel Data Lake, Graph API, Defender XDR Triage, KQL Search, Microsoft Learn, Azure MCP Server, Sentinel Graph (private preview)
- **3 Local MCP Apps** — Interactive heatmaps, geographic attack maps, incident commenting
- **Python Utilities** — HTML report generation with IP enrichment (geolocation, VPN detection, abuse scores, Shodan port/service/CVE intelligence)

---

## Capabilities

- **Incident Triage** — Analyze Defender XDR and Sentinel incidents with entity extraction and recursive investigation
- **User Investigation** — Sign-in anomalies, MFA status, device compliance, Identity Protection, HTML reports
- **Device Investigation** — Defender alerts, vulnerabilities, logged-on users, process/network/file events
- **IoC Analysis** — IP addresses, domains, URLs, file hashes with threat intelligence correlation
- **Honeypot Analysis** — Attack patterns, threat intel, vulnerability assessment, executive reports
- **KQL Query Authoring** — Schema-validated query generation with community examples
- **Authentication Forensics** — SessionId tracing, token reuse vs MFA, geographic anomalies
- **CA Policy Investigation** — Conditional Access failures, policy bypass detection
- **Scope Drift Detection** — 90-day behavioral baseline vs 7-day comparison for service principals, user accounts, and devices (3 specialized sub-skills)
- **MCP Usage Monitoring** — Graph MCP, Sentinel MCP, Azure MCP server audit with behavioral baselines, anomaly detection, and composite scoring
- **Email Threat Posture** — Defender for Office 365 reporting: inbound mail flow, threat composition (phishing/spam/malware), email authentication (DMARC/DKIM/SPF), ZAP post-delivery remediation, Safe Links click protection, attachment analysis, MDO incident summary, Email Protection Score
- **Ingestion & Cost Analysis** — Table-level volume breakdown, tier classification, anomaly detection, analytic rule inventory, license benefit analysis, migration candidates
- **Custom Detection Authoring** — Create, deploy, update, and manage Defender XDR custom detection rules via Graph API with manifest-driven batch deployment
- **AI Agent Posture Audit** — Agent inventory, authentication gaps, MCP tool proliferation, knowledge source exposure, XPIA risk, Agent Security Score for Copilot Studio and M365 Copilot agents
- **Data Security Analysis** — Sensitive information type (SIT) access patterns, DLP policy correlation, insider risk triage, EDM monitoring, file-based risk ranking, spike detection across DataSecurityEvents
- **Visualizations** — Interactive heatmaps, geographic attack maps, and SVG data dashboards

---

## 🤖 Agent Skills

This system uses **[VS Code Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills)** to provide modular, domain-specific investigation workflows. Skills are automatically detected based on keywords in your prompts.

### Available Skills (21)

| Category | Skill | Description | Trigger Keywords |
|----------|-------|-------------|------------------|
| 🔍 Core Investigation | **[computer-investigation](/.github/skills/computer-investigation/SKILL.md)** | Device security analysis for Entra Joined, Hybrid Joined, and Entra Registered devices: Defender alerts, compliance, logged-on users, vulnerabilities, process/network/file events | "investigate computer", "investigate device", "investigate endpoint", "check machine", hostname |
| 🔍 Core Investigation | **[honeypot-investigation](/.github/skills/honeypot-investigation/SKILL.md)** | Honeypot security analysis: attack patterns, threat intel, vulnerabilities, executive reports | "honeypot", "attack analysis", "threat actor" |
| 🔍 Core Investigation | **[incident-investigation](/.github/skills/incident-investigation/SKILL.md)** | Comprehensive incident analysis for Defender XDR and Sentinel incidents: criticality assessment, entity extraction, filtering, recursive entity investigation | "investigate incident", "incident ID", "analyze incident", "triage incident", incident number |
| 🔍 Core Investigation | **[ioc-investigation](/.github/skills/ioc-investigation/SKILL.md)** | Indicator of Compromise analysis: IP addresses, domains, URLs, file hashes. Includes Defender Threat Intelligence, Sentinel TI tables, CVE correlation, organizational exposure | "investigate IP", "investigate domain", "investigate URL", "investigate hash", "IoC", "is this malicious" |
| 🔍 Core Investigation | **[user-investigation](/.github/skills/user-investigation/SKILL.md)** | Entra ID user security analysis: sign-ins, anomalies, MFA, devices, audit logs, incidents, Identity Protection, HTML reports | "investigate user", "security investigation", "check user activity", UPN/email |
| 🔐 Auth & Access | **[authentication-tracing](/.github/skills/authentication-tracing/SKILL.md)** | Entra ID authentication chain forensics: SessionId analysis, token reuse vs interactive MFA, geographic anomalies | "trace authentication", "SessionId analysis", "token reuse", "geographic anomaly" |
| 🔐 Auth & Access | **[ca-policy-investigation](/.github/skills/ca-policy-investigation/SKILL.md)** | Conditional Access policy forensics: sign-in failure correlation, policy state changes, security bypass detection | "Conditional Access", "CA policy", "device compliance", "policy bypass" |
| 📈 Behavioral Analysis | **[scope-drift-detection/device](/.github/skills/scope-drift-detection/device/SKILL.md)** | Device process drift: configurable-window baseline, 5-dimension Drift Score (Volume/Processes/Accounts/Chains/Signing), fleet-wide or single-device, Heartbeat uptime corroboration | "device drift", "endpoint drift", "process baseline", "device behavioral change" |
| 📈 Behavioral Analysis | **[scope-drift-detection/spn](/.github/skills/scope-drift-detection/spn/SKILL.md)** | SPN scope drift: 90-day baseline vs 7-day comparison, 5-dimension Drift Score, correlated with AuditLogs, SecurityAlert, DeviceNetworkEvents | "scope drift", "service principal drift", "SPN behavioral change", "SPN drift" |
| 📈 Behavioral Analysis | **[scope-drift-detection/user](/.github/skills/scope-drift-detection/user/SKILL.md)** | User scope drift: 90-day baseline vs 7-day comparison, dual Drift Scores (7-dim interactive + 6-dim non-interactive), correlated with AuditLogs, SecurityAlert, Identity Protection, CloudAppEvents, EmailEvents | "user drift", "user scope drift", "user behavioral change", "UPN drift" |
| 🛡️ Posture & Exposure | **[exposure-investigation](/.github/skills/exposure-investigation/SKILL.md)** | Vulnerability & Exposure Management reporting: CVE assessment with exploit/CVSS data, security configuration compliance, end-of-support software, ExposureGraph critical assets, attack paths, Defender health, certificate status | "vulnerability report", "exposure report", "CVE assessment", "security posture", "TVM" |
| 🛡️ Posture & Exposure | **[ai-agent-posture](/.github/skills/ai-agent-posture/SKILL.md)** | AI agent security posture audit for Copilot Studio and M365 Copilot agents: agent inventory, authentication gaps, access control misconfigurations, MCP tool proliferation, knowledge source exposure, XPIA risk, credential detection, Agent Security Score | "AI agent posture", "agent security audit", "Copilot Studio agents", "agent inventory", "unauthenticated agents", "agent sprawl" |
| 🛡️ Posture & Exposure | **[email-threat-posture](/.github/skills/email-threat-posture/SKILL.md)** | Email threat protection posture report for Microsoft Defender for Office 365: inbound mail flow overview, threat composition (phishing/spam/malware), email authentication (DMARC/DKIM/SPF/CompAuth), ZAP post-delivery remediation, Safe Links click protection, attachment analysis, detection method breakdown, MDO security incidents, Email Protection Score with 5 dimensions. Inline chat, markdown file, and SVG dashboard output | "email threat report", "email security posture", "phishing report", "MDO report", "Defender for Office 365 report", "ZAP effectiveness", "Safe Links report", "DMARC report" |
| 🔒 Data Security | **[data-security-analysis](/.github/skills/data-security-analysis/SKILL.md)** | DataSecurityEvents (Purview/IRM) analysis: SIT access breakdowns, user risk ranking, file inventory, DLP policy correlation, Copilot SIT exposure, SIT GUID-to-name resolution, anomaly detection. Designed for 100k+ user environments | "data security", "sensitive information type", "SIT access", "DLP events", "DataSecurityEvents", "EDM access", "insider risk activity", "Purview data security" |
| 📊 Visualization | **[geomap-visualization](/.github/skills/geomap-visualization/SKILL.md)** | Interactive world map visualization for Sentinel data: attack origin maps, geographic threat distribution, IP geolocation with enrichment drill-down | "geomap", "world map", "geographic", "attack map", "attack origins" |
| 📊 Visualization | **[heatmap-visualization](/.github/skills/heatmap-visualization/SKILL.md)** | Interactive heatmap visualization for Sentinel data: attack patterns by time, activity grids, IP vs hour matrices, threat intel drill-down | "heatmap", "show heatmap", "visualize patterns", "activity grid" |
| 📊 Visualization | **[svg-dashboard](/.github/skills/svg-dashboard/SKILL.md)** | SVG data visualization dashboards: dual-mode renderer supporting manifest-driven structured dashboards (from skill reports) and freeform adaptive visualizations from ad-hoc investigation data. 14-widget component library | "generate SVG dashboard", "create a visual dashboard", "visualize this report", "SVG from this data" |
| 🔧 Tooling & Monitoring | **[detection-authoring](/.github/skills/detection-authoring/SKILL.md)** | Create, deploy, update, and manage Defender XDR custom detection rules via Graph API. Query adaptation from Sentinel KQL, manifest-driven batch deployment via PowerShell, lifecycle management | "create custom detection", "deploy detection", "detection rule", "custom detection", "deploy rule", "batch deploy" |
| 🔧 Tooling & Monitoring | **[kql-query-authoring](/.github/skills/kql-query-authoring/SKILL.md)** | KQL query creation using schema validation, community examples, Microsoft Learn | "write KQL", "create KQL query", "help with KQL", "query [table]" |
| 🔧 Tooling & Monitoring | **[mcp-usage-monitoring](/.github/skills/mcp-usage-monitoring/SKILL.md)** | MCP server usage monitoring and audit: Graph MCP endpoint analysis, Sentinel MCP auth events, Azure MCP ARM operations, workspace query governance, MCP Usage Score with 5 health/risk dimensions | "MCP usage", "MCP server monitoring", "MCP activity", "MCP audit", "Graph MCP", "Sentinel MCP", "Azure MCP" |
| 🔧 Tooling & Monitoring | **[sentinel-ingestion-report](/.github/skills/sentinel-ingestion-report/SKILL.md)** | Sentinel workspace ingestion & cost analysis: table-level volume breakdown, tier classification (Analytics/Basic/Data Lake), SecurityEvent/Syslog/CommonSecurityLog deep dives, ingestion anomaly detection, analytic rule inventory via REST API, custom detection inventory via Graph API, rule health via SentinelHealth, data lake tier migration candidates, license benefit analysis (DfS P2, M365 E5) | "ingestion report", "usage report", "data volume", "cost analysis", "table breakdown", "data lake tier", "ingestion anomaly", "cost optimization" |

### How Skills Work

1. You ask Copilot a question (e.g., "Investigate user@domain.com for the last 7 days")
2. Copilot detects keywords and loads the appropriate skill from `.github/skills/<skill-name>/SKILL.md`
3. The skill provides specialized workflow, KQL queries, and risk assessment criteria
4. Universal patterns from `.github/copilot-instructions.md` are inherited automatically

### Triggering Skills with Natural Language

You don't need to mention the skill name — keywords are detected automatically:

| What you say | Skill triggered |
|--------------|-----------------|
| "Investigate user@domain.com for the last 7 days" | user-investigation |
| "Analyze incident 12345" | incident-investigation |
| "Is this IP malicious? 203.0.113.42" | ioc-investigation |
| "Check the device WORKSTATION-01 for threats" | computer-investigation |
| "Show attack patterns on a heatmap" | heatmap-visualization |
| "Generate an SVG dashboard from the report" | svg-dashboard |
| "Map the geographic origins of these attacks" | geomap-visualization |
| "Write a KQL query to find failed sign-ins" | kql-query-authoring |
| "Trace this authentication back to the original MFA" | authentication-tracing |
| "Detect scope drift in service principals" | scope-drift-detection/spn |
| "Check user behavioral drift for user@domain.com" | scope-drift-detection/user |
| "Analyze device process drift across the fleet" | scope-drift-detection/device |
| "Show me MCP server usage for the last 30 days" | mcp-usage-monitoring |
| "Generate a Sentinel ingestion report for the last 30 days" | sentinel-ingestion-report |
| "Create custom detections for Event ID 4799" | detection-authoring |
| "Deploy these detection rules to Defender XDR" | detection-authoring |
| "Audit AI agent security posture" | ai-agent-posture |
| "Show me unauthenticated Copilot Studio agents" | ai-agent-posture |
| "Who accessed files with credit card numbers?" | data-security-analysis |
| "Run a data security analysis for the last 30 days" | data-security-analysis |
| "Generate an email threat protection report" | email-threat-posture |
| "What's our phishing delivery rate for the last 30 days?" | email-threat-posture |

### Follow-ups and Chaining

After running an investigation, ask follow-up questions without re-running the entire workflow:

```
Is that IP a VPN?
Trace authentication for that suspicious location
Was MFA used for those sign-ins?
```

Skills can be chained for comprehensive analysis:

```
1. "Investigate incident 12345" → incident-investigation extracts entities
2. "Now investigate the user from that incident" → user-investigation runs on extracted UPN
3. "Check if that IP is malicious" → ioc-investigation analyzes the suspicious IP
4. "Show me a heatmap of the attack patterns" → heatmap-visualization
```

Copilot uses existing investigation data from `temp/investigation_*.json` when available.

### Discovering Skills

```
What investigation skills do you have access to?
Explain the high-level workflow of the user-investigation skill
What data sources does the ioc-investigation skill use?
```

**📖 Reference:** [GitHub Agent Skills Documentation](https://docs.github.com/en/copilot/concepts/agents/about-agent-skills)

### Authoring New Skills from Investigations

One of the most powerful aspects of this project is that **ad-hoc threat hunting and investigations naturally evolve into reusable skills**. After completing an investigation — chasing a novel attack pattern, triaging an unfamiliar alert type, or building a new KQL query chain — you can ask Copilot to codify that workflow into a new SKILL.md file. This captures the verified queries, schema pitfalls, enrichment steps, and analytical logic so that any SOC analyst on the team can repeat the same high-quality investigation with a single natural-language prompt.

This extends beyond your own investigations. When new threat research drops — a blog post detailing an [AiTM phishing campaign](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/), a write-up on a novel [scope drift detection technique](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-agentic-soc-era-how-sentinel-mcp-enables-autonomous-security-reasoning/4491003), or an emerging ransomware TTP — you can feed the article URL to Copilot and ask it to extract the attacker behaviors, map them to relevant Sentinel tables, build the detection queries, validate them against your environment, and then package the entire workflow as a new skill. What used to be a manual process of reading a threat intel report, translating IOCs and TTPs into KQL, and documenting runbooks becomes a single conversational workflow.

It brings a DevOps mindset to Security Engineering: every investigation and every piece of external threat research becomes an opportunity to improve the shared knowledge base, drive collaboration across the team, and raise the overall quality bar — turning tribal knowledge into version-controlled, peer-reviewable, continuously improving automation.

**Sample prompts for creating a new skill:**

```
Based on the investigation we just completed, create a new reusable skill.
Review the queries we ran, the enrichment steps, and the analytical logic,
then package it all into a SKILL.md file following the existing skill format
in .github/skills/. Include the verified KQL queries, known schema pitfalls,
and a step-by-step workflow that another analyst could follow.
```

```
Read this threat intelligence article: <URL>
Extract the attacker TTPs — initial access, persistence mechanisms, lateral
movement, and exfiltration techniques. Map each TTP to the relevant Sentinel
and Defender tables, write detection queries, and create a new investigation
skill that hunts for these behaviors across our environment.
```

---

## 📁 Project Structure

```
security-investigator/
├── generate_report_from_json.py # Report generator (main entry point)
├── report_generator.py          # HTML report builder class
├── investigator.py              # Data models and core types
├── enrich_ips.py                # Standalone IP enrichment utility
├── cleanup_old_investigations.py # Automated cleanup (3+ days old)
├── config.json                  # Configuration (workspace IDs, mappings)
├── config.json.template         # Config template (committed to Git)
├── .env                         # API tokens (gitignored, auto-loaded by python-dotenv)
├── .env.template                # Token template (committed to Git)
├── .vscode/
│   └── mcp.json.template       # MCP server config template (copy to mcp.json)
├── requirements.txt             # Python dependencies
├── .github/
│   ├── copilot-instructions.md  # Skill detection, universal patterns, routing
│   └── skills/                  # 21 Agent Skills (modular investigation workflows)
│       ├── ai-agent-posture/
│       ├── authentication-tracing/
│       ├── ca-policy-investigation/
│       ├── computer-investigation/
│       ├── data-security-analysis/
│       ├── detection-authoring/
│       ├── email-threat-posture/
│       ├── exposure-investigation/
│       ├── geomap-visualization/
│       ├── heatmap-visualization/
│       ├── honeypot-investigation/
│       ├── incident-investigation/
│       ├── ioc-investigation/
│       ├── kql-query-authoring/
│       ├── mcp-usage-monitoring/
│       ├── scope-drift-detection/
│       │   ├── spn/              # Service principal drift (5 dimensions)
│       │   ├── user/             # User account drift (7+6 dimensions)
│       │   └── device/           # Device process drift (5 dimensions)
│       ├── sentinel-ingestion-report/
│       ├── svg-dashboard/
│       └── user-investigation/
├── queries/                     # Verified KQL query library (grep-searchable, by data domain)
│   ├── identity/               # Entra ID / Azure AD identity queries
│   ├── endpoint/               # Defender for Endpoint device queries
│   ├── email/                  # Defender for Office 365 email queries
│   ├── network/                # Network telemetry queries
│   └── cloud/                  # Cloud app & exposure management queries
├── mcp-apps/                    # Local MCP servers (visualization, automation)
│   ├── sentinel-geomap-server/
│   ├── sentinel-heatmap-server/
│   └── sentinel-incident-comment/
├── docs/                        # Setup guides and reference documentation
├── reports/                     # Generated investigation reports (organized by type)
│   ├── ai-agent-posture/       # AI agent security posture reports
│   ├── computer-investigations/ # Device security investigation reports
│   ├── data-security/          # Data security SIT analysis reports
│   ├── email-threat-posture/   # Email threat protection posture reports
│   ├── exposure/               # Exposure management reports
│   ├── honeypot/               # Honeypot executive reports
│   ├── mcp-usage/              # MCP usage monitoring reports
│   ├── scope-drift/            # Scope drift analysis reports
│   ├── sentinel/               # Sentinel ingestion & cost analysis reports
│   └── user-investigations/    # HTML user investigation reports
├── temp/                        # Investigation JSON files (auto-cleaned after 3 days)
└── archive/                     # Legacy code and design docs
```

### Query Library (`queries/`)

The `queries/` folder contains **verified, battle-tested KQL query collections** organized by detection scenario. These are the **Priority 2 lookup source** in the [KQL Pre-Flight Checklist](.github/copilot-instructions.md) — Copilot searches them before writing any ad-hoc KQL.

Each file uses a standardized metadata header for efficient `grep_search` discovery:
```markdown
# <Title>
**Tables:** <exact KQL table names>
**Keywords:** <searchable terms — attack techniques, scenarios, field names>
**MITRE:** <ATT&CK technique IDs, e.g., T1021.001, TA0008>
```

---

## 🚀 Setup

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **VS Code** | Version 1.99+ recommended (Agent mode + MCP support). [VS Code Insiders](https://code.visualstudio.com/insiders/) required for MCP Apps (visualization). |
| **GitHub Copilot** | Active subscription — [Copilot Pro+](https://github.com/features/copilot), Business, or Enterprise. Agent mode must be enabled. |
| **Python 3.8+** | For IP enrichment utility and report generation. [Download](https://www.python.org/downloads/) |
| **Azure CLI** | Required for Azure MCP Server (underlying auth) and `sentinel-ingestion-report` skill (`az monitor log-analytics query` for all KQL queries, `az rest` for analytic rule inventory, `az monitor log-analytics workspace table list` for tier classification). [Install](https://aka.ms/installazurecli). Authenticate: `az login --tenant <tenant_id>`, then `az account set --subscription <subscription_id>`. Requires **Log Analytics Reader** (KQL queries + table list) and **Microsoft Sentinel Reader** (analytic rule inventory) on the workspace. |
| **`log-analytics` CLI extension** | Required by the `sentinel-ingestion-report` skill for `az monitor log-analytics query` (all KQL queries in Phases 1-5). Install: `az extension add --name log-analytics`. Verify: `az extension list --query "[?name=='log-analytics']"`. |
| **PowerShell 7.0+** | Required for `sentinel-ingestion-report` skill (parallel query execution via `ForEach-Object -Parallel`). [Install](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell). Verify: `$PSVersionTable.PSVersion`. |
| **Node.js 18+** | Required for KQL Search MCP (`npx`) and building local MCP Apps. [Download](https://nodejs.org/) or install via `winget install OpenJS.NodeJS.LTS` (Windows) / `brew install node` (macOS). |
| **Microsoft Sentinel** | Log Analytics workspace with data. You'll need the workspace GUID and tenant ID. |
| **Entra ID Permissions** | If you can query Sentinel in the Azure Portal, you likely have sufficient access. The **Graph MCP server** requires a [one-time tenant provisioning](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode) by an admin. See [MCP Server Setup](#-mcp-server-setup) for detailed per-server requirements. |
| **Microsoft.Graph PowerShell** | Required for `detection-authoring` skill (`CustomDetection.ReadWrite.All` — create/update/delete custom detection rules via Graph API). Also used by `sentinel-ingestion-report` skill for rule inventory (`CustomDetection.Read.All` — read-only, degrades gracefully if not installed). `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`. |
| **GitHub PAT** | `public_repo` scope — [Create one here](https://github.com/settings/tokens/new). Used by KQL Search MCP. |

### 1. Install Dependencies

Verify prerequisites:
```powershell
python --version   # Requires 3.8+
node --version     # Requires 18+ (needed for KQL Search MCP)
az --version       # Azure CLI (needed for Azure MCP Server, ingestion report skill)
pwsh --version     # Requires 7.0+ (needed for sentinel-ingestion-report skill)
```

If Node.js is missing: [Download](https://nodejs.org/) or run `winget install OpenJS.NodeJS.LTS` (Windows) / `brew install node` (macOS).
If Azure CLI is missing: [Install](https://aka.ms/installazurecli), then `az login --tenant <tenant_id>` and `az account set --subscription <subscription_id>`.
If the `log-analytics` extension is missing: `az extension add --name log-analytics` (required for `sentinel-ingestion-report` skill).

Set up Python environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `config.json.template` to `config.json` and fill in your workspace details:

```json
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID_HERE",
  "tenant_id": "YOUR_TENANT_ID_HERE",
  "subscription_id": "YOUR_SUBSCRIPTION_ID_HERE",
  "azure_mcp": {
    "resource_group": "YOUR_LOG_ANALYTICS_RESOURCE_GROUP",
    "workspace_name": "YOUR_LOG_ANALYTICS_WORKSPACE_NAME",
    "tenant": "YOUR_TENANT_ID_HERE",
    "subscription": "YOUR_SUBSCRIPTION_ID_HERE"
  },
  "output_dir": "reports"
}
```

| Setting | Required | Description |
|---------|----------|-------------|
| `sentinel_workspace_id` | Yes | Microsoft Sentinel (Log Analytics) workspace GUID |
| `tenant_id` | Yes | Entra ID (Azure AD) tenant ID for your Sentinel workspace |
| `subscription_id` | Yes | Azure subscription ID containing the Sentinel workspace |
| `azure_mcp.*` | Yes | Azure MCP Server parameters — resource group, workspace name, tenant, subscription. Required to avoid cross-tenant auth errors. |
| `output_dir` | No | Directory for HTML reports (default: `reports`) |

#### API Tokens (`.env` file)

API tokens for IP enrichment are stored in a `.env` file (gitignored) rather than `config.json` for security. Copy the template and add your keys:

```powershell
copy .env.template .env
# Edit .env with your token values
```

```dotenv
IPINFO_TOKEN=your_token_here
ABUSEIPDB_TOKEN=your_token_here
VPNAPI_TOKEN=your_token_here
SHODAN_TOKEN=your_token_here
```

These are auto-loaded by `enrich_ips.py` via `python-dotenv` — no manual sourcing needed.

| Token | Required | Description |
|-------|----------|-------------|
| `IPINFO_TOKEN` | Recommended | [ipinfo.io](https://ipinfo.io/) API token — geolocation, ASN, org. Free: 1K/day; token: 50K/month; paid plans include VPN detection |
| `ABUSEIPDB_TOKEN` | Recommended | [AbuseIPDB](https://www.abuseipdb.com/) API token — IP reputation scoring (0-100 confidence). Free: 1K/day |
| `VPNAPI_TOKEN` | Optional | [vpnapi.io](https://vpnapi.io/) API token — VPN/proxy/Tor detection. Not needed if ipinfo.io is on a paid plan |
| `SHODAN_TOKEN` | Optional | [Shodan](https://account.shodan.io/) API key — open ports, services, CVEs, OS detection, tags. Free InternetDB fallback if no key or credits exhausted |

### 3. Configure MCP Servers

Copy the MCP server template (all platform servers + 3 optional MCP Apps are pre-configured):

```powershell
copy .vscode/mcp.json.template .vscode/mcp.json
```

The template includes inline documentation for each server. On first use, VS Code will prompt for:
- **Entra ID login** — browser-based auth for Sentinel Data Lake, Graph, Triage, and Sentinel Graph servers
- **[GitHub PAT](https://github.com/settings/tokens/new)** — for KQL Search MCP (schema intelligence and query discovery). Needs `public_repo` scope.

See [MCP Server Setup](#-mcp-server-setup) below for per-server permissions and installation guides.

### 4. Build MCP Apps (Optional — Visualization Skills)

> ⚠️ **VS Code Insiders Required:** MCP Apps currently require [VS Code Insiders](https://code.visualstudio.com/insiders/). Requires **Node.js 18+**.

**PowerShell (Windows):**
```powershell
cd mcp-apps/sentinel-geomap-server; npm install; npm run build; cd ../..
cd mcp-apps/sentinel-heatmap-server; npm install; npm run build; cd ../..
cd mcp-apps/sentinel-incident-comment; npm install; npm run build; cd ../..
```

**Bash (macOS/Linux):**
```bash
cd mcp-apps/sentinel-geomap-server && npm install && npm run build && cd ../..
cd mcp-apps/sentinel-heatmap-server && npm install && npm run build && cd ../..
cd mcp-apps/sentinel-incident-comment && npm install && npm run build && cd ../..
```

The `sentinel-incident-comment` MCP App requires an Azure Logic App backend. See [mcp-apps/sentinel-incident-comment/README.md](mcp-apps/sentinel-incident-comment/README.md) for setup. Based on [stefanpems/mcp-add-comment-to-sentinel-incident](https://github.com/stefanpems/mcp-add-comment-to-sentinel-incident).

---

## 🔌 MCP Server Setup

The system uses several Model Context Protocol (MCP) servers. All are **pre-configured** in [.vscode/mcp.json.template](.vscode/mcp.json.template) — copy it to `.vscode/mcp.json` to get started (see [Step 3 above](#3-configure-mcp-servers)). The sections below document permissions, tools, and installation guides for each server.

### At a Glance

| # | Server | MCP URL / Transport | Setup Guide | Key Permissions |
|---|--------|---------------------|-------------|-----------------|
| 1 | **Sentinel Data Lake** | `https://sentinel.microsoft.com/mcp/data-exploration` | [Setup](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-get-started) | Log Analytics Reader |
| 2 | **Microsoft Graph** | `https://mcp.svc.cloud.microsoft/enterprise` | [Setup](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode) | User.Read.All, Device.Read.All |
| 3 | **Sentinel Triage** | `https://sentinel.microsoft.com/mcp/triage` | [Setup](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool) | SecurityReader |
| 4 | **KQL Search** | `npx -y kql-search-mcp` (stdio) | [Setup](https://www.npmjs.com/package/kql-search-mcp) | [GitHub PAT](https://github.com/settings/tokens/new) (`public_repo`) |
| 5 | **Microsoft Learn** | `https://learn.microsoft.com/api/mcp` | [Setup](https://github.com/MicrosoftDocs/mcp) | None (free) |
| 6 | **Azure MCP Server** | VS Code extension (stdio) | [Setup](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/overview) | Contributor or Reader on subscription |
| 7 | **Sentinel Graph** ⚠️ | `https://sentinel.microsoft.com/mcp/graph` | [Blog](https://techcommunity.microsoft.com/blog/microsoft-security-blog/uncover-hidden-security-risks-with-microsoft-sentinel-graph/4469437) | Sentinel Reader — *Private Preview* |

### 1. Microsoft Sentinel MCP Server

**📖 [Installation Guide](https://learn.microsoft.com/en-us/copilot/security/developer/mcp-get-started)**

**Tools:** `query_lake`, `search_tables`, `list_sentinel_workspaces`

**Permissions:**
- **Log Analytics Reader** (minimum) — query workspace data
- **Sentinel Reader** (recommended) — full investigation capabilities
- **Sentinel Contributor** — watchlist management (optional)

### 2. MCP Server for Microsoft Graph

**📖 [Installation Guide](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode)**

**Tools:** `microsoft_graph_suggest_queries`, `microsoft_graph_get`, `microsoft_graph_list_properties`

**⚡ One-time tenant provisioning** (requires **Application Administrator** or **Cloud Application Administrator** role):

```powershell
# 1. Install the Entra Beta PowerShell module (v1.0.13+)
Install-Module Microsoft.Entra.Beta -Force -AllowClobber

# 2. Authenticate to your tenant
Connect-Entra -Scopes 'Application.ReadWrite.All', 'Directory.Read.All', 'DelegatedPermissionGrant.ReadWrite.All'

# 3. Register the MCP Server and grant permissions to VS Code
Grant-EntraBetaMCPServerPermission -ApplicationName VisualStudioCode
```

> This only needs to be done **once per tenant**. After provisioning, all users in the tenant can use the Graph MCP server by signing in with their own account.

**Permissions (delegated, per-user):**
- **User.Read.All** — user profiles and authentication methods
- **UserAuthenticationMethod.Read.All** — MFA methods
- **Device.Read.All** — device compliance and enrollment
- **IdentityRiskEvent.Read.All** — Identity Protection risk detections

### 3. Microsoft Sentinel Triage MCP Server

**📖 [Installation Guide](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool)**

**Tools (30+):** `RunAdvancedHuntingQuery`, `ListIncidents`, `GetAlertById`, `GetDefenderMachine`, `GetDefenderFileInfo`, `GetDefenderIpAlerts`, `ListUserRelatedMachines`, `GetDefenderMachineVulnerabilities`, and more.

**Permissions:**
- **Microsoft Defender for Endpoint API** — SecurityReader role minimum
- **Advanced Hunting** — read access to Defender XDR data

### 4. KQL Search MCP Server

**📖 [Installation Guide](https://www.npmjs.com/package/kql-search-mcp)**

**Option A: VS Code Extension (Recommended)**
1. Extensions panel → Search "KQL Search MCP" → Install
2. Command Palette → `KQL Search MCP: Set GitHub Token`

**Option B: NPX** — already configured in `.vscode/mcp.json.template`. Just needs a [GitHub PAT](https://github.com/settings/tokens/new) with `public_repo` scope (prompted on first use).

**Tools (34):** Schema intelligence, query validation, GitHub search, ASIM support for 331+ tables.

### 5. Microsoft Learn MCP Server

**📖 [Installation Guide](https://github.com/MicrosoftDocs/mcp)**

**One-click:** [Install in VS Code](https://vscode.dev/redirect/mcp/install?name=microsoft-learn&config=%7B%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A%2F%2Flearn.microsoft.com%2Fapi%2Fmcp%22%7D) — or already configured in `.vscode/mcp.json.template`.

**Tools:** `microsoft_docs_search`, `microsoft_docs_fetch`, `microsoft_code_sample_search`

No API key required — free, cloud-hosted by Microsoft.

### 6. Azure MCP Server

**📖 [Installation Guide](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/overview)**

Install via VS Code extension: search "Azure MCP Server" in Extensions, or install from the [Marketplace](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.azure-mcp). The extension registers as a stdio MCP server automatically.

**Tools:** `monitor_workspace_log_query`, `monitor_activitylog_list`, `group_list`, `subscription_list`, and 40+ namespaces covering AI, identity, security, databases, storage, compute, and networking.

**Permissions:**
- **Reader** (minimum) — read-only access to Azure resources
- **Log Analytics Reader** — for `workspace_log_query` (KQL against Log Analytics)
- **Contributor** — for write/modify operations (optional)

**Configuration:** Requires `azure_mcp` parameters in `config.json` (tenant, subscription, resource group, workspace name) to avoid cross-tenant auth errors. See [Configure Environment](#2-configure-environment).

### 7. Sentinel Graph MCP Server ⚠️ Private Preview

> **Note:** Sentinel Graph is currently in **private preview** and not available to all customers. If your tenant does not have access, this server will fail to connect — you can safely remove it from `.vscode/mcp.json`. See the [announcement blog post](https://techcommunity.microsoft.com/blog/microsoft-security-blog/uncover-hidden-security-risks-with-microsoft-sentinel-graph/4469437) for details and enrollment.

**Tools:** Entity graph exploration and relationship queries.

**Permissions:**
- **Sentinel Reader** (minimum)

Pre-configured in `.vscode/mcp.json.template`. Browser-based Entra ID login on first use.

### Verify Setup

Open **Copilot Chat** (`Ctrl+Shift+I`) in **Agent mode** and try these prompts:

| Test | Prompt to type in Copilot Chat |
|------|--------------------------------|
| Sentinel Data Lake | `List my Sentinel workspaces` |
| Microsoft Graph | `Look up my user profile in Graph` |
| Sentinel Triage | `List recent security incidents` |
| KQL Search | `What columns does the SigninLogs table have?` |
| Microsoft Learn | `Search Microsoft docs for KQL query language` |
| All skills | `What investigation skills do you have access to?` |

If any server fails, check the **MCP Servers** panel in VS Code (click the `{}` icon in the bottom status bar) to verify each server shows a green connected status.

---

## ⚙️ Configuration Details

### API Rate Limits (IP Enrichment)

| Provider | Free Tier | With Token |
|----------|-----------|------------|
| **ipinfo.io** | 1,000/day (geo, org, ASN) | 50,000/month; paid plans include VPN detection |
| **AbuseIPDB** | 1,000/day | 10,000/day ($20/month) |
| **vpnapi.io** | 1,000/month | 10,000/month ($9.99/month) |
| **Shodan** | InternetDB (unlimited, ports/vulns/tags) | $49 one-time membership: 100 queries/month (adds services, banners, SSL, OS) |

**Token priority:** If `ipinfo_token` is a paid plan, VPN detection is included and `vpnapi_token` is optional. Shodan uses the full API when a paid key is available; on 403/429 it automatically falls back to the free InternetDB.

IP enrichment happens during **report generation** (not data collection), so you can re-generate reports without re-querying Sentinel/Graph.

### Dependencies

```powershell
pip install -r requirements.txt
```

Core packages: **requests** (HTTP client for enrichment APIs), **python-dateutil** (date parsing for KQL time ranges).

---

## 🔒 Security Considerations

1. **Confidential Data** — Reports contain PII and sensitive security data. Mark as CONFIDENTIAL and follow organizational data classification policies.
2. **Access Control** — Restrict access to authorized SOC personnel. Use Azure RBAC for Sentinel, PIM for Graph API permissions.
3. **Audit Trail** — All investigations are timestamped. JSON files in `temp/` preserve snapshots; HTML reports include generation metadata.
4. **Data Retention** — Investigations older than 3 days are auto-deleted (configurable). Archive important investigations before cleanup.
5. **API Token Security** — Never commit `config.json` with tokens (already in `.gitignore`). Use environment variables or Azure Key Vault for production.
6. **Investigation JSON Files** — Stored in `temp/` (not committed to Git). Contain complete data including IP enrichment. Can be re-analyzed without re-querying.

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| **"No anomalies found"** | `Signinlogs_Anomalies_KQL_CL` table doesn't exist or has no data. See user-investigation skill docs. Wait 24h for initial population. |
| **"IP enrichment failed"** | ipinfo.io rate limits (1K/day free). Add token to `config.json` for 50K/month. |
| **"MCP server not available"** | Check VS Code MCP server config. Verify authentication tokens are valid. |
| **"User ID not found" (Graph)** | Verify UPN is correct. Check Graph permissions: User.Read.All. |
| **"Sentinel query timeout"** | Reduce date range. Add `\| take 10` to limit results. |
| **Report generation fails** | Validate JSON: `python -m json.tool temp/investigation_*.json`. Check required fields. |
| **SecurityIncident returns 0 results** | Use BOTH `targetUPN` and `targetUserId` (Object ID). Some incidents use Object ID. |
| **Risky sign-ins 404** | Must use `/beta` endpoint, not `/v1.0`. |

### Verify Connectivity

In **Copilot Chat** (Agent mode):
- `"List my Sentinel workspaces"` — verifies Sentinel Data Lake MCP
- `"Look up user@domain.com in Graph"` — verifies Graph MCP
- `"List recent incidents"` — verifies Sentinel Triage MCP

In **terminal**:
```powershell
python enrich_ips.py 8.8.8.8    # Verifies IP enrichment API tokens
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE). Use it, fork it, adapt it for your SOC — just keep the copyright notice.

---

## 🙏 Acknowledgments

### Microsoft Security Platform
- **[Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/)** — SIEM/SOAR platform powering all KQL queries and incident management
- **[Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/)** — Advanced Hunting, device telemetry, vulnerability management
- **[Microsoft Graph API](https://learn.microsoft.com/en-us/graph/)** — Entra ID identity data, user/group management, role assignments
- **[Microsoft Entra ID Protection](https://learn.microsoft.com/en-us/entra/id-protection/)** — Risk detections, risky sign-ins, user risk states

### MCP Servers
- **[Sentinel Data Lake MCP](https://learn.microsoft.com/en-us/azure/sentinel/datalake/)** — KQL query execution against Sentinel workspace
- **[Sentinel Triage MCP](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool)** — Incident triage, Advanced Hunting, Defender entity APIs
- **[MCP Server for Microsoft Graph](https://github.com/nicholasgasior/mcp-server-microsoft-graph)** — Graph API endpoint discovery and execution
- **[KQL Search MCP](https://www.npmjs.com/package/kql-search-mcp)** — Schema intelligence, GitHub KQL query discovery, ASIM validation
- **[Microsoft Learn MCP](https://learn.microsoft.com/en-us/training/support/mcp-get-started)** — Official documentation search and code sample retrieval

### Threat Intelligence APIs
- **[ipinfo.io](https://ipinfo.io/)** — IP geolocation, ISP/ASN identification, hosting provider detection
- **[vpnapi.io](https://vpnapi.io/)** — VPN, proxy, Tor exit node, and relay detection
- **[AbuseIPDB](https://www.abuseipdb.com/)** — Community-sourced IP abuse scoring and recent attack reports
- **[Shodan](https://www.shodan.io/)** — Open port enumeration, service/banner detection, CVE identification, infrastructure tagging

### Development Tools
- **[GitHub Copilot](https://github.com/features/copilot)** — AI coding assistant powering the natural language investigation interface
- **[VS Code Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills)** — Modular skill framework for specialized investigation workflows
- **[Model Context Protocol (MCP)](https://modelcontextprotocol.io/)** — Open protocol connecting LLMs to external data sources and tools

Special thanks to the Microsoft Security community for sharing KQL queries and detection logic, and to [stefanpems](https://github.com/stefanpems/mcp-add-comment-to-sentinel-incident) for the Sentinel incident commenting MCP pattern.

