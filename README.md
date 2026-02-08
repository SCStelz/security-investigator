# 🔒 Security Investigation Automation System

**Comprehensive, automated security investigations powered by Microsoft Sentinel, Defender XDR, Graph API, and threat intelligence — with 11 specialized Agent Skills**

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

# 3. Configure API keys
copy config.json.template config.json
# Edit config.json → add your Sentinel workspace ID, tenant ID, and API tokens

# 4. Configure MCP servers
copy .vscode\mcp.json.template .vscode\mcp.json
# All 5 required servers are pre-configured — just needs a GitHub PAT on first use

# 5. Open Copilot Chat (Ctrl+Shift+I) in Agent mode and ask:
#    "What skills do you have access to?"
#    "Investigate user@domain.com for the last 7 days"
```

**For detailed workflows and KQL queries:**
→ [.github/copilot-instructions.md](.github/copilot-instructions.md) (universal patterns, skill detection)
→ [.github/skills/](.github/skills/) (11 specialized investigation workflows)
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
│      (11 specialized workflows with KQL, risk assessment)          │
├────────────────────────────────────────────────────────────────────┤
│                        MCP Servers                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ Sentinel    │  │ Graph API    │  │ Sentinel Triage (XDR)     │  │
│  │ Data Lake   │  │ (Identity)   │  │ (Advanced Hunting)        │  │
│  └─────────────┘  └──────────────┘  └───────────────────────────┘  │
│  ┌─────────────┐  ┌──────────────┐                                 │
│  │ KQL Search  │  │ Microsoft    │                                 │
│  │ (Schema)    │  │ Learn (Docs) │                                 │
│  └─────────────┘  └──────────────┘                                 │
├────────────────────────────────────────────────────────────────────┤
│               MCP Apps (Local Visualization Servers)               │
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
- **11 Agent Skills** — Modular investigation workflows for incidents, users, devices, IoCs, authentication, scope drift, and more
- **5 MCP Server Integrations** — Sentinel Data Lake, Graph API, Defender XDR Triage, KQL Search, Microsoft Learn
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
- **Scope Drift Detection** — 90-day behavioral baseline vs 7-day comparison for service principals and user accounts
- **Visualizations** — Interactive heatmaps and geographic attack maps

---

## 🤖 Agent Skills

This system uses **[VS Code Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills)** to provide modular, domain-specific investigation workflows. Skills are automatically detected based on keywords in your prompts.

### Available Skills

| Skill | Description | Trigger Keywords |
|-------|-------------|------------------|
| **[incident-investigation](/.github/skills/incident-investigation/SKILL.md)** | Comprehensive incident analysis for Defender XDR and Sentinel incidents: criticality assessment, entity extraction, filtering, recursive entity investigation | "investigate incident", "incident ID", "analyze incident", "triage incident", incident number |
| **[user-investigation](/.github/skills/user-investigation/SKILL.md)** | Azure AD user security analysis: sign-ins, anomalies, MFA, devices, audit logs, incidents, Identity Protection, HTML reports | "investigate user", "security investigation", "check user activity", UPN/email |
| **[computer-investigation](/.github/skills/computer-investigation/SKILL.md)** | Device security analysis for Entra Joined, Hybrid Joined, and Entra Registered devices: Defender alerts, compliance, logged-on users, vulnerabilities, process/network/file events | "investigate computer", "investigate device", "investigate endpoint", "check machine", hostname |
| **[ioc-investigation](/.github/skills/ioc-investigation/SKILL.md)** | Indicator of Compromise analysis: IP addresses, domains, URLs, file hashes. Includes Defender Threat Intelligence, Sentinel TI tables, CVE correlation, organizational exposure | "investigate IP", "investigate domain", "investigate URL", "investigate hash", "IoC", "is this malicious" |
| **[honeypot-investigation](/.github/skills/honeypot-investigation/SKILL.md)** | Honeypot security analysis: attack patterns, threat intel, vulnerabilities, executive reports | "honeypot", "attack analysis", "threat actor" |
| **[kql-query-authoring](/.github/skills/kql-query-authoring/SKILL.md)** | KQL query creation using schema validation, community examples, Microsoft Learn | "write KQL", "create KQL query", "help with KQL", "query [table]" |
| **[authentication-tracing](/.github/skills/authentication-tracing/SKILL.md)** | Azure AD authentication chain forensics: SessionId analysis, token reuse vs interactive MFA, geographic anomalies | "trace authentication", "SessionId analysis", "token reuse", "geographic anomaly" |
| **[ca-policy-investigation](/.github/skills/ca-policy-investigation/SKILL.md)** | Conditional Access policy forensics: sign-in failure correlation, policy state changes, security bypass detection | "Conditional Access", "CA policy", "device compliance", "policy bypass" |
| **[scope-drift-detection](/.github/skills/scope-drift-detection/SKILL.md)** | Scope drift analysis for service principals AND user accounts: 90-day behavioral baseline vs 7-day recent activity, weighted Drift Score, correlated with AuditLogs, SecurityAlert, Identity Protection | "scope drift", "service principal drift", "SPN behavioral change", "user drift", "baseline deviation" |
| **[heatmap-visualization](/.github/skills/heatmap-visualization/SKILL.md)** | Interactive heatmap visualization for Sentinel data: attack patterns by time, activity grids, IP vs hour matrices, threat intel drill-down | "heatmap", "show heatmap", "visualize patterns", "activity grid" |
| **[geomap-visualization](/.github/skills/geomap-visualization/SKILL.md)** | Interactive world map visualization for Sentinel data: attack origin maps, geographic threat distribution, IP geolocation with enrichment drill-down | "geomap", "world map", "geographic", "attack map", "attack origins" |

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
| "Map the geographic origins of these attacks" | geomap-visualization |
| "Write a KQL query to find failed sign-ins" | kql-query-authoring |
| "Trace this authentication back to the original MFA" | authentication-tracing |
| "Detect scope drift in service principals" | scope-drift-detection |

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
├── config.json                  # Configuration (workspace IDs, tokens)
├── config.json.template         # Config template (committed to Git)
├── .vscode/
│   └── mcp.json.template       # MCP server config template (copy to mcp.json)
├── requirements.txt             # Python dependencies
├── .github/
│   ├── copilot-instructions.md  # Skill detection, universal patterns, routing
│   └── skills/                  # 11 Agent Skills (modular investigation workflows)
│       ├── authentication-tracing/
│       ├── ca-policy-investigation/
│       ├── computer-investigation/
│       ├── geomap-visualization/
│       ├── heatmap-visualization/
│       ├── honeypot-investigation/
│       ├── incident-investigation/
│       ├── ioc-investigation/
│       ├── kql-query-authoring/
│       ├── scope-drift-detection/
│       └── user-investigation/
├── queries/                     # Verified KQL query library (grep-searchable, by data domain)
│   ├── identity/               # Entra ID / Azure AD identity queries
│   │   ├── app_credential_management.md
│   │   └── service_principal_scope_drift.md
│   ├── endpoint/               # Defender for Endpoint device queries
│   │   ├── endpoint_failed_connections.md
│   │   ├── infostealer_hunting_campaign.md
│   │   ├── rare_process_chains.md
│   │   └── rdp_lateral_movement.md
│   ├── email/                  # Defender for Office 365 email queries
│   │   └── email_threat_detection.md
│   ├── network/                # Network telemetry queries
│   │   └── network_anomaly_detection.md
│   └── cloud/                  # Cloud app & exposure management queries
│       ├── cloudappevents_exploration.md
│       └── exposure_graph_attack_paths.md
├── mcp-apps/                    # Local MCP servers (visualization, automation)
│   ├── sentinel-geomap-server/
│   ├── sentinel-heatmap-server/
│   └── sentinel-incident-comment/
├── docs/                        # Setup guides and reference documentation
├── reports/                     # Generated HTML investigation reports
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
| **Python 3.8+** | For IP enrichment utility and report generation. |
| **Node.js 18+** | Required for KQL Search MCP (`npx`) and building local MCP Apps. |
| **Microsoft Sentinel** | Log Analytics workspace with data. You'll need the workspace GUID and tenant ID. |
| **Azure AD Permissions** | See [MCP Server Setup](#-mcp-server-setup) for per-server permission requirements. |
| **GitHub PAT** | `public_repo` scope — [Create one here](https://github.com/settings/tokens/new). Used by KQL Search MCP. |

### 1. Install Dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `config.json.template` to `config.json` and fill in your values:

```json
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID_HERE",
  "tenant_id": "YOUR_TENANT_ID_HERE",
  "ipinfo_token": null,
  "abuseipdb_token": null,
  "vpnapi_token": null,
  "shodan_token": null,
  "output_dir": "reports"
}
```

| Setting | Required | Description |
|---------|----------|-------------|
| `sentinel_workspace_id` | Yes | Microsoft Sentinel (Log Analytics) workspace GUID |
| `tenant_id` | Yes | Azure AD tenant ID for your Sentinel workspace |
| `ipinfo_token` | Recommended | [ipinfo.io](https://ipinfo.io/) API token — geolocation, ASN, org. Free: 1K/day; token: 50K/month; paid plans include VPN detection |
| `abuseipdb_token` | Recommended | [AbuseIPDB](https://www.abuseipdb.com/) API token — IP reputation scoring (0-100 confidence). Free: 1K/day |
| `vpnapi_token` | Optional | [vpnapi.io](https://vpnapi.io/) API token — VPN/proxy/Tor detection. Not needed if ipinfo.io is on a paid plan |
| `shodan_token` | Optional | [Shodan](https://account.shodan.io/) API key — open ports, services, CVEs, OS detection, tags. Free InternetDB fallback if no key or credits exhausted |
| `output_dir` | No | Directory for HTML reports (default: `reports`) |

### 3. Configure MCP Servers

Copy the MCP server template (all 5 required servers + 3 optional MCP Apps are pre-configured):

```powershell
copy .vscode/mcp.json.template .vscode/mcp.json
```

The template includes inline documentation for each server. On first use, VS Code will prompt for:
- **Azure AD login** — browser-based auth for Sentinel Data Lake, Graph, and Triage servers
- **GitHub PAT** — for KQL Search MCP (schema intelligence and query discovery)

See [MCP Server Setup](#-mcp-server-setup) below for per-server permissions and installation guides.

### 4. Build MCP Apps (Optional — Visualization Skills)

> ⚠️ **VS Code Insiders Required:** MCP Apps currently require [VS Code Insiders](https://code.visualstudio.com/insiders/). Requires **Node.js 18+**.

```powershell
cd mcp-apps/sentinel-geomap-server; npm install; npm run build; cd ../..
cd mcp-apps/sentinel-heatmap-server; npm install; npm run build; cd ../..
cd mcp-apps/sentinel-incident-comment; npm install; npm run build; cd ../..
```

The `sentinel-incident-comment` MCP App requires an Azure Logic App backend. See [mcp-apps/sentinel-incident-comment/README.md](mcp-apps/sentinel-incident-comment/README.md) for setup. Based on [stefanpems/mcp-add-comment-to-sentinel-incident](https://github.com/stefanpems/mcp-add-comment-to-sentinel-incident).

---

## 🔌 MCP Server Setup

The system **requires** five Model Context Protocol (MCP) servers. All five are **pre-configured** in [.vscode/mcp.json.template](.vscode/mcp.json.template) — copy it to `.vscode/mcp.json` to get started (see [Step 3 above](#3-configure-mcp-servers)). The sections below document permissions, tools, and installation guides for each server.

### At a Glance

| # | Server | Purpose | Setup Guide | Key Permissions |
|---|--------|---------|-------------|-----------------|
| 1 | **Sentinel Data Lake** | KQL queries on Log Analytics | [Setup](https://learn.microsoft.com/en-us/copilot/security/developer/mcp-get-started) | Log Analytics Reader |
| 2 | **Microsoft Graph** | User identity, devices, risk | [Setup](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode) | User.Read.All, Device.Read.All |
| 3 | **Sentinel Triage** | Advanced Hunting, Defender XDR | [Setup](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool) | SecurityReader |
| 4 | **KQL Search** | Schema validation, query examples | [Setup](https://www.npmjs.com/package/kql-search-mcp) | GitHub PAT (`public_repo`) |
| 5 | **Microsoft Learn** | Official docs and code samples | [Setup](https://github.com/MicrosoftDocs/mcp) | None (free) |

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

**Permissions:**
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

