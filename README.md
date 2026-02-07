# 🔒 Security Investigation Automation System

**Comprehensive, automated security investigations powered by Microsoft Sentinel, Defender XDR, Graph API, and threat intelligence — with 12 specialized Agent Skills**

An investigation automation framework that combines **GitHub Copilot**, **VS Code Agent Skills**, and **Model Context Protocol (MCP) servers** to enable natural language security investigations. Ask questions like *"Investigate this user for the last 7 days"* or *"Is this IP malicious?"* and get comprehensive analysis with KQL queries, threat intelligence correlation, and professional reports.

### Quick Start (TL;DR)

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Edit config.json with your workspace ID, tenant ID, and API keys
#    (see config.json.template for the full list)

# 3. Install the 5 required MCP servers (see MCP Server Setup below)

# 4. Ask GitHub Copilot:
"What skills do you have access to?"
"Investigate user@domain.com for the last 7 days"
```

**For detailed workflows and KQL queries:**
→ [.github/copilot-instructions.md](.github/copilot-instructions.md) (universal patterns, skill detection)
→ [.github/skills/](.github/skills/) (12 specialized investigation workflows)
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
│      (12 specialized workflows with KQL, risk assessment)          │
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
- **12 Agent Skills** — Modular investigation workflows for incidents, users, devices, IoCs, authentication, scope drift, and more
- **5 MCP Server Integrations** — Sentinel Data Lake, Graph API, Defender XDR Triage, KQL Search, Microsoft Learn
- **3 Local MCP Apps** — Interactive heatmaps, geographic attack maps, incident commenting
- **Python Utilities** — HTML report generation with IP enrichment (geolocation, VPN detection, abuse scores)

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
| **[critical-storage-exposure](/.github/skills/critical-storage-exposure/SKILL.md)** | Critical storage security analysis: exposure perimeter, attack paths, single point of failure detection for Azure Storage and AWS S3 | "critical storage exposure", "storage security", "blob security", "S3 exposure" |

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
├── requirements.txt             # Python dependencies
├── .github/
│   ├── copilot-instructions.md  # Skill detection, universal patterns, routing
│   └── skills/                  # 12 Agent Skills (modular investigation workflows)
│       ├── authentication-tracing/
│       ├── ca-policy-investigation/
│       ├── computer-investigation/
│       ├── critical-storage-exposure/
│       ├── geomap-visualization/
│       ├── heatmap-visualization/
│       ├── honeypot-investigation/
│       ├── incident-investigation/
│       ├── ioc-investigation/
│       ├── kql-query-authoring/
│       ├── scope-drift-detection/
│       └── user-investigation/
├── queries/                     # Verified KQL query library (grep-searchable)
│   ├── app_credential_management.md
│   ├── cloudappevents_exploration.md
│   ├── email_threat_detection.md
│   ├── endpoint_failed_connections.md
│   ├── exposure_graph_attack_paths.md
│   ├── network_anomaly_detection.md
│   ├── rare_process_chains.md
│   ├── rdp_lateral_movement.md
│   └── service_principal_scope_drift.md
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

- **Python 3.8+** with virtual environment
- **GitHub Copilot** in VS Code
- **Microsoft Sentinel Workspace** with Log Analytics access
- **5 MCP Servers** — see [MCP Server Setup](#-mcp-server-setup) below

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
| `output_dir` | No | Directory for HTML reports (default: `reports`) |

### 3. Build MCP Apps (Optional — Visualization Skills)

> ⚠️ **VS Code Insiders Required:** MCP Apps currently require [VS Code Insiders](https://code.visualstudio.com/insiders/).

```bash
cd mcp-apps/sentinel-geomap-server && npm install && npm run build
cd ../sentinel-heatmap-server && npm install && npm run build
cd ../sentinel-incident-comment && npm install && npm run build
cd ../..
```

The `sentinel-incident-comment` MCP App requires an Azure Logic App backend. See [mcp-apps/sentinel-incident-comment/README.md](mcp-apps/sentinel-incident-comment/README.md) for setup. Based on [stefanpems/mcp-add-comment-to-sentinel-incident](https://github.com/stefanpems/mcp-add-comment-to-sentinel-incident).

### 4. Register MCP Apps in VS Code

Create or update `.vscode/mcp.json`:

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "sentinel-webhook-url",
      "description": "Sentinel Incident Comment Webhook URL (Logic App)",
      "password": true
    }
  ],
  "servers": {
    "sentinel-geomap": {
      "command": "node",
      "args": ["${workspaceFolder}/mcp-apps/sentinel-geomap-server/dist/main.js", "--stdio"],
      "type": "stdio"
    },
    "sentinel-heatmap": {
      "command": "node",
      "args": ["${workspaceFolder}/mcp-apps/sentinel-heatmap-server/dist/main.js", "--stdio"],
      "type": "stdio"
    },
    "sentinel-incident-comment": {
      "command": "node",
      "args": ["${workspaceFolder}/mcp-apps/sentinel-incident-comment/dist/index.js", "--stdio"],
      "type": "stdio",
      "env": {
        "SENTINEL_COMMENT_WEBHOOK_URL": "${input:sentinel-webhook-url}"
      }
    }
  }
}
```

---

## 🔌 MCP Server Setup

The system **requires** five Model Context Protocol (MCP) servers. Investigations will fail without them.

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

**Option B: NPX (`.vscode/mcp.json`)**
```json
{
  "inputs": [
    { "type": "promptString", "id": "github-token", "description": "GitHub PAT", "password": true }
  ],
  "servers": {
    "kql-search": {
      "command": "npx",
      "args": ["-y", "kql-search-mcp"],
      "env": {
        "GITHUB_TOKEN": "${input:github-token}",
        "FAVORITE_REPOS": "Azure/Azure-Sentinel,microsoft/Microsoft-365-Defender-Hunting-Queries"
      }
    }
  }
}
```

**Tools (34):** Schema intelligence, query validation, GitHub search, ASIM support for 331+ tables.

**Prerequisite:** [GitHub PAT](https://github.com/settings/tokens/new) with `public_repo` scope.

### 5. Microsoft Learn MCP Server

**📖 [Installation Guide](https://github.com/MicrosoftDocs/mcp)**

**One-click:** [Install in VS Code](https://vscode.dev/redirect/mcp/install?name=microsoft-learn&config=%7B%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A%2F%2Flearn.microsoft.com%2Fapi%2Fmcp%22%7D)

**Manual (`.vscode/mcp.json`):**
```json
{
  "servers": {
    "microsoft-learn": { "type": "http", "url": "https://learn.microsoft.com/api/mcp" }
  }
}
```

**Tools:** `microsoft_docs_search`, `microsoft_docs_fetch`, `microsoft_code_sample_search`

No API key required — free, cloud-hosted by Microsoft.

### Verify Setup

```powershell
# Sentinel
mcp_sentinel-mcp-2_list_sentinel_workspaces()

# Graph
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/me?$select=displayName")

# Sentinel Triage
mcp_sentinel-tria_FetchAdvancedHuntingTablesOverview({"tableNames": ["DeviceInfo"]})

# KQL Search
mcp_kql-search_get_schema_statistics()

# Microsoft Learn
mcp_microsoft-lea_microsoft_docs_search({"query": "KQL query language"})
```

---

## ⚙️ Configuration Details

### API Rate Limits (IP Enrichment)

| Provider | Free Tier | With Token |
|----------|-----------|------------|
| **ipinfo.io** | 1,000/day (geo, org, ASN) | 50,000/month; paid plans include VPN detection |
| **AbuseIPDB** | 1,000/day | 10,000/day ($20/month) |
| **vpnapi.io** | 1,000/month | 10,000/month ($9.99/month) |

**Token priority:** If `ipinfo_token` is a paid plan, VPN detection is included and `vpnapi_token` is optional.

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

```powershell
# Graph API
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/users/user@domain.com?$select=id,displayName")

# Sentinel
mcp_sentinel-mcp-2_list_sentinel_workspaces()

# IP Enrichment
python enrich_ips.py 8.8.8.8
```

---

##  License

**Internal use only.** Designed for Microsoft Sentinel customers. Modify freely for internal SOC operations.

---

## 🙏 Acknowledgments

Built using **Microsoft Sentinel**, **Microsoft Graph API**, **Microsoft Identity Protection**, **ipinfo.io**, **vpnapi.io**, **AbuseIPDB**, and **GitHub Copilot**. Special thanks to the Microsoft Security community for sharing KQL queries and detection logic.

