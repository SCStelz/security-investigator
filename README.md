# 🔒 Security Investigation Automation System

**Comprehensive, automated security investigations with professional HTML reports - powered by Microsoft Sentinel, Graph API, and threat intelligence**

A Proof of Concept investigation automation system that leverages **GitHub Copilot**, **Microsoft Sentinel MCP Server**, and **Microsoft MCP Server for Enterprice (Graph API)** to deliver comprehensive user security assessments in minutes. Designed for SOC teams requiring repeatable, deterministic investigations with actionable risk assessments.

### Investigation Types

**User Security Investigations** - Analyze user accounts for anomalies, risky sign-ins, device compliance, and Identity Protection findings  
**Honeypot Attack Analysis** - Assess honeypot servers for attack patterns, threat intelligence, and exploit attempts  

---

## 🤖 Agent Skills (VS Code Copilot)

This system uses **[VS Code Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills)** to provide modular, domain-specific investigation workflows. Skills are automatically detected based on keywords in your prompts.

| Skill | Description | Trigger Keywords |
|-------|-------------|------------------|
| **[incident-investigation](/.github/skills/incident-investigation/SKILL.md)** | Comprehensive incident analysis for Defender XDR and Sentinel incidents: criticality assessment, entity extraction, filtering (RFC1918 IPs, tenant domains), recursive entity investigation using specialized skills | "investigate incident", "incident ID", "incident investigation", "analyze incident", "triage incident", incident number |
| **[user-investigation](/.github/skills/user-investigation/SKILL.md)** | Azure AD user security analysis: sign-ins, anomalies, MFA, devices, audit logs, incidents, Identity Protection, HTML reports | "investigate user", "security investigation", "check user activity", UPN/email |
| **[computer-investigation](/.github/skills/computer-investigation/SKILL.md)** | Device security analysis for Entra Joined, Hybrid Joined, and Entra Registered devices: Defender alerts, compliance, logged-on users, vulnerabilities, process/network/file events, automated investigations | "investigate computer", "investigate device", "investigate endpoint", "check machine", hostname |
| **[ioc-investigation](/.github/skills/ioc-investigation/SKILL.md)** | Indicator of Compromise analysis: IP addresses, domains, URLs, file hashes. Includes Defender Threat Intelligence, Sentinel TI tables, CVE correlation, organizational exposure assessment, and affected device enumeration | "investigate IP", "investigate domain", "investigate URL", "investigate hash", "IoC", "is this malicious", "threat intel", IP/domain/URL/hash |
| **[honeypot-investigation](/.github/skills/honeypot-investigation/SKILL.md)** | Honeypot security analysis: attack patterns, threat intel, vulnerabilities, executive reports | "honeypot", "attack analysis", "threat actor" |
| **[kql-query-authoring](/.github/skills/kql-query-authoring/SKILL.md)** | KQL query creation using schema validation, community examples, Microsoft Learn | "write KQL", "create KQL query", "help with KQL", "query [table]" |
| **[authentication-tracing](/.github/skills/authentication-tracing/SKILL.md)** | Azure AD authentication chain forensics: SessionId analysis, token reuse vs interactive MFA, geographic anomaly investigation | "trace authentication", "SessionId analysis", "token reuse", "geographic anomaly" |
| **[ca-policy-investigation](/.github/skills/ca-policy-investigation/SKILL.md)** | Conditional Access policy forensics: sign-in failure correlation, policy state changes, security bypass detection | "Conditional Access", "CA policy", "device compliance", "policy bypass" |
| **[heatmap-visualization](/.github/skills/heatmap-visualization/SKILL.md)** | Interactive heatmap visualization for Sentinel data: attack patterns by time, activity grids, IP vs hour matrices, threat intel drill-down panels | "heatmap", "show heatmap", "visualize patterns", "activity grid" |
| **[geomap-visualization](/.github/skills/geomap-visualization/SKILL.md)** | Interactive world map visualization for Sentinel data: attack origin maps, geographic threat distribution, IP geolocation with enrichment drill-down | "geomap", "world map", "geographic", "attack map", "attack origins" |

**How Skills Work:**
1. You ask Copilot a question (e.g., "Investigate user@domain.com for the last 7 days")
2. Copilot detects keywords and loads the appropriate skill from `.github/skills/<skill-name>/SKILL.md`
3. The skill provides specialized workflow, KQL queries, and risk assessment criteria
4. Universal patterns from `.github/copilot-instructions.md` are inherited automatically

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
│   ├── copilot-instructions.md  # GitHub Copilot integration guide (skill detection, universal patterns)
│   └── skills/                  # VS Code Agent Skills (modular investigation workflows)
│       ├── authentication-tracing/
│       │   └── SKILL.md         # SessionId forensics, token reuse vs MFA analysis
│       ├── ca-policy-investigation/
│       │   └── SKILL.md         # Conditional Access policy forensics
│       ├── computer-investigation/
│       │   └── SKILL.md         # Device security analysis for Entra/Hybrid/Registered devices
│       ├── geomap-visualization/
│       │   └── SKILL.md         # Interactive world map visualization for attack origins
│       ├── heatmap-visualization/
│       │   └── SKILL.md         # Interactive heatmap for time-based pattern analysis
│       ├── honeypot-investigation/
│       │   └── SKILL.md         # Attack pattern analysis, threat intel correlation
│       ├── incident-investigation/
│       │   └── SKILL.md         # Incident triage with entity extraction and deep investigation
│       ├── ioc-investigation/
│       │   └── SKILL.md         # IoC analysis: IPs, domains, URLs, file hashes
│       ├── kql-query-authoring/
│       │   └── SKILL.md         # Schema-validated KQL query generation
│       └── user-investigation/
│           └── SKILL.md         # Comprehensive user security analysis
├── mcp-apps/                    # Local MCP servers (visualization, automation)
│   ├── sentinel-geomap-server/  # World map visualization
│   ├── sentinel-heatmap-server/ # Heatmap visualization
│   └── sentinel-incident-comment/ # Add comments to Sentinel incidents
├── docs/
│   ├── Signinlogs_Anomalies_KQL_CL.md  # Anomaly table setup (for user-investigation skill)
│   ├── IDENTITY_PROTECTION.md          # Graph Identity Protection integration
│   ├── SECURITY_INCIDENT.md            # Incident correlation patterns
│   └── IP_SELECTION_REFACTOR.md        # IP prioritization logic
├── reports/                     # Generated HTML investigation reports
├── temp/                        # Investigation JSON files (auto-cleaned after 3 days)
└── archive/                     # Legacy code and design docs
```

**Key Files:**
- **`.github/copilot-instructions.md`** - Complete MCP workflow, KQL query samples, risk assessment framework
- **`agents/honeypotInvestigation/AGENTS.md`** - Honeypot investigation workflow, KQL queries, report template
- **`docs/Signinlogs_Anomalies_KQL_CL.md`** - MUST-READ prerequisite setup guide
- **`generate_report_from_json.py`** - Main report generation script (call this after data collection)

---

## 🚀 Quick Start

### Prerequisites

#### Required MCP Servers (CRITICAL - Must Install First)

This system **requires five MCP servers** to be installed and configured in VS Code:

1. **Microsoft Sentinel MCP Server** - For querying Sentinel logs and threat intel
   - 📖 **Setup Guide**: [Get started with Microsoft Sentinel MCP Server](https://learn.microsoft.com/en-us/copilot/security/developer/mcp-get-started)
   - Provides: `query_lake`, `search_tables`, `list_sentinel_workspaces` tools
   - Requires: Log Analytics Reader or Sentinel Reader RBAC role

2. **MCP Server for Microsoft Graph** - For querying user identity and device data
   - 📖 **Setup Guide**: [Get started with MCP Server for Microsoft Graph](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode)
   - Provides: `microsoft_graph_get`, `microsoft_graph_suggest_queries`, `microsoft_graph_list_properties` tools
   - Requires: User.Read.All, UserAuthenticationMethod.Read.All, Device.Read.All, IdentityRiskEvent.Read.All permissions

3. **Microsoft Sentinel Triage MCP Server** - For Advanced Hunting and Defender for Endpoint operations
   - 📖 **Setup Guide**: [Microsoft Sentinel Triage MCP Server](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool)
   - Provides: `RunAdvancedHuntingQuery`, `GetDefenderMachineVulnerabilities`, `GetDefenderMachine`, `ListAlerts`, `ListIncidents`, and 30+ Defender XDR tools
   - Requires: Microsoft Defender for Endpoint API permissions, SecurityReader role minimum
   - **Required for honeypot investigations** - Enables vulnerability scanning and Advanced Hunting queries

4. **KQL Search MCP Server** - For KQL query authoring with schema validation
   - 📖 **Setup Guide**: [KQL Search MCP on NPM](https://www.npmjs.com/package/kql-search-mcp)
   - Provides: `get_table_schema`, `search_tables`, `validate_kql_query`, `search_github_examples_fallback`, and 30+ query authoring tools
   - Requires: GitHub Personal Access Token with `public_repo` scope
   - **Required for kql-query-authoring skill** - Provides schema validation for 331+ tables

5. **Microsoft Learn MCP Server** - For official Microsoft documentation and code samples
   - 📖 **Setup Guide**: [Microsoft Learn MCP](https://github.com/MicrosoftDocs/mcp)
   - Provides: `microsoft_docs_search`, `microsoft_docs_fetch`, `microsoft_code_sample_search` tools
   - Requires: None (free, cloud-hosted by Microsoft)
   - **Required for kql-query-authoring skill** - Provides official KQL patterns and documentation

**⚠️ Without these MCP servers, investigations will fail. Set them up before proceeding.**

#### Additional Prerequisites

6. **Microsoft Sentinel Workspace** with Log Analytics access
7. **Python 3.8+** with virtual environment
8. **GitHub Copilot** (recommended for natural language investigation triggers)

### Setup Steps

#### 1. Install Dependencies

```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1  # PowerShell
# or
.venv\Scripts\activate.bat     # CMD

# Install packages
pip install -r requirements.txt
```

**MCP Apps Setup (for visualization and automation skills):**

> ⚠️ **VS Code Insiders Required:** MCP Apps currently require [VS Code Insiders](https://code.visualstudio.com/insiders/) to function. This feature will be available in the stable VS Code release soon, but for now, calling MCP Apps from the standard VS Code version is not supported.

```bash
# Build MCP Apps
cd mcp-apps/sentinel-geomap-server
npm install && npm run build
cd ../sentinel-heatmap-server
npm install && npm run build
cd ../sentinel-incident-comment
npm install && npm run build
cd ../..
```

**Sentinel Incident Comment (Additional Setup Required):**

The `sentinel-incident-comment` MCP App adds comments to Sentinel incidents and requires an Azure Logic App backend. See [mcp-apps/sentinel-incident-comment/README.md](mcp-apps/sentinel-incident-comment/README.md) for full setup instructions.

Based on: [stefanpems/mcp-add-comment-to-sentinel-incident](https://github.com/stefanpems/mcp-add-comment-to-sentinel-incident)

#### 2. Configure Environment

Edit `config.json` with your settings:

```json
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID_HERE",
  "tenant_id": "your-azure-tenant-id",
  "ipinfo_token": "your-ipinfo-token",
  "abuseipdb_token": "your-abuseipdb-token-here",
  "vpnapi_token": "your-vpnapi-token-here",
  "output_dir": "reports"
}
```

**MCP Apps Configuration:**

> ⚠️ **VS Code Insiders Required:** MCP Apps currently require [VS Code Insiders](https://code.visualstudio.com/insiders/) to function. This feature will be available in the stable VS Code release soon, but for now, calling MCP Apps from the standard VS Code version is not supported.

Create or update `.vscode/mcp.json` in your workspace root to register the MCP App servers:

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

The `${input:sentinel-webhook-url}` pattern securely prompts for the webhook URL when the MCP server starts, avoiding hardcoded secrets.

After adding this configuration, restart VS Code Insiders. Available tools:
- `mcp_sentinel-geom_show-attack-map` - Geographic attack visualization
- `mcp_sentinel-heat_show-signin-heatmap` - Time-based heatmap visualization
- `mcp_sentinel-inci_add_comment_to_sentinel_incident` - Add comments to Sentinel incidents

**Optional API Tokens:**
- **ipinfo.io** - Increases rate limit from 1,000/day to 50,000/month (free tier)
- **vpnapi.io** - VPN detection (included in ipinfo.io paid plans)
- **AbuseIPDB** - IP reputation scoring (free tier: 1,000/day)

---

## 💬 Working with Agent Skills

Skills are self-documenting workflows that Copilot loads automatically based on keywords in your prompts. Each skill contains:
- Specialized KQL queries and data collection steps
- Risk assessment criteria and severity thresholds
- Output formats (HTML reports, Markdown reports, visualizations)
- Follow-up analysis patterns

### Discovering Available Skills

**Ask Copilot what skills are available:**
```
What investigation skills do you have access to?
List all available skills in this workspace
What types of investigations can you perform?
```

**Get details about a specific skill:**
```
Explain the high-level workflow of the user-investigation skill
What does the incident-investigation skill do?
How does the authentication-tracing skill work?
What data sources does the ioc-investigation skill use?
```

### Triggering Skills with Natural Language

Skills are automatically detected based on keywords. You don't need to mention the skill name:

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

### Following Up on Investigations

After running an investigation, you can ask follow-up questions without re-running the entire workflow:

```
Is that IP a VPN?
What's the abuse score for the Hong Kong IP?
Trace authentication for that suspicious location
Show me details about that risk detection
Was MFA used for those sign-ins?
```

Copilot uses existing investigation data from `temp/investigation_*.json` when available.

### Combining Skills

Skills can be chained together for comprehensive analysis:

```
1. "Investigate incident 12345" → incident-investigation extracts entities
2. "Now investigate the user from that incident" → user-investigation runs on extracted UPN
3. "Check if that IP is malicious" → ioc-investigation analyzes the suspicious IP
4. "Show me a heatmap of the attack patterns" → heatmap-visualization
```

### Understanding Skill Output

**Ask about results after an investigation:**
```
Summarize the key findings from that investigation
What are the critical actions I should take?
Explain the risk assessment
What would you recommend for next steps?
```

**Request different output formats:**
```
Generate an HTML report for that user investigation
Create a markdown summary of the incident
Show the attack origins on a world map
```

---

## 🤖 GitHub Copilot Integration

This system is **designed for GitHub Copilot MCP integration** using **[VS Code Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills)**. 

### Architecture Overview

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
│                      Python Utilities                              │
│  generate_report_from_json.py  │  enrich_ips.py  │  report_generator│
└────────────────────────────────────────────────────────────────────┘
```

### Key Features

- **Automatic skill detection** - Keywords in your prompts route to specialized workflows
- **Parallel data collection** - Multiple Sentinel + Graph queries execute simultaneously
- **Follow-up analysis** - Uses cached JSON from previous investigations
- **Token management** - Efficient context handling for large datasets
- **Report generation** - HTML and Markdown reports with interactive elements

### Reference Files

| File | Purpose |
|------|---------|
| `.github/copilot-instructions.md` | Skill detection keywords, universal patterns, MCP server integration, troubleshooting |
| `.github/skills/<name>/SKILL.md` | Specialized investigation workflows with KQL queries and risk assessment criteria |
| `generate_report_from_json.py` | HTML report generation with IP enrichment |
| `enrich_ips.py` | Standalone IP enrichment (ipinfo, AbuseIPDB, VPN detection) |

---

## 🔌 MCP Server Integration

The system **requires** five Model Context Protocol (MCP) servers for Sentinel, Graph API, Defender XDR integration, and KQL query authoring capabilities.

### Required MCP Servers

#### 1. Microsoft Sentinel MCP Server (`mcp-sentinel-mcp-2`)

**📖 Installation Guide**: [Get started with Microsoft Sentinel MCP Server](https://learn.microsoft.com/en-us/copilot/security/developer/mcp-get-started)

**Tools provided:**
- `query_lake` - Execute KQL queries on Log Analytics workspace
- `search_tables` - Discover table schemas and column definitions
- `list_sentinel_workspaces` - List available workspace name/ID pairs

**Sample usage (via Copilot):**
```
mcp_sentinel-mcp-2_query_lake(query="SigninLogs | where TimeGenerated > ago(1h) | take 10")
```

**Required permissions:**
- **Log Analytics Reader** (minimum) - For querying workspace data
- **Sentinel Reader** (recommended) - For full investigation capabilities
- **Sentinel Contributor** - For watchlist management (optional)

#### 2. MCP Server for Microsoft Graph (`mcp-microsoft`)

**📖 Installation Guide**: [Get started with MCP Server for Microsoft Graph](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode)

**Tools provided:**
- `microsoft_graph_suggest_queries` - Find Graph API endpoints by intent (e.g., "get user by email")
- `microsoft_graph_get` - Execute Graph API calls (v1.0 or beta)
- `microsoft_graph_list_properties` - Explore entity schemas (user, device, group, etc.)

**Sample usage (via Copilot):**
```
mcp_microsoft_mcp_microsoft_graph_suggest_queries("get user by email")
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/users/user@domain.com?$select=id,displayName")
```

**Required permissions:**
- **User.Read.All** - Read user profiles and authentication methods
- **UserAuthenticationMethod.Read.All** - Read MFA methods
- **Device.Read.All** - Read device compliance and enrollment
- **IdentityRiskEvent.Read.All** - Read Identity Protection risk detections

#### 3. Microsoft Sentinel Triage MCP Server (`mcp-sentinel-tria`)

**📖 Installation Guide**: [Microsoft Sentinel Triage MCP Server](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool)

**Primary tools for honeypot investigations:**
- `RunAdvancedHuntingQuery` - Execute KQL queries across Defender XDR Advanced Hunting tables (DeviceInfo, DeviceNetworkEvents, etc.)
- `GetDefenderMachineVulnerabilities` - Query CVEs for a specific device (requires MDE machine ID)
- `FetchAdvancedHuntingTablesOverview` - List available Advanced Hunting tables with descriptions
- `FetchAdvancedHuntingTablesDetailedSchema` - Get complete column schemas for Advanced Hunting tables

**Additional investigation tools (30+ total):**
- `GetAlertById`, `ListAlerts` - Query security alerts
- `ListIncidents`, `GetIncidentById` - Query security incidents
- `GetDefenderMachine`, `GetDefenderMachineAlerts` - Query device details and alerts
- `GetDefenderFileInfo`, `GetDefenderFileAlerts` - File hash reputation and alerts
- `GetDefenderIpAlerts`, `GetDefenderIpStatistics` - IP-based threat hunting
- `ListUserRelatedMachines`, `ListUserRelatedAlerts` - User activity correlation

**Sample usage (via Copilot):**
```
mcp_sentinel-tria_RunAdvancedHuntingQuery({
  "kqlQuery": "DeviceInfo | where DeviceName =~ 'honeypot-server' | summarize arg_max(Timestamp, *)"
})

mcp_sentinel-tria_GetDefenderMachineVulnerabilities({"id": "<MDE_MACHINE_ID>"})
```

**Required permissions:**
- **Microsoft Defender for Endpoint API** - SecurityReader role (minimum)
- **Advanced Hunting** - Read access to Defender XDR data
- **Incident Management** - For reading SecurityIncident and SecurityAlert data

**Use cases:**
- **Honeypot investigations** - Required for vulnerability scanning and Advanced Hunting queries
- **Device forensics** - Query device network activity, file executions, logon events
- **Threat hunting** - Cross-device correlation using Advanced Hunting
- **Incident triage** - Automated alert and incident analysis

### Required MCP Servers (continued)

These MCP servers are **required** for the **kql-query-authoring** skill, providing schema validation, community examples, and official documentation.

#### 4. KQL Search MCP Server (`kql-search`)

**📖 Installation Guide**: [KQL Search MCP on NPM](https://www.npmjs.com/package/kql-search-mcp)

A Model Context Protocol server that searches GitHub for KQL queries using natural language, with built-in schema intelligence for 331+ KQL tables.

**Installation Options:**

**Option A: VS Code Extension (Recommended - No Node.js required)**
1. Open Extensions panel in VS Code (Ctrl+Shift+X)
2. Search for "KQL Search MCP"
3. Click Install
4. Run `KQL Search MCP: Set GitHub Token` from Command Palette

**Option B: NPX Configuration (`.vscode/mcp.json`)**
```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "github-token",
      "description": "GitHub Personal Access Token",
      "password": true
    }
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

**Prerequisites:**
- GitHub Personal Access Token with `public_repo` scope ([Create token](https://github.com/settings/tokens/new))

**Tools provided (34 total):**
- **Schema Intelligence (8 tools):** `get_table_schema`, `search_tables`, `list_table_categories`, `get_tables_by_category`, `generate_query_template`, `generate_query_from_natural_language`, `find_column`, `get_schema_statistics`
- **Query Validation (5 tools):** `generate_kql_query`, `validate_kql_query`, `get_query_documentation`, `check_microsoft_docs_mcp`, `search_github_examples_fallback` ✅
- **GitHub Search (8 tools):** `search_github_examples_fallback` ✅ (recommended), `get_kql_from_file`, `search_kql_repositories`, `get_rate_limit`, `search_repo_kql_queries`, `search_user_kql_queries`, `search_favorite_repos` ❌ (bug in v1.0.5), `get_cache_stats`
- **ASIM Schema (13 tools):** `list_asim_schemas`, `get_asim_schema_info`, `get_asim_field_info`, `generate_asim_query_template`, `validate_asim_parser`, `compare_parser_to_schema`, and more

**Key Features:**
- 331+ indexed tables from Microsoft Defender XDR, Microsoft Sentinel, and Azure Monitor
- Schema-validated query generation (table names, column names, data types verified)
- Natural language table search ("find authentication events", "show email security tables")
- ASIM (Advanced Security Information Model) support with 11 GA schemas
- GitHub search across all public repositories for KQL examples
- Smart caching and rate limit management

#### 5. Microsoft Learn MCP Server (`microsoft-learn`)

**📖 Installation Guide**: [Microsoft Learn MCP on GitHub](https://github.com/MicrosoftDocs/mcp)

Official Microsoft Learn MCP Server providing real-time access to Microsoft's official documentation and code samples.

**Installation:**

**Option A: VS Code One-Click Install**
- [Install in VS Code](https://vscode.dev/redirect/mcp/install?name=microsoft-learn&config=%7B%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A%2F%2Flearn.microsoft.com%2Fapi%2Fmcp%22%7D)

**Option B: Manual Configuration (`.vscode/mcp.json`)**
```json
{
  "servers": {
    "microsoft-learn": {
      "type": "http",
      "url": "https://learn.microsoft.com/api/mcp"
    }
  }
}
```

**Prerequisites:**
- None! Free, no API key required, cloud-hosted by Microsoft

**Tools provided:**
- `microsoft_docs_search` - Semantic search across Microsoft Learn documentation
- `microsoft_docs_fetch` - Fetch full documentation pages in markdown format
- `microsoft_code_sample_search` - Find official Microsoft/Azure code snippets with language filtering

**Key Features:**
- 🧠 **Eliminate hallucinations** - Stop AI from inventing non-existent SDK methods
- 🔌 **Plug & Play** - No API keys, no logins, no sign-ups required
- 🛡️ **100% Trusted** - Only accesses official 1st-party Microsoft documentation
- 💸 **Completely Free** - High search capacity for seamless coding sessions

**Why use both KQL Search + Microsoft Learn together:**
| Capability | KQL Search MCP | Microsoft Learn MCP | Combined |
|------------|----------------|---------------------|----------|
| Query Generation | ✅ 100% validated against schemas | ❌ No schema knowledge | ✅ Validated + docs |
| Schema Information | ✅ Structured table/column data | ❌ No structured schemas | ✅ Best of both |
| Latest Documentation | ✅ Weekly schema checks | ✅ Always current | ✅ Verified with docs |
| Query Examples | ✅ GitHub search | ✅ Official Microsoft examples | ✅ Maximum coverage |

### Setup Verification

After installing the MCP servers, verify they're working:

```powershell
# Test Sentinel MCP (Required)
mcp_sentinel-mcp-2_list_sentinel_workspaces()
# Expected: Array with your workspace name/ID

# Test Graph MCP (Required)
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/me?$select=displayName")
# Expected: JSON with your display name

# Test Sentinel Triage MCP (Required for honeypot investigations)
mcp_sentinel-tria_FetchAdvancedHuntingTablesOverview({"tableNames": ["DeviceInfo"]})
# Expected: Schema information for DeviceInfo table

# Test KQL Search MCP (Required for KQL authoring)
mcp_kql-search_get_schema_statistics()
# Expected: Statistics showing 331+ tables indexed

# Test Microsoft Learn MCP (Required for KQL authoring)
mcp_microsoft-lea_microsoft_docs_search({"query": "KQL query language"})
# Expected: Search results from Microsoft Learn
```

**Authentication:**
- All MCP servers handle Azure AD authentication automatically
- Use service principals with certificate auth for production (not interactive auth)
- Configure authentication tokens in VS Code MCP server settings

**Configuration:**
- MCP servers must be configured in VS Code settings (see installation guides above)
- Default workspace ID from `config.json` used if not specified in Sentinel queries
- Graph API calls require explicit endpoint paths (use `suggest_queries` to discover)

---

## ⚙️ Configuration

### config.json

```json
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID_HERE",
  "tenant_id": "your-azure-tenant-id",
  "ipinfo_token": "your-ipinfo-token-here",
  "abuseipdb_token": "your-abuseipdb-token-here",
  "vpnapi_token": "your-vpnapi-token-here",
  "output_dir": "reports"
}
```

### Configuration Options:

| Setting | Description | Required | Default |
|---------|-------------|----------|---------|
| `sentinel_workspace_id` | Microsoft Sentinel (Log Analytics) workspace GUID | Yes | None |
| `tenant_id` | Azure AD tenant ID for authentication context | No | Auto-detected from auth |
| `ipinfo_token` | ipinfo.io API token (increases rate limits to 50K/month, includes VPN detection in paid tier) | No | None (1K/day free) |
| `abuseipdb_token` | AbuseIPDB API token for IP reputation scoring (0-100 abuse confidence score) | No | None (1K/day free) |
| `vpnapi_token` | vpnapi.io API token for VPN/proxy/Tor detection (standalone service) | No | None (free tier available) |
| `output_dir` | Directory for generated HTML reports | No | `reports` |

### API Rate Limits (IP Enrichment):

**Without tokens (free tier):**
- **ipinfo.io**: 1,000 requests/day (geolocation, org, ASN only)
- **AbuseIPDB**: 1,000 requests/day (IP reputation scoring)
- **vpnapi.io**: 1,000 requests/month free tier (VPN/proxy detection)

**With tokens (recommended for production):**
- **ipinfo.io**: 50,000 requests/month (free tier) or unlimited (paid plans starting at $249/month - includes VPN detection)
- **AbuseIPDB**: 1,000 requests/day (free) or 10,000/day (paid plans starting at $20/month)
- **vpnapi.io**: 10,000 requests/month ($9.99/month) or 100,000/month ($49.99/month)

**Token Priority:**
- If `ipinfo_token` is a **paid plan**, VPN detection is included → `vpnapi_token` is optional
- If `ipinfo_token` is **free tier**, use `vpnapi_token` for VPN detection
- `abuseipdb_token` is always used independently for reputation scoring

**IP enrichment happens during report generation** (not data collection), so you can generate reports multiple times without re-querying Sentinel/Graph.

---

## 📦 Dependencies

Core Python packages:
- **requests** - HTTP client for IP enrichment APIs (ipinfo.io, vpnapi.io, AbuseIPDB)
- **python-dateutil** - Date parsing and manipulation for KQL time ranges

Install with:
```powershell
pip install -r requirements.txt
```

**Optional:**
- **ipykernel** - Jupyter notebook support (for testing/development)
- **pylance** - Python language server (VS Code extension)

---

## 🔒 Security Considerations

1. **Confidential Data** - All investigation reports contain PII and sensitive security data
   - Mark reports as CONFIDENTIAL
   - Store in secure file shares with access control
   - Follow organizational data classification policies
   - Reports include automatic confidentiality header with generator name/machine/timestamp

2. **Access Control** - Restrict access to investigation tools to authorized SOC personnel
   - Implement Azure RBAC for Sentinel workspace access
   - Use PIM (Privileged Identity Management) for Graph API permissions
   - Log all investigation executions for audit trail

3. **Audit Trail** - All investigations are timestamped and logged
   - JSON files in temp/ directory preserve investigation snapshots
   - HTML reports include generation metadata (user, machine, timestamp)
   - MCP server calls are logged in VS Code telemetry

4. **Data Retention** - Follow organizational policies for report storage
   - Automated cleanup: Investigations older than 3 days are auto-deleted (configurable)
   - Archive important investigations before cleanup
   - Consider long-term retention for compliance/forensics

5. **MCP Permissions** - Ensure MCP servers have appropriate RBAC permissions
   - Sentinel: Log Analytics Reader (minimum), Sentinel Contributor (for watchlists)
   - Graph API: User.Read.All, UserAuthenticationMethod.Read.All, Device.Read.All, IdentityRiskEvent.Read.All
   - Use service principals with certificate auth (not interactive auth)

6. **API Token Security** - Store API tokens securely
   - Never commit config.json with tokens to Git (already in .gitignore)
   - Use environment variables or Azure Key Vault for production deployments
   - Rotate tokens regularly (ipinfo.io, AbuseIPDB)

7. **Investigation JSON Files** - Contain complete investigation data
   - Stored in temp/ directory (not committed to Git)
   - Include IP enrichment data (VPN status, abuse scores, threat intel)
   - Can be re-analyzed without re-querying Sentinel/Graph

**Reports are marked CONFIDENTIAL and should be handled according to organizational security policies.**

---

## 🛠️ Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **"No anomalies found" error** | The `Signinlogs_Anomalies_KQL_CL` table doesn't exist or has no data. See the user-investigation skill documentation for KQL job setup. Wait 24 hours for initial data population. |
| **"Import could not be resolved" (Pylance warning)** | This is a false positive from Pylance type checking. The code will run correctly. Ignore or disable Pylance warnings. |
| **"IP enrichment failed"** | ipinfo.io rate limits (1,000/day free tier). Add API token to `config.json` for 50,000/month. Or wait for rate limit reset (midnight UTC). |
| **"MCP server not available"** | MCP servers must be installed and configured in VS Code. Check VS Code settings → Extensions → MCP Server Configuration. Verify authentication tokens are valid. |
| **"User ID not found" in Graph API** | User may not exist, or Graph API permissions missing. Verify UPN is correct. Check Graph API permissions: User.Read.All, UserAuthenticationMethod.Read.All. |
| **"Sentinel query timeout"** | Date range too large or table has too much data. Reduce date range (e.g., 7 days → 1 day). Add `| take 10` to limit results during testing. |
| **Missing device `trustType` or `approximateLastSignInDateTime`** | Use default values in JSON export: `trustType="Workplace"`, `approximateLastSignInDateTime="2025-01-01T00:00:00Z"`. Report generator handles nulls gracefully. |
| **Report generation fails** | Check JSON file has ALL required fields (see copilot-instructions.md for schema). Validate JSON syntax with `python -m json.tool temp/investigation_*.json`. |
| **Empty sections in report (Office 365, Audit Logs)** | Normal if user has no activity in that timeframe. Reports now show green "✓ No [X] detected" messages consistently. |
| **SecurityIncident query returns no results** | Ensure you're using BOTH `targetUPN` and `targetUserId` (Azure AD Object ID) in the query. Some incidents use Object ID instead of UPN. |
| **Risky sign-ins query fails with 404** | Must use `/beta` endpoint, not `/v1.0`. Graph API: `/beta/auditLogs/signIns?$filter=...` |

### Verification Steps

**1. Verify Graph API Permissions:**
```powershell
# Test user query
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/users/user@domain.com?$select=id,displayName")
```
**Expected:** JSON response with user ID and display name

**2. Verify Sentinel Connectivity:**
```powershell
# Test workspace query
mcp_sentinel-mcp-2_list_sentinel_workspaces()
```
**Expected:** Array with workspace name/ID pairs

**3. Verify IP Enrichment:**
```powershell
python enrich_ips.py 8.8.8.8
```
**Expected:** JSON with city, region, country, org, ASN, is_vpn, abuse_confidence_score

### Debug Mode

Enable verbose logging in `generate_report_from_json.py`:
```python
# Add at top of file
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## ‍💻 Contributing

This system is designed to be extended and customized for your organization's specific needs.

### Add Custom Risk Factors

Edit risk assessment logic in `report_generator.py` (search for `_assess_risk`):

```python
# Example: Flag non-VPN remote access as high risk
if 'VPN' not in ip_intel.org and ip_intel.country != 'US':
    risk_factors.append("Non-VPN international access detected")
    risk_score += 3
```

### Customize Report Styling

Edit `_get_styles()` in `report_generator.py`:

```python
# Change primary brand colors
:root {
    --primary-blue: #your-color;
    --critical-red: #your-color;
    --success-green: #your-color;
}
```

### Add New KQL Queries

Add to copilot-instructions.md Sample KQL Queries section:

1. Write and test query in Sentinel
2. Document in copilot-instructions.md with clear purpose
3. Add to parallel batch (Batch 1, 2, or 3)
4. Update JSON export structure in copilot-instructions.md
5. Update report generator to display new data

### Extend IP Enrichment

Edit `generate_report_from_json.py` to add new enrichment sources:

```python
# Example: Add custom threat feed lookup
threat_feed_url = f"https://your-threat-feed.com/api/check/{ip}"
response = requests.get(threat_feed_url)
ip_data['custom_threat_intel'] = response.json()
```

### Custom Anomaly Rules

Modify the KQL job in Sentinel (see `docs/Signinlogs_Anomalies_KQL_CL.md`):

```kql
// Example: Add custom anomaly type for weekend sign-ins
| extend IsWeekend = dayofweek(TimeGenerated) in (0, 6)  // Sunday=0, Saturday=6
| where IsWeekend
| extend AnomalyType = "WeekendActivity"
```

---

## 📜 License

**Internal use only.** Handle according to organizational security policies.

This system is designed for Microsoft Sentinel customers and is not licensed for external distribution. Modify freely for internal SOC operations.

---

## 🙏 Acknowledgments

Built using:
- **Microsoft Sentinel** - Security Information and Event Management (SIEM)
- **Microsoft Graph API** - Identity and device management
- **Microsoft Identity Protection** - Risk detection and assessment
- **ipinfo.io** - IP geolocation and organization data
- **vpnapi.io** - VPN/proxy/Tor detection
- **AbuseIPDB** - IP reputation and abuse reporting
- **GitHub Copilot** - MCP integration and natural language investigation triggers

Special thanks to the Microsoft Security community for sharing KQL queries and detection logic.

---

## 🚀 Getting Started (TL;DR)

1. **Install dependencies** - `pip install -r requirements.txt`
2. **Configure environment** - Edit config.json with workspace ID
3. **Run investigation** - Ask Copilot: "Investigate user@domain.com for the last 7 days"
4. **Review report** - Open HTML file in browser

**For detailed workflows, sample KQL queries, and troubleshooting:**
→ Read [.github/copilot-instructions.md](.github/copilot-instructions.md) (universal patterns, skill detection)
→ Browse [.github/skills/](.github/skills/) (10 specialized investigation workflows)

---

**Ready to investigate? Start with:**

```
Investigate user@domain.com for suspicious activity in the last 7 days
```

Or set up manually:
```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
# Edit config.json with your workspace ID

# 3. Ask GitHub Copilot
# "Investigate user@domain.com for the last 7 days"
```

