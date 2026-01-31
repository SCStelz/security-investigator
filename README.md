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
python -m venv .ven

# Activate virtual environment
.\.venv\Scripts\Activate.ps1  # PowerShell
# or
.venv\Scripts\activate.bat     # CMD

# Install packages
pip install -r requirements.txt
```

**MCP Apps Setup (for visualization skills):**

> ⚠️ **VS Code Insiders Required:** MCP Apps currently require [VS Code Insiders](https://code.visualstudio.com/insiders/) to function. This feature will be available in the stable VS Code release soon, but for now, calling MCP Apps from the standard VS Code version is not supported.

```
# Build MCP Apps (for visualization skills)
cd mcp-apps/sentinel-geomap-server
npm install
npm run build
cd ../sentinel-heatmap-server
npm install
npm run build
cd ../..
```

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

**MCP Apps Configuration (for visualization skills):**

> ⚠️ **VS Code Insiders Required:** MCP Apps currently require [VS Code Insiders](https://code.visualstudio.com/insiders/) to function. This feature will be available in the stable VS Code release soon, but for now, calling MCP Apps from the standard VS Code version is not supported.

Create or update `.vscode/mcp.json` in your workspace root to register the heatmap and geomap servers:

```json
{
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
    }
  }
}
```

After adding this configuration, restart VS Code Insiders. The tools `mcp_sentinel-geom_show-attack-map` and `mcp_sentinel-heat_show-signin-heatmap` will then be available.

**Optional API Tokens:**
- **ipinfo.io** - Increases rate limit from 1,000/day to 50,000/month (free tier)
- **vpnapi.io** - VPN detection (included in ipinfo.io paid plans)
- **AbuseIPDB** - IP reputation scoring (free tier: 1,000/day)

#### 3. Run Your First Investigation

**Option A: Natural Language via GitHub Copilot (Recommended)**

Just ask Copilot:
```
Investigate john.doe@contoso.com for the last 7 days
```

Copilot will automatically:
1. Query Microsoft Graph for user ID
2. Run parallel Sentinel KQL queries (anomalies, sign-ins, audit logs, incidents)
3. Run parallel Graph queries (MFA, devices, Identity Protection)
4. Extract and enrich IPs (threat intel, geolocation, VPN detection, abuse scores)
5. Export data to JSON (temp/investigation_*.json)
6. Generate HTML report (reports/Investigation_Report_*.html)
7. Clean up old investigations (3+ days)

**Option B: Direct Python Execution**

```powershell
# Set Python path
$env:PYTHONPATH = "c:\path\to\security-investigator"

# Generate report from JSON (after manual data collection)
.\.venv\Scripts\python.exe generate_report_from_json.py temp\investigation_user_20251201_120000.json
```

**Option C: Manual Investigation JSON Creation**

See `.github/copilot-instructions.md` for the complete MCP workflow with sample KQL queries.

---

## 📊 Investigation Workflow

The system uses a **parallel MCP-based workflow** for maximum performance:

### Phase 1: User Identification (3 seconds)
- Query Microsoft Graph: `/v1.0/users/<UPN>?$select=id,onPremisesSecurityIdentifier`
- Extract Azure AD Object ID (for incident correlation)
- Extract Windows SID (for on-premises incident correlation)

### Phase 2: Parallel Data Collection (60-90 seconds)

**Batch 1: Sentinel KQL Queries (run in parallel)**
1. **Anomalies** - Query `Signinlogs_Anomalies_KQL_CL` (baseline vs recent comparison)
2. **Sign-in by Application** - Top 5 apps (Interactive + Non-Interactive)
3. **Sign-in by Location** - Top 5 locations with success/failure counts
4. **Sign-in Failures** - Detailed breakdown by error code
5. **Audit Logs** - Aggregated by category (RoleManagement, UserManagement, Policy changes)
6. **Office 365 Activity** - Email, Teams, SharePoint operations
7. **DLP Events** - CloudAppEvents with sensitive data violations (limit 10)
8. **Security Incidents** - SecurityIncident + Alert join (deduplicated by ProviderIncidentId)

**Batch 2: IP Extraction and Enrichment**
1. **IP Selection Query** - Deterministic prioritization (8 anomaly + 4 risky + 3 frequent = 15 IPs max)
2. **Threat Intelligence** - ThreatIntelIndicators query (bulk IP lookup)
3. **IP Frequency** - Sign-in counts per IP with authentication patterns

**Batch 3: Microsoft Graph Queries (run in parallel)**
1. **User Profile** - displayName, jobTitle, department, officeLocation, accountEnabled
2. **MFA Methods** - All registered authentication methods
3. **Registered Devices** - Top 5 devices with compliance status, trust type, last sign-in
4. **User Risk Profile** - Identity Protection risk level and state
5. **Risk Detections** - Top 5 risk events (unlikelyTravel, anonymizedIPAddress, etc.)
6. **Risky Sign-ins** - Top 5 risky authentications (beta endpoint)

### Phase 3: IP Enrichment (built into report generation)
- **ipinfo.io** - Geolocation (city, region, country, org, ASN)
- **vpnapi.io** - VPN/proxy/Tor detection
- **AbuseIPDB** - Reputation scoring (0-100) and abuse report counts
- **Sentinel Threat Intel** - Match against ThreatIntelIndicators (from Batch 2)
- **Authentication Pattern** - MFA vs token reuse detection (from IP frequency query)

### Phase 4: Risk Assessment (automated)
- Calculate risk score from: anomalies, risk detections, threat intel matches, device compliance
- Identify mitigating factors: MFA enabled, compliant devices, no failures
- Generate prioritized recommendations: Critical (immediate) / High (24h) / Monitoring (14d)

### Phase 5: Report Generation (3-5 minutes)
- Export investigation data to JSON (temp/investigation_*.json)
- Run `generate_report_from_json.py` (handles IP enrichment API calls)
- Generate HTML report with dark theme, interactive timeline, Copy KQL buttons
- Auto-cleanup old investigations (3+ days) to save disk space

**Total Time: ~5-6 minutes** (most time spent on IP enrichment API calls)

---

## 📄 Report Output

Each investigation generates a **professional, dark-themed HTML report** with:

### Report Sections:
1. **Header** - User identity, job title, department, primary locations, account status
2. **Key Metrics Dashboard** - Anomalies, total sign-ins, DLP events, failures
3. **MFA Status** - Registered authentication methods with phishing-resistant detection
4. **Identity Protection** - Risk level, risk state, active risk detections, dropdown details
5. **Risk Assessment** - Overall risk level with expandable risk/mitigating factors
6. **Critical Actions** - Top 3 critical + top 2 high priority alerts
7. **Registered Devices** - Device name, OS, compliance status, last seen, stale device warnings
8. **Top Locations** - Sign-in counts by country with success/failure breakdown (paginated)
9. **Top Applications** - Sign-in counts by app (paginated)
10. **IP Intelligence** - Risk-scored IP cards with enrichment data (VPN, threat intel, abuse scores, auth patterns)
    - Category badges: THREAT (red), RISKY (orange), ANOMALY (yellow), PRIMARY/ACTIVE (blue)
    - IP type detection: Cloud (Azure/AWS/GCP), Residential ISP, VPN/Proxy, Hosting/Datacenter
    - Combined threat detection: Sentinel threat intel + AbuseIPDB reputation
    - MFA badges: 🔒 MFA, 🎫 Token, 🔑 Interactive, ❌ Failed
    - Expandable details: Organization, ASN, IP type, threat matches
    - Sortable by: Default (risk level) or Last Seen Date
    - Copy KQL button per IP (extracts all activity from that IP across all log sources)
11. **Security Incidents** - Deduplicated incidents with alert counts, severity, status, owner (links to Defender XDR)
12. **Office 365 Activity** - Email accessed, Teams messages, card actions, SharePoint access (5-column grid)
13. **DLP Events** - File copy operations to network shares/cloud with sensitivity rule names
14. **Sign-in Failures** - Error codes, descriptions, counts, affected apps/locations
15. **Azure AD Audit Log Activity** - Aggregated by category with sensitive operation highlighting (password reset, role changes, policy modifications)
16. **Recommendations** - 3-column layout (Critical/High/Monitoring) with actionable remediation steps
17. **Investigation Timeline** - Modal popup with chronological event visualization (date separators, color-coded severity, IP badges, DLP grouping)

### Report Features:
- ✅ **Dark Theme** - Microsoft brand colors (#00a1f1, #f65314, #7cbb00, #ffbb00)
- ✅ **Interactive Tables** - Pagination for long datasets (anomalies, incidents, audit logs)
- ✅ **Copy KQL Buttons** - One-click query copying for follow-up investigation in Sentinel
- ✅ **Gradient Cards** - Visual hierarchy with color-coded risk badges
- ✅ **Timeline Visualization** - Grouped DLP events, date separators, PST timezone conversion
- ✅ **Defender XDR Links** - Direct links to user profile, devices, incidents
- ✅ **Responsive Layout** - Two-column design with resizable splitter
- ✅ **Confidentiality Header** - Fixed header bar with generator name, machine, timestamp
- ✅ **Print-Ready** - Optimized for PDF export and stakeholder distribution
- ✅ **Browser-Optimized** - Opens directly in default browser, no external dependencies

**Example Output:** `Investigation_Report_Compact_username_2025-12-01_105405.html`

**Sample Timeline Events:**
```
2025-11-23
  18:45 PST - 🚨 Sign-in Anomaly: NewInteractiveIP: 203.0.113.42 from Singapore, SG 🚨 THREAT ⚠️ RISKY
  14:23 PST - ⚠️ Identity Protection: unlikelyTravel (MEDIUM) - Tokyo, JP (198.51.100.10) - atRisk
  12:15 PST - 📁 DLP Events (3 files): FileCopiedToNetworkShare - Sensitive.docx, Financial.xlsx...
```

---

## 🎯 Usage Examples

### Standard Investigation (7 days)
**Via GitHub Copilot:**
```
Investigate john.doe@contoso.com for the last 7 days
```

**Via Python (manual workflow):**
```powershell
# 1. Collect data using MCP tools (see copilot-instructions.md for KQL queries)
# 2. Export to JSON (temp/investigation_johndoe_20251201_120000.json)
# 3. Generate report
$env:PYTHONPATH = "c:\path\to\security-investigator"
.\.venv\Scripts\python.exe generate_report_from_json.py temp\investigation_johndoe_20251201_120000.json
```

### Quick Investigation (1-2 days)
**Via GitHub Copilot:**
```
Quick investigate suspicious.user@domain.com
```
**Date range:** Current date - 1 day to current date + 2 days (includes timezone buffer)

### Comprehensive Investigation (30 days)
**Via GitHub Copilot:**
```
Full investigation for compromised.account@company.com
```
**Date range:** Current date - 30 days to current date + 2 days

### Custom Date Range
**Via GitHub Copilot:**
```
Investigate user@company.com from 2025-11-01 to 2025-11-21
```

---

## 🎣 Honeypot Investigation Agent

The system includes a **specialized agent** for analyzing honeypot servers to assess attack patterns, threat intelligence, and defensive effectiveness. Honeypots are decoy systems designed to attract attackers and provide early warning of emerging threats.

### When to Use Honeypot Investigation

Use this agent when you need to:
- **Analyze attack patterns** targeting your honeypot infrastructure
- **Extract threat intelligence** from failed connection attempts and exploit probes
- **Assess honeypot effectiveness** at detecting and logging malicious activity
- **Identify novel attack techniques** not yet cataloged in threat intelligence feeds
- **Generate executive reports** on threat landscape and attacker behavior

### Triggering Honeypot Investigation

**Via GitHub Copilot:**
```
Investigate honeypot-server for the last 48 hours
Run honeypot security analysis for HONEYPOT-01 from Dec 10-12
Generate honeypot report for honeypot-server last 7 days
```

Copilot automatically detects honeypot investigations using these keywords:
- "honeypot"
- "attack analysis"
- "threat actor"

When detected, Copilot reads the specialized workflow from [`agents/honeypotInvestigation/AGENTS.md`](agents/honeypotInvestigation/AGENTS.md) and follows the honeypot-specific investigation pattern.

### Honeypot Investigation Workflow

#### Phase 1: Query Failed Connections (PARALLEL)
Execute 3 queries simultaneously:
- **SecurityEvent** - Windows failed logon attempts (EventID 4625, 4771, 4776)
- **W3CIISLog** - IIS web server HTTP errors (4xx/5xx status codes)
- **DeviceNetworkEvents** - Defender network traffic (inbound connections to common ports: 3389, 80, 443, 445, 22, etc.)

Extract unique IP addresses → Save to `temp/honeypot_ips_<timestamp>.json`

#### Phase 2: IP Enrichment & Threat Intelligence (PARALLEL)
- **Run IP enrichment script** - `enrich_ips.py --file temp/honeypot_ips_*.json`
  - Geolocation (city, region, country)
  - ISP/Organization (ASN, org name)
  - VPN/Proxy/Tor detection
  - Abuse reputation (AbuseIPDB confidence scores)
- **Query Sentinel Threat Intelligence** - ThreatIntelIndicators bulk IP lookup
  - Known malicious IPs
  - APT group attribution
  - Threat descriptions and confidence levels

#### Phase 3: Query Security Incidents
- Get Device ID from Sentinel DeviceInfo table
- Query SecurityIncident + SecurityAlert (joined for full context)
- **Critical filtering:** Only report incidents with Status="New" or "Active"
  - Status="Closed" + Classification="BenignPositive" = expected honeypot activity (not a threat)

#### Phase 4: Vulnerability Assessment
- Activate Advanced Hunting tools (`mcp_sentinel-tria`)
- Get MDE Machine ID via Advanced Hunting
- Query vulnerabilities using `GetDefenderMachineVulnerabilities`
- Cross-reference CVEs with observed attack patterns (were attackers targeting known vulnerabilities?)

#### Phase 5: Generate Executive Report
Create comprehensive markdown report with:
- **Executive Summary** - Attack overview, threat intelligence correlation, vulnerability context
- **Attack Surface Analysis** - Failed connections by IP, service, exploit type (with CVE references)
- **Threat Intelligence Correlation** - Known malicious IPs, APT groups, abuse confidence scores
- **Security Incidents** - Active vs closed incidents with benign positive filtering
- **Attack Pattern Analysis** - Targeted services, credential attacks, web exploits, port scanning
- **Vulnerability Status** - Current CVEs with exploitation risk assessment
- **Key Detection Insights** - MITRE ATT&CK mapping, novel indicators, attacker sophistication assessment
- **Honeypot Effectiveness** - Detection rate, threat intelligence value, recommendations

### Honeypot Report Output

**Example:** `reports/Honeypot_Executive_Report_HONEYPOT-01_20251213_150229.md`

**Report includes:**
- Attack timeline with peak attack times and attacker timezone estimation
- Geographic distribution (top 10 source countries with ASN/org details)
- Threat intelligence hit rate (e.g., "67% of attacking IPs matched threat intel at 100% confidence")
- CVE targeting analysis (PHPUnit RCE CVE-2017-9841, Struts2 CVE-2017-5638, etc.)
- MITRE ATT&CK tactic/technique mapping with evidence
- Honeypot effectiveness metrics (incident detection rate, novel IOC discovery)
- Actionable recommendations (immediate/short-term/long-term)

### Honeypot-Specific Features

**IP Enrichment with JSON Format:**
- Honeypot investigations use **simple JSON format** for IP lists: `{"ips": ["1.2.3.4", "5.6.7.8"]}`
- Script automatically detects format (simple vs full investigation JSON)
- Backward compatible with standard user investigation format

**Attack Pattern Detection:**
- Automatically identifies exploit patterns (SQL injection, XSS, path traversal, webshells)
- CVE correlation (cross-references targeted URIs with known vulnerabilities)
- Post-exploitation indicators (internal port scanning, C2 communication)

**Threat Intelligence Matching:**
- Bulk IP lookup in Sentinel ThreatIntelIndicators (single query for multiple IPs)
- AbuseIPDB integration with comment extraction (shows attack types and reporter comments)
- APT group attribution when available

**Benign Positive Filtering:**
- Automatically filters out expected honeypot incidents (Status="Closed" + Classification="BenignPositive")
- Only reports active threats requiring investigation
- Distinguishes between successful honeypot deception vs actual security concerns

### Configuration for Honeypot Investigations

**Required data sources:**
- **SecurityEvent** - Windows Security logs forwarded to Sentinel
- **W3CIISLog** - IIS web server logs (if honeypot runs web services)
- **DeviceNetworkEvents** - Microsoft Defender for Endpoint network logs
- **SecurityIncident/SecurityAlert** - Defender XDR incidents
- **DeviceInfo** - Defender device inventory

**Optional enhancements:**
- **AbuseIPDB API token** - Increases rate limit to 10,000/day, provides abuse report comments
- **ipinfo.io paid tier** - Includes VPN detection without separate vpnapi.io token

### Sample Honeypot Investigation

```
================================================================================
🎣 HONEYPOT INVESTIGATION AGENT
================================================================================

Investigation Target: CONTOSO-ADMIN (honeypot-server)
Date Range: 2025-12-11 to 2025-12-13 (48 hours)
Investigation Date: 2025-12-13

[00:15] ✓ Failed connection queries completed (15 seconds)
   - SecurityEvent: 1,234 failed logon attempts from 45 IPs
   - W3CIISLog: 567 HTTP errors from 32 IPs
   - DeviceNetworkEvents: 89 connection attempts from 28 IPs
   - Total unique IPs: 55

[02:30] ✓ IP enrichment completed (135 seconds)
   - 37 VPNs detected
   - 2 proxies detected
   - 40 high-confidence abuse IPs (100% score)
   - 4 clean residential IPs
   - Threat intelligence: 12 IPs matched Sentinel indicators

[02:45] ✓ Security incidents query completed (15 seconds)
   - 4 incidents found (3 closed benign positive, 1 active HIGH severity)
   - Active incident: Multi-stage attack chain (CommandAndControl + Persistence)

[03:10] ✓ Vulnerability scan completed (25 seconds)
   - 12 CVEs found (3 CRITICAL, 5 HIGH, 4 MEDIUM)
   - 2 CVEs actively targeted by attackers (PHPUnit RCE, Struts2 exploit)

[05:45] ✓ Report generated (155 seconds)
   - Report: reports/Honeypot_Executive_Report_honeypot-server_20251213_150229.md
   - Attack patterns: 67% opportunistic scanning, 33% targeted exploitation
   - Threat intelligence value: HIGH (12 novel malicious IPs discovered)

Total elapsed time: 5 minutes 45 seconds (345 seconds)

================================================================================
KEY FINDINGS
================================================================================
🚨 ACTIVE THREATS: 1 HIGH severity incident (Incident #2325)
   - Multi-stage attack: Reconnaissance → Exploitation → Persistence
   - Attacker IP: 93.174.93.12 (Amsterdam, NL) - 100% abuse confidence (7,238 reports)
   
🌍 ATTACK LANDSCAPE:
   - 55 unique attackers from 12 countries
   - Top sources: Netherlands (18 IPs), China (12 IPs), Russia (8 IPs)
   - 67% using VPN/proxy infrastructure (bulletproof hosting)
   
⚠️ EXPLOITS DETECTED:
   - PHPUnit RCE (CVE-2017-9841): 234 attempts from 15 IPs
   - Struts2 exploit (CVE-2017-5638): 89 attempts from 8 IPs
   - Webshell uploads: 45 attempts (SystemBC backdoor, upl.php)
   
🎯 HONEYPOT EFFECTIVENESS:
   - Incident detection rate: 7.3% (4 incidents / 55 attackers)
   - Novel IOCs: 12 malicious IPs not in threat intel feeds
   - Value proposition: HIGH - early warning for emerging attack patterns

================================================================================
```

### Advanced Honeypot Features

**SessionId Authentication Tracing:**
- Honeypot agent inherits authentication analysis patterns from main copilot-instructions
- Can trace token reuse vs interactive MFA for sophisticated attackers
- Identifies geographic anomalies (impossible travel, VPN switching)

**Custom Attack Pattern Detection:**
- Modify KQL queries in `agents/honeypotInvestigation/AGENTS.md` to add custom patterns
- Example: Weekend activity detection, specific malware family checks, router exploit targeting

**Integration with SOC Workflows:**
- Export IOCs from honeypot investigations to organizational threat intelligence platforms
- Share novel indicators with Microsoft Sentinel watchlists
- Correlate honeypot findings with production incident investigations

**Performance:**
- Parallel query execution: ~60 seconds for all data collection
- IP enrichment: ~2-3 minutes for 50-100 IPs
- Total investigation time: 5-6 minutes end-to-end

**For complete honeypot workflow details, see:** [`agents/honeypotInvestigation/AGENTS.md`](agents/honeypotInvestigation/AGENTS.md)

---

### Follow-Up Analysis (using existing investigation JSON)
**Via GitHub Copilot:**
```
Trace authentication for that Singapore IP
```
Copilot will:
1. Locate most recent investigation JSON for that user
2. Read `ip_enrichment` array for Singapore IP details (VPN status, abuse score, threat intel)
3. Read `signin_ip_counts` for authentication patterns (MFA vs token reuse)
4. Search copilot-instructions.md for authentication tracing workflow
5. Provide risk assessment based on enrichment context

**Common follow-up prompts:**
- "Is that a VPN?" → Reads `is_vpn` field from IP enrichment
- "What's the abuse score?" → Reads `abuse_confidence_score` field
- "Show me all authentication details for that IP" → Runs SessionId trace query
- "Was MFA used?" → Checks `last_auth_result_detail` field

---

## 🤖 GitHub Copilot Integration

This system is **designed for GitHub Copilot MCP integration** using **[VS Code Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills)**. Investigation workflows are modularized into 10 specialized skills in `.github/skills/`, with universal patterns and skill detection logic in `.github/copilot-instructions.md`.

### Natural Language Investigation Prompts:

**Standard Investigations:**
```
Investigate user@domain.com for anomalies in the last 7 days
Run a security investigation on admin@contoso.com for the last 7 days
```

**Quick Investigations (1-2 days):**
```
Quick investigate suspicious.user@domain.com
Run quick security check on external.user@partner.com
```

**Comprehensive Investigations (30 days):**
```
Full investigation for compromised.user@domain.com
Do a deep dive investigation on user@vendor.com from Nov 1 to Nov 21
```

**Follow-Up Analysis (uses existing investigation JSON):**
```
Trace authentication for that Hong Kong IP
Is that Singapore IP a VPN?
What's the risk level for 203.0.113.42?
Show me all sign-ins from that IP
Was MFA used for those authentications?
```

### What Copilot Automatically Does:

1. **Retrieves User ID** - Queries Microsoft Graph for Azure AD Object ID and Windows SID
2. **Runs Parallel Queries** - Executes 10+ Sentinel queries + 6 Graph queries simultaneously
3. **Extracts and Prioritizes IPs** - Selects top 15 IPs (8 anomaly + 4 risky + 3 frequent)
4. **Enriches IPs** - Queries threat intel, geolocation, VPN detection, abuse scores
5. **Exports to JSON** - Saves all data to temp/investigation_*.json (uses `create_file` tool)
6. **Generates Report** - Runs `generate_report_from_json.py` with proper PYTHONPATH
7. **Tracks Performance** - Reports timing after each phase (User ID: 3s, Data: 88s, JSON: 1s, Report: 334s)
8. **Cleans Up Old Files** - Automatically deletes investigations older than 3 days

### Critical Workflow Features:

- **Follow-up question handling** - Checks existing JSON before re-querying Sentinel/Graph
- **IP enrichment reading** - Parses `ip_enrichment` array for VPN status, abuse scores, threat intel
- **Authentication tracing** - Uses SessionId-based workflow from copilot-instructions.md
- **Risk assessment** - Quotes specific instruction criteria for HIGH/MEDIUM/LOW classifications
- **Token management** - Never echoes JSON in chat (avoids token limits)

**See `.github/copilot-instructions.md` for:**
- Skill detection keywords and routing logic
- Universal patterns (date ranges, token management, follow-up analysis)
- Available skills table with trigger keywords
- Troubleshooting guide (common errors and solutions)

**See `.github/skills/` for specialized workflows:**
- `incident-investigation/SKILL.md` - Incident triage with entity extraction and deep investigation
- `user-investigation/SKILL.md` - Complete user security investigation workflow (Phase 1-5)
- `computer-investigation/SKILL.md` - Device security analysis for Entra/Hybrid/Registered devices
- `ioc-investigation/SKILL.md` - IoC analysis for IPs, domains, URLs, file hashes
- `honeypot-investigation/SKILL.md` - Attack pattern analysis and threat intel correlation
- `kql-query-authoring/SKILL.md` - Schema-validated KQL query generation
- `authentication-tracing/SKILL.md` - SessionId forensics, token reuse vs MFA analysis
- `ca-policy-investigation/SKILL.md` - Conditional Access policy bypass detection
- `heatmap-visualization/SKILL.md` - Interactive heatmap for time-based pattern visualization
- `geomap-visualization/SKILL.md` - Interactive world map for geographic attack visualization

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

## 📝 Sample Investigation Output

```
================================================================================
🔒 SECURITY INVESTIGATION SYSTEM - MCP WORKFLOW
================================================================================

Investigation Target: user@domain.com
Date Range: 2025-11-29 to 2025-12-03 (48 hours + timezone buffer)
Investigation Date: 2025-12-01

[00:03] ✓ User ID retrieved (3 seconds)
   - Azure AD Object ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
   - Windows SID: S-1-5-21-1234567890-1234567890-1234567890-1234

[01:31] ✓ All data collected in parallel (88 seconds)
   
   Batch 1 - Sentinel KQL Queries:
   - Anomalies: 0 results
   - Sign-in Apps: 5 applications (706-153 sign-ins each)
   - Sign-in Locations: 2 locations (US: 1712, CA: 1552)
   - Sign-in Failures: 1 error type (50207)
   - Audit Events: 2 categories (UserManagement, ApplicationManagement)
   - Office Activity: 5 operation types (MailItemsAccessed, MessageRead, etc.)
   - DLP Events: 0 results
   - Security Incidents: 4 incidents (all high severity, all closed benign positive)
   
   Batch 2 - IP Extraction & Enrichment:
   - IP Selection: 3 IPs extracted (20.236.10.66, 50.92.91.237, 50.92.88.234)
   - Threat Intel: 0 malicious IPs found
   - IP Frequency: 1655, 1437, 96 sign-ins per IP
   
   Batch 3 - Microsoft Graph Queries:
   - User Profile: John Doe, SecOps Analyst, IT Security
   - MFA Methods: 5 methods (Windows Hello, Phone, Authenticator, Email, Password)
   - Devices: 5 registered (3 compliant, 2 non-compliant)
   - Risk Profile: Low risk, atRisk state
   - Risk Detections: 5 events (4 anonymizedIPAddress remediated, 1 anomalousToken at-risk)
   - Risky Sign-ins: 2 risky authentications from Vancouver

[01:32] ✓ Investigation data exported to JSON (72 seconds)
   - File: temp/investigation_user_20251201_184900.json
   - Size: 4,425 lines

[05:54] ✓ Report generated (308 seconds)
   - IP Enrichment: 3 IPs enriched (ipinfo.io, vpnapi.io, AbuseIPDB)
   - Report: reports/Investigation_Report_Compact_user_2025-12-01_105405.html
   - Cleanup: 5 old files deleted (0.70 MB freed)

Total elapsed time: 5 minutes 54 seconds (354 seconds)

================================================================================
INVESTIGATION SUMMARY
================================================================================
User: user@domain.com (John Doe)
Job Title: SecOps Analyst
Department: IT Security
Period: 2025-11-29 to 2025-12-03 (48 hours)

📊 KEY METRICS:
- Total Sign-ins: 3,264 (1,655 + 1,437 + 96 across 3 IPs)
- Sign-in Failures: 1 (error 50207)
- Anomalies Detected: 0
- DLP Events: 0
- Security Incidents: 4 (all closed benign positive)

🛡️ IDENTITY PROTECTION:
- Risk Level: LOW
- Risk State: atRisk
- Risk Detections: 5 (4 remediated, 1 at-risk)
  - 4x anonymizedIPAddress (remediated) - VPN usage
  - 1x anomalousToken (at-risk) - Requires investigation

🌐 IP INTELLIGENCE:
- 20.236.10.66 (US) - 1,655 sign-ins, Azure Cloud, MFA satisfied
- 50.92.91.237 (CA) - 1,437 sign-ins, TELUS (Residential ISP), MFA satisfied
- 50.92.88.234 (CA) - 96 sign-ins, TELUS (Residential ISP), MFA satisfied

📋 RECOMMENDATIONS:
🔴 CRITICAL: None
🟡 HIGH PRIORITY:
  1. Investigate anomalousToken risk detection (at-risk state)
  2. Enforce compliance on 2 non-compliant devices
🔵 MONITORING:
  1. Continue monitoring sign-in patterns for anomalies

Overall Risk Assessment: LOW
Disposition: Normal user activity with isolated risk detection requiring investigation

================================================================================
```

---

## 👨‍💻 Contributing

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
