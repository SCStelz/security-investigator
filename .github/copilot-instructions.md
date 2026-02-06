# GitHub Copilot - Security Investigation Integration

This workspace contains a security investigation automation system. GitHub Copilot can help you run investigations using natural language.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Available Skills](#available-skills)** - Specialized investigation workflows
3. **[Universal Patterns](#universal-patterns)** - Date ranges, time tracking, token management
4. **[Follow-Up Analysis](#-critical-follow-up-analysis-workflow-mandatory)** - Working with existing data
5. **[Ad-Hoc Queries](#appendix-ad-hoc-query-examples)** - Quick reference patterns
6. **[Troubleshooting](#troubleshooting-guide)** - Common issues and solutions

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**🤖 SPECIALIZED SKILLS DETECTION:**

**BEFORE starting any investigation, detect if user request requires a specialized skill:**

| Keywords in Request | Action Required |
|---------------------|-----------------|
| **"investigate incident"**, "incident ID", "incident investigation", "analyze incident", "triage incident", incident number with investigation context | Use the **incident-investigation** skill at `.github/skills/incident-investigation/SKILL.md` |
| **"investigate user"**, "security investigation", "check user activity", UPN/email with investigation context | Use the **user-investigation** skill at `.github/skills/user-investigation/SKILL.md` |
| **"investigate computer"**, "investigate device", "investigate endpoint", "check machine", "device security", hostname with investigation context | Use the **computer-investigation** skill at `.github/skills/computer-investigation/SKILL.md` |
| **"investigate IP"**, "investigate domain", "investigate URL", "investigate hash", "IoC investigation", "is this malicious", "threat intel", "check if [IP/domain/URL] is malicious", IP address or domain with investigation context | Use the **ioc-investigation** skill at `.github/skills/ioc-investigation/SKILL.md` |
| **"honeypot"**, "attack analysis", "threat actor" | Use the **honeypot-investigation** skill at `.github/skills/honeypot-investigation/SKILL.md` |
| **"write KQL"**, "create KQL query", "help with KQL", "query [table]", "KQL for [scenario]" | Use the **kql-query-authoring** skill at `.github/skills/kql-query-authoring/SKILL.md` |
| **"trace authentication"**, "trace back to interactive MFA", "SessionId analysis", "token reuse", "geographic anomaly", "impossible travel" | Use the **authentication-tracing** skill at `.github/skills/authentication-tracing/SKILL.md` |
| **"Conditional Access"**, "CA policy", "device compliance", "policy bypass", "53000", "50074", "530032" | Use the **ca-policy-investigation** skill at `.github/skills/ca-policy-investigation/SKILL.md` |
| **"heatmap"**, "show heatmap", "visualize patterns", "activity grid", "time-based visualization" | Use the **heatmap-visualization** skill at `.github/skills/heatmap-visualization/SKILL.md` |
| **"geomap"**, "world map", "geographic", "attack map", "show on map", "attack origins" | Use the **geomap-visualization** skill at `.github/skills/geomap-visualization/SKILL.md` |
| **Future skills** | Check `.github/skills/` folder with `list_dir` to discover available specialized workflows |

**Detection Pattern:**
1. Parse user request for specialized keywords
2. If match found: Read the appropriate SKILL.md file from `.github/skills/<skill-name>/SKILL.md`
3. Follow skill-specific workflow (inherits universal patterns from this file)

---

## 🔴 SENTINEL WORKSPACE SELECTION - GLOBAL RULE

**This rule applies to ALL skills and ALL Sentinel queries. Follow STRICTLY.**

When executing ANY Sentinel query (via the Sentinel Data Lake `query_lake` MCP tool):

### Workspace Selection Flow

1. **BEFORE first query:** Call `list_sentinel_workspaces()` to enumerate available workspaces
2. **If exactly 1 workspace:** Auto-select, display to user, proceed
3. **If multiple workspaces AND no prior selection in session:**
   - Display ALL workspaces with Name and ID
   - ASK user: "Which Sentinel workspace should I use for this investigation? Select one or more, or 'all'."
   - **⛔ STOP AND WAIT** for explicit user response
   - **⛔ DO NOT proceed until user selects**
4. **If query fails on selected workspace:**
   - **⛔ STOP IMMEDIATELY**
   - Report: "⚠️ Query failed on [WORKSPACE_NAME]. Error: [ERROR_MESSAGE]"
   - Display available workspaces
   - ASK user to select a different workspace
   - **⛔ DO NOT automatically retry with another workspace**

### 🔴 PROHIBITED ACTIONS

| Action | Status |
|--------|--------|
| Auto-selecting workspace when multiple exist | ❌ **PROHIBITED** |
| Switching workspaces after query failure without asking | ❌ **PROHIBITED** |
| Proceeding with ambiguous workspace context | ❌ **PROHIBITED** |
| Assuming workspace from previous conversation turns | ❌ **PROHIBITED** |
| Making any workspace decision on behalf of user | ❌ **PROHIBITED** |

### ✅ REQUIRED ACTIONS

| Scenario | Required Action |
|----------|----------------|
| Multiple workspaces, none selected | STOP, list all, ASK user, WAIT |
| Query fails with table/workspace error | STOP, report error, ASK user, WAIT |
| Single workspace available | Auto-select, DISPLAY to user, proceed |
| Workspace already selected in session | Reuse selection, DISPLAY which workspace is being used |

---

## Available Skills

| Skill | Description | Trigger Keywords |
|-------|-------------|------------------|
| **incident-investigation** | Comprehensive incident analysis for Defender XDR and Sentinel incidents: criticality assessment, entity extraction, filtering (RFC1918 IPs, tenant domains), recursive entity investigation using specialized skills | "investigate incident", "incident ID", "incident investigation", "analyze incident", "triage incident", incident number |
| **user-investigation** | Azure AD user security analysis: sign-ins, anomalies, MFA, devices, audit logs, incidents, Identity Protection, HTML reports | "investigate user", "security investigation", "check user activity", UPN/email |
| **computer-investigation** | Device security analysis for Entra Joined, Hybrid Joined, and Entra Registered devices: Defender alerts, compliance, logged-on users, vulnerabilities, process/network/file events, automated investigations | "investigate computer", "investigate device", "investigate endpoint", "check machine", hostname |
| **ioc-investigation** | Indicator of Compromise analysis: IP addresses, domains, URLs, file hashes. Includes Defender Threat Intelligence, Sentinel TI tables, CVE correlation, organizational exposure assessment, and affected device enumeration | "investigate IP", "investigate domain", "investigate URL", "investigate hash", "IoC", "is this malicious", "threat intel", IP/domain/URL/hash |
| **honeypot-investigation** | Honeypot security analysis: attack patterns, threat intel, vulnerabilities, executive reports | "honeypot", "attack analysis", "threat actor" |
| **critical-storage-exposure** | Critical storage security analysis: exposure perimeter, attack paths, single point of failure detection for Azure Storage Accounts, Blob Containers, and AWS S3 Buckets. Uses ExposureGraph to identify who can access critical storage resources | "critical storage exposure", "storage security", "blob security", "S3 exposure", "storage attack paths", "data exfiltration risk", storage account/container/bucket with investigation context |
| **kql-query-authoring** | KQL query creation using schema validation, community examples, Microsoft Learn | "write KQL", "create KQL query", "help with KQL", "query [table]" |
| **authentication-tracing** | Azure AD authentication chain forensics: SessionId analysis, token reuse vs interactive MFA, geographic anomaly investigation, risk assessment | "trace authentication", "trace back to interactive MFA", "SessionId analysis", "token reuse", "geographic anomaly" |
| **ca-policy-investigation** | Conditional Access policy forensics: sign-in failure correlation, policy state changes, security bypass detection, privilege abuse analysis | "Conditional Access", "CA policy", "device compliance", "policy bypass", "53000", "50074" |
| **heatmap-visualization** | Interactive heatmap visualization for Sentinel data: attack patterns by time, activity grids, IP vs hour matrices, threat intel drill-down panels | "heatmap", "show heatmap", "visualize patterns", "activity grid" |
| **geomap-visualization** | Interactive world map visualization for Sentinel data: attack origin maps, geographic threat distribution, IP geolocation with enrichment drill-down | "geomap", "world map", "geographic", "attack map", "attack origins" |

**Skill files location:** `.github/skills/<skill-name>/SKILL.md`

---

## Universal Patterns

**These patterns apply to ALL skills and ad-hoc queries:**

**Why this matters:**
- Sample queries include proper field handling (`Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'`)
- They avoid errors on dynamic fields (LocationDetails, ModifiedProperties, DeviceDetail)
- They're production-validated

**Example: User asks "What's that password reset about?" → Go to Sample Queries → Use Query #4**

---

## 🔄 CRITICAL: Follow-Up Analysis Workflow (MANDATORY)

**⚠️ BEFORE answering ANY follow-up question, you MUST:**
1. ✅ Check if investigation JSON exists for that user/date range
2. ✅ **Search copilot-instructions.md for relevant guidance** (use grep_search with topic keyword)
3. ✅ **Query Sentinel/Graph if you need addtional data** ONLY query Sentinel/Graph if enriched data AND instructions are insufficient
4. ✅ Search `ip_enrichment` json for relevant IP's if needed before coming to conclusions (contains VPN, ISP, abuse scores, threat intel)


**Common follow-up patterns that REQUIRE using enriched JSON:**
- "Trace authentication for [IP/location]" → Read `ip_enrichment` array + `signin_ip_counts`
- "Is that a VPN?" → Read `ip_enrichment` array, find IP, check `is_vpn` field
- "What's the risk level?" → Read `ip_enrichment` array, check `risk_level` + `abuse_confidence_score`
- "Tell me about [IP address]" → Read `ip_enrichment` array, filter by `ip` field (e.g., `"ip": "203.0.113.42"`)
- "Show me authentication details" → Read `ip_enrichment` array, check `last_auth_result_detail` field
- "Was that IP flagged by threat intel?" → Read `ip_enrichment` array, check `threat_description` field (non-empty = match)

**DO NOT re-query threat intel or sign-in data if it's already in the JSON file!**

**How to read IP enrichment data:**
1. Locate investigation JSON: `temp/investigation_<upn_prefix>_<timestamp>.json`
2. Read file and parse JSON structure
3. Navigate to `ip_enrichment` array (near end of file, after `risk_detections`/`risky_signins`)
4. Find IP entry: `ip_enrichment` is an array of objects - filter by `"ip": "<target_ip>"`
5. Extract relevant fields: `is_vpn`, `abuse_confidence_score`, `threat_description`, `last_auth_result_detail`, etc.

**How to find the investigation JSON:**
- Pattern: `temp/investigation_<upn_prefix>_<timestamp>.json`
- Most recent file for user is usually the one to analyze
- Use `file_search` or `list_dir` to locate existing investigations

---

## Integration with MCP Servers

The investigation system integrates with these MCP servers (which Copilot has access to):

### Microsoft Sentinel Data Lake MCP
Execute KQL queries and explore table schemas directly against your Sentinel workspace:
- **mcp_sentinel-data_query_lake**: Execute read-only KQL queries on Sentinel data lake tables. Best practices: filter on datetime first, use `take` or `summarize` operators to limit results, prefer narrowly scoped queries with explicit filters
- **mcp_sentinel-data_search_tables**: Discover table schemas using natural language queries. Returns table definitions to support query authoring
- **mcp_sentinel-data_list_sentinel_workspaces**: List all available Sentinel workspace name/ID pairs
- **Documentation**: https://learn.microsoft.com/en-us/azure/sentinel/datalake/

### Microsoft Sentinel Triage MCP
Incident investigation and threat hunting tools for Defender XDR and Sentinel:
- **Incident Management**: List/get incidents (`ListIncidents`, `GetIncidentById`), list/get alerts (`ListAlerts`, `GetAlertByID`)
- **Advanced Hunting**: Run KQL queries across Defender tables (`RunAdvancedHuntingQuery`), fetch table schemas (`FetchAdvancedHuntingTablesOverview`, `FetchAdvancedHuntingTablesDetailedSchema`)
- **Entity Investigation**: File info/stats/alerts (`GetDefenderFileInfo`, `GetDefenderFileStatistics`, `GetDefenderFileAlerts`), device details (`GetDefenderMachine`, `GetDefenderMachineAlerts`, `GetDefenderMachineLoggedOnUsers`), IP analysis (`GetDefenderIpAlerts`, `GetDefenderIpStatistics`), user activity (`ListUserRelatedAlerts`, `ListUserRelatedMachines`)
- **Vulnerability Management**: List affected devices (`ListDefenderMachinesByVulnerability`), software vulnerabilities (`ListDefenderVulnerabilitiesBySoftware`)
- **Remediation**: List/get remediation tasks (`ListDefenderRemediationActivities`, `GetDefenderRemediationActivity`)
- **When to Use**: Incident triage, threat hunting over your own Defender/Sentinel data, correlating alerts/entities during investigations
- **Documentation**: https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool

### 🔧 Tool Selection Rule: Data Lake vs Advanced Hunting

**When to use which KQL execution tool:**

| Scenario | Tool to Use |
|----------|-------------|
| **Default for most tables** | `mcp_sentinel-data_query_lake` (SigninLogs, AuditLogs, SecurityAlert, SecurityIncident, Device* tables, etc.) |
| **AzureDiagnostics table** | `RunAdvancedHuntingQuery` **ONLY** - this table is NOT in Sentinel Data Lake |
| **DeviceTvm* tables** (DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, etc.) | `RunAdvancedHuntingQuery` **ONLY** - TVM snapshot tables are NOT in Sentinel Data Lake |
| **XDR tables (Device*, Alert*, Email*, etc.)** | Try `mcp_sentinel-data_query_lake` first - these tables exist in Data Lake **only under specific conditions**; otherwise, they won't exist |
| **Table not found error** | If `mcp_sentinel-data_query_lake` fails with "table not found" or similar error, **retry with `RunAdvancedHuntingQuery`** - the table may exist only in Defender XDR Advanced Hunting |

**Important Notes:**
- `mcp_sentinel-data_query_lake` uses `TimeGenerated` as timestamp column
- `RunAdvancedHuntingQuery` uses `Timestamp` as timestamp column (adjust queries accordingly)
- Always check the error message - "Failed to resolve table" or "table not found" indicates the table doesn't exist in that data source

### KQL Search MCP
GitHub-powered KQL query discovery and schema intelligence (331+ tables from Defender XDR, Sentinel, Azure Monitor):
- **GitHub Query Discovery**: Search GitHub for KQL examples (`search_github_examples_fallback` ✅), find repos (`search_kql_repositories` ✅), extract from files (`get_kql_from_file` ✅). **Note:** `search_favorite_repos` has a known bug (v1.0.5) - use `search_github_examples_fallback` instead.
- **Schema Intelligence**: Get table schemas (`get_table_schema`), search tables by description (`search_tables`), find columns (`find_column`), list categories (`list_table_categories`)
- **Query Generation & Validation**: Generate validated KQL queries from natural language (`generate_kql_query`), validate existing queries (`validate_kql_query`), get Microsoft Learn docs (`get_query_documentation`)
- **ASIM Schema Support**: Search/validate/generate queries for 11 ASIM schemas (`search_asim_schemas`, `get_asim_schema_info`, `validate_asim_parser`, `generate_asim_query_template`)
- **When to Use**: Writing new KQL queries, finding query examples from community repos (Azure-Sentinel, Microsoft-365-Defender-Hunting-Queries), validating query syntax before execution, understanding table schemas
- **Documentation**: https://www.npmjs.com/package/kql-search-mcp

### Microsoft Learn MCP
Official Microsoft/Azure documentation search and code samples:
- **microsoft_docs_search**: Semantic search across Microsoft Learn documentation (returns up to 10 high-quality content chunks with title, URL, excerpt)
- **microsoft_docs_fetch**: Fetch complete Microsoft Learn pages in markdown format (use after search when you need full tutorials, troubleshooting guides, or complete documentation)
- **microsoft_code_sample_search**: Search official Microsoft/Azure code samples (up to 20 relevant code snippets with optional `language` filter: csharp, javascript, typescript, python, powershell, azurecli, sql, java, kusto, etc.)
- **When to Use**: Grounding answers in official Microsoft knowledge, finding latest Azure/Microsoft 365/Security documentation, getting official code examples for Microsoft technologies, verifying API usage patterns
- **Workflow**: Use `microsoft_docs_search` first for breadth → `microsoft_code_sample_search` for practical examples → `microsoft_docs_fetch` for depth when needed
- **Documentation**: https://learn.microsoft.com/en-us/training/support/mcp-get-started

### Microsoft Graph MCP
Azure AD and Microsoft 365 API integration:
- **mcp_microsoft_mcp_microsoft_graph_suggest_queries**: Find Graph API endpoints using natural language intent descriptions
- **mcp_microsoft_mcp_microsoft_graph_get**: Execute Graph API calls (MUST call suggest_queries first to get correct endpoints)
- **mcp_microsoft_mcp_microsoft_graph_list_properties**: Explore entity schemas when RAG examples are insufficient
- **Critical Workflow**: ALWAYS call `suggest_queries` before `get` - never construct URLs from memory. Resolve template variables before making final API calls
- **Documentation**: Built-in Graph MCP integration

### Sentinel Heatmap MCP (Custom Visualization)
Interactive heatmap visualization for Sentinel security data, rendered inline in VS Code chat:
- **mcp_sentinel-heat_show-signin-heatmap**: Display aggregated data as an interactive heatmap with optional threat intel drill-down
- **Location**: `mcp-apps/sentinel-heatmap-server/` (local TypeScript/React MCP App)

**Tool Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `data` | ✅ | Array of `{row, column, value}` objects from KQL query |
| `title` | ❌ | Heatmap title (default: "Sign-In Heatmap") |
| `rowLabel` | ❌ | Label for rows (e.g., "IP Address", "Application") |
| `colLabel` | ❌ | Label for columns (e.g., "Hour", "Day") |
| `valueLabel` | ❌ | Label for cell values (e.g., "Failed Attempts", "Sign-ins") |
| `colorScale` | ❌ | Color scheme: `green-red` (activity), `blue-red` (threats), `blue-yellow` (neutral) |
| `enrichment` | ❌ | Array of IP enrichment objects for click-to-expand threat intel panel |

**Enrichment Schema (for drill-down panels):**
```json
{
  "ip": "80.94.95.83",
  "city": "Timișoara",
  "country": "RO",
  "org": "AS204428 SS-Net",
  "is_vpn": false,
  "abuse_confidence_score": 100,
  "total_reports": 975,
  "last_reported": "2026-01-29",
  "threat_categories": ["RDP Brute-Force", "Hacking", "Port Scan"]
}
```

**When to Use:**
- Visualizing attack patterns by IP and time (honeypot investigations)
- Sign-in activity heatmaps by application and hour
- Failed authentication attempts by location and day
- Any aggregated Sentinel data with row/column/value structure

**KQL Query Pattern for Heatmap Data:**
```kql
<Table>
| where TimeGenerated between (start .. end)
| summarize value = count() by row = <dimension1>, column = format_datetime(bin(TimeGenerated, 1h), "HH:mm")
| project row, column, value
| order by column asc
```

**Example - Attack Heatmap by IP and Hour:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-01-26) .. datetime(2026-01-27))
| where EventID == 4625
| summarize value = count() by row = IpAddress, column = format_datetime(bin(TimeGenerated, 1h), "HH:mm")
| project row, column, value
| order by column asc, value desc
```

**Features:**
- 📊 Dark theme matching VS Code (Microsoft brand colors)
- 🎨 Three color scales for different use cases
- 🔍 Hover tooltips showing full details
- 🖱️ Click-to-expand threat intel panels (when enrichment data provided)
- 📈 Auto-calculated statistics (total, max, min, unique rows/columns)

### Custom Sentinel Tables

#### SigninLogs_Anomalies_KQL_CL
**Purpose:** Pre-computed sign-in anomaly detection table populated by hourly KQL job. Tracks new IPs and device combinations against 90-day baseline.

**Key Features:**
- **Anomaly Types:** `NewInteractiveIP`, `NewInteractiveDeviceCombo`, `NewNonInteractiveIP`, `NewNonInteractiveDeviceCombo`
- **Detection Model:** Compares last 1 hour activity against 90-day baseline (excluding most recent hour)
- **IPv6 Filtering:** Excludes transient IPv6 addresses to reduce false positives
- **Geographic Novelty:** Tracks country/city/state changes with novelty flags
- **Severity Scoring:** Based on artifact hit frequency and geographic novelty

**Key Columns:**
- `DetectedDateTime`: When anomaly was detected
- `UserPrincipalName`: Affected user
- `AnomalyType`: Category of anomaly
- `Value`: Anomalous artifact (IP address or OS|BrowserFamily combo)
- `Severity`: High/Medium/Low/Informational (based on hit count + geo novelty)
- `ArtifactHits`: Count of occurrences in 1-hour window
- `CountryNovelty`, `CityNovelty`, `StateNovelty`: Geographic novelty flags
- `BaselineSize`: Historical artifact baseline count
- `FirstSeenRecent`: First appearance timestamp
- `Baseline*List`: Arrays of historical IPs, countries, cities, devices, browsers

**When to Use:**
- Rapid anomaly triage during user investigations
- Identifying suspicious IP origins or device changes
- Geographic impossible travel detection
- Token theft indicators (non-interactive anomalies with geo changes)
- Baseline comparison for new authentication patterns

**Example Query:**
```kql
// Get high-severity anomalies for user
Signinlogs_Anomalies_KQL_CL
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ '<UPN>'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10 or CountryNovelty or CityNovelty or StateNovelty, "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| where Severity in ("High", "Medium")
| project DetectedDateTime, AnomalyType, Value, Severity, Country, City, 
    ArtifactHits, CountryNovelty, CityNovelty, OS, BrowserFamily
| order by DetectedDateTime desc
```

**Severity Thresholds (Hourly Detection):**
- **High:** ≥20 hits/hour + geographic novelty (very aggressive use)
- **Medium:** ≥10 hits/hour OR any geographic novelty
- **Low:** ≥5 hits/hour without geographic novelty
- **Informational:** 1-4 hits/hour

**Full Documentation:** See [docs/Signinlogs_Anomalies_KQL_CL.md](../docs/Signinlogs_Anomalies_KQL_CL.md) for complete schema and triage guidance.

## Configuration

Configuration is stored in `config.json`:
```json
{
  "sentinel_workspace_id": "<YOUR_WORKSPACE_ID>",
  "tenant_id": "your-tenant-id-here",
  "ipinfo_token": null,
  "output_dir": "reports"
}
```

---

## APPENDIX: Ad-Hoc Query Examples

### Ad-Hoc IP Enrichment Utility

For quick IP enrichment during investigation follow-ups, use the `enrich_ips.py` utility:

```powershell
# Enrich specific IPs from anomaly analysis
python enrich_ips.py 203.0.113.42 198.51.100.10 192.0.2.1

# Enrich all unenriched IPs from an investigation file
python enrich_ips.py --file temp/investigation_user_20251130.json
```

**Features:** Enriches IPs using ipinfo.io, vpnapi.io, and AbuseIPDB. Detects VPN, proxy, Tor, hosting, and abuse scores. Exports results to JSON.

**When to use:** Follow-up analysis, spot-checking suspicious IPs, completing partial investigations. **DO NOT use in main investigation workflow** (IP enrichment is already built into report generation).

---

### Best Practices for AuditLogs Queries

**CRITICAL: Use broad, simple filters for OperationName searches**

When searching AuditLogs for specific operations (password resets, role changes, policy modifications, etc.):

**❌ DON'T use overly specific filters:**
```kql
| where OperationName has_any ("password", "reset")  // May miss operations
| where OperationName == "Reset user password"       // Too restrictive - misses variations
```

**✅ DO use broad keyword matching:**
```kql
| where OperationName has "password"  // Catches all password-related operations
| where OperationName has "role"      // Catches all role-related operations
| where OperationName has "policy"    // Catches all policy-related operations
```

**Why this matters:**
- OperationName values vary: "Reset user password", "Change user password", "Self-service password reset", "Update password"
- `has_any()` requires exact word matches and can be unpredictable
- Simple `has "keyword"` is more reliable for exploratory queries
- You can always filter results further in subsequent `summarize` or `where` clauses

**Example - Finding password operations:**
```kql
AuditLogs
| where TimeGenerated between (start .. end)
| where OperationName has "password"  // Broad search
| where tostring(InitiatedBy) has '<UPN>' or tostring(TargetResources) has '<UPN>'
| summarize Count = count() by OperationName  // Then see what operations exist
| order by Count desc
```

**Then refine if needed:**
```kql
// After seeing results, target specific operation if necessary
| where OperationName == "Reset user password"
```

**Field Matching Best Practices:**
- **Always use `tostring()` for dynamic fields:** `tostring(InitiatedBy)`, `tostring(TargetResources)`
- **Use `has` for substring matching:** `tostring(InitiatedBy) has '<UPN>'`
- **Use `=~` for exact case-insensitive match:** `Identity =~ '<UPN>'`
- **Avoid direct field access on complex JSON:** Parse first with `parse_json()` then extract

---

### Enumerating User Permissions and Roles

When asked to check permissions or roles for a user account, **ALWAYS query BOTH**:

1. **Permanent Role Assignments** (active roles)
2. **PIM-Eligible Roles** (roles that can be activated on-demand)

**Step 1: Get User Object ID**
```
/v1.0/users/<UPN>?$select=id
```

**Step 2: Get Permanent Role Assignments**
```
/v1.0/roleManagement/directory/roleAssignments?$select=principalId&$filter=principalId eq '<USER_ID>'&$expand=roleDefinition($select=templateId,displayName,description)
```

**Step 3: Get PIM-Eligible Roles**
```
/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$select=memberType,startDateTime,endDateTime&$filter=principalId eq '<USER_ID>'&$expand=principal($select=id),roleDefinition($select=id,displayName,description)
```

**Step 4: Get Active PIM Role Assignments (time-bounded)**
```
/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=assignmentType,memberType,startDateTime,endDateTime&$filter=principalId eq '<USER_ID>' and startDateTime le <CURRENT_DATETIME> and endDateTime ge <CURRENT_DATETIME>&$expand=principal($select=id),roleDefinition($select=id,displayName,description)
```

**Example Output Format:**
```
Total Role Inventory for <USER>:

Permanent Active Roles (X):
1. Global Administrator
2. Security Administrator
...

PIM-Eligible Roles (Y):
1. Exchange Administrator (Eligible since: <date>, Expiration: <date or ∞>)
2. Intune Administrator (Eligible since: <date>, Expiration: <date or ∞>)
...

Active PIM Role Assignments (Z):
1. [Role Name] (Activated: <start>, Expires: <end>, Assignment Type: <type>)
...
```

**Security Analysis Guidance:**
- Flag if high-privilege roles (Global Admin, Security Admin, Application Admin) are **permanently assigned** instead of PIM-eligible
- Recommend converting permanent privileged roles to PIM-eligible with approval workflows
- Note if PIM eligibilities have no expiration (should be reviewed periodically)

---

## Output

The investigation generates:
- **JSON data file**: Raw investigation results
- **HTML report**: Professional, browser-ready report with:
  - Executive summary
  - Key metrics dashboard
  - Anomaly findings
  - IP intelligence cards
  - User profile & MFA status
  - Device inventory
  - Audit log timeline
  - Security alerts table
  - Risk assessment
  - Prioritized recommendations
  - Investigation conclusion

**Report Theme:**
- **Default**: Dark theme with Microsoft brand colors
  - Background: Dark gray gradients (#1a1a1a → #2d2d2d)
  - Primary accent: Microsoft blue (#00a1f1, #0078d4)
  - Highlights: Microsoft orange (#f65314), gold (#ffbb00), green (#7cbb00)
  - High contrast text for accessibility (#e0e0e0 on dark backgrounds)
- **Color Palette**:
  - Orange: #f65314 (critical alerts)
  - Gold: #ffbb00 (high priority)
  - Blue: #00a1f1 (medium/info)
  - Green: #7cbb00 (low/success)
  - Gray: #737373 (neutral elements)

## Example Workflow

User says: **"Investigate user@domain.com for suspicious activity in the last 7 days"**

Copilot should:
1. **Phase 1:** Get user Object ID from Microsoft Graph
2. **Phase 2:** Run all Sentinel and Graph queries in parallel batches
3. **Phase 2c:** Extract IPs and run threat intelligence query
4. **Phase 2d:** Create single JSON file with all results in temp/
5. **Phase 3:** Run `generate_report_from_json.py` script with JSON file path
6. Show the user the report path and provide brief summary

See "OPTIMIZED PARALLEL EXECUTION PATTERN" section above for detailed workflow.

## Error Handling

If the investigation encounters issues:
- Missing configuration: Falls back to defaults
- MCP query failures: Logs warnings, continues with available data
- IP enrichment failures: Returns "Error" status, continues investigation
- Missing user data: Shows "Unknown" in report, continues

The investigation is designed to be resilient and complete successfully even with partial data.

## Troubleshooting Guide

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Missing `department` or `officeLocation` in Graph API response** | Use `"Unknown"` as default value in JSON |
| **No anomalies found in Sentinel query** | Export empty array: `"anomalies": []` |
| **Graph API returns 404 for user** | Verify UPN is correct; check if user exists with different UPN |
| **Sentinel query timeout** | Reduce date range or add `| take 5` to limit results |
| **Missing `trustType` in device query** | Use default: `"trustType": "Workplace"` |
| **Null `approximateLastSignInDateTime`** | Use default: `"approximateLastSignInDateTime": "2025-01-01T00:00:00Z"` |
| **Report generation fails** | Check JSON file has ALL required fields; validate JSON syntax |
| **KQL syntax error** | Use EXACT query patterns from Sample KQL Queries section |
| **SemanticError: Failed to resolve column** | Field doesn't exist in table schema - remove it or check Sample KQL Queries for correct field names |
| **DeviceDetail, LocationDetails, ModifiedProperties errors** | These are dynamic fields - use `| take 1` to see raw structure, then parse with `parse_json()` or remove from query |
| **No results from SecurityIncident query** | Ensure you're using BOTH `targetUPN` and `targetUserId` variables |
| **Risky sign-ins query fails** | Must use `/beta` endpoint, not `/v1.0` |

### Required Field Defaults

If Graph API returns null for these fields, use these defaults:

```json
{
  "department": "Unknown",
  "officeLocation": "Unknown",
  "trustType": "Workplace",
  "approximateLastSignInDateTime": "2025-01-01T00:00:00Z"
}
```

### Empty Result Handling

If a Sentinel query returns no results, include empty arrays:

```json
{
  "anomalies": [],
  "signin_apps": [],
  "signin_locations": [],
  "signin_failures": [],
  "audit_events": [],
  "office_events": [],
  "dlp_events": [],
  "incidents": [],
  "risk_detections": [],
  "risky_signins": [],
  "threat_intel_ips": []
}
```

## Security Notes

- All reports are marked CONFIDENTIAL
- Reports contain sensitive user information
- Store reports securely
- Follow organizational data classification policies
- Investigation actions are logged for audit trail
