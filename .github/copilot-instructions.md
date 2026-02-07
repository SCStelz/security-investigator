# GitHub Copilot - Security Investigation Integration

This workspace contains a security investigation automation system. GitHub Copilot can help you run investigations using natural language.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[KQL Pre-Flight Checklist](#-kql-query-execution---pre-flight-checklist)** - Mandatory before EVERY query
3. **[Evidence-Based Analysis](#-evidence-based-analysis---global-rule)** - Anti-hallucination guardrails
4. **[Available Skills](#available-skills)** - Specialized investigation workflows
5. **[Ad-Hoc Queries](#appendix-ad-hoc-query-examples)** - Quick reference patterns
6. **[Troubleshooting](#troubleshooting-guide)** - Common issues and solutions

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**🤖 SKILL DETECTION:** Before starting any investigation, check the [Available Skills](#available-skills) section below and load the appropriate SKILL.md file.

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

## 🔴 KQL QUERY EXECUTION - PRE-FLIGHT CHECKLIST

**This checklist applies to EVERY KQL query before execution.**

**Exception — Skill & query library queries:** When following a SKILL.md investigation workflow or using a query directly from the `queries/` library, the queries are already verified and battle-tested. Skip Steps 1–4 and use those queries directly (substituting entity values as instructed). Step 5 (sanity-check zero results) still applies.

Before writing or executing any **ad-hoc KQL query** (i.e., not from a SKILL.md file), complete these steps **in order**:

### Step 1: Check for Existing Verified Queries

| Priority | Source | Action |
|----------|--------|--------|
| 1st | **Skills directory** (`.github/skills/`) | `grep_search` for the table name or entity pattern scoped to `.github/skills/**`. These are battle-tested queries with known pitfalls documented. |
| 2nd | **Queries library** (`queries/`) | `grep_search` for the table name, keyword, or technique scoped to `queries/**`. These are standalone verified query collections with standardized metadata headers (Tables, Keywords, MITRE fields). |
| 3rd | **This file's Appendix** | Check [Ad-Hoc Query Examples](#appendix-ad-hoc-query-examples) for canonical patterns (SecurityAlert→SecurityIncident join, AuditLogs best practices, etc.) |
| 4th | **KQL Search MCP** | Use `search_github_examples_fallback` or `validate_kql_query` for community-published examples |
| 5th | **Microsoft Learn MCP** | Use `microsoft_code_sample_search` with `language: "kusto"` for official examples |

**Short-circuit rule:** If a suitable query is found in Priority 1 (skills), Priority 2 (queries library), or Priority 3 (Appendix), skip Steps 2–4 and use it directly (substituting entity values). These sources are already schema-verified and pitfall-aware. Step 5 (sanity-check zero results) still applies.

### Step 2: Verify Table Schema

Before querying any table for the first time in a session, verify the schema:
- Use `search_tables` or `get_table_schema` from KQL Search MCP
- Confirm column names, types, and which columns contain GUIDs vs human-readable values
- Check if the table exists in Data Lake vs Advanced Hunting (see [Tool Selection Rule](#-tool-selection-rule-data-lake-vs-advanced-hunting))

### Step 3: Check Known Table Pitfalls

**Review this quick-reference before querying these tables:**

| Table | Pitfall | Required Action |
|-------|---------|----------------|
| **SecurityAlert** | `Status` field is **immutable** — always "New" regardless of actual state | MUST join with `SecurityIncident` to get real Status/Classification (see [Appendix pattern](#securityalertstatus-is-immutable---always-join-securityincident)) |
| **SecurityAlert** | `ProviderName` is an internal identifier (e.g., `MDATP`, `ASI Scheduled Alerts`, `MCAS`) and rolls up to generic names like `Microsoft XDR` at the incident level | Use **`ProductName`** for product grouping (e.g., `Azure Sentinel`, `Microsoft Defender Advanced Threat Protection`, `Microsoft Data Loss Prevention`). Also available: `ProductComponentName` (e.g., `Scheduled Alerts`, `NRT Alerts`). Translate raw values to current branding in reports. |
| **SecurityIncident** | `AlertIds` contains **SystemAlertId GUIDs**, NOT usernames, IPs, or entity names | NEVER filter `AlertIds` by entity name. Instead: query `SecurityAlert` first filtering by `Entities has '<entity>'`, then join to `SecurityIncident` on AlertId |
| **AuditLogs** | `InitiatedBy`, `TargetResources` are **dynamic fields** | Always wrap in `tostring()` before using `has` operator |
| **AuditLogs** | `OperationName` values vary across providers | Use broad `has "keyword"` instead of exact match for discovery queries |
| **SigninLogs** | `DeviceDetail`, `LocationDetails` are **dynamic fields** | Extract with `tostring(DeviceDetail.operatingSystem)` pattern |
| **SigninLogs** | `Location` is a **string** column, NOT dynamic. Dot-notation like `Location.countryOrRegion` will fail with SemanticError | Use `parse_json(LocationDetails).countryOrRegion` for geographic sub-properties. `Location` works with `dcount()`, `has`, `isnotempty()` but NOT dot-property access |
| **AADUserRiskEvents** | May have different retention than SigninLogs | Cross-reference with `SigninLogs` `RiskLevelDuringSignIn` for complete picture |
| **OfficeActivity** | Mailbox forwarding/redirect rules live here, **NOT in AuditLogs** | Filter by `OfficeWorkload == "Exchange"` and `Operation in~ ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")`. Check `Parameters` for `ForwardTo`, `RedirectTo`, `ForwardingSmtpAddress`. This table is the **primary source** for detecting email exfiltration via forwarding rules (MITRE T1114.003 / T1020). |
| **OfficeActivity** | `Parameters` and `OperationProperties` are **string fields** containing JSON | Use `contains` or `has` for keyword matching, then `parse_json(Parameters)` to extract specific values. Do NOT query AuditLogs for mailbox rule changes — they only appear in OfficeActivity (Exchange workload). |

### Step 4: Validate Before Execution

- For complex queries: use `validate_kql_query` to check syntax
- Ensure datetime filter is the FIRST filter in the query
- Use `take` or `summarize` to limit results

### Step 5: Sanity-Check Zero Results

**If a query returns 0 results for a commonly-populated table, STOP and verify:**

| Check | Action |
|-------|--------|
| Is the query logic correct? | Review join conditions, filter values, and field types |
| Am I filtering on GUIDs where I used a name (or vice versa)? | Check schema for field content type |
| Is the date range appropriate? | Ensure the time filter covers the expected data window |
| Does the table exist in this data source? | Try the other KQL execution tool if applicable |

⛔ **DO NOT report "no results found" until you have verified the query itself is correct.** A zero-result query may indicate a bad query, not absence of data.

### 🔴 PROHIBITED Actions

| Action | Status |
|--------|--------|
| Writing KQL from scratch without completing Steps 1-2 | ❌ **PROHIBITED** |
| Querying a table for the first time without checking schema | ❌ **PROHIBITED** |
| Filtering `SecurityIncident.AlertIds` by entity names | ❌ **PROHIBITED** |
| Reading `SecurityAlert.Status` as current investigation status | ❌ **PROHIBITED** |
| Reporting 0 results without sanity-checking the query logic | ❌ **PROHIBITED** |
| Assuming field content types without schema verification | ❌ **PROHIBITED** |

---

## 🔴 EVIDENCE-BASED ANALYSIS - GLOBAL RULE

**This rule applies to ALL skills, ALL queries, and ALL investigation outputs.**

### Core Principle
Base ALL findings strictly on data returned by MCP tools. Never invent, assume, or extrapolate data that was not explicitly retrieved.

### Required Behaviors

| Scenario | Required Action |
|----------|----------------|
| Query returns 0 results | State explicitly: "✅ No [anomaly/alert/event type] found in [time range]" |
| Field is null/missing in response | Report as "Unknown" or "Not available" - never fabricate values |
| Partial data available | State what WAS found and what COULD NOT be verified |
| User asks about data not queried | Query first, then answer - never guess based on "typical patterns" |

### 🔴 PROHIBITED Actions

| Action | Status |
|--------|--------|
| Inventing IP addresses, usernames, or entity names | ❌ **PROHIBITED** |
| Assuming counts or statistics not in query results | ❌ **PROHIBITED** |
| Describing "typical behavior" when no baseline was queried | ❌ **PROHIBITED** |
| Omitting sections silently when no data exists | ❌ **PROHIBITED** |
| Using phrases like "likely", "probably", "typically" without evidence | ❌ **PROHIBITED** |

### ✅ REQUIRED Output Patterns

**When data IS found:**
```
📊 Found 47 failed sign-ins from IP 203.0.113.42 between 2026-01-15 and 2026-01-22.
Evidence: SigninLogs query returned 47 records with ResultType=50126.
```

**When NO data is found:**
```
✅ No failed sign-ins detected for user@domain.com in the last 7 days.
Query: SigninLogs | where UserPrincipalName =~ 'user@domain.com' | where ResultType != 0
Result: 0 records
```

**When data is PARTIAL:**
```
⚠️ Sign-in data available, but DeviceEvents table not accessible in this workspace.
Verified: 12 successful authentications from 3 IPs
Unable to verify: Endpoint process activity (table not found)
```

### Risk Assessment Grounding

When assigning risk levels, cite the specific evidence:

| Risk Level | Evidence Required |
|------------|-------------------|
| **High** | Must cite ≥2 concrete findings (e.g., "AbuseIPDB score 95 + 47 failed logins in 1 hour") |
| **Medium** | Must cite ≥1 concrete finding with context (e.g., "New IP not in 90-day baseline") |
| **Low** | Must explain why low despite investigation (e.g., "IP is known corporate VPN egress") |
| **Informational** | Must still cite what was checked: "No alerts, no anomalies, no risky sign-ins found" |

### Emoji Formatting for Investigation Output

Use color-coded emojis consistently throughout investigation reports to make risks, mitigating factors, and status immediately scannable:

| Category | Emoji | When to Use |
|----------|-------|-------------|
| **High risk / critical finding** | 🔴 | High-severity alerts, confirmed compromise, high abuse scores, active threats |
| **Medium risk / warning** | 🟠 | Medium-severity detections, unresolved risk states, suspicious but unconfirmed activity |
| **Low risk / minor concern** | 🟡 | Low-severity detections, informational anomalies, items needing review but not urgent |
| **Mitigating factor / positive** | 🟢 | MFA enforced, phishing-resistant auth, clean threat intel, risk remediated/dismissed |
| **Informational / neutral** | 🔵 | Contextual notes, baseline data, configuration details, reference information |
| **Absence confirmed / clean** | ✅ | No alerts found, no anomalies, clean query results, verified safe |
| **Needs attention / action item** | ⚠️ | Unresolved risks, report-only policies, recommendations requiring human decision |
| **Data not available** | ❓ | Table not accessible, partial data, unable to verify |

**Example usage in summary tables:**
```markdown
| Factor | Finding |
|--------|---------|
| 🟢 **Auth Method** | Phishing-resistant passkey (device-bound) — strong credential |
| 🟠 **IP Reputation** | VPN exit node with 14 abuse reports (low confidence 5%) |
| 🔴 **Unresolved Risk** | `unfamiliarFeatures` detection still atRisk — needs admin action |
| ⚠️ **CA Policy Gap** | "Require MFA for risky sign-ins" is report-only, not enforcing |
| ✅ **MFA Enforcement** | MFA required and passed on 16/18 sign-ins |
```

Apply these emojis in:
- Summary assessment tables (prefix the factor name)
- Section headers when results indicate clear risk or clean status
- Inline findings where risk/mitigation context helps readability
- Recommendation items (prefix with ⚠️ for action items, 🟢 for confirmations)

### Explicit Absence Confirmation

After every investigation section, confirm what was checked even if nothing was found:

```markdown
## Security Alerts
✅ No security alerts involving user@domain.com in the last 30 days.
- Checked: SecurityAlert table (0 matches)
- Checked: SecurityIncident for associated entities (0 matches)
```

### KQL Query Research - Use Published Queries First

> **📋 Full pre-flight checklist:** See [KQL QUERY EXECUTION - PRE-FLIGHT CHECKLIST](#-kql-query-execution---pre-flight-checklist) above. This subsection summarizes the query research requirement.

Before writing any KQL query from scratch, **search for existing human-verified queries** in these sources (in priority order):

1. **Skills directory (`.github/skills/`):** Search existing SKILL.md files for reference queries using the table or pattern you need. These are battle-tested queries with known pitfalls documented (e.g., `SecurityAlert.Status` immutability, dynamic field parsing). Use `grep_search` with the table name or keyword scoped to `.github/skills/**`.
2. **Queries library (`queries/`):** Search standalone query collections for the table name, keyword, or MITRE technique. These files follow a standardized metadata header format with `Tables:`, `Keywords:`, and `MITRE:` fields for efficient keyword search. Use `grep_search` scoped to `queries/**`.
3. **This file's [Appendix](#appendix-ad-hoc-query-examples):** Check for canonical query patterns (SecurityAlert→SecurityIncident join, AuditLogs, etc.) before writing from scratch.
4. **KQL Search MCP:** Use `search_github_examples_fallback` or `validate_kql_query` to find community-published query examples from repositories like Azure-Sentinel and Microsoft-365-Defender-Hunting-Queries. Use `get_table_schema` to verify column names before querying.
5. **Microsoft Learn MCP:** Use `microsoft_code_sample_search` with `language: "kusto"` to find official Microsoft KQL examples.

**Why this matters:** Published queries encode institutional knowledge about schema quirks, immutable fields, required joins, and edge cases that are easy to get wrong when writing queries from scratch. Always prefer adapting a verified query over inventing one.

| Action | Status |
|--------|--------|
| Writing KQL without completing the [Pre-Flight Checklist](#-kql-query-execution---pre-flight-checklist) | ❌ **PROHIBITED** |
| Assuming field behavior without verifying in skill docs | ❌ **PROHIBITED** |
| Using a table for the first time without checking schema | ❌ **PROHIBITED** |

### Technical Context Enrichment

When explaining technical concepts, use **Microsoft Learn MCP** to ground responses in official documentation:

| When to Use | Example |
|-------------|---------|
| Explaining error codes | Search for "SigninLogs ResultType 50126" to get official meaning |
| Describing attack techniques | Search for "AiTM phishing" or "token theft" for official remediation guidance |
| Clarifying Azure/M365 features | Search for "Conditional Access device compliance" for accurate configuration details |
| Interpreting log fields | Search for table schema documentation when field meaning is unclear |

**Workflow:**
1. `microsoft_docs_search` → Find relevant articles
2. `microsoft_docs_fetch` → Get complete details when needed
3. **Cite the source** in your response (include URL when providing technical guidance)

---

## Available Skills

**BEFORE starting any investigation, detect if user request matches a specialized skill:**

| Skill | Description | Trigger Keywords |
|-------|-------------|------------------|
| **incident-investigation** | Comprehensive incident analysis for Defender XDR and Sentinel incidents: criticality assessment, entity extraction, filtering (RFC1918 IPs, tenant domains), recursive entity investigation using specialized skills | "investigate incident", "incident ID", "analyze incident", "triage incident", incident number |
| **user-investigation** | Azure AD user security analysis: sign-ins, anomalies, MFA, devices, audit logs, incidents, Identity Protection, HTML reports | "investigate user", "security investigation", "check user activity", UPN/email |
| **computer-investigation** | Device security analysis for Entra Joined, Hybrid Joined, and Entra Registered devices: Defender alerts, compliance, logged-on users, vulnerabilities, process/network/file events, automated investigations | "investigate computer", "investigate device", "investigate endpoint", "check machine", hostname |
| **ioc-investigation** | Indicator of Compromise analysis: IP addresses, domains, URLs, file hashes. Includes Defender Threat Intelligence, Sentinel TI tables, CVE correlation, organizational exposure assessment, and affected device enumeration | "investigate IP", "investigate domain", "investigate URL", "investigate hash", "IoC", "is this malicious", "threat intel", IP/domain/URL/hash |
| **honeypot-investigation** | Honeypot security analysis: attack patterns, threat intel, vulnerabilities, executive reports | "honeypot", "attack analysis", "threat actor" |
| **critical-storage-exposure** | Critical storage security analysis: exposure perimeter, attack paths, single point of failure detection for Azure Storage Accounts, Blob Containers, and AWS S3 Buckets. Uses ExposureGraph to identify who can access critical storage resources | "critical storage exposure", "storage security", "blob security", "S3 exposure", "storage attack paths", "data exfiltration risk" |
| **kql-query-authoring** | KQL query creation using schema validation, community examples, Microsoft Learn | "write KQL", "create KQL query", "help with KQL", "query [table]" |
| **authentication-tracing** | Azure AD authentication chain forensics: SessionId analysis, token reuse vs interactive MFA, geographic anomaly investigation, risk assessment | "trace authentication", "SessionId analysis", "token reuse", "geographic anomaly", "impossible travel" |
| **ca-policy-investigation** | Conditional Access policy forensics: sign-in failure correlation, policy state changes, security bypass detection, privilege abuse analysis | "Conditional Access", "CA policy", "device compliance", "policy bypass", "53000", "50074", "530032" |
| **scope-drift-detection** | Scope drift analysis for service principals AND user accounts: 90-day behavioral baseline vs. 7-day recent activity, weighted Drift Score (5 dimensions for SPNs; 7 dimensions for user interactive including apps/devices; 6 for non-interactive), correlated with AuditLogs, DeviceNetworkEvents, SecurityAlert, SigninLogs_Anomalies_KQL_CL, and Identity Protection. Supports inline chat and markdown file output | "scope drift", "service principal drift", "SPN behavioral change", "baseline deviation", "access expansion", "automation account drift", "user drift", "user behavioral change" |
| **heatmap-visualization** | Interactive heatmap visualization for Sentinel data: attack patterns by time, activity grids, IP vs hour matrices, threat intel drill-down panels | "heatmap", "show heatmap", "visualize patterns", "activity grid" |
| **geomap-visualization** | Interactive world map visualization for Sentinel data: attack origin maps, geographic threat distribution, IP geolocation with enrichment drill-down | "geomap", "world map", "attack map", "show on map", "attack origins" |

### Skill Detection Workflow

1. **Parse user request** for trigger keywords from table above
2. **If match found:** Read `.github/skills/<skill-name>/SKILL.md`
3. **Follow skill-specific workflow** (inherits global rules from this file)
4. **Future skills:** Check `.github/skills/` folder with `list_dir` to discover new workflows

**Skill files location:** `.github/skills/<skill-name>/SKILL.md`

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

---

## APPENDIX: Ad-Hoc Query Examples

### SecurityAlert.Status Is Immutable - Always Join SecurityIncident

**⚠️ CRITICAL:** The `Status` field on the `SecurityAlert` table is set to `"New"` at creation time and **never changes**. It does NOT reflect whether the alert has been investigated, closed, or classified.

To get the **actual investigation status**, you MUST join with `SecurityIncident`:

```kql
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has '<ENTITY>'
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| summarize Title = any(Title), Severity = any(Severity), Status = any(Status),
    Classification = any(Classification), CreatedTime = any(CreatedTime)
    by ProviderIncidentId
| order by CreatedTime desc
```

| Field | Source | Meaning |
|-------|--------|----------|
| `SecurityAlert.Status` | Alert table | **Immutable creation status** - always "New" |
| `SecurityIncident.Status` | Incident table | **Real status** - New/Active/Closed |
| `SecurityIncident.Classification` | Incident table | **Closure reason** - TruePositive/FalsePositive/BenignPositive |

**Reference:** See `.github/skills/geomap-visualization/SKILL.md` Query 6 and `.github/skills/user-investigation/SKILL.md` for the canonical join pattern.

---

### Queries Library — Standardized Format (`queries/`)

All query files in `queries/` MUST use this standardized metadata header for efficient `grep_search` discovery:

**File naming convention:** `{topic}.md` — lowercase, underscores, no redundant suffixes like `_queries` or `_sentinel`. Keep names short and descriptive of the detection scenario or data domain (e.g., `app_credential_management.md`, `rdp_lateral_movement.md`, `endpoint_failed_connections.md`).

```markdown
# <Title>

**Created:** YYYY-MM-DD  
**Platform:** Microsoft Sentinel | Microsoft Defender XDR | Both  
**Tables:** <comma-separated list of exact KQL table names>  
**Keywords:** <comma-separated searchable terms — attack techniques, scenarios, field names>  
**MITRE:** <comma-separated technique IDs, e.g., T1021.001, TA0008>  
**Timeframe:** Last N days (configurable)  
```

**Required fields for search efficiency:**

| Field | Purpose | Example |
|-------|---------|---------|
| `Tables:` | Exact KQL table names for `grep_search` by table | `AuditLogs, SecurityAlert, SecurityIncident` |
| `Keywords:` | Searchable terms covering attack scenarios, operations, field names | `credential, secret, certificate, persistence, app registration` |
| `MITRE:` | ATT&CK technique and tactic IDs | `T1098.001, T1136.003, TA0003` |

**Search pattern:** `grep_search` scoped to `queries/**` with the table name or keyword will hit the metadata header and locate the right file instantly.

**When creating new query files:** Follow this format. When updating existing files that lack these fields, add them.

**PII-Free Standard:** Query files in `queries/` must NEVER contain tenant-specific PII such as real workspace names, UPNs, server hostnames, GUIDs, or application names from live environments. Use generic placeholders (e.g., `<YourAppName>`, `user@contoso.com`, `<WorkspaceName>`) instead. Before committing or saving a query file, verify it contains no environment-specific identifiers.

---

### IP Enrichment Utility (`enrich_ips.py`)

Use `enrich_ips.py` to enrich IP addresses with **3rd-party threat intelligence** from ipinfo.io, vpnapi.io, and AbuseIPDB. This provides VPN/proxy/Tor detection, ISP/ASN details, hosting provider identification, abuse confidence scores, and recent community-reported attack activity.

**When to use:**
- Whenever the user asks to enrich, investigate, or check IPs
- When risky sign-ins, anomalies, or suspicious activity involve unfamiliar IP addresses
- During ad-hoc investigations, follow-up analysis, or spot-checking suspicious IPs
- Any time IP context would improve the investigation (e.g., confirming VPN usage, checking abuse history)

**When NOT to use:**
- When already executing a prescriptive skill workflow (from `.github/skills/`) that has its own built-in IP enrichment step — follow the skill's guidance instead to avoid duplication

```powershell
# Enrich specific IPs
python enrich_ips.py 203.0.113.42 198.51.100.10 192.0.2.1

# Enrich all unenriched IPs from an investigation file
python enrich_ips.py --file temp/investigation_user_20251130.json
```

**Output:** Detailed per-IP results (city, country, ISP/ASN, VPN/proxy/Tor flags, AbuseIPDB score + recent report comments) and a JSON export saved to `temp/`.

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

## Troubleshooting Guide

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Graph API returns 404 for entity** | Verify UPN/ID is correct; check if entity exists with different identifier |
| **Sentinel query timeout** | Reduce date range or add `| take 100` to limit results |
| **KQL syntax error** | Validate query with `validate_kql_query` tool before execution |
| **SemanticError: Failed to resolve column** | Field doesn't exist in table schema - use `get_table_schema` to check valid columns |
| **SemanticError: Failed to resolve table** | Table not in Data Lake - try `RunAdvancedHuntingQuery` instead |
| **Dynamic field errors (DeviceDetail, LocationDetails)** | Use `tostring()` wrapper or `parse_json()` to extract values |
| **Risky sign-ins query fails** | Must use `/beta` endpoint, not `/v1.0` |
| **Multiple workspaces available** | Follow SENTINEL WORKSPACE SELECTION rule - ask user to choose |
