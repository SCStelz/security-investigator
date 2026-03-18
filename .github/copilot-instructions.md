# GitHub Copilot - Security Investigation Integration

This workspace contains a security investigation automation system. GitHub Copilot can help you run investigations using natural language.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Environment Configuration](#-environment-configuration)** - Read `config.json` for workspace/tenant details
3. **[KQL Pre-Flight Checklist](#-kql-query-execution---pre-flight-checklist)** - Mandatory before EVERY query
4. **[Evidence-Based Analysis](#-evidence-based-analysis---global-rule)** - Anti-hallucination guardrails
5. **[Available Skills](#available-skills)** - Specialized investigation workflows
6. **[Ad-Hoc Queries](#appendix-ad-hoc-query-examples)** - Quick reference patterns
7. **[Troubleshooting](#troubleshooting-guide)** - Common issues and solutions

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**🤖 SKILL DETECTION:** Before starting any investigation, check the [Available Skills](#available-skills) section below and load the appropriate SKILL.md file.

---

## 🔧 ENVIRONMENT CONFIGURATION

**Environment-specific values (workspace IDs, tenant IDs, resource group names, API tokens) are stored in `config.json` at the workspace root.** This file is gitignored and never committed.

When you need environment values (especially for Azure MCP Server calls), **read `config.json`** instead of asking the user or hardcoding values.

**Schema** (see `config.json.template` for field names):

| Field | Used By | Purpose |
|-------|---------|--------|
| `sentinel_workspace_id` | Sentinel Data Lake MCP (`query_lake`) | Log Analytics workspace GUID |
| `tenant_id` | All Azure/Sentinel tools | Entra ID tenant |
| `subscription_id` | Azure MCP Server, Azure CLI | Azure subscription |
| `azure_mcp.resource_group` | Azure MCP `workspace_log_query` | RG containing Log Analytics workspace |
| `azure_mcp.workspace_name` | Azure MCP `workspace_log_query` | Log Analytics workspace display name |
| `azure_mcp.tenant` | Azure MCP Server (all calls) | Required to avoid cross-tenant auth errors |
| `azure_mcp.subscription` | Azure MCP Server (all calls) | Target subscription |
| `ipinfo_token` | `enrich_ips.py` | ipinfo.io API key |
| `abuseipdb_token` | `enrich_ips.py` | AbuseIPDB API key |
| `vpnapi_token` | `enrich_ips.py` | vpnapi.io API key |
| `shodan_token` | `enrich_ips.py` | Shodan API key |

### Prerequisites

| Dependency | Required By | Setup |
|------------|-------------|-------|
| **Azure CLI** (`az`) | Azure MCP Server (underlying auth), `sentinel-ingestion-report` skill (`az rest` for rule inventory, `az monitor` for tier classification) | Install: [aka.ms/installazurecli](https://aka.ms/installazurecli). Authenticate: `az login --tenant <tenant_id>`. Set subscription: `az account set --subscription <subscription_id>` |

> **Note:** Individual skills may have additional CLI dependencies documented in their own SKILL.md files. Check the skill file for skill-specific requirements before running a workflow.

**When making Azure MCP Server calls**, always pass `tenant` and `subscription` from `config.json` to avoid the multi-tenant auth issue (DefaultAzureCredential may pick up the wrong tenant).

---

## 🔴 SENTINEL WORKSPACE SELECTION - GLOBAL RULE1

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
| **SigninLogs** / **AADNonInteractiveUserSignInLogs** | `DeviceDetail`, `LocationDetails`, `ConditionalAccessPolicies`, `Status` may be **dynamic OR string** depending on workspace (Data Lake workspaces store them as strings). `AADNonInteractiveUserSignInLogs` stores these as **string always** | Always use `tostring(parse_json(DeviceDetail).operatingSystem)` — works for both types. Direct dot-notation `DeviceDetail.operatingSystem` fails with SemanticError when column is string type. Same applies to `Status` (use `parse_json(Status).errorCode`), `ConditionalAccessPolicies` — use `parse_json()` before dot-access or `mv-expand` |
| **SigninLogs** | `Location` is a **string** column, NOT dynamic. Dot-notation like `Location.countryOrRegion` will fail with SemanticError | Use `parse_json(LocationDetails).countryOrRegion` for geographic sub-properties. `Location` works with `dcount()`, `has`, `isnotempty()` but NOT dot-property access |
| **AADUserRiskEvents** | May have different retention than SigninLogs | Cross-reference with `SigninLogs` `RiskLevelDuringSignIn` for complete picture |
| **OfficeActivity** | Mailbox forwarding/redirect rules live here, **NOT in AuditLogs** | Filter by `OfficeWorkload == "Exchange"` and `Operation in~ ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")`. Check `Parameters` for `ForwardTo`, `RedirectTo`, `ForwardingSmtpAddress`. This table is the **primary source** for detecting email exfiltration via forwarding rules (MITRE T1114.003 / T1020). |
| **OfficeActivity** | `Parameters` and `OperationProperties` are **string fields** containing JSON | Use `contains` or `has` for keyword matching, then `parse_json(Parameters)` to extract specific values. Do NOT query AuditLogs for mailbox rule changes — they only appear in OfficeActivity (Exchange workload). |
| **Signinlogs_Anomalies_KQL_CL** | Custom `_CL` table names are **case-sensitive**. Table uses lowercase 'l' in "logs" — `Signinlogs` NOT `SigninLogs`. LLMs auto-correct this to match `SigninLogs` | Always copy exact table name `Signinlogs_Anomalies_KQL_CL`. If `SemanticError: Failed to resolve table`, verify casing first. If still fails, table may not exist in the workspace — skip gracefully |
| **SentinelHealth** | `SentinelResourceType` values use **title-case with a space**: `"Analytics Rule"`, NOT `"Analytic rule"`. LLMs consistently generate the wrong casing/spelling, returning 0 results despite 30k+ rows in the table | Always use `SentinelResourceType == "Analytics Rule"` (capital A, capital R, "Analytics" with an 's'). Other valid values: `"Data connector"`, `"Automation rule"`. If query returns 0 rows, check this filter first |
| **AADRiskySignIns** | Table does **NOT exist** in Sentinel Data Lake. Querying it returns `SemanticError: Failed to resolve table` | Use `AADUserRiskEvents` instead (contains Identity Protection risk detections). For sign-in-level risk data, use `SigninLogs` with `RiskLevelDuringSignIn` and `RiskState` columns |
| **SecurityIncident / SecurityAlert** | `IncidentNumber` and `SystemAlertId` are **Sentinel-local IDs** — the Triage MCP (`GetIncidentById`, `GetAlertById`) uses **Defender XDR IDs** and returns "not found" for Sentinel IDs | Use `SecurityIncident.ProviderIncidentId` for Triage MCP incident lookups. For alert drill-down, extract `parse_json(ExtendedProperties).IncidentId` from SecurityAlert. See [Sentinel ↔ Defender XDR ID Mapping](#-sentinel--defender-xdr-id-mapping--global-rule) for full mapping table |
| **AIAgentsInfo** | **Advanced Hunting only** — does NOT exist in Sentinel Data Lake. Multiple records per agent (state snapshots); `KnowledgeDetails` is a string containing a JSON array of JSON strings; `IsGenerativeOrchestrationEnabled` may be null | Always use `RunAdvancedHuntingQuery`. Deduplicate with `summarize arg_max(Timestamp, *) by AIAgentId`. Double-parse KnowledgeDetails: `mv-expand KnowledgeRaw = parse_json(KnowledgeDetails) \| extend KnowledgeJson = parse_json(tostring(KnowledgeRaw))`. Treat null GenAI flag as unknown. Table is in **Preview** — schema may change |
| **DataSecurityEvents** | **Advanced Hunting only** — requires Insider Risk Management opt-in. `SensitiveInfoTypeInfo` is `Collection(String)` NOT native dynamic — requires double `parse_json()`. Contains SIT **GUIDs** not names. Copilot events ("Risky prompt entered in Copilot", "Sensitive response received in Copilot") can dominate 90%+ of volume. `ObjectId` is the file identifier — `ObjectName`/`ObjectType` do NOT exist despite documentation. **Label columns:** `SensitivityLabelId` (string, can be comma-separated), `PreviousSensitivityLabelId` (string, label change events), `SharepointSiteSensitivityLabelId` (string), `RiskyAIUsageSensitivityLabelsInfo` (Collection(String), mostly `[null]`). Label data is sparse in SIT-dominant environments but significant in Purview-mature orgs | Always use `RunAdvancedHuntingQuery`. Double-parse: `mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo)) \| extend SITJson = parse_json(tostring(SIT))`. Pre-filter with `where SensitiveInfoTypeInfo has "<GUID>"` before `mv-expand`. Use `split(SensitivityLabelId, ",")` for multi-GUID label values. Use `data-security-analysis` skill for SIT and label GUID-to-name resolution. If table returns 0 rows, check IRM opt-in status |
| **AzureDiagnostics** | Commonly on **Analytics tier**, NOT Data Lake tier. `mcp_sentinel-data_query_lake` returns `SemanticError: Failed to resolve table` even though the table exists in the workspace. This is NOT the same table as `AzureActivity`. **AzureDiagnostics** = resource-specific diagnostic logs (Key Vault data plane: `SecretGet`, `Authentication`, `VaultGet`; SQL auditing; Firewall logs; App Service logs, etc.). **AzureActivity** = ARM control plane operations (resource creation/deletion, policy actions, role assignments, deployments). Confusing the two leads to querying the wrong table and missing critical data plane evidence | If Data Lake returns "Failed to resolve table", **immediately** try `RunAdvancedHuntingQuery` (AH can query Analytics-tier tables). Do NOT fall back to `AzureActivity` — it contains completely different data. Key columns: `ResourceType` (e.g., `VAULTS`), `OperationName` (e.g., `SecretGet`), `CallerIPAddress`, `ResultType`, `Resource` (resource name), `Category` (e.g., `AuditEvent`). Filter pattern: `AzureDiagnostics \| where ResourceType == "VAULTS" \| where Resource =~ "<vault-name>"`. For Key Vault investigations, look for `OperationName` values like `SecretGet`, `SecretList`, `Authentication`, `VaultGet` |

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

| Category | Skill | Description | Trigger Keywords |
|----------|-------|-------------|------------------|
| 🔍 Core Investigation | **computer-investigation** | Device security analysis for Entra Joined, Hybrid Joined, and Entra Registered devices: Defender alerts, compliance, logged-on users, vulnerabilities, process/network/file events, automated investigations | "investigate computer", "investigate device", "investigate endpoint", "check machine", hostname |
| 🔍 Core Investigation | **honeypot-investigation** | Honeypot security analysis: attack patterns, threat intel, vulnerabilities, executive reports | "honeypot", "attack analysis", "threat actor" |
| 🔍 Core Investigation | **incident-investigation** | Comprehensive incident analysis for Defender XDR and Sentinel incidents: criticality assessment, entity extraction, filtering (RFC1918 IPs, tenant domains), recursive entity investigation using specialized skills | "investigate incident", "incident ID", "analyze incident", "triage incident", incident number |
| 🔍 Core Investigation | **ioc-investigation** | Indicator of Compromise analysis: IP addresses, domains, URLs, file hashes. Includes Defender Threat Intelligence, Sentinel TI tables, CVE correlation, organizational exposure assessment, and affected device enumeration | "investigate IP", "investigate domain", "investigate URL", "investigate hash", "IoC", "is this malicious", "threat intel", IP/domain/URL/hash |
| 🔍 Core Investigation | **user-investigation** | Azure AD user security analysis: sign-ins, anomalies, MFA, devices, audit logs, incidents, Identity Protection, reports (inline chat, markdown file, HTML) | "investigate user", "security investigation", "check user activity", UPN/email |
| 🔐 Auth & Access | **authentication-tracing** | Azure AD authentication chain forensics: SessionId analysis, token reuse vs interactive MFA, geographic anomaly investigation, risk assessment | "trace authentication", "SessionId analysis", "token reuse", "geographic anomaly", "impossible travel" |
| 🔐 Auth & Access | **ca-policy-investigation** | Conditional Access policy forensics: sign-in failure correlation, policy state changes, security bypass detection, privilege abuse analysis | "Conditional Access", "CA policy", "device compliance", "policy bypass", "53000", "50074", "530032" |
| 📈 Behavioral Analysis | **scope-drift-detection/device** | Device/endpoint scope drift analysis: configurable-window process baseline for devices (fleet-wide or single-device). Weighted Drift Score (5 dimensions: Volume, Processes, Accounts, Process Chains, Signing Companies), correlated with SecurityAlert, DeviceInfo (uptime corroboration via MDE sensor health), DeviceProcessEvents. Supports inline chat and markdown file output | "device drift", "device process drift", "endpoint drift", "process baseline", "device behavioral change", "device scope drift" |
| 📈 Behavioral Analysis | **scope-drift-detection/spn** | SPN scope drift analysis: 90-day behavioral baseline vs. 7-day recent activity for service principals. Weighted Drift Score (5 dimensions: Volume, Resources, IPs, Locations, FailRate), correlated with SecurityAlert and AuditLogs. Supports inline chat and markdown file output | "scope drift", "service principal drift", "SPN behavioral change", "SPN drift", "baseline deviation", "access expansion", "automation account drift" |
| 📈 Behavioral Analysis | **scope-drift-detection/user** | User account scope drift analysis: 90-day behavioral baseline vs. 7-day recent activity for user accounts (UPNs). Two Drift Scores — Interactive (7 dimensions) and Non-Interactive (6 dimensions), correlated with SecurityAlert, AuditLogs, Signinlogs_Anomalies_KQL_CL, Identity Protection, CloudAppEvents (cloud app activity drift), and EmailEvents (email pattern drift). Supports inline chat and markdown file output | "user drift", "user behavioral change", "user scope drift", "UPN drift", "sign-in drift", "user baseline deviation" |
| 🛡️ Posture & Exposure | **exposure-investigation** | Vulnerability & Exposure Management reporting: CVE assessment with exploit/CVSS data, security configuration compliance, end-of-support software, ExposureGraph critical assets, attack paths, MDC security/management recommendations, MDE sensor health, certificate status. Org-wide and per-device scope. Inline chat and markdown file output | "vulnerability report", "exposure report", "CVE assessment", "security posture", "vulnerability assessment", "exposure management", "patch status", "end of support", "security recommendations", "attack paths", "critical assets", "configuration compliance", "TVM", "threat and vulnerability management" |
| �️ Posture & Exposure | **ai-agent-posture** | AI agent security posture audit for Copilot Studio and M365 Copilot agents: agent inventory, authentication gaps, access control misconfigurations, MCP tool proliferation, knowledge source exposure, XPIA email exfiltration risk, hard-coded credential detection, HTTP request risk, creator governance, agent sprawl analysis. Agent Security Score with 5 risk dimensions. Inline chat and markdown file output | "AI agent posture", "agent security audit", "Copilot Studio agents", "agent inventory", "agent authentication", "unauthenticated agents", "agent tools", "MCP tools on agents", "agent knowledge sources", "XPIA risk", "agent sprawl", "AI agent risk", "agent governance" |
| 🔒 Data Security | **data-security-analysis** | DataSecurityEvents (Purview/IRM) analysis: SIT access breakdowns, sensitivity label access patterns, user risk ranking, file inventory, DLP policy correlation, Copilot SIT exposure, label change tracking (downgrades/removals), Copilot label exposure, SIT GUID-to-name resolution (built-in + PowerShell), label GUID-to-name resolution (built-in + PowerShell), anomaly detection (7d vs 30d baseline spikes). Designed for 100k+ user environments with aggressive summarization. Inline chat and markdown file output | "data security", "sensitive information type", "SIT access", "who accessed sensitive data", "DLP events", "DataSecurityEvents", "EDM access", "exact data match", "credit card access", "sensitive file access", "insider risk activity", "Purview data security", "SIT breakdown", "classify access", "sensitivity label", "labeled documents", "label downgrade", "label change", "Copilot label exposure" |
| 📊 Visualization | **geomap-visualization** | Interactive world map visualization for Sentinel data: attack origin maps, geographic threat distribution, IP geolocation with enrichment drill-down | "geomap", "world map", "attack map", "show on map", "attack origins" |
| 📊 Visualization | **heatmap-visualization** | Interactive heatmap visualization for Sentinel data: attack patterns by time, activity grids, IP vs hour matrices, threat intel drill-down panels | "heatmap", "show heatmap", "visualize patterns", "activity grid" |
| 🔧 Tooling & Monitoring | **detection-authoring** | Create, deploy, update, and manage Defender XDR custom detection rules via Graph API. Query adaptation from Sentinel KQL, manifest-driven batch deployment via PowerShell, lifecycle management. Companion script: Deploy-CustomDetections.ps1 | "create custom detection", "deploy detection", "detection rule", "custom detection", "deploy rule", "batch deploy" |
| 🔧 Tooling & Monitoring | **kql-query-authoring** | KQL query creation using schema validation, community examples, Microsoft Learn | "write KQL", "create KQL query", "help with KQL", "query [table]" |
| 🔧 Tooling & Monitoring | **mcp-usage-monitoring** | MCP server usage monitoring and audit: Graph MCP endpoint analysis, Sentinel MCP auth events, Azure MCP ARM operations, workspace query governance, MCP proportion analysis, sensitive API detection, off-hours activity, user attribution, MCP Usage Score with 5 health/risk dimensions. Supports inline chat and markdown file output | "MCP usage", "MCP server monitoring", "MCP activity", "MCP audit", "Graph MCP", "Sentinel MCP", "Azure MCP", "AI agent monitoring", "tool usage monitoring", "MCP breakdown", "who is using MCP" |
| 🔧 Tooling & Monitoring | **sentinel-ingestion-report** | Sentinel workspace ingestion analysis: YAML-driven PowerShell pipeline gathers all data via az monitor/az rest/Graph API, writes a deterministic scratchpad, LLM renders the report. Covers table-level volume breakdown, tier classification (Analytics/Basic/Data Lake), SecurityEvent/Syslog/CommonSecurityLog deep dives, ingestion anomaly detection (24h and WoW), analytic rule inventory via REST API, rule health via SentinelHealth, detection coverage cross-reference, tier migration candidates with DL-eligibility lookup, license benefit analysis (DfS P2 500MB/server/day, M365 E5 data grant). **Post-report drill-down:** rule cross-referencing (AR via REST + CD via Graph API), ASIM parser dependency checks, error handling. Inline chat and markdown file output. **Companion files:** SKILL-report.md (rendering templates), SKILL-drilldown.md (drill-down patterns + pitfalls) | "ingestion report", "usage report", "data volume", "cost analysis", "table breakdown", "data lake tier", "ingestion anomaly", "cost optimization", "billable data", "workspace usage", "table ingestion", "SecurityEvent breakdown", "Defender for Servers benefit", "E5 ingestion benefit", "drill down", "which rules use", "rule cross-reference", "custom detection rules", "ASIM dependency", "ingestion drill-down" |

### Skill Detection Workflow

1. **Parse user request** for trigger keywords from table above
2. **If match found:** Read the skill file:
   - Standard skills: `.github/skills/<skill-name>/SKILL.md`
   - Subfolder skills (e.g., scope-drift-detection): `.github/skills/<parent-skill>/<sub-skill>/SKILL.md`
3. **Follow skill-specific workflow** (inherits global rules from this file)
4. **Future skills:** Check `.github/skills/` folder with `list_dir` to discover new workflows

**Skill files location:** `.github/skills/<skill-name>/SKILL.md` or `.github/skills/<parent-skill>/<sub-skill>/SKILL.md`

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
- **Advanced Hunting**: Run KQL queries across Defender XDR tables and connected Log Analytics workspace tables (`RunAdvancedHuntingQuery`), fetch table schemas (`FetchAdvancedHuntingTablesOverview`, `FetchAdvancedHuntingTablesDetailedSchema`)
- **Entity Investigation**: File info/stats/alerts (`GetDefenderFileInfo`, `GetDefenderFileStatistics`, `GetDefenderFileAlerts`), device details (`GetDefenderMachine`, `GetDefenderMachineAlerts`, `GetDefenderMachineLoggedOnUsers`), IP analysis (`GetDefenderIpAlerts`, `GetDefenderIpStatistics`), user activity (`ListUserRelatedAlerts`, `ListUserRelatedMachines`)
- **Vulnerability Management**: List affected devices (`ListDefenderMachinesByVulnerability`), software vulnerabilities (`ListDefenderVulnerabilitiesBySoftware`)
- **Remediation**: List/get remediation tasks (`ListDefenderRemediationActivities`, `GetDefenderRemediationActivity`)
- **When to Use**: Incident triage, threat hunting over your own Defender/Sentinel data, correlating alerts/entities during investigations
- **Documentation**: https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool

### � Sentinel ↔ Defender XDR ID Mapping — GLOBAL RULE

**The Sentinel Triage MCP (`GetIncidentById`, `GetAlertById`, `ListAlerts`) uses Defender XDR IDs, NOT Sentinel table IDs.** Passing Sentinel IDs to these tools returns "not found" errors.

| Sentinel Table Field | What It Is | Triage MCP Equivalent | How to Map |
|---------------------|------------|----------------------|------------|
| `SecurityIncident.IncidentNumber` | Sentinel-assigned sequential number | ❌ **Not accepted** by `GetIncidentById` | Use `SecurityIncident.ProviderIncidentId` instead — this is the Defender XDR incident ID |
| `SecurityIncident.ProviderIncidentId` | Defender XDR incident ID | ✅ **Pass this** to `GetIncidentById` | Direct — no mapping needed |
| `SecurityAlert.SystemAlertId` | Sentinel-assigned alert GUID | ❌ **Not accepted** by `GetAlertById` | Extract `IncidentId` from `SecurityAlert.ExtendedProperties` for the Defender XDR ID |

**When you discover incidents/alerts via Sentinel KQL (SecurityIncident, SecurityAlert tables) and need to drill down via Triage MCP:**

1. **For incidents:** Always `project ProviderIncidentId` in your Sentinel query and pass **that** value to `GetIncidentById`
2. **For alerts:** Extract the Defender ID from `ExtendedProperties`: `tostring(parse_json(ExtendedProperties).IncidentId)` — or query the incident via `ProviderIncidentId` first
3. **Never pass** `IncidentNumber` or `SystemAlertId` to Triage MCP tools

| Action | Status |
|--------|--------|
| Passing `SecurityIncident.IncidentNumber` to `GetIncidentById` | ❌ **PROHIBITED** |
| Passing `SecurityAlert.SystemAlertId` to `GetAlertById` | ❌ **PROHIBITED** |
| Using `ProviderIncidentId` from SecurityIncident for Triage MCP calls | ✅ **REQUIRED** |
| Extracting Defender ID from `ExtendedProperties.IncidentId` for alert drill-down | ✅ **REQUIRED** |

### �🔧 Tool Selection Rule: Data Lake vs Advanced Hunting

**Two KQL execution tools are available. Each has trade-offs:**

> **Key fact:** The LA workspace is connected to the unified Defender portal. Advanced Hunting can query **all** tables in the workspace — XDR-native tables (Device*, Email*, etc.), Sentinel-native tables (SigninLogs, AuditLogs, LAQueryLogs, etc.), and custom tables (`*_CL`). It is NOT limited to Defender XDR data only.

| Factor | `RunAdvancedHuntingQuery` (Advanced Hunting) | `mcp_sentinel-data_query_lake` (Sentinel Data Lake) |
|--------|-----------------------------------------------|------------------------------------------------------|
| **Cost** | Free for Analytics-tier tables (included in Defender license). **Note:** Tables on Auxiliary (Data Lake) or Basic plan still incur query costs even when queried via AH. | Billed per query (Log Analytics costs) |
| **Retention** | 30 days | 90+ days (workspace-configured) |
| **Timestamp column** | `Timestamp` for XDR-native tables; `TimeGenerated` for LA/Sentinel tables — use whichever the table requires | `TimeGenerated` |
| **Safety filter** | MCP-level safety filter may block queries with offensive security keywords | No additional safety filter beyond KQL validation |
| **Negation syntax** | `!has_any` and `!in~` may fail in `let` blocks — use `not()` wrappers | Standard KQL negation operators work reliably |

#### Ad-Hoc Query Decision Logic

For **ad-hoc queries** (user-initiated, not part of a skill workflow), use this simple decision:

| Condition | Tool | Reason |
|-----------|------|--------|
| **Lookback ≤ 30 days** (any table) | **Advanced Hunting** | Free for Analytics-tier tables; Auxiliary/Basic tables still incur query costs |
| **Lookback > 30 days** | **Data Lake** | AH only retains 30 days |
| **Query blocked by AH safety filter** | **Data Lake** | Data Lake has no MCP safety filter |
| **AH returns "table not found"** | **Data Lake** | Fallback for edge cases |

**Default: Advanced Hunting first.** It covers all tables in the connected workspace. Note: querying Auxiliary (Data Lake) or Basic tier tables via AH still incurs per-query costs — AH is only free for Analytics-tier tables.

#### Skill File Override Rule

**When executing a skill workflow** (from `.github/skills/`), the skill's tool specifications take precedence over the ad-hoc rule above. If a skill file specifies `mcp_sentinel-data_query_lake` for a query, use Data Lake. If it specifies `RunAdvancedHuntingQuery`, use AH. Skills may choose a specific tool deliberately for reasons like retention requirements, safety filter avoidance, or tested compatibility.

#### Timestamp Adaptation

When switching between tools, adapt the timestamp column if needed:
- XDR-native tables in AH use `Timestamp`
- LA/Sentinel tables use `TimeGenerated` in **both** tools
- When moving an XDR query to Data Lake: `Timestamp` → `TimeGenerated`

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

### Azure MCP Server
Direct Azure Resource Manager and Azure Monitor integration for quick ad-hoc queries:
- **`mcp_azure-mcp-ser_monitor` → `monitor_workspace_log_query`**: Execute KQL queries directly against Log Analytics workspace via Azure Monitor API. Same data as Sentinel Data Lake, but through the ARM path — useful for fast ad-hoc queries within the 90-day retention window.
- **`mcp_azure-mcp-ser_monitor` → `monitor_activitylog_list`**: Get Azure Activity Logs for specific resources (deployments, modifications, access patterns)
- **`mcp_azure-mcp-ser_group_list`**: List resource groups in a subscription
- **`mcp_azure-mcp-ser_subscription_list`**: List subscriptions

**Required parameters** — read from `config.json` (`azure_mcp` section):

| Parameter | Source | Why |
|-----------|--------|-----|
| `tenant` | `config.json → azure_mcp.tenant` | Prevents cross-tenant auth errors |
| `subscription` | `config.json → azure_mcp.subscription` | Targets correct subscription |
| `resource-group` | `config.json → azure_mcp.resource_group` | Required for `workspace_log_query` |
| `workspace` | `config.json → azure_mcp.workspace_name` | LA workspace display name |

**Calling `workspace_log_query`:**
```json
{
  "command": "monitor_workspace_log_query",
  "parameters": {
    "resource-group": "<from config.json>",
    "workspace": "<from config.json>",
    "tenant": "<from config.json>",
    "subscription": "<from config.json>",
    "table": "AzureActivity",
    "query": "AzureActivity | where TimeGenerated >= ago(1h) | take 10",
    "hours": 1,
    "limit": 20
  }
}
```

**When to use Azure MCP Server `workspace_log_query` vs Sentinel Data Lake `query_lake`:**

| Factor | Azure MCP `workspace_log_query` | Sentinel Data Lake `query_lake` |
|--------|---|---|
| **Speed** | Faster for ad-hoc (direct ARM call) | 5-15 min ingestion lag for very recent data |
| **Auth** | DefaultAzureCredential (VS Code cached) | Sentinel Platform Services OAuth |
| **Params** | Needs `resource-group` + `workspace` name + `table` | Needs `workspaceId` (GUID) |
| **Retention** | 90 days | 90 days (same workspace) |
| **Telemetry** | AppId `04b07795` via Azure CLI credential — `RequestClientApp` is **empty** in LAQueryLogs (not a unique fingerprint). Azure MCP appends `\n| limit N` to query text as best differentiator. 🔄 Previously `1950a258` + `csharpsdk,LogAnalyticsPSClient` — obsolete. | Under Sentinel MCP AppId (distinguishable) |
| **Best for** | Quick lookups, AzureActivity, ad-hoc exploration | Skill-based investigation workflows |

**🔍 Azure MCP Server Detection (🔄 Updated Feb 2026):** Azure MCP Server now uses `DefaultAzureCredential` → **Azure CLI** credential, producing AppId `04b07795-8ddb-461a-bbee-02f9e1bf7b46`. The previously documented fingerprint (AppId `1950a258` + `csharpsdk,LogAnalyticsPSClient`) is **obsolete** — only 1 occurrence found in 30-day lookback.
- **SigninLogs:** AppId `04b07795` — shared with manual Azure CLI, no unique sign-in fingerprint for Azure MCP
- **LAQueryLogs:** AADClientId `04b07795`, `RequestClientApp` is **empty**. Best differentiator: Azure MCP `monitor_workspace_log_query` appends `\n| limit N` to query text
- **AzureActivity:** Claims.appid `04b07795` (write operations only — reads not logged)
- **Token caching:** Sign-in events represent token acquisitions, NOT individual API calls. Count sign-in clusters as "access sessions".

See `.github/skills/mcp-usage-monitoring/SKILL.md` Queries 25-27 for detection queries.

- **Documentation**: https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/overview

### Custom Sentinel Tables

#### Signinlogs_Anomalies_KQL_CL
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

**Folder structure:** Query files are organized into subfolders by data domain:

| Subfolder | Domain | Examples |
|-----------|--------|----------|
| `queries/identity/` | Entra ID / Azure AD | `app_credential_management.md`, `service_principal_scope_drift.md` |
| `queries/endpoint/` | Defender for Endpoint | `rare_process_chains.md`, `infostealer_hunting_campaign.md` |
| `queries/email/` | Defender for Office 365 | `email_threat_detection.md` |
| `queries/network/` | Network telemetry | `network_anomaly_detection.md` |
| `queries/cloud/` | Cloud apps & exposure | `cloudappevents_exploration.md`, `exposure_graph_attack_paths.md` |

**File naming convention:** `{topic}.md` — lowercase, underscores, no redundant suffixes like `_queries` or `_sentinel`. Keep names short and descriptive of the detection scenario or data domain. Place new files in the subfolder matching their primary data source table.

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

**Optional: cd-metadata blocks for Custom Detection queries**

Query files intended for custom detection deployment should include per-query `<!-- cd-metadata -->` HTML comment blocks with structured YAML fields (schedule, category, impactedAssets, etc.). The full schema is defined in `.github/skills/detection-authoring/SKILL.md` under **CD Metadata Contract**. The **KQL Query Authoring** skill emits these blocks when it detects custom detection intent; the **Detection Authoring** skill consumes them when deploying queries.

**PII-Free Standard:** All committed documents — query files (`queries/`), skill files (`.github/skills/`), and any other versioned documentation — must NEVER contain tenant-specific PII such as real workspace names, UPNs, server hostnames, subscription/tenant GUIDs, or application names from live environments. Use generic placeholders (e.g., `<YourAppName>`, `user@contoso.com`, `<WorkspaceName>`, `la-yourworkspace`). **Before creating or updating any skill or query file, perform a PII sanity check:** scan the content for real identifiers that may have been copied from live investigation output or config files, and replace them with placeholders.

---

### IP Enrichment Utility (`enrich_ips.py`)

Use `enrich_ips.py` to enrich IP addresses with **3rd-party threat intelligence** from ipinfo.io, vpnapi.io, AbuseIPDB, and Shodan. This provides VPN/proxy/Tor detection, ISP/ASN details, hosting provider identification, abuse confidence scores, recent community-reported attack activity, open port enumeration, service/banner detection, known CVEs, and Shodan tags (e.g., honeypot, C2, self-signed).

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
