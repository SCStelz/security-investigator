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

**Environment-specific values (workspace IDs, tenant IDs, resource group names) are stored in `config.json` at the workspace root.** This file is gitignored and never committed.

When you need environment values (especially for Azure MCP Server calls), **read `config.json`** instead of asking the user or hardcoding values.

**`config.json` Schema** (see `config.json.template` for field names):

| Field | Used By | Purpose |
|-------|---------|--------|
| `sentinel_workspace_id` | Sentinel Data Lake MCP (`query_lake`) | Log Analytics workspace GUID |
| `tenant_id` | All Azure/Sentinel tools | Entra ID tenant |
| `subscription_id` | Azure MCP Server, Azure CLI | Azure subscription |
| `azure_mcp.resource_group` | Azure MCP `workspace_log_query` | RG containing Log Analytics workspace |
| `azure_mcp.workspace_name` | Azure MCP `workspace_log_query` | Log Analytics workspace display name |
| `azure_mcp.tenant` | Azure MCP Server (all calls) | Required to avoid cross-tenant auth errors |
| `azure_mcp.subscription` | Azure MCP Server (all calls) | Target subscription |

**API Tokens (`.env` file):** Enrichment API tokens are stored in `.env` (gitignored), loaded via `python-dotenv`. Copy `.env.template` to `.env` and fill in your keys.

| Environment Variable | Used By | Purpose |
|---------------------|---------|--------|
| `IPINFO_TOKEN` | `enrich_ips.py` | ipinfo.io API key |
| `ABUSEIPDB_TOKEN` | `enrich_ips.py` | AbuseIPDB API key |
| `VPNAPI_TOKEN` | `enrich_ips.py` | vpnapi.io API key |
| `SHODAN_TOKEN` | `enrich_ips.py` | Shodan API key |

> **Fallback:** `enrich_ips.py` also reads `ipinfo_token`/`abuseipdb_token`/`vpnapi_token`/`shodan_token` from `config.json` if the environment variables are not set. `.env` takes precedence.

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
| 1st | **Discovery manifest** (`.github/manifests/discovery-manifest.yaml`) | Read the manifest and match by **domain tag** (e.g., `identity`, `endpoint`, `email`) or **MITRE technique ID** (e.g., `T1078`, `T1566`). The manifest indexes all query files and skills with `title`, `path`, `domains`, `mitre`, and `prompt` fields. Best when you know the security domain or ATT&CK technique — skips scanning individual files. |
| 2nd | **Targeted `grep_search`** (skills + queries) | `grep_search` for the **specific table name** (e.g., `CloudAppEvents`, `OfficeActivity`) or **operation keyword** (e.g., `New-InboxRule`, `SecretGet`) scoped to `queries/**` and `.github/skills/**`. The manifest lacks table-name and keyword fields — grep fills this gap for table-specific lookups. |
| 3rd | **This file's Appendix** | Check [Ad-Hoc Query Examples](#appendix-ad-hoc-query-examples) for canonical patterns (SecurityAlert→SecurityIncident join, AuditLogs best practices, etc.) |
| 4th | **KQL Search MCP** | Use `search_github_examples_fallback` or `validate_kql_query` for community-published examples |
| 5th | **Microsoft Learn MCP** | Use `microsoft_code_sample_search` with `language: "kusto"` for official examples |

**When to use which:** If you know the **domain** ("identity threat") or **MITRE technique** (T1078) → start with Priority 1 (manifest). If you know the **table name** (`AuditLogs`) or **specific operation** (`Set-Mailbox`) → start with Priority 2 (grep). Both can be used together — manifest for breadth, grep for precision.

**Short-circuit rule:** If a suitable query is found in Priority 1 (manifest), Priority 2 (grep), or Priority 3 (Appendix), skip Steps 2–4 and use it directly (substituting entity values). These sources are already schema-verified and pitfall-aware. Step 5 (sanity-check zero results) still applies.

### Step 2: Verify Table Schema

Before querying any table for the first time in a session, verify the schema:
- Use `search_tables` or `get_table_schema` from KQL Search MCP
- Confirm column names, types, and which columns contain GUIDs vs human-readable values
- Check if the table exists in Data Lake vs Advanced Hunting (see [Tool Selection Rule](#-tool-selection-rule-data-lake-vs-advanced-hunting))
- **⚠️ Column name hallucination:** LLMs frequently use column names from one table on a different table. Common confusions: `Severity` vs `AlertSeverity` (SecurityIncident vs SecurityAlert), `OS` vs `OSPlatform` (Device* tables), `IPAddress` vs `RemoteIP` (varies by table), `Entities` (SecurityAlert only — not on SecurityIncident). Always verify the column exists on the specific table being queried.

### Step 3: Check Known Table Pitfalls

**Review this quick-reference before querying these tables:**

| Table | Pitfall | Required Action |
|-------|---------|----------------|
| **ALL Sentinel/LA tables** (SigninLogs, AuditLogs, SecurityAlert, SecurityIncident, OfficeActivity, etc.) | Column is **`TimeGenerated`**, NOT `Timestamp`. Using `Timestamp` on these tables returns `SemanticError: Failed to resolve column`. This is the **#1 most frequent Data Lake MCP error**. LLMs default to `Timestamp` from AH query patterns | **Data Lake:** Always `TimeGenerated`. **Advanced Hunting:** `Timestamp` for XDR-native tables (Device\*, Email\*, Cloud\*, Alert\*, Identity\*), `TimeGenerated` for Sentinel/LA tables. When adapting AH queries for Data Lake: replace ALL `Timestamp` → `TimeGenerated` |
| **AADRiskySignIns** | Table does **NOT exist** in Sentinel Data Lake. Querying it returns `SemanticError: Failed to resolve table` | Use `AADUserRiskEvents` instead (contains Identity Protection risk detections). For sign-in-level risk data, use `SigninLogs` with `RiskLevelDuringSignIn` and `RiskState` columns |
| **AADUserRiskEvents** | May have different retention than SigninLogs. **IP column is `IpAddress`** (lowercase 'p'), NOT `IPAddress`. Using `IPAddress` returns `Failed to resolve scalar expression`. LLMs default to `IPAddress` (matching SigninLogs convention) and consistently get this wrong. **Timestamp column is `ActivityDateTime`**, NOT `TimeGenerated` — using `TimeGenerated` silently returns 0 results (column exists but is ingestion time, not event time). `Location` is a **JSON string** — use `parse_json(Location).countryOrRegion` | Cross-reference with `SigninLogs` `RiskLevelDuringSignIn` for complete picture. Always use `IpAddress` (lowercase 'p') and `ActivityDateTime` for time filtering |
| **AIAgentsInfo** | **Advanced Hunting only** — does NOT exist in Sentinel Data Lake. Multiple records per agent (state snapshots); `KnowledgeDetails` is a string containing a JSON array of JSON strings; `IsGenerativeOrchestrationEnabled` may be null | Always use `RunAdvancedHuntingQuery`. Deduplicate with `summarize arg_max(Timestamp, *) by AIAgentId`. Double-parse KnowledgeDetails: `mv-expand KnowledgeRaw = parse_json(KnowledgeDetails) \| extend KnowledgeJson = parse_json(tostring(KnowledgeRaw))`. Treat null GenAI flag as unknown. Table is in **Preview** — schema may change |
| **AuditLogs** | `InitiatedBy`, `TargetResources` are **dynamic fields** | Always wrap in `tostring()` before using `has` operator |
| **AuditLogs** | `OperationName` values vary across providers — e.g., "Reset user password", "Change user password", "Self-service password reset" are all different values. **Consent lifecycle trap:** `"Consent to application"` is only 1 of 4+ operations. `has_any()` requires exact word matches and is unpredictable | Use broad `has "keyword"` for discovery (e.g., `has "password"`, `has "role"`), then refine with `summarize count() by OperationName`. For consent investigations use `queries/identity/app_credential_management.md` Query 5 which has the complete operation list |
| **AzureDiagnostics** | **Legacy table** — Microsoft [explicitly documents](https://learn.microsoft.com/azure/sentinel/datalake/kql-queries#query-considerations-and-limitations) that "Querying legacy tables such as AzureDiagnostics is not supported" in Data Lake. `mcp_sentinel-data_query_lake` returns `SemanticError: Failed to resolve table` even though the table exists in the workspace. Lake-only ingestion is also not supported (`No` in [connector reference](https://learn.microsoft.com/azure/sentinel/sentinel-tables-connectors-reference)). The portal may show the workspace as "Data Lake integrated" but individual tables have eligibility flags — this table is stuck on Analytics tier. This is NOT the same table as `AzureActivity`. **AzureDiagnostics** = resource-specific diagnostic logs (Key Vault data plane: `SecretGet`, `Authentication`, `VaultGet`; SQL auditing; Firewall logs; App Service logs, etc.). **AzureActivity** = ARM control plane operations (resource creation/deletion, policy actions, role assignments, deployments). Confusing the two leads to querying the wrong table and missing critical data plane evidence | If Data Lake returns "Failed to resolve table", **immediately** try `RunAdvancedHuntingQuery` (AH can query Analytics-tier tables). Do NOT fall back to `AzureActivity` — it contains completely different data. Key columns: `ResourceType` (e.g., `VAULTS`), `OperationName` (e.g., `SecretGet`), `CallerIPAddress`, `ResultType`, `Resource` (resource name), `Category` (e.g., `AuditEvent`). Filter pattern: `AzureDiagnostics \| where ResourceType == "VAULTS" \| where Resource =~ "<vault-name>"`. For Key Vault investigations, look for `OperationName` values like `SecretGet`, `SecretList`, `Authentication`, `VaultGet` |
| **BehaviorEntities / BehaviorInfo** | **Advanced Hunting only** — does NOT exist in Sentinel Data Lake. Table is in **Preview**. Two companion tables: `BehaviorInfo` (1 row per behavior — description, MITRE techniques, time window) and `BehaviorEntities` (N rows per behavior — entity decomposition). Populated by **MCAS** and **Sentinel UEBA** only — if these services aren't deployed, queries return 0 rows. `Categories` and `AttackTechniques` are **JSON strings**, not arrays — must `parse_json()` before `mv-expand`. K8s entity `AdditionalFields` contains deeply nested JSON with `$id`/`$ref` circular references. Low volume table (behavioral detections, not raw events). Significant overlap with SecurityAlert (same MCAS/MDC sources) but provides **below-alert-threshold signals** and **pre-decomposed entity rows** without parsing the SecurityAlert `Entities` JSON blob | Always use `RunAdvancedHuntingQuery`. Join tables on `BehaviorId`. Key ActionTypes: `ImpossibleTravelActivity`, `MultipleFailedLoginAttempts`, `MassDownload`, `UnusualAdditionOfCredentialsToAnOauthApp`, `K8S.NODE_DriftBlocked`, `K8S.NODE_MalwareBlocked`. Entity rows have `EntityRole` = `Impacted` or `Related`. Use for enriching user/IP investigations with MCAS/UEBA context. See `queries/cloud/behavior_entities.md` for verified query patterns |
| **CloudAppEvents** | **Extremely high-volume table** — ingests ALL M365 unified audit events (mail reads, file access, Teams, admin ops, etc.). Queries without selective early filters will timeout or get cancelled. **`RawEventData` is a large JSON blob** (often 5-100+ KB per row). **Performance killer #1:** `tostring(RawEventData) has "value"` — forces full JSON serialization on every row before substring search. **Performance killer #2:** Repeated `parse_json(RawEventData)` calls in separate `extend` statements — re-parses the entire blob per call. **Performance killer #3:** `AccountDisplayName has "partial"` — substring match without index; use `AccountObjectId` (GUID, indexed) or `AccountDisplayName =~` (exact, case-insensitive). **`AccountId` is a GUID (Entra ObjectId), NOT a UPN** — filtering `AccountId in~ ("user@domain.com")` returns 0 results silently. Use `AccountObjectId` (identical GUID) for indexed lookups, or `AccountDisplayName` for display-name-based filtering. To filter by UPN, resolve to ObjectId first via Graph API: `GET /v1.0/users/<UPN>?$select=id`. **Inbox rule queries:** For `New-InboxRule`/`Set-InboxRule`/`Set-Mailbox`, **ALWAYS also query `OfficeActivity`** (Exchange workload) — these tables are **complementary, not alternatives**. `CloudAppEvents` provides ActionType-based summaries and `AccountDisplayName`, but `OfficeActivity` provides the full `Parameters` JSON (forwarding targets: `ForwardTo`, `RedirectTo`, `ForwardingSmtpAddress`), per-operation `ClientIP`, and additional Exchange audit operations (`MoveToDeletedItems`, `MailItemsAccessed`, `Send`) critical for post-compromise forensics. When investigating mailbox manipulation, query BOTH tables. `ActionType` is CamelCase — use `contains` not `has` for partial matching (e.g., `ActionType contains "Sentinel"` not `has`) | **Filter order:** `Timestamp`/`TimeGenerated` first → `ActionType` (most selective, eliminates 99%+ rows) → identity filter (`AccountObjectId` preferred). **RawEventData:** Parse ONCE with `extend ParsedData = parse_json(RawEventData)` (or `parse_json(tostring(RawEventData))` in AH), then extract all fields from `ParsedData`. NEVER use `tostring(RawEventData) has "x"` for filtering — extract the specific field instead. **For inbox rule investigations, query BOTH:** (1) `CloudAppEvents` for ActionType summary + identity context, (2) `OfficeActivity \| where OfficeWorkload == "Exchange"` for full Parameters JSON, ClientIP, and additional Exchange operations (`MoveToDeletedItems`, `MailItemsAccessed`, `Send`). Never rely on CloudAppEvents alone for mailbox forensics |
| **DataSecurityEvents** | **Advanced Hunting only** — requires Insider Risk Management opt-in. `SensitiveInfoTypeInfo` is `Collection(String)` NOT native dynamic — requires double `parse_json()`. Contains SIT **GUIDs** not names. Copilot events ("Risky prompt entered in Copilot", "Sensitive response received in Copilot") can dominate 90%+ of volume. `ObjectId` is the file identifier — `ObjectName`/`ObjectType` do NOT exist despite documentation. **Label columns:** `SensitivityLabelId` (string, can be comma-separated), `PreviousSensitivityLabelId` (string, label change events), `SharepointSiteSensitivityLabelId` (string), `RiskyAIUsageSensitivityLabelsInfo` (Collection(String), mostly `[null]`). Label data is sparse in SIT-dominant environments but significant in Purview-mature orgs | Always use `RunAdvancedHuntingQuery`. Double-parse: `mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo)) \| extend SITJson = parse_json(tostring(SIT))`. Pre-filter with `where SensitiveInfoTypeInfo has "<GUID>"` before `mv-expand`. Use `split(SensitivityLabelId, ",")` for multi-GUID label values. Use `data-security-analysis` skill for SIT and label GUID-to-name resolution. If table returns 0 rows, check IRM opt-in status |
| **DeviceCustom\* (CDC Tables)** | Requires MDE Custom Data Collection (CDC) rules. These tables (`DeviceCustomFileEvents`, `DeviceCustomScriptEvents`, `DeviceCustomImageLoadEvents`, `DeviceCustomNetworkEvents`) do NOT exist in workspaces without CDC policies. They extend standard MDE telemetry beyond default thresholds. **Key per-table pitfalls:** `DeviceCustomScriptEvents` — script body is `ScriptContent`, NOT `AdditionalFields` (SemanticError); AMSI-only (Node.js/Go/Rust invisible). `DeviceCustomNetworkEvents` — coverage varies by CDC policy; some environments only collect Kerberos events, run discovery query first. `DeviceCustomFileEvents` — fills gaps when standard `DeviceFileEvents` returns 0 for known active directories. `DeviceCustomImageLoadEvents` — reveals native addons (`.node` modules, Python C extensions) | **CDC tables are optional** — if "Failed to resolve table", skip gracefully and note the telemetry gap. Query order: standard table first → if 0 results and activity is expected → try CDC equivalent → if CDC table doesn't exist → note as telemetry limitation |
| **DeviceInfo** | **Internet-facing detection pitfall:** `ExposureGraphNodes.rawData.IsInternetFacing`, `rawData.exposedToInternet`, and `rawData.isCustomerFacing` are all **unreliable** for determining actual internet exposure. `isCustomerFacing` is a business-function flag (NOT internet exposure). `IsInternetFacing`/`exposedToInternet` are not populated in many environments. LLMs default to querying these ExposureGraph properties and get null results. **`MachineTags` column renamed:** The old `MachineTags` column no longer exists — using it returns `Failed to resolve scalar expression`. It was split into three columns: `DeviceManualTags` (admin-set), `DeviceDynamicTags` (auto-assigned by rules), `RegistryDeviceTag` (set via registry). MS Learn may still reference `MachineTags` but the AH schema has only the new names. The Defender API `GetDefenderMachine` still returns `machineTags` (maps to `DeviceManualTags` in AH) | **Authoritative source:** Use `DeviceInfo.IsInternetFacing == true` (bool column). MDE maintains this via external scans + observed inbound connections; auto-expires after 48h. Extract details from `AdditionalFields`: `extractjson("$.InternetFacingReason", AdditionalFields)` (values: `PublicScan`, `InboundConnection`), `InternetFacingLocalPort`, `InternetFacingPublicScannedIp`. See `queries/network/internet_exposure_analysis.md` Query 1 and [MS Docs](https://learn.microsoft.com/en-us/defender-endpoint/internet-facing-devices#use-advanced-hunting). For inbound scan detail: `DeviceNetworkEvents` with `ActionType == "InboundInternetScanInspected"`. **Tags:** Use `DeviceManualTags`, `DeviceDynamicTags`, `RegistryDeviceTag` — NEVER `MachineTags` |
| **DeviceTvmSoftwareVulnerabilities / DeviceTvmSoftwareInventory / DeviceTvmSecureConfigurationAssessment / SecurityRecommendation** | **Advanced Hunting only** — Defender TVM tables do NOT exist in Sentinel Data Lake. **DeviceName is stored as FQDN** (e.g., `myserver.contoso.com`), NOT short hostname. Using `DeviceName =~ 'hostname'` returns 0 results. **`Timestamp` column pitfall:** `DeviceTvmSoftwareVulnerabilities` and `DeviceTvmSoftwareInventory` are **point-in-time snapshot tables with NO `Timestamp` column** — using `summarize arg_max(Timestamp, *)` or any `Timestamp` filter returns `Failed to resolve scalar expression`. `DeviceTvmSecureConfigurationAssessment` DOES have `Timestamp`. LLMs assume all TVM tables share the same schema and consistently add `Timestamp` where it doesn't exist | Always use `RunAdvancedHuntingQuery`. **Per-device filter:** Use `DeviceName startswith '<hostname>'` (matches both short and FQDN). NEVER use `=~` with short names. **No deduplication needed** on `DeviceTvmSoftwareVulnerabilities` / `DeviceTvmSoftwareInventory` — each row is already the latest state. For "last seen" or time context, join with `DeviceInfo` (which has `Timestamp`). For vulnerability investigations, use the `exposure-investigation` skill |
| **EntraIdSignInEvents** | **Case-sensitivity pitfall:** Capital `I` in `SignIn` — `EntraIdSigninEvents` (lowercase `i`) fails. `FetchAdvancedHuntingTablesDetailedSchema` does NOT index this table — use inline `getschema`. Covers **both interactive AND non-interactive** sign-ins — **default choice over** `SigninLogs` / `AADNonInteractiveUserSignInLogs` for AH queries (≤30d). SPN sign-ins use `EntraIdSpnSignInEvents`. **Column mapping vs Sentinel tables:** `ErrorCode` (int) vs `ResultType` (string), `AccountUpn` vs `UserPrincipalName`, `Application`/`ApplicationId` vs `AppDisplayName`/`AppId`, `Country`/`City` as direct strings (no `parse_json(LocationDetails)`), `RequestId` vs `OriginalRequestId`. **`LogonType` pitfall:** JSON array string (`["nonInteractiveUser"]`) — use `has` not `==`. `RiskLevelDuringSignIn`/`RiskState` are **int** (use `0`/`1`/`10`/`50`/`100`). `ConditionalAccessStatus` is **int** (`0`=applied, `1`=failed, `2`=not applied) | **AH queries (≤30d):** Default to `EntraIdSignInEvents`. **Data Lake / >30d:** Fall back to `SigninLogs` + `AADNonInteractiveUserSignInLogs` (union, 90+ day retention). Map column names when adapting between the two. [MS Learn reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table) |
| **ExposureGraphNodes / ExposureGraphEdges** | **Advanced Hunting only** — Exposure Management graph tables do NOT exist in Sentinel Data Lake | Always use `RunAdvancedHuntingQuery`. Uses `Timestamp`. See `exposure-investigation` skill for verified query patterns |
| **IdentityAccountInfo** | **Advanced Hunting only** — does NOT exist in Sentinel Data Lake. Table is in **Preview** — schema may change and many fields are not yet populated (`EnrolledMfas`, `TenantMembershipType`, `AuthenticationMethod`, `CriticalityLevel`, `DefenderRiskLevel`). Multiple snapshot records per account; `AssignedRoles` and `GroupMembership` are dynamic arrays. `SourceProviderRiskLevel` values vary by provider (AAD=High/Medium/Low, Okta=HIGH/MEDIUM, SailPoint=HIGH). `AccountStatus` vocabularies differ across providers (AAD: Enabled/Disabled/Deleted; SailPoint: ACTIVE/NONE/INACTIVE; Okta: STAGED/ACTIVE/DEPROVISIONED; CyberArk: ACTIVE/INVITED/SUSPENDED). **IdentityInfo UAC join pitfall:** `array_index_of(null_dynamic, "value")` returns `null` (not `-1`). Since `null != -1` is `true` in KQL, querying `array_index_of(UserAccountControl, "PasswordNeverExpires") != -1` without first filtering `isnotnull(UserAccountControl)` incorrectly returns true for ALL null-UAC accounts (~99% of identities), massively inflating PwdNeverExpires counts | Always use `RunAdvancedHuntingQuery`. Deduplicate with `summarize arg_max(Timestamp, *) by AccountId` (per-account) or `by IdentityId` (cross-provider). Parse roles/groups: `mv-expand Role = parse_json(AssignedRoles)`. `IdentityId` links accounts across providers — one identity can have accounts from multiple sources. For enrichment, join with `IdentityInfo` on `IdentityId` (not `AccountUpn` — avoids 1:many inflation). **When using UserAccountControl from IdentityInfo:** MUST add `where isnotnull(UserAccountControl)` BEFORE computing boolean flags with `array_index_of`. Use `identity-posture` skill for comprehensive identity posture reports |
| **OfficeActivity** | Mailbox forwarding/redirect rules live here, **NOT in AuditLogs** | Filter by `OfficeWorkload == "Exchange"` and `Operation in~ ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")`. Check `Parameters` for `ForwardTo`, `RedirectTo`, `ForwardingSmtpAddress`. This table is the **primary source** for detecting email exfiltration via forwarding rules (MITRE T1114.003 / T1020). |
| **OfficeActivity** | `Parameters` and `OperationProperties` are **string fields** containing JSON | Use `contains` or `has` for keyword matching, then `parse_json(Parameters)` to extract specific values. Do NOT query AuditLogs for mailbox rule changes — they only appear in OfficeActivity (Exchange workload). |
| **SecurityAlert** | `Status` field is **immutable** — always "New" regardless of actual state | MUST join with `SecurityIncident` to get real Status/Classification (see [Appendix pattern](#securityalertstatus-is-immutable---always-join-securityincident)) |
| **SecurityAlert** | `ProviderName` is an internal identifier (e.g., `MDATP`, `ASI Scheduled Alerts`, `MCAS`) and rolls up to generic names like `Microsoft XDR` at the incident level | Use **`ProductName`** for product grouping (e.g., `Azure Sentinel`, `Microsoft Defender Advanced Threat Protection`, `Microsoft Data Loss Prevention`). Also available: `ProductComponentName` (e.g., `Scheduled Alerts`, `NRT Alerts`). Translate raw values to current branding in reports. |
| **SecurityIncident** | `AlertIds` contains **SystemAlertId GUIDs**, NOT usernames, IPs, or entity names | NEVER filter `AlertIds` by entity name. Instead: query `SecurityAlert` first filtering by `Entities has '<entity>'`, then join to `SecurityIncident` on AlertId |
| **SecurityIncident** | **Phantom incidents with empty `AlertIds`:** Many Defender XDR-synced incidents have `AlertIds = []` — these never appear in the portal or Graph API and inflate closed incident counts. `TimeGenerated > ago(7d)` also captures old incidents with recent status updates, further inflating counts | **For accurate closed counts:** (1) Use `CreatedTime` (not `TimeGenerated`) for time-windowed queries, (2) Add `\| where array_length(AlertIds) > 0` to exclude phantom incidents |
| **SecurityIncident / SecurityAlert** | `IncidentNumber` and `SystemAlertId` are **Sentinel-local IDs** — Triage MCP uses **Defender XDR IDs** | Use `ProviderIncidentId` for Triage MCP lookups. See [Sentinel ↔ Defender XDR ID Mapping](#-sentinel--defender-xdr-id-mapping--global-rule) for full mapping |
| **SentinelHealth** | `SentinelResourceType` values use **title-case with a space**: `"Analytics Rule"`, NOT `"Analytic rule"`. LLMs consistently generate the wrong casing/spelling, returning 0 results despite 30k+ rows in the table | Always use `SentinelResourceType == "Analytics Rule"` (capital A, capital R, "Analytics" with an 's'). Other valid values: `"Data connector"`, `"Automation rule"`. If query returns 0 rows, check this filter first |
| **SigninLogs** / **AADNonInteractiveUserSignInLogs** | `DeviceDetail`, `LocationDetails`, `ConditionalAccessPolicies`, `Status` may be **dynamic OR string** depending on workspace (Data Lake workspaces store them as strings). `AADNonInteractiveUserSignInLogs` stores these as **string always** | Always use `tostring(parse_json(DeviceDetail).operatingSystem)` — works for both types. Direct dot-notation `DeviceDetail.operatingSystem` fails with SemanticError when column is string type. Same applies to `Status` (use `parse_json(Status).errorCode`), `ConditionalAccessPolicies` — use `parse_json()` before dot-access or `mv-expand` |
| **SigninLogs** | `Location` is a **string** column, NOT dynamic. Dot-notation like `Location.countryOrRegion` will fail with SemanticError | Use `parse_json(LocationDetails).countryOrRegion` for geographic sub-properties. `Location` works with `dcount()`, `has`, `isnotempty()` but NOT dot-property access |
| **Signinlogs_Anomalies_KQL_CL** | Custom `_CL` table names are **case-sensitive**. Table uses lowercase 'l' in "logs" — `Signinlogs` NOT `SigninLogs`. LLMs auto-correct this to match `SigninLogs` | Always copy exact table name `Signinlogs_Anomalies_KQL_CL`. If `SemanticError: Failed to resolve table`, verify casing first. If still fails, table may not exist in the workspace — skip gracefully |

> **💡 CDC Telemetry Escalation Pattern:** When standard MDE tables return 0 results for activity you have evidence exists, check whether `DeviceCustom*` tables are available. Not all environments have CDC enabled — if the tables don't resolve, document the telemetry gap rather than assuming absence of activity.

### Step 3b: Common KQL Anti-Patterns (All Tables)

These universal KQL mistakes are frequent LLM errors regardless of which table is queried:

| Anti-Pattern | Error | Fix |
|-------------|-------|-----|
| `mv-expand` on string column containing JSON | `expanded expression expected to have dynamic type` | `mv-expand parsed = parse_json(StringColumn)` — parse_json() BEFORE mv-expand |
| `dcount()` on dynamic column | `argument #1 cannot be dynamic` | `dcount(tostring(DynamicColumn))` — cast to scalar |
| `bin()` missing argument | `bin(): function expects 2 argument(s)` | Always provide both: `bin(TimeGenerated, 1h)` |
| `iff()` with mismatched branch types | `@then data type (real) must match @else (long)` | Cast both branches: `iff(cond, todouble(x), todouble(y))` |
| Joining on dynamic column | `join key 'X' is of a 'dynamic' type` | Cast before join: `\| extend AlertId = tostring(AlertId) \| join ...` |
| Duplicate column in `union` | `column named 'X' already exists` | Use `project-away` or `project-rename` before union |
| `prev()`/`next()` on unserialized rowset | `Function 'prev' cannot be invoked in current context` | Add `\| serialize` before `prev()`, `next()`, `row_cumsum()`, `row_number()` |

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
| Filtering `SecurityIncident.AlertIds` by entity names | ❌ **PROHIBITED** |
| Reading `SecurityAlert.Status` as current investigation status | ❌ **PROHIBITED** |
| Reporting 0 results without sanity-checking the query logic | ❌ **PROHIBITED** |
| Using `Timestamp` on Sentinel/LA tables in Data Lake queries | ❌ **PROHIBITED** — use `TimeGenerated` |

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
| 🔍 Core | **computer-investigation** | Device security analysis (alerts, compliance, vulnerabilities, process/network/file events) | "investigate computer", "investigate device", "investigate endpoint", "check machine", hostname |
| 🔍 Core | **honeypot-investigation** | Honeypot attack analysis with threat intel and executive reports | "honeypot", "attack analysis", "threat actor" |
| 🔍 Core | **incident-investigation** | Defender XDR / Sentinel incident triage with recursive entity investigation | "investigate incident", "incident ID", "analyze incident", "triage incident", incident number |
| 🔍 Core | **ioc-investigation** | IoC analysis for IPs, domains, URLs, file hashes with TI enrichment | "investigate IP", "investigate domain", "investigate URL", "investigate hash", "IoC", "is this malicious", "threat intel", IP/domain/URL/hash |
| 🔍 Core | **user-investigation** | Entra ID user security analysis (sign-ins, MFA, anomalies, incidents, Identity Protection) | "investigate user", "security investigation", "check user activity", UPN/email |
| 🔐 Auth | **authentication-tracing** | Authentication chain forensics (SessionId, token reuse, geographic anomalies) | "trace authentication", "SessionId analysis", "token reuse", "geographic anomaly", "impossible travel" |
| 🔐 Auth | **ca-policy-investigation** | Conditional Access policy forensics and bypass detection | "Conditional Access", "CA policy", "device compliance", "policy bypass", "53000", "50074", "530032" |
| 📈 Behavioral | **scope-drift-detection/device** | Device process baseline drift analysis with weighted Drift Score | "device drift", "device process drift", "endpoint drift", "process baseline", "device behavioral change", "device scope drift" |
| 📈 Behavioral | **scope-drift-detection/spn** | SPN behavioral drift (90d baseline vs 7d recent) with weighted Drift Score | "scope drift", "service principal drift", "SPN behavioral change", "SPN drift", "baseline deviation", "access expansion", "automation account drift" |
| 📈 Behavioral | **scope-drift-detection/user** | User sign-in drift (Interactive + Non-Interactive Drift Scores) | "user drift", "user behavioral change", "user scope drift", "UPN drift", "sign-in drift", "user baseline deviation" |
| 🛡️ Posture | **exposure-investigation** | Vulnerability & Exposure Management (CVEs, configs, attack paths, critical assets) | "vulnerability report", "exposure report", "CVE assessment", "security posture", "TVM", "attack paths", "critical assets" |
| 🛡️ Posture | **ai-agent-posture** | AI agent security audit (Copilot Studio, auth gaps, MCP tools, XPIA risk) | "AI agent posture", "agent security audit", "Copilot Studio agents", "agent inventory", "unauthenticated agents", "XPIA risk", "agent sprawl" |
| 🛡️ Posture | **app-registration-posture** | App registration posture (permissions, ownership, credentials, KQL attack chains) | "app registration posture", "service principal permissions", "dangerous app permissions", "app credential abuse", "SPN lateral movement", "app consent grant" |
| 🛡️ Posture | **email-threat-posture** | MDO email threat posture (phishing, DMARC/DKIM/SPF, ZAP, Safe Links) | "email threat report", "email security posture", "phishing report", "MDO report", "ZAP effectiveness", "DMARC report" |
| 🔒 Data | **data-security-analysis** | DataSecurityEvents analysis (SIT access, sensitivity labels, DLP, Copilot exposure) | "data security", "sensitive information type", "SIT access", "DLP events", "DataSecurityEvents", "sensitivity label", "label downgrade", "Copilot label exposure" |
| 🛡️ Posture | **identity-posture** | Identity posture via IdentityAccountInfo (multi-provider, privileged accounts, hygiene) | "identity posture", "identity report", "account inventory", "privileged accounts", "stale accounts", "identity hygiene", "IdentityAccountInfo" |
| 📊 Viz | **geomap-visualization** | Interactive world map for attack origins and IP geolocation | "geomap", "world map", "attack map", "show on map", "attack origins" |
| 📊 Viz | **heatmap-visualization** | Interactive heatmap for time-based activity patterns | "heatmap", "show heatmap", "visualize patterns", "activity grid" |
| 📊 Viz | **svg-dashboard** | SVG dashboards (KPI cards, charts, tables) from reports or ad-hoc data | "generate SVG dashboard", "create a visual dashboard", "visualize this report", "SVG from the report", "create SVG chart" |
| 🔍 Scan | **threat-pulse** | 15-min broad security scan across 9 domains with prioritized drill-down recommendations | "threat pulse", "quick scan", "security pulse", "morning hunt", "what should I focus on", "what can you do", "where do I start", "what's going on" |
| 🔧 Tooling | **detection-authoring** | Create/deploy/manage Defender XDR custom detection rules via Graph API | "create custom detection", "deploy detection", "detection rule", "custom detection", "deploy rule", "batch deploy" |
| 🔧 Tooling | **kql-query-authoring** | KQL query creation with schema validation and community examples | "write KQL", "create KQL query", "help with KQL", "query [table]" |
| 🔧 Tooling | **mcp-usage-monitoring** | MCP server usage audit (Graph/Sentinel/Azure MCP telemetry analysis) | "MCP usage", "MCP server monitoring", "MCP activity", "MCP audit", "who is using MCP" |
| 🔧 Tooling | **mitre-coverage-report** | MITRE ATT&CK coverage analysis (rule mapping, gaps, SOC Optimization alignment) | "MITRE coverage", "MITRE report", "ATT&CK coverage", "technique coverage", "coverage gaps", "MITRE score" |
| 🔧 Tooling | **sentinel-ingestion-report** | Sentinel ingestion analysis (volume, tiers, anomalies, rule health, cost optimization) | "ingestion report", "usage report", "data volume", "cost analysis", "table breakdown", "ingestion anomaly" |

### Skill Detection Workflow

1. **Parse user request** for trigger keywords from table above
2. **Getting started / exploratory requests:** If the user asks "what can you do?", "where do I start?", "help me investigate", "how do I use this", "show me what you can do", "what's going on?", or any open-ended orientation question — **recommend and offer to run the `threat-pulse` skill** as the starting point. Briefly explain it runs a 15-minute broad scan across 9 security domains and produces a prioritized dashboard with drill-down recommendations to specialized skills. Ask if they'd like to run it.
3. **If match found:** Read the skill file:
   - Standard skills: `.github/skills/<skill-name>/SKILL.md`
   - Subfolder skills (e.g., scope-drift-detection): `.github/skills/<parent-skill>/<sub-skill>/SKILL.md`
4. **Follow skill-specific workflow** (inherits global rules from this file)
5. **Future skills:** Check `.github/skills/` folder with `list_dir` to discover new workflows

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
  - **⚠️ `ListAlerts` limitation:** This tool has NO `incidentId` parameter. It only supports `createdAfter`, `createdBefore`, `severity`, `status`, `skip`, `top`. Calling it returns **all tenant alerts** up to the page size — any unsupported parameter is silently ignored. **To get alerts for a specific incident**, use `GetIncidentById` with `includeAlertsData=true`, or query `AlertInfo`/`AlertEvidence` via `RunAdvancedHuntingQuery` with entity-based filtering.
- **Advanced Hunting**: Run KQL queries across Defender XDR tables and connected Log Analytics workspace tables (`RunAdvancedHuntingQuery`), fetch table schemas (`FetchAdvancedHuntingTablesOverview`, `FetchAdvancedHuntingTablesDetailedSchema`)
- **Entity Investigation**: File info/stats/alerts (`GetDefenderFileInfo`, `GetDefenderFileStatistics`, `GetDefenderFileAlerts`), device details (`GetDefenderMachine`, `GetDefenderMachineAlerts`, `GetDefenderMachineLoggedOnUsers`), IP analysis (`GetDefenderIpAlerts`, `GetDefenderIpStatistics`), user activity (`ListUserRelatedAlerts`, `ListUserRelatedMachines`)
- **Vulnerability Management**: List affected devices (`ListDefenderMachinesByVulnerability`), software vulnerabilities (`ListDefenderVulnerabilitiesBySoftware`)
- **Remediation**: List/get remediation tasks (`ListDefenderRemediationActivities`, `GetDefenderRemediationActivity`)
- **When to Use**: Incident triage, threat hunting over your own Defender/Sentinel data, correlating alerts/entities during investigations
- **Documentation**: https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool

### 🔗 Sentinel ↔ Defender XDR ID Mapping — GLOBAL RULE

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

### 📋 SecurityIncident Query & Output Standards — GLOBAL RULE

**These rules apply to ALL SecurityIncident queries, not just Triage MCP interactions.**

Every SecurityIncident query MUST include `ProviderIncidentId` in the output and every incident presented to the user MUST include a clickable Defender XDR portal URL: `https://security.microsoft.com/incidents/{ProviderIncidentId}`.

| Action | Status |
|--------|--------|
| Querying SecurityIncident without projecting `ProviderIncidentId` | ❌ **PROHIBITED** |
| Presenting incidents to user without Defender XDR portal URL | ❌ **PROHIBITED** |
| Using `IncidentNumber` as the primary identifier in output | ❌ **PROHIBITED** |
| Including clickable `https://security.microsoft.com/incidents/{ProviderIncidentId}` link | ✅ **REQUIRED** |


### 🔧 Tool Selection Rule: Data Lake vs Advanced Hunting

**Two KQL execution tools are available. Each has trade-offs:**

> **Key fact:** The LA workspace is connected to the unified Defender portal. Advanced Hunting can query **all** tables in the workspace — XDR-native tables (Device*, Email*, etc.), Sentinel-native tables (SigninLogs, AuditLogs, LAQueryLogs, etc.), and custom tables (`*_CL`). It is NOT limited to Defender XDR data only.
>
> **ASIM parser functions** (`_Im_NetworkSession`, `_Im_WebSession`, `_Im_Dns`, `_Im_ProcessEvent`, etc.) and other workspace-level functions are **fully supported in Advanced Hunting** — they resolve against the connected LA workspace. However, `mcp_sentinel-data_query_lake` (Data Lake MCP) **cannot resolve** workspace-level functions and returns `Unknown function` errors for `_Im_*` calls. **Always use `RunAdvancedHuntingQuery` for ASIM parser queries.**

| Factor | `RunAdvancedHuntingQuery` (Advanced Hunting) | `mcp_sentinel-data_query_lake` (Sentinel Data Lake) |
|--------|-----------------------------------------------|------------------------------------------------------|
| **Cost** | Free for Analytics-tier tables (included in Defender license). **Note:** Tables on Auxiliary (Data Lake) or Basic plan still incur query costs even when queried via AH. | Billed per query (Log Analytics costs) |
| **Retention** | 30 days via Graph API (`/v1.0/security/runHuntingQuery`). The Defender portal UI can access full LA retention (90+ days) through a different API path — the 30-day cap is a **Graph API / MCP limitation**, not a data retention limit. For >30-day lookback via MCP, use Data Lake or Azure MCP `workspace_log_query` instead. | 90+ days (workspace-configured) |
| **Timestamp column** | `Timestamp` for XDR-native tables; `TimeGenerated` for LA/Sentinel tables — use whichever the table requires | `TimeGenerated` |
| **Safety filter** | MCP-level safety filter may block queries with offensive security keywords | No additional safety filter beyond KQL validation |
| **Negation syntax** | `!has_any` and `!in~` may fail in `let` blocks — use `not()` wrappers | Standard KQL negation operators work reliably |

#### Ad-Hoc Query Decision Logic

For **ad-hoc queries** (user-initiated, not part of a skill workflow), use this simple decision:

| Condition | Tool | Reason |
|-----------|------|--------|
| **Lookback ≤ 30 days** (any table) | **Advanced Hunting** | Free for Analytics-tier tables; Auxiliary/Basic tables still incur query costs |
| **Lookback > 30 days** | **Data Lake** or **Azure MCP `workspace_log_query`** | AH Graph API caps results at 30 days (portal has full 90-day access via different API path) |
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
- **Data format**: Array of `{row, column, value}` objects. Optional: `title`, `rowLabel`, `colLabel`, `valueLabel`, `colorScale` (`green-red`/`blue-red`/`blue-yellow`), `enrichment` (IP threat intel for drill-down panels)
- **When to Use**: Visualizing attack patterns by IP and time, sign-in activity by app/hour, failed auth by location/day
- **See**: `heatmap-visualization` skill for full usage guidance, KQL query patterns, and enrichment schema

### Azure MCP Server
Direct Azure Resource Manager and Azure Monitor integration for quick ad-hoc queries:
- **`mcp_azure-mcp-ser_monitor` → `monitor_workspace_log_query`**: Execute KQL queries directly against Log Analytics workspace via Azure Monitor API. Same data as Sentinel Data Lake, but through the ARM path — useful for fast ad-hoc queries within the 90-day retention window.
- **`mcp_azure-mcp-ser_monitor` → `monitor_activitylog_list`**: Get Azure Activity Logs for specific resources (deployments, modifications, access patterns)
- **`mcp_azure-mcp-ser_group_list`**: List resource groups in a subscription
- **`mcp_azure-mcp-ser_subscription_list`**: List subscriptions

**Required parameters:** Read `tenant`, `subscription`, `resource-group`, and `workspace` from `config.json` (`azure_mcp` section). See [Environment Configuration](#-environment-configuration) for field mapping.

**When to use Azure MCP Server `workspace_log_query` vs Sentinel Data Lake `query_lake`:**

| Factor | Azure MCP `workspace_log_query` | Sentinel Data Lake `query_lake` |
|--------|---|---|
| **Speed** | Faster for ad-hoc (direct ARM call) | 5-15 min ingestion lag for very recent data |
| **Auth** | DefaultAzureCredential (VS Code cached) | Sentinel Platform Services OAuth |
| **Params** | Needs `resource-group` + `workspace` name + `table` | Needs `workspaceId` (GUID) |
| **Retention** | 90 days | 90 days (same workspace) |
| **Best for** | Quick lookups, AzureActivity, ad-hoc exploration | Skill-based investigation workflows |

> **Azure MCP telemetry detection:** See `mcp-usage-monitoring` skill (Queries 25-27) for Azure MCP Server fingerprinting and usage analysis.

- **Documentation**: https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/overview

### Sentinel Exposure Graph MCP
Attack surface analysis tools for the Microsoft Security Exposure Management graph. **More effective than raw KQL** for per-asset attack path scenarios — use these first, fall back to KQL for fleet-wide sweeps.

> **⚠️ Preview:** The Sentinel Exposure Graph MCP server is in preview and may not be available in all environments. If the tools are not present (tool calls fail or are not listed), fall back to KQL queries against `ExposureGraphNodes` / `ExposureGraphEdges` in Advanced Hunting. See `queries/cloud/exposure_graph_attack_paths.md` for equivalent KQL patterns.

- **`mcp_sentinel-grap_graph_find_blastradius`**: All downstream targets reachable from a source asset. Params: `sourceName`
- **`mcp_sentinel-grap_graph_exposure_perimeter`**: Inbound perimeter — externally-reachable nodes with walkable paths TO a target. Params: `targetName`
  - **Known limitation:** May return empty for assets that ARE network-reachable but lack formal ExposureGraph perimeter classification. Fall back to KQL edge analysis with `EdgeLabel == "routes traffic to"` when empty.
- **`mcp_sentinel-grap_graph_find_walkable_paths`**: Full path between source and target with RBAC role detail, `isOverProvisioned` and `isIdentityInactive` flags. Params: `sourceName`, `targetName`
- **`mcp_sentinel-grap_graph_find_connected_nodes`**: All nodes of a specific type within N hops. Params: `sourceName`, `sourceNodeLabel`, `targetNodeLabel`, `maxHops` (1–3 recommended; higher = very large results)
- **`mcp_sentinel-grap_graph_get_context`**: Full graph schema (node/edge types). Params: `GraphName` (always `SystemScenarioEKGGraph`)

**Workflow:** blast radius → exposure perimeter → walkable paths for specific targets → connected nodes by type → KQL for fleet-wide analysis

- **When to Use**: Investigating compromised assets, mapping blast radius after incidents, validating attack paths, assessing critical asset exposure, identifying over-provisioned identities along permission chains
- **When to Use KQL Instead**: Fleet-wide sweeps, cookie chain analysis across all devices, choke point detection, permission role distribution across all paths, custom multi-join aggregations
- **Full documentation**: See `queries/cloud/exposure_graph_attack_paths.md` for detailed tool docs, parameters, examples, and 32 KQL queries

### 🔍 Resource Discovery — Cross-Subscription Lookup Pattern

**`config.json` only contains the primary Sentinel workspace subscription.** Resources investigated via Defender XDR (DeviceInfo, ExposureGraphNodes, alerts) often reside in **different subscriptions**. When you need to look up an Azure resource (VM, NSG, NIC, etc.) discovered through investigation queries:

1. Try `config.json` subscription first → `az vm list --query "[?contains(name, '<name>')]" --subscription "<config.json sub>"`
2. If not found → `az account list` to enumerate all subscriptions
3. Search each subscription until found
4. Use the discovered subscription + resource group for all subsequent ARM calls (NSG, NIC, subnet, etc.)

**Why this matters:** The Defender XDR unified portal aggregates devices across ALL connected subscriptions. A device flagged in `ExposureGraphNodes` or `DeviceInfo` may live in any subscription — the `config.json` subscription is only guaranteed to contain the Log Analytics workspace. Always specify `--subscription` explicitly in Azure CLI calls to avoid defaulting to the wrong subscription context.

### Custom Sentinel Tables

#### Signinlogs_Anomalies_KQL_CL
**Purpose:** Pre-computed sign-in anomaly detection table populated by hourly KQL job. Tracks new IPs and device combinations against 90-day baseline.

- **Anomaly Types:** `NewInteractiveIP`, `NewInteractiveDeviceCombo`, `NewNonInteractiveIP`, `NewNonInteractiveDeviceCombo`
- **Detection Model:** Compares last 1 hour activity against 90-day baseline; severity scored by artifact hit frequency + geographic novelty (`CountryNovelty`, `CityNovelty`, `StateNovelty`)
- **Key Columns:** `DetectedDateTime`, `UserPrincipalName`, `AnomalyType`, `Value`, `Severity`, `ArtifactHits`, `BaselineSize`, geographic novelty flags, `Baseline*List` arrays
- **When to Use:** Rapid anomaly triage during user investigations, impossible travel detection, token theft indicators (non-interactive anomalies with geo changes)

**Full Documentation:** See [docs/Signinlogs_Anomalies_KQL_CL.md](../docs/Signinlogs_Anomalies_KQL_CL.md) for complete schema, example queries, and severity thresholds.

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
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId)
| order by CreatedTime desc
```

> **Output rule:** When presenting these results to the user, always render `PortalUrl` as a clickable markdown link: `[#{ProviderIncidentId}]({PortalUrl})`. See [SecurityIncident Query & Output Standards](#-securityincident-query--output-standards--global-rule).

| Field | Source | Meaning |
|-------|--------|----------|
| `SecurityAlert.Status` | Alert table | **Immutable creation status** - always "New" |
| `SecurityIncident.Status` | Incident table | **Real status** - New/Active/Closed |
| `SecurityIncident.Classification` | Incident table | **Closure reason** - TruePositive/FalsePositive/BenignPositive |

**Reference:** See `queries/incidents/security_incident_analysis.md` for the canonical SecurityAlert→SecurityIncident join pattern.

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
**Domains:** <comma-separated threat-pulse domain tags — see Discovery Manifest below>  
**Timeframe:** Last N days (configurable)  
```

**Required fields for search efficiency:**

| Field | Purpose | Example |
|-------|---------|---------|
| `Tables:` | Exact KQL table names for `grep_search` by table | `AuditLogs, SecurityAlert, SecurityIncident` |
| `Keywords:` | Searchable terms covering attack scenarios, operations, field names | `credential, secret, certificate, persistence, app registration` |
| `MITRE:` | ATT&CK technique and tactic IDs | `T1098.001, T1136.003, TA0003` |
| `Domains:` | Threat-pulse domain tags for manifest-based cross-referencing | `identity, email` |

Valid domain tags: `incidents`, `identity`, `spn`, `endpoint`, `email`, `admin`, `cloud`, `exposure`

**Search pattern:** `grep_search` scoped to `queries/**` with the table name or keyword will hit the metadata header and locate the right file instantly.

**When creating new query files:** Follow this format. When updating existing files that lack these fields, add them.

#### Discovery Manifest (`.github/manifests/`)

The discovery manifest indexes all query files and skills with their domain tags, enabling **deterministic cross-referencing** by threat-pulse and other skills.

Two variants are generated:
- **`discovery-manifest.yaml`** (default) — title, path, domains, mitre, prompt only. ~500 lines. **Threat-pulse loads this one** to minimize context consumption.
- **`discovery-manifest-full.yaml`** (verbose, `--full` flag) — all fields (tables, keywords, mitre, domains, platform, timeframe). ~1300 lines.

**How it works:**
- Query files declare `**Domains:**` in their metadata header
- Skills declare `threat_pulse_domains:` and `drill_down_prompt:` in their YAML frontmatter
- `python .github/manifests/build_manifest.py` scans everything and emits both manifests to `.github/manifests/`
- The validator flags missing fields — missing `Domains:` on a query file is an error

**When to regenerate:** Run `python .github/manifests/build_manifest.py` after:
- Creating or renaming a query file or skill
- Changing `Domains:`, `threat_pulse_domains:`, or `drill_down_prompt:` values
- Adding new domain tags (update `VALID_DOMAINS` in `build_manifest.py` first)

**When to regenerate TOCs:** Run `python scripts/generate_tocs.py` after creating or updating a query file. The script auto-generates a `## Quick Reference — Query Index` table with clickable anchor links for every query heading that has a KQL code block. It is idempotent — strips and regenerates existing TOCs on re-run.

| Action | Status |
|--------|--------|
| Creating a query file without `**Domains:**` | ❌ **PROHIBITED** |
| Creating an investigation skill without `threat_pulse_domains:` | ❌ **PROHIBITED** |
| Forgetting to run `build_manifest.py` after adding files | ❌ **PROHIBITED** |
| Forgetting to run `generate_tocs.py` after adding/updating query files | ❌ **PROHIBITED** |

**🔴 REQUIRED: cd-metadata blocks for ALL queries in `queries/`**

Every query in a `queries/` file MUST include a `<!-- cd-metadata -->` HTML comment block immediately before the KQL code block — either `cd_ready: true` with full fields, or `cd_ready: false` with `adaptation_notes` explaining why. **Read the CD Metadata Contract in `.github/skills/detection-authoring/SKILL.md`** for the full schema, valid field values, and examples.

| Action | Status |
|--------|--------|
| Creating a query file in `queries/` without cd-metadata blocks | ❌ **PROHIBITED** |

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
