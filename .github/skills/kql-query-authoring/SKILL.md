---
name: kql-query-authoring
description: Use this skill when asked to write, create, or help with KQL (Kusto Query Language) queries for Microsoft Sentinel, Defender XDR, or Azure Data Explorer. Triggers on keywords like "write KQL", "create KQL query", "help with KQL", "query [table]", "KQL for [scenario]", or when a user requests queries for specific data analysis scenarios. This skill uses schema validation, Microsoft Learn documentation, and community examples to generate production-ready KQL queries.
---

# KQL Query Authoring - Instructions

## Purpose

Generate validated, production-ready KQL queries by combining schema validation (331+ indexed tables), Microsoft Learn documentation, community examples, and performance best practices.

---

## Prerequisites

**Required MCP Servers:**

1. **KQL Search MCP Server** — Schema validation, query examples, table discovery
   - **Install**: `npm install -g kql-search-mcp` ([npm](https://www.npmjs.com/package/kql-search-mcp))

2. **Microsoft Docs MCP Server** — Official Microsoft Learn documentation and code samples
   - **GitHub**: [MicrosoftDocs/mcp](https://github.com/MicrosoftDocs/mcp)

**Verification:** Tools should be available as `mcp_kql-search_*` and `mcp_microsoft-lea_*`.

---

## ⚠️ Known Issues

### `search_favorite_repos` Bug (v1.0.5)

❌ Broken — `ERROR_TYPE_QUERY_PARSING_FATAL`. Use `mcp_kql-search_search_github_examples_fallback` instead.

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Validate table schema FIRST** — `mcp_kql-search_get_table_schema` to verify table exists, column names, and data types.

2. **Check platform schema** — Sentinel uses `TimeGenerated`; Defender XDR uses `Timestamp`. Microsoft Learn examples default to XDR syntax — always convert before testing on Sentinel.

3. **Check local query library FIRST** — Search `queries/` and `.github/skills/` before writing from scratch. See the **KQL Pre-Flight Checklist** in `copilot-instructions.md` for the full priority order.

4. **Use multiple sources** — Schema (authoritative column names) + Microsoft Learn (official patterns) + community queries (real-world examples).

5. **Test using the correct execution tool** — Follow the **Tool Selection Rule** in `copilot-instructions.md`:
   - Sentinel-native tables → Data Lake or AH
   - XDR tables ≤ 30d → Advanced Hunting (free); > 30d → Data Lake
   - XDR-only tables (DeviceTvm*, Exposure*) → Advanced Hunting only
   - Adapt timestamp column when switching tools

6. **Test queries before presenting to user** — Run with `| take 5` via live execution. Use `mcp_kql-search_validate_kql_query` as fallback if live testing unavailable.

7. **Provide context** — Explain what the query does, expected results, and any limitations.

8. **Read the complete workflow below** before starting.

> **📋 Inherited rules:** This skill inherits the **KQL Pre-Flight Checklist**, **Tool Selection Rule (Data Lake vs Advanced Hunting)**, and **Known Table Pitfalls** from `copilot-instructions.md`. Those rules are authoritative — do not contradict them here.

---

## Query Authoring Workflow

### Step 1: Understand User Requirements

**Extract key information:**
- **Table(s) needed**: Which data source? (e.g., `EntraIdSignInEvents`, `EmailEvents`, `SecurityAlert`)
- **Time range**: How far back? (e.g., last 7 days, specific date range)
- **Filters**: What specific conditions? (e.g., user, IP, threat type)
- **Output**: Statistics, detailed records, time series, aggregations?
- **Platform**: Sentinel or Defender XDR? (affects column names)
- **Deployment target**: Custom detection rule? (see below)

**Custom Detection Intent Detection:**

If the user mentions "custom detection", "detection rule", "deploy as detection", "CD rule", "author detections for", or "deploy to Defender":

1. **Read the detection-authoring skill** (`.github/skills/detection-authoring/SKILL.md`) — Critical Rules and CD Metadata Contract sections
2. **Design queries with CD constraints** — row-level output, mandatory columns (`TimeGenerated`, `DeviceName`, `ReportId`), no bare `summarize`
3. **Include `cd-metadata` blocks** in the output file (see [Step 8](#step-8-format-and-deliver-output))
4. **Still write queries in Sentinel format** (with `let` variables, 7d lookback) — adaptation to CD format happens at deployment time via the detection-authoring skill

### Step 2: Check Local Query Library

Search for existing verified queries before writing from scratch:

1. `grep_search` in `queries/` for the table name or keyword
2. `grep_search` in `.github/skills/` for related investigation patterns
3. Check the **Ad-Hoc Query Examples** appendix in `copilot-instructions.md`

If a suitable query exists, adapt it and skip to Step 6. These queries encode known pitfalls and schema quirks.

### Step 3: Get Table Schema (MANDATORY)

```
mcp_kql-search_get_table_schema("<table_name>")
```

Returns: category, description, all columns with data types, and example queries. Use this to verify column names and understand data types.

### Step 4: Get Official Code Samples

```
mcp_microsoft-lea_microsoft_code_sample_search(
  query: "<table_name> <scenario description>",
  language: "kusto"
)
```

Include table name + scenario in the query (e.g., `"EmailEvents phishing detection"`).

### Step 5: Get Community Examples

```
mcp_kql-search_search_github_examples_fallback(
  table_name: "<table_name>",
  description: "<goal description>"
)
```

Also available: `mcp_kql-search_search_kql_repositories` to find KQL-focused repos.

### Step 6: Generate Query

Combine insights: schema for column names, Learn for patterns, community for techniques.

**Standalone queries rule:** When generating MULTIPLE separate queries, each must start directly with the table name — never use shared `let` variables across separate queries (they run independently). Use `let` variables only within a single complex query.

### Step 7: Validate and Test (MANDATORY)

**Test queries against live data before presenting to the user.**

1. Convert `Timestamp` → `TimeGenerated` if adapting MS Learn examples for Sentinel
2. Test via `mcp_sentinel-data_query_lake` or `RunAdvancedHuntingQuery` with `| take 5`
3. Verify results are sensible — check for empty results (wrong table/time/filters)
4. Fix schema mismatches or syntax errors, re-test
5. Remove test limits, present to user

**Common errors:**

| Error | Fix |
|-------|-----|
| `Failed to resolve column 'Timestamp'` | Use `TimeGenerated` (Sentinel) |
| `Failed to resolve column 'TimeGenerated'` | Use `Timestamp` (XDR AH) |
| `Table not found` | Verify with `get_table_schema`; try the other execution tool |
| `expected string expression` | Add `tostring()` after `mv-expand` or `parse_json` |
| Query timeout / too many results | Add datetime filter + `take` or `summarize` |

**Fallback validation:** `mcp_kql-search_validate_kql_query("<query>")` — syntax/schema check only, no live data.

### Step 8: Format and Deliver Output

**Single query:** Provide directly in chat with brief explanation and expected results.

**Multiple queries (3+):** Create a markdown file in `queries/<subfolder>/` with the standardized metadata header. This header is **mandatory** — `build_manifest.py` parses it to index the file for discovery by threat-pulse and other skills.

**File naming:** `queries/<subfolder>/<topic>.md` — e.g., `queries/email/email_threat_detection.md`

**Required metadata header template** (first 10 lines of every query file):

```markdown
# <Descriptive Title>

**Created:** YYYY-MM-DD  
**Platform:** Microsoft Sentinel | Microsoft Defender XDR | Both  
**Tables:** <comma-separated exact KQL table names>  
**Keywords:** <comma-separated searchable terms — attack techniques, scenarios, field names>  
**MITRE:** <comma-separated technique IDs, e.g., T1098.001, T1136.003, TA0008>  
**Domains:** <comma-separated domain tags from the valid set below>  
**Timeframe:** Last N days (configurable)  
```

**Valid domain tags:** `incidents`, `identity`, `spn`, `endpoint`, `email`, `admin`, `cloud`, `exposure`

| Field | Purpose | Parsed By |
|-------|---------|-----------|
| `Tables:` | Exact KQL table names for `grep_search` discovery | `build_manifest.py` (full manifest) |
| `Keywords:` | Searchable terms for attack scenarios, operations, field names | `build_manifest.py` (full manifest) |
| `MITRE:` | ATT&CK technique/tactic IDs for cross-referencing | `build_manifest.py` (slim + full) |
| `Domains:` | Domain tags for threat-pulse cross-referencing | `build_manifest.py` (slim + full) — **missing = validation error** |

**After creating a new query file:** Run `python .github/manifests/build_manifest.py` to regenerate the discovery manifest. The validator will flag any missing required fields.

**Subfolder selection:** Place files in the subfolder matching the primary data source: `identity/`, `endpoint/`, `email/`, `network/`, `cloud/`.

Include per-query documentation with Purpose, Thresholds, Expected Results, and Tuning guidance.

### CD-Aware Output

When CD intent is detected (Step 1), each query MUST include a `<!-- cd-metadata -->` HTML comment block. The full schema is in `.github/skills/detection-authoring/SKILL.md` under CD Metadata Contract.

**Valid cd-metadata fields (exhaustive list):**

| Field | Required | Notes |
|-------|----------|-------|
| `cd_ready` | Always | `true` or `false` |
| `schedule` | If cd_ready | `"0"` (NRT), `"1H"`, `"3H"`, `"12H"`, `"24H"` |
| `category` | If cd_ready | MITRE tactic (e.g., `Persistence`, `CredentialAccess`) |
| `title` | Optional | Dynamic title with `{{Column}}` placeholders (max 3 unique columns across title + description) |
| `impactedAssets` | If cd_ready | Array of `type` + `identifier` pairs |
| `recommendedActions` | Optional | Triage and response guidance string |
| `adaptation_notes` | Optional | What needs to change for CD format |

**⛔ `responseActions` is NOT a valid cd-metadata field.** It shares a name with the Graph API field that is **explicitly prohibited** in LLM-authored detections (`"responseActions": []` is mandatory). Do not include it. Put incident response guidance in `recommendedActions` instead.

```markdown
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Suspicious Scheduled Task on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Investigate the task XML and decode any encoded payloads."
adaptation_notes: "Remove let blocks, add mandatory columns"
-->
```

For queries not suitable for CD (baseline/statistical):
```markdown
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical baseline — requires bare summarize, not CD-compatible"
-->
```

**Summary table:** Include a `CD` column in the Implementation Priority table: `✅ 1H` / `❌`.

---

## Tool Quick Reference

| Tool | Purpose |
|------|---------|
| `mcp_kql-search_get_table_schema` | Get table columns, types, example queries (Step 3) |
| `mcp_microsoft-lea_microsoft_code_sample_search` | Official MS Learn KQL samples — use `language: "kusto"` (Step 4) |
| `mcp_kql-search_search_github_examples_fallback` | Community KQL examples by table name (Step 5) |
| `mcp_kql-search_search_kql_repositories` | Find GitHub repos with KQL collections |
| `mcp_kql-search_validate_kql_query` | Syntax/schema validation (fallback for Step 7) |
| `mcp_kql-search_find_column` | Find which tables contain a specific column |
| `mcp_kql-search_generate_kql_query` | Auto-generate schema-validated query from natural language |
| `mcp_sentinel-data_query_lake` | Execute KQL against live Sentinel (primary validation) |
| `mcp_sentinel-data_search_tables` | Discover tables using natural language |

---

## Schema Differences

| Platform | Timestamp Column | Notes |
|----------|-----------------|-------|
| **Sentinel / Log Analytics** | `TimeGenerated` | All ingested logs |
| **Defender XDR (Advanced Hunting)** | `Timestamp` | XDR-native tables only; Sentinel tables in AH still use `TimeGenerated` |

**Other common differences:** `Identity`/`UserPrincipalName` (Sentinel) vs `AccountUpn`/`AccountName` (XDR); `IPAddress` (Sentinel) vs `RemoteIP`/`LocalIP` (XDR). Always verify with `get_table_schema`.

### Sign-In Table Selection (High-Frequency Queries)

Sign-in queries are the most common query type. Use this decision rule:

| Scenario | Table | Key Differences |
|----------|-------|-----------------|
| **AH query, ≤30d** | **`EntraIdSignInEvents`** (single table) | Covers both interactive + non-interactive. `ErrorCode` (int), `AccountUpn`, `Country`/`City` (direct strings), `LogonType` (JSON array — use `has`), `Timestamp` |
| **Data Lake / >30d** | **`SigninLogs` + `AADNonInteractiveUserSignInLogs`** (union) | `ResultType` (string), `UserPrincipalName`, `parse_json(LocationDetails)` needed for geo, `IsInteractive` (bool), `TimeGenerated` |

**Common mistakes:**
- Using `union SigninLogs, AADNonInteractiveUserSignInLogs` in AH queries — unnecessary, `EntraIdSignInEvents` covers both
- Using `LogonType == "nonInteractiveUser"` — values are JSON arrays (`["nonInteractiveUser"]`), use `has`
- Using `ResultType` on `EntraIdSignInEvents` — column is `ErrorCode` (int), not string

> **Full details:** See `copilot-instructions.md` → Known Table Pitfalls → `EntraIdSignInEvents (AH table preference rule)` for complete column mapping and additional pitfalls.

> **Full table pitfalls** (dynamic field parsing, immutable fields, table casing, deprecated tables) are documented in `copilot-instructions.md` under **Known Table Pitfalls**. Refer there for `SecurityAlert.Status`, `AuditLogs.InitiatedBy`, `SigninLogs.DeviceDetail`, and 20+ other table-specific gotchas.

---

## Best Practices

### Performance Optimization

> **Reference:** [KQL Best Practices — Microsoft Learn](https://learn.microsoft.com/en-us/kusto/query/best-practices?view=microsoft-fabric)

#### 1. Filter on datetime columns first

The most important optimization. Datetime predicates use efficient index-based shard elimination, skipping entire data partitions without scanning.

```kql
// ✅ Correct — datetime first, then selective string filters
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "user@domain.com"

// ❌ Wrong — string filter before datetime
SigninLogs
| where UserPrincipalName =~ "user@domain.com"
| where TimeGenerated > ago(7d)
```

#### 2. Use `has` over `contains` for token matching

`has` uses the term index for full-token lookup. `contains` scans every character — dramatically slower on large tables.

```kql
// ✅ Faster — term-level index lookup
| where UserPrincipalName has "admin"

// ❌ Slower — full substring scan
| where UserPrincipalName contains "admin"
```

Use `contains` only when you genuinely need substring matching (e.g., fragments inside URL paths).

#### 3. Prefer case-sensitive operators

Case-sensitive comparisons (`==`, `in`, `has_cs`) are faster than case-insensitive (`=~`, `in~`, `has`). Use case-insensitive only when casing is unpredictable.

```kql
// ✅ Faster — ActionType, Operation, OfficeWorkload have consistent casing
| where ActionType == "LogonFailed"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where OfficeWorkload == "Exchange"

// 🔵 Use =~ only when casing varies (e.g., user-entered UPNs)
| where UserPrincipalName =~ "user@domain.com"
```

**Common fields with consistent casing** (always use `==` / `in`): `ActionType`, `Operation`, `OfficeWorkload`, `EventID`, `ResultType`, `DeliveryAction`, `EmailDirection`, `LogonType`, `Severity`, `Status`, `Classification`.

#### 4. Filter tables BEFORE joins

Pre-filter both sides of a join to reduce data volume. Move `where` clauses into subqueries.

```kql
// ✅ Correct — filter KB table before joining
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where IsExploitAvailable == true
    | where CvssScore >= 8.0
) on CveId

// ❌ Wrong — joins full tables, filters after
DeviceTvmSoftwareVulnerabilities
| join kind=inner DeviceTvmSoftwareVulnerabilitiesKB on CveId
| where IsExploitAvailable == true
```

**Join sizing rules:**
- Smaller table on the left (or `hint.strategy=broadcast` when left is small)
- `in` instead of `left semi join` for single-column filtering
- `lookup` instead of `join` when right side is small (<50 MB)
- `hint.shufflekey=<key>` when both sides are large with high-cardinality join key

#### 5. Use `materialize()` for multi-referenced `let` statements

Without `materialize()`, the engine may recompute the `let` expression each time it's referenced.

```kql
// ✅ Computed once, reused twice
let SprayFailures = materialize(
    EntraIdSignInEvents
    | where Timestamp > ago(7d)
    | where ErrorCode in (50126, 50053, 50057)
    | summarize FailedAttempts = count(), TargetUsers = dcount(AccountUpn)
        by SourceIP = IPAddress
    | where TargetUsers >= 5);
```

#### 6. Narrow `arg_max` to only needed columns

`arg_max(TimeGenerated, *)` materializes every column. Specify only what you use.

```kql
// ✅ Only 5 columns materialized
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, Entities, Tactics, Techniques, AlertName, AlertSeverity) by SystemAlertId

// ❌ Materializes all 30+ columns
SecurityAlert
| summarize arg_max(TimeGenerated, *) by SystemAlertId
```

#### 7. Pre-filter before JSON parsing

For rare key/value lookups in dynamic columns, use `has` to eliminate rows before expensive `parse_json()`.

```kql
// ✅ Term filter first, JSON parse on survivors
AuditLogs
| where tostring(TargetResources) has "MyApp"
| extend Target = tostring(parse_json(tostring(TargetResources[0])).displayName)
| where Target == "MyApp"
```

#### 8. Filter on table columns, not calculated columns

Filtering on native columns enables index usage; calculated columns force full scans.

```kql
// ✅ Filter on native column
SecurityEvent | where EventID == 4625

// ❌ Filter on calculated column
SecurityEvent | extend Cat = case(EventID == 4625, "Fail", ...) | where Cat == "Fail"
```

#### 9. Project only needed columns early

Drop unnecessary columns before expensive operators (`join`, `summarize`, `mv-expand`) to reduce memory and shuffling.

#### 10. Use `take` or `summarize` to limit results

Unbounded queries on large tables consume excessive resources.

#### 11. Platform-specific dynamic column access

In AH, `AuditLogs.InitiatedBy` and `TargetResources` are native dynamic — use direct dot-notation. In Data Lake, they may be string-typed requiring `parse_json()`.

```kql
// ✅ Advanced Hunting — direct access
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)

// ✅ Data Lake — parse_json wrapper
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)

// 🔵 Safe in both — stringify full field
| where tostring(InitiatedBy) has "user@domain.com"
```

### Security and Privacy

- **Limit sensitive data exposure** — redact PII with `strcat(substring(UPN, 0, 3), "***")` when appropriate
- **Filter early** — reduce dataset before projecting sensitive columns

### Code Quality

- **Comments** — explain what the query does and why key filters are applied
- **Meaningful variable names** — `let SuspiciousIPs = ...` not `let x = ...`
- **Standalone queries** — when providing multiple separate queries, each MUST start with the table name directly. Never share `let` variables across queries the user will run independently

---

## Dynamic Type Casting

**Common "expected string expression" error:** After `mv-expand`, `parse_json`, or `split`, values are `dynamic` — string functions fail. Always convert first:

```kql
// After mv-expand
| mv-expand AuthDetails
| extend AuthMethod = tostring(AuthDetails.authenticationMethod)

// After split
| extend Parts = split(UPN, "@")
| extend Domain = tostring(Parts[1])
```

**Rule of thumb:** If you get "expected string expression", add `tostring()`.
