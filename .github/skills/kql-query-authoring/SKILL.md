---
name: kql-query-authoring
description: Use this skill when asked to write, create, or help with KQL (Kusto Query Language) queries for Microsoft Sentinel, Defender XDR, or Azure Data Explorer. Triggers on keywords like "write KQL", "create KQL query", "help with KQL", "query [table]", "KQL for [scenario]", or when a user requests queries for specific data analysis scenarios. This skill uses schema validation, Microsoft Learn documentation, and community examples to generate production-ready KQL queries.
---

# KQL Query Authoring - Instructions

## Purpose

This skill helps generate validated, production-ready KQL (Kusto Query Language) queries by leveraging:
- **Schema validation** from 331+ indexed tables
- **Microsoft Learn documentation** for official patterns
- **Community query examples** from GitHub repositories
- **Best practices** for performance and security

---

## Prerequisites

**Required MCP Servers:**

This skill requires two MCP servers to be installed and configured in your VS Code environment:

1. **KQL Search MCP Server** - Provides schema validation, query examples, and table discovery
   - **NPM Package**: [kql-search-mcp](https://www.npmjs.com/package/kql-search-mcp)
   - **Install**: `npm install -g kql-search-mcp`
   - **Features**: 331+ indexed tables, schema validation, GitHub query search, query generation

2. **Microsoft Docs MCP Server** - Provides access to official Microsoft Learn documentation
   - **GitHub Repository**: [MicrosoftDocs/mcp](https://github.com/MicrosoftDocs/mcp)
   - **Features**: Official code samples, documentation fetch, Kusto language examples

**Verification:**
- KQL Search MCP tools should be available: `mcp_kql-search_*`
- Microsoft Docs MCP tools should be available: `mcp_microsoft-lea_*`

Without these MCP servers, this skill cannot access schema information or official documentation.

---

## ⚠️ Known Issues

### `search_favorite_repos` Bug (as of v1.0.5)

**Status:** ❌ Broken - GitHub API query parsing fails with any query

**Error:** `ERROR_TYPE_QUERY_PARSING_FATAL unable to parse query!`

**Affected Tool:** `mcp_kql-search_search_favorite_repos`

**Root Cause:** Bug in query construction when building GitHub Code Search API request, even with valid `GITHUB_TOKEN` and `FAVORITE_REPOS` configuration.

**Workarounds - Use these tools instead:**

| Tool | Status | Use Case |
|------|--------|----------|
| `mcp_kql-search_search_github_examples_fallback` | ✅ Works | Search all public repos for KQL examples |
| `mcp_microsoft-lea_microsoft_code_sample_search` | ✅ Works | Official Microsoft Learn code samples |
| `mcp_kql-search_get_table_schema` | ✅ Works | Schema validation with example queries |
| `mcp_kql-search_search_kql_repositories` | ✅ Works | Find repos containing KQL queries |

**Issue Tracking:** Report to [noodlemctwoodle/kql-search-mcp](https://github.com/noodlemctwoodle/kql-search-mcp/issues)

---

## 📑 TABLE OF CONTENTS

1. **[Prerequisites](#prerequisites)** - Required MCP servers
2. **[Known Issues](#-known-issues)** - Bug reports and workarounds
3. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
4. **[Query Authoring Workflow](#query-authoring-workflow)** - Step-by-step process
5. **[Tool Reference](#tool-reference)** - Available MCP tools
6. **[Query Patterns](#common-query-patterns)** - By use case
7. **[Schema Differences](#critical-schema-differences)** - Sentinel vs XDR
8. **[Validation Rules](#validation-rules)** - Quality checks
9. **[Best Practices](#best-practices)** - Performance & security

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before writing ANY KQL query:**

1. **ALWAYS validate table schema FIRST** - Use `mcp_kql-search_get_table_schema` to verify:
   - Table exists in the environment
   - Column names are correct
   - Data types are accurate
   - Common query patterns exist

2. **ALWAYS check schema differences** - Column names vary by platform:
   - **Microsoft Sentinel**: Uses `TimeGenerated` for timestamp
   - **Defender XDR**: Uses `Timestamp` for timestamp
   - **Other differences**: See [Schema Differences](#critical-schema-differences) section

3. **ALWAYS check local query library FIRST** - Before writing from scratch:
   - Search `queries/` and `.github/skills/` for existing verified queries (these are battle-tested and pitfall-aware)
   - See the **KQL Pre-Flight Checklist** in `copilot-instructions.md` for the full priority order
   - If a suitable query exists locally, adapt it instead of building from scratch

4. **ALWAYS use multiple sources** - Combine for best results:
   - Schema validation (authoritative column names)
   - Microsoft Learn code samples (official patterns)
   - Community queries (real-world examples)

5. **ALWAYS test queries using the correct execution tool** - Follow the **Tool Selection Rule** in `copilot-instructions.md`:
   - **Sentinel-native tables** (SigninLogs, AuditLogs, SecurityAlert, etc.) → Data Lake
   - **XDR tables** (Device*, Email*, Identity*, etc.) ≤ 30d → Advanced Hunting (free); > 30d → Data Lake
   - **XDR-only tables** (DeviceTvm*, Exposure*, etc.) → Advanced Hunting only
   - Adapt timestamp column when switching tools (`Timestamp` ↔ `TimeGenerated`)
   - **This is the MOST IMPORTANT validation step**

6. **ALWAYS validate syntax** (if live testing unavailable) - Use `mcp_kql-search_validate_kql_query` as fallback

7. **ALWAYS provide context** - Include:
   - What the query does
   - Expected results
   - Any limitations or notes

8. **ALWAYS read the complete ## Query Authoring Workflow**
   - Read all the steps of the workflow
   - Understand the process and actions you need to take

> **📋 Inherited rules:** This skill inherits the **KQL Pre-Flight Checklist**, **Tool Selection Rule (Data Lake vs Advanced Hunting)**, and **Known Table Pitfalls** from `copilot-instructions.md`. Those rules are authoritative — do not contradict them here.

---

## Query Authoring Workflow

### Step 1: Understand User Requirements

**Extract key information:**
- **Table(s) needed**: Which data source? (e.g., `SigninLogs`, `EmailEvents`, `SecurityAlert`)
- **Time range**: How far back? (e.g., last 7 days, specific date range)
- **Filters**: What specific conditions? (e.g., user, IP, threat type)
- **Output**: Statistics, detailed records, time series, aggregations?
- **Platform**: Sentinel or Defender XDR? (affects column names)

### Step 2: Check Local Query Library

**Before writing from scratch, search for existing verified queries:**

1. `grep_search` in `queries/` for the table name or keyword
2. `grep_search` in `.github/skills/` for related investigation patterns
3. Check the **Ad-Hoc Query Examples** appendix in `copilot-instructions.md`

If a suitable query exists, adapt it (substituting entity values) and skip to Step 6. These queries encode known pitfalls and schema quirks.

### Step 3: Get Table Schema (MANDATORY)

**If no local query found, start here to validate table and columns exist:**

```
mcp_kql-search_get_table_schema("<table_name>")
```

**What this returns:**
- ✅ Category (Sentinel, Defender XDR, Azure Monitor)
- ✅ Description of table purpose
- ✅ **Common columns** (most frequently used)
- ✅ **All columns** with data types
- ✅ **Example queries** (starting point)
- ✅ Keywords for search

**Use this to:**
1. Verify table exists
2. Get correct column names (avoid typos)
3. Understand data types (string, datetime, int, etc.)
4. See example query patterns

### Step 4: Get Official Code Samples

**Query Microsoft Learn for official patterns:**

```
mcp_microsoft-lea_microsoft_code_sample_search(
  query: "Detailed description of what you're trying to accomplish",
  language: "kusto"
)
```

**Best practices for search queries:**
- Include table name: "EmailEvents phishing detection"
- Include scenario: "threat hunting", "user activity", "mail flow"
- Include key concepts: "spam", "failed login", "malware"

**What you get:**
- Official Microsoft-documented patterns
- Production-validated examples
- Links to full documentation
- Best practice implementations

### Step 5: Get Community Examples

**⚠️ NOTE:** The `search_favorite_repos` tool has a known bug (see [Known Issues](#-known-issues)). Use the fallback tool instead.

**Search GitHub for real-world implementations:**

```
mcp_kql-search_search_github_examples_fallback(
  table_name: "EmailEvents",
  description: "Natural language description of query goal"
)
```

**Alternative - Search for KQL repositories:**
```
mcp_kql-search_search_kql_repositories(
  query: "sentinel detection hunting"
)
```

**What this provides:**
- Real-world query patterns from security analysts
- Detection rules from Microsoft Sentinel community
- Advanced techniques and optimizations
- Context from surrounding documentation

### Step 6: Generate Query

**Combine insights from all sources:**

1. **Use schema for column names** (authoritative source)
2. **Use Microsoft Learn for patterns** (official best practices)
3. **Use community examples for techniques** (real-world validation)

**🔥 CRITICAL: Microsoft Learn Examples Use Defender XDR Syntax!**

**⚠️ When using Microsoft Learn code samples:**
- Microsoft Learn examples use **Defender XDR Advanced Hunting** syntax with `Timestamp`
- If testing against **Sentinel**, you MUST convert `Timestamp` → `TimeGenerated` BEFORE testing
- Check the platform context - Sentinel vs Defender XDR - and adjust accordingly

**🔥 CRITICAL: Test queries BEFORE providing them to user - not after they ask!**

**⚠️ CRITICAL: Variables vs Multiple Standalone Queries**

**When user asks for MULTIPLE queries** (different analyses, different questions):
- ✅ **DO:** Start EACH query directly with table name (`EmailEvents`, `SigninLogs`, etc.)
- ❌ **DON'T:** Use shared variables (`let emailData = ...`) across separate queries
- **Why:** Each query is standalone - user runs them independently in separate windows
- **Test:** If you can't copy-paste a query alone and run it successfully, it's wrong

**When providing ONE complex query** (single cohesive analysis):
- ✅ **DO:** Use `let` variables to simplify logic and avoid repetition
- ✅ Example: `let suspiciousIPs = ...; SigninLogs | where IPAddress in (suspiciousIPs)`

**Query structure for standalone queries:**
```kql
// Description: What this query does
// Data source: Table name
// Time range: Lookback period
// Expected results: What you'll get

<TableName>
| where TimeGenerated > ago(7d)  // Sentinel
// OR
| where Timestamp > ago(7d)       // Defender XDR
| where <filters>
| project <relevant_columns>
| order by TimeGenerated desc
| take 100
```

### Step 7: Validate and Test (MANDATORY - Do This FIRST!)

**⚠️ TEST QUERIES BEFORE USER SEES THEM - NOT AFTER THEY ASK**

**🔴 CRITICAL PRE-TEST STEP: Platform Schema Conversion**

**BEFORE testing against Sentinel, you MUST:**
1. ✅ **Convert `Timestamp` → `TimeGenerated`** if using Microsoft Learn examples (they use Defender XDR syntax)
2. ✅ **Verify all column names** match Sentinel schema (not Defender XDR schema)
3. ✅ **Check the table exists** in Sentinel environment

**Why this matters:** Microsoft Learn code samples use `Timestamp` (Defender XDR Advanced Hunting syntax), but Sentinel uses `TimeGenerated`. Testing will FAIL if you don't convert first.

**Primary validation workflow (if Sentinel MCP available):**

1. ✅ **CONVERT SCHEMA** (Timestamp → TimeGenerated) BEFORE testing
2. ✅ **TEST AGAINST LIVE SENTINEL** using `mcp_sentinel-data_query_lake` with `| take 5`
3. ✅ Verify query returns results (not empty)
4. ✅ Fix any syntax errors or schema mismatches
5. ✅ Re-test until query works correctly
6. ✅ Only then provide query to user with confidence

**Post-test checks:**

1. ✅ Include comments explaining logic
2. ✅ Add `take` or `summarize` to limit results (remove test limits if too restrictive)
3. ✅ Check datetime formatting (see time formatting section below)

**🔥 CRITICAL: Always Test Queries Against Live Data**

**When Sentinel MCP Server is available, ALWAYS run queries to validate:**

```
mcp_sentinel-data_query_lake(
  query: "<your_complete_kql_query>",
  workspaceId: "<workspace_id_if_multiple>"  // Optional
)
```

**Why this is critical:**
- ✅ Validates query syntax against real Sentinel environment
- ✅ Confirms columns exist and are correctly typed
- ✅ Verifies data is present in the table
- ✅ Tests aggregations and calculations work correctly
- ✅ Reveals actual data patterns and edge cases
- ✅ Provides real results to show user what to expect

**Validation workflow:**

1. **Generate query** based on schema, docs, and examples
2. **Test query** using `mcp_sentinel-data_query_lake` with `| take 10` or `| take 5` limit
3. **Verify results** are sensible and expected
4. **Fix issues** if query fails or returns unexpected results
5. **Re-test** until query works correctly
6. **Provide to user** with confidence it will work

**Best practices for testing:**

- **Add `| take 10`** to limit results during testing (remove or adjust for user)
- **Test multiple queries in parallel** if providing multiple standalone queries
- **Check for empty results** - may indicate wrong table, time range, or filters
- **Verify calculations** - check that percentages, counts, and aggregations make sense
- **Review actual data values** - ensure field names and data types match expectations

**Example testing pattern:**

```kql
// Test Query: Sign-ins by user with CA status
SigninLogs
| where TimeGenerated > ago(7d)
| summarize 
    TotalSignIns = count(),
    CASuccess = countif(ConditionalAccessStatus == "success"),
    CAFailure = countif(ConditionalAccessStatus == "failure")
    by UserPrincipalName
| order by TotalSignIns desc
| take 5  // Limit for testing
```

**If query fails:**
- Check error message for column name issues
- Verify table exists in environment
- Confirm time range has data
- Review filter syntax
- Check for typos in field names

**Schema-only validation (fallback):**
```
mcp_kql-search_validate_kql_query("<your_query>")
```
**Note:** This only validates syntax and schema, not against live data. Prefer `mcp_sentinel-data_query_lake` when available.

### Step 8: Format and Deliver Output

**⚠️ CRITICAL: Output Format Based on Query Count**

**For SINGLE query requests:**
- ✅ **DO:** Provide query directly in chat window
- ✅ Include brief explanation and expected results
- ✅ Show sample output if tested against Sentinel
- ❌ **DON'T:** Create a file for single queries

**For MULTIPLE queries (3+ queries or comprehensive query collections):**
- ✅ **DO:** Create a comprehensive markdown file
- ✅ Save to `/queries` directory in workspace root
- ✅ Use descriptive filename: `<topic>_<platform>_queries.md`
- ✅ Include all queries with full documentation
- ✅ Add examples, use cases, and tuning guidance

**File naming convention:**
```
queries/endpoint/endpoint_failed_connections.md
queries/identity/app_credential_management.md
queries/email/email_threat_detection.md
```

**Markdown file structure for multiple queries:**
```markdown
# [Topic] - [Platform] Queries

**Created:** [Date]
**Platform:** Microsoft Sentinel / Defender XDR
**Data Sources:** [Tables used]
**Timeframe:** [Default lookback period]

---

## Overview

[Brief description of query collection purpose]

---

## Query 1: [Descriptive Title]

**Purpose:** [What this query detects/analyzes]

**Thresholds:**
- [Key threshold values]

```kql
// Query code with comments
```

**Expected Results:**
- Column descriptions
- What to look for

**Indicators of [Attack/Issue]:**
- [Key patterns to identify]

**Example Output:**
[Sample results if available]

---

## Query 2: [Next Query]
...

---

## Tuning and Customization
[How to adjust queries for environment]

## Alert Rule Recommendations
[How to convert to analytics rules]

## Investigation Workflow
[What to do with results]

---

```

**When to create query files:**
- User requests 3+ different queries
- User asks for "comprehensive" or "complete" query set
- User requests query collection for specific use case (threat hunting, investigation, monitoring)
- Queries are related and form a cohesive analysis workflow

**When to use chat output:**
- User requests 1-2 simple queries
- Quick ad-hoc query for immediate use
- User testing or learning KQL syntax
- Follow-up query to previous investigation

**File location:**
- **Directory:** `/queries` in workspace root
- **Git:** Already excluded in `.gitignore` (may contain environment-specific info)
- **Purpose:** Reusable query collections for common scenarios

---

## Tool Reference

### mcp_kql-search_get_table_schema

**Purpose:** Get comprehensive table schema with columns, types, and examples

**When to use:**
- Starting any new query
- Verifying column names
- Understanding data structure
- Finding example queries

**Input:**
```json
{
  "table_name": "EmailEvents"
}
```

**Returns:**
- Category and source
- Description
- Common columns (most used)
- All columns with types
- Example queries
- Keywords

---

### mcp_microsoft-lea_microsoft_code_sample_search

**Purpose:** Search official Microsoft Learn documentation for code samples

**When to use:**
- Need official Microsoft patterns
- Want production-validated examples
- Looking for best practices
- Need links to documentation

**Input:**
```json
{
  "query": "EmailEvents KQL query Defender for Office mail flow statistics spam threats",
  "language": "kusto"
}
```

**Returns:**
- Code snippets with descriptions
- Links to Microsoft Learn pages
- Official examples
- Context about usage

**Pro tip:** Include `language: "kusto"` parameter to filter for KQL samples only

---

### mcp_kql-search_search_github_examples_fallback ✅ (RECOMMENDED)

**Purpose:** Search all public GitHub repos for KQL query examples by table name

**When to use:**
- Need real-world query examples for a specific table
- `search_favorite_repos` is broken (see [Known Issues](#-known-issues))
- Looking for detection rules and community patterns
- Want unvalidated examples from the community

**Input:**
```json
{
  "table_name": "SecurityIncident",
  "description": "summarize by status classification severity"
}
```

**Returns:**
- Query examples from GitHub repositories
- Repository and file path context
- Raw KQL code (unvalidated - verify before use)

---

### mcp_kql-search_search_favorite_repos ❌ (BROKEN)

**Status:** ❌ Known bug as of v1.0.5 - do not use

**Error:** `ERROR_TYPE_QUERY_PARSING_FATAL unable to parse query!`

**Use instead:** `mcp_kql-search_search_github_examples_fallback` or `mcp_microsoft-lea_microsoft_code_sample_search`

---

### mcp_kql-search_search_kql_repositories ✅

**Purpose:** Find GitHub repositories containing KQL queries

**When to use:**
- Looking for well-maintained KQL query collections
- Want to discover new query sources
- Finding repos sorted by stars

**Input:**
```json
{
  "query": "sentinel detection hunting"
}
```

**Returns:**
- Repository list sorted by stars
- Repository descriptions
- Links to explore further

---

### mcp_sentinel-data_query_lake

**Purpose:** Execute KQL queries against live Microsoft Sentinel workspace for validation and testing

**When to use:**
- **ALWAYS when generating queries** - validate against real data
- Testing query syntax and logic
- Verifying columns exist and are correctly typed
- Confirming data is present in tables
- Validating aggregations and calculations
- Spot-checking query results before providing to user

**Input:**
```json
{
  "query": "SigninLogs | where TimeGenerated > ago(7d) | summarize count() by UserPrincipalName | take 10",
  "workspaceId": "optional-workspace-guid-if-multiple"
}
```

**Returns:**
- Query results in structured format
- Column names and data types
- Actual data rows
- Query statistics (execution time, resource usage)
- Error messages if query fails

**Best practices:**
- Add `| take 10` or `| take 5` during testing to limit results
- Test multiple queries in parallel when providing multiple standalone queries
- Check for empty results (may indicate wrong table/time range/filters)
- Verify calculations and aggregations are correct
- Review actual data values to ensure fields match expectations

**Example usage:**
```
// Test query before providing to user
mcp_sentinel-data_query_lake(
  query: "SigninLogs | where TimeGenerated > ago(7d) | summarize TotalSignIns = count(), UniqueApps = dcount(AppDisplayName) by UserPrincipalName | order by TotalSignIns desc | take 5"
)
```

**Critical notes:**
- This executes against **LIVE production data** - queries affect workspace resources
- Always use appropriate time ranges and result limits
- Failed queries return error messages to help debug issues
- Prefer this over schema-only validation when available

---

### mcp_sentinel-data_search_tables

**Purpose:** Discover relevant Sentinel tables using natural language queries

**When to use:**
- User request is ambiguous about which table to use
- Need to find tables for specific scenarios
- Exploring available data sources
- Confirming table availability in workspace

**Input:**
```json
{
  "query": "sign-in authentication Entra ID user activity",
  "workspaceId": "optional-workspace-guid-if-multiple"
}
```

**Returns:**
- Relevant table names
- Table schemas
- Descriptions of table contents
- Availability in workspace

**Use case:** "I need to query user sign-in data" → Tool suggests `SigninLogs`, `AADNonInteractiveUserSignInLogs`

**Search tips:**
- Use natural language
- Include table names
- Mention key concepts
- Be specific about goals

---

### mcp_kql-search_validate_kql_query

**Purpose:** Validate KQL query syntax and schema

**When to use:**
- Before executing queries
- After generating complex queries
- To catch common mistakes
- To verify column names

**Input:**
```json
{
  "query": "EmailEvents | where Timestamp > ago(7d) | summarize count() by ThreatTypes"
}
```

**Returns:**
- Syntax validation results
- Schema validation (table/column names)
- Warnings and errors
- Suggestions for fixes

---

### mcp_kql-search_find_column

**Purpose:** Find which tables contain a specific column

**When to use:**
- Know column name, not table
- Looking for similar data across tables
- Exploring schema relationships

**Input:**
```json
{
  "column_name": "ThreatTypes"
}
```

**Returns:**
- List of tables with that column
- Column details for each table
- Data types

---

### mcp_kql-search_generate_kql_query

**Purpose:** Auto-generate validated KQL query from natural language

**When to use:**
- Quick query generation
- Starting point for complex queries
- Learning KQL patterns
- Schema-validated output needed

**Input:**
```json
{
  "description": "show failed sign-ins from the last 24 hours",
  "table_name": "SigninLogs",
  "time_range": "24h",
  "filters": {"ResultType": "Failed"},
  "columns": ["TimeGenerated", "UserPrincipalName", "IPAddress", "Location"],
  "limit": 100
}
```

**Returns:**
- Fully validated query
- Schema validation results
- Documentation links
- Explanations

**Note:** All table names and columns are verified against 331+ table index

---

## Common Query Patterns

### 1. Basic Filtering and Projection

**Use case:** Get specific records matching criteria

```kql
// Get failed sign-ins for specific user
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "user@domain.com"
| where ResultType != "0"  // 0 = success
| project TimeGenerated, IPAddress, Location, ResultDescription
| order by TimeGenerated desc
| take 100
```

---

### 2. Aggregation and Statistics

**Use case:** Count, summarize, or group data

```kql
// Count emails by threat type
EmailEvents
| where TimeGenerated > ago(7d)
| summarize Count = count() by ThreatTypes
| order by Count desc
```

---

### 3. Time Series Analysis

**Use case:** Trend over time

```kql
// Daily sign-in volume
SigninLogs
| where TimeGenerated > ago(30d)
| summarize Count = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
| render timechart
```

---

### 4. Multiple Conditions

**Use case:** Complex filtering logic

```kql
// High-risk sign-ins
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium")
| where RiskState == "atRisk"
| where ConditionalAccessStatus != "success"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

---

### 5. Joins Across Tables

**Use case:** Correlate data from multiple sources

```kql
// Email threats with user info
EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has_any ("Phish", "Malware")
| join kind=inner (
    IdentityInfo
    | distinct AccountUpn, Department, JobTitle
) on $left.RecipientEmailAddress == $right.AccountUpn
| project TimeGenerated, RecipientEmailAddress, Department, JobTitle, ThreatTypes, Subject
```

---

### 6. JSON Parsing

**Use case:** Extract data from dynamic/JSON columns

```kql
// Parse authentication details
SigninLogs
| where TimeGenerated > ago(7d)
| extend AuthDetails = parse_json(AuthenticationDetails)
| mv-expand AuthDetails
| extend AuthMethod = tostring(AuthDetails.authenticationMethod)
| project TimeGenerated, UserPrincipalName, AuthMethod
```

---

### 7. Statistical Analysis

**Use case:** Percentiles, averages, distributions

```kql
// Sign-in duration statistics
SigninLogs
| where TimeGenerated > ago(7d)
| where isnotempty(ProcessingTimeInMilliseconds)
| summarize 
    AvgTime = avg(ProcessingTimeInMilliseconds),
    P50 = percentile(ProcessingTimeInMilliseconds, 50),
    P95 = percentile(ProcessingTimeInMilliseconds, 95),
    P99 = percentile(ProcessingTimeInMilliseconds, 99)
```

---

### 8. Dynamic Type Casting

**Use case:** Converting dynamic/JSON types to strings for manipulation

**⚠️ CRITICAL: Always convert dynamic types to string BEFORE using string functions**

**❌ Wrong - Will cause "expected string expression" error:**
```kql
EmailEvents
| where isnotempty(ThreatTypes)
| extend ThreatType = split(ThreatTypes, ",")
| mv-expand ThreatType
| extend ThreatType = trim(" ", ThreatType)  // ERROR: ThreatType is still dynamic
```

**✅ Correct - Convert to string first:**
```kql
EmailEvents
| where isnotempty(ThreatTypes)
| extend ThreatType = split(ThreatTypes, ",")
| mv-expand ThreatType
| extend ThreatType = tostring(ThreatType)  // Convert to string first
| extend ThreatType = trim(@"\s", ThreatType)  // Now string functions work
```

**Common scenarios requiring type conversion:**

```kql
// After mv-expand
| mv-expand AuthDetails
| extend AuthMethod = tostring(AuthDetails.authenticationMethod)  // Convert before use

// After parse_json
| extend Details = parse_json(AdditionalFields)
| extend EventType = tostring(Details.EventType)  // Convert before string operations

// After split operations
| extend Parts = split(UserPrincipalName, "@")
| extend Domain = tostring(Parts[1])  // Convert array element to string
```

**Rule of thumb:** If you get "expected string expression" error, add `tostring()` before the problematic operation.

---

## CRITICAL: Schema Differences

### Timestamp Column Names

**⚠️ MOST COMMON ERROR: Using wrong timestamp column**

| Platform | Column Name | Usage |
|----------|-------------|-------|
| **Microsoft Sentinel** | `TimeGenerated` | All ingested logs |
| **Defender XDR** | `Timestamp` | Advanced Hunting tables |
| **Azure Monitor** | `TimeGenerated` | Log Analytics tables |

**Example differences:**

```kql
// ✅ CORRECT for Sentinel
EmailEvents
| where TimeGenerated > ago(7d)

// ✅ CORRECT for Defender XDR
EmailEvents
| where Timestamp > ago(7d)
```

**How to avoid errors:**
1. Ask user which platform they're using
2. Check schema with `mcp_kql-search_get_table_schema`
3. Look at example queries in schema output
4. If query fails with "column not found", try alternate name

---

### Time Range Formatting

**⚠️ CRITICAL: Use `ago()` function, NOT datetime literals**

**✅ CORRECT - Use ago() function:**
```kql
SigninLogs
| where TimeGenerated > ago(7d)   // Last 7 days
| where TimeGenerated > ago(30d)  // Last 30 days
| where TimeGenerated > ago(1h)   // Last 1 hour
```

**❌ WRONG - Hardcoded datetime strings (will fail or give wrong results):**
```kql
SigninLogs
| where TimeGenerated > "2026-01-06"  // ERROR: String comparison
| where TimeGenerated > 2026-01-06    // ERROR: Invalid syntax
```

**For specific date ranges, use `between()` with `datetime()` function:**
```kql
let start = datetime(2026-01-01);
let end = datetime(2026-01-13);
SigninLogs
| where TimeGenerated between (start .. end)
```

**Common time range patterns:**
```kql
// Relative time ranges (PREFERRED)
| where TimeGenerated > ago(7d)      // Last 7 days
| where TimeGenerated > ago(24h)     // Last 24 hours
| where TimeGenerated > ago(90d)     // Last 90 days

// Specific date ranges
let startDate = datetime(2026-01-01);
let endDate = datetime(2026-01-31);
| where TimeGenerated between (startDate .. endDate)

// Time window (last X to Y ago)
| where TimeGenerated between (ago(14d) .. ago(7d))  // Between 14 and 7 days ago
```

**Time units for ago():**
- `d` = days
- `h` = hours
- `m` = minutes
- `s` = seconds

**Why ago() is preferred:**
- Always relative to query execution time
- No timezone confusion
- Works across all environments
- No need to calculate dates manually

---

### Other Common Differences

| Column | Sentinel | Defender XDR | Notes |
|--------|----------|--------------|-------|
| User identity | `Identity`, `UserPrincipalName` | `AccountUpn`, `AccountName` | Check schema |
| IP address | `IPAddress` | `RemoteIP`, `LocalIP` | Context-dependent |
| Device name | `DeviceName` | `DeviceName` | Usually consistent |

---

## Validation Rules

### Pre-Execution Checklist

Before providing any query to user:

- [ ] **Schema validated**: All tables exist
- [ ] **Columns verified**: All columns exist with correct names
- [ ] **Time column correct**: `TimeGenerated` vs `Timestamp`
- [ ] **Time filter included**: Always filter on time for performance
- [ ] **Results limited**: Include `take` or `summarize` to avoid huge results
- [ ] **Comments added**: Explain what query does
- [ ] **Data types correct**: String comparisons use `==` or `=~`, not `=`
- [ ] **Syntax valid**: No obvious typos or errors

---

### Common Syntax Errors to Avoid

**❌ Wrong:**
```kql
// Missing time filter
SigninLogs | where UserPrincipalName == "user@domain.com"

// Wrong timestamp column
EmailEvents | where Timestamp > ago(7d)  // If on Sentinel

// No result limit
SecurityAlert | where TimeGenerated > ago(7d)  // Could return 1000s of rows

// Wrong string comparison
SigninLogs | where UserPrincipalName = "user@domain.com"  // Use == or =~
```

**✅ Correct:**
```kql
// Time filter + result limit
SigninLogs 
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "user@domain.com"  // =~ is case-insensitive
| take 100

// Correct timestamp for platform
EmailEvents 
| where TimeGenerated > ago(7d)  // Sentinel
| take 100

// Aggregation instead of raw records
SecurityAlert 
| where TimeGenerated > ago(7d)
| summarize Count = count() by Severity

// Case-insensitive comparison
SigninLogs 
| where UserPrincipalName =~ "user@domain.com"  // =~ for case-insensitive
```

---

## Best Practices

### Performance Optimization

1. **Always filter on time first**
   ```kql
   | where TimeGenerated > ago(7d)  // First filter
   | where UserPrincipalName =~ "user@domain.com"  // Then specific filters
   ```

2. **Use `take` for exploration**
   ```kql
   | take 100  // Limit results during testing
   ```

3. **Use `summarize` instead of raw records**
   ```kql
   // Better
   | summarize Count = count() by Category
   
   // Avoid for large datasets
   | project Category, Details, TimeGenerated
   ```

4. **Project only needed columns**
   ```kql
   | project TimeGenerated, UserPrincipalName, IPAddress  // Only what you need
   ```

5. **Avoid wildcards in filters**
   ```kql
   // Better
   | where UserPrincipalName has "admin"
   
   // Slower
   | where UserPrincipalName contains "admin"
   ```

---

### Security and Privacy

1. **Limit sensitive data exposure**
   ```kql
   // Redact PII if needed
   | extend MaskedEmail = strcat(substring(UserPrincipalName, 0, 3), "***")
   ```

2. **Be careful with `take`**
   ```kql
   // Good for testing
   | take 10
   
   // May miss important data
   | take 1  // Too restrictive
   ```

3. **Filter early, filter often**
   ```kql
   | where TimeGenerated > ago(7d)  // Reduce dataset early
   | where isnotempty(UserPrincipalName)  // Remove nulls
   | where UserPrincipalName !has "service"  // Exclude service accounts
   ```

---

### Code Quality

1. **Always include comments**
   ```kql
   // Get failed sign-ins for admin accounts in last 24 hours
   SigninLogs
   | where TimeGenerated > ago(1d)
   | where UserPrincipalName has "admin"
   | where ResultType != "0"
   | project TimeGenerated, UserPrincipalName, IPAddress, ResultDescription
   ```

2. **Use meaningful variable names**
   ```kql
   let SuspiciousIPs = dynamic(["203.0.113.42", "198.51.100.10"]);
   SigninLogs
   | where IPAddress in (SuspiciousIPs)
   ```

3. **Format for readability**
   ```kql
   // Good formatting
   SigninLogs
   | where TimeGenerated > ago(7d)
   | where ResultType != "0"
   | summarize 
       FailedCount = count(),
       UniqueIPs = dcount(IPAddress)
       by UserPrincipalName
   | order by FailedCount desc
   ```

4. **Break complex queries into steps**
   ```kql
   let FailedSignins = SigninLogs
       | where TimeGenerated > ago(7d)
       | where ResultType != "0";
   
   let HighRiskUsers = FailedSignins
       | summarize FailCount = count() by UserPrincipalName
       | where FailCount > 10;
   
   HighRiskUsers
   | join kind=inner (FailedSignins) on UserPrincipalName
   | project TimeGenerated, UserPrincipalName, IPAddress, Location
   ```

5. **⚠️ CRITICAL: Use table names directly when providing multiple standalone queries**
   
   **❌ WRONG - Shared variables don't work across separate query executions:**
   ```kql
   // This pattern FAILS when user runs queries separately
   let emailData = EmailEvents | where Timestamp > ago(7d);
   
   // Query 1
   emailData  
   | summarize count() by EmailDirection
   
   // Query 2 - ERROR: 'emailData' is undefined in separate query window
   emailData  
   | summarize count() by ThreatTypes
   ```
   
   **✅ CORRECT - Each query references table directly (standalone/independent):**
   ```kql
   // Query 1: Mail flow by direction
   EmailEvents
   | where Timestamp > ago(7d)
   | summarize count() by EmailDirection
   
   // Query 2: Threats summary (completely independent)
   EmailEvents
   | where Timestamp > ago(7d)
   | summarize count() by ThreatTypes
   ```
   
   **✅ CORRECT - Variables WITHIN a single complex query:**
   ```kql
   // Single unified query - variables work here
   let emailData = EmailEvents | where Timestamp > ago(7d);
   let threatEmails = emailData | where isnotempty(ThreatTypes);
   
   threatEmails
   | summarize 
       TotalThreats = count(),
       BlockedCount = countif(DeliveryAction == "Blocked")
       by ThreatTypes
   ```
   
   **Decision Matrix:**
   
   | User Request | Pattern to Use | Reason |
   |-------------|----------------|---------|
   | "Show me 5 different mail flow analyses" | ❌ NO variables, ✅ Each query starts with `EmailEvents` | User runs each independently |
   | "Analyze mail flow with multiple dimensions" | ❌ NO variables, ✅ Each query starts with `EmailEvents` | Separate questions = separate queries |
   | "Create a comprehensive mail flow report" | ✅ ONE query with variables | Single cohesive analysis |
   | "Build a complex threat hunting query" | ✅ ONE query with variables | Logical flow within single execution |
   
   **Golden Rule:** If you're generating multiple queries separated by blank lines/headers, ALWAYS start each with the table name directly. Variables are ONLY for internal use within a single query.

---

## Query Output Formats

### 1. Provide Query with Context

**Always include:**
```markdown
## Query Name: [Descriptive Title]

**Purpose:** [What this query does]

**Data Source:** [Table name]

**Time Range:** [Lookback period]

**Platform:** [Sentinel / Defender XDR]

**Expected Results:** [What you'll get]

```kql
// [Query with comments]
```

**Key Columns:**
- `ColumnName`: Description
- `ColumnName`: Description

**Notes:**
- Any caveats or limitations
- Performance considerations
- Customization suggestions
```

---

### 2. Provide Multiple Variations

**Example:**

```markdown
### Option 1: Summary Statistics
```kql
EmailEvents
| where TimeGenerated > ago(7d)
| summarize Count = count() by ThreatTypes
| order by Count desc
```

### Option 2: Detailed Records
```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where isnotempty(ThreatTypes)
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, ThreatTypes, Subject
| take 100
```

### Option 3: Time Series
```kql
EmailEvents
| where TimeGenerated > ago(7d)
| summarize Count = count() by bin(TimeGenerated, 1d), ThreatTypes
| render timechart
```
```

---

### 3. Include Execution Guidance

**Add instructions:**

```markdown
## How to Run This Query

### In Microsoft Sentinel:
1. Navigate to **Logs** blade
2. Paste query
3. Set time range in picker (if not using `ago()`)
4. Click **Run**

### In Defender XDR:
1. Go to **Advanced Hunting**
2. Paste query
3. Adjust `Timestamp` if needed
4. Click **Run query**

### Via MCP Server:
```
mcp_sentinel-data_query_lake(query: "<query>")
```

## Expected Output Format

[Describe what user will see in results]
```

---

## Error Handling

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `Failed to resolve column 'Timestamp'` | Wrong platform (Sentinel uses `TimeGenerated`) | Change to `TimeGenerated` |
| `Failed to resolve column 'TimeGenerated'` | Wrong platform (XDR uses `Timestamp`) | Change to `Timestamp` |
| `Table 'EmailEvents' not found` | Table not available in environment | Verify table exists with schema tool |
| `Syntax error near '='` | Used `=` instead of `==` | Use `==` or `=~` for comparisons |
| `argument #2 expected to be a string expression` | String function used on dynamic type (after `mv-expand` or `parse_json`) | Add `tostring()` before string operations |
| `'let' statement not recognized` | Using variables across separate query contexts | Reference table name directly in each query |
| Query timeout | Too much data, no time filter | Add `where TimeGenerated > ago(7d)` |
| Too many results | No `take` or `summarize` | Add `| take 100` or aggregate |

---

### Troubleshooting Workflow

**When query fails:**

1. **Check schema**
   ```
   mcp_kql-search_get_table_schema("<table>")
   ```

2. **Validate syntax**
   ```
   mcp_kql-search_validate_kql_query("<query>")
   ```

3. **Verify column names**
   - Look at schema output
   - Check example queries
   - Try `mcp_kql-search_find_column("<column>")`

4. **Check platform**
   - Ask user: Sentinel or XDR?
   - Adjust timestamp column accordingly

5. **Simplify query**
   - Remove complex logic
   - Test basic `| take 10` first
   - Add filters incrementally

---

## Example Workflow

**User asks:** "Write a KQL query to find phishing emails in the last 7 days"

### Step 1: Get Schema
```
mcp_kql-search_get_table_schema("EmailEvents")
```

**Result:** Table exists, has columns `ThreatTypes`, `TimeGenerated` (Sentinel), `RecipientEmailAddress`, etc.

### Step 2: Get Official Examples
```
mcp_microsoft-lea_microsoft_code_sample_search(
  query: "EmailEvents phishing ThreatTypes KQL",
  language: "kusto"
)
```

**Result:** Found pattern: `where ThreatTypes has "Phish"`

### Step 3: Get Community Examples
```
mcp_kql-search_search_github_examples_fallback(
  table_name: "EmailEvents",
  description: "phishing detection delivered"
)
```

**Result:** Found examples with additional filters like `DeliveryAction == "Delivered"`

### Step 4: Generate Query

```kql
// Hunt for phishing emails delivered in last 7 days
// Data source: EmailEvents (Microsoft Defender for Office 365)
// Platform: Microsoft Sentinel
// Time range: Last 7 days

EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| project 
    TimeGenerated,
    RecipientEmailAddress,
    SenderFromAddress,
    Subject,
    DeliveryLocation,
    DetectionMethods
| order by TimeGenerated desc
| take 100
```

### Step 5: Provide Context

**Purpose:** Find phishing emails that were successfully delivered to users in the last 7 days

**Platform:** Microsoft Sentinel (uses `TimeGenerated`)

**Expected Results:** Up to 100 phishing emails with recipient, sender, subject, and detection details

**Key Columns:**
- `TimeGenerated`: When email was processed
- `RecipientEmailAddress`: Who received the phishing email
- `SenderFromAddress`: Attacker's email address
- `DetectionMethods`: How the phishing was detected
- `DeliveryLocation`: Where email was delivered (Inbox, Junk, etc.)

**Customization:**
- Change `7d` to adjust time range
- Remove `DeliveryAction` filter to see blocked phishing too
- Add `| where RecipientEmailAddress has "domain.com"` to filter by domain

---

## Summary

**Core Workflow:**
1. ✅ Get schema → Validate table and columns
2. ✅ Get Microsoft Learn samples → Official patterns
3. ✅ Get community examples → Real-world validation
4. ✅ Generate query → Combine insights
5. ✅ Validate → Check syntax and schema
6. ✅ Provide context → Explain query to user

**Key Success Factors:**
- Always validate schema first
- Check platform-specific columns (`TimeGenerated` vs `Timestamp`)
- Combine multiple sources (schema + Learn + community)
- Include comments and context
- Add time filters and result limits
- Test before providing to user

**Remember:** The schema is the authoritative source for column names. Microsoft Learn provides official patterns. Community queries show real-world usage. Combine all three for best results.
