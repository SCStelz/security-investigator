# Microsoft Sentinel Data Lake — Query Cost Best Practices

**Why this matters:** Data Lake interactive queries are billed on **data scanned** (≈ $5/TB). A 3‑month query over large firewall logs that scans the full table can read tens of terabytes (e.g., 80 TB ≈ $400) even when only a few GB actually match. The goal is to make the engine **read less**, not just return less.

> **The cost model in one line:** billed scan ≈ **(width of the columns actually read) × (rows in the time‑pruned range)**. The engine uses columnar pushdown, so `count` and `summarize by <small column>` stay cheap even over months — the explosions come from **reading wide columns (raw payloads/JSON) across a wide range**, not from row count alone.

---

## ⭐ Rule #0 — Estimate before you run

Never launch a wide historical scan blind. The `Usage` table is tiny and free to query — preview how much you're about to scan first.

```kql
// ---- Data Lake scan-volume + cost estimator ----
// Set these three values:
let TableName = "AWSCloudTrail";          // table you intend to query
let StartDate = datetime(2026-03-01);     // inclusive
let EndDate   = datetime(2026-06-01);     // exclusive
let RatePerTB = 5.0;                       // your Data Lake $/TB scanned
// -------------------------------------------------
let Weekly = Usage
    | where TimeGenerated >= StartDate and TimeGenerated < EndDate
    | where DataType == TableName
    | summarize GB = sum(Quantity) / 1024.0
        by Period = format_datetime(startofweek(TimeGenerated), "yyyy-MM-dd");
Weekly
| union (Weekly | summarize GB = sum(GB) | extend Period = "TOTAL")
| extend GB = round(GB, 3)
| extend EstScannedTB = round(GB / 1024.0, 3)
| extend EstCostUSD   = round((GB / 1024.0) * RatePerTB, 2)
| order by Period asc
```

Output: a weekly ingest breakdown for the table plus a `TOTAL` row, with estimated TB scanned and $ cost for the date range.

> **Note:** `Usage.Quantity` is ingested/billed volume (MB) — an excellent ballpark for scan volume, but not a penny‑exact invoice match. `startofweek()` is Sunday‑based, so the first/last buckets may be partial weeks.

> ⚠️ **Retention prerequisite — extend `Usage` retention for long-range estimates.** `Usage` is a standard Analytics-tier table that defaults to the workspace interactive retention (typically 90 days). If your `StartDate` reaches further back than that, the estimator **silently under-reports** — you just get fewer weekly rows, with no error. To make the estimator work over arbitrary windows:
> - **Raise the `Usage` table's *total* (long-term) retention** to your longest reporting horizon — up to 12 years (4,383 days). You do **not** need to extend *interactive* retention; long-term retention is enough and far cheaper.
> - **The cost is negligible.** `Usage` is a tiny metering table (a few rows per `DataType` per day), so extending its retention adds essentially nothing to storage spend — unlike extending retention on a real telemetry table.
> - **Minor caveat:** once the query reaches *beyond* the interactive window, that portion is served from long-term retention (a search/Lake-tier read), so the estimator goes from strictly-free to a tiny billed scan. Because `Usage` is so small, it stays effectively free.
> - **Authoritative spend** over long windows still comes from **Azure Cost Management / billing export** (longer retention, source of truth). Use this estimator for *volume/trend projection*; reconcile actual dollars against Cost Management.

---

## The best practices (ordered by cost impact)

### 1. Don't return raw wide rows — `project` narrow columns or `summarize`
**This is the #1 cost driver.** A query that ends in a bare filter (or exports raw rows) materializes *every column*, including the fat firewall payload/message/JSON columns, for every matching row. Cut to the few columns you need **before** the end of the query, or aggregate.
```kql
// EXPENSIVE — reads every column, including wide payloads
FirewallLogs
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-06-01))
| where DeviceAction == "deny"

// CHEAP — reads only 5 narrow columns
FirewallLogs
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-06-01))
| where DeviceAction == "deny"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, RuleName
```
**Red flags:** no `project` and no `summarize`; `project *`; selecting the raw payload/JSON column across the full range.

### 2. Put the time filter FIRST — and make it `TimeGenerated`
Data Lake prunes by ingestion‑time partitions. If `TimeGenerated` isn't the very first `where`, pruning silently breaks and you scan the whole table.
```kql
FirewallLogs
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-06-01))   // FIRST
| where DeviceAction == "deny"
| ...
```
**Pruning killers:** `search *`, `union *`, or any `parse`/`extend`/`project`/`join` placed *before* the time filter. Also confirm the range bounds are intentional (a missing upper bound or `ago(90d)` typo silently widens the scan).

### 3. Parse / `extend` / `mv-expand` wide columns *after* the filter, never before
`parse_json` / `parse` / `extract` / `mv-expand` on a wide column **before** the row count is narrowed forces the engine to read that entire wide column for every row in range — this is the classic 80 TB pattern. Always filter rows down first, then parse.

### 4. Narrow the time range to what you actually need
Wide‑open ranges scan more rows. If you don't need all 3 months at once, **chunk it** (e.g., 4 × ~3 weeks) so you can stop early once you find what you need.

### 5. Add selective filters right after the time filter
Filter on the most selective columns next (action, port, source/dest IP, rule name) so the engine skips data blocks early.

### 6. Summarize for trends instead of exporting raw rows
If the goal is counts/patterns, `summarize` / `top` / `percentile` rather than returning millions of raw events. Aggregations are cheap — testing showed a 30‑day `summarize` scanned barely more than a 1‑day one despite 28× the rows.
```kql
FirewallLogs
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-06-01))
| where DeviceAction == "deny"
| summarize Hits = count() by DestinationPort, bin(TimeGenerated, 1d)
| top 20 by Hits
```

### 7. Avoid large‑to‑large joins over months
A `join` between two big lake tables over a wide range multiplies the columns read on both sides. Filter and `project` both sides first, or `lookup` against a small set.

### 8. Prefer `has` / `==` over `contains` / regex — for *speed*, not bytes
`contains`, `matches regex`, and `has_cs` on free text force full‑text matching. **Note:** in testing this did **not** reduce bytes‑scanned versus `has` (the column is read either way) — the win is CPU and latency, plus correctness. Fix it, but it is **not** the lever that causes a runaway *cost*; columns 1–3 are.

### 9. For recurring big‑history needs, use KQL Jobs — don't re‑scan interactively
Run the expensive scan **once** as a scheduled Data Lake job that writes a curated/summarized output (e.g., to the Analytics tier), then query that small result repeatedly. Aggregating noisy traffic (allows, health checks) at this stage cuts both scan and storage cost.

---

## Quick checklist before running any large Data Lake query

- [ ] Ran the **Usage estimator** and confirmed the projected TB/$ is acceptable
- [ ] Query **`summarize`s or `project`s to narrow columns** — no bare raw‑row output, no `project *`, no wide payload/JSON column pulled across the range
- [ ] `where TimeGenerated between(...)` is the **first** line; range bounds are intentional
- [ ] No `parse`/`parse_json`/`extend`/`mv-expand` on a wide column **before** the row filter
- [ ] Most selective filters come next; `has`/`==` used (no `contains`/regex)
- [ ] No large‑to‑large `join` over the full range
- [ ] Output is **aggregated** (or chunked) rather than a raw bulk export
- [ ] Recurring/historical workloads moved to a **KQL Job + curated output**

---

## Who is querying the Lake? (all sources, not just MCP)

To find **every** user/identity running Data Lake queries — and spot who is driving cost — query the Purview unified audit surfaced in `CloudAppEvents`. This captures **all** Lake query channels, not just the MCP server: the Portal Data Lake Explorer, scheduled jobs, Security Copilot, Workbooks, Jupyter, Power BI, and direct KQL.

```kql
// ---- All identities querying the Sentinel Data Lake (last 30d) ----
let lookback = 30d;
// Resolve UserId GUIDs -> UPNs (best-effort; portal/job service identities won't resolve)
let upnMap = SigninLogs
    | where TimeGenerated >= ago(lookback)
    | summarize arg_max(TimeGenerated, UserPrincipalName) by UserId
    | project UserId, UserPrincipalName;
CloudAppEvents
| where TimeGenerated >= ago(lookback)
| where ActionType contains "Sentinel" or ActionType contains "KQL"   // CamelCase: use contains, NOT has
| extend RawData = parse_json(tostring(RawEventData))
| extend
    Operation     = tostring(RawData.Operation),
    RecordType    = toint(RawData.RecordType),
    Interface     = tostring(RawData.Interface),
    FailureReason = tostring(RawData.FailureReason),
    ExecDuration  = todouble(RawData.ExecutionDuration),
    TablesRead    = tostring(RawData.TablesRead),
    UserId        = tostring(RawData.UserId)
| where Operation contains "Completed" or RecordType == 379
| extend QuerySource = case(
    RecordType == 403 and Interface == "IMcpToolTemplate",  "MCP (stdio)",
    RecordType == 403 and Interface == "HttpMcpToolTemplate","MCP (HTTP)",
    RecordType == 379 and (Interface == "InterfaceNotProvided" or isempty(Interface)), "MCP-Driven (Probable)",
    RecordType == 379 and Interface has "msglakeexplorer",  "Portal (Lake Explorer)",
    RecordType == 379 and Interface has "msgjobmanagement",  "Scheduled Jobs",
    RecordType == 379 and Interface has "Medeina",           "Security Copilot",
    RecordType == 379 and Interface has "workbook",          "Workbook/Dashboard",
    RecordType == 379, strcat("Direct KQL (", Interface, ")"),
    "Other")
| summarize
    LakeQueries    = count(),
    Failures       = countif(isnotempty(FailureReason)),
    AvgDurationSec = round(avg(ExecDuration), 2),
    MaxDurationSec = round(max(ExecDuration), 2),
    Sources        = make_set(QuerySource, 10),
    TopTables      = make_set(TablesRead, 25),
    LastSeen       = max(TimeGenerated)
    by UserId
| join kind=leftouter upnMap on UserId
| extend Account = coalesce(UserPrincipalName, UserId)
| project Account, LakeQueries, Failures, AvgDurationSec, MaxDurationSec, Sources, LastSeen
| order by LakeQueries desc
```

> ⚠️ **Coverage gaps in this query (found Nov 2026):** it filters `ActionType contains "Sentinel" or "KQL"`, so it **excludes KQL Job runs** (`JobRun*`), and its `Interface` map predates the `*ToolExecutorComponent` names — MCP-driven rows now surface as `Direct KQL (<display name>)`. For cost-spike triage use the **Cost-spike triage playbook** section below.

**Notes & pitfalls (field-verified):**
- **`contains`, not `has`** — Sentinel audit values (`SentinelAIToolRunCompleted`, `KQLQueryCompleted`) are CamelCase with no word boundaries, so `has "Completed"` returns **false** for all of them and silently drops MCP rows.
- **`RawEventData` is a JSON string** — wrap in `parse_json(tostring(...))` and parse **once**.
- **Query channels you'll see** (`Sources` column): `MCP (stdio)` / `MCP (HTTP)` = the Sentinel Data Lake MCP server; `MCP-Driven (Probable)` = RecordType 379 with `InterfaceNotProvided` (MCP queries the audit pipeline didn't tag as 403); `Portal (Lake Explorer)` = `msglakeexplorer@msec-msg`; `Scheduled Jobs` = `msgjobmanagement@msec-msg`; plus Security Copilot, Workbooks, Jupyter (`ipykernel_launcher.py`), Power BI (`PowerBIConnector`).
- **UPN resolution is best-effort** — interactive users resolve via `SigninLogs`; service/portal identities (jobs, dashboards) keep their GUID/interface name in `Account`.
- **Want a per-source rollup instead of per-user?** Swap the `summarize ... by UserId` to `by QuerySource` for a channel-level breakdown, or add `bin(TimeGenerated, 1d)` for a daily trend.
- **Cost caveat:** this shows **who runs queries and how often/how long** — it is *activity*, not billed scan. `AvgDurationSec`/`MaxDurationSec` is the best in-table proxy for "expensive" queries; pair the heavy users with the Azure cost meter for the authoritative spend.

---

## Want the actual query text too?

The same `CloudAppEvents` records carry the **full KQL body**, so you can see exactly *what* each user ran — invaluable for spotting the expensive anti-patterns (`search *`, `union withsource=* *`, wide-column scans) and coaching the people running them.

The query text lives in different fields depending on the channel:
- **Direct KQL (RecordType 379)** — `RawEventData.QueryText` holds the raw KQL (Portal Lake Explorer, Scheduled Jobs, Security Copilot, and probable-MCP all populate it).
- **MCP tool calls (RecordType 403)** — the tool argument is in `RawEventData.InputParameters` as `{"query": "..."}`. For `query_lake` this is the KQL; for other tools it's that tool's input.

```kql
// ---- Actual KQL text per Lake query, heaviest first (last 7d) ----
let lookback = 7d;
let upnMap = SigninLogs
    | where TimeGenerated >= ago(30d)
    | summarize arg_max(TimeGenerated, UserPrincipalName) by UserId
    | project UserId, UserPrincipalName;
CloudAppEvents
| where TimeGenerated >= ago(lookback)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| extend
    Operation      = tostring(RawData.Operation),
    RecordType     = toint(RawData.RecordType),
    Interface      = tostring(RawData.Interface),
    ToolName       = tostring(RawData.ToolName),
    FailureReason  = tostring(RawData.FailureReason),
    ExecDurationMs = todouble(RawData.ExecutionDuration),
    TablesRead     = tostring(RawData.TablesRead),
    UserId         = tostring(RawData.UserId),
    QueryText      = tostring(RawData.QueryText),
    InputParams    = tostring(RawData.InputParameters)
| where Operation contains "Completed" or RecordType == 379
| extend QuerySource = case(
    RecordType == 403 and Interface == "IMcpToolTemplate",  "MCP (stdio)",
    RecordType == 403 and Interface == "HttpMcpToolTemplate","MCP (HTTP)",
    RecordType == 379 and (Interface == "InterfaceNotProvided" or isempty(Interface)), "MCP-Driven (Probable)",
    RecordType == 379 and Interface has "msglakeexplorer",  "Portal (Lake Explorer)",
    RecordType == 379 and Interface has "msgjobmanagement",  "Scheduled Jobs",
    RecordType == 379 and Interface has "Medeina",           "Security Copilot",
    RecordType == 379 and Interface has "workbook",          "Workbook/Dashboard",
    RecordType == 379, strcat("Direct KQL (", Interface, ")"),
    "Other")
// 379 -> QueryText; 403 -> InputParameters.query (the tool argument)
| extend QueryContent = iff(RecordType == 379, QueryText, tostring(parse_json(InputParams).query))
| where isnotempty(QueryContent)
| join kind=leftouter upnMap on UserId
| extend Account = coalesce(UserPrincipalName, ToolName, UserId)  // ToolName fills in for unresolved MCP identities
| project TimeGenerated, Account, QuerySource, ExecDurationMs, Tables = TablesRead,
    Failed = isnotempty(FailureReason),
    QueryContent = substring(QueryContent, 0, 500)   // trim; remove to see full text
| order by ExecDurationMs desc
| take 50
```

**Notes:**
- **Anti-pattern hunting:** sort by `ExecDurationMs` (it's **milliseconds**, despite some UIs labeling seconds) and scan the `QueryContent` for the runaway shapes from this guide — `search *`, `union withsource=* *`, no leading `TimeGenerated` filter, or a wide payload column pulled across a long range. In practice these dominate the top of the list.
- **`QueryContent` is trimmed to 500 chars** with `substring()` to keep the result readable — drop that line to capture the full query body (some are 2,000+ chars).
- **Privacy note:** query bodies can embed indicators an analyst was hunting (domains, IPs, UPNs). Treat this output as sensitive and restrict who can run it.
- **Per-user rollup of distinct queries:** swap the tail for `| summarize Queries = dcount(QueryContent), Samples = make_set(substring(QueryContent,0,200), 10), MaxDurationMs = max(ExecDurationMs) by Account | order by MaxDurationMs desc`.

---

## Cost-spike triage playbook — "Data lake query" meter jumped, who/what is driving it?

**Use when:** the *Data lake query* meter spikes while other lake meters (ingestion, storage, retention) stay flat. That meter is driven by **queries and jobs that scan lake data** — so the question is *which channel, which identity, which job, which repeated query*.

> **Validated Nov 2026 on a lab tenant.** All queries below are `RunAdvancedHuntingQuery` form (free, 30d max, `Timestamp`). For a window **> 30 days** (e.g. October baseline vs November), run the same query via the Data Lake with `Timestamp` → `TimeGenerated` (keep the `ActionType` filter first; counts/summaries are cheap).

### Audit-schema facts that change how you count (read first)

| Fact | Why it matters |
|---|---|
| **KQL Jobs are NOT `KQLQueryCompleted`.** They log as `JobRunScheduledCompleted` / `JobRunAdhocCompleted` (RecordType 377) with `JobName`, `JobType` (`KQL`, `GraphNotebook`, `WriteToLake`), `JobRunStatus`, `JobExecutionDurationInSecs`, and `Schedule` (JSON with `Recurrence.Frequency/Interval`). | The "Who is querying" filter above (`ActionType contains "Sentinel" or "KQL"`) **misses jobs entirely**. A job on a short cadence can out-run every human combined. |
| **Job query text and tables are not audited** for KQL jobs (only name/schedule/duration). | To see *what a KQL job scans*, open it in Defender portal → Microsoft Sentinel → Data lake exploration → **Jobs**. |
| **MCP calls produce two records**: a 403 `SentinelAIToolRunCompleted` (carries the caller **UPN**, `ToolName`) **and** a 379 `KQLQueryCompleted` whose `Interface` is the caller's **display name** and `UserId = "UserIdNotProvided"` (carries `TotalCPU`, `TablesRead`, `QueryText`). Row counts match 1:1 per caller. | Never add 403 + 379 together — you'll double count MCP. Count **379 + job events** for volume; use **403 only for identity (UPN) and tool name**. |
| **403 is not only Data Lake.** It also logs Advanced Hunting / Defender tools (`RunAdvancedHuntingQuery`, `GetAlertById`, …) incl. Security Copilot agent identities. | Filter `ToolName in ("query_lake","search_tables","list_sentinel_workspaces")` for lake activity. |
| **Interface names drifted**: older `IMcpToolTemplate` / `HttpMcpToolTemplate` are now `IMcpToolExecutorComponent` / `HttpMcpToolExecutorComponent`. | Hard-coded interface `case()` maps silently fall through to "Direct KQL (<name>)". |
| `DataScanned` is **0** on every record observed; `TotalCPU` (ms, 379 only), `ExecutionDuration` (ms) and job `JobExecutionDurationInSecs` are the best in-audit cost proxies. | Billed GB is **not** in the audit log. Reconcile dollars in Cost Management; use these to **rank**, not to price. |
| Failed queries are still logged (and frequently retried). | A looping/failing automation shows up as a high `Failed` count on one fingerprint (Query 7). |

### Query 1 — Rollup by channel (is it jobs, MCP, portal, workbooks?)

```kql
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType in ("KQLQueryCompleted", "JobRunScheduledCompleted", "JobRunAdhocCompleted")
| extend R = parse_json(tostring(RawEventData))
| extend Interface = tostring(R.Interface), JobType = tostring(R.JobType)
| extend Source = case(
    ActionType startswith "JobRun", strcat("Job: ", JobType),
    Interface has "msglakeexplorer", "Portal: Lake Explorer",
    Interface has "msgjobmanagement", "Portal: Jobs page",
    Interface has "workbook", "Workbook",
    Interface has "Medeina", "Security Copilot",
    Interface has_any ("ipykernel", "PowerBI"), "Notebook/Power BI",
    Interface in ("InterfaceNotProvided", ""), "Unattributed",
    "MCP-driven (display-name interface)")
| summarize Executions = count(), Last7d = countif(Timestamp >= ago(7d)),
    Failed = countif(isnotempty(tostring(R.FailureReason)) or tostring(R.JobRunStatus) in ("Failed", "Error")),
    CpuMin = round(sum(todouble(R.TotalCPU)) / 60000.0, 1),
    JobRuntimeHrs = round(sum(todouble(R.JobExecutionDurationInSecs)) / 3600.0, 1)
    by Source
| order by Executions desc
```

### Query 2 — Daily trend by channel (find the day the spike starts)

```kql
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType in ("KQLQueryCompleted", "JobRunScheduledCompleted", "JobRunAdhocCompleted")
| extend R = parse_json(tostring(RawEventData))
| extend Interface = tostring(R.Interface)
| extend Source = case(
    ActionType startswith "JobRun", "Job",
    Interface has "msglakeexplorer" or Interface has "msgjobmanagement", "Portal",
    Interface has "workbook", "Workbook",
    Interface has "Medeina", "SecCopilot",
    "MCP/Other")
| summarize Total = count(), Jobs = countif(Source == "Job"), Portal = countif(Source == "Portal"),
    Workbook = countif(Source == "Workbook"), SecCopilot = countif(Source == "SecCopilot"), McpOther = countif(Source == "MCP/Other"),
    JobRuntimeHrs = round(sumif(todouble(R.JobExecutionDurationInSecs), Source == "Job") / 3600.0, 1),
    InteractiveCpuMin = round(sumif(todouble(R.TotalCPU), Source != "Job") / 60000.0, 1),
    FailedQueries = countif(Source != "Job" and isnotempty(tostring(R.FailureReason)))
    by Day = bin(Timestamp, 1d)
| order by Day asc
```

**Data Lake variant for > 30d (weekly, cheap — reads no wide columns):**

```kql
CloudAppEvents
| where TimeGenerated >= datetime(2026-10-01) and TimeGenerated < datetime(2026-11-24)
| where ActionType in ("KQLQueryCompleted", "JobRunScheduledCompleted", "JobRunAdhocCompleted")
| summarize Executions = count() by Week = startofweek(TimeGenerated), ActionType
| order by Week asc, ActionType asc
```

### Query 3 — KQL job inventory (the "must be a KQL job" suspect list)

Per job: cadence, runs/day this week vs prior, runtime, failures. A cadence change (e.g., daily → hourly/by-minute) or a new job shows up as `RunsPerDay_Last7d` ≫ `RunsPerDay_Prev`. Runtime hours is the compute-weight proxy.

```kql
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType in ("JobRunScheduledCompleted", "JobRunAdhocCompleted")
| extend R = parse_json(tostring(RawEventData))
| extend JobName = tostring(R.JobName), JobType = tostring(R.JobType), Status = tostring(R.JobRunStatus),
    DurSecs = todouble(R.JobExecutionDurationInSecs), Sched = parse_json(tostring(R.Schedule)),
    RunKind = iff(ActionType == "JobRunScheduledCompleted", "Scheduled", "AdHoc")
| extend Cadence = strcat(tostring(Sched.Recurrence.Interval), " ", tostring(Sched.Recurrence.Frequency))
| summarize Runs = count(), Last7d = countif(Timestamp >= ago(7d)), Prev23d = countif(Timestamp < ago(7d)),
    Failed = countif(Status != "Succeeded"), TotalRuntimeHrs = round(sum(DurSecs) / 3600.0, 1),
    AvgDurSecs = round(avg(DurSecs), 0), MaxDurSecs = max(DurSecs),
    Cadences = make_set(Cadence, 3), RunKinds = make_set(RunKind, 2), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by JobName, JobType
| extend RunsPerDay_Last7d = round(Last7d / 7.0, 1), RunsPerDay_Prev = round(Prev23d / 23.0, 1)
| order by TotalRuntimeHrs desc
```

### Query 4 — Job lifecycle changes (who created / edited / re-enabled / hand-ran a job)

```kql
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType in ("JobCreated", "JobUpdated", "JobEnabled", "JobDisabled", "JobDeleted", "JobRunAdhoc", "JobRunStopped")
| extend R = parse_json(tostring(RawEventData))
| project Timestamp, ActionType, JobName = tostring(R.JobName), JobType = tostring(R.JobType),
    ChangedBy = tostring(R.UserId), Interface = tostring(R.Interface)
| order by Timestamp desc
```

> Beware: **editing a one-time job immediately re-executes it**, and a scheduled job's `LastModifiedAt` (inside `Schedule`) changes on every run — so use this query, not `LastModifiedAt`, to find real edits.

### Query 5 — MCP callers by UPN (Data Lake MCP tools only)

```kql
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType == "SentinelAIToolRunCompleted"
| extend R = parse_json(tostring(RawEventData))
| extend ToolName = tostring(R.ToolName)
| where ToolName in ("query_lake", "search_tables", "list_sentinel_workspaces")
| summarize Calls = count(), Last7d = countif(Timestamp >= ago(7d)), Failed = countif(isnotempty(tostring(R.FailureReason))),
    ExecMin = round(sum(todouble(R.ExecutionDuration)) / 60000.0, 1), MaxExecSec = round(max(todouble(R.ExecutionDuration)) / 1000.0, 0),
    Tools = make_set(ToolName, 3), ActiveDays = dcount(bin(Timestamp, 1d)), LastSeen = max(Timestamp)
    by Caller = tostring(R.UserId)
| top 25 by Calls desc
```

### Query 6 — Portal / workbook callers by UPN (engine-side, with CPU)

```kql
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType == "KQLQueryCompleted"
| extend R = parse_json(tostring(RawEventData))
| extend Caller = tostring(R.UserId), Interface = tostring(R.Interface)
| where Caller !in ("UserIdNotProvided", "Unknown", "")   // those rows are the MCP duplicates (see facts table)
| summarize Queries = count(), Last7d = countif(Timestamp >= ago(7d)), Failed = countif(isnotempty(tostring(R.FailureReason))),
    CpuMin = round(sum(todouble(R.TotalCPU)) / 60000.0, 1), MaxExecSec = round(max(todouble(R.ExecutionDuration)) / 1000.0, 0),
    Interfaces = make_set(Interface, 4), ActiveDays = dcount(bin(Timestamp, 1d))
    by Caller
| top 25 by CpuMin desc
```

### Query 7 — Repeated/looping queries (automation or a retry storm)

Normalizes literals/datetimes so the same query with a sliding window groups together. Many runs from many callers with a high `FailedRuns` is a script/agent retry loop.

```kql
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType == "KQLQueryCompleted"
| extend R = parse_json(tostring(RawEventData))
| extend Interface = tostring(R.Interface), UserId = tostring(R.UserId), QueryText = tostring(R.QueryText)
| where isnotempty(QueryText)
| extend Caller = iff(UserId in ("UserIdNotProvided", "Unknown", ""), Interface, UserId)
| extend Fingerprint = hash(replace_regex(replace_regex(QueryText, @"datetime\([^)]*\)", "datetime(?)"), @"\b\d+\b", "N"))
| summarize Runs = count(), Last7d = countif(Timestamp >= ago(7d)), Callers = dcount(Caller), ActiveDays = dcount(bin(Timestamp, 1d)),
    CpuMin = round(sum(todouble(R.TotalCPU)) / 60000.0, 1), AvgExecSec = round(avg(todouble(R.ExecutionDuration)) / 1000.0, 1),
    FailedRuns = countif(isnotempty(tostring(R.FailureReason))), Sample = take_any(substring(QueryText, 0, 140))
    by Fingerprint
| where Runs >= 5
| top 20 by Runs desc
```

> Do **not** add `TablesRead` to this output — for MCP-driven rows it can list hundreds of tables and bloats results.

### Query 8 — Which tables are being hit, weighted by table size (MCP `query_lake`)

`LakeQueries × IngestGB30d` is a **ranking weight, not dollars** — it surfaces large tables (sign-in, Graph activity, firewall) that are queried often. The inner join to `Usage` also discards the stray column names that appear in `TablesRead`.

```kql
let tableSize = Usage
    | where TimeGenerated >= ago(30d)
    | summarize IngestGB30d = round(sum(Quantity) / 1024.0, 1) by Table = DataType;
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType == "SentinelAIToolRunCompleted"
| extend R = parse_json(tostring(RawEventData))
| where tostring(R.ToolName) == "query_lake"
| mv-expand Table = R.TablesRead
| extend Table = tostring(Table)
| summarize LakeQueries = count(), Last7d = countif(Timestamp >= ago(7d)), Callers = dcount(tostring(R.UserId)),
    AvgExecSec = round(avg(todouble(R.ExecutionDuration)) / 1000.0, 1) by Table
| join kind=inner tableSize on Table
| extend ScanWeight = round(LakeQueries * IngestGB30d, 0)
| top 15 by ScanWeight desc
```

### How to read the results

1. **Query 1/2** — which channel's count (or job runtime) steps up when the bill does? If `Job:*` is flat but cost jumped, jobs are not the *count* driver — look at what a job scans (below).
2. **Query 3/4** — a new job, a cadence change (daily → hourly), or a re-enabled job near the spike date. Compare `RunsPerDay_Last7d` vs `RunsPerDay_Prev`. Jobs that **fail every run** (`Failed == Runs`) still consume schedule/compute — fix or disable.
3. **Query 5/6** — heaviest identities; a single caller with high `MaxExecSec`/`CpuMin` is a wide-scan suspect.
4. **Query 7** — identical queries repeated across days/callers (agents, workbooks refreshing, retry loops).
5. **Query 8 + the job's own definition (portal)** — a job's *scan size* = rows in the table × its lookback window. Daily jobs with a `ago(90d)`/`ago(180d)` lookback over a large table are the classic culprit — apply [best practices 1–3, 9](#the-best-practices-ordered-by-cost-impact) and use Rule #0 to estimate before changing anything.
6. **Reconcile** against the Azure cost meter for the spike dates; the audit log ranks activity, it does not bill it.

---

## Appendix — Reading per‑query scan stats (and their limits)

Each Data Lake query result carries a `QueryResourceConsumption` block you can inspect to understand a query's footprint:

| Field | Meaning |
|---|---|
| `input_dataset_statistics.extents.scanned` | data shards (extents) read |
| `input_dataset_statistics.rows.scanned` | rows read |
| `external_data.downloaded_bytes` / `downloaded_items` | lake (parquet) artifacts + bytes pulled |
| `resource_usage.cpu.total cpu`, `memory.peak_per_node`, `ExecutionTime` | compute cost |

**Important caveats (validated by testing on `AWSCloudTrail`):**
- These stats reflect the **query engine's orchestration over the columnar store**, heavily optimized by pushdown. `downloaded_bytes` did **not** scale with rows (28× rows → 1.46× bytes) and did **not** change between `contains` and `has`.
- Therefore **do not treat `downloaded_bytes` as the billed‑scan meter** — it under‑represents and doesn't track row‑level filters.
- Use the **`Usage`‑table estimator (Rule #0)** for the cost ballpark, and confirm the authoritative billed figure in **Azure cost meters**, not from this block.

---

**Reference:** [Query Microsoft Sentinel Data Lake (Microsoft Learn)](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-overview) · [Query considerations & limitations](https://learn.microsoft.com/azure/sentinel/datalake/kql-queries)
