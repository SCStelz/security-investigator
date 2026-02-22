# Sentinel Ingestion Report — Drill-Down & Reference (v2)

> **Just-in-time loading:** This file contains post-report drill-down patterns, known pitfalls, error handling, and appendix material. Load this file ONLY when:
> - User asks a follow-up question after report generation (drill-down patterns)
> - Debugging a query failure or scratchpad issue (error handling / known pitfalls)
> - **Do NOT load during data gathering or rendering** — all generation-time guidance is in SKILL.md and SKILL-report.md

---

## Post-Report Drill-Down Playbook

These are **ad-hoc investigation patterns** for post-report follow-up questions. During report generation, value-level verification is handled automatically by Invoke-IngestionScan.ps1 — these patterns are NOT needed during generation.

**Triggered by user follow-up questions like:**
- "Do any rules actually use EventID 8002?"
- "Which rules reference Syslog?"
- "What detections depend on Palo Alto traffic logs?"

> **🔴 MANDATORY: Always re-fetch from the Sentinel REST API for drill-down queries.** Do NOT reuse the cached `$rules` PowerShell variable from a previous Invoke-IngestionScan.ps1 session. The REST API call with JMESPath `contains()` is the **only reliable method** for searching rule query content. Reasons:
> 1. The `$rules` variable may have a different object shape than expected (e.g., `.query` vs `.properties.query` depending on the JMESPath projection)
> 2. PowerShell `-match` regex and JMESPath `contains()` have different matching semantics — `contains()` does literal substring matching which is more reliable for quoted values like `'8002'` inside KQL strings
> 3. The variable may be stale if rules were modified after the report was generated
> 4. The variable is not available outside the script's session

### Technique: Cross-Reference Analytic Rule Queries Against Specific Values

The Sentinel REST API returns the full KQL query text for every analytic rule. Since the API doesn't support server-side filtering on query content, pull all rules in one call and filter client-side using JMESPath `contains()`.

**Base API endpoint:**
```
GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-09-01
```

Read `config.json` for `subscription_id`, `azure_mcp.resource_group`, and `azure_mcp.workspace_name`.

**Step 0: Construct the URL (run once per session, then reuse `$arUrl` in all patterns)**

```powershell
# Read config values — run this FIRST, then all Pattern 1-5 commands use $arUrl
$cfg = Get-Content config.json | ConvertFrom-Json
$sub = $cfg.subscription_id
$rg  = $cfg.azure_mcp.resource_group
$ws  = $cfg.azure_mcp.workspace_name
$arUrl = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-09-01"

# Verify it works (should return rule count)
$test = az rest --method get --url $arUrl --query "length(value)" -o tsv 2>$null
Write-Host "Analytic rules found: $test"
```

> All patterns below assume `$arUrl` is set. If you see "Please login" or 0 results, re-run `az login` and verify `config.json` values.

### Pattern 1: Which rules reference a specific EventID?

When Section 3a flags a high-volume EventID (e.g., 8002 NTLM, 4688 Process Creation, 4624 Logon), check whether any detection actually uses it:

```powershell
# Replace '<EventID>' with the target EventID (assumes $arUrl set in Step 0)
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, '<EventID>')].{name: properties.displayName, severity: properties.severity, enabled: properties.enabled}" `
  -o table 2>`$null
```

**Interpret results:**
- **0 matches** → No rule uses this EventID. Options (in order of data preservation):
  1. **Split ingestion** — route this EventID to Data Lake tier via DCR filter. Events are retained for ad-hoc hunting and compliance but don't consume Analytics tier costs. Best when the EventID has legitimate forensic/hunting value (e.g., 4624 Logon, 4688 Process Creation) but no active detections.
  2. **DCR drop filter** — discard the EventID at ingestion. Maximum savings, zero retention. Best for truly noisy EventIDs with no hunting value (e.g., 4663 excessive file audits with overly broad SACLs).
  3. **Audit policy scoping** — reduce volume at the source by tightening Windows audit policy or SACL scope.
- **1+ matches** → Check the actual query context. A TI hash-matching rule that scans ALL events is different from a dedicated NTLM lateral movement detection. Read the query body to understand if the EventID is genuinely targeted or just swept up.

**Verify rule query context (when matches are found):**
```powershell
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, '<EventID>')].properties.query" `
  -o tsv 2>`$null | Select-String -Pattern '<EventID>' -Context 1,1
```

### Pattern 2: Which rules reference a Syslog facility, source, or process?

When Section 3b flags a high-volume Syslog facility (e.g., `authpriv`, `daemon`, `kern`), source device, or process:

```powershell
# Search for rules referencing a Syslog facility (assumes $arUrl set in Step 0)
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, 'authpriv')].{name: properties.displayName, severity: properties.severity, enabled: properties.enabled}" `
  -o table 2>`$null
```

```powershell
# Search for rules referencing a specific ProcessName (e.g., sshd)
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, 'sshd')].{name: properties.displayName, severity: properties.severity, enabled: properties.enabled}" `
  -o table 2>`$null
```

Also search for the source table itself — if no rules reference `Syslog` at all, the entire table is a Data Lake candidate:
```powershell
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, 'Syslog')].{name: properties.displayName, severity: properties.severity, enabled: properties.enabled}" `
  -o table 2>`$null
```

**ProcessName drill-down guidance:** When the report identifies high-volume processes within `daemon` facility (e.g., `systemd` at 40% of volume), search for rules that reference that ProcessName. If zero rules target it, the process is a strong DCR filter or split-ingestion candidate. Cross-reference with the ASIM `_Im_Authentication` parser which consumes Syslog `sshd`/`su`/`sudo` events — these must remain in Analytics tier even if no direct rules exist.

### Pattern 3: Which rules reference a CommonSecurityLog vendor/product or activity?

When Section 3c flags high-volume CEF appliance traffic (e.g., Palo Alto `TRAFFIC` events, Zscaler `Allowed` actions):

```powershell
# Search by DeviceVendor (e.g., Palo Alto Networks) — assumes $arUrl set in Step 0
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, 'Palo Alto')].{name: properties.displayName, severity: properties.severity, enabled: properties.enabled}" `
  -o table 2>`$null

# Search by Activity type (e.g., TRAFFIC)
az rest --method get --url $arUrl `
  --query "value[?properties.query && contains(properties.query, 'TRAFFIC')].{name: properties.displayName, severity: properties.severity, enabled: properties.enabled}" `
  -o table 2>`$null
```

### Pattern 4: Full rule query dump for manual analysis

If the user wants to audit all rule queries at once (e.g., to build a comprehensive EventID dependency map):

```powershell
# Export all enabled rule names and queries (assumes $arUrl set in Step 0)
az rest --method get --url $arUrl `
  --query "value[?properties.enabled==``true`` && properties.query].{name: properties.displayName, query: properties.query}" `
  -o json > temp/analytic_rule_queries.json
```

Then search locally:
```powershell
# Find all EventIDs referenced across all rules
Get-Content temp/analytic_rule_queries.json | Select-String -Pattern 'EventID\s*(==|in\s*\(|has|contains)' -AllMatches
```

### Pattern 5: ASIM Parser Table Dependency Verification

When Section 7a shows a 🔴 migration candidate with an ⚠️ ASIM dependency callout, or when the user asks "do any ASIM parsers use this table?", verify the dependency:

**Step 1: Identify which ASIM schemas are used by enabled rules**

Check `PHASE_4.ASIM` in the scratchpad first. If it shows ASIM patterns, use the rule names listed there. For deeper investigation:

```powershell
# Fetch all enabled rules and filter for ASIM function calls (assumes $arUrl set in Step 0)
$rules = az rest --method get --url $arUrl `
  --query "value[?properties.enabled==``true`` && properties.query].{displayName: properties.displayName, query: properties.query}" `
  -o json 2>$null | ConvertFrom-Json

$asimRules = $rules | Where-Object { $_.query -match '_Im_|_ASim_' }
$asimRules | ForEach-Object {
    $schemas = [regex]::Matches($_.query, '_Im_(\w+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    Write-Host "$($_.displayName): $($schemas -join ', ')"
}
```

**Step 2: Map detected ASIM schemas to source tables**

Focus on the three high-volume tables that are common migration candidates:

| Table | ASIM Schemas That Consume It | Key Parsers |
|-------|-----------------------------|-------------|
| **SecurityEvent** | Authentication (4624/4625), Process (4688/4689), File (4663), Audit (1102), Registry (4657/4663), Network Session (Firewall), User Management | 7+ ASIM parsers — nearly all schemas have a SecurityEvent/WindowsEvent source |
| **Syslog** | Authentication (sshd/su/sudo), DNS (BIND/Infoblox), Network Session (Fortinet/Meraki/WatchGuard), Web Session (Squid/Fortinet), User Management (authpriv) | Common for Linux-origin and network appliance-origin data |
| **CommonSecurityLog** | Authentication (Cisco ASA), Network Session (Palo Alto/Checkpoint/Cisco ASA/Zscaler/Barracuda/ForcePoint), Web Session (Palo Alto/Barracuda/Zscaler/F5), Audit Event (Barracuda) | The primary CEF ingestion table — heavily used by firewall/network ASIM parsers |

**Example drill-down conversation:**
> User: "Section 7a has an ASIM dependency warning on CommonSecurityLog. Which ASIM rules actually use it?"
>
> Agent: Runs Pattern 5 steps → finds 3 rules using `_Im_NetworkSession()` → Palo Alto CEF parser consumes CommonSecurityLog → confirms dependency → advises keeping on Analytics tier or using split ingestion (threat events → Analytics, TRAFFIC → Data Lake via DCR)

Source: [ASIM parsers list](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list)

### Pattern 6: Custom Detection Rule Inventory via Graph API

When the user asks to review Custom Detection (CD) rules — query text, schedules, last run status, or to cross-reference CD rules against specific tables/EventIDs.

> ⚠️ **Graph MCP limitation:** The Graph MCP server returns **403 Forbidden** for the CD endpoint because `CustomDetection.Read.All` is not in its available scopes. **Always use PowerShell `Invoke-MgGraphRequest`** via the terminal instead.

**Prerequisites:**
- `Microsoft.Graph.Authentication` module installed (`Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`)
- Interactive consent for `CustomDetection.Read.All` scope (one-time)

**Step 1: Fetch all Custom Detection rules**

```powershell
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Connect with required scope (skips if already connected with scope)
$ctx = Get-MgContext
if (-not $ctx -or $ctx.Scopes -notcontains 'CustomDetection.Read.All') {
    Connect-MgGraph -Scopes 'CustomDetection.Read.All' -NoWelcome
}

# Fetch rules — endpoint and $select from Q9b-CustomDetectionRules.yaml
$response = Invoke-MgGraphRequest -Method GET `
    -Uri '/beta/security/rules/detectionRules?$select=id,displayName,isEnabled,queryCondition,schedule,detectionAction,lastRunDetails,createdDateTime,lastModifiedDateTime' `
    -OutputType PSObject

# Display summary
$response.value | ForEach-Object {
    [PSCustomObject]@{
        Name       = $_.displayName
        Enabled    = $_.isEnabled
        Query      = $_.queryCondition.queryText
        Frequency  = $_.schedule.period
        LastRun    = $_.lastRunDetails.lastRunDateTime
        LastStatus = $_.lastRunDetails.status
        Created    = $_.createdDateTime
        Modified   = $_.lastModifiedDateTime
    }
} | Format-List
```

**Step 2: Cross-reference CD rules against a specific table or value**

After fetching, filter the results in PowerShell:

```powershell
# Which CD rules reference SecurityEvent?
$response.value | Where-Object { $_.queryCondition.queryText -match 'SecurityEvent' } |
    Select-Object displayName, isEnabled, @{N='Query';E={$_.queryCondition.queryText}}

# Which CD rules reference a specific EventID?
$response.value | Where-Object { $_.queryCondition.queryText -match '4688|ProcessCreate' } |
    Select-Object displayName, isEnabled, @{N='Query';E={$_.queryCondition.queryText}}
```

**Step 3: Identify stale or retirement candidates**

```powershell
# Rules that haven't run in the last 90 days
$cutoff = (Get-Date).AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
$response.value | Where-Object {
    $_.lastRunDetails.lastRunDateTime -and $_.lastRunDetails.lastRunDateTime -lt $cutoff
} | Select-Object displayName, isEnabled,
    @{N='LastRun';E={$_.lastRunDetails.lastRunDateTime}},
    @{N='Status';E={$_.lastRunDetails.status}}
```

**Interpret results:**
- **Enabled + completing regularly** → Active detection. Note frequency and last run for health check
- **Enabled + last run months ago** → Stale. Rule may have been superseded or schedule broken. Flag as retirement candidate
- **Disabled** → Intentionally turned off. Flag for cleanup if disabled >6 months
- **Last status = "failed"** → Investigate query errors. Common cause: table schema changes or renamed columns

**Key fields from the API response:**

| Field Path | Content |
|------------|---------|
| `displayName` | Rule name |
| `isEnabled` | `true`/`false` |
| `queryCondition.queryText` | Full KQL query (Advanced Hunting syntax) |
| `schedule.period` | Frequency: `PT1H` (hourly), `PT24H` (daily), `PT0S` (continuous) |
| `lastRunDetails.lastRunDateTime` | Last execution timestamp |
| `lastRunDetails.status` | `completed`, `failed`, `running` |
| `detectionAction` | Alert/entity mapping configuration |
| `createdDateTime` / `lastModifiedDateTime` | Lifecycle timestamps |

**Reference:** See [Q9b-CustomDetectionRules.yaml](queries/phase3/Q9b-CustomDetectionRules.yaml) for the canonical endpoint and `$select` fields. See also the [CloudAppEvents Appendix](#appendix-custom-detection-audit-trail-via-cloudappevents) below for CD *management* audit trail (edit events).

### When to Suggest These Drill-Downs

**During report generation:** Value-level verification is handled automatically by Invoke-IngestionScan.ps1. No manual drill-down patterns are needed during rendering.

**Post-report (ad-hoc, on user request):** In the report's Section 3 deep dives (3a, 3b, 3c) and Section 7 optimization recommendations, when flagging high-volume items with optimization recommendations (e.g., "🔴 High — consider DCR filter"), add a note:

> 💡 **Drill-down available:** Ask "query live — which rules use EventID 8002?" to verify detection dependencies before filtering or migrating. Follow Pattern 1 from this Drill-Down Playbook.

This gives the reader a clear path from report finding → actionable investigation → informed decision.

---

## YAML Query Library — Ad-Hoc Drill-Down Reference

The YAML files in `queries/` are the **single source of truth** for all KQL queries used by `Invoke-IngestionScan.ps1`. For drill-downs, **read the YAML file directly** — do NOT duplicate queries into this file.

### How to Use

1. **Read the YAML:** `read_file` the query path (paths are relative to this skill folder, e.g., `queries/phase4/Q11-RuleHealthSummary.yaml`)
2. **Extract the `query:` field** — this is the exact KQL the PS1 runs
3. **Adapt as needed:** Change timespan, add/modify filters (e.g., restrict to a specific `DataType`, `Computer`, `EventID`, or date range)
4. **Execute:** Use Advanced Hunting (≤30d, free) or Data Lake (>30d) per the Tool Selection Rule in copilot-instructions.md

> **Non-KQL queries:** Some YAMLs have `type: rest` (Q9), `type: cli` (Q10), or `type: graph` (Q9b). These don't have a `query:` field — they have `url:`, `command:`, or `endpoint:` respectively. Use the appropriate tool (az rest, Azure CLI, Invoke-MgGraphRequest).

### YAML Schema

Each YAML file contains:

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (e.g., `ingestion-q11`) |
| `name` | Human-readable name |
| `description` | What the query does and why |
| `phase` | Which PS1 phase runs it (1–5) |
| `type` | `kql`, `rest`, `cli`, or `graph` |
| `query` | KQL text (for `type: kql` only) |
| `timespan` | ISO 8601 duration (e.g., `P7D`, `P30D`) |
| `depends_on` | Query dependency (e.g., Q10b depends on Q10 output for tier arrays) |

### Complete Query Index

All paths relative to `.github/skills/sentinel-ingestion-report/queries/`.

| ID | Name | Type | Tables / Source | File | Drill-Down Scenario |
|----|------|------|----------------|------|---------------------|
| **Phase 1 — Volume Overview** | | | | | |
| Q1 | Usage by DataType | kql | `Usage` | `phase1/Q1-UsageByDataType.yaml` | Deep dive into which table drove a peak day |
| Q2 | Daily Ingestion Trend | kql | `Usage` | `phase1/Q2-DailyIngestionTrend.yaml` | Identify peak/min days, trend shifts |
| Q3 | Workspace Summary | kql | `Usage` | `phase1/Q3-WorkspaceSummary.yaml` | Baseline executive metrics |
| **Phase 2 — Table Deep Dives** | | | | | |
| Q4 | SecurityEvent by Computer | kql | `SecurityEvent` | `phase2/Q4-SecurityEventByComputer.yaml` | Which endpoints generate the most volume |
| Q5 | SecurityEvent by EventID | kql | `SecurityEvent` | `phase2/Q5-SecurityEventByEventID.yaml` | Which EventIDs drive volume (DCR filter input) |
| Q6a | Syslog by Host | kql | `Syslog` | `phase2/Q6a-SyslogByHost.yaml` | Noisiest Syslog sources |
| Q6b | Syslog by Facility × Severity | kql | `Syslog` | `phase2/Q6b-SyslogByFacilitySeverity.yaml` | DCR filter by facility/severity combo |
| Q6c | Syslog by Process × Facility | kql | `Syslog` | `phase2/Q6c-SyslogByProcess.yaml` | Filterable processes in noisy facilities |
| Q7 | CSL by Vendor/Product | kql | `CommonSecurityLog` | `phase2/Q7-CSLByVendor.yaml` | Which appliances send the most CEF |
| Q8 | CSL by Activity | kql | `CommonSecurityLog` | `phase2/Q8-CSLByActivity.yaml` | Highest-volume CEF event types |
| **Phase 3 — Rules & Tiers** | | | | | |
| Q9 | Analytic Rule Inventory | rest | Sentinel REST API | `phase3/Q9-AnalyticRuleInventory.yaml` | Fetch all AR queries (Patterns 1–5) |
| Q9b | Custom Detection Rules | graph | Graph `/beta/security/rules/detectionRules` | `phase3/Q9b-CustomDetectionRules.yaml` | CD rule inventory (Pattern 6) |
| Q10 | Table Tier Classification | cli | `az monitor` CLI | `phase3/Q10-TableTierClassification.yaml` | Analytics vs Basic vs Data Lake tiers |
| Q10b | Tier Volume Summary | kql | `Usage` + Q10 | `phase3/Q10b-TierSummary.yaml` | Per-tier cost breakdown (⚠️ has `{datalake_tables}` placeholder — needs Q10 output) |
| **Phase 4 — Detection Coverage & Health** | | | | | |
| Q11 | Rule Health Summary | kql | `SentinelHealth` | `phase4/Q11-RuleHealthSummary.yaml` | Rule execution pass/fail counts, NRT vs Scheduled |
| Q11d | Failing Rule Detail | kql | `SentinelHealth` | `phase4/Q11d-FailingRuleDetail.yaml` | Top failing rules with sample error messages |
| Q12 | SecurityAlert Firing | kql | `SecurityAlert` | `phase4/Q12-SecurityAlertFiring.yaml` | Which rules produce the most alerts, severity distribution |
| Q13 | All Tables with Data | kql | `Usage` | `phase4/Q13-AllTablesWithData.yaml` | Complete billable table inventory |
| **Phase 5 — Anomalies & Cost Optimization** | | | | | |
| Q14 | 24h Anomaly Detection | kql | `Usage` | `phase5/Q14-IngestionAnomaly24h.yaml` | Tables with >50% deviation from 7d average |
| Q15 | Week-over-Week Comparison | kql | `Usage` | `phase5/Q15-WeekOverWeek.yaml` | Tables with >20% WoW change |
| Q16 | Migration Candidates | kql | `Usage` | `phase5/Q16-MigrationCandidates.yaml` | Volume ranking for tier migration |
| Q17 | License Benefit Analysis | kql | `Usage` | `phase5/Q17-LicenseBenefitAnalysis.yaml` | DfS P2 + E5 daily benefit breakdown |
| Q17b | E5 Per-Table Breakdown | kql | `Usage` | `phase5/Q17b-E5PerTableBreakdown.yaml` | Individual E5-eligible table volumes |

### Common Drill-Down Recipes

These map user follow-up questions to YAML queries. Read the YAML, adapt filters, execute.

**"Dig into peak day from the report"**
→ Read Q1 (`Q1-UsageByDataType.yaml`). Replace `ago(30d)` with `between(datetime(YYYY-MM-DD) .. 1d)` to scope to the peak date. Shows which DataType drove the spike.

**"Which rules are failing and why?"**
→ Read Q11d (`Q11d-FailingRuleDetail.yaml`), execute as-is for 7d. For longer lookback, change `ago(7d)` to `ago(30d)`. Returns rule names, failure counts, and sample error text. Follow up with Q11 for the overall health summary (pass rate, NRT vs Scheduled).

**"What's causing the anomaly spike?"**
→ Execute Q14 (`Q14-IngestionAnomaly24h.yaml`) to see current 24h anomalies. Then drill into the specific table using the matching Phase 2 query: Q4/Q5 for SecurityEvent, Q6a–c for Syslog, Q7/Q8 for CommonSecurityLog.

**"Is this table safe to migrate to Data Lake?"**
→ Three checks: (1) Patterns 1–3 or 5 for AR cross-reference, (2) Pattern 6 for CD cross-reference, (3) Read Q12 (`Q12-SecurityAlertFiring.yaml`) to check if the table's rules actively produce alerts that would break if moved.

**"Show me E5 benefit utilization"**
→ Read Q17b (`Q17b-E5PerTableBreakdown.yaml`) for per-table volumes. Cross-reference with Q10 (`Q10-TableTierClassification.yaml`) to verify tier assignments.

**"What's changed week-over-week?"**
→ Read Q15 (`Q15-WeekOverWeek.yaml`), execute as-is. Returns tables with >20% change or >0.1 GB this week with `ChangePercent`.

**"Show SentinelHealth status for a specific rule"**
→ Read Q11d, adapt by adding `| where SentinelResourceName has '<RuleName>'` before the `summarize`. Shows failure count, last failure time, and sample error for that specific rule.

---

## Known Pitfalls

### Usage Table

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| `Usage` table has **no `TablePlan` column** | Cannot determine tier from KQL alone | Invoke-IngestionScan.ps1 uses Azure CLI `az monitor log-analytics workspace table list` (Q10) |
| `Usage.Quantity` is in **MB**, not GB | Miscalculated volumes if not converted | PS1 converts to GB: `sum(Quantity) / 1024` |
| `Usage` table updates in **batches (~6h)** | Very recent data may not appear | Note in report: "Usage data may lag by up to 6 hours" |
| `Usage.DataType` may differ from actual table names | Some custom tables have different naming | Cross-reference with `search_tables` if table name doesn't match |
| `estimate_data_size(*)` is an approximation | Per-table volume from direct table queries may differ from Usage table | Usage table is the authoritative source for billing; `estimate_data_size` is for relative comparison within a table |

### Table Schema Gotchas

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| `_SPLT_CL` tables appear in Usage alongside parent tables | May look like duplicate ingestion | Not double-counting — split ingestion routes different event subsets to each tier |
| `Signinlogs_Anomalies_KQL_CL` table name is **case-sensitive** | `SemanticError: Failed to resolve table` if auto-corrected to `SigninLogs` | Copy exact table name — lowercase 'l' in "logs" |
| `CommonSecurityLog` has 163 columns (many `DeviceCustom*` fields) | `estimate_data_size(*)` may be inflated by wide schema | Volume comparison is relative within the table — cross-reference with `Usage` for authoritative billing volume |
| `CommonSecurityLog.LogSeverity` is a **string**, not integer | May contain numeric strings ("0"-"10") or text ("Low", "High", "Unknown") | Group by `LogSeverity` as-is. If normalizing, use `case()` to map both formats |

### Value-Level Optimization Claims

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| **Table-level cross-reference ≠ value-level detection coverage** | The CrossRef tells you "SecurityEvent → 42 rules" but NOT which EventIDs those rules filter on. Claiming "no detection rule for EventID X" based on table-level data produces **incorrect optimization recommendations** | Invoke-IngestionScan.ps1 eliminates this risk with a **deterministic automated loop** that checks ALL values from Q5/Q6b/Q6c/Q8 against rule query text. The scratchpad `PHASE_4.ValueRef_*` sections contain the verified results. No LLM judgment involved |
| **Sweep rules vs. targeted rules** | A rule that queries `SecurityEvent \| where EventID in (8002, 8003, 8005)` sweeps ALL those EventIDs for hash matching — it's not a "dedicated" detection for any single EventID, but it IS a dependency. Recommending a DCR drop would break this rule silently | When reporting on EventIDs with rules, **read the rule names** from `PHASE_4.ValueRef_EventID` and interpret context. For post-report deep dives, use drill-down Pattern 1 to read actual query bodies |

### Custom Detection Rule Scope

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| **LLMs assume Custom Detections only target Defender XDR-native tables** (Device\*, Email\*, Identity\*) | Incorrect claim that CDs "cannot target SecurityEvent" or other Sentinel analytics tier tables, leading to incomplete detection coverage assessments and wrong migration recommendations | Custom Detection rules run on the **Advanced Hunting engine**, which queries ALL tables in the connected workspace — including Sentinel-native tables (SecurityEvent, SigninLogs, AuditLogs, Syslog, etc.) and custom tables (`*_CL`). Always include CD rules in detection coverage analysis for ANY table, not just XDR tables. Reference: [Compare analytics rules vs custom detections](https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections) |
| **Reporting "no detection rules" after checking only Sentinel analytic rules** | Missing Custom Detection coverage that may be the sole detection for certain tables or EventIDs | When asked "which rules reference [table/value]", ALWAYS check BOTH: (1) Sentinel AR via REST API (Patterns 1–5) AND (2) Custom Detection rules via Graph API (Pattern 6). A table may have 0 AR rules but active CD rules — recommending migration based on AR-only analysis would silently break those detections |

### Tool & Retention Limits

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| `az monitor log-analytics query` **free tier** | No per-query cost, but rate-limited | Invoke-IngestionScan.ps1 uses `-ThrottleLimit 5` for concurrent queries |
| **`az rest` requires Azure CLI authentication** | REST API call fails if `az login` session expired or wrong tenant/subscription | Re-authenticate with `az login`. Read `config.json` for correct subscription and tenant values |
| **Microsoft Graph module required for Q9b** | Custom Detection inventory fails without `Microsoft.Graph.Authentication` module | Install: `Install-Module Microsoft.Graph.Authentication`. PS1 handles graceful skip with diagnostic error in `CD_Status` |

### License Benefits

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| **DfS P2 benefit caveats** | Eligible table list varies between sources; benefit doesn't appear on invoices; pool is shared across subscription (total machines × 500MB, not per-machine) | Invoke-IngestionScan.ps1 computes pool from Q4 ServerCount. Cross-reference with [official docs](https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-ingestion-benefit). Verify via **View data allocation benefits** blade in Defender for Cloud portal |
| **E5 benefit requires Defender XDR connector streaming** | Tables only free if ingested via the Defender XDR connector, not manual agent upload | Verify connector enabled: billing should show `Free Benefit - M365 Defender Data Ingestion` line item |

---

## Error Handling — Invoke-IngestionScan.ps1

| Error | Cause | Resolution |
|-------|-------|------------|
| `SemanticError: Failed to resolve table 'SentinelHealth'` | SentinelHealth diagnostic setting not enabled | Q11/Q11d write EMPTY sections. Report §5b notes: "⚠️ SentinelHealth not enabled — rule execution health data unavailable." |
| `SemanticError: Failed to resolve table 'SentinelAudit'` | SentinelAudit not enabled | Affected sections write EMPTY |
| Usage query returns 0 results | No data in timeframe or permission issue | Check timeframe; verify workspace access; re-run `az login` |
| Azure CLI `table list` fails | Auth expired or wrong subscription | Re-authenticate: `az login`; verify subscription matches config.json |
| SecurityEvent/Syslog/CommonSecurityLog query returns 0 | Table not in workspace | PS1 writes EMPTY sections. Report skips deep dive: "✅ [Table] not present in this workspace" |
| Query timeout on large Usage aggregation | Very large workspace (>TB/day) | Reduce timeframe in YAML query files or increase `-ThrottleLimit` |
| `az rest` for analytic rules fails with auth error | Azure CLI session expired or wrong tenant/subscription | Re-authenticate with `az login`; read `config.json` for correct values |
| `az rest` returns empty `value[]` array | No Scheduled/NRT analytic rules in workspace, or JMESPath filter mismatch | Verify workspace has analytic rules in the Sentinel portal |
| Q9b (Graph API) fails | `Microsoft.Graph.Authentication` module not installed, or consent not granted | PS1 captures exact error in `CD_Status`. Report notes AR-only analysis. Install module: `Install-Module Microsoft.Graph.Authentication` |
| Scratchpad file not found | Invoke-IngestionScan.ps1 was not run, or ran with errors before writing | Re-run: `.\Invoke-IngestionScan.ps1 -Phase 0` for full run |
| Scratchpad `DL_Script_Output` section empty | Phase 5 DL classification failed | Re-run: `.\Invoke-IngestionScan.ps1 -Phase 5` |
| CrossRef shows all CD=0 but CD_Enabled > 0 | Phase 3 and Phase 4 ran in separate sessions | Re-run: `.\Invoke-IngestionScan.ps1 -Phase 3` then `-Phase 4` |

### Graceful Degradation

Invoke-IngestionScan.ps1 handles missing tables by writing `EMPTY` sections. During rendering, if a section is EMPTY:

```markdown
### 3c. CommonSecurityLog
✅ CommonSecurityLog not present in this workspace — section skipped.
```

Continue with all remaining sections. The report should always produce output for at least:
- Table Ingestion Breakdown (Section 2) — uses Usage table, available in all workspaces
- Ingestion Anomaly Detection (Section 4) — uses Usage table

### Re-Running Individual Phases

If a specific phase produced bad data, re-run just that phase:

```powershell
# Re-run Phase 3 only (rules + tiers)
.\Invoke-IngestionScan.ps1 -Phase 3

# Re-run Phase 4 only (detection coverage)
.\Invoke-IngestionScan.ps1 -Phase 4

# Re-run Phase 5 only (anomalies + cost)
.\Invoke-IngestionScan.ps1 -Phase 5

# Full re-run (all phases)
.\Invoke-IngestionScan.ps1 -Phase 0
```

Each phase appends to / overwrites its section in the existing scratchpad file. The scratchpad is rebuilt from scratch on each run, so partial re-runs produce a complete file.

---

## Appendix: Custom Detection Audit Trail via CloudAppEvents

Custom Detection **execution** telemetry is not available via LAQueryLogs or CloudAppEvents. However, Custom Detection **management** (create/edit/delete) audit events are logged in `CloudAppEvents` under the `Microsoft365Defender` workload.

**Discovery (Feb 2026):**

| ActionType | Workload | RecordType | What it captures |
|------------|----------|------------|------------------|
| `EditCustomDetection` | `Microsoft365Defender` | 113 | Rule edits — includes `RuleName`, `RuleId`, full `Query` text, `AlertCategory`, `AlertSeverity`, `MitreTechniques`, `UserId` (editor) |

**Query to enumerate Custom Detection rules from edit audit trail:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "EditCustomDetection"
| extend RawData = parse_json(RawEventData)
| extend RuleName = tostring(RawData.RuleName),
         RuleId = tostring(RawData.RuleId),
         Query = tostring(RawData.Query),
         AlertSeverity = tostring(RawData.AlertSeverity),
         AlertCategory = tostring(RawData.AlertCategory),
         MitreTechniques = tostring(RawData.MitreTechniques),
         Editor = tostring(RawData.UserId)
| summarize LastEdited = max(Timestamp), Editor = any(Editor) by RuleName, RuleId, AlertSeverity, AlertCategory
| order by LastEdited desc
```

**Limitations:**
- Only captures **edits** — no `CreateCustomDetection`, `RunCustomDetection`, or `DeleteCustomDetection` ActionTypes observed (as of Feb 2026)
- Rules that were created but never edited will not appear
- Requires Defender for Cloud Apps connector (`CloudAppEvents` table must be populated)
- Microsoft docs ([compare analytics rules vs Custom Detections](https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections)) note: "Rules audit logs available in advanced hunting → Exposed in the CloudAppEvents table for Microsoft Defender for Cloud Apps users."

**Not to be confused with:** `Job*` ActionTypes (`JobRunScheduled`, `JobCreated`, etc.) in CloudAppEvents — those are **Sentinel Data Lake KQL Jobs** (Workload: `Sentinel`), not Custom Detections.

---

## Additional References

- [Monitor and reduce costs for Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/billing-reduce-costs)
- [Azure Monitor data plan comparison](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-platform-logs#compare-data-plans)
- [Configure data collection rules](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview)
- [Workspace Usage Report workbook](https://learn.microsoft.com/en-us/azure/sentinel/usage-workbook)
- [Log Analytics table plan overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/basic-logs-configure)
- [Defender for Servers P2 data ingestion benefit](https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-ingestion-benefit)
- [View data allocation benefits](https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-ingestion-benefit#view-data-allocation-benefits)
- [Free data sources in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/billing?tabs=simplified%2Ccommitment-tiers#free-data-sources)
- [Compare analytics rules vs Custom Detections](https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections)
- [Sentinel REST API — Alert Rules](https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/list)
- [SOC Optimization dashboard](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-access?tabs=defender-portal)
- [ASIM parsers list](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list)
