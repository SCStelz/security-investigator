# Report Template — Sentinel Ingestion Analysis (v2)

> **📄 Just-in-time loading:** This file contains the complete report rendering templates (inline chat + markdown file). Load it at the start of **Phase 6 (rendering)** — alongside reading the timestamped scratchpad file (`temp/ingest_scratch_YYYYMMDD_HHmmss.md`). Do NOT load during data gathering (Invoke-IngestionScan.ps1 execution).

---

## Architecture Context (v2)

In v2, all data gathering is performed by `Invoke-IngestionScan.ps1`, which writes a deterministic scratchpad file. The LLM's only job during Phase 6 is to **read the scratchpad and render the report**. All query execution, cross-references, value-level checks, anomaly severity classification, DL eligibility scripts, and migration categorization are pre-computed by PowerShell.

**Data flow:** `Invoke-IngestionScan.ps1` → `temp/ingest_scratch_<timestamp>.md` → LLM reads scratchpad → renders report.

**Single-write rendering:** The entire report (§1-§8) is rendered in a single `create_file` call. Do NOT split into multiple writes — the LLM must hold the full template context throughout generation to prevent heading drift and column mutations in later sections.

**Q# references** in this document (Q1, Q9, Q10, etc.) identify which YAML query file produced the data. They are provenance labels — the LLM does not execute these queries during rendering.

---

## Section-to-Scratchpad Mapping

This table shows exactly which scratchpad keys feed each report section:

| Report Section | Scratchpad Keys | 
|----------------|----------------|
| §1 Workspace at a Glance | `PHASE_1.Metrics` (incl. `BillableTables`) + `META.ReportPeriod` |
| §1 Cost Waterfall | `PRERENDERED.CostWaterfall` (pre-rendered from `PHASE_1.Metrics` + `PHASE_5.LicenseBenefits`) |
| §1 Detection Posture | `PRERENDERED.DetectionPosture` (pre-rendered from `PHASE_3.RuleInventory` + `PHASE_4.CrossRef` + `PHASE_3.TierSummary`) |
| §1 Overall Assessment | Synthesized from all phases |
| §1 Top 3 Recommendations | Computed at render time from all scratchpad data using Rule E (see below) |
| §2a Top Tables | `PRERENDERED.TopTables` (pre-rendered from `PHASE_1.Tables` + `PHASE_4.CrossRef` + `PHASE_3.Tiers`) |
| §2b Tier Classification | `PHASE_3.TierSummary` + `PHASE_3.Tiers` + `PHASE_1.Tables` (per-DL-table volumes) |
| §3a SecurityEvent | `PRERENDERED.SE_Computer` + `PRERENDERED.SE_EventID` + `PHASE_5.LicenseBenefits` (DfSP2 pool) |
| §3b Syslog | `PRERENDERED.SyslogHost` + `PRERENDERED.SyslogFacility` + `PRERENDERED.SyslogFacSev` + `PRERENDERED.SyslogProcess` |
| §3c CommonSecurityLog | `PRERENDERED.CSL_Vendor` + `PRERENDERED.CSL_Activity` |
| §4a Anomaly Table | `PRERENDERED.AnomalyTable` (pre-rendered from `PHASE_5.Anomaly24h` + `PHASE_5.AnomalyWoW`, unified with Rule A severity) |
| §4b Daily Trend | `PRERENDERED.DailyChart` (pre-rendered from `PHASE_1.DailyTrend` with Rule C applied) |
| §5a Rule Inventory | `PHASE_3.RuleInventory` + `PHASE_4.CrossRef` + `PHASE_4.ZeroRuleTables` + `PHASE_4.ASIM` |
| §5b Health & Alerts | `PHASE_4.Health` + `PHASE_4.CrossValidation` (LLM prose) + `PRERENDERED.HealthAlerts` (AlertProducing + FailingRules tables with volume/severity badges) |
| §6 + §6a License Benefits | `PRERENDERED.BenefitSummary` (Combined Benefit Summary) + `PRERENDERED.DfSP2Detail` (pool detail + scenario insight) |
| §6b E5/XDR Benefits | `PRERENDERED.E5Tables` (per-table breakdown with tier, total, break-even, reconciliation) |
| §7a Migration Candidates | `PRERENDERED.Migration` (4 sub-tables with volume/rule badges, DL eligibility) + `PHASE_4.DetectionGaps` |
| §7b-d Priorities | Synthesized from §3 + §5 + §7a |
| §8 Appendix | `PRERENDERED.Headings` + `PRERENDERED.QueryTable` + `PRERENDERED.Footer` + `META` section |

---

## Inline Chat Executive Summary

````markdown
📊 SENTINEL INGESTION REPORT — <DATE>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Workspace:** <WORKSPACE_NAME> | **Period:** <TIMEFRAME>

### 📊 Workspace at a Glance

| | Metric | Value |
|---|--------|-------|
| 📦 | Active Tables (ingesting) | X of Y registered |
| 📦 | Billable Tables | X |
| 🕒 | Report Period | `META.ReportPeriod` verbatim |
| 📏 | Avg Daily Ingestion | `PHASE_1.Metrics.AvgDailyGB` GB/day |
| 📈 | Peak Day | X.XX GB (<DATE> — <DAY>) |
| 📉 | Min Day | X.XX GB (<DATE> — <DAY>) |
| 🔄 | Trend | Stable / Growing / Declining — <brief note> |

### 💰 Cost Waterfall

```
                                    N-Day (GB)     Avg/Day (GB)
  Total Ingestion                     X.XXX          X.XXX
  ─ Non-Billable                      -X.XXX         -X.XXX
  ──────────────────────────────────────────────────────────────
  Gross Billable                      X.XXX          X.XXX
  ─ Est. E5/XDR Benefit               -X.XXX         -X.XXX
  ─ Est. DfS P2 Benefit               -X.XXX         -X.XXX
  ──────────────────────────────────────────────────────────────
  🎯 Est. Net Billable               ~X.XXX         ~X.XXX
```

> ⚠️ Benefit estimates assume all applicable licenses are activated and connectors are streaming. E5 line shows total E5-eligible volume — actual grant depends on license count (see §6b).
>
> 💡 **Commitment Tier Planning:** Sentinel commitment tiers start at 100 GB/day. Compare the **Avg/Day Net Billable** against tier thresholds to decide between Pay-As-You-Go and commitment pricing.

### 🛡️ Detection Posture

| | Metric | Value |
|---|--------|-------|
| ✅ | Enabled Analytic Rules | X Scheduled, X NRT |
| 🛡️ | Enabled Custom Detections | X (via Graph API) |
| ⚫ | Disabled Rules | X AR, X CD |
| 📊 | Tables with Rules (top-20) | X of 20 |
| 🔴 | Tables with Zero Rules (top-20) | X of 20 |
| ⏱️ | Tables on Basic Tier | X |
| 🗄️ | Tables on Data Lake Tier | X |

### Overall Assessment

- 📈 **Ingestion pattern:** <weekday/weekend cycle description, trend assessment>
- 🔴 **Biggest lever:** <table name> at **X.XX GB (X.X%)** of billable volume. <brief context>
- 🔴 **<Second key finding>** — <details with evidence>
- 🟠 **<Warning-level finding>** — <details>
- 🟢 **<Positive finding>** — <details with evidence>

### 🎯 Top 3 Recommendations

| # | Severity | Recommendation | Table/Scope | Impact | Risk |
|---|----------|----------------|-------------|--------|------|
| 1 | 🔴 | **<Action>** | <TABLE/SCOPE> | **<Impact description>** | <Low/Med/High — brief reason> |
| 2 | 🔴 | **<Action>** | <TABLE/SCOPE> | **<Impact description>** | <Low/Med/High — brief reason> |
| 3 | 🟠 | **<Action>** | <TABLE/SCOPE> | **<Impact description>** | <Low/Med/High — brief reason> |

📄 Full report: reports/sentinel/sentinel_ingestion_report_<YYYYMMDD_HHMMSS>.md
````

---

## Markdown File Structure

The full markdown report file MUST follow this structure:

```markdown
# Sentinel Ingestion Analysis Report

**Generated:** <DATE>
**Workspace:** <WORKSPACE_NAME>
**Workspace ID:** <WORKSPACE_ID>
**Report Period:** <TIMEFRAME>
```

> **⛔ MANDATORY — Report Period format:** Copy `META.ReportPeriod` from the scratchpad **verbatim**. It is pre-computed by the PS1 as `YYYY-MM-DD to YYYY-MM-DD (N days)` with the partial report-generation day already excluded. Do NOT compute dates yourself — the PS1 handles this. Example: `Report Period: 2026-01-20 to 2026-02-18 (30 days)`. Do NOT invert to `N days (start to end)` format.

---

> **⛔ No chain-of-thought in report output.** Render only final, verified content. Silently correct any errors — never narrate the correction.

> **⛔ Never use "Auxiliary" or "auxiliary" in report output.** Azure CLI reports Data Lake tier as plan `Auxiliary` internally — always write **"Data Lake"** in all sections, tables, appendices, and prose. This also applies when describing tables — never call tables "auxiliary tables" (e.g., "Defender XDR auxiliary tables") as readers will confuse this with the Auxiliary tier label. Use "supplemental" or simply list the table names. This applies everywhere: Section 2a `Current Tier`, Section 2b, Detection Posture, Section 7a, Quick Wins, Appendix tier tables.

> **📋 Advisory disclaimer (MUST appear in every rendered report):** Add the following note immediately below the report header (after Workspace ID, before §1):
>
> *"This report presents data-driven recommendations based on automated analysis of ingestion patterns, detection coverage, and tier classification. All recommendations require human review and validation before implementation. Verify findings against your operational context, retention requirements, and compliance obligations before making changes."*

> ⛔ **SECTION HEADING LOCK:** Copy ALL section and sub-section headings from `PRERENDERED.Headings` in the scratchpad **verbatim**. Do NOT rename, reorder, or omit any heading. Do NOT invent headings not in the list (no Glossary, no §5c, no §8e).

## 1. Executive Summary

Four sub-sections arranged for scannable decision-making:

### 📊 Workspace at a Glance
Emoji-prefixed metric table with: Active Tables (ingesting vs registered), Billable Tables, Report Period, Avg Daily Ingestion, Peak Day (with date and weekday), Min Day (with date and weekday), Trend assessment.

> **Report Period:** Copy `META.ReportPeriod` verbatim (pre-computed, partial day excluded).
>
> **Avg Daily Ingestion:** Use `PHASE_1.Metrics.AvgDailyGB`. This is the KQL-computed average (total volume ÷ all calendar days including the partial report-generation day). The `DailyChart` block has a separate `Avg` line that excludes the partial day per Rule C — this is expected and correct for the chart context. Do NOT attempt to reconcile these two numbers; use `PHASE_1.Metrics.AvgDailyGB` for §1.

### 💰 Cost Waterfall

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.CostWaterfall` from the scratchpad **verbatim** into this section. It is a pre-rendered fenced-code-block ASCII subtraction diagram with two columns (N-Day volume and Avg/Day — column headers are dynamic based on `-Days`). Do NOT reformat as a markdown table. Do NOT recalculate any values — the PS1 pre-computed all numbers including Net Billable from daily category splits.
>
> After the code block, include the advisory note and Commitment Tier Planning callout from the Inline Chat Executive Summary template above.

### 🛡️ Detection Posture

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.DetectionPosture` from the scratchpad **verbatim** into this section. It is a pre-rendered 7-row emoji-prefixed metric table (`| Metric | Value |`) with all values and emoji prefixes pre-computed by the PS1: Enabled Analytic Rules (with `AR_Enabled − AR_NRT` breakdown), Enabled Custom Detections (or SKIPPED if Q9b failed), Disabled Rules, Tables with Rules/Zero Rules (top-20 counted against CrossRef), Basic/Data Lake tier counts. Do NOT recalculate any values, change emoji prefixes, or reorder rows.
>
> **Post-copy validation:** If the NRT count shows 0 but `PRERENDERED.HealthAlerts` Failing Rules sub-table contains rule names prefixed with "NRT", add an inline note: e.g., "225 Scheduled, 0 NRT (note: 2 NRT rules detected in health data — see §5b)".

### Overall Assessment
Punchy bullet list (3-5 items) with emoji severity prefixes (🔴/🟠/🟢/📈). Each bullet names the specific finding with bold numbers and evidence. Examples:
- 📈 Ingestion pattern description (weekday/weekend cycle, trend)
- 🔴 Biggest cost lever (single table dominating billable volume)
- 🔴 Second critical finding (e.g., noisy EventID with no detection value)
- 🟠 Warning-level finding (e.g., tables with zero detection coverage)
- 🟢 Positive finding (e.g., E5 benefit coverage percentage)

### 🎯 Top 3 Recommendations
Table with columns: #, Severity, Recommendation, Table/Scope, Impact, Risk. Recommendations can cover **any category**: cost optimization (tier migration, DCR filtering), detection gaps (rules on wrong tier, silent failures), operational health (agent issues, rule failures), or posture improvements. Each row uses severity emoji (🔴/🟠/🟡) in the Severity column.

> **Ranking source:** Compute the Top 3 at render time using **Rule E** categories from SKILL.md. Cross-reference all scratchpad sections — `PRERENDERED.Migration` (migration candidates), `PHASE_4.DetectionGaps` (rules on wrong tier), `PHASE_4.Health`/`FailingRules` (health issues), `PHASE_5.Anomaly24h`/`AnomalyWoW` (data loss signals), `PHASE_4.ValueRef_*` (filterable noise), `PHASE_2.*` (deep dive volumes) — to identify the highest-impact actionable findings. **Sort severity-first, then by score:** 🔴 items always rank above 🟠 items, regardless of score. Within the same severity tier, rank by descending `Score = SeverityWeight × ImpactValue` per Rule E.
>
> **Rule E — 11 categories (ranked by weight):**
>
> | Category | Weight | ImpactValue | Example |
> |----------|--------|-------------|---------|
> | Detection gap | 10 | rule count | Rules silently failing on DL tier |
> | Data loss | 10 | GB/day | Table ingestion dropped >80% WoW |
> | DL migration | 5 | BillableGB | Zero-rule table billable on Analytics |
> | DL + KQL Job promotion | 4 | BillableGB | High-volume 🟣/🟢 table — can complement split ingestion or stand alone; present both options and note they are combinable |
> | License benefit activation | 4 | unclaimed GB/day | E5/DfS P2 eligible volume not yet claimed |
> | DCR filter | 4 | saveable GB | Noisy EventID/facility with 0 rules |
> | Health fix | 4 | failing rules | Rule execution failures |
> | Volume spike / cost anomaly | 3 | spike GB | Zero-rule table with >50% positive deviation |
> | Duplicate ingestion | 3 | duplicate GB | Same appliance sending Syslog + CEF |
> | Split ingestion | 3 | GB × fraction | High-volume table with 1-2 narrow rules needing raw events |
> | Tier review | 2 | BillableGB | Sub-threshold tables worth evaluating |
>
> **Risk column:** Risk = the security or operational impact of NOT acting (SKILL.md Rule B). Do NOT interpret as implementation difficulty, effort, or change management risk.

> **⛔ MANDATORY VALIDATION — apply BEFORE finalizing Top 3:**
>
> **1. Impact column must cite verifiable data from the scratchpad:**
> - For cost recommendations: cite the **`PHASE_1.Tables` BillableGB** value if the table appears in the top 20. For sub-top-20 tables (only in `PRERENDERED.Migration`), cite the deep-dive GB value with the correct unit. Example: "~0.06 GB at Analytics rate → significantly cheaper on DL" — NOT invented round numbers. ⛔ **PROHIBITED:** (1) Extrapolating deep-dive→primary window (e.g., multiplying by Days/deepDiveDays) — this produces inaccurate numbers, especially for NEW tables with limited data. (2) Saying "free on Data Lake" — Data Lake tier has reduced cost vs Analytics but is **not free**. Use "significantly cheaper" or "reduced cost" instead. ⛔ **NEVER use the word "free" when describing Data Lake tier pricing.**
> - For detection gap recommendations: cite the rule count and tier from `PHASE_4.CrossRef`/`PHASE_3.Tiers`. Example: "5 rules silently failing against Data Lake tier"
> - **Non-XDR table remediation (⛔ CRITICAL):** The **PS1 Category column** now explicitly says `Detection gap (XDR)` or `Detection gap (non-XDR)`. **Read the Category column** to determine which remediation to present:
>   - `Detection gap (non-XDR)` → present **two options ONLY** — (1) move table back to Analytics tier, OR (2) remove/disable the analytic rules referencing the table (accepting the DL tier and the detection gap). ⛔ **PROHIBITED:** Offering "convert ARs to Custom Detections" for non-XDR tables. CDs run against Advanced Hunting which only retains Defender XDR tables for 30 days. Non-XDR tables on Data Lake are invisible to Advanced Hunting — CDs WILL NOT WORK.
>   - `Detection gap (XDR)` → present **three options** — (1) move back to Analytics, (2) convert ARs→CDs (XDR tables remain available in Advanced Hunting for 30 days regardless of Sentinel tier), OR (3) remove/disable ARs. Cite the AR/CD split from `PHASE_4.CrossRef` to show which rules work (CDs) vs broken (ARs)
> - For health recommendations: cite the failure count from `PHASE_4.Health`. Example: "41 combined failures this period"
> - ⛔ **PROHIBITED:** Inventing savings estimates that don't match any number in the scratchpad. Every Impact value must be traceable to a specific scratchpad key
>
> **2. For "Migrate to Data Lake" recommendations specifically**, cross-check these three data sources in the scratchpad. **All three must pass:**
>
> | Check | Source | Fail Action |
> |-------|--------|-------------|
> | **Not already on Data Lake/Basic** | `PHASE_3.Tiers` (Current Tier column) | ⛔ REJECT — table is already migrated. Use a different recommendation (DCR filter, retention reduction, etc.) |
> | **DL-eligible (confirmed)** | `PHASE_5.DL_Script_Output` | ⛔ If `No` → REJECT (cannot migrate). If `Unknown` → do NOT recommend "Migrate to Data Lake." Use **"Review DL eligibility"** as the action, or choose a non-migration action. Only recommend "Migrate to Data Lake" if `Yes` |
> | **Zero detection rules OR split-ingest viable** | `PHASE_4.CrossRef` (Total column) | ⛔ If rules > 0, do NOT recommend full migration. Recommend split-ingest (🟣) or keep on Analytics (🟢) instead |
>
> **Recommendation selection guidance:**
> - Prioritize by **severity × impact**: a 🔴 detection gap (rules silently failing) outranks a 🟠 cost saving of 0.06 GB/month
> - Mix categories when appropriate — a report with 1 detection gap, 1 cost optimization, and 1 health fix is more actionable than 3 minor tier migrations
> - It is acceptable to show only 1-2 recommendations if the workspace is well-optimized. Do NOT fabricate recommendations to fill 3 slots

---

## Section-by-Section Rendering Rules

### 2a. Top Tables by Volume

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.TopTables` from the scratchpad **verbatim** into this section. It is a pre-rendered 20-row table with columns `Volume | # | DataType | BillableGB (Nd) | Avg/Day (GB) | % | Rules | Current Tier` (where N = `-Days` value), plus totals line and legend. All emoji badges, percentage calculations, tier lookups, and rule-count breakdowns are pre-computed by the PS1. Do NOT recalculate any values, change emoji assignments, or reformat the table.

> **Emoji threshold reference — PS1 pre-applies these in all PRERENDERED blocks (§2a, §3a–§3c, §7a). Retained here for §8c methodology and manual verification:**
>
> **Column 1 — Volume band** (based on BillableGB):
>
> | Emoji | Threshold | Meaning |
> |-------|-----------|---------|
> | 🔴 | ≥500 GB | Major cost driver |
> | 🟠 | 100–499 GB | Significant |
> | 🟡 | 10–99 GB | Moderate |
> | 🟢 | <10 GB | Minimal |
>
> **Rules column — detection gap flag** (based on rule count from CrossRef + Current Tier):
>
> | Format | Condition | Signal |
> |--------|-----------|--------|
> | ⚠️ 0 | 0 rules AND tier is **Analytics** or **Basic** | Zero rules — cost optimization candidate |
> | 0 | 0 rules AND tier is **Data Lake** | Expected — analytic rules don't execute against Data Lake tables |
> | 🟠 N | 1–2 | Minimal coverage |
> | 🟡 N | 3–9 | Light coverage |
> | 🟢 N | 10–49 | Strong coverage |
> | 🟣 N | 50+ | Deep coverage |
>
> **Applies everywhere:** These rule-count badges apply globally — in §2a (Top Tables), §3a-§3c (deep-dive Rules columns), and §7a (migration sub-tables). §2a and §5a are pre-computed by PS1. Use the same thresholds consistently.
>
> **Data Lake exception:** Tables on Data Lake tier with 0 rules do NOT receive the ⚠️ emoji because analytic rules cannot run against Data Lake tables — 0 rules is the expected state, not a detection gap. If a Data Lake table has ≥1 rule, it IS a detection gap (rules silently failing) and receives the normal emoji (🟡/🟢/🟣) plus a note in §7a. Remediation always includes a second option: remove/disable the rules referencing the table (accepting DL and the gap). **Defender XDR table nuance:** XDR-native tables on Data Lake have a partial gap (only ARs are broken — see [Migration Classification](SKILL.md#migration-classification)). In §7a, check the **PS1 Category column** (`Detection gap (XDR)` vs `Detection gap (non-XDR)`) to determine which remediation options to present. ⛔ **NEVER offer CD conversion for non-XDR tables.**


### 2b. Tier Classification

**Data source:** `PHASE_3.TierSummary` (sourced from Q10 KQL cross-reference output — covers the **full** Usage table, not just top 20).

**Rendering:**
1. **Tier summary table** with actual volume numbers:
   `| Tier | Table Count | BillableGB (Nd) | % of Total |`
   Populate **directly from `PHASE_3.TierSummary`**. Do NOT re-compute from `PHASE_1.Tables` (Q1 is `take 20` and will produce incorrect per-tier totals).
2. **Prose note** below the table listing 2-3 notable tables per tier (largest contributors) — cross-reference `PHASE_1.Tables` with `PHASE_3.Tiers` for per-table volumes within each tier.
3. Include data gathering timestamp from `META.Generated`.

> Use exact counts from scratchpad — do NOT approximate with `~` prefixes.
> ⛔ **PROHIBITED:** Computing per-tier BillableGB by summing Q1 top-20 rows grouped by tier, or by back-calculating `BillableGB × %`. The `PHASE_3.TierSummary` IS the authoritative source.

### 3. Source Table Deep Dives

> **⛔ MANDATORY — Deep-dive column names and emoji formatting:** Use these exact column headers in ALL §3a–§3c tables: `Event Count` (two words), `Est. GB (Nd)` (abbreviated with period, N = deep-dive days), `%` (not "PercentOfTotal" or "% of Total"). Column headers are dynamic — copy from the PRERENDERED blocks verbatim. Emoji badges (volume band 🔴/🟠/🟡/🟢, security-relevance 🔒/📡/⚙️) MUST render as a **separate leading table column cell** — never merged into adjacent text (e.g., `| 🟢 | computer-name |` not `| 🟢 computer-name |`).

#### 3a. SecurityEvent

**By Computer:**

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.SE_Computer` from the scratchpad **verbatim** into this section. Columns: `Volume | Computer | Event Count | Est. GB (Nd) | %` (N = deep-dive days). Volume badges are pre-computed by the PS1. A `ServerCount: N` line and a volume band legend (🔴 ≥20 GB · 🟠 10–19 GB · 🟡 5–9 GB · 🟢 <5 GB) follow the table — include both. Use the `ServerCount` value for the §6a DfS P2 pool calculation. Do NOT recalculate badges, change column headers, or reformat.

🔍 Optimization insight for top contributors

**By EventID:**

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.SE_EventID` from the scratchpad **verbatim** into this section. Columns: `Volume | EventID | Description | Event Count | Est. GB (Nd) | % | Rules Referencing` (N = deep-dive days). Volume badges and rule badges with inline names are pre-computed by the PS1. A volume/rule band legend follows the table — include it. Unknown EventIDs have blank descriptions — you MAY add a description if you know it. Do NOT recalculate badges, change column headers, or reformat.

📋 EventID optimization potential ratings

**Combined — Top Computer × EventID Pairs:**
(Optional — cross-tabulation if warranted by findings)

#### 3b. Syslog

**By Source Host:**

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.SyslogHost` from the scratchpad **verbatim** into this section. Columns: `Source Host | Event Count | Est. GB (Nd) | % | Facilities | Severity Levels` (N = deep-dive days). Do NOT recalculate or reformat.

🔍 Noisiest host identification. If only 1–2 hosts appear despite many expected servers, flag forwarding architecture.

**By Facility:**

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.SyslogFacility` from the scratchpad **verbatim** into this section. Columns: `Badge | Facility | Event Count | Est. GB (Nd) | % | Rules` (N = deep-dive days). Security-relevance badges (🔒⚙️⏰📬📝📡) and rule badges with inline names are pre-computed by the PS1. A facility badge legend follows the table. Do NOT recalculate badges, change column headers, or reformat.

**By Facility × SeverityLevel:**

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.SyslogFacSev` from the scratchpad **verbatim** into this section. Columns: `Badge | Facility | Severity Level | Event Count | Est. GB (Nd) | %` (N = deep-dive days). Facility badges and RFC 5424 severity emojis (🔴🟠🟡🔵⚪⚫) are pre-computed by the PS1. A severity legend follows the table. Do NOT recalculate or reformat.

📋 Facility optimization potential ratings
🔧 DCR severity-per-facility recommendations: list each facility with current vs recommended minimum severity

> Also check ASIM parser dependencies (`PHASE_4.ASIM`) — `_Im_Authentication` consumes `sshd`/`su`/`sudo` from Syslog `authpriv`.

**Top ProcessName by Facility:**

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.SyslogProcess` from the scratchpad **verbatim** into this section. Columns: `Facility | Process Name | Event Count | Est. GB (Nd) | % | Rules` (N = deep-dive days). Rule badges with inline names are pre-computed by the PS1. Do NOT recalculate or reformat.

📋 ProcessName security relevance and optimization potential — identifies filterable noise within high-volume facilities (especially `daemon`)
🟣 Split ingestion candidates: noisy low-security processes (systemd, dbus-daemon) → Data Lake; security-critical processes (sshd, sudo, auditd) → Analytics

**Combined — Top Facility × ProcessName Pairs:**
(Optional — derived from `PHASE_2.Syslog_FacilitySeverity` and `PHASE_2.Syslog_Process` cross-tabulation if warranted)

#### 3c. CommonSecurityLog

**By DeviceVendor and DeviceProduct:**

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.CSL_Vendor` from the scratchpad **verbatim** into this section. It is a pre-rendered table with volume badge emojis, dynamic `Est. GB (Nd)` column headers (N = deep-dive days, set by PS1), and rule badge + inline rule names from Phase 4 cross-referencing. Do NOT recalculate, re-badge, or modify column headers.
>
> If `PRERENDERED.CSL_Vendor` shows "EMPTY", see EMPTY handling below.

🔍 Appliance-level optimization opportunities: filter routine TRAFFIC at DCR, or split-route noisy vendors/products to Data Lake (retain for hunting) while keeping threat-relevant events on Analytics. For vendors with high volume but few rules, consider DL + KQL job promotion (aggregate anomalies back to Analytics-tier `_KQL_CL` table) — this can complement split ingestion by running against the DL-routed portion.

**By Activity, LogSeverity, DeviceAction:**

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.CSL_Activity` from the scratchpad **verbatim** into this section. Same rendering rules as CSL_Vendor above — volume badges, dynamic headers, and rule badges are all PS1-computed. Do NOT recalculate.
>
> If `PRERENDERED.CSL_Activity` shows "EMPTY", see EMPTY handling below.

📋 Activity optimization potential ratings — three complementary strategies for high-volume activities:
1. **DCR filter** — drop at ingestion (zero cost, but data is lost permanently)
2. **Split ingestion** — DCR routes noisy low-value traffic to Data Lake, keeps threat-relevant events on Analytics (data retained for hunting/compliance)
3. **KQL job promotion** — for any data routed to Data Lake (whether via split ingestion or full table migration), schedule KQL jobs to aggregate and surface anomalies back to an Analytics-tier `_KQL_CL` table (e.g., connection volume spikes, rare DeviceActions, unusual source/destination patterns)

> Options 2 and 3 are complementary: split-route noisy traffic to Data Lake **and** run KQL jobs against that Data Lake data to extract detection value from it without paying Analytics-tier ingestion costs.

🟣 Split ingestion candidates: high-volume Activity+DeviceAction combos (e.g., `TRAFFIC`/`Allow`, `Connection`/`Accept`) with 0 rules → Data Lake; threat-relevant activities (`IDS`/`Deny`, `Malware`/`Block`) → Analytics

> **⛔ MANDATORY — EMPTY handling:** If `PRERENDERED.CSL_Vendor` is `EMPTY` AND `PRERENDERED.CSL_Activity` is `EMPTY`, render §3c as: "**Volume:** No CommonSecurityLog data recorded in the report period." followed by "No CSL data — no deep dive applicable. No DCR optimization needed at this time." Do NOT fabricate vendor counts, volume estimates, or placeholder table rows. An EMPTY scratchpad section means zero data — not "1 vendor with negligible volume" or "minimal data".

### 4. Ingestion Anomaly Detection

#### 4a. Per-Table Anomaly Summary (24h + WoW)

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.AnomalyTable` from the scratchpad **verbatim** into this section. It is a pre-rendered unified table merging Anomaly24h + AnomalyWoW data on `DataType`. Column headers are dynamic (generated by PS1 based on the `-Days` parameter) — e.g., `DataType | Last 24h (GB) | Nd Avg (GB) | 24h Deviation | This Period (GB) | Last Period (GB) | PoP Change | Severity`. The PS1 handles all merge/dedup logic, "—" fill for missing cross-columns, sort order, severity classification (per Rule A — see SKILL.md), and period label generation. Do NOT recalculate, re-merge, re-classify, or modify column headers.
>
> If `PRERENDERED.AnomalyTable` shows "NONE", render: "✅ No ingestion anomalies detected — all tables within normal deviation thresholds."
>
> **Methodology (reference):** 24h deviation uses same-weekday average (4-week lookback, ≥3 data points, flat 7d fallback) to avoid weekday/weekend false positives.

After the table, add narrative highlights: new tables, fastest growing, largest declines.

#### 4b. Daily Trend

**Data source:** `PHASE_1.DailyTrend`

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.DailyChart` from the scratchpad **verbatim** into this section. It is a pre-rendered ASCII bar chart with █ bars, peak/min/partial annotations, summary line (Avg/Peak/Min), and weekday averages. Rule C (partial-day exclusion) is already applied by the PS1. Do NOT recalculate any values, reformat the chart, or omit the weekday averages line.
>
> **Narrative validation:** Below the chart, write a pattern description (weekday/weekend cycle, trend). Reference the pre-computed weekday averages from the chart. Do NOT claim specific weekdays "dip" or "spike" without verifying against the averages.

Narrative: Pattern description (weekday/weekend, growth trend, spikes). Cite the weekday averages when describing cyclical patterns.

### 5. Detection Coverage

> ⛔ **SECTION 5 — STRUCTURAL ENFORCEMENT (read before rendering)**
>
> **Sub-section headings:** Use the §5 headings from `PRERENDERED.Headings` verbatim. Only two sub-sections exist: `#### 5a. Analytic Rule Inventory & Table Cross-Reference` and `#### 5b. Analytic Rule Health & Alerts (SentinelHealth + SecurityAlert)`. Do NOT create §5c, §5d, §5e, or any additional sub-sections.
>
> **§5a must contain (in this order):**
> 1. **Inventory summary table** — **⛔ EXACT column header:** `| Metric | Count |`. Render as a **single flat table with exactly 7 rows** (AR Total, AR Enabled with Scheduled + NRT breakdown, AR Disabled, CD Total, CD Enabled, CD Disabled, **Combined Enabled** bold). **NEVER split into two sub-tables** (e.g., separate "Analytic Rules" and "Custom Detections" tables). **NEVER use** a matrix layout (`Category | Total | Enabled | Disabled` columns). **NEVER use** `Category | Count` as column headers — it must be `Metric | Count`.
> 2. **Table-to-Rule Cross-Reference table** — Copy `PRERENDERED.CrossReference` verbatim (columns, badges, sort order, and key rule names pre-computed by PS1).
> 3. **ASIM Parser Dependencies** — inline paragraph or small table AFTER the cross-reference. NOT a separate sub-section.
>
> **⛔ §5b MANDATORY RENDERING ORDER (render in this exact sequence 1→2→3→4, do NOT reorder):**
> 1. **Cross-validation summary** — Read `PHASE_4.CrossValidation` and state Q11 vs Q9 counts and gap percentage (1–2 sentences).
> 2. **Alert-producing rules table** — Copy verbatim from `PRERENDERED.HealthAlerts` → `#### Alert-Producing Rules` sub-section (heading includes dynamic date range from PS1). Badges (🔥/📊/💤 volume, 🔴/🟠/🟡/🔵 severity) are PS1-computed. Include the `Total:` summary line.
> 3. **Health summary paragraph** — render as **prose paragraph**, NOT a `| Metric | Value |` table. Read `PHASE_4.Health` and state: total rules in SentinelHealth, overall success rate, failing rule count.
> 4. **Failing rules table** (conditional) — Copy verbatim from `PRERENDERED.HealthAlerts` → `#### Failing Rules`. Status badges (🟠 Failing) are PS1-computed. If `NONE`, skip this sub-section. Remediation notes as bullet list AFTER the table.

#### 5a. Analytic Rule Inventory & Table Cross-Reference

**Data source:** `PHASE_3.RuleInventory` (rule counts) + `PHASE_4.CrossRef` (table-to-rule mapping) + `PHASE_4.ZeroRuleTables` + `PHASE_4.ASIM`.

**Summary table:**
| Metric | Count |
|--------|-------|
| Total Scheduled/NRT rules (AR) | <TOTAL> |
| Enabled AR | <ENABLED> |
| Disabled AR | <DISABLED> |
| Total Custom Detection rules (CD) | <TOTAL> |
| Enabled CD | <ENABLED> |
| Disabled CD | <DISABLED> |
| **Combined enabled rules** | **<AR + CD>** |

> If Q9b was skipped (check `PHASE_3.RuleInventory.CD_Status`), note: "⚠️ Custom Detection inventory unavailable — showing AR-only analysis." The CD_Status line contains the exact terminal error for diagnostics.

**Table-to-Rule Cross-Reference** (tables referenced by ≥1 enabled rule, sorted by total rule count):

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.CrossReference` from the scratchpad **verbatim** into this section. It is a pre-rendered table with columns `| Coverage | Table | AR Rules | CD Rules | Total | Key Rule Names |`, sorted by Total descending. Coverage badges (🟣 ≥50, 🟢 10-49, 🟡 3-9, 🟠 1-2) and key rule names (up to 3 names + `; +N more`) are pre-computed by the PS1. Do NOT recalculate badges, change column headers, or reformat.

This is the definitive answer to "how many rules target each table" — produced by regex-searching all enabled rule query texts (AR + CD combined) for each ingested table name. The AR/CD breakdown reveals tables with exclusive Custom Detection coverage that would appear as zero-rule migration candidates in AR-only analysis. Tables with zero rules across both sources are listed in Section 7a as migration candidates.

> **📌 Custom Detection scope:** Custom Detection rules run on the Advanced Hunting engine, which queries ALL tables in the connected workspace — including Sentinel analytics tier tables (SecurityEvent, SigninLogs, Syslog, AuditLogs, etc.), not just Defender XDR-native tables (Device\*, Email\*, Identity\*). It is therefore expected and normal to see `CD > 0` for Sentinel-native tables. When writing insights about detection coverage, treat CD rules on Sentinel tables as equivalent to AR rules — they provide real detection value. Reference: [Compare analytics rules vs custom detections](https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections)

> ⛔ **MANDATORY CD CROSS-REFERENCE VALIDATION:** Before rendering this table, verify: if `PHASE_3.RuleInventory.CD_Enabled > 0` (Q9b succeeded), then at least one table in `PHASE_4.CrossRef` MUST show `CD > 0`. If ALL tables show `CD = 0` despite CD rules existing, the cross-reference data is corrupt — **DO NOT render**. Re-run `Invoke-IngestionScan.ps1 -Phase 3` followed by `-Phase 4` to regenerate the scratchpad data, then re-read the scratchpad.

**Composition notes:**
- Flag Heartbeat stub rules (test/lab artifacts with zero detection value)
- Flag test rules (generating noise alerts)
- Flag ASIM parser rules (from `PHASE_4.ASIM`) — may indirectly query additional tables not captured in cross-reference
- Note methodology: reverse cross-reference catches multi-table rules that single-table extraction would miss

#### 5b. Analytic Rule Health & Alerts (SentinelHealth + SecurityAlert)

**Data source:** `PHASE_4.Health` (aggregate metrics, LLM prose) + `PHASE_4.CrossValidation` (Q11 vs Q9 comparison, LLM prose) + `PRERENDERED.HealthAlerts` (Alert-Producing Rules table + Failing Rules table with badges).

**⚠️ Cross-validation (mandatory before rendering):** Read `PHASE_4.CrossValidation` — it contains `Q11_DistinctRules`, `Q9_AR_Enabled`, and a pre-computed `Gap` percentage. The PS1 now correctly uses `AR_Enabled` (AR-only, excluding CD rules) as the denominator per Rule D — SentinelHealth tracks AR executions only. Use the scratchpad's `Gap` value directly. If the gap exceeds 10%, note it in the report as a data quality caveat.

**🔴 Rendering instruction (what to show in the report):**

A full per-rule table with 200+ rows of healthy-silent rules adds no insight. Instead, render Section 5b as:

1. **Cross-validation summary** (mandatory): State the Q11 distinct rule count vs Q9 enabled rule count, and the gap percentage from `PHASE_4.CrossValidation`. If within tolerance (≤10%), note it. If exceeded, document it.

2. **Alert-producing rules table:** Copy verbatim from `PRERENDERED.HealthAlerts` → `#### Alert-Producing Rules` sub-section (heading includes dynamic date range from PS1). Volume badges (🔥/📊/💤) and severity badges (🔴/🟠/🟡/🔵) are PS1-computed. Include the `Total:` summary line. Do NOT reformat, reorder, or recalculate badges.

3. **Health summary paragraph**: Read `PHASE_4.Health` and render as **prose paragraph** (NOT a table). State:
   - Total distinct rules executing in SentinelHealth
   - Overall success rate across all rules (from `OverallSuccessRate`)
   - Count of rules with any failures (`FailingRuleCount`) — if any, reference the Failing Rules table below
   - NRT execution cadence note (e.g., "NRT rules execute ~10,080 times per 7 days, ≈ once per minute")

4. **Failing rules table** (conditional): Copy verbatim from `PRERENDERED.HealthAlerts` → `#### Failing Rules` sub-section. Status badges (🟠 Failing) and Kind (NRT/Scheduled) are PS1-computed. If `NONE`, skip this sub-section. Remediation notes as bullet list AFTER the table.

**Do NOT render:** A full table of all 200+ rules showing 🟢 Healthy / 🟡 Active but silent for every row. These are the default state and don't warrant per-row visibility.

**Why SentinelHealth instead of LAQueryLogs?** In unified Defender portal environments, ALL scheduled/NRT rule executions bypass LAQueryLogs entirely. SentinelHealth is the only table that tracks every rule execution.

### 6. License Benefit Analysis

> ⛔ **§6 — Sub-section headings:** Use the §6 headings from `PRERENDERED.Headings` verbatim (`### 6a. Defender for Servers P2 Pool Detail` and `### 6b. E5 / Defender XDR Pool Detail`).
>
> **§6 must contain (in this order):**
> 1. **Combined Benefit Summary:** Copy `PRERENDERED.BenefitSummary` from the scratchpad **verbatim** after the §6 heading (before §6a). Contains the 3-row summary table (DfS P2-Eligible, E5-Eligible, Remaining).
> 2. **§6a DfS P2 pool detail:** Copy `PRERENDERED.DfSP2Detail` from the scratchpad **verbatim** after the §6a heading. Contains pool calculation line with benefit details link, 6-row metrics table, and scenario-based insight paragraph.
> 3. **§6b E5 pool detail:** Copy `PRERENDERED.E5Tables` verbatim (already specified below).
>
> ⛔ **PROHIBITED:** (1) Recalculating Combined Benefit Summary rows — PS1-computed from Q17 averages. (2) Re-selecting the DfS P2 scenario — PS1 selects based on pool utilization. (3) Modifying pool calculation or metrics values. (4) Removing the benefit details link.
>
> ⚠️ **Conditional language note:** The scenario text in `PRERENDERED.DfSP2Detail` already uses conditional phrasing ("If DfS P2 is enabled…"). Do not remove or weaken these conditionals. Whether DfS P2 is actually enabled cannot be determined from Sentinel telemetry alone.

**Data source:** `PRERENDERED.BenefitSummary` + `PRERENDERED.DfSP2Detail` + `PRERENDERED.E5Tables` + `PHASE_5.LicenseBenefits` (raw key-values for §3a cross-reference).

For pool calculation methodology and interpretation guidance, see [Reference: License Benefits](#reference-license-benefits) in SKILL.md.

#### 6b. E5 / Defender XDR Pool Detail
Pool calculation: E5 data grant = (number of E5 licenses) × 5 MB/day ([offer details](https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer))
Note: Ask the user for E5 license count — this is not discoverable from Sentinel telemetry alone.
Insight: If M365 E5 / E5 Security licenses are active, the data grant covers up to the pool limit. Overage above the grant is billed at standard rates. The grant appears as `Free Benefit - M365 Defender Data Ingestion` on the bill.
For pool calculation methodology and interpretation guidance, see [Reference: License Benefits](#reference-license-benefits) in SKILL.md.

> **⛔ MANDATORY — E5-eligible table enumeration:**
>
> **Copy `PRERENDERED.E5Tables` from the scratchpad verbatim into this section.** It contains a pre-formatted table sorted by Volume desc with columns `| Table | Volume (Nd GB) | Tier |` (N = primary window days), a Total row, break-even license calculation, and sum reconciliation footnote (if applicable). Tier values are looked up from Q10 data. Do NOT reformat, reorder, recalculate, or add Category columns.
>
> The 29 E5-eligible table names (for reference — actual data comes from KQL query Q17b):
>
> | Category | Tables |
> |----------|--------|
> | **Entra ID** | SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, ADFSSignInLogs |
> | **Defender XDR (Device)** | DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceFileCertificateInfo |
> | **Defender XDR (Email)** | EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo |
> | **Defender XDR (Identity)** | IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents |
> | **Defender XDR (Other)** | AlertEvidence, CloudAppEvents, DynamicEventCollection |
> | **Other** | McasShadowItReporting, InformationProtectionLogs_CL |
>
> **Render all tables from `PRERENDERED.E5Tables`** — the table is pre-sorted by Volume desc and includes Tier lookups, Total row, break-even calculation, and sum reconciliation footnote. Copy verbatim. Do NOT split into category sub-tables or reorder.
>
> ⛔ **PROHIBITED:** (1) Splitting into 5 separate category sub-tables — use the single flat table from PRERENDERED. (2) Listing only Entra ID tables and omitting Device\*/Email\*/Identity\* tables. (3) Adding a Category column — the table names are self-descriptive. (4) Recalculating the break-even or reconciliation — these are PS1-computed.

### 7. Optimization Recommendations

#### 7a. Data Lake Migration Candidates

**Data source:** `PRERENDERED.Migration` (4 pre-formatted sub-tables with volume badges, rule badges, DL eligibility emojis) + `PHASE_4.DetectionGaps`.

> **⛔ MANDATORY FORMAT:** Copy `PRERENDERED.Migration` from the scratchpad **verbatim** into this section. It contains the legend, 4 sub-table headings (`#### Sub-table 1-4`), and pre-formatted markdown tables with columns `| DataType | Nd GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |` (N = deep-dive days). Volume badges (🔴/🟠/🟡/🟢), rule badges (🟣/🟢/🟡/🟠/⚠️ — matching the global badge reference; Data Lake tables with 0 rules show plain 0), and DL Eligible emojis (✅/❌/❓/📕) are pre-applied by PS1. Do NOT reformat, recalculate, or add/remove columns. Empty sub-tables render as "*No tables in this category.*"

**After copying verbatim**, the LLM adds callout notes below sub-tables using these descriptions:

**Sub-table 1: "DL Migration Candidates"** — Zero-rule tables with `DL Eligible = ✅ Yes` (🔴 category). Strong candidates for Data Lake migration. For high-volume tables, also evaluate DCR filtering. Review before acting.

**Sub-table 2: "Zero-Rule Tables — Not Eligible or Unknown"** — Zero-rule tables with `DL Eligible = ❌ No` or `❓ Unknown` (🟠 category). Not migration candidates — consider DCR filtering or adding analytic rules. `📕 KQL` tables also appear here.

**Sub-table 3: "Tables WITH Rules — Keep on Analytics"** — All tables with ≥1 rule. Detection gap entries (DL tier + rules) also render here with ❗ badge. PS1 specifies `Detection gap (XDR)` or `Detection gap (non-XDR)` in the Category column — use this to determine remediation options (see Category reference above).

**Sub-table 4: "Tables Already on Data Lake"** — DL tier with zero rules (no detection gap). No changes recommended.

**Do NOT render:** `SentinelHealthExecs`, `SuccessRate`, `AlertsFired` per-table columns — these are per-rule metrics that live in Section 5b. Mapping them back to tables is error-prone and produces unreliable data. Section 7a focuses on the **migration decision** (volume + rules + tier + eligibility).

**Category reference** (for interpreting `PRERENDERED.Migration` Category column — see [Migration Classification](SKILL.md#migration-classification) in SKILL.md for full criteria, XDR nuances, and remediation options):
- 🔵 KQL Job output → Sub-table 2
- 🔵 Already on Data Lake → Sub-table 4
- 🟢 Keep Analytics → Sub-table 3
- 🟣 Split ingestion candidate → Sub-table 3
- ❗ Detection gap (XDR) → Sub-table 3 — ARs broken, but CDs still work via Advanced Hunting. Remediation: (1) move back to Analytics, (2) convert ARs→CDs, (3) remove/disable ARs
- ❗ Detection gap (non-XDR) → Sub-table 3 — ARs broken AND CDs will NOT work (non-XDR tables are invisible to Advanced Hunting on Data Lake). Remediation: (1) move back to Analytics, (2) remove/disable ARs. ⛔ **PROHIBITED: offering "convert ARs to Custom Detections" for non-XDR tables**
- 🔴 Strong candidate (DL-eligible) → Sub-table 1
- 🟠 Not DL-eligible / unknown → Sub-table 2

> **LLM overlay checks (cross-reference at render time — do NOT change PS1 emojis):**
> - **Execution issues:** For any 🟢 table in Sub-table 3, check if its rules appear in `PRERENDERED.HealthAlerts` Failing Rules sub-table. If so, add a ⚠️ callout note below Sub-table 3: "Rules targeting [table] have execution issues — see §5b."
> - **ASIM dependency:** For any 🔴 table in Sub-table 1, check `PHASE_4.ASIM` for ASIM parsers consuming it. If found, add a ⚠️ callout note below Sub-table 1: "[table] is consumed by ASIM parsers — verify dependency before migrating (see [ASIM parsers list](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list))."
> - **SentinelHealth special case:** If `SentinelHealth` appears in Sub-table 1 as a zero-rule DL migration candidate, add a 💡 callout note: "SentinelHealth has zero analytic rules, but before migrating consider creating rules to **monitor analytic rule execution failures** (e.g., alert on >5 failures/hour for a single rule, or success rate dropping below 90%). This mirrors the §7d recommendation to automate anomaly alerting on the `Usage` table — SentinelHealth is the operational equivalent for detection health. Without rules here, rule failures go unnoticed until manual review."

> **💡 SOC Optimization cross-reference:** Tables classified as 🔴 or 🟠 (zero rules) should be cross-referenced with Microsoft's [SOC Optimization dashboard](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-access?tabs=defender-portal) in the Defender portal before acting on migration recommendations. SOC Optimization surfaces two complementary insights for these tables:
> - **Data value:** Flags tables not used by any analytics rules in the past 30 days and suggests either activating Content Hub rule templates or changing the table plan (Basic/Data Lake)
> - **Threat-based coverage:** Identifies gaps against specific attack scenarios (e.g., human-operated ransomware) and recommends Content Hub analytics rule templates that would use the table for detection
>
> If SOC Optimization recommends rule templates for a zero-rule table, activating those rules converts it from a migration candidate into a detection source — potentially changing its classification from 🔴→🟢.

#### 7b. ⚡ Quick Wins

Render applicable items from this checklist. Skip items that don't apply to the workspace data. Order by severity (🔴 first).

- **🔴 Detection gap remediation** — If Sub-table 3 contains any 🔴 Detection Gap rows (rules targeting Data Lake/Basic tier tables), this is the #1 quick win. State the table name, rule count, and action based on the **Category column** emitted by PS1:
  - **Detection gap (non-XDR):** Present **two options only** — (1) move table back to Analytics tier, (2) remove/disable the rules referencing the table (accepting DL). ⛔ **PROHIBITED:** Offering "convert ARs to Custom Detections" for non-XDR tables. Custom Detections run against Advanced Hunting, which only retains Defender XDR tables for 30 days. Non-XDR tables on Data Lake are invisible to Advanced Hunting.
  - **Detection gap (XDR):** Present **three options** — (1) move table back to Analytics tier, (2) convert ARs to Custom Detections (CDs run against Advanced Hunting which retains XDR tables for 30 days regardless of Sentinel tier), (3) remove/disable the ARs if detection is no longer needed.
  - Also mention KQL Jobs to promote specific results as a supplementary option. Link: [Manage data tiers](https://learn.microsoft.com/azure/sentinel/manage-data-overview)
- **🔴 Connector health investigation** — If `PHASE_5.Anomaly24h` or `PHASE_5.AnomalyWoW` shows a significant volume DROP (≥50%) on a table with ≥3 rules, flag it as a potential connector failure. State the table, drop %, and rule count. Recommend verifying connector status in the Sentinel data connectors page. A table with many rules and suddenly no data = blind spot
- **🟠 Data Lake migration** for 🔴 DL-eligible tables identified in Sub-table 1 — review suitability, then see [Manage data tiers](https://learn.microsoft.com/azure/sentinel/manage-data-overview). For high-volume tables, also evaluate DCR filtering to reduce unnecessary data before migrating — see [DCR transformations](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations)
- **🟠 Test/noise rule cleanup** — If `PRERENDERED.HealthAlerts` Alert-Producing Rules table contains rules that appear to be test/development rules (names like "Test", "Copy of", stub queries), recommend disabling them to reduce alert fatigue. Cite the alert count and severity
- **🟠 Volume spike investigation** — If `PHASE_5.Anomaly24h` or `PHASE_5.AnomalyWoW` shows a significant volume SPIKE (≥100%) on a zero-rule, non-security table (AzureMetrics, AppDependencies, etc.), flag it for investigation. A sudden spike in a table with no detection value may indicate misconfiguration or unnecessary data collection
- For 🟠 tables in Sub-table 2: consider DCR filtering to reduce volume, or adding analytic rules for detection coverage
- **SOC Optimization review:** Before migrating any 🔴/🟠 zero-rule table, review the [SOC Optimization page](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-access?tabs=defender-portal) in the Defender portal for data value and threat-based coverage recommendations
- DCR filtering for noisy EventIDs/devices — see [DCR transformations](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations)
- CommonSecurityLog traffic log filtering (TRAFFIC/Accept events)
- License benefit activation (if DfS P2 or E5 eligible volume is significant)

> **Documentation links:** When writing recommendation prose in §7b, include the relevant MS Learn hyperlink inline so the operator can click through. Use the links above as templates.

#### 7c. 🔧 Medium-Term Optimizations

Render applicable items from this checklist. Skip items that don't apply. These require more analysis or planning than quick wins.

- **Failing rule remediation** — If `PRERENDERED.HealthAlerts` Failing Rules sub-table contains rules with persistent failures (especially NRT rules), recommend investigating query complexity, timeouts, or data source issues. For timeout errors, suggest reducing lookback window, adding datetime filters, or limiting join cardinality. For NRT rules with many failures, suggest evaluating conversion to Scheduled rules with 5-minute intervals if near-real-time execution is not critical
- **Split ingestion and/or DL + KQL Job promotion** for 🟣 tables and high-volume 🟢 tables — present both options with trade-offs, and note they can be combined (see SKILL.md § "Split Ingestion and/or DL + KQL Job Promotion"). The LLM does not have rule query text, so present both approaches and let the operator decide based on whether their rules use raw event filters (→ split) or aggregation (→ DL + KQL Job) or both (→ split + KQL Job on the DL portion). Note KQL Job caveats: 15-min DL latency, rules must target `_KQL_CL`, tenant limit 3 concurrent / 100 enabled. Do NOT change PS1's `Category` emoji in §7a
- SecurityEvent EventID filtering via DCR
- Syslog facility filtering
- **Dual-ingestion / duplicate data detection** — If the same data source streams to BOTH Syslog and CommonSecurityLog (e.g., Palo Alto firewalls sending to Syslog local0 AND CEF/CSL), flag the overlap. Both paths incur ingestion cost for the same events. Recommend keeping whichever path has better detection coverage (check rule counts for each table) and dropping or DL-routing the other. Common pattern: firewall appliances configured with both syslog and CEF connectors. When both streams share a single DCR, the AMA parses CEF-formatted messages into CommonSecurityLog but also logs the raw line to Syslog — see [Syslog and CEF streams in the same DCR](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama?tabs=api#syslog-and-cef-streams-in-the-same-dcr) for DCR configuration guidance to eliminate the duplicate
- **Non-security telemetry routing** — If zero-rule tables like AppDependencies, AppPerformanceCounters, AppTraces, Perf, or AzureMetrics represent significant volume, recommend evaluating whether this data belongs in Sentinel at all. Application Insights telemetry and performance counters may be better routed to a dedicated Application Insights or Log Analytics workspace outside Sentinel to avoid unnecessary billing
- **Security-relevant zero-rule tables** — If `PRERENDERED.Migration` Sub-table 2 contains tables with clear security value but zero rules (e.g., MicrosoftServicePrincipalSignInLogs, IdentityLogonEvents, IdentityDirectoryEvents, OfficeActivity), recommend adding analytic rules from Content Hub rather than leaving them unmonitored. These tables carry security telemetry that should have detection coverage
- **Unknown DL eligibility research** — If Sub-table 2 contains tables with `❓ Unknown` DL eligibility and significant combined volume, recommend checking the [Manage data tiers](https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview) documentation for current eligibility. Microsoft periodically adds new tables to the DL-eligible list
- **Source-level audit reduction** — If SecurityEvent deep dive reveals a single EventID dominating volume (e.g., 4663 object access), AND the top contributors are specific servers, recommend reviewing the audit policy (SACL) configuration on those servers to narrow the auditing scope at source. This reduces ingestion before it reaches Sentinel, which is more effective than filtering after collection. Similarly, if Syslog shows systemd dominating daemon volume, review rsyslog/syslog-ng configuration
- Table tier optimization
- **Documentation links in rendered report:** Include inline hyperlinks so the operator can act: [DCR ingestion-time transformations](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations) for split ingestion, [KQL jobs](https://learn.microsoft.com/azure/sentinel/datalake/kql-jobs) for DL promotion path.

#### 7d. 🔄 Ongoing Maintenance

Render applicable items. These are recurring operational practices.

- **Weekly anomaly monitoring** — Review ingestion anomalies (§4a) weekly. Prioritize investigation when high-rule-count tables show significant drops (potential connector failures causing detection blind spots)
- **Automated ingestion anomaly alerting** — Recommend creating a scheduled analytic rule on the `Usage` table to detect >100% daily deviations for high-rule-count tables. This automates the weekly monitoring cadence and provides near-real-time alerting when a critical data source stops flowing. Example pattern: `Usage | where TimeGenerated > ago(1d) | summarize TodayMB = sum(Quantity) by DataType | join kind=inner (Usage | where TimeGenerated between (ago(8d) .. ago(1d)) | summarize AvgMB = avg(Quantity) by DataType) on DataType | where TodayMB < AvgMB * 0.5 or TodayMB > AvgMB * 3`
- **Rule health monitoring** — Check SentinelHealth weekly for failing rules. Persistent NRT failures (>20 failures/week) should be escalated — either fix the query or convert to scheduled rules. Track resolution of any failing rules identified in §5b
- **Quarterly tier review** — Re-run this ingestion report quarterly to catch new zero-rule tables, verify tier assignments, and update license benefit analysis. As new analytic rules are deployed or Content Hub templates activated, tables previously classified as zero-rule candidates may gain coverage
- **License benefit utilization monitoring** — Track DfS P2 and E5 benefit utilization via [Azure Cost Analysis](https://learn.microsoft.com/azure/azure-monitor/fundamentals/cost-usage#view-data-allocation-benefits). Verify `Free Benefit - M365 Defender Data Ingestion` and `Free Benefit - Defender for Servers` line items appear on the bill if licenses are active
- **SOC Optimization review cadence** — Review the [SOC Optimization dashboard](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-access?tabs=defender-portal) monthly for new data value and threat-based coverage recommendations

### 8. Appendix

> ⛔ **SECTION 8 — STRUCTURAL ENFORCEMENT (read before rendering)**
>
> **Sub-section headings:** Use the §8 headings from `PRERENDERED.Headings` verbatim (`8a. Query Reference`, `8b. Data Freshness`, `8c. Methodology`, `8d. Limitations`). Do NOT rename, reorder, merge, invent, or omit any sub-section. Do NOT invent a Glossary — there is no glossary section in this report.
>
> **§8a Query Reference** — Copy `PRERENDERED.QueryTable` from the scratchpad **verbatim**. This is the full 23-row audit trail. Include the `META.Generated` timestamp and total query count in a header line above the table. Do NOT summarize into a 5-row phase overview.
>
> **§8b Data Freshness** — 3–4 bullet points covering: Usage table update cadence (~6h batch), SentinelHealth latency (near real-time), tier classification source (Azure CLI point-in-time snapshot), scratchpad timestamp reference.
>
> **§8c Methodology** — Bullet list describing: volume calculation source (Usage table Quantity field), anomaly detection thresholds and volume floor, rule inventory source (REST API + Graph API), cross-reference methodology (reverse regex search), migration classification approach. **This is methodology, NOT a glossary.**
>
> **§8d Limitations** — Numbered list covering at minimum: Usage vs billing rounding, GB-not-dollars caveat, CD availability dependency on Graph API, SentinelHealth AR-only coverage, ASIM parser resolution limits, tier data CLI dependency. **NEVER omit §8d** — it sets data consumer expectations.
>
> **Footer:** Copy `PRERENDERED.Footer` from the scratchpad as the **last line** of the report. It is a pre-rendered 3-field pipe-delimited line (`Report generated: <ts> | Skill: ... | Mode: ...`). Do NOT rewrite in prose format.

#### 8a. Query Reference
Copy `PRERENDERED.QueryTable` from the scratchpad **verbatim**. Include the `META.Generated` timestamp and total query count in a header line above the table.

Plus non-KQL operations: REST API (Q9), Graph API (Q9b), Azure CLI (Q10), and automated post-processing (Phase 4 CrossRef, Phase 5 anomaly severity, DL classification, migration categorization).

#### 8b. Data Freshness
- Usage table: Updated every ~6 hours (batch processing)
- SentinelHealth: Near real-time
- Tier classification: Azure CLI snapshot at data gathering time
- Scratchpad timestamp: `META.Generated`

#### 8c. Methodology
- Volume calculations use `Quantity` from Usage table (in MB, converted to GB)
- Anomaly detection uses >50% deviation threshold with a 10 MB volume floor (tables where both periods are <10 MB are excluded as noise). Severity pre-computed by Invoke-IngestionScan.ps1 using Rule A thresholds
- **Analytic rule inventory** uses the Sentinel REST API as the **authoritative source** for enabled Scheduled and NRT analytic rules. Rule-to-table mapping uses **reverse cross-reference**: for each ingested table name from Q1 Usage, regex-search all enabled rule query texts for that table name. This catches multi-table rules (TI unions, joins, CTEs) that forward-parsing would miss. All cross-references are computed deterministically by Invoke-IngestionScan.ps1
- **Analytic rule execution health** uses SentinelHealth (Q11 for health overview, Q11d for failing rule details) + SecurityAlert (Q12) for alert firing counts
- **Migration candidates** are classified by Invoke-IngestionScan.ps1 by cross-referencing the verified table-to-rule mapping with tier data (Azure CLI) and DL eligibility (scripted classification). The 9-column Migration table in the scratchpad contains the pre-computed categorization

#### 8d. Limitations
- Usage table `Quantity` may not exactly match billing due to rounding and batch processing
- Cost estimates are in GB, not dollars — actual cost depends on pricing tier and commitment
- Custom Detection rules are fetched via Microsoft Graph API (Q9b). If Q9b is unavailable (module/consent issues), the report notes AR-only analysis and Custom Detection coverage is excluded
- Custom Detection execution health is not tracked in SentinelHealth — CD execution status is available only via the `lastRunDetails` field in the Graph API response (Q9b). Section 5b covers AR-only health metrics
- ASIM parser rules call abstraction functions (e.g., `_Im_WebSession()`) — target tables cannot be determined from query text alone. The automated ASIM detection maps them to source tables, but the mapping is based on the [published ASIM parsers list](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list) and may not cover custom workspace-specific parsers
- Table tier data requires Azure CLI — not queryable via KQL
