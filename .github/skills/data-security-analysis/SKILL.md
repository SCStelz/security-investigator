---
name: data-security-analysis
description: 'Use this skill when asked to analyze data security events, sensitive information type (SIT) access patterns, sensitivity label access patterns, DLP policy matches, or Purview insider risk activity. Triggers on keywords like "data security", "sensitive information type", "SIT access", "who accessed sensitive data", "DLP events", "DataSecurityEvents", "EDM access", "exact data match", "credit card access", "sensitive file access", "insider risk activity", "Purview data security", "SIT breakdown", "classify access", "sensitivity label", "labeled documents", "label downgrade", "label change", "Copilot label exposure", or when investigating which users accessed documents containing specific sensitive information types or sensitivity labels. This skill queries DataSecurityEvents in Advanced Hunting to produce comprehensive SIT and sensitivity label access analysis including volume breakdowns, user-level drill-downs, file inventories, action type distribution, DLP policy correlation, label change tracking, Copilot label exposure, temporal patterns, and risk-ranked user summaries. Supports inline chat and markdown file output. Designed for large environments (100k+ users) with aggressive summarization and tiered drill-down.'
threat_pulse_domains: [admin, cloud]
drill_down_prompt: 'Analyze data security events — SIT access patterns, label changes, DLP policy matches'
---

# Data Security Events Analysis — Instructions

## Purpose

This skill analyzes **DataSecurityEvents** (Microsoft Purview Insider Risk Management / DLP telemetry) to answer questions about **who accessed documents containing sensitive information types (SITs) and/or sensitivity labels** — including EDM (Exact Data Match), built-in SITs (credit cards, SSNs, etc.), trainable classifiers, and Microsoft Purview sensitivity labels (Confidential, Highly Confidential, custom labels, etc.).

**Primary Table:** `DataSecurityEvents` (Defender XDR Advanced Hunting)

| Use Case | Example Question |
|----------|------------------|
| SIT access audit | "Who accessed files with credit card numbers in the last 30 days?" |
| EDM monitoring | "Show me all access to documents matching our EDM SIT" |
| DLP event analysis | "What DLP policy matches occurred this week?" |
| Insider risk triage | "Which users have the most sensitive data interactions?" |
| SIT landscape overview | "What sensitive information types exist in our environment?" |
| **Sensitivity label audit** | **"Who accessed Highly Confidential labeled documents?"** |
| **Label change tracking** | **"Show me all label downgrades in the last 30 days"** |
| **Copilot label exposure** | **"What labeled documents did Copilot access in risky interactions?"** |

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[SIT GUID Mapping Strategy](#sit-guid-mapping-strategy)** - How SIT GUIDs are resolved to names
3. **[Label GUID Mapping Strategy](#label-guid-mapping-strategy)** - How sensitivity label GUIDs are resolved to names
4. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
5. **[Quick Start](#quick-start-tldr)** - 8-step execution pattern
6. **[Execution Workflow](#execution-workflow)** - 6-phase analysis process
7. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns (Queries 1-16d)
8. **[Report Template](#report-template)** - Rendering rules (15 rules) + output format specification
9. **[Known Pitfalls](#known-pitfalls)** - Table quirks and edge cases (27 entries)
10. **[Error Handling](#error-handling)** - Troubleshooting guide
11. **[SVG Dashboard Generation](#svg-dashboard-generation)** - Visual dashboard from report data

**Investigation shortcuts:**
- **DLP/exfiltration incident entities** (TP Q1): **Q3** (top users by SIT volume) → **Q6** (DLP policy matches) → **Q9** (single-user SIT profile for each incident entity) → **Q10b** (file-based spikes)
- **High-volume mailbox API access** (TP Q9): **Q9** (single-user SIT profile for API actors) → **Q4** (top files accessed) → **Q10b** (file-based spikes) → **Q6** (DLP policy matches)
- **Risky identity with data access** (TP Q3): **Q9** (single-user SIT profile) → **Q4** (top files) → **Q13** (label downgrade/changes by user)
- **Copilot sensitive data exposure** (TP Q1 Copilot incidents, or TP Q10 AppRegistration with AI keywords): **Q16a** (Copilot SIT landscape + agent/human split) → **Q16b** (top human users, high-priority SITs) → **Q16d** (prompt-only risk signal)
- **Label compliance / downgrade alert** (TP Q1 label-related incidents): **Q13** (label changes) → **Q15** (label-only events) → **Q14** (Copilot label exposure)
- **Tenant-wide data security posture** (standalone, no TP trigger): Full Phase 1–5 workflow

> **⛔ Shortcut Default Rule:** When a matching shortcut exists for the investigation context, **use it** — don't run the full workflow. Only run the full Phase 1-5 sequence when the user explicitly requests "full analysis", "comprehensive", or "tenant-wide overview". Shortcuts render only the report sections relevant to their query chain (plus Executive Summary and Recommendations, always).

### When invoked from a parent skill (threat-pulse, incident-investigation, user-investigation):
- Inherit the workspace selection from the parent investigation context
- **Skip output mode prompts** — default to inline chat (the parent skill controls the final output format)
- Match the TP Q# trigger to the shortcuts above and execute that chain with entity substitution
- Use **30d lookback** (AH default) unless the parent specifies otherwise

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY data security analysis:**

1. **ALWAYS use `RunAdvancedHuntingQuery`** — DataSecurityEvents is an Advanced Hunting table, NOT available in Sentinel Data Lake
2. **ALWAYS run Query 1 (SIT Discovery) first** — establishes which SITs are active and builds the GUID-to-Name mapping
3. **ALWAYS use `summarize` aggressively** — this table can have 600k+ rows in 30 days even in mid-size tenants. NEVER retrieve raw rows except for targeted samples
4. **ALWAYS pre-filter with `has` before `mv-expand`** on `SensitiveInfoTypeInfo` — the `has "<GUID>"` filter avoids expensive expansion on non-matching rows
5. **ALWAYS use `tostring()` + double `parse_json()`** for SensitiveInfoTypeInfo — it's `Collection(String)`, not native dynamic
6. **NEVER report SIT GUIDs without attempting name resolution** — use the mapping strategy below
7. **ALWAYS ask for output mode** if not specified: inline chat or markdown file
8. **Prerequisite:** DataSecurityEvents requires **Insider Risk Management opt-in** to share data with Defender XDR. If the table returns 0 rows or "table not found", inform the user of this requirement
9. **ALWAYS run the Label Coverage Assessment** (Query 11 quick stats variant) during Phase 1 to determine if this environment has significant label usage. Adapt the report accordingly (see Rule 11)
10. **NEVER report sensitivity label GUIDs without attempting name resolution** — use the label mapping strategy below
11. **ALWAYS use `split()` on `SensitivityLabelId`** — this column can contain comma-separated GUIDs (one per sub-entity), not a single GUID

### ⛔ PROHIBITED ACTIONS

| Action | Status |
|--------|--------|
| Querying DataSecurityEvents via `mcp_sentinel-data_query_lake` | ❌ **PROHIBITED** — AH-only table |
| Retrieving raw rows without `summarize` or `take` limit | ❌ **PROHIBITED** — table is massive |
| Reporting SIT GUIDs without name resolution attempt | ❌ **PROHIBITED** |
| Reporting sensitivity label GUIDs without name resolution attempt | ❌ **PROHIBITED** |
| Running `mv-expand` on SensitiveInfoTypeInfo without pre-filtering with `has` | ❌ **PROHIBITED** — performance killer at scale |
| Assuming `SensitiveInfoTypeInfo` is native dynamic | ❌ **PROHIBITED** — it's `Collection(String)`, requires double-parse |

---

## SIT GUID Mapping Strategy

### The Problem

`DataSecurityEvents.SensitiveInfoTypeInfo` contains SIT **GUIDs**, not human-readable names. SIT GUIDs fall into three categories:

| Category | Resolvable via KQL? | Example |
|----------|---------------------|---------|
| **Built-in Microsoft SITs** | ✅ Yes — use embedded mapping | `50842eb7-...-b085` → "Credit Card Number" |
| **Custom/EDM SITs** | ❌ No — org-specific GUIDs | `b28fcea1-...-9291` → "Project Obsidian" (custom) |
| **Trainable Classifiers (ML)** | ❌ No — `ClassifierType: "MLModel"` | `77a140be-...-7560` → unknown ML classifier |

### Resolution Strategy (3 tiers, in order)

#### Tier 1: Embedded Well-Known SIT Mapping (instant, no auth)

The query library below includes a `datatable` of the **most common Microsoft SIT GUIDs** encountered in production environments. This covers ~90% of detections in typical tenants.

#### Tier 2: User-Provided Custom SIT Mapping (config-driven)

If the user has custom/EDM SITs, they can provide a mapping in `config.json` under a `sit_mapping` key:

```json
{
  "sit_mapping": {
    "<custom-sit-guid-1>": "Your Custom SIT Name",
    "<custom-sit-guid-2>": "Your EDM SIT Name"
  }
}
```

**At skill startup:** Check if `config.json` has a `sit_mapping` section. If yes, merge it into the KQL `datatable` for name resolution.

#### Tier 3: PowerShell Resolution (optional, on-demand)

If unresolved GUIDs remain after Tier 1+2, **offer** to resolve them via PowerShell:

> "I found N SIT GUIDs that aren't in the built-in mapping. Would you like me to resolve them via `Get-DlpSensitiveInformationType`? This requires an active Security & Compliance PowerShell session (`Connect-IPPSSession`)."

If the user agrees:

```powershell
# Requires: Install-Module ExchangeOnlineManagement
# Requires: Connect-IPPSSession -UserPrincipalName <UPN>
Get-DlpSensitiveInformationType -Identity "<GUID>" | Select-Object Name, Id, Publisher
```

**After resolution:** Offer to save the mapping to `config.json` for future runs.

#### Post-Resolution Persistence (MANDATORY)

After Tier 3 PowerShell resolution completes, **always offer** to persist the resolved GUIDs:

> "I resolved N SIT GUIDs via PowerShell. Would you like me to save these to `config.json` under `sit_mapping` so future runs resolve them automatically via Tier 2?"

If the user agrees, read the current `config.json`, add/merge a `sit_mapping` object with the resolved GUIDs, and write it back. Format:

```json
{
  "sit_mapping": {
    "<guid>": "<resolved-name>",
    "<guid>": "<resolved-name>"
  }
}
```

**Why this matters:** Without persistence, every new session re-encounters the same unresolved GUIDs. The first report in a workspace should resolve and persist; subsequent runs benefit automatically.

### Trainable Classifiers

GUIDs with `ClassifierType: "MLModel"` are **trainable classifiers** and may not resolve via `Get-DlpSensitiveInformationType`. Display them as:
- `[ML Classifier] <GUID>` if unresolved
- Check if the GUID appears in the well-known mapping (some trainable classifiers have known GUIDs)

---

## Label GUID Mapping Strategy

### The Problem

`DataSecurityEvents` has **4 label-related columns**, all containing sensitivity label **GUIDs** (not names):

| Column | Type | Content |
|--------|------|---------|
| `SensitivityLabelId` | string | Label on the document at event time. Can contain **comma-separated GUIDs** (one per sub-entity) |
| `PreviousSensitivityLabelId` | string | Previous label — only populated on label-change events (downgrade, removal) |
| `SharepointSiteSensitivityLabelId` | string | Label on the SharePoint site (not the document) |
| `RiskyAIUsageSensitivityLabelsInfo` | Collection(String) | Labels on resources Copilot accessed in risky AI events — JSON array of objects with `SubEntityId`, `SubEntityName`, `SensitivityLabelId` |

### Resolution Strategy (3 tiers, in order)

#### Tier 1: Embedded Well-Known Label Mapping (instant, no auth)

The query library includes a `datatable` of **Microsoft default sensitivity labels** (the `defa4170-*` GUID family). All 12 default labels — including parent labels — use the deterministic pattern `defa4170-0d19-0005-XXXX-bc88714345d2`, confirmed across multiple tenants.

> **⚠️ Important:** Microsoft does not publish default label GUIDs in official documentation. The GUID pattern is confirmed via `Get-Label` on default-configuration tenants. Older tenants may have **renamed** default labels (e.g., "Non-business" instead of "Personal", "Internal exception" instead of "Anyone (unrestricted)") or **replaced** default parent label GUIDs with random tenant-specific ones. Always validate with `Get-Label` (Tier 3) when accuracy matters.

**Default Label GUID Pattern:** `defa4170-0d19-0005-XXXX-bc88714345d2` — complete mapping (12 labels, priority-ordered):

| GUID suffix | Priority | Default Name | Parent |
|-------------|----------|--------------|--------|
| `0000` | 0 | Personal | (top-level) |
| `0001` | 1 | Public | (top-level) |
| `0002` | 2 | General | (top-level) |
| `0003` | 3 | Anyone (unrestricted) | General |
| `0004` | 4 | All Employees (unrestricted) | General |
| `0005` | 5 | **Confidential** | (top-level, **parent**) |
| `0006` | 6 | Anyone (unrestricted) | Confidential |
| `0007` | 7 | All Employees | Confidential |
| `0008` | 8 | Trusted People | Confidential |
| `0009` | 9 | **Highly Confidential** | (top-level, **parent**) |
| `000a` | 10 | All Employees | Highly Confidential |
| `000b` | 11 | Specified People | Highly Confidential |

> **Older/customized tenants:** Admins may have renamed default labels or deleted and recreated parent labels with random GUIDs. If `Get-Label` returns a different GUID for "Confidential" or "Highly Confidential" (not matching `defa4170-*`), the tenant has custom parent labels — add them via `config.json` (Tier 2).

#### Tier 2: User-Provided Custom Label Mapping (config-driven)

Custom labels (org-created) have random GUIDs. Users can provide a mapping in `config.json`:

```json
{
  "label_mapping": {
    "<custom-label-guid-1>": "Your Custom Label",
    "<sub-label-guid>": "Sub-Label Name|Parent Label Name",
    "<parent-label-guid>": "Confidential"
  }
}
```

**Value format:** `"LabelName"` for top-level labels, `"LabelName|ParentName"` (pipe-delimited) for sub-labels. When building the KQL `datatable`, split on `|` to populate `LabelName` and `LabelParent` columns.

**Renamed defaults:** If a tenant has renamed default labels (e.g., `defa4170...0000` → "Non-business" instead of "Personal"), include the renamed GUID in `label_mapping` — Tier 2 entries override Tier 1 defaults.

**At skill startup:** Check if `config.json` has a `label_mapping` section. If yes, merge it into the KQL `datatable` for name resolution. Tier 2 entries take precedence over Tier 1 defaults for the same GUID.

#### Tier 3: PowerShell Resolution (optional, on-demand)

If unresolved label GUIDs remain after Tier 1+2, **offer** to resolve them via PowerShell:

> "I found N label GUIDs that aren't in the built-in mapping. Would you like me to resolve them via `Get-Label`? This requires an active Security & Compliance PowerShell session (`Connect-IPPSSession`)."

If the user agrees:

```powershell
# Requires: Install-Module ExchangeOnlineManagement
# Requires: Connect-IPPSSession -UserPrincipalName <UPN>
Get-Label | Select-Object DisplayName, @{N='LabelGuid';E={$_.Guid.ToString()}}, ParentLabelDisplayName | Format-List
```

**After resolution:** Offer to save the mapping to `config.json` under `label_mapping` for future runs (same persistence pattern as SIT mapping).

> **Key difference from SIT resolution:** Labels use `Get-Label` (not `Get-DlpSensitiveInformationType`). The cmdlet returns ALL labels at once — no need to query by individual GUID.

---

## Output Modes

**ASK the user which they prefer** if not explicitly specified. Both may be selected.

### Mode 1: Inline Chat Summary (Default)
- Render analysis directly in chat
- Includes summary tables, top-N breakdowns, risk-ranked user list
- Best for quick review and follow-up questions

### Mode 2: Markdown File Report
- Save to `reports/data-security/DataSecurity_Analysis_<scope>_<timestamp>.md`
- Full detail including all phases, temporal charts, file inventories
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename pattern:** `DataSecurity_Analysis_<scope>_YYYYMMDD_HHMMSS.md`
  - `<scope>` = `tenant_wide`, `sit_<SITname>`, `user_<username>`, etc.

---

## Quick Start (TL;DR)

1. **Determine scope** → Tenant-wide overview? Specific SIT? Specific user? Specific label? Time range?
2. **Check config.json** → Look for `sit_mapping` and `label_mapping` sections for custom name resolution
3. **Run Phase 1** → Query 1 (SIT Discovery) + Label Coverage Assessment (quick stats variant) to determine environment maturity
4. **Run Phase 2** → Queries 2-5 (breakdowns by action type, user, file, time)
5. **Run Phase 2.5** → Queries 16a-16d (Copilot SIT exposure analysis) — **conditional on Copilot volume** (see Phase 2.5 trigger)
6. **Run Phase 3** → Queries 6-8 (DLP correlation, workload, SIT drill-down), Query 10b (file-based spikes)
7. **Run Phase 4** → Queries 11-15 (label landscape, label-based user ranking, label downgrades, Copilot label exposure, label-only events) — **depth depends on label coverage** (see Rule 11)
8. **Output Results** → Render in selected mode(s), offer PowerShell resolution for unknowns

---

## Execution Workflow

### Phase 1: Discovery & Mapping (always run first)

**Goal:** Establish what SITs and labels exist in the data, their volume, and resolve GUIDs to names.

1. Run **Query 1** (SIT Discovery) — returns top SIT GUIDs with hit counts
2. Run **Label Coverage Assessment** (quick stats from Query 11 comment block) — returns label vs SIT coverage percentages
3. Apply Tier 1 mapping (embedded `datatable`) to resolve known SIT and label GUIDs
4. Check `config.json` for Tier 2 mapping (`sit_mapping` + `label_mapping`) to resolve custom GUIDs
5. Flag any remaining unresolved GUIDs for optional Tier 3 (PowerShell)
6. Present the SIT + label landscape to the user before proceeding
7. **Determine label analysis depth** based on coverage (see Rule 11)

### Phase 2: Breakdown Analysis

**Goal:** Decompose SIT access patterns by multiple dimensions.

Run these queries in parallel where possible:

| Query | Dimension | Purpose |
|-------|-----------|---------|
| Query 2 | **Action Type** | What operations triggered SIT detections (file read, download, copy, Copilot response, etc.) |
| Query 3 | **User Ranking** | Top users by SIT interaction volume — risk-ranked |
| Query 4 | **File Inventory** | Top files/documents containing the most SIT detections |
| Query 5 | **Temporal Pattern** | Daily/hourly volume trend to spot spikes |

### Phase 2.5: Copilot SIT Exposure Analysis (conditional on Copilot volume)

**Trigger:** Run this phase when **Copilot/AI events exceed 30% of total volume** (determined from Query 2 Action Type breakdown or Query 7 Workload breakdown).

**Goal:** Decompose Copilot SIT interactions by priority tier, identify users prompting high-value SITs into Copilot, separate service account noise from human risk signals, and estimate real interaction counts (correcting for row multiplication).

**Key insight:** Each Copilot interaction generates **~2-3 DSE rows on average** (up to 35 for complex exchanges) because Purview creates separate rows for prompt SIT matches, response SIT matches, and compound agent interactions. Raw event counts must be corrected for this multiplier when reporting interaction volumes.

| Query | Purpose |
|-------|---------|
| Query 16a | **Copilot SIT Landscape** — Which SITs fire in Copilot interactions, classified by priority tier (High/Medium/Low) |
| Query 16b | **Top Users by High-Priority SIT in Copilot** — Risk-ranked users excluding service accounts |
| Query 16c | **Daily Temporal Trend by SIT Category** — Spot adoption vs risk pattern changes over time |
| Query 16d | **Prompt-Only Human Users** — Users typing sensitive data INTO Copilot (primary risk signal), excluding service accounts and responses |

**Service Account Filtering:** Automated service accounts (e.g., Security Copilot agents, Purview agents) can generate 50-70% of all Copilot events. These accounts typically follow patterns like `securitycopilotagentuser-*`, `svc-*`, or system-generated UPN prefixes with GUIDs. Query 16a quantifies the agent vs human split; Queries 16b-16d exclude agents to surface human risk.

**Priority SIT Classification:** SITs are classified into tiers for Copilot risk assessment:

| Tier | SIT Categories | Risk Rationale |
|------|---------------|----------------|
| 🔴 **High** | Credit Card Numbers, SSNs, Azure/Cloud Credentials, Employee HR Data (custom) | Direct financial, identity, or infrastructure exposure |
| 🟡 **Medium** | Project code names (custom), Employee IDs (custom) | Business-sensitive but not directly exploitable |
| 🔵 **Low** | All Full Names, IP Addresses, Physical Addresses, Medical Terms | High-volume, low-specificity — noise in Copilot context |

> **Custom SIT classification:** Organizations should classify their custom/EDM SITs into these tiers. If `config.json` has a `sit_priority` section (mapping GUID → tier), use it. Otherwise, classify custom SITs as 🔴 High by default (conservative).

---

### Phase 3: Deep Dive (conditional on scope)

| Scenario | Run These |
|----------|-----------|
| **Tenant-wide overview** | Query 6 (DLP policy matches), Query 7 (Workload breakdown) |
| **Specific SIT investigation** | Query 8 (Single-SIT deep dive with full user/file/action breakdown) |
| **Specific user investigation** | Query 9 (Single-user SIT access profile) |
| **Anomaly detection** | Query 10b (file-based spikes — PRIMARY), Query 10 (overall spikes — secondary, includes Copilot) |

### Phase 4: Sensitivity Label Analysis (conditional on coverage)

**Goal:** Analyze sensitivity label access patterns, label changes, and Copilot label exposure.

**Run the Label Coverage Assessment first** (Phase 1, step 2). Then adapt depth per Rule 11:

| Label Coverage | Analysis Depth | Run These |
|---------------|----------------|----------|
| **≥5% of events have labels** (label-mature environment) | **Full label analysis** — dedicated report sections | Query 11 (label landscape), Query 12 (label-based user ranking), Query 13 (label changes), Query 14 (Copilot label exposure), Query 15 (label-only events) |
| **1-5% of events have labels** (emerging label environment) | **Summary label section** — condensed into one section | Query 11 (label landscape), Query 13 (label changes) |
| **<1% of events have labels** (SIT-dominant environment) | **Brief note only** — mention label presence in Scope & Limitations | Label coverage stats from Phase 1 assessment only |
| **User asks specifically about labels** | **Full label analysis** regardless of coverage percentage | All label queries (11-15) |

### Phase 5: Report Generation

Render findings using the Report Template below.

---

## Sample KQL Queries

### Well-Known SIT GUID Mapping (datatable)

Use this `let` block as a prefix for any query that needs name resolution. It covers the most common Microsoft SITs plus placeholders for custom SITs from `config.json`.

```kql
// Well-known SIT GUID mapping — covers ~90% of typical detections
// Add custom/EDM SIT GUIDs from config.json sit_mapping section
let SITMapping = datatable(SITId: string, SITName: string) [
    // ── Financial ──
    "50842eb7-edc8-4019-85dd-5a5c1f2bb085", "Credit Card Number",
    "cb353f78-2b72-4c3c-8827-92ebe4f69fdf", "ABA Routing Number",
    "78e09124-f2c3-4656-b32a-c1a132cd2711", "Brazil CPF Number",
    // ── Identity / PII ──
    "a44669fe-0d48-453d-a9b1-2cc83f2cba77", "U.S. Social Security Number (SSN)",
    "a7dd5e5f-e7f9-4626-a2c6-86a8cb6830d2", "IP Address v4",
    "1daa4ad5-e2dd-4ca4-a788-54722c09efb2", "IP Address",
    "50b8b56b-4ef8-44c2-a924-03374f5831ce", "All Full Names",
    "8548332d-6d71-41f8-97db-cc3b5fa544e6", "All Physical Addresses",
    "44aa44f2-63d1-41df-af0d-970283ac41e2", "U.S. Physical Addresses",
    "d1d18c85-1203-46f5-b32f-2d6309de4e5b", "Australia Physical Addresses",
    "6fa57f91-314a-4561-8248-7ab921957448", "Philippines Passport Number",
    "d0001c83-e72f-4360-98d3-f5a41dc5a380", "Indonesia Passport Number",
    // ── Healthcare ──
    "065bdd91-ef07-40d3-b8a4-0aea722eaa49", "All Medical Terms And Conditions",
    "17066377-466d-43ff-997f-c9240414021c", "Diseases",
    "f6dc2d17-3549-41e2-af29-ae1846ae9542", "Types Of Medication",
    "ee05bb9c-7b87-42e1-9987-446b243245d5", "Lab Test Terms",
    // ── Azure / Cloud secrets ──
    "0f587d92-eb28-44a9-bd1c-90f2892b47aa", "Azure DocumentDB Auth Key",
    "ce1a126d-186f-4700-8c0c-486157b953fd", "Azure SQL Connection String",
    "0b34bec3-d5d6-4974-b7b0-dcdb5c90c29d", "Azure IoT Connection String",
    "c7bc98e8-551a-4c35-a92d-d2c8cda714a7", "Azure Storage Account Key",
    "095a7e6c-efd8-46d5-af7b-5298d53a49fc", "Azure Redis Cache Connection String",
    // ─── ADD CUSTOM / EDM SITs FROM config.json sit_mapping HERE ───
    // Example: "<your-edm-guid>", "Your EDM SIT Name",
    "END_MARKER", "END_MARKER"
];
```

> **Instructions:** When building queries, read `config.json` for `sit_mapping` entries and insert them into the `datatable` above, replacing the `END_MARKER` row. If no custom mapping exists, remove the `END_MARKER` row.

---

### Query 1: SIT Discovery — Active SIT Landscape

**Purpose:** Find all active SIT GUIDs, their volume, and classify them.

```kql
// Query 1: SIT Discovery — What SITs are active in this environment?
// Adjust timespan as needed (default: 30d)
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| extend ClassifierType = tostring(SITJson.ClassifierType)
| extend SITConfidence = toint(SITJson.Confidence)
| extend SITCount = toint(SITJson.Count)
| summarize 
    TotalEvents = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId),
    AvgConfidence = avg(SITConfidence),
    MaxConfidence = max(SITConfidence),
    ClassifierTypes = make_set(ClassifierType)
    by SITId
| order by TotalEvents desc
| take 50
```

**Post-processing:** Join results with the `SITMapping` datatable to resolve names. Flag any GUIDs not in the mapping as "Unknown — custom/EDM SIT" or "[ML Classifier]" based on `ClassifierTypes`.

---

### Query 2: Action Type Breakdown

**Purpose:** Break down SIT detections by what operation triggered them.

```kql
// Query 2: Action Type Breakdown — What operations trigger SIT detections?
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize 
    EventCount = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId)
    by ActionType
| order by EventCount desc
```

---

### Query 3: Top Users by SIT Interaction Volume

**Purpose:** Risk-rank users by sensitive data interaction volume. Designed for 100k+ user environments.

```kql
// Query 3: Top 50 Users by SIT access volume
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize 
    TotalEvents = count(),
    DistinctSITs = dcount(tostring(parse_json(tostring(parse_json(tostring(SensitiveInfoTypeInfo))[0])).SensitiveInfoTypeId)),
    DistinctFiles = dcount(ObjectId),
    ActionTypes = make_set(ActionType),
    Workloads = make_set(Workload),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn
| order by TotalEvents desc
| take 50
```

---

### Query 4: Top Files by SIT Detection Count

**Purpose:** Identify the most sensitive documents — files with the most SIT detections across access events.

```kql
// Query 4: Top 30 Files by SIT detection frequency
// Excludes system/operational files (DLPCache, EBWebView) that are Defender operational reads, not user-initiated
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| where isnotempty(ObjectId)
| where ObjectId !has "DLPCache" and ObjectId !has "EBWebView" and ObjectId !has "\\ProgramData\\Microsoft\\Windows Defender\\"
| summarize 
    AccessCount = count(),
    DistinctUsers = dcount(AccountUpn),
    ActionTypes = make_set(ActionType),
    LastAccessed = max(Timestamp)
    by ObjectId
| order by AccessCount desc
| take 30
```

---

### Query 5: Temporal Pattern — Daily SIT Event Volume

**Purpose:** Detect volume spikes or anomalies in SIT-related activity over time.

```kql
// Query 5: Daily SIT event volume trend — includes file-based column for spike attribution (Rule 10)
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize 
    DailyEvents = count(), 
    FileEvents = countif(Workload !in ("Copilot", "ConnectedAIApp")),
    DistinctUsers = dcount(AccountUpn) 
    by Day = bin(Timestamp, 1d)
| order by Day asc
```

---

### Query 6: DLP Policy Match Correlation

**Purpose:** Show DLP policy matches alongside SIT detections — which policies fired and how often.

```kql
// Query 6: DLP Policy Match breakdown
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(DlpPolicyMatchInfo)
| extend DlpInfo = parse_json(DlpPolicyMatchInfo)
| mv-expand DlpPolicy = DlpInfo
| extend PolicyName = tostring(DlpPolicy.PolicyName)
| extend PolicyId = tostring(DlpPolicy.PolicyId)
| summarize 
    MatchCount = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId),
    ActionTypes = make_set(ActionType)
    by PolicyName
| order by MatchCount desc
```

---

### Query 7: Workload Breakdown

**Purpose:** Where is sensitive data being accessed — SharePoint, OneDrive, Exchange, Teams, Endpoints, Copilot?

```kql
// Query 7: Workload distribution of SIT events
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize 
    EventCount = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId)
    by Workload
| order by EventCount desc
```

---

### Query 8: Single-SIT Deep Dive

**Purpose:** Full breakdown for a specific SIT GUID — who accessed it, which files, what operations, over what time period.

> **Usage:** Replace `<TARGET_SIT_GUID>` with the specific SIT GUID to investigate (e.g., an EDM SIT GUID).

```kql
// Query 8: Single-SIT deep dive — replace GUID
let targetSIT = "<TARGET_SIT_GUID>";
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| where SensitiveInfoTypeInfo has targetSIT
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| where SITId == targetSIT
| extend SITConfidence = toint(SITJson.Confidence)
| extend SITCount = toint(SITJson.Count)
| summarize 
    AccessCount = count(),
    AvgConfidence = avg(SITConfidence),
    TotalSITInstances = sum(SITCount),
    ActionTypes = make_set(ActionType),
    Workloads = make_set(Workload),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn, ObjectId
| order by AccessCount desc
| take 100
```

---

### Query 9: Single-User SIT Access Profile

**Purpose:** Complete SIT interaction profile for a specific user — what SITs they accessed, which files, operations, and when.

> **Usage:** Replace `<TARGET_UPN>` with the user's UPN.

```kql
// Query 9: Single-user SIT access profile
let targetUser = "<TARGET_UPN>";
DataSecurityEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ targetUser
| where isnotempty(SensitiveInfoTypeInfo)
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| extend SITConfidence = toint(SITJson.Confidence)
| extend SITCount = toint(SITJson.Count)
| summarize 
    AccessCount = count(),
    DistinctFiles = dcount(ObjectId),
    AvgConfidence = avg(SITConfidence),
    ActionTypes = make_set(ActionType),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by SITId
| order by AccessCount desc
```

---

### Query 10: Anomaly Detection — Users with SIT Access Spikes

**Purpose:** Compare each user's recent 7-day SIT activity against their 30-day daily average to detect sudden spikes. Designed for 100k+ user environments.

```kql
// Query 10: SIT access spike detection (7d recent vs 23d baseline) — ALL events
// NOTE: This includes Copilot events. For file-based-only spikes, use Query 10b below.
let baseline = DataSecurityEvents
| where Timestamp between (ago(30d) .. ago(7d))
| where isnotempty(SensitiveInfoTypeInfo)
| summarize BaselineTotal = count() by AccountUpn
| extend BaselineDailyAvg = round(BaselineTotal / 23.0, 1); // 23 days in baseline window
let recent = DataSecurityEvents
| where Timestamp > ago(7d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize RecentTotal = count() by AccountUpn
| extend RecentDailyAvg = round(RecentTotal / 7.0, 1);
recent
| join kind=inner baseline on AccountUpn
| extend SpikeRatio = round(RecentDailyAvg / BaselineDailyAvg, 2)
| where SpikeRatio > 2.0 and RecentTotal > 20 and BaselineTotal >= 10
| project AccountUpn, BaselineDailyAvg, RecentDailyAvg, SpikeRatio, BaselineTotal, RecentTotal
| order by SpikeRatio desc
| take 30
```

---

### Query 10b: File-Based-Only Spike Detection (Excludes Copilot)

**Purpose:** Same as Query 10 but excludes Copilot and ConnectedAIApp events to surface actual file access spikes. This is the primary risk signal — Copilot spikes often just reflect adoption changes.

```kql
// Query 10b: File-based SIT access spike detection (excludes Copilot/AI events)
let CopilotActionTypes = dynamic(["Risky prompt entered in Copilot", "Sensitive response received in Copilot",
    "Risky prompt entered in connected AI apps", "Sensitive response received in connected AI apps"]);
let baseline = DataSecurityEvents
| where Timestamp between (ago(30d) .. ago(7d))
| where isnotempty(SensitiveInfoTypeInfo)
| where not(ActionType has_any (CopilotActionTypes))
| where Workload !in ("Copilot", "ConnectedAIApp")
| summarize BaselineTotal = count() by AccountUpn
| extend BaselineDailyAvg = round(BaselineTotal / 23.0, 1);
let recent = DataSecurityEvents
| where Timestamp > ago(7d)
| where isnotempty(SensitiveInfoTypeInfo)
| where not(ActionType has_any (CopilotActionTypes))
| where Workload !in ("Copilot", "ConnectedAIApp")
| summarize RecentTotal = count() by AccountUpn
| extend RecentDailyAvg = round(RecentTotal / 7.0, 1);
recent
| join kind=inner baseline on AccountUpn
| extend SpikeRatio = round(RecentDailyAvg / BaselineDailyAvg, 2)
| where SpikeRatio > 2.0 and RecentTotal > 10 and BaselineTotal >= 10
| project AccountUpn, BaselineDailyAvg, RecentDailyAvg, SpikeRatio, BaselineTotal, RecentTotal
| order by SpikeRatio desc
| take 30
```

---

### Well-Known Label GUID Mapping (datatable)

Use this `let` block as a prefix for label queries that need name resolution. It covers the Microsoft default sensitivity labels plus placeholder slots for custom labels from `config.json`.

```kql
// Microsoft default sensitivity label GUID mapping — all 12 labels
// Confirmed via Get-Label on default-configuration tenants
// Older tenants may have renamed labels or replaced parent GUIDs — validate with Get-Label if needed
// Add custom labels from config.json label_mapping section
let LabelMapping = datatable(LabelId: string, LabelName: string, LabelParent: string) [
    // ── Microsoft Default Labels (defa4170-0d19-0005-XXXX-bc88714345d2 family) ──
    // Priority 0-11, sequential GUID suffixes
    "defa4170-0d19-0005-0000-bc88714345d2", "Personal", "",
    "defa4170-0d19-0005-0001-bc88714345d2", "Public", "",
    "defa4170-0d19-0005-0002-bc88714345d2", "General", "",
    "defa4170-0d19-0005-0003-bc88714345d2", "Anyone (unrestricted)", "General",
    "defa4170-0d19-0005-0004-bc88714345d2", "All Employees (unrestricted)", "General",
    "defa4170-0d19-0005-0005-bc88714345d2", "Confidential", "",
    "defa4170-0d19-0005-0006-bc88714345d2", "Anyone (unrestricted)", "Confidential",
    "defa4170-0d19-0005-0007-bc88714345d2", "All Employees", "Confidential",
    "defa4170-0d19-0005-0008-bc88714345d2", "Trusted People", "Confidential",
    "defa4170-0d19-0005-0009-bc88714345d2", "Highly Confidential", "",
    "defa4170-0d19-0005-000a-bc88714345d2", "All Employees", "Highly Confidential",
    "defa4170-0d19-0005-000b-bc88714345d2", "Specified People", "Highly Confidential",
    // ─── ADD CUSTOM LABELS FROM config.json label_mapping HERE ───
    // Example: "<your-custom-label-guid>", "Your Custom Label", "Parent Label",
    "END_MARKER", "END_MARKER", "END_MARKER"
];
```

> **Instructions:** When building queries, read `config.json` for `label_mapping` entries and insert them into the `datatable` above, replacing the `END_MARKER` row. **Older/customized tenants:** If `Get-Label` shows parent labels (Confidential, Highly Confidential) with random GUIDs instead of `defa4170-*`, the admin has recreated them — add the tenant-specific GUIDs from `config.json` `label_mapping` or `Get-Label`. If resolved sub-label names differ from the datatable (e.g., "Non-business" vs "Personal"), prefer the `Get-Label` name for that tenant.

---

### Query 11: Label Coverage Overview — Sensitivity Label Landscape

**Purpose:** Discover which sensitivity labels appear in the data, their volume, and resolve GUIDs to names. Also includes a quick stats variant for Phase 1 coverage assessment.

**Quick Stats Variant (run first in Phase 1):**

```kql
// Label Coverage Assessment — run in Phase 1 to determine label analysis depth
DataSecurityEvents
| where Timestamp > ago(30d)
| summarize
    TotalEvents = count(),
    WithSIT = countif(isnotempty(SensitiveInfoTypeInfo) and SensitiveInfoTypeInfo != "[]"),
    WithLabel = countif(isnotempty(SensitivityLabelId)),
    WithPrevLabel = countif(isnotempty(PreviousSensitivityLabelId)),
    LabelOnly_NoSIT = countif(isnotempty(SensitivityLabelId) and (isempty(SensitiveInfoTypeInfo) or SensitiveInfoTypeInfo == "[]")),
    SIT_WithLabel = countif(isnotempty(SensitivityLabelId) and isnotempty(SensitiveInfoTypeInfo) and SensitiveInfoTypeInfo != "[]")
```

**Full Label Landscape Query:**

```kql
// Query 11: Label Landscape — which sensitivity labels appear and how often
// Prefix with LabelMapping datatable from above
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitivityLabelId)
| extend LabelIds = split(SensitivityLabelId, ",")
| mv-expand LabelIdRaw = LabelIds
| extend LabelId = tostring(trim(" ", tostring(LabelIdRaw)))
| where isnotempty(LabelId)
| lookup kind=leftouter LabelMapping on LabelId
| extend LabelDisplay = iff(isempty(LabelName) or LabelName == "END_MARKER",
    strcat("[Unknown] ", LabelId),
    iff(isempty(LabelParent), LabelName, strcat(LabelParent, " / ", LabelName)))
| summarize
    EventCount = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId),
    ActionTypes = make_set(ActionType)
    by LabelDisplay, LabelId
| order by EventCount desc
```

**Post-processing:** Flag any `[Unknown]` GUIDs for Tier 2/3 resolution. The `LabelDisplay` column renders as "Parent / Child" for sub-labels (e.g., "Highly Confidential / Project Obsidian") and just the label name for top-level labels.

---

### Query 12: Top Users by Labeled Document Access (File-Based)

**Purpose:** Risk-rank users by labeled document access volume, excluding Copilot/AI events. This is the label-dimension equivalent of Query 3.

```kql
// Query 12: Top users by labeled document access (file-based only)
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitivityLabelId)
| where ActionType !has "Copilot" and Workload !in ("Copilot", "ConnectedAIApp")
| summarize
    EventCount = count(),
    DistinctLabels = dcount(SensitivityLabelId),
    DistinctFiles = dcount(ObjectId),
    ActionTypes = make_set(ActionType),
    Workloads = make_set(Workload),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn
| order by EventCount desc
| take 30
```

---

### Query 13: Label Downgrade & Change Tracking

**Purpose:** Find all events where a sensitivity label was downgraded, removed, or changed. Critical for detecting policy circumvention or insider risk.

```kql
// Query 13: Label downgrade/removal events — detect label circumvention
// Prefix with LabelMapping datatable to resolve both current and previous label GUIDs
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(PreviousSensitivityLabelId)
| extend CurrentLabelId = SensitivityLabelId
| extend PrevLabelId = PreviousSensitivityLabelId
| lookup kind=leftouter (LabelMapping | project LabelId, CurrentLabelName=LabelName, CurrentParent=LabelParent) on $left.CurrentLabelId == $right.LabelId
| lookup kind=leftouter (LabelMapping | project LabelId, PrevLabelName=LabelName, PrevParent=LabelParent) on $left.PrevLabelId == $right.LabelId
| extend CurrentDisplay = iff(isempty(CurrentLabelName), iff(isempty(CurrentLabelId), "[Removed]", strcat("[Unknown] ", CurrentLabelId)),
    iff(isempty(CurrentParent), CurrentLabelName, strcat(CurrentParent, " / ", CurrentLabelName)))
| extend PrevDisplay = iff(isempty(PrevLabelName), strcat("[Unknown] ", PrevLabelId),
    iff(isempty(PrevParent), PrevLabelName, strcat(PrevParent, " / ", PrevLabelName)))
| project Timestamp, ActionType, AccountUpn, ObjectId,
    PreviousLabel = PrevDisplay, CurrentLabel = CurrentDisplay, Workload
| order by Timestamp desc
```

**Key ActionTypes in label change events:**
- `Label downgraded on a file` — label lowered (e.g., HC → Confidential)
- `Label removed from a file` — label stripped entirely
- `Label on file downgraded or removed, then file accessed by Copilot` — label reduced AND Copilot accessed the now-less-protected file

---

### Query 14: Copilot Label Exposure — Labeled Resources Accessed by Copilot

**Purpose:** Identify which sensitivity-labeled documents Copilot accessed during risky AI interactions. This surfaces data exposure risk where Copilot may be surfacing Highly Confidential content.

```kql
// Query 14: Copilot label exposure — what labeled docs did Copilot access in risky interactions?
// Prefix with LabelMapping datatable
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(RiskyAIUsageSensitivityLabelsInfo)
| where tostring(RiskyAIUsageSensitivityLabelsInfo) !has "null"
    or (tostring(RiskyAIUsageSensitivityLabelsInfo) has "null" and tostring(RiskyAIUsageSensitivityLabelsInfo) has "SensitivityLabelId")
| mv-expand LabelEntry = parse_json(tostring(RiskyAIUsageSensitivityLabelsInfo))
| extend LabelJson = parse_json(tostring(LabelEntry))
| extend SubEntityName = tostring(LabelJson.SubEntityName)
| extend LabelId = tostring(LabelJson.SensitivityLabelId)
| where isnotempty(LabelId)
| lookup kind=leftouter LabelMapping on LabelId
| extend LabelDisplay = iff(isempty(LabelName) or LabelName == "END_MARKER",
    strcat("[Unknown] ", LabelId),
    iff(isempty(LabelParent), LabelName, strcat(LabelParent, " / ", LabelName)))
| summarize
    EventCount = count(),
    DistinctUsers = dcount(AccountUpn),
    SubEntities = make_set(SubEntityName),
    ActionTypes = make_set(ActionType)
    by LabelDisplay, LabelId
| order by EventCount desc
```

**SubEntityName values:**
- `ResponseAccessedResource` — a labeled document that Copilot cited in its response
- `Response` — the Copilot response itself that was flagged

---

### Query 15: Label-Only Events — Events Triggered Purely by Label (No SIT Content Match)

**Purpose:** Find events where the trigger was the sensitivity label alone, not SIT content detection. These represent label-aware DLP/IRM policy matches.

```kql
// Query 15: Label-only events — triggered by label, not SIT content
// Prefix with LabelMapping datatable
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitivityLabelId)
| where isempty(SensitiveInfoTypeInfo) or SensitiveInfoTypeInfo == "[]"
| extend LabelIds = split(SensitivityLabelId, ",")
| mv-expand LabelIdRaw = LabelIds
| extend LabelId = tostring(trim(" ", tostring(LabelIdRaw)))
| where isnotempty(LabelId)
| lookup kind=leftouter LabelMapping on LabelId
| extend LabelDisplay = iff(isempty(LabelName) or LabelName == "END_MARKER",
    strcat("[Unknown] ", LabelId),
    iff(isempty(LabelParent), LabelName, strcat(LabelParent, " / ", LabelName)))
| summarize
    EventCount = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId),
    ActionTypes = make_set(ActionType),
    Workloads = make_set(Workload)
    by LabelDisplay, LabelId
| order by EventCount desc
```

**Why this matters:** In label-mature environments, this query can surface significant activity that the SIT-only queries completely miss. If a document has a "Highly Confidential" label but no SIT content (e.g., manually labeled strategic document), it only appears here.

---

### Query 16a: Copilot SIT Landscape with Priority Tiers

**Purpose:** Break down which SITs fire in Copilot interactions, classify by priority tier, and quantify service account vs human split. This is the entry point for Phase 2.5.

> **Prerequisite:** Merge the well-known SIT GUID mapping datatable (above) with any `config.json` `sit_mapping` entries before running.

```kql
// Query 16a: Copilot SIT Landscape — priority-tiered breakdown with agent/human split
// Prefix with SITMapping datatable
// ── SIT Priority Classification (canonical definition — Queries 16c/16d reference this) ──
let HighPrioritySITs = dynamic([
    "50842eb7-edc8-4019-85dd-5a5c1f2bb085",  // Credit Card Number
    "a44669fe-0d48-453d-a9b1-2cc83f2cba77",  // U.S. SSN
    "0f587d92-eb28-44a9-bd1c-90f2892b47aa",  // Azure DocumentDB Auth Key
    "ce1a126d-186f-4700-8c0c-486157b953fd",  // Azure SQL Connection String
    "0b34bec3-d5d6-4974-b7b0-dcdb5c90c29d",  // Azure IoT Connection String
    "c7bc98e8-551a-4c35-a92d-d2c8cda714a7",  // Azure Storage Account Key
    "095a7e6c-efd8-46d5-af7b-5298d53a49fc"   // Azure Redis Cache Connection String
    // ── ADD credential/HR SIT GUIDs from config.json sit_mapping HERE ──
]);
let MediumPrioritySITs = dynamic([
    // ── ADD project/employee ID SIT GUIDs from config.json sit_mapping HERE ──
]);
// ── Service account regex (update with org-specific patterns) ──
let ServiceAccountPattern = @"^(securitycopilotagentuser-|svc-)";
DataSecurityEvents
| where Timestamp > ago(30d)
| where ActionType has "Copilot"
| where isnotempty(SensitiveInfoTypeInfo)
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| extend IsAgent = AccountUpn matches regex ServiceAccountPattern
| summarize
    TotalEvents = count(),
    AgentEvents = countif(IsAgent),
    HumanEvents = countif(not(IsAgent) and isnotempty(AccountUpn)),
    HumanUsers = dcountif(AccountUpn, not(IsAgent) and isnotempty(AccountUpn)),
    PromptEvents = countif(ActionType has "prompt"),
    ResponseEvents = countif(ActionType has "response")
    by SITId
| lookup kind=leftouter SITMapping on $left.SITId == $right.SITId
| extend SITDisplay = iff(isempty(SITName) or SITName == "END_MARKER", strcat("[Unknown] ", SITId), SITName)
| extend PriorityTier = case(
    SITId in (HighPrioritySITs), "🔴 High",
    SITId in (MediumPrioritySITs), "🟡 Medium",
    "🔵 Low")
| project SITDisplay, PriorityTier, TotalEvents, AgentEvents, HumanEvents, HumanUsers, PromptEvents, ResponseEvents, SITId
| order by TotalEvents desc
```

**Post-processing:**
- Populate `HighPrioritySITs` and `MediumPrioritySITs` arrays with credential, HR, and custom SIT GUIDs from `config.json` `sit_mapping`. Any SIT not in either array defaults to Low.
- If `config.json` has a `sit_priority` section (GUID → tier mapping), use it to override the default classification.
- Calculate **Agent % of total** — if > 50%, flag prominently in report ("⚠️ N% of Copilot SIT events are from automated service accounts").
- Unknown SITs (`[Unknown]`) should be classified as 🔴 High by default (conservative — unknown custom SITs may be high-value EDM/exact data match).

---

### Query 16b: Top Users by High-Priority SIT in Copilot (Excluding Service Accounts)

**Purpose:** Risk-rank human users whose Copilot interactions triggered high-priority SIT detections. Excludes automated service accounts.

```kql
// Query 16b: Top 20 human users by high-priority SIT in Copilot interactions
// Prefix with SITMapping datatable and HighPrioritySITs + ServiceAccountPattern from Query 16a
DataSecurityEvents
| where Timestamp > ago(30d)
| where ActionType has "Copilot"
| where isnotempty(SensitiveInfoTypeInfo)
| where not(AccountUpn matches regex ServiceAccountPattern)
| where isnotempty(AccountUpn)
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| where SITId in (HighPrioritySITs)
| lookup kind=leftouter SITMapping on $left.SITId == $right.SITId
| extend SITDisplay = iff(isempty(SITName) or SITName == "END_MARKER", strcat("[Unknown] ", SITId), SITName)
| summarize
    Events = count(),
    DistinctHighSITs = dcount(SITId),
    SITNames = make_set(SITDisplay),
    PromptEvents = countif(ActionType has "prompt"),
    ResponseEvents = countif(ActionType has "response"),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn
| order by Events desc
| take 20
```

---

### Query 16c: Daily Copilot SIT Trend by Priority Category

**Purpose:** Track daily Copilot SIT detection volume by priority tier to distinguish adoption changes from risk spikes.

```kql
// Query 16c: Daily Copilot SIT trend by priority category (human users only)
// ── Copy HighPrioritySITs from Query 16a (canonical list: CCN, SSN, Azure credentials + config.json custom) ──
// ── Copy ServiceAccountPattern from Query 16a ──
DataSecurityEvents
| where Timestamp > ago(30d)
| where ActionType has "Copilot"
| where isnotempty(SensitiveInfoTypeInfo)
| where not(AccountUpn matches regex ServiceAccountPattern)
| where isnotempty(AccountUpn)
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| extend PriorityTier = iff(SITId in (HighPrioritySITs), "High", "Low")
| summarize Events = count() by Day = bin(Timestamp, 1d), PriorityTier
| order by Day asc, PriorityTier asc
```

**Post-processing:** Render as a dual-line chart or table with High vs Low columns per day. Spikes in the High tier warrant investigation; spikes in Low tier alone are typically noise from broad SITs (All Full Names, IP Addresses) and can be noted but not escalated.

---

### Query 16d: Prompt-Only Analysis — Human Users Typing Sensitive Data INTO Copilot

**Purpose:** The primary risk signal — users who typed sensitive data into Copilot prompts (not just receiving sensitive responses). Excludes service accounts and response-only events.

```kql
// Query 16d: Prompt-only human users with high-priority SIT detections
// This is the key risk signal: sensitive data entered BY the user INTO Copilot
// ── Copy HighPrioritySITs and ServiceAccountPattern from Query 16a ──
DataSecurityEvents
| where Timestamp > ago(30d)
| where ActionType has "prompt"  // Prompts only — user-initiated risk
| where isnotempty(SensitiveInfoTypeInfo)
| where not(AccountUpn matches regex ServiceAccountPattern)
| where isnotempty(AccountUpn)
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| where SITId in (HighPrioritySITs)
| lookup kind=leftouter SITMapping on $left.SITId == $right.SITId
| extend SITDisplay = iff(isempty(SITName) or SITName == "END_MARKER", strcat("[Unknown] ", SITId), SITName)
| summarize
    PromptEvents = count(),
    DistinctHighSITs = dcount(SITId),
    SITNames = make_set(SITDisplay),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn
| order by PromptEvents desc
| take 20
```

**Why prompts matter more than responses:**
- **"Risky prompt entered in Copilot"** = User typed/pasted sensitive data (SSN, credit card, credentials) into a Copilot prompt. This is a behavioral risk — the user chose to share sensitive data with AI.
- **"Sensitive response received in Copilot"** = Copilot retrieved and surfaced sensitive data from grounding sources (SharePoint, OneDrive, email). This is an access/configuration risk — overpermissioned data exposure.
- Prompt events are the stronger signal for insider risk and user coaching interventions.

---

## Report Template

### Report Rendering Rules

**These rules are MANDATORY for all report output (inline chat and markdown file). Follow strictly.**

#### Rule 1: Risk Rating Scale

When assigning risk levels to users in the file-based user ranking, use this hierarchy:

| Risk Level | Evidence Required |
|------------|------------------|
| **Critical** | "Files collected and exfiltrated" ActionType present — confirmed insider risk exfiltration signal **OR** mass exfiltration pattern: ≥1,000 distinct files to removable media + file deletions within a ≤48-hour window (volume-based escalation even without the IRM-labeled ActionType) |
| **High** | Exfiltration signals below Critical thresholds (e.g., USB copies < 1,000 files without deletion pattern) OR sustained high DLP alert volume (top 2-3 by events/files) |
| **Medium** | Broad SIT diversity (10+ SIT types) OR cross-workload activity (3+ workloads) OR external domain WITHOUT explicit exfiltration signal |
| **Low** | Single-workload, moderate volume, no exfiltration or anomaly signals |

⛔ **PROHIBITED:** Rating a user with "Files collected and exfiltrated" as Medium or Low. This ActionType is always High or Critical.
⛔ **PROHIBITED:** Rating a user with ≥1,000 files USB-copied + deletion in ≤48h as anything below Critical.

#### Rule 2: Executive Summary Uses File-Based Metrics Only

The Executive Summary **MUST** cite file-based (non-Copilot) event counts and file counts for user risk descriptions. Never cite overall metrics that include Copilot volume — this inflates perceived risk.

| Context | Cite | Example |
|---------|------|---------|
| ✅ File-based risk summary | Non-Copilot events, non-Copilot files | "u3087 generated 211 file-based events across 32 files" |
| ❌ Inflated overall metrics | Total events including Copilot | ~~"u1812 — 294 total events including 185 files"~~ |

#### Rule 3: Top Users Overall Section — Copilot Compression

When Copilot events exceed 80% of total volume:
- **Do NOT render** a standalone "Top Users Overall" section dominated by Copilot service accounts
- Instead, include a brief note: "Top overall users are dominated by Copilot service accounts/heavy Copilot users — see file-based user ranking below for actual data access risk."
- If any users in the top-10 overall have **multi-workload activity** (Copilot + file operations), call them out in a single sentence rather than a full table

#### Rule 4: Copilot Count Reconciliation

When reporting Copilot vs file-based splits, ensure the counts reconcile across sections:
- Action Type breakdown Copilot total = Workload breakdown Copilot total
- If they differ (e.g., Connected AI App events counted differently), annotate the delta
- Show the reconciliation in the Action Type section: "Copilot interactions: N events (Action Types: Risky prompt X + Sensitive response Y + Combined Z = N)"

#### Rule 5: Scope & Limitations Section (Required for Markdown Reports)

Markdown file reports MUST include a **Scope & Limitations** section immediately after the Executive Summary. Include:

```markdown
## Scope & Limitations

| Consideration | Detail |
|--------------|--------|
| **Data Source** | DataSecurityEvents (Defender XDR Advanced Hunting) — requires Insider Risk Management opt-in to share data with Defender XDR |
| **Coverage** | SIT detections + sensitivity label events — files with neither SIT content match nor sensitivity label do NOT appear in this data |
| **Label Coverage** | X% of events have sensitivity labels — label analysis depth adjusted accordingly (see Rule 11) |
| **Retention** | 30-day Advanced Hunting retention |
| **ML Classifiers** | N trainable classifier GUIDs could not be resolved — see Unresolved SIT GUIDs section |
| **Copilot Volume** | Copilot events represent X% of total volume and are separated from file-based analysis throughout this report |
```

Fill in the actual values for N and X% from the query results.

#### Rule 6: SIT Landscape Table Integrity

- Each GUID must appear **exactly once** in the SIT Landscape table — one row per GUID, no exceptions
- **NEVER group multiple GUIDs into a single row** with slash-separated values (e.g., `1e883268/d2cdc387/bf6e0b84...`). Even "copy" variants of the same SIT that share identical metrics MUST be separate rows
- After all GUID resolution tiers complete, deduplicate by GUID — if conflicts exist, prefer the most specific resolution (Tier 3 PowerShell > Tier 2 config > Tier 1 embedded)
- Group the table by category: Custom/Organization SITs, Built-in Microsoft SITs, ML Classifiers (Unresolvable)
- Do NOT include a GUID under two different names
- The total distinct SIT count cited in the Executive Summary must equal the number of rows in the SIT Landscape tables (sum of all category sub-tables)
- **Post-render verification (MANDATORY):** After building all SIT Landscape sub-tables, count the total rows. If the exec summary cites a different number, update the exec summary to match. Format: "N active SIT types" where N = sum of rows across Custom, Built-in, and Unresolved sub-tables

⛔ **PROHIBITED:** Bundling GUIDs like "Credit Card Number copy (x3)" with `6,966 ea.` — each of the 3 GUIDs must be its own row with its own exact counts
⛔ **PROHIBITED:** Exec summary citing a SIT count that doesn't match the actual row count in the SIT Landscape tables

#### Rule 7: Spike Detection — File-Based Primary, Overall Secondary

When rendering spike alerts:
- **Primary:** Always run and display **Query 10b** (file-based-only spikes) as the main spike alert section. This surfaces actual sensitive data access spikes.
- **Secondary:** Run Query 10 (all events) only if the user requests overall spikes or if there are interesting patterns worth noting. Include a clear note that these spikes are predominantly Copilot-driven.
- If only running one spike query, always prefer Query 10b.
- In the report, label sections clearly: "File-Based SIT Access Spikes" vs "Overall SIT Access Spikes (incl. Copilot)".

#### Rule 8: Top Files — Exclude System/Operational Files

The Top Files section must exclude Defender for Endpoint operational file reads:
- `C:\ProgramData\Microsoft\Windows Defender\DLPCache\*` — DLP label metadata cache reads
- `*\EBWebView\*` — Edge WebView browser cache
- Any path matching `\ProgramData\Microsoft\` that is clearly a system/cache path

If system files appear in results despite the query filter, separate them into a "System/Operational Files" subsection below the main "User-Accessed Files" list.

#### Rule 9: Risk Rating Consistency — Exec Summary Must Match User Table

Every user mentioned in the Executive Summary MUST use the **same risk rating** as in the File-Based Top Users table. If the table says 🔴 Critical, the exec summary must say Critical (and vice versa).

- After building the File-Based Top Users table (the source of truth), cross-check every user mention in the exec summary
- If there is a conflict, the User Table rating wins — update the exec summary to match
- Never rate a user differently in two sections of the same report

⛔ **PROHIBITED:** Exec summary says "High" while user table says "Critical" for the same user (or any other mismatch).

#### Rule 10: Temporal Pattern — Include File-Based Event Column

The Temporal Pattern (daily volume) section MUST include a `File Events` column alongside the total. Without this, daily spikes appear alarming when they may be entirely Copilot-driven.

| Column | Required | Source |
|--------|----------|--------|
| Date | ✅ | `bin(Timestamp, 1d)` |
| Daily Events | ✅ | Total `count()` |
| **File Events** | ✅ | `countif(Workload !in ("Copilot", "ConnectedAIApp"))` |
| Distinct Users | ✅ | `dcount(AccountUpn)` |
| Notable | ✅ | Annotation for spikes |

When annotating spikes (🔴), clarify whether the spike is Copilot-driven or file-driven:
- "🔴 Major spike — file-driven" (if File Events also spike)
- "🟡 Copilot adoption spike — file activity normal" (if only total spikes but File Events are stable)

Use Query 5 (updated) which returns both columns.

#### Rule 11: Adaptive Label Analysis Depth

The depth of sensitivity label analysis MUST be determined dynamically based on the Phase 1 Label Coverage Assessment. This prevents wasting queries in SIT-dominant environments while ensuring full coverage in label-mature environments.

| Label Coverage | Report Behavior |
|---------------|----------------|
| **≥5% labeled events** | Full dedicated label sections: Label Landscape table, Label-Based Top Users, Label Changes, Copilot Label Exposure, Label-Only Events. These render as peer sections alongside SIT analysis |
| **1-5% labeled events** | Condensed "Sensitivity Labels" section: Label Landscape table + Label Changes only. Other label dimensions mentioned in summary notes |
| **<1% labeled events** | Brief note in Scope & Limitations: "Sensitivity label data is sparse (<1% of events) — environment is SIT-dominant. N events had labels; see label coverage stats below." No dedicated label sections unless user asks |
| **User explicitly asks about labels** | Full label sections regardless of coverage percentage |

The Label Coverage Assessment also determines the overall report framing:
- **SIT-dominant** (<5% labels): Report title/framing stays "SIT Access Analysis" with label addendum
- **Dual signal** (5-50% labels): Report framing becomes "Data Security Analysis (SIT + Labels)"
- **Label-dominant** (>50% labels): Report framing becomes "Data Security Analysis" with labels as primary signal and SIT as secondary

⛔ **PROHIBITED:** Running all 5 label queries (11-15) when coverage is <1% and user didn't ask about labels — this wastes API calls and clutters the report.

#### Rule 12: Label Display Format — Always Show Parent/Child Hierarchy

When rendering sensitivity label names, ALWAYS show the parent-child hierarchy using "/" notation:

| Raw Label | Correct Display | Incorrect Display |
|-----------|----------------|------------------|
| Sub-label under Highly Confidential | "Highly Confidential / All Employees" | "All Employees" |
| Sub-label under Confidential | "Confidential / All employees" | "All employees" |
| Top-level label | "General" | "General" (correct as-is) |
| Unknown label | "[Unknown] abc12345..." | blank or omitted |

This prevents ambiguity — "All Employees" exists under BOTH Confidential and Highly Confidential as different labels with different GUIDs.

⛔ **PROHIBITED:** Displaying sub-label names without their parent (e.g., just "Specific people" — which parent?).

#### Rule 13: Service Account Separation in Copilot Analysis

All Copilot SIT analysis MUST separate **automated service accounts** from **human users**. Service accounts (Security Copilot agents, Purview agents, etc.) can generate 50-70% of Copilot event volume and must not inflate human risk metrics.

| Requirement | Detail |
|-------------|--------|
| **Identify service accounts** | Filter: `AccountUpn matches regex ServiceAccountPattern` (defined in Query 16a: `@"^(securitycopilotagentuser-\|svc-)"`). Check Query 16a results for additional org-specific patterns (any account with >10K events and a GUID-like UPN prefix is likely automated) |
| **Report agent volume separately** | Include a summary line: "⚠️ N automated service accounts generated X events (Y% of Copilot volume) — excluded from human risk analysis below" |
| **Never mix in user rankings** | Queries 16b-16d exclude agents by default. If rendering an overall Copilot user table, agents go in a separate subsection |
| **Power-user flagging** | After agent exclusion, if any single human user accounts for >20% of remaining Copilot events, flag them: "⚠️ Power user — may indicate automated workflow via Copilot" |

⛔ **PROHIBITED:** Including automated service accounts in human user risk rankings for Copilot SIT analysis.
⛔ **PROHIBITED:** Reporting raw Copilot event counts as "user interactions" without noting the ~2-3x row multiplication factor.

#### Rule 14: Copilot Event Row Multiplication Awareness

Each Copilot interaction generates **multiple DSE rows** (average ~2-3x, up to 35x for complex exchanges). Purview creates separate rows for:
- The **prompt** (if it contains a SIT match) — "Risky prompt entered in Copilot"
- The **response** (if grounding data contains SIT matches) — "Sensitive response received in Copilot"
- **Compound events** — agent interactions, SharePoint access, multiple simultaneous conditions

| Reporting Requirement | Format |
|----------------------|--------|
| Raw event counts | "N Copilot SIT events (raw DSE rows)" |
| Estimated interactions | "~N/2.5 estimated real interactions" (use the ratio from the environment if calculated) |
| User daily rates | If citing per-user daily rates, note whether raw or estimated: "~X interactions/day (estimated from Y raw events)" |

This rule prevents stakeholders from seeing "270K Copilot events" and panicking when the actual interaction count is ~95K.

#### Rule 15: Copilot SIT Report Section (Phase 2.5 Output)

When Phase 2.5 is triggered (Copilot >30% of events), render a dedicated **"Copilot SIT Exposure"** section with:

1. **Service Account vs Human Split** — "X events from N service accounts (Y%), Z events from N human users (Y%)" with the agent exclusion note
2. **SIT Priority Landscape** — Table from Query 16a showing SITs by priority tier (High/Medium/Low) with human-only metrics
3. **High-Priority SIT Users** — Top 10 human users from Query 16b with prompt vs response breakdown
4. **Prompt Risk Signal** — Top 10 users from Query 16d who typed high-priority SITs into Copilot prompts — this is the primary actionable finding
5. **Temporal Trend** — Daily trend from Query 16c (optional — include if spikes are interesting)

If Copilot events are <30% of total, skip Phase 2.5 entirely and note in the Copilot section: "Copilot events represent X% of total volume — below threshold for dedicated analysis. See Action Type breakdown for Copilot summary."

---

### Inline Chat Format

```markdown
## 📊 Data Security Events Analysis
**Scope:** <Tenant-wide / SIT: <name> / User: <UPN>>
**Time Range:** <start> to <end>
**Total Events:** <N> | **Distinct Users:** <N> | **Distinct Files:** <N>

### SIT Landscape
| # | SIT Name | GUID (short) | Events | Users | Files | Classifier |
|---|----------|-------------|--------|-------|-------|------------|
| 1 | Credit Card Number | 50842eb7... | 7,255 | 46 | 346 | Content |
| 2 | All Full Names | 50b8b56b... | 128,957 | 1,475 | 119 | Content |
| ... | | | | | | |

### Action Type Breakdown
| Action Type | Events | Users | Files |
|-------------|--------|-------|-------|
| Sensitive response received in Copilot | 228,564 | ... | ... |
| Risky prompt entered in Copilot | 390,905 | ... | ... |
| ... | | | |

### 🔴 Top Users by SIT Volume (Risk-Ranked)
| # | User | Total Events | Distinct SITs | Distinct Files | Last Active |
|---|------|-------------|---------------|----------------|-------------|
| 1 | user@domain.com | 12,345 | 8 | 42 | 2026-03-16 |
| ... | | | | | |

### 🏷️ Sensitivity Label Landscape (if ≥1% coverage)
| # | Label | GUID (short) | Events | Users | Files |
|---|-------|-------------|--------|-------|-------|
| 1 | Highly Confidential / All Employees | defa4170...000a | 62 | 9 | 31 |
| 2 | General | defa4170...0002 | 55 | 12 | 32 |
| ... | | | | | |

### ⚠️ Label Changes (if any PreviousSensitivityLabelId events exist)
| Timestamp | User | File | Previous Label | Current Label | Action |
|-----------|------|------|---------------|--------------|--------|
| 2026-03-11 | user@domain.com | doc.docx | HC / Project X | Confidential / All employees | Label downgraded |
| ... | | | | | |

### 🤖 Copilot SIT Exposure (if Copilot >30% of events)
**Service Accounts:** N agents generated X events (Y%) — excluded from analysis below
**Row Multiplication:** ~2-3 DSE rows per real interaction (est. ~Z real interactions)

| # | SIT Name | Priority | Human Events | Human Users | Prompts | Responses |
|---|----------|----------|-------------|-------------|---------|----------|
| 1 | Credit Card Number | 🔴 High | 1,234 | 89 | 456 | 778 |
| 2 | All Full Names | 🔵 Low | 45,678 | 1,200 | 12,345 | 33,333 |
| ... | | | | | | |

**🔴 Prompt Risk — Users Typing High-Priority SITs Into Copilot:**
| # | User | Prompt Events | SIT Types | Last Active |
|---|------|-------------|-----------|-------------|
| 1 | user@domain.com | 142 | SSN, Credit Card | 2026-03-16 |
| ... | | | | |

### ⚠️ SIT Access Spike Alerts
| User | Baseline (daily avg) | Recent (daily avg) | Spike Ratio | Status |
|------|---------------------|-------------------|-------------|--------|
| user@domain.com | 5.2 | 47.1 | 9.06x | 🔴 Spike |
| ... | | | | |

### Unresolved SIT GUIDs
<List of GUIDs not in mapping — offer PowerShell resolution>
```

### Markdown File Format

Same structure as inline, wrapped in proper markdown with:
- Report metadata header (generated timestamp, scope, tool versions)
- **Scope & Limitations section** immediately after Executive Summary (see Rule 5 above)
- Each section as H2/H3
- **File-based user ranking** as the primary risk section (NOT the Copilot-dominated overall ranking)
- DLP Policy Match section with DefaultRule explanation for empty PolicyName entries
- **Sensitivity Label sections** (if coverage ≥1% or user requested): Label Landscape, Label-Based Top Users, Label Changes, Copilot Label Exposure
- Code fences for any raw data samples
- Save to: `reports/data-security/DataSecurity_Analysis_<scope>_YYYYMMDD_HHMMSS.md`

---

## Known Pitfalls

| Pitfall | Detail | Mitigation |
|---------|--------|------------|
| **`SensitiveInfoTypeInfo` is `Collection(String)`, not dynamic** | Each element is a JSON **string** requiring double-parse: `parse_json(tostring(SensitiveInfoTypeInfo))` to expand array, then `parse_json(tostring(element))` to access fields | Always double-parse. Direct dot-notation fails silently |
| **Massive row counts** | 600k+ rows in 30 days for mid-size tenants; millions for 100k+ user orgs | ALWAYS `summarize` first. NEVER retrieve raw rows without `take` limit |
| **`mv-expand` is expensive** | Expanding SensitiveInfoTypeInfo across 600k rows without pre-filtering is extremely slow | Pre-filter with `where SensitiveInfoTypeInfo has "<GUID>"` before `mv-expand` |
| **Copilot dominates event volume** | 90%+ of events can be Copilot-related. See **Rules 2-3** for report handling and **Phase 2.5** for dedicated Copilot analysis | Filter to specific `ActionType` values for file access. Use `Workload !in ("Copilot", "ConnectedAIApp")` for file-only analysis |
| **Trainable classifiers (MLModel) don't resolve** | GUIDs with `ClassifierType: "MLModel"` may not exist in `Get-DlpSensitiveInformationType` | Display as `[ML Classifier] <GUID>` and note in report |
| **SIT GUID is per-SIT, not per-detection** | Multiple documents can match the same SIT GUID — the GUID identifies the SIT **type**, not the specific match | Use `Count` and `Confidence` fields from SITJson for detection-level detail |
| **`ObjectId` can be empty** | Copilot interaction events may not have an ObjectId (no specific file) | Filter `isnotempty(ObjectId)` for file-specific analysis |
| **IRM opt-in required** | DataSecurityEvents is populated by Insider Risk Management. No opt-in = empty table | Check for 0 results and explain the prerequisite |
| **Table schema evolves** | DataSecurityEvents is in **Preview** — column names and availability may change | Run `getschema` if queries fail with column resolution errors |
| **`DlpPolicyMatchInfo` is sparse** | Only ~0.5% of rows have DLP policy match data (the rest are IRM-only detections) | Don't assume all SIT events have DLP data; they're independent signals |
| **Duplicate GUID in SIT mapping** | One GUID can only resolve to one SIT name. If a GUID appears in both the embedded `datatable` and a Tier 2/3 resolution with a different name, the result will have duplicate rows with conflicting names. This can happen when a built-in SIT GUID overlaps with a custom SIT copy, or when PowerShell returns a different display name than the embedded mapping | After resolving all GUIDs, **deduplicate by GUID** before rendering the SIT Landscape table. If a GUID maps to multiple names, prefer the Tier 3 (PowerShell) name over Tier 1 (embedded). Never show the same GUID on two rows with different names |
| **Empty `PolicyName` = DefaultRule ("Always audit")** | DLP alerts with empty/null `PolicyName` are typically generated by the built-in `DefaultRule` that fires when "Always audit file activity for devices" is enabled (ON by default). These are NOT orphaned or misconfigured policies — they are the expected result of the default audit setting | In the DLP Policy Match section, explain: "Events with empty PolicyName are generated by the built-in DefaultRule, which audits all monitored file types (Office, PDF, CSV) on onboarded devices when 'Always audit file activity for devices' is enabled (default: ON). No explicit DLP policy is required for these events." |
| **Compound ActionType values** | Some events have ActionType values that combine multiple labels (e.g., "Risky prompt entered in Copilot, Sensitive response received in Copilot" or "Sensitive info shared on Teams, DLP Rule Matched"). These are literal string values from the data, not aggregation artifacts | Display compound ActionTypes exactly as they appear in the data. Do NOT split or merge them — they represent events where multiple conditions were met simultaneously |
| **System/operational files dominate Top Files** | Files under `C:\ProgramData\Microsoft\Windows Defender\DLPCache\RMSLabels\` and `*\EBWebView\*` are Defender for Endpoint reading sensitivity label metadata — NOT user-initiated file access. These can dominate 90%+ of the Top Files list | Query 4 filters these paths. If they still appear, separate into a "System/Operational Files" subsection. Never present DLPCache reads as user data access risk |
| **Localized SIT names in CloudAppEvents** | CloudAppEvents `DLPRuleMatch` events include SIT names, but names appear **in the user's locale** (e.g., "የዱቤ ካርድ ቁጥር" instead of "Credit Card Number" for Amharic users). Same GUID can map to different name strings depending on locale | Always aggregate by **SIT GUID**, never by SIT name. Use the GUID-to-name mapping (Tier 1/2/3) for canonical English names. This applies when cross-referencing CloudAppEvents with DataSecurityEvents |
| **Browsing events are not files — separate from Top Files** | ActionTypes like "Generative AI websites browsed" and "Gambling websites browsed" reference URLs, not files. They have no `ObjectId` file path — only a URL domain. Including them under "Top Files" is misleading | Render browsing/URL events in a separate subsection (e.g., "External / AI Service Access") below Top Files. Never mix URL-based events into the file ranking tables. Title the Top Files section accurately ("Top Files" not "Top Files & URLs") |
| **Temporal spike annotations must reference known users** | When annotating daily spikes in the Temporal Pattern table (e.g., "🔴 Major spike — u625 SharePoint batch"), the attributed user MUST appear elsewhere in the report — in the File-Based Top Users table, a drill-down section, or at minimum a footnote. Referencing a user that exists nowhere else in the report violates the evidence-based analysis rule and creates an unverifiable claim | Before annotating a spike with a user attribution, verify the user appears in the Top Users ranking. If they don't make the top-10 but are the spike driver, either: (a) add them to the user table with a note "included due to temporal spike attribution", or (b) use a generic annotation ("🔴 Major spike — file-driven") without naming the user |
| **`SensitivityLabelId` can contain comma-separated GUIDs** | When an event involves multiple sub-entities (e.g., Copilot accessing multiple labeled resources), the `SensitivityLabelId` column contains comma-separated GUIDs like `aaaa-...,aaaa-...,bbbb-...`. This is NOT a single GUID | Always `split(SensitivityLabelId, ",")` then `mv-expand` to handle multi-GUID values. Querying with `== "<GUID>"` will miss events; use `has "<GUID>"` for filtering or `split()` + `mv-expand` for enumeration |
| **`RiskyAIUsageSensitivityLabelsInfo` is mostly `[null]`** | The column is populated on 90%+ of Copilot events, but almost all contain `[null]` (a JSON array with a literal null element). Only events where Copilot actually accessed labeled resources have real data | Filter with `tostring(RiskyAIUsageSensitivityLabelsInfo) !has "null"` to exclude the null-dominated rows. The `isnotempty()` check alone is insufficient — `[null]` passes it |
| **Label GUIDs have no `ClassifierType` field** | Unlike SIT GUIDs which have `ClassifierType: "Content"` or `"MLModel"`, label GUIDs have no built-in type indicator. Resolution requires external lookup (datatable, config, or PowerShell `Get-Label`) | Use the Label GUID Mapping Strategy (3 tiers). Unknown labels display as `[Unknown] <GUID>` |
| **Default label GUIDs are deterministic but not officially documented** | All 12 default labels (including parents) use `defa4170-0d19-0005-XXXX-bc88714345d2` with sequential suffixes `0000`–`000b` (confirmed via `Get-Label` on default-configuration tenants). However, Microsoft does not publish these GUIDs in official docs. **Older/customized tenants** may have: (a) renamed default labels (e.g., "Non-business" instead of "Personal"), (b) replaced parent label GUIDs with random tenant-specific ones, or (c) added custom sub-labels that break the sequential pattern | The embedded datatable includes all 12 confirmed default GUIDs. For tenants with custom parent GUIDs, add them via `config.json` `label_mapping`. If `Get-Label` returns different names for a `defa4170` GUID, prefer the `Get-Label` name for that tenant |
| **`PreviousSensitivityLabelId` can equal `SensitivityLabelId`** | On "Label removed from a file" events, both fields may contain the same GUID (the label that was removed). The current label after removal may be empty | Check `ActionType` to distinguish: "Label downgraded" = actual label change; "Label removed" = label stripped (current may be empty); "Label on file downgraded or removed, then file accessed by Copilot" = compound event with Copilot exposure |
| **Label-only events require label-aware DLP/IRM policies** | Events with labels but no SIT content (Query 15) only appear if a DLP or IRM policy explicitly targets sensitivity labels. Environments with no label-based policies will see zero label-only events even if documents are labeled | If Query 15 returns 0 results AND labels exist (Query 11 > 0), this indicates no label-based DLP/IRM policies are configured — mention this as a gap in the report |
| **Copilot service accounts inflate event counts** | Automated service accounts can generate 50-70% of all Copilot events. See **Rule 13** for full requirements | Filter: `where not(AccountUpn matches regex ServiceAccountPattern)` (defined in Query 16a). Run Query 16a to quantify agent vs human split |
| **Copilot row multiplication (~2-3x per interaction)** | Each interaction generates ~2-3 DSE rows (prompt + response + compound events), up to 35 for complex exchanges. See **Rule 14** for reporting requirements | Estimate real interactions as `raw_events / 2.5`. Always include multiplier context when reporting Copilot volumes |
| **Correct field name is `SensitiveInfoTypeId` (not `SensitiveType`)** | Inside the `SensitiveInfoTypeInfo` JSON, the SIT GUID field is named `SensitiveInfoTypeId`. LLMs frequently generate `SensitiveType` or `SensitiveTypeId` — both are wrong and return null/empty when accessed | Always use `tostring(SITJson.SensitiveInfoTypeId)`. Other valid fields: `Confidence` (int), `ClassifierType` (string), `Count` (int), `SubEntityName` (string — "Prompt" or "Response" in Copilot events) |
| **`SubEntityName` distinguishes Prompt vs Response in Copilot SIT events** | Inside `SensitiveInfoTypeInfo` JSON, `SubEntityName` contains "Prompt" or "Response" — indicating whether the SIT was detected in the user's prompt or Copilot's response. This is more reliable than relying on `ActionType` text matching for prompt/response classification within individual SIT matches | Use `tostring(SITJson.SubEntityName)` when doing per-SIT prompt/response breakdowns. `ActionType` classifies the event-level action; `SubEntityName` classifies the per-SIT-match context |

---

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `Failed to resolve table 'DataSecurityEvents'` | Table not available — IRM not opted in, or not connected to Defender XDR | Inform user: "DataSecurityEvents requires Microsoft Purview Insider Risk Management opt-in to share data with Defender XDR." |
| `0 results` for SensitiveInfoTypeInfo queries | No SIT detections in timeframe, or SIT detection not enabled in IRM policies | Widen time range; check if IRM policies include SIT detection |
| `Failed to resolve column 'ObjectName'` | Schema changed or column renamed | Use `ObjectId` instead (confirmed available). Run `getschema` to verify current schema |
| PowerShell `Get-DlpSensitiveInformationType` fails | Not connected to IPPS session | Run `Connect-IPPSSession -UserPrincipalName <UPN>` first |
| `The term 'Get-DlpSensitiveInformationType' is not recognized` | Module not installed or IPPS session in different terminal | `Install-Module ExchangeOnlineManagement` then `Connect-IPPSSession` in the same terminal session |
| `The term 'Get-Label' is not recognized` | Not connected to IPPS session or module not loaded | Same as above — `Connect-IPPSSession` provides both `Get-DlpSensitiveInformationType` and `Get-Label` |
| Label GUIDs all show as `[Unknown]` | Default label datatable doesn't match target tenant (parent GUIDs vary) | Resolve via `Get-Label` and persist to `config.json` `label_mapping` |

---

## File Access Action Types Reference

When the user specifically asks about **who opened/accessed/downloaded documents**, filter to these ActionTypes:

| ActionType | Meaning |
|------------|---------|
| `Sensitive File read` | File opened on endpoint (Defender for Endpoint) |
| `File accessed on SPO` | File opened in SharePoint Online / OneDrive |
| `File downloaded from SharePoint` | File downloaded from SPO/OneDrive |
| `File copied to Removable media` | File copied to USB/removable storage |
| `File upload to cloud` | File uploaded to cloud storage |
| `Sensitive file created` | New file created with sensitive content |
| `File Archived` | File moved to archive |
| `Text copied to clipboard from sensitive file` | Clipboard copy from sensitive doc |

**Copilot-related ActionTypes** (separate category — AI interaction, not direct file access):

| ActionType | Meaning |
|------------|---------|
| `Sensitive response received in Copilot` | Copilot surfaced content matching a SIT |
| `Risky prompt entered in Copilot` | User prompt triggered risk detection |
| `Sensitive response received in Copilot;Agent generating sensitive responses` | Copilot agent generated response containing SIT matches |
| `Risky prompt entered in Copilot;Sensitive response received in Copilot` | Both prompt and response contained SIT matches |
| `Risky prompt entered in Copilot;Sensitive response received in Copilot;Exposing agent to risky prompts;Agent generating sensitive responses` | Compound agent event — prompt + response + agent risk |
| `Risky prompt entered in Copilot;Exposing agent to risky prompts` | User exposed a Copilot agent to a risky prompt |

**Label-related ActionTypes** (sensitivity label events):

| ActionType | Meaning |
|------------|--------|
| `Label downgraded on a file` | Sensitivity label lowered (e.g., HC → Confidential) |
| `Label removed from a file` | Sensitivity label stripped entirely |
| `Label on file downgraded or removed, then file accessed by Copilot` | Label reduced AND Copilot subsequently accessed the file |

**DLP ActionTypes:**

| ActionType | Meaning |
|------------|---------|
| `Generated High severity DLP alerts` | DLP policy triggered a high-severity alert |
| `DLP Rule Matched` | DLP rule matched (may be combined with other types) |

---

## SVG Dashboard Generation

After generating a Data Security Events analysis report (markdown file output), an SVG dashboard can be created using the shared SVG rendering skill.

**Trigger:** User asks "generate an SVG dashboard from the report" or "visualize this report"

**Workflow:**
1. Read this skill's `svg-widgets.yaml` (widget manifest — defines layout, colors, field mapping)
2. Read `.github/skills/svg-dashboard/SKILL.md` (rendering rules — component library, quality standards)
3. Extract data from the completed report using `data_sources.field_mapping_notes`
4. Render SVG → save as `{report_basename}_dashboard.svg` in the same directory

**Layout:** 5 rows — title banner, KPI cards (events/users/files/file%/copilot%/label%), top SITs bar chart + workload donut, risk-ranked users table + file action bars, assessment banner + recommendations.
