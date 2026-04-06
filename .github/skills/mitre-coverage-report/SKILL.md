---
name: mitre-coverage-report
description: 'MITRE ATT&CK Coverage Report — YAML-driven PowerShell pipeline gathers analytic rule MITRE tags, custom detection techniques, SOC Optimization recommendations, and alert/incident operational data via az rest/az monitor/Graph API, writes a deterministic scratchpad, LLM renders the report. Covers tactic-level coverage matrix, technique-level drill-down with rule mapping, coverage gap identification, SOC Optimization threat scenario alignment, untagged rule remediation, ICS/OT technique tracking, and MITRE Coverage Score (5 weighted dimensions). Inline chat and markdown file output.'
---

# MITRE ATT&CK Coverage Report — Instructions

## Purpose

This skill generates a comprehensive **MITRE ATT&CK Coverage Report** analyzing detection coverage across the ATT&CK Enterprise framework. It inventories all analytic rules and custom detections, maps them to MITRE tactics and techniques, identifies coverage gaps, and provides prioritized recommendations for improving detection posture.

**Entity Type:** Sentinel workspace (from `config.json`)

| Scope | Data Sources | Use Case |
|-------|--------------|----------|
| Workspace-wide (default) | Analytic Rules (REST), Custom Detections (Graph), SOC Optimization (REST), SecurityAlert/SecurityIncident (KQL) | Full MITRE coverage analysis |
| Operational correlation | SecurityAlert, SecurityIncident | Which MITRE-tagged rules actually produce alerts and incidents |

**What this report covers:** Tactic-level coverage matrix with per-tactic technique counts and percentages, technique-level drill-down with rule-to-technique mapping, coverage gap identification against the full ATT&CK Enterprise framework, SOC Optimization threat scenario alignment (AiTM, ransomware, BEC, etc.), untagged rule remediation with AI-suggested MITRE tags, ICS/OT technique tracking, operational MITRE correlation (which rules actually fire), and a composite MITRE Coverage Score.

**Complementary to:** This skill pairs with the `sentinel-ingestion-report` skill — ingestion report covers data volume, tier optimization, and cost; MITRE coverage report covers detection posture against the ATT&CK framework. Run both for a complete workspace assessment.

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────────────┐
 │  YAML query files        PowerShell script         LLM render   │
 │  queries/phase1-3/  ──→  Invoke-MitreScan.ps1  ──→  Phase 4    │
 │  (6 .yaml files)         (~1030 lines)             (SKILL-      │
 │                          • az rest (Sentinel API)   report.md)  │
 │                          • Invoke-MgGraphRequest                │
 │                          • az monitor (KQL)                     │
 │                          • mitre-attck-enterprise.json          │
 │                          • m365-platform-coverage.json (CTID)   │
 │                          ↓                                      │
 │                     temp/mitre_scratch_<ts>.md                  │
 │                     (~35 KB, 18+ sections)                     │
 └──────────────────────────────────────────────────────────────────┘
```

**Execution model:**
- **Phases 1-3** (data gathering): Fully automated by `Invoke-MitreScan.ps1`. Phase 1 uses `az rest` (Sentinel REST API) and optionally `Invoke-MgGraphRequest` (Graph API). Phase 2 uses `az rest` (SOC Optimization API). Phase 3 uses `az monitor log-analytics query` (KQL).
- **Phase 4** (rendering): LLM reads the scratchpad + `SKILL-report.md` and renders the report. This is the only phase requiring LLM involvement.

**Static reference:** `mitre-attck-enterprise.json` contains ATT&CK Enterprise v16.1 with 14 tactics, 216 techniques, and 475 sub-techniques. The PS1 loads this at startup to compute coverage gaps against the full framework. This file is version-controlled and should be updated when MITRE publishes new ATT&CK releases.

**Platform coverage reference:** `m365-platform-coverage.json` is a compact CTID (Center for Threat-Informed Defense) mapping of M365 Defender product capabilities to ATT&CK techniques. Contains detect/protect/respond coverage for 81 detect techniques across 38 capabilities (7 SecurityAlert product groups). Used for the 3-tier platform coverage classification:
- **Tier 1 (Alert-Proven):** SecurityAlert from M6 query has MITRE technique attribution — highest confidence
- **Tier 2 (Deployed Capability):** Product is active (has alerts) and CTID claims detect coverage for the technique — medium confidence
- **Tier 3 (Catalog Capability):** CTID maps coverage but no alert evidence for the product in this workspace — lowest confidence

To rebuild from upstream: download the [CTID M365 mapping JSON](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/), transform with PowerShell (group by parent technique, map capabilities to SecurityAlert ProductName). See `temp/ctid_raw.json` for the raw source.

---

## Companion Files — When to Load

| File | Purpose | When to Load |
|------|---------|--------------|
| **SKILL.md** (this file) | Architecture, workflow, rendering rules, score methodology, domain reference | Always — primary entry point |
| [SKILL-report.md](SKILL-report.md) | Report templates (§1-§6), section-to-scratchpad mapping, formatting rules | Phase 4 rendering only |
| [Invoke-MitreScan.ps1](Invoke-MitreScan.ps1) | PowerShell data-gathering pipeline (Phases 1-3) | Execution only — no need to read unless debugging |
| [mitre-attck-enterprise.json](mitre-attck-enterprise.json) | ATT&CK Enterprise v16.1 static reference | Referenced by PS1 at runtime — no manual loading |
| [m365-platform-coverage.json](m365-platform-coverage.json) | CTID M365 platform coverage reference (detect/protect/respond) | Referenced by PS1 at runtime — no manual loading |

---

## 📑 TABLE OF CONTENTS

1. **[Quick Start](#quick-start-tldr)** - 3-step execution pattern
2. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Prerequisites and prohibitions
3. **[Execution Workflow](#execution-workflow)** - Phases 0-4
4. **[Query File Reference](#query-file-reference)** - All 5 YAML files
5. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
6. **[Deterministic Rendering Rules](#deterministic-rendering-rules)** - Rules A-D (mandatory for Phase 4)
7. **[MITRE Coverage Score](#mitre-coverage-score)** - 5-dimension scoring methodology
8. **[Domain Reference](#domain-reference)** - ATT&CK interpretation, tactic priorities, Sentinel-specific mappings
9. **[SVG Dashboard Generation](#svg-dashboard-generation)** - Visual dashboard from completed report

---

## Quick Start (TL;DR)

**3-step execution pattern:**

```
Step 1:  Run Invoke-MitreScan.ps1 (Phases 1-3 — data gathering)
Step 2:  Read scratchpad + SKILL-report.md (Phase 4 prep)
Step 3:  Render full report (§1-§6) → create_file
```

### Step 1: Run Data Gathering

```powershell
# From workspace root — run all phases (default: 30 days alert/incident lookback):
& ".github/skills/mitre-coverage-report/Invoke-MitreScan.ps1"

# Specify a custom alert/incident lookback:
& ".github/skills/mitre-coverage-report/Invoke-MitreScan.ps1" -Days 7

# Run a specific phase (for re-runs / debugging):
& ".github/skills/mitre-coverage-report/Invoke-MitreScan.ps1" -Phase 1
```

**Output:** Scratchpad file at `temp/mitre_scratch_<timestamp>.md` (~28 KB, 12 sections).

**Timing:** Full run takes ~60-90 seconds (varying with REST API response times and KQL auth state).

### Step 2: Load Rendering Context

1. Read the scratchpad file (path printed by PS1 at completion)
2. Read [SKILL-report.md](SKILL-report.md) for rendering templates

### Step 3: Render Report (Single Write)

Render the **complete report (§1-§6)** in a single `create_file` call. Apply SKILL-report.md templates to scratchpad data, following Rules A-D. Write to the report file.

**⛔ Single-write requirement:** The entire report MUST be rendered in one `create_file` call. Do NOT split rendering across multiple tool calls.

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY MITRE coverage report:**

1. **Run `Invoke-MitreScan.ps1`** — this single script handles ALL data gathering (Phases 1-3). The LLM does NOT run queries, transcribe output, or write scratchpad sections
2. **Read `config.json`** for workspace ID, tenant, subscription, and Azure MCP parameters
3. **ALWAYS ask the user for output mode** if not specified: inline chat summary, markdown file report, or both (default: both)
4. **ALWAYS ask the user for timeframe** if not specified: the `-Days` parameter controls the alert/incident KQL lookback (Phase 3). Default: 30 days. Phases 1-2 (REST API) are not time-bounded
5. **ALWAYS use `create_file` for markdown reports** (never use terminal commands)
6. **ALWAYS sanitize PII** from saved reports — use generic placeholders for real rule names, workspace names, and tenant GUIDs in committed files
7. **Read scratchpad + SKILL-report.md** before rendering — the scratchpad is the sole data source
8. **Custom Detections may be SKIPPED** — the Graph API requires `CustomDetection.Read.All` which needs admin consent. If skipped, the report notes this and shows AR-only analysis. Do NOT treat SKIPPED as an error — it's a graceful degradation

### Prerequisites

| Dependency | Required By | Setup |
|------------|-------------|-------|
| **Azure CLI** (`az`) | All phases (REST + KQL) | Install: [aka.ms/installazurecli](https://aka.ms/installazurecli). Authenticate: `az login --tenant <tenant_id>` then `az account set --subscription <subscription_id>` |
| **Azure RBAC** | Phase 1-2 (REST API) | **Microsoft Sentinel Reader** on the workspace (analytic rule inventory + SOC Optimization) |
| **KQL auth** | Phase 3 (az monitor) | `az login` with `https://api.loganalytics.io/.default` scope (CA policy may enforce re-auth) |
| **Microsoft.Graph PowerShell** | Phase 1 M2 (Custom Detections) | `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`. Required scope: `CustomDetection.Read.All`. PS1 skips gracefully if unavailable |
| **PowerShell 7.0+** | Script execution | `#Requires -Version 7.0` |

### 🔴 PROHIBITED

- ❌ Running REST/KQL queries via MCP tools during data gathering — PS1 handles all queries
- ❌ Writing or modifying scratchpad sections manually — PS1 is the sole writer
- ❌ Fabricating technique counts, rule names, or coverage percentages
- ❌ Inventing ATT&CK technique IDs or names not in the reference JSON
- ❌ Overriding MITRE Coverage Score dimensions — the PS1 computes these deterministically
- ❌ Rendering the report without first reading the scratchpad file
- ❌ Reporting "100% coverage" for any tactic unless the data actually shows every technique covered

---

## Execution Workflow

### Phase 0: Initialization

1. Read `config.json` for `sentinel_workspace_id`, `subscription_id`, Azure MCP parameters
2. Confirm output mode and timeframe with user (pass `-Days` to PS1; default 30)
3. Verify prerequisites: `az login` session active, correct subscription set

### Phases 1-3: Data Gathering (automated by PS1)

Run `Invoke-MitreScan.ps1` — it handles all 3 phases automatically:

| Phase | Queries | Description | Execution Type |
|-------|---------|-------------|----------------|
| **1** | M1, M2 | Rule inventory — Analytic rules with MITRE tactics/techniques (REST), Custom Detection rules with mitreTechniques (Graph, graceful skip) | REST + Graph |
| **2** | M3 | SOC Optimization — Coverage recommendations with threat scenario context, MITRE tagging suggestions for untagged rules | REST |
| **3** | M4, M5, M6, M7, M8 | Operational correlation — SecurityAlert firing counts per rule with MITRE cross-reference, SecurityIncident volume by tactic, platform-native alert MITRE coverage, table ingestion volume for data readiness validation, data connector health from SentinelHealth | KQL |

**Post-processing (automated by PS1):**

| Task | Phase | Description |
|------|-------|-------------|
| Tactic coverage matrix | 1 | For each ATT&CK tactic, count enabled rules and covered techniques against the framework reference |
| Technique drill-down | 3 | Map every framework technique to its covering rules AND pre-compute tier/product annotations from CTID cross-reference |
| Untagged rule identification | 1 | Find rules with no MITRE tactics AND no techniques |
| ICS technique extraction | 1 | Separate T0xxx (ICS/OT) technique mappings |
| Threat scenario parsing | 2 | Extract active/recommended detection counts and per-tactic breakdowns from SOC Optimization |
| AI MITRE tagging suggestions | 2 | Extract suggested tactics/techniques for untagged rules. Cross-reference against Phase 1 actual rule tags to verify if suggestions were applied (emits `VerifyStatus`: Applied/Partial/NotApplied/NotFound per rule, plus summary counts `AR_TagsApplied`/`AR_TagsPartial`/`AR_TagsNotApplied`/`AR_TagsNotFound`) |
| Alert-to-MITRE correlation | 3 | Cross-reference firing alerts with Phase 1 MITRE tags |
| Active tactic coverage | 3 | Compute which tactics have rules that actually fire alerts |
| Platform alert MITRE extraction | 3 | Extract MITRE techniques attributed by platform-native product alerts (M6) |
| Product presence detection | 3 | Derive active M365 Defender products from SecurityAlert ProductName |
| CTID tier classification | 3 | Cross-reference active products with CTID mapping to classify techniques as Tier 1/2/3 |
| Combined tactic coverage | 3 | Merge custom rule and platform Tier 1/2 coverage per tactic |
| Data readiness cross-reference | 3 | Extract KQL table dependencies from rule queries, cross-reference with M7 ingestion volumes, classify rules as Ready/Partial/NoData |
| Connector health enrichment | 3 | Cross-reference M8 SentinelHealth connector status with Data Readiness — flag "Ready" rules whose feeding connector is degraded or failing |
| Table tier classification | 3 | Cross-reference M9 table tier metadata with rule KQL table dependencies — flag rules targeting Basic/Data Lake tier tables as "TierBlocked" (phantom coverage: rule structurally cannot fire regardless of data volume) |
| Coverage Score computation | All | Weighted composite score from 5 dimensions |

**Scratchpad output:** PS1 writes all results to `temp/mitre_scratch_<timestamp>.md` (~28 KB, ~12 named sections). See SKILL-report.md for the Section-to-Scratchpad Mapping.

### Phase 4: Render Output (LLM)

**🔴 MANDATORY — Load scratchpad + report template before rendering:**

1. **Read the scratchpad file** (path printed by PS1). This single file contains ALL data from Phases 1-3.
2. **Read [SKILL-report.md](SKILL-report.md)** for the complete rendering templates and formatting rules.

**Pre-render validation:**
1. Verify scratchpad has all 3 phase sections (PHASE_1 through PHASE_3)
2. Check SCORE section has all 5 dimensions
3. If Phase 3 shows FAILED for M4/M5 (token expiry), note this in the report — the Operational dimension defaults to 0

**Render — Section-by-Section:**

| Section | Data Source (scratchpad keys) | Required |
|---------|------------------------------|----------|
| §1 Executive Summary | All phases + SCORE | ✅ Coverage Score, Workspace at a Glance, Top 3 |
| §2 Tactic Coverage | PHASE_1.TacticCoverage | ✅ 14-tactic matrix with coverage % |
| §3 Technique Deep Dive | PHASE_3.TechniqueDetail (enriched with Tier/TierProducts) | ✅ Per-tactic technique tables with pre-computed tier badges |
| §4 Coverage Gap Analysis | PHASE_1.TacticCoverage + PHASE_3.TechniqueDetail + PHASE_2.ThreatScenarios | ✅ Gaps, priorities, threat scenario alignment |
| §5 Operational MITRE Correlation | PHASE_3.AlertFiring + IncidentsByTactic + ActiveTacticCoverage + PlatformAlertCoverage + PlatformTechniquesByTier + PlatformTacticCoverage + DataReadiness + DataReadiness_Summary + MissingTables + TierBlockedTables + ConnectorHealth + ConnectorHealth_Summary | ✅ Which rules fire, platform coverage, combined tactic view, data readiness, tier-blocked phantom coverage, connector health |
| §6 Recommendations | All phases | ✅ Untagged rule remediation, Content Hub suggestions, coverage priorities |

---

## Query File Reference

All queries are defined as YAML files in `queries/phase1-3/`.

### YAML Format

```yaml
id: mitre-m1                                   # Unique identifier
name: Analytic Rule MITRE Extraction            # Human-readable name
description: Fetch rules with tactics/techniques # What it does
phase: 1                                        # Which phase (1-3)
type: rest                                      # rest | graph | kql
url: https://management.azure.com/...           # REST API URL with placeholders
jmespath: value[].{...}                         # JMESPath projection (REST)
```

### Complete Query Inventory

| Phase | File | ID | Type | Description |
|-------|------|----|------|-------------|
| 1 | M1-AnalyticRuleMitre.yaml | mitre-m1 | rest | Scheduled + NRT analytic rules with MITRE tactics, techniques, severity, query text |
| 1 | M2-CustomDetectionMitre.yaml | mitre-m2 | graph | Custom Detection rules with mitreTechniques (graceful skip if auth unavailable) |
| 2 | M3-SocOptCoverage.yaml | mitre-m3 | rest | SOC Optimization coverage recommendations with threat scenarios and MITRE tagging suggestions |
| 3 | M4-AlertFiringByMitre.yaml | mitre-m4 | kql | SecurityAlert firing counts per rule with severity breakdown (30d lookback) |
| 3 | M5-IncidentsByTactic.yaml | mitre-m5 | kql | SecurityIncident volume by tactic with classification breakdown |
| 3 | M6-PlatformAlertCoverage.yaml | mitre-m6 | kql | Platform-native SecurityAlert detections with MITRE technique attribution (excludes custom rules) |
| 3 | M7-TableIngestionVolume.yaml | mitre-m7 | kql | 7-day average daily ingestion volume per table from Usage table for data readiness validation |
| 3 | M8-ConnectorHealth.yaml | mitre-m8 | kql | SentinelHealth data connector fetch status — latest state, success/failure counts, health % per connector (supplements M7 with early-warning connector failure detection) |
| 3 | M9-TableTierClassification.yaml | mitre-m9 | cli | Log Analytics table tier metadata (Analytics/Basic/Data Lake) via `az monitor log-analytics workspace table list` — identifies tables that analytics rules cannot query |

---

## Output Modes

### Mode 1: Inline Chat Summary (default for quick requests)
Compact executive summary rendered directly in chat with MITRE Coverage Score and top coverage gaps.

### Mode 2: Markdown File Report
Full detailed report saved to `reports/sentinel/mitre_coverage_report_<YYYYMMDD_HHMMSS>.md`.

### Mode 3: Both (default when user says "report" or "generate report")
Inline chat executive summary + full markdown file.

**Ask user if not specified:**
> "How would you like the MITRE coverage report? I can provide:
> 1. **Inline chat summary** — MITRE Score + top gaps in chat
> 2. **Markdown file** — detailed report saved to reports/sentinel/
> 3. **Both** (recommended) — summary in chat + full report file"

---

## Deterministic Rendering Rules

**These rules eliminate LLM interpretation variance. Apply them EXACTLY during Phase 4 rendering.**

### Rule A: Coverage Level Classification

Assign emoji badges to each tactic row in the coverage matrix based on the percentage of techniques covered:

| Coverage % | Badge | Level |
|------------|-------|-------|
| 0% | 🔴 | No coverage |
| 1-15% | 🟠 | Critical gap |
| 16-30% | 🟡 | Partial |
| 31-50% | 🔵 | Moderate |
| 51-75% | 🟢 | Good |
| >75% | ✅ | Strong |

**⛔ PROHIBITED:** Assigning badges based on "importance" or "this tactic is more relevant." The badge MUST match the percentage threshold table above.

### Rule B: Threat Scenario Priority

When rendering SOC Optimization threat scenarios, order by coverage gap (recommended minus active) descending, but assign **badges based on completion rate** (proportional to scenario size):

| Completion Rate | Priority | Badge |
|----------------|----------|-------|
| <15% | 🔴 High | Very early stage — most recommendations unaddressed |
| 15–35% | 🟠 Medium | Work in progress — significant room for improvement |
| 35–60% | 🟡 Low | Approaching healthy coverage for typical environments |
| ≥60% | ✅ Met | Strong coverage — well above realistic implementation targets |

> **Why rate-based?** Recommendation counts reflect the **full Content Hub template catalogue** including templates for vendor products not deployed in the environment (e.g., all firewall vendors). A 609-rule scenario will be permanently 🔴 under absolute-gap thresholds even at 80% coverage. Rate-based badges give proportional, meaningful progress signals.

> **CompletedBySystem note:** `CompletedBySystem` is a SOC Optimization state, not a rate indicator. Some CompletedBySystem entries have low rates (recommended >> active). Always use the **completion rate** for badge assignment. The State column is displayed for context but does NOT override the rate-based badge.

### Rule C: "Paper Tiger" Detection

When Phase 3 data is available, identify **paper tiger** rules — rules with MITRE tags that have NEVER produced an alert in the lookback period. These rules are tagged but non-operational, and their coverage is theoretical, not proven.

| Condition | Classification | Display |
|-----------|---------------|---------|
| Rule tagged with MITRE + 0 alerts in lookback | ⚠️ Paper tiger | Note in technique drill-down |
| Rule tagged with MITRE + ≥1 alert | ✅ Operationally validated | Normal display |
| Phase 3 data unavailable (FAILED/SKIPPED) | — | Skip paper-tiger analysis, note data gap |

**⛔ PROHIBITED:** Reporting coverage percentages as "validated" when Phase 3 data is missing. If M4/M5 failed, state: "Coverage percentages reflect rule tagging only — operational validation unavailable (Phase 3 KQL queries failed)."

### Rule D: Recommendation Ranking

Rank recommendations by impact using this priority order:

| Priority | Category | Criteria |
|----------|----------|----------|
| 1 | 🔴 **Low-rate threat scenarios** | SOC Optimization scenarios with <15% completion rate. **Exclude CompletedByUser scenarios with ≥50% completion rate** (Rule E — Reviewed & Addressed). Only include ⚠️ Premature CompletedByUser (<50% rate) |
| 2 | 🔴 **Zero-coverage detectable tactics** | Tactics with 0% coverage AND ✅ Detectable classification (see tactic table). **Exclude ⬜ Inherent blind spot tactics** (Reconnaissance, Resource Development) — report these as acknowledged limitations, not actionable gaps |
| 3 | 🟠 **Untagged rule remediation** | Rules with AI-suggested MITRE tags from SOC Optimization |
| 4 | 🟠 **Paper tiger rules** | MITRE-tagged rules that never fire (if Phase 3 available) |
| 5 | 🟡 **Low-coverage tactics** | Tactics with 1-15% coverage |
| 6 | 🟡 **Content Hub suggestions** | Template-based rules available for uncovered techniques |
| 7 | ⬜ **Inherent blind spot tactics** | Zero-coverage tactics classified as ⬜ Inherent blind spot. Acknowledge the limitation; suggest compensating controls (threat intel feeds, brand monitoring) only if relevant to the organization |

### Rule E: CompletedByUser Completion-Rate Gate

When a SOC Optimization threat scenario has `State == CompletedByUser`, the user has manually marked it as reviewed. However, marking a scenario "complete" after enabling 2/500 recommendations is fundamentally different from enabling 28/46. Use the **completion rate** (`ActiveDetections / RecommendedDetections × 100`) to determine rendering treatment:

| CompletedByUser + Completion Rate | Treatment | Rationale |
|---|---|---|
| **≥ 50%** | 🟢 **Reviewed & Addressed** — render in a separate muted "Reviewed Scenarios" summary below the active gaps table. Exclude from §6 recommendations and Coverage Priority Matrix | User has genuinely triaged the scenario; remaining gap is likely non-applicable templates or platform-only coverage |
| **< 50%** | ⚠️ **Premature Completion** — render in the main active gaps table with full gap badge + ⚠️ flag in the State column. Include in §6 recommendations | Gap is too large relative to recommendations to be a deliberate triage decision |

**Threshold:** 50% is the default. This balances trust in the user's judgment against protection from rubber-stamped completions.

**Scratchpad column:** `CompletionRate` is pre-computed by the PS1 and included in the `ThreatScenarios` row. The LLM reads this value directly — do not recompute it.

**Interaction with Rule B (rate-based badges):** Rule B still applies for badge assignment on all scenarios. Rule E only controls **where** CompletedByUser scenarios are rendered (active table vs reviewed summary) and whether they appear in §6 recommendations.

**CompletedBySystem** scenarios are not affected — they continue to use rate-based badges (Rule B) without the completion-rate gate, since the system assessment is independent of user action.

---

## MITRE Coverage Score

The MITRE Coverage Score is a composite metric (0-100) computed by the PS1 from 5 weighted dimensions. Each dimension scores 0-100 independently, then the weighted sum produces the final score.

### Dimensions

| # | Dimension | Weight | Formula | What It Measures |
|---|-----------|--------|---------|-----------------|
| 1 | **Breadth** | 25% | `(Σ per-technique readiness credit / total ATT&CK techniques) × 100` blended 60/40 with combined platform coverage | Readiness-weighted technique coverage. Each technique gets fractional credit based on the **best** rule covering it: Fired=1.0, Ready=0.75, Partial=0.50, NoData=0.25, TierBlocked=0.0. AR and CD rules follow the same readiness constraints. One firing rule gives full credit even if other rules covering the same technique are NoData |
| 2 | **Balance** | 10% | `(tactics with ≥1 rule / 14 tactics) × 100` | Whether coverage spans all kill chain phases or clusters in a few |
| 3 | **Operational** | 30% | `(MITRE-tagged rules that fired alerts / total MITRE-tagged enabled rules) × 100` | Whether tagged rules actually produce detections (not paper tigers). Highest weight: directly rewards purple teaming and operationally validated detections |
| 4 | **Tagging** | 15% | `(rules with MITRE tags / total rules) × 100` | Completeness of MITRE classification across the rule inventory |
| 5 | **SOC Alignment** | 20% | `(completed SOC recommendations / total SOC coverage recommendations) × 100` | Alignment with Microsoft's threat-scenario-driven coverage model |

### Score Interpretation

| Score Range | Assessment | Typical Profile |
|-------------|------------|-----------------|
| 80-100 | 🟢 **Strong** | Broad coverage, balanced tactics, operationally validated, well-tagged, SOC-aligned |
| 60-79 | 🔵 **Good** | Solid coverage with some gaps; may have clustering or unvalidated rules |
| 40-59 | 🟡 **Moderate** | Significant gaps in breadth or operational validation; improvement opportunities |
| 20-39 | 🟠 **Developing** | Limited coverage across the framework; many uncovered tactics |
| 0-19 | 🔴 **Critical** | Minimal detection coverage; urgent investment needed |

### Score Context Notes

- **Operational = 0** when Phase 3 KQL queries fail (token expiry). Report this: "Operational score 0 reflects data unavailability, not necessarily poor operational coverage."
- **SOC Alignment = 50** (default) when no SOC Optimization recommendations exist. This is a neutral baseline, not a penalty.
- **Breadth score is naturally low** because the ATT&CK framework contains 216+ techniques, many of which are endpoint-specific or pre-compromise with limited Sentinel visibility. Do NOT present this as a crisis — contextualize it: "Prioritize coverage by threat scenario relevance rather than pursuing raw percentage."
- **Custom Detections SKIPPED** affects Breadth and Tagging dimensions (rules not counted). Note the impact in the report.
- **Platform Coverage** is reported as a supplementary metric alongside the MITRE Score (not folded into the 5 dimensions). The scratchpad includes `Platform_Tier1/2/3`, `Platform_ActiveProducts`, and `RuleBasedPlusPlatform_Coverage`. Render this in §1 and §5 per SKILL-report.md templates. The CTID tier classification requires `m365-platform-coverage.json` — if the file is missing, platform tiers default to empty and the report notes the limitation.

---

## Domain Reference

### ATT&CK Enterprise Tactic Kill Chain Order

The 14 ATT&CK Enterprise tactics in kill chain order (PS1 uses this ordering for all output):

| # | Tactic (Sentinel API name) | Display Name | Cloud/Identity Relevance | Detectability |
|---|----------------------------|--------------|--------------------------|---------------|
| 1 | Reconnaissance | Reconnaissance | 🟡 Low — mostly pre-compromise; limited Sentinel visibility | ⬜ Inherent blind spot |
| 2 | ResourceDevelopment | Resource Development | 🟡 Low — attacker infrastructure; limited Sentinel visibility | ⬜ Inherent blind spot |
| 3 | InitialAccess | Initial Access | 🔴 High — phishing, valid accounts, external services | ✅ Detectable |
| 4 | Execution | Execution | 🟠 Medium — scripting, cloud admin commands | ✅ Detectable |
| 5 | Persistence | Persistence | 🔴 High — account manipulation, app registrations, inbox rules | ✅ Detectable |
| 6 | PrivilegeEscalation | Privilege Escalation | 🔴 High — tenant policy modification, valid accounts | ✅ Detectable |
| 7 | DefenseEvasion | Defense Evasion | 🟠 Medium — many techniques are endpoint-focused | ✅ Detectable |
| 8 | CredentialAccess | Credential Access | 🔴 High — brute force, token theft, AiTM | ✅ Detectable |
| 9 | Discovery | Discovery | 🟡 Medium — account/cloud service discovery | ✅ Detectable |
| 10 | LateralMovement | Lateral Movement | 🟠 Medium — remote services, internal spearphishing | ✅ Detectable |
| 11 | Collection | Collection | 🟡 Medium — email collection, data from cloud storage | ✅ Detectable |
| 12 | CommandAndControl | Command and Control | 🟠 Medium — application layer protocol, web service | ✅ Detectable |
| 13 | Exfiltration | Exfiltration | 🟠 Medium — exfiltration over C2 channel, cloud account | ✅ Detectable |
| 14 | Impact | Impact | 🟠 Medium — resource hijacking (crypto mining), account removal | ✅ Detectable |

**Detectability classification:**
- **✅ Detectable:** Techniques in this tactic generate observable events in Sentinel data sources (sign-in logs, audit logs, endpoint telemetry, email events, etc.). KQL detection rules can be written and deployed.
- **⬜ Inherent blind spot:** Techniques in this tactic describe attacker activity that occurs *outside* the monitored environment (e.g., attacker creating fake accounts on external services, acquiring infrastructure). CTID mappings for these tactics are typically protect/respond capabilities (Conditional Access blocking, PAM restrictions), not detect. No KQL detection rules exist or can realistically be created. **Do not recommend deploying rules for inherent blind spot tactics** — acknowledge the limitation and recommend compensating controls (e.g., brand monitoring services, threat intelligence feeds) if relevant.

### Sentinel-Specific MITRE Mapping Notes

- **Sentinel uses PascalCase** for tactic names in the REST API: `InitialAccess`, `CommandAndControl`, `CredentialAccess`. The ATT&CK STIX data uses kebab-case (`initial-access`). The reference JSON maps between these.
- **Sub-techniques (T1xxx.xxx)** are tracked by Sentinel but the REST API `properties.techniques` field may contain both parent techniques (T1078) and sub-techniques (T1078.004). The PS1 counts at the parent technique level for coverage matrix purposes.
- **ICS/OT techniques (T0xxx)** use a separate numbering scheme from ATT&CK for ICS. These are extracted and reported separately since they don't map to the Enterprise framework.
- **Custom Detection `mitreTechniques`** uses the same technique ID format but may specify sub-techniques that analytic rules don't. The PS1 aggregates both sources.

### Tactic-Specific Detection Guidance

When rendering recommendations (§6), use these cloud/identity-relevant technique priorities:

| Tactic | Key Sentinel-Detectable Techniques | Priority |
|--------|------------------------------------|----------|
| InitialAccess | T1078 (Valid Accounts), T1566 (Phishing), T1133 (External Remote Services) | 🔴 Must-have |
| Persistence | T1098 (Account Manipulation), T1136 (Create Account), T1078 (Valid Accounts) | 🔴 Must-have |
| CredentialAccess | T1110 (Brute Force), T1528 (Steal App Access Token), T1621 (MFA Request Gen) | 🔴 Must-have |
| PrivilegeEscalation | T1484 (Domain/Tenant Policy Mod), T1078 (Valid Accounts), T1098 (Account Manipulation) | 🔴 Must-have |
| DefenseEvasion | T1078 (Valid Accounts), T1484 (Domain/Tenant Policy Mod), T1562 (Impair Defenses) | 🟠 Important |
| Exfiltration | T1567 (Exfil Over Web Service), T1537 (Transfer to Cloud Account) | 🟠 Important |
| Collection | T1114 (Email Collection), T1213 (Data from Info Repos) | 🟠 Important |

### SOC Optimization Threat Scenario Reference

SOC Optimization recommendations map to named threat scenarios. When rendering §4, interpret these:

| Scenario | Key Attack Pattern | Priority Tactics |
|----------|--------------------|-----------------|
| AiTM (Adversary in the Middle) | Session token theft, AiTM phishing | InitialAccess, CredentialAccess |
| BEC (Financial Fraud) | Email account takeover for wire fraud | InitialAccess, CredentialAccess, Persistence |
| BEC (Mass Credential Harvest) | Large-scale phishing campaigns | InitialAccess, CredentialAccess, DefenseEvasion |
| Human Operated Ransomware | Post-compromise hands-on keyboard | LateralMovement, CredentialAccess, DefenseEvasion, Impact |
| Credential Exploitation | Credential stuffing, password spray | InitialAccess, CredentialAccess, Discovery |
| IaaS Resource Theft | Cloud compute hijacking (crypto mining) | CredentialAccess, Persistence, Impact |
| Network Infiltration | Traditional network-based attacks | Discovery, LateralMovement, C2 |
| X-Cloud Attacks | Cross-cloud lateral movement | CredentialAccess, PrivilegeEscalation, Persistence |
| ERP (SAP) | SAP financial process manipulation | InitialAccess, DefenseEvasion |

### SOC Optimization Recommendation States

| State | Meaning | Report Treatment |
|-------|---------|-----------------|
| `Active` | Recommendation is open and actionable | Show as gap — count toward coverage deficit |
| `InProgress` | User has started addressing the recommendation | Show as in-progress — partial credit |
| `CompletedBySystem` | Microsoft's automated assessment found coverage adequate | Use **rate-based badge** (may still show 🔴/🟠/🟡 if completion rate is low). State displayed in table for context |
| `Completed` | User manually marked as complete | Show as met — ✅ |

---

## SVG Dashboard Generation

After the report is generated, the user may request an SVG dashboard visualization.

**Trigger:** "generate SVG dashboard", "visualize this report", "SVG from the MITRE report"

**Workflow:**
1. Load the `svg-dashboard` skill
2. Use the rendered report + scratchpad data to build visualization widgets
3. Recommended widget types for MITRE coverage:
   - **Score card** — MITRE Coverage Score (40.1/100) with 5 dimension breakdown
   - **Bar chart** — Per-tactic coverage percentages (14 bars)
   - **Donut chart** — Rule inventory breakdown (AR enabled/disabled, CD enabled/disabled, untagged)
   - **Table** — Top 5 coverage gaps (tactic + gap %)
   - **KPI cards** — Total techniques covered, SOC scenarios met, untagged rules

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Phase 3 KQL queries fail (token expired) | Re-authenticate: `az login --tenant <tenant_id> --scope https://api.loganalytics.io/.default` |
| Custom Detections SKIPPED | Normal if Graph API admin consent not granted. Report proceeds with AR-only analysis |
| SOC Optimization returns 0 recs | Workspace may not have SOC Optimization enabled, or all recommendations are already completed |
| Breadth score seems low (10-20%) | This is typical — 216+ techniques means even well-covered workspaces have low percentages. Focus on threat-scenario-aligned priorities, not raw percentage |
| ICS techniques appear in output | Normal if Defender for IoT rules are deployed. They're reported separately from Enterprise ATT&CK |
| `az rest` returns 403 | Check RBAC: user needs **Microsoft Sentinel Reader** on the workspace |
