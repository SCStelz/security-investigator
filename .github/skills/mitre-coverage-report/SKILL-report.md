# Report Template — MITRE ATT&CK Coverage (v1)

> **📄 Just-in-time loading:** This file contains the complete report rendering templates (inline chat + markdown file). Load it at the start of **Phase 4 (rendering)** — alongside reading the timestamped scratchpad file (`temp/mitre_scratch_YYYYMMDD_HHmmss.md`). Do NOT load during data gathering (Invoke-MitreScan.ps1 execution).

---

## Architecture Context

All data gathering is performed by `Invoke-MitreScan.ps1`, which writes a deterministic scratchpad file. The LLM's only job during Phase 4 is to **read the scratchpad and render the report**. All query execution, MITRE mapping, coverage computation, and scoring are pre-computed by PowerShell.

**Data flow:** `Invoke-MitreScan.ps1` → `temp/mitre_scratch_<timestamp>.md` → LLM reads scratchpad → renders report.

**Single-write rendering:** The entire report (§1-§6) is rendered in a single `create_file` call.

---

## Section-to-Scratchpad Mapping

| Report Section | Scratchpad Keys |
|----------------|----------------|
| §1 MITRE Coverage Score | `SCORE.*` (all 5 dimensions + weights) |
| §1 Detection Inventory | `PHASE_1.AR_Summary` + `PHASE_1.CD_Summary` |
| §1 Top 3 Recommendations | Computed at render time from all scratchpad sections using Rule D |
| §2 Tactic Coverage Matrix | `PRERENDERED.TacticCoverageMatrix` (pre-rendered table with badges — copy VERBATIM). Raw data retained in `PHASE_1.TacticCoverage` for LLM narrative. |
| §3 Technique Deep Dive | `PRERENDERED.TechniqueTables` (pre-rendered per-tactic markdown tables — copy VERBATIM). Raw data retained in `PHASE_3.TechniqueDetail` for LLM narrative/analysis. |
| §3 Untagged Rules | `PHASE_1.UntaggedRules` |
| §3 ICS/OT Techniques | `PHASE_1.ICS_Techniques` |
| §4 Coverage Gap Analysis | `PHASE_1.TacticCoverage` (zero/low coverage tactics) + `PRERENDERED.ThreatScenarios` (pre-rendered tables with Rule B badges and Rule E split — copy VERBATIM). Raw `PHASE_2.ThreatScenarios` trimmed (fully captured in PRERENDERED). |
| §4 MITRE Tagging Suggestions | `PHASE_2.MitreTaggingSuggestions` |
| §5 Alert Firing | `PRERENDERED.AlertFiring` (pre-rendered table with [AR]/[CD] badges — copy VERBATIM). Raw `PHASE_3.AlertFiring` retained for other cross-refs; `AlertFiring_MitreCorrelation` trimmed (fully captured in PRERENDERED). `PHASE_3.ActiveTacticCoverage` trimmed (fully captured in PRERENDERED.ActiveVsTagged). |
| §5 Active vs Tagged | `PRERENDERED.ActiveVsTagged` (pre-rendered table with status badges — copy VERBATIM). |
| §5 Incidents by Tactic | `PRERENDERED.IncidentsByTactic` (pre-rendered table — copy VERBATIM). Raw `PHASE_3.IncidentsByTactic` trimmed (fully captured in PRERENDERED). |
| §5 Platform Alert Coverage | `PHASE_3.PlatformAlertCoverage` + `PHASE_3.DeployedProducts` |
| §5 Platform Tier Classification | `PHASE_3.PlatformTechniquesByTier` + `Tier1_AlertProven` + `Tier2_DeployedCapability` + `Tier3_CatalogCapability` |
| §5 Combined Tactic Coverage | `PRERENDERED.CombinedTacticCoverage` (pre-rendered table — copy VERBATIM). Raw `PHASE_3.PlatformTacticCoverage` trimmed (fully captured in PRERENDERED). |
| §5 Data Readiness | `PRERENDERED.DataReadiness` (pre-rendered summary + detail tables — copy VERBATIM). Raw `PHASE_3.DataReadiness` retained for AlertFiring cross-ref; `DataReadiness_Summary`, `MissingTables`, `TierBlockedTables` trimmed (fully captured in PRERENDERED). `PHASE_3.UnverifiedTables` retained for parser false positives note. |
| §5 Connector Health | `PRERENDERED.ConnectorHealth` (pre-rendered summary + detail tables — copy VERBATIM). Raw `PHASE_3.ConnectorHealth` retained for LastEvent timestamps; `ConnectorHealth_Summary` trimmed (fully captured in PRERENDERED). |
| §6 Recommendations | Synthesized from all phases |

---

## Inline Chat Executive Summary

````markdown
🛡️ MITRE ATT&CK COVERAGE REPORT — <DATE>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Workspace:** <WORKSPACE_NAME> | **ATT&CK:** Enterprise v<VERSION>

### 🎯 MITRE Coverage Score: **<SCORE>/100** — <ASSESSMENT>

| Dimension | Score | Weight | Description |
|-----------|-------|--------|-------------|
| Breadth | <X>/100 | 30% | <RULE_PCT>% rule-based · <COMBINED_PCT>% combined — blended 60/40 (phantom-adjusted) |
| Balance | <X>/100 | 15% | <X>/14 tactics have ≥1 rule |
| Operational | <X>/100 | 20% | <X>% of tagged rules fired alerts |
| Tagging | <X>/100 | 15% | <X>% of rules have MITRE tags |
| SOC Alignment | <X>/100 | 20% | <X>% of SOC scenarios addressed |

### 📊 Detection Inventory

| Metric | Count |
|--------|-------|
| Analytic Rules (enabled/total) | <ENABLED>/<TOTAL> |
| Custom Detections (enabled/total) | <ENABLED>/<TOTAL> (or SKIPPED) |
| Rules with MITRE tags | <COUNT> (<PCT>%) |
| Untagged rules | <COUNT> |
| Techniques covered | <COVERED>/<TOTAL> (<PCT>%) |
| Combined (Rule-Based+Platform) | <COMBINED>/<TOTAL> (<PCT>%) |
| Tactics with ≥1 rule | <COUNT>/14 |

### 🔴 Top Coverage Gaps

| # | Gap | Impact |
|---|-----|--------|
| 1 | <TACTIC/SCENARIO> — <DETAIL> | <REMEDIATION HINT> |
| 2 | <TACTIC/SCENARIO> — <DETAIL> | <REMEDIATION HINT> |
| 3 | <TACTIC/SCENARIO> — <DETAIL> | <REMEDIATION HINT> |

📄 Full report: reports/sentinel/mitre_coverage_report_<YYYYMMDD_HHMMSS>.md
````

---

## Markdown File Structure

```markdown
# MITRE ATT&CK Coverage Report

**Generated:** <DATE>
**Workspace:** <WORKSPACE_NAME>
**Workspace ID:** <WORKSPACE_ID>
**ATT&CK Version:** Enterprise v<VERSION> (<TECHNIQUE_COUNT> techniques, <SUBTECHNIQUE_COUNT> sub-techniques)
**Alert/Incident Lookback:** <DAYS> days
```

> **📋 Advisory disclaimer (MUST appear in every rendered report):** Add immediately below the header:
>
> *"This report analyzes detection coverage against the MITRE ATT&CK Enterprise framework based on rule MITRE tagging and operational alert data. Coverage percentages reflect enabled rules with MITRE tags — actual detection efficacy depends on data source availability, rule quality, and adversary behavior. All recommendations require human review and validation against organizational threat priorities before implementation."*

> **📋 "Why this report?" callout (MUST appear after the disclaimer in every rendered report):**
>
> *Why this report?* The built-in [Sentinel MITRE ATT&CK dashboard](https://security.microsoft.com/sentinel/mitre) ([docs](https://learn.microsoft.com/en-us/azure/sentinel/mitre-coverage?tabs=defender-portal)) only shows coverage for active Analytic Rules and Hunting Queries — it does **not** account for product-native platform alerts (MDE, MDI, MDCA, etc.), Custom Detection rules, or inherent Defender XDR coverage capabilities. This report fills that gap by combining rule-based coverage with platform alert evidence (Tier 1/2/3) and [SOC Optimization](https://security.microsoft.com/sentinel/precision) threat scenario alignment to provide a comprehensive view of actual detection posture.
>
> *Custom Detections migration:* Microsoft is [unifying detection authoring](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/custom-detections-are-now-the-unified-experience-for-creating-detections-in-micr/4463875) around Custom Detections as the preferred rule type — offering unlimited real-time detections, lower ingestion costs, and seamless Defender XDR integration. This report already inventories Custom Detections alongside Analytic Rules to ensure coverage tracking remains accurate as the migration progresses.

> ⛔ **No chain-of-thought in report output.** Render only final content.

---

## Section Rendering Rules

### 1. Executive Summary

Three sub-sections:

#### 🎯 MITRE Coverage Score

Render the score card from `SCORE.*` scratchpad section:

```markdown
## 🎯 MITRE Coverage Score: **<SCORE>/100** — <ASSESSMENT>

| Dimension | Score | Weight | Interpretation |
|-----------|-------|--------|----------------|
| **Breadth** | <X>/100 | 30% | <EFFECTIVE_COVERED>/<TOTAL> rule-based (<RULE_PCT>%) · <COMBINED>/<TOTAL> combined (<COMBINED_PCT>%) — blended 60/40 |
| **Balance** | <X>/100 | 15% | <N>/14 tactics have ≥1 enabled rule |
| **Operational** | <X>/100 | 20% | <N> unique MITRE-tagged rules produced alerts in <DAYS>d (out of <M> MITRE-tagged enabled rules) |
| **Tagging** | <X>/100 | 15% | <N>/<M> total rules (enabled + disabled) have MITRE ATT&CK tags |
| **SOC Alignment** | <X>/100 | 20% | <N>/<M> SOC coverage scenarios met |
```

**Score assessment:** Use the Score Interpretation table from SKILL.md (0-19 Critical, 20-39 Developing, 40-59 Moderate, 60-79 Good, 80-100 Strong).

**Contextual notes (render below the score card):**
- If Operational = 0 and Phase 3 status = FAILED: "⚠️ Operational score reflects KQL data unavailability, not operational coverage quality. Re-run with valid `az login` session for accurate operational scoring."
- If CD_Status = SKIPPED: "ℹ️ Custom Detection rules excluded (Graph API auth unavailable). Breadth and Tagging scores reflect AR-only inventory."
- Always: "ℹ️ Breadth scores are naturally low — the ATT&CK framework contains 216+ techniques, many of which are endpoint-specific or pre-compromise with limited Sentinel visibility. Breadth uses a blended formula (60% rule-based + 40% combined) to credit platform detections and purple team TTP testing while maintaining pressure on custom rule investment. Prioritize coverage by threat scenario relevance (see §4) rather than pursuing raw percentage."
- If `PhantomTechniques` > 0: "⚠️ Breadth adjusted: <N> phantom technique(s) subtracted from rule coverage — these techniques are only covered by rules targeting non-Analytics tier tables (Basic/Data Lake) that analytics rules structurally cannot query. Raw rule coverage: <TOTAL_COVERED>/<TOTAL> (<RAW_PCT>%). Effective rule coverage: <EFFECTIVE>/<TOTAL> (<ADJ_PCT>%). Phantom techniques: <LIST>."

#### 📊 Detection Inventory

Render from `PHASE_1.AR_Summary` + `PHASE_1.CD_Summary`:

| Metric | Count |
|--------|-------|
| Total Analytic Rules | `AR_Total` |
| Enabled AR (tagged / untagged) | `AR_Enabled` (`AR_Enabled - AR_NoMitre_Enabled` tagged / `AR_NoMitre_Enabled` untagged) |
| Disabled AR | `AR_Disabled` |
| Custom Detections (total) | `CD_Total` (or `CD_Status` if SKIPPED) |
| Enabled CD (MITRE-tagged / untagged) | `CD_Enabled` (`CD_Enabled - CD_NoMitre_Enabled` tagged / `CD_NoMitre_Enabled` untagged) |
| Disabled CD | `CD_Disabled` |
| **Combined Enabled Rules** | **`AR_Enabled + CD_Enabled`** |
| Rules with MITRE tags | `AR_WithTactics + CD_WithMitre` out of `AR_Total + CD_Total` total rules (inc. disabled) |
| Untagged rules | Count from `UntaggedRules` section |
| Techniques covered | `TacticCoverage TOTAL CoveredTechniques`/`TOTAL FrameworkTechniques` |
| Tactics with ≥1 rule | Count from `TacticCoverage` with EnabledRules > 0 |/14 |
| Data readiness | `DataReadiness_Ready`/(`Ready`+`Partial`+`NoData`+`TierBlocked`) enabled rules have all table dependencies flowing (`DataReadiness_Pct`%). `TierBlocked` rules target non-Analytics tier tables (phantom coverage). Connector health: `Connectors_Total` monitored, `Connectors_Failing` failing, `Connectors_Degraded` degraded (from SentinelHealth M8) |

**Scope notes:**
- "Tagged / untagged" split in the Enabled rows uses `AR_NoMitre_Enabled` and `CD_NoMitre_Enabled` (enabled-only counts)
- "Rules with MITRE tags" row uses `AR_WithTactics + CD_WithMitre` across ALL rules (enabled + disabled), matching the Tagging score denominator

#### 🛡️ Platform Coverage (CTID Integration)

**Data source:** `SCORE.Platform_*` + `SCORE.RuleBasedPlusPlatform_Coverage` + `SCORE.CTID_Version`

If CTID data is available (`CTID_Version` ≠ N/A), render a platform coverage summary:

```markdown
### 🛡️ Platform Coverage

Beyond custom rules, Defender XDR products provide built-in detection capabilities mapped by the [Center for Threat-Informed Defense (CTID)](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/).

| Layer | Techniques | Description |
|-------|-----------|-------------|
| 🟢 **Tier 1: Alert-Proven** | <N> | Platform products triggered SecurityAlerts with MITRE attribution in the last <DAYS>d |
| 🔵 **Tier 2: Deployed Capability** | <N> | Active products claim detection capability per CTID mapping, but no alerts in window |
| ⬜ **Tier 3: Catalog Capability** | <N> | CTID maps coverage, but the product has no alert evidence in this workspace |
| **Rule-Based** | <N> | Enabled analytic rules + custom detections with MITRE tags |
| **Combined (Rule-Based + T1 + T2)** | **<N>/<TOTAL> (<PCT>%)** | Unique techniques covered by any active detection source |

**Active products detected:** <list from DeployedProducts>
```

> *CTID Mapping v<VERSION> (ATT&CK v16.1). Platform coverage is supplementary — custom rules provide tailored, environment-specific detections that platform-native coverage cannot replace.*

If CTID data is NOT available (`CTID_Version` = N/A), skip this subsection entirely.

#### 🎯 Top 3 Recommendations

Table with columns: `| # | Priority | Recommendation | Impact |`

Compute using Rule D from SKILL.md. Priority emoji (🔴/🟠/🟡) based on the rule. Impact column must cite specific evidence from the scratchpad.

**Example:**
| # | Priority | Recommendation | Impact |
|---|----------|----------------|--------|
| 1 | 🔴 | **Enable Reconnaissance/Collection coverage** — 2 tactics with 0% technique coverage (0/11 and 0/17 respectively) | Zero visibility into pre-compromise recon and data collection stages |
| 2 | 🔴 | **Address Human Operated Ransomware gap** — SOC Optimization shows 28.1% completion rate (25/89 active detections) | Key tactic gaps in C2, Persistence, PrivEsc, Impact; mark In Progress and deploy environment-relevant templates |
| 3 | 🟠 | **Apply MITRE tags to 5 untagged rules** — SOC Optimization AI suggests tags for 7 rules | Improves Tagging score and enables gap analysis for these rules |

---

### 2. Tactic Coverage Matrix

**Data source:** `PRERENDERED.TacticCoverageMatrix` (pre-rendered table with Rule A badges already applied)

> ℹ️ Add this callout before the table: "Compare with the built-in [Sentinel MITRE ATT&CK dashboard](https://security.microsoft.com/sentinel/mitre) which shows Analytic Rule and Hunting Query coverage only. This table adds Custom Detection (CD) rules for a complete rule-based view; see §5.1 for combined rule + platform coverage."

**🔴 CRITICAL: Copy the pre-rendered table VERBATIM from `PRERENDERED.TacticCoverageMatrix`.**

The pipeline pre-renders the complete 14-row + TOTAL table with:
- Row numbers (kill-chain order)
- Badge assignment via Rule A thresholds (0% → 🔴, 1-15% → 🟠, 16-30% → 🟡, 31-50% → 🔵, 51-75% → 🟢, >75% → ✅)
- Human-readable tactic names (CamelCase → display)
- All numeric columns (Enabled Rules, Framework Techniques, Covered Techniques, Coverage %)
- TOTAL row with sums

**🔴 PROHIBITED:**
| Action | Status |
|--------|--------|
| Recalculating badges from coverage percentages | ❌ **PROHIBITED** |
| Changing tactic names or row order | ❌ **PROHIBITED** |
| Modifying any numeric values | ❌ **PROHIBITED** |
| Removing or adding rows | ❌ **PROHIBITED** |

> ℹ️ **TOTAL row note:** The "Enabled Rules" column in the TOTAL row sums per-tactic rule counts. Because a single rule can be tagged with multiple tactics (e.g., T1078 appears under InitialAccess, Persistence, PrivilegeEscalation, DefenseEvasion), this sum is higher than the Combined Enabled Rules count in §1. The per-tactic counts are correct for assessing each tactic's depth; the Combined Enabled count in §1 is the de-duplicated rule count.

**What the LLM adds (analytical — AFTER the table):**
- 2-3 sentences of narrative highlighting:
  1. How many tactics have zero coverage
  2. Which tactic has the most rules (and whether that coverage is efficient or over-concentrated)
  3. Cloud/identity relevance context (e.g., "The 3 zero-coverage tactics include 2 pre-compromise phases with limited Sentinel visibility and 1 post-compromise phase (Collection) that warrants attention")
- **If CTID data available:** Add a one-line combined coverage note after the narrative:
  > "📊 **Combined Coverage (Rule-Based + Platform Tier 1/2):** <COMBINED>/<TOTAL> techniques (<PCT>%). Platform-native detections add <UPLIFT> techniques beyond custom rules alone."

---

### 3. Technique Deep Dive

**Data source:** `PRERENDERED.TechniqueTables` (pre-rendered per-tactic markdown tables) + `PHASE_1.UntaggedRules` + `PHASE_1.ICS_Techniques`

> **Tables are now pre-rendered by the pipeline** to eliminate LLM rendering errors (cross-tactic hallucination, dropped platform alert names, inconsistent badge assignment, tactic name formatting). The `PRERENDERED.TechniqueTables` section contains complete per-tactic markdown tables with headers, badges, detections, and platform columns already computed. Raw data is retained in `PHASE_3.TechniqueDetail` for LLM narrative/analysis text.

#### 3a. Per-Tactic Technique Tables

**🔴 CRITICAL: Copy pre-rendered tables VERBATIM from `PRERENDERED.TechniqueTables`.**

Each tactic in the PRERENDERED section has a header followed by a complete markdown table. **Copy each table exactly as-is** — do not reorder rows, rename techniques, change badges, modify detections, or restructure the table in any way.

**Tactic header format (two variants):**
- **When platform adds coverage:** `#### <Tactic> (<Rules>/<Total> rules — <Pct>% · <Combined>/<Total> combined — <Pct>%)`
  - Example: `#### Defense Evasion (7/47 rules — 14.9% · 24/47 combined — 51.1%)`
- **When no platform uplift (rules == combined):** `#### <Tactic> (<Covered>/<Total> techniques — <Pct>%)`
  - Example: `#### Reconnaissance (0/11 techniques — 0%)`

**What the pipeline pre-renders (deterministic):**
- Tactic header with display name, coverage counts, and percentage
- Badge assignment: ✅ (custom rules), 🟢 (Tier 1 platform), 🔵 (Tier 2 platform), ⬜ (Tier 3 catalog), ❌ (true gap)
- Detections column: custom rule names with [AR]/[CD] prefixes for ✅ rows; platform alert names with product abbreviation prefixes (e.g., [MDE], [MDCA]) for 🟢 rows; em-dash for others
- Platform column: "Tier N" for ✅ with platform, "Tier N: MDE, MDI" for 🟢/🔵 rows, "⬜ Tier 3" for catalog, em-dash for true gaps
- Row sort order: ✅ first (by rules desc), then 🟢, 🔵, ⬜, ❌
- Large-tactic truncation: ❌ rows capped at 10 with "...and N additional" note

**What the LLM adds (analytical):**
- For **zero-coverage tactics** with `<!-- ZERO_COVERAGE -->` comment: write narrative context explaining why coverage is zero (e.g., Reconnaissance is pre-compromise, Collection has platform coverage but no custom rules). Reference specific technique IDs and their detection opportunities.
- For **any tactic**: optionally add 1-2 sentences of analysis AFTER the table (e.g., "Command and Control is heavily concentrated: all 23 rules target T1071 via TI-mapping templates"). Use `PHASE_3.TechniqueDetail` raw data for analysis if needed.
- **Cross-reference** with §4 SOC Optimization scenarios and §5.5 Data Readiness where relevant.

**🔴 PROHIBITED:**
| Action | Status |
|--------|--------|
| Modifying pre-rendered table content (rows, badges, values) | ❌ **PROHIBITED** |
| Adding techniques not in the pre-rendered table for a tactic | ❌ **PROHIBITED** |
| Replacing pre-rendered alert names with LLM-generated text | ❌ **PROHIBITED** |
| Moving techniques between tactic tables | ❌ **PROHIBITED** |
| Changing tactic header text (name, counts, percentage) | ❌ **PROHIBITED** |

#### 3b. Untagged Rules

**Data source:** `PHASE_1.UntaggedRules`

```markdown
### Untagged Rules (<COUNT> rules without MITRE tags)

| Rule Name | Rule ID | Enabled | Kind | Severity | Source |
|-----------|---------|---------|------|----------|--------|
| <NAME> | <ID> | <True/False> | <Scheduled/NRT/CustomDetection> | <Severity> | <AR/CD> |
```

Add a note:
> "⚠️ These rules have no MITRE ATT&CK tactics or techniques assigned. They cannot be included in coverage gap analysis. See §6 for AI-suggested MITRE tags from SOC Optimization."

#### 3c. ICS/OT Techniques (conditional)

**Data source:** `PHASE_1.ICS_Techniques`

Only render this section if ICS techniques exist in the scratchpad.

```markdown
### ICS/OT Technique Coverage

| Technique | Rules | Detections |
|-----------|-------|------------|
| T0806 | 1 | Excessive Login Attempts (Microsoft Defender for IoT) |
| ... | ... | ... |
```

> "ℹ️ ICS/OT techniques use the ATT&CK for ICS framework (T0xxx) and are tracked separately from Enterprise ATT&CK. These are not included in the MITRE Coverage Score."

---

### 4. Coverage Gap Analysis

**Data source:** `PHASE_1.TacticCoverage` + `PHASE_2.ThreatScenarios` + `PHASE_2.MitreTaggingSuggestions`

#### 4a. Critical Coverage Gaps

List all tactics with 0% coverage, **split into two groups** based on the Detectability classification from the tactic table in SKILL.md:

**Group 1 — Actionable Gaps (✅ Detectable tactics with 0% coverage):**
These are tactics where KQL detection rules exist and can be deployed. Prioritize remediation here.

```markdown
#### Actionable Gaps (0% Coverage — Detectable Tactics)

**With CTID data:** Distinguish true gaps from platform-covered techniques. Use `PlatformTechniquesByTier` to count how many techniques in each zero-coverage tactic have Tier 1/2 platform coverage vs none at all. True gaps (no custom rules AND no Tier 1/2) are highest priority for remediation.

| Tactic | Framework Techniques | True Gaps | Platform-Covered (T1+T2) | Cloud Relevance | Key True Gap Techniques |
|--------|---------------------|-----------|--------------------------|-----------------|------------------------|
| Collection | 17 | <N> | <N> | 🟠 Medium | T1114 Email Collection, T1213 Data from Info Repos |
```

For each actionable gap, provide 1-2 sentences of context:
- What's the risk of having no coverage?
- Quick pointer to available detections (Content Hub, community rules)

**Group 2 — Inherent Blind Spots (⬜ Non-detectable tactics with 0% coverage):**
These are tactics where attacker activity occurs *outside* the monitored environment. CTID mappings are typically protect/respond (Conditional Access, PAM), not detect — no KQL rules can realistically be deployed.

```markdown
#### Inherent Blind Spots (0% Coverage — Pre-Compromise Tactics)

| Tactic | Framework Techniques | CTID Protect/Respond | Note |
|--------|---------------------|---------------------|------|
| Reconnaissance | 11 | T1598 (Tier 3: CTID catalog) | Attacker information gathering occurs outside the tenant. Compensating controls: threat intel feeds, honeypots, brand monitoring |
| Resource Development | 8 | T1585, T1586 (Tier 3: Entra CA, Purview PAM — protect/respond only) | Attacker infrastructure build-out is invisible to Sentinel. CTID maps capabilities to block (CA) or restrict (PAM), not to detect |

> ℹ️ These tactics are excluded from the Top Recommendations and Coverage Priority Matrix. Zero coverage here is an accepted limitation of SIEM-based detection, not an actionable gap.
```

#### 4b. Threat Scenario Alignment

**Data source:** `PRERENDERED.ThreatScenarios` (pre-rendered tables with Rule B badges, Rule E CompletedByUser split, Key Tactic Gaps already computed)

**🔴 CRITICAL: Copy the pre-rendered tables VERBATIM from `PRERENDERED.ThreatScenarios`.**

The pipeline pre-renders TWO tables:

1. **`#### Active Gaps`** — Main table with active/in-progress/premature scenarios sorted by gap descending
2. **`#### Reviewed & Addressed Scenarios`** — CompletedByUser scenarios with ≥50% completion rate (only present if any exist)

**What the pipeline pre-renders (deterministic):**
- Rule B badge assignment based on **completion rate** (proportional to scenario size): Rate <15% → 🔴, 15–35% → 🟠, 35–60% → 🟡, ≥60% → ✅
- Rate column: `Active / Recommended` as a percentage — the primary progress indicator
- Rule E CompletedByUser split: ≥50% → Reviewed section, <50% → ⚠️ Premature in active table
- Gap computation (Recommended − Active)
- Key Tactic Gaps: top 3 most underserved tactics (<50% current/recommended ratio) from TacticSummary, with human-readable names
- Active gaps sorted by gap descending; Reviewed sorted by completion rate descending
- Reviewed scenario notes: "near-complete" (≥80%), "remaining gap likely platform-covered" (≥65%), "partial coverage accepted" (else)
- Unnamed/empty scenarios (0 recommended) filtered out

**🔴 PROHIBITED:**
| Action | Status |
|--------|--------|
| Recalculating badges from completion rates | ❌ **PROHIBITED** |
| Moving scenarios between Active Gaps and Reviewed tables | ❌ **PROHIBITED** |
| Changing sort order or row values | ❌ **PROHIBITED** |
| Modifying Key Tactic Gaps column | ❌ **PROHIBITED** |

**What the LLM adds (analytical — around/after the tables):**
- Before the Active Gaps table: the SOC Optimization introductory paragraph explaining what the feature is and how to interpret the columns (see below)
- After the Active Gaps table: 2–3 sentences of narrative highlighting the top 2–3 threat scenarios that need the most attention. Cross-reference with the tactic coverage matrix (§2) — if a threat scenario's key tactics are the same zero-coverage tactics from §2, emphasize the compound gap. When Sentinel Gap is high but Platform coverage is strong, note the opportunity: deploying Content Hub templates adds Sentinel-native visibility and alert correlation on top of existing platform detections
- After the Reviewed table (if present): the ℹ️ note about reviewed scenarios being excluded from §6 recommendations

**SOC Optimization intro paragraph** (add before the Active Gaps table):
> [SOC Optimization](https://security.microsoft.com/sentinel/precision) is a Microsoft Sentinel feature that analyzes your workspace's ingested logs and enabled analytics rules, then compares them to the detections needed to address specific attack scenarios. Each threat scenario below represents a known attack pattern (e.g., ransomware, credential exploitation, BEC) with a recommended set of detections. The "Rate" column shows what percentage of recommended detections are active — this is the primary progress indicator. The "Gap" column shows the absolute count of missing detections.

**Realistic target note** (add immediately after the intro paragraph, before the Active Gaps table):
> ℹ️ **Interpreting recommendation counts:** The "Rec." column reflects the **full Content Hub template catalogue** for each scenario — including templates for vendor products not deployed in your environment (e.g., Palo Alto, Cisco, Fortinet firewalls in a Microsoft-only stack). A realistic implementation target is **30–50%** of the recommended count, focusing on templates whose required data sources are already ingested. Use the Rate column and priority badges to track proportional progress rather than chasing the absolute gap to zero.

**InProgress workflow guidance** (add after the Active Gaps table narrative, before the Reviewed table):
> 💡 **Recommended workflow for large-gap scenarios (>100 recommended rules):** In the [SOC Optimization portal](https://security.microsoft.com/sentinel/precision), mark the scenario **In Progress**. Review the recommended Content Hub templates and activate the 15–25 most relevant to your deployed data connectors. Once your environment-appropriate subset is active, mark the scenario **Complete**. This report will then track it in the "Reviewed & Addressed" section with your actual completion rate — giving credit for deliberate, environment-tailored coverage rather than penalizing against the full vendor catalogue.

**Column semantics** (for LLM narrative reference, NOT for table modification):
- **Rate** = Active / Recommended as a percentage — the primary metric for judging scenario health. Badges are based on this value, not the absolute gap
- **Platform** = detections provided by deployed Defender XDR products ("free" from existing licenses)
- **Sentinel** = Content Hub templates already deployed as active Sentinel analytics rules
- **Sentinel Gap** = Content Hub templates recommended but NOT yet deployed (actionable)
- **Key Tactic Gaps** = top 3 tactics where current/recommended ratio is <50%

**CompletedBySystem note:** These entries use rate-based badges (Rule B) without the completion-rate gate. The scratchpad is pre-deduplicated — stale CompletedBySystem entries are dropped when an Active/InProgress entry exists for the same scenario.

#### 4c. AI-Suggested MITRE Tags

**Data source:** `PHASE_2.MitreTaggingSuggestions`

**Rendering depends on `State` and verification fields:**

**Case 1: `State: CompletedByUser` with all tags verified applied (`AR_TagsApplied == AR_TagSuggestions` and `AR_TagsNotApplied == 0` and `AR_TagsPartial == 0`):**

```markdown
#### AI-Suggested MITRE Tags — ✅ Completed & Verified

SOC Optimization identified <COUNT> rules for MITRE tagging. This recommendation was marked complete and **all suggested tags have been verified as applied** by cross-referencing the actual rule definitions.

- **Applied:** <AR_TagsApplied>/<AR_TagSuggestions> rules have the suggested tags on the rule definition
- **Enabled rules:** <ENABLED_COUNT> of <AR_TagSuggestions> (disabled rules don't contribute to active coverage in §2)

> 💡 No action required. Consider enabling disabled tagged rules if their data sources become available.
```

**Case 2: `State: CompletedByUser` but some tags NOT verified (`AR_TagsNotApplied > 0` or `AR_TagsPartial > 0`):**

```markdown
#### AI-Suggested MITRE Tags — ⚠️ Marked Complete, Partially Verified

SOC Optimization identified <COUNT> rules for MITRE tagging. The recommendation is marked CompletedByUser, but cross-referencing the actual rule definitions shows **not all suggested tags were applied**:

- ✅ **Applied:** <AR_TagsApplied> rules
- 🟡 **Partial:** <AR_TagsPartial> rules (some suggested tags applied, others missing)
- ❌ **Not Applied:** <AR_TagsNotApplied> rules (suggested tags not found on rule definition)
- ❓ **Not Found:** <AR_TagsNotFound> rules (rule ID not in current inventory — may have been deleted)

| Rule ID | Suggested Tactics | Suggested Techniques | Status | Enabled |
|---------|-------------------|---------------------|--------|---------|
| <RULE_ID> | <TACTICS> | <TECHNIQUES or (none)> | <VerifyStatus> | <Enabled> |

> ⚠️ **Action:** Review rules with NotApplied/Partial status — the SOC Optimization "Tag all rules" action may not have persisted. Apply missing tags manually via Analytics > [Rule] > Edit > General tab.
```

**Case 3: State is NOT `CompletedByUser` (Active, InProgress, etc.):**

```markdown
#### AI-Suggested MITRE Tags for Untagged Rules

SOC Optimization has identified <COUNT> rules that should be tagged with MITRE ATT&CK metadata:

| Rule ID | Suggested Tactics | Suggested Techniques | Status | Enabled |
|---------|-------------------|---------------------|--------|---------|
| <RULE_ID> | <TACTICS> | <TECHNIQUES or (none)> | <VerifyStatus> | <Enabled> |

> 💡 **Action:** Apply these MITRE tags via the Sentinel portal (Analytics > [Rule] > Edit > General tab > Tactics and techniques). This immediately improves the Tagging dimension of the MITRE Coverage Score and enables these rules to contribute to gap analysis.
```

If the tagging suggestions include techniques, cross-reference them with §2 to show how applying the tags would improve specific tactic coverage percentages.

---

### 5. Operational MITRE Correlation

**Data source:** `PHASE_3.AlertFiring` + `PHASE_3.AlertFiring_MitreCorrelation` + `PHASE_3.ActiveTacticCoverage` + `PHASE_3.IncidentsByTactic`

**If Phase 3 failed (M4/M5 returned FAILED):**
```markdown
## 5. Operational MITRE Correlation

⚠️ **Phase 3 data unavailable** — KQL queries for SecurityAlert and SecurityIncident failed (likely due to expired `az login` token). The coverage percentages in §2-§4 reflect rule tagging only; operational validation is not possible for this run.

**Impact on MITRE Coverage Score:** Operational dimension = 0 (data unavailability, not poor coverage).

**To resolve:** Re-authenticate with `az login --tenant <tenant_id> --scope https://api.loganalytics.io/.default` and re-run: `& ".github/skills/mitre-coverage-report/Invoke-MitreScan.ps1" -Phase 3`
```

**If Phase 3 succeeded:**

#### 5.1 Platform-Native Detection Coverage (M6)

**Data source:** `PHASE_3.PlatformAlertCoverage` + `PHASE_3.DeployedProducts` + `PHASE_3.PlatformTechniquesByTier` + `PHASE_3.PlatformTacticCoverage`

If `PlatformAlert_TechniqueCount > 0`, render platform coverage:

```markdown
#### Platform-Native Detection Coverage (<DAYS>d)

**Active Detection Sources** (from SecurityAlert with MITRE attribution):
- <ProductName>: <N> techniques
- ...
- Analytic Rules (AR): <N> techniques *(alert-firing AR rules with MITRE tags)* — include only if present in DeployedProducts
- Custom Detections (CD): <N> techniques *(alert-firing CD rules with MITRE tags)* — include only if present in DeployedProducts

> **Note:** Technique counts overlap between sources — one technique may be covered by multiple products AND rules. The total unique count is in the Combined row of §1 Platform Coverage.

**CTID Tier Classification** (v<VERSION>):

| Tier | Techniques | Description |
|------|-----------|-------------|
| 🟢 Tier 1: Alert-Proven | <N> | Platform alerts with MITRE techniques in <DAYS>d |
| 🔵 Tier 2: Deployed Capability | <N> | Active product + CTID detect mapping, no alerts |
| ⬜ Tier 3: Catalog Capability | <N> | CTID mapping only, product not detected as active |

**🔴 CRITICAL: Copy the Combined Tactic Coverage table VERBATIM from `PRERENDERED.CombinedTacticCoverage`.**

The pipeline pre-renders the complete 14-row + TOTAL table with **coverage badges** (🔴 0%, 🟠 <25%, 🟡 <50%, 🟢 ≥50%) on the Tactic column, human-readable tactic names, and all numeric columns (Rule-Based, T1, T2, T3, Combined, Framework, Coverage %). **Copy as-is** — do not recalculate numbers, rename tactics, or restructure.
```

**🔴 PROHIBITED:**
| Action | Status |
|--------|--------|
| Recalculating any numeric values | ❌ **PROHIBITED** |
| Changing tactic names or row order | ❌ **PROHIBITED** |
| Adding or removing columns | ❌ **PROHIBITED** |

**What the LLM adds (analytical — AFTER the table):** Compare custom-only coverage (from §2 TOTAL row) with combined coverage (from the TOTAL row here). Highlight the uplift from platform detections and identify tactics where platform coverage fills the most gaps. Note that Tier 2 is inferred (product is active but didn't trigger alerts for that specific technique in the lookback window).

If `PlatformAlert_TechniqueCount = 0` or status is FAILED/SKIPPED:
> "ℹ️ No platform-native MITRE-attributed alerts found in the <DAYS>d window. Platform tier classification defaults to Tier 3 (catalog) for all CTID-mapped techniques."

#### 5.2 Alert-Producing Rules by MITRE Tactic

**Data source:** `PRERENDERED.AlertFiring` (pre-rendered table with [AR]/[CD] badges, MITRE cross-reference, severity breakdown)

This section shows which SOC-authored rules are actually generating alerts in the lookback window, with MITRE tactic/technique correlation. Platform alerts (MDE, MDI, MDO, etc.) are intentionally excluded — they are covered in §5.1 Combined Tactic Coverage (Tier 1 alert-proven).

**Section title:** Use the `SectionTitle:` value from the PRERENDERED block. It reads "Top 50 Alert-Producing Rules" when the query hit its cap (results may be truncated), or "N Alert-Producing Rules" when all results fit (no truncation). Render as the subsection heading: `### {SectionTitle}`.

**🔴 CRITICAL: Copy the table from `### AlertFiring` in the `## PRERENDERED` section VERBATIM.**

The pipeline pre-renders the complete table with:
- **Volume badges** (🔴 ≥100 alerts, 🟠 ≥20 alerts) prefix on the Alert column — highlights high-volume drivers at a glance
- `[AR]` / `[CD]` badge prefix on each alert name:
  - **AR** = Analytic Rule (ProviderName `ASI Scheduled Alerts`)
  - **CD** = Custom Detection (identified by `AlertType == CustomDetection` literal string in SecurityAlert)
- Tactics column: from M1 rule inventory for AR rules, from SecurityAlert Tactics column for CD rules
- Techniques column: from M1 rule inventory for AR rules; `—` for CD rules (technique-level detail not available from SecurityAlert)
- Alert count and severity breakdown (H/M/L/I)
- Sorted by alert count descending
- Summary line with AR/CD counts and any limitation notes

**🔴 PROHIBITED:**
| Action | Status |
|--------|--------|
| Recalculating any numeric values | ❌ **PROHIBITED** |
| Changing alert names, badges, or row order | ❌ **PROHIBITED** |
| Adding or removing rows or columns | ❌ **PROHIBITED** |
| Modifying the Summary line | ❌ **PROHIBITED** |

**What the LLM adds (analytical — AFTER the table):**
- Identify which tactics are most operationally active (highest alert volumes)
- Flag tactics with tagged rules but zero firing alerts ("paper tigers") — cross-reference with §5.3
- Note any untagged rules that are firing alerts but lack MITRE coverage attribution
- If untagged rules exist in the `PHASE_1.UntaggedRules` section, call out how many are enabled and recommend MITRE tagging to improve coverage metrics

#### 5.3 Active vs Tagged Tactic Coverage

**Data source:** `PRERENDERED.ActiveVsTagged` (pre-rendered tactic summary table + silent rules detail table)

**🔴 CRITICAL: Copy ALL tables from `### ActiveVsTagged` in the `## PRERENDERED` section VERBATIM — both the tactic summary table AND the `#### SilentRules` detail sub-table.**

The pipeline pre-renders two tables:

**Tactic summary table:**
- Human-readable tactic names in MITRE kill chain order
- **Tagged Rules** — total enabled rules with MITRE tags for this tactic
- **Firing** — count of enabled rules that produced ≥1 alert in the lookback window
- **Silent** — count of enabled MITRE-tagged rules with 0 alerts (paper tigers)
- **Active (Alerts)** — total alert volume from firing rules
- **Status badges** — deterministic, based on firing/silent rule ratio:
  - ✅ **Validated** — most tagged rules are firing
  - 🟡 **Mostly silent** — ≥3 silent rules AND silent ≥ firing (tactic has rules but most aren't producing alerts)
  - ⚠️ **All silent** — tagged rules exist but zero alerts across all of them
  - 🔴 **No coverage** — 0 tagged rules

**Silent Rules detail sub-table (`#### SilentRules`):**
- Lists enabled MITRE-tagged rules (AR or CD) that produced 0 alerts in the lookback window
- **Condensed:** Clusters of ≥3 rules sharing the same (Tactics, Techniques) key are collapsed into a single row with a descriptive label and `(×N)` count. Rules in groups of 1-2 are listed individually.
- Sorted by Tactics then Name for readability
- Includes Source (AR/CD/AR+CD), Tactics, and Techniques columns

| Action | Status |
|--------|--------|
| Recalculating rule counts, alert volumes, or status badges | ❌ **PROHIBITED** |
| Adding/removing rules from the SilentRules table | ❌ **PROHIBITED** |
| Reordering or renaming tactics/rules | ❌ **PROHIBITED** |

**What the LLM adds (analytical — AFTER the tables):**

1. **Silent rule commentary:** Highlight tactics with the highest silent-to-firing ratio. Explain possible causes:
   - Rules may be highly specific (only fires on rare adversary behavior — e.g., ICS/OT rules in an office-centric environment)
   - Data source gaps (cross-reference with §5.5 Data Readiness — a NoData/Partial rule structurally can't fire)
   - Content Hub templates deployed without matching data connectors (common for TI-mapping rules)
   - The 30-day lookback may miss infrequently-firing detections (e.g., quarterly pentest-triggered rules)
2. **Validated highlights:** Note which tactics have the strongest operational validation (high firing-to-tagged ratio)
3. **Cross-reference with §5.5:** If a silent rule also appears in the NoData/Partial list, the root cause is confirmed — missing data source, not detection logic issue. Call this out explicitly.
4. **Actionable summary:** State the total silent rule count and recommend reviewing them for data source gaps or decommissioning unused Content Hub templates

#### 5.4 Incidents by Tactic (conditional)

**Data source:** `PRERENDERED.IncidentsByTactic` (pre-rendered table with human-readable tactic names and TOTAL row)

If `PRERENDERED.IncidentsByTactic` contains a table (not `<!-- NO_DATA -->`):

**🔴 CRITICAL: Copy the pre-rendered table VERBATIM from `PRERENDERED.IncidentsByTactic`.**

The pipeline pre-renders the complete table with:
- **Volume badges** (🔴 ≥100 incidents, 🟠 ≥25 incidents) prefix on the Tactic column — highlights high-volume tactics at a glance
- Human-readable tactic names (CamelCase → display, including non-Enterprise tactics like Pre-Attack, Inhibit Response Function)
- All numeric columns (Incidents, High, Medium, Low, Info, TP, FP, BP)
- Rows sorted by MITRE ATT&CK kill chain order (Reconnaissance → Impact), with non-Enterprise tactics (Pre-Attack, ICS) at the end
- TOTAL row with sums

**🔴 PROHIBITED:**
| Action | Status |
|--------|--------|
| Recalculating any numeric values | ❌ **PROHIBITED** |
| Changing tactic names or row order | ❌ **PROHIBITED** |
| Adding or removing rows | ❌ **PROHIBITED** |

**What the LLM adds (analytical — AFTER the table):**
- Highlight tactics with highest incident volumes and classification ratios
- If FP rate is high for a tactic, note that rules targeting those techniques may need tuning
- Cross-reference with §5.3 Active vs Tagged coverage for consistency

#### 5.5 Data Readiness (Table Ingestion Validation)

**Data source:** `PRERENDERED.DataReadiness` (pre-rendered summary + detail tables) + raw data in `PHASE_3.DataReadiness` + `PHASE_3.DataReadiness_Summary` + `PHASE_3.MissingTables` + `PHASE_3.TierBlockedTables`

This section validates whether enabled analytic rules have the data they need to fire.

**🔴 CRITICAL: Copy the tables from `### DataReadiness` in the `## PRERENDERED` section VERBATIM.**

The pipeline pre-renders all §5.5 tables deterministically:
- **Summary table** (5 rows: Ready/Partial/NoData/TierBlocked/DataReadiness%)
- **Rules with Missing Data Sources** detail table (non-Ready rules with status badges)
- **Missing Tables — Impact Summary** (tables sorted by rules affected)
- **Phantom Coverage — Tier-Blocked Tables** (tables on non-Analytics tiers)

| Action | Status |
|--------|--------|
| Recalculating rule counts or readiness percentage | PROHIBITED |
| Modifying status badges (✅/⚠️/🔴/🚫) | PROHIBITED |
| Reordering rows in any table | PROHIBITED |
| Adding/removing rules from the detail table | PROHIBITED |

**What the LLM adds (narrative only):**

1. **Section header and intro paragraph:** Explain that detection rules can only fire if their underlying data sources are actively ingesting events. Reference that this analysis extracts KQL table dependencies from each enabled analytic rule and validates them against the 7-day ingestion volume from the Usage table.

2. **Likely cause inference** for missing tables (add a "Likely Cause" interpretation after the Missing Tables table):
   - Tables with `_CL` suffix → Custom table, connector may be disconnected or logic app stopped
   - `SecurityEvent` → Windows agent (MMA/AMA) not deployed, or DCR not collecting expected EventIDs
   - `Syslog` / `CommonSecurityLog` → Linux agent or CEF forwarder not connected
   - AWS/GCP tables → Cross-cloud connector not configured; rules may be Content Hub templates without prerequisite data source
   - `ThreatIntelligenceIndicator` → Threat intelligence connector not enabled

3. **Tier-blocked narrative:** TierBlocked is a STRONGER signal than NoData — it means the rule is **structurally** unable to fire. Cross-reference with §5.6 Connector Health — a connector may show healthy (data IS flowing) but rules targeting the table are still non-functional.

4. **AlertFiring contradiction check:** Cross-reference NoData rules against `PHASE_3.AlertFiring`. If a NoData rule also produced alerts, flag as parser limitation (enrichment function names extracted as table dependencies). Do NOT recommend disabling such rules.

5. **Cross-reference with §5.3:** If a "paper tiger" rule also appears in NoData list, the root cause is confirmed — missing data source, not detection logic issue.

6. **Data Readiness limitations note** (include at end):
   > *Data readiness validates table-level ingestion presence, not event-level completeness. A table with active volume may still lack specific event types a rule requires. Complete detection validation requires purple team exercises such as Atomic Red Team tests mapped to ATT&CK technique IDs.*

**Known parser false positives** (include as a separate note if Partial rules contain obvious non-table names):
> *Some "Partial" rules may show false-positive missing tables where KQL column names, `let` variable names, or enrichment function identifiers were misidentified as table names. These rules likely have all required tables flowing and are effectively Ready.*

**If NO_DATA comment appears:** Report that data readiness analysis is unavailable — M7 may have failed or no enabled rules found.

#### 5.6 Connector Health (SentinelHealth Enrichment)

**Data source:** `PRERENDERED.ConnectorHealth` (pre-rendered summary + detail tables) + raw data in `PHASE_3.ConnectorHealth` + `PHASE_3.ConnectorHealth_Summary`

This section enriches Data Readiness with **leading indicator** signals from the SentinelHealth table.

**🔴 CRITICAL: Copy the tables from `### ConnectorHealth` in the `## PRERENDERED` section VERBATIM.**

The pipeline pre-renders all §5.6 tables deterministically:
- **Summary table** (3 rows: Healthy/Degraded/Failing)
- **Connectors with Health Issues** detail table (failing/degraded connectors sorted by health %)

| Action | Status |
|--------|--------|
| Recalculating connector counts | PROHIBITED |
| Modifying status badges (✅/⚠️/🔴) | PROHIBITED |
| Reordering or adding/removing connectors | PROHIBITED |

**What the LLM adds (narrative only):**

1. **Section header and intro paragraph:** Explain that SentinelHealth provides proactive connector failure detection — catching failures before they degrade 7-day ingestion averages.

2. **SentinelHealth coverage limitation note:** Only supported connectors are tracked (AWS CloudTrail/S3, Office 365, Dynamics 365, MDE, TI-TAXII/TIP, Codeless Connector Framework). CEF/Syslog agents, custom `_CL` tables, and many first-party connectors are NOT covered.

3. **Cross-reference with Data Readiness:** For each failing/degraded connector, check whether any rules classified as "Ready" depend on tables fed by that connector. Common mappings:
   - **Office 365** → OfficeActivity
   - **AWS CloudTrail** → AWSCloudTrail
   - **Threat Intelligence - TAXII / TIP** → ThreatIntelligenceIndicator

4. **Do NOT treat M8 absence as a deficiency.** SentinelHealth is supplementary enrichment.

**If NO_DATA comment appears:** Report that connector health monitoring is unavailable — SentinelHealth may not be enabled.

**Known parser false positives** (include as a separate `ℹ️` note if Partial rules contain obvious non-table names):
> *Some "Partial" rules may show false-positive missing tables where KQL column names, `let` variable names, or enrichment function identifiers were misidentified as table names by the extraction logic (e.g., "ResultType", "CallerIPAddress", "StartTime", "ActivityTime", "Role", "Create", "RequestURL", "CreateRemoteThreadApiCall"). These rules likely have all required tables flowing and are effectively Ready. Similarly, SAP Solution rules may show enrichment function names (SAPSystems, SAPUsersGetVIP) as missing tables — if the rule appears in AlertFiring, the primary table is ingesting.*

---

### 6. Recommendations

Synthesize all findings into actionable recommendations organized by priority.

#### 6a. ⚡ Quick Wins

Items that can be implemented immediately with minimal effort:

- **Apply AI-suggested MITRE tags** (from §4c) — if `State` is CompletedByUser with all verified Applied, note: "✅ Already completed and verified". If tags remain unapplied: "<COUNT> rules can be tagged via the Sentinel portal. Immediate improvement to Tagging score"
- **Enable Content Hub templates** for zero-coverage high-priority techniques (T1114 Email Collection, T1213 Data from Info Repos, etc.) — check [Sentinel Content Hub](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog)
- **Verify SOC Optimization recommendations** — review the [SOC Optimization dashboard](https://security.microsoft.com/sentinel/precision) for actionable template activations

**⚠️ Enabled-status verification:** When recommending that alert-producing untagged rules be tagged (e.g., "Tag Test2 and IOC historical match"), always cross-check the `Enabled` column from `PHASE_1.UntaggedRules`. A rule may have produced alerts during the lookback window but be currently **disabled**. If a rule is `Enabled: False`, note this explicitly: "currently disabled but was active during the lookback period". Never describe a disabled rule as "enabled" in recommendation text — this contradicts the §3 untagged rules table and confuses readers.

#### 6b. 🔧 Medium-Term Improvements

Items requiring investigation or custom rule development:

- **Address top threat scenario gaps** — prioritize scenarios from the §4b active gaps table (Active, InProgress, and ⚠️ Premature CompletedByUser). **Exclude Reviewed & Addressed scenarios** (CompletedByUser with ≥50% completion rate) — the SOC team has already triaged these
- **Develop custom detections** for cloud-relevant uncovered techniques (T1528 Steal Application Access Token, T1621 MFA Request Generation, T1537 Transfer Data to Cloud Account)
- **Review paper tiger rules** (if §5 data available) — rules that never fire may have overly specific logic, data source issues, or incorrect MITRE tagging. When recommending rules be disabled due to NoData status, **always exclude** rules that appear in `AlertFiring` — those are firing despite the parser's NoData classification (enrichment-table false positive)
- **Balance tactic coverage** — if rules are concentrated in 3-4 tactics, consider redistributing detection investment across the kill chain

#### 6c. 🔄 Ongoing Maintenance

Recurring operational practices:

- **Quarterly MITRE coverage review** — re-run this report quarterly to track coverage improvements and catch regressions
- **New rule MITRE tagging** — when deploying new analytic rules, always assign appropriate MITRE tactics and techniques
- **ATT&CK framework updates** — when MITRE publishes new ATT&CK versions, update `mitre-attck-enterprise.json` and re-run to assess coverage against new techniques
- **SOC Optimization monitoring** — review SOC Optimization recommendations monthly for new coverage suggestions

#### 6d. Coverage Priority Matrix

Final summary table mapping business impact to coverage investment:

```markdown
| Priority | Tactic/Scenario | Current State | Recommended Action | Effort |
|----------|----------------|---------------|-------------------|--------|
| 🔴 1 | <TACTIC/SCENARIO> | <CURRENT> | <ACTION> | <Low/Med/High> |
| 🔴 2 | <TACTIC/SCENARIO> | <CURRENT> | <ACTION> | <Low/Med/High> |
| 🟠 3 | <TACTIC/SCENARIO> | <CURRENT> | <ACTION> | <Low/Med/High> |
| ... | ... | ... | ... | ... |
```

Effort column = implementation difficulty (Low = enable template; Medium = customize existing rule; High = develop new rule from scratch). Unlike Risk in the ingestion report, Effort here IS about implementation complexity because this is a remediation planning table.

**⛔ PROHIBITED:** Including ⬜ Inherent blind spot tactics (Reconnaissance, Resource Development) in the Coverage Priority Matrix. These tactics have no deployable KQL detections — listing them as actionable recommendations is misleading. If the user specifically asks about them, explain the protect/respond vs detect distinction and suggest compensating controls in a separate note.

**⛔ PROHIBITED:** Including CompletedByUser scenarios with ≥50% completion rate (Reviewed & Addressed per Rule E) in the Coverage Priority Matrix or Top 3 Recommendations. These have been triaged by the SOC team. Only include CompletedByUser scenarios flagged as ⚠️ Premature (<50% rate).

---

### Appendix

#### A. Query Reference

| Phase | Query | Type | Description | Status |
|-------|-------|------|-------------|--------|
| 1 | M1 | REST | Analytic Rule MITRE Extraction | <OK/FAILED> |
| 1 | M2 | Graph | Custom Detection MITRE Extraction | <OK/SKIPPED/FAILED> |
| 2 | M3 | REST | SOC Optimization Coverage | <OK/FAILED> |
| 3 | M4 | KQL | Alert Firing by MITRE | <OK/FAILED> |
| 3 | M5 | KQL | Incidents by Tactic | <OK/FAILED> |
| 3 | M6 | KQL | Platform Alert MITRE Coverage | <OK/FAILED> |
| 3 | M7 | KQL | Table Ingestion Volume (Data Readiness) | <OK/FAILED> |
| 3 | M8 | KQL | Data Connector Health (SentinelHealth) | <OK/FAILED/NO_DATA> |

**Generated:** `META.Generated` | **Execution Time:** `META.ExecutionTime` | **Phases:** `META.Phases`

#### B. MITRE Coverage Score Methodology

The MITRE Coverage Score is a composite metric (0–100) computed from 5 weighted dimensions. It is designed to reward **operationally validated** detection coverage — teams that purple-team their rules and confirm they fire score higher than teams that deploy rules without validating them.

##### Dimensions & Weights

| # | Dimension | Weight | What It Measures |
|---|-----------|--------|-----------------|
| 1 | **Breadth** | 25% | Readiness-weighted technique coverage across the ATT&CK framework |
| 2 | **Balance** | 10% | Kill chain phase distribution — are all 14 tactics represented? |
| 3 | **Operational** | 30% | % of MITRE-tagged rules that actually produced alerts in the lookback period |
| 4 | **Tagging** | 15% | % of all rules (enabled + disabled) with at least 1 MITRE tag |
| 5 | **SOC Alignment** | 20% | Completion rate of Microsoft SOC Optimization coverage recommendations |

**Why Operational is the heaviest weight (30%):** A rule that has never fired is unvalidated — it *might* detect an attack, or it might have a broken query, wrong data source, or logic error. Teams that run purple team exercises, atomic tests, or otherwise trigger their detections prove their rules work. This score rewards that effort directly.

##### Breadth: Readiness-Weighted Credit

Unlike a simple "technique has a rule = covered" binary, Breadth assigns **fractional credit** per technique based on the data readiness of its **best** covering rule:

| Rule's Best Status | Credit | Meaning |
|-------------------|--------|---------|
| **Fired** (produced alerts) | 1.00 | Validated by real or simulated attack — highest confidence |
| **Ready** (data exists, 0 alerts) | 0.75 | Rule *can* fire — data pipeline is healthy, just hasn't been triggered |
| **Partial** (some tables missing) | 0.50 | Rule partially functional — may detect some variants but not all |
| **NoData** (zero ingestion) | 0.25 | Paper tiger — technique shows in the matrix but rule cannot fire |
| **TierBlocked** (table on wrong tier) | 0.00 | Structurally impossible — rule can never execute |

**How it works:** For each ATT&CK technique, the system checks every rule covering it and takes the **maximum** credit. If a technique has 1 firing rule and 10 NoData rules, it gets full 1.00 credit — the firing rule proves detection works. Both Analytic Rules (AR) and Custom Detection rules (CD) are assessed with the same readiness constraints.

The final Breadth score blends 60% readiness-weighted rule coverage + 40% combined coverage (rules + platform Tier 1 + Tier 2 detections).

##### Score Interpretation

| Score Range | Assessment | Typical Profile |
|-------------|------------|-----------------|
| 80–100 | 🟢 **Strong** | Broad coverage, balanced tactics, operationally validated, well-tagged, SOC-aligned |
| 60–79 | 🔵 **Good** | Solid coverage with some gaps; may have clustering or unvalidated rules |
| 40–59 | 🟡 **Moderate** | Significant gaps in breadth or operational validation; improvement opportunities |
| 20–39 | 🟠 **Developing** | Limited coverage across the framework; many uncovered tactics |
| 0–19 | 🔴 **Critical** | Minimal detection coverage; urgent investment needed |

#### C. Limitations

1. **Coverage ≠ detection:** Having a rule tagged with a technique does not guarantee detection — rule quality, data source availability, and adversary TTPs vary
2. **Operational dimension requires Phase 3:** If KQL queries fail, Operational score defaults to 0. This is a data gap, not necessarily poor operational coverage
3. **Custom Detection availability:** Graph API requires `CustomDetection.Read.All` admin consent. If unavailable, coverage metrics are AR-only
4. **Sub-technique granularity:** Coverage is measured at the parent technique level (e.g., T1078). Sub-technique-level coverage (T1078.001, T1078.004) would require deeper rule query text analysis
5. **ATT&CK framework currency:** The reference JSON reflects a point-in-time snapshot of ATT&CK Enterprise. Update when MITRE publishes new versions
6. **SOC Optimization scope:** Coverage recommendations are Microsoft's assessment based on deployed data sources and available Content Hub templates. They may not cover custom or third-party detection logic
7. **Paper tiger detection** depends on the lookback window — a rule that fires infrequently (quarterly) may appear as a paper tiger in a 30-day window

---

**Report generated:** <TIMESTAMP> | **Skill:** mitre-coverage-report v1 | **Mode:** <inline/file/both>
