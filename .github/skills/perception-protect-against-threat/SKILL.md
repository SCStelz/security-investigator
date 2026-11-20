---
name: perception-protect-against-threat
description: 'Run (or reuse) Microsoft Perception''s "Protect against a threat" playbook for a threat-intelligence article via the Perception MCP. The multi-agent run (Threat Intelligence, Recon, Detection Authoring, Posture Prioritization; about an hour) produces extracted threat intel with a threat-intel-platform gap table, tenant-aware detection proposals marked ready-to-deploy or requires-tuning, and threat-contextualised posture priorities. Validates the run (a failed session still ends Idle), presents results, and hands detections that need tuning to perception-tune-detection. Requires the Perception MCP; stops politely if it is not configured. Trigger keywords: "perception protect against a threat", "protect against this threat with perception", "perception proactive protection", "perception detections for article", "perception threat article".'
threat_pulse_domains: [perception]
drill_down_prompt: 'Search existing Perception protect runs or run the Protect against a threat playbook for {entity}'
---

# Perception — Protect Against a Threat

## Purpose

Turn a threat-intelligence article into **tenant-aware protection** using Microsoft Perception's `proactive-protection` playbook, then bring the human and this repo's tooling in to validate and tune what it proposes. It **complements** `threat-intel-campaign` (tested hunts) and `detection-authoring` (deployment) — it does not replace them. Positioning: *Perception proposes; this repo tests, tunes and deploys.*

**Read first:** [`.github/skills/perception-shared/REFERENCE.md`](../perception-shared/REFERENCE.md). **Only need the intelligence?** `perception-extract-threat-intel` reads existing Threat Intelligence reports for free (and can start a TI-only run for ≈ $4–$7) instead of this ≈ $209–$527 four-agent run.

**Entity:** a threat article — preferably the **internal Activity Profile ID + exact title** (known-good input form), otherwise an `https://` article URL — **or just a topic/name** ("LiteLLM", "are we protected against X?"), which Phase 1 resolves through the session cache.

**Runtime warning:** the full run is **≈ 1 hour** (TI ≈ 3 → Recon ≈ 14 → Detection Authoring ≈ 29 → Posture ≈ 30 min). It is meant to be **pre-run**; present it as a background job.

---

## Workflow

### Phase 0 — Preconditions
**🔴 MCP GATE — do this before reading the session index, saved reports, `reports/`, or Mission Control findings.** Check that `perception-mcp-*` tools are available (use the tool search tool; they are deferred). **If they are not: your reply MUST begin with the setup guidance** — *"The Perception MCP isn't configured in this session. Add an HTTP MCP server for `https://perception.microsoft.com/mcp` (e.g. `.mcp.json`: `\"perception-mcp\": { \"type\": \"http\", \"url\": \"https://perception.microsoft.com/mcp\" }`), sign in, reload MCP servers and retry. Needs Perception enabled in the tenant and Security Reader or higher. (Docs: https://learn.microsoft.com/en-us/security/agentic-security/agentic-security-mcp — it lists `https://perception.microsoft.com/mcp`; the `sentinel.microsoft.com` URL above also responds.)"* After the guidance you may *offer* a saved result for the same input, labeled "saved result, not re-validated — Perception MCP unavailable" `[asserted]`. **In this offline mode you must NOT write or edit any report, post a Mission Control finding, update `temp/perception_sessions.json`, run new analysis queries, or suggest follow-ups that need fresh Perception data.** A saved index entry or report is never a reason to skip the guidance. Full rules: REFERENCE §1.1. Then state the tenant.

### Phase 1 — Resolve the input
0. **Topic, name or question** (no ID/URL): refresh the session cache (REFERENCE §3.7; same steps as `perception-extract-threat-intel` Phase 1) and run `session_cache.py search <terms> --ti-only --articles`. One article matches → confirm it with the user (title + date) and continue with its internal ID. Several → list them and let the user pick. None → say so **with the cache depth**; do not guess an ID; offer `perception-extract-threat-intel` (find or request the article) or ask for a portal link/URL. Never start a run from a topic alone.
1. If the user gave an internal ID + title → use it (REFERENCE §2: `type: defenderThreatIntelligenceId`, `values:[<id>]`, `displayName:<title>` — required).
2. If the user gave only a URL → external URLs failed in one trial on an earlier MCP version (retry advised "in a few minutes"). Offer: **(a)** run `analyze-article` first as a ≈ 4 min viability check, then proceed to `proactive-protection` only if it extracted content; **(b)** go straight to the full run and accept the risk of a quick failure (it fails fast, in ~2 minutes, before any downstream agent runs).
3. Optionally, if a `list_sessions` scan finds a previous run for the same article under an internal ID (its `inputs[].displayName` shows the Activity Profile title), tell the user that form is available.

### Phase 2 — Lookup before running
Use the session cache first: `session_cache.py search "<title words>" --playbook proactive-protection` (also `detect-emerging-threats`, whose sessions carry the same four-agent style reports when they ran Detection Authoring), state its depth, and **validate each candidate with `list_outputs`** (REFERENCE §5; status alone is not proof). If the cache cannot answer, fall back to REFERENCE §3 (**page with `continuationToken` to the boundary or the 10-page cap — one page is never enough; state the scan depth reached**): match `tags` `playbookId=proactive-protection` (and `analyze-article`) plus `input:threat-intelligence=<id>` (internal), or `inputs[].displayName`/`entityUrl` = the URL (external runs record `value: "EXTERNAL"`). The article's publish/activity date is the boundary when known; if it isn't, page to the cap. Show candidates (status, createdAt, initiator, which agents completed via `list_agent_runs`). **Offer reuse** — a finished run has everything needed for the demo. Discard failed and report-less runs (REFERENCE §5). **URL input with no usable match:** apply the **title fallback** (REFERENCE §3.6) — fetch the page title, offer title-matched runs as *probable same article* (e.g. a run started from the internal Activity Profile ID) and ask the user to confirm before reusing one; this avoids an unnecessary ≈ 1 h re-run.

### Phase 3 — Start (if no reusable run)
Confirm (REFERENCE §1.3): playbook, article, ≈ 1 h runtime, **est. Perception cost ≈ $209–$527 for the four reports (Recon dominates)**, agent identity, capacity. Then `list_playbooks` → `start_session` with the shape from REFERENCE §2. Record it in `temp/perception_sessions.json` (`kind:"article"`).

### Phase 4 — Poll with per-stage progress
REFERENCE §4. Report stage transitions from `list_agent_runs` as they happen: Threat Intelligence → Recon → Detection Authoring → Posture Prioritization (one agent run each). If the Threat Intelligence run fails or finishes without a report (e.g. article not accessible), the downstream agents never start — stop polling and report the failure immediately.

### Phase 5 — Validate
REFERENCE §5. Expected files: `threat_intelligence_report.md`, `reconnaissance_report.md`, `detection_report.md`, `prioritization_response.md` (+ `summary.md`). Classify per stage — it is common for some stages to finish and others to be partial (e.g. posture scoring failed, detection measurement unavailable because of Advanced Hunting quota → *estimated, not measured*).

### Phase 6 — Present (save this skill's report as `report.md` plus one verbatim file per agent report in `reports/perception/protect-against-threat/<slug>_<yyyymmdd>/`; every Perception session mentioned is a clickable link — REFERENCE §9)
1. **Threat intelligence:** summary, actor/attribution (say "unattributed" if so), TTPs with ATT&CK IDs, indicators, and the **TIP coverage table** (already tracked vs missing). Execute the report's hunting queries and sweep the indicators in the tenant automatically (REFERENCE §6: bounded, read-only, AH ≤ 30 d; ask before Data Lake > 30 d) through this repo's KQL pre-flight path: (`EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, `DeviceNetworkEvents`, …) — "not seen in this tenant" is a valid, useful result.
2. **Detections:** table of candidates — name, severity, MITRE, **readiness** (*ready to deploy* / *requires tuning*), **measured vs estimated** volume, existing-similar-detection count. Decode wizard links with `.github/skills/detection-authoring/wizard_link.py decode` when the user wants to see the KQL.
3. **Recon:** scope of the read-only inventory and what it explicitly did *not* test (configuration ≠ tested reachability).
4. **Posture priorities:** ranked risks with **TI relevance** and the agent's own stated limitations (e.g. controls it could not validate = *coverage gap, not healthy state*). Split each item into the **observation** (what Perception found in the tenant: label *Perception-reported*, with the run date) and **Perception's assessment** (rank, likelihood, impact, TI relevance). **Automatically spot-check** the top-ranked observations with this repo's own read-only queries (`ai-agent-posture` / `exposure-investigation` patterns, Advanced Hunting, `ExposureGraph*`; bounded, no approval; REFERENCE §6) and report "N of M re-confirmed" with `[verified: <table>, <window>]`; items you could not check stay `[perception: session <id8>]`. Offer the full `ai-agent-posture` / `exposure-investigation` run (it is a full skill: ask) for the rest.
5. **Session link (mandatory):** `report.md` opens with the `**Perception session:** [🔗 Open session …]` line (REFERENCE §9) for the run it uses (and each other run it cites), and passes `session_cache.py check-links <report.md> --fix` (exit 0) before you present it; lookup tables link every session id.
6. Tag claims `[perception: session <id8>]` (= `[asserted]`). Any attack-graph/mermaid diagrams Perception included follow the limits in REFERENCE §7.1 (verbatim, few, size-capped).

### Phase 7 — Hand-off
- *Ready to deploy* detections: show the wizard link as-is for human review; deployment is a human click. If the user wants them promoted into this repo, route to `detection-authoring` (cd-metadata contract).
- *Requires tuning* detections: offer **`perception-tune-detection`** (Mission Control card) with this session as the entity.

### Phase 8 — Record
Post a finding (if launched from Mission Control): campaign summary, detection readiness counts, notable partial/failed stages, tagged `[perception: session <id8>]`. **Wording:** describe posture items as *Perception-reported* and say how many you spot-checked ("3 of 8 re-confirmed"); do not write "asserted", "unverified" or "need independent confirmation" for the whole posture set. A follow-up to `ai-agent-posture` / `exposure-investigation` should say what it adds ("verify the remaining items and cross-check ownership"), not that Perception's items are doubtful.

---

## Guardrails
- Never auto-start; always confirm. Never run red-team playbooks: refuse `red-web-pentest` / `find-fix-web-app-security-risks` outright, without asking for a target (REFERENCE §1.4).
- A finished session is not necessarily a useful one: a lone audit-log output means the article retrieval failed (REFERENCE §5).
- Perception detections are **proposals** — nothing is deployed by this skill.
- Save only under gitignored paths; remediation as portal paths only (REFERENCE §8).
- Don't present posture findings as proof the campaign reached the tenant; Perception itself says whether it found evidence of delivery or clicks — report that sentence verbatim in substance.
