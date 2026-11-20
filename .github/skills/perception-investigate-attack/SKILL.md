---
name: perception-investigate-attack
description: 'Investigate a Defender/Sentinel incident with Microsoft Perception (Attack Investigation Agent via the Perception MCP). Checks whether a Perception investigation already exists and reuses it, otherwise (after confirmation) starts the investigate-incident playbook asynchronously, polls it, validates the result, and presents the verdict, timeline, entities and visibility limits tagged as Perception output. Optionally compares against this repo''s own incident-investigation verdict and shows only the deltas. Requires the Perception MCP; stops politely if it is not configured. Trigger keywords: "perception investigate incident", "perception incident investigation", "ask perception about incident", "did perception already investigate", "perception session for incident".'
threat_pulse_domains: [perception]
drill_down_prompt: 'Search existing Perception investigations or run the Investigate attack playbook for incident {entity}'
---

# Perception — Investigate Attack

## Purpose

Use Microsoft Perception's **Attack Investigation Agent** as an independent, agentic *second opinion* on an incident. It **complements** `incident-investigation` — it never replaces it. Perception is fast and broad; this repo is evidence-gated. Together you get speed plus provenance.

**Read first:** [`.github/skills/perception-shared/REFERENCE.md`](../perception-shared/REFERENCE.md) — preconditions, input shapes, session lookup, polling, validation, evidence tags, output paths, remediation policy. This skill does not repeat those rules; it applies them.

**Entity:** an incident number (Defender XDR incident ID, i.e. `ProviderIncidentId`). If the user gives a Sentinel `IncidentNumber`, translate it to `ProviderIncidentId` first (Sentinel ↔ Defender ID mapping rule).

---

## Workflow

### Phase 0 — Preconditions
**🔴 MCP GATE — do this before reading the session index, saved reports, `reports/`, or Mission Control findings.** Check that `perception-mcp-*` tools are available (use the tool search tool; they are deferred). **If they are not: your reply MUST begin with the setup guidance** — *"The Perception MCP isn't configured in this session. Add an HTTP MCP server for `https://perception.microsoft.com/mcp` (e.g. `.mcp.json`: `\"perception-mcp\": { \"type\": \"http\", \"url\": \"https://perception.microsoft.com/mcp\" }`), sign in, reload MCP servers and retry. Needs Perception enabled in the tenant and Security Reader or higher. (Docs: https://learn.microsoft.com/en-us/security/agentic-security/agentic-security-mcp — it lists `https://perception.microsoft.com/mcp`; the `sentinel.microsoft.com` URL above also responds.)"* After the guidance you may *offer* a saved result for the same input, labeled "saved result, not re-validated — Perception MCP unavailable" `[asserted]`. **In this offline mode you must NOT write or edit any report, post a Mission Control finding, update `temp/perception_sessions.json`, run new analysis queries, or suggest follow-ups that need fresh Perception data.** A saved index entry or report is never a reason to skip the guidance. Full rules: REFERENCE §1.1. Then state the active tenant.

### Phase 1 — Incident facts (read-only)
`GetIncidentById` (`includeAlertsData: false`) for the incident: title, severity, status, `createdDateTime`, assignee, comments. Show the Defender portal link with `?tid=`.
- **Age gate:** if the incident is **> 30 days old**, warn that the Attack Investigation Agent cannot access it (REFERENCE §5) and ask whether to continue or use a newer seed alert.
- Note if the alerts are Purview DLP / app-governance / Sentinel-workspace sourced (extra agent grants needed).
- **Repo investigation lookup (mandatory, cheap — do it now, before Phase 2):** `glob` `reports/incidents/Incident_<id>_Investigation_*.md` and grep `.mission-control/findings.json` for `skill` = `incident-investigation` mentioning the incident; also check this conversation. Remember the result (source, filename/date, its verdict) — Phase 6 must report it and Phase 7 uses it. Do **not** skip this because a saved Perception report or index entry already exists.

### Phase 2 — Lookup before running
Follow REFERENCE §3: scan `list_sessions` — **page through with `continuationToken` until a page's oldest `createdAt` is older than the incident's `createdDateTime` (or the 10-page cap)**; one page is never enough — matching `tags` `playbookId=investigate-incident` **and** `input:incident=<id>` exactly (no title parsing):
1. Local index → 2. `list_sessions` scan to the boundary.
3. Discard unusable sessions (not `succeeded`, or no real `report.md`). If one or more usable sessions exist, show them (status, createdAt, `initiatedBy`) and **offer reuse** (fastest) or a fresh run.
4. State the scan depth you actually reached (pages, sessions, oldest `createdAt`, stop reason) in the output — REFERENCE §3.5.
4. State plainly that the incident itself carries no trace of Perception sessions (verified: no comment, tag or summary is written back), so the index/scan is the only way to find prior runs.

### Phase 3 — Start (only if no reusable session, or user wants a fresh run)
Confirm (REFERENCE §1.3): *"Start Perception `investigate-incident` for incident <id>? Async, typically 15–50 minutes, est. Perception cost ≈ $2.69–$18.82 (billed separately from Copilot credits; REFERENCE §1.3), runs under the agent's identity."* Then follow REFERENCE §2 (`list_playbooks` → GUID `playbookId`; `inputs` array):

```
perception-mcp-start_session
  playbookId: <GUID of investigate-incident from list_playbooks>
  inputs: [{"key":"incidentOrAlert","type":"defenderIncidentId","values":["<id>"]}]
```
Record `{kind:"incident", key:"<id>", sessionId, playbook, startedAt}` in `temp/perception_sessions.json`. Tell the user it is running in the background and that they can keep working.

### Phase 4 — Poll
REFERENCE §4 (`get_session` status; `list_agent_runs` for the Attack Investigation Agent's state and duration). Report one short progress line per check. Do not block the conversation unless the user asked you to wait.

### Phase 5 — Validate
REFERENCE §5: `get_session_summary` + `list_outputs`; require a real `report.md`. Classify **complete / partial / failed**. For failed/partial runs show the reason (e.g. incident too old, access, throttling) and offer a retry or the troubleshooting checks from the Attack Investigation Agent docs.

### Phase 6 — Present
Read `report.md` (`read_output`; if too large, parse the saved temp file). Present, with emoji conventions from the repo:
- **Verdict:** classification, determination, confidence.
- **Summary**, the **Attack graph** (Perception's mermaid block copied verbatim, colored per REFERENCE §7.1, and subject to its limits), and the **timeline** (condensed table).
- **Affected entities / IOCs** (as Perception states them).
- **Visibility limits** and anything Perception could not verify (mandatory section — never drop it).
- **Recommended response** re-rendered as portal paths (REFERENCE §8).
- Tag every load-bearing claim `[perception: session <id8>]`.
- **Repo investigation line (mandatory):** state either *"Repo investigation found: `<file or finding>` (<date>) — verdict <X>"* with an offer to compare (Phase 7), or *"No repo investigation found (checked conversation, `reports/incidents/`, Mission Control findings)"*. Never recommend running `incident-investigation` "for a side-by-side" when Phase 1 found one.
Save the full report to `reports/perception/investigate-attack/incident_<id>_<yyyymmdd>.md` (create the folder if missing) (gitignored) and give the path. **Links:** the report header and every mention of the incident or a Perception session are clickable Markdown links, never bare URLs or IDs (REFERENCE §9). Update the index entry (`status`, `reportPath`). **Session link (mandatory):** the report opens with the `**Perception session:** [🔗 Open session …]` line (REFERENCE §9) and passes `session_cache.py check-links <report.md> --fix` (exit 0) before you present it.

### Phase 7 — Compare (automatic when a repo investigation exists; the lookup already happened in Phase 1)
Use the repo investigation found in Phase 1 (sources, in order: this conversation's `incident-investigation` result; the newest saved `reports/incidents/Incident_<id>_Investigation_*.md` — state filename/date and that it may predate or be superseded; a Mission Control `incident-investigation` finding). **When a saved Perception report is reused (no fresh Phase 3–6), still run Phase 1's lookup and still offer the comparison.**
If one exists — or the user asks — do the comparison (no approval needed: it reads saved reports and runs bounded read-only checks, REFERENCE §6), reading the **verdict, key entities, timeline and recommendations** and showing **deltas only**:
| Item | This repo | Perception | Assessment |
- Agreements: note briefly.
- Perception-only claims: list them and **independently query** the relevant tables (follow the KQL pre-flight checklist) before citing them as `[verified]`.
- Disagreements: highlight for the human; do not pick a winner.
If none of the three exists, offer to run `incident-investigation` for the comparison rather than assuming (a full skill run: ask). A saved report is `[asserted]` context (not re-tested) unless you re-query its key claims.

### Phase 8 — Record
If launched from Mission Control, post a finding tagged `[perception: session <id8>]` (treated as `[asserted]`) — verdict, confidence, whether reused or fresh, and any partial/failed caveats.

---

## Guardrails
- Never auto-start a session; always confirm. Allow-list only: refuse `red-web-pentest`, `find-fix-web-app-security-risks` and any other non-listed playbook outright (REFERENCE §1.4).
- A finished session is not necessarily a useful one — validate the content (REFERENCE §5).
- Never write Perception output to tracked files; never emit state-changing commands.
- Never run red-team playbooks.
- Tenant-context check (if applicable) still applies before any risk assessment you add on top of Perception's output; mark memory-sourced facts `[asserted]`.
