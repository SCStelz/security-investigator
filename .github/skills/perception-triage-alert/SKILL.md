---
name: perception-triage-alert
description: 'Triage a Defender alert with Microsoft Perception (Triage Agent via the Perception MCP). Checks the alert and whether its type is on Microsoft''s documented Triage Agent list (warns, never silently refuses, when it is not), reuses an existing Perception triage session for that alert if one exists (manual or automatic), otherwise (after confirmation) starts the Triage alert playbook, polls it, validates the result (a "Not set" classification is inconclusive, not clean), and presents the verdict and reasoning tagged as Perception output next to Defender''s current classification of the alert, flagging disagreements for a human. Optionally compares with this repo''s own incident investigation and verifies Perception''s claims. Requires the Perception MCP; stops politely if it is not configured. Trigger keywords: "perception triage alert", "triage this alert with perception", "perception triage verdict", "did perception triage this alert", "is this alert a false positive perception", "perception alert verdict".'
threat_pulse_domains: [perception]
drill_down_prompt: 'Search existing Perception triage verdicts or run the Triage alert playbook for alert {entity}'
---

# Perception — Triage Alert

## Purpose

Use Microsoft Perception's **Triage Agent** as an independent, agentic *second opinion* on a single Defender alert: **true positive, false positive, or could not decide**, with reasoning. Many tenants run it automatically, so a verdict often already exists; this skill finds it before spending anything. It **complements** `incident-investigation` / `user-investigation` and never replaces them: Perception is fast and broad, this repo is evidence-gated. A Perception verdict stays `[asserted]` until re-checked here.

**Read first:** [`.github/skills/perception-shared/REFERENCE.md`](../perception-shared/REFERENCE.md): preconditions, input shapes, session lookup, polling, validation, evidence tags, output paths, remediation policy. This skill applies those rules; it does not repeat them.

**Helper (deterministic, no network):** [`triage_helper.py`](triage_helper.py) with a snapshot of Microsoft's supported-alert list ([`supported_alerts.json`](supported_alerts.json)).
```
python .github/skills/perception-triage-alert/triage_helper.py check "<alert title>"
python .github/skills/perception-triage-alert/triage_helper.py parse-report <triage_report.md>
python .github/skills/perception-triage-alert/triage_helper.py compare --perception "<verdict>" --defender <classification>
python .github/skills/perception-triage-alert/triage_helper.py refresh <learn page saved by microsoft_docs_fetch>   # when the Learn list changed
```

**Entity:** a Defender alert: its **alert ID** (the `id` that `GetAlertById` / `ListAlerts` return, e.g. `da…_1`, `fa…-08df…`) or a Defender portal alert link (`…/alerts/<id>`). A Sentinel `SecurityAlert.SystemAlertId` is **not** accepted: find the Defender alert ID (the alert's `VendorOriginalId`/`ProviderAlertId`, or `AlertInfo.AlertId`) and confirm it resolves with `GetAlertById` before using it. An *incident* number is not an alert: if given one, list its alerts and ask which to triage.

---

## Workflow

### Phase 0 — Preconditions
**🔴 MCP GATE — do this before reading the session cache, saved reports, `reports/`, or Mission Control findings.** Check that `perception-mcp-*` tools are available (use the tool search tool; they are deferred). **If they are not: your reply MUST begin with the setup guidance** — *"The Perception MCP isn't configured in this session. Add an HTTP MCP server for `https://perception.microsoft.com/mcp` (e.g. `.mcp.json`: `\"perception-mcp\": { \"type\": \"http\", \"url\": \"https://perception.microsoft.com/mcp\" }`), sign in, reload MCP servers and retry. Needs Perception enabled in the tenant and Security Reader or higher. (Docs: https://learn.microsoft.com/en-us/security/agentic-security/agentic-security-mcp)"* After the guidance you may *offer* a saved result for the same alert, labeled "saved result, not re-validated — Perception MCP unavailable" `[asserted]`. **In this offline mode you must NOT write or edit any report, post a Mission Control finding, update `temp/perception_sessions.json` or the session cache, run new analysis queries, or suggest follow-ups that need fresh Perception data.** A saved report is never a reason to skip the guidance. Full rules: REFERENCE §1.1. Then state the active tenant.

### Phase 1 — Alert facts and alert-type check (read-only)
1. `GetAlertById` (Sentinel Triage MCP) for the alert. **The response is large (full evidence arrays, names, UPNs, hostnames): read only the header fields and never copy evidence into tracked files.** Keep: `title`, `severity`, `status`, `classification`, `determination`, `serviceSource`/`detectionSource`, `createdDateTime`, `assignedTo`, `incidentId`, `alertWebUrl`, `incidentWebUrl`. Show the alert link (it carries `?tid=`) and the incident link `https://security.microsoft.com/incidents/<incidentId>?tid=<tenant_id>`. If the lookup fails, stop and say so (wrong ID type is the usual cause; Sentinel IDs are not accepted).
2. **Alert-type check (mandatory):** `triage_helper.py check "<title>"`.
   - **LISTED:** say which Learn category it matched (snapshot date shown).
   - **NOT LISTED:** Microsoft documents only a *subset* of alert types and says it grows, so this is a **warning, not a refusal**. Tell the user: *"Not on Microsoft's documented Triage Agent list (snapshot <date>), so a verdict is not guaranteed."* and, from this tenant's earlier runs, that unlisted types have behaved both ways (Entra ID Protection sign-in alerts received verdicts; a Safe Links click alert returned **Not set**, partly because the email content was gone). If the snapshot may be stale, re-read the Learn page (`microsoft_docs_fetch` the `source` URL) and `refresh`. **Ask before continuing** (reading existing sessions needs no confirmation; a *new* run does, and the unlisted warning goes into that prompt).
3. **Alert state:** Microsoft's prerequisites say the agent does not triage **resolved** alerts (automatic mode) and that alerts on Defender for Endpoint device groups the agent identity cannot see are triaged on incomplete data or fail. Note a resolved alert and mention both when relevant; manual sessions on already-resolved alerts have completed in this tenant, so do not refuse.
4. **Repo investigation lookup (mandatory, cheap — before Phase 2):** for the alert's `incidentId`, `glob` `reports/incidents/Incident_<id>_Investigation_*.md`, grep `.mission-control/findings.json` for `incident-investigation` findings mentioning it, and check this conversation. Remember the result for Phases 6–7. Do not skip this because a saved Perception report exists.

### Phase 2 — Lookup before running
Refresh the session cache (REFERENCE §3.7) if it was not refreshed in this conversation, then:
`python .github/skills/perception-shared/session_cache.py search "<alert id>" --playbook triage-security-copilot`
(Triage sessions carry the alert id in their title/inputs; tags are `playbookId=triage-security-copilot`, `input:triage-alert=<id>`, `method:Manual|Automatic`.) If the cache cannot answer, fall back to REFERENCE §3 (`list_sessions` paging, match the tag exactly); state the scan depth either way.
For each candidate (several runs per alert are normal; automatic runs by an administrator's rule appear as `method:Automatic`):
1. `get_session_summary` + `list_outputs`; require a real `triage_report.md` (REFERENCE §5).
2. `read_output` it (small) and run `triage_helper.py parse-report <file>`: classification, reasoning.
3. **A session can be `succeeded` with classification `Not set`:** that is *inconclusive*, not a verdict and not "clean". Show its reason (e.g. "email content not found") and discard it as a source of truth.
4. Table the usable and inconclusive runs: session link, method, date, who ran it, classification. **If runs disagree, say so** and show both reasonings; never pick one silently.
Offer **reuse** of the newest conclusive run (free, instant) or a fresh run.

### Phase 3 — Start (only if no conclusive session, or the user wants a fresh run)
Confirm first (REFERENCE §1.3): playbook *Triage alert*, the alert (title, id, severity), the **alert-type result** (add the NOT LISTED warning here), runtime (≈ 3–5 minutes; observed ≈ 4), **estimated Perception cost ≈ $0.33–$0.44 per alert** (portal estimate snapshot 2026-11-19, not a quote; billed separately from Copilot credits) and that it runs under the agent's identity. Start only after an explicit yes, then REFERENCE §2 (`list_playbooks` → GUID `playbookId`):
```
perception-mcp-start_session
  playbookId: <GUID of triage-security-copilot from list_playbooks>
  inputs: [{"key":"triage-alert","type":"defenderTriageAlertId","values":["<alert id>"],"displayName":"<alert title> - <alert id>"}]
```
(Key and type come from `list_playbooks`; the input accepts an alert ID or URL.) Record `{kind:"alert", key:"<id>", sessionId, playbook, startedAt}` in `temp/perception_sessions.json`. Never retry a failed start without checking `list_sessions` first (REFERENCE §2).

### Phase 4 — Poll
REFERENCE §4. One short progress line per check; the Triage Agent run is the one that matters (`list_agent_runs`). Do not block the conversation unless the user asked to wait.

### Phase 5 — Validate
`get_session_summary` + `list_outputs`; require `triage_report.md`; `parse-report`. Classify **conclusive** (True Positive / False Positive), **inconclusive** (`Not set`, missing report, cannot-evaluate reasoning) or **failed** (read the agent run's `failureInfo`). For inconclusive/failed results show the reason and the likely fixes from the docs (alert type not supported; email content deleted/quarantined; agent identity lacks access to the device group or workload; alert already resolved), pointing to the Defender portal (*Perception → Agents → Triage*) for an admin. **Do not retry automatically**, and never describe an inconclusive run as benign.

### Phase 6 — Present
Show, with the repo's emoji conventions:
- **Verdict:** Perception classification (🔴 True Positive / 🟢 False Positive / ❓ inconclusive), its reasoning (condensed, key sentence verbatim), session link, method, run date, agent runtime. Tag `[perception: session <id8>]` (= `[asserted]`).
- **Defender's current state for this alert** (from `GetAlertById`): `status`, `classification`, `determination`, `assignedTo`; then `triage_helper.py compare --perception "<verdict>" --defender <classification>` and show the result: **AGREE / PARTIAL / DISAGREE / NO-BASELINE / INCONCLUSIVE**. **DISAGREE is highlighted for human review, never auto-resolved** (in this tenant manual sessions have disagreed with an alert's existing classification in both directions).
- **No write-back claim.** Manual sessions did not change the alert's classification or status in this tenant. After a **fresh** run call `GetAlertById` again and report whether anything changed (expected: nothing). This skill never changes an alert, incident or classification.
- **Alert-type line:** LISTED / NOT LISTED (+ snapshot date).
- **Repo investigation line (mandatory):** *"Repo investigation found: `<file or finding>` (<date>), verdict <X>"* or *"No repo investigation found (checked conversation, `reports/incidents/`, Mission Control findings)"*.
- **Limits:** what Perception says it could not evaluate (never drop this).
- **Next steps** re-rendered as portal paths (REFERENCE §8). **Never advise closing or reclassifying on `[asserted]` or partly verified grounds**: say "consider closing after confirming <what is still unchecked>", and keep the decision with the analyst. A true-positive verdict on a still-open incident → recommend a human look and offer `incident-investigation` / `user-investigation`; do not contain or remediate.
Save the report to `reports/perception/triage-alert/alert_<id8>_<yyyymmdd>.md` (gitignored; create the folder if missing). **Links:** the alert, the incident and every Perception session are clickable Markdown links, never bare IDs or URLs (REFERENCE §9). **Session link (mandatory):** the report opens with the `**Perception session:** [🔗 Open session …]` line (one per session cited; or `**Perception session:** none (<reason>)` when none exists) and passes `session_cache.py check-links <report.md> --fix` **and** `triage_helper.py lint-report <report.md>` (both exit 0; the lint fails on IPs, UPNs/emails and user-agent strings, so rewrite generically and re-run) before you present it. Update the index entry (`status`, `reportPath`). **Keep evidence out of the report:** do not paste or restate names, UPNs, hostnames, device names, IP addresses, file names or command lines from `GetAlertById` evidence, including in a tenant-context section. Refer to them generically ("the alert's device", "the involved account") and, for tenant-memory checks, cite the **memory rule or section name** you matched (or that none matched), not the values you searched for. The alert and incident links already let the reader pull the evidence in the portal. The report is local and gitignored, but it is shared, screenshotted and demoed, so keep it minimal.

### Phase 7 — Verify and compare (automatic; REFERENCE §6)
A triage verdict is a claim about an alert; this repo can check it, and read-only checks need no approval.
- If a repo investigation exists (Phase 1), compare **verdict, key entities and recommendations**, deltas only (as `perception-investigate-attack` Phase 7).
- For a **false-positive** verdict on a high-severity or critical-asset alert, any **DISAGREE**, or an **inconclusive** run, **run a quick bounded check on the alert's own entities** (the alert's evidence tables in Advanced Hunting, ≤ 30 d: e.g. `UrlClickEvents`/`EmailEvents` for a mail alert, `EntraIdSignInEvents`/`AADUserRiskEvents` for a sign-in alert, `DeviceProcessEvents`/`DeviceNetworkEvents` for an endpoint alert), do it before Phase 6 is written so the report carries it, and report `[verified: <table>, <window>]` next to Perception's `[asserted]` reasoning. State what was and was not isolated (for example the exact event behind the alert). **Marker honesty:** use 🟢 on the independent-check row only when the check covered the alert's own event; if the exact event was not located or the check was partial, use 🟠 or ⚠️ and say what is missing, even when everything it did find looks benign. **Reused checks:** a `[verified: …]` result copied from an earlier saved report or finding was not re-confirmed this session, so tag it `[asserted: earlier report <date>]`, not `[verified]`, and say so on the row; re-run the quick check (or state that none was needed for a low-severity AGREE) before using it to support a benign verdict.
- **Offer, don't launch,** the full skills (`user-investigation`, `computer-investigation`, `ioc-investigation`, `incident-investigation`): they run dozens of queries and write their own reports.
- Perception-only claims must be independently queried (KQL pre-flight) before being cited as fact; disagreements go to the human.

### Phase 8 — Record
If launched from Mission Control, post a finding tagged `[perception: session <id8>]`: alert, Perception verdict, Defender's classification, agreement result, reused vs fresh, alert-type result, caveats. **Severity is grounded:** Perception-only content is `[asserted]`, so **`info`** for a false-positive or inconclusive result; **`low`** at most for a true-positive verdict or a DISAGREE, to flag it for a human (check this before posting: the finding's severity and every metric's severity). `medium`/`high` only for what the repo's own checks verified (`high` needs two or more concrete findings, per the repo's evidence rule). Entities: the alert and incident only, not people or hosts from the evidence. **Every metric's severity is `info`/`clean`/null** unless a check in this run found tenant activity (facts such as *alert type NOT LISTED* or *runs reused* are `info`, not `low`).

---

## Guardrails
- Never auto-start a session; always confirm, with the cost shown and the alert-type warning included. Allow-list only: refuse `red-web-pentest`, `find-fix-web-app-security-risks` and any other non-listed playbook outright (REFERENCE §1.4).
- The supported-alert list is a documented subset that grows: **warn, don't refuse**; never claim an unlisted alert "cannot" be triaged.
- A finished session is not necessarily a useful one: `succeeded` + `Not set` is inconclusive (REFERENCE §5).
- Perception's verdict never overrides Defender's classification or a human's: show both, flag disagreement.
- Reports never reproduce alert evidence (names, hosts, IPs, files, command lines); `lint-report` enforces the mechanical part, and the same applies to your chat summary.
- Never change alert, incident or classification state; never emit state-changing commands (REFERENCE §8). Never write Perception output or alert evidence to tracked files.
- Tenant-context check (if applicable) still applies before any risk assessment you add on top of Perception's output; mark memory-sourced facts `[asserted]`.
