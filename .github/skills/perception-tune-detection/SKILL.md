---
name: perception-tune-detection
description: 'Human-in-the-loop tuning of custom-detection proposals from a Microsoft Perception session (Detection Authoring Agent). Decodes the report''s "Open in Wizard" link to get the exact KQL and rule metadata, replays it against tenant history with Advanced Hunting (up to 30 days) or Sentinel Data Lake (longer lookbacks), slices the hits to find the noise, proposes and (with the analyst''s approval) applies tuning, proves the tuned rule (longer lookback, indicator sweep, synthetic positive/negative check), and re-encodes a verified Detection Wizard link with the tuned query. Never deploys; the analyst opens the link and saves the rule. Works on any finished Perception detection report, typically those marked requires-tuning. Trigger keywords: "tune perception detection", "tune the proposed detection", "perception detection noisy", "requires tuning", "re-encode wizard link", "tune custom detection from perception".'
threat_pulse_domains: [perception]
drill_down_prompt: 'Tune detections from an existing Perception session for {entity}'
---

# Perception — Tune a Proposed Detection

## Purpose

Perception's Detection Authoring Agent measures each proposed rule against tenant history and flags those that are **noisy** or whose volume could not be measured as *requires tuning*. This skill closes the loop: **a human and Copilot review the KQL, use Triage (Advanced Hunting) and Data Lake tools with a longer lookback to tune it, then produce a revised wizard link in the same encoded format Perception uses.**

**Read first:** [`.github/skills/perception-shared/REFERENCE.md`](../perception-shared/REFERENCE.md). KQL work follows the repo's **KQL pre-flight checklist** (Steps 0–6) — in particular Step 0 (lookback → tool), Step 1 (check `queries/**` and the manifest first), Step 5 (sanity-check zero results) and Step 6 (execute before sharing).

**Deterministic helper (use it; don't hand-roll the encoding):** [`wizard_link.py`](../detection-authoring/wizard_link.py) (lives in the core `detection-authoring` skill, which also uses it to hand analysts a prefilled wizard link for repo-authored rules).
```
python .github/skills/detection-authoring/wizard_link.py list-report <detection_report.md|saved read_output file> [--out-dir DIR]
python .github/skills/detection-authoring/wizard_link.py decode <url|token|file> [--out rule.json] [--query-out rule.kql]
python .github/skills/detection-authoring/wizard_link.py encode --base <original url|token|file> --query-file tuned.kql \
    [--name "..."] [--description "..."] --tid <tenant_id> [--out link.txt]
python .github/skills/detection-authoring/wizard_link.py insert <report.md> --link-file <link.txt> [--placeholder "{{WIZARD_LINK}}"] [--text "..."]
python .github/skills/detection-authoring/wizard_link.py verify <report.md|file> --link-file <link.txt> [--query-file tuned.kql]
python .github/skills/detection-authoring/wizard_link.py selftest
```
`encode` preserves every field Perception set; only `name`, `queryText`, `ruleDescription` may change; round-trip verified; fails loudly if the link format changes.

**🔴 Never type, retype or paste a wizard token yourself.** The links are 2–3 KB of base64; a single dropped or altered character silently breaks the link (the wizard just won't open it). The only way a token reaches a report is: `encode … --out <link.txt>` → write the report with the literal placeholder `{{WIZARD_LINK}}` → `insert` fills the exact link from the file → `verify` confirms every link in the report decodes and equals the saved file (exit code 0 required). If `verify` fails, fix by re-running `insert` on a fresh placeholder — never by editing the token.

**Entity:** a Perception session ID (preferred) **or** an article (internal ID/title or URL). For an article, resolve it to a finished session that produced a detection report (`proactive-protection` / *Protect against a threat*, or `detect-emerging-threats` / *Detect emerging threats*, which can only be started in the portal but whose sessions are readable here) via REFERENCE §3 (page with `continuationToken` to the boundary or cap; match `tags`/`inputs`, `status: succeeded`, real `detection_report.md` in `list_outputs`; state the scan depth reached). **Never start a run from this skill:** if none matches, say so (with the scan depth reached) and offer `perception-protect-against-threat`; if several match, list them (status, createdAt, initiator) and let the user choose rather than silently taking the newest; skip sessions with no detection report (failed, stub, or Detection Authoring never ran) and say why. **URL input:** if the exact URL match finds no usable session, apply the **title fallback** (REFERENCE §3.6) — fetch the page title, offer title-matched sessions as *probable same article* and **ask the user to confirm** before tuning anything.

**Nothing is deployed.** The analyst opens the link in the Defender portal, reviews, and clicks Save. (This skill's output is read-only analysis + a prefilled wizard link.)

---

## Workflow

### Phase 0 — Preconditions
**🔴 MCP GATE — do this before reading the session index, saved reports, `reports/`, or Mission Control findings.** Check that `perception-mcp-*` tools are available (use the tool search tool; they are deferred). **If they are not: your reply MUST begin with the setup guidance** — *"The Perception MCP isn't configured in this session. Add an HTTP MCP server for `https://perception.microsoft.com/mcp` (e.g. `.mcp.json`: `\"perception-mcp\": { \"type\": \"http\", \"url\": \"https://perception.microsoft.com/mcp\" }`), sign in, reload MCP servers and retry. Needs Perception enabled in the tenant and Security Reader or higher. (Docs: https://learn.microsoft.com/en-us/security/agentic-security/agentic-security-mcp — it lists `https://perception.microsoft.com/mcp`; the `sentinel.microsoft.com` URL above also responds.)"* After the guidance you may *offer* a saved result for the same input, labeled "saved result, not re-validated — Perception MCP unavailable" `[asserted]`. **In this offline mode you must NOT write or edit any report, post a Mission Control finding, update `temp/perception_sessions.json`, run new analysis queries, or suggest follow-ups that need fresh Perception data.** A saved index entry or report is never a reason to skip the guidance. Full rules: REFERENCE §1.1. Then state the tenant. Reading an existing session needs no start confirmation.

### Phase 1 — Select the detection
0. **Already tuned?** Check `reports/perception/tune-detection/` for an existing `tune_*` report or `tuned_CAND-*` files for this session. If found, say so and ask the user: show/reuse it (verify its link with `wizard_link.py verify`), tune a different candidate, or redo. **Do not silently re-run replays or widen scope** (extra candidates, extra lookbacks) beyond the single candidate the user asked for — offer them as options and wait.
1. Resolve the session; `list_outputs` → `read_output` `detection_report.md` (it is large, so it is returned as a saved temp file — use that file directly; never paste it into chat).
2. Run `wizard_link.py list-report <file> --out-dir reports/perception/tune-detection/<slug>_<id8>/` (save the source `detection_report.md` there too) — it lists every candidate with **readiness** (taken from the report's own *Ready to deploy* / *Requires tuning* grouping), severity, MITRE, frequency, **measured 14-day hits** and whether the volume was **estimated rather than measured**, and writes each candidate's `.token.txt`, `.kql` and `.rule.json`. Present that as the candidate table (add the tenant's alert-median "noisy" threshold from the report text if useful). Default target = **requires tuning**; let the user pick any, including ready rules whose volume was only *estimated* (worth a replay).
3. Show **the KQL first** for the chosen candidate and its metadata (frequency, lookback, severity, entities). Explain what the rule is trying to catch and which `let` parameters are the tuning knobs; Perception's "Detection Parameter Tuning" and "Known benign sources" tables in the report are the starting hypothesis. Never print the wizard token itself — it is very long. **NRT intent:** if the candidate is meant to be NRT, its link omits the frequency keys and the query uses `let`, so the wizard opens it as **Every hour** (verified); to get NRT, inline the `let` values and add `frequencyInMinutes: 0` / `intervalHours: 0` (see `detection-authoring` wizard notes), and state which schedule the tuned link will show.

### Phase 2 — Pre-flight
- Step 1: `grep`/manifest check of `queries/**` for the relevant table/keywords (e.g. `queries/email/…`); reuse verified patterns.
- Tenant context: if the tenant has a context-memory file (the one named by `memory_file` in `config.json`), skim its headers and search it for the specific senders/domains/subjects/IPs in play (simulators and test harnesses are common noise sources). Facts from memory are `[asserted]` until re-verified against telemetry this session — never skip a collection step because memory says "known noise".

### Phase 3 — Replay and slice
1. Convert the rule for replay: replace `ingestion_time() > ago(1h)` with a `Timestamp` window (`> ago(14d)` first); keep the logic identical. Remove the final wide `project` and replace with a **breakdown** union: total, and counts/distinct recipients by sender domain, direction, delivery action, subject, URL domain (top 12 each). Bounded output only — the Advanced Hunting quota is shared with Perception's own validation.
2. Run via `RunAdvancedHuntingQuery` (parameter name **`kqlQuery`**) for ≤ 30 d. If the user wants longer, or AH is throttled, use `query_lake` (`TimeGenerated` instead of `Timestamp`; check the table exists in the lake first — the email tables do in some tenants, not all; if not, say so and stay on AH). **Keep lake queries narrow:** a heavy multi-table 90-day query (several large tables joined/unioned) can drop the MCP transport. Query a single table first (a candidate-set *superset* is fine), then join only what's needed; if a call drops, say what you narrowed to and what stayed unverified.
3. Reconcile the replay total with Perception's reported hit count (they should be close; explain material differences — window, ingestion vs event time).
4. Sanity-check zero or surprising results (Step 5) before drawing conclusions.
5. Present the breakdown as a table and name the **dominant noise classes** with their share of hits. Identify *why* each matches (which lure term / URL rule) — usually generic words (`service`, `security`, `notification`, `alert`) or intra-org/system mail.

### Phase 4 — Tune with the human (approval required)
Propose specific changes, each with rationale and tradeoff, then **wait for approval** before applying. Typical levers, in order of preference:
1. Narrow generic lure terms to attack-specific ones (keep terms tied to the attack semantics).
2. Constrain direction/origin (e.g. inbound only) — state the blind spot it creates (compromised internal senders) and offer a companion rule.
3. Add tenant allowlists (`KnownGoodSenderDomains`, `KnownGoodUrlDomains`) only for **verified** benign sources — each entry must be justified by evidence, never added just to hit a number.
4. Add alert-side thresholds/aggregation only if a signal is genuinely low-fidelity per event.
Never tune solely to reach zero hits; a detection that cannot fire is not tuned, it is disabled.

### Phase 5 — Prove it
Run all of these against the tuned query and report each result:
- **Longer lookback replay** (30 d via AH; 60–90 d via Data Lake if available). Zero hits is acceptable only with evidence the rule *can* fire (below) — and report the hit count with the *original* rule over the same window for contrast.
- **Indicator sweep:** the article's IOCs (sender/URL domains, subject patterns, IPs) in `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents` (and other tables the TI report names). Report found / not found honestly; "campaign not in this tenant" is a valid outcome.
- **Synthetic positive/negative check:** a `datatable` of representative rows (campaign-style rows built from the article's described traits, noise rows from the replay breakdown) run through both the original and tuned logic. Label rows as synthetic. Confirm: campaign-style rows fire, noise rows don't.
- **Blind spots:** list what the tuned rule misses (and what the original also missed) — brand-less lures, internal senders, attachments/QR codes, etc.

### Phase 6 — Re-encode
1. Write the tuned KQL (with a short `//` comment header listing the changes, source session/candidate, replay results and blind spots — the helper strips comment headers) to `reports/perception/tune-detection/tuned_<candidate>_<slug>_<yyyymmdd>.kql`. **Restore the original rule's time predicate** (`ingestion_time() > ago(1h)` or whatever the rule used) — the replay window must not leak into the deployed query.
2. Run `wizard_link.py encode --base reports/perception/tune-detection/<slug>_<id8>/<CAND>.token.txt --query-file <tuned.kql> --name "<original name> - tuned (<MITRE>)" --description "<original description> Tuned: <one line>" --tid <tenant_id> --out reports/perception/tune-detection/tuned_<candidate>_<slug>_<yyyymmdd>.txt`.
3. Confirm the helper's output (`fields changed: ['name','queryText',…]`, round-trip passed).
4. **Put the link in the report mechanically:** write the tuning report with the bare placeholder `{{WIZARD_LINK}}` where the link belongs, run `wizard_link.py insert <report.md> --link-file <link.txt> --text "Open tuned <candidate> in the Detection Wizard"`, then `wizard_link.py verify <report.md> --link-file <link.txt> --query-file <tuned.kql>` and require exit code 0 (it prints the token length and a short hash; any dropped or altered character fails). Do the same for any other file that carries the link.
5. **In chat, point to the verified report/file** (path + the verify fingerprint) rather than re-emitting the token; Mission Control renders the report link as clickable. Only print the raw link in chat if the user asks — then print it with `decode`/`cat` of the saved file and copy it exactly from that tool output, never from memory.
6. Remind: the wizard needs an authenticated portal session; the format is observed, not a documented contract. Test once in the browser; if it misbehaves, remove `?tid=<…>` from the URL.

### Phase 7 — Hand-off and record
- If the user wants the tuned query in this repo's library: follow the `queries/` conventions (metadata header, cd-metadata block, `build_manifest.py`, `generate_tocs.py`) — **only on request**; or route to `detection-authoring`.
- If launched from Mission Control, post a finding: candidate, before/after hit counts, noise classes removed, blind spots, link path; tag `[perception: session <id8>]` for the proposal and `[verified: <table>]` for replay results. Link the source session and present the tuned wizard link as a clickable Markdown link (REFERENCE §9). **The tuning report must open with the `**Perception session:** [🔗 Open session …]` line and pass `session_cache.py check-links <report.md> --fix` (exit 0) before you present it.**

---

## Guardrails
- **Never deploy, save or enable a rule.** Never emit state-changing commands (Graph `POST` to detection rules, PowerShell, `az`). The only output is a prefilled wizard link for a human.
- Every KQL shown to the user must have been executed (pre-flight Step 6). Use `kqlQuery` for Triage MCP calls.
- Never starts any Perception session; refuse `red-web-pentest` / `find-fix-web-app-security-risks` outright (REFERENCE §1.4).
- Outputs go to `reports/perception/tune-detection/` (gitignored). No tenant GUIDs, UPNs or hostnames in tracked files.
- Report tuning honestly: what the tuned rule gives up is as important as the noise it removes.
