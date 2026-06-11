---
name: threat-intel-campaign
description: 'Turn a published threat-intelligence article into a tested threat-hunting campaign. Reads a platform-agnostic RSS/Atom feed (feed_url is a parameter — nothing vendor-specific is hardcoded), triages articles from a recent window, applies a huntability relevance gate to decide whether an article warrants a campaign, then writes/tests/tunes KQL hunts and publishes them as a campaign file under queries/threat-intelligence/YYYY-MM/. Also supports a single-article mode (pass an article URL directly). Side-effect-free: it writes campaign files and regenerates the manifest/TOCs but performs NO git commits or PRs — branch/PR orchestration belongs to the calling automation. Trigger keywords: "threat intel campaign", "ingest threat intelligence", "TI feed", "write hunts from this article", "threat intelligence blog", "build a hunting campaign".'
---

# Threat Intelligence Campaign Authoring — Instructions

## Purpose

This skill converts published threat-intelligence reporting into **tested, tuned, publish-ready threat-hunting campaigns** that land in `queries/threat-intelligence/YYYY-MM/`. It exists to be driven either:

- **Interactively** — a human gives one article URL ("read this article and write/test/tune hunts"), or
- **Unattended** — a scheduled automation passes a feed URL and the skill triages everything published in a recent window.

It does the *authoring* (parse → triage → relevance gate → write → test → tune → publish files → regenerate manifest/TOCs). It deliberately does **NOT** create branches, commits, or pull requests. That orchestration — and the per-article PR isolation — belongs to the calling workflow. This keeps the skill reusable and free of git side effects when a human runs it.

**What this skill produces:**

| Output | Description |
|--------|-------------|
| Campaign file(s) | `queries/threat-intelligence/YYYY-MM/<slug>.md` in the standard campaign format |
| Regenerated artifacts | `.github/manifests/discovery-manifest.yaml` + per-file Quick Reference TOCs |
| **Structured result** | A JSON array (one entry per article) the calling automation consumes to drive per-article PRs |
| Human summary | A readable per-article decision log |
| **In-chat hunt findings summary** | A per-article report of what the test runs actually surfaced — real hits, false positives to tune, and follow-up actions. Emitted to chat/run output only; **never written to a tracked file**. This is where concrete findings live, keeping the committed campaign file PII-free. |

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)**
2. **[Prerequisites](#prerequisites)**
3. **[Inputs / Parameters](#inputs--parameters)**
4. **[Invocation Modes](#invocation-modes)**
5. **[Execution Workflow](#execution-workflow)** — Phase 0–6
6. **[The Relevance Gate (Huntability Rubric)](#the-relevance-gate--huntability-rubric)**
7. **[Writing / Testing / Tuning Queries](#writing--testing--tuning-queries)**
8. **[Campaign File Format](#campaign-file-format)**
9. **[Structured Output Contract](#structured-output-contract)**
10. **[In-Chat Hunt Findings Summary](#in-chat-hunt-findings-summary)**
11. **[Known Pitfalls](#known-pitfalls)**
12. **[Quality Checklist](#quality-checklist)**

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **No git side effects.** This skill NEVER runs `git commit`, `git push`, `gh pr create`, or any branch operation. It writes files and regenerates the manifest/TOCs only. Publishing (branch + commit + PR per article) is the calling automation's job. If a human is running this interactively, leave the files in the working tree for them to review.

2. **`feed_url` is a parameter — nothing vendor-specific is hardcoded.** The skill handles any RSS 2.0 or Atom feed. The Microsoft Threat Intelligence feed is just one value a caller may pass; do not assume it.

3. **Advanced Hunting (≤30d) is the primary test/tune engine.** Write and validate every query against `RunAdvancedHuntingQuery` within a 30-day window. Fall back to the Sentinel Data Lake (`query_lake`, >30d) **only** when you need additional supporting evidence that AH's 30-day cap cannot provide (e.g., confirming a rare IOC's longer-term absence/presence). Follow the Tool Selection Rule and timestamp-adaptation guidance in `copilot-instructions.md`.

4. **⛔ Evidence-based "tested" claims only.** A query may be described as *tested* in the campaign file **only if it was actually executed**. If a query could not be run (table absent, AH safety filter, telemetry gap), say so explicitly and mark `cd_ready: false` with honest `adaptation_notes`. Never imply validation that did not happen. Follow the Evidence-Based Analysis rule in `copilot-instructions.md`.

5. **⛔ Committed output is PII-free — but published IOCs are NOT PII.** Test/tune runs against the live tenant, but campaign files are version-controlled. NEVER paste real *tenant* entities (your UPNs, hostnames, IPs, workspace/tenant GUIDs, app names) into a campaign file. **The article's published IOCs (hashes, domains, URLs, certs, filenames) are the opposite — they are public, shareable, and MUST be included verbatim** in the IOC Reference table and the IOC-sweep queries (this is how the committed companion files do it). Do not placeholder or omit a published IOC. Concrete *tenant findings* from test runs belong in the [In-Chat Hunt Findings Summary](#in-chat-hunt-findings-summary), not the file. Perform a PII sanity-check before finalizing each file.

6. **⛔ Every IOC must trace to the article. Never invent one.** Copy IOCs from the article's "Indicators of compromise" table (and any inline-cited indicators) exactly. Before finalizing, re-open the article's IOC section and confirm each hash/domain/URL/filename in your file appears there character-for-character. Hallucinated or mis-transcribed IOCs are a critical evidence-integrity failure — they produce false detections and erode trust. If an indicator only appears in narrative prose (not the IOC table), label it as such.

7. **Reference, don't reinvent.** Use the **kql-query-authoring** skill's discipline for query construction (schema validation via kql-search MCP, table pitfalls, `TimeGenerated` vs `Timestamp`), and the **detection-authoring** skill's **CD Metadata Contract** for the `<!-- cd-metadata -->` block on every query. Read those SKILL.md files when authoring.

8. **Workspace selection.** Follow the SENTINEL WORKSPACE SELECTION rule in `copilot-instructions.md`. In unattended runs the caller will specify the workspace; if exactly one exists, auto-select and state it.

9. **Read `config.json`** for workspace ID, tenant, and Azure MCP parameters before querying.

9. **Quiet runs are a success, not a failure.** If nothing in the window qualifies, that is a valid, expected outcome. Emit an empty/`"skipped"`-only result set and stop — do not lower the bar to manufacture a campaign.

---

## Prerequisites

| Dependency | Used for |
|------------|----------|
| **kql-search MCP** (`GITHUB_TOKEN` set) | Schema validation, table discovery, community query examples |
| **Sentinel Triage MCP** (`RunAdvancedHuntingQuery`) | Primary query testing/tuning (≤30d) |
| **Sentinel Data Lake MCP** (`query_lake`) | Supporting evidence only (>30d) |
| **Microsoft Learn MCP** | Grounding TTP/technique/error-code explanations |
| **Python 3** (stdlib `xml.etree`, `urllib`) | RSS/Atom parsing — no external dependency required |
| `web_fetch` / `web_search` tools | Fetching article bodies and the feed |
| `.github/manifests/build_manifest.py`, `scripts/generate_tocs.py` | Post-processing |

> Feed parsing uses Python stdlib (`xml.etree.ElementTree`) so it works unattended without `pip install`. `feedparser` may be used if already installed, but never assume it.

---

## Inputs / Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `feed_url` | *(required in feed mode)* | Any RSS 2.0 / Atom feed URL |
| `article_url` | *(none)* | A single article to process directly (single-article mode) |
| `lookback_hours` | `24` | How far back to consider feed entries (by published date) |
| `max_campaigns` | `3` | Cap on campaigns produced per run (bounds tenant query load + review burden) |
| `workspace_id` | from `config.json` | Sentinel workspace for testing |
| `min_queries` / `max_queries` | `4` / `9` | Soft bounds on queries per campaign |

---

## Invocation Modes

**A. Single-article mode** — caller passes `article_url` (the classic "read this article and write hunts" prompt).
→ Skip Phase 1 (feed) and the time filter. Still run Phase 2 (dedup) and Phase 3 (relevance gate) unless the human explicitly says "build it regardless". Then Phases 4–6 for that one article.

**B. Feed mode** — caller passes `feed_url` (+ optional `lookback_hours`).
→ Full Phase 0–6 across all qualifying entries in the window, capped at `max_campaigns`.

---

## Execution Workflow

### Phase 0 — Setup
1. Read `config.json` (workspace ID, tenant, subscription, Azure MCP params).
2. Resolve workspace per the selection rule. State which workspace is in use.
3. Confirm kql-search + Triage MCP are available (needed for testing).

### Phase 1 — Fetch & parse the feed *(feed mode only)*
Fetch `feed_url` and parse entries with Python stdlib so it works for **both** RSS and Atom:

```python
import sys, urllib.request, datetime as dt
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

feed_url = sys.argv[1]
lookback_hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=lookback_hours)

raw = urllib.request.urlopen(urllib.request.Request(feed_url, headers={"User-Agent": "ti-campaign/1.0"}), timeout=30).read()
root = ET.fromstring(raw)
ATOM = "{http://www.w3.org/2005/Atom}"

def text(el, *tags):
    for t in tags:
        for tag in (t, ATOM + t):
            f = el.find(tag)
            if f is not None and f.text:
                return f.text.strip()
    return None

def parse_date(s):
    if not s: return None
    try: return parsedate_to_datetime(s)              # RSS pubDate
    except Exception:
        try: return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))  # Atom ISO
        except Exception: return None

entries = list(root.iter("item")) or list(root.iter(ATOM + "entry"))  # RSS first, else Atom
for e in entries:
    title = text(e, "title")
    link = text(e, "link")
    if not link:
        a = e.find(ATOM + "link")
        link = a.get("href") if a is not None else None
    pub = parse_date(text(e, "pubDate", "published", "updated"))
    if pub and pub >= cutoff:
        print(f"{pub.isoformat()}\t{title}\t{link}")
```

Run it with the `powershell` tool (`python script.py <feed_url> <lookback_hours>`). Collect `(published, title, link)` for entries inside the window. If the feed only exposes summaries, you'll fetch full bodies in Phase 3.

### Phase 2 — Dedup against existing campaigns
For each candidate URL, check whether it's already been turned into a campaign:
- `grep` for the article URL (and a normalized form without trailing slash / query string) across `queries/threat-intelligence/**`.
- Also grep the proposed slug. If a match exists → mark `decision: "skipped"`, `reason: "already published"`, and drop it from the work list.

### Phase 3 — Relevance gate
For each remaining candidate, fetch the full article body (`web_fetch`) and apply the [Huntability Rubric](#the-relevance-gate--huntability-rubric). Produce a decision (`campaign` / `skipped`) with a one-line reason. Rank `campaign` candidates by huntability confidence and keep the top `max_campaigns`.

### Phase 4 — Write / test / tune *(per qualifying article)*
See [Writing / Testing / Tuning Queries](#writing--testing--tuning-queries). Output: a set of validated queries, each with an honest `cd-metadata` block and tuning notes.

### Phase 5 — Publish the campaign file
Write `queries/threat-intelligence/YYYY-MM/<slug>.md` in the exact [Campaign File Format](#campaign-file-format). `YYYY-MM` = the article's publication month. `<slug>` = short, kebab/underscore, descriptive (e.g., `soho_router_dns_hijacking`). **Do NOT hand-write the Quick Reference TOC** — `generate_tocs.py` creates it.

### Phase 6 — Regenerate artifacts + emit results
1. `python .github/manifests/build_manifest.py` (regenerate + validate; fix any error-level warnings on your new file).
2. `python scripts/generate_tocs.py` (insert the Quick Reference TOC).
3. Emit the [Structured Output Contract](#structured-output-contract) JSON + a human summary.
4. Emit the [In-Chat Hunt Findings Summary](#in-chat-hunt-findings-summary) — the per-article report of what the test runs actually found (hits, false positives to tune, follow-up actions). Chat/run output only; never write it to a tracked file.
5. **Stop. No git.**

---

## The Relevance Gate — Huntability Rubric

This is the judgment step: *does this article warrant a hunting campaign?* Decide with explicit gates, not vibes. Cite the evidence from the article for each gate.

### Hard gates (BOTH must PASS to build)

| Gate | PASS criteria | FAIL examples |
|------|---------------|---------------|
| **G1 — Huntable behavior** | Article describes specific, observable attacker behaviors mappable to ≥1 ATT&CK technique (process exec, persistence mechanism, C2 pattern, auth abuse, mailbox manipulation, registry/file artifacts, etc.) | "Threat actor targeted sector X" with no technique detail; pure attribution/geopolitics |
| **G2 — Telemetry coverage** | ≥1 behavior or IOC maps to a table we ingest (`Device*`, `Email*`, `Identity*`, `Signin*`/`EntraId*`, `Cloud*`, `Audit*`, `OfficeActivity`, network/DNS) | Behaviors only observable in telemetry we don't collect (e.g., physical, OT-only with no connector, third-party logs not onboarded) |

### Confidence signals (raise/lower priority among passing candidates)

| Signal | Effect |
|--------|--------|
| Concrete IOCs (hashes, domains, IPs, filenames, command lines, registry keys, user-agents) | ↑↑ strong — enables direct-match hunts |
| Multiple distinct mappable TTPs (richer attack chain) | ↑ |
| Named ATT&CK technique IDs in the article | ↑ |
| Novel TTP not already covered by an existing campaign/query | ↑ |
| Overlaps heavily with an existing campaign | ↓ (consider extending the existing file instead of a new one) |

### Auto-skip categories (do not build)
- Product/feature announcements, GA/preview notices, roadmap posts
- Analyst-recognition / "named a Leader" / awards
- Strategy, opinion, policy, or business-update posts
- Event/webinar recaps and partner marketing
- Pure data-breach news with no attacker TTPs/IOCs

### Decision rule
> **BUILD** if **G1 PASS** and **G2 PASS** and (concrete IOCs present **OR** ≥2 distinct mappable TTPs).
> Otherwise **SKIP** with a specific reason (which gate failed / which auto-skip category).

Record the rubric outcome in the structured result `reason` field (e.g., `"BUILD: 4 IOCs + 6 mappable TTPs (endpoint, identity)"` or `"SKIP: product announcement, G1 fail"`).

---

## Writing / Testing / Tuning Queries

For each qualifying article:

1. **Extract** the TTPs and IOCs. Map each TTP to ATT&CK technique IDs (use Microsoft Learn MCP to confirm technique semantics). Build the IOC table (hashes, domains, IPs, filenames, etc.).

2. **Pick detection surfaces.** Map TTPs → tables. Prefer XDR-native tables for AH testing. Check the discovery manifest + `grep queries/**` first — if an existing query file already covers a TTP, reuse/adapt its pattern and cite it as a companion rather than duplicating.

3. **Author each query** following the **kql-query-authoring** discipline:
   - Validate the table/columns via kql-search MCP (`get_table_schema`) before writing.
   - Respect the table pitfalls in `copilot-instructions.md` (e.g., `TimeGenerated` vs `Timestamp`, dynamic-field `parse_json`, `IpAddress` casing).
   - Datetime filter first; `project` a useful, PII-light column set; `order by`/`summarize` to bound output.

4. **Test in Advanced Hunting (≤30d).** Run every query via `RunAdvancedHuntingQuery`. Apply the Step-5 zero-result sanity check from `copilot-instructions.md` — a 0-row result must be *verified correct* (e.g., a direct-IOC sweep returning 0 in a clean environment is the desired outcome; a 0 from a broken filter is not). **As you test, record the findings** for each query — row count, whether hits look like true/false positives, and any notable entities — so you can build the [In-Chat Hunt Findings Summary](#in-chat-hunt-findings-summary) in Phase 6. These raw findings stay in chat; they do NOT go into the campaign file.

5. **Tune.** If a query is noisy, add targeted exclusions (trusted publishers, known service accounts, expected automation) and document them in **Tuning Notes** — generically, never with live tenant identifiers. Re-run after tuning.

6. **Supporting evidence via Data Lake (>30d) — only if needed.** If 30 days is insufficient to characterize prevalence/absence of a rare IOC, run a scoped `query_lake` (adapt `Timestamp`→`TimeGenerated` for Sentinel/LA tables). Use this for evidence, not as the primary engine.

7. **CD metadata.** Attach a `<!-- cd-metadata -->` block to every query per the **detection-authoring** CD Metadata Contract. Set `cd_ready: true` only for high-fidelity, low-noise queries that actually validated cleanly; otherwise `cd_ready: false` with `adaptation_notes` explaining what's needed.

8. **IOC freshness note.** IOC-match queries (hashes/domains) rot. Note that operators rotate IOCs and recommend periodic refresh from current MS TI / VirusTotal / a TI indicator table.

---

## Campaign File Format

Match the existing files in `queries/threat-intelligence/YYYY-MM/` exactly. Structure:

```markdown
# <Threat / Actor / Campaign> — Threat Hunts

**Created:** YYYY-MM-DD  
**Platform:** Microsoft Defender XDR | Microsoft Sentinel | Both  
**Tables:** <exact KQL table names, comma-separated>  
**Keywords:** <attack techniques, actor names, tooling, artifacts, field names>  
**MITRE:** <technique/tactic IDs, comma-separated>  
**Domains:** <threat-pulse domain tags: incidents|identity|spn|endpoint|email|admin|cloud|exposure>  
**Timeframe:** Last N days (configurable)  
**Source:** [<Article title> (<date>)](<article_url>)

---

## Threat Overview
<2–4 sentence synopsis grounded in the article. Include actor attribution if stated.>

### TTP Summary
| Capability | TTP |
|---|---|
| ... | ... |

### ⚠️ Hunt Pitfalls
| Pitfall | Mitigation |
|---|---|
| ... | ... |

---

## IOC Reference
<Table of published IOCs (hashes/domains/IPs/filenames). Note they rot; recommend refresh.>

---

## Query 1: <Title>

**Purpose:** <what it detects, and what a clean result looks like>  
**Severity:** <Low|Medium|High>  
**MITRE:** <technique IDs>  
<!-- cd-metadata
cd_ready: true|false
cd_table: <PrimaryTable>
cd_frequency: NRT|Hourly|...
cd_severity: <Low|Medium|High>
cd_mitre: ["T...."]
cd_entities: ["device","file","account",...]
cd_adaptation_notes: "<honest notes>"
-->
` ` `kql
<tested query>
` ` `
**Expected results:** <what to expect; 0-row interpretation if a direct IOC sweep>

---

## Query 2: ...
...

---

## General Tuning Notes
1. IOC refresh ...
2. Telemetry gaps ...
3. CD-readiness summary ...

---

## References
- Microsoft Threat Intelligence — [<title>](<url>)
- MITRE ATT&CK — [<technique/actor>](<attack url>)
- Companion files: [`queries/<domain>/<file>.md`](...)
```

**Header field requirements (enforced by `build_manifest.py`):** `Tables`, `Keywords`, `MITRE`, and `Domains` are mandatory. `Domains` values must come from the valid set (`incidents, identity, spn, endpoint, email, admin, cloud, exposure`). A missing `Domains` is an error-level manifest warning.

**Do NOT** pre-write a `## Quick Reference — Query Index` section — `generate_tocs.py` inserts it. Pre-creating it breaks the strip-and-reinsert logic.

---

## Structured Output Contract

At the end of every run, emit a JSON array (one object per article considered) so the calling automation can isolate per-article PRs. Print it in a fenced ```json block:

```json
[
  {
    "article_title": "SOHO router compromise leads to DNS hijacking...",
    "article_url": "https://www.microsoft.com/en-us/security/blog/2026/04/07/...",
    "published": "2026-04-07T00:00:00Z",
    "decision": "campaign",
    "reason": "BUILD: 6 mappable TTPs + IOCs (endpoint, identity)",
    "file_path": "queries/threat-intelligence/2026-04/dns_hijacking_soho_compromise.md",
    "queries_written": 9,
    "queries_tested": 9,
    "queries_cd_ready": 4,
    "domains": ["endpoint", "identity"]
  },
  {
    "article_title": "Microsoft named a Leader in ...",
    "article_url": "https://www.microsoft.com/en-us/security/blog/2026/04/05/...",
    "published": "2026-04-05T00:00:00Z",
    "decision": "skipped",
    "reason": "SKIP: analyst-recognition post, G1 fail",
    "file_path": null
  }
]
```

`decision` ∈ `campaign | skipped`. For `skipped`, `file_path` is `null`. Follow the JSON block with a short human-readable summary (counts, what was built, what was skipped and why).

---

## In-Chat Hunt Findings Summary

After the structured JSON, emit a **per-article findings summary** that reports what the test runs actually surfaced in the tenant. This is the counterpart to the PII-free campaign file: the file is the reusable, sanitized hunt definition; this summary is the **investigation result** of running those hunts right now.

**Where it goes:** chat / run output only. **Never** write it to a tracked file (not the campaign file, not any `queries/**` or `docs/**` file). For unattended runs, the calling automation decides where to route it (e.g., PR description, notification, ticket) per its own data-handling policy — the skill just emits it.

**PII posture:** Unlike the committed campaign file, this summary **may include the concrete entities an analyst needs to act** (device names, UPNs, IPs, file hashes, sender addresses, message IDs) — it is investigation output to an operator who already has tenant access, the same as any other investigation skill's chat output. Do not redact what's needed for triage; do not persist it to the repo.

**Skip when nothing actionable:** If every query returned a verified-clean 0 (e.g., all IOC sweeps clean in a tenant where the IOCs predate the AH window), say so in one line per query rather than padding. The value is in the hits and the FPs, not in restating "0 rows" decoratively.

### Format

```markdown
## 🔎 Hunt Findings — <Article Title> (<run date>)
**Workspace:** <name>  **Lookback:** <window>  **Queries run:** <n>

| # | Query | Rows | Assessment | Action |
|---|-------|------|------------|--------|
| 1 | AI-brand display-name spoof | 0 | ✅ Clean (tuned; no spoofed-domain phish in window) | None |
| 4 | Fake-AI installer download | 3 | 🟠 2 likely FP (sanctioned vendor), 1 to review | Verify host on DEVICE-X; see below |
| 7 | Endpoint IOC sweep | 0 | ✅ Clean — IOCs predate 30d AH window | Re-run in Data Lake (90d) for retrospective |

### 🔴 True / suspected positives
- **Q4 — DEVICE-X / user@contoso.com:** downloaded `seedance_setup_x64.exe` from `hxxp://…` at <time>. Not a sanctioned vendor host. **Follow-up:** isolate/triage device, pivot Q5 (execution) + Q7 (C2).

### 🟠 False positives to tune
- **Q4 — 2 rows:** `<vendor>` installer from `downloads.<vendor>.com` — legitimate. **Tuning:** add `downloads.<vendor>.com` to the trusted-host list (reflected generically in the file's Tuning Notes, not as a literal tenant value).

### ⚠️ Follow-up actions
- [ ] Re-run Q3/Q7 IOC sweeps in Sentinel Data Lake (>30d) for retrospective coverage.
- [ ] Confirm DEVICE-X download disposition with endpoint team.
- [ ] If positives confirmed, consider promoting Q1/Q4/Q5 to custom detections (see detection-authoring skill).
```

**Closing the loop with the campaign file:** when a finding reveals a tuning need (e.g., a legitimate host triggering FPs), capture the *generic* fix in the campaign file's **Tuning Notes / `adaptation_notes`** (e.g., "exclude sanctioned vendor download hosts") — never the literal tenant value. The findings summary names the specific host; the file describes the class of exclusion.

---

## Known Pitfalls

| Pitfall | Mitigation |
|---|---|
| Feed exposes only summaries, not full TTPs | Always `web_fetch` the full article body before the relevance gate and query authoring |
| Atom vs RSS schema differences (`<entry>`/`<published>` vs `<item>`/`<pubDate>`) | The Phase-1 parser handles both; never hardcode one shape |
| Treating a marketing/recognition post as huntable | Apply the auto-skip categories; G1 must find real behavior |
| Claiming a query is "tested" when it errored or hit the AH safety filter | Only mark tested if it ran and returned a sane result; otherwise `cd_ready: false` + notes |
| Pasting live tenant entities (from test runs) into the committed file | Campaign files are PII-free; test data informs tuning notes only |
| **Placeholdering or omitting an article's published IOCs** | Published IOCs are public, not PII — transcribe them verbatim into the IOC Reference table AND the IOC-sweep queries. Never ship `<HASH1>` placeholders or "see table" stand-ins. |
| **Inventing / mis-transcribing an IOC** | Every hash/domain/URL/filename must appear character-for-character in the article's IOC table. Re-verify against the source before finalizing; a hallucinated IOC is a critical evidence-integrity failure. |
| Using Data Lake as the primary engine | AH ≤30d is primary; Data Lake >30d for supporting evidence only |
| Hand-writing the Quick Reference TOC | Let `generate_tocs.py` generate it |
| Forgetting to regenerate the manifest | Always run `build_manifest.py` after writing files; resolve error-level warnings |
| Duplicating an existing campaign/query | Grep first; extend or cite companions instead of duplicating |
| Performing git operations | Never — publishing is the automation's responsibility |
| Putting real findings/entities in the committed file, OR omitting them from chat | Two separate outputs: campaign file = PII-free reusable hunt; In-Chat Hunt Findings Summary = real hits/FPs/follow-ups (chat only). Don't merge them. |

---

## Quality Checklist

Before emitting results, confirm:

- [ ] Every candidate has an explicit `decision` + evidence-based `reason`
- [ ] Each campaign file matches the standard format (header fields complete, `Domains` valid)
- [ ] Every query has a `cd-metadata` block with an honest `cd_ready` value
- [ ] Every query was tested in Advanced Hunting (or its non-execution is documented)
- [ ] Zero-result queries were sanity-checked (desired vs broken)
- [ ] No live tenant PII anywhere in the committed file
- [ ] Every published IOC from the article is present verbatim (no placeholders/omissions) and every IOC in the file traces back to the article's IOC table (no invented/mis-transcribed indicators)
- [ ] `build_manifest.py` runs clean (no error-level warnings on the new file)
- [ ] `generate_tocs.py` has inserted the Quick Reference TOC
- [ ] Structured JSON result emitted + human summary
- [ ] In-Chat Hunt Findings Summary emitted (hits, FPs to tune, follow-ups) — chat/run output only, not a tracked file
- [ ] No git operations performed
