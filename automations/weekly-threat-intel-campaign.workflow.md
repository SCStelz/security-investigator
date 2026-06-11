# Weekly Threat Intel Campaign

Autonomous, scheduled hunt-authoring automation built on the `threat-intel-campaign` skill. Checks a threat-intelligence RSS/Atom feed, triages the articles published in the last 7 days, applies a relevance gate, and — for each article that genuinely warrants it — **writes, tests, and tunes** KQL hunting queries (in Advanced Hunting against your tenant) and **opens a PR** with a new campaign file under `queries/threat-intelligence/YYYY-MM/`. The automation does the **publishing** (branches/PRs); the skill does the **authoring**.

> This is a **portable definition** for the GitHub Copilot app's scheduled-workflow system. See [`automations/README.md`](./README.md) for import instructions. Re-create it in **Workflows → New**, paste the Prompt below, and substitute every `YOUR_*` placeholder.

## Metadata

| Field | Value |
|-------|-------|
| Interval | Weekly |
| Schedule | Friday 08:00 (local) — pick any morning that suits your review cadence |
| Session mode | Autopilot |
| Model | Claude Opus 4.x (or your preferred high-reasoning model) |
| Reasoning effort | Medium |
| Output | One git branch + PR per qualifying article. Campaign files are **PII-free and committed**. `config.json` and `reports/**` are never committed. |

## Adapt notes

Replace these placeholders with your environment values before saving (pull them from your `config.json`):

| Placeholder | Source / meaning |
|-------------|------------------|
| `YOUR_WORKSPACE_ID_HERE` | `sentinel_workspace_id` — Log Analytics / Sentinel workspace GUID (used for query testing) |
| `YOUR_TENANT_ID_HERE` | `tenant_id` — Entra tenant GUID (used in queries and `tid=` portal links) |
| `YOUR_SUBSCRIPTION_ID_HERE` | `subscription_id` |
| `YOUR_LOG_ANALYTICS_RESOURCE_GROUP` | `azure_mcp.resource_group` |
| `YOUR_LOG_ANALYTICS_WORKSPACE_NAME` | `azure_mcp.workspace_name` |
| `YOUR_RSS_FEED_URL` | Any threat-intelligence **RSS or Atom** feed URL. The skill is feed-agnostic. Example (Microsoft Threat Intelligence blog): `https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed` |

**Tuning knobs (set inside the Prompt):**

| Knob | Default | Meaning |
|------|---------|---------|
| `lookback_hours` | `168` | Triage window. `168` = last 7 days (matches a weekly schedule). Use `24` for a daily cadence. |
| `max_campaigns` | `3` | Max number of qualifying articles to build + PR in one run (keeps a busy news week from opening too many PRs at once). |

**Prerequisites:** the user-scope MCP servers authenticated (`sentinel-data-mcp`, `sentinel-triage-mcp`, `microsoft-learn`, and `kql-search` for schema/example lookups), a populated `config.json`, and write access to the repo so the run can push branches and open PRs (`gh` authenticated). Scheduled runs are non-interactive — the prompt forbids interactive prompts and runs in autopilot.

**Note on the dedup / fresh-build behaviour:** the skill dedups against existing `queries/threat-intelligence/**` files (it skips an article already published). If you want to re-test the full end-to-end path, ensure the relevant campaign file is not already on the default branch.

## Prompt

```text
Weekly Threat Intel Campaign — autonomous scheduled hunt-authoring automation. You are running UNATTENDED in autopilot. Do NOT use interactive prompts, quick-pick menus, or wait for user input. Query execution against the tenant is READ-ONLY (testing/tuning hunts) — no state-changing tenant commands (per the Remediation Output Policy). Git/PR operations on THIS repo are expected and allowed (see STEP 5).

GOAL: Check a threat-intelligence RSS feed, triage articles published in the last 7 days, and for each article that genuinely warrants it, write + test + tune threat-hunting queries and open a PR with a new campaign file. This automation does the PUBLISHING (branches/PRs); the skill does the authoring.

STEP 1 — Bootstrap config.json (if missing):
Check for config.json at the repo root. If it does not exist, create it (it is gitignored — NEVER commit it) with exactly these values:
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID_HERE",
  "tenant_id": "YOUR_TENANT_ID_HERE",
  "subscription_id": "YOUR_SUBSCRIPTION_ID_HERE",
  "azure_mcp": { "resource_group": "YOUR_LOG_ANALYTICS_RESOURCE_GROUP", "workspace_name": "YOUR_LOG_ANALYTICS_WORKSPACE_NAME", "tenant": "YOUR_TENANT_ID_HERE", "subscription": "YOUR_SUBSCRIPTION_ID_HERE" },
  "output_dir": "reports"
}
If YOUR_WORKSPACE_ID_HERE is the only Sentinel workspace, auto-select it for all query testing.

STEP 2 — Load the skill:
Read and follow .github/skills/threat-intel-campaign/SKILL.md in full. It is the source of truth for the relevance gate (huntability rubric), query authoring/testing discipline, campaign file format, and the structured output contract. Honor its rules — especially: Advanced Hunting (<=30d) is the PRIMARY test/tune engine, Data Lake (>30d) only for supporting evidence; committed campaign files must be PII-FREE (never paste live tenant entities from test runs); published IOCs from the article (hashes, domains, URLs) are NOT PII and MUST be included verbatim; and every "tested" claim must reflect an actual executed query.

STEP 3 — Triage the feed (do this ONCE):
Parameters: feed_url = "YOUR_RSS_FEED_URL", lookback_hours = 168, max_campaigns = 3.
Run the skill's Phase-1 stdlib feed parser (python, no external deps) to list entries published in the last 7 days as (published, title, link). If the feed is unreachable or returns no entries in-window, STOP after STEP 6 reporting "no recent articles" — this is a normal quiet-week outcome, not a failure.

STEP 4 — Per-article build (loop, capped at max_campaigns qualifying campaigns):
For EACH candidate article URL, in published-date order, do the following in isolation so each campaign becomes its own PR:
  a. Ensure the working tree is clean and synced to the latest default branch: `git checkout main && git pull` (use the repo's actual default branch).
  b. Invoke the skill in SINGLE-ARTICLE mode for that one article_url. The skill will: dedup against existing queries/threat-intelligence/** (skip if already published), apply the relevance gate, and — only if the verdict is BUILD — author + test + tune the queries, write the campaign file, regenerate the manifest (build_manifest.py) and TOCs (generate_tocs.py), and emit the in-chat hunt findings summary.
  c. If the skill's decision for this article is "skipped" (dedup or relevance gate fail): record the reason, discard any working-tree changes (`git checkout -- .` / `git clean -fd` as needed), and move to the next candidate. Do NOT open a PR.
  d. If the decision is "campaign": create a dedicated branch `ti-campaign/<slug>` (slug from the campaign filename), stage ONLY the new campaign file plus the regenerated `.github/manifests/discovery-manifest.yaml` and any TOC changes, commit with message `threat-intel: add <slug> hunting campaign` (include the Co-authored-by: Copilot trailer), push the branch, and open a PR with `gh pr create` titled `Threat Intel Campaign: <article title>`. The PR body must summarize: source article link, actor/threat, TTPs + MITRE IDs covered, number of queries (written/tested/cd_ready), domains, and a one-line note that queries were tested in Advanced Hunting against your Sentinel workspace. Include the in-chat hunt findings summary (real hits, false positives to tune, follow-up actions) in the PR body or as a PR comment — but keep the committed campaign FILE itself PII-free. Apply labels if available (e.g., `threat-intel`, `hunting`) but don't fail the run if labels don't exist.
  e. Return to the default branch before the next iteration so branches stay isolated.
Stop after max_campaigns campaigns have been PR'd, or when the candidate list is exhausted.

STEP 5 — Git/PR rules:
One branch + one PR per qualifying article. Never commit campaign files or PRs to the default branch directly. Never commit config.json or anything under reports/. If `gh pr create` fails (auth/permission), keep the branch pushed and report the branch name so a human can open the PR manually.

STEP 6 — Report:
End your response with a concise summary: feed checked + window, number of articles in-window, and a per-article table of decision (campaign/skipped) + reason + PR link (or branch name) for built campaigns. If nothing qualified, say so plainly and confirm no PRs were opened.

Failure handling: If the Sentinel/kql-search MCP servers are not authenticated, STOP and report that re-authentication is needed (do not author untested queries). If a single article fails mid-build, discard its working-tree changes, note the failure, and continue with the remaining candidates — one bad article must not abort the whole run. Use only data returned by tools; never fabricate IOCs, TTPs, or test results.
```
