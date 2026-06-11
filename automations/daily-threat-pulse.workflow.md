# Daily Threat Pulse

Autonomous, scheduled SOC scan built on the `threat-pulse` skill. Runs unattended, loads tenant-context memory for accurate verdicts, executes the full 12-query pulse, then runs an **adaptive, self-directed drill-down loop** (up to 5, pivoting on what it finds) and writes a local Markdown report.

> This is a **portable definition** for the GitHub Copilot app's scheduled-workflow system. See [`automations/README.md`](./README.md) for import instructions. Re-create it in **Workflows → New**, paste the Prompt below, and substitute every `YOUR_*` placeholder.

## Metadata

| Field | Value |
|-------|-------|
| Interval | Daily |
| Schedule | 07:00 (local) |
| Session mode | Autopilot |
| Model | Claude Opus 4.x (or your preferred high-reasoning model) |
| Reasoning effort | Medium |
| Output | Local Markdown report only — **never committed / no PR** (contains live tenant PII; `reports/**` is gitignored) |

## Adapt notes

Replace these placeholders with your environment values before saving (pull them from your `config.json`):

| Placeholder | Source / meaning |
|-------------|------------------|
| `YOUR_WORKSPACE_ID_HERE` | `sentinel_workspace_id` — Log Analytics / Sentinel workspace GUID |
| `YOUR_TENANT_ID_HERE` | `tenant_id` — Entra tenant GUID (used in queries and `tid=` portal links) |
| `YOUR_SUBSCRIPTION_ID_HERE` | `subscription_id` |
| `YOUR_LOG_ANALYTICS_RESOURCE_GROUP` | `azure_mcp.resource_group` |
| `YOUR_LOG_ANALYTICS_WORKSPACE_NAME` | `azure_mcp.workspace_name` |
| `YOUR_TENANT_CONTEXT_MEMORY_PATH` | Absolute path to your tenant-context memory file (e.g. `<userprofile>\.copilot\memories\repo\<your-tenant>.md`). Omit STEP 1.5 if you don't use context memory. |
| `YOUR_INVESTIGATION_PATTERNS_MEMORY_PATH` | Optional absolute path to a supplementary investigation-patterns memory file. |
| `YOUR_DURABLE_REPORTS_PATH` | Absolute path to a durable reports folder visible outside the worktree (e.g. your synced/main checkout `reports\threat-pulse`). |
| `YOUR_TENANT_LABEL` | Short tenant label included in the report filename (e.g. `Zava`) so reports from different tenants are easy to tell apart. |

**Prerequisites:** the 3 user-scope MCP servers authenticated (`sentinel-data-mcp`, `sentinel-triage-mcp`, `microsoft-learn`), a populated `config.json`, and (recommended) tenant-context memory. Scheduled runs are non-interactive, so STEP 1.5 explicitly reads the memory file rather than relying on auto-load.

## Prompt

```text
Daily Threat Pulse — autonomous scheduled SOC scan. You are running UNATTENDED. Do NOT use vscode_askQuestions, interactive quick-pick menus, or memory-backed selection loops, and never wait for user input. This is read-only investigation only — no state-changing commands (per the Remediation Output Policy).

STEP 1 — Bootstrap config.json (if missing):
Check for config.json at the repo root. If it does not exist, create it (it is gitignored — NEVER commit it) with exactly these values:
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID_HERE",
  "tenant_id": "YOUR_TENANT_ID_HERE",
  "subscription_id": "YOUR_SUBSCRIPTION_ID_HERE",
  "azure_mcp": { "resource_group": "YOUR_LOG_ANALYTICS_RESOURCE_GROUP", "workspace_name": "YOUR_LOG_ANALYTICS_WORKSPACE_NAME", "tenant": "YOUR_TENANT_ID_HERE", "subscription": "YOUR_SUBSCRIPTION_ID_HERE" },
  "output_dir": "reports"
}

STEP 1.5 — Load tenant context memory (CRITICAL for accuracy — do NOT skip):
Scheduled runs are non-interactive, so user/repo memory does NOT auto-load. Before running queries and BEFORE writing ANY verdict, recommendation, "compromised" call, or escalation, read the tenant context file in full at:
  YOUR_TENANT_CONTEXT_MEMORY_PATH
Apply its documented checks to every finding and drill-down: account classification (A–F), validated personnel, known automation/orchestration user-agent fingerprints, known-good IPs and automation windows, and documented false-positive rules. If a signal matches a documented known/expected pattern, classify it as known/expected and do NOT escalate. If a signal does NOT match, investigate normally but explicitly state that you checked the tenant context. Also read YOUR_INVESTIGATION_PATTERNS_MEMORY_PATH if it exists. If the context file is missing, note that prominently in the report and proceed with standard analysis.

STEP 2 — Run the Threat Pulse scan:
Load and follow .github/skills/threat-pulse/SKILL.md, Phases 0 through 3, with a 7d lookback against your Sentinel workspace (YOUR_WORKSPACE_ID_HERE — if it is the only workspace, auto-select it). Execute all 12 queries (Q5 on Data Lake, the rest on Advanced Hunting in parallel). Produce the full report body: Dashboard Summary, Detailed Findings per domain with verdicts, Cross-Query Correlations, and Recommended Actions. Append tid=YOUR_TENANT_ID_HERE to all security.microsoft.com portal links. Every finding must cite query evidence; every "clear" verdict must cite 0 results.

STEP 3 — Adaptive autonomous drill-downs (override the interactive Phase 4 loop):
Run an intelligent, self-directed investigation loop of UP TO 5 drill-downs total. Do NOT pre-commit to a fixed list — select and pivot dynamically based on what each drill-down uncovers.

1. Build the initial drill-down candidate pool exactly as Phase 4 step 1 specifies: per-query Drill-down skill mappings + concrete entities from findings (UPNs, IPs, devices, CVEs, hostnames) + matching query-file and IOC prompts. Rank by verdict priority (red first, then orange, then yellow).
2. Drill-down loop (repeat until 5 are completed OR no worthwhile lead remains):
   a. SELECT the single highest-value lead from the current pool — the one most likely to confirm/refute a compromise or materially change the risk picture. Prefer red over orange over yellow, but use judgment: an orange with a strong pivot (e.g., a shared IP, token, device, or actor linking multiple findings) can outrank an isolated red.
   b. EXECUTE the referenced skill or query file scoped to its concrete entities, using 30d (Advanced Hunting) or 90d (Data Lake) lookback. Apply the STEP 1.5 tenant context when classifying every finding.
   c. RE-EVALUATE: from the results, extract any NEW entities or leads (newly surfaced IPs, UPNs, devices, sessions, tokens, parent/child processes, OAuth apps, etc.). Add promising new leads to the pool and re-rank. If a finding matches a documented known/expected pattern in tenant context, mark it resolved and do NOT spawn pivots from it.
   d. DECIDE whether to continue: pivot to the next lead if (and only if) there is still a non-clear lead worth investigating and you have not yet run 5. Stop early if the remaining pool is exhausted, all open threads are explained by tenant context, or further drill-downs would be redundant. Quality over quantity — do not pad to 5 with low-value queries.
3. If ALL domain verdicts are clear and the initial pool is empty, skip drill-downs entirely and state that clearly.

Keep every drill-down focused and strictly evidence-based; never fabricate entities or counts.

STEP 4 — Assemble the combined report:
Under a "## Automated Drill-Down Investigations" heading, append each drill-down (in the order executed) as its own subsection containing: the lead/prompt investigated, WHY it was selected (and, for pivots, which prior finding triggered it), the skill/query file used, key findings, supporting evidence, and a short risk verdict. After the subsections, add a brief "Investigation path" note summarizing how the loop pivoted (e.g., "Q3 risky sign-in -> IP a.b.c.d -> linked device DESKTOP-X -> lateral-movement check"). Note in a one-line header whether tenant context was successfully loaded and applied, and how many drill-downs ran (out of a max of 5) with the reason for stopping.

STEP 5 — Persist (LOCAL ONLY — reports contain live tenant PII; the reports/ folder is gitignored; NEVER commit or open a PR):
Save the complete report (scan + all drill-downs) as markdown to BOTH (include the YOUR_TENANT_LABEL tenant label in the filename so reports from different tenants are easy to tell apart):
- reports/threat-pulse/ThreatPulse_YOUR_TENANT_LABEL_<YYYY-MM-DD>.md  (in the current worktree)
- YOUR_DURABLE_REPORTS_PATH\ThreatPulse_YOUR_TENANT_LABEL_<YYYY-MM-DD>.md  (durable location visible outside the worktree; create the folder if needed)

STEP 6 — Executive summary:
End your response with a concise summary: scan date, whether tenant context was applied, # open/unresolved incidents, highest-risk identity, top exposure finding, how many drill-downs ran (out of 5) and why the loop stopped, and the list of drill-downs run with their verdicts and the pivot chain.

Failure handling: If the Sentinel MCP servers are not authenticated (auth/login error), stop and report that re-authentication is needed. enrich_ips.py may lack API tokens (.env absent) — if so, skip IP enrichment gracefully and note it. Use only data returned by tools; never fabricate entities or counts.
```
