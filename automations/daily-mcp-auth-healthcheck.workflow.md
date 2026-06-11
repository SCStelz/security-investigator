# Daily MCP Auth Health Check

A lightweight, read-only probe that calls **every MCP server** this project depends on with one cheap request, then prints a PASS/FAIL status table. Its job is **early detection** — surfacing any server whose authentication has lapsed so you can re-authenticate **before** your scheduled investigation/automation runs fire.

> This is a **portable definition** for the GitHub Copilot app's scheduled-workflow system. See [`automations/README.md`](./README.md) for import instructions. Re-create it in **Workflows → New**, paste the Prompt below, and substitute every `YOUR_*` placeholder.

## Why this exists (and its limits)

The OAuth-based servers (Sentinel Data Lake, Sentinel Triage) use **refresh tokens**. Regularly *using* them mitigates the ~90-day **inactivity** expiry — so a daily probe genuinely keeps them warm. But a probe **cannot** prevent policy-driven re-auth: Conditional Access re-prompts, MFA refresh, password changes, or admin token revocation all force an **interactive browser sign-in** that an unattended run can't perform. `kql-search` uses a **static GitHub PAT** (no refresh — it simply expires), Azure MCP rides on `az login`'s cached credentials, and Microsoft Learn needs no auth.

So this automation's real value is **fast detection + a clear report**. Schedule it **early** (before your other automations) so a failure is visible in time to fix it.

## Metadata

| Field | Value |
|-------|-------|
| Interval | Daily |
| Schedule | 06:30 (local) — set it *before* your earliest other automation |
| Session mode | Autopilot |
| Model | Claude Opus 4.x (low reasoning is sufficient — this is mechanical) |
| Reasoning effort | Low |
| Output | Status table in the run output only — **no external alert, no files, no git/PR** |

> 💡 **Notification tip:** the workflow itself only prints to its run output. To be pinged when it finishes, enable the app's "notify on completion" for this workflow, or check the run history each morning.

## Adapt notes

Replace these placeholders with your environment values before saving (pull them from your `config.json`):

| Placeholder | Source / meaning |
|-------------|------------------|
| `YOUR_WORKSPACE_ID_HERE` | `sentinel_workspace_id` — Log Analytics / Sentinel workspace GUID |
| `YOUR_TENANT_ID_HERE` | `tenant_id` — Entra tenant GUID |
| `YOUR_SUBSCRIPTION_ID_HERE` | `subscription_id` |
| `YOUR_LOG_ANALYTICS_RESOURCE_GROUP` | `azure_mcp.resource_group` |
| `YOUR_LOG_ANALYTICS_WORKSPACE_NAME` | `azure_mcp.workspace_name` |

**Prerequisites:** the MCP servers you want probed must be configured at user scope (`~/.copilot/mcp-config.json`). Add or drop probes in STEP 2 to match the servers you actually have configured; mark any server whose tools aren't present as SKIP rather than FAIL.

## Prompt

```text
Daily MCP Auth Health Check — autonomous, READ-ONLY connectivity/auth probe for every MCP server this project depends on. You are running UNATTENDED in autopilot. Do NOT use interactive prompts or wait for user input. Make exactly ONE minimal read-only call per server, classify the result, and print a status table. Do NOT perform any git/PR operations, write any files, create issues, or run any state-changing commands. Output only — there is no external alert.

IMPORTANT — you CANNOT fix broken auth in an unattended run (re-auth is interactive). Your only job is to DETECT and clearly REPORT which servers need a human to re-authenticate, so it can be fixed before your other scheduled automations run.

STEP 1 — Bootstrap config.json (if missing):
Check for config.json at the repo root. If it does not exist, create it (it is gitignored — NEVER commit it) with exactly these values:
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID_HERE",
  "tenant_id": "YOUR_TENANT_ID_HERE",
  "subscription_id": "YOUR_SUBSCRIPTION_ID_HERE",
  "azure_mcp": { "resource_group": "YOUR_LOG_ANALYTICS_RESOURCE_GROUP", "workspace_name": "YOUR_LOG_ANALYTICS_WORKSPACE_NAME", "tenant": "YOUR_TENANT_ID_HERE", "subscription": "YOUR_SUBSCRIPTION_ID_HERE" },
  "output_dir": "reports"
}

STEP 2 — Probe each MCP server with ONE cheap read-only call. If a call hangs or errors, record it and move on — never retry interactively. Capture the outcome for each:

  1. Sentinel Data Lake (sentinel-data-mcp): call list_sentinel_workspaces. PASS if it returns one or more workspaces.
  2. Sentinel Triage (sentinel-triage-mcp): call ListIncidents with top=1. PASS if it returns without an auth/permission error (an empty list is still PASS).
  3. Microsoft Learn (microsoft-learn): call microsoft_docs_search for "advanced hunting". PASS if it returns results. (No auth — pure connectivity check.)
  4. KQL Search (kql-search): call a schema lookup such as get_table_schema for "SigninLogs" (or search_tables for "sign-in"). PASS if it returns schema/results. This validates the GitHub PAT.
  5. Azure MCP Server (azure-mcp-server): call subscription_list (pass tenant + subscription from config.json). PASS if it returns one or more subscriptions.

STEP 3 — Classify each server into exactly one of:
  - PASS — call returned valid data (auth healthy).
  - FAIL (AUTH) — error indicates expired/invalid credentials, sign-in required, 401/403, consent/Conditional-Access, or token problems.
  - FAIL (OTHER) — call failed for a non-auth reason (timeout, service error, malformed request). Note the error.
  - SKIP — server/tool not available in this environment.
Capture the concrete error text for every non-PASS so the remediation is actionable.

STEP 4 — Report (this is the whole point of the run). Print:
  a. A header line with the run date/time and an overall verdict: "ALL HEALTHY" or "N server(s) need attention".
  b. A table: | # | MCP Server | Probe call | Result | Detail / error |
  c. For every FAIL (AUTH), a short remediation note:
     - Sentinel Data Lake / Triage → re-run the interactive sign-in for that MCP server in the GitHub Copilot app (browser OAuth); tokens are user-scope at ~/.copilot.
     - Azure MCP → run `az login --tenant YOUR_TENANT_ID_HERE` then `az account set --subscription YOUR_SUBSCRIPTION_ID_HERE`.
     - KQL Search → the GitHub PAT in ~/.copilot/mcp-config.json is invalid or expired; generate a new token (public_repo scope) and update GITHUB_TOKEN.
  d. A one-line reminder if anything failed: "Re-authenticate before your other scheduled automations run."

Use only data returned by the tools. Never fabricate a PASS — if you did not actually receive a successful response from a server, it is not PASS. Keep the output concise.
```
