# Daily MCP Auth Health Check

Autonomous, scheduled **read-only** connectivity/auth probe for the MCP servers this project depends on. Runs unattended, makes exactly one cheap read-only call per server, classifies each result (PASS / FAIL / SKIP), prints a status table, and raises a **Windows toast notification** with the overall verdict so an operator knows at a glance whether anything needs re-authentication before downstream automations run.

> This is a **portable definition** for the GitHub Copilot app's scheduled-workflow system. See [`automations/README.md`](./README.md) for import instructions. Re-create it in **Workflows → New**, paste the Prompt below, and substitute every `YOUR_*` placeholder.

## Metadata

| Field | Value |
|-------|-------|
| Interval | Daily |
| Schedule | A few hours before your other scheduled automations (so failures can be fixed first) |
| Session mode | Autopilot |
| Model | Any — this is a lightweight probe; a fast/cheap model is fine |
| Reasoning effort | Low |
| Output | Status table in the run log + a best-effort desktop toast. **Never** commits, opens PRs, or changes state. |

## Adapt notes

Replace these placeholders with your environment values before saving (pull them from your `config.json`):

| Placeholder | Source / meaning |
|-------------|------------------|
| `YOUR_WORKSPACE_ID_HERE` | `sentinel_workspace_id` — Log Analytics / Sentinel workspace GUID |
| `YOUR_TENANT_ID_HERE` | `tenant_id` — Entra tenant GUID |
| `YOUR_SUBSCRIPTION_ID_HERE` | `subscription_id` |
| `YOUR_LOG_ANALYTICS_RESOURCE_GROUP` | `azure_mcp.resource_group` |
| `YOUR_LOG_ANALYTICS_WORKSPACE_NAME` | `azure_mcp.workspace_name` |

**Which servers to probe:** the Prompt below probes the five MCP servers this project uses (Sentinel Data Lake, Sentinel Triage, Microsoft Learn, KQL Search, Azure MCP). Delete any probe for a server you don't run, and add probes for any extra servers you depend on — the pattern (one cheap read-only call → classify → report) is the same.

**Toast notification:** STEP 5 calls `scripts/Send-ToastNotification.ps1` (shipped in this repo — a dependency-free native Windows toast helper that self-detects PowerShell 7 vs 5.1). Toasts render only in an **interactive, logged-on Windows desktop session** and can be suppressed by Focus Assist / Do Not Disturb. On non-Windows hosts, or if you don't want desktop alerts, delete STEP 5 — the health check still prints its status table to the run log. The script reuses the built-in PowerShell AppUserModelID, so the toast sender shows as "Windows PowerShell".

**Azure MCP non-interactive auth:** Azure MCP's default credential chain can fall through to an interactive browser sign-in when run headless/unattended, which hangs a scheduled run. Pin it to the Azure CLI credential so it uses your cached `az` token silently (set a user/machine environment variable `AZURE_TOKEN_CREDENTIALS=AzureCliCredential`, then ensure `az login` is current). If you don't run Azure MCP, remove probe #5.

**Prerequisites:** the MCP servers you want to probe configured at user scope (`~/.copilot/mcp-config.json`) and authenticated at least once, plus a populated `config.json`. This automation can **detect** broken auth but cannot **fix** it — re-authentication is interactive and must be done by a human.

## Prompt

```text
Daily MCP Auth Health Check — autonomous, READ-ONLY connectivity/auth probe for the MCP servers this project depends on. You are running UNATTENDED in autopilot. Do NOT use interactive prompts or wait for user input. Make exactly ONE minimal read-only call per server, classify the result, and print a status table. Do NOT perform any git/PR operations, write any files, create issues, or run any state-changing commands. Do NOT run `az login`, `az account set`, or any other interactive CLI command. The ONLY shell command you are permitted to run is the toast-notification script in STEP 5 (a benign, non-state-changing local desktop notification) — everything else is MCP tool calls only. At the end of the run you WILL raise a local Windows toast notification (STEP 5) as the external alert.

IMPORTANT — you CANNOT fix broken auth in an unattended run (re-auth is interactive). Your only job is to DETECT and clearly REPORT which servers need a human to re-authenticate, so it can be fixed before your downstream scheduled automations run.

STEP 1 — Bootstrap config.json (if missing):
Check for config.json at the repo root. If it does not exist, create it (it is gitignored — NEVER commit it) with exactly these values:
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID_HERE",
  "tenant_id": "YOUR_TENANT_ID_HERE",
  "subscription_id": "YOUR_SUBSCRIPTION_ID_HERE",
  "azure_mcp": { "resource_group": "YOUR_LOG_ANALYTICS_RESOURCE_GROUP", "workspace_name": "YOUR_LOG_ANALYTICS_WORKSPACE_NAME", "tenant": "YOUR_TENANT_ID_HERE", "subscription": "YOUR_SUBSCRIPTION_ID_HERE" },
  "output_dir": "reports"
}

STEP 2 — Probe each configured MCP server with ONE cheap read-only MCP TOOL CALL (never a shell/CLI command). If a call hangs, errors, or triggers an interactive sign-in prompt, record it as a failure and move on — never retry, and never complete an interactive login. Capture the outcome for each:

  1. Sentinel Data Lake (sentinel-data-mcp): call list_sentinel_workspaces. PASS if it returns one or more workspaces.
  2. Sentinel Triage (sentinel-triage-mcp): call ListIncidents with top=1. PASS if it returns without an auth/permission error (an empty list is still PASS).
  3. Microsoft Learn (microsoft-learn): call microsoft_docs_search for "advanced hunting". PASS if it returns results. (No auth — this is a pure connectivity check.)
  4. KQL Search (kql-search): call a schema lookup such as get_table_schema for "SigninLogs" (or search_tables for "sign-in"). PASS if it returns schema/results. This validates the GitHub PAT.
  5. Azure MCP Server (azure-mcp-server): make a single read-only MCP tool call to subscription_list (pass tenant + subscription from config.json). PASS if it returns one or more subscriptions. This is an MCP tool call — do NOT run `az login` or any az CLI command. If the call hangs, returns an auth/credential error, or attempts to launch an interactive browser sign-in, immediately classify it as FAIL (AUTH) and move on — never wait for or complete the interactive login.

STEP 3 — Classify each server into exactly one of:
  - PASS — call returned valid data (auth healthy).
  - FAIL (AUTH) — error indicates expired/invalid credentials, sign-in required, 401/403, consent/Conditional-Access, an interactive login prompt, or token problems.
  - FAIL (OTHER) — call failed for a non-auth reason (timeout, service error, malformed request). Note the error.
  - SKIP — server/tool not available in this environment.
Capture the concrete error text for every non-PASS so the remediation is actionable.

STEP 4 — Report (this is the whole point of the run). Print:
  a. A header line with the run date/time and an overall verdict: "ALL HEALTHY" or "N server(s) need attention".
  b. A table: | # | MCP Server | Probe call | Result (PASS/FAIL/SKIP) | Detail / error |
  c. For every FAIL (AUTH), a short remediation note describing what a HUMAN needs to do (these are instructions for a person to run later — do NOT execute them yourself in this unattended run):
     - Sentinel Data Lake / Triage → a human must re-run the interactive sign-in for that MCP server in the GitHub Copilot app (browser OAuth); tokens are user-scope at ~/.copilot.
     - Azure MCP → a human must re-authenticate the Azure CLI interactively (`az login --tenant YOUR_TENANT_ID_HERE` then `az account set --subscription YOUR_SUBSCRIPTION_ID_HERE`) outside this run. Surface this as guidance text only — never run it here.
     - KQL Search → the GitHub PAT in ~/.copilot/mcp-config.json is invalid or expired; a human must generate a new token (public_repo scope) and update GITHUB_TOKEN.
  d. A one-line reminder if anything failed: "Re-authenticate before the next scheduled automation runs."

STEP 5 — Raise a Windows toast notification (the external alert; this is the one permitted shell command):
Run the reusable toast script from the repo root so the operator gets pinged on the desktop with the overall verdict. Invoke it with PowerShell (it self-detects PowerShell 7 vs 5.1 and handles the WinRT call internally):
  .\scripts\Send-ToastNotification.ps1 -Title <title> -Body <body> -Severity <Info|Warning|Error>
Choose the arguments from the STEP 4 verdict:
  - ALL HEALTHY → -Title "MCP Health Check" -Body "All MCP servers PASS — auth healthy." -Severity Info
  - One or more FAIL → -Title "MCP Health Check" -Body "<N> server(s) need re-auth: <comma-separated server names>." -Severity Warning
Keep the body under ~120 characters. The script prints TOAST_SENT_OK on success or TOAST_FAILED: <reason>; if it fails (e.g., no interactive desktop session, Focus Assist, script missing), note that one line in your output but do NOT treat it as a health-check failure — the toast is best-effort. Do NOT run any other shell command.

Use only data returned by the tools. Never fabricate a PASS — if you did not actually receive a successful response from a server, it is not PASS. Keep the output concise.
```
