# Automations

Reusable **GitHub Copilot app scheduled-workflow** definitions for this security-investigation engine.

## What these are (and are not)

Scheduled workflows live in the **GitHub Copilot desktop app's local store** (project-scoped, per machine) — they are **not** part of the git repo and do not sync automatically. The files in this folder are **portable, PII-free definitions** that let you (or anyone who forks this repo) re-create a workflow in their own Copilot app, and serve as version-controlled backups of the originals.

Each definition is a Markdown file (`*.workflow.md`) containing:

- **Metadata** — interval, schedule, session mode, model, reasoning effort.
- **Prompt** — the full workflow prompt with every tenant-specific value replaced by a `YOUR_*` placeholder (same convention as `config.json.template`).
- **Adapt notes** — what to substitute and any prerequisites.

## How to import a workflow into the Copilot app

1. Open the GitHub Copilot app → **Workflows** (scheduled automations).
2. Create a **New workflow**.
3. Copy the **Prompt** section from the `*.workflow.md` file and paste it in.
4. Replace every `YOUR_*` placeholder with your own environment values (see the file's **Adapt notes**).
5. Set **Interval / Schedule / Mode / Model / Reasoning effort** to match the **Metadata** section.
6. Save. (Optionally run it once on-demand to validate before relying on the schedule.)

## Prerequisites (shared by these automations)

- The 3 MCP servers configured at **user scope** (`~/.copilot/mcp-config.json`): `sentinel-data-mcp`, `sentinel-triage-mcp`, `microsoft-learn`. Authenticate once interactively so OAuth tokens are cached and refresh silently in scheduled runs.
- A populated `config.json` at the repo root (see `config.json.template`).
- (Optional but recommended) Tenant-context memory files in your Copilot CLI/app memory store so scheduled runs render accurate verdicts — see `notes/memory/README.md`.

## ⚠️ PII-free standard

These definitions are committed to git and **must never contain** real workspace names, tenant/subscription GUIDs, UPNs, hostnames, or local filesystem paths. Always use `YOUR_*` placeholders. Before committing a new or updated definition, scan it for values copied from a live workflow and replace them.

## Available definitions

| File | Purpose | Interval | Mode |
|------|---------|----------|------|
| `daily-threat-pulse.workflow.md` | Autonomous daily SOC scan (Threat Pulse) with adaptive, self-directed drill-downs and a local Markdown report | Daily | Autopilot |
| `weekly-threat-intel-campaign.workflow.md` | Autonomous weekly hunt-authoring run (Threat Intel Campaign) — triages a TI RSS feed and opens a PR with tested, tuned KQL hunting queries per qualifying article | Weekly | Autopilot |
| `daily-mcp-auth-healthcheck.workflow.md` | Read-only daily probe of every MCP server — keeps OAuth tokens warm and prints a PASS/FAIL table so you can re-authenticate before other automations run | Daily | Autopilot |
