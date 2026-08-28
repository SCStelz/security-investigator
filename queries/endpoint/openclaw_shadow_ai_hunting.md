# OpenClaw Shadow AI Agent — Threat Hunting Queries

**Created:** 2026-03-30  
**Platform:** Both  
**Tables:** DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceCustomFileEvents, DeviceCustomScriptEvents, DeviceCustomImageLoadEvents, SecurityAlert  
**Keywords:** openclaw, shadow AI, AI agent, telegram bot, node.js, npm, gateway, persistence, scheduled task, startup folder, clipboard access, self-hosted AI, process chain, C2, device pairing  
**MITRE:** T1053.005, T1547.001, T1059.001, T1071.001, T1071.004, T1564.001, T1119, T1132, TA0003, TA0011  
**Domains:** endpoint  
**Timeframe:** Last 90 days (configurable)

---

## Overview

This collection contains KQL queries for **hunting OpenClaw** — a self-hosted AI agent runtime distributed as an npm package. OpenClaw installs a persistent gateway daemon on endpoints, communicates with external APIs (Telegram Bot, OpenAI/ChatGPT, npm registry), and provides clipboard access, device pairing, and terminal UI capabilities.

**Context:** OpenClaw itself is a legitimate tool (see [Microsoft Security Blog — Running OpenClaw Safely](https://www.microsoft.com/en-us/security/blog/2026/02/19/running-openclaw-safely-identity-isolation-runtime-risk/)). However, it represents **Shadow AI** risk when deployed without organizational approval: it establishes persistence, communicates with external C2-like endpoints, accesses the clipboard, and can execute arbitrary commands. The ClawHavoc supply chain variant uses compromised `openclaw-agent.zip` packages to deliver malware.

### Architecture

```
Persistence Layer:
  ├─ Startup Folder BAT → cmd.exe → gateway.cmd → node.exe (dist/index.js gateway --port 18789)
  ├─ Scheduled Task ("OpenClaw Gateway") → cmd.exe → gateway.cmd → node.exe
  └─ PowerShell -ExecutionPolicy Bypass → openclaw-startup.ps1 → polls gateway → launches TUI

Gateway Daemon (node.exe PID on port 18789):
  ├─ api.telegram.org:443      — Bot API (built-in, not a skill/plugin)
  ├─ chatgpt.com:443           — AI inference
  ├─ auth.openai.com:443       — OAuth token refresh
  ├─ registry.npmjs.org:443    — Update checks
  └─ localhost:18789            — Local gateway API

Data Files (.openclaw/):
  ├─ agents/main/agent/auth-profiles.json  — Credential/token store (rotating content, fixed 2.7KB size)
  ├─ agents/main/sessions/*.jsonl          — AI conversation logs
  ├─ cron/jobs.json                        — Cron scheduler (PID-encoded temp files)
  ├─ devices/paired.json + pending.json    — Device pairing state
  ├─ identity/device-auth.json             — Device authentication
  └─ update-check.json                     — Version check metadata
```

### Key Behavioral Facts

- **Telegram integration is built-in** to the gateway binary (`dist/index.js`), NOT a separately installed skill. Connections to `api.telegram.org` begin within seconds of gateway startup.
- **AMSI is blind to Node.js** — AMSI hooks PowerShell/VBScript/JScript but NOT the V8 engine. AMSI captures the PowerShell startup scripts but none of the gateway's JavaScript HTTP calls.
- **Standard DeviceFileEvents may miss `.openclaw/` directory activity** due to MDE's default telemetry thresholds for Node.js I/O. CDC `DeviceCustomFileEvents` captures the full picture.
- **Only one native addon**: `@mariozechner/clipboard-win32-x64-msvc` (clipboard read/write). All other dependencies are pure JS and invisible to ImageLoad.
- **`auth-profiles.json` content mutates every 1–5 minutes** during active use (25+ unique SHA256 hashes with constant 2.7KB size) — indicates rotating session tokens alongside static API keys.

### Community Detection Rules

Source: [move78ai/OpenClaw-Threat-Hunting](https://github.com/move78ai/OpenClaw-Threat-Hunting) (Abhishek G Sharma, Move78 International)
- Rule 1: Shadow AI Process Execution (triggers on `openclaw` in process command lines)
- Rule 2: Connection to ClawHub/Moltbook infrastructure (supply chain C2 endpoints)
- Rule 3: ClawHavoc Supply Chain Artifacts (`openclaw-agent.zip`, `.openclaw\skills` directory)

### ClawHavoc Supply Chain IOCs

| IOC | Type | Context |
|-----|------|---------|
| `openclaw-agent.zip` | File | ClawHavoc dropper — trojaned agent package |
| `.openclaw\skills` directory | Path | ClawHavoc uses skills directory for implant staging (legitimate OpenClaw does NOT create this) |
| `clawhub.com` | Domain | Malicious skill marketplace impersonating official |
| `moltbook.com` | Domain | ClawHavoc C2 infrastructure |
| Port `18789` | Network | Default gateway listener — may attract scanners/probes |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [OpenClaw Process Execution Detection](#query-1-openclaw-process-execution-detection) | Detection | `DeviceProcessEvents` |
| 2 | [OpenClaw Persistence Mechanisms](#query-2-openclaw-persistence-mechanisms) | Investigation | `DeviceProcessEvents` |
| 3 | [OpenClaw Network Connections — External API Map](#query-3-openclaw-network-connections--external-api-map) | Investigation | `DeviceNetworkEvents` |
| 4 | [ClawHavoc Supply Chain IOC Check](#query-4-clawhavoc-supply-chain-ioc-check) | Investigation | `DeviceFileEvents` + `DeviceNetworkEvents` |
| 5 | [Fleet-Wide OpenClaw Spread Assessment](#query-5-fleet-wide-openclaw-spread-assessment) | Posture | `DeviceNetworkEvents` + multi |
| 6 | [Gateway Port 18789 Exposure Scan](#query-6-gateway-port-18789-exposure-scan) | Investigation | `DeviceNetworkEvents` |
| 7 | [Telegram Bot API Communication Pattern](#query-7-telegram-bot-api-communication-pattern) | Investigation | `DeviceNetworkEvents` |
| 8 | [OpenClaw .openclaw Directory File Activity (CDC)](#query-8-openclaw-openclaw-directory-file-activity-cdc) | Investigation | `DeviceCustomFileEvents` |
| 9 | [auth-profiles.json Token Rotation Tracking (CDC)](#query-9-auth-profilesjson-token-rotation-tracking-cdc) | Investigation | `DeviceCustomFileEvents` |
| 10 | [OpenClaw AMSI Script Content Capture (CDC)](#query-10-openclaw-amsi-script-content-capture-cdc) | Investigation | `DeviceCustomScriptEvents` |
| 11 | [Native Addon ImageLoad — Clipboard Access Module (CDC)](#query-11-native-addon-imageload--clipboard-access-module-cdc) | Investigation | `DeviceCustomImageLoadEvents` |
| 12 | [OpenClaw Gateway Instance Timeline via Cron Job Files (CDC)](#query-12-openclaw-gateway-instance-timeline-via-cron-job-files-cdc) | Investigation | `DeviceCustomFileEvents` |


## Query 1: OpenClaw Process Execution Detection

Detects any process execution involving OpenClaw binaries or command lines. Primary Shadow AI discovery query.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "OpenClaw Shadow AI process execution on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "Verify if OpenClaw is authorized in this environment. If unauthorized, isolate the device and check for persistence mechanisms (Scheduled Task, Startup folder). Run Query 4 to check for ClawHavoc supply chain IOCs."
adaptation_notes: "Remove summarize — convert to row-level project. Add DeviceId, ReportId columns."
-->

```kql
// OpenClaw Shadow AI Process Detection
// Tables: DeviceProcessEvents
// Lookback: 30d (configurable)
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has "openclaw" or InitiatingProcessCommandLine has "openclaw"
| summarize 
    EventCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Commands = make_set(ProcessCommandLine, 20),
    ParentCommands = make_set(InitiatingProcessCommandLine, 10)
    by DeviceName, AccountName, FileName
| order by EventCount desc
```

---

## Query 2: OpenClaw Persistence Mechanisms

Detects the three known persistence methods: Startup folder BAT, Scheduled Task, and PowerShell ExecutionPolicy Bypass.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "OpenClaw persistence mechanism detected on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Inspect the persistence method (Scheduled Task, Startup folder BAT, or ExecutionPolicy Bypass). Remove unauthorized persistence entries. Check for ClawHavoc supply chain artifacts."
adaptation_notes: "Already row-level with project. Add DeviceId + ReportId columns."
-->

```kql
// OpenClaw Persistence Detection
// Tables: DeviceProcessEvents
// Lookback: 90d
let lookback = 90d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where 
    // Scheduled Task persistence
    (ProcessCommandLine has "schtasks" and ProcessCommandLine has "openclaw")
    // ExecutionPolicy Bypass with openclaw startup script
    or (ProcessCommandLine has "ExecutionPolicy" and ProcessCommandLine has "Bypass" and ProcessCommandLine has "openclaw")
    // Gateway.cmd launched by svchost (Scheduled Task) or explorer (Startup folder)
    or (ProcessCommandLine has "gateway.cmd" and ProcessCommandLine has "openclaw")
    // Startup folder BAT file
    or (ProcessCommandLine has "openclaw" and InitiatingProcessFileName in~ ("explorer.exe", "svchost.exe"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId
| order by Timestamp asc
```

---

## Query 3: OpenClaw Network Connections — External API Map

Maps all external destinations contacted by the gateway daemon. Critical for identifying Telegram Bot, OpenAI, and update-check traffic.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet-wide aggregation query (summarize by RemoteUrl, DeviceName). Useful for threat hunting, not suitable for CD — no single-event row output."
-->

```kql
// OpenClaw External Network Connections
// Tables: DeviceNetworkEvents
// Lookback: 30d
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessCommandLine has "openclaw"
| where RemoteUrl != "" or RemoteIP !in ("", "127.0.0.1", "::1")
| summarize 
    Connections = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Ports = make_set(RemotePort),
    IPs = make_set(RemoteIP, 10)
    by RemoteUrl, DeviceName
| order by Connections desc
```

---

## Query 4: ClawHavoc Supply Chain IOC Check

Checks for connections to malicious ClawHub/Moltbook infrastructure and presence of supply chain artifacts.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "ClawHavoc supply chain IOC detected on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL — ClawHavoc supply chain compromise. Isolate device immediately. Check for openclaw-agent.zip dropper and .openclaw/skills directory. Investigate all processes spawned by node.exe. Rotate all credentials on the device."
adaptation_notes: "Union of two queries — cannot use NRT. Convert each branch to project row-level. Add DeviceId + ReportId. May need to split into two separate CDs (network IOC + file IOC) since union is fragile in CD."
-->

```kql
// ClawHavoc Supply Chain Detection
// Tables: DeviceNetworkEvents, DeviceFileEvents
// Lookback: 90d
let lookback = 90d;
let MaliciousDomains = dynamic(["clawhub.com", "moltbook.com"]);
// Check network connections to malicious infrastructure
let NetworkIOCs = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has_any (MaliciousDomains)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, 
    InitiatingProcessCommandLine, InitiatingProcessFileName;
// Check for supply chain file artifacts
let FileIOCs = DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileName =~ "openclaw-agent.zip" 
    or FolderPath has ".openclaw\\skills"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType,
    InitiatingProcessCommandLine;
NetworkIOCs
| union FileIOCs
| order by Timestamp asc
```

---

## Query 5: Fleet-Wide OpenClaw Spread Assessment

Identifies all devices in the environment with OpenClaw activity — process execution, network, or file events.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet-wide spread assessment with fullouter join and multi-table summarize. Statistical baseline query — not suitable for CD."
-->

```kql
// Fleet-Wide OpenClaw Presence
// Tables: DeviceProcessEvents, DeviceNetworkEvents
// Lookback: 90d
let lookback = 90d;
let ProcessDevices = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has "openclaw"
| summarize ProcessEvents = count(), FirstProcess = min(Timestamp), LastProcess = max(Timestamp) by DeviceName;
let NetworkDevices = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessCommandLine has "openclaw"
| summarize NetEvents = count(), FirstNet = min(Timestamp), LastNet = max(Timestamp) by DeviceName;
ProcessDevices
| join kind=fullouter NetworkDevices on DeviceName
| extend DeviceName = coalesce(DeviceName, DeviceName1)
| project DeviceName, ProcessEvents, FirstProcess, LastProcess, NetEvents, FirstNet, LastNet
| order by ProcessEvents desc
```

---

## Query 6: Gateway Port 18789 Exposure Scan

Checks for inbound connection attempts to port 18789 from other devices — if the gateway binds to 0.0.0.0 instead of 127.0.0.1, it may be probed by other machines on the network.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "LateralMovement"
title: "Inbound probe to OpenClaw gateway port 18789 on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Investigate inbound connections to port 18789 — the OpenClaw gateway may be exposed to the network. Verify if the gateway is bound to 0.0.0.0 or 127.0.0.1. Review source IPs for lateral movement or scanning activity."
adaptation_notes: "Remove summarize — convert to row-level project. Add DeviceId + ReportId columns. Filter already limits to non-localhost."
-->

```kql
// Port 18789 Exposure — Inbound Probes to OpenClaw Gateway
// Tables: DeviceNetworkEvents
// Lookback: 30d
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where LocalPort == 18789 and ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| summarize 
    Attempts = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SourceIPs = make_set(RemoteIP, 20)
    by DeviceName, ActionType
| order by Attempts desc
```

---

## Query 7: Telegram Bot API Communication Pattern

Detects connections to Telegram Bot API from any process — not limited to OpenClaw. Useful for fleet-wide C2 detection.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Non-Telegram app connecting to Telegram Bot API on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Investigate the process connecting to api.telegram.org. If node.exe with openclaw, check if OpenClaw is authorized. If powershell.exe or other unexpected process, investigate for C2 implant. Check process command line and parent process."
adaptation_notes: "Remove summarize — convert to row-level project. Add DeviceId + ReportId columns. Keep the Telegram Desktop exclusion filter."
-->

```kql
// Telegram Bot API Communication — Fleet-Wide
// Tables: DeviceNetworkEvents
// Lookback: 30d
// NOTE: Also catches legitimate Telegram Desktop app — filter by InitiatingProcessFileName to differentiate
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has "api.telegram.org" or RemoteUrl has "telegram.org"
| where InitiatingProcessFileName !in~ ("telegram.exe", "Telegram.exe")  // Exclude desktop app
| summarize 
    Connections = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Processes = make_set(InitiatingProcessFileName, 10),
    CommandLines = make_set(InitiatingProcessCommandLine, 10)
    by DeviceName, RemoteUrl
| order by Connections desc
```

---

## Query 8: OpenClaw .openclaw Directory File Activity (CDC)

**Requires CDC:** This query uses `DeviceCustomFileEvents` which requires MDE Custom Data Collection rules (specifically "FileCreation Collect All"). Standard `DeviceFileEvents` may return 0 results for `.openclaw/` activity due to Node.js I/O falling below MDE's default telemetry threshold.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "CDC table — requires DeviceCustomFileEvents (not available in all environments). Summarize aggregation for directory mapping. Not suitable for CD."
-->

```kql
// .openclaw Directory — Complete File Activity Map (CDC)
// Tables: DeviceCustomFileEvents
// Lookback: 90d
let lookback = 90d;
DeviceCustomFileEvents
| where TimeGenerated > ago(lookback)
| where FolderPath has ".openclaw"
| summarize 
    Events = count(), 
    FirstSeen = min(TimeGenerated), 
    LastSeen = max(TimeGenerated),
    ActionTypes = make_set(ActionType)
    by FileName, FolderPath, DeviceName
| order by Events desc
```

---

## Query 9: auth-profiles.json Token Rotation Tracking (CDC)

**Requires CDC:** Tracks content mutations in the credential store file. High mutation rate (25+ hashes in 10 days) is normal — indicates rotating session tokens. A sudden size change or new write process would be anomalous.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "CDC table — requires DeviceCustomFileEvents. Summarize aggregation for SHA256 mutation tracking — baseline query, not suitable for CD."
-->

```kql
// auth-profiles.json Credential Store Mutation Tracking (CDC)
// Tables: DeviceCustomFileEvents
// Lookback: 90d
let lookback = 90d;
DeviceCustomFileEvents
| where TimeGenerated > ago(lookback)
| where FileName == "auth-profiles.json"
| where FolderPath has ".openclaw"
| where isnotempty(SHA256)
| summarize 
    FirstSeen = min(TimeGenerated), 
    LastSeen = max(TimeGenerated), 
    WriteCount = count()
    by SHA256, FileSize, DeviceName, InitiatingProcessFileName
| order by FirstSeen asc
```

---

## Query 10: OpenClaw AMSI Script Content Capture (CDC)

**Requires CDC:** AMSI captures PowerShell script content from the startup chain. Note: Node.js V8 execution is invisible to AMSI — this only captures the PowerShell bootstrap scripts. Look for the `openclaw-startup.ps1` content and any unexpected PowerShell commands.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "OpenClaw PowerShell startup script captured by AMSI on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Review the AMSI-captured script content for malicious payloads. Legitimate openclaw-startup.ps1 polls the gateway health endpoint. Unexpected PowerShell content (encoded commands, downloads, credential access) indicates tampering."
adaptation_notes: "CDC table — requires DeviceCustomScriptEvents. Already row-level with project. Add DeviceId + ReportId. Column is ScriptContent (NOT AdditionalFields). Uses TimeGenerated (not Timestamp)."
-->

```kql
// AMSI Script Content from OpenClaw Startup Chain (CDC)
// Tables: DeviceCustomScriptEvents
// Schema note: Column is "ScriptContent" (NOT "AdditionalFields")
// Lookback: 90d
let lookback = 90d;
DeviceCustomScriptEvents
| where TimeGenerated > ago(lookback)
| where InitiatingProcessCommandLine has "openclaw"
| where isnotempty(ScriptContent)
// Filter out PowerShell engine boilerplate
| where ScriptContent !startswith "{ Set-StrictMode" 
    and ScriptContent != "$global:?"
    and ScriptContent !startswith "& { Set-StrictMode"
    and ScriptContent !startswith "@{"  // Module manifests
    and ScriptContent !has "FullyQualifiedErrorId"  // Error formatters
| project TimeGenerated, DeviceName, ScriptContent, InitiatingProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessId
| order by TimeGenerated asc
```

---

## Query 11: Native Addon ImageLoad — Clipboard Access Module (CDC)

**Requires CDC:** Detects loading of the clipboard-access native addon. This is the only OpenClaw-specific native module — all other dependencies are pure JavaScript.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "CDC table — requires DeviceCustomImageLoadEvents. Summarize aggregation for load counting. Could be adapted to row-level but clipboard addon loading is expected behavior for legitimate OpenClaw — low detection value as CD."
-->

```kql
// OpenClaw Clipboard Access Native Addon (CDC)
// Tables: DeviceCustomImageLoadEvents
// Lookback: 90d
let lookback = 90d;
DeviceCustomImageLoadEvents
| where TimeGenerated > ago(lookback)
| where FolderPath has "openclaw" and FolderPath has "clipboard"
| project TimeGenerated, DeviceName, FileName, FolderPath, FileSize, SHA256,
    InitiatingProcessCommandLine, InitiatingProcessFileName
| summarize LoadCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by FileName, FolderPath, DeviceName, SHA256
```

---

## Query 12: OpenClaw Gateway Instance Timeline via Cron Job Files (CDC)

**Requires CDC:** Maps gateway restart timeline by extracting PIDs from cron temp file names. Each gateway start produces a `jobs.json.<PID>.<hex>.tmp` file.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "CDC table — requires DeviceCustomFileEvents. Summarize aggregation for PID-based timeline reconstruction. Forensic analysis query, not suitable for CD."
-->

```kql
// OpenClaw Gateway Instance Timeline from Cron Temp Files (CDC)
// Tables: DeviceCustomFileEvents
// Lookback: 90d
let lookback = 90d;
DeviceCustomFileEvents
| where TimeGenerated > ago(lookback)
| where FolderPath has ".openclaw\\cron"
| where FileName startswith "jobs.json." and FileName endswith ".tmp"
| extend GatewayPID = extract(@"jobs\.json\.(\d+)\.", 1, FileName)
| summarize 
    FirstSeen = min(TimeGenerated),
    Events = count()
    by GatewayPID, DeviceName
| order by FirstSeen asc
```

---

## Investigation Playbook

### Triage Order

1. **Query 1** → Confirm OpenClaw presence and scope
2. **Query 5** → Fleet-wide spread assessment
3. **Query 4** → Check for ClawHavoc supply chain compromise (CRITICAL — if positive, escalate immediately)
4. **Query 3** → Map external communications
5. **Query 7** → Fleet-wide Telegram Bot API check (catches non-OpenClaw C2 too)
6. **Query 2** → Document persistence mechanisms
7. **Query 6** → Check gateway port exposure

### CDC Deep-Dive (if Custom Data Collection is enabled)

8. **Query 8** → Map complete `.openclaw` directory structure
9. **Query 9** → Track auth-profiles.json credential rotation
10. **Query 10** → Extract PowerShell startup script content from AMSI
11. **Query 11** → Confirm clipboard access addon loading
12. **Query 12** → Map gateway restart timeline

### What AMSI Cannot See

AMSI hooks PowerShell, VBScript, and JScript engines but **NOT** Node.js V8. This means:
- ✅ AMSI captures: `openclaw-startup.ps1` content, PowerShell module loads, `schtasks` commands
- ❌ AMSI misses: Telegram Bot API calls, OpenAI API calls, all gateway JavaScript execution, credential reading from `auth-profiles.json`

To investigate what the JavaScript gateway actually *does*, you must rely on:
- `DeviceNetworkEvents` for API destinations
- `DeviceCustomFileEvents` (CDC) for file system access patterns
- `DeviceCustomImageLoadEvents` (CDC) for native addon loading
- Process command-line analysis for gateway entry points

### Legitimate vs Malicious Differentiation

| Indicator | Legitimate OpenClaw | ClawHavoc / Malicious |
|-----------|--------------------|-----------------------|
| npm package source | `registry.npmjs.org` | Sideloaded `openclaw-agent.zip` |
| Skills directory | **Does NOT exist** | `.openclaw\skills\` present |
| Network destinations | `api.telegram.org`, `chatgpt.com`, `auth.openai.com` | `clawhub.com`, `moltbook.com` |
| Persistence | Scheduled Task + Startup folder (user-configured) | May add additional persistence |
| Process integrity | `node.exe` with signed Node.js binary | May use renamed/unsigned binaries |

---

## Related

- **`queries/endpoint/local_ai_agent_discovery.md`** — fleet-wide local AI agent inventory and posture via `AgentsInfo` (`Platform == "LocalAgents"`) and the exposure graph. Start there to see whether OpenClaw (or another self-hosted runtime) is present, then use this file's process/network/file/CDC queries for the deep dive. Query 6 (Recently Removed / Uninstalled Local Agents) pairs directly with this hunt.
- **`.github/skills/ai-agent-posture/SKILL.md`** — posture assessment for *cloud* agents (Copilot Studio, Agent Builder, Foundry) via the same `AgentsInfo` table.
