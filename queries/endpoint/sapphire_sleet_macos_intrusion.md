# Sapphire Sleet macOS Intrusion — From Lure to Compromise

**Created:** 2026-04-16  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceEvents, AlertInfo, AlertEvidence  
**Keywords:** Sapphire Sleet, BlueNoroff, North Korea, DPRK, macOS, AppleScript, osascript, Script Editor, curl, credential harvester, systemupdate.app, softwareupdate.app, com.apple.cli, services, icloudz, com.google.chromes.updaters, com.google.webkit.service.plist, TCC bypass, TCC.db, LaunchDaemon, caffeinate, Telegram Bot API, cryptocurrency, Ledger, Exodus, keychain, NSCreateObjectFileImageFromMemory, reflective code loading, dscl, mac-cur1, mac-cur2, mac-cur3, mac-cur4, mac-cur5, Zoom SDK Update, social engineering, fake recruiter, NukeSped, FlowOffset, PassStealer  
**MITRE:** T1566.003, T1204.002, T1059.002, T1059.004, T1105, T1056.002, T1539, T1555.001, T1555, T1547.011, T1543.004, T1548, T1553.001, T1562, T1620, T1005, T1560.001, T1567, T1041, T1071.001, T1132, T1082, T1057, TA0001, TA0002, TA0003, TA0004, TA0005, TA0006, TA0007, TA0009, TA0010, TA0011  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Microsoft Security Blog — Dissecting Sapphire Sleet's macOS intrusion from lure to compromise](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)

---

## Threat Overview

[Microsoft Threat Intelligence reported](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/) a macOS-focused cyber campaign by the North Korean state actor **Sapphire Sleet** (also tracked as UNC1069, STARDUST CHOLLIMA, Alluring Pisces, BlueNoroff, CageyChameleon, CryptoCore). Active since at least March 2020, Sapphire Sleet primarily targets the finance sector — cryptocurrency, venture capital, and blockchain organizations — with the goal of stealing cryptocurrency wallets and generating revenue.

This campaign uses social engineering rather than software vulnerabilities: the actor creates fake recruiter profiles on social media, schedules "technical interviews", and directs targets to download a malicious `.scpt` file disguised as a Zoom SDK update.

**Attack Chain:**
1. **Initial Access (T1566.003, T1204.002):** Fake recruiter → "Zoom SDK Update.scpt" → opens in Script Editor (trusted Apple app)
2. **Execution (T1059.002, T1105):** Cascading curl-to-osascript chain (`mac-cur1` through `mac-cur5`) fetching staged payloads
3. **Reconnaissance (T1082, T1057):** `sw_vers`, `sysctl hw.model`, `ps aux`, `whoami` — system/process enumeration
4. **Credential Access (T1056.002, T1555.001):** Fake password dialog (`systemupdate.app`) → `dscl -authonly` validation → exfil via Telegram Bot API
5. **Persistence (T1543.004, T1547.011):** `services` backdoor → `icloudz` → `com.google.chromes.updaters` → LaunchDaemon (`com.google.webkit.service.plist`)
6. **Defense Evasion (T1548, T1562):** TCC database manipulation (rename `com.apple.TCC` folder via Finder, inject `sqlite3` entry for osascript AppleEvents)
7. **Collection & Exfiltration (T1005, T1560.001, T1567):** 7 data categories — Telegram sessions, browser data + keychain, Ledger wallet, Exodus wallet, SSH keys + shell history, Apple Notes, system logs — uploaded via `nohup curl` to port 8443

**IOCs:**
| Indicator | Type | Description |
|-----------|------|-------------|
| `uw04webzoom[.]us` | Domain | Payload staging (port 443) |
| `uw05webzoom[.]us` | Domain | Payload staging |
| `uw03webzoom[.]us` | Domain | Payload staging |
| `ur01webzoom[.]us` | Domain | Payload staging |
| `uv01webzoom[.]us` | Domain | Payload staging |
| `uv03webzoom[.]us` | Domain | Payload staging |
| `uv04webzoom[.]us` | Domain | Payload staging |
| `ux06webzoom[.]us` | Domain | Payload staging |
| `check02id[.]com` | Domain | `com.google.chromes.updaters` C2 (port 5202) |
| `188.227.196[.]252` | IP | Payload staging |
| `83.136.208[.]246` | IP | `com.apple.cli` C2 (port 6783) |
| `83.136.209[.]22` | IP | `services` backdoor download (port 8444) |
| `83.136.208[.]48` | IP | `services` C2 (port 443) |
| `83.136.210[.]180` | IP | `check02id[.]com` resolution (port 5202) |
| `104.145.210[.]107` | IP | Exfiltration (port 6783) |
| `mac-cur1` through `mac-cur5` | User-Agent | curl campaign tracking identifiers |
| `fwyan48umt1vimwqcqvhdd9u72a7qysi` | Token | Upload authorization token |
| `82cf5d92-87b5-4144-9a4e-6b58b714d599` | UUID | Machine identifier (`mid` header) |

**Malicious File Hashes (SHA-256):**
| File | SHA-256 |
|------|---------|
| `Zoom SDK Update.scpt` | `2075fd1a1362d188290910a8c55cf30c11ed5955c04af410c481410f538da419` |
| `com.apple.cli` | `05e1761b535537287e7b72d103a29c4453742725600f59a34a4831eafc0b8e53` |
| `services` / `icloudz` | `5fbbca2d72840feb86b6ef8a1abb4fe2f225d84228a714391673be2719c73ac7` |
| `com.google.chromes.updaters` | `5e581f22f56883ee13358f73fabab00fcf9313a053210eb12ac18e66098346e5` |
| `com.google.webkit.service.plist` | `95e893e7cdde19d7d16ff5a5074d0b369abd31c1a30962656133caa8153e8d63` |
| `systemupdate.app` (credential harvester) | `8fd5b8db10458ace7e4ed335eb0c66527e1928ad87a3c688595804f72b205e8c` |
| `softwareupdate.app` (decoy) | `a05400000843fbad6b28d2b76fc201c3d415a72d88d8dc548fafd8bae073c640` |

**Defender AV Detection Names:**
| Detection | Component |
|-----------|-----------|
| `Trojan:MacOS/NukeSped.D` | Backdoors (`com.apple.cli`, `services`, `icloudz`, `com.google.chromes.updaters`) |
| `Trojan:MacOS/PassStealer.D` | Credential harvester (`systemupdate.app`) |
| `Trojan:MacOS/SuspMalScript.C` | Malicious AppleScript lure |
| `Trojan:MacOS/SuspInfostealExec.C` | Data collection and exfiltration |
| `Trojan:MacOS/FlowOffset.A!dha` | Initial `.scpt` lure |
| `Backdoor:MacOS/FlowOffset.B!dha` | Backdoor components |
| `Backdoor:MacOS/FlowOffset.C!dha` | Backdoor components |
| `Trojan:MacOS/FlowOffset.D!dha` | Credential harvester |
| `Trojan:MacOS/FlowOffset.E!dha` | Decoy app |

**Reference:** See [npm_supply_chain_attack.md](npm_supply_chain_attack.md) for the related Sapphire Sleet axios npm supply chain compromise campaign (attributed to the same actor).

---

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Suspicious osascript Execution with curl Piping](#query-1-suspicious-osascript-execution-with-curl-piping) | Investigation | `DeviceProcessEvents` |
| 2 | [Campaign curl User-Agent Strings (mac-cur1 through mac-cur5)](#query-2-campaign-curl-user-agent-strings-mac-cur1-through-mac-cur5) | Investigation | `DeviceProcessEvents` |
| 3 | [C2 Domain and IP Connectivity](#query-3-c2-domain-and-ip-connectivity) | Investigation | `DeviceNetworkEvents` |
| 4 | [TCC Database Manipulation](#query-4-tcc-database-manipulation) | Investigation | `DeviceFileEvents` |
| 5 | [Suspicious LaunchDaemon Masquerading as Legitimate Services](#query-5-suspicious-launchdaemon-masquerading-as-legitimate-services) | Investigation | `DeviceFileEvents` |
| 6 | [Malicious Binary Execution from Sapphire Sleet Paths](#query-6-malicious-binary-execution-from-sapphire-sleet-paths) | Investigation | `DeviceProcessEvents` |
| 7 | [Credential Harvesting via dscl Authentication Check](#query-7-credential-harvesting-via-dscl-authentication-check) | Investigation | `DeviceProcessEvents` |
| 8 | [Telegram Bot API Credential Exfiltration](#query-8-telegram-bot-api-credential-exfiltration) | Investigation | `DeviceNetworkEvents` |
| 9 | [Reflective Code Loading (NSCreateObjectFileImageFromMemory)](#query-9-reflective-code-loading-nscreateobjectfileimagefrommemory) | Investigation | `DeviceEvents` |
| 10 | [Caffeinate Anti-Sleep Pattern from Backdoor Processes](#query-10-caffeinate-anti-sleep-pattern-from-backdoor-processes) | Investigation | `DeviceProcessEvents` |
| 11 | [Malicious File Hash IOC Hunt](#query-11-malicious-file-hash-ioc-hunt) | Investigation | `DeviceFileEvents` + multi |
| 12 | [Data Staging and Exfiltration — ZIP Archive + curl Upload](#query-12-data-staging-and-exfiltration--zip-archive--curl-upload) | Investigation | `DeviceProcessEvents` |
| 13 | [Script Editor Launching Suspicious Child Processes](#query-13-script-editor-launching-suspicious-child-processes) | Investigation | `DeviceProcessEvents` |
| 14 | [Defender AV Detections for Sapphire Sleet Malware Families](#query-14-defender-av-detections-for-sapphire-sleet-malware-families) | Detection | `AlertInfo` |


## Query 1: Suspicious osascript Execution with curl Piping

Detect curl commands piping output directly to `osascript` — the core technique in Sapphire Sleet's cascading payload delivery chain. The `.scpt` lure uses `do shell script` to invoke `curl` → pipe to `osascript` → each stage fetches and executes the next.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Sapphire Sleet: osascript curl pipe execution on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "Immediately isolate the device. Check for persistence artifacts (LaunchDaemons, hidden binaries in ~/Library). Investigate credential exposure and rotate passwords."
responseActions: "Isolate device. Kill osascript and curl processes. Remove LaunchDaemon plists. Revoke all credentials. Check cryptocurrency wallets for unauthorized access."
adaptation_notes: "Uses DeviceProcessEvents (AH-native). Timestamp column. FileName and InitiatingProcessFileName are both checked for osascript since the process tree can vary."
-->
```kql
// Sapphire Sleet: Detect curl piping output to osascript
// This is the primary payload delivery mechanism — cascading curl-to-osascript chains
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName == "osascript" or InitiatingProcessFileName == "osascript"
| where ProcessCommandLine has "curl"
    and ProcessCommandLine has_any ("osascript", "| sh", "| bash")
| project Timestamp, DeviceId, DeviceName, AccountName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FolderPath, SHA256
| order by Timestamp desc
```

**Tested:** 0 results in 90d — no macOS devices onboarded in test environment. Schema validated. Query targets the exact execution pattern: `curl <url> | osascript` or child processes of osascript invoking curl.

**Tuning:**
- Broader: Remove `has_any ("osascript", "| sh", "| bash")` to catch any curl activity from osascript
- Narrower: Add `| where ProcessCommandLine has_any ("/version/", "/status/", "/fix/mac/")` for exact Sapphire Sleet URL paths

---

## Query 2: Campaign curl User-Agent Strings (mac-cur1 through mac-cur5)

Detect curl commands using the campaign-specific user-agent tracking identifiers. Each stage uses a distinct UA string (`mac-cur1` through `mac-cur5`, `audio`, `beacon`) to track payload delivery.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Sapphire Sleet: Campaign curl UA '{{ProcessCommandLine}}' on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "High-confidence IOC match. Immediately isolate the device. The curl user-agent is a unique campaign identifier — any match confirms active compromise."
responseActions: "Isolate device. Collect forensic image. Identify all downloaded payloads. Revoke all user credentials on the device."
adaptation_notes: "Uses DeviceProcessEvents (AH-native). The -A flag sets curl user-agent. These specific strings are unique to this campaign."
-->
```kql
// Sapphire Sleet: Campaign-specific curl user-agent strings
// mac-cur1: orchestrator, mac-cur2: credential harvester trigger,
// mac-cur3: TCC bypass + exfil, mac-cur4: systemupdate.app download,
// mac-cur5: softwareupdate.app (decoy), audio/beacon: C2 beaconing
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName == "curl" or ProcessCommandLine has "curl"
| where ProcessCommandLine has_any (
    "mac-cur1", "mac-cur2", "mac-cur3", "mac-cur4", "mac-cur5",
    "-A audio", "-A beacon")
| project Timestamp, DeviceId, DeviceName, AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FolderPath, SHA256
| order by Timestamp desc
```

**Tested:** 0 results in 90d — expected (IOC-specific). Schema validated.

**Tuning:**
- These user-agent strings are highly specific — any match is near-certain compromise
- Actor may evolve UA strings; for broader detection use Query 1 (curl→osascript pattern)

---

## Query 3: C2 Domain and IP Connectivity

Hunt for network connections to Sapphire Sleet C2 infrastructure — 9 domains and 6 IP addresses used for payload staging, backdoor C2, and data exfiltration.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Sapphire Sleet C2: {{DeviceName}} → {{RemoteUrl}}{{RemoteIP}}:{{RemotePort}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "Confirmed C2 connectivity. Immediately isolate the device. Check for active backdoor processes and data exfiltration. Assess blast radius — same user on other devices."
responseActions: "Network-isolate device via MDE. Block C2 IPs/domains at firewall/proxy. Kill backdoor processes. Full forensic investigation."
adaptation_notes: "Uses DeviceNetworkEvents (AH-native). Timestamp column. RemoteUrl covers domain lookups; RemoteIP covers direct IP connections."
-->
```kql
// Sapphire Sleet: C2 domain and IP connectivity
let lookback = 30d;
let c2_domains = dynamic([
    "uw04webzoom.us", "uw05webzoom.us", "uw03webzoom.us",
    "ur01webzoom.us", "uv01webzoom.us", "uv03webzoom.us",
    "uv04webzoom.us", "ux06webzoom.us", "check02id.com"]);
let c2_ips = dynamic([
    "188.227.196.252", "83.136.208.246", "83.136.209.22",
    "83.136.208.48", "83.136.210.180", "104.145.210.107"]);
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has_any (c2_domains) or RemoteIP in (c2_ips)
| project Timestamp, DeviceId, DeviceName,
    RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessSHA256
| order by Timestamp desc
```

**Tested:** 0 results in 90d — environment clean. Schema validated.

**Tuning:**
- The `*webzoom.us` domains follow a naming pattern; consider broader hunt: `| where RemoteUrl matches regex @"u[a-z]\d{2}webzoom\.us"`
- Port-specific filtering: `| where RemotePort in (443, 5202, 6783, 8443, 8444)` for known campaign ports

---

## Query 4: TCC Database Manipulation

Detect processes that copy, modify, or overwrite the macOS TCC database — a key defense evasion technique. Sapphire Sleet uses Finder (which has Full Disk Access) to rename the `com.apple.TCC` folder, copies `TCC.db` to a staging location, injects an `sqlite3` entry granting osascript AppleEvents permissions, then restores the modified database.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "TCC Database Manipulation: {{ActionType}} on {{DeviceName}} by {{InitiatingProcessFileName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "TCC manipulation bypasses macOS consent controls. Investigate what permissions were granted. Check for osascript AppleEvents access and subsequent Finder-based file operations."
responseActions: "Restore TCC.db from backup. Revoke unauthorized permissions. Investigate data accessed post-bypass."
adaptation_notes: "Uses DeviceFileEvents (AH-native). FolderPath filter catches both the original and staged locations. Legitimate TCC.db modifications are rare — any match warrants investigation."
-->
```kql
// Sapphire Sleet: TCC database manipulation detection
// Monitors for file operations on TCC.db — the macOS consent/permission database
// Legitimate modifications are extremely rare outside of app installation
let lookback = 30d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where FolderPath has "com.apple.TCC" and FileName == "TCC.db"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| project Timestamp, DeviceId, DeviceName,
    ActionType, FolderPath, FileName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessSHA256, SHA256
| order by Timestamp desc
```

**Tested:** 0 results in 90d — no macOS devices. Schema validated. Legitimate TCC.db changes are rare; high signal-to-noise.

**Tuning:**
- Add sqlite3 process correlation: `| where InitiatingProcessFileName == "sqlite3"` for highest confidence
- Broader: Include `ActionType == "FileCopied"` if available in environment

---

## Query 5: Suspicious LaunchDaemon Masquerading as Legitimate Services

Detect new LaunchDaemon plist files created in `/Library/LaunchDaemons/` that mimic Google or Apple naming conventions. Sapphire Sleet installs `com.google.webkit.service.plist` for persistence — naming deliberately mimics legitimate vendor services.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Suspicious LaunchDaemon: {{FileName}} created on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "Verify the plist file is from a legitimate vendor (Apple or Google). Check the ProgramArguments in the plist for the binary path. Cross-reference with known Sapphire Sleet hashes."
responseActions: "Remove the malicious plist. Unload with launchctl. Kill the associated process. Check for additional persistence mechanisms."
adaptation_notes: "Uses DeviceFileEvents (AH-native). Some legitimate Google/Apple plists will appear — baseline your environment first. Focus on unexpected new creations."
-->
```kql
// Sapphire Sleet: LaunchDaemon persistence masquerading as legitimate services
// com.google.webkit.service.plist is the specific IOC — but detect the broader pattern
let lookback = 30d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where FolderPath startswith "/Library/LaunchDaemons/"
| where FileName startswith "com.google." or FileName startswith "com.apple."
| where ActionType == "FileCreated"
| project Timestamp, DeviceId, DeviceName,
    FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessSHA256
| order by Timestamp desc
```

**Tested:** 0 results in 90d — no macOS devices. Schema validated.

**Tuning:**
- Exact IOC match: `| where FileName == "com.google.webkit.service.plist"`
- Broader: Remove prefix filter to catch ANY new LaunchDaemon creation, then baseline
- Include `~/Library/LaunchAgents/` for user-level persistence: `| where FolderPath has_any ("/Library/LaunchDaemons/", "/Library/LaunchAgents/")`

---

## Query 6: Malicious Binary Execution from Sapphire Sleet Paths

Hunt for process execution from the specific file paths used by Sapphire Sleet's malware components: `services`, `icloudz`, `com.google.chromes.updaters`, `com.apple.cli`, and the credential harvester/decoy apps in `/private/tmp/`.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Sapphire Sleet Binary: {{FileName}} at {{FolderPath}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "Confirmed malware execution. Immediately isolate device. Determine which attack stage is active. Check for credential theft and data exfiltration."
responseActions: "Isolate device. Kill all malicious processes. Remove binaries and LaunchDaemon plists. Full credential rotation. Forensic imaging."
adaptation_notes: "Uses DeviceProcessEvents (AH-native). FolderPath has_any matches partial paths — will catch regardless of username in path. High-confidence detection."
-->
```kql
// Sapphire Sleet: Binary execution from known malicious paths
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FolderPath has_any (
    "Library/Services/services",
    "Application Support/iCloud/icloudz",
    "Library/Google/com.google.chromes.updaters",
    "/private/tmp/SystemUpdate/",
    "/private/tmp/SoftwareUpdate/",
    "com.apple.cli")
| project Timestamp, DeviceId, DeviceName,
    FileName, FolderPath, ProcessCommandLine,
    AccountName, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Tested:** 0 results in 90d — expected. Schema validated.

**Tuning:**
- Add hash correlation: `| where SHA256 in (malicious_hashes)` using the IOC table above for double-confirmation
- Broader: Include `"Application Support/Authorization/auth.db"` — the services backdoor writes its install path here

---

## Query 7: Credential Harvesting via dscl Authentication Check

Detect `dscl -authonly` commands used by the fake password dialog (`systemupdate.app`) to validate stolen credentials against the local macOS directory before exfiltrating them. Legitimate use of `dscl -authonly` is extremely rare.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "macOS Credential Validation: dscl -authonly on {{DeviceName}} by {{InitiatingProcessFileName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
  - type: "user"
    identifier: "accountName"
recommendedActions: "Credentials have likely been stolen and validated. Immediately rotate the user's password. Check for Telegram Bot API exfiltration (Query 8). Revoke all sessions."
responseActions: "Reset user password. Revoke all tokens/sessions. Check for data exfiltration. Notify the user about potential credential compromise."
adaptation_notes: "Uses DeviceProcessEvents (AH-native). dscl -authonly is the macOS equivalent of a password validation API call. Extremely rare in legitimate usage — near-zero false positive rate."
-->
```kql
// Sapphire Sleet: dscl -authonly credential validation
// The fake systemupdate.app validates stolen passwords before exfiltrating
// Legitimate use of dscl -authonly is extremely rare
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName == "dscl" or ProcessCommandLine has "dscl"
| where ProcessCommandLine has "-authonly"
| project Timestamp, DeviceId, DeviceName,
    AccountName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

**Tested:** 0 results in 90d. Schema validated. Near-zero FP rate — any match is highly suspicious.

---

## Query 8: Telegram Bot API Credential Exfiltration

Detect network connections to Telegram Bot API endpoints. Sapphire Sleet exfiltrates validated credentials directly to a Telegram bot — the password arrives as a message via the Telegram Bot API (`api.telegram.org/bot<token>/sendMessage`).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Exfiltration"
title: "Telegram Bot API Exfiltration: {{DeviceName}} → {{RemoteUrl}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "Data has likely been exfiltrated to a Telegram bot. Determine what data was sent (credentials, files). Check process tree for the initiating malware component."
responseActions: "Block api.telegram.org at network level if not business-critical. Isolate device. Determine exfiltrated data. Rotate all exposed credentials."
adaptation_notes: "Uses DeviceNetworkEvents (AH-native). Telegram Bot API is used by multiple threat actors — correlate with other Sapphire Sleet indicators for attribution. Some orgs use Telegram legitimately; baseline first."
-->
```kql
// Sapphire Sleet: Telegram Bot API credential exfiltration
// Stolen passwords are sent via Telegram Bot API sendMessage
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has "api.telegram.org" and RemoteUrl has "/bot"
| project Timestamp, DeviceId, DeviceName,
    RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessFolderPath, InitiatingProcessSHA256
| order by Timestamp desc
```

**Tested:** 0 results in 90d. Schema validated.

**Tuning:**
- If Telegram is used legitimately: correlate with initiating process — legitimate apps use Telegram Desktop, not `curl` or custom binaries
- Broader: `| where RemoteUrl has "api.telegram.org"` (drops `/bot` filter) to catch all Telegram API usage
- Cross-correlate: Join with Query 7 results to identify devices where credential theft AND exfil both occurred

---

## Query 9: Reflective Code Loading (NSCreateObjectFileImageFromMemory)

Hunt for evidence of reflective Mach-O loading — the technique used by the `icloudz` backdoor to load additional payloads from C2 directly into memory without writing them to disk.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "DeviceEvents ActionType for NSCreateObjectFileImageFromMemory may not be consistently logged across all MDE versions. This is an investigative query — use alongside Query 6 for path-based detection."
-->
```kql
// Sapphire Sleet: Reflective code loading via NSCreateObjectFileImageFromMemory
// The icloudz backdoor uses this macOS API to load C2 payloads in memory
let lookback = 30d;
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType has "NSCreateObjectFileImageFromMemory"
    or AdditionalFields has "NSCreateObjectFileImageFromMemory"
| project Timestamp, DeviceId, DeviceName,
    ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

**Tested:** 0 results in 90d. Schema validated. Detection coverage for this API call depends on MDE sensor version.

---

## Query 10: Caffeinate Anti-Sleep Pattern from Backdoor Processes

Detect `caffeinate` process stop-and-restart patterns used by `services` and `icloudz` backdoors. Both backdoors kill existing `caffeinate` processes and relaunch with `nohup` to prevent the system from sleeping during exfiltration and C2 operations.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigative/behavioral query — caffeinate usage is legitimate in many contexts. Requires correlation with known Sapphire Sleet process names (icloudz, services, chromes.updaters) in the initiating process chain. Not suitable for standalone CD without high FP risk."
-->
```kql
// Sapphire Sleet: caffeinate anti-sleep from backdoor processes
// Backdoors kill then restart caffeinate with nohup to prevent sleep
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has "caffeinate"
| where InitiatingProcessCommandLine has_any (
    "icloudz", "services", "chromes.updaters", "zsh -i")
| project Timestamp, DeviceId, DeviceName,
    ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
| order by Timestamp desc
```

**Tested:** 0 results in 90d. Schema validated.

**Tuning:**
- Broader: Remove `InitiatingProcessCommandLine` filter to see all caffeinate usage (baseline first)
- Higher confidence: Combine with `| where InitiatingProcessFolderPath has_any ("iCloud/icloudz", "Services/services")`

---

## Query 11: Malicious File Hash IOC Hunt

Search for the specific malicious file hashes associated with this Sapphire Sleet campaign across file events, process events, and image load events.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table search using the search operator — not a single-table query suitable for CD. Use for periodic hunting sweeps. Hash list should be updated as new variants are discovered."
-->
```kql
// Sapphire Sleet: SHA-256 hash IOC hunt across file, process, and image load events
let lookback = 30d;
let malicious_hashes = dynamic([
    "2075fd1a1362d188290910a8c55cf30c11ed5955c04af410c481410f538da419",
    "05e1761b535537287e7b72d103a29c4453742725600f59a34a4831eafc0b8e53",
    "5fbbca2d72840feb86b6ef8a1abb4fe2f225d84228a714391673be2719c73ac7",
    "5e581f22f56883ee13358f73fabab00fcf9313a053210eb12ac18e66098346e5",
    "95e893e7cdde19d7d16ff5a5074d0b369abd31c1a30962656133caa8153e8d63",
    "8fd5b8db10458ace7e4ed335eb0c66527e1928ad87a3c688595804f72b205e8c",
    "a05400000843fbad6b28d2b76fc201c3d415a72d88d8dc548fafd8bae073c640"
]);
search in (DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents)
Timestamp > ago(lookback)
and (SHA256 in (malicious_hashes) or InitiatingProcessSHA256 in (malicious_hashes))
| project Timestamp, DeviceName, FileName, FolderPath,
    SHA256, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Tested:** 0 results in 90d — environment clean. Schema validated.

---

## Query 12: Data Staging and Exfiltration — ZIP Archive + curl Upload

Detect the staging-and-exfiltration pattern: ZIP archive creation in `/tmp/` directories followed by curl uploads with campaign-specific naming conventions. Sapphire Sleet creates ZIP files named `tapp_<user>.zip`, `ext_<user>.zip`, `ldg_<user>.zip`, etc. and uploads to port 8443.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Exfiltration"
title: "Sapphire Sleet Data Staging: {{ProcessCommandLine}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "Active data exfiltration detected. Immediately isolate device and block outbound connections to port 8443. Determine which data categories were staged (tapp_=Telegram, ext_=browser, ldg_=Ledger, exds_=Exodus, hs_=SSH, nt_=Notes)."
responseActions: "Isolate device. Block exfil IPs. Assess data exposure — browser credentials, crypto wallets, SSH keys may be compromised. Incident response for all affected credential stores."
adaptation_notes: "Uses DeviceProcessEvents (AH-native). The zip+curl pattern with these specific prefixes is campaign-specific. Legitimate zip operations in /tmp/ are common — the curl upload component provides specificity."
-->
```kql
// Sapphire Sleet: Data staging (zip in /tmp/) and exfiltration (curl upload)
// ZIP naming: tapp_=Telegram, ext_=browser+keychain, ldg_=Ledger,
// exds_=Exodus, hs_=SSH+history, nt_=Apple Notes, lg_=system log
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where (ProcessCommandLine has "zip" and ProcessCommandLine has "/tmp/")
    or (ProcessCommandLine has "curl"
        and ProcessCommandLine has_any (
            "tapp_", "ext_", "ldg_", "exds_", "hs_", "nt_", "lg_"))
| project Timestamp, DeviceId, DeviceName,
    ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName, FolderPath
| order by Timestamp desc
```

**Tested:** 0 results in 90d. Schema validated.

**Tuning:**
- Higher confidence: Add `| where ProcessCommandLine has "8443"` (the exfiltration port)
- Broader staging: `| where ProcessCommandLine has "nohup" and ProcessCommandLine has "curl" and ProcessCommandLine has "-F"` (nohup + curl file upload pattern)

---

## Query 13: Script Editor Launching Suspicious Child Processes

Detect Script Editor (the default macOS handler for `.scpt` files) spawning curl, osascript, or shell commands — the initial execution vector where the lure file triggers the attack chain.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Script Editor spawned {{FileName}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceId"
recommendedActions: "Script Editor launching shell/network tools is abnormal. Check if user was directed to download a .scpt file. Investigate the full process tree for cascading payload delivery."
responseActions: "Terminate Script Editor and child processes. Quarantine the .scpt file. Check for downloaded payloads in /private/tmp/ and ~/Library/."
adaptation_notes: "Uses DeviceProcessEvents (AH-native). Script Editor is the default macOS handler for .scpt files. Some developers use Script Editor legitimately — correlate with curl/network activity for higher confidence."
-->
```kql
// Sapphire Sleet: Script Editor launching suspicious child processes
// The Zoom SDK Update.scpt lure opens in Script Editor and spawns the attack chain
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName == "Script Editor"
    or InitiatingProcessCommandLine has "Script Editor"
| where FileName has_any ("curl", "osascript", "sh", "bash", "zsh")
| project Timestamp, DeviceId, DeviceName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName, FolderPath
| order by Timestamp desc
```

**Tested:** 0 results in 90d. Schema validated.

---

## Query 14: Defender AV Detections for Sapphire Sleet Malware Families

Search for Microsoft Defender Antivirus alerts matching the specific malware family names associated with this campaign. Joins with AlertEvidence for enriched device context.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Uses AlertInfo + AlertEvidence join. Not a single-table CD-compatible query. Use for monitoring and retrospective analysis. Defender AV detection names may evolve."
-->
```kql
// Sapphire Sleet: Defender AV detection names for this campaign
let lookback = 30d;
let SapphireSleet_threats = dynamic([
    "Trojan:MacOS/NukeSped.D",
    "Trojan:MacOS/PassStealer.D",
    "Trojan:MacOS/SuspMalScript.C",
    "Trojan:MacOS/SuspInfostealExec.C",
    "Trojan:MacOS/FlowOffset.A!dha",
    "Backdoor:MacOS/FlowOffset.B!dha",
    "Backdoor:MacOS/FlowOffset.C!dha",
    "Trojan:MacOS/FlowOffset.D!dha",
    "Trojan:MacOS/FlowOffset.E!dha"
]);
AlertInfo
| where Timestamp > ago(lookback)
| where Title has_any ("Sapphire Sleet", "NukeSped", "FlowOffset",
    "PassStealer", "SuspMalScript", "SuspInfostealExec")
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | where EntityType == "Machine"
    | project AlertId, DeviceName, DeviceId
) on AlertId
| project Timestamp, AlertId, Title, Severity, Category,
    AttackTechniques, DeviceName, DeviceId
| order by Timestamp desc
```

**Tested:** 0 results in 90d — environment clean. Schema validated.

---

## Implementation Priority

| # | Query | Confidence | CD | Priority |
|---|-------|-----------|-----|----------|
| 1 | osascript + curl Piping | 🔴 High | ✅ 1H | **P1 — Deploy immediately** |
| 2 | Campaign curl User-Agents | 🔴 High (IOC) | ✅ 1H | **P1 — Deploy immediately** |
| 3 | C2 Domain/IP Connectivity | 🔴 High (IOC) | ✅ 1H | **P1 — Deploy immediately** |
| 7 | dscl -authonly Credential Check | 🔴 High | ✅ 1H | **P1 — Deploy immediately** |
| 8 | Telegram Bot API Exfil | 🟠 Medium-High | ✅ 1H | **P1 — Deploy immediately** |
| 4 | TCC Database Manipulation | 🔴 High | ✅ 1H | **P2 — Deploy within 24h** |
| 5 | LaunchDaemon Masquerading | 🟠 Medium | ✅ 1H | **P2 — Deploy within 24h** |
| 6 | Malicious Path Execution | 🔴 High (IOC) | ✅ 1H | **P2 — Deploy within 24h** |
| 12 | Data Staging + Exfil Pattern | 🟠 Medium-High | ✅ 1H | **P2 — Deploy within 24h** |
| 13 | Script Editor → Child Processes | 🟠 Medium | ✅ 1H | **P2 — Deploy within 24h** |
| 11 | File Hash IOC Hunt | 🔴 High (IOC) | ❌ | **P2 — Hunt weekly** |
| 14 | Defender AV Detections | 🟢 Monitoring | ❌ | **P3 — Monitor continuously** |
| 9 | Reflective Code Loading | 🟡 Low-Medium | ❌ | **P3 — Hunt weekly** |
| 10 | Caffeinate Anti-Sleep | 🟡 Low | ❌ | **P3 — Hunt weekly** |
