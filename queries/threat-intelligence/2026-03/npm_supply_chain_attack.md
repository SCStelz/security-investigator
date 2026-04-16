# npm Supply Chain Attack Hunting — axios Compromise

**Created:** 2026-03-31  
**Platform:** Both  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceEvents, DeviceRegistryEvents, DeviceCustomFileEvents, DeviceCustomScriptEvents, ASimDnsActivityLogs, DeviceTvmSoftwareInventory, CloudProcessEvents  
**Keywords:** axios, npm, npm install, supply chain, plain-crypto-js, postinstall, setup.js, sfrclak, wt.exe, node.exe, node_modules, RAT, credential stealer, C2 beacon, PowerShell masquerade, VBScript dropper, cross-platform RAT, yarn, pnpm, npx, package-lock.json, yarn.lock, pnpm-lock.yaml, Sapphire Sleet, BlueNoroff, North Korea, DPRK  
**MITRE:** T1195.002, T1059.007, T1059.001, T1059.005, T1027, T1036.005, T1547.001, T1041, T1071.001, T1082, T1005, T1552.001, T1070.004  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This hunting campaign targets TTPs from the **axios npm supply chain compromise** disclosed March 31, 2026. **Microsoft Threat Intelligence has attributed this attack to Sapphire Sleet**, a North Korean (DPRK) state actor (also tracked as UNC1069, STARDUST CHOLLIMA, Alluring Pisces, BlueNoroff, CageyChameleon, CryptoCore). Sapphire Sleet focuses primarily on the finance sector — cryptocurrency, venture capital, and blockchain organizations — with the primary motivation of stealing cryptocurrency wallets to generate revenue.

The attacker compromised the npm maintainer account (`jasonsaayman`) of the widely-used `axios` HTTP client package (~300M weekly downloads) and published backdoored versions that delivered a cross-platform RAT via a malicious transitive dependency.

**Key intelligence sources:**
- **[Microsoft Threat Intelligence — Mitigating the Axios npm supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)** (attribution, MDE detections, mitigation guidance)
- **[Joe Desimone / Elastic Security — Technical Analysis Gist](https://gist.github.com/joe-desimone/36061dabd2bc2513705e0d083a9673e7)**
- **[Huntress — Supply-Chain Compromise of axios npm Package](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package)**
- **[Snyk — Axios npm Package Compromised: Supply Chain Attack Delivers Cross-Platform RAT](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)**

### Threat Summary

| Aspect | Detail |
|--------|--------|
| **Target Package** | `axios` — promise-based HTTP client, ~300M weekly npm downloads |
| **Compromised Maintainer** | `jasonsaayman` npm account (email changed from `jasonsaayman@gmail.com` → `ifstap@proton[.]me`) |
| **Attribution** | **Sapphire Sleet** (North Korea) — Microsoft Threat Intelligence confirmed. Also tracked as UNC1069, STARDUST CHOLLIMA, Alluring Pisces, BlueNoroff, CageyChameleon, CryptoCore |
| **Attack Method** | Published backdoored versions via npm CLI using compromised long-lived access token, bypassing OIDC Trusted Publishing |
| **Malicious Versions** | `axios@1.14.1` (tagged `latest`), `axios@0.30.4` (tagged `legacy`) |
| **Safe Versions** | `axios@1.14.0` (last legit 1.x — published via GitHub Actions OIDC with SLSA provenance), `axios@0.30.3` (last legit 0.x) |
| **Malicious Dependency** | `plain-crypto-js@4.2.1` — purpose-built payload delivery vehicle (brand-new package, attacker-controlled). Pre-staged clean v4.2.0 published ~18 hours earlier by `nrwise@proton[.]me` to establish publishing history |
| **Delivery Mechanism** | `plain-crypto-js` declares `"postinstall": "node setup.js"` — auto-executes on `npm install` |
| **Payload** | Cross-platform RAT (macOS: compiled C++ Mach-O, Windows: PowerShell RAT, Linux: Python RAT) |
| **C2 Domain** | `sfrclak[.]com:8000` (IP: `142.11.206.73`) — hosted on **Hostwinds** VPS (known Sapphire Sleet infrastructure provider), domain registered via **NameCheap** |
| **Campaign ID** | `6202033` (reversed = `3-30-2026`, date of attack) |
| **Exposure Window** | 2026-03-31 00:21 UTC to ~03:29 UTC (~3 hours) |
| **First Observed Infection** | 89 seconds after publish (macOS endpoint via Huntress EDR) |
| **Huntress Observed Impact** | 135 endpoints across all operating systems contacting C2 during window |
| **Obfuscation** | Two-layer: reversed base64 + XOR cipher (key `OrDeR_7077`, position-dependent index `7*i²%10`) |
| **Anti-Forensics** | `setup.js` self-deletes, swaps malicious `package.json` with clean `package.md` → post-incident inspection shows no `postinstall` hook |
| **Additional Compromised Packages** | `@qqbrowser/openclaw-qbot@0.0.130`, `@shadanai/openclaw` (versions `2026.3.31-1`, `2026.3.31-2`) — ship `plain-crypto-js` directly |

### Platform-Specific Tradecraft

| Platform | Delivery Chain | Persistence | Stage-2 Payload |
|----------|---------------|-------------|-----------------|
| **Windows** | `node setup.js` → VBScript (`%TEMP%\6202033.vbs`) → copies `powershell.exe` to `%PROGRAMDATA%\wt.exe` → curl downloads `6202033.ps1` → executes hidden with `-ep bypass` → self-deletes VBS+PS1 | Registry Run key `HKCU:\...\Run\MicrosoftUpdate` → `%PROGRAMDATA%\system.bat` (Hidden attribute) — re-fetches RAT on every login | Full PowerShell RAT: 60s beacon, 4 commands: `kill`, `peinject` (in-memory .NET assembly), `runscript` (3 modes), `rundir` |
| **macOS** | `node setup.js` → AppleScript via `osascript` → `curl` downloads Mach-O to `/Library/Caches/com.apple.act.mond` → `chmod 770` → `/bin/zsh` background exec | `/Library/Caches/com.apple.act.mond` (mimics Apple daemon naming) | C++ RAT (Universal Binary x86_64+ARM64): 60s beacon, same 4 commands, ad-hoc code-signing via `codesign --force --deep --sign -` |
| **Linux** | `node setup.js` → shell command → `curl` downloads Python script to `/tmp/ld.py` → `nohup python3 /tmp/ld.py &` | **None** (ephemeral — assumes CI/CD runners/containers) | Python 3 RAT (stdlib only): 60s beacon, same 4 commands, drops binaries to `/tmp/.<random6>` |

**Cross-platform RAT shared characteristics:**
- Identical C2 protocol: HTTP POST, Base64-encoded JSON
- Identical User-Agent: `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` (IE8 on WinXP — highly anomalous in 2026)
- POST body prefix mimics npm traffic: `packages.npm.org/product0` (macOS), `product1` (Windows), `product2` (Linux)
- 60-second beacon interval, status signals `Wow` / `Zzz`
- Initial recon: user directories, drive roots, running processes → `FirstInfo` beacon

### Timeline (UTC)

| Time | Event |
|------|-------|
| 2026-02-18T17:19:20Z | `axios@0.30.3` published legitimately by `jasonsaayman@gmail.com` |
| 2026-03-27T19:01:40Z | `axios@1.14.0` published legitimately via GitHub Actions OIDC |
| 2026-03-30 ~06:00 | `plain-crypto-js@4.2.0` published by `nrwise@proton[.]me` (clean pre-staging) |
| 2026-03-30T23:59:12Z | `plain-crypto-js@4.2.1` published — malicious `postinstall` payload introduced |
| 2026-03-31T00:05:41Z | Socket automated detection flags `plain-crypto-js@4.2.1` as malware (~6 min) |
| 2026-03-31T00:21:58Z | `axios@1.14.1` published and tagged `latest` — attack goes live |
| 2026-03-31T00:23:27Z | First Huntress-observed infection (macOS) — 89 seconds after publish |
| 2026-03-31T00:58:05Z | First Huntress-observed Windows infection via `wt.exe` |
| 2026-03-31T01:00:57Z | `axios@0.30.4` published and tagged `legacy` |
| ~2026-03-31T03:29Z | `plain-crypto-js` removed from npm by npm security team |
| ~2026-03-31T03:30Z | Compromised `axios` versions removed from npm |

### MITRE ATT&CK Coverage

| Technique | ID | Relevance |
|-----------|----|-----------|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Compromised npm maintainer account, malicious package publish |
| Command and Scripting Interpreter: JavaScript | T1059.007 | `node setup.js` postinstall dropper execution |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Windows RAT payload via renamed `wt.exe` |
| Command and Scripting Interpreter: Visual Basic | T1059.005 | VBScript launcher (`6202033.vbs`) for Windows stage-2 |
| Obfuscated Files or Information | T1027 | Reversed base64 + XOR cipher obfuscation in `setup.js` |
| Masquerading: Match Legitimate Name or Location | T1036.005 | `powershell.exe` → `wt.exe` (Windows Terminal); macOS binary at `/Library/Caches/com.apple.act.mond` (mimics Apple daemon) |
| Boot or Logon Autostart Execution: Startup Folder / Registry Run Keys | T1547.001 | `MicrosoftUpdate` registry Run key → hidden `system.bat` |
| Exfiltration Over C2 Channel | T1041 | Base64-encoded JSON POST to `sfrclak[.]com:8000` |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP C2 with fake IE8 User-Agent, POST bodies mimicking npm traffic |
| System Information Discovery | T1082 | Hostname, username, OS version, CPU, boot time, process list enumeration |
| Data from Local System | T1005 | Documents, Desktop, OneDrive, AppData, drive root enumeration |
| Unsecured Credentials: Credentials In Files | T1552.001 | npm tokens, SSH keys, API keys, .env files, cloud credentials at risk |
| Indicator Removal: File Deletion | T1070.004 | `setup.js` self-deletion, `package.json` swap with clean stub, VBS/PS1 deletion |

### Microsoft Defender Detection Names

> Source: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/) — Use these for SecurityAlert correlation and confirming MDE coverage.

| Platform | Detection Name | Type |
|----------|---------------|------|
| **Cross-platform** | `Trojan:Script/SuspObfusRAT.A` | Blocking |
| **Cross-platform** | `TrojanDownloader:JS/Crosdomd.A` | Blocking |
| **Cross-platform** | `Trojan:JS/AxioRAT.DA!MTB` | Blocking |
| **Windows** | `TrojanDownloader:PowerShell/Powdow.VUE!MTB` | Blocking |
| **Windows** | `Trojan:Win32/Malgent` | Blocking |
| **Windows** | `TrojanDownloader:PowerShell/Crosdomd.B` | Blocking |
| **Windows** | `TrojanDownloader:PowerShell/Crosdomd.A` | Blocking |
| **Windows** | `TrojanDownloader:BAT/TalonStrike.F!dha` | Blocking |
| **Windows** | `Backdoor:PowerShell/TalonStrike.B!dha` | Blocking |
| **Windows** | `Behavior:Win32/PSMasquerade.A` | Behavioral |
| **macOS** | `Trojan:MacOS/Multiverze!rfn` | Blocking |
| **macOS** | `Backdoor:MacOS/TalonStrike.A!dha` | Blocking |
| **macOS** | `Backdoor:MacOS/Crosdomd.A` | Blocking |
| **macOS** | `Behavior:MacOS/SuspNukeSpedExec.B` | Blocking |
| **macOS** | `Behavior:MacOS/SuspiciousActivityGen.AE` | Blocking |
| **Linux** | `Trojan:Python/TalonStrike.C!dha` | Blocking |
| **Linux** | `Backdoor:Python/TalonStrike.C!dha` | Blocking |
| **Cloud** | Malicious Axios supply chain activity detected (Defender for Cloud) | Alert |
| **Network** | Network protection + SmartScreen block on `sfrclak[.]com` / `142.11.206[.]73` | Blocking |

### IoCs

| Indicator | Type | Notes |
|-----------|------|-------|
| `sfrclak[.]com` | Domain | C2 server (registered via NameCheap) |
| `142.11.206.73` | IP | C2 IP address (Hostwinds VPS — known Sapphire Sleet infrastructure) |
| `142.11.206.72` | IP | Possible additional C2 IP (referenced in Microsoft blog mitigation section — may be typo for `.73` or adjacent infrastructure; monitor both) |
| `hxxp://sfrclak[.]com:8000/6202033` | URL | C2 endpoint (campaign ID `6202033`) |
| `packages[.]npm[.]org/product0` | POST Body | macOS C2 beacon identifier |
| `packages[.]npm[.]org/product1` | POST Body | Windows C2 beacon identifier |
| `packages[.]npm[.]org/product2` | POST Body | Linux C2 beacon identifier |
| `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` | User-Agent | RAT beacon string (all platforms) |
| `ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c` | SHA-256 | Windows `%TEMP%\6202033.ps1` — PowerShell RAT payload variant 1 (per Microsoft blog) |
| `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` | SHA-256 | Windows `%TEMP%\6202033.ps1` — PowerShell RAT payload variant 2 |
| `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd` | SHA-256 | Windows `%PROGRAMDATA%\system.bat` — persistence batch file created by RAT |
| `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` | SHA-256 | macOS Mach-O Universal Binary RAT (`/Library/Caches/com.apple.act.mond`) |
| `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` | SHA-256 | Linux Python RAT script (`/tmp/ld.py`) |
| `2553649f2322049666871cea80a5d0d6adc700ca` | SHA-1 | `axios@1.14.1` npm tarball |
| `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` | SHA-1 | `axios@0.30.4` npm tarball |
| `07d889e2dadce6f3910dcbc253317d28ca61c766` | SHA-1 | `plain-crypto-js@4.2.1` npm tarball |
| `axios@1.14.1` | Package version | Compromised — tagged `latest` |
| `axios@0.30.4` | Package version | Compromised — tagged `legacy` |
| `plain-crypto-js` | Package name | Malicious dependency (any version) — should NEVER exist in legitimate projects |
| `@qqbrowser/openclaw-qbot@0.0.130` | Package version | Additional compromised package shipping `plain-crypto-js` |
| `@shadanai/openclaw` | Package name | Additional compromised package (versions `2026.3.31-1`, `2026.3.31-2`) |
| `/Library/Caches/com.apple.act.mond` | File path | macOS stage-2 RAT binary |
| `%PROGRAMDATA%\wt.exe` | File path | Renamed `powershell.exe` (Windows) |
| `%PROGRAMDATA%\system.bat` | File path | Hidden persistence batch file (Windows) |
| `%TEMP%\6202033.vbs` | File path | VBScript launcher (self-deletes) |
| `%TEMP%\6202033.ps1` | File path | PowerShell payload (self-deletes) |
| `/tmp/ld.py` | File path | Linux Python RAT script |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` | Registry | Persistence Run key → `%PROGRAMDATA%\system.bat` |
| `ifstap@proton[.]me` | Email | Set on compromised `jasonsaayman` npm account |
| `nrwise@proton[.]me` | Email | Attacker-created npm account that published `plain-crypto-js` |

### References

| Source | URL |
|--------|-----|
| **Microsoft Threat Intelligence — Mitigating the Axios npm supply chain compromise** | https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/ |
| Joe Desimone / Elastic Security — Technical Analysis | https://gist.github.com/joe-desimone/36061dabd2bc2513705e0d083a9673e7 |
| Huntress — Supply-Chain Compromise of axios | https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package |
| Snyk — axios Compromised: Supply Chain Attack | https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/ |
| Socket Security — axios Compromised on npm | https://socket.dev/blog/axios-npm-package-compromised |
| StepSecurity — axios Compromised: Malicious Versions Drop RAT | https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan |
| Aikido — axios npm Compromised: Maintainer Hijacked | https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat |
| GitHub Issue #10604 — axios Maintainer Response | https://github.com/axios/axios/issues/10604 |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [— npm install / yarn add / pnpm add Command Detection (DeviceProces...](#query-1--npm-install--yarn-add--pnpm-add-command-detection-deviceprocessevents) | Detection | `DeviceProcessEvents` |
| 2 | [— Compromised axios Version Detection via Process Commands (DeviceP...](#query-2--compromised-axios-version-detection-via-process-commands-deviceprocessevents) | Detection | `DeviceProcessEvents` |
| 3 | [— plain-crypto-js File Artifacts on Disk (DeviceFileEvents)](#query-3--plain-crypto-js-file-artifacts-on-disk-devicefileevents) | Investigation | `DeviceFileEvents` |
| 4 | [— plain-crypto-js via CDC File Events (DeviceCustomFileEvents)](#query-4--plain-crypto-js-via-cdc-file-events-devicecustomfileevents) | Investigation | `DeviceCustomFileEvents` + `DeviceFileEvents` |
| 5 | [— Windows Stage-2 Filesystem IOCs (DeviceFileEvents)](#query-5--windows-stage-2-filesystem-iocs-devicefileevents) | Investigation | `DeviceFileEvents` |
| 6 | [— Windows Stage-2 CDC Detection (DeviceCustomFileEvents)](#query-6--windows-stage-2-cdc-detection-devicecustomfileevents) | Detection | `DeviceCustomFileEvents` |
| 7 | [— C2 Network Connections (DeviceNetworkEvents)](#query-7--c2-network-connections-devicenetworkevents) | Investigation | `DeviceNetworkEvents` |
| 8 | [— C2 DNS Resolution (ASIM DNS)](#query-8--c2-dns-resolution-asim-dns) | Investigation | `ASimDnsActivityLogs` |
| 9 | [— C2 DNS via MDE DNS Events (DeviceEvents)](#query-9--c2-dns-via-mde-dns-events-deviceevents) | Investigation | `DeviceEvents` |
| 10 | [— Stage-2 Payload SHA-256 Hash Match (DeviceFileEvents)](#query-10--stage-2-payload-sha-256-hash-match-devicefileevents) | Investigation | `DeviceFileEvents` |
| 11 | [— Windows Registry Persistence (DeviceRegistryEvents)](#query-11--windows-registry-persistence-deviceregistryevents) | Investigation | `DeviceRegistryEvents` |
| 12 | [— PowerShell Masquerading as wt.exe (DeviceProcessEvents)](#query-12--powershell-masquerading-as-wtexe-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 13 | [— npm Registry DNS Lookups Baseline (ASIM DNS)](#query-13--npm-registry-dns-lookups-baseline-asim-dns) | Dashboard | `ASimDnsActivityLogs` |
| 14 | [— npm Registry Network Connections (DeviceNetworkEvents)](#query-14--npm-registry-network-connections-devicenetworkevents) | Investigation | `DeviceNetworkEvents` |
| 15 | [— npm Install During Compromise Window (DeviceProcessEvents)](#query-15--npm-install-during-compromise-window-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 16 | [— node.exe Spawning Suspicious Network Connections (DeviceNetworkEv...](#query-16--nodeexe-spawning-suspicious-network-connections-devicenetworkevents) | Investigation | `DeviceNetworkEvents` |
| 17 | [— Anomalous IE8 User-Agent Detection (DeviceNetworkEvents)](#query-17--anomalous-ie8-user-agent-detection-devicenetworkevents) | Detection | `DeviceNetworkEvents` |
| 18 | [— postinstall Script Execution by node.exe (DeviceProcessEvents)](#query-18--postinstall-script-execution-by-nodeexe-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 19 | [— AMSI Script Content Analysis for npm Payloads (DeviceCustomScript...](#query-19--amsi-script-content-analysis-for-npm-payloads-devicecustomscriptevents) | Investigation | `DeviceCustomScriptEvents` |
| 20 | [— axios Package in Software Inventory (DeviceTvmSoftwareInventory)](#query-20--axios-package-in-software-inventory-devicetvmsoftwareinventory) | Posture | `DeviceTvmSoftwareInventory` |
| 21 | [— CDC node_modules File Activity Audit (DeviceCustomFileEvents)](#query-21--cdc-nodemodules-file-activity-audit-devicecustomfileevents) | Investigation | `DeviceCustomFileEvents` |
| 22 | [— VBScript/cscript Execution from Temp Directory (DeviceProcessEvents)](#query-22--vbscriptcscript-execution-from-temp-directory-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 23 | [— curl Downloads to Temp/ProgramData (DeviceProcessEvents)](#query-23--curl-downloads-to-tempprogramdata-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 24 | [— Linux/macOS Stage-2 File Artifacts (DeviceFileEvents)](#query-24--linuxmacos-stage-2-file-artifacts-devicefileevents) | Investigation | `DeviceFileEvents` |
| 25 | [— Generic npm postinstall Hook Abuse Detection (DeviceCustomScriptE...](#query-25--generic-npm-postinstall-hook-abuse-detection-devicecustomscriptevents) | Detection | `DeviceCustomScriptEvents` |
| 26 | [— CDC File Activity for axios Package Directories (DeviceCustomFile...](#query-26--cdc-file-activity-for-axios-package-directories-devicecustomfileevents) | Investigation | `DeviceCustomFileEvents` |
| 27 | [— Comprehensive npm Ecosystem Exposure Assessment (DeviceProcessEve...](#query-27--comprehensive-npm-ecosystem-exposure-assessment-deviceprocessevents) | Posture | `DeviceProcessEvents` |
| 28 | [— Cloud Workload postinstall Execution (CloudProcessEvents)](#query-28--cloud-workload-postinstall-execution-cloudprocessevents) | Investigation | `CloudProcessEvents` |
| 29 | [— ASIM Network Session IoC Detection (_Im_NetworkSession)](#query-29--asim-network-session-ioc-detection-imnetworksession) | Detection | — |
| 30 | [— ASIM Web Session IoC Detection (_Im_WebSession)](#query-30--asim-web-session-ioc-detection-imwebsession) | Detection | — |
| 31 | [— Compromised axios/plain-crypto-js in TVM Software Inventory (Devi...](#query-31--compromised-axiosplain-crypto-js-in-tvm-software-inventory-devicetvmsoftwareinventory) | Posture | `DeviceTvmSoftwareInventory` |


## Query Catalog

### Query 1 — npm install / yarn add / pnpm add Command Detection (DeviceProcessEvents)

**Goal:** Detect any npm, yarn, or pnpm package install commands across the MDE fleet. Foundation query for supply chain exposure assessment.  
**MITRE:** T1195.002, T1059.007

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Audit/inventory query using summarize with make_set and dcount — not suitable for CD alerting."
-->

```kql
// Audit all npm/yarn/pnpm install activity across fleet
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("npm install", "npm i ", "npm ci", "yarn add", "yarn install", "pnpm install", "pnpm add", "bun install", "bun add")
| extend PackageManagerRaw = case(
    ProcessCommandLine has "npm", "npm",
    ProcessCommandLine has "yarn", "yarn",
    ProcessCommandLine has "pnpm", "pnpm",
    ProcessCommandLine has "bun", "bun",
    "unknown")
| summarize 
    InstallCount = count(),
    Devices = make_set(DeviceName, 20),
    Users = make_set(AccountName, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SampleCommands = make_set(ProcessCommandLine, 20)
    by PackageManagerRaw
| order by InstallCount desc
```

---

### Query 2 — Compromised axios Version Detection via Process Commands (DeviceProcessEvents)

**Goal:** Detect explicit installation of compromised axios versions (`1.14.1`, `0.30.4`) or the malicious dependency `plain-crypto-js`.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Compromised axios/plain-crypto-js install detected on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "CRITICAL: Compromised npm package installed. If axios@1.14.1 or 0.30.4, treat as confirmed compromise. Isolate device, rotate all secrets (npm tokens, SSH keys, API keys, cloud credentials). Check for wt.exe in ProgramData, 6202033.vbs/.ps1 in Temp, system.bat persistence, MicrosoftUpdate registry key."
adaptation_notes: "Already row-level. Add DeviceId + ReportId columns."
-->

```kql
// Detect installation of compromised axios versions or plain-crypto-js
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("axios@1.14.1", "axios@0.30.4", "plain-crypto-js")
    or (ProcessCommandLine has "axios" 
        and ProcessCommandLine has_any ("npm install", "npm i ", "yarn add", "pnpm add", "bun add"))
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath
| order by Timestamp desc
```

---

### Query 3 — plain-crypto-js File Artifacts on Disk (DeviceFileEvents)

**Goal:** Detect any `plain-crypto-js` directory or files on disk. This package should NEVER exist in a legitimate project — its presence is a confirmed compromise indicator even if contents appear clean (anti-forensics swap).  
**MITRE:** T1195.002, T1070.004

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Malicious plain-crypto-js package detected on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: plain-crypto-js is a purpose-built malware delivery package from the axios supply chain attack. Even if package.json appears clean (anti-forensics swap), the system WAS compromised. Isolate device, rotate all secrets, check for stage-2 artifacts."
adaptation_notes: "Already row-level with SHA256. Add DeviceId + ReportId columns."
-->

```kql
// Detect plain-crypto-js — the malicious dependency (should NEVER exist)
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "plain-crypto-js" or FileName has "plain-crypto-js"
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

### Query 4 — plain-crypto-js via CDC File Events (DeviceCustomFileEvents)

**Goal:** Extended detection using Custom Data Collection tables for deeper file audit coverage. CDC captures file activity that standard `DeviceFileEvents` may miss — particularly in `node_modules` directories managed by npm.  
**MITRE:** T1195.002, T1070.004

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "CDC: Malicious plain-crypto-js file activity on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CDC detected plain-crypto-js file operations. This package is a confirmed malware delivery vehicle. Isolate device, rotate secrets, investigate full axios compromise chain."
adaptation_notes: "CDC table — may not exist in all environments. Skip gracefully if table not found. Already row-level. Add DeviceId + ReportId."
-->

```kql
// CDC: Detect plain-crypto-js file operations (deeper coverage than standard DeviceFileEvents)
DeviceCustomFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "plain-crypto-js" or FileName has "plain-crypto-js"
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256
| order by Timestamp desc
```

---

### Query 5 — Windows Stage-2 Filesystem IOCs (DeviceFileEvents)

**Goal:** Detect Windows-specific payload artifacts: `wt.exe` in ProgramData (renamed PowerShell), `6202033.vbs`/`.ps1` temp scripts, and `system.bat` persistence file.  
**MITRE:** T1036.005, T1547.001, T1070.004

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "axios Windows payload artifact detected on {{DeviceName}}: {{FileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: Windows stage-2 IOC found. wt.exe in ProgramData = renamed PowerShell (EDR evasion). Check for MicrosoftUpdate registry persistence, system.bat, and active C2 connections to sfrclak.com:8000. Isolate device immediately."
adaptation_notes: "Already row-level. Add DeviceId + ReportId columns."
-->

```kql
// Detect Windows stage-2 payload artifacts
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName =~ "wt.exe" and FolderPath has "ProgramData" and not(FolderPath has "WindowsApps"))
    or FileName in~ ("6202033.vbs", "6202033.ps1")
    or (FileName =~ "system.bat" and FolderPath has "ProgramData")
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

### Query 6 — Windows Stage-2 CDC Detection (DeviceCustomFileEvents)

**Goal:** Extended Windows IOC detection using CDC tables. Catches transient files (VBS/PS1 that self-delete) that standard `DeviceFileEvents` may not capture.  
**MITRE:** T1036.005, T1547.001, T1070.004

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "CDC: axios Windows artifact on {{DeviceName}}: {{FileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CDC captured Windows stage-2 artifact. Correlate with DeviceProcessEvents for wt.exe execution and registry events for MicrosoftUpdate persistence."
adaptation_notes: "CDC table — may not exist in all environments. Already row-level. Add DeviceId + ReportId."
-->

```kql
// CDC: Extended detection for Windows stage-2 artifacts
DeviceCustomFileEvents
| where Timestamp > ago(30d)
| where (FileName =~ "wt.exe" and FolderPath has "ProgramData" and not(FolderPath has "WindowsApps"))
    or FileName in~ ("6202033.vbs", "6202033.ps1")
    or (FileName =~ "system.bat" and FolderPath has "ProgramData")
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256
| order by Timestamp desc
```

---

### Query 7 — C2 Network Connections (DeviceNetworkEvents)

**Goal:** Detect outbound connections to the axios C2 domain `sfrclak[.]com` and IP `142.11.206.73`.  
**MITRE:** T1041, T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "Exfiltration"
title: "Outbound connection to axios C2 (sfrclak.com) from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: Device connected to the axios compromise C2 server. RAT was active and capable of arbitrary code execution. Isolate immediately, rotate ALL credentials, rebuild from known-good image."
adaptation_notes: "NRT-suitable — high-fidelity IoC match. Already row-level. Add DeviceId + ReportId."
-->

```kql
// Detect outbound connections to axios C2 domain/IP
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "sfrclak" 
    or RemoteIP in ("142.11.206.73", "142.11.206.72")
| project 
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 8 — C2 DNS Resolution (ASIM DNS)

**Goal:** Detect DNS lookups for the C2 domain `sfrclak[.]com` via ASIM-normalized DNS logs. Catches resolution attempts even if the HTTP connection was blocked by firewall/proxy.  
**MITRE:** T1041, T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "DNS resolution of axios C2 domain sfrclak.com from {{SrcIpAddr}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "DNS resolution of the axios C2 domain detected. Even if HTTP was blocked, a compromised package attempted to phone home. Identify the source device, check for plain-crypto-js in node_modules."
adaptation_notes: "Sentinel/LA table — use TimeGenerated. Dvc may serve as DeviceName proxy. No native ReportId — use EventUid as proxy."
-->

```kql
// DNS resolution of axios C2 domain
ASimDnsActivityLogs
| where TimeGenerated > ago(30d)
| where DnsQuery has "sfrclak"
| project 
    TimeGenerated,
    SrcIpAddr,
    DnsQuery,
    DnsQueryTypeName,
    DnsResponseName,
    DnsResponseCode,
    EventResult,
    Dvc,
    EventProduct
| order by TimeGenerated desc
```

---

### Query 9 — C2 DNS via MDE DNS Events (DeviceEvents)

**Goal:** Alternative C2 DNS detection using MDE's native DNS query telemetry for environments without ASIM DNS.  
**MITRE:** T1041, T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "MDE DNS query for axios C2 domain on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "MDE captured DNS lookup for the axios C2 domain. Source device likely has compromised axios or plain-crypto-js installed. Investigate immediately."
adaptation_notes: "Uses AdditionalFields dynamic column — ensure has operator matches correctly. Already row-level. Add DeviceId + ReportId."
-->

```kql
// MDE DNS telemetry for C2 domain
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where AdditionalFields has "sfrclak"
| project 
    Timestamp,
    DeviceName,
    ActionType,
    AdditionalFields
| order by Timestamp desc
```

---

### Query 10 — Stage-2 Payload SHA-256 Hash Match (DeviceFileEvents)

**Goal:** Match known stage-2 payload hashes across the fleet. Covers all five platform-specific payloads (including both Windows PS1 variants identified by Microsoft).  
**MITRE:** T1041, T1027

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "axios stage-2 payload hash matched on {{DeviceName}}: {{FileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: Known axios RAT payload detected via SHA-256 hash match. Device is CONFIRMED COMPROMISED. Isolate, rebuild, rotate all credentials."
adaptation_notes: "Already row-level with SHA256. Convert let statement to inline dynamic for CD compatibility. Add DeviceId + ReportId."
-->

```kql
// Match known stage-2 payload SHA-256 hashes
let malicious_hashes = dynamic([
    "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c",
    "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101",
    "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd",
    "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a",
    "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (malicious_hashes)
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 11 — Windows Registry Persistence (DeviceRegistryEvents)

**Goal:** Detect the `MicrosoftUpdate` registry Run key persistence mechanism used by the Windows RAT.  
**MITRE:** T1547.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "axios RAT registry persistence (MicrosoftUpdate Run key) on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: MicrosoftUpdate Run key persistence detected — the Windows RAT establishes this to re-download the payload on every login via hidden system.bat. Check %PROGRAMDATA%\\system.bat and %PROGRAMDATA%\\wt.exe. Isolate and rebuild."
adaptation_notes: "Already row-level. Add DeviceId + ReportId."
-->

```kql
// Detect MicrosoftUpdate registry Run key persistence
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"CurrentVersion\Run"
    and RegistryValueName =~ "MicrosoftUpdate"
| project 
    Timestamp,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 12 — PowerShell Masquerading as wt.exe (DeviceProcessEvents)

**Goal:** Detect the EDR evasion technique where `powershell.exe` is copied to `%PROGRAMDATA%\wt.exe` and executed with hidden window + execution policy bypass flags. `wt.exe` is the legitimate Windows Terminal binary — process-name heuristics won't flag it.  
**MITRE:** T1036.005, T1059.001

**Note:** This query may be blocked by the AH safety filter due to PowerShell-related keywords. If so, execute via `mcp_sentinel-data_query_lake` (Data Lake) instead.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "PowerShell masquerading as wt.exe detected on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Process masquerading detected: a binary with PowerShell's original filename is running as wt.exe. This is the exact axios compromise EDR evasion technique. Verify FolderPath — if in ProgramData, this is confirmed compromise."
adaptation_notes: "May need Data Lake execution (AH safety filter). Already row-level. Add DeviceId + ReportId."
-->

```kql
// Detect PowerShell masquerading — process name does not match original filename
// NOTE: Execute via Data Lake if AH safety filter blocks this query
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where ProcessVersionInfoOriginalFileName has "PowerShell"
| where not(FileName in~ ("powershell.exe", "pwsh.exe"))
| where not(FileName has "PowerShell-")  // Exclude legitimate PS installers (e.g., PowerShell-7.4.14-win-x64.exe)
| project 
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    ProcessVersionInfoOriginalFileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

### Query 13 — npm Registry DNS Lookups Baseline (ASIM DNS)

**Goal:** Identify devices resolving npm registry domains — baseline for understanding which systems actively use npm and are exposed to npm supply chain risk.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline/inventory query using summarize — designed for exposure scoping, not alerting."
-->

```kql
// Baseline: which devices resolve npm registry domains (30-day lookback)
ASimDnsActivityLogs
| where TimeGenerated > ago(30d)
| where DnsQuery has "npmjs.org" 
    or DnsQuery has "registry.npmjs"
    or DnsQuery has "registry.yarnpkg"
    or DnsQuery has "registry.npmmirror"
| summarize 
    QueryCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DnsQueries = make_set(DnsQuery, 10)
    by SrcIpAddr, Dvc
| order by QueryCount desc
```

---

### Query 14 — npm Registry Network Connections (DeviceNetworkEvents)

**Goal:** Detect devices making outbound connections to npm registries. Combined with timestamp correlation to the compromise window, identifies systems that may have pulled packages during the attack.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline/exposure query using summarize. For compromise-window detection, narrow the datetime filter to 2026-03-31 00:21–03:30 UTC."
-->

```kql
// Devices connecting to npm registries — exposure assessment
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "npmjs.org" 
    or RemoteUrl has "registry.npmjs"
    or RemoteUrl has "registry.yarnpkg"
    or RemoteUrl has "registry.npmmirror"
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    URLs = make_set(RemoteUrl, 20)
    by DeviceName
| order by ConnectionCount desc
```

---

### Query 15 — npm Install During Compromise Window (DeviceProcessEvents)

**Goal:** One-time forensic query — detect any npm install commands during the specific axios compromise window (2026-03-31 00:21–03:30 UTC).  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "One-time forensic query for a fixed compromise window. Not suitable for ongoing CD — hardcoded datetime range."
-->

```kql
// Detect npm install activity during the axios compromise window
DeviceProcessEvents
| where Timestamp between (datetime(2026-03-31T00:21:00Z) .. datetime(2026-03-31T03:30:00Z))
| where ProcessCommandLine has_any ("npm install", "npm i ", "npm ci", "yarn add", "yarn install", "pnpm install", "pnpm add", "bun install", "bun add")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FileName,
    FolderPath
| order by Timestamp asc
```

---

### Query 16 — node.exe Spawning Suspicious Network Connections (DeviceNetworkEvents)

**Goal:** Detect `node.exe` making outbound connections to unusual domains — catches both axios-specific C2 and generic npm postinstall-based exfiltration. The RAT uses curl for C2 communication, but the initial dropper runs as `node setup.js`.  
**MITRE:** T1041, T1071.001, T1059.007

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summarize aggregation by RemoteUrl/RemoteIP — designed for threat hunting review, not CD. High false-positive rate without tuning to specific environment."
-->

```kql
// node.exe making outbound connections — look for anomalous destinations
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
// Exclude common legitimate Node.js network targets
| where RemoteUrl !has "microsoft.com"
    and RemoteUrl !has "azure.com"
    and RemoteUrl !has "windows.net"
    and RemoteUrl !has "office.com"
    and RemoteUrl !has "github.com"
    and RemoteUrl !has "npmjs.org"
    and RemoteUrl !has "googleapis.com"
    and RemoteUrl !has "openai.com"
    and RemoteUrl !has "anthropic.com"
    and RemoteUrl !has "localhost"
| summarize 
    ConnectionCount = count(),
    Devices = make_set(DeviceName, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteUrl, RemoteIP
| order by ConnectionCount desc
| take 50
```

---

### Query 17 — Anomalous IE8 User-Agent Detection (DeviceNetworkEvents)

**Goal:** Detect the RAT's distinctive User-Agent string (`mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`). An IE8 on Windows XP User-Agent in 2026 is extremely anomalous and a reliable detection indicator across all three platform RAT variants.  
**MITRE:** T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "CommandAndControl"
title: "Anomalous IE8/WinXP User-Agent detected from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "IE8 on Windows XP User-Agent in 2026 is highly anomalous and matches the axios RAT beacon fingerprint (all platform variants). Investigate the initiating process and destination — correlate with sfrclak.com C2."
adaptation_notes: "AdditionalFields may need parsing depending on schema. 24H schedule — low urgency standalone but high value when correlated. Add DeviceId + ReportId."
-->

```kql
// Detect the RAT's anomalous IE8/WinXP User-Agent string in network events
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where AdditionalFields has "msie 8.0"
    and AdditionalFields has "windows nt 5.1"
| project 
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

---

### Query 18 — postinstall Script Execution by node.exe (DeviceProcessEvents)

**Goal:** Detect `node.exe` executing `setup.js` — the malicious postinstall hook in `plain-crypto-js`. Also catches broader suspicious postinstall patterns where node spawns shell/script processes.  
**MITRE:** T1059.007, T1195.002

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "node.exe spawned suspicious process on {{DeviceName}}: {{FileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "node.exe spawned a shell or script interpreter — may indicate a malicious npm postinstall hook. Check if the parent command references plain-crypto-js or setup.js. Review the process tree for C2 connections."
adaptation_notes: "Already row-level. May need FP tuning — some legitimate npm packages use postinstall hooks. Add DeviceId + ReportId."
-->

```kql
// node.exe spawning shell/script interpreters — postinstall hook pattern
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where FileName in~ ("cmd.exe", "cscript.exe", "wscript.exe", "osascript", "bash", "sh", "zsh", "python.exe", "python3", "python3.exe", "curl.exe", "curl")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

---

### Query 19 — AMSI Script Content Analysis for npm Payloads (DeviceCustomScriptEvents)

**Goal:** Search AMSI-captured script content for indicators of the axios compromise — obfuscation patterns, C2 URLs, campaign identifiers, and package names. AMSI captures PowerShell/VBScript execution, which covers the Windows stage-2 RAT.  
**MITRE:** T1059.001, T1059.005, T1027

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "CDC AMSI: axios compromise indicator in script on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "AMSI captured script content containing axios compromise indicators. Review full ScriptContent for C2 communication, credential exfiltration, or persistence commands."
adaptation_notes: "CDC table — may not exist in all environments. AMSI only sees PowerShell/VBScript/JScript — not Node.js. Already row-level. Add DeviceId + ReportId."
-->

```kql
// AMSI: Search captured scripts for axios compromise indicators
DeviceCustomScriptEvents
| where Timestamp > ago(30d)
| where ScriptContent has_any (
    "sfrclak",
    "6202033",
    "plain-crypto-js",
    "packages.npm.org",
    "OrDeR_7077",
    "wt.exe",
    "system.bat",
    "MicrosoftUpdate",
    "com.apple.act.mond"
)
| project 
    Timestamp,
    DeviceName,
    ScriptContent,
    InitiatingProcessFileName
| order by Timestamp desc
```

---

### Query 20 — axios Package in Software Inventory (DeviceTvmSoftwareInventory)

**Goal:** Check if axios (or node/npm) appears in TVM software inventory. Useful for identifying which devices have node.js ecosystems installed.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Inventory/baseline query using summarize — designed for exposure scoping, not alerting."
-->

```kql
// Software inventory: node.js, npm, and axios presence across fleet
DeviceTvmSoftwareInventory
| where SoftwareName has_any ("axios", "node", "npm", "nodejs")
| summarize 
    DeviceCount = dcount(DeviceName),
    Devices = make_set(DeviceName, 20),
    Versions = make_set(SoftwareVersion, 20)
    by SoftwareName, SoftwareVendor
| order by DeviceCount desc
```

---

### Query 21 — CDC node_modules File Activity Audit (DeviceCustomFileEvents)

**Goal:** Comprehensive audit of file creation events within `node_modules` directories via CDC. Catches npm package installations that standard `DeviceFileEvents` may miss, including postinstall artifacts, package.json modifications, and the anti-forensics `package.md` → `package.json` swap.  
**MITRE:** T1195.002, T1070.004

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Device-level summarize aggregation — designed for exposure scoping and forensic review. CDC table may not exist in all environments."
-->

```kql
// CDC: Comprehensive node_modules file activity audit
// Identifies active npm package installation on devices
DeviceCustomFileEvents
| where Timestamp > ago(7d)
| where FolderPath has "node_modules"
// Exclude bundled app node_modules (Windows Store apps, VS Code extensions)
| where FolderPath !has "WindowsApps"
    and FolderPath !has "Microsoft.GamingApp"
    and FolderPath !has @".vscode\extensions"
    and FolderPath !has @".vscode-insiders\extensions"
| summarize 
    FileCount = count(),
    ActionTypes = make_set(ActionType, 10),
    SamplePaths = make_set(FolderPath, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName
| order by FileCount desc
```

---

### Query 22 — VBScript/cscript Execution from Temp Directory (DeviceProcessEvents)

**Goal:** Detect the Windows attack chain pattern: `cscript.exe` executing a VBS file from the TEMP directory. The axios dropper writes `6202033.vbs` to `%TEMP%` and runs it via `cscript //nologo`, then deletes it.  
**MITRE:** T1059.005, T1070.004

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "cscript executing VBS from temp directory on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "cscript.exe is executing a VBScript from the TEMP directory — this matches the axios Windows dropper pattern. Check if initiated by node.exe and if the VBS filename contains '6202033'. Investigate the full process tree."
adaptation_notes: "Already row-level. May need FP tuning for legitimate admin scripts in temp. Add DeviceId + ReportId."
-->

```kql
// cscript executing VBS from temp directories — matches axios dropper chain
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "cscript.exe"
| where ProcessCommandLine has ".vbs"
| where ProcessCommandLine has_any ("Temp", "tmp", "TEMP", "AppData\\Local\\Temp")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

---

### Query 23 — curl Downloads to Temp/ProgramData (DeviceProcessEvents)

**Goal:** Detect `curl` downloading files to suspicious locations — both the Windows chain (`curl -s -X POST` to download PS1) and the macOS/Linux chains (`curl -o` to `/Library/Caches/` or `/tmp/`).  
**MITRE:** T1041, T1105

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Broad hunting query with summarize — needs environment-specific FP tuning for legitimate curl usage. Not CD-suitable without allowlists."
-->

```kql
// curl downloading files to suspicious locations
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl.exe", "curl")
| where ProcessCommandLine has_any ("ProgramData", "6202033", "sfrclak", "/Library/Caches/com.apple", "/tmp/ld.py")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 24 — Linux/macOS Stage-2 File Artifacts (DeviceFileEvents)

**Goal:** Detect macOS (`/Library/Caches/com.apple.act.mond`) and Linux (`/tmp/ld.py`) stage-2 RAT artifacts on non-Windows endpoints.  
**MITRE:** T1036.005, T1059.006

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "axios macOS/Linux RAT artifact detected on {{DeviceName}}: {{FileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: Platform-specific RAT artifact detected. macOS: com.apple.act.mond is a fake Apple daemon (Mach-O universal binary). Linux: ld.py is the Python RAT. Isolate device, rotate all credentials."
adaptation_notes: "Already row-level. Add DeviceId + ReportId."
-->

```kql
// Detect macOS and Linux stage-2 RAT artifacts
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "/Library/Caches/com.apple.act.mond"
    or (FileName =~ "ld.py" and FolderPath has "/tmp/")
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

### Query 25 — Generic npm postinstall Hook Abuse Detection (DeviceCustomScriptEvents)

**Goal:** Broader hunt for suspicious npm postinstall behavior captured by AMSI — base64-encoded payloads, obfuscated scripts, or child_process.spawn patterns in captured script content. Not axios-specific, but catches the class of attack.  
**MITRE:** T1059.007, T1027, T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Broad hunting query — high FP potential from legitimate npm postinstall hooks. Needs environment tuning. CDC table may not exist."
-->

```kql
// AMSI: Suspicious patterns in scripts spawned by node.exe
// Catches obfuscated postinstall payloads broadly, not just axios-specific
DeviceCustomScriptEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where ScriptContent has_any (
    "base64",
    "child_process",
    "exec(",
    "spawn(",
    "curl ",
    "Invoke-WebRequest",
    "DownloadString",
    "FromBase64String"
)
| project 
    Timestamp,
    DeviceName,
    ScriptContent,
    InitiatingProcessFileName
| order by Timestamp desc
| take 50
```

---

### Query 26 — CDC File Activity for axios Package Directories (DeviceCustomFileEvents)

**Goal:** Deep-dive CDC audit for any file operations within `axios` package directories in `node_modules`. Checks for the compromised version's distinctive change: addition of `plain-crypto-js` to dependencies in `package.json`, and the anti-forensics `package.md` file.  
**MITRE:** T1195.002, T1070.004

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Forensic deep-dive query — CDC may have high volume for this path. Not CD-suitable due to broad scope."
-->

```kql
// CDC: File operations within axios package directories
DeviceCustomFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "node_modules" and FolderPath has "axios"
// Exclude bundled Windows Store app node_modules
| where FolderPath !has "WindowsApps"
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256
| order by Timestamp desc
| take 100
```

---

### Query 27 — Comprehensive npm Ecosystem Exposure Assessment (DeviceProcessEvents)

**Goal:** Full-fleet inventory of node.js/npm ecosystem usage — identifies which devices have active node.js, npm, yarn, or related tooling. Foundation for assessing blast radius of ANY npm supply chain compromise.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet inventory query using summarize — designed for exposure reporting, not alerting."
-->

```kql
// Fleet inventory: All node.js/npm ecosystem process activity
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node", "npm.cmd", "npm", "npx.cmd", "npx", "yarn.cmd", "yarn", "pnpm.cmd", "pnpm", "bun.exe", "bun")
| summarize 
    ProcessCount = count(),
    Users = make_set(AccountName, 20),
    SampleCommands = make_set(ProcessCommandLine, 30),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, FileName
| order by ProcessCount desc
```

---

### Query 28 — Cloud Workload postinstall Execution (CloudProcessEvents)

**Goal:** Detect the `plain-crypto-js` postinstall hook executing on cloud workloads — CI/CD runners, containers, cloud VMs monitored by Defender for Cloud. This query is from the Microsoft blog and covers environments without MDE agent.  
**MITRE:** T1195.002, T1059.007

> Source: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Cloud: axios postinstall dropper or C2 download on cloud workload"
impactedAssets:
  - type: cloudResource
    identifier: azureResourceId
recommendedActions: "CRITICAL: Cloud workload executed the axios supply chain dropper. Rotate all secrets in the CI/CD environment, check for plain-crypto-js in build artifacts, and review connected cloud resources for lateral movement."
adaptation_notes: "CloudProcessEvents table — requires Defender for Cloud. Schema differs from DeviceProcessEvents: no DeviceName (use AzureResourceId/ContainerName), no InitiatingProcessFileName (use ParentProcessName). Already row-level. Add ReportId."
-->

```kql
// Detect plain-crypto-js postinstall hook or C2 download on cloud workloads
CloudProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCurrentWorkingDirectory endswith "/node_modules/plain-crypto-js"
    and (ProcessCommandLine has_all ("plain-crypto-js", "node setup.js")))
    or ProcessCommandLine has_all ("/tmp/ld.py", "sfrclak.com:8000")
| project
    Timestamp,
    AzureResourceId,
    ContainerImageName,
    KubernetesPodName,
    ContainerName,
    AccountName,
    ProcessCommandLine,
    ProcessCurrentWorkingDirectory,
    ParentProcessName
| order by Timestamp desc
```

---

### Query 29 — ASIM Network Session IoC Detection (_Im_NetworkSession)

**Goal:** Detect C2 connections across all data sources supported by ASIM network session parsers (firewalls, proxies, NDR, NSGs). Provides broader cross-vendor coverage beyond MDE-only `DeviceNetworkEvents`.  
**MITRE:** T1041, T1071.001

> Source: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)

**Note:** ASIM parser functions work via **Advanced Hunting** (not Data Lake MCP — `query_lake` cannot resolve workspace-level functions).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ASIM parser function _Im_NetworkSession — uses summarize aggregation. Works in AH and portal, NOT via Sentinel Data Lake MCP (query_lake). Best deployed as Sentinel Analytics Rule rather than CD."
-->

```kql
// ASIM: Detect C2 connections across all normalized network session sources
let lookback = 30d;
let ioc_ip_addr = dynamic(["142.11.206.73", "142.11.206.72"]);
let ioc_domains = dynamic(["sfrclak.com"]);
_Im_NetworkSession(starttime=todatetime(ago(lookback)), endtime=now())
| where DstIpAddr in (ioc_ip_addr) or DstDomain has_any (ioc_domains)
| summarize 
    FirstSeen = min(TimeGenerated), 
    LastSeen = max(TimeGenerated),
    EventCount = count() 
    by SrcIpAddr, DstIpAddr, DstDomain, Dvc, EventProduct, EventVendor
| order by EventCount desc
```

---

### Query 30 — ASIM Web Session IoC Detection (_Im_WebSession)

**Goal:** Detect C2 web connections and URL patterns across all ASIM web session sources (proxies, WAFs, SWGs). Catches HTTP-level indicators including the C2 URL path.  
**MITRE:** T1041, T1071.001

> Source: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)

**Note:** ASIM parser functions work via **Advanced Hunting** (not Data Lake MCP — `query_lake` cannot resolve workspace-level functions).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ASIM parser function _Im_WebSession — uses summarize aggregation. Works in AH and portal, NOT via Sentinel Data Lake MCP (query_lake). Best deployed as Sentinel Analytics Rule rather than CD."
-->

```kql
// ASIM: Detect C2 web sessions (IP + domain) across all normalized web session sources
let lookback = 30d;
let ioc_ip_addr = dynamic(["142.11.206.73", "142.11.206.72"]);
let ioc_domains = dynamic(["sfrclak.com"]);
_Im_WebSession(starttime=todatetime(ago(lookback)), endtime=now())
| where DstIpAddr in (ioc_ip_addr) or Url has_any (ioc_domains)
| summarize 
    FirstSeen = min(TimeGenerated), 
    LastSeen = max(TimeGenerated),
    EventCount = count() 
    by SrcIpAddr, DstIpAddr, Url, Dvc, EventProduct, EventVendor
| order by EventCount desc
```

---

### Query 31 — Compromised axios/plain-crypto-js in TVM Software Inventory (DeviceTvmSoftwareInventory)

**Goal:** Identify devices with the exact compromised package versions (`axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`) in TVM software inventory. More targeted than the broad Query 20 — a match here means the device has (or had) a compromised version installed.  
**MITRE:** T1195.002

> Source: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "InitialAccess"
title: "Compromised axios/plain-crypto-js version in TVM inventory on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Device has a compromised package version in software inventory. Isolate, rotate all secrets, check for stage-2 artifacts (wt.exe, system.bat, com.apple.act.mond, ld.py)."
adaptation_notes: "Already row-level. Add DeviceId. 24H schedule sufficient — TVM inventory updates infrequently."
-->

```kql
// Detect exact compromised versions in TVM software inventory
DeviceTvmSoftwareInventory
| where (SoftwareName has "axios" and SoftwareVersion in ("1.14.1", "0.30.4"))
    or (SoftwareName has "plain-crypto-js" and SoftwareVersion == "4.2.1")
| project
    DeviceName,
    SoftwareName,
    SoftwareVersion,
    SoftwareVendor,
    EndOfSupportStatus,
    EndOfSupportDate
| order by SoftwareName asc
```
