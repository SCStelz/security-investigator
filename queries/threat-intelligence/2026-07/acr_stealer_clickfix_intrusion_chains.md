# ACR Stealer — ClickFix Intrusion Chains (WebDAV/Python & MSHTA/Steganography) — Threat Hunts

**Created:** 2026-07-16  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceRegistryEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents  
**Keywords:** ACR Stealer, Amatera Stealer, ClickFix, RunMRU, WebDAV, pushd, @SSL, rundll32, conhost headless, delayed variable expansion, environment variable obfuscation, obfuscated PowerShell, MSHTA, HTA, VBScript COM, scheduled task masquerade, Autoupdate, timestomping, PowerShell history clearing, ConsoleHost_history, pythonw loader, LocalAppData Temp, LogiOptionsPlus masquerade, Fiber API, ConvertThreadToFiber, VirtualAlloc, reflective shellcode, process hollowing, steganography, JPEG payload, DPAPI, browser credential theft, Login Data, Web Data, Chromium, EtherHiding, blockchain dead drop, Web3 RPC, data staging, infostealer, MaaS  
**MITRE:** T1189, T1204, T1059.001, T1059.003, T1059.006, T1218.011, T1218.005, T1053.005, T1027, T1027.003, T1036, T1070.003, T1070.006, T1620, T1055, T1555.003, T1005, T1074, T1102, T1568.002  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [ACR Stealer: Two observed intrusion chains amid increased threat activity (2026-07-16)](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/)

---

## Threat Overview

From late April 2026 to mid-June 2026, Microsoft Defender Experts observed increased **ACR Stealer** activity (an information stealer offered as a malware-as-a-service and associated with the rebranding of **Amatera Stealer**). Two prevalent delivery campaigns stand out, both beginning with a **ClickFix** social-engineering lure (delivered via malvertising or SEO poisoning) that tricks the victim into running the attacker's command, but diverging in payload delivery and execution.

**Campaign 1 (WebDAV / Python / blockchain C2):** ClickFix launches `cmd.exe`, which invokes `rundll32.exe` to load a DLL from a remote **WebDAV** share over HTTPS (GUID-based path, benign-looking filenames such as `google.ct`). Stealthier variants mount the share with `pushd \\host@SSL\...` and run headlessly via `conhost --headless` with delayed environment-variable expansion. A heavily obfuscated PowerShell stage downloads a ZIP into a deceptive `%LocalAppData%\Temp` directory (e.g., `LogiOptionsPlus`), launches a **Python loader via bundled `pythonw.exe`**, establishes persistence through a hidden **scheduled task masquerading as a software update**, timestomps files from `notepad.exe`, and clears PowerShell history. The Python loader reconstructs an in-memory shellcode stage using **VirtualAlloc + Windows Fiber API** (`ConvertThreadToFiber`/`CreateFiber`/`SwitchToFiber`). A subset resolves C2 via **blockchain dead-drop (EtherHiding)** against public Web3 RPC endpoints.

**Campaign 2 (fileless MSHTA / steganography):** ClickFix spawns **`mshta.exe`** to fetch remote HTA content; an embedded VBScript loader abuses COM to decode and run obfuscated PowerShell. The PowerShell stage disables certificate validation, generates a victim ID, retrieves a **JPEG from an image host**, and extracts an encrypted payload from **image pixels (steganography)** for reflective in-memory shellcode execution (`LoadLibrary`/`GetProcAddress`/`VirtualAlloc`/`CreateThread`). Both campaigns converge on **Chromium browser credential theft** (`Login Data`/`Web Data` + DPAPI) and staging of PDFs/Office documents for exfiltration.

### TTP Summary
| Capability | TTP |
|---|---|
| ClickFix lure prompts command execution | Drive-by Compromise (T1189), User Execution (T1204) |
| `cmd.exe` / PowerShell / `pythonw.exe` launch staged payloads | Windows Command Shell (T1059.003), PowerShell (T1059.001), Python (T1059.006) |
| `rundll32.exe` loads DLL from remote WebDAV share | System Binary Proxy Execution: Rundll32 (T1218.011) |
| `mshta.exe` runs remote HTA content | System Binary Proxy Execution: Mshta (T1218.005) |
| Hidden scheduled task masquerading as a software update | Scheduled Task/Job: Scheduled Task (T1053.005) |
| Obfuscated PowerShell; `pushd`/`conhost --headless`/env-var obfuscation; masquerade dirs | Obfuscated Files or Information (T1027), Masquerading (T1036) |
| JPEG pixel data hides encrypted payload | Obfuscated Files or Information: Steganography (T1027.003) |
| PowerShell history clearing | Indicator Removal: Clear Command History (T1070.003) |
| Timestomping from `notepad.exe` | Indicator Removal: Timestomp (T1070.006) |
| In-memory shellcode via Fiber API / reflective loading | Reflective Code Loading (T1620), Process Injection (T1055) |
| Chromium `Login Data`/`Web Data` + DPAPI decryption | Credentials from Web Browsers (T1555.003) |
| PDFs / Office / synced enterprise data enumerated and archived | Data from Local System (T1005), Data Staged (T1074) |
| Web3 RPC / image hosts resolve or retrieve follow-on payloads/C2 | Web Service (T1102), Dead Drop Resolver (T1568.002) |

### ⚠️ Hunt Pitfalls
| Pitfall | Mitigation |
|---|---|
| `rundll32.exe`, `conhost.exe`, and `pushd` are common on healthy hosts | Anchor on the campaign-specific combination (remote `@SSL` WebDAV path + `rundll32`/`pushd`, or `conhost --headless` paired with `rundll32`/env-var obfuscation) rather than the LOLBIN alone |
| Chromium `Login Data`/`Web Data` are read by the browsers themselves and by legitimate backup/sync/security agents | Exclude the browser binaries and known-good accessors in your estate; treat access by an unexpected, non-browser process as the signal — validate the initiator per environment |
| Published C2 / payload-hosting domains rot after disclosure | Treat direct-match sweeps as point-in-time; refresh from current Microsoft TI / VirusTotal and re-run in Sentinel Data Lake (>30d) for retrospective coverage beyond the 30-day Advanced Hunting window |
| `pythonw.exe` / `python.exe` from `Temp` can be legitimate packaged apps and installers | Pair the interpreter-from-`Temp` hunt with a masquerade directory, a scheduled-task persistence hit, or a network IOC; tune out sanctioned packaged-Python vendors per environment |
| Obfuscated-PowerShell heuristics (arithmetic no-ops, dead loops, randomized variables) are sample-specific | Do not alert on generic obfuscation alone; combine with the delivery LOLBIN chain (WebDAV/MSHTA) or a persistence/network hit |
| ClickFix RunMRU regexes assume specific variant syntax | The three published variants share the `@ssl` WebDAV + `rundll32`/`pushd`/`conhost --headless` markers; broaden cautiously as the actor rotates command syntax |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [ClickFix RunMRU command — remote WebDAV rundll32 / pushd execution](#query-1-clickfix-runmru-command--remote-webdav-rundll32--pushd-execution) | Investigation | `DeviceRegistryEvents` |
| 2 | [rundll32 / pushd loading a DLL from a remote @SSL WebDAV share](#query-2-rundll32--pushd-loading-a-dll-from-a-remote-ssl-webdav-share) | Investigation | `DeviceProcessEvents` |
| 3 | [Scheduled-task persistence created by a malicious PowerShell script...](#query-3-scheduled-task-persistence-created-by-a-malicious-powershell-script-software-update-masquerade) | Detection | `DeviceProcessEvents` |
| 4 | [Suspicious MSHTA launch through PowerShell (Campaign 2 initial access)](#query-4-suspicious-mshta-launch-through-powershell-campaign-2-initial-access) | Investigation | `DeviceProcessEvents` |
| 5 | [conhost --headless obfuscated execution with rundll32 / pushd / del...](#query-5-conhost---headless-obfuscated-execution-with-rundll32--pushd--delayed-expansion) | Investigation | `DeviceProcessEvents` |
| 6 | [ACR Stealer C2 / payload-hosting domain sweep](#query-6-acr-stealer-c2--payload-hosting-domain-sweep) | Investigation | `DeviceNetworkEvents` |
| 7 | [Non-browser process accessing Chromium credential stores (Login Dat...](#query-7-non-browser-process-accessing-chromium-credential-stores-login-data--web-data) | Investigation | `DeviceFileEvents` |
| 8 | [Python loader (pythonw.exe) launched from a user-writable Temp / ma...](#query-8-python-loader-pythonwexe-launched-from-a-user-writable-temp--masquerade-directory) | Investigation | `DeviceProcessEvents` |
| 9 | [Indicator removal — PowerShell command-history clearing](#query-9-indicator-removal--powershell-command-history-clearing) | Investigation | `DeviceProcessEvents` |


## IOC Reference

> All indicators below are transcribed verbatim from the article's *Indicators of compromise* section. **IOCs rot** — operators rotate infrastructure after disclosure. Refresh from current Microsoft TI before relying on direct-match hunts, and run IOC sweeps in Sentinel Data Lake (>30d) for retrospective coverage beyond the 30-day Advanced Hunting window.

**Campaign 1 — network indicators**

| Indicator | Type | Description |
|---|---|---|
| `looksta[.]icu` | Domain | C2 domain |
| `contrite.quirksturdy[.]icu` | Domain | C2 domain |
| `ux.strainedeasily[.]icu` | Domain | C2 domain |
| `cpppemwjewjoiwejow[.]sale` | Domain | C2 domain |
| `breaksd.wifihot[.]icu` | Domain | C2 domain |
| `walter.filloco[.]icu` | Domain | C2 domain |
| `fast.raidher[.]icu` | Domain | C2 domain |
| `apigrokcloud[.]icu` | Domain | C2 domain |

**Campaign 2 — network indicators**

| Indicator | Type | Description |
|---|---|---|
| `enhanceblabber[.]cc` | Domain | C2 domain |
| `deep-harborio[.]com` | Domain | 1st-stage payload hosting site |
| `auramatrixa[.]com` | Domain | 1st-stage payload hosting site |
| `zealpraxis[.]com` | Domain | 1st-stage payload hosting site |
| `prism-vertex[.]com` | Domain | 1st-stage payload hosting site |
| `prism-matrixs[.]com` | Domain | 1st-stage payload hosting site |
| `proton-network[.]com` | Domain | 1st-stage payload hosting site |
| `creativecommunityinfo[.]art` | Domain | Payload hosting site |

**Host / behavioral artifacts (from narrative — not in the IOC table)**

| Indicator | Type | Description |
|---|---|---|
| `google.ct` | Filename | Benign-looking DLL name on the WebDAV share (example) |
| `LogiOptionsPlus` | Directory name | Deceptive masquerade dir under `%LocalAppData%\Temp` (example) |
| `Autoupdate` | Scheduled-task marker | Task name fragment for the software-update masquerade |
| `notepad.exe` | Timestomp source | Trusted binary whose timestamps are copied to deployed files |

---

## Query 1: ClickFix RunMRU command — remote WebDAV rundll32 / pushd execution

**Purpose:** Detects the ClickFix Run-dialog command captured in the `RunMRU` registry key that launches `rundll32`/`pushd` against a remote `@SSL` WebDAV share (GUID path), including the headless/obfuscated `conhost --headless` variant. Article-provided hunt. A clean estate returns 0; any hit is a strong ClickFix initial-access indicator.  
**Severity:** High  
**MITRE:** T1189, T1204, T1218.011
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "ClickFix RunMRU remote WebDAV command on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A ClickFix-style Run-dialog command referencing a remote @SSL WebDAV share (rundll32/pushd, optionally conhost --headless) was recorded in RunMRU. Isolate/triage the device, identify the WebDAV host and dropped DLL, hunt the downstream PowerShell/Python or MSHTA chain (Queries 2-6), check scheduled-task persistence (Query 3), and review browser-credential access (Query 7)."
adaptation_notes: "Article-provided regex; high fidelity (remote @SSL WebDAV path in a RunMRU value is not legitimate). Broaden cautiously as the actor rotates command syntax."
-->

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has "RunMRU"
| where (RegistryValueData has_all ("rundll32", "@ssl", " /c ", " start ") and (RegistryValueData matches regex @"\\\\[^\\]+@ssl\\[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\\w+\.\w+,#1" or RegistryValueData matches regex @"(?i)pushd \\\\[^\\]+@ssl\\[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12} "))
    or (RegistryValueData has_all ("@ssl", " /c ", "conhost --headless ") and RegistryValueData contains "rundll32")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Any match is a high-confidence ClickFix delivery indicator warranting immediate triage.

---

## Query 2: rundll32 / pushd loading a DLL from a remote @SSL WebDAV share

**Purpose:** Behavior-based companion to Query 1 that catches the execution regardless of RunMRU — process telemetry where `rundll32.exe`/`cmd.exe`/`conhost.exe` (or a `pushd` command) references a `\\host@SSL\` WebDAV path. High fidelity: remote `@SSL` WebDAV loading via `rundll32`/`pushd` is not normal enterprise behavior.  
**Severity:** High  
**MITRE:** T1218.011, T1027
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "rundll32/pushd remote @SSL WebDAV load on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A process referenced a remote @SSL WebDAV path via rundll32/pushd (ACR Stealer Campaign 1 delivery). Isolate/triage the device, capture the loaded DLL and WebDAV host, and pivot to the PowerShell/Python loader and scheduled-task persistence (Queries 3-4) and C2 sweep (Query 6)."
adaptation_notes: "Remote @SSL WebDAV in a command line is inherently suspicious; low expected FP. If a sanctioned internal WebDAV workflow exists, exclude that specific host."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "@SSL" or InitiatingProcessCommandLine has "@SSL"
| where FileName in~ ("rundll32.exe", "cmd.exe", "conhost.exe") or ProcessCommandLine has_any ("rundll32", "pushd")
| where ProcessCommandLine matches regex @"(?i)\\\\[^\\]+@ssl\\" or InitiatingProcessCommandLine matches regex @"(?i)\\\\[^\\]+@ssl\\"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Any hit warrants DLL capture and device triage.

---

## Query 3: Scheduled-task persistence created by a malicious PowerShell script (software-update masquerade)

**Purpose:** Detects the Campaign 1 persistence mechanism — an obfuscated PowerShell stage creating/running a hidden scheduled task masquerading as an autoupdate (`schtasks /run /tn <8-digit> Autoupdate`). Article-provided hunt.  
**Severity:** High  
**MITRE:** T1053.005, T1059.001
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "PowerShell autoupdate scheduled-task persistence on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "PowerShell created/ran a scheduled task masquerading as a software update (ACR Stealer persistence). Isolate/triage the device, enumerate and remove the malicious task, hunt the masquerade directory under %LocalAppData%\\Temp and the pythonw loader (Query 5), and review browser-credential access (Query 7)."
adaptation_notes: "Article-provided pattern anchored on the numeric task-name + Autoupdate marker; high fidelity. Tune if a legitimate updater in your estate matches the exact schtasks pattern."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_all ("-Command", "powershell")
| where ProcessCommandLine has_all ("schtasks", " /run /tn ", " Autoupdate ") and ProcessCommandLine matches regex "[0-9]{8}"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Any hit indicates active persistence — remove the task and triage the host.

---

## Query 4: Suspicious MSHTA launch through PowerShell (Campaign 2 initial access)

**Purpose:** Detects the Campaign 2 fileless chain — a `powershell.exe` (spawned from `explorer.exe`, i.e., ClickFix) launching `mshta.exe` against a remote HTTPS HTA with a numeric path token. Article-provided hunt.  
**Severity:** High  
**MITRE:** T1218.005, T1189
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "PowerShell-launched remote MSHTA on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An explorer-spawned PowerShell launched mshta.exe against a remote HTA (ACR Stealer Campaign 2 delivery). Isolate/triage the device, capture the HTA URL, hunt the steganographic image retrieval and in-memory shellcode chain, run the C2 sweep (Query 6), and review browser-credential access (Query 7)."
adaptation_notes: "Article-provided pattern; anchored on explorer-parented PowerShell + remote mshta + numeric path token. High fidelity."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessParentFileName has "explorer.exe"
| where InitiatingProcessFileName =~ "powershell.exe" and InitiatingProcessCommandLine in~ ('"PowerShell.exe" ', '"PowerShell.exe"')
| where ProcessCommandLine has_all ('"mshta.exe" https://') and ProcessCommandLine matches regex "/[0-9]{7}"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Any hit is a high-confidence Campaign 2 delivery indicator.

---

## Query 5: conhost --headless obfuscated execution with rundll32 / pushd / delayed expansion

**Purpose:** Detects the stealth variant of Campaign 1 that suppresses the console via `conhost --headless` and hides `pushd`/`rundll32`/host names using environment-variable obfuscation with delayed expansion (`cmd /v`, `/v:on`).  
**Severity:** High  
**MITRE:** T1027, T1218.011
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "conhost --headless obfuscated rundll32/pushd on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A conhost --headless command combined with rundll32/pushd or delayed variable expansion was observed (ACR Stealer Campaign 1 stealth variant). Isolate/triage the device, reconstruct the deobfuscated command, and pivot to WebDAV load (Query 2) and persistence (Query 3)."
adaptation_notes: "conhost --headless paired with rundll32/pushd or /v:on is uncommon in benign automation, but validate against sanctioned headless tooling in your estate before promoting to alert."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "conhost" and ProcessCommandLine has_any ("--headless", "-headless")
| where ProcessCommandLine has_any ("rundll32", "pushd", "cmd /c", "cmd /v", "/v:on") or InitiatingProcessCommandLine has_any ("rundll32", "pushd", "/v:on")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Review any hit for the deobfuscated WebDAV/rundll32 chain.

---

## Query 6: ACR Stealer C2 / payload-hosting domain sweep

**Purpose:** Direct network sweep for the published Campaign 1 and Campaign 2 domains (C2 and first-stage payload hosting). A clean estate returns 0; any hit identifies a host contacting attacker infrastructure.  
**Severity:** High  
**MITRE:** T1102, T1568.002
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "ACR Stealer C2/payload domain contact on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A host contacted a published ACR Stealer C2 or payload-hosting domain. Isolate/triage the device, capture the initiating process, block the domain at the proxy/DNS, hunt the delivery chain (Queries 1-5) and browser-credential theft (Query 7), and rotate exposed credentials/tokens. IOCs rot — confirm against current Microsoft TI."
adaptation_notes: "Direct domain match; low FP. IOCs rot after disclosure — refresh from current Microsoft TI/VirusTotal and re-run in Sentinel Data Lake (>30d) for retrospective coverage beyond the 30-day AH window."
-->

```kql
let iocDomains = dynamic([
    "looksta.icu", "contrite.quirksturdy.icu", "ux.strainedeasily.icu", "cpppemwjewjoiwejow.sale",
    "breaksd.wifihot.icu", "walter.filloco.icu", "fast.raidher.icu", "apigrokcloud.icu",
    "enhanceblabber.cc", "deep-harborio.com", "auramatrixa.com", "zealpraxis.com",
    "prism-vertex.com", "prism-matrixs.com", "proton-network.com", "creativecommunityinfo.art"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (iocDomains) or RemoteUrl in~ (iocDomains)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment (post-disclosure domains). Any match warrants immediate triage and domain blocking.

---

## Query 7: Non-browser process accessing Chromium credential stores (Login Data / Web Data)

**Purpose:** Detects browser-credential theft — a non-browser process reading the Chromium `Login Data` / `Web Data` SQLite databases, the precursor to DPAPI-based credential/token decryption used by both campaigns. Behavioral: requires per-environment tuning of legitimate accessors.  
**Severity:** Medium  
**MITRE:** T1555.003
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "CredentialAccess"
title: "Non-browser access to Chromium credential store on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A non-browser process accessed the Chromium Login Data/Web Data credential databases (browser-credential theft). Validate the initiating process; if not a sanctioned backup/sync/security agent, isolate/triage the device, correlate with the delivery chain (Queries 1-5) and C2 (Query 6), and rotate exposed browser credentials and session tokens."
adaptation_notes: "Behavioral — not CD-ready without estate-specific tuning. Exclude the browser binaries plus known-good accessors (backup, sync, EDR/DLP agents) in your environment before promoting to a detection; treat access by an unexpected process as the signal."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("Login Data", "Web Data") or FolderPath has_any (@"\User Data\Default\Login Data", @"\User Data\Default\Web Data")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "msedgewebview2.exe", "chrome_installer.exe", "GoogleUpdate.exe", "setup.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 after excluding sanctioned accessors. Any remaining hit by an unexpected process warrants credential-theft triage and token rotation.

---

## Query 8: Python loader (pythonw.exe) launched from a user-writable Temp / masquerade directory

**Purpose:** Detects the Campaign 1 Python loader — a `pythonw.exe`/`python.exe` instance running from a deceptive directory under `%LocalAppData%\Temp` (e.g., `LogiOptionsPlus`). Behavioral: portable/packaged Python and installers can also run interpreters from `Temp`, so tuning is required.  
**Severity:** Medium  
**MITRE:** T1059.006, T1036
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "Execution"
title: "pythonw.exe launched from Temp masquerade directory on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A Python interpreter executed from a user-writable Temp/masquerade directory (ACR Stealer Campaign 1 loader pattern). Validate the parent chain and directory; if not a sanctioned packaged app, isolate/triage the device, hunt the WebDAV delivery (Query 2), scheduled-task persistence (Query 3), and C2 (Query 6)."
adaptation_notes: "Behavioral — not CD-ready without tuning. Legitimate packaged-Python apps and installers run interpreters from Temp; pair with a masquerade dir, persistence, or network IOC and exclude sanctioned vendors. Not validated against positive samples (no Python interpreter telemetry present at authoring time)."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "pythonw.exe"
| where FolderPath has_any (@"\AppData\Local\Temp", @"\AppData\Roaming") or ProcessCommandLine has_any (@"\AppData\Local\Temp", @"\AppData\Roaming")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 where no Python-from-Temp activity exists. Any hit from an unexpected masquerade directory (not a sanctioned packaged app) warrants triage.

---

## Query 9: Indicator removal — PowerShell command-history clearing

**Purpose:** Detects the Campaign 1 anti-forensic step where the loader clears PowerShell command history (`ConsoleHost_history.txt` removal / `Clear-History` / PSReadLine history purge). Behavioral: legitimate cleanup/admin scripts can match.  
**Severity:** Medium  
**MITRE:** T1070.003
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "DefenseEvasion"
title: "PowerShell command-history clearing on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "PowerShell cleared its command history (ACR Stealer anti-forensic behavior). Validate the initiating script/account; if unexpected, isolate/triage the device and correlate with the delivery and persistence chain (Queries 1-5)."
adaptation_notes: "Behavioral — not CD-ready without tuning. Legitimate cleanup/hardening scripts clear PSReadLine history; scope to unexpected accounts/parents and pair with a delivery or persistence hit before promoting to a detection."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe") or FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("ConsoleHost_history.txt", "Clear-History", "PSReadLine", "(Get-PSReadlineOption)")
    and ProcessCommandLine has_any ("Remove-Item", "del ", "Clear-History", "Clear-Content", "rm ")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in the absence of history-clearing activity. Review any hit for unexpected accounts/parents.

---

## General Tuning Notes

1. **IOC refresh.** Query 6's domain list and the host artifacts are point-in-time. ACR Stealer is offered as a MaaS and operators rotate infrastructure/payloads after disclosure — refresh from current Microsoft TI / VirusTotal and re-run domain and behavioral sweeps in **Sentinel Data Lake (>30d)** for retrospective coverage beyond the 30-day Advanced Hunting window.
2. **Telemetry gaps.** Blockchain dead-drop C2 (EtherHiding) resolves via public Web3 RPC endpoints that vary by intrusion and are not enumerated in the article — no reliable static-domain hunt is provided for it; anchor on the endpoint delivery chain instead. Python-loader coverage (Query 8) depends on interpreter telemetry being present; where Python is not used, the query is inert.
3. **Behavioral vs. direct-match.** Queries 1-6 anchor on article-provided high-fidelity markers (RunMRU/WebDAV/MSHTA regexes and direct domain IOCs) and are marked `cd_ready: true`. Queries 7-9 are behavioral (browser-cred access, Python-from-Temp, history clearing) and require per-environment exclusion tuning — they are marked `cd_ready: false` with explicit `adaptation_notes` and should be validated/tuned before promotion to custom detections (see the **detection-authoring** skill).
4. **CD-readiness summary.** 6 of 9 queries are `cd_ready: true` (Queries 1-6); 3 are `cd_ready: false` pending environment-specific tuning (Queries 7-9).

---

## References
- Microsoft Threat Intelligence — [ACR Stealer: Two observed intrusion chains amid increased threat activity](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/)
- MITRE ATT&CK — [Rundll32 (T1218.011)](https://attack.mitre.org/techniques/T1218/011/), [Mshta (T1218.005)](https://attack.mitre.org/techniques/T1218/005/), [Credentials from Web Browsers (T1555.003)](https://attack.mitre.org/techniques/T1555/003/), [Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/), [Dead Drop Resolver (T1568.002)](https://attack.mitre.org/techniques/T1568/002/)
- Companion files: [`queries/threat-intelligence/2026-02/infostealer_hunting_campaign.md`](../2026-02/infostealer_hunting_campaign.md), [`queries/threat-intelligence/2026-06/stealc_amadey_infostealer.md`](../2026-06/stealc_amadey_infostealer.md), [`queries/threat-intelligence/2026-05/code_of_conduct_aitm_phishing.md`](../2026-05/code_of_conduct_aitm_phishing.md)
