# Kazuar / Secret Blizzard (Turla) — Threat Hunts

**Created:** 2026-05-15  
**Platform:** Microsoft Defender XDR | Microsoft Sentinel  
**Tables:** DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents, DeviceEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceCustomEvents  
**Keywords:** kazuar, secret blizzard, turla, fsb center 16, hpbprndiLOC, scrcons, wmi event consumer, ews c2, named pipe, mailslot, amsi bypass, etw bypass, wldp bypass, com loader, inprocserver32, working hours beacon, periodic beacon  
**MITRE:** T1027.002, T1546.003, T1071.001, T1071.003, T1071.005, T1059.005, T1218.010, T1218.011, T1546.015, T1562.001, T1562.006, T1546, T1129, T1055, T1029, T1573  
**Domains:** endpoint  
**Timeframe:** Last 90 days (configurable per hunt)  
**Source:** [Microsoft Threat Intelligence — Kazuar: Anatomy of a nation-state botnet (May 14, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/)

---

## Threat Overview

Hunts derived from Microsoft Threat Intelligence's 2026-05-14 blog *"Kazuar: Anatomy of a nation-state botnet"* — attribution to **Secret Blizzard** (a.k.a. Turla, FSB Center 16). Kazuar is a modular .NET backdoor delivered via COM/.NET loader chains, runs in-process inside `scrcons.exe` (WMI Event Consumer host), and uses multiple long-haul C2 transports (EWS via stolen tokens, WebSocket, HTTP).

### Kazuar TTP Summary

| Capability | TTP |
|---|---|
| **Delivery** | COM/.NET loader registered under `InprocServer32` pointing to user-writable path; activated via `regsvr32.exe` or `rundll32.exe`. |
| **Execution Host** | `scrcons.exe` (WMI Standard Event Consumer) loads the worker DLL via `live_in_scrcons` technique — survives WMI permanent event subscription. |
| **Defense Evasion** | In-memory AMSI / ETW / WLDP bypass; AV/EDR tampering on Defender, Sysmon, ETW providers. |
| **IPC** | Named pipes `\\.\pipe\<32-hex-lowercase-md5>` and mailslots `\\.\mailslot\<random>` for module-to-module comms. |
| **C2** | EWS-on-Office365 (uses victim's stolen OAuth token), WebSocket over TLS, plain HTTPS; ~1-hour periodic beacon aligned to working hours. |
| **Persistence** | WMI permanent event subscriptions (`__EventFilter` + `CommandLineEventConsumer` / `ActiveScriptEventConsumer`), COM hijacking. |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| `scrcons.exe` is a legitimate WMI host — abuse is the *combination* of `scrcons.exe` + user-writable module + external network. | Use Query 4 tier filtering; don't alert on every `scrcons.exe` module load. |
| EWS C2 traffic is indistinguishable from a normal mail client at the TLS layer. | Anchor on **initiating process** != Office stack and high-entropy session duration (Query 5). |
| Named-pipe telemetry (`NamedPipeEvent` / `PipeEvent` `ActionType`) is **not collected by default MDE** in many environments — requires Sysmon EID 17/18 or MDE CDC. | Query 3 includes Variant A (standard) and Variant B (CDC fallback); document telemetry gap when both are empty. |
| `regsvr32.exe` / `rundll32.exe` from user paths is high-volume noise from legitimate installers. | Exclude trusted publisher folders (`MsMpEng`, `msiexec`, signed Defender platform updates). |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Kazuar Reference IOC Sweep — File Hashes](#query-1-kazuar-reference-ioc-sweep--file-hashes) | Investigation | `DeviceFileEvents` + multi |
| 2 | [Kazuar Loader Filename — `hpbprndiLOC.dll`](#query-2-kazuar-loader-filename--hpbprndilocdll) | Investigation | `DeviceFileEvents` + multi |
| 3 | [Kazuar Named Pipe Pattern — `\\.\pipe\<32-hex>`](#query-3-kazuar-named-pipe-pattern--pipe32-hex) | Investigation | `DeviceEvents` + multi |
| 4 | [`scrcons.exe` Abuse — WMI Event Consumer with Unusual Network or Mo...](#query-4-scrconsexe-abuse--wmi-event-consumer-with-unusual-network-or-module-behavior) | Investigation | `DeviceImageLoadEvents` |
| 5 | [EWS-Based C2 — Non-Office Initiators Reaching Exchange Web Services](#query-5-ews-based-c2--non-office-initiators-reaching-exchange-web-services) | Investigation | `DeviceNetworkEvents` |
| 6 | [AMSI / ETW / WLDP Bypass and Defender Tampering Signals](#query-6-amsi--etw--wldp-bypass-and-defender-tampering-signals) | Investigation | `DeviceEvents` |
| 7 | [Working-Hours Periodic Beacon — Hour-Aligned C2 Heartbeat](#query-7-working-hours-periodic-beacon--hour-aligned-c2-heartbeat) | Investigation | `DeviceNetworkEvents` |
| 8 | [COM / .NET Loader Pattern — `InprocServer32` to User-Writable Path](#query-8-com--net-loader-pattern--inprocserver32-to-user-writable-path) | Investigation | `DeviceProcessEvents` |


## IOC Reference

The following SHA-256 hashes and filename indicator are published in the [Microsoft Threat Intelligence blog (May 14, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/). Refresh against current MS TI / VirusTotal periodically — operators rotate.

| SHA-256 | Component |
|---|---|
| `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4` | `hpbprndiLOC.dll` (Loader) |
| `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9` | Kernel module |
| `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d` | Bridge module |
| `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85` | Worker module |

**Filename IOC:** `hpbprndiLOC.dll` (loader DLL) — hunted by name in Query 2 in case the hash has rotated.

---

## Query 1: Kazuar Reference IOC Sweep — File Hashes

**Purpose:** Hash-based detection for the four published Kazuar SHA-256 IOCs across file, image-load, and process surfaces. Direct IOC match — zero results expected in clean environments and is the desired outcome.  
**Severity:** High  
**MITRE:** T1027.002  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceFileEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1027.002"]
cd_entities: ["device", "file"]
cd_adaptation_notes: "Direct IOC match. Static hash list — IOCs will rot. Recommend external CTI feed or TI indicator table refresh."
-->
```kql
let KazuarHashes = dynamic([
    "69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4",  // hpbprndiLOC.dll loader
    "c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9",  // Kernel module
    "6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d",  // Bridge module
    "436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85"   // Worker module
]);
union 
    (DeviceFileEvents
        | where TimeGenerated > ago(90d)
        | where SHA256 in (KazuarHashes)
        | extend Surface = "FileEvent"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName),
    (DeviceImageLoadEvents
        | where TimeGenerated > ago(90d)
        | where SHA256 in (KazuarHashes)
        | extend Surface = "ImageLoad", ActionType = "ImageLoaded"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName),
    (DeviceProcessEvents
        | where TimeGenerated > ago(90d)
        | where SHA256 in (KazuarHashes)
        | extend Surface = "ProcessLaunch"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName=AccountName)
```
**Expected results:** Zero rows in uncompromised environments. Any hit = high-confidence Kazuar indicator. Refresh hash list periodically from current MS TI / VirusTotal — these are sample hashes only.

---

## Query 2: Kazuar Loader Filename — `hpbprndiLOC.dll`

**Purpose:** Filename-anchored hunt for the published Kazuar loader DLL. Covers all three surfaces (file write, image load, process initiator) in case the hash has rotated but the operator reused the filename.  
**Severity:** High  
**MITRE:** T1027.002, T1129  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceFileEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1027.002", "T1129"]
cd_entities: ["device", "file"]
cd_adaptation_notes: "Filename is a published IOC and unusual — minimal FP risk. Operator may rename in next campaign; keep but pair with Query 1."
-->
```kql
let LoaderName = "hpbprndiLOC.dll";
union 
    (DeviceFileEvents
        | where TimeGenerated > ago(90d)
        | where FileName =~ LoaderName
        | extend Surface = "FileEvent"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName),
    (DeviceImageLoadEvents
        | where TimeGenerated > ago(90d)
        | where FileName =~ LoaderName
        | extend Surface = "ImageLoad", ActionType = "ImageLoaded"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName),
    (DeviceProcessEvents
        | where TimeGenerated > ago(90d)
        | where InitiatingProcessFileName =~ LoaderName or FileName =~ LoaderName
        | extend Surface = "ProcessLaunch"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName=AccountName)
| order by TimeGenerated desc
```
**Expected results:** Zero rows expected. Pair with Query 1 — any single hit warrants immediate device isolation and forensic image.

---

## Query 3: Kazuar Named Pipe Pattern — `\\.\pipe\<32-hex>`

**Purpose:** Detects Kazuar's IPC convention — named pipes whose name is a 32-character lowercase hex string (MD5 fingerprint). This is a high-fidelity heuristic but requires named-pipe telemetry which standard MDE does NOT collect by default. Provides Variant A (standard tables) and Variant B (CDC fallback).  
**Severity:** Medium  
**MITRE:** T1559, T1055  
<!-- cd-metadata
cd_ready: false
cd_table: DeviceEvents
cd_frequency: Hourly
cd_severity: Medium
cd_mitre: ["T1559", "T1055"]
cd_entities: ["device"]
cd_adaptation_notes: "TELEMETRY GAP: Variant A (DeviceEvents NamedPipeEvent) returns 0 rows in lab — standard MDE does not collect named pipe events. Variant B (DeviceCustomEvents) requires MDE Custom Data Collection rule for Sysmon EID 17/18 OR ETW provider 'Microsoft-Windows-Kernel-Pipe'. Without one of these, hunt is blind. Document the telemetry gap before tuning."
-->
```kql
// Variant A — standard DeviceEvents (NamedPipeEvent / PipeEvent ActionTypes)
// May return 0 rows even in compromised environments without pipe telemetry uplift.
DeviceEvents
| where TimeGenerated > ago(90d)
| where ActionType in~ ("NamedPipeEvent", "PipeEvent", "NamedPipeCreated", "NamedPipeConnected")
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| where isnotempty(PipeName)
| where PipeName matches regex @"^\\\\\.\\pipe\\[a-f0-9]{32}$"
| project TimeGenerated, DeviceName, ActionType, PipeName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by TimeGenerated desc
```
```kql
// Variant B — DeviceCustomEvents (MDE CDC) fallback for environments with Sysmon EID 17/18 ingestion
DeviceCustomEvents
| where TimeGenerated > ago(90d)
| where ActionType in~ ("Sysmon17", "Sysmon18", "PipeCreated", "PipeConnected")
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| where isnotempty(PipeName)
| where PipeName matches regex @"^\\\\\.\\pipe\\[a-f0-9]{32}$"
| project TimeGenerated, DeviceName, ActionType, PipeName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated desc
```
**Expected results:** Zero rows in clean environments. In labs without CDC-uplifted pipe telemetry, both variants return 0 = absence-unconfirmable. Recommend deploying MDE CDC rule for `Microsoft-Windows-Kernel-Pipe` ETW provider before relying on this hunt for detection.

---

## Query 4: `scrcons.exe` Abuse — WMI Event Consumer with Unusual Network or Module Behavior

**Purpose:** `scrcons.exe` is the WMI Standard Event Consumer host — Kazuar's `live_in_scrcons` technique loads modules in-process. Tier 1 flags `scrcons.exe` loading DLLs from user-writable paths (high fidelity); Tier 2 flags `scrcons.exe` making outbound external connections (medium fidelity, can have legitimate enterprise WMI subscriptions).  
**Severity:** High (Tier 1) / Medium (Tier 2)  
**MITRE:** T1546.003, T1059.005, T1546  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceImageLoadEvents
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1546.003", "T1059.005"]
cd_entities: ["device", "process"]
cd_adaptation_notes: "Tier 1 (image load from user-writable path) is high-fidelity — promote to NRT. Tier 2 (external network) requires tuning per environment; some orgs have legitimate WMI subscriptions reaching internal endpoints, but external destinations are rare."
-->
```kql
// Tier 1 — scrcons.exe loading modules from user-writable paths
let UserWritablePathPattern = @"(?i)\\users\\|\\programdata\\|\\appdata\\|\\temp\\|\\public\\";
DeviceImageLoadEvents
| where TimeGenerated > ago(90d)
| where InitiatingProcessFileName =~ "scrcons.exe"
| where FolderPath matches regex UserWritablePathPattern
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by TimeGenerated desc
```
```kql
// Tier 2 — scrcons.exe initiating external network connections
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where InitiatingProcessFileName =~ "scrcons.exe"
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| summarize ConnCount = count(), DistinctRemoteIPs = dcount(RemoteIP), SampleUrls = make_set(RemoteUrl, 5)
    by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, 1d)
| order by ConnCount desc
```
**Expected results:** Tier 1: zero rows in clean environments — any hit warrants investigation of the loaded module. Tier 2: low-volume in most environments; investigate any device with sustained external connections from `scrcons.exe`.

---

## Query 5: EWS-Based C2 — Non-Office Initiators Reaching Exchange Web Services

**Purpose:** Kazuar abuses stolen OAuth tokens to use Exchange Web Services (EWS) at `outlook.office365.com` as a C2 channel. Anchor: connection to EWS endpoint from a process that is NOT part of the legitimate Office mail stack. Tier-scored by suspicion (signed Microsoft process vs unsigned vs script host).  
**Severity:** Medium  
**MITRE:** T1071.003  
<!-- cd-metadata
cd_ready: false
cd_table: DeviceNetworkEvents
cd_frequency: Hourly
cd_severity: Medium
cd_mitre: ["T1071.003"]
cd_entities: ["device", "process"]
cd_adaptation_notes: "Research-tier. The Office allow-list will vary by environment — some shops use third-party mail clients or in-house Exchange tooling. Tune the OfficeStack list before promotion. Residual rows with empty InitiatingProcessFileName (network-stack-level traffic) are unavoidable noise."
-->
```kql
let OfficeStack = dynamic([
    "outlook.exe", "msoutlook.exe", "lync.exe", "onedrive.exe", "teams.exe", "ms-teams.exe", 
    "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "msaccess.exe", "mspub.exe",
    "officeclicktorun.exe", "msouc.exe", "groove.exe", "msoia.exe", "communicator.exe",
    "wisptis.exe", "searchprotocolhost.exe", "searchindexer.exe", "searchfilterhost.exe",
    // Known telemetry/compliance agents that legitimately touch EWS:
    "lastmiletelemetryclient.exe", "apphostregistrationverifier.exe", "mipdlp.exe", 
    "msedgewebview2.exe", "explorer.exe", "startmenuexperiencehost.exe"
]);
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl has "outlook.office365.com" or RemoteUrl has "outlook.office.com"
| where RemotePort == 443
| where isnotempty(InitiatingProcessFileName)
| where InitiatingProcessFileName !in~ (OfficeStack)
| extend SuspicionTier = case(
    InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "scrcons.exe", "regsvr32.exe", "rundll32.exe"), "Tier1-ScriptOrLolbas",
    InitiatingProcessFolderPath matches regex @"(?i)\\users\\|\\programdata\\|\\appdata\\|\\temp\\", "Tier2-UserWritablePath",
    "Tier3-OtherSignedProcess")
| summarize ConnCount = count(), DistinctRemoteIPs = dcount(RemoteIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName, SuspicionTier
| order by SuspicionTier asc, ConnCount desc
```
**Expected results:** Most hits will be Tier3 (legitimate signed processes that talk to EWS for sync or telemetry). Tier1 (script/lolbas) and Tier2 (user-writable path) are high-priority investigation candidates. Lab result: residual rows of empty-initiator network-stack noise after exclusion list — acceptable.

---

## Query 6: AMSI / ETW / WLDP Bypass and Defender Tampering Signals

**Purpose:** Kazuar tampers with AMSI, ETW, and WLDP (Windows Lockdown Policy) at runtime to evade scanning. Tier 1 catches explicit MDE-flagged bypass/tamper actions (high fidelity, very rare). Tier 2 collects ASR-rule-adjacent signals that often surface in benign Credential Guard / svchost interactions — informational only.  
**Severity:** High (Tier 1) / Low (Tier 2)  
**MITRE:** T1562.001, T1562.006  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1562.001", "T1562.006"]
cd_entities: ["device", "process"]
cd_adaptation_notes: "Tier 1 only — DO NOT include PowerShellCommand ActionType (returns 80k+ benign rows). Tier 1 actions are near-zero baseline events; any hit is high-priority. Tier 2 is informational/baselining only — do not promote to detection."
-->
```kql
// Tier 1 — explicit bypass/tamper ActionTypes (high fidelity)
DeviceEvents
| where TimeGenerated > ago(90d)
| where ActionType in~ (
    "AmsiBypassDetected", "AmsiScanBypass", "AmsiTamperAttempt",
    "EtwTamperingAttempt", "EtwSessionTampering", 
    "WldpBypass", "AntimalwareEngineDisabled", "AntivirusDisabled",
    "DefenderRealTimeProtectionTurnedOff", "TamperingAttempt")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated desc
```
```kql
// Tier 2 — ASR ancillary signals (informational; baseline before alerting)
DeviceEvents
| where TimeGenerated > ago(90d)
| where ActionType has_any ("AsrLsassCredentialTheft", "AsrOfficeChildProcess", "AsrPsExec", "AsrUntrustedExecutable", "AsrScriptObfuscatedMacro")
| summarize HitCount = count(), DistinctDevices = dcount(DeviceName), SampleInitiators = make_set(InitiatingProcessFileName, 10)
    by ActionType, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```
**Expected results:** Tier 1: zero rows in clean environments. Tier 2: low-to-moderate volume — use for baselining; investigate spikes or new initiator processes.

---

## Query 7: Working-Hours Periodic Beacon — Hour-Aligned C2 Heartbeat

**Purpose:** Kazuar uses a ~1-hour beacon aligned to victim working hours (06:00–22:00 local). Detects processes making periodic outbound connections to the same external destination at hour-resolution intervals. Tuned to exclude noisy Azure/Intune/RDS management agents.  
**Severity:** Medium  
**MITRE:** T1029, T1071.001  
<!-- cd-metadata
cd_ready: false
cd_table: DeviceNetworkEvents
cd_frequency: Hourly
cd_severity: Medium
cd_mitre: ["T1029", "T1071.001"]
cd_entities: ["device", "process"]
cd_adaptation_notes: "Research-tier. MinConns threshold (20) is environment-dependent — tune higher for noisy enterprises. ExcludedFolders list covers known Azure/Intune/RDInfra agents from lab tuning; expand per environment. Consider adding signed-publisher exclusion."
-->
```kql
let MinConns = 20;
let ExcludedFolders = dynamic([
    @"c:\windowsazure\",
    @"c:\packages\plugins\",
    @"c:\program files\microsoft intune management extension\",
    @"c:\program files\microsoft monitoring agent\",
    @"c:\program files\rdinfra\",
    @"c:\windows\system32\config\systemprofile\appdata\local\rdinfraagentmanagerextension\"
]);
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteIPType == "Public"
| where isnotempty(InitiatingProcessFileName)
| where datetime_part("hour", TimeGenerated) between (6 .. 22)
| extend LowerFolder = tolower(InitiatingProcessFolderPath)
| where not(LowerFolder has_any (ExcludedFolders))
| summarize 
    ConnCount = count(), 
    DistinctHours = dcount(bin(TimeGenerated, 1h)),
    DistinctDays = dcount(bin(TimeGenerated, 1d)),
    FirstSeen = min(TimeGenerated), 
    LastSeen = max(TimeGenerated)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort
| where ConnCount >= MinConns
| extend HoursPerDay = todouble(DistinctHours) / todouble(DistinctDays)
| where HoursPerDay >= 4.0 and DistinctDays >= 3
| order by ConnCount desc
```
**Expected results:** After exclusion tuning, residual rows are candidates for beacon investigation. Sort by `HoursPerDay` × `DistinctDays` to surface the most regular periodicity. Cross-check `RemoteIP` against threat intel.

---

## Query 8: COM / .NET Loader Pattern — `InprocServer32` to User-Writable Path

**Purpose:** Detects Kazuar's loader delivery — a COM class registered with `InprocServer32` pointing to a user-writable DLL, activated via `regsvr32.exe` or `rundll32.exe`. Tier 1 watches process launches; Tier 2 watches the registry write to `InprocServer32`.  
**Severity:** High (Tier 1) / Medium (Tier 2)  
**MITRE:** T1218.010, T1218.011, T1546.015  
<!-- cd-metadata
cd_ready: false
cd_table: DeviceProcessEvents
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1218.010", "T1218.011", "T1546.015"]
cd_entities: ["device", "process", "registry"]
cd_adaptation_notes: "Tier 1 needs additional process-tree context (parent process) for true ready state — currently raw process launches will fire on legitimate installers despite folder exclusions. Tier 2 requires per-environment review of CLSID registration patterns; Defender platform updates and MSI installers touch InprocServer32 keys frequently."
-->
```kql
// Tier 1 — regsvr32/rundll32 launching from user-writable path
let UserWritablePathPattern = @"(?i)\\users\\|\\programdata\\|\\appdata\\|\\temp\\|\\public\\";
let TrustedInitiators = dynamic(["msiexec.exe", "msmpeng.exe", "trustedinstaller.exe", "windowsupdatebox.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| where FileName in~ ("regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine matches regex UserWritablePathPattern
| where tolower(InitiatingProcessFileName) !in~ (TrustedInitiators)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName=AccountName
| order by TimeGenerated desc
```
```kql
// Tier 2 — InprocServer32 registry writes pointing to user-writable paths
let UserWritablePathPattern = @"(?i)\\users\\|\\programdata\\|\\appdata\\|\\temp\\|\\public\\";
let TrustedInitiators = dynamic(["msiexec.exe", "msmpeng.exe", "trustedinstaller.exe"]);
DeviceRegistryEvents
| where TimeGenerated > ago(90d)
| where ActionType in~ ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has "InprocServer32"
| where RegistryValueData matches regex UserWritablePathPattern
| where tolower(InitiatingProcessFileName) !in~ (TrustedInitiators)
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by TimeGenerated desc
```
**Expected results:** After exclusion tuning, residual rows in either tier are candidates for loader investigation. Pair with Query 1/2 hash and filename checks on the referenced DLL path.

---

## General Tuning Notes

1. **Refresh IOCs:** Hashes in Query 1 are from the May 2026 article. Operators rotate. Re-pull from MS TI / VirusTotal periodically.
2. **Telemetry gap (Query 3):** Named-pipe events require Sysmon EID 17/18 or MDE Custom Data Collection. Without those, the hunt is blind — document this before relying on absence-of-results.
3. **CD-readiness:** Q1, Q2, Q4, Q6-Tier-1 are marked `cd_ready: true` — high-fidelity, low-noise candidates for custom detection rules. Q3, Q5, Q7, Q8 are research-tier — tune per environment before promoting.
4. **Cross-environment tuning:** Exclusion lists in Q5 (Office stack + telemetry agents), Q7 (Azure/Intune/RDS folders), and Q8 (trusted installer initiators) were calibrated against a representative lab environment; expand per-environment as needed.
5. **Pivot strategy:** A Query 1 or Query 2 hit should trigger immediate device isolation, followed by Query 3-8 retro-hunts scoped to the affected device(s) for full attack-chain reconstruction.

---

## References

- Microsoft Threat Intelligence — [Kazuar: Anatomy of a nation-state botnet (May 14, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/)
- MITRE ATT&CK — [Secret Blizzard / Turla (G0010)](https://attack.mitre.org/groups/G0010/), [Kazuar (S0265)](https://attack.mitre.org/software/S0265/)
- Microsoft Defender Threat Analytics — Actor profile: *Secret Blizzard*
- Companion files: [`queries/endpoint/rare_process_chains.md`](../../endpoint/rare_process_chains.md), [`queries/network/network_anomaly_detection.md`](../../network/network_anomaly_detection.md), [`queries/cloud/graph_api_security_monitoring.md`](../../cloud/graph_api_security_monitoring.md)
