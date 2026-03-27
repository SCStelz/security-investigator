# Windows Startup Folder Persistence Hunting

**Created:** 2026-03-27  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents  
**Keywords:** startup folder, persistence, autostart, boot or logon, Start Menu, msbuild masquerade, file write, baseline, outlier, registry run key, CurrentVersion Run, T1547.001, Sysmon EventID 11  
**MITRE:** T1547.001, T1036.005  
**Timeframe:** Last 30 days (configurable)

---

## Overview

The Windows Startup folder (`%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\`) is one of the oldest — and still actively exploited — persistence mechanisms. Any executable, script, or shortcut placed in this directory runs automatically when the user logs in.

Despite being well-known, this technique continues to appear in active campaigns because:
- Many environments don't actively monitor file writes to this path
- Legitimate software occasionally writes here, creating noise that masks malicious activity
- It requires no elevated privileges (user-level Startup folder)
- No registry modification needed — harder to detect than Run key persistence

### Current Campaign Relevance

The **TeamPCP supply chain campaign** (March 2026 — Trivy, LiteLLM, Checkmarx) drops a payload named `msbuild.exe` in this exact location, masquerading as the legitimate Microsoft Build Engine. The infection chain:
1. Compromised PyPI package installed via `pip install`
2. Payloads hidden inside WAV audio files (steganography)
3. Decoded payload written to `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\msbuild.exe`
4. Persistence achieved — payload executes on every user login

See also: [python_supply_chain_attack.md](python_supply_chain_attack.md) for the full LiteLLM/TeamPCP hunting campaign.

### MITRE ATT&CK Coverage

| Technique | ID | Relevance |
|-----------|----|-----------|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | File writes to Startup folder for login persistence |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Naming payloads after legitimate binaries (e.g., `msbuild.exe`) |

### Hunting Strategy

1. **Baseline** what legitimately writes to the Startup folder fleet-wide (Query 1)
2. **Identify outliers** that deviate from the baseline (Query 2)
3. **Hunt for masquerading** — files with legitimate names but wrong metadata/paths (Query 3)
4. **Detect suspicious file types** — executables, scripts, and encoded payloads (Query 4)
5. **Trace process lineage** — what process wrote the file? (Query 5)
6. **Hunt for execution from Startup folder** — processes launched from this path (Query 6)
7. **Monitor All-Users Startup folder** — machine-level persistence requiring admin privileges (Query 7)
8. **Baseline Registry Run keys** — companion T1547.001 mechanism via `CurrentVersion\Run` (Query 8)
9. **Detect Run key outliers** — rare autostart registry entries across the fleet (Query 9)

### Data Lake / Extended Lookback Note

All queries use `Timestamp` for Advanced Hunting (≤30d). For **Sentinel Data Lake** lookback (90d+), change `Timestamp` → `TimeGenerated`. The `has_any` operator works identically in both platforms — verified by testing that `has_any` and `contains` return the same result count on real Startup folder paths.

In this environment, Startup folder writes are very sparse (only 2 events in 90d). **Registry Run keys (Queries 8–9) are the far more active T1547.001 mechanism** — prioritize those for ongoing monitoring.

---

## Query Catalog

### Query 1 — Startup Folder Baseline: What Normally Writes Here (DeviceFileEvents)

**Goal:** Establish a fleet-wide baseline of all file creation activity in the Startup folder. Group by initiating process and filename to identify what's "normal" in your environment. Run this first, then subtract known-good from subsequent hunts.  
**MITRE:** T1547.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline/inventory query using summarize with make_set and dcount — not suitable for CD alerting."
-->

```kql
// Baseline: What processes write files to the Startup folder across the fleet?
// Run this FIRST to understand normal activity, then exclude known-good in outlier queries
let StartupPaths = dynamic([
    @"\Start Menu\Programs\Startup\",
    @"\Start Menu\Programs\startup\"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (StartupPaths)
// Exclude common temp/zone identifier files that add noise
| where not(FileName endswith ":Zone.Identifier")
| summarize 
    FileCount = count(),
    DeviceCount = dcount(DeviceName),
    Devices = make_set(DeviceName, 25),
    Users = make_set(InitiatingProcessAccountName, 25),
    FileNames = make_set(FileName, 50),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by InitiatingProcessFileName
| order by DeviceCount desc, FileCount desc
```

**Tested 2026-03-27 (90d Data Lake):** `has_any` operator verified — returns identical results to `contains` (tested both operators, same 2-row output). In this environment, only `onenote.exe` creating `Send to OneNote.lnk` on 2 devices over the past 90 days. Startup folder file writes are very sparse — Run key persistence (Query 8–9) is far more active in this fleet.

**Expected output:** A short list of legitimate processes (e.g., `explorer.exe`, `OneDrive.exe`, application installers) that routinely write to the Startup folder. Anything not on this list in subsequent queries is an outlier worth investigating.

---

### Query 2 — Startup Folder Outlier Detection (DeviceFileEvents)

**Goal:** Find file writes to the Startup folder that are rare across the fleet — files seen on very few devices from uncommon initiating processes. These are your top-priority investigation targets.  
**MITRE:** T1547.001

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "Rare file written to Startup folder on {{DeviceName}} by {{InitiatingProcessFileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: initiatingProcessAccountName
recommendedActions: "Investigate the file written to the Startup folder. Check if the initiating process is legitimate. Verify file hash against threat intelligence. If suspicious, isolate the device and collect the file for analysis."
adaptation_notes: "Needs restructuring from summarize to row-level output. Remove make_set, keep per-event rows with DeviceId + ReportId."
-->

```kql
// Find RARE file writes to Startup folder — outliers that deviate from fleet baseline
// Tune the DeviceThreshold to match your environment (start with 3, lower for stricter detection)
let LookbackPeriod = 30d;
let DeviceThreshold = 3; // Files seen on <= this many devices are flagged as outliers
let StartupPaths = dynamic([
    @"\Start Menu\Programs\Startup\",
    @"\Start Menu\Programs\startup\"
]);
// Step 1: Calculate fleet prevalence for each (FileName + InitiatingProcess) pair
let FilePrevalence = DeviceFileEvents
    | where Timestamp > ago(LookbackPeriod)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FolderPath has_any (StartupPaths)
    | where not(FileName endswith ":Zone.Identifier")
    | summarize DevicesSeen = dcount(DeviceName) by FileName, InitiatingProcessFileName;
// Step 2: Return individual events for rare files
DeviceFileEvents
| where Timestamp > ago(LookbackPeriod)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (StartupPaths)
| where not(FileName endswith ":Zone.Identifier")
| lookup kind=inner (
    FilePrevalence | where DevicesSeen <= DeviceThreshold
) on FileName, InitiatingProcessFileName
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    SHA1,
    FileSize,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    DevicesSeen
| order by DevicesSeen asc, Timestamp desc
```

**Tuning guidance:**
- `DeviceThreshold = 3`: Start here — flags files that appeared on 3 or fewer devices in 30 days
- `DeviceThreshold = 1`: Strictest — only files unique to a single device (highest true positive rate, may miss slow-spreading malware)
- `DeviceThreshold = 5`: Looser — use if your fleet has many diverse software configurations

---

### Query 3 — Masquerading Detection: Legitimate Names, Wrong Metadata (DeviceFileEvents + DeviceProcessEvents)

**Goal:** Detect files in the Startup folder that use names of legitimate Windows binaries (like `msbuild.exe`, `svchost.exe`, `explorer.exe`) but were written by unexpected processes or have wrong version metadata. Directly relevant to the TeamPCP campaign which drops a payload named `msbuild.exe`.  
**MITRE:** T1547.001, T1036.005

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "Masquerading file '{{FileName}}' in Startup folder on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: initiatingProcessAccountName
recommendedActions: "A file with the name of a legitimate Windows binary was written to the Startup folder. This is a high-confidence indicator of masquerading (T1036.005). Isolate the device, collect the file for hash analysis, check for related supply chain compromise indicators."
adaptation_notes: "Row-level output. Add DeviceId + ReportId columns."
-->

```kql
// Detect files in Startup folder masquerading as legitimate Windows binaries
// HIGH confidence for malicious activity — legitimate tools never drop system binaries here
let StartupPaths = dynamic([
    @"\Start Menu\Programs\Startup\",
    @"\Start Menu\Programs\startup\"
]);
// Known system binary names attackers commonly masquerade as
let MasqueradeNames = dynamic([
    "msbuild.exe", "svchost.exe", "explorer.exe", "csrss.exe", "lsass.exe",
    "services.exe", "smss.exe", "winlogon.exe", "taskhostw.exe", "conhost.exe",
    "RuntimeBroker.exe", "dllhost.exe", "SearchIndexer.exe", "spoolsv.exe",
    "wininit.exe", "dwm.exe", "ctfmon.exe", "audiodg.exe", "WmiPrvSE.exe",
    "System.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe",
    "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (StartupPaths)
| where FileName in~ (MasqueradeNames)
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    SHA1,
    FileSize,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileOriginUrl,
    FileOriginReferrerUrl
| order by Timestamp desc
```

**Why this is high-confidence:** Legitimate Windows system binaries are NEVER installed to the Startup folder. Any match is suspicious by default. The `msbuild.exe` case from TeamPCP is a textbook example — the real MSBuild lives in `C:\Windows\Microsoft.NET\Framework\` or Program Files, never in `%AppData%\...Startup\`.

---

### Query 4 — Suspicious File Types in Startup Folder (DeviceFileEvents)

**Goal:** Hunt for executables, scripts, encoded files, and other suspicious file types written to the Startup folder. Legitimate Startup entries are typically `.lnk` shortcut files or well-known application executables — anything else warrants investigation.  
**MITRE:** T1547.001

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "Suspicious file type '{{FileName}}' dropped in Startup folder on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: initiatingProcessAccountName
recommendedActions: "Investigate the file dropped in the Startup folder. Script files (.bat, .vbs, .ps1, .js) and unusual executables are high-priority. Check file contents and initiating process chain."
adaptation_notes: "Row-level output. Add DeviceId + ReportId columns."
-->

```kql
// Hunt for suspicious file types dropped in the Startup folder
// Normal: .lnk shortcuts from installed software
// Suspicious: executables, scripts, encoded files, DLLs, Office macros
let StartupPaths = dynamic([
    @"\Start Menu\Programs\Startup\",
    @"\Start Menu\Programs\startup\"
]);
let SuspiciousExtensions = dynamic([
    ".exe", ".dll", ".scr", ".com", ".pif",          // Executables
    ".bat", ".cmd",                                    // Batch scripts
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",   // Script files
    ".ps1", ".psm1", ".psd1",                          // PowerShell
    ".hta",                                            // HTML Application
    ".py", ".pyw",                                     // Python scripts
    ".jar",                                            // Java archive
    ".wav", ".mp3",                                    // Steganography (TeamPCP hid payloads in WAV files)
    ".tmp", ".dat", ".bin",                            // Unusual data files
    ".iso", ".img",                                    // Disk images
    ".docm", ".xlsm", ".pptm"                         // Macro-enabled Office docs
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (StartupPaths)
| where not(FileName endswith ":Zone.Identifier")
| extend FileExtension = tolower(strcat(".", tostring(split(FileName, ".")[-1])))
| where FileExtension in (SuspiciousExtensions)
    or not(FileExtension in (".lnk", ".ini", ".url")) // Also catch unknown extensions
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    ActionType,
    FileName,
    FileExtension,
    FolderPath,
    SHA256,
    SHA1,
    FileSize,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileOriginUrl
| order by Timestamp desc
```

**Note on steganography:** The TeamPCP campaign hid payloads inside `.wav` audio files. While audio files in a Startup folder are obviously suspicious, some advanced attacks may use seemingly benign file types as payload containers — the suspicious extensions list includes `.wav`, `.tmp`, `.dat`, `.bin` for this reason.

---

### Query 5 — Process Lineage: What Wrote to Startup? (DeviceFileEvents)

**Goal:** Trace the full process chain that led to a file being written to the Startup folder. This reveals whether the write came from user activity (e.g., `explorer.exe` file copy), an installer (`msiexec.exe`), or a suspicious process chain (e.g., `python.exe` → decoded payload → file write).  
**MITRE:** T1547.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Enrichment/forensic query — multi-hop process chain not suitable for CD alerting."
-->

```kql
// Trace the full process chain for ANY file write to the Startup folder
// Focus on the initiating process hierarchy to understand how the file got there
let StartupPaths = dynamic([
    @"\Start Menu\Programs\Startup\",
    @"\Start Menu\Programs\startup\"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (StartupPaths)
| where not(FileName endswith ":Zone.Identifier")
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    // File details
    FileName,
    FolderPath,
    SHA256,
    FileSize,
    ActionType,
    // Process chain (3 levels deep)
    Level1_Process = InitiatingProcessFileName,
    Level1_Path = InitiatingProcessFolderPath,
    Level1_CmdLine = InitiatingProcessCommandLine,
    Level2_Process = InitiatingProcessParentFileName,
    // File origin (for downloads)
    FileOriginUrl,
    FileOriginReferrerUrl,
    FileOriginIP
| extend ProcessChain = strcat(Level2_Process, " → ", Level1_Process, " → [write] ", FileName)
| order by Timestamp desc
```

**What to look for in the process chain:**
- 🟢 `explorer.exe → [write] shortcut.lnk` — user or installer placing a shortcut (normal)
- 🟢 `msiexec.exe → [write] app.lnk` — MSI installer adding a startup entry (normal if expected)
- 🔴 `python.exe → [write] msbuild.exe` — supply chain payload dropping persistence (TeamPCP)
- 🔴 `powershell.exe → [write] update.bat` — script-based persistence drop
- 🔴 `cmd.exe → [write] svchost.exe` — masquerading binary from command line
- 🟠 Unknown process → [write] .exe — requires further investigation

---

### Query 6 — Execution FROM the Startup Folder (DeviceProcessEvents)

**Goal:** Detect processes launched from the Startup folder path. Complements the file-write queries — even if you missed the file drop, you can catch the payload executing on next login.  
**MITRE:** T1547.001

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "Process '{{FileName}}' executed from Startup folder on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "A process was executed from the Startup folder. Verify the file is legitimate software. Check the file hash against threat intelligence. If unexpected, isolate the device and collect the binary for analysis."
adaptation_notes: "Row-level output. Add DeviceId + ReportId columns."
-->

```kql
// Detect process execution FROM the Startup folder
// Catches payloads on execution even if the file drop was missed
let StartupPaths = dynamic([
    @"\Start Menu\Programs\Startup\",
    @"\Start Menu\Programs\startup\"
]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (StartupPaths)
| project 
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256,
    SHA1,
    FileSize,
    ProcessVersionInfoCompanyName,
    ProcessVersionInfoProductName,
    ProcessVersionInfoOriginalFileName,
    ProcessVersionInfoFileDescription,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

**Key enrichment for results:** Compare `FileName` vs `ProcessVersionInfoOriginalFileName` — if a file claims to be `msbuild.exe` but has no Microsoft version info, or `OriginalFileName` doesn't match, it's masquerading. Legitimate `msbuild.exe` will have `ProcessVersionInfoCompanyName == "Microsoft Corporation"` and `ProcessVersionInfoOriginalFileName == "MSBuild.exe"`.

---

### Query 7 — All-Users (Machine-Level) Startup Folder Monitoring (DeviceFileEvents)

**Goal:** Monitor the machine-level Startup folder (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`) which requires admin privileges to write to. File writes here affect ALL users on the device — higher impact than user-level persistence.  
**MITRE:** T1547.001

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "File '{{FileName}}' written to All-Users Startup folder on {{DeviceName}} (admin required)"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: initiatingProcessAccountName
recommendedActions: "A file was written to the machine-level Startup folder, which requires admin privileges and affects ALL users. This is higher severity than user-level persistence. Verify the file and initiating process immediately."
adaptation_notes: "Row-level output. Add DeviceId + ReportId columns."
-->

```kql
// Monitor the ALL-USERS Startup folder (requires admin privileges to write)
// Higher severity than user-level — affects every user who logs into the device
let AllUsersStartupPaths = dynamic([
    @"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\",
    @"ProgramData\Microsoft\Windows\Start Menu\Programs\startup\"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (AllUsersStartupPaths)
| where not(FileName endswith ":Zone.Identifier")
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    SHA1,
    FileSize,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessTokenElevation
| order by Timestamp desc
```

**Why this matters:** The user-level Startup folder (Queries 1–6) runs code as the individual user. The All-Users folder runs code as whoever logs in. An attacker with admin access will prefer this folder for broader persistence. The `InitiatingProcessTokenElevation` field shows whether the writing process was elevated.

---

### Query 8 — Registry Run Key Baseline (DeviceRegistryEvents)

**Goal:** Establish a fleet-wide baseline of all `CurrentVersion\Run` and `RunOnce` registry modifications. This is the companion detection to the Startup folder — same MITRE technique (T1547.001), but via registry instead of file system. In practice, Run keys are far more commonly used for autostart persistence than the Startup folder.  
**MITRE:** T1547.001

**Tested 2026-03-27 (30d AH + 90d Data Lake):** Returns active telemetry. Typical baseline in a managed Microsoft 365 environment includes: `MicrosoftEdgeAutoLaunch_*` (msedge.exe), `OneDrive` (onedrive.exe/onedrivesetup.exe), `Microsoft.Lists` (onedrivesetup.exe/onedrive.sync.service.exe), `Teams` (ms-teams.exe), `GlobalSecureAccessClient` (msiexec.exe — Microsoft Entra GSA). The 90d lookback also surfaced single-device entries: `Docker Desktop`, `RazerCortex`, `ZoomIt` — all legitimate but worth investigating as fleet outliers. Subtract the known-good entries when hunting with Query 9.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline/inventory query using summarize with make_set and dcount — not suitable for CD alerting."
-->

```kql
// Baseline: What programs are configured to autostart via Registry Run keys?
// Companion to Startup folder baseline (Query 1) — same technique, registry mechanism
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
| where ActionType == "RegistryValueSet"
| summarize 
    EventCount = count(),
    DeviceCount = dcount(DeviceName),
    Devices = make_set(DeviceName, 25),
    Users = make_set(InitiatingProcessAccountName, 25),
    SampleValues = make_set(RegistryValueData, 5),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RegistryValueName, InitiatingProcessFileName
| order by DeviceCount desc, EventCount desc
```

**Expected output:** Legitimate autostart entries from Microsoft and corporate-managed software. Anything not in this baseline is an outlier worth investigating with Query 9.

---

### Query 9 — Registry Run Key Outlier Detection (DeviceRegistryEvents)

**Goal:** Find rare Run key entries that appear on very few devices — the registry equivalent of Startup folder outlier detection (Query 2). Attackers using Run keys for persistence will create entries not seen fleet-wide.  
**MITRE:** T1547.001

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "Rare Run key '{{RegistryValueName}}' set on {{DeviceName}} by {{InitiatingProcessFileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: initiatingProcessAccountName
recommendedActions: "A rare Registry Run key was set on this device. This key configures a program to start automatically at user logon. Verify the RegistryValueData (the executable path) is legitimate. Check the initiating process — was this a known installer or a suspicious process? If unexpected, isolate the device."
adaptation_notes: "Needs restructuring from lookup-based filtering. Use inner join pattern with DeviceId + ReportId columns."
-->

```kql
// Find RARE Run key entries — outliers not seen across the fleet
// Known-good baseline (tune per environment): Edge, OneDrive, Teams
let LookbackPeriod = 30d;
let DeviceThreshold = 2; // Run keys seen on <= this many devices are flagged
// Known legitimate Run key patterns to exclude from outlier results
let KnownGoodPatterns = dynamic([
    "MicrosoftEdgeAutoLaunch",  // Edge auto-launch (per-device unique suffix)
    "OneDrive",                  // OneDrive autostart
    "Microsoft.Lists",           // OneDrive Lists integration
    "Teams",                     // Microsoft Teams
    "GlobalSecureAccessClient", // Microsoft Entra Global Secure Access client (msiexec.exe)
    "SecurityHealth"             // Windows Security Health (rare but legitimate)
]);
// Step 1: Calculate fleet prevalence per (ValueName + InitiatingProcess)
// Normalize Edge entries by stripping the per-device hash suffix
let RunKeyPrevalence = DeviceRegistryEvents
    | where Timestamp > ago(LookbackPeriod)
    | where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
    | where ActionType == "RegistryValueSet"
    | extend NormalizedValueName = case(
        RegistryValueName startswith "MicrosoftEdgeAutoLaunch", "MicrosoftEdgeAutoLaunch",
        RegistryValueName
    )
    | summarize DevicesSeen = dcount(DeviceName) by NormalizedValueName, InitiatingProcessFileName;
// Step 2: Return individual events for rare entries
DeviceRegistryEvents
| where Timestamp > ago(LookbackPeriod)
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
| where ActionType == "RegistryValueSet"
| extend NormalizedValueName = case(
    RegistryValueName startswith "MicrosoftEdgeAutoLaunch", "MicrosoftEdgeAutoLaunch",
    RegistryValueName
)
// Exclude known-good patterns
| where not(NormalizedValueName has_any (KnownGoodPatterns))
| lookup kind=inner (
    RunKeyPrevalence | where DevicesSeen <= DeviceThreshold
) on NormalizedValueName, InitiatingProcessFileName
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    DevicesSeen
| order by DevicesSeen asc, Timestamp desc
```

**Tuning guidance:**
- The `KnownGoodPatterns` list should be built from your Query 8 baseline results
- `MicrosoftEdgeAutoLaunch_*` entries have a per-device hash suffix — the query normalizes these to a single pattern to avoid every Edge device appearing as an "outlier"
- `DeviceThreshold = 2`: Flags entries seen on ≤ 2 devices. Set to 1 for strictest detection
- Add your organization's managed software to the exclusion list as you baseline

**Tested 2026-03-27 (90d Data Lake):** With the KnownGoodPatterns exclusion list above, 4 outlier entries remain in this environment: `Docker Desktop` (1 device), `RazerCortex` (1 device), `ZoomIt` (1 device — Sysinternals tool in `C:\Bin\`), and `GlobalSecureAccessClient` (2 devices — now in known-good list). All verified legitimate. If any of these are standard in your org, add them to `KnownGoodPatterns`.

---

## Triage Playbook

If any of the above queries return suspicious results:

### Immediate Assessment

1. **Check the file hash** — submit SHA256 to VirusTotal / Microsoft Defender TI. If the hash matches known malware, skip to containment
2. **Verify the process chain** (Query 5) — is the initiating process expected for this file?
3. **Check fleet prevalence** (Query 2's `DevicesSeen` column) — a file unique to 1 device is far more suspicious than one on 50 devices
4. **Compare metadata** — for executables, does `ProcessVersionInfoOriginalFileName` match the file name? Does the company match expectations?
5. **Check the timeline** — does the file write correlate with suspicious user activity, phishing email delivery, or a known supply chain compromise window?

### Investigation Escalation Criteria

| Signal | Risk | Action |
|--------|------|--------|
| File hash unknown to threat intel + seen on 1 device | 🔴 High | Isolate device, collect file for sandbox analysis |
| System binary name in Startup folder (Query 3 hit) | 🔴 High | Almost certainly malicious — legitimate OS binaries don't live here |
| `.exe` written by `python.exe`, `powershell.exe`, or `cmd.exe` | 🔴 High | Likely payload drop — check supply chain indicators |
| `.bat`/`.vbs`/`.ps1` script in Startup folder | 🟠 Medium | Could be admin tooling or malware — verify with device owner |
| `.lnk` shortcut created by unknown installer | 🟡 Low | Likely legitimate software — verify shortcut target path |
| Known software installer writing `.lnk` | 🟢 Normal | Add to baseline exclusion list |

### TeamPCP-Specific Indicators

If you find `msbuild.exe` in a Startup folder:

1. **Check the file path** — real MSBuild is in `C:\Windows\Microsoft.NET\Framework[64]\<version>\MSBuild.exe` or `C:\Program Files\MSBuild\`, NEVER in a Startup folder
2. **Check version info** — real MSBuild has `ProcessVersionInfoCompanyName == "Microsoft Corporation"`
3. **Check for WAV files** — the TeamPCP payload was hidden in WAV audio files; search for `.wav` files on the same device near the same timestamp
4. **Correlate with pip activity** — run the supply chain queries from [python_supply_chain_attack.md](python_supply_chain_attack.md) Queries 1–4 on the same device
5. **Check C2 communication** — search for network connections to `models.litellm[.]cloud`, `checkmarx[.]zone`, and `scan.aquasecurtiy[.]org`

### Baseline Maintenance

Re-run Query 1 monthly to update your baseline. When legitimate software changes (new tools deployed, applications updated), the baseline shifts. Document your known-good list:

```
# Example baseline exclusion list (customize for your environment)
# Format: InitiatingProcessFileName | Typical FileNames | Notes
explorer.exe       | *.lnk                | User/admin manually placing shortcuts
msiexec.exe        | *.lnk                | MSI installer creating startup entries
OneDriveSetup.exe  | OneDrive.lnk         | Microsoft OneDrive installer
Teams.exe          | *.lnk                | Microsoft Teams (classic) shortcut
```

Update the `DeviceThreshold` in Query 2 as your fleet grows — what's rare on 100 devices is different from what's rare on 10,000.
