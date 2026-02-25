# Infostealer Hunting Campaign — PXA Stealer, Eternidade, CrystalPDF & macOS Stealers

**Created:** 2026-02-07  
**Platform:** Both  
**Tables:** DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceEvents, DeviceRegistryEvents, SecurityAlert, EmailEvents, EmailAttachmentInfo  
**Keywords:** infostealer, PXA Stealer, Eternidade, CrystalPDF, svchost masquerade, pythonw, DLL sideloading, process injection, certutil, AutoIt, credential theft, ClickFix, VBS dropper, WhatsApp abuse, scheduled task persistence, registry run key, obfuscated python, Telegram exfiltration, data staging, ZIP archive  
**MITRE:** T1036.005, T1055, T1574.002, T1059.001, T1059.006, T1053.005, T1547.001, T1140, T1560.001, T1567, T1071.001, T1204.002, T1082, T1555, T1555.003, T1539, T1005, T1070.004, T1218  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This hunting campaign targets TTPs documented in the Microsoft Defender Security Research blog post:  
**[Infostealers without borders: macOS, Python stealers, and platform abuse](https://www.microsoft.com/en-us/security/blog/2026/02/02/infostealers-without-borders-macos-python-stealers-and-platform-abuse/)** (February 2, 2026)

### Threat Summary

| Campaign | Delivery | Key TTPs |
|----------|----------|----------|
| **PXA Stealer (Campaign 1)** | Phishing email → ZIP → Python payload | Python renamed to `svchost.exe`, DLL sideloading, registry persistence, Telegram C2 |
| **PXA Stealer (Campaign 2)** | Phishing email → redirect → MSI/payload | `cvtres.exe` injection from fake svchost, process hollowing, certutil decode |
| **Eternidade Stealer** | WhatsApp worm → VBS → batch → PowerShell | AutoIt script, MSI installer, PowerShell downloaders, WPPConnect abuse |
| **CrystalPDF** | Malvertising/SEO poisoning → fake PDF editor | Scheduled task persistence, browser credential theft, C2 connections |
| **DigitStealer** | Fake DynamicLake DMG (macOS) | curl exfiltration, credential/wallet harvesting |
| **MacSync** | ClickFix Terminal paste (macOS) | Fileless execution, curl + base64 pipeline, osascript |
| **Atomic Stealer (AMOS)** | Fake AI tool DMG (macOS) | AppleScript automation, Keychain theft |

### MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|--------------------|
| **Initial Access** | T1566.001 (Phishing Attachment), T1204.002 (Malicious File) |
| **Execution** | T1059.001 (PowerShell), T1059.006 (Python), T1059.005 (VBScript) |
| **Persistence** | T1547.001 (Registry Run Keys), T1053.005 (Scheduled Tasks) |
| **Defense Evasion** | T1036.005 (Masquerading: Match Legitimate Name), T1055 (Process Injection), T1574.002 (DLL Sideloading), T1140 (Deobfuscate/Decode), T1218 (Signed Binary Proxy Execution) |
| **Credential Access** | T1555.003 (Browser Credentials), T1539 (Steal Web Session Cookie), T1555 (Credentials from Password Stores) |
| **Discovery** | T1082 (System Information Discovery) |
| **Collection** | T1005 (Data from Local System), T1560.001 (Archive via Utility) |
| **Exfiltration** | T1567 (Exfiltration Over Web Service) |
| **Command and Control** | T1071.001 (Application Layer Protocol: Web) |
| **Defense Evasion** | T1070.004 (File Deletion) |

---

## 🔴 HIGH-PRIORITY QUERIES — Svchost Masquerading & Python Abuse

### Query 1: Renamed Python Binary Masquerading as svchost.exe (Process Activity)

**MITRE:** T1036.005 (Masquerading: Match Legitimate Name or Location)  
**Purpose:** Detect a Python interpreter (`pythonw.exe` or `python.exe`) renamed to `svchost.exe` launching child processes. This is the **primary PXA Stealer indicator** — the article describes the Python interpreter masquerading as `svchost.exe` to evade detection.

**Why this matters:** Legitimate `svchost.exe` is always located in `C:\Windows\System32\` and has `OriginalFileName = svchost.exe`. A Python binary renamed to `svchost.exe` will retain its original `VersionInfoOriginalFileName` of `pythonw.exe` or `python.exe`.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "PXA Stealer: Python masquerading as svchost.exe on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "High-signal detection. Minimal adaptation needed — already returns row-level events. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Python interpreter masquerading as svchost.exe — child process activity
// Source: Microsoft Security Blog - PXA Stealer Campaign 1
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName endswith "svchost.exe"
| where InitiatingProcessVersionInfoOriginalFileName has_any ("pythonw.exe", "python.exe", "python3.exe")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessVersionInfoOriginalFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

**Indicators of Compromise:**
- `InitiatingProcessVersionInfoOriginalFileName` shows `pythonw.exe` but `InitiatingProcessFileName` is `svchost.exe`
- `InitiatingProcessFolderPath` is NOT `C:\Windows\System32\`

---

### Query 2: Renamed Python Binary Masquerading as svchost.exe (Network Connections)

**MITRE:** T1036.005, T1071.001  
**Purpose:** Detect network connections initiated by a Python interpreter disguised as `svchost.exe`. PXA Stealer uses this to communicate with C2 and exfiltrate stolen data via Telegram.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "CommandAndControl"
title: "PXA Stealer: C2 connection from Python-as-svchost on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Row-level network events. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Network connections from Python masquerading as svchost.exe
// Source: Microsoft Security Blog - PXA Stealer Campaign 1
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName endswith "svchost.exe"
| where InitiatingProcessVersionInfoOriginalFileName has_any ("pythonw.exe", "python.exe", "python3.exe")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessVersionInfoOriginalFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol
| order by Timestamp desc
```

---

### Query 3: Broad Process Masquerading Detection — FileName vs OriginalFileName Mismatch

**MITRE:** T1036.005  
**Purpose:** Detect ANY process where the `FileName` doesn't match the `VersionInfoOriginalFileName`, indicating a renamed binary. Catches not just Python-as-svchost but any masquerading attempt (AutoIt renamed, other LOLBin abuse).

**Tuning Note:** This is a broad query. The exclusion list filters common false positives from legitimate software updaters. Review and expand the exclusion list for your environment.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregates by CurrentName/OriginalName/SHA256 with `summarize count()`. Broad detection that requires per-environment tuning of exclusion list. Better suited as a hunting query; use Q1/Q2/Q4 for targeted CD rules."
-->
```kql
// Hunt: Broad binary renaming detection — FileName vs OriginalFileName mismatch
// Catches Python-as-svchost, renamed AutoIt, and other masquerading
DeviceProcessEvents
| where Timestamp > ago(30d)
| where isnotempty(ProcessVersionInfoOriginalFileName)
| where isnotempty(FileName)
// Normalize: strip paths and compare base names
| extend OriginalName = tolower(ProcessVersionInfoOriginalFileName)
| extend CurrentName = tolower(FileName)
| where OriginalName != CurrentName
// Focus on high-value masquerading targets
| where CurrentName in~ ("svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
    "smss.exe", "winlogon.exe", "explorer.exe", "taskhost.exe", "conhost.exe",
    "rundll32.exe", "dllhost.exe")
// Exclude legitimate svchost
| where not(FolderPath has "\\Windows\\System32\\" and CurrentName == "svchost.exe" and OriginalName == "svchost.exe")
| summarize
    Count = count(),
    Devices = make_set(DeviceName, 10),
    Users = make_set(AccountName, 10),
    SampleCommandLine = take_any(ProcessCommandLine),
    SampleFolderPath = take_any(FolderPath),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by CurrentName, OriginalName, SHA256
| order by Count desc
```

---

### Query 4: svchost.exe Running Outside System32 (Location Anomaly)

**MITRE:** T1036.005  
**Purpose:** Legitimate `svchost.exe` ONLY runs from `C:\Windows\System32\`. Any instance outside that path is highly suspicious — could be renamed Python, malware, or another masquerading binary.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "svchost.exe running outside System32 on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "High-signal, low-FP detection. Row-level events. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: svchost.exe executing from non-standard locations
// Legitimate svchost ONLY runs from C:\Windows\System32\
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "svchost.exe"
| where FolderPath !has "\\Windows\\System32\\"
| where FolderPath !has "\\Windows\\SysWOW64\\"
// Exclude WinSxS servicing paths (legitimate during Windows Update)
| where FolderPath !has "\\WinSxS\\"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessVersionInfoOriginalFileName,
    ProcessVersionInfoProductName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

## 🟠 PROCESS INJECTION & DLL SIDELOADING

### Query 5: Process Injection — cvtres.exe Spawned by Fake svchost.exe

**MITRE:** T1055 (Process Injection)  
**Purpose:** PXA Stealer Campaign 2 uses `cvtres.exe` (Microsoft Resource File To COFF Object Conversion Utility) spawned by a fake `svchost.exe` that is NOT in `System32`. This indicates process injection or hollowing.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "Process Injection: cvtres.exe spawned by fake svchost on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "High-signal, very specific detection. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: cvtres.exe spawned by svchost.exe outside System32 (process injection)
// Source: Microsoft Security Blog - PXA Stealer Campaign 2
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName == "cvtres.exe"
| where InitiatingProcessFileName has "svchost.exe"
| where InitiatingProcessFolderPath !contains "system32"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessVersionInfoOriginalFileName,
    SHA256
| order by Timestamp desc
```

---

### Query 6: DLL Sideloading — Unexpected DLL Loads by Renamed Processes

**MITRE:** T1574.002 (Hijack Execution Flow: DLL Side-Loading)  
**Purpose:** Detect processes where a renamed binary loads unexpected DLLs, a technique used by PXA Stealer for defense evasion.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "DLL Sideloading: Renamed {{InitiatingProcessVersionInfoOriginalFileName}} loading DLLs on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Remove `| take 200` for production CD. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: DLL sideloading — unexpected DLL loads by processes with mismatched names
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "ImageLoaded" or ActionType has "DllLoad"
| where InitiatingProcessVersionInfoOriginalFileName != InitiatingProcessFileName
| where isnotempty(InitiatingProcessVersionInfoOriginalFileName)
// Focus on known masquerading patterns
| where InitiatingProcessVersionInfoOriginalFileName has_any ("pythonw.exe", "python.exe", "Autoit3.exe")
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessVersionInfoOriginalFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
| take 200
```

---

## 🟠 DEFENSE EVASION — CERTUTIL, AUTOIT & LOLBin ABUSE

### Query 7: certutil.exe Decoding Payloads

**MITRE:** T1140 (Deobfuscate/Decode Files or Information)  
**Purpose:** PXA Stealer uses `certutil.exe` to decode obfuscated payloads. Hunt for certutil decode operations, especially those targeting non-certificate files.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "LOLBin: certutil decode/download on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Row-level events. Low FP in most environments. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: certutil.exe used to decode payloads (LOLBin abuse)
// Legitimate use is rare outside PKI administration
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-decode", "/decode", "-decodehex", "/decodehex", 
    "-urlcache", "/urlcache", "-f ", "/f ")
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath,
    SHA256
| order by Timestamp desc
```

---

### Query 8: Renamed AutoIt Binary Executing Scripts

**MITRE:** T1218 (Signed Binary Proxy Execution)  
**Purpose:** Eternidade Stealer campaign uses a renamed AutoIt interpreter to execute malicious `.log` scripts. Detect AutoIt binaries running with non-standard names.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "Renamed AutoIt Binary: {{FileName}} (original: AutoIt3.exe) on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Row-level events. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Renamed AutoIt interpreter executing scripts
// Source: Microsoft Security Blog - Eternidade Stealer via WhatsApp
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoOriginalFileName == "AutoIt3.exe" 
    or InitiatingProcessVersionInfoOriginalFileName == "Autoit3.exe"
| where FileName !~ "AutoIt3.exe" or InitiatingProcessFileName !~ "AutoIt3.exe"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessVersionInfoOriginalFileName,
    InitiatingProcessFileName,
    InitiatingProcessVersionInfoOriginalFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "Eternidade: AutoIt executing .log script on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Companion to Q8 main query. Targets specific .log script pattern. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: AutoIt executing malicious .log scripts (Eternidade pattern)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessVersionInfoOriginalFileName == "Autoit3.exe"
| where InitiatingProcessCommandLine has ".log"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

### Query 9: Obfuscated Python Script Execution

**MITRE:** T1059.006 (Command and Scripting Interpreter: Python)  
**Purpose:** Detect Python interpreters executing obfuscated code, a core PXA Stealer technique. Looks for Python processes with suspicious command-line patterns.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Execution"
title: "Suspicious Python Execution: {{FileName}} with obfuscation on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Remove `| take 200`. Broad query — may need environment-specific tuning of `has_any` keywords. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Python processes with suspicious execution patterns
// Covers both legitimate python.exe and renamed python binaries
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("python.exe", "pythonw.exe", "python3.exe")
    or ProcessVersionInfoOriginalFileName has_any ("pythonw.exe", "python.exe")
// Suspicious indicators: encoding flags, temp paths, obfuscation, or data harvesting imports
| where ProcessCommandLine has_any (
    "-c \"import", "-c 'import",          // Inline one-liner execution
    "base64", "exec(", "eval(",           // Common obfuscation patterns
    "\\AppData\\", "\\Temp\\",            // Execution from temp/user directories
    "\\Public\\",                          // PXA Stealer stages in C:\Users\Public
    "telegram", "requests.post",          // C2 / exfil indicators
    "keyring", "browser", "wallet",        // Credential harvesting
    "chrome", "firefox", "edge"            // Browser data targeting
    )
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
| take 200
```

---

## 🟠 PERSISTENCE MECHANISMS

### Query 10: Registry Run Key Persistence

**MITRE:** T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)  
**Purpose:** PXA Stealer establishes persistence via registry Run keys. Detect suspicious entries, especially those pointing to Python scripts, renamed binaries, or user-writable paths.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "Suspicious Registry Run Key: {{RegistryValueName}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Row-level events. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Suspicious registry Run key creation for persistence
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    "\\CurrentVersion\\Run",
    "\\CurrentVersion\\RunOnce",
    "\\CurrentVersion\\RunServices"
)
// Focus on suspicious values
| where RegistryValueData has_any (
    "python", "pythonw", "svchost",
    "\\AppData\\", "\\Temp\\", "\\Public\\",
    ".py", ".pyw", ".bat", ".vbs", ".cmd",
    "autoit", "mshta", "wscript", "cscript",
    "powershell", "certutil"
)
| project
    Timestamp,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
| order by Timestamp desc
```

---

### Query 11: Scheduled Task Persistence (CrystalPDF & PXA Stealer Pattern)

**MITRE:** T1053.005 (Scheduled Task/Job: Scheduled Task)  
**Purpose:** CrystalPDF and PXA Stealer create scheduled tasks for persistence. Detect suspicious task creation, especially by processes with mismatched version info.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "Suspicious Scheduled Task created by {{InitiatingProcessFileName}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Row-level events. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Scheduled task creation by suspicious processes
// Source: CrystalPDF and PXA Stealer persistence
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "ScheduledTaskCreated"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessVersionInfoOriginalFileName,
    InitiatingProcessVersionInfoProductName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    AdditionalFields
| order by Timestamp desc
```

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "CrystalPDF Scheduled Task persistence on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "CrystalPDF-specific variant. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: CrystalPDF-specific scheduled task persistence
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "ScheduledTaskCreated"
| where InitiatingProcessVersionInfoProductName == "CrystalPDF"
    or InitiatingProcessFileName has "CrystalPDF"
    or ProcessCommandLine has "CrystalPDF"
| project
    Timestamp,
    DeviceName,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessVersionInfoProductName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

---

## 🟠 INITIAL ACCESS & DELIVERY

### Query 12: Encoded PowerShell Downloading Payloads

**MITRE:** T1059.001 (PowerShell), T1204.002 (User Execution: Malicious File)  
**Purpose:** PXA Stealer and Eternidade Stealer use PowerShell to download and execute payloads. Detect encoded or download-related PowerShell activity.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Execution"
title: "Encoded/Download PowerShell on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Remove `| take 200`. Broad keyword set may need tuning. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: PowerShell with encoded commands or download activity
// Common across PXA Stealer, Eternidade, and other infostealer campaigns
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any (
    "-encodedcommand", "-enc ", "-e ",
    "DownloadFile", "DownloadString", "DownloadData",
    "WebClient", "WebRequest", "Invoke-WebRequest",
    "IEX", "Invoke-Expression",
    "Start-BitsTransfer",
    "curl ", "wget ",
    "hidden", "-w hidden", "-windowstyle hidden"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FolderPath,
    SHA256
| order by Timestamp desc
| take 200
```

---

### Query 13: VBS/Batch Dropper Chain (Eternidade Stealer Pattern)

**MITRE:** T1059.005 (Visual Basic), T1059.003 (Windows Command Shell)  
**Purpose:** Eternidade Stealer starts with an obfuscated VBS that drops a batch file, which launches PowerShell downloaders. Detect this multi-stage dropper chain.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Execution"
title: "VBS Dropper: File dropped to Temp from Downloads on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: VBS files from Downloads folder dropping batch and archive files
// Source: Microsoft Security Blog - Eternidade Stealer via WhatsApp
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessCommandLine has_all ("Downloads", ".vbs")
| where FileName has_any (".zip", ".lnk", ".bat") 
| where FolderPath has "\\Temp\\"
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Execution"
title: "Eternidade: wscript launching batch installer on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Companion to Q13 main query. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: wscript.exe launching batch installers (Eternidade dropper chain)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessParentFileName == "wscript.exe"
| where InitiatingProcessCommandLine has_any ("instalar.bat", "python_install.bat", "install.bat", "setup.bat")
| where ProcessCommandLine !has "conhost.exe"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp desc
```

---

### Query 14: Malicious PDF File Extraction (PXA Stealer Campaign 2)

**MITRE:** T1204.002  
**Purpose:** PXA Stealer Campaign 2 extracts payloads embedded in seemingly legitimate PDF files with image extensions. Detect decompression targeting PDF-like paths with image file extraction.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "InitialAccess"
title: "PXA Stealer: Suspicious PDF/image archive extraction on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Very specific detection with narrow scope. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Suspicious archive extraction to Public folder with PDF/image content
// Source: Microsoft Security Blog - PXA Stealer Campaign 2
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_all ("-y", "x", @"C:", "Users", "Public", ".pdf")
| where ProcessCommandLine has_any (".jpg", ".png")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath,
    SHA256
| order by Timestamp desc
```

---

## 🟠 COLLECTION & EXFILTRATION

### Query 15: Sensitive Data Staging and ZIP Archiving

**MITRE:** T1560.001 (Archive Collected Data: Archive via Utility), T1005  
**Purpose:** Infostealers collect browser credentials, cookies, and wallet data into ZIP archives before exfiltration. Detect suspicious archive creation from temp/staging directories.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Collection"
title: "Data Staging: ZIP archive created in temp by {{InitiatingProcessFileName}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Remove `| take 200`. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: ZIP archive creation in temp/staging directories
// Common exfiltration preparation across all infostealer campaigns
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".zip"
| where FolderPath has_any ("\\Temp\\", "\\tmp\\", "\\AppData\\Local\\", "\\Public\\")
// Focus on suspicious initiating processes
| where InitiatingProcessFileName has_any (
    "python", "pythonw", "svchost",
    "powershell", "cmd", "wscript", "cscript",
    "autoit", "7z", "rar"
)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    FileSize,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    SHA256
| order by Timestamp desc
| take 200
```

---

### Query 16: Browser Credential Store Access

**MITRE:** T1555.003 (Credentials from Password Stores: Credentials from Web Browsers)  
**Purpose:** All infostealer campaigns in this blog target browser credential stores (Chrome, Firefox, Edge). Detect suspicious process access to these sensitive files.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "CredentialAccess"
title: "Browser Credential Access: {{FileName}} accessed by {{InitiatingProcessFileName}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Remove `| take 200`. May need additional browser/security tool exclusions per environment. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Suspicious access to browser credential and cookie stores
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "AppData"
| where FolderPath has_any ("\\Google\\Chrome\\", "\\Mozilla\\Firefox\\", "\\Microsoft\\Edge\\")
| where FileName has_any ("Login Data", "Cookies", "Web Data", "Local State",
    "logins.json", "cookies.sqlite", "key3.db", "key4.db", "cert9.db")
// Exclude browser processes themselves and known legitimate tools
| where not(InitiatingProcessFileName has_any ("chrome.exe", "firefox.exe", "msedge.exe",
    "MsMpEng.exe", "MpCopyAccelerator.exe", "SearchProtocolHost.exe", "OUTLOOK.EXE"))
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
| take 200
```

---

### Query 17: CrystalPDF C2 Network Connections

**MITRE:** T1071.001 (Application Layer Protocol: Web Protocols)  
**Purpose:** Detect network connections initiated by the CrystalPDF malware to its C2 infrastructure.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "CommandAndControl"
title: "CrystalPDF C2 Connection from {{DeviceName}} to {{RemoteIP}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Network connections from CrystalPDF malware
// Source: Microsoft Security Blog - CrystalPDF campaign
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessVersionInfoOriginalFileName == "CrystalPDF.exe"
    or InitiatingProcessFileName has "CrystalPDF"
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessVersionInfoOriginalFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
| order by Timestamp desc
```

---

## 🟡 DISCOVERY & SYSTEM RECONNAISSANCE

### Query 18: System Discovery via WMI or Python

**MITRE:** T1082 (System Information Discovery)  
**Purpose:** Infostealers perform system discovery using WMI queries and Python system calls to fingerprint the victim machine before data collection.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Discovery"
title: "System Discovery: {{FileName}} from suspicious parent {{InitiatingProcessFileName}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake. The dual filter on InitiatingProcessFileName + InitiatingProcessVersionInfoOriginalFileName narrows scope well."
-->
```kql
// Hunt: System discovery commands from suspicious parent processes
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("wmic.exe", "systeminfo.exe", "hostname.exe")
    or (ProcessCommandLine has "wmic" and ProcessCommandLine has_any ("os get", "computersystem", "bios"))
// Focus on suspicious parents (Python, scripts, renamed processes)
| where InitiatingProcessFileName has_any ("python", "pythonw", "svchost", "cmd.exe", "powershell.exe", "wscript.exe")
| where InitiatingProcessVersionInfoOriginalFileName has_any ("pythonw.exe", "python.exe")
    or InitiatingProcessFolderPath has_any ("\\AppData\\", "\\Temp\\", "\\Public\\", "\\Downloads\\")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessVersionInfoOriginalFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
| order by Timestamp desc
```

---

## 🟡 ANTI-FORENSICS

### Query 19: Suspicious Path/Directory Deletion (Evidence Cleanup)

**MITRE:** T1070.004 (Indicator Removal: File Deletion)  
**Purpose:** Infostealers delete their staging directories after exfiltration. Detect suspicious deletion of temp directories from script or renamed processes.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregates with `summarize count()` and threshold `DeletedFileCount > 5`. Returns per-device/process aggregations, not individual events. Would need restructuring to per-event detection for CD."
-->
```kql
// Hunt: Deletion of staging/temp directories by suspicious processes
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType has "Deleted" or ActionType has "FileDeleted"
| where FolderPath has_any ("\\Temp\\", "\\tmp\\", "\\Public\\", "\\AppData\\Local\\Temp\\")
// Focus on bulk deletion patterns (more than just single file)
| where InitiatingProcessFileName has_any ("python", "pythonw", "svchost", "cmd.exe", 
    "powershell.exe", "wscript.exe", "autoit")
| summarize
    DeletedFileCount = count(),
    DeletedFileTypes = make_set(tostring(split(FileName, ".")[-1]), 20),
    SampleFiles = make_set(FileName, 10),
    FirstDeletion = min(Timestamp),
    LastDeletion = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where DeletedFileCount > 5
| order by DeletedFileCount desc
```

---

## 🔵 IOC-BASED QUERIES

### Query 20: Known C2 Infrastructure (IP Addresses)

**Purpose:** Detect connections to known C2 IP addresses from the blog's IOC list.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Known Infostealer C2: {{DeviceName}} connected to {{RemoteIP}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "IOC-based detection — high priority, low FP. Schedule 1H for rapid response. IOC list should be updated as new indicators are published. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Connections to known infostealer C2 IPs
// Source: Microsoft Security Blog IOC list (Feb 2026)
let MaliciousIPs = dynamic([
    "217.119.139.117",   // AMOS C2 server
    "157.66.27.11",      // PureRAT C2 (PXA Campaign 1)
    "195.24.236.116"     // C2 server (PXA Campaign 2)
]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (MaliciousIPs)
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    InitiatingProcessAccountName
| order by Timestamp desc
```

---

### Query 21: Known C2 Domains

**Purpose:** Detect DNS resolution or connections to known C2 domains from the blog's IOC list.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Known Infostealer C2 Domain: {{DeviceName}} connected to {{RemoteUrl}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "IOC-based detection — high priority, low FP. Schedule 1H for rapid response. IOC list should be updated as new indicators are published. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Connections to known infostealer C2 domains
// Source: Microsoft Security Blog IOC list (Feb 2026)
let MaliciousDomains = dynamic([
    "dynamiclake.org",
    "booksmagazinetx.com", "goldenticketsshop.com",
    "barbermoo.coupons", "barbermoo.fun", "barbermoo.shop",
    "barbermoo.space", "barbermoo.today", "barbermoo.top",
    "barbermoo.world", "barbermoo.xyz",
    "alli-ai.pro",
    "ai.foqguzz.com", "day.foqguzz.com",
    "bagumedios.cloud",
    "negmari.com", "ramiort.com", "strongdwn.com"
]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (MaliciousDomains)
| project
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
| order by Timestamp desc
```

---

### Query 22: Known Malicious File Hashes

**Purpose:** Detect known infostealer payload hashes across process creation and file events.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Known Infostealer Hash: {{FileName}} ({{SHA256}}) on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "IOC-based detection — high priority, low FP. Schedule 1H for rapid response. Hash list should be updated as new indicators are published. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Known infostealer payload hashes in process events
// Source: Microsoft Security Blog IOC list (Feb 2026)
let MaliciousHashes = dynamic([
    // DigitStealer
    "3e20ddb90291ac17cef9913edd5ba91cd95437da86e396757c9d871a82b1282a",
    "da99f7570b37ddb3d4ed650bc33fa9fbfb883753b2c212704c10f2df12c19f63",
    // AMOS
    "42d51feea16eac568989ab73906bbfdd41641ee3752596393a875f85ecf06417",
    // CrystalPDF
    "598da788600747cf3fa1f25cb4fa1e029eca1442316709c137690e645a0872bb",
    "3bc62aca7b4f778dabb9ff7a90fdb43a4fdd4e0deec7917df58a18eb036fac6e",
    "c72f8207ce7aebf78c5b672b65aebc6e1b09d00a85100738aabb03d95d0e6a95"
]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 in (MaliciousHashes)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Known Infostealer Hash in File Event: {{FileName}} ({{SHA256}}) on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Companion to Q22 process hash query — covers file creation/modification events. Same IOC list maintenance notes apply. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Known infostealer payload hashes in file events
let MaliciousHashes = dynamic([
    "3e20ddb90291ac17cef9913edd5ba91cd95437da86e396757c9d871a82b1282a",
    "da99f7570b37ddb3d4ed650bc33fa9fbfb883753b2c212704c10f2df12c19f63",
    "42d51feea16eac568989ab73906bbfdd41641ee3752596393a875f85ecf06417",
    "598da788600747cf3fa1f25cb4fa1e029eca1442316709c137690e645a0872bb",
    "3bc62aca7b4f778dabb9ff7a90fdb43a4fdd4e0deec7917df58a18eb036fac6e",
    "c72f8207ce7aebf78c5b672b65aebc6e1b09d00a85100738aabb03d95d0e6a95"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (MaliciousHashes)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    ActionType,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 🔵 EMAIL-BASED INITIAL ACCESS

### Query 23: Phishing Emails with Infostealer Payloads

**MITRE:** T1566.001 (Phishing: Spearphishing Attachment)  
**Purpose:** Detect phishing emails delivering ZIPs, MSIs, or VBS files typically used by PXA Stealer and Eternidade campaigns.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "InitialAccess"
title: "Infostealer Phishing: {{FileType}} attachment from {{SenderFromDomain}} to {{RecipientEmailAddress}}"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
adaptation_notes: "Remove `| take 200`. The join on EmailEvents may need ThreatTypes filter adjusted for environment. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Hunt: Phishing emails with suspicious attachment types
// PXA Stealer and Eternidade use ZIP, MSI, and VBS attachments
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where FileType has_any ("zip", "msi", "vbs", "bat", "py", "lnk", "iso", "img")
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(30d)
    | where EmailDirection == "Inbound"
    | where ThreatTypes has_any ("Malware", "Phish") or DeliveryAction == "Delivered"
) on NetworkMessageId
| project
    Timestamp,
    RecipientEmailAddress,
    SenderFromAddress,
    SenderFromDomain,
    Subject,
    FileName,
    FileType,
    SHA256,
    ThreatTypes,
    DeliveryAction,
    DeliveryLocation
| order by Timestamp desc
| take 200
```

---

## 🔵 COMPOSITE MULTI-SIGNAL QUERY

### Query 24: Multi-TTP Infostealer Scoring — Devices with Multiple Warning Signs

**Purpose:** Generate a composite risk score per device by counting how many infostealer TTPs were observed. Devices with 3+ signals should be investigated immediately.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-let composite scoring query with 6 union subqueries. Exceeds CD character limits and uses complex aggregation logic. Not suitable for CD — use as periodic hunting query or analytics rule in Sentinel."
-->
```kql
// Hunt: Multi-signal infostealer detection — risk scoring per device
// Each signal adds 1 point; devices with 3+ should be triaged
let timeWindow = ago(30d);
// Signal 1: Process masquerading
let masquerading = DeviceProcessEvents
| where Timestamp > timeWindow
| where FileName =~ "svchost.exe" and not(FolderPath has "\\Windows\\System32\\")
| distinct DeviceName
| extend Signal = "Masquerading_svchost_outside_System32";
// Signal 2: Renamed python binary
let renamedPython = DeviceProcessEvents
| where Timestamp > timeWindow
| where ProcessVersionInfoOriginalFileName has_any ("pythonw.exe", "python.exe")
| where not(FileName has_any ("python", "pythonw"))
| distinct DeviceName
| extend Signal = "Renamed_Python_binary";
// Signal 3: certutil decode activity
let certutilDecode = DeviceProcessEvents
| where Timestamp > timeWindow
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-decode", "/decode", "-urlcache", "/urlcache")
| distinct DeviceName
| extend Signal = "Certutil_decode_activity";
// Signal 4: Registry Run key persistence from unusual paths
let runKeyPersistence = DeviceRegistryEvents
| where Timestamp > timeWindow
| where ActionType == "RegistryValueSet"
| where RegistryKey has "\\CurrentVersion\\Run"
| where RegistryValueData has_any ("python", "svchost", "\\AppData\\", "\\Temp\\", "\\Public\\", ".py", ".bat", ".vbs", "autoit")
| distinct DeviceName
| extend Signal = "Suspicious_RunKey_persistence";
// Signal 5: Scheduled task by non-standard process
// Tuning: Exclude empty InitiatingProcessFileName (system-created Office/Intune tasks during provisioning)
let scheduledTaskAbuse = DeviceEvents
| where Timestamp > timeWindow
| where ActionType == "ScheduledTaskCreated"
| where isnotempty(InitiatingProcessFileName)
| where not(InitiatingProcessFolderPath has "\\Windows\\System32\\")
| where not(InitiatingProcessFileName in~ ("schtasks.exe", "taskhostw.exe", "mmc.exe"))
| distinct DeviceName
| extend Signal = "Suspicious_ScheduledTask_creation";
// Signal 6: Browser credential access from non-browser process
let browserCredAccess = DeviceFileEvents
| where Timestamp > timeWindow
| where FolderPath has_any ("\\Google\\Chrome\\", "\\Mozilla\\Firefox\\", "\\Microsoft\\Edge\\")
| where FileName has_any ("Login Data", "Cookies", "logins.json")
| where not(InitiatingProcessFileName has_any ("chrome.exe", "firefox.exe", "msedge.exe", "MsMpEng.exe"))
| distinct DeviceName
| extend Signal = "Browser_credential_access";
// Combine all signals
union masquerading, renamedPython, certutilDecode, runKeyPersistence, scheduledTaskAbuse, browserCredAccess
| summarize 
    Signals = make_set(Signal),
    SignalCount = dcount(Signal)
    by DeviceName
| where SignalCount >= 2
| order by SignalCount desc
```

**Risk Interpretation:**

| Signal Count | Risk Level | Recommended Action |
|-------------|------------|-------------------|
| 5-6 | 🔴 **Critical** | Isolate device immediately, initiate full incident response |
| 3-4 | 🟠 **High** | Priority triage — likely active infostealer infection |
| 2 | 🟡 **Medium** | Investigate — may be early-stage compromise or false positive overlap |
| 1 | 🔵 **Low** | Review individual signal in context |

---

## Hunting Workflow

### Recommended Execution Order

1. **Start with IOC-based queries** (Queries 20-22) — fastest path to known-bad indicators
2. **Run high-priority masquerading queries** (Queries 1-4) — catches the svchost/Python abuse pattern you're most concerned about
3. **Run the composite multi-signal query** (Query 24) — holistic view of which devices have the most overlap
4. **Deep-dive into flagged devices** with the remaining queries for specific TTPs
5. **Check email delivery** (Query 23) — understand if phishing emails were the initial vector

### Tuning Guidance

- **Time window:** Default is 30 days. Expand to 90 days for baseline establishment or narrow to 7 days for active incident response
- **False positives:** Query 3 (broad masquerading) will need environment-specific tuning. Expect legitimate software updaters and installers to rename binaries
- **SOC integration:** Queries 1, 2, 4, and 5 are suitable for Sentinel Analytics Rules with low false-positive rates
- **Platform note:** All queries use `Timestamp` (Defender XDR Advanced Hunting syntax). For Sentinel Data Lake, change `Timestamp` to `TimeGenerated`
- **KQL compatibility:** Negation operators `!has_any` and `!in~` are not reliably supported in the Advanced Hunting API (cause "Unexpected: !" parser errors). Use `not(... has_any ...)` and `not(... in~ ...)` wrappers instead. Simple `!has` and `!contains` work in standalone queries but may fail inside `let` statement blocks.

### Related Workspace Queries

- [rare_process_chains.md](rare_process_chains.md) — Complementary parent-child process analysis for detecting unusual execution chains
- [endpoint_failed_connections.md](endpoint_failed_connections.md) — Network anomaly detection for C2 communication patterns

> **Note:** Both related queries are in the same `queries/endpoint/` folder.

### References

- [Microsoft Security Blog: Infostealers without borders (Feb 2, 2026)](https://www.microsoft.com/en-us/security/blog/2026/02/02/infostealers-without-borders-macos-python-stealers-and-platform-abuse/)
- [MITRE ATT&CK T1036.005 — Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
