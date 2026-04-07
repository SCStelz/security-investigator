# Storm-1175 / Medusa Ransomware — Threat Hunting Campaign

**Created:** 2026-04-07  
**Platform:** Both  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceTvmSoftwareVulnerabilities, AlertInfo, AlertEvidence  
**Keywords:** Storm-1175, Medusa ransomware, Gaze.exe, SimpleHelp, AnyDesk, Rclone, Bandizip, PDQ Deploy, PsExec, Impacket, wmiexec, smbexec, Cloudflare tunnel, LSASS, WDigest, NTDS.dit, SAM, web shell, RMM tools, credential theft, lateral movement, defense evasion, data exfiltration, nanodump, pypykatz, Veeam  
**MITRE:** T1190, T1059.001, T1136.001, T1098, T1021.001, T1021.002, T1219, T1003.001, T1003.002, T1003.003, T1112, T1562.001, T1486, T1567, T1572, T1048, T1569.002, T1072, T1036.005  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Microsoft Security Blog — Storm-1175 focuses gaze on vulnerable web-facing assets in high-tempo Medusa ransomware operations](https://www.microsoft.com/en-us/security/blog/2026/04/06/storm-1175-focuses-gaze-on-vulnerable-web-facing-assets-in-high-tempo-medusa-ransomware-operations/)

---

## Threat Overview

**Storm-1175** is a financially motivated cybercriminal actor operating high-velocity Medusa ransomware campaigns. Key characteristics:

- **Initial access** via N-day (and occasionally 0-day) exploitation of web-facing applications
- **Time-to-ransomware** as short as 24 hours, typically 5–6 days
- **Target sectors:** Healthcare, education, professional services, finance (AU, UK, US)
- **Key tools:** SimpleHelp, AnyDesk, PsExec, Impacket, PDQ Deployer, Rclone, Bandizip, Cloudflare tunnels, Mimikatz
- **Ransomware variant:** Medusa (Gaze.exe), deployed via PDQ Deployer or Group Policy

### Attack Chain Summary

```
Exploitation → Web Shell/RAT → New Admin Account → RMM Install / Cloudflare Tunnel
    → PsExec/RDP Lateral Movement → LSASS/NTDS.dit Credential Theft
    → Defender Tampering → Rclone Exfiltration → Medusa Ransomware (PDQ/GPO)
```

---

## IOCs (2026 Campaign)

| Indicator | Type | Description | First Seen | Last Seen |
|-----------|------|-------------|------------|-----------|
| `0cefeb6210b7103fd32b996beff518c9b6e1691a97bb1cda7f5fb57905c4be96` | SHA-256 | Gaze.exe (Medusa Ransomware) | 2026-03-01 | 2026-03-01 |
| `9632d7e4a87ec12fdd05ed3532f7564526016b78972b2cd49a610354d672523c` | SHA-256 | lsp.exe (Rclone) | 2024-04-01 | 2026-02-18 |
| `e57ba1a4e323094ca9d747bfb3304bd12f3ea3be5e2ee785a3e656c3ab1e8086` | SHA-256 | main.exe (SimpleHelp) | 2026-01-15 | 2026-01-15 |
| `5ba7de7d5115789b952d9b1c6cff440c9128f438de933ff9044a68fff8496d19` | SHA-256 | moon.exe (SimpleHelp) | 2025-09-15 | 2025-09-22 |
| `185.135.86[.]149` | IP | SimpleHelp C2 | 2024-02-23 | 2026-03-15 |
| `134.195.91[.]224` | IP | SimpleHelp C2 | 2024-02-23 | 2026-02-26 |
| `85.155.186[.]121` | IP | SimpleHelp C2 | 2024-02-23 | 2026-02-12 |

### Exploited CVEs

| CVE | Product | Year |
|-----|---------|------|
| CVE-2023-21529 | Microsoft Exchange | 2023 |
| CVE-2023-27350, CVE-2023-27351 | PaperCut | 2023 |
| CVE-2023-46805, CVE-2024-21887 | Ivanti Connect Secure | 2023–2024 |
| CVE-2024-1708, CVE-2024-1709 | ConnectWise ScreenConnect | 2024 |
| CVE-2024-27198, CVE-2024-27199 | JetBrains TeamCity | 2024 |
| CVE-2024-57726, CVE-2024-57727, CVE-2024-57728 | SimpleHelp | 2024 |
| CVE-2025-31161 | CrushFTP | 2025 |
| CVE-2025-10035 | GoAnywhere MFT | 2025 |
| CVE-2025-52691, CVE-2026-23760 | SmarterMail | 2025–2026 |
| CVE-2026-1731 | BeyondTrust | 2026 |

---

## Hunting Queries

---

### Query 1: SHA-256 File Hash IOC Hunt

**MITRE:** Multiple | **Tactic:** All Phases | **Tool:** Advanced Hunting  
**Tuning:** Direct IOC match — no false positives expected.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: File Hash IOC Hunt"
frequency: "24h"
lookback: "24h"
severity: "high"
mitre: ["T1486", "T1219", "T1567"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 / Medusa Ransomware - SHA-256 IOC Hunt (files + processes)
let Storm1175_Hashes = dynamic([
    "0cefeb6210b7103fd32b996beff518c9b6e1691a97bb1cda7f5fb57905c4be96", // Gaze.exe (Medusa)
    "9632d7e4a87ec12fdd05ed3532f7564526016b78972b2cd49a610354d672523c", // lsp.exe (Rclone)
    "e57ba1a4e323094ca9d747bfb3304bd12f3ea3be5e2ee785a3e656c3ab1e8086", // main.exe (SimpleHelp)
    "5ba7de7d5115789b952d9b1c6cff440c9128f438de933ff9044a68fff8496d19"  // moon.exe (SimpleHelp)
]);
union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where SHA256 in (Storm1175_Hashes)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 2: C2 IP Address IOC Hunt

**MITRE:** T1219 | **Tactic:** Command and Control | **Tool:** Advanced Hunting  
**Tuning:** Direct IOC match across network connections.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: C2 IP IOC Hunt"
frequency: "24h"
lookback: "24h"
severity: "high"
mitre: ["T1219"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 / Medusa - C2 IP IOC Hunt
let Storm1175_C2_IPs = dynamic([
    "185.135.86.149",  // SimpleHelp C2
    "134.195.91.224",  // SimpleHelp C2
    "85.155.186.121"   // SimpleHelp C2
]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (Storm1175_C2_IPs)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 3: RMM Tool Installation/Execution Detection

**MITRE:** T1219 | **Tactic:** Persistence, Command and Control | **Tool:** Advanced Hunting  
**Tuning:** Refined to match on process file names only (not command lines) to avoid false positives from unrelated processes mentioning RMM tool names. AnyDesk Safe Mode persistence pattern added as separate detection.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: RMM Tool Execution"
frequency: "24h"
lookback: "24h"
severity: "medium"
mitre: ["T1219"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: RMM Tool Installation / Execution
// Detects execution of RMM tools commonly used by Storm-1175
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (
    // Atera
    "AteraAgent.exe", "AteraSetupWizard.msi",
    // Level RMM
    "level-windows-amd64.exe", "level.exe",
    // N-able
    "BASupSrvc.exe",
    // DWAgent
    "dwagent.exe", "dwagsvc.exe",
    // MeshAgent
    "MeshAgent.exe",
    // ConnectWise ScreenConnect
    "ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe",
    // AnyDesk
    "AnyDesk.exe",
    // SimpleHelp
    "SimpleHelp.exe", "SimpleService.exe",
    // PDQ Deployer
    "PDQDeploy.exe", "PDQDeployRunner.exe", "PDQInventory.exe"
)
| summarize Count = count(),
    Devices = make_set(DeviceName, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Accounts = make_set(AccountName, 10)
    by FileName, FolderPath
| order by Count desc
```

---

### Query 4: AnyDesk Safe Mode Persistence

**MITRE:** T1219, T1547 | **Tactic:** Persistence | **Tool:** Advanced Hunting  
**Tuning:** Specifically targets AnyDesk being registered as a Safe Mode service — a technique used by ransomware operators to persist even when the system is booted into Safe Mode.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: AnyDesk Safe Mode Persistence"
frequency: "24h"
lookback: "24h"
severity: "high"
mitre: ["T1219", "T1547"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: AnyDesk / RMM Safe Mode Persistence
// Detects registration of RMM tools as Safe Mode services via registry
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "reg.exe"
| where ProcessCommandLine has "SafeBoot"
    and ProcessCommandLine has_any ("AnyDesk", "ScreenConnect", "SimpleHelp", 
        "MeshAgent", "DWAgent", "Atera", "Level")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 5: New Local Admin Account Creation

**MITRE:** T1136.001 | **Tactic:** Persistence, Privilege Escalation | **Tool:** Advanced Hunting  
**Tuning:** Targets `net.exe`/`net1.exe` with `/add` for user creation AND localgroup administrator additions. High-fidelity for detecting the specific Storm-1175 pattern of creating backdoor admin accounts.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: Local Admin Account Creation"
frequency: "1h"
lookback: "1h"
severity: "high"
mitre: ["T1136.001", "T1098"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: New Local Admin Account Creation via net commands
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("net.exe", "net1.exe")
| where (ProcessCommandLine has "user" and ProcessCommandLine has "/add")
    or (ProcessCommandLine has "localgroup" and ProcessCommandLine has "administrators"
        and ProcessCommandLine has "/add")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 6: Cloudflare Tunnel Masquerading or Execution

**MITRE:** T1572 | **Tactic:** Command and Control | **Tool:** Advanced Hunting  
**Tuning:** Two-pronged detection: (1) cloudflared.exe running from non-standard paths, (2) any binary named conhost.exe running outside System32/SysWOW64 (masquerading). Excludes credential harvesting noise from `find`/`grep` commands that mention `.cloudflared`.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: Cloudflare Tunnel Activity"
frequency: "24h"
lookback: "24h"
severity: "high"
mitre: ["T1572"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: Cloudflare Tunnel masquerading or execution
// Prong 1: Actual cloudflared binary execution (suspicious outside IT context)
// Prong 2: conhost.exe running outside legitimate system paths (masquerading)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // Actual cloudflared execution
    (FileName =~ "cloudflared.exe" and ProcessCommandLine has "tunnel")
    or
    // conhost.exe outside System32 (masquerading — Storm-1175 renames cloudflared to conhost.exe)
    (FileName =~ "conhost.exe"
        and not(FolderPath has_any ("\\Windows\\System32\\", "\\Windows\\SysWOW64\\"))
        and FolderPath != "")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 7: WDigest Credential Caching Registry Modification

**MITRE:** T1112, T1003.001 | **Tactic:** Credential Access | **Tool:** Advanced Hunting  
**Tuning:** High-fidelity — any modification to `UseLogonCredential` under WDigest is always suspicious.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: WDigest Credential Caching"
frequency: "1h"
lookback: "1h"
severity: "high"
mitre: ["T1112", "T1003.001"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: WDigest Credential Caching Enablement
// Enables cleartext credential storage in LSASS memory
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has "WDigest" and RegistryValueName =~ "UseLogonCredential"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
    ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 8: LSASS Credential Dumping Detection

**MITRE:** T1003.001 | **Tactic:** Credential Access | **Tool:** Advanced Hunting  
**Tuning:** Excludes legitimate MDE Client Analyzer procdump activity (dumps msinfo32, not lsass). Added explicit lsass target requirement for procdump matches.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: LSASS Credential Dumping"
frequency: "1h"
lookback: "1h"
severity: "high"
mitre: ["T1003.001"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: LSASS Credential Dumping
// Tuned to exclude MDE Client Analyzer (procdump on msinfo32)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // Procdump targeting lsass specifically
    (FileName in~ ("procdump.exe", "procdump64.exe")
        and ProcessCommandLine has "lsass")
    // Mimikatz and alternative credential dumping tools
    or FileName in~ ("mimikatz.exe", "sekurlsa.exe", "nanodump.exe", "pypykatz.exe")
    // Task Manager dumping lsass
    or (FileName =~ "taskmgr.exe" and ProcessCommandLine has "lsass")
    // Comsvcs.dll MiniDump (rundll32 LSASS dump technique)
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs.dll"
        and ProcessCommandLine has "MiniDump")
    // Direct LSASS process access patterns
    or (FileName =~ "powershell.exe" and ProcessCommandLine has "lsass"
        and ProcessCommandLine has_any ("dump", "memory", "minidump", "sekurlsa"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 9: NTDS.dit / SAM Database Access

**MITRE:** T1003.003, T1003.002 | **Tactic:** Credential Access | **Tool:** Advanced Hunting  
**Tuning:** High-fidelity for AD credential theft. Targets ntdsutil, vssadmin shadow copies, esentutl copies of ntds, and secretsdump. Excludes Linux `find` credential harvesting noise.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: NTDS.dit / SAM Access"
frequency: "1h"
lookback: "1h"
severity: "high"
mitre: ["T1003.003", "T1003.002"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: NTDS.dit / SAM Database Access
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // ntdsutil execution (AD database manipulation)
    FileName =~ "ntdsutil.exe"
    // Volume shadow copy creation (precursor to NTDS.dit theft)
    or (ProcessCommandLine has "vssadmin" and ProcessCommandLine has "shadow"
        and ProcessCommandLine has "create")
    // esentutl copying NTDS
    or (FileName =~ "esentutl.exe" and ProcessCommandLine has "ntds")
    // secretsdump (Impacket)
    or ProcessCommandLine has "secretsdump"
    // PsExec to DC with NTDS/SAM operations
    or (ProcessCommandLine has "ntds" and ProcessCommandLine has_any ("stop", "start", "dit", "SidHistory"))
    // Direct SAM hive extraction
    or (FileName =~ "reg.exe" and ProcessCommandLine has "save"
        and ProcessCommandLine has_any ("sam", "system", "security"))
// Exclude Linux find/grep noise
| where FileName !in~ ("find", "grep")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 10: Defender Antivirus Tampering (Registry)

**MITRE:** T1562.001 | **Tactic:** Defense Evasion | **Tool:** Advanced Hunting  
**Tuning:** Monitors registry changes to Defender settings. Excludes TemporaryPaths set by MsMpEng.exe itself (normal scanning behavior) — focuses on actor-initiated exclusions.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: Defender AV Tampering"
frequency: "1h"
lookback: "1h"
severity: "high"
mitre: ["T1562.001"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: Defender Antivirus Tampering via Registry
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has "Windows Defender"
    and (RegistryKey has_any ("Exclusions\\Paths", "Exclusions\\Extensions", "Exclusions\\Processes",
        "DisableAntiSpyware", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
        "DisableOnAccessProtection", "DisableRoutinelyTakingAction"))
// Exclude Defender engine self-managing temporary exclusions
| where not(InitiatingProcessFileName =~ "msmpeng.exe" and RegistryKey has "TemporaryPaths")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
    ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 11: PowerShell AV Exclusion / Encoded Commands

**MITRE:** T1562.001, T1059.001 | **Tactic:** Defense Evasion, Execution | **Tool:** Data Lake  
**Note:** This query must use Data Lake — Advanced Hunting safety filter blocks queries containing AV-disabling command patterns.  
**Tuning:** Excludes Azure Guest Configuration (`gc_worker.exe`) and Intune agent encoded commands which are benign.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Must use Data Lake due to AH safety filter. Contains PowerShell exclusion patterns that trigger content filtering."
-->

```kql
// Storm-1175 TTP: PowerShell AV Exclusion Path Manipulation
// MUST run via Data Lake (mcp_sentinel-data_query_lake) — blocked by AH safety filter
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Add-MpPreference", "Set-MpPreference", "-ExclusionPath")
// Exclude known benign sources
| where InitiatingProcessFileName !in~ ("gc_worker.exe",
    "microsoft.management.services.cloudmanageddesktop.agent.exe",
    "senseir.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName
| order by TimeGenerated desc
```

---

### Query 12: Rclone / Bandizip Data Exfiltration Tools

**MITRE:** T1567, T1048, T1560 | **Tactic:** Exfiltration, Collection | **Tool:** Advanced Hunting  
**Tuning:** Targets both known process names and Rclone-specific command line patterns.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: Rclone / Bandizip Exfiltration"
frequency: "24h"
lookback: "24h"
severity: "high"
mitre: ["T1567", "T1048", "T1560"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: Rclone / Bandizip Data Exfiltration
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // Known Rclone binary names (including Storm-1175's renamed lsp.exe)
    FileName in~ ("rclone.exe", "lsp.exe")
    // Bandizip archiving tool
    or FileName in~ ("Bandizip.exe", "bz.exe")
    // Rclone command-line patterns
    or (ProcessCommandLine has "rclone" and ProcessCommandLine has_any ("sync", "copy", "move", "config"))
    // Cloud storage provider keywords (catches Rclone even when further renamed)
    or (ProcessCommandLine has "sync"
        and ProcessCommandLine has_any (
            "mega:", "s3:", "b2:", "onedrive:", "gdrive:", "ftp:", "sftp:",
            "dropbox:", "azureblob:", "wasabi:", "backblaze:"
        ))
    // RunFileCopy.cmd — Storm-1175 ransomware deployment script
    or ProcessCommandLine has "RunFileCopy.cmd"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName,
    SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 13: PsExec / Impacket Lateral Movement

**MITRE:** T1021.002, T1569.002 | **Tactic:** Lateral Movement | **Tool:** Advanced Hunting  
**Tuning:** Detects both PsExec and Impacket-based lateral movement. PsExec detection covers both source-side execution and target-side service creation (`services.exe → cmd.exe /c`). Impacket detection covers `wmiexec`, `smbexec`, `atexec`, and `dcomexec` modules.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: PsExec / Impacket Lateral Movement"
frequency: "1h"
lookback: "1h"
severity: "high"
mitre: ["T1021.002", "T1569.002"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: PsExec and Impacket Lateral Movement
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // PsExec source-side execution
    FileName in~ ("psexec.exe", "psexec64.exe", "PsExec.exe")
    // PsExec target-side: service creation spawning cmd
    or (InitiatingProcessFileName =~ "psexesvc.exe"
        and ProcessCommandLine has_any (
            // Credential theft tools
            "Rubeus", "mimikatz", "sekurlsa", "lsass", "ntds", "secretsdump",
            // Payload delivery from suspicious paths
            "Temp\\", "ProgramData\\", "AppData\\",
            // Scripting engines
            "powershell", "cmd /c",
            // Collection / exfil / ransomware
            "rclone", "bandizip", ".MEDUSA"
        ))
    // Impacket lateral movement modules
    or (ProcessCommandLine has_any ("wmiexec", "smbexec", "atexec", "dcomexec")
        and FileName in~ ("python.exe", "python3.exe", "cmd.exe", "powershell.exe"))
    // Impacket target-side: services.exe spawning cmd.exe /c (PsExec service pattern)
    or (InitiatingProcessFileName =~ "services.exe" and FileName =~ "cmd.exe"
        and ProcessCommandLine has "/c" and ProcessCommandLine has_any (
            "echo", "\\\\127.0.0.1\\", "__output"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 14: RDP Firewall Modification

**MITRE:** T1021.001, T1562.004 | **Tactic:** Lateral Movement, Defense Evasion | **Tool:** Advanced Hunting  
**Tuning:** Detects enablement of RDP via firewall rule changes or registry modification.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: RDP Firewall Modification"
frequency: "1h"
lookback: "1h"
severity: "medium"
mitre: ["T1021.001", "T1562.004"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: RDP Firewall Enablement
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // netsh firewall modification for RDP
    (FileName in~ ("netsh.exe") and ProcessCommandLine has "firewall"
        and ProcessCommandLine has_any ("3389", "Remote Desktop"))
    // Registry modification to enable RDP
    or (FileName =~ "reg.exe" and ProcessCommandLine has "Terminal Server"
        and ProcessCommandLine has "fDenyTSConnections")
    // PowerShell firewall rule changes for RDP
    or (FileName in~ ("powershell.exe", "pwsh.exe")
        and ProcessCommandLine has_any ("Enable-NetFirewallRule", "Set-NetFirewallRule")
        and ProcessCommandLine has_any ("3389", "RemoteDesktop"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 15: Medusa Ransomware File Artifacts

**MITRE:** T1486 | **Tactic:** Impact | **Tool:** Advanced Hunting  
**Tuning:** Searches for Medusa-specific file patterns: `.MEDUSA` encrypted extension, ransom note, Gaze.exe binary.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: Medusa Ransomware Artifacts"
frequency: "1h"
lookback: "1h"
severity: "high"
mitre: ["T1486"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 Impact: Medusa Ransomware File Artifacts
DeviceFileEvents
| where Timestamp > ago(30d)
| where
    // Medusa encrypted file extension
    FileName endswith ".MEDUSA" or FileName endswith ".medusa"
    // Medusa ransom notes (multiple observed variants)
    or FileName in~ ("!!!READ_ME_MEDUSA!!!.txt", "MEDUSA_README.txt")
    // Broad catch for any MEDUSA-related file creation
    or (FileName has "MEDUSA" and ActionType == "FileCreated")
    // Known Medusa binary names
    or FileName in~ ("Gaze.exe", "gaze.exe")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 16: Web Shell Creation on Web Servers

**MITRE:** T1505.003 | **Tactic:** Persistence | **Tool:** Advanced Hunting  
**Tuning:** Detects creation of web-executable files in web server directories — common Storm-1175 initial persistence mechanism.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: Web Shell Creation"
frequency: "1h"
lookback: "1h"
severity: "high"
mitre: ["T1505.003"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: Web Shell Creation on Web Servers
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where (FileName endswith ".aspx" or FileName endswith ".asmx" or FileName endswith ".ashx"
    or FileName endswith ".jsp" or FileName endswith ".jspx"
    or FileName endswith ".php" or FileName endswith ".cfm")
| where FolderPath has_any ("inetpub", "wwwroot", "webapps", "htdocs", "www", "public_html",
    "SmarterMail", "Papercut", "TeamCity", "ScreenConnect",
    "Exchange", "OWA", "ECP", "tomcat", "nginx")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 17: Vulnerability Exposure Assessment

**MITRE:** T1190 | **Tactic:** Initial Access | **Tool:** Advanced Hunting  
**Tuning:** Checks TVM data for any devices vulnerable to CVEs exploited by Storm-1175.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "DeviceTvmSoftwareVulnerabilities has no Timestamp column. Assessment query only — cannot be scheduled as custom detection."
-->

```kql
// Storm-1175: Vulnerable Software Inventory Check
DeviceTvmSoftwareVulnerabilities
| where CveId in (
    "CVE-2023-21529", "CVE-2023-27351", "CVE-2023-27350",
    "CVE-2023-46805", "CVE-2024-21887",
    "CVE-2024-1709", "CVE-2024-1708",
    "CVE-2024-27198", "CVE-2024-27199",
    "CVE-2024-57726", "CVE-2024-57727", "CVE-2024-57728",
    "CVE-2025-31161", "CVE-2025-10035",
    "CVE-2025-52691", "CVE-2026-23760",
    "CVE-2026-1731"
)
| summarize CVEs = make_set(CveId), Software = make_set(SoftwareName)
    by DeviceName, VulnerabilitySeverityLevel
| order by VulnerabilitySeverityLevel desc
```

---

### Query 18: Correlated Defender Alerts for Storm-1175 TTPs

**MITRE:** Multiple | **Tactic:** All Phases | **Tool:** Advanced Hunting  
**Tuning:** Searches existing Defender alerts for titles matching Storm-1175 TTP detections.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summary/correlation query for alert review — not suitable for custom detection deployment."
-->

```kql
// Storm-1175: Correlated Defender Alert Review
AlertInfo
| where Timestamp > ago(30d)
| where Title has_any (
    "Medusa", "ransomware", "PsExec", "credential theft",
    "LSASS", "suspicious account", "remote monitoring",
    "SimpleHelp", "AnyDesk", "Rclone", "web shell",
    "Mimikatz", "antivirus exclusion", "Defender detection bypass",
    "remote access", "lateral movement", "data exfiltration"
)
| join kind=leftouter AlertEvidence on AlertId
| summarize
    Devices = make_set(DeviceName, 10),
    Users = make_set(AccountUpn, 10),
    EvidenceCount = count(),
    AlertTime = min(Timestamp)
    by AlertId, Title, Severity, Category
| order by AlertTime desc
```

---

### Query 19: Veeam Backup Credential Recovery

**MITRE:** T1555 | **Tactic:** Credential Access | **Tool:** Advanced Hunting  
**Tuning:** Detects scripts targeting Veeam backup credentials — a Storm-1175-specific technique for pivoting to additional hosts.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: Veeam Credential Recovery"
frequency: "24h"
lookback: "24h"
severity: "high"
mitre: ["T1555"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: Veeam Backup Credential Recovery
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // Scripts targeting Veeam credential database
    (ProcessCommandLine has "VeeamBackup" and ProcessCommandLine has_any ("password", "credential", "SqlConnection"))
    // Known Veeam credential extraction tools
    or ProcessCommandLine has_any ("Veeam-Get-Creds", "VeeamHax", "veeam_cred")
    // PowerShell accessing Veeam database
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has "Veeam"
        and ProcessCommandLine has_any ("Invoke-Sql", "SqlConnection", "password"))
    // SQL tools querying Veeam backup database directly
    or (FileName in~ ("sqlcmd.exe", "osql.exe") and ProcessCommandLine has "VeeamBackup")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 20: PDQ Deploy Weaponized for Payload Delivery

**MITRE:** T1072 | **Tactic:** Lateral Movement, Execution | **Tool:** Advanced Hunting  
**Tuning:** Detects PDQ Deploy execution and child processes. Storm-1175 uses PDQ Deploy to distribute Medusa ransomware and `RunFileCopy.cmd` across domain-joined systems at scale. PDQ Deploy is a legitimate IT tool — focus on unexpected installations, non-catalog payloads, and deployments outside maintenance windows.

<!-- cd-metadata
cd_ready: true
name: "Storm-1175: PDQ Deploy Payload Delivery"
frequency: "24h"
lookback: "24h"
severity: "high"
mitre: ["T1072"]
impacted_entity: "DeviceName"
-->

```kql
// Storm-1175 TTP: PDQ Deploy Weaponized for Payload Delivery
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // PDQ Deploy execution
    FileName in~ ("PDQDeploy.exe", "PDQDeployRunner.exe", "PDQInventory.exe")
    // Child processes launched by PDQ Deploy runner
    or InitiatingProcessFileName =~ "PDQDeployRunner.exe"
    // RunFileCopy.cmd — Storm-1175 ransomware deployment script distributed via PDQ
    or ProcessCommandLine has "RunFileCopy"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, DeviceId
| order by Timestamp desc
```

---

## Tuning Notes

These queries were tested and tuned to reduce false positives in a production Defender XDR environment:

| Query | Issue Found | Tuning Applied |
|-------|-------------|----------------|
| Q3 (RMM) | `reg.exe` false positives from command line matching | Split into Q3 (process name only) + Q4 (Safe Mode persistence pattern) |
| Q8 (LSASS) | MDE Client Analyzer procdump on msinfo32 matched `-ma` flag | Added explicit `lsass` target requirement for procdump |
| Q9 (NTDS) | Linux `find` commands listing ntds.dit as search target | Added `FileName !in~ ("find", "grep")` exclusion |
| Q10 (Defender) | MsMpEng.exe self-managing TemporaryPaths exclusions | Excluded `InitiatingProcessFileName =~ "msmpeng.exe"` + `TemporaryPaths` |
| Q11 (PS AV) | Azure Guest Config (`gc_worker.exe`) + Intune agent encoded commands | Excluded known benign parent processes; moved to Data Lake (AH safety filter blocks) |
| Q6 (Cloudflare) | Credential harvesting `find` commands mentioning `.cloudflared` directory | Refined to require `tunnel` keyword for cloudflared.exe execution |
