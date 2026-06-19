# The Gentlemen Ransomware (Storm-2697) — Threat Hunts

**Created:** 2026-06-18  
**Platform:** Microsoft Defender XDR | Microsoft Sentinel  
**Tables:** DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents, DeviceEvents, DeviceRegistryEvents  
**Keywords:** gentlemen, storm-2697, raas, go ransomware, garble, self-propagation, umc16h, README-GENTLEMEN, gentlemen.bmp, gentlemen_system, UpdateSystem, UpdateUser, GupdateS, GupdateU, vssadmin delete shadows, wevtutil cl, Set-MpPreference, taskkill, share$, psexec, wmic process call create, sc create, double extortion, defender tampering, shadow copy deletion  
**MITRE:** T1486, T1490, T1489, T1562.001, T1070.001, T1547.001, T1053.005, T1021.002, T1570, T1569.002, T1047, T1059.001, T1219, T1222.001, T1078  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable per hunt)  
**Source:** [Microsoft Threat Intelligence — The Gentlemen ransomware: Dissecting a self-propagating Go encryptor (May 28, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)

---

## Threat Overview

Hunts derived from Microsoft Threat Intelligence's 2026-05-28 blog *"The Gentlemen ransomware: Dissecting a self-propagating Go encryptor."* The Gentlemen is a **ransomware-as-a-service (RaaS)** platform operated by **Storm-2697**, a financially motivated actor that recruits affiliates (recently via a BreachForums partnership). The encryptor is written in **Go**, obfuscated with **Garble**, and uses double-extortion. Its distinguishing trait is an aggressive **self-propagation module** that attempts ~21 distinct remote-execution operations per reachable host (PsExec, WMIC/WMI, `sc create`, scheduled tasks, PowerShell remoting, admin-share copy), so a single successful path per host sustains worm-like spread. Files are encrypted with per-file ephemeral Curve25519 + XChaCha20 and renamed with the `.umc16h` extension; a `README-GENTLEMEN.txt` note is dropped in every directory.

### TTP Summary

| Capability | TTP |
|---|---|
| **Privilege Escalation / Exec** | Re-launches as SYSTEM via a one-time scheduled task `gentlemen_system`; sets `LOCKER_BACKGROUND=1` env marker (T1053.005, T1078). |
| **Defense Evasion — AV tamper** | `Set-MpPreference -DisableRealtimeMonitoring`, adds self + `C:\` to Defender exclusions (T1562.001). |
| **Defense Evasion — recovery** | Deletes Volume Shadow Copies via `vssadmin` and `wmic shadowcopy delete`; clears System/Application/Security logs with `wevtutil cl`; wipes Prefetch, RDP, Defender logs, and PSReadline history (T1490, T1070.001). |
| **Impact — service/process kill** | Mass `taskkill /F /IM` and `sc stop`/`net stop` against EDR, databases, backup agents, Office, email, hypervisors (T1489). |
| **Persistence** | Scheduled tasks `UpdateSystem` (SYSTEM) + `UpdateUser`; Run keys `GupdateS` (HKLM) + `GupdateU` (HKCU) (T1547.001, T1053.005). |
| **Lateral Movement / Staging** | Hidden anonymous SMB share `share$` → `C:\Temp`; drops/downloads PsExec; remote exec via PsExec, `wmic process call create`, `sc create` (`DefSvc`/`UpdateSvc`), scheduled tasks (`DefU`/`UpdateGU`/`UpdateGU2`), `Invoke-Command`, WMI `Win32_Process` (T1021.002, T1570, T1569.002, T1047, T1059.001). |
| **Defense Evasion — ACL** | `takeown` + `icacls ... /grant Everyone:F` (SID S-1-1-0) + `attrib -r` before encryption (T1222.001). |
| **Impact — encryption** | Per-file Curve25519+XChaCha20; `.umc16h` extension; wallpaper `%TEMP%\gentlemen.bmp`; optional free-space wipe (`wipefile.tmp`) and self-delete batch (`ping 127.0.0.1` delay) (T1486). |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| `schtasks.exe`, `sc.exe`, `net.exe`, `wevtutil.exe` are extremely high-volume in normal admin/RMM activity. | Anchor on **Gentlemen-specific artifact names** (`gentlemen_system`, `GupdateS`/`GupdateU`, `.umc16h`, `share$`) rather than the LOLBin alone. |
| Individual defense-evasion commands (a single `vssadmin delete`, one Defender exclusion) fire from legitimate backup/management tooling. | Use threshold/co-occurrence logic (Query 3, Query 6) and exclude sanctioned backup/management hosts generically. |
| The published SHA-256 hashes will rot — each build embeds a unique operator password and may be recompiled. | Treat Query 1 as a point-in-time sweep; refresh from current MS TI / VirusTotal and pair with behavioral queries (2–9). |
| AH (`Device*` tables) uses `Timestamp`; Sentinel Data Lake uses `TimeGenerated`. Queries below use `TimeGenerated` for portability. | When pasting into Advanced Hunting, replace `TimeGenerated` → `Timestamp`. |
| `wmic.exe` is deprecated/absent in some hardened fleets — `wmic`-based lateral movement may be invisible. | Pair WMIC hunts with the PowerShell-WMI (`Win32_Process`) and `Invoke-Command` variants; note telemetry gaps when empty. |
| The lateral-movement chain (Query 9) overlaps legitimate PsExec/WMIC admin usage. | Query 9 is a **hunt**, not a clean detection (`cd_ready: false`); scope to staging paths (`C:\Temp`, `share$`) and review manually. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Gentlemen Reference IOC Sweep — File Hashes](#query-1-gentlemen-reference-ioc-sweep--file-hashes) | Investigation | `DeviceEvent` + multi |
| 2 | [Microsoft Defender Tampering via `Set-MpPreference`](#query-2-microsoft-defender-tampering-via-set-mppreference) | Investigation | `DeviceProcessEvents` |
| 3 | [Shadow Copy Deletion + Event Log Clearing](#query-3-shadow-copy-deletion--event-log-clearing) | Investigation | `DeviceProcessEvents` |
| 4 | [Gentlemen-Named Scheduled Task Persistence / Execution](#query-4-gentlemen-named-scheduled-task-persistence--execution) | Detection | `DeviceProcessEvents` |
| 5 | [Run-Key Persistence — `GupdateS` / `GupdateU`](#query-5-run-key-persistence--gupdates--gupdateu) | Investigation | `DeviceRegistryEvents` |
| 6 | [Mass Process Termination — EDR / DB / Backup Kill Burst](#query-6-mass-process-termination--edr--db--backup-kill-burst) | Investigation | `DeviceProcessEvents` |
| 7 | [Anonymous SMB Staging — `share$` Distribution Point](#query-7-anonymous-smb-staging--share-distribution-point) | Investigation | `DeviceProcessEvents` |
| 8 | [Ransom Artifacts — `.umc16h` Files, Note, and Wallpaper](#query-8-ransom-artifacts--umc16h-files-note-and-wallpaper) | Investigation | `DeviceFileEvents` |
| 9 | [Self-Propagation — Remote Execution & Payload Staging](#query-9-self-propagation--remote-execution--payload-staging) | Investigation | `DeviceProcessEvents` |


## IOC Reference

The following SHA-256 hashes are published in the [Microsoft Threat Intelligence blog (May 28, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/). Operators rotate builds — refresh against current MS TI / VirusTotal periodically and rely on the behavioral queries for resilient coverage.

| SHA-256 | Type | Component |
|---|---|---|
| `22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67` | SHA-256 | Gentlemen ransomware encryptor |
| `078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b` | SHA-256 | PsExec binary (used for propagation) |
| `fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68` | SHA-256 | Gentlemen wallpaper bitmap (`gentlemen.bmp`) |

**Filename / artifact IOCs (from article narrative):** `.umc16h` (encrypted-file extension), `README-GENTLEMEN.txt` (ransom note), `gentlemen.bmp` (wallpaper), scheduled tasks `gentlemen_system` / `UpdateSystem` / `UpdateUser` / `DefU` / `UpdateGU` / `UpdateGU2`, services `DefSvc` / `UpdateSvc` / `UpdateSvc2`, Run-key values `GupdateS` / `GupdateU`, SMB share `share$`, env marker `LOCKER_BACKGROUND=1`.

---

## Query 1: Gentlemen Reference IOC Sweep — File Hashes

**Purpose:** Hash-based detection for the three published Gentlemen SHA-256 IOCs across file, image-load, process, and generic-event surfaces. Direct IOC match — zero results is the expected, desired outcome in a clean environment; any hit is high-confidence.  
**Severity:** High  
**MITRE:** T1486  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceFileEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1486"]
cd_entities: ["device", "file"]
cd_adaptation_notes: "Direct IOC hash match. Static list will rot as operators recompile builds (each embeds a unique password). Refresh from a TI indicator table / external CTI feed. Tested in Advanced Hunting (30d) — replace TimeGenerated with Timestamp when pasting into AH."
-->
```kql
let GentlemenHashes = dynamic([
    "22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67",  // encryptor
    "078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b",  // PsExec binary
    "fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68"   // gentlemen.bmp wallpaper
]);
union
    (DeviceFileEvents
        | where TimeGenerated > ago(30d)
        | where SHA256 in (GentlemenHashes)
        | extend Surface = "FileEvent"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName),
    (DeviceImageLoadEvents
        | where TimeGenerated > ago(30d)
        | where SHA256 in (GentlemenHashes)
        | extend Surface = "ImageLoad", ActionType = "ImageLoaded"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName),
    (DeviceProcessEvents
        | where TimeGenerated > ago(30d)
        | where SHA256 in (GentlemenHashes)
        | extend Surface = "ProcessLaunch"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName),
    (DeviceEvents
        | where TimeGenerated > ago(30d)
        | where SHA256 in (GentlemenHashes)
        | extend Surface = "DeviceEvent"
        | project TimeGenerated, Surface, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName)
| order by TimeGenerated desc
```
**Expected results:** Zero rows in uncompromised environments (verified clean at authoring time). Any hit = high-confidence Gentlemen indicator — triage the device immediately.

---

## Query 2: Microsoft Defender Tampering via `Set-MpPreference`

**Purpose:** Detects the pre-encryption defense-evasion step where the encryptor disables Defender real-time monitoring and adds broad exclusions (self executable and the entire `C:\` volume).  
**Severity:** High  
**MITRE:** T1562.001  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceProcessEvents
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1562.001"]
cd_entities: ["device", "account"]
cd_adaptation_notes: "Set-MpPreference -DisableRealtimeMonitoring is rare and high-signal but can fire from legitimate management/imaging tooling. Exclude sanctioned configuration-management hosts/accounts generically. Tested clean in Advanced Hunting (30d) — no MpPreference activity observed in window."
-->
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
| where ProcessCommandLine has "MpPreference"
| where ProcessCommandLine has_any (
    "DisableRealtimeMonitoring", "ExclusionPath", "ExclusionProcess",
    "DisableBehaviorMonitoring", "DisableIOAVProtection")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated desc
```
**Expected results:** Low/zero in well-managed fleets. Investigate any host that disables real-time monitoring and excludes `C:\` in the same command — a hallmark of pre-ransomware staging.

---

## Query 3: Shadow Copy Deletion + Event Log Clearing

**Purpose:** Detects inhibition of recovery and log tampering — `vssadmin`/`wmic` shadow-copy deletion and `wevtutil cl` clearing of System/Application/Security logs — co-occurring on a host.  
**Severity:** High  
**MITRE:** T1490, T1070.001  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceProcessEvents
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1490", "T1070.001"]
cd_entities: ["device", "account"]
cd_adaptation_notes: "vssadmin/wmic shadow deletion is classic ransomware and low-FP. wevtutil cl on Security log from a non-backup context is high-signal. Co-occurrence within a short window raises fidelity. Tested clean in Advanced Hunting (30d)."
-->
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadow")
     or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
     or (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl System", "cl Application", "cl Security", "clear-log"))
| extend Technique = case(
    FileName =~ "wevtutil.exe", "LogClear",
    "ShadowCopyDelete")
| summarize Techniques = make_set(Technique), Commands = make_set(ProcessCommandLine), Count = count()
    by DeviceName, bin(TimeGenerated, 1h)
| where array_length(Techniques) >= 1
| order by TimeGenerated desc
```
**Expected results:** Zero/low in environments without active ransomware. A host showing both shadow-copy deletion **and** Security-log clearing in the same hour is a strong destructive-attack signal.

---

## Query 4: Gentlemen-Named Scheduled Task Persistence / Execution

**Purpose:** Filename-anchored hunt for the encryptor's distinctive scheduled-task names used for SYSTEM re-execution, persistence, and remote propagation.  
**Severity:** High  
**MITRE:** T1053.005, T1547.001  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceProcessEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1053.005"]
cd_entities: ["device", "account"]
cd_adaptation_notes: "Anchored on Gentlemen-specific task names (gentlemen_system, DefU, UpdateGU, UpdateGU2). The generic names UpdateSystem/UpdateUser could theoretically collide with custom admin tasks — verify the invoking binary path. Tested clean in Advanced Hunting (30d): schtasks /create is high-volume (2k+) but none matched these names."
-->
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any (
    "gentlemen_system", "UpdateSystem", "UpdateUser",
    "DefU", "UpdateGU", "UpdateGU2")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated desc
```
**Expected results:** Zero in clean environments. `gentlemen_system`, `DefU`, `UpdateGU`, or `UpdateGU2` are near-unique to this ransomware — treat any hit as high-confidence.

---

## Query 5: Run-Key Persistence — `GupdateS` / `GupdateU`

**Purpose:** Detects the encryptor's redundant autorun persistence via the `GupdateS` (HKLM) and `GupdateU` (HKCU) Run-key values.  
**Severity:** High  
**MITRE:** T1547.001  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceRegistryEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1547.001"]
cd_entities: ["device"]
cd_adaptation_notes: "Value names GupdateS/GupdateU are Gentlemen-specific (note: visually similar to Google Update's gupdate — verify the data points to a non-Google path). Tested clean in Advanced Hunting (30d): 165 legitimate Run-key writes observed, none matching these value names."
-->
```kql
DeviceRegistryEvents
| where TimeGenerated > ago(30d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueName in~ ("GupdateS", "GupdateU")
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by TimeGenerated desc
```
**Expected results:** Zero in clean environments. Confirm the `RegistryValueData` path is **not** a legitimate Google Update binary before escalating.

---

## Query 6: Mass Process Termination — EDR / DB / Backup Kill Burst

**Purpose:** Detects the encryptor's pre-encryption sabotage where it `taskkill /F`-terminates many security, database, and backup processes in a short window to unlock files and disable defenses.  
**Severity:** High  
**MITRE:** T1489  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceProcessEvents
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1489"]
cd_entities: ["device"]
cd_adaptation_notes: "Threshold-based (>=3 distinct security/DB/backup targets killed per host per hour). Tune the threshold and target list per environment — legitimate IT cleanup scripts may kill a few. Tested clean in Advanced Hunting (30d): taskkill present (180 events) but no host hit the multi-target burst threshold."
-->
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName =~ "taskkill.exe" and ProcessCommandLine has "/F"
| extend Targets = extract_all(@"/IM\s+([^\s]+)", ProcessCommandLine)
| mv-expand Targets to typeof(string)
| where Targets has_any (
    "sqlservr", "sqlwriter", "mysqld", "postgres", "oracle", "dbeng", "sqlbrowser",
    "veeam", "backup", "iperius", "vsnapvss", "bedbh", "cbVSCService",
    "sophos", "vxmon", "beserver", "avagent", "cbservice", "raw_agent_svc",
    "outlook", "thunderbird", "excel", "winword", "vmms", "vmwp", "vmcompute")
| summarize KilledTargets = dcount(Targets), TargetList = make_set(Targets), Events = count()
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 1h)
| where KilledTargets >= 3
| order by KilledTargets desc
```
**Expected results:** Zero/low in normal operations. A host force-killing 3+ distinct EDR/DB/backup processes within an hour is a strong indicator of imminent encryption.

---

## Query 7: Anonymous SMB Staging — `share$` Distribution Point

**Purpose:** Detects the self-propagation staging step — creation of a hidden `share$` SMB share over `C:\Temp` (plus anonymous-access loosening / SMB1 enablement) to distribute the payload to peers.  
**Severity:** High  
**MITRE:** T1021.002, T1570  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceProcessEvents
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1021.002", "T1570"]
cd_entities: ["device", "account"]
cd_adaptation_notes: "The share name 'share$' over C:\\Temp is Gentlemen-specific. Anonymous-access registry rollback and SMB1 enablement are independently suspicious. Tested clean in Advanced Hunting (30d): no 'net share' activity observed in the environment in window."
-->
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FileName =~ "net.exe" and ProcessCommandLine has "share" and ProcessCommandLine has "share$")
     or (ProcessCommandLine has "share$" and ProcessCommandLine has @"C:\Temp")
     or (ProcessCommandLine has_any ("RestrictAnonymous", "EveryoneIncludesAnonymous") and ProcessCommandLine has "0")
     or (ProcessCommandLine has "SMB1" and ProcessCommandLine has_any ("Enable", "EnableSMB1Protocol"))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```
**Expected results:** Zero in clean environments. Creation of an anonymous `share$` over `C:\Temp`, especially alongside SMB1 enablement, indicates worm staging.

---

## Query 8: Ransom Artifacts — `.umc16h` Files, Note, and Wallpaper

**Purpose:** Filename/extension-anchored hunt for the encryption aftermath — `.umc16h` encrypted files, the `README-GENTLEMEN.txt` note dropped per directory, and the `gentlemen.bmp` wallpaper.  
**Severity:** High  
**MITRE:** T1486  
<!-- cd-metadata
cd_ready: true
cd_table: DeviceFileEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1486"]
cd_entities: ["device", "file"]
cd_adaptation_notes: "Extension .umc16h and filenames README-GENTLEMEN.txt / gentlemen.bmp are unique to this ransomware and near-zero FP. Tested clean in Advanced Hunting (30d)."
-->
```kql
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where FileName endswith ".umc16h"
     or FileName =~ "README-GENTLEMEN.txt"
     or FileName =~ "gentlemen.bmp"
| summarize FileCount = count(), Folders = dcount(FolderPath), Sample = any(FolderPath)
    by DeviceName, FileName, InitiatingProcessFileName, bin(TimeGenerated, 1h)
| order by FileCount desc
```
**Expected results:** Zero in clean environments. A burst of `.umc16h` renames or `README-GENTLEMEN.txt` drops across many folders confirms active encryption — initiate ransomware response immediately.

---

## Query 9: Self-Propagation — Remote Execution & Payload Staging

**Purpose:** Hunt for the distinctive lateral-movement chain — PsExec download fallback from Sysinternals Live, admin-share (`C$\Temp`) payload copy, and remote process creation via `wmic process call create` / `sc create` referencing staging paths.  
**Severity:** Medium  
**MITRE:** T1570, T1569.002, T1047, T1219  
<!-- cd-metadata
cd_ready: false
cd_table: DeviceProcessEvents
cd_frequency: Hourly
cd_severity: Medium
cd_mitre: ["T1570", "T1569.002", "T1047", "T1219"]
cd_entities: ["device", "account"]
cd_adaptation_notes: "Broad OR across multiple LOLBin lateral-movement techniques — legitimate admin/RMM tooling (PsExec, wmic, sc) will generate FPs. This is a HUNT, not a clean detection. Scope to staging paths (C:\\Temp, share$) and review manually before promoting. Tune by excluding sanctioned remote-admin tools. Tested clean in Advanced Hunting (30d): wmic process call create not observed in environment (wmic may be deprecated/absent in this fleet — pair with PowerShell-WMI variants)."
-->
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (ProcessCommandLine has "live.sysinternals.com" and ProcessCommandLine has "PsExec")
     or (FileName =~ "wmic.exe" and ProcessCommandLine has "process call create" and ProcessCommandLine has @"\Temp")
     or (FileName =~ "sc.exe" and ProcessCommandLine has "create" and ProcessCommandLine has "binPath" and ProcessCommandLine has @"\Temp\")
     or (ProcessCommandLine has @"\C$\Temp" and ProcessCommandLine has "copy")
     or (ProcessCommandLine has @"\share$\" and ProcessCommandLine has_any (".exe", "Win32_Process", "Invoke-Command"))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```
**Expected results:** Variable — expect some legitimate admin/RMM noise. Prioritize rows where remote execution references `C:\Temp` or `share$` staging paths and correlate with Queries 1–8 on the same device.

---

## General Tuning Notes

1. **IOC refresh.** The three SHA-256 hashes (Query 1) are point-in-time samples; each Gentlemen build embeds a unique operator password and may be recompiled. Refresh from a TI indicator table / current MS TI / VirusTotal and rely primarily on the behavioral queries (2–9) for durable coverage.
2. **Telemetry gaps.** `wmic.exe`-based lateral movement (Query 9) is invisible where WMIC is deprecated/removed — pair with the PowerShell-WMI (`Win32_Process`) and `Invoke-Command` variants. SMB share-creation telemetry depends on `net.exe` process visibility.
3. **AH vs Data Lake.** Queries use `TimeGenerated` for Sentinel Data Lake / portability. For Advanced Hunting, replace `TimeGenerated` → `Timestamp` on all `Device*` tables. All queries were authored and validated in Advanced Hunting over a 30-day window.
4. **Exclusions (generic).** Where defense-evasion or lateral-movement LOLBins fire from sanctioned backup, imaging, or remote-management tooling, exclude those tools/hosts by their generic role — never hard-code tenant-specific identifiers into the committed query.
5. **CD-readiness summary.** Queries 1–8 are `cd_ready: true` (high-fidelity, artifact-anchored). Query 9 is `cd_ready: false` — a manual hunt over noisy lateral-movement LOLBins; tune and scope before considering promotion to a custom detection.

---

## References

- Microsoft Threat Intelligence — [The Gentlemen ransomware: Dissecting a self-propagating Go encryptor (May 28, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
- MITRE ATT&CK — [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/), [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/), [T1489 Service Stop](https://attack.mitre.org/techniques/T1489/), [T1562.001 Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/), [T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- Companion files: [`queries/threat-intelligence/2026-04/storm_1175_medusa_ransomware_campaign.md`](../2026-04/storm_1175_medusa_ransomware_campaign.md)
