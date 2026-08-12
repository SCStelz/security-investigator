# DeadLock Ransomware — Rust Encryptor Threat Hunts

**Created:** 2026-08-11  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceFileEvents, DeviceRegistryEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceImageLoadEvents  
**Keywords:** DeadLock, ransomware, Rust encryptor, dlock, HOW_RECOVER, RECOVERY_CHAT, double extortion, batch UAC elevation, RunAs, ShellExecuteW, random cmd, token privilege escalation, SeDebugPrivilege, recycle bin empty, custom icon registration, DefaultIcon, service termination, windefend, vss, swprv, wbengine, mssearch, vmcompute, vmms, adws, ntds, kdc, process termination, event log clearing, wevtutil, WINEVT Channels, wallpaper change, Policies System Wallpaper, self-deletion batch, Session messenger, Polygon blockchain, EtherHiding, Wasabi, leak site, Lynx, INC ransomware  
**MITRE:** T1486, T1548.002, T1134.001, T1489, T1562.001, T1070.001, T1490, T1112, T1036.005, T1485, T1070.004, T1657  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [DeadLock ransomware: Breaking down a Rust-based encryptor with decentralized recovery infrastructure (2026-08-10)](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/)

---

## Threat Overview

Microsoft Threat Intelligence tracks **DeadLock** as an emerging, financially motivated ransomware operation first observed in July 2025 and deployed by multiple groups, including an affiliate of the **Lynx** and **INC** ransomware ecosystems. The Rust-based encryptor uses double extortion, language/country geofencing (CIS + select Middle Eastern locales) to self-delete in excluded regions, and a distinctive **decentralized recovery ecosystem** — the Session messaging network, Polygon blockchain smart contracts for configuration/leak-blog storage, and Wasabi S3 for leaked-file hosting — to resist takedowns.

On the host, the encryptor attempts **batch-script UAC elevation** (a randomly named 8-uppercase `.cmd` launched via `ShellExecuteW` with the `RunAs` verb), enables sensitive token privileges, empties the recycle bin, terminates security/backup/AD processes and services, clears and disables event log channels, encrypts files to a **`.dlock`** extension, registers a custom `.dlock` icon, changes the desktop wallpaper via registry policy, drops `HOW_RECOVER.<UID>.txt` and `RECOVERY_CHAT.<UID>.html` ransom notes, and self-deletes via a looping batch script.

### TTP Summary
| Capability | TTP |
|---|---|
| File encryption to `.dlock`; ransom notes | Data Encrypted for Impact (T1486) |
| Random 8-uppercase `.cmd` launched via `RunAs`/`ShellExecuteW` | Abuse Elevation Control Mechanism: Bypass UAC (T1548.002) |
| Enables SeDebug/SeRestore/SeBackup/SeTakeOwnership/SeAudit/SeSecurity | Access Token Manipulation: Token Impersonation/Theft (T1134.001) |
| Disables/stops `windefend`, `vss`, `swprv`, `wbengine`, `mssearch`, Hyper-V, AD services | Service Stop (T1489); Impair Defenses: Disable/Modify Tools (T1562.001) |
| Terminates security/backup/remote-access/shell processes | Service Stop (T1489) |
| Empties recycle bin; disables VSS/backup to block recovery | Inhibit System Recovery (T1490) |
| Clears Application/Security/System logs, disables WINEVT channels | Indicator Removal: Clear Windows Event Logs (T1070.001) |
| Registers custom `.dlock` DefaultIcon; changes wallpaper via policy | Modify Registry (T1112) |
| Self-deleting batch loop removes the encryptor binary | Indicator Removal: File Deletion (T1070.004) |
| Decentralized leak site / blockchain infra for extortion | Financial Theft (T1657) |

### ⚠️ Hunt Pitfalls
| Pitfall | Mitigation |
|---|---|
| These are XDR-native `Device*` tables — use `Timestamp`, not `TimeGenerated`, in Advanced Hunting | Follow the `copilot-instructions.md` table pitfalls |
| Ransom-note text (`HOW_RECOVER.<UID>.txt`) only drops on the **second** directory-processing pass — a single-iteration/minimal test may never produce it | Do not treat note absence as absence of encryption; anchor on the `.dlock` rename (Query 1) |
| Legitimate admin/service-management tools also stop services and run `.cmd` scripts | Anchor behavioral queries on the DeadLock target **stop-list** and the random-name pattern; require volume/co-occurrence thresholds (Queries 3–5) |
| `wevtutil.exe` is used benignly (e.g., Office ETW manifest install with `im`) | Filter to the **`cl`/clear-log** verb and core channels only (Query 4) |
| Published IOCs (hash + leak-site domains) rotate | Refresh from current Microsoft TI / VirusTotal before relying on Queries 6–7 |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [DeadLock encrypted-file rename and ransom-note drop](#query-1-deadlock-encrypted-file-rename-and-ransom-note-drop) | Investigation | `DeviceFileEvents` |
| 2 | [DeadLock registry branding — `.dlock` DefaultIcon and wallpaper policy](#query-2-deadlock-registry-branding--dlock-defaulticon-and-wallpaper-policy) | Investigation | `DeviceRegistryEvents` |
| 3 | [Randomly named 8-uppercase `.cmd` UAC elevation attempt](#query-3-randomly-named-8-uppercase-cmd-uac-elevation-attempt) | Investigation | `DeviceProcessEvents` |
| 4 | [Mass event-log clearing / channel disabling](#query-4-mass-event-log-clearing--channel-disabling) | Investigation | `DeviceProcessEvents` + `EventLog` |
| 5 | [Bulk termination of security, backup, and AD services](#query-5-bulk-termination-of-security-backup-and-ad-services) | Investigation | `DeviceProcessEvents` |
| 6 | [DeadLock encryptor hash sweep](#query-6-deadlock-encryptor-hash-sweep) | Investigation | `DeviceFileEvents` + multi |
| 7 | [DeadLock leak-site domain network sweep](#query-7-deadlock-leak-site-domain-network-sweep) | Investigation | `DeviceNetworkEvents` |


## IOC Reference

> Published indicators from the article's "Indicators of compromise" table. IOCs rot — operators rotate hashes and infrastructure. Refresh from current Microsoft Threat Intelligence / VirusTotal before depending on the direct-match sweeps (Queries 6–7). Domains are defanged here and de-fanged (bracketed) in prose; queries use plain forms.

| Indicator | Type | Description |
|---|---|---|
| `a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4` | SHA-256 | DeadLock ransomware encryptor |
| `deadlock.liveblog365[.]com` | Domain/URL | Leak site domain |
| `dlock.liveblog365[.]com` | Domain/URL | Leak site domain |
| `deadblogdbdu5wprek7wa2o4ce7rnt6u6ntqeud3hzjjcveosgpsqqqd[.]onion` | URL | Leak site (Tor) domain |
| `deadlockblog.great-site[.]net` | Domain/URL | Leak site domain |
| `deadlockblog.medianewsonline[.]com` | Domain/URL | Leak site domain |

**On-chain / decentralized infrastructure (context — not host IOCs):** Polygon smart contracts `0x8EF7c3e531d871D3B9D559722DE77EB1dEc19dAe` (chat proxy) and `0x757984507c82c8dA1d3969c535dB5706eEE6426C` (blog); public Polygon RPC endpoints (`polygon-bor-rpc.publicnode[.]com`, `polygon.drpc[.]org`, `polygon-pokt.nodies[.]app`, `polygon-rpc[.]com`, `1rpc[.]io/matic`, `polygon.meowrpc[.]com`); Session network + Wasabi S3 for leaked-file hosting.

---

## Query 1: DeadLock encrypted-file rename and ransom-note drop

**Purpose:** Detects the encryptor's signature filesystem artifacts — files renamed to the `.dlock` extension and the `HOW_RECOVER.<UID>.txt` / `RECOVERY_CHAT.<UID>.html` ransom notes. A clean environment returns 0 rows; any hit is high-confidence active encryption.  
**Severity:** High  
**MITRE:** T1486  
<!-- cd-metadata
cd_ready: true
schedule: "NRT"
category: "Impact"
title: "DeadLock ransomware .dlock encryption / ransom note on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Files renamed to .dlock and/or DeadLock ransom notes (HOW_RECOVER / RECOVERY_CHAT) were written. Treat as active ransomware: isolate the device immediately, identify and contain the encrypting process (pivot Queries 3-5), preserve volatile evidence, and initiate ransomware IR. Note the .txt note only drops on the second directory pass, so absence of the note does not mean absence of encryption."
adaptation_notes: "Very high fidelity - the .dlock extension and DeadLock note filenames are not legitimate. NRT-eligible. No tuning expected."
-->
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".dlock"
    or FileName matches regex @"(?i)^HOW_RECOVER\..*\.txt$"
    or FileName matches regex @"(?i)^RECOVERY_CHAT\..*\.html$"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp asc
```
**Expected results:** 0 rows in an uncompromised environment (verified clean at authoring). Any result indicates encryption in progress — respond immediately.

---

## Query 2: DeadLock registry branding — `.dlock` DefaultIcon and wallpaper policy

**Purpose:** Detects the two registry writes DeadLock uses to brand a compromised host: registering a custom DefaultIcon for the `.dlock` class (`HKLM\SOFTWARE\Classes\.dlock\DefaultIcon`) and persisting the ransom wallpaper via `...\CurrentVersion\Policies\System\Wallpaper`.  
**Severity:** High  
**MITRE:** T1112, T1486  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Impact"
title: "DeadLock registry branding (.dlock icon / wallpaper) on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Registry writes consistent with DeadLock host branding were observed (.dlock DefaultIcon registration and/or forced wallpaper via Policies\\System\\Wallpaper). Correlate with Query 1 (.dlock files) and Queries 3-5 (encryptor behavior); isolate and run ransomware IR if confirmed."
adaptation_notes: "The .dlock\\DefaultIcon key is unique to this threat (high fidelity). The Policies\\System\\Wallpaper key can be set by legitimate GPO/desktop management, so the OR branch is best used together with Query 1 or as a co-occurrence signal - not standalone. Consider splitting the wallpaper branch out if GPO noise appears."
-->
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where (RegistryKey has @"\Classes\.dlock")
    or (RegistryKey has @"CurrentVersion\Policies\System" and RegistryValueName =~ "Wallpaper")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Expected results:** 0 rows expected in a clean environment (verified at authoring). The `.dlock\DefaultIcon` branch is definitive; wallpaper-policy hits alone may be benign GPO activity — corroborate with Query 1.

---

## Query 3: Randomly named 8-uppercase `.cmd` UAC elevation attempt

**Purpose:** Detects DeadLock's UAC-elevation trick — generating a randomly named `.cmd` file of exactly 8 uppercase characters (e.g., `ESYEKQSY.cmd`) and executing it via `ShellExecuteW` with the `RunAs` verb to trigger the UAC consent dialog.  
**Severity:** Medium  
**MITRE:** T1548.002  
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "PrivilegeEscalation"
title: "Random 8-uppercase .cmd elevation on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A cmd.exe execution referencing a randomly named 8-uppercase .cmd file was observed, matching DeadLock's batch-based UAC elevation. Review the initiating process tree and correlate with Queries 1-2 and 4-5. If the parent is an unsigned/unknown binary, isolate and triage."
adaptation_notes: "Behavioral and pattern-based; the exact 8-uppercase name is the discriminator. Tested clean in the authoring environment, but other environments may run legitimate uppercase-named batch scripts - keep the [A-Z]{8} (exact length) anchor and pair with a RunAs/elevation or unsigned-parent signal before promoting to a detection. Marked cd_ready:false pending environment-specific FP validation."
-->
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "cmd.exe" or InitiatingProcessFileName =~ "cmd.exe"
| where ProcessCommandLine matches regex @"\b[A-Z]{8}\.cmd\b"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp asc
```
**Expected results:** 0 rows expected in most environments (verified clean at authoring; benign `.cmd` executions in the window used lowercase names). Investigate any match's initiating process lineage.

---

## Query 4: Mass event-log clearing / channel disabling

**Purpose:** Detects DeadLock's forensic-evidence destruction — clearing core Windows event log channels via `wevtutil cl` / `Clear-EventLog`, or disabling channels by writing `Enabled=0` under `WINEVT\Channels`.  
**Severity:** High  
**MITRE:** T1070.001  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Windows event log clearing on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Event log clearing or channel disabling was observed. This is a common ransomware/hands-on-keyboard anti-forensics step. Confirm the initiating process is not a sanctioned admin/maintenance task; correlate with Queries 1-5 and isolate if part of a ransomware chain."
adaptation_notes: "Filtered to the clear verb (wevtutil cl / Clear-EventLog) and WINEVT channel Enabled writes - excludes benign wevtutil 'im' manifest installs (e.g., Office ETW). Legitimate admins occasionally clear logs; scope out known maintenance service accounts/hosts in Tuning Notes if needed."
-->
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl ", "clear-log", " cl\t"))
    or ProcessCommandLine has "Clear-EventLog"
    or (ProcessCommandLine has @"WINEVT\Channels" and ProcessCommandLine has "Enabled")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Expected results:** 0 rows expected (verified clean at authoring — the 3,000+ `wevtutil` executions in-window were all benign `im` manifest installs, correctly excluded). Any `cl`/`Clear-EventLog` hit warrants review.

---

## Query 5: Bulk termination of security, backup, and AD services

**Purpose:** Detects DeadLock's environment preparation — disabling/stopping multiple defensive and recovery services (Defender, Volume Shadow Copy, backup engine, search, Hyper-V, Active Directory) in a short window to unlock files and blind defenses.  
**Severity:** High  
**MITRE:** T1489, T1562.001, T1490  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Bulk security/backup/AD service disable on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Multiple defensive/recovery services from the DeadLock stop-list were disabled or stopped within a short window. This is a strong pre-encryption ransomware signal. Isolate the device, identify the initiating process (correlate Queries 1-4), and begin ransomware IR."
adaptation_notes: "Anchored on the DeadLock service stop-list plus a distinct-target threshold (>=3 distinct targeted services in one hour) to suppress single legitimate service-config actions (e.g., Azure guest agent config). Adjust the DistinctTargets threshold per environment noise; exclude sanctioned patch/maintenance windows in Tuning Notes rather than with literal host values."
-->
```kql
let StopList = dynamic(["windefend","vss","swprv","wbengine","mssearch","vmcompute","vmms","adws","ntds","kdc","wuauserv","sense","wscsvc"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("sc.exe","net.exe","net1.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("stop","disabled","Stop-Service","Set-Service")
| extend TargetedService = tostring(extract(@"(?i)\b(windefend|vss|swprv|wbengine|mssearch|vmcompute|vmms|adws|ntds|kdc|wuauserv|sense|wscsvc)\b", 1, ProcessCommandLine))
| where isnotempty(TargetedService)
| summarize DistinctTargets = dcount(TargetedService), Targets = make_set(TargetedService, 15),
            Commands = make_set(ProcessCommandLine, 15), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where DistinctTargets >= 3
| order by DistinctTargets desc
```
**Expected results:** 0 rows expected in a clean environment (verified at authoring — in-window service-control activity targeted unrelated services like the Azure guest agent and never ≥3 DeadLock stop-list targets together). Any hit is a strong pre-encryption indicator.

---

## Query 6: DeadLock encryptor hash sweep

**Purpose:** Direct IOC match for the published DeadLock encryptor SHA-256 across file, process, and image-load telemetry.  
**Severity:** High  
**MITRE:** T1486  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Malware"
title: "DeadLock encryptor hash observed on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "The published DeadLock encryptor SHA-256 was observed on this device. Isolate immediately, block the hash, and run ransomware IR. Confirm scope with Queries 1-5."
adaptation_notes: "Direct hash IOC - definitive but perishable. Operators rotate binaries; refresh the hash list from current Microsoft TI / VirusTotal. A 0-row result is the desired outcome in a clean environment; if the sample predates the 30-day AH window, re-run in Sentinel Data Lake (90d) for retrospective coverage."
-->
```kql
let Hashes = dynamic(["a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4"]);
union
  (DeviceFileEvents      | where Timestamp > ago(30d) | where SHA256 in (Hashes) | extend Source = "File"),
  (DeviceProcessEvents   | where Timestamp > ago(30d) | where SHA256 in (Hashes) | extend Source = "Process"),
  (DeviceImageLoadEvents | where Timestamp > ago(30d) | where SHA256 in (Hashes) | extend Source = "ImageLoad")
| project Timestamp, Source, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Expected results:** 0 rows expected in a clean environment (verified at authoring). Any hit is a confirmed encryptor presence — respond immediately.

---

## Query 7: DeadLock leak-site domain network sweep

**Purpose:** Direct IOC match for the published DeadLock leak-site domains in network telemetry. Any resolution/connection from a managed device is anomalous and may indicate a victim viewing the leak site or actor activity.  
**Severity:** Medium  
**MITRE:** T1657  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "DeadLock leak-site domain contact from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A managed device contacted a published DeadLock leak-site domain. Investigate the initiating process and user, determine whether this is post-compromise victim activity, and correlate with Queries 1-6. Block the domains at the proxy/DNS layer."
adaptation_notes: "Direct domain IOC - definitive but perishable (leak-site infrastructure rotates). The '.onion' indicator will only surface if Tor traffic is proxied/logged. Refresh from current Microsoft TI. 0 rows is the desired clean-environment outcome."
-->
```kql
let Domains = dynamic([
    "deadlock.liveblog365.com","dlock.liveblog365.com",
    "deadlockblog.great-site.net","deadlockblog.medianewsonline.com",
    "deadblogdbdu5wprek7wa2o4ce7rnt6u6ntqeud3hzjjcveosgpsqqqd.onion"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (Domains)
    or RemoteUrl has "liveblog365"
    or RemoteUrl has "deadlockblog"
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Expected results:** 0 rows expected in a clean environment (verified at authoring). Any hit warrants investigation of the device/user and correlation with the endpoint queries above.

---

## General Tuning Notes

1. **IOC refresh.** Queries 6–7 match published hash/domain indicators that operators rotate. Refresh the `Hashes` and `Domains` lists from current Microsoft Threat Intelligence / VirusTotal on a regular cadence; treat 0-row results as "clean for the current IOC set," not permanent immunity.
2. **Telemetry & window.** All queries are XDR-native `Device*` tables (use `Timestamp`). Advanced Hunting caps at 30 days; for retrospective sweeps of a rare hash/domain that may predate the window, re-run Queries 6–7 in Sentinel Data Lake (adapt `Timestamp`→`TimeGenerated` for Sentinel/LA tables where applicable).
3. **Behavioral tuning (Queries 3–5).** Where a legitimate maintenance task, GPO, or automation triggers a match, add the *class* of exclusion generically (e.g., "exclude sanctioned patch-window service management," "exclude desktop-management wallpaper GPO") — never embed literal tenant host/account names in the committed query.
4. **CD-readiness summary.** Queries 1, 2, 4, 5, 6, 7 validated clean and are marked `cd_ready: true` (Query 1 NRT-eligible; Query 2's wallpaper branch benefits from Query 1 corroboration). Query 3 is marked `cd_ready: false` pending environment-specific false-positive validation of the 8-uppercase `.cmd` pattern.
5. **Ransom-note timing.** The `HOW_RECOVER.<UID>.txt` note only drops on the encryptor's *second* directory pass — anchor confirmation on the `.dlock` rename (Query 1), not the note.

---

## References
- Microsoft Threat Intelligence — [DeadLock ransomware: Breaking down a Rust-based encryptor with decentralized recovery infrastructure (2026-08-10)](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/)
- MITRE ATT&CK — [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/), [T1548.002 Bypass UAC](https://attack.mitre.org/techniques/T1548/002/), [T1489 Service Stop](https://attack.mitre.org/techniques/T1489/), [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/), [T1070.001 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- Companion files: [`queries/threat-intelligence/2026-07/acr_stealer_clickfix_intrusion_chains.md`](../2026-07/acr_stealer_clickfix_intrusion_chains.md) (endpoint infostealer chains), [`queries/endpoint/rare_process_chains.md`](../../endpoint/rare_process_chains.md)
