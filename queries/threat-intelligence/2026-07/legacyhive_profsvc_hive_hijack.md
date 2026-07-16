# LegacyHive — ProfSvc Registry Hive Hijack Local Privilege Escalation — Threat Hunts

**Created:** 2026-07-15  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceRegistryEvents  
**Keywords:** LegacyHive, Nightmare Eclipse, Chaotic Eclipse, MSNightmare, ProfSvc, User Profile Service, privilege escalation, registry hive, hive hijack, NTUSER.DAT, UsrClass.dat, offline registry, offreg.dll, Object Manager namespace, BaseNamedObjects, GLOBALROOT, symbolic link, NtCreateSymbolicLinkObject, NtCreateDirectoryObjectEx, CreateProcessWithLogonW, LOGON_WITH_PROFILE, batch oplock, User Shell Folders, Local AppData, zero-day, 0-day, local privilege escalation, LPE  
**MITRE:** T1068, T1106, T1112, T1134.001, T1552.002, TA0002, TA0004  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Chaotic Eclipse Unveils LegacyHive Exploit Affecting Fully Patched Windows Systems (2026-07-15)](https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html)

---

## Threat Overview

Security researcher **Chaotic Eclipse** (aka **Nightmare Eclipse**, GitHub handle **MSNightmare**) — a prolific, publicly-disclosing vulnerability researcher with a track record of dropping Windows zero-days — released **LegacyHive**, a proof-of-concept local privilege escalation exploit targeting the Windows **User Profile Service (ProfSvc)**, within hours of Microsoft's July 2026 Patch Tuesday. The PoC affects **fully patched** Windows desktop and server systems; no CVE or vendor fix existed at time of writing.

LegacyHive requires two standard-user credentials plus a third (target) username — which can belong to a higher-privileged account — supplied on the command line (`LegacyHive.exe <username> <password> <target_user_hive>`). It abuses raw **NT Object Manager namespace** APIs (`NtCreateDirectoryObjectEx`, `NtCreateSymbolicLinkObject`) together with the **offline registry library** (`offreg.dll`) to redirect the profile-loading logic so that it mounts the **target user's** registry hive inside the **attacker's own logon session** — without ever touching the target's hive directly or requiring the target to be logged on.

### TTP Summary
| Capability | TTP |
|---|---|
| Direct calls to `NtCreateSymbolicLinkObject` / `NtCreateDirectoryObjectEx` instead of Win32 wrappers | Native API (T1106) |
| Attacker-created Object Manager namespace directory (`\BaseNamedObjects\Restricted\<GUID>`) with symbolic links redirecting `...\Windows` to both the attacker's own scratch folder and the **target user's** `AppData\Local\Microsoft\Windows` | Hijack Execution Flow (T1574) |
| Offline edit of the attacker's **own** `NTUSER.DAT` via `offreg.dll` (`OROpenHiveByHandle` / `ORSetValue` / `ORSaveHive`) to repoint `HKCU\...\User Shell Folders\Local AppData` at `\\.\globalroot\BaseNamedObjects\Restricted` | Modify Registry (T1112) |
| `LogonUser` + `ImpersonateLoggedOnUser` to operate under the second supplied standard-user account while staging the hive | Access Token Manipulation: Token Impersonation/Theft (T1134.001) |
| Batch oplock (`FSCTL_REQUEST_BATCH_OPLOCK`) on a `UsrClass.dat` copy used to time the hive-mount race against `CreateProcessWithLogonW(..., LOGON_WITH_PROFILE, notepad.exe, CREATE_SUSPENDED, ...)` | Exploitation for Privilege Escalation (T1068) |
| Success confirmed via `RegOpenUserClassesRoot` returning the target's mounted hive inside the attacker's session — any secrets/config cached in that hive become accessible | Unsecured Credentials: Credentials in Registry (T1552.002) |

### ⚠️ Hunt Pitfalls
| Pitfall | Mitigation |
|---|---|
| The hijacked registry value (`Local AppData` → `globalroot\BaseNamedObjects`) is written via the **offline registry API** directly into `NTUSER.DAT` file bytes — this bypasses the live registry hooks `DeviceRegistryEvents` is built on, so the malicious value **will not appear** there for the unmodified PoC | Don't rely on `DeviceRegistryEvents` alone (Query 6 is a defense-in-depth check for manual/variant `reg.exe` replication, not the PoC itself). Anchor detection on the **file-level** artifacts instead (Queries 1–2) |
| A bare substring search for `"GLOBALROOT"` matches unrelated strings — e.g., Linux `update-ca-certificates` processing certificate files named `*_GlobalRoot_Class_*.crt` | Require the literal adjacency `globalroot...basenamedobjects` (Query 3), not a bare `has_any` on `"GLOBALROOT"` alone |
| `notepad.exe` launched via alternate credentials is not unique to this exploit — `svchost.exe` (Task Scheduler service host) launching `notepad.exe` under a different account is a common enterprise pattern for scheduled tasks configured to run as a service account | Exclude `svchost.exe` as an initiating process (already applied in Query 4) or require co-occurrence with the GUID-folder (Query 1) signal before escalating |
| `offreg.dll` is genuinely rare, but is legitimately loaded by some profile-management/migration tooling (e.g., user-state migration or imaging suites) | Treat Query 5 hits as a pivot, not an automatic true positive — correlate with Query 1 or Query 2 |
| The working directory is a **GUID-named folder at the root of `C:\`** (e.g., `C:\550e8400-e29b-41d4-a716-446655440000\`) — legitimate `NTUSER.DAT`/`UsrClass.dat` only ever live under `C:\Users\<user>\...` | This is the single highest-fidelity artifact for the unmodified PoC (Query 1) — a recompiled variant could trivially change the working-directory naming pattern |
| The tool requires **local console/interactive access** and two valid standard-user credentials plus the target username — it is not a remote or network-based exploit | Focus hunts on endpoint (`Device*`) telemetry; there is no useful network- or identity-plane signal for this specific chain |
| No CVE has been assigned at time of writing and the exploit affects a **fully patched** July 2026 image — patch-status filtering will not narrow scope | Treat as broadly applicable to all supported desktop/server Windows builds until Microsoft ships a fix |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [User hive staged in a GUID-named root folder (core exploit artifact)](#query-1-user-hive-staged-in-a-guid-named-root-folder-core-exploit-artifact) | Investigation | `DeviceFileEvents` |
| 2 | [NTUSER.DAT / UsrClass.dat modified by an unexpected process](#query-2-ntuserdat--usrclassdat-modified-by-an-unexpected-process) | Investigation | `DeviceFileEvents` |
| 3 | [Object Manager native namespace path reference (tuned)](#query-3-object-manager-native-namespace-path-reference-tuned) | Investigation | `DeviceProcessEvents` |
| 4 | [notepad.exe spawned via alternate-credential logon (CreateProcessWi...](#query-4-notepadexe-spawned-via-alternate-credential-logon-createprocesswithlogonw-artifact) | Investigation | `DeviceProcessEvents` |
| 5 | [offreg.dll module load by a non-standard process](#query-5-offregdll-module-load-by-a-non-standard-process) | Investigation | `DeviceImageLoadEvents` |
| 6 | [Live registry redirection of "Local AppData" (variant / manual-repl...](#query-6-live-registry-redirection-of-local-appdata-variant--manual-replication-check) | Investigation | `DeviceRegistryEvents` |
| 7 | [Combined LegacyHive behavioral risk score (hunting/triage aggregation)](#query-7-combined-legacyhive-behavioral-risk-score-huntingtriage-aggregation) | Posture | `DeviceProcessEvents` + `RiskScore` |


## IOC Reference

> LegacyHive is published as **source code** (`LegacyHive.cpp`), not a distributed binary sample — there are no reliable file-hash or filename IOCs to publish. A literal name/command-line sweep for `LegacyHive.exe` was considered but deliberately **excluded** from this file: the tool has no default distributed binary and any operator will trivially rename it before use, so a name-based check adds negligible real-world detection value. All queries below anchor exclusively on **behavioral artifacts** (Queries 1–6) that survive recompilation and renaming.

| Indicator | Type | Description |
|---|---|---|
| `C:\<GUID>\` (e.g., `C:\550e8400-e29b-41d4-a716-446655440000\`) | Behavioral / folder pattern | GUID-named working directory created directly under the system drive root; stages `ntuser.dat` and `UsrClass.dat` copies |
| `offreg.dll` | Library | Windows Offline Registry Library — used to modify the attacker's own `NTUSER.DAT` without triggering live registry hooks |
| `MSNightmare/LegacyHive` | Source repository | Public PoC source — [github.com/MSNightmare/LegacyHive](https://github.com/MSNightmare/LegacyHive) |

---

## Query 1: User hive staged in a GUID-named root folder (core exploit artifact)

**Purpose:** Detects the exploit's working directory pattern — `NTUSER.DAT`/`UsrClass.dat` staged directly inside a GUID-named folder at the root of a drive (`C:\<GUID>\`). Legitimate copies of these files never live outside `C:\Users\<user>\...`, making this the single highest-fidelity artifact for the unmodified PoC.  
**Severity:** High  
**MITRE:** T1068, T1552.002
<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "PrivilegeEscalation"
title: "Registry hive file staged in GUID-named root folder on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Confirm the GUID folder is not a known application's temp/staging directory. If confirmed unexpected, treat as a strong LegacyHive-pattern indicator: identify the account, contents of the folder, and any subsequent process (e.g., notepad.exe via CreateProcessWithLogonW) launched shortly after."
adaptation_notes: "Single table (DeviceFileEvents), no let/joins — NRT-eligible. Remove the Timestamp filter for NRT deployment per the detection-authoring skill's NRT constraints."
-->
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("ntuser.dat", "UsrClass.dat")
| where FolderPath matches regex @"(?i)^[A-Za-z]:\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName = InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```
**Expected results:** 0 in a clean environment — legitimate `NTUSER.DAT`/`UsrClass.dat` files only ever live under `C:\Users\<user>\...`, so any match here is a strong, low-noise indicator of the LegacyHive working-directory pattern specifically.

---

## Query 2: NTUSER.DAT / UsrClass.dat modified by an unexpected process

**Purpose:** Legitimate profile-hive maintenance is performed by a small, well-known set of system processes. LegacyHive replaces the attacker's own `NTUSER.DAT` via `MoveFileEx` from a non-standard process context. This is a broader behavioral catch-all (also catches manual hive tampering unrelated to this specific PoC).  
**Severity:** Medium  
**MITRE:** T1112, T1068
<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "PrivilegeEscalation"
title: "User registry hive modified by unexpected process on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Confirm whether the initiating process is a known, sanctioned profile/imaging tool for this environment. If not, investigate the process's parent chain and command line, and check for a co-occurring GUID-folder artifact (Query 1)."
adaptation_notes: "Single table, no let/joins — NRT-eligible. The exclusion list should be extended per-environment for known profile-management/migration tooling before deployment to reduce noise."
-->
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("NTUSER.DAT", "UsrClass.dat")
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| where InitiatingProcessFileName !in~ (
    "svchost.exe", "userinit.exe", "winlogon.exe", "explorer.exe",
    "searchindexer.exe", "lsass.exe", "dwm.exe", "services.exe",
    "wmiprvse.exe", "msiexec.exe", "trustedinstaller.exe"
)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    AccountName = InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```
**Expected results:** 0 from the documented system-process allowlist in most environments. Any hit warrants reviewing the initiating process's parent chain and command line; extend the allowlist per-environment for known profile-management/migration tooling before relying on this as a standalone alert.

---

## Query 3: Object Manager native namespace path reference (tuned)

**Purpose:** Hunts for the literal NT native-namespace path syntax (`globalroot\BaseNamedObjects`) that LegacyHive redirects through, in either a process's own or its parent's command line. Adapted from a broader community query that matched on bare `"GLOBALROOT"` alone.  
**Severity:** Medium  
**MITRE:** T1106, T1574
<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "PrivilegeEscalation"
title: "Object Manager native namespace path referenced on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Review the full command line for the referenced object-directory path and correlate with any hive-staging (Query 2) or hive-replacement (Query 3) activity on the same device around the same time."
adaptation_notes: "Single table, no let/joins — NRT-eligible. Uses matches regex; confirm regex performance at scale before enabling broadly."
-->
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine matches regex @"(?i)globalroot.{0,3}basenamedobjects"
    or InitiatingProcessCommandLine matches regex @"(?i)globalroot.{0,3}basenamedobjects"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName, ReportId
| order by Timestamp desc
```
**Expected results:** 0 in most environments. Note the query deliberately requires the literal `globalroot...basenamedobjects` adjacency rather than a bare `has_any` on `"GLOBALROOT"` alone — a looser match would false-positive on unrelated processes handling filenames that happen to contain "GlobalRoot" (e.g., certificate-management tooling processing root-CA files). Any hit under the tuned pattern is a meaningful indicator of Object Manager namespace abuse.

---

## Query 4: notepad.exe spawned via alternate-credential logon (CreateProcessWithLogonW artifact)

**Purpose:** LegacyHive's final step spawns `notepad.exe` suspended via `CreateProcessWithLogonW` with `LOGON_WITH_PROFILE`, using explicit credentials, to trigger Windows to process the hijacked profile path. A `notepad.exe` process whose account differs from its parent's account (an explicit-credential/"RunAs"-style launch) is an uncommon pattern for this specific target binary.  
**Severity:** Medium  
**MITRE:** T1134.001, T1068
<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "PrivilegeEscalation"
title: "notepad.exe launched via alternate-credential logon on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Confirm whether this is expected RunAs/deployment automation for this environment. If unexpected, check for a co-occurring GUID-folder artifact (Query 1) on the same device."
adaptation_notes: "Single table, no let/joins — NRT-eligible. svchost.exe is excluded because Task Scheduler-hosted scheduled tasks running as an alternate account are a common benign source for this pattern; extend the exclusion list per-environment before deployment."
-->
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "notepad.exe"
| where tolower(InitiatingProcessAccountName) != tolower(AccountName)
| where InitiatingProcessFileName !in~ (
    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "runtimebroker.exe", "userinit.exe", "svchost.exe"
)
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine,
    AccountName, InitiatingProcessFileName, InitiatingProcessAccountName,
    InitiatingProcessCommandLine, ReportId
| order by Timestamp desc
```
**Expected results:** 0 or very low volume in most environments. Note `svchost.exe` is excluded from `InitiatingProcessFileName` because Task Scheduler-hosted scheduled tasks configured to run under an alternate service account commonly launch utility processes this way — a legitimate pattern that would otherwise dominate results. Any hit from the remaining processes is worth investigating as a likely alternate-credential launch.

---

## Query 5: offreg.dll module load by a non-standard process

**Purpose:** LegacyHive uses the Windows Offline Registry Library (`offreg.dll`) to edit the attacker's own `NTUSER.DAT` without invoking live registry APIs. This DLL is rarely loaded outside profile-migration/imaging tooling, making any load event worth reviewing.  
**Severity:** Low  
**MITRE:** T1112
<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "PrivilegeEscalation"
title: "offreg.dll loaded by {{InitiatingProcessFileName}} on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Confirm whether the loading process is a known, sanctioned profile-management/migration/imaging tool. If not recognized, correlate with Query 1/2 hive artifacts on the same device."
adaptation_notes: "Single table, no let/joins — NRT-eligible. Rare DLL; expect low volume — good NRT candidate if ingestion lag is acceptable."
-->
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "offreg.dll"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    AccountName = InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```
**Expected results:** 0 in most environments — `offreg.dll` is rarely loaded outside profile-migration/imaging tooling. Any load event is worth reviewing; correlate with Query 1/2 hive artifacts before treating as a true positive.

---

## Query 6: Live registry redirection of "Local AppData" (variant / manual-replication check)

**Purpose:** The unmodified PoC writes its hijacked `Local AppData` value **offline** (bypassing live registry telemetry — see Hunt Pitfalls). This query is a defense-in-depth check for **variants or manual replication** that instead use the live registry API (e.g., via `reg.exe` or `RegSetValueEx`) to point `Local AppData` at a `globalroot`/`BaseNamedObjects` path.  
**Severity:** Low (by design — expected 0 for the PoC as published)  
**MITRE:** T1112, T1574
<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "PrivilegeEscalation"
title: "Local AppData registry value redirected to native namespace on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "If this ever fires, treat as a manual/variant hive-hijack attempt distinct from the published LegacyHive PoC (which bypasses this telemetry). Investigate the initiating process and account immediately."
adaptation_notes: "Single table, no let/joins — NRT-eligible. Documented as low-yield-by-design for the current PoC; retained for variant coverage and future-proofing."
-->
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryValueName =~ "Local AppData"
| where RegistryValueData has_any ("globalroot", "BaseNamedObjects")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, AccountName = InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```
**Expected results:** 0 for the published PoC as-is — its offline registry write does not generate this telemetry (see Hunt Pitfalls). This query exists as a defense-in-depth/variant check: a hit indicates a manual replication or fork that uses the live registry API instead.

---

## Query 7: Combined LegacyHive behavioral risk score (hunting/triage aggregation)

**Purpose:** Unifies the process- and file-level signals above (GUID-folder hive staging, unexpected hive replacement, native namespace references, alternate-credential `notepad.exe` launch) into a single risk-scored view for SOC triage — mirroring the structure of the community-shared generalized "Nightmare Eclipse" hunting query, tuned specifically to LegacyHive's validated artifacts.  
**Severity:** Informational (triage aggregation, not a single-condition alert)  
**MITRE:** T1068, T1106, T1112, T1134.001, T1552.002
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-signal union of DeviceProcessEvents + DeviceFileEvents with extend/case scoring logic — designed for analyst triage/dashboarding, not a single-condition custom detection. For CD deployment, use Queries 1-6 individually (each is a standalone, single-signal, cd_ready query)."
-->
```kql
let Lookback = 30d;
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | extend
        HasNativeNamespaceRef =
            ProcessCommandLine matches regex @"(?i)globalroot.{0,3}basenamedobjects"
            or InitiatingProcessCommandLine matches regex @"(?i)globalroot.{0,3}basenamedobjects",
        IsNotepadAltCredChild =
            FileName =~ "notepad.exe"
            and tolower(InitiatingProcessAccountName) != tolower(AccountName)
            and InitiatingProcessFileName !in~ (
                "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
                "runtimebroker.exe", "userinit.exe", "svchost.exe"
            )
    | where HasNativeNamespaceRef or IsNotepadAltCredChild
    | extend Signal = case(
        HasNativeNamespaceRef, "Object Manager native namespace path referenced",
        IsNotepadAltCredChild, "notepad.exe spawned via alternate-credential logon",
        "Suspicious process behavior"
    )
    | extend RiskScore =
          2
        + 4 * toint(HasNativeNamespaceRef)
        + 3 * toint(IsNotepadAltCredChild)
    | project Timestamp, DeviceId, DeviceName, ReportId = tostring(ReportId), ActionType,
        Source = "Process", Signal, RiskScore,
        ActorProcess = tostring(FileName), ActorPath = tostring(FolderPath),
        ActorCommandLine = tostring(ProcessCommandLine),
        ParentProcess = tostring(InitiatingProcessFileName),
        ParentCommandLine = tostring(InitiatingProcessCommandLine),
        ActorAccount = tostring(AccountName), Evidence = ProcessCommandLine
),
(
    DeviceFileEvents
    | where Timestamp > ago(Lookback)
    | extend
        IsRootGuidHiveStaging =
            FileName in~ ("ntuser.dat", "UsrClass.dat")
            and FolderPath matches regex @"(?i)^[A-Za-z]:\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        IsHiveReplacedByUnexpectedProcess =
            FileName in~ ("NTUSER.DAT", "UsrClass.dat")
            and ActionType in ("FileModified", "FileRenamed", "FileCreated")
            and InitiatingProcessFileName !in~ (
                "svchost.exe", "userinit.exe", "winlogon.exe", "explorer.exe",
                "searchindexer.exe", "lsass.exe", "dwm.exe", "services.exe",
                "wmiprvse.exe", "msiexec.exe", "trustedinstaller.exe"
            )
    | where IsRootGuidHiveStaging or IsHiveReplacedByUnexpectedProcess
    | extend Signal = case(
        IsRootGuidHiveStaging, "User hive staged in GUID-named root folder (LegacyHive working directory pattern)",
        IsHiveReplacedByUnexpectedProcess, "User hive modified by unexpected process",
        "Sensitive hive file activity"
    )
    | extend RiskScore =
          2
        + 7 * toint(IsRootGuidHiveStaging)
        + 3 * toint(IsHiveReplacedByUnexpectedProcess)
    | project Timestamp, DeviceId, DeviceName, ReportId = tostring(ReportId), ActionType,
        Source = "File", Signal, RiskScore,
        ActorProcess = tostring(InitiatingProcessFileName), ActorPath = tostring(InitiatingProcessFolderPath),
        ActorCommandLine = tostring(InitiatingProcessCommandLine),
        ParentProcess = tostring(InitiatingProcessParentFileName), ParentCommandLine = "N/A - File Event Context",
        ActorAccount = tostring(InitiatingProcessAccountName),
        Evidence = strcat("Target File Path: ", FolderPath, "\\", FileName)
)
| order by RiskScore desc, Timestamp desc
```
**Expected results:** 0 in a clean environment. This is a triage/dashboard view, not a single-condition detection — treat any non-zero `RiskScore` as a starting point for correlating across the individual queries above, not as a standalone verdict.

---

## General Tuning Notes

1. **No reliable name/hash-based IOCs exist for this PoC.** LegacyHive is published as source (`LegacyHive.cpp`) with no distributed binary. A name/command-line sweep for `LegacyHive.exe` was considered but deliberately **excluded** from this file — trivial renaming defeats it and it adds no real detection value beyond the behavioral queries. All detections here (Queries 1–6) anchor on artifacts that survive recompilation and renaming.
2. **`DeviceRegistryEvents` blind spot is intentional, not a bug to "fix."** The PoC's core primitive — offline hive editing via `offreg.dll` — is specifically designed to avoid live registry API hooks. Query 6 exists for variant coverage; do not expect it to catch the published PoC.
3. **Two known false-positive sources are already tuned out in the queries below:** (a) a bare `"GLOBALROOT"` substring match, which would false-positive on unrelated filenames containing that string (Query 3), and (b) `svchost.exe`-initiated `notepad.exe` launches, a common pattern for Task Scheduler-hosted scheduled tasks running as an alternate account (Query 4). Extend both exclusion lists further per-environment before enabling as automated detections.
4. **CD-readiness summary:** Queries 1–6 are each single-signal, single-table, and `cd_ready: true` — all NRT-eligible (`schedule: "0"`). Query 7 is `cd_ready: false` — it is a multi-signal risk-scored aggregation intended for analyst triage/dashboarding, not a standalone custom detection. Deploy Queries 1 and 4 first — they map to the highest-fidelity behavioral artifacts (GUID-rooted hive staging, alternate-credential `notepad.exe` launch).
5. **Re-run periodically as the PoC evolves.** As a source-published exploit, expect community forks/variants (different working-directory naming, different target process instead of `notepad.exe`, live-registry variants). Re-validate the behavioral anchors (GUID-folder pattern, hive replacement) against any observed variant before assuming continued coverage.
6. **This file is LegacyHive-specific.** Nightmare Eclipse/Chaotic Eclipse has a history of releasing multiple Windows local exploits targeting recovery/servicing components (WinRE, offline scanner, setup/OOBE flows). A companion, broader-scope campaign covering "trusted recovery/servicing process spawns risky child" patterns (see the community-shared generalized query referenced below) is a reasonable follow-up if this actor's activity continues.

---

## References
- Security Affairs — [Chaotic Eclipse Unveils LegacyHive Exploit Affecting Fully Patched Windows Systems (2026-07-15)](https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html)
- Public PoC source — [MSNightmare/LegacyHive — LegacyHive.cpp](https://github.com/MSNightmare/LegacyHive/blob/main/LegacyHive.cpp)
- Community hunting query (author's original, adapted and tuned in this file) — [lukehebe/KQL-Hunting_and_Detection-Queries — LegacyHive Hunting queries.kql](https://raw.githubusercontent.com/lukehebe/KQL-Hunting_and_Detection-Queries/refs/heads/main/LegacyHive%20Hunting%20queries.kql)
- Community-shared generalized "Nightmare Eclipse" hunting query — provided directly by the requester for context (unattributed/no public URL); covers the actor's broader pattern of trusted recovery/servicing processes (`MsMpEng`, `ReAgentC`, `SetupHost`, `WinPE`) spawning risky children and touching profile/recovery artifacts (WinRE, `unattend.xml`, `ReAgent.xml`). Complementary to — but out of scope for — this LegacyHive-specific file.
- MITRE ATT&CK — [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/), [T1106 Native API](https://attack.mitre.org/techniques/T1106/), [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112/), [T1134.001 Access Token Manipulation: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/), [T1552.002 Unsecured Credentials: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002/), [T1574 Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
