# Storm-2570 — Cross-RaaS Ransomware Affiliate Tradecraft (Qilin, DragonForce, Anubis, BERT) — Threat Hunts

**Created:** 2026-09-25  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents, DeviceNetworkEvents, AlertInfo, AlertEvidence  
**Keywords:** Storm-2570, ransomware affiliate, RaaS, Qilin, DragonForce, Anubis, BERT, human-operated ransomware, double extortion, RMM abuse, MeshAgent, MeshCentral, renamed meshagent64, Atera, AteraAgent, Splashtop Streamer, ScreenConnect, Remotely_Agent, NinjaRMM, Cloudflared, Cloudflare Tunnel, LocalSystem service, ngrok, RDP tunneling, NetScan, SoftPerfect Network Scanner, Nmap, Mimikatz, LaZagne, pypykatz, ntdsutil, IFM, Install From Media, NTDS.dit, Defender tampering, DisableAntiSpyware, DisableRealtimeMonitoring, WinDefend, PerfLogs exclusion, Group Policy Defender disable, PsExec, ip.txt host list, rdp.bat, fDenyTSConnections, Impacket, NetExec, admin shares, s5cmd, S3 exfiltration, credentials file, Rclone  
**MITRE:** T1219, T1572, T1036.005, T1543.003, T1046, T1003.001, T1003.003, T1555, T1562.001, T1112, T1021.001, T1021.002, T1047, T1569.002, T1570, T1567.002, T1537, T1119, T1486, T1027  
**Domains:** endpoint, incidents  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Beyond the ransomware: Tracking Storm-2570's consistent tradecraft across deployments (2026-09-24)](https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/)

---

## Threat Overview

**Storm-2570** is a ransomware affiliate Microsoft Threat Intelligence has tracked since April 2025. It works across several ransomware-as-a-service ecosystems — **Qilin, DragonForce, Anubis and BERT** — while keeping its pre-ransom tradecraft, infrastructure and tooling largely uniform. Victims span the US, Canada, UK, Spain, the Netherlands and Puerto Rico across healthcare, education, government, finance, energy, manufacturing and other sectors. Initial access is unconfirmed; intrusions progress through remote management tooling and hands-on-keyboard activity to credential access, lateral movement, exfiltration and encryption. The article's core message: **hunt the affiliate's behavior, not the payload** — the same actor and tools appear whichever ransomware is deployed.

Recurring behaviors:

- **MeshAgent/MeshCentral** as the operational bridge, **renamed with the victim's name** (for example `meshagent64-[organization name].exe`), running Base64-encoded commands. It is often paired with **Atera** (which then installs **Splashtop Streamer** for interactive control), **ScreenConnect**, **Remotely_Agent** and **NinjaRMM**.
- **Cloudflared** installed as a persistent **Cloudflare Tunnel service under LocalSystem**, and **ngrok** exposing **TCP 3389**.
- **NetScan / SoftPerfect Network Scanner Portable / Nmap** discovery.
- **Mimikatz, LaZagne and pypykatz**, plus **ntdsutil IFM** backups of `NTDS.dit` into `C:\Windows\Temp\<random>`.
- **Defender tampering**: real-time monitoring disabled, a **`C:\PerfLogs` exclusion**, and registry changes to `DisableAntiSpyware`, `DisableRealtimeMonitoring` and `WinDefend` service behavior.
- **PsExec with `@ip.txt` host lists** to push renamed MeshAgent and to run **`rdp.bat`** (Terminal Server settings plus a firewall rule for TCP 3389).
- **Impacket and NetExec over SMB**.
- Exfiltration with **s5cmd plus a credentials file** (`cp` with extension filters to S3), or **Rclone**.

> **Companion file:** [`queries/threat-intelligence/2026-04/storm_1175_medusa_ransomware_campaign.md`](../2026-04/storm_1175_medusa_ransomware_campaign.md) covers generic ransomware-affiliate hunts (RMM installs, LSASS dumping, NTDS/SAM access, Defender registry tampering, Rclone, PsExec/Impacket, RDP firewall changes). This file focuses on the **Storm-2570-specific variants** — renamed MeshAgent, RMM layering, LocalSystem tunnel services, IFM to Temp, `C:\PerfLogs` exclusions, Group Policy-delivered Defender disables, `@` host lists, s5cmd — plus a per-device toolkit-stacking hunt.

### TTP Summary

| Capability | TTP |
|---|---|
| Remote access (RMM) | MeshAgent/MeshCentral (renamed per victim), Atera → Splashtop, ScreenConnect, Remotely_Agent, NinjaRMM (T1219, T1036.005) |
| Tunneling | Cloudflared service under LocalSystem; ngrok exposing TCP 3389 (T1572, T1543.003) |
| Discovery | NetScan, SoftPerfect Network Scanner Portable, Nmap, native commands, file searching (T1046) |
| Credential access | Mimikatz, LaZagne, pypykatz (T1003.001, T1555); ntdsutil IFM of NTDS.dit to `C:\Windows\Temp` (T1003.003) |
| Defense impairment | Real-time monitoring disabled, `C:\PerfLogs` exclusion, `DisableAntiSpyware` / `DisableRealtimeMonitoring` / `WinDefend` registry changes (T1562.001, T1112) |
| Obfuscation | Base64-encoded commands through MeshAgent (T1027) |
| Lateral movement | PsExec with `@ip.txt`, `rdp.bat`, admin shares, Impacket, NetExec over SMB (T1021.001, T1021.002, T1047, T1569.002, T1570) |
| Exfiltration | s5cmd + credentials file to S3 with extension filters; Rclone continuous sync (T1567.002, T1537) |
| Impact | Qilin, DragonForce, Anubis or BERT encryption (T1486) |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **Every tool here is commodity or legitimate** | RMM agents, PsExec, ntdsutil, Rclone and Cloudflared all have sanctioned uses. The affiliate's signature is the **combination** on one host (Query 1) and the **specific variants**: renamed agents, LocalSystem tunnel services, `@` host lists, IFM to Temp, `C:\PerfLogs` exclusions. |
| **Renamed binaries defeat `FileName` matching** | MeshAgent is renamed with the victim's organization name, and PsExec is frequently renamed. Match `ProcessVersionInfoOriginalFileName` / `ProductName` / `CompanyName` as well as `FileName` (Queries 1–4, 7, 9). |
| **Group Policy and MDM write Defender policy keys legitimately** | `svchost.exe` (gpsvc) and `omadmclient.exe` write `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`. Query 6 separates **direct** tampering (High) from **Group Policy-delivered** disables (Medium) and ignores Defender's own `MsMpEng.exe` writes — but a GPO that disables real-time protection is still a finding, because ransomware actors with domain admin use GPOs too. |
| **Security tooling uses PsExec** | MDE Client Analyzer and diagnostics launch `PsExec -s` against the Defender for Endpoint registry keys. Queries 1 and 7 exclude those command lines; allowlist your own admin tooling by parent process and account. |
| **The article's command examples are images** | Microsoft published the ntdsutil, PsExec, `rdp.bat`, NetExec and s5cmd command lines as screenshots. The hunts implement the **behavior described in the article text** (IFM to Temp, `@ip.txt`, `fDenyTSConnections` plus a 3389 firewall rule, `cp` with extension filters) rather than transcribing literals. |
| **RDP enablement happens on the target, PsExec on the source** | Query 7 correlates `rdp.bat` / `fDenyTSConnections` / 3389 rules on the same device as PsExec. For fan-out, pivot `RemoteHosts` into the targets' `DeviceProcessEvents`. |
| **s5cmd is a Go binary with little version metadata** | Renamed s5cmd is hard to catch by metadata; lean on command-line structure (`cp`, `s3://`, `--credentials-file`, `--endpoint-url`, extension wildcards) and S3 connections from non-standard processes (Query 9). |
| **Attack simulations reproduce this tradecraft** | Purple-team and attack-disruption demos use Mimikatz, PsExec, renamed PsExec, GPO Defender disables and ransomware-extension canaries. Confirm with the simulation owner before closing; do not suppress the queries. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Storm-2570 toolkit stacking on a single device](#query-1-storm-2570-toolkit-stacking-on-a-single-device) | Investigation | `DeviceProcessEvents` |
| 2 | [Renamed MeshAgent and MeshAgent-driven encoded commands](#query-2-renamed-meshagent-and-meshagent-driven-encoded-commands) | Investigation | `DeviceEvents` + multi |
| 3 | [RMM stacking — multiple remote access products and Atera-delivered ...](#query-3-rmm-stacking--multiple-remote-access-products-and-atera-delivered-installs-on-one-host) | Investigation | `DeviceProcessEvents` + `RmmEvents` |
| 4 | [Cloudflared and ngrok tunnels — LocalSystem services, token runs an...](#query-4-cloudflared-and-ngrok-tunnels--localsystem-services-token-runs-and-rdp-exposure) | Investigation | `DeviceEvents` + `DeviceProcessEvents` |
| 5 | [ntdsutil IFM backup of NTDS.dit to a staging path, and NTDS/hive co...](#query-5-ntdsutil-ifm-backup-of-ntdsdit-to-a-staging-path-and-ntdshive-copies) | Investigation | `DeviceFileEvents` + multi |
| 6 | [Defender impairment — PerfLogs exclusions, direct disables and Grou...](#query-6-defender-impairment--perflogs-exclusions-direct-disables-and-group-policy-delivered-disables) | Investigation | `DeviceProcessEvents` + multi |
| 7 | [PsExec host-list fan-out, rdp.bat and RDP enablement](#query-7-psexec-host-list-fan-out-rdpbat-and-rdp-enablement) | Investigation | `DeviceProcessEvents` + multi |
| 8 | [Impacket and NetExec remote execution over SMB/WMI](#query-8-impacket-and-netexec-remote-execution-over-smbwmi) | Investigation | `DeviceProcessEvents` |
| 9 | [s5cmd and Rclone exfiltration to S3-compatible storage](#query-9-s5cmd-and-rclone-exfiltration-to-s3-compatible-storage) | Investigation | `DeviceNetworkEvents` + `DeviceProcessEvents` |
| 10 | [Defender detections matching the Storm-2570 coverage table, grouped...](#query-10-defender-detections-matching-the-storm-2570-coverage-table-grouped-by-device-and-kill-chain-stage) | Detection | `AlertInfo` |


## IOC Reference

> The article publishes **no file hashes, domains or IP addresses**; it is a tradecraft profile, and the hunts below are behavioral. Named artifacts from the article text:

| Indicator | Type | Description |
|---|---|---|
| `meshagent64-[organization name].exe` | Filename pattern | MeshAgent renamed with the victim organization's name |
| `Cloudflared.exe` (service, LocalSystem) | Tunnel | Persistent Cloudflare Tunnel service |
| `ngrok` exposing TCP 3389 | Tunnel | RDP exposed through ngrok |
| `ntdsutil` IFM to `C:\Windows\Temp\<random>` | Command behavior | NTDS.dit and registry hive staging for offline hash extraction |
| `C:\PerfLogs` | Defender exclusion | Path excluded from Defender scanning |
| `DisableAntiSpyware`, `DisableRealtimeMonitoring`, `WinDefend` | Registry | Defender impairment |
| `@ip.txt` | PsExec host list | Mass remote execution / MeshAgent deployment |
| `rdp.bat` | Script | Enables RDP (Terminal Server settings + TCP 3389 firewall rule) |
| `s5cmd.exe` + credentials file | Exfiltration | S3 `cp` with extension filters |
| Rclone | Exfiltration | Cloud sync of new and updated files |

---

## Query 1: Storm-2570 toolkit stacking on a single device

**Purpose:** The affiliate's tools are individually commodity; the signature is several of them on the same host. Classifies process executions into Storm-2570 tool families across RMM, tunneling, discovery, lateral movement, credential access, Defender tampering and exfiltration — using version metadata to catch renamed binaries — and surfaces devices with **three or more families**, or **RMM/tunnel plus credential access or exfiltration**. MDE diagnostic PsExec runs are excluded.  
**Severity:** High  
**MITRE:** T1219, T1572, T1046, T1570, T1003.001, T1562.001, T1567.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-device aggregation across tool families - hunting/triage, not row-level. Validated: 0 rows at minFamilies = 3 in the validation tenant over 30 days (AH), and 0 Storm-2570 RMM/tunnel/exfiltration/IFM executions over ~90 days (Data Lake). Lowering the threshold to 2 surfaces a purple-team workstation running Mimikatz plus PsExec, which shows the intended sensitivity. Promotion path: a Sentinel analytics rule on the same logic, with the single-behavior rules (Queries 5, 7, 8) as the CD layer."
-->

```kql
let lookback = 30d;
let minFamilies = 3;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| extend F = tolower(FileName), OF = tolower(ProcessVersionInfoOriginalFileName), PN = tolower(ProcessVersionInfoProductName), CO = tolower(ProcessVersionInfoCompanyName), CL = tolower(ProcessCommandLine)
| extend Family = case(
    F has "meshagent" or OF has "meshagent" or PN has "meshcentral" or PN has "mesh agent", "RMM:MeshAgent",
    F has "ateraagent" or CO has "atera", "RMM:Atera",
    F has_any ("srmanager", "srservice", "srstreamer") or CO has "splashtop", "RMM:Splashtop",
    F has "screenconnect" or PN has "screenconnect", "RMM:ScreenConnect",
    F has "remotely_agent" or CL has "remotely_agent", "RMM:Remotely",
    F has "ninjarmm" or CO has "ninjarmm" or CO has "ninjaone", "RMM:NinjaRMM",
    F == "cloudflared.exe" or OF == "cloudflared.exe" or (CL has "cloudflared" and CL has "tunnel"), "Tunnel:Cloudflared",
    F == "ngrok.exe" or OF == "ngrok.exe" or (CL has "ngrok" and CL has_any (" tcp ", "authtoken")), "Tunnel:ngrok",
    F has_any ("netscan", "nmap") or PN has_any ("network scanner", "nmap"), "Discovery:Scanner",
    F in ("psexec.exe", "psexec64.exe") or OF == "psexec.c", "LatMove:PsExec",
    CL has_any ("netexec", "nxc.exe", "nxc smb", "crackmapexec") or (CL has @"\\127.0.0.1\admin$\__" and CL has "2>&1"), "LatMove:NetExec/Impacket",
    F in ("mimikatz.exe", "lazagne.exe", "pypykatz.exe") or CL has_any ("sekurlsa::", "lsadump::", "lazagne", "pypykatz"), "CredAccess:Tool",
    F == "ntdsutil.exe" and CL has "ifm", "CredAccess:NTDS-IFM",
    CL has_any ("add-mppreference", "set-mppreference") and CL has_any ("exclusionpath", "disablerealtimemonitoring"), "DefenseEvasion:DefenderTamper",
    F == "s5cmd.exe" or CL has "s5cmd", "Exfil:s5cmd",
    F == "rclone.exe" or OF == "rclone.exe" or PN == "rclone", "Exfil:Rclone",
    "")
| where isnotempty(Family)
| where not(Family == "LatMove:PsExec" and ProcessCommandLine has_any ("Windows Advanced Threat Protection", "MDEClientAnalyzer", "winatp.cer", "SenseCM"))
| extend Phase = tostring(split(Family, ":")[0])
| summarize Families = dcount(Family), Phases = dcount(Phase), FamilySet = make_set(Family), Events = count(),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Accounts = make_set(AccountName, 10),
    SampleCommands = make_set(substring(ProcessCommandLine, 0, 200), 10)
    by DeviceId, DeviceName
| extend HasRmmOrTunnel = FamilySet has_any ("RMM:", "Tunnel:"), HasCredOrExfil = FamilySet has_any ("CredAccess:", "Exfil:")
| where Families >= minFamilies or (HasRmmOrTunnel and HasCredOrExfil)
| order by Phases desc, Families desc
```

**Expected results:** 0 rows in most environments. A device combining an RMM agent or tunnel with credential dumping or exfiltration tooling — especially across three or more phases — matches the Storm-2570 pre-ransom profile. Isolate it and pivot to Queries 2–9 for the same host.

---

## Query 2: Renamed MeshAgent and MeshAgent-driven encoded commands

**Purpose:** Extends Microsoft's published MeshAgent hunt. Beyond name matching, it uses **version metadata** (original file name, product, description) to catch binaries **renamed with the victim's organization name**. It adds MeshAgent **service installs** (with service account) and **network connections**, and flags **Base64-encoded PowerShell/cmd spawned by MeshAgent** — the obfuscated command execution described in the article.  
**Severity:** High  
**MITRE:** T1219, T1036.005, T1543.003, T1027

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table union with a per-device summary. CD path: split out the DeviceProcessEvents branch filtered to RenamedAgent or EncodedChild and project row-level Timestamp, DeviceId, DeviceName and ReportId (scheduled 1H) - high fidelity where MeshCentral is not sanctioned. Validated: 0 rows over 30 days. An independent RMM inventory (AnyDesk, TeamViewer, ScreenConnect, Splashtop, Atera, MeshAgent, NinjaOne, cloudflared, ngrok) also returned 0 executions, confirming a clean baseline rather than a broken filter."
-->

```kql
let lookback = 30d;
let MeshTerms = dynamic(["meshagent", "meshagent64", "meshcentral", "mesh agent"]);
let StandardNames = dynamic(["meshagent.exe", "meshagent64.exe", "meshagent32.exe"]);
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName has_any (MeshTerms) or ProcessVersionInfoOriginalFileName has_any (MeshTerms) or ProcessVersionInfoProductName has_any (MeshTerms)
        or ProcessVersionInfoFileDescription has_any (MeshTerms) or InitiatingProcessFileName has_any (MeshTerms)
    | extend ChildOfMesh = InitiatingProcessFileName has_any (MeshTerms) or InitiatingProcessVersionInfoProductName has_any (MeshTerms)
    | extend EncodedChild = ChildOfMesh and FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe") and ProcessCommandLine has_any ("-enc", "-encodedcommand", "frombase64string")
    | project Timestamp, DeviceId, DeviceName, SourceTable = "DeviceProcessEvents", ActionType, FileName, FolderPath,
              OriginalName = ProcessVersionInfoOriginalFileName, Product = ProcessVersionInfoProductName,
              CommandLine = ProcessCommandLine, Parent = InitiatingProcessFileName, SHA256, ChildOfMesh, EncodedChild, ServiceName = "", ServiceAccount = "", RemoteUrl = ""
),
(
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where FileName has_any (MeshTerms) or FolderPath has_any (MeshTerms) or FileName endswith ".msh"
    | project Timestamp, DeviceId, DeviceName, SourceTable = "DeviceFileEvents", ActionType, FileName, FolderPath,
              OriginalName = "", Product = "", CommandLine = InitiatingProcessCommandLine, Parent = InitiatingProcessFileName, SHA256,
              ChildOfMesh = false, EncodedChild = false, ServiceName = "", ServiceAccount = "", RemoteUrl = ""
),
(
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "ServiceInstalled"
    | extend AF = parse_json(AdditionalFields)
    | extend ServiceName = tostring(AF.ServiceName), ServiceAccount = tostring(AF.ServiceAccount)
    | where ServiceName has_any (MeshTerms) or FolderPath has_any (MeshTerms) or FileName has_any (MeshTerms)
    | project Timestamp, DeviceId, DeviceName, SourceTable = "DeviceEvents", ActionType, FileName, FolderPath,
              OriginalName = "", Product = "", CommandLine = InitiatingProcessCommandLine, Parent = InitiatingProcessFileName, SHA256,
              ChildOfMesh = false, EncodedChild = false, ServiceName, ServiceAccount, RemoteUrl = ""
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessFileName has_any (MeshTerms) or InitiatingProcessVersionInfoProductName has_any (MeshTerms) or RemoteUrl has "meshcentral"
    | project Timestamp, DeviceId, DeviceName, SourceTable = "DeviceNetworkEvents", ActionType, FileName = InitiatingProcessFileName, FolderPath = InitiatingProcessFolderPath,
              OriginalName = "", Product = InitiatingProcessVersionInfoProductName, CommandLine = InitiatingProcessCommandLine, Parent = InitiatingProcessParentFileName, SHA256 = InitiatingProcessSHA256,
              ChildOfMesh = false, EncodedChild = false, ServiceName = "", ServiceAccount = "", RemoteUrl = strcat(RemoteUrl, " ", RemoteIP, ":", RemotePort)
)
| extend RenamedAgent = (FileName has "meshagent" or OriginalName has "meshagent" or Product has_any (MeshTerms)) and FileName !in~ (StandardNames) and SourceTable != "DeviceFileEvents"
| summarize Events = count(), Sources = make_set(SourceTable), FileNames = make_set(FileName, 10), Paths = make_set(FolderPath, 10),
    RenamedAgent = max(toint(RenamedAgent)), EncodedChildren = countif(EncodedChild), MeshChildren = countif(ChildOfMesh),
    Services = make_set_if(strcat(ServiceName, " (", ServiceAccount, ")"), isnotempty(ServiceName), 5), RemoteEndpoints = make_set_if(RemoteUrl, isnotempty(RemoteUrl), 10),
    SampleCommands = make_set(substring(CommandLine, 0, 200), 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, DeviceName
| order by RenamedAgent desc, EncodedChildren desc, Events desc
```

**Expected results:** If MeshCentral is not an approved tool, **any** row warrants investigation. `RenamedAgent == 1` (for example a file name containing your organization's name) or `EncodedChildren > 0` closely matches Storm-2570. Isolate the host and find how the agent was delivered (Query 7 PsExec host lists).

---

## Query 3: RMM stacking — multiple remote access products and Atera-delivered installs on one host

**Purpose:** Storm-2570 "rotates among commercially available RMM platforms... often deploying multiple tools during the same intrusion," and uses **Atera to download and install Splashtop Streamer**. Records when each RMM product was first seen per device (by file name and signer metadata), flags hosts running **two or more RMM products**, and surfaces **installers or scripts spawned by AteraAgent**.  
**Severity:** Medium  
**MITRE:** T1219, T1105

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-device inventory with first-seen per product - hunting and posture. Build an allowlist of your sanctioned RMM product(s) and treat any second product on the same device as the finding. Validated: 0 rows. The validation tenant had no executions of any listed RMM product in 30 days (confirmed by an independent RMM inventory query), so the query could not be tuned against real RMM noise - IT-managed estates will need an allowlist."
-->

```kql
let lookback = 30d;
let RmmEvents = DeviceProcessEvents
| where Timestamp > ago(lookback)
| extend F = tolower(FileName), CO = tolower(ProcessVersionInfoCompanyName), PN = tolower(ProcessVersionInfoProductName)
| extend Rmm = case(
    F has "ateraagent" or CO has "atera", "Atera",
    F has_any ("srmanager", "srservice", "srstreamer", "splashtop") or CO has "splashtop", "Splashtop",
    F has "meshagent" or PN has_any ("meshcentral", "mesh agent"), "MeshAgent",
    F has "screenconnect" or PN has "screenconnect", "ScreenConnect",
    F has "remotely_agent", "Remotely",
    F has "ninjarmm" or CO has_any ("ninjarmm", "ninjaone"), "NinjaRMM",
    F has "anydesk" or CO has "anydesk", "AnyDesk",
    F has "teamviewer" or CO has "teamviewer", "TeamViewer",
    F has "rustdesk", "RustDesk",
    F has "simplehelp" or CO has "simplehelp", "SimpleHelp",
    "")
| where isnotempty(Rmm);
let AteraSpawned = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has "ateraagent" or InitiatingProcessParentFileName has "ateraagent"
| where FileName in~ ("msiexec.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "curl.exe", "bitsadmin.exe") or ProcessCommandLine has_any ("splashtop", "streamer", ".msi", "http")
| summarize AteraChildren = count(), AteraChildCmds = make_set(substring(ProcessCommandLine, 0, 200), 10) by DeviceId;
RmmEvents
| summarize RmmFirst = min(Timestamp), Launches = count(), SpawnedBy = make_set(InitiatingProcessFileName, 5) by DeviceId, DeviceName, Rmm
| summarize RmmCount = dcount(Rmm), RmmSet = make_set(Rmm), FirstRmm = min(RmmFirst), LastNewRmm = max(RmmFirst),
    Detail = make_bag(bag_pack(Rmm, bag_pack("first", RmmFirst, "launches", Launches, "spawnedBy", SpawnedBy))) by DeviceId, DeviceName
| join kind=leftouter AteraSpawned on DeviceId
| extend AteraAndSplashtop = set_has_element(RmmSet, "Atera") and set_has_element(RmmSet, "Splashtop"),
         HoursBetweenFirstAndLastNewRmm = round(datetime_diff("minute", LastNewRmm, FirstRmm) / 60.0, 1)
| where RmmCount >= 2 or coalesce(AteraChildren, 0) > 0
| project DeviceName, RmmCount, RmmSet, AteraAndSplashtop, HoursBetweenFirstAndLastNewRmm, AteraChildren = coalesce(AteraChildren, 0), AteraChildCmds, FirstRmm, Detail
| order by AteraAndSplashtop desc, RmmCount desc
```

**Expected results:** Estates with one standard RMM tool return 0. A second product appearing within hours of the first — especially Atera followed by Splashtop — is the Storm-2570 layering pattern. Confirm each product with IT; remove and block anything unsanctioned.

---

## Query 4: Cloudflared and ngrok tunnels — LocalSystem services, token runs and RDP exposure

**Purpose:** Storm-2570 "created a persistent Cloudflare Tunnel service on the victim host... configured to run automatically as a service under LocalSystem," and used **ngrok to expose TCP 3389**. Combines process command lines (`cloudflared service install`, `tunnel run --token`, `ngrok tcp 3389`, renamed binaries detected by original file name), `ServiceInstalled` events with the service account, and non-browser connections to Cloudflare Tunnel or ngrok infrastructure.  
**Severity:** High  
**MITRE:** T1572, T1543.003, T1021.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-source per-device summary. CD path: the DeviceProcessEvents branch filtered to ExposesRdp, ServiceInstall or Renamed is row-level and suitable as a 1H scheduled rule; the DeviceNetworkEvents branch alone is noisy where Cloudflare Tunnel is sanctioned. Validated: 0 rows over 30 days in AH, and 0 cloudflared/ngrok executions over ~90 days in the Data Lake."
-->

```kql
let lookback = 30d;
let TunnelDomains = dynamic(["argotunnel.com", "cfargotunnel.com", "trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev", "ngrok-agent.com"]);
let BrowserProcs = dynamic(["msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"]);
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | extend F = tolower(FileName), OF = tolower(ProcessVersionInfoOriginalFileName), CL = tolower(ProcessCommandLine)
    | where F in ("cloudflared.exe", "ngrok.exe") or OF in ("cloudflared.exe", "ngrok.exe")
        or (CL has "cloudflared" and CL has_any ("tunnel", "service install", "--token", "--url"))
        or (CL has "ngrok" and CL has_any (" tcp ", " http ", "authtoken", "--authtoken", "start "))
    | extend Tool = iff(F has "ngrok" or OF has "ngrok" or CL has "ngrok", "ngrok", "cloudflared")
    | extend ExposesRdp = CL has_any (" 3389", ":3389", "rdp://"), ServiceInstall = CL has "service install", TokenRun = CL has_any ("--token", "tunnel run"),
             Renamed = (OF in ("cloudflared.exe", "ngrok.exe")) and F != OF
    | project Timestamp, DeviceId, DeviceName, Source = "Process", Tool, Detail = substring(ProcessCommandLine, 0, 250), Account = AccountName,
              Parent = InitiatingProcessFileName, FolderPath, ExposesRdp, ServiceInstall, TokenRun, Renamed, ServiceAccount = ""
),
(
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "ServiceInstalled"
    | extend AF = parse_json(AdditionalFields)
    | extend ServiceName = tostring(AF.ServiceName), ServiceAccount = tostring(AF.ServiceAccount)
    | where ServiceName has_any ("cloudflared", "ngrok") or FileName in~ ("cloudflared.exe", "ngrok.exe") or FolderPath has_any ("cloudflared", "ngrok")
    | project Timestamp, DeviceId, DeviceName, Source = "ServiceInstalled", Tool = iff(ServiceName has "ngrok" or FolderPath has "ngrok", "ngrok", "cloudflared"),
              Detail = strcat(ServiceName, " -> ", FolderPath, "\\", FileName), Account = InitiatingProcessAccountName, Parent = InitiatingProcessFileName, FolderPath,
              ExposesRdp = false, ServiceInstall = true, TokenRun = false, Renamed = false, ServiceAccount
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteUrl has_any (TunnelDomains)
    | where InitiatingProcessFileName !in~ (BrowserProcs)
    | project Timestamp, DeviceId, DeviceName, Source = "Network", Tool = iff(RemoteUrl has "ngrok", "ngrok", "cloudflared"),
              Detail = strcat(RemoteUrl, " ", RemoteIP, ":", RemotePort), Account = InitiatingProcessAccountName, Parent = InitiatingProcessFileName, FolderPath = InitiatingProcessFolderPath,
              ExposesRdp = false, ServiceInstall = false, TokenRun = false, Renamed = false, ServiceAccount = ""
)
| summarize Events = count(), Sources = make_set(Source), Tools = make_set(Tool), ExposesRdp = max(toint(ExposesRdp)), ServiceInstall = max(toint(ServiceInstall)),
    TokenRun = max(toint(TokenRun)), Renamed = max(toint(Renamed)), ServiceAccounts = make_set_if(ServiceAccount, isnotempty(ServiceAccount), 3),
    Details = make_set(Detail, 10), Accounts = make_set(Account, 5), Parents = make_set(Parent, 5), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, DeviceName
| extend Priority = case(ExposesRdp == 1 or (ServiceInstall == 1 and set_has_element(ServiceAccounts, "LocalSystem")), "High", Renamed == 1 or TokenRun == 1, "High", "Medium")
| order by Priority asc, Events desc
```

**Expected results:** 0 rows where tunnels aren't sanctioned. A `cloudflared` service under LocalSystem on a server, or any `ngrok` session exposing 3389, is an outbound backdoor that bypasses inbound firewalling. Stop and remove the service, then review everything the host did after the tunnel appeared.

---

## Query 5: ntdsutil IFM backup of NTDS.dit to a staging path, and NTDS/hive copies

**Purpose:** Storm-2570 runs `ntdsutil` to "activate the NTDS Active Directory instance and create a full IFM backup in `C:\Windows\Temp\<XXXXXXXXX>`," then copies `NTDS.dit` and registry hives off-host for offline hash extraction. Detects ntdsutil IFM / `create full` commands (extracting the target path and flagging Temp, PerfLogs, ProgramData or Public paths) and `ntds.dit` / `SYSTEM` / `SECURITY` hive files created outside their normal locations.  
**Severity:** High  
**MITRE:** T1003.003

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "NTDS.dit IFM staging on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "ntdsutil created an Install From Media copy of Active Directory, or NTDS.dit/registry hives were written outside their normal locations. Unless this is a documented DC promotion or backup, assume all domain credential hashes are compromised: secure the staging folder, identify the session that ran the command, and plan a krbtgt double reset and privileged credential rotation."
adaptation_notes: "Row-level union of DeviceProcessEvents and DeviceFileEvents projecting Timestamp, DeviceId, DeviceName and ReportId - scheduled (not NRT) because of the union. Legitimate IFM is rare (RODC or DC promotion from media); allowlist documented DC build accounts. Validated: 0 rows over 30 days in AH and 0 ntdsutil IFM executions over ~90 days in the Data Lake. The validation tenant's AD attack simulations used DCSync rather than IFM, which Query 1's credential-tool family covers."
-->

```kql
let lookback = 30d;
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName =~ "ntdsutil.exe" or ProcessVersionInfoOriginalFileName =~ "ntdsutil.exe" or ProcessCommandLine has "ntdsutil"
    | extend CL = tolower(ProcessCommandLine)
    | where CL has "ifm" or CL has "create full" or CL has_any ("ac i ntds", "activate instance ntds")
    | extend TargetPath = extract(@"(?i)create\s+(?:full|sysvol\s+full|rodc)\s+""?([^""]+)""?", 1, ProcessCommandLine)
    | extend TempTarget = TargetPath has_any (@"\Windows\Temp", @"\Temp\", @"\PerfLogs", @"\ProgramData", @"\Users\Public") or CL has_any (@"\windows\temp", @"\perflogs")
    | project Timestamp, DeviceId, DeviceName, ReportId, Source = "ntdsutil IFM", AccountName, Detail = substring(ProcessCommandLine, 0, 250), TargetPath, TempTarget,
              InitiatingProcessFileName, InitiatingProcessCommandLine = substring(InitiatingProcessCommandLine, 0, 200)
),
(
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where FileName =~ "ntds.dit" or (FileName in~ ("SYSTEM", "SECURITY") and FolderPath has "registry")
    | where not(FolderPath startswith @"C:\Windows\NTDS") and not(FolderPath has @"\Windows\System32\config")
    | project Timestamp, DeviceId, DeviceName, ReportId, Source = "NTDS/hive copy", AccountName = InitiatingProcessAccountName, Detail = strcat(ActionType, " ", FolderPath),
              TargetPath = FolderPath, TempTarget = FolderPath has_any (@"\Windows\Temp", @"\Temp\", @"\PerfLogs", @"\ProgramData", @"\Users\Public"),
              InitiatingProcessFileName, InitiatingProcessCommandLine = substring(InitiatingProcessCommandLine, 0, 200)
)
| order by Timestamp desc
```

**Expected results:** 0 rows outside planned DC work. Any IFM to `C:\Windows\Temp` indicates domain-wide credential compromise — treat every domain account hash as exposed.

---

## Query 6: Defender impairment — PerfLogs exclusions, direct disables and Group Policy-delivered disables

**Purpose:** Storm-2570 "disabled real-time monitoring, added Defender exclusions for `C:\PerfLogs`... and modified registry values under Microsoft Defender service keys," including `DisableAntiSpyware`, `DisableRealtimeMonitoring` and `WinDefend` service behavior. Combines `Set-MpPreference` / `Add-MpPreference` command lines with Defender registry writes and excludes Defender and MDM self-management. It separates **direct** tampering (`High`) from **Group Policy-delivered** disables (`Medium`), because a GPO turning off real-time protection across the fleet is exactly how an affiliate with domain admin would prepare for mass encryption.  
**Severity:** High  
**MITRE:** T1562.001, T1112

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-device summary across process and registry sources. CD path: the registry branch filtered to DirectDisable or PerfLogsExclusion is row-level (DeviceRegistryEvents; NRT-eligible once split from the union). Tuning, validated in a live tenant: excluding MsMpEng.exe, MpCmdRun.exe and omadmclient.exe removed Defender's own state writes and Intune policy; marking gpsvc writes as Group Policy separated 9 workstations that received a GPO-delivered DisableRealtimeMonitoring=1 in one ~80-minute window from 1 workstation with direct tampering (remote Set-MpPreference via PsExec and a scripted DisableAntiSpyware=1)."
-->

```kql
let lookback = 30d;
let PolicyApply = dynamic(["msmpeng.exe", "mpcmdrun.exe", "omadmclient.exe", "deviceenroller.exe", "senseir.exe"]);
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where ProcessCommandLine has_any ("Set-MpPreference", "Add-MpPreference", "MpCmdRun")
    | extend CL = tolower(ProcessCommandLine)
    | where CL has_any ("exclusionpath", "exclusionprocess", "exclusionextension", "disablerealtimemonitoring", "disablebehaviormonitoring", "disableioavprotection", "disablescriptscanning", "-removedefinitions")
    | extend PerfLogsExclusion = CL has "perflogs" and CL has "exclusion",
             Disables = CL has_any ("disablerealtimemonitoring 1", "disablerealtimemonitoring $true", "disablerealtimemonitoring true", "disablebehaviormonitoring 1", "disablebehaviormonitoring $true", "disableioavprotection 1", "disableioavprotection $true", "-removedefinitions")
    | project Timestamp, DeviceId, DeviceName, Source = "Command line", Actor = AccountName, Detail = substring(ProcessCommandLine, 0, 250),
              Process = FileName, PerfLogsExclusion, Disables, ViaGroupPolicy = false
),
(
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where RegistryKey has_any (@"\Microsoft\Windows Defender", @"\Services\WinDefend", @"\Policies\Microsoft\Windows Defender")
    | where (RegistryValueName in~ ("DisableAntiSpyware", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableOnAccessProtection", "DisableScriptScanning") and RegistryValueData in ("1", "0x1", "0x00000001"))
         or (RegistryKey has @"\Services\WinDefend" and RegistryValueName =~ "Start" and RegistryValueData in ("4", "0x4", "0x00000004"))
         or (RegistryKey has @"\Exclusions\Paths" and ActionType == "RegistryValueSet")
    | where InitiatingProcessFileName !in~ (PolicyApply)
    | extend ViaGroupPolicy = InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has_any ("GPSvcGroup", "gpsvc")
    | extend PerfLogsExclusion = RegistryKey has @"\Exclusions\Paths" and RegistryValueName has "PerfLogs"
    | project Timestamp, DeviceId, DeviceName, Source = iff(ViaGroupPolicy, "Registry (Group Policy)", "Registry (direct)"), Actor = InitiatingProcessAccountName,
              Detail = strcat(RegistryKey, " | ", RegistryValueName, "=", RegistryValueData, " | ", InitiatingProcessFileName, " ", substring(InitiatingProcessCommandLine, 0, 120)),
              Process = InitiatingProcessFileName, PerfLogsExclusion, Disables = RegistryKey !has @"\Exclusions\", ViaGroupPolicy
)
| extend DirectDisable = Disables and not(ViaGroupPolicy), GpDisable = Disables and ViaGroupPolicy
| summarize Events = count(), Sources = make_set(Source), PerfLogsExclusion = max(toint(PerfLogsExclusion)),
    DirectDisables = countif(DirectDisable), GpDisables = countif(GpDisable), Actors = make_set(Actor, 5), Processes = make_set(Process, 5),
    Details = make_set(Detail, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, DeviceName
| extend Priority = case(PerfLogsExclusion == 1 or DirectDisables > 0, "High", GpDisables > 0, "Medium", "Low")
| project-away DeviceId
| order by Priority asc, FirstSeen asc
```

**Expected results:** `High` rows need immediate review. Many `Medium` rows with near-identical `FirstSeen` times mean a GPO pushed a Defender disable. Find the GPO and who changed it (Group Policy management activity on the domain controllers), confirm it was intended, and check each device's current state in Defender Vulnerability Management (*Turn on real-time protection*). Tamper Protection blocks most of these changes; enable it tenant-wide.

---

## Query 7: PsExec host-list fan-out, rdp.bat and RDP enablement

**Purpose:** Extends Microsoft's published PsExec hunt. Parses PsExec command lines for **`@<file>` host lists** (Storm-2570 uses `@ip.txt`), **explicit remote targets**, `rdp.bat` execution and **renamed PsExec** (via `ProcessVersionInfoOriginalFileName == "psexec.c"`). It correlates these with RDP enablement on the same device: `fDenyTSConnections` set to 0, or a firewall rule allowing TCP 3389 — the actions `rdp.bat` performs. MDE diagnostic PsExec runs are excluded.  
**Severity:** High  
**MITRE:** T1569.002, T1570, T1021.001, T1021.002, T1036.005

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-source-device summary with an RDP-enablement join. CD path: a row-level DeviceProcessEvents rule where ProcessCommandLine contains a PsExec '@' host list or 'rdp.bat', or ProcessVersionInfoOriginalFileName == 'psexec.c' with a non-standard FileName (renamed PsExec), scheduled 1H. Tuning, validated in a live tenant: the MDE diagnostic exclusion removed MDEClientAnalyzer and Defender registry queries run through PsExec -s. The one remaining row was a purple-team workstation (3 remote targets including a domain controller, and a PsExec copy renamed to notepad.exe), correctly rated Medium."
-->

```kql
let lookback = 30d;
let MdeDiagnostics = dynamic(["Windows Advanced Threat Protection", "MDEClientAnalyzer", "winatp.cer", "SenseCM", "MDATPClientAnalyzer"]);
let PsExecRuns = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("psexec.exe", "psexec64.exe") or ProcessVersionInfoOriginalFileName =~ "psexec.c" or ProcessCommandLine has_any ("psexec.exe", "psexec64.exe")
| where not(ProcessCommandLine has_any (MdeDiagnostics))
| extend HostList = extract(@"\s@([^\s""]+)", 1, ProcessCommandLine),
         RemoteHost = extract(@"\\\\([A-Za-z0-9\.\-_]+)\s", 1, ProcessCommandLine),
         RunsRdpBat = ProcessCommandLine has "rdp.bat",
         Renamed = FileName !in~ ("psexec.exe", "psexec64.exe")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, HostList, RemoteHost, RunsRdpBat, Renamed,
          CommandLine = substring(ProcessCommandLine, 0, 250), Parent = InitiatingProcessFileName;
let RdpEnable = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where (ProcessCommandLine has "fDenyTSConnections" and ProcessCommandLine has_any (" 0", "/d 0", "0x0"))
     or (ProcessCommandLine has_any ("netsh", "New-NetFirewallRule") and ProcessCommandLine has "3389" and ProcessCommandLine has_any ("allow", "Allow"))
     or FileName =~ "rdp.bat" or ProcessCommandLine has "rdp.bat"
| summarize RdpEnableEvents = count(), RdpCmds = make_set(substring(ProcessCommandLine, 0, 200), 5), RdpFirst = min(Timestamp) by DeviceId;
PsExecRuns
| summarize Runs = count(), HostLists = make_set_if(HostList, isnotempty(HostList), 5), RemoteHosts = make_set_if(RemoteHost, isnotempty(RemoteHost), 20),
    RunsRdpBat = max(toint(RunsRdpBat)), Renamed = max(toint(Renamed)), Accounts = make_set(AccountName, 5), Parents = make_set(Parent, 5),
    SampleCommands = make_set(CommandLine, 10), FirstRun = min(Timestamp), LastRun = max(Timestamp)
    by DeviceId, DeviceName
| join kind=leftouter RdpEnable on DeviceId
| extend RemoteHostCount = array_length(RemoteHosts), UsesHostList = array_length(HostLists) > 0
| extend Priority = case(UsesHostList or RunsRdpBat == 1, "High", RemoteHostCount >= 5 or coalesce(RdpEnableEvents, 0) > 0, "High", Renamed == 1, "Medium", "Low")
| project DeviceName, Priority, Runs, UsesHostList, HostLists, RemoteHostCount, RemoteHosts, RunsRdpBat, Renamed, RdpEnableEvents = coalesce(RdpEnableEvents, 0), RdpCmds,
          Accounts, Parents, FirstRun, LastRun, SampleCommands
| order by Priority asc, RemoteHostCount desc
```

**Expected results:** A few admin workstations. `UsesHostList` (the `@ip.txt` pattern), `rdp.bat`, a renamed PsExec, or fan-out to five or more hosts matches the Storm-2570 deployment stage. Pivot `RemoteHosts` into Query 2 (MeshAgent pushed to targets) and check the targets for RDP enablement.

---

## Query 8: Impacket and NetExec remote execution over SMB/WMI

**Purpose:** Detects Impacket/NetExec both **where they run** (client command lines) and **where they land**: the characteristic target-side shape `cmd.exe /Q /c <command> 1> \\127.0.0.1\ADMIN$\__<n> 2>&1` under `wmiprvse.exe` (wmiexec), `services.exe` (smbexec), the Task Scheduler (atexec) and `mmc.exe` (dcomexec). Target-side detection matters because the operator's client usually runs outside MDE coverage.  
**Severity:** High  
**MITRE:** T1021.002, T1047, T1569.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Row-level before the final summarize. CD path: drop the summarize and project Timestamp, DeviceId, DeviceName, ReportId (1H, or NRT for the single-table target-side patterns). Complements the Storm-1175 campaign's Impacket query by adding NetExec client patterns and atexec/dcomexec target shapes. Validated: 0 rows over 30 days; an independent check for any wmiprvse- or services-spawned cmd.exe with '2>&1' output redirection also returned 0, so the zero is a clean baseline."
-->

```kql
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| extend CL = tolower(ProcessCommandLine)
| extend Pattern = case(
    FileName in~ ("nxc.exe", "netexec.exe", "crackmapexec.exe", "cme.exe") or CL has_any ("netexec", "crackmapexec") or CL matches regex @"(^|[\s""\\/])nxc(\.exe)?\s+(smb|winrm|ldap|mssql|rdp|wmi|ssh)\b", "NetExec client",
    CL has_any ("wmiexec.py", "smbexec.py", "psexec.py", "atexec.py", "dcomexec.py", "secretsdump.py"), "Impacket client",
    InitiatingProcessFileName =~ "wmiprvse.exe" and FileName =~ "cmd.exe" and CL has "/q /c" and CL has @"\\127.0.0.1\" and CL has "2>&1", "Impacket/NetExec wmiexec (target)",
    InitiatingProcessFileName =~ "services.exe" and FileName =~ "cmd.exe" and CL has "/q /c" and CL has_any (@"\\127.0.0.1\c$\__output", @"\\127.0.0.1\admin$\__", "execute.bat"), "Impacket/NetExec smbexec (target)",
    InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has "Schedule" and FileName =~ "cmd.exe" and CL has "/c" and CL has @"\windows\temp\" and CL has ".tmp 2>&1", "Impacket atexec (target)",
    InitiatingProcessFileName =~ "mmc.exe" and FileName =~ "cmd.exe" and CL has "/q /c" and CL has "2>&1", "Impacket dcomexec (target)",
    "")
| where isnotempty(Pattern)
| project Timestamp, DeviceId, DeviceName, Pattern, AccountName, AccountDomain, FileName, CommandLine = substring(ProcessCommandLine, 0, 250),
          Parent = InitiatingProcessFileName, ParentCmd = substring(InitiatingProcessCommandLine, 0, 150), LogonId, ReportId
| summarize Events = count(), Patterns = make_set(Pattern), Accounts = make_set(AccountName, 5), SampleCommands = make_set(CommandLine, 10),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceId, DeviceName
| order by Events desc
```

**Expected results:** 0 rows in most environments; legitimate software rarely produces these exact shapes. Any target-side hit means an operator with valid credentials is executing remotely. Identify the source through the logon (`LogonId` → `DeviceLogonEvents`, network logon type 3) and treat the account as compromised.

---

## Query 9: s5cmd and Rclone exfiltration to S3-compatible storage

**Purpose:** Storm-2570 "staged `s5cmd.exe` alongside a credentials file and used it to copy documents, spreadsheets, images, databases, mail-related files, archives" to attacker S3 buckets, or used Rclone for continuous sync. Flags s5cmd/Rclone executions that copy or sync, reference a credentials or config file, target `s3://` or S3-compatible endpoints, or use extension filters (counting business file types in the wildcards). Also catches renamed Rclone via version metadata and joins S3 network connections from these processes.  
**Severity:** High  
**MITRE:** T1567.002, T1537, T1119

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-device summary with a network join. CD path: a row-level DeviceProcessEvents rule for s5cmd with ' cp ' plus 's3://' or a credentials/endpoint flag, and for renamed Rclone (ProcessVersionInfoProductName == 'rclone' with a non-standard FileName), scheduled 1H. Validated: 0 rows over 30 days in AH and 0 s5cmd/Rclone executions over ~90 days in the Data Lake. Where Rclone is a sanctioned backup tool, allowlist its service account and config path rather than the binary."
-->

```kql
let lookback = 30d;
let BusinessExts = dynamic(["doc", "docx", "xls", "xlsx", "pdf", "ppt", "pptx", "csv", "pst", "ost", "msg", "eml", "zip", "rar", "7z", "sql", "bak", "mdb", "accdb", "db"]);
let S3Endpoints = dynamic(["amazonaws.com", "s3.", "wasabisys.com", "backblazeb2.com", "r2.cloudflarestorage.com", "digitaloceanspaces.com", "idrivee2", "storjshare", "mega.nz", "mega.co.nz"]);
let ExfilProc = DeviceProcessEvents
| where Timestamp > ago(lookback)
| extend F = tolower(FileName), OF = tolower(ProcessVersionInfoOriginalFileName), PN = tolower(ProcessVersionInfoProductName), CL = tolower(ProcessCommandLine)
| extend Tool = case(F == "s5cmd.exe" or CL has "s5cmd", "s5cmd", F == "rclone.exe" or OF == "rclone.exe" or PN == "rclone" or CL has "rclone", "Rclone", "")
| where isnotempty(Tool)
| extend Copies = CL has_any (" cp ", " copy ", " sync ", " move ", " mv "),
         CredFile = CL has_any ("--credentials-file", "credentials", "--config", "rclone.conf", "aws_access_key_id"),
         S3Target = CL has "s3://" or CL has_any (S3Endpoints) or CL has "--endpoint-url",
         ExtFilter = CL has "*." or CL has "--include" or CL has "--exclude",
         Renamed = (OF == "rclone.exe" or PN == "rclone") and F != "rclone.exe",
         ExtHits = array_length(extract_all(strcat(@"\*\.(", strcat_array(BusinessExts, "|"), @")\b"), CL))
| project Timestamp, DeviceId, DeviceName, Tool, AccountName, FileName, FolderPath, Copies, CredFile, S3Target, ExtFilter, Renamed, ExtHits,
          CommandLine = substring(ProcessCommandLine, 0, 250), Parent = InitiatingProcessFileName;
let ExfilNet = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has_any (S3Endpoints)
| where InitiatingProcessFileName in~ ("s5cmd.exe", "rclone.exe") or InitiatingProcessVersionInfoProductName =~ "rclone" or InitiatingProcessCommandLine has_any ("s5cmd", "rclone")
| summarize NetConnections = count(), RemoteEndpoints = make_set(RemoteUrl, 10) by DeviceId;
ExfilProc
| summarize Runs = count(), Tools = make_set(Tool), Copies = max(toint(Copies)), CredFile = max(toint(CredFile)), S3Target = max(toint(S3Target)),
    ExtFilter = max(toint(ExtFilter)), Renamed = max(toint(Renamed)), MaxBusinessExtFilters = max(ExtHits), Accounts = make_set(AccountName, 5),
    Paths = make_set(FolderPath, 5), SampleCommands = make_set(CommandLine, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, DeviceName
| join kind=leftouter ExfilNet on DeviceId
| extend Priority = case(Copies == 1 and (S3Target == 1 or CredFile == 1), "High", Renamed == 1, "High", MaxBusinessExtFilters >= 3, "High", "Medium")
| project DeviceName, Priority, Tools, Runs, Copies, CredFile, S3Target, ExtFilter, MaxBusinessExtFilters, Renamed, NetConnections = coalesce(NetConnections, 0), RemoteEndpoints,
          Accounts, Paths, FirstSeen, LastSeen, SampleCommands
| order by Priority asc, Runs desc
```

**Expected results:** 0 rows unless Rclone or s5cmd is a sanctioned tool. A `cp`/`sync` to S3 with a credentials file and several business-extension filters matches the Storm-2570 double-extortion staging step. Capture the credentials file (it contains the actor's access keys), block the bucket endpoint, and report the keys to the storage provider.

---

## Query 10: Defender detections matching the Storm-2570 coverage table, grouped by device and kill-chain stage

**Purpose:** Pulls alerts whose titles match Microsoft's Storm-2570 detection table (hands-on-keyboard, remote access software, suspicious Atera activity, Defender bypass, credential exposure, dual-use tool renaming, exfiltration, ransomware behavior) and antivirus families (PsexecRemote, Mimikatz, LaZagne, Qilin, DragonForce, Anubis, BERT). Maps each alert to a kill-chain stage and groups by device, so hosts showing **several stages** stand out.  
**Severity:** High  
**MITRE:** T1219, T1562.001, T1003, T1567, T1486

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Alert-correlation triage over existing Defender detections; re-alerting would duplicate them. Validated in a live tenant: 11 device groups over 30 days. Every multi-stage device traced to documented attack-simulation activity (a Mimikatz/PsExec purple-team workstation, and a ransomware Attack-Disruption demo writing .lockbit-extension canary files). Several alert titles are generic ('Potential human-operated malicious activity'), so the stage count, not any single title, is the signal."
-->

```kql
let lookback = 30d;
let Storm2570Titles = dynamic([
  "Hands-on-keyboard attack involving multiple devices", "Remote access software", "Suspicious PowerShell command line",
  "Suspicious PowerShell download or encoded command execution", "Ransomware-linked threat actor detected", "Suspicious Atera activity",
  "File dropped and launched from remote location", "Defender detection bypass", "Attempt to turn off Microsoft Defender Antivirus protection",
  "Exposed credentials at risk of compromise", "Compromised account credentials", "Process memory dump", "Potential human-operated malicious activity",
  "Renaming of legitimate tools for possible data exfiltration", "Possible data exfiltration", "Hidden dual-use tool launch attempt",
  "Possible ransomware activity based on a known malicious extension", "Possible compromised user account delivering ransomware-related files",
  "Potentially compromised assets exhibiting ransomware-like behavior", "Ransomware behavior detected in the file system"]);
let Storm2570AvFamilies = dynamic(["PsexecRemote", "Mimikatz", "LaZagne", "Qilinloader", "Qilin", "DragonForce", "Anubis", "BERT"]);
AlertInfo
| where Timestamp > ago(lookback)
| where Title has_any (Storm2570Titles) or Title has_any (Storm2570AvFamilies)
| extend Stage = case(
    Title has_any ("Qilin", "DragonForce", "Anubis", "BERT", "ransomware", "Ransomware", "malicious extension"), "Impact",
    Title has_any ("exfiltration", "dual-use", "Renaming of legitimate tools"), "Exfiltration",
    Title has_any ("Mimikatz", "LaZagne", "credentials", "memory dump"), "CredentialAccess",
    Title has_any ("Defender", "bypass"), "DefenseImpairment",
    Title has_any ("Atera", "Remote access software", "remote location"), "Persistence/RMM",
    "Execution")
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | summarize Devices = make_set_if(DeviceName, isnotempty(DeviceName), 10), Accounts = make_set_if(AccountName, isnotempty(AccountName), 10),
                Files = make_set_if(FileName, isnotempty(FileName), 10) by AlertId
  ) on AlertId
| mv-expand Device = iff(array_length(Devices) == 0, dynamic([""]), Devices) to typeof(string)
| summarize Alerts = dcount(AlertId), Stages = make_set(Stage), StageCount = dcount(Stage), Titles = make_set(Title, 15),
    Accounts = make_set(Accounts, 10), Files = make_set(Files, 10), FirstAlert = min(Timestamp), LastAlert = max(Timestamp)
    by Device
| extend Priority = case(StageCount >= 3 or set_has_element(Stages, "Impact"), "High", StageCount == 2, "Medium", "Low")
| order by StageCount desc, Alerts desc
```

**Expected results:** In a quiet estate, a handful of single-stage rows. Any device with **Impact** alerts, or with three or more stages, should be handled as an active human-operated ransomware incident. Use the incident view in the Defender portal and pivot the device into Queries 1–9 to find the RMM, tunnel and exfiltration footholds that outlive the payload.

---

## General Tuning Notes

1. **Behavioral by design.** Storm-2570 changes payloads (Qilin, DragonForce, Anubis, BERT) but not tradecraft, and the article publishes no hashes or network IOCs. These hunts key on the recurring tool variants and their combination; they will outlast any single ransomware family.

2. **Allowlist sanctioned RMM and tunnels first.** Queries 2–4 are high fidelity only where MeshCentral, Atera, Splashtop, ScreenConnect, NinjaOne, Cloudflare Tunnel or ngrok are **not** approved. Inventory what IT actually uses, allowlist by signer plus install path plus service account, and treat everything else — especially a **second** RMM product on the same host — as the finding.

3. **Match version metadata, not just file names.** The actor renames MeshAgent after the victim, and renamed PsExec is common (the validation tenant's purple-team runs copied PsExec to `notepad.exe`). Keep the `ProcessVersionInfo*` conditions when adapting queries.

4. **A GPO that disables Defender is a ransomware-grade event.** Query 6 rates Group Policy-delivered disables as `Medium` so they stay visible. When many hosts flip `DisableRealtimeMonitoring=1` within minutes, find the GPO, the editor and the change ticket. Enable **Tamper Protection** so policy and script changes can't silently turn protection off.

5. **Correlate source and target.** PsExec, Impacket and NetExec show on the **source** (Query 7 host lists, Query 8 clients) and on **targets** (Query 8 target-side shapes, RDP enablement, MeshAgent installs). Pivot `RemoteHosts` and `LogonId` both ways.

6. **Attack simulations will light these up.** Purple-team and attack-disruption demos use this exact tooling. Confirm with the simulation owner, and keep a separate, documented exclusion rather than weakening the queries.

7. **Prevention has high payoff here.** Enable the ASR rule *Block process creations originating from PsExec and WMI commands*, restrict RDP and admin shares between workstations, remove standing Domain Admin, monitor and protect domain controllers against IFM, and block unapproved RMM and tunnel domains at the proxy.

8. **CD-readiness summary.** **Query 5 is `cd_ready: true`** (row-level ntdsutil IFM / NTDS copy detection, scheduled 1H). **Queries 1–4 and 6–10 are `cd_ready: false`**: they are per-device summaries, multi-source correlations or alert correlation. Each has a documented row-level CD path (Queries 2, 4, 6, 7, 8 and 9). All ten queries were executed against live Advanced Hunting; the RMM, tunnel, s5cmd/Rclone and IFM families were also swept over ~90 days in the Sentinel Data Lake (0 hits). **Queries 2–5, 8 and 9 had no matching telemetry in the validation tenant**, so they are syntax- and logic-validated against a verified clean baseline, not tuned against real noise.

---

## References

- Microsoft Threat Intelligence — [Beyond the ransomware: Tracking Storm-2570's consistent tradecraft across deployments (2026-09-24)](https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/)
- Microsoft Security — [Ransomware as a service: Understanding the cybercrime gig economy](https://www.microsoft.com/en-us/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/)
- Microsoft Learn — [ASR rule: Block process creations originating from PsExec and WMI commands](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-process-creations-originating-from-psexec-and-wmi-commands)
- Microsoft Security — [How to prevent lateral movement attacks using Microsoft 365 Defender](https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/)
- MITRE ATT&CK — [T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- MITRE ATT&CK — [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- MITRE ATT&CK — [T1003.003 OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)
- MITRE ATT&CK — [T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- MITRE ATT&CK — [T1569.002 System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- MITRE ATT&CK — [T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- Companion files: [`queries/threat-intelligence/2026-04/storm_1175_medusa_ransomware_campaign.md`](../2026-04/storm_1175_medusa_ransomware_campaign.md), [`queries/threat-intelligence/2026-05/gentlemen_ransomware_go_encryptor.md`](../2026-05/gentlemen_ransomware_go_encryptor.md), [`queries/endpoint/smb_threat_detection.md`](../../endpoint/smb_threat_detection.md), [`queries/endpoint/rdp_threat_detection.md`](../../endpoint/rdp_threat_detection.md)
