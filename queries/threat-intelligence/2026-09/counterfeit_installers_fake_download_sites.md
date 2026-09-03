# Counterfeit Software Installers — Silver Fox-Consistent Fake Download Sites to Persistent Implant — Threat Hunts

**Created:** 2026-09-01  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceImageLoadEvents, DeviceRegistryEvents  
**Keywords:** counterfeit installer, fake software download, spoofed vendor site, brand impersonation, typosquat, Silver Fox, Yinhu, server-side payload regeneration, polymorphic archive, wrapper installer, randomized payload path, world-writable drop, msiexec embedded, Windows Installer proxy execution, Defender exclusion tampering, Add-MpPreference, tamper protection, SYSTEM scheduled task, throwaway task, vssadmin delete shadows, shadow copy deletion, Windows Update neutralization, wuauserv, UsoSvc, WaaSMedicSvc, uhssvc, SoftwareDistribution, icacls hardening, DLL side-loading, XPSPLOG, UxEnhance64, process injection, CreateRemoteThread, Philips Speech masquerade, TrueUpdate, Indigo Rose, Alibaba Cloud OSS, non-standard port C2, FileOriginReferrerUrl, SmartScreen, attack disruption  
**MITRE:** T1583.001, T1583.006, T1204.002, T1059.001, T1059.003, T1218.007, T1053.005, T1562.001, T1036.005, T1574.002, T1055, T1222.001, T1112, T1021.002, T1489, T1490, T1105, T1071, T1571  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Counterfeit installers to system compromise: Tracking a deceptive software download campaign (2026-09-01)](https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/)

---

## Threat Overview

Microsoft Defender Experts tracked an active campaign that uses **counterfeit software-download websites** impersonating trusted vendors to distribute malicious installers. Microsoft assesses with **moderate confidence** that the activity is consistent with the publicly reported **Silver Fox** (also known as **Yinhu**, 银狐) fake-software campaign, but has **not** attributed it to a nation-state actor. Observed victims span healthcare and medical devices, manufacturing, gaming, technology, logistics, government, and higher education, predominantly affecting **China-based operations of multinational organizations and Chinese-speaking users** — consistent with the Chinese-language lure content and the `.com.cn` / `.hl.cn` infrastructure.

The entry point is a **high-fidelity clone of a legitimate vendor's download page** (Razer, Microsoft Edge, Kaspersky, Sejda PDF, Youdao, DiskGenius, Baidu Netdisk, oCam, draw.io, SteelSeries, Sogou, Calibre, and a MindMaster typosquat, among others). All funnel to a small set of dedicated delivery hosts. A defining characteristic is that **the downloaded archive keeps the same filename while its hash changes on every download** — server-side, per-request payload regeneration. In one case two content-distinct copies of the same-named archive were written within roughly **69 seconds**. Archive families observed include `app_setup.*`, `zinst.*`, `zintall.*`, `intsoft.*`, and `innstll.*`.

Opening the archive yields a **wrapper installer** with a generated name, which creates and launches a **stage-one payload at a randomized path under a world-writable or system location** — `C:\Users\Public\<random>\<random>.exe`, `C:\Program Files (x86)\<random>\<random>.exe`, `C:\ProgramData\<random>\<random>.exe`. **Names are randomized but payload content is stable**, so hashes remain useful even as filenames rotate. The end-to-end chain appears as a parent-to-child process tree: `msedge.exe` writes the archive → an archiver (`7zFM.exe`, `360zip.exe`, `WinRAR.exe`) extracts it → the wrapper runs → the wrapper launches the randomized stage-one payload. A **parallel execution vector** uses the Windows Installer service: the extracted installer invokes `msiexec.exe` in **embedded mode**, which writes and launches a randomized executable into `C:\Users\Public\<random>\` — the same masquerade pattern delivered under a signed, trusted Windows binary.

Payloads are **masqueraded through forged version metadata**. A later-stage payload declares `CompanyName: "Speech Processing Solutions GmbH"`, `FileDescription: "Philips Speech Driver Client Configuration"`, and `OriginalFileName: PhilipsSpeechDriverConfiguration.exe` — while retaining an unfilled build-template placeholder, `ProductName: "TODO: <Product name>"`, proving the version information was fabricated rather than inherited from genuine vendor software. Microsoft also observed **`svchost.exe` executing from a non-system path**. A separate persistent payload carries the metadata of the **Indigo Rose TrueUpdate Client** (`OriginalFileName: tu_rt.exe`) and exhibits that product's runtime behavior — writing `_ir_tu2_temp_*` artifacts on each execution and connecting to an attacker-controlled **Alibaba Cloud object storage** bucket over TLS to fetch further payloads: a legitimate update mechanism repurposed for delivery. Payloads also **side-load malicious DLLs from their own directory** (`XPSPLOG.dll` with the later-stage payload, `UxEnhance64.dll` with stage-one).

**Persistence and recurring execution** use scheduled tasks with names imitating routine IT or productivity jobs (`\Deadline Mission Target`, `\Hierarchy Tools Smooth Inventory`, `\Empowering Status Tools productivity Ahead`, `\5nboF`). Because payloads are launched by the Task Scheduler service (parented to `svchost.exe -k netsvcs -p -s Schedule`) and **multiple staggered tasks run per device**, affected hosts exhibit a characteristic **~60-second re-execution cadence**. For privileged actions the malware creates a **throwaway scheduled task running as SYSTEM** (`SCHTASKS /Create … /RL HIGHEST /RU "SYSTEM"`), executes the privileged action, then **runs and immediately deletes the task** to minimize its footprint.

**Defense evasion is layered and aggressive:** sweeping Microsoft Defender path exclusions via both `Add-MpPreference -ExclusionPath` and SYSTEM registry writes to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`; **volume shadow copy deletion** (`vssadmin delete shadows /all /quiet`) to inhibit recovery; **`icacls` hardening** of payload directories so standard users cannot remove them; and **neutralization of Windows Update** by stopping and disabling `wuauserv`, `UsoSvc`, `uhssvc`, and `WaaSMedicSvc`, renaming update DLLs, deleting the `SoftwareDistribution` cache, and disabling the Windows Update scheduled tasks. A **malicious Windows Defender Application Control policy** was written to the code-integrity store on multiple devices. **Process injection** into a legitimate user application moments after it started was also observed.

**Command and control** runs over application-layer protocols on **non-standard ports** (5090, 7031, 7032, 7088–7090, 8050, 28290, 28300), against a set of six-character `[.]net` domains and IP:port endpoints, with a primary hub on `202.95.14[.]237`. Notably, the dedicated C2 tier was **often unreachable while cloud-hosted staging on Alibaba Cloud OSS remained live** — so absence of successful C2 does not imply absence of compromise.

Infrastructure enrichment resolves the vendor look-alike domains into **two procurement channels** rather than independent infrastructure: six domains in AS132839 across four unrelated netblocks and three registered country codes sharing a nameserver pair, and two more in AS8796 in a single /21. The practical implication: **netblock- and geography-based grouping misses these relationships, while ASN-level analysis surfaces them** — but because these are shared commercial hosting/DNS providers with substantial unrelated tenancy, **ASN and nameserver are hunting pivots, not blocklist entries.**

### TTP Summary

| Capability | TTP |
|---|---|
| Infrastructure | Registered vendor look-alike `.com.cn` / `.hl.cn` brand domains, dedicated delivery hosts, and abused cloud object storage (T1583.001, T1583.006) |
| Initial access | Victim downloads a counterfeit installer from a spoofed vendor page reached via search/lure (T1204.002) |
| Delivery evasion | Same-named archive whose **hash changes on every download** — server-side per-request payload regeneration |
| Execution | Wrapper installer drops a **randomized-path, stable-content** stage-one payload under `Users\Public` / `ProgramData` / `Program Files (x86)` |
| Execution — proxy | `msiexec.exe -Embedding` launches a randomized payload under a signed, trusted Windows binary (T1218.007) |
| Execution — scripting | PowerShell and `cmd` routines write exclusions, delete shadow copies, and disable Windows Update (T1059.001, T1059.003) |
| Persistence | Disguised scheduled tasks with productivity-sounding names; **~60-second recurring re-execution** (T1053.005) |
| Privilege escalation | Throwaway `/RL HIGHEST /RU "SYSTEM"` scheduled task — create, run, delete (T1053.005) |
| Defense evasion | Broad `Add-MpPreference -ExclusionPath` plus SYSTEM registry exclusion writes; malicious WDAC policy (T1562.001, T1112) |
| Defense evasion | Forged version metadata (Philips Speech driver; `ProductName: "TODO: <Product name>"`), `svchost.exe` from non-system paths (T1036.005) |
| Defense evasion | DLL side-loading — `XPSPLOG.dll` (later-stage), `UxEnhance64.dll` (stage-one) (T1574.002) |
| Defense evasion | Process injection into a freshly started legitimate application (T1055) |
| Defense evasion | `icacls` hardening of payload directories against removal (T1222.001) |
| Impact | `vssadmin delete shadows /all /quiet` inhibits recovery (T1490) |
| Impact | Stops/disables `wuauserv`, `UsoSvc`, `uhssvc`, `WaaSMedicSvc`; wipes `SoftwareDistribution` (T1489) |
| Lateral movement | Attempted SMB remote file access to additional hosts (T1021.002) |
| Command and control | Repurposed updater runtime fetches payloads from Alibaba Cloud OSS; C2 on non-standard ports (T1105, T1071, T1571) |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **Hunting archive filenames or wrapper names** | Archive *names* repeat while **hashes change on every download**, and wrapper/payload names are randomized per install. Filename-based hunting fails in both directions. Pivot on the **drop-path shape**, the **stable stage-one/networking hashes**, and the referrer chain. |
| **`msiexec -Embedding` + `Global\MSI0000` looks specific but is not** | `Global\MSI0000` is **standard Windows Installer behavior** and appears across ordinary, legitimate MSI installations. Testing during authoring confirmed it produces a substantial benign baseline on its own. The **actual discriminator is the payload landing in `C:\Users\Public\<random>\`** — keep the world-writable path condition, and treat `Global\MSI0000` as descriptive context rather than a filter that narrows anything. |
| **Task Scheduler launching from `ProgramData` is extremely common** | Microsoft's published "disguised scheduled-task" pattern (`svchost -k netsvcs … Schedule` launching an `.exe` from a user-writable path) matches an enormous volume of **legitimate agent, updater, and management software** — it returned thousands of benign rows during authoring. The campaign's distinguishing feature is the **~60-second re-execution cadence from multiple staggered tasks**. Query 8 encodes that cadence, which reduced the same population to zero noise in testing. Do not deploy the un-caveated path-only version. |
| **Bare Windows Update service names are noisy** | Simply matching `wuauserv` / `UsoSvc` / `WaaSMedicSvc` / `uhssvc` in a command line hits routine, legitimate Windows Update servicing operations. Require the **destructive verbs** — `sc config … disabled`, `net stop`, `rename`, or a `SoftwareDistribution` deletion — not the service name alone. |
| **Bare `softwaredistribution` is noisy** | The folder is referenced by ordinary Windows Update maintenance. Require the **destructive verbs** (`erase /f /s /q`, `rmdir /s /q`, `del`) alongside it. |
| **ASN / nameserver treated as blocklist entries** | The article is explicit: these are **shared commercial hosting and DNS providers carrying substantial unrelated tenancy**. Use ASN and nameserver as **hunting pivots only** — blocking them would break large volumes of legitimate traffic. |
| **Assuming no successful C2 means no compromise** | The dedicated C2 tier was **intermittently unreachable** while the same payloads still completed TLS connections to cloud object storage. Hunt **failed/blocked** connection attempts (`ConnectionFailed`, `FirewallOutboundConnectionBlocked`) as well as successes. |
| **Blocklisting the cloud storage provider** | The staging bucket is on **legitimate Alibaba Cloud OSS**. Match the specific bucket hostnames as indicators; never block the provider domain. |
| **Trusting signed-looking version metadata** | Payloads carry **forged** vendor metadata. The tell is the combination of vendor-branded metadata with a **randomized directory and filename**, and the leftover build placeholder `ProductName: "TODO: <Product name>"`. |
| **Missing the referrer relationship** | The lure domains rotate constantly. `FileOriginUrl` / `FileOriginReferrerUrl` tie a downloaded archive to the impersonation page **and** the delivery host, surviving individual domain rotation — use them to catch new pairs. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Campaign payload hash sweep (direct IOC)](#query-1-campaign-payload-hash-sweep-direct-ioc) | Investigation | `DeviceFileEvents` + `DeviceProcessEvents` |
| 2 | [Command-and-control sweep — non-standard ports and six-character `....](#query-2-command-and-control-sweep--non-standard-ports-and-six-character-net-domains) | Investigation | `DeviceNetworkEvents` |
| 3 | [Lure, delivery, and cloud-staging infrastructure sweep](#query-3-lure-delivery-and-cloud-staging-infrastructure-sweep) | Investigation | `DeviceNetworkEvents` |
| 4 | [Randomized payload drop pattern in world-writable and system locations](#query-4-randomized-payload-drop-pattern-in-world-writable-and-system-locations) | Investigation | `DeviceFileEvents` + `DeviceProcessEvents` |
| 5 | [Microsoft Defender exclusion tampering and throwaway SYSTEM schedul...](#query-5-microsoft-defender-exclusion-tampering-and-throwaway-system-scheduled-task) | Detection | `DeviceProcessEvents` |
| 6 | [Recovery inhibition and Windows Update neutralization](#query-6-recovery-inhibition-and-windows-update-neutralization) | Investigation | `DeviceProcessEvents` |
| 7 | [Windows Installer embedded-mode drop to a world-writable path](#query-7-windows-installer-embedded-mode-drop-to-a-world-writable-path) | Investigation | `DeviceProcessEvents` |
| 8 | [Disguised scheduled tasks with high-cadence re-execution](#query-8-disguised-scheduled-tasks-with-high-cadence-re-execution) | Detection | `DeviceProcessEvents` |
| 9 | [Forged vendor metadata, non-system `svchost`, and campaign DLL side...](#query-9-forged-vendor-metadata-non-system-svchost-and-campaign-dll-side-loading) | Investigation | `DeviceProcessEvents` |


## IOC Reference

> Published indicators from the Microsoft Threat Intelligence article. **These IOCs rot quickly** — this campaign regenerates payloads server-side per request and rotates lure domains and delivery hosts continuously. The **behavioral hunts (Queries 4–9) are the durable coverage**; refresh Queries 1–3 against current Microsoft Threat Intelligence. Domains/IPs are defanged below; the queries use plain forms.

### Payload hashes (SHA-256) — stable content despite randomized filenames

| SHA-256 | Role |
|---|---|
| 676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7 | Stage-one payload |
| 6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8 | Later-stage payload (Philips Speech masquerade) |
| c4100ad39d8db98f063feb6c3b6c8e9a9f9d9bf25a1e0233f43b058ff8a7dbdf | Networking payload |
| 1bd3662d784840e410d2d3c0a1040277f7f549089447359f01e05c2559cb1f17 | Persistent payload (observed performing process injection) |
| c6100166e2d3b40388980f7674712ef39e937ac04925ca5d370415399ed73faf | TrueUpdate-based loader |
| f33d160d757e4b39019fdef21cf90cafb501b800ca0d4039366bc30856e3d81b | Persistent / networking payload |
| e4fe2dee8f0bb132fa15fc686d1f93df39530a2d3a8d3a1f3a605a057c04e7b3 | Supporting DLL |

### Brand-impersonation lure domains

| Domain | Impersonated brand |
|---|---|
| pc-razerzone[.]com[.]cn | Razer (Synapse driver) |
| app-microsoft-edge[.]com[.]cn | Microsoft Edge |
| kaspersky-lab[.]hl[.]cn | Kaspersky |
| sejda[.]hl[.]cn | Sejda PDF |
| translate-youdao[.]hl[.]cn | NetEase Youdao Dictionary |
| zh-diskgenius[.]com[.]cn | DiskGenius |
| baidu-pan[.]com[.]cn | Baidu Netdisk (Pan) |
| ocam-pc[.]com[.]cn | oCam Screen Recorder |
| cn-drawio[.]com[.]cn | draw.io |
| steelseries-cn[.]com[.]cn | SteelSeries |
| gw-sogou[.]com[.]cn | Sogou |
| calibre-ebook[.]com[.]cn | Calibre |
| mindmoster[.]com[.]cn | MindMaster (typosquat) |

Additional lure hosts named in the article (all `[.]com[.]cn` / `[.]hl[.]cn`): `pc-codex`, `jinshan-cibapc`, `zh-tbtool`, `web-tbtool`, `zh-doubaosrf`, `ieway-cn`.

### Delivery hosts, download endpoints, and cloud staging

| Indicator | Type | Description |
|---|---|---|
| gehie246[.]com | Domain | Dedicated delivery host (`/712down`) |
| yimxg25tiy[.]com | Domain | Dedicated delivery host (`/73inst`) |
| cc8ttkv35b[.]com | Domain | Dedicated delivery host (`/7qinst`) |
| n7b8t85zsg[.]com | Domain | Dedicated delivery host (`/ins711`) |
| bxfh[.]tzcdq[.]cn | Domain | Delivery host |
| tmsq[.]tzcdq[.]cn | Domain | Delivery host |
| mebx78e02[.]com | Domain | Delivery host |
| qwjre1487[.]com | Domain | Delivery host |
| `/712down`, `/73inst`, `/7qinst`, `/ins711` | URL paths | Download endpoints |
| newopt001.oss-cn-hongkong.aliyuncs[.]com/innstll.1.0.61.zip | URL | Attacker-controlled cloud staging object |
| upitem.oss-cn-hangzhou.aliyuncs[.]com | Domain | Attacker-controlled cloud staging bucket (TLS 443) |

### Command-and-control

| Indicator | Type |
|---|---|
| iualef[.]net, oijfwe[.]net, euioxu[.]net, czijbh[.]net, wfmwsj[.]net, tbdqxq[.]net | C2 domains (six-character `[.]net`) |
| 202.95.14[.]237 | C2 IP (primary hub, AS152194 CTG Server Limited) |
| 47.239.232[.]245, 161.248.87[.]157, 103.156.25[.]35, 103.183.3[.]162 | C2 IPs |
| 43.99.100[.]248, 47.239.175[.]163, 47.86.205[.]97, 47.243.218[.]255 | C2 IPs |
| 5090, 7031, 7032, 7088, 7089, 7090, 8050, 28290, 28300 | Non-standard C2 ports |

### Behavioral indicators

| Indicator | Type | Description |
|---|---|---|
| `app_setup.*`, `zinst.*`, `zintall.*`, `intsoft.*`, `innstll.*` | Archive names | Same-named archives whose hash changes per download |
| `C:\Users\Public\<random>\<random>.exe` | Path pattern | Stage-one drop location |
| `C:\Program Files (x86)\<random>\<random>.exe` | Path pattern | Later-stage drop location |
| `C:\ProgramData\<random>\<random>.exe` | Path pattern | Persistent payload location |
| `\Deadline Mission Target`, `\Hierarchy Tools Smooth Inventory`, `\Empowering Status Tools productivity Ahead`, `\5nboF` | Task names | Disguised scheduled tasks |
| `Speech Processing Solutions GmbH` / `PhilipsSpeechDriverConfiguration.exe` / `ProductName: "TODO: <Product name>"` | Version metadata | Forged masquerade metadata |
| `tu_rt.exe` (Indigo Rose TrueUpdate), `_ir_tu2_temp_*` | Metadata / artifacts | Repurposed updater runtime |
| XPSPLOG.dll, UxEnhance64.dll | Filenames | Side-loaded malicious DLLs |

---

## Query 1: Campaign payload hash sweep (direct IOC)

**Purpose:** Direct SHA-256 match for the seven stable campaign payloads across process execution, file write, and image-load telemetry. Because filenames and paths are randomized per install but **payload content is stable**, hashes remain the highest-confidence direct indicator for this campaign. Image-load coverage catches the side-loaded supporting DLL, which may never appear as a process image.  
**Severity:** High  
**MITRE:** T1204.002, T1105, T1574.002

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Counterfeit-installer campaign payload on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A stable payload hash from the counterfeit software-download campaign was observed. Treat the device as compromised. Expect layered defense evasion already in place: check for Microsoft Defender path exclusions, deleted volume shadow copies, disabled Windows Update services, and a malicious WDAC policy in the code-integrity store (Queries 5 and 6). Enumerate and remove the disguised scheduled tasks providing recurring execution (Query 8) - attack disruption may contain the device but full eradication of persistence requires responder action. Identify the download referrer chain to find the lure page and delivery host, and submit them for blocking."
adaptation_notes: "Direct published IOCs against stable payload content - the highest-fidelity query in this file, and unusually durable for this campaign because filenames rotate while hashes do not. Uses a union across three device tables, so NRT is unavailable; 1H is appropriate. Still refresh the hash list from current Microsoft Threat Intelligence, since the operator can rebuild payloads at any time."
-->

```kql
let CampaignSha256 = dynamic([
  "676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7",  // stage-one
  "6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8",  // later-stage (Philips masquerade)
  "c4100ad39d8db98f063feb6c3b6c8e9a9f9d9bf25a1e0233f43b058ff8a7dbdf",  // networking
  "1bd3662d784840e410d2d3c0a1040277f7f549089447359f01e05c2559cb1f17",  // persistent (process injection)
  "c6100166e2d3b40388980f7674712ef39e937ac04925ca5d370415399ed73faf",  // TrueUpdate loader
  "f33d160d757e4b39019fdef21cf90cafb501b800ca0d4039366bc30856e3d81b",  // persistent / networking
  "e4fe2dee8f0bb132fa15fc686d1f93df39530a2d3a8d3a1f3a605a057c04e7b3"]);// supporting DLL
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (CampaignSha256) or InitiatingProcessSHA256 in~ (CampaignSha256)
    | project Timestamp, SourceTable = "DeviceProcessEvents", DeviceName, DeviceId, ActionType,
        FileName, FolderPath, SHA256, AccountName,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ReportId),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (CampaignSha256) or InitiatingProcessSHA256 in~ (CampaignSha256)
    | project Timestamp, SourceTable = "DeviceFileEvents", DeviceName, DeviceId, ActionType,
        FileName, FolderPath, SHA256, AccountName = InitiatingProcessAccountName,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ReportId),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (CampaignSha256)
    | project Timestamp, SourceTable = "DeviceImageLoadEvents", DeviceName, DeviceId, ActionType,
        FileName, FolderPath, SHA256, AccountName = InitiatingProcessAccountName,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ReportId)
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Any match is a confirmed compromise — escalate and assume the full defense-evasion chain is already in place.

---

## Query 2: Command-and-control sweep — non-standard ports and six-character `.net` domains

**Purpose:** Direct-match sweep for the campaign's C2 IP:port set and six-character `[.]net` C2 domains. Deliberately includes **failed and firewall-blocked** connection attempts, because the article documents that the dedicated C2 tier was often unreachable while the same payloads still reached cloud staging — a blocked outbound attempt is therefore evidence of an active implant, not evidence of safety.  
**Severity:** High  
**MITRE:** T1071, T1571

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "CommandAndControl"
title: "Counterfeit-installer campaign C2 contact from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An endpoint attempted to contact published command-and-control infrastructure for the counterfeit software-download campaign. A blocked or failed connection still indicates an active implant on the host - the article documents the C2 tier being intermittently unreachable while payloads remained live. Identify the initiating process and its folder path (expect a randomized directory under Users\\Public, ProgramData, or Program Files (x86)), then triage the device for the full persistence and defense-evasion chain (Queries 5, 6, 8). Isolate and remediate; attack disruption alone does not eradicate persistence."
adaptation_notes: "Single-table DeviceNetworkEvents with no joins - NRT eligible. Direct published IOCs, high fidelity. The IP:port pairing keeps this tight; matching the C2 IPs on any port would be looser but may catch port rotation - evaluate for your environment. The six-character .net domain list is a snapshot and will decay as the operator registers new ones."
-->

```kql
let C2Ip = dynamic([
  "202.95.14.237",    // primary hub (AS152194)
  "47.239.232.245", "161.248.87.157", "103.156.25.35", "103.183.3.162",
  "43.99.100.248", "47.239.175.163", "47.86.205.97", "47.243.218.255"]);
let C2Ports = dynamic([5090, 7031, 7032, 7088, 7089, 7090, 8050, 28290, 28300]);
let C2Domains = dynamic(["iualef.net","oijfwe.net","euioxu.net","czijbh.net","wfmwsj.net","tbdqxq.net"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteIP in (C2Ip) and RemotePort in (C2Ports))
    or RemoteIP in (C2Ip)
    or RemoteUrl has_any (C2Domains)
| extend MatchType = case(
    RemoteUrl has_any (C2Domains),                              "C2Domain",
    RemoteIP in (C2Ip) and RemotePort in (C2Ports),             "C2IpPortPair",
    "C2IpOtherPort")
// Blocked/failed attempts are evidence of an active implant, not of safety
| extend Disposition = ActionType
| project Timestamp, MatchType, Disposition, DeviceName, DeviceId, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256,
    InitiatingProcessCommandLine, InitiatingProcessAccountName, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. `ConnectionFailed` or `FirewallOutboundConnectionBlocked` dispositions are **just as significant** as successes — investigate the initiating process regardless of outcome.

---

## Query 3: Lure, delivery, and cloud-staging infrastructure sweep

**Purpose:** Direct-match sweep across the three infrastructure tiers: the brand-impersonation lure pages, the dedicated delivery hosts and their `/712down`-style download endpoints, and the attacker-controlled Alibaba Cloud OSS staging buckets. Labels each hit by tier so the analyst immediately knows whether they are seeing a user browsing a fake page, an actual payload download, or a running implant fetching a further stage.  
**Severity:** High  
**MITRE:** T1583.001, T1583.006, T1204.002, T1105

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "InitialAccess"
title: "Counterfeit software-download infrastructure contacted from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An endpoint contacted counterfeit software-download campaign infrastructure. A LurePage hit means a user reached a spoofed vendor download page and may not yet have executed anything - check for a subsequent archive download and extraction. A DeliveryHost or CloudStaging hit means a payload was very likely retrieved; triage the device immediately with Queries 1, 4, and 7. Capture FileOriginUrl and FileOriginReferrerUrl on any downloaded archive to identify new lure-to-delivery pairs, and block the specific hosts - never the parent cloud storage provider, which is legitimate."
adaptation_notes: "Single-table DeviceNetworkEvents with no joins - NRT eligible. Direct published IOCs. Lure domains rotate aggressively so this list decays fast; the download-path fragments (/712down, /73inst, /7qinst, /ins711) are somewhat more durable than the hostnames but are short strings, so they are matched only in combination with URL context. Note the Alibaba Cloud OSS entries are specific bucket hostnames - never broaden to the aliyuncs.com provider domain, which is legitimate."
-->

```kql
let LureDomains = dynamic([
  "pc-razerzone.com.cn","app-microsoft-edge.com.cn","kaspersky-lab.hl.cn","sejda.hl.cn",
  "translate-youdao.hl.cn","zh-diskgenius.com.cn","baidu-pan.com.cn","ocam-pc.com.cn",
  "cn-drawio.com.cn","steelseries-cn.com.cn","gw-sogou.com.cn","calibre-ebook.com.cn",
  "mindmoster.com.cn","pc-codex.com.cn","jinshan-cibapc.com.cn","zh-tbtool.com.cn",
  "web-tbtool.com.cn","zh-doubaosrf.com.cn","ieway-cn.com.cn"]);
let DeliveryHosts = dynamic([
  "gehie246.com","yimxg25tiy.com","cc8ttkv35b.com","n7b8t85zsg.com",
  "bxfh.tzcdq.cn","tmsq.tzcdq.cn","mebx78e02.com","qwjre1487.com"]);
let DownloadPaths = dynamic(["/712down","/73inst","/7qinst","/ins711"]);
// Specific attacker-controlled buckets only - aliyuncs.com itself is legitimate cloud storage.
let CloudStaging = dynamic(["newopt001.oss-cn-hongkong.aliyuncs.com","upitem.oss-cn-hangzhou.aliyuncs.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (LureDomains)
    or RemoteUrl has_any (DeliveryHosts)
    or RemoteUrl has_any (CloudStaging)
    or (RemoteUrl has_any (DownloadPaths) and RemoteUrl has_any (DeliveryHosts))
| extend Tier = case(
    RemoteUrl has_any (CloudStaging),   "CloudStaging",
    RemoteUrl has_any (DeliveryHosts),  "DeliveryHost",
    "LurePage")
| project Timestamp, Tier, DeviceName, DeviceId, ActionType, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Escalation order is `CloudStaging` (running implant) > `DeliveryHost` (payload retrieved) > `LurePage` (user reached the fake page). For any hit, pull `FileOriginUrl` / `FileOriginReferrerUrl` from `DeviceFileEvents` to map new lure-to-delivery pairs as the operator rotates.

---

## Query 4: Randomized payload drop pattern in world-writable and system locations

**Purpose:** The campaign's **most durable behavioral signature**. Filenames and directory names are randomized per install, but the *shape* is stable: a short alphanumeric directory containing a short alphanumeric executable, under `C:\Users\Public\`, `C:\ProgramData\`, or `C:\Program Files (x86)\`. Adapted from Microsoft's published query, extended to also surface the file-write side of the drop and to flag the archiver/`msiexec`/`explorer` parents that characterize the two observed delivery vectors.  
**Severity:** High  
**MITRE:** T1204.002, T1036.005, T1218.007

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Randomized executable dropped to a world-writable path on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An executable with a randomized name was created or executed inside a randomized short directory under Users\\Public, ProgramData, or Program Files (x86) - the stable staging shape of the counterfeit software-download campaign, which survives the filename and hash rotation this operator relies on. Capture the SHA256 and compare against Query 1. Identify the parent: an archiver such as 7zFM, 360zip, or WinRAR indicates the wrapper-installer chain, while msiexec indicates the Windows Installer proxy vector. Check the device for Defender exclusions, deleted shadow copies, and disguised scheduled tasks before clearing."
adaptation_notes: "Behavioral and filename-independent, which makes it the most durable detection here. The regex is deliberately narrow - a 4-10 character alphanumeric directory containing a 4-10 character alphanumeric executable - so legitimate software using descriptive folder and file names does not match. Some installers and updaters do create GUID-like or hash-named staging directories under ProgramData and may match; baseline first and allowlist by publisher or by the specific parent process. Restricting to the campaign parent processes (the CampaignParent column) is available as a further tightening if the open version proves noisy locally."
-->

```kql
let DropPathRegex = @"(?i)^C:\\(Users\\Public|ProgramData|Program Files \(x86\))\\[A-Za-z0-9]{4,10}\\[A-Za-z0-9]{4,10}\.exe$";
let CampaignParents = dynamic(["msiexec.exe","explorer.exe","svchost.exe","cmd.exe","7zFM.exe","360zip.exe","WinRAR.exe","msedge.exe","chrome.exe"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FolderPath matches regex DropPathRegex
    | project Timestamp, Stage = "Execution", DeviceName, DeviceId, AccountName,
        FileName, FolderPath, SHA256, ProcessCommandLine,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ReportId),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in~ ("FileCreated", "FileModified", "FileRenamed")
    | where FolderPath matches regex DropPathRegex
    | project Timestamp, Stage = "FileWrite", DeviceName, DeviceId, AccountName = InitiatingProcessAccountName,
        FileName, FolderPath, SHA256, ProcessCommandLine = "",
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ReportId)
| extend CampaignParent = InitiatingProcessFileName in~ (CampaignParents)
| extend ArchiverParent = InitiatingProcessFileName in~ ("7zFM.exe","360zip.exe","WinRAR.exe","7z.exe","Bandizip.exe")
| sort by Timestamp desc
```

**Expected results:** Low volume in a healthy environment — legitimate software generally uses descriptive directory and file names rather than short random alphanumerics. `ArchiverParent == true` reproduces the article's documented chain (browser downloads archive → archiver extracts → wrapper drops payload) and is the strongest single confirmation.

---

## Query 5: Microsoft Defender exclusion tampering and throwaway SYSTEM scheduled task

**Purpose:** Detects the campaign's core defense-evasion step — writing sweeping Microsoft Defender path exclusions via `Add-MpPreference -ExclusionPath`, via direct registry writes to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, or via a **throwaway scheduled task running as SYSTEM** created solely to perform the privileged exclusion write before deleting itself. Flags the especially aggressive case where the exclusion covers a drive root or an entire top-level profile directory.  
**Severity:** High  
**MITRE:** T1562.001, T1112, T1053.005, T1059.001

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "DefenseEvasion"
title: "Microsoft Defender exclusion tampering on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A process attempted to add Microsoft Defender path exclusions, either through Add-MpPreference, a direct registry write to the Defender exclusions key, or a short-lived SYSTEM scheduled task created to perform the write. Legitimate exclusion management is performed centrally through policy, not ad hoc from a command line, and sweeping exclusions covering a drive root or an entire user profile are effectively never legitimate. Verify Tamper Protection is enforced - it blocks these writes even when the payload runs as SYSTEM. Review and remove any exclusions that were added, then hunt the excluded paths for payloads that were hidden by them, and check for shadow-copy deletion and Windows Update neutralization (Query 6)."
adaptation_notes: "Single-table with no joins - NRT eligible, and this is the highest-value promotion candidate in this file because it is both high fidelity and early in the kill chain. Expect a small benign baseline from endpoint management and antivirus-migration tooling that legitimately sets exclusions; allowlist those specific management agents by InitiatingProcessFileName rather than weakening the predicate. The SweepingExclusion column flags drive-root and whole-profile exclusions, which are effectively never legitimate and are the strongest sub-signal."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("Add-MpPreference", "Set-MpPreference", @"Windows Defender\Exclusions", "ExclusionPath", "ExclusionExtension")
| extend Method = case(
    ProcessCommandLine has "SCHTASKS" and ProcessCommandLine has "SYSTEM",   "ThrowawaySystemTask",
    ProcessCommandLine has @"Windows Defender\Exclusions",                   "RegistryExclusionWrite",
    ProcessCommandLine has_any ("Add-MpPreference","Set-MpPreference"),      "PowerShellExclusion",
    "Other")
// Drive-root or whole-profile exclusions are effectively never legitimate
| extend SweepingExclusion = ProcessCommandLine has_any (
    @"'C:\'", @"""C:\""", @"'C:\Users'", @"'C:\ProgramData'", @"'C:\Program Files (x86)'",
    "localappdata", @"C:\Users',", @"C:\',")
| extend ElevatedTask = ProcessCommandLine has "/RL HIGHEST" or ProcessCommandLine has @"/RU ""SYSTEM"""
| project Timestamp, DeviceName, DeviceId, AccountName, Method, SweepingExclusion, ElevatedTask,
    FileName, ProcessCommandLine, FolderPath,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, ReportId
| sort by Timestamp desc
```

**Expected results:** Near-zero in a well-managed environment where exclusions are set centrally by policy rather than ad hoc from a command line. Any `SweepingExclusion == true` row — an exclusion covering a drive root or an entire profile directory — should be treated as malicious until proven otherwise, and `Method == "ThrowawaySystemTask"` is this campaign's exact signature.

---

## Query 6: Recovery inhibition and Windows Update neutralization

**Purpose:** Detects the campaign's impact stage — volume shadow copy deletion, stopping and disabling the Windows Update service stack (`wuauserv`, `UsoSvc`, `uhssvc`, `WaaSMedicSvc`), renaming update DLLs, wiping the `SoftwareDistribution` cache, disabling Windows Update scheduled tasks, and `icacls` hardening of payload directories. **Every clause requires a destructive verb**, not merely a mention of the service or folder, which is what keeps this query usable.  
**Severity:** High  
**MITRE:** T1490, T1489, T1222.001, T1112, T1059.003

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "Impact"
title: "Recovery inhibition or Windows Update neutralization on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A process deleted volume shadow copies, disabled the Windows Update service stack, wiped the SoftwareDistribution cache, or hardened a payload directory with icacls. Shadow-copy deletion is a standard pre-ransomware and anti-recovery action and should be treated as an emergency regardless of attribution. Isolate the device, identify the initiating process and its folder path, restore the disabled update services and any renamed update DLLs, remove icacls ACL modifications on attacker-hardened directories, and hunt for the associated payloads and Defender exclusions (Queries 1, 4, 5). Verify backups are intact and offline."
adaptation_notes: "Single-table with no joins - NRT eligible and high fidelity, because every clause requires a destructive verb rather than a bare service or folder name. This distinction matters: testing during authoring showed that matching the Windows Update service names alone, or the SoftwareDistribution folder alone, produces a large benign baseline from routine servicing operations, whereas requiring sc config disabled, net stop, rename, or an erase/rmdir verb reduces it to nothing. Expect rare benign hits from legitimate imaging, servicing, or update-repair tooling; allowlist those specific management processes rather than relaxing the verb requirements."
-->

```kql
let UpdateServices = dynamic(["wuauserv", "UsoSvc", "uhssvc", "WaaSMedicSvc"]);
let PayloadDirs    = dynamic([@"C:\ProgramData\", @"C:\Users\Public\", @"C:\Program Files (x86)\"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where
    // Shadow-copy deletion - anti-recovery
       (ProcessCommandLine has "vssadmin" and ProcessCommandLine has "shadow" and ProcessCommandLine has_any ("delete", "resize"))
    or (ProcessCommandLine has "wmic" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    // Windows Update stack disabled - requires a destructive verb, not just the service name
    or (ProcessCommandLine has_any (UpdateServices) and ProcessCommandLine has_all ("sc", "config", "disabled"))
    or (ProcessCommandLine has_any (UpdateServices) and ProcessCommandLine has "net stop")
    or (ProcessCommandLine has "rename" and ProcessCommandLine has_any ("wuaueng", "WaaSMedicSvc"))
    or (ProcessCommandLine has "NoAutoUpdate")
    or (ProcessCommandLine has "Disable-ScheduledTask" and ProcessCommandLine has "WindowsUpdate")
    // SoftwareDistribution wipe - requires a destructive verb, not just the folder name
    or (ProcessCommandLine has "softwaredistribution" and ProcessCommandLine has_any ("erase ", "rmdir", "rd /s", "del /"))
    // Payload-directory ACL hardening against removal
    or (ProcessCommandLine has "icacls" and ProcessCommandLine has_any (PayloadDirs)
        and ProcessCommandLine has_any ("/grant", "/setowner", "/remove", "/inheritance"))
| extend Behavior = case(
    ProcessCommandLine has "shadow",                                                   "ShadowCopyDeletion",
    ProcessCommandLine has "icacls",                                                   "PayloadDirHardening",
    ProcessCommandLine has "softwaredistribution",                                     "SoftwareDistributionWipe",
    ProcessCommandLine has_any ("NoAutoUpdate", "Disable-ScheduledTask"),              "UpdatePolicyDisable",
    "UpdateServiceDisable")
| project Timestamp, Behavior, DeviceName, DeviceId, AccountName, FileName, ProcessCommandLine,
    FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessCommandLine, InitiatingProcessParentFileName, ReportId
| sort by Timestamp desc
```

**Expected results:** Near-zero. `ShadowCopyDeletion` is the highest-severity row type and warrants immediate isolation regardless of attribution. Multiple distinct `Behavior` values on the same device within a short window is the campaign's layered-evasion signature.

---

## Query 7: Windows Installer embedded-mode drop to a world-writable path

**Purpose:** Detects the campaign's parallel execution vector, where the extracted installer invokes `msiexec.exe` in **embedded mode** and the Windows Installer service writes and launches a randomized executable into `C:\Users\Public\<random>\`. Deliberately **does not** rely on the `Global\MSI0000` mutex string as a narrowing filter — testing showed that string is standard Windows Installer behavior present across ordinary legitimate installs. The **world-writable payload path is the real discriminator.**  
**Severity:** High  
**MITRE:** T1218.007, T1036.005

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "DefenseEvasion"
title: "Windows Installer launched a payload from a world-writable path on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "msiexec.exe running in embedded mode launched an executable from a world-writable directory such as C:\\Users\\Public. Legitimate MSI packages install into Program Files or a vendor-specific directory, not into world-writable user-shared locations, so this pattern is strongly indicative of the counterfeit-installer campaign's Windows Installer proxy-execution vector. Capture the payload SHA256 and compare against Query 1, identify the source MSI and where it was downloaded from, and triage the device for the associated persistence and defense-evasion chain."
adaptation_notes: "Single-table with no joins - NRT eligible. Important tuning finding from authoring: Microsoft's published version of this pattern pairs -Embedding with the Global\\MSI0000 mutex string, but testing showed that combination matches a substantial volume of entirely ordinary MSI installations, because Global\\MSI0000 is standard Windows Installer behavior. The condition that actually discriminates is the payload landing in a world-writable path, which produced zero benign matches in testing. This query therefore treats the world-writable path as the required condition and Global\\MSI0000 as descriptive context only. Rare legitimate installers may stage into ProgramData - allowlist those by publisher if they appear."
-->

```kql
let WorldWritablePaths = dynamic([@"C:\Users\Public\", @"C:\ProgramData\"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "msiexec.exe"
| where InitiatingProcessCommandLine has "-Embedding" or InitiatingProcessCommandLine has "/V"
// The world-writable payload path is the discriminator - NOT the Global\MSI0000 mutex,
// which is standard Windows Installer behavior present in ordinary legitimate installs.
| where FolderPath has_any (WorldWritablePaths)
| where FileName endswith ".exe"
| extend RandomizedName = FolderPath matches regex @"(?i)\\[A-Za-z0-9]{4,10}\\[A-Za-z0-9]{4,10}\.exe$"
| extend HasGlobalMsiMutex = InitiatingProcessCommandLine has @"Global\MSI0000"   // context only
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, FolderPath, SHA256,
    RandomizedName, HasGlobalMsiMutex, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in a healthy environment — legitimate MSI packages do not install executables into `C:\Users\Public`. `RandomizedName == true` confirms the campaign's staging shape and should be correlated with Query 4.

---

## Query 8: Disguised scheduled tasks with high-cadence re-execution

**Purpose:** Detects the campaign's persistence and recurring-execution behavior. Because multiple staggered disguised tasks run per device, affected hosts show a characteristic **~60-second re-execution cadence** for payloads launched by the Task Scheduler service (`svchost.exe -k netsvcs -p -s Schedule`) from user-writable directories. **The cadence is the detection** — the path-only pattern alone matches an enormous amount of legitimate agent and updater activity.  
**Severity:** High  
**MITRE:** T1053.005, T1036.005

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Requires per-environment threshold calibration before promotion, and uses a summarize with computed cadence so it is a scheduled hunting query rather than an NRT candidate. Critical tuning finding from authoring: the path-only version of this pattern - Task Scheduler launching an executable from ProgramData, Users\\Public, or Program Files (x86) - matched many thousands of entirely legitimate rows from ordinary agent, updater, and management software, making it unusable as published. Adding the campaign's actual signature, a high execution count with a very short average gap between executions, reduced that same population to zero noise in testing. Calibrate MinExecutions and MaxAvgGapMinutes against the local baseline: some legitimate monitoring agents also re-execute frequently and should be allowlisted by SHA256 or publisher before this is promoted."
-->

```kql
let LookBack = 30d;
// Calibrate these two thresholds against the local baseline before promotion.
let MinExecutions     = 20;
let MaxAvgGapMinutes  = 5.0;
DeviceProcessEvents
| where Timestamp > ago(LookBack)
// Launched by the Task Scheduler service host
| where InitiatingProcessCommandLine has "netsvcs" and InitiatingProcessCommandLine has "Schedule"
| where FileName endswith ".exe"
| where FolderPath matches regex @"(?i)^C:\\(Users\\Public|ProgramData|Program Files \(x86\))\\"
| summarize
    Executions   = count(),
    ActiveHours  = dcount(bin(Timestamp, 1h)),
    ActiveDays   = dcount(bin(Timestamp, 1d)),
    FirstSeen    = min(Timestamp),
    LastSeen     = max(Timestamp),
    Accounts     = make_set(AccountName, 5),
    SampleCmdLine= any(ProcessCommandLine)
    by DeviceName, DeviceId, FileName, FolderPath, SHA256
| extend WindowMinutes  = (LastSeen - FirstSeen) / 1m
| extend AvgGapMinutes  = iff(Executions > 1, todouble(WindowMinutes) / todouble(Executions - 1), todouble(-1))
// The ~60-second re-execution cadence is the campaign signature - the path alone is not
| where Executions >= MinExecutions and AvgGapMinutes > 0.0 and AvgGapMinutes <= MaxAvgGapMinutes
| extend RandomizedName = FolderPath matches regex @"(?i)\\[A-Za-z0-9]{4,10}\\[A-Za-z0-9]{4,10}\.exe$"
    or FolderPath matches regex @"(?i)^C:\\ProgramData\\[A-Za-z0-9]{4,10}\.exe$"
| project DeviceName, DeviceId, FileName, FolderPath, SHA256, RandomizedName,
    Executions, AvgGapMinutes, ActiveHours, ActiveDays, FirstSeen, LastSeen, Accounts, SampleCmdLine
| sort by Executions desc
```

**Expected results:** Effectively zero after the cadence condition is applied. Any surviving row — especially with `RandomizedName == true` and multiple distinct such executables on the **same device** — matches the campaign's multiple-staggered-task pattern. Correlate the SHA256 against Query 1 and the drop path against Query 4.

---

## Query 9: Forged vendor metadata, non-system `svchost`, and campaign DLL side-loading

**Purpose:** Detects the campaign's masquerading and side-loading behavior in one pass: payloads carrying **forged version metadata** (the Philips Speech driver identity, or the tell-tale unfilled build placeholder `ProductName: "TODO: <Product name>"`), the repurposed **Indigo Rose TrueUpdate** runtime and its `_ir_tu2_temp_*` artifacts, **`svchost.exe` executing from a non-system path**, and image loads of the campaign's specific **side-loaded DLLs** (`XPSPLOG.dll`, `UxEnhance64.dll`).  
**Severity:** High  
**MITRE:** T1036.005, T1574.002

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Masqueraded binary or campaign DLL side-load on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A process presented forged vendor version metadata, ran svchost.exe from a non-system path, or loaded a DLL name associated with this campaign's side-loading chain. The leftover build placeholder ProductName TODO is conclusive evidence that version information was fabricated rather than inherited from genuine vendor software, and svchost.exe outside System32 or SysWOW64 is never legitimate. Capture the SHA256 and compare against Query 1, then triage the device for the associated drop paths, persistence tasks, and Defender exclusions."
adaptation_notes: "Union across process and image-load telemetry, so NRT is unavailable. The metadata clauses are high fidelity: a ProductName still containing the TODO build placeholder, and svchost.exe running outside System32 or SysWOW64, are both effectively never legitimate. The side-loaded DLL filenames are generic enough that they could in principle collide with unrelated software, so they are surfaced as a labelled match type rather than treated as conclusive on their own - confirm by hash and by the loading process's folder path. Genuine Philips or Indigo Rose software, if actually deployed in the environment, would match the vendor-metadata clauses and should be allowlisted by signer and install path."
-->

```kql
let SideloadDlls = dynamic(["XPSPLOG.dll", "UxEnhance64.dll"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where
        // Forged vendor metadata / leftover build placeholder
           ProcessVersionInfoCompanyName has "Speech Processing Solutions"
        or ProcessVersionInfoOriginalFileName =~ "PhilipsSpeechDriverConfiguration.exe"
        or ProcessVersionInfoFileDescription has "Philips Speech Driver"
        or ProcessVersionInfoProductName has "TODO:"
        // Repurposed Indigo Rose TrueUpdate runtime
        or ProcessVersionInfoOriginalFileName =~ "tu_rt.exe"
        or ProcessVersionInfoProductName has "TrueUpdate"
        // svchost.exe outside System32 / SysWOW64 is never legitimate
        or (FileName =~ "svchost.exe"
            and FolderPath !contains @"\Windows\System32"
            and FolderPath !contains @"\Windows\SysWOW64")
    | extend MatchType = case(
        ProcessVersionInfoProductName has "TODO:",                          "BuildPlaceholderMetadata",
        ProcessVersionInfoCompanyName has "Speech Processing Solutions",    "PhilipsMasquerade",
        ProcessVersionInfoOriginalFileName =~ "PhilipsSpeechDriverConfiguration.exe", "PhilipsMasquerade",
        ProcessVersionInfoOriginalFileName =~ "tu_rt.exe",                  "TrueUpdateRuntime",
        ProcessVersionInfoProductName has "TrueUpdate",                     "TrueUpdateRuntime",
        "SvchostNonSystemPath")
    | project Timestamp, MatchType, SourceTable = "DeviceProcessEvents", DeviceName, DeviceId, AccountName,
        FileName, FolderPath, SHA256,
        ProcessVersionInfoCompanyName, ProcessVersionInfoProductName,
        ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription,
        InitiatingProcessFileName, InitiatingProcessFolderPath, ReportId),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where FileName in~ (SideloadDlls)
    | extend MatchType = "CampaignSideloadDll"
    | project Timestamp, MatchType, SourceTable = "DeviceImageLoadEvents", DeviceName, DeviceId,
        AccountName = InitiatingProcessAccountName,
        FileName, FolderPath, SHA256,
        ProcessVersionInfoCompanyName = "", ProcessVersionInfoProductName = "",
        ProcessVersionInfoOriginalFileName = "", ProcessVersionInfoFileDescription = "",
        InitiatingProcessFileName, InitiatingProcessFolderPath, ReportId),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName startswith "_ir_tu2_temp_"
    | extend MatchType = "TrueUpdateTempArtifact"
    | project Timestamp, MatchType, SourceTable = "DeviceFileEvents", DeviceName, DeviceId,
        AccountName = InitiatingProcessAccountName,
        FileName, FolderPath, SHA256,
        ProcessVersionInfoCompanyName = "", ProcessVersionInfoProductName = "",
        ProcessVersionInfoOriginalFileName = "", ProcessVersionInfoFileDescription = "",
        InitiatingProcessFileName, InitiatingProcessFolderPath, ReportId)
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. `BuildPlaceholderMetadata` and `SvchostNonSystemPath` are the two conclusive match types — neither has a legitimate explanation. `CampaignSideloadDll` should be confirmed by hash and by the loading process's folder path, since the filenames alone could in principle collide with unrelated software.

---

## General Tuning Notes

1. **Hunt behavior, not names.** Microsoft's own guidance for this campaign is explicit: file names and hashes rotate on every download because the archive is **regenerated server-side per request**. The durable pivots are the `C:\Users\Public\<random>\<random>.exe` and `C:\Program Files (x86)\<random>\<random>.exe` drop shape (Query 4), the forged-metadata masquerade (Query 9), and the stable stage-one and networking payload hashes (Query 1).

2. **`Global\MSI0000` narrows nothing.** Testing during authoring showed the `-Embedding` + `Global\MSI0000` combination matches a substantial volume of entirely ordinary MSI installations, because that mutex string is standard Windows Installer behavior. Query 7 therefore requires the **world-writable payload path** as the discriminator and keeps `Global\MSI0000` only as a context column. Do not reintroduce it as a filter and assume specificity.

3. **The scheduled-task pattern needs the cadence.** The path-only form of the disguised-task pattern — Task Scheduler launching an executable from `ProgramData` / `Users\Public` / `Program Files (x86)` — matched **many thousands** of legitimate agent, updater, and management rows in testing and is unusable as a detection on its own. Adding the campaign's actual signature (high execution count with a very short average inter-execution gap) reduced that same population to zero noise. Calibrate `MinExecutions` and `MaxAvgGapMinutes` locally, and allowlist legitimate high-frequency monitoring agents by hash or publisher.

4. **Require destructive verbs, not just names.** Matching the Windows Update service names (`wuauserv`, `UsoSvc`, `uhssvc`, `WaaSMedicSvc`) or the `SoftwareDistribution` folder on their own produces a large benign baseline from routine servicing. Query 6 requires `sc config … disabled`, `net stop`, `rename`, or an `erase`/`rmdir` verb alongside them, which is what makes it deployable.

5. **Enforce Tamper Protection.** It blocks Defender exclusion and registry writes **even when the payload runs as SYSTEM**, directly countering the throwaway SYSTEM scheduled-task technique this campaign depends on. Query 5 detects the attempt; Tamper Protection prevents the outcome.

6. **A blocked C2 connection is not an all-clear.** The article documents the dedicated C2 tier being intermittently unreachable while the same payloads still completed TLS connections to cloud object storage. Query 2 deliberately surfaces `ConnectionFailed` and `FirewallOutboundConnectionBlocked` dispositions — treat them as evidence of a live implant.

7. **ASN and nameserver are pivots, not blocklists.** The lure domains resolve into two shared commercial hosting/DNS procurement channels carrying substantial unrelated tenancy. ASN-level analysis surfaces relationships that netblock and geography-based grouping miss, but blocking at ASN or nameserver level would break large volumes of legitimate traffic.

8. **Never block the cloud storage provider.** The staging buckets are on legitimate Alibaba Cloud OSS. Query 3 matches the **specific bucket hostnames**; broadening to the provider domain would be both noisy and harmful.

9. **Correlate download referrers.** `FileOriginUrl` and `FileOriginReferrerUrl` in `DeviceFileEvents` tie a downloaded archive to both the impersonation page that served it and the delivery host. This relationship survives individual domain rotation and is the best way to discover new lure-to-delivery pairs as the published list decays.

10. **Attack disruption is containment, not eradication.** Microsoft observed attack disruption containing affected devices and accounts, but notes explicitly that **full eradication of persistence still required responder action**. After containment, enumerate and remove the disguised scheduled tasks, restore disabled update services and renamed update DLLs, remove attacker `icacls` ACL changes, clear malicious Defender exclusions, and check the code-integrity store for the malicious WDAC policy.

11. **CD-readiness summary.** **Queries 1, 2, 3, 4, 5, 6, 7, and 9 are `cd_ready: true`**, with **Queries 2, 3, 5, 6, and 7 NRT-eligible** as single-table queries. **Query 5 (Defender exclusion tampering) and Query 6 (recovery inhibition) are the highest-value promotions** — both are high fidelity, early or decisive in the kill chain, and independent of rotating infrastructure. **Query 8 is `cd_ready: false`** pending local calibration of its cadence thresholds. All nine queries were authored and executed against live Microsoft Defender Advanced Hunting telemetry during development, and the tuning findings in notes 2, 3, and 4 come directly from that testing.

---

## References

- Microsoft Threat Intelligence — [Counterfeit installers to system compromise: Tracking a deceptive software download campaign (2026-09-01)](https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/)
- MITRE ATT&CK — [T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- MITRE ATT&CK — [T1218.007 System Binary Proxy Execution: Msiexec](https://attack.mitre.org/techniques/T1218/007/)
- MITRE ATT&CK — [T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- MITRE ATT&CK — [T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- MITRE ATT&CK — [T1036.005 Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- MITRE ATT&CK — [T1574.002 Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- MITRE ATT&CK — [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- MITRE ATT&CK — [T1489 Service Stop](https://attack.mitre.org/techniques/T1489/)
- MITRE ATT&CK — [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- Microsoft Learn — [Protect security settings with Tamper Protection](https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- Microsoft Learn — [Configure block at first sight / cloud-delivered protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus)
- Companion files: [`queries/threat-intelligence/2026-08/macos_clickfix_fingerprinting_gate.md`](../2026-08/macos_clickfix_fingerprinting_gate.md), [`queries/endpoint/rare_process_chains.md`](../../endpoint/rare_process_chains.md)
