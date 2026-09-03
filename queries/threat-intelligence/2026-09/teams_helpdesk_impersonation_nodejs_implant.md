# Teams Helpdesk Impersonation — Remote Session to MSI Loader, Node.js Implant, and WinRM Lateral Movement — Threat Hunts

**Created:** 2026-09-02  
**Platform:** Microsoft Defender XDR  
**Tables:** CloudAppEvents, DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceImageLoadEvents  
**Keywords:** Teams phishing, spearphishing via service, external tenant chat, helpdesk impersonation, IT support impersonation, vishing, voice phishing, Quick Assist, RMM abuse, remote support tool, remote monitoring and management, request control, screen share, MSI loader, msiexec silent install, Azure Blob Storage payload, portable Node.js, node.exe, renamed node, LocalAppData loader, nonstandard extension, JavaScript implant, obfuscated JavaScript, EdgeUpdate persistence, Run key, Startup folder, WScript, rundll32, DLL export, screen capture, CopyFromScreen, ToBase64String, ADSI enumeration, domain admin discovery, user description harvesting, WinRM, 5985, wsman, lateral movement, domain controller, certificate authority, hands-on-keyboard, Ethereum smart contract C2, blockchain C2, long polling, cloudapp.azure.com  
**MITRE:** T1566.003, T1059.001, T1059.007, T1218.007, T1218.011, T1036, T1497.001, T1082, T1016, T1087.002, T1018, T1518.001, T1113, T1071.001, T1105, T1021.006, T1547.001  
**Domains:** endpoint, cloud  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Impersonating IT support: how threat actors turn a remote session into enterprise-wide access (2026-09-02)](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)

---

## Threat Overview

Microsoft Threat Intelligence observed a **human-operated intrusion campaign** that abuses **Microsoft Teams external collaboration** to impersonate IT or helpdesk personnel and socially engineer users into granting an **interactive remote session**. A threat actor operating from a separate tenant initiates a Teams chat or call under a pretext such as "Microsoft Security Update," "Spam Filter Update," or "Account Verification," and persuades the user to override Teams' external-tenant warnings — approving a *request control* prompt during a screen-share, or opening a remote-assistance tool and reading back the connection code. **Vishing is sometimes layered** to increase compliance and to keep malicious instructions and URLs out of the chat logs entirely.

This is **not a Teams vulnerability**. The platform surfaces external-tenant labels, Accept/Block prompts, message previews, and phishing indicators; the attack chain depends entirely on convincing the user to ignore them.

Once remote control is established, the operator runs **PowerShell to download a malicious MSI from attacker-controlled cloud storage** (Azure Blob Storage endpoints named to look like update infrastructure) and installs it silently with **`msiexec /qn`**. The MSI is disguised with helpdesk-themed names such as *devfix* or *Hotfix*. It stages a **script-based loader plus a separate encrypted implant file under `LocalAppData`**, then retrieves a **legitimate, signed portable Node.js runtime from the official distribution** and extracts it into a randomly named directory. A deferred MSI custom action launches hidden bootstrap code via **PowerShell, `cmd.exe`, or WScript**, and Node.js — sometimes a **renamed copy** — decrypts the high-entropy payload and executes the resulting JavaScript either through **standard input** or from a temporary `.js` file. Loaders and encrypted payloads use **nonstandard extensions** (`.tmp`, `.ini`, `.dat`, `.bin`, `.cfg`) specifically to evade controls that key on script extensions and unsigned binaries.

Per-user persistence is established under the name **`EdgeUpdate`** — either an `HKEY_CURRENT_USER\...\Run` value or a **Startup-folder shortcut** — launching the Node.js loader from `LocalAppData` at sign-in.

The implant communicates over **randomized HTTPS long-polling**, treating C2 responses as JavaScript and executing them dynamically with full access to Node.js module loading, process execution, and the file system. Observed tasking performed **sandbox/AV discovery** (display adapter name, `SecurityCenter2` antivirus enumeration), **periodic Base64-encoded desktop screen capture**, **ADSI-based Active Directory reconnaissance** (domain accounts, Windows Server computer objects with reachability probing, and harvesting of user `description` attributes), and **follow-on DLL execution via `rundll32`** invoking an exported function (`open`) with a per-execution token. The analyzed implants also contained **dormant logic to retrieve an updated C2 URL from an Ethereum smart contract**; this was disabled in recovered builds, which used a hard-coded fallback instead.

The intrusion culminates in **WinRM (TCP 5985) lateral movement** from a non-administrative application context toward dozens of domain-joined systems across multiple regions — file, database, and application servers, and critically **domain controllers and certificate authorities**. Targeting identity infrastructure at this stage is a hallmark of intrusions preceding large-scale data theft, extortion, or ransomware. The campaign relies almost entirely on **legitimate tooling** — Teams, remote support software, Windows Installer, Node.js, and native administrative protocols — so it blends into expected enterprise operations at nearly every stage.

### TTP Summary

| Capability | TTP |
|---|---|
| Initial access | External-tenant Teams chat/call impersonating IT or helpdesk; user coaxed into granting remote control (T1566.003) |
| Interactive access | Legitimate RMM / remote-support tooling driven by the operator after user consent |
| Delivery | PowerShell downloads a helpdesk-themed MSI (*devfix*, *Hotfix*) from attacker-controlled Azure Blob Storage (T1105, T1036) |
| Execution — installer | Silent install via `msiexec /qn`, suppressing all installer UI (T1218.007) |
| Execution — runtime | Legitimate signed **portable Node.js** retrieved from the official distribution and used to run an obfuscated JavaScript implant (T1059.007, T1105) |
| Execution — bootstrap | Deferred MSI custom action launches hidden PowerShell / `cmd.exe` / **WScript** bootstrap (T1059.001) |
| Defense evasion | Nonstandard loader/payload extensions (`.tmp`, `.ini`, `.dat`, `.bin`, `.cfg`), **renamed Node.js copies**, JavaScript supplied via **stdin**, signed-runtime execution (T1036) |
| Persistence | `EdgeUpdate`-named `HKCU\...\Run` value **or** Startup-folder shortcut launching the `LocalAppData` Node.js loader (T1547.001) |
| Sandbox evasion | Display-adapter name and installed-AV queries via `SecurityCenter2` (T1497.001, T1518.001) |
| Discovery | `systeminfo`, MachineGuid, disk inventory; `net session`/`net use`; `net user /domain`; ADSI server + user enumeration with `description` harvesting and CIM reachability probing (T1082, T1016, T1087.002, T1018) |
| Collection | Periodic desktop screen capture, resized, Base64-encoded, written to a temp file for exfiltration (T1113) |
| Command and control | Randomized **HTTPS long-polling**; responses executed as JavaScript. Dormant Ethereum smart-contract C2-URL lookup (T1071.001) |
| Follow-on execution | `rundll32` loading operator-supplied DLLs by exported function (`open`) with a per-execution token (T1218.011) |
| Lateral movement | **WinRM over TCP 5985** from a user-context process toward domain controllers and certificate authorities (T1021.006) |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **Node.js is legitimate and extremely common on developer endpoints** | Never alert on `node.exe` alone. Require the campaign-specific combination: launched by **WScript/cmd/PowerShell**, executing from **`LocalAppData`**, against a **nonstandard-extension** loader or via **stdin**. Baseline developer estates before promoting any Node.js query. |
| **Renamed Node.js copies evade `FileName =~ "node.exe"`** | The article explicitly notes renamed copies whose *file metadata* still identifies them as Node.js. Match on `ProcessVersionInfoOriginalFileName` / `ProcessVersionInfoProductName` **in addition to** `FileName`, or the core execution hunt will miss the evasive variant. |
| **`blob.core.windows.net` is legitimate Microsoft infrastructure** | Only the specific published subdomains are indicators. Never pattern-match the parent domain — hunt the exact hostnames, and pivot on *the process that fetched them* rather than the domain family. |
| **The C2 domains are `*.cloudapp.azure.com`** | Same trap: `cloudapp.azure.com` is legitimate Azure-hosted service space with substantial benign use. Only the exact published labels are indicators. |
| **`msiexec /qn` is standard enterprise software deployment** | Silent MSI installs are what management tooling does all day. The signal is `/qn` **combined with** a source path under `Downloads`/`AppData`/`Temp`, and a parent chain tracing to an interactive `explorer.exe` → PowerShell rather than to a management agent. Exclude your deployment tooling first. |
| **WinRM 5985 is normal from management workstations and agents** | The article's signal is WinRM initiated from a **user-context, non-administrative process**. Allowlist authorized management servers/workstations and management-agent parent processes, then look at what remains — especially fan-out to many hosts, and any connection to a domain controller or certificate authority. |
| **`rundll32` has abundant legitimate use** | Require a DLL path in a **user-writable directory** plus an unusual export name and an opaque token argument. `rundll32` alone is pure noise. |
| **Teams `RawEventData` is a large JSON blob** | Parse once with `extend RD = parse_json(tostring(RawEventData))`, then read all fields from `RD`. Never use `tostring(RawEventData) has "..."` as a filter — it forces full serialization of every row on a very high-volume table. |
| **`IsExternalUser` alone is not malicious** | Legitimate cross-tenant collaboration with partners, vendors, and customers is routine. Prioritize **first-ever contact** from an unfamiliar tenant that is closely followed by remote-support tooling or PowerShell activity on the recipient's device — the *correlation*, not the external flag, is the detection. |
| **Vishing keeps the payload out of the chat logs** | When the operator talks the victim through the steps by voice, there will be **no malicious URL or command in Teams telemetry at all**. Do not treat clean Teams message content as exculpatory; pivot to endpoint telemetry (Queries 4–9) on the recipient's device around the contact time. |
| **`CloudAppEvents` is very high volume** | Filter `Timestamp` → `ActionType` (most selective) → identity. `AccountId` is a GUID, not a UPN — use `AccountObjectId` for indexed identity lookups. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [External-tenant Teams contact — first-contact triage](#query-1-external-tenant-teams-contact--first-contact-triage) | Triage | `CloudAppEvents` |
| 2 | [Campaign file-hash sweep (direct IOC)](#query-2-campaign-file-hash-sweep-direct-ioc) | Investigation | `DeviceFileEvents` + multi |
| 3 | [Delivery and C2 infrastructure sweep (direct IOC)](#query-3-delivery-and-c2-infrastructure-sweep-direct-ioc) | Investigation | `DeviceNetworkEvents` |
| 4 | [Remote session delivery chain — PowerShell fetches an MSI, `msiexec...](#query-4-remote-session-delivery-chain--powershell-fetches-an-msi-msiexec-installs-it-silently) | Investigation | `DeviceFileEvents` + `DeviceProcessEvents` |
| 5 | [Node.js executing a nonstandard-extension loader from `LocalAppData`](#query-5-nodejs-executing-a-nonstandard-extension-loader-from-localappdata) | Investigation | `DeviceProcessEvents` |
| 6 | [`EdgeUpdate`-themed per-user persistence launching a `LocalAppData`...](#query-6-edgeupdate-themed-per-user-persistence-launching-a-localappdata-runtime) | Investigation | `DeviceFileEvents` + `DeviceRegistryEvents` |
| 7 | [Operator screen capture — hidden .NET desktop capture Base64-encode...](#query-7-operator-screen-capture--hidden-net-desktop-capture-base64-encoded-to-a-temp-file) | Triage | `DeviceProcessEvents` |
| 8 | [`rundll32` executing a DLL from a user-writable path with an export...](#query-8-rundll32-executing-a-dll-from-a-user-writable-path-with-an-export-and-token-argument) | Investigation | `DeviceProcessEvents` |
| 9 | [WinRM lateral movement from a user-context process](#query-9-winrm-lateral-movement-from-a-user-context-process) | Investigation | `DeviceNetworkEvents` |


## IOC Reference

> Published indicators from the Microsoft Threat Intelligence article. Microsoft generalized environment-specific values (paths, hostnames, account names) in its reporting, so **behavioral hunts (Queries 4–9) carry more durable value than the direct-match sweeps**. IOCs rot — refresh against current Microsoft Threat Intelligence before relying on Queries 2 and 3. Domains are defanged below; the queries use plain forms.

### File indicators (SHA-256)

| SHA-256 | Description |
|---|---|
| 4cfdcae6dd1d6d98b870c8f0654d504f2bf10479a117dc297de789c249dc389d | Malicious MSI loader package (silent `msiexec` install) |
| a4d145a6347e47d40b3ca48af5c6dba01bf019d0110e31a44bb70fc77d1d1676 | Malicious MSI loader package |
| cc6d0f3f47afeba018173604e34f527e8413d3a54ffb35caed529bff49055ec5 | Malicious MSI loader package |
| 0d2fc28af246f62f27e49207d1f64e236ad9ea029412b27877d1ae6c098e86e3 | Second-stage DLL (`rundll32`-loaded module) |
| 69e10e0cb7bb2137ebea12971adb02c662cf5543a4f8c9530812bcbf7b183a23 | Second-stage DLL (`rundll32`-loaded module) |
| a135fe4df18c711097e69b4f27ea32a74a955160bf2fb12da841f21866d95d87 | Second-stage DLL (`rundll32`-loaded module) |

### Payload delivery infrastructure

| Indicator | Type | Description |
|---|---|---|
| update1n5[.]blob.core.windows.net | Domain | Azure Blob Storage endpoint hosting the malicious MSI loader |
| update1n6[.]blob.core.windows.net | Domain | Azure Blob Storage endpoint hosting the malicious MSI loader |
| update1n7[.]blob.core.windows.net | Domain | Azure Blob Storage endpoint hosting the malicious MSI loader |
| update1n9[.]blob.core.windows.net | Domain | Azure Blob Storage endpoint hosting the malicious MSI loader |
| updatetmp[.]blob.core.windows.net | Domain | Azure Blob Storage endpoint hosting the malicious MSI loader |

### Command-and-control infrastructure

| Indicator | Type | Description |
|---|---|---|
| synctimes[.]australiaeast[.]cloudapp[.]azure[.]com | Domain | Hard-coded fallback C2; also the latest URL stored in the associated Ethereum contract |
| webwether[.]eastus[.]cloudapp[.]azure[.]com | Domain | Earlier URL stored in the Ethereum contract |
| dssdfvsdfvsdfvsdgbfbdvdzv[.]org | Domain | Earlier URL stored briefly in the Ethereum contract |

### Behavioral indicators (generalized by Microsoft — hunt these, not literals)

| Indicator | Type | Description |
|---|---|---|
| `EdgeUpdate` | Persistence name | Run-key value name **and** Startup-folder shortcut name used by both observed persistence variants |
| `devfix`, `Hotfix` | Filename theme | Helpdesk/update-themed MSI package names |
| `.tmp`, `.ini`, `.dat`, `.bin`, `.cfg` | Extensions | Nonstandard extensions on the staged loader and encrypted implant |
| `LocalAppData\<random>\` | Path pattern | Portable Node.js runtime and loader staging directory |
| `open` + token argument | `rundll32` export | Follow-on DLLs invoked by exported function `open` with a per-execution token |
| TCP 5985 `/wsman` | Network | WinRM lateral movement endpoint |

---

## Query 1: External-tenant Teams contact — first-contact triage

**Purpose:** Surfaces Teams chats, messages, and member additions involving an **external** user, decomposed into the participants and thread ID so an analyst can pivot to messages, calls, and URLs on the same thread. This is the campaign's entry point (T1566.003). Adapted from Microsoft's published hunting guidance, with the `RawEventData` parse corrected for Advanced Hunting and the `ActionType` filter placed before the identity filter for performance on this very high-volume table.  
**Severity:** Low  
**MITRE:** T1566.003

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Triage/hunting query, not detection-ready. External Teams collaboration is routine and legitimate in most tenants, so IsExternalUser alone produces unacceptable noise as a standalone alert. The detection-grade signal is correlation - first-ever external contact followed on the same user's device by remote-support tooling, PowerShell, or msiexec activity (Queries 4-9). Promotion path: maintain an allowlist of known partner tenant IDs, add a first-seen condition on the external OrganizationId, and require a temporally-correlated endpoint event. Note also that when the operator uses voice phishing, no malicious content appears in Teams telemetry at all - a clean result here does not exclude the campaign."
-->

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Teams"
| where ActionType in~ ("ChatCreated", "MessageSent", "MemberAdded")
| where IsExternalUser == true
// Parse the RawEventData blob exactly once - never filter with tostring(RawEventData) has "..."
| extend RD = parse_json(tostring(RawEventData))
| extend
    ChatThreadId      = tostring(RD.ChatThreadId),
    CommunicationType = tostring(RD.CommunicationType),
    MemberCount       = array_length(RD.Members),
    InitiatorUpn      = tostring(RD.Members[0].UPN),
    InitiatorOrgId    = tostring(RD.Members[0].OrganizationId),
    RecipientUpn      = tostring(RD.Members[1].UPN),
    RecipientOrgId    = tostring(RD.Members[1].OrganizationId)
| project Timestamp, ActionType, CommunicationType, ChatThreadId, MemberCount,
    InitiatorUpn, InitiatorOrgId, RecipientUpn, RecipientOrgId,
    AccountDisplayName, AccountObjectId, IsExternalUser, IsImpersonated,
    IPAddress, CountryCode, ISP, ReportId
| sort by Timestamp desc
```

**Expected results:** A routine baseline of legitimate partner, vendor, and customer collaboration in most tenants. Triage on **novelty and tempo**: an `InitiatorOrgId` never previously seen, a display name asserting an IT/helpdesk/support identity, and — decisively — endpoint activity on `RecipientUpn`'s device within minutes to hours (Queries 4–9). Capture `ChatThreadId` to pivot into `MessageEvents`, `CallActivityEvents`, and `MessageUrlInfo` for the same thread.

---

## Query 2: Campaign file-hash sweep (direct IOC)

**Purpose:** Direct SHA-256 match for the three published MSI loader packages and three second-stage DLLs, across process execution, file write, and image-load telemetry. Image-load coverage matters here because the second-stage DLLs are `rundll32`-loaded modules that may never appear as a process image. In an unaffected environment this returns 0; any hit is a confirmed-malware finding requiring immediate device isolation and credential rotation.  
**Severity:** High  
**MITRE:** T1218.007, T1218.011, T1105

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Teams-helpdesk-impersonation campaign binary on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A file hash published as part of the Teams helpdesk-impersonation MSI loader / Node.js implant campaign was observed. Treat the device as compromised by an interactive external operator. Isolate the device, identify the delivering process chain (expect PowerShell under a remote-support tool), and hunt the full chain with Queries 4-9. Because this campaign reaches WinRM lateral movement toward domain controllers and certificate authorities, assume network-level access was obtained and prioritize rotating every credential accessible from the host - including domain admin accounts if the host was domain-joined."
adaptation_notes: "Direct published IOCs - highest fidelity in this file. Uses a union across three device tables, which disqualifies NRT; 1H scheduling is appropriate. Hash-based coverage decays as the operator rebuilds payloads, so pair with the behavioral hunts (Queries 4-9) which survive rebuilds, and refresh the hash list from current Microsoft Threat Intelligence."
-->

```kql
let CampaignSha256 = dynamic([
  "4cfdcae6dd1d6d98b870c8f0654d504f2bf10479a117dc297de789c249dc389d",  // MSI loader package
  "a4d145a6347e47d40b3ca48af5c6dba01bf019d0110e31a44bb70fc77d1d1676",  // MSI loader package
  "cc6d0f3f47afeba018173604e34f527e8413d3a54ffb35caed529bff49055ec5",  // MSI loader package
  "0d2fc28af246f62f27e49207d1f64e236ad9ea029412b27877d1ae6c098e86e3",  // second-stage DLL
  "69e10e0cb7bb2137ebea12971adb02c662cf5543a4f8c9530812bcbf7b183a23",  // second-stage DLL
  "a135fe4df18c711097e69b4f27ea32a74a955160bf2fb12da841f21866d95d87"]);// second-stage DLL
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (CampaignSha256) or InitiatingProcessSHA256 in~ (CampaignSha256)
    | project Timestamp, SourceTable = "DeviceProcessEvents", DeviceName, DeviceId, ActionType,
        FileName, FolderPath, SHA256, AccountName,
        InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (CampaignSha256) or InitiatingProcessSHA256 in~ (CampaignSha256)
    | project Timestamp, SourceTable = "DeviceFileEvents", DeviceName, DeviceId, ActionType,
        FileName, FolderPath, SHA256, AccountName = InitiatingProcessAccountName,
        InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (CampaignSha256)
    | project Timestamp, SourceTable = "DeviceImageLoadEvents", DeviceName, DeviceId, ActionType,
        FileName, FolderPath, SHA256, AccountName = InitiatingProcessAccountName,
        InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId)
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Any match is a high-confidence compromise indicator — escalate immediately rather than tuning.

---

## Query 3: Delivery and C2 infrastructure sweep (direct IOC)

**Purpose:** Direct-match sweep for the five Azure Blob Storage MSI-hosting endpoints and the three C2 domains (including the hard-coded fallback and the URLs previously published to the actor's Ethereum contract). Splits results into `PayloadDelivery` and `CommandAndControl` so the intrusion stage is immediately obvious: a delivery hit alone may mean a download was attempted, while a C2 hit means the implant is running.  
**Severity:** High  
**MITRE:** T1105, T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "CommandAndControl"
title: "Teams-helpdesk campaign infrastructure contacted from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An endpoint contacted published payload-delivery or command-and-control infrastructure for the Teams helpdesk-impersonation campaign. Identify the initiating process: a delivery hit is typically PowerShell fetching the MSI during an operator-driven remote session, while a C2 hit means the Node.js implant is already executing. Isolate the device, pull the full process chain (Queries 4-9), and rotate credentials accessible from the host. Match only the exact hostnames - the parent domains blob.core.windows.net and cloudapp.azure.com are legitimate Microsoft infrastructure and must never be pattern-matched."
adaptation_notes: "Single-table DeviceNetworkEvents with no joins - NRT eligible. Direct published IOCs, high fidelity. Actor-controlled cloud-hosted infrastructure is cheap to rotate so this list decays quickly; refresh from current threat intelligence and rely on the behavioral hunts for durability. The exact-hostname matching is deliberate and must be preserved - broadening to the parent Azure domains would generate substantial false positives against legitimate Microsoft services."
-->

```kql
// Exact hostnames only. blob.core.windows.net and cloudapp.azure.com are legitimate
// Microsoft infrastructure - never broaden these matches to the parent domains.
let DeliveryHosts = dynamic([
  "update1n5.blob.core.windows.net",
  "update1n6.blob.core.windows.net",
  "update1n7.blob.core.windows.net",
  "update1n9.blob.core.windows.net",
  "updatetmp.blob.core.windows.net"]);
let C2Hosts = dynamic([
  "synctimes.australiaeast.cloudapp.azure.com",
  "webwether.eastus.cloudapp.azure.com",
  "dssdfvsdfvsdfvsdgbfbdvdzv.org"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (DeliveryHosts) or RemoteUrl has_any (C2Hosts)
| extend Stage = iff(RemoteUrl has_any (DeliveryHosts), "PayloadDelivery", "CommandAndControl")
| project Timestamp, Stage, DeviceName, DeviceId, ActionType, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, InitiatingProcessSHA256, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. A `PayloadDelivery` hit initiated by `powershell.exe` under an interactive parent is the campaign's Stage-2 signature; a `CommandAndControl` hit initiated by `node.exe` (or a renamed copy) confirms an active implant.

---

## Query 4: Remote session delivery chain — PowerShell fetches an MSI, `msiexec` installs it silently

**Purpose:** Detects the campaign's Stage-2 delivery: within an operator-driven remote session, PowerShell writes an `.msi` into a user-writable path (`Downloads`, `AppData`, `Temp`), which is then installed silently with `msiexec /qn`. Correlates the file write and the silent install on the same device within a short window so that neither half — both individually common — generates noise on its own.  
**Severity:** High  
**MITRE:** T1059.001, T1218.007, T1105, T1036

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Requires per-environment tuning before promotion. Silent MSI installation from a user-writable path is exactly what legitimate software-deployment and management tooling does, so the deployment agents in use must be allowlisted on InitiatingProcessFileName and the MSI source paths of sanctioned packaging systems excluded first. The durable, high-signal discriminator is the parent chain - an interactive explorer.exe or a remote-support tool leading to PowerShell, rather than a management agent - so encode that allowlist before considering a scheduled rule. Uses a join across DeviceFileEvents and DeviceProcessEvents, which disqualifies NRT."
-->

```kql
let LookBack = 30d;
let MsiWrites =
    DeviceFileEvents
    | where Timestamp > ago(LookBack)
    | where FileName endswith ".msi"
    | where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe")
    | where FolderPath has_any (@"\Downloads\", @"\AppData\", @"\Temp\", @"\Public\")
    | project MsiWriteTime = Timestamp, DeviceName, DeviceId, MsiFileName = FileName,
        MsiFolderPath = FolderPath, MsiSha256 = SHA256,
        WriterProcess = InitiatingProcessFileName,
        WriterCommandLine = InitiatingProcessCommandLine,
        WriterParent = InitiatingProcessParentFileName,
        WriterAccount = InitiatingProcessAccountName;
let SilentInstalls =
    DeviceProcessEvents
    | where Timestamp > ago(LookBack)
    | where FileName =~ "msiexec.exe" or InitiatingProcessFileName =~ "msiexec.exe"
    | where ProcessCommandLine has ".msi"
    | where ProcessCommandLine has_any ("/qn", "/quiet", "-qn", "/i")
    | project InstallTime = Timestamp, DeviceName, InstallCommandLine = ProcessCommandLine,
        InstallParent = InitiatingProcessFileName, InstallAccount = AccountName;
MsiWrites
| join kind=inner SilentInstalls on DeviceName
// Silent install follows the download closely within the same operator-driven remote session
| where InstallTime between (MsiWriteTime .. (MsiWriteTime + 30m))
| extend HelpdeskThemedName = MsiFileName has_any ("devfix", "hotfix", "fix", "update", "patch", "security")
| project MsiWriteTime, InstallTime, DeviceName, DeviceId, MsiFileName, MsiFolderPath, MsiSha256,
    HelpdeskThemedName, WriterProcess, WriterParent, WriterAccount, WriterCommandLine,
    InstallParent, InstallAccount, InstallCommandLine
| sort by MsiWriteTime desc
```

**Expected results:** Managed environments will surface legitimate deployment activity — allowlist those agents first. The campaign pattern is a **helpdesk-themed MSI name** (`HelpdeskThemedName == true`), a writer parent of `explorer.exe` or a remote-support executable rather than a management agent, and a source path under the interactive user's profile.

---

## Query 5: Node.js executing a nonstandard-extension loader from `LocalAppData`

**Purpose:** The campaign's **most durable execution signature**. A portable Node.js runtime — or a **renamed copy** whose file metadata still identifies it as Node.js — executes a staged loader from `LocalAppData`, where the loader and encrypted implant carry nonstandard extensions (`.tmp`, `.ini`, `.dat`, `.bin`, `.cfg`) or are supplied through **standard input** rather than as a `.js` file. Matching on version metadata in addition to filename is what catches the renamed-runtime variant that a `FileName =~ "node.exe"` filter alone would miss.  
**Severity:** High  
**MITRE:** T1059.007, T1036, T1105

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Requires baselining on developer estates before promotion, and was NOT fidelity-validated during authoring - the development environment had no Node.js execution telemetry at all, so the query executed successfully but had no positive or negative cases to tune against. Node.js is ubiquitous on engineering endpoints and legitimately runs from user-writable paths - nvm, Volta, fnm, Yarn/pnpm, VS Code extension hosts, and Electron applications all produce superficially similar telemetry. Tune by allowlisting sanctioned Node version managers and IDE-spawned processes on InitiatingProcessFolderPath, then require the script-host parent (wscript.exe / cscript.exe / cmd.exe / powershell.exe) which is the genuinely anomalous element - a developer's Node process is parented by an IDE, terminal, or package manager, not by WScript. Syntactically validated and executed only; measure the local baseline before considering any scheduled rule."
-->

```kql
let NonStandardExt = dynamic([".tmp", ".ini", ".dat", ".bin", ".cfg", ".log", ".txt"]);
let ScriptHosts    = dynamic(["wscript.exe", "cscript.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "msiexec.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
// Match the real runtime AND renamed copies, which retain Node.js file metadata
| where FileName =~ "node.exe"
    or ProcessVersionInfoOriginalFileName =~ "node.exe"
    or ProcessVersionInfoProductName has "Node.js"
    or ProcessVersionInfoFileDescription has "Node.js"
| extend RenamedRuntime = FileName !~ "node.exe"
| extend StagedFromLocalAppData = FolderPath has @"\AppData\Local\"
    or ProcessCommandLine has @"\AppData\Local\"
| extend NonStandardLoader = ProcessCommandLine has_any (NonStandardExt)
| extend StdinExecution = ProcessCommandLine has_any (" -e ", " --eval", " -p ", "--input-type")
    and not(ProcessCommandLine has ".js")
| extend ScriptHostParent = InitiatingProcessFileName in~ (ScriptHosts)
// Require the campaign combination, not Node.js on its own
| where StagedFromLocalAppData and (NonStandardLoader or StdinExecution or RenamedRuntime)
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, FolderPath, SHA256,
    RenamedRuntime, NonStandardLoader, StdinExecution, ScriptHostParent,
    ProcessVersionInfoOriginalFileName, ProcessVersionInfoProductName,
    ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessCommandLine, InitiatingProcessParentFileName, ReportId
| sort by Timestamp desc
```

**Expected results:** On developer-heavy estates expect legitimate Node.js tooling to appear; allowlist version managers and IDE-spawned processes. The decisive campaign combination is `ScriptHostParent == true` (especially **WScript**) together with `NonStandardLoader` or `StdinExecution` — a legitimate Node process is parented by an IDE, terminal, or package manager, never by `wscript.exe`.

---

## Query 6: `EdgeUpdate`-themed per-user persistence launching a `LocalAppData` runtime

**Purpose:** Detects both observed persistence variants — an `HKEY_CURRENT_USER\...\Run` value and a Startup-folder shortcut, both named **`EdgeUpdate`** — that launch the staged Node.js loader from `LocalAppData` at sign-in. Unions registry and file telemetry so either variant is caught, and deliberately flags *any* Run-key or Startup entry pointing into `LocalAppData` so that a renamed persistence entry is still surfaced.  
**Severity:** High  
**MITRE:** T1547.001, T1036

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Update-themed user persistence launching a LocalAppData runtime on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A per-user Run key value or Startup-folder shortcut was created that launches an executable from LocalAppData under an update-themed name - the persistence mechanism used by the Teams helpdesk-impersonation Node.js implant. Inspect the target path and its signature, and check whether it is a portable or renamed Node.js runtime. Genuine Microsoft Edge updates install to Program Files and run as a service or scheduled task, never as an HKCU Run value pointing into LocalAppData. Pivot to Query 5 for the execution chain and Query 3 for C2 contact, then isolate and rotate credentials if confirmed."
adaptation_notes: "Union across DeviceRegistryEvents and DeviceFileEvents, so NRT is not available. Reasonably high fidelity because the combination of an update-themed persistence name with a LocalAppData target is anomalous - legitimate updaters do not persist this way. Expect some benign hits from user-scoped auto-updating applications (Teams, Slack, Discord, Zoom and similar Electron apps legitimately install into LocalAppData); allowlist those specific known-good target paths rather than removing the LocalAppData condition, which is the core of the detection."
-->

```kql
let UpdateThemedNames = dynamic(["edgeupdate", "edge update", "msedgeupdate", "googleupdate", "update", "hotfix", "devfix"]);
union isfuzzy=true
  (DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType in~ ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
    | where RegistryValueData has @"\AppData\Local\"
    | project Timestamp, Mechanism = "HKCU Run key", DeviceName, DeviceId,
        AccountName = InitiatingProcessAccountName,
        PersistenceName = RegistryValueName, Target = RegistryValueData,
        RegistryKey, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in~ ("FileCreated", "FileModified", "FileRenamed")
    | where FolderPath has @"\Start Menu\Programs\Startup"
    | project Timestamp, Mechanism = "Startup folder", DeviceName, DeviceId,
        AccountName = InitiatingProcessAccountName,
        PersistenceName = FileName, Target = FolderPath,
        RegistryKey = "", InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId)
| extend UpdateThemed = tolower(PersistenceName) has_any (UpdateThemedNames)
| extend NodeRuntimeTarget = Target has_any ("node.exe", "wscript", ".js")
| sort by Timestamp desc
```

**Expected results:** Some benign volume from user-scoped auto-updating applications that legitimately install into `LocalAppData`. Prioritize rows where `UpdateThemed == true` — a Run value literally named `EdgeUpdate` pointing into `LocalAppData` is the campaign's exact signature, and genuine Microsoft Edge updates never persist that way.

---

## Query 7: Operator screen capture — hidden .NET desktop capture Base64-encoded to a temp file

**Purpose:** Detects the campaign's collection stage: C2-issued JavaScript tasking spawns short-lived `cmd.exe`/`powershell.exe` under the Node.js implant to capture the desktop with `System.Drawing`/`CopyFromScreen`, resize it, Base64-encode it, and write it to a temp file for exfiltration. Adapted from Microsoft's published query, with the Node.js parent condition relaxed to also catch the renamed-runtime variant and the .NET capture API combination retained as the high-fidelity core.  
**Severity:** High  
**MITRE:** T1113, T1059.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Collection"
title: "Scripted desktop screen capture encoded for exfiltration on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A process invoked the .NET desktop screen-capture APIs and Base64-encoded the result to a file - the collection behavior used by the Teams helpdesk-impersonation Node.js implant to periodically exfiltrate the victim's screen. Identify the parent process; a node.exe or renamed-Node parent confirms the campaign. Determine what was on screen during the capture window and treat any credentials, tokens, or sensitive data visible as exposed. Isolate the device, hunt the full chain with Queries 3-9, and rotate credentials accessible from the host."
adaptation_notes: "Requires the full API combination (CopyFromScreen plus ToBase64String or System.Drawing) rather than any single term, which makes it high fidelity - legitimate software captures screens through native APIs or dedicated tooling, not by assembling .NET reflection in a command line. Expect near-zero benign volume; possible exceptions are IT screenshot utilities and some monitoring or e-discovery agents, which should be allowlisted by parent process. Single-table but scheduled rather than NRT because the multi-term predicate benefits from batch evaluation."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
// Require the .NET screen-capture + encode combination, not any single term
| where ProcessCommandLine has "CopyFromScreen"
| where ProcessCommandLine has_any ("ToBase64String", "System.Drawing", "Bitmap")
| extend NodeParent =
       InitiatingProcessFileName =~ "node.exe"
    or InitiatingProcessParentFileName =~ "node.exe"
    or InitiatingProcessVersionInfoOriginalFileName =~ "node.exe"
    or InitiatingProcessVersionInfoProductName has "Node.js"
| extend WritesToDisk = ProcessCommandLine has_any ("WriteAllText", "WriteAllBytes", "Out-File", "Set-Content")
| extend HiddenWindow = ProcessCommandLine has_any ("-w hidden", "WindowStyle Hidden", "-nop", "-NoProfile")
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, ProcessCommandLine,
    NodeParent, WritesToDisk, HiddenWindow,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, InitiatingProcessVersionInfoOriginalFileName, ReportId
| sort by Timestamp desc
```

**Expected results:** Near-zero in a healthy environment. `NodeParent == true` confirms this campaign specifically; `NodeParent == false` with the same API combination still indicates scripted screen capture and warrants investigation regardless of attribution.

---

## Query 8: `rundll32` executing a DLL from a user-writable path with an export and token argument

**Purpose:** Detects the campaign's follow-on payload execution — `rundll32.exe` loading an operator-supplied DLL by an exported function (observed as `open`) with a per-execution token argument, consistent with modular loaders that gate execution behind a runtime-supplied key. Scoped to DLLs in **user-writable directories**, since `rundll32` against system DLLs is ordinary Windows behavior.  
**Severity:** High  
**MITRE:** T1218.011, T1105

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Needs environment tuning before promotion. rundll32 is heavily used by legitimate Windows components, installers, and third-party software, so the user-writable-path condition is doing most of the false-positive suppression and must be preserved. Some legitimate installers and updaters do stage DLLs under AppData or ProgramData and invoke them via rundll32, so allowlist those specific publishers or paths first. The strongest additional discriminator is a node.exe (or renamed-Node) ancestor, which is already surfaced as a column - consider requiring it before any scheduled deployment. The token-argument heuristic uses a length-based regex and should be validated against the local baseline."
-->

```kql
let UserWritablePaths = dynamic([@"\AppData\Local\", @"\AppData\Roaming\", @"\ProgramData\", @"\Users\Public\", @"\Temp\", @"\Downloads\"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has ".dll"
// rundll32 against system DLLs is ordinary Windows behavior - require a user-writable target
| where ProcessCommandLine has_any (UserWritablePaths)
| extend ExportName = extract(@"(?i)\.dll\s*,\s*([A-Za-z_][A-Za-z0-9_@]*)", 1, ProcessCommandLine)
| extend HasOpenExport = ExportName =~ "open"
// Per-execution token: a long opaque argument trailing the export name
| extend HasTokenArg = ProcessCommandLine matches regex @"(?i)\.dll\s*,\s*[A-Za-z_][A-Za-z0-9_@]*\s+[A-Za-z0-9+/=_-]{16,}"
| extend NodeAncestor =
       InitiatingProcessFileName =~ "node.exe"
    or InitiatingProcessParentFileName =~ "node.exe"
    or InitiatingProcessVersionInfoOriginalFileName =~ "node.exe"
| where isnotempty(ExportName)
| project Timestamp, DeviceName, DeviceId, AccountName, ExportName, HasOpenExport, HasTokenArg,
    NodeAncestor, ProcessCommandLine, FolderPath,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, ReportId
| sort by Timestamp desc
```

**Expected results:** A modest baseline from installers and third-party software that legitimately stage DLLs under user-writable paths. Prioritize `HasOpenExport == true` **and** `HasTokenArg == true`, and treat `NodeAncestor == true` as confirmation of this campaign.

---

## Query 9: WinRM lateral movement from a user-context process

**Purpose:** Detects the campaign's final observed stage — operator tasking through the Node.js implant initiating **WinRM connections over TCP 5985** to domain-joined systems, including domain controllers and certificate authorities. The article's discriminator is WinRM originating from a **non-administrative, user-context process**, so this query surfaces the initiating process and summarizes **fan-out** (distinct remote hosts per source device), which is what separates an operator sweeping the estate from a single administrative action.  
**Severity:** High  
**MITRE:** T1021.006

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Must be tuned per environment before promotion. WinRM on TCP 5985 is a normal administrative protocol - management servers, configuration-management agents, monitoring platforms, and admin workstations use it constantly and will dominate results until allowlisted. Tuning path: allowlist authorized management source devices by DeviceName and management-agent parent processes by InitiatingProcessFileName, then alert on what remains. The genuinely anomalous conditions already surfaced as columns are a script-host or Node.js initiator and high fan-out to many distinct hosts from a single non-management endpoint. Uses a summarize over network telemetry, so it is a hunting/threshold query rather than an NRT candidate."
-->

```kql
let LookBack = 30d;
let ScriptInitiators = dynamic(["powershell.exe","pwsh.exe","node.exe","wscript.exe","cscript.exe","cmd.exe","rundll32.exe","mshta.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(LookBack)
| where RemotePort == 5985 or RemoteUrl has "/wsman"
| extend ScriptHostInitiator = InitiatingProcessFileName in~ (ScriptInitiators)
| extend NodeInitiator =
       InitiatingProcessFileName =~ "node.exe"
    or InitiatingProcessVersionInfoOriginalFileName =~ "node.exe"
    or InitiatingProcessVersionInfoProductName has "Node.js"
| extend Target = coalesce(RemoteIP, RemoteUrl)
| summarize
    Connections       = count(),
    DistinctTargets   = dcount(Target),
    Targets           = make_set(Target, 50),
    FirstSeen         = min(Timestamp),
    LastSeen          = max(Timestamp),
    ActiveHours       = dcount(bin(Timestamp, 1h)),
    SampleCommandLine = any(InitiatingProcessCommandLine)
    by DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessAccountName,
       ScriptHostInitiator, NodeInitiator
| extend FanOutRisk = case(DistinctTargets >= 20, "High", DistinctTargets >= 5, "Medium", "Low")
| sort by DistinctTargets desc, Connections desc
```

**Expected results:** Legitimate management infrastructure will appear first and should be allowlisted by device and parent process. The campaign signature is `ScriptHostInitiator == true` (especially `NodeInitiator == true`) combined with `FanOutRisk` of Medium or High from an ordinary user endpoint. Any WinRM connection to a domain controller or certificate authority from a non-management workstation warrants immediate investigation.

---

## General Tuning Notes

1. **Behavioral hunts outlast the IOCs here.** Microsoft explicitly generalized environment-specific values (paths, hostnames, account names) in this reporting, and the actor's payloads and cloud-hosted infrastructure are cheap to rebuild. Queries 2 and 3 give immediate high-fidelity coverage; **Queries 4–9 are what still work after the operator rotates.** Refresh the hash and domain lists from current Microsoft Threat Intelligence, but do not rely on them alone.

2. **Never broaden the cloud-infrastructure matches.** `blob.core.windows.net` and `cloudapp.azure.com` are legitimate Microsoft infrastructure hosting substantial volumes of benign traffic. Query 3 matches **exact hostnames** by design. Broadening to the parent domains would produce unusable noise and risk blocking legitimate services.

3. **Correlation is the detection; individual stages are noise.** Every stage of this campaign uses legitimate tooling — Teams, remote-support software, Windows Installer, Node.js, WinRM. No single stage is reliably malicious. Investigate along the chain: external Teams contact (Q1) → remote-session MSI delivery (Q4) → Node.js loader execution (Q5) → persistence (Q6) → collection (Q7) / follow-on DLL (Q8) → WinRM lateral movement (Q9).

4. **Baseline Node.js before deploying Query 5.** On engineering estates Node.js legitimately runs from user-writable paths via nvm, Volta, fnm, Yarn/pnpm, VS Code extension hosts, and Electron apps. Allowlist those on `InitiatingProcessFolderPath` and lean on the **script-host parent** condition — a developer's Node process is parented by an IDE, terminal, or package manager, never by `wscript.exe`.

5. **Match on version metadata, not just filename.** The article documents **renamed copies** of the Node.js runtime. Queries 5, 7, 8, and 9 all check `ProcessVersionInfoOriginalFileName` / `ProcessVersionInfoProductName` alongside `FileName`; removing those conditions to simplify a query would blind it to the evasive variant.

6. **Vishing produces clean collaboration telemetry.** When the operator delivers instructions by voice, **no malicious URL or command appears in Teams telemetry at all**. A clean Query 1 result does not exclude this campaign — always pivot to endpoint telemetry on the suspected recipient's device around the contact window.

7. **Allowlist management infrastructure before Query 9.** WinRM is a legitimate administrative protocol. Build the allowlist of authorized management source devices and agent parent processes first; the residual — especially high fan-out from an ordinary endpoint, or any connection to a domain controller or certificate authority — is the finding.

8. **Assume network-level access on confirmation.** Microsoft's guidance is explicit: organizations finding indicators of this campaign should assume the operator obtained network-level access through the compromised host and **prioritize credential rotation for every credential accessible from that machine, including domain admin accounts if the host was domain-joined.** Isolation alone is insufficient given the WinRM pivot toward identity infrastructure.

9. **Telemetry dependencies.** Query 1 requires Microsoft Defender for Cloud Apps / Office 365 Teams auditing into `CloudAppEvents`. Queries 2 and 5–9 require Defender for Endpoint process, file, registry, image-load, and network telemetry. Where a table is absent, record the gap explicitly rather than reading a zero result as an all-clear.

10. **CD-readiness summary.** **Queries 2, 3, 6, and 7 are `cd_ready: true`** — the two direct-IOC sweeps plus the two behaviorally distinctive stages (update-themed `LocalAppData` persistence and scripted Base64 screen capture), with **Query 3 NRT-eligible** as a single-table query. **Queries 1, 4, 5, 8, and 9 are `cd_ready: false`**: each matches legitimate, high-volume enterprise behavior (external collaboration, silent MSI deployment, Node.js execution, `rundll32`, WinRM) and requires per-environment allowlisting before it could be promoted. All nine queries were authored and executed against live Microsoft Defender Advanced Hunting telemetry during development. **One caveat on Query 5:** it executed successfully but could **not** be fidelity-validated, because the authoring environment contained no Node.js execution telemetry to tune against — treat it as syntactically validated only and baseline it locally before use.

---

## References

- Microsoft Threat Intelligence — [Impersonating IT support: how threat actors turn a remote session into enterprise-wide access (2026-09-02)](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)
- MITRE ATT&CK — [T1566.003 Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
- MITRE ATT&CK — [T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- MITRE ATT&CK — [T1218.007 System Binary Proxy Execution: Msiexec](https://attack.mitre.org/techniques/T1218/007/)
- MITRE ATT&CK — [T1218.011 System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- MITRE ATT&CK — [T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- MITRE ATT&CK — [T1113 Screen Capture](https://attack.mitre.org/techniques/T1113/)
- MITRE ATT&CK — [T1021.006 Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)
- Microsoft Learn — [Security best practices for Microsoft Teams](https://learn.microsoft.com/en-us/MicrosoftTeams/teams-security-best-practices-for-safer-messaging)
- Microsoft Learn — [Manage external meetings and chat with trusted organizations](https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat)
- Microsoft Learn — [Attack surface reduction rules deployment](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-deployment-implement)
- Microsoft Learn — [Windows Remote Management](https://learn.microsoft.com/windows/win32/winrm/portal)
- Companion files: [`queries/threat-intelligence/2026-05/trusted_third_party_intrusion.md`](../2026-05/trusted_third_party_intrusion.md), [`queries/endpoint/rare_process_chains.md`](../../endpoint/rare_process_chains.md)
