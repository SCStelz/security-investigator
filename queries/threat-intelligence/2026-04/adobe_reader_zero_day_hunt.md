# Adobe Reader Zero-Day Exploitation & NTLM Leak Hunting Campaign

**Created:** 2026-04-09  
**Platform:** Both  
**Tables:** DeviceNetworkEvents, DeviceFileEvents, DeviceProcessEvents, DeviceCustomFileEvents, DeviceCustomScriptEvents, EmailAttachmentInfo  
**Keywords:** Adobe Reader, AcroRd32, Acrobat, PDF exploit, zero-day, CVE, RSS.addFeed, util.readFileIntoStream, NTLM leak, SMB, fingerprinting, sandbox escape, RCE, JavaScript obfuscation, CDC  
**MITRE:** T1203, T1059.007, T1005, T1082, T1041, T1071.001, T1187, T1566.001  
**Domains:** endpoint, email  
**Timeframe:** Last 30 days (configurable)

---

## Threat Overview

### EXPMON Zero-Day (April 7, 2026)

A highly sophisticated, **unpatched zero-day** fingerprinting exploit targeting Adobe Reader users was disclosed by EXPMON on April 7, 2026. The exploit:

1. Executes obfuscated JavaScript embedded in a PDF (object 9 → base64 decode from hidden form field "btn1" in object 7)
2. Calls the **privileged** `util.readFileIntoStream()` API to read local files (e.g., `ntdll.dll` for exact OS version)
3. Calls `RSS.addFeed()` to **exfiltrate** collected data (language, Reader version, OS version, local PDF path) to a remote C2 server
4. Receives and executes additional JavaScript from the C2 — enabling follow-up RCE/sandbox escape
5. Uses cryptography to decrypt payloads (evading network-level detection)

**No user interaction beyond opening the PDF is required.** Confirmed working on latest Adobe Reader (26.00121367). Campaign active since at least **November 2025** (4+ months).

### NTLM Credential Leak via `/Launch` Action (January 2025)

A separate but related vulnerability where PDF `/Launch` actions trigger outbound SMB connections, leaking NTLM hashes. Adobe considers this "by design" (intranet-only trust model). Foxit patched in v2024.4.

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Known C2 IP Address Connections (IOC Match)](#query-1-known-c2-ip-address-connections-ioc-match) | Investigation | `DeviceNetworkEvents` |
| 2 | [Known Malicious PDF File Hashes (IOC Match)](#query-2-known-malicious-pdf-file-hashes-ioc-match) | Investigation | `DeviceFileEvents` |
| 3 | [Adobe Reader Outbound Connections to Non-Standard Ports (Behavioral)](#query-3-adobe-reader-outbound-connections-to-non-standard-ports-behavioral) | Investigation | `DeviceNetworkEvents` |
| 4 | [Adobe Reader Connections to Non-Adobe Infrastructure (Behavioral)](#query-4-adobe-reader-connections-to-non-adobe-infrastructure-behavioral) | Investigation | `DeviceNetworkEvents` |
| 5 | [Adobe Reader Direct-IP Connections (No DNS — Behavioral)](#query-5-adobe-reader-direct-ip-connections-no-dns--behavioral) | Investigation | `DeviceNetworkEvents` |
| 6 | [PDF Reader NTLM Leak via SMB (Port 445)](#query-6-pdf-reader-ntlm-leak-via-smb-port-445) | Investigation | `DeviceNetworkEvents` |
| 7 | [Adobe Reader Spawning Suspicious Child Processes (Post-RCE)](#query-7-adobe-reader-spawning-suspicious-child-processes-post-rce) | Investigation | `DeviceProcessEvents` |
| 8 | [PDF File Delivery via Email then Opened (Kill Chain)](#query-8-pdf-file-delivery-via-email-then-opened-kill-chain) | Investigation | `DeviceFileEvents` + `EmailAttachmentInfo` |
| 9 | [PDF Open Followed by Outbound Network Connection (Behavioral Correl...](#query-9-pdf-open-followed-by-outbound-network-connection-behavioral-correlation) | Investigation | `DeviceFileEvents` + `DeviceNetworkEvents` |
| 10 | [Adobe Synchronizer User-Agent in Network Traffic](#query-10-adobe-synchronizer-user-agent-in-network-traffic) | Investigation | `DeviceNetworkEvents` |
| 11 | [Adobe Reader Network Connection Summary (Baseline Audit)](#query-11-adobe-reader-network-connection-summary-baseline-audit) | Dashboard | `DeviceNetworkEvents` |
| 12 | [CDC — Adobe Ecosystem File Activity Anomalies](#query-12-cdc--adobe-ecosystem-file-activity-anomalies) | Detection | `CRLogs` + `DeviceCustomFileEvents` |
| 13 | [CDC — AdobeCollabSync INetCache Downloads (RSS.addFeed Indicator)](#query-13-cdc--adobecollabsync-inetcache-downloads-rssaddfeed-indicator) | Investigation | `DeviceCustomFileEvents` |
| 14 | [CDC — Full Adobe Ecosystem Temp File Baseline](#query-14-cdc--full-adobe-ecosystem-temp-file-baseline) | Dashboard | `DeviceCustomFileEvents` |


## IOC Reference

| Type | Value | Context |
|------|-------|---------|
| **IP** | `169.40.2.68` (port 45191) | Original C2 server |
| **IP** | `188.214.34.20` (port 34123) | Variant C2 (found Apr 8, @greglesnewich) |
| **SHA256** | `65dca34b04416f9a113f09718cbe51e11fd58e7287b7863e37f393ed4d25dde7` | Original malicious PDF |
| **SHA256** | `54077a5b15638e354fa02318623775b7a1cc0e8c21e59bcbab333035369e377f` | Variant PDF (VT since 2025-11-28) |
| **User-Agent** | `Adobe Synchronizer` | RSS.addFeed() C2 callback identifier |
| **Processes** | `AcroRd32.exe`, `Acrobat.exe` | Adobe Reader executables |
| **Collab** | `adobecollabsync.exe` | RSS/collaboration sync — used by RSS.addFeed() |

> **Note:** IOC lists are point-in-time snapshots. New variants will use different infrastructure. The **behavioral queries** (3–11) detect the technique regardless of C2 infrastructure changes.

---

## References

- EXPMON blog post: [https://justhaifei1.blogspot.com/2026/04/expmon-detected-sophisticated-zero-day-adobe-reader.html](https://justhaifei1.blogspot.com/2026/04/expmon-detected-sophisticated-zero-day-adobe-reader.html)
- EXPMON public analysis: [https://pub.expmon.com/analysis/328131/](https://pub.expmon.com/analysis/328131/)
- VirusTotal (original): [https://www.virustotal.com/gui/file/65dca34b04416f9a113f09718cbe51e11fd58e7287b7863e37f393ed4d25dde7](https://www.virustotal.com/gui/file/65dca34b04416f9a113f09718cbe51e11fd58e7287b7863e37f393ed4d25dde7)
- NTLM leak article: [https://cybersecuritynews.com/zero-day-vulnerability-in-pdf-files-leaking-ntlm-data-in-adobe-foxit-reader/](https://cybersecuritynews.com/zero-day-vulnerability-in-pdf-files-leaking-ntlm-data-in-adobe-foxit-reader/)

---

## Baseline: Normal Adobe Reader Behavior

Understanding normal behavior is critical for tuning. Based on live environment analysis:

**Network (DeviceNetworkEvents):**
- Acrobat.exe connects to `cc-api-data.adobe.io`, `p13n.adobe.io`, `acroipm2.adobe.com`, `lcs-cops.adobe.io` on ports **80 and 443 only**
- OCSP checks to `ocsp.digicert.com` on port 80
- **No connections to raw IPs** — always DNS-resolved Adobe domains
- **No connections on non-standard ports** (45191, 34123, etc.)

**CDC File Activity (DeviceCustomFileEvents):**
- `adobecollabsync.exe` creates `etilqs_*` SQLite temp files in `collab_low\`
- IPC files in `GrowthSDK\Production\`
- Legitimate INetCache downloads: `purchasedetection[1].txt`, `killswitch-cs-fw[1].txt` (Adobe feature-flag/licensing)
- Crash logs in `CRLogs\crashlogs\`
- Licensing files in `acrobat_sbx\NGL\`

**AMSI (DeviceCustomScriptEvents):**
- Adobe Reader's JavaScript engine does **NOT** integrate with Windows AMSI
- Zero AMSI events from Acrobat/AcroRd32 processes — this is a known telemetry blind spot
- The obfuscated exploit JavaScript will NOT appear in AMSI captures

---

## Queries

### Query 1: Known C2 IP Address Connections (IOC Match)

**Purpose:** Direct IOC match — detect connections to the known C2 infrastructure from the EXPMON disclosure and variant sample. Highest confidence but lowest longevity (attackers rotate infra).

**Severity:** High  
**MITRE:** T1071.001, T1041

**Tuning Notes:**
- Add new IPs as variants are discovered (check EXPMON Twitter: @EXPMON_, VT community)
- Will NOT detect future variants using different infrastructure
- Query 3 (behavioral) is more durable

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Adobe Reader Zero-Day: Connection to known C2 {{RemoteIP}} from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Immediately isolate the device. Collect the PDF file that was open at the time. Check process tree for follow-up RCE activity. Revoke user credentials and rotate NTLM hashes if SMB was involved."
adaptation_notes: "Remove let block, inline the IP list. Add Timestamp, ReportId, DeviceId."
-->

```kql
// Hunt: Connections to known Adobe Reader zero-day C2 IPs
// Source: EXPMON disclosure (Apr 7 2026) + variant (Apr 8 2026)
let C2_IPs = dynamic(["169.40.2.68", "188.214.34.20"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (C2_IPs)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, LocalIP, ActionType, ReportId, DeviceId
| order by Timestamp desc
```

**Expected Results:**
- 0 results = clean (no known C2 contact)
- Any match = **critical** — immediate incident response required

---

### Query 2: Known Malicious PDF File Hashes (IOC Match)

**Purpose:** Detect the original malicious PDF and known variant by SHA256. Catches file creation (download, email save, file copy) across endpoint telemetry.

**Severity:** High  
**MITRE:** T1566.001, T1203

**Tuning Notes:**
- Add hashes as new variants appear on VirusTotal or are published by researchers
- Only 5/64 VT detection at time of disclosure — AV may miss this

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Adobe Reader Zero-Day: Known malicious PDF {{FileName}} on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Quarantine the PDF file immediately. Check if the file was opened (correlate with process events for AcroRd32.exe/Acrobat.exe). Investigate network connections from the device around the time of file creation."
adaptation_notes: "Remove let block, inline the hash list. Add Timestamp, ReportId, DeviceId."
-->

```kql
// Hunt: Known malicious PDF samples from EXPMON disclosure
let MaliciousPDF_SHA256 = dynamic([
    "65dca34b04416f9a113f09718cbe51e11fd58e7287b7863e37f393ed4d25dde7",
    "54077a5b15638e354fa02318623775b7a1cc0e8c21e59bcbab333035369e377f"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (MaliciousPDF_SHA256)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessAccountName,
    FileOriginUrl, FileOriginReferrerUrl, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 3: Adobe Reader Outbound Connections to Non-Standard Ports (Behavioral)

**Purpose:** The zero-day C2 uses custom high ports (45191, 34123). Legitimate Adobe Reader only connects on ports 80/443. This behavioral detection catches current AND future variants regardless of C2 IP rotation.

**Severity:** High  
**MITRE:** T1071.001, T1041

**Tuning Notes:**
- Normal Adobe Reader connects to `*.adobe.io`, `*.adobe.com`, `ocsp.digicert.com` on ports 80/443 only
- Any non-80/443 connection from Adobe Reader is highly anomalous
- Verified against live baseline: 18 connections in 30d, all on ports 80/443 to Adobe domains

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Adobe Reader suspicious non-standard port connection to {{RemoteIP}} from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Investigate what PDF was open at the time. Capture the remote IP and port for threat intel analysis. Check for subsequent child processes or file creation indicating RCE."
adaptation_notes: "Remove let blocks, inline the process list and port list. Add Timestamp, ReportId, DeviceId."
-->

```kql
// Hunt: Adobe Reader connecting to non-standard ports (C2 behavioral pattern)
// Baseline: normal Acrobat only connects on ports 80 and 443
let AdobeReaderProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe"]);
let StandardPorts = dynamic([80, 443, 8080]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (AdobeReaderProcesses)
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (StandardPorts)
| where RemoteIPType != "Private"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, LocalIP, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 4: Adobe Reader Connections to Non-Adobe Infrastructure (Behavioral)

**Purpose:** Detect Adobe Reader connecting to ANY non-Adobe domain. The exploit's `RSS.addFeed()` calls out to attacker-controlled servers. Legitimate Reader only talks to Adobe infrastructure.

**Severity:** Medium  
**MITRE:** T1071.001, T1082

**Tuning Notes:**
- Allowlist covers: `adobe.io`, `adobe.com`, `adobelogin.com`, `adobecc.com`, and certificate authorities (DigiCert, VeriSign, etc.)
- May need to add CDN domains if your org uses Adobe Document Cloud heavily
- `isnotempty(RemoteUrl)` filter excludes aggregated reports where URL is blank

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "CommandAndControl"
title: "Adobe Reader connection to non-Adobe domain {{RemoteUrl}} from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Check the resolved domain against threat intel. Investigate the PDF that was open. Look for data exfiltration patterns."
adaptation_notes: "Remove let blocks. Cannot use `not()` wrapper in CD — use `RemoteUrl !has` chain instead of `has_any` negation."
-->

```kql
// Hunt: Adobe Reader connecting to non-Adobe domains
// The zero-day RS.addFeed() calls out to attacker-controlled infrastructure
let AdobeReaderProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe"]);
let KnownAdobeDomains = dynamic(["adobe.io", "adobe.com", "adobelogin.com", 
    "adobecc.com", "adobeexchange.com", "digicert.com", "verisign.com",
    "symantec.com", "amazontrust.com", "letsencrypt.org"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (AdobeReaderProcesses)
| where ActionType in ("ConnectionSuccess", "ConnectionFound")
| where isnotempty(RemoteUrl)
| where not(RemoteUrl has_any (KnownAdobeDomains))
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 5: Adobe Reader Direct-IP Connections (No DNS — Behavioral)

**Purpose:** The known C2 addresses are raw IPs (169.40.2.68:45191, 188.214.34.20:34123). Legitimate Adobe Reader always resolves domains via DNS — a direct-IP connection is a strong anomaly indicator even for unknown future variants.

**Severity:** High  
**MITRE:** T1071.001, T1041

**Tuning Notes:**
- Baseline shows normal Acrobat always has a populated `RemoteUrl` (e.g., `cc-api-data.adobe.io`)
- A connection with empty `RemoteUrl` to a public IP = direct IP connection without DNS
- Very low false positive rate based on 30d baseline

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Adobe Reader direct IP connection (no DNS) to {{RemoteIP}} from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "This is highly anomalous — Adobe Reader should never connect to raw IPs. Immediately investigate what PDF was open, capture the destination IP, isolate the device, and check for follow-up exploitation."
adaptation_notes: "Remove let block, use regex inline. Add Timestamp, ReportId, DeviceId."
-->

```kql
// Hunt: Adobe Reader making direct-IP connections (no domain resolution)
// Normal behavior: always connects via DNS-resolved Adobe domains
// Exploit behavior: connects to raw IPs like 169.40.2.68:45191
let AdobeReaderProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (AdobeReaderProcesses)
| where ActionType in ("ConnectionSuccess", "ConnectionFound")
| where isempty(RemoteUrl) or RemoteUrl matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
| where RemoteIPType != "Private"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 6: PDF Reader NTLM Leak via SMB (Port 445)

**Purpose:** Detect PDF readers initiating outbound SMB connections (port 445), which indicates NTLM credential leak via the `/Launch` action vulnerability. Covers both Adobe Reader and Foxit Reader.

**Severity:** High  
**MITRE:** T1187

**Tuning Notes:**
- Adobe considers intranet NTLM behavior "by design" — users can disable via "Automatically trust sites from Win OS security zones"
- Foxit patched in v2024.4 — detections from Foxit indicate an unpatched installation
- Any SMB connection from a PDF reader to a **public** IP is critical
- The shared query had a bug: `RemotePort == "445"` uses string comparison — RemotePort is `int`, must use `== 445`

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "PDF Reader NTLM leak: SMB connection to {{RemoteIP}} from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "NTLM hashes may have been leaked to the remote IP. Reset the affected user's password immediately. Check if the remote IP is attacker-controlled. Patch Foxit Reader if applicable. For Adobe Reader, disable 'Automatically trust sites from Win OS security zones'."
adaptation_notes: "Remove let block. Add Timestamp, ReportId, DeviceId."
-->

```kql
// Hunt: PDF reader triggering outbound SMB connections (NTLM credential leak)
// Covers Adobe Reader AND Foxit Reader
// Fix from shared query: RemotePort is int, not string — use == 445 not == "445"
let PDFReaderProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe", 
    "FoxitPDFReader.exe", "FoxitReader.exe", "FoxitPhantomPDF.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (PDFReaderProcesses)
| where RemotePort == 445
| where ActionType in ("ConnectionSuccess", "ConnectionFound", "ConnectionRequest")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, LocalIP, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 7: Adobe Reader Spawning Suspicious Child Processes (Post-RCE)

**Purpose:** If the zero-day's follow-up RCE/sandbox escape exploit succeeds, Adobe Reader would spawn child processes for reconnaissance, persistence, or lateral movement. This detects the post-exploitation phase.

**Severity:** High  
**MITRE:** T1203, T1059.007

**Tuning Notes:**
- Adobe Reader should NEVER spawn cmd.exe, powershell.exe, or LOLBins
- May see legitimate `AdobeARM.exe` (updater) — not in suspicious list
- If sandbox escape succeeds, the child process may come from `RdrCEF.exe` (renderer) or `AdobeCollabSync.exe`

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Adobe Reader spawned suspicious process {{FileName}} on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Adobe Reader should never spawn these processes. Investigate the full process tree, capture the command line, and check for follow-up malicious activity. Isolate the device immediately."
adaptation_notes: "Remove let blocks. Add Timestamp, ReportId, DeviceId."
-->

```kql
// Hunt: Adobe Reader spawning LOLBins or reconnaissance tools (post-RCE indicator)
let AdobeReaderProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe", 
    "RdrCEF.exe", "adobecollabsync.exe"]);
let SuspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", 
    "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", 
    "certutil.exe", "bitsadmin.exe", "msiexec.exe", "whoami.exe", "net.exe", 
    "net1.exe", "nltest.exe", "tasklist.exe", "systeminfo.exe", "ipconfig.exe", 
    "curl.exe", "wget.exe", "nslookup.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (AdobeReaderProcesses)
| where FileName in~ (SuspiciousChildren)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName, AccountDomain, SHA256, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 8: PDF File Delivery via Email then Opened (Kill Chain)

**Purpose:** Correlate PDF attachments received via email with subsequent file creation on endpoints — traces the initial access vector (T1566.001). Join on SHA256 hash to link email delivery to endpoint activity.

**Severity:** Medium  
**MITRE:** T1566.001

**Tuning Notes:**
- Join is on SHA256 — requires both tables to have non-empty hashes
- Time window: email delivery to file creation within same 30d window
- May produce false positives for legitimate PDF attachments — prioritize correlation with anomalous network activity from queries 3-5

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table join on SHA256 with email data — too complex for CD rule format, use as manual hunting query."
-->

```kql
// Hunt: PDF delivered via email → landed on endpoint (initial access chain)
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where FileName endswith ".pdf"
| where isnotempty(SHA256)
| project EmailTimestamp = Timestamp, NetworkMessageId, SenderFromAddress, 
    RecipientEmailAddress, FileName, SHA256, FileSize
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName endswith ".pdf"
    | where ActionType == "FileCreated"
    | where InitiatingProcessFileName in~ ("outlook.exe", "olk.exe", "msedge.exe", "chrome.exe")
    | where isnotempty(SHA256)
    | project FileTimestamp = Timestamp, DeviceName, FileName, FolderPath, SHA256,
        InitiatingProcessFileName, InitiatingProcessAccountName
) on SHA256
| project EmailTimestamp, FileTimestamp, DeviceName, SenderFromAddress, 
    RecipientEmailAddress, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessAccountName
| order by EmailTimestamp desc
```

---

### Query 9: PDF Open Followed by Outbound Network Connection (Behavioral Correlation)

**Purpose:** Correlates PDF file activity by Adobe Reader with subsequent outbound network connections from the **same process instance** within 5 minutes. This is the core behavioral pattern of the zero-day: open PDF → JS executes → RSS.addFeed() calls C2.

**Severity:** Medium  
**MITRE:** T1203, T1041

**Tuning Notes:**
- Joins on `DeviceId`, `InitiatingProcessId`, and `InitiatingProcessCreationTime` to ensure same process instance
- 5-minute time window — exploit should callback within seconds, but using generous window for network delays
- Filters to public IPs only (`RemoteIPType != "Private"`)
- May require increasing the time window for slow network environments

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Inner join across DeviceFileEvents and DeviceNetworkEvents with process correlation — too complex for CD. Use as hunting query, deploy queries 3-5 as CD rules instead."
-->

```kql
// Hunt: PDF opened in Adobe Reader → outbound network connection from same process
// Core behavioral pattern: open PDF → JS executes → RSS.addFeed() callbacks
let AdobeReaderProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (AdobeReaderProcesses)
| where FileName endswith ".pdf"
| where ActionType in ("FileCreated", "FileModified")
| project PDFTime = Timestamp, DeviceId, DeviceName, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ (AdobeReaderProcesses)
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType != "Private"
    | project NetTime = Timestamp, DeviceId, RemoteIP, RemotePort, RemoteUrl,
        InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime
) on DeviceId, InitiatingProcessId, InitiatingProcessCreationTime
| where NetTime between (PDFTime .. (PDFTime + 5m))
| project PDFTime, NetTime, DeviceName, FileName, FolderPath,
    RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by PDFTime desc
```

---

### Query 10: Adobe Synchronizer User-Agent in Network Traffic

**Purpose:** The zero-day's `RSS.addFeed()` C2 callback uses the "Adobe Synchronizer" string in its User-Agent header. EXPMON specifically recommends monitoring for this. Check both `RemoteUrl` and `AdditionalFields` for this signature.

**Severity:** High  
**MITRE:** T1071.001

**Tuning Notes:**
- The `AdditionalFields` column in DeviceNetworkEvents sometimes contains HTTP headers
- This is a high-signal detection — "Adobe Synchronizer" in web traffic is rare in enterprise environments
- May also appear in proxy/firewall logs outside of MDE telemetry — check your web proxy

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Adobe Synchronizer user-agent detected in network traffic on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "The 'Adobe Synchronizer' user-agent is used by the RSS.addFeed() API in the Adobe Reader zero-day exploit. Investigate the destination IP/URL, identify which PDF triggered this, and check for data exfiltration."
adaptation_notes: "Straightforward single-table query. Add Timestamp, ReportId, DeviceId."
-->

```kql
// Hunt: "Adobe Synchronizer" user-agent in network traffic
// EXPMON recommendation: monitor all HTTP/HTTPS traffic with this UA string
// RSS.addFeed() uses this UA for C2 callbacks
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "Adobe Synchronizer" 
    or AdditionalFields has "Adobe Synchronizer"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine, 
    AdditionalFields, ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 11: Adobe Reader Network Connection Summary (Baseline Audit)

**Purpose:** Establish a baseline of all Adobe Reader network activity — domains contacted, ports used, connection counts. Use this to identify anomalies that deviate from the expected Adobe infrastructure pattern.

**Severity:** Informational  
**MITRE:** T1071.001

**Tuning Notes:**
- Run this first to understand your environment's normal Adobe Reader behavior
- Results should show ONLY Adobe domains (*.adobe.io, *.adobe.com) and OCSP responders on ports 80/443
- Anything outside this pattern warrants investigation

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline/statistical query with summarize and dcount — not suitable for CD."
-->

```kql
// Baseline: Adobe Reader network connection inventory
// Use this to establish normal behavior and identify anomalies
let AdobeReaderProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (AdobeReaderProcesses)
| where ActionType in ("ConnectionSuccess", "ConnectionFound")
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 10)
    by RemoteUrl, RemoteIP, RemotePort
| order by ConnectionCount desc
```

---

### Query 12: CDC — Adobe Ecosystem File Activity Anomalies

**Purpose:** Leverages DeviceCustomFileEvents (CDC) to detect Adobe processes writing files to **unexpected locations**. The zero-day may stage collected data or received payloads in temp directories before exfiltration. CDC captures low-level file I/O invisible to standard DeviceFileEvents.

**Severity:** Medium  
**MITRE:** T1005, T1074.001

**Tuning Notes:**
- Normal CDC baseline for Adobe: `collab_low\etilqs_*` (SQLite temp), `GrowthSDK\`, `acrobat_sbx\NGL\`, `CRLogs\`, `AdobeGCData\`
- Legitimate INetCache downloads: `purchasedetection[1].txt`, `killswitch-cs-fw[1].txt` (Adobe feature flags)
- The exploit's data staging would create files with non-standard names outside these paths
- **Requires CDC (Custom Data Collection) to be enabled** — if table doesn't resolve, skip gracefully

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline-aware anomaly detection with allowlist exclusions and summarize — not suitable for CD."
-->

```kql
// CDC Hunt: Adobe processes writing to unexpected locations
// Normal paths: collab_low, GrowthSDK, acrobat_sbx, CRLogs, AdobeGCData
// Suspicious: anything outside these paths (exploit data staging)
let AdobeProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe", 
    "adobecollabsync.exe", "RdrCEF.exe"]);
let NormalAdobePaths = dynamic(["collab_low", "GrowthSDK", "Adobe\\Acrobat", 
    "Adobe\\ARM", "AcroCEF", "Acrobat DC", "AdobeGCData", "acrobat_sbx", 
    "CRLogs", "AdobeGCClient"]);
DeviceCustomFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (AdobeProcesses)
| where not(FolderPath has_any (NormalAdobePaths))
| where FileName !startswith "etilqs_"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
```

**Tuning query — view anomalies summarized by folder pattern:**

```kql
// CDC: Summarized view — Adobe file activity outside normal paths
let AdobeProcesses = dynamic(["AcroRd32.exe", "Acrobat.exe", 
    "adobecollabsync.exe", "RdrCEF.exe"]);
let NormalAdobePaths = dynamic(["collab_low", "GrowthSDK", "Adobe\\Acrobat", 
    "Adobe\\ARM", "AcroCEF", "Acrobat DC", "AdobeGCData", "acrobat_sbx", 
    "CRLogs", "AdobeGCClient"]);
DeviceCustomFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (AdobeProcesses)
| where not(FolderPath has_any (NormalAdobePaths))
| where FileName !startswith "etilqs_"
| summarize 
    FileCount = count(),
    UniqueFiles = dcount(FileName),
    SampleFiles = make_set(FileName, 5),
    SamplePaths = make_set(FolderPath, 5)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1d)
| order by FileCount desc
```

---

### Query 13: CDC — AdobeCollabSync INetCache Downloads (RSS.addFeed Indicator)

**Purpose:** Specifically monitors `adobecollabsync.exe` writing to the Windows INetCache directory, which is the mechanism used by `RSS.addFeed()`. While legitimate Adobe feature-flag downloads exist here, unusual filenames or high volume may indicate exploit C2 response data being cached.

**Severity:** Medium  
**MITRE:** T1041, T1071.001

**Tuning Notes:**
- Known legitimate files: `purchasedetection[1].txt` (113 bytes), `killswitch-cs-fw[1].txt` (4 bytes)
- Exploit-related files would have different names and likely larger sizes
- Monitor for new/unusual filenames and SHA256 changes over time
- Parent process is normally `ADNotificationManager.exe`

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "CommandAndControl"
title: "AdobeCollabSync INetCache download: {{FileName}} on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Compare the downloaded file to known legitimate Adobe feature-flag files. Unusual filenames or sizes indicate C2 response data from the RSS.addFeed() exploit channel."
adaptation_notes: "Single table, straightforward filter. Add Timestamp, ReportId, DeviceId."
-->

```kql
// CDC Hunt: AdobeCollabSync writing to INetCache (RSS.addFeed downloads)
// Legitimate baseline: purchasedetection[1].txt (113B), killswitch-cs-fw[1].txt (4B)
// Suspicious: unfamiliar filenames, large file sizes, new SHA256 values
DeviceCustomFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "adobecollabsync.exe"
| where FolderPath has "INetCache"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, FileSize,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, InitiatingProcessParentFileName,
    ReportId, DeviceId
| order by Timestamp desc
```

---

### Query 14: CDC — Full Adobe Ecosystem Temp File Baseline

**Purpose:** Comprehensive baseline of ALL file creation by Adobe Reader ecosystem processes via CDC telemetry. Run periodically to detect new file patterns that could indicate exploit activity, payload drops, or data staging.

**Severity:** Informational  
**MITRE:** T1005, T1074.001

**Tuning Notes:**
- Use this to build and maintain an up-to-date baseline
- Alert on new folder paths or process names not previously seen
- CDC only captures `FileCreated` in this environment — no read/modify visibility

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline statistical query with summarize and make_set — not suitable for CD."
-->

```kql
// CDC Baseline: Full Adobe ecosystem file creation inventory
DeviceCustomFileEvents
| where Timestamp > ago(7d)
| where FileName has_any ("acrobat", "acro", "pdf", "reader", "adobe")
    or FolderPath has_any ("Acrobat", "Adobe", "AcroRd")
    or InitiatingProcessFileName has_any ("Acrobat", "AcroRd32", 
        "adobecollabsync", "adobegcclient", "adobearm", "acrodist", "RdrCEF")
| summarize 
    EventCount = count(),
    UniqueFiles = dcount(FileName),
    Devices = dcount(DeviceName),
    SampleFiles = make_set(FileName, 10),
    SamplePaths = make_set(FolderPath, 5)
    by InitiatingProcessFileName, ActionType
| order by EventCount desc
```

---

## AMSI Telemetry Gap — Not Adobe-Specific

### Background

Windows AMSI (Antimalware Scan Interface) is an **opt-in API** — applications must voluntarily call it before executing script content. Per [Microsoft's official documentation](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal), only these Windows-native components integrate with AMSI:

- **PowerShell** (scripts, interactive use, dynamic code evaluation)
- **Windows Script Host** (`wscript.exe`, `cscript.exe`)
- **Microsoft JScript/VBScript** (the Microsoft engine, not third-party JS runtimes)
- **Office VBA macros** (triggered on high-risk Win32/COM API calls)
- **UAC** (EXE, COM, MSI, ActiveX installation)

### What's NOT Covered

Every third-party JavaScript engine is invisible to AMSI because they don't call the API:

| Engine | Used By | AMSI? |
|--------|---------|-------|
| Adobe's JS engine (SpiderMonkey-derived) | Adobe Reader PDF scripting | ❌ |
| V8 | Chrome, Edge, Node.js, Electron apps | ❌ |
| SpiderMonkey | Firefox | ❌ |
| JavaScriptCore | Safari | ❌ |
| Any embedded Lua/Python/Ruby | Game mods, automation tools | ❌ |

This is a **well-known architectural limitation** in the security community — not specific to Adobe Reader. Any non-Microsoft script host is effectively an AMSI bypass.

### Impact on This Hunting Campaign

- `DeviceCustomScriptEvents` returns **zero results** for `AcroRd32.exe` / `Acrobat.exe` — confirmed in live testing
- The zero-day's obfuscated JavaScript (base64 decode → `util.readFileIntoStream()` → `RSS.addFeed()`) executes entirely within Adobe's JS engine, **never touching AMSI**
- This is exactly the attack pattern AMSI was designed to defeat (intercept after de-obfuscation, before execution) — but only works if the application has opted in
- **Do not interpret zero AMSI results as evidence the exploit did not execute**

### Why Adobe Reader Is Particularly Concerning

While the AMSI gap is industry-wide, Adobe Reader is an outsized risk because:

1. **Privileged JS APIs** — `util.readFileIntoStream()` reads local files, `RSS.addFeed()` makes network calls. These are not sandboxed
2. **Top phishing delivery vector** — PDFs are among the most common malicious email attachments
3. **Massive enterprise footprint** — deployed on most corporate endpoints
4. **Adobe could fix this** — the AMSI API is open; Adobe could call it before executing PDF JavaScript (like Microsoft does for VBA macros). They haven't

### Compensating Controls

Since AMSI cannot see Adobe Reader JavaScript, rely on these detections instead:

| Detection Layer | Queries | What It Catches |
|----------------|---------|-----------------|
| **Network behavioral** | Q3, Q4, Q5, Q10 | C2 callbacks from `RSS.addFeed()` — non-standard ports, non-Adobe domains, direct IPs, user-agent string |
| **Process behavioral** | Q7 | Post-RCE child process spawning (LOLBins, recon tools) |
| **File behavioral (CDC)** | Q12, Q13 | Data staging, anomalous INetCache downloads from `adobecollabsync.exe` |
| **IOC match** | Q1, Q2 | Known C2 IPs and malicious PDF hashes |
| **Kill chain correlation** | Q8, Q9 | Email delivery → endpoint, PDF open → network connection |

---

## Investigation Workflow

### Triage Priority

Run queries in this order for efficient threat hunting:

| Priority | Query | Rationale |
|----------|-------|-----------|
| **1** | Query 1 (Known C2 IPs) | Fastest — direct IOC match |
| **2** | Query 2 (Known PDF hashes) | File-based IOC match |
| **3** | Query 5 (Direct-IP connections) | High-fidelity behavioral — Adobe Reader never uses raw IPs |
| **4** | Query 3 (Non-standard ports) | Behavioral — C2 uses custom ports |
| **5** | Query 10 (Adobe Synchronizer UA) | Network signature from EXPMON guidance |
| **6** | Query 6 (NTLM/SMB leak) | Related vulnerability — credential theft |
| **7** | Query 7 (Child processes) | Post-exploitation indicator |
| **8** | Query 4 (Non-Adobe domains) | Broader behavioral net — more tuning needed |
| **9** | Query 9 (PDF→Network correlation) | Deep behavioral correlation |
| **10** | Query 13 (CDC INetCache downloads) | CDC-powered RSS.addFeed indicator |
| **11** | Query 12 (CDC file anomalies) | CDC-powered staging detection |
| **12** | Query 8 (Email→Endpoint chain) | Initial access tracing |
| **13** | Query 11 (Network baseline) | Environment awareness |
| **14** | Query 14 (CDC file baseline) | Environment awareness |

### If a Match Is Found

1. **Immediately isolate the device** via Defender for Endpoint
2. **Capture the PDF file** — preserve for forensic analysis and sample sharing
3. **Check process tree** — did Adobe Reader spawn any child processes? (Query 7)
4. **Trace network connections** — what data was sent to the C2? (Query 9)
5. **Reset credentials** — if NTLM leak detected (Query 6), reset user password immediately
6. **Check for lateral movement** — did the attacker move beyond the initial endpoint?
7. **Report the sample** — submit to EXPMON ([pub.expmon.com](https://pub.expmon.com)) and your threat intel team

### Issues with the Shared KQL

The user-shared query had several issues corrected in this campaign:

| Issue | Shared Query | Fix |
|-------|-------------|-----|
| Type mismatch | `RemotePort == "445"` (string) | `RemotePort == 445` (int) |
| Missing time filter | No `Timestamp` filter | Added `Timestamp > ago(30d)` |
| Scope too narrow | Only covers NTLM/SMB scenario | Added 13 queries covering full attack chain |
| Join key | `InitiatingProcessUniqueId` (new column) | Verified column exists; also provided `InitiatingProcessId` + `InitiatingProcessCreationTime` alternative for older schemas |
| Missing CDC | No DeviceCustomFileEvents coverage | Added 3 CDC-specific queries (12-14) for low-level file telemetry |
