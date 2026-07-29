# Email Threat Landscape Q2 2026 — Notable Campaign Hunts

**Created:** 2026-07-29  
**Platform:** Both  
**Tables:** EmailEvents, EmailUrlInfo, EmailAttachmentInfo, UrlClickEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents  
**Keywords:** Q2 2026, email threat landscape, automated BEC, Amazon SES, Python email.mime, aging report, payroll diversion, role-based mailbox, reply-bait BEC, executive impersonation, nested EML, Teams archive recording, voicemail lure, ICS calendar invite, OAuth silent sign-in, multi-tenant app redirect, login.microsoftonline redirect, ClickUp attachments, pixeldrain, Financial_report.bat, hidden PowerShell, BAT dropper, installer.exe, ecajovna, 9i6pokerdepot, clickup-attachments, credential phishing, QR code phishing, CAPTCHA-gated  
**MITRE:** T1566.001, T1566.002, T1598.002, T1656, T1204.001, T1204.002, T1059.001, T1059.003, T1105, T1070.004, T1564.003, T1528, TA0001, TA0002, TA0005  
**Domains:** email, endpoint, identity  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Microsoft Threat Intelligence — Email threat landscape: Q2 2026 trends and insights (July 23, 2026)](https://www.microsoft.com/en-us/security/blog/2026/07/23/email-threat-landscape-q2-2026-trends-and-insights/)

---

## Threat Overview

Microsoft Threat Intelligence's Q2 2026 (April–June) email report tracks ~7.6 billion email-based phishing threats, the continued decline of the disrupted **Tycoon2FA** PhaaS platform (down 92% from pre-disruption averages, pivoting to `.RU` hosting), and the growth of **Teams-based vishing** (weekly malicious call attempts reaching ~10× the mid-2025 baseline). Credential phishing remained 94–96% of malicious payloads; ICS calendar-invite payloads nearly quadrupled (+277%) in June.

This campaign file covers the **two notable, technique-rich campaigns** detailed in the report that are **new for Q2** and not already covered by the companion files listed under [References](#references):

1. **Automated BEC at scale (June 1, 2026):** A single actor used Python's `email.mime` library and the Amazon SES API to programmatically send >67,000 messages to >42,000 organizations in under three hours (14:08–16:52 UTC), running an **aging-report** data-harvest lure and a **payroll-diversion** executive-impersonation lure from shared infrastructure. Messages were sent from a DKIM-signed Slovak domain (`ecajovna[.]sk`) through SES so they passed SPF and achieved DKIM alignment. Neither lure carried a link or attachment — both were **reply-bait** to attacker mailboxes mimicking legitimate providers. Targeting used **generic role-based mailboxes** (`ar`, `accountsreceivable`, `hr`, `payroll`) plus a 1×1 open-tracking pixel to prioritize follow-up.
2. **Nested-EML → OAuth redirect → BAT dropper (June 14–15, 2026):** A phishing campaign targeting >107,000 users across ~19,000 organizations impersonated an internal "Internal Affairs – Financials & Staff Updates" function. Each message carried a **nested EML** posing as a Teams archive recording and an **ICS** calendar invite. The EML rendered a voicemail lure whose button pointed at `login.microsoftonline[.]com` requesting a **silent sign-in** against an attacker-registered **multi-tenant Entra app**; because no session satisfied the silent request, Microsoft auth redirected the victim to the attacker's pre-registered destination on `clickup-attachments[.]com`, which served `Financial_report.bat`. The BAT ran hidden PowerShell that pulled `installer.exe` from `pixeldrain[.]com` into `%Temp%`, ran it silently, and self-deleted.

### TTP Summary

| Capability | TTP |
|---|---|
| Automated bulk BEC via Amazon SES + Python `email.mime` | T1566.002 (link-less reply-bait), T1656 (impersonation) |
| Aging-report data-harvest lure | T1598.002 (phishing for information) |
| Payroll-diversion CEO/President impersonation | T1656 (impersonation), T1534-adjacent social engineering |
| Role-based mailbox targeting (`ar`, `hr`, `payroll`) + tracking pixel | T1598.002 |
| Nested EML voicemail lure / Teams archive recording | T1566.001 (spearphishing attachment) |
| OAuth silent sign-in against attacker multi-tenant app → open redirect | T1528, T1566.002 |
| `login.microsoftonline.com` link masking the true destination | T1204.001 (malicious link) |
| BAT dropper delivered from OAuth error redirect | T1204.002 (malicious file), T1059.003 |
| Hidden PowerShell staged download of `installer.exe` to `%Temp%` | T1059.001, T1564.003, T1105 |
| Dropper self-deletes after silent install | T1070.004 |
| ICS calendar-invite payload delivery surge (+277% in June) | T1566.001 |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| Published IOCs are dated June 1 and June 14–15, 2026 — **outside a 30-day Advanced Hunting window** for runs after ~mid-July | Direct IOC sweeps (Q1, Q3) returning 0 in AH is the **expected clean result**. For retrospective coverage of the original wave, re-run the IOC sweeps in Sentinel Data Lake (>30d) with `Timestamp`→`TimeGenerated` on XDR-native tables |
| The automated BEC carried **no link and no attachment** and passed SPF/DKIM | Cannot rely on `ThreatTypes`/URL/attachment signals. Hunt the **behavioral** shape: inbound, first-contact, link-less, role-mailbox targeting (Query 2) |
| Python `email.mime` MIME boundary (`===============[integer]==`) and SES `Feedback-ID`/`Message-ID` formats are diagnostic of automation | These live in raw MIME headers **not exposed** in `Email*` Advanced Hunting tables — inspect via Threat Explorer / message headers, not KQL |
| `clickup-attachments.com`, `pixeldrain.com`, and `login.microsoftonline.com` are **legitimate services** | Domain-only matches produce false positives. The high-fidelity IOC is the **full URL path** (`.../Financial_report.bat`, `/api/file/3v92oJiL`) and the abnormal delivery of a `.bat` via a link (Query 4) |
| ICS and nested-EML attachments can be legitimate (calendar invites, forwarded mail) | Treat as low-volume anomalies; allowlist known-good calendar-invite senders and scheduling systems before promoting to a detection (Query 6) |
| IOC infrastructure rotates quickly after publication | Refresh the IOC lists from current Microsoft TI / Defender Threat Intelligence before relying on the sweeps |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Automated BEC — Published Domain & Sender IOC Sweep](#query-1-automated-bec--published-domain--sender-ioc-sweep) | Investigation | `EmailEvents` + `EmailUrlInfo` |
| 2 | [Automated BEC — Role-Based Mailbox Targeting at Scale](#query-2-automated-bec--role-based-mailbox-targeting-at-scale) | Investigation | `EmailEvents` |
| 3 | [Nested-EML → BAT Campaign — Published IOC Sweep (Email + Endpoint)](#query-3-nested-eml--bat-campaign--published-ioc-sweep-email--endpoint) | Investigation | `DeviceFileEvents` + multi |
| 4 | [Malicious `.bat` Link Delivery & Click-Through (ClickUp / pixeldrain)](#query-4-malicious-bat-link-delivery--click-through-clickup--pixeldrain) | Investigation | `EmailUrlInfo` + `UrlClickEvents` |
| 5 | [BAT Dropper — Hidden PowerShell Staged Download to `%Temp%`](#query-5-bat-dropper--hidden-powershell-staged-download-to-temp) | Investigation | `DeviceProcessEvents` |
| 6 | [Rare ICS Calendar-Invite Payload Delivery](#query-6-rare-ics-calendar-invite-payload-delivery) | Investigation | `EmailAttachmentInfo` + `EmailEvents` |
| 7 | [Nested EML Voicemail / Teams-Archive-Recording Lure Attachment](#query-7-nested-eml-voicemail--teams-archive-recording-lure-attachment) | Investigation | `EmailAttachmentInfo` |


## IOC Reference

Published indicators transcribed verbatim from the article's *Indicators of compromise* table. IOCs rot — refresh from current Microsoft Defender Threat Intelligence before operational use. Defanged as published; queries below use the refanged form.

**Campaign A — Automated BEC (first/last seen 2026-06-01)**

| Type | Indicator | Description |
|---|---|---|
| Domain | `ecajovna[.]sk` | Domain used to send campaign emails (DKIM-signed via SES) |
| Domain | `ilyff[.]com` | Reply-to domain used to receive victim responses |
| Domain | `j-gmails[.]com` | Reply-to domain used to receive victim responses |
| Domain | `x2mails[.]com` | Reply-to domain used to receive victim responses |
| Email | `contact[@]ecajovna[.]sk` | Address used to send campaign emails |
| Email | `mail[@]ilyff[.]com` | Reply-to address |
| Email | `me[@]j-gmails[.]com` | Reply-to address |
| Email | `me[@]x2mails[.]com` | Reply-to address |

**Campaign B — Nested-EML → OAuth redirect → BAT dropper (first/last seen 2026-06-15)**

| Type | Indicator | Description |
|---|---|---|
| Domain | `9i6pokerdepot[.]com` | Sending domain; DKIM-signed by the operator (Postfix via Barracuda) |
| Email | `Customer.Service[@]9i6pokerdepot[.]com` | Campaign sender address |
| Domain | `t90141296286.p.clickup-attachments[.]com` | ClickUp attachment subdomain hosting the stage-2 BAT dropper |
| URL | `hxxps://t90141296286.p.clickup-attachments[.]com/t90141296286/fb39c3a9-3161-40ad-847b-0683e0409d6f/Financial_report.bat` | Stage-2 BAT dropper download URL |
| URL | `hxxps://pixeldrain[.]com/api/file/3v92oJiL` | Final `installer.exe` payload download URL |
| File name | `Re: Teams Archive Recording for {{DATE2}}.eml` | Nested EML attachment template name (literal `{{DATE2}}` = unfilled per-recipient token) |
| File name | `Financial_report.bat` | Stage-2 dropper batch file delivered from the OAuth error redirect |

> **Not included here (already covered):** the article also republishes the April **code-of-conduct** wave IOCs (`compliance-protectionoutlook[.]de`, `acceptable-use-policy-calendly[.]de`, `cocinternal[.]com`, `gadellinet[.]com`, `harteprn[.]com`, associated senders, and three PDF SHA-256 hashes). Those are fully covered in the companion file [`code_of_conduct_aitm_phishing.md`](../2026-05/code_of_conduct_aitm_phishing.md) — do not duplicate.

---

## Query 1: Automated BEC — Published Domain & Sender IOC Sweep

**Purpose:** Hard IOC sweep for the June-1 automated BEC campaign's sending domain and the three reply-to domains/addresses across `EmailEvents` (envelope + header sender) and `EmailUrlInfo`. A 0-row result is the expected clean outcome when the wave predates the 30-day window; treat any match as delivery of the reply-bait BEC.  
**Severity:** High  
**MITRE:** T1566.002, T1656, T1598.002  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Q2 automated BEC IOC match — {{SenderFromAddress}}"
impactedAssets:
  - type: mailbox
    identifier: recipientEmailAddress
recommendedActions: "Confirm delivery in Threat Explorer and quarantine related messages. Because the lure is reply-bait (no link/attachment), warn the targeted role mailbox owners not to reply and block the reply-to domains in the Tenant Allow/Block List. Hunt for any outbound replies to the reply-to addresses."
adaptation_notes: "AH-native, Timestamp on XDR tables. The EmailEvents arm carries the mailbox entity (RecipientEmailAddress); the EmailUrlInfo arm is correlation only and rarely fires for this link-less campaign. IOC list is point-in-time (2026-06-01) — refresh before operational use; direct match will be 0 once the wave ages out of the 30-day window."
-->
```kql
// Q2 2026 automated BEC: published domain + sender/reply-to IOC sweep
let lookback = 30d;
let iocDomains = dynamic(["ecajovna.sk","ilyff.com","j-gmails.com","x2mails.com"]);
let iocSenders = dynamic(["contact@ecajovna.sk","mail@ilyff.com","me@j-gmails.com","me@x2mails.com"]);
union
  ( EmailEvents
    | where Timestamp > ago(lookback)
    | where SenderMailFromAddress in~ (iocSenders) or SenderFromAddress in~ (iocSenders)
        or SenderMailFromDomain in~ (iocDomains) or SenderFromDomain in~ (iocDomains)
    | extend Source = "EmailEvents"
    | project Timestamp, Source, NetworkMessageId, SenderFromAddress, SenderMailFromAddress,
              SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes ),
  ( EmailUrlInfo
    | where Timestamp > ago(lookback)
    | where UrlDomain in~ (iocDomains)
    | extend Source = "EmailUrlInfo"
    | project Timestamp, Source, NetworkMessageId, Url, UrlDomain )
| order by Timestamp desc
```
**Expected results:** 0 rows when the campaign predates the 30-day AH window (verified clean). Re-run in Sentinel Data Lake (>30d, `TimeGenerated`) for retrospective coverage of the original June wave.

---

## Query 2: Automated BEC — Role-Based Mailbox Targeting at Scale

**Purpose:** Behavioral hunt for the campaign shape when infrastructure has rotated: a single external sender/domain sending **link-less, attachment-less** inbound mail to **multiple generic role mailboxes** (`ar`, `accountsreceivable`, `hr`, `payroll`, etc.). This is the reply-bait BEC pattern that carries no URL/attachment signal and can pass SPF/DKIM.  
**Severity:** Medium  
**MITRE:** T1656, T1598.002  
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical aggregation (summarize with dcount/countif) — not row-level, so not directly CD-deployable. Also environment-specific: the role-mailbox list must be adapted to the org's actual shared mailboxes (exact local-part match). Use as an interactive/scheduled hunt; if promoting to a detection, convert to a row-level form with a per-sender volume threshold and an allowlist of known-good bulk senders (newsletters, ticketing, vendors) that legitimately mail role mailboxes."
-->
```kql
// Q2 2026 automated BEC: link-less inbound reply-bait hitting multiple role mailboxes
let lookback = 30d;
let roleMailboxes = dynamic([
  "ar","accountsreceivable","accounts.receivable","ap","accountspayable",
  "hr","payroll","accounting","finance","billing","invoices"]);
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where AttachmentCount == 0 and UrlCount == 0          // reply-bait: no link, no attachment
| extend RecipLocal = tolower(tostring(split(RecipientEmailAddress, "@")[0]))
| where RecipLocal in (roleMailboxes)
| summarize Messages = count(), RoleMailboxesHit = dcount(RecipientEmailAddress),
    RecipRoles = make_set(RecipLocal, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
    DeliveredCount = countif(DeliveryAction == "Delivered")
    by SenderFromDomain, SenderFromAddress
| where RoleMailboxesHit >= 2                            // one sender fanning out across role mailboxes
| order by Messages desc
```
**Expected results:** 0 in environments with no externally-addressable role mailboxes. Where role mailboxes exist, tune the list to the org's real shared mailboxes and allowlist legitimate bulk senders that mail those addresses at volume.

---

## Query 3: Nested-EML → BAT Campaign — Published IOC Sweep (Email + Endpoint)

**Purpose:** Hard IOC sweep for the June-14/15 nested-EML campaign across email delivery (`EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`) and endpoint landing (`DeviceFileEvents`, `DeviceNetworkEvents`) for the sending domain, ClickUp/pixeldrain hosts, the BAT file name, and the Teams-archive EML template name.  
**Severity:** High  
**MITRE:** T1566.001, T1566.002, T1204.002, T1105  
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table union spans mailbox (Email*) and device (Device*) entities, so it cannot map to a single impactedAssets type for a clean CD deployment — split into per-table detections if deploying (Email arm → mailbox; Device arm → device). Domain-level matches on clickup-attachments.com / pixeldrain.com will false-positive on legitimate use — prefer the full-path URL IOCs. Point-in-time IOCs (2026-06-15); refresh before use."
-->
```kql
// Q2 2026 nested-EML/BAT campaign: published IOC sweep across email + endpoint
let lookback = 30d;
let iocDomains = dynamic(["9i6pokerdepot.com","clickup-attachments.com","pixeldrain.com"]);
let iocFiles = dynamic(["Financial_report.bat"]);
let emlNameToken = "Teams Archive Recording";
union
  ( EmailEvents
    | where Timestamp > ago(lookback)
    | where SenderFromDomain in~ (iocDomains) or SenderMailFromDomain in~ (iocDomains)
        or SenderFromAddress =~ "Customer.Service@9i6pokerdepot.com"
    | extend Source = "EmailEvents"
    | project Timestamp, Source, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes ),
  ( EmailUrlInfo
    | where Timestamp > ago(lookback)
    | where UrlDomain has_any (iocDomains)
    | extend Source = "EmailUrlInfo"
    | project Timestamp, Source, NetworkMessageId, Url, UrlDomain ),
  ( EmailAttachmentInfo
    | where Timestamp > ago(lookback)
    | where FileName in~ (iocFiles) or FileName has emlNameToken
    | extend Source = "EmailAttachmentInfo"
    | project Timestamp, Source, NetworkMessageId, FileName, FileType, SHA256, ThreatTypes ),
  ( DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ (iocFiles) or FileOriginUrl has_any (iocDomains)
    | extend Source = "DeviceFileEvents"
    | project Timestamp, Source, DeviceName, FileName, FolderPath, FileOriginUrl, InitiatingProcessFileName ),
  ( DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteUrl has_any (iocDomains)
    | extend Source = "DeviceNetworkEvents"
    | project Timestamp, Source, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine )
| order by Timestamp desc
```
**Expected results:** 0 rows when the wave predates the window (verified clean). Any `DeviceFileEvents`/`DeviceNetworkEvents` hit indicates the endpoint reached the dropper stage — pivot immediately to Query 5.

---

## Query 4: Malicious `.bat` Link Delivery & Click-Through (ClickUp / pixeldrain)

**Purpose:** Detect the distinctive delivery artifact of Campaign B — a **URL that points at a `.bat` file** and/or the ClickUp/pixeldrain payload hosts — in both email URLs (`EmailUrlInfo`) and Safe Links activations (`UrlClickEvents`). Delivering an executable batch file via a link is highly abnormal, so this catches rotated infrastructure using the same technique.  
**Severity:** High  
**MITRE:** T1566.002, T1204.001, T1105  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Link to .bat / payload host clicked — {{AccountUpn}}"
impactedAssets:
  - type: user
    identifier: accountUpn
recommendedActions: "A URL delivering a .bat is almost always malicious. If UrlClickEvents shows IsClickedThrough, treat the endpoint as suspected dropper execution: isolate/triage the device, hunt DeviceProcessEvents for a hidden-PowerShell download to %Temp% (Query 5), and check for installer.exe in Temp. Quarantine the source message and block the host."
adaptation_notes: "AH-native. The UrlClickEvents arm carries the user entity (AccountUpn); the EmailUrlInfo arm is correlation. The generic 'Url endswith .bat' clause is high-fidelity but review for rare legitimate internal automation links; the clickup-attachments.com/pixeldrain.com host clauses are broader and may catch legitimate service use — pair with the .bat clause for precision."
-->
```kql
// Q2 2026 nested-EML/BAT campaign: link-delivered .bat and ClickUp/pixeldrain payload hosts
let lookback = 30d;
let iocHosts = dynamic(["clickup-attachments.com","pixeldrain.com"]);
union
  ( EmailUrlInfo
    | where Timestamp > ago(lookback)
    | where Url has_any (iocHosts) or Url endswith ".bat"
    | extend Source = "EmailUrlInfo"
    | project Timestamp, Source, NetworkMessageId, Url, UrlDomain, UrlLocation ),
  ( UrlClickEvents
    | where Timestamp > ago(lookback)
    | where Url has_any (iocHosts) or Url endswith ".bat"
    | extend Source = "UrlClickEvents"
    | project Timestamp, Source, NetworkMessageId, Url, AccountUpn, IPAddress, ActionType, IsClickedThrough )
| order by Timestamp desc
```
**Expected results:** 0 rows in a clean window (verified). A `UrlClickEvents` row with `IsClickedThrough == 1` is the highest-priority outcome — the user reached the payload host.

---

## Query 5: BAT Dropper — Hidden PowerShell Staged Download to `%Temp%`

**Purpose:** Detect the endpoint execution stage — hidden-window PowerShell that downloads a payload (e.g., `installer.exe`) into `%Temp%`/AppData, or any PowerShell referencing the ClickUp/pixeldrain hosts. This is the `Financial_report.bat` → `powershell -w hidden` → `pixeldrain` → `%Temp%\installer.exe` chain, generalized so it survives IOC rotation.  
**Severity:** High  
**MITRE:** T1059.001, T1564.003, T1105, T1204.002  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Hidden PowerShell staged download to Temp — {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Review the full ProcessCommandLine and the initiating process (a .bat/cmd parent strongly corroborates the campaign). Locate and hash the downloaded executable in %Temp%, submit for analysis, isolate the device if confirmed, and hunt for follow-on execution and C2. The dropper self-deletes, so capture the file quickly."
adaptation_notes: "Single-table DeviceProcessEvents, device entity. Uses let for readability (schedule 1H tolerates let); for NRT convert let arrays to inline where-clauses. The IOC-host clause (pixeldrain/clickup) is high fidelity; the generic hidden-download-to-Temp clause is behavioral — tune by allowlisting known software-deployment tooling (SCCM/Intune, vendor updaters) that legitimately runs hidden PowerShell downloads."
-->
```kql
// Q2 2026 BAT dropper: hidden PowerShell staged download of an executable to Temp
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("pixeldrain.com","clickup-attachments.com")
    or (
        ProcessCommandLine has_any ("-w hidden","-windowstyle hidden","-windowstyle 1","/w hidden","-win h","-w h")
        and ProcessCommandLine has_any ("DownloadFile","DownloadString","Invoke-WebRequest","iwr","Start-BitsTransfer","curl ","wget ","Net.WebClient")
        and ProcessCommandLine has_any ("temp","%temp%","appdata")
        and ProcessCommandLine has ".exe"
       )
| project Timestamp, DeviceName, AccountUpn, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, ProcessIntegrityLevel
| order by Timestamp desc
```
**Expected results:** 0 rows in a clean window. Hidden-window PowerShell is common on its own, but the combination of a hidden window **and** a download primitive **and** a `%Temp%`/AppData path **and** a `.exe` target is highly selective, so the filter stays low-noise rather than firing on routine administrative scripting. Any hit with a `.bat`/`cmd.exe` parent is a strong Campaign-B indicator.

---

## Query 6: Rare ICS Calendar-Invite Payload Delivery

**Purpose:** Surface inbound messages carrying **ICS calendar-invite** attachments — a Q2 payload vector that rose +277% in June and, in Campaign B, accompanied the nested EML. ICS attachments are processed differently from normal attachments and can inject links into a calendar without an explicit open-and-click. In most tenants these are rare, making them a useful low-volume anomaly.  
**Severity:** Low  
**MITRE:** T1566.001  
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Join of EmailAttachmentInfo and EmailEvents (not NRT-eligible) and inherently FP-prone: legitimate meeting invites carry .ics. Requires an environment-specific allowlist of known-good calendar-invite senders and scheduling systems (e.g., first-party notification addresses, internal room/resource mailboxes) before it is detection-grade. Best used as a scheduled hunt; prioritize rows that are first-contact, from external free/low-reputation domains, or paired with a nested .eml attachment."
-->
```kql
// Q2 2026 ICS calendar-invite payload delivery (low-volume anomaly hunt)
let lookback = 30d;
let icsMsgs = EmailAttachmentInfo
    | where Timestamp > ago(lookback)
    | where FileName endswith ".ics" or FileType =~ "ics"
    | summarize IcsFileNames = make_set(FileName, 10) by NetworkMessageId;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| join kind=inner icsMsgs on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
    Subject, IcsFileNames, AttachmentCount, UrlCount, DeliveryAction, ThreatTypes, IsFirstContact
| order by Timestamp desc
```
**Expected results:** Very low volume in most tenants. Expect legitimate calendar invites (e.g., first-party `noreply@` scheduling systems) — allowlist those. Prioritize first-contact ICS from external low-reputation domains, especially messages that also carry a nested `.eml` (Query 7).

---

## Query 7: Nested EML Voicemail / Teams-Archive-Recording Lure Attachment

**Purpose:** Detect the nested `.eml` attachment that Campaign B used to render the voicemail lure ("Re: Teams Archive Recording for {{DATE2}}.eml"). A nested EML posing as a Teams recording or voicemail is an abnormal attachment type and a strong campaign indicator even after infrastructure rotates.  
**Severity:** Medium  
**MITRE:** T1566.001  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Nested EML voicemail/Teams-recording lure attachment — {{RecipientEmailAddress}}"
impactedAssets:
  - type: mailbox
    identifier: recipientEmailAddress
recommendedActions: "Render the message in Threat Explorer and inspect the nested EML for a voicemail/Teams-recording lure with a single action button pointing at login.microsoftonline.com (silent-sign-in redirect). Quarantine the message, and if any recipient interacted, pivot to Query 4 (link click) and Query 5 (endpoint dropper)."
adaptation_notes: "Single-table EmailAttachmentInfo, mailbox entity. The .eml + lure-name combination is high fidelity because nested EML attachments are rare relative to overall attachment volume. The name-token list may be broadened for other voicemail/recording lures; a bare .eml match without the name filter is too broad on its own."
-->
```kql
// Q2 2026 nested-EML campaign: voicemail / Teams archive recording lure attachment
let lookback = 30d;
EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where FileName endswith ".eml" or FileType =~ "eml"
| where FileName has_any ("Teams Archive Recording","Archive Recording","Teams Recording","voicemail","voice mail","voice message","new voice")
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
    FileName, FileType, FileExtension, SHA256, ThreatTypes
| order by Timestamp desc
```
**Expected results:** 0 rows in a clean window. Nested `.eml` attachments carrying a voicemail/Teams-recording lure name are rare relative to overall attachment volume, so any match is high-priority and warrants message inspection.

---

## General Tuning Notes

1. **IOC refresh.** All indicators are point-in-time (June 1 and June 14–15, 2026). The reply-to, sending, and payload-host infrastructure rotates quickly after publication. Refresh the `iocDomains`/`iocSenders`/`iocFiles`/`iocHosts` lists from current Microsoft Defender Threat Intelligence (or a TI indicator table) before relying on Queries 1, 3, 4.
2. **30-day window vs. original wave.** For runs after ~mid-July 2026 the published waves fall outside the Advanced Hunting 30-day cap, so the direct IOC sweeps (Queries 1, 3) correctly return 0. For retrospective hunting of the original June activity, re-run those sweeps in **Sentinel Data Lake** (>30d) and adapt `Timestamp`→`TimeGenerated` on the XDR-native tables.
3. **Legitimate-service noise.** `clickup-attachments.com`, `pixeldrain.com`, and `login.microsoftonline.com` are legitimate. Prefer full-URL-path IOCs over domain-only matches (Query 4), and allowlist sanctioned software-deployment tooling that runs hidden PowerShell downloads (Query 5).
4. **Behavioral vs. IOC coverage.** Queries 2, 5, 6, 7 are technique-based and survive infrastructure rotation; Queries 1, 3, 4 are IOC-anchored for the specific June waves. Run both classes together.
5. **CD-readiness summary.** `cd_ready: true` — Queries 1, 4, 5, 7 (single dominant entity, high-fidelity, validated clean). `cd_ready: false` — Query 2 (statistical aggregation + environment-specific role list), Query 3 (mixed mailbox/device entities across a union), Query 6 (FP-prone join requiring a known-good-sender allowlist). See each query's `adaptation_notes`.

---

## References

- Microsoft Threat Intelligence — [Email threat landscape: Q2 2026 trends and insights (July 23, 2026)](https://www.microsoft.com/en-us/security/blog/2026/07/23/email-threat-landscape-q2-2026-trends-and-insights/)
- Microsoft Threat Intelligence — [Inside Tycoon2FA: how a leading AiTM phishing kit operated at scale](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)
- Microsoft Threat Intelligence — [Breaking the code: Multi-stage 'code of conduct' phishing campaign leads to AiTM token compromise](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/)
- MITRE ATT&CK — [T1566.002 Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/), [T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/), [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1656 Impersonation](https://attack.mitre.org/techniques/T1656/)
- Companion files: [`queries/threat-intelligence/2026-04/email_threat_landscape_q1_2026.md`](../2026-04/email_threat_landscape_q1_2026.md), [`queries/threat-intelligence/2026-05/code_of_conduct_aitm_phishing.md`](../2026-05/code_of_conduct_aitm_phishing.md), [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md)
