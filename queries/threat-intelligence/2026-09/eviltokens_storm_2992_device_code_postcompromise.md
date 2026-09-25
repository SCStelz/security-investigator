# EvilTokens (Storm-2992) — Device Code Phishing Post-Compromise Chains — Threat Hunts

**Created:** 2026-09-25  
**Platform:** Microsoft Defender XDR  
**Tables:** EntraIdSignInEvents, AuditLogs, GraphAPIAuditEvents, CloudAppEvents, OfficeActivity, EmailEvents, EmailUrlInfo, EmailAttachmentInfo, UrlClickEvents, DeviceEvents, AlertInfo, AlertEvidence  
**Keywords:** EvilTokens, Storm-2992, phishing-as-a-service, PhaaS, device code phishing, device code flow, Cmsi:cmsi, OAuth device authorization grant, token theft, AI-assisted BEC, business email compromise, device registration, Primary Refresh Token, PRT persistence, Microsoft Authentication Broker, Register device, Graph reconnaissance, directory enumeration, directoryRoles, servicePrincipals, inbox rule, New-InboxRule, UpdateInboxRules, internal phishing, trusted-contact phishing, access token residual window, revokeSignInSessions, ConfirmAccountCompromised, Disable account, BrowserLaunchedToOpenUrl, Safe Links, Vercel, Cloudflare Workers, AWS Lambda, serverless redirect, password expiration lure, eFax, voicemail lure, RFP lure, invoice lure  
**MITRE:** T1566.001, T1566.002, T1528, T1550.001, T1078.004, T1098.005, T1087.004, T1069.003, T1114.002, T1564.008, T1534, TA0001, TA0003, TA0006, TA0007, TA0009  
**Domains:** identity, email, cloud  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Unmasking EvilTokens: Getting to the root of device code phishing (2026-09-22)](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)

---

## Threat Overview

**EvilTokens** is an AI-enabled phishing-as-a-service platform, developed and supported by the actor Microsoft tracks as **Storm-2992**, that emerged in February 2026 and compromised **more than 12,000 inboxes in over 10,000 organizations** before a Microsoft Digital Crimes Unit–led disruption. Subscribers ($1,500 up front, $500/month) get 44 lure themes, AI-written role-targeted emails, Cloudflare Workers/Bunny or PHP hosting, CAPTCHA gates, and a panel that auto-refreshes stolen tokens, detects admin accounts and keyword-scans inboxes with Telegram alerts.

The kit abuses the **OAuth device code flow**. When the victim clicks a lure (URL, PDF or HTML attachment; redirects frequently via `*.vercel.app`, `*.workers.dev` and AWS Lambda), a background script requests a **live device code**, copies it to the clipboard, and opens the genuine `microsoft.com/devicelogin` page, polling the actor's `/state` endpoint every 3–5 seconds. Pasting the code (plus password/MFA if no session exists) authenticates the **actor's** session. Post-compromise, actors **registered a new device within ~10 minutes** to obtain a Primary Refresh Token, or waited **hours** before creating concealing inbox rules and exfiltrating mail; used **Microsoft Graph to map organizational structure and permissions**; used AI to pick high-value finance/executive targets; and **sent further phishing from the compromised mailbox** to internal and external contacts. Microsoft notes that standard session revocation leaves **existing access tokens usable for up to an hour**, which hands-on actors exploit — hence the recommendation to temporarily disable compromised accounts.

> **Companion file:** [`queries/identity/device_code_phishing.md`](../../identity/device_code_phishing.md) (April 2026 EvilToken campaign) already covers device-code sign-in detection (ErrorCode 50199, `Cmsi:cmsi`), the April IOC IP ranges, serverless-redirect clicks, `Device Registration Service` activity, inbox-rule property hunts and MailItemsAccessed volume. **This file adds only the post-compromise *chains* and response-gap hunts** described in the September 2026 reporting. Run both.

### TTP Summary

| Capability | TTP |
|---|---|
| Lure delivery | AI-personalized emails, 44 themes (password expiry, doc-signing, voicemail/eFax, invoices, RFPs, shared files) with URLs, PDF or HTML attachments (T1566.001, T1566.002) |
| Evasion | Image links, multi-stage redirects via compromised sites and serverless hosts (Vercel, Cloudflare Workers, AWS Lambda), fake CAPTCHA gates |
| Token theft | Live device code generated at click time; clipboard auto-copy; real `microsoft.com/devicelogin`; `/state` polling (T1528) |
| Persistence | New device registration within ~10 min of compromise to mint a PRT (T1098.005) |
| Discovery | Microsoft Graph mapping of org structure and permissions (T1087.004, T1069.003) |
| Collection | AI-assisted mailbox triage; targeted searches for wire transfers, invoices, executive mail (T1114.002) |
| Defense evasion | Concealing inbox rules created hours after sign-in (T1564.008) |
| Lateral phishing | Follow-on phishing from the compromised account to internal and external contacts (T1534) |
| Response gap | Access tokens remain valid up to ~1 hour after refresh-token revocation (T1550.001) |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **Device code flow is legitimate admin tooling** | Azure CLI, Azure PowerShell, Graph PowerShell, VS Code and conference devices all use it. Never alert on `EndpointCall has "Cmsi:cmsi"` alone — every query here requires a **follow-on behavior** (registration, recon, rules, mass send, residual access). |
| **The device-code token rarely links directly to downstream API calls** | The initial `UniqueTokenId` is typically exchanged for refresh-derived access tokens, so joining `EntraIdSignInEvents.UniqueTokenId` to `GraphAPIAuditEvents.UniqueTokenIdentifier` almost never matches. Correlate on **user + client ApplicationId + time window** instead (Query 3). |
| **Mobile Authenticator enrollment looks like device code + device registration** | Setting up Microsoft Authenticator on iOS/Android can produce a `Cmsi:cmsi` sign-in and `Register device` within minutes from the user's own phone and IP. Query 2 down-ranks the same-IP mobile shape; attacker-registered devices are typically **Windows** via **Microsoft Authentication Broker** from hosting infrastructure. |
| **`CloudAppEvents.AccountId` is a GUID, not a UPN** | Filtering `AccountId in~ (<UPN list>)` silently returns 0 rows. Use `AccountObjectId` (Queries 4, 6). |
| **Inbox rules live in two tables** | `CloudAppEvents` gives ActionType + identity; `OfficeActivity` gives the full `Parameters` JSON and `ClientIP`. Query 4 unions both. |
| **Password resets are not containment** | Resets are frequent and leave access tokens valid. Query 6 only anchors on `Disable account`, refresh-token invalidation, and `ConfirmAccountCompromised`. |
| **Admin portals generate enormous Graph volume** | Security and Compliance Center / Azure Portal sessions call `/users/{upn}` constantly for people cards. Query 3 normalizes IDs/UPNs out of paths and counts **distinct endpoints**, not calls. |
| **Attack-simulation and click-simulation tooling produce real-looking clicks** | Safe Links detonation and phishing-simulation platforms click from their own infrastructure. Exclude those sources by IP/sender after verifying them; keep the device-code-after-click correlation (Query 7) as the discriminator. |
| **AH caps at 30 days** | For older compromises, port the chains to the Data Lake (`SigninLogs`/`AADNonInteractiveUserSignInLogs` with `AuthenticationProtocol == "deviceCode"`, `MicrosoftGraphActivityLogs`, `AuditLogs`, `OfficeActivity`). |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [EvilTokens-aligned Defender detections with evidence entities](#query-1-eviltokens-aligned-defender-detections-with-evidence-entities) | Detection | `AlertInfo` |
| 2 | [Device code sign-in followed by new device registration (PRT persis...](#query-2-device-code-sign-in-followed-by-new-device-registration-prt-persistence) | Investigation | `AuditLogs` + `EntraIdSignInEvents` |
| 3 | [Device code sign-in followed by Graph directory reconnaissance and ...](#query-3-device-code-sign-in-followed-by-graph-directory-reconnaissance-and-mail-access-same-client-app) | Investigation | `EntraIdSignInEvents` + `GraphAPIAuditEvents` |
| 4 | [Device code sign-in followed by (delayed) inbox rule creation — bot...](#query-4-device-code-sign-in-followed-by-delayed-inbox-rule-creation--both-audit-sources) | Detection | `CloudAppEvents` + multi |
| 5 | [Device code sign-in followed by a burst of outbound or internal mai...](#query-5-device-code-sign-in-followed-by-a-burst-of-outbound-or-internal-mail-trusted-contact-phishing) | Investigation | `EmailEvents` + `EntraIdSignInEvents` |
| 6 | [Residual token use after containment (the ~1-hour access-token window)](#query-6-residual-token-use-after-containment-the-1-hour-access-token-window) | Investigation | `AuditLogs` + multi |
| 7 | [MDO-alerted phishing mail → click or browser open → device code sig...](#query-7-mdo-alerted-phishing-mail--click-or-browser-open--device-code-sign-in-within-an-hour) | Detection | `AlertInfo` + multi |
| 8 | [Detected-but-delivered phishing that is still in the mailbox, with ...](#query-8-detected-but-delivered-phishing-that-is-still-in-the-mailbox-with-eviltokens-lure-shape) | Detection | `EmailAttachmentInfo` + multi |


## IOC Reference

> The September 2026 article publishes **no new indicators** (no hashes, domains or IPs) — Microsoft's DCU disruption took down EvilTokens infrastructure and the reporting focuses on the platform and TTPs. The **April 2026** EvilToken IP ranges and brand-impersonation domains remain in the companion file ([`device_code_phishing.md`](../../identity/device_code_phishing.md), Queries 4/4b). The hunts below are behavioral by design and survive infrastructure rotation.

**Behavioral indicators cited in the article:**

| Indicator | Type | Description |
|---|---|---|
| `microsoft.com/devicelogin` | Legitimate URL (abused) | Real Microsoft code-entry page the victim is steered to |
| `/state` polling every 3–5 s | Network behavior | Actor backend polling for token capture (not visible in tenant telemetry) |
| `*.vercel.app`, `*.workers.dev`, AWS Lambda | Hosting pattern | Serverless redirect hosting — legitimate platforms, match only in correlation |
| Device registration within ~10 minutes | Timing | PRT persistence after token capture |
| Inbox rule hours after sign-in | Timing | Delayed concealment to avoid immediate detection |

---

## Query 1: EvilTokens-aligned Defender detections with evidence entities

**Purpose:** Pulls the Defender for Identity / Defender XDR detections Microsoft lists for EvilTokens (device code authentication, token exchange, device registration, Graph activity and inbox rules after device code phishing), with accounts, IPs and devices from evidence, and flags synthetic risk-score test injections by their literal user-agent marker. Start triage here, then pivot each account into Queries 2–6.  
**Severity:** Medium  
**MITRE:** T1528, T1098.005, T1087.004, T1564.008

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Alert-correlation triage over existing Defender detections - re-alerting would duplicate them. Use as the entry point, then pivot per account. Validated: returned device code authentication alerts in the validation tenant; join to SecurityIncident on ProviderIncidentId for current status and classification."
-->

```kql
let lookback = 30d;
let EvilTokensDetections = dynamic([
  "Anomalous OAuth device code authentication activity",
  "Anomalous token exchange following device code authentication",
  "User account compromise via OAuth device code phishing",
  "Suspicious Azure authentication through possible device code phishing",
  "Suspicious Entra device join or registration",
  "Device registration after potential device code phishing",
  "Anomalous Microsoft Graph API activity after potential device code phishing",
  "Anomalous Microsoft Graph API POST activity after potential device code phishing",
  "Suspicious inbox rule created after potential device code phishing sign-in"]);
AlertInfo
| where Timestamp > ago(lookback)
| where Title has_any (EvilTokensDetections) or (Title has "device code")
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | summarize Accounts = make_set_if(coalesce(AccountUpn, AccountName), isnotempty(coalesce(AccountUpn, AccountName)), 10),
                IPs = make_set_if(RemoteIP, isnotempty(RemoteIP), 10),
                Devices = make_set_if(DeviceName, isnotempty(DeviceName), 5),
                UAs = make_set_if(tostring(parse_json(AdditionalFields).UserAgent), isnotempty(tostring(parse_json(AdditionalFields).UserAgent)), 5)
        by AlertId
  ) on AlertId
| extend SyntheticTestMarker = tostring(UAs) has "!!RiskScoreTesting"
| project Timestamp, AlertId, Title, Severity, ServiceSource, DetectionSource, Category, AttackTechniques, Accounts, IPs, Devices, SyntheticTestMarker
| order by Timestamp desc
```

**Expected results:** A short list in most tenants. Each alert typically appears twice (Defender for Identity and Defender XDR service sources). Prioritize accounts with registration, Graph or inbox-rule alerts over sign-in-only alerts; confirm incident status in the Defender portal.

---

## Query 2: Device code sign-in followed by new device registration (PRT persistence)

**Purpose:** EvilTokens actors registered a new device within ~10 minutes of capturing tokens to mint a Primary Refresh Token. Joins successful device code sign-ins (`Cmsi:cmsi`) to `Register device` audit events for the **same user within ±30 minutes**, surfacing registration OS/trust type, the registering IP, and whether the device code client was **Microsoft Authentication Broker** (the client used to reach the Device Registration Service). A symmetric window is used because sign-in and audit timestamps for broker flows can interleave.  
**Severity:** High  
**MITRE:** T1098.005, T1528

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table correlation (EntraIdSignInEvents join AuditLogs with a time window) - run as a scheduled hunt or Sentinel analytics rule. Validated: 1 pre-tuning match in the live validation tenant - a user enrolling Microsoft Authenticator on an iPhone from their own residential IP (Cmsi sign-in 6 minutes after 'Register device', same IP and iOS user agent). The Priority column down-ranks this mobile same-IP enrollment shape rather than filtering it, because a stolen token can also register a mobile device. The companion file's Query 7 covers single-table Device Registration Service activity for CD use."
-->

```kql
let lookback = 30d;
let regWindow = 30m;
let DeviceCode = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where EndpointCall has "Cmsi:cmsi" and ErrorCode == 0
| project DcTime = Timestamp, AccountObjectId, AccountUpn, DcIP = IPAddress, DcCountry = Country, DcApp = Application, DcAppId = ApplicationId, DcUA = UserAgent;
let Registrations = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName == "Register device" and Result =~ "success"
| extend Init = parse_json(tostring(InitiatedBy)), AD = parse_json(tostring(AdditionalDetails))
| mv-apply d = AD on (summarize DeviceOS = take_anyif(tostring(d.value), tostring(d.key) == "Device OS"),
                                TrustType = take_anyif(tostring(d.value), tostring(d.key) == "Device Trust Type"),
                                RegDeviceId = take_anyif(tostring(d.value), tostring(d.key) == "Device Id"))
| project RegTime = TimeGenerated, AccountObjectId = tostring(Init.user.id), RegIP = tostring(Init.user.ipAddress), DeviceOS, TrustType, RegDeviceId,
          RegDeviceName = tostring(parse_json(tostring(TargetResources))[0].displayName);
DeviceCode
| join kind=inner Registrations on AccountObjectId
| where RegTime between ((DcTime - regWindow) .. (DcTime + regWindow))
| extend MinutesDcToRegister = round(datetime_diff("second", RegTime, DcTime) / 60.0, 1),
         SameIP = DcIP == RegIP,
         BrokerFlow = DcAppId == "29d9ed98-a469-4536-ade2-f981bc1d605e",
         MobileEnrollmentShape = DeviceOS in~ ("iOS", "iPhone", "Android", "iPad") and DcUA has_any ("iPhone", "iPad", "Android")
| extend Priority = case(MobileEnrollmentShape and SameIP, "Low", BrokerFlow or DeviceOS =~ "Windows", "High", "Medium")
| project DcTime, RegTime, MinutesDcToRegister, AccountUpn, DcApp, DcIP, RegIP, SameIP, DcCountry, DcUA,
          RegDeviceName, RegDeviceId, DeviceOS, TrustType, BrokerFlow, MobileEnrollmentShape, Priority
| order by Priority asc, abs(MinutesDcToRegister) asc
```

**Expected results:** 0 rows in most tenants. A `High` row — Windows registration or a Broker device code flow, especially from an IP the user has never used — should be treated as PRT persistence: **disable the registered device in Entra, revoke refresh tokens, and temporarily disable the account** (Microsoft's guidance given the ~1 hour access-token window).

---

## Query 3: Device code sign-in followed by Graph directory reconnaissance and mail access (same client app)

**Purpose:** EvilTokens actors "programmatically mapped internal organizational structures and identified sensitive permissions the moment a token was secured." For each successful device code sign-in, this finds Graph calls by the **same user through the same client application** in the next 24 hours, normalizes object IDs/UPNs out of request paths, and counts **distinct** directory-recon endpoints (users, groups, directory roles, role management, service principals, applications, organization, manager/direct reports) and mail endpoints. It flags device code sign-ins from an IP the user had not used for a normal sign-in in the prior 14 days.  
**Severity:** High  
**MITRE:** T1087.004, T1069.003, T1114.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table correlation with a baseline - hunt or Sentinel analytics rule. Validated in a live tenant: pre-tuning, counting raw paths and joining on user only surfaced 25 admin users (portal people-card lookups and CLI administration). Joining on the device code client ApplicationId, normalizing GUIDs/UPNs out of paths, and excluding service-announcement 'messages' reduced this to 6 rows, 1 of them on a new device code IP. Token-ID linkage (UniqueTokenId to UniqueTokenIdentifier) matched 0 of these calls, which confirms the same-app join is required. Expect admin tooling (Graph PowerShell / Azure CLI) to appear; the Priority column (new IP + mail access) is the discriminator."
-->

```kql
let lookback = 30d;
let baseline = 14d;
let followWindow = 24h;
let minReconEndpoints = 5;
let DeviceCode = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where EndpointCall has "Cmsi:cmsi" and ErrorCode == 0
| project DcTime = Timestamp, AccountObjectId, AccountUpn, DcAppId = ApplicationId, DcApp = Application, DcIP = IPAddress, DcCountry = Country;
let PriorIPs = EntraIdSignInEvents
| where Timestamp > ago(lookback + baseline)
| where ErrorCode == 0 and EndpointCall !has "Cmsi:cmsi"
| summarize PriorFirst = min(Timestamp) by AccountObjectId, IPAddress;
let DeviceCodeScored = DeviceCode
| join kind=leftouter PriorIPs on AccountObjectId, $left.DcIP == $right.IPAddress
| extend NewDcIP = isnull(PriorFirst) or PriorFirst >= DcTime
| summarize DcTime = min(DcTime), DcIPs = make_set(DcIP, 5), DcCountries = make_set(DcCountry, 5), AnyNewDcIP = max(toint(NewDcIP))
    by AccountObjectId, AccountUpn, DcAppId, DcApp;
GraphAPIAuditEvents
| where Timestamp > ago(lookback)
| where isnotempty(AccountObjectId)
| join kind=inner DeviceCodeScored on AccountObjectId, $left.ApplicationId == $right.DcAppId
| where Timestamp between (DcTime .. (DcTime + followWindow))
| extend Path = tolower(tostring(split(tostring(split(RequestUri, "?")[0]), ".com/")[1]))
| extend Endpoint = replace_regex(Path, @"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[^/]+(%40|@)[^/]+|%23anonymized%23[^/]+", "{id}")
| extend Category = case(
    Endpoint has "serviceannouncement", "Other",
    Endpoint has_any ("/users", "/groups", "/memberof", "/transitivememberof", "/directoryroles", "/rolemanagement", "/organization", "/directreports", "/manager", "/people", "/contacts", "/serviceprincipals", "/applications", "/domains", "/subscribedskus", "/oauth2permissiongrants", "/approleassignments"), "DirectoryRecon",
    Endpoint has_any ("/messages", "/mailfolders", "/inbox", "/sendmail", "/attachments", "/messagerules"), "Mail",
    Endpoint has_any ("/drive", "/sites"), "Files",
    "Other")
| summarize Calls = count(),
    ReconCalls = countif(Category == "DirectoryRecon"), MailCalls = countif(Category == "Mail"), FileCalls = countif(Category == "Files"),
    ReconEndpoints = dcountif(Endpoint, Category == "DirectoryRecon"),
    SampleReconEndpoints = make_set_if(Endpoint, Category == "DirectoryRecon", 15),
    MailEndpoints = make_set_if(Endpoint, Category == "Mail", 10),
    Methods = make_set(RequestMethod, 5), GraphIPs = make_set(IpAddress, 10),
    FirstCall = min(Timestamp), LastCall = max(Timestamp)
    by AccountUpn, AccountObjectId, DcApp, DcTime, AnyNewDcIP, DcIPsText = tostring(DcIPs), DcCountriesText = tostring(DcCountries)
| where ReconEndpoints >= minReconEndpoints or MailCalls > 0
| extend MinutesToFirstCall = round(datetime_diff("second", FirstCall, DcTime) / 60.0, 1)
| extend Priority = case(AnyNewDcIP == 1 and MailCalls > 0, "High", AnyNewDcIP == 1, "Medium", "Low")
| order by AnyNewDcIP desc, MailCalls desc, ReconEndpoints desc
| project-away AccountObjectId
```

**Expected results:** Administrators using Graph PowerShell or Azure CLI with device code will appear as `Low`. Investigate `Medium`/`High` rows: a device code sign-in from a new IP followed within minutes by GET-only enumeration of directory roles, role members, service principals and applications — and especially any `/messages` or `/mailFolders` access — matches the EvilTokens post-compromise shape. Confirm with the user whether they started a device code sign-in.

---

## Query 4: Device code sign-in followed by (delayed) inbox rule creation — both audit sources

**Purpose:** Actors "waited several hours before creating malicious inbox rules." For each device code user, finds inbox rule / mailbox forwarding operations in **`CloudAppEvents` (by `AccountObjectId`) and `OfficeActivity` (by UPN)** within 72 hours, computes the delay, and flags forwarding, concealment (move/delete/mark-read, RSS or Archive folders) and finance keywords in the rule parameters. This corrects a common chain-query bug: filtering `CloudAppEvents.AccountId` (a GUID) by UPN silently returns nothing.  
**Severity:** High  
**MITRE:** T1564.008, T1114.003, T1528

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table chain (sign-in plus two mailbox audit sources) - hunt or Sentinel analytics rule. For CD-style coverage of rule content alone, use the companion file's Queries 8-9. Validated: executed cleanly with 0 rows. The validation tenant had only one inbox-rule operation tenant-wide in 30 days (by a user with no device code sign-in), so the chain could not be exercised against a positive - treat as syntax- and logic-validated only."
-->

```kql
let lookback = 30d;
let followWindow = 72h;
let DeviceCode = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where EndpointCall has "Cmsi:cmsi" and ErrorCode == 0
| summarize DcTime = min(Timestamp), DcIPs = make_set(IPAddress, 5), DcApps = make_set(Application, 5) by AccountObjectId, AccountUpn = tolower(AccountUpn);
let DcUpns = toscalar(DeviceCode | summarize make_set(AccountUpn));
let DcIds = toscalar(DeviceCode | summarize make_set(AccountObjectId));
let RuleOps = dynamic(["New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox", "New-TransportRule"]);
let CloudRules = CloudAppEvents
| where Timestamp > ago(lookback)
| where ActionType in (RuleOps)
| where AccountObjectId in (DcIds)
| extend RD = parse_json(tostring(RawEventData))
| project RuleTime = Timestamp, AccountObjectId, Source = "CloudAppEvents", Operation = ActionType, RuleIP = IPAddress,
          RuleParams = tostring(RD.Parameters), ClientApp = tostring(RD.ClientInfoString);
let OfficeRules = OfficeActivity
| where TimeGenerated > ago(lookback)
| where OfficeWorkload == "Exchange" and Operation in (RuleOps)
| where tolower(UserId) in (DcUpns)
| project RuleTime = TimeGenerated, AccountUpn = tolower(UserId), Source = "OfficeActivity", Operation, RuleIP = ClientIP, RuleParams = Parameters, ClientApp = ClientInfoString;
let Rules = union
  (CloudRules | join kind=inner (DeviceCode | project AccountObjectId, AccountUpn) on AccountObjectId | project-away AccountObjectId1),
  (OfficeRules);
Rules
| join kind=inner DeviceCode on AccountUpn
| where RuleTime between (DcTime .. (DcTime + followWindow))
| extend HoursAfterDeviceCode = round(datetime_diff("minute", RuleTime, DcTime) / 60.0, 1)
| extend Forwards = RuleParams has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress", "DeliverToMailboxAndForward"),
         Hides = RuleParams has_any ("MoveToFolder", "DeleteMessage", "MarkAsRead", "RSS", "Conversation History", "Archive"),
         FinanceKeywords = RuleParams has_any ("invoice", "payment", "wire", "bank", "remittance", "ACH", "transfer")
| project DcTime, RuleTime, HoursAfterDeviceCode, AccountUpn, Source, Operation, Forwards, Hides, FinanceKeywords, RuleIP, DcIPsText = tostring(DcIPs), DcAppsText = tostring(DcApps), ClientApp, RuleParams
| order by HoursAfterDeviceCode asc
```

**Expected results:** 0 rows normally. Any rule that hides or forwards mail, created by a user within 72 hours of a device code sign-in — particularly from a `RuleIP` matching the device code IP rather than the user's normal location — should be handled as BEC: remove the rule, review sent items, and follow the compromised-account playbook.

---

## Query 5: Device code sign-in followed by a burst of outbound or internal mail (trusted-contact phishing)

**Purpose:** EvilTokens access "can be used to send further emails internally to the organization and to external contacts, allowing the actor to send phishing emails for seemingly trusted contacts." For each device code user, counts messages and distinct recipients they sent in the following 48 hours, compares against their own 30-day daily recipient baseline, and surfaces spikes or any message Defender flagged as a threat.  
**Severity:** High  
**MITRE:** T1534, T1566.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline-relative correlation - hunt or Sentinel analytics rule. Validated: 8 device code users sent 35 messages within 48 hours of their device code sign-in in the validation tenant; none exceeded the 10-recipient / 3x-baseline spike threshold and none were flagged, so the tuned query returned 0 rows. Raise minRecipients for distribution-list-heavy senders; the Flagged branch (Defender verdict on the sender's own outbound mail) is the highest-fidelity signal."
-->

```kql
let lookback = 30d;
let followWindow = 48h;
let minRecipients = 10;
let DeviceCode = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where EndpointCall has "Cmsi:cmsi" and ErrorCode == 0
| summarize DcTime = min(Timestamp), DcIPs = make_set(IPAddress, 5), DcApps = make_set(Application, 5) by AccountObjectId, AccountUpn;
let DcIds = toscalar(DeviceCode | summarize make_set(AccountObjectId));
let Sent = EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection in ("Outbound", "Intra-org")
| where SenderObjectId in (DcIds);
let Baseline = Sent
| summarize BaselineDailyRecipients = round(1.0 * dcount(RecipientEmailAddress) / 30, 1) by SenderObjectId;
Sent
| join kind=inner DeviceCode on $left.SenderObjectId == $right.AccountObjectId
| where Timestamp between (DcTime .. (DcTime + followWindow))
| summarize SentMessages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress),
    ExternalRecipients = dcountif(RecipientEmailAddress, EmailDirection == "Outbound"),
    WithUrls = dcountif(NetworkMessageId, UrlCount > 0), WithAttachments = dcountif(NetworkMessageId, AttachmentCount > 0),
    Flagged = dcountif(NetworkMessageId, isnotempty(ThreatTypes)),
    Subjects = make_set(Subject, 10), FirstSend = min(Timestamp), LastSend = max(Timestamp)
    by SenderObjectId, AccountUpn, DcTime, DcAppsText = tostring(DcApps), DcIPsText = tostring(DcIPs)
| join kind=leftouter Baseline on SenderObjectId
| extend RecipientSpike = Recipients > 3 * max_of(BaselineDailyRecipients * 2, 1.0)
| where (Recipients >= minRecipients and RecipientSpike) or Flagged > 0
| project DcTime, AccountUpn, DcAppsText, DcIPsText, FirstSend, LastSend, SentMessages, Recipients, ExternalRecipients, BaselineDailyRecipients, RecipientSpike,
          WithUrls, WithAttachments, Flagged, Subjects
| order by Flagged desc, Recipients desc
```

**Expected results:** 0 rows normally. A hit with lure-style subjects (password expiry, shared document, invoice, RFP) and URLs/attachments shortly after a device code sign-in indicates the mailbox is being used as a trusted phishing platform — purge the messages with Threat Explorer and notify recipients.

---

## Query 6: Residual token use after containment (the ~1-hour access-token window)

**Purpose:** Microsoft observed that "standard session revocation often only invalidates refresh tokens, leaving existing access tokens active for up to an hour," and that EvilTokens operators exploit this window. After each strong containment action (`Disable account`, refresh-token invalidation / session revocation, Identity Protection `ConfirmAccountCompromised`), this collects Graph, CloudAppEvents and successful sign-in activity for the target over the next 90 minutes, highlighting mail operations and token-bearing API calls that continued after containment.  
**Severity:** High  
**MITRE:** T1550.001, T1078.004

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Response-assurance hunt, not a detection - run it after every containment action or on a schedule. Validated: including 'Reset user password' as an anchor produced 223 of 227 matches (routine resets), so it is excluded. With strong containment only, it returned residual activity after both 'Disable account' events and both 'ConfirmAccountCompromised' events in the validation tenant, including Graph API calls 18 minutes after an account disable. Residual activity after ConfirmAccountCompromised alone is expected because that action does not necessarily revoke sessions."
-->

```kql
let lookback = 30d;
let residualWindow = 90m;
let StrongContainment = dynamic(["Invalidate all refresh tokens for user", "Revoke user sessions", "Disable account", "ConfirmAccountCompromised"]);
let Containment = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in~ (StrongContainment)
| where Result =~ "success"
| extend TR = parse_json(tostring(TargetResources))
| extend TargetId = tostring(TR[0].id), TargetUpn = tolower(tostring(TR[0].userPrincipalName))
| extend Actor = coalesce(tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName), tostring(parse_json(tostring(InitiatedBy)).app.displayName))
| where isnotempty(TargetId)
| summarize ContainTime = min(TimeGenerated), Actions = make_set(OperationName), Actors = make_set(Actor, 5) by TargetId, TargetUpn;
let TargetIds = toscalar(Containment | summarize make_set(TargetId));
let Residual = union
  (GraphAPIAuditEvents | where Timestamp > ago(lookback) | where AccountObjectId in (TargetIds)
    | project Timestamp, TargetId = AccountObjectId, Src = "Graph", IP = IpAddress, Detail = strcat(RequestMethod, " ", tostring(split(tostring(split(RequestUri, "?")[0]), ".com/")[1])), IsMail = RequestUri has_any ("/messages", "/mailFolders", "/sendMail", "/messageRules")),
  (CloudAppEvents | where Timestamp > ago(lookback) | where AccountObjectId in (TargetIds)
    | project Timestamp, TargetId = AccountObjectId, Src = "CloudApp", IP = IPAddress, Detail = ActionType, IsMail = ActionType has_any ("MailItemsAccessed", "Send", "InboxRule", "UpdateInboxRules")),
  (EntraIdSignInEvents | where Timestamp > ago(lookback) | where AccountObjectId in (TargetIds) | where ErrorCode == 0
    | project Timestamp, TargetId = AccountObjectId, Src = "SignIn", IP = IPAddress, Detail = strcat("Sign-in: ", Application), IsMail = false);
Containment
| join kind=inner Residual on TargetId
| where Timestamp between (ContainTime .. (ContainTime + residualWindow))
| summarize ResidualEvents = count(), TokenApiEvents = countif(Src != "SignIn"), NewSignIns = countif(Src == "SignIn"), MailEvents = countif(IsMail),
    Sources = make_set(Src), IPs = make_set(IP, 10), SampleDetails = make_set(Detail, 15), LastResidual = max(Timestamp)
    by ContainTime, TargetUpn, ActionsText = tostring(Actions), ActorsText = tostring(Actors)
| extend MinutesOfResidualAccess = round(datetime_diff("second", LastResidual, ContainTime) / 60.0, 1)
| extend Priority = case(MailEvents > 0, "High", ActionsText has_any ("Disable account", "Invalidate", "Revoke") and TokenApiEvents > 0, "High", NewSignIns > 0, "Medium", "Low")
| order by Priority asc, MailEvents desc, ResidualEvents desc
```

**Expected results:** Some residual activity is normal because existing access tokens are still valid, which is exactly why the article recommends temporary disablement plus CAE. `High` rows — mail access, or API calls continuing after a disable/revoke — show the actor still operating in the gap: confirm CAE is enforced, disable registered devices, and review what was accessed in that window.

---

## Query 7: MDO-alerted phishing mail → click or browser open → device code sign-in within an hour

**Purpose:** Adapts Microsoft's published "Suspicious URL clicked" hunting query. Starting from messages attached to Defender for Office 365 alerts, it finds recipients who **clicked** (Safe Links `UrlClickEvents`) or **opened the URL in a browser from Outlook** (`DeviceEvents` `BrowserLaunchedToOpenUrl`, matched on account object ID rather than on-prem SID so cloud-only users are covered), then checks whether the **same user completed a device code sign-in within one hour** — the decisive EvilTokens link. It also flags serverless hosting.  
**Severity:** High  
**MITRE:** T1566.002, T1528

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table correlation - hunt or Sentinel analytics rule. The published version joins IdentityInfo on OnPremSid, which misses cloud-only users, and names the URL column 'UrlClickedByUserSid'. This version joins on InitiatingProcessAccountObjectId and adds Safe Links clicks plus the device-code-after-click correlation. Validated: 14 alerted-mail interactions in 30 days in the validation tenant (mostly phishing/click-simulation traffic and one user-reported message), with 0 followed by a device code sign-in. Exclude your simulation platforms' click infrastructure after verifying it."
-->

```kql
let lookback = 30d;
let dcWindow = 1h;
let ServerlessHosts = dynamic(["vercel.app", "workers.dev", "pages.dev", "lambda-url", "azurecontainerapps.io", "azurewebsites.net", "railway.app", "netlify.app", "onrender.com", "blob.core.windows.net", "r2.dev"]);
let AlertedMail = AlertInfo
| where Timestamp > ago(lookback)
| where ServiceSource =~ "Microsoft Defender for Office 365"
| join kind=inner (AlertEvidence | where Timestamp > ago(lookback) | where EntityType == "MailMessage" and isnotempty(NetworkMessageId) | project AlertId, NetworkMessageId) on AlertId
| summarize AlertTitles = make_set(Title, 5), AlertTime = min(Timestamp) by NetworkMessageId;
let AlertedIds = AlertedMail | project NetworkMessageId;
let Recipients = EmailEvents
| where Timestamp > ago(lookback)
| where NetworkMessageId in (AlertedIds)
| project NetworkMessageId, RecipientEmailAddress = tolower(RecipientEmailAddress), RecipientObjectId, Subject, SenderFromAddress, DeliveryAction, LatestDeliveryLocation, EmailTime = Timestamp;
let MailClicks = UrlClickEvents
| where Timestamp > ago(lookback)
| where NetworkMessageId in (AlertedIds)
| project ClickTime = Timestamp, NetworkMessageId, ClickUpn = tolower(AccountUpn), ClickedUrl = Url, ClickAction = ActionType, ClickIP = IPAddress, IsClickedThrough;
let AlertedUrls = EmailUrlInfo
| where Timestamp > ago(lookback)
| where NetworkMessageId in (AlertedIds)
| project NetworkMessageId, Url;
let EndpointOpens = DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType == "BrowserLaunchedToOpenUrl" and isnotempty(RemoteUrl)
| project OpenTime = Timestamp, RemoteUrl, DeviceName, OpenAccountObjectId = InitiatingProcessAccountObjectId, OpenProcess = InitiatingProcessFileName;
let DeviceCode = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where EndpointCall has "Cmsi:cmsi" and ErrorCode == 0
| project DcTime = Timestamp, DcUpn = tolower(AccountUpn), DcApp = Application, DcIP = IPAddress;
Recipients
| join kind=inner AlertedMail on NetworkMessageId
| join kind=leftouter MailClicks on NetworkMessageId, $left.RecipientEmailAddress == $right.ClickUpn
| join kind=leftouter (AlertedUrls | join kind=inner EndpointOpens on $left.Url == $right.RemoteUrl) on NetworkMessageId, $left.RecipientObjectId == $right.OpenAccountObjectId
| where isnotempty(ClickTime) or isnotempty(OpenTime)
| extend InteractionTime = coalesce(ClickTime, OpenTime), InteractedUrl = coalesce(ClickedUrl, RemoteUrl)
| join kind=leftouter DeviceCode on $left.RecipientEmailAddress == $right.DcUpn
| extend DcInWindow = isnotnull(DcTime) and DcTime between (InteractionTime .. (InteractionTime + dcWindow))
| summarize DeviceCodeAfterClick = max(toint(DcInWindow)), DcApps = make_set_if(DcApp, DcInWindow, 5), DcIPs = make_set_if(DcIP, DcInWindow, 5)
    by EmailTime, AlertTime, AlertTitlesText = tostring(AlertTitles), Subject, SenderFromAddress, RecipientEmailAddress, DeliveryAction, LatestDeliveryLocation,
       InteractionTime, ClickAction, InteractedUrl, ClickIP, DeviceName, OpenProcess
| extend ServerlessHost = InteractedUrl has_any (ServerlessHosts)
| extend Priority = case(DeviceCodeAfterClick == 1, "High", ServerlessHost and ClickAction != "ClickBlocked", "Medium", "Low")
| order by DeviceCodeAfterClick desc, ServerlessHost desc, InteractionTime desc
```

**Expected results:** Clicks on alerted mail are common, especially with simulations. `DeviceCodeAfterClick == 1` is the EvilTokens chain — treat it as confirmed token theft and run Queries 2–6 for that user immediately.

---

## Query 8: Detected-but-delivered phishing that is still in the mailbox, with EvilTokens lure shape

**Purpose:** Extends Microsoft's published "successfully delivered phishing" query. Finds inbound mail with a phish verdict that was delivered (or still sits in Inbox/Junk after ZAP), and scores the EvilTokens shape: a lure-theme subject (password expiry, voicemail/eFax, doc-signing, invoice/RFP/proposal, compensation/benefits, shared file), serverless-hosted URLs, a `devicelogin` link, and HTML/PDF/SVG attachments. Messages still in the mailbox are the exposure ZAP did not close.  
**Severity:** Medium  
**MITRE:** T1566.001, T1566.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture/exposure hunt over delivered mail - useful as a scheduled report rather than an alert. For CD, a row-level variant filtered to StillInMailbox == true and EvilTokensShape >= 2, projecting Timestamp, NetworkMessageId and ReportId, is viable (EmailEvents single table plus EmailUrlInfo join, scheduled 1H). Validated: 3 rows in the validation tenant, all internal phishing-simulation and mail-authentication test messages still in Inbox/Junk. Lure keywords are broad by design; tune them to the themes seen in your own reported-phish mailbox."
-->

```kql
let lookback = 30d;
let LureThemes = dynamic(["password expir", "password expiration", "action required", "voicemail", "voice message", "efax", "e-fax", "fax", "docusign", "document sign", "e-sign", "signature request", "shared a file", "shared document", "invoice", "remittance", "payment", "rfp", "request for proposal", "bid proposal", "proposal", "partnership agreement", "compensation", "benefits", "payroll", "microsoft 365", "office 365", "onedrive", "sharepoint", "mfa", "verify your account"]);
let ServerlessHosts = dynamic(["vercel.app", "workers.dev", "pages.dev", "lambda-url", "azurecontainerapps.io", "railway.app", "netlify.app", "onrender.com", "r2.dev"]);
let Delivered = EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where isnotempty(ThreatTypes) and ThreatTypes has "Phish"
| where DeliveryAction == "Delivered" or LatestDeliveryLocation in~ ("Inbox/folder", "Junk folder")
| extend SubjectLower = tolower(Subject)
| extend LureTheme = SubjectLower has_any (LureThemes)
| project Timestamp, NetworkMessageId, RecipientEmailAddress, RecipientObjectId, SenderFromAddress, SenderFromDomain, SenderIPv4, Subject, ThreatTypes, DetectionMethods,
          DeliveryAction, DeliveryLocation, LatestDeliveryLocation, LatestDeliveryAction, UrlCount, AttachmentCount, LureTheme;
let Urls = EmailUrlInfo
| where Timestamp > ago(lookback)
| where NetworkMessageId in ((Delivered | project NetworkMessageId))
| summarize UrlDomains = make_set(UrlDomain, 10), ServerlessUrl = max(toint(Url has_any (ServerlessHosts))), DeviceLoginUrl = max(toint(Url has_any ("microsoft.com/devicelogin", "aka.ms/devicelogin", "login.microsoftonline.com/common/oauth2/deviceauth"))) by NetworkMessageId;
let Attach = EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where NetworkMessageId in ((Delivered | project NetworkMessageId))
| summarize AttachmentTypes = make_set(FileType, 5), HtmlOrPdf = max(toint(FileType in~ ("html", "htm", "pdf", "svg", "shtml"))) by NetworkMessageId;
Delivered
| join kind=leftouter Urls on NetworkMessageId
| join kind=leftouter Attach on NetworkMessageId
| extend ServerlessUrl = coalesce(ServerlessUrl, 0), DeviceLoginUrl = coalesce(DeviceLoginUrl, 0), HtmlOrPdf = coalesce(HtmlOrPdf, 0)
| extend StillInMailbox = LatestDeliveryLocation in~ ("Inbox/folder", "Junk folder")
| extend EvilTokensShape = toint(LureTheme) + ServerlessUrl + DeviceLoginUrl + HtmlOrPdf
| where StillInMailbox or EvilTokensShape >= 2
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderIPv4, Subject, ThreatTypes, DetectionMethods, DeliveryAction, LatestDeliveryLocation, LatestDeliveryAction,
          StillInMailbox, LureTheme, ServerlessUrl, DeviceLoginUrl, HtmlOrPdf, EvilTokensShape, UrlDomains, AttachmentTypes
| order by StillInMailbox desc, EvilTokensShape desc, Timestamp desc
| take 100
```

**Expected results:** A small set of messages. For each `StillInMailbox` phish, remediate via Threat Explorer (soft delete) and check the recipient in Query 7 (click → device code). If this list is regularly non-empty, raise the anti-phishing Advanced Phishing Threshold to 2–3 and confirm ZAP is enabled, per the article.

---

## General Tuning Notes

1. **Behavioral by design.** The September reporting publishes no new IOCs, and Microsoft disrupted EvilTokens infrastructure. The hunts key on post-compromise chains that any device code phishing kit produces; refresh the companion file's April IOC ranges from current threat intelligence if you still use them.

2. **Correlation is the detection.** Device code flow, device registration, Graph enumeration, inbox rules and mass mail each have legitimate uses. All eight queries anchor on a successful device code sign-in (or a containment action) plus a follow-on behavior within a bounded window. Do not strip the anchor to "simplify" a query.

3. **Same-app joins beat token joins.** The device code `UniqueTokenId` is exchanged for refresh-derived tokens, so direct token linkage to Graph calls is effectively absent. Query 3 joins on `AccountObjectId` + client `ApplicationId` within 24 hours; keep that pairing when adapting it.

4. **Admin device code users are your baseline noise.** Build an allowlist of accounts that legitimately use Azure CLI / Graph PowerShell device code (or better, require them to use interactive or managed-identity flows) and block device code flow for everyone else via Conditional Access. Once blocked, **any** successful `Cmsi:cmsi` sign-in outside the exception group becomes high fidelity.

5. **Distinguish mobile enrollment from PRT theft.** Microsoft Authenticator setup on iOS/Android produces device code–like sign-ins and a `Register device` from the user's own phone and IP. Query 2 keeps these as `Low` rather than dropping them; attacker registrations are typically Windows, via Microsoft Authentication Broker, from hosting IPs.

6. **Containment is not instant.** Query 6 exists because revoking refresh tokens leaves access tokens valid for up to an hour. Pair revocation with **temporary account disablement**, disable any newly registered devices, and enforce Continuous Access Evaluation so critical events revoke access in near real time.

7. **Simulation noise.** Phishing-simulation platforms, Safe Links detonation and internal mail tests generate clicks and delivered-phish rows (Queries 7–8). Exclude them by verified sender domain or click-source IP, not by recipient.

8. **CD-readiness summary.** **All eight queries are `cd_ready: false`.** They are cross-table chains, baseline comparisons, response-assurance checks, or alert correlations, so they belong in scheduled hunts or Sentinel analytics rules. Query 8 has a documented single-table CD path. For single-event custom detections (device code sign-in, Device Registration Service activity, suspicious inbox rules), use the companion file's `cd_ready: true` queries. All eight were executed against live Advanced Hunting during authoring. **Query 4 is syntax- and logic-validated only** (no inbox-rule activity existed to test against).

---

## References

- Microsoft Threat Intelligence — [Unmasking EvilTokens: Getting to the root of device code phishing (2026-09-22)](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)
- Microsoft Threat Intelligence — [Inside an AI-enabled device code phishing campaign (2026-04-06)](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)
- Microsoft Learn — [OAuth 2.0 device authorization grant flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- Microsoft Learn — [Block authentication flows with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-authentication-flows)
- Microsoft Learn — [Continuous Access Evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation)
- Microsoft Learn — [Token theft playbook](https://learn.microsoft.com/security/operations/token-theft-playbook)
- Microsoft Learn — [Alert grading playbook: inbox manipulation rules](https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules)
- Microsoft Learn — [Responding to a compromised email account](https://learn.microsoft.com/defender-office-365/responding-to-a-compromised-email-account)
- MITRE ATT&CK — [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- MITRE ATT&CK — [T1098.005 Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- MITRE ATT&CK — [T1087.004 Account Discovery: Cloud Account](https://attack.mitre.org/techniques/T1087/004/)
- MITRE ATT&CK — [T1564.008 Hide Artifacts: Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/)
- MITRE ATT&CK — [T1534 Internal Spearphishing](https://attack.mitre.org/techniques/T1534/)
- Companion files: [`queries/identity/device_code_phishing.md`](../../identity/device_code_phishing.md), [`queries/identity/aitm_threat_detection.md`](../../identity/aitm_threat_detection.md), [`queries/cloud/graph_api_security_monitoring.md`](../../cloud/graph_api_security_monitoring.md)
