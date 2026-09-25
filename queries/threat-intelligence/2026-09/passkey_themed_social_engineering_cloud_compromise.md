# Passkey-Themed Social Engineering → MFA Persistence, Graph Reconnaissance and Cloud Data Collection — Threat Hunts

**Created:** 2026-09-25  
**Platform:** Microsoft Defender XDR  
**Tables:** EmailUrlInfo, EmailEvents, UrlClickEvents, MessageUrlInfo, MessageEvents, DeviceNetworkEvents, DeviceEvents, EntraIdSignInEvents, AuditLogs, CloudAppEvents, GraphAPIAuditEvents, IdentityInfo, AlertInfo, AlertEvidence  
**Keywords:** passkey lure, passkey phishing, SSO enrollment lure, helpdesk vishing, SMS phishing, smishing, IT helpdesk impersonation, AiTM, adversary-in-the-middle, device code phishing, OfficeHome, 50074, 50140, keep me signed in, My Sign-Ins, My Apps, Microsoft Approval Management, Microsoft Account Controls V2, OCaaS, MFA persistence, attacker-registered MFA method, security info registration, StrongAuthenticationPhoneAppDetail, SoftwareTokenActivated, NO_DEVICE_TOKEN, software OATH token, PhoneAppOTP, Microsoft Graph reconnaissance, directory enumeration, pagination, skiptoken, delta query, SharePoint download, OneDrive download, FileDownloaded, python-httpx, Exchange REST, One Outlook Web, anonymous proxy, Nicenic, organization-name subdomain, Storm-3121, Storm-3032, ShinyHunters, Falcon, BlackFile, Helix, extortion, Teams internal phishing  
**MITRE:** T1598.004, T1583.001, T1566.002, T1566.004, T1557, T1528, T1078.004, T1098.005, T1556.006, T1087.004, T1069.003, T1526, T1213.002, T1530, T1114.002, T1567, T1534  
**Domains:** identity, email, cloud  
**Timeframe:** Last 14–30 days (configurable; per-query)  
**Source:** [Passkey-themed social engineering leads to identity and cloud compromise (2026-09-09)](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)

---

## Threat Overview

Microsoft Security Research has tracked, since May 2026, cloud intrusions that begin with a **call or SMS to an employee's personal phone** from someone posing as the IT helpdesk. The caller insists a **passkey, MFA or SSO setup** must be updated immediately and sends a link to a convincing Microsoft sign-in look-alike. Despite the passkey theme, enrollment is rarely the goal. The narrative steers victims through **AiTM phishing** (credentials plus session token captured) or a **device code flow** (the victim authorizes the actor's client). Because the link is often opened on an unmanaged personal phone, **endpoint telemetry may hold no trace**; the employee's recollection is sometimes the only record of initial access.

The infrastructure embeds the **target organization's name as a subdomain** of generic, rapidly deployed domains (for example `companyname.add-passkey[.]com`, `companyname.integratedsso[.]com`), often registered through Nicenic and live within hours. Compromised accounts are also used to send the same passkey lures **internally over Microsoft Teams**. After sign-in — in one timeline, OfficeHome from an unmanaged device (`50074` MFA required → MFA via AiTM → `50140` keep-me-signed-in → success), then My Apps, My Profile, Microsoft Approval Management, Account Controls V2 and My Sign-Ins within four minutes — the actor **registers an MFA method it controls** (phone number, Authenticator app, or a **software OATH token** visible as `NO_DEVICE` / `NO_DEVICE_TOKEN` / `SoftwareTokenActivated`). It then runs **Node.js-driven Microsoft Graph reconnaissance** across tenant, directory, privilege/MFA, applications/consent, SharePoint/OneDrive and mailboxes, rotating IPs per stage. Collection follows at a deliberately measured pace (**fewer than 1,000 files or emails per hour**, over hours to days), from SharePoint/OneDrive (often with the `python-httpx` user agent) and from Exchange through REST APIs. The initial-access activity is used by several actors, including **Storm-3121** (initial access leading to ShinyHunters and Falcon extortion) and **Storm-3032** (split from BlackFile, now operating as Helix).

> **Companion files:** [`queries/threat-intelligence/2026-09/eviltokens_storm_2992_device_code_postcompromise.md`](eviltokens_storm_2992_device_code_postcompromise.md) and [`queries/identity/device_code_phishing.md`](../../identity/device_code_phishing.md) cover the device code branch. [`queries/identity/aitm_threat_detection.md`](../../identity/aitm_threat_detection.md) covers generic AiTM. This file covers the passkey-lure infrastructure, the OfficeHome session shape, MFA persistence, Graph recon-to-collection and measured M365 exfiltration.

### TTP Summary

| Stage | TTP |
|---|---|
| Reconnaissance | Employee and org-structure research from public and professional profiles |
| Initial access — lure | Helpdesk vishing and SMS to personal phones (T1598.004, T1566.004); internal Teams lures from compromised accounts (T1534) |
| Initial access — infrastructure | Look-alike sign-in portals on `org-name.<generic-passkey/sso/key domain>`, rotated per target (T1566.002) |
| Credential / token theft | AiTM (credentials + session token) or device code flow (T1557, T1528) |
| Valid accounts | Token replay or reused credentials with a previously planted PhoneAppOTP (T1078.004) |
| Persistence | Actor-controlled MFA method: phone, Authenticator app, or software OATH token (T1098.005, T1556.006) |
| Discovery | Graph enumeration of tenant, users, groups, roles, auth methods, apps/consent, sites/drives, mailboxes; paging, delta and search (T1087.004, T1069.003, T1526) |
| Collection | SharePoint/OneDrive FileAccessed/FileDownloaded (often `python-httpx`), Exchange REST, Graph `/content` and `/attachments` (T1213.002, T1530, T1114.002) |
| Exfiltration | Sustained, rate-limited (<1,000 items/hour) transfer through proxy infrastructure (T1567) |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **The initial lure is often invisible** | Calls and SMS to personal phones, opened on unmanaged devices, leave no email, Teams or endpoint record. A clean Query 1–2 result does not clear a user; start from their identity signals (Queries 3–5) and ask them. |
| **Every portal in the article's timeline loads on any normal M365 sign-in** | My Apps, Microsoft Approval Management, OCaaS, My Profile and M365ChatClient are fetched automatically by the Office portal. In validation, *every* matching OfficeHome session touched 3–5 of them. Query 5 is driven by the **unusual start IP and unmanaged device**, not the app list. |
| **The MFA registration audit IP is often a Microsoft service egress** | `AuditLogs` "User registered security info" frequently records a shared Azure IP used by dozens of users, not the client. Queries 3 and 9 treat any registration IP seen for ≥10 users as shared egress and anchor on **sign-in** IPs instead. |
| **The article's `Update user.` MFA-device query depends on tenant audit shape** | In the validation tenant, `CloudAppEvents` `Update user.` carried no `StrongAuthentication*` properties, while `AuditLogs` security-info registration carried 2,000+ events. Run both (Queries 3 and 4); an empty Query 4 is not proof of absence. |
| **Mobile self-enrollment looks like a new method from a new IP** | Setting up Authenticator or a passkey on a phone produces a sign-in from the phone's IP and a registration seconds later. Query 3 subtracts score for the Authenticator-app, mobile-user-agent shape. Actor-registered methods come from the **actor's** session. |
| **AH `EntraIdSignInEvents` is capped at 30 days** | Baseline plus lookback must fit in 30 days (Queries 3, 5, 6 and 9 use a 14-day lookback against a 16-day baseline). For longer baselines, port to `SigninLogs` / `AADNonInteractiveUserSignInLogs` in the Data Lake. |
| **Microsoft portal back-ends dominate Graph telemetry** | The article's broad Graph-recon hunt produced thousands of 30-minute windows in validation, mostly Microsoft portal back-ends (Office 365 Portal, Security & Compliance Center, Azure portal, My Signins, My Profile, My Apps, Entitlement Management, Entra user and app blades). Queries 6 and 9 exclude those client app IDs **and** require the Graph call's IP to be new for the user. The actor's automation uses its own token client, not these portals. |
| **Profile photos look like content collection** | `/users/{id}/photos/48x48/$value` matches a naive `/$value` content check. Exclude paths containing `/photo` (Queries 6, 9). |
| **Microsoft services bulk-read SharePoint** | Microsoft Search (`ODMTADemand`) and eDiscovery/Content Search export (`ExportWorker`) generate hundreds of thousands of `FileAccessed` events from Azure IPs. Exclude those user agents (Queries 7, 9). |
| **`CloudAppEvents.ApplicationId` is an integer** | Use `20892` (SharePoint), `15600` (OneDrive), `20893` (Exchange) without quotes. |
| **`!has_any` can fail in Advanced Hunting** | Use `not(x has_any (...))`. |
| **Attack simulations reuse these themes** | Attack Simulation Training sends "password reset"/"action required" lures with SSO-themed domains from internal senders. Confirm with the simulation owner before closing; exclude verified simulation senders, not the query logic. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Passkey-lure infrastructure sweep across email, clicks, Teams and e...](#query-1-passkey-lure-infrastructure-sweep-across-email-clicks-teams-and-endpoints-direct-ioc) | Investigation | `DeviceEvents` + multi |
| 2 | [Passkey, SSO and key-setup look-alike domains — pattern hunt with o...](#query-2-passkey-sso-and-key-setup-look-alike-domains--pattern-hunt-with-organization-name-subdomains) | Investigation | `DeviceNetworkEvents` + multi |
| 3 | [New MFA method registered shortly after an unusual sign-in (actor-c...](#query-3-new-mfa-method-registered-shortly-after-an-unusual-sign-in-actor-controlled-factor) | Investigation | `AuditLogs` + `EntraIdSignInEvents` |
| 4 | [Directory-level MFA device and software OATH token additions (`Upda...](#query-4-directory-level-mfa-device-and-software-oath-token-additions-update-user-strongauthentication-properties) | Investigation | `CloudAppEvents` |
| 5 | [OfficeHome AiTM-shaped session from an unmanaged device and new IP,...](#query-5-officehome-aitm-shaped-session-from-an-unmanaged-device-and-new-ip-fanning-out-to-identity-portals-and-collaboration-apps) | Investigation | `EntraIdSignInEvents` |
| 6 | [Microsoft Graph reconnaissance progressing to content collection, f...](#query-6-microsoft-graph-reconnaissance-progressing-to-content-collection-from-an-ip-new-to-the-user) | Investigation | `GraphAPIAuditEvents` |
| 7 | [Sustained SharePoint/OneDrive bulk access with automation user agen...](#query-7-sustained-sharepointonedrive-bulk-access-with-automation-user-agents-anonymous-proxies-or-uncommon-ispua) | Investigation | `CloudAppEvents` + `HourEvents` |
| 8 | [High-volume Exchange Online REST access through Office/Outlook Web ...](#query-8-high-volume-exchange-online-rest-access-through-officeoutlook-web-client-tokens) | Dashboard | `CloudAppEvents` + multi |
| 9 | [End-to-end chain — MFA method from a new IP, then Graph or SharePoi...](#query-9-end-to-end-chain--mfa-method-from-a-new-ip-then-graph-or-sharepointonedrive-collection-within-48-hours) | Investigation | `AuditLogs` + multi |
| 10 | [Internal Teams messages linking to passkey, SSO or sign-in-themed d...](#query-10-internal-teams-messages-linking-to-passkey-sso-or-sign-in-themed-domains) | Investigation | `MessageEvents` + `MessageUrlInfo` |
| 11 | [Defender detections matching the article's coverage table, grouped ...](#query-11-defender-detections-matching-the-articles-coverage-table-grouped-by-account-and-stage) | Detection | `AlertInfo` + multi |


## IOC Reference

> Published by Microsoft Security Research. Domains are defanged here and plain in the queries. The actor deploys **organization-specific subdomains** on these parent domains and rotates infrastructure quickly, so these lists age fast — Query 2's pattern hunt is the durable companion.

| Indicator | Type | Theme |
|---|---|---|
| passkeyhelpdesk[.]com | Domain | Passkey support lure |
| secure-passkey[.]com | Domain | Passkey security |
| setupmypasskey[.]com | Domain | Passkey setup |
| add-passkey[.]com | Domain | Passkey enrollment |
| integratedsso[.]com | Domain | SSO |
| oktasession[.]com | Domain | Identity-provider session |
| keysyncos[.]com | Domain | Key synchronization |
| oskeysync[.]com | Domain | Key synchronization |
| oskeysetup[.]com | Domain | Key setup |
| oskeyregister[.]com | Domain | Key registration |
| syncmykey[.]com | Domain | Key synchronization |
| myconnectkey[.]com | Domain | Key connection |
| oskeyconnect[.]com | Domain | Key connection |
| validationsetupac[.]com | Domain | Account validation and setup |
| portalsetuphub[.]com | Domain | Portal setup |

**Artifacts cited in the article narrative (not IOC-table entries):**

| Indicator | Type | Description |
|---|---|---|
| `companyname.<malicious-domain>.com` | URL pattern | Target organization name as subdomain (e.g. `contoso.add-passkey[.]com`) |
| `NO_DEVICE` / `NO_DEVICE_TOKEN` / `SoftwareTokenActivated` | Audit values | Software OATH token added via `Update user.` `StrongAuthenticationPhoneAppDetail` |
| `50074` → `50140` → success on OfficeHome | Sign-in sequence | MFA required → keep-me-signed-in interrupt → session established (AiTM shape) |
| `python-httpx` | User agent | Seen on high-volume SharePoint/OneDrive access (weak alone) |

---

## Query 1: Passkey-lure infrastructure sweep across email, clicks, Teams and endpoints (direct IOC)

**Purpose:** Matches the 15 published parent domains (and any organization-name subdomains under them) in email URLs, Safe Links clicks, Teams message URLs, endpoint network connections and browser URL opens. A clean environment returns 0; any **click** or **endpoint connection** is a likely credential or token compromise for that user.  
**Severity:** High  
**MITRE:** T1566.002, T1557

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table IOC union - for CD, split into single-table rules: UrlClickEvents (Url has_any IOC list, projecting Timestamp, AccountUpn, ReportId) and DeviceNetworkEvents (RemoteUrl has_any IOC list, projecting Timestamp, DeviceId, DeviceName, ReportId) are each NRT-eligible. Validated: 0 rows over 30 days in AH and 0 in EmailUrlInfo/UrlClickEvents/DeviceNetworkEvents over ~90 days in the Data Lake. The domains rotate quickly - pair with Query 2."
-->

```kql
let lookback = 30d;
let IOC_Domains = dynamic(["passkeyhelpdesk.com", "secure-passkey.com", "setupmypasskey.com", "add-passkey.com", "integratedsso.com", "oktasession.com",
  "keysyncos.com", "oskeysync.com", "oskeysetup.com", "oskeyregister.com", "syncmykey.com", "myconnectkey.com", "oskeyconnect.com",
  "validationsetupac.com", "portalsetuphub.com"]);
union isfuzzy=true
(EmailUrlInfo | where Timestamp > ago(lookback) | where UrlDomain has_any (IOC_Domains) or Url has_any (IOC_Domains)
 | join kind=leftouter (EmailEvents | where Timestamp > ago(lookback) | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, LatestDeliveryLocation) on NetworkMessageId
 | project Timestamp, Source = "Email URL", Domain = UrlDomain, Url, Who = RecipientEmailAddress, Detail = strcat(SenderFromAddress, " | ", Subject, " | ", DeliveryAction, "/", LatestDeliveryLocation)),
(UrlClickEvents | where Timestamp > ago(lookback) | where Url has_any (IOC_Domains)
 | project Timestamp, Source = strcat("URL click (", Workload, ")"), Domain = tostring(parse_url(Url).Host), Url, Who = AccountUpn, Detail = strcat(ActionType, " | clickedThrough=", IsClickedThrough, " | ", IPAddress)),
(MessageUrlInfo | where Timestamp > ago(lookback) | where Url has_any (IOC_Domains) or UrlDomain has_any (IOC_Domains)
 | project Timestamp, Source = "Teams message URL", Domain = UrlDomain, Url, Who = "", Detail = strcat("TeamsMessageId=", TeamsMessageId)),
(DeviceNetworkEvents | where Timestamp > ago(lookback) | where RemoteUrl has_any (IOC_Domains)
 | project Timestamp, Source = "Endpoint network", Domain = RemoteUrl, Url = RemoteUrl, Who = strcat(DeviceName, " / ", InitiatingProcessAccountName), Detail = strcat(InitiatingProcessFileName, " -> ", RemoteIP, ":", RemotePort, " ", ActionType)),
(DeviceEvents | where Timestamp > ago(lookback) | where ActionType in ("BrowserLaunchedToOpenUrl", "SmartScreenUrlWarning") and RemoteUrl has_any (IOC_Domains)
 | project Timestamp, Source = "Endpoint browser", Domain = tostring(parse_url(RemoteUrl).Host), Url = RemoteUrl, Who = strcat(DeviceName, " / ", InitiatingProcessAccountName), Detail = ActionType)
| extend OrgSubdomain = tostring(split(Domain, ".")[0])
| order by Timestamp desc
```

**Expected results:** 0 rows. `OrgSubdomain` shows which organization name the actor put in front of the domain; if it is yours, you are being targeted even without a click. For any click or connection, run Queries 3–9 for that user from the click time onward.

---

## Query 2: Passkey, SSO and key-setup look-alike domains — pattern hunt with organization-name subdomains

**Purpose:** Catches **new** infrastructure in the same family before IOC lists catch up. Takes the registrable domain from email URLs, clicks, Teams URLs and endpoint connections, flags root labels containing passkey/SSO/Okta/MFA/key-setup/validation themes, excludes legitimate identity providers (including Entra Seamless SSO's `microsoftazuread-sso.com`), and prioritizes hosts with a **subdomain** (the `org-name.<domain>` pattern) and any that were **clicked or reached from an endpoint**.  
**Severity:** Medium  
**MITRE:** T1566.002, T1583.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Heuristic, multi-table hunting query. Tuning, validated in a live tenant: the first pass surfaced Entra Seamless SSO (autologon.microsoftazuread-sso.com, 322 endpoint events), now in LegitRoots. The only remaining row was an SSO-themed domain in an internal Attack Simulation Training message (blocked, quarantined, never clicked), which shows the pattern works. Extend LegitRoots with your own IdP and SSO vendors; for CD, a UrlClickEvents-only variant filtered to Priority High is row-level."
-->

```kql
let lookback = 30d;
let ThemeRegex = @"(passkey|sso|okta|mfa|keysync|keysetup|keyregister|keyconnect|connectkey|setuphub|validationsetup|portalsetup|verifyid|idverify|accountactivat|authsetup|signinhelp|helpdesk)";
let LegitRoots = dynamic(["microsoft.com", "microsoftonline.com", "microsoftazuread-sso.com", "live.com", "office.com", "office365.com", "okta.com", "oktapreview.com", "okta-emea.com", "oktacdn.com", "apple.com", "google.com", "yubico.com", "fidoalliance.org", "passkeys.dev", "passkeys.io", "1password.com", "bitwarden.com", "duo.com", "duosecurity.com", "onelogin.com", "pingidentity.com", "auth0.com"]);
let Hosts = union isfuzzy=true
(EmailUrlInfo | where Timestamp > ago(lookback) | project Timestamp, Host = tolower(UrlDomain), Url, Source = "Email URL", NetworkMessageId, Who = ""),
(UrlClickEvents | where Timestamp > ago(lookback) | project Timestamp, Host = tolower(tostring(parse_url(Url).Host)), Url, Source = strcat("Click:", Workload), NetworkMessageId, Who = AccountUpn),
(MessageUrlInfo | where Timestamp > ago(lookback) | project Timestamp, Host = tolower(UrlDomain), Url, Source = "Teams URL", NetworkMessageId = "", Who = ""),
(DeviceNetworkEvents | where Timestamp > ago(lookback) | where RemoteUrl has_any ("passkey", "sso", "okta", "mfa", "keysync", "keysetup") | extend Host = tolower(trim_start(@"https?://", RemoteUrl)) | project Timestamp, Host = tostring(split(Host, "/")[0]), Url = RemoteUrl, Source = "Endpoint", NetworkMessageId = "", Who = DeviceName);
Hosts
| where isnotempty(Host)
| extend Labels = split(Host, ".")
| extend RootLabel = tostring(Labels[array_length(Labels) - 2]), Tld = tostring(Labels[array_length(Labels) - 1])
| extend Root = strcat(RootLabel, ".", Tld)
| where Root !in (LegitRoots)
| where RootLabel matches regex ThemeRegex
| extend Subdomain = iff(array_length(Labels) >= 3, strcat_array(array_slice(Labels, 0, array_length(Labels) - 3), "."), "")
| summarize Events = count(), Sources = make_set(Source), Hosts = make_set(Host, 10), Subdomains = make_set_if(Subdomain, isnotempty(Subdomain), 10),
    SampleUrls = make_set(Url, 5), Who = make_set_if(Who, isnotempty(Who), 10), Messages = dcountif(NetworkMessageId, isnotempty(NetworkMessageId)),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by Root
| extend OrgNameSubdomainPattern = array_length(Subdomains) > 0, Clicked = tostring(Sources) has "Click", ReachedEndpoint = tostring(Sources) has "Endpoint"
| extend Priority = case(Clicked or ReachedEndpoint, "High", OrgNameSubdomainPattern, "Medium", "Low")
| order by Priority asc, Events desc
```

**Expected results:** A short list. A root domain registered within the last few days, with your organization's name in `Subdomains`, is the campaign's signature — block it at the proxy and in Defender for Office 365, then check `Who` and the recipients of `Messages` for sign-ins in Queries 3 and 5. Validate registration age with domain WHOIS/RDAP before blocking broad themes.

---

## Query 3: New MFA method registered shortly after an unusual sign-in (actor-controlled factor)

**Purpose:** The actor's first objective after access is to "enroll an MFA method under their control" — a phone number, Authenticator app or software OTP token. For **established users** (with a prior sign-in baseline), finds security-info registrations within **two hours after a successful sign-in from an IP never seen for that user**, and scores them. Points are added for the registration coming from that same IP, a weak or phishable method (software OATH, Authenticator code, phone/SMS, email), a new country, an unmanaged device and sign-in risk; points are subtracted for the mobile self-enrollment shape. Temporary Access Pass issuance is excluded.  
**Severity:** High  
**MITRE:** T1098.005, T1556.006, T1078.004

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline plus cross-table correlation (AuditLogs + EntraIdSignInEvents) - run as a scheduled hunt or Sentinel analytics rule. Tuning, validated in a live tenant: without an established-user baseline, onboarding users produced ~250 matches (every IP is 'new' for a new user); a Temporary Access Pass exclusion removed ~1,100 bulk-issued TAP events. Registration IPs shared by 10+ users are Microsoft service egress and are ignored. The mobile self-enrollment penalty removed 7 legitimate phone-based passkey/Authenticator enrollments. The final 7 Medium rows were analysts registering methods from Azure-hosted admin workstations. Because AH sign-in data is capped at 30 days, the lookback is 14 days against a 16-day baseline."
-->

```kql
let lookback = 14d;
let baselineStart = 30d;
let chainWindow = 2h;
let minScore = 2;
let sharedEgressUsers = 10;
let RegistrationOps = AuditLogs
| where TimeGenerated > ago(lookback)
| where (OperationName in ("User registered security info", "Admin registered security info") and Result =~ "success") or OperationName == "POST UserAuthMethod.SoftwareOathProofupRegistration"
| extend Init = parse_json(tostring(InitiatedBy)), TR = parse_json(tostring(TargetResources))
| extend TargetUpn = tolower(coalesce(tostring(TR[0].userPrincipalName), tostring(Init.user.userPrincipalName))), RegIP = tostring(Init.user.ipAddress);
let SharedEgress = RegistrationOps | where isnotempty(RegIP) | summarize Users = dcount(TargetUpn) by RegIP | where Users >= sharedEgressUsers | project RegIP;
let Registrations = RegistrationOps
| extend Method = case(OperationName has "SoftwareOath", "Software OATH token", ResultReason has "Authenticator App with Code", "Authenticator app (code/OTP)", ResultReason has "Authenticator App", "Authenticator app (push)",
    ResultReason has_any ("phone", "Phone", "SMS"), "Phone / SMS", ResultReason has_any ("email", "Email"), "Email OTP", ResultReason has_any ("Fido2", "Passkey"), "Passkey / FIDO2", ResultReason has "temporary access pass", "Temporary Access Pass", "Unspecified method")
| where Method != "Temporary Access Pass"
| extend RegIP = iff(RegIP in (SharedEgress), "", RegIP)
| project RegTime = TimeGenerated, TargetUpn, Method, RegIP;
let RegUpns = toscalar(Registrations | summarize make_set(TargetUpn));
let SignIns = EntraIdSignInEvents
| where Timestamp > ago(baselineStart)
| where tolower(AccountUpn) in (RegUpns)
| where ErrorCode == 0
| project Timestamp, TargetUpn = tolower(AccountUpn), IPAddress, RiskLevelDuringSignIn, Country, IsManaged, Application, UserAgent;
let BaselineIPs = SignIns | where Timestamp < ago(lookback) | distinct TargetUpn, IPAddress;
let EstablishedUsers = BaselineIPs | summarize BaselineIpCount = dcount(IPAddress) by TargetUpn;
let BaselineCountries = SignIns | where Timestamp < ago(lookback) | distinct TargetUpn, Country;
let UnusualSignIns = SignIns
| where Timestamp > ago(lookback)
| join kind=leftanti BaselineIPs on TargetUpn, IPAddress
| join kind=leftouter (BaselineCountries | extend KnownCountry = true) on TargetUpn, Country
| summarize SignInTime = min(Timestamp), Risk = max(RiskLevelDuringSignIn), NewCountry = max(toint(isnull(KnownCountry))), Country = take_any(Country),
            Unmanaged = max(toint(IsManaged == 0)), Apps = make_set(Application, 10), UAs = make_set(substring(UserAgent, 0, 90), 5)
    by TargetUpn, IPAddress;
Registrations
| join kind=inner EstablishedUsers on TargetUpn
| join kind=inner UnusualSignIns on TargetUpn
| where RegTime between (SignInTime .. (SignInTime + chainWindow))
| extend SameIP = isnotempty(RegIP) and RegIP == IPAddress,
         WeakMethod = Method in ("Software OATH token", "Authenticator app (code/OTP)", "Phone / SMS", "Email OTP"),
         MobileSelfEnrollment = set_has_element(Apps, "Microsoft Authenticator App") and tostring(UAs) has_any ("AuthenticatorSSOExtension", "iPhone", "iPad", "Android", "Dalvik")
| extend Score = toint(SameIP) + toint(WeakMethod) + toint(NewCountry == 1) + toint(Unmanaged == 1) + iff(Risk >= 50, 2, 0) - iff(MobileSelfEnrollment, 3, 0)
| where Score >= minScore
| summarize MaxScore = max(Score), Methods = make_set(Method), RegIPs = make_set_if(RegIP, isnotempty(RegIP), 5), UnusualIPs = make_set(IPAddress, 5), Countries = make_set(Country, 5),
    NewCountry = max(NewCountry), MaxRisk = max(Risk), Unmanaged = max(Unmanaged), SignInApps = make_set(Apps, 10), UAs = make_set(UAs, 5),
    FirstUnusualSignIn = min(SignInTime), FirstReg = min(RegTime), BaselineIpCount = take_any(BaselineIpCount)
    by TargetUpn
| extend MinutesSignInToReg = round(datetime_diff("second", FirstReg, FirstUnusualSignIn) / 60.0, 1)
| extend Priority = case(MaxRisk >= 50 or MaxScore >= 4, "High", "Medium")
| project TargetUpn, Priority, MaxScore, Methods, MaxRisk, NewCountry, Countries, UnusualIPs, RegIPs, MinutesSignInToReg, FirstReg, SignInApps, UAs
| order by MaxScore desc, MaxRisk desc
```

**Expected results:** A handful of rows. Contact each user **through a verified channel** and ask whether they added the method and whether anyone called about "passkey" or "SSO" setup. If they didn't add it, remove the method, revoke sessions, and run Queries 6–9 from `FirstReg`. Enforce a Conditional Access policy for security-info registration (phishing-resistant strength, compliant device or named location, sign-in frequency *every time*, block at high risk).

---

## Query 4: Directory-level MFA device and software OATH token additions (`Update user.` StrongAuthentication properties)

**Purpose:** Adapts Microsoft's published query. Parses `Update user.` audit events in `CloudAppEvents` for `StrongAuthenticationPhoneAppDetail` / `StrongAuthenticationUserDetails` changes where the **device count increased**, a **software token** (`SoftwareTokenActivated`, `NO_DEVICE_TOKEN`) was added, or the registered phone details changed. It captures the actor (`UserId`, often a service principal for this operation), IP and ISP.  
**Severity:** High  
**MITRE:** T1098.005, T1556.006

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "MFA device or software token added for {{TargetUpn}}"
impactedAssets:
  - type: user
    identifier: accountObjectId
    column: TargetObjectId
recommendedActions: "A new MFA device, phone detail or software OATH token was added to this account. Confirm with the user through a verified out-of-band channel. If unexpected, remove the method, revoke all sessions and refresh tokens, reset the password, and review the user's Graph, SharePoint/OneDrive and Exchange activity since the change."
adaptation_notes: "Single-table row-level CloudAppEvents query with ReportId - suitable for a 1H custom detection. Validated: executed cleanly with 0 rows. In the validation tenant, 'Update user.' events carried no StrongAuthentication* modified properties at all (59 events, mostly PreferredLanguage), so this could not be exercised against a positive. Run Query 3 alongside it; tenants whose audit shape matches the article's sample will see these properties here."
-->

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Update user."
| extend RD = parse_json(tostring(RawEventData))
| where tostring(RD.ResultStatus) == "Success"
| where tostring(RD.ModifiedProperties) has_any ("StrongAuthenticationPhoneAppDetail", "StrongAuthenticationUserDetails")
| extend TargetObjectId = extract(@"User_([a-f0-9\-]+)", 1, tostring(RD.Target)), TargetUpn = tostring(RD.ObjectId), Actor = tostring(RD.UserId)
| mv-expand ModifiedProp = RD.ModifiedProperties
| where tostring(ModifiedProp.Name) in ("StrongAuthenticationPhoneAppDetail", "StrongAuthenticationUserDetails")
| extend PropertyName = tostring(ModifiedProp.Name), OldValue = tostring(ModifiedProp.OldValue), NewValue = tostring(ModifiedProp.NewValue)
| extend OldDeviceCount = countof(OldValue, @"""Id"""), NewDeviceCount = countof(NewValue, @"""Id"""),
         SoftwareTokenAdded = countof(NewValue, "SoftwareTokenActivated") > countof(OldValue, "SoftwareTokenActivated"),
         NoDeviceTokenAdded = countof(NewValue, "NO_DEVICE_TOKEN") > countof(OldValue, "NO_DEVICE_TOKEN"),
         PhoneChanged = PropertyName == "StrongAuthenticationUserDetails" and OldValue != NewValue
| where NewDeviceCount > OldDeviceCount or SoftwareTokenAdded or PhoneChanged
| project Timestamp, TargetUpn, TargetObjectId, Actor, PropertyName, OldDeviceCount, NewDeviceCount, SoftwareTokenAdded, NoDeviceTokenAdded, PhoneChanged,
          IPAddress, CountryCode, ISP, IsAnonymousProxy, ReportId, NewValue = substring(NewValue, 0, 500)
| order by Timestamp desc
```

**Expected results:** In tenants where these properties are logged, routine phone changes and new-phone Authenticator installs appear. A `SoftwareTokenAdded` / `NoDeviceTokenAdded` row the user can't explain is the exact attacker-controlled OATH token in the article's sample record.

---

## Query 5: OfficeHome AiTM-shaped session from an unmanaged device and new IP, fanning out to identity portals and collaboration apps

**Purpose:** Reproduces the article's timeline. It finds OfficeHome sessions from an **unmanaged device** containing the MFA-required (`50074`) or keep-me-signed-in (`50140`) interrupt followed by success, then everything that same `SessionId` reached in the next 60 minutes. Identity portals (My Sign-Ins, My Apps, My Profile, Approval Management, Account Controls V2, OCaaS) and collection apps (SharePoint, OneDrive, Outlook Web, `OwaDownloadAttachments`, Windows App – Web, M365ChatClient) are listed. Priority is driven by whether the **session start IP is new for the user** and whether the session hopped IPs.  
**Severity:** Medium  
**MITRE:** T1557, T1078.004, T1526

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Session reconstruction across EntraIdSignInEvents with a baseline - hunting only. The app fan-out alone is NOT a detection: in validation, every qualifying OfficeHome session touched 3-5 of the identity portals, because the Office portal loads them automatically. The discriminators are the unmanaged device, a start IP absent from the user's 16-day baseline, and IP changes within the session. Validated: 9 sessions over 14 days, with 6 from previously seen analyst or AVD egress (Low); the remaining new-IP sessions were Microsoft-hosted (AS8075) analyst environments. 50074 did not occur on OfficeHome in the validation tenant, so 50140 carries the pattern."
-->

```kql
let lookback = 14d;
let baselineStart = 30d;
let sessionWindow = 60m;
let minPortalApps = 3;
let IdentityPortals = dynamic(["My Signins", "My Apps", "My Profile", "Microsoft Approval Management", "Microsoft Account Controls V2", "OCaaS Experience Management Service", "Microsoft App Access Panel"]);
let CollectionApps = dynamic(["Office 365 SharePoint Online", "SharePoint Online Web Client Extensibility", "OneDrive", "Outlook Web", "One Outlook Web", "OwaDownloadAttachments", "M365ChatClient", "Windows App - Web", "Microsoft Teams Web Client", "Office 365 Exchange Online"]);
let Starts = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where Application =~ "OfficeHome"
| where isnotempty(SessionId)
| summarize StartTime = min(Timestamp), Codes = make_set(ErrorCode), Success = countif(ErrorCode == 0), StartIP = take_anyif(IPAddress, ErrorCode == 0),
            Unmanaged = max(toint(IsManaged == 0)), Country = take_any(Country), UA = take_any(substring(UserAgent, 0, 110)), Risk = max(RiskLevelDuringSignIn)
    by AccountObjectId, AccountUpn, SessionId
| where Success > 0 and (set_has_element(Codes, 50074) or set_has_element(Codes, 50140))
| where Unmanaged == 1;
let StartUsers = Starts | distinct AccountObjectId;
let BaselineIPs = EntraIdSignInEvents
| where Timestamp between (ago(baselineStart) .. ago(lookback))
| where AccountObjectId in (StartUsers) and ErrorCode == 0
| distinct AccountObjectId, IPAddress;
let SessionIds = Starts | project SessionId;
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where SessionId in (SessionIds) and ErrorCode == 0
| join kind=inner Starts on SessionId
| where Timestamp between (StartTime .. (StartTime + sessionWindow))
| summarize Apps = make_set(Application, 30), AppCount = dcount(Application),
    PortalApps = make_set_if(Application, Application in (IdentityPortals), 10),
    CollectionAppsHit = make_set_if(Application, Application in (CollectionApps), 10),
    SessionIPs = make_set(IPAddress, 5), LastEvent = max(Timestamp)
    by AccountObjectId, AccountUpn, SessionId, StartTime, StartIP, Country, UA, Risk
| extend PortalCount = array_length(PortalApps), CollectionCount = array_length(CollectionAppsHit)
| where PortalCount >= minPortalApps and CollectionCount >= 1
| join kind=leftouter (BaselineIPs | extend KnownIP = true) on AccountObjectId, $left.StartIP == $right.IPAddress
| extend NewStartIP = isnull(KnownIP), SessionMinutes = round(datetime_diff("second", LastEvent, StartTime) / 60.0, 1)
| extend Priority = case(NewStartIP and (Risk >= 50 or array_length(SessionIPs) > 1), "High", NewStartIP, "Medium", "Low")
| project StartTime, AccountUpn, Priority, StartIP, NewStartIP, Country, UA, Risk, SessionMinutes, AppCount, PortalCount, PortalApps, CollectionAppsHit, SessionIPs, SessionId
| order by Priority asc, PortalCount desc
```

**Expected results:** Many `Low` rows from users' normal locations. Investigate `High`/`Medium` sessions whose start IP belongs to a proxy or hosting provider the user doesn't normally use. Pivot the `SessionId` into Query 3 (did a method registration follow?) and the user into Queries 6–8.

---

## Query 6: Microsoft Graph reconnaissance progressing to content collection, from an IP new to the user

**Purpose:** Consolidates Microsoft's published Graph recon hunts (broad recon, privilege/MFA/app discovery, repository discovery, mailbox discovery, pagination and recon-to-collection). Categorizes each delegated Graph call, and for each user + IP + client app + hour requires **three or more recon categories**, six or more distinct paths, and either **content retrieval** (`/content`, `/attachments`, non-photo `/$value`) or heavy **paging/delta/search**. Microsoft portal back-ends are excluded, and only IPs **absent from the user's sign-in baseline** are kept — the actor "rotated infrastructure... separate IP addresses often used for authentication, reconnaissance, and exfiltration."  
**Severity:** High  
**MITRE:** T1087.004, T1069.003, T1526, T1213.002, T1114.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation plus baseline join - hunting or Sentinel analytics rule. Tuning, validated in a live tenant: the article's broad-recon logic produced thousands of 30-minute windows, dominated by Microsoft portal back-ends (Office 365 Portal, Security & Compliance Center, Azure portal, My Profile, My Apps, Entitlement Management, registered-apps blade), now excluded by client app ID. Requiring an IP new to the user cut the remainder to 4 windows. Excluding /photo $value calls (people-card thumbnails) removed 2 false 'content collection' rows. The final 2 rows were one admin's Graph PowerShell directory and role enumeration from Azure-hosted IPs. Extend PortalAppIds only after confirming an app is a Microsoft first-party portal back-end."
-->

```kql
let lookback = 7d;
let baselineStart = 30d;
let minCategories = 3;
let minDistinctPaths = 6;
// Microsoft first-party portal back-ends that fan out across directory, mail and files on normal page loads (validate for your tenant):
// Office 365 Portal, Security & Compliance Center, ADIbizaUX (Azure portal), Microsoft_AAD_RegisteredApps, Microsoft_AAD_UsersAndTenants,
// My Signins, My Profile, My Apps, Entra Identity Governance - Entitlement Management
let PortalAppIds = dynamic(["00000006-0000-0ff1-ce00-000000000000", "80ccca67-54bd-44ab-8625-4b79c4dc7775", "74658136-14ec-4630-ad9b-26e160ff0fc6", "18ed3507-a475-4ccb-b669-d66bc9f2a36e", "f9885e6e-6f74-46b3-b595-350157a27541", "19db86c3-b2b9-44cc-b339-36da233a3be2", "8c59ead7-d703-4a27-9e55-c96a0054c8d2", "2793995e-0a7d-40d7-bd35-6968ba142197", "810dcf14-1858-4bf2-8134-4c369fa3235b"]);
let Windows = GraphAPIAuditEvents
| where Timestamp > ago(lookback)
| where toint(ResponseStatusCode) between (200 .. 299)
| where isnotempty(AccountObjectId)
| where not(ApplicationId in (PortalAppIds))
| extend Uri = tolower(RequestUri), Path = tostring(split(tolower(RequestUri), "?")[0])
| extend ReconType = case(
   Uri has_any ("/content", "/attachments") or (Uri has "/$value" and not(Uri contains "/photo")), "ContentCollection",
   Uri has "/organization" or Uri has "/subscribedskus" or Uri has "/licensedetails", "Tenant",
   Uri has "/directoryroles" or Uri has "/rolemanagement" or Uri has "/authentication/methods", "PrivilegeMfa",
   Uri has "/applications" or Uri has "/serviceprincipals" or Uri has "/oauth2permissiongrants" or Uri has "/approleassign", "Application",
   Uri has "/sites" or Uri has "/drive" or Uri has "/lists", "Repository",
   Uri has "/messages" or Uri has "/mailfolders", "Mailbox",
   Uri has "/users" or Uri has "/groups" or Uri has "/members", "Directory",
   "Other")
| where ReconType != "Other"
| summarize Requests = count(), Categories = dcountif(ReconType, ReconType != "ContentCollection"), DistinctPaths = dcount(Path),
    ContentRequests = countif(ReconType == "ContentCollection"), Paging = countif(Uri has_any ("$top", "%24top", "$skip", "%24skip", "$skiptoken", "%24skiptoken", "/delta", "/search")),
    ReconTypes = make_set(ReconType, 10), SamplePaths = make_set(Path, 10), ResponseBytes = sum(ResponseSize)
    by AccountObjectId, IpAddress, ApplicationId, Window = bin(Timestamp, 1h)
| where Categories >= minCategories and DistinctPaths >= minDistinctPaths and (ContentRequests > 0 or Paging >= 8);
let Users = Windows | distinct AccountObjectId;
let KnownIPs = EntraIdSignInEvents
| where Timestamp between (ago(baselineStart) .. ago(lookback))
| where AccountObjectId in (Users) and ErrorCode == 0
| distinct AccountObjectId, IPAddress;
Windows
| join kind=leftanti KnownIPs on AccountObjectId, $left.IpAddress == $right.IPAddress
| extend Stage = iff(ContentRequests > 0, "Recon + collection", "Recon (automated paging)")
| extend Priority = iff(ContentRequests > 0, "High", "Medium")
| project Window, AccountObjectId, ApplicationId, IpAddress, Priority, Stage, Requests, Categories, ReconTypes, ContentRequests, Paging, DistinctPaths, ResponseBytes, SamplePaths
| order by Priority asc, Requests desc
```

**Expected results:** Administrators running Graph PowerShell or Azure CLI from new jump hosts will appear as `Medium`. A `High` row — broad directory, privilege and repository discovery plus content retrieval from an IP the user never signed in from — is the article's reconnaissance-to-collection chain. For >30 days, or to add token and session correlation, port to `MicrosoftGraphActivityLogs` in the Data Lake (`AppId`, `UserId`, `SignInActivityId`, `UserAgent`).

---

## Query 7: Sustained SharePoint/OneDrive bulk access with automation user agents, anonymous proxies or uncommon ISP/UA

**Purpose:** Consolidates Microsoft's `python-httpx` and anonymous-proxy SharePoint/OneDrive hunts. Counts `FileAccessed` / `FileDownloaded` / sync downloads per user + IP + hour (≥100) and keeps pairs with an **automation user agent** (`python-httpx`, `python-requests`, `aiohttp`, Node HTTP clients, Go, curl), an **anonymous proxy**, or Defender's `UncommonForUser` ISP/UA flags. It also surfaces pairs sustained over **three or more hours** — the article's "measured and sustained" collection at under 1,000 items per hour. Microsoft Search and eDiscovery export readers are excluded.  
**Severity:** High  
**MITRE:** T1530, T1213.002, T1567

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Two-level aggregation - hunting or Sentinel analytics rule. Tuning, validated in a live tenant: 906k SharePoint/OneDrive access events in 30 days, with 0 automation-UA and 0 anonymous-proxy events. Before tuning, the only matches were Purview eDiscovery/Content Search export ('ExportWorker' UA from Microsoft Azure, up to 7,222 files/hour for one custodian), now excluded alongside Microsoft Search ('ODMTADemand'). The tuned query returned 0 rows. For CD, a row-level variant limited to the python-httpx user agent (as in the article) is viable once you confirm no sanctioned scripts use it."
-->

```kql
let lookback = 30d;
let perHourMin = 100;
let minSustainedHours = 3;
let AutomationUAs = dynamic(["python-httpx", "python-requests", "aiohttp", "node-fetch", "axios", "undici", "Go-http-client", "curl/", "okhttp", "libwww-perl", "PowerShell/"]);
// Microsoft service readers that legitimately bulk-read content (Microsoft Search / eDiscovery export) - validate for your tenant
let ServiceUAs = dynamic(["ODMTADemand", "ExportWorker"]);
CloudAppEvents
| where Timestamp > ago(lookback)
| where ApplicationId in (20892, 15600)
| where ActionType in ("FileDownloaded", "FileAccessed", "FileSyncDownloadedFull", "SyncDownloadedFull", "FilePreviewed")
| where isnotempty(AccountObjectId) and isnotempty(IPAddress)
| where not(UserAgent has_any (ServiceUAs))
| extend AutomationUA = UserAgent has_any (AutomationUAs), UncommonIsp = UncommonForUser has "ISP", UncommonUa = UncommonForUser has "UserAgent"
| summarize HourEvents = count(), Files = dcount(ObjectName), AutomationUA = max(toint(AutomationUA)), AnonProxy = max(toint(IsAnonymousProxy == true)),
    UncommonIsp = max(toint(UncommonIsp)), UncommonUa = max(toint(UncommonUa)), UA = take_any(UserAgent), ISP = take_any(ISP), Actions = make_set(ActionType)
    by AccountObjectId, AccountDisplayName, IPAddress, Hour = bin(Timestamp, 1h)
| where HourEvents >= perHourMin
| summarize ActiveHours = count(), Events = sum(HourEvents), Files = sum(Files), MaxHour = max(HourEvents), FirstHour = min(Hour), LastHour = max(Hour),
    AutomationUA = max(AutomationUA), AnonProxy = max(AnonProxy), UncommonIsp = max(UncommonIsp), UncommonUa = max(UncommonUa),
    UAs = make_set(UA, 3), ISPs = make_set(ISP, 3), Actions = make_set(Actions)
    by AccountObjectId, AccountDisplayName, IPAddress
| extend Signals = AutomationUA + AnonProxy + UncommonIsp + UncommonUa, Sustained = ActiveHours >= minSustainedHours
| where AutomationUA == 1 or AnonProxy == 1 or Signals >= 2 or (Signals >= 1 and Sustained)
| extend Priority = case(AutomationUA == 1 or AnonProxy == 1, "High", "Medium")
| order by Priority asc, Events desc
```

**Expected results:** 0 rows in most tenants. A user pulling hundreds of files an hour for several hours through a scripting client or proxy IP is the collection stage. Revoke sessions immediately, block the IP, and use the audit trail (`ObjectName`) to scope what left. Sanctioned migration or backup tools will need an allowlist by account and IP.

---

## Query 8: High-volume Exchange Online REST access through Office/Outlook Web client tokens

**Purpose:** Adapts Microsoft's Exchange REST exfiltration hunt. Exchange REST activity performed with a user's token through the **One Outlook Web** or **Microsoft Office** client is logged with an empty `AccountObjectId`, the client as `AccountDisplayName`, and the user in `RawEventData.TokenObjectId`. Counts events per token user + IP + client per hour (≥500), joins the UPN from `IdentityInfo`, and summarizes sustained hours and operations.  
**Severity:** High  
**MITRE:** T1114.002, T1567

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation hunt (per hour, per token user/IP). Validated: executed cleanly with 0 rows. In the validation tenant, Exchange events with an empty AccountObjectId came only from supervision/label-rule service mailboxes and admin cmdlets - none carried the One Outlook Web / Office client display names the article describes - so the filter could not be exercised against a positive. Keep the client-name list current: the article lists both the display name and the app IDs as they appear in AccountDisplayName."
-->

```kql
let lookback = 30d;
let perHourMin = 500;
let MailClientNames = dynamic(["One Outlook Web", "Microsoft Office", "9199bf20-a13f-4107-85dc-02114787ef48", "d3590ed6-52b3-4102-aeff-aad2292ab01c"]);
CloudAppEvents
| where Timestamp > ago(lookback)
| where ApplicationId == 20893
| where isempty(AccountObjectId)
| where AccountDisplayName in (MailClientNames)
| where isnotempty(IPAddress)
| extend RD = parse_json(tostring(RawEventData))
| extend TokenUserId = tostring(RD.TokenObjectId), Operation = tostring(RD.Operation), ClientApp = AccountDisplayName
| summarize ExchangeRestEvents = count(), Operations = make_set(Operation, 10), UAs = make_set(UserAgent, 3), ISP = take_any(ISP), Country = take_any(CountryCode),
    AnonProxy = max(toint(IsAnonymousProxy == true))
    by TokenUserId, IPAddress, ClientApp, Hour = bin(Timestamp, 1h)
| where ExchangeRestEvents >= perHourMin
| summarize ActiveHours = count(), Events = sum(ExchangeRestEvents), MaxHour = max(ExchangeRestEvents), FirstHour = min(Hour), LastHour = max(Hour),
    Operations = make_set(Operations, 10), UAs = make_set(UAs, 5), ISP = take_any(ISP), Country = take_any(Country), AnonProxy = max(AnonProxy)
    by TokenUserId, IPAddress, ClientApp
| join kind=leftouter (IdentityInfo | where Timestamp > ago(14d) | summarize arg_max(Timestamp, AccountUpn) by AccountObjectId | project TokenUserId = AccountObjectId, AccountUpn) on TokenUserId
| order by Events desc
```

**Expected results:** 0 rows normally. Hundreds of REST mailbox operations an hour, for several hours, from one IP through an Outlook Web or Office client token matches the Exchange collection path. Pair it with the user's `MailItemsAccessed` audit to see which items were read.

---

## Query 9: End-to-end chain — MFA method from a new IP, then Graph or SharePoint/OneDrive collection within 48 hours

**Purpose:** The article's central guidance is to "investigate this sequence across identity, Microsoft Graph, SharePoint, OneDrive, and Exchange signals" rather than single events. For established users, this takes security-info registrations from an IP **not in the user's baseline** (ignoring shared Microsoft egress), then measures, within 48 hours, delegated Graph collection (content retrieval and recon calls, excluding portal back-ends and photos) and SharePoint/OneDrive downloads. Rows where collection ran **from the registration IP** are ranked highest.  
**Severity:** High  
**MITRE:** T1098.005, T1087.004, T1530, T1213.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table sequence correlation (AuditLogs, EntraIdSignInEvents, GraphAPIAuditEvents, CloudAppEvents) - Sentinel analytics rule or scheduled hunt. Tuning, validated in a live tenant: with loose thresholds (any content call, 100+ files) the chain matched 10 registrations whose follow-on activity was 1-3 Graph calls or ~118 routine file opens; the thresholds (20+ content calls, 200+ Graph calls, or 500+ files in 48 hours) and the shared-egress rule reduced this to 0 rows. The article's actor stayed under 1,000 items per hour but sustained collection for hours, so these 48-hour totals sit well below its observed volume."
-->

```kql
let lookback = 14d;
let baselineStart = 30d;
let followWindow = 48h;
let sharedEgressUsers = 10;
let minGraphContent = 20;
let minGraphCalls = 200;
let minSpoFiles = 500;
let PortalAppIds = dynamic(["00000006-0000-0ff1-ce00-000000000000", "80ccca67-54bd-44ab-8625-4b79c4dc7775", "74658136-14ec-4630-ad9b-26e160ff0fc6", "18ed3507-a475-4ccb-b669-d66bc9f2a36e", "f9885e6e-6f74-46b3-b595-350157a27541", "19db86c3-b2b9-44cc-b339-36da233a3be2", "8c59ead7-d703-4a27-9e55-c96a0054c8d2", "2793995e-0a7d-40d7-bd35-6968ba142197", "810dcf14-1858-4bf2-8134-4c369fa3235b"]);
let RegistrationOps = AuditLogs
| where TimeGenerated > ago(lookback)
| where (OperationName in ("User registered security info", "Admin registered security info") and Result =~ "success") or OperationName == "POST UserAuthMethod.SoftwareOathProofupRegistration"
| where not(ResultReason has "temporary access pass")
| extend Init = parse_json(tostring(InitiatedBy)), TR = parse_json(tostring(TargetResources))
| extend TargetUpn = tolower(coalesce(tostring(TR[0].userPrincipalName), tostring(Init.user.userPrincipalName))), RegIP = tostring(Init.user.ipAddress), Method = coalesce(ResultReason, OperationName);
let SharedEgress = RegistrationOps | where isnotempty(RegIP) | summarize Users = dcount(TargetUpn) by RegIP | where Users >= sharedEgressUsers | project RegIP;
let Registrations = RegistrationOps | where isnotempty(RegIP) and not(RegIP in (SharedEgress)) | project RegTime = TimeGenerated, TargetUpn, RegIP, Method;
let RegUpns = toscalar(Registrations | summarize make_set(TargetUpn));
let Ids = EntraIdSignInEvents | where Timestamp > ago(baselineStart) | where tolower(AccountUpn) in (RegUpns) | summarize by TargetUpn = tolower(AccountUpn), AccountObjectId;
let BaselineIPs = EntraIdSignInEvents | where Timestamp between (ago(baselineStart) .. ago(lookback)) | where tolower(AccountUpn) in (RegUpns) and ErrorCode == 0 | distinct TargetUpn = tolower(AccountUpn), IPAddress;
let SuspectRegs = Registrations
| join kind=inner (BaselineIPs | summarize by TargetUpn) on TargetUpn
| join kind=leftanti BaselineIPs on TargetUpn, $left.RegIP == $right.IPAddress
| join kind=inner Ids on TargetUpn;
let Users = SuspectRegs | distinct AccountObjectId;
let GraphCollection = GraphAPIAuditEvents
| where Timestamp > ago(lookback)
| where AccountObjectId in (Users) and toint(ResponseStatusCode) between (200 .. 299) and not(ApplicationId in (PortalAppIds))
| extend Uri = tolower(RequestUri)
| extend IsContent = Uri has_any ("/content", "/attachments") or (Uri has "/$value" and not(Uri contains "/photo"))
| where IsContent or Uri has_any ("/messages", "/mailfolders", "/drive", "/sites", "/users", "/groups", "/directoryroles", "/serviceprincipals")
| summarize GraphCalls = count(), GraphContent = countif(IsContent), GraphIPs = make_set(IpAddress, 5), GFirst = min(Timestamp) by AccountObjectId, Day = bin(Timestamp, 1d);
let SpoCollection = CloudAppEvents
| where Timestamp > ago(lookback)
| where AccountObjectId in (Users) and ApplicationId in (20892, 15600)
| where ActionType in ("FileDownloaded", "FileAccessed", "FileSyncDownloadedFull", "SyncDownloadedFull")
| where not(UserAgent has_any ("ODMTADemand", "ExportWorker"))
| summarize SpoFiles = count(), SpoIPs = make_set(IPAddress, 5), SFirst = min(Timestamp) by AccountObjectId, Day = bin(Timestamp, 1d);
SuspectRegs
| join kind=leftouter GraphCollection on AccountObjectId
| extend GraphInWindow = isnotnull(GFirst) and GFirst between (RegTime .. (RegTime + followWindow))
| join kind=leftouter SpoCollection on AccountObjectId
| extend SpoInWindow = isnotnull(SFirst) and SFirst between (RegTime .. (RegTime + followWindow))
| summarize GraphCalls = sumif(GraphCalls, GraphInWindow), GraphContent = sumif(GraphContent, GraphInWindow), SpoFiles = sumif(SpoFiles, SpoInWindow),
    GraphIPs = make_set_if(GraphIPs, GraphInWindow, 5), SpoIPs = make_set_if(SpoIPs, SpoInWindow, 5)
    by RegTime, TargetUpn, RegIP, Method
| where GraphContent >= minGraphContent or GraphCalls >= minGraphCalls or SpoFiles >= minSpoFiles
| extend CollectionFromRegIP = tostring(GraphIPs) has RegIP or tostring(SpoIPs) has RegIP
| extend Priority = iff(CollectionFromRegIP, "High", "Medium")
| order by CollectionFromRegIP desc, SpoFiles desc, GraphContent desc
```

**Expected results:** 0 rows normally. Any row is a near-complete match for the article's intrusion sequence. Treat it as a confirmed compromise: disable the account temporarily, revoke sessions and refresh tokens, remove the new method, reset credentials, and scope data access with Queries 6–8.

---

## Query 10: Internal Teams messages linking to passkey, SSO or sign-in-themed domains

**Purpose:** In some intrusions the actor used "a trusted employee identity" to "send similar passkey-themed messages through Microsoft Teams." Joins Teams message URLs to message metadata and flags, per sender per two hours, links to **themed domains** (passkey/SSO/Okta/MFA/key-setup/sign-in/verify/helpdesk) or fan-out to **five or more threads**. Internal user senders are ranked highest, and Teams threat verdicts are included.  
**Severity:** Medium  
**MITRE:** T1534, T1566.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Sender-window aggregation over MessageUrlInfo + MessageEvents - hunting only. Requires Defender for Office 365 Teams protection populating MessageEvents/MessageUrlInfo. Validated: executed cleanly with 0 rows; the validation tenant had only 84 Teams URL records in 30 days (mostly Workflows cards), so fan-out thresholds could not be tuned against real traffic. MessageEvents has no message body, so text-only lures without a URL are not visible here."
-->

```kql
let lookback = 30d;
let fanOutWindow = 2h;
let ThemeRegex = @"(passkey|sso|okta|mfa|keysync|keysetup|keyregister|keyconnect|connectkey|setuphub|validationsetup|portalsetup|signin|login|verify|helpdesk|authenticat)";
let CommonRoots = dynamic(["microsoft.com", "office.com", "sharepoint.com", "live.com", "microsoftonline.com", "office365.com", "outlook.com", "skype.com", "aka.ms", "bing.com", "github.com", "youtube.com", "linkedin.com"]);
MessageUrlInfo
| where Timestamp > ago(lookback)
| extend Host = tolower(UrlDomain)
| extend Labels = split(Host, ".")
| extend Root = strcat(tostring(Labels[array_length(Labels) - 2]), ".", tostring(Labels[array_length(Labels) - 1]))
| where Root !in (CommonRoots)
| join kind=inner (
    MessageEvents
    | where Timestamp > ago(lookback)
    | project TeamsMessageId, MsgTime = Timestamp, SenderEmailAddress, SenderObjectId, SenderType, IsExternalThread, ThreadId, ThreadType, RecipientDetails, ThreatTypes, DeliveryAction
  ) on TeamsMessageId
| extend ThemedDomain = Host matches regex ThemeRegex, OrgSubdomain = array_length(Labels) >= 3
| summarize Messages = dcount(TeamsMessageId), Threads = dcount(ThreadId), Recipients = dcount(tostring(RecipientDetails)), Roots = make_set(Root, 5), Hosts = make_set(Host, 5),
    Themed = max(toint(ThemedDomain)), External = max(toint(IsExternalThread)), Threats = make_set_if(ThreatTypes, isnotempty(ThreatTypes), 3), Delivery = make_set(DeliveryAction),
    SampleUrls = make_set(Url, 5), FirstSeen = min(MsgTime), LastSeen = max(MsgTime)
    by SenderEmailAddress, SenderObjectId, SenderType, Window = bin(MsgTime, fanOutWindow)
| where Themed == 1 or Threads >= 5 or array_length(Threats) > 0
| extend InternalSender = External == 0 and SenderType =~ "User"
| extend Priority = case(InternalSender and Themed == 1, "High", array_length(Threats) > 0, "High", InternalSender and Threads >= 5, "Medium", "Low")
| order by Priority asc, Threads desc
```

**Expected results:** 0 rows normally. An internal user sending passkey- or SSO-themed links to several colleagues means that sender is likely already compromised. Run Queries 3–9 for the **sender**, soft-delete the messages, and check each recipient's sign-ins after the message time.

---

## Query 11: Defender detections matching the article's coverage table, grouped by account and stage

**Purpose:** Pulls alerts whose titles match Microsoft's listed coverage: malicious or suspicious MFA device, Authenticator, phone or email registration; sign-in from recognized attacker infrastructure; suspicious Entra Graph API query; and automated mass SharePoint/OneDrive access via python-httpx. Groups them by account and kill-chain stage.  
**Severity:** High  
**MITRE:** T1098.005, T1087.004, T1530

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Alert-correlation triage over existing Defender detections; re-alerting would duplicate them. Validated: executed cleanly with 0 rows. A sanity search of all AlertInfo titles containing MFA, Graph, registration or attacker infrastructure found only unrelated detections (MFA-fatigue approval alerts, OAuth app registration), confirming the zero is real. 'Suspicious MFA Authentication Approval' (MFA fatigue, T1621) is deliberately not included - it is a different technique."
-->

```kql
let lookback = 30d;
let ArticleTitles = dynamic([
  "Malicious registration of a device with strong MFA", "Malicious registration of an attacker controlled MFA device",
  "Suspicious registration of a new Authenticator MFA method", "Malicious registration of a new Authenticator MFA method",
  "Suspicious registration of a new Phone MFA method", "Malicious registration of a new Phone MFA method", "Malicious registration of a new Email MFA method",
  "Malicious sign in from an IP address associated with recognized attacker infrastructure", "Suspicious Entra Graph API query observed",
  "Automated mass SharePoint/OneDrive file access via python-httpx", "A storage account was accessed from a suspicious IP address"]);
let Stage = (t:string) { case(t has "registration", "Persistence (MFA)", t has "Graph", "Discovery (Graph)", t has_any ("SharePoint", "OneDrive", "storage", "extracted", "exfiltrated"), "Collection/Exfil", t has "sign in", "Initial access", "Other") };
AlertInfo
| where Timestamp > ago(lookback)
| where Title has_any (ArticleTitles) or (Title has "MFA method" and Title has_any ("Suspicious", "Malicious")) or Title has "python-httpx" or Title has "Graph API query"
| extend Stage = Stage(Title)
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | summarize Accounts = make_set_if(coalesce(AccountUpn, AccountName), isnotempty(coalesce(AccountUpn, AccountName)), 10),
                IPs = make_set_if(RemoteIP, isnotempty(RemoteIP), 10) by AlertId
  ) on AlertId
| mv-expand Account = iff(array_length(Accounts) == 0, dynamic([""]), Accounts) to typeof(string)
| summarize Alerts = dcount(AlertId), Stages = make_set(Stage), StageCount = dcount(Stage), Titles = make_set(Title, 10), IPs = make_set(IPs, 10),
    FirstAlert = min(Timestamp), LastAlert = max(Timestamp) by Account
| extend Priority = case(StageCount >= 2, "High", "Medium")
| order by StageCount desc, Alerts desc
```

**Expected results:** Ideally 0. Any "Malicious registration of…" alert should be treated as confirmed persistence — pivot the account into Queries 5–9 from the alert time. Coverage depends on Defender for Identity and Defender for Cloud Apps being deployed.

---

## General Tuning Notes

1. **IOC refresh and pattern hunting.** The 15 published domains are parent domains with per-target subdomains and short lifetimes. Keep Query 1 current from Microsoft Defender Threat Intelligence, and rely on Query 2's theme-plus-subdomain pattern for new registrations. Validate a candidate's registration age before blocking.

2. **Sequence over single events.** The article is explicit: Graph calls to `/users`, `/groups` or `/sites` are normal individually. Queries 3, 5, 6 and 9 all require an identity anomaly (a new IP, unmanaged device or new method) **plus** follow-on behavior. Don't strip the anchors to simplify.

3. **Know your audit shape.** MFA method changes appear in `AuditLogs` security-info events (Query 3) and, in some tenants, as `Update user.` `StrongAuthentication*` properties in `CloudAppEvents` (Query 4). Run both, and treat the registration audit IP as unreliable when it is shared across many users.

4. **Portal back-ends and Microsoft services.** Exclude Microsoft first-party portal clients from Graph hunts, and Microsoft Search / eDiscovery readers from SharePoint hunts, by verified app ID or user agent — never by user or IP.

5. **Cloud-hosted analysts look like the actor.** Admins on Azure-hosted workstations produce new-IP, unmanaged-device sessions that register methods and enumerate the directory. Maintain named locations or an allowlist of administrative egress, and have privileged users register security info only from managed devices.

6. **Contain completely.** For a confirmed compromise: temporarily disable the account, revoke sessions and refresh tokens, remove **all** unrecognized methods (including software OATH tokens), reset credentials, remove attacker mailbox rules, and require re-registration under a phishing-resistant, device-bound Conditional Access policy. Access tokens can outlive a refresh-token revocation by up to an hour.

7. **Prevention.** Enforce phishing-resistant MFA, require compliant devices for Exchange, SharePoint and Graph-privileged apps, block device code and authentication transfer flows, restrict user consent, limit unmanaged devices to web-only (no download/sync), and harden helpdesk identity verification for any MFA reset.

8. **CD-readiness summary.** **Query 4 is `cd_ready: true`** (row-level `CloudAppEvents` MFA device / software token addition, 1H). **Queries 1–3 and 5–11 are `cd_ready: false`**: they are multi-table IOC or pattern hunts, baseline correlations, session reconstruction, aggregations or alert correlation. Queries 1, 2 and 7 document single-table CD variants. All eleven queries were executed against live Advanced Hunting; Query 1 was also swept over ~90 days in the Sentinel Data Lake. **Queries 4, 8 and 10 had no matching telemetry shape in the validation tenant**, so they are syntax- and logic-validated only.

---

## References

- Microsoft Security Research — [Passkey-themed social engineering leads to identity and cloud compromise (2026-09-09)](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)
- Microsoft Learn — [Conditional Access: authentication flows (block device code flow)](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows)
- Microsoft Learn — [Conditional Access: securing security info registration](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-security-info-registration)
- Microsoft Learn — [Microsoft Graph activity logs](https://learn.microsoft.com/graph/microsoft-graph-activity-logs-overview)
- Microsoft Learn — [Responding to a compromised email account](https://learn.microsoft.com/defender-office-365/responding-to-a-compromised-email-account)
- Microsoft Learn — [Revoke user sign-in sessions](https://learn.microsoft.com/graph/api/user-revokesigninsessions)
- MITRE ATT&CK — [T1598.004 Phishing for Information: Spearphishing Voice](https://attack.mitre.org/techniques/T1598/004/)
- MITRE ATT&CK — [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- MITRE ATT&CK — [T1098.005 Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- MITRE ATT&CK — [T1556.006 Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)
- MITRE ATT&CK — [T1087.004 Account Discovery: Cloud Account](https://attack.mitre.org/techniques/T1087/004/)
- MITRE ATT&CK — [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- MITRE ATT&CK — [T1114 Email Collection](https://attack.mitre.org/techniques/T1114/)
- MITRE ATT&CK — [T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- Companion files: [`eviltokens_storm_2992_device_code_postcompromise.md`](eviltokens_storm_2992_device_code_postcompromise.md), [`queries/identity/device_code_phishing.md`](../../identity/device_code_phishing.md), [`queries/identity/aitm_threat_detection.md`](../../identity/aitm_threat_detection.md), [`queries/cloud/graph_api_security_monitoring.md`](../../cloud/graph_api_security_monitoring.md), [`queries/cloud/cloudappevents_exploration.md`](../../cloud/cloudappevents_exploration.md)
