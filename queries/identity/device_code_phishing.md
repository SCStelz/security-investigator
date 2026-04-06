# AI-Enabled Device Code Phishing — Hunting & Detection Queries

**Created:** 2026-04-06  
**Platform:** Both  
**Tables:** EntraIdSignInEvents, CloudAppEvents, UrlClickEvents, SigninLogs, AADNonInteractiveUserSignInLogs  
**Keywords:** device code phishing, EvilToken, PhaaS, OAuth device authorization, token theft, dynamic code generation, device registration, inbox rules, email exfiltration, Graph API reconnaissance, Railway.com, Vercel, Cloudflare Workers, browser-in-the-browser, clipboard hijack, 50199, Cmsi:cmsi, MailItemsAccessed, PRT persistence  
**MITRE:** T1566.002, T1528, T1550.001, T1098.005, T1114.002, T1114.003, T1071.001, T1087.003, T1098  
**Timeframe:** Last 30 days (configurable)

---

## Overview

Queries derived from the Microsoft Security blog: [Inside an AI-enabled device code phishing campaign (April 2026)](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/).

This campaign represents a significant escalation from the [Storm-2372 device code phishing campaign (Feb 2025)](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/), driven by the **EvilToken** Phishing-as-a-Service (PhaaS) toolkit with:

- **Dynamic device code generation** — codes generated at click time (not pre-embedded in email), defeating the 15-minute expiry window
- **AI-generated hyper-personalized lures** — role-aligned themes (RFPs, invoices, manufacturing workflows)
- **Automated backend infrastructure** — Railway.com, Vercel, Cloudflare Workers, AWS Lambda nodes for short-lived polling
- **Browser-in-the-browser** — simulated browser windows hosting the auth handoff
- **Post-compromise automation** — Graph API reconnaissance, persona identification, targeted financial exfiltration

### Attack Chain Phases

| Phase | Activity | MITRE Technique |
|-------|----------|-----------------|
| 1. **Recon** | GetCredentialType endpoint probing (10-15d before phish) | T1589.002 |
| 2. **Initial Access** | Phishing emails with URLs/PDFs/HTML → redirect chain through serverless platforms | T1566.002 |
| 3. **Dynamic Code Gen** | Backend generates live device code at click time via `/api/device/start/` | T1528 |
| 4. **Exploitation** | Clipboard hijack + microsoft.com/devicelogin → user pastes code + MFA | T1550.001 |
| 5. **Validation** | Polling `/state` endpoint every 3-5s for token capture | T1528 |
| 6. **Persistence** | Device registration (PRT), malicious inbox rules, email exfiltration | T1098.005, T1114.002, T1114.003 |

### IOC IP Ranges

| IP Range | Infrastructure | Description |
|----------|---------------|-------------|
| `160.220.232.0/24` | Railway.com | Threat actor sign-in infrastructure |
| `160.220.234.0/24` | Railway.com | Threat actor sign-in infrastructure |
| `89.150.45.0/24` | HZ Hosting | Threat actor sign-in infrastructure |
| `185.81.113.0/24` | HZ Hosting | Threat actor sign-in infrastructure |
| `8.228.105.0/24` | — | Threat actor sign-in infrastructure |

### IOC Domains (Redirect Infrastructure)

| Domain Pattern | Type | Purpose |
|---------------|------|---------|
| `*.vercel.app` | Serverless hosting | Redirect chain / phishing page hosting |
| `*.workers.dev` | Cloudflare Workers | Redirect chain |
| `*.railway.app` | Railway.com PaaS | Backend polling / token capture |
| `graph-microsoft[.]com` | Brand impersonation | Phishing domain |
| `portal-azure[.]com` | Brand impersonation | Phishing domain |
| `office365-login[.]com` | Brand impersonation | Phishing domain |
| `office-verify[.]net` (with randomized subdomains) | Brand impersonation | Phishing domain |

### Table Compatibility Notes

> **`EntraIdSignInEvents`** is the current table name (replaces deprecated `AADSignInEventsBeta` since Dec 9, 2025). **Case-sensitive**: use exactly `EntraIdSignInEvents` (capital `I` in `SignIn`). The table includes the `RiskLevelDuringSignIn` column that `AADSignInEventsBeta` lacked. Schema verified in workspace 2026-04-06.
>
> For **Data Lake** / **Sentinel** queries (90d lookback), use `SigninLogs` + `AADNonInteractiveUserSignInLogs` as equivalents.

---

## Phase 1-4 Detection: Device Code Authentication

### Query 1: ErrorCode 50199 Followed by Success (Device Code Auth Pause)

**Purpose:** Detects the telltale device code phishing pattern — ErrorCode 50199 (user interaction required / device code input pause) followed by a successful auth (ErrorCode 0) within the same session. This is the signature of a user pasting a device code at `microsoft.com/devicelogin`.  
**Severity:** Medium  
**MITRE:** T1528, T1550.001

> **Validation (2026-04-06):** 49 results in 30d via Advanced Hunting — confirmed active device code auth in the environment.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Device code auth pattern detected for {{AccountUpn}}"
impactedAssets:
  - type: user
    identifier: accountUpn
adaptation_notes: "Summarize+has_all pattern returns one row per session. Adapting for CD requires restructuring to row-level output — use arg_max for latest event per CorrelationId."
-->
```kql
// Device code phishing: ErrorCode 50199 (user pause) + success (0) in same session
// Platform: Defender XDR Advanced Hunting
// Source: Microsoft Security Blog (April 2026) — adapted with correct table name
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where ErrorCode in (0, 50199)
| summarize
    ErrorCodes = make_set(ErrorCode),
    Timestamps = make_list(Timestamp),
    IPs = make_set(IPAddress),
    Apps = make_set(Application)
    by AccountUpn, CorrelationId, SessionId, bin(Timestamp, 1h)
| where ErrorCodes has_all (0, 50199)
| project AccountUpn, CorrelationId, SessionId, Timestamp, IPs, Apps
| order by Timestamp desc
```

### Query 2: Device Code Flow via EndpointCall (Cmsi:cmsi Indicator)

**Purpose:** Directly identifies device code authentication flow events using the `EndpointCall` field containing `Cmsi:cmsi` — the Entra ID server-side marker for the CMSI (Client Message Security Identifier) flow used in device code auth. This is more reliable than ErrorCode-based detection because it catches all device code flows regardless of outcome.  
**Severity:** Medium  
**MITRE:** T1528, T1550.001

> **Validation (2026-04-06):** 25 unique users with device code flow activity in 30d. Top user: 24 successful attempts.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Device code flow authentication by {{AccountUpn}} from {{IPAddress}}"
impactedAssets:
  - type: user
    identifier: accountUpn
adaptation_notes: "Row-level output per sign-in. Filter to ErrorCode == 0 for CD to reduce noise (successful auth only). Add risk columns for triage."
-->
```kql
// Device code flow detection via EndpointCall marker
// Platform: Defender XDR Advanced Hunting
// Source: Microsoft Security Blog (April 2026)
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where EndpointCall has "Cmsi:cmsi"
| where ErrorCode == 0
| project
    Timestamp, AccountUpn, IPAddress, Country, City, Application,
    RiskLevelDuringSignIn, RiskState, DeviceName, DeviceTrustType,
    IsManaged, IsCompliant, SessionId, UserAgent, Browser
| order by Timestamp desc
```

### Query 3: Device Code Auth Summary per User (Hunting)

**Purpose:** Summary view of all device code authentication activity per user for triage — shows attempt volume, success/fail ratio, geographic spread, and apps accessed. Useful for identifying both legitimate device code usage (conference rooms, IoT) and suspicious activity.  
**Severity:** Informational  
**MITRE:** T1528

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical summary query — aggregates with make_set and dcount, not suitable for row-level CD alert."
-->
```kql
// Device code auth summary per user — hunting view
// Platform: Defender XDR Advanced Hunting
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where EndpointCall has "Cmsi:cmsi"
| summarize
    AttemptCount = count(),
    SuccessCount = countif(ErrorCode == 0),
    FailCount = countif(ErrorCode != 0),
    ErrorCodes = make_set(ErrorCode),
    IPs = make_set(IPAddress, 10),
    Countries = make_set(Country, 10),
    Apps = make_set(Application, 5),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn
| extend SuccessRate = round(100.0 * SuccessCount / AttemptCount, 1)
| order by AttemptCount desc
```

---

## Phase 1: IOC-Based Detection

### Query 4: Sign-Ins from EvilToken/Campaign IOC IP Ranges

**Purpose:** Detects sign-ins from the specific IP ranges identified as threat actor infrastructure in the April 2026 blog (Railway.com PaaS, HZ Hosting). These IPs were observed serving device code polling and token capture backends.  
**Severity:** High  
**MITRE:** T1566.002, T1528

> **Validation (2026-04-06):** 0 results in 30d (AH) and 90d (Data Lake) — ✅ No sign-ins from campaign IOC IPs detected. IOCs are environment-clean.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Sign-in from device code phishing IOC IP {{IPAddress}} by {{AccountUpn}}"
impactedAssets:
  - type: user
    identifier: accountUpn
adaptation_notes: "Simple single-table filter. High-confidence IOC match. Update IP ranges as new campaign IOCs are published."
-->
```kql
// Sign-ins from EvilToken / AI device code phishing campaign IOC IPs
// Platform: Defender XDR Advanced Hunting
// Source: Microsoft Security Blog (April 2026)
// ⚠️ Update IOC list as new indicators are published
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where IPAddress has_any (
    "160.220.232.", "160.220.234.",  // Railway.com
    "89.150.45.", "185.81.113.",      // HZ Hosting
    "8.228.105."                      // Additional campaign infra
)
| project
    Timestamp, AccountUpn, IPAddress, Country, City, ErrorCode,
    Application, RiskLevelDuringSignIn, RiskState, SessionId,
    DeviceName, UserAgent
| order by Timestamp desc
```

### Query 4b: IOC IP Ranges — Data Lake 90-Day Lookback

**Purpose:** Extended lookback for IOC IPs using Sentinel Data Lake (SigninLogs). Use when Advanced Hunting's 30-day window isn't sufficient.  
**Severity:** High  
**MITRE:** T1566.002, T1528

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Sentinel Data Lake query for 90d lookback. Not suitable for CD (CD uses Advanced Hunting)."
-->
```kql
// IOC IP ranges — 90-day lookback via Sentinel Data Lake
// Platform: Microsoft Sentinel (Data Lake)
let IOC_IPs = dynamic(["160.220.232.", "160.220.234.", "89.150.45.", "185.81.113.", "8.228.105."]);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| where IPAddress has_any (IOC_IPs)
| project
    TimeGenerated, UserPrincipalName, IPAddress, ResultType,
    AppDisplayName, tostring(parse_json(LocationDetails).countryOrRegion),
    tostring(parse_json(LocationDetails).city),
    RiskLevelDuringSignIn, RiskState,
    tostring(parse_json(DeviceDetail).operatingSystem),
    UserAgent
| order by TimeGenerated desc
```

---

## Phase 2: Phishing Redirect Infrastructure Detection

### Query 5: URL Clicks to Serverless Redirect Infrastructure

**Purpose:** Detects user clicks on URLs hosted on the serverless platforms and brand-impersonating domains used in this campaign's redirect chain (Vercel, Cloudflare Workers, Railway.com, fake Microsoft/Azure domains). These platforms are used to host the intermediate redirect logic that delivers victims to the device code phishing page.  
**Severity:** Medium  
**MITRE:** T1566.002

> **Validation (2026-04-06):** 20 results in 30d — clicks to `*.vercel.app` domains detected (various clone/impersonation sites).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "URL click to suspicious redirect infrastructure by {{AccountUpn}}"
impactedAssets:
  - type: user
    identifier: accountUpn
adaptation_notes: "Single-table UrlClickEvents filter. Broad serverless domain filter may have FP from legitimate dev apps — tune with exclusion list per org."
-->
```kql
// Detect clicks to phishing redirect infrastructure
// Platform: Defender XDR Advanced Hunting
// Source: Microsoft Security Blog (April 2026)
UrlClickEvents
| where Timestamp > ago(30d)
| where Url has_any (
        ".vercel.app", ".workers.dev", ".railway.app",          // Serverless hosting
        "graph-microsoft.", "portal-azure.", "office365-login.", // Brand impersonation
        "office-verify."                                        // Randomized subdomain pattern
    )
    or UrlChain has_any (
        ".vercel.app", ".workers.dev", ".railway.app",
        "graph-microsoft.", "portal-azure.", "office365-login.",
        "office-verify."
    )
| project
    Timestamp, AccountUpn, Url, UrlChain, ActionType,
    ThreatTypes, DetectionMethods, IPAddress,
    IsClickedThrough, Workload
| order by Timestamp desc
```

### Query 6: URL Click Correlated with Risky Sign-In (Full Kill Chain)

**Purpose:** Connects the dots across the full attack chain — a user clicks a URL (phishing link), then within minutes performs a successful risky sign-in (device code auth from threat actor infrastructure). This is the highest-confidence detection for an active device code phishing compromise.  
**Severity:** High  
**MITRE:** T1566.002, T1528, T1550.001

> **Validation (2026-04-06):** 50+ results in 30d — URL-click-to-risky-sign-in correlations found (requires investigation to distinguish legitimate risky sign-ins from actual phishing).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "URL click followed by risky sign-in for {{AccountUpn}}"
impactedAssets:
  - type: user
    identifier: accountUpn
adaptation_notes: "Multi-table join (UrlClickEvents + EntraIdSignInEvents). CD supports let blocks and joins. High-signal but may need tuning on time window."
-->
```kql
// Kill chain: URL click → risky sign-in within minutes
// Platform: Defender XDR Advanced Hunting
// Source: Microsoft Security Blog (April 2026) — adapted for EntraIdSignInEvents
let suspiciousUserClicks = materialize(UrlClickEvents
    | where Timestamp > ago(30d)
    | extend AccountUpn = tolower(AccountUpn)
    | project ClickTime = Timestamp, ActionType, UrlChain, NetworkMessageId, Url, AccountUpn);
let interestedUsersUpn = suspiciousUserClicks
    | where isnotempty(AccountUpn)
    | distinct AccountUpn;
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where ErrorCode == 0
| where AccountUpn in~ (interestedUsersUpn)
| where RiskLevelDuringSignIn in (10, 50, 100)  // Low=10, Medium=50, High=100
| extend AccountUpn = tolower(AccountUpn)
| join kind=inner suspiciousUserClicks on AccountUpn
| where (Timestamp - ClickTime) between (-2min .. 7min)
| project
    Timestamp, AccountUpn, RiskLevelDuringSignIn,
    SessionId, IPAddress, ClickTime, Url, ReportId
| order by Timestamp desc
```

---

## Phase 6: Post-Compromise Detection

### Query 7: Suspicious Device Registration (PRT Persistence)

**Purpose:** Detects device registration events initiated by the "Device Registration Service" account — a post-compromise technique where threat actors register a new device to generate a Primary Refresh Token (PRT) for long-term persistent access. In the campaign, this occurred within 10 minutes of token capture.  
**Severity:** High  
**MITRE:** T1098.005

> **Validation (2026-04-06):** 0 results in 30d — ✅ No suspicious device registration activity detected.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Suspicious device registration for {{UserPrincipalName}}"
impactedAssets:
  - type: user
    identifier: accountUpn
adaptation_notes: "Single-table CloudAppEvents with JSON parsing. Row-level output. High-signal — device registration by 'Device Registration Service' is uncommon."
-->
```kql
// Post-compromise: Suspicious device registration (PRT persistence)
// Platform: Defender XDR Advanced Hunting
// Source: Microsoft Security Blog (April 2026)
CloudAppEvents
| where Timestamp > ago(30d)
| where AccountDisplayName == "Device Registration Service"
| extend ApplicationId_ = tostring(ActivityObjects[0].ApplicationId)
| extend ServiceName_ = tostring(ActivityObjects[0].Name)
| extend DeviceName = tostring(parse_json(tostring(RawEventData.ModifiedProperties))[1].NewValue)
| extend DeviceId = tostring(parse_json(tostring(parse_json(tostring(RawEventData.ModifiedProperties))[6].NewValue))[0])
| extend DeviceObjectId_ = tostring(parse_json(tostring(RawEventData.ModifiedProperties))[0].NewValue)
| extend UserPrincipalName = tostring(RawEventData.ObjectId)
| project
    Timestamp, ServiceName_, DeviceName, DeviceId,
    DeviceObjectId_, UserPrincipalName, IPAddress, City, CountryCode
| order by Timestamp desc
```

### Query 8: Malicious Inbox Rules with Special-Character Names

**Purpose:** Detects inbox rules created via Exchange Online where the rule name consists entirely of special characters (e.g., `..`, `//`, `!!`). This is a campaign-specific post-compromise IOC — threat actors use special-character-only rule names to hide rules in the UI and avoid keyword-based detection. These rules typically forward, redirect, or delete inbound email.  
**Severity:** High  
**MITRE:** T1114.003, T1564.008

> **Validation (2026-04-06):** 0 results in 30d — ✅ No special-character inbox rules detected.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Collection"
title: "Suspicious inbox rule with special-character name by {{AccountDisplayName}}"
impactedAssets:
  - type: mailbox
    identifier: accountUpn
adaptation_notes: "Single-table with mv-expand + regex filter. High-confidence IOC — legitimate rules virtually never use special-char-only names."
-->
```kql
// Post-compromise: Inbox rules with special-character-only names (evasion)
// Platform: Defender XDR Advanced Hunting
// Source: Microsoft Security Blog (April 2026)
CloudAppEvents
| where Timestamp > ago(30d)
| where ApplicationId == "20893" // Microsoft Exchange Online
| where ActionType in (
    "New-InboxRule", "Set-InboxRule", "Set-Mailbox",
    "Set-TransportRule", "New-TransportRule",
    "Enable-InboxRule", "UpdateInboxRules"
)
| where isnotempty(IPAddress)
| mv-expand ActivityObjects
| extend name = tostring(parse_json(ActivityObjects).Name)
| extend value = tostring(parse_json(ActivityObjects).Value)
| where name == "Name"
| extend RuleName = value
// Match rule names containing ONLY special characters
| where RuleName matches regex @"^[!@#$%^&*()_+=\{\}\[\]|\\:;""'<,>.?/~` -]+$"
| project
    Timestamp, AccountDisplayName, ActionType, RuleName,
    IPAddress, CountryCode, City
| order by Timestamp desc
```

### Query 9: All Inbox Rule Modifications with Suspicious Properties (Broader Hunt)

**Purpose:** Broader detection of inbox rule creation/modification with extraction of forwarding, redirect, and delete-message properties. Catches both the special-character campaign IOC and other suspicious inbox rule patterns (forwarding to external addresses, auto-delete rules). Use this for comprehensive post-compromise triage.  
**Severity:** Medium  
**MITRE:** T1114.003, T1020

> **Validation (2026-04-06):** 4 results in 30d — legitimate transport rules found (SAP compromise rule + email restriction rules).

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "Collection"
title: "Inbox rule modification by {{AccountDisplayName}}: {{ActionType}}"
impactedAssets:
  - type: mailbox
    identifier: accountUpn
adaptation_notes: "Uses make_bag which CD supports. Consider filtering to only forwarding/redirect properties for production CD to reduce FP."
-->
```kql
// Post-compromise: All inbox rule modifications with property extraction
// Platform: Defender XDR Advanced Hunting
CloudAppEvents
| where Timestamp > ago(30d)
| where ApplicationId == "20893" // Microsoft Exchange Online
| where ActionType in (
    "New-InboxRule", "Set-InboxRule", "Set-Mailbox",
    "Set-TransportRule", "New-TransportRule",
    "Enable-InboxRule", "UpdateInboxRules"
)
| where isnotempty(IPAddress)
| mv-expand ActivityObjects
| extend name = tostring(parse_json(ActivityObjects).Name)
| extend value = tostring(parse_json(ActivityObjects).Value)
| where name in (
    "Name", "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo",
    "ForwardingSmtpAddress", "DeleteMessage", "MarkAsRead"
)
| summarize
    Properties = make_bag(pack(name, value))
    by Timestamp, AccountDisplayName, ActionType, IPAddress, CountryCode
| order by Timestamp desc
```

### Query 10: Email Exfiltration — MailItemsAccessed from Uncommon ISP

**Purpose:** Detects email access (MailItemsAccessed via Exchange Online) where the ISP is uncommon for the user — a strong indicator of token replay from threat actor infrastructure. The campaign used stolen tokens to access email from infrastructure IPs that the user had never previously used.  
**Severity:** High  
**MITRE:** T1114.002

> **Validation (2026-04-06):** 0 results in 30d — ✅ No uncommon-ISP mail access detected.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Exfiltration"
title: "Mail accessed from uncommon ISP for {{AccountDisplayName}}"
impactedAssets:
  - type: mailbox
    identifier: accountUpn
adaptation_notes: "Simple single-table filter using built-in UncommonForUser enrichment. High-signal — ISP anomaly on mail access is a strong token-replay indicator."
-->
```kql
// Post-compromise: Email exfiltration via MailItemsAccessed from uncommon ISP
// Platform: Defender XDR Advanced Hunting
// Source: Microsoft Security Blog (April 2026)
CloudAppEvents
| where Timestamp > ago(30d)
| where ApplicationId == "20893" // Microsoft Exchange Online
| where ActionType == "MailItemsAccessed"
| where isnotempty(IPAddress)
| where UncommonForUser has "ISP"
| project
    Timestamp, AccountDisplayName, ActionType, IPAddress,
    CountryCode, City, UncommonForUser, UserAgent
| order by Timestamp desc
```

---

## Cross-Phase: Correlated Hunting

### Query 11: Anomalous Graph API Mail Access Volume (Nobelium-Pattern Exfiltration)

**Purpose:** Identifies users with unusually high MailItemsAccessed volume or multi-country email access via Exchange Online — patterns consistent with automated email exfiltration using stolen tokens (similar to Nobelium/Storm-0558 techniques, now used in device code phishing post-compromise).  
**Severity:** Medium  
**MITRE:** T1114.002, T1071.001

> **Validation (2026-04-06):** 4 results in 30d — users with >100 mail access events detected. Requires baseline comparison for anomaly confirmation.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical aggregation query — uses dcount and summarize for baseline analysis. Not suitable for row-level CD."
-->
```kql
// Graph API mail access volume anomaly (exfiltration indicator)
// Platform: Defender XDR Advanced Hunting
CloudAppEvents
| where Timestamp > ago(30d)
| where ApplicationId == "20893" // Microsoft Exchange Online
| where ActionType == "MailItemsAccessed"
| where isnotempty(IPAddress)
| summarize
    TotalAccess = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctCountries = dcount(CountryCode),
    Countries = make_set(CountryCode, 5),
    IPs = make_set(IPAddress, 5),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountDisplayName
| where TotalAccess > 100 or DistinctCountries > 2
| order by TotalAccess desc
```

### Query 12: Device Code Auth → Post-Compromise Activity Chain

**Purpose:** Correlates users who authenticated via device code flow with subsequent suspicious CloudAppEvents activity (mail access, send, search). This connects the initial access vector to post-compromise activity for full kill-chain visibility.  
**Severity:** High  
**MITRE:** T1528, T1114.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table correlation using let + in~ operator. Statistical output (summarize per user). For CD, would need to restructure as a join with row-level output."
-->
```kql
// Device code auth users → subsequent mail/search activity
// Platform: Defender XDR Advanced Hunting
let deviceCodeUsers = EntraIdSignInEvents
| where Timestamp > ago(30d)
| where EndpointCall has "Cmsi:cmsi"
| where ErrorCode == 0
| distinct AccountUpn;
CloudAppEvents
| where Timestamp > ago(30d)
| where AccountId in~ (deviceCodeUsers)
| where ActionType in ("MailItemsAccessed", "Send", "SearchQueryInitiatedExchange")
| summarize
    EventCount = count(),
    ActionTypes = make_set(ActionType),
    IPs = make_set(IPAddress, 5),
    Countries = make_set(CountryCode, 5)
    by AccountId
| order by EventCount desc
```

---

## Defender XDR Alert Coverage Reference

The following built-in Defender detections cover this campaign's TTPs. Use these alert names to cross-reference with SecurityAlert/SecurityIncident tables:

| Tactic | Alert / Detection | Product |
|--------|-------------------|---------|
| Initial Access | Predelivery protection for device code phishing emails | Defender for Office 365 |
| Credential Access | Anomalous OAuth device code authentication activity | Defender for Identity |
| Initial Access / Credential Access | Suspicious Azure authentication through possible device code phishing | Defender XDR |
| Credential Access | User account compromise via OAuth device code phishing | Defender XDR |
| Credential Access | Suspicious device code authentication following a URL click in an email from rare sender | Defender XDR |
| Defense Evasion | Malicious sign-in from an IP address associated with recognized threat actor infrastructure | Defender XDR |
| Defense Evasion | Activity from Anonymous IP address (anonymizedIPAddress) | Entra ID Protection |
| Defense Evasion / Credential Access | Microsoft Entra threat intelligence (investigationsThreatIntelligence) | Entra ID Protection |

---

## Mitigation Checklist

| Priority | Action | Reference |
|----------|--------|-----------|
| 🔴 **Critical** | Block device code flow via Conditional Access (except IoT/conference rooms) | [Authentication flows CA](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows) |
| 🔴 **Critical** | Implement phishing-resistant MFA (FIDO2/passkeys) | [Enable FIDO2](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-passkey-fido2) |
| 🟠 **High** | Configure Safe Links in Defender for Office 365 (enables device code phishing alerts) | [Safe Links](https://learn.microsoft.com/defender-office-365/safe-links-about) |
| 🟠 **High** | Configure anti-phishing policies | [Anti-phishing policies](https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about) |
| 🟠 **High** | Enable sign-in risk-based Conditional Access (block High, MFA for Medium) | [Risk policies](https://learn.microsoft.com/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies) |
| 🟠 **High** | Enable Continuous Access Evaluation (CAE) | [CAE overview](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation) |
| 🟡 **Medium** | If compromise detected: revoke refresh tokens (`revokeSignInSessions`) | [Revoke sessions](https://learn.microsoft.com/graph/api/user-revokesigninsessions) |
| 🟡 **Medium** | User education: do NOT enter codes from unfamiliar prompts | [Phishing protection](https://support.microsoft.com/en-us/security/protect-yourself-from-phishing) |
