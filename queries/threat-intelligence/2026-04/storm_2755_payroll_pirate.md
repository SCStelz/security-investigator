# Storm-2755 "Payroll Pirate" — AiTM Campaign Targeting Canadian Employees

**Created:** 2026-04-11  
**Platform:** Both  
**Tables:** EntraIdSignInEvents, SigninLogs, AADNonInteractiveUserSignInLogs, OfficeActivity, CloudAppEvents, EmailEvents, AADUserRiskEvents  
**Keywords:** Storm-2755, payroll pirate, AiTM, adversary-in-the-middle, axios, token replay, inbox rule, direct deposit, payroll, HR, Workday, SEO poisoning, malvertising, bluegraintours, session hijacking, credential theft, BEC, 50199  
**MITRE:** T1557, T1539, T1550.001, T1564.008, T1114.003, T1087, T1657, T1566.002, TA0001, TA0003, TA0005, TA0006, TA0040  
**Domains:** identity, email, cloud  
**Timeframe:** Last 30 days (configurable)

---

## Threat Overview

[Microsoft DART reported](https://www.microsoft.com/en-us/security/blog/2026/04/09/investigating-storm-2755-payroll-pirate-attacks-targeting-canadian-employees/) Storm-2755 as a financially motivated threat actor conducting AiTM phishing campaigns targeting Canadian employees. The actor uses SEO poisoning and malvertising on generic search terms ("Office 365", "Office 265") to lure victims to a credential-harvesting page at `bluegraintours[.]com`.

**Attack Chain:**
1. **Initial Access:** SEO poisoning → phishing page → credential and token theft (error code 50199 before success)
2. **Persistence:** Token replay via Axios HTTP client (`axios/1.7.9`) every ~30 minutes targeting OfficeHome app
3. **Discovery:** Intranet searches for payroll/HR keywords; emails with subject "Question about direct deposit"
4. **Defense Evasion:** Inbox rules hiding emails containing "direct deposit" or "bank"; operating at ~5 AM local time
5. **Impact:** Manual Workday login to change direct deposit banking information → payroll diverted

**IOCs:**
| Indicator | Type | Description |
|-----------|------|-------------|
| `bluegraintours[.]com` | Domain | AiTM phishing infrastructure |
| `axios/1.7.9` | User-Agent | HTTP client used for token replay |
| `50199` | Error Code | Sign-in interrupt preceding AiTM token capture |

**Reference:** See [aitm_threat_detection.md](../../identity/aitm_threat_detection.md) for comprehensive AiTM defensive program, posture hardening, and general-purpose AiTM detection queries (OfficeHome multi-country sessions, anomalous token correlation, MFA re-registration).

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Axios User-Agent in Sign-In Logs (Advanced Hunting)](#query-1-axios-user-agent-in-sign-in-logs-advanced-hunting) | Investigation | `EntraIdSignInEvents` |
| 1 | [b: Sentinel Data Lake Variant (>30d lookback)](#query-1b-sentinel-data-lake-variant-30d-lookback) | Investigation | `AADNonInteractiveUserSignInLogs` + `SigninLogs` |
| 2 | [50199 Error Preceding Successful Authentication (Advanced Hunting)](#query-2-50199-error-preceding-successful-authentication-advanced-hunting) | Investigation | `EntraIdSignInEvents` |
| 2 | [b: Time-Relaxed Variant (no RequestId join)](#query-2b-time-relaxed-variant-no-requestid-join) | Investigation | `EntraIdSignInEvents` |
| 3 | [Non-Interactive OfficeHome Token Replay at ~30min Cadence (Advanced...](#query-3-non-interactive-officehome-token-replay-at-30min-cadence-advanced-hunting) | Investigation | `EntraIdSignInEvents` |
| 4 | [Payroll-Keyword Inbox Rules — Defense Evasion (Sentinel Data Lake)](#query-4-payroll-keyword-inbox-rules--defense-evasion-sentinel-data-lake) | Detection | `OfficeActivity` |
| 5 | [Payroll-Keyword Inbox Rules — CloudAppEvents (Advanced Hunting)](#query-5-payroll-keyword-inbox-rules--cloudappevents-advanced-hunting) | Detection | `CloudAppEvents` |
| 6 | [Workday Payment Election Changes (Advanced Hunting)](#query-6-workday-payment-election-changes-advanced-hunting) | Investigation | `CloudAppEvents` |
| 7 | [Workday Inbox Rules — Evidence Hiding (Advanced Hunting)](#query-7-workday-inbox-rules--evidence-hiding-advanced-hunting) | Detection | `CloudAppEvents` |
| 8 | [Social Engineering Email — Direct Deposit Subject (Advanced Hunting)](#query-8-social-engineering-email--direct-deposit-subject-advanced-hunting) | Investigation | `EmailEvents` |
| 9 | [IOC Domain — bluegraintours[.]com Network Activity (Sentinel Data L...](#query-9-ioc-domain--bluegraintourscom-network-activity-sentinel-data-lake-via-asim) | Investigation | — |
| 10 | [IOC Domain — bluegraintours[.]com Web Sessions (Sentinel Data Lake ...](#query-10-ioc-domain--bluegraintourscom-web-sessions-sentinel-data-lake-via-asim) | Investigation | — |
| 11 | [Off-Hours Token Renewal (~5 AM Local Time) (Advanced Hunting)](#query-11-off-hours-token-renewal-5-am-local-time-advanced-hunting) | Investigation | `EntraIdSignInEvents` |
| 12 | [Full Chain Correlation — AiTM → Inbox Rule → Payroll Change (Advanc...](#query-12-full-chain-correlation--aitm--inbox-rule--payroll-change-advanced-hunting) | Detection | `CloudAppEvents` + `EntraIdSignInEvents` |


## Query 1: Axios User-Agent in Sign-In Logs (Advanced Hunting)

Detect sign-ins using the Axios HTTP client user-agent — the primary tool fingerprint for Storm-2755 token replay. `EntraIdSignInEvents` covers both interactive and non-interactive sign-ins in a single AH-native table.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Storm-2755 Axios User-Agent Sign-In — {{AccountUpn}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
recommendedActions: "Revoke user refresh tokens immediately. Investigate inbox rules for payroll keyword hiding. Check Workday/payroll SaaS for direct deposit changes."
responseActions: "Revoke sessions via Entra ID. Reset credentials. Remove malicious inbox rules. Notify HR/payroll team to verify banking details."
adaptation_notes: "Uses EntraIdSignInEvents (AH-native, covers interactive + non-interactive). ErrorCode is int. Country/City are direct string columns. LogonType is a JSON array string — use has for filtering. For >30d lookback, use Query 1b (Sentinel Data Lake variant)."
-->
```kql
// Storm-2755: Detect Axios user-agent in interactive + non-interactive sign-ins
// The Axios HTTP client (especially v1.7.9) is Storm-2755's primary token replay tool
// EntraIdSignInEvents covers both interactive and non-interactive in one table
let lookback = 30d;
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where UserAgent has "axios"
| project Timestamp, AccountUpn, Application, IPAddress,
    UserAgent, Country, City, ErrorCode, LogonType,
    SessionId, RequestId, RiskLevelDuringSignIn, RiskState
| order by Timestamp desc
```

**Tested:** Returns results — legitimate Axios usage found from VS Code (`axios/0.21.4`) and Verifiable Credentials Service (`axios/1.13.2`). Volume is low (3 hits/30d in test tenant). Storm-2755 uses `axios/1.7.9` specifically.

**Tuning:**
- High-confidence: Filter to `UserAgent has "axios/1.7.9"` for exact Storm-2755 variant
- Broader hunt: Keep `has "axios"` to catch version evolution
- Exclude known legitimate apps: `| where Application !in~ ("Visual Studio Code", "Verifiable Credentials Service Admin")`
- Exclude known automation accounts: `| where AccountUpn !in~ ("svc-automation@contoso.com")`

### Query 1b: Sentinel Data Lake Variant (>30d lookback)

For investigations requiring >30 days of history (beyond AH Graph API retention).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Sentinel Data Lake fallback for >30d lookback. Uses union of SigninLogs + AADNonInteractiveUserSignInLogs with parse_json for geo fields."
-->
```kql
// Storm-2755: Axios user-agent — Sentinel Data Lake variant (>30d lookback)
let lookback = 90d;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where UserAgent has "axios"
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend City = tostring(parse_json(LocationDetails).city)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
    UserAgent, Country, City, ResultType, IsInteractive,
    SessionId, OriginalRequestId, ConditionalAccessStatus,
    RiskLevelDuringSignIn, RiskState
| order by TimeGenerated desc
```

---

## Query 2: 50199 Error Preceding Successful Authentication (Advanced Hunting)

Error code 50199 (sign-in interrupt) immediately before a successful authentication is a hallmark of AiTM proxy interception. The phishing page interrupts the legitimate flow to capture the session token.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "InitialAccess"
title: "AiTM Sign-In Interrupt: {{AccountUpn}} — 50199 error then success from different IP"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
recommendedActions: "Check whether the successful sign-in IP differs from the 50199 IP. Correlate with UserAgent changes (Axios). Investigate for inbox rules and payroll changes."
adaptation_notes: "Uses EntraIdSignInEvents (AH-native). ErrorCode is int (not string). RequestId replaces OriginalRequestId. 15-minute window accounts for MFA completion delay through the proxy. For >30d lookback, use Query 2b."
-->
```kql
// Storm-2755: Detect 50199 sign-in interrupt followed by successful auth
// This pattern indicates AiTM proxy intercepting the authentication flow
let lookback = 30d;
let InterruptedSignIns = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 50199
| project InterruptTime = Timestamp, AccountUpn,
    InterruptIP = IPAddress, RequestId,
    InterruptUserAgent = UserAgent;
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| project SuccessTime = Timestamp, AccountUpn,
    SuccessIP = IPAddress, RequestId,
    SuccessUserAgent = UserAgent, Application, SessionId
| join kind=inner InterruptedSignIns on AccountUpn, RequestId
| where SuccessTime between (InterruptTime .. (InterruptTime + 15m))
| extend IPChanged = (InterruptIP != SuccessIP)
| extend UserAgentChanged = (InterruptUserAgent != SuccessUserAgent)
| extend AxiosReplay = (SuccessUserAgent has "axios")
| project SuccessTime, AccountUpn, Application,
    InterruptIP, SuccessIP, IPChanged,
    InterruptUserAgent, SuccessUserAgent, UserAgentChanged,
    AxiosReplay, SessionId, RequestId
| order by SuccessTime desc
```

**Tested:** Strict `RequestId` join returns 0 results (expected — the 50199 and success often have different RequestIds in AiTM flows). The time-relaxed variant (Query 2b) returns results but requires additional filtering to avoid false positives from legitimate 50199 interrupts (Azure CLI, Authentication Broker).

**Tuning:**
- High-confidence: Add `| where AxiosReplay == true` to isolate Storm-2755 specifically
- Medium-confidence: `| where IPChanged == true or UserAgentChanged == true`
- Reduce noise: `| where IPChanged == true and UserAgentChanged == true` (both indicators)
- If 0 results with RequestId join: Use Query 2b which joins on AccountUpn + time window only

### Query 2b: Time-Relaxed Variant (no RequestId join)

Falls back to time-based correlation when AiTM proxy generates different RequestIds for the interrupt and the replayed success.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Time-based join (no RequestId) — higher recall but needs filtering. Legitimate 50199 events (Azure CLI, Auth Broker) produce false positives with same-IP/same-UA. Add IPChanged or UserAgentChanged filter."
-->
```kql
// Storm-2755: 50199 → success (time-relaxed, no RequestId join)
let lookback = 30d;
let InterruptedSignIns = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 50199
| project InterruptTime = Timestamp, AccountUpn,
    InterruptIP = IPAddress, InterruptUserAgent = UserAgent;
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| project SuccessTime = Timestamp, AccountUpn,
    SuccessIP = IPAddress, SuccessUserAgent = UserAgent,
    Application, SessionId
| join kind=inner InterruptedSignIns on AccountUpn
| where SuccessTime between (InterruptTime .. (InterruptTime + 15m))
| extend IPChanged = (InterruptIP != SuccessIP)
| extend UserAgentChanged = (InterruptUserAgent != SuccessUserAgent)
| extend AxiosReplay = (SuccessUserAgent has "axios")
| where IPChanged == true or UserAgentChanged == true
| project SuccessTime, AccountUpn, Application,
    InterruptIP, SuccessIP, IPChanged,
    InterruptUserAgent, SuccessUserAgent, UserAgentChanged, AxiosReplay
| take 50
```

---

## Query 3: Non-Interactive OfficeHome Token Replay at ~30min Cadence (Advanced Hunting)

Storm-2755 maintains persistence by replaying stolen tokens to the OfficeHome app approximately every 30 minutes via non-interactive sign-ins. This cadence keeps the session alive without triggering reauthentication.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarize per user with session count and cadence stats. Not row-level output. Uses EntraIdSignInEvents (covers both interactive + non-interactive, filter via LogonType). For >30d lookback, substitute SigninLogs/AADNonInteractiveUserSignInLogs with TimeGenerated."
-->
```kql
// Storm-2755: Non-interactive OfficeHome token replay persistence (~30 min intervals)
// EntraIdSignInEvents covers both interactive and non-interactive sign-ins
let lookback = 30d;
let OfficeHomeAppId = "4765445b-32c6-49b0-83e6-1d93765276ca";
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ApplicationId == OfficeHomeAppId
| where ErrorCode == 0
| where LogonType has "nonInteractiveUser"
| summarize
    SignInCount = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctCountries = dcount(Country),
    Countries = make_set(Country, 5),
    IPs = make_set(IPAddress, 10),
    UserAgents = make_set(UserAgent, 5),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn
| extend SessionDurationHours = datetime_diff('hour', LastSeen, FirstSeen)
| extend AvgIntervalMinutes = iff(SignInCount > 1,
    toreal(datetime_diff('minute', LastSeen, FirstSeen)) / toreal(SignInCount - 1),
    toreal(0))
| where SignInCount > 20
    and AvgIntervalMinutes between (20.0 .. 45.0)
| project AccountUpn, SignInCount, AvgIntervalMinutes,
    SessionDurationHours, DistinctIPs, DistinctCountries,
    Countries, IPs, UserAgents, FirstSeen, LastSeen
| order by SignInCount desc
```

**Tested:** Returns results — 5 users with OfficeHome non-interactive cadence in the 20–45 min range (15–23 hour sessions, 22–53 sign-ins). Normal baseline patterns exist; correlate with Axios user-agent for high-confidence.

**Tuning:**
- Tighter cadence: Change range to `between (25.0 .. 35.0)` for exact Storm-2755 pattern
- Add Axios filter: Append `| where UserAgents has "axios"` for high-confidence
- Adjust threshold: Lower `SignInCount > 20` if looking at shorter windows

---

## Query 4: Payroll-Keyword Inbox Rules — Defense Evasion (Sentinel Data Lake)

Storm-2755 creates inbox rules to move/delete emails containing "direct deposit" or "bank" to hide HR correspondence from the victim. This is the primary defense evasion technique.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Payroll Keyword Inbox Rule: {{Operation}} by {{UserId}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
  - type: "mailbox"
    identifier: "accountUpn"
recommendedActions: "Immediately review and remove the inbox rule. Check if direct deposit or banking changes were made in payroll SaaS. Notify HR to verify recent pay instruction changes."
responseActions: "Remove inbox rule. Revoke user sessions. Reset credentials. Audit Workday/payroll system for banking changes."
adaptation_notes: "OfficeActivity is Sentinel-only. Parameters is a string field — use has for keyword matching. For AH, adapt to CloudAppEvents with matching ActionType."
-->
```kql
// Storm-2755: Inbox rules targeting payroll/banking keywords
// Rules that hide emails about direct deposits or banking from the victim
let lookback = 30d;
let PayrollKeywords = dynamic(["direct deposit", "bank", "payroll", "void cheque",
    "void check", "routing number", "account number", "payment election"]);
OfficeActivity
| where TimeGenerated > ago(lookback)
| where OfficeWorkload =~ "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where Parameters has_any (PayrollKeywords)
| where Parameters has_any ("DeleteMessage", "MoveToFolder", "MarkAsRead",
    "StopProcessingRules", "Conversation History")
| extend ClientIPAddress = case(
    ClientIP has ".", tostring(split(ClientIP, ":")[0]),
    ClientIP has "[", tostring(trim_start(@'\[', tostring(split(ClientIP, "]")[0]))),
    ClientIP)
| extend Events = todynamic(Parameters)
| project TimeGenerated, UserId, Operation, Parameters, 
    ClientIPAddress, ClientInfoString, OfficeObjectId
| order by TimeGenerated desc
```

**Expected Results:** Very low volume. Legitimate inbox rules mentioning "bank" or "direct deposit" are rare. Any match warrants immediate investigation.

**Tuning:**
- Reduce false positives: Add `| where Parameters has "StopProcessingRules"` (Storm-2755 hallmark — prevents further rule processing)
- Broader hunt: Remove the action filter (`DeleteMessage`, `MoveToFolder`) to catch rule creation with payroll keywords regardless of action

---

## Query 5: Payroll-Keyword Inbox Rules — CloudAppEvents (Advanced Hunting)

Same detection as Query 4, adapted for CloudAppEvents in Advanced Hunting. Useful for environments without OfficeActivity in Sentinel.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Payroll Keyword Inbox Rule (CloudApp): {{AccountDisplayName}}"
impactedAssets:
  - type: "user"
    identifier: "accountObjectId"
recommendedActions: "Immediately review and remove the inbox rule. Check if direct deposit or banking changes were made in payroll SaaS."
responseActions: "Remove inbox rule. Revoke user sessions. Reset credentials. Audit Workday/payroll for banking changes."
adaptation_notes: "CloudAppEvents is AH-native. Uses Timestamp. RawEventData.Parameters is dynamic — mv-apply for parameter extraction."
-->
```kql
// Storm-2755: Inbox rules targeting payroll/banking keywords (Advanced Hunting)
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend Params = RawEventData.Parameters
| where Params has_any ("direct deposit", "bank", "payroll", "void cheque",
    "void check", "routing number")
| where Params has_any ("DeleteMessage", "MoveToFolder", "StopProcessingRules")
| mv-apply Params on (
    where Params.Name in ("SubjectContainsWords", "BodyContainsWords",
        "SubjectOrBodyContainsWords", "From", "Name")
    | extend ParamName = tostring(Params.Name),
        ParamValue = tostring(Params.Value))
| summarize RuleParams = make_bag(bag_pack(ParamName, ParamValue))
    by Timestamp, AccountDisplayName, AccountObjectId,
    ActionType, IPAddress, UserAgent
| order by Timestamp desc
```

---

## Query 6: Workday Payment Election Changes (Advanced Hunting)

Detect direct interaction with Workday to change payment accounts — Storm-2755's fallback when social engineering of HR fails. Adapted from Microsoft's published hunting query.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Impact"
title: "Workday Payment Change: {{ActionType}} by {{AccountDisplayName}}"
impactedAssets:
  - type: "user"
    identifier: "accountObjectId"
recommendedActions: "Verify with the employee whether the payment change was intentional. Cross-reference with inbox rule creation (Query 4/5) and Axios sign-ins (Query 1)."
responseActions: "Freeze payroll changes. Contact employee through verified channel (phone). Reverse unauthorized banking changes."
adaptation_notes: "CloudAppEvents only — Workday telemetry requires Defender for Cloud Apps connector with Workday. Uses Timestamp."
-->
```kql
// Storm-2755: Workday payment election / bank account changes
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Workday"
| where ActionType in ("Change My Account", "Manage Payment Elections",
    "Manage Payment Elections - Step 2", "Change Payment Election")
| extend Descriptor = tostring(RawEventData.target.descriptor)
| project Timestamp, AccountDisplayName, AccountObjectId,
    ActionType, Descriptor, IPAddress, UserAgent, CountryCode, City
| order by Timestamp desc
```

**Expected Results:** Volume depends on payroll cycles. Correlate with Query 1 (Axios user-agent) or Query 4/5 (inbox rules) for the same user.

**Tuning:**
- If your org uses a different payroll SaaS, adapt `Application` value and `ActionType` values for that platform
- Cross-reference: `| where UserAgent has "axios"` to isolate threat-actor-controlled sessions

---

## Query 7: Workday Inbox Rules — Evidence Hiding (Advanced Hunting)

Detect inbox rules specifically filtering emails from Workday (`@myworkday.com`) — Storm-2755 hides Workday notifications to prevent the victim from seeing payment change confirmations. Adapted from Microsoft's published query.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Workday Evidence Hiding: Inbox rule filtering @myworkday.com — {{AccountDisplayName}}"
impactedAssets:
  - type: "user"
    identifier: "accountObjectId"
recommendedActions: "Check Workday for recent payment election or banking changes. Review full inbox rule parameters for additional hidden keywords."
responseActions: "Remove the inbox rule. Verify Workday payment details. Revoke sessions."
adaptation_notes: "CloudAppEvents AH-native. RawEventData.Parameters contains rule config. Uses Timestamp."
-->
```kql
// Storm-2755: Inbox rules hiding Workday notification emails
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend Params = RawEventData.Parameters
| where Params has "From" and Params has "@myworkday.com"
| where Params has "DeleteMessage" or Params has "MoveToFolder"
| mv-apply Params on (
    where Params.Name == "From"
    | extend RuleFrom = tostring(Params.Value))
| mv-apply Params on (
    where Params.Name == "Name"
    | extend RuleName = tostring(Params.Value))
| project Timestamp, AccountDisplayName, AccountObjectId,
    RuleName, RuleFrom, IPAddress, UserAgent, ActionType
| order by Timestamp desc
```

---

## Query 8: Social Engineering Email — Direct Deposit Subject (Advanced Hunting)

Storm-2755 sends emails with the subject "Question about direct deposit" to HR/finance staff, impersonating the compromised employee. This query hunts for those outbound emails.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "Collection"
title: "Payroll Social Engineering Email: '{{Subject}}' from {{SenderFromAddress}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
recommendedActions: "Verify with the sender through an out-of-band channel (phone) whether they sent this email. Check if the sender account shows Axios sign-ins or inbox rule changes."
adaptation_notes: "EmailEvents AH-native. Uses Timestamp. Subject matching is case-insensitive via has. For Sentinel, use OfficeActivity with Operation == 'Send'."
-->
```kql
// Storm-2755: Social engineering emails about direct deposit / payroll
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Intra-org"
| where Subject has_any ("direct deposit", "void cheque", "void check",
    "change bank", "payment details", "banking information",
    "new bank account", "update payment")
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, SenderIPv4, SenderMailFromDomain,
    DeliveryAction, DeliveryLocation, ThreatTypes
| order by Timestamp desc
```

**Expected Results:** Some legitimate direct deposit inquiries will appear. Look for:
- Compromised accounts (cross-reference with Query 1 Axios detections)
- Multiple employees sending similar emails to HR within a short window
- Emails sent outside business hours (~5 AM local time)

**Tuning:**
- Narrow to specific HR recipients: `| where RecipientEmailAddress has_any ("hr@", "payroll@", "finance@")`
- Cross-correlate: Join with Query 1 results to flag emails from accounts with Axios sign-ins

---

## Query 9: IOC Domain — bluegraintours[.]com Network Activity (Sentinel Data Lake via ASIM)

Hunt for any network activity involving the Storm-2755 AiTM phishing domain. Uses the ASIM Network Session parser for broad coverage across firewall, proxy, and NDR data sources.

> **Tool:** Use `RunAdvancedHuntingQuery` — ASIM parser functions (`_Im_NetworkSession`) are not supported in Data Lake MCP (`query_lake`).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Uses ASIM parser function _Im_NetworkSession which requires RunAdvancedHuntingQuery. Not a standalone table query — cannot adapt to CD format. Use for initial triage; deploy IOC via TI connector for automated matching."
-->
```kql
// Storm-2755: IOC domain hunting across all network session sources (ASIM)
let lookback = 30d;
let ioc_domains = dynamic(["bluegraintours.com"]);
_Im_NetworkSession(starttime=todatetime(ago(lookback)), endtime=now())
| where DstDomain has_any (ioc_domains)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count()
    by SrcIpAddr, DstIpAddr, DstDomain, Dvc, EventProduct, EventVendor
| order by EventCount desc
```

---

## Query 10: IOC Domain — bluegraintours[.]com Web Sessions (Sentinel Data Lake via ASIM)

Hunt for web browsing/proxy activity to the phishing domain using ASIM Web Session parser.

> **Tool:** Use `RunAdvancedHuntingQuery` — ASIM parser functions are not supported in Data Lake MCP.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Uses ASIM parser function _Im_WebSession. Not a standalone table query. Deploy IOC via TI connector for automated matching."
-->
```kql
// Storm-2755: IOC domain in web sessions (ASIM)
let ioc_domains = dynamic(["bluegraintours.com"]);
_Im_WebSession(url_has_any=ioc_domains)
| project TimeGenerated, SrcIpAddr, DstIpAddr, Url, 
    DstDomain, HttpStatusCode, Dvc, EventProduct
| order by TimeGenerated desc
```

---

## Query 11: Off-Hours Token Renewal (~5 AM Local Time) (Advanced Hunting)

Storm-2755 renews stolen sessions around 5 AM in the user's local time zone to avoid detection during business hours. This query identifies non-interactive sign-ins with Axios user-agent occurring consistently during off-hours.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical baseline query — groups by hour-of-day. Country is a direct string column in EntraIdSignInEvents (no parse_json needed). Application replaces AppDisplayName. For >30d lookback, substitute AADNonInteractiveUserSignInLogs with TimeGenerated + parse_json(LocationDetails)."
-->
```kql
// Storm-2755: Off-hours non-interactive sign-ins (token renewal pattern)
// Targets activity at ~5 AM local time — common Storm-2755 evasion window
// EntraIdSignInEvents provides Country as a direct string column
let lookback = 30d;
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| where LogonType has "nonInteractiveUser"
| extend HourUTC = hourofday(Timestamp)
// Canadian time zones: UTC-3.5 (NST) to UTC-8 (PST)
// 5 AM local ≈ 8:30-13:00 UTC depending on zone
| where HourUTC between (8 .. 13)
| where UserAgent has "axios"
| summarize
    SignInCount = count(),
    DistinctDays = dcount(format_datetime(Timestamp, "yyyy-MM-dd")),
    IPs = make_set(IPAddress, 10),
    Apps = make_set(Application, 5)
    by AccountUpn, HourUTC, Country
| where DistinctDays > 3
| project AccountUpn, HourUTC, Country, SignInCount,
    DistinctDays, IPs, Apps
| order by SignInCount desc
```

---

## Query 12: Full Chain Correlation — AiTM → Inbox Rule → Payroll Change (Advanced Hunting)

Correlate the complete Storm-2755 kill chain: Axios sign-in detected → inbox rule with payroll keywords → Workday payment change. A match across all three stages is a high-confidence compromise indicator.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-stage correlation across 3 tables with let blocks. Output is per-user summary. Not suitable for CD — use as forensic investigation query after individual Query 1/4/6 alerts fire."
-->
```kql
// Storm-2755: Full kill chain correlation
// Stage 1: Axios sign-ins → Stage 2: Payroll inbox rules → Stage 3: Workday changes
let lookback = 30d;
// Stage 1: Users with Axios user-agent sign-ins
let AxiosUsers = materialize(
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where UserAgent has "axios"
| summarize
    AxiosFirstSeen = min(Timestamp),
    AxiosLastSeen = max(Timestamp),
    AxiosSignIns = count(),
    AxiosIPs = make_set(IPAddress, 10)
    by AccountObjectId, AccountUpn);
// Stage 2: Payroll-keyword inbox rules for those users
let InboxRuleUsers = materialize(
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| where RawEventData.Parameters has_any ("direct deposit", "bank",
    "payroll", "@myworkday.com")
| where AccountObjectId in ((AxiosUsers | project AccountObjectId))
| summarize
    RuleCreated = min(Timestamp),
    RuleCount = count()
    by AccountObjectId, AccountDisplayName);
// Stage 3: Workday payment changes for those users
let PayrollChanges = 
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application == "Workday"
| where ActionType has_any ("Payment", "Account", "Elections")
| where AccountObjectId in ((InboxRuleUsers | project AccountObjectId))
| summarize
    PayrollChangeTime = min(Timestamp),
    PayrollActions = make_set(ActionType, 5)
    by AccountObjectId, AccountDisplayName;
// Correlate all three stages
AxiosUsers
| join kind=inner InboxRuleUsers on AccountObjectId
| join kind=leftouter PayrollChanges on AccountObjectId
| project AccountUpn, AccountObjectId,
    AxiosFirstSeen, AxiosLastSeen, AxiosSignIns, AxiosIPs,
    RuleCreated, RuleCount,
    PayrollChangeTime, PayrollActions,
    FullChainConfirmed = isnotnull(PayrollChangeTime)
| order by FullChainConfirmed desc, AxiosSignIns desc
```

**Expected Results:** Any match with `FullChainConfirmed == true` is a near-certain compromise requiring immediate incident response. Even Stage 1 + Stage 2 matches (without Stage 3) warrant urgent investigation.

---

## Implementation Priority

| # | Query | Confidence | CD | Priority |
|---|-------|-----------|-----|----------|
| 1 | Axios User-Agent Sign-Ins | 🔴 High | ✅ 1H | **P1 — Deploy immediately** |
| 4 | Payroll Keyword Inbox Rules (Sentinel) | 🔴 High | ✅ 1H | **P1 — Deploy immediately** |
| 5 | Payroll Keyword Inbox Rules (AH) | 🔴 High | ✅ 1H | **P1 — Deploy immediately** |
| 7 | Workday Evidence Hiding | 🔴 High | ✅ 1H | **P1 — Deploy immediately** |
| 2 | 50199 Error → Success Pattern | 🟠 Medium-High | ✅ 3H | **P2 — Deploy within 24h** |
| 6 | Workday Payment Changes | 🟠 Medium | ✅ 1H | **P2 — Deploy within 24h** |
| 8 | Direct Deposit Subject Emails | 🟡 Medium | ✅ 3H | **P3 — Hunt weekly** |
| 3 | OfficeHome ~30min Cadence | 🟡 Medium | ❌ | **P3 — Hunt weekly** |
| 11 | Off-Hours Token Renewal | 🟡 Low-Medium | ❌ | **P3 — Hunt weekly** |
| 9 | IOC Domain (Network ASIM) | 🔵 IOC | ❌ | **P2 — Deploy via TI connector** |
| 10 | IOC Domain (Web ASIM) | 🔵 IOC | ❌ | **P2 — Deploy via TI connector** |
| 12 | Full Chain Correlation | 🔴 High (forensic) | ❌ | **P3 — Run on-demand** |
