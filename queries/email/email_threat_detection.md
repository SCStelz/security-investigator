# Email Threat Detection & Investigation Queries

**Created:** 2026-02-06  
**Platform:** Both  
**Tables:** EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, EmailAttachmentInfo, UrlClickEvents  
**Keywords:** email, phishing, AiTM, adversary-in-the-middle, BEC, business email compromise, spam, malware, ZAP, inbox rule, attachment, URL click, Safe Links, first contact, DMARC, DKIM, SPF, authentication, forwarding, detection methods  
**MITRE:** T1566.001, T1566.002, T1598, T1114.003, T1534, T1020, TA0001, TA0009, TA0010  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This collection of KQL queries covers email-based threat detection across the Microsoft Defender for Office 365 (MDO) tables available in Sentinel Data Lake. These tables power investigations for phishing campaigns, AiTM attacks, BEC fraud, malware delivery, and email exfiltration.

**Tables Reference:**

| Table | Purpose | Key Join Column |
|-------|---------|-----------------|
| `EmailEvents` | Core email metadata — sender, recipient, direction, threats, delivery action | `NetworkMessageId` |
| `EmailPostDeliveryEvents` | Post-delivery actions — ZAP (zero-hour auto purge), manual remediation | `NetworkMessageId` |
| `EmailUrlInfo` | URLs embedded in emails | `NetworkMessageId` |
| `EmailAttachmentInfo` | File attachments in emails | `NetworkMessageId` |
| `UrlClickEvents` | Safe Links click tracking — who clicked, was it blocked or allowed | `NetworkMessageId`, `Url` |

> **⚠️ Data Lake vs Advanced Hunting:** These tables exist in the Sentinel Data Lake when the Defender XDR connector is enabled. Use `TimeGenerated` (not `Timestamp`) as the datetime column in Data Lake queries. If a table is missing, retry with `RunAdvancedHuntingQuery` using `Timestamp`.

---

## 1. Mail Flow Overview

### 1.1 Inbound Email Summary with Threat Breakdown

High-level view of inbound email volume and threat categorization.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/dashboard query — summarizes inbound mail volume with threat category breakdown. No row-level detection."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| summarize
    TotalInbound = count(),
    Clean = countif(isempty(ThreatTypes)),
    Phish = countif(ThreatTypes has "Phish"),
    Malware = countif(ThreatTypes has "Malware"),
    Spam = countif(ThreatTypes has "Spam"),
    HighConfPhish = countif(ConfidenceLevel has "High" and ThreatTypes has "Phish"),
    Blocked = countif(DeliveryAction == "Blocked"),
    Delivered = countif(DeliveryAction == "Delivered"),
    Junked = countif(DeliveryAction == "Junked"),
    DistinctSenders = dcount(SenderFromAddress),
    DistinctRecipients = dcount(RecipientEmailAddress)
| project TotalInbound, Clean, Phish, Malware, Spam, HighConfPhish,
    Blocked, Delivered, Junked, DistinctSenders, DistinctRecipients
```

### 1.2 Email Volume Trend by Day and Direction

Daily trend useful for spotting anomalous spikes (e.g., phishing campaigns).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Time-series aggregation query — bins email volume by day and direction. Baseline trend tool, not a detection."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| summarize Count = count() by EmailDirection, Day = bin(TimeGenerated, 1d)
| order by Day asc, EmailDirection
```

### 1.3 Top Sender Domains by Volume

Identify high-volume sending domains — useful for spotting impersonation or bulk senders.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — top sender domains by volume with take 20. Baseline/hunting tool."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| summarize
    EmailCount = count(),
    PhishCount = countif(ThreatTypes has "Phish"),
    SpamCount = countif(ThreatTypes has "Spam"),
    DistinctSenders = dcount(SenderFromAddress)
    by SenderFromDomain
| order by EmailCount desc
| take 20
```

---

## 2. Phishing Detection

### 2.1 Phishing Emails — Detailed View

List all emails detected as phishing with delivery details.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Row-level phishing listing, but redundant with existing MDO phishing detections. Better used as investigation query than CD."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where ThreatTypes has "Phish"
| project TimeGenerated, Subject, SenderFromAddress, SenderFromDomain,
    RecipientEmailAddress, DeliveryAction, DeliveryLocation,
    LatestDeliveryAction, LatestDeliveryLocation,
    ThreatTypes, ThreatNames, DetectionMethods,
    NetworkMessageId, InternetMessageId
| order by TimeGenerated desc
```

### 2.2 Top Phishing Sender Domains

Quick view of which domains are sending the most phishing emails.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — top phishing sender domains. Hunting/triage tool."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where ThreatTypes has "Phish"
| summarize Count = count() by SenderFromDomain
| top 10 by Count
```

### 2.3 Most Targeted Recipients for Phishing

Identify users receiving the most phishing attempts — high-value targets or compromised distribution lists.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes phishing count per recipient. Hunting/triage tool."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where ThreatTypes has "Phish" and EmailDirection == "Inbound"
| summarize PhishCount = count(), DistinctSenders = dcount(SenderFromAddress) by RecipientEmailAddress
| order by PhishCount desc
| take 15
```

### 2.4 Phishing Emails That Were Delivered (Not Blocked)

Critical: phishing emails that made it to user mailboxes — potential compromise indicators.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Phishing Email Delivered to Mailbox — {{RecipientEmailAddress}}"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Check if user clicked any URLs or opened attachments. Review Safe Links click activity via UrlClickEvents. Investigate user sign-ins for signs of compromise."
responseActions: "Purge email from mailbox via manual remediation. Revoke user sessions if compromise suspected. Block sender domain."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered" or LatestDeliveryAction == "Delivered"
| project TimeGenerated, Subject, SenderFromAddress, RecipientEmailAddress,
    DeliveryAction, LatestDeliveryAction, DeliveryLocation, LatestDeliveryLocation,
    ThreatNames, DetectionMethods, NetworkMessageId
| order by TimeGenerated desc
```

### 2.5 First-Contact Phishing Attempts

Emails from senders who have never emailed the recipient before. A strong AiTM/BEC indicator.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "First-Contact Phishing Attempt — {{RecipientEmailAddress}}"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Verify sender legitimacy. Check if user interacted with URLs or attachments. Review UrlClickEvents for Safe Links activity."
responseActions: "Purge email from mailbox. Block sender domain if confirmed malicious. Alert user not to interact with message."
adaptation_notes: "The UrlCount > 3 branch catches non-phishing emails with many URLs — consider removing for tighter CD scope."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| where IsFirstContact == true
| where ThreatTypes has "Phish" or UrlCount > 3
| project TimeGenerated, Subject, SenderFromAddress, SenderFromDomain,
    RecipientEmailAddress, IsFirstContact, UrlCount, AttachmentCount,
    ThreatTypes, DeliveryAction, NetworkMessageId
| order by TimeGenerated desc
```

---

## 3. AiTM / Adversary-in-the-Middle Hunting

### 3.1 AiTM Proxy Sign-In Detection (OfficeHome App)

AiTM kits like Evilginx2 authenticate through the OfficeHome app. Cross-country or multi-IP sessions within the same `OriginalRequestId` are indicators.

> **Note:** This query uses `SigninLogs`, not `EmailEvents`, but is included because it directly follows from email-based AiTM phishing.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "CredentialAccess"
title: "AiTM Multi-Country OfficeHome Session — {{UserPrincipalName}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
recommendedActions: "Verify whether user has legitimate multi-country VPN usage. Cross-reference with AADUserRiskEvents for anomalousToken detections. Check inbox rules via OfficeActivity."
responseActions: "Revoke user refresh tokens. Force MFA re-registration. Investigate concurrent sessions and inbox rule changes."
adaptation_notes: "Uses SigninLogs (available in AH via connected workspace). Change TimeGenerated to Timestamp for AH. The let variable is a constant AppId, not a parameter."
-->
```kql
// Detect OfficeHome sessions with multi-country sign-ins (AiTM token replay indicator)
let OfficeHomeAppId = "4765445b-32c6-49b0-83e6-1d93765276ca";
SigninLogs
| where TimeGenerated > ago(30d)
| where AppId == OfficeHomeAppId
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend City = tostring(parse_json(LocationDetails).city)
| summarize
    Countries = make_set(Country),
    Cities = make_set(City),
    IPs = make_set(IPAddress),
    SignIns = count()
    by UserPrincipalName, OriginalRequestId
| where array_length(Countries) > 1
| project UserPrincipalName, OriginalRequestId, Countries, Cities, IPs, SignIns
| order by SignIns desc
```

### 3.2 AiTM Full Chain: Phishing Email → Anomalous Token → Inbox Rule

Correlate the full AiTM attack chain: phishing email received → anomalous token detected → inbox rule created.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-stage investigation chain — uses let block with cross-table join (EmailEvents → AADUserRiskEvents). AADUserRiskEvents may not be available in AH. Better used as forensic follow-up after AiTM alert."
-->
```kql
// Step 1: Find phishing emails delivered to users
let PhishedUsers = EmailEvents
| where TimeGenerated > ago(30d)
| where ThreatTypes has "Phish" and EmailDirection == "Inbound"
| where DeliveryAction != "Blocked"
| distinct RecipientEmailAddress;
// Step 2: Check for anomalous token risk events for those users
AADUserRiskEvents
| where TimeGenerated > ago(30d)
| where RiskEventType == "anomalousToken"
| where UserPrincipalName in~ (PhishedUsers)
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel,
    IpAddress, Location, RiskState
| order by TimeGenerated desc
```

### 3.3 Inbox Rules Created After Phishing Email Delivery

Detect inbox rules created shortly after a phishing email was received — key AiTM/BEC indicator.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table correlation (EmailEvents → OfficeActivity). OfficeActivity is Sentinel-only and may not be available in Advanced Hunting. Forensic follow-up query."
-->
```kql
let PhishRecipients = EmailEvents
| where TimeGenerated > ago(30d)
| where ThreatTypes has "Phish" and EmailDirection == "Inbound"
| where DeliveryAction != "Blocked"
| project RecipientEmailAddress, PhishTime = TimeGenerated;
OfficeActivity
| where TimeGenerated > ago(30d)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| join kind=inner PhishRecipients on $left.UserId == $right.RecipientEmailAddress
| where TimeGenerated between (PhishTime .. (PhishTime + 24h))
| project TimeGenerated, UserId, Operation, Parameters, PhishTime,
    ClientIP, SessionId
| order by TimeGenerated desc
```

---

## 4. Email Authentication Analysis

### 4.1 Email Authentication Failures (DMARC/DKIM/SPF)

Identify emails failing authentication checks — spoofing indicators.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Extremely noisy — DMARC/DKIM/SPF failures are common for legitimate email. Would generate thousands of CD alerts per day. Use as hunting/investigation baseline, not detection."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend
    DMARC = tostring(AuthDetails.DMARC),
    DKIM = tostring(AuthDetails.DKIM),
    SPF = tostring(AuthDetails.SPF),
    CompAuth = tostring(AuthDetails.CompAuth)
| where DMARC == "fail" or DKIM == "fail" or SPF == "fail" or CompAuth == "fail"
| project TimeGenerated, SenderFromAddress, SenderFromDomain,
    SenderMailFromDomain, RecipientEmailAddress, Subject,
    DMARC, DKIM, SPF, CompAuth, DeliveryAction
| order by TimeGenerated desc
```

### 4.2 Authentication Failure Summary by Domain

Aggregate authentication failures by sender domain to identify systematic spoofing.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes auth failure counts by domain. Hunting/triage tool."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend
    DMARC = tostring(AuthDetails.DMARC),
    DKIM = tostring(AuthDetails.DKIM),
    SPF = tostring(AuthDetails.SPF),
    CompAuth = tostring(AuthDetails.CompAuth)
| summarize
    TotalEmails = count(),
    DMARCFail = countif(DMARC == "fail"),
    DKIMFail = countif(DKIM == "fail"),
    SPFFail = countif(SPF == "fail"),
    CompAuthFail = countif(CompAuth == "fail")
    by SenderFromDomain
| where DMARCFail > 0 or DKIMFail > 0 or SPFFail > 0 or CompAuthFail > 0
| order by TotalEmails desc
```

### 4.3 Envelope-From vs Header-From Mismatch (Display Name Spoofing)

Detects when the MAIL FROM domain doesn't match the FROM header domain — common in spoofing.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes envelope/header mismatch count by domain pair. Hunting/triage tool for identifying spoofing patterns."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| where SenderFromDomain != SenderMailFromDomain
| where isnotempty(SenderMailFromDomain)
| summarize
    Count = count(),
    Subjects = make_set(Subject, 3)
    by SenderFromDomain, SenderMailFromDomain, SenderFromAddress
| order by Count desc
| take 20
```

---

## 5. Detection Methods & Policy Analysis

### 5.1 Detection Methods Breakdown

Understand what MDO detection methods are triggering on inbound mail.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes detection method frequency. Operational dashboard/reporting query."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where isnotempty(DetectionMethods) and DetectionMethods != "{}"
| extend DetMethods = parse_json(DetectionMethods)
| extend FirstDetection = tostring(bag_keys(DetMethods)[0])
| extend FirstSubcategory = iif(
    FirstDetection != "" and array_length(DetMethods[FirstDetection]) > 0,
    strcat(FirstDetection, ": ", tostring(DetMethods[FirstDetection][0])),
    FirstDetection)
| summarize Count = count() by FirstSubcategory
| order by Count desc
```

### 5.2 Overridden Threats (Allow Policies Bypassing Detection)

Emails detected as threats but allowed by policy — review for false negative risk.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes override/allow counts by policy type. Operational dashboard for policy tuning."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where OrgLevelAction == "Allow" and isnotempty(ThreatTypes)
| summarize Count = count() by ThreatTypes, OrgLevelPolicy, DetectionMethods
| order by Count desc
```

### 5.3 Third-Party Detection Integration

Emails detected by non-Microsoft security vendors integrated via ICES.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Monitoring/investigation query — lists all third-party detections without threat filtering. Volume varies widely by environment. Better as hunting tool."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where DetectionMethods contains "Thirdparty"
| project TimeGenerated, NetworkMessageId, RecipientEmailAddress,
    SenderFromAddress, ThreatTypes, DetectionMethods,
    LatestDeliveryLocation
| order by TimeGenerated desc
```

---

## 6. Post-Delivery Actions (ZAP & Remediation)

### 6.1 ZAP Actions Summary

Overview of Zero-hour Auto Purge activity — catches threats discovered after delivery.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes ZAP action counts by type. Operational dashboard for ZAP effectiveness monitoring."
-->
```kql
EmailPostDeliveryEvents
| where TimeGenerated > ago(30d)
| summarize
    TotalActions = count(),
    PhishZAP = countif(ActionType == "Phish ZAP"),
    MalwareZAP = countif(ActionType == "Malware ZAP"),
    SpamZAP = countif(ActionType == "Spam ZAP"),
    SuccessCount = countif(ActionResult == "Success"),
    ErrorCount = countif(ActionResult == "Error")
| project TotalActions, PhishZAP, MalwareZAP, SpamZAP, SuccessCount, ErrorCount
```

### 6.2 Failed ZAP Actions (Threats Still in Mailbox)

Critical: ZAP attempted remediation but failed — threats may still be in user mailboxes.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "ZAP Remediation Failed — Threat Still in Mailbox {{RecipientEmailAddress}}"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Manually remediate the email from affected mailboxes. Verify ZAP failure reason (e.g., message in shared mailbox, retention policy, user moved to subfolder). Check if user interacted with the threat."
responseActions: "Purge threat from mailbox via manual remediation. Review user activity for signs of compromise. Investigate UrlClickEvents if URLs were present."
-->
```kql
EmailPostDeliveryEvents
| where TimeGenerated > ago(30d)
| where ActionType has "ZAP" and ActionResult == "Error"
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(30d)
) on NetworkMessageId, RecipientEmailAddress
| project TimeGenerated, ActionType, ActionResult, RecipientEmailAddress,
    SenderFromAddress, Subject, ThreatTypes, LatestDeliveryLocation,
    NetworkMessageId
| order by TimeGenerated desc
```

### 6.3 User Activity After Failed ZAP (Compromise Check)

Check if users who received un-remediated emails had subsequent suspicious sign-in activity.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table investigation chain (EmailPostDeliveryEvents → EmailEvents → SigninLogs). Multi-step correlation with risk-based filtering. Better as forensic follow-up after ZAP failure alert."
-->
```kql
let FailedZAPUsers = EmailPostDeliveryEvents
| where TimeGenerated > ago(30d)
| where ActionType has "ZAP" and ActionResult == "Error"
| distinct RecipientEmailAddress;
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName in~ (FailedZAPUsers)
| where RiskLevelDuringSignIn in ("medium", "high")
    or RiskLevelAggregated in ("medium", "high")
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
    RiskLevelDuringSignIn, RiskLevelAggregated, ResultType,
    parse_json(LocationDetails).countryOrRegion
| order by TimeGenerated desc
```

---

## 7. URL Analysis

### 7.1 URLs in Inbound Emails — Domain Summary

Top URL domains embedded in inbound emails — spot phishing infrastructure domains.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes URL domain frequency. Hunting/triage tool for identifying suspicious domains."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound" and UrlCount > 0
| join kind=inner (
    EmailUrlInfo
    | where TimeGenerated > ago(30d)
) on NetworkMessageId
| summarize
    UrlCount = dcount(Url),
    EmailCount = dcount(NetworkMessageId)
    by UrlDomain
| where UrlCount > 2
| order by UrlCount desc
| take 20
```

### 7.2 Suspicious URL Patterns (Long URLs, Encoded Params)

Hunt for URLs with characteristics common in phishing kits — long URLs, base64-like parameters.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Hunting query with heuristic thresholds (strlen > 200, contains patterns). Uses take 50 for manual review. Not precise enough for automated CD alerting."
-->
```kql
EmailUrlInfo
| where TimeGenerated > ago(30d)
| where strlen(Url) > 200
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(30d)
    | where EmailDirection == "Inbound"
) on NetworkMessageId
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress,
    Subject, Url, UrlDomain, ThreatTypes, DeliveryAction
| order by TimeGenerated desc
| take 50
```

### 7.3 Safe Links Clicks — All Activity

Full Safe Links click tracking — who clicked what URL, and was it allowed or blocked.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Full activity listing — includes both blocked and allowed clicks without threat filtering. Too noisy for CD; use Q7.4 (allowed clicks on malicious URLs) instead."
-->
```kql
UrlClickEvents
| where TimeGenerated > ago(30d)
| project TimeGenerated, AccountUpn, Url, UrlChain,
    ActionType, IsClickedThrough, ThreatTypes,
    IPAddress, NetworkMessageId, Workload
| order by TimeGenerated desc
```

### 7.4 Clicks Allowed on Malicious URLs (User Exposed to Threat)

URLs that Safe Links identified as threats but the user was allowed through — high-risk exposure.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "User Clicked Malicious URL — {{AccountUpn}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
recommendedActions: "Check if user entered credentials after clicking. Review SigninLogs for anomalous sign-ins from new IPs/devices. Investigate the URL reputation and landing page."
responseActions: "Revoke user sessions if credential entry suspected. Reset password. Block URL at network/proxy level."
-->
```kql
UrlClickEvents
| where TimeGenerated > ago(30d)
| where ActionType == "ClickAllowed" or IsClickedThrough == true
| where isnotempty(ThreatTypes)
| project TimeGenerated, AccountUpn, Url, ThreatTypes,
    ActionType, IsClickedThrough, IPAddress, Workload, NetworkMessageId
| order by TimeGenerated desc
```

### 7.5 URL Click Summary by User

Identify users with the most Safe Links click activity — potential risky click behavior.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes click counts per user. Behavioral analysis/reporting tool."
-->
```kql
UrlClickEvents
| where TimeGenerated > ago(30d)
| summarize
    TotalClicks = count(),
    BlockedClicks = countif(ActionType == "ClickBlocked"),
    AllowedClicks = countif(ActionType == "ClickAllowed"),
    ClickedThrough = countif(IsClickedThrough == true),
    PhishClicks = countif(ThreatTypes has "Phish"),
    DistinctUrls = dcount(Url)
    by AccountUpn
| order by TotalClicks desc
```

---

## 8. Attachment Analysis

### 8.1 Attachment Summary by File Type

Breakdown of attachment types seen in email — identify uncommon/risky file types.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes attachment file type frequency. Operational dashboard for identifying risky file type trends."
-->
```kql
EmailAttachmentInfo
| where TimeGenerated > ago(30d)
| summarize
    Count = count(),
    DistinctFiles = dcount(FileName),
    DistinctSenders = dcount(SenderFromAddress)
    by FileType
| order by Count desc
```

### 8.2 Malicious Attachments Detected

Attachments flagged as threats — with sender and recipient details.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Malicious Email Attachment Detected — {{RecipientEmailAddress}}"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Verify delivery action (blocked vs delivered). If delivered, check if user opened the attachment. Cross-reference SHA256 with DeviceFileEvents for endpoint execution."
responseActions: "Purge email from mailbox if delivered. Block sender domain. Submit attachment hash to TI for further analysis."
-->
```kql
EmailAttachmentInfo
| where TimeGenerated > ago(30d)
| where isnotempty(ThreatTypes)
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(30d)
) on NetworkMessageId
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress,
    Subject, FileName, FileType, FileExtension, SHA256,
    ThreatTypes, ThreatNames, DetectionMethods,
    DeliveryAction, NetworkMessageId
| order by TimeGenerated desc
```

### 8.3 Attachment Hash Lookup Against Threat Intelligence

Cross-reference attachment hashes with external threat intelligence feeds.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Uses externaldata() with external URL — not supported in custom detections. The external TI CSV URL would need to be replaced with a Sentinel watchlist or ThreatIntelligenceIndicator join."
-->
```kql
// Replace the externaldata URL with your preferred TI feed
let abuse_sha256 = (externaldata(sha256_hash: string)
[@"https://bazaar.abuse.ch/export/txt/sha256/recent/"]
with (format="txt"))
| where sha256_hash !startswith "#"
| project sha256_hash;
abuse_sha256
| join kind=inner (
    EmailAttachmentInfo
    | where TimeGenerated > ago(7d)
) on $left.sha256_hash == $right.SHA256
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress,
    FileName, FileType, SHA256, ThreatTypes, DetectionMethods
```

### 8.4 Attachments on Devices (Lateral Spread Check)

Check if malicious email attachments were saved/executed on endpoint devices.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Malicious Email Attachment on Device — {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Investigate device for malware execution. Check DeviceProcessEvents for child processes spawned from the attachment. Review DeviceNetworkEvents for C2 communication."
responseActions: "Isolate device if active execution detected. Run full AV scan. Collect forensic artifacts from the device."
-->
```kql
// Requires DeviceFileEvents table
EmailAttachmentInfo
| where TimeGenerated > ago(30d)
| where isnotempty(ThreatTypes) and isnotempty(SHA256)
| join kind=inner (
    DeviceFileEvents
    | where TimeGenerated > ago(30d)
) on SHA256
| project TimeGenerated, FileName, SHA256, DeviceName, DeviceId,
    SenderFromAddress, RecipientEmailAddress, ThreatTypes,
    NetworkMessageId
| order by TimeGenerated desc
```

---

## 9. Business Email Compromise (BEC)

### 9.1 Outbound Emails from Compromised Accounts

After account takeover, attackers send BEC payment fraud emails from the victim's mailbox.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Parameter-dependent — requires let SuspectedUsers list to be populated with known compromised accounts. Investigation follow-up query, not standalone detection."
-->
```kql
// Provide list of suspected compromised users
let SuspectedUsers = dynamic(["<UPN1>", "<UPN2>"]);
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Outbound"
| where SenderFromAddress in~ (SuspectedUsers)
| project TimeGenerated, Subject, SenderFromAddress, RecipientEmailAddress,
    RecipientDomain, UrlCount, AttachmentCount, EmailLanguage,
    NetworkMessageId
| order by TimeGenerated desc
```

### 9.2 External Forwarding Detection via Email Events

Detect emails being auto-forwarded outside the organization.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Noisy without tenant-specific filtering — catches all forwarded emails including legitimate auto-forwards. Would need exclusion list for known-good forwarding rules before CD deployment."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where isnotempty(ForwardingInformation)
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress,
    Subject, ForwardingInformation, EmailDirection,
    NetworkMessageId
| order by TimeGenerated desc
```

### 9.3 Email Forwarding Rules via OfficeActivity (Comprehensive)

Detect inbox rule creation/modification that sets up forwarding or redirection.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Uses OfficeActivity table — Sentinel-only, may not be available in Advanced Hunting. For CD, consider CloudAppEvents with ActionType containing inbox rule operations instead."
-->
```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardingSmtpAddress")
    or Parameters has_any ("DeleteMessage", "MarkAsRead")
| project TimeGenerated, UserId, Operation, Parameters,
    ClientIP, UserAgent = tostring(parse_json(ExtendedProperties)[0].Value)
| order by TimeGenerated desc
```

---

## 10. MDO Efficacy & Operational Metrics

### 10.1 MDO Detection Efficacy (Pre vs Post-Delivery)

Measure the effectiveness of Defender for Office 365 at catching threats before and after delivery.

> Source: [Microsoft Learn — MDO Efficacy Query](https://learn.microsoft.com/en-us/defender-office-365/reports-mdo-email-collaboration-dashboard#appendix-advanced-hunting-efficacy-query-in-defender-for-office-365-plan-2)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Complex statistical query with toscalar() calculations and multiple let blocks for pre/post-delivery efficacy measurement. Operational reporting, not event-driven detection."
-->
```kql
let _startTime = ago(30d);
let _endTime = now();
let PreDelivery = toscalar(
    EmailEvents
    | where TimeGenerated between (_startTime .. _endTime)
        and EmailDirection == "Inbound"
        and (ThreatTypes contains "Phish" or ThreatTypes contains "Malware")
    | where not(DeliveryAction == "Blocked" and DeliveryLocation in ("Dropped", "Failed"))
    | summarize PreDelivery = count()
);
let PostDelivery = toscalar(
    EmailPostDeliveryEvents
    | where TimeGenerated between (_startTime .. _endTime)
        and ActionType in ("Malware ZAP", "Phish ZAP")
        and ActionResult in ("Success", "UserTriaged")
    | summarize PostDelivery = count()
);
let Uncaught = toscalar(
    EmailPostDeliveryEvents
    | where TimeGenerated between (_startTime .. _endTime)
        and ActionType in ("Malware ZAP", "Phish ZAP")
        and ActionResult !in ("Success", "UserTriaged")
    | summarize Uncaught = count()
);
let PreDeliveryReal = toreal(PreDelivery);
let PostDeliveryReal = toreal(PostDelivery);
let UncaughtReal = toreal(Uncaught);
let Effectiveness = round(
    iif(
        (PreDeliveryReal + PostDeliveryReal + UncaughtReal) == 0,
        0.0,
        ((PreDeliveryReal + PostDeliveryReal) / (PreDeliveryReal + PostDeliveryReal + UncaughtReal)) * 100.0
    ), 2
);
union
    (print StatisticName = "Pre-Delivery Catch", Value = PreDeliveryReal),
    (print StatisticName = "Post-Delivery Catch", Value = PostDeliveryReal),
    (print StatisticName = "Failed ZAP / Miss", Value = UncaughtReal),
    (print StatisticName = "Efficacy %", Value = Effectiveness)
| project StatisticName, Value
```

### 10.2 Delivery Action Breakdown

Where are emails ending up? Inbox, Junk, Quarantine, or Blocked?

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes delivery location distribution. Operational dashboard for MDO effectiveness monitoring."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| summarize Count = count() by DeliveryAction, DeliveryLocation
| order by Count desc
```

### 10.3 Latest Delivery Location (Post-ZAP State)

After ZAP and manual remediation, where do emails currently reside?

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes current delivery location post-remediation. Operational dashboard for remediation effectiveness."
-->
```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| where isnotempty(ThreatTypes)
| summarize Count = count() by LatestDeliveryAction, LatestDeliveryLocation, ThreatTypes
| order by Count desc
```

---

## 11. Cross-Table Correlation Queries

### 11.1 Phishing Email → Device Logon Correlation

Find device logons within 30 minutes of receiving a phishing email — indicates user interacted with the phish.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Device Logon After Phishing Email — {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Investigate device logon source (local vs remote). Check if user clicked URLs in the phishing email via UrlClickEvents. Review DeviceProcessEvents for post-logon suspicious activity."
responseActions: "Isolate device if malicious activity confirmed. Revoke user sessions. Reset credentials if credential harvesting suspected."
adaptation_notes: "Cross-table time-bounded join (EmailEvents → DeviceLogonEvents within 30min). Both tables are AH-native."
-->
```kql
// Requires DeviceLogonEvents table
EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has "Phish" and EmailDirection == "Inbound"
| where DeliveryAction != "Blocked"
| project EmailTime = TimeGenerated, Subject, SenderFromAddress,
    AccountName = tostring(split(RecipientEmailAddress, "@")[0])
| join kind=inner (
    DeviceLogonEvents
    | where TimeGenerated > ago(7d)
    | project LogonTime = TimeGenerated, AccountName, DeviceName
) on AccountName
| where (LogonTime - EmailTime) between (0min .. 30min)
| project EmailTime, LogonTime, AccountName, DeviceName,
    Subject, SenderFromAddress
| order by EmailTime desc
```

### 11.2 Malicious Email → PowerShell Execution Correlation

Detect PowerShell activity on devices shortly after receiving malicious emails.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "PowerShell Execution After Malicious Email — {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Analyze PowerShell command line for encoded commands, download cradles, or reconnaissance activity. Check parent process chain. Review DeviceNetworkEvents for C2 callbacks."
responseActions: "Isolate device immediately. Collect PowerShell script block logs. Revoke user sessions and reset credentials."
adaptation_notes: "Cross-table time-bounded join (EmailEvents → DeviceProcessEvents within 30min). Both tables are AH-native. Consider expanding FileName filter to include pwsh.exe for PowerShell 7."
-->
```kql
// Requires DeviceProcessEvents table
let MaliciousEmails = EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has "Malware" and EmailDirection == "Inbound"
| where DeliveryAction != "Blocked"
| project EmailTime = TimeGenerated, Subject, SenderFromAddress,
    AccountName = tostring(split(RecipientEmailAddress, "@")[0]);
MaliciousEmails
| join kind=inner (
    DeviceProcessEvents
    | where TimeGenerated > ago(7d)
    | where FileName =~ "powershell.exe"
    | project ProcTime = TimeGenerated, AccountName, DeviceName,
        InitiatingProcessParentFileName, FileName, ProcessCommandLine
) on AccountName
| where (ProcTime - EmailTime) between (0min .. 30min)
| project EmailTime, ProcTime, AccountName, DeviceName,
    Subject, SenderFromAddress, ProcessCommandLine
| order by EmailTime desc
```

### 11.3 Email with URL → URL Click → Sign-in Timeline

Full chain: phishing email with URL → user clicked the URL → subsequent sign-in activity.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "3-table join investigation chain (EmailUrlInfo → UrlClickEvents → AADSignInEventsBeta). Complex multi-step correlation with leftouter joins. Better as forensic investigation query, not automated CD."
-->
```kql
let SuspiciousClicks = UrlClickEvents
| where TimeGenerated > ago(30d)
| where ActionType == "ClickAllowed" or IsClickedThrough == true
| project ClickTime = TimeGenerated, AccountUpn, Url, NetworkMessageId;
SuspiciousClicks
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(30d)
    | where EmailDirection == "Inbound"
) on NetworkMessageId
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(30d)
    | where ResultType == 0
    | project SignInTime = TimeGenerated, UserPrincipalName, AppDisplayName,
        IPAddress, parse_json(LocationDetails).countryOrRegion
) on $left.AccountUpn == $right.UserPrincipalName
| where SignInTime between (ClickTime .. (ClickTime + 1h))
| project ClickTime, SignInTime, AccountUpn, Url, SenderFromAddress,
    Subject, AppDisplayName, IPAddress
| order by ClickTime desc
```

---

## 12. Targeted Investigation Queries

### 12.1 All Emails for a Specific User

Pull all email activity for a specific user under investigation.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Parameter-dependent — requires let TargetUser to be populated. Investigation/forensic query for specific user analysis."
-->
```kql
let TargetUser = "<UPN>";
EmailEvents
| where TimeGenerated > ago(30d)
| where RecipientEmailAddress =~ TargetUser or SenderFromAddress =~ TargetUser
| project TimeGenerated, EmailDirection, SenderFromAddress, RecipientEmailAddress,
    Subject, ThreatTypes, DeliveryAction, LatestDeliveryAction,
    UrlCount, AttachmentCount, IsFirstContact, NetworkMessageId
| order by TimeGenerated desc
```

### 12.2 Trace a Specific Email by NetworkMessageId

Deep-dive into a single email across all related tables.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Parameter-dependent — requires let MsgId (NetworkMessageId). Multi-query investigation block using semicolons to query EmailEvents, EmailUrlInfo, EmailAttachmentInfo, and EmailPostDeliveryEvents separately. Forensic drill-down, not detection."
-->
```kql
let MsgId = "<NetworkMessageId>";
// Core email metadata
EmailEvents
| where NetworkMessageId == MsgId
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject,
    EmailDirection, ThreatTypes, DetectionMethods, DeliveryAction,
    LatestDeliveryAction, LatestDeliveryLocation, AuthenticationDetails;
// URLs in the email
EmailUrlInfo
| where NetworkMessageId == MsgId
| project Url, UrlDomain, UrlLocation;
// Attachments in the email
EmailAttachmentInfo
| where NetworkMessageId == MsgId
| project FileName, FileType, FileExtension, SHA256, ThreatTypes;
// Post-delivery actions
EmailPostDeliveryEvents
| where NetworkMessageId == MsgId
| project TimeGenerated, ActionType, ActionResult;
// Click events
UrlClickEvents
| where NetworkMessageId == MsgId
| project TimeGenerated, AccountUpn, Url, ActionType, IsClickedThrough, ThreatTypes
```

### 12.3 Emails from a Suspicious Sender

Investigate all emails from a specific sender address or domain.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Parameter-dependent — requires let SuspiciousSender to be populated. 90-day lookback exceeds CD maximum. Investigation/forensic query for sender-based analysis."
-->
```kql
let SuspiciousSender = "<sender@domain.com>";
EmailEvents
| where TimeGenerated > ago(90d)
| where SenderFromAddress =~ SuspiciousSender
    or SenderMailFromAddress =~ SuspiciousSender
| project TimeGenerated, SenderFromAddress, SenderMailFromAddress,
    RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction,
    UrlCount, AttachmentCount, AuthenticationDetails, NetworkMessageId
| order by TimeGenerated desc
```

---

## Schema Quick Reference

### EmailEvents Key Columns

| Column | Type | Notes |
|--------|------|-------|
| `NetworkMessageId` | string | Primary key — joins to all other email tables |
| `InternetMessageId` | string | RFC 5322 message ID from sending system |
| `EmailDirection` | string | `Inbound`, `Outbound`, `Intra-org` |
| `ThreatTypes` | string | Pipe-delimited: `Phish`, `Malware`, `Spam` |
| `DetectionMethods` | string | JSON string — use `parse_json()` to extract |
| `AuthenticationDetails` | string | JSON string with DMARC/DKIM/SPF/CompAuth results |
| `DeliveryAction` | string | Initial action: `Delivered`, `Blocked`, `Junked`, `Replaced` |
| `LatestDeliveryAction` | string | Current state after ZAP/remediation |
| `IsFirstContact` | bool | True if sender has never emailed this recipient before |
| `SenderFromDomain` | string | Domain from the FROM header (visible to user) |
| `SenderMailFromDomain` | string | Domain from the envelope MAIL FROM (may differ) |
| `ForwardingInformation` | string | Present if email was auto-forwarded |

### Common Join Patterns

| Join | Left Table | Right Table | Join Key(s) |
|------|-----------|-------------|-------------|
| Email → URLs | `EmailEvents` | `EmailUrlInfo` | `NetworkMessageId` |
| Email → Attachments | `EmailEvents` | `EmailAttachmentInfo` | `NetworkMessageId` |
| Email → Post-Delivery | `EmailEvents` | `EmailPostDeliveryEvents` | `NetworkMessageId`, `RecipientEmailAddress` |
| Email → URL Clicks | `EmailEvents` | `UrlClickEvents` | `NetworkMessageId` |
| Email → Device Events | `EmailEvents` | `DeviceLogonEvents` | `AccountName` (extract from `RecipientEmailAddress`) |

### Known Pitfalls

| Field | Pitfall |
|-------|---------|
| `DetectionMethods` | JSON string, NOT dynamic — must `parse_json()` before accessing sub-keys |
| `AuthenticationDetails` | JSON string — must `parse_json()` before accessing DMARC/DKIM/SPF |
| `ThreatTypes` | String field — use `has` not `==` (values can be pipe-delimited) |
| `TimeGenerated` vs `Timestamp` | Data Lake uses `TimeGenerated`; Advanced Hunting uses `Timestamp` |
| `IsFirstContact` | May be null for non-inbound emails — always filter `EmailDirection == "Inbound"` first |
