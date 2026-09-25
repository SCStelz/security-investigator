# AI-Assisted Executive Impersonation and Vendor Invoice Fraud (ACH) — Threat Hunts

**Created:** 2026-09-25  
**Platform:** Microsoft Defender XDR  
**Tables:** EmailEvents, EmailUrlInfo, UrlClickEvents, IdentityInfo, AlertInfo, AlertEvidence  
**Keywords:** executive impersonation, CEO fraud, business email compromise, BEC, invoice fraud, vendor impersonation, ServiceNow impersonation, ACH payment, ACH Parment, due bill, wire transfer, accounts payable, finance mailbox, fabricated invoice, forwarded thread, reply-to divergence, display name spoofing, lookalike domain, service-nowinc, domainlify, third-party email service, ESP abuse, generative AI phishing template, AI-generated HTML comments, em dash, first contact sender, ZAP, zero-hour auto purge, T1656, T1657  
**MITRE:** T1591, T1598, T1583.001, T1585.002, T1566, T1566.001, T1566.003, T1036, T1656, T1657  
**Domains:** email, identity  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Protecting organizations from AI-assisted executive impersonation and invoice fraud (2026-09-10)](https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/)

---

## Threat Overview

Between **August 3 and 5, 2026**, Microsoft detected a financial-fraud campaign of **more than a million emails** (87.7% to US recipients) sent through **multiple third-party email service accounts**. Each message impersonated an **executive of the recipient's own company** (CEO, CFO, President) in the sender display name, the reply-to display name and the signature. It asked accounts payable to process an **ACH payment of nearly $50,000**. The body was a short "approval" of the "invoice below". Beneath it sat a fabricated, recipient-personalized **"ServiceNow Platform — Annual Subscription" invoice** with the actor's bank details, and a fake "forwarded" exchange between the impersonated executive and ServiceNow's President. The "forwarded" content lacked real forwarding headers and was left-aligned rather than nested, with tells like "no need to copy me".

The actor registered **`service-nowinc[.]com`** (the fake ServiceNow President's address and the invoice contact) and **`domainlify[.]net`** (the Reply-To) on July 31. Payment destinations varied across samples. The HTML templates carried hallmarks of **generative-AI construction** — verbose HTML comments, capitalized section banners (`===========`), heavy em-dash use and uniform structure — with invoice IDs and narrative constant across samples while organization details changed. ServiceNow and the other referenced organizations were impersonated, **not compromised**.

> **Companion file:** [`queries/threat-intelligence/2026-07/email_threat_landscape_q2_2026.md`](../2026-07/email_threat_landscape_q2_2026.md) covers the Q2 2026 automated BEC wave (role-mailbox targeting, reply-bait). This file adds the September invoice-fraud IOCs plus executive display-name impersonation, vendor look-alike domains, finance-recipient targeting and victim-reply engagement hunts.

### TTP Summary

| Stage | TTP |
|---|---|
| Reconnaissance | Public research on executives, finance staff and vendor relationships (T1591, T1598) |
| Resource development | Look-alike vendor domain and a separate Reply-To domain registered days before sending (T1583.001); third-party email service sender accounts (T1585.002) |
| Delivery | Bulk sending through third-party email services (T1566.003) |
| Impersonation | Recipient's own executive in display name, reply-to name and signature; vendor branding and a fabricated forwarded thread (T1656, T1036) |
| Lure | Fabricated invoice with actor bank details, personalized "BILLED TO"; offer of a PDF on request (T1566, T1566.001) |
| Impact | Accounts payable initiates ACH / bank transfer to actor-controlled accounts (T1657) |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **The fraud is in the body, which Advanced Hunting doesn't expose** | `EmailEvents` has no message body, HTML or Reply-To header. AI-template tells (HTML comments, banners, em dashes) and the fake forwarded thread can't be hunted in AH; use Threat Explorer / email entity page or Defender for Office 365 submissions for content. The hunts here key on **headers, sender and recipient context, and victim behavior**. |
| **Reply-To isn't a column** | The actor's Reply-To domain differed from the sender. Query 5 detects the effect instead: a finance user **replying** to a lure subject at a domain different from the lure's sender. |
| **Executive names are also legitimately used by internal systems and simulations** | Attack Simulation Training and tenant-owned relay subdomains send as executive display names. Queries 2 and 3 compute the tenant's own domain family (recipient domains and their subdomains) and rank those `Low`; add verified simulation sender domains to `SimulationSenderDomains`. |
| **"Overdue" matches training lures** | An early draft of the finance-lure regex matched "Overdue Annual Compliance Training". The lure regex requires *overdue invoice/payment/bill/balance*; keep it specific. |
| **Short vendor brand tokens are noisy** | `ups`, `aws`, `sap` and `zoom` appear inside unrelated words (`image-upscaling`, `ttcoups`). Query 4 matches short brands only as a domain-label **prefix**, and long brands anywhere. Extend `LegitRoots` with each vendor's real sending and tracking domains. |
| **`IdentityInfo` titles and departments vary by tenant** | Queries 2 and 3 use a title regex (CEO/CFO/President/Founder/…) and department keywords (Finance, Accounting, AP, Treasury, Procurement). Tune them to your HR taxonomy, or seed a static list of executives and AP mailboxes. |
| **The campaign ran on August 3–5** | That falls outside a 30-day AH window from late September. Run Query 1 in the Sentinel Data Lake (`TimeGenerated`) for retrospective coverage. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Invoice-fraud campaign IOC sweep — senders, look-alike domains, URL...](#query-1-invoice-fraud-campaign-ioc-sweep--senders-look-alike-domains-urls-clicks-and-outbound-replies) | Investigation | `EmailEvents` + multi |
| 2 | [External mail using one of your executives' display names (CEO/CFO/...](#query-2-external-mail-using-one-of-your-executives-display-names-ceocfopresident-impersonation) | Investigation | `EmailEvents` + `IdentityInfo` |
| 3 | [Finance-lure mail from external senders to finance, AP and treasury...](#query-3-finance-lure-mail-from-external-senders-to-finance-ap-and-treasury-recipients) | Investigation | `EmailEvents` + `IdentityInfo` |
| 4 | [Vendor look-alike domains in sender, envelope or URL (the `service-...](#query-4-vendor-look-alike-domains-in-sender-envelope-or-url-the-service-nowinc-pattern) | Investigation | `EmailEvents` + `EmailUrlInfo` |
| 5 | [Users replying to finance lures at a different or never-before-cont...](#query-5-users-replying-to-finance-lures-at-a-different-or-never-before-contacted-domain-reply-to-divergence) | Investigation | `EmailEvents` |
| 6 | [Defender for Office 365 alerts and post-delivery outcomes on financ...](#query-6-defender-for-office-365-alerts-and-post-delivery-outcomes-on-finance-lure-mail) | Detection | `AlertInfo` + multi |


## IOC Reference

> Published by Microsoft Threat Intelligence (defanged here, plain in the queries). Sender addresses are from **third-party email service accounts** and are likely abused or disposable; the look-alike and Reply-To domains are actor-registered. Refresh from current Microsoft Defender Threat Intelligence before relying on Query 1.

| Indicator | Type | Description |
|---|---|---|
| service-nowinc[.]com | Domain | Domain impersonating ServiceNow |
| gomez@service-nowinc[.]com | Email address | Email address associated with bank account |
| domainlify[.]net | Domain | Newly registered domain used in Reply-to address |
| notifications@uinsure[.]co[.]uk | Email address | Sender email address used to send out emails |
| info@tivityhealth[.]com | Email address | Sender email address used to send out emails |
| no-reply@lumalisboa[.]com | Email address | Sender email address used to send out emails |
| noreply@mctci[.]com | Email address | Sender email address used to send out emails |
| info@nuf[.]co[.]jp | Email address | Sender email address used to send out emails |
| info@lohnsteuerhilfe-aktuell-verein[.]de | Email address | Sender email address used to send out emails |
| info@tovimbatista[.]pt | Email address | Sender email address used to send out emails |
| contact@eemusicclass[.]co[.]uk | Email address | Sender email address used to send out emails |
| info@lifeones[.]com | Email address | Sender email address used to send out emails |

**Lure artifacts cited in the article narrative (not IOC-table entries):**

| Indicator | Type | Description |
|---|---|---|
| "ServiceNow Platform — Annual Subscription" | Invoice title | Fabricated vendor invoice |
| "due bill", "ACH Parment" | Subject keywords | Financial lure subjects (note the misspelling) |
| ~$50,000 ACH | Amount | Requested payment size |
| "no need to copy me" | Phrase | Fake forwarded-thread tell |

---

## Query 1: Invoice-fraud campaign IOC sweep — senders, look-alike domains, URLs, clicks and outbound replies

**Purpose:** Matches the published sender addresses, the ServiceNow look-alike and the Reply-To domain across inbound sender fields (header and envelope), email URLs, Safe Links clicks and — critically — **outbound mail to the IOC addresses or domains**, which would mean someone replied to the fraudster. A clean result is 0 rows.  
**Severity:** High  
**MITRE:** T1566, T1656, T1657

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Executive-impersonation invoice fraud IOC match for {{Recipient}}"
impactedAssets:
  - type: mailbox
    identifier: recipientEmailAddress
    column: Recipient
recommendedActions: "A message from or to a published invoice-fraud indicator was observed. Quarantine related messages via Threat Explorer, block the domains and senders in the Tenant Allow/Block List, and contact the recipient and accounts payable to confirm no payment was initiated. If an outbound reply exists, treat it as active engagement: freeze any pending payment to the requested account and notify the bank."
adaptation_notes: "IOC union - for CD, deploy the EmailEvents branches as single-table rules (inbound sender match and outbound-reply match), projecting Timestamp, NetworkMessageId, ReportId and RecipientEmailAddress. Validated: 0 rows over 30 days in AH, and 0 rows in EmailEvents/EmailUrlInfo from 2026-07-25 onward (covering the Aug 3-5 campaign) in the Sentinel Data Lake. Sender addresses are abused third-party email service accounts and will rotate."
-->

```kql
let lookback = 30d;
let IOC_Domains = dynamic(["service-nowinc.com", "domainlify.net"]);
let IOC_Senders = dynamic(["gomez@service-nowinc.com", "notifications@uinsure.co.uk", "info@tivityhealth.com", "no-reply@lumalisboa.com", "noreply@mctci.com", "info@nuf.co.jp",
  "info@lohnsteuerhilfe-aktuell-verein.de", "info@tovimbatista.pt", "contact@eemusicclass.co.uk", "info@lifeones.com"]);
union isfuzzy=true
(EmailEvents | where Timestamp > ago(lookback)
 | where SenderFromAddress in~ (IOC_Senders) or SenderMailFromAddress in~ (IOC_Senders) or SenderFromDomain in~ (IOC_Domains) or SenderMailFromDomain in~ (IOC_Domains)
 | project Timestamp, Source = "EmailEvents sender", Indicator = coalesce(SenderFromAddress, SenderMailFromAddress), Recipient = RecipientEmailAddress, Subject, Detail = strcat(DeliveryAction, "/", LatestDeliveryLocation, " | ", ThreatTypes), NetworkMessageId),
(EmailUrlInfo | where Timestamp > ago(lookback) | where UrlDomain has_any (IOC_Domains) or Url has_any (IOC_Domains)
 | project Timestamp, Source = "EmailUrlInfo", Indicator = Url, Recipient = "", Subject = "", Detail = UrlLocation, NetworkMessageId),
(EmailEvents | where Timestamp > ago(lookback) | where EmailDirection == "Outbound" | where RecipientDomain in~ (IOC_Domains) or RecipientEmailAddress in~ (IOC_Senders)
 | project Timestamp, Source = "Outbound reply to IOC", Indicator = RecipientEmailAddress, Recipient = SenderFromAddress, Subject, Detail = DeliveryAction, NetworkMessageId),
(UrlClickEvents | where Timestamp > ago(lookback) | where Url has_any (IOC_Domains)
 | project Timestamp, Source = "URL click", Indicator = Url, Recipient = AccountUpn, Subject = "", Detail = ActionType, NetworkMessageId)
| order by Timestamp desc
```

**Expected results:** 0 rows. Any **"Outbound reply to IOC"** row is the most urgent: a user has engaged the fraudster, so contact finance before any payment clears. For retrospective coverage of the August 3–5 wave, run the `EmailEvents` and `EmailUrlInfo` branches in the Sentinel Data Lake with `TimeGenerated`.

---

## Query 2: External mail using one of your executives' display names (CEO/CFO/President impersonation)

**Purpose:** The actor put the **recipient company's own executive** in the sender display name. Builds the executive list from `IdentityInfo` (job titles matching CEO, CFO, COO, President, Founder, Chair, Managing Director, General Counsel, Treasurer, Controller). It finds inbound mail whose display name **exactly equals** an executive's name — or contains an executive title — sent from an address that isn't that executive's. The tenant's own domain family is ranked `Low`; `High` requires an external domain plus a finance-lure subject or first contact.  
**Severity:** High  
**MITRE:** T1656, T1036, T1566

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-sender aggregation with IdentityInfo and tenant-domain derivation - hunting query. CD path: a row-level variant (drop the summarize; project Timestamp, NetworkMessageId, ReportId, RecipientEmailAddress) filtered to Priority High is viable once simulation senders are listed. Tuning, validated in a live tenant: the first pass returned 762 messages from 9 senders, all Attack Simulation Training or tenant-owned relay subdomains. Deriving the tenant's own domain family moved 161 messages to Low; the remaining Medium rows were two simulation sender domains, which belong in SimulationSenderDomains. Tightening the finance regex ('overdue' no longer matches training lures) removed all previous High rows."
-->

```kql
let lookback = 30d;
let ExecTitleRegex = @"(?i)\b(chief|ceo|cfo|coo|cto|cio|ciso|president|founder|chair(man|woman|person)?|managing director|general counsel|treasurer|controller)\b";
let FinanceLure = @"(?i)(invoice|\bach\b|wire|remit|payment|parment|due bill|past due|overdue (invoice|payment|bill|balance)|bank detail|funds transfer|subscription|payable)";
let SimulationSenderDomains = dynamic([]); // add verified phishing-simulation sender domains here
let Executives = IdentityInfo
| where Timestamp > ago(14d)
| summarize arg_max(Timestamp, AccountDisplayName, JobTitle, AccountUpn, EmailAddress) by AccountObjectId
| where JobTitle matches regex ExecTitleRegex and isnotempty(AccountDisplayName)
| project ExecName = tolower(trim(" ", AccountDisplayName)), ExecTitle = JobTitle, ExecUpn = tolower(AccountUpn), ExecMail = tolower(EmailAddress);
let ExecNames = toscalar(Executives | summarize make_set(ExecName));
let ExecAddresses = toscalar(Executives | summarize u = make_set(ExecUpn), m = make_set(ExecMail) | project a = array_concat(u, m));
let TenantDomains = toscalar(EmailEvents | where Timestamp > ago(7d) | where EmailDirection == "Inbound" | summarize make_set(tolower(RecipientDomain), 500));
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| extend DisplayLower = tolower(trim(" ", SenderDisplayName)), FromDomain = tolower(SenderFromDomain)
| extend NameMatch = DisplayLower in (ExecNames), TitleInName = SenderDisplayName matches regex ExecTitleRegex
| where NameMatch or TitleInName
| where not(tolower(SenderFromAddress) in (ExecAddresses))
| where not(FromDomain in (SimulationSenderDomains))
| extend TD = TenantDomains
| mv-apply td = TD to typeof(string) on (summarize OwnDomainFamily = max(toint(FromDomain == td or FromDomain endswith strcat(".", td))))
| extend FinanceSubject = Subject matches regex FinanceLure,
         EnvelopeMismatch = tolower(SenderMailFromDomain) != FromDomain,
         StillInMailbox = LatestDeliveryLocation in~ ("Inbox/folder", "Junk folder")
| extend Priority = case(NameMatch and OwnDomainFamily == 0 and (FinanceSubject or IsFirstContact), "High",
                         NameMatch and OwnDomainFamily == 0, "Medium",
                         TitleInName and FinanceSubject and OwnDomainFamily == 0, "Medium", "Low")
| summarize Messages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress), SampleRecipients = make_set(RecipientEmailAddress, 5), Subjects = make_set(Subject, 5),
    FinanceSubjects = countif(FinanceSubject), FirstContact = countif(IsFirstContact), EnvelopeMismatch = max(toint(EnvelopeMismatch)), StillInMailbox = dcountif(NetworkMessageId, StillInMailbox),
    Threats = make_set_if(ThreatTypes, isnotempty(ThreatTypes), 3), Priority = take_any(Priority), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by SenderDisplayName, SenderFromAddress, FromDomain, NameMatch, TitleInName, OwnDomainFamily
| extend PriorityRank = case(Priority == "High", 1, Priority == "Medium", 2, 3)
| order by PriorityRank asc, Recipients desc
| project-away PriorityRank
| project SenderDisplayName, SenderFromAddress, FromDomain, Priority, Messages, Recipients, FinanceSubjects, StillInMailbox
```

**Expected results:** In a well-tuned tenant, `High` rows are rare and serious: your executive's name on a message from an unrelated external domain with an invoice or payment subject. Quarantine it, check `StillInMailbox`, and use Query 5 to see whether anyone replied. Configure **user impersonation protection** for these executives in the Defender for Office 365 anti-phishing policy.

---

## Query 3: Finance-lure mail from external senders to finance, AP and treasury recipients

**Purpose:** The campaign targeted accounts payable. Finds inbound external mail with a financial-lure subject (invoice, ACH, wire, remittance, payment, the article's misspelled "Parment", "due bill", bank details, subscription, payable) delivered to **finance staff** (by `IdentityInfo` department or title) or **finance role mailboxes** (ap@, accountspayable@, invoices@, billing@, treasury@, payments@, payroll@…). Each sender is scored on first contact, header/envelope domain mismatch (typical of third-party email services), a body with no link or attachment (the invoice is inline HTML), a DMARC result other than pass, and any Defender verdict.  
**Severity:** Medium  
**MITRE:** T1566, T1566.003, T1657

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-sender scored aggregation with IdentityInfo - hunting query. Legitimate vendor invoices share these subjects, so the Score (first contact, envelope mismatch, no link or attachment, DMARC not pass, threat verdict) and StillInMailbox drive priority. Validated: 0 rows over 30 days after tuning. A pre-tuning run matched one simulation 'Overdue Annual Compliance Training' email to a finance user; the tightened lure regex removed it. Tune the department and title keywords and the role-mailbox regex to your organization."
-->

```kql
let lookback = 30d;
let FinanceLure = @"(?i)(invoice|\bach\b|wire|remit|payment|parment|due bill|past due|overdue (invoice|payment|bill|balance)|bank detail|funds transfer|subscription|payable)";
let FinanceRoleMailboxes = @"(?i)^(ap|accountspayable|accounts\.payable|accounts-payable|payables|invoice|invoices|billing|finance|treasury|payments|payroll|ar|receivables)@";
let SimulationSenderDomains = dynamic([]); // add verified phishing-simulation sender domains here
let FinanceUsers = IdentityInfo
| where Timestamp > ago(14d)
| summarize arg_max(Timestamp, Department, JobTitle) by AccountObjectId
| where Department has_any ("Finance", "Accounting", "Accounts Payable", "Treasury", "Procurement", "Purchasing")
     or JobTitle has_any ("Accounts Payable", "Accountant", "Controller", "Treasur", "Finance", "Payroll", "Procurement", "Billing")
| distinct AccountObjectId;
let TenantDomains = toscalar(EmailEvents | where Timestamp > ago(7d) | where EmailDirection == "Inbound" | summarize make_set(tolower(RecipientDomain), 500));
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where Subject matches regex FinanceLure
| where RecipientObjectId in (FinanceUsers) or RecipientEmailAddress matches regex FinanceRoleMailboxes
| extend FromDomain = tolower(SenderFromDomain), MailFromDomain = tolower(SenderMailFromDomain)
| where not(FromDomain in (SimulationSenderDomains))
| extend TD = TenantDomains
| mv-apply td = TD to typeof(string) on (summarize OwnDomainFamily = max(toint(FromDomain == td or FromDomain endswith strcat(".", td))))
| where OwnDomainFamily == 0
| extend Auth = parse_json(AuthenticationDetails)
| extend DmarcResult = tostring(Auth.DMARC), EnvelopeMismatch = MailFromDomain != FromDomain,
         NoLinkNoAttachment = UrlCount == 0 and AttachmentCount == 0,
         StillInMailbox = LatestDeliveryLocation in~ ("Inbox/folder", "Junk folder")
| extend Score = toint(IsFirstContact) + toint(EnvelopeMismatch) + toint(NoLinkNoAttachment) + toint(DmarcResult !in~ ("pass", "bestguesspass")) + toint(isnotempty(ThreatTypes))
| summarize Messages = dcount(NetworkMessageId), Recipients = make_set(RecipientEmailAddress, 10), RecipientCount = dcount(RecipientEmailAddress),
    Subjects = make_set(Subject, 5), DisplayNames = make_set(SenderDisplayName, 5), MailFromDomains = make_set(MailFromDomain, 5), SenderIPs = make_set(SenderIPv4, 5),
    MaxScore = max(Score), FirstContact = max(toint(IsFirstContact)), StillInMailbox = dcountif(NetworkMessageId, StillInMailbox), Threats = make_set_if(ThreatTypes, isnotempty(ThreatTypes), 3),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by SenderFromAddress, FromDomain
| extend Priority = case(MaxScore >= 3 and StillInMailbox > 0, "High", MaxScore >= 2, "Medium", "Low")
| order by Priority asc, RecipientCount desc
```

**Expected results:** Real vendors appear here routinely. `High` means a first-contact sender whose envelope domain differs from the header domain (a third-party email service), with no link or attachment, still sitting in an AP mailbox. Confirm payment requests out of band using a vendor contact already on file, **never** the details in the message.

---

## Query 4: Vendor look-alike domains in sender, envelope or URL (the `service-nowinc` pattern)

**Purpose:** The actor registered `service-nowinc[.]com` to pose as ServiceNow. Extracts the registrable domain from inbound header senders, envelope senders and email URLs, strips hyphens and underscores, and flags domains containing a **vendor brand** (ServiceNow, DocuSign, Salesforce, Workday, Adobe, Intuit/QuickBooks, PayPal, Stripe, Bill.com, Coupa, Ariba, NetSuite, Oracle, Microsoft, Amazon, FedEx…) that aren't the vendor's legitimate domains. Short brands (Zoom, Slack, Okta, AWS, DHL, UPS, SAP) must appear as a label **prefix**. Look-alikes used as the **sender** of inbound mail rank `High`.  
**Severity:** Medium  
**MITRE:** T1583.001, T1656, T1036

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Brand-token heuristic over three domain sources - hunting query. Tuning, validated in a live tenant: the first pass surfaced legitimate vendor infrastructure (microsoftonline.com, microsoftexperts.com, onmicrosoft.com, awstrack.me, awsstatic.com, sharepointonline.com, media-amazon.com, slackhq.com, slack-edge.com, awscloud.com) and short-token noise (image-upscaling, ttcoups); these are now handled by LegitRoots and the short-brand prefix rule. The four remaining rows were Attack Simulation Training landing pages in intra-org simulation mail, including a ServiceNow look-alike - correctly Low. Add the vendors you actually pay to LongBrands and LegitRoots."
-->

```kql
let lookback = 30d;
let LongBrands = dynamic(["servicenow", "docusign", "salesforce", "workday", "adobe", "intuit", "quickbooks", "paypal", "stripe", "billcom", "coupa", "ariba", "netsuite", "oracle", "atlassian", "dropbox", "microsoft", "office365", "sharepoint", "amazon", "fedex"]);
let ShortBrands = dynamic(["zoom", "slack", "okta", "aws", "dhl", "ups", "sap"]); // matched only as a label prefix to limit noise
let LegitRoots = dynamic(["servicenow.com", "service-now.com", "servicenowservices.com", "docusign.com", "docusign.net", "salesforce.com", "force.com", "workday.com", "myworkday.com", "adobe.com", "adobesign.com", "intuit.com", "quickbooks.com", "paypal.com", "stripe.com", "bill.com", "coupa.com", "coupahost.com", "ariba.com", "netsuite.com", "oracle.com", "zoom.us", "zoom.com", "atlassian.com", "atlassian.net", "slack.com", "slackhq.com", "slack-edge.com", "dropbox.com", "microsoft.com", "microsoftonline.com", "onmicrosoft.com", "microsoftexperts.com", "office365.com", "office.com", "sharepoint.com", "sharepointonline.com", "okta.com", "amazon.com", "media-amazon.com", "amazonaws.com", "amazonses.com", "aws.com", "awstrack.me", "awsstatic.com", "awscloud.com", "fedex.com", "dhl.com", "ups.com", "sap.com"]);
let Msg = EmailEvents
| where Timestamp > ago(lookback)
| project NetworkMessageId, EmailDirection, Subject, RecipientEmailAddress, SenderFromAddress, SenderFromDomain = tolower(SenderFromDomain), SenderMailFromDomain = tolower(SenderMailFromDomain), DeliveryAction, LatestDeliveryLocation, ThreatTypes;
let Domains = union
(Msg | project NetworkMessageId, Domain = SenderFromDomain, Role = "From"),
(Msg | project NetworkMessageId, Domain = SenderMailFromDomain, Role = "MailFrom"),
(EmailUrlInfo | where Timestamp > ago(lookback) | project NetworkMessageId, Domain = tolower(UrlDomain), Role = "URL");
Domains
| where isnotempty(Domain)
| extend Labels = split(Domain, ".")
| extend RootLabel = tostring(Labels[array_length(Labels) - 2])
| extend Root = strcat(RootLabel, ".", tostring(Labels[array_length(Labels) - 1]))
| where not(Root in (LegitRoots))
| extend RootFlat = replace_string(replace_string(RootLabel, "-", ""), "_", "")
| mv-apply b = LongBrands to typeof(string) on (where RootFlat contains b | summarize LongBrand = take_any(b))
| mv-apply s = ShortBrands to typeof(string) on (where RootFlat startswith s | summarize ShortBrand = take_any(s))
| extend Brand = coalesce(LongBrand, ShortBrand)
| where isnotempty(Brand)
| join kind=inner Msg on NetworkMessageId
| summarize Messages = dcount(NetworkMessageId), Roles = make_set(Role), Directions = make_set(EmailDirection), Recipients = dcount(RecipientEmailAddress),
    Senders = make_set(SenderFromAddress, 5), Subjects = make_set(Subject, 5), Delivered = dcountif(NetworkMessageId, DeliveryAction == "Delivered"),
    StillInMailbox = dcountif(NetworkMessageId, LatestDeliveryLocation in~ ("Inbox/folder", "Junk folder")), Threats = make_set_if(ThreatTypes, isnotempty(ThreatTypes), 3)
    by Root, Brand
| extend SenderSpoof = set_has_element(Roles, "From") or set_has_element(Roles, "MailFrom"), Inbound = set_has_element(Directions, "Inbound")
| extend Priority = case(SenderSpoof and Inbound, "High", Inbound and StillInMailbox > 0, "Medium", "Low")
| order by Priority asc, Messages desc
```

**Expected results:** A short list. A look-alike of a vendor you actually pay, used as an inbound **sender** (as `service-nowinc[.]com` was for the fake ServiceNow President), is the campaign pattern. Check the domain's registration date (the actor's was days old), block it, and alert accounts payable to that vendor's name.

---

## Query 5: Users replying to finance lures at a different or never-before-contacted domain (Reply-To divergence)

**Purpose:** The fraud only works if someone answers. The actor's Reply-To (`domainlify[.]net`) differed from the sending address, so a victim's reply goes to a **different domain** from the one the lure came from. It matches delivered inbound finance-lure messages to the recipient's **outbound** messages with the same normalized subject (RE:/FW: stripped) within seven days, and flags replies whose recipient domain differs from the lure's sender domain and/or **wasn't contacted by the organization in the prior 23 days**.  
**Severity:** High  
**MITRE:** T1656, T1657

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Inbound-to-outbound subject correlation with a domain baseline - hunting or Sentinel analytics rule. Validated: 6 correlated replies over 30 days in the validation tenant, all users answering Attack Simulation Training 'Request for Invoice Access' lures at the same simulation domain (Low: no divergence, known domain). No divergent or new-domain replies. Subject normalization strips common reply/forward prefixes in several languages; extend it if your mail clients add others. A High row warrants an immediate call to finance."
-->

```kql
let lookback = 30d;
let replyWindow = 7d;
let FinanceLure = @"(?i)(invoice|\bach\b|wire|remit|payment|parment|due bill|past due|overdue (invoice|payment|bill|balance)|bank detail|funds transfer|subscription|payable)";
let Normalize = (s:string) { trim(" ", replace_regex(tolower(s), @"^((re|fw|fwd|aw|wg|sv|tr)\s*:\s*)+", "")) };
let Lures = EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where Subject matches regex FinanceLure
| extend Key = Normalize(Subject), LureDomain = tolower(SenderFromDomain), Victim = tolower(RecipientEmailAddress)
| where strlen(Key) >= 6
| project LureTime = Timestamp, Victim, Key, LureSubject = Subject, LureSender = SenderFromAddress, LureDisplayName = SenderDisplayName, LureDomain, LureNetworkMessageId = NetworkMessageId, IsFirstContact;
let KnownOutboundDomains = EmailEvents
| where Timestamp between (ago(30d) .. ago(replyWindow))
| where EmailDirection == "Outbound"
| distinct RecipientDomain = tolower(RecipientDomain);
let Replies = EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Outbound"
| extend Key = Normalize(Subject), Victim = tolower(SenderFromAddress), ReplyDomain = tolower(RecipientDomain)
| project ReplyTime = Timestamp, Victim, Key, ReplySubject = Subject, ReplyTo = RecipientEmailAddress, ReplyDomain, AttachmentCount, UrlCount;
Lures
| join kind=inner Replies on Victim, Key
| where ReplyTime between (LureTime .. (LureTime + replyWindow))
| join kind=leftouter (KnownOutboundDomains | extend KnownDomain = true) on $left.ReplyDomain == $right.RecipientDomain
| extend ReplyToDiverges = ReplyDomain != LureDomain, NewReplyDomain = isnull(KnownDomain)
| extend Priority = case(ReplyToDiverges and NewReplyDomain, "High", ReplyToDiverges or NewReplyDomain, "Medium", "Low")
| project LureTime, ReplyTime, Victim, Priority, LureSubject, LureDisplayName, LureSender, LureDomain, ReplyTo, ReplyDomain, ReplyToDiverges, NewReplyDomain, IsFirstContact, AttachmentCount, UrlCount, LureNetworkMessageId
| order by Priority asc, ReplyTime desc
```

**Expected results:** 0 `High` rows normally. A finance user replying to "invoice approved" mail at a brand-new domain that isn't the lure's sender is exactly how this fraud progresses. Pull the thread in Threat Explorer, block the reply domain, contact the user and AP, and tell the bank if a transfer was requested or sent.

---

## Query 6: Defender for Office 365 alerts and post-delivery outcomes on finance-lure mail

**Purpose:** Microsoft's coverage for this campaign is Defender for Office 365 spam/malicious verdicts, post-delivery removal and ZAP. Joins Defender for Office 365 alerts (excluding DLP policy matches) to finance-lure messages through alert evidence, and reports per sender how many recipients got the message, how many copies are **still in a mailbox**, and how many were remediated. It shows whether ZAP and post-delivery actions closed the exposure.  
**Severity:** Medium  
**MITRE:** T1566, T1657

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Alert-correlation and exposure report over existing Defender for Office 365 alerts; re-alerting would duplicate them. Validated: executed cleanly with 0 rows after tuning. A pre-tuning run returned DLP policy matches on internal invoice emails and simulation-training alerts caught by the broad 'overdue' keyword; excluding DLP titles and tightening the lure regex removed both. Treat StillInMailbox > 0 as an action item."
-->

```kql
let lookback = 30d;
let FinanceLure = @"(?i)(invoice|\bach\b|wire|remit|payment|parment|due bill|past due|overdue (invoice|payment|bill|balance)|bank detail|funds transfer|subscription|payable)";
AlertInfo
| where Timestamp > ago(lookback)
| where ServiceSource =~ "Microsoft Defender for Office 365"
| where not(Title startswith "DLP policy")
| join kind=inner (AlertEvidence | where Timestamp > ago(lookback) | where EntityType == "MailMessage" and isnotempty(NetworkMessageId) | project AlertId, NetworkMessageId) on AlertId
| join kind=inner (
    EmailEvents | where Timestamp > ago(lookback)
    | where Subject matches regex FinanceLure
    | project NetworkMessageId, Subject, SenderFromAddress, SenderDisplayName, SenderFromDomain, RecipientEmailAddress, EmailDirection, DeliveryAction, LatestDeliveryLocation, LatestDeliveryAction, IsFirstContact
  ) on NetworkMessageId
| summarize Alerts = dcount(AlertId), AlertTitles = make_set(Title, 5), Messages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress),
    Subjects = make_set(Subject, 5), Directions = make_set(EmailDirection), StillInMailbox = dcountif(NetworkMessageId, LatestDeliveryLocation in~ ("Inbox/folder", "Junk folder")),
    Remediated = dcountif(NetworkMessageId, LatestDeliveryAction has_any ("Removed", "Moved", "Quarantine", "Deleted") or LatestDeliveryLocation in~ ("Quarantine", "Deleted items", "Dropped")),
    FirstAlert = min(Timestamp), LastAlert = max(Timestamp)
    by SenderFromAddress, SenderDisplayName, SenderFromDomain
| extend Priority = case(StillInMailbox > 0, "High", "Medium")
| order by Priority asc, Recipients desc
```

**Expected results:** When a campaign lands, expect rows with high `Remediated` counts. Any `StillInMailbox > 0` means ZAP didn't reach every copy — soft-delete them from Threat Explorer and confirm ZAP is enabled for phish and spam in the anti-spam policies.

---

## General Tuning Notes

1. **IOC refresh.** The sender addresses are abused third-party email service accounts and will change; the look-alike and Reply-To domains were registered days before sending. Refresh Query 1 from Microsoft Defender Threat Intelligence and rely on Queries 2–5 for new waves.

2. **What Advanced Hunting can't see.** The fabricated invoice, the fake forwarded thread and the AI-template tells (HTML comments, `===========` banners, em dashes) live in the message body. Use Threat Explorer, the email entity page and admin submissions for content analysis; these hunts cover headers, identities and behavior.

3. **Make your executives and AP mailboxes explicit.** Queries 2 and 3 derive executives and finance staff from `IdentityInfo`. If titles and departments aren't populated consistently, replace those subqueries with a static list or a Sentinel watchlist of executives and AP / treasury mailboxes.

4. **Separate simulations.** Attack Simulation Training and internal relay subdomains reuse executive names and invoice themes. List verified simulation sender domains in `SimulationSenderDomains` (Queries 2 and 3) instead of weakening the logic.

5. **The reply is the key signal.** Query 5 finds the moment a lure turns into a conversation. Pair it with a finance process control: any change to bank details or any new payee must be verified by phone, using a number already on file.

6. **Prevention.** Enforce SPF, DKIM and DMARC (`p=reject`) for your domains. Enable user and domain impersonation protection for executives and key vendors in the anti-phishing policy, and first-contact safety tips. Enable ZAP, automatic attack disruption and the Advanced Phishing Threshold. Configure connectors carefully so third-party mail doesn't bypass filtering.

7. **CD-readiness summary.** **Query 1 is `cd_ready: true`** (IOC match, split per `EmailEvents` branch for row-level output). **Queries 2–6 are `cd_ready: false`**: they are aggregations, scored heuristics, cross-message correlation or alert correlation. Query 2 documents a row-level CD path. All six queries were executed against live Advanced Hunting, and Query 1 was also run over the campaign window in the Sentinel Data Lake. **Queries 3 and 6 returned 0 rows after tuning**, and no real campaign traffic was present to test the `High` paths of Queries 2–5 against.

---

## References

- Microsoft Threat Intelligence — [Protecting organizations from AI-assisted executive impersonation and invoice fraud (2026-09-10)](https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/)
- Microsoft Learn — [Anti-phishing policies in Microsoft Defender for Office 365 (impersonation protection)](https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about)
- Microsoft Learn — [Zero-hour auto purge (ZAP)](https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge)
- Microsoft Learn — [Configure automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption)
- Microsoft Learn — [Set up DMARC to validate the From address domain](https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure)
- MITRE ATT&CK — [T1656 Impersonation](https://attack.mitre.org/techniques/T1656/)
- MITRE ATT&CK — [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657/)
- MITRE ATT&CK — [T1583.001 Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/)
- MITRE ATT&CK — [T1566 Phishing](https://attack.mitre.org/techniques/T1566/)
- Companion files: [`queries/threat-intelligence/2026-07/email_threat_landscape_q2_2026.md`](../2026-07/email_threat_landscape_q2_2026.md), [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md)
