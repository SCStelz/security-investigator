# ASCII Smuggling — Invisible Unicode Tag Characters for Phishing Filter Evasion — Threat Hunts

**Created:** 2026-09-03  
**Platform:** Microsoft Defender XDR (Advanced Hunting) | Microsoft Sentinel Data Lake (retrospective)  
**Tables:** EmailEvents, EmailUrlInfo  
**Keywords:** ASCII smuggling, Unicode tag characters, Unicode Tags block, U+E0000, U+E007F, U+E0020, TAG SPACE, invisible characters, zero-width space, homoglyph, keyword obfuscation, tokenizer evasion, filter evasion, prompt injection, XPIA, cross-prompt injection, finance lure, business loan phishing, line of credit, advance funding, SBA phishing, disposable sender domains, email marketing platform abuse, ActiveCampaign, click tracking domain, envelope sender pattern, acemlnd, activehosted, bulk sending infrastructure  
**MITRE:** T1566.002, T1027, T1583.001, T1583.006, T1656  
**Domains:** email  
**Timeframe:** Last 30 days (configurable). For retrospective coverage of the campaign's active phase (2026-02-09 → ~2026-05-15), query **Sentinel Data Lake** with an explicit window and `TimeGenerated` — see General Tuning Note 2.  
**Source:** [ASCII smuggling crosses over from AI prompt injection to phishing evasion (2026-09-03)](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/)

---

## Threat Overview

Microsoft researchers observed a **high-volume finance-themed phishing campaign** that abuses **invisible Unicode tag characters** (the Unicode Tags block, **U+E0000–U+E007F**) — a technique popularized by AI **prompt-injection / cross-prompt-injection (XPIA)** research as *"ASCII smuggling."* Crucially, the campaign **inverted** the technique's usual purpose. Rather than hiding instructions *for* an AI model, the operator inserted a single invisible tag character — specifically **U+E0020 (TAG SPACE)** — *inside* high-signal financial lure words to split them apart, so that `funding` was transmitted as `fun⟨U+E0020⟩ding`. To a human recipient the word still reads normally; to a literal string matcher, a regex without invisible-codepoint handling, or an ML/NLP classifier's tokenizer, the familiar keyword no longer appears as a contiguous unit.

The activity was discovered by a hunting signature originally built for **Microsoft Defender for Office 365 prompt injection protection**. Signature hits jumped roughly two orders of magnitude on **February 9, 2026** (from ~21,000 to more than 1.3 million messages in a day), peaked above 2.3 million messages, and sustained a **strict weekday-only cadence** — near-silent every weekend — characteristic of scheduled bulk-sending infrastructure. The high-volume phase persisted about three months and **dropped sharply after May 15, 2026**, with lower residual activity through mid-June.

Roughly **96% of flagged volume** clustered onto ~**148 disposable, finance-themed sender domains** built by recombining a small 28-word vocabulary (`advance`, `boost`, `capital`, `funding`, `guardian`, `loc`, `rocket`, `rush`, …). The mail itself was relayed through infrastructure associated with the **legitimate email-marketing platform ActiveCampaign**, which rewrites outbound links through its own click-tracking domains (`acemlnd[.]com`, `activehosted[.]com`) and uses envelope (P1) senders shaped `em-<digits>.<brand-domain>` plus a shared sending pool (`acems<N>[.]com`, `emsd<N>[.]com`). Microsoft connected the activity to a broader ActiveCampaign-delivered SBA-themed phishing campaign previously documented by Fortra; that campaign predated the adoption of tag characters and continued after they were dropped.

**The defensive upside:** because Unicode tag characters appear so rarely in normal mail, their presence is a **high-confidence, low-false-positive signal**. A technique intended to make messages look *more* benign to ML models instead hands defenders a durable, content-based indicator.

### TTP Summary

| Capability | TTP |
|---|---|
| Keyword / tokenizer evasion | Invisible **U+E0020 (TAG SPACE)** inserted inside finance lure words (`funding` → `fun⟨U+E0020⟩ding`) to break literal matching and sub-word tokenization (T1027) |
| Lure theme | Business loan, line-of-credit, and advance-funding offers; credential-harvesting / fraud funnel (T1566.002) |
| Disposable infrastructure | ~148 finance-themed header (P2) sender domains recombined from a 28-word vocabulary, rotated continuously (T1583.001) |
| Legitimate-service abuse | Mail relayed via a commercial email-marketing platform, inheriting its IP reputation and authentication to complicate reputation-based filtering (T1583.006) |
| Envelope shaping | Per-account envelope subdomains `em-<digits>.<brand-domain>`; shared sending pool `acems<N>[.]com` / `emsd<N>[.]com` (~98.5% of messages) |
| Link laundering | All body links rewritten to platform click-tracking domains `acemlnd[.]com` / `activehosted[.]com` (~99.8% match envelope *or* tracking pattern) |
| Brand pretext | Finance-brand look-alike sender domains lending legitimacy to loan/funding offers (T1656) |
| Operational tempo | Weekday-only bulk sending with near-zero weekend volume — scheduled infrastructure |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **Legitimate tag-character use: subdivision flag emojis** | The flags of **England, Scotland, and Wales** are encoded as a base flag code point **U+1F3F4** followed by an invisible tag-character sequence. A naive "any tag character" rule fires on them. Exclude any string that also contains **U+1F3F4** (Query 2) — this is the single most important tuning step. |
| KQL cannot express supplementary-plane characters as string literals | KQL's `\u` escape is BMP-only and `\U` is rejected. Use a **`matches regex` character class** — `@"[\x{E0000}-\x{E007F}]"` — which RE2 evaluates correctly against supplementary code points. Do **not** try `has`/`contains` with a literal tag character. |
| Assuming the campaign's *body* obfuscation is visible in `EmailEvents` | `EmailEvents` exposes **`Subject`**, not the message body. Tag characters inserted into body copy are **not** hunted by Query 2. Treat Query 2 as a subject-line detector and pair it with sender/infrastructure hunts (Queries 1, 3, 5) for body-only cases. |
| Treating the sending netblock as an IOC | The article explicitly notes the bulk-origin block **173.236.20[.]0/24** is **legitimate space belonging to the abused marketing platform — not an IOC on its own.** Use it only as clustering corroboration; blocking it would break legitimate marketing mail. |
| Treating platform tracking domains as malicious | `acemlnd[.]com` and `activehosted[.]com` are the **legitimate platform's** click-tracking domains and carry substantial benign marketing traffic. Query 4 is a corroboration/pivot hunt, **not** a standalone detection. |
| Hunting only the exact published sender domains | The domains are disposable and rotated continuously; only 20 of ~148 were published. Pair the direct sweep (Query 1) with the vocabulary heuristic (Query 5). |
| Assuming the campaign window is unreachable | The tag-character phase ran **Feb 9 – May 15, 2026**, which is outside the 30-day Advanced Hunting window — but **Sentinel Data Lake retention is configurable up to 12 years**, so that period is normally still queryable there. Run the retrospective sweep in Data Lake over the explicit campaign window rather than assuming a zero in AH means "not present." Adapt `Timestamp` → `TimeGenerated` for Data Lake. |
| Only checking the Tags block | Tag characters are the *novel* choice. The same evasion is long-established with zero-width space (**U+200B**), zero-width non-joiner, no-break space (**U+00A0**), soft hyphens, and homoglyphs. Query 2 includes an optional broadened variant. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Campaign sender-domain sweep (direct IOC)](#query-1-campaign-sender-domain-sweep-direct-ioc) | Investigation | `EmailEvents` |
| 2 | [Unicode Tags-block characters in subject (core technique detector)](#query-2-unicode-tags-block-characters-in-subject-core-technique-detector) | Detection | `EmailEvents` |
| 3 | [Broadened invisible-character and homoglyph separator sweep](#query-3-broadened-invisible-character-and-homoglyph-separator-sweep) | Investigation | `EmailEvents` |
| 4 | [Email-marketing platform envelope shape and click-tracking corrobor...](#query-4-email-marketing-platform-envelope-shape-and-click-tracking-corroboration) | Investigation | `EmailEvents` + `EmailUrlInfo` |
| 5 | [Finance-vocabulary disposable sender-domain heuristic](#query-5-finance-vocabulary-disposable-sender-domain-heuristic) | Investigation | `EmailEvents` |


## IOC Reference

> Published indicators from the Microsoft Threat Intelligence article. **IOCs rot** — this campaign rotated disposable sender domains continuously and the tag-character phase ended around 2026-05-15. Refresh against current Microsoft Threat Intelligence before relying on direct-match sweeps. Domains are defanged in this table; the queries use plain forms.

### Campaign sender domains (top 20 by signature hits, 2026-02-09; ~148 total observed)

| Sender domain | Hits (2026-02-09) |
|---|---|
| guardiangrowthfunding[.]com | 30,442 |
| digitalcapitalboost[.]com | 27,021 |
| thebusinessloanexpress[.]com | 25,048 |
| yourlocfunding[.]com | 24,482 |
| advancefundingboost[.]com | 24,053 |
| guardiancapitalway[.]com | 23,921 |
| harboradvancefunding[.]com | 23,595 |
| unitedfundingwave[.]com | 23,269 |
| directcapitalboost[.]com | 22,875 |
| onlinedirectfinance[.]com | 21,195 |
| catalystcapitalharbor[.]com | 21,130 |
| rocketboostfunding[.]com | 20,908 |
| digitalrushcapital[.]com | 20,796 |
| guardianloccapital[.]com | 20,781 |
| guardianlocchoice[.]com | 20,553 |
| ourbusinessloans[.]com | 20,444 |
| directcapitalpulse[.]com | 19,767 |
| catalystboostfunding[.]com | 19,519 |
| elevatecapitalrush[.]com | 19,395 |
| fundingexpresscapital[.]com | 18,695 |

### Sender-domain vocabulary (all 20 domains above are recombinations of these 28 tokens)

`advance` · `boost` · `business` · `capital` · `catalyst` · `choice` · `digital` · `direct` · `elevate` · `express` · `finance` · `funding` · `growth` · `guardian` · `harbor` · `loan` · `loans` · `loc` · `online` · `our` · `pulse` · `rocket` · `rush` · `the` · `united` · `wave` · `way` · `your`

Additional lure vocabulary named in the narrative: `lend`, `solutions`, `hedge`, `pillar`, `fund`.

### Content and infrastructure patterns

| Indicator | Type | Description |
|---|---|---|
| `U+E0000`–`U+E007F` | Unicode range | Unicode Tags block — the hallmark of ASCII smuggling. **Primary content signal.** |
| `U+E0020` | Unicode code point | TAG SPACE — the specific separator spliced inside lure keywords |
| `U+1F3F4` | Unicode code point | Base flag code point preceding England/Scotland/Wales subdivision flags — **exclusion marker**, not an IOC |
| acemlnd[.]com | Domain | Legitimate email-marketing platform **click-tracking** domain (abused; not malicious per se) |
| activehosted[.]com | Domain | Legitimate email-marketing platform **click-tracking** domain (abused; not malicious per se) |
| `em-<digits>.<brand-domain>` | Envelope (P1) pattern | Per-account envelope subdomain shape; regex `em-\d+\.` — ~98.5% of campaign messages |
| `acems<N>[.]com`, `emsd<N>[.]com` | Envelope (P1) pattern | Platform shared sending pool (e.g. `emsd4[.]com`, `s9.acems10[.]com`) |
| 173.236.20[.]0/24 | Netblock | ~92% of daily volume originated here. **NOT an IOC** — legitimate space belonging to the abused platform. Clustering corroboration only. |

---

## Query 1: Campaign sender-domain sweep (direct IOC)

**Purpose:** Direct-match sweep for the 20 published finance-themed campaign sender domains across both the header (P2) and envelope (P1) sender domains. In an unaffected environment this returns 0; any hit identifies recipients who received campaign mail and the delivery disposition applied.  
**Severity:** Medium  
**MITRE:** T1566.002, T1583.001

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "InitialAccess"
title: "ASCII-smuggling finance phishing sender domain delivered to {{RecipientEmailAddress}}"
impactedAssets:
  - type: mailbox
    identifier: accountUpn
    column: RecipientEmailAddress
recommendedActions: "A message from a published ASCII-smuggling finance-phishing sender domain was observed. Confirm the delivery disposition, purge any message delivered to the inbox via ZAP/manual remediation, and check whether the recipient clicked a tracking link (pivot to Query 4). These sender domains are disposable and rotate continuously - refresh the domain list from current Microsoft Threat Intelligence and pair with the vocabulary heuristic (Query 5) to catch rotated infrastructure."
adaptation_notes: "Single-table EmailEvents, no joins - NRT eligible. High fidelity when it fires, but the published list covers only 20 of ~148 observed domains and the campaign rotates aggressively; value decays without list maintenance. The tag-character phase of this campaign ran 2026-02-09 to approximately 2026-05-15, which is outside the 30-day Advanced Hunting window - run the retrospective sweep in Sentinel Data Lake (retention configurable up to 12 years) over that explicit window, adapting Timestamp to TimeGenerated. As a forward-looking scheduled rule this static list is primarily useful for detecting campaign resumption or reuse of the same domains."
-->

```kql
let CampaignSenderDomains = dynamic([
  "guardiangrowthfunding.com","digitalcapitalboost.com","thebusinessloanexpress.com","yourlocfunding.com",
  "advancefundingboost.com","guardiancapitalway.com","harboradvancefunding.com","unitedfundingwave.com",
  "directcapitalboost.com","onlinedirectfinance.com","catalystcapitalharbor.com","rocketboostfunding.com",
  "digitalrushcapital.com","guardianloccapital.com","guardianlocchoice.com","ourbusinessloans.com",
  "directcapitalpulse.com","catalystboostfunding.com","elevatecapitalrush.com","fundingexpresscapital.com"]);
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromDomain has_any (CampaignSenderDomains)
    or SenderMailFromDomain has_any (CampaignSenderDomains)
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderFromDomain,
    SenderMailFromDomain, SenderDisplayName, SenderIPv4, RecipientEmailAddress, Subject,
    EmailDirection, DeliveryAction, DeliveryLocation, LatestDeliveryAction, LatestDeliveryLocation,
    ThreatTypes, DetectionMethods, ConfidenceLevel, BulkComplaintLevel, AuthenticationDetails, UrlCount, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Because the published domains belong to a phase that ran **2026-02-09 to ~2026-05-15**, a 30-day Advanced Hunting run today cannot reach that period — but **Sentinel Data Lake can**, since its retention is configurable up to 12 years. To actually confirm whether the campaign reached your users, re-run this sweep in Data Lake scoped to the campaign window rather than a relative `ago()`:

```kql
// Sentinel Data Lake retrospective variant - EmailEvents uses TimeGenerated here, not Timestamp
| where TimeGenerated between (datetime(2026-02-09) .. datetime(2026-05-16))
```

Any hit indicates the campaign reached your tenant (retrospective), or — in a present-day window — campaign resumption or reuse of the same disposable domains. Either warrants recipient triage.

---

## Query 2: Unicode Tags-block characters in subject (core technique detector)

**Purpose:** Detects the campaign's defining technique — characters from the Unicode Tags block (**U+E0000–U+E007F**) present in an email subject — while excluding the one routine legitimate use, the England/Scotland/Wales subdivision flag emojis (which are encoded as tag sequences following base flag code point **U+1F3F4**). Because tag characters are otherwise near-absent from normal mail, this is the **highest-value, most durable detection in this file**: it is infrastructure-independent and survives sender-domain rotation.  
**Severity:** Medium  
**MITRE:** T1027, T1566.002

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "DefenseEvasion"
title: "Invisible Unicode tag characters in email subject to {{RecipientEmailAddress}}"
impactedAssets:
  - type: mailbox
    identifier: accountUpn
    column: RecipientEmailAddress
recommendedActions: "An inbound email subject contains characters from the Unicode Tags block (U+E0000-U+E007F) after excluding subdivision flag emojis. This is an extremely rare construct in legitimate mail and indicates either keyword/tokenizer evasion or an attempt to smuggle hidden instructions to an AI assistant that ingests the raw message (XPIA). Inspect the raw subject and body for split lure keywords or hidden instruction text, review the sender's authentication and delivery disposition, and purge if malicious. Expected benign sources are email-security gateways, mailbox providers, and security researchers forwarding test messages - build an allowlist of those senders rather than relaxing the rule."
adaptation_notes: "Single-table EmailEvents, no joins - NRT eligible. Expected volume is very low because Unicode Tags-block characters are near-absent from legitimate mail, which is what makes this a high-precision detector. The U+1F3F4 exclusion is mandatory. Validate the regex mechanism in any new environment by swapping the character class for a commonly-present invisible character (e.g. U+00A0) and confirming it returns rows - this distinguishes a true negative from a broken filter. Note this covers Subject only; EmailEvents does not expose the message body, where this campaign primarily inserted the separator."
-->

```kql
EmailEvents
| where Timestamp > ago(30d)
| where isnotempty(Subject)
// Unicode Tags block (U+E0000-U+E007F) - the ASCII-smuggling hallmark.
// KQL \u escapes are BMP-only, so a RE2 character class is required for these supplementary code points.
| where Subject matches regex @"[\x{E0000}-\x{E007F}]"
// Exclude the one routine legitimate use: England/Scotland/Wales subdivision flag emojis,
// which encode as a tag-character sequence following the base flag code point U+1F3F4.
| where not(Subject matches regex @"\x{1F3F4}")
| extend TagCharCount = countof(Subject, @"[\x{E0000}-\x{E007F}]", "regex")
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderFromDomain,
    SenderMailFromDomain, SenderDisplayName, SenderIPv4, RecipientEmailAddress, Subject, TagCharCount,
    EmailDirection, DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods,
    ConfidenceLevel, BulkComplaintLevel, AuthenticationDetails, UrlCount, ReportId
| sort by Timestamp desc
```

**Expected results:** Near-zero in a healthy environment — this is a deliberately high-precision, low-noise detector. Residual benign hits, if any, are typically email-security gateways, mailbox providers, or security/AI researchers forwarding messages that contain tag characters; allowlist those specific senders rather than weakening the rule. Any *unexplained* hit is high-signal and warrants raw-message inspection for both split lure keywords and hidden AI-directed instructions.

---

## Query 3: Broadened invisible-character and homoglyph separator sweep

**Purpose:** Widens Query 2 beyond the Tags block to the long-established invisible separators used for the same keyword-fracturing purpose — zero-width space (U+200B), zero-width non-joiner (U+200C), zero-width joiner (U+200D), word joiner (U+2060), soft hyphen (U+00AD), no-break space (U+00A0), and the bidirectional control range (U+202A–U+202E). Surfaces the technique class rather than this campaign's specific character choice, and is the right hunt if an operator rotates away from the Tags block.  
**Severity:** Low  
**MITRE:** T1027, T1566.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Hunting/triage query, not detection-ready. The broadened invisible-character set includes code points with legitimate uses in normal mail: U+00A0 (no-break space) is common in HTML-authored subjects and in localized typography such as French number/currency spacing, soft hyphens appear in typeset content, and ZWJ is used in emoji sequences. Expect a routine benign baseline dominated by the NoBreakSoft column, so per-environment baselining and an exclusion list are required before any promotion. Prefer Query 2 (Tags block only) for detection; use this query to characterize the local baseline and to catch technique rotation."
-->

```kql
let InvisibleSeparators = @"[\x{200B}-\x{200D}\x{2060}\x{00AD}\x{00A0}\x{202A}-\x{202E}\x{FEFF}]";
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where isnotempty(Subject)
| where Subject matches regex InvisibleSeparators
    or Subject matches regex @"[\x{E0000}-\x{E007F}]"
| extend
    TagBlockChars   = countof(Subject, @"[\x{E0000}-\x{E007F}]", "regex"),
    ZeroWidthChars  = countof(Subject, @"[\x{200B}-\x{200D}\x{2060}\x{FEFF}]", "regex"),
    NoBreakOrSoft   = countof(Subject, @"[\x{00A0}\x{00AD}]", "regex"),
    BidiControl     = countof(Subject, @"[\x{202A}-\x{202E}]", "regex")
| summarize
    Messages        = count(),
    Recipients      = dcount(RecipientEmailAddress),
    DistinctSubjects= dcount(Subject),
    TagBlock        = sum(TagBlockChars),
    ZeroWidth       = sum(ZeroWidthChars),
    NoBreakSoft     = sum(NoBreakOrSoft),
    Bidi            = sum(BidiControl),
    FirstSeen       = min(Timestamp),
    LastSeen        = max(Timestamp),
    SampleSubject   = any(Subject)
    by SenderFromDomain, SenderMailFromDomain, DeliveryAction, ThreatTypes
| order by Messages desc
```

**Expected results:** A modest baseline dominated by `NoBreakSoft` (no-break space / soft hyphen) from ordinary HTML-authored marketing and localized mail — these are expected and benign. `TagBlock > 0` is the high-signal column and should be treated as Query 2 output. A sender showing a sustained, high `ZeroWidth` count against finance or credential-themed subjects deserves review.

---

## Query 4: Email-marketing platform envelope shape and click-tracking corroboration

**Purpose:** Clusters mail carrying the abused platform's **envelope (P1) shape** — `em-<digits>.<brand-domain>` and the shared sending pool `acems<N>[.]com` / `emsd<N>[.]com` — and joins it to the platform's **click-tracking domains** (`acemlnd[.]com`, `activehosted[.]com`) from `EmailUrlInfo`. Across the measured campaign activity ~98.5% of messages matched the envelope pattern and ~99.8% matched the envelope *or* tracking-URL pattern, making this the strongest **corroboration** pivot once a content or sender signal has already fired.  
**Severity:** Low  
**MITRE:** T1583.006, T1566.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "PROHIBITED as a standalone detection - these are the legitimate envelope and click-tracking patterns of a widely used commercial email-marketing platform, and any organization receiving sanctioned marketing mail will match them heavily. The article is explicit that these are corroboration signals, not IOCs. Also uses a join across EmailEvents and EmailUrlInfo, which disqualifies NRT. Use only as an investigation pivot after Query 1, 2, or 5 fires; if ever promoted, it must be gated on co-occurrence with the Unicode content signal plus the finance-brand sender pattern (the article's stated high-precision combination)."
-->

```kql
let TrackingDomains = dynamic(["acemlnd.com","activehosted.com"]);
let TrackedMessages =
    EmailUrlInfo
    | where Timestamp > ago(30d)
    | where UrlDomain has_any (TrackingDomains) or Url has_any (TrackingDomains)
    | summarize TrackingUrls = count(), SampleTrackingUrl = any(Url) by NetworkMessageId;
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| extend EnvelopeShape = case(
    SenderMailFromDomain matches regex @"(?i)^em-\d+\.",              "PerAccountSubdomain(em-<digits>)",
    SenderMailFromDomain matches regex @"(?i)(^|\.)acems\d+\.",       "SharedPool(acems<N>)",
    SenderMailFromDomain matches regex @"(?i)(^|\.)emsd\d+\.",        "SharedPool(emsd<N>)",
    SenderMailFromDomain has_any (TrackingDomains),                   "PlatformDomain",
    "None")
| join kind=leftouter TrackedMessages on NetworkMessageId
| where EnvelopeShape != "None" or isnotempty(SampleTrackingUrl)
| summarize
    Messages     = count(),
    Recipients   = dcount(RecipientEmailAddress),
    FirstSeen    = min(Timestamp),
    LastSeen     = max(Timestamp),
    ActiveDays   = dcount(bin(Timestamp, 1d)),
    TrackedMsgs  = countif(isnotempty(SampleTrackingUrl)),
    SampleSubject= any(Subject)
    by SenderFromDomain, SenderMailFromDomain, EnvelopeShape, DeliveryAction
| order by Messages desc
```

**Expected results:** Any organization that receives sanctioned marketing mail relayed through this platform will see legitimate rows here — that is normal and **not** an indicator. The campaign-relevant pattern is a *large fan-out of many distinct finance-vocabulary brand domains sharing a small set of reused envelope account numbers*, combined with weekday-only `ActiveDays` clustering. Use this to size and bound an incident after a Query 1/2/5 hit, never as a first-order alert.

---

## Query 5: Finance-vocabulary disposable sender-domain heuristic

**Purpose:** Catches **rotated** campaign infrastructure that the static list in Query 1 misses, by scoring inbound sender domains on how many tokens from the campaign's 28-word finance vocabulary they are assembled from. The observed domains are pure recombinations (e.g. `guardian`+`growth`+`funding`, `catalyst`+`capital`+`harbor`), so a domain root built from **two or more** of these tokens and unseen in the environment's history is a strong candidate for the same generator.  
**Severity:** Low  
**MITRE:** T1583.001, T1656

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Heuristic pattern-matching over sender-domain composition - requires per-environment tuning before any detection use. Legitimate financial-services senders (banks, lenders, brokers, payment providers, and the organization's own finance vendors) will naturally match two or more of these generic English finance tokens and must be allowlisted first. Recommended promotion path: maintain an allowlist of sanctioned financial senders, add a first-seen/newly-observed-domain condition, and require co-occurrence with the Unicode content signal (Query 2) - the article's stated high-precision combination is Unicode content plus finance-brand pattern."
-->

```kql
let FinanceTokenRegex = @"(advance|boost|business|capital|catalyst|choice|digital|direct|elevate|express|finance|funding|growth|guardian|harbor|loans|loan|lend|solutions|hedge|pillar|loc|online|pulse|rocket|rush|united|wave|fund)";
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where isnotempty(SenderFromDomain)
| extend SenderDomainRoot = tolower(tostring(split(SenderFromDomain, ".")[0]))
| extend MatchedTokens = extract_all(FinanceTokenRegex, SenderDomainRoot)
| extend TokenCount = array_length(set_union(MatchedTokens, dynamic([])))
// Two or more distinct finance tokens in the domain root mirrors the campaign's generator.
| where TokenCount >= 2
| summarize
    Messages      = count(),
    Recipients    = dcount(RecipientEmailAddress),
    ActiveDays    = dcount(bin(Timestamp, 1d)),
    FirstSeen     = min(Timestamp),
    LastSeen      = max(Timestamp),
    Tokens        = any(MatchedTokens),
    EnvelopeDomains = make_set(SenderMailFromDomain, 10),
    Dispositions  = make_set(DeliveryAction, 5),
    Verdicts      = make_set(ThreatTypes, 5),
    SampleSubject = any(Subject)
    by SenderFromDomain, TokenCount
| order by TokenCount desc, Messages desc
```

**Expected results:** Legitimate financial institutions and finance-adjacent vendors will appear and should be allowlisted on first review — the value is in what remains. Prioritize domains that are **newly observed**, send in **weekday-only bursts**, have **short `ActiveDays` spans**, and fan out across **many similar sibling domains**. Cross-reference survivors against Query 2 (Unicode content) and Query 4 (envelope shape) before escalating.

---

## General Tuning Notes

1. **IOC refresh.** The 20 sender domains in Query 1 are a published sample of ~148 observed on a single day, and the operator rotated disposable domains continuously. Treat the list as a snapshot: refresh it from current Microsoft Threat Intelligence / VirusTotal before relying on direct matches, and lean on Query 5 for rotated infrastructure.

2. **Time-window reality — and how to actually cover it.** The tag-character phase of this campaign ran **2026-02-09 to ~2026-05-15**. That window is outside the 30-day Advanced Hunting cap, so an AH run today genuinely cannot see it — but **Sentinel Data Lake retention is configurable up to 12 years**, so the period is normally still fully queryable there. **Do not treat an Advanced Hunting zero as proof of absence.** Run the retrospective sweep in Data Lake against the explicit campaign window:

   ```kql
   EmailEvents
   | where TimeGenerated between (datetime(2026-02-09) .. datetime(2026-05-16))
   // ... then apply the Query 1 sender-domain list and/or the Query 2 tag-character regex
   ```

   Remember the platform difference: `EmailEvents` is an XDR-native table, so it uses **`Timestamp` in Advanced Hunting** but **`TimeGenerated` in Data Lake** — leaving `Timestamp` in a Data Lake query returns a `SemanticError`, and using a relative `ago(30d)` silently misses the entire campaign period. Validate any retrospective zero with a positive control over the same window (e.g. count subjects matching a commonly-present invisible character such as U+00A0) to prove the regex engine matched historical data rather than silently failing. The queries additionally retain forward-looking value: the broader campaign continued after the technique was dropped and may readopt it, and the technique is now widely publicized.

3. **The mandatory exclusion.** Any Unicode-Tags-block rule *must* exclude the England/Scotland/Wales subdivision flag emojis (base code point **U+1F3F4** followed by a tag sequence), or it will fire on ordinary mail. This single exclusion is what turns the naive signature into a low-false-positive detector.

4. **KQL supplementary-plane handling.** KQL's `\u` string escape is BMP-only and `\U` is rejected outright, so tag characters cannot be written as string literals. Always match them with a RE2 character class in `matches regex` / `countof(..., "regex")`, e.g. `@"[\x{E0000}-\x{E007F}]"`. This pattern was verified to correctly match a smuggled `fun⟨U+E0020⟩ding` construction, correctly match a Wales-flag sequence, and correctly reject clean text.

5. **Subject-only telemetry gap.** `EmailEvents` exposes `Subject` but not the message body, and this campaign inserted the separator primarily into **body** lure copy. Query 2 therefore detects only the subject-line case. For body coverage, rely on Defender for Office 365's own prompt-injection/obfuscation protections and on the sender/infrastructure hunts (Queries 1, 4, 5). Note this gap explicitly when reporting hunt coverage.

6. **Do not blocklist the abused platform.** `acemlnd[.]com`, `activehosted[.]com`, the `em-<digits>.` envelope shape, and the `173.236.20[.]0/24` netblock all belong to a **legitimate** commercial email-marketing platform. The article is explicit that the netblock is "not an IOC on its own." Blocking any of these would break sanctioned marketing mail. They are clustering and corroboration signals only — which is why Queries 4 and 5 are `cd_ready: false`.

7. **The high-precision combination.** Per the article, the recommended high-precision rule is **Unicode content pattern + finance-brand sender pattern**, using the envelope/tracking/origin patterns as corroboration. Operationally: alert on Query 2, enrich with Query 5, corroborate with Query 4.

8. **Verify your own normalization pipeline.** The strategic takeaway is a possible detection blind spot: because the Tags block is less commonly abused than zero-width space or NBSP, confirm that your mail-filtering normalization and tokenization steps strip or normalize **U+E0000–U+E007F** consistently. Query 3 helps characterize which invisible-character classes actually reach your users.

9. **CD-readiness summary.** **Queries 1 and 2 are `cd_ready: true`** (single-table `EmailEvents`, no joins, NRT-eligible), with **Query 2 the recommended promotion** — it is infrastructure-independent, survives domain rotation, and targets a construct that is near-absent from legitimate mail. **Queries 3, 4, and 5 are `cd_ready: false`**: Query 3 matches invisible characters with legitimate uses, and Queries 4 and 5 match legitimate marketing-platform infrastructure and legitimate financial senders respectively. All five queries were authored and executed against live Microsoft Defender Advanced Hunting telemetry during development, and the Query 1/2/4 detection logic was additionally executed in Sentinel Data Lake against the campaign's actual active window (2026-02-09 → 2026-05-15) per Note 2, with invisible-character positive controls confirming the regex matched historical data.

---

## References

- Microsoft Threat Intelligence — [ASCII smuggling crosses over from AI prompt injection to phishing evasion (2026-09-03)](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/)
- MITRE ATT&CK — [T1566.002 Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- MITRE ATT&CK — [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- MITRE ATT&CK — [T1583.001 Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/)
- MITRE ATT&CK — [T1583.006 Acquire Infrastructure: Web Services](https://attack.mitre.org/techniques/T1583/006/)
- MITRE ATT&CK — [T1656 Impersonation](https://attack.mitre.org/techniques/T1656/)
- MITRE ATLAS — [AML.T0051 LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051) (the technique's origin context; not an ATT&CK Enterprise ID)
- Unicode — [Unicode Tags block (U+E0000–U+E007F)](https://www.unicode.org/charts/PDF/UE0000.pdf)
- Microsoft Learn — [Zero-hour auto purge (ZAP) in Defender for Office 365](https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge)
- Companion files: [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md), [`queries/threat-intelligence/2026-06/ai_brands_as_bait_social_engineering.md`](../2026-06/ai_brands_as_bait_social_engineering.md)
