# AI Brands as Bait — Social Engineering Threat Hunts

**Created:** 2026-06-12  
**Platform:** Microsoft Defender XDR  
**Tables:** EmailEvents, EmailAttachmentInfo, UrlClickEvents, DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceImageLoadEvents, DeviceFileCertificateInfo, AADUserRiskEvents  
**Keywords:** AI brand impersonation, ChatGPT lure, Claude lure, DeepSeek lure, Copilot lure, OpenAI, Anthropic, malvertising, SEO poisoning, fake AI installer, GitHub release abuse, Vidar stealer, Lumma stealer, GhostSocks, Hijack Loader, Oyster, Python loader, pythonw.exe, code-signing abuse, Fox Tempest, Storm-3075, MSaaS, AiTM, anomalous token, phishing kit, credit card harvesting  
**MITRE:** T1566.001, T1566.002, T1656, T1204.001, T1204.002, T1608.006, T1583.001, T1588.003, T1553.002, T1059.006, T1105, T1071.001, T1539, T1557, T1555, TA0001, TA0002, TA0011  
**Domains:** email, endpoint, identity  
**Timeframe:** Last 30 days (configurable)  
**Source:** [AI brands as bait: How threat actors are using the AI hype in social engineering (2026-06-08)](https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-the-ai-hype-in-social-engineering/)

---

## Threat Overview

Microsoft Threat Intelligence reports a growing wave of campaigns that **impersonate the branding of popular AI platforms** (ChatGPT, Microsoft Copilot, DeepSeek, Anthropic's Claude) as social-engineering lures. The activity is **pure brand abuse — not a compromise of any referenced vendor** — and spans phishing, malvertising, and SEO-driven attacks that lead to credential theft, financial fraud, or malware infection. Microsoft attributes the malvertising thread to the initial access broker **Storm-3075**, which delivers payloads (Vidar, Lumma, Hijack Loader, Oyster) on behalf of downstream actors, frequently using malware code-signed via the malware-signing-as-a-service (MSaaS) operation attributed to **Fox Tempest**.

Four concrete campaigns are detailed: (1) a **ChatGPT-themed phishing kit** harvesting credit-card data via a multi-hop redirect chain through abused legitimate services; (2) a **Claude-themed AiTM phishing** campaign using a PDF "appeal form" attachment leading to token theft; (3) **"Awesome AI Windows Plugin" / "Flux Pro AI" malvertising** that drops a signed `ProFluxeFlowAi-win-Setup.exe`, which launches a Python downloader and pulls Vidar from C2; and (4) **fake DeepSeek V4 installers** hosted on a fraudulent GitHub org/repo, discovered via SEO and LLM-aware `llms.txt` poisoning, delivering a shared loader observed under many rotating AI-brand filenames.

### TTP Summary
| Capability | TTP |
|---|---|
| AI-brand display-name / subject impersonation in inbound email | T1656 Impersonation, T1566.001/.002 Phishing |
| PDF "appeal form" attachment initiating credential-harvest chain | T1566.001 Spearphishing Attachment, T1204.002 User Execution |
| Multi-hop redirect chain through abused legitimate services (CRM, awstrack, Rebrandly) | T1566.002, T1204.001 Malicious Link |
| CAPTCHA / "Continue"-checkmark gating to evade sandbox detonation | Defense evasion (anti-analysis) |
| AiTM landing pages intercepting auth tokens / session cookies | T1557 Adversary-in-the-Middle, T1539 Steal Web Session Cookie |
| Malvertising + SEO/LLM poisoning to deliver fake AI installers | T1608.006 SEO Poisoning, T1583.001 Acquire Infrastructure: Domains |
| Fake GitHub org/repo + release-asset CDN abuse for `.7z`/`.exe` payloads | T1204.002 User Execution: Malicious File |
| Code-signing of malware via Fox Tempest MSaaS | T1588.003 Obtain Code-Signing Certs, T1553.002 Code Signing |
| Python-based downloader dropped to `%AppData%\Local` (`pythonw.exe` + `LICENSE.txt`) running shellcode | T1059.006 Python, T1105 Ingress Tool Transfer |
| C2 retrieval of Vidar infostealer | T1071.001 Web Protocols, T1555 Credentials from Stores |

### ⚠️ Hunt Pitfalls
| Pitfall | Mitigation |
|---|---|
| **Legitimate AI-vendor mail is a false positive** for brand-keyword email hunts (e.g., genuine `openai.com` notifications) | Exclude known vendor sending domains via an allowlist; pair brand keyword with an action/urgency theme; review verdict + auth results |
| IOCs from the article (Mar–May 2026) **predate the 30-day Advanced Hunting window** | A 0-row result on direct IOC sweeps is the **expected clean outcome**; for retrospective coverage re-run hash/domain sweeps in Sentinel Data Lake (90d) |
| Lure filenames **rotate constantly** (DeepSeek → GPT-5.5 → Claude Code → Kimi → Seedance, etc.) | Treat the lure-name list as seed values; maintain/extend it; prefer the shared loader hash and behavioral signals over any single name |
| `pythonw.exe` from `%AppData%` can be **legitimate** for some packaged Python apps | Correlate with recent archive/installer download, suspicious parent, and `.txt`-as-script command lines before alerting |
| `SHA256` is frequently unpopulated on `Device*`/`Email*` tables | Pivot to `SHA1` when available; the IOC table below provides SHA-256 — resolve SHA-1 via Defender file page / MDTI when sweeping endpoints |
| Brand impersonation often arrives **fully authenticated** (abused ESPs / display-name-only spoof) | Do not rely on SPF/DKIM/DMARC failures alone; weight display-name-vs-domain mismatch and lure theme |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [AI-Brand Impersonation Phishing Lure (Inbound Email)](#query-1-ai-brand-impersonation-phishing-lure-inbound-email) | Investigation | `EmailEvents` |
| 2 | [Claude Appeal PDF — Attachment Hash & Name Sweep](#query-2-claude-appeal-pdf--attachment-hash--name-sweep) | Investigation | `EmailAttachmentInfo` |
| 3 | [Malicious URL Clicks to Campaign Infrastructure](#query-3-malicious-url-clicks-to-campaign-infrastructure) | Investigation | `UrlClickEvents` |
| 4 | [Fake AI Installer Download (Rotating Lure Filenames)](#query-4-fake-ai-installer-download-rotating-lure-filenames) | Investigation | `DeviceFileEvents` |
| 5 | [Endpoint File-Hash IOC Sweep (Loader & Installer Payloads)](#query-5-endpoint-file-hash-ioc-sweep-loader--installer-payloads) | Investigation | `DeviceFileEvents` + multi |
| 6 | [Python Loader Persistence in %AppData%\Local](#query-6-python-loader-persistence-in-appdatalocal) | Investigation | `DeviceProcessEvents` |
| 7 | [Vidar / Loader C2 Network Connections](#query-7-vidar--loader-c2-network-connections) | Investigation | `DeviceNetworkEvents` |
| 8 | [Fox Tempest Code-Signing Certificate Sweep](#query-8-fox-tempest-code-signing-certificate-sweep) | Investigation | `DeviceFileCertificateInfo` |
| 9 | [Post-Click AiTM Token-Anomaly Correlation](#query-9-post-click-aitm-token-anomaly-correlation) | Detection | `AADUserRiskEvents` + `UrlClickEvents` |


## IOC Reference

> Published indicators transcribed verbatim from the article's "Indicators of compromise" table. **IOCs rot** — operators rotate hashes/domains rapidly (the DeepSeek archive hash rotated three times in three days). Refresh against current Microsoft Defender Threat Intelligence / VirusTotal / your TI indicator table before relying on direct matches.

| Type | Value | Description | First seen | Last seen |
|------|-------|-------------|-----------|-----------|
| SHA-256 | `791efb555eefb7215e96659a1353a97416743b66bdd72705493129c64057d40e` | `Fill and Sign Claude Appeal Form.pdf` attachment | 2026-04-20 | 2026-04-20 |
| URL | `hxxp://dash.awaydouble[.]org/0v2auth` | URL inside the Claude PDF attachment | 2026-04-20 | 2026-04-20 |
| URL | `hxxps://github[.]com/shippingtechnologymovie/AI-techVideos/releases/download/13123/ProFluxeFlowAi-win-Setup.exe` | Fraudulent GitHub repo (taken down) hosting malware | 2026-03-13 | 2026-03-14 |
| SHA-256 | `c7c5072df9f83f4c440a5c3bb4be1d5f6c67bbf78f196406ca20d27b43b975b8` | `ProFluxeFlowAi-win-Setup.exe` | 2026-03-13 | 2026-03-14 |
| SignerSHA-1 | `4f5c5b3ef45cfff7721754487a86aeff9a2e6e32` | Fraudulently obtained code-signing certificate (Fox Tempest MSaaS) | 2026-03-13 | 2026-03-14 |
| Domain | `brokeapt[.]com` | Attacker-controlled C2 for Python loader | 2026-03-10 | 2026-05-20 |
| Domain | `pan.ssffaa19[.]xyz` | Vidar C2 | 2026-03-13 | 2026-03-14 |
| Domain | `pan.rongtv[.]xyz` | Vidar C2 | 2026-03-13 | 2026-03-14 |
| URL | `hxxps://github[.]com/DeepSeek-V4/deepseek-V4/releases/download/deepseek-V4/deepseek-v4-pro_x64.7z` | Fraudulent GitHub repo (taken down) hosting malware | 2026-04-24 | 2026-04-28 |
| SHA-256 | `0a26238f6c516de5885457c93042531aa59bc206a9537cebf5267cedc6c68531` | `deepseek-v4-pro_x64.7z` (v1) | 2026-04-24 | 2026-05-18 |
| SHA-256 | `8610d4fb0ec5b525071c2aaec4df0f8fcbb3673aba58a7e1959fc44e83c0e2ca` | `deepseek-v4-flash_x64.7z` (v1) | 2026-04-24 | 2026-04-28 |
| SHA-256 | `99231deb373997364381d1eb513d2d42231d418c3a2db9007c5af9bd56ab9371` | `deepseek-v4-flash_x64.7z` (v2) | 2026-04-26 | 2026-04-28 |
| SHA-256 | `25270cc429ada8028b5b33220ed412c47907ecceea7377d608fac5af01bed56a` | `deepseek-v4-pro_x64.7z` (v2) | 2026-04-26 | 2026-04-28 |
| SHA-256 | `56d722b0331bf0aaa86bb37483486c6dff6ad9427fc473ed7c3226c21a9bdd23` | DeepSeek extracted PE (`deepseek-v4-pro_x64.exe`, `deepseek-v4-flash_x64.exe`, `VectorEngine.exe`) | 2026-04-26 | 2026-04-28 |
| SHA-256 | `5455341ed1bbe75a664fca2dd0794c508e1874f75360253a7ff5bc119bc92d80` | Shared loader, observed under multiple AI-brand lure names | 2026-04-12 | 2026-05-21 |

**Redirect-chain / landing infrastructure named in narrative (abused-legitimate or compromised, not in the IOC table):** `grupoconstat[.]bitrix24[.]com[.]br` (abused CRM), `awstrack[.]me` (Amazon tracking), `legendarytrendsbay[.]shop` (compromised, `/ChatGPT/` folder), `servicing.pureplantcravings[.]com` (Claude landing), `dash.awaydouble[.]org` (AiTM landing host).

**Sibling lure filenames (rotating ecosystem, from narrative):** `Manus_AI_Desktop_x64.exe`, `seedance_x64.exe`, `gpt-5.5-Pro_x64.exe`, `gpt-5.5-Thinking_x64.exe`, `Kimi-Swarm-Station_x64.exe`, `fraudGPT_x64.exe`, `GrokCLI_x64.exe`, `gemma-4-omni_x64.exe`, `LTX-2.3_x64.exe`, `TradeAI.exe`, `OpenClaw_x64.7z`, `WormGPT_x64.7z`, `DeepSeekAI_agent_x64.7z`.

---

## Query 1: AI-Brand Impersonation Phishing Lure (Inbound Email)

**Purpose:** Detect inbound email that impersonates an AI brand by display name or subject while combining an account/billing/policy urgency theme — the common pattern across the ChatGPT (payment-update) and Claude (AUP-appeal) campaigns. A clean result is 0 rows after the legitimate-vendor-domain allowlist is applied; hits are candidate brand-spoof phishing for triage.  
**Severity:** Medium  
**MITRE:** T1656, T1566.001, T1566.002
<!-- cd-metadata
cd_ready: false
cd_table: EmailEvents
cd_frequency: Hourly
cd_severity: Medium
cd_mitre: ["T1656", "T1566.002"]
cd_entities: ["account", "mailbox"]
cd_adaptation_notes: "Behavioral lure detection. Subject keyword set is intentionally broad and will need per-tenant tuning; expand the legitDomains allowlist with every AI vendor your org legitimately receives mail from (a legitimate vendor notification was the only FP in testing). Consider requiring a display-name-vs-SenderFromDomain mismatch or non-clean verdict before promoting to a detection."
-->
```kql
let aiBrands = dynamic(["ChatGPT","OpenAI","Copilot","DeepSeek","Anthropic","Claude","Gemini","Grok","Perplexity"]);
// Allowlist legitimate AI-vendor sending domains to suppress genuine vendor mail (primary FP source).
let legitDomains = dynamic(["openai.com","email.openai.com","anthropic.com","deepseek.com","microsoft.com","google.com","x.ai","perplexity.ai"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where SenderDisplayName has_any (aiBrands) or Subject has_any (aiBrands)
| where Subject has_any ("payment","subscription","Plus","appeal","AUP","acceptable use","policy","violation","update payment","verify","suspend","downgrade","limited","billing")
| where not(SenderFromDomain has_any (legitDomains))
| project Timestamp, NetworkMessageId, SenderDisplayName, SenderFromAddress, SenderFromDomain, Subject, DeliveryAction, ThreatTypes, ConfidenceLevel, RecipientEmailAddress
| order by Timestamp desc
| take 100
```
**Expected results:** 0 rows in a clean tenant after the allowlist. Any hit is a display-name/subject brand-spoof candidate — verify sender domain reputation and whether the message was delivered to inbox.

---

## Query 2: Claude Appeal PDF — Attachment Hash & Name Sweep

**Purpose:** Direct-match sweep for the Claude-themed phishing PDF, both by published SHA-256 and by the distinctive attachment name. 0 rows is the expected clean outcome (the IOC predates the 30-day window); a hit means the campaign attachment reached a mailbox.  
**Severity:** High  
**MITRE:** T1566.001
<!-- cd-metadata
cd_ready: true
cd_table: EmailAttachmentInfo
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1566.001"]
cd_entities: ["account", "mailbox", "file"]
cd_adaptation_notes: "Direct IOC match (single published hash + attachment-name heuristic). IOC will rot — refresh from current MS TI. The FileName clause provides resilience if the hash rotates but the lure name is reused."
-->
```kql
let pdfHash = "791efb555eefb7215e96659a1353a97416743b66bdd72705493129c64057d40e";
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where SHA256 == pdfHash or FileName has "Claude Appeal Form"
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256, ThreatTypes
| order by Timestamp desc
```
**Expected results:** 0 rows (direct IOC sweep, clean = good). Investigate any match as a delivered campaign attachment; pivot to `UrlClickEvents` (Query 3) for the same `NetworkMessageId`.

---

## Query 3: Malicious URL Clicks to Campaign Infrastructure

**Purpose:** Detect Safe Links click activity against the campaign's attacker-controlled and compromised landing hosts (AiTM, phishing kit, C2). 0 rows is the expected clean outcome; a clickthrough (`IsClickedThrough == 1`) is a strong post-delivery compromise signal warranting identity follow-up.  
**Severity:** High  
**MITRE:** T1566.002, T1204.001
<!-- cd-metadata
cd_ready: true
cd_table: UrlClickEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1566.002", "T1204.001"]
cd_entities: ["account"]
cd_adaptation_notes: "Direct IOC host match. Hosts rot quickly — refresh list. legendarytrendsbay[.]shop and pureplantcravings[.]com were compromised-legitimate sites, so historical benign clicks are possible; weight IsClickedThrough and ThreatTypes."
-->
```kql
let badHosts = dynamic(["awaydouble.org","brokeapt.com","ssffaa19.xyz","rongtv.xyz","legendarytrendsbay.shop","pureplantcravings.com"]);
UrlClickEvents
| where Timestamp > ago(30d)
| where Url has_any (badHosts)
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, ThreatTypes, Workload, NetworkMessageId
| order by Timestamp desc
```
**Expected results:** 0 rows (direct IOC sweep). A clickthrough is suspected AiTM/credential exposure — revoke sessions, force reset, and run Query 9.

---

## Query 4: Fake AI Installer Download (Rotating Lure Filenames)

**Purpose:** Detect creation of executables/archives whose names match the rotating fake-AI-tool lure ecosystem (DeepSeek V4, Flux Pro AI, Manus, Seedance, GPT-5.5, Kimi, WormGPT, etc.), typically dropped from a browser after GitHub release-asset / malvertising redirection. Behavioral; review `FileOriginUrl` for GitHub release CDN or streaming-site referrers.  
**Severity:** Medium  
**MITRE:** T1204.002, T1608.006
<!-- cd-metadata
cd_ready: false
cd_table: DeviceFileEvents
cd_frequency: Hourly
cd_severity: Medium
cd_mitre: ["T1204.002", "T1608.006"]
cd_entities: ["device", "file", "account"]
cd_adaptation_notes: "Behavioral; lure names rotate constantly so the name list is a maintained seed, not exhaustive. Some tokens (e.g. generic product names) can FP — scope to FileOriginUrl containing release-asset CDNs or untrusted referrers, and correlate with the shared loader hash (Query 5) for higher fidelity before promoting to a detection."
-->
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where (FileName endswith ".exe" or FileName endswith ".7z")
| where FileName has_any ("deepseek-v4","ProFluxeFlowAi","Flux Pro","FluxPro","Manus_AI","seedance","gpt-5.5","Kimi-Swarm","fraudGPT","GrokCLI","gemma-4-omni","LTX-2.3","OpenClaw","WormGPT","DeepSeekAI","TradeAI","VectorEngine")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessFileName, InitiatingProcessAccountUpn
| order by Timestamp desc
| take 100
```
**Expected results:** 0 rows in a clean enterprise environment (the campaign primarily hit consumer endpoints). Any hit: verify download source and submit the file for analysis; pivot to Query 6 (Python loader) and Query 7 (C2).

---

## Query 5: Endpoint File-Hash IOC Sweep (Loader & Installer Payloads)

**Purpose:** Direct-match sweep for the published payload hashes (fake-installer archives, extracted PE, and the shared loader) across file, image-load, and process telemetry. 0 rows is the expected clean outcome given the IOC age; a hit indicates payload presence/execution on an endpoint.  
**Severity:** High  
**MITRE:** T1204.002, T1105
<!-- cd-metadata
cd_ready: true
cd_table: DeviceFileEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1204.002", "T1105"]
cd_entities: ["device", "file", "account"]
cd_adaptation_notes: "Direct IOC hash match via union across file/image-load/process tables. SHA256 is often unpopulated on Device* tables — if endpoint sweeps come back empty despite suspicion, resolve these SHA-256 to SHA-1 (Defender file page / MDTI) and add a parallel SHA1 clause. Hashes rot; refresh from current MS TI."
-->
```kql
let fileHashes = dynamic([
"c7c5072df9f83f4c440a5c3bb4be1d5f6c67bbf78f196406ca20d27b43b975b8",
"0a26238f6c516de5885457c93042531aa59bc206a9537cebf5267cedc6c68531",
"8610d4fb0ec5b525071c2aaec4df0f8fcbb3673aba58a7e1959fc44e83c0e2ca",
"99231deb373997364381d1eb513d2d42231d418c3a2db9007c5af9bd56ab9371",
"25270cc429ada8028b5b33220ed412c47907ecceea7377d608fac5af01bed56a",
"56d722b0331bf0aaa86bb37483486c6dff6ad9427fc473ed7c3226c21a9bdd23",
"5455341ed1bbe75a664fca2dd0794c508e1874f75360253a7ff5bc119bc92d80"]);
union DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 in (fileHashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountUpn
| order by Timestamp desc
```
**Expected results:** 0 rows (direct IOC sweep). Re-run in Sentinel Data Lake (90d) for retrospective coverage outside the AH window.

---

## Query 6: Python Loader Persistence in %AppData%\Local

**Purpose:** Detect the malvertising chain's second stage — a Python interpreter (`pythonw.exe`) staged in `%AppData%\Local` executing a `.txt`-disguised downloader script (the article describes `pythonw.exe` + `LICENSE.txt` dropped there). Behavioral; correlate the parent installer and the C2 callout.  
**Severity:** High  
**MITRE:** T1059.006, T1105
<!-- cd-metadata
cd_ready: false
cd_table: DeviceProcessEvents
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1059.006", "T1105"]
cd_entities: ["device", "account", "process"]
cd_adaptation_notes: "Behavioral. pythonw.exe under %AppData%\\Local can be legitimate for some packaged Python apps — before promoting, add a clause requiring a recently downloaded installer parent or a .txt/non-.py script argument, and allowlist known-good packaged Python apps in your environment."
-->
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "pythonw.exe"
| where FolderPath has @"\AppData\Local"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, AccountName, AccountUpn
| order by Timestamp desc
| take 100
```
**Expected results:** 0 rows expected in a clean environment. Investigate any hit where the command line references a `.txt` script or the parent is a recently downloaded AI-themed installer; pivot to Query 7 for C2.

---

## Query 7: Vidar / Loader C2 Network Connections

**Purpose:** Direct-match sweep for outbound connections to the published C2 domains (Python-loader C2 and Vidar C2). 0 rows is the expected clean outcome; a hit is a high-confidence compromise indicator identifying the beaconing process and device.  
**Severity:** High  
**MITRE:** T1071.001, T1105
<!-- cd-metadata
cd_ready: true
cd_table: DeviceNetworkEvents
cd_frequency: NRT
cd_severity: High
cd_mitre: ["T1071.001", "T1105"]
cd_entities: ["device", "account"]
cd_adaptation_notes: "Direct IOC domain match. C2 domains rot — refresh from current MS TI. brokeapt[.]com had a long observed window (Mar–May 2026) so retains value longer than the Vidar .xyz C2s."
-->
```kql
let c2Hosts = dynamic(["brokeapt.com","pan.ssffaa19.xyz","pan.rongtv.xyz","ssffaa19.xyz","rongtv.xyz"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (c2Hosts)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountUpn
| order by Timestamp desc
```
**Expected results:** 0 rows (direct IOC sweep). Any hit: isolate the device, identify the initiating process, and sweep for the loader hashes (Query 5).

---

## Query 8: Fox Tempest Code-Signing Certificate Sweep

**Purpose:** Detect files on endpoints signed with the fraudulently obtained code-signing certificate attributed to the Fox Tempest MSaaS operation (the same signer Microsoft revoked >1,000 certs for). Direct-match on the published signer SHA-1 thumbprint. 0 rows is the expected clean outcome.  
**Severity:** High  
**MITRE:** T1553.002, T1588.003
<!-- cd-metadata
cd_ready: true
cd_table: DeviceFileCertificateInfo
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1553.002", "T1588.003"]
cd_entities: ["device", "file"]
cd_adaptation_notes: "Direct IOC match on SignerHash (cert SHA-1 thumbprint). High fidelity and longer-lived than file hashes since it covers any binary signed by this cert. Microsoft has revoked this cert; a post-revocation hit may indicate stale binaries or replay — investigate regardless."
-->
```kql
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where SignerHash == "4f5c5b3ef45cfff7721754487a86aeff9a2e6e32"
| project Timestamp, DeviceName, SHA1, IsSigned, Signer, SignerHash, Issuer, IsTrusted, CertificateExpirationTime
| order by Timestamp desc
```
**Expected results:** 0 rows (direct IOC sweep). Any signed file from this thumbprint should be treated as malware regardless of `IsTrusted`; pivot on `SHA1` into `DeviceFileEvents`/`DeviceProcessEvents`.

---

## Query 9: Post-Click AiTM Token-Anomaly Correlation

**Purpose:** Correlate a phishing/campaign URL clickthrough with an Entra ID Protection risk detection (anomalous token / unfamiliar features) for the same user within 24 hours — the AiTM token-theft outcome described for the Claude campaign. Behavioral correlation; a match is a strong account-compromise signal.  
**Severity:** High  
**MITRE:** T1557, T1539, T1078
<!-- cd-metadata
cd_ready: false
cd_table: UrlClickEvents
cd_frequency: Hourly
cd_severity: High
cd_mitre: ["T1557", "T1539"]
cd_entities: ["account"]
cd_adaptation_notes: "Cross-table correlation (UrlClickEvents x AADUserRiskEvents). AADUserRiskEvents is a Sentinel/LA-tier table — confirm it is in scope for your Custom Detection tier. Tune the 24h window and the click-qualifier (broaden beyond the seeded campaign hosts to any Phish-verdict clickthrough). AADUserRiskEvents uses ActivityDateTime (not TimeGenerated) and IpAddress (lowercase p)."
-->
```kql
let clicks = UrlClickEvents
| where Timestamp > ago(30d)
| where IsClickedThrough == "1"
| where ThreatTypes has_any ("Phish","Malware") or Url has_any ("awaydouble.org","pureplantcravings.com","legendarytrendsbay.shop","brokeapt.com")
| project ClickTime=Timestamp, AccountUpn, Url, NetworkMessageId;
clicks
| join kind=inner (
    AADUserRiskEvents
    | where ActivityDateTime > ago(30d)
    | where RiskEventType in ("anomalousToken","unfamiliarFeatures")
    | project RiskTime=ActivityDateTime, UserPrincipalName, RiskEventType, RiskLevel, RiskState, IpAddress
) on $left.AccountUpn == $right.UserPrincipalName
| where RiskTime between (ClickTime .. (ClickTime + 24h))
| project ClickTime, RiskTime, AccountUpn, Url, RiskEventType, RiskLevel, RiskState, IpAddress
| order by ClickTime desc
```
**Expected results:** 0 rows in a clean tenant. A match is suspected AiTM token theft — revoke refresh tokens, force password reset, and hunt for attacker inbox rules and OAuth grants.

---

## General Tuning Notes

1. **IOC refresh.** Every direct-match query (Q2, Q3, Q5, Q7, Q8) uses point-in-time indicators from the article (Mar–May 2026). Operators rotate hashes and domains rapidly — the DeepSeek archive rotated three hash generations in three days. Refresh these lists from current Microsoft Defender Threat Intelligence, VirusTotal, or a maintained TI indicator table on a recurring basis.
2. **Telemetry gaps / window.** All queries were authored and tested in Microsoft Defender Advanced Hunting against a 30-day window. The article's IOCs largely predate that window, so direct-match sweeps returning 0 are the expected clean result, not a coverage gap. For retrospective hunting, re-run the hash/domain sweeps (Q5, Q7) in the Sentinel Data Lake (90 days) with `Timestamp`→`TimeGenerated` adaptation where applicable. `SHA256` is frequently unpopulated on `Device*` tables — resolve to `SHA1` for endpoint sweeps when needed.
3. **Lure-name maintenance.** The fake-installer ecosystem recycles whichever AI tool is trending. Treat the Query 4 filename list as a seed set and extend it as new lures emerge; the shared loader hash (Query 5) and the C2/cert IOCs are more durable anchors than any single brand name.
4. **CD-readiness summary.** Direct-IOC, low-FP queries are marked `cd_ready: true` (Q2, Q3, Q5, Q7, Q8). Behavioral/correlation queries that need per-tenant tuning before becoming detections are `cd_ready: false` (Q1 — broad subject keywords + vendor allowlist; Q4 — rotating lure names; Q6 — legitimate packaged-Python FP risk; Q9 — cross-table window + Sentinel-tier table dependency).

---

## References

- Microsoft Threat Intelligence — [AI brands as bait: How threat actors are using the AI hype in social engineering (2026-06-08)](https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-the-ai-hype-in-social-engineering/)
- Microsoft Threat Intelligence — [Exposing Fox Tempest: a malware-signing service operation (2026-05-19)](https://www.microsoft.com/en-us/security/blog/2026/05/19/exposing-fox-tempest-a-malware-signing-service-operation/)
- Microsoft Threat Intelligence — [Lumma Stealer: breaking down the delivery techniques and capabilities (2025-05-21)](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- MITRE ATT&CK — [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/), [T1553.002 Code Signing](https://attack.mitre.org/techniques/T1553/002/), [T1059.006 Python](https://attack.mitre.org/techniques/T1059/006/), [T1608.006 SEO Poisoning](https://attack.mitre.org/techniques/T1608/006/)
- Companion files: [`queries/threat-intelligence/2026-02/infostealer_hunting_campaign.md`](../2026-02/infostealer_hunting_campaign.md) (Vidar/Lumma infostealer endpoint hunts), [`queries/threat-intelligence/2026-05/code_of_conduct_aitm_phishing.md`](../2026-05/code_of_conduct_aitm_phishing.md) (AiTM PDF-phish → token-theft chain), [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md) (general phishing / Safe Links / ZAP)
