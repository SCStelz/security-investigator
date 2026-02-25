# AiTM / Adversary-in-the-Middle — Defensive Program & Hunting Playbook

**Created:** 2026-02-11  
**Platform:** Both  
**Tables:** SigninLogs, AADSignInEventsBeta, AADUserRiskEvents, AuditLogs, SecurityAlert, SecurityIncident, OfficeActivity, CloudAppEvents, EmailEvents, UrlClickEvents, IdentityLogonEvents, DeviceEvents, AlertInfo, AlertEvidence  
**Keywords:** AiTM, adversary-in-the-middle, token theft, session cookie, phishing resistant, FIDO2, passkey, Evilginx, token replay, BEC, MFA bypass, attack disruption, compliant network, Global Secure Access, token protection, CAE, continuous access evaluation  
**MITRE:** T1557, T1539, T1528, T1550.004, T1114.003, T1098, T1078, TA0006, TA0001, TA0009  
**Timeframe:** Last 30 days (configurable)

---

## Executive Summary

Microsoft observed a **146% rise in AiTM attacks** over the past year (2024-2025). AiTM phishing bypasses traditional MFA by proxying the user's authentication session through a reverse-proxy server (e.g., Evilginx, Muraena, Modlishka), capturing both credentials and session cookies. The stolen session cookie allows the attacker to replay tokens and access resources as the victim — **MFA alone is not sufficient protection**.

This document synthesizes intelligence from [Jeffrey Appel's 2026 AiTM guide](https://jeffreyappel.nl/aitm-mfa-phishing-attacks-in-combination-with-new-microsoft-protections-2023-edt/), official Microsoft Learn documentation, and the Microsoft Secure Future Initiative to deliver:

1. **A prioritized defensive program** with actionable posture improvements
2. **Detection & alerting configuration** across the Microsoft security stack
3. **KQL hunting queries** for both Sentinel Data Lake and Defender XDR Advanced Hunting
4. **Response playbook** for confirmed AiTM compromise

---

## Part 1: AiTM Attack Anatomy

### Attack Flow

```
1. 📧 Phishing email with AiTM link → User clicks
2. 🌐 Reverse proxy (Evilginx) serves cloned sign-in page
3. 🔑 User enters credentials → Proxied to real login.microsoftonline.com  
4. 📱 MFA prompt fires → User completes MFA (SMS, push, Authenticator — all bypassed)
5. 🍪 Session cookie + tokens captured by attacker's proxy server
6. 🎭 Attacker replays stolen cookie from different IP/location
7. 📬 Post-compromise: Inbox rules, BEC, MFA method registration, data exfiltration
```

### What AiTM Bypasses

| Method | Bypassed by AiTM? | Rationale |
|--------|:-----------------:|-----------|
| Password + SMS OTP | ✅ Yes | OTP relayed through proxy in real-time |
| Password + Phone call | ✅ Yes | Approval relayed through proxy |
| Microsoft Authenticator (push) | ✅ Yes | Push approval relayed; even number matching/additional context is bypassed |
| Microsoft Authenticator (number matching) | ✅ Yes | Number displayed is proxied from real site |
| Passwordless phone sign-in | ✅ Yes | Token still captured (password field empty in Evilginx) |
| **FIDO2 Security Keys** | 🛡️ **No** | Origin-bound cryptographic assertion — proxy domain fails origin check |
| **Windows Hello for Business** | 🛡️ **No** | Device-bound TPM credential with origin verification |
| **Certificate-based Authentication (CBA)** | 🛡️ **No** | Client TLS certificate bound to legitimate server |
| **Passkeys (FIDO2 — device-bound or synced)** | 🛡️ **No** | WebAuthn origin binding prevents proxy interception |
| **Platform Credential for macOS (Secure Enclave)** | 🛡️ **No** | Hardware-bound with origin check |

> **Key insight:** Only phishing-resistant methods using cryptographic origin binding (FIDO2/WebAuthn/CBA) are inherently immune. All other methods require **additional Conditional Access controls** to prevent token replay after the phishing completes.

### Known Threat Actors

| Storm ID | Alias | AiTM Kit | Primary Targets |
|----------|-------|----------|----------------|
| Storm-0563 | DEV-0563 | Custom proxy | General enterprise |
| Storm-0928 | DEV-0928 | EvilProxy / SendGrid | Financial services |
| Storm-1101 | DEV-1101 | Open-source AiTM kit | Mass phishing campaigns |
| Storm-1747 | — | Tycoon2FA (PhaaS) | Enterprise, BEC |

---

## Part 2: Defensive Program — Prioritized Actions

### 🔴 Tier 1 — Critical (Prevent AiTM Token Theft)

These controls **directly prevent** the AiTM attack from succeeding.

#### 1.1 Deploy Phishing-Resistant MFA (FIDO2/Passkeys)

**Impact:** Eliminates the core AiTM vulnerability — proxied authentication  
**Effort:** Medium-High (credential lifecycle, user training, hardware procurement)

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable passkey/FIDO2 in Authentication Methods policy | Entra Admin Center → Protection → Authentication Methods → Passkey (FIDO2) | [Enable passkey authentication](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-passkey-fido2) |
| Enforce attestation for FIDO2 keys | Restrict to approved AAGUIDs to prevent rogue key registration | [FIDO2 hardware vendors](https://learn.microsoft.com/entra/identity/authentication/concept-fido2-hardware-vendor) |
| Enroll privileged accounts first | Start with Global Admin, Security Admin, Exchange Admin | [Plan phishing-resistant deployment](https://learn.microsoft.com/entra/identity/authentication/how-to-plan-prerequisites-phishing-resistant-passwordless-authentication) |
| Register Windows Hello for Business | WHfB with TPM is a FIDO2-certified authenticator on Windows 11 | [WHfB deployment guide](https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/) |
| Deploy Passkeys in Microsoft Authenticator | Mobile passkey for iOS/Android (device-bound) | [Passkeys in Authenticator](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-authenticator-passkey) |
| Create CA policy: Require phishing-resistant MFA strength | Use built-in "Phishing-resistant MFA" authentication strength | [Policy: Phishing-resistant MFA for all users](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength) |

> **Microsoft SFI benchmark:** 92% of employee productivity accounts now protected by phishing-resistant methods ([SFI Phishing-Resistant MFA](https://learn.microsoft.com/security/zero-trust/sfi/phishing-resistant-mfa)).

#### 1.2 Require Compliant/Hybrid Joined Devices

**Impact:** Even if tokens are stolen, they cannot be replayed from unmanaged devices  
**Effort:** Medium (requires Intune enrollment, compliance policies)

| Action | Detail | Reference |
|--------|--------|-----------|
| CA Policy: Require compliant device for all cloud apps | Grant control → Require device to be marked as compliant | [Policy: Require compliant device](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance) |
| CA Policy: Require Hybrid Entra ID join (for domain-joined PCs) | Grant control → Require Microsoft Entra hybrid joined device | [Hybrid join CA](https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device) |
| Apply to **all cloud apps** | Do NOT scope to specific apps — attackers will target unprotected apps | Blog insight: "Don't limit CA based on specific apps" |
| Handle mobile (BYOD) with MAM + Defender MTD | Mobile threat defense prevents malware-based token exfiltration | [Mobile Threat Defense](https://learn.microsoft.com/defender-business/mdb-mtd) |

> ⚠️ **TokenSmith bypass:** Research shows device compliance can potentially be circumvented ([JumpSec TokenSmith](https://labs.jumpsec.com/tokensmith-bypassing-intune-compliant-device-conditional-access/)). Layer with network-based controls (Tier 1.3) for defense-in-depth.

#### 1.3 Deploy Global Secure Access (Compliant Network)

**Impact:** Prevents token replay from outside your organizational network boundary  
**Effort:** Medium (requires GSA client deployment to managed devices)

| Action | Detail | Reference |
|--------|--------|-----------|
| Deploy Global Secure Access client to managed devices | Install GSA client for Windows, macOS, iOS, Android | [Global Secure Access overview](https://learn.microsoft.com/entra/global-secure-access/overview-what-is-global-secure-access) |
| CA Policy: Require compliant network | Blocks authentication from devices not connected via GSA | [Compliant network check](https://learn.microsoft.com/entra/global-secure-access/how-to-compliant-network) |
| Enable Universal CAE | Near-real-time token revocation for any app accessed via GSA | [Universal CAE](https://learn.microsoft.com/entra/global-secure-access/concept-universal-continuous-access-evaluation) |
| Consider Strict Enforcement mode | Blocks token replay from different IP than original auth | [CAE Strict Enforcement](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation-strict-enforcement) |
| Enable web content filtering | Block newly registered domains and liability categories | [Web content filtering](https://learn.microsoft.com/entra/global-secure-access/how-to-configure-web-content-filtering) |

**Alternative (without GSA):** Use location-based CA policies with named locations (trusted IP ranges). Less secure than GSA because IP ranges require manual maintenance and don't cover roaming users.

---

### 🟠 Tier 2 — High (Limit Blast Radius & Accelerate Detection)

These controls don't prevent the initial token capture but **minimize damage** and **detect compromise quickly**.

#### 2.1 Configure Automatic Attack Disruption

**Impact:** Near-real-time automatic containment of detected AiTM attacks  
**Effort:** Low-Medium (requires Defender XDR ecosystem deployment)

| Action | Detail | Reference |
|--------|--------|-----------|
| Deploy all Defender XDR workloads | Defender for Identity, Office, Endpoint, Cloud Apps | [Configure attack disruption](https://learn.microsoft.com/defender-xdr/configure-attack-disruption) |
| Configure Defender for Identity action accounts | gMSA or local system for automated user disable | [DfI action accounts](https://learn.microsoft.com/defender-for-identity/manage-action-accounts) |
| Verify Attack Disruption is enabled (default: on) | Settings → Microsoft Defender XDR → Automated investigation | [Attack disruption overview](https://learn.microsoft.com/defender-xdr/automatic-attack-disruption) |
| Connect Defender for Cloud Apps connectors | Required: Office 365 + Azure connectors for cookie replay detection | [Connect Office 365](https://learn.microsoft.com/defender-cloud-apps/connect-office-365) |

**Attack disruption flow for AiTM:**
1. Identifies high-confidence AiTM attack from correlated XDR signals
2. Automatically disables user account in AD and Entra ID
3. Revokes stolen session cookies
4. Tags incident with "Attack Disruption" and "AiTM attack"

#### 2.2 Enable Entra ID Identity Protection Risk Policies

**Impact:** Automatic response when AiTM-related risk detections fire  
**Effort:** Low

| Action | Detail | Reference |
|--------|--------|-----------|
| User risk policy: Block or require secure password change at High risk | Identity Protection → User risk policy → High → Block access | [Configure risk policies](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies) |
| Sign-in risk policy: Require MFA at Medium+ risk | Identity Protection → Sign-in risk policy → Medium and above | Same |
| Enable Continuous Access Evaluation (CAE) | Near-real-time token revocation on user risk change | [CAE overview](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation) |

**AiTM-specific risk detections (Entra ID Protection):**
- 🔴 **Attacker in the Middle** — Direct AiTM detection
- 🔴 **Anomalous Token** — Token with unusual characteristics (device mismatch, IP anomaly)
- 🟠 **Unfamiliar sign-in properties** — Sign-in from unusual location/device
- 🟠 **Unfamiliar sign-in properties for session cookies** — Cookie replay from anomalous context

#### 2.3 Enable Token Protection (Conditional Access)

**Impact:** Binds tokens to the device, preventing replay from other devices  
**Effort:** Low (limited app support — layer with other controls)

| Action | Detail | Reference |
|--------|--------|-----------|
| CA Policy: Require token protection (session control) | Session → Require token protection for sign-in sessions | [Token Protection](https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection) |
| Supported apps: Exchange Online, SharePoint Online, Teams | Also: OneDrive sync, Power BI Desktop, VS 2022+, Windows App | Same |
| Requires: Entra joined, hybrid joined, or registered devices | PRT must be available for token binding | Same |

> ⚠️ **Limitation:** Token protection does NOT prevent the initial token capture — it prevents **replay**. Per blog testing: "sometimes it was taking quite some time" and results were inconsistent. Use as **additional layer**, not sole control.

#### 2.4 Block Device Code Flow

**Impact:** Prevents AiTM variant using device code phishing  
**Effort:** Low

| Action | Detail | Reference |
|--------|--------|-----------|
| CA Policy: Block device code flow | Authentication flows → Device code flow → Block | [Authentication flows CA](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows#device-code-flow) |
| Exception: Conference room devices on specific networks | Allow only for legitimate IoT/limited-input scenarios | Same |

---

### 🟡 Tier 3 — Important (Defense-in-Depth & Hardening)

#### 3.1 Defender for Endpoint — Network Protection & SmartScreen

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable Network Protection in block mode | Blocks connections to known AiTM infrastructure | [Network protection](https://learn.microsoft.com/defender-endpoint/network-protection) |
| Enable Defender SmartScreen | Early warning for phishing/AiTM websites | [SmartScreen](https://learn.microsoft.com/deployedge/microsoft-edge-security-smartscreen) |
| Configure SmartScreen bypass prevention | Prevent users from clicking through warnings | [Enhanced phishing protection](https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/enhanced-phishing-protection) |
| Web content filtering: Block newly registered domains | AiTM domains are typically < 30 days old | [Web content filtering](https://learn.microsoft.com/defender-endpoint/web-content-filtering) |
| Web content filtering: Audit uncategorized domains | Monitor before blocking to reduce business impact | Same |

#### 3.2 Defender for Office 365 — Email Protection

| Action | Detail | Reference |
|--------|--------|-----------|
| Safe Links: Enable URL scanning | Blocks known AiTM phishing URLs in emails | [Safe Links policies](https://learn.microsoft.com/defender-office-365/safe-links-policies-configure) |
| Safe Attachments: Enable dynamic delivery | Sandboxes attachments before delivery | [Safe Attachments](https://learn.microsoft.com/defender-office-365/safe-attachments-policies-configure) |
| Anti-phishing: Enable first-contact safety tip | Warns on emails from new senders | [Anti-phishing policies](https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about) |
| Review MDO Secure Score recommendations | Ensure all protection settings are optimized | Defender portal → Secure Score |

#### 3.3 Device Hardening

| Action | Detail | Reference |
|--------|--------|-----------|
| Configure Credential Guard (Windows) | Isolates LSA, prevents credential theft from memory | [Credential Guard](https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure) |
| Validate Windows Enrollment Attestation | Ensure TPM requirements met on all devices | [Enrollment attestation](https://learn.microsoft.com/intune/intune-service/enrollment/windows-enrollment-attestation) |
| macOS: Disable iCloud Keychain sync via Intune | Prevents token sync to personal iCloud | [macOS restrictions](https://learn.microsoft.com/intune/intune-service/configuration/device-restrictions-macos) |
| macOS: Configure Platform SSO (Secure Enclave) | Phishing-resistant auth for Mac devices | [Platform SSO](https://learn.microsoft.com/intune/intune-service/configuration/platform-sso-macos) |
| Enable Enterprise SSO plugin for Apple | Leverages PRT for application SSO on Apple devices | [Enterprise SSO plugin](https://learn.microsoft.com/entra/identity-platform/apple-sso-plugin) |

#### 3.4 Secure Onboarding & Credential Lifecycle

| Action | Detail | Reference |
|--------|--------|-----------|
| Use Temporary Access Pass (TAP) for onboarding | Time-bound credential for initial passkey registration | [Configure TAP](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass) |
| Implement Lifecycle Workflows | Automate MFA registration/deactivation at each user stage | [Lifecycle workflows](https://learn.microsoft.com/entra/id-governance/what-are-lifecycle-workflows) |
| Use Entra Verified ID for remote identity verification | High-assurance identity proofing with face liveness | [Verified ID](https://learn.microsoft.com/entra/verified-id/decentralized-identifier-overview) |

---

## Part 3: Detection & Alert Configuration

### Built-In Alerts That Detect AiTM Activity

Configure and verify all of these are active and generating incidents:

#### Microsoft Defender XDR

| Alert Name | Detection | Priority |
|-----------|-----------|----------|
| **User compromised in AiTM phishing attack** | Direct AiTM classification + Attack Disruption tag | 🔴 Critical |
| **Connection to adversary-in-the-middle (AiTM) phishing site** | EDR network detection via known AiTM indicators | 🔴 Critical |
| **Stolen session cookie was used** | Cookie replay detected via Cloud Apps + Edge | 🔴 Critical |
| **Possible AiTM phishing attempt** | Cloud Apps + Endpoint correlation | 🟠 High |
| **Storm-0928 activity group** | Threat intel match for EvilProxy campaigns | 🟠 High |
| **BEC-related credential harvesting attack** | Post-AiTM BEC activity detected | 🟠 High |
| **Suspicious phishing emails sent by BEC-related user** | Compromised account sending phishing | 🟠 High |

#### Microsoft Entra ID Protection

| Alert Name | Risk Type | Priority |
|-----------|-----------|----------|
| **Attacker in the Middle** | User risk | 🔴 Critical |
| **Anomalous Token** | User risk | 🔴 Critical |
| **Unfamiliar sign-in properties** | Sign-in risk | 🟠 High |
| **Unfamiliar sign-in properties for session cookies** | Sign-in risk | 🟠 High |
| **Threat Intelligence Session** | Sign-in risk | 🟠 High |

#### Microsoft Defender for Cloud Apps

| Alert Name | Detection | Priority |
|-----------|-----------|----------|
| **Suspicious inbox manipulation rule** | BEC follow-on activity | 🟠 High |
| **Impossible travel activity** | Geographic anomaly after token replay | 🟠 High |
| **Activity from infrequent country** | Token used from unusual location | 🟡 Medium |
| **Suspicious email deletion activity** | Evidence tampering post-BEC | 🟠 High |

#### Microsoft Defender for Office 365

| Alert Name | Detection | Priority |
|-----------|-----------|----------|
| **Email messages containing malicious file removed after delivery** | ZAP remediation | 🟡 Medium |
| **A potentially malicious URL click was detected** | User clicked AiTM link | 🟠 High |
| **A user clicked through to a potentially malicious URL** | User bypassed warning | 🟠 High |
| **Suspicious email-sending patterns detected** | Compromised account mass-mailing | 🟠 High |

---

## Part 4: Hunting & Detection Queries

### Query 1: AiTM Proxy Sign-In — OfficeHome Multi-Country Session (Advanced Hunting)

Detects sign-ins through the OfficeHome application (AppId `4765445b`) where the same session has sign-ins from multiple countries — a classic AiTM token replay indicator.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "AiTM Token Replay: {{AccountDisplayName}} session used from multiple countries"
impactedAssets:
  - type: "user"
    identifier: "accountName"
adaptation_notes: "Multi-let join query. CD supports `let` blocks. High-signal detection for AiTM proxy attacks."
-->
```kql
// AiTM Detection: OfficeHome proxy sign-in with cross-country session replay
// Platform: Defender XDR Advanced Hunting
let OfficeHomeSessionIds = 
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where ApplicationId == "4765445b-32c6-49b0-83e6-1d93765276ca" // OfficeHome application 
| where ClientAppUsed == "Browser" 
| where LogonType has "interactiveUser" 
| summarize arg_min(Timestamp, Country) by SessionId;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ApplicationId != "4765445b-32c6-49b0-83e6-1d93765276ca"
| where ClientAppUsed == "Browser" 
| project OtherTimestamp = Timestamp, Application, ApplicationId, 
    AccountObjectId, AccountDisplayName, OtherCountry = Country, SessionId
| join OfficeHomeSessionIds on SessionId
| where OtherTimestamp > Timestamp and OtherCountry != Country
```

### Query 2: AiTM Proxy Sign-In — Sentinel Data Lake Variant

Same logic adapted for Sentinel Data Lake using `SigninLogs`.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "AiTM Token Replay: {{UserPrincipalName}} session from {{OriginalCountry}} replayed from {{ReplayCountry}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
adaptation_notes: "Sentinel Data Lake variant of Q1. Uses `parse_json(LocationDetails)` for country extraction."
-->
```kql
// AiTM Detection: OfficeHome proxy with cross-country sessions
// Platform: Sentinel Data Lake
let OfficeHomeAppId = "4765445b-32c6-49b0-83e6-1d93765276ca";
let OfficeHomeSessions = SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where AppId == OfficeHomeAppId
| where ClientAppUsed == "Browser"
| where IsInteractive == true
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| summarize arg_min(TimeGenerated, Country) by OriginalRequestId;
SigninLogs
| where TimeGenerated > ago(7d)
| where AppId != OfficeHomeAppId
| where ClientAppUsed == "Browser"
| extend OtherCountry = tostring(parse_json(LocationDetails).countryOrRegion)
| project OtherTimestamp = TimeGenerated, AppDisplayName, AppId,
    UserPrincipalName, OtherCountry, IPAddress, OriginalRequestId
| join kind=inner OfficeHomeSessions on OriginalRequestId
| where OtherTimestamp > TimeGenerated and OtherCountry != Country
| project OtherTimestamp, UserPrincipalName, AppDisplayName, IPAddress,
    OriginalCountry = Country, ReplayCountry = OtherCountry, OriginalRequestId
| order by OtherTimestamp desc
```

### Query 3: Anomalous Token Risk Events Correlated with Phishing Emails

Detects users who had phishing emails delivered AND subsequently triggered anomalous token detections.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "CredentialAccess"
title: "AiTM Full Chain: {{UserPrincipalName}} phished then {{RiskEventType}} detected"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
adaptation_notes: "Multi-source correlation (EmailEvents + AADUserRiskEvents). Row-level output per risk event. 30d lookback is within CD limits."
-->
```kql
// AiTM Full Chain: Phishing delivery → Anomalous token detection
// Platform: Sentinel Data Lake
let PhishedUsers = EmailEvents
| where TimeGenerated > ago(30d)
| where ThreatTypes has "Phish" and EmailDirection == "Inbound"
| where DeliveryAction != "Blocked"
| distinct RecipientEmailAddress;
AADUserRiskEvents
| where TimeGenerated > ago(30d)
| where RiskEventType in ("anomalousToken", "attackerinTheMiddle",
    "unfamiliarFeatures", "mcasImpossibleTravel")
| where UserPrincipalName in~ (PhishedUsers)
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel,
    RiskState, IpAddress, Location, DetectionTimingType,
    TokenIssuerType, Source
| order by TimeGenerated desc
```

### Query 4: New MFA Method Registration After Suspicious Sign-In

Attackers register a new MFA method (including FIDO2 keys) after AiTM compromise to maintain persistent access.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "Persistence"
title: "Post-AiTM MFA Registration: {{OperationName}} by {{AccountUpn}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
adaptation_notes: "Cross-table correlation (AADUserRiskEvents + AuditLogs). The `has_any (RiskyUsers)` pattern works for moderate user volumes. For large environments, consider limiting the `let` subquery. Must extract AccountUpn from InitiatedBy dynamic field (coalesce with Identity fallback). Use CorrelationId as proxy ReportId."
-->
```kql
// Post-AiTM: New MFA method registration following risky sign-in
// Platform: Sentinel Data Lake
let RiskyUsers = AADUserRiskEvents
| where TimeGenerated > ago(14d)
| where RiskEventType in ("anomalousToken", "attackerinTheMiddle")
| where RiskLevel in ("high", "medium")
| distinct UserPrincipalName;
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has "authentication method"
    or OperationName has "security info"
    or OperationName has "strong authentication"
| where tostring(TargetResources) has_any (RiskyUsers)
    or tostring(InitiatedBy) has_any (RiskyUsers)
| project TimeGenerated, OperationName, 
    InitiatedBy = tostring(InitiatedBy),
    TargetResources = tostring(TargetResources),
    Result, ResultDescription
| order by TimeGenerated desc
```

### Query 5: Inbox Rules Created During Anomalous Token Sessions (Advanced Hunting)

Detects inbox rule creation that correlates with Anomalous Token alerts — key BEC follow-on indicator.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Collection"
title: "Post-AiTM Inbox Rule: {{RawEventData.Name}} created during anomalous token session"
impactedAssets:
  - type: "user"
    identifier: "accountObjectId"
adaptation_notes: "Advanced Hunting only — uses AlertInfo + AlertEvidence + CloudAppEvents with `materialize()`. Multi-let pipeline. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// Post-AiTM BEC: Inbox rules during anomalous token session
// Platform: Defender XDR Advanced Hunting
let suspiciousSessionIds = materialize(
AlertInfo
| where Timestamp > ago(7d)
| where Title == "Anomalous Token"
| join (AlertEvidence 
    | where Timestamp > ago(7d) 
    | where EntityType == "CloudLogonSession") on AlertId
| project sessionId = todynamic(AdditionalFields).SessionId);
let hasSuspiciousSessionIds = isnotempty(toscalar(suspiciousSessionIds));
CloudAppEvents
| where hasSuspiciousSessionIds
| where Timestamp > ago(21d)
| where ActionType == "New-InboxRule"
| where RawEventData.SessionId in (suspiciousSessionIds)
```

### Query 6: Suspicious Inbox Rules for Forwarding/Redirect (Sentinel Data Lake)

Detects mailbox forwarding/redirect rules that indicate BEC-stage exfiltration post-AiTM.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Exfiltration"
title: "Inbox Forwarding Rule: {{Operation}} by {{UserId}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
  - type: "mailbox"
    identifier: "accountUpn"
adaptation_notes: "Sentinel Data Lake (OfficeActivity). Row-level events with clear exfiltration indicators. `Parameters` is a string field — use `has` for keyword matching."
-->
```kql
// Post-AiTM BEC: Email exfiltration via forwarding rules
// Platform: Sentinel Data Lake
// MITRE: T1114.003, T1020
OfficeActivity
| where TimeGenerated > ago(30d)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule", 
    "Set-Mailbox", "UpdateInboxRules")
| where Parameters has_any ("ForwardTo", "RedirectTo", 
    "ForwardingSmtpAddress", "ForwardAsAttachmentTo")
    or Parameters has_any ("MoveToFolder", "MarkAsRead", "Delete")
| project TimeGenerated, UserId, Operation, Parameters,
    ClientIP, ClientInfoString, OfficeObjectId
| order by TimeGenerated desc
```

### Query 7: Token Replay — Same SessionId from Multiple IPs/Countries

Detects token replay by identifying sessions used from geographically dispersed locations.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes per SessionId with `dcount(IPAddress) > 1` threshold. Output is one row per session, not per event. Would require restructuring to produce row-level alerts for CD."
-->
```kql
// AiTM Token Replay: Same session used from multiple locations
// Platform: Sentinel Data Lake
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend City = tostring(parse_json(LocationDetails).city)
| summarize
    DistinctIPs = dcount(IPAddress),
    DistinctCountries = dcount(Country),
    Countries = make_set(Country),
    Cities = make_set(City),
    IPs = make_set(IPAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SignInCount = count()
    by UserPrincipalName, OriginalRequestId
| where DistinctIPs > 1 and DistinctCountries > 1
| extend SessionDuration = LastSeen - FirstSeen
| where SessionDuration < 1h // Short sessions with multi-country = high confidence
| project UserPrincipalName, OriginalRequestId, Countries, Cities, 
    IPs, DistinctIPs, DistinctCountries, SessionDuration, SignInCount
| order by DistinctCountries desc, DistinctIPs desc
```

### Query 8: URL Click-Through to Phishing Sites

Identifies users who clicked through to URLs classified as phishing — early AiTM chain indicator.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes per AccountUpn with click counts and URL lists. Output is one row per user, not per click event. Would need restructuring for row-level alerting."
-->
```kql
// AiTM Early Warning: Users clicking phishing URLs
// Platform: Defender XDR Advanced Hunting
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickAllowed" or IsClickedThrough != "0"
| where ThreatTypes has "Phish"
| summarize ClickCount = count(), 
    Urls = make_set(Url),
    NetworkMessages = make_set(NetworkMessageId)
    by AccountUpn
| project AccountUpn, ClickCount, Urls, NetworkMessages
| order by ClickCount desc
```

### Query 9: Network Protection Events — AiTM Site Connection Attempts

Detects endpoint connections to known AiTM infrastructure blocked or audited by Network Protection.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "AiTM Network Connection: {{DeviceName}} → {{RemoteUrl}} ({{ResponseCategory}})"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
  - type: "user"
    identifier: "initiatingAccountName"
adaptation_notes: "Row-level events from DeviceEvents. The `has_any` filter on RemoteUrl for login/office keywords may be broad — tune for your environment. Change `Timestamp` to `TimeGenerated` for Sentinel Data Lake."
-->
```kql
// AiTM Infrastructure: Network protection events on endpoints
// Platform: Defender XDR Advanced Hunting
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("ExploitGuardNetworkProtectionAudited", 
    "ExploitGuardNetworkProtectionBlocked")
| extend ParsedFields = parse_json(AdditionalFields)
| extend RemoteUrl = tostring(ParsedFields.RemoteUrl)
| extend ResponseCategory = tostring(ParsedFields.ResponseCategory)
| where ResponseCategory in ("Phishing", "CustomBlockList", "MaliciousUrl")
    or RemoteUrl has_any ("login", "microsoftonline", "office", "outlook")
| project Timestamp, DeviceName, RemoteUrl, ResponseCategory, 
    ActionType, InitiatingProcessFileName,
    InitiatingProcessAccountName
| order by Timestamp desc
```

### Query 10: PIM Elevation Without Re-Authentication After AiTM

Checks if PIM role activation occurred after an AiTM-related risk detection — stolen tokens bypass PIM MFA because MFA claim is already in the session.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "PrivilegeEscalation"
title: "Post-AiTM PIM Activation: {{OperationName}} by compromised user"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
adaptation_notes: "Cross-table correlation (AADUserRiskEvents + AuditLogs). Same `has_any (AiTMUsers)` pattern as Q4. For large environments, consider limiting the `let` subquery."
-->
```kql
// Post-AiTM: PIM role activation with pre-existing MFA claim
// Platform: Sentinel Data Lake
let AiTMUsers = AADUserRiskEvents
| where TimeGenerated > ago(14d)
| where RiskEventType in ("anomalousToken", "attackerinTheMiddle")
| distinct UserPrincipalName;
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has "PIM" or OperationName has "role"
| where OperationName has "activation" or OperationName has "elevat"
| where tostring(InitiatedBy) has_any (AiTMUsers)
| project TimeGenerated, OperationName,
    InitiatedBy = tostring(InitiatedBy),
    TargetResources = tostring(TargetResources),
    Result
| order by TimeGenerated desc
```

### Query 11: SmartScreen AiTM Phishing Blocks

Tracks SmartScreen blocks on AiTM phishing pages across the fleet.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes by ResponseCategory with `make_set(DeviceName)` and `make_set(Users)`. Output is one row per category, not per event. Would need restructuring for row-level alerting."
-->
```kql
// SmartScreen: Phishing site blocks (potential AiTM prevention)
// Platform: Defender XDR Advanced Hunting  
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SmartScreenUrlWarning" 
    or ActionType == "SmartScreenExploitWarning"
| extend ParsedFields = parse_json(AdditionalFields)
| extend Experience = tostring(ParsedFields.Experience)
| extend ResponseCategory = tostring(ParsedFields.ResponseCategory)
| where Experience == "CustomBlockList" 
    or ResponseCategory in ("Phishing", "Malicious")
| project Timestamp, DeviceName, 
    InitiatingProcessAccountName,
    ResponseCategory, Experience, ActionType
| summarize BlockCount = count(), 
    Devices = make_set(DeviceName),
    Users = make_set(InitiatingProcessAccountName)
    by ResponseCategory
```

### Query 12: Comprehensive AiTM Alert Summary — Incident Correlation

Summarizes all AiTM-related alerts joined to incidents for SOC triage.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "SOC triage summary query — aggregates AiTM-related alerts into incident-level summaries. Uses SecurityAlert→SecurityIncident canonical join pattern. Output is one row per incident, not per alert event."
-->
```kql
// AiTM Alert Summary: All AiTM alerts with incident correlation
// Platform: Sentinel Data Lake
let AiTMAlerts = SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertName has_any ("AiTM", "adversary-in-the-middle",
    "Anomalous Token", "Stolen session cookie",
    "phishing attack", "cookie theft",
    "Attacker in the Middle", "session cookie was used")
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, 
    ProviderName, ProductName, Tactics;
SecurityIncident
| where CreatedTime > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner AiTMAlerts on $left.AlertId == $right.SystemAlertId
| summarize 
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    AlertNames = make_set(AlertName),
    AlertCount = dcount(SystemAlertId),
    CreatedTime = any(CreatedTime)
    by IncidentNumber
| order by CreatedTime desc
```

### Query 13: Post-AiTM Cloud App Reconnaissance  

Detects unusual cloud app activity patterns consistent with post-compromise reconnaissance — mailbox searches, SharePoint access, Azure subscription changes.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation aggregation query — summarizes per AccountObjectId per 1h bin with `make_set()` aggregations. Cross-table correlation (AlertInfo + CloudAppEvents) with `materialize()`. Output is one row per user per hour, not per event."
-->
```kql
// Post-AiTM: Cloud app reconnaissance and data access
// Platform: Defender XDR Advanced Hunting
let AiTMIncidentUsers = materialize(
AlertInfo
| where Timestamp > ago(7d)
| where Title has_any ("AiTM", "Anomalous Token", 
    "Stolen session cookie", "phishing attack")
| join AlertEvidence on AlertId
| where EntityType == "User"
| distinct AccountObjectId);
CloudAppEvents
| where Timestamp > ago(7d)
| where AccountObjectId in (AiTMIncidentUsers)
| where ActionType in ("MailItemsAccessed", "FileDownloaded", 
    "SearchQueryPerformed", "FileAccessed", "FilePreviewed",
    "Send", "MoveToDeletedItems", "SoftDelete",
    "New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
    "Add-MailboxPermission", "Set-Mailbox")
| summarize ActivityCount = count(),
    ActionTypes = make_set(ActionType),
    IPs = make_set(IPAddress),
    Countries = make_set(CountryCode)
    by AccountObjectId, bin(Timestamp, 1h)
| order by Timestamp desc
```

---

## Part 5: Response Playbook — Confirmed AiTM Compromise

When AiTM compromise is confirmed via alerts or hunting queries:

### Immediate Actions (0-30 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Revoke all sessions** | Entra Admin → User → Revoke sessions (invalidates all refresh tokens) |
| 2 | **Reset password** | Force password change (prevents credential reuse) |
| 3 | **Disable account** (if active attack) | Disable in Entra ID to stop all access immediately |
| 4 | **Review & remove suspicious MFA methods** | Check [aka.ms/mysecurityinfo](https://aka.ms/mysecurityinfo) — remove any attacker-registered FIDO2 keys, phone numbers, or authenticator apps |
| 5 | **Block attacker IPs** | Add to Named Locations → Block, or custom indicator in MDE |

### Investigation (30-120 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 6 | **Review inbox rules** | Check for ForwardTo, RedirectTo, MoveToFolder+MarkAsRead rules |
| 7 | **Check OAuth app consents** | Review Entra → Enterprise Apps → User consents for malicious apps |
| 8 | **Audit PIM activations** | Verify no privileged roles were activated with stolen session |
| 9 | **Check email activity** | Search for BEC activity — sent emails, read emails, deleted emails |
| 10 | **Review Azure resource changes** | Check for subscription modifications, new VMs, Entra ID changes |
| 11 | **Check SharePoint/OneDrive access** | Review file downloads, sharing activity |
| 12 | **Enrich attacker IPs** | Run `python enrich_ips.py <attacker_IPs>` for threat intelligence |

### Remediation (2-24 hours)

| Step | Action | Detail |
|------|--------|--------|
| 13 | **Remove malicious inbox rules** | Delete all forwarding/redirect rules created by attacker |
| 14 | **Remove unauthorized OAuth consents** | Revoke any malicious app registrations |
| 15 | **Block phishing domains** | Add to Defender for Endpoint custom indicators + Tenant Allow/Block List |
| 16 | **Notify affected users** | Inform users of compromise, phishing lure, and reset procedure |
| 17 | **Re-enable account** | After full remediation, re-enable with phishing-resistant MFA |
| 18 | **Report phishing domain** | Submit to Microsoft via Defender portal → Submit URL |

### Post-Incident (1-7 days)

| Step | Action |
|------|--------|
| 19 | Update Conditional Access policies based on gaps discovered |
| 20 | Accelerate phishing-resistant MFA rollout for affected user population |
| 21 | Review Attack Disruption effectiveness — did it fire? How fast? |
| 22 | Document lessons learned and update detection rules |

---

## Part 6: Maturity Assessment Checklist

Use this checklist to assess your organization's AiTM defense maturity:

### Level 1 — Basic (High Risk)
- [ ] MFA enabled for all users (any method)
- [ ] Defender for Office 365 Safe Links and Safe Attachments enabled
- [ ] Basic Conditional Access policies (require MFA)

### Level 2 — Intermediate (Moderate Risk)
- [ ] Phishing-resistant MFA for privileged accounts
- [ ] Device compliance required via Conditional Access
- [ ] Entra ID Identity Protection risk policies configured
- [ ] Defender for Cloud Apps connectors enabled (O365 + Azure)
- [ ] Attack Disruption prerequisites met

### Level 3 — Advanced (Low Risk)
- [ ] Phishing-resistant MFA for ALL users (not just admins)
- [ ] Token Protection enforced for supported apps
- [ ] Global Secure Access deployed with compliant network CA policy
- [ ] Web content filtering blocking newly registered domains
- [ ] Device code flow blocked
- [ ] Continuous Access Evaluation enabled with strict enforcement
- [ ] SmartScreen with bypass prevention enabled fleet-wide
- [ ] Active threat hunting with queries from this playbook

### Level 4 — Optimal (Minimal Risk)
- [ ] 100% phishing-resistant MFA (FIDO2/passkeys) — zero legacy MFA
- [ ] Universal CAE via Global Secure Access
- [ ] Automated response playbooks in Sentinel/Defender
- [ ] Regular AiTM simulation exercises (purple team with Evilginx)
- [ ] Lifecycle Workflows with TAP-based onboarding
- [ ] Verified ID for remote identity proofing

---

## References

### Microsoft Official Documentation
- [Protecting tokens in Microsoft Entra](https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id)
- [Phishing-resistant MFA (Secure Future Initiative)](https://learn.microsoft.com/security/zero-trust/sfi/phishing-resistant-mfa)
- [Token Protection in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection)
- [Automatic Attack Disruption](https://learn.microsoft.com/defender-xdr/automatic-attack-disruption)
- [Configure Attack Disruption](https://learn.microsoft.com/defender-xdr/configure-attack-disruption)
- [Session Cookie Theft Alert Playbook](https://learn.microsoft.com/defender-xdr/session-cookie-theft-alert)
- [Compliant Network Check (Global Secure Access)](https://learn.microsoft.com/entra/global-secure-access/how-to-compliant-network)
- [Universal Continuous Access Evaluation](https://learn.microsoft.com/entra/global-secure-access/concept-universal-continuous-access-evaluation)
- [Plan Phishing-Resistant Passwordless Deployment](https://learn.microsoft.com/entra/identity/authentication/how-to-plan-prerequisites-phishing-resistant-passwordless-authentication)
- [Enable Passkey/FIDO2](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-passkey-fido2)
- [Conditional Access Authentication Flows](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows)
- [Risk-Based Conditional Access Policies](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies)

### Community / Blog
- [Jeffrey Appel — AiTM/MFA Phishing Attacks with Microsoft Protections (2026 Edition)](https://jeffreyappel.nl/aitm-mfa-phishing-attacks-in-combination-with-new-microsoft-protections-2023-edt/)
- [Fabian Bader — Why FIDO2 Security Keys are Important](https://cloudbrothers.info/fido2-security-keys-are-important/)
- [Fabian Bader — Continuous Access Evaluation](https://cloudbrothers.info/continuous-access-evaluation/)
- [JumpSec — TokenSmith: Bypassing Compliant Device CA](https://labs.jumpsec.com/tokensmith-bypassing-intune-compliant-device-conditional-access/)

### Microsoft Threat Intelligence
- [Defeating Adversary-in-the-Middle Phishing Attacks](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/defeating-adversary-in-the-middle-phishing-attacks/1751777)
- [Multi-stage AiTM Phishing and BEC Campaign Abusing SharePoint (Jan 2026)](https://www.microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint/)
- [Detecting and Mitigating Multi-Stage AiTM Phishing and BEC Campaign](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/)
- [DEV-1101 High-Volume AiTM Campaigns](https://www.microsoft.com/en-us/security/blog/2023/03/13/dev-1101-enables-high-volume-aitm-campaigns-with-open-source-phishing-kit/)
