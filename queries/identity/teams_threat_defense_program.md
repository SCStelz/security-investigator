# Microsoft Teams — Threat Defense Program & Hunting Playbook

**Created:** 2026-02-12  
**Platform:** Both  
**Tables:** CloudAppEvents, MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo, UrlClickEvents, EmailEvents, DeviceProcessEvents, DeviceEvents, DeviceNetworkEvents, OfficeActivity, AuditLogs, SigninLogs, AADSignInEventsBeta, SecurityAlert, SecurityIncident, AlertInfo, AlertEvidence, IdentityLogonEvents  
**Keywords:** Teams, vishing, social engineering, tech support scam, email bombing, device code phishing, TeamsPhisher, DarkGate, Quick Assist, RMM, external access, guest access, federation, deepfake, Storm-1811, Storm-2372, Storm-1674, Storm-0324, Midnight Blizzard, Octo Tempest, Void Blizzard, Peach Sandstorm, Sangria Tempest, BRc4, ConvoC2, GraphRunner, AADInternals, TeamFiltration  
**MITRE:** T1566 (Phishing), T1566.003 (Phishing via Service), T1598 (Phishing for Information), T1534 (Internal Spearphishing), T1204 (User Execution), T1219 (Remote Access Software), T1078 (Valid Accounts), T1528 (Steal Application Access Token), T1550.001 (Application Access Token), T1136 (Create Account), T1098 (Account Manipulation), T1071 (Application Layer Protocol), T1567 (Exfiltration Over Web Service), T1087 (Account Discovery), T1069 (Permission Groups Discovery), T1106 (Native API), TA0001, TA0003, TA0005, TA0006, TA0007, TA0009, TA0010, TA0011  
**Timeframe:** Last 30 days (configurable)

---

## Executive Summary

Microsoft Teams is a high-value target for both cybercriminals and state-sponsored actors due to its extensive collaboration features and global enterprise adoption. Threat actors abuse Teams' core capabilities — **messaging (chat), calls/meetings, and video-based screen-sharing** — at different points along the attack chain.

This document synthesizes intelligence from [Microsoft's "Disrupting threats targeting Microsoft Teams" blog](https://www.microsoft.com/en-us/security/blog/2025/10/07/disrupting-threats-targeting-microsoft-teams/) (October 2025), official Microsoft Learn documentation, and observed threat actor TTPs to deliver:

1. **A structured attack taxonomy** mapping threat actor techniques to Teams features
2. **A prioritized defensive program** with actionable controls across identity, endpoint, Teams admin, and data layers
3. **KQL hunting queries** for both Sentinel Data Lake and Defender XDR Advanced Hunting
4. **A detection catalog** mapping built-in Microsoft Defender alerts to Teams threats
5. **A response playbook** for confirmed Teams-based compromise

### Key Threat Vectors

| Vector | Technique | Example Actors |
|--------|-----------|----------------|
| **Tech Support Vishing** | Email bombing → Teams call impersonating IT help desk → RMM tool install → Ransomware | Storm-1811, 3AM/BlackSuit affiliates |
| **Device Code Phishing** | Fake Teams meeting invite → Device code auth flow → Token capture → Persistent access | Storm-2372, Midnight Blizzard |
| **Malicious Chat/Files** | External chat with phishing links or DarkGate malware via TeamsPhisher | Storm-1674, Storm-0324, Sangria Tempest |
| **AiTM via Teams Branding** | Spoofed Teams notification → AiTM proxy login page → Session cookie theft | Storm-00485 |
| **Deepfake Social Engineering** | Video/audio deepfakes on Teams calls impersonating executives | Octo Tempest |
| **Post-Compromise C2** | BRc4, ConvoC2 using Teams messaging/webhooks as C2 channel | Various |
| **Data Collection/Exfil** | GraphRunner, AADInternals, TeamFiltration for chat/file exfiltration | Void Blizzard, Peach Sandstorm |

---

## Part 1: Teams Attack Chain Anatomy

### Full Attack Chain Mapped to Teams Features

```
1. 🔍 RECONNAISSANCE
   └─ Enumerate tenants, users, presence, federation config
   └─ Tools: TeamsEnum, MSFT-Recon-RS, ROADtools, Graph API
   └─ Presence status leaks user availability to external parties

2. 🔧 RESOURCE DEVELOPMENT
   └─ Compromise/purchase legitimate tenants for impersonation
   └─ Configure custom domains + branding to mimic IT/help desk
   └─ Create fake "Help Desk" / "Microsoft Security" display names

3. 📨 INITIAL ACCESS
   └─ Email bombing → Teams vishing call (Storm-1811 playbook)
   └─ Device code phishing via fake Teams meeting invites (Storm-2372)
   └─ TeamsPhisher to deliver DarkGate/JSSloader payloads
   └─ External chat with malicious links or file attachments
   └─ Fake Teams installer serving credential-stealing malware
   └─ AiTM phishing using Teams notification bait (Storm-00485)

4. 🔒 PERSISTENCE
   └─ Stolen OAuth refresh tokens for long-lived access
   └─ Guest user creation in target tenant
   └─ Adding attacker credentials to compromised Teams account
   └─ RMM tools (Quick Assist, AnyDesk) for backdoor access

5. ⚡ EXECUTION
   └─ Malicious links/files in chat → code execution
   └─ RMM/remote access tool installation via social engineering

6. 📈 PRIVILEGE ESCALATION
   └─ Compromised Teams admin → external communication manipulation
   └─ Permission group changes, trust relationship abuse

7. 🔑 CREDENTIAL ACCESS
   └─ Token theft via TeamFiltration OAuth flows
   └─ Password spraying → OAuth token request for Teams
   └─ MFA fatigue attacks (repeated auth prompts)
   └─ Social engineering help desk for MFA reset (Octo Tempest)

8. 🔎 DISCOVERY
   └─ AzureHound for Entra ID enumeration (Void Blizzard)
   └─ AD Explorer for on-prem AD snapshots (Peach Sandstorm)
   └─ Teams web client for conversation/message access
   └─ AADInternals for Teams group/permission discovery

9. ↔️ LATERAL MOVEMENT
   └─ Abusing external communication settings and trust relationships
   └─ VEILDrive: impersonating IT personnel cross-tenant

10. 📦 COLLECTION
    └─ Mine Teams chats for credentials, collaboration intel
    └─ GraphRunner to export all Teams conversations via Graph API
    └─ AADInternals to collect chat data and user profiles
    └─ Pivot from compromised account to OneDrive/SharePoint

11. 📡 COMMAND & CONTROL
    └─ BRc4 using Teams communications protocols for C2
    └─ ConvoC2 with Adaptive Cards embedding data in hidden spans
    └─ Legitimate remote access tools (Quick Assist, AnyDesk)

12. 📤 EXFILTRATION
    └─ TeamFiltration exfiltration module (chats + OneDrive/SharePoint)
    └─ Teams messages directing data to attacker-controlled cloud storage

13. 💥 IMPACT
    └─ Ransomware deployment post-RMM install
    └─ Extortion/threatening messages via Teams (Octo Tempest)
    └─ Financial theft through social engineering
```

### Known Threat Actors Targeting Teams

| Actor | Type | Primary Technique | Objective |
|-------|------|-------------------|-----------|
| **Storm-1811** | Financial | Email bombing + Teams vishing + Quick Assist → RMM → Ransomware | Ransomware deployment |
| **Storm-2372** | State-sponsored | Device code phishing via fake Teams meeting invites | Persistent access, espionage |
| **Storm-1674** | Financial | TeamsPhisher delivery of DarkGate malware | Access brokering |
| **Storm-0324** | Financial | TeamsPhisher delivery of JSSloader for Sangria Tempest | Ransomware access vector |
| **Storm-00485** | Financial | AiTM phishing using Teams branding | Credential/session theft |
| **Midnight Blizzard** | State (Russia) | Impersonating security/tech support for auth code capture | Espionage |
| **Octo Tempest** | Financial | Aggressive Teams-based social engineering of help desks | MFA takeover, ransomware |
| **Void Blizzard** | State (Russia) | Post-compromise Teams data collection via web client | Espionage |
| **Peach Sandstorm** | State (Iran) | Malicious ZIP files via Teams, AD Explorer snapshots | Intelligence gathering |
| **Sangria Tempest** | Financial | VEILDrive: cross-tenant Teams impersonation | Ransomware |
| **3AM/BlackSuit** | Financial | Storm-1811 playbook clone: email bomb + Teams vishing | Ransomware |

---

## Part 2: Defensive Program — Prioritized Actions

### 🔴 Tier 1 — Critical (Prevent Initial Access via Teams)

These controls **directly block** the most common Teams attack vectors.

#### 1.1 Restrict External Access and Federation

**Impact:** Eliminates the primary attack surface — external users initiating unsolicited chats and calls  
**Effort:** Low-Medium (policy change, minimal infrastructure)

| Action | Detail | Reference |
|--------|--------|-----------|
| Restrict external access to allowed domains only | Teams Admin Center → External access → Choose which domains to allow/block | [Manage external access](https://learn.microsoft.com/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings) |
| Block external communication with trial-only tenants | Prevents disposable tenant abuse for social engineering | [External access settings](https://learn.microsoft.com/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings) |
| Disable presence sharing with external users | Stops reconnaissance of user availability/status | [Presence in Teams](https://learn.microsoft.com/microsoftteams/presence-admins#presence-states-in-teams) |
| Disable anonymous users from starting conversations | Prevent unmanaged personas from initiating chat | [Anonymous users in meetings](https://learn.microsoft.com/microsoftteams/anonymous-users-in-meetings) |
| Require verification checks for meeting join | Anonymous/untrusted users must verify identity before joining | [Join verification check](https://learn.microsoft.com/microsoftteams/join-verification-check) |
| Configure lobby policies | Prevent external users from bypassing the meeting lobby | [Lobby policies](https://learn.microsoft.com/microsoftteams/who-can-bypass-meeting-lobby) |
| Restrict who can present and request control | Prevent external users from automatically requesting screen control | [Manage who can present](https://learn.microsoft.com/microsoftteams/meeting-who-present-request-control) |

> ⚠️ **Key insight from Microsoft blog:** Many threat actors (Storm-1674, Storm-0324, Sangria Tempest) depend on **unrestricted external access** to deliver malicious payloads via TeamsPhisher. Restricting external access to allowed domains is the single most impactful control.

#### 1.2 Block Device Code Authentication Flow

**Impact:** Prevents Storm-2372-style device code phishing — one of the most effective Teams-delivered attacks  
**Effort:** Low (Conditional Access policy)

| Action | Detail | Reference |
|--------|--------|-----------|
| CA Policy: Block device code flow for all users | Authentication flows → Device code flow → Block | [Authentication flows CA](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows#device-code-flow) |
| Exception: Conference room/IoT devices on specific named locations | Allow only for legitimate limited-input scenarios | Same |
| Monitor for device code auth attempts | Hunt for `DeviceCodeCredential` usage in SigninLogs | See Query 7 below |

> 🔴 **Storm-2372 (Feb 2025)** captured authentication tokens by masquerading as Teams meeting invitations and building rapport through Teams chats. When victims used Storm-2372-generated device codes, the attacker stole authenticated sessions via valid access tokens.

#### 1.3 Deploy Phishing-Resistant MFA

**Impact:** Prevents credential-based attacks (password spray → OAuth token, MFA fatigue, AiTM via Teams branding)  
**Effort:** Medium-High (credential lifecycle, user training)

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable passkey/FIDO2 authentication | Eliminates password spray + MFA fatigue attacks | [Enable FIDO2](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-passkey-fido2) |
| Enforce phishing-resistant MFA strength via CA | Use built-in "Phishing-resistant MFA" authentication strength | [MFA strength policy](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength) |
| Prioritize privileged accounts (Global Admin, Teams Admin) | Teams Admin compromise enables trust relationship abuse | [Plan prerequisites](https://learn.microsoft.com/entra/identity/authentication/how-to-plan-prerequisites-phishing-resistant-passwordless-authentication) |

#### 1.4 Disable or Remove Quick Assist (If Unused)

**Impact:** Removes the primary RMM tool abused in Storm-1811 vishing attacks  
**Effort:** Low (Intune policy)

| Action | Detail | Reference |
|--------|--------|-----------|
| Remove Quick Assist if your org uses Remote Help or another tool | Eliminates Storm-1811/3AM attack vector entirely | [Remote Help](https://www.microsoft.com/security/business/endpoint-management/microsoft-intune-remote-help) |
| If Quick Assist is needed, monitor its usage | Create detection rules for unexpected Quick Assist launches | See Query 9 below |

---

### 🟠 Tier 2 — High (Detect & Contain Teams-Based Attacks)

#### 2.1 Enable Defender for Office 365 Teams Protection

**Impact:** Direct threat scanning of Teams messages, links, and attachments  
**Effort:** Low (configuration in Defender portal)

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable Safe Links for Teams | Scans URLs in Teams messages at time of click | [Safe Links policies](https://learn.microsoft.com/defender-office-365/safe-links-policies-configure) |
| Enable Safe Attachments for SharePoint/OneDrive/Teams | Sandboxes files shared via Teams chat before access | [Safe Attachments for SPO/ODB/Teams](https://learn.microsoft.com/defender-office-365/safe-attachments-for-spo-odfb-teams-configure) |
| Configure Zero-hour Auto Purge (ZAP) for Teams | Retroactively removes malicious messages from Teams chats | [ZAP in Teams](https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge#zero-hour-auto-purge-zap-in-microsoft-teams) |
| Block downloads of detected malicious files | Use SharePoint Online PowerShell to prevent malicious file downloads | [Prevent malicious downloads](https://learn.microsoft.com/defender-office-365/safe-attachments-for-spo-odfb-teams-configure#step-2-recommended-use-sharepoint-online-powershell-to-prevent-users-from-downloading-malicious-files) |
| Create alert policies for detected files | Get notified when Safe Attachments detects malware in Teams files | [Alert policies](https://learn.microsoft.com/defender-xdr/alert-policies#default-alert-policies) |
| Configure quarantine policy for ZAP detections | Set appropriate quarantine handling for removed Teams messages | [Quarantine policies](https://learn.microsoft.com/defender-office-365/quarantine-policies) |

#### 2.2 Enable Defender for Cloud Apps Monitoring

**Impact:** Behavioral analytics, anomaly detection, and policy enforcement for Teams  
**Effort:** Low-Medium (connector configuration)

| Action | Detail | Reference |
|--------|--------|-----------|
| Connect Office 365 to Defender for Cloud Apps | Enables Teams activity monitoring in CloudAppEvents | [Connect Office 365](https://learn.microsoft.com/defender-cloud-apps/connect-office-365) |
| Select Microsoft 365 activities checkbox | Ensures CloudAppEvents is populated with Teams data | Defender portal → Settings → Cloud apps → App connectors |
| Enable App Governance | Detects OAuth app abuse involving Teams permissions | [App Governance](https://learn.microsoft.com/defender-cloud-apps/app-governance-get-started) |
| Create threat detection policies | Auto-detect sign-ins from risky locations, impossible travel, etc. | [Threat detection policies](https://learn.microsoft.com/defender-cloud-apps/policies-threat-protection) |
| Monitor for illicit consent grants | Detect apps requesting Teams-related Graph API permissions | [Detect illicit consent](https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants) |
| Monitor external user chat with activity policies | Defender for Cloud Apps can alert on external user Teams interactions | [Activity policies](https://learn.microsoft.com/defender-cloud-apps/user-activity-policies) |

#### 2.3 Enable Email Bombing Protection

**Impact:** Detects the precursor to many Teams vishing attacks  
**Effort:** Low (built-in Defender for Office 365 feature)

| Action | Detail | Reference |
|--------|--------|-----------|
| Verify email bombing detection is active | Defender for Office 365 detects mail bombing patterns | [Protection against email bombs](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/protection-against-email-bombs-with-microsoft-defender-for-office-365/4418048) |
| Configure alerts for email bombing detection | Ensure SOC is notified when email bombing is detected | See Query 3 below |
| Correlate email bombing with subsequent Teams calls | Hunt for the Storm-1811 pattern: bomb → vishing → RMM | See Query 4 below |

#### 2.4 Configure Identity Protection Risk Policies

**Impact:** Automatic response to anomalous Teams sign-in patterns and token theft  
**Effort:** Low

| Action | Detail | Reference |
|--------|--------|-----------|
| CA: Block at High user risk | Identity Protection → User risk policy → High → Block | [Configure risk policies](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies) |
| CA: Require MFA at Medium+ sign-in risk | Catches anomalous Teams logins, impossible travel, etc. | Same |
| Enable Continuous Access Evaluation (CAE) | Near-real-time token revocation — Teams is a supported cloud app | [CAE overview](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation) |
| Monitor "Anomalous Microsoft Teams login from web client" | Entra ID Protection detection specifically for Teams | [Risk detections](https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks) |

---

### 🟡 Tier 3 — Important (Defense-in-Depth & Hardening)

#### 3.1 Harden Endpoint Security

| Action | Detail | Reference |
|--------|--------|-----------|
| Enable Network Protection in block mode | Blocks connections to malicious infrastructure from Teams links | [Network protection](https://learn.microsoft.com/defender-endpoint/network-protection) |
| Enable Web Protection | URL filtering for Teams links opened in browser | [Web protection](https://learn.microsoft.com/defender-endpoint/web-protection-overview) |
| Enable cloud-delivered protection | Shares detection status between M365 and MDE | [Cloud-delivered protection](https://learn.microsoft.com/defender-endpoint/cloud-protection-microsoft-defender-antivirus) |
| Enable EDR in block mode | Post-breach detection even with non-Microsoft AV | [EDR in block mode](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/edr-in-block-mode) |
| Enable tamper protection | Prevent security settings from being disabled by attackers | [Tamper protection](https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection) |
| Keep Teams clients updated | Patch vulnerabilities in Teams desktop/mobile apps | [Teams client updates](https://learn.microsoft.com/microsoftteams/teams-client-update) |
| Use App Control (WDAC) over AppLocker | Control which executables can run alongside Teams | [App Control overview](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview) |
| Require device compliance via CA | Ensures only managed/compliant devices access Teams | [Device compliance CA](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance) |

#### 3.2 Enable Attack Surface Reduction (ASR) Rules

| ASR Rule | Relevance to Teams Threats | Reference |
|----------|---------------------------|-----------|
| Block Win32 API calls from Office macros | Prevents payload execution from Teams-delivered Office files | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-win32-api-calls-from-office-macros) |
| Block Office apps from injecting code | Prevents code injection from Teams-shared documents | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-office-applications-from-injecting-code-into-other-processes) |
| Block Office apps from creating executable content | Blocks executable drops from malicious Teams attachments | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-office-applications-from-creating-executable-content) |
| Block all Office apps from creating child processes | Prevents Office-based execution chains | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-all-office-applications-from-creating-child-processes) |
| Block credential stealing from LSASS | Prevents post-compromise credential theft | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-credential-stealing-from-the-windows-local-security-authority-subsystem) |
| Block persistence through WMI event subscription | Prevents post-RMM persistence mechanisms | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-persistence-through-wmi-event-subscription) |
| Block process creations from PSExec and WMI | Lateral movement prevention post-Teams compromise | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-process-creations-originating-from-psexec-and-wmi-commands) |
| Block JavaScript/VBScript from launching executables | Prevents script-based execution from Teams-delivered content | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-javascript-or-vbscript-from-launching-downloaded-executable-content) |
| Block use of copied/impersonated system tools | Prevents attacker use of tools like cmd.exe copies | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#block-use-of-copied-or-impersonated-system-tools) |
| Use advanced protection against ransomware | Last-resort protection against ransomware payloads | [ASR reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#use-advanced-protection-against-ransomware) |

#### 3.3 Secure Teams Apps and Data

| Action | Detail | Reference |
|--------|--------|-----------|
| Control Teams app installation per-app and per-user/group | Prevent unauthorized app installation | [App-centric management](https://learn.microsoft.com/microsoftteams/app-centric-management) |
| Evaluate app permissions before allowing | Review compliance, security, and data handling | [App permissions](https://learn.microsoft.com/microsoftteams/app-permissions) |
| Use sensitivity labels for Teams meetings | Classify and protect sensitive meeting content | [Sensitivity labels for meetings](https://learn.microsoft.com/microsoftteams/meeting-templates-sensitivity-labels-policies) |
| Enable end-to-end encryption for sensitive meetings | Teams Premium feature for heightened confidentiality | [E2E encryption](https://learn.microsoft.com/microsoftteams/enhanced-teams-experience) |
| Configure DLP for Teams chats/channels | Block sharing of sensitive information in Teams | [Purview DLP for Teams](https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description) |
| Manage SharePoint/OneDrive sharing settings | Control external sharing of Teams files | [Sharing settings](https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off) |
| Manage Teams recording policies | Control who can record meetings and town halls | [Recording policies](https://learn.microsoft.com/microsoftteams/meeting-recording) |
| Restrict external content sharing in meetings (Premium) | Prevent data leakage in meetings with external users | [Block external content share](https://learn.microsoft.com/microsoftteams/block-external-content-share) |

#### 3.4 Secure Guest Access

| Action | Detail | Reference |
|--------|--------|-----------|
| Review and restrict guest access settings | Limit what guests can do in Teams | [Guest access](https://learn.microsoft.com/microsoftteams/guest-access) |
| Secure external access with Entra ID | Apply CA policies to guest/external users | [Secure external access](https://learn.microsoft.com/entra/architecture/9-secure-access-teams-sharepoint) |
| Use PIM for Teams Admin role | Just-in-time access reduces standing privilege exposure | [PIM](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-getting-started) |
| Block inbound PSTN calls at tenant level (if not needed) | Prevents external phone-based vishing via Teams | [Block inbound calls](https://learn.microsoft.com/microsoftteams/block-inbound-calls) |

#### 3.5 Raise Security Awareness

| Action | Detail | Reference |
|--------|--------|-----------|
| Deploy attack simulation training for Teams | Teams attack simulation is in preview — enroll now | [Attack simulation training](https://learn.microsoft.com/defender-office-365/attack-simulation-training-get-started) |
| Train on QR code phishing, deepfakes, voice phishing | Specific threats targeting Teams users | [Teams attack simulation](https://learn.microsoft.com/defender-office-365/attack-simulation-training-teams) |
| Train on tech support scam recognition | Storm-1811 playbook relies on user trust of "help desk" calls | [Protect from tech support scams](https://support.microsoft.com/windows/protect-yourself-from-tech-support-scams-2ebf91bd-f94c-2a8a-e541-f5c800d18435) |
| Train on ClickFix social engineering | Users tricked into running PowerShell via clipboard | [ClickFix](https://security.microsoft.com/threatanalytics3/bdf0d0c5-f5f3-435a-b4a1-6e3beb73b5b9/analystreport) |
| Enable user reporting of suspicious Teams messages | Configure and customize reporting experience | [User reporting settings for Teams](https://learn.microsoft.com/defender-office-365/submissions-teams) |

#### 3.6 Auditing and Logging

| Action | Detail | Reference |
|--------|--------|-----------|
| Verify Microsoft Purview auditing is enabled | Required for forensic investigation of Teams incidents | [Enable auditing](https://learn.microsoft.com/purview/audit-log-enable-disable) |
| Review Teams audit log events | Familiarize with available Teams-specific events | [Teams audit log events](https://learn.microsoft.com/purview/audit-teams-audit-log-events) |
| Connect to Sentinel Data Lake | Ensure CloudAppEvents and Teams telemetry flow to Sentinel | [Sentinel Data Lake](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-lake-overview) |
| Enable SecOps for Teams false negative/positive management | Proactive management of misclassified Teams messages | [SecOps for Teams](https://learn.microsoft.com/defender-office-365/mdo-support-teams-sec-ops-guide) |

---

## Part 3: Detection & Alert Configuration

### Built-In Alerts That Detect Teams-Targeted Threats

Configure and verify all of these are active and generating incidents:

#### Microsoft Defender XDR

| Alert Name | Detection | Priority |
|-----------|-----------|----------|
| **Password Spray detected via suspicious Teams client (TeamFiltration)** | TeamFiltration tool usage for OAuth token harvesting | 🔴 Critical |
| **Malicious sign in from a risky IP address** | Risky sign-in correlated with Teams access | 🔴 Critical |
| **Malicious sign in from an unusual user agent** | Anomalous Teams client user agent | 🟠 High |
| **Account compromised following a password-spray attack** | End-to-end password spray → Teams access chain | 🟠 High |
| **Compromised user account identified in Password Spray activity** | Credential compromise affecting Teams user | 🟠 High |
| **Successful authentication after password spray attack** | Post-spray authentication success | 🟠 High |

#### Microsoft Defender for Office 365

| Alert Name | Detection | Priority |
|-----------|-----------|----------|
| **Malicious link shared in Teams chat** | URL threat detection in Teams messages | 🔴 Critical |
| **User clicked a malicious link in Teams chat** | Post-click detection of malicious Teams URL | 🔴 Critical |
| **Potentially Malicious IT Support Teams impersonation post mail bombing** | Storm-1811 playbook detection (email bomb + Teams vishing) | 🔴 Critical |
| **A potentially malicious URL click was detected** | Generic URL click detection (includes Teams) | 🟠 High |
| **Possible AiTM phishing attempt** | AiTM phishing via Teams branding | 🟠 High |

#### Microsoft Entra ID Protection

| Alert Name | Risk Type | Priority |
|-----------|-----------|----------|
| **Impossible travel** | Token replay from geographically distant location | 🟠 High |
| **Anomalous Microsoft Teams login from web client** | Teams-specific anomalous login detection | 🟠 High |

#### Microsoft Defender for Endpoint

| Alert Name | Detection | Priority |
|-----------|-----------|----------|
| **Suspicious module loaded using Microsoft Teams** | Malicious DLL sideloading via Teams process | 🔴 Critical |
| **Suspicious usage of remote management software** | Quick Assist/AnyDesk launched after Teams interaction | 🟠 High |

#### Microsoft Defender for Cloud Apps

| Alert Name | Detection | Priority |
|-----------|-----------|----------|
| **Consent granted to application with Microsoft Teams permissions** | OAuth app abuse targeting Teams | 🔴 Critical |
| **Risky user installed a suspicious application in Microsoft Teams** | Malicious app installation in Teams | 🔴 Critical |
| **Compromised account signed in to Microsoft Teams** | Compromised credential used for Teams access | 🟠 High |
| **Microsoft Teams chat initiated by a suspicious external user** | External social engineering attempt detection | 🟠 High |
| **Suspicious Teams access via Graph API** | Programmatic Teams access (GraphRunner, AADInternals) | 🟠 High |
| **Possible mail exfiltration by app** | OAuth app exfiltrating data via Teams/mail | 🟠 High |

#### Microsoft Defender for Identity

| Alert Name | Detection | Priority |
|-----------|-----------|----------|
| **Account enumeration reconnaissance** | Pre-attack enumeration of Teams-accessible accounts | 🟡 Medium |
| **Suspicious additions to sensitive groups** | Post-compromise privilege escalation | 🟠 High |
| **Account Enumeration reconnaissance (LDAP)** | LDAP-based enumeration (on-prem hybrid) | 🟡 Medium |

---

## Part 4: Hunting & Detection Queries

### Query 1: Detect Potential Data Exfiltration via Teams External Chat

Identifies users sending an unusually high volume of messages to external tenants in a short timeframe — potential data exfiltration or social engineering staging.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: Exfiltration
title: "High-volume Teams external messaging by {{SenderUPN}} to {{RecipientDomain}}"
impactedAssets:
  - type: user
    identifier: SenderUPN
recommendedActions: "Review the user's recent Teams chat activity and confirm whether external communication is authorized. Check for data exfiltration indicators."
responseActions:
  - "Revoke user sessions"
  - "Block external tenant in Teams Admin Center"
-->
```kql
// Teams Exfiltration: High-volume external messaging
// Platform: Defender XDR Advanced Hunting
// MITRE: T1567 (Exfiltration Over Web Service)
let timeWindow = 1h;
let messageThreshold = 20;
let trustedDomains = dynamic(["trustedpartner.com", "anothertrusted.com"]);
CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType == "MessageSent"
| where Application == "Microsoft Teams"
| where isnotempty(AccountObjectId)
| where tostring(parse_json(RawEventData).ParticipantInfo.HasForeignTenantUsers) == "true"
| where tostring(parse_json(RawEventData).CommunicationType) in ("OneOnOne", "GroupChat")
| extend RecipientDomain = tostring(parse_json(RawEventData).ParticipantInfo.ParticipatingDomains[1])
| where RecipientDomain !in (trustedDomains)
| extend SenderUPN = tostring(parse_json(RawEventData).UserId)
| summarize MessageCount = count()
    by bin(Timestamp, timeWindow), SenderUPN, RecipientDomain
| where MessageCount > messageThreshold
| project Timestamp, MessageCount, SenderUPN, RecipientDomain
| sort by MessageCount desc
```

### Query 2: Detect Malicious Teams Content via MessageEvents

Identifies phishing, malware, and spam content detected in Teams messages by Defender for Office 365.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: InitialAccess
title: "Malicious Teams content detected — {{ThreatTypes}} from {{SenderDisplayName}}"
impactedAssets:
  - type: mailbox
    identifier: SenderEmailAddress
adaptation_notes: "SenderEmailAddress identifies the threat source. Parse RecipientDetails to extract the targeted internal user for impactedAssets if needed."
-->
```kql
// Teams Content Threats: Phishing, malware, and spam in Teams messages
// Platform: Defender XDR Advanced Hunting
// MITRE: T1566.003 (Phishing via Service)
MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
    or ThreatTypes has "Malware"
    or ThreatTypes has "Spam"
| project Timestamp, SenderDisplayName, SenderEmailAddress,
    RecipientDetails, IsOwnedThread, ThreadType, 
    IsExternalThread, ThreatTypes, ReportId
| order by Timestamp desc
```

### Query 3: Detect Email Bombing Preceding Teams Vishing (Storm-1811 Pattern)

Detects the email bombing precursor that Storm-1811 and 3AM affiliates use before initiating Teams vishing calls.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: InitialAccess
title: "Email bombing detected targeting {{RecipientEmailAddress}}"
impactedAssets:
  - type: mailbox
    identifier: RecipientEmailAddress
recommendedActions: "Correlate with subsequent Teams calls or external chat activity (Storm-1811 pattern). Check for RMM tool installation."
-->
```kql
// Storm-1811 Precursor: Email bombing detection
// Platform: Defender XDR Advanced Hunting
// MITRE: T1566 (Phishing), T1204 (User Execution)
EmailEvents
| where Timestamp > ago(1d)
| where DetectionMethods contains "Mail bombing"
| project Timestamp, NetworkMessageId, SenderFromAddress, 
    RecipientEmailAddress, Subject, ReportId
| order by Timestamp desc
```

### Query 4: Email Bombing → Teams Interaction Correlation

Correlates email bombing victims with subsequent Teams chat activity from external users — the full Storm-1811 kill chain precursor.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: InitialAccess
title: "Storm-1811 pattern: email bomb victim {{TargetUPN}} contacted by external Teams user {{SenderDisplayName}}"
impactedAssets:
  - type: user
    identifier: TargetUPN
recommendedActions: "Confirm whether the user was social-engineered into installing RMM tools. Check DeviceProcessEvents for Quick Assist, AnyDesk, TeamViewer."
responseActions:
  - "Isolate device if RMM tool found"
  - "Revoke user sessions"
  - "Block attacker tenant in Teams Admin Center"
-->
```kql
// Storm-1811 Kill Chain: Email bombing → suspicious Teams chat
// Platform: Defender XDR Advanced Hunting
// MITRE: T1566, T1598 (Phishing for Information)
let EmailBombVictims = EmailEvents
| where Timestamp > ago(7d)
| where DetectionMethods contains "Mail bombing"
| distinct RecipientEmailAddress;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "ChatCreated"
| where tostring(parse_json(RawEventData).ParticipantInfo.HasForeignTenantUsers) == "true"
| where tostring(parse_json(RawEventData).CommunicationType) == "OneOnOne"
| extend TargetUPN = tostring(parse_json(RawEventData).Members[1].UPN)
| extend SenderDisplayName = tostring(parse_json(RawEventData).Members[0].DisplayName)
| where TargetUPN in~ (EmailBombVictims)
| project Timestamp, SenderDisplayName, TargetUPN,
    AccountObjectId, IPAddress, CountryCode
| order by Timestamp desc
```

### Query 5: Suspicious External Help Desk Impersonation in Teams

Detects external Teams chats where the sender impersonates IT support, help desk, or similar roles — a hallmark of Storm-1811, Midnight Blizzard, and Octo Tempest.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: InitialAccess
title: "External Teams help desk impersonation by {{SenderDisplayName}}"
impactedAssets:
  - type: mailbox
    identifier: SenderEmailAddress
adaptation_notes: "SenderEmailAddress is the external impersonator. RecipientDetails contains the internal victim but requires parsing for clean impactedAssets."
recommendedActions: "Verify whether internal users interacted with the external sender. Check for subsequent RMM tool installation or credential harvesting."
-->
```kql
// Social Engineering: External help desk impersonation in Teams
// Platform: Defender XDR Advanced Hunting
// MITRE: T1534 (Internal Spearphishing), T1598
MessageEvents
| where Timestamp > ago(5d)
| where IsExternalThread == true
| where (RecipientDetails contains "help" and RecipientDetails contains "desk")
    or (RecipientDetails contains "it" and RecipientDetails contains "support")
    or (RecipientDetails contains "working" and RecipientDetails contains "home")
    or (SenderDisplayName contains "help" and SenderDisplayName contains "desk")
    or (SenderDisplayName contains "it" and SenderDisplayName contains "support")
    or (SenderDisplayName contains "working" and SenderDisplayName contains "home")
    or SenderDisplayName has_any ("Microsoft Security", "Microsoft  Security",
        "Help Desk Team", "Help Desk IT", "IT Admin", "Tech Support")
| project Timestamp, SenderDisplayName, SenderEmailAddress, 
    RecipientDetails, IsOwnedThread, ThreadType
| order by Timestamp desc
```

### Query 6: Help Desk Impersonation → Process Execution Correlation

Extends Query 5 by joining external Teams help desk interactions with suspicious process executions on the target's device — detects the full vishing → RMM installation chain.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: Execution
title: "Vishing → RMM: {{FileName}} launched on {{DeviceName}} after help desk chat with {{VictimUPN}}"
impactedAssets:
  - type: device
    identifier: DeviceName
  - type: user
    identifier: VictimUPN
recommendedActions: "Isolate device immediately. Review DeviceProcessEvents timeline for post-RMM lateral movement, credential theft, and payload drops."
responseActions:
  - "Isolate device via MDE"
  - "Revoke user sessions"
  - "Block attacker tenant in Teams Admin Center"
  - "Kill RMM process"
-->
```kql
// Vishing → RMM: Help desk chat → suspicious process execution
// Platform: Defender XDR Advanced Hunting
// MITRE: T1219 (Remote Access Software), T1204 (User Execution)
let suspiciousRMM = dynamic([
    "QuickAssist.exe", "AnyDesk.exe", "anydesk.exe", 
    "TeamViewer.exe", "ScreenConnect.exe", 
    "ConnectWise.exe", "RustDesk.exe",
    "msra.exe", "ScreenConnect.ClientService.exe"]);
let timeAgo = ago(7d);
MessageEvents
| where Timestamp > timeAgo
| where IsExternalThread == true
| where (SenderDisplayName contains "help" and SenderDisplayName contains "desk")
    or (SenderDisplayName contains "it" and SenderDisplayName contains "support")
    or SenderDisplayName has_any ("Microsoft Security", "Help Desk Team", "Tech Support")
| extend VictimUPN = tostring(split(RecipientDetails, ",")[0])
| summarize FirstChat = min(Timestamp) by SenderEmailAddress, VictimUPN
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > timeAgo
    | where FileName in~ (suspiciousRMM)
        or ProcessCommandLine has_any ("QuickAssist", "AnyDesk", 
            "TeamViewer", "ScreenConnect", "ConnectWise", "RustDesk")
    ) on $left.VictimUPN == $right.InitiatingProcessAccountUpn
| where Timestamp > FirstChat
| where Timestamp < FirstChat + 2h // RMM launched within 2 hours of chat
| project ChatTime = FirstChat, RMMTime = Timestamp, 
    VictimUPN, SenderEmailAddress,
    DeviceName, FileName, ProcessCommandLine
| order by ChatTime desc
```

### Query 7: Device Code Phishing Attempts (Storm-2372 Pattern)

Detects device code authentication flow usage which is commonly abused via fake Teams meeting invitations.

<!-- cd-metadata
cd_ready: true
schedule: "12H"
category: CredentialAccess
title: "Device code authentication by {{UserPrincipalName}} from {{Country}}"
impactedAssets:
  - type: user
    identifier: UserPrincipalName
adaptation_notes: "Sentinel Data Lake query using SigninLogs. For CD, adapt to AADSignInEventsBeta with `LogonType == 'deviceCode'` and `Timestamp` column. See Query 20 for the AH equivalent."
recommendedActions: "Verify whether device code auth was legitimate (IoT/conference room scenario). If unexpected, revoke sessions and investigate for token theft."
-->
```kql
// Device Code Phishing: Suspicious device code auth attempts
// Platform: Sentinel Data Lake
// MITRE: T1528 (Steal Application Access Token)
SigninLogs
| where TimeGenerated > ago(14d)
| where AuthenticationProtocol == "deviceCode"
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend City = tostring(parse_json(LocationDetails).city)
| extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
| extend Browser = tostring(parse_json(DeviceDetail).browser)
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    IPAddress, Country, City, OS, Browser,
    ResultType, ResultDescription, 
    RiskLevelDuringSignIn, RiskState,
    ConditionalAccessStatus, AuthenticationRequirement
| order by TimeGenerated desc
```

### Query 8: Suspicious Teams Chat — External User One-on-One with Impersonation Keywords (Sentinel)

Sentinel-compatible version using CloudAppEvents to detect phishing and social engineering via Teams.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: InitialAccess
title: "External Teams impersonation chat targeting {{TargetUPN}} from {{SenderDisplayName}}"
impactedAssets:
  - type: user
    identifier: TargetUPN
recommendedActions: "Check if the internal user engaged with the external sender. Look for credential harvesting, file downloads, or RMM tool installation."
-->
```kql
// Teams Social Engineering: External one-on-one chats with impersonation
// Platform: Sentinel Data Lake (or Advanced Hunting)
// MITRE: T1534, T1598
CloudAppEvents
| where TimeGenerated > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "ChatCreated"
| where tostring(parse_json(RawEventData).ParticipantInfo.HasForeignTenantUsers) == "true"
| where tostring(parse_json(RawEventData).CommunicationType) == "OneOnOne"
| where tostring(parse_json(RawEventData).ParticipantInfo.HasGuestUsers) == "false"
| extend SenderDisplayName = tostring(parse_json(RawEventData).Members[0].DisplayName)
| extend TargetUPN = tolower(tostring(parse_json(RawEventData).Members[1].UPN))
| where SenderDisplayName has_any ("Microsoft Security", "Microsoft  Security",
    "Help Desk", "Help Desk Team", "Help Desk IT", "IT Support",
    "IT Admin", "Tech Support", "Security Team", "office")
| project TimeGenerated, SenderDisplayName, TargetUPN, 
    AccountObjectId, IPAddress, CountryCode
| order by TimeGenerated desc
```

### Query 9: Quick Assist and RMM Tool Usage Following Teams Activity

Detects RMM tool launches that occur within a short timeframe of Teams calls or meetings — the vishing → RMM installation chain.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: Execution
title: "RMM tool {{FileName}} launched after Teams activity on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Verify RMM launch was authorized. If unexpected, isolate device and review process timeline for lateral movement."
responseActions:
  - "Isolate device via MDE"
  - "Kill RMM process"
-->
```kql
// Vishing Detection: RMM tool launch after Teams activity
// Platform: Defender XDR Advanced Hunting
// MITRE: T1219 (Remote Access Software)
let suspiciousProcs = dynamic([
    "QuickAssist.exe", "AnyDesk.exe", "TeamViewer.exe",
    "ScreenConnect.exe", "ConnectWise.exe", "RustDesk.exe",
    "msra.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (suspiciousProcs)
    or ProcessCommandLine has_any ("QuickAssist", "AnyDesk", 
        "TeamViewer", "ScreenConnect", "RustDesk")
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has "teams.microsoft.com"
        or RemoteUrl has "teams.live.com"
    | summarize LastTeamsActivity = max(Timestamp) by DeviceName
) on DeviceName
| where isnotempty(LastTeamsActivity)
| where Timestamp between (LastTeamsActivity .. (LastTeamsActivity + 2h))
| project RMMTimestamp = Timestamp, DeviceName, 
    FileName, ProcessCommandLine,
    InitiatingProcessAccountName,
    LastTeamsActivity,
    TimeDelta = Timestamp - LastTeamsActivity
| order by RMMTimestamp desc
```

### Query 10: Teams File Uploads and Access Summary (Sentinel)

Tracks files uploaded to Teams Chat Files storage in SharePoint and their subsequent access patterns — detects potential data staging and collection.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "OfficeActivity (Sentinel-only) with self-join over 30 days for upload/access correlation. Summary/aggregation query with bag_pack and make_bag. Not suitable for direct CD."
-->
```kql
// Data Collection: Teams file uploads and access tracking
// Platform: Sentinel Data Lake
// MITRE: T1567 (Exfiltration Over Web Service), TA0009 (Collection)
OfficeActivity
| where TimeGenerated > ago(30d)
| where RecordType =~ "SharePointFileOperation"
| where Operation =~ "FileUploaded"
| where UserId != "app@sharepoint"
| where SourceRelativeUrl has "Microsoft Teams Chat Files"
| join kind=leftouter (
    OfficeActivity
    | where TimeGenerated > ago(30d)
    | where RecordType =~ "SharePointFileOperation"
    | where Operation =~ "FileDownloaded" or Operation =~ "FileAccessed"
    | where UserId != "app@sharepoint"
    | where SourceRelativeUrl has "Microsoft Teams Chat Files"
) on OfficeObjectId
| extend userBag = bag_pack(UserId1, ClientIP1)
| summarize make_set(UserId1, 10000), make_bag(userBag, 10000) 
    by TimeGenerated, UserId, OfficeObjectId, SourceFileName
| extend NumberUsers = array_length(bag_keys(bag_userBag))
| project timestamp = TimeGenerated, UserId, 
    FileLocation = OfficeObjectId, FileName = SourceFileName, 
    AccessedBy = bag_userBag, NumberOfUsersAccessed = NumberUsers
| order by NumberOfUsersAccessed desc
```

### Query 11: OAuth App Consent with Teams Permissions

Detects new OAuth app consent grants requesting Microsoft Teams or Microsoft Graph permissions related to Teams — potential malicious app installation.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "AuditLogs 30-day broad investigation query with dynamic field parsing. Broad `has 'consent'` filter returns high volume. For CD, narrow OperationName to specific consent operations and reduce timeframe to `ago(1d)`."
-->
```kql
// OAuth Abuse: App consent with Teams-related permissions
// Platform: Sentinel Data Lake
// MITRE: T1098 (Account Manipulation), T1550.001 (Application Access Token)
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "consent"
| where tostring(TargetResources) has_any ("Teams", "Microsoft Graph",
    "Chat.Read", "Chat.ReadWrite", "ChannelMessage",
    "TeamsActivity", "TeamsApp", "TeamSettings",
    "Team.ReadBasic", "Channel.ReadBasic")
| extend InitiatedByUPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend AppName = tostring(parse_json(tostring(TargetResources))[0].displayName)
| extend AppId = tostring(parse_json(tostring(TargetResources))[0].id)
| project TimeGenerated, OperationName, InitiatedByUPN, 
    AppName, AppId,
    Result, ResultDescription,
    TargetResources = tostring(TargetResources)
| order by TimeGenerated desc
```

### Query 12: Teams-Related Security Alert Summary with Incident Correlation

Summarizes all Teams-related alerts joined to incidents for SOC triage and trend analysis.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "SOC triage summary — multi-join SecurityAlert→SecurityIncident aggregation with make_set and dcount. Dashboard/reporting query, not a detection."
-->
```kql
// Teams Alert Summary: All Teams-related alerts with incident correlation
// Platform: Sentinel Data Lake
let TeamsAlerts = SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertName has_any (
    "Teams", "TeamFiltration",
    "IT Support", "mail bombing",
    "malicious link shared in Teams",
    "clicked a malicious link in Teams",
    "suspicious external user",
    "Teams permissions",
    "Teams impersonation",
    "Suspicious module loaded using Microsoft Teams",
    "suspicious application in Microsoft Teams",
    "Compromised account signed in to Microsoft Teams",
    "Suspicious Teams access via Graph API")
    or AlertName has_any (
    "device code", "anomalous token",
    "remote management software",
    "password spray")
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, 
    ProviderName, ProductName, Tactics;
SecurityIncident
| where CreatedTime > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner TeamsAlerts on $left.AlertId == $right.SystemAlertId
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

### Query 13: Suspicious Teams Access via Microsoft Graph API

Detects programmatic access to Teams data via Graph API — indicates potential use of GraphRunner, AADInternals, or custom exfiltration tools.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "AuditLogs 30-day broad investigation query. OperationName `has_any` with generic terms ('application', 'service principal', 'oauth') is too broad for scheduled detection. For CD, narrow to specific Graph API consent/app operations."
-->
```kql
// Graph API Abuse: Programmatic Teams data access
// Platform: Sentinel Data Lake
// MITRE: T1106 (Native API), TA0009 (Collection)
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("application", "service principal", "oauth")
| where tostring(TargetResources) has_any ("Teams", "Microsoft Graph")
| project TimeGenerated, OperationName,
    InitiatedBy = tostring(InitiatedBy),
    TargetResources = tostring(TargetResources),
    Result, ResultDescription
| order by TimeGenerated desc
```

### Query 14: Teams Meeting Join from Anomalous Locations

Detects users joining Teams meetings from locations that are anomalous compared to their baseline — potential token replay or compromised session.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "90-day baseline vs 7-day comparison for anomalous Teams meeting locations. Exceeds 30-day CD lookback limit. For CD, reduce baseline to `ago(30d)..ago(7d)` and use a shorter comparison window."
-->
```kql
// Anomalous Meeting Join: Teams access from unusual locations
// Platform: Sentinel Data Lake
// MITRE: T1550.001 (Application Access Token)
let TeamsAppIds = dynamic([
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264", // Microsoft Teams
    "5e3ce6c0-2b1f-4285-8d4b-75ee78787346", // Teams Web Client
    "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"  // Teams mobile
]);
let UserBaseline = SigninLogs
| where TimeGenerated between (ago(90d) .. ago(7d))
| where AppId in (TeamsAppIds)
| where ResultType == 0
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| summarize BaselineCountries = make_set(Country) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(7d)
| where AppId in (TeamsAppIds)
| where ResultType == 0
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend City = tostring(parse_json(LocationDetails).city)
| join kind=inner UserBaseline on UserPrincipalName
| where not(Country in (BaselineCountries))
| project TimeGenerated, UserPrincipalName, AppDisplayName,
    IPAddress, Country, City,
    BaselineCountries,
    RiskLevelDuringSignIn, ConditionalAccessStatus
| order by TimeGenerated desc
```

### Query 15: TeamsPhisher/DarkGate — External Chat Created with Process Execution

Detects the TeamsPhisher delivery pattern: external Teams chat creation followed by suspicious process execution on an alerted device.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: Execution
title: "TeamsPhisher pattern: external chat → {{FileName}} execution by {{TargetUPN}} on {{DeviceName}}"
impactedAssets:
  - type: user
    identifier: TargetUPN
  - type: device
    identifier: DeviceName
recommendedActions: "Isolate device. Review process chain for malware payload (DarkGate, JSSloader). Block attacker tenant."
responseActions:
  - "Isolate device via MDE"
  - "Revoke user sessions"
  - "Block attacker tenant in Teams Admin Center"
-->
```kql
// TeamsPhisher: External chat → malicious process execution chain
// Platform: Defender XDR Advanced Hunting
// MITRE: T1566.003 (Phishing via Service), T1204 (User Execution)
let suspiciousUpns = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("ms-teams.exe", "Teams.exe", "msteams.exe")
| where FileName !in~ ("ms-teams.exe", "Teams.exe", "msteams.exe",
    "chrome.exe", "msedge.exe", "firefox.exe")
| where isnotempty(InitiatingProcessAccountUpn)
| project InitiatingProcessAccountUpn, DeviceName, FileName, 
    ProcessCommandLine, Timestamp;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "ChatCreated"
| where tostring(parse_json(RawEventData).ParticipantInfo.HasForeignTenantUsers) == "true"
| where tostring(parse_json(RawEventData).CommunicationType) == "OneOnOne"
| extend TargetUPN = tolower(tostring(parse_json(RawEventData).Members[1].UPN))
| join kind=inner suspiciousUpns 
    on $left.TargetUPN == $right.InitiatingProcessAccountUpn
| where suspiciousUpns.Timestamp > Timestamp
| project ChatTime = Timestamp, ExecTime = suspiciousUpns.Timestamp,
    TargetUPN, DeviceName, FileName, ProcessCommandLine,
    IPAddress, CountryCode
| order by ChatTime desc
```

### Query 16: Teams URL Click-Through to Malicious Sites

Identifies users who clicked through malicious URLs shared in Teams messages.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: InitialAccess
title: "Malicious URL click-through in Teams by {{AccountUpn}} ({{ClickCount}} clicks)"
impactedAssets:
  - type: user
    identifier: AccountUpn
recommendedActions: "Check if the user's device was compromised post-click. Review endpoint timeline for payload execution."
-->
```kql
// Teams Phishing: Malicious URL click-throughs
// Platform: Defender XDR Advanced Hunting
// MITRE: T1204.001 (User Execution: Malicious Link)
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickAllowed" or IsClickedThrough != "0"
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| where Workload == "Teams" or Url has "teams"
| summarize ClickCount = count(),
    Urls = make_set(Url, 10),
    NetworkMessages = make_set(NetworkMessageId, 10)
    by AccountUpn
| project AccountUpn, ClickCount, Urls, NetworkMessages
| order by ClickCount desc
```

### Query 17: Teams ZAP Events — Retroactive Message Removal

Monitors Zero-hour Auto Purge (ZAP) activity in Teams to see what threats were caught after delivery.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ZAP remediation monitoring — tracks messages already removed by Defender. Informational/operational visibility, not a threat detection. Use for SOC dashboards."
-->
```kql
// Teams ZAP: Retroactive malicious message removal
// Platform: Defender XDR Advanced Hunting
MessagePostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("ZAP", "Quarantine", "Remove")
| project Timestamp, SenderDisplayName, SenderEmailAddress,
    RecipientDetails, ActionType, ThreatTypes,
    DeliveryLocation, ReportId
| order by Timestamp desc
```

### Query 18: Suspicious Module Loaded via Teams Process

Detects DLL sideloading or injection into the Teams process — a known endpoint attack technique.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: Execution
title: "Suspicious DLL {{FileName}} loaded via Teams on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Investigate the DLL origin and signing status. Check if Teams was trojanized or if this is a sideloading attempt."
responseActions:
  - "Isolate device via MDE"
  - "Collect DLL sample for analysis"
-->
```kql
// Teams DLL Sideload: Suspicious modules loaded by Teams
// Platform: Defender XDR Advanced Hunting
// MITRE: T1574.002 (DLL Side-Loading)
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("ms-teams.exe", "Teams.exe", "msteams.exe")
| where not(FolderPath startswith "C:\\Program Files")
| where not(FolderPath startswith "C:\\Windows\\System32")
| where not(FolderPath has "WindowsApps")
| where not(FolderPath has "Microsoft\\Teams")
| where FileName endswith ".dll"
| project Timestamp, DeviceName, FileName, FolderPath,
    SHA256, InitiatingProcessFileName,
    InitiatingProcessAccountName
| order by Timestamp desc
```

### Query 19: Cross-Tenant Teams Communication Anomalies

Identifies users with sudden spikes in cross-tenant Teams communication — potential indicator of compromised accounts being used for lateral movement or data exfiltration.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "30-day baseline vs 7-day comparison with daily rate calculation and anomaly factor. Aggregation per account with baseline ratio. For CD, simplify to a fixed threshold rather than baseline comparison."
-->
```kql
// Cross-Tenant Anomaly: Unusual external Teams communication volume
// Platform: Defender XDR Advanced Hunting
// MITRE: T1534 (Internal Spearphishing), T1567
let BaselineExternal = CloudAppEvents
| where Timestamp between (ago(30d) .. ago(7d))
| where Application == "Microsoft Teams"
| where ActionType in ("MessageSent", "ChatCreated")
| where tostring(parse_json(RawEventData).ParticipantInfo.HasForeignTenantUsers) == "true"
| summarize BaselineCount = count() by AccountObjectId
| extend AvgDaily = BaselineCount / 23.0; // 23 day window
let RecentExternal = CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType in ("MessageSent", "ChatCreated")
| where tostring(parse_json(RawEventData).ParticipantInfo.HasForeignTenantUsers) == "true"
| summarize RecentCount = count(),
    ExternalDomains = make_set(
        tostring(parse_json(RawEventData).ParticipantInfo.ParticipatingDomains[1]), 10),
    LastActivity = max(Timestamp)
    by AccountObjectId, AccountDisplayName;
RecentExternal
| join kind=leftouter BaselineExternal on AccountObjectId
| extend AvgDaily = coalesce(AvgDaily, 0.0)
| extend RecentDaily = RecentCount / 7.0
| where RecentDaily > AvgDaily * 3 or (AvgDaily == 0 and RecentCount > 10)
| project AccountDisplayName, RecentCount, RecentDaily, 
    AvgDaily, ExternalDomains, LastActivity,
    AnomalyFactor = iff(AvgDaily > 0, RecentDaily / AvgDaily, 999.0)
| order by AnomalyFactor desc
```

### Query 20: Device Code Phishing — Successful Device Code Auth with Risk Correlation (Advanced Hunting)

Detects successful device code authentications correlated with risk events — the Storm-2372 post-exploitation phase.

<!-- cd-metadata
cd_ready: true
schedule: "12H"
category: CredentialAccess
title: "Device code auth success by {{AccountUpn}} from {{Country}} — risk: {{RiskLevelDuringSignIn}}"
impactedAssets:
  - type: user
    identifier: AccountUpn
recommendedActions: "Verify device code auth was legitimate. If unexpected, revoke all sessions immediately and investigate for token theft."
responseActions:
  - "Revoke user sessions"
  - "Reset password"
  - "Review and remove suspicious MFA methods"
-->
```kql
// Storm-2372: Device code auth success + risk correlation
// Platform: Defender XDR Advanced Hunting
// MITRE: T1528 (Steal Application Access Token)
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where ErrorCode == 0
| where LogonType == "deviceCode"
| project Timestamp, AccountUpn, AccountObjectId,
    Application, ApplicationId,
    IPAddress, Country, City,
    DeviceName, SessionId,
    RiskLevelDuringSignIn, RiskState
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(14d)
    | where EntityType == "User"
    | distinct AccountObjectId, AlertId
    | join AlertInfo on AlertId
    | project AccountObjectId, AlertTitle = Title, AlertSeverity = Severity
) on AccountObjectId
| project Timestamp, AccountUpn, Application, 
    IPAddress, Country, City,
    RiskLevelDuringSignIn, RiskState,
    AlertTitle, AlertSeverity
| order by Timestamp desc
```

### Query 21: Teams C2 Channel Detection — Adaptive Card / Webhook Abuse

Detects potential C2 activity using Teams Adaptive Cards or incoming webhooks (ConvoC2 pattern).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: CommandAndControl
title: "Teams connector/bot activity: {{ActionType}} — {{AppName}} by {{AccountDisplayName}}"
impactedAssets:
  - type: user
    identifier: AccountDisplayName
adaptation_notes: "AccountDisplayName may not be a clean UPN. Consider adding AccountObjectId for entity mapping. Review AppName values to tune out legitimate connectors."
recommendedActions: "Verify the connector/bot/app is legitimate. Check for ConvoC2 indicators and Adaptive Card abuse."
-->
```kql
// C2 Detection: Suspicious Teams webhook and connector activity
// Platform: Defender XDR Advanced Hunting
// MITRE: T1071 (Application Layer Protocol), TA0011 (C&C)
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType in ("ConnectorAdded", "BotAddedToConversation",
    "AppInstalled", "TabAdded")
| extend RawData = parse_json(RawEventData)
| extend ConnectorType = tostring(RawData.AddOnType)
| extend AppName = tostring(RawData.AddOnName)
| project Timestamp, ActionType, AccountDisplayName,
    AccountObjectId, AppName, ConnectorType,
    IPAddress, CountryCode, IsExternalUser
| order by Timestamp desc
```

### Query 22: Comprehensive Teams Threat Activity Dashboard

Provides a high-level summary of all suspicious Teams activity across multiple dimensions for SOC dashboards.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "SOC dashboard summary — multi-let aggregation across 5 tables (CloudAppEvents, MessageEvents, UrlClickEvents, EmailEvents, DeviceProcessEvents) for overview metrics. Not a detection."
-->
```kql
// SOC Dashboard: Teams threat activity summary
// Platform: Defender XDR Advanced Hunting
let ExternalChats = CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "ChatCreated"
| where tostring(parse_json(RawEventData).ParticipantInfo.HasForeignTenantUsers) == "true"
| summarize ExternalChatsCreated = count();
let MaliciousMessages = MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes has_any ("Phish", "Malware", "Spam")
| summarize MaliciousTeamsMessages = count();
let URLClicks = UrlClickEvents
| where Timestamp > ago(7d)
| where ThreatTypes has_any ("Phish", "Malware")
| summarize MaliciousClicks = count();
let EmailBombs = EmailEvents
| where Timestamp > ago(7d)
| where DetectionMethods contains "Mail bombing"
| summarize EmailBombDetections = count();
let RMMActivity = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("QuickAssist.exe", "AnyDesk.exe", 
    "TeamViewer.exe", "ScreenConnect.exe")
| summarize RMMLaunches = count();
ExternalChats | extend Category = "External Chats Created"
| project Category, Count = ExternalChatsCreated
| union (MaliciousMessages | extend Category = "Malicious Teams Messages"
    | project Category, Count = MaliciousTeamsMessages)
| union (URLClicks | extend Category = "Malicious URL Clicks"
    | project Category, Count = MaliciousClicks)
| union (EmailBombs | extend Category = "Email Bombing Detections"
    | project Category, Count = EmailBombDetections)
| union (RMMActivity | extend Category = "RMM Tool Launches"
    | project Category, Count = RMMLaunches)
| order by Count desc
```

---

## Part 5: Response Playbook — Confirmed Teams-Based Compromise

### Scenario A: Tech Support Vishing (Storm-1811 / 3AM Pattern)

**Trigger:** Email bombing detected → Teams call from "Help Desk" → RMM tool installed

#### Immediate Actions (0-30 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Isolate the device** | MDE → Device page → Isolate device (allow Defender comms) |
| 2 | **Revoke all user sessions** | Entra Admin → User → Revoke sessions |
| 3 | **Reset user password** | Force password change |
| 4 | **Disable RMM tools** | Kill Quick Assist, AnyDesk, TeamViewer processes on device |
| 5 | **Block attacker tenant** | Teams Admin → External access → Block the external domain |

#### Investigation (30-120 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 6 | **Review MDE timeline** | Check for post-RMM lateral movement, credential theft, payload drops |
| 7 | **Check for persistence** | Startup folder, scheduled tasks, WMI subscriptions, registry Run keys |
| 8 | **Audit account activity** | Review AuditLogs for changes made during compromise window |
| 9 | **Check for ransomware indicators** | Look for encryption activity, ransom notes, shadow copy deletion |
| 10 | **Identify other targeted users** | Search email bombing and Teams chat patterns for broader campaign |
| 11 | **Enrich attacker IPs** | Run `python enrich_ips.py <attacker_IPs>` for threat intelligence |

### Scenario B: Device Code Phishing (Storm-2372 Pattern)

**Trigger:** Device code authentication with anomalous characteristics or risk detection

#### Immediate Actions (0-30 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Revoke all sessions** | Entra Admin → User → Revoke sessions (invalidates all tokens) |
| 2 | **Reset password** | Force password change |
| 3 | **Review & remove suspicious MFA methods** | Check for attacker-registered methods |
| 4 | **Block attacker IPs in Named Locations** | CA → Named locations → Block identified IPs |

#### Investigation (30-120 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 5 | **Review inbox rules** | Check for ForwardTo, RedirectTo rules (post-compromise BEC) |
| 6 | **Check OAuth app consents** | Review for malicious apps granted during session |
| 7 | **Review Teams chat/file activity** | Check for data exfiltration via Teams/OneDrive/SharePoint |
| 8 | **Check sign-in logs for token replay** | Look for same SessionId from multiple IPs/countries |
| 9 | **Verify CA policy coverage** | Ensure device code flow is now blocked for all users |

### Scenario C: TeamsPhisher/Malware Delivery

**Trigger:** Safe Links/Attachments detection in Teams or user report of suspicious Teams message

#### Immediate Actions (0-30 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Quarantine the message** | Defender portal → Submissions → Quarantine the Teams message |
| 2 | **Check if link/file was accessed** | Review UrlClickEvents and OfficeActivity for access |
| 3 | **Isolate affected devices** | If payload was executed, isolate via MDE |
| 4 | **Block the sending tenant** | Teams Admin → External access → Block domain |
| 5 | **Block malicious URLs/hashes** | Add to Tenant Allow/Block List and MDE custom indicators |

### Scenario D: Post-Compromise Data Collection (GraphRunner / AADInternals)

**Trigger:** Suspicious Graph API activity targeting Teams data or anomalous Teams web client access

#### Immediate Actions (0-30 minutes)

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Revoke all sessions** for compromised user | Entra Admin → User → Revoke sessions |
| 2 | **Review OAuth app registrations** | Entra → App registrations → Check for attacker-created apps |
| 3 | **Review Enterprise App consents** | Remove any suspicious app consents |
| 4 | **Audit Teams data access** | Review CloudAppEvents for chat export, file access patterns |

#### Post-Incident (All Scenarios — 1-7 days)

| Step | Action |
|------|--------|
| 1 | Review and tighten External Access settings based on attack vector |
| 2 | Update Teams Admin policies (lobby, presentations, guest access) |
| 3 | Deploy attack simulation training for Teams scenarios |
| 4 | Verify all detection alerts in Part 3 are active and generating incidents |
| 5 | Add attacker indicators (domains, IPs, hashes) to threat intelligence |
| 6 | Document lessons learned and update this playbook |

---

## Part 6: Maturity Assessment Checklist

Use this checklist to assess your organization's Teams threat defense maturity:

### Level 1 — Basic (High Risk)
- [ ] MFA enabled for all users (any method)
- [ ] Default Teams external access settings (no restrictions)
- [ ] Defender for Office 365 basic protection enabled
- [ ] Microsoft Purview auditing enabled

### Level 2 — Intermediate (Moderate Risk)
- [ ] External access restricted to allowed domains only
- [ ] Trial-only tenant communication blocked
- [ ] Device code flow blocked via Conditional Access
- [ ] Safe Links and Safe Attachments enabled for Teams
- [ ] ZAP for Teams configured
- [ ] Quick Assist removed or monitored (if unused)
- [ ] Defender for Cloud Apps connected with Office 365 connector
- [ ] Email bombing detection active
- [ ] Identity Protection risk policies configured (Medium+ sign-in risk)
- [ ] User reporting of suspicious Teams messages enabled

### Level 3 — Advanced (Low Risk)
- [ ] Phishing-resistant MFA for privileged accounts (Teams Admin, Global Admin)
- [ ] Lobby policies enforced for all meetings (no external bypass)
- [ ] Anonymous user verification required
- [ ] External users cannot present or request screen control
- [ ] Guest access restricted with appropriate governance
- [ ] All ASR rules enabled in block mode
- [ ] Network Protection in block mode
- [ ] Device compliance required via Conditional Access
- [ ] Continuous Access Evaluation (CAE) enabled
- [ ] Defender for Cloud Apps threat detection policies active
- [ ] Custom detection rules from hunting queries in this playbook
- [ ] PSTN inbound call blocking (if not needed)
- [ ] Meeting recording policies configured
- [ ] Teams app installation restricted per-app/per-user

### Level 4 — Optimal (Minimal Risk)
- [ ] Phishing-resistant MFA for ALL users (FIDO2/passkeys)
- [ ] External access limited to explicitly allowed domains with business justification
- [ ] Presence sharing with external users disabled
- [ ] End-to-end encryption for sensitive meetings (Teams Premium)
- [ ] Sensitivity labels and meeting templates deployed
- [ ] DLP policies for Teams chats/channels
- [ ] Attack simulation training for Teams scenarios deployed
- [ ] Active threat hunting with all queries from this playbook
- [ ] Automated response playbooks in Sentinel/Defender
- [ ] Regular Teams-focused purple team exercises
- [ ] App Control (WDAC) for endpoint hardening
- [ ] Global Secure Access with compliant network check

---

## References

### Microsoft Official Documentation
- [Teams Security Guide](https://learn.microsoft.com/microsoftteams/teams-security-guide)
- [Manage external access in Teams](https://learn.microsoft.com/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings)
- [Guest access in Teams](https://learn.microsoft.com/microsoftteams/guest-access)
- [Safe Attachments for SPO, OneDrive, and Teams](https://learn.microsoft.com/defender-office-365/safe-attachments-for-spo-odfb-teams-configure)
- [Safe Links policies](https://learn.microsoft.com/defender-office-365/safe-links-policies-configure)
- [Zero-hour Auto Purge (ZAP) in Teams](https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge#zero-hour-auto-purge-zap-in-microsoft-teams)
- [MDO Support for Teams — SecOps Guide](https://learn.microsoft.com/defender-office-365/mdo-support-teams-sec-ops-guide)
- [Configure Teams protection in Defender for Office 365](https://learn.microsoft.com/defender-office-365/mdo-support-teams-quick-configure)
- [User reporting settings for Teams messages](https://learn.microsoft.com/defender-office-365/submissions-teams)
- [Secure external access to Teams with Entra ID](https://learn.microsoft.com/entra/architecture/9-secure-access-teams-sharepoint)
- [Meeting and event policies](https://learn.microsoft.com/microsoftteams/meeting-policies-overview)
- [Join verification check](https://learn.microsoft.com/microsoftteams/join-verification-check)
- [Lobby policies](https://learn.microsoft.com/microsoftteams/who-can-bypass-meeting-lobby)
- [Manage who can present and request control](https://learn.microsoft.com/microsoftteams/meeting-who-present-request-control)
- [Block inbound calls](https://learn.microsoft.com/microsoftteams/block-inbound-calls)
- [Teams audit log events](https://learn.microsoft.com/purview/audit-teams-audit-log-events)
- [Teams app permissions](https://learn.microsoft.com/microsoftteams/app-permissions)
- [App-centric management in Teams](https://learn.microsoft.com/microsoftteams/app-centric-management)
- [Conditional Access: Authentication flows (device code)](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows#device-code-flow)
- [Continuous Access Evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Attack Simulation Training for Teams](https://learn.microsoft.com/defender-office-365/attack-simulation-training-teams)
- [Connect Office 365 to Defender for Cloud Apps](https://learn.microsoft.com/defender-cloud-apps/connect-office-365)
- [Detect and remediate illicit consent grants](https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants)
- [Compromised and malicious applications incident response playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-compromised-malicious-app)
- [Attack surface reduction rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
- [Network protection](https://learn.microsoft.com/defender-endpoint/network-protection)
- [Microsoft Sentinel Data Lake](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-lake-overview)
- [Advanced Hunting tables: MessageEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-messageevents-table)
- [Advanced Hunting tables: MessagePostDeliveryEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-messagepostdeliveryevents-table)
- [Advanced Hunting tables: MessageUrlInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-messageurlinfo-table)
- [Advanced Hunting tables: UrlClickEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-urlclickevents-table)
- [Advanced Hunting tables: CloudAppEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudappevents-table)
- [Presence in Teams](https://learn.microsoft.com/microsoftteams/presence-admins)

### Microsoft Threat Intelligence
- [Disrupting threats targeting Microsoft Teams (October 2025)](https://www.microsoft.com/en-us/security/blog/2025/10/07/disrupting-threats-targeting-microsoft-teams/)
- [Storm-2372 device code phishing campaign (February 2025)](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [Storm-1811 misusing Quick Assist (May 2024)](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/)
- [Octo Tempest multi-industry attacks (July 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/16/protecting-customers-from-octo-tempest-attacks-across-multiple-industries/)
- [Void Blizzard espionage targeting critical sectors (May 2025)](https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/)
- [Storm-0324/Sangria Tempest misusing App Installer (December 2023)](https://www.microsoft.com/en-us/security/blog/2023/12/28/financially-motivated-threat-actors-misusing-app-installer)
- [Peach Sandstorm deploys Tickler malware (August 2024)](https://www.microsoft.com/en-us/security/blog/2024/08/28/peach-sandstorm-deploys-new-custom-tickler-malware-in-long-running-intelligence-gathering-operations/)
- [Defending against evolving identity attack techniques — AiTM via Teams branding (May 2025)](https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/)
- [Protection against email bombs (Defender for Office 365)](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/protection-against-email-bombs-with-microsoft-defender-for-office-365/4418048)
- [Keys to the kingdom: RMM exploits enabling human-operated intrusions](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/keys-to-the-kingdom-rmm-exploits-enabling-human-operated-intrusions-in-2024%E2%80%9325/4410903)

### Community / External
- [3AM ransomware: vishing + Quick Assist (Sophos, May 2025)](https://news.sophos.com/en-us/2025/05/20/a-familiar-playbook-with-a-twist-3am-ransomware-actors-dropped-virtual-machine-with-vishing-and-quick-assist/)
- [DarkGate via Teams vishing (Trend Micro, December 2024)](https://www.trendmicro.com/en_us/research/24/l/darkgate-malware.html)
- [VEILDrive: Microsoft Services for C2 (Hunters, 2024)](https://www.hunters.security/en/blog/veildrive-microsoft-services-malware-c2)
- [Email bombing + Teams vishing ransomware campaigns (Sophos, January 2025)](https://news.sophos.com/en-us/2025/01/21/sophos-mdr-tracks-two-ransomware-campaigns-using-email-bombing-microsoft-teams-vishing/)
- [Fake Teams for Mac delivers Atomic Stealer (Malwarebytes, July 2025)](https://www.malwarebytes.com/blog/threat-intelligence/2024/07/fake-microsoft-teams-for-mac-delivers-atomic-stealer)
- [Inside the Microsoft Teams attack matrix (Cyberdom)](https://cyberdom.blog/inside-the-microsoft-teams-attack-matrix-unpacking-the-the-frontier-in-collaboration-threats/)
- [Dangerous functionalities in Teams (Proofpoint)](https://www.proofpoint.com/us/blog/threat-insight/dangerous-functionalities-in-microsoft-teams-enable-phishing)
- [CISA Secure Cloud Business Applications (SCuBA)](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)

### Attacker Tooling (For Awareness)
- [TeamsPhisher](https://github.com/Octoberfest7/TeamsPhisher) — Teams message delivery exploitation tool
- [TeamFiltration](https://github.com/Flangvik/TeamFiltration) — Teams enumeration, spraying, exfiltration
- [TeamsEnum](https://github.com/sse-secure-systems/TeamsEnum) — Teams/tenant enumeration
- [GraphRunner](https://github.com/dafthack/GraphRunner) — Post-compromise Teams/Graph data exfiltration
- [AADInternals](https://aadinternals.com/aadinternals/) — Azure AD admin tool (commonly abused)
- [ConvoC2](https://github.com/cxnturi0n/convoC2) — C2 via Teams Adaptive Cards
- [MSFT-Recon-RS](https://github.com/copyleftdev/msft-recon-rs) — Microsoft tenant reconnaissance
- [ROADtools](https://github.com/dirkjanm/ROADtools) — Azure AD exploration framework
