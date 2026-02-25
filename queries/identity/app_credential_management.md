# Application & Service Principal Credential Management Queries

**Created:** 2026-02-06  
**Platform:** Microsoft Sentinel  
**Tables:** AuditLogs  
**Keywords:** credential, secret, certificate, key, password, app registration, service principal, ownership, consent, permission, persistence, ApplicationManagement  
**MITRE:** T1098.001, T1136.003, T1550.001, TA0003  
**Timeframe:** Last 90 days (configurable)

---

## Overview

This collection of KQL queries monitors credential lifecycle events for Entra ID Application Registrations and Service Principals. These operations are high-value targets for attackers seeking persistence — adding a secret or certificate to an existing application grants long-lived, non-MFA access that bypasses Conditional Access policies.

**Key Detection Patterns:**
- Secrets or certificates added to existing applications (persistence)
- New application registrations with immediate credential provisioning
- Service principal credential rotation anomalies
- Ownership changes that precede credential modifications
- Consent grants and permission escalation

**Relevant AuditLogs Operation Names:**
| Operation | Meaning |
|-----------|---------|
| `Update application – Certificates and secrets management ` | Secret/cert added or removed on an App Registration |
| `Create application – Certificates and secrets management ` | New App Registration created with credential context |
| `Add service principal credentials` | Certificate/secret added directly to a Service Principal |
| `Remove service principal credentials` | Certificate/secret removed from a Service Principal |
| `Add application` | New App Registration created |
| `Update application` | App Registration properties modified |
| `Add owner to application` | Owner added (can then manage credentials) |
| `Add owner to service principal` | Owner added to SP |
| `Add delegated permission grant` | OAuth2 consent granted |
| `Consent to application` | Admin or user consent given |

**Important Notes:**
- `InitiatedBy` and `TargetResources` are **dynamic fields** — always wrap in `tostring()` before using `has`
- `OperationName` values may have trailing spaces (e.g., `"Update application – Certificates and secrets management "`)
- KeyType `Password` = client secret; KeyType `AsymmetricX509Cert` = certificate

---

## Query 1: All Credential Changes — Full Detail (PRIMARY AUDIT)

**Purpose:** Complete inventory of every secret/certificate add, update, or removal across all applications and service principals.

**Use this query to:**
- Audit all credential lifecycle events over 90 days
- Identify who added/removed credentials and on which apps
- Distinguish human-initiated changes from automated rotations
- Detect unexpected credential additions (persistence indicator)

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "App Credential Change: {{CredentialAction}} {{CredentialType}} on {{TargetName}} by {{Actor}}"
impactedAssets:
  - type: "user"
    identifier: "Actor"
adaptation_notes: "Reduce `ago(90d)` to `ago(1d)` or shorter for scheduled detection. Row-level output per credential change event. The `in~` filter list for OperationName includes trailing spaces — preserve them."
-->
```kql
// All Application & Service Principal Credential Changes (Last 90 Days)
// Shows actor, target, credential type, and what was added/removed
AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Create application – Certificates and secrets management ",
    "Add service principal credentials",
    "Remove service principal credentials"
  )
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend InitiatedByAppId = tostring(parse_json(tostring(InitiatedBy)).app.appId)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, strcat(InitiatedByApp, " (AppId: ", InitiatedByAppId, ")"))
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetName = tostring(Target.displayName)
| extend TargetId = tostring(Target.id)
| extend TargetType = tostring(Target.type)
| extend ModifiedProps = parse_json(tostring(Target.modifiedProperties))
| extend KeyDescription = tostring(ModifiedProps[0].newValue)
| extend OldKeyDescription = tostring(ModifiedProps[0].oldValue)
| extend CredentialAction = case(
    OperationName has "Remove", "🔴 Removed",
    OperationName has "Create", "🟢 Created",
    array_length(parse_json(KeyDescription)) > array_length(parse_json(OldKeyDescription)), "🟢 Added",
    array_length(parse_json(KeyDescription)) < array_length(parse_json(OldKeyDescription)), "🔴 Removed",
    "🔄 Modified")
| extend CredentialType = case(
    KeyDescription has "AsymmetricX509Cert", "Certificate",
    KeyDescription has "Password", "Client Secret",
    OldKeyDescription has "AsymmetricX509Cert", "Certificate",
    OldKeyDescription has "Password", "Client Secret",
    "Unknown")
| project
    TimeGenerated,
    OperationName,
    Result,
    Actor,
    TargetName,
    TargetType,
    CredentialAction,
    CredentialType,
    TargetId,
    CorrelationId
| order by TimeGenerated desc
```

**Expected Results:**
- `Actor`: Human UPN or system app name that performed the change
- `TargetName`: Application or Service Principal name affected
- `CredentialAction`: Whether a credential was Added, Removed, or Modified
- `CredentialType`: Certificate or Client Secret
- `CorrelationId`: Links related operations (e.g., remove old + add new during rotation)

**Indicators of Malicious Activity:**
- **Unknown actor adding credentials to high-privilege apps** — persistence via app credential
- **Credential added outside business hours** — stealth modification
- **Client secret added to app that previously only used certificates** — downgrade to weaker credential
- **Credential added by service principal, not a human** — possible automated persistence
- **Credential added but no corresponding removal** — accumulation of access methods

**Tuning:**
- Adjust timeframe: Change `ago(90d)` to desired lookback period
- Focus on human-initiated only: Add `| where isnotempty(InitiatedByUser)`
- Exclude known automation: Add `| where Actor !has "ConnectSyncProvisioning"`

---

## Query 2: Human vs Automated Credential Changes (Summary)

**Purpose:** Quick overview distinguishing human-initiated credential changes from automated service account rotations.

**Use this query to:**
- Identify which credential changes require analyst review
- Confirm automated rotations are following expected cadence
- Spot unexpected human actors modifying application credentials

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summary/aggregation query — summarizes per actor with `make_set()`, `dcount()`, and `count()`. Output is one row per actor, not per event. Use Q1 for event-level detection."
-->
```kql
// Summary: Human vs Automated Credential Changes (Last 90 Days)
AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Create application – Certificates and secrets management ",
    "Add service principal credentials",
    "Remove service principal credentials"
  )
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend ActorType = iff(isnotempty(InitiatedByUser), "Human", "Automated/Service")
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetName = tostring(Target.displayName)
| summarize
    TotalChanges = count(),
    DistinctTargets = dcount(tostring(Target.id)),
    Targets = make_set(TargetName, 10),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated),
    Operations = make_set(OperationName)
    by ActorType, Actor
| order by ActorType asc, TotalChanges desc
```

**Expected Results:**
- Rows grouped by `ActorType` (Human vs Automated)
- `TotalChanges`: Count of credential operations per actor
- `Targets`: Applications/SPs affected by each actor
- `Operations`: Types of credential operations performed

**What to Look For:**
- **Unfamiliar human actors** — who is managing app credentials in your tenant?
- **Automated actors with unusually high counts** — possible runaway automation
- **Human actors modifying first-party Microsoft apps** — should be rare and reviewed

---

## Query 3: New Application Registrations with Full Context

**Purpose:** Detect new application registrations — the first step in establishing app-based persistence.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "New App Registration: {{AppName}} created by {{Actor}}"
impactedAssets:
  - type: "user"
    identifier: "Actor"
adaptation_notes: "Reduce `ago(90d)` to `ago(1d)` for scheduled detection. Row-level output per new app registration event."
-->
```kql
// New Application Registrations (Last 90 Days)
// Includes who created them and what permissions/credentials were set up
AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "ApplicationManagement"
| where OperationName =~ "Add application"
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend AppName = tostring(Target.displayName)
| extend AppId = tostring(Target.id)
| extend ModifiedProps = parse_json(tostring(Target.modifiedProperties))
| project
    TimeGenerated,
    Actor,
    AppName,
    AppId,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

**Follow-Up:** After identifying new apps, check if credentials were immediately provisioned by correlating the `CorrelationId` with credential management operations:

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "New App with Immediate Credential: {{AppName}} — credential added {{TimeDelta}}s after creation"
impactedAssets:
  - type: "user"
    identifier: "AppName"
adaptation_notes: "Multi-let correlation query: new app registration joined with credential operations within 5 minutes. Reduce `ago(90d)` to `ago(1d)` for scheduled detection. High-signal — scripted persistence setup."
-->
```kql
// Check if new apps received credentials at creation time
let NewApps = AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName =~ "Add application"
| extend Target = parse_json(tostring(TargetResources))[0]
| project AppId = tostring(Target.id), AppName = tostring(Target.displayName), CreatedTime = TimeGenerated, CorrelationId;
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName has "Certificates and secrets management"
| extend Target = parse_json(tostring(TargetResources))[0]
| extend AppId = tostring(Target.id)
| join kind=inner NewApps on AppId
| where abs(datetime_diff('minute', TimeGenerated, CreatedTime)) <= 5
| project
    CreatedTime,
    AppName,
    CredentialOperation = OperationName,
    CredentialTime = TimeGenerated,
    TimeDelta = datetime_diff('second', TimeGenerated, CreatedTime),
    CorrelationId
| order by CreatedTime desc
```

**Indicators of Suspicious App Creation:**
- **App created by non-admin user** — may indicate compromised account or insider threat
- **Credential added within seconds of creation** — scripted/automated persistence setup
- **Generic or obfuscated app names** — attacker trying to blend in
- **App created outside business hours** — stealth creation

---

## Query 4: Application Ownership Changes

**Purpose:** Detect when owners are added to applications — owners can manage credentials, making this a privilege escalation vector.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "PrivilegeEscalation"
title: "App Ownership Change: {{NewOwner}} added to {{TargetName}} by {{Actor}}"
impactedAssets:
  - type: "user"
    identifier: "Actor"
adaptation_notes: "Reduce `ago(90d)` to `ago(1d)` for scheduled detection. Row-level output per ownership change event. High-signal when followed by credential modifications (see follow-up query)."
-->
```kql
// Application & Service Principal Ownership Changes (Last 90 Days)
AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "ApplicationManagement"
| where OperationName in~ ("Add owner to application", "Add owner to service principal")
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetName = tostring(Target.displayName)
| extend TargetType = tostring(Target.type)
| extend ModifiedProps = parse_json(tostring(Target.modifiedProperties))
| extend NewOwner = tostring(ModifiedProps[0].newValue)
| project
    TimeGenerated,
    OperationName,
    Actor,
    TargetName,
    TargetType,
    NewOwner,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

**Why This Matters:**
- App owners can add credentials, modify redirect URIs, and manage permissions
- Attacker adds themselves as owner → adds credential → gains persistent access
- Look for ownership changes followed by credential additions (correlate via `TargetName`)

**Follow-Up:** Cross-reference ownership changes with subsequent credential modifications:

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "Persistence"
title: "Ownership→Credential Chain: {{TargetName}} — owner added by {{OwnerAddedBy}}, credential changed by {{CredentialChangeBy}} {{DaysAfterOwnerChange}}d later"
impactedAssets:
  - type: "user"
    identifier: "OwnerAddedBy"
  - type: "user"
    identifier: "CredentialChangeBy"
adaptation_notes: "Multi-let correlation query: ownership change joined with credential modification within 7 days on same app. Very high-signal for persistence via app takeover. Reduce `ago(90d)` to `ago(7d)` for scheduled detection."
-->
```kql
// Ownership change followed by credential change on same app (Last 90 Days)
let OwnerChanges = AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in~ ("Add owner to application", "Add owner to service principal")
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetName = tostring(Target.displayName)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| project OwnerAddedTime = TimeGenerated, TargetName, OwnerAddedBy = InitiatedByUser;
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName has "Certificates and secrets management" or OperationName has "credentials"
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetName = tostring(Target.displayName)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| join kind=inner OwnerChanges on TargetName
| where TimeGenerated > OwnerAddedTime
| where datetime_diff('day', TimeGenerated, OwnerAddedTime) <= 7
| project
    OwnerAddedTime,
    TargetName,
    OwnerAddedBy,
    CredentialChangeTime = TimeGenerated,
    CredentialChangeBy = InitiatedByUser,
    OperationName,
    DaysAfterOwnerChange = datetime_diff('day', TimeGenerated, OwnerAddedTime)
| order by OwnerAddedTime desc
```

---

## Query 5: Consent Grants & Permission Changes

**Purpose:** Monitor OAuth2 consent grants and delegated permission changes — attackers use illicit consent grants to access data.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Consent/Permission Change: {{OperationName}} on {{TargetName}} by {{Actor}}"
impactedAssets:
  - type: "user"
    identifier: "Actor"
adaptation_notes: "Reduce `ago(90d)` to `ago(1d)` for scheduled detection. Row-level output per consent/permission event. Covers illicit consent grant attack (T1550.001)."
-->
```kql
// Consent Grants & Permission Changes (Last 90 Days)
AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Add delegated permission grant",
    "Remove delegated permission grant",
    "Consent to application",
    "Add app role assignment to service principal",
    "Remove app role assignment from service principal"
  )
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetName = tostring(Target.displayName)
| extend ModifiedProps = parse_json(tostring(Target.modifiedProperties))
| extend PermissionDetails = tostring(ModifiedProps)
| project
    TimeGenerated,
    OperationName,
    Actor,
    TargetName,
    Result,
    PermissionDetails,
    CorrelationId
| order by TimeGenerated desc
```

**Indicators of Illicit Consent Grant (T1550.001):**
- **Consent granted to unknown/external application** — phishing-based consent attack
- **High-privilege permissions (Mail.Read, Files.ReadWrite.All)** — data exfiltration capability
- **User-consented app with broad scope** — should be admin-consented only
- **Consent followed by immediate data access** — correlate with sign-in logs

---

## Query 6: All ApplicationManagement Activity — Operation Breakdown

**Purpose:** High-level summary of all application management operations for baselining normal activity.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summary/aggregation query — summarizes by OperationName with `count()`, `dcount()`, `countif()`. Output is one row per operation type, not per event. Use for baselining, not detection."
-->
```kql
// ApplicationManagement Operation Summary (Last 90 Days)
AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "ApplicationManagement"
| summarize
    Count = count(),
    SuccessCount = countif(Result == "success"),
    FailureCount = countif(Result == "failure"),
    Actors = dcount(coalesce(
        tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName),
        tostring(parse_json(tostring(InitiatedBy)).app.displayName)
    )),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by OperationName
| extend FailureRate = round((FailureCount * 100.0) / Count, 1)
| order by Count desc
```

**Use this for:**
- Establishing baseline of normal application management volume
- Identifying unusual operations or spikes
- Confirming expected automated operations are running
- Spotting failed operations that may indicate unauthorized attempts

---

## Query 7: Credential Expiry Risk — Apps with Credentials Approaching Expiration

**Purpose:** Use Microsoft Graph API to identify applications with secrets/certificates nearing expiration. This is a Graph API query, not KQL — use with the Graph MCP tool.

**Graph API Approach:**

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Graph API query, not KQL — cannot be deployed as a custom detection. Use with the Graph MCP tool for point-in-time credential inventory."
-->
```
GET /v1.0/applications?$select=displayName,appId,passwordCredentials,keyCredentials
```

Then check `passwordCredentials[].endDateTime` and `keyCredentials[].endDateTime` against current date.

**Note:** AuditLogs only capture credential *changes*, not current credential state. For a point-in-time inventory of active credentials and their expiry dates, use Graph API.

---

## Detection Rule Deployment

### Recommended Scheduled Analytics Rules

**Rule 1: Credential Added to Application by Non-Automated Actor**

- **Query:** Query 1 filtered to `| where isnotempty(InitiatedByUser)`
- **Schedule:** Every 15 minutes, lookup last 20 minutes
- **Severity:** Medium
- **Entity Mappings:** Account → Actor, CloudApplication → TargetName
- **Tactics:** Persistence (T1098.001)

**Rule 2: Ownership Change Followed by Credential Modification**

- **Query:** Query 4 follow-up query (ownership → credential correlation)
- **Schedule:** Every 1 hour, lookup last 2 hours
- **Severity:** High
- **Entity Mappings:** Account → OwnerAddedBy, CloudApplication → TargetName
- **Tactics:** Persistence, Privilege Escalation

**Rule 3: New Application Registration**

- **Query:** Query 3 (new app registrations)
- **Schedule:** Every 30 minutes, lookup last 35 minutes
- **Severity:** Informational (Medium if credentials added at creation)
- **Entity Mappings:** Account → Actor, CloudApplication → AppName
- **Tactics:** Persistence (T1136.003)

---

## Tuning Recommendations

### Reducing False Positives

1. **Exclude known automated service accounts:**
   ```kql
   | where Actor !has "ConnectSyncProvisioning"
   | where Actor !has "Device Registration Service"
   | where Actor !has "Power Virtual Agents Service"
   ```

2. **Focus on human-initiated changes only:**
   ```kql
   | where isnotempty(tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName))
   ```

3. **Exclude specific known-good applications:**
   ```kql
   | where TargetName !in ("<YourConnectSyncApp>", "<YourPasswordProtectionProxy>")
   ```

### Increasing Detection Sensitivity

1. **Include all ApplicationManagement operations:**
   ```kql
   | where Category == "ApplicationManagement"
   // Remove OperationName filter to see everything
   ```

2. **Alert on any credential added to first-party Microsoft apps:**
   ```kql
   | where TargetName has_any ("Microsoft", "Office", "Azure", "Graph")
   ```

---

## Investigation Workflow

When a credential change alert fires:

1. **Identify the actor:**
   - Is this a known admin or service account?
   - Check sign-in logs for the actor around the same time — were they compromised?

2. **Examine the target application:**
   - What permissions does this app have? (Check Graph API: `/v1.0/applications/{id}?$select=requiredResourceAccess`)
   - Does this app have access to sensitive data (Mail, Files, Directory)?

3. **Check for lateral activity:**
   - Did the actor make other changes in the same session? (Correlate by `CorrelationId`)
   - Were permissions/consent grants added around the same time? (Query 5)

4. **Verify credential type:**
   - Client secrets expire (max 2 years) — lower risk if short-lived
   - Certificates can be long-lived — higher risk for persistence

5. **Response actions:**
   - If unauthorized: Remove the credential immediately via Azure Portal or Graph API
   - Revoke sign-in sessions for the actor: `Revoke-MgUserSignInSession`
   - Review Conditional Access: Ensure workload identity policies cover the app
   - If app owner was compromised: Remove ownership, rotate all app credentials

---

## Additional Resources

**Microsoft Documentation:**
- [Application and service principal objects in Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals)
- [Monitor app credential changes](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/recommendation-remove-unused-credential-from-apps)
- [Workload identity protection](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview)

**MITRE ATT&CK:**
- [T1098.001 - Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [T1136.003 - Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)
- [T1550.001 - Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)

---

## Version History

- **v1.0 (2026-02-06):** Initial query collection created
  - 7 queries covering credential lifecycle, ownership, consent, and baselining
  - All queries verified against live Sentinel AuditLogs
  - Schema validated: `InitiatedBy` and `TargetResources` use `tostring()` + `parse_json()` pattern
  - Known pitfall documented: OperationName trailing spaces
