# CloudAppEvents Exploration - Microsoft Sentinel Queries

**Created:** 2026-01-13  
**Platform:** Microsoft Sentinel  
**Tables:** CloudAppEvents  
**Keywords:** cloud app, Office 365, Azure AD, AWS, external user, admin activity, impersonation, anonymous proxy, geographic anomaly, baseline  
**MITRE:** T1078, T1199, TA0001, TA0009  
**Timeframe:** Last 7 days (configurable)

---

## Overview

This query collection helps security analysts understand the types of events, activity patterns, and security indicators within the CloudAppEvents table. CloudAppEvents captures activities from Office 365, Azure AD, AWS, and other cloud applications integrated with Microsoft Defender for Cloud Apps.

**Key Use Cases:**
- Cloud application activity baseline establishment
- External user access monitoring
- Administrative operation tracking
- Geographic anomaly detection
- Impersonation and anonymous proxy detection

**Schema Note:** In Sentinel, CloudAppEvents uses `TimeGenerated` for timestamps (not `Timestamp` as in Defender XDR Advanced Hunting).

---

## Query 1: Top 20 Action Types by Frequency

**Purpose:** Discover the most common actions occurring in your cloud applications to establish baseline activity patterns.

**Use Case:** Understanding normal vs. anomalous action types; identifying unexpected spikes in specific operations.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation query — summarizes action type frequency across all events. No row-level alert logic or identifiable impacted assets."
-->
```kql
// Top 20 action types by frequency (last 7 days)
CloudAppEvents
| where TimeGenerated > ago(7d)
| summarize EventCount = count() by ActionType
| order by EventCount desc
| take 20
```

**Expected Results:**
- `ActionType` (string): Specific action performed (e.g., "Set-ConditionalAccessPolicy", "MailItemsAccessed")
- `EventCount` (long): Number of occurrences

**What to Look For:**
- ✅ Conditional Access policy changes (monitor for unauthorized modifications)
- ✅ Incident management actions (Write Comments, AddCommentToIncident)
- ✅ KQL query executions (analyst activity tracking)
- ⚠️ Unusual spikes in privileged operations

**Example Output:**
```
ActionType                      EventCount
Set-ConditionalAccessPolicy     1633
Write Comments                  745
UnAssignUserFromIncident        421
KQLQueryCompleted               296
```

---

## Query 2: Application Distribution

**Purpose:** Identify which cloud applications generate the most events and track unique user engagement per application.

**Use Case:** Understanding cloud app adoption; detecting shadow IT; monitoring application usage patterns.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation query — summarizes event and user counts per application. No row-level detection or threshold-based alerting."
-->
```kql
// Application distribution - which cloud apps generate most events
CloudAppEvents
| where TimeGenerated > ago(7d)
| summarize EventCount = count(), UniqueUsers = dcount(AccountObjectId) by Application
| order by EventCount desc
```

**Expected Results:**
- `Application` (string): Cloud application name (e.g., "Microsoft 365", "Amazon Web Services")
- `EventCount` (long): Total events from this app
- `UniqueUsers` (long): Distinct users accessing the app

**What to Look For:**
- ✅ Unexpected applications (shadow IT)
- ✅ Low user count but high event count (potential automation or service account abuse)
- ⚠️ New third-party apps not in approved list

**Example Output:**
```
Application                      EventCount  UniqueUsers
Microsoft 365                    2792        3
Microsoft Exchange Online        1818        1
Microsoft Azure                  1280        2
Amazon Web Services              208         1
```

---

## Query 3: Activity Types Breakdown

**Purpose:** Understand high-level activity categories with sample actions to classify event types.

**Use Case:** Categorizing events into buckets (Basic operations, Administrative, User interactions); building detection rules by activity type.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation query — categorizes events by ActivityType. Exploration tool for understanding event composition, not a detection."
-->
```kql
// Activity types breakdown with sample action types
CloudAppEvents
| where TimeGenerated > ago(7d)
| summarize EventCount = count(), SampleActions = make_set(ActionType, 5) by ActivityType
| order by EventCount desc
```

**Expected Results:**
- `ActivityType` (string): High-level category (e.g., "Basic", "Run", "Edit", "Add")
- `EventCount` (long): Events in this category
- `SampleActions` (dynamic array): Up to 5 example action types

**What to Look For:**
- ✅ "Run" activities (privileged operations execution)
- ✅ "Edit" activities (configuration changes)
- ✅ "Add" activities (new objects created)
- ⚠️ Unusual activity types for user accounts

**Example Output:**
```
ActivityType           EventCount  SampleActions
Basic                  4223        ["KQLQueryCompleted", "SentinelAIToolRunStarted", ...]
Run                    2012        ["Set-ConditionalAccessPolicy", "AttachmentAccess", ...]
Interactwithcopilot    71          ["CopilotInteraction"]
```

---

## Query 4: Admin Operations Analysis

**Purpose:** Identify administrative activities and which admins are performing them across cloud platforms.

**Use Case:** Privilege escalation detection; unauthorized admin activity; IAM role changes; compliance auditing.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes admin operations by ActionType with take 15. Exploration/hunting tool; could be adapted to detect specific high-risk admin actions as individual row-level alerts."
-->
```kql
// Admin operations analysis
CloudAppEvents
| where TimeGenerated > ago(7d)
| where IsAdminOperation == true
| summarize AdminEventCount = count(), 
            UniqueAdmins = dcount(AccountObjectId),
            Applications = make_set(Application, 10)
  by ActionType
| order by AdminEventCount desc
| take 15
```

**Expected Results:**
- `ActionType` (string): Administrative action type
- `AdminEventCount` (long): Number of admin operations
- `UniqueAdmins` (long): Distinct admin accounts
- `Applications` (dynamic array): Applications where admin action occurred

**What to Look For:**
- ⚠️ AWS IAM role/policy changes (privilege escalation indicators)
- ⚠️ Azure AD application updates (OAuth app compromise)
- ⚠️ Single admin performing bulk operations (potential compromise)
- ✅ Expected admin activity patterns

**Security Indicators:**
- High admin event count from single account = potential automated abuse
- Admin operations from unexpected geolocations
- Admin operations during off-hours

**Example Output:**
```
ActionType                        AdminEventCount  UniqueAdmins  Applications
List attached role policies       14               1             ["Amazon Web Services"]
Update application.               10               2             ["Microsoft 365"]
```

---

## Query 5: External User Activity

**Purpose:** Monitor external users (guest accounts, B2B collaboration) accessing your cloud resources.

**Use Case:** Guest account abuse detection; data exfiltration monitoring; unauthorized external access.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes external user activity by ActionType. Exploration tool for external access patterns, not a detection."
-->
```kql
// External user activity
CloudAppEvents
| where TimeGenerated > ago(7d)
| where IsExternalUser == true
| summarize EventCount = count(),
            UniqueExternalUsers = dcount(AccountObjectId),
            Applications = make_set(Application)
  by ActionType
| order by EventCount desc
```

**Expected Results:**
- `ActionType` (string): Action performed by external user
- `EventCount` (long): External user events
- `UniqueExternalUsers` (long): Distinct external accounts
- `Applications` (dynamic array): Apps accessed by external users

**What to Look For:**
- ⚠️ External users performing admin operations
- ⚠️ External users accessing sensitive SharePoint/OneDrive content
- ⚠️ Unexpected external user domains
- ✅ Expected B2B collaboration patterns

**Security Thresholds:**
- >50 events from single external user = investigate for abuse
- External user + admin operation = high priority alert
- External user + file download = data exfiltration risk

**Example Output:**
```
ActionType                UniqueExternalUsers  EventCount  Applications
Write Comments            1                    705         ["Microsoft Azure"]
Write Datascanners        1                    29          ["Microsoft Azure"]
Search                    1                    8           ["Microsoft 365"]
```

---

## Query 6: Events by Object Type

**Purpose:** Understand what types of objects (files, folders, applications, policies) are being accessed or modified.

**Use Case:** Data classification; access pattern analysis; compliance monitoring; change tracking.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes events by ObjectType with take 15. Exploration tool for understanding accessed object categories."
-->
```kql
// Events by object type with action examples
CloudAppEvents
| where TimeGenerated > ago(7d)
| where isnotempty(ObjectType)
| summarize EventCount = count(),
            SampleActions = make_set(ActionType, 5)
  by ObjectType
| order by EventCount desc
| take 15
```

**Expected Results:**
- `ObjectType` (string): Type of object (e.g., "Task", "File", "Application", "Policy")
- `EventCount` (long): Operations on this object type
- `SampleActions` (dynamic array): Example actions performed

**What to Look For:**
- ✅ "Policy" objects (Conditional Access, DLP policy changes)
- ✅ "Application" objects (OAuth app registrations/modifications)
- ✅ "File" objects (sensitive document access)
- ⚠️ Bulk operations on single object type

**Example Output:**
```
ObjectType                       EventCount  SampleActions
Task                             2012        ["ListBuckets", "Set-ConditionalAccessPolicy", ...]
Resource                         1280        ["Write Datascanners", "KeepAlive Consoles", ...]
Application                      35          ["Add service principal.", "Update application.", ...]
File                             29          ["FileAccessed", "FileSyncUploadedFull", ...]
```

---

## Query 7: Geographic Distribution & Anonymous Proxy Detection

**Purpose:** Analyze geographic patterns and detect connections from anonymous proxies or VPNs (potential evasion techniques).

**Use Case:** Impossible travel detection; threat actor infrastructure identification; VPN/proxy abuse monitoring.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes geographic patterns per application with calculated AnonymousProxyPercent. See Alert Rule 1 below for a CD-ready anonymous proxy detection."
-->
```kql
// Geographic distribution (anonymous proxies vs regular connections)
CloudAppEvents
| where TimeGenerated > ago(7d)
| summarize TotalEvents = count(),
            AnonymousProxyEvents = countif(IsAnonymousProxy == true),
            TopCountries = make_set(CountryCode, 10)
  by Application
| extend AnonymousProxyPercent = round(AnonymousProxyEvents * 100.0 / TotalEvents, 2)
| order by TotalEvents desc
```

**Expected Results:**
- `Application` (string): Cloud application
- `TotalEvents` (long): Total events
- `AnonymousProxyEvents` (long): Events from anonymous proxies
- `AnonymousProxyPercent` (real): Percentage from proxies
- `TopCountries` (dynamic array): Most common country codes

**What to Look For:**
- ⚠️ **Any anonymous proxy usage** (threat actor evasion technique)
- ⚠️ Unexpected countries (especially high-risk regions)
- ⚠️ Single user accessing from multiple countries in short timeframe
- ✅ Expected geographic distribution matching business locations

**Security Thresholds:**
- AnonymousProxyPercent > 0% = Investigate immediately
- User accessing from >3 countries in 24h = Impossible travel
- Access from high-risk countries (CN, RU, KP, IR) = Priority review

**Example Output:**
```
Application                      TotalEvents  AnonymousProxyEvents  AnonymousProxyPercent  TopCountries
Microsoft 365                    2792         0                     0.00                   ["","CA","US"]
Microsoft Exchange Online        1818         0                     0.00                   ["","US","CA"]
```

---

## Query 8: Daily Event Trend

**Purpose:** Visualize event volume trends over time by application to detect anomalies and establish baselines.

**Use Case:** Capacity planning; anomaly detection; incident correlation; workload pattern analysis.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Time-series aggregation query — bins events by day and application for trend visualization. Baseline tool, not a detection."
-->
```kql
// Daily event trend over last 7 days
CloudAppEvents
| where TimeGenerated > ago(7d)
| summarize EventCount = count() by bin(TimeGenerated, 1d), Application
| order by TimeGenerated asc
```

**Expected Results:**
- `TimeGenerated` (datetime): Day bucket
- `Application` (string): Cloud application
- `EventCount` (long): Events on that day

**What to Look For:**
- ⚠️ Sudden spikes (>3x baseline) = potential attack or misconfiguration
- ⚠️ Drops to zero = logging failure or service outage
- ✅ Consistent patterns = healthy baseline
- ⚠️ Weekend/off-hours activity spikes = potential compromise

**Tuning:**
- Change `1d` to `1h` for hourly granularity
- Change `ago(7d)` to `ago(30d)` for monthly trends

**Example Output:**
```
TimeGenerated           Application                 EventCount
2026-01-06T00:00:00Z   Microsoft Azure             4
2026-01-07T00:00:00Z   Microsoft 365               213
2026-01-09T00:00:00Z   Microsoft Azure             807  <-- Spike detected
```

---

## Query 9: Impersonation Events

**Purpose:** Detect user impersonation activities (when one user performs actions on behalf of another).

**Use Case:** Privilege abuse detection; delegated access monitoring; potential account takeover indicators.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query — summarizes impersonation events by Application. See Alert Rule 4 below for a CD-ready impersonation detection."
-->
```kql
// Impersonation events (if any)
CloudAppEvents
| where TimeGenerated > ago(7d)
| where IsImpersonated == true
| summarize EventCount = count(),
            UniqueUsers = dcount(AccountObjectId),
            SampleActions = make_set(ActionType, 10)
  by Application
| order by EventCount desc
```

**Expected Results:**
- `Application` (string): Where impersonation occurred
- `EventCount` (long): Impersonation events
- `UniqueUsers` (long): Accounts involved
- `SampleActions` (dynamic array): Actions performed via impersonation

**What to Look For:**
- ⚠️ **ANY impersonation events warrant investigation**
- ⚠️ Impersonation from unexpected accounts
- ⚠️ Impersonation combined with admin operations
- ✅ Expected delegated access (e.g., IT support accounts with proper approval)

**Security Indicators:**
- Impersonation event count = immediate review required
- Impersonation + data access = data breach risk
- Impersonation + privilege escalation = critical priority

**Note:** If query returns 0 rows, no impersonation detected (good security posture).

---

## Query 10: Sample Event Details

**Purpose:** Get detailed view of actual events for manual inspection and field validation.

**Use Case:** Incident investigation; understanding event schema; validating detection logic; training.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation sampling query — projects selected fields with take 50. Schema exploration tool, not a detection."
-->
```kql
// Sample events with key details
CloudAppEvents
| where TimeGenerated > ago(7d)
| project TimeGenerated, 
          Application, 
          ActionType, 
          ActivityType,
          AccountDisplayName,
          ObjectType,
          ObjectName,
          IsAdminOperation,
          IsExternalUser,
          CountryCode,
          City
| take 50
```

**Expected Results:**
- Full event details with key fields projected
- 50 most recent events for sampling

**What to Look For:**
- Verify field data quality (empty values, nulls)
- Understand event context and relationships
- Sample suspicious action types for deeper analysis

**Tuning:**
- Add `| where AccountDisplayName == "user@domain.com"` for user-specific sampling
- Add `| where ActionType contains "Policy"` for targeted sampling
- Change `take 50` to adjust sample size

---

## Tuning and Customization

### Time Range Adjustment
```kql
// Change from 7 days to other periods
| where TimeGenerated > ago(7d)   // Last 7 days
| where TimeGenerated > ago(24h)  // Last 24 hours
| where TimeGenerated > ago(30d)  // Last 30 days

// Or use absolute date ranges
| where TimeGenerated between (datetime(2026-01-01) .. datetime(2026-01-13))
```

### User-Specific Filtering
```kql
// Add to any query to focus on specific user
| where AccountDisplayName == "user@domain.com"
| where AccountObjectId == "<user_object_id>"
```

### Application-Specific Analysis
```kql
// Focus on specific cloud app
| where Application == "Amazon Web Services"
| where Application in ("Microsoft 365", "Microsoft Azure")
```

### High-Priority Event Filtering
```kql
// Combine security flags
| where IsAdminOperation == true and IsExternalUser == true
| where IsAnonymousProxy == true
| where IsImpersonated == true
```

---

## Alert Rule Recommendations

### Alert Rule 1: Anonymous Proxy Usage
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Cloud App Access via Anonymous Proxy — {{AccountDisplayName}}"
impactedAssets:
  - type: "user"
    identifier: "AccountDisplayName"
recommendedActions: "Verify whether the user has legitimate business need for VPN/proxy. Review session activity for data exfiltration or config changes. Check SigninLogs for correlated risky sign-in events."
responseActions: "Block IP at Conditional Access Named Locations. Revoke user refresh tokens. Investigate concurrent sessions."
-->
```kql
CloudAppEvents
| where TimeGenerated > ago(1h)
| where IsAnonymousProxy == true
| summarize EventCount = count(), 
            Applications = make_set(Application),
            Countries = make_set(CountryCode)
  by AccountDisplayName, IPAddress
| where EventCount > 0
```
**Severity:** High  
**Frequency:** Every 5 minutes  
**Description:** Detects any cloud app access via anonymous proxy/VPN

---

### Alert Rule 2: External User Admin Operations
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "PrivilegeEscalation"
title: "External User Performed Admin Operation — {{AccountDisplayName}}"
impactedAssets:
  - type: "user"
    identifier: "AccountDisplayName"
recommendedActions: "Verify the external user identity and whether admin delegation is authorized. Check AuditLogs for B2B invitation and role assignment history."
responseActions: "Revoke external user access. Remove admin role assignment. Review affected application/resource for unauthorized changes."
-->
```kql
CloudAppEvents
| where TimeGenerated > ago(1h)
| where IsExternalUser == true and IsAdminOperation == true
| project TimeGenerated, AccountDisplayName, Application, ActionType, CountryCode
```
**Severity:** High  
**Frequency:** Every 5 minutes  
**Description:** External users performing admin operations (potential privilege abuse)

---

### Alert Rule 3: Bulk Conditional Access Changes
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Bulk Conditional Access Policy Changes — {{AccountDisplayName}}"
impactedAssets:
  - type: "user"
    identifier: "AccountDisplayName"
recommendedActions: "Review which CA policies were modified and whether changes weaken security posture. Correlate with sign-in failures that resolved after changes. Check for policy rollbacks."
responseActions: "Revert unauthorized CA policy changes. Lock admin account if compromised. Audit all CA policies for weakened conditions."
-->
```kql
CloudAppEvents
| where TimeGenerated > ago(1h)
| where ActionType == "Set-ConditionalAccessPolicy"
| summarize PolicyChanges = count() by AccountDisplayName, bin(TimeGenerated, 5m)
| where PolicyChanges >= 5
```
**Severity:** Medium  
**Frequency:** Every 15 minutes  
**Description:** ≥5 CA policy changes in 5 minutes (potential policy manipulation)

---

### Alert Rule 4: Impersonation Activity
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "User Impersonation Detected — {{AccountDisplayName}}"
impactedAssets:
  - type: "user"
    identifier: "AccountDisplayName"
recommendedActions: "Verify whether impersonation is authorized (delegated admin, support scenarios). Review impersonated actions for data access or privilege escalation."
responseActions: "Disable impersonation permissions. Revoke session tokens for both impersonator and impersonated accounts. Alert SOC for containment."
-->
```kql
CloudAppEvents
| where TimeGenerated > ago(1h)
| where IsImpersonated == true
| project TimeGenerated, AccountDisplayName, Application, ActionType, ObjectType
```
**Severity:** High  
**Frequency:** Every 5 minutes  
**Description:** Any user impersonation detected

---

## Investigation Workflow

### Step 1: Establish Baseline
1. Run **Query 1-3** to understand normal activity patterns
2. Document baseline action types, applications, and activity types
3. Note typical event volumes per application

### Step 2: Security Review
1. Run **Query 4** (Admin Operations) - review for unexpected privileged activity
2. Run **Query 5** (External Users) - validate B2B collaboration is authorized
3. Run **Query 7** (Geographic Analysis) - check for anonymous proxies or unexpected countries
4. Run **Query 9** (Impersonation) - investigate any results

### Step 3: Anomaly Detection
1. Run **Query 8** (Daily Trend) - identify spikes or drops
2. Compare current volumes to baseline
3. Investigate date/time of anomalies

### Step 4: Targeted Investigation
1. Use **Query 10** (Sample Events) with user/app filters
2. Drill into suspicious action types
3. Correlate with other log sources (SigninLogs, AuditLogs)

### Step 5: Incident Response
1. If malicious activity confirmed:
   - Disable compromised accounts
   - Revoke OAuth app permissions
   - Reset Conditional Access policies
   - Block suspicious IPs at firewall
2. Document findings in incident ticket
3. Run queries again to confirm remediation

---

## Advanced Investigation Query

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Parameter-dependent investigation query — uses let targetUser variable for targeted user analysis with 30-day lookback. Aggregation with ThreatScore calculation. Not suitable for CD."
-->
```kql
// Comprehensive user investigation across all cloud apps
let targetUser = "user@domain.com";
CloudAppEvents
| where TimeGenerated > ago(30d)
| where AccountDisplayName contains targetUser or AccountObjectId contains targetUser
| summarize EventCount = count(),
            Applications = make_set(Application),
            ActionTypes = make_set(ActionType),
            Countries = make_set(CountryCode),
            IsAdmin = max(IsAdminOperation),
            IsExternal = max(IsExternalUser),
            IsProxy = max(IsAnonymousProxy),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
  by AccountDisplayName
| extend ThreatScore = case(
    IsProxy == true, 100,
    IsAdmin == true and IsExternal == true, 90,
    IsAdmin == true, 50,
    IsExternal == true, 30,
    0
  )
| order by ThreatScore desc, EventCount desc
```

**Purpose:** Rapid user risk assessment across all cloud applications with threat scoring.

---

## Schema Reference

### Key CloudAppEvents Columns
- `TimeGenerated` (datetime): Event timestamp (Sentinel)
- `Application` (string): Cloud application name
- `ActionType` (string): Specific action performed
- `ActivityType` (string): High-level activity category
- `AccountObjectId` (string): User's Entra ID Object ID
- `AccountDisplayName` (string): User display name
- `IsAdminOperation` (bool): Admin operation flag
- `IsExternalUser` (bool): External/guest user flag
- `IsAnonymousProxy` (bool): Anonymous proxy detection
- `IsImpersonated` (bool): Impersonation flag
- `IPAddress` (string): Source IP address
- `CountryCode` (string): 2-letter country code
- `City` (string): City name
- `ObjectType` (string): Type of object accessed
- `ObjectName` (string): Name of object
- `RawEventData` (dynamic): Full raw event JSON
- `ActivityObjects` (dynamic): Objects involved in activity

### Related Tables
- `SigninLogs` - Entra ID interactive sign-ins (correlate by AccountObjectId)
- `AADNonInteractiveUserSignInLogs` - Non-interactive auth (correlate by AccountObjectId)
- `AuditLogs` - Azure AD audit events (correlate by Identity/InitiatedBy)
- `OfficeActivity` - Office 365 audit logs (correlate by UserId)

---

## Performance Optimization Tips

1. **Time filters first:** Always filter `TimeGenerated` early in query
2. **Use summarize:** Aggregations are faster than scanning all rows
3. **Limit result sets:** Use `take` or `top` for large result sets
4. **Index-friendly operators:** Use `==` for exact matches, `has` for word searches
5. **Avoid `contains` on high-cardinality fields:** Use `has` instead when possible

---

## References

- **Microsoft Docs:** [CloudAppEvents schema reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-cloudappevents-table)
- **Defender for Cloud Apps:** [Activity log reference](https://learn.microsoft.com/en-us/defender-cloud-apps/activity-filters)
- **MITRE ATT&CK:** Techniques detectable via CloudAppEvents:
  - T1098 - Account Manipulation (admin operations)
  - T1078 - Valid Accounts (external user abuse)
  - T1090 - Proxy (anonymous proxy usage)
  - T1199 - Trusted Relationship (B2B compromise)

---

**Query Collection Version:** 1.0  
**Last Updated:** January 13, 2026  
**Maintainer:** Security Investigator Workspace  
**Tested Against:** Microsoft Sentinel production environment
