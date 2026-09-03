# Privileged Account Creation & Escalation Detection

**Created:** 2026-09-03
**Platform:** Microsoft Defender XDR
**Tables:** IdentityInfo, AuditLogs, IdentityDirectoryEvents
**Keywords:** privileged account, Global Administrator, Domain Admins, Enterprise Admins, Schema Admins, Defender for Identity, MDI, sensitive account, honeytoken, PIM, role assignment, privilege escalation, AssignedRoles, GroupMembership, Tags, on-prem, hybrid
**MITRE:** T1078.002, T1078.003, T1098, T1098.003, T1136.001, T1136.002
**Domains:** identity
**Timeframe:** Detection window 1d (recent) vs 14d (baseline), configurable

---

## Overview

This file covers two complementary detection angles for "a new privileged account appeared, or an existing account gained privilege it didn't have before":

1. **Cloud (Entra ID) roles** — `AuditLogs` for the real-time granting event + `IdentityInfo.AssignedRoles` for baseline/current-state comparison.
2. **On-prem / Hybrid (Active Directory via Defender for Identity)** — `IdentityInfo.GroupMembership` for explicit privileged AD group names (Domain Admins, Enterprise Admins, Schema Admins, etc.) + `IdentityInfo.Tags` for MDI's own computed `Sensitive`/`Privileged Account`/`Honeytoken` flags, which is the more robust signal because MDI resolves **nested/effective group membership** automatically (an account added to a group that is itself a member of Domain Admins will still get flagged, without needing to enumerate every nested group name yourself).

**Design pattern used throughout:** every "new privileged account" query is a **baseline-diff**, not a point-in-time snapshot — it compares a "current" window (last 1d) against a "baseline" window (the preceding ~14d) for the *same account*, and only fires when the account had **zero** privileged signal in the baseline but **has one now**. This is what actually satisfies "wasn't privileged before, is now" rather than just listing all privileged accounts every run.

**Recommended pairing:** Query 1 (event-driven, fast) gives you the *who/when/what role* the moment it happens; Query 2 and Query 4 (snapshot-diff) give you a *corroborating baseline check*; Query 3 combines both for the highest-confidence single detection. Query 5 is the on-prem/hybrid equivalent of Query 2, using MDI's own privilege classification instead of a hardcoded group list.

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Real-Time Entra Privileged Role Assignment (Event-Driven)](#query-1-real-time-entra-privileged-role-assignment-event-driven) | Investigation | `AuditLogs` |
| 2 | [Entra Role Snapshot-Diff — Newly Privileged Account (No Real-Time E...](#query-2-entra-role-snapshot-diff--newly-privileged-account-no-real-time-event-required) | Investigation | `IdentityInfo` |
| 3 | [Corroborated Detection — First-Time Privileged Role Grant (Event + ...](#query-3-corroborated-detection--first-time-privileged-role-grant-event--baseline) | Dashboard | `AuditLogs` + `IdentityInfo` |
| 4 | [On-Prem / Hybrid — Explicit Privileged AD Group Membership](#query-4-on-prem--hybrid--explicit-privileged-ad-group-membership) | Investigation | `IdentityInfo` |
| 5 | [On-Prem / Hybrid — Newly MDI-Flagged Sensitive/Privileged Account (...](#query-5-on-prem--hybrid--newly-mdi-flagged-sensitiveprivileged-account-nested-membership-included) | Investigation | `IdentityInfo` |
| 6 | [PIM Eligibility Grant — Early Warning Before Activation (Bonus)](#query-6-pim-eligibility-grant--early-warning-before-activation-bonus) | Investigation | `AuditLogs` |


## Query 1: Real-Time Entra Privileged Role Assignment (Event-Driven)

🔴 **Fires the moment a Tier-0/Tier-1 Entra directory role is granted** — via `AuditLogs "Add member to role"`. This is the fastest signal (works whether the grant is a standing/permanent assignment or a PIM activation) but on its own **cannot tell you if this is the account's first time holding a privileged role** — see Query 3 for the corroborated version. Tested live against this tenant: correctly surfaced routine PIM activations by known admins, alongside one activation for an account with no prior high-privilege history.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let CriticalRoles = dynamic([
  "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
  "Security Administrator", "Application Administrator", "Cloud Application Administrator",
  "Exchange Administrator", "SharePoint Administrator", "Intune Administrator",
  "Conditional Access Administrator", "User Administrator"
]);
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "Add member to role"
| where Result == "success"
| extend Target = TargetResources[0]
| extend TargetUpn = tostring(Target.userPrincipalName)
| extend TargetObjectId = tostring(Target.id)
| extend ModProps = Target.modifiedProperties
| mv-expand Prop = ModProps
| where tostring(Prop.displayName) == "Role.DisplayName"
| extend RoleName = trim(@'"', tostring(Prop.newValue))
| where RoleName in (CriticalRoles)
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend ActorApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend EffectiveActor = iff(isnotempty(Actor), Actor, ActorApp)
| project TimeGenerated, TargetUpn, TargetObjectId, RoleName, EffectiveActor, Result
| order by TimeGenerated desc
```

**Purpose:** Catches every grant of a Tier-0/Tier-1 Entra role (Global Administrator, Privileged Role Administrator, Security Administrator, etc.) in near-real-time, including PIM activations (`EffectiveActor = "MS-PIM"` for self-service activations) and direct/permanent assignments (`EffectiveActor` = the human admin UPN).

**Tuning notes:**
- `RoleName` is extracted from `TargetResources[0].modifiedProperties` where `displayName == "Role.DisplayName"` — this is the only reliable extraction path; do not assume array position is fixed.
- `EffectiveActor = "MS-PIM"` means a **self-service PIM activation** by the target account itself (temporary, expires) — much lower risk than a **different** actor granting a **permanent** assignment to someone else. Always check whether `EffectiveActor` equals the target or is a distinct admin.
- Extend `CriticalRoles` with any tenant-specific Tier-0 roles (e.g., `Hybrid Identity Administrator`, `Partner Tier2 Support`).

**Verdict logic:**
- 🔴 Escalate: `EffectiveActor` ≠ `TargetUpn` AND role is `Global Administrator`/`Privileged Role Administrator` AND the grant is a **permanent** assignment (not a PIM activation)
- 🟠 Investigate: Any grant where `TargetUpn` has no prior PIM-eligibility or standing privileged role (cross-check Query 2/3)
- 🟡 Monitor: Routine PIM self-activation by an already-known/documented admin
- ✅ Clear: 0 results

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Privileged Entra role \"{{RoleName}}\" granted to {{TargetUpn}}"
impactedAssets:
  - type: user
    identifier: accountUpn
    column: TargetUpn
recommendedActions: "Confirm the grant was authorized via change management or a documented PIM justification. If EffectiveActor differs from TargetUpn and the role is Global Administrator or Privileged Role Administrator, treat as high priority — verify with the actor and the target account owner before allowing the session to continue. Cross-check against Query 2/3 to see if this is the account's first-ever privileged role."
adaptation_notes: "Remove mv-expand if CD row-level constraints reject it in testing; pre-flatten RoleName via a scalar extraction instead. Add DeviceName/TimeGenerated per mandatory CD columns at deployment time."
-->

## Query 2: Entra Role Snapshot-Diff — Newly Privileged Account (No Real-Time Event Required)

🔴 **Baseline-diff detector** — flags any Entra identity that currently holds a Tier-0/Tier-1 role but held **none** of those roles in the preceding baseline window. Useful as a safety net if `AuditLogs` role-grant events are missed, delayed, or the grant happened via a path other than `"Add member to role"` (e.g., group-based role assignment). Tested live against this tenant and correctly surfaced a real newly-privileged account with 0 prior critical roles in the 14-day baseline.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let CriticalRoles = dynamic([
  "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
  "Security Administrator", "Application Administrator", "Cloud Application Administrator",
  "Exchange Administrator", "SharePoint Administrator", "Intune Administrator",
  "Conditional Access Administrator", "User Administrator"
]);
let Current = IdentityInfo
| where Timestamp > ago(1d)
| summarize arg_max(Timestamp, AccountUpn, AccountDisplayName, AssignedRoles) by AccountObjectId
| extend CurrentRoles = parse_json(tostring(AssignedRoles))
| extend CurrentCritical = set_intersect(CurrentRoles, CriticalRoles)
| where array_length(CurrentCritical) > 0;
let Baseline = IdentityInfo
| where Timestamp between (ago(14d) .. ago(1d))
| summarize arg_max(Timestamp, AssignedRoles) by AccountObjectId
| extend BaselineRoles = parse_json(tostring(AssignedRoles))
| extend BaselineCritical = set_intersect(BaselineRoles, CriticalRoles)
| project AccountObjectId, BaselineCritical;
Current
| join kind=leftouter Baseline on AccountObjectId
| extend BaselineCritical = iff(isnull(BaselineCritical), dynamic([]), BaselineCritical)
| where array_length(BaselineCritical) == 0
| project AccountObjectId, AccountUpn, AccountDisplayName, NewCriticalRoles = CurrentCritical, Timestamp
```

**Purpose:** Compares each account's current `AssignedRoles` snapshot against its own snapshot from 1–14 days ago. Only fires when the critical-role intersection was empty at baseline and is non-empty now — a true "went from non-privileged to privileged" signal, independent of which mechanism granted it.

**Tuning notes:**
- Requires `set_intersect()` (not `set_intersection()` — that function does not exist in KQL).
- Accounts with **no baseline row at all** (brand-new identities, not just newly-privileged ones) will also match — `BaselineCritical` defaults to an empty array via the `leftouter` join. Consider adding `| where isnotnull(BaselineCritical_original)` if you want to exclude brand-new accounts and only alert on existing accounts gaining privilege.
- Widen the baseline window (e.g., 30d/90d) to reduce false positives from accounts whose `IdentityInfo` snapshot simply didn't refresh during a shorter window.

**Verdict logic:**
- 🔴 Escalate: Any `NewCriticalRoles` containing `Global Administrator` or `Privileged Role Administrator`
- 🟠 Investigate: Any other role in `NewCriticalRoles`
- ✅ Clear: 0 results

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "Account {{AccountUpn}} newly holds a privileged Entra role"
impactedAssets:
  - type: user
    identifier: accountUpn
    column: AccountUpn
recommendedActions: "Verify this privilege grant against change-management records. If unexpected, review AuditLogs for the granting operation and actor, and consider reverting the role assignment pending confirmation."
adaptation_notes: "Contains a join across two sub-queries on the same table — not NRT-eligible. Deploy at 24H (or the shortest interval that still lets IdentityInfo refresh between runs)."
-->

## Query 3: Corroborated Detection — First-Time Privileged Role Grant (Event + Baseline)

🔴 **Highest-confidence single detection** — combines Query 1's real-time grant event with Query 2's baseline check via a `leftanti` join, so it fires **only** when (a) a critical role was just granted AND (b) the target account held no critical role in the prior 14 days. This is the query to deploy if you want one alert per genuine "new privileged account" event instead of three separate signals to correlate manually.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let CriticalRoles = dynamic([
  "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
  "Security Administrator", "Application Administrator", "Cloud Application Administrator",
  "Exchange Administrator", "SharePoint Administrator", "Intune Administrator",
  "Conditional Access Administrator", "User Administrator"
]);
let LookbackWindow = 1d;
let BaselineWindow = 14d;
let NewRoleGrants = AuditLogs
| where TimeGenerated > ago(LookbackWindow)
| where OperationName == "Add member to role"
| where Result == "success"
| extend Target = TargetResources[0]
| extend TargetUpn = tostring(Target.userPrincipalName)
| extend TargetObjectId = tostring(Target.id)
| extend ModProps = Target.modifiedProperties
| mv-expand Prop = ModProps
| where tostring(Prop.displayName) == "Role.DisplayName"
| extend RoleName = trim(@'"', tostring(Prop.newValue))
| where RoleName in (CriticalRoles)
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend ActorApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend EffectiveActor = iff(isnotempty(Actor), Actor, ActorApp)
| project TimeGenerated, TargetUpn, TargetObjectId, RoleName, EffectiveActor;
let PriorPrivilegedAccounts = IdentityInfo
| where Timestamp between (ago(BaselineWindow) .. ago(LookbackWindow))
| summarize arg_max(Timestamp, AssignedRoles) by AccountObjectId
| extend PriorRoles = parse_json(tostring(AssignedRoles))
| extend PriorCritical = set_intersect(PriorRoles, CriticalRoles)
| where array_length(PriorCritical) > 0
| project AccountObjectId;
NewRoleGrants
| join kind=leftanti (PriorPrivilegedAccounts) on $left.TargetObjectId == $right.AccountObjectId
| order by TimeGenerated desc
```

**Purpose:** `join kind=leftanti` keeps only rows from `NewRoleGrants` whose `TargetObjectId` does **not** appear in `PriorPrivilegedAccounts` — i.e., the account did not already hold a critical role in the 14-day window before the grant. This is the query to page a SOC analyst on: a genuinely new admin, corroborated by both the event and the historical baseline.

**Tuning notes:**
- Tested live against this tenant: correctly excluded routine PIM re-activations by long-standing documented admins, while a first-time grant would pass through (validate this behavior periodically as your admin roster changes).
- Widen `LookbackWindow` to `3d` or `7d` if you run this on a less-frequent schedule and want to catch grants between runs.

**Verdict logic:**
- 🔴 Escalate: Any result where `RoleName` is `Global Administrator` / `Privileged Role Administrator` / `Privileged Authentication Administrator`
- 🟠 Investigate: Any other result (first-time grant of a non-Tier-0 critical role)
- ✅ Clear: 0 results

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "Persistence"
title: "New privileged account: {{TargetUpn}} granted {{RoleName}}"
impactedAssets:
  - type: user
    identifier: accountUpn
    column: TargetUpn
recommendedActions: "This account held no critical Entra role in the prior 14 days and was just granted one. Verify authorization with the granting actor (EffectiveActor) and the account owner before treating as routine. If EffectiveActor is not a documented admin or an expected PIM self-activation, escalate immediately."
adaptation_notes: "Contains AuditLogs + IdentityInfo cross-table join — not NRT-eligible. Deploy at 3H for near-real-time coverage without join-related NRT restrictions."
-->

## Query 4: On-Prem / Hybrid — Explicit Privileged AD Group Membership

🔴 **Native AD privileged group detector** — flags any Hybrid/On-premises identity whose `GroupMembership` includes one of the classic Tier-0 Active Directory groups (Domain Admins, Enterprise Admins, Schema Admins, etc.), surfaced via Defender for Identity into `IdentityInfo`. Complements Query 5 (which uses MDI's own computed sensitivity tag instead of a hardcoded group list).

**Tool:** `RunAdvancedHuntingQuery`

```kql
let PrivilegedADGroups = dynamic([
  "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
  "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
  "DnsAdmins", "Group Policy Creator Owners", "Cert Publishers", "Key Admins", "Enterprise Key Admins"
]);
IdentityInfo
| where Timestamp > ago(1d)
| where IdentityEnvironment in ("Hybrid", "On-premises") or SourceProvider in ("ActiveDirectory", "Hybrid")
| summarize arg_max(Timestamp, AccountUpn, AccountDisplayName, GroupMembership, DistinguishedName) by AccountObjectId
| extend Groups = parse_json(tostring(GroupMembership))
| extend PrivilegedGroups = set_intersect(Groups, PrivilegedADGroups)
| where array_length(PrivilegedGroups) > 0
| project AccountUpn, AccountDisplayName, PrivilegedGroups, DistinguishedName, Timestamp
```

**Purpose:** Direct membership check against the well-known Tier-0/Tier-1 built-in AD security groups that Domain Admins-equivalent privilege escalation targets. `IdentityInfo.GroupMembership` is populated by Defender for Identity's sensor telemetry for `Hybrid`/`On-premises` identities.

**Tuning notes:**
- **⚠️ Only detects *direct* membership**, not nested group membership (e.g., a user added to a custom group that is itself a member of Domain Admins will NOT match here). Use Query 5 for nested/effective membership coverage — MDI itself resolves nesting when computing the `Sensitive` tag.
- 0 results is a valid, verified outcome in environments (including this lab tenant, verified 2026-09-03) that use custom-named security groups rather than the literal built-in group names — confirm your environment's actual privileged group names before assuming "0 results = no privileged accounts."
- For the "wasn't privileged before" requirement, wrap this query in the same baseline-diff pattern as Query 2 (compare `PrivilegedGroups` at `ago(1d)` vs a 14d-prior snapshot).

**Verdict logic:**
- 🔴 Escalate: `PrivilegedGroups` contains `Domain Admins` or `Enterprise Admins`
- 🟠 Investigate: `PrivilegedGroups` contains any other listed group
- ✅ Clear: 0 results (verify against your actual AD group naming before treating as "no privileged on-prem accounts")

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "On-prem privileged group membership: {{AccountUpn}} in {{PrivilegedGroups}}"
impactedAssets:
  - type: user
    identifier: accountUpn
    column: AccountUpn
recommendedActions: "Confirm this on-prem privileged group membership is documented and authorized. Cross-reference with Active Directory directly (dsa.msc / Get-ADGroupMember) to rule out MDI sensor lag, and check IdentityDirectoryEvents for the underlying group-modification event if MDI captured it."
adaptation_notes: "Single-table row-level output; NRT-eligible if you accept a 1d lookback substituted for a shorter one at deployment. Extend PrivilegedADGroups with any tenant-specific Tier-0 group names before deploying."
-->

## Query 5: On-Prem / Hybrid — Newly MDI-Flagged Sensitive/Privileged Account (Nested Membership Included)

🔴 **Most robust on-prem detector** — instead of hardcoding group names, this uses Defender for Identity's own computed `Tags` classification (`Sensitive`, `Privileged Account`, `Honeytoken`) on `IdentityInfo`, which MDI derives from **effective/nested** group membership, `adminCount=1`, and other AD-native privilege indicators — catching cases Query 4's direct-membership check would miss. Applies the same baseline-diff pattern as Query 2/3, adapted for on-prem identities.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let PrivilegedTags = dynamic(["Sensitive", "Privileged Account"]);
let Current = IdentityInfo
| where Timestamp > ago(1d)
| summarize arg_max(Timestamp, AccountUpn, AccountDisplayName, Tags, IdentityEnvironment) by AccountObjectId
| extend CurrentTags = parse_json(tostring(Tags))
| where array_length(set_intersect(CurrentTags, PrivilegedTags)) > 0;
let Baseline = IdentityInfo
| where Timestamp between (ago(14d) .. ago(1d))
| summarize arg_max(Timestamp, Tags) by AccountObjectId
| extend BaselineTags = parse_json(tostring(Tags))
| extend BaselinePriv = set_intersect(BaselineTags, PrivilegedTags)
| project AccountObjectId, BaselinePriv;
Current
| join kind=leftouter Baseline on AccountObjectId
| extend BaselinePriv = iff(isnull(BaselinePriv), dynamic([]), BaselinePriv)
| where array_length(BaselinePriv) == 0
| project AccountObjectId, AccountUpn, AccountDisplayName, IdentityEnvironment, Timestamp
```

**Purpose:** Same baseline-diff logic as Query 2, but on the `Tags` field instead of `AssignedRoles` — this is the on-prem/hybrid analog and is MDI's authoritative "this account is privileged" signal, since it already accounts for nested group resolution that a raw `GroupMembership` string match (Query 4) cannot.

**Tuning notes:**
- `Honeytoken` is intentionally excluded from `PrivilegedTags` in this query — honeytoken accounts are decoys, not real privileged accounts, and belong in a separate honeytoken-activity detection, not a privilege-escalation one. Include it only if you specifically want to know when the `Honeytoken` tag itself is newly applied (e.g., a new decoy was provisioned).
- 0 results in a given run is valid — it means no account transitioned into `Sensitive`/`Privileged Account` status in the last 24h, not that MDI found no privileged accounts at all (query Query 4 or a plain "current state" version of this query without the baseline diff for a full inventory).
- Cross-reference hits with `IdentityDirectoryEvents` (`ActionType` values like `"Group Membership Changed"`, if your MDI sensor emits it) for the specific AD operation that caused the tag change.

**Verdict logic:**
- 🔴 Escalate: Newly `Privileged Account`-tagged identity with no clear business justification
- 🟠 Investigate: Newly `Sensitive`-tagged identity
- ✅ Clear: 0 results

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "On-prem/hybrid account {{AccountUpn}} newly flagged privileged by Defender for Identity"
impactedAssets:
  - type: user
    identifier: accountUpn
    column: AccountUpn
recommendedActions: "Confirm this account's new Sensitive/Privileged Account classification is expected (e.g., a documented admin onboarding). If unexpected, investigate what group membership or AD attribute change caused MDI to reclassify the account — check IdentityDirectoryEvents and native MDI 'Suspicious additions to sensitive groups' alerts for corroboration."
adaptation_notes: "Contains a join across two sub-queries on the same table — not NRT-eligible. Deploy at 24H matching the IdentityInfo refresh cadence."
-->

## Query 6: PIM Eligibility Grant — Early Warning Before Activation (Bonus)

🟡 **Earlier warning signal** — fires when an account becomes **eligible** for a privileged role via PIM (`"Add eligible member to role"`), before it ever activates that role. Useful as an earlier tripwire than Query 1/3, since eligibility grants are rarer/more deliberate admin actions than activations.

**Tool:** `RunAdvancedHuntingQuery`

```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "Add eligible member to role"
| where Result == "success"
| extend Target = TargetResources[0]
| extend TargetUpn = tostring(Target.userPrincipalName)
| extend ModProps = Target.modifiedProperties
| mv-expand Prop = ModProps
| where tostring(Prop.displayName) == "Role.DisplayName"
| extend RoleName = trim(@'"', tostring(Prop.newValue))
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| project TimeGenerated, TargetUpn, RoleName, Actor
| order by TimeGenerated desc
```

**Purpose:** Captures the moment someone is made *eligible* to activate a role via PIM — a deliberate administrative decision, distinct from the (often automated) activation events in Query 1. `Actor` is frequently empty for PIM-driven internal operations; treat an empty `Actor` alongside an unfamiliar `TargetUpn` as worth a closer look.

**Verdict logic:**
- 🟠 Investigate: `RoleName` is Tier-0 (`Global Administrator`, `Privileged Role Administrator`) and `TargetUpn` is not a previously-documented admin
- 🟡 Monitor: Routine eligibility grants for known admin rotation
- ✅ Clear: 0 results

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "PIM eligibility granted: {{TargetUpn}} for {{RoleName}}"
impactedAssets:
  - type: user
    identifier: accountUpn
    column: TargetUpn
recommendedActions: "Confirm the PIM eligibility grant matches an approved access request. Cross-reference with Query 1/3 to see if this eligibility is later activated."
adaptation_notes: "Single-table, row-level — NRT-eligible if mv-expand behaves correctly in NRT mode; validate before deploying at schedule '0'."
-->

## Deployment Notes

| Query | CD-Ready | Recommended Schedule | Notes |
|---|---|---|---|
| Q1 — Real-time Entra role grant | ✅ | 1H | Fastest signal, no baseline correlation |
| Q2 — Entra snapshot-diff | ✅ | 24H | Safety net if Q1 misses the grant event |
| Q3 — Corroborated first-time grant | ✅ | 3H | **Recommended primary detection** — highest confidence |
| Q4 — On-prem explicit group membership | ✅ | 24H | Direct membership only; extend group list per environment |
| Q5 — On-prem MDI Tags drift | ✅ | 24H | **Recommended primary on-prem detection** — nested membership included |
| Q6 — PIM eligibility grant | ✅ | 1H | Earliest possible warning, higher noise |

See `.github/skills/detection-authoring/SKILL.md` for the full deployment workflow (single or batch) once you're ready to turn any of these into a live Custom Detection rule.

## References

- `.github/skills/identity-posture/SKILL.md` Query 4 — the org-wide (non-diffed) privileged account audit this file's baseline logic builds on
- `.github/skills/detection-authoring/SKILL.md` — CD Metadata Contract and deployment workflow
- [MDI: Investigate users tagged as sensitive](https://learn.microsoft.com/en-us/defender-for-identity/entity-tags)
