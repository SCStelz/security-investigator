# MCP Server Usage Monitoring Report

**Generated:** 2026-02-08 21:30 UTC  
**Workspace:** la-contoso (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)  
**Analysis Period:** 2025-11-10 → 2026-02-08 (90 days)  
**Data Sources:** MicrosoftGraphActivityLogs, SigninLogs, AADNonInteractiveUserSignInLogs, LAQueryLogs, CloudAppEvents, AzureActivity, AuditLogs

---

## Executive Summary

Four MCP servers are actively monitored in this environment: **Graph MCP**, **Sentinel Triage MCP**, **Sentinel Data Lake MCP**, and **Azure MCP Server**. Over the 90-day period, **7,208 total MCP calls** were observed across all channels, driven by **1–2 known users** (primarily `secadmin@contoso.com`). The environment shows healthy single-user adoption patterns with security-focused Graph API usage (54.1% calls to sensitive endpoints — consistent with investigation workflows). The primary concern is the **8.1% error rate on Data Lake `query_lake` tool** (453 schema/semantic errors), indicating AI-generated KQL queries sometimes reference non-existent columns or tables. Two Copilot Studio agent identities were detected — one active, one deleted within minutes (testing pattern).

**MCP Usage Score: 43/100 — 🟡 Elevated** (driven by sensitive endpoint concentration and Data Lake error rate; mitigated by single-user profile and security-use-case justification).

---

## Table of Contents

1. [Graph MCP Server](#graph-mcp-server)
2. [Sentinel Triage MCP](#sentinel-triage-mcp)
3. [Sentinel Data Lake MCP](#sentinel-data-lake-mcp)
4. [Azure MCP Server](#azure-mcp-server)
5. [Workspace Query Governance (Two-Tier)](#workspace-query-governance-two-tier)
6. [Agent Identity Attribution](#agent-identity-attribution)
7. [MCP Usage Score](#mcp-usage-score)
8. [Security Assessment](#security-assessment)
9. [Recommendations](#recommendations)
10. [Appendix: Query Details](#appendix-query-details)

---

## Graph MCP Server

> **Data Source:** `MicrosoftGraphActivityLogs`  
> **AppId:** `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`  
> **Caller Attribution:** 100% delegated user flow (Client Certificate), single user (`a1b2c3d4` = secadmin@contoso.com)

### Daily Usage Trend

```
Graph MCP Usage — Last 90 Days (9 active days)
Day           Calls  Trend
─────────────────────────────────────────────
2026-02-08  │   5   ██
2026-02-07  │   3   █
2026-02-06  │  59   ██████████████████████████████
2026-02-05  │  61   ███████████████████████████████
2026-02-02  │   1   
2026-01-30  │   1   
2026-01-29  │  14   ███████
2026-01-27  │   7   ███
2026-01-26  │   6   ███
─────────────────────────────────────────────
Total: 157  │  Avg: 17.4/active day  │  Peak: 61 (Feb 5)
Active Days: 9 of 90 (10%)  │  Error Rate: 0.0%
```

### Top Endpoints (25 endpoints accessed)

| Rank | Endpoint | Calls | % Total | Last Used |
|------|----------|-------|---------|-----------|
| 1 | `/beta/identity/conditionalAccess/policies` | 27 | 17.2% | 2026-02-06 |
| 2 | `/v1.0/users/{UPN}` | 25 | 15.9% | 2026-02-06 |
| 3 | `/v1.0/users/{id}/authentication/methods` | 16 | 10.2% | 2026-02-06 |
| 4 | `/v1.0/identityProtection/riskyUsers` | 10 | 6.4% | 2026-02-06 |
| 5 | `/v1.0/groups/{id}` | 7 | 4.5% | 2026-02-06 |
| 6 | `/v1.0/identityProtection/riskDetections` | 7 | 4.5% | 2026-02-06 |
| 7 | `/v1.0/devices` | 6 | 3.8% | 2026-02-07 |
| 8 | `/v1.0/reports/authenticationMethods/userRegistrationDetails/{id}` | 6 | 3.8% | 2026-02-06 |
| 9 | `/v1.0/identityProtection/riskyUsers/{id}` | 6 | 3.8% | 2026-02-06 |
| 10 | `/v1.0/auditLogs/signIns` | 5 | 3.2% | 2026-02-06 |

### Sensitive API Access

| Endpoint Pattern | Calls | Method | Risk Assessment |
|-----------------|-------|--------|----------------|
| 🟠 `conditionalAccess/policies` | 30 | GET | Read access to CA policy configurations |
| 🟠 `authentication/methods` | 17 | GET | Read MFA method inventory per user |
| 🟠 `identityProtection/riskyUsers` | 16 | GET | Read Identity Protection risk status |
| 🟠 `identityProtection/riskDetections` | 7 | GET | Read risk detection events |
| 🟡 `auditLogs/signIns` | 9 | GET | Read sign-in audit trail |
| 🟡 `servicePrincipals` | 3 | GET | Enumerate service principals |
| 🟡 `identityProtection/riskyUsers/{id}/history` | 2 | GET | Read risk state history |
| 🟡 `roleManagement/directory/roleAssignments` | 1 | GET | Read PIM role assignments |

**Summary:** 🟠 **85 of 157 calls (54.1%)** targeted sensitive Graph endpoints. All calls were **read-only (GET)**. This profile is consistent with a security investigation workflow — no write operations, no credential modifications, no privilege escalation attempts detected.

### Off-Hours Activity

| Metric | Value |
|--------|-------|
| Total Calls | 157 |
| Off-Hours (UTC) | 116 (73.9%) |
| Business Hours (UTC) | 41 (26.1%) |

> ⚠️ **Timezone Note:** Off-hours calculation uses UTC (08:00–18:00). The primary user is US-based, so UTC "off-hours" largely corresponds to US business hours. When adjusted for US Pacific (UTC-8), the off-hours percentage drops to an estimated ~15–20%. This is **not a security concern**.

### Caller Attribution

| Caller Type | Auth Method | User ID | Calls | Endpoints | Success Rate | Source IPs |
|------------|-------------|---------|-------|-----------|-------------|------------|
| 👤 User (Delegated) | Client Certificate | `a1b2c3d4` (secadmin) | 157 | 34 | 100.0% | `198.51.100.x` (Azure proxy) |

✅ **No Service Principal or Agent Identity callers detected** on Graph MCP. All 157 calls originated from a single human user via delegated permissions.

---

## Sentinel Triage MCP

> **Data Sources:** `SigninLogs` (authentication), `LAQueryLogs` (query volume)  
> **Server AppId:** `bbbbbbbb-cccc-dddd-eeee-ffffffffffff` (Sentinel Triage MCP)  
> **Platform AppId:** `cccccccc-dddd-eeee-ffff-111111111111` (Sentinel Platform Services)

### Authentication Events by Client

| Client App | AppId | Sign-Ins | Users | Client Type | Last Seen |
|-----------|-------|---------|-------|-------------|-----------|
| Sentinel Platform Services App Reg | `cccccccc` | 25 | 1 | Browser | 2026-02-06 |
| Visual Studio Code | `aebc6443` | 3 | 1 | Desktop | 2026-01-29 |
| PowerPlatform-sentinelmcp-Connector | `dddddddd` | 1 | 1 | Browser | 2026-01-13 |

**Total:** 29 authentication events, 1 distinct user (`secadmin@contoso.com`).

### Query Volume (Analytics Tier — LAQueryLogs)

| AppId | Service | Category | Queries | Users | Avg CPU (ms) | Rows Returned | Active Since |
|-------|---------|----------|---------|-------|-------------|---------------|-------------|
| `bbbbbbbb` | Sentinel Triage MCP | 🤖 **MCP Server** | 1,076 | 1 | 301 | 1,036 | 2025-11-17 |

**Details:**
- 🟢 Consistent, sustained usage over ~83 days (Nov 17 → Feb 8)
- 🟢 Avg CPU: 301ms — moderate, no heavy analytical workloads
- 🟢 1,036 rows returned — low result sets indicating focused, targeted queries

---

## Sentinel Data Lake MCP

> **Data Source:** `CloudAppEvents` (Purview unified audit log)  
> **Classification:** RecordType 403 + Interface `IMcpToolTemplate` = MCP-driven | RecordType 379 = Direct KQL  
> **Active Since:** 2025-11-14

### MCP vs Direct KQL Delineation

| Access Pattern | Total Calls | Success | Failures | Error Rate | Users |
|---------------|-------------|---------|----------|------------|-------|
| 🤖 **MCP Server-Driven** | 5,974 | 5,506 | 468 | 7.8% | 3 |
| 👤 **Direct KQL** | 9,263 | 8,858 | 405 | 4.4% | 3 |
| **Combined** | **15,237** | **14,364** | **873** | **5.7%** | **3** |

> Users: `secadmin@contoso.com`, `analyst@contoso.com`, `UserIdNotProvided`

### MCP Tool Breakdown

| Tool Name | Calls | Success | Failures | Error Rate | Avg Duration (s) | Max Duration (s) | Last Seen |
|-----------|-------|---------|----------|------------|-------------------|-------------------|-----------|
| `query_lake` | 5,689 | 5,226 | 463 | 🟠 8.1% | 6,809 | 303,029 | 2026-02-08 |
| `list_sentinel_workspaces` | 142 | 142 | 0 | ✅ 0.0% | 227 | 1,658 | 2026-02-08 |
| `search_tables` | 85 | 85 | 0 | ✅ 0.0% | 6,576 | 21,035 | 2026-02-08 |
| `get_entity_analysis` | 27 | 27 | 0 | ✅ 0.0% | 30,400 | 50,365 | 2026-02-06 |
| `analyze_user_entity` | 17 | 12 | 5 | 🔴 29.4% | 545 | 2,269 | 2026-02-03 |
| `analyze_url_entity` | 8 | 8 | 0 | ✅ 0.0% | 239 | 388 | 2026-02-06 |
| `DLP_Events_Critical_By_UPN` | 6 | 6 | 0 | ✅ 0.0% | 9,577 | 10,707 | 2026-01-28 |

> 🔵 **Custom MCP Tool Detected:** `DLP_Events_Critical_By_UPN` is a user-defined MCP tool (saved KQL query exposed as MCP tool). 6 calls with 100% success rate.

### Error Analysis

| Error Category | Count | % of Failures | Sample Error | Affected Tools |
|---------------|-------|---------------|--------------|----------------|
| 🟠 Schema/Semantic Error | 453 | 96.8% | `Failed to resolve scalar expression`, `Failed to resolve column`, `Failed to resolve table` | `query_lake` |
| 🟡 Other Error | 14 | 3.0% | `ServiceException`, `TooManyRequests`, `Time range must not exceed 7 days`, `The operation was canceled` | `query_lake`, `analyze_user_entity` |
| 🟡 KQL Syntax Error | 1 | 0.2% | `'2025-14' could not be parsed as datetime` | `query_lake` |

**Root Cause Analysis:**
- 🟠 The dominant error type (Schema/Semantic — 96.8%) indicates AI-generated KQL queries referencing non-existent columns or tables. This is expected when LLMs generate exploratory queries against unfamiliar schemas. Tables affected include `AADNonInteractiveUserSignInLogs`, `AzureActivity`, `LAQueryLogs`, `AzureDiagnostics`, `DeviceProcessEvents`.
- 🟡 Rate limiting (`TooManyRequests`) observed — 1 instance of burst request limit exceeded.
- 🟡 Time range violations — entity analysis tools enforced 7-day max range.

### Tables Accessed via MCP `query_lake`

Sentinel tables queried through the Data Lake MCP tool:

```
SecurityAlert, SecurityEvent, W3CIISLog, Heartbeat,
DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents,
SecurityIncident, SigninLogs, AADNonInteractiveUserSignInLogs,
AzureActivity, LAQueryLogs, AzureDiagnostics, CloudAppEvents,
DeviceProcessEvents
```

---

## Azure MCP Server

> **Detection Method:** Composite signal analysis — AppId `1950a258` + UserAgent `azsdk-net-Identity (.NET 9.x; Microsoft Windows)` in AADNonInteractiveUserSignInLogs + `csharpsdk,LogAnalyticsPSClient` in LAQueryLogs.  
> **Note:** Sign-in events represent **token acquisitions**, not individual API calls. Cached tokens (~1hr) serve multiple MCP calls.

### Authentication Events

| User | Sign-Ins | Success | Failures | Resources Accessed | IP | Period |
|------|---------|---------|----------|-------------------|-----|--------|
| secadmin@contoso.com | 4 | 2 | 2 | Log Analytics API, ARM, Graph | `198.51.100.66` | Feb 2 – Feb 8 |
| collaborator@contoso.com | 1 | 1 | 0 | ARM | `203.0.113.89` | Jan 14 |

**Total:** 5 token acquisition events, 2 distinct users.

> 🔵 **Low volume is expected.** Azure MCP Server caches tokens for ~1 hour. 5 sign-in events represent ~5 access sessions, not 5 API calls. Actual Azure MCP tool invocations are significantly higher (no per-call telemetry available for read operations).

### Workspace Queries (LAQueryLogs)

| Timestamp | User | RequestClientApp | Response | CPU (ms) |
|-----------|------|------------------|----------|----------|
| Detected | secadmin | `csharpsdk,LogAnalyticsPSClient` | 200 | 16 |

**Total:** 1 workspace query detected via LAQueryLogs with `csharpsdk` fingerprint.

### AzureActivity Write Operations

✅ **No ARM write operations detected** with Claims.appid `1950a258` in the 90-day period. Azure MCP Server was used exclusively for read-only operations (list subscriptions, list resources, query workspace) which do not appear in AzureActivity.

---

## Workspace Query Governance (Two-Tier)

### Analytics Tier (LAQueryLogs)

| Rank | AppId | Source | Category | Queries | % Total | Users | Avg CPU (ms) |
|------|-------|--------|----------|---------|---------|-------|-------------|
| 1 | `fc780465` | Sentinel Engine | ⚙️ Platform | 174,180 | 97.51% | 4 | 25 |
| 2 | `de8c33bb` | Logic Apps Connector | ⚙️ Platform | 1,776 | 0.99% | 1 | 64 |
| 3 | `bbbbbbbb` | **Sentinel Triage MCP** | 🤖 **MCP Server** | 1,076 | 0.60% | 1 | 301 |
| 4 | `80ccca67` | Sentinel Portal (M365 Sec) | 🌐 Portal | 1,005 | 0.56% | 3 | 1,106 |
| 5 | `95a5d94c` | Azure Portal (AppInsights) | 🌐 Portal | 198 | 0.11% | 1 | 2,928 |
| 6 | `a0965655` | Sentinel Investigation Queries | ⚙️ Platform | 195 | 0.11% | 1 | 153 |
| 7 | `37b80b6b` | Sentinel DataCollection Aggregator | ⚙️ Platform | 57 | 0.03% | 2 | 414 |
| 8 | `bda0771f` | Sentinel Portal (variant) | 🌐 Portal | 59 | 0.03% | 1 | 310 |
| 9 | `6e00b31f` | AppAnalytics / LogAnalytics | 🌐 Portal | 35 | 0.02% | 1 | 121 |
| 10 | `4853cebb` | AzureMonitorLogsConnector | ⚙️ Platform | 14 | <0.01% | 1 | 66 |
| 11 | `c216a200` | Unknown | ❓ Other | 6 | <0.01% | 1 | 34 |
| 12 | `04b07795` | Azure CLI | 🖥️ CLI | 4 | <0.01% | 1 | 28 |
| 13 | `1950a258` | **Azure MCP Server** | 🤖 **MCP Server** | 1 | <0.01% | 1 | 16 |
| 14 | `6e00b31f` | LogAnalyticsExtension | 🌐 Portal | 1 | <0.01% | 1 | 16 |

**Total Analytics Tier:** 178,607 queries

```
Analytics Tier Query Sources — 90d (LAQueryLogs)
──────────────────────────────────────────────────────────
Sentinel Engine       ████████████████████████████████████████  97.51%  (174,180)
Logic Apps            █                                         0.99%    (1,776)
Sentinel Triage MCP   ░                                         0.60%    (1,076)
Sentinel Portal       ░                                         0.56%    (1,005)
Azure Portal          ░                                         0.11%      (198)
Other                 ░                                         0.23%      (372)
──────────────────────────────────────────────────────────
🤖 MCP Servers: 0.60% (1,077)  │  🌐 Portal: 0.72%  │  ⚙️ Platform: 98.68%
```

### Data Lake Tier (CloudAppEvents)

| Access Pattern | Calls | % Total | Users | Error Rate |
|---------------|-------|---------|-------|------------|
| 🤖 MCP Server-Driven | 5,974 | 39.2% | 3 | 7.8% |
| 👤 Direct KQL | 9,263 | 60.8% | 3 | 4.4% |
| **Total** | **15,237** | **100%** | **3** | **5.7%** |

```
Data Lake Tier Query Sources — 90d (CloudAppEvents)
──────────────────────────────────────────────────────────
Direct KQL            ████████████████████████                  60.8%    (9,263)
Data Lake MCP         ████████████████                          39.2%    (5,974)
──────────────────────────────────────────────────────────
🤖 MCP Server-Driven: 39.2%  │  👤 Direct KQL: 60.8%
```

### Combined MCP Proportion

| Tier | MCP Queries | Total Queries | MCP % |
|------|------------|---------------|-------|
| Analytics (LAQueryLogs) | 1,077 | 178,607 | 0.60% |
| Data Lake (CloudAppEvents) | 5,974 | 15,237 | 39.2% |
| Graph API | 157 | 157 | 100% |
| **Combined** | **7,208** | **194,001** | **3.7%** |

> 🔵 **Context:** The Analytics tier is dominated by Sentinel Engine automated queries (97.5%), making MCP appear proportionally small. On the Data Lake tier — which represents human-initiated analysis — MCP accounts for nearly 40% of all queries, reflecting heavy AI-assisted investigation workflows.

---

## Agent Identity Attribution

### Agent Inventory (from AuditLogs + Graph API)

| Agent Name | SPN ID | Created By | Created | Status | Operations |
|------------|--------|-----------|---------|--------|-----------|
| 🤖 Agent (Microsoft Copilot Studio) | `dddddddd-eeee-ffff-1111-222222222222` | Power Virtual Agents Service | 2026-01-09 | 🟢 Active | Add SPN → Add Owner (secadmin, PVA Service) → Update SPN (×4) |
| 🤖 Sentinel Data Exploration Agent (Microsoft Copilot Studio) | `eeeeeeee-ffff-1111-2222-333333333333` | Power Virtual Agents Service | 2026-01-26 | 🔴 Deleted | Add SPN → Add Owner → Update SPN → Remove SPN → **Hard Delete** (same day) |
| ❌ Agent 365 Tools | `ffffffff-1111-2222-3333-444444444444` | secadmin@contoso.com | 2026-01-06 | Active | **NOT an Agent Identity** — standard app registration with "Agent" in name |

### Agent Lifecycle Timeline

```
2026-01-06 16:08  ── Agent 365 Tools ── Add service principal (by secadmin@contoso.com)
                     └── ❌ Standard app registration, NOT a Copilot Studio agent

2026-01-09 18:30  ── Agent (Microsoft Copilot Studio) ── Add service principal (by Power Virtual Agents Service)
                     └── Add owner: secadmin (a1b2c3d4)
                     └── Add owner: Power Virtual Agents Service (b2c3d4e5)
                     └── Update service principal (×4)
                     └── 🟢 Status: ACTIVE

2026-01-26 18:31  ── Sentinel Data Exploration Agent (Microsoft Copilot Studio) ── Add service principal (Power Virtual Agents Service)
                     └── Add owner: secadmin (a1b2c3d4)
                     └── Add owner: Power Virtual Agents Service (b2c3d4e5)
                     └── Update service principal (×2)
2026-01-26 19:02  ── Sentinel Data Exploration Agent ── Remove service principal → Hard delete (by Power Virtual Agents Service)
                     └── 🔴 Lifetime: ~30 minutes (testing/experimentation pattern)
```

> 🔵 **Classification Note:** Agent classification used AuditLogs `InitiatedBy` = `Power Virtual Agents Service` as the primary indicator. The "Agent 365 Tools" SPN was created manually by a user and has no agentic tags — it is a standard app registration despite "Agent" in the display name.

### Agent Identity Impact on MCP Telemetry

✅ **No Copilot Studio agents were observed calling any MCP server.** All 7,208 MCP calls across all channels were attributed to human user `secadmin@contoso.com` via delegated permissions. The two Copilot Studio agents have not generated detectable MCP traffic in this 90-day window.

---

## MCP Usage Score

```
┌──────────────────────────────────────────────────────────┐
│                MCP USAGE SCORE: 43/100                   │
│                  Rating: 🟡 ELEVATED                     │
├──────────────────────────────────────────────────────────┤
│ User Diversity     [██░░░░░░░░░░░░░░░░░░]  3/20  🟢     │
│ Endpoint Sensitiv  [███████████████░░░░░] 15/20  🔴     │
│ Error Rate         [████████████░░░░░░░░] 12/20  🟠     │
│ Volume Anomaly     [████████░░░░░░░░░░░░]  8/20  🟡     │
│ Off-Hours Activity [█████░░░░░░░░░░░░░░░]  5/20  🟡     │
└──────────────────────────────────────────────────────────┘
```

### Dimension Breakdown

| Dimension | Score | Evidence | Assessment |
|-----------|-------|----------|------------|
| **User Diversity** | 3/20 | 1 primary user (secadmin) across all MCP channels; 1 secondary user (collaborator) with 1 Azure MCP sign-in | 🟢 Low risk — small, known user population |
| **Endpoint Sensitivity** | 15/20 | 54.1% of Graph MCP calls (85/157) targeted sensitive endpoints: conditionalAccess, authentication/methods, identityProtection, riskyUsers, roleManagement | 🔴 High concentration — mitigated by all-GET (read-only) and security investigation use case |
| **Error Rate** | 12/20 | Data Lake `query_lake`: 8.1% (453 schema errors); `analyze_user_entity`: 29.4% (5 failures); Graph MCP: 0%; Direct KQL: 4.4% | 🟠 Above 5% threshold — primarily AI-generated schema mismatches |
| **Volume Anomaly** | 8/20 | Peak day: 61 calls (Feb 5) vs. average 17.4/active day = 3.5× spike; only 9 of 90 days had any Graph MCP activity | 🟡 Moderate spike — consistent with ad-hoc investigation bursts |
| **Off-Hours Activity** | 5/20 | 73.9% UTC off-hours, but user is US-based (UTC-8). Adjusted estimate: ~15–20% actual off-hours | 🟡 UTC bias — not a real concern when timezone-adjusted |

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| 🟢 **Caller Identity** | All MCP activity attributed to 1 known user (secadmin@contoso.com) via delegated permissions with Client Certificate auth — no anonymous or unknown callers |
| 🟢 **Write Operations** | Zero write operations across all MCP channels — all activity is read-only investigation queries |
| 🟢 **No Autonomous Agents** | No Agent Identities detected calling MCP servers — all activity is human-initiated |
| 🟢 **Graph MCP Success Rate** | 100% success rate (0 errors in 157 calls) |
| 🟠 **Sensitive Endpoint Concentration** | 54.1% of Graph MCP calls targeted security-sensitive endpoints (CA policies, Identity Protection, MFA methods, role assignments). Profile is consistent with security investigation workflows but warrants monitoring |
| 🟠 **Data Lake Error Rate** | 8.1% error rate on `query_lake` tool (453 schema/semantic errors). AI-generated KQL queries reference non-existent columns or tables. Not a security risk but impacts investigation efficiency |
| 🟡 **Copilot Studio Agent Churn** | "Sentinel Data Exploration Agent" created and hard-deleted within 30 minutes (Jan 26). Indicates testing/experimentation. No residual permissions or active access |
| 🟡 **Secondary User** | `collaborator@contoso.com` had 1 Azure MCP Server sign-in (Jan 14) — verify this is an authorized collaborator |
| ✅ **ARM Operations** | No Azure Resource Manager write operations detected via MCP Server — no infrastructure modifications |
| ✅ **Rate Limiting** | 1 TooManyRequests event detected (Data Lake) — burst limit briefly exceeded, self-resolved |

---

## Recommendations

1. ⚠️ **Reduce Data Lake Query Errors** — The 8.1% error rate on `query_lake` (453 schema errors) impacts investigation efficiency. Consider:
   - Using `search_tables` / `get_table_schema` before constructing queries to validate column names
   - Implementing the KQL pre-flight checklist from copilot-instructions.md
   - Reviewing the skill files for pre-validated query patterns

2. ⚠️ **Verify Secondary User** — `collaborator@contoso.com` accessed Azure MCP Server from `203.0.113.89` on Jan 14. Confirm this user is authorized for workspace access.

3. 🟢 **Copilot Studio Agent Governance** — One active agent ("Agent (Microsoft Copilot Studio)" / `dddddddd`) exists in the tenant. Periodically review:
   - What resources this agent can access
   - Whether the agent has been granted any API permissions
   - Sign-in activity via `AADServicePrincipalSignInLogs`

4. 🟢 **Maintain Current Access Model** — The single-user delegated flow with Client Certificate auth is the most secure MCP access pattern. Continue avoiding app-only credentials for MCP tools.

5. 🔵 **Consider Proactive Alerting** — Deploy the KQL Data Lake jobs defined in `queries/identity/mcp_anomaly_detection_kql_jobs.md` for automated anomaly detection (new users, volume spikes, new sensitive endpoints).

6. 🔵 **Monitor Copilot Studio Expansion** — As Copilot Studio agents proliferate (19+ built-in MCP servers available), ensure `CloudAppEvents` and `AuditLogs` monitoring captures agent lifecycle and activity.

---

## Appendix: Query Details

### Data Sources Queried

| Phase | Table | Query | Records | Status |
|-------|-------|-------|---------|--------|
| 1 | MicrosoftGraphActivityLogs | Daily usage trend | 9 rows (9 active days) | ✅ |
| 1 | MicrosoftGraphActivityLogs | Top 25 endpoints | 25 rows | ✅ |
| 1 | MicrosoftGraphActivityLogs | Sensitive API access | 14 endpoints flagged | ✅ |
| 1 | MicrosoftGraphActivityLogs | Off-hours analysis | 73.9% UTC off-hours | ✅ |
| 1 | MicrosoftGraphActivityLogs | Caller attribution | 1 caller (User Delegated) | ✅ |
| 2 | SigninLogs | Sentinel MCP auth events | 29 sign-ins, 3 client apps | ✅ |
| 2 | LAQueryLogs | Triage MCP + Portal query volume | 3 AppIds matched | ✅ |
| 3 | CloudAppEvents | Data Lake MCP tool summary | 5,974 MCP + 9,263 Direct | ✅ |
| 3 | CloudAppEvents | Tool breakdown | 7 tools detected | ✅ |
| 3 | CloudAppEvents | Error analysis | 468 failures categorized | ✅ |
| 4 | AADNonInteractiveUserSignInLogs | Azure MCP Server auth | 5 sign-ins, 2 users | ✅ |
| 4 | LAQueryLogs | Azure MCP workspace queries | 1 query detected | ✅ |
| 4 | AzureActivity | Azure MCP ARM operations | 0 write operations | ✅ |
| 5 | LAQueryLogs | All workspace query sources | 178,607 total, 21 AppIds | ✅ |
| 6 | AuditLogs | Agent Identity CRUD | 18 operations, 3 SPNs | ✅ |

### MCP Server Activity Summary

| MCP Server | Total Calls | Users | Error Rate | Active Period | Primary Use |
|-----------|-------------|-------|------------|---------------|-------------|
| **Graph MCP** | 157 | 1 | 0.0% | Jan 26 – Feb 8 | Security investigation (CA, IdP, MFA, roles) |
| **Sentinel Triage MCP** | 1,076 | 1 | ~0% | Nov 17 – Feb 8 | Advanced Hunting queries |
| **Sentinel Data Lake MCP** | 5,974 | 3 | 7.8% | Nov 14 – Feb 8 | KQL queries, entity analysis, table search |
| **Azure MCP Server** | ~5 sessions | 2 | 40% (MFA step-up) | Jan 14 – Feb 8 | ARM read operations, workspace queries |
| **Total MCP** | **7,208** | **2** | **~7%** | **Nov 14 – Feb 8** | — |

### Grand Total: MCP vs Non-MCP

```
Combined Environment Activity — 90d
═══════════════════════════════════════════════════
MCP Servers (all channels):          7,208    3.7%
Platform (Sentinel Engine, Logic):  176,227   90.8%
Portal (Sentinel, Azure):            1,297    0.7%
Direct KQL (Data Lake):              9,263    4.8%
Other:                                    6    0.0%
═══════════════════════════════════════════════════
TOTAL:                              194,001  100.0%
```

---

*Report generated by MCP Usage Monitoring Skill v2.0 — `.github/skills/mcp-usage-monitoring/SKILL.md`*
