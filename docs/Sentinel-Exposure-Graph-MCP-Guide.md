# Microsoft Sentinel Exposure Graph MCP Server Guide

**Last Updated**: February 2, 2026  
**MCP Server**: `sentinel-graph-mcp`  
**Purpose**: Analyze organizational attack surface and lateral movement paths

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Available Tools](#available-tools)
3. [Core Concepts](#core-concepts)
4. [Getting Started](#getting-started)
5. [Common Investigation Workflows](#common-investigation-workflows)
6. [Query Patterns](#query-patterns)
7. [Tips & Tricks](#tips--tricks)
8. [Troubleshooting](#troubleshooting)
9. [Integration with Other MCP Servers](#integration-with-other-mcp-servers)

---

## Overview

The Microsoft Sentinel Exposure Graph MCP Server provides tools to analyze your organization's security posture by mapping:
- **Attack paths** to critical resources
- **Lateral movement** possibilities from compromised assets
- **Credential exposure** chains through devices and users
- **Permission relationships** between identities and resources

**Key Limitation**: All tools require **known asset names** as input. There is **no discovery/enumeration capability**. You must obtain asset names from other sources first.

---

## Available Tools

### 1. `graph_exposure_perimeter`
**Purpose**: Find all entry points that can reach a target resource

**When to use**:
- Assessing how a critical resource can be compromised
- Understanding attack surface for crown jewel assets
- Identifying which devices/users have access paths to sensitive resources

**Parameters**:
- `targetName` (required): Name of the target resource (e.g., Azure resource, SQL server, Key Vault)
- `minPathLength` (optional): Minimum path length (default: 1)
- `maxPathLength` (optional): Maximum path length (default: 5)
- `resultsCountLimit` (optional): Max results to return (default: 1000)

**Example**:
```javascript
graph_exposure_perimeter({
  targetName: "my-critical-sql-server",
  maxPathLength: 5
})
```

**Returns**:
- List of devices/users that can reach the target
- Criticality scores, risk scores, vulnerability status
- Number of graph connections (exposure metric)
- Edge relationships showing the attack path

---

### 2. `graph_find_blastradius`
**Purpose**: Evaluate potential impact if a source is compromised

**When to use**:
- Incident response - assessing damage from a compromised device/user
- Risk prioritization - identifying high-impact assets
- Privilege escalation analysis

**Parameters**:
- `sourceName` (required): Name of the source asset (device name or UPN)

**Example**:
```javascript
graph_find_blastradius({
  sourceName: "my-laptop-device"
})
```

**Returns**:
- All resources reachable from the compromised source
- Credential chains and permission paths
- Criticality of reachable resources

---

### 3. `graph_find_walkable_paths`
**Purpose**: Map specific attack paths between two assets

**When to use**:
- Understanding HOW an attacker moved from A to B
- Validating specific attack scenarios
- Documenting evidence for incident reports

**Parameters**:
- `sourceName` (required): Starting point (device or user)
- `targetName` (required): Destination resource
- Max 4 hops, 1000 results limit

**Example**:
```javascript
graph_find_walkable_paths({
  sourceName: "compromised-device",
  targetName: "sensitive-resource"
})
```

**Returns**:
- Step-by-step path showing nodes and edges
- Credential types used at each hop
- Permission types required

---

## Core Concepts

### Criticality Levels
| Value | Meaning | Typical Assets |
|-------|---------|----------------|
| **1** | High | Domain controllers, critical servers, privileged users |
| **2** | Medium | Standard workstations, regular users |
| **0** | Low | Unclassified or low-value assets |

### NumberOfAllNeighbours (Exposure Metric)
- Total graph connections for an asset
- Higher number = greater exposure/attack surface
- Example: A device with 365 neighbors has high exposure
- Use to prioritize hardening efforts

### Edge Types (Relationships)
| Edge Type | Meaning | Example |
|-----------|---------|---------|
| **contains** | Device stores credential | Device → Cookie/PRT |
| **can authenticate as** | Credential enables user auth | Cookie → User |
| **has permissions to** | User has RBAC on resource | User → Azure Resource |
| **has credentials of** | Device has user session token | Device → User PRT |

### Credential Types
| Type | Description | Persistence |
|------|-------------|-------------|
| **Primary Refresh Token (PRT)** | Long-lived token for Azure AD auth | Persistent across reboots |
| **Entra User Cookie** | Session-based browser token | Session-bound, less persistent |

### RBAC Roles (Common)
- **Reader**: Read-only access (`*/read`)
- **Contributor**: Manage resources (no RBAC changes)
- **Owner**: Full control including RBAC management (`*`)
- **Custom Roles**: Service-specific (e.g., Azure AI User)

---

## Getting Started

### Prerequisites
1. **Get asset names first** - Use one of these methods:
   - **Defender Advanced Hunting**: Query `DeviceInfo` table
   - **List Incidents**: Extract device/user names from active alerts
   - **Manual input**: From Azure portal, Security Center, or inventory

### Step 1: Discover Asset Names
Since Graph tools don't have discovery, bootstrap with:

**Option A: Query Defender for Devices**
```kql
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceName, DeviceId, OSPlatform
| order by DeviceName asc
```

**Option B: Extract from Incidents**
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| where Severity == "High"
| mv-expand Entities = parse_json(Entities)
| where Entities.Type == "host"
| extend DeviceName = tostring(Entities.HostName)
| summarize Devices = make_set(DeviceName) by IncidentNumber
```

### Step 2: Run Initial Assessment
Start with high-value targets:

```javascript
// Check exposure of critical SQL server
graph_exposure_perimeter({ targetName: "sqlserver-prod-01" })

// Check exposure of Azure OpenAI resource
graph_exposure_perimeter({ targetName: "my-aoai-resource" })

// Check exposure of Key Vault
graph_exposure_perimeter({ targetName: "kv-secrets-prod" })
```

### Step 3: Investigate Findings
For each high-exposure entry point device:

```javascript
// Check blast radius of suspicious device
graph_find_blastradius({ sourceName: "device-name-from-step2" })
```

---

## Common Investigation Workflows

### Workflow 1: Crown Jewel Asset Protection

**Goal**: Understand attack surface for critical infrastructure

```
1. Identify crown jewel assets (SQL, Key Vaults, Azure AI, etc.)
2. Run exposure_perimeter on each asset
3. Review results for:
   - High-exposure devices (NumberOfAllNeighbours > 200)
   - Criticality 1 users with access
   - Devices with vulnerabilities (HasVulnerabilities = true)
4. For high-risk devices, run blast_radius to assess lateral movement potential
5. Prioritize remediation based on:
   - Criticality + Exposure + Vulnerabilities
   - Owner permissions (can modify RBAC)
```

**Example Query Sequence**:
```javascript
// Step 1: Find who can reach SQL server
graph_exposure_perimeter({ targetName: "sql-prod-db" })

// Step 2: Device "desktop-ABC" has exposure 365, check its blast radius
graph_find_blastradius({ sourceName: "desktop-ABC" })

// Step 3: Map specific path from device to SQL
graph_find_walkable_paths({ 
  sourceName: "desktop-ABC", 
  targetName: "sql-prod-db" 
})
```

---

### Workflow 2: Incident Response - Compromised Device

**Goal**: Assess damage and scope from a known compromised asset

```
1. Extract device name from incident/alert
2. Run blast_radius to see what attacker can reach
3. Check if any reachable resources are crown jewels
4. For each critical reachable resource, run exposure_perimeter to find other at-risk devices
5. Isolate device, rotate credentials, force re-authentication
```

**Example**:
```javascript
// Incident reports device "laptop-XYZ" compromised
graph_find_blastradius({ sourceName: "laptop-XYZ" })

// Result shows access to Key Vault "kv-secrets"
// Now check who ELSE can reach this Key Vault
graph_exposure_perimeter({ targetName: "kv-secrets" })
```

---

### Workflow 3: Privileged User Risk Analysis

**Goal**: Assess impact if a privileged user account is compromised

```
1. Identify privileged users (Global Admins, Security Admins, etc.)
2. Run blast_radius on each user's UPN
3. Document all accessible resources
4. Recommend PIM (Privileged Identity Management) if not using
5. Check for impossible travel, anonymous IPs in sign-ins
```

**Example**:
```javascript
// Check blast radius of admin user
graph_find_blastradius({ sourceName: "admin@domain.com" })

// Empty result? Good - user has no persistent credentials on devices
// Non-empty? Lists all resources accessible via stored tokens
```

---

### Workflow 4: Multi-Stage Attack Path Analysis

**Goal**: Reconstruct attack path from initial access to target

```
1. Start with initial compromise point (phishing email device)
2. Run blast_radius to see lateral movement options
3. Identify intermediate hops (devices with credentials)
4. For each hop, check exposure_perimeter of next target
5. Map full attack chain
```

**Example**:
```javascript
// Phishing victim device
graph_find_blastradius({ sourceName: "phished-laptop" })
// → Shows access to "server-ABC"

// Check server's blast radius
graph_find_blastradius({ sourceName: "server-ABC" })
// → Shows access to "domain-controller"

// Validate full path
graph_find_walkable_paths({ 
  sourceName: "phished-laptop", 
  targetName: "domain-controller" 
})
```

---

## Query Patterns

### Pattern 1: Find Most Exposed Devices
**Problem**: Which devices have the widest attack surface?

**Workflow**:
```
1. Pick a critical resource as target
2. Run exposure_perimeter
3. Sort results by NumberOfAllNeighbours descending
4. Top results = most exposed devices
```

**Interpretation**:
- Device with 365 neighbors = very exposed (many connections)
- Device with 56 neighbors = moderately exposed
- Device with 0 neighbors = not in graph or isolated

---

### Pattern 2: Identify Over-Privileged Access
**Problem**: Who has Owner permissions that shouldn't?

**Workflow**:
```
1. Run exposure_perimeter on critical Azure resources
2. Review permissions in results
3. Look for "has permissions to" edges with role = "Owner"
4. Verify if those users should have full control
```

**Red Flags**:
- Non-admin users with Owner on production resources
- Service principals with Owner on multiple Key Vaults
- Field devices with Owner credentials stored

---

### Pattern 3: Credential Exposure Assessment
**Problem**: Which devices store privileged credentials?

**Workflow**:
```
1. Run exposure_perimeter on sensitive resources
2. Trace back through "can authenticate as" edges
3. Find "contains" edges showing credential storage
4. Identify devices with Primary Refresh Tokens (persistent)
```

**Risk Ranking**:
- **High**: PRT on vulnerable device with high exposure
- **Medium**: Session cookie on patched device
- **Low**: PRT on secure admin workstation

---

### Pattern 4: Zero Blast Radius Validation
**Problem**: Confirming devices/users have minimal access

**Workflow**:
```
1. Run blast_radius on device/user
2. Empty result = good security posture
3. Non-empty = document accessible resources
```

**Use Cases**:
- Validating least-privilege implementation
- Confirming field device isolation
- Verifying guest user restrictions

---

## Tips & Tricks

### 1. **Always Start with Exposure Perimeter, Not Blast Radius**
- **Exposure Perimeter**: "Who can attack **this target**?" (defensive view)
- **Blast Radius**: "What can **this source** reach?" (attacker view)
- Start defensive to find vulnerabilities in critical assets

### 2. **Empty Results Don't Always Mean Safe**
Empty blast radius can mean:
- ✅ Good: Device/user has no privileged access (least privilege working)
- ⚠️ Misleading: Device not in graph yet, or query used wrong name
- ⚠️ Data issue: Device is a leaf node, not an entry point

**Verify with**: Check if device exists in Defender inventory first

### 3. **Use Organization-Specific Naming Patterns**
Graph queries are **case-insensitive** but **exact-match required**:
- ✅ Use: Full device name from inventory (`desktop-abc123`)
- ❌ Avoid: Partial names (`desktop*`), wildcards not supported
- 💡 Tip: Keep a list of crown jewel asset names for quick queries

### 4. **Combine Graph + Threat Intelligence**
Workflow:
```
1. Run exposure_perimeter on Azure OpenAI
2. Extract IP addresses from results
3. Run IP enrichment (VPN detection, abuse scores)
4. Correlate with sign-in logs for geographic anomalies
```

### 5. **Prioritize by Criticality × Exposure × Vulnerabilities**
Risk Score Formula:
```
Risk = (Criticality Level) × (NumberOfAllNeighbours / 100) × (HasVulnerabilities ? 2 : 1)
```

Example:
- Criticality 1 device with 365 neighbors + vulnerabilities = **7.3 risk score**
- Criticality 2 device with 56 neighbors + no vulnerabilities = **1.12 risk score**

Focus remediation on highest risk scores.

### 6. **Session Tokens vs Persistent Tokens**
| Token Type | Risk Level | Detection | Mitigation |
|------------|------------|-----------|------------|
| **Entra User Cookie** | Medium | Expires with session | Force sign-out, rotate |
| **Primary Refresh Token (PRT)** | **High** | **Persistent across reboots** | **Device wipe, re-enroll** |

**Action**: If compromised device has PRT to privileged user → **immediate device isolation**

### 7. **Cross-Reference with Conditional Access Policies**
After finding exposure:
```
1. List devices with access to critical resource
2. Check if devices are compliant (Intune)
3. Verify Conditional Access policies enforce:
   - MFA for sensitive resources
   - Compliant device requirement
   - Trusted location restrictions
```

### 8. **Automate Common Queries**
Save frequently used targets:
```python
CROWN_JEWELS = [
    "sql-prod-01",
    "kv-secrets-prod",
    "aoai-production",
    "domain-controller-01"
]

for asset in CROWN_JEWELS:
    result = graph_exposure_perimeter(targetName=asset)
    analyze_and_report(result)
```

### 9. **Use Graph for Attack Disruption Validation**
After implementing controls:
```
Before: exposure_perimeter shows 15 devices can reach Key Vault
After: Deploy Conditional Access requiring compliant devices
Validate: Re-run exposure_perimeter, confirm reduced to 5 approved devices
```

### 10. **Document Walkable Paths for Incident Reports**
For executive reporting:
```javascript
// Get detailed attack path evidence
result = graph_find_walkable_paths({
  sourceName: "initial-compromise-device",
  targetName: "breached-database"
})

// Use to create visual diagram showing:
// Device → Cookie → User → RBAC → Database
```

---

## Troubleshooting

### Issue: Empty Results for Known Assets

**Symptoms**: Query returns `{"Rows": []}`

**Possible Causes**:
1. **Asset name mismatch** - Check exact spelling/capitalization
2. **Asset not in Exposure Graph** - Recently added, not yet ingested
3. **No inbound paths** - Asset is completely isolated (good!)
4. **Wrong query type** - Used blast_radius when exposure_perimeter needed

**Solution**:
```
1. Verify asset name exists in Defender/Azure inventory
2. Try alternative names (hostname vs FQDN vs device ID)
3. Wait 24h for graph ingestion if asset is new
4. Switch query type (exposure vs blast radius)
```

---

### Issue: Too Many Results

**Symptoms**: Query returns 1000+ results, truncated

**Solution**:
```javascript
// Reduce scope with path length
graph_exposure_perimeter({ 
  targetName: "my-resource",
  maxPathLength: 3  // Reduce from default 5
})

// Or increase limit
graph_exposure_perimeter({ 
  targetName: "my-resource",
  resultsCountLimit: 5000
})
```

---

### Issue: Query Timeout

**Symptoms**: Request takes >30 seconds, fails

**Solution**:
- Reduce `maxPathLength` to 3 or 4
- Reduce `resultsCountLimit` to 500
- Query during off-peak hours
- Break large queries into smaller asset groups

---

### Issue: Unexpected Zero Blast Radius

**Context**: User/device should have access based on Azure RBAC

**Possible Causes**:
1. **JIT (Just-In-Time) Access** - Permissions are temporary, not persistent
2. **PIM Eligible** - User must activate role first (not permanently assigned)
3. **Token not stored** - User authenticated but device doesn't cache credentials
4. **Service Principal** - Graph may not track non-user identities fully

**Validation**:
```
1. Check Azure portal for permanent vs eligible role assignments
2. Review sign-in logs to confirm recent authentication
3. Verify device has Defender agent reporting credential storage
```

---

## Integration with Other MCP Servers

### 1. Sentinel Data Lake MCP
**Use Case**: Correlate graph findings with security logs

```javascript
// Step 1: Find exposed devices via Graph
devices = graph_exposure_perimeter({ targetName: "key-vault-prod" })

// Step 2: Query sign-in logs for those devices
kql_query = `
SigninLogs
| where TimeGenerated > ago(30d)
| where DeviceName in ("device1", "device2", "device3")
| where RiskLevel != "none"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskLevel
`
query_lake({ query: kql_query })
```

---

### 2. Sentinel Triage MCP (Defender XDR)
**Use Case**: Get detailed device/user context after Graph query

```javascript
// Step 1: Graph shows device "laptop-ABC" has high exposure
graph_exposure_perimeter({ targetName: "critical-resource" })

// Step 2: Get full device details from Defender
GetDefenderMachine({ id: "laptop-ABC" })

// Step 3: Check alerts on that device
GetDefenderMachineAlerts({ id: "laptop-ABC" })
```

---

### 3. Microsoft Graph MCP (Azure AD)
**Use Case**: Enumerate role assignments for users found in Graph

```javascript
// Step 1: Graph shows user has access via RBAC
graph_exposure_perimeter({ targetName: "azure-openai" })
// Result: User "user@domain.com" has permissions

// Step 2: Get full permission inventory
microsoft_graph_get({ endpoint: "/v1.0/users/{userId}/memberOf" })

// Step 3: Check for PIM eligibility
microsoft_graph_get({ 
  endpoint: "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=principalId eq '{userId}'"
})
```

---

### 4. KQL Search MCP
**Use Case**: Generate optimized queries based on Graph findings

```javascript
// Step 1: Graph reveals device with vulnerabilities
graph_exposure_perimeter({ targetName: "resource-X" })
// Shows: Device "vuln-device" has exposure 250

// Step 2: Generate KQL to investigate device activity
generate_kql_query({
  intent: "Find all failed sign-in attempts from device vuln-device in last 7 days",
  tables: ["SigninLogs", "DeviceLogonEvents"]
})
```

---

### 5. Sentinel Heatmap/Geomap MCP
**Use Case**: Visualize exposure findings geographically

```javascript
// Step 1: Graph finds 20 devices can reach Key Vault
result = graph_exposure_perimeter({ targetName: "kv-prod" })

// Step 2: Query sign-ins for those devices
kql_query = `
SigninLogs
| where TimeGenerated > ago(7d)
| where DeviceName in ({device_list})
| summarize Attempts = count() by IPAddress, Location, tostring(LocationDetails.city), tostring(LocationDetails.geoCoordinates.latitude), tostring(LocationDetails.geoCoordinates.longitude)
`

// Step 3: Visualize on geomap
show_attack_map({ data: results_from_kql })
```

---

## Advanced Patterns

### Pattern: Credential Chain Analysis
**Goal**: Trace credential flow from device to resource

```javascript
// 1. Find devices that can reach SQL server
exposure = graph_exposure_perimeter({ targetName: "sql-prod" })

// 2. For each device, map the credential chain:
// Example result shows:
//   Device "laptop-XYZ"
//     → contains → Entra Cookie (74f40f54...)
//       → can authenticate as → User "admin@domain"
//         → has permissions to → SQL Server (Owner role)

// 3. Risk assessment:
//   - Cookie = Session-based (medium risk)
//   - Owner role = Full control (high impact)
//   - Recommendation: Demote to Reader, implement PIM
```

---

### Pattern: Multi-Hop Attack Path Discovery
**Goal**: Find all 3-hop attack chains to a target

```javascript
// Query with specific path length
result = graph_exposure_perimeter({ 
  targetName: "domain-controller",
  minPathLength: 3,
  maxPathLength: 3
})

// Analyze edges to reconstruct chains:
// Device → Token → User → Permissions → Resource
// Look for: Criticality 0 device → Criticality 1 user → Critical asset
```

---

### Pattern: Vulnerability-Driven Prioritization
**Goal**: Focus on devices with vulnerabilities + high exposure

```javascript
// 1. Get exposure for critical resource
result = graph_exposure_perimeter({ targetName: "azure-openai" })

// 2. Filter to vulnerable devices
vulnerable_devices = result.rows.filter(row => 
  row.HasVulnerabilities === true && 
  row.NumberOfAllNeighbours > 200
)

// 3. For each vulnerable device, check blast radius
for (device of vulnerable_devices) {
  blast = graph_find_blastradius({ sourceName: device.NodeName })
  if (blast.rows.length > 10) {
    alert(`Critical: ${device.NodeName} has vulns + high exposure + large blast radius`)
  }
}
```

---

## Best Practices Summary

✅ **DO**:
- Always obtain asset names from inventory before querying Graph
- Start with exposure_perimeter for defensive posture assessment
- Use blast_radius for incident response and impact analysis
- Cross-reference Graph findings with sign-in logs and alerts
- Prioritize remediation by: Criticality × Exposure × Vulnerabilities
- Document walkable paths for incident reports
- Regularly audit exposure perimeter of crown jewel assets

❌ **DON'T**:
- Don't expect Graph to discover/enumerate assets (it can't)
- Don't assume empty blast radius means no risk (could be data issue)
- Don't ignore session tokens (they're still exploitable)
- Don't query Graph without validating asset names exist first
- Don't rely solely on Graph (combine with threat intel, logs, alerts)

---

## Sample Investigation Checklist

**Pre-Investigation**:
- [ ] Identified crown jewel assets (SQL, Key Vaults, Azure AI, etc.)
- [ ] Obtained device inventory from Defender or incidents
- [ ] Validated asset names match Graph naming conventions

**Exposure Assessment**:
- [ ] Ran exposure_perimeter on all crown jewel assets
- [ ] Documented devices with exposure > 200
- [ ] Identified Criticality 1 users with Owner permissions
- [ ] Flagged devices with vulnerabilities + high exposure

**Impact Analysis**:
- [ ] Ran blast_radius on high-exposure devices
- [ ] Documented reachable critical resources
- [ ] Mapped credential chains (PRT vs session tokens)
- [ ] Cross-referenced with active incidents/alerts

**Remediation Planning**:
- [ ] Prioritized by risk score (Criticality × Exposure × Vulns)
- [ ] Recommended PIM for Owner role assignments
- [ ] Suggested device isolation for PRT credential exposure
- [ ] Created Conditional Access policies for high-risk paths

**Validation**:
- [ ] Re-ran queries post-remediation
- [ ] Confirmed reduced exposure metrics
- [ ] Documented before/after comparison
- [ ] Updated security architecture diagrams

---

## Additional Resources

- **Exposure Graph Documentation**: [Microsoft Learn - Security Exposure Management](https://learn.microsoft.com/en-us/security-exposure-management/)
- **Conditional Access**: [Microsoft Learn - Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/)
- **PIM Configuration**: [Microsoft Learn - Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/)
- **Defender XDR Integration**: [Microsoft Sentinel + Defender XDR](https://learn.microsoft.com/en-us/azure/sentinel/microsoft-365-defender-sentinel-integration)

---

**Document Version**: 1.0  
**Feedback**: Submit issues or enhancements to your security operations team
