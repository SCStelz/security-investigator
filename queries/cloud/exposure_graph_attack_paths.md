# ExposureGraph Critical Assets & Attack Paths - Complete Query Library

**Created:** 2026-01-15  
**Updated:** 2026-02-12  
**Platform:** Microsoft Defender XDR | Azure Resource Graph  
**Tables:** ExposureGraphNodes, ExposureGraphEdges, securityresources (ARG)  
**Keywords:** exposure graph, critical assets, attack paths, vulnerabilities, RCE, privilege escalation, internet-facing, cloud resources, Azure, AWS, GCP, identity, storage, entra-userCookie, cookie chain, choke point, blast radius, highRiskVulnerabilityInsights, Key Vault, OpenAI, permissions, Owner, Contributor, Secrets Officer  
**MITRE:** T1068, T1190, T1078, T1550.004, T1539, T1552.001, TA0004, TA0001, TA0006, TA0008  
**Timeframe:** Point-in-time (snapshot data)

---

## 📋 Overview

This guide provides comprehensive KQL queries for finding critical assets and analyzing attack paths using the **ExposureGraphNodes** and **ExposureGraphEdges** tables in Microsoft Defender XDR Advanced Hunting, plus **Azure Resource Graph** queries for pre-computed cloud attack paths.

**32 production-ready queries** organized into 12 sections for security operations.

---

## 🎯 Query Categories

### 1. Critical Devices & Assets (Queries 1-4)
- **Query 1**: All critical devices (criticality < 4)
- **Query 2**: Critical devices exposed to internet
- **Query 3**: Critical VMs vulnerable to RCE
- **Query 4**: Internet-facing devices with privilege escalation vulns

### 2. Critical Users & Identities (Query 5)
- **Query 5**: Users logged into multiple critical devices

### 3. Attack Path Analysis (Queries 6-8)
- **Query 6**: Multi-hop attack paths (RCE device → User → Critical server)
- **Query 7**: Hybrid cloud-to-on-premises attack paths
- **Query 8**: IP-to-VM attack paths (up to 3 hops)

### 4. Cloud Multi-Environment (Queries 9-10)
- **Query 9**: Resources across Azure/AWS/GCP
- **Query 10**: Critical cloud assets summary

### 5. Vulnerability Analysis (Queries 11-12)
- **Query 11**: CVEs affecting critical devices
- **Query 12**: Critical devices ranked by vulnerability count

### 6. Exploration & Discovery (Queries 13-16)
- **Query 13**: All node types (asset types)
- **Query 14**: All edge types (relationship types)
- **Query 15**: Incoming connections to VMs
- **Query 16**: Outgoing connections from VMs

### 7. External Data Sources (Queries 17-19)
- **Query 17**: Assets from ServiceNow CMDB
- **Query 18**: Tenable vulnerability data
- **Query 19**: Rapid7 vulnerability data

### 8. Schema Inspection (Query 20)
- **Query 20**: Sample node properties for VMs

### 9. Vulnerable Device Attack Paths — Cookie Chain Analysis (Queries 21-25)
- **Query 21**: Devices with high-risk vulnerability insights (entry points)
- **Query 22**: Direct attack paths: VulnDevice → Cookie → User → Target (by type)
- **Query 23**: Group-mediated attack paths: VulnDevice → Cookie → User → Group → Target
- **Query 24**: Discover all intermediary patterns between devices and targets
- **Query 25**: Comprehensive path count (union direct + group-mediated)

### 10. Attack Path Permission Analysis (Queries 26-28)
- **Query 26**: Permission role breakdown on attack paths (Reader/Owner/Contributor/Secrets)
- **Query 27**: High-privilege users with dangerous role assignments via attack paths
- **Query 28**: Critical users (by Entra criticality level) reachable from vulnerable devices

### 11. Entry Points & Choke Points (Queries 29-30)
- **Query 29**: Top entry-point devices ranked by blast radius (unique targets reachable)
- **Query 30**: Choke point detection — users appearing in most attack paths

### 12. Azure Resource Graph — Pre-Computed Attack Paths (Queries 31-32)
- **Query 31**: All pre-computed attack paths from Azure Resource Graph
- **Query 32**: Attack path summary by scenario with instance counts

---

## 🔑 Key Concepts

### Criticality Levels
- **Level 0-1**: Most critical assets (domain controllers, high-value servers)
- **Level 2-3**: High priority assets
- **Level 4+**: Standard assets
- **Lower number = Higher criticality**

### Node Categories
Common categories you'll see:
- `device` - Physical or virtual devices
- `virtual_machine` - Cloud VMs
- `identity` - User accounts and service principals
- `ip_address` - Network addresses
- `compute` - Compute resources

### Edge Labels (Relationships)
Common edge types (by volume):
- `has permissions to` - Azure RBAC role assignments to resources
- `affecting` - CVE vulnerabilities affecting assets
- `member of` - Group membership relationships
- `has role on` - Role assignments (often via groups)
- `contains` - Parent contains child (e.g., device → entra-userCookie)
- `can authenticate as` - Identity impersonation via cached credentials
- `Can Authenticate As` - Authentication relationships (on-prem/identity)
- `CanRemoteInteractiveLogonTo` - Remote login permissions
- `has credentials of` - Device has stored credentials for a user
- `frequently logged in by` - Device frequently used by a user

### Node Property Reference — Key Security Properties

**Devices (`NodeProperties.rawData`):**

| Property | Type | Description |
|----------|------|-------------|
| `highRiskVulnerabilityInsights` | dynamic | Vulnerability summary — the PRIMARY property for attack path entry points |
| `highRiskVulnerabilityInsights.hasHighOrCritical` | bool | Device has high/critical severity CVEs |
| `highRiskVulnerabilityInsights.maxCvssScore` | real | Highest CVSS score across all CVEs on device |
| `highRiskVulnerabilityInsights.vulnerableToRemoteCodeExecution` | bool | Device has RCE-exploitable CVEs |
| `highRiskVulnerabilityInsights.vulnerableToPrivilegeEscalation` | bool | Device has privesc-exploitable CVEs |
| `highRiskVulnerabilityInsights.explotabilityLevels` | dynamic | Breakdown of exploitability categories |
| `criticalityLevel` | dynamic | Nested object: `{criticalityLevel: int, ruleNames: [...]}` |
| `exposureScore` | real | Device exposure score (0-100) |
| `riskScore` | real | Device risk score (0-100) |
| `publicIP` | string | Public IP if internet-facing |
| `IsInternetFacing` | bool | Legacy internet-facing flag |
| `exposedToInternet` | bool | Current internet-facing flag |

> ⚠️ **PITFALL**: `vulnerableToRCE` and `hasVulnerabilities` do NOT reliably exist as top-level properties on most devices. Always use `highRiskVulnerabilityInsights` instead. The legacy `vulnerableToRCE` property exists only on a subset of nodes.

**Users (`NodeProperties.rawData`):**

| Property | Type | Description |
|----------|------|-------------|
| `criticalityLevel` | dynamic | Nested JSON: `{type, criticalityLevel: int, ruleBasedCriticalityLevel: int, ruleNames: [...]}` |
| `assignedRoles` | dynamic | Entra ID directory roles assigned to user |
| `accountEnabled` | bool | Whether account is active |
| `isActive` | bool | Recent activity flag |
| `accountUpn` | string | User Principal Name |
| `hasLeakedCredentials` | bool | Identity Protection leaked credentials flag |
| `hasAdLeakedCredentials` | bool | AD-sourced leaked credentials flag |

> ⚠️ **PITFALL**: User `criticalityLevel` is a nested JSON string, NOT a plain integer. You must use `parse_json(tostring(NodeProperties.rawData.criticalityLevel)).criticalityLevel` to extract the numeric level.

**Storage Accounts (`NodeProperties.rawData`):**

| Property | Type | Description |
|----------|------|-------------|
| `containsSensitiveData` | bool | Purview classification: contains sensitive data |
| `exposedToInternet` | bool | Storage account is publicly accessible |
| `criticalityLevel` | int | Asset criticality (plain int, not nested) |

**Edge Properties (`EdgeProperties.rawData`):**

| Edge Label | Key Property | Description |
|------------|-------------|-------------|
| `has permissions to` | `permissions.roles[]` | Array of RBAC roles: `{name, id, roleAssignmentId, actions, dataActions}` |
| `has permissions to` | `permissions.evidence` | Node IDs and edge IDs forming the permission chain |

### entra-userCookie — The Attack Path Pivot

The `entra-userCookie` node type represents a **cached Entra ID authentication token** stored on a device. This is the critical pivot in identity-based attack paths:

```
Device (compromised) → contains → entra-userCookie → can authenticate as → User → has permissions to → Azure Resource
```

**Attack scenario**: If an attacker compromises a device with high-severity vulnerabilities, they can extract cached authentication cookies to impersonate the logged-in user and access any Azure resource that user has permissions to — **without needing the user's password or MFA**.

This maps to MITRE ATT&CK:
- **T1539**: Steal Web Session Cookie
- **T1550.004**: Use Alternate Authentication Material: Web Session Cookie

---

## 🚀 Quick Start Examples

### Find Your Most Critical Assets

```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| extend CriticalityLevel = tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| project 
    DeviceName = NodeName,
    CriticalityLevel,
    Categories,
    NodeLabel
| order by CriticalityLevel asc
```

**Sample Results:**
```
DeviceName                                  CriticalityLevel  Categories                           NodeLabel
ashtravel-dc.ashtravel.alpineskihouse.co   0                 [compute, device, virtual_machine]   microsoft.compute/virtualmachines
mb-dc1.internal.niseko.alpineskihouse.co   0                 [compute, device, virtual_machine]   microsoft.compute/virtualmachines
main-dc.zava-corp.com                      1                 [compute, device, virtual_machine]   microsoft.compute/virtualmachines
```

---

### Find Internet-Exposed Critical Assets

```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| where isnotnull(NodeProperties.rawData.IsInternetFacing)
| project 
    DeviceName = NodeName,
    CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel,
    InternetFacing = "Yes"
| order by CriticalityLevel asc
```

---

### Discover All Asset Types in Your Environment

```kql
ExposureGraphNodes
| summarize NodeCount = count() by NodeLabel
| order by NodeCount desc
```

**Use this to understand what's tracked** before building more complex queries.

---

### Find All Relationship Types

```kql
ExposureGraphEdges
| summarize EdgeCount = count() by EdgeLabel
| order by EdgeCount desc
```

**Use this to understand what connections exist** in your attack surface.

---

## 📊 Multi-Cloud Inventory

```kql
ExposureGraphNodes
| where NodeLabel contains "microsoft.compute" or NodeLabel contains "aws." or NodeLabel contains "gcp."
| extend CloudProvider = case(
    NodeLabel contains "microsoft.compute", "Azure",
    NodeLabel contains "aws.", "AWS",
    NodeLabel contains "gcp.", "GCP",
    "Other"
)
| summarize 
    ResourceCount = count(),
    SampleResources = make_set(NodeName, 5)
    by CloudProvider, NodeLabel
| order by CloudProvider asc, ResourceCount desc
```

**Sample Results:**
```
CloudProvider  NodeLabel                                ResourceCount  SampleResources
Azure         microsoft.compute/virtualmachines/ext...  279           [MicrosoftMonitoringAgent, AzurePolicyforWindows, ...]
Azure         microsoft.compute/virtualmachines        92            [vnevado-proxy, D4IoT, w11-gsa, ...]
GCP           gcp.serviceaccount                       91            [microsoft-defender-cspm@..., ...]
```

---

## 🔗 Graph Query Pattern

Attack path queries use the `make-graph` and `graph-match` operators:

```kql
// Step 1: Filter nodes to reduce graph size
let FilteredNodes = ExposureGraphNodes
| where <filter conditions>;

// Step 2: Build graph structure
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with FilteredNodes on NodeId

// Step 3: Match patterns
| graph-match (SourceNode)-[edge]->(TargetNode)
    where <pattern conditions>
    project <output columns>
```

**Key points:**
- Filter nodes FIRST (performance)
- Use `make-graph` to create graph structure
- Use `graph-match` with pattern matching syntax
- Arrow syntax: `(Node1)-[edge]->(Node2)` means "Node1 connects to Node2"
- Use `*1..3` for multi-hop paths: `(A)-[edge*1..3]->(B)`

---

## 🎯 Common Use Cases

### Security Triage Priority
1. **Query 1** - Get all critical assets
2. **Query 2** - Filter for internet-exposed
3. **Query 11** - Check CVEs affecting them
4. **Query 12** - Rank by vulnerability count

### Attack Path Investigation
1. **Query 6** - Multi-hop attack paths (RCE → User → Critical Server)
2. **Query 7** - Hybrid cloud/on-prem paths
3. **Query 8** - External IP exposure paths
4. **Query 22** - Cookie chain: VulnDevice → Cookie → User → Azure Resource
5. **Query 23** - Group-mediated: VulnDevice → Cookie → User → Group → Resource
6. **Query 24** - Discover ALL intermediary patterns automatically
7. **Query 25** - Comprehensive deduplicated path count

### Permission & Privilege Analysis
1. **Query 26** - Role breakdown: who has Reader vs Owner vs Secrets access?
2. **Query 27** - High-privilege users reachable via attack paths
3. **Query 28** - Critical users (Global Admin, etc.) exposed by vulnerable devices

### Blast Radius & Choke Points
1. **Query 29** - Top entry-point devices by blast radius
2. **Query 30** - Choke point users (highest-impact identity pivots)

### Identity Risk Assessment
1. **Query 5** - Users with access to multiple critical devices
2. **Query 6** - Attack paths involving users
3. **Query 28** - Critical users reachable from vulnerable devices

### Cloud Security Posture
1. **Query 9** - Multi-cloud inventory
2. **Query 10** - Critical cloud assets
3. **Query 3** - Cloud VMs with RCE vulns
4. **Query 31-32** - Azure Resource Graph pre-computed attack paths

---

## 🛠️ How to Run These Queries

### Method 1: Copilot with MCP Tools (Recommended)

Ask Copilot:
```
"Run the critical devices query from the ExposureGraph guide"
```

Copilot will use the `RunAdvancedHuntingQuery` tool from the Sentinel Triage MCP server.

### Method 2: Microsoft Defender Portal

1. Go to **Microsoft Defender Portal** → [https://security.microsoft.com](https://security.microsoft.com)
2. Navigate to **Hunting** → **Advanced Hunting**
3. Copy query from this document
4. Paste into query editor
5. Click **Run query**

### Method 3: PowerShell with Microsoft Graph API

```powershell
$query = @"
ExposureGraphNodes
| where set_has_element(Categories, "device")
| take 10
"@

Invoke-MgSecurityRunHuntingQuery -Query $query
```

---

## 📚 Additional Resources

### Official Documentation
- [Query the Enterprise Exposure Graph](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph)
- [Exposure Graph Schemas and Operators](https://learn.microsoft.com/en-us/security-exposure-management/schemas-operators)
- [Hunt for Threats Using the Hunting Graph](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-graph)

### Schema Reference

**ExposureGraphNodes Columns:**
- `NodeId` (string) - Unique identifier
- `NodeLabel` (string) - Node type (e.g., "microsoft.compute/virtualmachines")
- `NodeName` (string) - Display name
- `Categories` (dynamic) - Array of categories
- `NodeProperties` (dynamic) - Properties including security insights
- `EntityIds` (dynamic) - Known identifiers (Device IDs, Azure Resource IDs, etc.)

**ExposureGraphEdges Columns:**
- `SourceNodeId` (string) - Source node identifier
- `TargetNodeId` (string) - Target node identifier
- `EdgeLabel` (string) - Relationship type
- `EdgeProperties` (dynamic) - Edge-specific properties
- `SourceNodeLabel` (string) - Source node type
- `TargetNodeLabel` (string) - Target node type
- `SourceNodeName` (string) - Source node name
- `TargetNodeName` (string) - Target node name

---

## ⚠️ Important Notes

### Data Source
- These queries run in **Defender XDR Advanced Hunting** (NOT Sentinel Data Lake)
- Use the `RunAdvancedHuntingQuery` tool from the Sentinel Triage MCP server
- Tables available: ExposureGraphNodes, ExposureGraphEdges, Device*, Alert*, Email*, etc.

### Timestamp Differences
- **Advanced Hunting**: Uses `Timestamp` column
- **Sentinel Data Lake**: Uses `TimeGenerated` column
- ExposureGraph tables may not have timestamp columns (they represent current state)

### Performance Tips
- **Filter early**: Reduce nodes before graph operations
- **Use `take`**: Limit results during development
- **Test incrementally**: Start simple, add complexity gradually
- **Avoid `*`**: Project only needed columns

### Data Freshness
- Exposure graph data updates periodically (not real-time)
- Attack paths are recalculated as environment changes
- Check node properties for last update timestamps

---

## 🎓 Example Workflow: Investigating Critical Asset Exposure

**Scenario**: Security team needs to assess risk of critical assets exposed to attack paths

### Step 1: Identify Critical Assets
```kql
// Query 1 - Get all critical devices
ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
```

### Step 2: Check Internet Exposure
```kql
// Query 2 - Filter for internet-facing
ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| where isnotnull(NodeProperties.rawData.IsInternetFacing)
```

### Step 3: Identify Vulnerabilities
```kql
// Query 11 - CVEs affecting critical devices
let CriticalDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| project NodeId, DeviceName = NodeName;
ExposureGraphEdges
| where EdgeLabel == "affecting"
| where SourceNodeLabel == "Cve"
| join kind=inner CriticalDeviceIds on $left.TargetNodeId == $right.NodeId
| project DeviceName, CVE = SourceNodeName
```

### Step 4: Map Attack Paths
See **Query 6** below in the complete query library for multi-hop attack path detection.

### Step 5: Prioritize Remediation
1. Focus on critical assets (level 0-1)
2. Prioritize internet-exposed assets
3. Address assets with most CVEs first
4. Consider attack path choke points

---

## 💡 Pro Tips

1. **Start with exploration queries** (13-16) to understand your environment
2. **Filter by criticality level < 2** for highest priority assets
3. **Combine with other Defender tables** (AlertEvidence, DeviceTvmSoftwareVulnerabilities)
4. **Save queries as hunting rules** for continuous monitoring
5. **Use graph-match for complex attack paths** instead of multiple joins
6. **Check NodeProperties.rawData** for rich security context
7. **Correlate with SecurityIncident table** to find active threats to critical assets
8. **Use `highRiskVulnerabilityInsights`** not `vulnerableToRCE` for vulnerability filtering — the former is reliably populated on devices
9. **User criticality is nested JSON** — always `parse_json(tostring(...))` before extracting `criticalityLevel`
10. **Edge properties contain RBAC roles** — parse `EdgeProperties.rawData.permissions.roles` for Owner/Contributor/Secrets analysis
11. **Two attack path sources exist** — ExposureGraph (identity-based device→user→resource) and Azure Resource Graph (cloud-native internet-exposed→resource)
12. **Union direct + group-mediated paths** for comprehensive coverage — group membership adds ~15-25% more paths

---

**Last Updated**: 2026-02-12  
**Query File**: ExposureGraph_CriticalAssets_AttackPaths.kql  
**Author**: Security Investigation System
## 📚 Complete Query Library

### SECTION 1: Critical Devices & Assets

#### Query 1: Find All Critical Devices (Criticality Level < 4)

**Description**: Lists all devices with high criticality (levels 1-3, where lower = more critical)  
**Use Case**: Identify most important assets requiring priority protection

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time device inventory. Not event-driven; CD requires temporal detection with Timestamp/TimeGenerated filtering."
-->
```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| extend CriticalityLevel = tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| project 
    DeviceName = NodeName,
    DeviceId = NodeId,
    CriticalityLevel,
    Categories,
    EntityIds,
    NodeLabel
| order by CriticalityLevel asc
```

#### Query 2: Critical Devices Exposed to Internet

**Description**: Find critical devices that are internet-facing (high risk)  
**Use Case**: Priority remediation - critical assets with external exposure

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time device posture query. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| where isnotnull(NodeProperties.rawData.IsInternetFacing)
| extend CriticalityLevel = tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| extend InternetFacing = tostring(NodeProperties.rawData.IsInternetFacing)
| project 
    DeviceName = NodeName,
    DeviceId = NodeId,
    CriticalityLevel,
    InternetFacing,
    Categories,
    NodeLabel
| order by CriticalityLevel asc
```

#### Query 3: Critical Virtual Machines Vulnerable to RCE

**Description**: Find critical VMs exposed to internet with Remote Code Execution vulnerabilities  
**Use Case**: Highest risk assets requiring immediate attention

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time VM vulnerability posture. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| where set_has_element(Categories, "virtual_machine")
| where isnotnull(NodeProperties.rawData.exposedToInternet)
| where isnotnull(NodeProperties.rawData.vulnerableToRCE)
| extend OSType = tostring(NodeProperties.rawData.osType)
| project 
    VMName = NodeName,
    VMId = NodeId,
    NodeLabel,
    OSType,
    ExposedToInternet = "Yes",
    VulnerableToRCE = "Yes",
    Categories
| order by VMName asc
```

#### Query 4: Internet-Facing Devices Vulnerable to Privilege Escalation

**Description**: Find internet-facing devices with privilege escalation vulnerabilities  
**Use Case**: Identify devices vulnerable to privilege escalation attacks from external sources

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time device vulnerability posture. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| where isnotnull(NodeProperties.rawData.IsInternetFacing)
| where isnotnull(NodeProperties.rawData.VulnerableToPrivilegeEscalation)
| where set_has_element(Categories, "device")
| extend PrivEscVulnerable = tostring(NodeProperties.rawData.VulnerableToPrivilegeEscalation)
| project 
    DeviceName = NodeName,
    DeviceId = NodeId,
    NodeLabel,
    Categories,
    VulnerableToPrivilegeEscalation = PrivEscVulnerable,
    InternetFacing = "Yes"
| order by DeviceName asc
```

---

### SECTION 2: Critical Users & Identities

#### Query 5: Users Logged Into Multiple Critical Devices

**Description**: Find users with access to more than one critical device (potential lateral movement risk)  
**Use Case**: Identify users with broad access to critical infrastructure

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time identity-device correlation via graph traversal. Not event-driven; CD requires temporal detection."
-->
```kql
let IdentitiesAndCriticalDevices = ExposureGraphNodes
| where
    // Critical Device (criticality level < 4)
    (set_has_element(Categories, "device") and isnotnull(NodeProperties.rawData.criticalityLevel) and NodeProperties.rawData.criticalityLevel.criticalityLevel < 4)
    // or identity
    or set_has_element(Categories, "identity");
ExposureGraphEdges
| where EdgeLabel == "Can Authenticate As"
| make-graph SourceNodeId --> TargetNodeId with IdentitiesAndCriticalDevices on NodeId
| graph-match (Device)-[canConnectAs]->(Identity)
    where set_has_element(Identity.Categories, "identity") and set_has_element(Device.Categories, "device")
    project IdentityIds=Identity.EntityIds, DeviceIds=Device.EntityIds, IdentityName=Identity.NodeName, DeviceName=Device.NodeName
| mv-apply DeviceIds on (
    where DeviceIds.type == "DeviceInventoryId")
| mv-apply IdentityIds on (
    where IdentityIds.type == "SecurityIdentifier")
| summarize 
    NumberOfDevicesUserLoggedinTo=count(), 
    DeviceList=make_set(DeviceName) 
    by UserId=tostring(IdentityIds.id), IdentityName
| where NumberOfDevicesUserLoggedinTo > 1
| project 
    UserId,
    IdentityName,
    NumberOfCriticalDevices = NumberOfDevicesUserLoggedinTo,
    CriticalDevices = DeviceList
| order by NumberOfCriticalDevices desc
```

---

### SECTION 3: Attack Path Analysis

#### Query 6: Attack Paths - Devices with RCE → Users → Critical Servers

**Description**: Find attack paths where RCE-vulnerable devices connect to users who can remotely login to critical servers  
**Use Case**: Identify multi-hop attack chains from vulnerable endpoints to critical assets

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time attack path graph traversal. Not event-driven; CD requires temporal detection."
-->
```kql
let IdentitiesAndCriticalDevices = ExposureGraphNodes
| where 
    // Critical devices & devices with RCE vulnerabilities
    (set_has_element(Categories, "device") and 
        (
            // Critical devices
            (isnotnull(NodeProperties.rawData.criticalityLevel) and NodeProperties.rawData.criticalityLevel.criticalityLevel < 4)
            or 
            // Devices with RCE vulnerability
            isnotnull(NodeProperties.rawData.vulnerableToRCE)
        )
    )
    or 
    // identity
    set_has_element(Categories, "identity");
ExposureGraphEdges
| where EdgeLabel in~ ("Can Authenticate As", "CanRemoteInteractiveLogonTo")
| make-graph SourceNodeId --> TargetNodeId with IdentitiesAndCriticalDevices on NodeId
| graph-match (DeviceWithRCE)-[CanConnectAs]->(Identity)-[CanRemoteLogin]->(CriticalDevice)
    where 
        CanConnectAs.EdgeLabel =~ "Can Authenticate As" and
        CanRemoteLogin.EdgeLabel =~ "CanRemoteInteractiveLogonTo" and
        set_has_element(Identity.Categories, "identity") and 
        set_has_element(DeviceWithRCE.Categories, "device") and isnotnull(DeviceWithRCE.NodeProperties.rawData.vulnerableToRCE) and
        set_has_element(CriticalDevice.Categories, "device") and isnotnull(CriticalDevice.NodeProperties.rawData.criticalityLevel)
    project 
        RCEDeviceName = DeviceWithRCE.NodeName,
        RCEDeviceIds = DeviceWithRCE.EntityIds,
        IdentityName = Identity.NodeName,
        IdentityIds = Identity.EntityIds,
        CriticalDeviceName = CriticalDevice.NodeName,
        CriticalDeviceIds = CriticalDevice.EntityIds,
        CriticalityLevel = CriticalDevice.NodeProperties.rawData.criticalityLevel.criticalityLevel
| order by CriticalityLevel asc
```

#### Query 7: Hybrid Attack Paths - Cloud to On-Premises

**Description**: Identify potential hybrid attack paths between cloud VMs and on-premises devices  
**Use Case**: Detect lateral movement opportunities across cloud/on-prem boundaries

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time hybrid attack path mapping. Not event-driven; CD requires temporal detection."
-->
```kql
let CloudAssets = ExposureGraphNodes
| where Categories has "virtual_machine" and (NodeLabel contains "microsoft.compute" or NodeLabel contains "aws." or NodeLabel contains "gcp.");
let OnPremAssets = ExposureGraphNodes
| where Categories has "device" and not(NodeLabel contains "microsoft.compute" or NodeLabel contains "aws." or NodeLabel contains "gcp.");
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (CloudVM)-[edge1]->(Identity)-[edge2]->(OnPremDevice)
    where set_has_element(CloudVM.Categories, "virtual_machine") and 
        (CloudVM.NodeLabel contains "microsoft.compute" or CloudVM.NodeLabel contains "aws." or CloudVM.NodeLabel contains "gcp.") and
        set_has_element(Identity.Categories, "identity") and
        set_has_element(OnPremDevice.Categories, "device") and
        not(OnPremDevice.NodeLabel contains "microsoft.compute" or OnPremDevice.NodeLabel contains "aws." or OnPremDevice.NodeLabel contains "gcp.")
    project 
        CloudVMName = CloudVM.NodeName,
        CloudVMLabel = CloudVM.NodeLabel,
        IdentityName = Identity.NodeName,
        OnPremDeviceName = OnPremDevice.NodeName,
        Edge1Label = edge1.EdgeLabel,
        Edge2Label = edge2.EdgeLabel
| order by CloudVMName asc
```

#### Query 8: Attack Paths from IPs to Critical VMs (Up to 3 Hops)

**Description**: Show all paths from IP addresses to virtual machines passing through up to 3 assets  
**Use Case**: Understand external network exposure and access paths to VMs

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time IP-to-VM path analysis. Not event-driven; CD requires temporal detection."
-->
```kql
let IPsAndVMs = ExposureGraphNodes
| where (set_has_element(Categories, "ip_address") or set_has_element(Categories, "virtual_machine"));
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with IPsAndVMs on NodeId
| graph-match (IP)-[anyEdge*1..3]->(VM)
    where set_has_element(IP.Categories, "ip_address") and set_has_element(VM.Categories, "virtual_machine")
    project 
        SourceIP = IP.NodeName,
        IpIds = IP.EntityIds,
        IpProperties = IP.NodeProperties.rawData,
        TargetVM = VM.NodeName,
        VmIds = VM.EntityIds,
        VmProperties = VM.NodeProperties.rawData,
        PathLength = array_length(anyEdge)
| order by PathLength asc, SourceIP asc
```

---

### SECTION 4: Cloud Multi-Environment Analysis

#### Query 9: Cloud Resources Across Azure, AWS, and GCP

**Description**: Count and categorize cloud resources from different providers  
**Use Case**: Multi-cloud visibility and asset inventory

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time multi-cloud resource inventory. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| where NodeLabel contains "microsoft.compute" or NodeLabel contains "aws." or NodeLabel contains "gcp."
| extend CloudProvider = case(
    NodeLabel contains "microsoft.compute", "Azure",
    NodeLabel contains "aws.", "AWS",
    NodeLabel contains "gcp.", "GCP",
    "Other"
)
| summarize 
    ResourceCount = count(),
    Resources = make_set(NodeName)
    by CloudProvider, NodeLabel
| order by CloudProvider asc, ResourceCount desc
```

#### Query 10: Critical Cloud Assets Summary

**Description**: Inventory of critical assets across all cloud providers  
**Use Case**: Executive dashboard of critical cloud infrastructure

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time critical asset summary. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| where (NodeLabel contains "microsoft.compute" or NodeLabel contains "aws." or NodeLabel contains "gcp.")
    and isnotnull(NodeProperties.rawData.criticalityLevel)
    and NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| extend CloudProvider = case(
    NodeLabel contains "microsoft.compute", "Azure",
    NodeLabel contains "aws.", "AWS",
    NodeLabel contains "gcp.", "GCP",
    "Other"
)
| extend CriticalityLevel = tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| summarize 
    CriticalAssetCount = count(),
    AssetNames = make_set(NodeName)
    by CloudProvider, CriticalityLevel
| order by CloudProvider asc, CriticalityLevel asc
```

---

### SECTION 5: Vulnerability Analysis on Critical Assets

#### Query 11: CVEs Affecting Critical Devices

**Description**: Find all CVE vulnerabilities affecting critical devices  
**Use Case**: Prioritize vulnerability remediation for critical assets

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time CVE-to-device mapping. Not event-driven; CD requires temporal detection."
-->
```kql
let CriticalDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| project NodeId, DeviceName = NodeName, CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel;
ExposureGraphEdges
| where EdgeLabel == "affecting"
| where SourceNodeLabel == "Cve"
| join kind=inner CriticalDeviceIds on $left.TargetNodeId == $right.NodeId
| project 
    DeviceName,
    CriticalityLevel,
    CVE = SourceNodeName,
    EdgeProperties
| order by CriticalityLevel asc, CVE desc
```

#### Query 12: Critical Devices with Multiple Vulnerabilities

**Description**: Rank critical devices by number of CVE vulnerabilities  
**Use Case**: Identify most vulnerable critical assets for remediation priority

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time vulnerability count ranking. Not event-driven; CD requires temporal detection."
-->
```kql
let CriticalDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| project NodeId, DeviceName = NodeName, CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel;
ExposureGraphEdges
| where EdgeLabel == "affecting"
| where SourceNodeLabel == "Cve"
| join kind=inner CriticalDeviceIds on $left.TargetNodeId == $right.NodeId
| summarize 
    CVECount = count(),
    CVEs = make_set(SourceNodeName)
    by DeviceName, CriticalityLevel
| order by CVECount desc, CriticalityLevel asc
```

---

### SECTION 6: Exploration & Discovery Queries

#### Query 13: List All Unique Node Labels (Asset Types)

**Description**: Discover all types of nodes in your exposure graph  
**Use Case**: Understand what asset types are tracked in your environment

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — schema exploration query. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| summarize NodeCount = count() by NodeLabel
| order by NodeCount desc
```

#### Query 14: List All Unique Edge Labels (Relationship Types)

**Description**: Discover all relationship types in your exposure graph  
**Use Case**: Understand what connections and permissions exist

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — schema exploration query. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphEdges
| summarize EdgeCount = count() by EdgeLabel
| order by EdgeCount desc
```

#### Query 15: Incoming Connections to Virtual Machines

**Description**: Find all types of assets that can connect TO virtual machines  
**Use Case**: Understand attack surface and access paths to VMs

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time graph traversal for VM access mapping. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (SourceNode)-[edges]->(TargetNode)
    where TargetNode.NodeLabel == "microsoft.compute/virtualmachines"
    project IncomingNodeLabels = SourceNode.NodeLabel 
| summarize ConnectionCount = count() by IncomingNodeLabels
| order by ConnectionCount desc
```

#### Query 16: Outgoing Connections from Virtual Machines

**Description**: Find all types of assets that virtual machines can connect TO  
**Use Case**: Understand what VMs can access (lateral movement potential)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time graph traversal for VM outbound access. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (SourceNode)-[edges]->(TargetNode)
    where SourceNode.NodeLabel == "microsoft.compute/virtualmachines"
    project OutgoingNodeLabels = TargetNode.NodeLabel 
| summarize ConnectionCount = count() by OutgoingNodeLabels
| order by ConnectionCount desc
```

---

### SECTION 7: External Data Source Integrations

#### Query 17: Assets from ServiceNow CMDB

**Description**: Find all assets imported from ServiceNow CMDB connector  
**Use Case**: Validate ServiceNow integration and asset correlation

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — integration validation query. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| where NodeProperties contains ("serviceNowCmdbAssetInfo")
| extend SnowInfo = NodeProperties.rawData.serviceNowCmdbAssetInfo
| project 
    NodeName,
    NodeLabel,
    Categories,
    ServiceNowInfo = SnowInfo
| take 100
```

#### Query 18: CVEs from Tenable Vulnerability Scanner

**Description**: Find all vulnerabilities reported by Tenable on ingested assets  
**Use Case**: Validate Tenable integration and vulnerability tracking

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — integration validation query. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphEdges
| where EdgeLabel == "affecting" 
| where SourceNodeLabel == "Cve" 
| where isnotempty(EdgeProperties.rawData.tenableReportInfo)
| project 
    AssetName = TargetNodeName,
    CVE = SourceNodeName,
    TenableInfo = EdgeProperties.rawData.tenableReportInfo
| take 100
```

#### Query 19: CVEs from Rapid7 Vulnerability Scanner

**Description**: Find all vulnerabilities reported by Rapid7 on ingested assets  
**Use Case**: Validate Rapid7 integration and vulnerability tracking

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — integration validation query. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphEdges
| where EdgeLabel == "affecting" 
| where SourceNodeLabel == "Cve" 
| where isnotempty(EdgeProperties.rawData.rapid7ReportInfo)
| project 
    AssetName = TargetNodeName,
    CVE = SourceNodeName,
    Rapid7Info = EdgeProperties.rawData.rapid7ReportInfo
| take 100
```

---

### SECTION 8: Sample Property Inspection

#### Query 20: Sample Node Properties for Virtual Machines

**Description**: View sample NodeProperties structure for VMs to understand available data  
**Use Case**: Schema exploration and understanding available properties

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — schema inspection query. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| where NodeLabel == "microsoft.compute/virtualmachines"
| project-keep NodeName, NodeProperties
| take 1
```

---

### SECTION 9: Vulnerable Device Attack Paths — Cookie Chain Analysis

> **Core concept**: When a device has high-severity vulnerabilities, an attacker who compromises it can extract cached `entra-userCookie` tokens to impersonate logged-in users and pivot to ANY Azure resource those users have permissions on — without needing the user's password or MFA. These queries map that blast radius.

#### Query 21: Devices with High-Risk Vulnerability Insights (Entry Points)

**Description**: Find all devices flagged with high-risk vulnerability insights — the entry points for identity-based attack paths  
**Use Case**: Identify the device population that feeds into attack path analysis  
**Key Property**: `NodeProperties.rawData.highRiskVulnerabilityInsights`

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time device vulnerability posture. Not event-driven; CD requires temporal detection."
-->
```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| extend 
    HasHighOrCritical = tostring(NodeProperties.rawData.highRiskVulnerabilityInsights.hasHighOrCritical),
    MaxCvss = toreal(NodeProperties.rawData.highRiskVulnerabilityInsights.maxCvssScore),
    VulnToRCE = tostring(NodeProperties.rawData.highRiskVulnerabilityInsights.vulnerableToRemoteCodeExecution),
    VulnToPrivEsc = tostring(NodeProperties.rawData.highRiskVulnerabilityInsights.vulnerableToPrivilegeEscalation),
    Criticality = tostring(NodeProperties.rawData.criticalityLevel)
| project DeviceName = NodeName, MaxCvss, HasHighOrCritical, VulnToRCE, VulnToPrivEsc, Criticality, NodeLabel
| order by MaxCvss desc
```

> **⚠️ PITFALL**: Do NOT use `NodeProperties.rawData.vulnerableToRCE` or `NodeProperties.rawData.hasVulnerabilities` — these legacy properties exist only on a subset of devices. The `highRiskVulnerabilityInsights` object is the reliable, comprehensive property. Always check `hasHighOrCritical` within it.

#### Query 22: Direct Attack Paths — VulnDevice → Cookie → User → Target (by Target Type)

**Description**: Map all direct 3-hop identity-based attack paths from vulnerable devices through cached cookies to Azure resources, broken down by target resource type  
**Use Case**: Understand which Azure resource types are reachable from compromised devices  
**Pattern**: `Device -[contains]→ entra-userCookie -[can authenticate as]→ User -[has permissions to]→ Target`

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time cookie chain attack path analysis. Not event-driven; CD requires temporal detection."
-->
```kql
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId;
ExposureGraphEdges
| where EdgeLabel in~ ("contains", "can authenticate as", "has permissions to")
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Device)-[e1]->(Cookie)-[e2]->(User)-[e3]->(Target)
    where 
        set_has_element(Device.Categories, "device") and
        Cookie.NodeLabel =~ "entra-userCookie" and
        User.NodeLabel =~ "user" and
        not(Target.NodeLabel in~ ("user", "group", "entra-userCookie", "serviceprincipal"))
    project DeviceId = Device.NodeId, DeviceName = Device.NodeName, 
        UserName = User.NodeName, TargetName = Target.NodeName, 
        TargetLabel = Target.NodeLabel
| join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
| summarize 
    TotalPaths = count(),
    UniqueDevices = dcount(DeviceName),
    UniqueUsers = dcount(UserName),
    UniqueTargets = dcount(TargetName)
    by TargetLabel
| order by UniqueTargets desc
```

**Expected target types**: `microsoft.keyvault/vaults`, `microsoft.storage/storageaccounts`, `microsoft.cognitiveservices/accounts`, `microsoft.compute/virtualmachines`, `microsoft.logic/workflows`, `microsoft.containerservice/managedclusters`, `microsoft.kubernetes/connectedclusters`, etc.

#### Query 23: Group-Mediated Attack Paths — VulnDevice → Cookie → User → Group → Target

**Description**: Map 4-hop attack paths where users access resources via group membership (adds ~15-25% more paths vs direct-only)  
**Use Case**: Capture attack paths that go through Entra ID group RBAC assignments  
**Pattern**: `Device -[contains]→ Cookie -[can authenticate as]→ User -[member of]→ Group -[has role on]→ Target`

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time group-mediated attack path analysis. Not event-driven; CD requires temporal detection."
-->
```kql
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Device)-[e1]->(Cookie)-[e2]->(User)-[e3]->(Group)-[e4]->(Target)
    where 
        set_has_element(Device.Categories, "device") and
        Cookie.NodeLabel =~ "entra-userCookie" and
        User.NodeLabel =~ "user" and
        Group.NodeLabel =~ "group" and
        not(Target.NodeLabel in~ ("user", "group", "entra-userCookie", "serviceprincipal"))
    project DeviceId = Device.NodeId, DeviceName = Device.NodeName, 
        UserName = User.NodeName, GroupName = Group.NodeName,
        TargetName = Target.NodeName, TargetLabel = Target.NodeLabel,
        e3Label = e3.EdgeLabel, e4Label = e4.EdgeLabel
| join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
| summarize 
    TotalPaths = count(),
    UniqueDeviceTargetPairs = dcount(strcat(DeviceName, "|", TargetName)),
    UniqueGroups = dcount(GroupName)
    by TargetLabel, e3Label, e4Label
| order by UniqueDeviceTargetPairs desc
```

#### Query 24: Discover ALL Intermediary Patterns Between Devices and a Target Type

**Description**: Automatically discover every 3-hop path pattern (node labels and edge labels) between vulnerable devices and a specific target resource type  
**Use Case**: Find attack chain patterns you didn't know existed — critical for comprehensive coverage  
**Customization**: Change the `TargetType` variable to discover patterns for any resource type

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data with parameter substitution (let TargetType). Point-in-time pattern discovery, not event-driven."
-->
```kql
// Change the target NodeLabel below to discover patterns for any resource type
let TargetType = "microsoft.keyvault/vaults";
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Device)-[e1]->(N1)-[e2]->(N2)-[e3]->(Target)
    where set_has_element(Device.Categories, "device") and
        Target.NodeLabel =~ TargetType
    project DeviceId = Device.NodeId, DeviceName = Device.NodeName, 
        N1Label = N1.NodeLabel, N2Label = N2.NodeLabel,
        e1Label = e1.EdgeLabel, e2Label = e2.EdgeLabel, e3Label = e3.EdgeLabel,
        TargetName = Target.NodeName
| join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
| summarize PathCount = count(), 
    UniqueDeviceTargetPairs = dcount(strcat(DeviceName, "|", TargetName))
    by N1Label, N2Label, e1Label, e2Label, e3Label
| order by UniqueDeviceTargetPairs desc
```

**Known patterns discovered** (for Key Vaults):

| N1 Label | N2 Label | Edge Chain | Typical Volume |
|----------|----------|------------|----------------|
| `entra-userCookie` | `user` | `contains` → `can authenticate as` → `has permissions to` | Highest |
| `user` | `group` | `has credentials of` → `member of` → `has role on` | Medium |
| `user` | `group` | `frequently logged in by` → `member of` → `has role on` | Medium |
| `entra-userCookie` | `user` | `contains` → `can authenticate as` → `has role on` | Low |

#### Query 25: Comprehensive Deduplicated Path Count — Union All Patterns

**Description**: Count unique (device, target) pairs across ALL attack path patterns (direct + group-mediated) for accurate deduplication  
**Use Case**: Get accurate path counts that approximate what the Defender portal shows  
**Customization**: Change `TargetNodeLabelFilter` for different resource types

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data with parameter substitution (let TargetNodeLabelFilter). Point-in-time path deduplication, not event-driven."
-->
```kql
// Comprehensive: Union direct + group-mediated paths for total unique pairs
// Change TargetNodeLabelFilter below for different resource types
let TargetNodeLabelFilter = "microsoft.keyvault/vaults";
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId;
// Pattern A: 3-hop direct (Device→N1→N2→Target)
let ThreeHop = ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Device)-[e1]->(N1)-[e2]->(N2)-[e3]->(Target)
    where set_has_element(Device.Categories, "device") and
        Target.NodeLabel =~ TargetNodeLabelFilter
    project DeviceId = Device.NodeId, DeviceName = Device.NodeName, TargetName = Target.NodeName
| join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
| distinct DeviceName, TargetName;
// Pattern B: 4-hop via group (Device→N1→N2→N3→Target)
let FourHop = ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Device)-[e1]->(N1)-[e2]->(N2)-[e3]->(N3)-[e4]->(Target)
    where set_has_element(Device.Categories, "device") and
        Target.NodeLabel =~ TargetNodeLabelFilter
    project DeviceId = Device.NodeId, DeviceName = Device.NodeName, TargetName = Target.NodeName
| join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
| distinct DeviceName, TargetName;
union ThreeHop, FourHop
| distinct DeviceName, TargetName
| summarize TotalUniquePathPairs = count()
```

> **Portal reconciliation note**: The Defender portal counts attack path "instances" using a proprietary deduplication engine. Your KQL counts may differ by 5-10% because the portal may use additional intermediary patterns or different deduplication logic. Getting within 90-95% match is expected.

---

### SECTION 10: Attack Path Permission Analysis

> These queries show not just that a path EXISTS, but what PERMISSIONS the attacker would gain. An attack path to Key Vault with `Reader` is very different from one with `Key Vault Secrets Officer`.

#### Query 26: Permission Role Breakdown on Attack Paths

**Description**: Break down RBAC roles on attack path edges to show what permissions users actually have on target resources  
**Use Case**: Distinguish low-risk (Reader) from critical (Owner/Secrets Officer) attack paths  
**Customization**: Change the `TargetNodeLabelFilter` for different resource types

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data with parameter substitution (let TargetNodeLabelFilter). Point-in-time RBAC analysis, not event-driven."
-->
```kql
// Change target filter below for different resource types
let TargetNodeLabelFilter = "microsoft.keyvault/vaults";
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId;
ExposureGraphEdges
| where EdgeLabel == "has permissions to"
| where TargetNodeId in (
    (ExposureGraphNodes | where NodeLabel =~ TargetNodeLabelFilter | project NodeId)
)
| extend roles = parse_json(tostring(EdgeProperties.rawData)).permissions.roles
| mv-expand role = roles
| extend RoleName = tostring(role.name)
| join kind=inner (
    ExposureGraphEdges
    | make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
    | graph-match (Device)-[e1]->(Cookie)-[e2]->(User)
        where set_has_element(Device.Categories, "device") and
            Cookie.NodeLabel =~ "entra-userCookie" and User.NodeLabel =~ "user"
        project DeviceId = Device.NodeId, UserId = User.NodeId
    | join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
    | distinct UserId
) on $left.SourceNodeId == $right.UserId
| summarize PathCount = count(), UniqueUsers = dcount(SourceNodeId), UniqueTargets = dcount(TargetNodeId) 
    by RoleName
| order by PathCount desc
```

**Risk interpretation for Key Vault roles:**

| Role | Risk | Can Access Secrets? |
|------|------|-------------------|
| 🔴 Key Vault Secrets Officer | Critical | Read, write, delete ALL secrets |
| 🔴 Key Vault Secrets User | Critical | Read ALL secrets |
| 🔴 Owner | Critical | Full control including IAM |
| 🟠 Contributor | High | Write access, can modify config |
| 🟡 Reader | Low | Metadata only, cannot read secrets |

#### Query 27: High-Privilege Users Reachable via Attack Paths

**Description**: Identify users with Owner, Contributor, or Secrets access to resources who are reachable from vulnerable devices  
**Use Case**: Highest-priority remediation — these attack paths grant dangerous write/admin access  
**Customization**: Change the `TargetNodeLabelFilter` and role filter list for different resource types

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data with parameter substitution (let TargetNodeLabelFilter). Point-in-time privilege analysis, not event-driven."
-->
```kql
// Change target filter below for different resource types
let TargetNodeLabelFilter = "microsoft.keyvault/vaults";
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId;
ExposureGraphEdges
| where EdgeLabel == "has permissions to"
| where TargetNodeId in (
    (ExposureGraphNodes | where NodeLabel =~ TargetNodeLabelFilter | project NodeId)
)
| extend roles = parse_json(tostring(EdgeProperties.rawData)).permissions.roles
| mv-expand role = roles
| extend RoleName = tostring(role.name)
| where RoleName in ("Owner", "Contributor", "Key Vault Secrets User", "Key Vault Secrets Officer",
    "Storage Blob Data Contributor", "Storage Blob Data Owner")
| join kind=inner (
    ExposureGraphEdges
    | make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
    | graph-match (Device)-[e1]->(Cookie)-[e2]->(User)
        where set_has_element(Device.Categories, "device") and
            Cookie.NodeLabel =~ "entra-userCookie" and User.NodeLabel =~ "user"
        project DeviceId = Device.NodeId, DeviceName = Device.NodeName, 
            UserId = User.NodeId, UserName = User.NodeName
    | join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
    | distinct UserId, UserName, DeviceName
) on $left.SourceNodeId == $right.UserId
| join kind=inner (
    ExposureGraphNodes | where NodeLabel =~ TargetNodeLabelFilter 
    | project TargetNodeId = NodeId, TargetName = NodeName
) on TargetNodeId
| summarize 
    Roles = make_set(RoleName), 
    TargetCount = dcount(TargetName), 
    Targets = make_set(TargetName), 
    Devices = make_set(DeviceName) 
    by UserName
| order by TargetCount desc
```

#### Query 28: Critical Users (by Entra Criticality) Reachable from Vulnerable Devices

**Description**: Find users with high Entra ID criticality levels (Global Admins, Security Admins, etc.) who are reachable from devices with high-severity vulnerabilities  
**Use Case**: THE most dangerous attack paths — compromising these users grants broad tenant-level access

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time critical user reachability analysis. Not event-driven; CD requires temporal detection."
-->
```kql
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Device)-[e1]->(Cookie)-[e2]->(User)
    where set_has_element(Device.Categories, "device") and
        Cookie.NodeLabel =~ "entra-userCookie" and User.NodeLabel =~ "user"
    project DeviceId = Device.NodeId, DeviceName = Device.NodeName, 
        UserName = User.NodeName, 
        UserCritRaw = tostring(User.NodeProperties.rawData.criticalityLevel),
        MaxCvss = toreal(Device.NodeProperties.rawData.highRiskVulnerabilityInsights.maxCvssScore)
| join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
| where isnotempty(UserCritRaw) and UserCritRaw != "{}"
| extend UserCritLevel = toint(parse_json(UserCritRaw).criticalityLevel),
    CritRules = tostring(parse_json(UserCritRaw).ruleNames)
| distinct DeviceName, UserName, UserCritLevel, CritRules, MaxCvss
| order by UserCritLevel asc, UserName asc
```

**Criticality levels (lower = more critical):**

| Level | Meaning | Typical Roles |
|-------|---------|---------------|
| 🔴 0 | Highest criticality | Global Administrator, highly critical assets |
| 🟠 1 | High criticality | Security Admin, Compliance Admin, SharePoint Admin |
| 🟡 2-3 | Medium criticality | Various admin roles |

> **Remediation priority**: A criticality-0 user (Global Admin) reachable from a CVSS 9.8 device is an **immediate, critical risk**. The attacker gains full tenant control by compromising a single vulnerable endpoint.

> **⚠️ PITFALL**: User `criticalityLevel` is a nested JSON string, NOT a plain integer. You must use `parse_json(tostring(...)).criticalityLevel` to extract the numeric level. Direct `toint()` on the raw property will return null.

---

### SECTION 11: Attack Path Entry Points & Choke Points

#### Query 29: Top Entry-Point Devices by Blast Radius

**Description**: Rank vulnerable devices by how many unique Azure resources an attacker could reach by compromising them  
**Use Case**: Prioritize vulnerability remediation by actual impact — a device reaching 465 targets is more urgent than one reaching 10

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time blast radius ranking. Not event-driven; CD requires temporal detection."
-->
```kql
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId, MaxCvss = toreal(NodeProperties.rawData.highRiskVulnerabilityInsights.maxCvssScore);
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Device)-[e1]->(Cookie)-[e2]->(User)-[e3]->(Target)
    where set_has_element(Device.Categories, "device") and
        Cookie.NodeLabel =~ "entra-userCookie" and User.NodeLabel =~ "user" and
        not(Target.NodeLabel in~ ("user", "group", "entra-userCookie", "serviceprincipal"))
    project DeviceId = Device.NodeId, DeviceName = Device.NodeName, 
        UserName = User.NodeName,
        TargetName = Target.NodeName, TargetLabel = Target.NodeLabel
| join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
| summarize 
    UniqueTargets = dcount(TargetName),
    UniqueUsers = dcount(UserName),
    TargetTypes = make_set(TargetLabel),
    KVs = dcountif(TargetName, TargetLabel =~ "microsoft.keyvault/vaults"),
    OpenAI = dcountif(TargetName, TargetLabel =~ "microsoft.cognitiveservices/accounts"),
    Storage = dcountif(TargetName, TargetLabel =~ "microsoft.storage/storageaccounts")
    by DeviceName, MaxCvss
| order by UniqueTargets desc
| take 20
```

#### Query 30: Choke Point Detection — Users in Most Attack Paths

**Description**: Find users who appear as identity pivots in the most attack paths — these are choke points where remediation has maximum impact  
**Use Case**: Locking down credentials for a top choke-point user blocks MANY attack paths at once

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph snapshot data — point-in-time choke point identification. Not event-driven; CD requires temporal detection."
-->
```kql
let VulnDeviceIds = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where isnotnull(NodeProperties.rawData.highRiskVulnerabilityInsights)
| project NodeId;
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (Device)-[e1]->(Cookie)-[e2]->(User)-[e3]->(Target)
    where set_has_element(Device.Categories, "device") and
        Cookie.NodeLabel =~ "entra-userCookie" and User.NodeLabel =~ "user" and
        not(Target.NodeLabel in~ ("user", "group", "entra-userCookie", "serviceprincipal"))
    project DeviceId = Device.NodeId, DeviceName = Device.NodeName, 
        UserName = User.NodeName, TargetName = Target.NodeName,
        UserCritRaw = tostring(User.NodeProperties.rawData.criticalityLevel)
| join kind=inner VulnDeviceIds on $left.DeviceId == $right.NodeId
| summarize 
    UniqueTargets = dcount(TargetName),
    UniqueDevices = dcount(DeviceName),
    TotalPaths = count(),
    UserCritRaw = take_any(UserCritRaw)
    by UserName
| extend UserCritLevel = toint(parse_json(UserCritRaw).criticalityLevel),
    CritRules = tostring(parse_json(UserCritRaw).ruleNames)
| project UserName, UserCritLevel, CritRules, UniqueTargets, UniqueDevices, TotalPaths
| order by UniqueTargets desc
| take 15
```

**Remediation actions for choke points:**
1. 🔴 Enforce phishing-resistant MFA (FIDO2/passkeys) for all choke-point users
2. 🔴 Enable token protection / CAE continuous access evaluation
3. 🟠 Reduce standing permissions — convert to PIM-eligible with approval workflows
4. 🟠 Apply Conditional Access: require compliant/managed devices for privileged access
5. 🟡 Monitor choke-point users with custom Sentinel analytics rules for anomalous sign-ins

---

### SECTION 12: Azure Resource Graph — Pre-Computed Attack Paths

> **Two complementary data sources**: ExposureGraph (Sections 9-11 above) covers identity-based attack paths from devices through users to cloud resources. Azure Resource Graph covers **pre-computed cloud-native attack paths** from internet-exposed entry points to critical resources. Together they provide complete coverage.

> **⚠️ Execution note**: These are NOT KQL queries for Advanced Hunting. They run via Azure CLI `az graph query` against the Azure Resource Graph.

#### Query 31: All Pre-Computed Attack Paths from Azure Resource Graph

**Description**: Retrieve all attack paths pre-computed by Microsoft Defender for Cloud  
**Use Case**: Get named attack scenarios with descriptions, attack stories, and remediation guidance  
**Execution**: Azure CLI (not Advanced Hunting)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Azure Resource Graph CLI query (az graph query) — not KQL for Defender XDR Advanced Hunting. Runs against ARM, not applicable for CD."
-->
```bash
az graph query -q "
  securityresources
  | where type == 'microsoft.security/attackpaths'
  | extend DisplayName = tostring(properties.displayName),
      Description = tostring(properties.description),
      AttackStory = tostring(properties.attackStory),
      EntryPointType = tostring(properties.graphComponent.entryPointEntityType),
      TargetType = tostring(properties.graphComponent.targetEntityType)
  | project DisplayName, Description, AttackStory, EntryPointType, TargetType, properties
  | order by DisplayName asc
" --first 1000
```

**Typical scenarios returned:**
- `Internet exposed VM with high severity vulnerabilities has permissions to a Key Vault`
- `Internet exposed API with unauthenticated access has permissions to a storage account`
- `Internet exposed VM can authenticate to a VM which has access to a storage account`

> **Coverage**: ARG attack paths cover **cloud-only, internet-exposed** scenarios. They do NOT include device → identity → resource paths (those are in ExposureGraph). The "Device with high severity vulnerabilities..." paths visible in the Defender portal come from ExposureGraph, not ARG.

#### Query 32: Attack Path Summary by Scenario with Instance Counts

**Description**: Group pre-computed attack paths by scenario name with counts per scenario  
**Use Case**: Quick overview of which attack path types exist and their prevalence  
**Execution**: Azure CLI (not Advanced Hunting)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Azure Resource Graph CLI query (az graph query) — not KQL for Defender XDR Advanced Hunting. Runs against ARM, not applicable for CD."
-->
```bash
az graph query -q "
  securityresources
  | where type == 'microsoft.security/attackpaths'
  | extend DisplayName = tostring(properties.displayName)
  | summarize Count = count() by DisplayName
  | order by Count desc
" --first 100
```

**Full remediation detail** for a specific path (includes `graphComponent` with entities, connections, and insights):

```bash
az graph query -q "
  securityresources
  | where type == 'microsoft.security/attackpaths'
  | where properties.displayName has 'Key Vault'
  | take 1
" --first 1 -o json
```

The `graphComponent` field contains the full attack chain: source entity → intermediate hops → target, with remediation recommendations for each step.

---

### Attack Path Data Source Reference

| Attribute | ExposureGraph (KQL) | Azure Resource Graph (CLI) |
|-----------|-------------------|---------------------------|
| **Tool** | `RunAdvancedHuntingQuery` | `az graph query` |
| **Tables** | ExposureGraphNodes, ExposureGraphEdges | `securityresources` (`microsoft.security/attackpaths`) |
| **Path types** | Device → Identity → Cloud Resource | Internet → Cloud → Cloud Resource |
| **Entry points** | Vulnerable managed devices, domain controllers | Internet-exposed VMs, APIs, web apps |
| **Pivot** | `entra-userCookie` (cached Entra ID token) | Direct cloud resource chains |
| **Named scenarios** | ❌ Raw graph — you define patterns | ✅ Pre-named: "Internet exposed VM with..." |
| **Remediation** | ❌ Must determine from edge/role analysis | ✅ Built-in remediation guidance |
| **Custom patterns** | ✅ Unlimited `graph-match` patterns | ❌ Fixed pre-computed scenarios |
| **Portal match** | "Device with high severity vulnerabilities..." | "Internet exposed..." |
| **Deduplication** | Manual: `distinct DeviceName, TargetName` | Pre-computed counts |

---

**Last Updated**: 2026-02-12