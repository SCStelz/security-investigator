# ExposureGraph Critical Assets & Attack Paths - Complete Query Library

## 📋 Overview

This guide provides comprehensive KQL queries for finding critical assets and analyzing attack paths using the **ExposureGraphNodes** and **ExposureGraphEdges** tables in Microsoft Defender XDR Advanced Hunting.

**20 production-ready queries** organized into 8 sections for security operations.

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
Common edge types:
- `Can Authenticate As` - Authentication relationships
- `CanRemoteInteractiveLogonTo` - Remote login permissions
- `affecting` - CVE vulnerabilities affecting assets

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
1. **Query 6** - Multi-hop attack paths
2. **Query 7** - Hybrid cloud/on-prem paths
3. **Query 8** - External IP exposure paths

### Identity Risk Assessment
1. **Query 5** - Users with access to multiple critical devices
2. **Query 6** - Attack paths involving users

### Cloud Security Posture
1. **Query 9** - Multi-cloud inventory
2. **Query 10** - Critical cloud assets
3. **Query 3** - Cloud VMs with RCE vulns

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

---

**Last Updated**: 2026-02-02  
**Query File**: ExposureGraph_CriticalAssets_AttackPaths.kql  
**Author**: Security Investigation System
## 📚 Complete Query Library

### SECTION 1: Critical Devices & Assets

#### Query 1: Find All Critical Devices (Criticality Level < 4)

**Description**: Lists all devices with high criticality (levels 1-3, where lower = more critical)  
**Use Case**: Identify most important assets requiring priority protection

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

```kql
ExposureGraphNodes
| summarize NodeCount = count() by NodeLabel
| order by NodeCount desc
```

#### Query 14: List All Unique Edge Labels (Relationship Types)

**Description**: Discover all relationship types in your exposure graph  
**Use Case**: Understand what connections and permissions exist

```kql
ExposureGraphEdges
| summarize EdgeCount = count() by EdgeLabel
| order by EdgeCount desc
```

#### Query 15: Incoming Connections to Virtual Machines

**Description**: Find all types of assets that can connect TO virtual machines  
**Use Case**: Understand attack surface and access paths to VMs

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

```kql
ExposureGraphNodes
| where NodeLabel == "microsoft.compute/virtualmachines"
| project-keep NodeName, NodeProperties
| take 1
```

---

**Last Updated**: 2026-02-02