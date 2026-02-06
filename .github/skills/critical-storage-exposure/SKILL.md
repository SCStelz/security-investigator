---
name: critical-storage-exposure
description: Use this skill when asked to investigate critical storage exposure, assess storage security posture, or analyze attack paths to sensitive data. Triggers on keywords like "critical storage exposure", "storage security", "blob security", "S3 exposure", "storage attack paths", or when investigating data exfiltration risks across Azure and AWS environments. This skill provides comprehensive exposure perimeter analysis for Azure Storage Accounts, Blob Containers, and AWS S3 Buckets.
---

# Critical Storage Exposure Investigation Agent - Instructions

## Purpose

This agent performs comprehensive security analysis on critical storage resources to identify exposure risks, attack paths, and potential data exfiltration threats across Azure and AWS environments. The investigation focuses on **who can access critical storage** (exposure perimeter) rather than what storage can access (blast radius), as storage resources are data sinks, not attack launchers.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Investigation Scope](#investigation-scope)** - Storage resource types
3. **[Execution Workflow](#execution-workflow)** - Complete process with phases
4. **[KQL Query Library](#kql-query-library)** - Validated query patterns
5. **[Report Template](#report-template)** - Executive markdown structure
6. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

### 🛑 MANDATORY: Read Before Executing

**YOU MUST READ AND FULLY UNDERSTAND THIS ENTIRE SKILL FILE BEFORE STARTING THE INVESTIGATION.**

- Do NOT skim the instructions
- Do NOT skip phases because they seem optional
- Do NOT substitute different tools for the ones specified
- Each phase has specific tools and methods documented - USE THEM EXACTLY

---

### 🚨 MANDATORY: Step Tracking Pattern

**YOU MUST TRACK AND REPORT PROGRESS AFTER EVERY PHASE:**

```
[Phase X] ✓ Description (XX seconds)
```

**Required Reporting Points:**
1. After Phase 1 (Advanced Hunting activation)
2. After Phase 2 (Storage resource discovery)
3. After Phase 3 (Exposure perimeter analysis)
4. After Phase 4 (Vulnerability assessment) - **⛔ DO NOT SKIP**
5. After Phase 5 (Attack path reconstruction)
6. After Phase 6 (Cross-cloud segmentation)
7. After Phase 7 (Report generation)
8. Final: Total elapsed time

**Use `manage_todo_list` tool to track phases if available.**

---

### Core Rules

**Before starting ANY critical storage investigation:**

1. **ALWAYS use Defender XDR Advanced Hunting** (NOT Sentinel Data Lake - ExposureGraph tables only exist in Advanced Hunting)
2. **ALWAYS activate Advanced Hunting tools first** using `activate_advanced_hunting_tools()`
3. **ALWAYS query all storage types in parallel** (Azure Storage Accounts, Blob Containers, S3 Buckets)
4. **ALWAYS run exposure perimeter checks in parallel batches** (max 6-8 simultaneous calls)
5. **ALWAYS complete Phase 4 (Vulnerability Assessment)** when `HasVulnerabilities=true` is detected
6. **ALWAYS save final report to reports/ folder** using `create_file` tool
7. **DO NOT use blast radius** for storage resources (storage cannot pivot to other systems - they are data sinks)
8. **DO NOT skip phases** - each phase is mandatory unless explicitly marked optional

**Key Concept:**
- **Exposure Perimeter** = Who/what can access storage (USEFUL ✅)
- **Blast Radius** = What storage can access (USELESS for data stores ❌)

---

## Investigation Scope

### Storage Resource Types Analyzed

| Resource Type | NodeLabel | Description | Criticality Filter |
|---------------|-----------|-------------|-------------------|
| **Azure Storage Accounts** | `microsoft.storage/storageaccounts` | Parent storage resources with RBAC | `criticalityLevel == 0` |
| **Azure Blob Containers** | `BlobContainer` | Container-level storage with granular permissions | `criticalityLevel == 0` |
| **AWS S3 Buckets** | `s3.bucket` | AWS object storage with IAM policies | `criticalityLevel == 0` |

**Note:** Criticality Level 0 = Most critical assets (counterintuitive - lower number = higher criticality)

### What This Investigation Reveals

1. **Exposure Perimeter**: Complete attack path from entry points to storage
2. **Attack Path Analysis**: Device → Credential/Token → User → Storage
3. **Single Point of Failure**: Users/devices with access to multiple critical storage resources
4. **Permission Analysis**: RBAC roles, IAM policies, Owner/Contributor assignments
5. **Cross-Cloud Segmentation**: Azure vs AWS isolation validation
6. **Container vs Account Protection**: Granular permission effectiveness

---

## Execution Workflow

### Phase 1: Activate Advanced Hunting Tools

**MANDATORY FIRST STEP:**

```
activate_advanced_hunting_tools()
```

**Why:** ExposureGraph tables (ExposureGraphNodes, ExposureGraphEdges) only exist in Defender XDR Advanced Hunting, NOT in Sentinel Data Lake.

---

### Phase 2: Query All Critical Storage Resources (PARALLEL)

**Execute ALL THREE queries in parallel using `mcp_sentinel-tria_RunAdvancedHuntingQuery`:**

#### Query 2A: Azure Storage Accounts

```kql
ExposureGraphNodes
| where NodeLabel == "microsoft.storage/storageaccounts"
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel == 0
| project 
    NodeName, 
    NodeId, 
    NodeLabel,
    CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel,
    EntityIds
| order by NodeName asc
```

#### Query 2B: Azure Blob Containers

```kql
ExposureGraphNodes
| where NodeLabel == "BlobContainer"
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel == 0
| project 
    NodeName, 
    NodeId, 
    NodeLabel,
    CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel,
    EntityIds
| order by NodeName asc
```

#### Query 2C: AWS S3 Buckets

```kql
ExposureGraphNodes
| where NodeLabel == "s3.bucket"
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel == 0
| project 
    NodeName, 
    NodeId, 
    NodeLabel,
    CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel,
    EntityIds
| order by NodeName asc
```

**After Phase 2 completes:**
- Consolidate results into a single list: `[{"name": "...", "type": "storage_account"}, ...]`
- Count total assets by type

---

### Phase 3: Exposure Perimeter Analysis (PARALLEL BATCHES)

**For each storage resource discovered in Phase 2, run `mcp_sentinel-grap_graph_exposure_perimeter`:**

**Batch Execution Pattern:**
- **Batch Size**: 6-8 resources per parallel call (reduced from 8-10 due to API rate limits)
- **Why Batching**: VS Code token limits, avoid overwhelming MCP server, API throttling limits
- **Empty Results**: Storage with no exposure perimeter (GOOD NEWS ✅)
- **Results with Rows**: Storage exposed via attack path (REQUIRES ANALYSIS ❌)
- **⚠️ RATE LIMIT HANDLING**: If you hit "Too many requests" errors, STOP querying and document which resources were checked successfully

```python
# Example structure - agent should use appropriate tool calls
for batch in batched(storage_resources, batch_size=6):
    parallel_calls = [
        mcp_sentinel-grap_graph_exposure_perimeter(targetName=resource['name'])
        for resource in batch
    ]
    # Execute all calls in batch simultaneously
    # If rate limit hit, break loop and proceed to report generation
```

**Rate Limit Handling:**
1. **If Rate Limit Hit**: Document which resources were successfully checked
2. **Error Message Pattern**: `"Too many requests. MCP graph collection request limit exceeded. Please retry after..."`
3. **Continue with Report**: Continue with Phase 4, then report with available data, clearly marking unchecked resources as "UNKNOWN - Rate limit"
4. **Extrapolation Logic**: If similar resource types (e.g., AWS S3 buckets) show 0% exposure consistently, note high likelihood of security for unchecked resources of same type

**Exposure Perimeter Result Structure:**

Each result contains:
- **NodeId/NodeName/NodeLabel**: Entity in the attack path (device, user, credential, storage)
- **Criticality**: Criticality level of the entity (if applicable)
- **HasVulnerabilities**: Boolean indicating if device has known CVEs
- **NumberOfAllNeighbours**: Connection count (high = privileged entity)
- **Edges**: JSON array of relationships (attack path hops)

**Key Analysis Points:**
1. **Device**: Entry point with vulnerabilities (Level 1 criticality common)
2. **Credential/Token**: Authentication artifact (Entra cookie, service principal)
3. **User**: Identity with RBAC permissions (check NumberOfAllNeighbours)
4. **Storage**: Target resource (Level 0 criticality)

---

### Phase 4: Device Vulnerability Assessment ⚠️ MANDATORY

**⛔ DO NOT SKIP THIS PHASE** - If HasVulnerabilities=true is detected in ANY exposure perimeter result, you MUST retrieve CVE details before proceeding to Phase 4.

**For each device in the exposure perimeter with HasVulnerabilities=true, retrieve detailed CVE data using Advanced Hunting:**

#### Step 4A: Identify Vulnerable Devices (REQUIRED CHECK)

From exposure perimeter results, extract device entities:
- Filter for `NodeLabel == "device"`
- Check `HasVulnerabilities == true`
- Extract **DeviceId** from `EntityIds` array (look for `DeviceInventoryId` or `SenseDeviceId`)

**Get device details using `mcp_sentinel-tria_GetDefenderMachine(id)`:**

This returns valuable context for the report:
- **computerDnsName**: Full device name
- **osPlatform / osVersion**: OS details (e.g., Windows 11 25H2)
- **exposureLevel**: High/Medium/Low exposure rating
- **riskScore**: None/Low/Medium/High risk score
- **healthStatus**: Active/Inactive/ImpairedCommunication
- **rbacGroupName**: Device group (e.g., "Field devices")
- **isAadJoined**: Entra join status
- **managedBy**: Intune/ConfigMgr/Unknown
- **lastSeen**: Last check-in timestamp

#### Step 4B: Query Vulnerability Summary (Advanced Hunting)

Run this KQL query using `mcp_sentinel-tria_RunAdvancedHuntingQuery` to get vulnerability counts by severity:

```kql
DeviceTvmSoftwareVulnerabilities
| where DeviceId == "<DEVICE_ID>"
| summarize 
    CVECount = count(), 
    CriticalCount = countif(VulnerabilitySeverityLevel == "Critical"),
    HighCount = countif(VulnerabilitySeverityLevel == "High"),
    MediumCount = countif(VulnerabilitySeverityLevel == "Medium"),
    LowCount = countif(VulnerabilitySeverityLevel == "Low"),
    CVEs = make_set(CveId, 20)
| project CVECount, CriticalCount, HighCount, MediumCount, LowCount, CVEs
```

**Returns:**
- Total CVE count affecting the device
- Breakdown by severity level (Critical, High, Medium, Low)
- Sample list of CVE IDs (first 20)

#### Step 4C: Query Critical CVE Details (Advanced Hunting)

If CriticalCount > 0, run this query to get detailed information on critical vulnerabilities:

```kql
DeviceTvmSoftwareVulnerabilities
| where DeviceId == "<DEVICE_ID>"
| where VulnerabilitySeverityLevel == "Critical"
| project CveId, VulnerabilitySeverityLevel, SoftwareName, SoftwareVendor, SoftwareVersion
| distinct CveId, VulnerabilitySeverityLevel, SoftwareName, SoftwareVendor, SoftwareVersion
| order by SoftwareName asc
```

**Returns:**
- CVE IDs for critical vulnerabilities
- Affected software name, vendor, and version
- Use this to identify which software needs immediate patching

**Note:** The `DeviceTvmSoftwareVulnerabilities` table exists in Advanced Hunting only (NOT in Sentinel Data Lake). This is consistent with Phase 1 where we activated Advanced Hunting tools.

**After Phase 4 completes:**
- Consolidate vulnerability data by device
- Count Critical/High/Medium/Low CVEs per device
- Identify affected software requiring immediate patching
- Flag devices with critical browser/OS vulnerabilities (high exploit likelihood)

---

### Phase 4: Attack Path Reconstruction

**For each exposed storage resource, parse the exposure perimeter data:**

#### Step 5A: Extract Attack Chain

From the `Edges` JSON array, identify the complete path:

```
Device (e.g., alpineskihouse-u411)
  ↓ [contains]
Entra Cookie (e.g., 74f40f549cac61bd...)
  ↓ [can authenticate as]
User (e.g., Denise Charron)
  ↓ [has permissions to]
Storage Account (e.g., contosooutdoorscorpdata)
```

#### Step 5B: Permission Analysis

Parse `EdgeProperties.AdditionalData.permissions.roles` to extract:
- **Role Name**: Owner, Contributor, Reader, etc.
- **Subscription Context**: Which Azure subscription
- **Actions**: Specific RBAC permissions (`*`, `*/read`, etc.)

#### Step 5C: Risk Assessment

Calculate risk based on:
- **Device Vulnerabilities**: `HasVulnerabilities == true` + CVE count + Exploit availability
- **User Privilege**: `NumberOfAllNeighbours > 30` = high privilege
- **Permission Level**: Owner > Contributor > Reader
- **Exposure Count**: How many storage resources share the same attack path

**Risk Scoring Matrix:**
| Factor | Multiplier |
|--------|------------|
| Critical CVEs with exploits | 3x |
| High CVEs with exploits | 2x |
| Owner permissions | 2x |
| User with >50 neighbors | 1.5x |
| Multiple storage accounts via same path | 1.5x per account |

---

### Phase 5: Generate Executive Report

**Use the [Report Template](#report-template) below to create comprehensive markdown report.**

**Save to:** `reports/Critical_Storage_Exposure_Report_<YYYY-MM-DD_HHMMSS>.md`

**Timestamp Format:** Use current date/time in format `YYYY-MM-DD_HHMMSS` (e.g., `2026-02-02_161530`)

**Report Sections:**
1. Executive Summary
2. Storage Resource Inventory
3. Exposure Perimeter Findings
4. Attack Path Analysis (Entry Points, Identity Exposure, Credentials)
5. Remediation Recommendations (by priority)
6. Conclusion

---

## KQL Query Library

### Query: All Critical Storage Assets (Combined)

```kql
ExposureGraphNodes
| where NodeLabel in ("microsoft.storage/storageaccounts", "BlobContainer", "s3.bucket")
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel == 0
| extend StorageType = case(
    NodeLabel == "microsoft.storage/storageaccounts", "Azure Storage Account",
    NodeLabel == "BlobContainer", "Azure Blob Container",
    NodeLabel == "s3.bucket", "AWS S3 Bucket",
    "Other"
)
| project 
    StorageName = NodeName, 
    StorageType,
    NodeId,
    CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel
| order by StorageType asc, StorageName asc
```

### Query: Storage Account Breakdown by Criticality

```kql
ExposureGraphNodes
| where NodeLabel == "microsoft.storage/storageaccounts"
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| extend CriticalityLevel = tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| summarize Count = count() by CriticalityLevel
| order by CriticalityLevel asc
```

### Query: Blob Containers with Sensitive Keywords

```kql
ExposureGraphNodes
| where NodeLabel == "BlobContainer"
| where isnotnull(NodeProperties.rawData.criticalityLevel)
| where NodeProperties.rawData.criticalityLevel.criticalityLevel == 0
| where NodeName has_any ("sensitive", "pii", "confidential", "secret", "internal", "corp")
| project NodeName, CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel
| order by NodeName asc
```

---

## Report Template

Use this structure for executive reports:

```markdown
# Critical Storage Exposure Security Analysis
**Report Generated:** <TIMESTAMP>  
**Classification:** CONFIDENTIAL  
**Investigation Scope:** Critical Storage Resources (Criticality Level 0)

---

## Executive Summary

[3 comprehensive paragraphs covering storage security posture, exposure findings, and key risks]

**Key Metrics:**
- **Total Critical Storage Resources:** [count] ([Azure count] Azure + [AWS count] AWS)
- **Exposed Resources:** [count] ([percentage]%)
- **Secure Resources (No Exposure):** [count] ([percentage]%)
**Risk Level:** [CRITICAL/HIGH/MEDIUM/LOW]

---

## 1. Storage Resource Inventory

### 1.1 Azure Storage Accounts
**Total:** [count]  
**Criticality Level 0:** [count]

| Storage Account Name | Subscription | Exposed | Attack Path |
|----------------------|--------------|---------|-------------|
| [account1] | [sub] | [YES/NO] | [path or N/A] |
| [account2] | [sub] | [YES/NO] | [path or N/A] |

### 1.2 Azure Blob Containers
**Total:** [count]  
**Criticality Level 0:** [count]

| Container Name | Sensitivity | Exposed | Attack Path |
|----------------|-------------|---------|-------------|
| [container1] | [e.g., PII] | [YES/NO] | [path or N/A] |
| [container2] | [e.g., Secrets] | [YES/NO] | [path or N/A] |

### 1.3 AWS S3 Buckets
**Total:** [count]  
**Criticality Level 0:** [count]

| Bucket Name | Purpose | Exposed | Attack Path |
|-------------|---------|---------|-------------|
| [bucket1] | [e.g., CloudTrail Logs] | [YES/NO] | [path or N/A] |
| [bucket2] | [e.g., Sensitive Data] | [YES/NO] | [path or N/A] |

---

## 2. Exposure Perimeter Findings

### 2.1 Overall Exposure Statistics

| Resource Type | Total | Exposed | Secure | Exposure Rate |
|---------------|-------|---------|--------|---------------|
| Azure Storage Accounts | [#] | [#] | [#] | [%]% |
| Azure Blob Containers | [#] | [#] | [#] | [%]% |
| AWS S3 Buckets | [#] | [#] | [#] | [%]% |
| **TOTAL** | [#] | [#] | [#] | [%]% |

### 2.2 Exposed Storage Resources

#### [Storage Resource Name 1] - [Resource Type]
**Risk Level:** [CRITICAL/HIGH/MEDIUM]

**Attack Path:**
```
Device: [device-name] (Level [X] criticality, HasVulnerabilities: [true/false])
  ↓ [contains]
Credential: [credential-hash] (Type: [Entra cookie/Service Principal/etc.])
  ↓ [can authenticate as]
User: [user-name] (Level [X] criticality, [#] neighbors)
  ↓ [has permissions to]
Storage: [storage-name] (Level 0 criticality)
```

**Permissions:**
- **Role:** [Owner/Contributor/Reader]
- **Subscription:** [subscription-id]
- **Actions:** [RBAC actions]

[Repeat for each exposed storage resource]

---

## 3. Attack Path Analysis

### 3.1 Entry Points (Vulnerable Devices)

| Device Name | Criticality | Has Vulnerabilities | CVE Count (Critical/High) | Storage Resources Accessible | Risk Level |
|-------------|-------------|---------------------|---------------------------|------------------------------|------------|
| [device1] | [Level] | [YES/NO] | [X/Y] | [count] | [CRITICAL/HIGH/MEDIUM] |

### 3.2 Identity Exposure

| User Name | Criticality | Neighbors | Storage Resources Accessible | Permission Level |
|-----------|-------------|-----------|------------------------------|------------------|
| [user1] | [Level] | [#] | [count] | [Owner/Contributor] |

### 3.3 Credential Analysis

| Credential Type | Hash/ID | User | Storage Count |
|-----------------|---------|------|---------------|
| Entra Cookie | [hash] | [user] | [count] |
| Service Principal | [id] | [name] | [count] |

---

## 4. Remediation Recommendations

### Critical Priority (Immediate - 24h)
| Risk | Affected Resources | Action |
|------|-------------------|--------|
| [Risk description] | [#] | [Action] |

### High Priority (Short-Term - 1 week)
| Risk | Affected Resources | Action |
|------|-------------------|--------|
| [Risk description] | [#] | [Action] |

### Medium Priority (Long-Term - 30 days)
| Risk | Affected Resources | Action |
|------|-------------------|--------|
| [Risk description] | [#] | [Action] |

---

## 5. Conclusion

[2-3 paragraphs summarizing investigation findings, security posture assessment, and key takeaways]

**Security Posture Rating:** [CRITICAL/POOR/FAIR/GOOD/EXCELLENT]

---

**Investigation Metadata:**
- **Total Storage Resources Analyzed:** [count]
- **Report Generation Date:** [timestamp]

```

---

## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **ExposureGraph tables not found** | You're querying Sentinel Data Lake - switch to Advanced Hunting using `activate_advanced_hunting_tools()` |
| **"Tool disabled" error for RunAdvancedHuntingQuery** | Must call `activate_advanced_hunting_tools()` first to enable the tool |
| **Empty exposure perimeter results** | This is GOOD - means storage has no walkable attack path (secure configuration) |
| **"Too many requests" / Rate limit exceeded** | **STOP querying immediately**. Proceed to report generation with available data. Mark unchecked resources as "UNKNOWN - Rate limit" in report. Reduce batch size to 4-6 for future runs. |
| **Exposure perimeter API timeout** | Batch size too large - reduce to 5-6 resources per parallel call |
| **NodeProperties.rawData is null** | Storage resource doesn't have criticality metadata - exclude from analysis |
| **EdgeProperties.AdditionalData missing permissions** | Non-RBAC edge type (e.g., "contains" vs "has permissions to") - focus on permission edges only |
| **AWS S3 buckets show no exposure but Azure does** | Expected if cross-cloud segmentation is working - document as positive finding |
| **Partial investigation due to rate limit** | Include disclaimer in report: "Investigation completed with partial data due to API throttling. X resources checked successfully, Y resources marked UNKNOWN. Pattern analysis suggests [extrapolate based on available data]." |
| **DeviceTvmSoftwareVulnerabilities table not found** | You're querying Sentinel Data Lake - this table only exists in Advanced Hunting. Ensure you activated Advanced Hunting tools in Phase 1. |
| **DeviceId not found in vulnerability query** | Verify DeviceId format matches what's in EntityIds from exposure perimeter (use DeviceInventoryId or SenseDeviceId value) |

### Validation Checklist

Before delivering report, verify:
- ✅ All storage types queried (Azure Storage Accounts, Blob Containers, S3 Buckets)
- ✅ Exposure perimeter checked for ALL discovered critical storage resources **OR** rate limit hit documented
- ✅ Attack paths fully reconstructed (Device → Credential → User → Storage)
- ✅ Permissions parsed correctly from EdgeProperties JSON
- ✅ Device vulnerabilities retrieved for exposed attack paths
- ✅ **Rate limit impact documented in report** if partial investigation
- ✅ Report saved to correct path: `reports/Critical_Storage_Exposure_Report_<YYYY-MM-DD_HHMMSS>.md`
- ✅ Absolute path returned to user

---

## Integration with Main Copilot Instructions

This skill follows all patterns from the main `copilot-instructions.md`:
- **Universal Patterns:** Inherits date range rules, parallel execution, token management
- **Sentinel Graph MCP Tools:** Uses `mcp_sentinel-grap_graph_exposure_perimeter` for attack path analysis
- **Advanced Hunting MCP Tools:** Uses `mcp_sentinel-tria_RunAdvancedHuntingQuery` for ExposureGraph queries
- **KQL Best Practices:** Follows ExposureGraph query patterns from `queries/ExposureGraph_QuickReference.md`
- **Report Generation:** Uses `create_file` tool for all markdown output

**Example Invocations:**
- "Investigate critical storage exposure across Azure and AWS"
- "Run critical storage security assessment"
- "Analyze attack paths to sensitive storage accounts"
- "Check exposure perimeter for all critical blob containers"
- "Generate storage security posture report"

---

## Advanced Analysis Techniques

### Detecting Privilege Creep

**Question:** Are users accumulating storage permissions over time?

**Method:** Compare `NumberOfAllNeighbours` metric:
- **> 50 neighbors:** User has excessive cross-resource access
- **> 100 neighbors:** Likely service account or privileged administrator
- **Recommendation:** Audit all permissions for users with high neighbor counts

### Identifying Lateral Movement Risks

**Question:** Can an attacker pivot from one storage account to others via the same attack path?

**Method:** Group exposed storage by `SourceNodeId` (device) and `TargetNodeId` (user):
- If multiple storage resources share the same device/user/credential chain, this is lateral movement risk
- Prioritize securing the shared entry point (device) over individual storage accounts

### Container-Level Protection Effectiveness

**Question:** Why do containers have better protection than storage accounts?

**Investigation Steps:**
1. Query RBAC assignments at storage account level vs container level
2. Identify if container-specific roles are being used (e.g., "Storage Blob Data Contributor" on container, not account)
3. Document this pattern as best practice for replication

---

## Performance Optimization

### Batch Size Guidelines

| Total Storage Resources | Recommended Batch Size | Estimated Time | Risk of Rate Limit |
|------------------------|------------------------|----------------|-------------------|
| < 10 resources | 6-8 per batch | ~30 seconds | Low |
| 10-25 resources | 6 per batch | ~1-2 minutes | Medium |
| 25-50 resources | 6 per batch | ~2-3 minutes | High |
| > 50 resources | 4-5 per batch | ~4-5 minutes | Very High |

**Why Batching Matters:**
- VS Code token limits (1M tokens)
- MCP server connection stability
- Graph query complexity (exposure perimeter = recursive path finding)
- **API rate limits** (typically ~20-25 exposure perimeter queries before throttling)

**Rate Limit Mitigation:**
1. **Prioritize Critical Resources:** Query storage accounts with sensitive names first (e.g., "sensitive", "pii", "secret", "internal")
2. **Reduce Batch Size:** If you have >20 total resources, reduce batch size to 4-6
3. **Monitor for Errors:** Check each batch result for rate limit errors before proceeding
4. **Accept Partial Results:** If rate limit hit, proceed with report generation using available data

---

*Last Updated: February 2, 2026*
