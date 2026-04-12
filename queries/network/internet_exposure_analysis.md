# Internet Exposure Analysis

**Created:** 2026-03-31  
**Platform:** Both  
**Tables:** ExposureGraphNodes, ExposureGraphEdges, DeviceInfo, DeviceNetworkEvents, DeviceNetworkInfo  
**Keywords:** internet exposure, public IP, customer-facing, inbound connections, RDP, SSH, firewall rules, NSG, attack surface, listening ports, exposure score, network scanning  
**MITRE:** T1190, T1133, T1021.001, T1021.004, TA0001, TA0043  
**Domains:** exposure  
**Timeframe:** Last 7-30 days (configurable)  

---

## Overview

Combines three tiers of internet exposure intelligence to identify, validate, and prioritize internet-facing assets:

| Tier | Source | Signal | Reliability |
|------|--------|--------|-------------|
| **1. Authoritative** | `DeviceInfo.IsInternetFacing` | MDE-confirmed via external scan or observed inbound connection. Auto-expires after 48h of no activity ([MS Docs](https://learn.microsoft.com/en-us/defender-endpoint/internet-facing-devices#use-advanced-hunting)) | Highest — ground truth from Microsoft's external scanning infrastructure |
| **2. Theoretical** | ExposureGraph (`isCustomerFacing`, firewall rules) | What topology/config ALLOWS — `isCustomerFacing` is a business-function flag, NOT a confirmed internet exposure indicator | Medium — may overcount (public IP + open rules ≠ reachable) |
| **3. Observed** | `DeviceNetworkEvents` inbound connections | What traffic is ACTUALLY arriving from public IPs | High for confirmation, but requires active attackers/scanners to generate signal |

**Start with Tier 1 (DeviceInfo)** for the authoritative list, then enrich with Tier 2 (ExposureGraph) for topology context and Tier 3 (DeviceNetworkEvents) for traffic validation.

### Data Source Summary

| Table | Source | What It Tells You |
|-------|--------|-------------------|
| `ExposureGraphNodes` | Exposure Management | Which devices/IPs are flagged as customer-facing, exposure scores, public IPs |
| `ExposureGraphEdges` | Exposure Management | Firewall/NSG rules: what ports are allowed from what CIDRs |
| `DeviceInfo` | MDE | **`IsInternetFacing`** (bool) — authoritative internet-facing classification via external scans + observed inbound connections. `AdditionalFields` provides reason, port, public IP, protocol, last-seen. Auto-expires after 48h. [MS Docs](https://learn.microsoft.com/en-us/defender-endpoint/internet-facing-devices) |
| `DeviceNetworkEvents` | MDE | Actual inbound connections accepted, connection failures (probes), listening ports |
| `DeviceNetworkInfo` | MDE | Network adapter config: public IPs, `IsConnectedToInternet` flag, network categories |

### ⚠️ RemoteIPType FourToSixMapping Pitfall

**CRITICAL:** Filtering `RemoteIPType == "Public"` misses connections to services using IPv4-mapped IPv6 sockets (e.g., IIS dual-stack listeners). When IIS accepts an IPv4 connection through its `::ffff:` binding, MDE classifies `RemoteIPType` as `FourToSixMapping` — even though the source IP is a public internet address. This means **queries filtering only on `"Public"` will report 0 inbound web connections** while `W3CIISLog` shows hundreds of requests from the same IPs on the same port.

**Fix:** When querying environments with IIS dual-stack listeners (or any IPv4-mapped IPv6 sockets), add `FourToSixMapping` to the filter: `RemoteIPType in ("Public", "FourToSixMapping")`. Alternatively, use RFC1918 exclusion filters (as in `queries/endpoint/endpoint_failed_connections.md` Query 2) which catch all non-private IPs regardless of MDE's type classification. The queries below use `RemoteIPType == "Public"` for simplicity — add `FourToSixMapping` if your environment uses dual-stack web services.

### Key ActionTypes in DeviceNetworkEvents

| ActionType | Meaning | Use For |
|------------|---------|---------|
| `InboundConnectionAccepted` | Remote IP successfully connected inbound | Confirming exposure — something is listening AND reachable |
| `ConnectionFailed` | Connection attempt failed (RST/timeout) | Detecting scanning/probing against closed ports |
| `ConnectionAttempt` | Outbound or inbound TCP attempt | Port probing (when LocalPort is populated with RemoteIPType=Public) |
| `ListeningConnectionCreated` | Process opened a listening socket | Service discovery — what ports are open on each device |

---

## Quick Reference — Query Index

**Investigation shortcuts:**
- **Internet-facing device with RDP exposed** (TP Q11, Q4): **1** (which devices) → **7** (RDP cadence + top attackers) → **6** (source IP enrichment)
- **Critical asset exposure posture** (TP Q11): **1** (authoritative list) + **4** (inbound volumes) + **5** (port breakdown)
- **Scanning/probing against exposed device** (TP Q11, Q4): **8** (failed connections) → **6** (top attackers) → **12** (specific port hunt)
- **Full exposure validation for incident device** (TP Q1): **1** (MDE confirmed) + **2** (ExposureGraph topology) + **11** (cross-reference rules vs traffic)

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [MDE Internet-Facing Devices (DeviceInfo)](#query-1-mde-internet-facing-devices-deviceinfo) | Investigation | `DeviceInfo` |
| 2 | [Customer-Facing Devices (Exposure Graph)](#query-2-customer-facing-devices-exposure-graph) | Investigation | `ExposureGraphNodes` |
| 3 | [Internet-Exposed Firewall Rules (Exposure Graph)](#query-3-internet-exposed-firewall-rules-exposure-graph) | Detection | `ExposureGraphEdges` |
| 4 | [Inbound Connections Accepted — Device Ranking](#query-4-inbound-connections-accepted--device-ranking) | Investigation | `DeviceNetworkEvents` |
| 5 | [Inbound Connections by Port](#query-5-inbound-connections-by-port) | Investigation | `DeviceNetworkEvents` |
| 6 | [Top Inbound Attackers by Source IP](#query-6-top-inbound-attackers-by-source-ip) | Triage | `DeviceNetworkEvents` |
| 7 | [RDP Brute-Force Analysis](#query-7-rdp-brute-force-analysis) | Detection | `DeviceNetworkEvents` |
| 8 | [Connection Failures — Scanning/Probing Detection](#query-8-connection-failures--scanningprobing-detection) | Detection | `DeviceNetworkEvents` |
| 9 | [Listening Ports — Service Discovery](#query-9-listening-ports--service-discovery) | Investigation | `DeviceNetworkEvents` |
| 10 | [DeviceNetworkInfo — Devices on Public Networks](#query-10-devicenetworkinfo--devices-on-public-networks) | Investigation | `DeviceNetworkInfo` |
| 11 | [Exposure Validation — Cross-Reference Graph Rules with Observed Tra...](#query-11-exposure-validation--cross-reference-graph-rules-with-observed-traffic) | Detection | `DeviceNetworkEvents` + `ExposureGraphNodes` |
| 12 | [Specific Port Exposure Hunt](#query-12-specific-port-exposure-hunt) | Investigation | `DeviceNetworkEvents` |
| 13 | [ExposureGraph Node Type Inventory](#query-13-exposuregraph-node-type-inventory) | Posture | `ExposureGraphNodes` |
| 14 | [IP Address Nodes — Public IP Inventory](#query-14-ip-address-nodes--public-ip-inventory) | Posture | `ExposureGraphNodes` |


## Query 1: MDE Internet-Facing Devices (DeviceInfo)

Authoritative internet-facing classification from Microsoft Defender for Endpoint. MDE flags devices as internet-facing based on **external scans** (Microsoft probes detecting reachable ports) and **observed inbound connections** (actual incoming traffic from public IPs). The tag auto-expires after 48 hours of no activity — stale data is automatically cleaned. This is the ground-truth source for internet exposure and should be checked **before** ExposureGraph topology queries.

**Reference:** [Internet-facing devices — Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/internet-facing-devices#use-advanced-hunting)

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "InitialAccess"
title: "Internet-facing device {{DeviceName}} detected via {{InternetFacingReason}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Verify device should be internet-facing. Review exposed port and protocol. Check NSG/firewall rules. Investigate the InternetFacingReason — PublicScan (externally detected) vs InboundConnection (observed traffic)."
adaptation_notes: "Remove summarize — convert to per-DeviceId rows. Add DeviceId column. Consider filtering to critical assets only by joining with ExposureGraphNodes criticality"
-->

```kql
// MDE-confirmed internet-facing devices (authoritative source)
DeviceInfo
| where Timestamp > ago(7d)
| where IsInternetFacing == true
| summarize arg_max(Timestamp, *) by DeviceId
| extend InternetFacingReason = extractjson("$.InternetFacingReason", AdditionalFields, typeof(string)),
    InternetFacingLocalPort = extractjson("$.InternetFacingLocalPort", AdditionalFields, typeof(int)),
    InternetFacingScannedPublicPort = extractjson("$.InternetFacingPublicScannedPort", AdditionalFields, typeof(int)),
    InternetFacingScannedPublicIp = extractjson("$.InternetFacingPublicScannedIp", AdditionalFields, typeof(string)),
    InternetFacingLocalIp = extractjson("$.InternetFacingLocalIp", AdditionalFields, typeof(string)),
    InternetFacingTransportProtocol = extractjson("$.InternetFacingTransportProtocol", AdditionalFields, typeof(string)),
    InternetFacingLastSeen = extractjson("$.InternetFacingLastSeen", AdditionalFields, typeof(datetime))
| project DeviceName, InternetFacingReason, InternetFacingLocalIp, InternetFacingLocalPort,
    InternetFacingScannedPublicIp, InternetFacingScannedPublicPort,
    InternetFacingTransportProtocol, InternetFacingLastSeen
| order by InternetFacingLastSeen desc
```

**Key fields:**
- `IsInternetFacing`: Boolean on DeviceInfo — set by MDE when device is confirmed reachable from the internet
- `InternetFacingReason`: `PublicScan` (Microsoft's external scanner detected the device) or `InboundConnection` (device received external incoming communication)
- `InternetFacingLocalPort` / `InternetFacingScannedPublicPort`: The port confirmed open
- `InternetFacingScannedPublicIp`: The public IP that was scanned/connected to
- `InternetFacingLastSeen`: Last time the device was confirmed internet-facing (tag removed after 48h of no events)

**Comparison with ExposureGraph flags:**

| Property | Source | Meaning | Reliability |
|----------|--------|---------|-------------|
| `DeviceInfo.IsInternetFacing` | MDE | Confirmed via external scan or inbound connection | **Authoritative** — auto-expires after 48h |
| `ExposureGraphNodes.rawData.isCustomerFacing` | Exposure Management | Device serves a business function | **Not internet exposure** — business flag only |
| `ExposureGraphNodes.rawData.publicIP` | Exposure Management | Device has a public IP assigned | **Inconclusive** — NSG may block all inbound |
| `ExposureGraphNodes.rawData.IsInternetFacing` | Exposure Management | Legacy internet-facing flag | **Unreliable** — not populated in many environments |
| `ExposureGraphNodes.rawData.exposedToInternet` | Exposure Management | Current internet-facing flag | **Unreliable** — not populated in many environments |

---

## Query 2: Customer-Facing Devices (Exposure Graph)

Devices flagged as customer-facing by Exposure Management, with exposure scores and public IPs. Note: `isCustomerFacing` is a **business-function flag** indicating the device serves a customer/business role — it does NOT confirm actual internet reachability. Use Query 1 (`DeviceInfo.IsInternetFacing`) for authoritative internet-facing classification.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture inventory query — ExposureGraphNodes summarize/project, not suitable for row-level alerting"
-->

```kql
// Customer-facing devices with exposure scores
ExposureGraphNodes
| where NodeLabel == "device"
| extend Props = parse_json(tostring(NodeProperties.rawData))
| extend isCustomerFacing = tobool(Props.isCustomerFacing)
| extend publicIP = tostring(Props.publicIP)
| extend deviceName = tostring(Props.deviceName)
| extend osPlatform = tostring(Props.osPlatformFriendlyName)
| extend exposureScore = tostring(Props.exposureScore)
| extend deviceType = tostring(Props.deviceType)
| extend onboardingStatus = tostring(Props.onboardingStatus)
| extend riskScore = tostring(Props.riskScore)
| where isCustomerFacing == true
| project deviceName, publicIP, osPlatform, deviceType, exposureScore, riskScore, onboardingStatus
| order by exposureScore desc
```

**Key fields:**
- `isCustomerFacing`: Boolean — business-function flag, NOT internet exposure. Devices serving authentication, file sharing, or customer-facing apps get flagged regardless of actual internet reachability
- `exposureScore`: None / Low / Medium / High — composite vulnerability + configuration score
- `publicIP`: The public IP assigned to the device — does NOT confirm reachability (NSG/firewall may block all inbound)

---

## Query 3: Internet-Exposed Firewall Rules (Exposure Graph)

Extracts all firewall/NSG rules that allow traffic from `0.0.0.0/0` (the entire internet) to specific resources, with port and protocol details.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture inventory query — ExposureGraphEdges topology, not event-driven. Use for scheduled posture snapshots, not CD alerts"
-->

```kql
// Firewall rules allowing traffic from the internet
ExposureGraphEdges
| where EdgeLabel == "routes traffic to"
| extend edgeProps = parse_json(tostring(EdgeProperties.rawData))
| extend trafficRaw = tostring(edgeProps.allowedAffectiveTraffic)
| where isnotempty(trafficRaw) and trafficRaw has "0.0.0.0/0"
| extend srcIP = tostring(SourceNodeName)
| extend tgtResource = tostring(TargetNodeName)
| extend tgtType = TargetNodeLabel
| project srcIP, tgtResource, tgtType, trafficRaw
```

**To parse individual port rules from the nested JSON:**

```kql
// Parsed firewall rules — one row per allowed port range
ExposureGraphEdges
| where EdgeLabel == "routes traffic to"
| extend edgeProps = parse_json(tostring(EdgeProperties.rawData))
| extend trafficStr = tostring(edgeProps.allowedAffectiveTraffic)
| where isnotempty(trafficStr) and trafficStr has "0.0.0.0/0"
| extend srcIP = tostring(SourceNodeName)
| extend tgtResource = tostring(TargetNodeName)
| extend tgtType = TargetNodeLabel
| project srcIP, tgtResource, tgtType, trafficStr
| extend trafficJson = parse_json(trafficStr)
| mv-expand rule = trafficJson
| extend destPorts = tostring(rule.destinationPortRanges)
| extend srcCIDR = tostring(rule.sourceCidr)
| extend protocol = case(
    tostring(rule.protocolRanges) == '["6"]', "TCP",
    tostring(rule.protocolRanges) == '["17"]', "UDP",
    tostring(rule.protocolRanges) == '["1"]', "ICMP",
    tostring(rule.protocolRanges))
| where srcCIDR has "0.0.0.0/0"
| project srcIP, tgtResource, tgtType, destPorts, protocol, srcCIDR
| order by tgtResource asc
```

**Risky port filter — find resources with RDP/SSH/SMB open from internet:**

```kql
// High-risk ports exposed to the internet
ExposureGraphEdges
| where EdgeLabel == "routes traffic to"
| extend edgeProps = parse_json(tostring(EdgeProperties.rawData))
| extend trafficStr = tostring(edgeProps.allowedAffectiveTraffic)
| where isnotempty(trafficStr) and trafficStr has "0.0.0.0/0"
| where trafficStr has_any ("3389", "22", "445", "1433", "3306", "5432", "27017", "6379")
| extend srcIP = tostring(SourceNodeName)
| extend tgtResource = tostring(TargetNodeName)
| extend tgtType = TargetNodeLabel
| project srcIP, tgtResource, tgtType, trafficStr
```

---

## Query 4: Inbound Connections Accepted — Device Ranking

Confirms exposure by showing which devices are actually receiving inbound connections from public IPs, ranked by volume and source IP diversity.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "InitialAccess"
title: "Internet-exposed device {{DeviceName}} accepted {{InboundConnections}} inbound connections"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Review NSG/firewall rules for this device. Verify that inbound services are intentionally exposed. Check if the device should be customer-facing."
adaptation_notes: "Remove summarize — convert to row-level with per-connection rows. Add DeviceId, RemoteIP, LocalPort columns. Consider threshold filter (e.g., > 50 connections/day) to avoid noise"
-->

```kql
// Devices receiving inbound connections from the internet
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| summarize 
    InboundConnections = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    TargetPorts = make_set(LocalPort, 20),
    DistinctPorts = dcount(LocalPort),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName
| order by InboundConnections desc
```

---

## Query 5: Inbound Connections by Port

Shows which ports are receiving the most inbound traffic from the internet — identifies the highest-risk services.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical summary grouped by port — useful for posture reporting but not row-level alerting. Use Query 4 or 12 for CD-ready variants"
-->

```kql
// Inbound accepted connections by destination port
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| summarize 
    Connections = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    Devices = make_set(DeviceName, 10),
    DeviceCount = dcount(DeviceName)
    by LocalPort
| extend Service = case(
    LocalPort == 22, "SSH",
    LocalPort == 80, "HTTP",
    LocalPort == 443, "HTTPS",
    LocalPort == 445, "SMB",
    LocalPort == 1433, "MSSQL",
    LocalPort == 3306, "MySQL",
    LocalPort == 3389, "RDP",
    LocalPort == 5432, "PostgreSQL",
    LocalPort == 5985, "WinRM-HTTP",
    LocalPort == 5986, "WinRM-HTTPS",
    LocalPort == 8080, "HTTP-Alt",
    LocalPort == 8443, "HTTPS-Alt",
    LocalPort == 18789, "OpenClaw-GW",
    strcat("Port-", tostring(LocalPort)))
| order by Connections desc
```

---

## Query 6: Top Inbound Attackers by Source IP

Identifies the most active source IPs sending inbound connections — useful for enrichment and threat intel correlation.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "High-volume inbound attacker {{RemoteIP}} targeting {{DeviceCount}} devices"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Enrich the source IP via enrich_ips.py or TI lookup. If abuse score is high, consider blocking at NSG/firewall level. Check if connections were to risky ports (RDP, SSH, SMB)."
adaptation_notes: "Restructure to row-level: remove summarize, project per-connection rows with RemoteIP, DeviceName, LocalPort. Add threshold (e.g., dcount(DeviceName) > 3) to detect multi-device scanners"
-->

```kql
// Top source IPs making inbound connections
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| summarize 
    Connections = count(),
    TargetDevices = make_set(DeviceName, 10),
    DeviceCount = dcount(DeviceName),
    TargetPorts = make_set(LocalPort, 10),
    PortCount = dcount(LocalPort),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP
| order by Connections desc
| take 25
```

---

## Query 7: RDP Brute-Force Analysis

Deep-dive into RDP (3389) exposure — hourly attack cadence, top attackers, and target device distribution.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "RDP brute-force activity on {{DeviceName}} from {{RemoteIP}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Verify RDP should be internet-exposed. Consider restricting to JIT access or VPN-only. Enrich attacker IP. Check for successful RDP logons following brute-force attempts."
adaptation_notes: "First KQL block (hourly cadence) is statistical — not CD-ready. Second block (top attackers) needs row-level conversion: remove summarize, project per-connection rows. Add DeviceId, ReportId"
-->

```kql
// RDP inbound — hourly attack cadence
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| where LocalPort == 3389
| summarize Connections = count() by bin(Timestamp, 1h), DeviceName
| order by Timestamp desc
```

```kql
// RDP inbound — top attackers (for enrichment)
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| where LocalPort == 3389
| summarize 
    Hits = count(),
    Devices = make_set(DeviceName, 10),
    DeviceCount = dcount(DeviceName)
    by RemoteIP
| order by Hits desc
| take 20
```

---

## Query 8: Connection Failures — Scanning/Probing Detection

Detects failed inbound connections — indicates port scanning or probing against closed/filtered ports.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "Discovery"
title: "Port scanning detected — {{Failures}} failed connections on port {{LocalPort}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Review which ports are being probed. If high-value ports (RDP, SSH, SMB), verify firewall rules are blocking. Enrich top source IPs for threat intel."
adaptation_notes: "Summarize by LocalPort — needs restructure to row-level per-device. Add DeviceName to group-by or convert to per-connection rows. Add threshold filter to avoid ephemeral port noise"
-->

```kql
// Failed inbound connections — scanning detection
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionFailed"
| where RemoteIPType == "Public"
| summarize 
    Failures = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    Devices = make_set(DeviceName, 10),
    DeviceCount = dcount(DeviceName)
    by LocalPort
| where Failures > 5
| extend Service = case(
    LocalPort == 0, "SYN-Scan (port 0)",
    LocalPort == 22, "SSH",
    LocalPort == 445, "SMB",
    LocalPort == 3389, "RDP",
    LocalPort == 18789, "OpenClaw-GW",
    LocalPort < 1024, strcat("Well-Known-", tostring(LocalPort)),
    strcat("Ephemeral-", tostring(LocalPort)))
| order by Failures desc
```

---

## Query 9: Listening Ports — Service Discovery

Shows what ports each device has opened for listening in the last 7 days. Focus on well-known ports (< 10000) to identify actual services vs ephemeral.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Discovery"
title: "New listening port {{LocalPort}} opened on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Verify the listening process is authorized. Check if the port is exposed to the internet via NSG/firewall. Investigate the InitiatingProcess for unexpected services."
adaptation_notes: "Remove summarize — convert to per-event rows with DeviceName, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine. Add DeviceId, ReportId. Filter to risky ports only for CD (22, 80, 443, 445, 3389, 8080, 18789)"
-->

```kql
// Well-known listening ports per device
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ListeningConnectionCreated"
| where LocalPort > 0 and LocalPort < 10000
| summarize 
    Devices = make_set(DeviceName, 15),
    DeviceCount = dcount(DeviceName),
    Occurrences = count()
    by LocalPort
| extend Service = case(
    LocalPort == 22, "SSH",
    LocalPort == 80, "HTTP",
    LocalPort == 139, "NetBIOS",
    LocalPort == 443, "HTTPS",
    LocalPort == 445, "SMB",
    LocalPort == 2869, "SSDP/UPnP",
    LocalPort == 3389, "RDP",
    LocalPort == 4317, "OpenTelemetry",
    LocalPort == 5040, "CDPUserSvc",
    LocalPort == 5985, "WinRM-HTTP",
    LocalPort == 6516, "Azure-MMA-6516",
    LocalPort == 6601, "Azure-MMA-6601",
    LocalPort == 6602, "Azure-MMA-6602",
    LocalPort == 7680, "WUDO (Delivery Opt)",
    LocalPort == 7768, "BeyondTrust/Other",
    LocalPort == 8080, "HTTP-Alt",
    LocalPort == 18789, "OpenClaw-GW",
    strcat("Port-", tostring(LocalPort)))
| order by DeviceCount desc, LocalPort asc
```

---

## Query 10: DeviceNetworkInfo — Devices on Public Networks

Lists MDE-enrolled devices that report being connected to the internet, with their public IP assignments and network category.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "DeviceNetworkInfo snapshot query — reports current state, not security events. Not suitable for CD alerting. Use for posture enrichment in other queries"
-->

```kql
// Devices with IsConnectedToInternet = true and public network category
DeviceNetworkInfo
| where Timestamp > ago(1d)
| summarize arg_max(Timestamp, *) by DeviceId
| mv-expand Net = parse_json(ConnectedNetworks)
| extend IsInternet = tobool(Net.IsConnectedToInternet)
| extend NetCategory = tostring(Net.Category)
| where IsInternet == true and NetCategory == "Public"
| mv-expand IPset = parse_json(IPAddresses)
| extend IPAddr = tostring(IPset.IPAddress)
| extend IPType = tostring(IPset.AddressType)
| project DeviceName, IPAddr, IPType, NetCategory, Timestamp
| order by DeviceName asc
```

---

## Query 11: Exposure Validation — Cross-Reference Graph Rules with Observed Traffic

Joins ExposureGraph firewall rules (what's allowed) with DeviceNetworkEvents (what's observed) to find gaps — rules that allow traffic but no observed connections (unused exposure), or connections on ports not in the rule set (unexpected exposure).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table join with let statements and leftouter join — multi-table correlation query not suitable for CD. Uses ExposureGraphNodes (static topology) + DeviceNetworkEvents. Use for scheduled posture reporting"
-->

```kql
// Step 1: Get customer-facing devices from ExposureGraph
let ExposedDevices = ExposureGraphNodes
| where NodeLabel == "device"
| extend Props = parse_json(tostring(NodeProperties.rawData))
| where tobool(Props.isCustomerFacing) == true
| extend deviceName = tolower(tostring(Props.deviceName))
| extend publicIP = tostring(Props.publicIP)
| extend exposureScore = tostring(Props.exposureScore)
| project deviceName, publicIP, exposureScore;
// Step 2: Get observed inbound connections
let ObservedInbound = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| summarize 
    InboundCount = count(),
    UniqueIPs = dcount(RemoteIP),
    Ports = make_set(LocalPort, 20)
    by DeviceName
| extend deviceName = tolower(DeviceName);
// Step 3: Cross-reference — what's exposed vs what's seeing traffic
ExposedDevices
| join kind=leftouter ObservedInbound on deviceName
| extend HasObservedTraffic = isnotnull(InboundCount)
| project deviceName, publicIP, exposureScore, 
    HasObservedTraffic, InboundCount, UniqueIPs, Ports
| order by InboundCount desc
```

**Interpretation:**
- `HasObservedTraffic = true` + high InboundCount → **Confirmed exposure, actively targeted** (corroborate with Query 1 `DeviceInfo.IsInternetFacing`)
- `HasObservedTraffic = false` + customer-facing → **Theoretical exposure only** — `isCustomerFacing` is a business-function flag, not confirmed internet reachability. Verify via Query 1
- Not in ExposureGraph but receiving inbound → **Shadow exposure** (missing from topology model — check Query 1 for authoritative status)

---

## Query 12: Specific Port Exposure Hunt

Template query for hunting inbound connections on a specific port — replace `<TARGET_PORT>` with the port of interest (e.g., 18789 for OpenClaw gateway).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Inbound connection activity on monitored port {{LocalPort}} on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Verify whether this port should be reachable from the internet. Investigate the listening process. Enrich source IPs for threat intel. If port is OpenClaw (18789), check for Shadow AI agent installation."
adaptation_notes: "Replace <TARGET_PORT> with specific port value. Remove summarize — convert to per-connection rows. Add DeviceId, ReportId, RemoteIP columns. Split into separate CD rules per target port for clarity"
-->

```kql
// Hunt for inbound activity on a specific port
let targetPort = <TARGET_PORT>;
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType in ("InboundConnectionAccepted", "ConnectionAttempt", "ConnectionFailed")
| where RemoteIPType == "Public"
| where LocalPort == targetPort
| summarize 
    Accepted = countif(ActionType == "InboundConnectionAccepted"),
    Attempts = countif(ActionType == "ConnectionAttempt"),
    Failed = countif(ActionType == "ConnectionFailed"),
    UniqueIPs = dcount(RemoteIP),
    TopIPs = make_set(RemoteIP, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName
| extend Status = case(
    Accepted > 0, "🔴 ACCEPTING CONNECTIONS",
    Attempts > 10, "🟠 Being Probed (likely closed)",
    Attempts > 0, "🟡 Minor probing",
    Failed > 0, "🔵 Connection failures only",
    "✅ No activity")
| order by Accepted desc, Attempts desc
```

---

## Query 13: ExposureGraph Node Type Inventory

Discovery query — enumerate all node types and counts in the ExposureGraph to understand your topology coverage.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Pure inventory/discovery query — summarize count() by NodeLabel/EdgeLabel. No security event to alert on"
-->

```kql
// ExposureGraph node type inventory
ExposureGraphNodes
| summarize Count = count() by NodeLabel
| order by Count desc
```

```kql
// ExposureGraph edge type inventory
ExposureGraphEdges
| summarize Count = count() by EdgeLabel
| order by Count desc
```

---

## Query 14: IP Address Nodes — Public IP Inventory

Lists all public IP address nodes in the ExposureGraph with their associated categories and properties.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ExposureGraph topology inventory — static IP listing with route-to edges. Not event-driven, not suitable for CD"
-->

```kql
// All IP address nodes in ExposureGraph
ExposureGraphNodes
| where NodeLabel == "IP address"
| extend Props = parse_json(tostring(NodeProperties.rawData))
| extend ipAddress = tostring(Props.ipAddress)
| extend fqdn = tostring(Props.fqdn)
| project NodeName, ipAddress, fqdn, Categories = tostring(NodeCategories)
| order by ipAddress asc
```

**Follow-up: what resources does each IP route traffic to?**

```kql
// IP → resource routing with traffic rules
ExposureGraphEdges
| where EdgeLabel == "routes traffic to"
| where SourceNodeLabel == "IP address"
| extend edgeProps = parse_json(tostring(EdgeProperties.rawData))
| extend traffic = tostring(edgeProps.allowedAffectiveTraffic)
| project 
    SourceIP = SourceNodeName, 
    TargetResource = TargetNodeName, 
    TargetType = TargetNodeLabel,
    TrafficRules = traffic
| order by SourceIP asc
```

---

## Investigation Workflow

### Full Internet Exposure Assessment

1. **Run Query 1** — Get MDE-confirmed internet-facing devices (`DeviceInfo.IsInternetFacing`) — authoritative starting point
2. **Run Query 2** — Identify customer-facing devices in ExposureGraph for additional topology context
3. **Run Query 3** — Check what firewall rules allow from `0.0.0.0/0`
4. **Run Query 4+5** — Confirm which devices/ports are actually receiving inbound traffic
5. **Run Query 11** — Cross-reference: customer-facing devices with vs without observed traffic
6. **Run Query 8** — Check what scanning/probing is hitting closed ports
7. **Run Query 9** — Inventory all listening ports across the fleet
8. **Enrich top attacker IPs** using `enrich_ips.py` from Query 6 output

### Specific Port Hunt (e.g., OpenClaw 18789)

1. **Run Query 12** with `targetPort = 18789`
2. **Run Query 3** (risky port variant) — check if NSG/firewall allows 18789
3. **Enrich source IPs** from Query 12 output
4. Cross-reference with process-level evidence (DeviceProcessEvents for the listening service)

### Key Telemetry Gaps

| Gap | Impact | Workaround |
|-----|--------|------------|
| ExposureGraph only covers resources with Azure/GCP/AWS connectors | On-prem or unmanaged devices won't appear in topology queries | Use DeviceNetworkEvents `InboundConnectionAccepted` to detect exposure empirically |
| `ConnectionAttempt` may not always populate for inbound probes | Missing some scanning evidence | Use `ConnectionFailed` as primary probe detection |
| DeviceNetworkInfo `IsConnectedToInternet` is self-reported by the OS | NAT'd devices behind corporate firewalls may report true | Cross-reference with `DeviceInfo.IsInternetFacing` (Query 1) for authoritative internet reachability — NOT `isCustomerFacing` which is a business-function flag |
| `DeviceInfo.IsInternetFacing` auto-expires after 48h of no activity | Intermittently-exposed devices may lose the tag between scan cycles | Check `InternetFacingLastSeen` in `AdditionalFields` for last confirmation time. Use DeviceNetworkEvents (Query 4) as backup confirmation |
| ExposureGraph has 30-day retention in Advanced Hunting | Can't look back further for historical topology changes | Snapshot key queries periodically for trend analysis |

---

**Last Updated:** 2026-04-11  
**Author:** Security Investigation System
