# DNS Hijacking via SOHO Router Compromise — Detection Queries

**Created:** 2026-04-08  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceNetworkInfo, DeviceNetworkEvents, DeviceRegistryEvents, DeviceProcessEvents, EntraIdSignInEvents, CloudAppEvents  
**Keywords:** DNS hijacking, SOHO router, DNS settings modification, DHCP poisoning, adversary-in-the-middle, AiTM, Forest Blizzard, Storm-2754, dnsmasq, DNS resolver, DnsAddresses, DHCP DNS  
**MITRE:** T1584.002, T1557, T1040, TA0042, TA0006, TA0009  
**Domains:** endpoint, identity  
**Timeframe:** Last 7-30 days (configurable)

---

## Context

Based on [Microsoft Threat Intelligence blog (2026-04-07)](https://www.microsoft.com/en-us/security/blog/2026/04/07/soho-router-compromise-leads-to-dns-hijacking-and-adversary-in-the-middle-attacks/): Forest Blizzard (Russian military intelligence) and its sub-group Storm-2754 have been compromising vulnerable SOHO devices at scale since August 2025, modifying their DNS settings to redirect DNS traffic through actor-controlled infrastructure. Compromised routers push malicious DNS resolvers to connected Windows endpoints via DHCP, enabling passive DNS collection and selective TLS AiTM attacks against high-value targets (Microsoft Outlook on the web, government servers).

**Attack chain:**
1. SOHO router compromised → DNS settings modified (dnsmasq on port 53)
2. Connected endpoints receive malicious DNS via DHCP lease renewal
3. Actor passively collects DNS queries for reconnaissance
4. Selective AiTM against priority targets (spoofed TLS certificates for Microsoft 365 domains)

**Key detection surfaces in MDE telemetry:**
- `DeviceNetworkInfo.DnsAddresses` — Periodic snapshots of each device's configured DNS servers (the PRIMARY detection surface for DHCP-driven DNS hijacking)
- `DeviceNetworkEvents` — Port 53 outbound connections to unusual external resolvers
- `DeviceRegistryEvents` — DNS-related registry modifications (limited coverage for DHCP-driven changes)
- `DeviceProcessEvents` — Command-line DNS modification via netsh/PowerShell/wmic
- `EntraIdSignInEvents` — Post-compromise risky sign-ins from stolen credentials

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [DNS Configuration Drift — Baseline vs Recent](#query-1-dns-configuration-drift--baseline-vs-recent) | Dashboard | `DeviceNetworkInfo` |
| 2 | [Non-Corporate External DNS Resolver Detection](#query-2-non-corporate-external-dns-resolver-detection) | Detection | `DeviceNetworkInfo` |
| 3 | [DNS Server Change Timeline per Device](#query-3-dns-server-change-timeline-per-device) | Investigation | `DeviceNetworkInfo` |
| 4 | [Suspicious DNS (Port 53) Traffic to Non-Standard Resolvers](#query-4-suspicious-dns-port-53-traffic-to-non-standard-resolvers) | Investigation | `DeviceNetworkEvents` |
| 5 | [DNS-Modifying Process Detection](#query-5-dns-modifying-process-detection) | Detection | `DeviceProcessEvents` |
| 6 | [Fleet DNS Anomaly — Rare DNS Servers](#query-6-fleet-dns-anomaly--rare-dns-servers) | Detection | `DeviceNetworkInfo` |
| 7 | [DHCP-Assigned External DNS — The SOHO Router TTP](#query-7-dhcp-assigned-external-dns--the-soho-router-ttp) | Investigation | `DeviceNetworkInfo` |
| 8 | [Post-Compromise AiTM — High-Risk Sign-Ins](#query-8-post-compromise-aitm--high-risk-sign-ins) | Investigation | `EntraIdSignInEvents` |
| 9 | [Post-Compromise Mailbox Access — Search and MailItemsAccessed](#query-9-post-compromise-mailbox-access--search-and-mailitemsaccessed) | Investigation | `CloudAppEvents` |
| — | [How to Build Your Organizational DNS Baseline](#how-to-build-your-organizational-dns-baseline) | Dashboard | `DeviceNetworkInfo` |


## Queries

### Query 1: DNS Configuration Drift — Baseline vs Recent

**Purpose:** Detect devices whose DNS servers changed by comparing a 30-7d baseline against the most recent 7 days. This is the signature of a SOHO router compromise where the router's DHCP settings are modified to push actor-controlled DNS.  
**Severity:** Medium  
**MITRE:** T1584.002, T1557  
**Tuning Notes:** WSL2 NAT adapters (`172.x.x.1` pattern on virtual adapters) and VPN transitions (office ↔ home) will produce expected drift. Add `where not(NetworkAdapterName has "WSL")` and corporate-specific VPN adapter whitelists to reduce noise. Home workers changing Wi-Fi networks will show gateway DNS changes — correlate with the non-RFC1918 external DNS detections (Query 2/7) for higher-confidence findings.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Uses let blocks and join — complex baseline query not suitable for CD. Use as a hunting query."
-->

```kql
// DNS Configuration Drift — Baseline vs Recent per Device
// Detects devices whose DNS servers changed recently compared to their own 30d baseline
let BaselineWindow = DeviceNetworkInfo
    | where Timestamp between (ago(30d) .. ago(7d))
    | where isnotempty(DnsAddresses) and NetworkAdapterStatus == "Up"
    | mv-expand DnsAddress = parse_json(DnsAddresses)
    | extend DnsServer = tostring(DnsAddress)
    | where isnotempty(DnsServer) and DnsServer !startswith "fec0" and DnsServer != "::1"
    | summarize BaselineDnsServers = make_set(DnsServer) by DeviceId, DeviceName;
let RecentWindow = DeviceNetworkInfo
    | where Timestamp > ago(7d)
    | where isnotempty(DnsAddresses) and NetworkAdapterStatus == "Up"
    | mv-expand DnsAddress = parse_json(DnsAddresses)
    | extend DnsServer = tostring(DnsAddress)
    | where isnotempty(DnsServer) and DnsServer !startswith "fec0" and DnsServer != "::1"
    | summarize RecentDnsServers = make_set(DnsServer), LastSeen = max(Timestamp) by DeviceId, DeviceName;
RecentWindow
| join kind=inner BaselineWindow on DeviceId
| mv-expand RecentDns = RecentDnsServers
| extend RecentDnsStr = tostring(RecentDns)
| where not(set_has_element(BaselineDnsServers, RecentDnsStr))
| project LastSeen, DeviceName, NewDnsServer = RecentDnsStr, BaselineDnsServers, RecentDnsServers
| order by LastSeen desc
```

---

### Query 2: Non-Corporate External DNS Resolver Detection

**Purpose:** Flag devices configured with DNS servers that are external (non-RFC1918), not Azure Wire Server, and not well-known public DNS providers. In the Forest Blizzard campaign, compromised SOHO routers push actor-controlled external DNS IPs that don't match any well-known provider.  
**Severity:** High  
**MITRE:** T1584.002  
**Tuning Notes:** Add your organization's legitimate ISP DNS ranges and any corporate external resolvers to the exclusion list. IPv6 ISP DNS (e.g., `2001:558:feed::*` for Comcast, `2600:*` for various ISPs) should be evaluated per-environment. The query excludes well-known public DNS by IP — add public DoH/DoT provider IPs if relevant.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "Non-Corporate External DNS Resolver on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Verify the external DNS resolver IP is a legitimate ISP or corporate DNS. If unknown, check whether the device is connected through a SOHO router that may have been compromised. Reset DNS settings and investigate the router."
adaptation_notes: "Single table, mv-expand + summarize arg_max produces row-level output per device+DNS pair. Add DeviceId and ReportId in project."
-->

```kql
// Non-Corporate External DNS Resolver Detection
// Flag devices using DNS servers outside corporate/well-known ranges
DeviceNetworkInfo
| where Timestamp > ago(7d)
| where isnotempty(DnsAddresses) and NetworkAdapterStatus == "Up"
| mv-expand DnsAddress = parse_json(DnsAddresses)
| extend DnsServer = tostring(DnsAddress)
| where isnotempty(DnsServer)
    and DnsServer !startswith "127." 
    and DnsServer != "::1" 
    and DnsServer !startswith "fec0"
// Exclude well-known public DNS providers
| where DnsServer !in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", 
    "149.112.112.112", "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2")
// Exclude Azure Wire Server
| where DnsServer != "168.63.129.16"
// Flag non-RFC1918 (external) DNS servers — not internal, not well-known, not Azure
| where not(
    DnsServer startswith "10." or 
    DnsServer matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or 
    DnsServer startswith "192.168.")
// Exclude IPv6 link-local (router advertisements)
| where not(DnsServer startswith "fe80")
| summarize 
    arg_max(Timestamp, NetworkAdapterName, IPv4Dhcp),
    DeviceCount = dcount(DeviceName)
    by DeviceName, DeviceId, DnsServer
| project Timestamp, DeviceName, DeviceId, DnsServer, DhcpServer = IPv4Dhcp, 
    NetworkAdapterName, DeviceCount
| order by Timestamp desc
```

---

### Query 3: DNS Server Change Timeline per Device

**Purpose:** Track DNS configuration changes over time for each device — creates a chronological timeline of every DNS server change. Essential for incident response: shows exactly when a device's DNS was modified (e.g., when DHCP lease from compromised router took effect).  
**Severity:** Informational  
**MITRE:** T1584.002  
**Tuning Notes:** The `serialize` + `prev()` pattern detects any change in the full DNS config string. Filter out known adapter cycling (WSL, VPN reconnects) by adding adapter-name exclusions. Reduce time granularity from `1h` bins to `4h` or `1d` for longer lookbacks.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Uses serialize + prev() window function — not supported in custom detections. Hunting/IR query only."
-->

```kql
// DNS Server Change Timeline — Chronological DNS config changes per device
DeviceNetworkInfo
| where Timestamp > ago(14d)
| where isnotempty(DnsAddresses) and NetworkAdapterStatus == "Up"
| summarize arg_max(Timestamp, DnsAddresses, NetworkAdapterName, IPv4Dhcp) 
    by DeviceId, DeviceName, bin(Timestamp, 1h)
| extend DnsConfig = tostring(DnsAddresses)
| order by DeviceName asc, Timestamp asc
| serialize
| extend PrevDnsConfig = prev(DnsConfig), PrevDevice = prev(DeviceName)
| where DeviceName == PrevDevice and DnsConfig != PrevDnsConfig
| where isnotempty(PrevDnsConfig)
| project Timestamp, DeviceName, NewDns = DnsConfig, PreviousDns = PrevDnsConfig, 
    NetworkAdapterName, DhcpServer = IPv4Dhcp
| order by DeviceName asc, Timestamp asc
```

---

### Query 4: Suspicious DNS (Port 53) Traffic to Non-Standard Resolvers

**Purpose:** Detect devices sending DNS queries (port 53) to external IPs that are not well-known public DNS resolvers or internal infrastructure. Forest Blizzard's actor-controlled DNS servers listen on port 53 using dnsmasq.  
**Severity:** Medium  
**MITRE:** T1584.002, T1071.004  
**Tuning Notes:** DCs running `dns.exe` legitimately query root nameservers (192.48.79.30, 199.19.56.1, etc.) — exclude root hints or restrict to non-`dns.exe` processes. ISP DNS resolvers on remote worker devices will appear — add known ISP ranges or correlate with `DeviceNetworkInfo` to identify which DNS was DHCP-assigned vs manually configured.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "CommandAndControl"
title: "DNS Traffic to Uncommon External Resolver {{RemoteIP}} from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Investigate the external DNS resolver IP. Check if this is a known ISP resolver or a potentially actor-controlled DNS server. Correlate with DeviceNetworkInfo to determine if this was DHCP-assigned from a SOHO router."
adaptation_notes: "Remove summarize, convert to row-level output with DeviceId and ReportId. May need to inline well-known IP list."
-->

```kql
// Suspicious DNS (Port 53) to Non-Standard Resolvers
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 53
| where ActionType in ("ConnectionSuccess", "ConnectionFound")
// Exclude well-known public DNS
| where RemoteIP !in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", 
    "149.112.112.112", "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2")
// Exclude Azure Wire Server and loopback
| where RemoteIP != "168.63.129.16" and RemoteIP !startswith "127."
// Exclude internal DNS and root nameservers (DCs query root hints legitimately)
| where not(RemoteIP startswith "10." or 
    RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or 
    RemoteIP startswith "192.168.")
// Exclude DNS server processes querying root hints
| where InitiatingProcessFileName != "dns.exe"
| summarize 
    ConnectionCount = count(),
    DeviceCount = dcount(DeviceName),
    Devices = make_set(DeviceName, 20),
    Processes = make_set(InitiatingProcessFileName, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP
| order by DeviceCount desc, ConnectionCount desc
```

---

### Query 5: DNS-Modifying Process Detection

**Purpose:** Detect command-line execution of tools that modify DNS settings (netsh, PowerShell Set-DnsClientServerAddress, wmic, reg.exe). While the Forest Blizzard campaign modifies DNS via DHCP (router-level), an attacker with endpoint access could also force DNS changes via these tools.  
**Severity:** High  
**MITRE:** T1584.002, T1112  
**Tuning Notes:** Low noise in managed environments — DNS changes via CLI are unusual. Legitimate IT scripts (e.g., VPN connection scripts) may trigger this. Add process parent whitelists for known management tools. The `ipconfig /flushdns` pattern is excluded (cache flush, not a DNS server change).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "DNS Settings Modified via Command Line on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Review the command that modified DNS settings. Determine if this was a legitimate IT action or an attempt to redirect DNS traffic to an attacker-controlled server."
adaptation_notes: "Row-level output, single table. Remove flushdns exclusion comment, add DeviceId and ReportId."
-->

```kql
// DNS-Modifying Process Detection — CLI tools changing DNS settings
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("netsh.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "reg.exe")
| where ProcessCommandLine has_any ("DnsClientServerAddress", "DhcpNameServer", 
    "NameServer", "dnsservers")
    and ProcessCommandLine has_any ("set", "add", "change", "new")
// Exclude DNS cache flush (benign)
| where not(ProcessCommandLine has "flushdns")
| project Timestamp, DeviceName, DeviceId, FileName, ProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessCommandLine, 
    AccountName = InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```

---

### Query 6: Fleet DNS Anomaly — Rare DNS Servers

**Purpose:** Identify DNS servers that are used by very few devices in the fleet (≤2). In a SOHO DNS hijacking scenario, a compromised router only affects devices on that network segment — producing a DNS server seen by just 1-2 devices while the rest of the fleet uses corporate DNS.  
**Severity:** Medium  
**MITRE:** T1584.002  
**Tuning Notes:** Adjust the `DeviceCount <= 2` threshold based on fleet size. Larger fleets can increase to `<= 3`. Remote/home workers will have unique gateway DNS — correlate rare DNS servers with RFC1918 gateway addresses (192.168.x.1, 10.0.x.1) to identify home network DNS. The highest-priority findings are rare DNS servers that are ALSO external (non-RFC1918).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical fleet-wide aggregation — requires dcount across all devices. Hunting query only."
-->

```kql
// Fleet DNS Anomaly — Rare DNS Servers (used by ≤2 devices)
DeviceNetworkInfo
| where Timestamp > ago(7d)
| where isnotempty(DnsAddresses) and NetworkAdapterStatus == "Up"
| mv-expand DnsAddress = parse_json(DnsAddresses)
| extend DnsServer = tostring(DnsAddress)
| where isnotempty(DnsServer) and DnsServer != "::1" and DnsServer !startswith "fec0" 
    and DnsServer !startswith "127."
| summarize DeviceCount = dcount(DeviceName), 
    Devices = make_set(DeviceName, 20),
    Adapters = make_set(NetworkAdapterName, 10)
    by DnsServer
// Rare = used by very few devices
| where DeviceCount <= 2
// Exclude well-known public DNS
| where DnsServer !in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", 
    "149.112.112.112", "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2", 
    "168.63.129.16")
// Flag external vs internal
| extend IsExternal = not(
    DnsServer startswith "10." or 
    DnsServer matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or 
    DnsServer startswith "192.168.")
| order by IsExternal desc, DeviceCount asc
```

---

### Query 7: DHCP-Assigned External DNS — The SOHO Router TTP

**Purpose:** The highest-fidelity query for the Forest Blizzard TTP. Specifically detects DHCP-configured interfaces where the DHCP server assigned non-well-known external DNS resolvers. This is exactly what happens when a compromised SOHO router serves malicious DNS to connected endpoints.  
**Severity:** High  
**MITRE:** T1584.002, T1557  
**Tuning Notes:** This query requires the DHCP field (`IPv4Dhcp`) to be populated — only works for DHCP-configured IPv4 adapters. ISP DNS resolvers assigned by home ISP routers will appear (legitimate). Add known ISP DNS ranges per geography to reduce noise. The combination of DHCP server = typical home gateway (192.168.1.1) + unknown external DNS = strongest indicator.

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "DefenseEvasion"
title: "DHCP-Assigned External DNS Resolver on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "A DHCP server assigned a non-standard external DNS resolver to this device. Verify the DHCP server (likely a home/SOHO router) has not been compromised. Check the DNS resolver IP for threat intel. Reset DNS settings and investigate the router firmware."
adaptation_notes: "Single table, mv-expand + summarize arg_max produces row-level per device+DNS pair. Add DeviceId and ReportId."
-->

```kql
// DHCP-Assigned External DNS — The SOHO Router Compromise TTP
// Highest-fidelity query: detects DHCP-configured devices receiving unknown external DNS
DeviceNetworkInfo
| where Timestamp > ago(7d)
| where isnotempty(DnsAddresses) and NetworkAdapterStatus == "Up"
| where isnotempty(IPv4Dhcp) // Only DHCP-configured interfaces
| mv-expand DnsAddress = parse_json(DnsAddresses)
| extend DnsServer = tostring(DnsAddress)
| where isnotempty(DnsServer) and DnsServer != "::1" and DnsServer !startswith "fec0" 
    and DnsServer !startswith "127."
// Flag external (non-RFC1918, non-Azure) DNS
| where not(
    DnsServer startswith "10." or 
    DnsServer matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or 
    DnsServer startswith "192.168." or
    DnsServer == "168.63.129.16")
// Exclude well-known public DNS providers
| where DnsServer !in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", 
    "149.112.112.112", "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2")
// Exclude IPv6 link-local
| where not(DnsServer startswith "fe80")
| summarize 
    arg_max(Timestamp, NetworkAdapterName, IPv4Dhcp),
    Occurrences = count()
    by DeviceName, DeviceId, DnsServer
| project Timestamp, DeviceName, DeviceId, DnsServer, DhcpServer = IPv4Dhcp, 
    NetworkAdapterName, Occurrences
| order by Timestamp desc
```

---

### Query 8: Post-Compromise AiTM — High-Risk Sign-Ins

**Purpose:** Hunt for post-compromise activity after DNS hijacking enables AiTM. Forest Blizzard steals credentials via TLS AiTM then accesses cloud resources as a legitimate user. This query (adapted from the Microsoft blog) surfaces high-risk sign-ins that may indicate stolen credential use.  
**Severity:** High  
**MITRE:** T1557, T1078  
**Tuning Notes:** `RiskLevelDuringSignIn == 100` is the highest risk. ErrorCode 0 = successful sign-in, 50140 = "This occurred due to 'Keep me signed in' interrupt" (token refresh). Correlate with the DNS hijacking queries above — if a device had its DNS modified AND the user has high-risk sign-ins, prioritize investigation.

> **Note:** The Microsoft blog used `AADSignInEventsBeta` which is deprecated (Dec 2025). This query uses `EntraIdSignInEvents` (the replacement table). Ensure correct casing: capital `I` in `SignIn`.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "High-Risk Sign-In by {{AccountDisplayName}} from {{IPAddress}}"
impactedAssets:
  - type: user
    identifier: AccountDisplayName
recommendedActions: "Investigate the high-risk sign-in. Check if the user's device had DNS settings modified (SOHO router compromise). Verify the sign-in location and device. If credentials were stolen via AiTM, force password reset and revoke sessions."
adaptation_notes: "Single table, row-level output. Replace Timestamp column reference with proper AH format. Add ReportId."
-->

```kql
// Post-Compromise AiTM — High-Risk Sign-Ins (from Microsoft blog, adapted)
// Surfaces successful sign-ins with highest risk level (potential stolen credentials)
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where RiskLevelDuringSignIn == 100
| where ErrorCode == 0 or ErrorCode == 50140
| project Timestamp, Application, LogonType, AccountDisplayName, UserAgent, IPAddress, 
    ReportId
| order by Timestamp desc
```

---

### Query 9: Post-Compromise Mailbox Access — Search and MailItemsAccessed

**Purpose:** Detect post-compromise activity where an attacker (using stolen credentials from AiTM) searches mailboxes or accesses sensitive email items. Forest Blizzard targets Outlook on the web specifically.  
**Severity:** High  
**MITRE:** T1114.002, T1557  
**Tuning Notes:** Scope to specific suspicious user accounts (fill in `AccountObjectId`). Without scoping, this returns all search/mail access events across the organization. Cross-reference with Query 8 results to identify users with risky sign-ins.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Requires user-specific AccountObjectId scoping — not suitable as a fleet-wide CD without customization."
-->

```kql
// Post-Compromise Mailbox Access — Search and MailItemsAccessed
// Detect attacker searching/reading email after AiTM credential theft
CloudAppEvents
| where Timestamp > ago(14d)
// Uncomment and fill in suspicious account IDs from Query 8 results:
// | where AccountObjectId in ("<suspicious-user-objectid>")
| where ActionType has_any ("Search", "MailItemsAccessed")
| summarize 
    ActionCount = count(),
    Applications = make_set(Application, 10),
    IPs = make_set(IPAddress, 20)
    by AccountObjectId, AccountDisplayName, ActionType
| order by ActionCount desc
```

---

## DNS Server Baseline Reference

### How to Build Your Organizational DNS Baseline

Run this query to catalog all DNS servers in use across the fleet. Save the results and use them to customize the allowlists in the detection queries above.

```kql
// DNS Server Baseline — Catalog all DNS servers in use across the fleet
DeviceNetworkInfo
| where Timestamp > ago(30d)
| where isnotempty(DnsAddresses) and NetworkAdapterStatus == "Up"
| mv-expand DnsAddress = parse_json(DnsAddresses)
| extend DnsServer = tostring(DnsAddress)
| where isnotempty(DnsServer) and DnsServer != "::1" and DnsServer !startswith "fec0"
    and DnsServer !startswith "127."
| summarize 
    DeviceCount = dcount(DeviceName),
    Devices = make_set(DeviceName, 50),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Adapters = make_set(NetworkAdapterName, 20)
    by DnsServer
| extend IsExternal = not(
    DnsServer startswith "10." or 
    DnsServer matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\." or 
    DnsServer startswith "192.168." or
    DnsServer == "168.63.129.16")
| order by DeviceCount desc
```

### Common Legitimate DNS Patterns to Exclude

| DNS Server | Purpose | Notes |
|------------|---------|-------|
| `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` | Corporate/internal DNS | Add your org's specific IPs to allowlists |
| `168.63.129.16` | Azure Wire Server | Standard for Azure VMs — always exclude |
| `8.8.8.8`, `8.8.4.4` | Google Public DNS | Well-known, generally safe |
| `1.1.1.1`, `1.0.0.1` | Cloudflare DNS | Well-known, generally safe |
| `9.9.9.9`, `149.112.112.112` | Quad9 DNS | Threat-blocking resolver |
| `208.67.222.222`, `208.67.220.220` | OpenDNS (Cisco) | Well-known, generally safe |
| `4.2.2.1`, `4.2.2.2` | Level3/CenturyLink DNS | Legacy but common |
| `127.0.0.1`, `::1` | Loopback | DCs point to themselves |
| `172.x.x.1` (WSL adapters) | WSL2 NAT gateway | Hyper-V virtual networking |
| `fe80::*` | IPv6 link-local | Router advertisements |
| `fec0:0:0:ffff::*` | IPv6 site-local | Legacy, VPN fallback |

---

## Investigation Playbook

When any of the queries above return results:

1. **Triage** — Identify which devices show DNS anomalies
2. **Correlate** — Check if the same devices have high-risk sign-ins (Query 8)
3. **Enrich** — Run the suspicious DNS server IPs through threat intelligence (`enrich_ips.py`)
4. **Verify** — Check `DeviceNetworkInfo` DHCP server field to identify the upstream router
5. **Scope** — Determine if multiple devices share the same DHCP server (indicating router compromise vs single device)
6. **Remediate** — Reset DNS settings, investigate/replace compromised SOHO router, force password reset for affected users, revoke sessions
