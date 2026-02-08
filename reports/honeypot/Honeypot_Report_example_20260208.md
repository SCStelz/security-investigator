# Honeypot Security Analysis - CONTOSO-HONEY
**Analysis Period:** February 7, 2026 00:00 UTC to February 8, 2026 04:00 UTC (24 hours)  
**Report Generated:** February 8, 2026  
**Workspace:** la-contoso  
**Classification:** CONFIDENTIAL

---

## Executive Summary

Over the past 24 hours, the **CONTOSO-HONEY** honeypot (Windows Server 2019, Public IP: 203.0.113.50) attracted attack activity from **39 unique IP addresses** across three attack vectors: RDP brute force (SecurityEvent), web application scanning (W3CIISLog), and network reconnaissance (DeviceNetworkEvents). The honeypot generated **1 active HIGH-severity security incident** (#2426) involving Credential Access and Command & Control tactics, with 15 associated alerts currently in **New** status requiring triage.

Threat intelligence enrichment of the top 15 attacking IPs revealed a highly hostile landscape: **11 of 15 IPs (73%) are flagged with 100% abuse confidence** on AbuseIPDB, **11 of 15 (73%) match active Sentinel ThreatIntelIndicators**, and **9 of 15 (60%) are operating through VPN services** to obscure their origin. The most prolific attacker — **192.53.122.11** (Akamai/Linode, Toronto, CA) — launched 293 web reconnaissance requests in under 1 minute, probing for Nmap fingerprinting, VPN appliances (Pulse Secure, Cisco SDK), REST APIs, and healthcare applications.

The honeypot currently has **21 unpatched CVEs** (1 Critical, 4 High, 7 Medium, 9 Low) primarily affecting OpenSSL and .NET Core components. While this is by-design for a honeypot to attract attacker interest, the Critical OpenSSL vulnerability (CVE-2025-15467) warrants monitoring for active exploitation attempts. The honeypot continues to fulfill its mission of attracting and cataloging attacker TTPs, providing early warning indicators for the broader network.

**Key Metrics:**
| Metric | Value |
|--------|-------|
| **Total Attack Attempts** | 419+ (3 failed logons + 416 HTTP requests) |
| **Unique Attacking IPs** | 39 |
| **Security Incidents Triggered** | 1 (HIGH severity, 15 alerts) |
| **Known Malicious IPs (Threat Intel)** | 11/15 enriched (73%) |
| **VPN/Proxy Usage** | 9/15 enriched (60%) |
| **Current Vulnerabilities** | 1 CRITICAL, 4 HIGH, 7 MEDIUM, 9 LOW |

---

## 1. Attack Surface Analysis

### 1.1 Attack Vector Distribution

| Source | Unique IPs | Total Events | Primary Target |
|--------|-----------|--------------|----------------|
| **W3CIISLog** (HTTP) | 30 | 416 requests | Web services (ports 80/443) |
| **DeviceNetworkEvents** (RDP) | 11 | 11 connections | RDP (port 3389) |
| **SecurityEvent** (Auth) | 2 | 3 failed logons | Windows authentication |

### 1.2 Top Attackers by Volume

| Rank | IP Address | Country | Attack Type | Volume | Key Behavior |
|------|-----------|---------|-------------|--------|--------------|
| 🔴 1 | 192.53.122.11 | 🇨🇦 CA | Web scan + RDP | 293 HTTP + 1 RDP | Heavy scanner: Nmap, VPN appliance probes, SDK, REST APIs |
| 🔴 2 | 82.165.66.87 | 🇩🇪 DE | Web exploit | 44 HTTP | PHPUnit RCE exploit scanner (CVE-2017-9841) |
| 🔴 3 | 85.133.218.134 | 🇮🇷 IR | Web exploit | 44 HTTP | PHPUnit RCE exploit scanner (CVE-2017-9841) |
| 🟠 4 | 109.168.132.237 | 🇷🇺 RU | Web scan | 8 HTTP | Nmap, SDK, HNAP, evox probing |
| 🟠 5 | 65.49.1.10 | 🇺🇸 US | Web scan | 6 HTTP | SharePoint enumeration (_vti_pvt, _layouts, GeoServer) |
| 🟡 6 | 88.214.25.125 | 🇩🇪 DE | RDP brute force | 2 failed logons + 1 RDP | Attempted login as "Test" account |
| 🟡 7 | 35.216.144.195 | 🇨🇭 CH | RDP brute force | 1 failed logon + 1 RDP | Attempted login as "xmco" (abuse.xmco.com) |

### 1.3 Geographic Distribution

| Country | IPs | Percentage |
|---------|-----|------------|
| 🇩🇪 Germany | 4 | 27% |
| 🇷🇺 Russia | 3 | 20% |
| 🇺🇸 United States | 3 | 20% |
| 🇳🇱 Netherlands | 1 | 7% |
| 🇨🇦 Canada | 1 | 7% |
| 🇨🇭 Switzerland | 1 | 7% |
| 🇮🇷 Iran | 1 | 7% |
| 🇫🇷 France | 1 | 7% |

### 1.4 Targeted Services

| Service | Port | Connections | Attack Pattern |
|---------|------|-------------|----------------|
| **IIS Web Server** | 80/443 | 416 requests | Web scanning, exploit probing, path traversal |
| **RDP** | 3389 | 11 connections | Inbound TCP connections from external IPs |
| **Windows Auth** | N/A | 3 failed logons | Credential brute force (EventID 4625) |

---

## 2. Threat Intelligence Correlation

### 2.1 Sentinel ThreatIntelIndicators Matches

**11 of 15 enriched IPs matched active threat intelligence indicators** — all with Confidence 100% (except 192.53.122.11 at 64%).

| IP Address | TI Source | Description | Confidence |
|-----------|-----------|-------------|------------|
| 🔴 95.215.0.144 | MSTIC HoneyPot | Brute force attack to gain access | 100% |
| 🔴 193.142.147.209 | MSTIC HoneyPot | Brute force attack to gain access | 100% |
| 🔴 65.49.1.10 | AbuseIPDB Feed | Shadowserver Foundation scanner, 1,150 reports | 100% |
| 🔴 45.91.64.6 | AbuseIPDB Feed | F6 (RU), 3,445 reports | 100% |
| 🔴 176.32.195.85 | AbuseIPDB Feed | Interactive TV LLC (AM), 3,490 reports | 100% |
| 🔴 45.135.193.11 | AbuseIPDB Feed | Pfcloud UG (DE), 1,228 reports | 100% |
| 🔴 82.165.66.87 | MSTIC HoneyPot | Brute force attack to gain access | 100% |
| 🔴 147.185.132.81 | MSTIC HoneyPot | Brute force attack to gain access | 100% |
| 🔴 35.216.144.195 | AbuseIPDB Feed | Google LLC (CH), 801 reports | 100% |
| 🔴 88.214.25.125 | AbuseIPDB Feed | VDS&VPN services (DE), 838 reports | 100% |
| 🟠 192.53.122.11 | AbuseIPDB Feed | Linode (CA), 23 reports | 64% |

### 2.2 AbuseIPDB Summary

| Risk Level | Count | IPs |
|------------|-------|-----|
| 🔴 **High (>75% confidence)** | 11 | 176.32.195.85, 193.142.147.209, 95.215.0.144, 45.91.64.6, 82.165.66.87, 85.133.218.134, 88.214.25.125, 91.238.181.92, 45.135.193.11, 35.216.144.195, 65.49.1.10 |
| 🟠 **Medium (25-75%)** | 1 | 192.53.122.11 (64%) |
| 🟡 **Low (<25%)** | 2 | 104.131.88.102 (5%), 109.168.132.237 (3%) |
| ⚪ **Whitelisted** | 1 | 147.185.132.81 (0%, but 5,414 reports) |

**Most Reported IPs (by community report count):**
1. 🔴 193.142.147.209 — **30,555 reports** (Amsterdam, NL — ColocaTel Inc.)
2. 🔴 176.32.195.85 — **9,905 reports** (Yerevan, AM — Ucom CJSC)
3. 🔴 147.185.132.81 — **5,414 reports** (Moncks Corner, US — Google LLC)
4. 🔴 45.91.64.6 — **5,182 reports** (Moscow, RU — JSC Buduschee)
5. 🔴 95.215.0.144 — **4,555 reports** (Saint Petersburg, RU — Petersburg Internet Network)

### 2.3 VPN/Proxy/Anonymization

| Type | Count | IPs |
|------|-------|-----|
| **VPN** | 9 | 192.53.122.11, 82.165.66.87, 193.142.147.209, 35.216.144.195, 104.131.88.102, 95.215.0.144, 45.135.193.11, 65.49.1.10, 147.185.132.81 |
| **Proxy** | 1 | 65.49.1.10 |
| **Tor** | 0 | — |

### 2.4 Shodan Intelligence

| Tag | Count | Implication |
|-----|-------|-------------|
| **scanner** | 4 | 193.142.147.209, 147.185.132.81, 45.91.64.6, 95.215.0.144 — Known internet-wide scanners |
| **cloud** | 2 | 192.53.122.11 (Linode), 35.216.144.195 (Google Cloud) — Cloud-hosted attack infrastructure |

**Notable findings:**
- 🔴 193.142.147.209 has port 9999 running a TP-Link Kasa module serving an **ELF executable** — possible C2 or botnet infrastructure
- 91.238.181.92 exposes Microsoft RPC (port 135) and NetBIOS (port 139) — likely a compromised Windows host
- 65.49.1.10 hostname: **scan-52a.shadowserver.org** — known security research scanner

---

## 3. Security Incidents

### Active Incident

| Field | Value |
|-------|-------|
| 🔴 **Incident ID** | #2426 |
| **Title** | Multi-stage incident involving Credential access & Command and control on one endpoint |
| **Severity** | 🔴 HIGH |
| **Status** | ⚠️ New (unresolved) |
| **Classification** | Not yet classified |
| **Created** | 2026-02-07 21:20:32 UTC |
| **Last Modified** | 2026-02-08 03:26:02 UTC |
| **Alert Count** | 15 |
| **MITRE Tactics** | Credential Access (TA0006), Command and Control (TA0011) |
| **Portal Link** | [View in Microsoft 365 Defender](https://security.microsoft.com/incident2/2426/overview?tid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) |

⚠️ **Action Required:** This incident is in **New** status with HIGH severity and 15 alerts. The combination of Credential Access and Command & Control tactics indicates potential attacker success beyond initial reconnaissance. Immediate triage is recommended.

---

## 4. Attack Pattern Analysis

### 4.1 Web Application Scanning (W3CIISLog)

**PHPUnit RCE Exploitation (CVE-2017-9841):**
- 🔴 **82.165.66.87** and **85.133.218.134** both probed 44 URLs targeting `phpunit/src/Util/PHP/eval-stdin.php` — a well-known remote code execution vulnerability
- Multiple path variations attempted: `/vendor/phpunit/`, `/phpunit/`, `/vendor/vendor/phpunit/`
- All requests returned HTTP 401 (authentication required — blocked by IIS)

**Infrastructure Discovery (192.53.122.11 — 293 requests in <1 minute):**
- Nmap service fingerprinting (`/nmaplowercheck1770504995`)
- VPN appliance probing: Pulse Secure (`/dana-cached/hc/HostCheckerInstaller.osx`)
- VMware/vSphere: `/sdk`
- REST API discovery: `/rest/applinks/1.0/manifest` (Atlassian)
- IoT/Router: `/cgi-mod/header_logo.cgi`
- Healthcare: `/human.aspx`
- Webmin: `/webui`
- Health checks: `/health`

**SharePoint/Microsoft Enumeration (65.49.1.10):**
- `/_vti_pvt/service.cnf` — SharePoint version detection
- `/_layouts/15/debug_dev.js` — SharePoint debug mode check
- `/_layouts/15/spinstall1.aspx` / `spinstall0.aspx` — SharePoint installation pages
- `/geoserver/web/` — GeoServer web console

**Other Notable Probes:**
- `/SDK/webLanguage` — Hikvision DVR/NVR exploitation
- `/setup.cgi` — Router/IoT configuration
- `/evox/about` — EvoX game server
- `/HNAP1` — Home Network Administration Protocol
- `/developmentserver/metadatauploader` — SAP metadata upload
- `/dispatch.asp` — Legacy web application

### 4.2 RDP Brute Force (SecurityEvent + DeviceNetworkEvents)

| Attacker IP | Country | Failed Logons | Target Account | RDP Connection |
|------------|---------|---------------|----------------|----------------|
| 88.214.25.125 | 🇩🇪 DE | 2 | `\Test` | ✅ Yes |
| 35.216.144.195 | 🇨🇭 CH | 1 | `abuse.xmco.com\xmco` | ✅ Yes |

- **11 unique IPs** established inbound RDP connections (TCP 3389)
- All connections from external, non-RFC1918 addresses
- The `abuse.xmco.com\xmco` account suggests automated scanning by a security research firm (XMCO)

### 4.3 MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| **Reconnaissance (TA0043)** | T1595.002 - Active Scanning: Vulnerability Scanning | Nmap fingerprinting, PHPUnit probing, SharePoint enumeration |
| **Initial Access (TA0001)** | T1190 - Exploit Public-Facing Application | PHPUnit RCE attempts, Hikvision SDK probe, GeoServer access |
| **Initial Access (TA0001)** | T1133 - External Remote Services | 11 inbound RDP connections |
| **Credential Access (TA0006)** | T1110.001 - Brute Force: Password Guessing | 3 failed logon attempts (EventID 4625) |
| **Command and Control (TA0011)** | — | Indicated by Incident #2426 alerts |

---

## 5. Honeypot Vulnerability Status

### 5.1 CVE Inventory Summary

| Severity | Count | Affected Software |
|----------|-------|-------------------|
| 🔴 **Critical** | 1 | OpenSSL |
| 🟠 **High** | 4 | .NET Core (3), OpenSSL (1) |
| 🟡 **Medium** | 7 | .NET Core (3), OpenSSL (4) |
| 🔵 **Low** | 9 | OpenSSL (9) |
| **Total** | **21** | |

### 5.2 Critical & High Vulnerabilities

| CVE ID | Severity | Software | Vendor |
|--------|----------|----------|--------|
| 🔴 CVE-2025-15467 | Critical | OpenSSL | OpenSSL |
| 🟠 CVE-2025-9230 | High | OpenSSL | OpenSSL |
| 🟠 CVE-2018-8356 | High | .NET Core | Microsoft |
| 🟠 CVE-2018-0765 | High | .NET Core | Microsoft |
| 🟠 CVE-2017-11770 | High | .NET Core | Microsoft |

### 5.3 Exploitation Risk Assessment

- ⚠️ **CVE-2025-15467 (OpenSSL, Critical)**: Monitor for active exploitation. OpenSSL vulnerabilities are commonly targeted in internet-facing services.
- 🔵 **Legacy .NET Core CVEs (2017-2018)**: These are older vulnerabilities with known patches. Their presence is consistent with honeypot design to attract older exploit toolkits.
- ✅ **No exploit availability flags** were set on any CVE (CveTags empty), reducing the immediate risk of automated exploitation.
- ✅ **0 CVEs found by Shodan** across attacker infrastructure — attackers are not exposing known-vulnerable services themselves.

---

## 6. Key Detection Insights

### 6.1 Automated Scanning Patterns
- 🔴 **192.53.122.11** executed 293 requests in under 1 minute — clearly automated, scanning a broad catalog of web application fingerprints
- 🔴 **82.165.66.87** and **85.133.218.134** used identical PHPUnit attack patterns (same URL list) — likely the same threat actor or shared exploit toolkit
- 🟠 **193.142.147.209** operates Shodan-tagged scanner infrastructure with a suspicious ELF binary served on port 9999

### 6.2 Notable Threat Actors & Infrastructure
- **65.49.1.10** — Shadowserver Foundation scanner (scan-52a.shadowserver.org). This is a known **security research organization** that performs internet-wide scanning. Low threat, informational value.
- **35.216.144.195** — Google Cloud IP used from Zürich, flagged as VPN, with 2,019 abuse reports. Likely compromised or purpose-built cloud infrastructure for scanning.
- **147.185.132.81** — Google LLC IP, whitelisted on AbuseIPDB despite 5,414 reports. Tagged as scanner on Shodan. Likely automated research or compromised cloud instance.

### 6.3 Novel Indicators
- 🔴 **193.142.147.209** serving ELF executable on port 9999 via TP-Link Kasa module — warrants investigation as potential botnet/C2 infrastructure
- 🟠 Account name `abuse.xmco.com\xmco` used in RDP brute force — XMCO is a French cybersecurity firm; this may be their own scanning infrastructure or spoofed by attackers
- 🔴 Incident #2426 C2 detection suggests at least one attacker may have achieved post-exploitation connectivity

---

## 7. Honeypot Effectiveness

### 7.1 Detection Metrics

| Metric | Value | Assessment |
|--------|-------|------------|
| Unique attackers detected | 39 | ✅ Strong attraction |
| Threat intel match rate | 73% (11/15 enriched) | ✅ Excellent coverage |
| Incident generation | 1 HIGH incident, 15 alerts | ✅ Alert pipeline working |
| Attack vector diversity | 3 vectors (HTTP, RDP, Auth) | ✅ Multi-service coverage |
| Geographic diversity | 8+ countries | ✅ Global threat visibility |
| VPN usage detection | 60% (9/15) | ✅ Anonymization tracking effective |

### 7.2 Recommendations

| Priority | Recommendation | Rationale |
|----------|---------------|-----------|
| ⚠️ **Immediate** | Triage Incident #2426 | HIGH severity, 15 alerts, C2 + CredentialAccess tactics — currently unresolved |
| ⚠️ **Immediate** | Block 193.142.147.209 at perimeter | 30,555 abuse reports, scanner tag, ELF binary on port 9999, active brute force globally |
| 🟠 **Short-term** | Review OpenSSL CVE-2025-15467 (Critical) | Evaluate whether this vulnerability is being actively targeted by web scanners |
| 🟠 **Short-term** | Add PHPUnit URL patterns to IDS signatures | Two IPs (82.165.66.87, 85.133.218.134) attempted CVE-2017-9841 exploitation |
| 🔵 **Ongoing** | Continue monitoring RDP brute force patterns | 11 unique IPs attempted RDP connections — consider rate-limiting or alerting on threshold |
| 🔵 **Ongoing** | Feed IoCs to TI platform | All 11 high-confidence IPs should be propagated to network-wide blocking |

---

## 8. Conclusion

The **CONTOSO-HONEY** honeypot continues to effectively attract and catalog attack activity from diverse global sources. In the past 24 hours, it recorded 39 unique attacking IPs with a 73% match rate against active threat intelligence, demonstrating strong visibility into the current threat landscape.

**Key Takeaways:**
1. 🔴 **Incident #2426 requires immediate attention** — HIGH severity with C2 and Credential Access tactics, 15 unresolved alerts
2. 🔴 **Web scanning dominates** — 416 HTTP requests from 30 IPs, with PHPUnit RCE (CVE-2017-9841) and broad infrastructure fingerprinting as the primary attack patterns
3. 🟠 **RDP remains under active targeting** — 11 external IPs attempted inbound RDP connections, consistent with ongoing global RDP brute force campaigns
4. 🟢 **Threat intelligence enrichment is effective** — 73% of top attackers already flagged in Sentinel TI, with 60% using VPN services for anonymization
5. 🔵 **Vulnerability posture is by-design** — 21 CVEs (1 Critical) serve the honeypot's purpose of appearing vulnerable, but the Critical OpenSSL CVE warrants monitoring

---

**Investigation Timeline:**

| Phase | Duration | Details |
|-------|----------|---------|
| Phase 1: Failed connection queries | ~30s | SecurityEvent, W3CIISLog, DeviceNetworkEvents (parallel) |
| Phase 2: IP enrichment + threat intel | ~60s | 15 IPs enriched + Sentinel TI query (parallel) |
| Phase 3: Security incidents | ~15s | DeviceInfo lookup + SecurityAlert/SecurityIncident join |
| Phase 4: Vulnerability assessment | ~15s | Advanced Hunting DeviceTvmSoftwareVulnerabilities |
| Phase 5: Report generation | ~30s | Executive markdown report |
| **Total Investigation Time** | **~2.5 minutes** | |

---

*Report generated by Security Investigation Agent — Honeypot Investigation Skill v2.0*
