#!/usr/bin/env python3
"""Generate fresh synthetic data for sentinel-ingestion-report enterprise demo.

Produces 23 JSON query files + meta.json in the enterprise/ subfolder.
Designed for a ~200 GB/day enterprise workspace with realistic data that
exercises all 20 PRERENDERED blocks and key report recommendations.

Usage:
    python generate_enterprise_data.py              # default: 30 days
    python generate_enterprise_data.py --days 7      # 7-day window
    python generate_enterprise_data.py --days 90     # 90-day window
"""

import argparse
import json
import os
import random
import math
from datetime import datetime, timedelta

random.seed(42)  # Reproducible output

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enterprise")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
WORKSPACE_NAME = "la-contoso-prod"
WORKSPACE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

# ═══════════════════════════════════════════════════════════════════════════
# MASTER TABLE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════
# Each table: (name, billable_gb_30d, non_billable_gb_30d, solution, tier, dl_eligible)
# tier: "Analytics" | "Basic" | "Auxiliary" (DL)
# dl_eligible: from PS1 dlYes/dlNo lists + patterns
# fmt: (name, billableGB, nonBillableGB, solution, plan, in_q1_top20)

TABLES = [
    # ── Top 20 by Billable Volume (Q1) ──────────────────────────────
    ("CommonSecurityLog",                 1250.0,  0.0, "LogManagement",   "Analytics", True),  # Firewall traffic — typically #1
    ("Syslog",                             920.0,  0.0, "LogManagement",   "Analytics", True),  # Firewalls + Linux via syslog
    ("SecurityEvent",                      680.0,  0.0, "Security",        "Analytics", True),
    ("SigninLogs",                         520.0,  0.0, "LogManagement",   "Analytics", True),
    ("AADNonInteractiveUserSignInLogs",    390.0,  0.0, "LogManagement",   "Analytics", True),
    ("DeviceProcessEvents",                285.0,  0.0, "LogManagement",   "Analytics", True),
    ("AzureActivity",                      250.0,  0.0, "LogManagement",   "Analytics", True),
    ("DeviceNetworkEvents",                235.0,  0.0, "LogManagement",   "Analytics", True),
    ("AuditLogs",                          195.0,  0.0, "LogManagement",   "Analytics", True),
    ("DeviceFileEvents",                   170.0,  0.0, "LogManagement",   "Analytics", True),
    ("OfficeActivity",                     145.0,  0.0, "LogManagement",   "Analytics", True),
    ("AWSCloudTrail",                      130.0,  0.0, "LogManagement",   "Auxiliary", True),  # Already on DL
    ("CloudAppEvents",                     108.0,  0.0, "LogManagement",   "Analytics", True),
    ("DeviceEvents",                        95.0,  0.0, "LogManagement",   "Analytics", True),
    ("StorageBlobLogs",                     78.0,  0.0, "LogManagement",   "Analytics", True),  # DL candidate (0 rules)
    ("AzureDiagnostics",                    65.0,  0.0, "LogManagement",   "Basic",     True),
    ("EmailEvents",                         58.0,  0.0, "LogManagement",   "Analytics", True),
    ("DeviceRegistryEvents",                48.0,  0.0, "LogManagement",   "Analytics", True),
    ("AADManagedIdentitySignInLogs",         38.0,  0.0, "LogManagement",   "Analytics", True),  # DL candidate (0 rules)
    ("DeviceLogonEvents",                   32.0,  0.0, "LogManagement",   "Analytics", True),
    # ── Medium tables (not in Q1 top 20) ────────────────────────────
    ("SecurityAlert",                       28.0,  0.0, "Security",        "Analytics", False),
    ("AADServicePrincipalSignInLogs",        22.0,  0.0, "LogManagement",   "Analytics", False),
    ("IdentityLogonEvents",                 18.0,  0.0, "LogManagement",   "Analytics", False),
    ("DeviceInfo",                          16.0,  0.0, "LogManagement",   "Analytics", False),
    ("SecurityIncident",                    14.0,  0.0, "Security",        "Analytics", False),
    ("EmailAttachmentInfo",                 12.0,  0.0, "LogManagement",   "Analytics", False),
    ("DeviceNetworkInfo",                   11.0,  0.0, "LogManagement",   "Analytics", False),
    ("EmailUrlInfo",                        10.0,  0.0, "LogManagement",   "Analytics", False),
    ("IdentityQueryEvents",                  9.5,  0.0, "LogManagement",   "Analytics", False),
    ("IdentityDirectoryEvents",              8.5,  0.0, "LogManagement",   "Analytics", False),
    ("DeviceImageLoadEvents",                8.0,  0.0, "LogManagement",   "Analytics", False),
    ("AlertEvidence",                        7.5,  0.0, "LogManagement",   "Analytics", False),
    ("AlertInfo",                            6.0,  0.0, "LogManagement",   "Analytics", False),
    ("AADProvisioningLogs",                  5.5,  0.0, "LogManagement",   "Analytics", False),
    ("DeviceFileCertificateInfo",            5.0,  0.0, "LogManagement",   "Analytics", False),
    ("EmailPostDeliveryEvents",              4.5,  0.0, "LogManagement",   "Analytics", False),
    ("MicrosoftGraphActivityLogs",           4.0,  0.0, "LogManagement",   "Analytics", False),
    ("UrlClickEvents",                       3.8,  0.0, "LogManagement",   "Analytics", False),
    ("LAQueryLogs",                          3.5,  0.0, "LogManagement",   "Analytics", False),
    ("ThreatIntelligenceIndicator",          3.0,  0.0, "Security",        "Analytics", False),
    ("SentinelHealth",                       2.8,  0.0, "LogManagement",   "Analytics", False),
    ("ConfigurationChange",                  2.5,  0.0, "LogManagement",   "Analytics", False),
    ("AADUserRiskEvents",                    2.2,  0.0, "LogManagement",   "Analytics", False),
    ("GCPAuditLogs",                         2.0,  0.0, "LogManagement",   "Analytics", False),
    ("WindowsFirewall",                      1.8,  0.0, "LogManagement",   "Analytics", False),
    ("W3CIISLog",                            1.5,  0.0, "LogManagement",   "Analytics", False),
    # ── Data Lake custom tables ─────────────────────────────────────
    ("SecurityEvent_Aux_CL",                15.0,  0.0, "LogManagement",   "Auxiliary", False),
    ("SecurityEvent_SPLT_CL",                8.0,  0.0, "LogManagement",   "Auxiliary", False),
    # ── KQL Job outputs ─────────────────────────────────────────────
    ("Signinlogs_Anomalies_KQL_CL",          2.0,  0.0, "LogManagement",   "Auxiliary", False),
    # ── Application Insights tables (non-security telemetry) ────────
    ("AppTraces",                            45.0,  0.0, "LogManagement",   "Analytics", False),  # Zero rules → DL candidate + non-security routing
    ("AppDependencies",                      22.0,  0.0, "LogManagement",   "Analytics", False),  # Zero rules → DL candidate + non-security routing
    ("AppPerformanceCounters",               10.0,  0.0, "LogManagement",   "Analytics", False),  # Zero rules → non-security routing
    ("AppRequests",                           8.0,  0.0, "LogManagement",   "Analytics", False),  # Zero rules → non-security routing
    # ── Small tables ────────────────────────────────────────────────
    ("McasShadowItReporting",                1.2,  0.0, "LogManagement",   "Analytics", False),
    ("ADFSSignInLogs",                       1.0,  0.0, "LogManagement",   "Analytics", False),
    ("DynamicEventCollection",               0.8,  0.0, "LogManagement",   "Analytics", False),
    ("WindowsEvent",                         0.5,  0.0, "LogManagement",   "Analytics", False),
    ("SecurityRecommendation",               0.4,  0.0, "Security",        "Analytics", False),
    ("Perf",                                18.0,  0.0, "LogManagement",   "Analytics", False),  # Performance counters — non-security telemetry routing candidate
    ("Event",                                0.2,  0.0, "LogManagement",   "Analytics", False),
    ("ContainerLogV2",                       0.15, 0.0, "LogManagement",   "Analytics", False),
    # ── Non-billable tables ─────────────────────────────────────────
    ("Heartbeat",                            0.0, 280.0, "LogManagement",  "Analytics", False),
    ("AzureMetrics",                         0.0, 120.0, "LogManagement",  "Analytics", False),
    ("Usage",                                0.0,  55.0, "LogManagement",  "Analytics", False),
    ("Operation",                            0.0,  12.0, "LogManagement",  "Analytics", False),
]

# Compute totals — base reference values for 30-day window (used inside generate_all with scale factors)
BASE_30D_BILLABLE = sum(t[1] for t in TABLES)
BASE_30D_NON_BILLABLE = sum(t[2] for t in TABLES)
BILLABLE_TABLE_COUNT = sum(1 for t in TABLES if t[1] > 0)
TOTAL_TABLE_COUNT = len(TABLES)

# ═══════════════════════════════════════════════════════════════════════════
# ANALYTIC RULES — Generate realistic rules referencing workspace tables
# ═══════════════════════════════════════════════════════════════════════════
# Rules grouped by primary table they query. Format: (displayName, kind, tables_referenced)
RULE_TEMPLATES = [
    # SecurityEvent rules (~45)
    ("Multiple failed logon attempts", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4625"),
    ("Brute force attack against user", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4625 | summarize count() by Account"),
    ("Account lockout detected", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4740"),
    ("User account created", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4720"),
    ("User account deleted", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4726"),
    ("User account enabled", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4722"),
    ("User account disabled", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4725"),
    ("Password reset attempt detected", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID in (4723, 4724)"),
    ("Kerberos TGT request anomaly", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4768"),
    ("Kerberos service ticket anomaly", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4769"),
    ("NTLM authentication detected", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4776"),
    ("Golden ticket activity detected", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4769 | where TicketEncryptionType == '0x17'"),
    ("Logon with explicit credentials", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4648"),
    ("Special privileges assigned to new logon", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4672"),
    ("New process created - suspicious", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4688"),
    ("Audit log cleared", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 1102"),
    ("Scheduled task created on DC", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4698"),
    ("Domain trust created", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4706"),
    ("Group membership change - global", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID in (4728, 4729)"),
    ("Group membership change - local", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID in (4732, 4733)"),
    ("Group membership change - universal", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4756"),
    ("Computer account created", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4741"),
    ("Computer account changed", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4742"),
    ("Kerberos pre-auth failure", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4771"),
    ("Firewall rule changed", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID in (4946, 4947, 4948)"),
    ("Network share accessed", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 5140"),
    ("Object access attempt", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4663"),
    ("Audit policy changed", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4719"),
    ("Token right adjustment", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4703"),
    ("Workstation locked/unlocked anomaly", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID in (4800, 4801)"),
    ("WFP connection blocked", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 5157"),
    ("Credential Manager read", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 5379"),
    ("External device recognized", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 6416"),
    ("Handle to sensitive object", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4656"),
    ("Multiple password resets by user", "Scheduled", ["SecurityEvent", "AuditLogs"], "SecurityEvent | where EventID in (4723, 4724)\nAuditLogs | where OperationName has 'password'"),
    ("Successful logon from rare IP", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4624"),
    ("Possible pass-the-hash activity", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4624 | where LogonType == 3"),
    ("Possible pass-the-ticket activity", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4768"),
    ("Privileged service called", "NRT", ["SecurityEvent"], "SecurityEvent | where EventID == 4673"),
    ("Security group enumeration", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID in (4798, 4799)"),
    ("User right assigned", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4704"),
    ("Kerberos policy changed", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4713"),
    ("Event logging shut down", "NRT", ["SecurityEvent"], "SecurityEvent | where EventID == 1100"),
    ("Permissions on object changed", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4670"),
    ("Boot Configuration Data loaded", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4826"),
    # SigninLogs rules (~35)
    ("Sign-in from unknown IP", "Scheduled", ["SigninLogs"], "SigninLogs | where ResultType == 0"),
    ("Multiple failed sign-ins single user", "Scheduled", ["SigninLogs"], "SigninLogs | where ResultType != 0"),
    ("Sign-in from blocked country", "Scheduled", ["SigninLogs"], "SigninLogs | where LocationDetails has 'CN'"),
    ("MFA fatigue attack detection", "Scheduled", ["SigninLogs"], "SigninLogs | where ResultType == 50074"),
    ("Impossible travel detection", "Scheduled", ["SigninLogs"], "SigninLogs | where RiskLevelDuringSignIn != 'none'"),
    ("Legacy authentication attempt", "Scheduled", ["SigninLogs"], "SigninLogs | where ClientAppUsed !in ('Browser', 'Mobile Apps and Desktop clients')"),
    ("Sign-in from anonymous IP", "Scheduled", ["SigninLogs"], "SigninLogs | where RiskLevelDuringSignIn == 'high'"),
    ("Risky sign-in followed by MFA change", "Scheduled", ["SigninLogs", "AuditLogs"], "SigninLogs | where RiskLevelDuringSignIn != 'none'\nAuditLogs | where OperationName has 'MFA'"),
    ("Token replay attack detection", "NRT", ["SigninLogs"], "SigninLogs | where TokenIssuerType == 'AzureAD'"),
    ("Conditional Access policy bypass", "Scheduled", ["SigninLogs"], "SigninLogs | where ConditionalAccessStatus == 'notApplied'"),
    ("Sign-in from Tor exit node", "Scheduled", ["SigninLogs"], "SigninLogs | where IPAddress has '185.'"),
    ("AiTM phishing session detected", "NRT", ["SigninLogs"], "SigninLogs | where SessionId != ''"),
    ("Password spray attack detection", "Scheduled", ["SigninLogs"], "SigninLogs | where ResultType == 50126"),
    ("Suspicious consent grant", "Scheduled", ["SigninLogs", "AuditLogs"], "SigninLogs\nAuditLogs | where OperationName == 'Consent to application'"),
    ("Sign-in from unfamiliar location", "Scheduled", ["SigninLogs"], "SigninLogs | where RiskState == 'atRisk'"),
    ("Successful sign-in after multiple failures", "Scheduled", ["SigninLogs"], "SigninLogs | where ResultType == 0 | join kind=inner (SigninLogs | where ResultType != 0)"),
    ("Sign-in from breached credential", "Scheduled", ["SigninLogs"], "SigninLogs | where RiskDetail has 'leaked'"),
    ("Guest user sign-in anomaly", "Scheduled", ["SigninLogs"], "SigninLogs | where UserType == 'Guest'"),
    ("Service principal sign-in failure spike", "Scheduled", ["AADServicePrincipalSignInLogs"], "AADServicePrincipalSignInLogs | where ResultType != 0"),
    ("Managed identity anomalous sign-in", "Scheduled", ["AADNonInteractiveUserSignInLogs"], "AADNonInteractiveUserSignInLogs | where ResultType != 0"),
    ("Non-interactive sign-in from new IP", "Scheduled", ["AADNonInteractiveUserSignInLogs"], "AADNonInteractiveUserSignInLogs | where IPAddress != ''"),
    ("Non-interactive sign-in burst", "Scheduled", ["AADNonInteractiveUserSignInLogs"], "AADNonInteractiveUserSignInLogs | summarize count() by AppDisplayName"),
    ("First access credential added", "NRT", ["AuditLogs"], "AuditLogs | where OperationName has 'credential'"),
    ("Sign-in risk policy triggered", "Scheduled", ["SigninLogs"], "SigninLogs | where RiskLevelDuringSignIn in ('medium', 'high')"),
    ("Cross-tenant sign-in detected", "Scheduled", ["SigninLogs"], "SigninLogs | where HomeTenantId != ResourceTenantId"),
    ("Suspicious application consent", "Scheduled", ["SigninLogs"], "SigninLogs | where ResourceDisplayName has 'Graph'"),
    ("Privileged role sign-in from new device", "Scheduled", ["SigninLogs", "AuditLogs"], "SigninLogs\nAuditLogs | where OperationName has 'role'"),
    ("Excessive failed interactive sign-ins", "Scheduled", ["SigninLogs"], "SigninLogs | where ResultType != 0 | where IsInteractive == true"),
    ("Unusual token lifetime detected", "Scheduled", ["SigninLogs"], "SigninLogs | where TokenIssuerType != ''"),
    ("Sign-in from VPN exit node", "Scheduled", ["SigninLogs"], "SigninLogs | where NetworkLocationDetails has 'vpn'"),
    ("Multi-geo sign-in within short window", "Scheduled", ["SigninLogs"], "SigninLogs | where Location != '' | summarize dcount(Location) by UserPrincipalName"),
    # AuditLogs rules (~30)
    ("Application credential added", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'credential'"),
    ("Application permission granted", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName == 'Add app role assignment to service principal'"),
    ("Conditional Access policy modified", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'conditional access'"),
    ("User assigned to privileged role", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'role'"),
    ("MFA method registration change", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'authentication method'"),
    ("Privileged role activation via PIM", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'PIM'"),
    ("Application ownership change", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'owner'"),
    ("Bulk user creation detected", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName == 'Add user'"),
    ("Cross-tenant access settings changed", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'cross-tenant'"),
    ("External identity provider added", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'identity provider'"),
    ("Application consent granted - risky", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName == 'Consent to application' | where tostring(TargetResources) has 'Mail.Read'"),
    ("Custom domain added to tenant", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'domain'"),
    ("Directory role member added", "NRT", ["AuditLogs"], "AuditLogs | where OperationName has 'Add member to role'"),
    ("Self-service password reset completed", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'password'"),
    ("Federation settings changed", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'federation'"),
    ("Group created with suspicious name", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName == 'Add group'"),
    ("Multitenant application modified", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'application'"),
    ("Tenant configuration change", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'tenant'"),
    ("B2B invitation redeemed from risky country", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'invitation'"),
    ("Service principal credential rotation", "Scheduled", ["AuditLogs"], "AuditLogs | where OperationName has 'service principal'"),
    # DeviceProcessEvents rules (~25)
    ("Suspicious process execution", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName in~ ('powershell.exe', 'cmd.exe')"),
    ("LOLBIN execution detected", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName in~ ('certutil.exe', 'mshta.exe', 'regsvr32.exe')"),
    ("Process injection detected", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where ProcessCommandLine has 'inject'"),
    ("Obfuscated PowerShell command", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where ProcessCommandLine has '-enc'"),
    ("Fileless malware technique", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where InitiatingProcessFileName == 'wmiprvse.exe'"),
    ("Credential dumping tool detected", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName in~ ('mimikatz.exe', 'procdump.exe')"),
    ("Reconnaissance tool execution", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName in~ ('nmap.exe', 'masscan.exe')"),
    ("Remote execution via PsExec", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName == 'psexec.exe'"),
    ("Suspicious child process of Office app", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where InitiatingProcessFileName in~ ('WINWORD.EXE', 'EXCEL.EXE')"),
    ("DLL sideloading detected", "Scheduled", ["DeviceProcessEvents", "DeviceFileEvents"], "DeviceProcessEvents\nDeviceFileEvents | where FileName endswith '.dll'"),
    ("Script interpreter anomaly", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName in~ ('wscript.exe', 'cscript.exe')"),
    ("Renamed system binary detection", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where SHA256 != '' | where FileName !in~ ('svchost.exe')"),
    ("Suspicious use of certutil", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName == 'certutil.exe' | where ProcessCommandLine has '-urlcache'"),
    ("BITSAdmin abuse detected", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName == 'bitsadmin.exe'"),
    ("Rare process execution on DC", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where DeviceName has 'DC'"),
    ("Base64 encoded command execution", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where ProcessCommandLine matches regex '[A-Za-z0-9+/=]{50,}'"),
    ("Lateral movement via WMI", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName == 'wmic.exe'"),
    ("Persistence via registry run key", "Scheduled", ["DeviceProcessEvents", "DeviceRegistryEvents"], "DeviceProcessEvents\nDeviceRegistryEvents | where RegistryKey has 'CurrentVersion\\Run'"),
    ("Scheduled task creation via command line", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName == 'schtasks.exe' | where ProcessCommandLine has '/create'"),
    ("Ransomware indicators detected", "NRT", ["DeviceProcessEvents", "DeviceFileEvents"], "DeviceProcessEvents\nDeviceFileEvents | where FileName endswith '.encrypted'"),
    ("Suspicious net.exe usage", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName in~ ('net.exe', 'net1.exe')"),
    ("Remote desktop tool detected", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName in~ ('anydesk.exe', 'teamviewer.exe')"),
    ("Cobalt Strike beacon indicator", "NRT", ["DeviceProcessEvents", "DeviceNetworkEvents"], "DeviceProcessEvents\nDeviceNetworkEvents | where RemotePort in (443, 8443)"),
    ("Data staging detected", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName in~ ('rar.exe', '7z.exe') | where ProcessCommandLine has '-p'"),
    ("Suspicious service installation", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName == 'sc.exe' | where ProcessCommandLine has 'create'"),
    # DeviceNetworkEvents rules (~15)
    ("C2 beaconing pattern detected", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort in (443, 8080)"),
    ("DNS tunneling detected", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort == 53 | where RemoteUrl has 'dnscat'"),
    ("Connection to known malicious IP", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemoteIP has '185.220.'"),
    ("Unusual outbound port usage", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort > 10000"),
    ("Data exfiltration over DNS", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort == 53"),
    ("TOR network connection detected", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort == 9001"),
    ("SMB lateral movement detected", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort == 445"),
    ("RDP brute force detected", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort == 3389"),
    ("Suspicious outbound connection volume", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | summarize count() by RemoteIP"),
    ("Connection to crypto mining pool", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemoteUrl has 'pool.mining'"),
    ("IRC connection detected", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort in (6667, 6697)"),
    ("LDAP query to external IP", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort == 389"),
    ("Connection to bulletproof hosting", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemoteIP has '91.215.'"),
    ("WinRM lateral movement", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort in (5985, 5986)"),
    ("Large data transfer detected", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where SentBytes > 100000000"),
    # DeviceFileEvents rules (~15)
    ("Ransomware file extension detected", "NRT", ["DeviceFileEvents"], "DeviceFileEvents | where FileName endswith '.encrypted' or FileName endswith '.locked'"),
    ("Suspicious file in startup folder", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FolderPath has 'Startup'"),
    ("Large file copy to removable drive", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FolderPath has 'USB'"),
    ("Hosts file modification", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName == 'hosts'"),
    ("Sensitive file access detected", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FolderPath has 'passwords' or FileName has 'credential'"),
    ("Shadow copy deletion detected", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName has 'vssadmin'"),
    ("Web shell file created", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName endswith '.aspx' | where FolderPath has 'wwwroot'"),
    ("Suspicious DLL dropped", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName endswith '.dll' | where FolderPath has 'Temp'"),
    ("Batch file created in temp", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName endswith '.bat' | where FolderPath has 'Temp'"),
    ("SAM database access detected", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName has 'SAM'"),
    ("NTDS.dit access detected", "NRT", ["DeviceFileEvents"], "DeviceFileEvents | where FileName == 'ntds.dit'"),
    ("Macro-enabled document dropped", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName endswith '.xlsm' or FileName endswith '.docm'"),
    ("ISO/IMG file mounted", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName endswith '.iso' or FileName endswith '.img'"),
    ("File created by suspicious process", "Scheduled", ["DeviceFileEvents", "DeviceProcessEvents"], "DeviceFileEvents\nDeviceProcessEvents"),
    ("LNK file with hidden payload", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName endswith '.lnk'"),
    # Syslog rules (~12)
    ("SSH brute force attack", "Scheduled", ["Syslog"], "Syslog | where Facility == 'auth' | where SyslogMessage has 'Failed password'"),
    ("Root privilege escalation", "NRT", ["Syslog"], "Syslog | where Facility == 'authpriv' | where SyslogMessage has 'sudo'"),
    ("Syslog daemon restart", "Scheduled", ["Syslog"], "Syslog | where Facility == 'daemon' | where ProcessName == 'systemd'"),
    ("Authentication failure burst", "Scheduled", ["Syslog"], "Syslog | where Facility == 'auth' | where SyslogMessage has 'authentication failure'"),
    ("Suspicious cron job created", "Scheduled", ["Syslog"], "Syslog | where Facility == 'cron'"),
    ("Kernel module loaded", "Scheduled", ["Syslog"], "Syslog | where Facility == 'kern' | where SyslogMessage has 'module'"),
    ("Linux user created", "Scheduled", ["Syslog"], "Syslog | where Facility == 'authpriv' | where ProcessName == 'useradd'"),
    ("Linux user deleted", "Scheduled", ["Syslog"], "Syslog | where Facility == 'authpriv' | where ProcessName == 'userdel'"),
    ("Firewall rule change on Linux", "Scheduled", ["Syslog"], "Syslog | where ProcessName in ('iptables', 'nftables')"),
    ("PAM authentication error", "Scheduled", ["Syslog"], "Syslog | where Facility == 'auth' | where SyslogMessage has 'pam_unix'"),
    ("SELinux denial detected", "Scheduled", ["Syslog"], "Syslog | where Facility == 'kern' | where SyslogMessage has 'avc:  denied'"),
    ("SSH key authentication from new IP", "Scheduled", ["Syslog"], "Syslog | where Facility == 'auth' | where ProcessName == 'sshd'"),
    # CommonSecurityLog rules (~10)
    ("IDS alert - critical severity", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where LogSeverity == 10"),
    ("Firewall deny from internal to external", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where DeviceAction == 'Deny'"),
    ("Data loss prevention alert", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where DeviceVendor == 'Palo Alto Networks'"),
    ("Anomalous firewall traffic pattern", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where Activity has 'traffic'"),
    ("VPN connection from unusual country", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where DeviceVendor == 'Fortinet' | where Activity has 'vpn'"),
    ("WAF attack blocked", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where DeviceProduct == 'FortiWeb'"),
    ("Port scan detected by IDS", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where Activity has 'scan'"),
    ("Malware detected by proxy", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where DeviceProduct == 'Zscaler'"),
    ("URL category violation", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where Activity has 'URL'"),
    ("Unusual protocol detected", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where DeviceAction == 'Alert'"),
    # OfficeActivity rules (~10)
    ("Mailbox forwarding rule created", "Scheduled", ["OfficeActivity"], "OfficeActivity | where OfficeWorkload == 'Exchange' | where Operation in ('New-InboxRule', 'Set-InboxRule')"),
    ("Suspicious Teams meeting created", "Scheduled", ["OfficeActivity"], "OfficeActivity | where OfficeWorkload == 'MicrosoftTeams'"),
    ("Mass file download from SharePoint", "Scheduled", ["OfficeActivity"], "OfficeActivity | where OfficeWorkload == 'SharePoint' | where Operation == 'FileDownloaded'"),
    ("External sharing enabled", "Scheduled", ["OfficeActivity"], "OfficeActivity | where Operation has 'SharingSet'"),
    ("DLP policy matched", "Scheduled", ["OfficeActivity"], "OfficeActivity | where Operation has 'DLP'"),
    ("eDiscovery search started", "Scheduled", ["OfficeActivity"], "OfficeActivity | where Operation has 'SearchStarted'"),
    ("Mailbox permission changed", "Scheduled", ["OfficeActivity"], "OfficeActivity | where OfficeWorkload == 'Exchange' | where Operation has 'Permission'"),
    ("Bulk email deletion detected", "Scheduled", ["OfficeActivity"], "OfficeActivity | where OfficeWorkload == 'Exchange' | where Operation == 'HardDelete'"),
    ("Admin audit log disabled", "Scheduled", ["OfficeActivity"], "OfficeActivity | where Operation has 'AuditLog'"),
    ("Power Automate flow created with external action", "Scheduled", ["OfficeActivity"], "OfficeActivity | where OfficeWorkload == 'PowerAutomate'"),
    # CloudAppEvents rules (~8)
    ("Suspicious OAuth app consent", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where ActionType == 'ConsentToApplication'"),
    ("Mass download from cloud storage", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where ActionType == 'FileDownloaded'"),
    ("Cloud app high severity alert", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where Application has 'Office'"),
    ("Impossible travel in cloud apps", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where ActionType has 'Login'"),
    ("Risky cloud app usage detected", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where Application !in ('Microsoft Office 365')"),
    ("Cloud session anomaly", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where ActionType == 'SessionActivity'"),
    ("Shadow IT application detected", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where ApplicationId != ''"),
    ("Suspicious mailbox rule via API", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where ActionType has 'InboxRule'"),
    # AzureActivity rules (~8)
    ("Resource group deleted", "Scheduled", ["AzureActivity"], "AzureActivity | where OperationNameValue has 'delete' | where ActivitySubstatusValue == 'OK'"),
    ("Key vault access anomaly", "Scheduled", ["AzureActivity"], "AzureActivity | where ResourceProviderValue == 'MICROSOFT.KEYVAULT'"),
    ("Subscription-level role assignment", "Scheduled", ["AzureActivity"], "AzureActivity | where OperationNameValue has 'roleAssignment'"),
    ("Network security group modified", "Scheduled", ["AzureActivity"], "AzureActivity | where OperationNameValue has 'networkSecurityGroups'"),
    ("Storage account public access enabled", "Scheduled", ["AzureActivity"], "AzureActivity | where OperationNameValue has 'storageAccounts'"),
    ("VM deleted or deallocated", "Scheduled", ["AzureActivity"], "AzureActivity | where OperationNameValue has 'virtualMachines/delete'"),
    ("Diagnostic setting removed", "Scheduled", ["AzureActivity"], "AzureActivity | where OperationNameValue has 'diagnosticSettings/delete'"),
    ("Azure policy assignment changed", "Scheduled", ["AzureActivity"], "AzureActivity | where OperationNameValue has 'policyAssignments'"),
    # DeviceEvents rules (~8)
    ("Antivirus detection", "Scheduled", ["DeviceEvents"], "DeviceEvents | where ActionType == 'AntivirusDetection'"),
    ("Exploit guard block", "Scheduled", ["DeviceEvents"], "DeviceEvents | where ActionType has 'ExploitGuard'"),
    ("Tamper protection triggered", "NRT", ["DeviceEvents"], "DeviceEvents | where ActionType == 'TamperProtection'"),
    ("USB device connected", "Scheduled", ["DeviceEvents"], "DeviceEvents | where ActionType == 'UsbDriveMount'"),
    ("Smart screen override", "Scheduled", ["DeviceEvents"], "DeviceEvents | where ActionType == 'SmartScreenUrlWarning'"),
    ("ASR rule triggered", "Scheduled", ["DeviceEvents"], "DeviceEvents | where ActionType has 'AsrRule'"),
    ("Controlled folder access blocked", "Scheduled", ["DeviceEvents"], "DeviceEvents | where ActionType has 'ControlledFolderAccess'"),
    ("Suspicious browser extension installed", "Scheduled", ["DeviceEvents"], "DeviceEvents | where ActionType == 'BrowserExtensionInstalled'"),
    # EmailEvents rules (~8)
    ("Phishing email delivered", "Scheduled", ["EmailEvents"], "EmailEvents | where ThreatTypes has 'Phish'"),
    ("Malware attachment detected", "Scheduled", ["EmailEvents"], "EmailEvents | where ThreatTypes has 'Malware'"),
    ("Email from spoofed sender", "Scheduled", ["EmailEvents"], "EmailEvents | where AuthenticationDetails has 'spf=fail'"),
    ("Bulk email campaign detected", "Scheduled", ["EmailEvents"], "EmailEvents | where BulkComplaintLevel > 7"),
    ("Executive impersonation attempt", "Scheduled", ["EmailEvents"], "EmailEvents | where Subject has 'CEO' or Subject has 'CFO'"),
    ("Email with suspicious URL", "Scheduled", ["EmailEvents", "EmailUrlInfo"], "EmailEvents\nEmailUrlInfo | where UrlDomain has 'suspicious'"),
    ("ZAP action taken on email", "Scheduled", ["EmailEvents"], "EmailEvents | where LatestDeliveryAction == 'Junked'"),
    ("High confidence phishing", "NRT", ["EmailEvents"], "EmailEvents | where ThreatTypes has 'Phish' | where ConfidenceLevel == 'High'"),
    # DeviceRegistryEvents rules (~6)
    ("Registry run key modification", "Scheduled", ["DeviceRegistryEvents"], "DeviceRegistryEvents | where RegistryKey has 'CurrentVersion\\Run'"),
    ("AMSI bypass registry change", "Scheduled", ["DeviceRegistryEvents"], "DeviceRegistryEvents | where RegistryKey has 'AMSI'"),
    ("WDigest credential caching enabled", "Scheduled", ["DeviceRegistryEvents"], "DeviceRegistryEvents | where RegistryKey has 'WDigest'"),
    ("UAC bypass registry modification", "Scheduled", ["DeviceRegistryEvents"], "DeviceRegistryEvents | where RegistryKey has 'fodhelper'"),
    ("Defender exclusion path added", "Scheduled", ["DeviceRegistryEvents"], "DeviceRegistryEvents | where RegistryKey has 'Windows Defender\\Exclusions'"),
    ("COM object hijacking detected", "Scheduled", ["DeviceRegistryEvents"], "DeviceRegistryEvents | where RegistryKey has 'InprocServer32'"),
    # DeviceLogonEvents rules (~5)
    ("RDP brute force on endpoint", "Scheduled", ["DeviceLogonEvents"], "DeviceLogonEvents | where LogonType == 'RemoteInteractive'"),
    ("New local admin logon", "Scheduled", ["DeviceLogonEvents"], "DeviceLogonEvents | where IsLocalAdmin == True"),
    ("Interactive logon at unusual hour", "Scheduled", ["DeviceLogonEvents"], "DeviceLogonEvents | where LogonType == 'Interactive'"),
    ("Service account interactive logon", "Scheduled", ["DeviceLogonEvents"], "DeviceLogonEvents | where AccountName has 'svc'"),
    ("Failed logon on sensitive server", "Scheduled", ["DeviceLogonEvents"], "DeviceLogonEvents | where ActionType == 'LogonFailed'"),
    # IdentityLogonEvents rules (~5)
    ("LDAP brute force detected", "Scheduled", ["IdentityLogonEvents"], "IdentityLogonEvents | where Protocol == 'Ldap' | where ActionType == 'LogonFailed'"),
    ("NTLM relay attack pattern", "Scheduled", ["IdentityLogonEvents"], "IdentityLogonEvents | where Protocol == 'Ntlm'"),
    ("Kerberoasting pattern detected", "Scheduled", ["IdentityLogonEvents"], "IdentityLogonEvents | where Protocol == 'Kerberos'"),
    ("DC shadow attack detected", "Scheduled", ["IdentityLogonEvents"], "IdentityLogonEvents | where ActionType has 'DCShadow'"),
    ("Identity protection alert correlation", "Scheduled", ["IdentityLogonEvents", "SigninLogs"], "IdentityLogonEvents\nSigninLogs"),
    # AWSCloudTrail rules (~3, on DL → detection gap!)
    ("AWS root account login", "Scheduled", ["AWSCloudTrail"], "AWSCloudTrail | where EventName == 'ConsoleLogin' | where UserIdentityType == 'Root'"),
    ("AWS IAM policy changed", "Scheduled", ["AWSCloudTrail"], "AWSCloudTrail | where EventName has 'PutRolePolicy'"),
    ("AWS S3 bucket made public", "Scheduled", ["AWSCloudTrail"], "AWSCloudTrail | where EventName has 'PutBucketAcl'"),
    # SecurityAlert/Incident rules (~5)
    ("High severity alert correlation", "Scheduled", ["SecurityAlert"], "SecurityAlert | where AlertSeverity == 'High'"),
    ("Multi-stage attack detected", "Scheduled", ["SecurityAlert", "SecurityIncident"], "SecurityAlert\nSecurityIncident | where Severity == 'High'"),
    ("Alert-to-incident correlation", "Scheduled", ["SecurityAlert"], "SecurityAlert | where ProviderName has 'MDATP'"),
    ("Fusion attack detection", "Scheduled", ["SecurityAlert"], "SecurityAlert | where ProductName has 'Azure Sentinel'"),
    ("Threat intelligence match", "Scheduled", ["SecurityAlert", "ThreatIntelligenceIndicator"], "SecurityAlert\nThreatIntelligenceIndicator"),
    # Misc cross-table rules (~10)
    ("MFA registration from suspicious IP", "Scheduled", ["AuditLogs", "SigninLogs"], "AuditLogs | where OperationName has 'authentication method'\nSigninLogs"),
    ("Insider threat - mass download + USB", "Scheduled", ["DeviceFileEvents", "DeviceEvents"], "DeviceFileEvents\nDeviceEvents | where ActionType == 'UsbDriveMount'"),
    ("Unusual identity query pattern", "Scheduled", ["IdentityQueryEvents"], "IdentityQueryEvents | where ActionType has 'Query'"),
    ("Identity directory change anomaly", "Scheduled", ["IdentityDirectoryEvents"], "IdentityDirectoryEvents | where ActionType has 'Group'"),
    ("Email post-delivery action", "Scheduled", ["EmailPostDeliveryEvents"], "EmailPostDeliveryEvents | where ActionType has 'ZAP'"),
    ("Graph API anomaly detected", "Scheduled", ["MicrosoftGraphActivityLogs"], "MicrosoftGraphActivityLogs | where ResponseStatusCode >= 400"),
    ("URL click to malicious site", "Scheduled", ["UrlClickEvents"], "UrlClickEvents | where IsClickedThrough == True"),
    ("Config change on managed server", "Scheduled", ["ConfigurationChange"], "ConfigurationChange | where ConfigChangeType has 'Software'"),
    ("GCP privilege escalation", "Scheduled", ["GCPAuditLogs"], "GCPAuditLogs | where OperationName has 'SetIamPolicy'"),
    ("LA query exfiltration pattern", "Scheduled", ["LAQueryLogs"], "LAQueryLogs | where ResponseRowCount > 10000"),
]

# Add ~20 disabled rules
DISABLED_RULES = [
    ("Deprecated - Old brute force detection v1", "Scheduled", ["SecurityEvent"], "SecurityEvent | where EventID == 4625"),
    ("Deprecated - Legacy sign-in rule", "Scheduled", ["SigninLogs"], "SigninLogs | where ResultType != 0"),
    ("Test rule - DO NOT ENABLE", "Scheduled", ["AuditLogs"], "AuditLogs | where Category == 'Test'"),
    ("Draft - Suspicious PowerShell v2", "Scheduled", ["DeviceProcessEvents"], "DeviceProcessEvents | where FileName == 'powershell.exe'"),
    ("Disabled - Noisy DNS alert", "Scheduled", ["DeviceNetworkEvents"], "DeviceNetworkEvents | where RemotePort == 53"),
    ("Backup - Old firewall rule", "Scheduled", ["CommonSecurityLog"], "CommonSecurityLog | where DeviceAction == 'Drop'"),
    ("WIP - New email detection", "Scheduled", ["EmailEvents"], "EmailEvents | where Subject has 'invoice'"),
    ("Archived - Syslog login v1", "Scheduled", ["Syslog"], "Syslog | where Facility == 'auth'"),
    ("Deprecated - Config drift v1", "Scheduled", ["ConfigurationChange"], "ConfigurationChange"),
    ("Test - Cloud app rule", "Scheduled", ["CloudAppEvents"], "CloudAppEvents | where ActionType == 'Test'"),
    ("Deprecated - AzureActivity v1", "Scheduled", ["AzureActivity"], "AzureActivity | where OperationNameValue has 'write'"),
    ("Disabled - Too many false positives", "Scheduled", ["DeviceFileEvents"], "DeviceFileEvents | where FileName endswith '.tmp'"),
    ("WIP - Identity correlation v2", "Scheduled", ["IdentityLogonEvents"], "IdentityLogonEvents"),
    ("Test - Device logon pattern", "Scheduled", ["DeviceLogonEvents"], "DeviceLogonEvents"),
    ("Deprecated - Old AWS rule", "Scheduled", ["AWSCloudTrail"], "AWSCloudTrail | where EventName == 'ListBuckets'"),
    ("Backup - Registry baseline", "Scheduled", ["DeviceRegistryEvents"], "DeviceRegistryEvents"),
    ("Disabled - OfficeActivity noise", "Scheduled", ["OfficeActivity"], "OfficeActivity | where Operation == 'FileAccessed'"),
    ("Deprecated - Graph v1", "Scheduled", ["MicrosoftGraphActivityLogs"], "MicrosoftGraphActivityLogs"),
    ("Test - Alert correlation v0", "Scheduled", ["SecurityAlert"], "SecurityAlert"),
    ("WIP - GCP logging v2", "Scheduled", ["GCPAuditLogs"], "GCPAuditLogs"),
    ("Deprecated - Heartbeat monitor", "Scheduled", ["Heartbeat"], "Heartbeat | where TimeGenerated > ago(5m)"),
    ("Disabled - W3C log analysis", "Scheduled", ["W3CIISLog"], "W3CIISLog | where scStatus >= 500"),
]

# Custom detection rules (Q9b — Graph API format)
CUSTOM_DETECTION_RULES = [
    ("TI map IP entity to SigninLogs", True, "SigninLogs | where IPAddress in (ThreatIntelIndicators)"),
    ("TI map URL entity to CloudAppEvents", True, "CloudAppEvents | where ActionType has 'url'\nThreatIntelIndicators"),
    ("TI map domain entity to DeviceNetworkEvents", True, "DeviceNetworkEvents | where RemoteUrl in (ThreatIntelIndicators)"),
    ("TI map hash entity to DeviceFileEvents", True, "DeviceFileEvents | where SHA256 in (ThreatIntelIndicators)"),
    ("TI map email entity to EmailEvents", True, "EmailEvents | where SenderFromAddress in (ThreatIntelIndicators)"),
    ("Suspicious inbound connection to server", True, "DeviceNetworkEvents | where ActionType == 'InboundConnectionAccepted'"),
    ("Credential access via LSASS", True, "DeviceProcessEvents | where FileName == 'lsass.exe'"),
    ("Exchange server web shell detection", True, "DeviceFileEvents | where FolderPath has 'inetpub'"),
    ("Anomalous sign-in pattern", True, "SigninLogs | where RiskState == 'atRisk'"),
    ("Brute force RDP detection", True, "DeviceLogonEvents | where LogonType == 'RemoteInteractive'"),
    ("Phishing email with attachment", True, "EmailEvents | where AttachmentCount > 0 | where ThreatTypes has 'Phish'\nEmailAttachmentInfo"),
    ("Suspicious PowerShell download", True, "DeviceProcessEvents | where FileName == 'powershell.exe' | where ProcessCommandLine has 'downloadstring'"),
    ("Test detection - suspended", False, "SecurityEvent | where EventID == 4625"),
    ("Draft - SOC triage rule", False, "SecurityAlert | where AlertSeverity == 'Medium'"),
]

# ═══════════════════════════════════════════════════════════════════════════
# SECURITY EVENT COMPUTERS
# ═══════════════════════════════════════════════════════════════════════════
DOMAINS = ["contoso.com", "northwind.com", "fabrikam.local"]

def generate_server_names(count):
    """Generate realistic Windows server names."""
    prefixes = [
        ("DC", 6),       # Domain controllers
        ("SQL", 10),     # SQL servers
        ("WEB", 15),     # Web servers
        ("APP", 20),     # Application servers
        ("FILE", 8),     # File servers
        ("EXCH", 4),     # Exchange servers
        ("ADFS", 3),     # ADFS servers
        ("SCCM", 2),     # Config manager
        ("WSUS", 2),     # WSUS
        ("CA", 2),       # Certificate authority
        ("PRINT", 5),    # Print servers
        ("RDS", 6),      # Remote desktop
        ("HV", 12),      # Hyper-V hosts
        ("MGMT", 4),     # Management servers
        ("PKI", 2),      # PKI servers
        ("NPS", 3),      # Network policy
        ("WS", 350),     # Workstations
    ]
    servers = []
    for prefix, n in prefixes:
        actual_n = min(n, count - len(servers))
        if actual_n <= 0:
            break
        for i in range(1, actual_n + 1):
            domain = random.choice(DOMAINS)
            servers.append(f"{prefix}-{i:03d}.{domain}")
    return servers[:count]


# ═══════════════════════════════════════════════════════════════════════════
# SYSLOG HOSTS
# ═══════════════════════════════════════════════════════════════════════════
SYSLOG_HOSTS = [
    "fw-edge-01", "fw-edge-02", "fw-core-01",
    "lnx-web-01", "lnx-web-02", "lnx-web-03",
    "lnx-app-01", "lnx-app-02",
    "lnx-db-01", "lnx-db-02",
    "lnx-jump-01", "lnx-monitor-01",
    "lnx-ci-01", "lnx-docker-01", "lnx-docker-02",
    "lnx-k8s-master-01", "lnx-k8s-worker-01", "lnx-k8s-worker-02",
    "lnx-dns-01", "lnx-ntp-01",
]

SYSLOG_FACILITIES = ["auth", "authpriv", "daemon", "kern", "cron", "user", "local0", "local1", "local3", "mail", "syslog"]
SYSLOG_SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
SYSLOG_PROCESSES = [
    "sshd", "systemd", "sudo", "cron", "rsyslogd", "auditd", "named",
    "dockerd", "kubelet", "nginx", "httpd", "postfix", "dovecot",
    "iptables", "NetworkManager", "polkitd", "dbus-daemon",
    "containerd", "etcd", "kube-apiserver", "coredns",
    "pam_unix", "login", "su", "useradd", "passwd",
    "apt-get", "yum", "rpm", "systemd-logind", "journald",
]

# ═══════════════════════════════════════════════════════════════════════════
# CSL VENDORS
# ═══════════════════════════════════════════════════════════════════════════
CSL_VENDORS = [
    ("Palo Alto Networks", "PAN-OS", 45),
    ("Fortinet", "FortiGate", 25),
    ("Cisco", "ASA", 12),
    ("Zscaler", "ZIA", 8),
    ("Check Point", "SmartDefense", 5),
    ("F5", "BIG-IP ASM", 3),
    ("Barracuda", "WAF", 2),
]

CSL_ACTIVITIES = [
    ("TRAFFIC", "informational", "allow", 30),
    ("TRAFFIC", "informational", "deny", 15),
    ("TRAFFIC", "informational", "drop", 10),
    ("THREAT", "high", "alert", 5),
    ("THREAT", "critical", "block", 3),
    ("THREAT", "medium", "alert", 8),
    ("SYSTEM", "informational", "n/a", 4),
    ("URL-FILTERING", "informational", "allow", 6),
    ("URL-FILTERING", "warning", "block", 4),
    ("CONFIG", "informational", "n/a", 2),
    ("GLOBALPROTECT", "informational", "success", 5),
    ("GLOBALPROTECT", "warning", "fail", 2),
    ("AUTHENTICATION", "informational", "success", 3),
    ("AUTHENTICATION", "warning", "failed", 2),
    ("WILDFIRE", "high", "alert", 1),
]

# ═══════════════════════════════════════════════════════════════════════════
# E5-ELIGIBLE TABLES (from Q17b YAML)
# ═══════════════════════════════════════════════════════════════════════════
E5_TABLES = [
    "SigninLogs", "AuditLogs", "AADNonInteractiveUserSignInLogs",
    "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
    "AADProvisioningLogs", "ADFSSignInLogs", "McasShadowItReporting",
    "DeviceEvents", "DeviceFileEvents", "DeviceImageLoadEvents",
    "DeviceInfo", "DeviceLogonEvents", "DeviceNetworkEvents",
    "DeviceNetworkInfo", "DeviceProcessEvents", "DeviceRegistryEvents",
    "DeviceFileCertificateInfo", "EmailAttachmentInfo", "EmailEvents",
    "EmailPostDeliveryEvents", "EmailUrlInfo", "IdentityLogonEvents",
    "IdentityQueryEvents", "IdentityDirectoryEvents", "AlertEvidence",
    "CloudAppEvents", "DynamicEventCollection",
]

# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def write_json(filename, data):
    """Write data to JSON file in OUTPUT_DIR."""
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  ✅ {filename} ({len(data) if isinstance(data, list) else 1} {'rows' if isinstance(data, list) else 'object'})")


def daily_volumes(avg_gb, days, base_date, variance=0.15):
    """Generate daily volumes with realistic variance around an average."""
    volumes = []
    for i in range(days):
        # Weekends slightly lower
        day_of_week = (base_date + timedelta(days=i)).weekday()
        weekend_factor = 0.82 if day_of_week >= 5 else 1.0
        vol = avg_gb * weekend_factor * random.uniform(1 - variance, 1 + variance)
        volumes.append(round(vol, 3))
    return volumes


# ═══════════════════════════════════════════════════════════════════════════
# GENERATE ALL FILES
# ═══════════════════════════════════════════════════════════════════════════

def generate_all():
    # ── Parse CLI args ───────────────────────────────────────────────
    parser = argparse.ArgumentParser(description="Generate synthetic ingestion data")
    parser.add_argument("--days", type=int, choices=[1, 7, 30, 60, 90], default=30,
                        help="Primary reporting window in days (default: 30)")
    args = parser.parse_args()

    # ── Derive windows (mirrors PS1 logic) ───────────────────────────
    NUM_DAYS = args.days + 1  # +1 for partial-day exclusion buffer
    if args.days <= 7:
        DEEP_DIVE_DAYS = args.days
    elif args.days <= 30:
        DEEP_DIVE_DAYS = 7
    elif args.days <= 60:
        DEEP_DIVE_DAYS = 14
    else:
        DEEP_DIVE_DAYS = 30
    WOW_TOTAL_DAYS = DEEP_DIVE_DAYS * 2
    BASE_DATE = datetime(2026, 2, 1)

    # ── Scale factors ────────────────────────────────────────────────
    # TABLES list uses 30-day reference volumes → scale_primary = days/30
    # Hardcoded deep-dive values (Q4-Q8,Q11) use 7-day reference → scale_deepdive = DD/7
    scale_primary = args.days / 30
    scale_deepdive = DEEP_DIVE_DAYS / 7

    # ── Compute window-scaled volumes ────────────────────────────────
    TOTAL_BILLABLE = BASE_30D_BILLABLE * scale_primary
    TOTAL_NON_BILLABLE = BASE_30D_NON_BILLABLE * scale_primary
    TOTAL_GB = TOTAL_BILLABLE + TOTAL_NON_BILLABLE
    AVG_DAILY_GB = round(TOTAL_GB / NUM_DAYS, 3)
    BILLABLE_TABLE_COUNT = sum(1 for t in TABLES if t[1] > 0)
    TOTAL_TABLE_COUNT = len(TABLES)

    print(f"Generating synthetic data for '{WORKSPACE_NAME}'")
    print(f"  Window: {args.days}d primary, {DEEP_DIVE_DAYS}d deep-dive, {WOW_TOTAL_DAYS}d comparison")
    print(f"  Target: ~{round(TOTAL_GB / NUM_DAYS)} GB/day, {TOTAL_GB:.0f} GB total over {NUM_DAYS} days")
    print(f"  Tables: {TOTAL_TABLE_COUNT} total, {BILLABLE_TABLE_COUNT} billable")
    print()

    # ─── meta.json ───────────────────────────────────────────────────
    write_json("meta.json", {
        "workspace_name": WORKSPACE_NAME,
        "workspace_id": WORKSPACE_ID,
    })

    # ─── Q1: Top tables by volume ────────────────────────────────────
    q1_tables = [t for t in TABLES if t[5]]  # in_q1_top20 == True
    q1_data = []
    for name, billable, nonbill, solution, plan, _ in sorted(q1_tables, key=lambda t: t[1], reverse=True):
        scaled_bill = round(billable * scale_primary, 3)
        scaled_nonbill = round(nonbill * scale_primary, 3)
        q1_data.append({
            "DataType": name,
            "BillableGB": scaled_bill,
            "NonBillableGB": scaled_nonbill,
            "AvgDailyGB": round(scaled_bill / NUM_DAYS, 3),
            "Solution": solution,
            "TableName": "PrimaryResult",
        })
    write_json("ingestion-q1.json", q1_data)

    # ─── Q2: Daily ingestion trend ───────────────────────────────────
    daily_vols = daily_volumes(AVG_DAILY_GB, days=NUM_DAYS, base_date=BASE_DATE, variance=0.12)
    q2_data = []
    for i in range(NUM_DAYS):
        day = BASE_DATE + timedelta(days=i)
        q2_data.append({
            "TimeGenerated": day.strftime("%Y-%m-%d 12:00:00 AM"),
            "DailyGB": round(daily_vols[i], 3),
            "TableName": "PrimaryResult",
        })
    write_json("ingestion-q2.json", q2_data)

    # ─── Q3: Workspace summary ───────────────────────────────────────
    q3_data = {
        "TotalGB": round(TOTAL_GB, 3),
        "BillableGB": round(TOTAL_BILLABLE, 3),
        "NonBillableGB": round(TOTAL_NON_BILLABLE, 3),
        "AvgDailyGB": round(AVG_DAILY_GB, 3),
        "TotalTableCount": TOTAL_TABLE_COUNT,
        "BillableTableCount": BILLABLE_TABLE_COUNT,
        "BillablePercent": round(TOTAL_BILLABLE / TOTAL_GB * 100, 1),
        "DayCount": NUM_DAYS,
        "TableName": "PrimaryResult",
    }
    write_json("ingestion-q3.json", q3_data)

    # ─── Q4: SecurityEvent by Computer (deep-dive window) ──────────
    num_servers = 450
    servers = generate_server_names(num_servers)
    # 1180 GB = original 7-day reference; scale_deepdive = DEEP_DIVE_DAYS/7
    se_total_gb = round(1180.0 * scale_deepdive, 1)
    se_total_mb = se_total_gb * 1024

    # Create a power-law distribution for server volumes
    # DCs and key servers get more events
    weights = []
    for s in servers:
        if s.startswith("DC-"):
            weights.append(random.uniform(8, 15))
        elif s.startswith("SQL-"):
            weights.append(random.uniform(3, 7))
        elif s.startswith("EXCH-"):
            weights.append(random.uniform(4, 8))
        elif s.startswith("WEB-"):
            weights.append(random.uniform(2, 5))
        elif s.startswith("APP-"):
            weights.append(random.uniform(1.5, 4))
        elif s.startswith("HV-"):
            weights.append(random.uniform(2, 5))
        elif s.startswith("RDS-"):
            weights.append(random.uniform(1.5, 3))
        else:
            weights.append(random.uniform(0.2, 1.5))

    total_weight = sum(weights)
    q4_data = []
    for i, server in enumerate(servers):
        frac = weights[i] / total_weight
        est_mb = round(se_total_mb * frac, 0)
        event_count = int(est_mb * random.uniform(900, 1300))  # ~1000 events per MB
        q4_data.append({
            "Computer": server,
            "EventCount": event_count,
            "EstimatedGB": round(est_mb / 1024, 2),
            "PercentOfTotal": round(est_mb / se_total_mb * 100, 1),
            "TotalServers": num_servers,
            "TableName": "PrimaryResult",
        })
    q4_data.sort(key=lambda x: x["EstimatedGB"], reverse=True)
    q4_data = q4_data[:25]  # KQL query uses | take 25
    write_json("ingestion-q4.json", q4_data)

    # ─── Q5: SecurityEvent by EventID ────────────────────────────────
    # Realistic distribution of Windows Security Event IDs
    event_ids = [
        (4624, 28.0), (4625, 12.0), (4672, 8.0), (4688, 7.5), (4689, 7.0),
        (4634, 6.0), (4648, 4.0), (4776, 3.5), (4768, 3.0), (4769, 2.5),
        (5156, 2.5), (5158, 2.0), (4627, 2.0), (4703, 1.5), (4656, 1.5),
        (4663, 5.5), (4670, 1.0), (4662, 0.8), (4658, 0.8), (4740, 0.5),
        (4720, 0.3), (4726, 0.2), (4798, 0.3), (1102, 0.05), (4719, 0.05),
    ]
    eid_total_pct = sum(e[1] for e in event_ids)
    q5_data = []
    for eid, pct in event_ids:
        mb = round(se_total_mb * (pct / 100), 0)
        event_count = int(mb * random.uniform(900, 1300))
        q5_data.append({
            "EventID": eid,
            "EventCount": event_count,
            "EstimatedGB": round(mb / 1024, 2),
            "PercentOfTotal": round(pct * (100 / eid_total_pct), 1),
            "TableName": "PrimaryResult",
        })
    q5_data.sort(key=lambda x: x["EstimatedGB"], reverse=True)
    write_json("ingestion-q5.json", q5_data)

    # ─── Q6a: Syslog by Host (deep-dive window) ────────────────────
    syslog_total_mb = round(390.0 * scale_deepdive, 1) * 1024
    host_weights = [random.uniform(1, 8) for _ in SYSLOG_HOSTS]
    total_hw = sum(host_weights)
    q6a_data = []
    for i, host in enumerate(SYSLOG_HOSTS):
        frac = host_weights[i] / total_hw
        est_mb = round(syslog_total_mb * frac, 0)
        event_count = int(est_mb * random.uniform(2500, 4000))
        # Pick 3-6 facilities and 2-4 severities per host
        facilities = random.sample(SYSLOG_FACILITIES, min(random.randint(3, 6), len(SYSLOG_FACILITIES)))
        severities = random.sample(["notice", "warning", "info", "err", "crit"], random.randint(2, 4))
        q6a_data.append({
            "SourceHost": host,
            "EventCount": event_count,
            "EstimatedGB": round(est_mb / 1024, 2),
            "PercentOfTotal": round(frac * 100, 1),
            "Facilities": json.dumps(facilities),
            "SeverityLevels": json.dumps(severities),
            "TableName": "PrimaryResult",
        })
    q6a_data.sort(key=lambda x: x["EstimatedGB"], reverse=True)
    write_json("ingestion-q6a.json", q6a_data)

    # ─── Q6b: Syslog by Facility × Severity ─────────────────────────
    q6b_data = []
    # Generate realistic facility×severity combos
    fac_sev_combos = [
        ("auth", "notice", 18), ("auth", "info", 12), ("auth", "warning", 5), ("auth", "err", 2),
        ("authpriv", "notice", 8), ("authpriv", "info", 5), ("authpriv", "warning", 2),
        ("daemon", "warning", 15), ("daemon", "info", 10), ("daemon", "notice", 6), ("daemon", "err", 3),
        ("kern", "warning", 8), ("kern", "info", 5), ("kern", "notice", 3), ("kern", "err", 1), ("kern", "crit", 0.3),
        ("cron", "info", 4), ("cron", "notice", 2),
        ("user", "info", 5), ("user", "notice", 3), ("user", "warning", 1),
        ("local0", "info", 6), ("local0", "warning", 3), ("local0", "err", 1),
        ("local1", "info", 3), ("local1", "notice", 2),
        ("local3", "info", 4), ("local3", "warning", 2),
        ("mail", "info", 2), ("mail", "warning", 1),
        ("syslog", "info", 3), ("syslog", "notice", 1),
    ]
    total_fac_weight = sum(c[2] for c in fac_sev_combos)
    for fac, sev, weight in fac_sev_combos:
        frac = weight / total_fac_weight
        est_mb = round(syslog_total_mb * frac, 0)
        event_count = int(est_mb * random.uniform(2500, 4000))
        q6b_data.append({
            "Facility": fac,
            "SeverityLevel": sev,
            "EventCount": event_count,
            "EstimatedGB": round(est_mb / 1024, 2),
            "PercentOfTotal": round(frac * 100, 1),
            "DistinctHosts": random.randint(3, 18),
            "TableName": "PrimaryResult",
        })
    q6b_data.sort(key=lambda x: x["EstimatedGB"], reverse=True)
    write_json("ingestion-q6b.json", q6b_data)

    # ─── Q6c: Syslog by Process ──────────────────────────────────────
    proc_weights = [
        ("sshd", "auth", 20), ("systemd", "daemon", 18), ("sudo", "authpriv", 8),
        ("cron", "cron", 6), ("rsyslogd", "syslog", 4), ("auditd", "authpriv", 5),
        ("dockerd", "daemon", 7), ("kubelet", "daemon", 6), ("nginx", "local0", 5),
        ("named", "daemon", 3), ("postfix", "mail", 3), ("iptables", "kern", 2),
        ("NetworkManager", "daemon", 2), ("polkitd", "authpriv", 1.5),
        ("containerd", "daemon", 4), ("etcd", "daemon", 2),
        ("kube-apiserver", "daemon", 3), ("coredns", "daemon", 2),
        ("pam_unix", "auth", 4), ("login", "auth", 2),
        ("su", "auth", 1), ("useradd", "authpriv", 0.5),
        ("httpd", "local0", 3), ("dovecot", "mail", 1),
        ("dbus-daemon", "daemon", 1), ("journald", "daemon", 2),
        ("apt-get", "daemon", 0.5), ("systemd-logind", "authpriv", 2),
        ("passwd", "authpriv", 0.3), ("rpm", "daemon", 0.3),
    ]
    total_proc_weight = sum(p[2] for p in proc_weights)
    q6c_data = []
    for proc, fac, weight in proc_weights:
        frac = weight / total_proc_weight
        est_mb = round(syslog_total_mb * frac, 0)
        event_count = int(est_mb * random.uniform(2500, 4000))
        q6c_data.append({
            "ProcessName": proc,
            "Facility": fac,
            "EventCount": event_count,
            "EstimatedGB": round(est_mb / 1024, 2),
            "PercentOfTotal": round(frac * 100, 1),
            "DistinctHosts": random.randint(2, 18),
            "TableName": "PrimaryResult",
        })
    q6c_data.sort(key=lambda x: x["EstimatedGB"], reverse=True)
    write_json("ingestion-q6c.json", q6c_data)

    # ─── Q7: CSL by Vendor (deep-dive window) ───────────────────────
    csl_total_mb = round(340.0 * scale_deepdive, 1) * 1024
    total_vendor_weight = sum(v[2] for v in CSL_VENDORS)
    q7_data = []
    for vendor, product, weight in CSL_VENDORS:
        frac = weight / total_vendor_weight
        est_mb = round(csl_total_mb * frac, 0)
        event_count = int(est_mb * random.uniform(1500, 3000))
        q7_data.append({
            "DeviceVendor": vendor,
            "DeviceProduct": product,
            "EventCount": event_count,
            "EstimatedGB": round(est_mb / 1024, 2),
            "PercentOfTotal": round(frac * 100, 1),
            "TableName": "PrimaryResult",
        })
    q7_data.sort(key=lambda x: x["EstimatedGB"], reverse=True)
    write_json("ingestion-q7.json", q7_data)

    # ─── Q8: CSL by Activity ─────────────────────────────────────────
    total_act_weight = sum(a[3] for a in CSL_ACTIVITIES)
    q8_data = []
    for activity, severity, action, weight in CSL_ACTIVITIES:
        frac = weight / total_act_weight
        est_mb = round(csl_total_mb * frac, 0)
        event_count = int(est_mb * random.uniform(1500, 3000))
        q8_data.append({
            "Activity": activity,
            "LogSeverity": severity,
            "DeviceAction": action,
            "EventCount": event_count,
            "EstimatedGB": round(est_mb / 1024, 2),
            "PercentOfTotal": round(frac * 100, 1),
            "TableName": "PrimaryResult",
        })
    q8_data.sort(key=lambda x: x["EstimatedGB"], reverse=True)
    write_json("ingestion-q8.json", q8_data)

    # ─── Q9: Analytic rules (REST API format) ────────────────────────
    q9_data = []
    rule_id_counter = 0
    for display_name, kind, tables, query in RULE_TEMPLATES:
        rule_id_counter += 1
        q9_data.append({
            "displayName": display_name,
            "enabled": True,
            "kind": kind,
            "query": query,
            "ruleId": f"rule-{rule_id_counter:04d}-aaaa-bbbb-cccc-{rule_id_counter:012d}",
        })
    for display_name, kind, tables, query in DISABLED_RULES:
        rule_id_counter += 1
        q9_data.append({
            "displayName": display_name,
            "enabled": False,
            "kind": kind,
            "query": query,
            "ruleId": f"rule-{rule_id_counter:04d}-aaaa-bbbb-cccc-{rule_id_counter:012d}",
        })
    write_json("ingestion-q9.json", q9_data)

    # ─── Q9b: Custom detection rules (Graph API format) ──────────────
    q9b_data = []
    cd_id_counter = 5000
    for display_name, is_enabled, query_text in CUSTOM_DETECTION_RULES:
        cd_id_counter += 1
        q9b_data.append({
            "id": cd_id_counter,
            "displayName": display_name,
            "isEnabled": is_enabled,
            "createdDateTime": "2025-11-20 3:00:00 PM",
            "lastModifiedDateTime": "2026-01-15 10:30:00 AM",
            "queryCondition": {
                "queryText": query_text,
                "lastModifiedDateTime": "",
            },
            "schedule": {
                "period": "1H",
                "nextRunDateTime": "2026-02-20 2:00:00 AM",
            },
            "lastRunDetails": {
                "lastRunDateTime": "2026-02-20 1:00:00 AM",
                "status": "completed",
                "failureReason": "",
                "errorCode": "",
            },
            "detectionAction": {
                "organizationalScope": "",
                "alertTemplate": "",
                "responseActions": [],
            },
        })
    write_json("ingestion-q9b.json", q9b_data)

    # ─── Q10: Table tier classification (CLI format) ─────────────────
    # All known tables (including empty ones not in our TABLES list)
    q10_data = []
    # First add our actual tables with their real tiers
    added_tables = set()
    for name, _, _, _, plan, _ in TABLES:
        q10_data.append({"name": name, "plan": plan})
        added_tables.add(name)
    # Add ~850 more standard Sentinel tables (all as Analytics since they're defaults)
    extra_tables = [
        "SecurityBaseline", "SecurityBaselineSummary", "ProtectionStatus",
        "SecurityDetection", "Update", "UpdateSummary", "UpdateRunProgress",
        "AutoscaleEvaluationsLog", "AutoscaleScaleActionsLog",
        "AppServiceHTTPLogs", "AppServiceConsoleLogs", "AppServiceAppLogs",
        "AppServiceFileAuditLogs", "AppServiceAuditLogs",
        "FunctionAppLogs", "AppServicePlatformLogs",
        "AzureDevOpsAuditing", "ABSBotRequests",
        "ADAssessmentRecommendation", "ADSecurityAssessmentRecommendation",
        "SQLAssessmentRecommendation",
        "BehaviorAnalytics", "Anomalies", "HuntingBookmark",
        "DeviceTvmSoftwareInventory", "DeviceTvmSoftwareVulnerabilities",
        "DeviceTvmInfoGathering", "DeviceTvmSecureConfigurationAssessment",
        "DeviceTvmHardwareFirmware", "DeviceTvmBrowserExtensions",
        "DeviceTvmCertificateInfo", "DeviceTvmSoftwareEvidenceBeta",
        "DeviceTvmSecureConfigurationAssessmentKB",
        "ExposureGraphNodes", "ExposureGraphEdges",
        "SecurityRecommendation", "CommonSecurityLog",
        "VMConnection", "VMBoundPort", "VMProcess", "VMComputer",
        "InsightsMetrics", "ContainerLog", "ContainerInventory",
        "ContainerNodeInventory", "KubePodInventory", "KubeNodeInventory",
        "KubeEvents", "KubeServices", "KubeMonAgentEvents",
        "HDInsightAmbariClusterAlerts", "HDInsightAmbariSystemMetrics",
        "WireData", "DnsEvents", "DnsInventory",
        "NetworkMonitoring", "LinuxAuditLog", "Watchlist",
        "MicrosoftPurviewInformationProtection",
        "PowerBIActivity", "PowerBIDatasetsWorkspace",
        "DynamicsActivity",
        "MCASActivityLog", "MCASEvaluationPolicy",
        "SentinelAudit", "DataSensitivityLogEvent",
        "SecuritySuggestion", "NetworkAccessTraffic",
        "ASimAuditEventLogs", "ASimDnsActivityLogs",
        "ASimNetworkSessionLogs", "ASimWebSessionLogs",
        "ASimFileEventLogs", "ASimProcessEventLogs",
        "ASimRegistryEventLogs", "ASimAuthenticationEventLogs",
        "ASimDhcpEventLogs", "ASimUserManagementActivityLogs",
        "MDCFileIntegrityMonitoringEvents",
    ]
    for t in extra_tables:
        if t not in added_tables:
            q10_data.append({"name": t, "plan": "Analytics"})
            added_tables.add(t)
    # Fill to ~900 tables with generic names
    generic_tables = [f"Table{i}" for i in range(len(q10_data), 900)]
    for t in generic_tables:
        q10_data.append({"name": t, "plan": "Analytics"})
    write_json("ingestion-q10.json", q10_data)

    # ─── Q10b: Tier summary (primary window) ──────────────────────
    analytics_gb = sum(t[1] + t[2] for t in TABLES if t[4] == "Analytics") * scale_primary
    basic_gb = sum(t[1] + t[2] for t in TABLES if t[4] == "Basic") * scale_primary
    dl_gb = sum(t[1] + t[2] for t in TABLES if t[4] == "Auxiliary") * scale_primary
    analytics_billable = sum(t[1] for t in TABLES if t[4] == "Analytics") * scale_primary
    basic_billable = sum(t[1] for t in TABLES if t[4] == "Basic") * scale_primary
    dl_billable = sum(t[1] for t in TABLES if t[4] == "Auxiliary") * scale_primary
    analytics_count = sum(1 for t in TABLES if t[4] == "Analytics")
    basic_count = sum(1 for t in TABLES if t[4] == "Basic")
    dl_count = sum(1 for t in TABLES if t[4] == "Auxiliary")

    q10b_data = [
        {
            "Tier": "Analytics",
            "TotalGB": round(analytics_gb, 3),
            "BillableGB": round(analytics_billable, 3),
            "TableCount": analytics_count,
            "PercentOfTotal": round(analytics_gb / TOTAL_GB * 100, 1),
            "TableName": "PrimaryResult",
        },
        {
            "Tier": "Data Lake",
            "TotalGB": round(dl_gb, 3),
            "BillableGB": round(dl_billable, 3),
            "TableCount": dl_count,
            "PercentOfTotal": round(dl_gb / TOTAL_GB * 100, 1),
            "TableName": "PrimaryResult",
        },
        {
            "Tier": "Basic",
            "TotalGB": round(basic_gb, 3),
            "BillableGB": round(basic_billable, 3),
            "TableCount": basic_count,
            "PercentOfTotal": round(basic_gb / TOTAL_GB * 100, 1),
            "TableName": "PrimaryResult",
        },
    ]
    write_json("ingestion-q10b.json", q10b_data)

    # ─── Q11: Rule health summary (deep-dive window) ────────────────
    enabled_rules = [r for r in RULE_TEMPLATES]
    nrt_count = sum(1 for r in RULE_TEMPLATES if r[1] == "NRT")
    scheduled_count = len(RULE_TEMPLATES) - nrt_count
    # 138 executions per rule in 7d reference window
    scaled_exec = int(138 * scale_deepdive)
    scaled_fail = int(47 * scale_deepdive)
    q11_data = {
        "TotalRules": len(RULE_TEMPLATES),
        "TotalExec": len(RULE_TEMPLATES) * scaled_exec,
        "TotalFail": scaled_fail,
        "FailingRules": 4,
        "NRTRules": nrt_count,
        "ScheduledRules": scheduled_count,
        "TableName": "PrimaryResult",
    }
    write_json("ingestion-q11.json", q11_data)

    # ─── Q11d: Failing rule details ──────────────────────────────────
    q11d_data = [
        {
            "SentinelResourceName": "NRT First access credential added to Application or Service Principal where no credential was present",
            "FailureCount": 23,
            "LastFailure": "2026-02-18 3:45:12 AM",
            "SampleError": "Rule's scheduled run at 02/18/2026 03:45:12 failed after numerous attempts. It will be re-executed over the next scheduled time.",
            "TableName": "PrimaryResult",
        },
        {
            "SentinelResourceName": "Suspicious process execution",
            "FailureCount": 12,
            "LastFailure": "2026-02-19 11:20:00 PM",
            "SampleError": "Semantic error: 'DeviceProcessEvents' failed to resolve column 'InitiatingProcessIntegrityLevel'.",
            "TableName": "PrimaryResult",
        },
        {
            "SentinelResourceName": "GCP privilege escalation",
            "FailureCount": 8,
            "LastFailure": "2026-02-20 6:15:30 AM",
            "SampleError": "Table 'GCPAuditLogs' has no data in the specified time range.",
            "TableName": "PrimaryResult",
        },
        {
            "SentinelResourceName": "Deprecated - Old brute force detection v1",
            "FailureCount": 4,
            "LastFailure": "2026-02-17 2:00:00 PM",
            "SampleError": "Rule execution timed out after 300 seconds.",
            "TableName": "PrimaryResult",
        },
    ]
    write_json("ingestion-q11d.json", q11d_data)

    # ─── Q12: Alert-producing rules (primary window) ──────────────
    alert_rules = [
        ("Brute force attack against user", 142, 0, 142, 0, 0, "Scheduled Alerts"),
        ("Sign-in from unknown IP", 89, 0, 89, 0, 0, "Scheduled Alerts"),
        ("Multiple failed sign-ins single user", 76, 0, 0, 76, 0, "Scheduled Alerts"),
        ("Application credential added", 64, 0, 0, 64, 0, "Scheduled Alerts"),
        ("Password spray attack detection", 53, 0, 0, 53, 0, "Scheduled Alerts"),
        ("Mailbox forwarding rule created", 41, 41, 0, 0, 0, "Scheduled Alerts"),
        ("SSH brute force attack", 38, 0, 38, 0, 0, "Scheduled Alerts"),
        ("Suspicious process execution", 35, 35, 0, 0, 0, "Scheduled Alerts"),
        ("IDS alert - critical severity", 28, 28, 0, 0, 0, "Scheduled Alerts"),
        ("Obfuscated PowerShell command", 22, 22, 0, 0, 0, "Scheduled Alerts"),
        ("Conditional Access policy modified", 19, 0, 0, 19, 0, "Scheduled Alerts"),
        ("Application ownership change", 15, 0, 0, 15, 0, "Scheduled Alerts"),
        ("C2 beaconing pattern detected", 12, 12, 0, 0, 0, "Scheduled Alerts"),
        ("Ransomware indicators detected", 8, 8, 0, 0, 0, "NRT Alerts"),
        ("Privileged service called", 6, 0, 0, 0, 6, "NRT Alerts"),
        ("Event logging shut down", 4, 4, 0, 0, 0, "NRT Alerts"),
        ("Directory role member added", 3, 0, 0, 0, 3, "NRT Alerts"),
        ("Token replay attack detection", 2, 2, 0, 0, 0, "NRT Alerts"),
    ]
    q12_data = []
    for name, count, high, med, low, info, component in alert_rules:
        sc = max(1, int(count * scale_primary))
        sh = max(0, int(high * scale_primary))
        sm = max(0, int(med * scale_primary))
        sl = max(0, int(low * scale_primary))
        si = max(0, int(info * scale_primary))
        q12_data.append({
            "AlertName": name,
            "AlertCount": sc,
            "HighSev": sh,
            "MediumSev": sm,
            "LowSev": sl,
            "InfoSev": si,
            "ProductComponentName": component,
            "RuleId": f"alert-rule-{hash(name) % 100000:05d}",
            "FirstAlert": "2026-01-22 08:15:00 AM",
            "LastAlert": "2026-02-19 11:45:00 PM",
            "TableName": "PrimaryResult",
        })
    write_json("ingestion-q12.json", q12_data)

    # ─── Q13: All tables with data (primary window) ───────────────
    q13_data = []
    for name, billable, nonbill, _, _, _ in TABLES:
        total = billable + nonbill
        if total > 0:
            q13_data.append({
                "DataType": name,
                "BillableGB": round(billable * scale_primary, 3),
                "TableName": "PrimaryResult",
            })
    q13_data.sort(key=lambda x: x["BillableGB"], reverse=True)
    write_json("ingestion-q13.json", q13_data)

    # ─── Q14: 24h ingestion anomalies ────────────────────────────────
    # Tables with significant deviations in the last 24h (values in GB)
    anomaly_24h = [
        ("StorageBlobLogs", 5.08, 2.34, 117),    # Big spike
        ("AWSCloudTrail", 1.76, 4.10, -57),       # Drop
        ("GCPAuditLogs", 0.27, 0.06, 352),           # Huge spike (small table)
        ("DeviceRegistryEvents", 2.05, 1.51, 35), # Moderate increase
        ("DeviceNetworkEvents", 8.30, 7.42, 12),  # Slight increase
        ("AzureDiagnostics", 1.37, 2.05, -33),    # Drop
        ("SecurityEvent_Aux_CL", 0.41, 0.47, -12),  # Slight drop (DL table)
        ("OfficeActivity", 0.94, 4.68, -80),        # Severe drop → data loss signal (10 rules depend on this!)
        ("AppTraces", 4.29, 1.42, 202),              # Volume spike on zero-rule non-security table
    ]
    q14_data = []
    for dt, last24h, avg7d, dev in anomaly_24h:
        q14_data.append({
            "DataType": dt,
            "Last24hGB": last24h,
            "Avg7dDailyGB": avg7d,
            "DeviationPercent": dev,
            "TableName": "PrimaryResult",
        })
    write_json("ingestion-q14.json", q14_data)

    # ─── Q15: Period-over-period anomalies (deep-dive window) ─────
    anomaly_wow = [
        ("StorageBlobLogs", 18.07, 8.01, 125.6),
        ("GCPAuditLogs", 1.91, 0.42, 355.8),
        ("AzureActivity", 60.55, 52.73, 14.8),
        ("CloudAppEvents", 23.93, 21.48, 11.4),
        ("AWSCloudTrail", 12.30, 17.77, -30.8),
        ("DeviceRegistryEvents", 10.55, 9.28, 13.7),
        ("AzureDiagnostics", 9.57, 14.36, -33.3),
        ("SentinelHealth", 0.61, 0.57, 6.9),
        ("OfficeActivity", 6.78, 43.12, -84.3),
    ]
    q15_data = []
    for dt, this_period, last_period, change in anomaly_wow:
        q15_data.append({
            "DataType": dt,
            "ThisWeekGB": round(this_period * scale_deepdive, 2),
            "LastWeekGB": round(last_period * scale_deepdive, 2),
            "ChangePercent": change,
            "DataType1": dt,
            "TableName": "PrimaryResult",
        })
    write_json("ingestion-q15.json", q15_data)

    # ─── Q16: Migration candidates ───────────────────────────────────
    # All billable tables for migration analysis (7-day MB volumes)
    q16_data = []
    for name, billable, _, _, _, _ in TABLES:
        if billable > 0:
            # 7-day GB = billable_gb_30d / 30 * 7
            gb_7d = round(billable / 30 * 7, 2)
            q16_data.append({
                "DataType": name,
                "BillableGB": gb_7d,
                "TableName": "PrimaryResult",
            })
    q16_data.sort(key=lambda x: x["BillableGB"], reverse=True)
    write_json("ingestion-q16.json", q16_data)

    # ─── Q17: License benefit analysis (primary window) ───────────
    # DfS P2: SecurityEvent only, pool = serverCount × 0.5 GB/day
    # E5: 29 specific table types
    # Daily averages are window-independent (GB/day from TABLES 30d base)
    se_daily_avg = 680.0 / 30  # SecurityEvent daily average
    e5_daily = sum(t[1] / 30 for t in TABLES if t[0] in E5_TABLES)

    q17_data = []
    for i in range(NUM_DAYS):
        day = BASE_DATE + timedelta(days=i)
        day_of_week = day.weekday()
        weekend = 0.82 if day_of_week >= 5 else 1.0

        total_day = daily_vols[i]  # From Q2
        dfsp2 = round(se_daily_avg * weekend * random.uniform(0.88, 1.12), 6)
        e5 = round(e5_daily * weekend * random.uniform(0.90, 1.10), 6)
        remaining = round(max(0, total_day - dfsp2 - e5), 6)

        q17_data.append({
            "Day": day.strftime("%Y-%m-%d 12:00:00 AM"),
            "TotalGB": round(total_day, 6),
            "DFSP2GB": dfsp2,
            "E5GB": e5,
            "RemainingGB": remaining,
            "TableName": "PrimaryResult",
        })
    write_json("ingestion-q17.json", q17_data)

    # ─── Q17b: E5-eligible per-table breakdown (primary window) ──
    q17b_data = []
    for name, billable, _, _, _, _ in TABLES:
        if name in E5_TABLES and billable > 0:
            q17b_data.append({
                "DataType": name,
                "VolumeGB": round(billable * scale_primary, 3),
                "TableName": "PrimaryResult",
            })
    q17b_data.sort(key=lambda x: x["VolumeGB"], reverse=True)
    write_json("ingestion-q17b.json", q17b_data)

    # ─── Summary ─────────────────────────────────────────────────────
    print()
    print(f"✅ Generated {len(os.listdir(OUTPUT_DIR))} files in {OUTPUT_DIR}")
    print(f"   Window: {args.days}d primary, {DEEP_DIVE_DAYS}d deep-dive")
    print(f"   Total: {TOTAL_GB:.1f} GB ({AVG_DAILY_GB:.1f} GB/day)")
    print(f"   Billable: {TOTAL_BILLABLE:.1f} GB, Non-Billable: {TOTAL_NON_BILLABLE:.1f} GB")
    print(f"   Analytic Rules: {len(RULE_TEMPLATES)} enabled + {len(DISABLED_RULES)} disabled = {len(RULE_TEMPLATES) + len(DISABLED_RULES)} total")
    print(f"   Custom Detections: {len(CUSTOM_DETECTION_RULES)} ({sum(1 for r in CUSTOM_DETECTION_RULES if r[1])} enabled)")
    print(f"   Servers: {num_servers} (Q4)")
    print(f"   DfS P2 Pool: {num_servers} × 0.5 = {num_servers * 0.5} GB/day")
    print(f"   E5-eligible tables: {len(q17b_data)}")
    print()
    print("Migration recommendation triggers:")
    print(f"   StorageBlobLogs: Analytics, 0 rules, DL-eligible → Sub-table 1 (DL candidate)")
    print(f"   AADManagedIdentitySignInLogs: Analytics, 0 rules, DL-eligible → Sub-table 1 (DL candidate)")
    print(f"   AWSCloudTrail: Data Lake, has rules → Detection gap")
    print(f"   AzureDiagnostics: Basic tier")
    print(f"   SecurityEvent_Aux_CL: Data Lake (KQL Job)")


if __name__ == "__main__":
    generate_all()
