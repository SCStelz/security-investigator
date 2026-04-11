"""
Security Investigator - Core Investigation Engine
Automates user security investigations across Microsoft Sentinel, Graph API, and threat intelligence sources
"""

import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
import os
from dataclasses import dataclass, asdict
from collections import defaultdict
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from exceptions import ConfigurationError, EnrichmentError


@dataclass
class InvestigationConfig:
    """Configuration for investigation"""
    sentinel_workspace_id: str
    tenant_id: str
    ipinfo_token: Optional[str] = None
    abuseipdb_token: Optional[str] = None
    output_dir: str = "reports"
    
    @classmethod
    def from_file(cls, path: str = "config.json"):
        """Load configuration from JSON file"""
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    config = json.load(f)
                    return cls(**config)
            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid JSON in config file {path}: {e}")
            except (TypeError, KeyError) as e:
                raise ConfigurationError(f"Invalid configuration structure in {path}: {e}")
        return cls(
            sentinel_workspace_id="",
            tenant_id=""
        )


@dataclass
class AnomalyFinding:
    """Represents a detected anomaly"""
    detected_date: str
    upn: str
    anomaly_type: str
    value: str
    severity: str
    country: str
    city: str
    country_novelty: bool
    city_novelty: bool
    artifact_hits: int
    first_seen: str


@dataclass
class IPIntelligence:
    """IP address enrichment data"""
    ip: str
    city: str
    region: str
    country: str
    org: str
    asn: str
    timezone: str
    risk_level: str
    assessment: str
    # AbuseIPDB fields
    abuse_confidence_score: int = 0
    is_whitelisted: bool = False
    total_reports: int = 0
    usage_type: str = "Unknown"
    isp: str = "Unknown"
    # VPN detection fields (vpnapi.io)
    is_vpn: bool = False
    vpn_network: str = "Unknown"
    # IP source category for color coding
    ip_category: str = "frequent"  # "anomaly", "risky", or "frequent"
    # Threat Intelligence fields (Sentinel ThreatIntelIndicators)
    threat_detected: bool = False
    threat_description: str = ""
    threat_confidence: int = 0
    threat_tlp_level: str = ""
    threat_activity_groups: str = ""
    # Anomaly context fields (for compact report)
    first_seen: str = ""
    last_seen: str = ""
    signin_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    anomaly_type: str = ""
    hit_count: int = 0
    categories: list = None
    # Authentication pattern field (from Query 2d)
    last_auth_result_detail: str = ""  # Last authenticationStepResultDetail for this IP


@dataclass
class UserProfile:
    """User identity information"""
    display_name: str
    upn: str
    job_title: str
    department: str
    office_location: str
    account_enabled: bool
    user_type: str


@dataclass
class MFAStatus:
    """MFA configuration details"""
    mfa_enabled: bool
    methods_count: int
    methods: List[str]
    has_fido2: bool
    has_authenticator: bool


@dataclass
class DeviceInfo:
    """Device registration details"""
    display_name: str
    operating_system: str
    trust_type: str
    is_compliant: bool
    approximate_last_sign_in: str


@dataclass
class RiskDetection:
    """Entra ID Identity Protection risk detection"""
    risk_event_type: str
    risk_state: str
    risk_level: str
    risk_detail: str
    detected_date: str
    last_updated: str
    activity: str
    ip_address: str
    location_city: str
    location_state: str
    location_country: str


@dataclass
class RiskySignIn:
    """Risky sign-in event from Entra ID"""
    sign_in_id: str
    created_date: str
    upn: str
    app_display_name: str
    ip_address: str
    location_city: str
    location_state: str
    location_country: str
    risk_state: str
    risk_level: str
    risk_event_types: List[str]
    risk_detail: str
    status_error_code: int
    status_failure_reason: str


@dataclass
class DLPEvent:
    """Data Loss Prevention event from Microsoft Defender for Cloud Apps"""
    time_generated: str
    user_id: str
    device_name: str
    client_ip: str
    rule_name: str
    file_name: str
    operation: str
    target_domain: str
    target_file_path: str
    severity: str = "High"  # DLP events are always high severity


@dataclass
class UserRiskProfile:
    """User's overall risk profile from Identity Protection"""
    risk_level: str
    risk_state: str
    risk_detail: str
    risk_last_updated: str
    is_deleted: bool
    is_processing: bool


@dataclass
class InvestigationResult:
    """Complete investigation results"""
    upn: str
    user_id: Optional[str]  # Azure AD User Object ID
    investigation_date: str
    start_date: str
    end_date: str
    
    # Findings
    anomalies: List[AnomalyFinding]
    ip_intelligence: List[IPIntelligence]
    user_profile: Optional[UserProfile]
    mfa_status: Optional[MFAStatus]
    devices: List[DeviceInfo]
    
    # Identity Protection (Entra ID)
    user_risk_profile: Optional[UserRiskProfile]
    risk_detections: List[RiskDetection]
    risky_signins: List[RiskySignIn]
    
    # Activity logs
    # Updated: allow summarized dict structure (by_application, by_location, failures, temporal_heatmap, totals)
    # Original implementation used a List[Dict] of raw events; investigations now pass a dict of aggregated lists.
    signin_events: Dict[str, Any]
    audit_events: List[Dict]
    office_events: List[Dict]
    security_alerts: List[Dict]
    dlp_events: List[DLPEvent]  # Data Loss Prevention events
    
    # Risk assessment
    risk_level: str
    risk_factors: List[str]
    mitigating_factors: List[str]
    
    # Recommendations
    critical_actions: List[str]
    high_priority_actions: List[str]
    monitoring_actions: List[str]
    
    # KQL queries used (for Copy KQL feature in reports)
    kql_queries: Optional[Dict[str, str]] = None
    
    # Result count metadata (for "Showing X of Y" indicators in reports)
    result_counts: Optional[Dict[str, Dict[str, int]]] = None
    # Expected structure: {
    #   'anomalies': {'displayed': 7, 'total': 36},
    #   'signin_by_application': {'displayed': 20, 'total': 90},
    #   'signin_by_location': {'displayed': 3, 'total': 3},
    #   'audit_events': {'displayed': 4, 'total': 4},
    #   'office_events': {'displayed': 10, 'total': 10},
    #   'security_alerts': {'displayed': 7, 'total': 7}
    # }
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class SecurityInvestigator:
    """Main investigation orchestrator"""
    
    def __init__(self, config: Optional[InvestigationConfig] = None):
        """Initialize investigator with configuration"""
        self.config = config or InvestigationConfig.from_file()
        self.session = requests.Session()
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
        self._slow_threshold = 10.0  # seconds per phase threshold

    def _timed(self, label: str, fn: Callable, *args, **kwargs):
        start = time.time()
        try:
            return fn(*args, **kwargs)
        finally:
            dur = time.time() - start
            print(f"⏱️  {label} completed in {dur:.2f}s")
            if dur > self._slow_threshold:
                print(f"⚠️  SLOW PHASE: {label} took {dur:.2f}s (>{self._slow_threshold}s threshold) – investigate query efficiency or network latency")
        
    def investigate_user(
        self, 
        upn: str, 
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        days_back: int = 7
    ) -> InvestigationResult:
        """
        Conduct complete security investigation for a user
        
        Args:
            upn: User principal name (email)
            start_date: Investigation start date (YYYY-MM-DD)
            end_date: Investigation end date (YYYY-MM-DD)
            days_back: Days to look back if dates not specified
            
        Returns:
            InvestigationResult with all findings
        """
        # Calculate date range
        if not end_date:
            end_date = datetime.now().strftime("%Y-%m-%d")
        if not start_date:
            start = datetime.now() - timedelta(days=days_back)
            start_date = start.strftime("%Y-%m-%d")
            
        print(f"🔍 Starting investigation for {upn}")
        print(f"📅 Date range: {start_date} to {end_date}")
        
        # Initialize result
        result = InvestigationResult(
            upn=upn,
            user_id=None,
            investigation_date=datetime.now().isoformat(),
            start_date=start_date,
            end_date=end_date,
            anomalies=[],
            ip_intelligence=[],
            user_profile=None,
            mfa_status=None,
            devices=[],
            user_risk_profile=None,
            risk_detections=[],
            risky_signins=[],
            signin_events={},
            audit_events=[],
            office_events=[],
            security_alerts=[],
            dlp_events=[],
            risk_level="Unknown",
            risk_factors=[],
            mitigating_factors=[],
            critical_actions=[],
            high_priority_actions=[],
            monitoring_actions=[]
        )
        
        # Phase 1: Query anomaly detection table
        print("\n📊 Phase 1: Querying anomaly detection table...")
        result.anomalies = self._timed('Phase 1 Anomalies', self._query_anomalies, upn, start_date, end_date)
        print(f"   Found {len(result.anomalies)} anomalies")
        
        # Phase 2: Get sign-in activity
        print("\n🔐 Phase 2: Analyzing sign-in activity...")
        result.signin_events = self._timed('Phase 2 Sign-in Activity', self._query_signin_logs, upn, days_back=1)
        print(f"   Found {len(result.signin_events)} sign-in events")
        
        # Phase 3: IP enrichment
        print("\n🌐 Phase 3: Enriching IP addresses...")
        unique_ips = self._timed('Extract IPs', self._extract_unique_ips, result.anomalies, result.signin_events)
        result.ip_intelligence = self._timed('Phase 3 IP Enrichment', self._enrich_ips, unique_ips)
        print(f"   Enriched {len(result.ip_intelligence)} IP addresses")
        
        # Phase 4: User identity & MFA & Identity Protection
        print("\n👤 Phase 4: Retrieving user profile, MFA status, and Identity Protection data...")
        result.user_profile = self._timed('User Profile', self._get_user_profile, upn)
        result.mfa_status = self._timed('MFA Status', self._get_mfa_status, upn)
        result.devices = self._timed('Devices', self._get_user_devices, upn)
        result.user_risk_profile = self._timed('User Risk Profile', self._get_user_risk_profile, upn)
        result.risk_detections = self._timed('Risk Detections', self._get_risk_detections, upn)
        result.risky_signins = self._timed('Risky Sign-ins', self._get_risky_signins, upn, start_date, end_date)
        print(f"   User: {result.user_profile.display_name if result.user_profile else 'Unknown'}")
        print(f"   MFA Methods: {result.mfa_status.methods_count if result.mfa_status else 0}")
        print(f"   Devices: {len(result.devices)}")
        print(f"   User Risk: {result.user_risk_profile.risk_level if result.user_risk_profile else 'Unknown'} ({result.user_risk_profile.risk_state if result.user_risk_profile else 'Unknown'})")
        print(f"   Risk Detections: {len(result.risk_detections)}")
        print(f"   Risky Sign-ins: {len(result.risky_signins)}")
        
        # Phase 5: Azure AD Audit logs
        print("\n📋 Phase 5: Querying Azure AD audit logs...")
        result.audit_events = self._timed('Phase 5 Audit Logs', self._query_audit_logs, upn, start_date, end_date)
        print(f"   Found {len(result.audit_events)} audit events")
        
        # Phase 6: Office 365 activity
        print("\n📧 Phase 6: Querying Office 365 activity...")
        result.office_events = self._timed('Phase 6 Office 365', self._query_office_activity, upn, start_date, end_date)
        print(f"   Found {len(result.office_events)} Office events")
        
        # Phase 7: Security alerts
        print("\n🚨 Phase 7: Querying security alerts...")
        result.security_alerts = self._timed('Phase 7 Security Alerts', self._query_security_alerts, upn, start_date, end_date)
        print(f"   Found {len(result.security_alerts)} security alerts")
        
        # Phase 8: Risk assessment
        print("\n⚖️  Phase 8: Performing risk assessment...")
        self._timed('Phase 8 Risk Assessment', self._assess_risk, result)
        print(f"   Risk Level: {result.risk_level}")
        
        # Phase 9: Generate recommendations
        print("\n🎯 Phase 9: Generating recommendations...")
        self._timed('Phase 9 Recommendations', self._generate_recommendations, result)
        print(f"   Critical actions: {len(result.critical_actions)}")
        print(f"   High priority: {len(result.high_priority_actions)}")
        
        print(f"\n✅ Investigation complete!")
        return result
    
    def _query_anomalies(self, upn: str, start_date: str, end_date: str) -> List[AnomalyFinding]:
        """Query Signinlogs_Anomalies_KQL_CL table (placeholder - uses MCP in practice)"""
        # This would use the Sentinel MCP server in practice
        # For now, return structure to show integration point
        print(f"   ⚠️  Requires Sentinel MCP: query_lake with Signinlogs_Anomalies_KQL_CL")
        return []
    
    def _query_signin_logs(self, upn: str, days_back: int = 1) -> List[Dict]:
        """Query SigninLogs table (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Sentinel MCP: query_lake with SigninLogs")
        return []
    
    def _query_audit_logs(self, upn: str, start_date: str, end_date: str) -> List[Dict]:
        """Query AuditLogs table (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Sentinel MCP: query_lake with AuditLogs")
        return []
    
    def _query_office_activity(self, upn: str, start_date: str, end_date: str) -> List[Dict]:
        """Query OfficeActivity table (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Sentinel MCP: query_lake with OfficeActivity")
        return []
    
    def _query_security_alerts(self, upn: str, start_date: str, end_date: str) -> List[Dict]:
        """Query SecurityAlert table (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Sentinel MCP: query_lake with SecurityAlert")
        return []
    
    def _get_user_profile(self, upn: str) -> Optional[UserProfile]:
        """Get user profile from Microsoft Graph (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Graph MCP: microsoft_graph_get for user profile")
        return None
    
    def _get_mfa_status(self, upn: str) -> Optional[MFAStatus]:
        """Get MFA status from Microsoft Graph (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Graph MCP: microsoft_graph_get for authentication methods")
        return None
    
    def _get_user_devices(self, upn: str) -> List[DeviceInfo]:
        """Get user devices from Microsoft Graph (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Graph MCP: microsoft_graph_get for registered devices")
        return []
    
    def _get_user_risk_profile(self, upn: str) -> Optional[UserRiskProfile]:
        """Get user risk profile from Identity Protection (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Graph MCP: microsoft_graph_get for /v1.0/identityProtection/riskyUsers/<USER_ID>")
        return None
    
    def _get_risk_detections(self, upn: str) -> List[RiskDetection]:
        """Get risk detections from Identity Protection (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Graph MCP: microsoft_graph_get for /v1.0/identityProtection/riskDetections")
        return []
    
    def _get_risky_signins(self, upn: str, start_date: str, end_date: str) -> List[RiskySignIn]:
        """Get risky sign-ins from Entra ID (placeholder - uses MCP in practice)"""
        print(f"   ⚠️  Requires Graph MCP: microsoft_graph_get for /beta/auditLogs/signIns with risk filters")
        return []
    
    def _extract_unique_ips(self, anomalies: List[AnomalyFinding], signin_events) -> List[str]:
        """Extract unique IP addresses from findings"""
        ips = set()
        
        # From anomalies
        for anomaly in anomalies:
            if self._is_ip_address(anomaly.value):
                ips.add(anomaly.value)
        
        # From sign-in events - handle both dict and list formats
        if isinstance(signin_events, dict):
            # New format: dict with by_location, by_application, etc.
            
            # Extract from by_location
            if 'by_location' in signin_events:
                for loc in signin_events['by_location']:
                    for ip in loc.get('IPAddresses', []):
                        ips.add(ip)
            
            # Extract from by_application
            if 'by_application' in signin_events:
                for app in signin_events['by_application']:
                    for ip in app.get('IPAddresses', []):
                        ips.add(ip)
                        
        elif isinstance(signin_events, list):
            # Old format: list of individual events
            for event in signin_events:
                if 'IPAddress' in event:
                    ips.add(event['IPAddress'])
        
        # Filter out IPv6
        return [ip for ip in ips if ':' not in ip]
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        import re
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, value))
    
    def _enrich_ips(self, ips: List[str]) -> List[IPIntelligence]:
        """Enrich IP addresses with ipinfo.io (parallel when list is large)"""
        if not ips:
            return []

        def enrich_single(ip: str) -> IPIntelligence:
            try:
                url = f"https://ipinfo.io/{ip}/json"
                headers = {"Accept": "application/json"}
                if self.config.ipinfo_token:
                    headers["Authorization"] = f"Bearer {self.config.ipinfo_token}"
                resp = self.session.get(url, headers=headers, timeout=5)
                data = resp.json() if resp.status_code == 200 else {}
                risk_level, assessment = self._assess_ip_risk(data, ip)
                return IPIntelligence(
                    ip=ip,
                    city=data.get('city', 'Unknown'),
                    region=data.get('region', 'Unknown'),
                    country=data.get('country', 'Unknown'),
                    org=data.get('org', 'Unknown'),
                    asn=data.get('org', 'Unknown').split()[0] if data.get('org') else 'Unknown',
                    timezone=data.get('timezone', 'Unknown'),
                    risk_level=risk_level,
                    assessment=assessment
                )
            except (requests.RequestException, ConnectionError) as e:
                return IPIntelligence(
                    ip=ip,
                    city="Error",
                    region="Error",
                    country="Error",
                    org="Error",
                    asn="Error",
                    timezone="Error",
                    risk_level="Unknown",
                    assessment=f"Enrichment failed: {str(e)}"
                )
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                return IPIntelligence(
                    ip=ip,
                    city="Error",
                    region="Error",
                    country="Error",
                    org="Error",
                    asn="Error",
                    timezone="Error",
                    risk_level="Unknown",
                    assessment=f"Enrichment data error: {str(e)}"
                )

        # Decide parallel vs sequential
        results: List[IPIntelligence] = []
        if len(ips) <= 5:
            for ip in ips:
                results.append(enrich_single(ip))
            return results

        max_workers = min(8, len(ips))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(enrich_single, ip): ip for ip in ips}
            for fut in as_completed(future_map):
                results.append(fut.result())
        return results
    
    def _assess_ip_risk(self, data: Dict, ip: str) -> tuple[str, str]:
        """Assess risk level for an IP address"""
        org = data.get('org', '').lower()
        
        # Microsoft infrastructure
        if 'microsoft' in org or 'azure' in org:
            return "LOW", "Microsoft Azure infrastructure"
        
        # Known ISPs
        if any(isp in org for isp in ['telus', 'comcast', 'verizon', 'att', 'rogers']):
            return "LOW", "Legitimate residential/business ISP"
        
        # VPN/Hosting providers
        if any(keyword in org for keyword in ['datacamp', 'hosting', 'vpn', 'proxy', 'cloud']):
            return "MEDIUM", "VPN/Cloud/Hosting provider - requires verification"
        
        return "MEDIUM", "Unknown organization - requires review"
    
    def _assess_risk(self, result: InvestigationResult):
        """Assess overall risk level and identify factors"""
        risk_score = 0
        
        # High-risk indicators
        for anomaly in result.anomalies:
            if anomaly.country_novelty:
                result.risk_factors.append(f"New country access: {anomaly.country}")
                risk_score += 3
            if anomaly.city_novelty:
                result.risk_factors.append(f"New city access: {anomaly.city}")
                risk_score += 2
        
        # IP intelligence
        for ip_intel in result.ip_intelligence:
            # Threat intelligence detection (HIGHEST PRIORITY)
            if ip_intel.threat_detected:
                result.risk_factors.append(
                    f"⚠️ Threat Intel Match: {ip_intel.ip} - {ip_intel.threat_description} "
                    f"(Confidence: {ip_intel.threat_confidence}%)"
                )
                risk_score += 5  # Highest weight for confirmed threat intel
            # Standard IP risk assessment
            elif ip_intel.risk_level == "HIGH":
                result.risk_factors.append(f"High-risk IP: {ip_intel.ip} ({ip_intel.assessment})")
                risk_score += 3
            elif ip_intel.risk_level == "MEDIUM":
                result.risk_factors.append(f"Suspicious IP: {ip_intel.ip} ({ip_intel.assessment})")
                risk_score += 1
        
        # Security alerts
        high_severity_alerts = [a for a in result.security_alerts if a.get('Severity', a.get('AlertSeverity')) == 'High']
        medium_severity_alerts = [a for a in result.security_alerts if a.get('Severity', a.get('AlertSeverity')) == 'Medium']
        
        if high_severity_alerts:
            result.risk_factors.append(f"{len(high_severity_alerts)} high-severity security alerts")
            risk_score += len(high_severity_alerts) * 2
        
        if medium_severity_alerts:
            result.risk_factors.append(f"{len(medium_severity_alerts)} medium-severity security alerts")
            risk_score += len(medium_severity_alerts)
        
        # Identity Protection risk detections
        active_risks = [r for r in result.risk_detections if r.risk_state in ['atRisk', 'confirmedCompromised']]
        if active_risks:
            high_risk_detections = [r for r in active_risks if r.risk_level in ['high', 'medium']]
            if high_risk_detections:
                result.risk_factors.append(f"{len(high_risk_detections)} active identity risk detections")
                risk_score += len(high_risk_detections) * 2
        
        # User risk profile
        if result.user_risk_profile:
            if result.user_risk_profile.risk_state == 'confirmedCompromised':
                result.risk_factors.append("User account confirmed compromised in Identity Protection")
                risk_score += 10
            elif result.user_risk_profile.risk_state == 'atRisk':
                if result.user_risk_profile.risk_level in ['high', 'medium']:
                    result.risk_factors.append(f"User at risk (Identity Protection: {result.user_risk_profile.risk_level})")
                    risk_score += 3 if result.user_risk_profile.risk_level == 'high' else 2
        
        # Mitigating factors
        if result.mfa_status and result.mfa_status.mfa_enabled:
            result.mitigating_factors.append("MFA enabled with multiple methods")
            risk_score -= 2
        
        if result.mfa_status and result.mfa_status.has_fido2:
            result.mitigating_factors.append("FIDO2 security key registered (phishing-resistant)")
            risk_score -= 1
        
        # Determine risk level
        if risk_score >= 8:
            result.risk_level = "CRITICAL"
        elif risk_score >= 5:
            result.risk_level = "HIGH"
        elif risk_score >= 3:
            result.risk_level = "MEDIUM"
        elif risk_score >= 1:
            result.risk_level = "LOW"
        else:
            result.risk_level = "INFO"
    
    def _generate_recommendations(self, result: InvestigationResult):
        """Generate actionable recommendations"""
        
        # Critical actions
        if any("New country" in factor for factor in result.risk_factors):
            result.critical_actions.append(
                "Contact user immediately to verify international access or VPN usage"
            )
        
        if any("policy" in alert.get('AlertName', '').lower() for alert in result.security_alerts):
            result.critical_actions.append(
                "Review and validate all Conditional Access policy modifications"
            )
        
        # High priority
        if result.mfa_status and not result.mfa_status.has_fido2:
            result.high_priority_actions.append(
                "Register FIDO2 security key for phishing-resistant authentication"
            )
        
        non_compliant = [d for d in result.devices if not d.is_compliant]
        if len(non_compliant) > 0:
            result.high_priority_actions.append(
                f"Enforce compliance on {len(non_compliant)} non-compliant devices"
            )
        
        # Monitoring actions
        result.monitoring_actions.append(
            f"Enhanced monitoring for {result.upn} - flag any new anomalies for 14 days"
        )
        
        if result.ip_intelligence:
            suspicious_ips = [ip for ip in result.ip_intelligence if ip.risk_level in ["HIGH", "MEDIUM"]]
            if suspicious_ips:
                result.monitoring_actions.append(
                    f"Monitor for additional access from suspicious IPs: {', '.join([ip.ip for ip in suspicious_ips])}"
                )


def main():
    """Example usage"""
    config = InvestigationConfig(
        sentinel_workspace_id="YOUR_WORKSPACE_ID_HERE",
        tenant_id="your-tenant-id",
        ipinfo_token=None  # Optional
    )
    
    investigator = SecurityInvestigator(config)
    
    # Run investigation
    result = investigator.investigate_user(
        upn="user@domain.com",
        days_back=7
    )
    
    # Save results
    output_file = f"investigation_{result.upn.split('@')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(result.to_dict(), f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")
    print(f"📊 Risk Level: {result.risk_level}")
    print(f"🚨 Risk Factors: {len(result.risk_factors)}")
    print(f"✅ Mitigating Factors: {len(result.mitigating_factors)}")


if __name__ == "__main__":
    main()
