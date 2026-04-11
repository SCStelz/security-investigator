"""
Generate COMPACT investigation report from JSON data file.

Usage:
    python generate_compact_report.py <json_file_path> [--force-enrich]

Example:
    python generate_compact_report.py temp/investigation_user_20251126_150214.json
    python generate_compact_report.py temp/investigation_user_20251126_150214.json --force-enrich

Options:
    --force-enrich    Force fresh IP enrichment even if cached data exists
"""

import json
import sys
import logging
from pathlib import Path
from investigator import InvestigationResult, AnomalyFinding, IPIntelligence, UserProfile, MFAStatus, DeviceInfo, RiskDetection, RiskySignIn, UserRiskProfile, DLPEvent
from report_generator import CompactReportGenerator
from datetime import datetime, timedelta
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from exceptions import ConfigurationError, EnrichmentError, DataValidationError, ReportGenerationError

logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from config.json."""
    config_path = Path(__file__).parent / 'config.json'
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in config file {config_path}: {e}")
    return {}

def enrich_ip_abuseipdb(ip: str, api_key: str) -> dict:
    """Get IP reputation data from AbuseIPDB."""
    if not api_key:
        return None
    
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        
        if resp.status_code == 200:
            return resp.json().get('data', {})
        elif resp.status_code == 429:
            print(f"⚠️  AbuseIPDB rate limit exceeded for {ip} (1000 requests/day limit)")
            return None
        return None
    except (requests.RequestException, ConnectionError):
        return None
    except (json.JSONDecodeError, KeyError):
        return None

def enrich_ip(ip: str, config: dict = None) -> IPIntelligence:
    """Enrich IP address with geolocation and risk assessment from multiple sources."""
    if config is None:
        config = load_config()
    
    try:
        # Get ipinfo.io data
        ipinfo_token = config.get('ipinfo_token')
        if ipinfo_token:
            url = f"https://ipinfo.io/{ip}/json?token={ipinfo_token}"
        else:
            url = f"https://ipinfo.io/{ip}/json"
        headers = {"Accept": "application/json"}
        resp = requests.get(url, headers=headers, timeout=5)
        
        # Handle rate limiting gracefully - don't use error response as data
        if resp.status_code == 429:
            print(f"⚠️  ipinfo.io rate limit exceeded for {ip}")
            data = {}
        elif resp.status_code == 200:
            data = resp.json()
        else:
            data = {}
        
        org = data.get('org', 'Unknown')
        risk_level = "LOW"
        assessment_parts = []
        
        # Get AbuseIPDB data
        abuse_data = None
        abuseipdb_key = config.get('abuseipdb_token')
        if abuseipdb_key:
            abuse_data = enrich_ip_abuseipdb(ip, abuseipdb_key)
        
        # Analyze AbuseIPDB data
        abuse_score = 0
        total_reports = 0
        is_whitelisted = False
        
        if abuse_data:
            abuse_score = abuse_data.get('abuseConfidenceScore', 0)
            total_reports = abuse_data.get('totalReports', 0)
            is_whitelisted = abuse_data.get('isWhitelisted', False)
            
            # Adjust risk level based on AbuseIPDB score
            if is_whitelisted:
                assessment_parts.append("✓ Whitelisted by AbuseIPDB")
            elif abuse_score >= 75:
                risk_level = "HIGH"
                assessment_parts.append(f"⚠️ AbuseIPDB: {abuse_score}% abuse confidence ({total_reports} reports)")
            elif abuse_score >= 25:
                risk_level = "MEDIUM"
                assessment_parts.append(f"⚠️ AbuseIPDB: {abuse_score}% abuse confidence ({total_reports} reports)")
            elif total_reports > 0:
                assessment_parts.append(f"AbuseIPDB: {total_reports} reports, {abuse_score}% confidence")
            else:
                assessment_parts.append("✓ No abuse reports in AbuseIPDB")
        
        # Analyze ipinfo.io data
        if "hosting" in org.lower() or "vpn" in org.lower() or "proxy" in org.lower():
            if risk_level == "LOW":
                risk_level = "MEDIUM"
            assessment_parts.append("Hosting/VPN/Proxy provider - monitor for suspicious activity")
        elif "cloud" in org.lower() or "amazon" in org.lower() or "microsoft" in org.lower() or "google" in org.lower():
            if not assessment_parts:
                assessment_parts.append("Major cloud provider - legitimate service")
        elif "telecom" in org.lower() or "communications" in org.lower() or "telus" in org.lower() or "comcast" in org.lower():
            if not assessment_parts:
                assessment_parts.append("Legitimate residential ISP")
        
        # Build final assessment
        if not assessment_parts:
            assessment_parts.append("Legitimate ISP")
        
        assessment = " | ".join(assessment_parts)
        
        # Create IPIntelligence object with AbuseIPDB data
        ip_intel = IPIntelligence(
            ip=ip,
            city=data.get('city', 'Unknown'),
            region=data.get('region', 'Unknown'),
            country=data.get('country', 'Unknown'),
            org=data.get('org', 'Unknown'),
            asn=data.get('org', 'Unknown').split()[0] if data.get('org') else 'Unknown',
            timezone=data.get('timezone', 'Unknown'),
            risk_level=risk_level,
            assessment=assessment,
            abuse_confidence_score=abuse_score,
            is_whitelisted=is_whitelisted,
            total_reports=total_reports
        )
        
        # Get VPN detection data from vpnapi.io
        vpnapi_token = config.get('vpnapi_token')
        if vpnapi_token:
            try:
                vpn_response = requests.get(f"https://vpnapi.io/api/{ip}?key={vpnapi_token}", timeout=5)
                if vpn_response.status_code == 429:
                    print(f"⚠️  vpnapi.io rate limit exceeded for {ip}")
                    raise EnrichmentError("Rate limit", status_code=429, service="vpnapi.io")
                vpn_response.raise_for_status()
                vpn_data = vpn_response.json()
                
                # Extract VPN detection results
                if vpn_data:
                    security_info = vpn_data.get('security', {})
                    ip_intel.is_vpn = security_info.get('vpn', False)
                    ip_intel.vpn_network = vpn_data.get('network', {}).get('network', 'Unknown')
                    
                    # Adjust risk assessment if VPN detected
                    org_lower = org.lower()
                    is_major_cloud = any(provider in org_lower for provider in ['microsoft', 'azure', 'amazon', 'aws', 'google', 'gcp', 'cloudflare', 'akamai', 'fastly', 'oracle cloud'])
                    
                    if ip_intel.is_vpn and not is_major_cloud:
                        if ip_intel.risk_level == "LOW":
                            ip_intel.risk_level = "MEDIUM"
            except (requests.RequestException, ConnectionError, EnrichmentError):
                pass
            except (json.JSONDecodeError, KeyError):
                pass
        
        return ip_intel
        
    except (requests.RequestException, ConnectionError) as e:
        return IPIntelligence(
            ip=ip, city="Error", region="Error", country="Error",
            org="Error", asn="Error", timezone="Error",
            risk_level="Unknown", assessment=f"Enrichment failed: {str(e)}"
        )
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        return IPIntelligence(
            ip=ip, city="Error", region="Error", country="Error",
            org="Error", asn="Error", timezone="Error",
            risk_level="Unknown", assessment=f"Enrichment data error: {str(e)}"
        )

def main():
    if len(sys.argv) < 2:
        print("❌ Error: Missing JSON file path")
        print("\nUsage: python generate_compact_report.py <json_file_path> [--force-enrich]")
        print("Example: python generate_compact_report.py temp/investigation_user_20251126_150214.json")
        sys.exit(1)
    
    json_file = Path(sys.argv[1])
    force_enrich = '--force-enrich' in sys.argv
    
    if not json_file.exists():
        print(f"❌ Error: File not found: {json_file}")
        sys.exit(1)
    
    # Load ALL data from JSON file
    print(f"📂 Loading investigation data from {json_file.name}...")
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Check for cached IP enrichment data
    has_cached_enrichment = 'ip_enrichment' in data and 'enrichment_metadata' in data
    if has_cached_enrichment and not force_enrich:
        enriched_at = data['enrichment_metadata'].get('last_enriched', 'unknown')
        ip_count = data['enrichment_metadata'].get('ip_count', 0)
        print(f"✓ Using cached IP enrichment from {enriched_at} ({ip_count} IPs)")
        print(f"  Tip: Use --force-enrich to refresh IP enrichment data")
    elif has_cached_enrichment and force_enrich:
        print(f"🔄 Force refresh requested - will re-enrich all IPs")
    
    # Extract data sections
    anomalies_data = data.get('anomalies', [])
    signin_apps_data = data.get('signin_apps', [])
    signin_locations_data = data.get('signin_locations', [])
    signin_failures_data = data.get('signin_failures', [])
    signin_ip_counts_data = data.get('signin_ip_counts', [])  # NEW: Per-IP sign-in counts
    audit_events_data = data.get('audit_events', [])
    office_data = data.get('office_events', [])
    dlp_data = data.get('dlp_events', [])
    incidents_data = data.get('incidents', [])
    user_profile_data = data.get('user_profile')
    mfa_data = data.get('mfa_methods')
    devices_data = data.get('devices', [])
    risk_profile_data = data.get('risk_profile')
    risk_detections_data = data.get('risk_detections', [])
    risky_signins_data = data.get('risky_signins', [])
    
    # Transform JSON → dataclasses
    result = InvestigationResult(
        upn=data['upn'],
        user_id=data.get('user_id'),  # Azure AD Object ID
        investigation_date=data['investigation_date'],
        start_date=data['start_date'],
        end_date=data['end_date'],
        anomalies=[AnomalyFinding(
            detected_date=a['DetectedDateTime'],
            upn=a['UserPrincipalName'],
            anomaly_type=a['AnomalyType'],
            value=a['Value'],
            severity=a['Severity'],
            country=a['Country'],
            city=a['City'],
            country_novelty=a['CountryNovelty'],
            city_novelty=a['CityNovelty'],
            artifact_hits=a['ArtifactHits'],
            first_seen=a['FirstSeenRecent']
        ) for a in anomalies_data],
        ip_intelligence=[],  # Will be populated via IP enrichment
        user_profile=UserProfile(
            display_name=user_profile_data['displayName'],
            upn=user_profile_data['userPrincipalName'],
            job_title=user_profile_data['jobTitle'],
            department=user_profile_data['department'],
            office_location=user_profile_data['officeLocation'],
            account_enabled=user_profile_data['accountEnabled'],
            user_type=user_profile_data['userType']
        ) if user_profile_data else None,
        mfa_status=None,  # Will be transformed below
        devices=[DeviceInfo(
            display_name=d['displayName'],
            operating_system=d['operatingSystem'],
            trust_type=d['trustType'],
            is_compliant=d['isCompliant'],
            approximate_last_sign_in=d['approximateLastSignInDateTime'][:10]
        ) for d in devices_data],
        user_risk_profile=UserRiskProfile(
            risk_level=risk_profile_data['riskLevel'],
            risk_state=risk_profile_data['riskState'],
            risk_detail=risk_profile_data['riskDetail'],
            risk_last_updated=risk_profile_data['riskLastUpdatedDateTime'],
            is_deleted=risk_profile_data['isDeleted'],
            is_processing=risk_profile_data['isProcessing']
        ) if risk_profile_data else None,
        risk_detections=[RiskDetection(
            risk_event_type=rd['riskEventType'],
            risk_state=rd['riskState'],
            risk_level=rd['riskLevel'],
            risk_detail=rd['riskDetail'],
            detected_date=rd['detectedDateTime'],
            last_updated=rd.get('lastUpdatedDateTime', rd['detectedDateTime']),  # Fallback to detectedDateTime if not present
            activity=rd['activity'],
            ip_address=rd['ipAddress'],
            location_city=rd['location']['city'],
            location_state=rd['location']['state'],
            location_country=rd['location']['countryOrRegion']
        ) for rd in risk_detections_data],
        risky_signins=[RiskySignIn(
            sign_in_id=rs['id'],
            created_date=rs['createdDateTime'],
            upn=rs['userPrincipalName'],
            app_display_name=rs['appDisplayName'],
            ip_address=rs['ipAddress'],
            location_city=rs['location']['city'],
            location_state=rs['location']['state'],
            location_country=rs['location']['countryOrRegion'],
            risk_state=rs['riskState'],
            risk_level=rs['riskLevelDuringSignIn'],
            risk_event_types=rs['riskEventTypes_v2'],
            risk_detail=rs['riskDetail'],
            status_error_code=rs['status']['errorCode'],
            status_failure_reason=rs['status']['failureReason']
        ) for rs in risky_signins_data],
        signin_events={},  # Will build below
        audit_events=audit_events_data,
        office_events=office_data,
        dlp_events=[DLPEvent(
            time_generated=d['TimeGenerated'],
            user_id=d['UserId'],
            device_name=d['DeviceName'],
            client_ip=d['ClientIP'],
            rule_name=d['RuleName'],
            file_name=d['File'],
            operation=d['Operation'],
            target_domain=d.get('TargetDomain', ''),
            target_file_path=d.get('TargetFilePath', '')
        ) for d in dlp_data],
        security_alerts=[],  # Will build with deduplication
        risk_level="MEDIUM",
        risk_factors=[],
        mitigating_factors=[],
        critical_actions=[],
        high_priority_actions=[],
        monitoring_actions=[]
    )
    
    # Transform MFA methods
    # Handle both raw Graph API format ('value' key) and processed format ('methods' key)
    if mfa_data:
        if 'value' in mfa_data:
            # Raw Graph API response format
            methods = [m['@odata.type'].split('.')[-1] for m in mfa_data['value']]
        elif 'methods' in mfa_data:
            # Processed format (from MCP tool output)
            methods = [m['type'] + 'AuthenticationMethod' for m in mfa_data['methods']]
        else:
            methods = []
        
        if methods:
            # Check if user is a guest account (MFA managed by home tenant)
            is_guest = user_profile_data.get('userType', '') == 'Guest'
            
            # For guest accounts, check if MFA is being used via sign-in auth patterns
            mfa_via_token = False
            if is_guest and signin_ip_counts_data:
                # Check if all/most sign-ins show MFA via token (external tenant MFA)
                mfa_signin_count = sum(1 for ip in signin_ip_counts_data 
                                       if 'MFA requirement satisfied' in ip.get('LastAuthResultDetail', ''))
                total_signin_ips = len(signin_ip_counts_data)
                # If 80%+ of IPs show MFA via token, consider MFA enabled (managed externally)
                if total_signin_ips > 0 and (mfa_signin_count / total_signin_ips) >= 0.8:
                    mfa_via_token = True
            
            result.mfa_status = MFAStatus(
                mfa_enabled=(len(methods) > 1) or mfa_via_token,  # Local MFA OR guest with external MFA
                methods_count=len(methods),
                methods=methods,
                has_fido2=any('fido2' in m.lower() or 'passkey' in m.lower() for m in methods),
                has_authenticator=any('authenticator' in m.lower() for m in methods)
            )
    
    # Build signin_events dict
    # Use signin_ip_counts for accurate total counts (includes ALL IPs, not just top 5 apps)
    total_signins_from_ips = sum(ip.get('SignInCount', 0) for ip in signin_ip_counts_data)
    total_failures_from_failures = sum(f.get('FailureCount', 0) for f in signin_failures_data)
    
    result.signin_events = {
        'by_application': signin_apps_data,
        'applications': signin_apps_data,  # CRITICAL: Add this mapping for Top Applications section
        'by_location': signin_locations_data,
        'locations': signin_locations_data,  # CRITICAL: Add this mapping for Top Locations section
        'failures': signin_failures_data,
        'total_signins': total_signins_from_ips if total_signins_from_ips > 0 else sum(app.get('SignInCount', 0) for app in signin_apps_data),  # Prefer IP counts, fallback to app counts
        'total_success': total_signins_from_ips - total_failures_from_failures if total_signins_from_ips > 0 else sum(app.get('SuccessCount', 0) for app in signin_apps_data),
        'total_failures': total_failures_from_failures
    }
    
    # Transform incidents data (no deduplication needed - KQL query handles this)
    result.security_incidents = []
    for inc in incidents_data:
        result.security_incidents.append({
            'IncidentNumber': inc.get('IncidentNumber', inc.get('ProviderIncidentId', 'N/A')),  # Fallback to ProviderIncidentId if IncidentNumber not present
            'ProviderIncidentId': inc.get('ProviderIncidentId', 'N/A'),
            'Title': inc['Title'],
            'Severity': inc['Severity'],
            'Status': inc['Status'],
            'CreatedTime': inc['CreatedTime'],
            'ProviderIncidentUrl': inc.get('ProviderIncidentUrl', ''),
            'OwnerUPN': inc.get('OwnerUPN', 'Unassigned'),
            'AlertCount': inc.get('AlertCount', 1),
            # Keep legacy keys for compatibility
            'incident_number': inc.get('IncidentNumber', inc.get('ProviderIncidentId', 'N/A')),
            'title': inc['Title'],
            'severity': inc['Severity'],
            'status': inc['Status'],
            'created_time': inc['CreatedTime']
        })
    
    # Already sorted by CreatedTime desc from KQL query
    
    # 🌐 IP ENRICHMENT (Use deterministic list from Query 1 → Query 3d)
    print(f"\n🌐 Enriching IP addresses...")
    
    # Get config
    config = load_config()
    
    # Build threat intel map for risk assessment
    threat_intel_map = {}
    for threat_intel in data.get('threat_intel_ips', []):
        ip = threat_intel.get('IPAddress', '')
        if ip:
            threat_intel_map[ip] = threat_intel
    
    # Use signin_ip_counts as source of truth (comes from Query 1 → Query 3d pipeline)
    signin_ip_counts_data = data.get('signin_ip_counts', [])
    signin_ip_frequency = {}
    signin_ip_timeline = {}
    signin_ip_auth_pattern = {}
    signin_ip_success_failure = {}
    
    # Extract all IP data from signin_ip_counts (Query 3d results)
    collected_ips = []
    for entry in signin_ip_counts_data:
        ip = entry.get('IPAddress')
        count = entry.get('SignInCount', 0)
        success_count = entry.get('SuccessCount', 0)
        failure_count = entry.get('FailureCount', 0)
        first_seen = entry.get('FirstSeen')
        last_seen = entry.get('LastSeen')
        last_auth_detail = entry.get('LastAuthResultDetail', '')
        if ip:
            collected_ips.append(ip)
            signin_ip_frequency[ip] = count
            signin_ip_success_failure[ip] = {'SuccessCount': success_count, 'FailureCount': failure_count}
            if first_seen and last_seen:
                signin_ip_timeline[ip] = {'FirstSeen': first_seen, 'LastSeen': last_seen}
            if last_auth_detail:
                signin_ip_auth_pattern[ip] = last_auth_detail
    
    # Calculate percentile-based frequency thresholds for badge assignment
    if signin_ip_frequency:
        counts = sorted(signin_ip_frequency.values(), reverse=True)
        p90_index = max(0, int(len(counts) * 0.10) - 1)  # Top 10%
        p75_index = max(0, int(len(counts) * 0.25) - 1)  # 75th percentile
        
        high_freq_threshold = counts[p90_index] if p90_index < len(counts) else 0
        active_threshold = counts[p75_index] if p75_index < len(counts) else 0
        
        # Calculate recency cutoff (7 days before end of investigation period)
        try:
            investigation_end = datetime.fromisoformat(data['end_date'])
            recency_cutoff = investigation_end - timedelta(days=7)
        except (ValueError, KeyError):
            recency_cutoff = datetime.now() - timedelta(days=7)
        
        print(f"\n📊 Frequency thresholds: High (≥{high_freq_threshold}), Active (≥{active_threshold} + recent)")
    else:
        high_freq_threshold = 0
        active_threshold = 0
        recency_cutoff = None
    
    # Assign categories based on threat intel, anomalies, risky signins, and frequency
    ip_categories = {}
    for ip in collected_ips:
        ip_categories[ip] = []
        
        # Check threat intel
        if ip in threat_intel_map:
            ip_categories[ip].append('threat')
        
        # Check anomalies
        for anomaly in result.anomalies:
            if anomaly.anomaly_type.endswith('IP') and anomaly.value == ip:
                if 'anomaly' not in ip_categories[ip]:
                    ip_categories[ip].append('anomaly')
                break
        
        # Check risky signins/detections
        for risky_signin in result.risky_signins:
            if risky_signin.ip_address == ip:
                if 'risky' not in ip_categories[ip]:
                    ip_categories[ip].append('risky')
                break
        
        for risk_detection in result.risk_detections:
            if risk_detection.ip_address == ip:
                if 'risky' not in ip_categories[ip]:
                    ip_categories[ip].append('risky')
                break
        
        # Assign frequency badge
        count = signin_ip_frequency.get(ip, 0)
        is_recent = False
        if recency_cutoff and ip in signin_ip_timeline:
            last_seen_str = signin_ip_timeline[ip].get('LastSeen', '')
            if last_seen_str:
                try:
                    last_seen_dt = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00').replace('+00:00', ''))
                    is_recent = last_seen_dt >= recency_cutoff
                except (ValueError, AttributeError):
                    pass
        
        if count >= high_freq_threshold:
            ip_categories[ip].append('primary')
        elif count >= active_threshold and is_recent:
            ip_categories[ip].append('active')
    
    # Build location map from signin_locations (fallback for IPs without geolocation data)
    ip_location_map = {}
    signin_locations_data = data.get('signin_locations', [])
    for loc_entry in signin_locations_data:
        location = loc_entry.get('Location', '')
        for ip in loc_entry.get('IPAddresses', []):
            if ip not in ip_location_map and location:
                ip_location_map[ip] = location
    
    # 🚀 IP ENRICHMENT (cached or fresh)
    result.ip_intelligence = []
    
    # Use cached enrichment if available and not forcing refresh
    if has_cached_enrichment and not force_enrich:
        print(f"\n📦 Loading {len(collected_ips)} IP addresses from cache...")
        cached_enrichment = {item['ip']: item for item in data['ip_enrichment']}
        
        for ip in collected_ips:
            if ip in cached_enrichment:
                cached_data = cached_enrichment[ip]
                ip_intel = IPIntelligence(
                    ip=ip,
                    city=cached_data.get('city', 'Unknown'),
                    region=cached_data.get('region', 'Unknown'),
                    country=cached_data.get('country', 'Unknown'),
                    org=cached_data.get('org', 'Unknown'),
                    asn=cached_data.get('asn', 'Unknown'),
                    timezone=cached_data.get('timezone', 'Unknown'),
                    risk_level=cached_data.get('risk_level', 'LOW'),
                    assessment=cached_data.get('assessment', '')
                )
                ip_intel.categories = ip_categories.get(ip, [])
                ip_intel.is_vpn = cached_data.get('is_vpn', False)
                ip_intel.is_proxy = cached_data.get('is_proxy', False)
                ip_intel.is_tor = cached_data.get('is_tor', False)
                ip_intel.is_hosting = cached_data.get('is_hosting', False)
                ip_intel.abuse_confidence_score = cached_data.get('abuse_confidence_score', 0)
                ip_intel.total_reports = cached_data.get('total_reports', 0)
                ip_intel.is_whitelisted = cached_data.get('is_whitelisted', False)
                ip_intel.threat_description = cached_data.get('threat_description', '')
                ip_intel.anomaly_type = cached_data.get('anomaly_type', '')
                ip_intel.first_seen = cached_data.get('first_seen', '')
                ip_intel.last_seen = cached_data.get('last_seen', '')
                ip_intel.hit_count = cached_data.get('hit_count', 0)
                ip_intel.signin_count = cached_data.get('signin_count', 0)
                ip_intel.success_count = cached_data.get('success_count', 0)
                ip_intel.failure_count = cached_data.get('failure_count', 0)
                ip_intel.last_auth_result_detail = cached_data.get('last_auth_result_detail', '')
                result.ip_intelligence.append(ip_intel)
                print(f"  ✓ {ip} (cached)")
            else:
                print(f"  ⚠ {ip} - not in cache, skipping")
    else:
        # Perform fresh IP enrichment
        print(f"\n🌐 Enriching {len(collected_ips)} IP addresses in parallel...")
        
        def enrich_single_ip(ip):
            """Enrich a single IP and return tuple of (ip, ip_intel)"""
            ip_intel = enrich_ip(ip, config)
        
            # Add categories
            ip_intel.categories = ip_categories.get(ip, [])
        
            # Add threat intel data if available and upgrade risk level
            if ip in threat_intel_map:
                threat_data = threat_intel_map[ip]
                ip_intel.threat_description = threat_data.get('ThreatDescription', '')
                # Threat intel match = HIGH risk (confirmed malicious activity)
                ip_intel.risk_level = "HIGH"
                ip_intel.assessment = f"⚠️ Threat Intelligence Match: {ip_intel.threat_description}"
        
            # Find anomaly data for this IP - prioritize Interactive over NonInteractive
            anomaly_found = False
            selected_anomaly = None
        
            for anomaly in result.anomalies:
                if anomaly.value == ip:
                    if selected_anomaly is None:
                        selected_anomaly = anomaly
                    # Prefer Interactive over NonInteractive when both exist
                    elif 'Interactive' in anomaly.anomaly_type and 'NonInteractive' not in anomaly.anomaly_type:
                        selected_anomaly = anomaly
        
            if selected_anomaly:
                ip_intel.anomaly_type = selected_anomaly.anomaly_type
                ip_intel.first_seen = selected_anomaly.detected_date.split('T')[0] if 'T' in selected_anomaly.detected_date else selected_anomaly.detected_date
                ip_intel.hit_count = selected_anomaly.artifact_hits
                anomaly_found = True
            
                # Override location data from anomaly if available (more accurate than ipinfo.io)
                if hasattr(selected_anomaly, 'city') and selected_anomaly.city:
                    ip_intel.city = selected_anomaly.city
                if hasattr(selected_anomaly, 'state') and selected_anomaly.state:
                    ip_intel.region = selected_anomaly.state
                if hasattr(selected_anomaly, 'country') and selected_anomaly.country:
                    ip_intel.country = selected_anomaly.country
        
            # If not an anomaly, populate first_seen from risky signin or frequent signin data
            if not anomaly_found:
                # Check risky signins for this IP
                risky_dates = []
                risky_location_data = None
                for risky_signin in result.risky_signins:
                    if risky_signin.ip_address == ip:
                        risky_dates.append(risky_signin.created_date)
                        # Store location data from first matching risky signin
                        if risky_location_data is None:
                            risky_location_data = {
                                'city': risky_signin.location_city,
                                'state': risky_signin.location_state,
                                'country': risky_signin.location_country
                            }
            
                # Check risk detections for this IP
                for risk_detection in result.risk_detections:
                    if risk_detection.ip_address == ip:
                        risky_dates.append(risk_detection.detected_date)
                        # Store location data from first matching risk detection
                        if risky_location_data is None:
                            risky_location_data = {
                                'city': risk_detection.location_city,
                                'state': risk_detection.location_state,
                                'country': risk_detection.location_country
                            }
            
                # Use earliest risky date if found
                if risky_dates:
                    earliest_risky = min(risky_dates)
                    latest_risky = max(risky_dates)
                    ip_intel.first_seen = earliest_risky.split('T')[0] if 'T' in earliest_risky else earliest_risky
                    ip_intel.last_seen = latest_risky.split('T')[0] if 'T' in latest_risky else latest_risky
                
                    # Override location data from risky signin/detection if available
                    if risky_location_data:
                        if risky_location_data['city']:
                            ip_intel.city = risky_location_data['city']
                        if risky_location_data['state']:
                            ip_intel.region = risky_location_data['state']
                        if risky_location_data['country']:
                            ip_intel.country = risky_location_data['country']
                # Otherwise, use FirstSeen/LastSeen from signin_ip_counts if available
                elif ip in signin_ip_timeline:
                    first_seen_timestamp = signin_ip_timeline[ip].get('FirstSeen', '')
                    last_seen_timestamp = signin_ip_timeline[ip].get('LastSeen', '')
                    ip_intel.first_seen = first_seen_timestamp.split('T')[0] if 'T' in first_seen_timestamp else first_seen_timestamp
                    ip_intel.last_seen = last_seen_timestamp.split('T')[0] if 'T' in last_seen_timestamp else last_seen_timestamp
            
                # Set type based on category
                if 'threat' in ip_intel.categories:
                    ip_intel.anomaly_type = 'Threat Intelligence Match'
                elif 'risky' in ip_intel.categories:
                    ip_intel.anomaly_type = 'Risky Sign-in'
                elif 'primary' in ip_intel.categories:
                    ip_intel.anomaly_type = 'Primary Sign-in'
                elif 'active' in ip_intel.categories:
                    ip_intel.anomaly_type = 'Active Sign-in'
                elif 'normal' in ip_intel.categories:
                    ip_intel.anomaly_type = 'Normal Sign-in'
        
            # Always populate last_seen from signin_ip_timeline if available (regardless of IP type)
            if ip in signin_ip_timeline and not ip_intel.last_seen:
                last_seen_timestamp = signin_ip_timeline[ip].get('LastSeen', '')
                ip_intel.last_seen = last_seen_timestamp.split('T')[0] if 'T' in last_seen_timestamp else last_seen_timestamp
        
            # Always populate signin_count from signin_ip_frequency if available
            if ip in signin_ip_frequency:
                ip_intel.signin_count = signin_ip_frequency[ip]
        
            # Always populate last_auth_result_detail from signin_ip_auth_pattern if available
            if ip in signin_ip_auth_pattern:
                ip_intel.last_auth_result_detail = signin_ip_auth_pattern[ip]
        
            # Always populate success_count and failure_count from signin_ip_success_failure if available
            if ip in signin_ip_success_failure:
                ip_intel.success_count = signin_ip_success_failure[ip].get('SuccessCount', 0)
                ip_intel.failure_count = signin_ip_success_failure[ip].get('FailureCount', 0)
        
            # FALLBACK: Use signin_locations data if API didn't return location (city/country == "Unknown")
            if (ip_intel.city == "Unknown" or ip_intel.country == "Unknown") and ip in ip_location_map:
                country_code = ip_location_map[ip]
                ip_intel.country = country_code
                # We only have country code from signin_locations, not city
                # Keep city as "Unknown" but at least we have country now
        
            return (ip, ip_intel)
    
        # Parallel enrichment with max_workers=5 to respect API rate limits
        # ipinfo.io: 50k/month free tier (plenty of headroom)
        # AbuseIPDB: 1k/day free tier (5 concurrent = safe)
        # vpnapi.io: 1k/day free tier (5 concurrent = safe)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(enrich_single_ip, ip): ip for ip in collected_ips}
        
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    _, ip_intel = future.result()
                    result.ip_intelligence.append(ip_intel)
                    print(f"  ✓ {ip}")
                except (requests.RequestException, ConnectionError, json.JSONDecodeError, KeyError, ValueError) as e:
                    print(f"  ✗ {ip} - {str(e)}")
                    # Create error placeholder
                    error_intel = IPIntelligence(
                        ip=ip, city="Error", region="Error", country="Error",
                        org="Error", asn="Error", timezone="Error",
                        risk_level="Unknown", assessment=f"Enrichment failed: {str(e)}"
                    )
                    error_intel.categories = ip_categories.get(ip, [])
                    result.ip_intelligence.append(error_intel)
    
            # Sort to maintain priority order (since parallel execution can return out of order)
            ip_order = {ip: idx for idx, ip in enumerate(collected_ips)}
            result.ip_intelligence.sort(key=lambda x: ip_order.get(x.ip, 999))
        
        # Save enrichment data back to JSON
        print(f"\n💾 Saving IP enrichment data to {json_file.name}...")
        enrichment_data = []
        for ip_intel in result.ip_intelligence:
            enrichment_data.append({
                'ip': ip_intel.ip,
                'city': ip_intel.city,
                'region': ip_intel.region,
                'country': ip_intel.country,
                'org': ip_intel.org,
                'asn': ip_intel.asn,
                'timezone': ip_intel.timezone,
                'risk_level': ip_intel.risk_level,
                'assessment': ip_intel.assessment,
                'is_vpn': getattr(ip_intel, 'is_vpn', False),
                'is_proxy': getattr(ip_intel, 'is_proxy', False),
                'is_tor': getattr(ip_intel, 'is_tor', False),
                'is_hosting': getattr(ip_intel, 'is_hosting', False),
                'abuse_confidence_score': getattr(ip_intel, 'abuse_confidence_score', 0),
                'total_reports': getattr(ip_intel, 'total_reports', 0),
                'is_whitelisted': getattr(ip_intel, 'is_whitelisted', False),
                'threat_description': getattr(ip_intel, 'threat_description', ''),
                'anomaly_type': getattr(ip_intel, 'anomaly_type', ''),
                'first_seen': getattr(ip_intel, 'first_seen', ''),
                'last_seen': getattr(ip_intel, 'last_seen', ''),
                'hit_count': getattr(ip_intel, 'hit_count', 0),
                'signin_count': getattr(ip_intel, 'signin_count', 0),
                'success_count': getattr(ip_intel, 'success_count', 0),
                'failure_count': getattr(ip_intel, 'failure_count', 0),
                'last_auth_result_detail': getattr(ip_intel, 'last_auth_result_detail', ''),
                'threat_detected': getattr(ip_intel, 'threat_detected', False),
                'threat_confidence': getattr(ip_intel, 'threat_confidence', 0),
                'threat_tlp_level': getattr(ip_intel, 'threat_tlp_level', ''),
                'threat_activity_groups': getattr(ip_intel, 'threat_activity_groups', '')
            })
        
        data['ip_enrichment'] = enrichment_data
        data['enrichment_metadata'] = {
            'last_enriched': datetime.now().isoformat(),
            'ip_count': len(enrichment_data)
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"  ✓ Saved {len(enrichment_data)} enriched IPs to JSON")
    
    # 🎯 DYNAMIC RISK ASSESSMENT (based on actual data)
    risk_factors = []
    mitigating_factors = []
    
    # Risk Factors
    # 1. Geographic anomalies
    new_countries = set()
    for anomaly in result.anomalies:
        if anomaly.country_novelty and anomaly.country:  # Filter out empty country strings
            new_countries.add(anomaly.country)
    if new_countries:
        countries_str = ', '.join(sorted(new_countries))
        risk_factors.append(f"🌍 <strong>Geographic anomalies:</strong> {len(new_countries)} new {'country' if len(new_countries) == 1 else 'countries'} ({countries_str})")
    
    # 2. Device compliance failures
    signin_failures = signin_failures_data or []
    compliance_failures = [f for f in signin_failures if f.get('ResultType') == '53000']
    if compliance_failures:
        total_failures = sum(f.get('FailureCount', 0) for f in compliance_failures)
        risk_factors.append(f"🔓 <strong>Device compliance:</strong> {total_failures} failures (53000)")
    
    # 3. DLP violations
    dlp_count = len(result.dlp_events) if result.dlp_events else 0
    if dlp_count > 0:
        risk_factors.append(f"📤 <strong>DLP violations:</strong> {dlp_count} events (network share + cloud)")
    
    # 4. VPN/Proxy usage (exclude major cloud providers)
    vpn_ips = []
    for ip in result.ip_intelligence:
        if ip.is_vpn:
            # Check if this is major cloud infrastructure (same logic as IP card display)
            org_lower = ip.org.lower() if ip.org else ""
            is_major_infra = any(provider in org_lower for provider in [
                'microsoft', 'azure', 'amazon', 'aws', 'google', 'gcp', 
                'cloudflare', 'akamai', 'fastly', 'oracle cloud'
            ])
            # Only flag as VPN risk if NOT major cloud provider
            if not is_major_infra:
                vpn_ips.append(ip)
    
    if vpn_ips:
        risk_factors.append(f"🎭 <strong>Anonymous IPs:</strong> VPN/proxy usage detected")
    
    # 5. Identity Protection risk
    if result.user_risk_profile and result.user_risk_profile.risk_state == 'atRisk':
        risk_level = result.user_risk_profile.risk_level
        risk_factors.append(f"⚠️ <strong>Identity Protection:</strong> User at {risk_level} risk (atRisk)")
    
    # 6. Active incidents
    open_incidents = [inc for inc in result.security_incidents if inc.get('status') != 'Closed']
    if open_incidents:
        risk_factors.append(f"🚨 <strong>Active incidents:</strong> {len(open_incidents)} open (DLP + auth anomalies)")
    
    # 7. Privileged account (if job title indicates)
    if result.user_profile and result.user_profile.job_title:
        privileged_roles = ['admin', 'secops', 'security', 'analyst', 'engineer']
        if any(role in result.user_profile.job_title.lower() for role in privileged_roles):
            risk_factors.append(f"🔑 <strong>Privileged account:</strong> {result.user_profile.job_title}")
    
    # Mitigating Factors
    # 1. MFA status
    if result.mfa_status and result.mfa_status.mfa_enabled:
        method_count = result.mfa_status.methods_count
        mitigating_factors.append(f"✅ MFA active ({method_count} methods including Authenticator)")
    
    # 2. Sign-in success rate
    signin_events = result.signin_events or {}
    total_signins = signin_events.get('total_signins', 0)
    total_failures = signin_events.get('total_failures', 0)
    if total_signins > 0:
        success_rate = ((total_signins - total_failures) / total_signins) * 100
        mitigating_factors.append(f"✅ {success_rate:.1f}% sign-in success rate")
    
    # 3. Risk detections remediated
    if result.risk_detections:
        remediated = [rd for rd in result.risk_detections if rd.risk_state == 'remediated']
        if len(remediated) == len(result.risk_detections):
            mitigating_factors.append(f"✅ All risk detections remediated (passed MFA)")
    
    # 4. Managed/compliant devices
    compliant_devices = [d for d in (result.devices or []) if d.is_compliant]
    if compliant_devices:
        mitigating_factors.append(f"✅ Managed/compliant devices available")
    
    # 5. Standard app usage
    signin_apps = signin_apps_data or []
    standard_apps = ['Office 365', 'Azure Portal', 'Microsoft Teams', 'Outlook']
    if signin_apps and all(app.get('AppDisplayName') in standard_apps for app in signin_apps[:3]):
        mitigating_factors.append(f"✅ Standard app usage patterns")
    
    # 6. No threat intel matches
    threat_ips = [ip for ip in result.ip_intelligence if ip.threat_description]
    if not threat_ips:
        mitigating_factors.append(f"✅ No threat intel matches on IPs")
    
    # Calculate risk score and level
    risk_score = len(risk_factors) * 10 - len(mitigating_factors) * 5
    risk_score = max(0, min(100, risk_score + 30))  # Baseline 30, cap at 0-100
    
    if risk_score >= 70:
        risk_level = 'HIGH'
    elif risk_score >= 40:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    result.risk_assessment = {
        'risk_level': risk_level,
        'risk_score': risk_score,
        'risk_factors': risk_factors,
        'mitigating_factors': mitigating_factors
    }
    
    # 🎯 DYNAMIC CRITICAL ACTIONS (user-friendly summaries)
    critical_actions = []
    high_priority_actions = []
    
    # 1. DLP Events (HIGHEST PRIORITY)
    dlp_count = len(result.dlp_events) if result.dlp_events else 0
    if dlp_count > 0:
        # Categorize DLP operations
        network_share_count = sum(1 for dlp in result.dlp_events if 'NetworkShare' in dlp.operation or 'network share' in dlp.operation.lower())
        cloud_upload_count = sum(1 for dlp in result.dlp_events if 'Cloud' in dlp.operation or 'Upload' in dlp.operation)
        
        operations_desc = []
        if network_share_count > 0:
            operations_desc.append("network share")
        if cloud_upload_count > 0:
            # Get unique domains
            domains = set(dlp.target_domain for dlp in result.dlp_events if dlp.target_domain)
            if domains:
                operations_desc.append(f"{', '.join(list(domains)[:2])} upload")
            else:
                operations_desc.append("cloud upload")
        
        ops_str = ' + '.join(operations_desc) if operations_desc else "sensitive file operations"
        critical_actions.append(f"<strong>1. Investigate DLP events</strong><br>{dlp_count} sensitive file operations detected ({ops_str})")
    
    # 2. Geographic Anomalies (only if NOT from major cloud providers)
    non_cloud_countries = set()  # Initialize to avoid UnboundLocalError
    if new_countries:
        # Check if these countries are from major cloud provider IPs
        # Build set of countries with major cloud presence
        cloud_countries = set()
        for ip in result.ip_intelligence:
            if ip.country:
                org_lower = ip.org.lower() if ip.org else ""
                is_major_infra = any(provider in org_lower for provider in [
                    'microsoft', 'azure', 'amazon', 'aws', 'google', 'gcp', 
                    'cloudflare', 'akamai', 'fastly', 'oracle cloud'
                ])
                if is_major_infra:
                    # Map country name to country code for comparison
                    # new_countries contains 2-letter codes (e.g., "NL")
                    # We need to check if IP's country matches anomaly's country
                    for anomaly in result.anomalies:
                        if anomaly.country and anomaly.country in new_countries:
                            # Check if this anomaly IP matches this enriched IP
                            if anomaly.value == ip.ip:
                                cloud_countries.add(anomaly.country)
        
        # Only recommend investigation if anomalous countries are NOT all from cloud providers
        non_cloud_countries = new_countries - cloud_countries
        if non_cloud_countries:
            countries_str = ', '.join(sorted(non_cloud_countries))
            high_priority_actions.append(f"<strong>{'2' if critical_actions else '1'}. Review geographic anomalies</strong><br>Verify VPN usage for {countries_str} sign-ins")
    
    # 3. Device Compliance Failures
    compliance_failures = [f for f in signin_failures_data if f.get('ResultType') == '53000']
    if compliance_failures:
        total_failures = sum(f.get('FailureCount', 0) for f in compliance_failures)
        action_num = len(critical_actions) + len(high_priority_actions) + 1
        high_priority_actions.append(f"<strong>{action_num}. Address device compliance</strong><br>Fix non-compliant devices ({total_failures} failures)")
    
    # 4. Active Security Incidents
    open_incidents = [inc for inc in result.security_incidents if inc.get('status') != 'Closed']
    if open_incidents:
        action_num = len(critical_actions) + len(high_priority_actions) + 1
        high_priority_actions.append(f"<strong>{action_num}. Review open security incidents</strong><br>{len(open_incidents)} incidents require attention")
    
    # 5. Risky Sign-ins
    at_risk_signins = [s for s in result.risky_signins if s.risk_state == 'atRisk']
    if at_risk_signins:
        action_num = len(critical_actions) + len(high_priority_actions) + 1
        unique_ips = len(set(s.ip_address for s in at_risk_signins))
        high_priority_actions.append(f"<strong>{action_num}. Investigate risky sign-ins</strong><br>{len(at_risk_signins)} at-risk sign-ins from {unique_ips} IP{'s' if unique_ips > 1 else ''}")
    
    # 6. MONITORING ACTIONS (14-day follow-up)
    monitoring_actions = []
    
    # Monitor for additional DLP events if any were detected
    if dlp_count > 0:
        monitoring_actions.append('Monitor for additional DLP events')
    
    # Track VPN/proxy usage if geographic anomalies detected (exclude cloud providers)
    if non_cloud_countries:
        monitoring_actions.append('Track VPN/proxy usage patterns')
    
    # Review privileged account activity if user has elevated roles
    user_profile = result.user_profile
    if user_profile and (user_profile.job_title and ('admin' in user_profile.job_title.lower() or 'manager' in user_profile.job_title.lower())):
        monitoring_actions.append('Review privileged account activity')
    
    # Monitor threat intel if risky IPs detected
    if threat_ips:
        monitoring_actions.append('Monitor threat intelligence feeds for new indicators')
    
    # Watch for unusual sign-in times
    monitoring_actions.append('Watch for sign-ins during unusual hours')
    
    # Default monitoring if no specific actions
    if not monitoring_actions:
        monitoring_actions.append('Continue normal monitoring procedures')
    
    result.recommendations = {
        'critical_actions': critical_actions,
        'high_priority_actions': high_priority_actions,
        'monitoring_actions': monitoring_actions
    }
    
    # CRITICAL: Populate kql_queries for "Copy KQL" buttons
    result.kql_queries = {
        'anomalies': f"""let start = datetime({result.start_date});
let end = datetime({result.end_date});
// Get the most recent sign-in per IP with full event context
let most_recent_signins = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '{result.upn}'
| summarize arg_max(TimeGenerated, *) by IPAddress;
// Expand authentication details for the most recent sign-in per IP
most_recent_signins
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend HasAuthDetails = array_length(AuthDetails) > 0
| extend AuthDetailsToExpand = iif(HasAuthDetails, AuthDetails, dynamic([{{"authenticationStepResultDetail": ""}}]))
| mv-expand AuthDetailsToExpand
| extend AuthStepResultDetail = tostring(AuthDetailsToExpand.authenticationStepResultDetail)
| extend AuthPriority = case(
    AuthStepResultDetail has "MFA requirement satisfied", 1,
    AuthStepResultDetail has "Correct password", 2,
    AuthStepResultDetail has "Passkey", 2,
    AuthStepResultDetail has "Phone sign-in", 2,
    AuthStepResultDetail has "SMS verification", 2,
    AuthStepResultDetail has "First factor requirement satisfied", 3,
    AuthStepResultDetail has "MFA required", 4,
    999)
| summarize 
    MostRecentTime = any(TimeGenerated),
    MostRecentResultType = any(ResultType),
    HasAuthDetails = any(HasAuthDetails),
    MinPriority = min(AuthPriority),
    AllAuthDetails = make_set(AuthStepResultDetail)
    by IPAddress
| extend LastAuthResultDetail = case(
    MostRecentResultType != "0", "Authentication failed",  // Failure takes priority over auth details
    not(HasAuthDetails) and MostRecentResultType == "0", "Token",  // Non-interactive token-based auth
    MinPriority == 1 and AllAuthDetails has "MFA requirement satisfied", "MFA requirement satisfied by claim in the token",  // Catches all MFA variants
    MinPriority == 2 and AllAuthDetails has "Correct password", "Correct password",
    MinPriority == 2 and AllAuthDetails has "Passkey (device-bound)", "Passkey (device-bound)",
    MinPriority == 3 and AllAuthDetails has "First factor requirement satisfied by claim in the token", "First factor requirement satisfied by claim in the token",
    MinPriority == 4 and AllAuthDetails has "MFA required in Azure AD", "MFA required in Azure AD",
    tostring(AllAuthDetails[0]))
// Join back to get aggregate sign-in counts across all time
| join kind=inner (
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ '{result.upn}'
    | summarize 
        SignInCount = count(),
        SuccessCount = countif(ResultType == '0'),
        FailureCount = countif(ResultType != '0'),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by IPAddress
) on IPAddress
| project IPAddress, SignInCount, SuccessCount, FailureCount, FirstSeen, LastSeen, LastAuthResultDetail
| order by SignInCount desc""",
        'signin_failures': f"""let start = datetime({result.start_date});
let end = datetime({result.end_date});
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '{result.upn}'
| where ResultType != '0'
| summarize 
    FailureCount=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Applications=make_set(AppDisplayName),
    Locations=make_set(Location)
    by ResultType, ResultDescription
| order by FailureCount desc""",
        'dlp': f"""let upn = '{result.upn}';
let start = datetime({result.start_date});
let end = datetime({result.end_date});
CloudAppEvents
| where TimeGenerated between (start .. end)
| where ActionType in ("FileCopiedToRemovableMedia", "FileUploadedToCloud", "FileCopiedToNetworkShare")
| extend DlpAudit = parse_json(RawEventData)["DlpAuditEventMetadata"]
| extend File = parse_json(RawEventData)["ObjectId"]
| extend UserId = parse_json(RawEventData)["UserId"]
| extend DeviceName = parse_json(RawEventData)["DeviceName"]
| extend ClientIP = parse_json(RawEventData)["ClientIP"]
| extend RuleName = parse_json(RawEventData)["PolicyMatchInfo"]["RuleName"]
| extend Operation = parse_json(RawEventData)["Operation"]
| extend TargetDomain = parse_json(RawEventData)["TargetDomain"]
| extend TargetFilePath = parse_json(RawEventData)["TargetFilePath"]
| where isnotnull(DlpAudit)
| where UserId == upn
| summarize by TimeGenerated, tostring(UserId), tostring(DeviceName), tostring(ClientIP), tostring(RuleName), tostring(File), tostring(Operation), tostring(TargetDomain), tostring(TargetFilePath)
| order by TimeGenerated desc""",
        'audit': f"""let start = datetime({result.start_date});
let end = datetime({result.end_date});
AuditLogs
| where TimeGenerated between (start .. end)
| where Identity =~ '{result.upn}' or tostring(InitiatedBy) has '{result.upn}'
| summarize 
    Count=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Operations=make_set(OperationName, 10)
    by Category, Result
| order by Count desc""",
        'incidents': f"""let targetUPN = "{result.upn}";
let targetUserId = "{data['user_id']}";
let targetSid = "{data['user_sid']}";
let start = datetime({result.start_date});
let end = datetime({result.end_date});
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has targetUPN or Entities has targetUserId or Entities has targetSid
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| extend ProviderIncidentUrl = tostring(AdditionalData.providerIncidentUrl)
| extend OwnerUPN = tostring(Owner.userPrincipalName)
| project 
    IncidentNumber,
    ProviderIncidentId,
    Title,
    Severity,
    Status,
    Classification,
    CreatedTime,
    OwnerUPN,
    ProviderIncidentUrl,
    AlertName,
    AlertSeverity,
    ProviderName,
    Tactics
| order by CreatedTime desc""",
        'activity_summary': f"""OfficeActivity
| where TimeGenerated between (datetime({result.start_date}) .. datetime({result.end_date}))
| where UserId =~ '{result.upn}'
| summarize ActivityCount = count() by RecordType, Operation
| order by ActivityCount desc"""
    }
    
    result.result_counts = data.get('result_counts', {})
    
    # Generate COMPACT HTML report
    print(f"\n📄 Generating COMPACT HTML report...")
    generator = CompactReportGenerator()
    report_path = generator.generate(result)
    print(f"\n✅ Investigation complete!")
    print(f"📊 Compact Report: {report_path}")
    
    # 🗑️ CLEANUP: Remove old investigation JSON and HTML files (3-day retention for lab data)
    print(f"\n🗑️ Running cleanup of old investigation files...")
    try:
        from cleanup_old_investigations import cleanup_old_investigations
        cleanup_old_investigations(temp_dir="temp", reports_dir="reports", retention_days=3, dry_run=False)
    except (ImportError, OSError, PermissionError) as e:
        print(f"⚠️  Cleanup skipped: {e}")

if __name__ == "__main__":
    main()
