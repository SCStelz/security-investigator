"""
Compact Security Investigation Report Generator
Generates high-density, two-column HTML reports from investigation results
"""

from typing import Dict, List, Optional
from datetime import datetime
import json
import os
import socket
import logging
from investigator import InvestigationResult, AnomalyFinding, IPIntelligence, DeviceInfo
from exceptions import ReportGenerationError

logger = logging.getLogger(__name__)


class CompactReportGenerator:
    """Generates compact HTML investigation reports with two-column layout"""
    
    def __init__(self):
        """Initialize compact report generator"""
        pass
    
    def _get_current_user(self) -> str:
        """Get current Windows username"""
        try:
            return os.getlogin().upper()
        except OSError:
            return os.environ.get('USERNAME', 'UNKNOWN').upper()
    
    def _get_machine_name(self) -> str:
        """Get current machine hostname"""
        try:
            return socket.gethostname().upper()
        except OSError:
            return 'UNKNOWN'
    
    def _get_ip_category_badges(self, categories: list, size: str = 'normal') -> str:
        """Generate IP category badges HTML (shared between IP cards and timeline)
        
        Args:
            categories: List of category strings ('threat', 'risky', 'anomaly', 'primary', 'active')
            size: 'normal' for IP cards (11px), 'small' for timeline (10px)
        """
        if not categories:
            return ''
        
        # Size configurations
        if size == 'small':
            padding = '2px 6px'
            font_size = '10px'
            margin = '4px'
        else:  # normal
            padding = '2px 8px'
            font_size = '11px'
            margin = '6px'
        
        # Sort categories by severity: threat > risky > anomaly > primary/active
        severity_order = {'threat': 0, 'risky': 1, 'anomaly': 2, 'primary': 3, 'active': 4}
        sorted_categories = sorted(categories, key=lambda x: severity_order.get(x, 99))
        
        badges = []
        for cat in sorted_categories:
            if cat == 'threat':
                badges.append(f'<span style="background: #dc3545; color: white; padding: {padding}; border-radius: 3px; font-size: {font_size}; font-weight: bold; margin-left: {margin};">🚨 THREAT</span>')
            elif cat == 'risky':
                badges.append(f'<span style="background: #ff7f00; color: white; padding: {padding}; border-radius: 3px; font-size: {font_size}; font-weight: bold; margin-left: 4px;">⚠️ RISKY</span>')
            elif cat == 'anomaly':
                badges.append(f'<span style="background: #ffc107; color: #1a1a1a; padding: {padding}; border-radius: 3px; font-size: {font_size}; font-weight: bold; margin-left: 4px;">ANOMALY</span>')
            elif cat == 'primary':
                badges.append(f'<span style="background: #007bff; color: white; padding: {padding}; border-radius: 3px; font-size: {font_size}; font-weight: bold; margin-left: {margin};">PRIMARY</span>')
            elif cat == 'active':
                badges.append(f'<span style="background: #17a2b8; color: white; padding: {padding}; border-radius: 3px; font-size: {font_size}; font-weight: bold; margin-left: {margin};">ACTIVE</span>')
        return ''.join(badges)
    
    
    def generate(self, result: InvestigationResult, output_path: Optional[str] = None) -> str:
        """
        Generate compact HTML report from investigation results
        
        Args:
            result: InvestigationResult object
            output_path: Optional custom output path
            
        Returns:
            Path to generated HTML file
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            username = result.upn.split('@')[0]
            output_path = f"reports/user-investigations/Investigation_Report_Compact_{username}_{timestamp}.html"
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Generate HTML content
        html = self._generate_html(result)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    def _generate_html(self, result: InvestigationResult) -> str:
        """Generate complete HTML document"""
        
        # Store queries and result counts for access in section builders
        self.kql_queries = result.kql_queries or {}
        self.result_counts = result.result_counts or {}
        
        # Add IP-specific KQL queries for "Copy KQL" buttons in IP Intelligence section
        for ip_intel in (result.ip_intelligence or []):
            ip_address = ip_intel.ip
            kql_key = f"ip_{ip_address.replace('.', '_')}"
            location = f"{ip_intel.city}, {ip_intel.country}" if ip_intel.city else ip_intel.country
            self.kql_queries[kql_key] = f"""// Activity from IP: {ip_address} ({location})
// Organization: {ip_intel.org}
// Risk Level: {ip_intel.risk_level}
let TargetIP = "{ip_address}";
let TimeRange = 30d;
union isfuzzy=true
    (SigninLogs
    | where TimeGenerated > ago(TimeRange)
    | where IPAddress == TargetIP
    | project TimeGenerated, LogSource="SigninLogs", UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType, ResultDescription),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(TimeRange)
    | where IPAddress == TargetIP
    | project TimeGenerated, LogSource="AADNonInteractiveUserSignInLogs", UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType, ResultDescription),
    (OfficeActivity
    | where TimeGenerated > ago(TimeRange)
    | where ClientIP == TargetIP
    | project TimeGenerated, LogSource="OfficeActivity", UserPrincipalName=UserId, IPAddress=ClientIP, Location="", AppDisplayName=Operation, ResultType=ResultStatus, ResultDescription=Operation, operatingSystem=""),
    (AuditLogs
    | where TimeGenerated > ago(TimeRange)
    | where tostring(InitiatedBy.user.ipAddress) == TargetIP or tostring(InitiatedBy.app.ipAddress) == TargetIP
    | project TimeGenerated, LogSource="AuditLogs", UserPrincipalName=tostring(InitiatedBy.user.userPrincipalName), IPAddress=coalesce(tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress)), Location="", AppDisplayName=OperationName, ResultType=Result, ResultDescription=OperationName, operatingSystem=""),
    (AzureActivity
    | where TimeGenerated > ago(TimeRange)
    | where CallerIpAddress == TargetIP
    | project TimeGenerated, LogSource="AzureActivity", UserPrincipalName=Caller, IPAddress=CallerIpAddress, Location="", AppDisplayName=OperationNameValue, ResultType=ActivityStatusValue, ResultDescription=OperationNameValue, operatingSystem="")
| order by TimeGenerated desc"""
        
        # Build sections
        header = self._build_header(result)
        left_column = self._build_left_column(result)
        right_column = self._build_right_column(result)
        timeline_modal = self._build_timeline_modal(result)
        
        # Build recommendations section
        recommendations = self._build_recommendations(result)
        
        # Combine into full HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compact Security Investigation Report - {result.upn}</title>
    {self._get_styles()}
</head>
<body>
    <!-- Watermark Header Bar -->
    <div style="position: fixed; top: 0; left: 0; right: 0; 
                background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
                color: white; padding: 10px 20px; z-index: 9999;
                box-shadow: 0 2px 8px rgba(0,0,0,0.4);
                font-size: 13px; font-weight: 600;
                border-bottom: 2px solid #ff6b6b;">
        <div style="display: flex; align-items: center; justify-content: space-between; max-width: 1800px; margin: 0 auto;">
            <div style="display: flex; align-items: center; gap: 20px;">
                <span style="font-size: 16px;">🔒</span>
                <span style="font-weight: 700; font-size: 14px;">CONFIDENTIAL - INTERNAL USE ONLY</span>
            </div>
            <div style="display: flex; align-items: center; gap: 15px; font-size: 12px; opacity: 0.95;">
                <span>Generated by: <strong>{self._get_current_user()}</strong></span>
                <span style="opacity: 0.6;">|</span>
                <span>Machine: <strong>{self._get_machine_name()}</strong></span>
                <span style="opacity: 0.6;">|</span>
                <span>Date: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}</strong></span>
            </div>
        </div>
    </div>
    
    <!-- Main content with top margin to clear watermark -->
    <div class="container" style="margin-top: 50px;">
        {header}
        <div class="content">
            <div class="left-column">
                {left_column}
            </div>
            <div class="resize-handle"></div>
            <div class="right-column">
                {right_column}
            </div>
        </div>
        {recommendations}
        <div class="footer">
            <strong style="color: #f65314;">⚠️ CONFIDENTIAL</strong> - Security Investigation Report | Generated: {result.investigation_date} | 
            Investigation Period: {result.start_date} to {result.end_date}
        </div>
    </div>
    {timeline_modal}
    {self._get_javascript()}
</body>
</html>"""
        return html
    
    def _build_header(self, result: InvestigationResult) -> str:
        """Build compact header with user info and timeline button"""
        user_profile = result.user_profile
        user_id = result.user_id or ''
        
        if user_profile:
            display_name = user_profile.display_name
            job_title = user_profile.job_title
            department = user_profile.department
            location = user_profile.office_location
            account_enabled = user_profile.account_enabled
            user_type = user_profile.user_type
        else:
            display_name = result.upn.split('@')[0]
            job_title = 'Unknown'
            department = 'Unknown'
            location = 'Unknown'
            account_enabled = True
            user_type = 'Member'
        
        account_status = '<span style="color: #90ee90;">● Active</span>' if account_enabled else '<span style="color: #f65314;">● Disabled</span>'
        defender_link = f'<a href="https://security.microsoft.com/user?aad={user_id}" target="_blank" style="color: #00a1f1; font-size: 0.9em; margin-left: 10px; text-decoration: none;" title="View user in Microsoft Defender XDR">🛡️</a>' if user_id else ''
        
        # Build primary location badges (top 5 locations)
        signin_events = result.signin_events or {}
        locations = signin_events.get('locations', [])
        location_badges = ''
        
        if locations:
            sorted_locations = sorted(locations, key=lambda x: x.get('SignInCount', 0), reverse=True)[:5]
            badges = []
            for idx, loc in enumerate(sorted_locations):
                loc_name = loc.get('Location', 'Unknown')
                total = loc.get('SignInCount', 0)
                failures = loc.get('FailureCount', 0)
                
                # Badge color: Primary location (green), moderate failures (yellow), high failures (red)
                failure_rate = (failures / total * 100) if total > 0 else 0
                if idx == 0:
                    # Primary location (most frequent) - green
                    badge_color = '#7cbb00'
                elif failure_rate > 20:
                    badge_color = '#f65314'  # Red for high failure rate
                elif failure_rate > 5:
                    badge_color = '#ffbb00'  # Yellow for moderate failure rate
                else:
                    badge_color = '#7cbb00'  # Green for low/no failures
                
                badges.append(f'''<span style="background: {badge_color}; color: white; padding: 3px 8px; border-radius: 10px; font-size: 0.7em; font-weight: 500; margin-right: 6px; white-space: nowrap; display: inline-block;">📍 {loc_name}</span>''')
            
            location_badges = ''.join(badges)
        
        return f"""
        <div class="header">
            <div>
                <h1>{display_name}{defender_link} <span style="color: #555; font-weight: 300;">|</span> <span style="font-size: 0.6em; font-weight: 400; opacity: 0.9;">{result.upn} • {job_title}</span></h1>
                <div style="font-size: 1em; opacity: 0.9; margin-top: 4px; line-height: 1.6;">
                    <div>{department} • {location} • {location_badges}</div>
                    <div>{account_status} • {user_type}</div>
                </div>
            </div>
            <div class="meta">
                <div><strong>Investigation Date:</strong> {result.investigation_date}</div>
                <div><strong>Period:</strong> {result.start_date} to {result.end_date}</div>
                <div style="margin-top: 8px;">
                    <button class="timeline-button" onclick="openTimeline()">📅 View Investigation Timeline</button>
                </div>
            </div>
        </div>
        """
    
    def _build_left_column(self, result: InvestigationResult) -> str:
        """Build left column sections"""
        sections = []
        
        # Key Metrics
        sections.append(self._build_key_metrics(result))
        
        # MFA Status
        sections.append(self._build_mfa_status(result))
        
        # Risk Assessment
        sections.append(self._build_risk_assessment(result))
        
        # Critical Actions
        sections.append(self._build_critical_actions(result))
        
        # Identity Protection
        sections.append(self._build_identity_protection(result))
        
        # Registered Devices
        sections.append(self._build_devices_section(result))
        
        # Top Locations
        sections.append(self._build_top_locations(result))
        
        # Top Applications
        sections.append(self._build_top_applications(result))
        
        return '\n'.join(sections)
    
    def _build_right_column(self, result: InvestigationResult) -> str:
        """Build right column sections"""
        sections = []
        
        # User IP Intelligence
        sections.append(self._build_ip_intelligence(result))
        
        # Security Incidents
        sections.append(self._build_security_incidents(result))
        
        # Office 365 Activity
        sections.append(self._build_office_activity(result))
        
        # DLP Events
        sections.append(self._build_dlp_events(result))
        
        # Sign-in Failures
        sections.append(self._build_signin_failures(result))
        
        # Azure AD Audit Log Activity
        sections.append(self._build_audit_activity(result))
        
        return '\n'.join(sections)
    
    def _build_key_metrics(self, result: InvestigationResult) -> str:
        """Build key metrics dashboard"""
        anomaly_count = len(result.anomalies) if result.anomalies else 0
        
        # Calculate sign-in totals
        signin_events = result.signin_events or {}
        total_signins = signin_events.get('total_signins', 0)
        total_failures = signin_events.get('total_failures', 0)
        
        # DLP events count
        dlp_count = len(result.dlp_events) if result.dlp_events else 0
        
        # Format sign-ins (13.5K format)
        if total_signins >= 1000:
            signins_display = f"{total_signins / 1000:.1f}K"
        else:
            signins_display = str(total_signins)
        
        return f"""
        <div class="section">
            <h2>📊 Key Metrics</h2>
            <div class="metrics">
                <div class="metric">
                    <div class="metric-value">{anomaly_count}</div>
                    <div class="metric-label">Anomalies</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{signins_display}</div>
                    <div class="metric-label">Sign-ins</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{dlp_count}</div>
                    <div class="metric-label">DLP Events</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{total_failures}</div>
                    <div class="metric-label">Failures</div>
                </div>
            </div>
        </div>
        """
    
    def _build_mfa_status(self, result: InvestigationResult) -> str:
        """Build MFA status badges"""
        mfa_status = result.mfa_status
        user_profile = result.user_profile
        is_guest = user_profile and user_profile.user_type == 'Guest'
        
        if not mfa_status or not mfa_status.mfa_enabled:
            status_html = '<span class="badge badge-critical">❌ No MFA Configured</span>'
        else:
            # For guest accounts with only password method but MFA enabled (external MFA)
            if is_guest and mfa_status.methods_count == 1 and 'passwordAuthenticationMethod' in (mfa_status.methods or []):
                status_html = '<span class="badge badge-low">✓ MFA Enabled (Home Tenant)</span>'
            else:
                method_badges = []
                # Clean up method names for display
                method_name_map = {
                    'fido2AuthenticationMethod': 'Windows Hello',
                    'microsoftAuthenticatorAuthenticationMethod': 'Authenticator',
                    'phoneAuthenticationMethod': 'Phone',
                    'emailAuthenticationMethod': 'Email',
                    'passwordAuthenticationMethod': 'Password',
                    'softwareOathAuthenticationMethod': 'Software Token',
                    'temporaryAccessPassAuthenticationMethod': 'Temp Access Pass'
                }
                
                for method in (mfa_status.methods or []):
                    # Clean method name
                    clean_name = method_name_map.get(method, method.replace('AuthenticationMethod', '').replace('authentication', '').title())
                    method_badges.append(f'<span class="badge badge-low">{clean_name}</span>')
                
                status_html = '\n'.join(method_badges)
        
        return f"""
        <div class="section">
            <h2>🔐 MFA Status</h2>
            <div style="display: flex; gap: 4px; flex-wrap: wrap; margin-top: 6px;">
                {status_html}
            </div>
        </div>
        """
    
    def _build_identity_protection(self, result: InvestigationResult) -> str:
        """Build Identity Protection status card"""
        risk_profile = result.user_risk_profile
        risk_detections = result.risk_detections or []
        
        # Check if we have any data
        if not risk_profile and not risk_detections:
            return f"""
            <div class="section">
                <h2>🛡️ Identity Protection</h2>
                <p style="color: #7cbb00; margin-top: 6px;">✓ No risk detected</p>
            </div>
            """
        
        # Build risk profile display
        if risk_profile:
            risk_level = risk_profile.risk_level or 'none'
            risk_state = risk_profile.risk_state or 'none'
            
            # Map risk level to badge
            risk_badge_map = {
                'none': ('badge-info', '✓'),
                'low': ('badge-low', '⚠️'),
                'medium': ('badge-medium', '⚠️'),
                'high': ('badge-critical', '🚨')
            }
            badge_class, icon = risk_badge_map.get(risk_level.lower(), ('badge-info', 'ℹ️'))
            
            # Map risk state to color and label
            state_map = {
                'atRisk': ('#f65314', 'Active Risk'),
                'confirmedCompromised': ('#f65314', 'Compromised'),
                'dismissed': ('#737373', 'Dismissed'),
                'remediated': ('#7cbb00', 'Remediated'),
                'none': ('#7cbb00', 'No Risk')
            }
            state_color, state_label = state_map.get(risk_state, ('#737373', risk_state))
            
            # Count active risk detections
            active_risks = [d for d in risk_detections if d.risk_state in ['atRisk', 'confirmedCompromised']]
            
            risk_html = f"""
            <div style="margin-top: 6px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="color: #b0b0b0; font-size: 0.85em;">Risk Level:</span>
                    <span class="badge {badge_class}">{icon} {risk_level.upper()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="color: #b0b0b0; font-size: 0.85em;">State:</span>
                    <span style="color: {state_color}; font-weight: 500;">{state_label}</span>
                </div>
            """
            
            # Build dropdown with ALL risk detections (not just active ones)
            if result.risk_detections:
                details_rows = []
                for detection in result.risk_detections:
                    # Format location
                    location_parts = [p for p in [detection.location_city, detection.location_state, detection.location_country] if p]
                    location = ', '.join(location_parts) if location_parts else 'Unknown'
                    
                    # Risk level badge
                    level_badge_map = {'low': 'badge-low', 'medium': 'badge-medium', 'high': 'badge-critical'}
                    level_badge = level_badge_map.get(detection.risk_level.lower(), 'badge-info')
                    
                    # Risk state badge/color
                    state_map = {
                        'atRisk': ('badge-critical', 'Active Risk'),
                        'confirmedCompromised': ('badge-critical', 'Compromised'),
                        'remediated': ('badge-info', 'Remediated'),
                        'dismissed': ('badge-low', 'Dismissed')
                    }
                    state_badge, state_label = state_map.get(detection.risk_state, ('badge-info', detection.risk_state))
                    
                    # Highlight active risks with different background
                    row_bg = "background: rgba(246, 83, 20, 0.15);" if detection.risk_state in ['atRisk', 'confirmedCompromised'] else ""
                    
                    details_rows.append(f"""
                        <tr style="font-size: 0.8em; {row_bg}">
                            <td style="padding: 4px;">{detection.detected_date[:10]}</td>
                            <td style="padding: 4px;">{detection.risk_event_type}</td>
                            <td style="padding: 4px;"><span class="badge {level_badge}">{detection.risk_level}</span></td>
                            <td style="padding: 4px;"><span class="badge {state_badge}">{state_label}</span></td>
                            <td style="padding: 4px;">{detection.ip_address or 'N/A'}</td>
                            <td style="padding: 4px;">{location}</td>
                        </tr>
                    """)
                
                # Warning box if active risks exist
                if active_risks:
                    risk_html += f"""
                    <div style="margin-top: 6px; padding: 6px; background: rgba(246, 83, 20, 0.1); border-left: 3px solid #f65314; border-radius: 3px;">
                        <span style="color: #f65314; font-weight: 500;">⚠️ {len(active_risks)} Active Risk Detection{'s' if len(active_risks) > 1 else ''}</span>
                    </div>
                    """
                
                risk_html += f"""
                <details style="margin-top: 6px; padding: 6px; background: rgba(0, 161, 241, 0.1); border-left: 3px solid #00a1f1; border-radius: 3px; cursor: pointer;">
                    <summary style="color: #00a1f1; font-weight: 500; list-style: none; user-select: none;">
                        📋 Recent Risk Detections <span style="font-size: 0.8em; color: #737373;">▼</span>
                    </summary>
                    <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(0, 161, 241, 0.3);">
                        <table style="width: 100%; font-size: 0.85em;">
                            <thead>
                                <tr style="color: #b0b0b0; font-size: 0.75em; text-align: left;">
                                    <th style="padding: 4px;">Date</th>
                                    <th style="padding: 4px;">Type</th>
                                    <th style="padding: 4px;">Level</th>
                                    <th style="padding: 4px;">State</th>
                                    <th style="padding: 4px;">IP</th>
                                    <th style="padding: 4px;">Location</th>
                                </tr>
                            </thead>
                            <tbody>
                                {''.join(details_rows)}
                            </tbody>
                        </table>
                    </div>
                </details>
                """
            elif risk_detections:
                last_detection = max(risk_detections, key=lambda d: d.detected_date)
                risk_html += f"""
                <div style="margin-top: 4px; font-size: 0.85em; color: #737373;">
                    Last detection: {last_detection.detected_date[:10]}
                </div>
                """
            
            risk_html += "</div>"
        else:
            # No risk profile but have detections
            active_risks = [d for d in risk_detections if d.risk_state in ['atRisk', 'confirmedCompromised']]
            if active_risks:
                risk_html = f"""
                <div style="margin-top: 6px; padding: 6px; background: rgba(246, 83, 20, 0.1); border-left: 3px solid #f65314; border-radius: 3px;">
                    <span style="color: #f65314; font-weight: 500;">⚠️ {len(active_risks)} Active Risk Detection{'s' if len(active_risks) > 1 else ''}</span>
                </div>
                """
            else:
                risk_html = '<p style="color: #7cbb00; margin-top: 6px;">✓ Risks resolved</p>'
        
        return f"""
        <div class="section">
            <h2>🛡️ Identity Protection</h2>
            {risk_html}
        </div>
        """
    
    def _build_risk_assessment(self, result: InvestigationResult) -> str:
        """Build risk assessment section"""
        risk_level = result.risk_assessment.get('risk_level', 'UNKNOWN')
        risk_factors = result.risk_assessment.get('risk_factors', [])
        mitigating_factors = result.risk_assessment.get('mitigating_factors', [])
        
        # Badge class based on risk level
        badge_class_map = {
            'CRITICAL': 'badge-critical',
            'HIGH': 'badge-high',
            'MEDIUM': 'badge-medium',
            'LOW': 'badge-low',
            'INFO': 'badge-info'
        }
        badge_class = badge_class_map.get(risk_level, 'badge-info')
        
        # Build risk factors list
        risk_factors_html = ''
        if risk_factors:
            risk_items = '\n'.join([f'<li>{factor}</li>' for factor in risk_factors])
            risk_factors_html = f"""
                    <details open>
                        <summary>Risk Factors ({len(risk_factors)})</summary>
                        <ul>
                            {risk_items}
                        </ul>
                    </details>
            """
        
        # Build mitigating factors list
        mitigating_html = ''
        if mitigating_factors:
            mitigating_items = '\n'.join([f'<li>{factor}</li>' for factor in mitigating_factors])
            mitigating_html = f"""
                    <details open>
                        <summary>Mitigating Factors ({len(mitigating_factors)})</summary>
                        <ul>
                            {mitigating_items}
                        </ul>
                    </details>
            """
        
        return f"""
        <div class="section">
            <h2>🎯 Risk Assessment</h2>
            <div style="margin-bottom: 10px;">
                <strong>Overall Risk:</strong> <span class="badge {badge_class}">{risk_level}</span>
            </div>
            <div style="margin-bottom: 10px; font-size: 0.9em; color: #b0b0b0;">
                Risk level is calculated based on {len(risk_factors)} risk factor{'s' if len(risk_factors) != 1 else ''} 
                {f'and {len(mitigating_factors)} mitigating factor{"s" if len(mitigating_factors) != 1 else ""}' if mitigating_factors else ''}.
            </div>
            {risk_factors_html}
            {mitigating_html}
        </div>
        """
    
    def _build_critical_actions(self, result: InvestigationResult) -> str:
        """Build critical actions alerts"""
        recommendations = result.recommendations
        critical = recommendations.get('critical_actions', [])
        high_priority = recommendations.get('high_priority_actions', [])
        
        alerts_html = []
        
        for action in critical[:3]:  # Top 3 critical
            alerts_html.append(f'<div class="alert alert-critical"><strong>🚨 CRITICAL:</strong> {action}</div>')
        
        for action in high_priority[:2]:  # Top 2 high priority
            alerts_html.append(f'<div class="alert alert-high"><strong>⚠️ HIGH:</strong> {action}</div>')
        
        if not alerts_html:
            alerts_html.append('<div class="alert alert-medium"><strong>✓ INFO:</strong> No critical actions required</div>')
        
        return f"""
        <div class="section">
            <h2>🎯 Critical Actions</h2>
            {''.join(alerts_html)}
        </div>
        """
    
    def _build_devices_section(self, result: InvestigationResult) -> str:
        """Build registered devices table"""
        from datetime import datetime, timedelta
        
        devices = result.devices or []
        
        # Build Defender devices link if user_id available
        user_id = result.user_id or ''
        devices_defender_link = f'<a href="https://security.microsoft.com/user?aad={user_id}&tab=data&datatab=devices" target="_blank" style="color: #00a1f1; font-size: 0.75em; margin-left: 10px; text-decoration: none;" title="View user devices in Microsoft Defender XDR">🛡️</a>' if user_id else ''
        
        if not devices:
            return f"""
            <div class="section">
                <h2>💻 Registered Devices{devices_defender_link}</h2>
                <p style="color: #b0b0b0; margin-top: 8px;">No registered devices found</p>
            </div>
            """
        
        # Detect stale devices (6+ months since last sign-in)
        stale_cutoff = datetime.now() - timedelta(days=180)
        stale_devices = set()
        for device in devices:
            if device.approximate_last_sign_in and device.approximate_last_sign_in != 'N/A':
                try:
                    last_signin = datetime.fromisoformat(device.approximate_last_sign_in.replace('Z', '+00:00').replace('+00:00', ''))
                    if last_signin < stale_cutoff:
                        stale_devices.add(device.display_name)
                except (ValueError, AttributeError):
                    pass
        
        rows = []
        for device in devices[:5]:  # Top 5 devices
            name = device.display_name
            os = device.operating_system
            compliant = device.is_compliant
            last_seen = device.approximate_last_sign_in[:10] if device.approximate_last_sign_in else 'N/A'
            
            is_stale = name in stale_devices
            compliant_badge = '<span style="color: #7cbb00;">✓ Yes</span>' if compliant else '<span style="color: #f65314;">✗ No</span>'
            
            # Add stale indicator
            stale_badge = ' <span style="color: #ffbb00; font-size: 0.75em;">⚠ STALE</span>' if is_stale else ''
            
            rows.append(f"""
                <tr>
                    <td>{name}{stale_badge}</td>
                    <td>{os}</td>
                    <td>{compliant_badge}</td>
                    <td>{last_seen}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <h2>💻 Registered Devices{devices_defender_link}</h2>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>OS</th>
                        <th>Compliant</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        """
    
    def _build_top_locations(self, result: InvestigationResult) -> str:
        """Build top sign-in locations with pagination"""
        signin_events = result.signin_events or {}
        locations = signin_events.get('locations', [])
        
        if not locations:
            return f"""
            <div class="section">
                <h2>📍 Top Locations</h2>
                <p style="color: #b0b0b0; margin-top: 8px;">No location data available</p>
            </div>
            """
        
        # Sort by total sign-ins
        sorted_locations = sorted(locations, key=lambda x: x.get('SignInCount', 0), reverse=True)[:8]  # Top 8
        
        rows = []
        for idx, location in enumerate(sorted_locations):
            loc = location.get('Location', 'Unknown')
            country = loc.split(',')[-1].strip() if ',' in loc else loc
            count = location.get('SignInCount', 0)
            success = location.get('SuccessCount', 0)
            failures = location.get('FailureCount', 0)
            
            # Style attribute for pagination
            style = '' if idx < 3 else ' style="display: none;"'
            page = (idx // 3) + 1
            
            rows.append(f"""
                <tr class="location-row" data-page="{page}"{style}>
                    <td>{country}</td>
                    <td style="text-align: center;">{count}</td>
                    <td style="text-align: center;"><span style="color: #7cbb00;">✓ {success}</span></td>
                    <td style="text-align: center;"><span style="color: #f65314;">✗ {failures}</span></td>
                </tr>
            """)
        
        total_pages = (len(sorted_locations) + 2) // 3  # 3 per page
        
        pagination = ''
        if total_pages > 1:
            pagination = f"""
            <div class="pagination-controls">
                <button class="page-button" id="locPrevBtn" onclick="changeLocationPage(-1)" disabled>← Prev</button>
                <span id="locPageInfo" style="color: #b0b0b0;">Page <span id="locCurrentPage">1</span> of {total_pages}</span>
                <button class="page-button" id="locNextBtn" onclick="changeLocationPage(1)">Next →</button>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>📍 Top Locations</h2>
            <table id="locationsTable">
                <thead>
                    <tr>
                        <th>Location</th>
                        <th style="text-align: center;">Total</th>
                        <th style="text-align: center;">Success</th>
                        <th style="text-align: center;">Failures</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
            {pagination}
        </div>
        """
    
    def _build_top_applications(self, result: InvestigationResult) -> str:
        """Build top sign-in applications with pagination"""
        signin_events = result.signin_events or {}
        applications = signin_events.get('applications', [])
        
        if not applications:
            return f"""
            <div class="section">
                <h2>📱 Top Applications</h2>
                <p style="color: #b0b0b0; margin-top: 8px;">No application data available</p>
            </div>
            """
        
        # Sort by total sign-ins
        sorted_apps = sorted(applications, key=lambda x: x.get('SignInCount', 0), reverse=True)[:8]  # Top 8
        
        rows = []
        for idx, app in enumerate(sorted_apps):
            app_name = app.get('AppDisplayName', 'Unknown')
            count = app.get('SignInCount', 0)
            success = app.get('SuccessCount', 0)
            failures = app.get('FailureCount', 0)
            
            # Style attribute for pagination
            style = '' if idx < 3 else ' style="display: none;"'
            page = (idx // 3) + 1
            
            rows.append(f"""
                <tr class="application-row" data-page="{page}"{style}>
                    <td>{app_name}</td>
                    <td style="text-align: center;">{count}</td>
                    <td style="text-align: center;"><span style="color: #7cbb00;">✓ {success}</span></td>
                    <td style="text-align: center;"><span style="color: #f65314;">✗ {failures}</span></td>
                </tr>
            """)
        
        total_pages = (len(sorted_apps) + 2) // 3  # 3 per page
        
        pagination = ''
        if total_pages > 1:
            pagination = f"""
            <div class="pagination-controls">
                <button class="page-button" id="appPrevBtn" onclick="changeApplicationPage(-1)" disabled>← Prev</button>
                <span id="appPageInfo" style="color: #b0b0b0;">Page <span id="appCurrentPage">1</span> of {total_pages}</span>
                <button class="page-button" id="appNextBtn" onclick="changeApplicationPage(1)">Next →</button>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>📱 Top Applications</h2>
            <table id="applicationsTable">
                <thead>
                    <tr>
                        <th>Application</th>
                        <th style="text-align: center;">Total</th>
                        <th style="text-align: center;">Success</th>
                        <th style="text-align: center;">Failures</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
            {pagination}
        </div>
        """
    
    def _build_ip_intelligence(self, result: InvestigationResult) -> str:
        """Build IP intelligence cards with pagination"""
        ip_intelligence = result.ip_intelligence or []
        
        if not ip_intelligence:
            return f"""
            <div class="section">
                <h2>🌐 User Sign-in IP Intelligence<button class="kql-copy-button" onclick="copyKQL(event, 'anomalies')" title="Copy KQL Query">📋</button></h2>
                <p style="color: #b0b0b0; margin-top: 8px;">No IP intelligence data available</p>
            </div>
            """
        
        # Sort by category priority then risk level (matching original report)
        # Priority: threat → dual-source (anomaly+risky) → risky → anomaly → frequent
        def get_sort_key(ip):
            categories = ip.categories if ip.categories else []
            
            # Threat intel gets HIGHEST priority (confirmed malicious)
            if 'threat' in categories:
                return 0
            # Dual-source (both anomaly and risky) second priority
            elif 'anomaly' in categories and 'risky' in categories:
                return 1
            elif 'risky' in categories:
                return 2
            elif 'anomaly' in categories:
                return 3
            else:
                return 4
        
        risk_priority = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        
        sorted_ips = sorted(ip_intelligence, 
                          key=lambda x: (
                              get_sort_key(x),
                              risk_priority.get(x.risk_level, 99)
                          ))
        
        cards = []
        for idx, ip in enumerate(sorted_ips):
            # Style attribute for pagination (4 per page)
            style = '' if idx < 4 else ' style="display: none;"'
            page = (idx // 4) + 1
            
            cards.append(self._build_ip_card(ip, page, style))
        
        total_pages = (len(sorted_ips) + 3) // 4  # 4 per page
        
        pagination = ''
        if total_pages > 1:
            pagination = f"""
            <div class="pagination-controls">
                <button class="page-button" id="prevBtn" onclick="changeAnomalyPage(-1)" disabled>← Prev</button>
                <span id="pageInfo" style="color: #b0b0b0;">Page <span id="currentPage">1</span> of {total_pages}</span>
                <button class="page-button" id="nextBtn" onclick="changeAnomalyPage(1)">Next →</button>
            </div>
            """
        
        # Add sort controls inline with header
        
        return f"""
        <div class="section">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h2 style="margin: 0;">🌐 User Sign-in IP Intelligence</h2>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <label for="ipSortSelect" style="color: #b0b0b0; font-size: 0.9em;">Sort by:</label>
                    <select id="ipSortSelect" onchange="sortIPCards()" style="background: #2d2d2d; color: #e0e0e0; border: 1px solid #404040; border-radius: 4px; padding: 4px 8px; font-size: 0.9em; cursor: pointer;">
                        <option value="default">Default (Risk Level)</option>
                        <option value="last-seen">Last Seen Date</option>
                    </select>
                    <button onclick="copyKQL(event, 'anomalies')" title="Copy KQL Query" style="background: none; border: none; color: #00a1f1; cursor: pointer; font-size: 1.3em; padding: 4px 8px; transition: all 0.2s ease;">📋</button>
                </div>
            </div>
            <div class="ip-grid">
                {''.join(cards)}
            </div>
            {pagination}
        </div>
        """
    
    def _get_mfa_badge(self, auth_detail: str) -> str:
        """Generate MFA badge based on auth pattern"""
        if not auth_detail:
            return ""
        
        # Failure states (check first)
        if "MFA required" in auth_detail or "Authentication failed" in auth_detail:
            return '<span style="background: #f65314; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold;">❌ Failed</span>'
        
        # Token-based authentication (non-interactive, no auth details logged)
        if auth_detail == "Token":
            return '<span style="background: #00b7c3; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold;">🎫 Token</span>'
        
        # MFA states (token reuse OR passkey which is inherently MFA)
        if "MFA requirement satisfied" in auth_detail or "Passkey" in auth_detail:
            return '<span style="background: #7cbb00; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold;">🔒 MFA</span>'
        
        # Interactive password only (single factor)
        if "Correct password" in auth_detail:
            return '<span style="background: #00a1f1; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold;">🔑 Interactive</span>'
        
        # First factor token reuse
        if "First factor requirement satisfied" in auth_detail:
            return '<span style="background: #737373; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold;">PWD</span>'
        return ""
    
    def _build_ip_card(self, ip: IPIntelligence, page: int, style: str) -> str:
        """Build individual IP intelligence card"""
        # Determine risk class
        risk_class_map = {'CRITICAL': 'critical-risk', 'HIGH': 'high-risk', 'MEDIUM': 'medium-risk', 'LOW': 'low-risk', 'INFO': 'low-risk'}
        risk_class = risk_class_map.get(ip.risk_level, 'low-risk')
        
        # Build category badges (inline with IP) - use shared method
        category_badges = self._get_ip_category_badges(ip.categories or [], size='normal')
        
        # Build threat intel content
        threat_intel = ''
        if ip.threat_description or ip.org or ip.asn:
            org = ip.org or 'Unknown'
            asn = ip.asn or 'N/A'
            threat_match = ip.threat_description if ip.threat_description else '✓ None found'
            threat_color = '#f65314' if ip.threat_description else '#7cbb00'
            
            # Detect IP type (matching original report logic)
            org_lower = org.lower()
            is_major_infra = any(provider in org_lower for provider in [
                'microsoft', 'azure', 'amazon', 'aws', 'google', 'gcp', 
                'cloudflare', 'akamai', 'fastly', 'oracle cloud'
            ])
            
            ip_type = ""
            ip_type_color = "#b0b0b0"
            if is_major_infra:
                if 'microsoft' in org_lower or 'azure' in org_lower:
                    ip_type = "☁️ Azure Cloud"
                    ip_type_color = "#00a1f1"
                elif 'amazon' in org_lower or 'aws' in org_lower:
                    ip_type = "☁️ AWS Cloud"
                    ip_type_color = "#ff9900"
                elif 'google' in org_lower or 'gcp' in org_lower:
                    ip_type = "☁️ GCP Cloud"
                    ip_type_color = "#4285f4"
                elif 'cloudflare' in org_lower or 'akamai' in org_lower or 'fastly' in org_lower:
                    ip_type = "☁️ CDN/Edge Network"
                    ip_type_color = "#00a1f1"
                else:
                    ip_type = "☁️ Cloud Provider"
                    ip_type_color = "#00a1f1"
            elif any(res in org_lower for res in ['rogers', 'telus', 'shaw', 'bell', 'comcast', 'at&t', 'verizon', 'spectrum', 'cox']):
                ip_type = "🏠 Residential ISP"
                ip_type_color = "#7cbb00"
            elif 'vpn' in org_lower or 'proxy' in org_lower:
                ip_type = "🔒 VPN/Proxy"
                ip_type_color = "#ffc107"
            elif 'hosting' in org_lower or 'datacenter' in org_lower or 'server' in org_lower:
                ip_type = "🖥️ Hosting/Datacenter"
                ip_type_color = "#ffc107"
            elif 'telecom' in org_lower or 'communications' in org_lower or 'mobile' in org_lower:
                ip_type = "📱 Telecom/Mobile"
                ip_type_color = "#7cbb00"
            elif 'business' in org_lower or 'enterprise' in org_lower or 'corporate' in org_lower:
                ip_type = "🏢 Corporate Network"
                ip_type_color = "#7cbb00"
            else:
                ip_type = "🌐 ISP"
                ip_type_color = "#b0b0b0"
            
            # Build combined threat detection status
            # Combine Sentinel Threat Intel + AbuseIPDB data
            has_threat_intel = threat_match != '✓ None found'
            has_abuseipdb = hasattr(ip, 'abuse_confidence_score') and ip.abuse_confidence_score > 0
            
            threat_details = []
            threat_color = '#7cbb00'  # Default green (clean)
            
            if has_threat_intel:
                threat_details.append(f"<strong>Sentinel:</strong> {threat_match}")
                threat_color = '#f65314'  # Red
            
            if has_abuseipdb:
                score = ip.abuse_confidence_score
                reports = getattr(ip, 'total_reports', 0)
                if score >= 75:
                    abuse_label = f"<strong>AbuseIPDB:</strong> High Risk ({score}/100, {reports} reports)"
                    threat_color = '#f65314'  # Red
                elif score >= 25:
                    abuse_label = f"<strong>AbuseIPDB:</strong> Medium Risk ({score}/100, {reports} reports)"
                    if threat_color != '#f65314':  # Only override if not already red
                        threat_color = '#ffc107'  # Yellow
                else:
                    abuse_label = f"<strong>AbuseIPDB:</strong> Low Risk ({score}/100, {reports} reports)"
                threat_details.append(abuse_label)
            
            if not threat_details:
                combined_threat = '✓ None found'
                threat_color = '#7cbb00'
            else:
                combined_threat = '<br>'.join(threat_details)
            
            # Build status badge
            status_badge = ""
            if has_threat_intel or (has_abuseipdb and ip.abuse_confidence_score >= 25):
                status_badge = '<span style="color: #f65314; font-weight: bold;">⚠️ THREAT DETECTED</span>'
            else:
                status_badge = '<span style="color: #7cbb00; font-weight: bold;">✓ Clean</span>'
            
            # Add VPN detection indicator (from vpnapi.io)
            # Exclude major cloud providers from VPN highlighting
            vpn_indicator = ""
            if hasattr(ip, 'is_vpn') and ip.is_vpn and not is_major_infra:
                vpn_indicator = f" | <span style='color: #ffc107; font-weight: bold;'>🔒 VPN</span>"
            
            threat_intel = f"""
            <details style="width: 100%; margin-top: 8px;">
                <summary style="cursor: pointer; user-select: none;">🔍 Details</summary>
                <div class="threat-intel-content">
                    <div class="threat-row">
                        <span class="label">Organization:</span>
                        <span class="value">{org}</span>
                    </div>
                    <div class="threat-row">
                        <span class="label">ASN:</span>
                        <span class="value">{asn}</span>
                    </div>
                    <div class="threat-row">
                        <span class="label">IP Type:</span>
                        <span class="value" style="color: {ip_type_color}; font-weight: bold;">{ip_type}{vpn_indicator} | {status_badge}</span>
                    </div>
                    <div class="threat-row">
                        <span class="label">Threat Match:</span>
                        <span class="value" style="color: {threat_color};">{combined_threat}</span>
                    </div>
                </div>
            </details>
            """
        
        # Build location display
        location = f"{ip.city}, {ip.country}" if ip.city and ip.country else ip.country or "Unknown"
        
        # Badge color
        badge_class_map = {'CRITICAL': 'badge-critical', 'HIGH': 'badge-high', 'MEDIUM': 'badge-medium', 'LOW': 'badge-low', 'INFO': 'badge-info'}
        badge_class = badge_class_map.get(ip.risk_level, 'badge-info')
        
        # Determine date label and whether to show date based on IP category
        date_label = "First Seen:"
        show_date = False
        if ip.categories:
            if 'anomaly' in ip.categories:
                date_label = "First Seen:"
                show_date = True
            elif 'risky' in ip.categories:
                date_label = "Detected:"
                show_date = True
            elif 'threat' in ip.categories:
                date_label = "Detected:"
                show_date = True
        
        # Build date row(s) - always show first_seen and last_seen if available
        date_row = ""
        if ip.first_seen and ip.last_seen:
            # Both dates available - show in one row with two columns
            date_row = f"""
                <div class="ip-info-item" style="grid-column: 1 / -1; display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="label">{date_label}</span>
                        <span class="value">{ip.first_seen}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="label">Last Seen:</span>
                        <span class="value">{ip.last_seen}</span>
                    </div>
                </div>"""
        elif ip.first_seen:
            # Only first_seen available
            date_row = f"""
                <div class="ip-info-item" style="grid-column: 1 / -1; display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="label">{date_label}</span>
                        <span class="value">{ip.first_seen}</span>
                    </div>
                </div>"""
        elif ip.last_seen:
            # Only last_seen available
            date_row = f"""
                <div class="ip-info-item" style="grid-column: 1 / -1; display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="label">Last Seen:</span>
                        <span class="value">{ip.last_seen}</span>
                    </div>
                </div>"""
        
        # Add data attributes for sorting
        last_seen_timestamp = ip.last_seen or ''
        if last_seen_timestamp:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(last_seen_timestamp.replace('Z', '+00:00'))
                last_seen_sort = dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, AttributeError):
                last_seen_sort = last_seen_timestamp
        else:
            last_seen_sort = '1970-01-01 00:00:00'  # Fallback for missing dates
        
        # Category priority (matches Python get_sort_key logic)
        categories = ip.categories if ip.categories else []
        if 'threat' in categories:
            cat_priority = 0
        elif 'anomaly' in categories and 'risky' in categories:
            cat_priority = 1
        elif 'risky' in categories:
            cat_priority = 2
        elif 'anomaly' in categories:
            cat_priority = 3
        else:
            cat_priority = 4
        
        risk_priority = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5}
        risk_sort = risk_priority.get(ip.risk_level, 99)
        
        # Generate KQL button with unique key
        kql_key = f"ip_{ip.ip.replace('.', '_')}"
        copy_kql_btn = f'<button class="kql-copy-button" onclick="copyKQL(event, \'{kql_key}\')" title="Copy IP Investigation KQL Query" style="margin-left: 2px; padding: 0 2px; font-size: 12px;">📋</button>'
        
        return f"""
        <div class="ip-card {risk_class} anomaly-card" data-page="{page}" data-category="{cat_priority}" data-risk="{risk_sort}" data-last-seen="{last_seen_sort}"{style}>
            <div class="ip-header">
                <div class="ip-address">{ip.ip}{category_badges}</div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="badge {badge_class}">{ip.risk_level.title()}</span>
                    {copy_kql_btn}
                </div>
            </div>
            <div class="ip-info">
                <div class="ip-info-item" style="grid-column: 1 / -1; display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="label">Location:</span>
                        <span class="value">{location}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span class="label">Sign-ins:</span>
                        <span class="value" style="color: #7cbb00;">✓ {ip.success_count if ip.success_count else 0}</span>
                        <span class="value" style="color: #dc3545;">✗ {ip.failure_count if ip.failure_count else 0}</span>
                    </div>
                </div>{date_row}
                <div class="ip-info-item" style="grid-column: 1 / -1; display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="label">Type:</span>
                        <span class="value" style="color: {ip_type_color};">{ip_type or 'N/A'}{vpn_indicator}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="label">Recent Auth:</span>
                        {self._get_mfa_badge(ip.last_auth_result_detail) if ip.last_auth_result_detail else '<span class="value">N/A</span>'}
                    </div>
                </div>
                <div class="ip-info-item" style="grid-column: 1 / -1;">
                    {threat_intel}
                </div>
            </div>
        </div>
        """
    
    def _build_dlp_events(self, result: InvestigationResult) -> str:
        """Build DLP events table"""
        dlp_events = result.dlp_events or []
        
        if not dlp_events:
            return f"""
            <div class="section">
                <h2>📤 Recent DLP Events<button class="kql-copy-button" onclick="copyKQL(event, 'dlp')" title="Copy KQL Query">📋</button></h2>
                <p style="color: #7cbb00; margin-top: 8px;">✓ No DLP events detected</p>
            </div>
            """
        
        rows = []
        for event in dlp_events[:5]:  # Top 5
            # Format time (e.g., "Nov 26 18:19")
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(event.time_generated.replace('Z', '+00:00'))
                time_str = dt.strftime('%b %d %H:%M')
            except (ValueError, AttributeError):
                time_str = event.time_generated
            
            # Operation badge
            operation = event.operation
            if 'NetworkShare' in operation or 'network share' in operation.lower():
                op_badge = '<span class="badge badge-critical">Network Share</span>'
            elif 'Cloud' in operation or 'Upload' in operation:
                op_badge = '<span class="badge badge-high">Cloud Upload</span>'
            else:
                op_badge = f'<span class="badge badge-medium">{operation}</span>'
            
            # Extract just the filename (not full path)
            file = event.file_name.split('\\')[-1] if event.file_name else 'Unknown'
            target = event.target_file_path or event.target_domain or 'Unknown'
            ip_address = event.client_ip
            
            rows.append(f"""
                <tr>
                    <td>{time_str}</td>
                    <td>{op_badge}</td>
                    <td style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{event.file_name}">{file}</td>
                    <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{target}">{target}</td>
                    <td>{ip_address}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <h2>📤 Recent DLP Events<button class="kql-copy-button" onclick="copyKQL(event, 'dlp')" title="Copy KQL Query">📋</button></h2>
            <table>
                <tr>
                    <th style="width: 100px;">Time</th>
                    <th style="width: 130px;">Operation</th>
                    <th style="width: 180px;">File</th>
                    <th style="width: 200px;">Target</th>
                    <th style="width: 120px;">IP Address</th>
                </tr>
                {''.join(rows)}
            </table>
        </div>
        """
    
    def _build_security_incidents(self, result: InvestigationResult) -> str:
        """Build security incidents table with pagination"""
        incidents = result.security_incidents or []
        user_id = result.user_id or ''
        defender_link = f'<a href="https://security.microsoft.com/user?aad={user_id}" target="_blank" style="color: #00a1f1; font-size: 0.75em; margin-left: 10px; text-decoration: none;" title="View user in Microsoft Defender XDR">🛡️</a>' if user_id else ''
        
        if not incidents:
            return f"""
            <div class="section">
                <h2>🚨 Recent Security Incidents<button class="kql-copy-button" onclick="copyKQL(event, 'incidents')" title="Copy KQL Query">📋</button>{defender_link}</h2>
                <p style="color: #7cbb00; margin-top: 8px;">✓ No security incidents detected</p>
            </div>
            """
        
        # No deduplication needed - KQL query already handles this
        # Take top 10 incidents (already deduplicated and sorted by KQL)
        top_incidents = incidents[:10]
        
        rows = []
        for idx, incident in enumerate(top_incidents):
            # Get raw title and shorten if needed
            raw_title = incident.get('Title', 'Unknown')
            # Shorten long titles for better display
            if len(raw_title) > 60:
                # Try to extract meaningful part
                if 'involving one user' in raw_title:
                    title = raw_title.replace(' involving one user', '')
                elif 'in a device' in raw_title:
                    title = raw_title.replace(' in a device', '')
                else:
                    title = raw_title[:60] + '...'
            else:
                title = raw_title
            
            severity = incident.get('Severity', 'Unknown')
            status = incident.get('Status', 'Unknown')
            created_time = incident.get('CreatedTime', 'Unknown')
            owner = incident.get('OwnerUPN', 'Unassigned')
            incident_url = incident.get('ProviderIncidentUrl', '')
            provider_incident_id = incident.get('ProviderIncidentId', 'N/A')
            alert_count = incident.get('AlertCount', 1)
            
            # Format time as "Nov 26 20:59"
            time_str = created_time
            if created_time != 'Unknown':
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(created_time.replace('Z', '+00:00'))
                    time_str = dt.strftime('%b %d %H:%M')
                except (ValueError, AttributeError):
                    time_str = created_time
            
            severity_badge_map = {
                'High': 'badge-critical',
                'Medium': 'badge-medium',
                'Low': 'badge-low',
                'Informational': 'badge-info'
            }
            severity_badge = severity_badge_map.get(severity, 'badge-info')
            
            # Status badge mapping
            status_badge_map = {
                'Active': 'badge-critical',
                'New': 'badge-critical',
                'InProgress': 'badge-medium',
                'Resolved': 'badge-low',
                'Closed': 'badge-info'
            }
            status_badge = status_badge_map.get(status, 'badge-info')
            
            # Style for pagination (4 per page)
            style = '' if idx < 4 else ' style="display: none;"'
            page = (idx // 4) + 1
            
            # Build title cell with link if URL available
            if incident_url:
                title_cell = f'<a href="{incident_url}" target="_blank" rel="noopener noreferrer" style="color: #00a1f1;">{title}</a>'
            else:
                title_cell = title
            
            rows.append(f"""
                <tr class="incident-row" data-page="{page}"{style}>
                    <td>{time_str}</td>
                    <td><span class="badge {severity_badge}">{severity}</span></td>
                    <td>{provider_incident_id}</td>
                    <td style="text-align: center; font-weight: bold; color: #00a1f1;">{alert_count}</td>
                    <td>{title_cell}</td>
                    <td><span class="badge {status_badge}">{status}</span></td>
                    <td>{owner}</td>
                </tr>
            """)
        
        total_pages = (len(top_incidents) + 3) // 4  # 4 per page
        
        pagination = ''
        if total_pages > 1:
            pagination = f"""
            <div class="pagination-controls">
                <button class="page-button" id="incPrevBtn" onclick="changeIncidentPage(-1)" disabled>← Prev</button>
                <span id="incPageInfo" style="color: #b0b0b0;">Page <span id="incCurrentPage">1</span> of {total_pages}</span>
                <button class="page-button" id="incNextBtn" onclick="changeIncidentPage(1)">Next →</button>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>🚨 Recent Security Incidents<button class="kql-copy-button" onclick="copyKQL(event, 'incidents')" title="Copy KQL Query">📋</button>{defender_link}</h2>
            <table id="incidentsTable">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>ID</th>
                        <th style="width: 45px; text-align: center;" title="Number of alerts in this incident">🔔</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Owner</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
            {pagination}
        </div>
        """
    
    def _build_signin_failures(self, result: InvestigationResult) -> str:
        """Build sign-in failures table"""
        signin_events = result.signin_events or {}
        failures = signin_events.get('failures', [])
        
        if not failures:
            return f"""
            <div class="section">
                <h2>🔒 Recent Sign-in Failures<button class="kql-copy-button" onclick="copyKQL(event, 'signin_failures')" title="Copy KQL Query">📋</button></h2>
                <p style="color: #7cbb00; margin-top: 8px;">✓ No sign-in failures detected</p>
            </div>
            """
        
        rows = []
        for failure in failures[:5]:  # Top 5
            # Support both formats: capitalized (from JSON) and lowercase (legacy)
            error_code = failure.get('ResultType') or failure.get('error_code', 'Unknown')
            description = failure.get('ResultDescription') or failure.get('description', 'Unknown')
            count = failure.get('FailureCount') or failure.get('count', 0)
            apps_list = failure.get('Applications') or failure.get('applications', [])
            locations_list = failure.get('Locations') or failure.get('locations', [])
            
            apps = ', '.join(apps_list[:3])  # Top 3 apps
            locations = ', '.join(locations_list[:2])  # Top 2 locations
            
            # Truncate long descriptions to 100 characters (allows ~2-3 rows)
            if len(description) > 100:
                description = description[:97] + '...'
            
            rows.append(f"""
                <tr>
                    <td>{error_code}</td>
                    <td style="white-space: normal; word-wrap: break-word;">{description}</td>
                    <td style="text-align: center;"><strong>{count}</strong></td>
                    <td style="font-size: 0.85em;">{apps}</td>
                    <td style="font-size: 0.85em;">{locations}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <h2>🔒 Recent Sign-in Failures<button class="kql-copy-button" onclick="copyKQL(event, 'signin_failures')" title="Copy KQL Query">📋</button></h2>
            <table>
                <thead>
                    <tr>
                        <th>Error</th>
                        <th>Description</th>
                        <th style="text-align: center;">Count</th>
                        <th>Applications</th>
                        <th>Locations</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        """
    
    def _build_office_activity(self, result: InvestigationResult) -> str:
        """Build Office 365 activity stats"""
        office_events = result.office_events or []
        
        if not office_events:
            return f"""
            <div class="section">
                <h2>📈 Common Office 365 Activity<button class="kql-copy-button" onclick="copyKQL(event, 'activity_summary')" title="Copy KQL Query">📋</button></h2>
                <p style="color: #7cbb00; margin-top: 8px;">✓ No Office 365 activity detected</p>
            </div>
            """
        
        # Map operation names to friendly labels
        operation_labels = {
            'MailItemsAccessed': 'Emails Accessed',
            'MessageRead': 'Teams Messages',
            'PerformedCardAction': 'Teams Card Actions',
            'FileAccessed': 'SharePoint Access',
            'Send': 'Emails Sent',
            'FileModified': 'Files Modified',
            'FileSyncDownloadedFull': 'OneDrive Syncs'
        }
        
        # Build 3-column grid for top 5 Office activities
        cards = []
        for event in office_events[:5]:  # Top 5 activities
            operation = event.get('Operation', event.get('operation', 'Unknown'))
            count = event.get('ActivityCount', event.get('count', 0))
            label = operation_labels.get(operation, operation)
            
            cards.append(f"""
                <div style="background: #2a2a2a; padding: 10px; border-radius: 4px; text-align: center;">
                    <div style="font-size: 1.5em; font-weight: bold; color: #7cbb00;">{count}</div>
                    <div style="font-size: 0.85em; color: #b0b0b0;">{label}</div>
                </div>
            """)
        
        return f"""
        <div class="section">
            <h2>📈 Common Office 365 Activity<button class="kql-copy-button" onclick="copyKQL(event, 'activity_summary')" title="Copy KQL Query">📋</button></h2>
            <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-top: 8px;">
                {''.join(cards)}
            </div>
        </div>
        """
    
    def _build_audit_activity(self, result: InvestigationResult) -> str:
        """Build Azure AD audit log activity table with pagination"""
        audit_events = result.audit_events or []
        
        if not audit_events:
            return f"""
            <div class="section">
                <h2>📋 Recent Azure AD Audit Log Activity<button class="kql-copy-button" onclick="copyKQL(event, 'audit')" title="Copy KQL Query">📋</button></h2>
                <p style="color: #7cbb00; margin-top: 8px;">✓ No audit log activity detected</p>
            </div>
            """
        
        # Check if aggregated or raw events
        is_aggregated = audit_events and 'Category' in audit_events[0]
        
        if is_aggregated:
            # Calculate total events
            total_events = sum(event.get('Count', event.get('count', 0)) for event in audit_events)
            
            # Build table rows for all audit events (paginated client-side)
            all_rows = []
            for i, event in enumerate(audit_events):
                category = event.get('Category', 'Unknown')
                count = event.get('Count', event.get('count', 0))
                result_status = event.get('Result', 'Unknown')
                operations = event.get('Operations', [])
                
                # Category badge
                category_colors = {
                    'RoleManagement': '#f65314',
                    'UserManagement': '#00a1f1',
                    'ApplicationManagement': '#7cbb00',
                    'Policy': '#ffbb00'
                }
                category_color = category_colors.get(category, '#737373')
                category_badge = f'<span style="background: {category_color}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;">{category}</span>'
                
                # Result badge
                result_color = '#7cbb00' if result_status == 'success' else '#f65314'
                result_badge = f'<span style="background: {result_color}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;">{result_status}</span>'
                
                # Operations (show all with wrapping and highlight sensitive ones)
                sensitive_keywords = [
                    'password', 'reset', 'secret', 'key', 'credential', 'permission', 
                    'consent', 'grant', 'role', 'admin', 'privilege', 'oauth', 'certificate',
                    'conditional access', 'policy'
                ]
                
                # Build operations display with highlighting
                ops_html = []
                for op in operations:
                    is_sensitive = any(keyword in op.lower() for keyword in sensitive_keywords)
                    if is_sensitive:
                        ops_html.append(f'<span style="color: #f65314; font-weight: 500;">🔐 {op}</span>')
                    else:
                        ops_html.append(op)
                
                ops_display = ', '.join(ops_html)
                
                # Check if ANY operation is sensitive for row highlighting
                has_sensitive = any(keyword in op.lower() for op in operations for keyword in sensitive_keywords)
                row_bg = 'background: rgba(246, 83, 20, 0.1);' if has_sensitive else ''
                
                # Add page class (5 per page)
                page_num = (i // 5) + 1
                display_style = '' if i < 5 else 'display: none;'
                
                all_rows.append(f"""
                    <tr class="audit-row" data-page="{page_num}" style="{display_style} {row_bg}">
                        <td>{category_badge}</td>
                        <td style="text-align: center;"><strong>{count}</strong></td>
                        <td style="text-align: center;">{result_badge}</td>
                        <td style="font-size: 0.85em; white-space: normal; word-wrap: break-word;">{ops_display}</td>
                    </tr>
                """)
            
            total_pages = (len(audit_events) + 2) // 3  # 3 per page
            
            pagination = ''
            if total_pages > 1:
                pagination = f"""
                <div class="pagination-controls">
                    <button class="page-button" id="auditPrevBtn" onclick="changeAuditPage(-1)" disabled>← Prev</button>
                    <span id="auditPageInfo" style="color: #b0b0b0;">Page <span id="auditCurrentPage">1</span> of {total_pages}</span>
                    <button class="page-button" id="auditNextBtn" onclick="changeAuditPage(1)">Next →</button>
                </div>
                """
            
            return f"""
            <div class="section">
                <h2>📋 Recent Azure AD Audit Log Activity<button class="kql-copy-button" onclick="copyKQL(event, 'audit')" title="Copy KQL Query">📋</button></h2>
                <table style="margin-top: 8px;">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th style="text-align: center;">Count</th>
                            <th style="text-align: center;">Result</th>
                            <th>Operations</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(all_rows)}
                    </tbody>
                </table>
                {pagination}
            </div>
            """
        else:
            # Raw events - paginated 3 per page
            sensitive_keywords = [
                'password', 'reset', 'secret', 'key', 'credential', 'permission', 
                'consent', 'grant', 'role', 'admin', 'privilege', 'oauth', 'certificate',
                'conditional access', 'policy'
            ]
            
            all_rows = []
            for i, event in enumerate(audit_events):
                timestamp = event.get('TimeGenerated', 'Unknown')[:16]
                operation = event.get('OperationName', 'Unknown')
                result_status = event.get('Result', 'Unknown')
                
                # Check if operation is sensitive
                is_sensitive = any(keyword in operation.lower() for keyword in sensitive_keywords)
                
                # Highlight sensitive operations
                if is_sensitive:
                    operation_display = f'<span style="color: #f65314; font-weight: 500;">🔐 {operation}</span>'
                    row_bg = 'background: rgba(246, 83, 20, 0.1);'
                else:
                    operation_display = operation
                    row_bg = ''
                
                result_color = '#7cbb00' if result_status == 'success' else '#f65314'
                result_badge = f'<span style="background: {result_color}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;">{result_status}</span>'
                
                page_num = (i // 5) + 1
                display_style = '' if i < 5 else 'display: none;'
                
                all_rows.append(f"""
                    <tr class="audit-row" data-page="{page_num}" style="{display_style} {row_bg}">
                        <td style="font-size: 0.85em;">{timestamp}</td>
                        <td>{operation_display}</td>
                        <td style="text-align: center;">{result_badge}</td>
                    </tr>
                """)
            
            total_pages = (len(audit_events) + 4) // 5  # 5 per page
            
            pagination = ''
            if total_pages > 1:
                pagination = f"""
                <div class="pagination-controls">
                    <button class="page-button" id="auditPrevBtn" onclick="changeAuditPage(-1)" disabled>← Prev</button>
                    <span id="auditPageInfo" style="color: #b0b0b0;">Page <span id="auditCurrentPage">1</span> of {total_pages}</span>
                    <button class="page-button" id="auditNextBtn" onclick="changeAuditPage(1)">Next →</button>
                </div>
                """
            
            return f"""
            <div class="section">
                <h2>📋 Recent Azure AD Audit Log Activity<button class="kql-copy-button" onclick="copyKQL(event, 'audit')" title="Copy KQL Query">📋</button></h2>
                <table style="margin-top: 8px;">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Operation</th>
                            <th style="text-align: center;">Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(all_rows)}
                    </tbody>
                </table>
                {pagination}
            </div>
            """
    
    def _build_recommendations(self, result: InvestigationResult) -> str:
        """Build full-width recommendations section with three columns"""
        recommendations = result.recommendations or {}
        critical = recommendations.get('critical_actions', [])
        high_priority = recommendations.get('high_priority_actions', [])
        monitoring = recommendations.get('monitoring_actions', [])
        
        # Build critical actions list
        critical_html = ''
        for action in critical:
            # Remove HTML tags for cleaner display
            clean_action = action.replace('<strong>', '').replace('</strong>', '').replace('<br>', ': ')
            critical_html += f'<li>{clean_action}</li>'
        
        if not critical_html:
            critical_html = '<li>No critical actions required</li>'
        
        # Build high priority actions list
        high_html = ''
        for action in high_priority:
            clean_action = action.replace('<strong>', '').replace('</strong>', '').replace('<br>', ': ')
            high_html += f'<li>{clean_action}</li>'
        
        if not high_html:
            high_html = '<li>No high priority actions</li>'
        
        # Build monitoring actions list
        monitoring_html = ''
        for action in monitoring:
            monitoring_html += f'<li>{action}</li>'
        
        if not monitoring_html:
            monitoring_html = '<li>Continue normal monitoring procedures</li>'
        
        return f"""
        <div style="padding: 10px;">
            <div class="section">
                <h2>💡 Recommendations</h2>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                    <div>
                        <h3 style="color: #f65314; font-size: 1em; margin-bottom: 6px;">Critical (Immediate)</h3>
                        <ul style="font-size: 0.85em;">
                            {critical_html}
                        </ul>
                    </div>
                    <div>
                        <h3 style="color: #ffbb00; font-size: 1em; margin-bottom: 6px;">High Priority (24 hours)</h3>
                        <ul style="font-size: 0.85em;">
                            {high_html}
                        </ul>
                    </div>
                    <div>
                        <h3 style="color: #00a1f1; font-size: 1em; margin-bottom: 6px;">Monitoring (14 days)</h3>
                        <ul style="font-size: 0.85em;">
                            {monitoring_html}
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _build_timeline_modal(self, result: InvestigationResult) -> str:
        """Build timeline modal with chronological events"""
        timeline_items = self._build_timeline_items(result)
        
        return f"""
        <div id="timelineModal" class="timeline-modal">
            <div class="timeline-modal-content">
                <span class="timeline-close" onclick="closeTimeline()">&times;</span>
                <h2 style="color: #00a1f1; margin-bottom: 20px;">📅 Investigation Timeline</h2>
                <div class="timeline">
                    {timeline_items}
                </div>
            </div>
        </div>
        """
    
    def _build_timeline_items(self, result: InvestigationResult) -> str:
        """Build chronological timeline items"""
        events = []
        
        # Helper function to get IP badges
        def get_ip_badges(ip_address: str) -> str:
            if not ip_address:
                return ''
            
            # Build categories from raw data sources (not just enriched IPs)
            categories = []
            
            # Check if this IP is in anomalies
            for anomaly in (result.anomalies or []):
                if anomaly.anomaly_type.endswith('IP') and anomaly.value == ip_address:
                    if 'anomaly' not in categories:
                        categories.append('anomaly')
                    break
            
            # Check if this IP is in risky signins/detections
            for risky_signin in (result.risky_signins or []):
                if risky_signin.ip_address == ip_address:
                    if 'risky' not in categories:
                        categories.append('risky')
                    break
            
            for risk_detection in (result.risk_detections or []):
                if risk_detection.ip_address == ip_address:
                    if 'risky' not in categories:
                        categories.append('risky')
                    break
            
            # Check enriched IP data for threat intel and frequency badges
            if result.ip_intelligence:
                enriched_ip = next((ip for ip in result.ip_intelligence if ip.ip == ip_address), None)
                if enriched_ip and enriched_ip.categories:
                    # Add threat and frequency categories from enriched data
                    for cat in enriched_ip.categories:
                        if cat in ['threat', 'primary', 'active'] and cat not in categories:
                            categories.append(cat)
            
            if not categories:
                return ''
            
            return self._get_ip_category_badges(categories, size='small')
        
        # Collect all timestamped events
        
        # Anomalies
        for anomaly in (result.anomalies or []):
            # Add IP badges for all IP-type anomalies (both Interactive and NonInteractive)
            ip_badges = get_ip_badges(anomaly.value) if anomaly.anomaly_type.endswith('IP') else ''
            details = f'{anomaly.anomaly_type}: {anomaly.value} from {anomaly.city}, {anomaly.country}'
            if ip_badges:
                details += f' {ip_badges}'
            events.append({
                'time': anomaly.detected_date,
                'severity': anomaly.severity.lower(),
                'icon': '🚨',
                'title': f'Sign-in Anomaly',
                'details': details
            })
        
        # Risk Detections
        for detection in (result.risk_detections or []):
            location = f"{detection.location_city}, {detection.location_country}" if detection.location_city else detection.location_country
            ip_badges = get_ip_badges(detection.ip_address)
            details_parts = []
            if location:
                details_parts.append(location)
            if detection.ip_address:
                details_parts.append(f"({detection.ip_address})")
            details_parts.append(f"- {detection.risk_state}")
            if ip_badges:
                details_parts.append(ip_badges)
            events.append({
                'time': detection.detected_date,
                'severity': detection.risk_level.lower() if detection.risk_level else 'medium',
                'icon': '⚠️',
                'title': f'Identity Protection: {detection.risk_event_type}',
                'details': ' '.join(details_parts)
            })
        
        # Risky Sign-ins
        for signin in (result.risky_signins or []):
            location = f"{signin.location_city}, {signin.location_country}" if signin.location_city else signin.location_country
            ip_badges = get_ip_badges(signin.ip_address)
            details = f"{location} ({signin.ip_address}) - {signin.risk_state}" if location else f"{signin.ip_address} - {signin.risk_state}"
            if ip_badges:
                details += f" {ip_badges}"
            events.append({
                'time': signin.created_date,
                'severity': signin.risk_level.lower() if signin.risk_level else 'medium',
                'icon': '🔐',
                'title': f'Risky Sign-in: {signin.app_display_name}',
                'details': details
            })
        
        # DLP Events
        for dlp in (result.dlp_events or []):
            filename = dlp.file_name.split("\\")[-1] if "\\" in dlp.file_name else dlp.file_name
            ip_badges = get_ip_badges(dlp.client_ip)
            details = f'{dlp.operation} - {filename}'
            if ip_badges:
                details += f' {ip_badges}'
            events.append({
                'time': dlp.time_generated,
                'severity': 'high',
                'icon': '📁',
                'title': 'DLP Event',
                'details': details,
                'ip': dlp.client_ip  # Store IP for grouping
            })
        
        # Security Incidents
        for incident in (result.security_incidents or []):
            severity_map = {'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Informational': 'low'}
            # Use both uppercase and lowercase field names
            title = incident.get('Title') or incident.get('title', 'Security Incident')
            status = incident.get('Status') or incident.get('status', 'Unknown')
            severity = incident.get('Severity') or incident.get('severity', 'Medium')
            created_time = incident.get('CreatedTime') or incident.get('created_time')
            
            events.append({
                'time': created_time,
                'severity': severity_map.get(severity, 'medium'),
                'icon': '🛡️',
                'title': f'Security Incident: {title}',
                'details': f'Status: {status} | Severity: {severity}'
            })
        
        # Sort by time (newest first)
        events.sort(key=lambda x: x['time'] if x['time'] else '', reverse=True)
        
        # Group DLP events that are within 5 minutes of each other
        from datetime import datetime, timedelta
        consolidated_events = []
        i = 0
        while i < len(events):
            event = events[i]
            
            # Check if this is a DLP event
            if event.get('title') == 'DLP Event':
                # Look ahead for more DLP events within 5 minutes
                dlp_group = [event]
                try:
                    current_time = datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
                    j = i + 1
                    while j < len(events) and events[j].get('title') == 'DLP Event':
                        next_event = events[j]
                        next_time = datetime.fromisoformat(next_event['time'].replace('Z', '+00:00'))
                        time_diff = abs((current_time - next_time).total_seconds())
                        
                        if time_diff <= 300:  # 5 minutes in seconds
                            dlp_group.append(next_event)
                            j += 1
                        else:
                            break
                    
                    # If we found multiple DLP events, consolidate them
                    if len(dlp_group) > 1:
                        # Extract file names and IPs from all events
                        files = [e['details'].split(' - ', 1)[-1] for e in dlp_group]
                        operations = set(e['details'].split(' - ', 1)[0] for e in dlp_group)
                        ips = list(set(e.get('ip') for e in dlp_group if e.get('ip')))
                        
                        # Build details string with IPs
                        details = f'{", ".join(operations)} - {", ".join(files[:3])}{"..." if len(files) > 3 else ""}'
                        if ips:
                            details += f' | Device IP: {", ".join(ips[:2])}{"..." if len(ips) > 2 else ""}'
                        
                        consolidated_events.append({
                            'time': event['time'],
                            'severity': 'high',
                            'icon': '📁',
                            'title': f'DLP Events ({len(dlp_group)} files)',
                            'details': details
                        })
                        i = j  # Skip the grouped events
                    else:
                        # Single DLP event - add IP if available
                        if event.get('ip'):
                            event_copy = event.copy()
                            event_copy['details'] = f"{event['details']} | Device IP: {event['ip']}"
                            consolidated_events.append(event_copy)
                        else:
                            consolidated_events.append(event)
                        i += 1
                except (ValueError, AttributeError):
                    # If parsing fails, just add the event as-is
                    consolidated_events.append(event)
                    i += 1
            else:
                consolidated_events.append(event)
                i += 1
        
        # Group by date and build HTML
        html_parts = []
        current_date = None
        
        from datetime import datetime
        from zoneinfo import ZoneInfo
        
        for event in consolidated_events:  # Show ALL events (no limit)
            if not event['time']:
                continue
            
            try:
                # Parse UTC time and convert to PST
                utc_time = datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
                pst_time = utc_time.astimezone(ZoneInfo('America/Los_Angeles'))
                event_date = pst_time.strftime('%Y-%m-%d')
                event_time = pst_time.strftime('%H:%M')
            except (ValueError, AttributeError, KeyError):
                # Fallback to original parsing if conversion fails
                event_date = event['time'].split('T')[0] if 'T' in event['time'] else event['time'].split(' ')[0]
                event_time = event['time'].split('T')[1][:5] if 'T' in event['time'] else event['time'].split(' ')[1][:5] if ' ' in event['time'] else ''
            
            # Add date separator
            if event_date != current_date:
                current_date = event_date
                html_parts.append(f"""
                    <div class="timeline-date-separator">
                        <div class="timeline-date-label">{event_date}</div>
                    </div>
                """)
            
            # Add event
            html_parts.append(f"""
                <div class="timeline-item">
                    <div class="timeline-marker {event['severity']}">
                        <span class="timeline-icon">{event['icon']}</span>
                    </div>
                    <div class="timeline-content">
                        <div class="timeline-time">{event_time} PST</div>
                        <div class="timeline-title">{event['title']}</div>
                        <div class="timeline-details">{event['details']}</div>
                    </div>
                </div>
            """)
        
        return ''.join(html_parts) if html_parts else '<p style="color: #b0b0b0;">No timeline events available</p>'
    
    def _get_styles(self) -> str:
        """Get CSS styles for compact report"""
        return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 13.5px;
            line-height: 1.4;
            color: #e0e0e0;
            background: #1a1a1a;
            padding: 11.25px;
        }
        
        .container {
            max-width: 1575px;
            margin: 0 auto;
            background: #1e1e1e;
            border-radius: 6.75px;
            box-shadow: 0 4.5px 22.5px rgba(0,0,0,0.5);
        }
        
        .header {
            background: linear-gradient(135deg, #00a1f1 0%, #0078d4 100%);
            color: white;
            padding: 16.875px 22.5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 1.6875em;
            margin: 0;
        }
        
        .header .meta {
            font-size: 0.85em;
            text-align: right;
        }
        
        .content {
            display: grid;
            grid-template-columns: 1.7fr 5px 3.3fr;
            gap: 11.25px;
            padding: 11.25px;
            position: relative;
        }
        
        .resize-handle {
            cursor: col-resize;
            background: transparent;
            position: relative;
            width: 5px;
            margin: 0 3px;
        }
        
        .resize-handle:hover {
            background: #00a1f1;
        }
        
        .resize-handle::before {
            content: '';
            position: absolute;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            width: 3px;
            height: 30px;
            background: #3a3a3a;
            border-radius: 2px;
        }
        
        .resize-handle:hover::before {
            background: #00a1f1;
        }
        
        .left-column, .right-column {
            display: flex;
            flex-direction: column;
            gap: 11.25px;
        }
        
        .section {
            background: #252525;
            border-radius: 4.5px;
            padding: 13.5px;
            border-left: 3.375px solid #00a1f1;
        }
        
        .section h2 {
            font-size: 1.2375em;
            color: #00a1f1;
            margin-bottom: 9px;
            padding-bottom: 4.5px;
            border-bottom: 1.125px solid #3a3a3a;
            position: relative;
        }
        
        .metrics {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 9px;
        }
        
        .metric {
            background: linear-gradient(135deg, #00a1f1 0%, #0078d4 100%);
            padding: 11.25px;
            border-radius: 4.5px;
            text-align: center;
        }
        
        .metric-value {
            font-size: 2.025em;
            font-weight: bold;
            color: white;
        }
        
        .metric-label {
            font-size: 0.95625em;
            color: rgba(255,255,255,0.9);
            margin-top: 2.25px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 1.0125em;
        }
        
        #incidentsTable {
            min-height: 270px;
        }
        
        th {
            background: #2a2a2a;
            color: #00a1f1;
            padding: 6.75px 9px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2.25px solid #3a3a3a;
        }
        
        td {
            padding: 5.625px 9px;
            border-bottom: 1.125px solid #2a2a2a;
        }
        
        tr:hover {
            background: #2a2a2a;
        }
        
        .ip-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 9px;
        }
        
        .ip-card {
            background: #2a2a2a;
            border-left: 3.375px solid #ffbb00;
            padding: 11.25px;
            border-radius: 4.5px;
        }
        
        .ip-card.critical-risk { border-left-color: #f65314; }
        .ip-card.high-risk { border-left-color: #f65314; }
        .ip-card.medium-risk { border-left-color: #ffbb00; }
        .ip-card.low-risk { border-left-color: #7cbb00; }
        
        .ip-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6.75px;
        }
        
        .ip-address {
            font-weight: 600;
            color: #00a1f1;
            font-size: 1.18125em;
        }
        
        .ip-info {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 4.5px;
            font-size: 0.95625em;
        }
        
        .ip-info-item {
            display: flex;
            justify-content: space-between;
        }
        
        .label {
            color: #b0b0b0;
            font-weight: 500;
        }
        
        .value {
            color: #e0e0e0;
            font-weight: 600;
        }
        
        .alert {
            padding: 9px 13.5px;
            margin: 6.75px 0;
            border-left: 3.375px solid;
            border-radius: 3.375px;
            font-size: 1.0125em;
        }
        
        .alert-critical { background: #3d1f1f; border-color: #f65314; }
        .alert-high { background: #3d3520; border-color: #ffbb00; }
        .alert-medium { background: #1f2f3d; border-color: #00a1f1; }
        
        .badge {
            display: inline-block;
            padding: 2.25px 9px;
            border-radius: 3.375px;
            font-size: 0.9em;
            font-weight: 600;
            margin: 2.25px;
        }
        
        .badge-critical { background: #f65314; color: white; }
        .badge-high { background: #ffbb00; color: #1a1a1a; }
        .badge-medium { background: #00a1f1; color: white; }
        .badge-low { background: #7cbb00; color: white; }
        .badge-info { background: #737373; color: white; }
        
        ul {
            margin: 6.75px 0 6.75px 22.5px;
            font-size: 1.0125em;
        }
        
        li {
            margin: 3.375px 0;
        }
        
        details {
            margin: 9px 0;
        }
        
        summary {
            cursor: pointer;
            padding: 9px;
            background: #2a2a2a;
            border-radius: 4.5px;
            font-weight: 600;
            color: #00a1f1;
        }
        
        summary:hover {
            background: #333;
        }
        
        details[open] summary {
            margin-bottom: 9px;
        }
        
        .ip-card details {
            margin-top: 9px;
            border-top: 1.125px solid #3a3a3a;
            padding-top: 9px;
        }
        
        .ip-card summary {
            padding: 6.75px 9px;
            background: #333;
            border-radius: 3.375px;
            font-size: 0.95625em;
            cursor: pointer;
            color: #00a1f1;
            font-weight: 500;
        }
        
        .ip-card summary::marker {
            color: #00a1f1;
        }
        
        .threat-intel-content {
            padding: 9px;
            background: #2a2a2a;
            border-radius: 3.375px;
            margin-top: 6.75px;
            font-size: 0.95625em;
        }
        
        .threat-row {
            display: flex;
            justify-content: space-between;
            padding: 4.5px 0;
            border-bottom: 1.125px solid #333;
        }
        
        .threat-row:last-child {
            border-bottom: none;
        }
        
        .timeline-button {
            background: linear-gradient(135deg, #00a1f1 0%, #0078d4 100%);
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            width: 100%;
            transition: all 0.2s ease;
        }
        
        .timeline-button:hover {
            background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 120, 212, 0.4);
        }
        
        .timeline-modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
        }
        
        .timeline-modal.active {
            display: block;
        }
        
        .timeline-modal-content {
            background: #1e1e1e;
            margin: 5% auto;
            padding: 20px;
            border: 1px solid #00a1f1;
            border-radius: 8px;
            width: 60%;
            max-width: 900px;
            max-height: 80vh;
            overflow-y: auto;
            position: relative;
        }
        
        .timeline-close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            line-height: 20px;
        }
        
        .timeline-close:hover,
        .timeline-close:focus {
            color: #00a1f1;
        }
        
        .footer {
            background: #252525;
            padding: 10px 20px;
            text-align: center;
            font-size: 0.85em;
            color: #737373;
            border-top: 1px solid #3a3a3a;
        }
        
        .timeline {
            position: relative;
            padding-left: 30px;
            margin-top: 20px;
        }
        
        .timeline::before {
            content: '';
            position: absolute;
            left: 10px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: linear-gradient(to bottom, #00a1f1, #0078d4);
        }
        
        .timeline-date-separator {
            margin: 20px 0 15px 0;
            padding: 8px 12px;
            background: linear-gradient(135deg, #2d1f1f 0%, #3d2020 100%);
            border-left: 4px solid #00a1f1;
            border-radius: 4px;
        }
        
        .timeline-date-label {
            color: #00a1f1;
            font-weight: 600;
            font-size: 1.1em;
        }
        
        .timeline-item {
            position: relative;
            margin-bottom: 20px;
            padding-left: 30px;
        }
        
        .timeline-marker {
            position: absolute;
            left: -20px;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 2px solid #1e1e1e;
        }
        
        .timeline-marker.medium {
            background: #ffbb00;
        }
        
        .timeline-marker.low {
            background: #7cbb00;
        }
        
        .timeline-marker.high {
            background: #f65314;
        }
        
        .timeline-icon {
            font-size: 12px;
        }
        
        .timeline-content {
            background: #252525;
            padding: 12px;
            border-radius: 6px;
            border-left: 3px solid #00a1f1;
        }
        
        .timeline-time {
            color: #b0b0b0;
            font-size: 0.85em;
            margin-bottom: 5px;
        }
        
        .timeline-title {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .timeline-details {
            color: #b0b0b0;
            font-size: 0.9em;
        }
        
        .pagination-controls {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #333;
        }
        
        .page-button {
            background: linear-gradient(135deg, #00a1f1 0%, #0078d4 100%);
            color: white;
            border: none;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.2s ease;
        }
        
        .page-button:hover:not(:disabled) {
            background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
            transform: translateY(-1px);
        }
        
        .page-button:disabled {
            background: #333;
            color: #666;
            cursor: not-allowed;
        }
        
        .page-info {
            color: #b0b0b0;
        }
        
        .kql-copy-button {
            background: none;
            border: none;
            color: #00a1f1;
            cursor: pointer;
            font-size: 0.9em;
            padding: 0 8px;
            transition: all 0.2s ease;
        }
        
        /* Absolute positioning for section header buttons */
        .section h2 .kql-copy-button {
            position: absolute;
            right: 0;
            top: 6px;
        }
        
        .kql-copy-button:hover {
            color: #0078d4;
            transform: scale(1.1);
        }
    </style>
        """
    
    def _get_javascript(self) -> str:
        """Get JavaScript for interactivity"""
        # Build KQL queries object
        kql_json = json.dumps(self.kql_queries, indent=4)
        
        return f"""
    <script>
        const kqlQueries = {kql_json};
        
        // Track if Lake Explorer has been opened
        let lakeExplorerOpened = false;
        
        function copyKQL(event, queryType) {{
            event.stopPropagation();
            const query = kqlQueries[queryType] || 'Query not available';
            
            // Copy to clipboard
            navigator.clipboard.writeText(query).then(() => {{
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '✓';
                btn.style.color = '#7cbb00';
                setTimeout(() => {{
                    btn.textContent = originalText;
                    btn.style.color = '#00a1f1';
                }}, 2000);
                
                // Open Lake Explorer only on first click
                if (!lakeExplorerOpened) {{
                    window.open('https://security.microsoft.com/lake-explorer', '_blank');
                    lakeExplorerOpened = true;
                }}
            }});
        }}
        
        function openTimeline() {{
            document.getElementById('timelineModal').classList.add('active');
        }}
        
        function closeTimeline() {{
            document.getElementById('timelineModal').classList.remove('active');
        }}
        
        // Close modal on ESC or outside click
        window.onclick = function(event) {{
            const modal = document.getElementById('timelineModal');
            if (event.target === modal) {{
                closeTimeline();
            }}
        }}
        
        document.addEventListener('keydown', function(event) {{
            if (event.key === 'Escape') {{
                closeTimeline();
            }}
        }});
        
        // IP Intelligence Pagination
        let currentAnomalyPage = 1;
        const ipsPerPage = 4;
        
        function changeAnomalyPage(direction) {{
            const cards = document.querySelectorAll('.anomaly-card');
            const totalPages = Math.ceil(cards.length / ipsPerPage);
            
            currentAnomalyPage += direction;
            currentAnomalyPage = Math.max(1, Math.min(currentAnomalyPage, totalPages));
            
            cards.forEach(card => {{
                card.style.display = parseInt(card.dataset.page) === currentAnomalyPage ? 'block' : 'none';
            }});
            
            document.getElementById('currentPage').textContent = currentAnomalyPage;
            document.getElementById('prevBtn').disabled = currentAnomalyPage === 1;
            document.getElementById('nextBtn').disabled = currentAnomalyPage === totalPages;
        }}
        
        function sortIPCards() {{
            const sortBy = document.getElementById('ipSortSelect').value;
            const ipGrid = document.querySelector('.ip-grid');
            const cards = Array.from(ipGrid.querySelectorAll('.anomaly-card')); // SCOPED to ipGrid only!
            
            // Sort cards based on selection
            cards.sort((a, b) => {{
                if (sortBy === 'last-seen') {{
                    // Sort by last seen date (newest first)
                    const dateA = a.dataset.lastSeen || '1970-01-01 00:00:00';
                    const dateB = b.dataset.lastSeen || '1970-01-01 00:00:00';
                    return dateB.localeCompare(dateA);
                }} else {{
                    // Default: Sort by category priority first, then risk level
                    // CRITICAL: Use isNaN check, NOT || 99, because parseInt("0") returns 0 which is falsy!
                    const catA = parseInt(a.dataset.category);
                    const catB = parseInt(b.dataset.category);
                    const riskA = parseInt(a.dataset.risk);
                    const riskB = parseInt(b.dataset.risk);
                    
                    const catAVal = isNaN(catA) ? 99 : catA;
                    const catBVal = isNaN(catB) ? 99 : catB;
                    const riskAVal = isNaN(riskA) ? 99 : riskA;
                    const riskBVal = isNaN(riskB) ? 99 : riskB;
                    
                    if (catAVal !== catBVal) {{
                        return catAVal - catBVal;
                    }}
                    return riskAVal - riskBVal;
                }}
            }});
            
            // Re-order cards in the DOM without destroying them
            // This preserves all data attributes
            cards.forEach((card, idx) => {{
                card.dataset.page = Math.floor(idx / ipsPerPage) + 1;
                card.style.display = (idx < ipsPerPage) ? 'block' : 'none'; // Show first page only
                ipGrid.appendChild(card); // appendChild moves the element if it already exists
            }});
            
            // Reset to page 1
            currentAnomalyPage = 1;
            const totalPages = Math.ceil(cards.length / ipsPerPage);
            
            // Update pagination controls
            if (document.getElementById('currentPage')) {{
                document.getElementById('currentPage').textContent = 1;
                document.getElementById('prevBtn').disabled = true;
                document.getElementById('nextBtn').disabled = totalPages <= 1;
            }}
        }}
        
        // Security Incidents Pagination
        let currentIncidentPage = 1;
        const incidentsPerPage = 4;
        
        function changeIncidentPage(direction) {{
            const rows = document.querySelectorAll('.incident-row');
            const totalPages = Math.ceil(rows.length / incidentsPerPage);
            
            currentIncidentPage += direction;
            currentIncidentPage = Math.max(1, Math.min(currentIncidentPage, totalPages));
            
            rows.forEach(row => {{
                row.style.display = parseInt(row.dataset.page) === currentIncidentPage ? '' : 'none';
            }});
            
            document.getElementById('incCurrentPage').textContent = currentIncidentPage;
            document.getElementById('incPrevBtn').disabled = currentIncidentPage === 1;
            document.getElementById('incNextBtn').disabled = currentIncidentPage === totalPages;
        }}
        
        // Top Locations Pagination
        let currentLocationPage = 1;
        const locationsPerPage = 3;
        
        function changeLocationPage(direction) {{
            const rows = document.querySelectorAll('.location-row');
            const totalPages = Math.ceil(rows.length / locationsPerPage);
            
            currentLocationPage += direction;
            currentLocationPage = Math.max(1, Math.min(currentLocationPage, totalPages));
            
            rows.forEach(row => {{
                row.style.display = parseInt(row.dataset.page) === currentLocationPage ? '' : 'none';
            }});
            
            document.getElementById('locCurrentPage').textContent = currentLocationPage;
            document.getElementById('locPrevBtn').disabled = currentLocationPage === 1;
            document.getElementById('locNextBtn').disabled = currentLocationPage === totalPages;
        }}
        
        // Top Applications Pagination
        let currentApplicationPage = 1;
        const applicationsPerPage = 3;
        
        function changeApplicationPage(direction) {{
            const rows = document.querySelectorAll('.application-row');
            const totalPages = Math.ceil(rows.length / applicationsPerPage);
            
            currentApplicationPage += direction;
            currentApplicationPage = Math.max(1, Math.min(currentApplicationPage, totalPages));
            
            rows.forEach(row => {{
                row.style.display = parseInt(row.dataset.page) === currentApplicationPage ? '' : 'none';
            }});
            
            document.getElementById('appCurrentPage').textContent = currentApplicationPage;
            document.getElementById('appPrevBtn').disabled = currentApplicationPage === 1;
            document.getElementById('appNextBtn').disabled = currentApplicationPage === totalPages;
        }}
        
        // Column Resizing
        (function() {{
            const resizeHandle = document.querySelector('.resize-handle');
            const container = document.querySelector('.content');
            const leftColumn = document.querySelector('.left-column');
            const rightColumn = document.querySelector('.right-column');
            
            if (!resizeHandle || !container || !leftColumn || !rightColumn) return;
            
            let isResizing = false;
            let startX = 0;
            let startLeftWidth = 0;
            let startRightWidth = 0;
            
            resizeHandle.addEventListener('mousedown', function(e) {{
                isResizing = true;
                startX = e.clientX;
                
                // Get current widths
                const leftRect = leftColumn.getBoundingClientRect();
                const rightRect = rightColumn.getBoundingClientRect();
                startLeftWidth = leftRect.width;
                startRightWidth = rightRect.width;
                
                // Prevent text selection during drag
                document.body.style.userSelect = 'none';
                document.body.style.cursor = 'col-resize';
                e.preventDefault();
            }});
            
            document.addEventListener('mousemove', function(e) {{
                if (!isResizing) return;
                
                const deltaX = e.clientX - startX;
                const totalWidth = startLeftWidth + startRightWidth;
                const newLeftWidth = Math.max(200, Math.min(totalWidth - 200, startLeftWidth + deltaX));
                const newRightWidth = totalWidth - newLeftWidth;
                
                // Calculate fractions based on new widths
                const leftFr = newLeftWidth / totalWidth * 5;  // Scale to ~5 total units
                const rightFr = newRightWidth / totalWidth * 5;
                
                // Update grid template
                container.style.gridTemplateColumns = `${{leftFr}}fr 5px ${{rightFr}}fr`;
            }});
            
            document.addEventListener('mouseup', function() {{
                if (isResizing) {{
                    isResizing = false;
                    document.body.style.userSelect = '';
                    document.body.style.cursor = '';
                }}
            }});
        }})();
        
        // Azure AD Audit Log Pagination
        let currentAuditPage = 1;
        const auditPerPage = 3;
        
        function changeAuditPage(direction) {{
            const rows = document.querySelectorAll('.audit-row');
            const totalPages = Math.ceil(rows.length / auditPerPage);
            
            currentAuditPage += direction;
            currentAuditPage = Math.max(1, Math.min(currentAuditPage, totalPages));
            
            rows.forEach(row => {{
                row.style.display = parseInt(row.dataset.page) === currentAuditPage ? '' : 'none';
            }});
            
            document.getElementById('auditCurrentPage').textContent = currentAuditPage;
            document.getElementById('auditPrevBtn').disabled = currentAuditPage === 1;
            document.getElementById('auditNextBtn').disabled = currentAuditPage === totalPages;
        }}
    </script>
        """


# CLI entry point for testing
if __name__ == "__main__":
    import sys
    import subprocess
    from pathlib import Path
    
    if len(sys.argv) < 2:
        print("Usage: python report_generator_compact.py <json_file>")
        sys.exit(1)
    
    json_file = Path(sys.argv[1])
    
    if not json_file.exists():
        print(f"❌ Error: File not found: {json_file}")
        sys.exit(1)
    
    print(f"📂 Using JSON file: {json_file}")
    print(f"⚙️ Running generate_report_from_json.py to transform data...")
    
    # Use generate_report_from_json.py to do the heavy lifting (data transformation + IP enrichment)
    # Then we'll just swap out the report generator
    
    # We need to import after the main script runs, so we'll call it directly
    # and capture the InvestigationResult object
    
    # For now, just run the existing script and tell user to use the standalone compact generator
    print("\n" + "="*60)
    print("COMPACT REPORT GENERATOR")
    print("="*60)
    print("\nTo generate a compact report from JSON:")
    print(f"\n1. First, ensure data is transformed:")
    print(f"   python generate_report_from_json.py {json_file}")
    print(f"\n2. Or modify generate_report_from_json.py line ~1030 to use:")
    print(f"   from report_generator_compact import CompactReportGenerator")
    print(f"   generator = CompactReportGenerator()")
    print("\n" + "="*60)
    
    # For now, let's just demonstrate by importing the transform logic
    print("\n💡 Quick demo: Importing and using the compact generator...")
    
    # Import the data transformation from generate_report_from_json
    exec(open('generate_report_from_json.py').read().replace('if __name__ == "__main__":', 'if False:'))
    
    # Now call main() which will use the modified generator
    print("\n✓ Compact report generator is ready to use!")
