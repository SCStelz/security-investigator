"""Tests for CompactReportGenerator."""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from report_generator import CompactReportGenerator
from investigator import (
    InvestigationResult,
    AnomalyFinding,
    IPIntelligence,
    UserProfile,
    MFAStatus,
    DeviceInfo,
    RiskDetection,
    RiskySignIn,
    DLPEvent,
    UserRiskProfile,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_ip_intel(**overrides) -> IPIntelligence:
    """Helper to build an IPIntelligence with sensible defaults."""
    defaults = dict(
        ip="10.0.0.1",
        city="Ithaca",
        region="New York",
        country="US",
        org="AS1234 Example ISP",
        asn="AS1234",
        timezone="America/New_York",
        risk_level="LOW",
        assessment="Low risk residential IP",
        abuse_confidence_score=0,
        is_whitelisted=False,
        total_reports=0,
        usage_type="ISP",
        isp="Example ISP",
        is_vpn=False,
        vpn_network="Unknown",
        ip_category="frequent",
        threat_detected=False,
        threat_description="",
        threat_confidence=0,
        threat_tlp_level="",
        threat_activity_groups="",
        first_seen="2026-04-01",
        last_seen="2026-04-10",
        signin_count=50,
        success_count=48,
        failure_count=2,
        anomaly_type="",
        hit_count=0,
        categories=["primary", "active"],
        last_auth_result_detail="MFA requirement satisfied by claim in the token",
    )
    defaults.update(overrides)
    return IPIntelligence(**defaults)


def _make_anomaly(**overrides) -> AnomalyFinding:
    defaults = dict(
        detected_date="2026-04-10T12:00:00Z",
        upn="jsmith@contoso.com",
        anomaly_type="InteractiveIP",
        value="203.0.113.50",
        severity="High",
        country="RU",
        city="Moscow",
        country_novelty=True,
        city_novelty=True,
        artifact_hits=3,
        first_seen="2026-04-10",
    )
    defaults.update(overrides)
    return AnomalyFinding(**defaults)


def _make_device(**overrides) -> DeviceInfo:
    defaults = dict(
        display_name="LAPTOP-ABC",
        operating_system="Windows 11",
        trust_type="AzureAd",
        is_compliant=True,
        approximate_last_sign_in="2026-04-09T10:00:00Z",
    )
    defaults.update(overrides)
    return DeviceInfo(**defaults)


def _make_risk_detection(**overrides) -> RiskDetection:
    defaults = dict(
        risk_event_type="unfamiliarFeatures",
        risk_state="atRisk",
        risk_level="high",
        risk_detail="riskPolicyMatched",
        detected_date="2026-04-10T08:00:00Z",
        last_updated="2026-04-10T08:05:00Z",
        activity="signin",
        ip_address="203.0.113.50",
        location_city="Moscow",
        location_state="",
        location_country="RU",
    )
    defaults.update(overrides)
    return RiskDetection(**defaults)


def _make_risky_signin(**overrides) -> RiskySignIn:
    defaults = dict(
        sign_in_id="abc123",
        created_date="2026-04-10T08:00:00Z",
        upn="jsmith@contoso.com",
        app_display_name="Microsoft Teams",
        ip_address="203.0.113.50",
        location_city="Moscow",
        location_state="",
        location_country="RU",
        risk_state="atRisk",
        risk_level="high",
        risk_event_types=["unfamiliarFeatures"],
        risk_detail="riskPolicyMatched",
        status_error_code=0,
        status_failure_reason="",
    )
    defaults.update(overrides)
    return RiskySignIn(**defaults)


def _make_dlp_event(**overrides) -> DLPEvent:
    defaults = dict(
        time_generated="2026-04-10T14:00:00Z",
        user_id="jsmith@contoso.com",
        device_name="LAPTOP-ABC",
        client_ip="10.0.0.5",
        rule_name="Block PII uploads",
        file_name="C:\\Users\\jsmith\\Documents\\salary_report.xlsx",
        operation="FileUploaded",
        target_domain="dropbox.com",
        target_file_path="/uploads/salary_report.xlsx",
        severity="High",
    )
    defaults.update(overrides)
    return DLPEvent(**defaults)


def _make_user_risk_profile(**overrides) -> UserRiskProfile:
    defaults = dict(
        risk_level="high",
        risk_state="atRisk",
        risk_detail="riskPolicyMatched",
        risk_last_updated="2026-04-10T08:00:00Z",
        is_deleted=False,
        is_processing=False,
    )
    defaults.update(overrides)
    return UserRiskProfile(**defaults)


def _make_result(**overrides) -> InvestigationResult:
    """Build a minimal InvestigationResult with dynamic attributes the report expects."""
    defaults = dict(
        upn="jsmith@contoso.com",
        user_id="user-object-id-123",
        investigation_date="2026-04-10",
        start_date="2026-04-03",
        end_date="2026-04-10",
        anomalies=[],
        ip_intelligence=[],
        user_profile=UserProfile(
            display_name="John Smith",
            upn="jsmith@contoso.com",
            job_title="Engineer",
            department="IT",
            office_location="Ithaca, NY",
            account_enabled=True,
            user_type="Member",
        ),
        mfa_status=MFAStatus(
            mfa_enabled=True,
            methods_count=2,
            methods=["microsoftAuthenticatorAuthenticationMethod", "passwordAuthenticationMethod"],
            has_fido2=False,
            has_authenticator=True,
        ),
        devices=[],
        user_risk_profile=None,
        risk_detections=[],
        risky_signins=[],
        signin_events={},
        audit_events=[],
        office_events=[],
        security_alerts=[],
        dlp_events=[],
        risk_level="LOW",
        risk_factors=[],
        mitigating_factors=["MFA enabled"],
        critical_actions=[],
        high_priority_actions=[],
        monitoring_actions=["Continue normal monitoring"],
        kql_queries={},
        result_counts={},
    )
    defaults.update(overrides)
    result = InvestigationResult(**defaults)

    # The report generator accesses these dynamic attributes
    if not hasattr(result, "risk_assessment"):
        result.risk_assessment = {
            "risk_level": result.risk_level,
            "risk_factors": result.risk_factors,
            "mitigating_factors": result.mitigating_factors,
        }
    if not hasattr(result, "recommendations"):
        result.recommendations = {
            "critical_actions": result.critical_actions,
            "high_priority_actions": result.high_priority_actions,
            "monitoring_actions": result.monitoring_actions,
        }
    if not hasattr(result, "security_incidents"):
        result.security_incidents = []

    return result


@pytest.fixture
def gen():
    """Return a fresh CompactReportGenerator."""
    return CompactReportGenerator()


@pytest.fixture
def base_result():
    """Minimal investigation result with defaults."""
    return _make_result()


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestCompactReportGeneratorInit:
    def test_init_creates_instance(self, gen):
        assert isinstance(gen, CompactReportGenerator)

    def test_instance_has_expected_public_methods(self, gen):
        assert callable(getattr(gen, "generate", None))


# ---------------------------------------------------------------------------
# _get_current_user / _get_machine_name
# ---------------------------------------------------------------------------


class TestGetCurrentUser:
    def test_returns_uppercase_string(self, gen):
        user = gen._get_current_user()
        assert user == user.upper()

    @patch("os.getlogin", side_effect=OSError)
    def test_fallback_to_environ(self, mock_login, gen, monkeypatch):
        monkeypatch.setenv("USERNAME", "testuser")
        user = gen._get_current_user()
        assert user == "TESTUSER"

    @patch("os.getlogin", side_effect=OSError)
    def test_fallback_to_unknown(self, mock_login, gen, monkeypatch):
        monkeypatch.delenv("USERNAME", raising=False)
        user = gen._get_current_user()
        assert user == "UNKNOWN"


class TestGetMachineName:
    def test_returns_uppercase_string(self, gen):
        name = gen._get_machine_name()
        assert name == name.upper()

    @patch("socket.gethostname", side_effect=OSError)
    def test_fallback_to_unknown(self, mock_hostname, gen):
        assert gen._get_machine_name() == "UNKNOWN"


# ---------------------------------------------------------------------------
# _get_ip_category_badges
# ---------------------------------------------------------------------------


class TestGetIpCategoryBadges:
    def test_empty_categories_returns_empty_string(self, gen):
        assert gen._get_ip_category_badges([]) == ""

    def test_none_categories_returns_empty_string(self, gen):
        assert gen._get_ip_category_badges(None) == ""

    def test_threat_badge_contains_threat_text(self, gen):
        html = gen._get_ip_category_badges(["threat"])
        assert "THREAT" in html
        assert "#dc3545" in html  # red background

    def test_risky_badge(self, gen):
        html = gen._get_ip_category_badges(["risky"])
        assert "RISKY" in html
        assert "#ff7f00" in html

    def test_anomaly_badge(self, gen):
        html = gen._get_ip_category_badges(["anomaly"])
        assert "ANOMALY" in html
        assert "#ffc107" in html

    def test_primary_badge(self, gen):
        html = gen._get_ip_category_badges(["primary"])
        assert "PRIMARY" in html
        assert "#007bff" in html

    def test_active_badge(self, gen):
        html = gen._get_ip_category_badges(["active"])
        assert "ACTIVE" in html
        assert "#17a2b8" in html

    def test_severity_ordering(self, gen):
        html = gen._get_ip_category_badges(["active", "threat", "anomaly"])
        threat_pos = html.index("THREAT")
        anomaly_pos = html.index("ANOMALY")
        active_pos = html.index("ACTIVE")
        assert threat_pos < anomaly_pos < active_pos

    def test_small_size_uses_10px_font(self, gen):
        html = gen._get_ip_category_badges(["threat"], size="small")
        assert "font-size: 10px" in html

    def test_normal_size_uses_11px_font(self, gen):
        html = gen._get_ip_category_badges(["threat"], size="normal")
        assert "font-size: 11px" in html

    def test_unknown_category_ignored(self, gen):
        html = gen._get_ip_category_badges(["unknown_category"])
        assert html == ""

    def test_multiple_badges_concatenated(self, gen):
        html = gen._get_ip_category_badges(["threat", "risky"])
        assert "THREAT" in html
        assert "RISKY" in html


# ---------------------------------------------------------------------------
# _get_mfa_badge
# ---------------------------------------------------------------------------


class TestGetMfaBadge:
    def test_empty_string_returns_empty(self, gen):
        assert gen._get_mfa_badge("") == ""

    def test_none_returns_empty(self, gen):
        assert gen._get_mfa_badge(None) == ""

    def test_mfa_satisfied(self, gen):
        badge = gen._get_mfa_badge("MFA requirement satisfied by claim")
        assert "MFA" in badge
        assert "#7cbb00" in badge  # green

    def test_passkey(self, gen):
        badge = gen._get_mfa_badge("Passkey used for sign-in")
        assert "MFA" in badge

    def test_mfa_required_failure(self, gen):
        badge = gen._get_mfa_badge("MFA required but not completed")
        assert "Failed" in badge
        assert "#f65314" in badge  # red

    def test_authentication_failed(self, gen):
        badge = gen._get_mfa_badge("Authentication failed during MFA")
        assert "Failed" in badge

    def test_token_auth(self, gen):
        badge = gen._get_mfa_badge("Token")
        assert "Token" in badge
        assert "#00b7c3" in badge

    def test_correct_password(self, gen):
        badge = gen._get_mfa_badge("Correct password provided")
        assert "Interactive" in badge
        assert "#00a1f1" in badge

    def test_first_factor_satisfied(self, gen):
        badge = gen._get_mfa_badge("First factor requirement satisfied by token")
        assert "PWD" in badge
        assert "#737373" in badge

    def test_unrecognized_string_returns_empty(self, gen):
        assert gen._get_mfa_badge("some random text") == ""


# ---------------------------------------------------------------------------
# _build_key_metrics
# ---------------------------------------------------------------------------


class TestBuildKeyMetrics:
    def test_zero_values(self, gen, base_result):
        html = gen._build_key_metrics(base_result)
        assert "Key Metrics" in html
        assert "Anomalies" in html
        assert "Sign-ins" in html
        assert "DLP Events" in html
        assert "Failures" in html

    def test_anomaly_count_shown(self, gen):
        result = _make_result(anomalies=[_make_anomaly(), _make_anomaly()])
        html = gen._build_key_metrics(result)
        assert ">2<" in html

    def test_large_signins_formatted_as_k(self, gen):
        result = _make_result(signin_events={"total_signins": 13500, "total_failures": 5})
        html = gen._build_key_metrics(result)
        assert "13.5K" in html

    def test_small_signins_not_formatted(self, gen):
        result = _make_result(signin_events={"total_signins": 999, "total_failures": 0})
        html = gen._build_key_metrics(result)
        assert "999" in html

    def test_dlp_count_reflects_events(self, gen):
        result = _make_result(dlp_events=[_make_dlp_event()])
        html = gen._build_key_metrics(result)
        assert ">1<" in html


# ---------------------------------------------------------------------------
# _build_mfa_status
# ---------------------------------------------------------------------------


class TestBuildMfaStatus:
    def test_no_mfa_shows_critical(self, gen):
        result = _make_result(mfa_status=None)
        html = gen._build_mfa_status(result)
        assert "No MFA Configured" in html
        assert "badge-critical" in html

    def test_mfa_disabled_shows_critical(self, gen):
        result = _make_result(
            mfa_status=MFAStatus(mfa_enabled=False, methods_count=0, methods=[], has_fido2=False, has_authenticator=False)
        )
        html = gen._build_mfa_status(result)
        assert "No MFA Configured" in html

    def test_mfa_enabled_shows_method_names(self, gen, base_result):
        html = gen._build_mfa_status(base_result)
        assert "Authenticator" in html
        assert "Password" in html
        assert "badge-low" in html

    def test_guest_with_password_only_shows_home_tenant(self, gen):
        result = _make_result(
            user_profile=UserProfile(
                display_name="Guest User",
                upn="guest@external.com",
                job_title="Contractor",
                department="External",
                office_location="Remote",
                account_enabled=True,
                user_type="Guest",
            ),
            mfa_status=MFAStatus(
                mfa_enabled=True,
                methods_count=1,
                methods=["passwordAuthenticationMethod"],
                has_fido2=False,
                has_authenticator=False,
            ),
        )
        html = gen._build_mfa_status(result)
        assert "Home Tenant" in html

    def test_method_name_mapping(self, gen):
        result = _make_result(
            mfa_status=MFAStatus(
                mfa_enabled=True,
                methods_count=3,
                methods=["fido2AuthenticationMethod", "phoneAuthenticationMethod", "emailAuthenticationMethod"],
                has_fido2=True,
                has_authenticator=False,
            ),
        )
        html = gen._build_mfa_status(result)
        assert "Windows Hello" in html
        assert "Phone" in html
        assert "Email" in html


# ---------------------------------------------------------------------------
# _build_risk_assessment
# ---------------------------------------------------------------------------


class TestBuildRiskAssessment:
    def test_low_risk(self, gen, base_result):
        html = gen._build_risk_assessment(base_result)
        assert "Risk Assessment" in html
        assert "LOW" in html
        assert "badge-low" in html

    def test_critical_risk_badge(self, gen):
        result = _make_result(risk_level="CRITICAL", risk_factors=["Compromised credentials"])
        result.risk_assessment = {"risk_level": "CRITICAL", "risk_factors": ["Compromised credentials"], "mitigating_factors": []}
        html = gen._build_risk_assessment(result)
        assert "badge-critical" in html
        assert "CRITICAL" in html
        assert "Compromised credentials" in html

    def test_risk_factors_listed(self, gen):
        factors = ["New country", "VPN detected", "Impossible travel"]
        result = _make_result(risk_factors=factors)
        result.risk_assessment = {"risk_level": "HIGH", "risk_factors": factors, "mitigating_factors": []}
        html = gen._build_risk_assessment(result)
        assert "Risk Factors (3)" in html
        for f in factors:
            assert f in html

    def test_mitigating_factors_listed(self, gen):
        mitigating = ["MFA enabled", "Corporate IP"]
        result = _make_result(mitigating_factors=mitigating)
        result.risk_assessment = {"risk_level": "LOW", "risk_factors": [], "mitigating_factors": mitigating}
        html = gen._build_risk_assessment(result)
        assert "Mitigating Factors (2)" in html

    def test_unknown_risk_level_uses_info_badge(self, gen):
        result = _make_result(risk_level="BANANA")
        result.risk_assessment = {"risk_level": "BANANA", "risk_factors": [], "mitigating_factors": []}
        html = gen._build_risk_assessment(result)
        assert "badge-info" in html

    def test_all_badge_classes_mapped(self, gen):
        for level, badge in [
            ("CRITICAL", "badge-critical"),
            ("HIGH", "badge-high"),
            ("MEDIUM", "badge-medium"),
            ("LOW", "badge-low"),
            ("INFO", "badge-info"),
        ]:
            result = _make_result(risk_level=level)
            result.risk_assessment = {"risk_level": level, "risk_factors": [], "mitigating_factors": []}
            html = gen._build_risk_assessment(result)
            assert badge in html


# ---------------------------------------------------------------------------
# _build_critical_actions
# ---------------------------------------------------------------------------


class TestBuildCriticalActions:
    def test_no_actions_shows_info(self, gen, base_result):
        html = gen._build_critical_actions(base_result)
        assert "No critical actions required" in html

    def test_critical_actions_displayed(self, gen):
        result = _make_result(critical_actions=["Revoke sessions", "Reset password"])
        result.recommendations = {"critical_actions": ["Revoke sessions", "Reset password"], "high_priority_actions": []}
        html = gen._build_critical_actions(result)
        assert "CRITICAL" in html
        assert "Revoke sessions" in html
        assert "Reset password" in html

    def test_max_three_critical_shown(self, gen):
        actions = [f"Action {i}" for i in range(5)]
        result = _make_result(critical_actions=actions)
        result.recommendations = {"critical_actions": actions, "high_priority_actions": []}
        html = gen._build_critical_actions(result)
        assert "Action 0" in html
        assert "Action 2" in html
        assert "Action 3" not in html  # 4th should not appear

    def test_high_priority_actions_displayed(self, gen):
        result = _make_result(high_priority_actions=["Review logs"])
        result.recommendations = {"critical_actions": [], "high_priority_actions": ["Review logs"]}
        html = gen._build_critical_actions(result)
        assert "HIGH" in html
        assert "Review logs" in html


# ---------------------------------------------------------------------------
# _build_devices_section
# ---------------------------------------------------------------------------


class TestBuildDevicesSection:
    def test_no_devices(self, gen, base_result):
        html = gen._build_devices_section(base_result)
        assert "No registered devices found" in html

    def test_devices_listed(self, gen):
        result = _make_result(devices=[_make_device(display_name="LAPTOP-001", is_compliant=True)])
        html = gen._build_devices_section(result)
        assert "LAPTOP-001" in html
        assert "Windows 11" in html
        assert "Yes" in html  # compliant

    def test_non_compliant_device(self, gen):
        result = _make_result(devices=[_make_device(is_compliant=False)])
        html = gen._build_devices_section(result)
        assert "No" in html
        assert "#f65314" in html  # red color

    def test_stale_device_flagged(self, gen):
        result = _make_result(
            devices=[_make_device(approximate_last_sign_in="2025-01-01T00:00:00Z")]
        )
        html = gen._build_devices_section(result)
        assert "STALE" in html

    def test_max_five_devices(self, gen):
        devices = [_make_device(display_name=f"DEV-{i}") for i in range(8)]
        result = _make_result(devices=devices)
        html = gen._build_devices_section(result)
        assert "DEV-4" in html
        assert "DEV-5" not in html

    def test_defender_link_present_when_user_id(self, gen):
        result = _make_result(user_id="abc-123", devices=[_make_device()])
        html = gen._build_devices_section(result)
        assert "security.microsoft.com" in html

    def test_no_defender_link_without_user_id(self, gen):
        result = _make_result(user_id=None, devices=[_make_device()])
        html = gen._build_devices_section(result)
        # The Defender link should not be present
        assert "security.microsoft.com/user?aad=&tab" not in html


# ---------------------------------------------------------------------------
# _build_top_locations
# ---------------------------------------------------------------------------


class TestBuildTopLocations:
    def test_no_locations(self, gen, base_result):
        html = gen._build_top_locations(base_result)
        assert "No location data available" in html

    def test_locations_rendered(self, gen):
        result = _make_result(
            signin_events={
                "locations": [
                    {"Location": "Ithaca, US", "SignInCount": 100, "SuccessCount": 95, "FailureCount": 5},
                    {"Location": "Moscow, RU", "SignInCount": 3, "SuccessCount": 0, "FailureCount": 3},
                ]
            }
        )
        html = gen._build_top_locations(result)
        assert "US" in html
        assert "RU" in html
        assert "100" in html

    def test_pagination_controls_for_many_locations(self, gen):
        locs = [{"Location": f"City{i}, C{i}", "SignInCount": 10 - i, "SuccessCount": 10 - i, "FailureCount": 0} for i in range(6)]
        result = _make_result(signin_events={"locations": locs})
        html = gen._build_top_locations(result)
        assert "pagination-controls" in html
        assert "Page" in html


# ---------------------------------------------------------------------------
# _build_top_applications
# ---------------------------------------------------------------------------


class TestBuildTopApplications:
    def test_no_applications(self, gen, base_result):
        html = gen._build_top_applications(base_result)
        assert "No application data available" in html

    def test_applications_rendered(self, gen):
        result = _make_result(
            signin_events={
                "applications": [
                    {"AppDisplayName": "Microsoft Teams", "SignInCount": 200, "SuccessCount": 198, "FailureCount": 2}
                ]
            }
        )
        html = gen._build_top_applications(result)
        assert "Microsoft Teams" in html
        assert "200" in html


# ---------------------------------------------------------------------------
# _build_ip_intelligence
# ---------------------------------------------------------------------------


class TestBuildIpIntelligence:
    def test_no_ip_data(self, gen, base_result):
        # Need to set kql_queries for the method
        gen.kql_queries = {}
        gen.result_counts = {}
        html = gen._build_ip_intelligence(base_result)
        assert "No IP intelligence data available" in html

    def test_ip_cards_rendered(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        ip = _make_ip_intel(ip="10.0.0.1", risk_level="HIGH", categories=["anomaly"])
        result = _make_result(ip_intelligence=[ip])
        html = gen._build_ip_intelligence(result)
        assert "10.0.0.1" in html
        assert "IP Intelligence" in html

    def test_sorting_by_category_priority(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        threat_ip = _make_ip_intel(ip="1.1.1.1", risk_level="CRITICAL", categories=["threat"])
        normal_ip = _make_ip_intel(ip="2.2.2.2", risk_level="LOW", categories=["active"])
        result = _make_result(ip_intelligence=[normal_ip, threat_ip])
        html = gen._build_ip_intelligence(result)
        # Threat IP should appear before normal IP
        assert html.index("1.1.1.1") < html.index("2.2.2.2")

    def test_pagination_with_many_ips(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        ips = [_make_ip_intel(ip=f"10.0.0.{i}", categories=["active"]) for i in range(6)]
        result = _make_result(ip_intelligence=ips)
        html = gen._build_ip_intelligence(result)
        assert "pagination-controls" in html


# ---------------------------------------------------------------------------
# _build_ip_card
# ---------------------------------------------------------------------------


class TestBuildIpCard:
    def test_basic_card_structure(self, gen):
        ip = _make_ip_intel()
        html = gen._build_ip_card(ip, page=1, style="")
        assert "ip-card" in html
        assert ip.ip in html
        assert "Location:" in html

    def test_critical_risk_class(self, gen):
        ip = _make_ip_intel(risk_level="CRITICAL")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "critical-risk" in html

    def test_threat_description_shown(self, gen):
        ip = _make_ip_intel(threat_description="Known C2 server", org="Shady Hosting")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "Known C2 server" in html

    def test_azure_cloud_detected(self, gen):
        ip = _make_ip_intel(org="Microsoft Azure Cloud")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "Azure Cloud" in html

    def test_aws_cloud_detected(self, gen):
        ip = _make_ip_intel(org="Amazon AWS Hosting")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "AWS Cloud" in html

    def test_residential_isp_detected(self, gen):
        ip = _make_ip_intel(org="Comcast Cable Communications")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "Residential ISP" in html

    def test_vpn_indicator_shown_for_non_cloud(self, gen):
        ip = _make_ip_intel(org="Some VPN Service", is_vpn=True)
        html = gen._build_ip_card(ip, page=1, style="")
        assert "VPN" in html

    def test_vpn_indicator_hidden_for_cloud(self, gen):
        ip = _make_ip_intel(org="Microsoft Azure", is_vpn=True)
        html = gen._build_ip_card(ip, page=1, style="")
        # VPN badge should not appear for major cloud infrastructure
        # The VPN indicator span with ffc107 color should not be present
        assert "🔒 VPN</span>" not in html

    def test_abuseipdb_high_risk(self, gen):
        ip = _make_ip_intel(abuse_confidence_score=80, total_reports=50)
        html = gen._build_ip_card(ip, page=1, style="")
        assert "AbuseIPDB" in html
        assert "High Risk" in html

    def test_abuseipdb_medium_risk(self, gen):
        ip = _make_ip_intel(abuse_confidence_score=30, total_reports=5)
        html = gen._build_ip_card(ip, page=1, style="")
        assert "Medium Risk" in html

    def test_abuseipdb_low_risk(self, gen):
        ip = _make_ip_intel(abuse_confidence_score=10, total_reports=2)
        html = gen._build_ip_card(ip, page=1, style="")
        assert "Low Risk" in html

    def test_location_display_with_city_and_country(self, gen):
        ip = _make_ip_intel(city="Berlin", country="DE")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "Berlin, DE" in html

    def test_location_display_country_only(self, gen):
        ip = _make_ip_intel(city="", country="DE")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "DE" in html

    def test_date_row_with_both_dates(self, gen):
        ip = _make_ip_intel(first_seen="2026-04-01", last_seen="2026-04-10")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "2026-04-01" in html
        assert "2026-04-10" in html

    def test_date_row_first_seen_only(self, gen):
        ip = _make_ip_intel(first_seen="2026-04-01", last_seen="")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "2026-04-01" in html

    def test_no_dates(self, gen):
        ip = _make_ip_intel(first_seen="", last_seen="")
        html = gen._build_ip_card(ip, page=1, style="")
        # Should still render without error
        assert "ip-card" in html

    def test_mfa_badge_in_card(self, gen):
        ip = _make_ip_intel(last_auth_result_detail="MFA requirement satisfied by claim in the token")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "MFA" in html

    def test_kql_copy_button_present(self, gen):
        ip = _make_ip_intel(ip="192.168.1.1")
        html = gen._build_ip_card(ip, page=1, style="")
        assert "copyKQL" in html
        assert "ip_192_168_1_1" in html

    def test_risk_badge_classes(self, gen):
        for level, expected_badge in [
            ("CRITICAL", "badge-critical"),
            ("HIGH", "badge-high"),
            ("MEDIUM", "badge-medium"),
            ("LOW", "badge-low"),
            ("INFO", "badge-info"),
        ]:
            ip = _make_ip_intel(risk_level=level)
            html = gen._build_ip_card(ip, page=1, style="")
            assert expected_badge in html


# ---------------------------------------------------------------------------
# _build_signin_failures
# ---------------------------------------------------------------------------


class TestBuildSigninFailures:
    def test_no_failures(self, gen, base_result):
        html = gen._build_signin_failures(base_result)
        assert "No sign-in failures detected" in html

    def test_failures_rendered(self, gen):
        result = _make_result(
            signin_events={
                "failures": [
                    {
                        "ResultType": "50126",
                        "ResultDescription": "Invalid username or password",
                        "FailureCount": 15,
                        "Applications": ["Teams", "Outlook"],
                        "Locations": ["US"],
                    }
                ]
            }
        )
        html = gen._build_signin_failures(result)
        assert "50126" in html
        assert "Invalid username or password" in html
        assert "15" in html
        assert "Teams" in html

    def test_legacy_field_names_supported(self, gen):
        result = _make_result(
            signin_events={
                "failures": [
                    {
                        "error_code": "53003",
                        "description": "Blocked by CA",
                        "count": 7,
                        "applications": ["Exchange"],
                        "locations": ["DE"],
                    }
                ]
            }
        )
        html = gen._build_signin_failures(result)
        assert "53003" in html
        assert "Blocked by CA" in html

    def test_long_description_truncated(self, gen):
        long_desc = "A" * 150
        result = _make_result(
            signin_events={
                "failures": [
                    {"ResultType": "1", "ResultDescription": long_desc, "FailureCount": 1, "Applications": [], "Locations": []}
                ]
            }
        )
        html = gen._build_signin_failures(result)
        assert "..." in html


# ---------------------------------------------------------------------------
# _build_office_activity
# ---------------------------------------------------------------------------


class TestBuildOfficeActivity:
    def test_no_activity(self, gen, base_result):
        html = gen._build_office_activity(base_result)
        assert "No Office 365 activity detected" in html

    def test_activity_cards_rendered(self, gen):
        result = _make_result(
            office_events=[
                {"Operation": "MailItemsAccessed", "ActivityCount": 500},
                {"Operation": "Send", "ActivityCount": 25},
            ]
        )
        html = gen._build_office_activity(result)
        assert "Emails Accessed" in html
        assert "500" in html
        assert "Emails Sent" in html

    def test_unknown_operation_uses_raw_name(self, gen):
        result = _make_result(office_events=[{"Operation": "CustomOp", "ActivityCount": 3}])
        html = gen._build_office_activity(result)
        assert "CustomOp" in html

    def test_max_five_activities(self, gen):
        events = [{"Operation": f"Op{i}", "ActivityCount": i} for i in range(8)]
        result = _make_result(office_events=events)
        html = gen._build_office_activity(result)
        assert "Op4" in html
        assert "Op5" not in html


# ---------------------------------------------------------------------------
# _build_dlp_events
# ---------------------------------------------------------------------------


class TestBuildDlpEvents:
    def test_no_dlp_events(self, gen, base_result):
        html = gen._build_dlp_events(base_result)
        assert "No DLP events detected" in html

    def test_dlp_events_rendered(self, gen):
        result = _make_result(dlp_events=[_make_dlp_event()])
        html = gen._build_dlp_events(result)
        assert "salary_report.xlsx" in html
        # target_file_path takes priority over target_domain in the template
        assert "/uploads/salary_report.xlsx" in html

    def test_dlp_events_target_domain_fallback(self, gen):
        result = _make_result(dlp_events=[_make_dlp_event(target_file_path="")])
        html = gen._build_dlp_events(result)
        assert "dropbox.com" in html

    def test_network_share_operation_badge(self, gen):
        result = _make_result(
            dlp_events=[_make_dlp_event(operation="CopyToNetworkShare")]
        )
        html = gen._build_dlp_events(result)
        assert "Network Share" in html
        assert "badge-critical" in html

    def test_cloud_upload_operation_badge(self, gen):
        result = _make_result(
            dlp_events=[_make_dlp_event(operation="CloudUpload")]
        )
        html = gen._build_dlp_events(result)
        assert "Cloud Upload" in html
        assert "badge-high" in html


# ---------------------------------------------------------------------------
# _build_security_incidents
# ---------------------------------------------------------------------------


class TestBuildSecurityIncidents:
    def test_no_incidents(self, gen, base_result):
        gen.kql_queries = {}
        gen.result_counts = {}
        html = gen._build_security_incidents(base_result)
        assert "No security incidents detected" in html

    def test_incidents_rendered(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        result = _make_result()
        result.security_incidents = [
            {
                "Title": "Suspicious sign-in from Tor",
                "Severity": "High",
                "Status": "Active",
                "CreatedTime": "2026-04-10T08:00:00Z",
                "OwnerUPN": "admin@contoso.com",
                "ProviderIncidentUrl": "https://security.microsoft.com/incident/123",
                "ProviderIncidentId": "INC-123",
                "AlertCount": 3,
            }
        ]
        html = gen._build_security_incidents(result)
        assert "Suspicious sign-in from Tor" in html
        assert "badge-critical" in html  # High severity
        assert "INC-123" in html
        assert "admin@contoso.com" in html

    def test_long_title_truncated(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        result = _make_result()
        result.security_incidents = [
            {
                "Title": "A" * 80,
                "Severity": "Medium",
                "Status": "New",
                "CreatedTime": "2026-04-10T08:00:00Z",
                "OwnerUPN": "Unassigned",
                "ProviderIncidentUrl": "",
                "ProviderIncidentId": "INC-999",
                "AlertCount": 1,
            }
        ]
        html = gen._build_security_incidents(result)
        assert "..." in html

    def test_severity_badge_mapping(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        for severity, expected_badge in [
            ("High", "badge-critical"),
            ("Medium", "badge-medium"),
            ("Low", "badge-low"),
            ("Informational", "badge-info"),
        ]:
            result = _make_result()
            result.security_incidents = [
                {
                    "Title": "Test",
                    "Severity": severity,
                    "Status": "Active",
                    "CreatedTime": "2026-04-10T08:00:00Z",
                    "OwnerUPN": "",
                    "ProviderIncidentUrl": "",
                    "ProviderIncidentId": "X",
                    "AlertCount": 1,
                }
            ]
            html = gen._build_security_incidents(result)
            assert expected_badge in html


# ---------------------------------------------------------------------------
# _build_audit_activity
# ---------------------------------------------------------------------------


class TestBuildAuditActivity:
    def test_no_audit_events(self, gen, base_result):
        gen.kql_queries = {}
        gen.result_counts = {}
        html = gen._build_audit_activity(base_result)
        assert "No audit log activity detected" in html

    def test_aggregated_events(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        result = _make_result(
            audit_events=[
                {
                    "Category": "UserManagement",
                    "Count": 15,
                    "Result": "success",
                    "Operations": ["Add user", "Update user"],
                }
            ]
        )
        html = gen._build_audit_activity(result)
        assert "UserManagement" in html
        assert "15" in html
        assert "Add user" in html

    def test_sensitive_operations_highlighted(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        result = _make_result(
            audit_events=[
                {
                    "Category": "RoleManagement",
                    "Count": 1,
                    "Result": "success",
                    "Operations": ["Reset password"],
                }
            ]
        )
        html = gen._build_audit_activity(result)
        assert "🔐" in html
        assert "#f65314" in html  # sensitive highlight color

    def test_raw_events_rendered(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        result = _make_result(
            audit_events=[
                {"TimeGenerated": "2026-04-10T12:00:00Z", "OperationName": "Add member to group", "Result": "success"}
            ]
        )
        html = gen._build_audit_activity(result)
        assert "2026-04-10T12:00" in html
        assert "Add member to group" in html


# ---------------------------------------------------------------------------
# _build_identity_protection
# ---------------------------------------------------------------------------


class TestBuildIdentityProtection:
    def test_no_risk_data(self, gen, base_result):
        html = gen._build_identity_protection(base_result)
        assert "No risk detected" in html

    def test_with_risk_profile(self, gen):
        result = _make_result(
            user_risk_profile=_make_user_risk_profile(),
            risk_detections=[_make_risk_detection()],
        )
        html = gen._build_identity_protection(result)
        assert "HIGH" in html
        assert "Active Risk" in html

    def test_risk_level_badge_mapping(self, gen):
        for level, badge in [("none", "badge-info"), ("low", "badge-low"), ("medium", "badge-medium"), ("high", "badge-critical")]:
            profile = _make_user_risk_profile(risk_level=level, risk_state="none")
            result = _make_result(user_risk_profile=profile)
            html = gen._build_identity_protection(result)
            assert badge in html

    def test_active_risk_warning(self, gen):
        result = _make_result(
            user_risk_profile=_make_user_risk_profile(),
            risk_detections=[_make_risk_detection(risk_state="atRisk")],
        )
        html = gen._build_identity_protection(result)
        assert "Active Risk Detection" in html

    def test_risk_detections_dropdown(self, gen):
        result = _make_result(
            user_risk_profile=_make_user_risk_profile(),
            risk_detections=[
                _make_risk_detection(risk_event_type="unfamiliarFeatures"),
                _make_risk_detection(risk_event_type="anonymizedIPAddress", risk_state="remediated"),
            ],
        )
        html = gen._build_identity_protection(result)
        assert "Recent Risk Detections" in html
        assert "unfamiliarFeatures" in html
        assert "anonymizedIPAddress" in html

    def test_no_profile_but_active_detections(self, gen):
        result = _make_result(
            user_risk_profile=None,
            risk_detections=[_make_risk_detection(risk_state="atRisk")],
        )
        html = gen._build_identity_protection(result)
        assert "Active Risk Detection" in html

    def test_no_profile_resolved_detections(self, gen):
        result = _make_result(
            user_risk_profile=None,
            risk_detections=[_make_risk_detection(risk_state="remediated")],
        )
        html = gen._build_identity_protection(result)
        assert "Risks resolved" in html


# ---------------------------------------------------------------------------
# _build_header
# ---------------------------------------------------------------------------


class TestBuildHeader:
    def test_header_contains_user_info(self, gen, base_result):
        html = gen._build_header(base_result)
        assert "John Smith" in html
        assert "jsmith@contoso.com" in html
        assert "Engineer" in html
        assert "IT" in html

    def test_header_without_user_profile(self, gen):
        result = _make_result(user_profile=None)
        html = gen._build_header(result)
        assert "jsmith" in html  # derived from UPN
        assert "Unknown" in html

    def test_disabled_account_shows_disabled(self, gen):
        result = _make_result(
            user_profile=UserProfile(
                display_name="Disabled User",
                upn="disabled@contoso.com",
                job_title="N/A",
                department="N/A",
                office_location="N/A",
                account_enabled=False,
                user_type="Member",
            )
        )
        html = gen._build_header(result)
        assert "Disabled" in html
        assert "#f65314" in html

    def test_defender_link_present_with_user_id(self, gen, base_result):
        html = gen._build_header(base_result)
        assert "security.microsoft.com" in html

    def test_no_defender_link_without_user_id(self, gen):
        result = _make_result(user_id=None)
        html = gen._build_header(result)
        # Should not have defender link
        assert 'aad=' not in html or 'aad=""' not in html

    def test_location_badges_from_signin_events(self, gen):
        result = _make_result(
            signin_events={
                "locations": [
                    {"Location": "Ithaca, US", "SignInCount": 100, "FailureCount": 0},
                    {"Location": "Moscow, RU", "SignInCount": 5, "FailureCount": 4},
                ]
            }
        )
        html = gen._build_header(result)
        assert "Ithaca, US" in html

    def test_investigation_dates_shown(self, gen, base_result):
        html = gen._build_header(base_result)
        assert "2026-04-03" in html
        assert "2026-04-10" in html


# ---------------------------------------------------------------------------
# _build_recommendations
# ---------------------------------------------------------------------------


class TestBuildRecommendations:
    def test_empty_recommendations(self, gen):
        result = _make_result()
        result.recommendations = {}
        html = gen._build_recommendations(result)
        assert "Recommendations" in html
        assert "No critical actions required" in html
        assert "Continue normal monitoring" in html

    def test_all_sections_populated(self, gen):
        result = _make_result()
        result.recommendations = {
            "critical_actions": ["Revoke sessions"],
            "high_priority_actions": ["Review audit logs"],
            "monitoring_actions": ["Watch for 14 days"],
        }
        html = gen._build_recommendations(result)
        assert "Revoke sessions" in html
        assert "Review audit logs" in html
        assert "Watch for 14 days" in html

    def test_html_tags_stripped_from_actions(self, gen):
        result = _make_result()
        result.recommendations = {
            "critical_actions": ["<strong>Reset password</strong><br>Immediately"],
            "high_priority_actions": [],
            "monitoring_actions": [],
        }
        html = gen._build_recommendations(result)
        # The <strong> tags should be removed
        assert "<strong>" not in html.split("Recommendations")[1].split("</div>")[0]


# ---------------------------------------------------------------------------
# _build_timeline_items
# ---------------------------------------------------------------------------


class TestBuildTimelineItems:
    def test_empty_timeline(self, gen):
        result = _make_result()
        html = gen._build_timeline_items(result)
        assert "No timeline events available" in html

    def test_anomalies_in_timeline(self, gen):
        result = _make_result(anomalies=[_make_anomaly()])
        html = gen._build_timeline_items(result)
        assert "Sign-in Anomaly" in html
        assert "InteractiveIP" in html
        assert "Moscow" in html

    def test_risk_detections_in_timeline(self, gen):
        result = _make_result(risk_detections=[_make_risk_detection()])
        html = gen._build_timeline_items(result)
        assert "Identity Protection" in html
        assert "unfamiliarFeatures" in html

    def test_risky_signins_in_timeline(self, gen):
        result = _make_result(risky_signins=[_make_risky_signin()])
        html = gen._build_timeline_items(result)
        assert "Risky Sign-in" in html
        assert "Microsoft Teams" in html

    def test_dlp_events_in_timeline(self, gen):
        result = _make_result(dlp_events=[_make_dlp_event()])
        html = gen._build_timeline_items(result)
        assert "DLP Event" in html

    def test_security_incidents_in_timeline(self, gen):
        result = _make_result()
        result.security_incidents = [
            {
                "Title": "Suspicious Tor sign-in",
                "Severity": "High",
                "Status": "Active",
                "CreatedTime": "2026-04-10T08:00:00Z",
            }
        ]
        html = gen._build_timeline_items(result)
        assert "Security Incident" in html
        assert "Suspicious Tor sign-in" in html

    def test_dlp_events_consolidated(self, gen):
        """Multiple DLP events within 5 minutes should be grouped."""
        events = [
            _make_dlp_event(time_generated="2026-04-10T14:00:00Z", file_name="file1.xlsx"),
            _make_dlp_event(time_generated="2026-04-10T14:02:00Z", file_name="file2.xlsx"),
            _make_dlp_event(time_generated="2026-04-10T14:03:00Z", file_name="file3.xlsx"),
        ]
        result = _make_result(dlp_events=events)
        html = gen._build_timeline_items(result)
        assert "DLP Events (3 files)" in html

    def test_events_sorted_newest_first(self, gen):
        result = _make_result(
            anomalies=[
                _make_anomaly(detected_date="2026-04-08T12:00:00Z"),
                _make_anomaly(detected_date="2026-04-10T12:00:00Z"),
            ]
        )
        html = gen._build_timeline_items(result)
        # The newer event's date section should appear first
        first_date_pos = html.index("2026-04-10")
        second_date_pos = html.index("2026-04-08")
        assert first_date_pos < second_date_pos


# ---------------------------------------------------------------------------
# _get_styles / _get_javascript
# ---------------------------------------------------------------------------


class TestStylesAndJavascript:
    def test_styles_returns_css(self, gen):
        css = gen._get_styles()
        assert "<style>" in css
        assert "body" in css
        assert "badge-critical" in css

    def test_javascript_returns_script(self, gen):
        gen.kql_queries = {"anomalies": "let x = 1;"}
        js = gen._get_javascript()
        assert "<script>" in js


# ---------------------------------------------------------------------------
# _generate_html (integration-level)
# ---------------------------------------------------------------------------


class TestGenerateHtml:
    def test_full_html_generation(self, gen, base_result):
        html = gen._generate_html(base_result)
        assert "<!DOCTYPE html>" in html
        assert "CONFIDENTIAL" in html
        assert "John Smith" in html
        assert "jsmith@contoso.com" in html
        assert "</html>" in html

    def test_html_includes_all_sections(self, gen, base_result):
        html = gen._generate_html(base_result)
        assert "Key Metrics" in html
        assert "MFA Status" in html
        assert "Risk Assessment" in html
        assert "Critical Actions" in html
        assert "Identity Protection" in html
        assert "Registered Devices" in html
        assert "Recommendations" in html

    def test_kql_queries_set_for_ip_intelligence(self, gen):
        ip = _make_ip_intel(ip="192.168.1.1", city="Boston", country="US", org="TestOrg", risk_level="MEDIUM")
        result = _make_result(ip_intelligence=[ip])
        gen._generate_html(result)
        assert "ip_192_168_1_1" in gen.kql_queries
        assert "192.168.1.1" in gen.kql_queries["ip_192_168_1_1"]


# ---------------------------------------------------------------------------
# generate (file writing)
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_generate_creates_file(self, gen, base_result, tmp_path):
        output = str(tmp_path / "test_report.html")
        result_path = gen.generate(base_result, output_path=output)
        assert result_path == output
        assert os.path.exists(output)
        with open(output) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content

    def test_generate_default_path(self, gen, base_result, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result_path = gen.generate(base_result)
        assert "Investigation_Report_Compact_jsmith" in result_path
        assert os.path.exists(result_path)

    def test_generate_creates_directory(self, gen, base_result, tmp_path):
        output = str(tmp_path / "nested" / "dir" / "report.html")
        gen.generate(base_result, output_path=output)
        assert os.path.exists(output)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_none_signin_events(self, gen):
        result = _make_result(signin_events=None)
        # Should not raise
        html = gen._build_key_metrics(result)
        assert "Key Metrics" in html

    def test_none_anomalies(self, gen):
        result = _make_result(anomalies=None)
        html = gen._build_key_metrics(result)
        assert ">0<" in html  # anomaly count = 0

    def test_none_dlp_events(self, gen):
        result = _make_result(dlp_events=None)
        html = gen._build_dlp_events(result)
        assert "No DLP events detected" in html

    def test_none_ip_intelligence(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        result = _make_result(ip_intelligence=None)
        html = gen._build_ip_intelligence(result)
        assert "No IP intelligence data available" in html

    def test_none_devices(self, gen):
        result = _make_result(devices=None)
        html = gen._build_devices_section(result)
        assert "No registered devices found" in html

    def test_none_office_events(self, gen):
        result = _make_result(office_events=None)
        html = gen._build_office_activity(result)
        assert "No Office 365 activity detected" in html

    def test_none_audit_events(self, gen):
        gen.kql_queries = {}
        gen.result_counts = {}
        result = _make_result(audit_events=None)
        html = gen._build_audit_activity(result)
        assert "No audit log activity detected" in html

    def test_empty_upn_split(self, gen):
        """UPN without @ should not crash."""
        result = _make_result(upn="noemailformat")
        result.risk_assessment = {"risk_level": "LOW", "risk_factors": [], "mitigating_factors": []}
        # Header should still work
        html = gen._build_header(result)
        assert "noemailformat" in html

    def test_ip_intel_with_none_categories(self, gen):
        ip = _make_ip_intel(categories=None)
        html = gen._build_ip_card(ip, page=1, style="")
        assert "ip-card" in html

    def test_device_with_na_last_signin(self, gen):
        result = _make_result(devices=[_make_device(approximate_last_sign_in="N/A")])
        html = gen._build_devices_section(result)
        assert "N/A" in html

    def test_signin_failures_empty_applications(self, gen):
        result = _make_result(
            signin_events={
                "failures": [
                    {"ResultType": "123", "ResultDescription": "Error", "FailureCount": 1, "Applications": [], "Locations": []}
                ]
            }
        )
        html = gen._build_signin_failures(result)
        assert "123" in html

    def test_timeline_event_with_none_time(self, gen):
        """Events with None time should be skipped in timeline rendering."""
        result = _make_result()
        result.security_incidents = [
            {"Title": "NoTime", "Severity": "Low", "Status": "Closed", "CreatedTime": None}
        ]
        # Should not crash
        html = gen._build_timeline_items(result)
        assert isinstance(html, str)
