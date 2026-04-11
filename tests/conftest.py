"""Shared test fixtures for security-investigator."""

import json
import os
import pytest


@pytest.fixture
def sample_config():
    """Minimal config.json structure for testing."""
    return {
        "tenant_id": "test-tenant-id",
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "workspace_id": "test-workspace-id",
        "resource_group": "test-rg",
        "subscription_id": "test-sub-id",
        "workspace_name": "test-workspace",
    }


@pytest.fixture
def sample_config_file(tmp_path, sample_config):
    """Write a config.json to a temp directory and return the path."""
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(sample_config))
    return str(config_path)


@pytest.fixture
def sample_sign_in_log_entry():
    """A single Azure AD sign-in log entry."""
    return {
        "TimeGenerated": "2026-04-10T12:00:00Z",
        "UserPrincipalName": "jsmith@contoso.com",
        "IPAddress": "203.0.113.50",
        "Location": "US",
        "ResultType": "0",
        "ResultDescription": "Success",
        "AppDisplayName": "Microsoft Office",
        "ClientAppUsed": "Browser",
        "DeviceDetail": json.dumps({"browser": "Chrome", "operatingSystem": "Windows 10"}),
        "ConditionalAccessStatus": "success",
        "RiskLevelDuringSignIn": "none",
        "RiskState": "none",
        "AuthenticationRequirement": "singleFactorAuthentication",
    }


@pytest.fixture
def sample_ip_enrichment():
    """Sample IP enrichment API response data."""
    return {
        "ip": "203.0.113.50",
        "city": "Anytown",
        "region": "California",
        "country": "US",
        "org": "AS12345 Example ISP",
        "loc": "34.0522,-118.2437",
        "timezone": "America/Los_Angeles",
    }


@pytest.fixture
def sample_investigation_json(tmp_path):
    """Create a minimal investigation JSON file for report generation tests."""
    data = {
        "subject": "jsmith@contoso.com",
        "investigation_start": "2026-04-10T12:00:00Z",
        "investigation_end": "2026-04-10T13:00:00Z",
        "summary": {
            "risk_level": "Medium",
            "total_sign_ins": 10,
            "failed_sign_ins": 2,
            "unique_ips": 3,
            "unique_locations": 2,
        },
        "sign_in_logs": [],
        "audit_logs": [],
        "ip_details": {},
        "alerts": [],
        "mailbox_rules": [],
        "recent_mfa_changes": [],
    }
    path = tmp_path / "investigation_test.json"
    path.write_text(json.dumps(data, indent=2))
    return str(path)
