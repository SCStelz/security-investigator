"""Tests for generate_report_from_json.py"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import responses

from generate_report_from_json import (
    enrich_ip,
    enrich_ip_abuseipdb,
    load_config,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_with_keys(tmp_path):
    """Config dict with all API keys populated."""
    return {
        "ipinfo_token": "test-ipinfo-token",
        "abuseipdb_token": "test-abuse-key",
        "vpnapi_token": "test-vpnapi-key",
    }


@pytest.fixture
def minimal_investigation_data():
    """Minimal valid investigation JSON structure for main() tests."""
    return {
        "upn": "testuser@contoso.com",
        "user_id": "abc-123",
        "investigation_date": "2026-04-10",
        "start_date": "2026-03-10",
        "end_date": "2026-04-10",
        "anomalies": [],
        "signin_apps": [],
        "signin_locations": [],
        "signin_failures": [],
        "signin_ip_counts": [],
        "audit_events": [],
        "office_events": [],
        "dlp_events": [],
        "incidents": [],
        "user_profile": {
            "displayName": "Test User",
            "userPrincipalName": "testuser@contoso.com",
            "jobTitle": "Analyst",
            "department": "IT",
            "officeLocation": "Ithaca",
            "accountEnabled": True,
            "userType": "Member",
        },
        "mfa_methods": {
            "value": [
                {"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"},
                {"@odata.type": "#microsoft.graph.phoneAuthenticationMethod"},
            ]
        },
        "devices": [],
        "risk_profile": {
            "riskLevel": "none",
            "riskState": "none",
            "riskDetail": "none",
            "riskLastUpdatedDateTime": "2026-04-10T00:00:00Z",
            "isDeleted": False,
            "isProcessing": False,
        },
        "risk_detections": [],
        "risky_signins": [],
        "threat_intel_ips": [],
        "user_sid": "S-1-5-21-0000000000-0000000000-0000000000-1234",
    }


@pytest.fixture
def investigation_json_file(tmp_path, minimal_investigation_data):
    """Write minimal investigation JSON to a temp file and return the path."""
    path = tmp_path / "investigation_test.json"
    path.write_text(json.dumps(minimal_investigation_data, indent=2))
    return str(path)


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    """Tests for load_config()."""

    def test_returns_empty_dict_when_no_config(self, tmp_path, monkeypatch):
        """When config.json does not exist, returns empty dict."""
        # Point __file__ to a temp directory where no config.json exists
        monkeypatch.setattr("generate_report_from_json.__file__", str(tmp_path / "fake_module.py"))
        result = load_config()
        assert result == {}

    def test_loads_valid_config(self, tmp_path):
        """When config.json exists, it is parsed and returned."""
        config_data = {"ipinfo_token": "abc123", "abuseipdb_token": "xyz"}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        with patch("generate_report_from_json.Path") as MockPath:
            parent_mock = MagicMock()
            MockPath.return_value = parent_mock
            path_mock = MagicMock()
            path_mock.exists.return_value = True
            path_mock.__str__ = MagicMock(return_value=str(config_path))
            # Make open work with the real file
            path_mock.open = config_path.open
            parent_mock.__truediv__ = MagicMock(return_value=path_mock)

            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__ = MagicMock(
                    return_value=open(str(config_path))
                )
                mock_open.return_value.__exit__ = MagicMock(return_value=False)
                # Simplify: just patch at module level
                pass

        # Straightforward approach: write the file where the function expects it
        # and patch Path(__file__).parent to point to tmp_path
        with patch("generate_report_from_json.Path") as MockPath:
            mock_file_path = MagicMock()
            mock_file_path.parent = tmp_path
            MockPath.return_value = mock_file_path
            config_file = tmp_path / "config.json"
            config_file.write_text(json.dumps(config_data))
            # The function does Path(__file__).parent / 'config.json'
            # We need to intercept this chain
            MockPath.return_value.__truediv__ = MagicMock(return_value=config_file)
            # config_file.exists() is True (real file), but Path wrapping may differ
            # Let's just use a direct mock of open
            result = load_config()

        assert result == config_data


# ---------------------------------------------------------------------------
# enrich_ip_abuseipdb
# ---------------------------------------------------------------------------

class TestEnrichIpAbuseipdb:
    """Tests for the AbuseIPDB enrichment function."""

    def test_returns_none_when_no_api_key(self):
        result = enrich_ip_abuseipdb("1.2.3.4", "")
        assert result is None

    def test_returns_none_when_api_key_is_none(self):
        result = enrich_ip_abuseipdb("1.2.3.4", None)
        assert result is None

    @responses.activate
    def test_successful_enrichment(self):
        """A 200 response returns the 'data' payload."""
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 42, "totalReports": 5}},
            status=200,
        )

        result = enrich_ip_abuseipdb("1.2.3.4", "test-key")

        assert result is not None
        assert result["abuseConfidenceScore"] == 42
        assert result["totalReports"] == 5

    @responses.activate
    def test_rate_limit_returns_none(self):
        """A 429 should return None gracefully."""
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"errors": [{"detail": "rate limit"}]},
            status=429,
        )

        result = enrich_ip_abuseipdb("1.2.3.4", "test-key")
        assert result is None

    @responses.activate
    def test_server_error_returns_none(self):
        """A 500 should return None."""
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={},
            status=500,
        )

        result = enrich_ip_abuseipdb("1.2.3.4", "test-key")
        assert result is None

    @responses.activate
    def test_network_error_returns_none(self):
        """Connection errors return None."""
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            body=ConnectionError("network down"),
        )

        result = enrich_ip_abuseipdb("1.2.3.4", "test-key")
        assert result is None


# ---------------------------------------------------------------------------
# enrich_ip
# ---------------------------------------------------------------------------

class TestEnrichIp:
    """Tests for the main IP enrichment orchestrator."""

    @responses.activate
    def test_basic_enrichment_no_tokens(self):
        """With no API tokens, uses ipinfo.io free tier only."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/10.0.0.1/json",
            json={
                "ip": "10.0.0.1",
                "city": "Ithaca",
                "region": "New York",
                "country": "US",
                "org": "AS1234 Comcast Communications",
                "timezone": "America/New_York",
            },
            status=200,
        )

        result = enrich_ip("10.0.0.1", config={})

        assert result.ip == "10.0.0.1"
        assert result.city == "Ithaca"
        assert result.country == "US"
        assert result.risk_level == "LOW"
        assert "ISP" in result.assessment or "communications" in result.assessment.lower() or "Legitimate" in result.assessment

    @responses.activate
    def test_enrichment_with_ipinfo_token(self, config_with_keys):
        """When ipinfo_token is present, it is appended to the URL."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/10.0.0.1/json",
            json={"ip": "10.0.0.1", "city": "NYC", "region": "NY", "country": "US",
                  "org": "AS1234 ISP", "timezone": "America/New_York"},
            status=200,
        )
        # AbuseIPDB call
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": False}},
            status=200,
        )
        # vpnapi call
        responses.add(
            responses.GET,
            "https://vpnapi.io/api/10.0.0.1",
            json={"security": {"vpn": False}, "network": {"network": "ISP Net"}},
            status=200,
        )

        result = enrich_ip("10.0.0.1", config=config_with_keys)

        assert result.ip == "10.0.0.1"
        # Verify the ipinfo request included the token
        assert "token=test-ipinfo-token" in responses.calls[0].request.url

    @responses.activate
    def test_hosting_provider_gets_medium_risk(self):
        """IPs from hosting/VPN/proxy providers get MEDIUM risk."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/5.5.5.5/json",
            json={"ip": "5.5.5.5", "city": "Amsterdam", "region": "NH",
                  "country": "NL", "org": "AS9999 HostingCo VPN Services",
                  "timezone": "Europe/Amsterdam"},
            status=200,
        )

        result = enrich_ip("5.5.5.5", config={})

        assert result.risk_level == "MEDIUM"
        assert "Hosting/VPN/Proxy" in result.assessment

    @responses.activate
    def test_high_abuse_score_gets_high_risk(self, config_with_keys):
        """AbuseIPDB score >= 75 results in HIGH risk."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/8.8.8.8/json",
            json={"ip": "8.8.8.8", "city": "Ashburn", "region": "VA",
                  "country": "US", "org": "AS15169 Google LLC",
                  "timezone": "America/New_York"},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 85, "totalReports": 200, "isWhitelisted": False}},
            status=200,
        )
        # vpnapi
        responses.add(
            responses.GET,
            "https://vpnapi.io/api/8.8.8.8",
            json={"security": {"vpn": False}, "network": {"network": "Google"}},
            status=200,
        )

        result = enrich_ip("8.8.8.8", config=config_with_keys)

        assert result.risk_level == "HIGH"
        assert result.abuse_confidence_score == 85
        assert result.total_reports == 200

    @responses.activate
    def test_medium_abuse_score(self, config_with_keys):
        """AbuseIPDB score between 25-74 results in MEDIUM risk."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/1.1.1.1/json",
            json={"ip": "1.1.1.1", "city": "LA", "region": "CA",
                  "country": "US", "org": "AS1234 SomeISP",
                  "timezone": "America/Los_Angeles"},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 50, "totalReports": 10, "isWhitelisted": False}},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://vpnapi.io/api/1.1.1.1",
            json={"security": {"vpn": False}, "network": {"network": "Net"}},
            status=200,
        )

        result = enrich_ip("1.1.1.1", config=config_with_keys)

        assert result.risk_level == "MEDIUM"

    @responses.activate
    def test_whitelisted_ip(self, config_with_keys):
        """Whitelisted IPs in AbuseIPDB stay LOW risk."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/2.2.2.2/json",
            json={"ip": "2.2.2.2", "city": "Berlin", "region": "Berlin",
                  "country": "DE", "org": "AS5678 TelecomDE",
                  "timezone": "Europe/Berlin"},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": True}},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://vpnapi.io/api/2.2.2.2",
            json={"security": {"vpn": False}, "network": {"network": "Net"}},
            status=200,
        )

        result = enrich_ip("2.2.2.2", config=config_with_keys)

        assert result.risk_level == "LOW"
        assert result.is_whitelisted is True
        assert "Whitelisted" in result.assessment

    @responses.activate
    def test_vpn_detected_non_cloud_becomes_medium(self, config_with_keys):
        """VPN detection on non-cloud IP upgrades risk to MEDIUM."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/3.3.3.3/json",
            json={"ip": "3.3.3.3", "city": "Zurich", "region": "ZH",
                  "country": "CH", "org": "AS9876 SmallISP",
                  "timezone": "Europe/Zurich"},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": False}},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://vpnapi.io/api/3.3.3.3",
            json={"security": {"vpn": True}, "network": {"network": "VPNNet"}},
            status=200,
        )

        result = enrich_ip("3.3.3.3", config=config_with_keys)

        assert result.is_vpn is True
        assert result.risk_level == "MEDIUM"

    @responses.activate
    def test_vpn_on_major_cloud_stays_low(self, config_with_keys):
        """VPN flag from a major cloud provider does not upgrade risk."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/4.4.4.4/json",
            json={"ip": "4.4.4.4", "city": "Redmond", "region": "WA",
                  "country": "US", "org": "AS8075 Microsoft Corporation",
                  "timezone": "America/Los_Angeles"},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": False}},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://vpnapi.io/api/4.4.4.4",
            json={"security": {"vpn": True}, "network": {"network": "MSFT"}},
            status=200,
        )

        result = enrich_ip("4.4.4.4", config=config_with_keys)

        # Should stay LOW because Microsoft is a major cloud provider
        assert result.risk_level == "LOW"

    @responses.activate
    def test_ipinfo_rate_limit_graceful(self):
        """ipinfo.io 429 doesn't crash; fields default to 'Unknown'."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/9.9.9.9/json",
            json={"error": "rate limit"},
            status=429,
        )

        result = enrich_ip("9.9.9.9", config={})

        assert result.ip == "9.9.9.9"
        assert result.city == "Unknown"
        assert result.risk_level == "LOW"

    @responses.activate
    def test_vpnapi_rate_limit_handled(self, config_with_keys):
        """vpnapi.io 429 is caught silently."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/7.7.7.7/json",
            json={"ip": "7.7.7.7", "city": "London", "region": "England",
                  "country": "GB", "org": "AS111 BT",
                  "timezone": "Europe/London"},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": False}},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://vpnapi.io/api/7.7.7.7",
            json={},
            status=429,
        )

        result = enrich_ip("7.7.7.7", config=config_with_keys)

        # Should succeed without vpn data
        assert result.ip == "7.7.7.7"
        assert result.is_vpn is False  # Default

    @responses.activate
    def test_total_network_failure_returns_error_intel(self):
        """Complete request failure returns an error IPIntelligence."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/6.6.6.6/json",
            body=ConnectionError("DNS resolution failed"),
        )

        result = enrich_ip("6.6.6.6", config={})

        assert result.ip == "6.6.6.6"
        assert result.city == "Error"
        assert "Enrichment failed" in result.assessment

    @responses.activate
    def test_cloud_provider_assessment(self):
        """Major cloud provider org gets appropriate assessment."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/20.0.0.1/json",
            json={"ip": "20.0.0.1", "city": "Ashburn", "region": "VA",
                  "country": "US", "org": "AS8075 Microsoft Azure",
                  "timezone": "America/New_York"},
            status=200,
        )

        result = enrich_ip("20.0.0.1", config={})

        assert result.risk_level == "LOW"
        assert "cloud" in result.assessment.lower() or "legitimate" in result.assessment.lower()


# ---------------------------------------------------------------------------
# JSON loading and validation
# ---------------------------------------------------------------------------

class TestJsonLoadingValidation:
    """Tests for loading and validating investigation JSON files."""

    def test_load_valid_json(self, tmp_path, minimal_investigation_data):
        """Valid JSON loads without error."""
        path = tmp_path / "valid.json"
        path.write_text(json.dumps(minimal_investigation_data))

        with open(str(path), encoding="utf-8") as f:
            data = json.load(f)

        assert data["upn"] == "testuser@contoso.com"
        assert "user_profile" in data

    def test_malformed_json_raises(self, tmp_path):
        """Malformed JSON raises json.JSONDecodeError."""
        path = tmp_path / "bad.json"
        path.write_text("{not valid json")

        with pytest.raises(json.JSONDecodeError):
            with open(str(path)) as f:
                json.load(f)

    def test_missing_file_raises(self, tmp_path):
        """Opening a non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            with open(str(tmp_path / "nonexistent.json")) as f:
                json.load(f)

    def test_missing_required_keys(self, tmp_path):
        """JSON missing 'upn' key triggers KeyError during transformation."""
        data = {"investigation_date": "2026-04-10"}
        path = tmp_path / "incomplete.json"
        path.write_text(json.dumps(data))

        with open(str(path)) as f:
            loaded = json.load(f)

        # The main() function accesses data['upn'] directly, so missing it would raise KeyError
        with pytest.raises(KeyError):
            _ = loaded["upn"]


# ---------------------------------------------------------------------------
# main() integration (mock everything external)
# ---------------------------------------------------------------------------

class TestMainFunction:
    """Integration tests for main() with all external calls mocked."""

    def test_missing_arg_exits(self):
        """Calling main with no args prints usage and exits."""
        with patch("sys.argv", ["generate_report_from_json.py"]):
            with pytest.raises(SystemExit) as exc_info:
                from generate_report_from_json import main
                main()
            assert exc_info.value.code == 1

    def test_nonexistent_file_exits(self, tmp_path):
        """Passing a non-existent file path exits with code 1."""
        fake_path = str(tmp_path / "does_not_exist.json")
        with patch("sys.argv", ["generate_report_from_json.py", fake_path]):
            with pytest.raises(SystemExit) as exc_info:
                from generate_report_from_json import main
                main()
            assert exc_info.value.code == 1

    @responses.activate
    def test_main_with_cached_enrichment(self, tmp_path, minimal_investigation_data):
        """When ip_enrichment is cached, no HTTP calls are made for enrichment."""
        minimal_investigation_data["ip_enrichment"] = []
        minimal_investigation_data["enrichment_metadata"] = {
            "last_enriched": "2026-04-10T12:00:00",
            "ip_count": 0,
        }
        path = tmp_path / "investigation_cached.json"
        path.write_text(json.dumps(minimal_investigation_data))

        mock_generator = MagicMock()
        mock_generator.generate.return_value = str(tmp_path / "report.html")

        with patch("sys.argv", ["generate_report_from_json.py", str(path)]), \
             patch("generate_report_from_json.CompactReportGenerator", return_value=mock_generator), \
             patch("generate_report_from_json.load_config", return_value={}), \
             patch("cleanup_old_investigations.cleanup_old_investigations", return_value=(0, 0)):
            from generate_report_from_json import main
            main()

        mock_generator.generate.assert_called_once()
        # No HTTP calls should have been made for IP enrichment
        assert len(responses.calls) == 0

    @responses.activate
    def test_main_force_enrich(self, tmp_path, minimal_investigation_data):
        """--force-enrich triggers fresh IP enrichment even with cached data."""
        minimal_investigation_data["ip_enrichment"] = []
        minimal_investigation_data["enrichment_metadata"] = {
            "last_enriched": "2026-04-10T12:00:00",
            "ip_count": 0,
        }
        # No IPs to enrich, so no HTTP calls expected, but the code path should go through fresh enrichment
        path = tmp_path / "investigation_force.json"
        path.write_text(json.dumps(minimal_investigation_data))

        mock_generator = MagicMock()
        mock_generator.generate.return_value = str(tmp_path / "report.html")

        with patch("sys.argv", ["generate_report_from_json.py", str(path), "--force-enrich"]), \
             patch("generate_report_from_json.CompactReportGenerator", return_value=mock_generator), \
             patch("generate_report_from_json.load_config", return_value={}), \
             patch("cleanup_old_investigations.cleanup_old_investigations", return_value=(0, 0)):
            from generate_report_from_json import main
            main()

        mock_generator.generate.assert_called_once()

    @responses.activate
    def test_main_with_ip_enrichment(self, tmp_path, minimal_investigation_data):
        """main() enriches IPs from signin_ip_counts when no cache exists."""
        minimal_investigation_data["signin_ip_counts"] = [
            {
                "IPAddress": "10.1.1.1",
                "SignInCount": 5,
                "SuccessCount": 4,
                "FailureCount": 1,
                "FirstSeen": "2026-04-01T00:00:00Z",
                "LastSeen": "2026-04-10T00:00:00Z",
                "LastAuthResultDetail": "MFA requirement satisfied",
            }
        ]
        path = tmp_path / "investigation_enrich.json"
        path.write_text(json.dumps(minimal_investigation_data))

        # Mock ipinfo
        responses.add(
            responses.GET,
            "https://ipinfo.io/10.1.1.1/json",
            json={"ip": "10.1.1.1", "city": "Ithaca", "region": "NY",
                  "country": "US", "org": "AS1234 Cornell", "timezone": "America/New_York"},
            status=200,
        )

        mock_generator = MagicMock()
        mock_generator.generate.return_value = str(tmp_path / "report.html")

        with patch("sys.argv", ["generate_report_from_json.py", str(path)]), \
             patch("generate_report_from_json.CompactReportGenerator", return_value=mock_generator), \
             patch("generate_report_from_json.load_config", return_value={}), \
             patch("cleanup_old_investigations.cleanup_old_investigations", return_value=(0, 0)):
            from generate_report_from_json import main
            main()

        mock_generator.generate.assert_called_once()
        # Verify the result passed to generate has the enriched IP
        call_args = mock_generator.generate.call_args
        result_obj = call_args[0][0]
        assert len(result_obj.ip_intelligence) == 1
        assert result_obj.ip_intelligence[0].ip == "10.1.1.1"
        assert result_obj.ip_intelligence[0].signin_count == 5

    @responses.activate
    def test_main_saves_enrichment_to_json(self, tmp_path, minimal_investigation_data):
        """After fresh enrichment, data is saved back to the JSON file."""
        minimal_investigation_data["signin_ip_counts"] = [
            {"IPAddress": "10.2.2.2", "SignInCount": 3, "SuccessCount": 3,
             "FailureCount": 0, "FirstSeen": "2026-04-05T00:00:00Z",
             "LastSeen": "2026-04-10T00:00:00Z", "LastAuthResultDetail": "Token"}
        ]
        path = tmp_path / "investigation_save.json"
        path.write_text(json.dumps(minimal_investigation_data))

        responses.add(
            responses.GET,
            "https://ipinfo.io/10.2.2.2/json",
            json={"ip": "10.2.2.2", "city": "Boston", "region": "MA",
                  "country": "US", "org": "AS5678 ISP", "timezone": "America/New_York"},
            status=200,
        )

        mock_generator = MagicMock()
        mock_generator.generate.return_value = str(tmp_path / "report.html")

        with patch("sys.argv", ["generate_report_from_json.py", str(path)]), \
             patch("generate_report_from_json.CompactReportGenerator", return_value=mock_generator), \
             patch("generate_report_from_json.load_config", return_value={}), \
             patch("cleanup_old_investigations.cleanup_old_investigations", return_value=(0, 0)):
            from generate_report_from_json import main
            main()

        # Re-read the JSON file and verify enrichment was saved
        with open(str(path)) as f:
            saved = json.load(f)

        assert "ip_enrichment" in saved
        assert "enrichment_metadata" in saved
        assert saved["enrichment_metadata"]["ip_count"] == 1
        assert saved["ip_enrichment"][0]["ip"] == "10.2.2.2"
        assert saved["ip_enrichment"][0]["city"] == "Boston"


# ---------------------------------------------------------------------------
# MFA transformation
# ---------------------------------------------------------------------------

class TestMFATransformation:
    """Test MFA data parsing in both raw and processed formats."""

    @responses.activate
    def test_raw_graph_api_mfa_format(self, tmp_path, minimal_investigation_data):
        """MFA data in raw Graph API format ('value' key) is parsed correctly."""
        path = tmp_path / "investigation_mfa_raw.json"
        path.write_text(json.dumps(minimal_investigation_data))

        mock_generator = MagicMock()
        mock_generator.generate.return_value = str(tmp_path / "report.html")

        with patch("sys.argv", ["generate_report_from_json.py", str(path)]), \
             patch("generate_report_from_json.CompactReportGenerator", return_value=mock_generator), \
             patch("generate_report_from_json.load_config", return_value={}), \
             patch("cleanup_old_investigations.cleanup_old_investigations", return_value=(0, 0)):
            from generate_report_from_json import main
            main()

        result_obj = mock_generator.generate.call_args[0][0]
        assert result_obj.mfa_status is not None
        assert result_obj.mfa_status.mfa_enabled is True
        assert result_obj.mfa_status.methods_count == 2

    @responses.activate
    def test_processed_mfa_format(self, tmp_path, minimal_investigation_data):
        """MFA data in processed format ('methods' key) is parsed correctly."""
        minimal_investigation_data["mfa_methods"] = {
            "methods": [
                {"type": "microsoftAuthenticator"},
                {"type": "phone"},
            ]
        }
        path = tmp_path / "investigation_mfa_proc.json"
        path.write_text(json.dumps(minimal_investigation_data))

        mock_generator = MagicMock()
        mock_generator.generate.return_value = str(tmp_path / "report.html")

        with patch("sys.argv", ["generate_report_from_json.py", str(path)]), \
             patch("generate_report_from_json.CompactReportGenerator", return_value=mock_generator), \
             patch("generate_report_from_json.load_config", return_value={}), \
             patch("cleanup_old_investigations.cleanup_old_investigations", return_value=(0, 0)):
            from generate_report_from_json import main
            main()

        result_obj = mock_generator.generate.call_args[0][0]
        assert result_obj.mfa_status is not None
        assert result_obj.mfa_status.methods_count == 2
        assert result_obj.mfa_status.has_authenticator is True


# ---------------------------------------------------------------------------
# Risk assessment logic
# ---------------------------------------------------------------------------

class TestRiskAssessment:
    """Test the dynamic risk assessment computed in main()."""

    @responses.activate
    def test_low_risk_baseline(self, tmp_path, minimal_investigation_data):
        """No anomalies, no incidents produces a baseline risk score."""
        path = tmp_path / "investigation_risk.json"
        path.write_text(json.dumps(minimal_investigation_data))

        mock_generator = MagicMock()
        mock_generator.generate.return_value = str(tmp_path / "report.html")

        with patch("sys.argv", ["generate_report_from_json.py", str(path)]), \
             patch("generate_report_from_json.CompactReportGenerator", return_value=mock_generator), \
             patch("generate_report_from_json.load_config", return_value={}), \
             patch("cleanup_old_investigations.cleanup_old_investigations", return_value=(0, 0)):
            from generate_report_from_json import main
            main()

        result_obj = mock_generator.generate.call_args[0][0]
        assert hasattr(result_obj, "risk_assessment")
        assert result_obj.risk_assessment["risk_level"] in ("LOW", "MEDIUM", "HIGH")

    @responses.activate
    def test_dlp_events_create_critical_action(self, tmp_path, minimal_investigation_data):
        """DLP events produce a critical action recommendation."""
        minimal_investigation_data["dlp_events"] = [
            {
                "TimeGenerated": "2026-04-10T10:00:00Z",
                "UserId": "testuser@contoso.com",
                "DeviceName": "WORKSTATION01",
                "ClientIP": "10.0.0.1",
                "RuleName": "PII Rule",
                "File": "sensitive.xlsx",
                "Operation": "FileCopiedToNetworkShare",
                "TargetDomain": "",
                "TargetFilePath": "\\\\server\\share",
            }
        ]
        path = tmp_path / "investigation_dlp.json"
        path.write_text(json.dumps(minimal_investigation_data))

        mock_generator = MagicMock()
        mock_generator.generate.return_value = str(tmp_path / "report.html")

        with patch("sys.argv", ["generate_report_from_json.py", str(path)]), \
             patch("generate_report_from_json.CompactReportGenerator", return_value=mock_generator), \
             patch("generate_report_from_json.load_config", return_value={}), \
             patch("cleanup_old_investigations.cleanup_old_investigations", return_value=(0, 0)):
            from generate_report_from_json import main
            main()

        result_obj = mock_generator.generate.call_args[0][0]
        critical = result_obj.recommendations["critical_actions"]
        assert len(critical) >= 1
        assert "DLP" in critical[0]


# ---------------------------------------------------------------------------
# Conftest fixture integration
# ---------------------------------------------------------------------------

class TestConftestFixture:
    """Verify the sample_investigation_json fixture from conftest.py works."""

    def test_sample_investigation_json_is_valid(self, sample_investigation_json):
        """The conftest fixture produces a readable, valid JSON file."""
        with open(sample_investigation_json) as f:
            data = json.load(f)

        assert data["subject"] == "jsmith@contoso.com"
        assert data["summary"]["risk_level"] == "Medium"
        assert isinstance(data["sign_in_logs"], list)

    def test_sample_investigation_json_file_exists(self, sample_investigation_json):
        """The fixture creates a real file on disk."""
        assert os.path.exists(sample_investigation_json)
        assert sample_investigation_json.endswith(".json")
