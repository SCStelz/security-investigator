"""Tests for enrich_ips.py — IP enrichment utility."""

import json
import sys
from unittest.mock import mock_open, patch

import pytest
import responses

# ---------------------------------------------------------------------------
# Module under test
# ---------------------------------------------------------------------------
sys.path.insert(0, "/tmp/repo-health-security-investigator")
import enrich_ips

# ---------------------------------------------------------------------------
# Helpers / constants
# ---------------------------------------------------------------------------

TEST_IP = "203.0.113.50"
TEST_IP_2 = "198.51.100.10"
PRIVATE_IP = "192.168.1.1"

SAMPLE_CONFIG = {
    "ipinfo_token": "test-ipinfo-token",
    "abuseipdb_token": "test-abuseipdb-token",
    "vpnapi_token": "test-vpnapi-token",
    "shodan_token": "test-shodan-token",
}

SAMPLE_CONFIG_NO_KEYS = {}


def _ipinfo_response(ip=TEST_IP, **overrides):
    base = {
        "ip": ip,
        "city": "Anytown",
        "region": "California",
        "country": "US",
        "org": "AS12345 Example ISP",
        "loc": "34.0522,-118.2437",
        "timezone": "America/Los_Angeles",
        "privacy": {
            "vpn": False,
            "proxy": False,
            "tor": False,
            "hosting": False,
        },
    }
    base.update(overrides)
    return base


def _vpnapi_response(**overrides):
    base = {
        "security": {
            "vpn": False,
            "proxy": False,
            "tor": False,
            "relay": False,
        }
    }
    base.update(overrides)
    return base


def _abuseipdb_check_response(score=0, reports=0, whitelisted=False):
    return {
        "data": {
            "abuseConfidenceScore": score,
            "totalReports": reports,
            "isWhitelisted": whitelisted,
        }
    }


def _abuseipdb_reports_response(reports=None):
    if reports is None:
        reports = []
    return {"data": {"results": reports}}


def _shodan_full_response(**overrides):
    base = {
        "ports": [22, 80, 443],
        "os": "Linux",
        "vulns": ["CVE-2021-44228"],
        "tags": [],
        "hostnames": ["example.com"],
        "last_update": "2026-04-01T12:00:00.000000",
        "data": [
            {
                "port": 22,
                "transport": "tcp",
                "product": "OpenSSH",
                "version": "8.9",
                "_shodan": {"module": "ssh"},
                "data": "SSH-2.0-OpenSSH_8.9",
            },
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.22",
                "_shodan": {"module": "https"},
                "data": "HTTP/1.1 200 OK",
                "ssl": {
                    "cert": {
                        "subject": {"CN": "example.com"},
                        "issuer": {"O": "Let's Encrypt"},
                        "expired": False,
                    }
                },
            },
        ],
    }
    base.update(overrides)
    return base


def _internetdb_response(**overrides):
    base = {
        "ports": [80, 443],
        "vulns": ["CVE-2022-1234"],
        "tags": ["self-signed"],
        "hostnames": ["fallback.example.com"],
        "cpes": ["cpe:/a:nginx:nginx:1.22"],
    }
    base.update(overrides)
    return base


def _register_all_apis_ok(ip=TEST_IP, config=None):
    """Register successful responses for all four API providers."""
    config = config or SAMPLE_CONFIG

    responses.add(
        responses.GET,
        f"https://ipinfo.io/{ip}/json",
        json=_ipinfo_response(ip=ip),
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://vpnapi.io/api/{ip}",
        json=_vpnapi_response(),
        status=200,
    )
    responses.add(
        responses.GET,
        "https://api.abuseipdb.com/api/v2/check",
        json=_abuseipdb_check_response(),
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://api.shodan.io/shodan/host/{ip}",
        json=_shodan_full_response(),
        status=200,
    )


# ===========================================================================
# load_config tests
# ===========================================================================


class TestLoadConfig:
    """Tests for load_config()."""

    def test_loads_from_config_json(self, tmp_path):
        config_data = {"ipinfo_token": "from-file", "shodan_token": "shodan-file"}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        with patch.object(enrich_ips, "__file__", str(tmp_path / "enrich_ips.py")):
            with patch.dict("os.environ", {}, clear=True):
                result = enrich_ips.load_config()

        assert result["ipinfo_token"] == "from-file"
        assert result["shodan_token"] == "shodan-file"

    def test_env_vars_override_config_json(self, tmp_path):
        config_data = {"ipinfo_token": "from-file", "shodan_token": "shodan-file"}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))

        env = {"IPINFO_TOKEN": "from-env", "SHODAN_TOKEN": "shodan-env"}
        with patch.object(enrich_ips, "__file__", str(tmp_path / "enrich_ips.py")):
            with patch.dict("os.environ", env, clear=True):
                result = enrich_ips.load_config()

        assert result["ipinfo_token"] == "from-env"
        assert result["shodan_token"] == "shodan-env"

    def test_missing_config_file_raises(self, tmp_path):
        with patch.object(enrich_ips, "__file__", str(tmp_path / "enrich_ips.py")):
            with pytest.raises(FileNotFoundError):
                enrich_ips.load_config()


# ===========================================================================
# enrich_single_ip — ipinfo.io
# ===========================================================================


class TestIpinfo:
    """IPInfo.io enrichment tests."""

    @responses.activate
    def test_basic_enrichment(self):
        _register_all_apis_ok()
        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)

        assert result["ip"] == TEST_IP
        assert result["city"] == "Anytown"
        assert result["region"] == "California"
        assert result["country"] == "US"
        assert result["org"] == "AS12345 Example ISP"
        assert result["timezone"] == "America/Los_Angeles"
        assert result["asn"] == "AS12345"

    @responses.activate
    def test_lat_lon_parsed(self):
        _register_all_apis_ok()
        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)

        assert result["latitude"] == pytest.approx(34.0522)
        assert result["longitude"] == pytest.approx(-118.2437)

    @responses.activate
    def test_malformed_loc_field(self):
        """loc without a comma should not crash."""
        responses.add(
            responses.GET,
            f"https://ipinfo.io/{TEST_IP}/json",
            json=_ipinfo_response(loc="BADDATA"),
            status=200,
        )
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["latitude"] is None
        assert result["longitude"] is None

    @responses.activate
    def test_loc_non_numeric(self):
        """loc with non-numeric parts after split should not crash."""
        responses.add(
            responses.GET,
            f"https://ipinfo.io/{TEST_IP}/json",
            json=_ipinfo_response(loc="abc,def"),
            status=200,
        )
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["latitude"] is None
        assert result["longitude"] is None

    @responses.activate
    def test_privacy_flags(self):
        privacy = {"vpn": True, "proxy": True, "tor": True, "hosting": True}
        responses.add(
            responses.GET,
            f"https://ipinfo.io/{TEST_IP}/json",
            json=_ipinfo_response(privacy=privacy),
            status=200,
        )
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["is_vpn"] is True
        assert result["is_proxy"] is True
        assert result["is_tor"] is True
        assert result["is_hosting"] is True

    @responses.activate
    def test_ipinfo_500_graceful(self):
        """Non-200 from ipinfo should leave defaults."""
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", status=500)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["city"] == "Unknown"
        assert result["country"] == "Unknown"

    @responses.activate
    def test_ipinfo_timeout(self):
        """Connection error from ipinfo should not crash."""
        responses.add(
            responses.GET,
            f"https://ipinfo.io/{TEST_IP}/json",
            body=ConnectionError("timeout"),
        )
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["city"] == "Unknown"

    @responses.activate
    def test_no_ipinfo_token_still_works(self):
        """Should call ipinfo without a token param when token is missing."""
        config = {**SAMPLE_CONFIG, "ipinfo_token": None}
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, config)
        assert result["city"] == "Anytown"

    @responses.activate
    def test_org_without_as_prefix(self):
        """Org that doesn't start with AS should not set asn."""
        responses.add(
            responses.GET,
            f"https://ipinfo.io/{TEST_IP}/json",
            json=_ipinfo_response(org="Example Corp"),
            status=200,
        )
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["asn"] == "Unknown"


# ===========================================================================
# enrich_single_ip — vpnapi.io
# ===========================================================================


class TestVpnapi:
    """VPNapi.io enrichment tests."""

    @responses.activate
    def test_vpnapi_flags(self):
        security = {"vpn": True, "proxy": True, "tor": True, "relay": True}
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(
            responses.GET,
            f"https://vpnapi.io/api/{TEST_IP}",
            json=_vpnapi_response(security=security),
            status=200,
        )
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["vpnapi_security_vpn"] is True
        assert result["vpnapi_security_proxy"] is True
        assert result["vpnapi_security_tor"] is True
        assert result["vpnapi_security_relay"] is True

    @responses.activate
    def test_vpnapi_error_graceful(self):
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", body=ConnectionError("fail"))
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["vpnapi_security_vpn"] is False

    @responses.activate
    def test_vpnapi_500_leaves_defaults(self):
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", status=500)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["vpnapi_security_vpn"] is False


# ===========================================================================
# enrich_single_ip — AbuseIPDB
# ===========================================================================


class TestAbuseIPDB:
    """AbuseIPDB enrichment tests."""

    @responses.activate
    def test_abuse_score_and_reports(self):
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json=_abuseipdb_check_response(score=85, reports=12),
            status=200,
        )
        # Reports endpoint (called because total_reports > 0)
        reports = [
            {
                "reportedAt": "2026-04-01T10:00:00Z",
                "reporterCountryCode": "US",
                "categories": [14, 18],
                "comment": "Port scanning observed",
            }
        ]
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/reports",
            json=_abuseipdb_reports_response(reports),
            status=200,
        )
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)

        assert result["abuse_confidence_score"] == 85
        assert result["total_reports"] == 12
        assert len(result["recent_comments"]) == 1
        assert result["recent_comments"][0]["reporter_country"] == "US"
        assert "Port Scan" in result["recent_comments"][0]["categories"]
        assert "Brute-Force" in result["recent_comments"][0]["categories"]

    @responses.activate
    def test_abuse_rate_limit_429(self, capsys):
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", status=429)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)

        assert result["abuse_confidence_score"] == 0
        assert result["total_reports"] == 0
        captured = capsys.readouterr()
        assert "Rate limit" in captured.err

    @responses.activate
    def test_abuse_skipped_without_token(self):
        """No abuseipdb_token means the API is never called."""
        config = {**SAMPLE_CONFIG, "abuseipdb_token": None}
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, config)
        assert result["abuse_confidence_score"] == 0
        assert result["recent_comments"] == []

    @responses.activate
    def test_abuse_whitelisted(self):
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json=_abuseipdb_check_response(whitelisted=True),
            status=200,
        )
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["is_whitelisted"] is True

    @responses.activate
    def test_abuse_reports_endpoint_error(self, capsys):
        """Reports fetch failure should not crash."""
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json=_abuseipdb_check_response(score=50, reports=5),
            status=200,
        )
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/reports",
            body=ConnectionError("timeout"),
        )
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["total_reports"] == 5
        assert result["recent_comments"] == []
        captured = capsys.readouterr()
        assert "AbuseIPDB Reports" in captured.err

    @responses.activate
    def test_abuse_unknown_category_id(self):
        """Category IDs not in ABUSE_CATEGORIES should render as #N."""
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json=_abuseipdb_check_response(score=30, reports=1),
            status=200,
        )
        reports = [
            {
                "reportedAt": "2026-04-01T10:00:00Z",
                "reporterCountryCode": "DE",
                "categories": [999],
                "comment": "Unknown attack",
            }
        ]
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/reports",
            json=_abuseipdb_reports_response(reports),
            status=200,
        )
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", json=_shodan_full_response(), status=200)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert "#999" in result["recent_comments"][0]["categories"]


# ===========================================================================
# enrich_single_ip — Shodan
# ===========================================================================


class TestShodan:
    """Shodan enrichment tests (full API + InternetDB fallback)."""

    @responses.activate
    def test_shodan_full_api(self):
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(
            responses.GET,
            f"https://api.shodan.io/shodan/host/{TEST_IP}",
            json=_shodan_full_response(),
            status=200,
        )

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)

        assert result["shodan_ports"] == [22, 80, 443]
        assert result["shodan_os"] == "Linux"
        assert "CVE-2021-44228" in result["shodan_vulns"]
        assert result["shodan_hostnames"] == ["example.com"]
        assert len(result["shodan_services"]) == 2
        # Check SSL info on the HTTPS service
        https_svc = [s for s in result["shodan_services"] if s["port"] == 443][0]
        assert https_svc["ssl_subject"] == "example.com"
        assert https_svc["ssl_issuer"] == "Let's Encrypt"
        assert https_svc["ssl_expired"] is False

    @responses.activate
    def test_shodan_404_no_fallback(self):
        """404 means IP not in Shodan, no InternetDB fallback needed."""
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", status=404)

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["shodan_ports"] == []
        assert result["shodan_services"] == []

    @responses.activate
    def test_shodan_403_falls_back_to_internetdb(self):
        """403 (free key) should trigger InternetDB fallback."""
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(responses.GET, f"https://api.shodan.io/shodan/host/{TEST_IP}", status=403)
        responses.add(
            responses.GET,
            f"https://internetdb.shodan.io/{TEST_IP}",
            json=_internetdb_response(),
            status=200,
        )

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["shodan_ports"] == [80, 443]
        assert result["shodan_cpes"] == ["cpe:/a:nginx:nginx:1.22"]
        assert "self-signed" in result["shodan_tags"]

    @responses.activate
    def test_shodan_no_token_uses_internetdb(self):
        """No Shodan token should go straight to InternetDB."""
        config = {**SAMPLE_CONFIG, "shodan_token": None}
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(
            responses.GET,
            f"https://internetdb.shodan.io/{TEST_IP}",
            json=_internetdb_response(),
            status=200,
        )

        result = enrich_ips.enrich_single_ip(TEST_IP, config)
        assert result["shodan_ports"] == [80, 443]

    @responses.activate
    def test_shodan_full_api_error_falls_back(self, capsys):
        """Connection error on full API should fall back to InternetDB."""
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(
            responses.GET,
            f"https://api.shodan.io/shodan/host/{TEST_IP}",
            body=ConnectionError("timeout"),
        )
        responses.add(
            responses.GET,
            f"https://internetdb.shodan.io/{TEST_IP}",
            json=_internetdb_response(),
            status=200,
        )

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["shodan_ports"] == [80, 443]
        captured = capsys.readouterr()
        assert "Shodan" in captured.err

    @responses.activate
    def test_internetdb_also_fails(self, capsys):
        """Both Shodan APIs failing should leave empty defaults."""
        config = {**SAMPLE_CONFIG, "shodan_token": None}
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(
            responses.GET,
            f"https://internetdb.shodan.io/{TEST_IP}",
            body=ConnectionError("down"),
        )

        result = enrich_ips.enrich_single_ip(TEST_IP, config)
        assert result["shodan_ports"] == []
        assert result["shodan_vulns"] == []

    @responses.activate
    def test_shodan_vulns_sorted(self):
        """Vulns should be sorted alphabetically."""
        responses.add(responses.GET, f"https://ipinfo.io/{TEST_IP}/json", json=_ipinfo_response(), status=200)
        responses.add(responses.GET, f"https://vpnapi.io/api/{TEST_IP}", json=_vpnapi_response(), status=200)
        responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", json=_abuseipdb_check_response(), status=200)
        responses.add(
            responses.GET,
            f"https://api.shodan.io/shodan/host/{TEST_IP}",
            json=_shodan_full_response(vulns=["CVE-2022-9999", "CVE-2021-0001", "CVE-2023-5555"]),
            status=200,
        )

        result = enrich_ips.enrich_single_ip(TEST_IP, SAMPLE_CONFIG)
        assert result["shodan_vulns"] == ["CVE-2021-0001", "CVE-2022-9999", "CVE-2023-5555"]


# ===========================================================================
# enrich_ips (parallel enrichment)
# ===========================================================================


class TestEnrichIps:
    """Tests for the parallel enrich_ips() function."""

    @responses.activate
    def test_enriches_multiple_ips(self):
        for ip in [TEST_IP, TEST_IP_2]:
            _register_all_apis_ok(ip=ip)

        with patch("enrich_ips.load_config", return_value=SAMPLE_CONFIG):
            results = enrich_ips.enrich_ips([TEST_IP, TEST_IP_2], max_workers=2)

        assert len(results) == 2
        # Results should be sorted by IP
        assert results[0]["ip"] < results[1]["ip"]

    @responses.activate
    def test_empty_ip_list(self):
        with patch("enrich_ips.load_config", return_value=SAMPLE_CONFIG):
            results = enrich_ips.enrich_ips([])

        assert results == []

    @responses.activate
    def test_single_ip(self):
        _register_all_apis_ok()
        with patch("enrich_ips.load_config", return_value=SAMPLE_CONFIG):
            results = enrich_ips.enrich_ips([TEST_IP])

        assert len(results) == 1
        assert results[0]["ip"] == TEST_IP


# ===========================================================================
# extract_ips_from_investigation
# ===========================================================================


class TestExtractIps:
    """Tests for extract_ips_from_investigation()."""

    def test_simple_ip_list_format(self, tmp_path):
        data = {"ips": ["1.2.3.4", "5.6.7.8"]}
        path = tmp_path / "ips.json"
        path.write_text(json.dumps(data))

        result = enrich_ips.extract_ips_from_investigation(str(path))
        assert result == ["1.2.3.4", "5.6.7.8"]

    def test_full_investigation_format(self, tmp_path):
        data = {
            "ip_enrichment": [{"ip": "1.2.3.4"}],
            "signin_apps": [{"IPAddresses": ["1.2.3.4", "5.6.7.8"]}],
            "signin_locations": [{"IPAddresses": ["9.10.11.12"]}],
        }
        path = tmp_path / "investigation.json"
        path.write_text(json.dumps(data))

        result = enrich_ips.extract_ips_from_investigation(str(path))
        # 1.2.3.4 is already enriched, so only 5.6.7.8 and 9.10.11.12
        assert sorted(result) == ["5.6.7.8", "9.10.11.12"]

    def test_skips_ipv6(self, tmp_path):
        data = {
            "ip_enrichment": [],
            "signin_apps": [{"IPAddresses": ["1.2.3.4", "2001:db8::1"]}],
            "signin_locations": [],
        }
        path = tmp_path / "investigation.json"
        path.write_text(json.dumps(data))

        result = enrich_ips.extract_ips_from_investigation(str(path))
        assert result == ["1.2.3.4"]

    def test_all_ips_already_enriched(self, tmp_path):
        data = {
            "ip_enrichment": [{"ip": "1.2.3.4"}],
            "signin_apps": [{"IPAddresses": ["1.2.3.4"]}],
            "signin_locations": [],
        }
        path = tmp_path / "investigation.json"
        path.write_text(json.dumps(data))

        result = enrich_ips.extract_ips_from_investigation(str(path))
        assert result == []

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            enrich_ips.extract_ips_from_investigation("/nonexistent/path.json")

    def test_invalid_json_raises(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("NOT JSON")
        with pytest.raises(json.JSONDecodeError):
            enrich_ips.extract_ips_from_investigation(str(path))

    def test_deduplicates_ips(self, tmp_path):
        data = {
            "ip_enrichment": [],
            "signin_apps": [
                {"IPAddresses": ["1.2.3.4", "5.6.7.8"]},
                {"IPAddresses": ["1.2.3.4"]},
            ],
            "signin_locations": [{"IPAddresses": ["5.6.7.8"]}],
        }
        path = tmp_path / "investigation.json"
        path.write_text(json.dumps(data))

        result = enrich_ips.extract_ips_from_investigation(str(path))
        assert sorted(result) == ["1.2.3.4", "5.6.7.8"]


# ===========================================================================
# CLI / main()
# ===========================================================================


class TestMain:
    """Tests for CLI argument parsing and main()."""

    def test_no_args_exits(self):
        with patch.object(sys, "argv", ["enrich_ips.py"]):
            with pytest.raises(SystemExit) as exc_info:
                enrich_ips.main()
            assert exc_info.value.code == 1

    def test_file_flag_missing_path_exits(self):
        with patch.object(sys, "argv", ["enrich_ips.py", "--file"]):
            with pytest.raises(SystemExit) as exc_info:
                enrich_ips.main()
            assert exc_info.value.code == 1

    @responses.activate
    def test_file_flag_with_empty_results_exits(self, tmp_path):
        data = {
            "ip_enrichment": [{"ip": "1.2.3.4"}],
            "signin_apps": [{"IPAddresses": ["1.2.3.4"]}],
            "signin_locations": [],
        }
        path = tmp_path / "investigation.json"
        path.write_text(json.dumps(data))

        with patch.object(sys, "argv", ["enrich_ips.py", "--file", str(path)]):
            with pytest.raises(SystemExit) as exc_info:
                enrich_ips.main()
            assert exc_info.value.code == 0

    @responses.activate
    def test_direct_ip_args(self, tmp_path):
        _register_all_apis_ok()

        with patch.object(sys, "argv", ["enrich_ips.py", TEST_IP]):
            with patch("enrich_ips.load_config", return_value=SAMPLE_CONFIG):
                with patch("enrich_ips.Path") as mock_path_cls:
                    # Mock the output file writing
                    mock_output = mock_path_cls.return_value.__truediv__.return_value
                    mock_output.parent.mkdir = lambda exist_ok: None
                    mock_open_obj = mock_open()
                    with patch("builtins.open", mock_open_obj):
                        enrich_ips.main()


# ===========================================================================
# Print functions (smoke tests)
# ===========================================================================


class TestPrintFunctions:
    """Smoke tests for output formatting functions."""

    def _make_result(self, **overrides):
        base = {
            "ip": TEST_IP,
            "city": "Anytown",
            "region": "CA",
            "country": "US",
            "org": "AS12345 Example ISP",
            "asn": "AS12345",
            "timezone": "America/Los_Angeles",
            "latitude": 34.05,
            "longitude": -118.24,
            "is_vpn": False,
            "is_proxy": False,
            "is_tor": False,
            "is_hosting": False,
            "vpnapi_security_vpn": False,
            "vpnapi_security_proxy": False,
            "vpnapi_security_tor": False,
            "vpnapi_security_relay": False,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "is_whitelisted": False,
            "recent_comments": [],
            "shodan_ports": [],
            "shodan_services": [],
            "shodan_os": None,
            "shodan_vulns": [],
            "shodan_tags": [],
            "shodan_hostnames": [],
            "shodan_cpes": [],
            "shodan_last_update": None,
        }
        base.update(overrides)
        return base

    def test_print_detailed_results(self, capsys):
        results = [self._make_result()]
        enrich_ips.print_detailed_results(results)
        captured = capsys.readouterr()
        assert TEST_IP in captured.out
        assert "Anytown" in captured.out

    def test_print_detailed_results_with_flags(self, capsys):
        results = [self._make_result(is_vpn=True, abuse_confidence_score=90, total_reports=5)]
        enrich_ips.print_detailed_results(results)
        captured = capsys.readouterr()
        assert "ipinfo:VPN" in captured.out
        assert "Abuse:90%" in captured.out

    def test_print_abuse_comments_no_comments(self, capsys):
        results = [self._make_result()]
        enrich_ips.print_abuse_comments(results)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_print_abuse_comments_with_data(self, capsys):
        comments = [
            {
                "date": "2026-04-01 10:00:00",
                "reporter_country": "US",
                "categories": ["Port Scan", "Brute-Force"],
                "comment": "Scanning observed",
            }
        ]
        results = [self._make_result(abuse_confidence_score=80, recent_comments=comments)]
        enrich_ips.print_abuse_comments(results)
        captured = capsys.readouterr()
        assert "Scanning observed" in captured.out
        assert "Port Scan" in captured.out

    def test_print_shodan_details_no_ports(self, capsys):
        results = [self._make_result()]
        enrich_ips.print_shodan_details(results)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_print_shodan_details_with_services(self, capsys):
        services = [
            {
                "port": 443,
                "transport": "tcp",
                "module": "https",
                "product": "nginx",
                "version": "1.22",
                "banner_snippet": "HTTP OK",
                "ssl_subject": "example.com",
                "ssl_issuer": "LE",
                "ssl_expired": False,
            }
        ]
        results = [
            self._make_result(
                shodan_ports=[443],
                shodan_services=services,
                shodan_os="Linux",
                shodan_vulns=["CVE-2021-44228"],
                shodan_last_update="2026-04-01T12:00:00",
            )
        ]
        enrich_ips.print_shodan_details(results)
        captured = capsys.readouterr()
        assert "nginx" in captured.out
        assert "CVE-2021-44228" in captured.out

    def test_print_shodan_details_internetdb_fallback(self, capsys):
        """No services means InternetDB fallback display."""
        results = [
            self._make_result(
                shodan_ports=[80, 443],
                shodan_cpes=["cpe:/a:nginx:nginx:1.22"],
            )
        ]
        enrich_ips.print_shodan_details(results)
        captured = capsys.readouterr()
        assert "Open ports:" in captured.out
        assert "cpe:/a:nginx" in captured.out

    def test_print_shodan_many_cves(self, capsys):
        """More than 15 CVEs should show '... and N more'."""
        vulns = [f"CVE-2021-{i:04d}" for i in range(20)]
        results = [self._make_result(shodan_ports=[80], shodan_vulns=vulns)]
        enrich_ips.print_shodan_details(results)
        captured = capsys.readouterr()
        assert "and 5 more" in captured.out

    def test_print_summary(self, capsys):
        results = [
            self._make_result(is_vpn=True, shodan_ports=[22, 80], shodan_vulns=["CVE-1"]),
            self._make_result(ip=TEST_IP_2, abuse_confidence_score=80, total_reports=3),
        ]
        enrich_ips.print_summary(results)
        captured = capsys.readouterr()
        assert "VPN IPs: 1" in captured.out
        assert "High confidence (>75%): 1" in captured.out
        assert "Total open ports discovered: 2" in captured.out

    def test_print_summary_c2_tags(self, capsys):
        results = [self._make_result(shodan_tags=["c2"])]
        enrich_ips.print_summary(results)
        captured = capsys.readouterr()
        assert "C2/Malware" in captured.out
        assert TEST_IP in captured.out

    def test_print_summary_honeypot_tags(self, capsys):
        results = [self._make_result(shodan_tags=["honeypot"])]
        enrich_ips.print_summary(results)
        captured = capsys.readouterr()
        assert "Honeypot" in captured.out


# ===========================================================================
# ABUSE_CATEGORIES constant
# ===========================================================================


class TestAbuseCategories:
    """Verify the category mapping is complete and correct."""

    def test_known_categories(self):
        assert enrich_ips.ABUSE_CATEGORIES[14] == "Port Scan"
        assert enrich_ips.ABUSE_CATEGORIES[18] == "Brute-Force"
        assert enrich_ips.ABUSE_CATEGORIES[22] == "SSH"
        assert enrich_ips.ABUSE_CATEGORIES[7] == "Phishing"

    def test_all_ids_are_ints(self):
        for key in enrich_ips.ABUSE_CATEGORIES:
            assert isinstance(key, int)

    def test_all_names_are_strings(self):
        for val in enrich_ips.ABUSE_CATEGORIES.values():
            assert isinstance(val, str)
            assert len(val) > 0
