"""
Phase 6C: Live Threat Intelligence Integration Test Suite
Validates:
1. Live VirusTotal API v3 lookups (domain, IP, URL, file hash)
2. Live AbuseIPDB API v2 lookups (IP abuse score, country, ISP, last reported)
3. Strict pre-validation for IPv4/IPv6 inputs
4. Graceful handling of HTTP 401/403, 404, 429, and timeouts
5. Unconfigured degraded mode behavior
6. Secret protection (zero API key leakage across endpoints and exports)
7. Threat Intel IOC correlation and schema enrichment
8. Category capping to prevent double-counting
"""

import sys
import time
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import pytest
import requests

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import create_app
from app.config import Config
from app.utils.threat_intel import ThreatIntelClient, threat_intel
from app.modules.ioc_extractor import ioc_extractor
from app.modules.scoring import RiskScoringEngine
from app.models import db, ExtractedIOC, Investigation


@pytest.fixture(scope="module")
def app_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        client = app.test_client()
        yield client


class TestPhase6CControlledThreatIntel:
    """Deterministic, controlled-fixture validation for VirusTotal v3 response processing."""

    def test_01_vt_domain_lookup_controlled(self):
        """Verify VirusTotal domain lookup parsing and attributes using controlled fixture."""
        mock_payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 75, "undetected": 10},
                    "categories": {"Forcepoint": "search engines", "Sophos": "clean"},
                    "reputation": 100
                }
            }
        }
        with patch.object(threat_intel, "_vt_get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_payload
            mock_get.return_value = mock_resp

            result = threat_intel.check_vt_domain("google.com")
            assert result["status"] == "success"
            assert result["checked"] is True
            assert "verdict" in result
            assert "malicious_votes" in result
            assert "categories" in result

    def test_02_vt_ip_lookup_controlled(self):
        """Verify VirusTotal IP lookup parsing and harmless stats using controlled fixture."""
        mock_payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 85, "undetected": 5},
                    "country": "US",
                    "as_owner": "Google LLC",
                    "reputation": 100
                }
            }
        }
        with patch.object(threat_intel, "_vt_get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_payload
            mock_get.return_value = mock_resp

            result = threat_intel.check_vt_ip("8.8.8.8")
            assert result["status"] == "success"
            assert result["checked"] is True
            assert "verdict" in result
            assert "harmless_votes" in result
            assert result["harmless_votes"] >= 50

    def test_03_vt_hash_lookup_controlled(self):
        """Verify VirusTotal hash lookup detection of EICAR using controlled fixture."""
        mock_payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 64, "suspicious": 0, "harmless": 0, "undetected": 5},
                    "type_description": "DOS executable",
                    "names": ["eicar.com", "eicar.com.txt"]
                }
            }
        }
        with patch.object(threat_intel, "_vt_get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_payload
            mock_get.return_value = mock_resp

            eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            result = threat_intel.check_vt_hash(eicar_sha256)
            assert result["status"] == "success"
            assert result["checked"] is True
            assert result["verdict"] == "malicious"
            assert result["malicious_votes"] >= 50

    def test_04_vt_url_lookup_controlled(self):
        """Verify VirusTotal URL lookup parsing using controlled fixture."""
        mock_payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 10}
                }
            }
        }
        with patch.object(threat_intel, "_vt_get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_payload
            mock_get.return_value = mock_resp

            result = threat_intel.check_vt_url("https://www.google.com")
            assert result["status"] in ["success", "not_found"]
            assert result["checked"] is True


class TestPhase6CLiveThreatIntel:

    # ---------------- 1. Live VirusTotal Lookups ----------------
    def test_01_live_vt_domain_lookup(self):
        """Verify live VirusTotal domain lookup returns expected structure and valid analysis stats."""
        if not Config.VIRUSTOTAL_API_KEY:
            pytest.skip("VIRUSTOTAL_API_KEY not configured")
        
        result = threat_intel.check_vt_domain("google.com")
        if result.get("status") == "rate_limited":
            pytest.skip(f"Live VirusTotal free tier public quota exceeded (HTTP 429): {result.get('message')}")
        assert result["status"] == "success"
        assert result["checked"] is True
        assert "verdict" in result
        assert "malicious_votes" in result
        assert "categories" in result

    def test_02_live_vt_ip_lookup(self):
        """Verify live VirusTotal IP lookup queries /api/v3/ip_addresses/{ip}."""
        if not Config.VIRUSTOTAL_API_KEY:
            pytest.skip("VIRUSTOTAL_API_KEY not configured")
        
        result = threat_intel.check_vt_ip("8.8.8.8")
        if result.get("status") == "rate_limited":
            pytest.skip(f"Live VirusTotal free tier public quota exceeded (HTTP 429): {result.get('message')}")
        assert result["status"] == "success"
        assert result["checked"] is True
        assert "verdict" in result
        assert "harmless_votes" in result
        assert result["harmless_votes"] >= 50

    def test_03_live_vt_hash_lookup(self):
        """Verify live VirusTotal hash lookup correctly identifies known EICAR test file."""
        if not Config.VIRUSTOTAL_API_KEY:
            pytest.skip("VIRUSTOTAL_API_KEY not configured")
        
        # Standard EICAR test string SHA-256
        eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        result = threat_intel.check_vt_hash(eicar_sha256)
        if result.get("status") == "rate_limited":
            pytest.skip(f"Live VirusTotal free tier public quota exceeded (HTTP 429): {result.get('message')}")
        assert result["status"] == "success"
        assert result["checked"] is True
        assert result["verdict"] == "malicious"
        assert result["malicious_votes"] >= 50

    def test_04_live_vt_url_lookup(self):
        """Verify live VirusTotal URL lookup generates base64 identifier and queries API."""
        if not Config.VIRUSTOTAL_API_KEY:
            pytest.skip("VIRUSTOTAL_API_KEY not configured")
        
        result = threat_intel.check_vt_url("https://www.google.com")
        if result.get("status") == "rate_limited":
            pytest.skip(f"Live VirusTotal free tier public quota exceeded (HTTP 429): {result.get('message')}")
        # Should return success or not_found, but not an unhandled error
        assert result["status"] in ["success", "not_found"]
        assert result["checked"] is True

    # ---------------- 2. Live AbuseIPDB Lookups ----------------
    def test_05_live_abuseipdb_ip_lookup(self):
        """Verify live AbuseIPDB IP reputation lookup returns confidence score, ISP, and country."""
        if not Config.ABUSEIPDB_API_KEY:
            pytest.skip("ABUSEIPDB_API_KEY not configured")
        
        result = threat_intel.check_abuseipdb("1.1.1.1")
        assert result["status"] == "success"
        assert result["checked"] is True
        assert "abuse_confidence_score" in result
        assert "country_code" in result
        assert "isp" in result
        assert result["verdict"] in ["clean", "suspicious", "malicious"]

    def test_06_abuseipdb_pre_validation_rejects_non_ips(self):
        """Verify AbuseIPDB client rejects domain names, URLs, and malformed strings before sending request."""
        invalid_inputs = [
            "evil-phishing-domain.com",
            "https://1.1.1.1/malicious.exe",
            "999.999.999.999",
            "not-an-ip-address",
            ""
        ]
        for item in invalid_inputs:
            res = threat_intel.check_abuseipdb(item)
            assert res["status"] == "invalid_ip"
            assert res["checked"] is False
            assert "is not a valid IPv4 or IPv6 address" in res["message"]

    def test_07_virustotal_ip_pre_validation_rejects_non_ips(self):
        """Verify VirusTotal IP lookup rejects non-IP addresses before dispatch."""
        res = threat_intel.check_vt_ip("malicious-subdomain.victim.com")
        assert res["status"] == "invalid_ip"
        assert res["checked"] is False
        assert "is not a valid IPv4 or IPv6 address" in res["message"]

    # ---------------- 3. Error Handling and Health States ----------------
    def test_08_unconfigured_mode(self):
        """Verify ThreatIntelClient operates gracefully in degraded mode when keys are absent."""
        client = ThreatIntelClient()
        client.vt_api_key = None
        client.abuseipdb_api_key = None

        res_hash = client.check_vt_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert res_hash["status"] == "not_configured"
        assert res_hash["checked"] is False
        assert res_hash["verdict"] == "unknown"  # NEVER claim clean when unconfigured

        res_ip = client.check_abuseipdb("8.8.8.8")
        assert res_ip["status"] == "not_configured"
        assert res_ip["checked"] is False
        assert res_ip["verdict"] == "unknown"

    def test_09_http_401_403_auth_failure(self):
        """Verify HTTP 401/403 triggers invalid_api_key status and records auth_failed health."""
        client = ThreatIntelClient()
        client.vt_api_key = "invalid_dummy_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("requests.get", return_value=mock_resp):
            res = client.check_vt_domain("example.com")
            assert res["status"] == "invalid_api_key"
            assert res["checked"] is False
            assert client.get_provider_status("virustotal")["status"] == "auth_failed"

    def test_10_http_429_rate_limiting(self):
        """Verify HTTP 429 triggers rate_limited status and records rate_limited health."""
        client = ThreatIntelClient()
        client.vt_api_key = "valid_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        with patch("requests.get", return_value=mock_resp):
            res = client.check_vt_hash("some_hash")
            assert res["status"] == "rate_limited"
            assert res["checked"] is False
            assert client.get_provider_status("virustotal")["status"] == "rate_limited"

    def test_11_http_404_not_found(self):
        """Verify HTTP 404 indicates hash/domain not seen in database without error."""
        client = ThreatIntelClient()
        client.vt_api_key = "valid_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("requests.get", return_value=mock_resp):
            res = client.check_vt_hash("unseen_hash")
            assert res["status"] == "not_found"
            assert res["checked"] is True
            assert res["verdict"] == "unknown"  # Must not claim clean

    def test_12_request_timeout(self):
        """Verify network timeout returns timeout status and records unavailable health."""
        client = ThreatIntelClient()
        client.abuseipdb_api_key = "valid_key"

        with patch("requests.get", side_effect=requests.exceptions.Timeout):
            res = client.check_abuseipdb("1.1.1.1")
            assert res["status"] == "timeout"
            assert res["checked"] is False
            assert client.get_provider_status("abuseipdb")["status"] == "unavailable"

    # ---------------- 4. Zero Secret Leakage Protection ----------------
    def test_13_no_api_keys_leaked_in_dashboard_endpoints(self, app_client):
        """Verify that VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY never appear in API responses."""
        keys_to_check = []
        if Config.VIRUSTOTAL_API_KEY:
            keys_to_check.append(Config.VIRUSTOTAL_API_KEY)
        if Config.ABUSEIPDB_API_KEY:
            keys_to_check.append(Config.ABUSEIPDB_API_KEY)

        endpoints = [
            "/api/dashboard/stats",
            "/api/dashboard/integrations",
            "/api/health"
        ]

        for ep in endpoints:
            resp = app_client.get(ep)
            assert resp.status_code == 200
            resp_text = resp.get_data(as_text=True)
            for secret in keys_to_check:
                assert secret not in resp_text, f"Secret leaked in endpoint {ep}!"

    def test_14_no_api_keys_in_provider_status(self):
        """Verify get_provider_status dictionary never exposes raw keys."""
        for provider in ["virustotal", "abuseipdb", "urlscan"]:
            status_dict = threat_intel.get_provider_status(provider)
            status_str = str(status_dict)
            if Config.VIRUSTOTAL_API_KEY:
                assert Config.VIRUSTOTAL_API_KEY not in status_str
            if Config.ABUSEIPDB_API_KEY:
                assert Config.ABUSEIPDB_API_KEY not in status_str

    # ---------------- 5. Threat Intel Correlation & Schema ----------------
    def test_15_ioc_extractor_threat_intel_enrichment(self):
        """Verify extract_all_iocs attaches provider, confidence, api_status, and lookup_timestamp."""
        context = {
            "sender_domain": "suspicious-invoice.com",
            "originating_ip": "185.220.101.5",
            "domain_intel": {
                "domain_reputation": "malicious",
                "ip_reputation": "malicious",
                "ip_abuse_score": 95
            },
            "urls": [
                {
                    "original_url": "http://suspicious-invoice.com/pay.exe",
                    "domain": "suspicious-invoice.com",
                    "vt_reputation": "malicious",
                    "detection_flags": ["executable_download"]
                }
            ],
            "attachments": [
                {
                    "filename": "invoice_malware.exe",
                    "detected_mime": "application/x-dosexec",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "vt_reputation": "malicious",
                    "has_macro": False,
                    "is_dangerous_extension": True
                }
            ]
        }

        iocs = ioc_extractor.extract_all_iocs(context)
        assert len(iocs) > 0

        # Check domain IOC
        dom_iocs = [i for i in iocs if i["ioc_type"] == "domain"]
        assert len(dom_iocs) >= 1
        assert dom_iocs[0]["provider"] == "virustotal"
        assert dom_iocs[0]["api_status"] == "success"
        assert dom_iocs[0]["lookup_timestamp"] != ""

        # Check IP IOC
        ip_iocs = [i for i in iocs if i["ioc_type"] == "ipv4"]
        assert len(ip_iocs) >= 1
        assert ip_iocs[0]["provider"] == "abuseipdb"
        assert ip_iocs[0]["confidence"] == 95
        assert ip_iocs[0]["api_status"] == "success"

        # Check SHA256 IOC
        hash_iocs = [i for i in iocs if i["ioc_type"] == "sha256"]
        assert len(hash_iocs) >= 1
        assert hash_iocs[0]["provider"] == "virustotal"
        assert hash_iocs[0]["confidence"] == 90
        assert hash_iocs[0]["reputation"] == "malicious"

    def test_16_ioc_csv_export_format(self):
        """Verify export_csv includes Provider, Confidence, API Status, and Lookup Timestamp headers."""
        sample_iocs = [
            {
                "ioc_type": "ipv4",
                "ioc_value": "185.220.101.5",
                "defanged_value": "185[.]220[.]101[.]5",
                "reputation": "malicious",
                "context": "Originating IP",
                "provider": "abuseipdb",
                "confidence": 98,
                "api_status": "success",
                "lookup_timestamp": "2026-11-06T08:00:00Z"
            }
        ]
        csv_out = ioc_extractor.export_csv(sample_iocs)
        assert "Provider" in csv_out
        assert "Confidence" in csv_out
        assert "API Status" in csv_out
        assert "Lookup Timestamp" in csv_out
        assert "abuseipdb" in csv_out
        assert "98" in csv_out

    # ---------------- 6. Anti-Double Counting Category Capping ----------------
    def test_17_category_capping_prevents_runaway_scoring(self):
        """Verify that combining multiple external intelligence flags respects category caps."""
        scoring = RiskScoringEngine()
        
        # Identity category hits: multiple severe flags
        domain_intel = {
            "domain": "phish-bank.com",
            "ip_abuse_score": 100,      # triggers INTEL_ABUSEIPDB_HIGH (+20)
            "domain_reputation": "malicious", # triggers INTEL_DOMAIN_MALICIOUS (+25)
            "has_mx": False             # triggers DOMAIN_NO_MX_RECORDS (+10)
        }
        # Raw identity total = 20 + 25 + 10 = 55
        # Identity cap is 35
        
        result = scoring.calculate_risk(rule_hits=[], domain_intel=domain_intel, auth_info={})
        breakdown = result["category_breakdown"]
        
        assert breakdown["identity"] == 35, f"Expected capped identity score of 35, got {breakdown['identity']}"
        assert result["overall_score"] == 35
        assert result["risk_category"] == "Medium"

