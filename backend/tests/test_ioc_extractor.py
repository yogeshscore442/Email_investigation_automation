import pytest
from app.modules.ioc_extractor import ioc_extractor
from app.utils.defanger import defang_url, defang_ip, defang_domain, defang_email

def test_defangers():
    assert defang_url("https://malicious.com/path") == "hxxps://malicious[.]com/path"
    assert defang_ip("192.168.1.50") == "192[.]168[.]1[.]50"
    assert defang_domain("phishing-bank.com") == "phishing-bank[.]com"
    assert defang_email("hacker@evil.com") == "hacker[@]evil[.]com"

def test_ioc_extraction_and_export():
    ctx = {
        "sender_email": "attacker@evil.com",
        "sender_domain": "evil.com",
        "reply_email": "divert@redirect.org",
        "originating_ip": "185.220.101.5",
        "plain_body": "Contact us at support@evil.com or visit http://evil.com/login",
        "hops": [{"hop_number": 1, "ip_address": "194.26.29.80", "by_server": "mx.corp.com"}],
        "domain_intel": {"domain_reputation": "suspicious", "ip_reputation": "malicious"},
        "urls": [{"original_url": "http://evil.com/login", "domain": "evil.com", "vt_reputation": "malicious"}],
        "attachments": [{"filename": "payload.docm", "sha256": "abcdef123456", "md5": "0123456789abcdef", "has_macro": True}]
    }

    iocs = ioc_extractor.extract_all_iocs(ctx)
    ioc_types = {i["ioc_type"] for i in iocs}

    assert "email" in ioc_types
    assert "domain" in ioc_types
    assert "ipv4" in ioc_types
    assert "url" in ioc_types
    assert "filename" in ioc_types
    assert "sha256" in ioc_types

    # Test export CSV and JSON
    csv_out = ioc_extractor.export_csv(iocs)
    assert "IOC Type,IOC Value (Raw)" in csv_out
    assert "185[.]220[.]101[.]5" in csv_out

    json_out = ioc_extractor.export_json(iocs)
    assert "defanged_value" in json_out

