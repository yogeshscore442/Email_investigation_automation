import pytest
from app.modules.headers import header_analyzer

def test_spf_dkim_dmarc_parsing():
    headers = [
        {"name": "From", "value": "support@paypal-security.com"},
        {"name": "Reply-To", "value": "hacker@freemail.ru"},
        {"name": "Return-Path", "value": "<bounce@another-domain.com>"},
        {"name": "Authentication-Results", "value": "mx.google.com; spf=fail (domain does not designate sender); dkim=pass; dmarc=fail (p=REJECT)"},
        {"name": "Received", "value": "from relay.phish.com ([198.51.100.99]) by mx.google.com with ESMTP id hop2; Thu, 05 Nov 2026 10:05:00 -0500"},
        {"name": "Received", "value": "from internal.node ([10.0.0.1]) by relay.phish.com with SMTP id hop1; Thu, 05 Nov 2026 10:00:00 -0500"},
        {"name": "Message-ID", "value": "<bad-msg-123@paypal-security.com>"},
        {"name": "Date", "value": "Thu, 05 Nov 2026 10:00:00 -0500"}
    ]

    res = header_analyzer.analyze_headers(headers)
    assert res["from_domain"] == "paypal-security.com"
    assert res["reply_domain"] == "freemail.ru"
    assert res["sender_reply_mismatch"] is True
    assert res["auth"]["spf_status"] == "fail"
    assert res["auth"]["dkim_status"] == "pass"
    assert res["auth"]["dmarc_status"] == "fail"
    assert len(res["hops"]) == 2
    # Verify transit delay was calculated
    assert res["hops"][1]["delay_seconds"] == 300
