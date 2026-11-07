import pytest
from app.modules.rules_engine import rules_engine
from app.modules.scoring import risk_scoring

def test_phishing_rules_and_scoring():
    ctx = {
        "subject": "URGENT: Your account password has expired",
        "body_plain": "Please verify your account and credentials immediately within 24 hours.",
        "headers_info": {
            "from_name": "Microsoft Support",
            "from_email": "security@attacker-host.xyz",
            "from_domain": "attacker-host.xyz",
            "sender_reply_mismatch": True,
            "mismatch_details": "From and Reply-To mismatch"
        },
        "auth": {
            "spf_status": "fail",
            "dmarc_status": "fail"
        },
        "hops": [],
        "domain_intel": {
            "domain": "attacker-host.xyz",
            "is_lookalike": True,
            "targeted_brand": "microsoft",
            "similarity_score": 0.85,
            "has_mx": False
        },
        "urls": [
            {
                "defanged_url": "hxxp://185[.]220[.]101[.]5/login",
                "detection_flags": [{"type": "IP_BASED_URL", "severity": "high", "message": "Host is IP"}]
            }
        ],
        "attachments": [],
        "sanitizer_res": {}
    }

    hits = rules_engine.evaluate_all(ctx)
    rule_ids = {h["rule_id"] for h in hits}

    assert "RULE_AUTH_DMARC_FAIL" in rule_ids
    assert "RULE_AUTH_SPF_FAIL" in rule_ids
    assert "RULE_SENDER_REPLYTO_MISMATCH" in rule_ids
    assert "RULE_LOOKALIKE_DOMAIN" in rule_ids
    assert "RULE_MALICIOUS_URL_DETECTED" in rule_ids

    # Test scoring
    score_res = risk_scoring.calculate_risk(hits, ctx["domain_intel"], ctx["auth"])
    assert score_res["overall_score"] >= 60
    assert score_res["risk_category"] in ["High", "Critical"]
    assert score_res["verdict"] in ["Phishing", "Critical Phishing / Malware"]
    assert len(score_res["factors"]) > 0

