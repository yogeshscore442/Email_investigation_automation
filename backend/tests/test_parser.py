import pytest
from pathlib import Path
from app.modules.parser import email_parser

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "data" / "samples"

def test_parse_legitimate_eml():
    eml_file = SAMPLES_DIR / "legitimate_newsletter.eml"
    with open(eml_file, "rb") as f:
        data = email_parser.parse_eml_bytes(f.read(), "legitimate_newsletter.eml")

    assert "Tech Updates Weekly" in data["subject"]
    assert "techupdates.com" in data["sender"]
    assert len(data["headers"]) > 5
    assert "https://techupdates.com/articles/cloud-security-2026" in data["body_html"]

def test_parse_macro_attachment_eml():
    eml_file = SAMPLES_DIR / "macro_invoice_phishing.eml"
    with open(eml_file, "rb") as f:
        data = email_parser.parse_eml_bytes(f.read(), "macro_invoice_phishing.eml")

    assert len(data["attachments"]) == 1
    att = data["attachments"][0]
    assert att["filename"] == "Overdue_Invoice_INV9812.docm"
    assert att["sha256"] != ""
    assert att["md5"] != ""
    assert att["file_size"] > 0

def test_parse_raw_text():
    raw_headers = "From: attacker@evil.com\nTo: victim@target.com\nSubject: Test Alert\nMessage-ID: <1234@evil.com>\n"
    raw_body = "Please visit http://evil.com/login to verify your password."
    data = email_parser.parse_raw_text(raw_headers, raw_body)

    assert data["subject"] == "Test Alert"
    assert data["sender"] == "attacker@evil.com"
    assert "http://evil.com/login" in data["body_plain"]

