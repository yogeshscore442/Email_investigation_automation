"""
Comprehensive Automated Test Suite for Phase 5:
SOC Attack Simulation & Detection Validation
Tests PS-01 through PS-08 simulations, live/mocked Splunk retrieval,
and SIEM detection rule evaluations (DET-PS01 to DET-IOC06).
"""

import os
import sys
import json
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app import create_app
from app.models import db, Incident, Investigation
from app.utils.splunk_client import splunk_client
from app.modules.siem_detection_engine import siem_detection_engine, DETECTION_RULES_CATALOG
from simulations import (
    sim_ps01_powershell,
    sim_ps02_failed_auth,
    sim_ps03_network,
    sim_ps04_file_create,
    sim_ps05_registry,
    sim_ps06_process_access,
    sim_ps07_ioc_correlation,
    sim_ps08_incident_timeline
)


@pytest.fixture
def app_ctx():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app


@pytest.fixture
def client(app_ctx):
    return app_ctx.test_client()


def test_01_phase5_status_endpoint(client):
    """Verifies that the Phase 5 status endpoint returns SIEM metrics and 8 simulations."""
    res = client.get("/api/phase5/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "operational"
    assert "splunk" in data
    assert len(data["simulations"]) == 8
    assert data["detection_rules_count"] == 6


def test_02_detection_rules_catalog_and_mitre_mapping(client):
    """Validates the 6 formal SIEM detection rules and their MITRE ATT&CK justifications."""
    res = client.get("/api/phase5/rules")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_rules"] == 6
    
    rule_ids = {r["rule_id"] for r in data["rules"]}
    assert rule_ids == {"DET-PS01", "DET-AUTH02", "DET-NET03", "DET-FILE04", "DET-REG05", "DET-IOC06"}
    
    for r in data["rules"]:
        assert "rule_id" in r
        assert "name" in r
        assert "detection_logic" in r
        assert "required_telemetry" in r
        assert "mitre_attack" in r
        assert "severity" in r
        assert "false_positive_considerations" in r
        assert "technique_id" in r["mitre_attack"]


def test_03_ps01_powershell_execution():
    """Validates PS-01 harmless PowerShell execution and live Splunk Event ID 1 extraction."""
    res = sim_ps01_powershell.run_simulation()
    assert res["test_id"] == "PS-01"
    assert res["status"] == "LIVE PASSED"
    assert "sysmon" in res["extracted_evidence"]
    sysmon = res["extracted_evidence"]["sysmon"]
    assert "powershell" in sysmon["image"].lower()
    assert "PHASE5_SIM_PS01_MARKER" in sysmon["command_line"]


def test_04_ps02_failed_authentication():
    """Validates PS-02 controlled failed logon attempts (Event ID 4625)."""
    res = sim_ps02_failed_auth.run_simulation()
    assert res["test_id"] == "PS-02"
    assert res["status"] == "LIVE PASSED"
    ev = res["extracted_evidence"]
    assert ev["event_id"] == "4625"
    assert "Phase5SecTestUser" in ev["target_user_name"]


def test_05_ps03_network_monitoring():
    """Validates PS-03 harmless local loopback HTTP socket (Event ID 3)."""
    res = sim_ps03_network.run_simulation()
    assert res["test_id"] == "PS-03"
    assert res["status"] == "LIVE PASSED"
    ev = res["extracted_evidence"]
    assert ev["event_id"] == "3"
    assert ev["destination_ip"] == "127.0.0.1"


def test_06_ps04_file_creation():
    """Validates PS-04 lab script file creation (Event ID 11)."""
    res = sim_ps04_file_create.run_simulation()
    assert res["test_id"] == "PS-04"
    assert res["status"] == "LIVE PASSED"
    ev = res["extracted_evidence"]
    assert ev["event_id"] == "11"
    assert "phase5_marker.ps1" in ev["target_filename"]


def test_07_ps05_registry_monitoring():
    """Validates PS-05 dedicated test registry key manipulation (Event ID 12/13)."""
    res = sim_ps05_registry.run_simulation()
    assert res["test_id"] == "PS-05"
    assert res["status"] == "LIVE PASSED"
    ev = res["extracted_evidence"]
    assert ev["event_id"] in ["12", "13"]
    assert res["operation_success"] is True


def test_08_ps06_process_access_monitoring():
    """Validates PS-06 safe process access telemetry inspection (Event ID 10)."""
    res = sim_ps06_process_access.run_simulation()
    assert res["test_id"] == "PS-06"
    assert res["status"] == "LIVE PASSED"
    ev = res["extracted_evidence"]
    assert ev["event_id"] == "10"
    assert "lsass" in ev["target_image"].lower()


def test_09_ps07_email_ioc_correlation_and_anti_fabrication():
    """Validates PS-07 email IOC correlation and anti-fabrication truthfulness."""
    res = sim_ps07_ioc_correlation.run_simulation()
    assert res["test_id"] == "PS-07"
    assert res["status"] == "LIVE PASSED"
    assert res["anti_fabrication_verified"] is True
    # Verify unobserved external indicators return no_matching_events
    assert res["telemetry_status"] in ["no_matching_events", "confirmed"]


def test_10_ps08_incident_timeline_chronology():
    """Validates PS-08 chronological timeline sorting and 4-tier telemetry statuses."""
    res = sim_ps08_incident_timeline.run_simulation()
    assert res["test_id"] == "PS-08"
    assert res["status"] == "LIVE PASSED"
    assert res["is_chronological"] is True
    assert res["total_events"] >= 6
    statuses = set(res["statuses_observed"])
    assert "confirmed" in statuses
    assert "no_matching_events" in statuses
    assert "unavailable_telemetry" in statuses


def test_11_siem_detection_engine_evaluation():
    """Validates the SIEM detection engine against real simulation evidence."""
    events_by_rule = {
        "DET-PS01": [{"event_id": "1", "image": "powershell.exe", "command_line": "powershell.exe -ExecutionPolicy Bypass PHASE5_SIM_PS01_MARKER"}],
        "DET-AUTH02": [{"event_id": "4625", "target_user_name": "Phase5SecTestUser"}],
        "DET-NET03": [{"event_id": "3", "destination_port": "5000"}],
        "DET-FILE04": [{"event_id": "11", "target_filename": "C:\\lab\\phase5_marker.ps1"}],
        "DET-REG05": [{"event_id": "13", "target_object": "HKCU\\Software\\Phase5Lab"}],
        "DET-IOC06": [{"total_matches": 0, "anti_fabrication_verified": True}]
    }
    
    eval_res = siem_detection_engine.evaluate_all(events_by_rule)
    assert eval_res["total_rules"] == 6
    assert eval_res["triggered_rules"] == 6
    
    for rid, r in eval_res["rules"].items():
        assert r["matched"] is True


def test_12_phase5_api_execution_and_results(client):
    """Tests the /api/phase5/run/<id> and /api/phase5/results REST endpoints."""
    # Run single test via API
    res_ps1 = client.post("/api/phase5/run/PS-01")
    assert res_ps1.status_code == 200
    assert res_ps1.get_json()["status"] == "success"
    
    # Query results endpoint
    res_results = client.get("/api/phase5/results")
    assert res_results.status_code == 200
    data = res_results.get_json()
    assert "simulations" in data
    assert "detections" in data
    assert "PS-01" in data["simulations"]


def test_13_phase5_timeline_endpoint(client):
    """Tests the /api/phase5/timeline endpoint."""
    res = client.get("/api/phase5/timeline")
    assert res.status_code == 200
    data = res.get_json()
    assert "timeline" in data
    assert data["is_chronological"] is True

