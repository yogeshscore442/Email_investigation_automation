"""
Test Suite: Navigation Pages & API Integration Contracts
Specifically verifies endpoints supporting:
1. Incidents & SIEM (/api/incidents, /api/incidents/stats, /api/incidents/correlate, /api/siem/status)
2. Attack Sim & Detections (/api/phase5/status, /api/phase5/rules, /api/phase5/results, /api/phase5/timeline, /api/phase5/run/<id>)
3. Authentication flow (/api/auth/login, /api/auth/me)
"""

import os
import json
import pytest
from app import create_app
from app.models import db, User, Incident, Investigation

@pytest.fixture
def app_instance():
    app = create_app()
    app.config["TESTING"] = True
    yield app

@pytest.fixture
def client(app_instance):
    return app_instance.test_client()

@pytest.fixture
def analyst_token(app_instance, client):
    """Provides a valid analyst JWT token."""
    with app_instance.app_context():
        user = User.query.filter_by(username="analyst").first()
        if not user:
            user = User(username="analyst", email="analyst@soc.corp", role="analyst")
            user.set_password("AnalystPassword2026!Secure")
            db.session.add(user)
            db.session.commit()
    
    r = client.post("/api/auth/login", json={
        "username": "analyst",
        "password": "AnalystPassword2026!Secure"
    })
    assert r.status_code == 200, f"Login failed: {r.get_json()}"
    return r.get_json()["token"]

def test_auth_login_and_profile(client, analyst_token):
    """Verifies that authentication succeeds and issued JWT retrieves user profile."""
    assert analyst_token and len(analyst_token) > 20
    
    # Check /api/auth/me with Bearer token
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {analyst_token}"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "success"
    assert data["user"]["username"] == "analyst"
    assert data["user"]["role"] == "analyst"

def test_incidents_page_endpoints(client, analyst_token):
    """Verifies all API endpoints required by Incidents & SIEM dashboard."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1. GET /api/incidents/stats
    r_stats = client.get("/api/incidents/stats", headers=headers)
    assert r_stats.status_code == 200
    stats = r_stats.get_json()
    assert "total_incidents" in stats
    assert "critical_count" in stats
    assert "siem_status" in stats
    assert "splunk" in stats["siem_status"]
    assert "wazuh" in stats["siem_status"]

    # 2. GET /api/incidents
    r_inc = client.get("/api/incidents", headers=headers)
    assert r_inc.status_code == 200
    assert isinstance(r_inc.get_json(), list)

    # 3. GET /api/siem/status
    r_siem = client.get("/api/siem/status", headers=headers)
    assert r_siem.status_code == 200
    siem = r_siem.get_json()
    assert "splunk" in siem
    assert "wazuh" in siem

    # 4. POST /api/incidents/correlate
    r_corr = client.post("/api/incidents/correlate", headers=headers)
    assert r_corr.status_code == 200
    corr = r_corr.get_json()
    assert "status" in corr

def test_attack_sim_page_endpoints(client, analyst_token):
    """Verifies all API endpoints required by Attack Sim & Detections dashboard."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1. GET /api/phase5/status
    r_stat = client.get("/api/phase5/status", headers=headers)
    assert r_stat.status_code == 200
    status_data = r_stat.get_json()
    assert status_data.get("status") == "operational"
    assert len(status_data.get("simulations", [])) == 8
    assert status_data.get("detection_rules_count") == 6

    # 2. GET /api/phase5/rules
    r_rules = client.get("/api/phase5/rules", headers=headers)
    assert r_rules.status_code == 200
    rules_data = r_rules.get_json()
    assert rules_data.get("total_rules") == 6
    assert len(rules_data.get("rules", [])) == 6

    # 3. GET /api/phase5/results
    r_res = client.get("/api/phase5/results", headers=headers)
    assert r_res.status_code == 200
    results_data = r_res.get_json()
    assert "simulations" in results_data
    assert "detections" in results_data

    # 4. GET /api/phase5/timeline
    r_time = client.get("/api/phase5/timeline", headers=headers)
    assert r_time.status_code == 200
    time_data = r_time.get_json()
    assert "timeline" in time_data
    assert "is_chronological" in time_data
    assert time_data["is_chronological"] is True

def test_single_simulation_dispatch_contract(client, analyst_token):
    """Verifies executing a safe simulation endpoint without raising 500."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    
    # Test invalid simulation ID validation
    r_bad = client.post("/api/phase5/run/INVALID-99", headers=headers)
    assert r_bad.status_code == 400
    assert "Invalid simulation ID" in r_bad.get_json().get("error", "")

    # Test valid simulation ID PS-04 (File creation in dedicated sandbox directory)
    r_sim = client.post("/api/phase5/run/PS-04", headers=headers)
    assert r_sim.status_code == 200
    data = r_sim.get_json()
    assert data.get("status") in ["success", "completed"]
    assert "result" in data

