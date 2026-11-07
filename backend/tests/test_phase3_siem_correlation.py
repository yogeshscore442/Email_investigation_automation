import json
import pytest
from unittest.mock import patch, MagicMock
from app import create_app
from app.models import db, Investigation, ExtractedIOC, Incident, IncidentTimelineEvent, PlaybookAction
from app.modules.correlation_engine import correlation_engine
from app.utils.splunk_client import splunk_client
from app.utils.wazuh_client import wazuh_client

@pytest.fixture
def app_ctx():
    app = create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.app_context():
        db.create_all()
        yield app

@pytest.fixture
def client(app_ctx):
    return app_ctx.test_client()

# ============================================================================
# 1. MODULE 1: IOC CORRELATION & CAMPAIGN CLUSTERING
# ============================================================================

def test_ioc_correlation_and_campaign_clustering(app_ctx):
    """
    Module 1: Cross-investigation IOC correlation.
    Verifies that multiple emails sharing malicious domains or URLs are clustered
    into a unified targeted campaign.
    """
    # Create two related investigations targeting two employees
    inv1 = Investigation(
        subject="URGENT: Microsoft 365 Password Expiration",
        sender="Microsoft Security <admin@office365-security-alert.xyz>",
        sender_domain="office365-security-alert.xyz",
        recipient="victim.analyst@cyberdefensecorp.internal",
        verdict="Critical Phishing / Malware",
        overall_risk_score=95,
        risk_category="Critical"
    )
    inv2 = Investigation(
        subject="URGENT: Microsoft 365 Password Expiration",
        sender="Microsoft Security <admin@office365-security-alert.xyz>",
        sender_domain="office365-security-alert.xyz",
        recipient="finance.controller@cyberdefensecorp.internal",
        verdict="Critical Phishing / Malware",
        overall_risk_score=95,
        risk_category="Critical"
    )
    db.session.add_all([inv1, inv2])
    db.session.commit()

    # Add shared URLs
    from app.models import EmailUrl
    u1 = EmailUrl(investigation_id=inv1.id, original_url="http://185.220.101.5/login.php", defanged_url="hxxp://185[.]220[.]101[.]5/login.php", domain="185.220.101.5", vt_reputation="malicious")
    u2 = EmailUrl(investigation_id=inv2.id, original_url="http://185.220.101.5/login.php", defanged_url="hxxp://185[.]220[.]101[.]5/login.php", domain="185.220.101.5", vt_reputation="malicious")
    db.session.add_all([u1, u2])
    db.session.commit()

    # Run correlation pass
    res = correlation_engine.run_correlation()
    assert res["status"] == "success"
    assert res["total_incidents"] >= 1

    # Verify correlated incident for inv1
    incident = inv1.incidents.first()
    assert incident is not None
    assert incident.severity == "Critical"
    assert "Multi-User" in incident.campaign_name or "Campaign" in incident.campaign_name
    
    # Assert both targeted corporate users are identified
    users = json.loads(incident.affected_users_json)
    assert "victim.analyst@cyberdefensecorp.internal" in users
    assert "finance.controller@cyberdefensecorp.internal" in users

    # Assert investigations are linked
    assert inv1 in incident.investigations
    assert inv2 in incident.investigations
    assert len(incident.investigations) >= 2

# ============================================================================
# 2. MODULE 2: SPLUNK SIEM INTEGRATION
# ============================================================================

def test_splunk_degraded_when_unconfigured():
    """Verify Splunk enters degraded mode without simulating false events."""
    orig_host = splunk_client.host
    try:
        splunk_client.host = ""
        status = splunk_client.get_service_status()
        assert status["status"] == "not_configured"
        assert status["mode"] == "degraded"

        res = splunk_client.execute_search("index=main")
        assert res["status"] == "not_configured"
        assert res["checked"] is False
        assert res["events_count"] == 0
    finally:
        splunk_client.host = orig_host

def test_splunk_mocked_search_execution():
    """Validate Splunk search query parsing and event extraction."""
    orig_host = splunk_client.host
    orig_token = splunk_client.token
    try:
        splunk_client.host = "splunk.corp.internal"
        splunk_client.token = "mock-splunk-bearer-token"

        mock_ndjson_resp = (
            '{"result":{"_time":"2026-11-05T11:22:05Z","sourcetype":"cisco:esa","sender":"admin@office365-security-alert.xyz","recipient":"analyst@target.internal","action":"delivered"}}\n'
            '{"result":{"_time":"2026-11-05T11:22:15Z","sourcetype":"squid:access","dest_ip":"185.220.101.5","http_status":"200","url":"http://185.220.101.5/login.php"}}\n'
        )

        with patch("requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = mock_ndjson_resp
            mock_post.return_value = mock_resp

            res = splunk_client.execute_search('index=main sourcetype="cisco:esa"')
            assert res["status"] == "success"
            assert res["checked"] is True
            assert res["events_count"] == 2
            assert res["events"][0]["sourcetype"] == "cisco:esa"
            assert res["events"][1]["dest_ip"] == "185.220.101.5"
    finally:
        splunk_client.host = orig_host
        splunk_client.token = orig_token

def test_splunk_error_handling_and_auth_failure():
    """Validate Splunk 401 auth failure and 429 rate limit handling."""
    orig_host = splunk_client.host
    orig_token = splunk_client.token
    try:
        splunk_client.host = "splunk.corp.internal"
        splunk_client.token = "invalid-token"

        # HTTP 401
        with patch("requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_post.return_value = mock_resp

            res = splunk_client.execute_search("index=main")
            assert res["status"] == "auth_failed"
            assert res["checked"] is False

        # HTTP 429
        with patch("requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_post.return_value = mock_resp

            res = splunk_client.execute_search("index=main")
            assert res["status"] == "rate_limited"
            assert res["checked"] is False
    finally:
        splunk_client.host = orig_host
        splunk_client.token = orig_token

# ============================================================================
# 3. MODULE 3: WAZUH EDR & SIEM INTEGRATION
# ============================================================================

def test_wazuh_degraded_when_unconfigured():
    """Verify Wazuh enters degraded mode without fabricating endpoint alerts."""
    orig_host = wazuh_client.host
    try:
        wazuh_client.host = ""
        status = wazuh_client.get_service_status()
        assert status["status"] == "not_configured"
        assert status["mode"] == "degraded"

        res = wazuh_client.search_alerts()
        assert res["status"] == "not_configured"
        assert res["checked"] is False
        assert res["alerts_count"] == 0
    finally:
        wazuh_client.host = orig_host

def test_wazuh_mocked_alert_retrieval_and_agent_mapping():
    """Validate Wazuh alerts and agent inventory mapping."""
    orig_host = wazuh_client.host
    orig_user = wazuh_client.user
    orig_pass = wazuh_client.password
    try:
        wazuh_client.host = "wazuh-manager.corp.internal"
        wazuh_client.user = "wazuh-api-user"
        wazuh_client.password = "wazuh-secret"

        mock_auth_resp = {"data": {"token": "jwt-token-12345"}}
        mock_alerts_resp = {
            "data": {
                "affected_items": [
                    {
                        "id": "alert-991",
                        "timestamp": "2026-11-05T11:25:00Z",
                        "rule": {
                            "id": "100201",
                            "description": "Suspicious PowerShell command line spawning from winword.exe",
                            "level": 12,
                            "mitre": {"id": ["T1059.001"]}
                        },
                        "agent": {
                            "id": "001",
                            "name": "WKSTN-ANALYST",
                            "ip": "10.200.4.196"
                        },
                        "full_log": "Process powershell.exe created by parent winword.exe"
                    }
                ]
            }
        }

        with patch("requests.get") as mock_get:
            # First call for auth token, second for alerts
            resp_auth = MagicMock()
            resp_auth.status_code = 200
            resp_auth.json.return_value = mock_auth_resp

            resp_alerts = MagicMock()
            resp_alerts.status_code = 200
            resp_alerts.json.return_value = mock_alerts_resp

            mock_get.side_effect = [resp_auth, resp_alerts]

            res = wazuh_client.search_alerts(query="rule.level>=10")
            assert res["status"] == "success"
            assert res["checked"] is True
            assert res["alerts_count"] == 1
            alert = res["alerts"][0]
            assert alert["agent_name"] == "WKSTN-ANALYST"
            assert alert["rule_level"] == 12
            assert "powershell" in alert["rule_description"].lower()
    finally:
        wazuh_client.host = orig_host
        wazuh_client.user = orig_user
        wazuh_client.password = orig_pass

# ============================================================================
# 4. MODULE 4: INCIDENT TIMELINE TELEMETRY ATTRIBUTION
# ============================================================================

def test_incident_timeline_distinguishes_telemetry_status(app_ctx):
    """
    Module 4: Chronological timeline construction.
    Confirms that verified email events are marked 'confirmed', while
    unconfigured proxy and EDR logs are marked 'unavailable_telemetry'.
    """
    inv = Investigation(
        subject="Confidential Wire Transfer Notice",
        sender="CEO <ceo@gmail.com>",
        sender_domain="gmail.com",
        recipient="finance.controller@cyberdefensecorp.internal",
        verdict="Suspicious",
        overall_risk_score=40,
        risk_category="Medium"
    )
    db.session.add(inv)
    db.session.commit()

    correlation_engine.run_correlation()
    incident = inv.incidents.first()
    assert incident is not None

    events = incident.timeline_events.all()
    assert len(events) >= 3

    statuses = {e.telemetry_status for e in events}
    # Must have confirmed email delivery
    assert "confirmed" in statuses
    # Must explicitly document unavailable SIEM telemetry when unconfigured
    assert "unavailable_telemetry" in statuses

    # Verify that unconfigured proxy is clearly documented
    proxy_ev = next((e for e in events if "Proxy" in e.source), None)
    assert proxy_ev is not None
    assert proxy_ev.telemetry_status == "unavailable_telemetry"
    assert "Not Observed" in proxy_ev.title or "Unconfigured" in proxy_ev.title

# ============================================================================
# 5. MODULE 6: SOC RESPONSE PLAYBOOK & ANALYST APPROVAL CONTROL
# ============================================================================

def test_playbook_approval_requirement_and_execution_guardrails(app_ctx, client):
    """
    Module 6: Response Playbook governance.
    CRITICAL SECURITY CONTROL: Destructive/disruptive actions (quarantine, domain block,
    endpoint isolation) MUST require explicit analyst approval before execution!
    """
    Incident.query.filter(Incident.title.like("%guardrail-test%")).delete()
    db.session.commit()

    inv = Investigation(
        subject="Phishing Alert",
        sender="Attacker <bad@guardrail-test-domain.xyz>",
        sender_domain="guardrail-test-domain.xyz",
        recipient="user@target.internal",
        verdict="Critical Phishing / Malware",
        overall_risk_score=90,
        risk_category="Critical"
    )
    db.session.add(inv)
    db.session.commit()

    correlation_engine.run_correlation()
    incident = inv.incidents.first()
    assert incident is not None

    actions = incident.playbook_actions.all()
    assert len(actions) >= 1
    # Pick pending action
    action = next((a for a in actions if a.approval_status == "pending_approval"), actions[0])

    # Verify initial state
    assert action.requires_approval is True
    assert action.approval_status == "pending_approval"

    # ATTEMPT 1: Execute WITHOUT approval -> MUST FAIL (403 Forbidden)
    exec_res = client.post(f"/api/incidents/{incident.id}/actions/{action.id}/execute")
    assert exec_res.status_code == 403
    assert "requires explicit analyst approval" in exec_res.get_json()["error"]

    # ATTEMPT 2: Analyst grants approval
    approve_res = client.post(
        f"/api/incidents/{incident.id}/actions/{action.id}/approve",
        json={"analyst_name": "Senior SOC Analyst"}
    )
    assert approve_res.status_code == 200
    updated_act = approve_res.get_json()["action"]
    assert updated_act["approval_status"] == "approved"
    assert updated_act["approved_by"] == "Senior SOC Analyst"

    # ATTEMPT 3: Execute AFTER approval -> MUST SUCCEED
    exec_success = client.post(f"/api/incidents/{incident.id}/actions/{action.id}/execute")
    assert exec_success.status_code == 200
    exec_data = exec_success.get_json()
    assert exec_data["status"] == "executed"
    assert exec_data["action"]["approval_status"] == "executed"

# ============================================================================
# 6. DEDUPLICATION & FALSE-POSITIVE DEFENSE
# ============================================================================

def test_clean_newsletter_does_not_create_spurious_incident(app_ctx):
    """
    Verifies that harmless newsletters (Risk Score < 30) are not
    spuriously promoted into high-severity SOC incidents.
    """
    Incident.query.filter(Incident.title.like("%legit-tech%")).delete()
    db.session.commit()

    clean_inv = Investigation(
        subject="Weekly Engineering Tech Newsletter",
        sender="Tech News <news@legit-tech.org>",
        sender_domain="legit-tech.org",
        recipient="developer@corp.internal",
        verdict="Legitimate",
        overall_risk_score=10,
        risk_category="Low"
    )
    db.session.add(clean_inv)
    db.session.commit()

    res = correlation_engine.run_correlation()
    # No malicious incident should be created for a single benign newsletter
    assert clean_inv.incidents.count() == 0
    incidents = Incident.query.all()
    assert not any("legit-tech.org" in inc.title for inc in incidents)

def test_incident_correlation_deduplication(app_ctx):
    """
    Verifies that running correlation multiple times updates existing incidents
    rather than duplicating alerts.
    """
    inv = Investigation(
        subject="Invoice Overdue",
        sender="Accounting <billing@fake-vendor.xyz>",
        sender_domain="fake-vendor.xyz",
        recipient="accounts.payable@corp.internal",
        verdict="Critical Phishing / Malware",
        overall_risk_score=85,
        risk_category="Critical"
    )
    db.session.add(inv)
    db.session.commit()

    # Pass 1
    res1 = correlation_engine.run_correlation()
    count1 = Incident.query.count()

    # Pass 2 (Idempotent run)
    res2 = correlation_engine.run_correlation()
    count2 = Incident.query.count()

    assert count1 == count2
    assert res2["incidents_created"] == 0

# ============================================================================
# 7. SIEM & INCIDENT REST API CONTRACTS
# ============================================================================

def test_incident_api_contracts(app_ctx, client):
    """Validates /api/incidents/stats and /api/siem/status endpoints."""
    stats_res = client.get("/api/incidents/stats")
    assert stats_res.status_code == 200
    stats = stats_res.get_json()
    assert "total_incidents" in stats
    assert "severity_distribution" in stats
    assert "siem_status" in stats
    assert "splunk" in stats["siem_status"]
    assert "wazuh" in stats["siem_status"]

    siem_res = client.get("/api/siem/status")
    assert siem_res.status_code == 200
    siem = siem_res.get_json()
    assert siem["splunk"]["mode"] in ["live", "degraded"]
    assert siem["wazuh"]["mode"] in ["live", "degraded"]
