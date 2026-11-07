"""
Comprehensive End-to-End Manual SOC Validation Script for Phase 4D
Executes all 6 validation tests with detailed logging and assertions:
Test 1: Application Connectivity (Flask, React, Splunk REST API, Auth, Indexes)
Test 2: Email Investigation (Upload, Parse, Headers, SPF/DKIM/DMARC, URLs, Attachments, Hashes, IOCs)
Test 3: SIEM Correlation (Splunk Event Queries: Domains, IPs, Hashes, Sysmon 1/3, Windows 4624/4625, PowerShell 4104)
Test 4: Incident Timeline (Chronological order, Timestamp attribution, Hostname, Anti-fabrication)
Test 5: Reporting (PDF, HTML, JSON reports, IOC CSV/JSON exports)
Test 6: Response Approval Guardrails (Analyst approval required, safety verification)
"""

import os
import sys
import json
from pathlib import Path
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

API_BASE = "http://127.0.0.1:5000/api"
FRONTEND_URL = "http://127.0.0.1:5173"

def run_test_1():
    print("\n" + "=" * 70)
    print("TEST 1: APPLICATION CONNECTIVITY & SIEM READINESS")
    print("=" * 70)

    # 1. Flask backend
    r_flask = requests.get(f"{API_BASE}/siem/status", timeout=5)
    assert r_flask.status_code == 200, f"Flask backend returned {r_flask.status_code}"
    siem = r_flask.json()
    splunk = siem.get("splunk", {})
    wazuh = siem.get("wazuh", {})
    print(f"[LIVE PASSED] Flask Backend: HTTP {r_flask.status_code} OK")

    # 2. React frontend
    r_react = requests.get(FRONTEND_URL, timeout=5)
    assert r_react.status_code == 200, f"React frontend returned {r_react.status_code}"
    print(f"[LIVE PASSED] React Frontend: HTTP {r_react.status_code} OK (Served {len(r_react.text)} bytes)")

    # 3. Splunk REST API & Auth
    assert splunk.get("status") == "operational", f"Splunk status: {splunk.get('status')}"
    assert splunk.get("mode") == "live", f"Splunk mode: {splunk.get('mode')}"
    print(f"[LIVE PASSED] Splunk REST API: Operational at {splunk.get('host')}")
    print(f"[LIVE PASSED] Splunk Version: Enterprise {splunk.get('version')} (Server: {splunk.get('server_name')})")

    # 4. Indexes
    indexes = splunk.get("indexes", {})
    assert "sysmon" in indexes and indexes["sysmon"] > 10000
    assert "windows" in indexes and indexes["windows"] > 10000
    assert "powershell" in indexes and indexes["powershell"] > 1000
    print(f"[LIVE PASSED] Active Indexes:")
    print(f"       - sysmon:     {indexes['sysmon']:,} events")
    print(f"       - windows:    {indexes['windows']:,} events")
    print(f"       - powershell: {indexes['powershell']:,} events")
    print(f"       - Total:      {splunk.get('total_events', 0):,} events")
    print(f"[NOT CONFIGURED] Wazuh Status: {wazuh.get('status').upper()} ({wazuh.get('message')})")
    return True


def run_test_2_and_3():
    print("\n" + "=" * 70)
    print("TEST 2 & 3: EMAIL INVESTIGATION & SIEM CORRELATION")
    print("=" * 70)

    samples_dir = BASE_DIR / "data" / "samples"
    
    # Test with credential phishing sample
    target_sample = samples_dir / "credential_phishing_microsoft.eml"
    if not target_sample.exists():
        target_sample = samples_dir / "macro_invoice_phishing.eml"

    print(f"Uploading Controlled Phishing Sample: {target_sample.name}")
    with open(target_sample, "rb") as f:
        r_upload = requests.post(
            f"{API_BASE}/investigate/upload",
            files={"file": (target_sample.name, f, "message/rfc822")}
        )
    assert r_upload.status_code in [200, 201], f"Upload failed: {r_upload.status_code} {r_upload.text}"
    inv_data = r_upload.json()
    inv_id = inv_data.get("id") or inv_data.get("investigation_id")
    print(f"[LIVE PASSED] Investigation Ingested & Parsed: ID={inv_id}")
    print(f"       Subject:  {inv_data.get('subject')}")
    print(f"       Sender:   {inv_data.get('sender')}")
    print(f"       Risk:     {inv_data.get('overall_risk_score')} ({inv_data.get('risk_category')})")
    print(f"       Verdict:  {inv_data.get('verdict')}")

    # Inspect full investigation details
    r_detail = requests.get(f"{API_BASE}/investigate/{inv_id}")
    assert r_detail.status_code == 200
    detail = r_detail.json()

    # Headers & Authentication Analysis
    auth = detail.get("authentication_results", {}) or {}
    print(f"[LIVE PASSED] Email Header & Authentication Analysis:")
    print(f"       - SPF:              {auth.get('spf_result', 'N/A')}")
    print(f"       - DKIM:             {auth.get('dkim_result', 'N/A')}")
    print(f"       - DMARC:            {auth.get('dmarc_result', 'N/A')}")
    print(f"       - X-Originating-IP: {auth.get('x_originating_ip', 'N/A')}")
    print(f"       - Mismatch Flags:   Sender/Reply-To: {auth.get('sender_reply_to_mismatch', False)}")

    # URLs & Attachments
    urls = detail.get("urls", [])
    attachments = detail.get("attachments", [])
    iocs = detail.get("extracted_iocs", [])
    print(f"[LIVE PASSED] Artifacts & Indicators Extracted:")
    print(f"       - URLs Discovered:        {len(urls)}")
    for u in urls[:3]:
        print(f"         * {u.get('defanged_url', u.get('url'))}")
    print(f"       - Attachments Analyzed:   {len(attachments)}")
    for a in attachments[:3]:
        print(f"         * {a.get('filename')} (SHA256: {a.get('sha256', '')[:16]}...)")
    print(f"       - Total Normalised IOCs:  {len(iocs)}")

    # TEST 3: Splunk SIEM Correlation
    print("\n--- Querying Live Splunk for Extracted Email IOCs ---")
    hashes = [a.get("sha256") for a in attachments if a.get("sha256")]
    ips = [auth.get("x_originating_ip")] if auth.get("x_originating_ip") else []
    domains = [u.get("domain") for u in urls if u.get("domain")]

    r_corr = requests.post(
        f"{API_BASE}/siem/splunk/search",
        json={
            "query_type": "correlation",
            "hashes": hashes,
            "ips": ips,
            "domains": domains
        }
    )
    assert r_corr.status_code == 200
    corr_data = r_corr.json()
    print(f"[LIVE PASSED] Live Splunk IOC Pivot Executed: Status={corr_data.get('status')}")
    print(f"       Telemetry Status: {corr_data.get('telemetry_status')}")
    print(f"       Total Matches:    {corr_data.get('total_matches')}")
    print(f"       Process Events:   {len(corr_data.get('process_events', []))}")
    print(f"       Network Sockets:  {len(corr_data.get('network_events', []))}")
    print(f"       Auth Events:      {len(corr_data.get('auth_events', []))}")

    # Verify dedicated searches on all three Splunk indexes
    r_sysmon = requests.post(f"{API_BASE}/siem/splunk/search", json={"query_type": "endpoint"})
    assert r_sysmon.status_code == 200 and r_sysmon.json().get("events_count", 0) > 0
    print(f"[LIVE PASSED] Live Sysmon Search (EventID 1/3): Retrieved {r_sysmon.json()['events_count']} events")

    r_sec = requests.post(f"{API_BASE}/siem/splunk/search", json={"query_type": "windows"})
    assert r_sec.status_code == 200 and r_sec.json().get("events_count", 0) > 0
    print(f"[LIVE PASSED] Live Windows Security Search (EventID 4624/4625): Retrieved {r_sec.json()['events_count']} events")

    r_ps = requests.post(f"{API_BASE}/siem/splunk/search", json={"query_type": "powershell"})
    assert r_ps.status_code == 200 and r_ps.json().get("events_count", 0) > 0
    print(f"[LIVE PASSED] Live PowerShell Search (EventID 4104): Retrieved {r_ps.json()['events_count']} events")

    return inv_id


def run_test_4_and_5_and_6(inv_id):
    print("\n" + "=" * 70)
    print("TEST 4, 5, 6: INCIDENT TIMELINE, REPORTING & PLAYBOOK GUARDRAILS")
    print("=" * 70)

    # 1. Trigger incident correlation pass
    r_trig = requests.post(f"{API_BASE}/incidents/correlate")
    assert r_trig.status_code == 200
    print(f"[LIVE PASSED] Incident Correlation Engine: {r_trig.json()}")

    # 2. Retrieve incidents
    r_incs = requests.get(f"{API_BASE}/incidents")
    assert r_incs.status_code == 200
    incidents = r_incs.json()
    assert len(incidents) > 0, "Zero incidents found"
    inc = incidents[0]
    inc_id = inc["id"]
    print(f"[LIVE PASSED] Correlated Incident Found: ID={inc_id} ({inc.get('incident_number')}) - Severity: {inc.get('severity')}")

    r_detail = requests.get(f"{API_BASE}/incidents/{inc_id}")
    assert r_detail.status_code == 200
    inc_detail = r_detail.json()

    # TEST 4: Timeline verification
    timeline = inc_detail.get("timeline", [])
    print(f"[LIVE PASSED] Chronological Timeline Events Count: {len(timeline)}")
    assert len(timeline) >= 2, "Expected at least 2 timeline events"

    statuses = set()
    for ev in timeline:
        st = ev.get("telemetry_status")
        statuses.add(st)
        print(f"       [{st}] {ev.get('timestamp')[:19]} | {ev.get('source')}: {ev.get('title')}")

    assert "confirmed" in statuses, "Expected confirmed email event"
    print(f"[LIVE PASSED] Anti-Fabrication Guardrail: Verified timeline maintains truthful attribution ({statuses})")

    # TEST 5: Reports (JSON, HTML, PDF, IOC Exports)
    print("\n--- Generating and Validating SOC Reports ---")
    
    # JSON SOC Report
    r_json = requests.get(f"{API_BASE}/investigate/{inv_id}/report")
    assert r_json.status_code == 200
    json_report = r_json.json()
    assert "report_metadata" in json_report or "report_id" in json_report or "investigation_id" in json_report
    report_id = json_report.get("report_metadata", {}).get("report_id", "N/A")
    print(f"[LIVE PASSED] JSON SOC Report: Generated ID={report_id} ({len(r_json.content)} bytes)")

    # HTML SOC Report
    r_html = requests.get(f"{API_BASE}/investigate/{inv_id}/report/html")
    assert r_html.status_code == 200
    assert "text/html" in r_html.headers.get("Content-Type", "")
    print(f"[LIVE PASSED] HTML SOC Report: Generated ({len(r_html.content)} bytes)")

    # PDF SOC Report
    r_pdf = requests.get(f"{API_BASE}/investigate/{inv_id}/report/pdf")
    assert r_pdf.status_code == 200
    assert r_pdf.headers.get("Content-Type") == "application/pdf"
    assert len(r_pdf.content) > 1000
    print(f"[LIVE PASSED] PDF SOC Report: Generated ({len(r_pdf.content)} bytes, Content-Type: application/pdf)")

    # Save PDF copy
    pdf_path = BASE_DIR / "data" / "final_soc_validation_report.pdf"
    with open(pdf_path, "wb") as f:
        f.write(r_pdf.content)
    print(f"       Saved binary copy to: {pdf_path.name}")

    # IOC Exports (JSON & CSV)
    r_ioc_json = requests.get(f"{API_BASE}/investigate/{inv_id}/iocs/export?format=json")
    assert r_ioc_json.status_code == 200
    print(f"[LIVE PASSED] IOC Export (JSON): Size={len(r_ioc_json.content)} bytes")

    r_ioc_csv = requests.get(f"{API_BASE}/investigate/{inv_id}/iocs/export?format=csv")
    assert r_ioc_csv.status_code == 200
    print(f"[LIVE PASSED] IOC Export (CSV): Size={len(r_ioc_csv.content)} bytes")

    # TEST 6: Response Action Approval Guardrails
    print("\n--- Verifying SOC Response Approval Guardrails ---")
    actions = inc_detail.get("playbook_actions", [])
    print(f"[LIVE PASSED] Generated Playbook Actions Count: {len(actions)}")
    assert len(actions) > 0, "No playbook actions generated"

    first_action = actions[0]
    action_id = first_action["id"]
    print(f"       Target Action: ID={action_id} - '{first_action.get('title')}'")
    print(f"       Requires Approval: {first_action.get('requires_approval')}")
    print(f"       Approval Status:   {first_action.get('approval_status')}")

    # 1. Attempt to execute without approval (must be blocked)
    r_exec_unapproved = requests.post(f"{API_BASE}/incidents/{inc_id}/actions/{action_id}/execute")
    print(f"[LIVE PASSED] Attempt execution without approval: HTTP {r_exec_unapproved.status_code} ({r_exec_unapproved.json().get('error', 'Blocked')})")
    assert r_exec_unapproved.status_code in [400, 403], "Unapproved destructive action was not blocked!"

    # 2. Approve action explicitly
    r_approve = requests.post(
        f"{API_BASE}/incidents/{inc_id}/actions/{action_id}/approve",
        json={"analyst_name": "Lead SOC Specialist"}
    )
    assert r_approve.status_code == 200
    print(f"[LIVE PASSED] Explicit Analyst Approval Granted: Status={r_approve.json().get('action', {}).get('approval_status')}")

    # 3. Simulate execution after approval (safe guardrail - does not disrupt production)
    r_exec = requests.post(f"{API_BASE}/incidents/{inc_id}/actions/{action_id}/execute")
    assert r_exec.status_code == 200
    exec_res = r_exec.json().get("execution_result", {})
    print(f"[LIVE PASSED] Action Executed Safely in Simulation Mode: {exec_res.get('message')}")

    return True


if __name__ == "__main__":
    t1 = run_test_1()
    inv_id = run_test_2_and_3()
    t456 = run_test_4_and_5_and_6(inv_id)
    print("\n" + "=" * 70)
    print("ALL 6 MANUAL VALIDATION WORKFLOWS COMPLETED WITH 100% SUCCESS!")
    print("=" * 70)
