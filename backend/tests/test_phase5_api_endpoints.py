"""
Verification script for Phase 5 REST API Endpoints used by Phase5Dashboard.jsx
Supports both in-process Flask test client (for pytest) and standalone live HTTP requests.
"""
import sys
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import create_app


class ResponseAdapter:
    def __init__(self, flask_resp):
        self.status_code = flask_resp.status_code
        self._resp = flask_resp

    def json(self):
        return self._resp.get_json() or {}


class FlaskClientWrapper:
    def __init__(self, client):
        self.client = client

    def get(self, url, **kwargs):
        # Strip host prefix if present
        path = url.replace("http://127.0.0.1:5000", "")
        return ResponseAdapter(self.client.get(path))


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return FlaskClientWrapper(app.test_client())


def test_phase5_api(client=None):
    if client is None:
        app = create_app()
        app.config["TESTING"] = True
        client = FlaskClientWrapper(app.test_client())

    print("=" * 80)
    print("VERIFYING PHASE 5 FRONTEND-BACKEND REST API CONTRACTS")
    print("=" * 80)

    # 1. GET /api/siem/status
    print("\n1. Testing GET /api/siem/status:")
    r = client.get("/api/siem/status")
    print(f"Status Code: {r.status_code}")
    data = r.json()
    print(f"Splunk Status: {data.get('splunk', {}).get('status')}")
    print(f"Splunk Host:   {data.get('splunk', {}).get('host')}")
    print(f"Indexes:       {list(data.get('splunk', {}).get('indexes', {}).keys())}")
    print(f"Wazuh Status:  {data.get('wazuh', {}).get('status')} (Mode: {data.get('wazuh', {}).get('mode')})")
    assert r.status_code == 200

    # 2. GET /api/phase5/status
    print("\n2. Testing GET /api/phase5/status:")
    r = client.get("/api/phase5/status")
    print(f"Status Code: {r.status_code}")
    data = r.json()
    sims = data.get("simulations", [])
    print(f"Phase 5 Status:        {data.get('status')}")
    print(f"Total Simulations:     {len(sims)}")
    print(f"Total Detection Rules: {data.get('detection_rules_count')}")
    print(f"Cached Results:        {data.get('cached_results_count')}")
    print(f"Splunk Host:           {data.get('splunk', {}).get('server_name')} ({data.get('splunk', {}).get('host')})")
    print(f"Total Splunk Events:   {data.get('splunk', {}).get('total_events')}")
    assert r.status_code == 200
    assert len(sims) == 8
    assert data.get("detection_rules_count") == 6
    assert data.get("cached_results_count") == 8

    # 3. GET /api/phase5/rules
    print("\n3. Testing GET /api/phase5/rules:")
    r = client.get("/api/phase5/rules")
    print(f"Status Code: {r.status_code}")
    rules = r.json().get("rules", [])
    print(f"Rules Catalog Loaded:  {len(rules)} rules")
    for rdata in rules:
        print(f"  - {rdata.get('rule_id')}: {rdata.get('name')} [{rdata.get('severity')}] MITRE: {rdata.get('mitre_attack', {}).get('technique_id')}")
    assert len(rules) == 6

    # 4. GET /api/phase5/results
    print("\n4. Testing GET /api/phase5/results:")
    r = client.get("/api/phase5/results")
    print(f"Status Code: {r.status_code}")
    sim_res = r.json().get("simulations", {})
    print(f"Cached Simulations Loaded: {len(sim_res)}")
    for sid, sdata in sim_res.items():
        print(f"  - {sid}: {sdata.get('name')} -> Status: {sdata.get('status')}")
    assert len(sim_res) == 8

    # 5. GET /api/phase5/timeline
    print("\n5. Testing GET /api/phase5/timeline:")
    r = client.get("/api/phase5/timeline")
    print(f"Status Code: {r.status_code}")
    tdata = r.json()
    events = tdata.get("timeline", [])
    print(f"Timeline Events Loaded: {len(events)}")
    print(f"Is Chronological:       {tdata.get('is_chronological')}")
    print(f"Observed Statuses:      {tdata.get('statuses_observed')}")
    assert len(events) == 9
    assert tdata.get("is_chronological") is True

    print("\n>> ALL 5 REST API ENDPOINTS VERIFIED OPERATIONAL FOR FRONTEND.")


if __name__ == "__main__":
    test_phase5_api()
