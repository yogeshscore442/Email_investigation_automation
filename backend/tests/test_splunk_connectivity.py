"""
Splunk REST API Live Connectivity and Telemetry Verification Script
Verifies:
1. Splunk REST authentication using credentials loaded from backend/.env.
2. Retrieval of Splunk Enterprise server metadata (version, build, server name).
3. Retrieval of configured and active indexes (sysmon, windows, powershell).
4. Real-time search execution on `sysmon` index (Process Creation, Network, etc.).
5. Real-time search execution on `windows` index (Security Events 4624, 4625, etc.).
6. Real-time search execution on `powershell` index.
7. Discovery of actual sourcetypes and fields present in the indices.
"""

import sys
import os
import json
from pathlib import Path
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure backend root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.config import Config


def run_connectivity_test():
    print("=" * 70)
    print("PHASE 4C: SPLUNK REST API LIVE CONNECTIVITY & TELEMETRY VERIFICATION")
    print("=" * 70)

    host = Config.SPLUNK_HOST
    port = Config.SPLUNK_PORT
    username = Config.SPLUNK_USERNAME
    password = Config.SPLUNK_PASSWORD
    verify_ssl = Config.SPLUNK_SSL_VERIFY

    if not host or not username or not password:
        print("[FAIL] Missing Splunk host, username, or password in configuration.")
        return False

    base_url = f"https://{host}:{port}"
    auth = (username, password)
    headers = {"Accept": "application/json"}

    # 1. Authenticate & Retrieve Server Information
    print("\n[STEP 1] Querying Splunk Server Information...")
    try:
        resp = requests.get(
            f"{base_url}/services/server/info?output_mode=json",
            auth=auth,
            headers=headers,
            verify=verify_ssl,
            timeout=10
        )
        if resp.status_code != 200:
            print(f"[FAIL] Server info returned HTTP status {resp.status_code}")
            return False

        server_info = resp.json()["entry"][0]["content"]
        version = server_info.get("version", "Unknown")
        server_name = server_info.get("serverName", "Unknown")
        os_name = server_info.get("os_name", "Unknown")
        build = server_info.get("build", "Unknown")
        print(f"[PASS] Connected to Splunk Enterprise {version} (Build {build}) on {os_name}")
        print(f"       Server Name: {server_name}")
    except Exception as e:
        print(f"[FAIL] Connection error to Splunk REST API: {e}")
        return False

    # 2. Retrieve Index Information
    print("\n[STEP 2] Inspecting Configured Indexes...")
    try:
        resp = requests.get(
            f"{base_url}/services/data/indexes?output_mode=json&count=100",
            auth=auth,
            headers=headers,
            verify=verify_ssl,
            timeout=10
        )
        if resp.status_code != 200:
            print(f"[FAIL] Index query returned HTTP status {resp.status_code}")
            return False

        indexes_data = resp.json().get("entry", [])
        index_names = {idx["name"]: idx["content"].get("totalEventCount", 0) for idx in indexes_data}
        
        target_indexes = ["sysmon", "windows", "powershell", "main"]
        for target in target_indexes:
            if target in index_names:
                print(f"[PASS] Index '{target}' exists - Total Events: {index_names[target]}")
            else:
                print(f"[WARN] Index '{target}' not found in Splunk index catalog.")
    except Exception as e:
        print(f"[FAIL] Error retrieving index data: {e}")
        return False

    # Helper function for one-shot export searches
    def execute_spl(spl_query: str, earliest="-30d", latest="now", max_count=5):
        url = f"{base_url}/services/search/jobs/export"
        params = {
            "search": f"search {spl_query}",
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
            "count": max_count
        }
        res = requests.post(url, auth=auth, data=params, verify=verify_ssl, timeout=15)
        if res.status_code != 200:
            return None, res.status_code
        events = []
        for line in res.text.strip().splitlines():
            if line:
                try:
                    parsed = json.loads(line)
                    if "result" in parsed:
                        events.append(parsed["result"])
                except Exception:
                    continue
        return events, 200

    # 3. Query `sysmon` Index
    print("\n[STEP 3] Querying Events from `sysmon` Index...")
    events, status = execute_spl("index=sysmon | xmlkv | head 5", earliest="-30d", max_count=5)
    if status == 200:
        print(f"[PASS] Retrieved {len(events)} sample events from `index=sysmon` (HTTP {status})")
        if events:
            sample = events[0]
            sourcetype = sample.get("sourcetype", "Unknown")
            event_code = sample.get("EventCode") or sample.get("EventID") or sample.get("Id")
            image = sample.get("Image") or sample.get("process_name")
            print(f"       Sample Sourcetype: {sourcetype} | EventCode/EventID: {event_code} | Host: {sample.get('host')}")
            if image:
                print(f"       Process Image: {image}")
            # Check fields
            common_fields = [k for k in ["Image", "CommandLine", "ParentImage", "DestinationIp", "DestinationPort", "Hashes", "User", "LogonId", "RuleName", "UtcTime"] if k in sample]
            print(f"       Extracted XML Fields: {common_fields}")
    else:
        print(f"[FAIL] Query on `sysmon` failed with HTTP {status}")

    # 4. Query `windows` Index
    print("\n[STEP 4] Querying Events from `windows` Index...")
    events, status = execute_spl("index=windows | xmlkv | head 5", earliest="-30d", max_count=5)
    if status == 200:
        print(f"[PASS] Retrieved {len(events)} sample events from `index=windows` (HTTP {status})")
        if events:
            sample = events[0]
            sourcetype = sample.get("sourcetype", "Unknown")
            event_code = sample.get("EventCode") or sample.get("EventID")
            user = sample.get("TargetUserName") or sample.get("Account_Name") or sample.get("SubjectUserName")
            print(f"       Sample Sourcetype: {sourcetype} | EventCode/EventID: {event_code} | User: {user}")
    else:
        print(f"[FAIL] Query on `windows` failed with HTTP {status}")

    # 5. Query `powershell` Index
    print("\n[STEP 5] Querying Events from `powershell` Index...")
    events, status = execute_spl("index=powershell | xmlkv | head 5", earliest="-30d", max_count=5)
    if status == 200:
        print(f"[PASS] Retrieved {len(events)} sample events from `index=powershell` (HTTP {status})")
        if events:
            sample = events[0]
            sourcetype = sample.get("sourcetype", "Unknown")
            event_id = sample.get("EventCode") or sample.get("EventID")
            print(f"       Sample Sourcetype: {sourcetype} | EventID: {event_id} | Host: {sample.get('host')}")
    else:
        print(f"[FAIL] Query on `powershell` failed with HTTP {status}")

    print("\n" + "=" * 70)
    print("ALL CONNECTIVITY AND LIVE SPLUNK REST CHECKS COMPLETE")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = run_connectivity_test()
    sys.exit(0 if success else 1)
