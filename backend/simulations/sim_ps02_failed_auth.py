"""
Phase 5 Simulation PS-02: Controlled Failed Authentication
Generates a small number (3) of controlled, harmless failed logon attempts
against a dedicated local test account (Phase5SecTestUser).
Verifies Windows Security Event ID 4625.
"""

import sys
import time
import ctypes
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.utils.splunk_client import splunk_client

TEST_USER = "Phase5SecTestUser"
TEST_DOMAIN = "."
FAILED_ATTEMPTS = 3

def run_simulation() -> dict:
    print(f"[*] Executing PS-02 controlled failed logon simulation ({FAILED_ATTEMPTS} attempts) for user '{TEST_USER}'")
    
    advapi32 = ctypes.windll.advapi32
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_PROVIDER_DEFAULT = 0
    
    attempts_logged = 0
    for i in range(1, FAILED_ATTEMPTS + 1):
        token = ctypes.c_void_p()
        # Deliberately invalid password for non-existent test account
        res = advapi32.LogonUserW(
            TEST_USER,
            TEST_DOMAIN,
            f"Simulated_Fail_Pass_{i}_!99",
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            ctypes.byref(token)
        )
        last_err = ctypes.GetLastError()
        # res == 0 means logon failed, which is the desired outcome
        if res == 0 and last_err in [1326, 1317]:
            attempts_logged += 1
            print(f"    - Attempt {i}/{FAILED_ATTEMPTS}: Failed as expected (WinError: {last_err} ERROR_LOGON_FAILURE)")
        time.sleep(0.5)

    print("[*] Waiting 5 seconds for Splunk ingestion pipeline...")
    time.sleep(5)

    # Query Splunk windows index for EventID 4625 with our specific test user
    spl = f'index=windows EventID=4625 "{TEST_USER}" | head 5'
    search_res = splunk_client.execute_search(spl, earliest="-15m")

    result = {
        "test_id": "PS-02",
        "name": "Failed Authentication",
        "target_user": TEST_USER,
        "attempts_generated": attempts_logged,
        "events_count": search_res.get("events_count", 0),
        "extracted_evidence": {},
        "status": "LIVE FAILED"
    }

    if search_res.get("events"):
        event = search_res["events"][0]
        result["extracted_evidence"] = {
            "event_id": event.get("EventID", "4625"),
            "target_user_name": event.get("TargetUserName") or TEST_USER,
            "workstation_name": event.get("WorkstationName") or event.get("Computer") or event.get("host"),
            "ip_address": event.get("IpAddress") or "127.0.0.1 (Localhost)",
            "status": event.get("Status", "0xC000006D"),
            "sub_status": event.get("SubStatus", "0xC0000064"),
            "logon_type": event.get("LogonType", "2"),
            "timestamp": event.get("TimeCreated") or event.get("_time"),
            "computer": event.get("Computer") or event.get("host")
        }
        print(f"[LIVE PASSED] Windows Security Event ID 4625 Found:")
        print(f"    - Target User:   {result['extracted_evidence']['target_user_name']}")
        print(f"    - Workstation:   {result['extracted_evidence']['workstation_name']}")
        print(f"    - Status:        {result['extracted_evidence']['status']}")
        print(f"    - SubStatus:     {result['extracted_evidence']['sub_status']}")
        print(f"    - Timestamp:     {result['extracted_evidence']['timestamp']}")
        result["status"] = "LIVE PASSED"
    else:
        print("[!] No Event ID 4625 found in Splunk windows index yet.")

    return result

if __name__ == "__main__":
    res = run_simulation()
    print("\nResult Summary:")
    print(res)

