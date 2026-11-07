"""
Phase 5 Simulation PS-06: Process Access Monitoring (Safe Inspection)
Inspects available Sysmon Event ID 10 (Process Access) telemetry in Splunk.
SAFETY ENFORCEMENT:
- Strictly NO credential dumping (e.g., Mimikatz, procdump on LSASS).
- Strictly NO memory extraction or unauthorized process manipulation.
- Analyzes existing benign process access telemetry (e.g. svchost/sysmain -> lsass with 0x2000 limited rights).
Extracts: Source Process, Target Process, Granted Access Mask, Call Trace, Timestamp.
"""

import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.utils.splunk_client import splunk_client

def run_simulation() -> dict:
    print("[*] Executing PS-06: Safe Process Access Telemetry Inspection (Sysmon Event ID 10)")
    print("[*] Safety Check: Zero credential dumping or unauthorized process access initiated.")
    
    # Query Splunk Sysmon index for recent EventID 10 events
    spl = 'index=sysmon EventID=10 | head 5'
    search_res = splunk_client.execute_search(spl, earliest="-1h")

    if search_res.get("events_count", 0) == 0:
        spl_fallback = 'index=sysmon EventID=10 | head 5'
        search_res = splunk_client.execute_search(spl_fallback, earliest="-24h")

    result = {
        "test_id": "PS-06",
        "name": "Process Access Monitoring",
        "safety_mode": "Safe Telemetry Inspection (No Memory/Credential Manipulation)",
        "events_count": search_res.get("events_count", 0),
        "extracted_evidence": {},
        "status": "LIVE FAILED"
    }

    if search_res.get("events"):
        event = search_res["events"][0]
        result["extracted_evidence"] = {
            "event_id": event.get("EventID", "10"),
            "source_image": event.get("SourceImage"),
            "source_process_id": event.get("SourceProcessId"),
            "target_image": event.get("TargetImage"),
            "target_process_id": event.get("TargetProcessId"),
            "granted_access": event.get("GrantedAccess"),
            "call_trace": (event.get("CallTrace") or "")[:120] + "...",
            "source_user": event.get("SourceUser"),
            "target_user": event.get("TargetUser"),
            "timestamp": event.get("TimeCreated") or event.get("_time"),
            "computer": event.get("Computer") or event.get("host")
        }
        print(f"[LIVE PASSED] Sysmon Event ID 10 Found:")
        print(f"    - Source Image:   {result['extracted_evidence']['source_image']}")
        print(f"    - Target Image:   {result['extracted_evidence']['target_image']}")
        print(f"    - Granted Access: {result['extracted_evidence']['granted_access']}")
        print(f"    - Source User:    {result['extracted_evidence']['source_user']}")
        print(f"    - Timestamp:      {result['extracted_evidence']['timestamp']}")
        result["status"] = "LIVE PASSED"
    else:
        print("[!] No Sysmon Event ID 10 found in Splunk yet.")

    return result

if __name__ == "__main__":
    res = run_simulation()
    print("\nResult Summary:")
    print(res)

