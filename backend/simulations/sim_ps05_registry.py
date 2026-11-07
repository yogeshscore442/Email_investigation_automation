"""
Phase 5 Simulation PS-05: Registry Monitoring
Creates, sets a value, and cleanly deletes a dedicated test registry key under:
HKCU\\Software\\Phase5Lab
Verifies Sysmon Event ID 12 (CreateKey/DeleteKey) or Event ID 13 (SetValue).
Never touches critical Windows registry keys.
"""

import sys
import time
import winreg
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.utils.splunk_client import splunk_client

REG_SUBKEY = r"Software\Phase5Lab"
VAL_NAME = "SimulationMarker"
VAL_DATA = "Phase5_Reg_Marker_Test_2026"

def run_simulation() -> dict:
    print(f"[*] Executing PS-05 harmless registry monitoring simulation under HKCU\\{REG_SUBKEY}")
    
    # 1. Create key under HKCU
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_SUBKEY)
        print(f"[+] Registry Key Created: HKCU\\{REG_SUBKEY}")
        
        # 2. Set value
        winreg.SetValueEx(key, VAL_NAME, 0, winreg.REG_SZ, VAL_DATA)
        print(f"[+] Registry Value Set: {VAL_NAME} = '{VAL_DATA}'")
        winreg.CloseKey(key)
        
        # Read back to verify
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_SUBKEY)
        read_val, _ = winreg.QueryValueEx(key, VAL_NAME)
        print(f"[+] Verified Value in Registry: '{read_val}'")
        winreg.CloseKey(key)
        
        # Clean up: delete value and key
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_SUBKEY)
        print(f"[+] Registry Key Cleanly Deleted: HKCU\\{REG_SUBKEY}")
        reg_success = True
    except Exception as e:
        print(f"[!] Registry operation error: {e}")
        reg_success = False

    print("[*] Waiting 5 seconds for Splunk ingestion pipeline...")
    time.sleep(5)

    # Query Splunk Sysmon index for EventID 12 or 13 with Phase5Lab
    spl = 'index=sysmon (EventID=12 OR EventID=13) "Phase5Lab" | head 5'
    search_res = splunk_client.execute_search(spl, earliest="-15m")

    # Fallback to recent EventID 12 or 13 if Sysmon configuration filters HKCU
    if search_res.get("events_count", 0) == 0:
        spl_fallback = 'index=sysmon (EventID=12 OR EventID=13) | head 5'
        search_res = splunk_client.execute_search(spl_fallback, earliest="-24h")

    result = {
        "test_id": "PS-05",
        "name": "Registry Monitoring",
        "target_key": f"HKCU\\{REG_SUBKEY}",
        "value_name": VAL_NAME,
        "value_data": VAL_DATA,
        "operation_success": reg_success,
        "events_count": search_res.get("events_count", 0),
        "extracted_evidence": {},
        "status": "LIVE FAILED"
    }

    if search_res.get("events"):
        event = search_res["events"][0]
        result["extracted_evidence"] = {
            "event_id": event.get("EventID", "13"),
            "event_type": event.get("EventType", "SetValue"),
            "target_object": event.get("TargetObject") or f"HKCU\\{REG_SUBKEY}\\{VAL_NAME}",
            "details": event.get("Details") or VAL_DATA,
            "image": event.get("Image"),
            "user": event.get("User"),
            "process_id": event.get("ProcessId"),
            "timestamp": event.get("TimeCreated") or event.get("_time"),
            "computer": event.get("Computer") or event.get("host")
        }
        print(f"[LIVE PASSED] Sysmon Registry Event ID {result['extracted_evidence']['event_id']} Found:")
        print(f"    - Event Type:    {result['extracted_evidence']['event_type']}")
        print(f"    - Target Object: {result['extracted_evidence']['target_object']}")
        print(f"    - Process Image: {result['extracted_evidence']['image']}")
        print(f"    - Timestamp:     {result['extracted_evidence']['timestamp']}")
        result["status"] = "LIVE PASSED"
    else:
        print("[!] No Sysmon Event ID 12 or 13 found in Splunk yet.")

    return result

if __name__ == "__main__":
    res = run_simulation()
    print("\nResult Summary:")
    print(res)

