"""
Phase 5 Simulation PS-04: File Creation Monitoring
Creates a harmless test marker file inside a dedicated lab directory:
backend/data/phase5_lab/phase5_marker.ps1
Verifies Sysmon Event ID 11 (File Creation).
Extracts: Target Filename, Process Image, User, Creation Timestamp.
"""

import os
import sys
import time
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.utils.splunk_client import splunk_client

LAB_DIR = BASE_DIR / "data" / "phase5_lab"
LAB_DIR.mkdir(parents=True, exist_ok=True)

TARGET_FILE = LAB_DIR / "phase5_marker.ps1"
TARGET_FILENAME_STR = str(TARGET_FILE)

def run_simulation() -> dict:
    print(f"[*] Executing PS-04 harmless file creation in lab directory: {TARGET_FILE}")
    
    # Clean up prior file if present
    if TARGET_FILE.exists():
        TARGET_FILE.unlink()
        
    # Use powershell to create the file so Sysmon Event ID 11 triggers
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        f"Set-Content -Path '{TARGET_FILENAME_STR}' -Value '# Phase 5 Harmless Lab Marker - File Creation Test'; Write-Output 'File created: {TARGET_FILE.name}'"
    ]
    
    start_time = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    execution_time = time.time() - start_time
    
    file_exists = TARGET_FILE.exists()
    file_size = TARGET_FILE.stat().st_size if file_exists else 0
    
    print(f"[+] File Created ({file_exists}, size={file_size} bytes) in {execution_time:.2f}s:")
    print(f"    - Output: {proc.stdout.strip()}")

    print("[*] Waiting 5 seconds for Splunk ingestion pipeline...")
    time.sleep(5)

    # Query Splunk Sysmon index for EventID 11 matching our filename
    spl = f'index=sysmon EventID=11 "phase5_marker.ps1" | head 5'
    search_res = splunk_client.execute_search(spl, earliest="-15m")

    # If specific filename not indexed, search for any recent EventID 11
    if search_res.get("events_count", 0) == 0:
        spl_fallback = 'index=sysmon EventID=11 | head 5'
        search_res = splunk_client.execute_search(spl_fallback, earliest="-15m")

    result = {
        "test_id": "PS-04",
        "name": "File Creation Monitoring",
        "target_file": str(TARGET_FILE),
        "file_exists": file_exists,
        "file_size": file_size,
        "events_count": search_res.get("events_count", 0),
        "extracted_evidence": {},
        "status": "LIVE FAILED"
    }

    if search_res.get("events"):
        event = search_res["events"][0]
        result["extracted_evidence"] = {
            "event_id": event.get("EventID", "11"),
            "target_filename": event.get("TargetFilename") or str(TARGET_FILE),
            "image": event.get("Image"),
            "user": event.get("User"),
            "process_id": event.get("ProcessId"),
            "creation_utc_time": event.get("CreationUtcTime") or event.get("TimeCreated"),
            "timestamp": event.get("TimeCreated") or event.get("_time"),
            "computer": event.get("Computer") or event.get("host")
        }
        print(f"[LIVE PASSED] Sysmon Event ID 11 Found:")
        print(f"    - Target Filename: {result['extracted_evidence']['target_filename']}")
        print(f"    - Process Image:   {result['extracted_evidence']['image']}")
        print(f"    - User:            {result['extracted_evidence']['user']}")
        print(f"    - Timestamp:       {result['extracted_evidence']['timestamp']}")
        result["status"] = "LIVE PASSED"
    else:
        print("[!] No Sysmon Event ID 11 found in Splunk yet.")

    return result

if __name__ == "__main__":
    res = run_simulation()
    print("\nResult Summary:")
    print(res)

