"""
Phase 5 Simulation PS-01: Suspicious PowerShell Execution
Generates a controlled, harmless PowerShell execution with an observable marker.
Verifies Sysmon Event ID 1 (Process Creation) and PowerShell Event ID 4104 (Script Block).
"""

import sys
import time
import subprocess
from pathlib import Path

# Add backend directory to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.utils.splunk_client import splunk_client

MARKER = "PHASE5_SIM_PS01_MARKER"

def run_simulation() -> dict:
    print(f"[*] Executing PS-01 harmless PowerShell execution with marker: {MARKER}")
    
    # Harmless PowerShell command that prints the marker and system uptime/date
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        f"Write-Output '{MARKER}'; Write-Output 'Host: $env:COMPUTERNAME - User: $env:USERNAME'"
    ]
    
    start_time = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    execution_time = time.time() - start_time
    
    print(f"[+] PowerShell Process Exited (code {proc.returncode}) in {execution_time:.2f}s")
    print(f"[+] Output: {proc.stdout.strip()}")
    
    # Wait briefly for Splunk forwarder to buffer and index event
    print("[*] Waiting 5 seconds for Splunk ingestion pipeline...")
    time.sleep(5)
    
    # Query Splunk Sysmon index
    spl_sysmon = f'index=sysmon "{MARKER}" | head 5'
    sysmon_res = splunk_client.execute_search(spl_sysmon, earliest="-15m")
    
    # Query Splunk PowerShell index
    spl_ps = f'index=powershell "{MARKER}" | head 5'
    ps_res = splunk_client.execute_search(spl_ps, earliest="-15m")
    
    result = {
        "test_id": "PS-01",
        "name": "Suspicious PowerShell Execution",
        "marker": MARKER,
        "execution_returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "sysmon_events_count": sysmon_res.get("events_count", 0),
        "powershell_events_count": ps_res.get("events_count", 0),
        "extracted_evidence": {},
        "status": "LIVE FAILED"
    }
    
    if sysmon_res.get("events"):
        event = sysmon_res["events"][0]
        result["extracted_evidence"]["sysmon"] = {
            "event_id": event.get("EventID", "1"),
            "image": event.get("Image"),
            "command_line": event.get("CommandLine"),
            "parent_image": event.get("ParentImage"),
            "parent_command_line": event.get("ParentCommandLine"),
            "user": event.get("User"),
            "process_id": event.get("ProcessId"),
            "timestamp": event.get("TimeCreated") or event.get("_time"),
            "computer": event.get("Computer") or event.get("host")
        }
        print(f"[LIVE PASSED] Sysmon Event ID 1 Found:")
        print(f"    - Image:        {event.get('Image')}")
        print(f"    - CommandLine:  {event.get('CommandLine')}")
        print(f"    - ParentImage:  {event.get('ParentImage')}")
        print(f"    - User:         {event.get('User')}")
        print(f"    - Timestamp:    {event.get('TimeCreated') or event.get('_time')}")
        result["status"] = "LIVE PASSED"
    else:
        print("[!] No Sysmon Event ID 1 found for marker yet.")

    if ps_res.get("events"):
        pevent = ps_res["events"][0]
        script_content = pevent.get("ScriptBlockText") or pevent.get("Payload") or pevent.get("ContextInfo") or ""
        result["extracted_evidence"]["powershell"] = {
            "event_id": pevent.get("EventID", "4104"),
            "script_block_text": script_content[:200],
            "computer": pevent.get("Computer") or pevent.get("host"),
            "timestamp": pevent.get("TimeCreated") or pevent.get("_time")
        }
        print(f"[LIVE PASSED] PowerShell Event ID {pevent.get('EventID')} Found:")
        print(f"    - Script/Payload: {script_content[:80]}...")

    return result

if __name__ == "__main__":
    res = run_simulation()
    print("\nResult Summary:")
    print(res)
