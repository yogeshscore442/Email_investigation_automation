import sys
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.utils.splunk_client import splunk_client

def run_hunting_audit():
    queries = [
        {
            "id": "HUNT-01",
            "name": "Suspicious PowerShell Execution (Obfuscation & In-Memory Cradles)",
            "spl": 'index=sysmon EventID=1 (Image="*\\\\powershell.exe" OR Image="*\\\\pwsh.exe") | head 10',
            "index": "sysmon",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "time_range": "earliest=-30d to latest=now",
            "full_spl": 'index=sysmon EventID=1 (Image="*\\\\powershell.exe" OR Image="*\\\\pwsh.exe") | eval IsSuspicious=case(match(CommandLine, "(?i)-(enc|encodedcommand)"), "Base64_Encoded_Execution", match(CommandLine, "(?i)-ExecutionPolicy\\s+Bypass"), "ExecutionPolicy_Bypass", match(CommandLine, "(?i)(downloadstring|downloadfile)"), "Download_Cradle", match(ParentImage, "(?i)(winword|excel|outlook|chrome|msedge)"), "Suspicious_Parent_Process", true(), "Normal_Admin") | head 10'
        },
        {
            "id": "HUNT-02",
            "name": "Repeated Authentication Failures & Password Spraying",
            "spl": 'index=windows EventID=4625 | head 10',
            "index": "windows",
            "sourcetype": "XmlWinEventLog:Security",
            "time_range": "earliest=-30d to latest=now",
            "full_spl": 'index=windows EventID=4625 | head 10'
        },
        {
            "id": "HUNT-03",
            "name": "Suspicious Process Access & LSASS Handle Acquisition",
            "spl": 'index=sysmon EventID=10 | head 10',
            "index": "sysmon",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "time_range": "earliest=-30d to latest=now",
            "full_spl": 'index=sysmon EventID=10 TargetImage="*\\\\lsass.exe" | head 10'
        },
        {
            "id": "HUNT-04",
            "name": "Persistence-Related Registry Autostart Modifications",
            "spl": 'index=sysmon (EventID=12 OR EventID=13) | head 10',
            "index": "sysmon",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "time_range": "earliest=-30d to latest=now",
            "full_spl": 'index=sysmon (EventID=12 OR EventID=13) (TargetObject="*\\\\CurrentVersion\\\\Run*" OR TargetObject="*\\\\CurrentVersion\\\\RunOnce*" OR TargetObject="*\\\\Services\\\\*" OR TargetObject="*\\\\Software\\\\Phase5Lab*") | head 10'
        },
        {
            "id": "HUNT-05",
            "name": "Suspicious Non-Browser Script-Initiated Network Connections",
            "spl": 'index=sysmon EventID=3 DestinationPort IN (5000, 8089, 4444, 8080, 8443) | head 10',
            "index": "sysmon",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "time_range": "earliest=-30d to latest=now",
            "full_spl": 'index=sysmon EventID=3 Image IN ("*\\\\powershell.exe", "*\\\\cmd.exe", "*\\\\python.exe") | head 10'
        }
    ]

    results = []
    print(f"[*] Checking Splunk Connection: configured={splunk_client.is_configured()}")
    status = splunk_client.get_service_status()
    print(f"[*] Splunk Status: {status.get('status')} | Version: {status.get('version')} | Indexes: {status.get('indexes')}")

    for q in queries:
        print(f"\n==========================================")
        print(f"Executing {q['id']}: {q['name']}")
        print(f"SPL: {q['full_spl']}")
        res = splunk_client.execute_search(q['full_spl'], earliest="-30d", latest="now", max_count=10)
        events = res.get("events", [])
        count = len(events)
        print(f"Status: {res.get('status')} | Returned Events: {count}")
        
        # If full_spl returned 0 (e.g. because of strict filter or lab artifact cleanup), try base query to inspect raw field availability
        base_res = None
        if count == 0:
            print(f"[*] Running base query to check available index events: {q['spl']}")
            base_res = splunk_client.execute_search(q['spl'], earliest="-30d", latest="now", max_count=10)
            print(f"[*] Base Query Returned Events: {len(base_res.get('events', []))}")

        sample_event_ids = []
        sample_details = []
        active_events = events if count > 0 else (base_res.get("events", []) if base_res else [])
        for ev in active_events[:3]:
            eid = ev.get("EventID") or ev.get("EventCode")
            sample_event_ids.append(str(eid))
            sample_details.append({
                "time": ev.get("_time"),
                "event_id": eid,
                "host": ev.get("Computer") or ev.get("host"),
                "image": ev.get("Image") or ev.get("SourceImage"),
                "command_line": str(ev.get("CommandLine") or "")[:80],
                "target": ev.get("TargetImage") or ev.get("TargetObject") or ev.get("TargetUserName") or ev.get("DestinationIp")
            })

        results.append({
            "id": q["id"],
            "name": q["name"],
            "spl": q["full_spl"],
            "base_spl": q["spl"],
            "index": q["index"],
            "sourcetype": q["sourcetype"],
            "time_range": q["time_range"],
            "count": count,
            "base_count": len(base_res.get("events", [])) if base_res else count,
            "sample_event_ids": list(set(sample_event_ids)),
            "sample_details": sample_details
        })

    out_path = BASE_DIR / "data" / "phase6b_hunting_live_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Wrote results to {out_path}")

if __name__ == "__main__":
    run_hunting_audit()
