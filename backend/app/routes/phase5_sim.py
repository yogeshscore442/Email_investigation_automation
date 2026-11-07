"""
Routes: Phase 5 SOC Attack Simulation & Detection Validation
Endpoints to execute, monitor, and audit harmless security simulations
against live Splunk indexes and evaluate SIEM detection rules.
"""

import sys
import json
from pathlib import Path
from flask import Blueprint, jsonify, request

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ..utils.auth import require_auth
from ..utils.splunk_client import splunk_client
from ..modules.siem_detection_engine import siem_detection_engine, DETECTION_RULES_CATALOG

# Import simulations
from simulations import (
    sim_ps01_powershell,
    sim_ps02_failed_auth,
    sim_ps03_network,
    sim_ps04_file_create,
    sim_ps05_registry,
    sim_ps06_process_access,
    sim_ps07_ioc_correlation,
    sim_ps08_incident_timeline
)

phase5_bp = Blueprint("phase5", __name__, url_prefix="/api/phase5")

CACHE_FILE = BASE_DIR / "data" / "phase5_simulation_cache.json"

def _load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_cache(data: dict):
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

@phase5_bp.route("/status", methods=["GET"])
@require_auth(required_role="analyst")
def get_simulation_status():
    """Returns the SIEM connection status and available simulation suites."""
    splunk_status = splunk_client.get_service_status()
    cached = _load_cache()
    
    simulations_catalog = [
        {"id": "PS-01", "name": "Suspicious PowerShell Execution", "event_type": "Sysmon Event ID 1 & PS 4104", "target": "powershell.exe"},
        {"id": "PS-02", "name": "Failed Authentication", "event_type": "Windows Security Event ID 4625", "target": "Phase5SecTestUser"},
        {"id": "PS-03", "name": "Network Connection Monitoring", "event_type": "Sysmon Event ID 3", "target": "127.0.0.1:5000"},
        {"id": "PS-04", "name": "File Creation Monitoring", "event_type": "Sysmon Event ID 11", "target": "phase5_marker.ps1"},
        {"id": "PS-05", "name": "Registry Monitoring", "event_type": "Sysmon Event ID 12/13", "target": "HKCU\\Software\\Phase5Lab"},
        {"id": "PS-06", "name": "Process Access Monitoring", "event_type": "Sysmon Event ID 10", "target": "Safe Handle Telemetry"},
        {"id": "PS-07", "name": "Email IOC Correlation", "event_type": "Multi-Index SIEM Pivot", "target": "credential_phishing_microsoft.eml"},
        {"id": "PS-08", "name": "Chronological Incident Timeline", "event_type": "Correlated SOC Timeline", "target": "Unified Incident"}
    ]

    return jsonify({
        "status": "operational",
        "splunk": splunk_status,
        "simulations": simulations_catalog,
        "detection_rules_count": len(DETECTION_RULES_CATALOG),
        "cached_results_count": len(cached)
    })

@phase5_bp.route("/rules", methods=["GET"])
@require_auth(required_role="analyst")
def get_detection_rules():
    """Returns the catalog of 6 formal SIEM detection rules."""
    return jsonify({
        "total_rules": len(DETECTION_RULES_CATALOG),
        "rules": list(DETECTION_RULES_CATALOG.values())
    })

@phase5_bp.route("/run/<test_id>", methods=["POST"])
@require_auth(required_role="analyst")
def execute_simulation(test_id):
    """Executes a specific simulation or all simulations."""
    test_id_upper = test_id.upper()
    cached = _load_cache()
    
    dispatch = {
        "PS-01": sim_ps01_powershell.run_simulation,
        "PS-02": sim_ps02_failed_auth.run_simulation,
        "PS-03": sim_ps03_network.run_simulation,
        "PS-04": sim_ps04_file_create.run_simulation,
        "PS-05": sim_ps05_registry.run_simulation,
        "PS-06": sim_ps06_process_access.run_simulation,
        "PS-07": sim_ps07_ioc_correlation.run_simulation,
        "PS-08": sim_ps08_incident_timeline.run_simulation
    }

    if test_id_upper == "ALL":
        results = {}
        for tid, func in dispatch.items():
            try:
                res = func()
                results[tid] = res
                cached[tid] = res
            except Exception as e:
                results[tid] = {"test_id": tid, "status": "LIVE FAILED", "error": str(e)}
                cached[tid] = results[tid]
        _save_cache(cached)
        return jsonify({"status": "completed", "executed": len(results), "results": results})

    if test_id_upper not in dispatch:
        return jsonify({"error": f"Invalid simulation ID '{test_id}'. Valid IDs: {list(dispatch.keys())} or ALL"}), 400

    try:
        sim_func = dispatch[test_id_upper]
        res = sim_func()
        cached[test_id_upper] = res
        _save_cache(cached)
        return jsonify({"status": "success", "result": res})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@phase5_bp.route("/results", methods=["GET"])
@require_auth(required_role="analyst")
def get_simulation_results():
    """Returns all latest simulation results and detection rule evaluations."""
    cached = _load_cache()
    
    # Evaluate detection rules against captured simulation evidence
    events_by_rule = {
        "DET-PS01": [cached["PS-01"]["extracted_evidence"]["sysmon"]] if "PS-01" in cached and "sysmon" in cached["PS-01"].get("extracted_evidence", {}) else [],
        "DET-AUTH02": [cached["PS-02"]["extracted_evidence"]] if "PS-02" in cached and "extracted_evidence" in cached["PS-02"] else [],
        "DET-NET03": [cached["PS-03"]["extracted_evidence"]] if "PS-03" in cached and "extracted_evidence" in cached["PS-03"] else [],
        "DET-FILE04": [cached["PS-04"]["extracted_evidence"]] if "PS-04" in cached and "extracted_evidence" in cached["PS-04"] else [],
        "DET-REG05": [cached["PS-05"]["extracted_evidence"]] if "PS-05" in cached and "extracted_evidence" in cached["PS-05"] else [],
        "DET-IOC06": [{"total_matches": cached["PS-07"].get("splunk_matches", 0), "anti_fabrication_verified": cached["PS-07"].get("anti_fabrication_verified", False)}] if "PS-07" in cached else []
    }

    detection_eval = siem_detection_engine.evaluate_all(events_by_rule)

    return jsonify({
        "simulations": cached,
        "detections": detection_eval
    })

@phase5_bp.route("/timeline", methods=["GET"])
@require_auth(required_role="analyst")
def get_phase5_timeline():
    """Returns the correlated incident timeline from PS-08."""
    cached = _load_cache()
    if "PS-08" in cached:
        return jsonify(cached["PS-08"])
    
    # Generate on demand if not cached
    res = sim_ps08_incident_timeline.run_simulation()
    cached["PS-08"] = res
    _save_cache(cached)
    return jsonify(res)
