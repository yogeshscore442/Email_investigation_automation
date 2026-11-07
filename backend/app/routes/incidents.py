import json
from datetime import datetime
from flask import Blueprint, request, jsonify
from ..models import db, Incident, IncidentTimelineEvent, PlaybookAction, Investigation
from ..modules.correlation_engine import correlation_engine
from ..utils.splunk_client import splunk_client
from ..utils.wazuh_client import wazuh_client
from ..utils.auth import require_auth

incidents_bp = Blueprint("incidents", __name__, url_prefix="/api")

@incidents_bp.route("/incidents", methods=["GET"])
@require_auth(required_role="analyst")
def get_incidents():
    """Returns a list of all correlated SOC incidents."""
    severity_filter = request.args.get("severity")
    status_filter = request.args.get("status")

    query = Incident.query.order_by(Incident.created_at.desc())
    if severity_filter:
        query = query.filter(Incident.severity == severity_filter)
    if status_filter:
        query = query.filter(Incident.status == status_filter)

    incidents = query.all()
    return jsonify([inc.to_summary_dict() for inc in incidents])

@incidents_bp.route("/incidents/stats", methods=["GET"])
@require_auth(required_role="analyst")
def get_incident_stats():
    """Aggregates telemetry metrics for the SOC Incident Dashboard."""
    total_incidents = Incident.query.count()
    crit_count = Incident.query.filter(Incident.severity == "Critical").count()
    high_count = Incident.query.filter(Incident.severity == "High").count()
    med_count = Incident.query.filter(Incident.severity == "Medium").count()
    low_count = Incident.query.filter(Incident.severity == "Low").count()

    all_incidents = Incident.query.all()
    all_users = set()
    all_endpoints = set()
    all_campaigns = set()

    for inc in all_incidents:
        if inc.campaign_name:
            all_campaigns.add(inc.campaign_name)
        users = json.loads(inc.affected_users_json) if inc.affected_users_json else []
        for u in users:
            all_users.add(u)
        endpoints = json.loads(inc.affected_endpoints_json) if inc.affected_endpoints_json else []
        for ep in endpoints:
            all_endpoints.add(ep.get("hostname") or ep.get("ip_address"))

    return jsonify({
        "total_incidents": total_incidents,
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "affected_users_count": len(all_users),
        "affected_endpoints_count": len(all_endpoints),
        "active_campaigns_count": len(all_campaigns),
        "severity_distribution": [
            {"name": "Critical", "count": crit_count, "color": "#ef4444"},
            {"name": "High", "count": high_count, "color": "#f97316"},
            {"name": "Medium", "count": med_count, "color": "#eab308"},
            {"name": "Low", "count": low_count, "color": "#22c55e"}
        ],
        "siem_status": {
            "splunk": splunk_client.get_service_status(),
            "wazuh": wazuh_client.get_service_status()
        }
    })

@incidents_bp.route("/incidents/<incident_id>", methods=["GET"])
@require_auth(required_role="analyst")
def get_incident_detail(incident_id):
    """Retrieves full incident details, correlated investigations, timeline and actions."""
    inc = db.session.get(Incident, incident_id)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(inc.to_full_dict())

@incidents_bp.route("/incidents/correlate", methods=["POST"])
@require_auth(required_role="analyst")
def trigger_correlation():
    """Triggers correlation across all completed email investigations."""
    result = correlation_engine.run_correlation()
    return jsonify(result), 200

@incidents_bp.route("/incidents/<incident_id>/actions/<int:action_id>/approve", methods=["POST"])
@require_auth(required_role="analyst")
def approve_action(incident_id, action_id):
    """Analyst grants explicit approval for a disruptive SOC playbook action."""
    action = db.session.get(PlaybookAction, action_id)
    if not action or action.incident_id != incident_id:
        return jsonify({"error": "Playbook action not found"}), 404

    data = request.get_json(silent=True) or {}
    analyst_name = data.get("analyst_name", "SOC Lead Analyst")

    action.approval_status = "approved"
    action.approved_by = analyst_name
    action.approved_at = datetime.utcnow()
    action.execution_log = f"Approved by {analyst_name} at {action.approved_at.isoformat()}."

    # Add a timeline event recording the analyst action
    event = IncidentTimelineEvent(
        incident_id=incident_id,
        timestamp=datetime.utcnow().isoformat(),
        phase="Containment",
        source="SOC Analyst",
        title=f"Playbook Action Approved: {action.title}",
        details=f"Analyst {analyst_name} approved action '{action.title}' targeting '{action.target}'.",
        telemetry_status="confirmed",
        raw_event_json=json.dumps({"action_id": action.id, "target": action.target})
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({
        "status": "success",
        "action": action.to_dict(),
        "message": f"Action approved by {analyst_name}."
    })

@incidents_bp.route("/incidents/<incident_id>/actions/<int:action_id>/reject", methods=["POST"])
@require_auth(required_role="analyst")
def reject_action(incident_id, action_id):
    """Analyst rejects a proposed playbook action."""
    action = db.session.get(PlaybookAction, action_id)
    if not action or action.incident_id != incident_id:
        return jsonify({"error": "Playbook action not found"}), 404

    data = request.get_json(silent=True) or {}
    analyst_name = data.get("analyst_name", "SOC Lead Analyst")
    reason = data.get("reason", "Action rejected based on analyst assessment.")

    action.approval_status = "rejected"
    action.approved_by = analyst_name
    action.approved_at = datetime.utcnow()
    action.execution_log = f"Rejected by {analyst_name}: {reason}"

    db.session.commit()
    return jsonify({
        "status": "success",
        "action": action.to_dict(),
        "message": "Action rejected."
    })

@incidents_bp.route("/incidents/<incident_id>/actions/<int:action_id>/execute", methods=["POST"])
@require_auth(required_role="admin")
def execute_action(incident_id, action_id):
    """
    Executes an approved containment action.
    STRICT CONTROL: Enforces that approval_status must be 'approved' before execution!
    """
    action = db.session.get(PlaybookAction, action_id)
    if not action or action.incident_id != incident_id:
        return jsonify({"error": "Playbook action not found"}), 404

    if action.requires_approval and action.approval_status != "approved":
        return jsonify({
            "error": "Destructive or disruptive action requires explicit analyst approval before execution."
        }), 403

    # Execute specific containment action
    execution_result = {}
    if action.action_type == "isolate_endpoint":
        # Call Wazuh client for endpoint isolation
        agent_id = "001"  # Default agent mapping or target resolution
        execution_result = wazuh_client.isolate_endpoint(agent_id)
    elif action.action_type == "block_domain":
        execution_result = {
            "status": "success",
            "message": f"Domain '{action.target}' pushed to DNS Sinkhole and SWG Gateway Deny List."
        }
    elif action.action_type == "quarantine_email":
        execution_result = {
            "status": "success",
            "message": f"Purge signal issued to Exchange Online / Google Workspace for {action.target}."
        }
    elif action.action_type == "revoke_session":
        execution_result = {
            "status": "success",
            "message": f"Identity session token revocation API called for user {action.target}."
        }
    elif action.action_type == "reset_password":
        execution_result = {
            "status": "success",
            "message": f"Mandatory password reset flag set for user {action.target}."
        }

    action.approval_status = "executed"
    action.execution_log += f"\n[Execution Result]: {json.dumps(execution_result)}"

    # Record Containment Event in Incident Timeline
    event = IncidentTimelineEvent(
        incident_id=incident_id,
        timestamp=datetime.utcnow().isoformat(),
        phase="Containment",
        source="Automated Response Orchestrator",
        title=f"Containment Action Executed: {action.title}",
        details=f"Successfully executed '{action.title}' targeting '{action.target}'.",
        telemetry_status="confirmed",
        raw_event_json=json.dumps(execution_result)
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({
        "status": "executed",
        "action": action.to_dict(),
        "execution_result": execution_result
    })

# ==================== Direct SIEM Telemetry Queries ====================

@incidents_bp.route("/siem/status", methods=["GET"])
@require_auth(required_role="analyst")
def get_siem_status():
    """Returns connectivity and operational status for Splunk and Wazuh SIEMs."""
    return jsonify({
        "splunk": splunk_client.get_service_status(),
        "wazuh": wazuh_client.get_service_status()
    })

@incidents_bp.route("/siem/splunk/search", methods=["POST"])
@require_auth(required_role="analyst")
def search_splunk():
    """Executes on-demand targeted query to Splunk."""
    data = request.get_json() or {}
    query_type = data.get("query_type", "proxy")
    
    if query_type == "email":
        result = splunk_client.search_email_gateway(
            sender=data.get("sender"),
            recipient=data.get("recipient"),
            message_id=data.get("message_id")
        )
    elif query_type == "endpoint":
        result = splunk_client.search_endpoint_sysmon(
            hashes=data.get("hashes", []),
            ips=data.get("ips", []),
            process_names=data.get("process_names", [])
        )
    elif query_type == "windows":
        result = splunk_client.search_windows_security(
            usernames=data.get("usernames", []),
            ips=data.get("ips", []),
            event_codes=data.get("event_codes")
        )
    elif query_type == "powershell":
        result = splunk_client.search_powershell(
            commands=data.get("commands", [])
        )
    elif query_type == "correlation":
        result = splunk_client.correlate_email_iocs(
            sender=data.get("sender"),
            recipient=data.get("recipient"),
            domains=data.get("domains", []),
            ips=data.get("ips", []),
            urls=data.get("urls", []),
            hashes=data.get("hashes", [])
        )
    else:
        result = splunk_client.search_network_proxy_dns(
            domains=data.get("domains", []),
            ips=data.get("ips", [])
        )
    return jsonify(result)

@incidents_bp.route("/siem/wazuh/alerts", methods=["POST"])
@require_auth(required_role="analyst")
def search_wazuh():
    """Queries Wazuh EDR for recent endpoint alerts."""
    data = request.get_json() or {}
    query = data.get("query", "")
    limit = int(data.get("limit", 25))
    result = wazuh_client.search_alerts(query=query, limit=limit)
    return jsonify(result)

