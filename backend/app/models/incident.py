import uuid
import json
from datetime import datetime
from .investigation import db

incident_investigations = db.Table(
    "incident_investigations",
    db.Column("incident_id", db.String(36), db.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    db.Column("investigation_id", db.String(36), db.ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True)
)

class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_number = db.Column(db.String(30), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), default="Medium", index=True)  # Low, Medium, High, Critical
    status = db.Column(db.String(20), default="New", index=True)  # New, Investigating, Contained, Closed
    campaign_name = db.Column(db.String(255), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    summary = db.Column(db.Text, default="")
    
    # Correlated entity aggregates stored as JSON
    affected_users_json = db.Column(db.Text, default="[]")
    affected_endpoints_json = db.Column(db.Text, default="[]")
    correlated_iocs_json = db.Column(db.Text, default="[]")
    
    # Relationships
    investigations = db.relationship(
        "Investigation",
        secondary=incident_investigations,
        backref=db.backref("incidents", lazy="dynamic"),
        lazy="joined"
    )
    timeline_events = db.relationship("IncidentTimelineEvent", backref="incident", cascade="all, delete-orphan", lazy="dynamic")
    playbook_actions = db.relationship("PlaybookAction", backref="incident", cascade="all, delete-orphan", lazy="dynamic")

    def to_summary_dict(self):
        affected_users = json.loads(self.affected_users_json) if self.affected_users_json else []
        affected_endpoints = json.loads(self.affected_endpoints_json) if self.affected_endpoints_json else []
        correlated_iocs = json.loads(self.correlated_iocs_json) if self.correlated_iocs_json else []
        
        return {
            "id": self.id,
            "incident_number": self.incident_number,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "campaign_name": self.campaign_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "summary": self.summary,
            "investigations_count": len(self.investigations),
            "affected_users_count": len(affected_users),
            "affected_endpoints_count": len(affected_endpoints),
            "correlated_iocs_count": len(correlated_iocs)
        }

    def to_full_dict(self):
        affected_users = json.loads(self.affected_users_json) if self.affected_users_json else []
        affected_endpoints = json.loads(self.affected_endpoints_json) if self.affected_endpoints_json else []
        correlated_iocs = json.loads(self.correlated_iocs_json) if self.correlated_iocs_json else []
        
        # Sort timeline chronologically
        events = sorted(self.timeline_events.all(), key=lambda e: e.timestamp or "")
        actions = sorted(self.playbook_actions.all(), key=lambda a: a.id)

        return {
            "id": self.id,
            "incident_number": self.incident_number,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "campaign_name": self.campaign_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "summary": self.summary,
            "affected_users": affected_users,
            "affected_endpoints": affected_endpoints,
            "correlated_iocs": correlated_iocs,
            "investigations": [inv.to_summary_dict() for inv in self.investigations],
            "timeline": [e.to_dict() for e in events],
            "playbook_actions": [a.to_dict() for a in actions]
        }

class IncidentTimelineEvent(db.Model):
    __tablename__ = "incident_timeline_events"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(36), db.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = db.Column(db.String(50), nullable=False)  # ISO string or header date
    phase = db.Column(db.String(50), default="Delivery")  # Delivery, Execution, Credential Access, C2, Containment
    source = db.Column(db.String(50), default="Email Gateway")  # Email Gateway, Splunk Proxy, Sysmon, Wazuh EDR, Analyst
    title = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, default="")
    telemetry_status = db.Column(db.String(30), default="confirmed")  # confirmed, inferred, unavailable_telemetry
    raw_event_json = db.Column(db.Text, default="{}")

    def to_dict(self):
        raw_event = json.loads(self.raw_event_json) if self.raw_event_json else {}
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "phase": self.phase,
            "source": self.source,
            "title": self.title,
            "details": self.details,
            "telemetry_status": self.telemetry_status,
            "raw_event": raw_event
        }

class PlaybookAction(db.Model):
    __tablename__ = "playbook_actions"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(36), db.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = db.Column(db.String(50), nullable=False)  # quarantine_email, block_domain, isolate_endpoint, revoke_session, reset_password
    title = db.Column(db.String(255), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, default="")
    severity = db.Column(db.String(20), default="Medium")  # Low, Medium, High, Critical
    requires_approval = db.Column(db.Boolean, default=True)
    approval_status = db.Column(db.String(20), default="pending_approval")  # pending_approval, approved, rejected, executed
    approved_by = db.Column(db.String(100), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    execution_log = db.Column(db.Text, default="")

    def to_dict(self):
        return {
            "id": self.id,
            "action_type": self.action_type,
            "title": self.title,
            "target": self.target,
            "details": self.details,
            "severity": self.severity,
            "requires_approval": self.requires_approval,
            "approval_status": self.approval_status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "execution_log": self.execution_log
        }

