import uuid
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Investigation(db.Model):
    __tablename__ = "investigations"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), default="pending")  # pending, completed, failed
    
    # Metadata
    subject = db.Column(db.String(500), default="[No Subject]")
    sender = db.Column(db.String(255), default="")
    sender_domain = db.Column(db.String(255), default="")
    recipient = db.Column(db.String(500), default="")
    cc = db.Column(db.String(500), default="")
    bcc = db.Column(db.String(500), default="")
    reply_to = db.Column(db.String(255), default="")
    message_id = db.Column(db.String(255), default="")
    email_date = db.Column(db.String(100), default="")
    
    # Verdicts & Risk Scoring
    verdict = db.Column(db.String(50), default="Pending")  # Legitimate, Suspicious, Phishing, Malicious BEC
    overall_risk_score = db.Column(db.Integer, default=0)
    risk_category = db.Column(db.String(20), default="Low")  # Low, Medium, High, Critical
    
    # Storage & Content
    raw_eml_path = db.Column(db.String(500), nullable=True)
    plain_body = db.Column(db.Text, default="")
    sanitized_html = db.Column(db.Text, default="")
    error_message = db.Column(db.Text, nullable=True)
    
    # Relationships
    headers = db.relationship("EmailHeader", backref="investigation", cascade="all, delete-orphan", lazy=True)
    hops = db.relationship("EmailHop", backref="investigation", cascade="all, delete-orphan", lazy=True)
    urls = db.relationship("EmailUrl", backref="investigation", cascade="all, delete-orphan", lazy=True)
    attachments = db.relationship("Attachment", backref="investigation", cascade="all, delete-orphan", lazy=True)
    rules = db.relationship("DetectionRuleHit", backref="investigation", cascade="all, delete-orphan", lazy=True)
    iocs = db.relationship("ExtractedIOC", backref="investigation", cascade="all, delete-orphan", lazy=True)
    auth_result = db.relationship("AuthenticationResult", uselist=False, backref="investigation", cascade="all, delete-orphan", lazy=True)
    risk_breakdown = db.relationship("RiskScoreBreakdown", uselist=False, backref="investigation", cascade="all, delete-orphan", lazy=True)
    ai_analysis = db.relationship("AiAnalysis", uselist=False, backref="investigation", cascade="all, delete-orphan", lazy=True)
    sender_intel = db.relationship("SenderDomainIntel", uselist=False, backref="investigation", cascade="all, delete-orphan", lazy=True)

    def to_summary_dict(self):
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "status": self.status,
            "subject": self.subject,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "recipient": self.recipient,
            "verdict": self.verdict,
            "overall_risk_score": self.overall_risk_score,
            "risk_category": self.risk_category,
            "urls_count": len(self.urls),
            "attachments_count": len(self.attachments),
            "rule_hits_count": len(self.rules)
        }

    def to_full_dict(self):
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "status": self.status,
            "subject": self.subject,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "recipient": self.recipient,
            "cc": self.cc,
            "bcc": self.bcc,
            "reply_to": self.reply_to,
            "message_id": self.message_id,
            "email_date": self.email_date,
            "verdict": self.verdict,
            "overall_risk_score": self.overall_risk_score,
            "risk_category": self.risk_category,
            "plain_body": self.plain_body,
            "sanitized_html": self.sanitized_html,
            "headers": [h.to_dict() for h in self.headers],
            "hops": [hop.to_dict() for hop in sorted(self.hops, key=lambda x: x.hop_number)],
            "auth_result": self.auth_result.to_dict() if self.auth_result else None,
            "sender_intel": self.sender_intel.to_dict() if self.sender_intel else None,
            "urls": [u.to_dict() for u in self.urls],
            "attachments": [a.to_dict() for a in self.attachments],
            "rules": [r.to_dict() for r in self.rules],
            "iocs": [i.to_dict() for i in self.iocs],
            "risk_breakdown": self.risk_breakdown.to_dict() if self.risk_breakdown else None,
            "ai_analysis": self.ai_analysis.to_dict() if self.ai_analysis else None
        }

class EmailHeader(db.Model):
    __tablename__ = "email_headers"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, index=True)
    name = db.Column(db.String(150), nullable=False)
    value = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {"name": self.name, "value": self.value}

class EmailHop(db.Model):
    __tablename__ = "email_hops"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, index=True)
    hop_number = db.Column(db.Integer, nullable=False)
    from_server = db.Column(db.String(255), default="")
    by_server = db.Column(db.String(255), default="")
    ip_address = db.Column(db.String(100), default="")
    protocol = db.Column(db.String(50), default="")
    timestamp_str = db.Column(db.String(100), default="")
    delay_seconds = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "hop_number": self.hop_number,
            "from_server": self.from_server,
            "by_server": self.by_server,
            "ip_address": self.ip_address,
            "protocol": self.protocol,
            "timestamp_str": self.timestamp_str,
            "delay_seconds": self.delay_seconds
        }

class AuthenticationResult(db.Model):
    __tablename__ = "authentication_results"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, unique=True)
    spf_status = db.Column(db.String(50), default="none")  # pass, fail, softfail, neutral, none
    spf_details = db.Column(db.String(500), default="")
    dkim_status = db.Column(db.String(50), default="none")  # pass, fail, none
    dkim_details = db.Column(db.String(500), default="")
    dmarc_status = db.Column(db.String(50), default="none")  # pass, fail, none
    dmarc_details = db.Column(db.String(500), default="")
    raw_auth_results = db.Column(db.Text, default="")
    x_originating_ip = db.Column(db.String(100), default="")

    def to_dict(self):
        return {
            "spf_status": self.spf_status,
            "spf_details": self.spf_details,
            "dkim_status": self.dkim_status,
            "dkim_details": self.dkim_details,
            "dmarc_status": self.dmarc_status,
            "dmarc_details": self.dmarc_details,
            "x_originating_ip": self.x_originating_ip,
            "raw_auth_results": self.raw_auth_results
        }

class SenderDomainIntel(db.Model):
    __tablename__ = "sender_domain_intel"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, unique=True)
    domain = db.Column(db.String(255), default="")
    ip_address = db.Column(db.String(100), default="")
    mx_records = db.Column(db.Text, default="[]")  # JSON serialized
    spf_record = db.Column(db.Text, default="")
    dmarc_record = db.Column(db.Text, default="")
    domain_age_days = db.Column(db.Integer, nullable=True)
    registrar = db.Column(db.String(255), default="Unknown")
    is_lookalike = db.Column(db.Boolean, default=False)
    targeted_brand = db.Column(db.String(100), default="")
    ip_abuse_score = db.Column(db.Integer, default=0)
    ip_reputation = db.Column(db.String(50), default="unknown")
    domain_reputation = db.Column(db.String(50), default="unknown")

    def to_dict(self):
        import json
        return {
            "domain": self.domain,
            "ip_address": self.ip_address,
            "mx_records": json.loads(self.mx_records) if self.mx_records else [],
            "spf_record": self.spf_record,
            "dmarc_record": self.dmarc_record,
            "domain_age_days": self.domain_age_days,
            "registrar": self.registrar,
            "is_lookalike": self.is_lookalike,
            "targeted_brand": self.targeted_brand,
            "ip_abuse_score": self.ip_abuse_score,
            "ip_reputation": self.ip_reputation,
            "domain_reputation": self.domain_reputation
        }

class EmailUrl(db.Model):
    __tablename__ = "email_urls"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, index=True)
    original_url = db.Column(db.Text, nullable=False)
    defanged_url = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(255), default="")
    is_ip_based = db.Column(db.Boolean, default=False)
    is_shortened = db.Column(db.Boolean, default=False)
    has_suspicious_tld = db.Column(db.Boolean, default=False)
    brand_spoofed = db.Column(db.String(100), default="")
    detection_flags = db.Column(db.Text, default="[]")  # JSON serialized
    vt_reputation = db.Column(db.String(50), default="unknown")
    urlscan_verdict = db.Column(db.String(50), default="unknown")

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "original_url": self.original_url,
            "defanged_url": self.defanged_url,
            "domain": self.domain,
            "is_ip_based": self.is_ip_based,
            "is_shortened": self.is_shortened,
            "has_suspicious_tld": self.has_suspicious_tld,
            "brand_spoofed": self.brand_spoofed,
            "detection_flags": json.loads(self.detection_flags) if self.detection_flags else [],
            "vt_reputation": self.vt_reputation,
            "urlscan_verdict": self.urlscan_verdict
        }

class Attachment(db.Model):
    __tablename__ = "attachments"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    reported_mime = db.Column(db.String(100), default="")
    detected_mime = db.Column(db.String(100), default="")
    is_mismatch = db.Column(db.Boolean, default=False)
    sha256 = db.Column(db.String(64), default="")
    md5 = db.Column(db.String(32), default="")
    has_macro = db.Column(db.Boolean, default=False)
    is_dangerous_extension = db.Column(db.Boolean, default=False)
    vt_reputation = db.Column(db.String(50), default="unknown")
    vt_malicious_votes = db.Column(db.Integer, default=0)
    macro_findings = db.Column(db.Text, default="[]")  # JSON serialized

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "filename": self.filename,
            "file_size": self.file_size,
            "reported_mime": self.reported_mime,
            "detected_mime": self.detected_mime,
            "is_mismatch": self.is_mismatch,
            "sha256": self.sha256,
            "md5": self.md5,
            "has_macro": self.has_macro,
            "is_dangerous_extension": self.is_dangerous_extension,
            "vt_reputation": self.vt_reputation,
            "vt_malicious_votes": self.vt_malicious_votes,
            "macro_findings": json.loads(self.macro_findings) if self.macro_findings else []
        }

class DetectionRuleHit(db.Model):
    __tablename__ = "detection_rule_hits"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, index=True)
    rule_id = db.Column(db.String(100), nullable=False)
    rule_name = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), default="low")  # info, low, medium, high, critical
    category = db.Column(db.String(50), default="general")
    weight = db.Column(db.Integer, default=10)
    description = db.Column(db.Text, default="")
    evidence = db.Column(db.Text, default="")

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "weight": self.weight,
            "description": self.description,
            "evidence": self.evidence
        }

class ExtractedIOC(db.Model):
    __tablename__ = "extracted_iocs"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, index=True)
    ioc_type = db.Column(db.String(50), nullable=False)  # ipv4, domain, url, email, sha256, md5, filename
    ioc_value = db.Column(db.Text, nullable=False)
    defanged_value = db.Column(db.Text, nullable=False)
    reputation = db.Column(db.String(50), default="unknown")  # clean, suspicious, malicious, unknown
    context = db.Column(db.String(255), default="")
    provider = db.Column(db.String(50), default="heuristic")  # virustotal, abuseipdb, urlscan, rdap, heuristic
    confidence = db.Column(db.Integer, default=0)  # 0 to 100
    lookup_timestamp = db.Column(db.String(50), default="")  # ISO format string
    api_status = db.Column(db.String(50), default="not_queried")  # success, not_configured, rate_limited, invalid_api_key, error

    def to_dict(self):
        return {
            "id": self.id,
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "defanged_value": self.defanged_value,
            "reputation": self.reputation,
            "context": self.context,
            "provider": self.provider or "heuristic",
            "confidence": self.confidence or 0,
            "lookup_timestamp": self.lookup_timestamp or "",
            "api_status": self.api_status or "not_queried"
        }

class RiskScoreBreakdown(db.Model):
    __tablename__ = "risk_score_breakdowns"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, unique=True)
    auth_score = db.Column(db.Integer, default=0)
    sender_score = db.Column(db.Integer, default=0)
    url_score = db.Column(db.Integer, default=0)
    attachment_score = db.Column(db.Integer, default=0)
    content_score = db.Column(db.Integer, default=0)
    total_score = db.Column(db.Integer, default=0)
    explanation_json = db.Column(db.Text, default="[]")

    def to_dict(self):
        import json
        return {
            "auth_score": self.auth_score,
            "sender_score": self.sender_score,
            "url_score": self.url_score,
            "attachment_score": self.attachment_score,
            "content_score": self.content_score,
            "total_score": self.total_score,
            "factors": json.loads(self.explanation_json) if self.explanation_json else []
        }

class AiAnalysis(db.Model):
    __tablename__ = "ai_analyses"
    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey("investigations.id"), nullable=False, unique=True)
    executive_summary = db.Column(db.Text, default="")
    technical_summary = db.Column(db.Text, default="")
    mitre_attack_json = db.Column(db.Text, default="[]")
    recommended_actions_json = db.Column(db.Text, default="[]")
    model_used = db.Column(db.String(50), default="Deterministic Rule Heuristic Engine")

    def to_dict(self):
        import json
        return {
            "executive_summary": self.executive_summary,
            "technical_summary": self.technical_summary,
            "mitre_attack": json.loads(self.mitre_attack_json) if self.mitre_attack_json else [],
            "recommended_actions": json.loads(self.recommended_actions_json) if self.recommended_actions_json else [],
            "model_used": self.model_used
        }

