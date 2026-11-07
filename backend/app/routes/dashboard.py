from flask import Blueprint, jsonify
from sqlalchemy import func
from ..models import db, Investigation, ExtractedIOC
from ..config import Config
from ..utils.threat_intel import threat_intel

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api")

def get_integrations_payload():
    """Generates detailed integration operational and telemetry status."""
    has_openai = bool(Config.OPENAI_API_KEY or (Config.AI_PROVIDER == "openai" and Config.AI_API_KEY))
    has_gemini = bool(Config.AI_PROVIDER == "gemini" and Config.AI_API_KEY)
    
    vt_status = threat_intel.get_provider_status("virustotal")
    abuse_status = threat_intel.get_provider_status("abuseipdb")
    urlscan_status = threat_intel.get_provider_status("urlscan")

    return {
        "virustotal": {
            "name": "VirusTotal API v3",
            "type": "threat_intel",
            "status": vt_status.get("status", "operational" if Config.VIRUSTOTAL_API_KEY else "not_configured"),
            "mode": vt_status.get("mode", "live" if Config.VIRUSTOTAL_API_KEY else "degraded"),
            "capabilities": ["Domain Reputation", "IP Reputation", "URL Reputation", "File Hash Analysis (SHA256/MD5)"],
            "rate_limit_handled": True,
            "last_checked": vt_status.get("last_checked"),
            "last_successful_check": vt_status.get("last_successful_check")
        },
        "abuseipdb": {
            "name": "AbuseIPDB API v2",
            "type": "threat_intel",
            "status": abuse_status.get("status", "operational" if Config.ABUSEIPDB_API_KEY else "not_configured"),
            "mode": abuse_status.get("mode", "live" if Config.ABUSEIPDB_API_KEY else "degraded"),
            "capabilities": ["IP Confidence Score", "Abuse Reports Count", "ISP & Geolocation Analysis"],
            "rate_limit_handled": True,
            "last_checked": abuse_status.get("last_checked"),
            "last_successful_check": abuse_status.get("last_successful_check")
        },
        "urlscan": {
            "name": "URLScan.io API v1",
            "type": "threat_intel",
            "status": urlscan_status.get("status", "operational" if Config.URLSCAN_API_KEY else "not_configured"),
            "mode": urlscan_status.get("mode", "live" if Config.URLSCAN_API_KEY else "degraded"),
            "capabilities": ["Automated URL Submission", "Screenshot Capture", "Contacted Domains Extraction"],
            "rate_limit_handled": True,
            "last_checked": urlscan_status.get("last_checked"),
            "last_successful_check": urlscan_status.get("last_successful_check")
        },
        "ai_llm": {
            "name": f"AI LLM Engine ({Config.AI_PROVIDER.upper()})" if (has_openai or has_gemini) else "AI LLM Engine (Offline / Fallback)",
            "type": "ai_engine",
            "status": "configured" if (has_openai or has_gemini) else "not_configured",
            "mode": "live" if (has_openai or has_gemini) else "heuristic_fallback",
            "provider": Config.AI_PROVIDER if (has_openai or has_gemini) else "deterministic_heuristics",
            "model": Config.AI_MODEL if (has_openai or has_gemini) else "SOC Rules Expert Matrix",
            "capabilities": ["Executive Incident Summary", "Technical DFIR Analysis", "MITRE ATT&CK Grounding", "SOC Incident Playbooks"]
        },
        "rdap": {
            "name": "Open RDAP Protocol (ICANN / ARIN)",
            "type": "open_intelligence",
            "status": "operational",
            "mode": "live",
            "capabilities": ["Domain Registration Age", "Registrar Verification", "Autonomous System (ASN) Lookup"]
        }
    }

@dashboard_bp.route("/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """Aggregates metrics and statistics for the SOC Dashboard."""
    total_count = Investigation.query.count()
    
    # Counts by risk category
    low_risk = Investigation.query.filter(Investigation.risk_category == "Low").count()
    med_risk = Investigation.query.filter(Investigation.risk_category == "Medium").count()
    high_risk = Investigation.query.filter(Investigation.risk_category == "High").count()
    crit_risk = Investigation.query.filter(Investigation.risk_category == "Critical").count()

    # Verdict groupings
    phishing_count = Investigation.query.filter(
        Investigation.verdict.in_(["Phishing", "Critical Phishing / Malware"])
    ).count()
    legitimate_count = Investigation.query.filter(Investigation.verdict == "Legitimate").count()
    suspicious_count = Investigation.query.filter(Investigation.verdict == "Suspicious").count()

    # Risk Distribution Chart series
    risk_distribution = [
        {"name": "Low Risk (0-29)", "count": low_risk, "color": "#22c55e"},
        {"name": "Medium Risk (30-59)", "count": med_risk, "color": "#eab308"},
        {"name": "High Risk (60-79)", "count": high_risk, "color": "#f97316"},
        {"name": "Critical Risk (80-100)", "count": crit_risk, "color": "#ef4444"}
    ]

    # IOC Statistics
    ioc_types_query = db.session.query(
        ExtractedIOC.ioc_type, func.count(ExtractedIOC.id)
    ).group_by(ExtractedIOC.ioc_type).all()

    ioc_stats = {t: c for t, c in ioc_types_query}
    total_iocs = ExtractedIOC.query.count()

    # Recent Investigations (Last 6)
    recents = Investigation.query.order_by(Investigation.created_at.desc()).limit(6).all()

    return jsonify({
        "metrics": {
            "total_investigated": total_count,
            "phishing_detected": phishing_count,
            "legitimate_count": legitimate_count,
            "suspicious_count": suspicious_count,
            "high_risk_count": high_risk,
            "critical_risk_count": crit_risk,
            "total_iocs_extracted": total_iocs
        },
        "risk_distribution": risk_distribution,
        "ioc_stats": {
            "urls": ioc_stats.get("url", 0),
            "domains": ioc_stats.get("domain", 0),
            "ips": ioc_stats.get("ipv4", 0),
            "hashes": ioc_stats.get("sha256", 0) + ioc_stats.get("md5", 0),
            "emails": ioc_stats.get("email", 0),
            "files": ioc_stats.get("filename", 0)
        },
        "integrations": get_integrations_payload(),
        "recent_investigations": [r.to_summary_dict() for r in recents]
    })

@dashboard_bp.route("/dashboard/integrations", methods=["GET"])
def get_dashboard_integrations():
    """Returns detailed operational statuses for all external intelligence providers."""
    return jsonify(get_integrations_payload())

@dashboard_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint and threat intelligence configuration status."""
    return jsonify({
        "status": "operational",
        "service": "AI-Powered Automated Email Investigation & Phishing Detection System",
        "version": "1.0.0",
        "integrations": {
            k: f"{v['status']} ({v['mode']})" for k, v in get_integrations_payload().items()
        }
    })

