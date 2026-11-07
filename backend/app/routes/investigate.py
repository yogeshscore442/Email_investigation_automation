import os
import uuid
from pathlib import Path
from flask import Blueprint, request, jsonify, Response, send_file
from werkzeug.utils import secure_filename
from ..models import db, Investigation, ExtractedIOC
from ..orchestrator import orchestrator
from ..modules.ioc_extractor import ioc_extractor
from ..modules.report_gen import report_generator
from ..utils.auth import require_auth
from ..extensions import limiter
from ..config import Config
import io

investigate_bp = Blueprint("investigate", __name__, url_prefix="/api")

@investigate_bp.route("/investigate/upload", methods=["POST"])
@limiter.limit(Config.RATELIMIT_UPLOAD)
@require_auth(required_role="analyst")
def upload_email():
    """Uploads and investigates .eml or .msg file with deep validation."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Please upload a .eml or .msg file."}), 400

    uploaded_file = request.files["file"]
    filename = secure_filename(uploaded_file.filename or "")
    if not filename:
        return jsonify({"error": "Filename is missing or invalid."}), 400

    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".eml", ".msg", ".txt"]:
        return jsonify({"error": f"Unsupported file type '{ext}'. Supported formats: .eml, .msg"}), 400

    # Read bytes for payload validation
    raw_bytes = uploaded_file.read()
    if not raw_bytes or len(raw_bytes) == 0:
        return jsonify({"error": "Uploaded file is empty (0 bytes). Please upload valid email evidence."}), 400

    # Content-Level Security Validation: Block direct binaries masquerading as .eml
    if raw_bytes.startswith(b"MZ") or raw_bytes.startswith(b"\x7fELF"):
        return jsonify({
            "error": "Malicious payload rejected: Executable binary detected masquerading with an email file extension.",
            "status": 400
        }), 400

    # Content-Level Security Validation for Outlook .msg (must be OLE2 compound binary)
    if ext == ".msg":
        if not raw_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return jsonify({
                "error": "Malformed file rejected: File has .msg extension but lacks valid Outlook OLE2 compound binary headers.",
                "status": 400
            }), 400

    try:
        if ext == ".msg":
            safe_temp_name = f"temp_{uuid.uuid4().hex[:8]}_{filename}"
            temp_path = Config.STORAGE_DIR / safe_temp_name
            with open(temp_path, "wb") as f:
                f.write(raw_bytes)
            inv = orchestrator.investigate_msg_file(str(temp_path))
        else:
            inv = orchestrator.investigate_eml_bytes(raw_bytes, filename)

        return jsonify({
            "message": "Email investigated successfully.",
            "investigation_id": inv.id,
            "verdict": inv.verdict,
            "overall_risk_score": inv.overall_risk_score,
            "risk_category": inv.risk_category
        }), 201

    except Exception as e:
        return jsonify({"error": f"Investigation failed: {str(e)}"}), 500

@investigate_bp.route("/investigate/headers", methods=["POST"])
@require_auth(required_role="analyst")
def investigate_headers():
    """Investigates pasted raw headers and body."""
    data = request.get_json() or {}
    raw_headers = data.get("raw_headers", "").strip()
    raw_body = data.get("raw_body", "").strip()

    if not raw_headers:
        return jsonify({"error": "No raw headers provided."}), 400

    try:
        inv = orchestrator.investigate_raw_headers_and_body(raw_headers, raw_body)
        return jsonify({
            "message": "Headers investigated successfully.",
            "investigation_id": inv.id,
            "verdict": inv.verdict,
            "overall_risk_score": inv.overall_risk_score,
            "risk_category": inv.risk_category
        }), 201
    except Exception as e:
        return jsonify({"error": f"Header investigation failed: {str(e)}"}), 500

@investigate_bp.route("/investigations", methods=["GET"])
@require_auth(required_role="analyst")
def list_investigations():
    """Lists investigations with optional pagination and filtering."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    verdict_filter = request.args.get("verdict", "")
    risk_filter = request.args.get("risk_category", "")

    query = Investigation.query.order_by(Investigation.created_at.desc())
    if verdict_filter:
        query = query.filter(Investigation.verdict == verdict_filter)
    if risk_filter:
        query = query.filter(Investigation.risk_category == risk_filter)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "investigations": [inv.to_summary_dict() for inv in pagination.items]
    })

@investigate_bp.route("/investigate/<string:inv_id>", methods=["GET"])
@require_auth(required_role="analyst")
def get_investigation(inv_id):
    """Retrieves full investigation forensic dossier."""
    inv = db.session.get(Investigation, inv_id)
    if not inv:
        return jsonify({"error": "Investigation record not found."}), 404
    return jsonify(inv.to_full_dict())

@investigate_bp.route("/investigate/<string:inv_id>/iocs", methods=["GET"])
@require_auth(required_role="analyst")
def get_investigation_iocs(inv_id):
    """Retrieves IOCs for a specific investigation."""
    inv = db.session.get(Investigation, inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found."}), 404

    iocs = [i.to_dict() for i in inv.iocs]
    return jsonify({
        "investigation_id": inv.id,
        "total_iocs": len(iocs),
        "iocs": iocs
    })

@investigate_bp.route("/investigate/<string:inv_id>/iocs/export", methods=["GET"])
@require_auth(required_role="analyst")
def export_iocs(inv_id):
    """Exports IOCs in CSV or JSON format."""
    inv = db.session.get(Investigation, inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found."}), 404

    fmt = request.args.get("format", "csv").lower()
    iocs_data = [i.to_dict() for i in inv.iocs]

    if fmt == "json":
        json_str = ioc_extractor.export_json(iocs_data)
        return Response(
            json_str,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment;filename=iocs_{inv_id[:8]}.json"}
        )
    else:
        csv_str = ioc_extractor.export_csv(iocs_data)
        return Response(
            csv_str,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=iocs_{inv_id[:8]}.csv"}
        )

@investigate_bp.route("/investigate/<string:inv_id>/report", methods=["GET"])
@require_auth(required_role="analyst")
def get_soc_report(inv_id):
    """Generates structured SOC report JSON."""
    inv = db.session.get(Investigation, inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found."}), 404

    rpt = report_generator.generate_json_report(inv.to_full_dict())
    return jsonify(rpt)

@investigate_bp.route("/investigate/<string:inv_id>/report/html", methods=["GET"])
@require_auth(required_role="analyst")
def get_soc_report_html(inv_id):
    """Renders printable HTML SOC report."""
    inv = db.session.get(Investigation, inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found."}), 404

    html_content = report_generator.generate_html_report(inv.to_full_dict())
    return Response(html_content, mimetype="text/html")

@investigate_bp.route("/investigate/<string:inv_id>/report/pdf", methods=["GET"])
@require_auth(required_role="analyst")
def get_soc_report_pdf(inv_id):
    """Downloads generated PDF investigation report."""
    inv = db.session.get(Investigation, inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found."}), 404

    try:
        pdf_bytes = report_generator.generate_pdf_report(inv.to_full_dict())
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"SOC_Report_{inv_id[:8]}.pdf"
        )
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500

@investigate_bp.route("/investigate/<string:inv_id>", methods=["DELETE"])
@require_auth(required_role="admin")
def delete_investigation(inv_id):
    """Deletes an investigation and its associated artifacts on disk."""
    inv = db.session.get(Investigation, inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found."}), 404

    # Secure unlinking of files on disk
    if inv.raw_eml_path and os.path.exists(inv.raw_eml_path):
        try:
            os.remove(inv.raw_eml_path)
        except Exception:
            pass

    for att in inv.attachments:
        if att.safe_storage_path and os.path.exists(att.safe_storage_path):
            try:
                os.remove(att.safe_storage_path)
            except Exception:
                pass

    db.session.delete(inv)
    db.session.commit()
    return jsonify({"message": f"Investigation {inv_id} deleted successfully."})
