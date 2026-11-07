import io
import json
from xml.sax.saxutils import escape
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class SocReportGeneratorModule:
    """
    Module 10: SOC Investigation Report
    Generates structured, professional security investigation reports in JSON,
    printable HTML, and downloadable PDF format using ReportLab.
    """

    def generate_json_report(self, inv_dict: dict) -> dict:
        """Constructs comprehensive 14-section JSON SOC report."""
        return {
            "report_metadata": {
                "report_id": f"SOC-RPT-{inv_dict.get('id', '')[:8].upper()}",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "classification": "TLP:AMBER - STRICT RESTRICTED DISTRIBUTION"
            },
            "section_1_incident_overview": {
                "investigation_id": inv_dict.get("id"),
                "status": inv_dict.get("status"),
                "final_verdict": inv_dict.get("verdict"),
                "overall_risk_score": inv_dict.get("overall_risk_score"),
                "risk_category": inv_dict.get("risk_category"),
                "executive_summary": (inv_dict.get("ai_analysis") or {}).get("executive_summary", "")
            },
            "section_2_email_metadata": {
                "subject": inv_dict.get("subject"),
                "sender": inv_dict.get("sender"),
                "sender_domain": inv_dict.get("sender_domain"),
                "recipient": inv_dict.get("recipient"),
                "cc": inv_dict.get("cc"),
                "reply_to": inv_dict.get("reply_to"),
                "message_id": inv_dict.get("message_id"),
                "email_date": inv_dict.get("email_date")
            },
            "section_3_header_analysis": {
                "total_headers_extracted": len(inv_dict.get("headers") or []),
                "hops_count": len(inv_dict.get("hops") or []),
                "hops": inv_dict.get("hops") or []
            },
            "section_4_auth_results": inv_dict.get("auth_result") or {},
            "section_5_sender_domain_analysis": inv_dict.get("sender_intel") or {},
            "section_6_url_investigation": {
                "total_urls_extracted": len(inv_dict.get("urls") or []),
                "urls": inv_dict.get("urls") or []
            },
            "section_7_attachment_analysis": {
                "total_attachments": len(inv_dict.get("attachments") or []),
                "attachments": inv_dict.get("attachments") or []
            },
            "section_8_ioc_extraction": inv_dict.get("iocs") or [],
            "section_9_threat_intel_findings": {
                "domain_reputation": (inv_dict.get("sender_intel") or {}).get("domain_reputation", "unknown"),
                "ip_abuse_score": (inv_dict.get("sender_intel") or {}).get("ip_abuse_score", 0),
                "ip_reputation": (inv_dict.get("sender_intel") or {}).get("ip_reputation", "unknown")
            },
            "section_10_risk_score_breakdown": inv_dict.get("risk_breakdown") or {},
            "section_11_detection_evidence": inv_dict.get("rules") or [],
            "section_12_mitre_attack_mapping": (inv_dict.get("ai_analysis") or {}).get("mitre_attack", []),
            "section_13_technical_summary": (inv_dict.get("ai_analysis") or {}).get("technical_summary", ""),
            "section_14_recommended_remediation": (inv_dict.get("ai_analysis") or {}).get("recommended_actions", [])
        }

    def generate_html_report(self, inv_dict: dict) -> str:
        """Generates self-contained HTML report with CSS print styles."""
        rpt = self.generate_json_report(inv_dict)
        verdict = inv_dict.get("verdict", "Unknown")
        score = inv_dict.get("overall_risk_score", 0)
        
        # Color coding
        color_class = "danger" if score >= 60 else ("warning" if score >= 30 else "success")
        badge_bg = "#dc2626" if score >= 60 else ("#d97706" if score >= 30 else "#16a34a")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SOC Investigation Report - {inv_dict.get('id')[:8]}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
  .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; padding: 32px; border-radius: 8px; border: 1px solid #334155; }}
  h1, h2, h3 {{ color: #e2e8f0; margin-top: 24px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-weight: bold; color: white; background: {badge_bg}; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; margin-bottom: 24px; }}
  th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; font-size: 14px; }}
  th {{ background: #0f172a; color: #94a3b8; font-weight: 600; }}
  .defanged {{ font-family: monospace; background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
  @media print {{
    body {{ background: white; color: black; }}
    .container {{ border: none; padding: 0; background: white; }}
    th, td {{ border: 1px solid #ccc; }}
    th {{ background: #eee; color: #333; }}
    .badge {{ border: 1px solid black; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div style="display: flex; justify-content: space-between; align-items: center;">
    <div>
      <h1 style="border: none; margin: 0;">SOC Incident Investigation Report</h1>
      <div style="color: #94a3b8; font-size: 14px;">Report ID: {rpt['report_metadata']['report_id']} | Classification: {rpt['report_metadata']['classification']}</div>
    </div>
    <div style="text-align: right;">
      <div class="badge">{verdict.upper()} (Risk Score: {score}/100)</div>
    </div>
  </div>

  <h2>1. Incident & Email Metadata</h2>
  <table>
    <tr><th>Subject</th><td>{inv_dict.get('subject')}</td></tr>
    <tr><th>Sender (From)</th><td>{inv_dict.get('sender')}</td></tr>
    <tr><th>Recipient (To)</th><td>{inv_dict.get('recipient')}</td></tr>
    <tr><th>Message-ID</th><td class="defanged">{inv_dict.get('message_id')}</td></tr>
    <tr><th>Originating IP</th><td class="defanged">{inv_dict.get('auth_result', {}).get('x_originating_ip') or 'N/A'}</td></tr>
  </table>

  <h2>2. Authentication Security Results</h2>
  <table>
    <tr><th>Protocol</th><th>Status</th><th>Verification Details</th></tr>
    <tr><td>SPF</td><td><strong>{inv_dict.get('auth_result', {}).get('spf_status', 'none').upper()}</strong></td><td>{inv_dict.get('auth_result', {}).get('spf_details') or 'N/A'}</td></tr>
    <tr><td>DKIM</td><td><strong>{inv_dict.get('auth_result', {}).get('dkim_status', 'none').upper()}</strong></td><td>{inv_dict.get('auth_result', {}).get('dkim_details') or 'N/A'}</td></tr>
    <tr><td>DMARC</td><td><strong>{inv_dict.get('auth_result', {}).get('dmarc_status', 'none').upper()}</strong></td><td>{inv_dict.get('auth_result', {}).get('dmarc_details') or 'N/A'}</td></tr>
  </table>

  <h2>3. Key Detection Findings & Rules Triggered</h2>
  <table>
    <tr><th>Rule Name</th><th>Severity</th><th>Evidence & Findings</th></tr>
    {''.join(f"<tr><td><strong>{r.get('rule_name')}</strong></td><td>{r.get('severity').upper()}</td><td>{r.get('evidence')}</td></tr>" for r in inv_dict.get('rules', []))}
  </table>

  <h2>4. Extracted Indicators of Compromise (IOCs)</h2>
  <table>
    <tr><th>Type</th><th>Defanged Indicator</th><th>Context</th><th>Reputation</th></tr>
    {''.join(f"<tr><td>{i.get('ioc_type')}</td><td class='defanged'>{i.get('defanged_value')}</td><td>{i.get('context')}</td><td>{i.get('reputation')}</td></tr>" for i in inv_dict.get('iocs', [])[:15])}
  </table>

  <h2>5. MITRE ATT&CK Mapping</h2>
  <table>
    <tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th></tr>
    {''.join(f"<tr><td><strong>{m.get('technique_id')}</strong></td><td>{m.get('technique_name')}</td><td>{m.get('tactic')}</td></tr>" for m in inv_dict.get('ai_analysis', {}).get('mitre_attack', []))}
  </table>

  <h2>6. Recommended Incident Response Playbook</h2>
  <table>
    <tr><th>Phase</th><th>Priority</th><th>Action</th><th>Remediation Details</th></tr>
    {''.join(f"<tr><td>{a.get('phase')}</td><td><strong>{a.get('priority')}</strong></td><td>{a.get('action')}</td><td>{a.get('details')}</td></tr>" for a in inv_dict.get('ai_analysis', {}).get('recommended_actions', []))}
  </table>
</div>
</body>
</html>"""
        return html

    def generate_pdf_report(self, inv_dict: dict) -> bytes:
        """Generates downloadable PDF report using ReportLab."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            "ReportSubTitle",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=12
        )
        h2_style = ParagraphStyle(
            "ReportH2",
            parent=styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=10,
            spaceAfter=6
        )
        cell_style = ParagraphStyle(
            "CellText",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1e293b")
        )
        cell_bold = ParagraphStyle(
            "CellBold",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0f172a")
        )

        elements = []

        # Header Title
        elements.append(Paragraph("Automated SOC Email Investigation Report", title_style))
        rpt_id = f"SOC-RPT-{inv_dict.get('id', '')[:8].upper()}"
        elements.append(Paragraph(f"Report ID: {rpt_id} | Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')} | TLP:AMBER", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

        # Executive Summary Box
        verdict = inv_dict.get("verdict", "Unknown")
        score = inv_dict.get("overall_risk_score", 0)
        verdict_color = colors.HexColor("#dc2626") if score >= 60 else (colors.HexColor("#d97706") if score >= 30 else colors.HexColor("#16a34a"))

        summary_data = [
            [Paragraph("<b>FINAL VERDICT:</b>", cell_style), Paragraph(f"<font color='{verdict_color.hexval()}'><b>{escape(str(verdict.upper()))}</b></font>", cell_style),
             Paragraph("<b>RISK SCORE:</b>", cell_style), Paragraph(f"<b>{score} / 100 ({escape(str(inv_dict.get('risk_category', 'Low')))})</b>", cell_style)]
        ]
        summary_table = Table(summary_data, colWidths=[100, 160, 100, 160])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 10))

        # Email Metadata
        elements.append(Paragraph("1. Incident Metadata", h2_style))
        meta_data = [
            [Paragraph("Subject", cell_bold), Paragraph(escape(str(inv_dict.get("subject", "[No Subject]"))), cell_style)],
            [Paragraph("Sender (From)", cell_bold), Paragraph(escape(str(inv_dict.get("sender", "N/A"))), cell_style)],
            [Paragraph("Recipient (To)", cell_bold), Paragraph(escape(str(inv_dict.get("recipient", "N/A"))), cell_style)],
            [Paragraph("Message-ID", cell_bold), Paragraph(escape(str(inv_dict.get("message_id", "N/A"))), cell_style)],
            [Paragraph("Originating IP", cell_bold), Paragraph(escape(str(inv_dict.get("auth_result", {}).get("x_originating_ip") or "N/A")), cell_style)]
        ]
        meta_table = Table(meta_data, colWidths=[120, 400])
        meta_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # Detection Rules
        elements.append(Paragraph("2. Triggered Security Rules", h2_style))
        rule_rows = [[Paragraph("Rule Name", cell_bold), Paragraph("Severity", cell_bold), Paragraph("Evidence", cell_bold)]]
        rules = inv_dict.get("rules", [])
        if rules:
            for r in rules[:8]:
                rule_rows.append([
                    Paragraph(escape(str(r.get("rule_name", ""))), cell_style),
                    Paragraph(escape(str(r.get("severity", "").upper())), cell_style),
                    Paragraph(escape(str(r.get("evidence", ""))[:120]), cell_style)
                ])
        else:
            rule_rows.append([Paragraph("No security rules triggered.", cell_style), Paragraph("INFO", cell_style), Paragraph("Clean baseline.", cell_style)])

        rules_table = Table(rule_rows, colWidths=[150, 70, 300])
        rules_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(rules_table)
        elements.append(Spacer(1, 10))

        # MITRE ATT&CK
        elements.append(Paragraph("3. MITRE ATT&CK Mapping", h2_style))
        mitre_rows = [[Paragraph("ID", cell_bold), Paragraph("Technique Name", cell_bold), Paragraph("Tactic", cell_bold)]]
        mitre_list = inv_dict.get("ai_analysis", {}).get("mitre_attack", [])
        if mitre_list:
            for m in mitre_list[:5]:
                mitre_rows.append([
                    Paragraph(escape(str(m.get("technique_id", ""))), cell_style),
                    Paragraph(escape(str(m.get("technique_name", ""))), cell_style),
                    Paragraph(escape(str(m.get("tactic", ""))), cell_style)
                ])
        else:
            mitre_rows.append([Paragraph("None", cell_style), Paragraph("No adversarial techniques identified.", cell_style), Paragraph("N/A", cell_style)])

        mitre_table = Table(mitre_rows, colWidths=[80, 260, 180])
        mitre_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(mitre_table)
        elements.append(Spacer(1, 10))

        # Remediation Actions
        elements.append(Paragraph("4. Recommended SOC Remediation", h2_style))
        rec_rows = [[Paragraph("Phase", cell_bold), Paragraph("Priority", cell_bold), Paragraph("Action", cell_bold)]]
        actions = inv_dict.get("ai_analysis", {}).get("recommended_actions", [])
        if actions:
            for a in actions[:5]:
                rec_rows.append([
                    Paragraph(escape(str(a.get("phase", ""))), cell_style),
                    Paragraph(escape(str(a.get("priority", ""))), cell_style),
                    Paragraph(f"<b>{escape(str(a.get('action', '')))}</b>: {escape(str(a.get('details', ''))[:100])}", cell_style)
                ])
        else:
            rec_rows.append([Paragraph("Monitoring", cell_style), Paragraph("Low", cell_style), Paragraph("Standard monitoring, no immediate action required.", cell_style)])

        rec_table = Table(rec_rows, colWidths=[90, 70, 360])
        rec_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(rec_table)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

report_generator = SocReportGeneratorModule()
