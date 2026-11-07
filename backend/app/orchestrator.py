import json
import logging
from .models import (
    db,
    Investigation,
    EmailHeader,
    EmailHop,
    AuthenticationResult,
    SenderDomainIntel,
    EmailUrl,
    Attachment,
    DetectionRuleHit,
    ExtractedIOC,
    RiskScoreBreakdown,
    AiAnalysis
)
from .modules import (
    email_parser,
    header_analyzer,
    domain_intel,
    url_analyzer,
    attachment_forensics,
    rules_engine,
    risk_scoring,
    ioc_extractor,
    ai_investigator
)
from .utils.sanitizer import sanitize_email_html

logger = logging.getLogger(__name__)

class InvestigationOrchestrator:
    """
    Central pipeline that runs the complete 10-module automated investigation.
    """

    def investigate_eml_bytes(self, raw_bytes: bytes, filename: str = "evidence.eml") -> Investigation:
        """Runs investigation pipeline on uploaded EML bytes."""
        parsed_data = email_parser.parse_eml_bytes(raw_bytes, filename)
        return self._execute_pipeline(parsed_data)

    def investigate_msg_file(self, file_path: str) -> Investigation:
        """Runs investigation pipeline on Outlook .msg file."""
        parsed_data = email_parser.parse_msg_file(file_path)
        return self._execute_pipeline(parsed_data)

    def investigate_raw_headers_and_body(self, raw_headers: str, raw_body: str = "") -> Investigation:
        """Runs investigation pipeline on pasted raw headers and body."""
        parsed_data = email_parser.parse_raw_text(raw_headers, raw_body)
        return self._execute_pipeline(parsed_data)

    def _execute_pipeline(self, parsed: dict) -> Investigation:
        # Create Investigation record
        inv = Investigation(
            subject=parsed.get("subject", "[No Subject]"),
            sender=parsed.get("sender", ""),
            recipient=parsed.get("recipient", ""),
            cc=parsed.get("cc", ""),
            bcc=parsed.get("bcc", ""),
            reply_to=parsed.get("reply_to", ""),
            message_id=parsed.get("message_id", ""),
            email_date=parsed.get("date", ""),
            raw_eml_path=parsed.get("evidence_path", ""),
            plain_body=parsed.get("body_plain", ""),
            status="processing"
        )
        db.session.add(inv)
        db.session.flush()

        try:
            # Step 1: Sanitize HTML & extract form threats
            sanitizer_res = sanitize_email_html(parsed.get("body_html", ""))
            inv.sanitized_html = sanitizer_res.get("sanitized_html", "")

            # Step 2: Analyze Headers & Authentication
            headers_info = header_analyzer.analyze_headers(parsed.get("headers", []))
            inv.sender_domain = headers_info.get("from_domain", "")
            if not inv.reply_to and headers_info.get("reply_email"):
                inv.reply_to = headers_info.get("reply_email")

            # Persist raw headers
            for h in parsed.get("headers", []):
                db.session.add(EmailHeader(
                    investigation_id=inv.id,
                    name=h.get("name", ""),
                    value=h.get("value", "")
                ))

            # Persist hops
            for hop in headers_info.get("hops", []):
                db.session.add(EmailHop(
                    investigation_id=inv.id,
                    hop_number=hop.get("hop_number", 1),
                    from_server=hop.get("from_server", ""),
                    by_server=hop.get("by_server", ""),
                    ip_address=hop.get("ip_address", ""),
                    protocol=hop.get("protocol", ""),
                    timestamp_str=hop.get("timestamp_str", ""),
                    delay_seconds=hop.get("delay_seconds", 0)
                ))

            # Step 3: Domain & Sender Threat Intelligence
            originating_ip = headers_info.get("auth", {}).get("x_originating_ip", "")
            domain_intel_data = domain_intel.investigate_domain_and_ip(
                domain=inv.sender_domain,
                originating_ip=originating_ip
            )

            # Persist Auth Results
            auth_obj = AuthenticationResult(
                investigation_id=inv.id,
                spf_status=headers_info["auth"]["spf_status"],
                spf_details=headers_info["auth"]["spf_details"],
                dkim_status=headers_info["auth"]["dkim_status"],
                dkim_details=headers_info["auth"]["dkim_details"],
                dmarc_status=headers_info["auth"]["dmarc_status"],
                dmarc_details=headers_info["auth"]["dmarc_details"],
                x_originating_ip=originating_ip,
                raw_auth_results=headers_info["auth"]["raw_auth_results"]
            )
            db.session.add(auth_obj)

            # Persist Domain Intel
            intel_obj = SenderDomainIntel(
                investigation_id=inv.id,
                domain=domain_intel_data.get("domain", ""),
                ip_address=domain_intel_data.get("ip_address", ""),
                mx_records=json.dumps(domain_intel_data.get("mx_records", [])),
                spf_record=domain_intel_data.get("spf_record", ""),
                dmarc_record=domain_intel_data.get("dmarc_record", ""),
                domain_age_days=domain_intel_data.get("domain_age_days"),
                registrar=domain_intel_data.get("registrar", "Unknown"),
                is_lookalike=domain_intel_data.get("is_lookalike", False),
                targeted_brand=domain_intel_data.get("targeted_brand", ""),
                ip_abuse_score=domain_intel_data.get("ip_abuse_score", 0),
                ip_reputation=domain_intel_data.get("ip_reputation", "unknown"),
                domain_reputation=domain_intel_data.get("domain_reputation", "unknown")
            )
            db.session.add(intel_obj)

            # Step 4: URL Analysis
            urls_analyzed = url_analyzer.extract_and_analyze_urls(
                body_plain=parsed.get("body_plain", ""),
                body_html=parsed.get("body_html", "")
            )
            for u in urls_analyzed:
                db.session.add(EmailUrl(
                    investigation_id=inv.id,
                    original_url=u.get("original_url", ""),
                    defanged_url=u.get("defanged_url", ""),
                    domain=u.get("domain", ""),
                    is_ip_based=u.get("is_ip_based", False),
                    is_shortened=u.get("is_shortened", False),
                    has_suspicious_tld=u.get("has_suspicious_tld", False),
                    brand_spoofed=u.get("brand_spoofed", ""),
                    detection_flags=json.dumps(u.get("detection_flags", [])),
                    vt_reputation=u.get("vt_reputation", "unknown"),
                    urlscan_verdict=u.get("urlscan_verdict", "unknown")
                ))

            # Step 5: Attachment Forensics
            attachments_analyzed = attachment_forensics.analyze_attachments(parsed.get("attachments", []))
            for a in attachments_analyzed:
                db.session.add(Attachment(
                    investigation_id=inv.id,
                    filename=a.get("filename", "file.bin"),
                    file_size=a.get("file_size", 0),
                    reported_mime=a.get("reported_mime", ""),
                    detected_mime=a.get("detected_mime", ""),
                    is_mismatch=a.get("is_mismatch", False),
                    sha256=a.get("sha256", ""),
                    md5=a.get("md5", ""),
                    has_macro=a.get("has_macro", False),
                    is_dangerous_extension=a.get("is_dangerous_extension", False),
                    vt_reputation=a.get("vt_reputation", "unknown"),
                    vt_malicious_votes=a.get("vt_malicious_votes", 0),
                    macro_findings=json.dumps(a.get("macro_findings", []))
                ))

            # Step 6: Phishing Detection Rule Engine
            rule_context = {
                "subject": inv.subject,
                "body_plain": inv.plain_body,
                "headers_info": headers_info,
                "auth": headers_info["auth"],
                "hops": headers_info["hops"],
                "domain_intel": domain_intel_data,
                "urls": urls_analyzed,
                "attachments": attachments_analyzed,
                "sanitizer_res": sanitizer_res
            }
            triggered_rules = rules_engine.evaluate_all(rule_context)
            for r in triggered_rules:
                db.session.add(DetectionRuleHit(
                    investigation_id=inv.id,
                    rule_id=r.get("rule_id"),
                    rule_name=r.get("rule_name"),
                    severity=r.get("severity"),
                    category=r.get("category"),
                    weight=r.get("weight"),
                    description=r.get("description"),
                    evidence=r.get("evidence")
                ))

            # Step 7: Risk Scoring Engine
            risk_result = risk_scoring.calculate_risk(
                rule_hits=triggered_rules,
                domain_intel=domain_intel_data,
                auth_info=headers_info["auth"]
            )
            inv.overall_risk_score = risk_result["overall_score"]
            inv.risk_category = risk_result["risk_category"]
            inv.verdict = risk_result["verdict"]

            # Persist Risk Breakdown
            cats = risk_result["category_breakdown"]
            db.session.add(RiskScoreBreakdown(
                investigation_id=inv.id,
                auth_score=cats.get("auth", 0),
                sender_score=cats.get("identity", 0),
                url_score=cats.get("url", 0),
                attachment_score=cats.get("attachment", 0),
                content_score=cats.get("content", 0),
                total_score=inv.overall_risk_score,
                explanation_json=json.dumps(risk_result.get("factors", []))
            ))

            # Step 8: IOC Extraction
            ioc_context = {
                "sender_email": headers_info.get("from_email"),
                "sender_domain": inv.sender_domain,
                "reply_email": headers_info.get("reply_email"),
                "reply_domain": headers_info.get("reply_domain"),
                "return_path_email": headers_info.get("return_path_email"),
                "originating_ip": originating_ip,
                "plain_body": inv.plain_body,
                "hops": headers_info.get("hops", []),
                "domain_intel": domain_intel_data,
                "urls": urls_analyzed,
                "attachments": attachments_analyzed
            }
            extracted_iocs = ioc_extractor.extract_all_iocs(ioc_context)
            for ioc in extracted_iocs:
                db.session.add(ExtractedIOC(
                    investigation_id=inv.id,
                    ioc_type=ioc.get("ioc_type"),
                    ioc_value=ioc.get("ioc_value"),
                    defanged_value=ioc.get("defanged_value"),
                    reputation=ioc.get("reputation"),
                    context=ioc.get("context"),
                    provider=ioc.get("provider", "heuristic"),
                    confidence=ioc.get("confidence", 0),
                    lookup_timestamp=ioc.get("lookup_timestamp", ""),
                    api_status=ioc.get("api_status", "not_queried")
                ))

            # Step 9: AI Investigation & MITRE ATT&CK Mapping
            ai_context = {
                "subject": inv.subject,
                "sender_email": headers_info.get("from_email"),
                "sender_domain": inv.sender_domain,
                "message_id": inv.message_id,
                "verdict": inv.verdict,
                "overall_risk_score": inv.overall_risk_score,
                "originating_ip": originating_ip,
                "auth": headers_info["auth"],
                "hops": headers_info["hops"],
                "domain_intel": domain_intel_data,
                "urls": urls_analyzed,
                "attachments": attachments_analyzed,
                "rules": triggered_rules
            }
            ai_data = ai_investigator.generate_investigation_ai(ai_context)
            db.session.add(AiAnalysis(
                investigation_id=inv.id,
                executive_summary=ai_data.get("executive_summary", ""),
                technical_summary=ai_data.get("technical_summary", ""),
                mitre_attack_json=json.dumps(ai_data.get("mitre_attack", [])),
                recommended_actions_json=json.dumps(ai_data.get("recommended_actions", [])),
                model_used=ai_data.get("model_used", "")
            ))

            inv.status = "completed"
            db.session.commit()
            return inv

        except Exception as e:
            logger.exception("Investigation pipeline failed")
            db.session.rollback()
            inv.status = "failed"
            inv.error_message = str(e)
            db.session.commit()
            raise

orchestrator = InvestigationOrchestrator()

