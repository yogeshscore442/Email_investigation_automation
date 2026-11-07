import re
import csv
import io
import json
from datetime import datetime
from ..utils.defanger import defang_url, defang_ip, defang_domain, defang_email

class IocExtractorModule:
    """
    Module 8: IOC Extraction Engine
    Extracts, deduplicates, defangs, and classifies Indicators of Compromise (IOCs).
    Enriches with threat intelligence provider metadata (VirusTotal, AbuseIPDB).
    Provides CSV and JSON export routines.
    """

    EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

    def extract_all_iocs(self, investigation_data: dict) -> list[dict]:
        """
        Extracts structured IOCs across the parsed investigation data.
        Returns a list of deduplicated IOC objects with threat intelligence attribution.
        """
        iocs = []
        seen = set()
        now_ts = datetime.utcnow().isoformat() + "Z"

        def add_ioc(ioc_type: str, raw_value: str, context: str, reputation: str = "unknown",
                    provider: str = "heuristic", confidence: int = 0, api_status: str = "not_queried"):
            if not raw_value:
                return
            cleaned = raw_value.strip().lower() if ioc_type in ["email", "domain", "sha256", "md5"] else raw_value.strip()
            key = (ioc_type, cleaned)
            if key in seen:
                return
            seen.add(key)

            # Generate defanged display value
            if ioc_type == "url":
                defanged = defang_url(cleaned)
            elif ioc_type == "ipv4":
                defanged = defang_ip(cleaned)
            elif ioc_type == "domain":
                defanged = defang_domain(cleaned)
            elif ioc_type == "email":
                defanged = defang_email(cleaned)
            else:
                defanged = cleaned

            iocs.append({
                "ioc_type": ioc_type,
                "ioc_value": cleaned,
                "defanged_value": defanged,
                "reputation": reputation,
                "context": context,
                "provider": provider,
                "confidence": confidence,
                "api_status": api_status,
                "lookup_timestamp": now_ts
            })

        # 1. Email Addresses
        sender_email = investigation_data.get("sender_email")
        if sender_email:
            add_ioc("email", sender_email, "Sender Address (From)")

        reply_email = investigation_data.get("reply_email")
        if reply_email:
            add_ioc("email", reply_email, "Reply-To Address")

        ret_email = investigation_data.get("return_path_email")
        if ret_email:
            add_ioc("email", ret_email, "Return-Path Address")

        # Extract emails from body
        plain_body = investigation_data.get("plain_body", "")
        for em in self.EMAIL_REGEX.findall(plain_body):
            add_ioc("email", em, "Body Email Reference")

        # 2. Domains
        sender_dom = investigation_data.get("sender_domain")
        if sender_dom:
            dom_rep = investigation_data.get("domain_intel", {}).get("domain_reputation", "unknown")
            vt_provider = "virustotal" if dom_rep != "unknown" else "heuristic"
            vt_status = "success" if dom_rep != "unknown" else "not_configured"
            add_ioc("domain", sender_dom, "Sender Domain", dom_rep, provider=vt_provider, api_status=vt_status)

        reply_dom = investigation_data.get("reply_domain")
        if reply_dom:
            add_ioc("domain", reply_dom, "Reply-To Domain")

        # 3. IP Addresses
        orig_ip = investigation_data.get("originating_ip")
        if orig_ip:
            ip_rep = investigation_data.get("domain_intel", {}).get("ip_reputation", "unknown")
            abuse_score = investigation_data.get("domain_intel", {}).get("ip_abuse_score", 0)
            abuse_status = "success" if (ip_rep != "unknown" or abuse_score > 0) else "not_configured"
            add_ioc("ipv4", orig_ip, "Originating / Sending Mail IP", ip_rep,
                    provider="abuseipdb", confidence=abuse_score, api_status=abuse_status)

        for hop in investigation_data.get("hops", []):
            hop_ip = hop.get("ip_address")
            if hop_ip:
                add_ioc("ipv4", hop_ip, f"Transit Hop #{hop.get('hop_number')} ({hop.get('by_server')})")

        # 4. URLs
        for u in investigation_data.get("urls", []):
            u_rep = u.get("vt_reputation", "unknown")
            if u_rep == "unknown" and u.get("detection_flags"):
                u_rep = "suspicious"
            u_provider = "virustotal" if u.get("vt_reputation") not in [None, "unknown"] else "heuristic"
            u_status = "success" if u_provider == "virustotal" else "not_configured"
            add_ioc("url", u.get("original_url"), "Extracted Body Hyperlink", u_rep,
                    provider=u_provider, api_status=u_status)
            
            # Also extract the URL's domain
            if u.get("domain"):
                add_ioc("domain", u.get("domain"), f"Destination Domain for Link")

        # 5. Attachment Hashes & Filenames
        for att in investigation_data.get("attachments", []):
            att_rep = att.get("vt_reputation", "unknown")
            if att.get("has_macro") or att.get("is_dangerous_extension"):
                att_rep = "suspicious" if att_rep == "unknown" else att_rep

            add_ioc("filename", att.get("filename"), f"Attachment ({att.get('detected_mime')})", att_rep)
            if att.get("sha256"):
                h_provider = "virustotal" if att.get("vt_reputation") not in [None, "unknown"] else "heuristic"
                h_status = "success" if h_provider == "virustotal" else "not_configured"
                conf = 90 if att_rep == "malicious" else (50 if att_rep == "suspicious" else 0)
                add_ioc("sha256", att.get("sha256"), f"SHA256 for '{att.get('filename')}'", att_rep,
                        provider=h_provider, confidence=conf, api_status=h_status)
            if att.get("md5"):
                add_ioc("md5", att.get("md5"), f"MD5 for '{att.get('filename')}'", att_rep)

        return iocs

    def export_csv(self, iocs: list[dict]) -> str:
        """Exports IOC list to CSV formatted string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IOC Type", "IOC Value (Raw)", "Defanged Value", "Reputation", "Context", "Provider", "Confidence", "API Status", "Lookup Timestamp"])
        for i in iocs:
            writer.writerow([
                i.get("ioc_type"),
                i.get("ioc_value"),
                i.get("defanged_value"),
                i.get("reputation"),
                i.get("context"),
                i.get("provider", "heuristic"),
                i.get("confidence", 0),
                i.get("api_status", "not_queried"),
                i.get("lookup_timestamp", "")
            ])
        return output.getvalue()

    def export_json(self, iocs: list[dict]) -> str:
        """Exports IOC list to JSON formatted string."""
        return json.dumps(iocs, indent=2)

ioc_extractor = IocExtractorModule()

