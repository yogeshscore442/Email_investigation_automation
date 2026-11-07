import json
import logging
from datetime import datetime
import dns.resolver
import tldextract
from difflib import SequenceMatcher
from ..config import Config
from ..utils.threat_intel import threat_intel

logger = logging.getLogger(__name__)

class DomainIntelModule:
    """
    Module 3: Sender and Domain Intelligence
    Performs DNS records resolution (MX, SPF, DMARC), RDAP domain age retrieval,
    typosquatting / lookalike brand impersonation detection, and IP reputation lookups.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0

    def investigate_domain_and_ip(self, domain: str, originating_ip: str = "") -> dict:
        """Runs full intelligence investigation on domain and IP."""
        clean_domain = domain.strip().lower()
        if not clean_domain:
            return self._empty_intel()

        # 1. DNS Resolution (MX, SPF, DMARC)
        dns_info = self._resolve_dns(clean_domain)

        # 2. RDAP Domain Registration Age & Registrar
        rdap_info = threat_intel.lookup_rdap_domain(clean_domain)
        domain_age_days = self._calculate_age_days(rdap_info.get("registration_date"))

        # 3. Lookalike / Brand Impersonation Detection
        lookalike_info = self._detect_lookalike(clean_domain)

        # 4. IP Threat Intelligence (AbuseIPDB primary, VirusTotal IP corroboration)
        ip_intel = {"abuse_score": 0, "reputation": "unknown", "country": "Unknown", "isp": "Unknown", "vt_ip_reputation": "unknown"}
        if originating_ip:
            abuse_res = threat_intel.check_abuseipdb(originating_ip)
            if abuse_res.get("checked"):
                ip_intel["abuse_score"] = abuse_res.get("abuse_confidence_score", 0)
                ip_intel["reputation"] = abuse_res.get("verdict", "unknown")
                ip_intel["country"] = abuse_res.get("country_code", "Unknown")
                ip_intel["isp"] = abuse_res.get("isp", "Unknown")
            else:
                rdap_ip = threat_intel.lookup_rdap_ip(originating_ip)
                if rdap_ip.get("checked"):
                    ip_intel["country"] = rdap_ip.get("country", "Unknown")
                    ip_intel["isp"] = rdap_ip.get("name", "Unknown")

            # Corroborate with VirusTotal IP reputation
            vt_ip_res = threat_intel.check_vt_ip(originating_ip)
            if vt_ip_res.get("checked"):
                ip_intel["vt_ip_reputation"] = vt_ip_res.get("verdict", "unknown")
                if ip_intel["country"] in ["Unknown", ""] and vt_ip_res.get("country"):
                    ip_intel["country"] = vt_ip_res.get("country")
                if ip_intel["isp"] in ["Unknown", ""] and vt_ip_res.get("as_owner"):
                    ip_intel["isp"] = vt_ip_res.get("as_owner")
                if ip_intel["reputation"] == "unknown" and vt_ip_res.get("verdict") in ["malicious", "suspicious"]:
                    ip_intel["reputation"] = vt_ip_res.get("verdict")

        # 5. Domain Threat Intel (VirusTotal)
        vt_domain = threat_intel.check_vt_domain(clean_domain)
        domain_reputation = vt_domain.get("verdict", "unknown")

        return {
            "domain": clean_domain,
            "ip_address": originating_ip,
            "mx_records": dns_info["mx_records"],
            "has_mx": len(dns_info["mx_records"]) > 0,
            "spf_record": dns_info["spf_record"],
            "has_spf": bool(dns_info["spf_record"]),
            "dmarc_record": dns_info["dmarc_record"],
            "has_dmarc": bool(dns_info["dmarc_record"]),
            "domain_age_days": domain_age_days,
            "registration_date": rdap_info.get("registration_date"),
            "registrar": rdap_info.get("registrar", "Unknown"),
            "is_lookalike": lookalike_info["is_lookalike"],
            "targeted_brand": lookalike_info["targeted_brand"],
            "similarity_score": lookalike_info["similarity_score"],
            "is_punycode": clean_domain.startswith("xn--") or ".xn--" in clean_domain,
            "ip_abuse_score": ip_intel["abuse_score"],
            "ip_reputation": ip_intel["reputation"],
            "ip_country": ip_intel["country"],
            "ip_isp": ip_intel["isp"],
            "vt_ip_reputation": ip_intel.get("vt_ip_reputation", "unknown"),
            "domain_reputation": domain_reputation
        }

    def _resolve_dns(self, domain: str) -> dict:
        mx_records = []
        spf_record = ""
        dmarc_record = ""

        # MX lookup
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append(str(rdata.exchange).rstrip('.'))
        except Exception:
            pass

        # SPF TXT lookup
        try:
            txt_answers = self.resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                txt_str = "".join([s.decode('utf-8', errors='ignore') for s in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    spf_record = txt_str
                    break
        except Exception:
            pass

        # DMARC TXT lookup (_dmarc.domain)
        try:
            dmarc_answers = self.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_answers:
                txt_str = "".join([s.decode('utf-8', errors='ignore') for s in rdata.strings])
                if txt_str.startswith("v=DMARC1"):
                    dmarc_record = txt_str
                    break
        except Exception:
            pass

        return {
            "mx_records": mx_records,
            "spf_record": spf_record,
            "dmarc_record": dmarc_record
        }

    def _calculate_age_days(self, reg_date_str: str) -> int:
        if not reg_date_str:
            return None
        try:
            # Parse ISO date strings (e.g., 2024-01-15T08:00:00Z)
            cleaned = reg_date_str.split("T")[0]
            dt = datetime.strptime(cleaned, "%Y-%m-%d")
            diff = datetime.utcnow() - dt
            return max(0, diff.days)
        except Exception:
            return None

    def _detect_lookalike(self, domain: str) -> dict:
        """
        Detects brand impersonation and typosquatting:
        e.g. micros0ft.com, paypa1-update.com, secure-apple.com
        """
        extracted = tldextract.extract(domain)
        domain_core = extracted.domain.lower()
        subdomain = extracted.subdomain.lower()

        # Check against targeted brands
        for brand in Config.TARGETED_BRANDS:
            # Exact match is genuine brand
            if domain_core == brand:
                return {"is_lookalike": False, "targeted_brand": "", "similarity_score": 1.0}

            # Brand in subdomain while main domain is different: e.g. paypal.com.evil-phish.net
            if brand in subdomain and domain_core != brand:
                return {
                    "is_lookalike": True,
                    "targeted_brand": brand,
                    "similarity_score": 0.95,
                    "reason": f"Brand '{brand}' appears in subdomain of unauthorized domain '{domain_core}'"
                }

            # Levenshtein / SequenceMatcher check on domain core
            ratio = SequenceMatcher(None, domain_core, brand).ratio()
            # If high similarity (typosquatting like micr0soft or paypa1)
            if ratio >= 0.80 and domain_core != brand:
                return {
                    "is_lookalike": True,
                    "targeted_brand": brand,
                    "similarity_score": round(ratio, 2),
                    "reason": f"Domain name '{domain_core}' is typosquatting brand '{brand}' ({round(ratio*100)}% match)"
                }

            # Brand embedding with hyphens / keywords: e.g. login-microsoft-verify.com
            if brand in domain_core and len(domain_core) > len(brand) + 2:
                return {
                    "is_lookalike": True,
                    "targeted_brand": brand,
                    "similarity_score": 0.88,
                    "reason": f"Domain name contains target brand '{brand}' with deceptive prefixes/suffixes"
                }

        return {"is_lookalike": False, "targeted_brand": "", "similarity_score": 0.0}

    def _empty_intel(self) -> dict:
        return {
            "domain": "",
            "ip_address": "",
            "mx_records": [],
            "has_mx": False,
            "spf_record": "",
            "has_spf": False,
            "dmarc_record": "",
            "has_dmarc": False,
            "domain_age_days": None,
            "registration_date": None,
            "registrar": "Unknown",
            "is_lookalike": False,
            "targeted_brand": "",
            "similarity_score": 0.0,
            "is_punycode": False,
            "ip_abuse_score": 0,
            "ip_reputation": "unknown",
            "ip_country": "Unknown",
            "ip_isp": "Unknown",
            "domain_reputation": "unknown"
        }

domain_intel = DomainIntelModule()
