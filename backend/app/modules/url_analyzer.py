import re
from urllib.parse import urlparse, unquote, parse_qs
from bs4 import BeautifulSoup
import tldextract
from ..config import Config
from ..utils.defanger import defang_url
from ..utils.threat_intel import threat_intel
from ..utils.network_security import is_ssrf_safe_url

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rb.gy", "rebrand.ly", "cutt.ly", "bl.ink", "tiny.cc", "shorte.st"
}

class UrlAnalyzerModule:
    """
    Module 4: URL Investigation
    Extracts URLs from HTML and plaintext, decodes obfuscation, detects brand
    spoofing in subdomains, IP addresses, shortened links, and queries VT/URLScan.
    """

    URL_REGEX = re.compile(
        r'(?:https?|ftp)://[^\s<>"\'{}|\\^`]+',
        re.IGNORECASE
    )

    def extract_and_analyze_urls(self, body_plain: str, body_html: str = "") -> list:
        """Extracts unique URLs and runs security analysis on each."""
        raw_urls = set()

        # 1. Regex on plaintext
        if body_plain:
            for match in self.URL_REGEX.findall(body_plain):
                raw_urls.add(match.rstrip('.,;()[]'))

        # 2. BeautifulSoup on HTML
        if body_html:
            try:
                soup = BeautifulSoup(body_html, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("http://") or href.startswith("https://"):
                        raw_urls.add(href.rstrip('.,;()[]'))
            except Exception:
                pass

        results = []
        for raw_url in raw_urls:
            analyzed = self._analyze_single_url(raw_url)
            results.append(analyzed)

        return results

    def _analyze_single_url(self, raw_url: str) -> dict:
        decoded_url = unquote(raw_url)
        defanged = defang_url(raw_url)
        parsed = urlparse(decoded_url)
        
        hostname = (parsed.hostname or "").lower()
        extracted = tldextract.extract(hostname)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        subdomain = extracted.subdomain.lower()
        tld = extracted.suffix.lower()

        detection_flags = []

        # 1. IP-Based URL check & SSRF inspection
        is_safe, ssrf_reason = is_ssrf_safe_url(raw_url)
        if not is_safe:
            detection_flags.append({
                "type": "SSRF_PROHIBITED_DESTINATION",
                "severity": "critical",
                "message": f"URL targets protected internal/metadata address: {ssrf_reason}"
            })

        is_ip_based = bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname))
        if is_ip_based:
            detection_flags.append({
                "type": "IP_BASED_URL",
                "severity": "high",
                "message": f"URL host is a raw IP address ({hostname}) rather than a registered domain"
            })

        # 2. Shortened URL check
        is_shortened = hostname in SHORTENER_DOMAINS or domain in SHORTENER_DOMAINS
        if is_shortened:
            detection_flags.append({
                "type": "SHORTENED_URL",
                "severity": "medium",
                "message": f"URL uses URL shortener service ({domain}) which conceals destination"
            })

        # 3. Suspicious TLD check
        has_suspicious_tld = tld in Config.SUSPICIOUS_TLDS
        if has_suspicious_tld:
            detection_flags.append({
                "type": "SUSPICIOUS_TLD",
                "severity": "medium",
                "message": f"Domain uses high-abuse/suspicious top-level domain (.{tld})"
            })

        # 4. Brand Spoofing in Subdomains
        # e.g. login.microsoft.com.attacker.com
        brand_spoofed = ""
        for brand in Config.TARGETED_BRANDS:
            if brand in subdomain and extracted.domain != brand:
                brand_spoofed = brand
                detection_flags.append({
                    "type": "BRAND_IN_SUBDOMAIN",
                    "severity": "high",
                    "message": f"Brand '{brand}' found in subdomain of unrelated domain '{domain}'"
                })
                break

        # 5. Userinfo / Credentials Obfuscation in URL
        if "@" in parsed.netloc:
            detection_flags.append({
                "type": "DECEPTIVE_USERINFO",
                "severity": "high",
                "message": "URL uses deceptive '@' userinfo syntax to mislead analyst/victim"
            })

        # 6. Embedded Open Redirect Parameter
        query_params = parse_qs(parsed.query)
        for param in ["url", "redirect", "redirect_to", "next", "target", "dest", "destination"]:
            if param in query_params:
                target_val = query_params[param][0]
                if target_val.startswith("http"):
                    detection_flags.append({
                        "type": "POTENTIAL_OPEN_REDIRECT",
                        "severity": "medium",
                        "message": f"URL contains open-redirect parameter '{param}' pointing to {target_val}"
                    })

        # 7. Dangerous File Download at Path
        for ext in Config.DANGEROUS_EXTENSIONS:
            if parsed.path.lower().endswith(ext):
                detection_flags.append({
                    "type": "DIRECT_DANGEROUS_DOWNLOAD",
                    "severity": "critical",
                    "message": f"URL directly links to high-risk downloadable payload '{ext}'"
                })
                break

        # 8. VirusTotal & URLScan checks
        vt_res = threat_intel.check_vt_url(raw_url)
        vt_reputation = vt_res.get("verdict", "unknown")
        if vt_reputation in ["malicious", "suspicious"]:
            detection_flags.append({
                "type": "VIRUSTOTAL_MALICIOUS_URL",
                "severity": "critical",
                "message": f"VirusTotal flagged URL as {vt_reputation} ({vt_res.get('malicious_votes', 0)} detections)"
            })

        urlscan_res = threat_intel.search_urlscan(domain)
        urlscan_verdict = urlscan_res.get("verdict", "unknown")
        if urlscan_verdict == "malicious":
            detection_flags.append({
                "type": "URLSCAN_MALICIOUS_DOMAIN",
                "severity": "critical",
                "message": f"URLScan.io flagged domain as malicious"
            })

        return {
            "original_url": raw_url,
            "defanged_url": defanged,
            "domain": domain,
            "hostname": hostname,
            "is_ip_based": is_ip_based,
            "is_shortened": is_shortened,
            "has_suspicious_tld": has_suspicious_tld,
            "brand_spoofed": brand_spoofed,
            "detection_flags": detection_flags,
            "vt_reputation": vt_reputation,
            "urlscan_verdict": urlscan_verdict
        }

url_analyzer = UrlAnalyzerModule()

