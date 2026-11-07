import base64
import ipaddress
import logging
import time
from datetime import datetime
import requests
from ..config import Config
from .network_security import is_ssrf_safe_url, is_ssrf_safe_ip

logger = logging.getLogger(__name__)

_UNSET = object()

class ThreatIntelClient:
    def __init__(self):
        self._vt_api_key = _UNSET
        self._abuseipdb_api_key = _UNSET
        self._urlscan_api_key = _UNSET
        self.timeout = 15
        self._health_cache = {
            "virustotal": {"status": "operational" if self.vt_api_key else "not_configured", "last_checked": None, "last_success": None},
            "abuseipdb": {"status": "operational" if self.abuseipdb_api_key else "not_configured", "last_checked": None, "last_success": None},
            "urlscan": {"status": "operational" if self.urlscan_api_key else "not_configured", "last_checked": None, "last_success": None}
        }

    @property
    def vt_api_key(self):
        if self._vt_api_key is not _UNSET:
            return self._vt_api_key or ""
        return Config.VIRUSTOTAL_API_KEY

    @vt_api_key.setter
    def vt_api_key(self, val):
        self._vt_api_key = val or ""

    @property
    def abuseipdb_api_key(self):
        if self._abuseipdb_api_key is not _UNSET:
            return self._abuseipdb_api_key or ""
        return Config.ABUSEIPDB_API_KEY

    @abuseipdb_api_key.setter
    def abuseipdb_api_key(self, val):
        self._abuseipdb_api_key = val or ""

    @property
    def urlscan_api_key(self):
        if self._urlscan_api_key is not _UNSET:
            return self._urlscan_api_key or ""
        return Config.URLSCAN_API_KEY

    @urlscan_api_key.setter
    def urlscan_api_key(self, val):
        self._urlscan_api_key = val or ""

    def reset_overrides(self):
        self._vt_api_key = _UNSET
        self._abuseipdb_api_key = _UNSET
        self._urlscan_api_key = _UNSET

    def _record_health(self, provider: str, status: str):
        now_iso = datetime.utcnow().isoformat() + "Z"
        if provider not in self._health_cache:
            self._health_cache[provider] = {}
        self._health_cache[provider]["status"] = status
        self._health_cache[provider]["last_checked"] = now_iso
        if status in ["operational", "success"]:
            self._health_cache[provider]["last_success"] = now_iso

    def _vt_get(self, url: str):
        """Helper to query VirusTotal v3 with retry on transient network disconnects."""
        headers = {"x-apikey": self.vt_api_key}
        for attempt in range(2):
            try:
                return requests.get(url, headers=headers, timeout=self.timeout)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if attempt == 0:
                    time.sleep(2)
                    continue
                raise

    # ==================== VirusTotal v3 ====================
    def check_vt_hash(self, file_hash: str) -> dict:
        """Query VirusTotal v3 for a file hash (MD5, SHA1, SHA256)."""
        if not self.vt_api_key:
            return {"status": "not_configured", "checked": False, "verdict": "unknown", "malicious_votes": 0, "harmless_votes": 0}
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        try:
            resp = self._vt_get(url)
            if resp.status_code == 200:
                self._record_health("virustotal", "operational")
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                verdict = "malicious" if malicious > 2 else ("suspicious" if (malicious > 0 or suspicious > 1) else "clean")
                return {
                    "status": "success",
                    "checked": True,
                    "verdict": verdict,
                    "malicious_votes": malicious,
                    "suspicious_votes": suspicious,
                    "harmless_votes": harmless,
                    "type_description": data.get("type_description", ""),
                    "names": data.get("names", [])[:5]
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "checked": True, "verdict": "unknown", "message": "Hash not seen on VirusTotal"}
            elif resp.status_code == 429:
                self._record_health("virustotal", "rate_limited")
                return {"status": "rate_limited", "checked": False, "verdict": "unknown", "message": "VirusTotal API rate limit or quota exceeded", "code": 429}
            elif resp.status_code in [401, 403]:
                self._record_health("virustotal", "auth_failed")
                return {"status": "invalid_api_key", "checked": False, "verdict": "unknown", "message": "Invalid or unauthorized VirusTotal API key", "code": resp.status_code}
            else:
                return {"status": "error", "checked": False, "verdict": "unknown", "code": resp.status_code}
        except requests.exceptions.Timeout:
            self._record_health("virustotal", "unavailable")
            return {"status": "timeout", "checked": False, "verdict": "unknown", "error": "VirusTotal request timed out"}
        except Exception as e:
            logger.warning(f"VirusTotal hash check failed: {e}")
            return {"status": "error", "checked": False, "verdict": "unknown", "error": str(e)}

    def check_vt_domain(self, domain: str) -> dict:
        """Query VirusTotal v3 for domain reputation."""
        if not self.vt_api_key:
            return {"status": "not_configured", "checked": False, "verdict": "unknown", "malicious_votes": 0}
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        try:
            resp = self._vt_get(url)
            if resp.status_code == 200:
                self._record_health("virustotal", "operational")
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                verdict = "malicious" if malicious > 2 else ("suspicious" if (malicious > 0 or suspicious > 1) else "clean")
                return {
                    "status": "success",
                    "checked": True,
                    "verdict": verdict,
                    "malicious_votes": malicious,
                    "suspicious_votes": suspicious,
                    "categories": attrs.get("categories", {}),
                    "reputation": attrs.get("reputation", 0)
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "checked": True, "verdict": "unknown", "message": "Domain not seen on VirusTotal"}
            elif resp.status_code == 429:
                self._record_health("virustotal", "rate_limited")
                return {"status": "rate_limited", "checked": False, "verdict": "unknown", "message": "VirusTotal API rate limit or quota exceeded", "code": 429}
            elif resp.status_code in [401, 403]:
                self._record_health("virustotal", "auth_failed")
                return {"status": "invalid_api_key", "checked": False, "verdict": "unknown", "message": "Invalid or unauthorized VirusTotal API key", "code": resp.status_code}
            return {"status": "error", "checked": False, "verdict": "unknown", "code": resp.status_code}
        except requests.exceptions.Timeout:
            self._record_health("virustotal", "unavailable")
            return {"status": "timeout", "checked": False, "verdict": "unknown", "error": "VirusTotal request timed out"}
        except Exception as e:
            logger.warning(f"VirusTotal domain check failed: {e}")
            return {"status": "error", "checked": False, "verdict": "unknown", "error": str(e)}

    def check_vt_ip(self, ip_address: str) -> dict:
        """Query VirusTotal v3 for IP address reputation."""
        if not self.vt_api_key:
            return {"status": "not_configured", "checked": False, "verdict": "unknown", "malicious_votes": 0}

        clean_ip = str(ip_address).strip()
        try:
            ipaddress.ip_address(clean_ip)
        except (ValueError, AttributeError):
            return {
                "status": "invalid_ip",
                "checked": False,
                "verdict": "unknown",
                "message": f"'{ip_address}' is not a valid IPv4 or IPv6 address"
            }

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}"
        try:
            resp = self._vt_get(url)
            if resp.status_code == 200:
                self._record_health("virustotal", "operational")
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                verdict = "malicious" if malicious > 2 else ("suspicious" if (malicious > 0 or suspicious > 1) else "clean")
                return {
                    "status": "success",
                    "checked": True,
                    "verdict": verdict,
                    "malicious_votes": malicious,
                    "suspicious_votes": suspicious,
                    "harmless_votes": harmless,
                    "as_owner": attrs.get("as_owner", ""),
                    "country": attrs.get("country", ""),
                    "reputation": attrs.get("reputation", 0)
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "checked": True, "verdict": "unknown", "message": "IP not seen on VirusTotal"}
            elif resp.status_code == 429:
                self._record_health("virustotal", "rate_limited")
                return {"status": "rate_limited", "checked": False, "verdict": "unknown", "message": "VirusTotal API rate limit or quota exceeded", "code": 429}
            elif resp.status_code in [401, 403]:
                self._record_health("virustotal", "auth_failed")
                return {"status": "invalid_api_key", "checked": False, "verdict": "unknown", "message": "Invalid or unauthorized VirusTotal API key", "code": resp.status_code}
            return {"status": "error", "checked": False, "verdict": "unknown", "code": resp.status_code}
        except requests.exceptions.Timeout:
            self._record_health("virustotal", "unavailable")
            return {"status": "timeout", "checked": False, "verdict": "unknown", "error": "VirusTotal request timed out"}
        except Exception as e:
            logger.warning(f"VirusTotal IP check failed: {e}")
            return {"status": "error", "checked": False, "verdict": "unknown", "error": str(e)}

    def check_vt_url(self, target_url: str) -> dict:
        """Query VirusTotal v3 for URL reputation using base64 URL ID."""
        if not self.vt_api_key:
            return {"status": "not_configured", "checked": False, "verdict": "unknown", "malicious_votes": 0}
        
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        try:
            resp = self._vt_get(url)
            if resp.status_code == 200:
                self._record_health("virustotal", "operational")
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                verdict = "malicious" if malicious > 1 else ("suspicious" if (malicious > 0 or suspicious > 0) else "clean")
                return {
                    "status": "success",
                    "checked": True,
                    "verdict": verdict,
                    "malicious_votes": malicious,
                    "suspicious_votes": suspicious
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "checked": True, "verdict": "unknown"}
            elif resp.status_code == 429:
                self._record_health("virustotal", "rate_limited")
                return {"status": "rate_limited", "checked": False, "verdict": "unknown", "message": "VirusTotal API rate limit or quota exceeded", "code": 429}
            elif resp.status_code in [401, 403]:
                self._record_health("virustotal", "auth_failed")
                return {"status": "invalid_api_key", "checked": False, "verdict": "unknown", "message": "Invalid or unauthorized VirusTotal API key", "code": resp.status_code}
            return {"status": "error", "checked": False, "verdict": "unknown", "code": resp.status_code}
        except requests.exceptions.Timeout:
            self._record_health("virustotal", "unavailable")
            return {"status": "timeout", "checked": False, "verdict": "unknown", "error": "VirusTotal request timed out"}
        except Exception as e:
            logger.warning(f"VirusTotal URL check failed: {e}")
            return {"status": "error", "checked": False, "verdict": "unknown", "error": str(e)}

    # ==================== AbuseIPDB ====================
    def check_abuseipdb(self, ip_address: str) -> dict:
        """Check IP reputation via AbuseIPDB API v2 with pre-validation for IPv4/IPv6."""
        if not self.abuseipdb_api_key:
            return {"status": "not_configured", "checked": False, "verdict": "unknown", "abuse_confidence_score": 0}
        
        # Validate IPv4 or IPv6 format before sending request (do not send domains/URLs)
        clean_ip = str(ip_address).strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except (ValueError, AttributeError):
            return {
                "status": "invalid_ip",
                "checked": False,
                "verdict": "unknown",
                "abuse_confidence_score": 0,
                "message": f"'{ip_address}' is not a valid IPv4 or IPv6 address"
            }

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": str(ip_obj), "maxAgeInDays": "90", "verbose": True}
        headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                self._record_health("abuseipdb", "operational")
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                verdict = "malicious" if score >= 50 else ("suspicious" if score >= 20 else "clean")
                return {
                    "status": "success",
                    "checked": True,
                    "verdict": verdict,
                    "abuse_confidence_score": score,
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "usage_type": data.get("usageType", "Unknown"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported_at": data.get("lastReportedAt")
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "checked": True, "verdict": "unknown", "abuse_confidence_score": 0, "message": "IP address not found in AbuseIPDB database"}
            elif resp.status_code == 429:
                self._record_health("abuseipdb", "rate_limited")
                return {"status": "rate_limited", "checked": False, "verdict": "unknown", "message": "AbuseIPDB rate limit exceeded (HTTP 429)", "abuse_confidence_score": 0}
            elif resp.status_code in [401, 403]:
                self._record_health("abuseipdb", "auth_failed")
                return {"status": "invalid_api_key", "checked": False, "verdict": "unknown", "message": "Invalid or unauthorized AbuseIPDB API key (HTTP 401/403)", "abuse_confidence_score": 0}
            return {"status": "error", "checked": False, "verdict": "unknown", "code": resp.status_code, "abuse_confidence_score": 0}
        except requests.exceptions.Timeout:
            self._record_health("abuseipdb", "unavailable")
            return {"status": "timeout", "checked": False, "verdict": "unknown", "error": "AbuseIPDB request timed out", "abuse_confidence_score": 0}
        except Exception as e:
            logger.warning(f"AbuseIPDB check failed: {e}")
            return {"status": "error", "checked": False, "verdict": "unknown", "error": str(e), "abuse_confidence_score": 0}

    # ==================== Provider Status & Health Checks ====================
    def get_provider_status(self, provider: str) -> dict:
        """Returns the operational status of a provider without exposing API secrets."""
        provider = provider.lower()
        if provider == "virustotal":
            is_cfg = bool(self.vt_api_key)
            cached = self._health_cache.get("virustotal", {})
            st = cached.get("status", "operational" if is_cfg else "not_configured")
            return {
                "name": "VirusTotal API v3",
                "provider": "virustotal",
                "status": st,
                "mode": "live" if is_cfg else "degraded",
                "configured": is_cfg,
                "capabilities": ["Domain Reputation", "IP Reputation", "URL Reputation", "File Hash Analysis (SHA256/MD5)"],
                "last_checked": cached.get("last_checked"),
                "last_successful_check": cached.get("last_success")
            }
        elif provider == "abuseipdb":
            is_cfg = bool(self.abuseipdb_api_key)
            cached = self._health_cache.get("abuseipdb", {})
            st = cached.get("status", "operational" if is_cfg else "not_configured")
            return {
                "name": "AbuseIPDB API v2",
                "provider": "abuseipdb",
                "status": st,
                "mode": "live" if is_cfg else "degraded",
                "configured": is_cfg,
                "capabilities": ["IP Confidence Score", "Abuse Reports Count", "ISP & Geolocation Analysis"],
                "last_checked": cached.get("last_checked"),
                "last_successful_check": cached.get("last_success")
            }
        elif provider == "urlscan":
            is_cfg = bool(self.urlscan_api_key)
            cached = self._health_cache.get("urlscan", {})
            st = cached.get("status", "operational" if is_cfg else "not_configured")
            return {
                "name": "URLScan.io API v1",
                "provider": "urlscan",
                "status": st,
                "mode": "live" if is_cfg else "degraded",
                "configured": is_cfg,
                "capabilities": ["Automated URL Submission", "Screenshot Capture", "Contacted Domains Extraction"],
                "last_checked": cached.get("last_checked"),
                "last_successful_check": cached.get("last_success")
            }
        return {"provider": provider, "status": "unknown"}

    def health_check(self, provider: str = None) -> dict:
        """Executes a live probe against configured APIs and updates status cache."""
        results = {}
        if provider in [None, "virustotal"] and self.vt_api_key:
            res = self.check_vt_domain("google.com")
            results["virustotal"] = self.get_provider_status("virustotal")
        if provider in [None, "abuseipdb"] and self.abuseipdb_api_key:
            res = self.check_abuseipdb("1.1.1.1")
            results["abuseipdb"] = self.get_provider_status("abuseipdb")
        return results

    # ==================== URLScan.io ====================
    def search_urlscan(self, domain_or_url: str) -> dict:
        """Search existing URLScan.io scans."""
        if not self.urlscan_api_key:
            return {"status": "not_configured", "checked": False, "verdict": "unknown"}
        
        query = f"domain:{domain_or_url}" if not domain_or_url.startswith("http") else f"page.url:\"{domain_or_url}\""
        url = f"https://urlscan.io/api/v1/search/?q={query}&size=1"
        headers = {"API-Key": self.urlscan_api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                results = resp.json().get("results", [])
                if results:
                    top = results[0]
                    verdicts = top.get("verdicts", {})
                    malicious = verdicts.get("overall", {}).get("malicious", False)
                    score = verdicts.get("overall", {}).get("score", 0)
                    contacted = top.get("lists", {}).get("domains", [])
                    return {
                        "status": "success",
                        "checked": True,
                        "verdict": "malicious" if malicious or score > 50 else "clean",
                        "score": score,
                        "screenshot": top.get("screenshot", ""),
                        "page_title": top.get("page", {}).get("title", ""),
                        "contacted_domains": contacted,
                        "scan_id": top.get("_id", "")
                    }
                return {"status": "not_found", "checked": True, "verdict": "unknown"}
            elif resp.status_code == 429:
                return {"status": "rate_limited", "checked": False, "verdict": "unknown", "message": "URLScan.io rate limit exceeded (HTTP 429)"}
            elif resp.status_code in [401, 403]:
                return {"status": "invalid_api_key", "checked": False, "verdict": "unknown", "message": "Invalid or unauthorized URLScan.io API key (HTTP 401/403)"}
            return {"status": "error", "checked": False, "verdict": "unknown", "code": resp.status_code}
        except Exception as e:
            logger.warning(f"URLScan check failed: {e}")
            return {"status": "error", "checked": False, "verdict": "unknown", "error": str(e)}

    def submit_urlscan(self, target_url: str, is_public: bool = False) -> dict:
        """Submit a URL to URLScan.io for analysis."""
        is_safe, reason = is_ssrf_safe_url(target_url)
        if not is_safe:
            return {"status": "rejected", "checked": False, "verdict": "blocked", "message": f"SSRF Protection: {reason}"}

        if not self.urlscan_api_key:
            return {"status": "not_configured", "checked": False, "verdict": "unknown"}
        
        url = "https://urlscan.io/api/v1/scan/"
        headers = {"API-Key": self.urlscan_api_key, "Content-Type": "application/json"}
        payload = {"url": target_url, "visibility": "public" if is_public else "unlisted"}
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "status": "submitted",
                    "checked": True,
                    "scan_id": data.get("uuid"),
                    "result_url": data.get("result"),
                    "api_url": data.get("api"),
                    "visibility": data.get("visibility", "unlisted")
                }
            elif resp.status_code == 429:
                return {"status": "rate_limited", "checked": False, "message": "URLScan.io submission rate limit reached"}
            elif resp.status_code in [401, 403]:
                return {"status": "invalid_api_key", "checked": False, "message": "Unauthorized URLScan.io API key"}
            return {"status": "error", "checked": False, "code": resp.status_code, "message": resp.text[:150]}
        except Exception as e:
            logger.warning(f"URLScan submission failed: {e}")
            return {"status": "error", "checked": False, "error": str(e)}

    def get_urlscan_result(self, scan_id: str) -> dict:
        """Retrieve completed scan results from URLScan.io."""
        if not self.urlscan_api_key:
            return {"status": "not_configured", "checked": False}
        
        url = f"https://urlscan.io/api/v1/result/{scan_id}/"
        headers = {"API-Key": self.urlscan_api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                verdicts = data.get("verdicts", {})
                lists = data.get("lists", {})
                page = data.get("page", {})
                task = data.get("task", {})
                malicious = verdicts.get("overall", {}).get("malicious", False)
                score = verdicts.get("overall", {}).get("score", 0)
                screenshot_url = task.get("screenshotURL") or f"https://urlscan.io/screenshots/{scan_id}.png"
                contacted_domains = lists.get("domains", [])
                return {
                    "status": "success",
                    "checked": True,
                    "verdict": "malicious" if (malicious or score > 50) else "clean",
                    "score": score,
                    "screenshot": screenshot_url,
                    "page_title": page.get("title", ""),
                    "page_domain": page.get("domain", ""),
                    "contacted_domains": contacted_domains,
                    "scan_id": scan_id
                }
            elif resp.status_code == 404:
                return {"status": "pending", "checked": True, "message": "Scan in progress or scan ID not found"}
            elif resp.status_code == 429:
                return {"status": "rate_limited", "checked": False, "message": "URLScan.io rate limit reached"}
            return {"status": "error", "checked": False, "code": resp.status_code}
        except Exception as e:
            logger.warning(f"URLScan result retrieval failed: {e}")
            return {"status": "error", "checked": False, "error": str(e)}

    # ==================== RDAP Lookup ====================
    def lookup_rdap_domain(self, domain: str) -> dict:
        """
        Queries open RDAP services (rdap.org / ICANN) for domain registration date and registrar.
        Requires NO API keys.
        """
        for attempt in range(2):
            try:
                url = f"https://rdap.org/domain/{domain}"
                resp = requests.get(url, timeout=10, headers={"Accept": "application/json"})
                if resp.status_code == 200:
                    data = resp.json()
                    registration_date = None
                    expiration_date = None
                    for event in data.get("events", []):
                        action = event.get("eventAction", "")
                        if action in ["registration", "created"]:
                            registration_date = event.get("eventDate")
                        elif action in ["expiration", "expires"]:
                            expiration_date = event.get("eventDate")
                    
                    # Extract registrar
                    registrar = "Unknown"
                    for entity in data.get("entities", []):
                        roles = entity.get("roles", [])
                        if "registrar" in roles:
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1 and isinstance(vcard[1], list):
                                for prop in vcard[1]:
                                    if len(prop) > 3 and prop[0] == "fn":
                                        registrar = prop[3]
                                        break

                    return {
                        "status": "success",
                        "checked": True,
                        "registration_date": registration_date,
                        "expiration_date": expiration_date,
                        "registrar": registrar,
                        "raw_rdap": data.get("handle", "")
                    }
                elif resp.status_code == 404:
                    return {"status": "not_found", "checked": True, "registration_date": None}
            except Exception as e:
                logger.debug(f"RDAP domain lookup attempt {attempt+1} failed: {e}")
                if attempt == 1:
                    return {"status": "failed", "checked": False, "registration_date": None, "error": str(e)}
        return {"status": "failed", "checked": False, "registration_date": None}

    def lookup_rdap_ip(self, ip_addr: str) -> dict:
        """Queries RDAP for IP address ASN / network info without API keys."""
        if not is_ssrf_safe_ip(ip_addr):
            return {"status": "rejected", "checked": False, "error": "SSRF Protection: Prohibited private, loopback, or reserved IP address"}
        try:
            url = f"https://rdap.arin.net/registry/ip/{ip_addr}"
            resp = requests.get(url, timeout=5, headers={"Accept": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "status": "success",
                    "checked": True,
                    "name": data.get("name", ""),
                    "handle": data.get("handle", ""),
                    "start_address": data.get("startAddress", ""),
                    "end_address": data.get("endAddress", ""),
                    "country": data.get("country", "")
                }
            return {"status": "not_found", "checked": True}
        except Exception as e:
            return {"status": "failed", "checked": False, "error": str(e)}

threat_intel = ThreatIntelClient()

