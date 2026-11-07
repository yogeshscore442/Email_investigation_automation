import os
import logging
import json
import xml.etree.ElementTree as ET
import requests
import urllib3
from typing import Optional, Dict, List, Any
from ..config import Config

logger = logging.getLogger(__name__)

# Suppress insecure HTTPS warnings for self-signed certificates in local lab
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkClient:
    """
    Module 2: Splunk Enterprise REST API SIEM Integration
    Interfaces directly with the Splunk REST API to correlate email indicators with:
    1. Sysmon endpoint events (Process Creation, Network Connections, File Creation).
    2. Windows Security auditing events (Logon Success 4624, Logon Failure 4625, Privileges 4672).
    3. PowerShell Operational logs (Script Block Execution 4104).
    4. Network Proxy / DNS egress logs.
    5. Email Gateway delivery telemetry.

    Operates in live mode when configured, and graceful degraded mode when unconfigured.
    Never exposes passwords, tokens, or sensitive authentication headers in outputs or logs.
    """

    def __init__(self):
        self.host = Config.SPLUNK_HOST
        self.port = Config.SPLUNK_PORT
        self.token = Config.SPLUNK_TOKEN
        self.username = Config.SPLUNK_USERNAME
        self.password = Config.SPLUNK_PASSWORD
        self.index = Config.SPLUNK_INDEX
        self.indexes = getattr(Config, "SPLUNK_INDEXES", ["sysmon", "windows", "powershell"])
        
        # TLS Verification Hardening: Support CA bundle or strict boolean
        ca_bundle = getattr(Config, "SPLUNK_CA_BUNDLE", "")
        if ca_bundle and os.path.exists(ca_bundle):
            self.verify_ssl = ca_bundle
        else:
            self.verify_ssl = Config.SPLUNK_SSL_VERIFY

        if self.verify_ssl is False:
            logger.warning("Splunk TLS verification is DISABLED. In production, configure SPLUNK_CA_BUNDLE or enable SPLUNK_SSL_VERIFY=true.")

        self.timeout = int(os.getenv("SPLUNK_TIMEOUT", "45"))

    def is_configured(self) -> bool:
        """Returns True if minimum required credentials and host are present."""
        return bool(self.host and (self.token or (self.username and self.password)))

    def _get_auth_headers(self) -> Dict[str, str]:
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _get_auth_param(self):
        if not self.token and self.username and self.password:
            return (self.username, self.password)
        return None

    def _parse_xml_raw(self, raw_xml: str) -> Dict[str, Any]:
        """
        Parses raw Windows/Sysmon XML event string into structured key-value attributes.
        Extracts both System attributes (EventID, TimeCreated, Computer) and EventData fields
        (Image, CommandLine, Hashes, DestinationIp, TargetUserName, etc.).
        """
        if not raw_xml or not isinstance(raw_xml, str):
            return {}
        
        extracted = {}
        try:
            root = ET.fromstring(raw_xml)
            for elem in root.iter():
                tag_name = elem.tag.split("}")[-1]
                # System metadata
                if tag_name in ["EventID", "Computer", "Task", "Opcode", "Keywords"]:
                    if elem.text:
                        extracted[tag_name] = elem.text.strip()
                elif tag_name == "TimeCreated":
                    extracted["TimeCreated"] = elem.attrib.get("SystemTime")
                elif tag_name == "Execution":
                    extracted["ProcessID"] = elem.attrib.get("ProcessID")
                    extracted["ThreadID"] = elem.attrib.get("ThreadID")
                elif tag_name == "Provider":
                    extracted["ProviderName"] = elem.attrib.get("Name")

                # EventData key-value items (<Data Name="Image">C:\...</Data>)
                elif tag_name == "Data":
                    name = elem.attrib.get("Name")
                    if name and elem.text:
                        extracted[name] = elem.text.strip()
        except Exception as e:
            logger.debug(f"Failed to parse XML event: {e}")
        return extracted

    def get_service_status(self) -> Dict[str, Any]:
        """
        Returns the operational status of the Splunk SIEM integration,
        querying server metadata and active index event counts.
        """
        if not self.is_configured():
            return {
                "name": "Splunk Enterprise SIEM",
                "status": "not_configured",
                "mode": "degraded",
                "host": self.host or "Not configured",
                "indexes": {},
                "total_events": 0,
                "message": "Splunk host or credentials unconfigured. Operating in offline degraded mode."
            }

        # Query server info
        url = f"https://{self.host}:{self.port}/services/server/info?output_mode=json"
        headers = self._get_auth_headers()
        auth = self._get_auth_param()

        try:
            resp = requests.get(url, headers=headers, auth=auth, verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("entry", [{}])[0].get("content", {})
                version = data.get("version", "Unknown")
                server_name = data.get("serverName", "SplunkHost")
                os_name = data.get("os_name", "Windows")

                # Query index metrics
                index_counts = self.get_index_statistics()
                total_events = sum(index_counts.values())

                return {
                    "name": "Splunk Enterprise SIEM",
                    "status": "operational",
                    "mode": "live",
                    "host": f"{self.host}:{self.port}",
                    "version": version,
                    "server_name": server_name,
                    "os": os_name,
                    "indexes": index_counts,
                    "total_events": total_events,
                    "message": f"Splunk Enterprise {version} operational. Active indexes: sysmon ({index_counts.get('sysmon', 0):,}), windows ({index_counts.get('windows', 0):,}), powershell ({index_counts.get('powershell', 0):,})."
                }
            elif resp.status_code in [401, 403]:
                return {
                    "name": "Splunk Enterprise SIEM",
                    "status": "auth_failed",
                    "mode": "degraded",
                    "host": f"{self.host}:{self.port}",
                    "indexes": {},
                    "total_events": 0,
                    "error": "Splunk authentication failed (HTTP 401/403). Check SPLUNK_USERNAME and SPLUNK_PASSWORD."
                }
            elif resp.status_code == 429:
                return {
                    "name": "Splunk Enterprise SIEM",
                    "status": "rate_limited",
                    "mode": "degraded",
                    "host": f"{self.host}:{self.port}",
                    "indexes": {},
                    "total_events": 0,
                    "error": "Splunk search limit reached (HTTP 429)."
                }
            else:
                return {
                    "name": "Splunk Enterprise SIEM",
                    "status": "error",
                    "mode": "degraded",
                    "host": f"{self.host}:{self.port}",
                    "code": resp.status_code,
                    "indexes": {},
                    "total_events": 0,
                    "error": f"Splunk server returned unexpected HTTP {resp.status_code}."
                }
        except Exception as e:
            logger.debug(f"Splunk connectivity check failed: {e}")
            return {
                "name": "Splunk Enterprise SIEM",
                "status": "unavailable",
                "mode": "degraded",
                "host": f"{self.host}:{self.port}",
                "indexes": {},
                "total_events": 0,
                "error": f"Failed to connect to Splunk REST API: {str(e)}"
            }

    def get_index_statistics(self) -> Dict[str, int]:
        """Queries /services/data/indexes to retrieve event counts for configured indexes."""
        if not self.is_configured():
            return {}

        url = f"https://{self.host}:{self.port}/services/data/indexes?output_mode=json&count=100"
        headers = self._get_auth_headers()
        auth = self._get_auth_param()

        try:
            resp = requests.get(url, headers=headers, auth=auth, verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code == 200:
                entries = resp.json().get("entry", [])
                stats = {}
                for item in entries:
                    name = item.get("name")
                    content = item.get("content", {})
                    count = int(content.get("totalEventCount", 0))
                    if name in ["sysmon", "windows", "powershell", "firewall", "main"] or name in self.indexes:
                        stats[name] = count
                return stats
        except Exception as e:
            logger.debug(f"Failed to fetch index statistics: {e}")
        return {}

    def execute_search(self, spl_query: str, earliest: str = "-30d", latest: str = "now", max_count: int = 50) -> Dict[str, Any]:
        """
        Executes a one-shot search export against the Splunk REST API.
        Parses newline-delimited JSON and automatically enriches raw XML events into structured fields.
        """
        if not self.is_configured():
            return {
                "status": "not_configured",
                "checked": False,
                "events_count": 0,
                "events": [],
                "message": "Splunk unconfigured. No live search executed."
            }

        url = f"https://{self.host}:{self.port}/services/search/jobs/export"
        headers = self._get_auth_headers()
        auth = self._get_auth_param()

        # Splunk REST requires form-encoded data payload
        data = {
            "search": f"search {spl_query}",
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
            "count": max_count
        }

        try:
            resp = requests.post(
                url,
                headers=headers,
                auth=auth,
                data=data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                events = []
                for line in resp.text.strip().splitlines():
                    if not line:
                        continue
                    try:
                        parsed = requests.compat.json.loads(line)
                        if "result" in parsed:
                            result = parsed["result"]
                            # If raw XML is present, parse XML into top-level fields
                            if "_raw" in result and ("<Event" in result["_raw"] or "<EventID>" in result["_raw"]):
                                xml_fields = self._parse_xml_raw(result["_raw"])
                                # Merge xml_fields without overwriting Splunk system fields unless empty
                                for k, v in xml_fields.items():
                                    if k not in result or not result[k]:
                                        result[k] = v
                            events.append(result)
                    except Exception:
                        continue

                return {
                    "status": "success",
                    "checked": True,
                    "events_count": len(events),
                    "events": events
                }
            elif resp.status_code == 429:
                return {
                    "status": "rate_limited",
                    "checked": False,
                    "events_count": 0,
                    "events": [],
                    "message": "Splunk concurrent search limit reached (HTTP 429)."
                }
            elif resp.status_code in [401, 403]:
                return {
                    "status": "auth_failed",
                    "checked": False,
                    "events_count": 0,
                    "events": [],
                    "message": "Splunk authentication failure (HTTP 401/403)."
                }
            return {
                "status": "error",
                "checked": False,
                "events_count": 0,
                "events": [],
                "code": resp.status_code,
                "message": f"Splunk returned HTTP status {resp.status_code}"
            }
        except Exception as e:
            logger.warning(f"Splunk search execution failed: {e}")
            return {
                "status": "error",
                "checked": False,
                "events_count": 0,
                "events": [],
                "error": str(e)
            }

    # ==================== Targeted Splunk SIEM Searches ====================

    def search_endpoint_sysmon(
        self,
        hashes: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        process_names: Optional[List[str]] = None,
        max_count: int = 50
    ) -> Dict[str, Any]:
        """
        Correlates Windows Sysmon events:
        - Event ID 1: Process Creation matching file hashes (SHA256/MD5) or binary names.
        - Event ID 3: Outbound/Inbound network connection sockets.
        - Event ID 10: Process Access (LSASS tampering).
        - Event ID 11: File Creation.
        """
        clauses = []

        if hashes:
            clean_hashes = [h.strip() for h in hashes if len(h.strip()) >= 8][:10]
            if clean_hashes:
                hash_terms = " OR ".join([f'Hashes="*{h}*"' for h in clean_hashes])
                clauses.append(f'((EventID=1 OR "<EventID>1</EventID>") AND ({hash_terms}))')

        if ips:
            clean_ips = [ip.strip() for ip in ips if ip.strip() and not ip.startswith(("127.", "0.0."))][:10]
            if clean_ips:
                ip_terms = " OR ".join([f'DestinationIp="{ip}" OR SourceIp="{ip}"' for ip in clean_ips])
                clauses.append(f'((EventID=3 OR "<EventID>3</EventID>") AND ({ip_terms}))')

        if process_names:
            clean_procs = [p.strip() for p in process_names if p.strip()][:5]
            if clean_procs:
                proc_terms = " OR ".join([f'Image="*{p}*"' for p in clean_procs])
                clauses.append(f'((EventID=1 OR "<EventID>1</EventID>") AND ({proc_terms}))')

        if not clauses:
            # General sample query across Sysmon index
            spl = "index=sysmon (EventID=1 OR EventID=3 OR \"<EventID>1</EventID>\" OR \"<EventID>3</EventID>\") | head 25"
        else:
            spl = f"index=sysmon ({' OR '.join(clauses)}) | head {max_count}"

        return self.execute_search(spl, max_count=max_count)

    def search_windows_security(
        self,
        usernames: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        event_codes: Optional[List[int]] = None,
        max_count: int = 50
    ) -> Dict[str, Any]:
        """
        Correlates Windows Security Auditing events:
        - Event ID 4624: Successful Logon (session identifier TargetLogonId).
        - Event ID 4625: Failed Logon (sub-status 0xC0000064 vs 0xC000006A).
        - Event ID 4672: Special Privileges Assigned (SeDebugPrivilege).
        - Event ID 4688: Process Creation.
        """
        codes = event_codes or [4624, 4625, 4672, 4688]
        code_filter = " OR ".join([f'EventID={c} OR "<EventID>{c}</EventID>"' for c in codes])
        clauses = [f"({code_filter})"]

        if usernames:
            clean_users = [u.strip() for u in usernames if u.strip() and u.strip().upper() not in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]][:8]
            if clean_users:
                user_terms = " OR ".join([f'TargetUserName="*{u}*"' for u in clean_users])
                clauses.append(f"({user_terms})")

        if ips:
            clean_ips = [ip.strip() for ip in ips if ip.strip() and not ip.startswith(("127.", "0.0."))][:8]
            if clean_ips:
                ip_terms = " OR ".join([f'IpAddress="{ip}"' for ip in clean_ips])
                clauses.append(f"({ip_terms})")

        spl = f"index=windows ({' AND '.join(clauses)}) | head {max_count}"
        return self.execute_search(spl, max_count=max_count)

    def search_powershell(
        self,
        commands: Optional[List[str]] = None,
        max_count: int = 50
    ) -> Dict[str, Any]:
        """
        Correlates Windows PowerShell Operational logs:
        - Event ID 4104: Script Block Logging.
        - Event ID 4103: Module Execution Logging.
        """
        clauses = ['(EventID=4104 OR EventID=4103 OR "<EventID>4104</EventID>" OR "<EventID>4103</EventID>")']

        if commands:
            clean_cmds = [c.strip() for c in commands if len(c.strip()) >= 3][:8]
            if clean_cmds:
                cmd_terms = " OR ".join([f'ScriptBlockText="*{c}*"' for c in clean_cmds])
                clauses.append(f"({cmd_terms})")

        spl = f"index=powershell ({' AND '.join(clauses)}) | head {max_count}"
        return self.execute_search(spl, max_count=max_count)

    def search_network_proxy_dns(
        self,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        max_count: int = 50
    ) -> Dict[str, Any]:
        """Correlates outbound network proxy and DNS egress telemetry."""
        terms = []
        if domains:
            clean_domains = [d.strip() for d in domains if len(d.strip()) >= 4][:10]
            if clean_domains:
                terms.append("(" + " OR ".join([f'query="*{d}*"' for d in clean_domains]) + ")")
        if ips:
            clean_ips = [ip.strip() for ip in ips if ip.strip() and not ip.startswith(("127.", "0.0."))][:10]
            if clean_ips:
                terms.append("(" + " OR ".join([f'dest_ip="{ip}"' for ip in clean_ips]) + ")")

        if not terms:
            return {"status": "not_queried", "checked": False, "events_count": 0, "events": []}

        spl = f"index IN (windows, sysmon, main) ({' OR '.join(terms)}) | head {max_count}"
        return self.execute_search(spl, max_count=max_count)

    def search_email_gateway(
        self,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        message_id: Optional[str] = None,
        max_count: int = 50
    ) -> Dict[str, Any]:
        """Correlates email MTA gateway delivery and quarantine events."""
        clauses = []
        if sender:
            clauses.append(f'sender="*{sender}*"')
        if recipient:
            clauses.append(f'recipient="*{recipient}*"')
        if message_id:
            clauses.append(f'message_id="*{message_id}*"')

        if not clauses:
            return {"status": "not_queried", "checked": False, "events_count": 0, "events": []}

        spl = f"index=* sourcetype IN (\"cisco:esa\", \"ms:o365:reporting:messagetrace\", \"proofpoint:pps:filter\") " + " AND ".join(clauses) + f" | head {max_count}"
        return self.execute_search(spl, max_count=max_count)

    def correlate_email_iocs(
        self,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
        hashes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes unified cross-source correlation against Splunk for an analyzed email's IOCs.
        Returns matched events grouped by activity category with confirmed vs unobserved evidence.
        """
        if not self.is_configured():
            return {
                "status": "not_configured",
                "telemetry_status": "unavailable_telemetry",
                "message": "Splunk SIEM unconfigured. Operating in degraded offline mode."
            }

        # 1. Search Sysmon for process creation (hashes) and socket connections (ips)
        sysmon_res = self.search_endpoint_sysmon(hashes=hashes, ips=ips)
        
        # 2. Search Windows Security for authentication anomalies (ips)
        usernames = []
        if recipient and "@" in recipient:
            usernames.append(recipient.split("@")[0])
        sec_res = self.search_windows_security(usernames=usernames, ips=ips)

        # 3. Search PowerShell for command execution
        ps_res = self.search_powershell()

        # Group matches
        all_matches = []
        process_events = []
        network_events = []
        auth_events = []

        if sysmon_res.get("status") == "success":
            for ev in sysmon_res.get("events", []):
                eid = str(ev.get("EventID") or ev.get("EventCode") or "")
                if eid == "1":
                    process_events.append(ev)
                    all_matches.append(ev)
                elif eid == "3":
                    network_events.append(ev)
                    all_matches.append(ev)

        if sec_res.get("status") == "success":
            for ev in sec_res.get("events", []):
                auth_events.append(ev)
                all_matches.append(ev)

        # Classification
        if all_matches:
            classification = "confirmed"
        else:
            classification = "no_matching_events"

        return {
            "status": "success",
            "telemetry_status": classification,
            "total_matches": len(all_matches),
            "process_events": process_events,
            "network_events": network_events,
            "auth_events": auth_events,
            "all_events": all_matches
        }


splunk_client = SplunkClient()
