import re
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime

class HeaderAnalyzerModule:
    """
    Module 2: Email Header Analysis
    Parses SPF/DKIM/DMARC authentication results, reconstructs Received hops,
    calculates transit delays, and detects header anomalies and mismatches.
    """

    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def analyze_headers(self, headers_list: list) -> dict:
        """
        Analyzes the list of headers ({'name': ..., 'value': ...}).
        """
        headers_map = {}
        for h in headers_list:
            key = h["name"].lower()
            if key not in headers_map:
                headers_map[key] = []
            headers_map[key].append(h["value"])

        # 1. Identity & Mismatch Checks
        raw_from = self._get_first(headers_map, "from")
        from_name, from_email = parseaddr(raw_from)
        from_domain = from_email.split("@")[1].lower() if "@" in from_email else ""

        raw_reply_to = self._get_first(headers_map, "reply-to")
        reply_name, reply_email = parseaddr(raw_reply_to)
        reply_domain = reply_email.split("@")[1].lower() if "@" in reply_email else ""

        raw_return_path = self._get_first(headers_map, "return-path")
        ret_name, return_path_email = parseaddr(raw_return_path)
        return_path_domain = return_path_email.split("@")[1].lower() if "@" in return_path_email else ""

        sender_reply_mismatch = False
        mismatch_details = ""
        if reply_email and from_email and reply_email.lower() != from_email.lower():
            sender_reply_mismatch = True
            mismatch_details = f"From '{from_email}' does not match Reply-To '{reply_email}'"

        return_path_mismatch = False
        if return_path_domain and from_domain and return_path_domain != from_domain:
            return_path_mismatch = True

        # 2. Originating IP
        x_originating_ip = ""
        for ip_header in ["x-originating-ip", "x-sender-ip", "x-source-ip", "x-client-ip"]:
            val = self._get_first(headers_map, ip_header)
            if val:
                match = self.IP_REGEX.search(val)
                if match:
                    x_originating_ip = match.group(0)
                    break

        # 3. Authentication-Results Parsing
        auth_results_raw = " ".join(headers_map.get("authentication-results", []) + headers_map.get("arc-authentication-results", []))
        auth_status = self._parse_auth_results(auth_results_raw, headers_map)
        if not auth_status["x_originating_ip"]:
            auth_status["x_originating_ip"] = x_originating_ip

        # 4. Received Hops Reconstruction & Delay Calculation
        raw_received = headers_map.get("received", [])
        hops = self._parse_received_hops(raw_received)

        # If originating IP is still missing, check the earliest external hop IP
        if not auth_status["x_originating_ip"] and hops:
            earliest_hop = hops[-1]
            if earliest_hop["ip_address"] and not self._is_private_ip(earliest_hop["ip_address"]):
                auth_status["x_originating_ip"] = earliest_hop["ip_address"]

        # 5. Header Anomalies Detection
        anomalies = []
        if len(headers_map.get("from", [])) > 1:
            anomalies.append("Multiple 'From' headers detected (RFC 5322 violation / Header injection attempt)")
        
        msg_id = self._get_first(headers_map, "message-id")
        if not msg_id:
            anomalies.append("Missing 'Message-ID' header")
        elif not (msg_id.startswith("<") and msg_id.endswith(">")):
            anomalies.append(f"Non-standard Message-ID syntax: '{msg_id}'")

        if not headers_map.get("date"):
            anomalies.append("Missing 'Date' header")

        return {
            "from_name": from_name,
            "from_email": from_email,
            "from_domain": from_domain,
            "reply_email": reply_email,
            "reply_domain": reply_domain,
            "return_path_email": return_path_email,
            "return_path_domain": return_path_domain,
            "sender_reply_mismatch": sender_reply_mismatch,
            "mismatch_details": mismatch_details,
            "return_path_mismatch": return_path_mismatch,
            "auth": auth_status,
            "hops": hops,
            "anomalies": anomalies
        }

    def _get_first(self, headers_map: dict, key: str) -> str:
        vals = headers_map.get(key, [])
        return vals[0] if vals else ""

    def _parse_auth_results(self, raw_auth: str, headers_map: dict) -> dict:
        spf_status = "none"
        spf_details = ""
        dkim_status = "none"
        dkim_details = ""
        dmarc_status = "none"
        dmarc_details = ""
        x_originating_ip = ""

        if raw_auth:
            # SPF match
            spf_m = re.search(r'spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?', raw_auth, re.IGNORECASE)
            if spf_m:
                spf_status = spf_m.group(1).lower()
                spf_details = spf_m.group(2) or ""

            # DKIM match
            dkim_m = re.search(r'dkim\s*=\s*(pass|fail|none|neutral|temperror|permerror)\b(?:\s*\(([^)]+)\))?', raw_auth, re.IGNORECASE)
            if dkim_m:
                dkim_status = dkim_m.group(1).lower()
                dkim_details = dkim_m.group(2) or ""

            # DMARC match
            dmarc_m = re.search(r'dmarc\s*=\s*(pass|fail|none|temperror|permerror)\b(?:\s*\(([^)]+)\))?', raw_auth, re.IGNORECASE)
            if dmarc_m:
                dmarc_status = dmarc_m.group(1).lower()
                dmarc_details = dmarc_m.group(2) or ""

            # Check if IP is in auth results
            ip_m = re.search(r'sender IP is\s+([0-9.]+)', raw_auth, re.IGNORECASE)
            if ip_m:
                x_originating_ip = ip_m.group(1)

        # Fallback check on dedicated headers
        if spf_status == "none" and headers_map.get("received-spf"):
            spf_hdr = headers_map.get("received-spf")[0]
            first_word = spf_hdr.strip().split()[0].lower()
            if first_word in ["pass", "fail", "softfail", "neutral", "none"]:
                spf_status = first_word
                spf_details = spf_hdr

        if dkim_status == "none" and headers_map.get("dkim-signature"):
            dkim_status = "present"
            dkim_details = "DKIM-Signature header is present"

        return {
            "spf_status": spf_status,
            "spf_details": spf_details,
            "dkim_status": dkim_status,
            "dkim_details": dkim_details,
            "dmarc_status": dmarc_status,
            "dmarc_details": dmarc_details,
            "x_originating_ip": x_originating_ip,
            "raw_auth_results": raw_auth
        }

    def _parse_received_hops(self, received_list: list) -> list:
        """
        Parses Received headers in chronological order (bottom-to-top).
        Hop 1 = origin/earliest, Hop N = final destination mail server.
        """
        hops = []
        # Received headers are prepended by each MTA, so reverse to follow transmission order
        ordered_received = list(reversed(received_list))

        prev_timestamp = None
        for idx, rec_text in enumerate(ordered_received, start=1):
            hop_data = self._dissect_single_received(rec_text, idx)
            
            # Calculate transit delay between hops
            delay_sec = 0
            if hop_data["timestamp_dt"] and prev_timestamp:
                delta = (hop_data["timestamp_dt"] - prev_timestamp).total_seconds()
                delay_sec = max(0, int(delta))
            
            hop_data["delay_seconds"] = delay_sec
            if hop_data["timestamp_dt"]:
                prev_timestamp = hop_data["timestamp_dt"]

            hops.append(hop_data)

        return hops

    def _dissect_single_received(self, text: str, hop_num: int) -> dict:
        norm = " ".join(text.split())
        from_server = ""
        by_server = ""
        ip_addr = ""
        proto = "SMTP"
        timestamp_str = ""
        timestamp_dt = None

        # Extract 'from'
        from_m = re.search(r'from\s+([^\s;]+)', norm, re.IGNORECASE)
        if from_m:
            from_server = from_m.group(1)

        # Extract 'by'
        by_m = re.search(r'by\s+([^\s;]+)', norm, re.IGNORECASE)
        if by_m:
            by_server = by_m.group(1)

        # Extract IP address
        ip_m = self.IP_REGEX.search(norm)
        if ip_m:
            ip_addr = ip_m.group(0)

        # Extract with protocol
        proto_m = re.search(r'with\s+([A-Za-z0-9_-]+)', norm, re.IGNORECASE)
        if proto_m:
            proto = proto_m.group(1)

        # Extract date/time after semicolon
        if ";" in norm:
            time_part = norm.split(";")[-1].strip()
            timestamp_str = time_part
            try:
                timestamp_dt = parsedate_to_datetime(time_part)
            except Exception:
                timestamp_dt = None

        return {
            "hop_number": hop_num,
            "from_server": from_server,
            "by_server": by_server,
            "ip_address": ip_addr,
            "protocol": proto,
            "timestamp_str": timestamp_str,
            "timestamp_dt": timestamp_dt
        }

    def _is_private_ip(self, ip: str) -> bool:
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) > 1 and 16 <= int(parts[1]) <= 31:
                return True
        return False

header_analyzer = HeaderAnalyzerModule()

