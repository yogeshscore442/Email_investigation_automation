# Phase 6C: AbuseIPDB API v2 Integration and Validation Report

**Author:** Senior SOC Engineer, DFIR Architect & SIEM Integration Engineer  
**Date:** November 6, 2026  
**System:** AI-Powered Automated Email Investigation & SOC Incident Correlation Platform  
**Integration Status:** Operational & Live Verified  

---

## 1. Executive Summary

As part of **Phase 6C: Live Threat Intelligence Integration**, the platform was connected to the **AbuseIPDB REST API v2**. The integration enables automated reputation screening for incoming mail servers, transit relay hops, and contacted external IP addresses, providing:
- **Abuse Confidence Score** (0% to 100% based on crowd-sourced abuse reports)
- **ISP and Organization Identification** (Autonomous System Owner / Host)
- **Geolocation Data** (Country Code)
- **Usage Type Classification** (Data Center / Web Hosting / Commercial / Residential)
- **Total Abuse Reports & Recency** (Aggregated report counts and `last_reported_at` timestamps)
- **Strict Pre-Validation** (Guarantees domains and URLs are never erroneously submitted to IP-only endpoints)

---

## 2. Technical Implementation Architecture

The AbuseIPDB client is integrated in [`backend/app/utils/threat_intel.py`](file:///C:/Users/YOGESH/Downloads/Email_Investigation/backend/app/utils/threat_intel.py) under `ThreatIntelClient.check_abuseipdb(ip_address: str)`.

### 2.1 Strict IPv4 / IPv6 Pre-Validation Engine

Sending invalid formats or domain names to the AbuseIPDB API wastes daily rate limits and causes HTTP 422 Unprocessable Entity errors. To eliminate this:
1. Every input string is passed through Python's standard `ipaddress.ip_address(clean_ip)`.
2. Any string that fails standard IP parsing (e.g. `domain.com`, `http://...`, `not-an-ip`) is intercepted immediately.
3. The method returns `{"status": "invalid_ip", "checked": False, "verdict": "unknown", "message": "..."}` without performing network I/O.

### 2.2 Endpoint Specification

- **Endpoint:** `GET https://api.abuseipdb.com/api/v2/check`
- **Headers:** `{"Key": "<SECRET>", "Accept": "application/json"}`
- **Parameters:**
  - `ipAddress`: Cleaned IPv4 or IPv6 string
  - `maxAgeInDays`: `90` (standard 90-day threat window)
  - `verbose`: `True` (enables detailed ISP and report metadata)

---

## 3. Score Mapping & Risk Tiering

AbuseIPDB returns an integer `abuseConfidenceScore` from `0` to `100`. The platform applies the following DFIR verdict thresholds:

| Confidence Score Range | Engine Verdict | Scoring Impact | SOC Action / Context |
| :---: | :---: | :---: | :--- |
| **80 – 100%** | `malicious` | +20 Identity Score | Confirmed active threat / botnet / spam node |
| **50 – 79%** | `malicious` | +20 Identity Score | High abuse likelihood; automated relay abuse |
| **20 – 49%** | `suspicious` | +10 Identity Score | Multiple recent abuse complaints |
| **0 – 19%** | `clean` | 0 Points | Low risk / benign infrastructure |

### Category Cap Enforcement (Anti-Double Counting)
To prevent runaway false positives when multiple external intelligence sources flag the same entity, the Risk Scoring Engine enforces a strict **`identity` category cap of 35 points**. Even if AbuseIPDB (+20), VirusTotal Domain (+25), and Missing MX (+10) trigger concurrently (55 raw points), the identity contribution is strictly clamped to `35`.

---

## 4. Live Verification Evidence

Live verification was performed against the production AbuseIPDB API v2 using the provisioned credentials.

### 4.1 Live Benign Query: `1.1.1.1` (Cloudflare Public DNS)
```json
{
  "status": "success",
  "checked": true,
  "verdict": "clean",
  "abuse_confidence_score": 0,
  "total_reports": 0,
  "country_code": "AU",
  "isp": "APNIC and Cloudflare DNS Resolver project",
  "usage_type": "Data Center/Web Hosting/Transit",
  "is_whitelisted": true,
  "last_reported_at": null
}
```

### 4.2 Pre-Validation Rejection Cases
Tested via automated test suite `test_phase6c_threat_intel_live.py`:

| Input Value | Pre-Validation Result | Network Call Made? |
| :--- | :--- | :---: |
| `evil-phishing-domain.com` | `status: "invalid_ip"` | **No** |
| `https://1.1.1.1/malicious.exe` | `status: "invalid_ip"` | **No** |
| `999.999.999.999` | `status: "invalid_ip"` | **No** |
| `not-an-ip-address` | `status: "invalid_ip"` | **No** |
| `""` (empty string) | `status: "invalid_ip"` | **No** |

---

## 5. Resilient Error Handling & Circuit Breaking

The client handles all standard HTTP edge cases:
- **HTTP 401 / 403 (Unauthorized):** Returns `status: "invalid_api_key"` and sets provider cache to `auth_failed`.
- **HTTP 404 (Not Found):** Returns `status: "not_found"`, `verdict: "unknown"`.
- **HTTP 429 (Rate Limited):** Returns `status: "rate_limited"`, `verdict: "unknown"`, updates cache to `rate_limited`.
- **Timeout (8s):** Catches `requests.exceptions.Timeout`, returns `status: "timeout"`, updates cache to `unavailable`.
- **Unconfigured Mode:** Returns `status: "not_configured"`, `checked: false`, `verdict: "unknown"`.

---

## 6. Correlation with Email Telemetry & Splunk

When an email investigation processes an originating IP or transit hops:
1. `DomainIntelModule` queries AbuseIPDB.
2. If malicious or high abuse score ($\ge 50$), an `ExtractedIOC` is saved:
   - `ioc_type`: `"ipv4"`
   - `ioc_value`: `<ip>`
   - `defanged_value`: `<defanged_ip>`
   - `reputation`: `"malicious"`
   - `provider`: `"abuseipdb"`
   - `confidence`: `<abuse_confidence_score>`
   - `api_status`: `"success"`
   - `lookup_timestamp`: `<iso_timestamp>`
3. Splunk SIEM searches (`DET-IOC06` and Threat Hunting queries) cross-reference this IP across Windows Firewall, Sysmon Network (Event ID 3), and DNS logs.

