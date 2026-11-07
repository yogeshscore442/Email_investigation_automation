# Phase 7: PhishScope SOC — Backend Security Hardening Report

**Assessment Date**: 2026-11-06  
**Auditor**: Senior Application Security Engineer & SOC Lead Architect  
**Classification**: TLP:AMBER | Internal SOC Security Review  
**Project**: AI-Powered Automated Email Investigation & SOC Incident Correlation Platform (PhishScope SOC)  
**Status**: **VERIFIED**

---

## 1. Executive Summary

Production backend security hardening has been implemented across the Flask API gateway, forensic processing modules, network utilities, and database layer. The platform enforces defense-in-depth principles: all untrusted user and email evidence inputs are strictly sanitized, external requests are filtered against Server-Side Request Forgery (SSRF), internal stack traces are shielded from clients, and modern browser security headers are enforced across every HTTP response.

---

## 2. Security Controls & Implementations

### 2.1 Request Size & Upload Validation
- **Upload Limit**: Enforced globally at `MAX_CONTENT_LENGTH = 25 * 1024 * 1024` (25 MB). Payloads exceeding this threshold are immediately rejected with HTTP 413 without loading into memory.
- **Empty File Protection**: 0-byte uploads return HTTP 400 Bad Request.
- **Executable Masquerade Defense**: Files uploaded with `.eml` or `.msg` extensions are checked for DOS/Windows PE (`MZ`, `\x4d\x5a`) and Linux ELF (`\x7fELF`) magic bytes. Executables masquerading as email files are blocked with HTTP 400.
- **Compound Binary Verification**: `.msg` uploads must begin with the standard Microsoft OLE2 signature (`\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1`).

### 2.2 Filename Sanitization & Path Traversal Prevention
- **Filename Sanitization**: Applied using `werkzeug.utils.secure_filename`. Strips directory traversal sequences (`../`, `..\`, `/`, `\`) and non-ASCII control characters.
- **Canonical Storage Bounds Checking**:
  ```python
  att_path = (Config.STORAGE_DIR / f"{att_id}_{att_filename}").resolve()
  if not str(att_path).startswith(str(Config.STORAGE_DIR.resolve())):
      att_path = Config.STORAGE_DIR / f"{att_id}_sanitized_attachment.bin"
  ```
  Guarantees that files cannot be written outside the designated quarantined storage vault.

### 2.3 HTML Sanitization & Email Body Dissection
- **Bleach Whitelist**: Raw email bodies are sanitized using `bleach.clean()` combined with `bleach.css_sanitizer.CSSSanitizer`.
- **Active Element Purging**: `<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`, `<meta>` tags are completely decomposed from the DOM.
- **De-anonymization Prevention**: 1x1 tracking pixels and external image web beacons have their `src` replaced with safe data URIs, preserving analyst privacy.
- **Defanging**: All URLs in HTML anchors are defanged (`href="#"`, `data-original-href="..."`, `javascript:` and `data:` schemes converted to safe pseudo-protocols).

### 2.4 Server-Side Request Forgery (SSRF) Protection
Implemented in `backend/app/utils/network_security.py` and enforced across `UrlAnalyzerModule` and `ThreatIntelClient`:
- **Prohibited Address Ranges**:
  - Loopback: `127.0.0.0/8`, `::1`
  - Private (RFC 1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Link-Local: `169.254.0.0/16`, `fe80::/10`
  - Cloud Metadata Services: `169.254.169.254` (AWS/Azure/GCP), `fd00:ec2::254`
  - Multicast / Reserved: `224.0.0.0/4`, `240.0.0.0/4`
- **DNS Rebinding Prevention**: Domains are resolved via `socket.getaddrinfo()` before dispatching external network queries. If any resolved IP belongs to a private or internal range, the request is immediately blocked with verdict `SSRF Protection: Prohibited private or reserved IP destination`.

### 2.5 HTTP Response Security Headers
Configured as Flask `@app.after_request` middleware:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' http://127.0.0.1:5000 http://localhost:5000 http://127.0.0.1:5173 http://localhost:5173; frame-ancestors 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 2.6 CORS Hardening
- Wildcard `*` replaced with configurable `Config.CORS_ORIGINS` whitelist (`http://127.0.0.1:5173`, `http://localhost:5173`, `http://127.0.0.1:5000`, `http://localhost:5000`).
- Cross-origin requests from arbitrary unauthorized web origins are rejected by CORS preflight.

### 2.7 Error Handling & Information Leakage Shielding
- Custom `@app.errorhandler(500)` returns a standardized, uninformative error message accompanied by a unique `request_id` (`[req_id=a1b2c3d4]`).
- Detailed Python tracebacks and SQL syntax exceptions are logged securely to the server log and never returned in HTTP JSON responses.

### 2.8 Database Concurrency & Query Safety
- **SQL Injection Prevention**: All queries utilize SQLAlchemy ORM parameterized queries; raw SQL is limited to schema checks with parameterized values.
- **SQLite Performance & Concurrency**: Configured Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) and enforced referential integrity (`PRAGMA foreign_keys=ON;`).
- **Live Hot Backups**: Script `backend/scripts/backup_db.py` uses SQLite Online Backup API for hot, lock-free, transactionally consistent snapshots with automatic integrity verification (`PRAGMA integrity_check`).

---

## 3. Verification Matrix

| Hardening Requirement | Verification Technique | Expected Outcome | Status |
| :--- | :--- | :--- | :---: |
| **Request Size Limits** | Upload payload > 25MB | HTTP 413 Payload Too Large | **VERIFIED** |
| **Executable Rejection** | Upload Windows PE with `.eml` | HTTP 400 Executable binary detected | **VERIFIED** |
| **Path Traversal Defense** | Filename `../../etc/passwd` | Filename sanitized to `passwd` | **VERIFIED** |
| **HTML Sanitization** | HTML containing `<script>alert(1)</script>` | Script tag stripped; defanged | **VERIFIED** |
| **SSRF: Loopback Target** | URL pointing to `http://127.0.0.1:8089` | Blocked: targets loopback address | **VERIFIED** |
| **SSRF: Cloud Metadata** | URL pointing to `http://169.254.169.254/` | Blocked: targets cloud metadata service | **VERIFIED** |
| **Security Headers** | Inspect `GET /api/health` response | CSP, X-Frame-Options, X-Content-Type-Options present | **VERIFIED** |
| **CORS Restriction** | Inspect `Access-Control-Allow-Origin` | Whitelist origins only; no wildcard with credentials | **VERIFIED** |
| **Stack Trace Shielding** | Trigger 500 error | Generic JSON with `request_id`; zero traceback | **VERIFIED** |
| **Database Hot Backup** | Run `python backend/scripts/backup_db.py` | Transactionally consistent snapshot created with OK status | **VERIFIED** |

