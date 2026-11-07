<p align="center">
  <img src="frontend/public/logo.png" alt="PhishScope SOC" width="620" />
</p>

# PhishScope SOC: AI-Powered Automated Email Investigation & SOC Incident Correlation Platform

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![React 18](https://img.shields.io/badge/React-18.0-61dafb.svg)](https://react.dev/)
[![Splunk Enterprise](https://img.shields.io/badge/Splunk%20Enterprise-10.6.1.1-black.svg)](https://www.splunk.com/)
[![Sysmon](https://img.shields.io/badge/Microsoft-Sysmon-blue.svg)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-CSS-38bdf8.svg)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Classification: TLP:AMBER](https://img.shields.io/badge/Classification-TLP%3AAMBER-orange.svg)](#)

A production-grade Security Operations Center (SOC) automated email forensic investigation and incident response platform. Designed for SOC Analysts, DFIR Specialists, and Threat Intelligence teams to rapidly triage, analyze, correlate with SIEM telemetry, and neutralize email-based attacks including **Phishing**, **Business Email Compromise (BEC)**, **Executive Impersonation**, **Malicious Macros**, and **Credential Harvesting**.

---

## ⚡ Quick Start & Installation Guide

### Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: 18.x or higher with `npm`
- **Git**

### Option A: One-Click Quick Launch (Windows)
Simply run the included startup script from the project root:
```cmd
start.bat
```
This script automatically:
1. Validates Python and Node.js dependencies.
2. Installs frontend packages if not already present.
3. Launches the Flask Backend REST API (`http://127.0.0.1:5000`).
4. Launches the React Vite Frontend (`http://127.0.0.1:5173`).
5. Automatically opens your default web browser to the dashboard.

---

### Option B: Manual Step-by-Step Setup

#### 1. Clone the Repository
```bash
git clone https://github.com/yogeshscore442/Email_investigation_automation.git
cd Email_investigation_automation
```

#### 2. Backend Setup (Flask REST API)
```bash
# Navigate to the backend folder
cd backend

# Optional: Create and activate a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Copy the sample environment file to create your local .env
# Windows:
copy .env.example .env
# Linux / macOS:
cp .env.example .env

# Start the Flask API server (runs on http://127.0.0.1:5000)
python run.py
```

#### 3. Frontend Setup (React 18 + Vite)
In a new terminal window:
```bash
# Navigate to frontend folder
cd frontend

# Install Node modules
npm install

# Start the Vite development server (runs on http://127.0.0.1:5173)
npm run dev
```

#### 4. Access the Application
Open your browser and navigate to:
**`http://127.0.0.1:5173`**

---

### 🔑 Default Demo Accounts

The platform includes local test credentials for rapid role-based testing:

| Role | Username | Password |
|---|---|---|
| **SOC Analyst** | `analyst` | `AnalystPassword2026!Secure` |
| **Administrator** | `admin` | `AdminPassword2026!Secure` |
| **SOC Lead** | `lead` | `LeadPassword2026!Secure` |

---

### 🛡️ How to Use PhishScope SOC

1. **Email Ingestion**:
   - Drag & drop any `.eml` or Outlook `.msg` file onto the analysis zone.
   - Or paste raw RFC 5322 header and body text directly.
   - Or click any pre-configured attack simulation scenario in the dashboard.
2. **Automated DFIR Analysis**:
   - **Header & Auth Verification**: SPF, DKIM, and DMARC alignment with transit hop delay calculation.
   - **Domain & URL Intel**: Safe defanging, brand typosquatting, RDAP registration age, and DNS checks.
   - **Attachment Forensics**: Static magic-byte verification, hash generation (MD5/SHA-256), and OLE VBA macro disassembly.
3. **Transparent Risk Scoring**:
   - Weighted risk score (0–100) mapped to MITRE ATT&CK techniques.
4. **SIEM Correlation & Threat Hunting**:
   - Correlate extracted indicators against live Splunk Enterprise or Wazuh EDR telemetry.
   - Anti-fabrication guardrail strictly separates confirmed events from unconfigured telemetry.
5. **Incident Response & Export**:
   - Generate full 14-section PDF reports, download IOC lists (JSON/CSV), and trigger human-in-the-loop playbook actions.

---

## 1. System Architecture

```mermaid
flowchart TD
    subgraph Ingestion["1. Evidence Ingestion"]
        UI_Upload[".eml / .msg File Drag & Drop"]
        UI_Paste["Raw RFC 5322 Headers & Body"]
        UI_Demo["1-Click Attack Preset Sandbox"]
    end

    subgraph API["2. Flask REST API Gateway (Port 5000)"]
        EP_Upload["POST /api/investigate/upload"]
        EP_Headers["POST /api/investigate/headers"]
        EP_Detail["GET /api/investigate/:id"]
        EP_SIEM["POST /api/siem/splunk/search"]
        EP_Status["GET /api/siem/status"]
        EP_Correlate["POST /api/incidents/correlate"]
        EP_Report["GET /api/investigate/:id/report (PDF / HTML / JSON)"]
        EP_Actions["POST /api/incidents/:id/actions/:id/approve"]
    end

    subgraph ForensicEngine["3. Investigation & Detection Engine"]
        M1["M1: RFC Parser & Evidence Vault"]
        M2["M2: Header & Auth Analyzer (SPF/DKIM/DMARC)"]
        M3["M3: Sender & Domain Intel (DNS/RDAP)"]
        M4["M4: URL Defanger & Typosquatting"]
        M5["M5: Attachment Forensics & VBA OLE"]
        M6["M6: Rule Detection Engine (12+ Rules)"]
        M7["M7: 0-100 Weighted Risk Scoring"]
        M8["M8: IOC Normalizer & Exporter"]
        M9["M9: MITRE ATT&CK & AI Summaries"]
        M10["M10: DFIR Multi-Format Reporter"]
    end

    subgraph SOCEngine["4. SOC Correlation & SIEM Engine"]
        M11["M11: Cross-Investigation IOC Clustering"]
        M12["M12: Splunk REST API Search Client"]
        M13["M13: Anti-Fabrication Timeline Builder"]
        M14["M14: Response Playbook & Approval Gate"]
    end

    subgraph SplunkSIEM["5. Live Splunk Enterprise 10.6.1.1 (Port 8089)"]
        IDX_Sysmon[("index=sysmon<br/>Sysmon EventID 1 & 3")]
        IDX_Windows[("index=windows<br/>Security EventID 4624 & 4625")]
        IDX_PowerShell[("index=powershell<br/>Script Block EventID 4104")]
    end

    subgraph Storage["6. Persistent Data Layer"]
        DB[("SQLite / PostgreSQL Database")]
        Vault[("Isolated Evidence Storage Vault")]
    end

    Ingestion --> API
    API --> ForensicEngine
    ForensicEngine --> Storage
    ForensicEngine --> SOCEngine
    SOCEngine --> SplunkSIEM
    SOCEngine --> DB
```

---

## 2. Key Modules & Technical Capabilities

### Module 1: Email Collection & Evidence Ingestion
- Native support for RFC 822/5322 `.eml` and Outlook `.msg` compound binary formats.
- Extraction of `From`, `To`, `CC`, `BCC`, `Reply-To`, `Subject`, `Date`, and `Message-ID`.
- Preserves raw evidence in an isolated quarantine storage vault (`backend/data/storage/`).
- Computes SHA256 and MD5 hashes for all attachments.

### Module 2: Email Header & Transit Chain Analysis
- Hop-by-hop `Received` header reconstruction tracing mail from origin to final MTA.
- Calculation of hop transit delays in seconds; flags queuing or timestamp tampering (>1h).
- Originating IP extraction (`X-Originating-IP`, `X-Sender-IP`, earliest public relay hop).
- Strict parsing of `Authentication-Results` (SPF, DKIM, DMARC) with mismatch verification.

### Module 3: Sender & Domain Threat Intelligence
- Real DNS queries via `dnspython` for MX, SPF TXT records, and `_dmarc.<domain>` policies.
- Open RDAP domain age calculations and registrar discovery.
- Brand Impersonation & Typosquatting Engine: Levenshtein distance and subdomain brand matching against high-value targets (Microsoft, Apple, PayPal, Google, Banks, DHL, etc.).
- Originating IP Abuse Confidence score lookup via AbuseIPDB and VirusTotal.

### Module 4: URL Forensic Investigation
- Safe defanging across UI and reports (`hxxps://target[.]com`).
- Decodes obfuscated URL encodings and evaluates userinfo syntax (`http://user:pass@evil.com`).
- Detects raw IP hosts, shortened URLs, suspicious TLDs (`.xyz`, `.top`, `.icu`, `.buzz`), brand-in-subdomains, and open redirect parameters.
- Integration with VirusTotal v3 and URLScan.io.

### Module 5: Static Attachment Forensics
- Magic byte identification and extension mismatch detection (e.g. `.exe` disguised as `.pdf`).
- Detection of dangerous scripts and executables (`.exe`, `.scr`, `.bat`, `.vbs`, `.ps1`, `.iso`, `.hta`).
- Active VBA macro extraction via `oletools.olevba` and OpenXML inspection for `vbaProject.bin`. Detects execution strings like `AutoOpen`, `Shell`, `powershell`, `CreateObject`.
- **Strict Host Safety**: Files are never executed locally.

### Module 6: Modular Phishing Detection Engine
- Extensible `BaseRule` architecture:
  - `RULE_AUTH_DMARC_FAIL` / `RULE_AUTH_SPF_FAIL`
  - `RULE_SENDER_REPLYTO_MISMATCH` / `RULE_DISPLAY_NAME_SPOOFING`
  - `RULE_LOOKALIKE_DOMAIN` / `RULE_MALICIOUS_URL_DETECTED`
  - `RULE_MACRO_ATTACHMENT_DETECTED` / `RULE_DANGEROUS_ATTACHMENT`
  - `RULE_CREDENTIAL_HARVESTING_FORM` / `RULE_CREDENTIAL_HARVESTING_LANGUAGE`
  - `RULE_URGENCY_SOCIAL_ENGINEERING` / `RULE_SUSPICIOUS_TRANSIT_DELAY`

### Module 7: Transparent Risk Scoring Engine (0–100)
- **0–29 Low Risk**: Legitimate communications, valid SPF/DKIM/DMARC.
- **30–59 Medium Risk**: Authentication mismatches without malicious links; newly registered domains.
- **60–79 High Risk**: Impersonation indicators, suspicious attachments, multiple combined red flags.
- **80–100 Critical Risk**: Weaponized macros, confirmed credential harvesting, high threat intelligence hits.
- **Double-Counting Caps**: Auth max 20, Identity max 35, URL max 45, Attachment max 50, Content max 25, Headers max 10.

### Module 8: IOC Normalizer & Multi-Format Exporter
- Automated extraction and deduplication of IPv4, Domain, URL, Email, Filename, and Hashes.
- Exportable via REST API or UI in 1 click as JSON or CSV.

### Module 9: AI Investigation & MITRE ATT&CK Mapping
- Maps findings to MITRE ATT&CK techniques (`T1566.001`, `T1566.002`, `T1598`, `T1036`, `T1204.002`, `T1059`).
- LLM summaries with strict prompt injection resistance and deterministic heuristic fallback.

### Module 10: Multi-Format SOC DFIR Reporting
- Generates 14-section formal DFIR investigation reports.
- Formats: ReportLab PDF (downloadable binary), Interactive HTML, and Structured JSON.

### Module 11: Cross-Investigation IOC Correlation & Campaign Clustering
- Automatically clusters related investigations targeting multiple corporate users with shared IOCs.
- Synthesizes consolidated SOC Incident dossiers with shared severity calculations.

### Module 12: Splunk Enterprise SIEM REST API Integration
- Connects directly to Windows Splunk Enterprise on `https://127.0.0.1:8089`.
- Dynamic XML Event Parser: Extracts fields from raw Windows Event Log XML (`<Data Name="...">`).
- Live Splunk Index Queries:
  - `index=sysmon`: Process creation (`EventCode=1`) and network sockets (`EventCode=3`).
  - `index=windows`: Logon successes (`EventCode=4624`) and failures (`EventCode=4625`).
  - `index=powershell`: Script block logging (`EventCode=4104`).
- **Anti-Fabrication Guardrail**: Distinguishes `confirmed` events from `no_matching_events` and `unavailable_telemetry`.
- **Response Playbook Approval**: Destructive actions (e.g., Mailbox Purge, Host Isolation) require explicit SOC analyst sign-off before simulated execution.

---

## 3. Technology Stack

### Backend
- **Language**: Python 3.10+
- **Framework**: Flask 3.0, Flask-CORS, Flask-SQLAlchemy
- **ORM & Database**: SQLAlchemy 2.0 (SQLite initial, PostgreSQL compatible)
- **SIEM Integration**: Splunk REST API (`requests` with form-encoded `search/jobs/export`)
- **Parsers & Forensics**: `email.policy.default`, `extract-msg`, `oletools.olevba`, `hashlib`
- **Threat Intel & DNS**: `dnspython`, `requests`, `tldextract`
- **Sanitization & PDF**: `bleach`, `BeautifulSoup4`, `reportlab 4.2`
- **Testing**: `pytest` (156 automated tests across Phases 1–7B)

### Frontend
- **Framework**: React 18 with Vite
- **Styling**: Tailwind CSS
- **Charts & Visualization**: Recharts (`BarChart`, `ResponsiveContainer`)
- **Icons**: Lucide React
- **HTTP Client**: Axios

---

## 4. REST API Documentation

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Analyst authentication with salted PBKDF2 verification, brute-force lockout, and JWT token issue. |
| `GET` | `/api/auth/me` | Retrieve profile information for the authenticated session. |
| `POST` | `/api/auth/refresh` | Issue refreshed JWT session token. |
| `POST` | `/api/auth/logout` | Revoke active JWT session and add JTI to server-side blacklist. |
| `GET` | `/api/auth/users` | List registered analyst accounts (Admin only). |
| `POST` | `/api/auth/users` | Provision new analyst account with designated RBAC role (Admin only). |
| `POST` | `/api/investigate/upload` | Multipart file upload (`.eml` or `.msg`). Initiates complete 10-module pipeline. |
| `POST` | `/api/investigate/headers` | JSON payload `{ raw_headers: "...", raw_body: "..." }`. |
| `GET` | `/api/investigations` | Paginated investigation dossiers with verdict & risk filters. |
| `GET` | `/api/investigate/:id` | Full forensic investigation dossier. |
| `GET` | `/api/investigate/:id/iocs` | Extracted IOC indicators for the investigation. |
| `GET` | `/api/investigate/:id/iocs/export?format=csv` | Download IOC list formatted as CSV. |
| `GET` | `/api/investigate/:id/iocs/export?format=json` | Download IOC list formatted as JSON. |
| `GET` | `/api/investigate/:id/report` | 14-section structured SOC report in JSON format. |
| `GET` | `/api/investigate/:id/report/html` | Formatted printable HTML report view. |
| `GET` | `/api/investigate/:id/report/pdf` | Download generated PDF investigation report. |
| `GET` | `/api/siem/status` | Real-time Splunk & Wazuh SIEM connectivity and index metrics. |
| `POST` | `/api/siem/splunk/search` | Execute live Splunk searches (`correlation`, `endpoint`, `windows`, `powershell`). |
| `POST` | `/api/incidents/correlate` | Trigger cross-investigation IOC correlation pass. |
| `GET` | `/api/incidents` | List all correlated SOC incident dossiers. |
| `GET` | `/api/incidents/:id` | Get incident details with chronological timeline & playbooks. |
| `POST` | `/api/incidents/:id/actions/:id/approve` | Explicit analyst approval for response playbook actions. |
| `POST` | `/api/incidents/:id/actions/:id/execute` | Execute approved response action (simulation sandbox). |
| `GET` | `/api/dashboard/stats` | Aggregated dashboard metrics, risk distribution series, and recent dossiers. |

---

## 5. Splunk SIEM Integration & Setup

### Environment Requirements
- **Host OS**: Windows 11 Enterprise
- **Splunk Enterprise**: Version 10.6.1.1+ (Windows native service)
- **Splunk Universal Forwarder**: Ingestion port 9997
- **Sysmon**: Microsoft Sysmon v15+ configured with SwiftOnSecurity or Modular rules

### Configuration (`backend/.env`)
```bash
# Splunk Enterprise REST API Configuration
SPLUNK_HOST=127.0.0.1
SPLUNK_PORT=8089
SPLUNK_USERNAME=botnet
SPLUNK_PASSWORD=<YOUR_SPLUNK_PASSWORD>
SPLUNK_INDEX=sysmon
SPLUNK_INDEXES=sysmon,windows,powershell

# Wazuh EDR (Optional / Degraded Mode)
WAZUH_API_HOST=
WAZUH_API_USER=
WAZUH_API_PASSWORD=
```

### Verified Splunk Indexes
1. **`index=sysmon`** (62,000+ events): Process creation (`EventCode=1`), network connections (`EventCode=3`).
2. **`index=windows`** (139,000+ events): User authentication (`EventCode=4624`), failed logons (`EventCode=4625`).
3. **`index=powershell`** (2,200+ events): Script block execution (`EventCode=4104`).

---

## 6. Installation & Deployment Guide

### Quick Start (1-Click Run on Windows)
Simply double-click [`start.bat`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/start.bat) in the project root:
- Automatically cleans up any previous stale processes on ports 5000 and 5173.
- Checks Python and Node.js prerequisites automatically.
- Launches the Flask Backend API server (`http://127.0.0.1:5000`).
- Launches the React Vite Frontend server (`http://127.0.0.1:5173`).
- Automatically polls readiness and opens your default browser to the PhishScope SOC Dashboard.
- To terminate both servers cleanly, simply press any key in the `start.bat` console window.

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- Splunk Enterprise running locally on Windows (port 8089)

### 1. Backend Setup
```bash
cd backend
python -m pip install -r requirements.txt
# Copy environment template and configure Splunk password
copy .env.example .env
# Seed representative attack scenarios
python seed.py
# Start Flask Backend on port 5000
python run.py
```

### 2. Frontend Setup
```bash
cd ../frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```
Frontend interface will be accessible at `http://127.0.0.1:5173`.

---

## 7. Running Verification & Audit Test Suites

### Automated Test Suite (156 Tests - 100% Passing)
```bash
cd backend
python -m pytest tests/ -v
```
Test suites include:
- `tests/test_phase7b_independent_audit.py`: 15 independent security audit tests covering JWT authentication, privilege boundaries, SSRF target filtering, Splunk TLS & custom CA bundles, Docker configurations, and SQLite hot backups.
- `tests/test_phase7_security_hardening.py`: 10 comprehensive security hardening tests covering auth bypass, RBAC, SQLi, path traversal, malicious upload, SSRF, secret leakage, CORS, rate limiting, and JWT lifecycle.
- `tests/test_phase6d_end_to_end_validation.py`: 8 comprehensive end-to-end integration, forensic parsing, live TI, SIEM correlation, scoring cap, and security defense tests.
- `tests/test_phase6c_threat_intel_live.py`: 17 live VirusTotal v3 and AbuseIPDB v2 integration, IP pre-validation, degraded mode, zero secret exposure, and category capping tests.
- `tests/test_phase6b_adversarial_audit.py`: 10 Phase 6B independent validation, scoring boundary, and adversarial testing tests.
- `tests/test_phase6_detection_engineering.py`: 11 Phase 6A detection engineering, thresholding, false-positive suppression, and live threat hunting tests.
- `tests/test_phase5_soc_simulations.py`: 13 Phase 5 SOC attack simulation and SIEM detection engine tests.
- `tests/test_phase5_api_endpoints.py`: 1 Phase 5 frontend-backend REST contract validation.
- `tests/test_phase4_splunk_live.py`: 15 live Splunk REST API and security tests.
- `tests/test_phase3_siem_correlation.py`: 8 SOC correlation, campaign clustering, and playbook approval tests.
- `tests/test_audit_end_to_end.py`: 20-point SOC core architecture audit.
- `tests/test_live_and_mocked_integrations.py`: 15 threat intel and AI integration tests.
- Core Unit Tests (`test_parser.py`, `test_headers.py`, `test_ioc_extractor.py`, `test_api.py`, `test_rules_and_scoring.py`): 13 core forensic tests.

### Phase 7B: Independent Security Audit & Deployment Verification
Phase 7B provides rigorous, independent verification of all security controls, privilege boundaries, and operational hardening:
- **JWT Authentication & Lifecycle Audit**: Verified valid login issuing standard claims (`sub`, `username`, `role`, `exp`, `iat`, `jti`), immediate rejection of invalid credentials, expired tokens, tampered signatures, missing tokens, and `alg: "none"` evasion attempts. Verified server-side token invalidation upon logout via the `_REVOKED_TOKENS` blacklist, and verified PBKDF2:SHA256 salted password hashing (600,000 iterations) with zero plaintext storage.
- **RBAC Privilege Boundary Enforcement**: Tested and confirmed 4-tier role enforcement (`admin (4)` > `lead (3)` > `analyst (2)` > `auditor (1)`). Verified that analysts cannot access administrative user management (`HTTP 403`), auditors cannot delete evidence or trigger playbooks, and analysts cannot execute destructive containment actions without explicit procedural lead/admin approval.
- **SSRF Defense & Comprehensive Target Filtering**: Tested target inspection against `127.0.0.1`, `[::1]`, `localhost`, RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata (`169.254.169.254`, `metadata.google.internal`), and verified RFC 6052 NAT64 prefix extraction (`64:ff9b::/96`). Intercepted live threat intelligence clients (URLScan, RDAP) prior to outbound network dispatch.
- **Splunk Enterprise TLS Hardening**: Tested certificate validation, custom CA bundle support (`SPLUNK_CA_BUNDLE`), credential masking in logs/exceptions, and safe graceful degradation when SIEM endpoints are unreachable.
- **Docker Production Security**: Audited multi-stage Dockerfiles, unprivileged non-root execution (`USER socuser`), `.dockerignore` secret exclusion rules, localhost port isolation (`127.0.0.1`), and health checks. (Static configurations `VERIFIED`; local host Docker daemon accurately classified as `NOT CONFIGURED`).
- **Database Backup Integrity & Recovery**: Validated lock-free hot backup utility (`backend/scripts/backup_db.py`) utilizing the SQLite Online Backup API. Confirmed snapshot integrity check (`PRAGMA integrity_check == 'ok'`), live test restore into clean test database, and isolation of backup files.
- **Full Regression Suite**: 156/156 automated tests passing with zero failures across the entire test suite.

Documentation:
- [`phase7B_jwt_audit.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7B_jwt_audit.md)
- [`phase7B_authorization_audit.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7B_authorization_audit.md)
- [`phase7B_ssrf_audit.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7B_ssrf_audit.md)
- [`phase7B_docker_audit.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7B_docker_audit.md)
- [`phase7B_backup_restore_audit.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7B_backup_restore_audit.md)
- [`phase7B_final_security_report.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7B_final_security_report.md)

### Phase 7: Production Security Hardening & Container Deployment
Phase 7 prepares the PhishScope SOC platform for enterprise production deployment with defense-in-depth:
- **Analyst Authentication & JWT Sessions**: PBKDF2:SHA256 (600,000 iterations) salted password hashing, cryptographically signed HS256 JWT session tokens with standard claims (`sub`, `username`, `role`, `exp`, `iat`), session refresh endpoint, and 15-minute account lockout after 5 consecutive failed logins.
- **Hierarchical 4-Tier RBAC**: Enforced access control (`admin (4)` > `lead (3)` > `analyst (2)` > `auditor (1)`) on destructive playbook executions, evidence deletion, and analyst user provisioning.
- **SSRF Defense-in-Depth**: Strict IP validation (`is_ssrf_safe_ip`) and DNS resolution verification (`is_ssrf_safe_url`) blocking loopback (`127.0.0.1`), private networks (RFC 1918), link-local (`169.254.0.0/16`), and cloud metadata services (`169.254.169.254`, `fd00:ec2::254`).
- **HTTP Security Headers & CORS**: Integrated CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy` across all API responses. Restricted CORS to authorized origins.
- **SQLite Concurrency & Hot Backups**: Write-Ahead Logging (`PRAGMA journal_mode=WAL;`), foreign keys enabled, and non-blocking hot backup script `backend/scripts/backup_db.py` utilizing the SQLite Online Backup API with automated integrity checks.
- **Production Container Orchestration**: Authored unprivileged production Dockerfiles for backend (Gunicorn) and frontend (Nginx alpine) with health checks and localhost port binding via `docker-compose.yml`.

Documentation:
- [`phase7_security_audit.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7_security_audit.md)
- [`phase7_authentication_report.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7_authentication_report.md)
- [`phase7_backend_hardening.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7_backend_hardening.md)
- [`phase7_deployment_guide.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7_deployment_guide.md)
- [`phase7_final_validation.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase7_final_validation.md)

### Phase 6D: End-to-End Email Investigation Validation
Phase 6D validates the complete email investigation pipeline using real attack samples, live external threat intelligence, and live Splunk SIEM telemetry:
- **Test 1: Phishing Email Upload & Forensic Parsing**: Automated ingestion and deep RFC 5322 parsing of `credential_phishing_microsoft.eml` (credential harvesting) and `macro_invoice_phishing.eml` (macro-enabled payload staging). Validated complete extraction of transit hops, SPF/DKIM/DMARC authentication failures, defanged URLs, domains, and SHA-256 attachment hashes.
- **Test 2: Live Threat Intelligence**: Real-time querying of VirusTotal v3 and AbuseIPDB v2 APIs. Recorded live reputation telemetry: AbuseIPDB score `100/100` for known bad IP `185.220.101.5` (443 abuse reports), score `0/100` for `1.1.1.1`, 64 antivirus vendor detections for EICAR hash, and clean RDAP registration verification. Strictly passive hashing—zero file uploads to external services.
- **Test 3: AI Investigation**: Validated structured LLM threat analysis, indicator explanations, and actionable SOC recommendations. Verified graceful, non-fabricating degradation when OpenAI API quota is exhausted (HTTP 429), automatically falling back to the SOC Heuristic Engine with transparent model attribution.
- **Test 4: SIEM Correlation**: Pivot queries against live Splunk Enterprise (`127.0.0.1:8089`) correlating email IOCs with Sysmon and Windows security logs on host `LAPTOP-OUBJLUDB`. Strictly preserved raw event IDs and timestamps, maintaining an evidence-backed distinction between confirmed detections and unobserved external indicators (`telemetry_status: "no_matching_events"`).
- **Test 5: Risk Scoring & Anti-Double-Counting**: Validated that correlated threat intel cannot cause runaway scores. Enforced category contribution caps (Identity max 35, URL max 45) and Critical alert gating ($\ge 85$ score AND $\ge 2$ independent factors).
- **Test 6: SOC Dashboard API Contracts**: Validated complete API schema compliance across investigation status, IOC reputation tables, external provider health badges, SIEM pivots, incident timeline, and AI/heuristic explanations.
- **Test 7: Security Controls & Defense-in-Depth**: Verified zero credential leakage across frontend responses, reports, and Git commits; active blocking of executable masquerading attachments (e.g. `invoice.pdf.exe`); strict HTML sanitization; API timeout resilience; and prompt injection neutralization.
- **Test 8: Full Regression Suite**: 131/131 tests passing across the entire testing suite.

Documentation:
- [`phase6D_end_to_end_validation.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6D_end_to_end_validation.md)
- [`phase6D_investigation_evidence.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6D_investigation_evidence.md)
- [`phase6D_security_validation.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6D_security_validation.md)
- [`phase6D_final_report.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6D_final_report.md)

### Phase 6C: Live Threat Intelligence API Integration
Phase 6C operationalizes real-time, external threat intelligence correlation:
- **VirusTotal REST API v3**: Multi-engine malware detection, reputation scoring, and categorizations across domains, IP addresses (`/api/v3/ip_addresses/{ip}`), URLs, and attachment file hashes (SHA-256/MD5).
- **Strict Passive Hashing**: Zero attachment uploads to third parties. Cryptographic hashes are computed locally to protect confidentiality.
- **AbuseIPDB REST API v2**: Crowd-sourced abuse confidence scores, ISP identification, geolocation, usage type, and abuse reporting timestamps.
- **Strict IP Pre-Validation**: Intercepts non-IP inputs (`ipaddress.ip_address()`) to eliminate malformed requests and preserve API rate limits.
- **Anti-Double-Counting Scoring Architecture**: Strict category contribution caps (Identity capped at 35) to prevent multiple external flags from triggering artificial runaway critical alerts.
- **Integrity Rule**: Unavailable APIs (missing key, 429, timeout) transition to degraded mode and record verdicts as `unknown` with `confidence: 0`—never fabricating clean results.
- **Zero Secret Exposure**: Strict isolation of credentials in `backend/.env` with sanitization across frontend payloads, export files, and logs.

Documentation:
- [`phase6C_virustotal_validation.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6C_virustotal_validation.md)
- [`phase6C_abuseipdb_validation.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6C_abuseipdb_validation.md)
- [`phase6C_integration_report.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6C_integration_report.md)

### Phase 6B: Independent Detection Validation & Adversarial Testing
Phase 6B independently validates detection logic and adversarial resilience:
- **Scoring Formula & Boundary Verification**: Verified exact behavior for scores 49, 50, 69, 70, 84, 85, 100 with Critical gating enforcement.
- **Office-to-PowerShell Defect Remediation**: Enhanced `_matches_logic()` in `DET-PS01` to intercept Office parents (`winword.exe`, `excel.exe`) even without explicit bypass switches.
- **Duplicate Suppression Audit**: Confirmed 600s suppression window while guaranteeing non-merging of multi-user and multi-host incidents.
- **5 Live Splunk Threat Hunting Queries**: Validated directly against 771,920 live events in Splunk Enterprise.

Documentation:
- [`phase6B_scoring_audit.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6B_scoring_audit.md)
- [`phase6B_false_positive_negative_testing.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6B_false_positive_negative_testing.md)
- [`phase6B_deduplication_audit.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6B_deduplication_audit.md)
- [`phase6B_hunting_validation.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6B_hunting_validation.md)
- [`phase6B_final_report.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6B_final_report.md)

### Phase 6A: Advanced SOC Detection Engineering & Threat Hunting
Phase 6A introduces production-grade detection tuning and false-positive suppression:
- **Evidence-Based Severity Scoring (0–100)**: Dynamic scoring where `CRITICAL` strictly requires Score $\ge 85$ and $\ge 2$ corroborating indicators.
- **Duplicate Alert Suppression**: 600-second sliding window deduplication based on composite hash keys (`rule_id + host + user + entity`).
- **Benign Baseline Suppression**: Whitelisting of administrative cmdlets (`Get-Process`), single logon typos, browser sockets (`chrome.exe`), benign files (`.txt`, `.docx`), and trusted domains.
- **5 Live Splunk Threat Hunting Queries**:
  - `TH-HUNT-01`: Suspicious PowerShell & Encoded Commands (`index=sysmon`, `index=powershell`)
  - `TH-HUNT-02`: Authentication Anomalies & Brute-Force Spraying (`index=windows EventCode=4625`)
  - `TH-HUNT-03`: Suspicious Process Cross-Access & Injection (`index=sysmon EventCode=10`)
  - `TH-HUNT-04`: Autostart Persistence & Run Key Modifications (`index=sysmon EventCode=12/13`)
  - `TH-HUNT-05`: Rare Network Sockets & LOLBAS Outbound Traffic (`index=sysmon EventCode=3`)

Documentation:
- [`phase6_detection_engineering.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6_detection_engineering.md)
- [`phase6_false_positive_analysis.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6_false_positive_analysis.md)
- [`phase6_mitre_mapping.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6_mitre_mapping.md)
- [`phase6_threat_hunting_queries.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6_threat_hunting_queries.md)
- [`phase6_validation_report.md`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/phase6_validation_report.md)

### Phase 5 Attack Simulations & Detection Engineering
Interactive UI Console: `http://127.0.0.1:5173/phase5`

Execute standalone, harmless simulations directly:
```bash
# PS-01: Encoded PowerShell Process & Script Block Telemetry
python backend/simulations/sim_ps01_powershell.py

# PS-02: Controlled Failed Logons (Windows Security Event 4625)
python backend/simulations/sim_ps02_failed_auth.py

# PS-03: Outbound LOLBAS Network Connection (Sysmon Event 3)
python backend/simulations/sim_ps03_network.py

# PS-04: Script Staging in Temp Directory (Sysmon Event 11)
python backend/simulations/sim_ps04_file_create.py

# PS-05: Autostart Registry Persistence & Sanitization (Sysmon Event 12/13)
python backend/simulations/sim_ps05_registry.py

# PS-06: Safe Process Handle Access Telemetry (Sysmon Event 10)
python backend/simulations/sim_ps06_process_access.py

# PS-07: Phishing Email Ingestion & IOC Anti-Fabrication Hunt
python backend/simulations/sim_ps07_ioc_correlation.py

# PS-08: 4-Tier Multi-Source Incident Timeline Reconstruction
python backend/simulations/sim_ps08_incident_timeline.py
```

### Manual End-to-End SOC Validation Script
```bash
python backend/tests/manual_soc_validation.py
```
Validates all 6 operational SOC workflows:
1. Application Connectivity (Flask, React, Splunk 8089, Indexes).
2. Phishing Email Ingestion & Forensic Parsing.
3. Live Splunk IOC Pivot Search.
4. Incident Timeline & Anti-Fabrication Telemetry Attribution.
5. Multi-Format Report Generation (PDF, HTML, JSON, CSV).
6. Response Playbook Approval Guardrail (HTTP 403 block on unapproved actions).

---

## 8. SOC Demonstration & Screenshot Checklist

When demonstrating this platform to SOC leadership or academic evaluators, capture the following key views:

- [ ] **1. SIEM Status Banner**: Showing live Splunk Enterprise connectivity, version `10.6.1.1`, and active event counts across `sysmon`, `windows`, and `powershell` indexes (>200,000 events).
- [ ] **2. Phishing Analysis Dossier**: Ingestion of `credential_phishing_microsoft.eml`, displaying 100/100 risk score, SPF/DMARC failure alerts, defanged URLs, and MITRE ATT&CK techniques.
- [ ] **3. Live Splunk Search Panel**: Real-time query results showing Sysmon process executions (`EventCode=1`) and Windows logons (`EventCode=4624`) matching local host activity.
- [ ] **4. Correlated Incident Timeline**: Demonstrating the strict separation between `confirmed` local events, `no_matching_events` for unseen email IOCs, and `unavailable_telemetry` for unconfigured sensors.
- [ ] **5. Response Playbook Approval Flow**: Modal showing blocked execution on unapproved destructive actions (HTTP 403) followed by analyst approval sign-off.
- [ ] **6. Generated PDF Investigation Report**: Downloaded binary `final_soc_validation_report.pdf` showing formal TLP:AMBER classification, executive summary, and evidence tables.

---

## 9. Security Controls & Operational Boundaries

- **Defanging**: All URLs, IPs, domains, and email addresses are defanged (`hxxps[://]`, `[.]`, `[@]`) to eliminate accidental click-throughs.
- **HTML Sanitization**: Embedded JavaScript, iframes, meta refreshes, and tracking web beacons are stripped or neutralized using `bleach`.
- **No Dynamic Execution**: Attachments are inspected purely through static file analysis, magic byte identification, and static macro stream parsers.
- **Credential Protection**: SIEM and API credentials are kept in backend `.env` variables, never logged, and stripped from all REST API responses.
- **Human-in-the-Loop Safeguards**: Containment actions (account reset, message purge, host isolation) cannot execute without human analyst authorization.
- **Degraded Mode Operation**: When external threat intelligence or Wazuh EDR is unconfigured, the platform operates transparently without throwing errors or generating synthetic alerts.
