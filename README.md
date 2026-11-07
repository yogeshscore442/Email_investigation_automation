<p align="center">
  <img src="frontend/public/logo.png" alt="PhishScope SOC" width="600" />
</p>

# PhishScope SOC

> **Automated DFIR & Phishing Investigation Platform**  
> Rapidly triage, analyze, correlate with SIEM telemetry, and neutralize email-based attacks.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![React 18](https://img.shields.io/badge/React-18.0-61dafb.svg)](https://react.dev/)
[![Splunk SIEM](https://img.shields.io/badge/Splunk%20SIEM-Supported-black.svg)](https://www.splunk.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ⚡ Quick Start (How to Run)

### Option 1: One-Click Run (Windows)
Just double-click or run:
```cmd
start.bat
```
This automatically installs dependencies, boots Flask on port 5000, starts Vite on port 5173, and launches your browser at `http://127.0.0.1:5173`.

---

### Option 2: Manual Setup

#### 1. Backend (Flask API)
```bash
cd backend
python -m venv venv
# Windows: venv\Scripts\activate  |  Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
copy .env.example .env          # Linux/macOS: cp .env.example .env
python run.py
```
> Backend runs at: `http://127.0.0.1:5000`

#### 2. Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
```
> Web Dashboard opens at: `http://127.0.0.1:5173`

---

## 🔑 Where to Add Your API Keys

All configuration settings and API keys are stored in:
📁 **`backend/.env`** *(copy from `backend/.env.example`)*

Open `backend/.env` in any text editor and paste your free API keys:

```env
# -------------------------------------------------------------
# Optional Threat Intel API Keys (Safe to leave blank!)
# -------------------------------------------------------------
# VirusTotal (Free): https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AbuseIPDB (Free):  https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# URLScan (Free):    https://urlscan.io/user/profile
URLSCAN_API_KEY=your_urlscan_api_key_here
```

> 💡 **Safe Degraded Mode**:  
> **API keys are 100% optional!** If left empty, PhishScope automatically operates in Safe Degraded Mode — local DNS lookups, RDAP domain registration age, static file magic analysis, and heuristic threat scoring work completely offline.

---

## 🛡️ Core Features

- **Email Ingestion**: Upload RFC 822/5322 `.eml`, Outlook `.msg`, or paste raw email headers.
- **Header & Auth Analysis**: Hop-by-hop transit hop tracing, relay latency, and SPF/DKIM/DMARC verification.
- **Attachment Forensics**: Static magic-byte verification, hash generation (MD5/SHA256), and OLE VBA macro extraction.
- **URL & Domain Intel**: URL defanging (`hxxps://`), typosquatting detection, and brand impersonation defense.
- **Weighted Risk Scoring (0–100)**: Transparent scoring engine mapped directly to MITRE ATT&CK techniques.
- **SIEM & Splunk Correlation**: Correlate email IOCs with live Splunk Enterprise / Sysmon endpoint telemetry.
- **SOC DFIR Reporting**: 1-click export of 14-section PDF reports, interactive HTML, and normalized IOC CSVs.

---

## 👤 Demo Login Credentials

The application includes local evaluation accounts:

| Role | Username | Password |
|---|---|---|
| **SOC Analyst** | `analyst` | `AnalystPassword2026!Secure` |
| **Administrator** | `admin` | `AdminPassword2026!Secure` |
| **SOC Lead** | `lead` | `LeadPassword2026!Secure` |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).  
Copyright (c) 2026 Yogesh.
