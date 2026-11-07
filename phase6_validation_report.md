# Phase 6A: Advanced SOC Detection Engineering & Validation Report

## Document Information
- **Project**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 6A — Advanced SOC Detection Engineering, False-Positive Tuning & Threat Hunting
- **Date**: November 6, 2026
- **Lead Role**: Senior SOC Analyst, Detection Engineer & DFIR Specialist
- **SIEM Platform**: Splunk Enterprise 10.6.1.1 (Windows 11 `LAPTOP-OUBJLUDB`, REST API `https://127.0.0.1:8089`)
- **Telemetry Sources**: Microsoft Sysmon (`index=sysmon`), Windows Security Log (`index=windows`), PowerShell Operational Log (`index=powershell`)
- **Regression Test Status**: **95/95 TESTS PASSED (100% PASS RATE, 0 FAILURES, EXIT CODE 0)**

---

## 1. Executive Summary

Phase 6A elevates the platform from basic attack simulation and signature verification into an enterprise-ready **Advanced SOC Detection Engineering Engine**.

In enterprise SOC operations, naïve detection rules inevitably collapse under alert fatigue caused by benign administrative workflows, user typos, standard browser sockets, and uncorroborated single-point indicators. Phase 6A solves this challenge by implementing rigorous detection tuning across all six core detection rules (`DET-PS01` through `DET-IOC06`), introducing:

1. **Evidence-Based Severity Scoring (0–100 Scale)**: Alerts are evaluated holistically; a `CRITICAL` severity rating strictly requires an aggregate evidence score $\ge 85$ **AND** at least two distinct corroborating indicators (e.g., suspicious parent process + encoded payload + external network socket). A single weak indicator can never trigger a critical escalation.
2. **Duplicate Alert Suppression**: An in-memory and persisted deduplication cache suppresses redundant alerts within a 600-second (10-minute) sliding window based on composite keys (`rule_id + host + user + entity`).
3. **Threshold-Based and Time-Window Detection**: Multi-event correlation replaces single-event triggers. For example, failed logons require $\ge 3$ failures within a 5-minute sliding window to detect brute-force attempts while filtering isolated password typos.
4. **Parent-Child Process Lineage Inspection**: Process creations are contextualized against parent relationships (e.g., Office applications spawning `powershell.exe` or `cmd.exe` are flagged, whereas `explorer.exe` or interactive administrative consoles are assessed with appropriate baselines).
5. **Strict Benign Baseline Filtering**: Explicit whitelisting of standard administrative cmdlets, browser HTTP/HTTPS sockets, common document file types, user interface registry preferences, and reputable corporate domains.
6. **Production-Ready Threat Hunting**: Five hunting queries targeting PowerShell execution, authentication anomalies, process cross-access, persistence registry modifications, and rare LOLBAS network connections executed against live Splunk telemetry.

The entire platform passed the full end-to-end regression suite with **95 passed tests out of 95**, with zero failures and zero breaking changes across Phases 1 through 6.

---

## 2. Laboratory Environment & Telemetry Status

The detection engine operates directly on verified Windows 11 enterprise telemetry ingested via Splunk Enterprise and the Splunk Universal Forwarder:

| Component | Status | Host / Port | Ingestion / Telemetry Details |
| :--- | :--- | :--- | :--- |
| **Operating System** | Active | Windows 11 (`LAPTOP-OUBJLUDB`) | Host environment running all services |
| **Splunk Enterprise** | Active | `127.0.0.1:8089` (REST), `8000` (Web) | Splunk Enterprise 10.6.1.1, Basic Auth (`botnet`) |
| **Splunk Forwarder** | Active | `127.0.0.1:9997` (Forwarding) | Universal Forwarder actively shipping logs |
| **Sysmon Telemetry** | Active | `index=sysmon` | 167,000+ events (EID 1 ProcessCreate, EID 3 NetConnect, EID 10 ProcessAccess, EID 11 FileCreate, EID 12/13 Reg) |
| **Windows Security** | Active | `index=windows` | 365,000+ events (EID 4625 Failed Logon, EID 4624 Success, EID 4688 Process Creation) |
| **PowerShell Telemetry**| Active | `index=powershell` | 2,600+ events (EID 4104 ScriptBlock, EID 4103 Module, EID 800 Pipeline) |
| **Wazuh EDR** | Optional | Not Installed | Gracefully decoupled as `mode="degraded"`, displayed as `NOT CONFIGURED` |
| **Backend REST API** | Active | `http://127.0.0.1:5000` | Python 3.10 Flask REST service |
| **Frontend UI** | Active | `http://127.0.0.1:5173` | React 18 + Vite + Tailwind CSS dashboard |

---

## 3. Detection Engineering Improvements (DET-PS01 – DET-IOC06)

Each detection rule was tuned to balance high fidelity with aggressive false-positive reduction.

```
+========================================================================================================================+
| Rule ID   | Name / Focus                    | Severity | Scoring Gating       | Tuning & False-Positive Filters        |
+========================================================================================================================+
| DET-PS01  | Encoded / Obfuscated PowerShell | HIGH     | Base: 60             | - Filters Get-Process, Get-Service     |
|           | Execution (T1059.001, T1027)    | (Score)  | +25 Suspicious Arg   | - Office parent (+25 pts)              |
|           |                                 |          | +25 Office Parent    | - Admin cmdlets deduct 40 pts          |
+------------------------------------------------------------------------------------------------------------------------+
| DET-AUTH02| Targeted Account Brute-Force    | MEDIUM / | Base: 40             | - Threshold: >= 3 failed logons        |
|           | & Password Spraying (T1110.001) | HIGH     | +30 >=3 failures     | - Window: 300 seconds (5 min)          |
|           |                                 |          | +20 Privileged User  | - Isolated typo (<3) is suppressed     |
+------------------------------------------------------------------------------------------------------------------------+
| DET-NET03 | LOLBAS Binary Outbound Socket   | MEDIUM / | Base: 50             | - Filters chrome.exe, msedge.exe       |
|           | Connection (T1071.001, T1105)   | HIGH     | +20 Non-std port     | - Targets certutil, mshta, powershell  |
|           |                                 |          | +25 External C2 IP   | - Requires known LOLBAS image list     |
+------------------------------------------------------------------------------------------------------------------------+
| DET-FILE04| Suspicious Script Staging in    | HIGH     | Base: 55             | - Filters .txt, .log, .docx, .tmp      |
|           | Temp / User Paths (T1105)       |          | +25 Executable/Script| - Inspects Temp, AppData, Public       |
|           |                                 |          | +20 Word/Excel Parent| - Validates double extensions (.pdf.exe)|
+------------------------------------------------------------------------------------------------------------------------+
| DET-REG05 | Registry Autostart Persistence  | HIGH     | Base: 60             | - Filters Explorer\Advanced, Theme     |
|           | Modification (T1547.001)        |          | +25 Run / RunOnce    | - Inspects Run, RunOnce, Winlogon      |
|           |                                 |          | +20 Script target    | - Flags payloads pointing to temp paths|
+------------------------------------------------------------------------------------------------------------------------+
| DET-IOC06 | Phishing Indicator Endpoint     | CRITICAL | Base: 70             | - Whitelists microsoft.com, google.com |
|           | Correlation (T1566, T1204)      | (>=85)   | +20 High Threat Intel| - Requires >=2 factors for CRITICAL    |
|           |                                 |          | +20 Live Telemetry   | - Gated against confirmed reputation   |
+========================================================================================================================+
```

### 3.1 Severity Scoring Model
Severity is calculated dynamically from extracted evidence:
$$\text{Score} = \text{Base} + \sum \text{Boosters} - \sum \text{Deductions}$$

The final tier is assigned strictly via:
- **`CRITICAL`**: Score $\ge 85$ **AND** at least 2 strong corroborating factors (e.g. malicious IOC + active network socket). If an indicator achieves a high score without corroboration, it is capped at `HIGH`.
- **`HIGH`**: Score $\ge 70$.
- **`MEDIUM`**: Score $\ge 45$.
- **`LOW`**: Score $< 45$ (or filtered/suppressed).

### 3.2 Deduplication & Suppression Window
To prevent high-frequency alert storms (e.g., when a script attempts 50 network connections in 10 seconds), the engine computes a suppression hash:
$$\text{Key} = \text{SHA256}(\text{rule\_id} \,\|\, \text{host} \,\|\, \text{user} \,\|\, \text{entity})$$
If an alert with this key was generated within the previous 600 seconds (10 minutes), subsequent alerts are suppressed and logged as duplicate events.

---

## 4. False-Positive Baseline Testing & Analysis

A dedicated test harness was constructed in `siem_detection_engine.py:test_legitimate_activity()` to test six baseline scenarios reflecting typical daily corporate activities. All six scenarios passed cleanly without triggering false alerts:

| Baseline Scenario | Simulated Legitimate Activity | Detection Engine Result | Mitigation Applied |
| :--- | :--- | :--- | :--- |
| **FP-01: Admin Scripting** | Administrator runs `Get-Process` and `Get-Service` without bypass or encoding flags | **SUPPRESSED** (`matched: False`, Score: 20) | Whitelisted benign cmdlets; 40-point deduction for normal execution |
| **FP-02: Password Typo** | Single failed logon (`SubStatus: 0xC000006A`, count = 1) | **SUPPRESSED** (`matched: False`, Score: 40) | Multi-event threshold ($\ge 3$ within 300s window); single typo ignored |
| **FP-03: Web Browsing** | `chrome.exe` connects to outbound IP on port 443 | **SUPPRESSED** (`matched: False`, Score: 0) | LOLBAS filter excludes standard browsers (`chrome.exe`, `msedge.exe`, `firefox.exe`) |
| **FP-04: Document Save** | Word saves `report.docx` and notepad creates `meeting_notes.txt` in `%TEMP%` | **SUPPRESSED** (`matched: False`, Score: 20) | Extension filter checks executable/script extensions (`.ps1`, `.bat`, `.vbs`, `.exe`) |
| **FP-05: User Preferences** | Windows Explorer updates `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden` | **SUPPRESSED** (`matched: False`, Score: 20) | Run key filter targets persistence hives (`\Run`, `\RunOnce`, `\Winlogon\Userinit`), ignoring UI settings |
| **FP-06: Corporate Domain** | Telemetry references `update.microsoft.com` or `accounts.google.com` | **SUPPRESSED** (`matched: False`, Score: 20) | Benign domain whitelist checks indicators against trusted corporate infrastructure |

---

## 5. Live Threat Hunting Queries in Splunk Enterprise

Five production threat hunting queries were formulated, validated, and executed directly against live Splunk Enterprise:

### Hunt 1: Suspicious PowerShell Execution (TH-HUNT-01)
- **SPL Query**:
  ```spl
  (index=sysmon EventCode=1 (Image="*powershell.exe" OR Image="*pwsh.exe") (CommandLine="*-enc*" OR CommandLine="*-ExecutionPolicy Bypass*" OR CommandLine="*downloadstring*")) 
  OR (index=powershell EventCode=4104 (ScriptBlockText="*bypass*" OR ScriptBlockText="*downloadstring*" OR ScriptBlockText="*System.Net.WebClient*"))
  | stats count min(_time) as first_seen max(_time) as last_seen by host, user, Image, CommandLine
  | sort - count
  ```
- **Live Splunk Verification**: Successfully isolated the Phase 5 execution markers (`PHASE5_SIM_PS01_MARKER`) on `LAPTOP-OUBJLUDB` while ignoring thousands of normal Windows PowerShell module loadings.

### Hunt 2: Authentication Anomalies & Targeted User Spraying (TH-HUNT-02)
- **SPL Query**:
  ```spl
  index=windows EventCode=4625 
  | stats count as failure_count, values(SubStatus) as error_codes, values(WorkstationName) as source_workstations by host, TargetUserName
  | where failure_count >= 3
  | sort - failure_count
  ```
- **Live Splunk Verification**: Successfully surfaced targeted brute-force activity against `Phase5SecTestUser` (3 failed attempts, SubStatus `0xC000006A`), cleanly filtering out single user mistakes.

### Hunt 3: Suspicious Process Cross-Access (TH-HUNT-03)
- **SPL Query**:
  ```spl
  index=sysmon EventCode=10 (GrantedAccess="0x1F0FFF" OR GrantedAccess="0x1010" OR GrantedAccess="0x143A" OR GrantedAccess="0x1000")
  | stats count, values(CallTrace) as traces by host, SourceImage, TargetImage, GrantedAccess
  | sort - count
  ```
- **Live Splunk Verification**: Accurately audited process access masks, identifying query-limited handles (`0x1000` from `python.exe`) while highlighting potential injection candidates.

### Hunt 4: Persistence via Registry Autostart Modification (TH-HUNT-04)
- **SPL Query**:
  ```spl
  index=sysmon (EventCode=12 OR EventCode=13) (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*" OR TargetObject="*\\Windows\\CurrentVersion\\Explorer\\StartupApproved*" OR TargetObject="*\\Phase5Lab*")
  | stats count, values(Details) as registry_values by host, Image, TargetObject
  | sort - count
  ```
- **Live Splunk Verification**: Accurately identified modification of autostart locations and verified the presence of the controlled `Phase5Lab` persistence registry artifact.

### Hunt 5: Rare Outbound Network Sockets & LOLBAS Connections (TH-HUNT-05)
- **SPL Query**:
  ```spl
  index=sysmon EventCode=3 (Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*certutil.exe" OR Image="*mshta.exe" OR Image="*cscript.exe" OR Image="*wscript.exe" OR Image="*rundll32.exe")
  | stats count, values(DestinationPort) as dst_ports by host, Image, DestinationIp
  | sort - count
  ```
- **Live Splunk Verification**: Captured socket establishment by `powershell.exe` connecting to loopback port `5000` during `PS-03` simulation while filtering all standard application traffic.

---

## 6. Full Regression Test Execution Metrics

The complete test suite was executed in Windows PowerShell using pytest across all test modules:

```
Command: powershell -Command "cd backend; python -m pytest tests/ -v"
Test Run Duration: 244.96 seconds (04:04)
Test Session Exit Code: 0 (Clean Pass)
```

### 6.1 Test Module Breakdown

| Test Module | Tests | Result | Focus Area |
| :--- | :---: | :---: | :--- |
| `tests/test_api.py` | 2 | **PASSED** | Core health & investigation upload endpoints |
| `tests/test_audit_end_to_end.py` | 20 | **PASSED** | 20-point comprehensive SOC application audit |
| `tests/test_headers.py` | 1 | **PASSED** | SPF, DKIM, and DMARC authentication parsing |
| `tests/test_ioc_extractor.py` | 2 | **PASSED** | Defanging, regex extraction, CSV/JSON serialization |
| `tests/test_live_and_mocked_integrations.py` | 15 | **PASSED** | VirusTotal, AbuseIPDB, URLScan, OpenAI, RDAP APIs |
| `tests/test_parser.py` | 3 | **PASSED** | Legitimate, malicious macro, and raw text email parsing |
| `tests/test_phase3_siem_correlation.py` | 11 | **PASSED** | Campaign correlation, Splunk/Wazuh decoupling, playbooks |
| `tests/test_phase4_splunk_live.py` | 15 | **PASSED** | Live Splunk REST queries, Sysmon/Security/PowerShell indexes |
| `tests/test_phase5_api_endpoints.py` | 1 | **PASSED** | Simulation execution API endpoints and validation |
| `tests/test_phase5_soc_simulations.py` | 13 | **PASSED** | Simulations PS-01 through PS-08 live telemetry verification |
| `tests/test_phase6_detection_engineering.py` | 11 | **PASSED** | Detection tuning, FP suppression, scoring, hunting queries |
| `tests/test_rules_and_scoring.py` | 1 | **PASSED** | Email risk score calculation and heuristic rule engines |
| **TOTAL** | **95** | **100% PASSED** | **Zero Regressions Across All Phases 1–6A** |

### 6.2 Live Telemetry vs. Mocked/Degraded Breakdown
- **Live Environment Tests (78 tests)**: Tested against the live Windows 11 host operating system, live local Splunk Enterprise REST service (`https://127.0.0.1:8089`), live Windows Event Log service, live Sysmon v15 driver, real SQLite database persistence, live cryptographic hashing (SHA256), and live RDAP network queries.
- **Mocked / Degraded Mode Tests (17 tests)**: Tested safety fallbacks when external third-party cloud services are unconfigured, rate-limited, or encountering network failures (e.g., VirusTotal 429 quota exhaustion, AbuseIPDB invalid API key, OpenAI rate limit fallback to deterministic summarization, and Wazuh not-installed handling).

---

## 7. Deliverables Summary

The following formal documentation artifacts have been generated in the project root and artifact directories:

1. **`phase6_detection_engineering.md`**: Complete technical specifications for rules `DET-PS01` through `DET-IOC06`, including tuning logic, thresholds, parent-child correlations, and suppression keys.
2. **`phase6_false_positive_analysis.md`**: In-depth false-positive study detailing six corporate benign baselines and their automated suppression mechanisms.
3. **`phase6_mitre_mapping.md`**: Comprehensive enterprise matrix mapping all detection rules and hunting queries to MITRE ATT&CK Tactics, Techniques, Sub-techniques, and evidence sources.
4. **`phase6_threat_hunting_queries.md`**: Five production-ready Splunk SPL hunting queries with field dictionaries, analyst execution guides, and triage response steps.
5. **`phase6_validation_report.md`**: Executive validation report (this document) recording architecture status, test metrics, and verification evidence.

---

## 8. Audit Sign-Off & Conclusion

Phase 6A has met every requirement specified for Advanced SOC Detection Engineering:
- **No alert fabrication**: Every endpoint detection is anchored in real Splunk telemetry.
- **No false-positive alert floods**: Benign administrative baselines and isolated user mistakes are cleanly suppressed.
- **No arbitrary critical alerts**: Critical severity is mathematically gated behind composite multi-factor evidence.
- **Architectural continuity**: All Phase 1–5 capabilities remain 100% intact with 95/95 passing regression tests.

**Engineering Status**: **PHASE 6A COMPLETE & FULLY VALIDATED**
