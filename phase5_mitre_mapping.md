# Phase 5: MITRE ATT&CK Enterprise Matrix Mapping

## Document Information
- **System**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 5 — SOC Attack Simulation & Detection Engineering
- **Framework**: MITRE ATT&CK Enterprise Framework (v14)
- **Target OS**: Windows 11 Enterprise (`LAPTOP-OUBJLUDB`)

---

## 1. Enterprise Matrix Alignment Overview

| Tactic | Technique ID | Technique Name | Simulation ID | Detection Rule | Telemetry Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Spearphishing Attachment | PS-07, PS-08 | DET-IOC06 | Email Parser / Sysmon EID 1, 11 |
| **Initial Access** | T1566.002 | Spearphishing Link | PS-07, PS-08 | DET-IOC06 | Email Parser / Sysmon EID 3, 22 |
| **Execution** | T1204.001 | User Execution: Malicious Link | PS-07, PS-08 | DET-IOC06 | Browser / Sysmon EID 3 |
| **Execution** | T1204.002 | User Execution: Malicious File | PS-04, PS-07 | DET-FILE04, DET-IOC06 | Sysmon EID 1 |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | PS-01, PS-03, PS-04 | DET-PS01, DET-NET03 | Sysmon EID 1, PowerShell EID 4104 |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | PS-01 | DET-PS01 | PowerShell EID 4104 / Sysmon EID 1 |
| **Credential Access** | T1110.001 | Brute Force: Password Guessing | PS-02 | DET-AUTH02 | Windows Security EID 4625 |
| **Credential Access** | T1110.003 | Brute Force: Password Spraying | PS-02 | DET-AUTH02 | Windows Security EID 4625 |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | PS-03 | DET-NET03 | Sysmon EID 3 |
| **Command and Control** | T1105 | Ingress Tool Transfer | PS-04 | DET-FILE04 | Sysmon EID 11 |
| **Persistence** | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | PS-05 | DET-REG05 | Sysmon EID 12, 13 |
| **Discovery** | T1057 | Process Discovery | PS-06 | PS-06 (Audited) | Sysmon EID 10 |

---

## 2. In-Depth Technique & Detection Analysis

### 2.1 T1566.001 / T1566.002: Phishing (Attachments & Links)
- **Observed Behavior**: Ingestion of suspicious `.eml` payload containing credential-harvesting hyperlinked URLs and macro/script attachments.
- **Detections**:
  - Email Parser extracts raw URLs, defangs indicators (`hxxp://`), resolves redirects, and evaluates SPF/DKIM/DMARC authentication.
  - Threat Intelligence orchestrator queries VirusTotal and AbuseIPDB.
  - `DET-IOC06` queries Splunk to verify if endpoint users opened links or initiated network connections to the sender IP or malicious domains.

### 2.2 T1059.001: PowerShell Execution & T1027: Obfuscation
- **Observed Behavior**: Invocation of `powershell.exe` with execution policy bypass flags, encoded command strings, and in-memory evaluations (`Invoke-Expression`).
- **Detections**:
  - `DET-PS01`: Captures process creation in `sysmon` (EID 1) matching `-EncodedCommand`, `-enc`, `Invoke-Expression`, or `DownloadString`.
  - PowerShell Script Block Logging (EID 4104) de-obfuscates the executed memory stream into plain text for analyst inspection.

### 2.3 T1110.001: Brute Force Password Guessing
- **Observed Behavior**: Sequential failed logon attempts against designated user accounts generating multiple Event ID 4625 records.
- **Detections**:
  - `DET-AUTH02`: Aggregates Event ID 4625 across 5-minute windows grouped by `TargetUserName`. Fires when `failure_count >= 3`. Distinguishes bad password (`0xC000006A`) from disabled account or account lockout (`0xC0000234`).

### 2.4 T1071.001: Application Layer Protocol (Web Protocols via LOLBAS)
- **Observed Behavior**: PowerShell creating raw TCP sockets on HTTP/HTTPS ports to interact with local/remote web endpoints.
- **Detections**:
  - `DET-NET03`: Monitors Sysmon Event ID 3 for non-browser processes (`powershell.exe`, `cmd.exe`, `wscript.exe`) establishing network sockets on ports 80, 443, 8080, 5000.

### 2.5 T1105: Ingress Tool Transfer & T1547.001: Registry Persistence
- **Observed Behavior**: Payload drop in user staging directory (`backend/data/phase5_lab/phase5_marker.ps1`) followed by autostart registry key creation.
- **Detections**:
  - `DET-FILE04`: Sysmon Event ID 11 monitors file drops with `.ps1`, `.vbs`, `.exe`, or `.dll` extensions in user temporary and staging folders.
  - `DET-REG05`: Sysmon Event ID 13 captures `SetValue` operations targeting Run keys or application persistence registries.

