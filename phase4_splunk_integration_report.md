# Phase 4: Splunk Enterprise REST API Live Integration Report

**System:** AI-Powered Automated Email Investigation and Phishing Detection System  
**Environment:** Windows 11 Enterprise (Host OS)  
**SIEM Target:** Splunk Enterprise 10.6.1.1 (Native Windows Service, Build `b2ae2962645c`)  
**Collector:** Microsoft Sysmon v15+ (`Microsoft-Windows-Sysmon/Operational`) & Splunk Universal Forwarder  
**Status:** **OPERATIONAL & LIVE VALIDATED**  
**Classification:** **LIVE PASSED**  

---

## 1. Executive Summary

Phase 4 bridges the Automated Email Investigation and Phishing Detection System directly to a live, on-premise Windows 11 Splunk Enterprise SIEM instance. The integration queries indexed endpoint, authentication, and script execution logs via the Splunk REST API (`https://127.0.0.1:8089`) without requiring intermediaries, mock data, or external virtual machines.

As required by project specifications:
- **Splunk Enterprise** is running natively on Windows 11 listening on ports `8089` (REST API), `8000` (Web UI), and forwarding ingestion via `9997`.
- **Wazuh** is not installed and is maintained as **OPTIONAL / NOT CONFIGURED** across both backend telemetry and the analyst UI.
- Real-time queries directly search across **155,680+ live events** indexed in `sysmon`, `windows`, and `powershell`.
- The anti-fabrication guardrail is strictly enforced: indicators not observed in endpoint telemetry are categorized as `no_matching_events`, preserving forensic integrity.

---

## 2. Infrastructure Architecture & Telemetry Pipeline

```mermaid
flowchart TD
    subgraph Host["Host Machine: Windows 11 (LAPTOP-OUBJLUDB)"]
        subgraph Endpoints["Endpoint Telemetry Sources"]
            Sysmon["Sysmon64 Service<br>(Driver: SysmonDrv.sys)"]
            WinSec["Windows LSA Subsystem<br>(lsass.exe / Security Log)"]
            PSCore["PowerShell Engine<br>(Operational ScriptBlock 4104)"]
        end

        subgraph Ingestion["Log Transport Pipeline"]
            UF["Splunk Universal Forwarder<br>(outputs.conf: 127.0.0.1:9997)"]
        end

        subgraph SIEM["Splunk Enterprise 10.6.1.1"]
            SplunkReceiver["Splunk TCP Receiver<br>(Port 9997)"]
            Splunkd["Splunkd Daemon / Search Head<br>(Port 8089 HTTPS REST API)"]
            IdxSysmon[("index=sysmon<br>54,855 events")]
            IdxWin[("index=windows<br>98,842 events")]
            IdxPS[("index=powershell<br>1,983 events")]
        end

        subgraph EmailApp["Automated Email Investigation Platform"]
            FlaskBackend["Flask REST API<br>(http://127.0.0.1:5000)"]
            SplunkClient["splunk_client.py<br>(Authenticated HTTPS Client)"]
            CorrEngine["correlation_engine.py<br>(Cross-Source Correlator)"]
            ReactUI["React + Vite Frontend<br>(http://127.0.0.1:5173)"]
        end
    end

    Sysmon -->|XML Channel| UF
    WinSec -->|XML Channel| UF
    PSCore -->|XML Channel| UF
    UF -->|TCP 9997 Forwarding| SplunkReceiver
    SplunkReceiver --> IdxSysmon
    SplunkReceiver --> IdxWin
    SplunkReceiver --> IdxPS
    IdxSysmon --- Splunkd
    IdxWin --- Splunkd
    IdxPS --- Splunkd
    SplunkClient -->|HTTPS REST Auth (Port 8089)| Splunkd
    FlaskBackend --> SplunkClient
    FlaskBackend --> CorrEngine
    ReactUI <--> FlaskBackend
```

---

## 3. Discovered Splunk Catalog & Telemetry Inventory

Inspection of the live Splunk Enterprise instance via `/services/server/info` and `/services/data/indexes` revealed the following active data pipeline:

| Index Name | Real Indexed Event Count | Dominant Sourcetype | Primary Monitored Event IDs |
| :--- | :--- | :--- | :--- |
| **`sysmon`** | **54,855** | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Event ID 1 (Process Create), Event ID 3 (Network Connect), Event ID 5 (Process Terminate), Event ID 10 (Process Access), Event ID 11 (File Create) |
| **`windows`** | **98,842** | `XmlWinEventLog:Security`, `XmlWinEventLog:System`, `XmlWinEventLog:Application` | Event ID 4624 (Logon Success), Event ID 4625 (Logon Failure), Event ID 4672 (Privilege Assignment), Event ID 4689 (Process Exit) |
| **`powershell`** | **1,983** | `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` | Event ID 4104 (Script Block Logging), Event ID 4103 (Module Execution) |
| **`main`** | **0** | Default | Reserved / Standalone synthetic uploads |
| **Total** | **155,680+** | Multi-Source | Unified SOC Investigation Dataset |

---

## 4. Key Engineering Implementations

### 4.1 Native XML Windows Event Parsing
Splunk forwarders with `renderXml = true` transmit structured XML records wrapped in `<Event xmlns="...">`. Standard key extraction frequently misses unparsed XML tags unless specific field extraction rules exist.

The enhanced [splunk_client.py](file:///c:/Users/YOGESH/Downloads/Email_Investigation/backend/app/utils/splunk_client.py) implements a high-throughput XML parser (`_parse_xml_raw`) that automatically unpacks both:
- **System Tag Attributes:** `EventID`, `TimeCreated`, `Computer`, `Execution` (ProcessID/ThreadID), `Keywords`.
- **EventData Key-Value Elements:** Dynamically extracts `<Data Name="Image">`, `<Data Name="CommandLine">`, `<Data Name="Hashes">`, `<Data Name="DestinationIp">`, `<Data Name="TargetUserName">`, `<Data Name="TargetLogonId">`, and `<Data Name="ScriptBlockText">`.

This ensures that regardless of whether Splunk has field extraction rules pre-installed, every single event field is immediately accessible to the correlation engine.

### 4.2 Cross-Source Email IOC Correlation Workflow
When an analyst inspects a suspicious email or triggers the correlation engine:
1. **IOC Extraction:** SHA256/MD5 hashes, sender IP, originating IPs, embedded URLs, domain names, and recipient usernames are collected.
2. **Targeted SPL Queries:**
   - **Sysmon:** Queries `index=sysmon` for matching process creation hashes (`Hashes="*{hash}*"`) or outbound C2 network sockets (`DestinationIp="{ip}"`).
   - **Windows Security:** Queries `index=windows` for authentication events (4624/4625) linking to the caller IP or recipient username.
   - **PowerShell:** Queries `index=powershell` for script block commands (4104).
3. **Forensic Attribution & Guardrails:**
   - If an endpoint event matches: Classified as `confirmed` and highlighted on the chronological incident timeline with Process Name, Parent PID, and Session LogonId.
   - If no event matches: Recorded as `no_matching_events`. The system explicitly states that no execution was observed on monitored endpoints, preventing false positives.

### 4.3 Security & Credential Isolation
- Credentials (`SPLUNK_USERNAME`, `SPLUNK_PASSWORD`) are stored exclusively in `backend/.env`.
- Root `.gitignore` and `backend/.gitignore` strictly exclude `.env`, `.env.*`, and credential artifacts.
- Zero credentials or tokens are printed to terminal logs, returned in API payloads, or exposed to the React frontend.
- Authentication failures (HTTP 401/403) and rate limits (HTTP 429) are gracefully handled in degraded mode without crashing the server.

---

## 5. Verification Status

| Integration Check | Result | Evidence |
| :--- | :--- | :--- |
| **Splunk Enterprise REST API Ping** | **LIVE PASSED** | HTTP 200 via `https://127.0.0.1:8089/services/server/info` |
| **Catalog & Index Metrics** | **LIVE PASSED** | Discovered `sysmon` (54,855), `windows` (98,842), `powershell` (1,983) |
| **Sysmon Event Extraction** | **LIVE PASSED** | Retrieved Process Create & Network Socket events with full XML fields |
| **Windows Security Extraction** | **LIVE PASSED** | Retrieved Event ID 4624/4689 with user and session attributes |
| **PowerShell Script Block Extraction** | **LIVE PASSED** | Retrieved Event ID 4104 with script code |
| **Anti-Fabrication Guardrail** | **LIVE PASSED** | Unobserved indicators correctly output `no_matching_events` |
| **Wazuh Status Display** | **LIVE PASSED** | Displayed as `OPTIONAL / NOT CONFIGURED` with zero fabricated alerts |
| **Regression Test Suites** | **LIVE PASSED** | 61/61 tests passing across Phases 1, 2, 3, and 4 |

