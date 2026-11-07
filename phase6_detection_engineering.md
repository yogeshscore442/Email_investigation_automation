# Phase 6A: Advanced SOC Detection Engineering Specification

## Document Information
- **System**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 6A — Advanced SOC Detection Engineering & Tuning
- **SIEM Platform**: Splunk Enterprise 10.6.1.1 (Windows 11 `LAPTOP-OUBJLUDB`, REST API `https://127.0.0.1:8089`)
- **Telemetry Indexes**: `index=sysmon`, `index=windows`, `index=powershell`
- **Engine Module**: [`backend/app/modules/siem_detection_engine.py`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/backend/app/modules/siem_detection_engine.py)

---

## 1. Executive Summary & Engineering Philosophy

In modern enterprise SOC environments, rudimentary signature matching creates overwhelming alert volumes, high false-positive rates, and severe alert fatigue. Phase 6A elevates the platform's detection capabilities from basic pattern matching into an **advanced, evidence-grounded detection engineering system**.

### Key Detection Engineering Enhancements
1. **Dynamic Severity Scoring**: Never assigns `Critical` based on a single weak indicator. Requires multiple corroborating evidence items and an aggregate score $\ge 85$.
2. **Threshold & Burst Analysis**: Enforces sliding time-window thresholds (e.g., failed logons requiring $\ge 3$ attempts within 300 seconds).
3. **Parent-Child Process Context**: Dissects process lineage (e.g., Office applications or browsers spawning PowerShell are weighted significantly higher than legitimate shells).
4. **Duplicate Alert Suppression**: In-memory suppression window (600s) prevents repeated alerts with identical signatures `(rule_id, user, computer, signature)`.
5. **Benign Baseline Filtering**: Automatically filters out benign administrative cmdlets, browser web sockets, non-script file writes, and standard UI preference changes.

---

## 2. Detection Rules Catalog & Specification

```
+========================================================================================================================+
| Rule ID    | Name                            | Severity | MITRE ATT&CK | Telemetry Sources         | Base Score        |
+========================================================================================================================+
| DET-PS01   | Suspicious PowerShell Execution | High     | T1059.001    | Sysmon EID 1, PS EID 4104 | 60                |
| DET-AUTH02 | Repeated Failed Logons          | Medium   | T1110.001    | Windows Security EID 4625 | 45                |
| DET-NET03  | Unusual Script Network Socket   | Medium   | T1071.001    | Sysmon EID 3              | 50                |
| DET-FILE04 | Suspicious Script in Staging    | Medium   | T1105        | Sysmon EID 11             | 45                |
| DET-REG05  | Registry Autostart Modification | High     | T1547.001    | Sysmon EID 12, 13         | 65                |
| DET-IOC06  | Email IOC Endpoint Match        | Critical | T1566        | Sysmon EID 1, 3, 22       | 75                |
+========================================================================================================================+
```

---

## 3. In-Depth Rule Specifications

### 3.1 Rule DET-PS01: Suspicious PowerShell Execution
- **Detection Purpose**: Detects suspicious command-line invocations of PowerShell involving execution policy bypass, base64 encoding, in-memory script evaluations, download cradles, or abnormal parent processes.
- **Required Telemetry**:
  - `Sysmon Event ID 1` (Process Creation)
  - `PowerShell Event ID 4104` (Script Block Logging)
- **Production Splunk SPL**:
  ```spl
  index=sysmon EventID=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
    (CommandLine="*-enc*" OR CommandLine="*-ExecutionPolicy Bypass*" 
     OR CommandLine="*Invoke-Expression*" OR CommandLine="*DownloadString*" 
     OR CommandLine="*PHASE5_SIM_PS01_MARKER*")
  OR index=powershell EventID=4104 ("Invoke-Expression" OR "PHASE5_SIM_PS01_MARKER" OR "DownloadString")
  | table _time, Computer, User, ParentImage, Image, CommandLine, ScriptBlockText
  ```
- **Context & Parent-Child Logic**:
  - If `ParentImage` matches `winword.exe`, `excel.exe`, `outlook.exe`, or `chrome.exe`: **+25 points**.
  - If `CommandLine` includes `-enc` or Base64 payload: **+20 points**.
  - If `CommandLine` includes `DownloadString` or `Invoke-Expression`: **+20 points**.
  - If benign command (`Get-Process`, `Get-Service`): **-40 points** (Suppressed).

---

### 3.2 Rule DET-AUTH02: Repeated Failed Logon Attempts
- **Detection Purpose**: Identifies automated password guessing, brute force, or password spraying targeting local or domain accounts.
- **Required Telemetry**:
  - `Windows Security Event ID 4625` (An account failed to log on)
- **Production Splunk SPL**:
  ```spl
  index=windows EventID=4625 (Status="0xC000006D" OR SubStatus="0xC0000064" OR SubStatus="0xC000006A")
  | bin _time span=5m
  | stats count, earliest(_time) as first_seen, latest(_time) as last_seen,
          values(WorkstationName) as workstations, values(IpAddress) as source_ips
          by _time, TargetUserName, Computer
  | where count >= 3
  ```
- **Threshold & Time-Window Logic**:
  - Requires `count >= 3` failures within a 300-second window.
  - Isolated single failure (`count == 1`) is classified as benign typo and suppressed (`matched: False`).
  - If `TargetUserName` is `Administrator` or `root`: **+20 points**.
  - If `count >= 5`: **+25 points** (elevated to High).

---

### 3.3 Rule DET-NET03: Unusual Script-Initiated Network Connection
- **Detection Purpose**: Detects non-browser scripting utilities establishing network connections to management API ports (5000, 8089) or suspicious destinations.
- **Required Telemetry**:
  - `Sysmon Event ID 3` (Network Connection Detected)
- **Production Splunk SPL**:
  ```spl
  index=sysmon EventID=3 Image IN ("*\\powershell.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\cmd.exe", "*\\mshta.exe")
    DestinationPort IN (5000, 8089, 4444, 8080, 8443)
  | table _time, Computer, User, Image, SourceIp, DestinationIp, DestinationPort, Protocol
  ```
- **Process Lineage & Exclusion Logic**:
  - Standard browsers (`chrome.exe`, `msedge.exe`, `firefox.exe`) are explicitly excluded.
  - Sockets initiated by LOLBAS binaries receive **+15 points**.
  - Sockets to external non-RFC1918 IPs receive **+20 points**.

---

### 3.4 Rule DET-FILE04: Suspicious Script Creation in Dedicated Target Directory
- **Detection Purpose**: Identifies dropping of script or binary files into user staging folders (`Temp`, `AppData\Local\Temp`, `Downloads`, `phase5_lab`).
- **Required Telemetry**:
  - `Sysmon Event ID 11` (FileCreate)
- **Production Splunk SPL**:
  ```spl
  index=sysmon EventID=11 TargetFilename IN ("*.ps1", "*.bat", "*.vbs", "*.js", "*.exe", "*.dll")
    AND (TargetFilename="*\\Temp\\*" OR TargetFilename="*\\AppData\\Local\\Temp\\*" 
         OR TargetFilename="*\\Users\\*\\Downloads\\*" OR TargetFilename="*\\phase5_lab\\*")
  | table _time, Computer, Image, TargetFilename, CreationUtcTime
  ```
- **File Filtering Logic**:
  - Non-executable files (`.txt`, `.tmp`, `.log`, `.csv`, `.docx`) are explicitly ignored.
  - File in staging path + script extension yields **+25 points**.

---

### 3.5 Rule DET-REG05: Suspicious Registry Autostart Modification
- **Detection Purpose**: Monitors changes to Windows autostart extensibility points (Run, RunOnce, Startup, Services, or lab persistence branches).
- **Required Telemetry**:
  - `Sysmon Event ID 12` (Object Added/Deleted)
  - `Sysmon Event ID 13` (SetValue)
- **Production Splunk SPL**:
  ```spl
  index=sysmon (EventID=12 OR EventID=13)
    (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*" 
     OR TargetObject="*\\Services\\*" OR TargetObject="*\\Software\\Phase5Lab*")
  | table _time, Computer, EventType, Image, TargetObject, Details
  ```
- **Exclusion Logic**:
  - User preference keys (`\Explorer\Advanced\Hidden`, `\Control Panel\Desktop`) are rejected as benign.
  - Run/RunOnce additions yield **+25 points**.

---

### 3.6 Rule DET-IOC06: Email IOC to Endpoint Host Telemetry Correlation
- **Detection Purpose**: Correlates threat indicators extracted from investigated emails against host telemetry in Splunk.
- **Required Telemetry**:
  - Email Forensic Parser IOCs
  - `Sysmon Event ID 1, 3, 22`
  - `Windows Security Event ID 4624/4625`
- **Production Splunk SPL**:
  ```spl
  (index=sysmon (EventID=1 AND Hashes IN (email_hashes)) OR (EventID=3 AND DestinationIp IN (email_ips)) OR (EventID=22 AND QueryName IN (email_domains)))
  OR (index=windows EventID=4624 IpAddress IN (email_ips))
  ```
- **Anti-Fabrication & Reputation Gating**:
  - If IOC is in corporate domain whitelist (`microsoft.com`, `google.com`), alert is suppressed (**-40 points**).
  - Unobserved indicators produce `no_matching_events` and zero alert generation.
  - Confirmed endpoint match yields **+20 points**, resulting in a Critical alert only when corroborated by multiple telemetry items.

---

## 4. Evidence-Based Severity Scoring Algorithm

To avoid alert inflation, the engine calculates dynamic severity using the formula:
$$\text{Final Score} = \text{Clamp}_{5}^{100}\left(\text{Base Score} + \sum \text{Corroborating Factors} - \sum \text{Benign Factors}\right)$$

### Severity Tier Thresholds:
- **`Critical`** ($\ge 85$ points): Requires $\ge 2$ strong corroborating factors (e.g. Malicious parent + Encoded payload + C2 connection).
- **`High`** ($65 - 84$ points): Clear malicious pattern (e.g. ExecutionPolicy Bypass + Staged script drop).
- **`Medium`** ($40 - 64$ points): Anomalous behavior exceeding thresholds (e.g. 3 failed logons).
- **`Low`** ($20 - 39$ points): Isolated suspicious anomaly without corroborating activity.
- **`Informational`** ($< 20$ points): Benign activity with minor pattern overlap.

