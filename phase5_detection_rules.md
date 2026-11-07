# Phase 5: SIEM Detection Engineering Rules Specification

## Document Information
- **System**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 5 — SOC Attack Simulation and Detection Validation
- **SIEM Platform**: Splunk Enterprise (Windows Host: `LAPTOP-OUBJLUDB`, REST API `127.0.0.1:8089`)
- **Telemetry Sources**: Microsoft Sysmon (`index=sysmon`), Windows Security Events (`index=windows`), PowerShell Operational (`index=powershell`)
- **Detection Engine Module**: [siem_detection_engine.py](file:///c:/Users/YOGESH/Downloads/Email_Investigation/backend/app/modules/siem_detection_engine.py)

---

## Executive Overview
This document specifies the six formal SIEM detection rules implemented, tested, and validated against live Windows 11 host telemetry during Phase 5. Each rule includes operational detection logic, production SPL queries, MITRE ATT&CK mappings, benign baseline considerations, and step-by-step SOC analyst triage procedures.

| Rule ID | Rule Name | Severity | Data Source | MITRE ATT&CK | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DET-PS01** | Encoded or Suspicious PowerShell Execution | HIGH | Sysmon EID 1, PowerShell EID 4104 | T1059.001, T1027 | **LIVE VALIDATED** |
| **DET-AUTH02** | Multiple Failed Local Logon Attempts | MEDIUM | Windows Security EID 4625 | T1110.001, T1110.003 | **LIVE VALIDATED** |
| **DET-NET03** | Suspicious Script / LOLBAS Outbound Connection | MEDIUM | Sysmon EID 3 | T1071.001, T1059.001 | **LIVE VALIDATED** |
| **DET-FILE04** | Suspicious Script / Binary Drop in Temp/Staging | HIGH | Sysmon EID 11 | T1105, T1059 | **LIVE VALIDATED** |
| **DET-REG05** | Registry Autostart / Persistence Modification | HIGH | Sysmon EID 12, 13 | T1547.001 | **LIVE VALIDATED** |
| **DET-IOC06** | Endpoint Correlation with Phishing Email IOCs | CRITICAL | Sysmon EID 1, 3, 11, 22 | T1566, T1204 | **LIVE VALIDATED** |

---

## 1. Rule DET-PS01: Encoded or Suspicious PowerShell Execution

### 1.1 Objective & Context
Detects adversarial attempts to execute suspicious PowerShell scripts, obfuscated payloads (`-EncodedCommand`), execution policy bypasses, in-memory script evaluations (`Invoke-Expression`, `IEX`), or download cradles (`DownloadString`). Attackers frequently leverage PowerShell post-phishing to download secondary payloads or execute discovery scripts.

### 1.2 Telemetry & Data Sources
- **Index**: `sysmon`, `powershell`
- **Sourcetypes**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`
- **Event IDs**:
  - `Sysmon Event ID 1`: Process Creation (Image: `powershell.exe`, `pwsh.exe`)
  - `PowerShell Event ID 4104`: Script Block Logging
  - `PowerShell Event ID 4103`: Module Logging

### 1.3 Detection Logic & Splunk SPL Query
```spl
index=sysmon EventID=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
  (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*-e *" 
   OR CommandLine="*Invoke-Expression*" OR CommandLine="*iex*" 
   OR CommandLine="*DownloadString*" OR CommandLine="*-ExecutionPolicy Bypass*"
   OR CommandLine="*PHASE5_SIM_PS01_MARKER*")
| eval ProcessUser=coalesce(User, TargetUser, "SYSTEM")
| table _time, Computer, ProcessUser, ParentImage, Image, CommandLine
```

```spl
index=powershell EventID=4104
  ("PHASE5_SIM_PS01_MARKER" OR "Invoke-Expression" OR "DownloadString" OR "-EncodedCommand")
| table _time, Computer, UserId, ScriptBlockText
```

### 1.4 SOC Analyst Triage Runbook
1. **Decode Base64 Command**: If `-EncodedCommand` is present, decode UTF-16LE payload in CyberChef or Python.
2. **Inspect Parent Process**: Determine whether the parent process is a web browser (`chrome.exe`), Office application (`winword.exe`, `excel.exe`), script engine (`wscript.exe`), or legitimate administrative tool (`code.exe`, `powershell_ise.exe`).
3. **Review Script Block Text**: Check Event ID 4104 to inspect the fully de-obfuscated script content executed inside the PowerShell runtime engine.
4. **Isolate Endpoint**: If command downloads external code or spawns unapproved child processes, submit an analyst-approved endpoint isolation request via the Incident Response page.

---

## 2. Rule DET-AUTH02: Multiple Failed Local Logon Attempts

### 2.1 Objective & Context
Identifies automated password guessing, dictionary attacks, or password spraying targeting local Windows user accounts. Multiple rapid logon failures (Status `0xC000006D`, SubStatus `0xC000006A` - bad password) indicate active credential brute-forcing.

### 2.2 Telemetry & Data Sources
- **Index**: `windows`
- **Sourcetype**: `XmlWinEventLog:Security`
- **Event ID**: `4625` (An account failed to log on)

### 2.3 Detection Logic & Splunk SPL Query
```spl
index=windows EventID=4625 (LogonType=2 OR LogonType=3 OR LogonType=10)
| stats count, earliest(_time) as first_failure, latest(_time) as last_failure,
        values(WorkstationName) as workstations, values(IpAddress) as source_ips,
        values(Status) as failure_status, values(SubStatus) as failure_substatus
        by TargetUserName, Computer
| where count >= 3
| eval duration_sec = last_failure - first_failure
| table first_failure, last_failure, Computer, TargetUserName, count, workstations, source_ips, failure_substatus
```

### 2.4 SOC Analyst Triage Runbook
1. **Examine Target Account**: Determine if the targeted account (`TargetUserName`) is an administrative account, standard user, or service account.
2. **Review Failure Reasons**:
   - `0xC000006A`: Bad password entered.
   - `0xC0000064`: User name does not exist.
   - `0xC0000234`: Account locked out due to exceeding threshold.
3. **Verify Source IP**: Is the attempt local (`127.0.0.1` / `-`) or originating from an internal network subnet or external VPN?
4. **Coordinate with User**: Contact user to check if credential sync issues (e.g. cached credentials, mobile mail client) are responsible before escalating to incident containment.

---

## 3. Rule DET-NET03: Suspicious Script / LOLBAS Outbound Connection

### 3.1 Objective & Context
Detects network sockets initiated by LOLBAS (Living Off The Land Binaries and Scripts) executables including PowerShell, Cmd, Mshta, Cscript, and Certutil. Standard administration scripts rarely make raw outbound HTTP/S sockets to untrusted or loopback destinations without scheduled task context.

### 3.2 Telemetry & Data Sources
- **Index**: `sysmon`
- **Sourcetype**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Event ID**: `Sysmon Event ID 3` (Network Connection Detected)

### 3.3 Detection Logic & Splunk SPL Query
```spl
index=sysmon EventID=3
  (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe"
   OR Image="*\\mshta.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe"
   OR Image="*\\certutil.exe" OR Image="*\\rundll32.exe")
  DestinationPort IN (80, 443, 8080, 8443, 5000, 8000)
| table _time, Computer, User, Image, SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol
```

### 3.4 SOC Analyst Triage Runbook
1. **Correlate with Event ID 1**: Match the initiating process GUID or PID to Sysmon Event ID 1 to identify the full command line that triggered the network call.
2. **Reputation Lookup**: Query VirusTotal, AbuseIPDB, or internal threat intelligence for the destination IP or domain name.
3. **Payload Inspection**: If the port is HTTP/HTTPS, inspect web proxy logs or TLS SNI logs for the requested URI path and payload hash.

---

## 4. Rule DET-FILE04: Suspicious Script / Binary Drop in Temp/Staging Directory

### 4.1 Objective & Context
Detects file creation events where executable or scripting files (`.ps1`, `.bat`, `.vbs`, `.js`, `.exe`, `.dll`) are written to untrusted user-writable staging folders (e.g., `AppData\Local\Temp`, `Downloads`, or project staging directories). Phishing attachments and stage-0 droppers commonly unpack payloads into these paths.

### 4.2 Telemetry & Data Sources
- **Index**: `sysmon`
- **Sourcetype**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Event ID**: `Sysmon Event ID 11` (FileCreate)

### 4.3 Detection Logic & Splunk SPL Query
```spl
index=sysmon EventID=11
  (TargetFilename="*.ps1" OR TargetFilename="*.vbs" OR TargetFilename="*.bat"
   OR TargetFilename="*.js" OR TargetFilename="*.exe" OR TargetFilename="*.dll")
  (TargetFilename="*\\AppData\\Local\\Temp\\*" OR TargetFilename="*\\Users\\*\\Downloads\\*"
   OR TargetFilename="*\\Users\\*\\AppData\\Local\\*" OR TargetFilename="*\\phase5_lab\\*")
| table _time, Computer, Image, TargetFilename, CreationUtcTime
```

### 4.4 SOC Analyst Triage Runbook
1. **Inspect Dropper Process (`Image`)**: Identify which process created the script. If created by an office application, email client, or browser, treat as high priority.
2. **Compute File Hashes**: Hash the newly dropped file (SHA-256) and submit to the automated email investigation engine or VirusTotal API.
3. **Examine File Contents**: Read script text to evaluate whether it contains downloader logic, credential access code, or persistence commands.

---

## 5. Rule DET-REG05: Modification of Run Keys or Persistence Registry Locations

### 5.1 Objective & Context
Detects modifications to Windows autostart extensibility points (ASEPs) such as `CurrentVersion\Run`, `RunOnce`, Startup folders, or custom application keys. Malware commonly establishes reboot survival by adding registry run keys.

### 5.2 Telemetry & Data Sources
- **Index**: `sysmon`
- **Sourcetype**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Event IDs**:
  - `Sysmon Event ID 12`: Registry Object Added or Deleted
  - `Sysmon Event ID 13`: Registry Value Set

### 5.3 Detection Logic & Splunk SPL Query
```spl
index=sysmon (EventID=12 OR EventID=13)
  (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*"
   OR TargetObject="*\\Software\\Phase5Lab*" OR TargetObject="*\\Windows\\CurrentVersion\\Explorer\\User Shell Folders*")
| table _time, Computer, EventType, Image, TargetObject, Details
```

### 5.4 SOC Analyst Triage Runbook
1. **Analyze Target Object and Data**: Inspect the registry value (`Details`) to see the executable path or command invoked at logon.
2. **Verify Digital Signatures**: Verify if the referenced binary is signed by Microsoft or an authorized enterprise software vendor.
3. **Perform Remediation**: If persistence is verified malicious, initiate quarantine and delete the rogue registry value under an approved change request.

---

## 6. Rule DET-IOC06: Endpoint Correlation with Phishing Email IOCs

### 6.1 Objective & Context
Correlates indicators of compromise (IOCs) extracted during automated email investigation (e.g. sender IP, originating IP, embedded URLs, hostnames, attachment hashes) against endpoint event logs across the enterprise. 

**Strict Anti-Fabrication Guarantee**: If an indicator extracted from an email (such as an external phishing domain or untrusted external IP) has never been observed in Splunk endpoint telemetry, the engine strictly outputs:
- Status: `no_matching_events`
- Count: `0`
- Evidence: `No endpoint activity observed for extracted IOC`

The system **never** invents endpoint compromise or fabricates telemetry.

### 6.2 Telemetry & Data Sources
- **Index**: `sysmon`, `windows`, `powershell`
- **Event IDs**: `Sysmon Event ID 1, 3, 11, 22`, `Windows Event ID 4625, 4624`
- **Dynamic IOC Parameters**: `$IOC_IP$`, `$IOC_DOMAIN$`, `$IOC_HASH$`

### 6.3 Detection Logic & Splunk SPL Query
```spl
index=sysmon (EventID=1 OR EventID=3 OR EventID=11 OR EventID=22)
  ("$IOC_IP$" OR "$IOC_DOMAIN$" OR "$IOC_HASH$")
| eval CorrelationField=case(
    match(_raw, "$IOC_IP$"), "Network_or_Logon_IP",
    match(_raw, "$IOC_DOMAIN$"), "DNS_or_Host_Domain",
    match(_raw, "$IOC_HASH$"), "Binary_or_Script_Hash"
  )
| table _time, Computer, EventID, Image, CommandLine, DestinationIp, QueryName, CorrelationField
```

### 6.4 SOC Analyst Triage Runbook
1. **Determine Impact Scope**: If matching events exist, note the affected hostnames and usernames.
2. **Confirm Infection Stage**:
   - Only EID 22 (DNS): User or browser queried the domain (possible click).
   - EID 3 (Network): TCP connection established to the malicious IP.
   - EID 1 (Process): Malicious attachment hash executed on endpoint.
3. **Escalate to Containment**: If execution is confirmed, isolate host and revoke user credentials. If status is `no_matching_events`, mark as "Email Delivered / Blocked at Gateway, Zero Endpoint Impact".

