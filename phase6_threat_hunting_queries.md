# Phase 6A: Production Splunk Threat-Hunting Query Catalog

## Document Information
- **System**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 6A — Threat Hunting & Advanced Detection
- **SIEM Platform**: Splunk Enterprise 10.6.1.1 (Windows 11 `LAPTOP-OUBJLUDB`)
- **Indexes**: `sysmon`, `windows`, `powershell`

---

## Executive Overview
Threat hunting proactively searches for elusive adversarial behaviors that bypass standard alerting thresholds. The five queries below are constructed strictly from **verified available fields** in `index=sysmon`, `index=windows`, and `index=powershell`.

```
+========================================================================================================================+
| Hunt ID   | Hunting Scenario                | Target Index & Event IDs     | Primary Detection Indicators       |
+========================================================================================================================+
| HUNT-01   | Suspicious PowerShell Execution | sysmon (1), powershell (4104)| -enc, Bypass, Cradles, Word parent |
| HUNT-02   | Repeated Authentication Failures| windows (4625)               | SubStatus 0xC000006A, Burst >= 3   |
| HUNT-03   | Suspicious Process Access       | sysmon (10)                  | Target: lsass.exe, Access != 0x1000|
| HUNT-04   | Registry Persistence Changes    | sysmon (12, 13)              | Run, RunOnce, Services ImagePath   |
| HUNT-05   | Suspicious Script Network Sockets| sysmon (3)                  | Non-browser LOLBAS egress on ports |
+========================================================================================================================+
```

---

## 1. Hunt 1: Suspicious PowerShell Execution (Obfuscation & In-Memory Cradles)

### 1.1 Objective & Rationale
Identifies adversaries leveraging PowerShell post-phishing to download secondary payloads, execute encoded commands, or evade execution policies.

### 1.2 Splunk Query (SPL)
```spl
index=sysmon EventID=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval IsSuspicious=case(
    match(CommandLine, "(?i)-(enc|encodedcommand)\b"), "Base64_Encoded_Execution",
    match(CommandLine, "(?i)-ExecutionPolicy\s+Bypass\b"), "ExecutionPolicy_Bypass",
    match(CommandLine, "(?i)(downloadstring|downloadfile|webclient|invoke-webrequest)"), "Download_Cradle",
    match(CommandLine, "(?i)(invoke-expression|\biex\b)"), "In_Memory_Script_Evaluation",
    match(ParentImage, "(?i)(winword|excel|outlook|chrome|msedge|wscript|cscript)\.exe"), "Suspicious_Parent_Process",
    true(), "Normal_Admin"
  )
| where IsSuspicious!="Normal_Admin"
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen, 
        values(ParentImage) as parent_processes, values(User) as users 
        by Computer, IsSuspicious, CommandLine
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

### 1.3 Threat Hunter Triage & Pivot Runbook
1. If `IsSuspicious == "Suspicious_Parent_Process"`, inspect email client (`outlook.exe`) or browser downloads around `first_seen`.
2. Pivot to `index=powershell EventID=4104` matching `Computer` and `_time` to extract the full de-obfuscated script block text.
3. Check `ParentCommandLine` to determine if a macro document or shortcut launched the shell.

---

## 2. Hunt 2: Repeated Authentication Failures & Password Spraying

### 2.1 Objective & Rationale
Hunts for brute force guessing, password spraying, or credential stuffing targeting local accounts or domain credentials.

### 2.2 Splunk Query (SPL)
```spl
index=windows EventID=4625
| eval FailureReason=case(
    SubStatus="0xc000006a" OR SubStatus="0xC000006A", "Bad Password",
    SubStatus="0xc0000064" OR SubStatus="0xC0000064", "Unknown Username",
    SubStatus="0xc0000234" OR SubStatus="0xC0000234", "Account Locked Out",
    true(), "Other Failure"
  )
| bin _time span=5m
| stats count as failure_burst, 
        values(WorkstationName) as workstations, 
        values(IpAddress) as source_ips, 
        values(LogonType) as logon_types 
        by _time, Computer, TargetUserName, FailureReason
| where failure_burst >= 3
| sort - failure_burst
```

### 2.3 Threat Hunter Triage & Pivot Runbook
1. Inspect `FailureReason`: If `Bad Password`, verify whether a subsequent successful logon (`EventID=4624`) occurred within 5 minutes (user typo) or if the account locked out (`0xC0000234`).
2. If `source_ips` is an external VPN or unusual subnet, correlate with firewall and threat intel logs.
3. Correlate with `TargetUserName`: High-privilege targets (Domain Admins, Executive Accounts) require immediate credential resets.

---

## 3. Hunt 3: Suspicious Process Access & LSASS Handle Acquisition

### 3.1 Objective & Rationale
Identifies unapproved processes opening handles to the Local Security Authority Subsystem Service (`lsass.exe`) with memory-reading permissions (`PROCESS_VM_READ`).

### 3.2 Splunk Query (SPL)
```spl
index=sysmon EventID=10 TargetImage="*\\lsass.exe"
| eval AccessMaskDesc=case(
    GrantedAccess="0x1010" OR GrantedAccess="0x00001010", "PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ (High Suspicion)",
    GrantedAccess="0x1F0FFF" OR GrantedAccess="0x001f0fff", "PROCESS_ALL_ACCESS (Mimikatz / Full Dump)",
    GrantedAccess="0x1438" OR GrantedAccess="0x00001438", "PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE",
    GrantedAccess="0x1000" OR GrantedAccess="0x00001000", "PROCESS_QUERY_LIMITED_INFORMATION (Audited / Benign Probe)",
    true(), "Other Handle Mask"
  )
| eval IsKnownLegit=if(match(SourceImage, "(?i)(csrss|services|svchost|MsMpEng|GamingServices)\.exe"), 1, 0)
| where IsKnownLegit=0 OR (GrantedAccess!="0x1000" AND GrantedAccess!="0x2000")
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen 
        by Computer, SourceUser, SourceImage, TargetImage, GrantedAccess, AccessMaskDesc, CallTrace
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

### 3.3 Threat Hunter Triage & Pivot Runbook
1. Check `SourceImage`: If process is located in `Users\AppData` or `Temp`, treat as immediate credential theft incident.
2. Review `CallTrace`: Native DLLs vs unbacked memory modules (`UNKNOWN`).
3. Isolate host immediately if `GrantedAccess == "0x1F0FFF"` or `0x1010` from non-system processes.

---

## 4. Hunt 4: Persistence-Related Registry Autostart Modifications

### 4.1 Objective & Rationale
Uncovers malware establishing reboot persistence via Windows Autostart Extensibility Points (ASEPs), Run keys, or malicious service installations.

### 4.2 Splunk Query (SPL)
```spl
index=sysmon (EventID=12 OR EventID=13)
  (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*" 
   OR TargetObject="*\\Services\\*" OR TargetObject="*\\Software\\Phase5Lab*"
   OR TargetObject="*\\Windows\\CurrentVersion\\Explorer\\User Shell Folders*")
| eval Action=if(EventID=12, "Key_Created_Or_Deleted", "Value_Set")
| eval SuspiciousTarget=case(
    match(TargetObject, "(?i)\\CurrentVersion\\Run"), "Run_Autostart_Key",
    match(TargetObject, "(?i)\\CurrentVersion\\RunOnce"), "RunOnce_Autostart_Key",
    match(TargetObject, "(?i)\\Services\\.*\\ImagePath"), "Service_ImagePath_Modification",
    match(TargetObject, "(?i)Phase5Lab"), "Lab_Persistence_Branch",
    true(), "Other_ASEP"
  )
| table _time, Computer, Action, Image, SuspiciousTarget, TargetObject, Details
| sort - _time
```

### 4.3 Threat Hunter Triage & Pivot Runbook
1. Inspect `Details`: Check executable path in registry value. If path points to `%TEMP%`, `%APPDATA%`, or an unquoted service path with spaces, treat as high severity.
2. Check `Image`: Which process set the value? Did an Office application (`WINWORD.EXE`) or PowerShell modify the Run key?
3. Remediate rogue key via change management approval workflow.

---

## 5. Hunt 5: Suspicious Non-Browser Script-Initiated Network Connections

### 5.1 Objective & Rationale
Hunts for command-and-control beaconing, staging downloads, or data exfiltration initiated by non-browser utilities (LOLBAS).

### 5.2 Splunk Query (SPL)
```spl
index=sysmon EventID=3
| eval IsBrowser=if(match(Image, "(?i)(chrome|msedge|firefox|brave|opera)\.exe"), 1, 0)
| eval IsScriptEngine=if(match(Image, "(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|certutil|rundll32|regsvr32|python)\.exe"), 1, 0)
| where IsBrowser=0 AND (IsScriptEngine=1 OR DestinationPort IN (5000, 8089, 4444, 8080, 8443, 9001))
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen, 
        values(User) as users by Computer, Image, SourceIp, DestinationIp, DestinationPort, Protocol
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

### 5.3 Threat Hunter Triage & Pivot Runbook
1. If `DestinationIp` is an external public IP, query VirusTotal and AbuseIPDB for reputation.
2. Correlate with `EventID=1` (Process Creation) using PID to view full command-line arguments.
3. Check firewall or proxy logs for HTTP GET/POST URLs and payload sizes.
