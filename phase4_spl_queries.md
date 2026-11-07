# Phase 4: Production SPL Query Playbook & Telemetry Reference

**System:** AI-Powered Automated Email Investigation and Phishing Detection System  
**SIEM Platform:** Splunk Enterprise 10.6.1.1 (Windows 11 Local Indexer)  
**Target Indexes:** `index=sysmon`, `index=windows`, `index=powershell`  
**Purpose:** SOC Analyst query reference for pivoting from email IOCs to endpoint and network activity.  

---

## 1. Sysmon Telemetry Queries (`index=sysmon`)

### 1.1 Process Creation Matching Email Attachment Hash (Sysmon Event ID 1)
Identifies whether weaponized attachment binaries (EXE, DLL, SCR, ISO payloads) were executed on any monitored endpoint.

```spl
index=sysmon (EventID=1 OR "<EventID>1</EventID>")
| eval ProcImage=coalesce(Image, process_path)
| eval ProcCmd=coalesce(CommandLine, cmdline)
| eval ParentProc=coalesce(ParentImage, parent_process_path)
| eval ProcUser=coalesce(User, user)
| eval SessionID=coalesce(LogonId, LogonGuid)
| eval HashVal=coalesce(Hashes, hash)
| search HashVal="*<SHA256_OR_MD5_HASH>*" OR ProcImage="*<ATTACHMENT_FILENAME>*"
| table _time, Computer, ProcUser, SessionID, ParentProc, ProcImage, ProcCmd, ProcessId, ParentProcessId, HashVal
| sort - _time
```

### 1.2 Outbound Socket Connection to Malicious Sender or C2 IP (Sysmon Event ID 3)
Tracks network handshakes initiated by processes to malicious external coordinates discovered in email headers or body links.

```spl
index=sysmon (EventID=3 OR "<EventID>3</EventID>")
| eval ProcImage=coalesce(Image, process_path)
| eval SrcIP=coalesce(SourceIp, src_ip)
| eval DstIP=coalesce(DestinationIp, dest_ip)
| eval DstPort=coalesce(DestinationPort, dest_port)
| eval DstHost=coalesce(DestinationHostname, dest_host)
| search DstIP IN ("<SUSPICIOUS_SENDER_IP>", "<EXTERNAL_C2_IP>") OR DstHost="*<SUSPICIOUS_DOMAIN>*"
| table _time, Computer, ProcImage, ProcessId, User, SrcIP, SourcePort, DstIP, DstPort, DstHost, Protocol
| sort - _time
```

### 1.3 LSASS Memory Access & Credential Harvesting (Sysmon Event ID 10)
Detects post-compromise credential dumping attempts following macro execution or phishing payload delivery.

```spl
index=sysmon (EventID=10 OR "<EventID>10</EventID>")
| eval SourceBinary=coalesce(SourceImage, process_path)
| eval TargetBinary=coalesce(TargetImage, target_path)
| eval GrantedAccessMask=coalesce(GrantedAccess, access_mask)
| search TargetBinary="*\\lsass.exe" AND SourceBinary!="*\\svchost.exe" AND SourceBinary!="*\\csrss.exe"
| table _time, Computer, SourceBinary, SourceProcessId, TargetBinary, GrantedAccessMask, CallTrace
| sort - _time
```

### 1.4 Dropped File Creation in Staging Directories (Sysmon Event ID 11)
Monitors files written into shared or volatile folders (`AppData\Local\Temp`, `C:\Users\Public`).

```spl
index=sysmon (EventID=11 OR "<EventID>11</EventID>")
| eval TargetFile=coalesce(TargetFilename, file_path)
| eval ProcImage=coalesce(Image, process_path)
| search TargetFile="*\\AppData\\Local\\Temp\\*" OR TargetFile="*\\Users\\Public\\*"
| table _time, Computer, Image, TargetFile, CreationUtcTime, User
| sort - _time
```

---

## 2. Windows Security Queries (`index=windows`)

### 2.1 Failed Logon Triage & Password Spraying (Event ID 4625)
Differentiates user enumeration (`0xC0000064`) from credential guessing (`0xC000006A`).

```spl
index=windows (EventID=4625 OR EventCode=4625 OR "<EventID>4625</EventID>")
| eval TargetUser=coalesce(TargetUserName, user)
| eval SourceIP=coalesce(IpAddress, src_ip)
| eval SubStatusCode=coalesce(SubStatus, Sub_Status)
| eval FailureReason=case(
    SubStatusCode="0xC0000064", "Username does not exist (Enumeration)",
    SubStatusCode="0xC000006A", "Bad password (Credential Guessing)",
    SubStatusCode="0xC0000234", "Account locked out",
    SubStatusCode="0xC0000072", "Account disabled",
    true(), "Other Status: ".SubStatusCode
  )
| eval LogonTypeDesc=case(
    LogonType=2, "2: Interactive (Console)",
    LogonType=3, "3: Network (SMB/RPC)",
    LogonType=10, "10: Remote Desktop (RDP)",
    true(), "LogonType: ".LogonType
  )
| stats count as FailureCount,
        earliest(_time) as FirstAttempt,
        latest(_time) as LastAttempt,
        values(FailureReason) as Reasons,
        values(LogonTypeDesc) as Protocols
        by SourceIP, TargetUser, Computer
| sort - FailureCount
```

### 2.2 Successful Authentication Session Pivot (Event ID 4624)
Extracts the unique `TargetLogonId` to pivot between Windows authentication and Sysmon process executions.

```spl
index=windows (EventID=4624 OR EventCode=4624 OR "<EventID>4624</EventID>")
| eval TargetUser=coalesce(TargetUserName, user)
| eval SourceIP=coalesce(IpAddress, src_ip)
| eval SessionLogonID=coalesce(TargetLogonId, LogonId)
| search TargetUser!="SYSTEM" AND TargetUser!="LOCAL SERVICE" AND TargetUser!="NETWORK SERVICE"
| table _time, Computer, TargetUser, SessionLogonID, LogonType, SourceIP, AuthenticationPackageName
| sort - _time
```

### 2.3 Special Privileges Assigned (Event ID 4672)
Identifies administrative tokens (`SeDebugPrivilege`, `SeTcbPrivilege`) assigned upon session creation.

```spl
index=windows (EventID=4672 OR EventCode=4672 OR "<EventID>4672</EventID>")
| eval TargetUser=coalesce(TargetUserName, SubjectUserName, user)
| eval SessionLogonID=coalesce(SubjectLogonId, TargetLogonId)
| table _time, Computer, TargetUser, SessionLogonID, PrivilegeList
| sort - _time
```

---

## 3. PowerShell Telemetry Queries (`index=powershell`)

### 3.1 Malicious Script Block Execution & Download Cradles (Event ID 4104)
Catches in-memory download cradles (`Invoke-WebRequest`, `DownloadString`, `System.Net.WebClient`, `-EncodedCommand`).

```spl
index=powershell (EventID=4104 OR EventCode=4104 OR "<EventID>4104</EventID>")
| eval ScriptText=coalesce(ScriptBlockText, Script_Block_Text)
| search ScriptText="*DownloadString*" OR ScriptText="*Invoke-WebRequest*" 
      OR ScriptText="*System.Net.WebClient*" OR ScriptText="*FromBase64String*"
      OR ScriptText="*ExecutionPolicy Bypass*" OR ScriptText="*hidden*"
| table _time, Computer, ScriptBlockId, ScriptText
| sort - _time
```

---

## 4. Unified Cross-Source SOC Incident Timeline SPL

Reconstructs the full end-to-end incident narrative across Windows Security, Sysmon, and PowerShell:

```spl
index IN (sysmon, windows, powershell) (
    EventID IN (4625, 4624, 4672, 1, 3, 4104) 
    OR "<EventID>4625</EventID>" OR "<EventID>4624</EventID>" OR "<EventID>4672</EventID>"
    OR "<EventID>1</EventID>" OR "<EventID>3</EventID>" OR "<EventID>4104</EventID>"
  )
| eval EID=coalesce(EventID, EventCode)
| eval Activity=case(
    EID=4625, "Authentication Failure (4625)",
    EID=4624, "Successful Authentication (4624)",
    EID=4672, "Privilege Elevation (4672)",
    EID=1,    "Process Execution (Sysmon 1)",
    EID=3,    "Network Egress Socket (Sysmon 3)",
    EID=4104, "PowerShell Script Block (4104)",
    true(),   "Other Event"
  )
| eval Details=case(
    EID=4625, "Failed logon for [".coalesce(TargetUserName, user)."] from IP: ".coalesce(IpAddress, src_ip)." (LogonType: ".LogonType.")",
    EID=4624, "Successful logon for [".coalesce(TargetUserName, user)."] SessionID: ".coalesce(TargetLogonId, LogonId)." from IP: ".coalesce(IpAddress, src_ip),
    EID=4672, "Privileges assigned to [".coalesce(TargetUserName, SubjectUserName)."] Privs: ".replace(PrivilegeList, "\n", ", "),
    EID=1,    "Process: [".coalesce(Image, process_path)."] spawned by [".coalesce(ParentImage, parent_process_path)."] Cmd: ".coalesce(CommandLine, cmdline),
    EID=3,    "Socket opened to [".DestinationIp.":".DestinationPort."] by [".coalesce(Image, process_path)."]",
    EID=4104, "ScriptBlock: ".substr(coalesce(ScriptBlockText, Script_Block_Text), 1, 150),
    true(),   "Raw event"
  )
| table _time, Computer, EID, Activity, Details
| sort 0 _time
```

