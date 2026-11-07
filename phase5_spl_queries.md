# Phase 5: Production Splunk SPL Hunting & Detection Query Catalog

## Document Information
- **System**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 5 — SOC Attack Simulation & Detection Validation
- **SIEM Platform**: Splunk Enterprise (Windows 11 `LAPTOP-OUBJLUDB`, REST API `127.0.0.1:8089`)
- **Indexes**: `sysmon`, `windows`, `powershell`

---

## 1. PowerShell & Process Creation Hunting (Sysmon Event ID 1 & PowerShell Event ID 4104)

### 1.1 Suspicious PowerShell CommandLine Hunting (DET-PS01)
```spl
index=sysmon EventID=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
  (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*-e *" 
   OR CommandLine="*Invoke-Expression*" OR CommandLine="*iex*" 
   OR CommandLine="*DownloadString*" OR CommandLine="*-ExecutionPolicy Bypass*"
   OR CommandLine="*PHASE5_SIM_PS01_MARKER*")
| eval ProcessUser=coalesce(User, TargetUser, "SYSTEM")
| stats count, min(_time) as first_seen, max(_time) as last_seen 
  by Computer, ProcessUser, ParentImage, Image, CommandLine
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

### 1.2 PowerShell Script Block Logging (De-obfuscation Hunt)
```spl
index=powershell EventID=4104
  ("PHASE5_SIM_PS01_MARKER" OR "Invoke-Expression" OR "DownloadString" OR "-EncodedCommand" OR "FromBase64String" OR "Start-Process")
| eval ScriptSnippet=substr(ScriptBlockText, 1, 300)
| table _time, Computer, UserId, ScriptSnippet
| sort - _time
```

### 1.3 Unusual Parent-Child Process Spawning
```spl
index=sysmon EventID=1 (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\outlook.exe" OR ParentImage="*\\chrome.exe")
  (Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe")
| table _time, Computer, User, ParentImage, ParentCommandLine, Image, CommandLine
```

---

## 2. Authentication & Account Anomaly Hunting (Windows Event ID 4625 & 4624)

### 2.1 Failed Logon Burst Detection (DET-AUTH02)
```spl
index=windows EventID=4625 (LogonType=2 OR LogonType=3 OR LogonType=10)
| bin _time span=5m
| stats count as failure_count,
        values(WorkstationName) as workstations,
        values(IpAddress) as source_ips,
        values(Status) as status_codes,
        values(SubStatus) as substatus_codes
        by _time, TargetUserName, Computer
| where failure_count >= 3
| eval FailureReason=case(
    substatus_codes="0xC000006A", "Bad Password",
    substatus_codes="0xC0000064", "User Does Not Exist",
    substatus_codes="0xC0000234", "Account Locked Out",
    true(), "Other Failure"
  )
| table _time, Computer, TargetUserName, failure_count, FailureReason, workstations, source_ips
```

### 2.2 Account Spraying across Multiple Usernames
```spl
index=windows EventID=4625
| stats dc(TargetUserName) as distinct_users, values(TargetUserName) as targeted_users, count by IpAddress, WorkstationName
| where distinct_users >= 3
| sort - distinct_users
```

---

## 3. Network Connection Hunting (Sysmon Event ID 3)

### 3.1 Scripting Utility Network Connections (DET-NET03)
```spl
index=sysmon EventID=3
  (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe"
   OR Image="*\\mshta.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe"
   OR Image="*\\certutil.exe" OR Image="*\\rundll32.exe")
  DestinationPort IN (80, 443, 8080, 8443, 5000, 8000)
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen
  by Computer, User, Image, SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol
| convert ctime(first_seen) ctime(last_seen)
```

### 3.2 Non-Standard Outbound Web Traffic by Process
```spl
index=sysmon EventID=3 DestinationPort IN (80, 443, 8080)
| eval IsKnownBrowser=if(match(Image, "(chrome|msedge|firefox|brave)\\.exe"), 1, 0)
| where IsKnownBrowser=0
| stats count by Image, DestinationIp, DestinationPort
| sort - count
```

---

## 4. File Creation Hunting (Sysmon Event ID 11)

### 4.1 Script and Binary Drop in User Paths (DET-FILE04)
```spl
index=sysmon EventID=11
  (TargetFilename="*.ps1" OR TargetFilename="*.vbs" OR TargetFilename="*.bat"
   OR TargetFilename="*.js" OR TargetFilename="*.exe" OR TargetFilename="*.dll"
   OR TargetFilename="*.hta")
  (TargetFilename="*\\AppData\\Local\\Temp\\*" OR TargetFilename="*\\Users\\*\\Downloads\\*"
   OR TargetFilename="*\\Users\\*\\AppData\\Local\\*" OR TargetFilename="*\\phase5_lab\\*")
| table _time, Computer, Image, TargetFilename, CreationUtcTime
| sort - _time
```

---

## 5. Registry Persistence Hunting (Sysmon Event ID 12 & 13)

### 5.1 Run Key and Autostart Modifications (DET-REG05)
```spl
index=sysmon (EventID=12 OR EventID=13)
  (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*"
   OR TargetObject="*\\Software\\Phase5Lab*" OR TargetObject="*\\Windows\\CurrentVersion\\Explorer\\User Shell Folders*")
| eval Action=if(EventID=12, "ObjectAddedOrDeleted", "ValueSet")
| table _time, Computer, Action, Image, TargetObject, Details
```

---

## 6. Process Access & Handle Hunting (Sysmon Event ID 10)

### 6.1 Suspicious Cross-Process OpenProcess Queries (PS-06)
```spl
index=sysmon EventID=10
  (TargetImage="*\\lsass.exe" OR TargetImage="*\\svchost.exe" OR TargetImage="*\\csrss.exe")
| eval AccessHex=GrantedAccess
| table _time, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
| sort - _time
```

---

## 7. Phishing Email IOC Cross-Correlation (DET-IOC06)

### 7.1 Multi-Indicator Correlation Query
```spl
index=sysmon (EventID=1 OR EventID=3 OR EventID=11 OR EventID=22)
  ("$IOC_IP$" OR "$IOC_DOMAIN$" OR "$IOC_HASH$")
| eval IOCType=case(
    match(_raw, "(?i)$IOC_IP$"), "Network_or_Logon_IP",
    match(_raw, "(?i)$IOC_DOMAIN$"), "DNS_or_Host_Domain",
    match(_raw, "(?i)$IOC_HASH$"), "Binary_or_Script_Hash"
  )
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen,
        values(EventID) as event_ids, values(Image) as process_images,
        values(DestinationIp) as dest_ips, values(QueryName) as dns_queries
        by Computer, IOCType
| convert ctime(first_seen) ctime(last_seen)
```

### 7.2 Strict Anti-Fabrication Guarantee
When an investigated email contains zero observed IOCs on the endpoint:
- The subsearch returns **0 events**.
- The API outputs `status: "no_matching_events"`.
- Never displays artificial process compromise or speculative endpoint alerts.

