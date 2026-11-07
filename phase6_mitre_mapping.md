# Phase 6A: MITRE ATT&CK Enterprise Framework Mapping

## Document Information
- **System**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 6A — Advanced Detection Engineering & Threat Hunting
- **Framework**: MITRE ATT&CK Enterprise Matrix (v14)
- **Host**: Windows 11 Enterprise (`LAPTOP-OUBJLUDB`)

---

## 1. Enterprise Matrix Alignment Overview

| Tactic | Technique ID | Technique Name | Detection / Hunt Rule | Telemetry Source | Explicit SOC Rationale & Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | **T1566.001** | Spearphishing Attachment | `DET-IOC06` | Email Parser, Sysmon EID 1 | Malicious invoice/macro attachments extracted and matched against endpoint file hashes. |
| **Initial Access** | **T1566.002** | Spearphishing Link | `DET-IOC06` | Email Parser, Sysmon EID 3, 22 | Credential-harvesting links extracted from emails correlated with endpoint DNS queries and outbound TCP connections. |
| **Execution** | **T1204.001** | User Execution: Malicious Link | `DET-IOC06`, `HUNT-05` | Sysmon EID 3, 22 | User clicking a link in a phishing email resulting in endpoint browser socket to the external IP. |
| **Execution** | **T1204.002** | User Execution: Malicious File | `DET-FILE04`, `DET-IOC06` | Sysmon EID 1, 11 | User opening a dropped script or macro-enabled document resulting in process creation. |
| **Execution** | **T1059.001** | Command and Scripting Interpreter: PowerShell | `DET-PS01`, `HUNT-01` | Sysmon EID 1, PowerShell EID 4104 | Invocations of `powershell.exe` with bypass flags, download cradles, or encoded commands. |
| **Defense Evasion** | **T1027** | Obfuscated Files or Information | `DET-PS01`, `HUNT-01` | Sysmon EID 1, PowerShell EID 4104 | Base64 `-EncodedCommand` execution de-obfuscated via PowerShell Script Block Logging (EID 4104). |
| **Credential Access**| **T1110.001** | Brute Force: Password Guessing | `DET-AUTH02`, `HUNT-02` | Windows Security EID 4625 | Sequential failed logons targeting local/domain accounts with Status `0xC000006D` / SubStatus `0xC000006A`. |
| **Credential Access**| **T1110.003** | Brute Force: Password Spraying | `DET-AUTH02`, `HUNT-02` | Windows Security EID 4625 | Distributed failed logons across multiple accounts originating from the same workstation or IP. |
| **Credential Access**| **T1003.001** | OS Credential Dumping: LSASS Memory | `HUNT-03` | Sysmon EID 10 | Cross-process handle acquisition targeting `lsass.exe` with read/dump access masks (`0x1010`, `0x1F0FFF`). |
| **Command & Control**| **T1071.001** | Application Layer Protocol: Web Protocols | `DET-NET03`, `HUNT-05` | Sysmon EID 3 | Outbound HTTP/HTTPS or raw TCP sockets established by LOLBAS utilities (`powershell.exe`, `wscript.exe`). |
| **Command & Control**| **T1105** | Ingress Tool Transfer | `DET-FILE04` | Sysmon EID 11 | Downloader scripts saving secondary payloads into staging directories (`Temp`, `AppData\Local\Temp`). |
| **Persistence** | **T1547.001** | Boot or Logon Autostart Execution: Registry Run Keys | `DET-REG05`, `HUNT-04` | Sysmon EID 12, 13 | Registry modifications under `HKCU/HKLM CurrentVersion\Run`, `RunOnce`, or system `Services`. |
| **Defense Evasion** | **T1112** | Modify Registry | `DET-REG05`, `HUNT-04` | Sysmon EID 12, 13 | Direct modification of registry keys or values to establish persistence or weaken security settings. |
| **Discovery** | **T1057** | Process Discovery | `HUNT-03` | Sysmon EID 10 | Querying limited process information across system processes (`GrantedAccess: 0x1000`). |

---

## 2. In-Depth Technique & SOC Telemetry Analysis

### 2.1 Initial Access: T1566.001 / T1566.002 (Spearphishing)
- **Attack Narrative**: Adversary sends a spoofed Microsoft security notification (`credential_phishing_microsoft.eml`) containing credential-harvesting link `http://login.microsoft.com.account-update.xyz/auth`.
- **Telemetry Correlated**:
  - Email forensic extraction captures domain `account-update.xyz` and IP `185.220.101.5`.
  - Splunk cross-correlation searches `index=sysmon` (EID 3 & 22) and `index=windows` (EID 4624/4625).
  - Anti-fabrication check verifies whether any endpoint user accessed the link.

### 2.2 Execution: T1059.001 (PowerShell) & Defense Evasion: T1027 (Obfuscation)
- **Attack Narrative**: Stage-0 phishing macro or malicious shortcut launches PowerShell with `-ExecutionPolicy Bypass` and Base64 encoded payload.
- **Telemetry Correlated**:
  - `Sysmon Event ID 1`: Captures `Image: powershell.exe`, `ParentImage: winword.exe` (Suspicious Office parent), and `CommandLine: powershell.exe -ExecutionPolicy Bypass -enc ...`.
  - `PowerShell Event ID 4104`: De-obfuscates the Base64 script in memory and logs raw script block text for forensic analysis.

### 2.3 Credential Access: T1110.001 (Password Guessing) & T1003.001 (LSASS Memory)
- **Attack Narrative**: Adversary attempts repeated credential guessing against an employee account or probes `lsass.exe` to read memory.
- **Telemetry Correlated**:
  - `Windows Event ID 4625`: Captures multiple failed logons for `Phase5SecTestUser` within 5 minutes.
  - `Sysmon Event ID 10`: Monitors handles opened to `C:\Windows\system32\lsass.exe`. Differentiates benign handle queries (`GrantedAccess: 0x1000`) from unauthorized memory reading (`GrantedAccess: 0x1010` / `0x1F0FFF`).

### 2.4 Command & Control: T1071.001 (Web Protocols via LOLBAS)
- **Attack Narrative**: PowerShell or Mshta connects back to a command-and-control server on port 5000 or 8089 to retrieve secondary instructions.
- **Telemetry Correlated**:
  - `Sysmon Event ID 3`: Captures non-browser socket with `Image: powershell.exe`, `DestinationIp: 127.0.0.1`, `DestinationPort: 5000`. Excludes standard web browsers (`chrome.exe`, `msedge.exe`).

### 2.5 Persistence: T1547.001 (Registry Run Keys) & Ingress Tool Transfer (T1105)
- **Attack Narrative**: Adversary stages a script in `AppData\Local\Temp` and adds an autostart entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- **Telemetry Correlated**:
  - `Sysmon Event ID 11`: File creation of `.ps1` script in user staging folder.
  - `Sysmon Event ID 13`: SetValue operation targeting autostart Run key or `Phase5Lab` registry branch.

