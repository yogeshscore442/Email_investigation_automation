# Phase 6A: False-Positive Reduction & Benign Baseline Analysis

## Document Information
- **System**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 6A — Advanced Detection Engineering & Tuning
- **SIEM Platform**: Splunk Enterprise (Windows 11 `LAPTOP-OUBJLUDB`)
- **Focus**: Eliminating alert fatigue and suppressing benign administrative/user activities without sacrificing detection fidelity.

---

## 1. Enterprise Benign Baselines vs. Threat Indicators

In production enterprise networks, benign software installers, systems management agents, and everyday users routinely perform actions that overlap superficially with adversarial tactics. Without strict contextual filtering, SOC analysts face severe alert fatigue.

```
+========================================================================================================================+
| Rule ID    | Monitored Technique             | Benign Operational Baseline       | Phase 6A Tuning & Suppression Logic|
+========================================================================================================================+
| DET-PS01   | PowerShell Execution            | Admin cmdlets (Get-Process, dir)  | Rejects unencoded commands without |
|            |                                 | VS Code extension initialization  | bypass flags (-40 points).         |
+------------------------------------------------------------------------------------------------------------------------+
| DET-AUTH02 | Failed Logons                   | User typo (1-2 bad attempts)      | Enforces threshold >= 3 in 5 min.  |
|            |                                 | Stale Outlook or Wi-Fi cache      | Suppresses isolated typos.         |
+------------------------------------------------------------------------------------------------------------------------+
| DET-NET03  | Script Network Sockets          | Web browsers (Chrome, Edge)       | Restricts strictly to LOLBAS       |
|            |                                 | Local web dev server polling      | binaries; excludes browsers.       |
+------------------------------------------------------------------------------------------------------------------------+
| DET-FILE04 | Script Drop in Staging          | Text files, logs, Office docs     | Requires executable extension in   |
|            |                                 | Package cache extractions         | staging paths (\Temp\, \Downloads\)|
+------------------------------------------------------------------------------------------------------------------------+
| DET-REG05  | Registry Autostart Modification | User UI preferences (Hidden files)| Targets only known ASEP branches   |
|            |                                 | Display settings, Office prefs    | (Run, RunOnce, Services).          |
+------------------------------------------------------------------------------------------------------------------------+
| DET-IOC06  | Email IOC Correlation           | Benign cloud domains (Microsoft,  | Whitelists top corporate domains   |
|            |                                 | Google, GitHub) in normal emails  | unless corroborated by intel.      |
+========================================================================================================================+
```

---

## 2. Tested Legitimate Activity Scenarios

To prove that benign activity does not generate spurious alerts, Phase 6A implements dedicated baseline validation tests in [`test_phase6_detection_engineering.py`](file:///c:/Users/YOGESH/Downloads/Email_Investigation/backend/tests/test_phase6_detection_engineering.py):

### Scenario 1: Normal PowerShell Administration
- **Activity**: System administrator executes `powershell.exe Get-Process` or `powershell.exe Get-Service` to inspect running tasks.
- **Evaluation Result**:
  - `matched`: **`False`**
  - Severity: `Informational`
  - Scoring adjustment: **-40 points**
  - **Verdict**: Successfully suppressed. Zero alert created.

### Scenario 2: Isolated User Logon Typo
- **Activity**: An employee mistypes their password once on workstation lock screen (`count = 1`).
- **Evaluation Result**:
  - `matched`: **`False`**
  - Scoring adjustment: **-30 points** (Below threshold)
  - **Verdict**: Successfully suppressed. Alert only fires when $\ge 3$ consecutive failures occur within 300 seconds.

### Scenario 3: Legitimate Web Browser Traffic
- **Activity**: `chrome.exe` establishes an outbound TCP socket to port 5000 or 8089 to access an internal dashboard or API documentation.
- **Evaluation Result**:
  - `matched`: **`False`**
  - Process Lineage Filter: `chrome.exe` is identified as an authorized web browser and rejected by `DET-NET03`.
  - **Verdict**: Successfully suppressed. Sockets must originate from LOLBAS or scripting engines (`powershell.exe`, `wscript.exe`, `cmd.exe`).

### Scenario 4: Ordinary File Creation
- **Activity**: User creates `diagnostic_log.txt` or `meeting_notes.docx` in their temporary directory.
- **Evaluation Result**:
  - `matched`: **`False`**
  - Extension Filter: Non-executable extensions (`.txt`, `.log`, `.tmp`, `.docx`, `.pdf`) are excluded by `DET-FILE04`.
  - **Verdict**: Successfully suppressed. Only executable scripts (`.ps1`, `.bat`, `.vbs`, `.exe`) trigger alerts.

### Scenario 5: User Interface Preference Registry Changes
- **Activity**: Windows Explorer updates user preference key `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden` to toggle hidden files.
- **Evaluation Result**:
  - `matched`: **`False`**
  - Key Branch Filter: Non-persistence settings are excluded from `DET-REG05`.
  - **Verdict**: Successfully suppressed. Only autostart locations (`Run`, `RunOnce`, `Services`) trigger alerts.

### Scenario 6: High-Frequency Benign Corporate Domain in Email
- **Activity**: An email contains valid links to `login.microsoftonline.com` or `github.com`.
- **Evaluation Result**:
  - `matched`: **`False`**
  - Whitelist Gating: Top trusted domains are exempted from `DET-IOC06` endpoint correlation unless flagged by threat intelligence.
  - **Verdict**: Successfully suppressed. Prevents every internal email from triggering false-positive incident tickets.

---

## 3. Recommended Production SPL Tuning Filters

To deploy these detection rules in high-volume production enterprise environments, apply the following exclusion filters:

### 3.1 Tuning DET-PS01 (PowerShell)
```spl
... NOT (CommandLine="*splunk-powershell.exe*" OR CommandLine="*CCM\\CcmExec.exe*" 
         OR CommandLine="*Microsoft Intune Management Extension*"
         OR CommandLine="*Microsoft.PowerShell.Utility*")
... NOT (ParentImage="*\\Microsoft VS Code\\Code.exe")
```

### 3.2 Tuning DET-AUTH02 (Logons)
```spl
... | where count >= 5 AND duration_sec <= 300
... | search NOT TargetUserName IN ("*$")
... | search NOT (WorkstationName="DC01" AND TargetUserName="HEALTHCHECK_*")
```

### 3.3 Tuning DET-NET03 (Network Connections)
```spl
... DestinationIp!="127.0.0.1" DestinationIp!="::1"
... NOT (DestinationPort=443 AND QueryName IN ("*.windowsupdate.com", "*.microsoft.com", "*.azure.com"))
```

### 3.4 Tuning DET-FILE04 (File Drops)
```spl
... NOT (Image="*\\GoogleUpdate.exe" OR Image="*\\msedgeupdate.exe" OR Image="*\\tiworker.exe")
... NOT (TargetFilename="*\\__PSScriptPolicyTest_*.ps1")
```

### 3.5 Tuning DET-REG05 (Registry Persistence)
```spl
... NOT (Details="*\\Microsoft\\Teams\\*" OR Details="*\\Webex\\*" OR Details="*\\OneDrive.exe*")
... NOT (TargetObject="*\\Services\\McAfee*")
```

