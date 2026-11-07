# Phase 5: False Positive Triage, Benign Baselines & Detection Tuning Guide

## Document Information
- **System**: AI-Powered Automated Email Investigation and SOC Incident Response Platform
- **Phase**: Phase 5 — SOC Attack Simulation & Detection Engineering
- **SIEM Platform**: Splunk Enterprise (Windows 11 `LAPTOP-OUBJLUDB`, REST API `127.0.0.1:8089`)

---

## 1. Benign Operational Baselines & False Positive Evaluation

In an enterprise Windows environment, legitimate administrative scripts, endpoint management agents, and software installers often exhibit behaviors that match malicious patterns. To prevent alert fatigue and maintain a high signal-to-noise ratio (SNR), detection rules must account for legitimate operational baselines.

| Rule ID | Rule Name | Expected False Positives (Benign) | Typical Sources | Severity | Recommended Tuning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DET-PS01** | Encoded or Suspicious PowerShell | SCCM, Intune, Chocolatey, VS Code tasks | Admin scripts, IDE extensions | HIGH | Whitelist signed scripts & parent PIDs |
| **DET-AUTH02** | Multiple Failed Logons | Expired password cache, Outlook sync, user typos | Workstation screen lock, VPN client | MEDIUM | Tune threshold (`>= 5`) and exclude service accts |
| **DET-NET03** | LOLBAS Script Network Socket | Local dev servers, REST API polling, proxy scripts | Python, Vite, PowerShell web cmdlets | MEDIUM | Exclude loopback `127.0.0.1` in production |
| **DET-FILE04** | Script / Binary in Staging Directory | Chrome/Edge auto-updates, Git checkouts, installers | Web browser updates, package managers | HIGH | Filter signed binaries & trusted parent processes |
| **DET-REG05** | Registry Autostart Modification | Enterprise app installers (Teams, Zoom, OneDrive) | Legitimate MSI installers, per-user software | HIGH | Filter signed binaries in `Program Files` |
| **DET-IOC06** | Email IOC Correlation | Legitimate cloud services (e.g. `microsoft.com`, `aws`) | High-frequency benign domains in emails | CRITICAL | Enforce IOC reputation threshold prior to hunt |

---

## 2. In-Depth Rule Tuning & Whitelisting Strategies

### 2.1 Tuning Rule DET-PS01 (Encoded or Suspicious PowerShell)
- **Observed Benign Behavior**:
  - Microsoft Intune and SCCM execute Base64-encoded management scripts to collect hardware telemetry and enforce compliance.
  - Development tools (e.g. Visual Studio Code PowerShell extension) run initialization commands using `-ExecutionPolicy Bypass`.
- **Recommended SPL Exclusions**:
  ```spl
  ... NOT (ParentImage="*\\Microsoft Intune Management Extension\\*")
  ... NOT (ParentImage="*\\CCM\\CcmExec.exe")
  ... NOT (CommandLine="*\\Microsoft VS Code\\*")
  ... NOT (CommandLine="*Microsoft.PowerShell.Utility*")
  ```
- **Analytic Filter**: Enforce digital signature verification. If a PowerShell script is digitally signed by the internal enterprise code-signing certificate authority, suppress the alert.

---

### 2.2 Tuning Rule DET-AUTH02 (Multiple Failed Local Logon Attempts)
- **Observed Benign Behavior**:
  - A user changes their Active Directory password on their desktop, but their smartphone or laptop still caches the previous password and attempts Wi-Fi / Exchange ActiveSync authentication every 60 seconds.
  - A user mistypes their password twice before successfully logging in on the third attempt.
- **Recommended SPL Exclusions & Threshold Adjustment**:
  ```spl
  ... | where failure_count >= 5 AND duration_sec <= 300
  ... | search NOT TargetUserName IN ("*$")
  ```
- **Tuning Strategy**:
  - Increase threshold from 3 to 5 failures within a 5-minute sliding window.
  - Correlate with subsequent Event ID 4624 (Successful Logon). If a successful logon occurs from the same workstation within 60 seconds, downgrade priority to Informational (password typo).

---

### 2.3 Tuning Rule DET-NET03 (Suspicious Script / LOLBAS Outbound Connection)
- **Observed Benign Behavior**:
  - System administrators running PowerShell scripts using `Invoke-RestMethod` to query internal API gateways, ServiceNow, or Azure management portals.
  - Local developers communicating with `127.0.0.1` dev servers (Flask, Node, Docker).
- **Recommended SPL Exclusions**:
  ```spl
  ... DestinationIp!="127.0.0.1" DestinationIp!="::1"
  ... NOT (DestinationIp IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
  ... NOT (DestinationPort=443 AND QueryName IN ("*.microsoft.com", "*.azure.com", "*.windowsupdate.com"))
  ```
- **Tuning Strategy**:
  - Exclude loopback and RFC 1918 private subnets unless explicitly hunting for lateral movement.
  - Filter outbound connections to trusted Microsoft Cloud endpoints.

---

### 2.4 Tuning Rule DET-FILE04 (Suspicious Script / Binary Drop in Temp/Staging)
- **Observed Benign Behavior**:
  - Google Chrome and Microsoft Edge download updater components into `AppData\Local\Google\Update` and `AppData\Local\Temp`.
  - Python PIP or NPM package installations extracting helper scripts into `%TEMP%`.
- **Recommended SPL Exclusions**:
  ```spl
  ... NOT (Image="*\\GoogleUpdate.exe" OR Image="*\\msedgeupdate.exe")
  ... NOT (TargetFilename="*\\npm-cache\\*" OR TargetFilename="*\\pip-build-tracker\\*")
  ```
- **Tuning Strategy**:
  - Exclude known signed update agents.
  - Require the file creation event to be followed within 15 minutes by an Event ID 1 (Process Creation) for the same file path before raising a high-severity alert.

---

### 2.5 Tuning Rule DET-REG05 (Registry Autostart / Persistence Modification)
- **Observed Benign Behavior**:
  - Official workplace collaboration applications (e.g. Microsoft Teams, Webex, Zoom, Google Drive) adding `Run` registry keys during user login.
- **Recommended SPL Exclusions**:
  ```spl
  ... NOT (Details="*\\Microsoft\\Teams\\*")
  ... NOT (Details="*\\Webex\\*")
  ... NOT (Details="*\\Zoom\\*")
  ```
- **Tuning Strategy**:
  - Build an approved application baseline. Alert on registry additions whose target executable is unquoted, located in `AppData\Local\Temp`, or unsigned.

---

### 2.6 Tuning Rule DET-IOC06 (Endpoint Correlation with Phishing Email IOCs)
- **Observed Benign Behavior**:
  - Legitimate emails containing hyperlinks to standard cloud vendors (`login.microsoftonline.com`, `google.com`, `sharepoint.com`, `github.com`).
- **Recommended Pre-Filter**:
  - **Reputation Gating**: Do not query Splunk for every URL extracted from legitimate emails. Only initiate endpoint correlation when:
    1. The email risk score is `>= 50` (Suspicious or Malicious).
    2. SPF/DKIM/DMARC authentication failed or domain is flagged by VirusTotal/AbuseIPDB.
    3. The domain is not on the corporate Top-1M Alexa/Tranco whitelist.
  - **Zero Fabrication**: If no events exist in Splunk, return `no_matching_events` and document zero endpoint exposure.

