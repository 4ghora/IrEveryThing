# 1. What it is

* **Microsoft Defender Antivirus** (formerly **Windows Defender**) is a built-in **endpoint protection platform in Windows** that provides anti-malware, behavioral detection, exploit protection, and integration with Microsoft security ecosystems.
* Installed by default on **Windows 10, Windows 11, and Windows Server** systems.
* Uses **signature-based detection, cloud intelligence, and behavioral analysis** to detect malicious files and activity.
* Integrates with **Microsoft Defender for Endpoint** for advanced detection and response.
* Logs security events into **Windows Event Logs** and advanced telemetry to Defender/XDR platforms.
* Commonly monitored by SOC teams through **SIEM integrations (Splunk, Sentinel, QRadar, etc.)**.

---

# 2. Legitimate Use

* Provides **baseline endpoint protection** against malware, ransomware, and malicious scripts.
* Performs **real-time scanning** of files, processes, and downloads.
* Executes **scheduled antivirus scans** across endpoints.
* Detects **suspicious behavior using heuristics and cloud-based threat intelligence**.
* Integrates with enterprise security tooling for **centralized monitoring and response**.
* Supports **enterprise policy management via Group Policy, Intune, or MDM**.

Common enterprise uses:

* Endpoint antivirus protection across Windows environments.
* Automated malware remediation.
* Endpoint telemetry source for **SOC threat hunting**.
* Integration with **EDR for advanced threat detection**.

---

# 3. Attacker Abuse

Attackers frequently try to **disable or evade Defender** to run malware undetected.

### Common attacker techniques

* **Disabling real-time protection**

  * PowerShell command:
    `Set-MpPreference -DisableRealtimeMonitoring $true`
  * MITRE: **T1562.001**

* **Adding Defender exclusions**

  * Excluding folders or processes where malware resides.
  * MITRE: **T1562.001**

* **Stopping Defender services**

  * Attempting to stop `WinDefend` service or tamper with registry.
  * MITRE: **T1562.001**

* **Tampering with Defender registry keys**

  * Example path:
    `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`

* **Using Defender exclusions for malware persistence**

  * Attackers add `C:\Temp` or `C:\Users\Public` as exclusions.

* **Disabling Defender via Group Policy or PowerShell**

  * Common during ransomware deployment.

---

# 4. SIEM Detection Opportunities

### Alert 1 — Defender Real-Time Protection Disabled

**Suspicious Behavior**

* Defender real-time protection disabled via PowerShell or registry modification.

**Detection Logic**

* Detect:

  * PowerShell execution containing `Set-MpPreference -DisableRealtimeMonitoring`
  * Registry change disabling Defender

Example logic:

```
EventID=4688
Process=PowerShell
CommandLine contains "Set-MpPreference"
AND "DisableRealtimeMonitoring"
```

**Log Sources**

* Windows Security Event Logs
* PowerShell Logs (Event ID 4104)
* Defender Operational Logs
* EDR telemetry

---

### Alert 2 — Defender Exclusion Added

**Suspicious Behavior**

* A process or directory added to Defender exclusion list.

**Detection Logic**

```
CommandLine contains "Add-MpPreference"
AND ("ExclusionPath" OR "ExclusionProcess")
```

OR registry modification:

```
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions
```

**Log Sources**

* PowerShell logs
* Defender Operational logs
* Windows Security Logs
* EDR telemetry

---

### Alert 3 — Defender Service Stopped

**Suspicious Behavior**

* Security tool service unexpectedly stopped.

**Detection Logic**

```
EventID=7036
ServiceName="WinDefend"
State="Stopped"
```

**Log Sources**

* Windows System Logs
* EDR telemetry

---

### Alert 4 — Tamper Protection Disabled

**Suspicious Behavior**

* Defender Tamper Protection turned off to allow modifications.

**Detection Logic**

```
DefenderSettingChange
Setting = TamperProtection
NewValue = Disabled
```

**Log Sources**

* Defender logs
* Microsoft Defender for Endpoint telemetry
* Windows Event Logs

---

### Alert 5 — Suspicious PowerShell Defender Configuration Changes

**Suspicious Behavior**

* PowerShell modifying Defender configuration.

**Detection Logic**

```
EventID=4104
ScriptBlock contains:
  Set-MpPreference
  Add-MpPreference
  Remove-MpPreference
```

**Log Sources**

* PowerShell Script Block Logs
* Windows Security Logs
* EDR telemetry

---

# 5. Investigation Indicators

SOC analysts should examine:

* **PowerShell execution logs**

  * Look for `Set-MpPreference` or `Add-MpPreference`.

* **Registry changes**

  * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`

* **New Defender exclusions**

  * Suspicious directories like:

    * `C:\Users\Public`
    * `C:\Temp`
    * `C:\ProgramData`

* **Process ancestry**

  * What spawned the PowerShell process modifying Defender.

* **Unexpected Defender service changes**

  * `WinDefend` service start/stop events.

* **Endpoint timeline**

  * File drops → Defender disabled → malware execution.

---

# 6. Mitigations / Security Best Practices

* **Enable Defender Tamper Protection**

  * Prevents unauthorized changes to Defender settings.

* **Restrict PowerShell usage**

  * Use **Constrained Language Mode** or **AppLocker/WDAC**.

* **Monitor Defender configuration changes**

  * Alert on `Set-MpPreference` or exclusion changes.

* **Use centralized EDR**

  * Integrate with **Microsoft Defender for Endpoint**.

* **Implement least privilege**

  * Only admins can modify Defender settings.

* **Block suspicious directories from exclusions**

  * Alert on common attacker abuse paths.

---
