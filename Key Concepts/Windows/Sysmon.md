# **Sysmon (System Monitor)**

# **1. What It Is**

* **Sysmon** is a Windows system service and driver that logs detailed system activity such as process creation, network connections, file changes, and registry modifications.
* It is part of the **Sysinternals** tools published by **Microsoft**.
* Installed as a Windows service that persists across reboots and writes telemetry into **Windows Event Logs** (Applications and Services Logs → Microsoft → Windows → Sysmon).
* Provides much deeper host telemetry than default Windows logging.
* Commonly deployed in **Windows enterprise environments** integrated with **SIEM platforms, EDR tools, and threat hunting pipelines**.
* Requires a configuration file (XML) that defines what events should be logged.

---

# 2. Legitimate Use

* **Enhanced endpoint visibility** for SOC monitoring (process, network, registry, driver activity).
* Used by security teams for **incident response, threat hunting, and forensic analysis**.
* Enables detection of suspicious behaviors such as:

  * process injection
  * credential dumping
  * persistence mechanisms.
* Frequently integrated with SIEM platforms like **Splunk**, **Microsoft Sentinel**, and **Elastic Security**.
* Helps organizations build **behavior-based detections rather than relying on antivirus signatures**.
* Widely used in **blue team labs and detection engineering environments**.

---

# 3. Attacker Abuse

Attackers cannot directly abuse Sysmon itself often, but they **attempt to disable, bypass, or evade it**.

**Common attacker actions:**

* **Disable or uninstall Sysmon** to reduce logging.
* Modify the **Sysmon configuration file** to stop logging key activity.
* Use tools that generate **minimal detectable telemetry**.
* Attempt to clear Sysmon event logs.

**Typical attack scenarios**

* After gaining admin access, attacker runs:

  ```
  sysmon -u
  ```

  to uninstall it.
* Attacker kills the **Sysmon service** to blind defenders.
* Modify configuration to exclude malicious processes.
* Use **living-off-the-land binaries (LOLBins)** that blend into legitimate logs.

**MITRE ATT&CK Techniques**

* **T1562**
* **T1070**
* **T1055**
* **T1547**

(Sysmon often logs activity related to these techniques.)

---

# 4. SIEM Detection Opportunities

### **Alert 1 — Sysmon Service Stopped or Uninstalled**

**Suspicious Behavior**

* Sysmon service unexpectedly stopped or removed.

**Detection Logic**

```
EventID = 7045 OR EventID = 7036
AND ServiceName = "Sysmon"
AND State = "Stopped" OR "Deleted"
```

**Log Sources**

* Windows System Event Logs
* Sysmon Event Logs
* EDR telemetry

---

### **Alert 2 — Suspicious Process Spawn (PowerShell, CMD from Office)**

**Suspicious Behavior**

* Office application spawning command interpreters.

**Detection Logic**

```
Sysmon EventID = 1
ParentImage IN (winword.exe, excel.exe, outlook.exe)
Image IN (powershell.exe, cmd.exe, wscript.exe)
```

**Log Sources**

* Sysmon Event ID 1 (Process Creation)
* EDR telemetry

---

### **Alert 3 — Suspicious Network Connection from Non-Browser Process**

**Suspicious Behavior**

* Unusual outbound network connections.

**Detection Logic**

```
Sysmon EventID = 3
Image NOT IN (chrome.exe, edge.exe, firefox.exe)
DestinationPort IN (4444, 1337, 8080)
```

**Log Sources**

* Sysmon Event ID 3 (Network Connection)
* Firewall logs
* EDR telemetry

---

### **Alert 4 — Possible Credential Dumping**

**Suspicious Behavior**

* Access to **lsass.exe** memory.

**Detection Logic**

```
Sysmon EventID = 10
TargetImage = lsass.exe
GrantedAccess contains 0x1FFFFF
```

**Log Sources**

* Sysmon Event ID 10 (Process Access)
* EDR telemetry

---

### **Alert 5 — Persistence via Registry Run Key**

**Suspicious Behavior**

* Registry modification to autorun locations.

**Detection Logic**

```
Sysmon EventID = 13
TargetObject contains
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

**Log Sources**

* Sysmon Event ID 13 (Registry Set)
* Windows Registry logs

---

# 5. Investigation Indicators

SOC analysts should review:

* **Sysmon Event ID 1** – suspicious process execution chains.
* **Event ID 3** – unexpected outbound connections from system utilities.
* **Event ID 7** – suspicious DLL loads (common in injection attacks).
* **Event ID 8 / 10** – process injection or LSASS access attempts.
* Parent-child relationships such as:

  * `winword.exe → powershell.exe`
  * `explorer.exe → rundll32.exe`.
* Processes running from unusual paths:

  * `C:\Users\Public`
  * `C:\Temp`
  * `%AppData%`.

Also check:

* If **Sysmon logging suddenly stopped**.
* Changes to **Sysmon configuration file**.
* Evidence of **log clearing**.

---

# 6. Mitigations / Security Best Practices

**Deployment & Hardening**

* Deploy Sysmon using hardened configs like **SwiftOnSecurity Sysmon Config**.
* Restrict **administrator privileges** to prevent attackers disabling Sysmon.
* Monitor **Sysmon service status changes**.

**Monitoring**

* Forward Sysmon logs to a **central SIEM** immediately.
* Create detection rules for:

  * process injection
  * suspicious parent-child processes
  * persistence modifications.

**Preventive Controls**

* Enable **tamper protection through EDR**.
* Apply **application control** using **Microsoft Defender Application Control** or **AppLocker**.
* Protect logging infrastructure from attackers.
* Periodically **validate Sysmon configuration integrity**.

---