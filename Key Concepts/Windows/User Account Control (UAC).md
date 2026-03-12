## 1. What it is

* **User Account Control (UAC)** is a Windows security mechanism that limits application privileges and prevents unauthorized system-level changes.
* Introduced in **Windows Vista** and present in modern Windows versions such as **Windows 10** and **Windows 11**.
* Forces applications to run with **standard user privileges by default**, even if the user belongs to the Administrators group.
* When a process requests **elevated privileges**, UAC triggers a **consent prompt** or **credential prompt**.
* Uses **integrity levels** (Low, Medium, High, System) to enforce privilege boundaries.
* Commonly used in **enterprise Windows endpoints, servers, and domain-joined environments**.

---

# 2. Legitimate Use

* Prevents **unauthorized privilege escalation** by requiring explicit approval for administrative actions.
* Ensures applications run with **least privilege** unless elevation is required.
* Protects critical system components such as:

  * Registry
  * System directories
  * Services configuration
* Used by administrators when installing:

  * software
  * drivers
  * updates
  * enterprise tools.
* Enterprise IT often configures UAC via **Microsoft Group Policy**.
* Helps reduce impact of **malware executed by standard users**.

---

# 3. Attacker Abuse

Attackers frequently attempt to **bypass UAC to gain elevated privileges without triggering prompts**.

### Common Abuse Techniques

* **UAC Bypass via Auto-Elevated Binaries**

  * Abuse trusted Windows binaries that automatically run with high privileges.
  * Example: `fodhelper.exe`, `computerdefaults.exe`.

* **Registry Hijacking for UAC Bypass**

  * Modify registry keys used by auto-elevated binaries.
  * Example path:

  ```
  HKCU\Software\Classes\ms-settings\shell\open\command
  ```

* **Token Manipulation**

  * Stealing or duplicating elevated tokens from privileged processes.

* **DLL Hijacking in Auto-Elevated Processes**

  * Inject malicious DLLs into trusted elevated executables.

* **Living-off-the-Land UAC Bypass**

  * Abuse native Windows tools such as:
  * `eventvwr.exe`
  * `sdclt.exe`

### MITRE ATT&CK Mapping

* **MITRE ATT&CK**

  * **T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control**
  * **T1112 — Modify Registry**
  * **T1055 — Process Injection**
  * **T1574 — Hijack Execution Flow**

---

# 4. SIEM Detection Opportunities

### Alert 1: Suspicious UAC Bypass via fodhelper.exe

**Suspicious Behavior**

* `fodhelper.exe` launched by a non-admin process followed by elevated execution.

**Detection Logic**

```
ProcessName = "fodhelper.exe"
AND ParentProcess NOT IN ("explorer.exe", "services.exe")
AND UserIntegrityLevel = Medium
```

**Log Sources**

* Windows Security Event Logs
* Sysmon Process Creation
* EDR Telemetry

---

### Alert 2: Registry Modification Linked to UAC Bypass

**Suspicious Behavior**

* Creation or modification of registry keys used for UAC bypass.

**Detection Logic**

```
RegistryPath CONTAINS
HKCU\Software\Classes\ms-settings\shell\open\command
AND Action = SetValue
```

**Log Sources**

* Sysmon Event ID 13 (Registry Set)
* Windows Security Logs
* EDR telemetry

---

### Alert 3: Auto-Elevated Binary Spawned by Suspicious Parent

**Suspicious Behavior**

* Known auto-elevated Windows binaries launched by scripting tools.

**Detection Logic**

```
ProcessName IN ("computerdefaults.exe","sdclt.exe","eventvwr.exe")
AND ParentProcess IN ("powershell.exe","cmd.exe","wscript.exe")
```

**Log Sources**

* Sysmon Event ID 1
* EDR telemetry
* Windows Security Event ID 4688

---

### Alert 4: Medium Integrity Process Spawning High Integrity Child

**Suspicious Behavior**

* A process running with medium integrity spawning a high-integrity process without normal elevation prompts.

**Detection Logic**

```
ParentIntegrityLevel = Medium
AND ChildIntegrityLevel = High
AND User NOT IN ApprovedAdmins
```

**Log Sources**

* EDR telemetry
* Sysmon Process Creation
* Windows Security Logs

---

# 5. Investigation Indicators

SOC analysts should review:

* **Process Trees**

  * Parent-child relationships around auto-elevated binaries.

* **Registry Changes**

  * Keys related to:

  ```
  HKCU\Software\Classes\ms-settings\
  HKCU\Software\Classes\exefile\
  ```

* **Suspicious Parent Processes**

  * `powershell.exe`
  * `cmd.exe`
  * `wscript.exe`
  * `mshta.exe`

* **Integrity Level Changes**

  * Medium → High without interactive consent.

* **Command-line Arguments**

  * Auto-elevated binaries executed with unusual flags.

* **Correlated Lateral Movement Activity**

  * Elevated privileges used shortly after UAC bypass.

---

# 6. Mitigations / Security Best Practices

* **Set UAC to Highest Enforcement**

  * Configure **“Always Notify”** via **Microsoft Group Policy**.

* **Enable Credential Prompt for Admins**

  * Require credentials instead of simple consent.

* **Deploy Application Control**

  * Use **Microsoft Defender Application Control** or **AppLocker**.

* **Monitor Auto-Elevated Binaries**

  * Track execution of:
  * `fodhelper.exe`
  * `sdclt.exe`
  * `eventvwr.exe`

* **Enable Advanced Logging**

  * Sysmon
  * Windows Event ID 4688 (Process Creation)
  * Registry monitoring

* **Implement EDR Behavioral Detection**

  * Use tools like **Microsoft Defender for Endpoint**.

---