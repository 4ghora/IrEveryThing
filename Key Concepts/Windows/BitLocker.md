# 1. What it is

* **Windows BitLocker** is a full-disk encryption feature built into **Microsoft Windows** that encrypts entire volumes to protect data at rest.
* Uses **AES encryption** with keys stored in **TPM (Trusted Platform Module)**, password, PIN, or recovery key.
* Protects **operating system drives, fixed data drives, and removable drives** (BitLocker To Go).
* Integrated with **Active Directory** and **Microsoft Intune** for enterprise key management.
* Commonly deployed on **enterprise laptops, servers, and workstations** to prevent data theft if devices are lost or stolen.
* Generates telemetry in **Windows Event Logs**, EDR tools, and device management platforms.

---

# 2. Legitimate Use

* **Data-at-rest protection** for corporate devices containing sensitive information.
* Helps organizations meet **compliance requirements** (HIPAA, PCI-DSS, GDPR).
* **Automatic encryption via Group Policy or Intune** during device provisioning.
* Securely stores **recovery keys in Active Directory or Azure AD** for helpdesk recovery.
* Enables **BitLocker To Go** to encrypt USB drives used by employees.
* Prevents **offline disk access attacks** if a device is stolen.

---

# 3. Attacker Abuse

Attackers sometimes abuse BitLocker or interact with it during post-exploitation.

* **Ransomware enabling BitLocker** to encrypt disks and lock victims out instead of deploying custom encryption.
* Attackers may **extract BitLocker recovery keys** from **Active Directory or Azure AD** after privilege escalation.
* Malicious users may **disable BitLocker protection** before exfiltrating sensitive data from stolen systems.
* Attackers may use **BitLocker To Go** to encrypt stolen data on removable drives before exfiltration.
* Some malware uses **`manage-bde.exe`** to enable encryption as a destructive action.
* Relevant MITRE ATT&CK mappings:

  * **Data Encrypted for Impact (T1486)**
  * **Data from Local System (T1005)**
  * **Modify Registry (T1112)** (BitLocker config changes)

---

# 4. SIEM Detection Opportunities

### Alert: BitLocker Encryption Enabled on Multiple Systems

* **Suspicious Behavior**

  * BitLocker suddenly enabled across many endpoints outside of normal IT deployment.

* **Detection Logic**

  ```
  Detect BitLocker enablement events on multiple hosts within short timeframe
  AND user != approved deployment service account
  ```

* **Log Sources**

  * Windows Event Logs
  * EDR telemetry
  * Intune / Endpoint Manager logs

---

### Alert: Suspicious Execution of manage-bde.exe

* **Suspicious Behavior**

  * BitLocker CLI tool executed by non-admin user or suspicious process.

* **Detection Logic**

  ```
  ProcessName = manage-bde.exe
  AND ParentProcess NOT IN (explorer.exe, trusted admin tools)
  ```

* **Log Sources**

  * EDR process telemetry
  * Windows Security Logs (4688)
  * Sysmon Event ID 1

---

### Alert: BitLocker Protection Disabled

* **Suspicious Behavior**

  * Disk encryption protection suspended or disabled unexpectedly.

* **Detection Logic**

  ```
  EventID indicating BitLocker protection suspended
  AND device not in maintenance window
  ```

* **Log Sources**

  * Windows Event Logs (Microsoft-Windows-BitLocker-API)
  * EDR telemetry

---

### Alert: BitLocker Recovery Key Accessed in Active Directory

* **Suspicious Behavior**

  * User retrieving recovery keys from AD/Azure AD unexpectedly.

* **Detection Logic**

  ```
  Access to BitLocker recovery objects
  AND user NOT IN helpdesk/security group
  ```

* **Log Sources**

  * Active Directory audit logs
  * Azure AD audit logs
  * Identity monitoring tools

---

### Alert: Rapid BitLocker Encryption Followed by System Lockout

* **Suspicious Behavior**

  * Encryption triggered and device becomes inaccessible (possible ransomware).

* **Detection Logic**

  ```
  BitLocker enablement event
  FOLLOWED BY abnormal shutdown or lock events
  ```

* **Log Sources**

  * Windows System logs
  * EDR telemetry
  * BitLocker operational logs

---

# 5. Investigation Indicators

* **Command-line usage**

  * `manage-bde -on`
  * `manage-bde -off`
  * `manage-bde -protectors`

* **Event logs**

  * `Microsoft-Windows-BitLocker/BitLocker Management`
  * BitLocker operational logs

* **Process execution**

  * `manage-bde.exe`
  * `powershell.exe` invoking BitLocker cmdlets

* **Registry changes**

  ```
  HKLM\SOFTWARE\Policies\Microsoft\FVE
  ```

* **Identity activity**

  * Unusual **recovery key retrieval**
  * Privileged account accessing BitLocker objects

* **Endpoint anomalies**

  * Sudden encryption operations on many hosts
  * Device becoming inaccessible post encryption

---

# 6. Mitigations / Security Best Practices

* **Store recovery keys securely** in **Active Directory or Azure AD** with restricted access.
* **Limit access to BitLocker recovery keys** using RBAC and auditing.
* **Monitor BitLocker events** centrally in SIEM for enable/disable operations.
* **Restrict use of `manage-bde`** via application control (e.g., AppLocker).
* Enable **TPM + PIN** for stronger authentication during boot.
* Use **EDR detection rules** for abnormal encryption activity.
* Implement **change management monitoring** for disk encryption operations.
* Ensure **backup and recovery procedures** exist in case BitLocker is abused by attackers.

---