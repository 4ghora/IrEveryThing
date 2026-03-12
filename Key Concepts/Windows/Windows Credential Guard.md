## Windows Credential Guard

---

# 1. What It Is

* **Windows Credential Guard** is a security feature in **Microsoft Windows** that protects credentials by isolating them in a **virtualized secure container** using **Hyper-V**–based **Virtualization-Based Security (VBS)**.
* It prevents credential theft attacks that target **LSASS memory**, such as dumping passwords or NTLM hashes.
* Secrets like **NTLM hashes and Kerberos TGTs** are stored in an isolated process called **LSAISO (LSA Isolated)**.
* Even if attackers obtain **SYSTEM privileges**, they cannot directly read protected credentials from memory.
* Primarily used in **Windows 10/11 Enterprise**, **Windows Server**, and enterprise Active Directory environments.
* Protects against credential-theft tools such as **Mimikatz**.

---

# 2. Legitimate Use

* Protects **domain credentials** stored in memory against credential-dumping malware.
* Commonly deployed in **enterprise Windows endpoints** through **Group Policy or Intune**.
* Used in **privileged access workstations (PAWs)** and **Tier-0 admin systems**.
* Helps mitigate **Pass-the-Hash (PtH)** and **Pass-the-Ticket (PtT)** attacks.
* Works with **Secure Boot, TPM, and VBS** to enforce hardware-backed security.
* Often deployed alongside **Windows Defender Credential Protection stack**.

---

# 3. Attacker Abuse / Bypass Attempts

Attackers usually **cannot directly abuse Credential Guard**, but they try to **disable or bypass it**.

**Common attacker actions**

* **Disable Credential Guard** via registry/GPO modification before credential dumping.
* **Kernel-level attacks or drivers** to bypass virtualization protection.
* **Downgrade attacks** by booting systems without VBS protections.
* **Use alternate credential theft methods** (token impersonation, DCSync).
* **Credential harvesting from other sources** like browser stores or SAM.

**Typical attack scenarios**

* Attacker gains **local admin**, checks if Credential Guard is enabled.
* Attempts to **disable VBS and reboot system**.
* Executes **credential dumping tools** after disabling protection.

**MITRE ATT&CK**

* Credential Dumping – **T1003**
* Modify Registry – **T1112**
* Boot or Logon Autostart Execution – **T1547**
* Exploitation for Privilege Escalation – **T1068**

---

# 4. SIEM Detection Opportunities

### Alert 1 — Credential Guard Disabled

**Suspicious Behavior**

Credential Guard registry settings modified or disabled.

**Example Detection Logic**

```
Registry modification where:
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity = 0
OR
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags changed
```

**Relevant Log Sources**

* Windows Security Logs
* Sysmon Event ID 13 (Registry)
* EDR Telemetry

---

### Alert 2 — Suspicious Access to LSASS

**Suspicious Behavior**

Processes attempting to read LSASS memory despite Credential Guard protections.

**Example Detection Logic**

```
Process accessing lsass.exe
AND Process NOT IN (approved security tools)
AND GrantedAccess includes PROCESS_VM_READ
```

**Relevant Log Sources**

* Sysmon Event ID 10 (Process Access)
* EDR telemetry
* Windows Defender logs

---

### Alert 3 — VBS or Hyper-V Security Disabled

**Suspicious Behavior**

Changes to system configuration disabling virtualization security.

**Example Detection Logic**

```
bcdedit /set hypervisorlaunchtype off
OR
bcdedit modifications affecting virtualization security
```

**Relevant Log Sources**

* Process Creation Logs (Event ID 4688)
* Sysmon Event ID 1
* EDR command telemetry

---

### Alert 4 — Credential Dumping Tool Execution

**Suspicious Behavior**

Execution of credential dumping utilities.

**Example Detection Logic**

```
ProcessName IN (mimikatz.exe, procdump.exe)
AND CommandLine contains "lsass"
```

**Relevant Log Sources**

* Windows Event ID 4688
* Sysmon Event ID 1
* EDR detections

---

### Alert 5 — Driver Loading for Security Bypass

**Suspicious Behavior**

Unsigned or suspicious drivers loaded that could attempt VBS bypass.

**Example Detection Logic**

```
Driver load
AND SignatureStatus != Trusted
AND User context = Administrator
```

**Relevant Log Sources**

* Sysmon Event ID 6 (Driver Load)
* Windows Kernel logs
* EDR telemetry

---

# 5. Investigation Indicators

Analysts should check:

* **Credential Guard status**

  * `msinfo32` → "Credential Guard Running"
* Registry values:

  * `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags`
  * `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`
* Presence of **LSAISO.exe process**.
* Process access attempts to **lsass.exe**.
* Execution of credential dumping tools such as **Mimikatz** or **ProcDump**.
* Unexpected **driver loads or kernel exploits**.

---

# 6. Mitigations / Security Best Practices

* Enable **Windows Credential Guard** via **Group Policy, Intune, or MDM**.
* Enforce **Secure Boot + TPM + VBS**.
* Restrict **local administrator privileges** using **least privilege**.
* Monitor **LSASS access attempts** via EDR or Sysmon.
* Enable **attack surface reduction (ASR) rules** to block credential theft tools.
* Implement **Privileged Access Workstations (PAWs)** for domain admins.

---