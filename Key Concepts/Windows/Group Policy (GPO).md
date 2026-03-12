## 1. What **Group Policy (GPO)** Is

* **Group Policy** is a Windows feature used to centrally manage configuration and security settings for **users and computers in an Active Directory domain**.
* Policies are stored in **Group Policy Objects (GPOs)** and linked to **OUs, domains, or sites**.
* Settings are applied to endpoints through the **Group Policy Client service** and retrieved from **domain controllers**.
* Policies include **security settings, scripts, software deployment, registry changes, firewall rules, and user restrictions**.
* Core components:

  * **Group Policy Container (GPC)** – stored in Active Directory
  * **Group Policy Template (GPT)** – stored in **SYSVOL** on domain controllers
* Common environments:

  * **Windows enterprise domains**
  * Hybrid **AD + cloud environments**
  * Managed workstation/server fleets.

---

# 2. Legitimate Use

Organizations rely heavily on GPO for centralized administration.

* **Security configuration management**

  * Password policies
  * Account lockout policies
  * Windows Defender and firewall settings
* **System hardening**

  * Disable USB devices
  * Configure audit policies
  * Restrict software execution
* **Software deployment**

  * Automatically install MSI packages across endpoints
* **Login/Startup automation**

  * Run **PowerShell, batch, or VBS scripts**
* **Compliance enforcement**

  * Apply baseline configurations such as **CIS benchmarks**
* **Enterprise user environment management**

  * Desktop configuration, mapped drives, printers.

---

# 3. Attacker Abuse

GPO is a **high-value persistence and lateral movement mechanism** because it allows attackers to execute code across many systems.

### Common Abuse Scenarios

* **Malicious startup or logon scripts**

  * Attackers add PowerShell or batch scripts to a GPO.
  * Scripts execute automatically on all targeted machines.

* **Privilege escalation / persistence**

  * Modify policies to add attacker account to **local Administrators**.

* **Mass malware deployment**

  * Use **software installation GPO** to push malicious MSI payloads.

* **Disable security controls**

  * Turn off **Windows Defender, logging, or EDR components**.

* **Lateral movement**

  * Use GPO to deploy **scheduled tasks or services** across hosts.

* **Domain-wide backdoors**

  * Malicious GPO linked to high-level OU affecting thousands of machines.

### Relevant MITRE ATT&CK Techniques

* **T1484.001 – Domain Policy Modification**
* **T1053 – Scheduled Task/Job**
* **T1547 – Boot or Logon Autostart Execution**
* **T1562 – Impair Defenses**
* **T1105 – Ingress Tool Transfer**

---

# 4. SIEM Detection Opportunities

### 1️⃣ Alert: **Group Policy Object Modification**

**Suspicious Behavior**

* Unauthorized modification of an existing GPO.

**Detection Logic**

```
EventID = 5136
AND ObjectClass = "groupPolicyContainer"
AND OperationType = "Value Modified"
AND User NOT IN (approved GPO admins)
```

**Log Sources**

* Windows Security Logs (Domain Controller)
* AD DS Audit Logs
* EDR telemetry

---

### 2️⃣ Alert: **New GPO Created**

**Suspicious Behavior**

* Attackers create new GPO to deploy persistence or malware.

**Detection Logic**

```
EventID = 5137
AND ObjectClass = "groupPolicyContainer"
```

Flag if creator account is:

* non-admin
* service account
* unusual admin account

**Log Sources**

* Windows Security Event Logs (DC)
* AD logs

---

### 3️⃣ Alert: **GPO Linked to High Privilege OU or Domain Root**

**Suspicious Behavior**

* New GPO linked to **Domain Controllers OU or root domain**.

**Detection Logic**

```
EventID = 5136
AND Attribute = "gPLink"
AND TargetOU IN ("Domain Controllers","Root Domain")
```

**Log Sources**

* AD Directory Service Logs
* Windows Security Logs

---

### 4️⃣ Alert: **Startup/Logon Script Added to GPO**

**Suspicious Behavior**

* Scripts added to GPO that execute across many machines.

**Detection Logic**

```
EventID = 5136
AND AttributeModified IN ("scriptPath","gPCMachineExtensionNames")
```

Or detect file changes in:

```
\\SYSVOL\Policies\*\Machine\Scripts
```

**Log Sources**

* Windows Security Logs
* File monitoring on **SYSVOL**
* EDR file telemetry

---

### 5️⃣ Alert: **SYSVOL Policy File Modification**

**Suspicious Behavior**

* Direct modification of **GPT files in SYSVOL**.

**Detection Logic**

```
File Write
Path = \\*\SYSVOL\*\Policies\*
AND User NOT IN approved_admins
```

**Log Sources**

* File Integrity Monitoring
* Sysmon Event ID 11
* EDR telemetry
* Windows File Auditing

---

### 6️⃣ Alert: **Mass Policy Refresh Trigger**

**Suspicious Behavior**

* Adversary forces machines to update policy to quickly execute malicious scripts.

**Detection Logic**

Detect abnormal usage of:

```
gpupdate /force
Invoke-GPUpdate
```

across many endpoints.

**Log Sources**

* PowerShell logs
* Process creation logs (Sysmon Event 1)
* EDR telemetry

---

# 5. Investigation Indicators

SOC analysts investigating suspicious GPO activity should review:

* **Who modified the GPO**

  * Account privileges
  * Source workstation
* **Changes to SYSVOL**

  * New scripts in:

  ```
  SYSVOL\Policies\*\Machine\Scripts
  SYSVOL\Policies\*\User\Scripts
  ```
* **New scheduled tasks or services deployed via policy**
* **Malicious PowerShell or batch scripts**
* **Sudden policy propagation across many hosts**
* **Endpoint execution patterns**

  * Same script executed across multiple systems
* **GPO GUID references**

  * Identify affected endpoints
* **Domain controller logs**

  * Event IDs:

    * 5136
    * 5137
    * 5141

---

# 6. Mitigations / Security Best Practices

### Access Control

* Restrict **GPO modification rights** to a small group of administrators.
* Use **tiered administration model (Tier 0)** for domain controllers and GPO management.

### Monitoring

* Enable **Advanced AD Auditing**:

  * Directory Service Changes
  * Object Access
* Monitor **SYSVOL file changes**.

### Security Hardening

* Use **Group Policy Change Control** process.
* Implement **Privileged Access Workstations (PAW)** for AD admins.

### Detection Improvements

* Monitor **PowerShell script block logging**.
* Correlate **GPO changes with endpoint behavior**.

### Defensive Tools

* Deploy **File Integrity Monitoring on SYSVOL**.
* Integrate **EDR telemetry with SIEM**.

### Backup & Recovery

* Maintain **version-controlled GPO backups**.
* Quickly restore compromised policies.

---