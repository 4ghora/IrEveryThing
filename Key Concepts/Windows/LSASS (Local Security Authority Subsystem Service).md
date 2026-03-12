## LSASS (Local Security Authority Subsystem Service)

---

# 1. What It Is

* **Local Security Authority Subsystem Service (LSASS)** is a critical Windows process responsible for **authentication, credential management, and security policy enforcement**.
* The executable **`lsass.exe`** runs as a protected system process and stores **authentication secrets in memory**.
* It handles authentication for **NTLM, Kerberos, and Active Directory logons**.
* LSASS maintains **cached credentials, Kerberos tickets, password hashes, and access tokens** for logged-in sessions.
* Used in **Windows enterprise environments**, especially **Active Directory domain-joined systems**.

---

# 2. Legitimate Use

* **User Authentication Processing**

  * Validates credentials during logon via **Kerberos or NTLM**.

* **Credential Storage**

  * Temporarily stores **Kerberos tickets, NTLM hashes, and session credentials** in memory.

* **Security Policy Enforcement**

  * Enforces **local security policies and password validation**.

* **Single Sign-On (SSO)**

  * Maintains authentication tokens for seamless access across services.

* **Integration with Active Directory**

  * Communicates with **domain controllers** for authentication and authorization decisions.

---

# 3. Attacker Abuse

Attackers frequently target LSASS because it contains **valuable credentials in memory**.

### Credential Dumping

* Attackers dump LSASS memory to extract:

  * NTLM password hashes
  * Cleartext credentials
  * Kerberos tickets
* Often performed using tools like **Mimikatz**, **ProcDump**, or **comsvcs.dll**.

**MITRE ATT&CK:**

* **OS Credential Dumping: LSASS Memory (T1003.001)**

---

### LSASS Process Handle Access

* Malware opens a **read handle to LSASS** to dump credentials without writing files.

**MITRE:**

* **Credential Dumping**

---

### MiniDump File Creation

* Attackers generate **LSASS dump files** (`.dmp`) using tools like:

```
procdump.exe -ma lsass.exe lsass.dmp
```

* These dumps are later **exfiltrated and parsed offline**.

---

### Living-Off-The-Land Credential Dumping

* Abuse native Windows components:

| Tool                       | Technique       |
| -------------------------- | --------------- |
| `rundll32` + `comsvcs.dll` | MiniDump LSASS  |
| `taskmgr`                  | Manual dump     |
| `powershell`               | Memory scraping |

---

# 4. SIEM Detection Opportunities

## Alert 1: LSASS Memory Access by Non-System Process

**Suspicious Behavior**

* A non-standard process attempts to open a handle to `lsass.exe`.

**Detection Logic**

```
ProcessAccess
WHERE TargetProcess = lsass.exe
AND AccessMask CONTAINS "PROCESS_VM_READ"
AND SourceProcess NOT IN (known AV, EDR, backup tools)
```

**Log Sources**

* EDR Telemetry (Defender, CrowdStrike, SentinelOne)
* Sysmon Event ID 10 (Process Access)

---

## Alert 2: LSASS Dump File Creation

**Suspicious Behavior**

* Creation of `.dmp` files associated with LSASS.

**Detection Logic**

```
FileCreate
WHERE FileName LIKE "*lsass*.dmp"
OR CommandLine CONTAINS "lsass"
```

**Log Sources**

* Sysmon Event ID 11
* EDR file telemetry

---

## Alert 3: ProcDump Targeting LSASS

**Suspicious Behavior**

* Use of ProcDump against the LSASS process.

**Detection Logic**

```
ProcessCreation
WHERE ProcessName = procdump.exe
AND CommandLine CONTAINS "lsass"
```

**Log Sources**

* Windows Event ID 4688
* Sysmon Event ID 1
* EDR telemetry

---

## Alert 4: Rundll32 LSASS Dump via comsvcs.dll

**Suspicious Behavior**

* `rundll32` used to dump LSASS memory.

**Detection Logic**

```
ProcessCreation
WHERE ProcessName = rundll32.exe
AND CommandLine CONTAINS "comsvcs.dll"
AND CommandLine CONTAINS "MiniDump"
```

**Log Sources**

* Windows Security Logs (4688)
* Sysmon Event ID 1
* EDR telemetry

---

## Alert 5: Suspicious Handle Access to LSASS

**Suspicious Behavior**

* Unusual process requesting **high privilege access rights** to LSASS.

**Detection Logic**

```
ProcessAccess
WHERE TargetProcess = lsass.exe
AND GrantedAccess IN (0x1fffff, 0x1010, 0x1410)
```

**Log Sources**

* Sysmon Event ID 10
* EDR telemetry

---

# 5. Investigation Indicators

During a SOC investigation, analysts should examine:

* **Processes accessing LSASS**

  * Unknown binaries requesting memory access.

* **Suspicious command lines**

  * `procdump -ma lsass`
  * `rundll32 comsvcs.dll MiniDump`

* **Dump files on disk**

  * `lsass.dmp`
  * `*.dmp` files in `Temp` or `Users\Public`.

* **Parent-child process anomalies**

  * `powershell → procdump`
  * `cmd → rundll32 → lsass dump`.

* **Credential theft follow-on activity**

  * Lateral movement
  * Pass-the-hash authentication attempts.

---

# 6. Mitigations / Security Best Practices

### Enable LSASS Protection

* Enable **LSA Protection (RunAsPPL)** to prevent unauthorized memory access.

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
RunAsPPL = 1
```

---

### Credential Guard

* Enable **Windows Defender Credential Guard** to isolate secrets from LSASS.

---

### Restrict Debug Privileges

* Limit **SeDebugPrivilege** to only trusted administrators.

---

### EDR Monitoring

* Deploy EDR capable of detecting:

  * Memory scraping
  * LSASS handle access
  * Credential dumping tools.

---

### Monitor Dump File Creation

* Alert on `.dmp` file creation across sensitive systems.

---

### Disable WDigest

* Prevent storage of **cleartext passwords** in LSASS memory.

---