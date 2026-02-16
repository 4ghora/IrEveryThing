## 1. Alert Name

**Detect Malicious Use of Msiexec Mimikatz**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects suspicious execution of **`msiexec.exe`** with command-line arguments associated with **Mimikatz credential-dumping modules** such as:

- `privilege::`
- `sekurlsa`
- `token::`

### Detection Logic:

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "msiexec.exe"
and (ProcessCommandLine contains "privilege::"
or ProcessCommandLine has "sekurlsa"
or ProcessCommandLine contains "token::")
```

This indicates potential abuse of a legitimate Windows binary (**Living-Off-the-Land Binary – LOLBin**) to execute Mimikatz commands.

---

### 2.1 What triggered the alert

The alert was triggered because:

- The process **msiexec.exe** was observed executing
- The command line included Mimikatz module keywords such as:
    - `sekurlsa::logonpasswords`
    - `privilege::debug`
    - `token::elevate`

**Example Trigger Scenario:**

```
msiexec.exe /q /i payload.msi
→ internally launches mimikatz with sekurlsa::logonpasswords
```

OR

```
msiexec.exe privilege::debug sekurlsa::logonpasswords
```

This indicates possible credential dumping behavior.

---

### 2.2 Which security tool generated it

Typically generated from:

- **Microsoft Defender for Endpoint (MDE)**
- **Microsoft Sentinel (via DeviceProcessEvents table)**
- Any EDR collecting process telemetry with command-line logging enabled

Data Source: `DeviceProcessEvents`

---

### 2.3 Why this alert is important

This alert indicates potential:

- **Credential Dumping (MITRE ATT&CK T1003)**
- **Privilege Escalation**
- **Token Manipulation (T1134)**
- **Defense Evasion using LOLBins (T1218 – Signed Binary Proxy Execution)**

Mimikatz usage often signals:

- Domain compromise
- Lateral movement preparation
- Full Active Directory takeover

---

### 2.4 Define Severity? Conditions to escalate alert to more severity.

**Default Severity: High**

Escalate to **Critical** if:

- Target system is:
    - Domain Controller
    - Tier-0 asset
    - Admin workstation
- User is:
    - Domain Admin
    - Privileged Service Account
- `sekurlsa::logonpasswords` successfully executed
- Suspicious lateral movement observed
- LSASS memory access confirmed

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts analyst must understand

### 1. Msiexec.exe

- Legitimate Windows Installer utility
- Located at: `C:\Windows\System32\msiexec.exe`
- Normally installs MSI packages
- Abused as a **LOLBIN**

### 2. Mimikatz

- Open-source post-exploitation tool
- Extracts plaintext passwords, NTLM hashes, Kerberos tickets from LSASS
- Requires SeDebugPrivilege

### 3. sekurlsa Module

- Extracts credentials from LSASS memory
- Example: `sekurlsa::logonpasswords`

### 4. privilege::debug

- Enables debug privileges required to access LSASS memory

### 5. Token Manipulation

- Stealing or impersonating access tokens
- Example: `token::elevate`

### 6. LSASS

- Local Security Authority Subsystem Service
- Stores credentials in memory
- Common credential dumping target

---

## 4. Attacker Perspective

### 4.1 Why attackers use this technique

- Avoid detection using legitimate signed binaries
- Bypass application whitelisting
- Blend into normal system processes

---

### 4.2 What they try to achieve

- Dump credentials
- Extract NTLM hashes
- Obtain Kerberos tickets
- Elevate privileges
- Move laterally
- Establish domain dominance

---

### 4.3 Real-world attack examples

- **FIN7** – Used Mimikatz for credential harvesting
- **Wizard Spider** – Leveraged credential dumping before deploying ransomware
- **APT28** – Used Mimikatz variants for AD compromise

---

### 4.4 Potential Business Impact

- Full domain compromise
- Ransomware deployment
- Data exfiltration
- Financial fraud
- Regulatory penalties
- Operational downtime

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm hostname and user

- Identify affected device
- Logged-in user at execution time
- Is user privileged?

---

### 5.2 Check entities criticality

- Is host:
    - Domain Controller?
    - Jump server?
    - Admin workstation?

---

### 5.3 Verify alert severity

- Check if multiple similar alerts exist
- Confirm presence of LSASS access events
- Check process integrity level

---

## 6. Investigation Steps

---

### 6.1 What questions should an analyst ask himself?

1. Is msiexec executing legitimately?
2. What was the parent process?
3. Did it spawn child processes?
4. Did it access LSASS?
5. Was credential dumping successful?
6. Is there lateral movement?
7. Is this part of red team activity?

---

### 6.2 Answer the questions

**1. Was msiexec expected?**

Check:

```
DeviceProcessEvents
| where FileName == "msiexec.exe"
| summarize count() by DeviceName, AccountName
```

**2. Parent process suspicious?**

Look for:

- powershell.exe
- cmd.exe
- rundll32.exe
- wmic.exe

**3. Child processes spawned?**

Investigate process tree:

```
DeviceProcessEvents
| where InitiatingProcessFileName == "msiexec.exe"
```

**4. LSASS Access?**

```
DeviceProcessEvents
| where FileName == "lsass.exe"
```

OR check EDR memory access logs.

**5. Network Activity?**

```
DeviceNetworkEvents
| where InitiatingProcessFileName == "msiexec.exe"
```

---

### 6.3 Major Investigations (Important)

- Process tree analysis
- Check command-line arguments
- Verify file hash reputation
- Check for dropped MSI files
- Analyze memory dumps
- Identify lateral movement
- Review domain controller logs

---

### 6.4 Minor Investigations (Related)

- Check scheduled tasks
- Review persistence mechanisms
- Check registry run keys
- Check for suspicious services
- Investigate SMB activity

---

## 7. Evidence to Collect

- Full process tree
- Command line
- File hash (SHA256)
- User SID
- Logon session ID
- LSASS access logs
- Network connections
- Memory dump (if possible)
- MSI file dropped (if exists)

---

## 8. Indicators of True Positive

- `sekurlsa::logonpasswords` in command line
- `privilege::debug` observed
- LSASS handle access events
- Abnormal parent process
- Execution from Temp directory
- Suspicious network connections post-execution
- Hash matches known Mimikatz variants
- Lateral movement shortly after

---

## 9. Indicators of False Positive

- Authorized red team activity
- Security testing tools execution
- Known internal penetration testing schedule
- Legitimate MSI installation (no Mimikatz keywords)

Note: Legitimate msiexec **should never** include `sekurlsa` or `token::` arguments.

---

## 10. Incident Response Actions (If True Positive)

---

### 10.1 Containment

- Isolate affected host immediately
- Disable compromised accounts
- Reset privileged credentials
- Block malicious hashes

---

### 10.2 Eradication

- Remove malicious binaries
- Kill malicious processes
- Remove persistence
- Patch vulnerabilities exploited

---

### 10.3 Recovery

- Reimage compromised host
- Force password reset (Domain Admins)
- Rotate service account credentials
- Monitor domain controllers

---

## 11. Mitigation & Prevention

- Enable LSASS protection (RunAsPPL)
- Enable Credential Guard
- Enforce least privilege
- Monitor for T1003 techniques
- Block Mimikatz signatures via EDR
- Disable unnecessary debug privileges
- Enable attack surface reduction (ASR rules)
- Monitor LOLBin abuse (msiexec, rundll32, regsvr32)

---
