## 1. Alert Name

**Dumping LSASS Process Into a File**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects suspicious access to the **LSASS process** (`lsass.exe`) with full memory access rights and usage of debugging libraries commonly associated with credential dumping.

### 2.1 What triggered the alert

The query monitors:

- **Sysmon Event ID 10** → ProcessAccess event
- Target process:
    
    ```
    C:\Windows\System32\lsass.exe
    ```
    
- Access mask:
    
    ```
    GrantedAccess = 0x1FFFFF
    ```
    
    (Full access — includes PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, etc.)
    
- CallTrace contains:
    - `dbghelp.dll`
    - `dbgcore.dll`

This indicates a process attempted to read LSASS memory using Windows debugging libraries — a classic memory dumping technique.

### 2.2 Which security tool generated it

- **Microsoft Sysmon**
    - Log Source: `Microsoft-Windows-Sysmon/Operational`
    - Event ID: 10 (Process Access)

Forwarded typically into:

- Microsoft Sentinel
- Splunk
- QRadar
- Elastic SIEM

---

### 2.3 Why this alert is important

LSASS (Local Security Authority Subsystem Service) stores:

- NTLM hashes
- Kerberos TGTs
- Plaintext credentials (if WDigest enabled)
- Cached domain credentials

Dumping LSASS = **Credential Access**

MITRE ATT&CK Technique:

- **T1003.001 – OS Credential Dumping: LSASS Memory**

If successful, attacker can:

- Perform Pass-the-Hash
- Create Golden/Silver tickets
- Move laterally
- Escalate privileges to Domain Admin

This is a **high-impact post-compromise action**.

---

### 2.4 Define Severity? Conditions to escalate alert to more severity.

**Default Severity: High**

Escalate to **Critical** if:

- Source process is:
    - `powershell.exe`
    - `cmd.exe`
    - `rundll32.exe`
    - `procdump.exe`
    - Unknown unsigned binary
- The user context is:
    - Domain Admin
    - Server Admin
- Target is:
    - Domain Controller
    - Tier 0 asset
- Followed by:
    - Lateral movement
    - Kerberos anomalies
    - Suspicious outbound traffic

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts analyst must understand about the entities in alert

### LSASS (Local Security Authority Subsystem Service)

- Critical Windows process
- Manages authentication & credential material
- Runs as SYSTEM
- Memory contains highly sensitive secrets

### Sysmon Event ID 10 – ProcessAccess

- Logged when one process accesses another
- Important fields:
    - SourceImage
    - TargetImage
    - GrantedAccess
    - CallTrace

### GrantedAccess = 0x1FFFFF

- Full control over target process
- Indicates ability to:
    - Read memory
    - Write memory
    - Inject threads

### dbghelp.dll / dbgcore.dll

- Windows debugging libraries
- Used legitimately for crash dumps
- Also abused by:
    - Mimikatz
    - ProcDump
    - Custom dumpers

### MITRE ATT&CK

- T1003.001 – LSASS memory dumping

---

## 4. Attacker Perspective

### 4.1 Why attackers use this technique

Because LSASS contains reusable credentials.

If attacker already has local admin:

→ Dump LSASS

→ Extract hashes

→ Move laterally

---

### 4.2 What they try to achieve

- Extract NTLM hashes
- Steal Kerberos tickets
- Gain Domain Admin
- Maintain persistence

---

### 4.3 Real-world attack examples

- **Mimikatz**
- **Cobalt Strike**
- **Ryuk**
- **Conti**

Nearly all modern ransomware operations dump LSASS before encryption.

---

### 4.4 Potential Business Impact

- Domain-wide compromise
- Full Active Directory takeover
- Data exfiltration
- Ransomware deployment
- Regulatory impact (GDPR, HIPAA, etc.)

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm hostname and user

- Is this a Domain Controller?
- Which account executed the SourceProcess?
- Is it SYSTEM? Admin? Service account?

### 5.2 Check entities criticality

- Is this Tier 0?
- Is it production server?
- Is it executive laptop?

### 5.3 Verify alert severity

- Check SourceImage
- Check digital signature
- Check parent process

---

# 6. Investigation Steps

---

## 6.1 What questions should an analyst ask himself while investigating alert.

1. What process accessed LSASS?
2. Is the process legitimate?
3. Is this part of approved activity?
4. Was a dump file created?
5. Did lateral movement occur afterward?
6. Is the host showing other compromise signs?

---

## 6.2 Answer the questions.

### 1️⃣ What process accessed LSASS?

Check:

```
SourceImage
SourceProcessGUID
```

Look for:

- procdump.exe
- powershell.exe
- unknown .exe from temp folder

---

### 2️⃣ Is the process legitimate?

Legitimate cases:

- AV software
- EDR agent
- Backup agent
- Windows Error Reporting

Verify:

- Digital signature
- File path
- Hash reputation (VirusTotal)

---

### 3️⃣ Was a dump file created?

Search:

```
DeviceFileEvents
| where FileName endswith ".dmp"
```

Common dump names:

- lsass.dmp
- debug.dmp

---

### 4️⃣ Did lateral movement occur afterward?

Search for:

- New logon sessions (4624 Type 3)
- PsExec usage
- SMB admin share access
- Remote Service creation

---

### 5️⃣ Any suspicious parent process?

Look at:

```
Sysmon Event ID 1
ParentImage
CommandLine
```

Red flags:

- Office spawning PowerShell
- Browser spawning cmd
- Unknown binary in AppData

---

## 6.3 Major Investigations (Important Investigation steps)

### 🔴 A. Correlate Process Tree

```
EventID == 1
| where ProcessGuid == "<SourceProcessGUID>"
```

Build full process lineage.

---

### 🔴 B. Check for Credential Abuse

- Event 4624 (Type 3/10)
- Event 4672 (Special privileges)
- Kerberos TGS anomalies

---

### 🔴 C. Check EDR telemetry

- Memory dump detection
- Suspicious injection alerts
- Behavior-based detection

---

### 🔴 D. Hash reputation check

- SHA256 lookup
- Threat intelligence feeds

---

## 6.4 Minor Investigations (Related Investigation steps)

- Check if user recently logged in interactively
- Check RDP logs
- Review scheduled tasks
- Review service creation (Event 7045)
- Look for encoded PowerShell

---

# 7. Evidence to Collect

- Memory dump file (if exists)
- Source process binary
- SHA256 hash
- Full process tree
- Security logs (4624, 4672)
- Netflow data
- EDR telemetry snapshot

---

# 8. Indicators of True Positive

- Unsigned binary accessing LSASS
- Dump file creation
- Use of procdump with `ma lsass`
- Suspicious parent process
- Lateral movement after event
- New admin accounts created

---

# 9. Indicators of False Positive

- Known AV process
- EDR performing memory scan
- Authorized IR team activity
- Windows Error Reporting crash dump

---

# 10. Incident Response Actions (If True Positive)

---

## 10.1 Containment

- Immediately isolate host
- Disable compromised accounts
- Block hash if reused
- Reset privileged credentials

---

## 10.2 Eradication

- Remove malicious binaries
- Clear persistence mechanisms
- Reimage if necessary
- Force domain-wide password reset (if DC affected)

---

## 10.3 Recovery

- Restore from clean backup
- Monitor for re-compromise
- Re-enable host after validation
- Implement heightened monitoring

---

# 11. Mitigation & Prevention

- Enable LSASS protection:
    
    ```
    RunAsPPL = 1
    ```
    
- Disable WDigest
- Credential Guard
- EDR memory protection
- Block procdump via AppLocker
- Implement Tiered Admin Model
- Reduce local admin rights
- Monitor Sysmon Event ID 10 aggressively

---
