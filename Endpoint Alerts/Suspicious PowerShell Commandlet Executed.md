# Suspicious PowerShell Commandlet Executed

Type: IR Eveything
Updated: February 16, 2026 9:38 PM
Created: February 16, 2026 9:17 PM

---

## 1. Alert Name

**Suspicious PowerShell Commandlet Executed**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects execution of specific **Active Directory reconnaissance-related PowerShell cmdlets** on endpoints.

The query monitors `DeviceEvents` where:

- `ActionType == "PowerShellCommand"`
- The executed command contains any of the following:

```
Get-ADUserResultantPasswordPolicy
Get-DomainPolicy
Get-DomainUser
Get-DomainComputer
Get-DomainController
Get-DomainGroup
Get-DomainTrust
Get-ADTrust
Get-ForestTrust
```

These cmdlets are commonly used for **Active Directory enumeration and trust discovery**.

---

### 2.1 What triggered the alert

The alert is triggered when:

- A PowerShell command execution event is logged.
- The command contains one or more of the listed AD reconnaissance cmdlets.
- The query extracts:
    - Username
    - Device hostname
    - Process details
    - Command line context

Example triggering command:

```powershell
Get-DomainUser -Identity Administrator
Get-DomainTrust
Get-ADUserResultantPasswordPolicy -Identity user1
```

---

### 2.2 Which security tool generated it

- **Microsoft Defender for Endpoint (MDE)**
- Ingested into **Microsoft Sentinel**
- Based on `DeviceEvents` telemetry

---

### 2.3 Why this alert is important

These cmdlets are heavily used during:

- Initial domain reconnaissance
- Privilege escalation planning
- Lateral movement preparation
- Domain trust mapping
- Kerberoasting targeting
- Password policy discovery

MITRE ATT&CK Mapping:

- **T1087.002** – Account Discovery: Domain Account
- **T1069.002** – Permission Groups Discovery: Domain Groups
- **T1482** – Domain Trust Discovery
- **T1018** – Remote System Discovery

If executed outside administrative context, this is **highly suspicious**.

---

### 2.4 Define Severity? Conditions to escalate alert to more severity.

**Medium Severity (Default):**

- Standard admin workstation
- Known IT account
- Change management activity

**High Severity:**

- Executed by:
    - Non-admin user
    - Service account
    - Recently created account
- Occurs on:
    - Domain Controller
    - Critical server
- Executed via:
    - `powershell.exe -EncodedCommand`
    - `rundll32`, `wmi`, `winrm`
- Followed by:
    - Kerberos ticket requests (Event 4769)
    - Lateral movement activity

**Critical Severity:**

- Combined with credential dumping
- C2 beaconing detected
- Mass account enumeration
- Trust enumeration in multi-forest environment

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts analyst must understand about the entities in alert

**1️⃣ Active Directory Enumeration**

Process of querying AD objects (users, groups, trusts, computers). Used by admins — but also attackers during reconnaissance.

**2️⃣ Domain Trusts**

Trust relationships between domains/forests allowing authentication across boundaries. Attackers enumerate trusts to identify pivot paths.

**3️⃣ Resultant Password Policy (RSoP)**

Reveals effective password policy applied to user. Attackers check:

- Minimum length
- Lockout threshold
- Complexity
    
    Used for password spraying planning.
    

**4️⃣ PowerView & Recon Toolkits**

`Get-DomainUser`, `Get-DomainTrust`, etc. are commonly from:

- PowerView
- Empire
- Cobalt Strike modules
- BloodHound collectors

These are red-team favorite commands.

**5️⃣ PowerShell Logging**

Understand:

- Script Block Logging
- Module Logging
- Process creation events
- Encoded command detection

---

## 4. Attacker Perspective

### 4.1 Why attackers use this technique

After initial foothold, attackers perform **internal reconnaissance** to:

- Identify high-value accounts
- Map domain structure
- Identify domain controllers
- Discover trust paths

This is typically post-exploitation Phase 2.

---

### 4.2 What they try to achieve

- Identify Domain Admin members
- Identify privileged groups
- Locate DCs
- Discover weak password policy
- Map trust relationships for lateral pivot

---

### 4.3 Real-world attack examples

- **FIN7** used PowerShell AD enumeration before ransomware deployment.
- **APT29** leveraged PowerShell-based AD discovery.
- **Conti** performed extensive domain enumeration prior to mass encryption.

---

### 4.4 Potential Business Impact

- Full domain compromise
- Lateral movement
- Ransomware deployment
- Data exfiltration
- Cross-domain compromise via trusts

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm hostname and user

- Is device a:
    - Domain Controller?
    - IT admin workstation?
    - Regular user laptop?
- Is user:
    - IT admin?
    - Service account?
    - Newly created?

---

### 5.2 Check entities criticality

- Is device Tier-0 asset?
- Is account privileged?
- Is system internet-facing?

---

### 5.3 Verify alert severity

- Single command?
- Mass enumeration?
- Encoded PowerShell?
- After-hours activity?

---

## 6. Investigation Steps

---

### 6.1 What questions should an analyst ask himself while investigating alert

1. Is this legitimate administrative activity?
2. Is the account authorized to run AD enumeration?
3. Was PowerShell executed interactively or remotely?
4. Is this part of a larger attack chain?
5. What happened before and after?

---

### 6.2 Answer the questions

**Q1: Legitimate admin activity?**

Check:

- Change tickets
- Admin workstation baseline
- Historical behavior of user

**Q2: Authorized account?**

Review:

- AD group membership
- Privilege level
- Past activity logs

**Q3: Interactive or remote?**

Check parent process:

- `explorer.exe` → interactive
- `wmiprvse.exe` → remote WMI
- `winrm.exe` → remote PowerShell
- `cmd.exe` with encoded command → suspicious

**Q4: Larger attack chain?**

Look for:

- Logon type 3 from unusual host
- Mimikatz execution
- Lateral movement attempts

---

### 6.3 Major Investigations (Important Investigation steps)

**1️⃣ Full PowerShell command reconstruction**

```
DeviceEvents
| where DeviceName == "hostname"
| where ActionType == "PowerShellCommand"
```

**2️⃣ Process Tree Analysis**

```
DeviceProcessEvents
| where InitiatingProcessId == "<PID>"
```

Check:

- Parent process
- Command line
- Encoded strings

**3️⃣ Account Activity Timeline**

```
DeviceLogonEvents
| where AccountName == "username"
```

Check:

- Lateral movement
- Multiple system logons
- Privilege escalation

**4️⃣ Kerberos Ticket Activity**

Look for:

- Event ID 4769 spike
- Service ticket requests

**5️⃣ Network Activity**

Check:

- Outbound connections after enumeration
- C2 indicators

---

### 6.4 Minor Investigations (Related Investigation steps)

- Check for:
    - Base64 encoded PowerShell
    - AMSI bypass attempts
    - Suspicious scheduled tasks
    - Recent account creations
    - Group membership changes
- Check:
    - Event 4728 (User added to privileged group)
    - Event 4732

---

## 7. Evidence to Collect

- Full PowerShell command
- Process tree
- User logon history
- Kerberos logs
- Network connections
- Memory snapshot (if active compromise suspected)
- EDR telemetry export

---

## 8. Indicators of True Positive

- Non-admin executing AD discovery
- Encoded PowerShell
- Multiple enumeration commands executed rapidly
- Execution from compromised user workstation
- Followed by lateral movement
- Suspicious parent process
- Trust enumeration in single-domain org
- Correlation with credential dumping

---

## 9. Indicators of False Positive

- IT admin workstation
- Approved audit activity
- Security team running BloodHound
- Change window activity
- Repeated historical behavior from same admin

---

## 10. Incident Response Actions (If True Positive)

---

### 10.1 Containment

- Isolate affected host via EDR
- Disable or reset user account
- Block suspicious IPs
- Revoke Kerberos tickets

---

### 10.2 Eradication

- Remove persistence mechanisms
- Scan for malware payloads
- Remove unauthorized tools
- Force password resets for:
    - Privileged accounts
    - Service accounts

---

### 10.3 Recovery

- Restore affected systems
- Monitor for re-enumeration
- Review domain trust exposure
- Validate no privileged group modifications

---

## 11. Mitigation & Prevention

**Technical Controls**

- Enable:
    - PowerShell Script Block Logging
    - Module Logging
    - Constrained Language Mode
- Restrict:
    - PowerShell remoting
- Implement:
    - Tiered admin model
    - Privileged Access Workstations (PAWs)
- Monitor:
    - Encoded PowerShell commands
    - Domain enumeration patterns

**Detection Improvements**

- Alert on:
    - High-frequency AD queries
    - Enumeration + Kerberoasting chain
    - Enumeration + Trust discovery
    - Enumeration from non-admin devices

---