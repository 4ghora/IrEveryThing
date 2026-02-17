## 1. Alert Name

**Shadow Copy Deletions**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects execution of commands commonly used to delete **Volume Shadow Copies**, disable **System Restore**, or remove backup artifacts — techniques heavily associated with ransomware and destructive attacks.

The query monitors `DeviceProcessEvents` for specific command-line patterns such as:

- `vssadmin.exe delete shadows /all /quiet`
- `wmic.exe shadowcopy delete`
- `wbadmin delete catalog -quiet`
- PowerShell WMI deletion of `Win32_ShadowCopy`
- Registry modifications disabling System Restore
- Scheduled task modifications for `\Microsoft\Windows\SystemRestore\SR`

These actions map primarily to:

- **MITRE ATT&CK T1490 – Inhibit System Recovery**
- Often seen in combination with:
    - T1486 – Data Encrypted for Impact
    - T1059 – Command & Scripting Interpreter
    - T1106 – Native API

---

### 2.1 What Triggered the Alert

The alert is triggered when:

```
DeviceProcessEvents
| where ProcessCommandLine has_any (CommonRansomwareExecutionCommands)
```

If any process command line contains the predefined ransomware-related shadow deletion commands, the alert fires.

### Example Trigger Scenarios:

1. **Ransomware execution stage**
    
    ```
    vssadmin.exe delete shadows /all /quiet
    ```
    
2. **Living-off-the-land attack**
    
    ```
    wmic.exe shadowcopy delete
    ```
    
3. **PowerShell abuse**
    
    ```
    Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
    ```
    
4. **Backup deletion**
    
    ```
    wbadmin delete systemstatebackup -keepVersions:0
    ```
    

These commands are executed prior to encryption to prevent file restoration.

---

### 2.2 Which Security Tool Generated It

This query is designed for:

- **Microsoft Defender for Endpoint**
- **Microsoft Sentinel (Azure Sentinel)**

Specifically using:

- `DeviceProcessEvents` table (MDE telemetry)
- Process command-line logging

---

### 2.3 Why This Alert is Important

Shadow copy deletion is a **high-confidence ransomware precursor behavior**.

Attackers delete backups to:

- Prevent recovery
- Increase ransom payment likelihood
- Ensure operational disruption

If confirmed malicious, this typically indicates:

- Late-stage attack
- Pre-encryption phase
- Domain-wide impact potential

This alert is rarely noise in enterprise environments.

---

### 2.4 Define Severity? Conditions to Escalate Alert to More Severity

**Default Recommended Severity: High**

Escalate to **Critical** if:

- Executed on:
    - Domain Controllers
    - File Servers
    - Backup servers
- Followed by:
    - Mass file modifications
    - Known ransomware process names
    - Suspicious PowerShell activity
    - Lateral movement (PsExec, WMI, SMB)
- Executed by:
    - Non-admin user
    - Compromised service account
- Observed across multiple endpoints

---

## 3. Knowledge Required Before Investigation

This section is critical. Analysts must understand underlying technologies.

---

### 3.1 Concepts Analyst Must Understand

### 1. Volume Shadow Copy Service (VSS)

- Windows feature creating point-in-time snapshots.
- Used by:
    - System Restore
    - Backup solutions
    - File history

Shadow copies allow restoring previous file versions.

Attackers delete them using:

- `vssadmin`
- `wmic`
- PowerShell WMI
- Direct API calls

If VSS is removed:

- Users cannot restore files
- Ransomware recovery becomes difficult

---

### 2. vssadmin.exe

Legitimate Windows binary used to manage VSS.

Example legitimate use:

```
vssadmin list shadows
```

Malicious usage:

```
vssadmin delete shadows /all /quiet
```

This command:

- Deletes all restore points
- Suppresses confirmation prompts
- Leaves no recovery option

Living-off-the-Land Binary (LOLBIN).

---

### 3. WMIC Shadowcopy Deletion

```
wmic shadowcopy delete
```

Uses WMI interface to delete shadow copies.

Why attackers use it:

- Avoid detection on vssadmin
- Bypass simple command-based detections

---

### 4. wbadmin

Windows backup utility.

Malicious use:

```
wbadmin delete catalog -quiet
```

Removes backup catalog → breaks restore capabilities.

---

### 5. Registry-Based System Restore Disable

Keys modified:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore
```

Values:

- DisableConfig
- DisableSR

If set to 1 → System Restore disabled.

This is stealthier than deleting shadow copies directly.

---

### 6. Scheduled Task Abuse

Modifying:

```
\Microsoft\Windows\SystemRestore\SR
```

Attackers disable restore service via `schtasks`.

---

### 7. MITRE Context – T1490

“Inhibit System Recovery” is used in:

- Ransomware
- Destructive malware (e.g., wipers)

This usually occurs in:

- Final stage before encryption
- After privilege escalation

---

## 4. Attacker Perspective

---

### 4.1 Why Attackers Use This Technique

Attackers want:

- No rollback capability
- Guaranteed impact
- Increased ransom leverage

Without deleting shadow copies:

- Victims can restore data
- Ransom loses power

---

### 4.2 What They Try to Achieve

- Maximize operational disruption
- Destroy backups
- Force payment
- Delay IR response

This is not reconnaissance — this is impact phase.

---

### 4.3 Real-World Attack Examples

- **Ryuk**
    
    Used `vssadmin delete shadows /all /quiet`
    
- **Conti**
    
    Deleted shadow copies and disabled recovery before encryption
    
- **LockBit**
    
    Uses multiple fallback techniques for shadow copy removal
    
- **NotPetya**
    
    Disabled recovery to maximize destruction
    

---

### 4.4 Potential Business Impact

- Total data encryption
- No file recovery
- Business outage
- Regulatory fines
- Reputation damage
- Domain-wide compromise

On backup server → catastrophic impact.

---

## 5. Pre-Investigation Checklist

---

### 5.1 Confirm Hostname and User

From alert:

- `DeviceName`
- `AccountName`
- `TimeGenerated`

Check:

- Is this a server?
- Is this admin account?
- Is it service account?

---

### 5.2 Check Entity Criticality

Classify asset:

- Domain Controller?
- File server?
- Backup server?
- User workstation?

High-value asset → escalate.

---

### 5.3 Verify Alert Severity

Check:

- Was it manual admin action?
- Change window?
- IT backup maintenance?

If not during change window → suspicious.

---

## 6. Investigation Steps

---

### 6.1 What Questions Should an Analyst Ask?

1. Who executed the command?
2. Was it interactive or remote?
3. Was there privilege escalation?
4. Are there other ransomware indicators?
5. Did file encryption follow?
6. Was lateral movement observed?
7. Was this part of legitimate backup cleanup?

---

---

### 6.2 Answer the Questions

Below are structured answers with investigation logic and practical KQL examples.

---

### Q1 – Who executed the command?

**Objective:** Identify the exact user, session type, and legitimacy of execution.

```
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where ProcessCommandLine has_any ("vssadmin", "shadowcopy", "wbadmin")
| project TimeGenerated, AccountName, InitiatingProcessAccountName,
          LogonId, ProcessCommandLine, InitiatingProcessFileName
```

**What to check:**

- Is `AccountName` a Domain Admin or Backup Admin?
- Is it a service account?
- Is this account normally used on this host?
- Has this account triggered prior alerts?

🚨 Suspicious Indicators:

- Standard user executing deletion
- Service account used interactively
- Recently created account

---

### Q2 – What is the Parent Process Chain?

**Objective:** Identify if execution was user-driven, script-based, or malware-driven.

```
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where ProcessCommandLine has_any ("vssadmin","shadowcopy","wbadmin")
| project TimeGenerated, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
```

**Normal chain:**

```
explorer.exe → cmd.exe → vssadmin.exe
```

**Suspicious chains:**

```
winword.exe → powershell.exe → vssadmin.exe
wscript.exe → cmd.exe → vssadmin.exe
unknown.exe → cmd.exe → wmic.exe
```

🚨 Red flags:

- Office process spawning PowerShell
- Unknown executable spawning deletion command
- Encoded PowerShell before deletion

This suggests execution via macro, phishing, or C2.

---

### Q3 – Was the Execution Remote?

**Objective:** Determine lateral movement.

Check logon type:

```
DeviceLogonEvents
| where DeviceName == "HOSTNAME"
| where LogonId == "<LogonId from process event>"
| project AccountName, LogonType, RemoteIP
```

**LogonType values:**

- 2 → Interactive
- 3 → Network
- 10 → RemoteInteractive (RDP)

🚨 Suspicious:

- Network logon followed by shadow deletion
- RDP session from unusual IP
- Service logon followed by deletion

If remote IP is internal but unusual → possible lateral movement.

---

### Q4 – Was There Privilege Escalation Before This?

Shadow copy deletion requires administrative privileges.

Check prior privilege escalation:

```
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where TimeGenerated between (ago(6h) .. now())
| where ProcessCommandLine has_any ("net localgroup administrators",
                                    "whoami /priv",
                                    "token",
                                    "runas")
```

Also check:

- Event ID 4672 (Special privileges assigned)
- UAC bypass behavior
- Token manipulation

🚨 If admin privileges were obtained shortly before deletion → attack progression.

---

### Q5 – Did Encryption or Destructive Activity Follow?

Shadow deletion is often a **precursor to encryption**.

Look for mass file activity:

```
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where TimeGenerated > <ShadowDeletionTime>
| summarize count() by FolderPath
| sort by count_ desc
```

Indicators:

- High volume file writes
- File extensions changing
- Creation of ransom notes (e.g., README.txt)
- Files renamed to unusual extensions

🚨 If file modification spike follows deletion → ransomware likely active.

---

### Q6 – Is This Activity Observed on Other Devices?

Check if outbreak is spreading:

```
DeviceProcessEvents
| where ProcessCommandLine has_any ("delete shadows","shadowcopy delete")
| summarize count() by DeviceName
```

If multiple devices show same command within short timeframe:

- Coordinated deployment
- Domain-wide attack
- Ransomware propagation

Escalate immediately to Critical.

---

### Q7 – Was Backup Infrastructure Targeted?

Check if:

- Backup server executed deletion
- Backup agent services stopped

```
DeviceProcessEvents
| where DeviceName contains "backup"
| where ProcessCommandLine has_any ("wbadmin","vssadmin")
```

If backup infrastructure compromised → catastrophic impact.

---

### Q8 – Was There C2 Communication Around This Time?

Shadow deletion usually occurs after attacker establishes foothold.

Check network connections:

```
DeviceNetworkEvents
| where DeviceName == "HOSTNAME"
| where TimeGenerated between (ago(4h) .. now())
| summarize by RemoteIP, RemotePort, InitiatingProcessFileName
```

Look for:

- Suspicious external IPs
- Known malicious domains
- Beaconing patterns

If external C2 present → active attacker.

---

### 6.3 Major Investigations (Critical Analysis Steps)

These steps determine scope and impact.

---

### 1️⃣ Build Full Attack Timeline

Construct 6–12 hour timeline:

- Initial access
- Privilege escalation
- Credential dumping
- Lateral movement
- Shadow copy deletion
- Encryption activity

This helps identify attack phase.

---

### 2️⃣ Investigate Lateral Movement Techniques

Look for:

- PsExec usage
- WMI remote execution
- SMB admin shares
- RDP logins
- Scheduled task creation across hosts

```
DeviceProcessEvents
| where ProcessCommandLine has_any ("psexec","wmic /node","schtasks /create")
```

Shadow deletion across multiple hosts via PsExec = ransomware deployment.

---

### 3️⃣ Check for Persistence Mechanisms

Before deletion, attacker may establish persistence:

- Registry Run keys
- Scheduled tasks
- Services creation

```
DeviceRegistryEvents
| where RegistryKey has "Run"
```

---

### 4️⃣ Check Domain Controller Logs

If executed on DC:

- Kerberos anomalies
- DCSync attempts
- Replication abuse

Shadow deletion on DC often indicates full domain compromise.

---

### 5️⃣ Validate Backup Server Integrity

- Check backup job failures
- Check immutable backups
- Confirm offline backups exist

---

### 6.4 Minor Investigations (Supporting Analysis)

These steps help validate false positives.

---

### 1. Confirm Change Window

- Check IT maintenance calendar
- Confirm change ticket
- Validate CAB approval

---

### 2. Confirm Backup Cleanup Policies

Some organizations:

- Periodically purge shadow copies
- Rotate backups automatically

Verify documentation.

---

### 3. Validate Script Automation

Check if:

- Known IT script path
- Signed script
- Known hash
- Previously observed in environment

---

### 4. User Behavioral Baseline

Check:

- Does this admin normally manage backups?
- Has this account executed similar commands historically?

```
DeviceProcessEvents
| where AccountName == "User"
| where ProcessCommandLine has "vssadmin"
| summarize count() by bin(TimeGenerated, 30d)
```

If never seen before → suspicious.

---

## 7. Evidence to Collect

Proper evidence collection is critical for confirming ransomware staging and supporting forensics.

### Process-Level Evidence

- Full process tree (parent → child chain)
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- SHA256 hash of initiating executable
- File path of binary
- Process execution timestamp
- LogonId and SessionId

---

### User & Authentication Evidence

- LogonType (2, 3, 10)
- Source IP address
- RDP logs
- Account privilege level
- Event ID 4672 (Special privileges assigned)
- MFA logs (if admin account)

---

### File System Evidence

- Mass file modifications
- Ransom note creation
- Newly created file extensions
- Deleted backup artifacts (.wbcat, .bkf, .vhd)

---

### Network Evidence

- Outbound connections during execution window
- DNS queries to suspicious domains
- SMB connections to other endpoints
- Lateral movement artifacts

---

### System-Level Evidence

- Registry modifications to:
    
    ```
    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore
    ```
    
- Scheduled task modifications
- Backup service status changes
- Event Logs:
    - System
    - Security
    - Microsoft-Windows-Backup

---

## 8. Indicators of True Positive

These strongly indicate ransomware staging or destructive activity:

- Shadow copy deletion followed by mass file encryption
- Execution from PowerShell with encoded command
- Parent process is unknown or malicious
- Activity observed across multiple hosts
- Remote execution (LogonType 3 or 10)
- Admin privilege obtained shortly before deletion
- Account not normally used for backup management
- Backup server targeted
- C2 communication present
- Ransom note detected

If 3 or more high-confidence indicators are present → escalate to Critical.

---

## 9. Indicators of False Positive

Possible benign scenarios:

- Backup retention policy enforcement
- IT performing storage cleanup
- Scheduled script for backup rotation
- Maintenance window activity
- Executed by known backup admin
- Documented CAB change request
- No follow-on suspicious behavior
- Single host only

Key validation step:

Confirm with IT before closing.

---

## 10. Incident Response Actions (If True Positive)

Shadow copy deletion is often late-stage attack behavior. Immediate containment is essential.

---

### 10.1 Containment

**Immediate Actions:**

- Isolate affected host from network
- Disable compromised accounts
- Block lateral movement ports (445, 3389, 5985)
- Revoke active sessions
- Remove Kerberos tickets (if domain compromise suspected)

If multiple endpoints impacted:

- Activate ransomware incident response plan
- Consider network segmentation
- Temporarily disable admin shares if feasible

Time is critical — encryption may already be in progress.

---

### 10.2 Eradication

After containment:

- Identify initial access vector
- Remove malicious binaries
- Remove persistence:
    - Scheduled tasks
    - Registry run keys
    - Services
- Patch exploited vulnerabilities
- Reset credentials:
    - Local admins
    - Domain admins
    - Service accounts

If domain compromise suspected:

- Rotate KRBTGT password (carefully planned)
- Reset privileged accounts

---

### 10.3 Recovery

- Restore from offline/immutable backups
- Validate backup integrity before restoration
- Rebuild compromised machines
- Monitor restored systems for reinfection
- Validate no shadow deletion commands reappear

Important:

If shadow copies are deleted and no backups exist → recovery complexity increases drastically.

---

## 11. Mitigation & Prevention

Shadow copy deletion is an impact-stage behavior. Prevention must focus on reducing attacker ability to reach that stage.

---

### 1. Restrict Administrative Privileges

- Implement least privilege
- Remove local admin rights
- Use Privileged Access Workstations (PAWs)
- Enforce Just-In-Time (JIT) access

---

### 2. Attack Surface Reduction (ASR Rules)

Enable rules to block:

- Office spawning child processes
- Credential stealing from LSASS
- Suspicious PowerShell execution

---

### 3. Block LOLBIN Abuse

- Monitor usage of:
    - vssadmin.exe
    - wmic.exe
    - wbadmin.exe
- Alert on T1490 behavior
- Consider AppLocker or WDAC policies

---

### 4. Backup Hardening

- Use immutable backups
- Store backups offline
- Separate backup credentials from domain
- Monitor backup server logs

---

### 5. Lateral Movement Controls

- Disable unnecessary SMB
- Restrict RDP access
- Monitor PsExec usage
- Enable network segmentation

---

### 6. Behavioral Detection Improvements

Instead of only command matching:

Correlate:

- Admin privilege escalation
- Followed by shadow deletion
- Followed by mass file write activity

Multi-stage correlation reduces false positives and increases detection confidence.

---
