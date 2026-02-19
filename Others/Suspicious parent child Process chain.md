# Suspicious Parent Child Process Chains

# 1) Office → PowerShell

### Chain

```
winword.exe / excel.exe / outlook.exe / powerpnt.exe → powershell.exe
```

### What These Processes Are

* **winword.exe** – Microsoft Word
* **excel.exe** – Microsoft Excel
* **outlook.exe** – Microsoft Outlook
* **powerpnt.exe** – Microsoft PowerPoint
* **powershell.exe** – Windows scripting and automation engine

### Why Attackers Use It

Macro-enabled documents execute malicious PowerShell payloads after phishing.

### Investigation in Sentinel

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe","powerpnt.exe")
| where FileName =~ "powershell.exe"
```

Look for:

* `-enc`, `-encodedcommand`
* `IEX`
* Web download commands
* Hidden execution flags

Then check:

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
```

Escalate if external IP + encoded command present.

---

# 2) Office → cmd → PowerShell → External IP

### Chain

```
winword.exe → cmd.exe → powershell.exe → Internet
```

### What These Processes Are

* **cmd.exe** – Windows command interpreter

### Why Attackers Use It

Layered execution to bypass simple detection rules.

### Investigation

1. Validate macro origin.
2. Extract PowerShell payload.
3. Check downloaded file.
4. Search for persistence (schtasks, registry).
5. Check lateral movement.

Immediate high severity if beaconing detected.

---

# 3) Office → wscript / cscript

### Chain

```
outlook.exe → wscript.exe / cscript.exe
```

### What These Processes Are

* **wscript.exe / cscript.exe** – Windows Script Host engines (VBScript/JS)

### Why Attackers Use It

Malicious email attachment executing .vbs or .js payload.

### Investigation

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "outlook.exe"
| where FileName in~ ("wscript.exe","cscript.exe")
```

Check:

* Script path (Temp/Downloads)
* Double extensions
* External network communication

---

# 4) Browser → Script Engine

### Chain

```
chrome.exe / msedge.exe / firefox.exe → powershell.exe / mshta.exe / cmd.exe
```

### What These Processes Are

* Browsers – User web access applications
* **mshta.exe** – HTML application host

### Why Attackers Use It

Drive-by downloads or malicious extensions.

### Investigation

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
| where FileName in~ ("powershell.exe","mshta.exe","cmd.exe")
```

Check:

* URL in command line
* Execution from Temp
* Unsigned child binary

---

# 5) mshta → PowerShell

### Chain

```
mshta.exe → powershell.exe
```

### What Is mshta.exe

Executes .hta files (often abused for fileless malware).

### Why Attackers Use It

Signed binary proxy execution.

### Investigation

```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
```

Red flags:

* Remote URL
* Encoded PowerShell child
* External connection

---

# 6) explorer → PowerShell

### Chain

```
explorer.exe → powershell.exe
```

### What Is explorer.exe

Windows GUI shell (launches programs when user double-clicks).

### Why Attackers Use It

Malicious shortcut (.lnk) or user-triggered payload.

### Investigation

Check:

* Execution path (Downloads/Desktop)
* Suspicious arguments
* Previous phishing activity

---

# 7) WMI → Command Execution

### Chain

```
wmiprvse.exe → cmd.exe / powershell.exe
```

### What Is wmiprvse.exe

WMI provider host used for system management and remote execution.

### Why Attackers Use It

Lateral movement across systems.

### Investigation

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 3
```

Check:

* Source IP
* Privileged account usage
* Multiple host involvement

High severity if multi-host pattern detected.

---

# 8) PowerShell → Credential Dumping

### Chain

```
powershell.exe → procdump.exe / rundll32.exe / mimikatz.exe
```

### What These Are

* **procdump.exe** – Memory dump utility
* **rundll32.exe** – DLL execution utility
* **mimikatz.exe** – Credential extraction tool

### Why Attackers Use It

Dump LSASS memory to extract credentials.

### Investigation

```kql
DeviceProcessEvents
| where ProcessCommandLine has "lsass"
```

Then:

```kql
DeviceFileEvents
| where FileName endswith ".dmp"
```

Immediate escalation if confirmed.

---

# 9) cmd → certutil

### Chain

```
cmd.exe → certutil.exe
```

### What Is certutil.exe

Certificate utility abused to download payloads.

### Why Attackers Use It

Living-off-the-land file download.

### Investigation

```kql
DeviceProcessEvents
| where FileName =~ "certutil.exe"
```

Look for:

```
-urlcache -split -f http
```

Then search dropped file execution.

---

# 10) rundll32 → Suspicious DLL

### Chain

```
rundll32.exe → malicious.dll
```

### What Is rundll32.exe

Legitimate Windows DLL execution binary.

### Why Attackers Use It

Reflective DLL injection and proxy execution.

### Investigation

Check:

* DLL location (Temp/AppData suspicious)
* Digital signature
* Network activity

---

# 11) services → PowerShell

### Chain

```
services.exe → powershell.exe
```

### What Is services.exe

Service Control Manager.

### Why Attackers Use It

Persistence via malicious service creation.

### Investigation

```kql
SecurityEvent
| where EventID == 7045
```

Check service name and binary path.

---

# 12) svchost → cmd

### Chain

```
svchost.exe → cmd.exe
```

### What Is svchost.exe

Hosts Windows service groups.

### Why Suspicious

Services normally don’t spawn shells.

### Investigation

Check:

* Newly created service
* Lateral movement context
* Privileged account usage

---

# 13) Scheduled Task → PowerShell

### Chain

```
taskeng.exe / svchost.exe → powershell.exe
```

### What These Are

* **taskeng.exe** – Task Scheduler engine

### Why Attackers Use It

Persistence via scheduled tasks.

### Investigation

```kql
SecurityEvent
| where EventID == 4698
```

Check:

* Random task names
* Execution path
* Trigger type

---

# 14) winlogon → cmd / PowerShell

### Chain

```
winlogon.exe → cmd.exe / powershell.exe
```

### What Is winlogon.exe

Handles user logon process.

### Why Attackers Use It

Registry-based persistence.

### Investigation

```kql
DeviceRegistryEvents
| where RegistryKey has "Run"
```

Check startup entries.

---

# 15) LSASS as Parent

### Chain

```
lsass.exe → any child process
```

### What Is lsass.exe

Local Security Authority Subsystem Service (credential storage).

### Why Critical

LSASS rarely spawns children. Almost always malicious.

Immediate containment recommended.

---

# 16) PowerShell → reg add (Persistence)

### Chain

```
powershell.exe → reg.exe
```

### What Is reg.exe

Registry modification tool.

### Why Suspicious

Persistence via Run keys.

### Investigation

```kql
DeviceProcessEvents
| where FileName =~ "reg.exe"
| where ProcessCommandLine has "Run"
```

---

# 17) PsExec → cmd

### Chain

```
psexec.exe → cmd.exe
```

### What Is PsExec

Sysinternals remote execution tool.

### Why Attackers Use It

SMB-based lateral movement.

### Investigation

Check:

* Logon type 3 events
* Source IP
* Multi-host activity

---

# High-Severity Escalation Indicators Across All Chains

Escalate immediately if:

* Encoded PowerShell present
* External C2 communication
* LSASS access or memory dump
* Privileged account misuse
* Same behavior across multiple endpoints
* Service or scheduled task persistence

---
