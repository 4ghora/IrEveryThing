## 1. Alert Name

**Port Sweep**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects **horizontal port scanning activity** originating from a single `SourceIp` that connects to **more than 200 different destination hosts on the same port within 30 seconds**, excluding ports 80 and 443.

The detection logic aggregates Azure Firewall logs across:

* `AZFWApplicationRule`
* `AZFWNetworkRule`
* `AzureDiagnostics` (legacy firewall logs)

It groups traffic by:

* `SourceIp`
* `DestinationPort`
* 30-second time bin

Then counts unique destinations (`make_set(Fqdn)`).
If `array_length(...) > 200`, it flags the activity.

This behavior strongly aligns with **MITRE ATT&CK – T1046 (Network Service Discovery)**.

---

### 2.1 What Triggered the Alert

The alert triggers when:

* One `SourceIp`
* Contacts
* More than **200 unique FQDNs or destination IPs**
* On the same port
* Within 30 seconds
* Excluding ports 80 and 443

#### Example 1 – Internal Lateral Reconnaissance

```
SourceIp: 10.10.25.14
DestinationPort: 445
Time Window: 12:00:00 – 12:00:30
Unique Targets: 312 internal IPs
```

This likely indicates:

* SMB reconnaissance
* Worm propagation attempt
* Credential spraying against SMB

#### Example 2 – External Recon

```
SourceIp: 52.x.x.x
DestinationPort: 3389
Unique Targets: 278 internal IPs
```

Likely:

* RDP scanning attempt from internet
* Credential brute-force staging

The threshold (200 hosts in 30 seconds) eliminates casual traffic and highlights automated scanning tools like:

* `nmap`
* `masscan`
* Custom scanners
* Worms

---

### 2.2 Which Security Tool Generated It

* **Azure Firewall**

  * Application Rule logs
  * Network Rule logs
* Ingested into:

  * Azure Monitor Logs
  * Microsoft Sentinel (if configured)

Primary telemetry source: **Azure Firewall Traffic Logs**

---

### 2.3 Why This Alert Is Important

Port sweeping is almost always a **pre-attack reconnaissance stage**.

It indicates:

* Active host discovery
* Service enumeration
* Lateral movement staging
* Worm propagation
* Misconfigured automation (less common)

This is typically:

* Pre-ransomware behavior
* Pre-credential dumping behavior
* Pre-exploitation scanning

High-speed scanning (>200 hosts in 30s) suggests:

* Automation
* Malicious intent
* Compromise or attacker-controlled asset

---

### 2.4 Define Severity? Conditions to Escalate Alert to More Severity

**Default Severity: Medium–High**

Escalate to **High or Critical** if:

* Source IP is:

  * Domain Controller
  * Privileged server
  * Management server
* Port scanned is high-risk:

  * 445 (SMB)
  * 3389 (RDP)
  * 5985/5986 (WinRM)
  * 22 (SSH)
* Scan is internal-to-internal (lateral movement)
* Followed by:

  * Authentication failures
  * Successful logins
  * Process execution events
* Endpoint telemetry shows:

  * `nmap`, `masscan`
  * PowerShell network enumeration
  * Suspicious child processes

Escalate to **Critical** if:

* Confirmed compromise of scanning host
* Scan followed by malware deployment
* Scan originated from privileged asset

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts Analyst Must Understand

#### 1. Port Sweep vs Port Scan

* **Port Sweep (Horizontal Scan)**:

  * One port
  * Many hosts
  * Example: Scan port 445 across entire subnet

* **Port Scan (Vertical Scan)**:

  * Many ports
  * One host

This alert detects **horizontal sweep behavior**.

---

#### 2. Azure Firewall Logging Architecture

Understand:

* `AZFWApplicationRule` → FQDN-based filtering
* `AZFWNetworkRule` → IP/Port filtering
* `AzureDiagnostics` → Legacy log schema

Important fields:

* `SourceIp`
* `DestinationPort`
* `Fqdn`
* `TimeGenerated`

Analysts must understand that:

* FQDN may represent IP in NetworkRule logs
* Firewall may log both allowed and denied traffic

---

#### 3. Common High-Risk Ports

| Port | Service | Risk                         |
| ---- | ------- | ---------------------------- |
| 445  | SMB     | Lateral movement, ransomware |
| 3389 | RDP     | Credential brute-force       |
| 22   | SSH     | Remote compromise            |
| 1433 | MSSQL   | Data theft                   |
| 5985 | WinRM   | Lateral movement             |

Understanding service context is critical.

---

#### 4. Reconnaissance Phase in Attack Lifecycle

In most intrusions:

1. Initial access
2. Reconnaissance (internal scanning)
3. Privilege escalation
4. Lateral movement
5. Payload deployment

Port sweep typically occurs after foothold.

---

#### 5. Normal vs Abnormal Behavior

Normal behavior:

* Vulnerability scanner (Qualys, Nessus)
* Patch management tool
* Monitoring systems

Abnormal behavior:

* Workstation scanning subnet
* DC scanning peers
* Random external IP scanning internal servers

Analyst must know asset baseline behavior.

---

## 4. Attacker Perspective

### 4.1 Why Attackers Use This Technique

Attackers perform port sweeps to:

* Identify live hosts
* Identify exposed services
* Find lateral movement paths
* Locate domain controllers
* Identify backup servers

Without scanning, attackers are blind.

---

### 4.2 What They Try to Achieve

* Map internal network
* Discover exploitable services
* Locate weak authentication services
* Prepare for credential attacks
* Identify ransomware targets

---

### 4.3 Real-World Attack Examples

1. **WannaCry (2017)**

   * Used SMB scanning on port 445
   * Rapid propagation

2. **Ryuk Ransomware**

   * Internal SMB and RDP enumeration before encryption

3. **Cobalt Strike Operators**

   * Use built-in port scan modules
   * PowerShell TCP scanning scripts

---

### 4.4 Potential Business Impact

* Lateral spread of ransomware
* Data exfiltration staging
* Domain compromise
* Service disruption
* Regulatory penalties

Port sweep may be first sign of internal compromise.

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm Hostname and User

* Map `SourceIp` to:

  * Hostname
  * Owner
  * Logged-in user
* Determine:

  * Is it server or workstation?
  * Cloud workload or on-prem?

---

### 5.2 Check Entities Criticality

* Is the source:

  * Domain Controller?
  * Jump server?
  * Security appliance?
* Are targets:

  * Critical servers?
  * Backup systems?

---

### 5.3 Verify Alert Severity

Check:

* Volume
* Port risk
* Follow-up activity
* Threat intelligence hits

Adjust severity accordingly.

---

## 6. Investigation Steps

### 6.1 Questions Analyst Should Ask

1. Is the source IP internal or external?
2. Is this expected scanner activity?
3. What port is being scanned?
4. Is scanning allowed or denied?
5. Is there follow-on suspicious activity?
6. Who owns the source system?
7. Has this host shown prior alerts?

---

### 6.2 Answer the Questions

**Internal Source?**

* High suspicion of lateral movement.

**External Source?**

* Likely internet recon.
* Check firewall action (Allowed vs Denied).

**High-risk port?**

* Escalate.

**Scanner system?**

* Validate asset tag and scheduled scan window.

---

### 6.3 Major Investigations

#### A. Correlate with Endpoint Logs

In Defender:

```
DeviceNetworkEvents
| where InitiatingProcessFileName in ("nmap.exe","powershell.exe","cmd.exe")
| where RemotePort == 445
```

Look for:

* TCP SYN flood pattern
* Sequential IP targeting

---

#### B. Check Process Tree

```
DeviceProcessEvents
| where DeviceName == "<hostname>"
| order by Timestamp desc
```

Look for:

* nmap
* masscan
* PowerShell loops
* Suspicious parent processes

---

#### C. Authentication Attempts

```
SecurityEvent
| where EventID in (4624, 4625)
| where IpAddress == "<SourceIp>"
```

Look for brute force attempts.

---

#### D. Lateral Movement

```
DeviceLogonEvents
| where RemoteIP == "<SourceIp>"
```

---

### 6.4 Minor Investigations

* Threat intel check on source IP
* Check if host is vulnerability scanner
* Check change management
* Validate firewall rule hits
* Review DNS logs for scanning patterns

---

## 7. Evidence to Collect

* Firewall logs (raw events)
* Endpoint process tree
* Netstat output
* Memory image (if compromised)
* User login history
* Scheduled tasks
* Installed tools list

---

## 8. Indicators of True Positive

* Rapid sequential IP targeting
* High-speed SYN packets
* nmap/masscan present
* PowerShell TCP scan scripts
* Followed by authentication attempts
* Followed by lateral movement
* Host shows other suspicious alerts

---

## 9. Indicators of False Positive

* Approved vulnerability scanner
* Patch management system
* Monitoring appliance
* Load balancer health checks
* Known security assessment window
* Firewall deny-only internet noise

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

* Isolate host from network
* Block outbound connections
* Disable suspicious account
* Apply firewall deny rule

---

### 10.2 Eradication

* Remove scanning tools
* Remove malware
* Patch exploited vulnerabilities
* Reset compromised credentials

---

### 10.3 Recovery

* Restore clean system image
* Rejoin to domain
* Monitor for reinfection
* Increase logging temporarily

---

## 11. Mitigation & Prevention

* Network segmentation
* East-west firewall rules
* Disable unused services
* SMB hardening
* RDP MFA enforcement
* EDR tamper protection
* Reduce local admin privileges
* Enable firewall IDS alerts

Lower threshold for high-risk ports (445, 3389).

---

## 12. Actions an IR Should Never Do (Port Sweep – In Brief)

1. **Do NOT block the Source IP immediately**
   Verify whether it is an approved vulnerability scanner, monitoring tool, or IT system before containment.

2. **Do NOT treat all external scans as breaches**
   If traffic is denied and no successful connections exist, it may be routine internet scanning.

3. **Do NOT ignore internal-to-internal sweeps**
   A workstation scanning SMB/RDP internally is high-risk and may indicate lateral movement.

4. **Do NOT close the alert without endpoint correlation**
   Always check EDR for scanning tools (nmap, PowerShell scripts) and related suspicious processes.

5. **Do NOT reboot the suspected host immediately**
   You may lose volatile evidence needed to confirm compromise.

6. **Do NOT assume high volume equals malicious intent**
   Validate against change management and scheduled security scans first.
