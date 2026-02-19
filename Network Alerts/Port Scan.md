## 1. Alert Name

**Port Scan**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects potential **port scanning activity** by identifying a single `SourceIp` communicating with **more than 100 different destination ports within 30 seconds**, grouped per `Fqdn` (destination).

### Detection Logic Breakdown

```kusto
let MinimumDifferentPortsThreshold = 100;
let BinTime = 30s;
```

* Threshold: More than **100 unique destination ports**
* Time window: **30 seconds**
* Grouping: By `SourceIp`, `TimeGenerated (30s bin)`, and `Fqdn`

The query aggregates logs from:

* `AZFWApplicationRule`
* `AZFWNetworkRule`
* `AzureDiagnostics` (Firewall logs)

It calculates:

```kusto
dcount(DestinationPort)
```

If a source IP connects to >100 distinct ports on the same FQDN/IP within 30 seconds → alert triggers.

---

### 2.1 What Triggered the Alert

The alert triggers when:

* A single **Source IP**
* Attempts connections to
* **More than 100 different ports**
* On a specific FQDN/IP
* Within **30 seconds**

Example scenario:

```
Source IP: 10.10.10.5
Destination: 172.16.1.20
Ports attempted: 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389 ... (100+ ports)
Time window: 12:00:00 – 12:00:30
```

This behavior strongly indicates automated scanning (e.g., TCP SYN scan).

---

### 2.2 Which Security Tool Generated It

* **Microsoft Azure Firewall**
* Logs ingested into **Microsoft Sentinel**
* Data sources:

  * `AZFWApplicationRule`
  * `AZFWNetworkRule`
  * `AzureDiagnostics`

Detection is firewall-log-based, not endpoint-based.

---

### 2.3 Why This Alert is Important

Port scanning is mapped to:

* MITRE ATT&CK **T1046 – Network Service Discovery**
* MITRE ATT&CK **TA0043 – Reconnaissance**

It often precedes:

* Exploitation
* Lateral movement
* Vulnerability exploitation
* Ransomware deployment

Port scanning is usually the **first technical phase after initial access**.

---

### 2.4 Define Severity? Conditions to Escalate Alert to More Severity

**Default Severity:** Medium

Escalate to **High** if:

* Source IP is internal
* Destination is Domain Controller / SQL / critical server
* Scanning followed by authentication attempts
* Scanning followed by exploitation behavior
* Source IP belongs to compromised workstation
* External IP matches threat intelligence

Escalate to **Critical** if:

* Scanning followed by:

  * Successful exploitation
  * Credential dumping
  * Lateral movement
  * Malware execution

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts Analyst Must Understand

#### 1. Port Scanning Types

| Type              | Description                 | Detection Characteristics    |
| ----------------- | --------------------------- | ---------------------------- |
| TCP SYN Scan      | Half-open scan              | Many SYNs, no full handshake |
| TCP Connect Scan  | Full connection             | Completed handshakes         |
| UDP Scan          | No handshake                | Harder to detect             |
| Stealth/Slow Scan | Low & slow                  | Spread across time           |
| Vertical Scan     | Many ports on 1 host        | This alert                   |
| Horizontal Scan   | Same port across many hosts | Different detection          |

This alert detects **vertical scan**.

---

#### 2. Azure Firewall Log Tables

**AZFWApplicationRule**

* Logs application-layer traffic
* Includes FQDN filtering

**AZFWNetworkRule**

* Layer 3/4 traffic
* Raw IP and port connections

**AzureDiagnostics**

* Legacy diagnostic logs
* Requires parsing (`parse msg_s`)

---

#### 3. dcount()

`dcount()` calculates approximate distinct count.

It detects **unique ports**, not number of attempts.

Example:

* 500 attempts to port 80 → NOT triggered
* 1 attempt each to 101 ports → Triggered

---

#### 4. Time Binning (`bin(TimeGenerated, 30s)`)

Events grouped in fixed 30-second buckets.

Attacker using:

* 1 port per second → 30 ports → No alert
* 4 ports per second → 120 ports → Alert

---

#### 5. Firewall vs Endpoint Visibility

Firewall logs:

* Show network connections
* Do NOT show process names
* Do NOT show user context

You must pivot to:

* EDR logs
* Sign-in logs
* VM logs

---

## 4. Attacker Perspective

### 4.1 Why Attackers Use This Technique

* Identify exposed services
* Identify outdated services
* Map network attack surface
* Identify lateral movement paths

---

### 4.2 What They Try to Achieve

* Find open RDP (3389)
* Find SMB (445)
* Find database ports (1433, 3306)
* Identify vulnerable services

---

### 4.3 Real-World Attack Examples

* **WannaCry** exploited open SMB 445.
* **NotPetya** spread via lateral movement.
* **FIN7** performs internal reconnaissance before privilege escalation.

Most ransomware operators perform aggressive internal scanning post-initial access.

---

### 4.4 Potential Business Impact

* Data breach
* Ransomware deployment
* Domain compromise
* Regulatory fines
* Production outage

If attacker finds:

* Open RDP → brute force
* Open SMB → exploitation
* Open SQL → data exfiltration

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm Hostname and User

* Is Source IP internal or external?
* Map IP to hostname
* Identify logged-in user
* Check if it’s server, workstation, or network device

---

### 5.2 Check Entities Criticality

* Is destination a:

  * Domain Controller?
  * Production database?
  * Internet-facing server?
  * Azure VM hosting business app?

---

### 5.3 Verify Alert Severity

* Number of ports scanned
* Frequency
* Any post-scan suspicious behavior
* TI match?

---

## 6. Investigation Steps

### 6.1 Questions Analyst Should Ask

1. Is source internal or external?
2. Is scanning automated?
3. Is this vulnerability scanner?
4. Is this red team activity?
5. Is this followed by authentication attempts?
6. Was exploitation attempted?
7. Has this source shown suspicious behavior before?

---

### 6.2 Answer the Questions

#### Q1: Internal or External?

If external:

* Likely internet scanning
* Check if blocked by firewall

If internal:

* Higher concern
* Possible compromised host

---

#### Q2: Is it Automated?

Indicators:

* Sequential port attempts
* Rapid timing
* TCP SYN patterns

---

#### Q3: Is it Legitimate Scanner?

Check:

* Does IP belong to:

  * Nessus?
  * Qualys?
  * Azure Defender?
  * Internal vulnerability scanner?

If yes → validate change ticket.

---

#### Q4: Followed by Exploitation?

Query:

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where IpAddress == "<SourceIP>"
```

Look for:

* Failed logons
* Service installs
* Suspicious PowerShell
* LSASS dump attempts

---

## 6.3 Major Investigations

1. Pivot to EDR:

   * Identify process generating traffic
   * Example:

   ```kusto
   DeviceNetworkEvents
   | where RemoteIP == "<DestinationIP>"
   ```

2. Check for lateral movement:

   * 445 connections?
   * 3389 connections?

3. Check process ancestry:

   * cmd.exe?
   * powershell.exe?
   * nmap.exe?
   * Unknown binary?

4. Check for exploitation tools:

   * Metasploit
   * nmap
   * masscan

5. Timeline correlation:

   * Scan → exploit → credential theft → lateral movement?

---

## 6.4 Minor Investigations

* Geo-location of external IP
* ASN lookup
* Threat intelligence match
* Historical activity from same IP
* Check maintenance window

---

## 7. Evidence to Collect

* Firewall logs (raw)
* EDR process logs
* User session logs
* Authentication logs
* Network packet captures (if available)
* Threat intelligence results

---

## 8. Indicators of True Positive

* Internal workstation scanning DC
* Unknown process generating scan
* No vulnerability scan ticket
* Follow-up exploitation attempts
* Same source performing credential dumping
* High-speed port enumeration pattern

---

## 9. Indicators of False Positive

* Approved vulnerability scan
* Red team exercise
* IT troubleshooting activity
* Known network monitoring system
* Security assessment window

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

* Isolate affected host
* Block Source IP at firewall
* Disable user account if compromised
* Restrict lateral movement

---

### 10.2 Eradication

* Remove malware
* Patch exploited services
* Reset credentials
* Re-image if necessary

---

### 10.3 Recovery

* Restore affected systems
* Monitor for re-scan
* Deploy EDR containment rules
* Validate no persistence remains

---

## 11. Mitigation & Prevention

* Enable network segmentation
* Restrict east-west traffic
* Deploy internal IDS/IPS
* Harden firewall rules
* Disable unused ports
* Enable just-in-time access
* Implement Zero Trust

---
## Actions an IR Should **Never** Do – Port Scan Alert

1. **Never block the source immediately** without confirming if it’s legitimate (vulnerability scanner, red team, IT activity).
2. **Never ignore internal scanning** — internal-to-internal scans are high risk and often indicate compromise.
3. **Never close as “just reconnaissance”** without checking for post-scan exploitation (RDP, SMB, brute force, PowerShell).
4. **Never kill processes or reboot the host before collecting evidence** (process tree, command line, network logs).
5. **Never rely only on firewall logs** — pivot to EDR, authentication logs, and endpoint telemetry.
6. **Never contact the user prematurely** — you may alert a real attacker.
7. **Never assume it’s a false positive without change validation** (ticket, maintenance window).
8. **Never overreact by shutting down production systems without coordination.**

Port scans are often the first step before lateral movement or ransomware — treat them carefully, not casually.

