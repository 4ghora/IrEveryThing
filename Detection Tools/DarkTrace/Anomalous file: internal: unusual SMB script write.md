## 1. Alert Name

**Anomalous file: internal: unusual SMB script write**

---

## 2. Alert Description (Detection Logic Explanation)

### 2.1 What Triggered the Alert

This alert is typically triggered by **behavioral anomaly detection** at the **SMB protocol level**, specifically when:

* A host writes a **script file** (e.g., `.ps1`, `.vbs`, `.js`, `.bat`, `.cmd`) over SMB.
* The write activity deviates from historical baseline behavior for:

  * The source device
  * The destination share
  * The file type
  * Time-of-day access pattern
* The write occurs to:

  * Administrative shares (`ADMIN$`, `C$`, `IPC$`)
  * SYSVOL/NETLOGON
  * Unusual internal file servers
  * Peer workstations (lateral movement pattern)

**Detection Layers:**

* **Flow-level**: Abnormal SMB session volume or rare peer-to-peer SMB communication.
* **Protocol-level**: SMB2/SMB3 `WRITE` requests for script-like filenames.
* **Payload-level (metadata)**: File extension pattern, entropy anomalies, suspicious file naming conventions.

**Example Trigger Scenario:**

* Endpoint A (user workstation) connects via SMB to Endpoint B.
* Writes `update.ps1` to `\\EndpointB\C$\Windows\Temp\`
* This workstation has never previously performed administrative SMB writes.
* Darktrace’s behavioral model flags it as anomalous.

---

### 2.2 Which Security Tool Generated It

The alert originates from **Darktrace**, a behavioral AI-based NDR platform.

Darktrace uses:

* Self-learning baselines
* Peer group analysis
* Protocol metadata inspection
* Internal traffic modeling

It does not rely solely on signatures; it uses **unsupervised machine learning models** to detect deviation from established norms.

---

### 2.3 Why This Alert Is Important (Network Security Perspective)

SMB-based script writes internally are strongly correlated with:

* **Lateral Movement (MITRE T1021.002 – SMB/Windows Admin Shares)**
* **Remote Service Execution**
* **Ransomware Propagation**
* **Worm-like spread**
* **Living-off-the-Land attacks**
* **Persistence via Startup folder writes**
* **Domain-wide script deployment abuse**

Internal SMB is highly trusted traffic. Attackers exploit this trust to:

* Blend in
* Avoid perimeter controls
* Move laterally after initial compromise

SMB write anomalies are frequently seen during:

* Cobalt Strike lateral staging
* PsExec-based movement
* Ransomware pre-encryption spread phase

---

### 2.4 Severity Assessment & Escalation Criteria

**Default Severity:** Medium–High

Escalate to **High/Critical** if:

* Script written to:

  * Domain Controllers
  * Critical servers
  * Backup infrastructure
* Concurrent authentication anomalies (Event 4624 Type 3 bursts)
* Rapid SMB connections to multiple hosts
* Known ransomware patterns
* SMB write followed by:

  * Service creation
  * Scheduled task creation
  * Remote process execution
* Communication to external C2 after SMB write

---

## 3. Knowledge Required Before Investigation

### 3.1 SMB Protocol Deep Understanding

An analyst must understand:

### A. SMB (Server Message Block)

SMB is an application-layer protocol operating over:

* TCP 445 (Direct SMB)
* TCP 139 (NetBIOS session service)

It enables:

* File sharing
* Printer access
* Remote execution via admin shares
* Named pipes communication

---

### B. SMB2/SMB3 Operation Flow

Typical SMB write sequence:

1. `NEGOTIATE`
2. `SESSION_SETUP`
3. `TREE_CONNECT`
4. `CREATE`
5. `WRITE`
6. `CLOSE`

The alert likely involves anomalous `CREATE` + `WRITE` commands for script extensions.

Example:

```
SMB2 CREATE Request File: \Windows\Temp\stage.ps1
SMB2 WRITE Request Length: 14523 bytes
```

---

### C. Administrative Shares

Default hidden shares:

* `C$`
* `ADMIN$`
* `IPC$`

Attackers abuse these for remote file staging.

Example lateral movement pattern:

```
Source → TCP 445 → Target C$
Write payload.ps1
Execute via:
- WMI
- Service creation
- Scheduled task
```

---

### D. Script File Types Common in Attacks

* `.ps1` – PowerShell stagers
* `.vbs` – VBScript droppers
* `.js` – Windows Script Host payloads
* `.bat/.cmd` – Execution wrappers

These are often:

* Encoded
* Obfuscated
* High entropy
* Short-lived

---

### E. Windows Authentication Over SMB

SMB uses:

* NTLM
* Kerberos

Key points:

* NTLM may indicate credential reuse.
* Kerberos from abnormal hosts could suggest ticket theft.

---

### F. Typical Legitimate SMB Script Writes

Legitimate cases include:

* IT pushing login scripts
* SCCM deployments
* Software distribution tools
* Backup agents

Analyst must differentiate:

| Legitimate                  | Malicious                |
| --------------------------- | ------------------------ |
| Scheduled deployment window | Random time              |
| Known service account       | User workstation account |
| Central management server   | Peer workstation         |
| Consistent pattern          | Sudden burst             |

---

## 4. Attacker Perspective

### 4.1 Why Attackers Use SMB Script Writes

SMB is:

* Native to Windows
* Trusted internally
* Rarely blocked internally
* Highly flexible for file staging

It avoids:

* Egress monitoring
* Proxy logging
* Firewall detection

---

### 4.2 What They Try to Achieve

Primary Objectives:

* **Lateral Movement**
* **Remote Code Execution**
* **Ransomware Spread**
* **Credential Harvesting tools deployment**
* **Persistence via startup folder scripts**

---

### 4.3 Real-World Examples

* **WannaCry** – spread via SMB exploitation.
* **NotPetya** – used SMB + credential reuse for propagation.
* **Ryuk** – staged binaries via admin shares.
* **Cobalt Strike** – lateral movement using SMB beacons and service creation.

---

### 4.4 Potential Business Impact

* Domain-wide ransomware
* Data destruction
* Lateral privilege escalation
* Business outage
* Regulatory breach

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm Network Entities

* Source IP
* Destination IP
* MAC address
* Hostname (DHCP logs)
* Logged-in user
* AD OU membership
* Asset criticality

---

### 5.2 Network Segment & Direction

* Internal-to-Internal?
* Workstation-to-Server?
* Workstation-to-Workstation?
* Is target a Domain Controller?
* Is source in PCI/CDE?

---

### 5.3 Correlation Check

* Multiple SMB alerts?
* Kerberos anomalies?
* NTLM brute force?
* EDR alerts?
* DNS anomalies?

---

## 6. Investigation Steps

### 6.1 Key Questions Analyst Must Ask

1. Is this host authorized to write scripts via SMB?
2. Is the destination a high-value asset?
3. Was the file executed after being written?
4. Are there lateral movement patterns?
5. Is there credential misuse?
6. Is this part of a larger campaign?

---

### 6.2 Answers & Analysis Logic

**Q1:** Check historical SMB activity baseline.
If rare → suspicious.

**Q2:** If destination = DC or file server → high severity.

**Q3:** Check:

* Windows Event 7045 (service creation)
* 4698 (scheduled task)
* 4688 (process creation)

**Q4:** Check multiple hosts receiving similar writes.

**Q5:** Check if NTLM authentication used from workstation.

**Q6:** Review 24–48 hour timeline.

---

### 6.3 Major Investigations

* Full PCAP reconstruction of SMB session
* Extract file (if possible)
* Hash calculation
* Sandbox detonation
* Check file entropy
* Check filename patterns
* Correlate with authentication logs
* Check for subsequent outbound C2 traffic

---

### 6.4 Minor Investigations

* User behavior review
* Change management validation
* Patch cycle verification
* Check IT automation tools

---

## 7. Evidence to Collect

* Full PCAP
* SMB metadata logs
* NetFlow records
* Windows Event Logs:

  * 4624
  * 4672
  * 4688
  * 7045
* File hash (SHA256)
* EDR telemetry
* Authentication logs
* DHCP logs

---

## 8. Indicators of True Positive

* Script written to multiple hosts rapidly
* Admin share usage from workstation
* Encoded PowerShell content
* Unusual time-of-day
* Follow-up service creation
* Concurrent privilege escalation
* Communication to external suspicious IPs

---

## 9. Indicators of False Positive

* SCCM deployment window
* Patch management script rollout
* Known IT service account
* Scheduled backup process
* Documented change ticket

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

* Isolate source host (EDR network containment)
* Disable compromised account
* Block SMB from source at NAC/Firewall
* Monitor other hosts for similar writes

---

### 10.2 Eradication

* Remove malicious files
* Reimage compromised endpoints
* Reset credentials (especially privileged)
* Remove persistence mechanisms

---

### 10.3 Recovery

* Restore from clean backups
* Validate no reinfection
* Monitor SMB activity intensively for 72 hours

---

## 11. Mitigation & Prevention

* Disable SMBv1
* Restrict admin share access
* Implement SMB signing
* Lateral movement detection policies
* Segmentation between workstations
* Block workstation-to-workstation SMB
* Enforce least privilege
* Monitor write operations to admin shares

---

## 12. Actions an IR Should Never Do (In Context of This Alert)

* Do NOT immediately delete the script before forensic capture.
* Do NOT reboot the machine before memory capture.
* Do NOT assume internal SMB is safe.
* Do NOT close the alert without checking lateral spread.
* Do NOT rely only on endpoint telemetry — verify network evidence.
* Do NOT notify user prematurely before investigation.

---