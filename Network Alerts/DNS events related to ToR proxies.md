## 1. Alert Name

**DNS events related to ToR proxies**

---

## 2. Alert Description (Detection Logic Explanation)

### 2.1 What triggered the alert

The query monitors the `DnsEvents` table and filters DNS requests where the queried domain (`Name`) contains known **Tor-to-Web proxy domains** such as:

* `tor2web.org`
* `onion.to`
* `onion.link`
* `tor2web.io`
* `hiddenservice.net`
* `s1.tor-gateways.de`, etc.

Example trigger scenario:

* A user workstation queries:
  `examplehiddenservice.onion.link`
* The DNS request appears in `DnsEvents`
* The domain matches the `has_any()` list of Tor proxy services
* Alert is generated.

Detection logic:

```kusto
DnsEvents
| where Name has_any ("tor2web.org", "onion.to", ...)
```

The query also extracts:

* `HostName` → machine name
* `DnsDomain` → domain of the host

This detection does **not detect native Tor (.onion) traffic**, but detects attempts to access hidden services via **Tor2Web gateways** (clear-web proxies).

---

### 2.2 Which security tool generated it

Typically generated in:

* Microsoft Defender for Endpoint (MDE)
* Microsoft Sentinel (custom analytic rule)
* Any SIEM ingesting DNS logs

Data source:

* Endpoint DNS telemetry
* DNS server logs
* Defender `DnsEvents` table

---

### 2.3 Why this alert is important

Tor proxy domains are commonly used for:

* Command & Control (C2) infrastructure
* Data exfiltration
* Malware payload hosting
* Ransomware negotiation portals
* Access to underground markets

MITRE ATT&CK Mapping:

* **T1090.003 – Proxy: Multi-hop Proxy**
* **T1071.004 – Application Layer Protocol: DNS**
* **T1568.003 – Dynamic Resolution: DNS**

Accessing Tor2Web domains may indicate:

* Malware beaconing
* User attempting anonymous browsing
* Insider threat activity
* Compromised host staging exfiltration

---

### 2.4 Define Severity? Conditions to escalate alert to more severity

**Default Severity: Medium**

Escalate to **High/Critical** if:

* Host is a Domain Controller, server, or privileged admin workstation
* DNS activity correlates with:

  * Suspicious PowerShell activity
  * LSASS access
  * Credential dumping
  * Data compression followed by outbound traffic
* Repeated DNS lookups to multiple Tor gateways
* EDR shows suspicious parent process (e.g., `powershell.exe`, `wscript.exe`)
* Traffic occurs after phishing alert

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts analyst must understand about the entities in alert

#### 1. Tor Network Architecture

Tor (The Onion Router) is an anonymity network that routes traffic through multiple encrypted relay nodes.

* Entry Node
* Middle Node
* Exit Node
* Hidden Services (.onion)

Normal Tor requires Tor client software.

However, Tor2Web allows access to `.onion` sites **without Tor software**, via public HTTP gateways like:

```
malicioussite.onion.link
```

These services act as **reverse proxies** between clearnet and Tor.

---

#### 2. Tor2Web Gateways

Tor2Web domains convert:

```
examplehidden.onion
```

Into:

```
examplehidden.onion.link
```

Attackers use these because:

* Corporate networks often block Tor protocol
* DNS filtering might miss proxy domains
* Works via standard HTTPS (port 443)

From defender perspective:
DNS logs will show normal domain resolution.

---

#### 3. DNS Telemetry in Endpoint vs DNS Server Logs

Analyst must understand:

* `DnsEvents` from endpoint show **device-level queries**
* DNS server logs show network-level queries
* Browser may use DoH (DNS over HTTPS), bypassing local DNS logs

Limitations:

* If attacker uses DoH, this alert may not trigger
* If Tor client is installed, DNS may not resolve via standard DNS

---

#### 4. Command and Control via Tor

Modern malware families use Tor:

* Ransomware (e.g., negotiation portals)
* TrickBot
* QakBot
* Cobalt Strike over Tor

Advantages for attacker:

* Hides backend infrastructure
* Makes takedown difficult
* Obfuscates IP address of C2

---

#### 5. DNS-based C2 Patterns

Analyst must recognize:

* High-frequency DNS lookups
* Long randomized subdomains
* Repeated failed DNS queries
* Queries from system processes

Example suspicious pattern:

```
abc123xyz.onion.link
def456uvw.onion.link
```

---

## 4. Attacker Perspective

### 4.1 Why attackers use this technique

* Avoid IP-based blocking
* Hide real C2 servers
* Maintain anonymity
* Host malicious payloads anonymously
* Operate ransomware portals

---

### 4.2 What they try to achieve

* Establish encrypted C2 channel
* Exfiltrate sensitive data anonymously
* Download second-stage malware
* Communicate with botnet infrastructure

---

### 4.3 Real-world attack examples

* **Conti Ransomware** used Tor-based negotiation sites
* **Ryuk operators** hosted data leak portals over Tor
* **Emotet** leveraged Tor for resilient C2
* Various APT groups use Tor bridges for covert channels

---

### 4.4 Potential Business Impact

* Data exfiltration
* Ransomware deployment
* Credential theft
* Regulatory non-compliance
* Lateral movement staging
* Reputation damage

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm hostname and user

* Identify device owner
* Identify logged-in user
* Check if system is shared or kiosk

### 5.2 Check entities criticality

* Is this:

  * Domain Controller?
  * Server?
  * Finance workstation?
  * Privileged admin endpoint?

### 5.3 Verify alert severity

* Is it single query or repeated?
* Any correlated suspicious alerts?
* Was user browsing intentionally?

---

## 6. Investigation Steps

### 6.1 What questions should an analyst ask himself while investigating alert?

1. Is this user-initiated browsing or automated malware?
2. What process generated the DNS request?
3. Is there outbound traffic to resolved IP?
4. Is there correlated suspicious activity?
5. Has this host shown prior compromise indicators?

---

### 6.2 Answer the questions

**1. User or malware?**
Check initiating process.

```kusto
DeviceNetworkEvents
| where RemoteUrl has_any ("onion.link","tor2web")
```

Check parent process chain.

---

**2. Which process made the request?**

```kusto
DnsEvents
| where Name has_any ("onion.link","tor2web")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

Red flags:

* powershell.exe
* rundll32.exe
* wscript.exe
* mshta.exe

---

**3. Was connection established?**

```kusto
DeviceNetworkEvents
| where RemoteUrl has_any ("onion")
| summarize count(), sum(SentBytes)
```

Look for:

* Data upload
* Repeated connections

---

**4. Any suspicious process activity?**

```kusto
DeviceProcessEvents
| where DeviceName == "<affected host>"
| where Timestamp between (alert_time-30m .. alert_time+30m)
```

Look for:

* Encoded PowerShell
* Suspicious child processes
* Credential dumping tools

---

### 6.3 Major Investigations (Important Investigation steps)

1. Process Tree Analysis
2. Outbound traffic volume analysis
3. Correlation with EDR alerts
4. Check for persistence mechanisms
5. Credential access attempts
6. Lateral movement attempts

---

### 6.4 Minor Investigations (Related Investigation steps)

* Browser history check
* User interview
* Proxy logs
* Check if domain is blocked in firewall
* Check threat intel reputation

---

## 7. Evidence to Collect

* DNS query logs
* Full process tree
* Memory dump (if suspicious)
* Network flow logs
* EDR timeline
* User login history
* Browser artifacts
* Firewall/proxy logs

---

## 8. Indicators of True Positive

* DNS queries initiated by PowerShell or script engine
* Repeated beaconing pattern
* Data upload spikes
* Correlated malware alerts
* Persistence found
* Credential dumping detected
* Lateral movement observed

---

## 9. Indicators of False Positive

* User manually browsing security research content
* Security team testing Tor access
* Threat research lab machine
* Single DNS query with no follow-up traffic
* Blocked by DNS sinkhole with no connection attempt

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

* Isolate endpoint from network
* Block domain at DNS and firewall
* Disable affected user account (if suspicious)
* Revoke active tokens

---

### 10.2 Eradication

* Remove malware
* Delete persistence mechanisms
* Reset credentials
* Reimage system (if high confidence compromise)

---

### 10.3 Recovery

* Restore from clean backup
* Monitor for re-infection
* Validate domain controller integrity
* Re-enable user after password reset

---

## 11. Mitigation & Prevention

* DNS filtering
* Block Tor exit nodes
* Disable unauthorized software installation
* Implement EDR with network telemetry
* Enable DNS logging enterprise-wide
* Implement Zero Trust model
* Restrict PowerShell execution policies
* Monitor outbound encrypted traffic anomalies

---

## 12. Actions an IR Should Never Do (In Context of Alert)

* Do NOT assume Tor = malicious without context
* Do NOT immediately reimage without evidence collection
* Do NOT ignore single DNS events without correlation
* Do NOT alert user prematurely (may tip attacker)
* Do NOT block domains before confirming scope
* Do NOT reset credentials without checking lateral spread
* Do NOT close as false positive without checking process origin

---
