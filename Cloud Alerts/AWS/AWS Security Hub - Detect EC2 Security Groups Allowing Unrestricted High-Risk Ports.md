## 1. Alert Name

**AWS Security Hub - Detect EC2 Security Groups Allowing Unrestricted High-Risk Ports**

---

## 2. Alert Description (Detection Logic Explanation)

### 2.1 What triggered the alert

This alert is triggered when:

* A finding in **ACTIVE** state
* Compliance status = **FAILED**
* Control ID = **EC2.19**
* Resource type = `AwsEc2SecurityGroup`
* One or more **high-risk ports** are exposed
* Source CIDR = `0.0.0.0/0` or `::/0` (Internet-wide access)

The query specifically checks for inbound rules where:

```kql
toint(Perm.FromPort) in (HighRiskPorts)
```

And where:

```kql
Range.CidrIp in ("0.0.0.0/0", "::/0")
```

### Example Trigger Scenario

A security group has:

* Port 3389 open
* Source: 0.0.0.0/0

This means **RDP is exposed to the entire internet**, triggering EC2.19 compliance failure.

High-risk ports monitored include:

* 22 (SSH)
* 3389 (RDP)
* 445 (SMB)
* 3306 (MySQL)
* 5432 (PostgreSQL)
* 1433 (MSSQL)
* 9200 (Elasticsearch)
* 25 (SMTP)
* 21 (FTP)
* 23 (Telnet)
* 8080/8888/3000 (Web/App services)
* etc.

---

### 2.2 Which security tool generated it

The alert originates from:

AWS Security Hub

Specifically from security control:

**EC2.19 — Security groups should not allow unrestricted access to high-risk ports**

Security Hub aggregates findings from:

* AWS Config
* AWS Foundational Security Best Practices (FSBP)
* Other integrated services

---

### 2.3 Why this alert is important

Security groups are **stateful firewalls** at the instance level.

When high-risk ports are open to `0.0.0.0/0`:

* Any internet host can connect
* Automated scanners continuously probe these ports
* Attackers can brute-force, exploit CVEs, or deploy malware

This is one of the **top cloud misconfigurations leading to breaches**.

Maps to MITRE ATT&CK:

* T1190 – Exploit Public-Facing Application
* T1133 – External Remote Services
* T1110 – Brute Force
* T1021 – Remote Services

---

### 2.4 Define Severity? Conditions to escalate alert to more severity

**Default Severity: Medium–High**

Escalate to HIGH or CRITICAL if:

* Port 22 or 3389 open publicly
* Associated instance has public IP
* Instance hosts production workloads
* Instance tagged as critical asset
* Repeated failed login attempts seen
* Known CVE vulnerability exists on exposed service
* Port 445, 1433, 9200 exposed publicly

Escalate to CRITICAL if:

* Signs of exploitation detected
* Known ransomware TTPs observed
* Lateral movement suspected

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts Analyst Must Understand

#### 1. AWS Security Groups

* Stateful virtual firewall
* Applied at ENI/instance level
* Control inbound and outbound traffic
* Rule structure:

  * Protocol
  * Port range
  * Source CIDR

Example:

```
TCP 3389
Source: 0.0.0.0/0
```

This means any IP globally can connect to RDP.

---

#### 2. CIDR Notation

* `0.0.0.0/0` → Entire IPv4 internet
* `::/0` → Entire IPv6 internet
* `10.0.0.0/8` → Internal private network

Understanding CIDR is critical to evaluate exposure.

---

#### 3. High-Risk Ports and Their Services

| Port | Service       | Risk                             |
| ---- | ------------- | -------------------------------- |
| 22   | SSH           | Brute force, credential stuffing |
| 3389 | RDP           | Ransomware entry vector          |
| 445  | SMB           | Worm propagation                 |
| 1433 | MSSQL         | Database exploitation            |
| 9200 | Elasticsearch | Data theft                       |
| 25   | SMTP          | Spam relay abuse                 |

Analyst must know:

* Which ports should NEVER be internet-exposed
* Which may be legitimate (e.g., 443 web server)

---

#### 4. Public vs Private EC2 Instances

An open security group does not automatically mean exposure.

Exposure exists when:

* Instance has Public IP
* Elastic IP attached
* NAT or Internet Gateway route exists

Understanding VPC routing is essential.

---

#### 5. AWS Security Hub Control EC2.19

This control checks:

* High-risk ports
* Public exposure
* Compliance baseline

Failure indicates deviation from AWS best practices.

---

#### 6. MITRE ATT&CK Mapping in Cloud Context

Common mappings:

* T1190 – Exploit Public-Facing Application
* T1133 – External Remote Services
* T1021.004 – SSH
* T1021.001 – RDP
* T1110 – Brute Force

Analyst must understand how cloud exposure maps to attack techniques.

---

## 4. Attacker Perspective

### 4.1 Why attackers use this technique

Attackers continuously scan the internet for:

* Open SSH (22)
* Open RDP (3389)
* Open DB ports (3306, 5432, 1433)
* Open Elasticsearch (9200)

Misconfigurations are easier to exploit than zero-days.

---

### 4.2 What they try to achieve

* Initial Access
* Credential harvesting
* Ransomware deployment
* Crypto mining
* Data exfiltration
* Botnet recruitment

---

### 4.3 Tools/Commands Attackers Use

Scanning:

* masscan
* nmap

Brute force:

* Hydra
* Crowbar

Exploitation:

* Metasploit
* SQL exploitation frameworks

Cloud exploitation:

* Enumerate IAM role credentials from metadata
* Pivot inside VPC

---

### 4.4 Real-World Attack Examples

1. Elasticsearch exposed (9200):

   * Attackers wiped indices
   * Left ransom notes

2. RDP exposed (3389):

   * Brute force
   * Deployed ransomware
   * Disabled backups

3. MSSQL open (1433):

   * xp_cmdshell execution
   * Malware deployment

---

### 4.5 Potential Business Impact

* Full infrastructure compromise
* Data breach
* Regulatory penalties
* Ransomware downtime
* Cloud resource abuse (crypto mining costs)

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm hostname and user

* Identify EC2 instance(s) attached to SG
* Check instance name, tags
* Identify owner via tagging
* Check IAM role attached

---

### 5.2 Check entity criticality

* Is instance production?
* Is it database?
* Is it domain controller equivalent?
* Is it internet-facing application?

---

### 5.3 Verify alert severity

* Which ports exposed?
* Public IP assigned?
* External traffic seen?
* Historical login attempts?

---

## 6. Investigation Steps

### 6.1 Questions Analyst Should Ask

1. Is the instance actually internet-exposed?
2. Is this intentional business configuration?
3. Is there suspicious traffic to exposed port?
4. Has brute force occurred?
5. Has exploitation occurred?
6. Is lateral movement happening?

---

### 6.2 Answer the Questions

#### Check Exposure

AWS CLI:

```
aws ec2 describe-instances
```

Verify:

* PublicIpAddress
* Subnet route table
* Internet Gateway association

---

#### Check VPC Flow Logs

Query:

```
filter dstPort=3389
```

Look for:

* High connection attempts
* Multiple source IPs
* Repeated SYN attempts

---

#### Check OS Logs (EDR)

Linux:

* /var/log/auth.log
* Failed SSH attempts

Windows:

* Event ID 4625
* Event ID 4624
* RDP logon events

---

### 6.3 Major Investigations (Important)

1. Confirm instance exposure
2. Analyze VPC Flow Logs
3. Review CloudTrail for security group modifications
4. Check IAM activity around rule change
5. Inspect instance for compromise indicators
6. Review GuardDuty findings

---

### 6.4 Minor Investigations (Related)

* Check vulnerability scan results
* Check patch level
* Validate key-based SSH enforcement
* Confirm MFA enforcement
* Verify if rule change was temporary

---

## 7. Evidence to Collect

* Security group configuration (JSON export)
* CloudTrail logs
* VPC Flow Logs
* OS authentication logs
* EDR telemetry
* GuardDuty findings
* Instance snapshot (if needed)

---

## 8. Indicators of True Positive

* High inbound scan activity
* Brute force attempts detected
* Successful login from unknown IP
* Malware detected
* Suspicious outbound connections
* Unauthorized SG modification

---

## 9. Indicators of False Positive

* Bastion host intentionally exposed
* Port restricted to corporate IP range (not 0.0.0.0/0)
* Temporary rule during maintenance
* WAF/proxy in front of service
* Port open but instance has no public IP

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

* Remove `0.0.0.0/0` rule immediately
* Restrict to known IP ranges
* Isolate instance
* Remove public IP
* Rotate credentials

---

### 10.2 Eradication

* Patch vulnerable services
* Remove malware
* Reset passwords
* Rotate IAM credentials
* Disable compromised accounts

---

### 10.3 Recovery

* Restore from clean AMI
* Validate configuration baseline
* Re-enable traffic with restrictions
* Monitor aggressively

---

## 11. Mitigation & Prevention

* Use bastion hosts
* Use VPN access
* Enforce least privilege CIDR
* Use AWS Firewall Manager
* Enable GuardDuty
* Enable Config rules
* Automate remediation via Lambda
* Use Security Hub auto-remediation

---

## 12. Actions an IR Should Never Do

* Never delete security group without capturing evidence
* Never modify instance before collecting logs
* Never assume exposure = compromise
* Never ignore repeated brute force
* Never publicly expose database ports
* Never rotate credentials before capturing forensic evidence

---