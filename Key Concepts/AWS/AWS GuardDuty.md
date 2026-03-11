# 1. What It Is

* **Managed threat detection service** in Amazon Web Services that continuously monitors AWS accounts for malicious or unauthorized activity.
* Uses **machine learning, anomaly detection, and threat intelligence feeds** to identify suspicious behavior.
* Analyzes multiple AWS telemetry sources without requiring agents.
* Primary data sources include:

  * **AWS CloudTrail**
  * **Amazon VPC Flow Logs**
  * **AWS DNS Logs**
  * **Amazon EKS Audit Logs**
* Generates **GuardDuty Findings** which can be forwarded to SIEM platforms (e.g., Splunk, Sentinel, QRadar).

---

# 2. Legitimate Use

* **Managed threat monitoring** for AWS accounts without deploying IDS sensors.
* Detects **credential abuse, compromised EC2 instances, crypto mining, and reconnaissance**.
* Helps SOC teams monitor **API activity, unusual network traffic, and suspicious DNS queries**.
* Integrated with:

  * **AWS Security Hub**
  * **Amazon EventBridge**
* Common enterprise uses:

  * Continuous threat monitoring across **multi-account AWS environments**
  * Security visibility for **DevOps workloads**
  * Feeding findings into **SIEM/SOAR pipelines**

---

# 3. Attacker Abuse

Attackers **don’t directly “abuse” GuardDuty**, but their activities generate findings. However they often attempt to **evade or disable it**.

### Common Attack Scenarios

* **Compromised IAM credentials**

  * Used to enumerate AWS resources.
  * GuardDuty detects unusual API usage.
  * MITRE:

    * T1078
    * T1087

* **EC2 instance compromise**

  * Reverse shells or botnet activity.
  * GuardDuty detects connections to **known malicious IPs**.
  * MITRE:

    * T1105

* **Crypto mining**

  * Malware deployed on EC2 instances.
  * GuardDuty detects mining pools.
  * MITRE:

    * T1496

* **Data exfiltration from S3**

  * Access from unusual geolocation or anonymous sources.
  * MITRE:

    * T1537

* **Defense evasion**

  * Disabling GuardDuty or modifying detectors.
  * MITRE:

    * T1562

---

# 4. SIEM Detection Opportunities

Even though GuardDuty generates findings itself, SOC teams should also detect **suspicious interactions with GuardDuty and high-risk findings**.

---

### Alert 1: GuardDuty Disabled

**Suspicious Behavior**

* GuardDuty detector is disabled or deleted.
* Common attacker defense evasion technique after gaining AWS access.

**Example Detection Logic**

```
eventSource = guardduty.amazonaws.com
AND eventName IN ("DeleteDetector","UpdateDetector")
AND requestParameters.enable = false
```

**Relevant Log Sources**

* CloudTrail
* SIEM ingestion pipeline

---

### Alert 2: High-Severity GuardDuty Finding

**Suspicious Behavior**

* GuardDuty generates a **HIGH severity finding** such as:

  * Credential compromise
  * Crypto mining
  * EC2 backdoor communication.

**Example Detection Logic**

```
source = guardduty
severity >= 7
```

**Relevant Log Sources**

* GuardDuty findings
* Security Hub
* EventBridge

---

### Alert 3: IAM Credential Exfiltration Detected

**Suspicious Behavior**

* GuardDuty finding indicates AWS credentials used from suspicious IP or TOR network.

**Example Detection Logic**

```
finding.type = UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
```

**Relevant Log Sources**

* GuardDuty Findings
* CloudTrail

---

### Alert 4: EC2 Instance Communicating with Known C2

**Suspicious Behavior**

* EC2 instance connects to known command-and-control infrastructure.

**Example Detection Logic**

```
finding.type = Backdoor:EC2/C&CActivity.B!DNS
OR finding.type = Trojan:EC2/DNSDataExfiltration
```

**Relevant Log Sources**

* GuardDuty Findings
* VPC Flow Logs
* DNS Logs

---

### Alert 5: Crypto Mining Activity Detected

**Suspicious Behavior**

* GuardDuty identifies EC2 instance communicating with crypto mining pool.

**Example Detection Logic**

```
finding.type = CryptoCurrency:EC2/BitcoinTool.B!
```

**Relevant Log Sources**

* GuardDuty findings
* VPC Flow Logs
* EDR telemetry

---

# 5. Investigation Indicators

SOC analysts should review the following artifacts when investigating GuardDuty alerts:

* **Affected AWS resource**

  * EC2 instance ID
  * IAM user
  * Access key ID
* **Source IP and geolocation anomalies**

  * New country
  * Known TOR nodes
* **Suspicious API calls in CloudTrail**

  * `ListBuckets`
  * `GetCallerIdentity`
  * `CreateAccessKey`
* **Network indicators**

  * Outbound connections to known malicious IPs
  * Unusual DNS queries
* **Instance compromise evidence**

  * New processes
  * Reverse shells
  * Unexpected cron jobs or persistence

---

# 6. Mitigations / Security Best Practices

**Configuration Hardening**

* Enable GuardDuty in **all regions**.
* Use **multi-account GuardDuty with delegated administrator**.
* Enable additional protections:

  * EKS protection
  * S3 protection
  * Malware protection.

**Monitoring Improvements**

* Forward GuardDuty findings to:

  * SIEM
  * Security Hub
  * SOAR automation.
* Implement **alerts on high severity findings immediately**.

**Preventive Controls**

* Use **least privilege IAM policies**.
* Enforce **MFA for privileged users**.
* Rotate and monitor **access keys**.
* Restrict outbound traffic using **security groups and NACLs**.
* Use **EDR/agent monitoring on EC2 instances**.

---