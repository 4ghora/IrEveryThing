## 1. What **AWS Config** Is

* A **configuration monitoring and auditing service** in **Amazon Web Services** that continuously records resource configurations.
* Tracks **changes to AWS resources** (IAM roles, security groups, EC2 instances, S3 buckets, etc.).
* Stores configuration snapshots and **configuration history** for compliance and auditing.
* Integrates with **AWS CloudTrail**, **Amazon S3**, and **Amazon CloudWatch** for logging and alerting.
* Used across **cloud governance, compliance monitoring, and security auditing** in AWS environments.
* Enables rule-based checks through **AWS Config Rules**.

---

# 2. Legitimate Use

* **Compliance monitoring**

  * Ensure infrastructure follows standards (CIS, NIST, internal policies).
* **Configuration change tracking**

  * Detect who changed a security group, IAM role, or encryption setting.
* **Security auditing**

  * Identify misconfigurations like public S3 buckets.
* **Automated remediation**

  * Combine with **AWS Systems Manager** or Lambda to auto-remediate violations.
* **Multi-account governance**

  * Centralized monitoring through **AWS Organizations**.
* **Forensics**

  * Historical configuration timeline helps during incident investigations.

---

# 3. Attacker Abuse

Attackers often **disable or manipulate AWS Config to hide activity**.

### Common Abuse Scenarios

* **Disabling AWS Config**

  * Prevents recording of configuration changes.
  * Hides malicious modifications to resources.

* **Deleting configuration history**

  * Attackers delete S3 buckets storing Config snapshots.

* **Altering Config rules**

  * Disable compliance rules detecting risky configurations.

* **Stopping configuration recorders**

  * Prevents new resource changes from being logged.

* **Creating malicious rules**

  * Mask malicious changes or trigger automated responses.

### MITRE ATT&CK Mapping

* **Indicator Removal on Host**

  * Disabling monitoring services.
* **Impair Defenses**

  * Disabling AWS security services.
* **Modify Cloud Compute Infrastructure**

  * Changing security configurations.

---

# 4. SIEM Detection Opportunities

### Alert 1: AWS Config Recorder Stopped

**Suspicious Behavior**

* An attacker stops configuration recording to prevent monitoring.

**Detection Logic**

```
eventSource = config.amazonaws.com
eventName = StopConfigurationRecorder
```

**Log Sources**

* AWS CloudTrail

---

### Alert 2: AWS Config Deleted

**Suspicious Behavior**

* Deleting Config removes monitoring for the environment.

**Detection Logic**

```
eventSource = config.amazonaws.com
eventName = DeleteConfigurationRecorder
OR
eventName = DeleteDeliveryChannel
```

**Log Sources**

* CloudTrail

---

### Alert 3: Config Rule Disabled or Deleted

**Suspicious Behavior**

* Compliance checks removed before malicious configuration change.

**Detection Logic**

```
eventSource = config.amazonaws.com
eventName IN
(DeleteConfigRule, PutConfigRule)
```

Check if rule state becomes **INACTIVE**.

**Log Sources**

* CloudTrail
* AWS Config logs

---

### Alert 4: Config S3 Bucket Tampering

**Suspicious Behavior**

* Attacker deletes or modifies S3 bucket storing configuration history.

**Detection Logic**

```
eventSource = s3.amazonaws.com
eventName IN (DeleteBucket, PutBucketPolicy, DeleteBucketPolicy)
bucketName = <config-log-bucket>
```

**Log Sources**

* CloudTrail
* S3 Access Logs

---

### Alert 5: AWS Config Delivery Channel Modified

**Suspicious Behavior**

* Attacker changes delivery location for configuration logs.

**Detection Logic**

```
eventSource = config.amazonaws.com
eventName = PutDeliveryChannel
```

Look for:

* new S3 bucket
* new SNS topic

**Log Sources**

* CloudTrail

---

# 5. Investigation Indicators

SOC analysts should review:

* **CloudTrail events**

  * `StopConfigurationRecorder`
  * `DeleteConfigurationRecorder`
  * `PutDeliveryChannel`
* **User identity performing action**

  * IAM user vs assumed role
  * unusual principal
* **Time correlation**

  * Config disabled **before privilege escalation or persistence**
* **S3 bucket changes**

  * Config log bucket policy modifications
* **Account activity anomalies**

  * API calls from unusual IP addresses or regions
* **Recent infrastructure changes**

  * Security group exposure
  * IAM policy changes
  * new EC2 instances

---

# 6. Mitigations / Security Best Practices

### Hardening

* Enable **AWS Config in all regions**.
* Use **centralized logging account** for Config logs.
* Restrict access to Config APIs with **least privilege IAM policies**.

### Preventive Controls

* Enable **S3 bucket versioning** for Config logs.
* Use **SCPs in AWS Organizations** to prevent disabling Config.

Example SCP control:

```
Deny:
config:StopConfigurationRecorder
config:DeleteConfigurationRecorder
```

### Monitoring Improvements

* Alert on **any Config service modification**.
* Monitor **S3 bucket modifications** for Config logs.
* Correlate **Config disablement with other security service changes**.

### Additional Security Services

Integrate with:

* **AWS Security Hub**
* **Amazon GuardDuty**
* **AWS CloudTrail**

to detect suspicious cloud activity.

---

A **high-fidelity SOC detection** is:

> **“Multiple AWS security services disabled by same principal within short time window.”**

---