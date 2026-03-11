## 1. What It Is

* **AWS CloudTrail** is an AWS logging service that records **API calls and account activity** across AWS infrastructure.
* It logs actions performed via **AWS Console, CLI, SDKs, and services**.
* CloudTrail captures **who did what, when, from where, and using which resource**.
* Logs are typically delivered to **Amazon S3** and can be analyzed with **Amazon CloudWatch**, **Amazon Athena**, or a SIEM.
* Used for **security monitoring, forensic investigation, and compliance auditing**.
* Supports **management events, data events, and insight events** across AWS services.

---

# 2. Legitimate Use

Organizations rely on CloudTrail for **visibility and accountability across cloud environments**.

* **Audit API activity**

  * Track actions such as `CreateUser`, `RunInstances`, `DeleteBucket`.
* **Security investigations**

  * Determine **who performed a malicious action** and when.
* **Compliance requirements**

  * Supports standards like **PCI-DSS, SOC2, ISO 27001**.
* **Operational troubleshooting**

  * Identify configuration changes that caused outages.
* **Centralized logging**

  * Organization-level trails capture logs from **all AWS accounts**.
* **Automation triggers**

  * Security tools use CloudTrail events to trigger alerts or remediation.

---

# 3. Attacker Abuse

Attackers often attempt to **evade detection or abuse API visibility gaps**.

### 1. Disable CloudTrail Logging

Attackers stop logging to avoid detection after gaining privileged access.

Example actions:

* `StopLogging`
* `DeleteTrail`

**MITRE ATT&CK**

* T1562 – Impair Defenses
* T1562.008 – Disable Cloud Logs

---

### 2. Modify CloudTrail Configuration

Attackers change log destinations or encryption settings.

Example:

* Change S3 bucket
* Disable log validation

**MITRE ATT&CK**

* T1562 – Defense Evasion

---

### 3. Delete CloudTrail Logs

If attackers have access to the **S3 log bucket**, they may remove evidence.

Example actions:

* `DeleteObject` on CloudTrail logs.

**MITRE ATT&CK**

* T1070 – Indicator Removal

---

### 4. Use CloudTrail to Understand the Environment

Attackers query CloudTrail to **enumerate activity and identify privileged roles**.

Example:

* `LookupEvents`

**MITRE ATT&CK**

* T1087 – Account Discovery
* T1082 – System Information Discovery

---

### 5. Exploit Lack of Data Event Logging

If **data events are disabled**, attackers may access resources such as:

* S3 objects
* Lambda executions

Without detailed logs.

**MITRE ATT&CK**

* T1530 – Data from Cloud Storage

---

# 4. SIEM Detection Opportunities

### Alert 1 — CloudTrail Logging Disabled

**Suspicious Behavior**

* A user disables CloudTrail logging.

**Detection Logic**

```
EventName = StopLogging
OR EventName = DeleteTrail
```

**Log Sources**

* CloudTrail Management Events

---

### Alert 2 — CloudTrail Configuration Modified

**Suspicious Behavior**

* CloudTrail configuration changed (log bucket, encryption, validation).

**Detection Logic**

```
EventName IN (UpdateTrail, PutEventSelectors)
```

**Log Sources**

* CloudTrail

---

### Alert 3 — CloudTrail Log Bucket Deletion Activity

**Suspicious Behavior**

* Deleting objects from the CloudTrail log storage bucket.

**Detection Logic**

```
EventSource = s3.amazonaws.com
AND EventName = DeleteObject
AND bucket_name = "cloudtrail-log-bucket"
```

**Log Sources**

* CloudTrail Data Events
* S3 Access Logs

---

### Alert 4 — Unusual CloudTrail Lookup Activity

**Suspicious Behavior**

* Excessive event lookups suggesting reconnaissance.

**Detection Logic**

```
EventName = LookupEvents
AND Count(user) > threshold
```

**Log Sources**

* CloudTrail

---

### Alert 5 — CloudTrail Trail Deleted and Recreated

**Suspicious Behavior**

* Trail deleted then recreated to reset monitoring.

**Detection Logic**

```
Sequence:
DeleteTrail
followed by
CreateTrail within short time window
```

**Log Sources**

* CloudTrail

---

# 5. Investigation Indicators

SOC analysts should review the following artifacts:

* **CloudTrail event history**

  * `StopLogging`
  * `DeleteTrail`
  * `UpdateTrail`
* **User identity details**

  * IAM user or role
  * Assumed role sessions
* **Source IP address**

  * Unusual geolocation or unknown IP ranges.
* **S3 log bucket activity**

  * Object deletion or overwrite.
* **Time gaps in logging**

  * Missing CloudTrail events indicating tampering.
* **Follow-on activity**

  * Privilege escalation
  * IAM role changes
  * Resource deployment.

---

# 6. Mitigations / Security Best Practices

### 1. Enable Organization-Level Trails

Use **organization trails** to ensure logging across all accounts.

---

### 2. Protect the Log Storage Bucket

Secure the **CloudTrail S3 bucket** by:

* Enabling **S3 Object Lock**
* Restricting delete permissions
* Enabling versioning

---

### 3. Enable Log File Integrity Validation

Use **CloudTrail log validation** to detect tampering.

---

### 4. Monitor CloudTrail Configuration Changes

Create SIEM alerts for:

* `StopLogging`
* `DeleteTrail`
* `UpdateTrail`

---

### 5. Enable Data Event Logging

Capture sensitive operations such as:

* S3 object access
* Lambda invocations

---

### 6. Implement MFA for Privileged Actions

Require **MFA for IAM and Organizations administrators** performing high-risk operations.

---