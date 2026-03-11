# 1. What is AWS KMS

* AWS Key Management Service (KMS) is a managed service used to create, store, and control **cryptographic keys** used to encrypt data in AWS.
* Provides **customer-managed keys (CMKs)** and **AWS-managed keys** for encryption operations such as `Encrypt`, `Decrypt`, `GenerateDataKey`, and `Sign`.
* Integrates with many AWS services such as **S3, EBS, RDS, Lambda, Secrets Manager, and CloudWatch Logs**.
* Uses **envelope encryption**, where KMS protects a master key that encrypts data keys used by applications.
* Key operations are logged via **CloudTrail**, making KMS highly observable for SOC monitoring.
* Often used in **cloud-native enterprise infrastructure** for protecting sensitive data, secrets, and backups.

---

# 2. Legitimate Use

Organizations rely on KMS for **data protection and regulatory compliance**.

* Encrypting **S3 buckets, EBS volumes, RDS databases, and backups**.
* Securing **application secrets** stored in Secrets Manager or Parameter Store.
* Managing **customer-managed encryption keys** for compliance requirements (PCI-DSS, HIPAA, etc.).
* Enabling **cross-account encryption workflows** in multi-account AWS architectures.
* Automating encryption operations in **CI/CD pipelines and serverless environments**.
* Performing **cryptographic signing or verification** for applications.

---

# 3. Attacker Abuse

Attackers abuse KMS primarily after **credential compromise or privilege escalation**.

### Common Abuse Scenarios

* **Decrypting protected secrets**

  * If an attacker gains IAM permissions (`kms:Decrypt`), they can retrieve plaintext secrets.
  * Example: decrypting secrets used by applications.

* **Privilege escalation through key policies**

  * Attackers modify KMS key policies to grant themselves access.

* **Disabling or scheduling deletion of keys**

  * Causes **data availability disruption** or destroys encryption keys.

* **Using KMS to decrypt data keys**

  * Allows attackers to decrypt large datasets encrypted by envelope encryption.

* **Grant abuse**

  * Creating KMS grants to allow persistent access to encrypted resources.

### Relevant MITRE ATT&CK Techniques

* **T1552 – Unsecured Credentials**
* **T1555 – Credentials from Password Stores**
* **T1098 – Account Manipulation**
* **T1485 – Data Destruction**
* **T1530 – Data from Cloud Storage Object**

---

# 4. SIEM Detection Opportunities

Below are practical SOC detections using **CloudTrail KMS events**.

---

### Alert: Unusual KMS Decrypt Activity

**Suspicious Behavior**

* A principal performs an abnormal number of `Decrypt` operations which may indicate **secret extraction**.

**Example Detection Logic**

```
CloudTrail EventName = "Decrypt"
AND Count(Decrypt) by User > baseline
AND SourceIP not in corporate ranges
```

**Relevant Logs**

* CloudTrail (KMS API events)
* VPC Flow Logs
* EDR telemetry

---

### Alert: KMS Key Policy Modified

**Suspicious Behavior**

* A user modifies a KMS key policy to grant new principals access.

**Example Detection Logic**

```
EventSource = kms.amazonaws.com
AND EventName = PutKeyPolicy
```

**Relevant Logs**

* CloudTrail

---

### Alert: KMS Key Scheduled for Deletion

**Suspicious Behavior**

* A KMS key scheduled for deletion, potentially leading to **data loss or ransomware-style sabotage**.

**Example Detection Logic**

```
EventName = ScheduleKeyDeletion
```

**Relevant Logs**

* CloudTrail

---

### Alert: KMS Grant Created for New Principal

**Suspicious Behavior**

* An attacker creates a **grant** allowing a new IAM principal to decrypt data.

**Example Detection Logic**

```
EventName = CreateGrant
AND GranteePrincipal NOT IN approved principals
```

**Relevant Logs**

* CloudTrail

---

### Alert: Cross-Account KMS Access

**Suspicious Behavior**

* A principal from another AWS account accesses a KMS key.

**Example Detection Logic**

```
EventName IN (Decrypt, GenerateDataKey)
AND userIdentity.accountId != keyOwnerAccountId
```

**Relevant Logs**

* CloudTrail

---

# 5. Investigation Indicators

SOC analysts should review the following artifacts during investigation:

* **CloudTrail KMS API events**

  * `Decrypt`
  * `GenerateDataKey`
  * `CreateGrant`
  * `PutKeyPolicy`
  * `ScheduleKeyDeletion`
* **IAM identity performing the action**

  * Role vs user vs assumed role
* **Source IP address and geolocation**
* **Associated service**

  * S3, Lambda, Secrets Manager
* **Abnormal spike in decrypt operations**
* **Cross-account access patterns**
* **Recently changed IAM roles or policies**

---

# 6. Mitigations / Security Best Practices

### Access Control

* Use **least privilege IAM policies** for KMS actions.
* Avoid granting broad permissions like:

```
kms:Decrypt
kms:*
```

---

### Key Policy Hardening

* Restrict key policies to **specific IAM roles only**.
* Avoid `"Principal": "*"`.

---

### Enable Monitoring

* Enable **CloudTrail for all regions**.
* Send KMS logs to **SIEM for anomaly detection**.

---

### Use Automatic Key Rotation

* Enable **annual key rotation** for customer-managed keys.

---

### Restrict Cross-Account Usage

* Explicitly allow only approved accounts in **key policies**.

---

### Alert on High-Risk KMS Operations

SOC should monitor:

* `PutKeyPolicy`
* `CreateGrant`
* `ScheduleKeyDeletion`
* `DisableKey`
* abnormal `Decrypt` spikes

---