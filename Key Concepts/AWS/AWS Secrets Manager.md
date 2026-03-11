## Concept: AWS Secrets Manager

---

# 1. What It Is

* A managed secret storage service in Amazon Web Services that securely stores **credentials, API keys, tokens, and database passwords**.
* Secrets are encrypted using AWS Key Management Service (KMS) and accessed through IAM-controlled APIs.
* Supports **automatic credential rotation** using Lambda functions.
* Integrates with services such as Amazon RDS, AWS Lambda, and Amazon ECS.
* All API actions are logged through AWS CloudTrail, which is a key log source for SOC monitoring.
* Used widely in **cloud-native and enterprise AWS environments** to eliminate hardcoded secrets.

---

# 2. Legitimate Use

* Secure storage of **database credentials, API tokens, SSH keys, and service passwords**.
* Applications retrieve secrets dynamically using IAM roles instead of storing credentials in code.
* **Automated secret rotation** for services like RDS to reduce credential exposure risk.
* DevOps and CI/CD pipelines retrieve secrets during deployment.
* Centralized **secret lifecycle management** including versioning and auditing.
* Helps organizations comply with **security standards (PCI-DSS, SOC2, ISO 27001)**.

---

# 3. Attacker Abuse

Attackers target Secrets Manager to **harvest credentials and move laterally in cloud environments**.

**Common Abuse Scenarios**

* Compromised IAM role or access key used to **retrieve secrets via `GetSecretValue`**.
* Attackers enumerate available secrets using `ListSecrets`.
* Secrets are exfiltrated and used to access **databases, SaaS APIs, or internal services**.
* Attackers modify or replace secrets to **persist access or break services**.
* Privilege escalation by retrieving secrets that contain **higher-privilege credentials**.

**MITRE ATT&CK Mapping**

* T1552 – Unsecured Credentials
* T1555 – Credentials from Password Stores
* T1528 – Steal Application Access Token
* T1078 – Valid Accounts
* T1041 – Exfiltration Over C2 Channel

---

# 4. SIEM Detection Opportunities

### Alert 1: Unusual Secrets Retrieval by IAM Identity

**Suspicious Behavior**

Large or abnormal retrieval of secrets from an IAM user/role that rarely accesses Secrets Manager.

**Detection Logic**

* CloudTrail event = `GetSecretValue`
* Baseline deviation for user/role
* High volume retrieval within short time window

Example Logic:

```
eventSource = secretsmanager.amazonaws.com
eventName = GetSecretValue
count(secretId) > threshold
group by userIdentity within 10 minutes
```

**Log Sources**

* AWS CloudTrail
* IAM Access Analyzer
* EDR (for compromised host correlation)

---

### Alert 2: Secrets Enumeration Activity

**Suspicious Behavior**

Attacker enumerates all secrets to identify sensitive credentials.

**Detection Logic**

```
eventSource = secretsmanager.amazonaws.com
eventName = ListSecrets
AND userIdentity NOT IN known automation roles
```

or

```
ListSecrets followed by multiple GetSecretValue events
```

**Log Sources**

* CloudTrail

---

### Alert 3: Secret Value Access From Unusual Location

**Suspicious Behavior**

Secrets accessed from a **new IP, region, or anomalous geolocation**.

**Detection Logic**

```
eventName = GetSecretValue
AND sourceIPAddress NOT IN baseline_ip_range
```

**Log Sources**

* CloudTrail
* VPC Flow Logs
* Identity logs

---

### Alert 4: Secret Modification or Rotation Change

**Suspicious Behavior**

Attacker modifies a secret to **replace credentials or disable rotation**.

**Detection Logic**

```
eventName IN (
UpdateSecret,
PutSecretValue,
DeleteSecret,
RotateSecret,
UpdateSecretVersionStage
)
AND userIdentity NOT IN approved_admin_roles
```

**Log Sources**

* CloudTrail

---

### Alert 5: Secret Access Immediately After IAM Compromise

**Suspicious Behavior**

Secrets accessed right after suspicious IAM events like key creation.

**Detection Logic**

```
(CreateAccessKey OR AssumeRole)
FOLLOWED BY GetSecretValue within 15 minutes
```

**Log Sources**

* CloudTrail
* AWS GuardDuty findings
* IAM logs

---

# 5. Investigation Indicators

SOC analysts should examine:

* **CloudTrail events**

  * `GetSecretValue`
  * `ListSecrets`
  * `UpdateSecret`
* **UserIdentity fields**

  * IAM user
  * assumed role
  * federated identity
* **Source IP address anomalies**

  * TOR/VPN/cloud provider IPs
  * new geo location
* **Secrets accessed**

  * database credentials
  * API tokens
  * production system passwords
* **Time correlation**

  * secret retrieval immediately after:

    * IAM access key creation
    * role assumption
    * suspicious login

Additional artifacts:

* Application logs using the stolen credential
* Database access logs
* EDR telemetry on compromised EC2 instances

---

# 6. Mitigations / Security Best Practices

**Access Control**

* Apply **least privilege IAM policies** for secrets access.
* Restrict `GetSecretValue` to specific application roles.

**Monitoring**

* Enable and centralize **CloudTrail logging for Secrets Manager APIs**.
* Alert on **enumeration or mass secret retrieval**.

**Network Controls**

* Use **VPC endpoints** for Secrets Manager access to prevent internet access.
* Restrict access to trusted networks.

**Credential Hygiene**

* Enable **automatic secret rotation** wherever possible.
* Avoid storing **high-privilege credentials** in Secrets Manager.

**Advanced Security Controls**

* Use **resource-based policies** to limit secret access.
* Implement **AWS Config rules** to detect public or overly permissive secret policies.
* Monitor anomalies with Amazon GuardDuty.

---