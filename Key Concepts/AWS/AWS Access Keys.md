## 1. What It Is

* **AWS Access Keys** are **long-term credentials** used to authenticate programmatic access to **Amazon Web Services APIs and CLI.
* Each key pair consists of:

  * **Access Key ID**
  * **Secret Access Key**
* They are associated with **AWS Identity and Access Management (IAM) users or service accounts.
* Access keys allow interaction with AWS services via **CLI tools, SDKs, scripts, or automation pipelines**.
* Unlike temporary credentials from **AWS Security Token Service**, access keys **do not expire automatically** unless rotated or disabled.
* All API actions performed with access keys are recorded in **AWS CloudTrail**, which is critical for SOC monitoring.

---

# 2. Legitimate Use

* **Automation and DevOps**

  * CI/CD pipelines use access keys to deploy infrastructure or applications.

* **Application integration**

  * Backend services use access keys to interact with AWS APIs.

* **Infrastructure management**

  * System administrators use AWS CLI or SDK tools for automation tasks.

* **Third-party tool integration**

  * Security scanners, backup solutions, and monitoring tools authenticate using access keys.

* **Legacy environments**

  * Older systems that cannot use IAM roles rely on access keys.

* **Cross-service automation**

  * Scripts performing tasks like:
  * provisioning resources
  * uploading data to S3
  * managing infrastructure.

---

# 3. Attacker Abuse

Access keys are **one of the most common entry points for AWS breaches**.

---

### 1. Credential Leakage in Code Repositories

* Developers accidentally commit access keys to **GitHub or source code repositories**.
* Attackers scan public repos and immediately abuse exposed credentials.

MITRE:

* T1552

---

### 2. Credential Theft from Compromised Hosts

* Malware or attackers extract access keys from:

  * configuration files
  * environment variables
  * `.aws/credentials`.

MITRE:

* T1555

---

### 3. Cloud Resource Abuse (Cryptomining)

* Stolen access keys used to:

  * launch EC2 instances
  * run cryptominers
  * create large cloud bills.

MITRE:

* T1496

---

### 4. Privilege Escalation

* If compromised keys belong to privileged users, attackers can:

  * create new users
  * attach policies
  * modify roles.

MITRE:

* T1078

---

### 5. Data Exfiltration

* Attackers use stolen keys to access services like:

  * S3
  * DynamoDB
  * Secrets Manager.

MITRE:

* T1530

---

# 4. SIEM Detection Opportunities

### Alert 1: Access Key Used from Unusual Geographic Location

**Suspicious Behavior**

* API calls using an access key from a country never previously associated with the user.

**Detection Logic**

```
eventSource = "*"
AND userIdentity.accessKeyId = <key>
AND geoLocation NOT IN baseline_countries
```

**Log Sources**

* CloudTrail
* Geo-IP enrichment logs

---

### Alert 2: Access Key Used from Multiple Locations Quickly

**Suspicious Behavior**

* Same access key used from different geographic regions within a short timeframe.

**Detection Logic**

```
GROUP BY accessKeyId
IF distinct(sourceIPAddress_country) > 2
WITHIN 30 minutes
```

**Log Sources**

* CloudTrail
* SIEM geo-enrichment

---

### Alert 3: New Access Key Created for IAM User

**Suspicious Behavior**

* Attackers often create additional keys for persistence.

**Detection Logic**

```
eventName = CreateAccessKey
AND userIdentity.type != "Service"
```

**Log Sources**

* CloudTrail
* IAM audit logs

---

### Alert 4: Unusual API Activity by Access Key

**Suspicious Behavior**

* Access key suddenly performs sensitive administrative actions.

**Detection Logic**

```
eventName IN (
CreateUser,
AttachUserPolicy,
CreateAccessKey,
PutRolePolicy
)
AND userIdentity.accessKeyId = <key>
```

**Log Sources**

* CloudTrail

---

### Alert 5: Access Key Used Outside Approved Networks

**Suspicious Behavior**

* API requests originating outside corporate or AWS infrastructure.

**Detection Logic**

```
sourceIPAddress NOT IN corporate_ip_ranges
AND userIdentity.type = IAMUser
```

**Log Sources**

* CloudTrail
* Threat intel feeds

---

# 5. Investigation Indicators

SOC analysts should review the following artifacts:

* **CloudTrail API activity**

  * Identify actions performed using the access key.

* **Access key creation history**

  * Look for `CreateAccessKey` events.

* **Source IP addresses**

  * Investigate:
  * geolocation
  * TOR/VPN usage
  * attacker infrastructure.

* **Service usage anomalies**

  * sudden activity in:
  * EC2
  * IAM
  * S3
  * Lambda.

* **Time-based anomalies**

  * access during unusual hours or outside business operations.

* **New resources created**

  * instances
  * users
  * roles
  * policies.

---

# 6. Mitigations / Security Best Practices

### Hardening

* Avoid long-term access keys whenever possible.
* Use **IAM roles and temporary credentials** instead.
* Enforce **least privilege policies** for IAM users.

---

### Monitoring

* Enable **CloudTrail in all regions**.
* Continuously monitor:

  * `CreateAccessKey`
  * `DeleteAccessKey`
  * unusual API activity.

---

### Preventive Controls

* Enforce **regular access key rotation**.
* Use **AWS Secrets Manager or secure vaults** for credential storage.
* Enable **MFA for IAM users**.
* Implement **Service Control Policies (SCPs)** to limit high-risk actions.