## 1. What AWS IAM Is

**AWS Identity and Access Management**

* A core AWS service used to **manage identities and permissions** for accessing AWS resources.
* Controls **who can authenticate (Users/Roles)** and **what actions they can perform (Policies)**.
* Main components:

  * **Users** – long-term identities representing people or applications.
  * **Groups** – collections of users for easier permission management.
  * **Roles** – temporary identities assumed by users/services with specific permissions.
  * **Policies** – JSON documents defining allowed or denied actions.
* Used across **AWS cloud environments** for secure access to services like EC2, S3, Lambda, etc.
* Integrated with services like **AWS CloudTrail** and **Amazon GuardDuty** for monitoring and detection.

---

# 2. Legitimate Use

* **Access Control Management**

  * Grant least-privileged access to AWS resources.
* **Role-Based Access Control (RBAC)**

  * Assign permissions via groups and roles instead of individual users.
* **Temporary Access via Roles**

  * EC2 instances assume roles to access AWS services securely.
* **Cross-Account Access**

  * Roles allow secure access between different AWS accounts.
* **Automation & DevOps**

  * CI/CD pipelines assume roles to deploy infrastructure.
* **Service Integrations**

  * AWS services (Lambda, ECS, Glue, etc.) use roles to interact with other services.

---

# 3. Attacker Abuse

Attackers frequently target IAM because **privilege escalation and persistence in AWS almost always involve IAM changes.**

### Credential Theft

* Stolen **IAM access keys** allow API access to AWS.
* Attackers use them via CLI/SDK to enumerate and exploit resources.
* MITRE: **Valid Accounts**

### Privilege Escalation via IAM Policies

* Modify or attach **AdministratorAccess policies** to compromised identities.
* MITRE: **Account Manipulation**

### Creating Backdoor IAM Users

* Attackers create **new IAM users with access keys** for persistence.

### Role Abuse / Role Chaining

* Assume roles with broader privileges.
* Abuse overly permissive trust relationships.

### Policy Modification

* Modify policies to allow sensitive actions (e.g., `iam:PassRole`, `sts:AssumeRole`).

### Disabling Logging

* If permissions allow, attackers disable **AWS CloudTrail** to hide activity.

---

# 4. SIEM Detection Opportunities

### Alert 1: IAM User Created

**Suspicious Behavior**

Creation of a new IAM user may indicate attacker persistence.

**Detection Logic**

```
eventName = CreateUser
AND userIdentity.type != "AWSService"
```

**Log Sources**

* CloudTrail
* AWS IAM logs
* EDR (if API calls from compromised host)

---

### Alert 2: Administrator Policy Attached

**Suspicious Behavior**

A user or role gains **AdministratorAccess** privileges.

**Detection Logic**

```
eventName = AttachUserPolicy OR AttachRolePolicy
AND requestParameters.policyArn CONTAINS "AdministratorAccess"
```

**Log Sources**

* CloudTrail

---

### Alert 3: Access Key Created for IAM User

**Suspicious Behavior**

Creation of long-term credentials for persistence.

**Detection Logic**

```
eventName = CreateAccessKey
```

**Log Sources**

* CloudTrail

---

### Alert 4: Unusual AssumeRole Activity

**Suspicious Behavior**

Role assumption from unexpected IP, user agent, or geography.

**Detection Logic**

```
eventName = AssumeRole
AND sourceIPAddress NOT IN approved_ranges
```

**Log Sources**

* CloudTrail
* VPC Flow Logs

---

### Alert 5: IAM Policy Modified

**Suspicious Behavior**

Modification of policies may indicate privilege escalation.

**Detection Logic**

```
eventName IN (
PutUserPolicy,
PutRolePolicy,
CreatePolicyVersion,
SetDefaultPolicyVersion
)
```

**Log Sources**

* CloudTrail

---

### Alert 6: CloudTrail Disabled

**Suspicious Behavior**

Attackers disable logging to evade detection.

**Detection Logic**

```
eventName IN (StopLogging, DeleteTrail)
```

**Log Sources**

* CloudTrail
* GuardDuty

---

# 5. Investigation Indicators

SOC analysts should review the following artifacts:

* **CloudTrail logs**

  * `CreateUser`
  * `AttachPolicy`
  * `CreateAccessKey`
  * `AssumeRole`
* **Source IP anomalies**

  * Login/API calls from unknown regions.
* **New access keys**

  * Recently generated keys with active usage.
* **Privilege changes**

  * Users suddenly gaining admin permissions.
* **Role trust policy changes**

  * External accounts added to trust relationships.
* **User agent anomalies**

  * CLI usage (`aws-cli`, `boto3`) from unusual systems.

---

# 6. Mitigations / Security Best Practices

### Enforce Least Privilege

* Avoid wildcard permissions (`*`).
* Use scoped IAM policies.

### Disable Long-Term Credentials

* Prefer **roles and temporary STS tokens**.

### Enable Multi-Factor Authentication

* Enforce MFA for privileged IAM users.

### Monitor IAM Changes

* Log and alert on:

  * policy changes
  * new users
  * access key creation.

### Use Service Control Policies (SCP)

* Restrict dangerous actions across AWS accounts.

### Continuous Monitoring

* Use:

  * **Amazon GuardDuty**
  * **AWS Security Hub**
  * SIEM ingestion of **AWS CloudTrail**

---