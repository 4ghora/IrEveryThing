## 1. What It Is

* **IAM Role Assumption** refers to temporarily obtaining permissions of an **IAM Role** using **AWS Security Token Service (STS)** via the `AssumeRole` API.
* A role contains a **set of policies** defining allowed actions and is assumed to gain **temporary credentials** (Access Key, Secret Key, Session Token).
* Commonly used in **Amazon Web Services cloud environments** for cross-account access and service permissions.
* Users, applications, or services can assume roles through **trust policies** that define which principals can assume the role.
* The action is logged in **AWS CloudTrail** with events like `AssumeRole`, `AssumeRoleWithSAML`, and `AssumeRoleWithWebIdentity`.
* Temporary credentials typically last **15 minutes to 12 hours**, depending on configuration.

---

# 2. Legitimate Use

* **Cross-account access** between multiple AWS accounts in large enterprise environments.
* **Service-to-service access** (e.g., EC2 instance assuming a role to access S3 or DynamoDB).
* **Federated identity access** from external identity providers such as corporate SSO.
* **Least privilege operations** by using short-lived credentials instead of long-term keys.
* **CI/CD pipelines** assuming deployment roles to deploy infrastructure.
* **Third-party vendor access** to specific AWS resources using dedicated roles.

---

# 3. Attacker Abuse

* **Privilege escalation** by assuming a role with higher privileges than the compromised identity.
* **Cross-account pivoting** if trust relationships allow external accounts to assume roles.
* **Persistence** by repeatedly assuming roles with temporary credentials.
* **Credential abuse** if an attacker steals IAM credentials that are allowed to assume roles.
* **Instance role abuse** when attackers compromise EC2 instances and retrieve instance metadata credentials.
* Relevant **MITRE ATT&CK techniques**:

  * **T1078** – using legitimate IAM credentials.
  * **T1552** – extracting role credentials from instance metadata.
  * **T1098** – modifying trust policies to allow new role assumptions.
  * **T1021** – accessing resources via assumed roles.

Typical attack scenarios:

* Compromised IAM user **assumes admin role** in another AWS account.
* Attacker exploits **SSRF to EC2 metadata service** and steals instance role credentials.
* Insider modifies **role trust policy** to allow attacker-controlled account.
* Stolen credentials repeatedly **assume roles for lateral movement across accounts**.

---

# 4. SIEM Detection Opportunities

### Alert 1: Unusual IAM Role Assumption from New IP

**Suspicious Behavior**

* IAM role assumed from an IP address or geographic region not previously seen.

**Detection Logic**

* Detect `AssumeRole` where:

  * `sourceIPAddress` not in historical baseline for user
  * OR country not typical for the principal.

**Log Sources**

* AWS CloudTrail
* SIEM geo-IP enrichment

---

### Alert 2: High Volume of Role Assumptions

**Suspicious Behavior**

* Abnormally high number of `AssumeRole` calls within a short period.

**Detection Logic**

```
count(AssumeRole events) by user > baseline threshold
within 10 minutes
```

**Log Sources**

* AWS CloudTrail
* SIEM behavior analytics

---

### Alert 3: Privileged Role Assumed by Non-Admin Identity

**Suspicious Behavior**

* Low-privileged IAM user assuming highly privileged roles such as admin roles.

**Detection Logic**

```
eventName = AssumeRole
AND roleArn contains "Admin" OR "AdministratorAccess"
AND userIdentity not in approved admin list
```

**Log Sources**

* AWS CloudTrail
* IAM configuration data

---

### Alert 4: Cross-Account Role Assumption

**Suspicious Behavior**

* Role assumption initiated from an external AWS account.

**Detection Logic**

```
eventName = AssumeRole
AND userIdentity.accountId != recipientAccountId
```

**Log Sources**

* AWS CloudTrail

---

### Alert 5: Role Assumption from EC2 Metadata Credentials

**Suspicious Behavior**

* Role assumption performed by temporary credentials obtained from EC2 instance metadata.

**Detection Logic**

* Detect `AssumeRole` where:

  * `userIdentity.type = AssumedRole`
  * `sessionContext.sessionIssuer.type = Role`
  * AND unusual API activity follows.

**Log Sources**

* AWS CloudTrail
* EDR telemetry on EC2 hosts

---

# 5. Investigation Indicators

* **CloudTrail entries** for `AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`.
* **Source IP addresses and geolocation anomalies**.
* **Role session names** (attackers sometimes use random or scripted names).
* **Unusual chained role assumptions** (role assuming another role).
* **EC2 instance metadata access logs** indicating credential retrieval attempts.
* **New or modified IAM trust policies** allowing additional principals.

Artifacts to review:

* IAM role trust policy
* Session duration settings
* Subsequent API activity after role assumption
* Cross-account relationships.

---

# 6. Mitigations / Security Best Practices

* Implement **least privilege IAM role policies** and limit who can assume roles.
* Restrict role assumption with **conditions** (IP restrictions, MFA requirement).
* Enable **MFA for role assumption** where possible.
* Monitor **CloudTrail for AssumeRole events** and integrate with SIEM.
* Use **AWS IAM Access Analyzer** to detect risky cross-account trust relationships.
* Limit **EC2 instance metadata access** using **IMDSv2** to prevent credential theft.
* Rotate and audit **IAM trust policies regularly**.