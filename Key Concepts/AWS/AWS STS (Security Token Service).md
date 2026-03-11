## 1. What It Is

* **AWS Security Token Service (STS)** is an AWS service that issues **temporary security credentials** used to access AWS resources.
* Credentials typically include **Access Key ID, Secret Access Key, and Session Token** that expire after a short duration.
* STS is heavily used with **IAM roles**, allowing users or services to **assume roles and gain temporary privileges**.
* Common APIs include **AssumeRole, AssumeRoleWithSAML, AssumeRoleWithWebIdentity, and GetSessionToken**.
* Used across AWS environments for **cross-account access, federated authentication, and service-to-service access**.
* STS activity is logged in **AWS CloudTrail**, making it critical for **SOC monitoring and incident response**.

---

# 2. Legitimate Use

* **Cross-account access**

  * Organizations allow users in one AWS account to access resources in another account via **AssumeRole**.

* **Federated identity authentication**

  * Enterprises integrate identity providers (Okta, Azure AD, etc.) with AWS using **SAML federation**.

* **Temporary credentials for applications**

  * Applications running on **EC2, Lambda, or containers** obtain temporary credentials via IAM roles.

* **Least privilege access**

  * Temporary credentials reduce risk compared to long-lived access keys.

* **DevOps and automation**

  * CI/CD systems assume roles to deploy infrastructure.

* **Third-party integrations**

  * Security tools or SaaS platforms assume roles to monitor AWS environments.

---

# 3. Attacker Abuse

Attackers frequently abuse STS because **temporary credentials often bypass traditional key monitoring**.

---

### 1. Privilege Escalation via AssumeRole

* If attackers compromise an IAM user or instance role, they can **assume higher privileged roles**.
* This can lead to **full AWS account takeover**.

MITRE:

* T1078
* T1098

---

### 2. Cross-Account Persistence

* Attackers create **trust relationships between accounts**.
* They then use **STS AssumeRole** to persist access even after credentials are revoked.

MITRE:

* T1136

---

### 3. IAM Role Credential Theft

* Attackers compromise an **EC2 instance** and query the **instance metadata service** to obtain role credentials.
* These credentials are then used to call **STS APIs**.

MITRE:

* T1552

---

### 4. Federation Token Abuse

* If attackers compromise **SAML federation or identity provider accounts**, they can generate **STS tokens**.
* This bypasses normal IAM user authentication monitoring.

MITRE:

* T1078

---

### 5. Token Reuse from External Infrastructure

* Stolen STS credentials can be used **outside AWS infrastructure**.
* Attackers run commands from:

  * attacker servers
  * VPN exit nodes
  * TOR.

MITRE:

* T1528

---

# 4. SIEM Detection Opportunities

### Alert 1: Suspicious AssumeRole from Unusual Source IP

**Suspicious Behavior**

* STS `AssumeRole` API called from an IP address outside normal enterprise ranges.

**Detection Logic**

```
eventName = "AssumeRole"
AND sourceIPAddress NOT IN corporate_ip_ranges
```

**Log Sources**

* CloudTrail
* SIEM cloud audit logs

---

### Alert 2: High Frequency STS Token Generation

**Suspicious Behavior**

* Unusual volume of `AssumeRole` or `GetSessionToken` requests indicating automation or attacker scripts.

**Detection Logic**

```
COUNT(eventName IN ("AssumeRole","GetSessionToken"))
BY userIdentity
WITHIN 10 minutes > threshold
```

**Log Sources**

* CloudTrail
* AWS CloudWatch

---

### Alert 3: AssumeRole into High Privilege Role

**Suspicious Behavior**

* A user assumes roles such as **AdminRole or OrganizationAccountAccessRole**.

**Detection Logic**

```
eventName = "AssumeRole"
AND requestParameters.roleArn CONTAINS "Admin"
```

**Log Sources**

* CloudTrail
* IAM access logs

---

### Alert 4: STS Token Used from New Geographic Location

**Suspicious Behavior**

* Temporary credentials used from a country not previously associated with the user.

**Detection Logic**

```
userIdentity.type = AssumedRole
AND geoLocation NOT IN baseline_countries
```

**Log Sources**

* CloudTrail
* SIEM geo-enrichment logs

---

### Alert 5: STS Token Usage from Non-AWS Infrastructure

**Suspicious Behavior**

* Assumed role credentials used from IPs outside known **AWS ranges or corporate networks**.

**Detection Logic**

```
userIdentity.type = AssumedRole
AND sourceIPAddress NOT IN AWS_IP_RANGES
AND sourceIPAddress NOT IN corporate_ip_ranges
```

**Log Sources**

* CloudTrail
* Threat intel IP feeds

---

# 5. Investigation Indicators

During investigation analysts should review:

* **CloudTrail STS events**

  * `AssumeRole`
  * `AssumeRoleWithSAML`
  * `GetSessionToken`

* **Source IP addresses**

  * Identify suspicious geolocation or TOR/VPN usage.

* **Role ARN used**

  * Determine **privilege level of the assumed role**.

* **Session context**

  * `sessionIssuer`
  * `principalId`
  * `sessionName`.

* **Subsequent API activity**

  * Look for actions after token generation:

    * `CreateUser`
    * `AttachRolePolicy`
    * `RunInstances`
    * `CreateAccessKey`.

* **Cross-account access**

  * Check trust relationships and role policies.

---

# 6. Mitigations / Security Best Practices

### Hardening

* Enforce **least privilege IAM roles**.
* Restrict **role trust policies** to specific accounts and identities.
* Limit **maximum session duration** for STS tokens.

---

### Monitoring

* Enable **CloudTrail logging in all regions**.
* Alert on **AssumeRole into privileged roles**.
* Monitor **STS usage from unusual IP ranges or countries**.

---

### Preventive Controls

* Require **MFA for AssumeRole operations**.
* Use **AWS Organizations SCPs** to limit privilege escalation paths.
* Regularly audit **IAM trust relationships**.
* Use **short-lived tokens with strict expiration policies**.

---