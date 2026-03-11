## 1. What AWS Service Control Policies (SCP) Are

* **AWS Organizations Service Control Policies (SCPs)** are **organization-level guardrails** that define the **maximum permissions** allowed for accounts in an AWS organization.
* SCPs **do not grant permissions**; they only **restrict what IAM users/roles can do**, even if IAM policies allow the action.
* SCPs apply to **AWS accounts, Organizational Units (OUs), or the entire organization**.
* They are enforced during authorization when AWS evaluates policies alongside **AWS Identity and Access Management (IAM)** policies.
* Used primarily in **multi-account AWS environments** to enforce centralized security governance.
* Logs for SCP-related actions are primarily captured via **AWS CloudTrail**.

---

# 2. Legitimate Use

Organizations use SCPs to enforce **security guardrails across all AWS accounts**.

* **Prevent risky actions globally**

  * Example: deny `iam:CreateUser`, `cloudtrail:StopLogging`, or `s3:DeleteBucket`.
* **Restrict regions**

  * Only allow workloads in approved regions (e.g., block `us-west-1`).
* **Protect security services**

  * Prevent disabling **CloudTrail**, **GuardDuty**, or **Security Hub**.
* **Enforce least privilege**

  * Ensure accounts cannot exceed predefined privilege boundaries.
* **Compliance enforcement**

  * Restrict actions that violate frameworks like PCI, HIPAA, or ISO.
* **Control account provisioning**

  * Apply guardrails automatically when new accounts join an OU.

---

# 3. Attacker Abuse

Attackers target SCPs when they obtain **organization-level access**.

### 1. Disable Security Guardrails

* Modify or detach SCPs to **remove restrictions** preventing malicious activity.
* Example: remove SCP blocking `iam:*`.

**MITRE ATT&CK**

* T1098 – Account Manipulation
* T1562 – Impair Defenses

---

### 2. Enable Privilege Escalation Paths

* Modify SCPs to allow previously restricted IAM actions:

  * `iam:CreatePolicy`
  * `iam:AttachRolePolicy`
  * `sts:AssumeRole`

**MITRE ATT&CK**

* T1068 – Privilege Escalation
* T1098 – Account Manipulation

---

### 3. Disable Security Logging

Attackers remove SCPs that enforce logging controls.

Example actions:

* `cloudtrail:StopLogging`
* `config:StopConfigurationRecorder`

**MITRE ATT&CK**

* T1562.008 – Disable Cloud Logs

---

### 4. Allow Deployment of Malicious Infrastructure

Attackers modify SCPs restricting compute/network services to allow:

* `ec2:RunInstances`
* `lambda:CreateFunction`

Then deploy **crypto miners or backdoors**.

**MITRE ATT&CK**

* T1496 – Resource Hijacking

---

### 5. OU-Level Policy Tampering

Instead of modifying the root SCP, attackers move an account into an OU with **less restrictive policies**.

**MITRE ATT&CK**

* T1098 – Account Manipulation

---

# 4. SIEM Detection Opportunities

## Alert 1 — SCP Policy Modification

**Suspicious Behavior**

* Modification of an existing Service Control Policy.

**Detection Logic**

```
CloudTrail EventName = UpdatePolicy
AND PolicyType = SERVICE_CONTROL_POLICY
```

**Log Sources**

* CloudTrail Management Events

---

## Alert 2 — SCP Detached from OU or Account

**Suspicious Behavior**

* An SCP removed from an OU/account potentially removing guardrails.

**Detection Logic**

```
EventName = DetachPolicy
AND PolicyType = SERVICE_CONTROL_POLICY
```

**Log Sources**

* CloudTrail

---

## Alert 3 — New SCP Created with Broad Permissions

**Suspicious Behavior**

* Creation of SCP allowing dangerous actions (`Action:*` or `NotAction` usage).

**Detection Logic**

```
EventName = CreatePolicy
AND PolicyType = SERVICE_CONTROL_POLICY
AND policyDocument contains "Action":"*"
```

**Log Sources**

* CloudTrail

---

## Alert 4 — AWS Account Moved Between OUs

**Suspicious Behavior**

* Account moved to a different OU which may have weaker SCP restrictions.

**Detection Logic**

```
EventName = MoveAccount
```

**Log Sources**

* CloudTrail

---

## Alert 5 — SCP Deleted

**Suspicious Behavior**

* Removal of SCP guardrails protecting multiple accounts.

**Detection Logic**

```
EventName = DeletePolicy
AND PolicyType = SERVICE_CONTROL_POLICY
```

**Log Sources**

* CloudTrail

---

# 5. Investigation Indicators

When investigating suspicious SCP activity, analysts should check:

* **CloudTrail events**

  * `CreatePolicy`
  * `UpdatePolicy`
  * `AttachPolicy`
  * `DetachPolicy`
  * `DeletePolicy`
* **Identity performing the action**

  * IAM user, role, or assumed role.
* **Source IP / geolocation anomalies**

  * Unknown admin locations.
* **Policy diff analysis**

  * Compare old vs new SCP JSON.
* **OU/account changes**

  * Look for `MoveAccount` activity.
* **Follow-on activity**

  * IAM privilege escalation
  * Security service disablement.

---

# 6. Mitigations / Security Best Practices

### 1. Restrict Organizations Admin Access

* Limit **`organizations:*` permissions** to very few administrators.

---

### 2. Protect Security SCPs

Create **immutable guardrails** that prevent:

* `cloudtrail:StopLogging`
* `guardduty:DeleteDetector`
* `config:StopConfigurationRecorder`

---

### 3. Enable CloudTrail Organization Trails

Use **organization-wide trails** to ensure:

* SCP modifications are logged centrally.

---

### 4. Implement Change Monitoring

* SIEM alerts for **SCP create/update/delete events**.
* Integrate alerts into **SOAR workflows**.

---

### 5. Use MFA and Just-In-Time Access

Protect high-risk actions like:

* `organizations:UpdatePolicy`
* `organizations:MoveAccount`

---

### 6. Periodic Policy Audits

Regularly review:

* OU structures
* Attached SCPs
* Unintended permission allowances

---