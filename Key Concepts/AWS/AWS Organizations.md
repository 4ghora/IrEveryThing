## 1. What **AWS Organizations** Is

* A governance service from **Amazon Web Services** that allows centralized management of multiple AWS accounts.
* Used to create a **multi-account cloud environment** with hierarchical structures called **Organizational Units (OUs)**.
* Enables **centralized policy enforcement** using **Service Control Policies (SCPs)** across all member accounts.
* Often integrated with services like **AWS CloudTrail**, **AWS IAM**, and **AWS Control Tower**.
* Widely used in **enterprise AWS environments** to separate production, development, security, and sandbox accounts.
* Critical for **centralized governance, billing consolidation, and security controls**.

---

# 2. Legitimate Use

* **Centralized account governance** for large organizations operating dozens or hundreds of AWS accounts.
* Apply **Service Control Policies (SCPs)** to enforce security restrictions (e.g., block root access usage or restrict regions).
* **Consolidated billing** across multiple AWS accounts.
* **Segmentation of environments** (Prod, Dev, Security, Logging accounts).
* Integration with **identity federation and IAM roles** for centralized authentication.
* Used by security teams to enforce **baseline security guardrails** across the organization.

---

# 3. Attacker Abuse

Attackers targeting AWS often attempt to manipulate **AWS Organizations governance controls** for persistence or privilege escalation.

### Common Abuse Scenarios

* **Account takeover of the management account**

  * Full control over all child accounts.

* **Modification of Service Control Policies**

  * Removing security guardrails to enable malicious activity.

* **Adding malicious accounts to the organization**

  * Used for resource abuse or lateral movement.

* **Leaving the organization**

  * Compromised accounts may detach from org to evade monitoring.

* **Disabling delegated admin security services**

  * Such as security monitoring accounts.

### MITRE ATT&CK Mapping

* **MITRE ATT&CK**

  * T1098 – Account Manipulation
  * T1484 – Domain or Policy Modification
  * T1078 – Valid Accounts
  * T1090 – Proxy / Infrastructure for attacker-controlled accounts
  * T1562 – Impair Defenses

---

# 4. SIEM Detection Opportunities

### Alert 1 — **Service Control Policy Modified**

**Suspicious Behavior**

* SCP changes may remove security restrictions across the organization.

**Detection Logic**

```
CloudTrail EventName in
(UpdatePolicy, CreatePolicy, DeletePolicy, AttachPolicy, DetachPolicy)
AND requestParameters.policyType = "SERVICE_CONTROL_POLICY"
```

**Log Sources**

* AWS CloudTrail (Management Events)

---

### Alert 2 — **Account Removed from Organization**

**Suspicious Behavior**

* A member account leaving the organization may evade centralized monitoring.

**Detection Logic**

```
EventName = LeaveOrganization
OR EventName = RemoveAccountFromOrganization
```

**Log Sources**

* CloudTrail

---

### Alert 3 — **New Account Invited to Organization**

**Suspicious Behavior**

* Unexpected accounts added to the organization may indicate attacker infrastructure.

**Detection Logic**

```
EventName = InviteAccountToOrganization
OR EventName = CreateAccount
```

**Log Sources**

* CloudTrail

---

### Alert 4 — **Delegated Administrator Modified**

**Suspicious Behavior**

* Attackers may register themselves as delegated admins for key services.

**Detection Logic**

```
EventName in
(RegisterDelegatedAdministrator,
 DeregisterDelegatedAdministrator)
```

**Log Sources**

* CloudTrail

---

### Alert 5 — **Organization Policy Updated by Non-Admin Role**

**Suspicious Behavior**

* Unauthorized IAM role modifying organization policies.

**Detection Logic**

```
EventSource = organizations.amazonaws.com
AND EventName in (UpdatePolicy, AttachPolicy)
AND userIdentity.sessionContext.sessionIssuer.userName NOT IN (approved-admin-roles)
```

**Log Sources**

* CloudTrail
* IAM logs

---

# 5. Investigation Indicators

SOC analysts should investigate the following artifacts:

* **CloudTrail events related to Organizations**

  * `CreateAccount`
  * `AttachPolicy`
  * `RemoveAccountFromOrganization`

* **User identity performing the action**

  * IAM role
  * Federated identity
  * Root user activity

* **Unusual OU movements**

  * Accounts moved to OUs with fewer restrictions.

* **Recent IAM privilege changes**

  * New roles capable of modifying organization policies.

* **Geographic anomalies**

  * Management account access from unusual IP or regions.

* **Changes to SCP policies**

  * Removal of restrictions (e.g., disabling region restrictions).

---

# 6. Mitigations / Security Best Practices

### Governance Hardening

* Restrict **AWS Organizations administration** to **dedicated security roles**.
* Enforce **MFA** for management account users.
* Avoid using the **root account** for organizational actions.

### Monitoring Improvements

* Enable **AWS CloudTrail** **organization trails** to capture events from all accounts.
* Send logs to centralized SIEM (e.g., Splunk, Sentinel, QRadar).
* Create **alerts for Organizations API activity**.

### Preventive Controls

* Implement **strict Service Control Policies (SCPs)** preventing risky actions.
* Use **AWS Control Tower** for automated guardrails.
* Separate **security logging accounts** from workloads.

### Detection Hardening

* Maintain allowlists for **roles authorized to modify organization policies**.
* Monitor **delegated admin changes**.
* Alert on **LeaveOrganization events** immediately.

---