

# 1. What It Is

* **Azure Policy** is a governance service that **enforces rules and compliance standards on Azure resources**.
* It ensures resources deployed in **Microsoft Azure** follow organizational policies (e.g., allowed regions, required tags, encryption settings).
* Policies can **audit, deny, modify, or automatically remediate** non-compliant resources.
* Works through **policy definitions, assignments, initiatives, and remediation tasks**.
* Commonly used across **subscriptions, resource groups, and management groups** in enterprise cloud environments.
* Integrated with **Azure Resource Manager (ARM)** and logged through **Azure Activity Logs**.

---

# 2. Legitimate Use

Organizations use Azure Policy to enforce **cloud governance and security baselines**.

* Enforce **mandatory security controls** (e.g., require disk encryption or HTTPS).
* Restrict deployment to **approved regions or VM types**.
* Ensure **mandatory tagging** for asset management and cost tracking.
* Prevent creation of **publicly exposed resources** (e.g., public storage accounts).
* Enforce compliance frameworks such as **CIS, ISO 27001, NIST**.
* Automatically **remediate non-compliant resources** using remediation tasks.

Typical enterprise usage:

* Security baseline enforcement
* Regulatory compliance
* Cloud governance
* DevOps guardrails

---

# 3. Attacker Abuse

Attackers with sufficient Azure permissions can **modify or remove policies to bypass security controls**.

### Common Abuse Scenarios

* **Disabling restrictive policies**

  * Allows attacker to deploy malicious resources.
* **Removing security initiatives**

  * Removes enforcement for encryption, logging, or network restrictions.
* **Creating permissive policies**

  * Allow deployment of risky configurations.
* **Tampering with remediation tasks**

  * Prevent automatic security fixes.
* **Assigning policy exemptions**

  * Bypass controls without removing policy.

### Example Attack Path

1. Attacker compromises **Azure AD account**
2. Gains **Owner / Policy Contributor permissions**
3. Removes restrictive policies
4. Deploys malicious infrastructure (C2 VM, storage for exfiltration)

### Relevant MITRE ATT&CK

* **T1098** – modifying governance settings
* **T1562** – disabling security enforcement
* **T1078** – using compromised Azure accounts
* **T1526**

---

# 4. SIEM Detection Opportunities

### Alert 1 — Azure Policy Deleted

**Suspicious Behavior**

A policy definition or assignment is deleted, potentially removing governance protections.

**Detection Logic**

```
OperationName = "Microsoft.Authorization/policyAssignments/delete"
OR
OperationName = "Microsoft.Authorization/policyDefinitions/delete"
```

Trigger when:

* Deletion performed by non-admin
* Outside change window

**Log Sources**

* Azure Activity Logs
* Azure Resource Manager logs
* SIEM ingestion (Sentinel / Splunk / QRadar)

---

### Alert 2 — Azure Policy Modified

**Suspicious Behavior**

Existing policy definition updated to reduce restrictions.

**Detection Logic**

```
OperationName = "Microsoft.Authorization/policyDefinitions/write"
```

Investigate when:

* Policy rules changed
* Scope expanded unexpectedly

**Log Sources**

* Azure Activity Logs
* Azure Resource Manager

---

### Alert 3 — New Policy Exemption Created

**Suspicious Behavior**

Policy exemption created allowing resources to bypass governance rules.

**Detection Logic**

```
OperationName = "Microsoft.Authorization/policyExemptions/write"
```

Alert when:

* Exemption scope = subscription
* Created by unusual identity

**Log Sources**

* Azure Activity Logs

---

### Alert 4 — Policy Assignment Removed From Subscription

**Suspicious Behavior**

Critical baseline policy removed from subscription or management group.

**Detection Logic**

```
OperationName = "Microsoft.Authorization/policyAssignments/delete"
AND
Scope = "Subscription"
```

Alert if:

* Policy is tagged as **security baseline**

**Log Sources**

* Azure Activity Logs

---

### Alert 5 — Policy Remediation Task Stopped

**Suspicious Behavior**

Remediation tasks halted, preventing automatic correction of insecure resources.

**Detection Logic**

```
OperationName contains "policyRemediations"
AND
Status = Failed OR Cancelled
```

**Log Sources**

* Azure Activity Logs
* Azure Policy Insights logs

---

# 5. Investigation Indicators

When investigating suspicious Azure Policy activity, analysts should review:

### Identity Context

* Azure AD user or service principal performing change
* Privileged role assignments (Owner, Contributor, Policy Contributor)

### Change Details

* Policy definition before vs after modification
* Policy scope (management group / subscription)

### Timeline Analysis

* Sequence of actions:

  * Policy removal
  * Resource creation
  * Network rule changes

### Resource Deployment Following Policy Removal

Watch for attacker infrastructure such as:

* Public **VM deployments**
* Storage accounts used for **data exfiltration**
* **Public IP addresses**

### Authentication Signals

* Unusual sign-in location
* New device or IP
* MFA bypass or impossible travel

Log sources:

* Azure AD Sign-in Logs
* Azure Activity Logs
* Defender for Cloud alerts
* EDR telemetry

---

# 6. Mitigations / Security Best Practices

### Access Control

* Restrict **Policy Contributor / Owner roles**.
* Use **Privileged Identity Management (PIM)** for just-in-time access.

### Governance Protection

* Protect critical policies using **management group scope**.
* Use **policy initiatives** instead of standalone policies.

### Monitoring

* Forward **Azure Activity Logs** to SIEM (e.g., **Microsoft Sentinel**).
* Create alerts for **policy deletion or exemption creation**.

### Change Management

* Require **approval workflows** for policy changes.
* Track changes through **Azure Resource Graph and version control**.

### Defense-in-Depth

* Combine **Azure Policy + Defender for Cloud + RBAC restrictions**.
* Implement **Azure Blueprints / landing zone governance**.

### Logging & Retention

* Enable long-term storage for:

  * Activity logs
  * Policy insights
  * Azure AD logs

---