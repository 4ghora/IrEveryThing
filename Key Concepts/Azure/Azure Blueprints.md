## 1. What It Is

* **Azure Blueprints** is an Azure governance service that allows organizations to **define, deploy, and manage standardized environments** using a packaged set of artifacts.
* Artifacts can include **Azure Policy assignments, Role-Based Access Control (RBAC), resource groups, and ARM templates**.
* Blueprints are applied at the **management group or subscription level** to enforce consistent configurations across multiple environments.
* Commonly used in **enterprise cloud governance, compliance frameworks, and landing zone architectures**.
* Integrates with **Azure Policy**, **Azure Resource Manager**, and **Azure RBAC** for automated governance.

---

# 2. Legitimate Use

* **Standardized environment deployment**

  * Ensure every new Azure subscription follows a predefined **security and governance baseline**.
* **Compliance enforcement**

  * Enforce frameworks like **CIS, NIST, ISO 27001**, or internal regulatory policies.
* **Landing zone automation**

  * Deploy networking, monitoring, and security controls consistently for new environments.
* **RBAC and policy automation**

  * Automatically apply required **least-privilege roles and security policies**.
* **Infrastructure-as-code governance**

  * Centralized teams can enforce **organization-wide architecture standards**.

---

# 3. Attacker Abuse

Attackers with **Azure management permissions** may abuse Azure Blueprints to persist, weaken security controls, or deploy malicious resources.

### 1. Security Policy Downgrade

* Modify Blueprint artifacts to **remove or weaken security policies**.
* Example: removing policies that enforce **logging or encryption**.

MITRE:

* **Modify Cloud Compute Infrastructure**
* **Impair Defenses**

---

### 2. Privilege Escalation via RBAC Artifacts

* Add **high-privileged role assignments** within Blueprint artifacts.
* Blueprint redeployment grants attackers **Owner or Contributor access** to multiple subscriptions.

MITRE:

* **Account Manipulation**
* **Privilege Escalation**

---

### 3. Persistent Backdoor Infrastructure

* Inject malicious **ARM templates** that automatically deploy:

  * rogue VMs
  * attacker-controlled identities
  * outbound access infrastructure.

MITRE:

* **Create Cloud Account**
* **Persistence**

---

### 4. Governance Tampering for Long-Term Access

* Attackers modify Blueprint assignments so that **security policies never get enforced**.
* This creates **long-term stealth in the cloud environment**.

MITRE:

* **Cloud Infrastructure Discovery**
* **Defense Evasion**

---

# 4. SIEM Detection Opportunities

### Alert 1 — Azure Blueprint Definition Modified

**Suspicious Behavior**

* A Blueprint definition is modified, potentially altering security policies or RBAC assignments.

**Detection Logic**

```
OperationName = "Microsoft.Blueprint/blueprints/write"
AND ResultType = "Success"
```

**Log Sources**

* Azure Activity Logs
* Azure Resource Manager logs
* SIEM ingestion (Sentinel / Splunk)

---

### Alert 2 — Blueprint Assignment Created or Updated

**Suspicious Behavior**

* Blueprint applied or updated at subscription/management group level.

**Detection Logic**

```
OperationName contains "blueprintAssignments/write"
```

**Log Sources**

* Azure Activity Logs
* Azure Resource Manager logs

---

### Alert 3 — RBAC Role Added via Blueprint Artifact

**Suspicious Behavior**

* Blueprint deployment adds privileged roles like Owner or Contributor.

**Detection Logic**

```
OperationName = "Microsoft.Authorization/roleAssignments/write"
AND InitiatedBy contains "Blueprint"
AND RoleDefinitionName IN ("Owner","Contributor")
```

**Log Sources**

* Azure Activity Logs
* Azure AD Audit Logs

---

### Alert 4 — Blueprint Deployment from Unusual Identity

**Suspicious Behavior**

* Blueprint operations initiated by:

  * new admin account
  * service principal
  * external identity.

**Detection Logic**

```
OperationName contains "Blueprint"
AND InitiatedBy NOT IN Approved_Admin_List
```

**Log Sources**

* Azure Activity Logs
* Azure AD Sign-In Logs

---

### Alert 5 — Large-Scale Resource Deployment via Blueprint

**Suspicious Behavior**

* Blueprint deployment creates many resources simultaneously.

**Detection Logic**

```
ResourceDeploymentCount > Threshold
AND DeploymentSource = Blueprint
```

**Log Sources**

* Azure Resource Manager logs
* Azure Activity Logs

---

# 5. Investigation Indicators

SOC analysts should examine:

* **Who modified or assigned the Blueprint**

  * account identity
  * service principal
  * IP location.
* **Changes inside the Blueprint artifacts**

  * RBAC changes
  * policy removals
  * ARM template additions.
* **New resource deployments after Blueprint change**

  * unexpected VMs
  * new managed identities
  * new networking resources.
* **Changes to Azure Policy assignments**

  * removal of logging or security enforcement.
* **Timeline correlation**

  * Blueprint change → RBAC change → suspicious activity.

Key logs:

* Azure Activity Logs
* Azure AD Audit Logs
* Azure Resource Manager deployment logs
* Azure Policy logs.

---

# 6. Mitigations / Security Best Practices

### Restrict Blueprint Permissions

* Limit **Blueprint Contributor / Owner roles** to a small governance team.

### Enable Full Logging

* Send **Azure Activity Logs and ARM deployment logs to SIEM**.

### Implement RBAC Monitoring

* Alert on **high-privilege role assignments via Blueprint artifacts**.

### Change Control for Governance

* Require **approval workflows for Blueprint modifications**.

### Use Immutable Governance Policies

* Use **Azure Policy with deny effects** for critical security controls.

### Monitor Management Group Changes

* Blueprint assignments at **management group level** affect many subscriptions.

---