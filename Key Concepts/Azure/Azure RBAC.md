## 1. What Azure RBAC Is

* **Azure Role-Based Access Control (Azure RBAC)** is the authorization system used in **Microsoft Azure** to control **who can access resources and what actions they can perform**.
* RBAC works by assigning **roles** to **users, groups, service principals, or managed identities** at different scopes.
* **Scopes include:**

  * Management Group
  * Subscription
  * Resource Group
  * Individual Resource
* Roles define **permissions (actions)** such as read, write, delete, or execute operations on Azure resources.
* Built-in roles include **Owner, Contributor, Reader**, and many service-specific roles.
* Used widely in **cloud governance, least privilege access control, and multi-team enterprise environments**.

---

# 2. Legitimate Use

* Enforces **least privilege access** across cloud environments.
* Allows **segregation of duties** between admins, developers, and operations teams.
* Enables **fine-grained access control** to critical infrastructure (VMs, storage, networking).
* Supports **automation and DevOps pipelines** via **service principals or managed identities**.
* Common enterprise scenarios:

  * Developers granted **Contributor access** to a resource group.
  * Security teams given **Reader access** for monitoring.
  * Platform engineers assigned **Owner** at subscription level.
  * CI/CD pipelines using **service principals with limited roles**.

---

# 3. Attacker Abuse

Attackers commonly abuse RBAC for **privilege escalation and persistence**.

### Privilege Escalation

* Compromised identity assigns itself **higher privileged roles**.
* Example:

  * Contributor elevates to **Owner** on subscription.

**MITRE Mapping**

* **T1098**
* **T1078**

---

### Persistence via Backdoor Access

* Attacker adds **malicious service principal or external user** to RBAC.
* Grants **Owner/Contributor** roles for long-term persistence.

**MITRE Mapping**

* **T1136**
* **T1098**

---

### Lateral Movement Across Resources

* Attacker enumerates RBAC roles and finds resources they can access.
* Uses permissions to:

  * Dump secrets
  * Modify VM configurations
  * Deploy malicious workloads.

**MITRE Mapping**

* **T1087**
* **T1526**

---

### Stealthy Permission Granting

* Adds **low-visibility role assignments** at **resource-group level** rather than subscription.
* Harder for admins to notice.

---

# 4. SIEM Detection Opportunities

### Alert 1 — Privileged RBAC Role Assignment

**Suspicious Behavior**

* High privilege role (Owner, User Access Administrator) assigned.

**Example Detection Logic**

```
OperationName = "Create role assignment"
AND
RoleDefinitionName IN ("Owner","User Access Administrator")
```

**Relevant Log Sources**

* Azure Activity Logs
* Azure AD Audit Logs
* SIEM ingestion via **Microsoft Sentinel**

---

### Alert 2 — Role Assignment by Non-Admin Identity

**Suspicious Behavior**

* RBAC roles assigned by a **non-administrative user or service principal**.

**Detection Logic**

```
OperationName = "Create role assignment"
AND
InitiatingUser NOT IN Known_Admin_List
```

**Log Sources**

* Azure Activity Logs
* Azure AD Audit Logs

---

### Alert 3 — RBAC Assignment to External User

**Suspicious Behavior**

* Role granted to **external/B2B user or unknown service principal**.

**Detection Logic**

```
OperationName = "Create role assignment"
AND
PrincipalType = "Guest"
```

**Log Sources**

* Azure AD Logs
* Azure Activity Logs

---

### Alert 4 — Multiple RBAC Changes in Short Time

**Suspicious Behavior**

* Burst of role assignments indicating **automated privilege escalation or attacker automation**.

**Detection Logic**

```
count(RoleAssignments) > 5
GROUP BY InitiatingUser
TIMEWINDOW 10 minutes
```

**Log Sources**

* Azure Activity Logs

---

### Alert 5 — Role Assignment at Subscription Scope

**Suspicious Behavior**

* High privilege assignment applied at **subscription level** instead of resource group.

**Detection Logic**

```
OperationName = "Create role assignment"
AND
Scope CONTAINS "/subscriptions/"
AND
RoleDefinitionName = "Owner"
```

**Log Sources**

* Azure Activity Logs

---

# 5. Investigation Indicators

When investigating suspicious RBAC activity, analysts should check:

* **Who created the role assignment**

  * User, service principal, or managed identity.
* **Scope of assignment**

  * Subscription vs resource group vs individual resource.
* **New identities involved**

  * Newly created service principals or guest users.
* **Timing anomalies**

  * RBAC changes outside business hours.
* **Correlation with other activity**

  * VM creation
  * Key Vault access
  * Storage access
  * Token usage
* **Azure Activity Logs**

  * `Microsoft.Authorization/roleAssignments/write`

---

# 6. Mitigations / Security Best Practices

### Principle of Least Privilege

* Avoid excessive **Owner or Contributor** assignments.
* Prefer **custom roles** with limited permissions.

---

### Use Privileged Identity Management (PIM)

Use **Microsoft Entra Privileged Identity Management:

* Just-in-time role elevation
* Approval workflows
* Automatic expiration.

---

### Monitor RBAC Changes

* Continuously monitor **roleAssignments/write events**.
* Send alerts to SIEM.

---

### Restrict Role Assignment Capability

Only allow **User Access Administrator** or **Owner** roles to assign RBAC roles.

---

### Log Retention and SIEM Integration

Forward logs to SIEM such as:

* **Microsoft Sentinel**
* **Splunk**
* **Elastic Security**

---

### Use Conditional Access + MFA

Protect privileged accounts using:

* MFA
* Device compliance
* Network restrictions.

---