## 1. What it is

* **Microsoft Entra ID Privileged Identity Management (PIM)** is a security feature that provides **just-in-time (JIT) privileged access** to administrative roles instead of permanent privileges.
* It is primarily used in **Microsoft Azure / Microsoft Entra ID environments** but also governs **Azure RBAC roles and Azure resource permissions**.
* Users are assigned **eligible roles** and must **activate them temporarily** when administrative access is required.
* Activation may require **MFA, approval workflow, or justification**, and the role expires automatically after a defined duration.
* PIM provides **audit logs, alerts, and access reviews** to track privileged role usage and reduce standing privilege risk.
* Common roles managed through PIM include **Global Administrator, Privileged Role Administrator, and Azure Subscription Owner**.

---

# 2. Legitimate Use

* **Reduce standing privileges** by giving administrators temporary access only when required.
* Enforce **MFA and approval workflows** before privileged role activation.
* Enable **time-bound access** for operations teams performing maintenance or incident response.
* Support **auditing and compliance requirements** (PCI-DSS, ISO 27001, SOC2).
* Allow **temporary elevation for DevOps engineers** managing Azure infrastructure.
* Perform **periodic access reviews** to ensure privileged roles remain justified.

---

# 3. Attacker Abuse

Attackers target PIM to obtain **temporary administrative privileges that look legitimate**.

* **Compromised admin activates PIM role**

  * An attacker who compromises an eligible account activates **Global Admin** or **Subscription Owner** access.

* **Malicious role assignment**

  * Attacker with partial admin rights adds themselves or a backdoor account as **PIM eligible**.

* **Privilege escalation via PIM configuration**

  * Changing PIM policies (approval disabled, duration increased).

* **Abuse of JIT activation to evade detection**

  * Activate role briefly → perform malicious actions → allow role to expire.

* **Persistence through eligible roles**

  * Assign hidden or dormant accounts as eligible admins.

**Relevant MITRE ATT&CK Techniques**

* **T1078 – Valid Accounts**
* **T1098 – Account Manipulation**
* **T1548 – Abuse Elevation Control Mechanism**
* **T1068 – Privilege Escalation**

---

# 4. SIEM Detection Opportunities

### Alert 1: Privileged Role Activated via PIM

**Suspicious Behavior**

User activates a high-risk administrative role.

**Detection Logic**

```
Event: Activate eligible role
Role IN ("Global Administrator","Privileged Role Administrator","Owner")
User NOT IN approved_admin_list
```

**Log Sources**

* Entra ID Audit Logs
* PIM Activity Logs
* SIEM Identity telemetry

---

### Alert 2: Privileged Role Activation Without MFA

**Suspicious Behavior**

Admin role activated without MFA or conditional access enforcement.

**Detection Logic**

```
PIM Activation Event
AND MFA requirement = false
OR MFA status != satisfied
```

**Log Sources**

* Azure AD Sign-in Logs
* PIM Activity Logs
* Conditional Access logs

---

### Alert 3: New Eligible Admin Role Assignment

**Suspicious Behavior**

A user is added as **eligible** for privileged roles.

**Detection Logic**

```
Operation: Add eligible member to role
Role IN ("Global Admin","Owner","Privileged Role Admin")
Initiator NOT IN IAM_admin_team
```

**Log Sources**

* Entra ID Audit Logs
* PIM Activity Logs

---

### Alert 4: PIM Policy Modification

**Suspicious Behavior**

Security controls in PIM are weakened.

**Detection Logic**

```
Operation: Update role management policy
Changes include:
- MFA requirement disabled
- Approval removed
- Activation duration increased
```

**Log Sources**

* Entra ID Audit Logs
* PIM configuration logs

---

### Alert 5: Privileged Role Activated from Suspicious Location

**Suspicious Behavior**

Privileged role activation from unusual geography or risky IP.

**Detection Logic**

```
PIM Role Activation
AND sign-in risk = high
OR geo_location NOT IN normal_user_locations
```

**Log Sources**

* Azure AD Sign-in Logs
* PIM Activity Logs
* Conditional Access Risk logs

---

# 5. Investigation Indicators

SOC analysts should examine:

* **PIM activation logs**

  * Role activated, duration, justification text.

* **Account authentication activity**

  * Impossible travel or suspicious IP addresses.

* **Actions performed during activation window**

  * Creation of new users, service principals, or API keys.

* **Role assignment changes**

  * New eligible admins added before or after incident.

* **Conditional Access bypass indicators**

  * MFA failures or policy exemptions.

* **Azure activity logs**

  * Resource changes performed while privileged role was active.

---

# 6. Mitigations / Security Best Practices

* **Require MFA for all PIM activations.**
* **Enable approval workflows** for high-risk roles (Global Admin, Owner).
* **Limit activation duration** (e.g., 1 hour maximum).
* **Monitor PIM logs in SIEM** and create real-time alerts.
* **Use access reviews** to remove stale eligible role assignments.
* **Restrict PIM management roles** (Privileged Role Administrator).
* **Implement Conditional Access policies** for privileged role activation.
* **Enable Azure AD Identity Protection** for risky sign-ins.

---