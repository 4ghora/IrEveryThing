
# 1. What it is

* **Azure Conditional Access** is a policy engine that controls authentication decisions based on user identity, device state, location, risk level, and application context.
* It is part of **Microsoft Entra ID** and acts as **policy-based access control for cloud identities**.
* Policies evaluate conditions such as **user, device compliance, IP location, sign-in risk, and application sensitivity**.
* If conditions match, controls like **MFA, device compliance, session restrictions, or blocking access** are enforced.
* Used primarily in **Azure, Microsoft 365, and enterprise cloud identity environments**.
* Logs are recorded in **Azure AD Sign-in Logs, Audit Logs, and Conditional Access Insights**.

---

# 2. Legitimate Use

* Enforce **Multi-Factor Authentication (MFA)** for sensitive applications like **Microsoft 365** or VPN portals.
* Restrict access to corporate applications **only from compliant or managed devices**.
* Implement **location-based policies**, allowing logins only from trusted networks.
* Block authentication attempts from **high-risk sign-ins detected by identity protection systems**.
* Apply **session restrictions** for web access to sensitive resources (e.g., download restrictions).
* Enable **Zero Trust security models** by verifying identity, device posture, and context before granting access.

---

# 3. Attacker Abuse

* Attackers modify Conditional Access policies after **compromising a privileged identity** to weaken security.
* Create policies **excluding attacker-controlled accounts from MFA enforcement**.
* Disable or alter policies that block **risky sign-ins or unknown device access**.
* Abuse **legacy authentication exemptions** to bypass MFA protections.
* Create overly permissive policies allowing access **from any device or location**.
* Relevant MITRE ATT&CK techniques:

  * **T1098 – Account Manipulation**
  * **T1556 – Modify Authentication Process**
  * **T1078 – Valid Accounts**

---

# 4. SIEM Detection Opportunities

### Alert 1: Conditional Access Policy Modified

* **Suspicious Behavior**

  * A privileged user modifies an existing Conditional Access policy.
* **Detection Logic**

  * Detect changes to policy configuration or enforcement state.
* **Example Logic**

  ```
  Operation = "Update Conditional Access Policy"
  OR Operation = "Add Conditional Access Policy"
  ```
* **Log Sources**

  * Azure AD Audit Logs
  * Microsoft Entra Audit Logs
  * SIEM integrations

---

### Alert 2: MFA Exclusion Added to Conditional Access Policy

* **Suspicious Behavior**

  * A user account is excluded from MFA enforcement.
* **Detection Logic**

  ```
  ConditionalAccessPolicyUpdate
  AND ModifiedProperty contains "ExcludeUsers"
  ```
* **Log Sources**

  * Azure AD Audit Logs
  * Conditional Access Policy Logs

---

### Alert 3: Conditional Access Policy Disabled

* **Suspicious Behavior**

  * A security policy enforcing MFA or device compliance is disabled.
* **Detection Logic**

  ```
  Operation = "Update Conditional Access Policy"
  AND NewValue = "Disabled"
  ```
* **Log Sources**

  * Azure AD Audit Logs
  * SIEM monitoring policy configuration

---

### Alert 4: High-Risk Sign-in Allowed by Conditional Access

* **Suspicious Behavior**

  * Sign-in classified as risky but access granted due to policy configuration.
* **Detection Logic**

  ```
  RiskLevel = High
  AND ConditionalAccessStatus = Success
  ```
* **Log Sources**

  * Azure AD Sign-in Logs
  * Identity Protection Logs

---

### Alert 5: Conditional Access Policy Created by Non-Admin

* **Suspicious Behavior**

  * A new Conditional Access policy is created by an unexpected account.
* **Detection Logic**

  ```
  Operation = "Add Conditional Access Policy"
  AND UserRole NOT IN ("Global Admin","Security Admin")
  ```
* **Log Sources**

  * Azure AD Audit Logs
  * Identity governance logs

---

# 5. Investigation Indicators

* Review **Azure AD Audit Logs** for policy creation, updates, or deletion events.
* Identify **who modified the policy and from which IP/device**.
* Compare **old vs new policy configuration** for suspicious exclusions or relaxations.
* Analyze **recent sign-in logs** after policy changes to identify attacker access.
* Look for **new accounts excluded from MFA or device compliance checks**.
* Investigate correlated events such as **privilege escalation or risky sign-ins**.

---

# 6. Mitigations / Security Best Practices

* Restrict Conditional Access management to **dedicated privileged roles only**.
* Implement **Privileged Identity Management (PIM)** for temporary admin access.
* Enforce **MFA for all privileged accounts** including Conditional Access administrators.
* Monitor **policy changes with real-time SIEM alerts**.
* Maintain **baseline policies** such as “Require MFA for admins” and “Block legacy authentication”.
* Enable **Conditional Access policy change logging and security monitoring**.

---