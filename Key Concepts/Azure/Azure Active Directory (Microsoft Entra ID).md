## 1. What it is

* **Azure Active Directory (Azure AD)**, now called **Microsoft Entra ID**, is Microsoft's **cloud identity and access management (IAM) service** used to authenticate and authorize users, applications, and services.
* It manages **user identities, groups, roles, authentication, and access policies** for cloud and enterprise resources.
* Used heavily in **Microsoft 365, Azure, SaaS applications, and hybrid enterprise environments**.
* Supports authentication protocols such as **OAuth2, OpenID Connect (OIDC), SAML, and Kerberos (hybrid)**.
* Provides features like **SSO, Conditional Access, MFA, Identity Protection, and device management**.
* Logs authentication and identity activity used by **SOC teams for monitoring account compromise and privilege abuse**.

---

# 2. Legitimate Use

* Centralized **identity management for users, groups, and service principals**.
* Provides **Single Sign-On (SSO)** to enterprise applications like Microsoft 365, Salesforce, and internal apps.
* Enforces **Conditional Access policies** based on device posture, location, or risk score.
* Enables **Multi-Factor Authentication (MFA)** for stronger authentication.
* Supports **service-to-service authentication using service principals and managed identities**.
* Integrates with **on-prem Active Directory through Azure AD Connect** for hybrid environments.

---

# 3. Attacker Abuse

* **Credential compromise** allowing attackers to authenticate to cloud services.
* **Token theft or token replay** to access resources without re-authentication.
* **Service principal abuse** where attackers create or hijack applications to maintain persistence.
* **Privilege escalation via role assignments** such as Global Admin or Application Admin.
* **Consent phishing attacks** where malicious applications request permissions from users.
* **Conditional Access bypass attempts** using legacy authentication protocols.

**MITRE ATT&CK Mapping**

* **T1078 – Valid Accounts**
* **T1550 – Use of Authentication Tokens**
* **T1098 – Account Manipulation**
* **T1528 – Steal Application Access Token**
* **T1136 – Create Account**

---

# 4. SIEM Detection Opportunities

### Alert 1: Suspicious Azure AD Global Administrator Role Assignment

**Suspicious Behavior**

* A new user or service principal is granted **Global Administrator privileges**, which could indicate privilege escalation.

**Detection Logic**

```
IF role_assigned == "Global Administrator"
AND actor NOT IN approved_admin_accounts
THEN alert
```

**Log Sources**

* Azure AD Audit Logs
* Microsoft Entra ID Audit Logs
* SIEM ingestion (Sentinel / Splunk)

---

### Alert 2: Impossible Travel Login

**Suspicious Behavior**

* User authenticates from **two geographically distant locations within an unrealistic timeframe**, suggesting credential compromise.

**Detection Logic**

```
IF user_login_country changes
AND time_between_logins < travel_time_threshold
THEN alert
```

**Log Sources**

* Azure AD Sign-in Logs
* Conditional Access Logs
* Identity Protection Logs

---

### Alert 3: Consent Granted to Suspicious Application

**Suspicious Behavior**

* A user grants **OAuth permissions to a newly registered application**, possibly indicating a consent phishing attack.

**Detection Logic**

```
IF operation == "Consent to application"
AND app_created_recently == TRUE
AND permissions include high_privilege_scopes
THEN alert
```

**Log Sources**

* Azure AD Audit Logs
* Microsoft Graph Activity Logs

---

### Alert 4: Excessive Failed Azure AD Logins

**Suspicious Behavior**

* Multiple failed login attempts may indicate **password spraying or brute force attempts**.

**Detection Logic**

```
COUNT(failed_logins) > threshold
FROM same_IP OR across multiple users
WITHIN 5 minutes
```

**Log Sources**

* Azure AD Sign-in Logs
* Defender for Identity
* SIEM correlation

---

### Alert 5: Service Principal Credential Addition

**Suspicious Behavior**

* A new **client secret or certificate added to a service principal**, possibly indicating persistence.

**Detection Logic**

```
IF operation == "Add service principal credentials"
AND actor NOT IN automation_accounts
THEN alert
```

**Log Sources**

* Azure AD Audit Logs
* Microsoft Graph Logs

---

# 5. Investigation Indicators

* **Unusual login locations or IP addresses** in Azure AD sign-in logs.
* **Login attempts using legacy authentication protocols** bypassing MFA.
* **Newly created service principals or applications** with excessive permissions.
* **Role assignment changes**, especially involving Global Admin or Privileged Role Admin.
* **Consent events for applications requesting high privilege scopes** (Mail.ReadWrite, Directory.ReadWrite.All).
* **MFA changes or MFA disabled events** for privileged users.

---

# 6. Mitigations / Security Best Practices

* Enforce **Multi-Factor Authentication (MFA)** for all users, especially administrators.
* Disable **legacy authentication protocols** (POP, IMAP, basic auth).
* Implement **Conditional Access policies** based on device compliance and location.
* Use **Privileged Identity Management (PIM)** for just-in-time admin access.
* Monitor **Azure AD Audit Logs and Sign-in Logs continuously in SIEM**.
* Restrict **user consent for applications** and require admin approval for high-risk permissions.

---
