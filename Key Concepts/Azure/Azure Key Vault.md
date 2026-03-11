## 1. What **Azure Key Vault** Is

* **Azure Key Vault** is a cloud service used to securely store and manage **secrets, cryptographic keys, and certificates**.
* It provides centralized protection for **API keys, passwords, TLS certificates, encryption keys, and tokens** used by applications.
* Supports **two object types**:

  * **Secrets** – passwords, tokens, connection strings
  * **Keys** – cryptographic keys used for encryption/decryption
* Integrates with **Azure Active Directory** for authentication and authorization.
* Commonly used in **Azure cloud workloads**, DevOps pipelines, serverless applications, and enterprise applications.

---

# 2. Legitimate Use

Organizations use Key Vault to **securely manage sensitive secrets** without hardcoding them into applications.

* Store **database credentials, API tokens, service account passwords, and certificates**.
* Applications retrieve secrets at runtime using **managed identities** instead of storing credentials in code.
* Centralized **certificate lifecycle management** (TLS cert issuance and renewal).
* Secure **encryption key management** for disk encryption, storage encryption, and database encryption.
* DevOps pipelines retrieve secrets during deployments (e.g., CI/CD automation).
* Used for **Bring Your Own Key (BYOK)** scenarios for regulatory or compliance requirements.

---

# 3. Attacker Abuse

Attackers often target Key Vault because it is a **high-value secret repository**.

### Secret Theft

* Compromised identity retrieves secrets from Key Vault.
* Enables access to databases, APIs, or internal services.
* **MITRE ATT&CK:**

  * Credential Access – **T1552: Unsecured Credentials**

### Privilege Escalation

* Attacker grants themselves **Key Vault access policies or RBAC roles**.
* Allows secret extraction or key manipulation.
* **MITRE ATT&CK:**

  * **T1098 – Account Manipulation**

### Persistence via Certificates or Keys

* Attacker uploads malicious certificates or keys.
* Used to maintain long-term access.

### Encryption Key Abuse

* Compromise of encryption keys may allow:

  * Decryption of protected data
  * Data tampering

### Reconnaissance

* Attackers enumerate vault contents:

  * List secrets
  * List keys
  * List certificates

**MITRE ATT&CK**

* **T1087 – Account Discovery**
* **T1552 – Credential Access**
* **T1528 – Steal Application Access Token**

---

# 4. SIEM Detection Opportunities

### Alert 1: Excessive Secret Retrieval

**Suspicious Behavior**

* Identity retrieving a large number of secrets in a short time.

**Detection Logic**

```
Count SecretGet operations per user > threshold within 5 minutes
```

**Log Sources**

* Azure Key Vault logs
* Azure Monitor logs
* Azure Activity Logs
* Azure AD Sign-in logs

---

### Alert 2: Key Vault Access Policy Modification

**Suspicious Behavior**

* New permissions added allowing secret or key access.

**Detection Logic**

```
OperationName == "VaultAccessPolicyChanged"
AND NewPermissions contains "get" OR "list"
```

**Log Sources**

* Azure Activity Logs
* Azure Resource Manager logs

---

### Alert 3: Unusual IP Accessing Key Vault

**Suspicious Behavior**

* Key Vault access from unfamiliar geographic region or IP.

**Detection Logic**

```
OperationName == "SecretGet"
AND IPAddress NOT IN known_corporate_ranges
```

**Log Sources**

* Key Vault diagnostic logs
* Azure AD sign-in logs
* Conditional access logs

---

### Alert 4: Secret Enumeration

**Suspicious Behavior**

* Multiple `SecretList` operations indicating vault reconnaissance.

**Detection Logic**

```
OperationName == "SecretList"
COUNT > baseline per user
```

**Log Sources**

* Key Vault logs
* Azure Monitor logs

---

### Alert 5: Key Vault Role Assignment

**Suspicious Behavior**

* New RBAC role granting secret/key access.

**Detection Logic**

```
OperationName == "Create role assignment"
AND Role contains "Key Vault"
```

**Log Sources**

* Azure Activity Logs
* Azure RBAC logs

---

# 5. Investigation Indicators

When investigating Key Vault alerts, analysts should check:

* **Which identity accessed the vault**

  * User account
  * Service principal
  * Managed identity
* **Number of secrets retrieved**

  * Unusual bulk access
* **Source IP / geographic location**

  * Foreign country or TOR/VPN infrastructure
* **Recent RBAC or access policy changes**
* **Application logs**

  * Did an application suddenly start pulling secrets?
* **Related authentication activity**

  * Suspicious logins in Azure AD
* **Correlation with other cloud activity**

  * VM creation
  * storage access
  * token abuse

---

# 6. Mitigations / Security Best Practices

### Identity & Access Control

* Use **RBAC instead of access policies** where possible.
* Apply **least privilege** for secret access.
* Use **managed identities** for applications instead of credentials.

### Network Security

* Restrict vault access using **private endpoints**.
* Limit access to trusted IP ranges.

### Monitoring

* Enable **Key Vault diagnostic logging**.
* Send logs to **SIEM (e.g., Microsoft Sentinel)**.
* Alert on:

  * secret enumeration
  * bulk secret retrieval
  * permission changes

### Secret Hygiene

* Rotate secrets regularly.
* Avoid long-lived credentials.

### Conditional Access

* Enforce **MFA for privileged identities**.

### Protection Against Mass Exfiltration

* Monitor for **unusual API activity or automation patterns**.

---