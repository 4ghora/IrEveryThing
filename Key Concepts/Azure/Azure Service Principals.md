## 1. What It Is

* **Azure Service Principals** are **identities for applications or automation** in **Microsoft Azure** used to authenticate and access Azure resources.
* Created automatically when an **Azure App Registration** is created in **Microsoft Entra ID** (formerly Azure AD).
* Used for **machine-to-machine authentication** instead of human user accounts.
* Authentication methods typically include **client secrets, certificates, or federated credentials**.
* Commonly used by **CI/CD pipelines, automation scripts, and infrastructure-as-code tools** to access Azure APIs.
* Similar concept to **AWS IAM Roles/Users for applications**.

---

# 2. Legitimate Use

* **Automation & DevOps**

  * CI/CD pipelines (e.g., Terraform, GitHub Actions, Azure DevOps) use Service Principals to deploy infrastructure.
* **Application-to-Azure API access**

  * Backend services authenticate to Azure APIs like Key Vault, Storage, or Graph.
* **Infrastructure-as-Code**

  * Tools provision resources using Service Principal credentials.
* **Third-party integrations**

  * Monitoring or security tools integrate with Azure using a Service Principal.
* **Service-to-service authentication**

  * Microservices securely access other Azure resources.
* **Least-privilege access model**

  * RBAC roles assigned specifically to applications rather than users.

---

# 3. Attacker Abuse

Attackers commonly abuse Service Principals because **they often have persistent credentials and high privileges**.

### Common Abuse Scenarios

* **Compromised Client Secret**

  * Secrets stored in Git repos, scripts, or CI logs get leaked.
* **Token Abuse**

  * Attackers authenticate using stolen Service Principal credentials to obtain Azure access tokens.
* **Privilege Escalation**

  * Compromised SPs with **Owner or Contributor roles** allow resource takeover.
* **Persistence via Rogue Service Principal**

  * Attackers create a new Service Principal with high privileges.
* **Credential Addition**

  * Add new client secrets or certificates to existing Service Principals.

### Relevant MITRE ATT&CK Techniques

* **T1078.004 – Valid Accounts: Cloud Accounts**
* **T1098 – Account Manipulation**
* **T1550 – Use of Application Access Token**
* **T1528 – Steal Application Access Token**
* **T1136 – Create Account**

---

# 4. SIEM Detection Opportunities

### Alert 1 — Service Principal Authentication from Unusual Location

**Suspicious Behavior**

* Service Principal signs in from an IP/geolocation not previously observed.

**Detection Logic**

```
ServicePrincipalSignInLogs
| where IPAddress not in KnownSPIPRanges
| summarize count() by AppId, IPAddress, Location
```

**Log Sources**

* Azure AD / Entra ID Sign-in Logs
* Service Principal Sign-in Logs
* Conditional Access logs

---

### Alert 2 — New Credential Added to Service Principal

**Suspicious Behavior**

* New **client secret or certificate added** to an existing Service Principal.

**Detection Logic**

```
AuditLogs
| where OperationName in ("Add service principal credentials","Update application")
| where InitiatedBy != expected_admin_accounts
```

**Log Sources**

* Entra ID Audit Logs
* Microsoft Graph Activity Logs

---

### Alert 3 — Service Principal Assigned High Privilege Role

**Suspicious Behavior**

* Service Principal granted **Owner, Global Admin, or Contributor roles**.

**Detection Logic**

```
AzureActivity
| where OperationName contains "roleAssignments/write"
| where Properties contains "Owner" or "Contributor"
| where IdentityType == "ServicePrincipal"
```

**Log Sources**

* Azure Activity Logs
* Entra ID Audit Logs

---

### Alert 4 — Creation of New Service Principal

**Suspicious Behavior**

* New Service Principal created unexpectedly.

**Detection Logic**

```
AuditLogs
| where OperationName == "Add service principal"
| summarize count() by InitiatedBy, AppDisplayName
```

**Log Sources**

* Entra ID Audit Logs

---

### Alert 5 — Service Principal Performing Large Resource Enumeration

**Suspicious Behavior**

* Service Principal making excessive Azure API calls (possible recon).

**Detection Logic**

```
AzureActivity
| summarize count() by Caller, OperationName
| where count_ > threshold
```

**Log Sources**

* Azure Activity Logs
* Azure Resource Manager logs
* Defender for Cloud

---

# 5. Investigation Indicators

When investigating suspicious Service Principal activity, analysts should examine:

* **Service Principal ID / App ID**

  * Identify the associated application.
* **Credential changes**

  * Recently added **client secrets or certificates**.
* **RBAC role assignments**

  * Check if the SP has **Owner, Contributor, or custom high-privilege roles**.
* **Sign-in telemetry**

  * IP address, geolocation, user agent, token type.
* **API activity**

  * Look for abnormal operations (VM creation, Key Vault access, role changes).
* **Token usage**

  * Multiple tokens issued in short timeframes.

---

# 6. Mitigations / Security Best Practices

### Identity Hardening

* Prefer **Managed Identities** over Service Principals where possible.
* Avoid long-lived **client secrets**.

### Secret Protection

* Store credentials in **Azure Key Vault**.
* Rotate Service Principal secrets regularly.

### Least Privilege

* Avoid assigning **Owner or Global Admin roles** to Service Principals.
* Use **granular RBAC roles**.

### Monitoring

* Enable logging for:

  * Entra ID Sign-in Logs
  * Audit Logs
  * Azure Activity Logs
* Send logs to SIEM (e.g., Sentinel, Splunk).

### Conditional Access

* Restrict Service Principal sign-ins by:

  * IP ranges
  * workload identity federation
  * managed identity usage.

### Governance Controls

* Periodically audit:

  * **unused Service Principals**
  * **excessive privileges**
  * **stale credentials**

---