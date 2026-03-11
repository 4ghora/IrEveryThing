## 1. What It Is

* **Managed Identities** are automatically managed identities in **Microsoft Microsoft Azure** that allow applications to authenticate to Azure services **without storing credentials**.
* The identity exists in **Azure Active Directory** and can receive **RBAC permissions** to access resources such as Key Vault, Storage, or databases.
* Two types exist:

  * **System-assigned** – tied to a single Azure resource (VM, App Service, Function).
  * **User-assigned** – reusable identity that can be attached to multiple resources.
* Authentication happens through the **Azure Instance Metadata Service (IMDS)**, which issues tokens to the workload.
* Commonly used in **Azure VMs, App Services, Functions, Kubernetes (AKS), Logic Apps**, and automation services.

---

# 2. Legitimate Use

* **Secretless authentication** – applications authenticate to services without storing API keys or passwords.
* **Secure service-to-service communication** (e.g., VM accessing Key Vault or Storage Account).
* **Automation and DevOps pipelines** interacting with Azure resources.
* **Workload identity for microservices** in **Azure Kubernetes Service**.
* **Infrastructure automation** tools such as Terraform or Azure Automation runbooks.
* Enables **principle of least privilege** using **Azure RBAC roles**.

---

# 3. Attacker Abuse

Attackers who compromise a resource can **steal or abuse the Managed Identity token** to move laterally or access additional resources.

### Common Attack Scenarios

* **Token theft from compromised VM**

  * Attacker queries **IMDS endpoint (169.254.169.254)** to retrieve an access token.
  * Uses token to access resources like Key Vault or Storage.

* **Privilege escalation via over-permissioned identities**

  * Managed identity has **Contributor / Owner** privileges.
  * Attacker uses identity to modify infrastructure.

* **Secret extraction**

  * Managed identity allowed to read secrets in **Azure Key Vault**.
  * Attacker retrieves database credentials or certificates.

* **Cloud resource enumeration**

  * Using stolen token with **Azure REST APIs** or **Azure CLI**.

### Relevant MITRE ATT&CK

* **T1552 – Unsecured Credentials**
* **T1528 – Steal Application Access Token**
* **T1078 – Valid Accounts**
* **T1530 – Data from Cloud Storage**
* **T1550 – Use of Authentication Tokens**

---

# 4. SIEM Detection Opportunities

### Alert 1 — Managed Identity Token Request from Suspicious Process

**Suspicious Behavior**

* Non-standard process on VM requesting token from IMDS endpoint.

**Detection Logic**

```
Process making HTTP request to:
169.254.169.254/metadata/identity/oauth2/token
AND
Process NOT in allowed baseline (Azure services / SDK)
```

**Relevant Log Sources**

* EDR telemetry
* Sysmon Event ID 3 (network connection)
* Defender for Endpoint
* Linux auditd / eBPF telemetry

---

### Alert 2 — Managed Identity Accessing Key Vault Secrets

**Suspicious Behavior**

* Managed identity retrieving large number of secrets.

**Detection Logic**

```
Operation = SecretGet
AND
CallerIdentityType = ManagedIdentity
AND
Count > baseline threshold
```

**Relevant Log Sources**

* Azure Key Vault Diagnostic Logs
* Azure Monitor Logs
* Azure Activity Logs

---

### Alert 3 — Unusual Azure API Activity Using Managed Identity

**Suspicious Behavior**

* Managed identity performing management operations not typical for workload.

**Detection Logic**

```
CallerType = ManagedIdentity
AND
OperationName IN (CreateRoleAssignment, DeleteResource, ListKeys)
AND
ResourceType not normally accessed
```

**Relevant Log Sources**

* Azure Activity Logs
* Azure Resource Manager logs
* Azure Monitor

---

### Alert 4 — Managed Identity Performing Storage Enumeration

**Suspicious Behavior**

* Identity listing large number of storage containers or blobs.

**Detection Logic**

```
AuthenticationType = ManagedIdentity
AND
OperationName IN (ListContainers, ListBlobs)
AND
Volume anomaly detected
```

**Relevant Log Sources**

* Azure Storage Analytics Logs
* Azure Monitor Logs
* Defender for Cloud

---

### Alert 5 — Managed Identity Role Assignment Change

**Suspicious Behavior**

* New RBAC permissions granted to a Managed Identity.

**Detection Logic**

```
Operation = Create role assignment
AND
PrincipalType = ManagedIdentity
```

**Relevant Log Sources**

* Azure Activity Logs
* Azure AD Audit Logs

---

# 5. Investigation Indicators

SOC analysts should review:

* **Resource hosting the managed identity**

  * VM, App Service, AKS pod, Function.

* **Token access patterns**

  * Calls to **IMDS endpoint (169.254.169.254)**.

* **Unusual API activity**

  * Management operations instead of normal workload activity.

* **Key Vault or Storage access spikes**

  * Large-scale secret retrieval or data listing.

* **New RBAC assignments**

  * Identity suddenly granted **Owner/Contributor** roles.

* **Process telemetry**

  * Curl, PowerShell, Python scripts requesting tokens.

Example suspicious command:

```
curl 'http://169.254.169.254/metadata/identity/oauth2/token'
```

---

# 6. Mitigations / Security Best Practices

### Identity & Access Hardening

* Apply **least privilege RBAC roles** to managed identities.
* Avoid assigning **Owner/Contributor** roles to workloads.
* Use **separate identities per application**.

### Monitoring & Detection

* Enable logging for:

  * Azure Activity Logs
  * Key Vault diagnostics
  * Storage access logs
* Monitor **IMDS token requests** on VMs.

### Infrastructure Hardening

* Restrict outbound access to **IMDS endpoint** where possible.
* Implement **network segmentation** for workloads.

### Secret Protection

* Limit **Key Vault secret read permissions**.
* Use **Key Vault access policies or RBAC carefully**.

### Threat Detection

* Enable **Microsoft Defender for Cloud** for abnormal identity activity.
* Baseline normal API behavior of workloads.

---