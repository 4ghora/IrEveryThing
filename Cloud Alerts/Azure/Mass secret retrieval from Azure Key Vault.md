## 1. Alert Name

**Mass secret retrieval from Azure Key Vault**

---

## 2. Alert Description (Detection Logic Explanation)

### 2.1 What triggered the alert

This alert is triggered when a single identity (User, Service Principal, or Managed Identity) performs:

* More than **10 distinct secret/key retrievals** (`dcount(requestUri_s) > 10`)
* More than **50 total retrieval events** (`EventCount > 50`)
* Operations include:

  * `SecretGet`
  * `KeyGet`
  * `VaultGet`

Detection logic:

1. Query monitors `AzureDiagnostics` for **VAULTS** resource type.
2. Filters out known legitimate AppIds:

   * `509e4652-da8d-478d-a730-e9d4a1996ca4` (Azure Resource Graph)
   * `8cae6e77-e04e-42ce-b5cb-50d82bce26b1` (Microsoft Policy Insights)
3. Identifies identities retrieving **more than 10 distinct secrets**
4. Then checks if **total retrieval activity > 50 events**
5. Summarizes by:

   * CallerObjectId
   * UPN
   * IP address
   * Resource list
   * Operation list

Example Trigger Scenario:

* A compromised service principal loops through vault secrets:

  ```bash
  az keyvault secret list --vault-name prod-vault
  az keyvault secret show --vault-name prod-vault --name db-password
  ```
* 75 secret retrievals in 5 minutes from single identity → Alert fires.

---

### 2.2 Which security tool generated it

* **Microsoft Azure Sentinel (Microsoft Sentinel)**
* Data Source: `AzureDiagnostics` (Azure Key Vault logs)
* Log Type: Azure Resource Logs (Data Plane Operations)

---

### 2.3 Why this alert is important

Azure Key Vault stores:

* Database passwords
* API keys
* OAuth secrets
* Encryption keys
* Certificates

Mass retrieval behavior strongly indicates:

* Credential harvesting
* Cloud environment mapping
* Lateral movement preparation
* Pre-ransomware staging
* Data exfiltration

This maps to:

* **MITRE ATT&CK T1552 – Unsecured Credentials**
* **T1555 – Credentials from Password Stores**
* **T1003 (Cloud equivalent credential access)**

---

### 2.4 Define Severity? Conditions to escalate alert to more severity

**Default Severity: High**

Escalate to Critical if:

* Identity is:

  * Global Admin
  * Privileged Role Admin
  * Key Vault Contributor
* Access from:

  * Unusual country
  * TOR/VPN IP
* Happens outside business hours
* Multiple vaults accessed
* Followed by:

  * Azure AD sign-in anomalies
  * VM deployments
  * Storage access spikes
* Secrets belong to:

  * Production databases
  * Backup credentials
  * CI/CD pipelines

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts analyst must understand about the entities in alert

#### 1. Azure Key Vault (Data Plane vs Control Plane)

Azure Key Vault has:

* **Control Plane operations**

  * Vault creation
  * Access policy modification
  * Role assignment
    Logged in: Azure Activity Logs

* **Data Plane operations**

  * SecretGet
  * KeyGet
  * CertificateGet
    Logged in: AzureDiagnostics

This alert focuses on **Data Plane operations**.

Analyst must differentiate:

* Was vault configuration changed?
* Or was secret content retrieved?

---

#### 2. Identity Types in Azure

CallerObjectId may represent:

* User Account (UPN present)
* Service Principal (AppId present)
* Managed Identity (system-assigned or user-assigned)

Example:

* Compromised DevOps SPN may pull all secrets.
* Managed Identity on compromised VM may auto-extract secrets.

---

#### 3. Service Principals & App Registrations

Attackers often:

* Compromise Service Principal secret
* Add new credential to App Registration
* Use `az login --service-principal`

Service Principals often have:

* Broad permissions
* No MFA
* Long-lived credentials

---

#### 4. Azure RBAC & Key Vault Access Models

Two models:

1. Vault Access Policies (legacy)
2. Azure RBAC-based model

Understand:

* Who has `Key Vault Secrets User`
* Who has `Key Vault Administrator`

Misconfigured RBAC often enables mass extraction.

---

#### 5. AzureDiagnostics Log Fields

Important fields:

* `identity_claim_appid_g`
* `CallerObjectId`
* `CallerObjectUPN`
* `CallerIPAddress`
* `requestUri_s`
* `clientInfo_s`

These reveal:

* Tool used (Azure CLI, SDK, PowerShell)
* Source IP
* User agent string

---

#### 6. Typical Legitimate Behavior

Legitimate patterns:

* Application retrieves **specific secret repeatedly**
* CI/CD pulls limited secret set
* Backup job accesses known keys

Suspicious behavior:

* Accessing many different secret names
* Rapid enumeration pattern
* Access across multiple vaults

---

## 4. Attacker Perspective

### 4.1 Why attackers use this technique

After initial Azure compromise, attackers:

* Enumerate secrets
* Collect credentials
* Escalate privileges
* Prepare ransomware

Secrets are a shortcut to:

* SQL databases
* Storage accounts
* Kubernetes clusters

---

### 4.2 What they try to achieve

* Credential harvesting
* Privilege escalation
* Cloud lateral movement
* Backup destruction
* Persistence
* Encryption key theft

---

### 4.3 What tools/commands attackers use

Azure CLI:

```bash
az keyvault secret list --vault-name prod-vault
az keyvault secret show --vault-name prod-vault --name secret1
```

PowerShell:

```powershell
Get-AzKeyVaultSecret -VaultName prod-vault
```

Python SDK:

```python
from azure.keyvault.secrets import SecretClient
```

Token replay using:

* Azure AD token theft
* MSAL libraries

---

### 4.4 Real-world attack examples

* **Microsoft Storm-0558** exploited cloud token weaknesses for mailbox access.
* **LAPSUS$** used cloud credential harvesting for privilege escalation.
* Multiple ransomware gangs target cloud secrets before encryption phase.

---

### 4.5 Potential Business Impact

* Full Azure tenant compromise
* Data breach
* Backup deletion
* Ransomware
* Compliance violations
* Key compromise (crypto exposure)

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm hostname and user

* Identify CallerObjectId
* Map to:

  * Azure AD user
  * Service Principal
  * Managed Identity
* Resolve source VM or IP

---

### 5.2 Check entities criticality

* Is vault production?
* Are secrets high-value?
* Is identity privileged?

---

### 5.3 Verify alert severity

Check:

* Time of activity
* Geo-location
* IP reputation
* Concurrent alerts

---

## 6. Investigation Steps

### 6.1 What questions should an analyst ask himself

1. Who is the identity?
2. Is this normal for this identity?
3. How many vaults accessed?
4. From where?
5. What secrets were accessed?
6. What happened after retrieval?

---

### 6.2 Answer the questions

Correlate:

Azure AD Sign-in Logs:

```kusto
SigninLogs
| where UserId == "<CallerObjectId>"
```

Audit role assignments:

```kusto
AzureActivity
| where OperationName contains "roleAssignment"
```

Check IP anomalies:

```kusto
SigninLogs
| summarize by IPAddress, Location
```

---

### 6.3 Major Investigations (Important Investigation steps)

1. Validate identity legitimacy
2. Review IP geolocation
3. Check device compliance
4. Check token usage pattern
5. Investigate secret sensitivity
6. Look for follow-up actions:

   * Storage access
   * SQL login attempts
   * VM deployment
   * Privilege assignment

---

### 6.4 Minor Investigations (Related Investigation steps)

* User agent analysis
* Conditional Access bypass
* MFA enforcement status
* Recent password reset
* Service principal credential creation

---

## 7. Evidence to Collect

* AzureDiagnostics logs
* Sign-in logs
* Audit logs
* Secret names accessed
* IP reputation report
* Role assignment history
* Affected vault configuration
* Token lifetime info

---

## 8. Indicators of True Positive

* Access from new country
* Access outside business hours
* High-privileged identity
* Enumeration pattern
* Multiple vault access
* Follow-up suspicious Azure activity
* User denies activity

---

## 9. Indicators of False Positive

* Known CI/CD deployment window
* Approved migration script
* Backup job execution
* Newly onboarded automation
* Azure Resource Graph AppId
* Policy Insights AppId

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

* Disable user or service principal
* Revoke refresh tokens
* Rotate all accessed secrets
* Block suspicious IP
* Remove RBAC roles

---

### 10.2 Eradication

* Investigate entry vector
* Remove malicious App registrations
* Enforce MFA
* Reset credentials
* Remove unauthorized API permissions

---

### 10.3 Recovery

* Restore secrets from backup if altered
* Rebuild compromised VMs
* Monitor for re-auth attempts
* Re-enable identity with reduced privileges

---

## 11. Mitigation & Prevention

* Enforce MFA everywhere
* Use Managed Identity instead of secret-based auth
* Enable Key Vault firewall
* Enable Private Endpoints
* Enable Defender for Cloud
* Limit secret access via RBAC
* Enable Just-in-Time access
* Monitor abnormal retrieval baseline
* Rotate secrets regularly

---

## 12. Actions an IR Should Never Do (In Context of Alert)

* Do NOT delete logs
* Do NOT rotate secrets before identifying affected systems
* Do NOT disable account without collecting evidence
* Do NOT assume service principal activity is normal
* Do NOT ignore single-vault extraction if secrets are critical

---