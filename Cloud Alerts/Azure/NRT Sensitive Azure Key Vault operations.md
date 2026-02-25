## 1. Alert Name

**NRT Sensitive Azure Key Vault Operations**

---

## 2. Alert Description (Detection Logic Explanation)

### 2.1 What Triggered the Alert

This alert is triggered when **successful sensitive operations** are performed on an Azure Key Vault resource.

The query monitors `AzureDiagnostics` logs and looks for:

* `ResourceType =~ "VAULTS"`
* `ResultType =~ "Success"`
* `OperationName` in:

  * `VaultDelete`
  * `KeyDelete`
  * `SecretDelete`
  * `SecretPurge`
  * `KeyPurge`
  * `SecretBackup`
  * `KeyBackup`

The alert aggregates:

* User UPN
* AAD Object ID
* Caller IP
* Request URI
* Time range of activity

Example Trigger Scenario:

* A user successfully performs `SecretBackup` on multiple secrets within a short timeframe.
* An attacker purges (`SecretPurge`) deleted secrets to permanently remove forensic evidence.
* A compromised admin deletes an entire vault (`VaultDelete`).

This is **Near Real-Time (NRT)** detection, meaning response time must be fast.

---

### 2.2 Which Security Tool Generated It

* Log Source: Azure Key Vault logs via `AzureDiagnostics`
* Platform: Microsoft Microsoft Sentinel
* Data Source: Azure Key Vault diagnostic logs

---

### 2.3 Why This Alert Is Important

Azure Key Vault stores:

* Application secrets
* Database credentials
* API keys
* Certificates
* Encryption keys

If an attacker:

* Backs up secrets → Credential exfiltration
* Purges secrets → Anti-forensics
* Deletes vault → Service outage
* Deletes encryption keys → Data loss

This alert directly protects **confidentiality, integrity, and availability**.

Mapped to MITRE ATT&CK:

* Credential Access – T1552 (Unsecured Credentials)
* Impact – T1485 (Data Destruction)
* Defense Evasion – T1070 (Indicator Removal)
* Exfiltration – T1041

---

### 2.4 Define Severity & Escalation Conditions

**Default Severity: High**

Escalate to Critical if:

* Operation = `VaultDelete`
* `SecretBackup` or `KeyBackup` performed by non-admin
* Caller IP from foreign country or TOR/VPN
* Multiple sensitive operations in short time
* Privileged identity involved
* Account recently added to privileged role
* Activity outside business hours

Downgrade if:

* Change ticket exists
* Activity from approved automation/service principal
* Known maintenance window

---

## 3. Knowledge Required Before Investigation

This section is critical for Tier 1–3 analysts.

---

### 3.1 Concepts Analyst Must Understand

#### 1. Azure Key Vault Architecture

Azure Key Vault is a cloud service for securely storing:

* Secrets (passwords, tokens)
* Keys (RSA, EC)
* Certificates

There are two permission models:

* Access Policies (legacy)
* Azure RBAC (recommended)

Important:

* Soft Delete: Deleted items can be recovered.
* Purge: Permanently removes deleted item.
* Backup: Exports secret/key material (potential exfil path).

---

#### 2. Operation Types in Alert

| Operation    | Risk Explanation                      |
| ------------ | ------------------------------------- |
| VaultDelete  | Entire vault removed → service outage |
| SecretDelete | Could be malicious cleanup            |
| SecretPurge  | Permanent destruction                 |
| SecretBackup | Possible secret exfiltration          |
| KeyBackup    | Crypto material theft                 |
| KeyPurge     | Destruction of encryption keys        |

Example:
If an attacker deletes + purges secrets, they are preventing incident recovery.

---

#### 3. Azure AD Identity Concepts

Logs include:

* `identity_claim_upn_s` (UserPrincipalName)
* `identity_claim_http_schemas...objectidentifier_g` (AAD Object ID)

Understand:

* Difference between User vs Service Principal
* Privileged roles:

  * Global Administrator
  * Key Vault Administrator
  * Owner

Investigate via:

* `AuditLogs`
* `SigninLogs`

---

#### 4. AzureDiagnostics Log Structure

Table: `AzureDiagnostics`

Key Fields:

* `OperationName`
* `CallerIPAddress`
* `requestUri_s`
* `ResultType`
* `TimeGenerated`

Analyst must understand:

* API-based access
* Portal access
* Automation-based calls

---

#### 5. Key Vault Soft Delete & Purge Protection

If Purge Protection is disabled:

* Attackers can permanently destroy secrets.
* Recovery becomes impossible.

Check vault configuration.

---

#### 6. Lateral Movement & Cloud Kill Chain

After initial compromise:

1. Attacker gains Azure AD access.
2. Enumerates resources.
3. Targets Key Vault.
4. Extracts secrets.
5. Uses secrets for:

   * Database access
   * Application impersonation
   * Further cloud pivoting

---

## 4. Attacker Perspective

---

### 4.1 Why Attackers Use This Technique

Because Key Vault is a central credential repository.

Compromise here = compromise everywhere.

---

### 4.2 What They Try to Achieve

* Steal database credentials
* Extract API keys
* Obtain signing certificates
* Destroy encryption keys (ransomware cloud impact)
* Remove evidence of compromise

---

### 4.3 Tools / Commands Attackers Use

Azure CLI:

```
az keyvault secret backup --vault-name <vault> --name <secret>
az keyvault secret delete
az keyvault secret purge
```

PowerShell:

```
Backup-AzKeyVaultSecret
Remove-AzKeyVaultSecret
```

Direct REST API calls:

```
DELETE https://<vault>.vault.azure.net/secrets/<name>
```

---

### 4.4 Real-World Attack Examples

* Microsoft reported cloud credential theft campaigns targeting Key Vault.
* LAPSUS$ exploited cloud misconfigurations to extract secrets.
* Storm-0558 abused stolen signing keys in Azure-related incidents.

---

### 4.5 Potential Business Impact

* Application outages
* Data breach
* Regulatory penalties
* Loss of encryption keys
* Business continuity disruption

---

## 5. Pre-Investigation Checklist

---

### 5.1 Confirm Hostname and User

* Validate UPN
* Validate AAD Object ID
* Confirm if user or service principal
* Validate Caller IP ownership

---

### 5.2 Check Entity Criticality

* Is vault production?
* Does it store encryption keys?
* Is it used by customer-facing apps?

---

### 5.3 Verify Alert Severity

* Operation type
* Privilege level
* Geolocation anomaly
* Volume of actions

---

## 6. Investigation Steps

---

### 6.1 Questions Analyst Must Ask

1. Is the identity expected to perform this operation?
2. Is there a change ticket?
3. Is IP location normal?
4. Were there suspicious sign-ins before this?
5. Was privilege recently granted?
6. Are multiple vaults impacted?
7. Is there evidence of secret exfiltration?

---

### 6.2 Answer the Questions (How to Validate)

#### Check Sign-in History

```kql
SigninLogs
| where UserPrincipalName == "<UPN>"
| where TimeGenerated between (StartTimeUtc - 2h .. EndTimeUtc + 2h)
```

Look for:

* Impossible travel
* MFA bypass
* Risky sign-ins

---

#### Check Privilege Escalation

```kql
AuditLogs
| where OperationName contains "Add member to role"
```

---

#### Check Volume Pattern

```kql
AzureDiagnostics
| where ResourceType == "VAULTS"
| summarize count() by OperationName, bin(TimeGenerated, 5m)
```

---

### 6.3 Major Investigations

1. Identity compromise validation
2. Secret backup verification
3. RBAC role assignment review
4. Cross-resource pivot (storage, SQL, app service)
5. IP reputation check
6. Timeline reconstruction

---

### 6.4 Minor Investigations

* Check if automation account triggered it
* Review deployment logs
* Validate maintenance window
* Check if activity aligns with CI/CD pipeline

---

## 7. Evidence to Collect

* AzureDiagnostics logs
* SigninLogs
* AuditLogs
* RBAC assignments
* Vault configuration (Purge Protection status)
* Exported secret metadata
* IP geolocation data
* Conditional Access logs

---

## 8. Indicators of True Positive

* SecretBackup by non-admin
* Purge operation shortly after delete
* Suspicious IP
* MFA failure before success
* Privilege granted shortly before operation
* Multiple vault access in short period
* Activity outside working hours
* Service principal token abuse

---

## 9. Indicators of False Positive

* Approved maintenance
* Key rotation process
* CI/CD automation
* Backup script execution
* Security team performing test
* Documented vault decommission

---

## 10. Incident Response Actions (If True Positive)

---

### 10.1 Containment

* Disable user/service principal
* Revoke sessions
* Rotate all affected secrets
* Block suspicious IP
* Lock down vault access

---

### 10.2 Eradication

* Remove unauthorized RBAC assignments
* Reset credentials
* Enable Purge Protection
* Enforce MFA & Conditional Access

---

### 10.3 Recovery

* Restore deleted secrets (if soft delete enabled)
* Redeploy affected applications
* Validate encryption integrity
* Monitor for persistence

---

## 11. Mitigation & Prevention

* Enable Purge Protection
* Use RBAC over access policies
* Enable Defender for Cloud
* Implement Just-In-Time access
* Monitor SecretBackup operations specifically
* Conditional Access for privileged roles
* Log analytics alert tuning
* Regular secret rotation
* Use managed identities instead of secrets

---

## 12. Actions an IR Should Never Do (In Context of Alert)

* Do NOT immediately purge secrets during investigation
* Do NOT disable vault before collecting logs
* Do NOT reset credentials before identifying scope
* Do NOT ignore backup operations
* Do NOT assume admin activity is legitimate
* Do NOT notify user before validating compromise
* Do NOT delete forensic logs

---