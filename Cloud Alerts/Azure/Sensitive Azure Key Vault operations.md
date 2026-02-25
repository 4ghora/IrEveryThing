## 1. Alert Name

**Sensitive Azure Key Vault Operations**

---

## 2. Alert Description (Detection Logic Explanation)

### 2.1 What Triggered the Alert

This alert is triggered when **successful high-risk operations** are executed against an Azure Key Vault.

The detection logic:

* Monitors `AzureDiagnostics`
* Filters:

  * `ResourceType =~ "VAULTS"`
  * `ResultType =~ "Success"`
* Matches operation names against:

```
["VaultDelete", "KeyDelete", "SecretDelete", 
 "SecretPurge", "KeyPurge", 
 "SecretBackup", "KeyBackup"]
```

The query aggregates:

* User Principal Name (identity_claim_upn_s)
* Azure AD Object ID
* Caller IP address
* Client information
* Operation list
* Request URI
* Time window (StartTimeUtc → EndTimeUtc)

Example triggering scenarios:

1. A user runs:

   ```
   az keyvault secret backup --vault-name prod-kv --name db-password
   ```

   → `SecretBackup` logged as Success.

2. A privileged admin deletes an entire vault:

   ```
   az keyvault delete --name prod-kv
   ```

   → `VaultDelete` logged as Success.

3. A service principal purges a key after deletion:
   → `KeyPurge` event appears.

The alert only fires if the operation **succeeded**, which makes it high fidelity.

---

### 2.2 Which Security Tool Generated It

* Data source: AzureDiagnostics logs
* SIEM: Microsoft Sentinel
* Cloud platform: Microsoft Azure
* Targeted service: Azure Key Vault

---

### 2.3 Why This Alert Is Important

Azure Key Vault stores:

* Database credentials
* Storage account keys
* Application secrets
* Encryption keys
* Certificates

Sensitive operations such as backup, purge, or delete can indicate:

* Credential exfiltration (MITRE T1552)
* Valid account abuse (T1078)
* Cloud privilege escalation
* Ransomware preparation
* Destructive insider activity (T1485)
* Defense evasion via key destruction (T1562)

If an attacker gains Azure AD access, Key Vault is often one of the first high-value targets.

---

### 2.4 Define Severity & Escalation Conditions

**Default Severity: High**

Escalate to Critical if:

* `VaultDelete` or `SecretPurge` on production vault
* Backup operations from unfamiliar IP
* Privileged account involved (Global Admin, Key Vault Admin)
* Activity outside business hours
* Correlation with risky Azure AD sign-in
* Multiple secrets backed up within short window
* Followed by suspicious resource creation

Lower to Medium only if:

* Confirmed change ticket
* Automation account performing scheduled task
* Approved decommission activity

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts Analyst Must Understand

This section is critical before beginning investigation.

---

### A. Azure Key Vault Architecture

Azure Key Vault is a managed secrets store.

Objects stored:

1. **Secrets** – Passwords, API keys, connection strings
2. **Keys** – Used for encryption/decryption
3. **Certificates** – TLS certificates

There are two access models:

* Vault Access Policies (legacy)
* Azure RBAC (recommended)

Soft-delete behavior:

* `SecretDelete` → moves secret to deleted state.
* `SecretPurge` → permanently removes it.

If purge protection is disabled:
Attacker can permanently destroy encryption keys.

Example:

If an attacker:

1. Deletes a disk encryption key.
2. Purges it.
3. Azure VM encrypted with that key becomes unrecoverable.

---

### B. Control Plane vs Data Plane

Key Vault operations occur in two planes:

Control plane:

* Vault creation
* Vault deletion
* RBAC changes

Data plane:

* Secret access
* Key backup
* Secret deletion

Your query focuses on **data plane operations**.

Understanding this difference is important to correlate with:

* AzureActivity (control plane)
* AzureDiagnostics (data plane)

---

### C. Azure AD Identity & Service Principals

Alert fields:

* identity_claim_upn_s → human user
* AadUserId → Azure AD object ID
* clientInfo_s → tool used
* CallerIPAddress → origin

Possibilities:

1. Human interactive login (Azure Portal, CLI)
2. Service Principal
3. Managed Identity
4. Automation Account

Example:

If UPN is blank but object ID exists → likely service principal.
If clientInfo contains “AzureCLI” → manual CLI use.
If clientInfo contains “AzurePowerShell” → scripted automation.

---

### D. Secret Backup Risk

`SecretBackup` and `KeyBackup` are especially dangerous.

Backup command exports encrypted blob:

```
az keyvault secret backup
```

Attacker can:

* Download backup
* Restore into their own tenant
* Extract secrets offline

This is credential exfiltration via API.

---

### E. Privilege Escalation Context

Check if attacker:

1. Added themselves to Key Vault Admin role.
2. Elevated via Privileged Identity Management.
3. Used stolen refresh token.

Investigate Azure AD Audit Logs for role assignment changes.

---

### F. Logging Sources

You must correlate across:

* SignInLogs
* AuditLogs
* AzureActivity
* AzureDiagnostics
* ConditionalAccessLogs

Without correlation, investigation is incomplete.

---

## 4. Attacker Perspective

### 4.1 Why Attackers Use This Technique

Once inside Azure AD, attacker priorities:

1. Persistence
2. Lateral movement
3. Credential harvesting
4. Data destruction

Key Vault centralizes secrets → high-value target.

---

### 4.2 What They Try to Achieve

* Extract database credentials
* Extract storage account keys
* Export encryption keys
* Disable encryption
* Sabotage environment
* Prepare ransomware detonation

---

### 4.3 What Tools / Commands Attackers Use

Azure CLI:

```
az login
az keyvault secret list
az keyvault secret backup
az keyvault delete
```

Azure PowerShell:

```
Backup-AzKeyVaultSecret
Remove-AzKeyVault
```

REST API:

```
POST https://{vault}.vault.azure.net/secrets/{name}/backup
```

Token abuse:

* Stolen OAuth token replay
* Refresh token replay
* Service principal secret abuse

---

### 4.4 Real-World Attack Examples

1. Cloud ransomware groups stealing secrets before encryption.
2. OAuth phishing campaign → Azure token theft → Key Vault exfiltration.
3. Insider deletes encryption keys before resignation.
4. DevOps pipeline compromise → automated secret extraction.

---

### 4.5 Potential Business Impact

* Total cloud compromise
* Credential leakage
* Production outage
* Encryption key loss
* Legal/regulatory impact
* Financial loss

If DB credentials exposed:
Complete data exfiltration possible.

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm Hostname and User

* Extract UPN
* Extract AAD Object ID
* Determine human vs service principal
* Validate caller IP

---

### 5.2 Check Entities Criticality

* Is vault production?
* Does it store privileged secrets?
* Does it store encryption keys?
* Business owner of vault?

---

### 5.3 Verify Alert Severity

* Operation type
* Time window
* Privilege level
* IP risk score
* Multiple correlated alerts?

---

## 6. Investigation Steps

### 6.1 Questions Analyst Should Ask

1. Who performed the action?
2. Was sign-in suspicious?
3. Is IP trusted?
4. Was privilege recently elevated?
5. Is this during maintenance?
6. Were multiple secrets accessed?
7. Was backup file downloaded?
8. Did activity expand to other resources?

---

### 6.2 Answer the Questions

Check Sign-in behavior:

```kql
SigninLogs
| where UserPrincipalName == "<UPN>"
| where TimeGenerated between (StartTimeUtc-2h .. EndTimeUtc+2h)
```

Look for:

* RiskLevelHigh
* MFA failure
* Unusual country
* Anonymous IP

---

Check role assignment:

```kql
AuditLogs
| where TargetResources contains "<UPN>"
| where OperationName contains "Add member to role"
```

---

Check secret access volume:

```kql
AzureDiagnostics
| where identity_claim_upn_s == "<UPN>"
| summarize count() by OperationName
```

---

### 6.3 Major Investigations

* Correlate with risky login
* Verify Conditional Access evaluation
* Check for mass secret backup
* Check for purge after delete
* Verify service principal secret age
* Inspect AzureActivity for vault deletion
* Identify if secrets used post-backup
* Investigate lateral movement

---

### 6.4 Minor Investigations

* Validate IP in corporate IP list
* Confirm change ticket
* Check DevOps job history
* Review automation account logs
* Validate clientInfo tool usage

---

## 7. Evidence to Collect

* SignInLogs
* AuditLogs
* AzureDiagnostics raw events
* AzureActivity
* RBAC assignments
* Conditional Access logs
* IP reputation lookup
* Secret names affected
* Service principal credentials
* Device ID and session ID

---

## 8. Indicators of True Positive

* External IP not seen before
* Multiple SecretBackup operations
* Privilege escalation before vault access
* High-risk sign-in event
* Production vault targeted
* Purge events present
* Token replay indicators
* Service principal misuse
* Impossible travel sign-in

---

## 9. Indicators of False Positive

* Approved vault decommission
* Security team backup exercise
* Scheduled automation job
* DevOps pipeline activity
* Known migration activity

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

* Disable user or service principal
* Revoke refresh tokens
* Block suspicious IP
* Remove elevated RBAC role
* Enable purge protection
* Isolate compromised workload

---

### 10.2 Eradication

* Rotate all secrets in vault
* Regenerate encryption keys
* Reset service principal secrets
* Review RBAC roles tenant-wide
* Hunt for persistence mechanisms

---

### 10.3 Recovery

* Restore secrets from clean backup
* Re-enable production apps
* Monitor sign-ins closely
* Conduct tenant-wide compromise assessment
* Implement additional Conditional Access controls

---

## 11. Mitigation & Prevention

* Enable purge protection
* Enforce MFA on privileged roles
* Implement PIM for JIT access
* Restrict vault access via Private Endpoint
* Monitor SecretBackup operations
* Block legacy authentication
* Rotate service principal credentials regularly
* Apply Conditional Access based on device compliance

---

## 12. Actions an IR Should Never Do (In Context of Alert)

* Never purge without evidence collection
* Never reset password before log capture
* Never assume admin action is legitimate
* Never close alert without sign-in validation
* Never ignore backup operations
* Never rotate secrets before scoping impact
* Never disable logging during investigation

---