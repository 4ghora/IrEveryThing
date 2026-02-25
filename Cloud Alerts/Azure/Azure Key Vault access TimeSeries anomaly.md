# 1. Alert Name

**Azure Key Vault Access TimeSeries Anomaly**

---

# 2. Alert Description (Detection Logic Explanation)

## 2.1 What Triggered the Alert

This alert is triggered when:

* There is an **anomalous increase** in successful `SecretGet`, `KeyGet`, or `VaultGet` operations.
* The anomaly is detected using `series_decompose_anomalies()` on a **14-day historical baseline**.
* The anomaly score exceeds **3 (scorethreshold)**.
* The baseline count is greater than **25 events** (to avoid low-volume noise).
* The anomaly occurred within the **last 2 days**.

Detection logic flow:

1. Pull 14 days of Azure Key Vault logs (`AzureDiagnostics`).
2. Filter only:

   * `ResourceType == VAULTS`
   * `ResultType == Success`
   * Operation in (`SecretGet`, `KeyGet`, `VaultGet`)
3. Exclude known Azure system AppID (`509e4652-da8d-478d-a730-e9d4a1996ca4`).
4. Build a time series per **CallerIPAddress**.
5. Detect anomalies via linear regression model (`linefit`).
6. Identify anomaly hours with unusually high access volume.
7. Join back with raw logs to extract detailed identity, request URI, and object info.

### Example Scenario

* A service principal normally performs 50 `SecretGet` operations daily.
* Suddenly, it performs 900 in one hour.
* Baseline = 60, Current = 900.
* Anomaly score > 3 → Alert triggered.

---

## 2.2 Which Security Tool Generated It

* Microsoft Sentinel (SIEM)
* Data source: AzureDiagnostics logs
* Analytics rule using KQL with time-series anomaly detection

---

## 2.3 Why This Alert is Important

Azure Key Vault stores:

* API keys
* Database credentials
* Encryption keys
* Certificates
* OAuth secrets

A spike in secret retrieval often indicates:

* Credential dumping from cloud vault
* Service principal abuse
* Compromised automation identity
* Post-exploitation data harvesting

This aligns with MITRE ATT&CK:

* **T1552.004** – Credentials in Cloud Storage
* **T1528** – Steal Application Access Token
* **T1078** – Valid Accounts
* **T1003 (Cloud variant)** – Credential Access

---

## 2.4 Define Severity? Conditions to Escalate

### Medium Severity:

* Known automation account
* Change window in progress
* No external IP involvement

### High Severity:

* Unusual IP address
* New user/service principal
* Accessing many different secrets
* Occurs outside business hours
* Followed by suspicious login activity

### Critical Severity:

* Privileged secrets accessed (Prod DB, encryption keys)
* External IP + unfamiliar device
* Lateral movement observed after secret access
* Signs of exfiltration

---

# 3. Knowledge Required Before Investigation

This section is critical.

---

## 3.1 Concepts Analyst Must Understand

### 1. Azure Key Vault Architecture

Azure Key Vault is a cloud service used to securely store:

* Secrets
* Keys
* Certificates

Two access models:

1. Access Policies
2. Azure RBAC (Role-Based Access Control)

Important roles:

* Key Vault Administrator
* Key Vault Secrets User
* Key Vault Reader

Analyst must understand:

* Who has access?
* Via RBAC or access policy?
* Is it human or service principal?

---

### 2. Service Principals & Managed Identities

Most Key Vault access is performed by:

* Service principals
* Azure managed identities
* Automation accounts
* CI/CD pipelines

Example:

* Azure DevOps pipeline retrieving DB password.

If compromised:

* Attacker can silently extract secrets.

---

### 3. AzureDiagnostics Table Structure

Important fields:

* `OperationName`
* `CallerIPAddress`
* `identity_claim_oid_g`
* `identity_claim_upn_s`
* `clientInfo_s`
* `requestUri_s`
* `id_s`

Analyst must know how to pivot:

```kql
AzureDiagnostics
| where ResourceType == "VAULTS"
| where CallerIPAddress == "X.X.X.X"
```

---

### 4. Time Series Anomaly Detection

The query uses:

```kql
series_decompose_anomalies()
```

Meaning:

* It detects statistical deviations from historical pattern.
* Not rule-based.
* It adapts to seasonal patterns.

Important:
An anomaly ≠ malicious.
It means statistically unusual behavior.

---

### 5. Azure Identity Logs Correlation

You must correlate with:

* SigninLogs
* AuditLogs
* AADServicePrincipalSignInLogs

To check:

* Was identity recently created?
* Was MFA bypassed?
* Was password reset?

---

# 4. Attacker Perspective

## 4.1 Why Attackers Use This Technique

Once attackers gain:

* Azure AD account
* Service principal credentials
* OAuth token

Their next goal is:

→ Dump secrets from Key Vault.

---

## 4.2 What They Try to Achieve

* Steal database passwords
* Obtain API tokens
* Extract encryption keys
* Access storage accounts
* Deploy ransomware

This is often post-exploitation.

---

## 4.3 Tools/Commands Attackers Use

### Azure CLI

```bash
az keyvault secret list --vault-name ProdVault
az keyvault secret show --name DBPassword
```

### PowerShell

```powershell
Get-AzKeyVaultSecret
```

### REST API

Direct HTTPS calls with stolen token.

---

## 4.4 Real-World Attack Examples

* **Microsoft Storm-0558 token abuse case (2023)**
  Attackers used stolen signing keys to access cloud services.

* **Uber breach (2022)**
  Attackers escalated privileges and accessed internal secrets.

* **SolarWinds supply chain compromise (2020)**
  Compromised credentials used to access cloud secrets.

---

## 4.5 Potential Business Impact

* Production database compromise
* Customer PII exposure
* Encryption key theft
* Ransomware deployment
* Regulatory fines
* Reputation damage

---

# 5. Pre-Investigation Checklist

## 5.1 Confirm Hostname and User

* Identify CallerObjectId
* Map to user or service principal
* Determine device origin via SigninLogs

---

## 5.2 Check Entities Criticality

* Is this production vault?
* Does it contain privileged secrets?
* Is identity high-privileged?

---

## 5.3 Verify Alert Severity

* Check anomaly score
* Check volume difference
* Check IP origin

---

# 6. Investigation Steps

---

## 6.1 Questions Analyst Should Ask

1. Is Caller IP known?
2. Is identity legitimate?
3. Is access volume abnormal compared to past?
4. What secrets were accessed?
5. Was there subsequent suspicious activity?
6. Was there lateral movement?

---

## 6.2 Answer the Questions

### Check IP Reputation

```kql
SigninLogs
| where IPAddress == "X.X.X.X"
```

Check:

* Geo-location
* ASN
* TOR/proxy usage

---

### Check Identity Behavior

```kql
SigninLogs
| where UserPrincipalName == "user@domain.com"
| summarize count() by AppDisplayName
```

---

### Check Secrets Accessed

```kql
AzureDiagnostics
| where OperationName == "SecretGet"
| summarize count() by requestUri_s
```

Look for:

* Bulk secret retrieval
* Enumeration pattern

---

## 6.3 Major Investigations

1. Correlate with sign-in anomalies.
2. Check if token was issued recently.
3. Verify conditional access logs.
4. Check if new service principal created.
5. Look for privilege escalation before anomaly.
6. Investigate post-secret activity (DB login attempts).

---

## 6.4 Minor Investigations

* Check maintenance window
* Validate deployment schedules
* Confirm with DevOps team
* Review recent Azure automation changes

---

# 7. Evidence to Collect

* AzureDiagnostics logs (full 14 days)
* SigninLogs
* AAD AuditLogs
* List of secrets accessed
* IP reputation data
* RBAC role assignments
* Token issuance logs

---

# 8. Indicators of True Positive

* New IP never seen before
* Service principal used outside normal hours
* Accessing large number of different secrets
* Subsequent DB login attempts
* Secret exfiltration followed by data download
* Identity created recently

---

# 9. Indicators of False Positive

* Scheduled deployment job
* New microservice rollout
* Password rotation automation
* Azure DevOps pipeline activity
* Backup/DR test

---

# 10. Incident Response Actions (If True Positive)

---

## 10.1 Containment

* Disable compromised account
* Revoke active tokens
* Rotate all accessed secrets
* Block suspicious IP

---

## 10.2 Eradication

* Remove malicious service principals
* Reconfigure RBAC
* Reset credentials
* Remove persistence

---

## 10.3 Recovery

* Redeploy services with new secrets
* Validate no unauthorized DB access
* Enable enhanced logging
* Conduct environment-wide credential review

---

# 11. Mitigation & Prevention

* Enforce least privilege
* Enable Key Vault firewall rules
* Use Private Endpoints
* Enable Soft Delete + Purge Protection
* Monitor high-volume `SecretGet`
* Enable Conditional Access
* Rotate secrets automatically
* Use Managed Identities instead of stored credentials

---

# 12. Actions an IR Should Never Do (In Context of Alert)

* Never delete Key Vault logs prematurely
* Never rotate secrets before understanding scope
* Never disable production service principal without impact analysis
* Never assume anomaly = compromise
* Never ignore small anomalies in high-value vaults
* Never rely only on IP reputation

---