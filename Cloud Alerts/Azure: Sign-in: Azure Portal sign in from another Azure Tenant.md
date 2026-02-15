## 1. Alert Name

**Azure Portal sign in from another Azure Tenant**

---

## 2. Alert Description (Detection Logic Explanation)

### 2.1 What triggered the alert

- A user successfully authenticated to the **Azure Portal** (`AppDisplayName = "Azure Portal"`) from an **IP address associated with Azure ranges** that does **not belong to their home tenant**.
- Detection logic focuses on **cross-tenant logins**, where `HomeTenantId != ResourceTenantId` and `ResourceTenantId` matches the monitored tenant (`AADTenantId`).
- The alert specifically filters for IPs within **Microsoft-managed Azure IP ranges**, using the `ServiceTags_Public.json` feed to ensure only valid Azure addresses are considered.

> Example: A user with `user@companyA.com` logs into an Azure subscription owned by `companyB.com`. This is abnormal unless there’s a legitimate cross-tenant access scenario like B2B collaboration.
> 

### 2.2 Which security tool generated it

- **Primary source:** Azure **SigninLogs** (Azure AD Audit Logs)
- **SIEM layer:** The provided KQL query is intended for **Microsoft Sentinel** or any SIEM ingesting Azure AD logs.

### 2.3 Why this alert is important

- Cross-tenant logins may indicate **identity compromise** or **malicious lateral movement**.
- Attackers often attempt to use valid Azure credentials from compromised accounts to escalate privileges in other tenants (`T1190`, `T1078` – Valid Accounts, MITRE ATT&CK).
- Alerts are rare; therefore, each event could represent a **potential high-risk incident**, especially for privileged users.

### 2.4 Severity

- **Low:** Trusted B2B collaboration user or service principal; no sensitive resources accessed.
- **Medium:** Regular user logging in from an external tenant unexpectedly; sensitive resources minimally affected.
- **High/Critical:**
    - Privileged account (Global Admin, Subscription Owner) logs in from an external tenant.
    - Multiple cross-tenant logins from the same user/IP.
    - Logins followed by suspicious activity like RBAC changes or resource deployments.

---

## 3. Knowledge Required Before Investigation

1. **Azure Tenants & HomeTenantId vs ResourceTenantId:**
    - `HomeTenantId` = tenant where the user account was created.
    - `ResourceTenantId` = tenant being accessed.
    - Legitimate B2B collaborations or guest accounts may trigger this, so context is critical.
2. **Azure IP Ranges:**
    - Azure services use specific IP ranges. Understanding ranges prevents misattributing legitimate internal traffic as external.
3. **AppDisplayName (Azure Portal) vs Other Apps:**
    - This alert is scoped to **portal access**, indicating **potential administrative activity** rather than standard API calls.
4. **Login metadata understanding:**
    - `UserAgent`, `Location`, `IPAddress` are key for geolocation and environment correlation.

> Example: A U.S.-based user suddenly logs in from `West Europe` Azure IP—could be suspicious if no VPN/B2B relationship exists.
> 

---

## 4. Attacker Perspective

### 4.1 Why attackers use this technique

- Exploit **valid credentials** from one tenant to pivot into another (`T1078`).
- Abuse **cross-tenant collaboration** to gain access to high-value subscriptions or resources.

### 4.2 What they try to achieve

- Access sensitive data (storage accounts, Key Vaults).
- Deploy malware or exfiltrate data via Azure services.
- Establish **persistent backdoors** using service principals or automation accounts.

### 4.3 Real-world attack examples

- **Akamai & Microsoft B2B compromise:** Attackers used compromised guest accounts to move laterally into enterprise tenants.
- **APT29 (Cozy Bear):** Leveraged valid accounts to access cloud resources in cross-tenant scenarios.

### 4.4 Potential Business Impact

- Data theft (Blob, SQL, Key Vault).
- Unauthorized deployment of resources leading to financial loss.
- Regulatory impact due to data exposure across tenants.

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm hostname and user

- Verify `UserPrincipalName` and associated `AccountName`.
- Validate device and IP (`IPAddress`, `Location`, `UserAgent`).

### 5.2 Check entities criticality

- Identify if the user is **privileged** (Global Admin, Owner, Contributor).
- Determine resource sensitivity (critical subscriptions, Key Vaults, databases).

### 5.3 Verify alert severity

- Confirm cross-tenant login is **unexpected** and not due to legitimate B2B or partner collaboration.

---

## 6. Investigation Steps

### 6.1 What questions should an analyst ask

1. Is the login consistent with user role, location, and working hours?
2. Is the source IP associated with legitimate Azure services or attacker infrastructure?
3. Has this user accessed sensitive resources after the login?
4. Are there multiple logins from different tenants/IPs?
5. Any follow-on suspicious activities (RBAC changes, service principal creation, resource deployments)?

### 6.2 Answers

- Correlate `SigninLogs` with **conditional access policies**, **B2B invitations**, and **Privileged Identity Management logs**.
- Check **GeoIP** and **VPN logs** to rule out legitimate location.
- Review **activity logs**: `AzureActivity`, `AuditLogs`, `KeyVaultAccessLogs`.

### 6.3 Major Investigations (Important)

1. **Verify cross-tenant login:**
    
    ```
    SigninLogs
    | where UserPrincipalName == "<User>"
    | where HomeTenantId != ResourceTenantId
    | summarize count(), min(TimeGenerated), max(TimeGenerated) by IPAddress, Location
    ```
    
2. **Check for post-login administrative actions:**
    
    ```
    AzureActivity
    | where Caller == "<User>"
    | where OperationName has_any ("Add role assignment", "Create VM", "Create Service Principal")
    ```
    
3. **Correlate with EDR alerts:** Look for suspicious PowerShell, RDP, or network connections post-login.
4. **Check for suspicious service principals or managed identities created** in the last 24–72 hours.

### 6.4 Minor Investigations (Related)

- Check `UserAgent` anomalies.
- Validate if IP is part of legitimate corporate Azure tenant ranges.
- Review historical login patterns to spot unusual activity trends.

---

## 7. Evidence to Collect

- `SigninLogs` entries with full metadata.
- AzureActivity logs for sensitive actions.
- Network connection logs (EDR/SIEM).
- Identity metadata (privileges, group memberships, MFA status).

---

## 8. Indicators of True Positive

- Successful login from **foreign tenant** without prior B2B relationship.
- Access to **sensitive resources** immediately after login.
- Creation of **new service principals** or role escalations.
- Suspicious `UserAgent` or IP geolocation mismatch.
- Multiple tenants/IPs accessed in short timeframe.

---

## 9. Indicators of False Positive

- Legitimate B2B guest user or cross-tenant collaboration account.
- Managed automation account accessing resources.
- VPN or ExpressRoute IP address mapped to a known internal range.
- MFA challenge passed legitimately for cross-tenant access.

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

- Disable compromised user accounts.
- Block suspicious IP addresses at Azure AD Conditional Access.
- Revoke active sessions via Azure AD    

### 10.2 Eradication

- Remove unauthorized service principals, app registrations, or roles.
- Rotate affected credentials and enforce MFA.
- Conduct threat hunting across other tenants for similar compromise.

### 10.3 Recovery

- Reinstate accounts after verification.
- Monitor logs for repeat or lateral access attempts.
- Ensure security posture: Conditional Access, Privileged Identity Management, logging enabled.

---

## 11. Mitigation & Prevention

- Enforce **Conditional Access policies** restricting cross-tenant logins.
- Require **MFA for all administrative users**, including guest accounts.
- Enable **Azure AD Identity Protection** for risk-based sign-in analysis.
- Audit **B2B collaboration settings** regularly.
- Regularly update **Azure Service Tag IP lists** in SIEM queries.

---
