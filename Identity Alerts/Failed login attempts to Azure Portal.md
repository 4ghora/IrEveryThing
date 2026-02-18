## 1. Alert Name

**Failed Login Attempts to Azure Portal**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects **multiple failed authentication attempts to Azure Portal** within a defined time window, with logic to exclude cases where a successful login occurs after failures. It correlates data from:

- `SigninLogs`
- `AADNonInteractiveUserSignInLogs`

It specifically monitors:

- **Azure Portal application only**
- Excessive failed logins
- Multiple IP addresses
- No subsequent successful login

### 2.1 What Triggered the Alert

The alert is triggered when:

- Failed login attempts (`ResultType` not in success codes)
- Occur within **1 day (timeRange)**
- From:
    - ≥ 2 unique IP addresses AND ≥ 5 failed attempts
        
        **OR**
        
    - ≥ 20 failed attempts from a single IP
- No successful login afterward
- Targeting **Azure Portal (AppDisplayName = "Azure Portal")**

Example Scenario:

- User: `admin@company.com`
- 8 failed logins
- From 4 different IP addresses
- No successful login after failures
    
    → Alert triggers.
    

OR

- 25 failed attempts
- From 1 IP address
    
    → Alert triggers (possible brute force).
    

---

### 2.2 Which Security Tool Generated It

- **Microsoft Sentinel (Azure SIEM)**
- Data Source:
    - Microsoft Entra ID (formerly Azure AD)
    - `SigninLogs`
    - `AADNonInteractiveUserSignInLogs`

---

### 2.3 Why This Alert Is Important

Azure Portal access provides:

- VM management
- Storage access
- Key Vault secrets
- Role assignments
- Subscription-level administrative access

Brute force or password spraying against Azure Portal can lead to:

- Privilege escalation
- Cloud resource takeover
- Lateral movement in cloud environment

Maps to MITRE ATT&CK:

- **T1110 – Brute Force**
- **T1078 – Valid Accounts**
- **T1098 – Account Manipulation**

---

### 2.4 Define Severity? Conditions to Escalate Alert to More Severity

**Default Severity:** Medium

Escalate to High/Critical if:

- Target account is:
    - Global Administrator
    - Privileged Role Administrator
    - Subscription Owner
- Failures from:
    - Foreign countries
    - Known malicious IPs
- Impossible travel detected
- Followed by:
    - Successful login
    - Role assignment changes
    - MFA reset attempts
    - Service Principal creation
    - Resource deployment

---

## 3. Knowledge Required Before Investigation

This section is critical. Analysts must deeply understand Azure identity and authentication mechanisms.

---

### 3.1 Concepts Analyst Must Understand

### 1. Microsoft Entra ID Authentication Flow

Azure authentication involves:

- Username validation
- Password verification
- Conditional Access evaluation
- MFA challenge
- Token issuance

Understanding this helps determine:

- Whether failure is password-related
- MFA-related
- Conditional Access-related

Example ResultType Codes:

- `50053` → Account locked
- `50126` → Invalid credentials
- `50074` → MFA required
- `50076` → MFA enforced

---

### 2. ResultType & ResultDescription

These define why authentication failed.

Analyst must:

- Decode common error codes
- Identify password spray patterns
- Differentiate between:
    - User typing wrong password
    - Attacker brute forcing
    - Conditional Access block

---

### 3. Azure Portal vs Non-Interactive Sign-ins

- `SigninLogs` → Interactive logins (user login via browser)
- `AADNonInteractiveUserSignInLogs` → API / token-based logins

Attackers may:

- Attempt web login (portal)
- Use scripted authentication attempts

---

### 4. Password Spraying vs Brute Force

Brute Force:

- One account
- Many passwords
- Often from one IP

Password Spraying:

- One password
- Many accounts
- Usually distributed IPs

Indicators:

- Multiple users targeted → spraying
- One user heavily targeted → brute force

---

### 5. IPAddressCount Logic

If:

- Multiple IPs → distributed attack
- Single IP high volume → automated script

Understand:

- NAT environments
- VPN gateways
- Corporate proxies

---

### 6. Conditional Access & MFA Policies

Analyst must verify:

- Was MFA enforced?
- Was login blocked by CA?
- Was risk-based policy triggered?

---

### 7. Privileged Role Identification

Understand:

- Global Admin
- Privileged Role Admin
- App Owner
- Subscription Owner

Compromise of such accounts = high impact.

---

## 4. Attacker Perspective

---

### 4.1 Why Attackers Use This Technique

Attackers target Azure Portal because:

- It provides full cloud control
- It often contains overprivileged users
- Cloud identities are exposed publicly (UPNs predictable)

---

### 4.2 What They Try to Achieve

- Gain valid credentials
- Bypass MFA
- Deploy malicious resources
- Create backdoor accounts
- Extract secrets from Key Vault
- Disable security logging

---

### 4.3 Real-World Attack Examples

- APT29 used password spraying against cloud accounts.
- LAPSUS$ targeted cloud admin accounts.
- Microsoft reports continuous password spray attempts targeting Azure tenants globally.

---

### 4.4 Potential Business Impact

If successful:

- Data exfiltration
- Cryptomining deployment
- Ransomware staging in cloud
- Service disruption
- Regulatory penalties

---

## 5. Pre-Investigation Checklist

---

### 5.1 Confirm Hostname and User

- Identify UserPrincipalName
- Check UserId
- Verify display name resolution (GUID mapping logic in query)

---

### 5.2 Check Entities Criticality

- Is user privileged?
- Is account service account?
- Is it break-glass account?

---

### 5.3 Verify Alert Severity

Recalculate severity based on:

- Role
- IP reputation
- Country
- Follow-up activity

---

## 6. Investigation Steps

---

### 6.1 Questions Analyst Should Ask

1. Are failures from same IP or multiple IPs?
2. Is IP known malicious?
3. Is user privileged?
4. Any successful login after failures?
5. Was MFA challenged?
6. Is this normal user behavior?
7. Are multiple users targeted from same IP?

---

### 6.2 Answer the Questions

Use Sentinel queries:

Check Success After Failure:

```
SigninLogs
| where UserPrincipalName == "user@company.com"
| where ResultType == "0"
```

Check IP Reputation:

- Threat Intelligence table
- Microsoft Defender TI

Check Multiple Users from Same IP:

```
SigninLogs
| where IPAddress == "x.x.x.x"
| summarize dcount(UserPrincipalName)
```

---

## 6.3 Major Investigations (Important Steps)

1. Check if attacker succeeded later.
2. Check if account role changed.
3. Review audit logs for:
    - Role assignments
    - Service principal creation
    - Key Vault access
4. Look for impossible travel.
5. Check device compliance.
6. Review Conditional Access logs.

---

## 6.4 Minor Investigations (Related Steps)

- User recent password change?
- VPN IP?
- Corporate proxy?
- Known penetration testing?
- Account lockout events?

---

## 7. Evidence to Collect

- Full Sign-in logs
- IP addresses
- Geo-location data
- Conditional Access result
- Audit logs
- Role assignments
- MFA logs

---

## 8. Indicators of True Positive

- Multiple IP attempts
- Foreign country access
- Known malicious IP
- Privileged account targeted
- Successful login after failures
- Followed by suspicious Azure activity

---

## 9. Indicators of False Positive

- User mistyped password
- Corporate VPN IP
- Known vulnerability scan
- MFA misconfiguration
- Password recently changed

---

## 10. Incident Response Actions (If True Positive)

---

### 10.1 Containment

- Disable account
- Revoke sessions
- Reset password
- Force MFA re-registration

---

### 10.2 Eradication

- Remove malicious role assignments
- Delete rogue service principals
- Remove unauthorized resources

---

### 10.3 Recovery

- Re-enable account securely
- Audit all Azure activity
- Monitor closely for 7–14 days

---

## 11. Mitigation & Prevention

- Enforce MFA for all users
- Enforce Conditional Access:
    - Block legacy auth
    - Geo restrictions
- Implement Azure AD Identity Protection
- Enable Smart Lockout
- Use passwordless authentication
- Monitor high-risk sign-ins
- Restrict Global Admin count
- Implement Privileged Identity Management (PIM)

---
