## 1. Alert Name

**Azure AD Role Assignment Outside Privileged Identity Management (PIM)**

---

## 2. Alert Description (Detection Logic Explanation)

This alert detects when a user is **added to an Azure AD role outside of Privileged Identity Management (PIM)**. It identifies role assignments performed directly through Azure AD role management instead of approved, time-bound, and audited elevation via PIM.

### 2.1 What triggered the alert

The query monitors:

- `AuditLogs`
- `Category = "RoleManagement"`
- `OperationName` containing:
    - `"Add member to role outside of PIM"` OR
    - `"Add member to role"` where:
        - `LoggedByService = "Core Directory"`
        - `Identity != "MS-PIM"` and `Identity != "MS-PIM-Fairfax"`

This means:

- A role assignment occurred
- It was not initiated via Microsoft PIM service
- It was performed directly by a user or service principal

**Example Trigger Scenario:**

- A Global Administrator manually adds a user to:
    - Global Administrator
    - Privileged Role Administrator
    - Application Administrator
- The assignment is permanent and not time-bound
- The action is logged under Core Directory, not MS-PIM

This is high-risk because it bypasses approval workflows and auditing controls.

---

### 2.2 Which security tool generated it

- Data Source: **Azure AD AuditLogs**
- Typically detected via:
    - **Microsoft Sentinel**
    - **Microsoft Defender for Cloud Apps**
    - Custom SIEM using Azure AD logs

The query format strongly indicates **Microsoft Sentinel (KQL)**.

---

### 2.3 Why this alert is important

Role assignments directly impact **tenant-wide privileges**.

If an attacker gains control of:

- Global Administrator
- Privileged Role Administrator
- Exchange Administrator
- Application Administrator

They can:

- Create backdoor accounts
- Register malicious apps
- Disable security controls
- Extract data
- Persist long-term

This maps to:

- **MITRE ATT&CK T1098 – Account Manipulation**
- **MITRE ATT&CK T1078 – Valid Accounts**
- **MITRE ATT&CK T1068 – Privilege Escalation**

Role abuse is a common post-compromise technique.

---

### 2.4 Define Severity? Conditions to escalate alert to more severity.

**Default Severity: High**

Escalate to Critical if:

- Role assigned is:
    - Global Administrator
    - Privileged Role Administrator
    - Security Administrator
- Initiator is:
    - Suspicious account
    - Newly created account
    - Service principal
- Source IP:
    - Anonymous/VPN/Tor
    - Foreign country
- MFA was bypassed or not enforced
- Occurred outside business hours
- Followed by:
    - App registrations
    - Conditional Access changes
    - Role assignments to other users

---

## 3. Knowledge Required Before Investigation

This section is critical for Tier 1–3 analysts.

---

### 3.1 Concepts analyst must understand about the entities in alert with their brief explanation.

### 1. Azure AD (Microsoft Entra ID) Roles

Azure AD roles provide administrative permissions over the tenant.

Examples:

- Global Administrator → Full tenant control
- Privileged Role Administrator → Can assign roles
- Application Administrator → Can manage enterprise apps
- Security Administrator → Can manage security settings

**Key concept:** Role assignments are equivalent to privilege escalation.

---

### 2. Privileged Identity Management (PIM)

PIM enforces:

- Just-in-Time (JIT) access
- Approval workflow
- Time-bound elevation
- MFA enforcement
- Auditing

If a role is assigned **outside PIM**, it means:

- Permanent role assignment
- No approval process
- No expiration
- High persistence risk

Attackers prefer permanent role assignment for persistence.

---

### 3. AuditLogs Table

Contains:

- OperationName
- InitiatedBy (user/app)
- TargetResources
- IP Address
- Timestamp
- Role details

Analysts must know how to:

- Expand `TargetResources`
- Identify role ID
- Correlate Initiator and Target

---

### 4. InitiatedBy Object

Can be:

- User
- Service Principal (Application)

If initiated by service principal:

- Check for:
    - Compromised automation
    - Malicious app registration
    - OAuth abuse

---

### 5. Service Principal Abuse

Attackers often:

- Register malicious Azure AD apps
- Grant API permissions
- Assign roles to service principal
- Use certificate-based authentication for stealth persistence

This bypasses password-based monitoring.

---

### 6. Identity Field

If `Identity != MS-PIM`:

- Role was not activated via PIM
- It was manually assigned

This is the detection core.

---

### 7. Azure AD Attack Patterns

Common post-compromise flow:

1. Compromise admin via phishing
2. Assign role to attacker-controlled account
3. Create app registration
4. Grant API permissions
5. Disable logging
6. Maintain persistence

Analyst must understand this lifecycle.

---

## 4. Attacker Perspective

---

### 4.1 Why attackers use this technique

Attackers want:

- Long-term persistence
- Full tenant control
- Ability to create backdoors
- Disable detection
- Access mailboxes and SharePoint

Role manipulation gives full identity control.

---

### 4.2 What they try to achieve

- Escalate from user → Global Admin
- Maintain hidden privileged access
- Modify Conditional Access
- Create OAuth persistence
- Dump Azure AD directory data

---

### 4.3 Real-world attack examples

1. **APT29 (Nobelium)**
    - Compromised Azure AD accounts
    - Added privileged roles
    - Created OAuth apps for persistence
2. **Business Email Compromise (BEC) campaigns**
    - Compromise admin
    - Assign Exchange Admin
    - Create mailbox forwarding rules
3. **Storm-0558 campaign**
    - Token abuse
    - Privilege escalation in Microsoft cloud environments

---

### 4.4 Potential Business Impact

- Complete tenant takeover
- Data exfiltration (email, SharePoint, OneDrive)
- Ransomware deployment
- Security control disabling
- Regulatory penalties
- Loss of business continuity

Impact level: Severe

---

## 5. Pre-Investigation Checklist

---

### 5.1 Confirm hostname and user

- Identify:
    - InitiatingUserPrincipalName
    - InitiatingAadUserId
    - TargetUserPrincipalName
- Determine:
    - Was this human or service principal?
    - Was it interactive login?

---

### 5.2 Check entities criticality

- Is target user:
    - Already privileged?
    - Break-glass account?
    - Service account?
- Is initiator:
    - Tier 0 admin?
    - Automation account?

---

### 5.3 Verify alert severity

- What role was assigned?
- Permanent or temporary?
- From what IP?
- Geo-location?
- MFA status?

---

## 6. Investigation Steps

---

### 6.1 What questions should an analyst ask himself while investigating alert.

1. Who performed the role assignment?
2. Was it expected change?
3. What role was assigned?
4. Was PIM bypassed intentionally?
5. From where was it performed?
6. What happened after assignment?
7. Is initiator compromised?
8. Has this account performed similar actions before?

---

### 6.2 Answer the questions

**Q1: Who performed the assignment?**

Check:

```
AuditLogs
| where Category == "RoleManagement"
| where OperationName contains "Add member to role"
| project TimeGenerated, InitiatedBy, TargetResources
```

Identify:

- User or App
- IP Address

---

**Q2: Was it expected?**

- Check change management ticket
- Validate with IAM team
- Review if role assignment matches onboarding process

---

**Q3: What role was assigned?**

Extract Role ID:

```
AuditLogs
| where OperationName contains "Add member to role"
| extend RoleName = tostring(TargetResources[0].displayName)
| project TimeGenerated, RoleName
```

If high-privilege role → escalate.

---

**Q4: Was PIM bypassed intentionally?**

Check if PIM enabled for that role.

If PIM is mandatory and bypass occurred:

- This is strong suspicious indicator.

---

**Q5: Source IP analysis**

```
SigninLogs
| where UserPrincipalName == "<Initiator>"
```

Check:

- Unusual country
- New device
- Risky sign-in flag
- MFA failure events

---

**Q6: What happened after assignment?**

Look for:

- App registrations
- Role assignments
- Conditional Access changes
- Mailbox forwarding
- Security setting changes

---

### 6.3 Major Investigations (Important Investigation steps)

1. Review sign-in logs of initiator (24–72 hours prior)
2. Check if account recently had risky sign-in
3. Check if MFA was recently disabled
4. Verify if initiator was added to privileged role before performing assignment
5. Investigate newly created service principals
6. Look for OAuth consent grants
7. Search for additional role assignments
8. Check for role removal (covering tracks)

---

### 6.4 Minor Investigations (Related Investigation steps)

- Check if target account logged in immediately after role assignment
- Look for mailbox export
- Review audit logs for data access spikes
- Check if Azure subscriptions were modified
- Review Azure Resource Manager activity logs

---

## 7. Evidence to Collect

- Full AuditLogs entry (JSON)
- Sign-in logs of initiator
- IP address reputation
- Device ID
- MFA logs
- Conditional Access evaluation
- Role definition details
- Tenant configuration export

---

## 8. Indicators of True Positive

- Role assigned to new or unknown account
- No change request exists
- Initiator had risky login
- IP from unusual geography
- Multiple privilege escalations in short time
- Follow-up suspicious activities
- Service principal created shortly after
- PIM normally enforced but bypass occurred

---

## 9. Indicators of False Positive

- Approved onboarding
- Documented emergency access
- Break-glass activation
- IAM automation process
- Known Azure DevOps pipeline activity

---

## 10. Incident Response Actions (If True Positive)

---

### 10.1 Containment

- Immediately remove role assignment
- Disable initiator account
- Revoke active sessions
- Reset password and enforce MFA
- Disable suspicious service principals

---

### 10.2 Eradication

- Remove malicious apps
- Review API permissions
- Rotate secrets and certificates
- Review Conditional Access policies
- Validate no persistence remains

---

### 10.3 Recovery

- Restore legitimate access via PIM
- Re-enable secured account
- Monitor for 7–14 days
- Perform tenant-wide privilege review

---

## 11. Mitigation & Prevention

1. Enforce PIM for all privileged roles
2. Require MFA for role assignments
3. Block permanent Global Admin accounts
4. Implement Conditional Access for admin roles
5. Monitor service principal role assignments
6. Alert on role assignments outside business hours
7. Implement Zero Trust identity model
8. Conduct regular privileged access reviews

---
