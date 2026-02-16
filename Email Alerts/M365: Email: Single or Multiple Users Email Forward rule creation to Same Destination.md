# 1. Alert Name

**Single/Multiple Users Email Forward rule creation to Same Destination**

---

# 2. Alert Description (Detection Logic Explanation)

This detection identifies scenarios where **multiple Microsoft 365 users configure mailbox forwarding to the same external email address** within a defined time window.

The query analyzes **Exchange Online audit logs (OfficeActivity table)** and detects:

- Forwarding configuration via:
    - `ForwardTo`
    - `RedirectTo`
    - `ForwardingSmtpAddress`
- Extracts destination email address
- Counts distinct users forwarding to the same destination
- Triggers when:
    - `DistinctUserCount > 1`
    - Activity occurred in the last 1 day
    - Lookback period is 7 days

It also extracts:

- Client IP
- Port
- User list
- Time range

---

## 2.1 What Triggered the Alert

The alert was triggered because:

- More than one user account configured forwarding
- All forwarding rules point to the same `DestinationMailAddress`
- The change occurred recently (within last 24 hours)
- Logged under Exchange workload

Example trigger scenario:

| User | Action | Destination |
| --- | --- | --- |
| [user1@company.com](mailto:user1@company.com) | Set-Mailbox ForwardTo | [attacker@gmail.com](mailto:attacker@gmail.com) |
| [user2@company.com](mailto:user2@company.com) | New-InboxRule RedirectTo | [attacker@gmail.com](mailto:attacker@gmail.com) |

DistinctUserCount = 2 → Alert fires.

---

## 2.2 Which Security Tool Generated It

- **Microsoft Sentinel (Azure Sentinel)**
- Data Source: **Microsoft 365 Unified Audit Logs**
- Table: `OfficeActivity`
- Workload: Exchange Online

---

## 2.3 Why This Alert Is Important

Mailbox forwarding is a **common persistence and data exfiltration technique**.

This detection aligns with:

- **MITRE ATT&CK T1114.003 – Email Collection: Email Forwarding Rule**
- Often observed in:
    - Business Email Compromise (BEC)
    - Account takeover campaigns
    - Internal espionage
    - Financial fraud attacks

Multiple users forwarding to the same address is a **strong indicator of coordinated compromise**.

---

## 2.4 Define Severity? Conditions to Escalate Alert to More Severity

### Default Severity: **Medium**

### Escalate to HIGH if:

- Destination email is external and unknown
- Users are:
    - Finance
    - Executive
    - HR
    - Privileged accounts
- Forwarding enabled silently (no user awareness)
- Same ClientIP across multiple users
- IP is:
    - Foreign
    - TOR exit node
    - Known malicious
- MFA disabled or bypass detected
- Sign-in anomalies exist

### Escalate to CRITICAL if:

- Confirmed account takeover
- Financial fraud in progress
- Sensitive mailboxes affected (CEO, CFO)
- Widespread tenant compromise

---

# 3. Knowledge Required Before Investigation

---

## 3.1 Concepts Analyst Must Understand

### 1. Exchange Mailbox Forwarding

Mailbox forwarding allows automatic redirection of incoming emails to another mailbox.

Types:

- **ForwardTo** → forwards and keeps copy
- **RedirectTo** → forwards without keeping original
- **ForwardingSmtpAddress** → SMTP-level forwarding

Attackers prefer SMTP forwarding for stealth.

---

### 2. Inbox Rules vs Mailbox-Level Forwarding

Inbox rules:

- User-created
- Can hide specific emails
- Often used in BEC

Mailbox-level forwarding:

- Configured via admin or PowerShell
- Broader impact

---

### 3. Unified Audit Logs (UAL)

Records:

- Who made change
- From where (ClientIP)
- When
- What operation

Critical for timeline reconstruction.

---

### 4. Business Email Compromise (BEC)

Attackers:

- Phish credentials
- Log into mailbox
- Set forwarding
- Monitor financial conversations
- Inject fraudulent payment instructions

---

# 4. Attacker Perspective

---

## 4.1 Why Attackers Use This Technique

- Passive data exfiltration
- Stealthy persistence
- Avoid triggering download alerts
- Monitor sensitive discussions silently

---

## 4.2 What They Try to Achieve

- Financial fraud
- Invoice redirection
- Executive impersonation
- Data theft
- Espionage

---

## 4.3 Real-World Attack Examples

- **Microsoft 365 BEC campaigns**
- Financial redirection scams targeting CFOs
- OAuth token abuse campaigns

Common pattern:

1. Credential phishing
2. Login from foreign IP
3. Set forwarding
4. Delete security alerts
5. Monitor payment emails

---

## 4.4 Potential Business Impact

- Wire transfer fraud
- Confidential data leakage
- Regulatory violations (GDPR)
- Reputation damage
- Legal consequences

---

# 5. Pre-Investigation Checklist

---

## 5.1 Confirm Hostname and User

- Validate impacted users
- Confirm tenant
- Extract:
    - UserId
    - ClientIP
    - DestinationMailAddress

---

## 5.2 Check Entities Criticality

Are users:

- Executives?
- Finance team?
- Privileged admins?
- Service accounts?

---

## 5.3 Verify Alert Severity

- How many users?
- Internal vs external destination?
- Same IP used?
- Recent sign-in anomalies?

---

# 6. Investigation Steps

---

## 6.1 What Questions Should an Analyst Ask?

1. Is destination email internal or external?
2. Did users knowingly configure forwarding?
3. Was there suspicious login activity?
4. Is same IP linked to all modifications?
5. Are inbox rules also created?
6. Was MFA bypassed?
7. Any data exfiltration signs?

---

## 6.2 Answer the Questions

### Q1: Is destination external?

If external → higher suspicion.

Check:

```
SigninLogs
| where UserPrincipalName in ("user1@company.com","user2@company.com")
```

---

### Q2: Suspicious Login?

Look for:

- Impossible travel
- TOR IP
- Risky sign-in flag
- MFA failure

---

### Q3: Same Client IP?

If same IP configured multiple mailboxes → likely single attacker.

---

### Q4: Additional malicious configurations?

Check:

```
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule")
```

---

## 6.3 Major Investigations (Important Steps)

### 1. Analyze Sign-in Logs

- Check last 7 days
- Compare geolocation
- Look for:
    - Anonymous IP
    - VPN
    - Suspicious device ID

---

### 2. Check Risky Sign-ins

```
SigninLogs
| where RiskLevelDuringSignIn != "none"
```

---

### 3. Investigate Mailbox Audit Logs

Look for:

- Email deletions
- Security notification deletion
- Suspicious search queries

---

### 4. Check for Lateral Movement

- Same IP accessing multiple accounts?
- Same device ID?
- Same user agent?

---

### 5. Validate Forwarding Status

Use Exchange PowerShell:

```powershell
Get-Mailbox user@company.com | fl ForwardingSmtpAddress,DeliverToMailboxAndForward
```

---

## 6.4 Minor Investigations (Related Steps)

- Check Defender alerts for those users
- Check endpoint compromise
- Review recent phishing reports
- Check OAuth app consent logs
- Validate Conditional Access logs

---

# 7. Evidence to Collect

- Audit log entries
- Sign-in logs
- Client IP reputation
- User agent strings
- Forwarding configuration snapshot
- Risk events
- Email trace logs

Preserve for forensic retention.

---

# 8. Indicators of True Positive

- External unknown forwarding address
- Same IP configured multiple users
- IP from foreign country
- Risky sign-in detected
- MFA bypass
- Inbox rules hiding emails
- Users unaware of configuration
- Mailbox audit logs show mass rule creation

---

# 9. Indicators of False Positive

- Shared mailbox forwarding configured intentionally
- Migration activity
- Admin performing bulk configuration
- HR automation setup
- Verified IT change ticket

---

# 10. Incident Response Actions (If True Positive)

---

## 10.1 Containment

- Disable forwarding immediately
- Revoke user sessions
- Reset password
- Enforce MFA reset
- Block suspicious IP

---

## 10.2 Eradication

- Remove malicious inbox rules
- Remove OAuth tokens
- Reconfigure Conditional Access
- Investigate phishing entry point

---

## 10.3 Recovery

- Restore deleted emails
- Notify impacted departments
- Monitor mailbox activity
- Enable mailbox auditing if disabled

---

# 11. Mitigation & Prevention

- Enforce MFA for all users
- Disable external auto-forwarding via policy
- Enable mailbox auditing
- Implement Conditional Access:
    - Block legacy authentication
- Enable Defender for Office 365
- Alert on forwarding rule creation (single-user too)
- Monitor risky sign-ins continuously
- User phishing awareness training

---
