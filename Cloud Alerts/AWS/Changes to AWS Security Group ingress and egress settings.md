## 1. Alert Name

**Changes to AWS Security Group ingress and egress settings**

---

## 2. Alert Description (Detection Logic Explanation)

### 2.1 What Triggered the Alert

This alert is triggered when modifications are made to **EC2 Security Groups** via CloudTrail events:

```kql
let EventNameList = dynamic([
"AuthorizeSecurityGroupEgress",
"AuthorizeSecurityGroupIngress",
"RevokeSecurityGroupEgress",
"RevokeSecurityGroupIngress"
]);
```

The query monitors AWS CloudTrail logs for:

* Adding inbound rules (`AuthorizeSecurityGroupIngress`)
* Adding outbound rules (`AuthorizeSecurityGroupEgress`)
* Removing rules (`Revoke*`)

The alert becomes significant when:

* A rule allows **0.0.0.0/0** (IPv4) or `::/0` (IPv6)
* High-risk ports are exposed (e.g., 22, 3389, 3306, 5432, 6379, 9200)
* The change was performed by an unusual user, service, or IP address

The query aggregates:

* Actor identity (UserIdentityArn, UserIdentityType)
* Source IP address
* MFA status
* AWS region
* Time window of changes

This enables identification of suspicious bulk rule modifications.

**Example Trigger Scenario:**

An IAM user executes:

```bash
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
```

If SSH (22) is opened to the world, the alert fires.

---

### 2.2 Which Security Tool Generated It

* Primary log source: **AWS CloudTrail**
* Detection platform: AWS Security Hub (integrated findings)
* Query likely executed in **Microsoft Sentinel**, **Splunk**, or other SIEM

Entity references:

* AWS Security Hub
* Amazon EC2
* AWS CloudTrail

---

### 2.3 Why This Alert Is Important

Security Groups are **stateful virtual firewalls** controlling EC2 network access.

Opening high-risk ports to `0.0.0.0/0`:

* Enables brute-force attempts
* Enables remote exploitation
* Enables C2 beacon exposure
* Exposes databases to internet scanning

This aligns with MITRE ATT&CK:

* T1190 – Exploit Public-Facing Application
* T1133 – External Remote Services
* T1078 – Valid Accounts
* T1098 – Account Manipulation

This alert may indicate:

* Misconfiguration
* Credential compromise
* Lateral movement preparation
* Persistence establishment

---

### 2.4 Define Severity? Conditions to Escalate Alert to More Severity

**Medium Severity**

* Change performed by known DevOps user
* Temporary exposure
* MFA enabled
* Corporate IP source

**High Severity**

* High-risk port exposed to 0.0.0.0/0
* MFA not used
* Unusual region
* Source IP from foreign ASN
* Privileged IAM role used

**Critical Severity**

* Port 22/3389 opened globally on production instance
* IAM role compromise suspected
* Multiple security groups modified
* Followed by suspicious EC2 login attempts
* Linked to known threat IP

---

## 3. Knowledge Required Before Investigation

### 3.1 Concepts Analyst Must Understand

#### 1. EC2 Security Groups

Security Groups are **stateful firewalls** attached to EC2 instances.

Key properties:

* Control inbound & outbound traffic
* Default deny inbound
* Rules specify:

  * Protocol
  * Port range
  * Source (CIDR, SG, prefix list)

**Example:**

```
Inbound:
TCP 22 0.0.0.0/0   (Dangerous)
```

This means anyone globally can attempt SSH login.

---

#### 2. High-Risk Ports

Commonly abused ports:

| Port | Service       | Risk                   |
| ---- | ------------- | ---------------------- |
| 22   | SSH           | Brute force, key theft |
| 3389 | RDP           | Ransomware entry       |
| 3306 | MySQL         | Data theft             |
| 5432 | PostgreSQL    | DB exposure            |
| 6379 | Redis         | No-auth exploitation   |
| 9200 | Elasticsearch | Data leak              |

Analyst must understand service behavior and authentication model.

---

#### 3. AWS IAM Identity Types

CloudTrail includes:

* IAMUser
* AssumedRole
* Root
* AWSService
* FederatedUser

Important fields:

* `UserIdentityType`
* `UserIdentityArn`
* `SessionMfaAuthenticated`

**Example:**

```
arn:aws:sts::123456789:assumed-role/AdminRole/AWSCLI-Session
```

This means a role session via STS.

---

#### 4. CloudTrail Logging

CloudTrail records:

* Who made change
* From which IP
* What region
* What parameters

Critical fields:

* `SourceIpAddress`
* `UserAgent`
* `ResponseElements`
* `AdditionalEventData`

Analyst must know how to reconstruct API call.

---

#### 5. AWS Regions & Geo Risk

Attackers often:

* Use compromised credentials from different country
* Create exposure in rarely used region

Example:
Org normally operates in ap-south-1 but change occurred in us-east-1.

---

#### 6. Session MFA Status

`SessionMfaAuthenticated = false`

High risk if:

* Privileged role used
* Root account used without MFA

---

## 4. Attacker Perspective

### 4.1 Why Attackers Use This Technique

They modify Security Groups to:

* Establish backdoor access
* Bypass internal firewall restrictions
* Enable C2 communication
* Expose databases for direct access

---

### 4.2 What They Try to Achieve

* Persistence
* Remote command execution
* Data exfiltration
* Lateral movement
* Ransomware staging

---

### 4.3 Tools / Commands Attackers Use

AWS CLI:

```bash
aws ec2 authorize-security-group-ingress
```

Terraform modification:

```hcl
cidr_blocks = ["0.0.0.0/0"]
```

AWS Console UI

Compromised IAM credentials via:

* Phishing
* Token theft
* GitHub secrets leak

---

### 4.4 Real-World Attack Examples

* Capital One breach involved cloud misconfiguration exploitation.
* Tesla Kubernetes exposure led to crypto-mining incident.

Common pattern:

1. Credential compromise
2. Security group modification
3. Remote shell deployment
4. Crypto miner or ransomware execution

---

### 4.5 Potential Business Impact

* Public data exposure
* Ransomware encryption
* Regulatory penalties
* Cloud cost explosion (crypto mining)
* Reputation damage

---

## 5. Pre-Investigation Checklist

### 5.1 Confirm Hostname and User

* Identify EC2 instance ID linked to SG
* Map SG to critical assets
* Identify IAM user/role
* Confirm whether service account or human

---

### 5.2 Check Entity Criticality

* Is instance production?
* Is database attached?
* Internet-facing ELB attached?
* Contains PII?

---

### 5.3 Verify Alert Severity

Cross-check:

* Port exposed
* Source CIDR
* MFA status
* Geo-IP of SourceIpAddress
* Historical behavior of user

---

## 6. Investigation Steps

### 6.1 Questions Analyst Should Ask

1. Who made the change?
2. Was MFA used?
3. Was change approved?
4. Is this user normally modifying SG?
5. What ports were exposed?
6. Is instance internet-facing?
7. Were login attempts seen after exposure?
8. Is there abnormal EC2 activity after rule change?

---

### 6.2 Answer the Questions

Use CloudTrail:

```kql
AWSCloudTrail
| where EventName == "AuthorizeSecurityGroupIngress"
| project TimeGenerated, UserIdentityArn, SourceIpAddress, RequestParameters
```

Check EC2 network logs (VPC Flow Logs):

```kql
AWSVPCFlowLogs
| where DstPort in (22,3389)
| where Action == "ACCEPT"
```

Check GuardDuty findings (if integrated).

---

### 6.3 Major Investigations

1. Review RequestParameters

   * Confirm CIDR range
   * Confirm port range

2. Investigate Source IP

   * Geo location
   * ASN
   * Corporate IP match?

3. Check Subsequent Events

   * IAM changes?
   * New access keys?
   * EC2 metadata abuse?

4. Check EC2 Logs

   * Linux: /var/log/auth.log
   * Windows: Security Event 4624

5. Check for Persistence

   * New IAM roles?
   * New EC2 instance launched?
   * User data script modified?

---

### 6.4 Minor Investigations

* Compare with change ticket
* Check CloudFormation logs
* Verify Terraform pipeline activity
* Confirm CI/CD change window

---

## 7. Evidence to Collect

* CloudTrail raw event JSON
* Security group rule before/after snapshot
* EC2 system logs
* VPC Flow Logs
* IAM credential report
* Geo-IP enrichment of source
* MFA logs
* GuardDuty findings

---

## 8. Indicators of True Positive

* 0.0.0.0/0 exposure on SSH/RDP
* MFA disabled
* Source IP foreign/unusual ASN
* No change ticket
* Multiple SGs modified
* Brute force attempts after exposure
* IAM user recently created

---

## 9. Indicators of False Positive

* DevOps engineer during deployment
* Change ticket exists
* Temporary exposure removed quickly
* Known CI/CD pipeline role
* Source IP matches corporate NAT

---

## 10. Incident Response Actions (If True Positive)

### 10.1 Containment

* Immediately revoke risky SG rule
* Disable compromised IAM credentials
* Rotate access keys
* Isolate affected EC2 instance (detach from network)

---

### 10.2 Eradication

* Reset IAM credentials
* Patch exposed service
* Remove unauthorized IAM roles
* Rebuild compromised EC2 instance

---

### 10.3 Recovery

* Restore from clean AMI
* Re-enable controlled SG rules
* Enable mandatory MFA
* Review IAM least privilege

---

## 11. Mitigation & Prevention

* Enforce SCP to deny 0.0.0.0/0 on sensitive ports
* AWS Config rule: `restricted-ssh`
* Enable GuardDuty
* Mandatory MFA for IAM
* Use Bastion host
* Implement Security Group baseline monitoring
* Continuous posture assessment via Security Hub

---

## 12. Actions an IR Should Never Do (In Context of Alert)

* Do NOT delete CloudTrail logs
* Do NOT modify SG before collecting evidence
* Do NOT notify suspected compromised user prematurely
* Do NOT shut down instance without snapshot
* Do NOT assume DevOps change without verification

---