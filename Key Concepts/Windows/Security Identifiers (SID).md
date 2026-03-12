## 1. What it is

* **Windows Security Identifier (SID)** is a **unique identifier assigned to security principals** in Windows environments.
* Security principals include **users, groups, computers, and services** in **Active Directory** or local systems.
* A SID is used internally by Windows to determine **permissions and access control**, not the username.
* Example SID format: `S-1-5-21-3623811015-3361044348-30300820-1013`
* SIDs are heavily used in **ACLs (Access Control Lists)** to control access to files, registry keys, services, and AD objects.
* Found across **Windows OS, Active Directory environments, enterprise networks, and identity infrastructure**.

---

# 2. Legitimate Use

* **Access Control Enforcement**

  * Windows uses SIDs in **ACLs** to determine whether a principal can access an object.

* **User & Group Identification**

  * Even if a **username changes**, the SID remains the same.

* **Active Directory Security**

  * Domain controllers use SIDs to enforce **domain privileges and group memberships**.

* **Token Creation During Logon**

  * During authentication, Windows builds an **access token containing the user's SID and group SIDs**.

* **Cross-domain Access**

  * **SIDHistory attribute** allows users migrating domains to maintain previous permissions.

* **System-level accounts**

  * Built-in accounts have well-known SIDs (e.g., `S-1-5-18` for **Local System**).

---

# 3. Attacker Abuse

Attackers often manipulate SIDs to **escalate privileges, maintain persistence, or bypass access controls**.

### 1. SID History Injection

* Attackers inject **privileged SIDs into SIDHistory attribute**.
* Grants privileges like **Domain Admin** without being a member of the group.

**MITRE ATT&CK**

* `T1098 – Account Manipulation`

---

### 2. Golden Ticket / Kerberos Ticket Forgery

* Forged **Kerberos tickets include arbitrary SIDs**.
* Attackers insert **high privilege group SIDs**.

**MITRE ATT&CK**

* `T1558.001 – Golden Ticket`

---

### 3. RID Hijacking

* Modify **Relative Identifier (RID)** portion of SID to impersonate privileged accounts.

Example:
User SID modified to match **Administrator RID (500)**.

**MITRE ATT&CK**

* `T1078 – Valid Accounts`

---

### 4. Persistence Using Built-in SIDs

* Abuse privileged SIDs like:

  * `S-1-5-32-544` → Administrators
  * `S-1-5-18` → SYSTEM

**MITRE ATT&CK**

* `T1134 – Access Token Manipulation`

---

### 5. ACL Backdoors

* Attackers add **malicious SID entries into ACLs** to maintain hidden access.

**MITRE ATT&CK**

* `T1222 – File and Directory Permissions Modification`

---

# 4. SIEM Detection Opportunities

## Alert 1 — Suspicious SIDHistory Modification

**Suspicious Behavior**

Modification of the **SIDHistory attribute**, which should rarely change.

**Detection Logic**

```
IF ActiveDirectoryEvent
AND AttributeModified = "SIDHistory"
AND InitiatingUser NOT IN approved_migration_accounts
THEN Alert
```

**Relevant Log Sources**

* Windows Security Logs
* Domain Controller Logs
* AD Audit Logs
* EDR telemetry

Relevant Event IDs:

* **5136** – Directory Object Modified

---

## Alert 2 — User Assigned Privileged SID

**Suspicious Behavior**

User account receives **Domain Admin or Enterprise Admin SID** unexpectedly.

**Detection Logic**

```
Detect SIDHistory containing:
S-1-5-21-*-512 (Domain Admins)
S-1-5-21-*-519 (Enterprise Admins)
```

**Log Sources**

* AD logs
* Windows Security Logs
* Identity monitoring platforms

---

## Alert 3 — Logon Token Contains Unexpected Privileged SID

**Suspicious Behavior**

User logon token includes **privileged group SID** but user is not part of that group.

**Detection Logic**

```
LogonEvent
AND TokenGroups contains Admin SID
AND User NOT member_of AdminGroup
```

**Log Sources**

* Windows Event Logs
* EDR telemetry
* Authentication logs

Relevant Events:

* **4624 – Successful Logon**

---

## Alert 4 — Possible RID Hijacking

**Suspicious Behavior**

Account SID ends with **RID 500 or other privileged RID** but username is not Administrator.

**Detection Logic**

```
IF SID endswith "-500"
AND AccountName != "Administrator"
```

**Log Sources**

* AD logs
* Windows Security Logs
* Directory audit logs

---

## Alert 5 — ACL Modified With Unknown SID

**Suspicious Behavior**

ACL modified to include **unrecognized or orphan SIDs**.

**Detection Logic**

```
ObjectPermissionChange
AND SID NOT resolved_to_known_account
```

**Log Sources**

* Windows Security Logs
* File auditing logs
* EDR telemetry

Relevant Events:

* **4670 – Permissions on object changed**
* **4662 – Object operation**

---

# 5. Investigation Indicators

SOC analysts should check the following artifacts:

* **SIDHistory attribute values**

  * Look for **privileged SIDs added recently**.

* **Group membership anomalies**

  * Compare **token groups vs AD group membership**.

* **Unusual RIDs**

  * Accounts ending in:
  * `-500` (Administrator)
  * `-512` (Domain Admins)
  * `-519` (Enterprise Admins)

* **ACL entries with unresolved SIDs**

  * Often appear as **S-1-5-21-XXXX-XXXX-XXXX-XXXX** without a name.

* **Kerberos ticket anomalies**

  * Unexpected group SIDs inside **PAC (Privilege Attribute Certificate)**.

* **Changes made from non-admin hosts**

  * SID-related changes coming from **workstations instead of DCs**.

---

# 6. Mitigations / Security Best Practices

### Restrict SIDHistory Changes

* Only allow **authorized AD migration tools** to modify SIDHistory.

---

### Monitor Directory Changes

* Enable **Active Directory auditing**:

  * Event **5136**
  * Event **4662**

---

### Enforce Tiered Admin Model

* Limit access to **Domain Admin privileges**.
* Use **Privileged Access Workstations (PAW)**.

---

### Detect Privileged SID Usage

* Monitor authentication tokens containing:

  * `512`
  * `519`
  * `500`

---

### Regular SIDHistory Audits

* Periodically audit:

```
Get-ADUser -Filter * -Properties SIDHistory
```

Look for **unexpected privileged SIDs**.

---

### Deploy Identity Threat Detection

Tools that help detect SID abuse:

* **Microsoft Defender for Identity**
* **SIEM correlation rules**
* **EDR identity telemetry**

---