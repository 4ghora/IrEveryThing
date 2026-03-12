# 1. What Domain Trusts Are

* **Microsoft Active Directory Domain Trusts** are relationships between two **AD domains** that allow users in one domain to authenticate and access resources in another.
* Trusts allow **identity authentication to cross domain boundaries** using the **Kerberos protocol**.
* Common in **large enterprise environments** where multiple domains or forests exist.
* Used across **Windows enterprise infrastructures** and hybrid environments integrated with **Microsoft Entra ID** (formerly Azure AD).
* Trust types include:

  * **Parent–child trusts**
  * **Forest trusts**
  * **External trusts**
  * **Shortcut trusts**
  * **Realm trusts**
* Trusts define **direction (one-way or two-way)** and **scope (domain or forest level)**.

---

# 2. Legitimate Use

Organizations rely on domain trusts to support large-scale identity management.

* **Cross-domain authentication**

  * Users from Domain A access resources in Domain B.
* **Enterprise mergers and acquisitions**

  * Temporary trust relationships between separate AD forests.
* **Resource forests**

  * Separate domain hosts applications while user accounts live elsewhere.
* **Delegated administration**

  * Different business units maintain separate domains.
* **Geographically distributed environments**

  * Parent-child domain structures for large companies.
* **Hybrid identity architectures**

  * Trust relationships supporting **on-prem AD + cloud identity federation**.

---

# 3. Attacker Abuse

Domain trusts are a **high-value lateral movement pathway**. If one domain is compromised, attackers may pivot across trusted domains.

### Common Abuse Techniques

* **Cross-domain lateral movement**

  * Attackers compromise one domain then move to trusted domains.
* **Privilege escalation across trusts**

  * Abuse **Enterprise Admin or trust relationships** to escalate privileges.
* **Kerberos ticket abuse**

  * Forged tickets used to access resources in trusted domains.

### Typical Attack Scenarios

* **Trust enumeration**

  * Adversaries map trust relationships to plan lateral movement.
* **Golden Ticket with cross-domain access**

  * Forged Kerberos TGT used to access trusted domain resources.
* **SID History abuse**

  * Attackers add privileged SIDs from another domain to gain access.
* **Compromise child domain → attack forest root**

  * Common AD escalation path.

### Relevant MITRE ATT&CK Techniques

* **T1482 Domain Trust Discovery**
* **T1550 Use Alternate Authentication Material**
* **T1558 Steal or Forge Kerberos Tickets**
* **T1134 Access Token Manipulation**
* **T1098 Account Manipulation**

---

# 4. SIEM Detection Opportunities

Below are practical alerts SOC teams commonly deploy.

---

### Alert: Domain Trust Discovery Activity

**Suspicious Behavior**

* Enumeration of trust relationships using built-in tools or PowerShell.

**Example Detection Logic**

```
ProcessName IN ("nltest.exe", "dsquery.exe", "powershell.exe")
AND CommandLine CONTAINS ("domain_trusts", "/domain_trusts", "Get-ADTrust", "Get-ADDomainTrust")
```

**Relevant Log Sources**

* Windows Security Logs
* Sysmon
* EDR telemetry
* PowerShell logs (Event ID 4104)

---

### Alert: New Domain Trust Created

**Suspicious Behavior**

* Creation of new trust relationships that could allow unauthorized access between domains.

**Example Detection Logic**

```
EventID = 4716 OR 4713
AND ObjectType = "Trusted Domain"
```

**Relevant Log Sources**

* Windows Security Event Logs
* Domain Controller logs
* AD auditing logs

---

### Alert: Modification of Existing Domain Trust

**Suspicious Behavior**

* Trust direction or authentication scope changed.

**Example Detection Logic**

```
EventID = 4716
AND ChangeType = "TrustAttributeChanged"
```

**Relevant Log Sources**

* Domain Controller Security Logs
* AD Change auditing logs

---

### Alert: SID History Added to Account

**Suspicious Behavior**

* Privileged SID from another domain added to user account.

**Example Detection Logic**

```
EventID = 4765 OR 4766
```

**Relevant Log Sources**

* Windows Security Event Logs
* Domain Controller logs

---

### Alert: Kerberos Ticket Activity Across Domains

**Suspicious Behavior**

* Authentication requests using Kerberos tickets across domain boundaries.

**Example Detection Logic**

```
EventID = 4769
AND TargetDomain != SourceDomain
AND PrivilegedAccount = TRUE
```

**Relevant Log Sources**

* Windows Security Logs (Kerberos)
* Domain Controller logs

---

# 5. Investigation Indicators

SOC analysts should investigate the following artifacts when domain trust abuse is suspected.

* **Domain trust enumeration commands**

  * `nltest /domain_trusts`
  * `Get-ADTrust`
  * `Get-ADDomain`
* **Unusual Kerberos ticket activity**

  * Cross-domain TGT requests.
* **Unexpected SID History entries**

  * Especially containing **Domain Admin or Enterprise Admin SIDs**.
* **Trust configuration changes**

  * Recently created or modified trusts.
* **Privileged accounts authenticating across domains**

  * Particularly service accounts or rarely used admins.
* **AD reconnaissance tools**

  * **BloodHound**, **PowerView**, **SharpHound** used for trust mapping.

---

# 6. Mitigations / Security Best Practices

Defensive controls to reduce risk from domain trust abuse.

### Harden Trust Relationships

* Prefer **one-way trusts** instead of two-way when possible.
* Use **Selective Authentication** instead of domain-wide authentication.
* Avoid unnecessary **external trusts**.

### Limit Privilege Exposure

* Restrict **Enterprise Admin membership**.
* Use **tiered admin model (Tier 0 / Tier 1 / Tier 2)**.

### Monitor Trust Changes

* Enable **Active Directory auditing** for trust creation/modification.
* Send logs to **SIEM for correlation**.

### Prevent Kerberos Abuse

* Implement **Kerberos armoring (FAST)**.
* Rotate **KRBTGT password regularly**.

### Detect AD Reconnaissance

* Monitor for **PowerShell AD enumeration**.
* Detect tools like **BloodHound** collecting trust data.

### Network Segmentation

* Restrict **administrative access between domains**.
* Enforce **privileged access workstations (PAWs)**.

---