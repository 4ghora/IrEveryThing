## Privileged Access Workstations (PAW)

---

# 1. What It Is

* **Privileged Access Workstations (PAWs)** are **dedicated, hardened workstations used exclusively for performing privileged administrative tasks**.
* They are designed to **isolate high-privilege credentials and sessions** from standard user environments where malware risk is higher.
* PAWs are commonly deployed in **Windows Active Directory environments**, but also apply to **Azure, AWS, and enterprise identity systems**.
* Typically restricted to managing **Domain Controllers, identity systems, cloud consoles, and sensitive infrastructure**.
* PAWs are part of Microsoft's **privileged access strategy** alongside **Just-in-Time (JIT) access and tiered administration models**.
* They help prevent **credential theft, pass-the-hash, token theft, and privilege escalation attacks**.

---

# 2. Legitimate Use

* Administrators use PAWs to **log into sensitive systems such as Domain Controllers, Azure portals, or hypervisors**.
* Prevents **privileged credentials from being exposed on potentially compromised user workstations**.
* Often integrated with **Privileged Identity Management (PIM)** for temporary elevation.
* Used in **Tiered Admin Models**:

  * Tier 0 → Domain Controllers / Identity
  * Tier 1 → Servers
  * Tier 2 → Workstations
* PAWs typically enforce:

  * Restricted software
  * Application allow-listing
  * No email or web browsing
* Organizations use them to **reduce the attack surface for administrative accounts**.

---

# 3. Attacker Abuse

Attackers often target PAW protections because **compromising a PAW gives direct access to high-value administrative privileges**.

### Common Abuse Scenarios

* **Credential Theft from PAWs**

  * Malware attempts to dump credentials from PAW memory.
  * MITRE: Credential Dumping (T1003)

* **Privileged Account Misuse Outside PAW**

  * Admin credentials used on regular workstations.
  * MITRE: Valid Accounts (T1078)

* **Lateral Movement to PAW**

  * Attackers pivot to the PAW to harvest high privilege tokens.
  * MITRE: Remote Services (T1021)

* **Compromised Admin Workstation → Domain Takeover**

  * If a PAW is not isolated properly, malware can capture domain admin credentials.

* **Shadow Admin Behavior**

  * Privileged actions performed from non-PAW devices.

* **Cloud Console Abuse**

  * Admin uses normal workstation to log into AWS/Azure admin portals.

---

# 4. SIEM Detection Opportunities

### Alert 1 — Privileged Account Login from Non-PAW Host

**Suspicious Behavior**

Admin credentials used from a workstation not designated as a PAW.

**Detection Logic**

```
IF account IN privileged_accounts
AND source_host NOT IN PAW_asset_list
THEN alert
```

**Log Sources**

* Windows Security Event Logs (4624)
* Active Directory logs
* EDR telemetry
* Identity provider logs (Azure AD / Okta)

---

### Alert 2 — Domain Admin Interactive Login to Workstation

**Suspicious Behavior**

Domain admin logging directly into a user workstation.

**Detection Logic**

```
EventID = 4624
LogonType = 2 OR 10
AccountGroup = "Domain Admins"
HostRole = "Workstation"
```

**Log Sources**

* Windows Security Logs
* Domain Controller authentication logs
* EDR telemetry

---

### Alert 3 — Privileged Session from Untrusted Network

**Suspicious Behavior**

Admin access initiated from external network or VPN endpoint not associated with PAW.

**Detection Logic**

```
IF privileged_login = TRUE
AND source_ip NOT IN trusted_admin_networks
```

**Log Sources**

* VPN logs
* Firewall logs
* Identity provider logs
* Cloud audit logs

---

### Alert 4 — Remote Access to PAW System

**Suspicious Behavior**

Remote RDP/SMB session into PAW host from a non-admin machine.

**Detection Logic**

```
EventID = 4624
LogonType = 10
DestinationHost IN PAW_asset_list
SourceHost NOT IN admin_network
```

**Log Sources**

* Windows Security Logs
* RDP logs
* EDR telemetry

---

### Alert 5 — Privileged Account Running Suspicious Tools on PAW

**Suspicious Behavior**

Execution of credential dumping or lateral movement tools.

**Detection Logic**

```
ProcessName IN ("mimikatz","procdump","rubeus")
UserPrivilege = Admin
HostRole = PAW
```

**Log Sources**

* EDR telemetry
* Windows Event ID 4688
* Sysmon Process Creation logs

---

# 5. Investigation Indicators

SOC analysts investigating PAW alerts should review:

* **Authentication Logs**

  * Windows Event ID **4624 / 4625**
  * Privileged account login locations

* **Host Activity**

  * Process creation logs (Sysmon 1 / Event 4688)
  * Suspicious tools or scripts

* **Network Connections**

  * Lateral movement attempts
  * RDP/SMB sessions involving PAWs

* **Credential Artifacts**

  * LSASS memory access attempts
  * Token manipulation behavior

* **Asset Role Verification**

  * Confirm if host is registered as an official PAW

* **User Behavior**

  * Admin accessing email/web from PAW
  * Logins outside standard admin hours

---

# 6. Mitigations / Security Best Practices

**Strict PAW Isolation**

* Separate PAW network segment from normal workstation network.

**Enforce Tiered Administration**

* Prevent Tier 0 credentials from logging into lower tier systems.

**Application Allowlisting**

* Use **AppLocker / WDAC** to restrict executable tools.

**Credential Protections**

* Enable:

  * Windows Credential Guard
  * LSASS protection
  * Restricted Admin Mode

**Multi-Factor Authentication**

* Enforce MFA for privileged accounts across:

  * VPN
  * Cloud consoles
  * Identity providers

**Monitoring Improvements**

* Maintain **asset inventory of PAW systems** in SIEM.
* Track **privileged account logins outside PAW baseline**.
* Monitor **remote access attempts to PAWs**.

---