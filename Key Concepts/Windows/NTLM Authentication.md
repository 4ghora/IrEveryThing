# 1. What It Is

* **NTLM (NT LAN Manager)** is a Microsoft authentication protocol used to authenticate users and computers in Windows environments.
* It is a **challenge-response protocol** where the server sends a challenge and the client responds using a hash derived from the user’s password.
* NTLM does **not require a domain controller connection**, which allows it to function in legacy or offline scenarios.
* Commonly used when **Kerberos cannot be used** (e.g., non-domain systems, IP-based connections, legacy apps).
* Found mainly in **Windows environments**, but also appears in **SMB, IIS, Exchange, SharePoint, and some Linux Samba environments**.

---

# 2. Legitimate Use

* **Backward compatibility** with legacy systems and applications that do not support Kerberos.
* **Local account authentication** where domain authentication is unavailable.
* **Cross-network authentication** where Kerberos SPN resolution fails.
* Used by **SMB file sharing, IIS web authentication, and some enterprise applications**.
* Used in **workgroup environments or standalone systems** without Active Directory.

---

# 3. Attacker Abuse

Attackers heavily abuse NTLM because it relies on **password hashes instead of tickets**.

### Common Attacks

* **Pass-the-Hash (PtH)**
  Attackers authenticate using a stolen NTLM hash without needing the plaintext password.

* **NTLM Relay Attacks**
  Intercept NTLM authentication and relay it to another service to gain access.

* **Credential Dumping**
  Extract NTLM hashes from LSASS memory.

* **SMB Relay / Lateral Movement**

### Typical Attack Scenarios

* Compromise workstation → dump credentials → perform **Pass-the-Hash to other systems**.
* Use tools like **Responder + ntlmrelayx** to perform **NTLM relay attacks**.
* Exploit **LLMNR/NBT-NS poisoning** to capture NTLM hashes.
* Abuse NTLM authentication against **SMB, LDAP, HTTP, MSSQL** services.

### MITRE ATT&CK Mapping

* **T1550.002 – Use of Stolen Credentials: Pass the Hash**
* **T1557.001 – Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning**
* **T1110 – Brute Force**
* **T1003 – OS Credential Dumping**
* **T1021.002 – SMB/Windows Admin Shares**

---

# 4. SIEM Detection Opportunities

### Alert 1: NTLM Authentication from Unusual Host

**Suspicious Behavior**

User authenticates via NTLM from a host they normally do not use.

**Detection Logic**

```
IF AuthenticationProtocol = NTLM
AND SourceHost NOT IN Known_User_Hosts
AND Success = True
```

**Log Sources**

* Windows Security Logs
* Event ID **4624**
* Domain Controller Logs
* EDR Telemetry

---

### Alert 2: Excessive NTLM Authentication Failures

**Suspicious Behavior**

Multiple failed NTLM logins indicating brute force or hash spraying.

**Detection Logic**

```
COUNT(EventID=4625 AND AuthenticationPackage=NTLM)
GROUP BY SourceIP
> Threshold (e.g., 20 in 5 minutes)
```

**Log Sources**

* Windows Security Logs
* Domain Controller Logs

---

### Alert 3: NTLM Authentication to Domain Controller

**Suspicious Behavior**

NTLM used against a DC where Kerberos should normally be used.

**Detection Logic**

```
EventID = 4624
AND AuthenticationPackage = NTLM
AND DestinationHost IN DomainControllers
```

**Log Sources**

* Domain Controller Security Logs
* Event ID **4624**

---

### Alert 4: NTLM Logins Using Local Administrator Account

**Suspicious Behavior**

Local admin accounts authenticating across multiple machines (possible Pass-the-Hash).

**Detection Logic**

```
EventID = 4624
AND AuthenticationPackage = NTLM
AND AccountName = "Administrator"
AND LogonType = 3
```

**Log Sources**

* Windows Security Logs
* EDR telemetry

---

### Alert 5: NTLM Authentication from Non-Windows Systems

**Suspicious Behavior**

NTLM authentication initiated from suspicious tools or Linux hosts (Impacket, Responder).

**Detection Logic**

```
AuthenticationProtocol = NTLM
AND SourceOS != Windows
```

**Log Sources**

* Domain Controller Logs
* EDR
* Network Telemetry

---

# 5. Investigation Indicators

During investigation, analysts should review:

* **Windows Event IDs**

  * **4624** – Successful logon
  * **4625** – Failed logon
  * **4776** – NTLM authentication validation
* **Logon Type**

  * Type **3 (Network)** → SMB lateral movement
* **Authentication Package**

  * NTLM vs Kerberos
* **Source IP anomalies**

  * Logins from unusual hosts or segments
* **Multiple systems authenticating using same account**

  * Possible **Pass-the-Hash**
* **Presence of attack tools**

  * Responder
  * Impacket
  * CrackMapExec
  * Mimikatz

---

# 6. Mitigations / Security Best Practices

### Reduce or Eliminate NTLM

* **Disable NTLM where possible**
* Enforce **Kerberos authentication**

---

### Enable NTLM Auditing

Configure Windows policies:

```
Network Security: Restrict NTLM
```

Audit NTLM usage before disabling.

---

### Disable LLMNR and NBT-NS

Prevents NTLM hash capture via poisoning attacks.

Group Policy:

```
Turn off Multicast Name Resolution
```

---

### Implement SMB Signing

* Prevents **NTLM relay attacks**
* Enable SMB signing across servers.

---

### Credential Protection

* Enable **Credential Guard**
* Prevent **LSASS dumping**
* Use **Protected Users Group**

---

### Strong Monitoring

* Alert on **NTLM usage to domain controllers**
* Monitor **lateral movement patterns**
* Detect **authentication anomalies**

---