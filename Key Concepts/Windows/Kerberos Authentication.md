## 1. What It Is

* **Kerberos** is a ticket-based network authentication protocol that uses symmetric cryptography to authenticate users and services securely.
* It relies on a **Key Distribution Center (KDC)** which consists of the **Authentication Server (AS)** and **Ticket Granting Server (TGS)**.
* Users authenticate once and receive a **Ticket Granting Ticket (TGT)** which allows them to request service tickets.
* Kerberos avoids sending passwords over the network by using **encrypted tickets and session keys**.
* Primarily used in **Windows Active Directory environments**, but also supported on **Linux enterprise environments and some cloud-integrated identity systems**.

---

# 2. Legitimate Use

* **Single Sign-On (SSO)** within enterprise environments after the initial login.
* Secure authentication between **users, applications, and services** inside a domain.
* Used heavily by **Active Directory services** such as SMB file shares, RDP, SQL Server, and IIS.
* Enables **mutual authentication**, where both client and server verify each other.
* Reduces password exposure by using **time-limited encrypted tickets** instead of transmitting credentials.

---

# 3. Attacker Abuse

* **Kerberoasting (MITRE T1558.003)**: Attackers request service tickets for SPN accounts and crack them offline to recover service account passwords.
* **AS-REP Roasting (MITRE T1558.004)**: Accounts without Kerberos pre-authentication allow attackers to obtain crackable authentication responses.
* **Golden Ticket (MITRE T1558.001)**: With the compromised **KRBTGT account hash**, attackers forge TGTs to impersonate any user.
* **Silver Ticket (MITRE T1558.002)**: Attackers forge service tickets to access specific services without contacting the domain controller.
* **Pass-the-Ticket (MITRE T1550.003)**: Stolen Kerberos tickets from memory are reused for lateral movement.

---

# 4. SIEM Detection Opportunities

### Alert 1: Excessive Kerberos Service Ticket Requests

* **Description:** Large number of TGS requests may indicate Kerberoasting activity.
* **Detection Logic:**
  `count(EventID=4769) by user > threshold within short timeframe`
* **Log Sources:**
  Windows Security Logs (Domain Controller Event ID 4769)

---

### Alert 2: Kerberos Pre-Authentication Disabled Account Used

* **Description:** AS-REP roasting attempt against accounts with pre-authentication disabled.
* **Detection Logic:**
  `EventID=4768 AND PreAuthType=0`
* **Log Sources:**
  Windows Security Logs (Event ID 4768)

---

### Alert 3: Suspicious Service Ticket Encryption Type

* **Description:** Attackers request tickets using **RC4 encryption** because it is easier to crack.
* **Detection Logic:**
  `EventID=4769 AND TicketEncryptionType=RC4`
* **Log Sources:**
  Domain Controller Security Logs

---

### Alert 4: Abnormal Ticket Lifetime

* **Description:** Forged tickets (Golden Ticket) often have **unusually long expiration times**.
* **Detection Logic:**
  `Kerberos ticket lifetime > policy baseline`
* **Log Sources:**
  Domain Controller logs, EDR telemetry

---

### Alert 5: Service Ticket Requested for Unusual SPN

* **Description:** User requesting service tickets for multiple SPNs they normally do not access.
* **Detection Logic:**
  `EventID=4769 AND distinct SPN requests by user > threshold`
* **Log Sources:**
  Windows Security Logs

---

# 5. Investigation Indicators

* High volume of **Event ID 4769 (TGS requests)** from a single host.
* Accounts requesting **service tickets for many SPNs quickly**.
* Presence of **RC4 encrypted tickets** in environments that primarily use AES.
* Accounts with **Kerberos pre-authentication disabled**.
* Suspicious processes on endpoints like **Mimikatz, Rubeus, or Impacket tools** extracting tickets.

---

# 6. Mitigations / Security Best Practices

* Enforce **AES encryption for Kerberos tickets** and disable RC4 where possible.
* Use **strong passwords and rotation for service accounts** to prevent Kerberoasting.
* Enable **Kerberos pre-authentication for all accounts**.
* Monitor and restrict **Domain Controller access and KRBTGT account exposure**.
* Implement **EDR monitoring for credential dumping tools and abnormal Kerberos activity**.

---