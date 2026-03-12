# 1. What it is

* LDAP (Lightweight Directory Access Protocol) is a protocol used to query and modify directory services, primarily Active Directory (AD) in Windows environments.
* Used for authentication, authorization, and directory lookups across enterprise networks.
* Operates over TCP/UDP ports 389 (LDAP) and 636 (LDAPS, encrypted).
* Critical in Windows enterprise environments for user, group, and computer account management.
* Often integrated with services like Exchange, SharePoint, and cloud identity synchronization tools (e.g., Azure AD Connect).

---

## 2. Legitimate Use

* Directory queries to authenticate users and computers.
* Retrieving group membership, user attributes, and policy settings for applications or services.
* Synchronization of on-prem AD accounts with cloud identity platforms.
* Application access control based on AD groups.
* Enterprise automation for onboarding/offboarding using scripts querying LDAP.

---

## 3. Attacker Abuse

* **Credential harvesting:** Attackers query LDAP to enumerate users, groups, and service accounts.
* **Reconnaissance:** LDAP queries to map domain structure, privileges, and group memberships. (MITRE ATT&CK T1087.002 – Account Discovery)
* **Password attacks:** Abuse LDAP binding to attempt brute-force or password spraying. (T1110.003 – Password Spraying)
* **Privilege escalation:** Identifying accounts with administrative privileges or weak access. (T1069 – Permission Groups Discovery)
* **Exfiltration:** Exporting sensitive directory info for later lateral movement or targeted phishing campaigns.

---

## 4. SIEM Detection Opportunities

| Alert Name                | Suspicious Behavior                                             | Example Detection Logic                                                        | Relevant Log Sources                                         |
| ------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| LDAP Enumeration          | High-volume queries retrieving many user or group objects       | Count LDAP queries per account; alert if > threshold (e.g., >1000 objects/min) | Windows Security Event Logs (4648, 4624), AD DS logs, Sysmon |
| LDAP Anonymous Bind       | Unauthorized anonymous LDAP access attempt                      | Detect binds to LDAP with no authentication                                    | AD DS logs, Windows Security Event Logs                      |
| LDAP Bind Failures        | Repeated failed LDAP binds from a single source                 | Failed LDAP binds > threshold in short period                                  | AD DS logs, Windows Security Event Logs                      |
| Sensitive Group Query     | Access to highly privileged groups (Domain Admins)              | Alert on queries requesting membership of privileged groups                    | AD DS logs, Security Event Logs                              |
| Unusual LDAPS Connections | LDAPS connections from endpoints that don’t normally query LDAP | Alert on new source IPs initiating LDAPS connections                           | Windows Firewall Logs, Network IDS, EDR telemetry            |

---

## 5. Investigation Indicators

* Logs showing multiple LDAP queries targeting high-privilege groups.
* Unexpected accounts performing LDAP binds outside normal work hours or from unusual endpoints.
* Spike in failed bind attempts indicating brute-force activity.
* Exported directory data files or scripts interacting with AD programmatically.
* Lateral movement patterns after LDAP reconnaissance (e.g., access to new hosts).

---

## 6. Mitigations / Security Best Practices

* Enforce **LDAPS** for encrypted queries; disable plain LDAP where possible.
* Restrict LDAP access to authorized systems and administrators via firewall rules.
* Implement **account lockout policies** to detect and stop brute-force attempts.
* Monitor and alert on anomalous LDAP activity (high-volume queries, access to privileged groups).
* Use **tiered administrative model** to limit exposure of high-privilege accounts.
* Regularly audit AD accounts, groups, and service accounts for unnecessary permissions.

# Sample Queries

## 1. User Enumeration

* **Goal:** Identify all users in the domain.
* **Example Queries:**

```ldap
(&(objectClass=user)(objectCategory=person))
```

```ldap
(objectClass=user)
```

* Returns all user objects in AD, including service accounts and administrators.
* **SOC Detection:** High-volume queries from a single account or endpoint.

---

## 2. Group Enumeration

* **Goal:** Discover domain and privileged groups.
* **Example Queries:**

```ldap
(&(objectClass=group)(cn=Domain Admins))
```

```ldap
(objectClass=group)
```

* Attackers target groups like **Domain Admins**, **Enterprise Admins**, **Schema Admins**.
* **SOC Detection:** Queries for highly privileged groups outside normal admin operations.

---

## 3. Service Account Discovery

* **Goal:** Find accounts used for services (often with elevated privileges).
* **Example Queries:**

```ldap
(&(objectCategory=person)(objectClass=user)(description=*)) 
```

```ldap
(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)) 
```

* These return users with SPNs or special descriptions indicating service accounts.
* **SOC Detection:** Unexpected SPN queries, especially from non-admin endpoints.

---

## 4. Password/Authentication Checks

* **Goal:** Check if credentials exist via LDAP bind (pre-auth).
* **Example Attack Technique:** Bind to LDAP with known username/password to test validity.

```ldap
ldap_bind('CN=Administrator,CN=Users,DC=domain,DC=com','Password123!')
```

* **SOC Detection:** Failed bind spikes, unusual bind attempts from endpoints outside normal admin workflows.

---

## 5. Domain Structure Mapping

* **Goal:** Map organizational units (OUs), computers, and trust relationships.
* **Example Queries:**

```ldap
(&(objectClass=organizationalUnit))
```

```ldap
(objectClass=computer)
```

* Attackers map network layout for lateral movement.
* **SOC Detection:** Queries that enumerate OUs, computers, and trusts outside typical admin patterns.

---

## 6. Privileged Attribute Harvesting

* **Goal:** Exfiltrate attributes like lastLogon, manager, group memberships.
* **Example Queries:**

```ldap
(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com))
```

```ldap
(&(objectClass=user)(|(mail=*)(telephoneNumber=*)))
```

* Useful for spear phishing or targeted attacks.
* **SOC Detection:** Queries for sensitive attributes or cross-referencing multiple user attributes.

---