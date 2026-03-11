## 1. What it is

* **Technical Explanation:** Storage Account Access Keys are high-privilege credentials that provide full administrative access to an Azure Storage Account (blobs, queues, tables, files). Possession of a key allows full read/write/delete operations.
* **Environment:** Azure (primarily), but conceptually similar to AWS S3 Access Keys. Can be used via REST API, SDKs, CLI, or portal.
* **Persistence:** Keys remain valid until manually regenerated, making them a high-value target if leaked.
* **Management:** Two keys exist per account (primary and secondary) to enable key rotation without downtime.
* **Authentication Alternative:** Used instead of Azure AD RBAC or SAS tokens for service-level access.

---

## 2. Legitimate Use

* **Automation:** Used by applications, scripts, or services requiring full access to a storage account.
* **Legacy Systems:** Older applications may not support Azure AD authentication or SAS tokens.
* **Backup and Data Ingestion:** For automated backups, ETL jobs, or data pipelines needing unrestricted storage access.
* **High Availability:** Two keys allow rotation without service disruption.
* **Cross-Service Access:** Enables non-Azure services to interact with storage accounts securely when Azure AD isn’t available.

---

## 3. Attacker Abuse

* **Key Theft:** Attackers target storage account keys via phishing, misconfigured repositories, or compromised service principals.
* **Full Data Exfiltration:** Once obtained, keys allow downloading, modifying, or deleting all data in the storage account.
* **Persistence:** Keys provide long-term access unless rotated. Attackers may avoid detection by using legitimate tools.
* **Cloud Misuse:** Keys can be used to spin up malware-laden containers, store staging data, or move data out of the tenant.
* **MITRE ATT&CK Mapping:**

  * **T1537** – Transfer Data to Cloud Account
  * **T1078** – Valid Accounts (keys act as long-lived credentials)
  * **T1496** – Resource Hijacking

---

## 4. SIEM Detection Opportunities

| Alert Name                                    | Suspicious Behavior Description                                              | Example Detection Logic                                                    | Relevant Log Sources                                                |
| --------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Excessive Storage Key Usage**               | Access key used outside normal patterns (unusual IPs, times, or geographies) | Identify storage account key activity from rare locations or unusual hours | Azure Storage Analytics, Azure Monitor, CloudTrail (if cross-cloud) |
| **Key Regeneration Anomaly**                  | Frequent or unexpected regeneration of keys                                  | Detect multiple key rotations within short intervals                       | Azure Activity Logs, Azure AD Audit Logs                            |
| **Abnormal Data Exfiltration**                | Large volume of read/download operations using keys                          | Threshold-based alert on >X GB downloaded in Y minutes                     | Storage Analytics, Network Logs, EDR Telemetry                      |
| **Unauthorized Client Access**                | Requests from unknown IPs or unauthorized apps using keys                    | Compare source IP/app against baseline access patterns                     | Azure Storage Logs, Firewall Logs                                   |
| **Key Access from Suspicious Script/Process** | Programmatic access from non-approved automation tools                       | Detect key usage originating from unusual executables or service accounts  | EDR telemetry, Sysmon, Azure Monitor                                |

---

## 5. Investigation Indicators

* **Access Logs:** IP addresses, user agents, and timestamp patterns in Azure Storage Logs.
* **Key Usage Patterns:** Look for spikes in GET/PUT/DELETE operations or cross-region access.
* **Associated Accounts/Services:** Identify which service or application is using the key.
* **Data Access Scope:** Which containers, blobs, or tables were accessed.
* **Change History:** Key rotations, policy changes, or newly granted permissions.
* **Persistence Artifacts:** Scripts, scheduled jobs, or Azure Functions that reference the key.

---

## 6. Mitigations / Security Best Practices

* **Prefer Azure AD over Keys:** Use RBAC, Managed Identities, or SAS tokens instead of long-lived keys.
* **Key Rotation:** Rotate keys regularly and immediately if a compromise is suspected.
* **Restrict IP Ranges:** Limit access via firewall rules to known IPs or VNETs.
* **Monitor Usage:** Implement alerts for unusual geographic access, excessive reads, or key misuse.
* **Audit & Inventory:** Maintain an up-to-date inventory of applications and services using keys.
* **Secrets Management:** Store keys in secure vaults (e.g., Azure Key Vault) instead of hardcoding in scripts.

---