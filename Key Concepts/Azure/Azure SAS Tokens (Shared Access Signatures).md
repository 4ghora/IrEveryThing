## 1. What it is

* SAS (Shared Access Signature) tokens are time-limited, permission-scoped tokens granting delegated access to Azure Storage resources (Blobs, Queues, Tables, Files) without sharing the account key.
* Can be **user-delegation SAS** (via Azure AD) or **account-level SAS** (via storage account key).
* Used in **Azure cloud environments**, primarily with **Azure Storage services**.
* Allows granular access control: read, write, delete, list, and more.
* Can specify start/end times, allowed IP ranges, and protocol restrictions (HTTPS only).

---

## 2. Legitimate Use

* Enables temporary access to storage resources for external users or services without exposing account keys.
* Common for **file sharing**, **application uploads**, **data pipelines**, and **third-party integrations**.
* Supports **automation scripts** and **serverless functions** needing scoped storage access.
* Useful in **time-bound tasks**, e.g., exporting reports or logs to external partners.
* Supports **least-privilege access** for applications and temporary credentials.

---

## 3. Attacker Abuse

* Steal SAS tokens to **exfiltrate sensitive data** or **manipulate storage**.
* Abuse overly permissive SAS tokens (e.g., write/delete) to deploy malware or ransomware.
* Generate SAS tokens via **compromised credentials** or **misconfigured applications**.
* Use stolen tokens for **lateral movement** in cloud environments.
* MITRE ATT&CK mappings:

  * **T1078** – Valid Accounts (use compromised SAS)
  * **T1530** – Data from Cloud Storage Object
  * **T1486** – Data Encrypted for Impact (if write/delete abused)

---

## 4. SIEM Detection Opportunities

| Alert Name                              | Suspicious Behavior                                                   | Example Detection Logic                                                            | Log Sources                                    |
| --------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------- |
| **Unusual SAS Token Creation**          | SAS token created outside normal schedule or by non-standard accounts | Detect SAS creation events from rare IPs, unusual users, or outside business hours | Azure Activity Logs, Azure Storage Logs        |
| **Excessive SAS Token Usage**           | High volume of SAS token requests in short period                     | Count SAS token usage per token; alert on spikes above baseline                    | Azure Storage Logs                             |
| **SAS Token with Extended Permissions** | SAS token grants unusual permissions (delete/write)                   | Inspect SAS token ACLs for risky permissions                                       | Azure Storage Logs, Azure AD Logs              |
| **Access from Unusual Geo Locations**   | SAS token used from unexpected IP addresses or regions                | Geo-map IPs accessing storage via SAS and alert on anomalies                       | Azure Storage Logs, Azure AD Sign-in Logs      |
| **Anonymous or Public SAS Exposure**    | Tokens allowing public access detected                                | Identify containers/blobs with SAS token enabling public read/write                | Azure Storage Inventory, Azure Security Center |

---

## 5. Investigation Indicators

* Examine **who generated the SAS token**, **when**, and **permissions granted**.
* Analyze **access logs tied to SAS tokens**, including IP addresses, operations (read/write/delete), and data paths.
* Look for **multiple SAS tokens generated in short intervals** or by service accounts that normally don’t create SAS.
* Check for **tokens used beyond expiration** or from abnormal regions.
* Review **application code or scripts** that may have leaked SAS tokens.

---

## 6. Mitigations / Security Best Practices

* Use **short-lived SAS tokens** and **least privilege permissions** (read-only where possible).
* Enable **Azure AD-based user delegation SAS** instead of account keys.
* Restrict **IP ranges and protocols** for SAS tokens.
* Monitor **creation and usage of SAS tokens** via Azure Activity Logs and integrate into SIEM alerts.
* Rotate storage account keys regularly and avoid embedding SAS tokens in public repos or client-side code.

---