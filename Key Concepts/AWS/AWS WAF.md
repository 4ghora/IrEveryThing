# 1. What It Is

* **AWS WAF** is a **Layer 7 web application firewall** that filters and monitors HTTP/HTTPS requests before they reach applications.
* It protects workloads behind services like **Amazon CloudFront**, **Application Load Balancer**, **Amazon API Gateway**, and **AWS AppSync**.
* Security rules inspect **IP addresses, headers, URI paths, query strings, and request bodies**.
* Used in **AWS cloud environments** to block attacks like SQL injection, XSS, bots, and malicious payloads.
* Integrates with **AWS Shield**, logging to **Amazon CloudWatch** or **Amazon S3** for SOC visibility.

---

# 2. Legitimate Use

* Protect **internet-facing web applications and APIs** from common web attacks.
* Enforce **IP allowlists/denylists** and geo-blocking policies.
* Deploy **managed rule sets** for OWASP Top 10 protections.
* Implement **rate limiting** to mitigate bot abuse and credential stuffing.
* Integrate with **CloudFront/CDN** to filter malicious traffic at edge locations.
* Enable **centralized web security control** for microservices and API architectures.

---

# 3. Attacker Abuse

* **Disable or weaken WAF protections** to allow malicious traffic.
* Modify rules to **allow attacker IPs or remove blocked patterns**.
* Create overly broad **allow rules that bypass inspection**.
* Use stolen AWS credentials to **associate/disassociate WAF from protected resources**.
* Modify logging configuration to **disable WAF logs and evade detection**.
* MITRE ATT&CK mappings:

  * **MITRE ATT&CK T1562 – Impair Defenses**
  * T1098 – Account Manipulation
  * T1078 – Valid Accounts
  * T1565 – Data Manipulation (rule modification)

Typical attacker scenario:

1. Compromise IAM user/role
2. Modify WAF rules or detach WAF from CloudFront/ALB
3. Launch web attacks (SQLi, webshell upload, credential stuffing)

---

# 4. SIEM Detection Opportunities

### Alert: **AWS WAF Disabled or Disassociated**

* **Behavior:** WAF removed from protected resource (ALB, CloudFront).
* **Detection Logic:**

  * CloudTrail event `DisassociateWebACL` OR `DeleteWebACL`
  * Initiated by unusual IAM principal or outside maintenance window.
* **Log Sources:**

  * CloudTrail
  * IAM logs
  * AWS Config

---

### Alert: **Suspicious WAF Rule Modification**

* **Behavior:** Security rules changed unexpectedly.
* **Detection Logic:**

  * CloudTrail event `UpdateWebACL` or `UpdateRuleGroup`
  * Change introduces `ALLOW` rule with wildcard pattern or attacker IP.
* **Log Sources:**

  * CloudTrail
  * AWS Config
  * CloudWatch Logs

---

### Alert: **WAF Logging Disabled**

* **Behavior:** Logging for WAF turned off or changed.
* **Detection Logic:**

  * CloudTrail event `DeleteLoggingConfiguration`
  * Logging target changed from S3/CloudWatch.
* **Log Sources:**

  * CloudTrail
  * AWS Config

---

### Alert: **High Volume of Blocked Requests**

* **Behavior:** Sudden spike in blocked traffic indicating attack.
* **Detection Logic:**

  * WAF log entries `action=BLOCK` exceeding baseline threshold.
  * Requests from same IP or user-agent.
* **Log Sources:**

  * WAF Logs
  * CloudWatch Metrics
  * S3 WAF log storage

---

### Alert: **Rate Limit Rule Triggered (Possible Credential Stuffing)**

* **Behavior:** Rate-based rule triggered frequently for authentication endpoint.
* **Detection Logic:**

  * WAF rule `RATE_BASED` triggered > threshold within timeframe.
* **Log Sources:**

  * WAF Logs
  * CloudWatch Metrics

---

# 5. Investigation Indicators

* **CloudTrail events**

  * `UpdateWebACL`
  * `DisassociateWebACL`
  * `DeleteWebACL`
  * `PutLoggingConfiguration`
* **IAM principal performing changes**

  * Unusual role, new user, or access from unknown IP.
* **WAF logs**

  * High volume of SQLi/XSS patterns from specific IP ranges.
* **Geo anomalies**

  * Traffic from unexpected countries.
* **User-agent anomalies**

  * Bots or automation frameworks (curl, python requests).
* **Changes in rule behavior**

  * Rules suddenly changed from `BLOCK` → `ALLOW`.

---

# 6. Mitigations / Security Best Practices

* **Restrict WAF administration**

  * Least privilege IAM policies for WAF management.
* **Enable WAF logging**

  * Send logs to **S3 + CloudWatch** for SIEM ingestion.
* **Use AWS Managed Rules**

  * OWASP Top 10 protection sets.
* **Enable AWS Config rules**

  * Detect unauthorized WAF configuration changes.
* **Implement change monitoring**

  * Alert on WebACL updates or disassociation events.
* **Use centralized security monitoring**

  * Integrate logs with SIEM (Splunk, Sentinel, QRadar, Elastic).

---