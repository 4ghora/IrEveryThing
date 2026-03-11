## 1. What it is

* AWS Shield is a managed Distributed Denial of Service (DDoS) protection service for AWS resources.
* Two tiers: **Standard** (automatic protection for all AWS services) and **Advanced** (enhanced mitigation, attack diagnostics, and 24/7 DDoS response team support).
* Protects services like **CloudFront**, **Elastic Load Balancing (ELB)**, **Route 53**, and **Global Accelerator**.
* Integrated with **AWS WAF** and CloudWatch for monitoring and mitigation.
* Used primarily in **AWS cloud environments**; no native deployment on on-prem or other clouds.

---

## 2. Legitimate Use

* Protects public-facing applications from volumetric, protocol, and application-layer DDoS attacks.
* Ensures **high availability** and **business continuity** for websites and APIs.
* Provides **real-time metrics and alerts** for unusual traffic spikes.
* Enables organizations to **leverage AWS-managed mitigations** without manual network configuration.
* Often combined with WAF rules to **filter malicious traffic** targeting specific endpoints.

---

## 3. Attacker Abuse

* Attackers may **launch DDoS attacks** to disrupt services or mask other malicious activity (e.g., data exfiltration or account takeover).
* Can be used as a **smokescreen** while performing brute-force, credential-stuffing, or network reconnaissance.
* May probe **shielded resources** to find misconfigured endpoints or unprotected subdomains.
* Possible abuse in **AWS resource exhaustion attacks**, especially for cost impact (pay-per-request services under high traffic).
* MITRE ATT&CK techniques mapped:

  * **T1499** – Endpoint Denial of Service
  * **T1498** – Network Denial of Service

---

## 4. SIEM Detection Opportunities

**Alert Name:** High Rate of Incoming Requests

* Suspicious Behavior: Sudden spike in requests to a single endpoint or resource.
* Example Detection Logic: Threshold-based alert on CloudFront/ELB request counts exceeding 3× baseline within 5 minutes.
* Relevant Log Sources: CloudWatch, CloudTrail, ELB access logs, VPC Flow Logs

**Alert Name:** Unusual Geographic Traffic Distribution

* Suspicious Behavior: Massive traffic originating from atypical regions for the application.
* Example Detection Logic: Compare request geo-location against historical access patterns; trigger alert if >90% from new regions.
* Relevant Log Sources: CloudFront logs, Route 53 query logs, CloudTrail

**Alert Name:** AWS Shield Attack Notifications

* Suspicious Behavior: AWS Shield Advanced reports detected attack or mitigation action.
* Example Detection Logic: Monitor SNS notifications or AWS Config logs for `AttackDetected` events.
* Relevant Log Sources: AWS Shield Advanced notifications, CloudWatch Events, CloudTrail

**Alert Name:** Repeated 4XX/5XX Responses

* Suspicious Behavior: Surge in 4XX/5XX errors indicating potential attack probing or application stress.
* Example Detection Logic: Monitor ELB/CloudFront logs for error response spikes >2× normal baseline.
* Relevant Log Sources: ELB access logs, CloudFront logs

---

## 5. Investigation Indicators

* **Traffic patterns:** unusually high request rates, abnormal protocols, or repeated malformed packets.
* **Source IP analysis:** concentration of requests from single ASN or new geographies.
* **Resource impact:** sudden increase in CPU, memory, or application error rates.
* **CloudTrail events:** creation/modification of WAF rules, load balancers, or security groups around attack time.
* **Correlation with other alerts:** account logins, network scanning, or suspicious API calls coinciding with attack window.

---

## 6. Mitigations / Security Best Practices

* Enable **AWS Shield Advanced** for critical public-facing endpoints.
* Combine with **AWS WAF** rules to block known malicious patterns.
* Configure **CloudWatch alarms** for traffic spikes, error rates, and unusual geographic access.
* Use **rate limiting** and **throttling** for APIs and endpoints.
* Regularly review **security group and network ACL configurations** to minimize attack surface.
---