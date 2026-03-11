## 1. What it is

* AWS Security Hub is a **cloud security posture management service** that aggregates findings from multiple AWS security services (e.g., GuardDuty, Inspector, Macie) and third-party tools into a single dashboard.
* Provides **compliance checks**, security standards (CIS AWS Foundations, PCI DSS), and centralized alerting.
* Used primarily in **AWS environments**, but integrates with **SIEM solutions** via APIs or EventBridge for enterprise-wide monitoring.
* Continuously evaluates resources against **security best practices** and produces findings in a structured format.
* Supports **automated response workflows** using AWS Lambda and EventBridge.

---

## 2. Legitimate Use

* Centralizes security alerts from AWS services to simplify **SOC monitoring**.
* Automates **continuous compliance checks** against frameworks like CIS, helping auditors and security teams.
* Tracks and prioritizes findings across multiple AWS accounts and regions.
* Supports **integration with SIEMs** (Splunk, QRadar, Sentinel) for broader enterprise visibility.
* Enables automated workflows for **remediation** of critical security findings (e.g., disabling exposed S3 buckets).

---

## 3. Attacker Abuse

* **Finding suppression or evasion**: Attackers may modify resource tags or configurations to avoid triggering Security Hub alerts.
* **Credential misuse**: Compromised users may create or modify Security Hub integrations to blind monitoring.
* **Abuse of automation**: Malicious actors could trigger automated workflows (via EventBridge or Lambda) to **delete logs or remove evidence**.
* **Reconnaissance**: Accessing Security Hub findings may reveal misconfigured services or vulnerable resources for lateral movement.
* MITRE ATT&CK mappings:

  * **T1530** – Data from Cloud Storage (e.g., inspecting S3 findings)
  * **T1078** – Valid Accounts (abusing IAM to disable monitoring)
  * **T1562.001** – Impair Defenses: Disable or modify security tools

---

## 4. SIEM Detection Opportunities

* **Alert Name:** Security Hub Findings Disabled

  * **Suspicious Behavior:** Security Hub is turned off or its standards are modified unexpectedly.
  * **Detection Logic:** Monitor CloudTrail events for `DisableSecurityHub`, `UpdateStandardsControl`.
  * **Log Sources:** CloudTrail, EventBridge logs

* **Alert Name:** Unusual High-Severity Findings

  * **Suspicious Behavior:** Multiple high-severity findings generated in short succession.
  * **Detection Logic:** Count high-severity findings per account within a time window; alert if spike exceeds baseline.
  * **Log Sources:** Security Hub findings, CloudWatch

* **Alert Name:** Unauthorized Findings Export

  * **Suspicious Behavior:** Findings sent to external S3 buckets or third-party tools without approval.
  * **Detection Logic:** CloudTrail events for `BatchImportFindings` or cross-account S3 writes.
  * **Log Sources:** CloudTrail, S3 access logs

* **Alert Name:** Automation Rule Abuse

  * **Suspicious Behavior:** Security Hub custom actions triggering unusual Lambda or EventBridge executions.
  * **Detection Logic:** Detect unexpected Lambda invocations triggered by Security Hub custom actions.
  * **Log Sources:** CloudTrail, CloudWatch Logs, Lambda execution logs

* **Alert Name:** Findings Access Anomalies

  * **Suspicious Behavior:** IAM users or roles accessing findings they don’t normally interact with.
  * **Detection Logic:** Baseline normal Security Hub API usage and alert on anomalies.
  * **Log Sources:** CloudTrail, IAM activity logs

---

## 5. Investigation Indicators

* **Key Artifacts:**

  * Security Hub findings JSON with affected resource details.
  * CloudTrail logs for Security Hub API calls.
  * IAM changes (roles, policies) associated with Security Hub access.
  * Lambda execution logs tied to Security Hub automation.
  * Cross-account or cross-region activity logs.
* **Suspicious Patterns:**

  * Repeated high-severity findings suddenly disappearing.
  * Unusual geographic access to Security Hub dashboards.
  * Unauthorized modifications to security standards or suppression rules.

---

## 6. Mitigations / Security Best Practices

* **Configuration Hardening:**

  * Enforce Security Hub enabled in all accounts and regions; enable multi-account aggregation.
  * Apply **least privilege IAM policies** for Security Hub access.
* **Monitoring Improvements:**

  * Forward findings to SIEM and create baseline alerting thresholds for anomalies.
  * Monitor CloudTrail for all Security Hub API calls.
* **Preventive Controls:**

  * Enable multi-factor authentication (MFA) for users accessing Security Hub.
  * Integrate automated response workflows carefully; audit Lambda triggers and EventBridge rules.
  * Regularly review and validate security standard controls to prevent evasion.

---