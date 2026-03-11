## 1. What It Is

* AWS Inspector is an automated vulnerability and configuration assessment service for AWS workloads.
* It scans EC2 instances, container images, and Lambda functions for known vulnerabilities, misconfigurations, and insecure network configurations.
* Generates findings with severity levels (Low, Medium, High, Critical) and integrates with AWS Security Hub or SIEMs via CloudWatch Events.
* Used in **AWS environments**, primarily EC2, ECR (containers), Lambda, and Security Hub-integrated dashboards.
* Helps identify CVEs, CIS benchmark deviations, and runtime security risks.

---

## 2. Legitimate Use

* Continuous vulnerability assessment for cloud workloads.
* Compliance validation against standards like CIS AWS Foundations, PCI-DSS, and HIPAA.
* Prioritize patching and remediation of critical vulnerabilities in EC2 instances or container images.
* Supports DevSecOps pipelines by scanning container images pre-deployment.
* Generates actionable reports for cloud security teams and auditors.

---

## 3. Attacker Abuse

* Misuse is rare directly, but attackers can use findings indirectly:

  * Leverage unpatched CVEs reported by Inspector to compromise EC2 instances.
  * Identify misconfigured IAM roles or overly permissive security group exposures detected in Inspector reports.
  * Use knowledge of security findings to plan lateral movement or privilege escalation.
* Techniques mapping to MITRE ATT&CK:

  * **T1190 – Exploit Public-Facing Application** (if Inspector flags vulnerable services)
  * **T1078 – Valid Accounts** (abusing misconfigured accounts found via findings)
  * **T1560 – Cloud Service Discovery** (attackers can exploit misconfigurations detected by Inspector)

---

## 4. SIEM Detection Opportunities

* **Alert Name:** New High-Critical Vulnerability Detected

  * **Suspicious Behavior:** EC2 or container image reports a critical CVE via Inspector
  * **Detection Logic:** `IF Inspector findings severity >= High THEN generate alert`
  * **Log Sources:** AWS CloudWatch Events, Security Hub, CloudTrail

* **Alert Name:** Unauthorized Inspector Scan Trigger

  * **Suspicious Behavior:** Inspector assessment run by unknown or non-admin IAM user
  * **Detection Logic:** `IF CloudTrail event = CreateAssessmentTarget AND user NOT in approved admins THEN alert`
  * **Log Sources:** CloudTrail, CloudWatch

* **Alert Name:** Repeated Failed Remediation Attempts

  * **Suspicious Behavior:** Multiple failed attempts to remediate vulnerabilities flagged by Inspector
  * **Detection Logic:** `IF Inspector finding remediation state = FAILED > 3 times within 1 hour THEN alert`
  * **Log Sources:** Inspector logs, CloudWatch, Security Hub

* **Alert Name:** Unexpected Open Network Ports

  * **Suspicious Behavior:** Inspector flags new misconfigured or exposed ports in EC2 instances
  * **Detection Logic:** `IF security group findings indicate new public-facing ports THEN alert`
  * **Log Sources:** Inspector findings, VPC Flow Logs, CloudTrail

---

## 5. Investigation Indicators

* Check **Inspector Findings Report**: severity, resource affected, CVE IDs.
* IAM user or role triggering scans—look for unusual accounts or unusual scan frequency.
* Look for repeated failure to patch or remediate critical findings.
* Correlate with network traffic logs for exploitation attempts of detected vulnerabilities.
* Check EDR telemetry on EC2/container for signs of compromise related to CVEs.

---

## 6. Mitigations / Security Best Practices

* Enable **automatic assessment runs** and integrate findings with Security Hub for centralized monitoring.
* Limit Inspector access to **security/operations IAM roles**; use least privilege.
* Regularly **patch and update EC2 instances, container images, and Lambda functions**.
* Monitor CloudTrail for **unauthorized Inspector scans or API activity**.
* Automate remediation workflows where possible (SSM Run Command, Lambda triggers).
* Review and harden **network security groups, IAM roles, and container configurations** flagged by Inspector findings.

---