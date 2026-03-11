# 1. What it is

* **Amazon VPC Security Groups** are **stateful virtual firewalls** that control inbound and outbound traffic to resources within **Amazon Virtual Private Cloud**.
* They operate at the **instance or ENI (Elastic Network Interface)** level, filtering traffic based on **protocol, port, and source/destination IP or security group**.
* Rules are **allow-only**; there are no explicit deny rules. If traffic isn’t allowed, it is implicitly denied.
* Security groups are **stateful**, meaning return traffic is automatically allowed when a request is permitted.
* Commonly used in **AWS cloud environments** to protect **EC2 instances, RDS databases, load balancers, and other VPC resources**.

---

# 2. Legitimate Use

* Restrict network access to workloads such as **web servers (80/443), SSH (22), RDP (3389), or database ports**.
* Implement **application tier segmentation** (e.g., web → app → database tiers).
* Allow **security group referencing** to permit traffic between trusted resources without exposing them publicly.
* Control **administrative access** (SSH/RDP) only from trusted IP ranges like corporate VPN.
* Enable **dynamic infrastructure** where instances inherit network rules automatically through assigned security groups.

---

# 3. Attacker Abuse

* Attackers modify security groups to **expose services to the internet** (e.g., opening SSH/RDP to `0.0.0.0/0`).
* Compromised IAM credentials can be used to **add permissive inbound rules** for persistence or lateral movement.
* Attackers may allow **internal lateral movement** by permitting overly broad traffic between security groups.
* They may open outbound traffic to allow **C2 communication** or data exfiltration.
* Relevant **MITRE ATT&CK Techniques**:

  * **T1562** – modifying security configurations
  * **T1090** – enabling outbound connectivity for C2
  * **T1021** – exposing SSH/RDP for remote access
  * **T1046** – scanning newly exposed services

---

# 4. SIEM Detection Opportunities

### Alert 1 — Security Group Allows Public Administrative Access

* **Suspicious Behavior:** Security group modified to allow SSH/RDP from `0.0.0.0/0`.
* **Detection Logic:**

  * CloudTrail event `AuthorizeSecurityGroupIngress`
  * `port in (22,3389)` AND `cidrIp = 0.0.0.0/0`
* **Log Sources:**

  * **AWS CloudTrail**
  * **Amazon GuardDuty**

---

### Alert 2 — Mass Security Group Rule Changes

* **Suspicious Behavior:** Large number of rule modifications in short timeframe (possible attacker automation).
* **Detection Logic:**

  * Count of `AuthorizeSecurityGroupIngress` OR `RevokeSecurityGroupIngress` > threshold within 5 minutes.
* **Log Sources:**

  * CloudTrail
  * SIEM correlation logs

---

### Alert 3 — Security Group Modified by Unusual IAM Identity

* **Suspicious Behavior:** Security group change performed by user/service that normally does not manage networking.
* **Detection Logic:**

  * Event: `AuthorizeSecurityGroupIngress` OR `AuthorizeSecurityGroupEgress`
  * `userIdentity` NOT IN baseline network admin roles.
* **Log Sources:**

  * CloudTrail
  * IAM logs

---

### Alert 4 — Security Group Egress Opened to Internet

* **Suspicious Behavior:** Egress rule modified to allow outbound traffic to `0.0.0.0/0` for unusual ports.
* **Detection Logic:**

  * Event `AuthorizeSecurityGroupEgress`
  * Destination CIDR `0.0.0.0/0` AND port NOT IN baseline allowed ports.
* **Log Sources:**

  * CloudTrail
  * VPC Flow Logs

---

### Alert 5 — Security Group Attached to Multiple Instances Unexpectedly

* **Suspicious Behavior:** Potential lateral movement by attaching permissive security group to many instances.
* **Detection Logic:**

  * Event `ModifyNetworkInterfaceAttribute` OR `RunInstances` with unusual security group ID.
* **Log Sources:**

  * CloudTrail
  * **Amazon VPC Flow Logs**

---

# 5. Investigation Indicators

* Recent **CloudTrail events** involving:

  * `AuthorizeSecurityGroupIngress`
  * `AuthorizeSecurityGroupEgress`
  * `RevokeSecurityGroup*`
* IAM identity responsible for the change (user, role, assumed role session).
* Source IP address from the API call (possible attacker infrastructure).
* **Security group rule history** and baseline comparison.
* Unusual network activity in **VPC Flow Logs** after the rule change (e.g., new inbound SSH connections).
* Newly exposed instances or ports not previously reachable from the internet.

---

# 6. Mitigations / Security Best Practices

* Restrict security group management to **dedicated IAM roles** with least privilege.
* Implement **AWS Config rules** to detect overly permissive rules (e.g., `0.0.0.0/0` for admin ports).
* Enable automated alerting via **AWS Security Hub**.
* Use **infrastructure-as-code (Terraform/CloudFormation)** and prevent manual changes where possible.
* Enforce **just-in-time access** for SSH/RDP instead of permanent open rules.
* Continuously monitor changes using **CloudTrail + SIEM correlation** and maintain rule baselines.

---