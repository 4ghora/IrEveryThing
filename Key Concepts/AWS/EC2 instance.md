## 1. What It Is

* **Amazon EC2 (Elastic Compute Cloud)** is a cloud service that provides **virtual machines (instances)** running in the **Amazon Web Services (AWS)** cloud.
* An **EC2 instance** is a **virtual server** that runs an OS (Linux or Windows) with configurable CPU, memory, networking, and storage.
* Instances run inside **VPC networks**, attach **EBS volumes**, and can use **IAM roles** to access other AWS services.
* Instances are commonly accessed through **SSH (Linux)** or **RDP (Windows)**.
* Operational actions such as **start, stop, terminate, modify, or create instances** are logged via **CloudTrail**.
* In enterprise environments, EC2 instances often host **applications, databases, containers, CI/CD systems, or internal services**.

---

# 2. Legitimate Use

* **Application hosting**

  * Web servers, APIs, microservices, backend services.
* **Enterprise workloads**

  * Windows domain servers, application servers, middleware platforms.
* **Development and testing**

  * Temporary instances spun up for CI/CD pipelines or testing environments.
* **Data processing**

  * Batch jobs, big data processing, machine learning workloads.
* **Scalable infrastructure**

  * Integrated with **Auto Scaling Groups** and load balancers.
* **Bastion / jump hosts**

  * Secure entry points for administrators to access private networks.

---

# 3. Attacker Abuse

Attackers frequently target EC2 because it provides **compute, network access, and IAM privileges**.

### 1. Credential-Based Instance Creation

* Stolen AWS keys used to **launch attacker-controlled EC2 instances**.
* Often used for **cryptomining or staging attacks**.
* MITRE:

  * **T1078**

---

### 2. IAM Role Abuse via Instance Metadata

* If attackers gain access to an EC2 instance they can query:

  * `http://169.254.169.254`
* This returns **temporary IAM credentials** from the instance role.
* MITRE:

  * **T1552**
  * **T1528**

---

### 3. Persistence via Rogue EC2 Instances

* Attackers create hidden instances in unused regions.
* Used for:

  * persistence
  * command and control
  * data staging
* MITRE:

  * **T1136**
  * **T1098**

---

### 4. EC2 Used for Internal Recon

* Once compromised, instances can scan internal networks.
* Attackers enumerate:

  * internal services
  * other instances
  * databases.
* MITRE:

  * **T1046**

---

### 5. Data Exfiltration Staging Node

* Attackers spin up EC2 instances to:

  * receive stolen data
  * proxy outbound traffic.
* MITRE:

  * **T1041**

---

# 4. SIEM Detection Opportunities

### Alert 1: New EC2 Instance Launched in Unusual Region

**Suspicious Behavior**

* Instances created in regions where the organization normally does not operate.

**Detection Logic**

```
eventName = RunInstances
AND awsRegion NOT IN approved_regions
```

**Log Sources**

* CloudTrail
* AWS Config
* SIEM cloud audit logs

---

### Alert 2: High Volume EC2 Instance Creation

**Suspicious Behavior**

* Burst of instance launches indicating cryptomining or attacker automation.

**Detection Logic**

```
COUNT(eventName="RunInstances")
BY userIdentity
WITHIN 10 minutes > threshold
```

**Log Sources**

* CloudTrail
* AWS CloudWatch Logs

---

### Alert 3: Instance Metadata Credential Abuse

**Suspicious Behavior**

* EC2 instance retrieving IAM credentials followed by external API calls.

**Detection Logic**

```
metadata credential retrieval
FOLLOWED BY
AWS API calls from new IP
```

**Log Sources**

* VPC Flow Logs
* EDR telemetry
* CloudTrail

---

### Alert 4: EC2 Security Group Modified to Allow Public Access

**Suspicious Behavior**

* Security group modified to allow inbound access from **0.0.0.0/0**.

**Detection Logic**

```
eventName = AuthorizeSecurityGroupIngress
AND cidrIp = "0.0.0.0/0"
AND port IN (22,3389)
```

**Log Sources**

* CloudTrail
* AWS Config

---

### Alert 5: EC2 Instance Role Used From External Location

**Suspicious Behavior**

* Temporary credentials associated with an EC2 role used from **non-AWS infrastructure**.

**Detection Logic**

```
userIdentity.type = AssumedRole
AND sourceIPAddress NOT IN AWS_IP_RANGES
```

**Log Sources**

* CloudTrail
* VPC Flow Logs
* Identity logs

---

# 5. Investigation Indicators

When investigating suspicious EC2 activity, analysts should examine:

* **CloudTrail events**

  * `RunInstances`
  * `TerminateInstances`
  * `ModifyInstanceAttribute`
  * `AssociateIamInstanceProfile`

* **Instance metadata access**

  * requests to `169.254.169.254`.

* **Unusual regions or availability zones**

  * attackers often deploy resources in **unused regions**.

* **Unexpected IAM role usage**

  * instance roles accessing **S3, Secrets Manager, or IAM APIs**.

* **Outbound network traffic**

  * connections to:

    * crypto mining pools
    * suspicious external IPs
    * TOR nodes.

* **Instance tagging anomalies**

  * missing or unusual tags (attackers rarely tag resources properly).

---

# 6. Mitigations / Security Best Practices

### Hardening

* Enforce **IMDSv2** to prevent metadata credential theft.
* Use **least privilege IAM roles** for instances.
* Restrict **SSH/RDP exposure** using security groups.

---

### Monitoring

* Enable:

  * **CloudTrail (all regions)**
  * **VPC Flow Logs**
  * **GuardDuty**
* Monitor for:

  * unusual instance launches
  * abnormal API usage.

---

### Preventive Controls

* Use **Service Control Policies (SCPs)** to restrict instance creation in unauthorized regions.
* Implement **AWS Config rules** for security group misconfigurations.
* Require **MFA for privileged IAM users**.
* Use **instance tagging enforcement policies**.

---

✅ **SOC Insight**

From a SOC perspective, EC2 is one of the **most abused AWS services** because attackers can:

* create compute resources
* pivot internally
* steal IAM credentials
* run cryptominers

Therefore, **CloudTrail monitoring for `RunInstances` and IAM role activity is one of the highest priority detections in AWS environments.**

---

If you'd like, I can also explain **how attackers steal EC2 IAM credentials via SSRF and metadata abuse** — a **very common real-world cloud attack technique tested in cloud security interviews.**
