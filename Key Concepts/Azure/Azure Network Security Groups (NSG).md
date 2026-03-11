

# 1. What It Is

* **Azure Network Security Groups (NSGs)** are stateful Layer 3/4 firewall rules used to **control inbound and outbound network traffic** in **Microsoft Azure** virtual networks.
* NSGs contain **allow/deny rules** based on:

  * Source / Destination IP
  * Port
  * Protocol (TCP, UDP, Any)
  * Direction (Inbound / Outbound)
* They can be attached to:

  * **Subnets**
  * **Network Interfaces (NICs)** of individual VMs
* Rules are processed by **priority order (lower number = higher priority)**.
* Used in **Azure enterprise environments** to enforce **network segmentation and access control**.

---

# 2. Legitimate Use

* **Micro-segmentation of workloads**

  * Restrict traffic between application tiers (Web → App → DB).
* **Restrict administrative access**

  * Limit **RDP (3389)** or **SSH (22)** access to specific corporate IP ranges.
* **Zero Trust network design**

  * Allow only required ports and deny everything else.
* **Environment isolation**

  * Separate **production, staging, and development networks**.
* **Compliance requirements**

  * Implement firewall policies required by regulatory standards.

---

# 3. Attacker Abuse

Attackers often modify NSGs to **create persistence or enable lateral movement**.

### Common Abuse Scenarios

* **Open management ports to the internet**

  * Allow inbound **RDP/SSH from 0.0.0.0/0** to compromised VM.
* **Bypass segmentation**

  * Modify rules to allow traffic between isolated subnets.
* **Enable C2 communication**

  * Allow outbound traffic to attacker-controlled infrastructure.
* **Disable blocking rules**

  * Delete deny rules preventing malicious traffic.
* **Hide malicious infrastructure**

  * Create permissive NSGs for attacker-controlled VMs.

### MITRE ATT&CK Mapping

* **Modify Cloud Compute Infrastructure**
* **Cloud Infrastructure Discovery**
* **Ingress Tool Transfer**
* **Exfiltration Over C2 Channel**

---

# 4. SIEM Detection Opportunities

## Alert 1: NSG Rule Allowing Internet Access to Management Ports

**Suspicious Behavior**

* A rule is created allowing **0.0.0.0/0 → RDP (3389) or SSH (22)**.

**Example Detection Logic**

```
OperationName = "Create or Update Network Security Rule"
AND DestinationPort IN (22,3389)
AND SourceAddressPrefix = "0.0.0.0/0"
AND Access = "Allow"
```

**Relevant Log Sources**

* Azure Activity Logs
* Azure Resource Manager logs
* Azure Sentinel / SIEM

---

## Alert 2: NSG Rule Modification by Unusual Identity

**Suspicious Behavior**

* NSG rules modified by **new user, service principal, or compromised account**.

**Example Detection Logic**

```
OperationName = "Microsoft.Network/networkSecurityGroups/securityRules/write"
AND Caller NOT IN Known_Admin_Accounts
```

**Relevant Log Sources**

* Azure Activity Logs
* Azure AD Audit Logs
* Identity Protection logs

---

## Alert 3: High-Risk Outbound Rule Creation

**Suspicious Behavior**

* NSG rule allowing **all outbound traffic to any destination**.

**Example Detection Logic**

```
OperationName = "Create or Update Network Security Rule"
AND Direction = "Outbound"
AND DestinationAddressPrefix = "0.0.0.0/0"
AND DestinationPortRange = "*"
AND Access = "Allow"
```

**Relevant Log Sources**

* Azure Activity Logs
* Defender for Cloud alerts
* Azure Sentinel

---

## Alert 4: NSG Deletion or Detachment from Subnet

**Suspicious Behavior**

* NSG removed from a subnet or NIC, effectively disabling network restrictions.

**Example Detection Logic**

```
OperationName IN (
"Delete Network Security Group",
"Microsoft.Network/virtualNetworks/subnets/write"
)
AND Previous_NSG_Association EXISTS
```

**Relevant Log Sources**

* Azure Activity Logs
* Azure Resource Manager logs

---

## Alert 5: Multiple NSG Changes in Short Time Window

**Suspicious Behavior**

* Rapid rule creation/modification suggesting automated attack or misconfiguration.

**Example Detection Logic**

```
COUNT(NSG_Rule_Changes) > 5
WITHIN 5 minutes
BY Caller
```

**Relevant Log Sources**

* Azure Activity Logs
* SIEM correlation engine

---

# 5. Investigation Indicators

SOC analysts should investigate:

* **Identity that performed the change**

  * User account
  * Service principal
  * Managed identity
* **Source IP of the Azure API request**

  * Check if coming from unusual location.
* **Affected resources**

  * VM
  * Subnet
  * Application tier
* **Newly opened ports**

  * RDP, SSH, database ports.
* **Subsequent activity**

  * VM login attempts
  * data exfiltration
  * suspicious outbound traffic.

Additional artifacts:

* Azure Activity Logs
* NSG configuration diff
* VM sign-in logs
* Defender for Cloud alerts

---

# 6. Mitigations / Security Best Practices

* **Restrict NSG modification permissions**

  * Use **Azure Role-Based Access Control** to limit changes to network admins only.
* **Enable monitoring and alerting**

  * Send **Azure Activity Logs to SIEM** such as **Microsoft Sentinel**.
* **Use Just-In-Time VM access**

  * Enable **Microsoft Defender for Cloud JIT access** for RDP/SSH.
* **Block internet access to management ports**

  * Require **VPN or bastion access** using **Azure Bastion**.
* **Implement baseline policies**

  * Use **Azure Policy** to prevent rules allowing **0.0.0.0/0** to sensitive ports.
* **Automated configuration auditing**

  * Continuously check NSG rules using security posture tools.

---s