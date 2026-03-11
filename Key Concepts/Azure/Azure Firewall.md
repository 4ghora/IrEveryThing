## 1. What it is

* **Azure Firewall** is a **managed, stateful Layer 3–7 firewall service in Microsoft Azure** used to control inbound and outbound traffic for cloud workloads.
* Provides **network rules, application rules, and DNAT rules** to filter traffic based on IP, ports, FQDNs, and protocols.
* Typically deployed in a **hub-and-spoke network architecture** to centralize traffic inspection.
* Integrates with **Azure Monitor, Microsoft Sentinel, and Azure Log Analytics** for logging and SIEM analysis.
* Supports **threat intelligence filtering, TLS inspection, and forced tunneling** for enhanced security.
* Commonly used to control **egress internet traffic from Azure VMs, containers, and PaaS services**.

---

# 2. Legitimate Use

* Centralized **network security control point** for Azure VNets.
* Enforces **egress filtering** to restrict outbound internet traffic from workloads.
* Implements **application-based filtering** (allow only trusted domains like software updates).
* Provides **DNAT rules** to expose internal services (e.g., web servers) to the internet securely.
* Used in **hub-spoke architectures** where all spokes route traffic through a shared firewall.
* Integrates with **SIEM tools for visibility and threat monitoring**.

---

# 3. Attacker Abuse

Attackers rarely “exploit” Azure Firewall directly but may **abuse firewall configurations** after gaining access.

### Common Abuse Scenarios

* **Firewall rule modification to allow C2 traffic**

  * Attacker modifies rules to allow outbound connections to attacker infrastructure.

* **Creating overly permissive rules**

  * Example: `Allow Any → Internet` enabling unrestricted outbound access.

* **Abusing DNAT rules**

  * Exposing internal resources (RDP/SSH) to the internet.

* **Log tampering**

  * Disabling diagnostics to hide malicious traffic.

* **Using allowed outbound rules for data exfiltration**

### Relevant MITRE ATT&CK Techniques

* T1562.004 – Impair Defenses: Disable or Modify System Firewall
* T1071 – Application Layer Protocol
* T1041 – Exfiltration Over C2 Channel
* T1021 – Remote Services

---

# 4. SIEM Detection Opportunities

### Alert 1: Azure Firewall Rule Modification

**Suspicious Behavior**

* A firewall rule is added, modified, or deleted which may weaken network security.

**Detection Logic**

```
OperationName == "Microsoft.Network/azureFirewalls/write"
OR
OperationName contains "firewallPolicy"
```

Look for:

* rule changes
* policy updates

**Log Sources**

* Azure Activity Logs
* Azure Firewall Administrative Logs
* Azure Resource Manager logs

---

### Alert 2: Suspicious Outbound Traffic to Rare External IP

**Suspicious Behavior**

* Internal workloads initiating connections to previously unseen or rare external IP addresses.

**Detection Logic**

```
AzureFirewallNetworkRule
| summarize count() by SourceIP, DestinationIP
| where DestinationIP not in known_baseline
```

**Log Sources**

* Azure Firewall Network Rule Logs
* Azure Log Analytics
* Microsoft Sentinel

---

### Alert 3: Unusual High Volume Outbound Traffic (Possible Exfiltration)

**Suspicious Behavior**

* Large outbound traffic volume from a VM or subnet through Azure Firewall.

**Detection Logic**

```
AzureFirewallNetworkRule
| summarize total_bytes=sum(Bytes) by SourceIP
| where total_bytes > threshold
```

**Log Sources**

* Azure Firewall Flow Logs
* Azure Monitor
* Network Watcher logs

---

### Alert 4: DNAT Rule Created Exposing Management Ports

**Suspicious Behavior**

* New DNAT rule exposing RDP (3389) or SSH (22) to the internet.

**Detection Logic**

```
OperationName == "Microsoft.Network/azureFirewalls/write"
AND
RuleType == "DNAT"
AND
DestinationPort in (22,3389)
```

**Log Sources**

* Azure Activity Logs
* Azure Firewall Policy Logs

---

### Alert 5: Firewall Diagnostics Logging Disabled

**Suspicious Behavior**

* Firewall diagnostic logs disabled, potentially hiding malicious traffic.

**Detection Logic**

```
OperationName == "Microsoft.Insights/diagnosticSettings/delete"
OR
OperationName == "Microsoft.Insights/diagnosticSettings/write"
```

**Log Sources**

* Azure Activity Logs
* Azure Monitor Logs

---

# 5. Investigation Indicators

SOC analysts investigating suspicious Azure Firewall activity should review:

* **Recent firewall rule changes**

  * Who modified them
  * Time of change
  * Justification.

* **Unusual outbound traffic patterns**

  * Large transfers
  * New external destinations.

* **Source workload behavior**

  * VM process activity
  * Possible malware beaconing.

* **DNAT rules exposing sensitive services**

  * RDP
  * SSH
  * databases.

* **Diagnostic logging status**

  * Was logging disabled before suspicious activity?

* **IP reputation**

  * Destination IP flagged by threat intel feeds.

---

# 6. Mitigations / Security Best Practices

### Configuration Hardening

* Implement **least privilege RBAC** for firewall management.
* Restrict firewall policy changes to **network security administrators only**.
* Use **Azure Firewall Policy** instead of local rules for centralized control.
* Avoid **Any → Internet outbound rules** unless necessary.

### Monitoring Improvements

* Enable **Azure Firewall diagnostic logs**:

  * Network Rule Logs
  * Application Rule Logs
  * Threat Intelligence Logs.

* Send logs to **Microsoft Sentinel or enterprise SIEM**.

* Create alerts for:

  * firewall rule changes
  * abnormal egress traffic.

### Preventive Controls

* Enable **Threat Intelligence mode (Alert or Deny)**.
* Use **egress filtering with FQDN allowlists**.
* Implement **Just-In-Time access for management ports**.
* Regularly review firewall rules and remove unused entries.

---