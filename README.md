# FortiGate Dynamic IP Blocklist (Threat Feed)

This repository maintains a dynamic list of malicious/scanning IP addresses (`blocklist.txt`) that can be automatically synchronized with FortiOS using **External Connectors (Threat Feeds)**.

---

## FortiGate Configuration Guide

Run the following commands via the FortiGate CLI to pull the list and enforce blocking for both **Local-in (Control Plane)** and **Forwarding (Data Plane)** traffic.

### 1. Configure the External Threat Feed Connector
Configures the FortiGate to periodically pull the IP list from GitHub.

```fortios
config system external-resource
    edit "GitHub-IP-Blocklist"
        set type address
        set resource "https://raw.githubusercontent.com/ict-italy/block-ip-list/main/blocklist.txt"
    next
end
```
> **Note:** `set refresh-rate 5` defines the update interval in minutes (default range: 1–43200).

---

### 2. Block Local-In Traffic (VPN, Management, IKE/IPsec)
Standard firewall policies only filter transit traffic. To block malicious hosts from reaching the firewall itself (e.g., scanning ports UDP 500/4500 for IPsec Phase 1 negotiation or attacking management interfaces), a **Local-In Policy** is required.

```fortios
config firewall local-in-policy
    edit 0
        set intf "any"
        set srcaddr "GitHub-IP-Blocklist"
        set dstaddr "all"
        set action deny
        set service "ALL"
        set schedule "always"
    next
end
```
> **Note:** In `local-in-policy`, the default action is **DROP/DENY**.

---

### 3. Block Forwarding / Transit Traffic (LAN, DMZ, VIPs)
Blocks connections from listed IPs attempting to reach internal subnets or Virtual IPs (VIPs) through the firewall.

```fortios
config firewall policy
    edit 0
        set name "Block-List Drop"
        set uuid cbf90fa4-9a1c-51f1-9e28-5c5e3430bdb1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "GitHub-IP-Blocklist"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```
> **Important:** Move this rule to the top of your policy table to ensure it evaluates before allow rules.

---

