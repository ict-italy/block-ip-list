<!-- STATS_START -->
![Last Updated](https://img.shields.io/badge/Last%20Updated-2026--09--02%2010:17%20UTC-lightgrey) ![Total Records](https://img.shields.io/badge/Total%20Records-1812-blue) ![Total IPs](https://img.shields.io/badge/Total%20IPs-14669-success)

![/23](https://img.shields.io/badge/%2F23-7-orange) ![/24](https://img.shields.io/badge/%2F24-36-orange) ![/28](https://img.shields.io/badge/%2F28-1-orange) ![/29](https://img.shields.io/badge/%2F29-5-orange) ![/30](https://img.shields.io/badge/%2F30-6-orange) ![/31](https://img.shields.io/badge/%2F31-32-orange) ![/32](https://img.shields.io/badge/%2F32-1725-orange) 

<!-- STATS_END -->

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

> https://community.fortinet.com/fortigate-3/technical-tip-use-an-external-connector-ip-address-threat-feed-in-local-in-policy-129651

---

### 3. Block Forwarding / Transit Traffic (LAN, DMZ, VIPs)
Blocks connections from listed IPs attempting to reach internal subnets or Virtual IPs (VIPs) through the firewall.

```fortios
config firewall policy
    edit 0
        set name "Block-List Drop"
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

### 4. Verify / Diagnostics
To verify that your FortiGate is successfully downloading and parsing the blocklist, run the following command in the CLI:
```fortios
diagnose sys external-resource show GitHub-IP-Blocklist
```
This will display the download status, the number of loaded entries, and the last update timestamp directly on your firewall.

---

## ⚙️ How it works (Under the Hood)
This repository is fully automated via GitHub Actions to ensure maximum efficiency for your firewall hardware. Upon every update to either `blocklist.txt` or `blocklist-expanded.txt`, a Python script processes the lists:
1. **Deduplication:** Removes any duplicate IP entries across both files.
2. **Subnet Collapsing (`blocklist.txt`):** Aggregates overlapping IPs and subnets (e.g., merging multiple `/24`s into a `/23`) to minimize the total number of routing/policy entries, saving memory on your device.
3. **Safety Filtering:** Automatically drops private network spaces (RFC 1918) and restricted IPs to prevent accidental lockouts of local networks.
4. **Private Whitelisting:** Checks entries against a hidden Gist whitelist to ensure critical infrastructure is never blocked.
5. **Full IP Expansion (`blocklist-expanded.txt`):** For legacy systems or basic firewalls that do not support CIDR notation (subnets), the script automatically generates a second file where every subnet is fully expanded into individual IP addresses (limited to `/16` masks to prevent file size explosion).
