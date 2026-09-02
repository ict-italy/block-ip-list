import ipaddress
import sys
import os
import urllib.request
import urllib.error

filename = 'blocklist.txt'
whitelist_url = os.getenv('WHITELIST_URL')

whitelist_nets = []

if whitelist_url:
    try:
        req = urllib.request.Request(whitelist_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            whitelist_data = response.read().decode('utf-8')
            
        for w_line in whitelist_data.splitlines():
            w_line = w_line.strip()

            if w_line and not w_line.startswith('#'):
                try:
                    whitelist_nets.append(ipaddress.ip_network(w_line, strict=False))
                except ValueError:

                    print("Warning: Invalid IP format found in Gist. Ignored.")
        print("Whitelist loaded securely from Gist.")
    except urllib.error.URLError:
        print("Error downloading whitelist from Gist.")
else:
    print("WHITELIST_URL is not set. Proceeding without whitelist.")


lines = []
for fn in ['blocklist.txt', 'blocklist-expanded.txt']:
    try:
        with open(fn, 'r') as f:
            lines.extend(f.read().splitlines())
    except FileNotFoundError:
        print(f"File {fn} not found. Proceeding.")
if not lines:
    print("No input files found.")
    sys.exit(1)

raw_ips = []
whitelisted_count = 0  

for line in lines:
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    
    try:
        net = ipaddress.ip_network(line, strict=False)
        

        if net.is_private or net.is_loopback or net.is_multicast or net == ipaddress.ip_network('0.0.0.0/0'):
            print(f"Skipped restricted/private IP: {line}")
            continue
            

        is_whitelisted = False
        for w_net in whitelist_nets:
            if net.overlaps(w_net):

                whitelisted_count += 1
                is_whitelisted = True
                break
                
        if is_whitelisted:
            continue

        raw_ips.append(net)
    except ValueError:
        print(f"Invalid IP format skipped: {line}")


optimized_ips = list(ipaddress.collapse_addresses(raw_ips))


with open('blocklist.txt', 'w') as f:
    for ip in optimized_ips:
        f.write(f"{ip}\n")

# --- EXPAND TO SINGLE IPs ---
with open('blocklist-expanded.txt', 'w') as f:
    for ip in optimized_ips:
        if ip.prefixlen < 16:
            print(f"Warning: Subnet {ip} is too large (/{ip.prefixlen}) to expand. Skipping in expanded list.")
            continue
        for addr in ip:
            f.write(f"{addr}\n")

print(f"Optimization complete. Optimized entries: {len(optimized_ips)}.")
if whitelisted_count > 0:
    print(f"Silently removed {whitelisted_count} entries overlapping with private whitelist.")

# --- README BADGES UPDATE ---
import re
from collections import Counter
import datetime

# Calculate statistics
total_records = len(optimized_ips)
total_ips = sum(ip.num_addresses for ip in optimized_ips)
subnet_counts = Counter(ip.prefixlen for ip in optimized_ips)

# Generate badges markdown
# -------------------------------------------------------------------------
# COLOR CONFIGURATION:
# You can change the colors at the end of each URL (e.g., '-blue', '-success').
# Popular colors: blue, green, red, yellow, orange, purple, pink, lightgrey.
# 'success' = bright green, 'critical' = red, 'important' = orange.
# -------------------------------------------------------------------------
last_updated_raw = datetime.datetime.now(datetime.timezone.utc).strftime("%Y--%m--%d %H:%M UTC")
last_updated = last_updated_raw.replace(' ', '%20')
badges_md = f"![Last Updated](https://img.shields.io/badge/Last%20Updated-{last_updated}-lightgrey) "
badges_md += f"![Total Records](https://img.shields.io/badge/Total%20Records-{total_records}-blue) "
badges_md += f"![Total IPs](https://img.shields.io/badge/Total%20IPs-{total_ips}-success)\n\n"

for prefix, count in sorted(subnet_counts.items()):
    badges_md += f"![/{prefix}](https://img.shields.io/badge/%2F{prefix}-{count}-orange) "

badges_md += "\n\n"

# Update README.md
readme_path = 'README.md'
try:
    with open(readme_path, 'r', encoding='utf-8') as f:
        readme_content = f.read()
        
    new_readme_content = re.sub(
        r'<!-- STATS_START -->.*?<!-- STATS_END -->',
        f'<!-- STATS_START -->\n{badges_md}<!-- STATS_END -->',
        readme_content,
        flags=re.DOTALL
    )

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(new_readme_content)
    print("README.md updated with latest statistics badges.")
except FileNotFoundError:
    print(f"Warning: {readme_path} not found. Badges not updated.")
