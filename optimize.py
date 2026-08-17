import ipaddress
import sys
import os

filename = 'blocklist.txt'
whitelist_file = 'my_whitelist.tmp'

whitelist_nets = []

# Считываем белый список из временного файла
if os.path.exists(whitelist_file):
    with open(whitelist_file, 'r') as wf:
        for w_line in wf:
            w_line = w_line.strip()
            if w_line:
                try:
                    whitelist_nets.append(ipaddress.ip_network(w_line, strict=False))
                except ValueError:
                    print(f"Warning: Invalid whitelist IP format: {w_line}")
    
    # Заметаем следы: удаляем файл с вашими IP, чтобы он не ушел в публичный репозиторий
    os.remove(whitelist_file)

try:
    with open(filename, 'r') as f:
        lines = f.read().splitlines()
except FileNotFoundError:
    print(f"File {filename} not found.")
    sys.exit(1)

raw_ips = []

for line in lines:
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    
    try:
        net = ipaddress.ip_network(line, strict=False)
        
        # 1. Защита от блокировки локалок и дефолтных сетей
        if net.is_private or net.is_loopback or net.is_multicast or net == ipaddress.ip_network('0.0.0.0/0'):
            print(f"Skipped restricted/private IP: {line}")
            continue
            
        # 2. Защита ВАШИХ адресов
        is_whitelisted = False
        for w_net in whitelist_nets:
            if net.overlaps(w_net):
                # В логе Actions будет просто сказано, что IP пропущен, без указания из-за какого именно адреса
                print(f"Skipped {line} -> Overlaps with your whitelist!")
                is_whitelisted = True
                break
                
        if is_whitelisted:
            continue

        raw_ips.append(net)
    except ValueError:
        print(f"Invalid IP format skipped: {line}")

optimized_ips = list(ipaddress.collapse_addresses(raw_ips))

with open(filename, 'w') as f:
    for ip in optimized_ips:
        f.write(f"{ip}\n")

print(f"Optimization complete. Optimized entries: {len(optimized_ips)}.")
