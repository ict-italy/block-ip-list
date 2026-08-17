import ipaddress
import sys
import os
import urllib.request
import urllib.error

filename = 'blocklist.txt'
whitelist_url = os.getenv('WHITELIST_URL')

whitelist_nets = []

# 1. Скачиваем белый список из Secret Gist напрямую в память
if whitelist_url:
    try:
        req = urllib.request.Request(whitelist_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            whitelist_data = response.read().decode('utf-8')
            
        for w_line in whitelist_data.splitlines():
            w_line = w_line.strip()
            # Пропускаем пустые строки и комментарии
            if w_line and not w_line.startswith('#'):
                try:
                    whitelist_nets.append(ipaddress.ip_network(w_line, strict=False))
                except ValueError:
                    # Убрали вывод самого значения w_line, чтобы не светить опечатки из Gist
                    print("Warning: Invalid IP format found in Gist. Ignored.")
        print("Whitelist loaded securely from Gist.")
    except urllib.error.URLError:
        print("Error downloading whitelist from Gist.")
else:
    print("WHITELIST_URL is not set. Proceeding without whitelist.")

# 2. Читаем и оптимизируем публичный blocklist.txt
try:
    with open(filename, 'r') as f:
        lines = f.read().splitlines()
except FileNotFoundError:
    print(f"File {filename} not found.")
    sys.exit(1)

raw_ips = []
whitelisted_count = 0  # Добавляем тихий счетчик

for line in lines:
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    
    try:
        net = ipaddress.ip_network(line, strict=False)
        
        # Защита от блокировки локалок (это публичные адреса, их светить можно)
        if net.is_private or net.is_loopback or net.is_multicast or net == ipaddress.ip_network('0.0.0.0/0'):
            print(f"Skipped restricted/private IP: {line}")
            continue
            
        # Защита ВАШИХ адресов
        is_whitelisted = False
        for w_net in whitelist_nets:
            if net.overlaps(w_net):
                # Молча увеличиваем счетчик, не печатая сам IP в консоль!
                whitelisted_count += 1
                is_whitelisted = True
                break
                
        if is_whitelisted:
            continue

        raw_ips.append(net)
    except ValueError:
        print(f"Invalid IP format skipped: {line}")

# Агрегируем сети и удаляем дубли
optimized_ips = list(ipaddress.collapse_addresses(raw_ips))

# Перезаписываем файл
with open(filename, 'w') as f:
    for ip in optimized_ips:
        f.write(f"{ip}\n")

print(f"Optimization complete. Optimized entries: {len(optimized_ips)}.")
if whitelisted_count > 0:
    print(f"Silently removed {whitelisted_count} entries overlapping with private whitelist.")
