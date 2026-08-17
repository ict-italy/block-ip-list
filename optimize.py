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
        # Добавляем фиктивный User-Agent, чтобы GitHub не отбивал запрос
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
                    print(f"Warning: Invalid whitelist IP format in Gist: {w_line}")
        print("Whitelist loaded securely from Gist.")
    except urllib.error.URLError as e:
        print(f"Error downloading whitelist from Gist: {e}")
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

for line in lines:
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    
    try:
        net = ipaddress.ip_network(line, strict=False)
        
        # Защита от блокировки локалок
        if net.is_private or net.is_loopback or net.is_multicast or net == ipaddress.ip_network('0.0.0.0/0'):
            print(f"Skipped restricted/private IP: {line}")
            continue
            
        # Защита ВАШИХ адресов
        is_whitelisted = False
        for w_net in whitelist_nets:
            if net.overlaps(w_net):
                # Логируем только факт пропуска, не светя сам адрес из белого списка
                print(f"Skipped {line} -> Overlaps with private whitelist!")
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
