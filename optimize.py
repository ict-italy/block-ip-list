import ipaddress
import sys

filename = 'blocklist.txt'

try:
    with open(filename, 'r') as f:
        lines = f.read().splitlines()
except FileNotFoundError:
    print(f"File {filename} not found.")
    sys.exit(1)

raw_ips = []
invalid_lines = 0

for line in lines:
    line = line.strip()
    # Пропускаем пустые строки и комментарии
    if not line or line.startswith('#'):
        continue
    
    try:
        # Парсим IP или подсеть (strict=False позволяет парсить '192.168.1.1/24' без ошибок хостовой части)
        net = ipaddress.ip_network(line, strict=False)
        
        # Защита от блокировки локалок и критичных сетей
        if net.is_private or net.is_loopback or net.is_multicast or net == ipaddress.ip_network('0.0.0.0/0'):
            print(f"Skipped restricted/private IP: {line}")
            continue
            
        raw_ips.append(net)
    except ValueError:
        print(f"Invalid IP format skipped: {line}")
        invalid_lines += 1

# Магия: удаляет дубли, поглощает мелкие сети в крупные, агрегирует соседние IP в подсети и сортирует
optimized_ips = list(ipaddress.collapse_addresses(raw_ips))

# Перезаписываем файл
with open(filename, 'w') as f:
    for ip in optimized_ips:
        f.write(f"{ip}\n")

print(f"Optimization complete. Original valid entries: {len(raw_ips)}. Optimized entries: {len(optimized_ips)}.")
