# utils.py
from datetime import datetime
import json
import ipaddress

# Güvenilir IP aralıkları ve şirketler
TRUSTED_NETWORKS = {
    "Google": [
        "8.8.8.0/24", "8.8.4.0/24", "142.250.0.0/16", "172.217.0.0/16", "216.58.0.0/16", "173.194.0.0/16", "74.125.0.0/16", "64.233.0.0/16", "66.102.0.0/16", "72.14.0.0/16", "209.85.0.0/16", "66.249.0.0/16", "64.18.0.0/16", "207.126.0.0/16", "173.255.0.0/16", "108.177.0.0/16", "172.253.0.0/16", "142.250.0.0/16", "216.239.0.0/16",
    ],
    "Microsoft": [
        "13.64.0.0/11", "20.0.0.0/8", "40.0.0.0/8", "52.0.0.0/8",
    ],
    "Amazon": [
        "52.0.0.0/8", "54.0.0.0/8",
    ],
    "Cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22",
    ]
}

def filter_by_ip(packets, ip_address):
    return [pkt for pkt in packets if pkt.get("src") == ip_address or pkt.get("dst") == ip_address]

def convert_to_json(data):
    return json.dumps(data, indent=4, ensure_ascii=False)

def log_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def summarize_packet(packet):
    port_info = f":{packet['dst_port']}" if 'dst_port' in packet else ""
    protocol_info = f" | {packet['protocol']}"
    if 'method' in packet and packet['method']:
        protocol_info += f" {packet['method']}"
    return f"[{log_time()}] {packet['src']} → {packet['dst']}{port_info}{protocol_info} | {packet['length']} bytes"

def is_suspicious_port(packet, threshold_ports=None):
    default_ports = {
        21: "FTP - Dosya transferi", 22: "SSH - Uzaktan erişim", 23: "Telnet - Uzaktan erişim", 25: "SMTP - E-posta", 3389: "RDP - Uzak masaüstü", 445: "SMB - Dosya paylaşımı", 1433: "MSSQL - Veritabanı", 3306: "MySQL - Veritabanı", 5432: "PostgreSQL - Veritabanı", 27017: "MongoDB - Veritabanı"
    }
    threshold_ports = threshold_ports or default_ports
    dst_port = packet.get("dst_port")
    src_port = packet.get("src_port")
    if dst_port in threshold_ports:
        return True, threshold_ports[dst_port]
    elif src_port in threshold_ports:
        return True, threshold_ports[src_port]
    return False, None

def save_to_file(data, filename="output.json"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(convert_to_json(data))

def write_to_log(message, filename="network_analysis.log"):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"{message}\n")

def group_threats(threats):
    grouped = {}
    for threat in threats:
        if "DDoS" in threat:
            grouped.setdefault("DDoS", []).append(threat)
        elif "Keylogger" in threat:
            grouped.setdefault("Keylogger", []).append(threat)
        elif "port" in threat.lower():
            grouped.setdefault("Şüpheli Port", []).append(threat)
        elif "protokol" in threat.lower():
            grouped.setdefault("Diğer Tehditler", []).append(threat)
        else:
            grouped.setdefault("Trafik Analizi", []).append(threat)
    return grouped

def is_trusted_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for company, ranges in TRUSTED_NETWORKS.items():
            for net in ranges:
                if ip_obj in ipaddress.ip_network(net):
                    return True, company
        return False, None
    except ValueError:
        return False, None

def is_normal_traffic(packet, stats):
    NORMAL_THRESHOLDS = {
        'packets_per_ip': 500, 'large_packets': 100, 'small_packets': 200, 'total_packets': 5000
    }
    is_trusted, company = is_trusted_ip(packet.get("src", ""))
    if is_trusted:
        return True
    is_trusted, company = is_trusted_ip(packet.get("dst", ""))
    if is_trusted:
        return True
    src = packet.get("src", "")
    if stats['sources'].get(src, 0) > NORMAL_THRESHOLDS['packets_per_ip']:
        return False
    if stats['large_packets'] > NORMAL_THRESHOLDS['large_packets']:
        return False
    if stats['small_packets'] > NORMAL_THRESHOLDS['small_packets']:
        return False
    if stats['total_packets'] > NORMAL_THRESHOLDS['total_packets']:
        return False
    return True
