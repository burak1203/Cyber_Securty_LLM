from src.utils import summarize_packet, is_suspicious_port, is_normal_traffic, write_to_log
import re
import json
import base64
import ipaddress
from collections import defaultdict

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def is_keylogger_behavior(pkt, packet_stats):
    try:
        # Hem content hem content_ascii alanını kontrol et
        content = str(pkt.get("content", "")) if isinstance(pkt, dict) else str(getattr(pkt, "content", ""))
        content_ascii = pkt.get("content_ascii", "") if isinstance(pkt, dict) and "content_ascii" in pkt else getattr(pkt, "content_ascii", "") if hasattr(pkt, "content_ascii") else ""
        src = pkt.get("src", "") if isinstance(pkt, dict) else getattr(pkt, "src", "")
        
        # Debug bilgisi
        print(f"[DEBUG] Keylogger analizi - Kaynak: {src}")
        print(f"[DEBUG] İçerik: {content[:200]}...")
        print(f"[DEBUG] ASCII: {content_ascii[:200]}...")
        
        # 1) HTTP header'larında Host: localhost:8000 ve User-Agent: python-requests varsa keylogger olarak işaretle
        if ("Host: localhost:8000" in content or "Host: localhost:8000" in content_ascii) and ("User-Agent: python-requests" in content or "User-Agent: python-requests" in content_ascii):
            print("[DEBUG] Host: localhost:8000 ve User-Agent: python-requests tespit edildi! (Keylogger)")
            return True, "Host: localhost:8000 ve User-Agent: python-requests tespit edildi (Keylogger)"
        
        for check_content in [content, content_ascii]:
            if not check_content:
                continue
                
            # HTTP POST isteği kontrolü
            if "POST" in check_content and "application/json" in check_content:
                print("[DEBUG] HTTP POST isteği tespit edildi")
                try:
                    # JSON verisini bul
                    json_start = check_content.find('{')
                    json_end = check_content.rfind('}') + 1
                    if json_start != -1 and json_end != -1:
                        json_str = check_content[json_start:json_end]
                        print(f"[DEBUG] JSON verisi: {json_str[:200]}...")
                        json_data = json.loads(json_str)
                        
                        if 'data' in json_data:
                            print("[DEBUG] Base64 verisi tespit edildi")
                            try:
                                decoded = base64.b64decode(json_data['data']).decode(errors='ignore')
                                print(f"[DEBUG] Çözülmüş veri: {decoded[:200]}...")
                                inner_data = json.loads(decoded)
                                
                                if 'data' in inner_data and 'timestamp' in inner_data:
                                    if isinstance(inner_data['data'], list):
                                        for item in inner_data['data']:
                                            if 'k' in item and 't' in item:
                                                if len(str(item['k'])) == 1 and isinstance(item['t'], (int, float)):
                                                    print("[DEBUG] Keylogger veri yapısı tespit edildi!")
                                                    return True, "Keylogger veri yapısı tespit edildi (JSON+base64)"
                            except Exception as e:
                                print(f"[DEBUG] Base64/JSON çözme hatası: {str(e)}")
                except Exception as e:
                    print(f"[DEBUG] JSON çözme hatası: {str(e)}")
            
            # Yerel ağ için özel kontroller
            if src == "127.0.0.1" or src == "localhost":
                # Küçük ve sık gelen POST istekleri
                if len(check_content) < 100:
                    small_packet_count = packet_stats['small_packets_per_src'].get(src, 0)
                    if small_packet_count > 5:  # Eşik değerini düşürdük
                        print(f"[DEBUG] Yerel ağda küçük paket tespit edildi: {small_packet_count}")
                        return True, "Yerel ağda düzenli küçük paketler tespit edildi"
                
                # Base64 içeriği kontrolü
                if re.fullmatch(r'[A-Za-z0-9+/=]{20,}', check_content):
                    print("[DEBUG] Base64 içeriği tespit edildi")
                    try:
                        decoded = base64.b64decode(check_content).decode(errors='ignore')
                        if decoded.startswith('{') and decoded.endswith('}'):
                            json_data = json.loads(decoded)
                            if 'data' in json_data and 'timestamp' in json_data:
                                print("[DEBUG] Keylogger veri yapısı tespit edildi!")
                                return True, "Keylogger veri yapısı tespit edildi (base64)"
                    except Exception as e:
                        print(f"[DEBUG] Base64/JSON çözme hatası: {str(e)}")
        
        return False, ""
    except Exception as e:
        print(f"[DEBUG] Keylogger analizi sırasında hata: {str(e)}")
        return False, ""

def detect_threats(packets, stop_flag=None):
    threats = set()
    packet_stats = {
        'total_packets': len(packets),
        'protocols': {},
        'sources': {},
        'destinations': {},
        'large_packets': 0,
        'small_packets': 0,
        'small_packets_per_src': defaultdict(int)
    }
    ALLOWED_PROTOCOLS = [
        "TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "TLS", "SSL", "ARP", "DHCP",
        "SSDP", "MDNS", "NTP", "SNMP", "SMTP", "POP3", "IMAP", "FTP", "SSH",
        "TELNET", "RDP", "SMB", "NBNS", "LLMNR", "DATA", "JSON", "QUIC"
    ]
    DDOS_THRESHOLDS = {
        'packets_per_second': 1000,
        'packets_per_source': 500,
        'total_packets': 1000,
        'large_packets': 500
    }
    for pkt in packets:
        if stop_flag is not None and stop_flag():
            print("⏹️ Tehdit analizi kullanıcı tarafından durduruldu.")
            break
        try:
            protocol = pkt.get("protocol", "") if isinstance(pkt, dict) else getattr(pkt, "protocol", "")
            src = pkt.get("src", "") if isinstance(pkt, dict) else getattr(pkt, "src", "")
            dst = pkt.get("dst", "") if isinstance(pkt, dict) else getattr(pkt, "dst", "")
            length = int(pkt.get("length", 0)) if isinstance(pkt, dict) else int(getattr(pkt, "length", 0))
            # DATA-TEXT-LINES protokolüyle ilgili hiçbir işlem yapılmasın
            if protocol == "DATA-TEXT-LINES":
                continue
            packet_stats['protocols'][protocol] = packet_stats['protocols'].get(protocol, 0) + 1
            packet_stats['sources'][src] = packet_stats['sources'].get(src, 0) + 1
            packet_stats['destinations'][dst] = packet_stats['destinations'].get(dst, 0) + 1
            if length > 1000:
                packet_stats['large_packets'] += 1
            elif length < 100:
                packet_stats['small_packets'] += 1
                packet_stats['small_packets_per_src'][src] += 1
            is_keylogger, reason = is_keylogger_behavior(pkt, packet_stats)
            if is_keylogger:
                msg = f"Keylogger aktivitesi tespit edildi ({reason}) - {summarize_packet(pkt)}"
                threats.add(msg)
                write_to_log(f"[Keylogger Tespiti] {msg}")
            if protocol in ["UDP", "DATA"]:
                if packet_stats['sources'].get(src, 0) > DDOS_THRESHOLDS['packets_per_source']:
                    msg = f"DDoS benzeri UDP/DATA trafiği tespit edildi - {src} adresinden {packet_stats['sources'][src]} paket"
                    threats.add(msg)
                    write_to_log(f"[DDoS Tespiti] {msg}")
            elif protocol == "TCP":
                if "SYN" in str(pkt) and packet_stats['sources'].get(src, 0) > DDOS_THRESHOLDS['packets_per_source']:
                    msg = f"DDoS benzeri TCP SYN trafiği tespit edildi - {src} adresinden {packet_stats['sources'][src]} paket"
                    threats.add(msg)
                    write_to_log(f"[DDoS Tespiti] {msg}")
            is_suspicious, port_info = is_suspicious_port(pkt)
            if is_suspicious:
                msg = f"Şüpheli port kullanımı ({port_info}) - {summarize_packet(pkt)}"
                threats.add(msg)
                write_to_log(f"[Port Tespiti] {msg}")
        except Exception as e:
            error_msg = f"[DEBUG] Paket analizi sırasında hata: {str(e)}"
            print(error_msg)
            write_to_log(error_msg)
    if packet_stats['total_packets'] > DDOS_THRESHOLDS['total_packets']:
        msg = f"Yüksek trafik hacmi tespit edildi - Toplam {packet_stats['total_packets']} paket"
        threats.add(msg)
        write_to_log(f"[DDoS Tespiti] {msg}")
    for src, count in packet_stats['sources'].items():
        if count > DDOS_THRESHOLDS['packets_per_source']:
            msg = f"Tek kaynaktan yoğun trafik - {src} adresinden {count} paket"
            threats.add(msg)
            write_to_log(f"[DDoS Tespiti] {msg}")
    debug_stats = f"""
[DEBUG] Paket İstatistikleri:
Toplam Paket: {packet_stats['total_packets']}
Protokoller: {packet_stats['protocols']}
Büyük Paketler: {packet_stats['large_packets']}
Küçük Paketler: {packet_stats['small_packets']}
Kaynak IP'ler: {packet_stats['sources']}
"""
    print(debug_stats)
    write_to_log(debug_stats)
    return list(threats)
