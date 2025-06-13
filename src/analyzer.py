from src.utils import write_to_log
import binascii

def analyze_packets(packets):
    print(f"📦 {len(packets)} paket yakalandı.")
    analysis = []
    for i, pkt in enumerate(packets):
        try:
            # IP ve protokol bilgisi
            src = getattr(pkt.ip, 'src', '127.0.0.1') if hasattr(pkt, 'ip') else '127.0.0.1'
            dst = getattr(pkt.ip, 'dst', '127.0.0.1') if hasattr(pkt, 'ip') else '127.0.0.1'
            protocol = pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'Unknown'
            length = int(getattr(pkt, 'length', 0)) if hasattr(pkt, 'length') else 0
            packet_data = {
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "length": length
            }

            # HTTP içeriği
            content = ''
            if hasattr(pkt, 'http'):
                packet_data["method"] = getattr(pkt.http, 'request_method', '')
                packet_data["host"] = getattr(pkt.http, 'host', '')
                packet_data["uri"] = getattr(pkt.http, 'request_uri', '')
                for attr in ['file_data', 'request', 'payload', 'data', 'json_value', 'response_for_uri', 'response_line', 'response_code', 'response_phrase']:
                    if hasattr(pkt.http, attr):
                        val = getattr(pkt.http, attr)
                        if val:
                            content += str(val)
            # TCP içeriği
            elif hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
                content = getattr(pkt.tcp, 'payload', '')
            # Loopback içeriği
            elif hasattr(pkt, 'loopback') and hasattr(pkt.loopback, 'payload'):
                content = getattr(pkt.loopback, 'payload', '')
            # Raw data
            elif hasattr(pkt, 'data'):
                content = getattr(pkt, 'data', '')
            packet_data["content"] = content

            # HEX içeriği ASCII'ye çevir
            if isinstance(content, str) and all(c in '0123456789abcdefABCDEF: ' for c in content.replace(':', '')) and len(content.replace(':', '')) > 20:
                try:
                    hex_str = content.replace(':', '').replace(' ', '')
                    ascii_str = binascii.unhexlify(hex_str).decode(errors='ignore')
                    packet_data['content_ascii'] = ascii_str
                except Exception:
                    pass

            # Debug ve log
            print(f"[DEBUG] Paket {i}:")
            print(f"  Kaynak: {packet_data['src']}")
            print(f"  Hedef: {packet_data['dst']}")
            print(f"  Protokol: {packet_data['protocol']}")
            if 'content' in packet_data:
                print(f"  İçerik: {str(packet_data['content'])[:200]}...")
                write_to_log(f"[DEBUG] Paket {i} İçerik: {str(packet_data['content'])[:200]}...")
            if 'content_ascii' in packet_data:
                print(f"  İçerik (ascii): {packet_data['content_ascii'][:200]}...")
                write_to_log(f"[DEBUG] Paket {i} İçerik (ascii): {packet_data['content_ascii'][:200]}...")
            analysis.append(packet_data)
            if i % 10 == 0:
                print(f"🔄 {i}. paket işlendi...")
        except Exception as e:
            print(f"⚠️ Hata: {e}")
            write_to_log(f"[ERROR] Paket {i} analiz edilirken hata: {e}")
            continue
    return analysis
