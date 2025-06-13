# src/capture.py
import pyshark
import signal
import sys

def signal_handler(sig, frame):
    print("\n✅ Trafik yakalama durduruldu.")
    sys.exit(0)

def start_capture(interface="Wi-Fi 2", duration=None): # Adapter for loopback traffic capture
    print(f"📡 {interface} arayüzünden veri toplanıyor...")
    print("⚠️ Durdurmak için Ctrl+C tuşlarına basın.")
    
    # Ctrl+C sinyalini yakala
    signal.signal(signal.SIGINT, signal_handler)
    
    capture = pyshark.LiveCapture(interface=interface)
    packets = []

    try:
        # Süre belirtilmişse o kadar bekle, belirtilmemişse sürekli yakala
        if duration:
            capture.sniff(timeout=duration)
        else:
            capture.sniff_continuously()

        for pkt in capture.sniff_continuously(packet_count=len(capture)):
            packets.append(pkt)

    except KeyboardInterrupt:
        print("\n✅ Trafik yakalama durduruldu.")
    except Exception as e:
        print(f"❌ Hata oluştu: {str(e)}")
    finally:
        print(f"✅ {len(packets)} paket yakalandı.")
        return packets
