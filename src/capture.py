# src/capture.py
import pyshark
import signal
import sys
import threading
import asyncio

def signal_handler(sig, frame):
    print("\n✅ Trafik yakalama durduruldu.")
    sys.exit(0)

def start_capture(interface="Wi-Fi 2", duration=None, stop_flag=None): # Adapter for loopback traffic capture
    # Thread'de asyncio event loop yoksa oluştur
    if threading.current_thread() is not threading.main_thread():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    print(f"📡 {interface} arayüzünden veri toplanıyor...")
    print("⚠️ Durdurmak için Ctrl+C tuşlarına basın.")
    
    # Sadece ana thread'de signal handler ekle
    if threading.current_thread() is threading.main_thread():
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
            if stop_flag is not None and stop_flag():
                print("⏹️ Yakalama kullanıcı tarafından durduruldu.")
                break
            packets.append(pkt)

    except KeyboardInterrupt:
        print("\n✅ Trafik yakalama durduruldu.")
    except Exception as e:
        print(f"❌ Hata oluştu: {str(e)}")
    finally:
        print(f"✅ {len(packets)} paket yakalandı.")
        return packets
