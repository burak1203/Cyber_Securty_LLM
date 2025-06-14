# -*- coding: utf-8 -*-
from src.capture import start_capture
from src.analyzer import analyze_packets
from src.detector import detect_threats
from src.llm_interpreter import explain_threat
from src.utils import log_time, write_to_log, group_threats

def main():
    try:
        # Log dosyasını temizle ve başlangıç mesajını yaz
        with open("network_analysis.log", "w", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n[{log_time()}] Analiz başlatıldı\n{'='*80}\n")
        
        write_to_log(f"\n[{log_time()}] 📡 Trafik toplanıyor...")
        packets = start_capture()

        write_to_log(f"\n[{log_time()}] 📊 Paketler analiz ediliyor...")
        results = analyze_packets(packets)

        write_to_log(f"\n[{log_time()}] 🔍 Tehditler tespit ediliyor...")
        threats = detect_threats(results)

        if not threats:
            write_to_log(f"\n[{log_time()}] ✅ Her şey yolunda! Şüpheli bir aktivite tespit edilmedi.")
            return

        write_to_log(f"\n[{log_time()}] 🤖 LLM ile açıklamalar hazırlanıyor...\n")
        
        # Tehditleri gruplandır
        grouped_threats = group_threats(threats)
        
        # Her tehdit türü için tüm tehditleri birleştir
        all_threats_text = ""
        for threat_type, threat_list in grouped_threats.items():
            all_threats_text += f"\n🔺 {threat_type} Tehditleri:\n"
            all_threats_text += "-" * 50 + "\n"
            for threat in threat_list:
                all_threats_text += f"📌 {threat}\n"
        
        # Öncelikli tehdit türleri
        priority_threats = ["DDoS", "Keylogger", "Şüpheli Port", "Trafik Analizi", "Diğer Tehditler"]
        
        # Her tehdit türü için tek bir analiz yap
        for threat_type in priority_threats:
            if threat_type in grouped_threats:
                threat_list = grouped_threats[threat_type]
                write_to_log(f"\n🔺 {threat_type} Tehditleri:")
                write_to_log("-" * 50)
                
                # Her tehdit türü için tüm örnekleri listele
                for threat in threat_list:
                    write_to_log(f"📌 {threat}")
                
                # Her tehdit türü için tek bir analiz yap
                if threat_list:
                    try:
                        example_threat = threat_list[0]
                        # Tüm tehditleri ve paket istatistiklerini LLM'e gönder
                        explanation = explain_threat(example_threat, all_threats_text)
                        write_to_log(f"\n📢 Analiz:\n{explanation}")
                    except Exception as e:
                        write_to_log(f"\n⚠️ LLM analizi yapılamadı: {str(e)}")
                        write_to_log("Analiz atlanıyor ve devam ediliyor...")
                    write_to_log("-" * 50)

        write_to_log(f"\n[{log_time()}] Analiz tamamlandı.\n{'='*80}")

    except Exception as e:
        import traceback
        error_msg = f"\n[{log_time()}] ❌ Hata oluştu:\n{str(e)}\n{traceback.format_exc()}"
        write_to_log(error_msg)
        print(error_msg)  # Hata mesajını hem log'a hem terminale yaz

def run_full_analysis(stop_flag=None):
    try:
        with open("network_analysis.log", "w", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n[{log_time()}] Analiz başlatıldı\n{'='*80}\n")
        with open("llm_analysis.log", "w", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n[{log_time()}] LLM Analiz Logu\n{'='*80}\n")
        write_to_log(f"\n[{log_time()}] \U0001F4E1 Trafik toplanıyor...")
        packets = start_capture(stop_flag=stop_flag)
        write_to_log(f"\n[{log_time()}] \U0001F4CA Paketler analiz ediliyor...")
        results = analyze_packets(packets)
        write_to_log(f"\n[{log_time()}] \U0001F50D Tehditler tespit ediliyor...")
        threats = detect_threats(results)
        if not threats:
            write_to_log(f"\n[{log_time()}] \u2705 Her şey yolunda! Şüpheli bir aktivite tespit edilmedi.")
            return "Her şey yolunda! Şüpheli bir aktivite tespit edilmedi."
        write_to_log(f"\n[{log_time()}] \U0001F916 LLM ile açıklamalar hazırlanıyor...\n")
        grouped_threats = group_threats(threats)
        all_threats_text = ""
        for threat_type, threat_list in grouped_threats.items():
            all_threats_text += f"\n\U0001F6A8 {threat_type} Tehditleri:\n"
            all_threats_text += "-" * 50 + "\n"
            for threat in threat_list:
                all_threats_text += f"\U0001F4CC {threat}\n"
        priority_threats = ["DDoS", "Keylogger", "Şüpheli Port", "Trafik Analizi", "Diğer Tehditler"]
        result_text = ""
        for threat_type in priority_threats:
            if threat_type in grouped_threats:
                threat_list = grouped_threats[threat_type]
                write_to_log(f"\n\U0001F6A8 {threat_type} Tehditleri:")
                write_to_log("-" * 50)
                for threat in threat_list:
                    write_to_log(f"\U0001F4CC {threat}")
                if threat_list:
                    try:
                        example_threat = threat_list[0]
                        explanation = explain_threat(example_threat, all_threats_text)
                        # LLM analizini ayrı dosyaya yaz
                        write_to_log(f"\n\U0001F4E2 Analiz:\n{explanation}", filename="llm_analysis.log")
                        result_text += f"\n[{threat_type}]\n{explanation}\n"
                    except Exception as e:
                        write_to_log(f"\n\u26A0\uFE0F LLM analizi yapılamadı: {str(e)}", filename="llm_analysis.log")
                        write_to_log("Analiz atlanıyor ve devam ediliyor...", filename="llm_analysis.log")
                write_to_log("-" * 50)
        write_to_log(f"\n[{log_time()}] Analiz tamamlandı.\n{'='*80}")
        return result_text if result_text else "Tehditler tespit edildi, ancak analiz sonucu yok."
    except Exception as e:
        import traceback
        error_msg = f"\n[{log_time()}] \u274C Hata oluştu:\n{str(e)}\n{traceback.format_exc()}"
        write_to_log(error_msg)
        write_to_log(error_msg, filename="llm_analysis.log")
        return error_msg

if __name__ == "__main__":
    main()