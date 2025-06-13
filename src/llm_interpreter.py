import os
import re
import requests
from huggingface_hub import InferenceClient
from bs4 import BeautifulSoup

HUGGINGFACE_API_TOKEN = os.getenv("HUGGINGFACE_API_TOKEN")
if not HUGGINGFACE_API_TOKEN:
    raise ValueError("HUGGINGFACE_API_TOKEN environment variable is not set!")

client = InferenceClient(token=HUGGINGFACE_API_TOKEN)

def get_ip_info(ip):
    """IP adresi hakkında bilgi alır (ipinfo.io üzerinden)."""
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json")
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ip": ip,
                "isp": data.get("org", ""),
                "org": data.get("org", ""),
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "as": data.get("asn", {}).get("asn", "") if "asn" in data else ""
            }
        return None
    except Exception as e:
        return None

def is_trusted_isp(isp):
    trusted_isps = [
        "Turk Telekomunikasyon", "Turk Telekom", "TTNet", "Superonline", "TurkNet", "Google", "Microsoft", "Amazon", "Cloudflare", "Akamai", "DigitalOcean", "OVH", "Hetzner", "Linode", "Vultr", "GoDaddy", "Namecheap", "Hostinger", "Bluehost", "HostGator"
    ]
    if not isp:
        return False
    return any(trusted in isp for trusted in trusted_isps)

def extract_ip_from_threat(threat):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, threat)
    if match:
        return match.group(0)
    return None

def analyze_ip_with_llm(ip, ip_info):
    if not ip_info:
        return "IP bilgisi alınamadı."
    try:
        prompt = f"""Aşağıdaki IP adresini analiz et ve güvenilir olup olmadığını değerlendir:\n\nIP: {ip}\nISP: {ip_info['isp']}\nOrganizasyon: {ip_info['org']}\nÜlke: {ip_info['country']}\nŞehir: {ip_info['city']}\nAS: {ip_info['as']}\n\nÖNEMLİ KURALLAR:\n1. Aşağıdaki şirketlerin herhangi bir alt şirketi veya bölümü güvenilirdir:\n   - Microsoft (Microsoft Limited, Microsoft Corporation, Microsoft Azure, vb.)\n   - Google (Google LLC, Google Cloud, Google Fiber, vb.)\n   - Amazon (Amazon.com, AWS, Amazon Web Services, vb.)\n   - Cloudflare (Cloudflare Inc., Cloudflare Ltd, vb.)\n   - Turk Telekom (Turk Telekomunikasyon, TTNet, vb.)\n   - Superonline (Superonline Iletisim, vb.)\n   - TurkNet (TurkNet Iletisim, vb.)\n2. ISP ve Organizasyon bilgilerini dikkatli analiz et:\n   - 'Microsoft Limited' -> Güvenilir (Microsoft'un alt şirketi)\n   - 'Microsoft Azure' -> Güvenilir (Microsoft'un bulut servisi)\n   - 'Google Cloud' -> Güvenilir (Google'ın bulut servisi)\n   - 'AWS' -> Güvenilir (Amazon'un bulut servisi)\n   - 'Cloudflare' -> Güvenilir (CDN ve güvenlik şirketi)\n3. AS (Autonomous System) numarası da önemli:\n   - Microsoft AS: 8075, 3598, 5761, vb.\n   - Google AS: 15169, 19527, vb.\n   - Amazon AS: 16509, 14618, vb.\n   - Cloudflare AS: 13335, vb.\n4. Özellikle dikkat edilmesi gerekenler:\n   - Şirket isimlerinin farklı yazılışları (örn: 'Microsoft Limited' = 'Microsoft Corp' = güvenilir)\n   - Alt şirketler ve bölümler (örn: 'Microsoft Azure' = güvenilir)\n   - Bulut servisleri (örn: 'AWS' = güvenilir)\n   - CDN ve güvenlik şirketleri (örn: 'Cloudflare' = güvenilir)\n5. DDoS ve Saldırı Tespiti:\n   - Eğer IP bilinmeyen bir kaynaktan geliyorsa ve yoğun trafik varsa -> YÜKSEK TEHDİT\n   - Eğer IP yerel ağdan geliyorsa ve yoğun trafik varsa -> YÜKSEK TEHDİT\n   - Eğer IP bilinmeyen bir ülkeden geliyorsa -> YÜKSEK TEHDİT\n   - Eğer IP bilinmeyen bir ISP'den geliyorsa -> YÜKSEK TEHDİT\n\nLütfen şu başlıkları içeren bir analiz yap:\n1. IP'nin kaynağı ve sağlayıcısı hakkında bilgi\n2. Güvenlik açısından değerlendirme\n3. Öneriler\n\nEğer IP yukarıdaki kurallara göre güvenilir bir kaynaktan geliyorsa, sadece 'Güvenilir IP' yaz.\nAksi takdirde detaylı analiz yap ve neden güvenilir olmadığını açıkla."""
        
        # API bağlantısını yeniden dene
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = client.text_generation(
                    model="mistralai/Mistral-7B-Instruct-v0.3",
                    prompt=prompt,
                    max_new_tokens=200,
                    temperature=0.7,
                    top_p=0.9,
                )
                return response
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"[DEBUG] API bağlantı hatası, yeniden deneniyor... ({attempt + 1}/{max_retries})")
                    continue
                else:
                    print(f"[DEBUG] API bağlantı hatası: {str(e)}")
                    return "API bağlantı hatası nedeniyle analiz yapılamadı. Lütfen internet bağlantınızı kontrol edin."
    except Exception as e:
        print(f"[DEBUG] Beklenmeyen hata: {str(e)}")
        return "Beklenmeyen bir hata oluştu. Lütfen daha sonra tekrar deneyin."

def explain_threat(threat, all_threats_text=""):
    """Tehdidi analiz eder ve açıklar."""
    ip = extract_ip_from_threat(threat)
    if not ip:
        return "Tehdit mesajında IP adresi bulunamadı."
    ip_info = get_ip_info(ip)
    if not ip_info:
        return "IP bilgisi alınamadı."
    analysis = analyze_ip_with_llm(ip, ip_info)
    if "Güvenilir IP" in analysis:
        return "Bu IP güvenilir olarak değerlendirildi."
    # Tehdit mesajını ve tüm tehditleri analiz et
    return f"{analysis}\n\nEkstra bilgi:\n{all_threats_text}"