# Ağ Trafiği Analiz ve Tehdit Tespit Sistemi

Bu uygulama, ağ trafiğini gerçek zamanlı olarak izleyen, analiz eden ve potansiyel güvenlik tehditlerini tespit eden bir araçtır. LLM (Large Language Model) entegrasyonu sayesinde, tespit edilen tehditler hakkında detaylı açıklamalar ve öneriler sunar.

## Özellikler

- 🔍 Gerçek zamanlı ağ trafiği izleme
- 🛡️ Otomatik tehdit tespiti
- 🤖 LLM destekli tehdit analizi
- 📊 Detaylı log kayıtları
- 🚨 DDoS, Keylogger ve şüpheli port kullanımı tespiti
- 🌐 IP adresi analizi ve güvenilirlik kontrolü

## Gereksinimler

- Python 3.8 veya üzeri (3.11.0 önerilir)
- Wireshark
- Npcap (Windows için)
- HuggingFace API Token

## Kurulum

1. Gerekli Python paketlerini yükleyin:
```bash
pip install -r requirements.txt
```

2. Wireshark ve Npcap'ı yükleyin:
   - Windows: https://www.wireshark.org/download.html
   - Linux: `sudo apt-get install wireshark`

3. HuggingFace API Token'ınızı ayarlayın:
```bash
export HUGGINGFACE_API_TOKEN="your_token_here"  # Linux/Mac
set HUGGINGFACE_API_TOKEN=your_token_here       # Windows
```

## Kullanım

### 1. Ağ Arayüzünü Seçme

Uygulamayı kullanmadan önce, izlemek istediğiniz ağ arayüzünü belirlemeniz gerekir. Windows'ta ağ arayüzlerini görmek için:

```bash
netsh interface show interface
```

Linux'ta:
```bash
ip link show
```

### 2. Uygulamayı Çalıştırma

```bash
python main.py
```

Varsayılan olarak uygulama "Wi-Fi 2" arayüzünü kullanır. Farklı bir arayüz kullanmak için `src/capture.py` dosyasındaki `interface` parametresini değiştirin.

### 3. Trafik Yakalama

- Uygulama başladığında trafik yakalamaya başlar
- İstediğiniz zaman Ctrl+C tuşlarına basarak yakalamayı durdurabilirsiniz
- Yakalama durduğunda, toplanan veriler otomatik olarak analiz edilir

### 4. Sonuçları İnceleme

Analiz sonuçları `network_analysis.log` dosyasında saklanır. Bu dosyada:

- Yakalanan paketlerin özeti
- Tespit edilen tehditler
- LLM tarafından yapılan analizler
- Öneriler ve uyarılar

bulunur.

## Tespit Edilen Tehdit Türleri

1. **DDoS Saldırıları**
   - Yüksek trafik hacmi
   - Tek kaynaktan yoğun paket gönderimi
   - UDP/TCP SYN flood

2. **Keylogger Aktivitesi**
   - Şüpheli veri yapıları
   - Düzenli küçük paketler
   - Base64 kodlu veriler

3. **Şüpheli Port Kullanımı**
   - Bilinen tehlikeli portlar
   - Beklenmeyen port kullanımları

4. **Trafik Analizi**
   - Anormal protokol kullanımı
   - Şüpheli IP adresleri
   - Güvenilir olmayan kaynaklar

## Güvenlik Uyarıları

- Bu uygulamayı sadece izin verilen ağlarda kullanın
- Başkalarının ağ trafiğini izlemeden önce gerekli izinleri alın
- Hassas verileri içeren log dosyalarını güvenli bir şekilde saklayın

## Hata Giderme

1. **"No such interface" hatası**
   - Doğru ağ arayüzünü seçtiğinizden emin olun
   - Wireshark'ın yüklü olduğunu kontrol edin

2. **"Permission denied" hatası**
   - Windows: Yönetici olarak çalıştırın
   - Linux: `sudo` ile çalıştırın veya Wireshark kullanıcı grubuna ekleyin

3. **LLM analizi çalışmıyor**
   - HuggingFace API Token'ınızın doğru ayarlandığından emin olun
   - İnternet bağlantınızı kontrol edin

## Katkıda Bulunma

1. Bu depoyu fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/tehdit-tespiti-gelistirmesi`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik: Açıklama'`)
4. Branch'inizi push edin (`git push origin feature/tehdit-tespiti-gelistirmesi`)
5. Pull Request oluşturun

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın. 