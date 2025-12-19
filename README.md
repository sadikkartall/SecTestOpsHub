# SecTestOpsHub

**Unified Docker-Based Orchestration Platform for Multi-Tool Security Testing**

SecTestOpsHub, bilgi güvenliği tarama araçlarını tek bir Docker tabanlı platformda birleştirmek için tasarlanmış araştırma odaklı bir projedir. Web tabanlı bir panel üzerinden taramaları başlatmak, çıktıları tutarlı biçimde arşivlemek ve akademik/kurumsal raporlara dönüştürülebilir bir veri üretim hattı sunmayı hedefler.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-compose-blue.svg)](https://www.docker.com/)

## 📋 Özellikler

- ✅ **10 Entegre Güvenlik Aracı**: Ping, Whois, Nmap, Nikto, Gobuster, OWASP ZAP, testssl.sh, dnsrecon, theHarvester, Amass
- ✅ **Tek Panelden Yönetim**: Web tabanlı arayüz ile tüm araçları tek yerden kontrol
- ✅ **Standart Çıktı Formatları**: JSON, XML, TXT, HTML formatlarında tutarlı çıktılar
- ✅ **Docker Tabanlı**: Tekrarlanabilir ve taşınabilir altyapı
- ✅ **RESTful API**: Programatik erişim ve otomasyon desteği
- ✅ **Modüler Mimari**: Kolay genişletilebilir servis yapısı
- ✅ **Akademik Odaklı**: IEEE makalesi ve araştırma için uygun şeffaf mimari

## 🏗️ Mimari

```
┌─────────────┐
│   Frontend  │  Web Interface (Nginx, Port: 8080)
│  HTML/JS    │
└──────┬──────┘
       │ REST API
┌──────▼──────┐
│   Backend   │  FastAPI (Python 3.12, Port: 8000)
│  FastAPI    │
└──────┬──────┘
       │
  ┌────┴────┐
  │         │
┌─▼──┐   ┌──▼──┐
│ZAP │   │Tools│  Security Tools (10 tools)
│Cntr│   │Backend│
└─┬──┘   └──┬──┘
  │         │
  └────┬────┘
       │
┌──────▼──────┐
│ Data Volume │  ./data:/app/data
│  (Shared)   │
└─────────────┘
```

## 🛠️ Entegre Güvenlik Araçları

| Araç | Versiyon | Amaç | Çıktı Formatı |
|------|----------|------|---------------|
| **Ping** | System | Hedef erişilebilirlik ve IP çözümleme | TXT |
| **Whois** | System | Domain kayıt bilgileri | TXT |
| **Nmap** | System | Ağ taraması, servis tespiti, OS detection | XML, TXT |
| **Nikto** | 2.5.0 | Web sunucu güvenlik taraması | JSON, TXT |
| **Gobuster** | 3.6.0 | Directory enumeration | JSON, TXT |
| **OWASP ZAP** | Stable | Web uygulama güvenlik testi | HTML |
| **testssl.sh** | Latest | SSL/TLS konfigürasyon testi | JSON, TXT |
| **dnsrecon** | Latest | DNS enumeration | JSON, TXT |
| **theHarvester** | Latest | OSINT bilgi toplama | JSON, TXT |
| **Amass** | 5.0.1 | Subdomain enumeration | JSON, TXT |

## 🚀 Hızlı Başlangıç

### Gereksinimler

- Docker & Docker Compose
- 4GB+ RAM (önerilen)
- Linux/macOS/Windows (Docker Desktop)

### Kurulum

1. **Projeyi klonlayın:**
```bash
git clone https://github.com/sadikkartall/SecTestOpsHub.git
cd SecTestOpsHub
```

2. **Ortam değişkeni dosyasını oluşturun (opsiyonel):**
```bash
cp env.example .env
```

3. **Servisleri başlatın:**
```bash
docker compose up --build
```

4. **Servislerin hazır olmasını bekleyin (30-60 saniye)**

5. **Tarayıcıda açın:**
- **Web Paneli**: http://localhost:8080
- **API Dokümantasyonu**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### Kullanım

1. Web panelinde hedef URL'yi girin (örn: `example.com` veya `https://example.com`)
2. İstediğiniz araçları seçin (varsayılan: tümü seçili)
3. "Planı Oluştur" butonuna tıklayın
4. Tarama sonuçları ekranda görüntülenecek ve `data/` dizinine kaydedilecek

## 📁 Dizin Yapısı

```
SecTestOpsHub/
├── backend/                 # FastAPI tabanlı API
│   ├── src/
│   │   ├── main.py         # Uygulama girişi
│   │   ├── routers/        # API endpoint'leri
│   │   ├── models/         # Pydantic veri modelleri
│   │   └── services/      # Araç entegrasyonları
│   ├── requirements.txt    # Python bağımlılıkları
│   └── Dockerfile          # Backend container imajı
├── frontend/               # Statik web paneli
│   ├── web/                # HTML, CSS, JavaScript
│   └── Dockerfile          # Frontend container imajı (Nginx)
├── data/                   # Çıktı dosyaları (paylaşılan volume)
├── docker-compose.yml      # Servis orkestrasyonu
├── env.example             # Ortam değişkeni şablonu
└── README.md               # Bu dosya
```

## 🔧 Teknik Detaylar

### Backend

- **Framework**: FastAPI 0.115.0
- **Python**: 3.12
- **Veri Modelleri**: Pydantic 2.9.2
- **API Dokümantasyonu**: Otomatik Swagger/OpenAPI
- **Özellikler**: 
  - RESTful API tasarımı
  - Tip güvenliği (Pydantic)
  - CORS desteği
  - Hata yönetimi ve timeout kontrolü

### Frontend

- **Teknoloji**: Vanilla HTML/CSS/JavaScript
- **Sunucu**: Nginx
- **Özellikler**:
  - Araç seçimi (checkbox)
  - Gerçek zamanlı sonuç görüntüleme
  - JSON çıktılarını okunabilir formatta gösterim

### Containerization

- **Backend Container**: Python 3.12-slim base image
  - NET_RAW, NET_ADMIN capabilities (Nmap için)
  - Docker socket mount (ZAP kontrolü için)
  - Paylaşılan volume mount
- **Frontend Container**: Nginx
- **ZAP Container**: Ayrı container, docker exec ile kontrol

## 📊 Veri Yönetimi

- **Çıktı Dizini**: `./data/` (host ve container arasında paylaşılan)
- **Dosya İsimlendirme**: `<tool>-<uuid>.<ext>` formatında
- **Desteklenen Formatlar**: JSON, XML, TXT, HTML
- **Veri Standardizasyonu**: Her araç için tutarlı çıktı formatları

## 🔌 API Kullanımı

### Tarama Başlatma

```bash
curl -X POST "http://localhost:8000/scans/" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "example.com",
    "tools": ["nmap", "nikto", "gobuster"]
  }'
```

### Health Check

```bash
curl http://localhost:8000/health
```

Detaylı API dokümantasyonu için: http://localhost:8000/docs

## 🧪 Geliştirme

### Yerel Geliştirme

```bash
# Backend'i yerel olarak çalıştırma
cd backend
pip install -r requirements.txt
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Frontend'i yerel olarak çalıştırma
cd frontend/web
python -m http.server 8080
```

### Yeni Araç Ekleme

1. `backend/src/services/` dizinine yeni modül ekleyin
2. Standart fonksiyon imzası: `run_<tool>(target, output_dir, ...) -> <Tool>Result`
3. `backend/src/models/scan.py` içine sonuç modeli ekleyin
4. `backend/src/routers/scans.py` içine entegrasyon ekleyin

## 🎯 Hedefler ve Kapsam

- ✅ Çoklu güvenlik aracını tek panelden yönetilebilir kılma
- ✅ Tekrarlanabilir deneysel altyapı (Docker)
- ✅ Çıktıların standardizasyonu
- ✅ Akademik kullanım için şeffaf mimari
- 🔄 Asenkron tarama desteği (planlanan)
- 🔄 Raporlama modülü (planlanan)
- 🔄 Kimlik doğrulama (planlanan)

## 📚 Dokümantasyon

- **API Dokümantasyonu**: http://localhost:8000/docs (Swagger UI)
- **Kod Yorumları**: Türkçe yorumlarla desteklenmiştir
- **Mimari Detaylar**: Kod içinde açıklamalar mevcuttur

## ⚠️ Güvenlik ve Etik

- ⚠️ **Bu araç sadece yasal ve izinli güvenlik testleri için kullanılmalıdır**
- ⚠️ Sahip olmadığınız sistemleri taramayın
- ⚠️ Tüm testler kontrollü ortamlarda yapılmalıdır
- ⚠️ Yazarlar, kötüye kullanımdan sorumlu değildir

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen:

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'feat: Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

### Geliştirme İlkeleri

- **Modülerlik**: Her araç kendi servis modülünde ele alınır
- **Şeffaflık**: Tüm kod Türkçe yorumlarla desteklenir
- **Genişletilebilirlik**: Yeni araç ekleme kolay ve standartlaştırılmıştır
- **Güvenlik**: Docker soketi erişimi ve kaynak sınırları dikkate alınır

## 📄 Lisans

Bu proje akademik/kurumsal değerlendirme içindir. Lisans seçimi ve atıf formatı makale gereksinimlerine göre güncellenecektir.

## 📧 İletişim

- **GitHub**: [sadikkartall/SecTestOpsHub](https://github.com/sadikkartall/SecTestOpsHub)
- **Issues**: Sorular ve bug raporları için GitHub Issues kullanın

## 👥 Ekip

Proje, IEEE bildirisi kapsamında geliştirilmektedir.

---

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!**
