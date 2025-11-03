# SecTestOps Hub

**Entegre Güvenlik Test Otomasyonu ve AI Destekli Analiz Platformu**

## 📋 Proje Özeti

SecTestOps Hub, farklı güvenlik test araçlarını tek bir web platformunda toplayarak, otomatik zafiyet taraması, sonuç analizi ve yapay zekâ destekli raporlama işlemlerini merkezi bir şekilde gerçekleştirir.

### Temel Özellikler

- ✅ Tek panelden çoklu araç taraması (8 güvenlik aracı)
- ✅ AI destekli bulgu analizi ve öneri sistemi
- ✅ Normalize edilmiş raporlama (PDF, Markdown, JSON)
- ✅ CVSS skorlama ve OWASP Top 10 eşlemesi
- ✅ Etkileşimli dashboard ve real-time tarama takibi
- ✅ Playbook support - Önceden tanımlanmış tarama senaryoları
- ✅ STUB_MODE - Test için örnek veriler
- ✅ GitHub Actions CI/CD pipeline

## 🏗️ Mimari

```
┌─────────────┐
│   React     │  Frontend (Port 3000)
│  Dashboard  │
└──────┬──────┘
       │
┌──────▼──────┐
│   FastAPI   │  Backend API (Port 8000)
│   Backend   │
└──────┬──────┘
       │
┌──────▼──────┐     ┌─────────────┐
│   Celery    │────▶│   Redis     │
│   Worker    │     │   Queue     │
└──────┬──────┘     └─────────────┘
       │
      ├───▶ Nmap (Network Scan)
      ├───▶ OWASP ZAP (Web App Scan)
      ├───▶ Trivy (SCA / Container Scan)
      ├───▶ Nikto, Amass, ffuf
      └───▶ WhatWeb, testssl.sh
```

## 🚀 Hızlı Başlangıç

### Gereksinimler

- Docker & Docker Compose
- 4GB+ RAM

### 3 Adımda Başlat

```bash
# 1. Proje dizinine git
cd SecTestOps_Hub

# 2. Docker Compose ile başlat (tüm servisleri otomatik başlatır)
docker-compose up -d

# İlk çalıştırma için build gerekir (5-10 dakika sürebilir)
# docker-compose up -d --build

# 3. Servislerin hazır olmasını bekle (30-60 saniye)
# Ardından tarayıcıda aç
http://localhost:3000
```

**API Dokümantasyonu:** http://localhost:8000/docs  
**Health Check:** http://localhost:8000/health

> 💡 **Notlar:**
> - İlk çalıştırma 5-10 dakika sürebilir (Docker image'ları indiriliyor ve build ediliyor)
> - Frontend, API hazır olana kadar bekler (healthcheck ile)
> - Tüm servisler (PostgreSQL, Redis, API, Worker, Frontend) otomatik başlatılır
> - Veritabanı tabloları otomatik oluşturulur
> - Gerçek taramalar için: `STUB_MODE=false docker-compose up -d`
> - Test için: `STUB_MODE=true docker-compose up -d` (varsayılan: false)

Detaylı komutlar ve sorun giderme için → [RUN_COMMANDS.md](RUN_COMMANDS.md)

## 🛠️ Kullanılan Teknolojiler

### Backend
- FastAPI - Modern, hızlı web framework
- PostgreSQL - İlişkisel veritabanı
- Celery - Asenkron iş kuyruğu
- Redis - Message broker
- SQLAlchemy - ORM

### Frontend
- React 18
- Material-UI / Tailwind CSS
- Axios - API client
- Chart.js - Grafikler

### Güvenlik Araçları
- **Nmap** - Ağ keşfi ve port taraması
- **OWASP ZAP** - Web uygulama güvenlik testi  
- **Trivy** - Container ve dependency güvenlik analizi
- **Nikto** - Web sunucu güvenlik taraması
- **Amass** - Subdomain keşfi ve haritalama
- **ffuf** - Web fuzzing ve endpoint keşfi
- **WhatWeb** - Web teknolojisi parmak izi tespiti
- **testssl.sh** - TLS/SSL güvenlik analizi

### AI/LLM
- OpenAI API (GPT-3.5/4) veya HuggingFace modelleri
- Bulgu özetleme ve öneri sistemi

## 📊 Veri Modeli

```
Targets
├── id (UUID)
├── url (String)
├── description (String)
└── created_at (Timestamp)

Scans
├── id (UUID)
├── target_id (FK)
├── tools (Array)
├── status (Enum: pending, running, completed, failed)
├── started_at (Timestamp)
└── finished_at (Timestamp)

Findings
├── id (UUID)
├── scan_id (FK)
├── tool (String)
├── title (String)
├── severity (Enum: critical, high, medium, low, info)
├── cvss_score (Float)
├── owasp_category (String)
├── endpoint (String)
├── description (Text)
├── recommendation (Text)
├── ai_summary (Text)
└── probable_fp (Boolean)
```

## 🔒 Güvenlik ve Etik

- Tüm testler **izinli** ve **kontrollü** ortamlarda yapılmalıdır
- Varsayılan tarama modu: **non-intrusive**
- Hassas veri maskeleme aktiftir
- OWASP ve etik hacking standartlarına uygundur

## 📝 IEEE Makale İçin Test Metrikleri

- **False Positive Oranı**: AI-assisted vs Manual
- **Triage Süresi**: Ortalama analiz süresi karşılaştırması
- **Coverage**: OWASP Top 10 kapsama oranı
- **Kullanıcı Memnuniyeti**: Test grubu değerlendirmesi

## 📄 Lisans

MIT License - Akademik araştırma ve eğitim amaçlı kullanım.

[Lisans detayları için LICENSE dosyasına bakın](LICENSE)

## 📚 Dokümantasyon

Proje dokümantasyon dosyaları:

- **[RUN_COMMANDS.md](RUN_COMMANDS.md)** - Detaylı çalıştırma komutları ve sorun giderme
- **[TOOLS_GUIDE.md](TOOLS_GUIDE.md)** - 8 güvenlik aracı hakkında detaylı bilgi
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Sistem mimarisi ve teknik detaylar
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Katkıda bulunma rehberi

## 🎓 IEEE Makale İçin

Bu proje IEEE bildirisi kapsamında geliştirilmiştir. Test metrikleri toplama, deneysel veriler ve akademik katkılar için detaylı dokümantasyona bakın.

**Toplanacak Metrikler:**
- False Positive Oranı (AI-assisted vs Manual)
- Triage Süresi (Analiz süresi karşılaştırması)
- OWASP Top 10 Coverage (Kapsama oranı)
- Kullanıcı Memnuniyeti (SUS Score, Test grubu)

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen [CONTRIBUTING.md](CONTRIBUTING.md) dosyasını okuyun.

```bash
# Fork & Clone
git clone https://github.com/YOUR_USERNAME/SecTestOps_Hub.git

# Branch oluştur
git checkout -b feature/amazing-feature

# Değişiklikleri commit et
git commit -m "feat: Add amazing feature"

# Push ve Pull Request aç
git push origin feature/amazing-feature
```

## 📧 İletişim

- GitHub Issues: Sorular ve bug raporları için
- Email: [iletişim bilgisi eklenecek]

## 👥 Ekip

Proje, IEEE bildirisi kapsamında geliştirilmektedir.

---

**⚠️ Yasal Uyarı**: Bu araç sadece yasal ve izinli güvenlik testleri için kullanılmalıdır. Yazarlar, kötüye kulanımdan sorumlu değildir. Sahip olmadığınız sistemleri taramayın!

