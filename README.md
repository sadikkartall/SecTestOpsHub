# SecTestOpsHub

**Unified Docker-Based Orchestration Platform for Multi-Tool Security Testing**

SecTestOpsHub, bilgi güvenliği tarama araçlarını tek bir Docker tabanlı platformda birleştirmek için tasarlanmış araştırma odaklı bir projedir. Web tabanlı bir panel üzerinden taramaları başlatmak, çıktıları tutarlı biçimde arşivlemek ve akademik/kurumsal raporlara dönüştürülebilir bir veri üretim hattı sunmayı hedefler.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-compose-blue.svg)](https://www.docker.com/)

## 📋 İçindekiler

- [Özellikler](#-özellikler)
- [Sistem Mimarisi](#-sistem-mimarisi)
- [Entegre Güvenlik Araçları](#-entegre-güvenlik-araçları)
- [Klasör Yapısı](#-klasör-yapısı)
- [Hızlı Başlangıç](#-hızlı-başlangıç)
- [API Kullanımı](#-api-kullanımı)
- [Geliştirme](#-geliştirme)
- [Güvenlik ve Etik](#-güvenlik-ve-etik)

## ✨ Özellikler

- ✅ **10 Entegre Güvenlik Aracı**: Ping, Whois, Nmap, Nikto, Gobuster, OWASP ZAP, testssl.sh, dnsrecon, theHarvester, Subfinder
- ✅ **AI Destekli Güvenlik Analizi**: Gemini AI ile otomatik güvenlik analizi ve öneriler
- ✅ **Tek Panelden Yönetim**: Web tabanlı arayüz ile tüm araçları tek yerden kontrol
- ✅ **Standart Çıktı Formatları**: JSON, XML, TXT, HTML formatlarında tutarlı çıktılar
- ✅ **Normalizasyon Sistemi**: Tüm araç çıktıları standart `NormalizedResult` formatına dönüştürülür
- ✅ **Türkçe Çıktılar**: ZAP sonuçları ve AI analizleri Türkçe olarak sunulur
- ✅ **Docker Tabanlı**: Tekrarlanabilir ve taşınabilir altyapı
- ✅ **RESTful API**: Programatik erişim ve otomasyon desteği
- ✅ **Modüler Mimari**: Kolay genişletilebilir servis yapısı
- ✅ **Akademik Odaklı**: IEEE makalesi ve araştırma için uygun şeffaf mimari

## 🏗️ Sistem Mimarisi

### Genel Mimari

```
┌─────────────────────────────────────────────────────────────┐
│                        Kullanıcı                            │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        │ HTTP İsteği
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Frontend Container (Nginx)                                 │
│  - Port: 8080                                               │
│  - Statik HTML/CSS/JavaScript                               │
│  - Volume: ./frontend/web:/usr/share/nginx/html            │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        │ REST API (POST /scans/)
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Backend Container (FastAPI)                                │
│  - Port: 8000                                               │
│  - Python 3.12                                              │
│  - Capabilities: NET_RAW, NET_ADMIN                        │
│  - Docker Socket Mount: /var/run/docker.sock               │
│  - Volume: ./data:/app/data                                 │
└───────┬─────────────────────────────────────────────────────┘
        │
        ├─────────────────┬─────────────────┬──────────────┐
        │                 │                 │              │
        ▼                 ▼                 ▼              ▼
┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────┐
│   Ping      │  │   Whois     │  │   Nmap      │  │  Nikto   │
│   Service   │  │   Service   │  │   Service   │  │  Service │
└─────────────┘  └──────────────┘  └─────────────┘  └──────────┘
        │                 │                 │              │
        ▼                 ▼                 ▼              ▼
┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────┐
│  Gobuster   │  │     ZAP     │  │  testssl.sh │  │ dnsrecon│
│   Service   │  │  Container  │  │   Service   │  │ Service │
└─────────────┘  └──────────────┘  └─────────────┘  └──────────┘
        │                 │                 │              │
        ▼                 ▼                 ▼              ▼
┌─────────────┐  ┌──────────────┐
│theHarvester │  │  Subfinder  │
│   Service   │  │   Service   │
└─────────────┘  └──────────────┘
        │                 │
        └─────────┬───────┘
                  │
                  ▼
        ┌──────────────────┐
        │  Normalizasyon    │
        │  Sistemi         │
        │  (normalized.py) │
        └──────────────────┘
                  │
                  ▼
        ┌──────────────────┐
        │  Paylaşılan      │
        │  Veri Volume      │
        │  ./data:/app/data │
        └──────────────────┘
```

### Mimari Bileşenleri

#### 1. Frontend Katmanı
- **Teknoloji**: Vanilla HTML/CSS/JavaScript
- **Sunucu**: Nginx
- **Port**: 8080
- **Özellikler**:
  - Araç seçimi (checkbox)
  - Gerçek zamanlı sonuç görüntüleme
  - Normalize edilmiş JSON çıktılarını okunabilir formatta gösterim
  - Ham çıktı ve normalize edilmiş JSON'u `<details>` tag'leri ile gizlenebilir şekilde gösterme

#### 2. Backend Katmanı
- **Framework**: FastAPI 0.115.0
- **Python**: 3.12
- **Port**: 8000
- **Veri Modelleri**: Pydantic 2.9.2
- **Özellikler**:
  - RESTful API tasarımı
  - Tip güvenliği (Pydantic)
  - CORS desteği
  - Hata yönetimi ve timeout kontrolü
  - Otomatik Swagger/OpenAPI dokümantasyonu

#### 3. Servis Katmanı
Her güvenlik aracı için ayrı servis modülü:
- `ping.py`: Ping servisi
- `whois.py`: Whois servisi
- `nmap.py`: Nmap servisi
- `nikto.py`: Nikto servisi
- `gobuster.py`: Gobuster servisi
- `zap.py`: ZAP servisi (docker exec ile kontrol)
- `testssl.py`: testssl.sh servisi
- `dnsrecon.py`: dnsrecon servisi
- `theharvester.py`: theHarvester servisi
- `subfinder.py`: Subfinder servisi

#### 4. Normalizasyon Sistemi
Tüm araç çıktıları standart `NormalizedResult` formatına dönüştürülür. Bu sistem sayesinde:
- **Tutarlı Veri Yapısı**: Tüm araçlar aynı formatta sonuç döner
- **Frontend Entegrasyonu**: Tek bir görüntüleme mantığı ile tüm araçlar gösterilir
- **Genişletilebilirlik**: Yeni araçlar kolayca eklenebilir
- **Akademik Raporlama**: Standart format ile rapor üretimi kolaylaşır

**Schema**: `backend/src/models/normalized.py`

#### 5. AI Destekli Güvenlik Analizi
Gemini AI entegrasyonu ile otomatik güvenlik analizi yapılır:
- **Otomatik Analiz**: Tüm tarama sonuçları otomatik olarak analiz edilir
- **Risk Seviyesi Değerlendirmesi**: Her araç için risk seviyesi belirlenir (critical, high, medium, low, safe)
- **Detaylı Öneriler**: Her bulgu için pratik çözüm önerileri sunulur
- **Tool Bazlı Analiz**: Her araç için özel analiz ve özet
- **Genel Güvenlik Raporu**: Tüm araçların birleşik analizi ve korelasyonları
- **Kısa ve Profesyonel**: Öz ve net analiz formatı

**Servis**: `backend/src/services/analyze_results.py`

**Gereksinimler**:
- Gemini API Key (`.env` dosyasında `GEMINI_API_KEY` olarak tanımlanmalı)
- API Key almak için: https://makersuite.google.com/app/apikey

**NormalizedResult Yapısı**:
```python
{
  "tool": "nmap",                    # Araç adı
  "target": "example.com",            # Hedef (domain, IP veya URL)
  "timestamp": "2025-12-17T...",     # İşlem zamanı (ISO format)
  "status": "success|partial|failed", # İşlem durumu
  "summary": "Özet bilgi",           # İnsan okunabilir özet
  "findings": [                       # Bulgular listesi
    {
      "type": "vulnerability",       # Bulgu türü
      "severity": "HIGH",             # Önem seviyesi (INFO, LOW, MEDIUM, HIGH, CRITICAL)
      "title": "Bulgu başlığı",       # Bulgu başlığı
      "evidence": {...}               # Detaylı kanıtlar
    }
  ],
  "metrics": {                        # Araç özelinde metrikler
    "ports": [...],
    "subdomains": [...],
    "total_subdomains": 10,
    ...
  },
  "raw": {                            # Ham çıktı bilgileri
    "stdout": "...",                  # Standart çıktı
    "stderr": "...",                  # Hata çıktısı
    "exit_code": 0,                   # Çıkış kodu
    "command": "..."                  # Çalıştırılan komut
  }
}
```

**Finding Yapısı**:
```python
{
  "type": "vulnerability|subdomain_discovery|security_alert|...",
  "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
  "title": "Bulgu başlığı",
  "evidence": {
    # Araç özelinde detaylı bilgiler
    # Örn: port, service, cve_id, subdomain, source, vb.
  }
}
```

**Normalizasyon Fonksiyonları**:
Her araç için `normalize_<tool>()` fonksiyonu mevcuttur:
- `normalize_ping()`: Ping sonuçlarını normalize eder
- `normalize_whois()`: Whois sonuçlarını normalize eder
- `normalize_nmap()`: Nmap XML/çıktısını normalize eder
- `normalize_nikto()`: Nikto JSON çıktısını normalize eder
- `normalize_gobuster()`: Gobuster çıktısını normalize eder
- `normalize_zap()`: ZAP HTML raporunu normalize eder
- `normalize_testssl()`: testssl.sh JSON çıktısını normalize eder
- `normalize_dnsrecon()`: dnsrecon JSON çıktısını normalize eder
- `normalize_theharvester()`: theHarvester JSON çıktısını normalize eder
- `normalize_subfinder()`: Subfinder JSONL çıktısını normalize eder

**Normalizasyon Akışı**:
1. Araç çalıştırılır ve ham çıktı alınır
2. Ham çıktı dosyaya kaydedilir (JSON, XML, TXT formatında)
3. `normalize_<tool>()` fonksiyonu çağrılır
4. Ham çıktı parse edilir ve `NormalizedResult` oluşturulur
5. Normalize edilmiş JSON dosyaya kaydedilir (`<tool>-<uuid>-normalized.json`)
6. Frontend normalize edilmiş JSON'u kullanarak sonuçları gösterir

#### 6. Container Yapısı
- **Backend Container**: Python 3.12-slim base image
  - NET_RAW, NET_ADMIN capabilities (Nmap için)
  - Docker socket mount (ZAP kontrolü için)
  - Paylaşılan volume mount (`./data:/app/data`)
- **Frontend Container**: Nginx
  - Volume mount: `./frontend/web:/usr/share/nginx/html` (live updates için)
- **ZAP Container**: Ayrı container, docker exec ile kontrol
  - Image: `ghcr.io/zaproxy/zaproxy:stable`
  - Volume mount: `./data:/zap/wrk`

## 🛠️ Entegre Güvenlik Araçları

### Hedef Format Özeti

| Araç | IP Adresi | Domain/Hostname | URL | Notlar |
|------|-----------|-----------------|-----|--------|
| **Ping** | ✅ | ✅ | ✅ (hostname çıkarılır) | IP veya hostname kabul eder |
| **Whois** | ✅ | ✅ | ✅ (hostname çıkarılır) | IP için ARIN/RIPE sorgusu |
| **Nmap** | ✅ | ✅ | ✅ (hostname çıkarılır) | IP veya hostname kabul eder |
| **Nikto** | ❌ | ✅ | ✅ (hostname çıkarılır) | Hostname gerekli |
| **Gobuster** | ❌ | ❌ | ✅ | Tam URL gerekli |
| **OWASP ZAP** | ❌ | ❌ | ✅ | Tam URL gerekli |
| **testssl.sh** | ✅ | ✅ | ✅ (hostname:port çıkarılır) | IP kullanılabilir ama sertifika sorunlu |
| **dnsrecon** | ❌ | ✅ | ✅ (domain çıkarılır) | Domain gerekli |
| **theHarvester** | ❌ | ✅ | ✅ (domain çıkarılır) | Domain gerekli |
| **Subfinder** | ❌ | ✅ | ✅ (domain çıkarılır) | Domain gerekli |

**Not**: URL formatında hedef verildiğinde, sistem otomatik olarak uygun formatı çıkarır (hostname, domain, port, vb.).

---

### 1. Ping

**Amaç**: Hedef host/IP'nin erişilebilirliğini test etmek ve IP çözümlemesi yapmak.

**Hedef Format**: 
- ✅ **IP Adresi**: `192.168.1.1`
- ✅ **Hostname/Domain**: `example.com`
- ✅ **URL'den otomatik çıkarılır**: URL verilirse hostname çıkarılır

**Kullanım Senaryosu**: 
- Hedef sistemin çevrimiçi olup olmadığını kontrol etmek
- DNS çözümlemesi yapmak
- Ağ bağlantısını test etmek

**Parametreler**:
- `-c 4`: 4 paket gönder (varsayılan)

**Çıktı Formatı**: TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- Hedef IP adresi
- Paket istatistikleri (gönderilen, alınan, kayıp)
- RTT metrikleri (min, avg, max, mdev)
- Erişilebilirlik durumu

---

### 2. Whois

**Amaç**: Domain kayıt bilgilerini sorgulamak.

**Hedef Format**: 
- ✅ **Domain**: `example.com`
- ✅ **IP Adresi**: `192.168.1.1` (ARIN/RIPE sorgusu)
- ✅ **URL'den otomatik çıkarılır**: URL verilirse hostname çıkarılır

**Kullanım Senaryosu**:
- Domain sahibi bilgilerini öğrenmek
- Kayıt tarihlerini kontrol etmek
- Registrar bilgilerini almak
- IP adresi için ARIN/RIPE sorgusu yapmak

**Parametreler**:
- Hedef domain veya IP adresi (otomatik algılanır)

**Çıktı Formatı**: TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- Domain/IP bilgisi
- Registrar bilgisi
- Kayıt tarihleri (oluşturma, güncelleme, son kullanma)
- Nameserver'lar
- İletişim bilgileri (registrant, admin, tech)
- IP aralığı (IP sorgusu için)

**Timeout**: 20 saniye

---

### 3. Nmap

**Amaç**: Ağ taraması, port tespiti, servis versiyonu tespiti, OS tespiti.

**Hedef Format**: 
- ✅ **IP Adresi**: `192.168.1.1`
- ✅ **Hostname/Domain**: `example.com`
- ✅ **URL'den otomatik çıkarılır**: URL verilirse hostname çıkarılır

**Kullanım Senaryosu**:
- Açık portları tespit etmek
- Çalışan servisleri ve versiyonlarını öğrenmek
- İşletim sistemi tespiti yapmak
- Güvenlik açıklarını taramak

**Parametreler**:
- `-Pn`: Ping taraması yapma (host discovery atla)
- `-sS`: SYN scan (stealth scan)
- `-sV`: Servis versiyonu tespiti
- `-sC`: Varsayılan script'leri çalıştır
- `-O`: İşletim sistemi tespiti
- `-T4`: Agresif zamanlama (hızlı tarama)
- `--top-ports 1000`: En yaygın 1000 portu tara
- `-oX`: XML çıktı dosyası
- `-oN`: Normal (text) çıktı dosyası

**Çıktı Formatı**: XML, TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- Host durumu (up/down)
- Açık portlar ve servisler
- Servis versiyonları
- İşletim sistemi bilgisi (CPE, accuracy, osclass)
- Tarama süresi
- Uyarılar

**Timeout**: 5 dakika (300 saniye)

**Not**: NET_RAW ve NET_ADMIN capabilities gereklidir (docker-compose.yml'de tanımlı).

---

### 4. Nikto

**Amaç**: Web sunucu güvenlik taraması.

**Hedef Format**: 
- ✅ **Hostname/Domain**: `example.com` (URL'den otomatik çıkarılır)
- ❌ **IP Adresi**: Doğrudan desteklenmez (hostname gerekli)
- ✅ **URL**: `https://example.com` (hostname ve port çıkarılır)

**Kullanım Senaryosu**:
- Web sunucu yapılandırma hatalarını tespit etmek
- Güvenlik açıklarını bulmak
- Eski yazılım versiyonlarını tespit etmek
- Potansiyel güvenlik risklerini belirlemek

**Parametreler**:
- `-h`: Hedef host
- `-p`: Port numarası
- `-output`: Çıktı dosyası
- `-Format json`: JSON formatında çıktı
- `-ask no`: Etkileşimli soruları devre dışı bırak
- `-Display V`: Verbose (ayrıntılı) çıktı
- `-useragent`: Özel user agent
- `-timeout 10`: İstek timeout'u (saniye)
- `-ssl`: SSL/TLS kullan (HTTPS için)
- `-root`: Kök path (varsa)

**Çıktı Formatı**: JSON, TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- Hedef bilgileri (host, port, SSL)
- Sunucu bilgisi
- Toplam bulgu sayısı
- Bulgular severity'ye göre kategorize edilmiş (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Bulguların detaylı açıklamaları

**Timeout**: 15 dakika (900 saniye)

---

### 5. Gobuster

**Amaç**: Web dizin ve dosya enumeration (brute force).

**Hedef Format**: 
- ✅ **URL**: `https://example.com` veya `http://example.com:8080/path`
- ✅ **Tam URL gerekli**: Şema, host, port ve path bilgisi kullanılır
- ❌ **IP Adresi**: Doğrudan desteklenmez (URL formatında olmalı)

**Kullanım Senaryosu**:
- Gizli dizinleri bulmak
- Yedek dosyaları tespit etmek
- API endpoint'lerini keşfetmek
- Yönetim panellerini bulmak

**Parametreler**:
- `dir`: Directory enumeration modu
- `-u`: Hedef URL
- `-w`: Wordlist dosyası (varsayılan: `/usr/share/seclists/Discovery/Web-Content/common.txt`)
- `-t 20`: Thread sayısı (varsayılan: 20)
- `-k`: SSL sertifika doğrulamasını atla
- `--timeout 10s`: İstek timeout'u
- `-b ""`: Blacklist'i devre dışı bırak
- `-s "200,204,301,302,307,401,403"`: İlginç status kodları
- `-x "php,html,txt,js,bak"`: Uzantı listesi
- `-o`: Çıktı dosyası

**Varsayılan Ayarlar**:
- Wordlist: `common.txt` (fallback: `directory-list-2.3-medium.txt`)
- Threads: 20
- Timeout: 10 saniye
- Status codes: 200,204,301,302,307,401,403
- Extensions: php, html, txt, js, bak

**Çıktı Formatı**: TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- Hedef URL
- Tarama parametreleri (method, threads, wordlist, extensions, status codes)
- Bulgular (path, status, size, redirect)
- Bulgular status koduna göre gruplandırılmış
- Toplam bulgu sayısı
- Status dağılımı

**Timeout**: 15 dakika (900 saniye)

---

### 6. OWASP ZAP

**Amaç**: Web uygulama güvenlik testi (otomatik vulnerability scanning).

**Hedef Format**: 
- ✅ **URL**: `https://example.com` veya `http://example.com:8080`
- ✅ **Tam URL gerekli**: Şema, host ve port bilgisi kullanılır
- ❌ **IP Adresi**: Doğrudan desteklenmez (URL formatında olmalı)

**Kullanım Senaryosu**:
- Web uygulama güvenlik açıklarını tespit etmek
- OWASP Top 10 risklerini taramak
- XSS, SQL injection gibi yaygın açıkları bulmak
- Güvenlik başlıklarını kontrol etmek

**Parametreler**:
- `zap.sh`: ZAP script
- `-cmd`: Komut satırı modu (GUI yok)
- `-quickurl`: Hızlı tarama için hedef URL
- `-quickout`: HTML rapor çıktı dosyası

**Çıktı Formatı**: HTML, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- ZAP versiyonu ve tarama tarihi
- Risk özeti (High, Medium, Low, Informational, False Positives)
- Alert listesi (isim, risk seviyesi, instance sayısı)
- Her alert için detaylar:
  - Description (açıklama)
  - Etkilenen URL'ler
  - Solution (çözüm önerileri)
  - CWE ID, WASC ID, Plugin ID
  - Reference linkler

**Timeout**: 15 dakika (900 saniye)

**Not**: ZAP ayrı bir container'da çalışır, backend `docker exec` ile kontrol eder.

---

### 7. testssl.sh

**Amaç**: SSL/TLS konfigürasyon testi.

**Hedef Format**: 
- ✅ **Hostname/Domain**: `example.com` (URL'den otomatik çıkarılır)
- ✅ **IP Adresi**: `192.168.1.1` (desteklenir ancak sertifika doğrulaması sorunlu olabilir)
- ✅ **Format**: `hostname:port` veya `IP:port`

**Kullanım Senaryosu**:
- SSL/TLS sertifika bilgilerini kontrol etmek
- Protokol desteğini test etmek (TLS 1.0, 1.1, 1.2, 1.3)
- Cipher suite'leri değerlendirmek
- Güvenlik açıklarını tespit etmek (Heartbleed, POODLE, vb.)
- HTTP security header'larını kontrol etmek

**Parametreler**:
- `--jsonfile`: JSON çıktı dosyası
- `--quiet`: Sadece önemli çıktıları göster
- `--warnings off`: Etkileşimli uyarıları devre dışı bırak
- `--socket-timeout 10`: TCP socket bağlantı timeout'u (saniye)
- `--openssl-timeout 10`: OpenSSL bağlantı timeout'u (saniye)

**Özel Davranış**:
- Port 80 ise otomatik olarak 443'e geçer (SSL/TLS testi için)

**Çıktı Formatı**: JSON, TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- Protokol desteği (TLS 1.0, 1.1, 1.2, 1.3)
- Cipher kategorileri (strong, weak, null, anonymous)
- Güvenlik açıkları (Heartbleed, POODLE, vb.)
- Sertifika bilgileri
- HTTP security header'ları
- Rating score ve grade

**Timeout**: 10 dakika (600 saniye)

---

### 8. dnsrecon

**Amaç**: DNS enumeration ve kayıt tespiti.

**Hedef Format**: 
- ✅ **Domain**: `example.com` (URL'den otomatik çıkarılır)
- ❌ **IP Adresi**: Desteklenmez (domain gerekli)

**Kullanım Senaryosu**:
- DNS kayıtlarını toplamak (A, AAAA, MX, NS, TXT, SOA)
- Subdomain'leri keşfetmek
- DNS sunucu bilgilerini öğrenmek
- SPF, DMARC kayıtlarını kontrol etmek
- DNSSEC durumunu kontrol etmek

**Parametreler**:
- `-d`: Hedef domain
- `-j`: JSON çıktı dosyası
- `-t std`: Standart DNS kayıtları (A, AAAA, MX, NS, TXT, SOA)
- `--lifetime 120`: DNS sorgu timeout'u (saniye)

**Çıktı Formatı**: JSON, TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- DNSSEC durumu (configured/not configured)
- DNS kayıt türleri ve sayıları
- Name server'lar
- Mail server'lar (MX)
- Address kayıtları (A, AAAA)
- TXT kayıtları (SPF, DMARC, verification records)

**Timeout**: 10 dakika (600 saniye)

**Not**: Bazı domain'lerde çalışmayabilir (DNS kayıtları eksik, sunucu yanıt vermiyor, rate limiting).

---

### 9. theHarvester

**Amaç**: OSINT (Open Source Intelligence) bilgi toplama.

**Hedef Format**: 
- ✅ **Domain**: `example.com` (URL'den otomatik çıkarılır)
- ❌ **IP Adresi**: Desteklenmez (domain gerekli)

**Kullanım Senaryosu**:
- E-posta adreslerini toplamak
- Host ve subdomain'leri keşfetmek
- IP adreslerini bulmak
- Sosyal medya ve forum'lardan bilgi toplamak

**Parametreler**:
- `-d`: Hedef domain
- `-b all`: Tüm kaynakları kullan (google, bing, shodan, vb.)
- `-f`: JSON çıktı dosyası

**Kaynaklar**:
- Google, Bing, Yahoo
- Shodan, Censys
- GitHub, Twitter
- LinkedIn, Facebook
- Ve daha fazlası...

**Çıktı Formatı**: JSON, TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- Hedef domain
- Kaynak istatistikleri:
  - Başarılı kaynaklar
  - Başarısız kaynaklar
  - API key eksik kaynaklar
  - Hata olan kaynaklar
- Kaynak bazlı sonuçlar (her kaynaktan bulunan email, host, IP sayıları)
- Toplam sonuçlar:
  - E-posta adresleri
  - Host'lar
  - Subdomain'ler
  - IP adresleri
  - URL'ler

**Timeout**: 10 dakika (600 saniye)

**Not**: Bazı kaynaklar API key gerektirebilir (Shodan, Censys, vb.).

---

### 10. Subfinder

**Amaç**: Subdomain enumeration (pasif kaynaklar).

**Hedef Format**: 
- ✅ **Domain**: `example.com` (URL'den otomatik çıkarılır)
- ❌ **IP Adresi**: Desteklenmez (domain gerekli)

**Kullanım Senaryosu**:
- Subdomain'leri keşfetmek
- Farklı kaynaklardan subdomain bilgisi toplamak
- Pasif enumeration yapmak
- Certificate transparency log'larını taramak

**Parametreler**:
- `-d`: Hedef domain
- `-oJ`: JSON çıktı formatı (JSONL)
- `-silent`: Sadece subdomain'leri göster (progress bar yok)
- `-timeout 60`: Her kaynak için timeout (saniye)

**Kaynaklar**:
- DNS
- Certificate Transparency
- PassiveDNS
- Shodan
- Censys
- VirusTotal
- Ve daha fazlası...

**Çıktı Formatı**: JSON (JSONL), TXT, JSON (normalize edilmiş)

**Normalize Edilmiş Çıktı**:
- Hedef domain
- Toplam subdomain sayısı (unique subdomain'ler)
- Subdomain listesi (alfabetik sıralı)
- Kaynak listesi (hangi kaynaklardan bulundu: anubis, crtsh, hackertarget, vb.)
- Her subdomain için Finding objesi:
  - Type: `subdomain_discovery`
  - Severity: `INFO`
  - Evidence: subdomain, IP, source, domain bilgileri

**Parsing Özellikleri**:
- JSON dosyasından (JSONL formatı) parse edilir
- stdout çıktısından parse edilir
- raw_output içindeki JSON satırlarından parse edilir
- Ana domain filtrelenir (sadece gerçek subdomain'ler sayılır)
- Duplicate subdomain'ler otomatik olarak kaldırılır

**Timeout**: 5 dakika (300 saniye)

**Not**: Subfinder hızlı ve güvenilir pasif enumeration sağlar. JSONL formatındaki çıktılar otomatik olarak parse edilir ve normalize edilmiş formatta sunulur.

---

## 📁 Klasör Yapısı

```
SecTestOpsHub/
├── backend/                          # FastAPI tabanlı backend servisi
│   ├── Dockerfile                    # Backend container imajı
│   ├── requirements.txt              # Python bağımlılıkları
│   └── src/                          # Kaynak kodlar
│       ├── main.py                   # FastAPI uygulama giriş noktası
│       ├── models/                   # Pydantic veri modelleri
│       │   ├── __init__.py          # Model export'ları
│       │   ├── scan.py              # Tarama sonuç modelleri (PingResult, NmapResult, vb.)
│       │   └── normalized.py        # Normalizasyon şeması (NormalizedResult, Finding)
│       ├── routers/                  # API endpoint'leri
│       │   ├── __init__.py
│       │   └── scans.py             # /scans/ endpoint'i (POST)
│       └── services/                 # Güvenlik araçları servisleri
│           ├── __init__.py
│           ├── ping.py              # Ping servisi
│           ├── whois.py             # Whois servisi
│           ├── nmap.py              # Nmap servisi
│           ├── nikto.py             # Nikto servisi
│           ├── gobuster.py          # Gobuster servisi
│           ├── zap.py               # ZAP servisi
│           ├── testssl.py           # testssl.sh servisi
│           ├── dnsrecon.py          # dnsrecon servisi
│           ├── theharvester.py      # theHarvester servisi
│           ├── subfinder.py         # Subfinder servisi
│           └── analyze_results.py   # Gemini AI güvenlik analizi servisi
│   └── tests/                        # Test dosyaları (şu an boş)
│       └── __init__.py
│
├── frontend/                         # Statik web paneli
│   ├── Dockerfile                    # Frontend container imajı (Nginx)
│   └── web/                          # Web dosyaları
│       ├── index.html                # Ana sayfa
│       ├── main.js                   # JavaScript (API çağrıları, sonuç gösterimi)
│       └── styles.css                # CSS stilleri
│
├── data/                             # Çıktı dosyaları (paylaşılan volume)
│   └── .gitkeep                      # Git için boş klasör
│
├── docker-compose.yml                # Docker Compose konfigürasyonu
├── env.example                       # Ortam değişkeni şablonu
├── .gitignore                        # Git ignore kuralları
└── README.md                         # Bu dosya
```

### Dosya İsimlendirme

Tüm çıktı dosyaları UUID tabanlı isimlendirme kullanır:
- Format: `<tool>-<uuid>.<ext>`
- Örnek: `nmap-f7b6f889-adbb-44e5-97e1-843b68a0bc37.xml`
- Normalize edilmiş JSON: `<tool>-<uuid>-normalized.json`

### Veri Akışı

1. **Kullanıcı İsteği**: Frontend'den POST `/scans/` isteği
2. **Backend İşleme**: `routers/scans.py` endpoint'i
3. **Servis Çağrıları**: Her seçili araç için ilgili servis modülü çağrılır
4. **Araç Çalıştırma**: `subprocess.run()` ile araç çalıştırılır
5. **Çıktı Kaydetme**: Ham çıktı `data/` dizinine kaydedilir
6. **Normalizasyon**: `normalize_<tool>()` fonksiyonu ile standart formata dönüştürülür
7. **Yanıt**: `ScanPlan` modeli ile JSON yanıt döner
8. **Frontend Gösterimi**: `main.js` normalize edilmiş veriyi kullanıcı dostu formatta gösterir

## 🚀 Hızlı Başlangıç

### Gereksinimler

- Docker & Docker Compose
- 4GB+ RAM (önerilen)
- Linux/macOS/Windows (Docker Desktop)
- İnternet bağlantısı (araç indirme ve tarama için)

### Kurulum

1. **Projeyi klonlayın:**
```bash
git clone https://github.com/sadikkartall/SecTestOpsHub.git
cd SecTestOpsHub
```

2. **Ortam değişkeni dosyasını oluşturun:**
```bash
cp env.example .env
```

3. **Gemini API Key'i ekleyin (AI analizi için):**
```bash
# .env dosyasını düzenleyin ve GEMINI_API_KEY değerini ekleyin
# API Key almak için: https://makersuite.google.com/app/apikey
GEMINI_API_KEY=your_gemini_api_key_here
```

**Not**: AI analizi olmadan da sistem çalışır, ancak güvenlik analizi özelliği devre dışı kalır.

4. **Servisleri başlatın:**
```bash
docker compose up --build
```

5. **Servislerin hazır olmasını bekleyin (30-60 saniye)**

6. **Tarayıcıda açın:**
- **Web Paneli**: http://localhost:8080
- **API Dokümantasyonu**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### Kullanım

1. Web panelinde hedef URL'yi girin (örn: `example.com` veya `https://example.com`)
2. İstediğiniz araçları seçin (varsayılan: tümü seçili)
3. "Planı Oluştur" butonuna tıklayın
4. Tarama sonuçları ekranda görüntülenecek ve `data/` dizinine kaydedilecek

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

1. `backend/src/services/` dizinine yeni modül ekleyin (örn: `newtool.py`)
2. Standart fonksiyon imzası: `run_<tool>(target, output_dir, ...) -> <Tool>Result`
3. Normalizasyon fonksiyonu ekleyin: `normalize_<tool>(...) -> NormalizedResult`
4. `backend/src/models/scan.py` içine sonuç modeli ekleyin (örn: `NewToolResult`)
5. `backend/src/routers/scans.py` içine entegrasyon ekleyin
6. `frontend/web/main.js` içine görüntüleme kodu ekleyin

### Kod Standartları

- **Yorumlar**: Tüm yorumlar Türkçe olmalıdır
- **Fonksiyon İsimleri**: İngilizce (Python standartları)
- **Değişken İsimleri**: İngilizce (Python standartları)
- **Dokümantasyon**: Docstring'ler Türkçe olabilir

## ⚠️ Güvenlik ve Etik

- ⚠️ **Bu araç sadece yasal ve izinli güvenlik testleri için kullanılmalıdır**
- ⚠️ Sahip olmadığınız sistemleri taramayın
- ⚠️ Tüm testler kontrollü ortamlarda yapılmalıdır
- ⚠️ Yazarlar, kötüye kullanımdan sorumlu değildir
- ⚠️ Rate limiting ve etik hacking prensiplerine uyun

## 📚 Teknik Detaylar

### Backend Bağımlılıkları

- `fastapi==0.115.0`: Web framework
- `uvicorn==0.30.6`: ASGI server
- `pydantic==2.9.2`: Veri validasyonu
- `httpx==0.27.2`: HTTP client
- `beautifulsoup4==4.12.3`: HTML parsing (ZAP için)
- `lxml==5.1.0`: XML parsing (Nmap için)
- `google-generativeai==0.8.3`: Gemini AI entegrasyonu
- `python-dotenv==1.0.0`: Ortam değişkenleri yönetimi

### Frontend Teknolojileri

- Vanilla JavaScript (ES6+)
- Fetch API (REST çağrıları için)
- CSS3 (modern stiller)

### Container Özellikleri

- **Backend**: Python 3.12-slim, NET_RAW/NET_ADMIN capabilities
- **Frontend**: Nginx alpine
- **ZAP**: OWASP ZAP stable image

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
