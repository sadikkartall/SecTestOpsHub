# 🚀 SecTestOps Hub - Çalıştırma Komutları

## 📋 Hızlı Başlangıç

### 1️⃣ İlk Kurulum

```powershell
# Proje dizinine git
cd C:\Users\sdkkr\Desktop\SecTestOps_Hub

# Docker Desktop'ın çalıştığından emin ol
# (Docker Desktop uygulamasını aç - yeşil balina ikonu)

# Tüm servisleri başlat
docker-compose up -d
```

**İlk kurulum:** 5-10 dakika sürer (image'lar indiriliyor)

---

## 🎯 Farklı Modlar ile Çalıştırma

### STUB_MODE (Önerilen - İlk Deneme İçin)

```powershell
# Test modu - gerçek araçlar çalışmaz, örnek veriler üretilir
$env:STUB_MODE="true"
docker-compose up -d
```

**Avantajlar:**
- ✅ Hızlı test
- ✅ İnternet bağlantısı gerekmez
- ✅ Ağda tarama yapmaz (güvenli)

---

### Normal Mod (Gerçek Araçlar)

```powershell
# Gerçek güvenlik araçları çalışır
$env:STUB_MODE="false"
docker-compose up -d
```

**Gereksinimler:**
- ✅ İnternet bağlantısı
- ✅ İzinli hedefler kullan
- ⚠️ İlk tarama 15-20 dakika sürebilir

---

## 📊 Servisleri Kontrol Etme

### Durum Kontrolü

```powershell
# Tüm container'ların durumunu göster
docker-compose ps

# Beklenen çıktı:
# NAME                   STATUS          PORTS
# sectestops_postgres    Up (healthy)    5432/tcp
# sectestops_redis       Up (healthy)    6379/tcp
# sectestops_api         Up              8000/tcp
# sectestops_worker      Up
# sectestops_frontend    Up              3000/tcp
```

### Log İzleme

```powershell
# Tüm servislerin logları
docker-compose logs -f

# Sadece API logları
docker-compose logs -f api

# Sadece Worker logları
docker-compose logs -f worker

# Son 50 satır log
docker-compose logs --tail=50 worker
```

---

## 🛑 Durdurma

### Kontrollü Durdurma

```powershell
# Container'ları durdur (veriler korunur)
docker-compose stop

# Tamamen sil (veritabanı dahil her şey silinir)
docker-compose down

# Veritabanı dahil tamamen temizle
docker-compose down -v
```

---

## 🔄 Yeniden Başlatma

### Kod Değişikliği Sonrası

```powershell
# Dockerfile değiştiyse rebuild et
docker-compose up -d --build

# Sadece restart et (kod değişikliği yoksa)
docker-compose restart
```

### Temiz Başlangıç

```powershell
# Her şeyi sil
docker-compose down -v

# Yeniden başlat
docker-compose up -d
```

---

## 🌐 Tarayıcıda Erişim

| Servis | URL | Açıklama |
|--------|-----|----------|
| **Frontend** | http://localhost:3000 | Ana uygulama |
| **API** | http://localhost:8000 | Backend API |
| **API Docs** | http://localhost:8000/docs | Swagger UI |
| **ReDoc** | http://localhost:8000/redoc | ReDoc UI |
| **Health** | http://localhost:8000/health | Sağlık kontrolü |

---

## 🧪 İlk Tarama

### 1. Frontend'de Target Ekle

```
1. http://localhost:3000 aç
2. "Targets" sekmesi
3. "Add Target" butonu
4. URL gir (örn: scanme.nmap.org)
5. Kaydet
```

### 2. Tarama Başlat

```
1. Target'ın yanındaki scan ikonuna tıkla
2. Tools seç (Nmap, ZAP, Trivy)
3. Veya Playbook seç
4. "Start" butonu
```

### 3. Sonuçları Gör

```
1. "Scans" sekmesi
2. Status "Completed" olana kadar bekle
3. "View" ikonuna tıkla
4. Findings listesini gör
5. Rapor indir (PDF/Markdown/JSON)
```

---

## 🎯 Kullanım Senaryoları

### Senaryo 1: STUB_MODE ile Hızlı Test

```powershell
# STUB_MODE aktifleştir
$env:STUB_MODE="true"
docker-compose up -d

# Herhangi bir hedefe tara
# Frontend: scanme.nmap.org
# 10 saniyede tamamlanır (örnek veriler)
```

### Senaryo 2: OWASP Juice Shop Test

```powershell
# 1. Juice Shop'u başlat
docker run -d -p 3001:3000 bkimminich/juice-shop

# 2. STUB_MODE kapalı olsun
$env:STUB_MODE="false"
docker-compose up -d

# 3. Frontend'de tara
# URL: http://host.docker.internal:3001
# Tools: nmap, zap, trivy

# 4. 15-20 dakika bekle
# 5. XSS, SQL Injection bulguları gelir
```

### Senaryo 3: Sadece Nmap Taraması

```powershell
# Frontend'de tarama başlatırken:
# Sadece "nmap" işaretle
# Zap ve Trivy'yi kapat
# Daha hızlı tamamlanır (2-3 dakika)
```

---

## 🔧 Sorun Giderme Komutları

### Port Zaten Kullanılıyor

```powershell
# Hangi process kullanıyor bak
netstat -ano | findstr :3000
netstat -ano | findstr :8000

# Process'i sonlandır (PID'yi bulup)
taskkill /F /PID <PID>
```

### Container Başlamıyor

```powershell
# Logları detaylı kontrol et
docker-compose logs api
docker-compose logs worker

# Özel bir servisi yeniden başlat
docker-compose restart api
docker-compose restart worker
```

### Veritabanı Hatası

```powershell
# PostgreSQL container'ına bağlan
docker exec -it sectestops_postgres psql -U sectestops -d sectestops_db

# Tabloları listele
\dt

# Çık
\q
```

### Worker Çalışmıyor

```powershell
# Worker loglarını izle
docker-compose logs -f worker

# Redis bağlantısını test et
docker exec -it sectestops_redis redis-cli ping
# Çıktı: PONG olmalı

# Celery worker'ı manuel başlat (debug için)
docker exec -it sectestops_worker celery -A tasks worker --loglevel=debug
```

### Frontend API'ye Bağlanamıyor

```powershell
# API'nin çalıştığını kontrol et
curl http://localhost:8000/health

# Frontend ortam değişkenlerini kontrol et
docker exec -it sectestops_frontend env | grep REACT_APP_API_URL
```

---

## 📦 Veritabanı İşlemleri

### Yedekleme

```powershell
# PostgreSQL dump al
docker exec sectestops_postgres pg_dump -U sectestops sectestops_db > backup.sql

# Findings'leri CSV olarak export et
docker exec sectestops_postgres psql -U sectestops -d sectestops_db -c "COPY findings TO STDOUT WITH CSV HEADER" > findings.csv
```

### Geri Yükleme

```powershell
# Backup'tan geri yükle
cat backup.sql | docker exec -i sectestops_postgres psql -U sectestops sectestops_db
```

---

## 🔍 Debug Komutları

### Container İçine Gir

```powershell
# API container'ına gir
docker exec -it sectestops_api bash

# Worker container'ına gir
docker exec -it sectestops_worker bash

# PostgreSQL'e gir
docker exec -it sectestops_postgres psql -U sectestops -d sectestops_db
```

### Python Kodunu Test Et

```powershell
# Worker container'ında Python shell aç
docker exec -it sectestops_worker python

# Örnek testler:
# >>> from parsers.nmap_parser import NmapParser
# >>> parser = NmapParser()
# >>> print(parser)
```

### Artifacts Klasörünü İncele

```powershell
# Artifacts klasörünü listele
ls artifacts

# Bir scan'in çıktılarını gör
ls artifacts/<scan_id>/

# Nmap XML'i görüntüle
cat artifacts/<scan_id>/nmap_output.xml
```

---

## ⚙️ Ortam Değişkenleri

### Worker Ortam Değişkenleri

```powershell
# STUB_MODE kontrolü
docker exec sectestops_worker env | grep STUB_MODE

# ENABLE_AI kontrolü
docker exec sectestops_worker env | grep ENABLE_AI
```

### .env Dosyası Oluştur

```bash
# api/.env dosyası oluştur
DATABASE_URL=postgresql://sectestops:securepassword123@postgres:5432/sectestops_db
REDIS_URL=redis://redis:6379/0
SECRET_KEY=your-secret-key-change-in-production
OPENAI_API_KEY=your-openai-api-key
STUB_MODE=false
ENABLE_AI_ANALYSIS=true
```

---

## 🎓 IEEE Makale İçin Veri Toplama

### 1. Test Hedefleri Hazırla

```powershell
# OWASP Juice Shop
docker run -d -p 3001:3000 --name juice-shop bkimminich/juice-shop

# DVWA
docker run -d -p 8081:80 --name dvwa vulnerables/web-dvwa

# testphp.vulnweb.com (online, izinli)
```

### 2. Batch Tarama

```powershell
# Her hedef için tarama başlat (Frontend'den)

# Juice Shop
# Target: http://host.docker.internal:3001

# DVWA  
# Target: http://host.docker.internal:8081

# testphp
# Target: http://testphp.vulnweb.com
```

### 3. Verileri Dışa Aktar

```powershell
# Tüm findings'leri CSV olarak al
docker exec sectestops_postgres psql -U sectestops -d sectestops_db \
  -c "COPY (SELECT * FROM findings ORDER BY created_at DESC) TO STDOUT WITH CSV HEADER" \
  > findings_export.csv

# İstatistikleri JSON olarak al
curl http://localhost:8000/api/statistics > statistics.json
```

---

## 🚀 Performans İpuçları

### İlk Tarama Uzun Sürüyorsa

```powershell
# Worker loglarını izle
docker-compose logs -f worker

# Normal süreler:
# - Nmap: 2-5 dakika
# - ZAP: 5-15 dakika  
# - Trivy: 1-3 dakika
```

### RAM Yetersizse

```powershell
# Docker Desktop → Settings → Resources
# Memory: 4 GB'ye düşür
# CPUs: 2'ye düşür
```

### Disk Doluyorsa

```powershell
# Eski artifacts'ları temizle
docker exec -it sectestops_worker find /app/artifacts -mtime +7 -delete

# Eski images'ları temizle
docker system prune -a
```

---

## ✅ Başarı Kontrol Listesi

Kontrol et:

- [ ] Docker Desktop açık ve çalışıyor
- [ ] `docker-compose ps` tüm servisleri "Up" gösteriyor
- [ ] http://localhost:3000 açılıyor
- [ ] http://localhost:8000/health "healthy" dönüyor
- [ ] Frontend'de target ekleyebiliyorum
- [ ] Tarama başlatabiliyorum
- [ ] Sonuçları görebiliyorum
- [ ] Rapor indirebiliyorum

**Hepsi ✓ ise sistem hazır! 🎉**

---

## 🆘 Acil Durum

### Hiçbir Şey Çalışmıyor

```powershell
# 1. Docker Desktop'ı kapat ve aç
# 2. Bilgisayarı yeniden başlat
# 3. Projeyi temizle
docker-compose down -v
# 4. Yeniden başlat
docker-compose up -d --build
```

### Yardım Alanları

- **README.md** - Genel bilgi
- **SETUP_GUIDE.md** - Detaylı kurulum
- **TOOLS_GUIDE.md** - Araçlar hakkında detay
- **ARCHITECTURE.md** - Teknik mimari

---

**🎉 İyi çalışmalar! Sorularınız için GitHub Issues kullanın!**

