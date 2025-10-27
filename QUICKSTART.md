# 🚀 SecTestOps Hub - Hızlı Başlangıç

## 5 Dakikada Başla!

### 1️⃣ Gereksinimleri Kontrol Et

```bash
docker --version    # Docker 20.10+
docker-compose --version  # Docker Compose 2.0+
```

### 2️⃣ Projeyi Başlat

```bash
# Tüm servisleri başlat
docker-compose up -d

# Logları takip et
docker-compose logs -f
```

### 3️⃣ Web Arayüzüne Git

Tarayıcıda aç: **http://localhost:3000**

### 4️⃣ İlk Taramayı Yap

1. **"Targets"** → **"Add Target"**
2. URL gir: `scanme.nmap.org` veya `http://testphp.vulnweb.com`
3. **"Start Scan"** butonuna tıkla
4. **"Scans"** → Taramayı takip et
5. Tamamlandığında **"View Details"** ile sonuçları gör
6. **"Download Report"** → PDF/Markdown/JSON indir

## 🧪 Test Hedefleri (Yasal & İzinli)

### Local Test Uygulamaları

```bash
# OWASP Juice Shop
docker run -d -p 3001:3000 bkimminich/juice-shop
# Target: http://localhost:3001

# DVWA
docker run -d -p 8081:80 vulnerables/web-dvwa
# Target: http://localhost:8081
```

### Online Test Hedefleri

- `scanme.nmap.org` - Nmap test hedefi
- `http://testphp.vulnweb.com` - Web app test hedefi

## 🛑 Durdurma

```bash
# Servisleri durdur
docker-compose stop

# Servisleri durdur ve sil
docker-compose down

# Veritabanı dahil her şeyi sil
docker-compose down -v
```

## 📊 API Test

```bash
# Health check
curl http://localhost:8000/health

# Targets listesi
curl http://localhost:8000/api/targets

# İstatistikler
curl http://localhost:8000/api/statistics
```

## 🔧 Sorun mu var?

```bash
# Logları kontrol et
docker-compose logs api
docker-compose logs worker
docker-compose logs postgres

# Servisleri yeniden başlat
docker-compose restart

# Temiz başlangıç
docker-compose down -v
docker-compose up --build
```

## 🎓 IEEE Makale İçin

### Test Senaryoları

1. **False Positive Analizi**
   - 5 farklı hedefi tara
   - AI analizli vs analizsiz karşılaştır
   - `probable_fp` oranını ölç

2. **Triage Süresi**
   - Manuel analiz süresini kaydet
   - AI-assisted süreyi kaydet
   - Karşılaştırma grafiği oluştur

3. **Coverage Analizi**
   - OWASP Top 10 kategorilerini say
   - Kapsama yüzdesini hesapla

4. **Kullanıcı Testi**
   - 10 kişilik test grubu
   - SUS anketi uygula
   - Sonuçları analiz et

### Veri Toplama

```bash
# Bulguları CSV olarak dışa aktar
docker exec sectestops_postgres psql -U sectestops -d sectestops_db -c \
  "COPY (SELECT * FROM findings) TO STDOUT WITH CSV HEADER" > findings.csv

# İstatistikleri JSON olarak al
curl http://localhost:8000/api/statistics > statistics.json

# Tarama loglarını kaydet
docker-compose logs worker > worker_logs.txt
```

## 🤝 Yardım

Sorun mu yaşıyorsun? 

1. `SETUP_GUIDE.md` dosyasına bak
2. `ARCHITECTURE.md` ile mimariyi anla
3. GitHub Issues aç
4. Logs paylaş: `docker-compose logs > debug.log`

## ⚠️ Yasal Uyarı

**SADECE** sahip olduğunuz veya test izni aldığınız sistemleri tarayın!

---

**🎉 Başarılar! IEEE makaleniz için bol bulgu!**

