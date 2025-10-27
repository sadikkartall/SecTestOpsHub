# SecTestOps Hub - Kurulum ve Kullanım Kılavuzu

## 📋 Gereksinimler

Projeyi çalıştırmadan önce sisteminizde şunların kurulu olması gerekir:

- **Docker Desktop** (Windows/Mac) veya **Docker Engine + Docker Compose** (Linux)
- **Python 3.11+** (local development için)
- **Node.js 18+** (local development için)
- **Git**
- **4GB+ RAM**

## 🚀 Hızlı Başlangıç (Docker ile)

### 1. Projeyi Klonlayın

```bash
cd SecTestOps_Hub
```

### 2. Ortam Değişkenlerini Ayarlayın

API klasöründe `.env` dosyası oluşturun:

```bash
cd api
cp .env.example .env
```

`.env` dosyasını düzenleyin ve gerekli değişkenleri ayarlayın:

```env
DATABASE_URL=postgresql://sectestops:securepassword123@postgres:5432/sectestops_db
REDIS_URL=redis://redis:6379/0
SECRET_KEY=your-super-secret-key-change-this-in-production
OPENAI_API_KEY=your-openai-api-key-here  # Opsiyonel (AI analizi için)
```

### 3. Docker Compose ile Başlatın

Proje kök dizininde:

```bash
docker-compose up --build
```

İlk çalıştırmada image'ların indirilmesi ve build edilmesi 5-10 dakika sürebilir.

### 4. Servisleri Kontrol Edin

Aşağıdaki servisler otomatik olarak başlar:

- **PostgreSQL**: `localhost:5432`
- **Redis**: `localhost:6379`
- **Backend API**: `http://localhost:8000`
- **Frontend**: `http://localhost:3000`
- **Celery Worker**: Arka planda çalışır

### 5. Web Arayüzüne Erişin

Tarayıcınızda şu adresi açın:

```
http://localhost:3000
```

## 📊 API Dokümantasyonu

FastAPI otomatik dokümantasyon sağlar:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## 🎯 İlk Tarama Nasıl Yapılır?

### 1. Target Ekleyin

- Frontend'de **"Targets"** sekmesine gidin
- **"Add Target"** butonuna tıklayın
- Hedef URL veya IP'yi girin (örn: `http://testphp.vulnweb.com` veya `scanme.nmap.org`)
- Opsiyonel bir açıklama ekleyin
- **"Add Target"** butonuna tıklayın

### 2. Tarama Başlatın

- Eklediğiniz target'ın yanındaki **"Scan"** ikonuna tıklayın
- Tarama otomatik olarak başlar
- **"Scans"** sekmesinden ilerlemeyi takip edin

### 3. Sonuçları Görüntüleyin

- Tarama tamamlandığında (status: **Completed**)
- Scan satırındaki **"View"** ikonuna tıklayın
- Tüm bulguları severity'ye göre görüntüleyin
- AI özetlerini ve önerilerini okuyun

### 4. Rapor İndirin

- Scan detay sayfasında **"Download Report"** butonuna tıklayın
- İstediğiniz formatı seçin:
  - **JSON**: Programatik işlemler için
  - **Markdown**: Dokümantasyon için
  - **PDF**: Sunum ve arşivleme için

## 🛠️ Development Modu (Local)

Docker kullanmadan local development için:

### Backend

```bash
cd api
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# PostgreSQL ve Redis'in çalıştığından emin olun
uvicorn main:app --reload
```

### Worker

```bash
cd worker
source venv/bin/activate  # veya yeni venv oluşturun
pip install -r requirements.txt

celery -A tasks worker --loglevel=info
```

### Frontend

```bash
cd frontend
npm install
npm start
```

## 🧪 Test İçin Güvenli Hedefler

Yasal ve izinli test için kullanabileceğiniz hedefler:

1. **OWASP Juice Shop** (local Docker ile çalıştırın):
   ```bash
   docker run -p 3001:3000 bkimminich/juice-shop
   ```
   Target: `http://localhost:3001`

2. **DVWA (Damn Vulnerable Web Application)**:
   ```bash
   docker run -p 8081:80 vulnerables/web-dvwa
   ```
   Target: `http://localhost:8081`

3. **Scanme Nmap**:
   Target: `scanme.nmap.org`

4. **WebGoat**:
   ```bash
   docker run -p 8080:8080 webgoat/webgoat
   ```
   Target: `http://localhost:8080`

⚠️ **Uyarı**: Sahip olmadığınız sistemleri taramayın! Yasadışıdır.

## 🔧 Sorun Giderme

### Docker Servisi Başlamıyor

```bash
# Logları kontrol edin
docker-compose logs api
docker-compose logs worker
docker-compose logs postgres

# Servisleri yeniden başlatın
docker-compose down
docker-compose up --build
```

### Veritabanı Bağlantı Hatası

```bash
# PostgreSQL'in hazır olduğundan emin olun
docker-compose ps

# Manuel bağlantı testi
docker exec -it sectestops_postgres psql -U sectestops -d sectestops_db
```

### Tarama Başlamıyor

```bash
# Worker loglarını kontrol edin
docker-compose logs worker

# Redis bağlantısını test edin
docker exec -it sectestops_redis redis-cli ping
```

### Frontend API'ye Bağlanamıyor

- `.env` dosyasında `REACT_APP_API_URL` değişkenini kontrol edin
- Backend'in çalıştığından emin olun: `curl http://localhost:8000/health`

## 🧹 Temizleme

Tüm container'ları ve volume'ları silmek için:

```bash
docker-compose down -v
```

Sadece container'ları durdurmak için:

```bash
docker-compose stop
```

## 📈 Üretim Deployment (Production)

Üretim ortamı için ek adımlar:

1. **Güvenlik**:
   - `.env` dosyasındaki tüm şifreleri değiştirin
   - `SECRET_KEY` için güçlü bir anahtar oluşturun
   - PostgreSQL ve Redis'i dış erişimden koruyun

2. **Performans**:
   - `docker-compose.prod.yml` oluşturun
   - Nginx reverse proxy ekleyin
   - SSL/TLS sertifikası yapılandırın

3. **Monitoring**:
   - Log aggregation (ELK, Grafana Loki)
   - Metrics (Prometheus + Grafana)
   - Alerting (Alertmanager)

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📝 IEEE Makale İçin Notlar

### Deneysel Metrikler Toplamak İçin:

1. **False Positive Oranı**:
   - Findings tablosundaki `probable_fp` alanını kullanın
   - Manuel doğrulama sonuçlarıyla karşılaştırın

2. **Triage Süresi**:
   - Scan süresini (`finished_at - started_at`) ölçün
   - AI analizli vs analizsiz karşılaştırın

3. **Coverage**:
   - `owasp_category` alanındaki dağılımı analiz edin
   - OWASP Top 10 kapsama yüzdesini hesaplayın

4. **Kullanıcı Memnuniyeti**:
   - Test grubu oluşturun
   - SUS (System Usability Scale) anketi uygulayın

### Verileri Dışa Aktarma:

```bash
# PostgreSQL'den CSV export
docker exec sectestops_postgres psql -U sectestops -d sectestops_db -c "COPY findings TO STDOUT WITH CSV HEADER" > findings.csv

# JSON export
curl http://localhost:8000/api/findings > findings.json
```

## 📧 Destek

Sorularınız için:
- GitHub Issues açın
- [Email adresi eklenecek]

## 📄 Lisans

Bu proje akademik araştırma amaçlıdır.

---

**⚠️ Yasal Uyarı**: Bu araç sadece yasal ve izinli güvenlik testleri için kullanılmalıdır. Yazarlar, kötüye kullanımdan sorumlu değildir.

