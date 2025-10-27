# SecTestOps Hub - Teknik Mimari Dokümantasyonu

## 📐 Sistem Mimarisi

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                          │
│                    React Frontend (Port 3000)                   │
│   - Dashboard    - Targets    - Scans    - Findings            │
└────────────────────────────┬────────────────────────────────────┘
                             │ REST API (HTTP/JSON)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       BACKEND API LAYER                         │
│                     FastAPI (Port 8000)                         │
│   - Authentication    - CRUD Operations    - Report Generation  │
└────────────┬─────────────────────────┬──────────────────────────┘
             │                         │
             ▼                         ▼
┌────────────────────────┐   ┌─────────────────────────┐
│   PostgreSQL Database  │   │    Redis Message Broker │
│      (Port 5432)       │   │       (Port 6379)       │
│  - targets             │   │  - Task Queue           │
│  - scans               │   │  - Results Cache        │
│  - findings            │   └──────────┬──────────────┘
└────────────────────────┘              │
                                        ▼
                             ┌─────────────────────────┐
                             │   CELERY WORKER         │
                             │   Background Tasks      │
                             └──────────┬──────────────┘
                                        │
                 ┌──────────────────────┼──────────────────────┐
                 ▼                      ▼                      ▼
        ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
        │  Nmap Scanner  │    │  OWASP ZAP     │    │  Trivy Scanner │
        │  (Docker)      │    │  (Docker)      │    │  (Docker)      │
        │  Network Scan  │    │  Web App Scan  │    │  SCA / CVE     │
        └────────┬───────┘    └────────┬───────┘    └────────┬───────┘
                 │                     │                     │
                 └─────────────────────┼─────────────────────┘
                                       ▼
                             ┌─────────────────────────┐
                             │   PARSERS & ANALYZERS   │
                             │  - XML/JSON Parsing     │
                             │  - CVSS Scoring         │
                             │  - OWASP Mapping        │
                             └──────────┬──────────────┘
                                        ▼
                             ┌─────────────────────────┐
                             │    AI ANALYZER          │
                             │  OpenAI / HuggingFace   │
                             │  - Summary Generation   │
                             │  - FP Detection         │
                             │  - Recommendations      │
                             └──────────┬──────────────┘
                                        ▼
                             ┌─────────────────────────┐
                             │   REPORT GENERATOR      │
                             │  - JSON Export          │
                             │  - Markdown Export      │
                             │  - PDF Generation       │
                             └─────────────────────────┘
```

## 🗂️ Veri Modeli (Database Schema)

### Targets Table

```sql
CREATE TABLE targets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url             VARCHAR(500) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);
```

### Scans Table

```sql
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id       UUID REFERENCES targets(id) ON DELETE CASCADE,
    tools           VARCHAR[] NOT NULL DEFAULT ARRAY['nmap', 'zap', 'trivy'],
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    started_at      TIMESTAMP,
    finished_at     TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW(),
    error_message   TEXT,
    metadata        JSONB
);
```

### Findings Table

```sql
CREATE TABLE findings (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID REFERENCES scans(id) ON DELETE CASCADE,
    tool                VARCHAR(50) NOT NULL,
    title               VARCHAR(500) NOT NULL,
    severity            VARCHAR(20) NOT NULL,
    cvss_score          FLOAT,
    cve_id              VARCHAR(50),
    owasp_category      VARCHAR(100),
    endpoint            VARCHAR(1000),
    description         TEXT,
    recommendation      TEXT,
    ai_summary          TEXT,
    ai_recommendation   TEXT,
    probable_fp         BOOLEAN DEFAULT FALSE,
    raw_output          JSONB,
    created_at          TIMESTAMP DEFAULT NOW()
);
```

## 🔄 Veri Akışı (Data Flow)

### 1. Tarama Başlatma (Scan Initiation)

```
User → Frontend → API → Database (Create Scan) → Celery Task → Worker
```

1. Kullanıcı frontend'den tarama başlatır
2. API yeni bir `Scan` kaydı oluşturur (status: pending)
3. Celery task kuyruğuna eklenir
4. Worker task'ı alır ve işlemeye başlar
5. Scan status `running` olarak güncellenir

### 2. Tarama Yürütme (Scan Execution)

```
Worker → Tool Container → Parse Output → Store Findings → AI Analysis
```

1. Worker, her araç için Docker container başlatır
2. Araç çalışır ve sonuçları dosyaya yazar
3. Parser, tool output'unu okur ve normalize eder
4. Finding kayıtları veritabanına eklenir
5. AI analyzer her finding için analiz yapar
6. Scan status `completed` olarak güncellenir

### 3. Sonuç Görüntüleme (Results Display)

```
User → Frontend → API → Database (Query Findings) → Frontend (Display)
```

1. Kullanıcı scan detayına gider
2. Frontend, findings listesini çeker
3. Severity'ye göre gruplandırılır
4. AI özetleri ve önerileriyle birlikte gösterilir

## 🧩 Bileşen Detayları

### Backend API (FastAPI)

**Teknolojiler:**
- FastAPI (async web framework)
- SQLAlchemy (ORM)
- Pydantic (validation)
- PostgreSQL (database)

**Endpoints:**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/` | Health check |
| POST | `/api/targets` | Yeni target ekle |
| GET | `/api/targets` | Tüm targetları listele |
| DELETE | `/api/targets/{id}` | Target sil |
| POST | `/api/scans` | Yeni tarama başlat |
| GET | `/api/scans` | Tüm taramaları listele |
| GET | `/api/scans/{id}` | Tarama detayı |
| GET | `/api/findings` | Tüm bulguları listele |
| GET | `/api/scans/{id}/findings` | Taramaya ait bulguları getir |
| GET | `/api/statistics` | İstatistikler |
| GET | `/api/scans/{id}/report/json` | JSON rapor |
| GET | `/api/scans/{id}/report/markdown` | Markdown rapor |
| GET | `/api/scans/{id}/report/pdf` | PDF rapor |

### Worker (Celery)

**Görevler:**

1. **Nmap Scan Task**
   - Command: `nmap -sV -sC -oX output.xml target`
   - Parser: XML → Findings
   - Severity mapping: Port/service bazlı

2. **ZAP Scan Task**
   - Command: `zap-baseline.py -t target -J output.json`
   - Parser: JSON → Findings
   - OWASP Top 10 mapping

3. **Trivy Scan Task**
   - Command: `trivy fs --format json -o output.json target`
   - Parser: JSON → Findings
   - CVE ve CVSS skorları

### Parsers

Her araç için özel parser modülü:

**NmapParser:**
- XML parsing (xmltodict)
- Open port detection
- Service version extraction
- Severity assignment

**ZapParser:**
- JSON parsing
- Alert classification
- OWASP category mapping
- Risk to severity conversion

**TrivyParser:**
- JSON parsing
- CVE extraction
- CVSS score mapping
- Package vulnerability analysis

### AI Analyzer

**İşlevler:**

1. **Summary Generation**
   - Finding description'ı özetle
   - Teknik olmayan dilde açıklama
   - 2-3 cümle ile etki analizi

2. **Recommendation Generation**
   - Actionable remediation steps
   - Priority belirleme
   - Alternative çözümler

3. **False Positive Detection**
   - Context analysis
   - Severity vs impact comparison
   - Historical pattern matching

**Prompt Template:**

```python
"""
Analyze this security finding:

Tool: {tool}
Title: {title}
Severity: {severity}
Description: {description}

Provide:
1. SUMMARY: 2-3 sentence summary
2. RECOMMENDATION: Specific remediation steps
3. FALSE_POSITIVE: YES/NO assessment
"""
```

### Report Generator

**Formatlar:**

1. **JSON**
   - Structured data
   - API entegrasyonu için
   - Programatik işlem

2. **Markdown**
   - Human-readable
   - Documentation
   - Git-friendly

3. **PDF**
   - Professional reports
   - Presentations
   - Archiving

**PDF Yapısı:**
- Cover page (scan metadata)
- Executive summary (statistics)
- Findings by severity
- Remediation recommendations
- OWASP mapping

## 🔒 Güvenlik Özellikleri

1. **Input Validation**
   - Pydantic schemas
   - URL/IP format validation
   - SQL injection prevention (ORM)

2. **Network Isolation**
   - Docker network segmentation
   - Tool containers isolated
   - No direct internet access from worker

3. **Data Protection**
   - Sensitive data masking
   - No credential storage in logs
   - Encrypted database connections

4. **Rate Limiting**
   - Max concurrent scans
   - Tool timeout limits
   - API request throttling

## 📊 Performans Optimizasyonları

1. **Async Operations**
   - FastAPI async endpoints
   - Non-blocking I/O
   - Concurrent scan handling

2. **Caching**
   - Redis result caching
   - Static content caching
   - Database query optimization

3. **Resource Management**
   - Docker resource limits
   - Worker pool sizing
   - Connection pooling

## 🧪 Test Stratejisi

### Unit Tests

```bash
# Backend
pytest api/tests/

# Worker
pytest worker/tests/

# Frontend
npm test
```

### Integration Tests

```bash
# API + Database
pytest api/tests/integration/

# End-to-end
pytest tests/e2e/
```

### Load Tests

```bash
# Locust load testing
locust -f tests/load/locustfile.py
```

## 📈 Monitoring & Logging

### Log Seviyeler

- **DEBUG**: Detailed diagnostic info
- **INFO**: General operational events
- **WARNING**: Warning messages
- **ERROR**: Error events
- **CRITICAL**: Critical errors

### Metrics

- Scan duration
- Finding counts by severity
- Tool success/failure rates
- API response times
- Worker queue length

## 🚀 Deployment Stratejileri

### Development

```bash
docker-compose up
```

### Production

```bash
docker-compose -f docker-compose.prod.yml up -d
```

**Prod optimizations:**
- Multi-stage Docker builds
- Nginx reverse proxy
- SSL/TLS certificates
- Load balancing
- Health checks
- Auto-restart policies

## 📚 Teknoloji Stack Özeti

| Layer | Teknoloji | Versiyon |
|-------|-----------|----------|
| Frontend | React | 18.x |
| UI Library | Material-UI | 5.x |
| Backend | FastAPI | 0.109.x |
| Database | PostgreSQL | 15.x |
| Cache/Queue | Redis | 7.x |
| Worker | Celery | 5.x |
| ORM | SQLAlchemy | 2.x |
| Containerization | Docker | 24.x |
| AI/LLM | OpenAI API | 1.x |
| PDF Generation | ReportLab | 4.x |
| Tools | Nmap, ZAP, Trivy | Latest |

## 🔗 Bağımlılıklar

### Python (Backend/Worker)

```txt
fastapi==0.109.0
uvicorn==0.27.0
sqlalchemy==2.0.25
celery==5.3.6
redis==5.0.1
openai==1.10.0
reportlab==4.0.9
```

### JavaScript (Frontend)

```json
{
  "react": "^18.2.0",
  "@mui/material": "^5.14.20",
  "axios": "^1.6.5",
  "react-router-dom": "^6.21.1",
  "chart.js": "^4.4.1"
}
```

---

Bu mimari dokümantasyon, IEEE makale için "Methodology" bölümünde kullanılabilir.

