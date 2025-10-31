# 🔧 SecTestOps Hub - Güvenlik Araçları Kılavuzu

## 📊 Desteklenen Güvenlik Araçları

Bu platform **8 farklı güvenlik test aracını** entegre etmiştir:

---

## 1️⃣ Nmap

### 📋 Tanım
**Network Mapper** - Ağ keşfi ve port taraması için en yaygın kullanılan araç

### 🎯 Ne Yapar?
- Açık portları tespit eder
- Çalışan servisleri keşfeder
- Servis versiyonlarını tespit eder
- İşletim sistemi parmak izi alır

### 🔧 Kullanılan Komut
```bash
nmap -sV --max-retries 1 --host-timeout 300s -oX nmap_output.xml <target>
```

**Parametreler:**
- `-sV`: Service version detection
- `--max-retries 1`: Maximum 1 retry
- `--host-timeout 300s`: Timeout 300 saniye
- `-oX`: XML formatında çıktı

### 📄 Çıktı Formatı
- **Format:** XML
- **Parse Edildiği Yer:** `worker/parsers/nmap_parser.py`

### ⚠️ Ne Tespit Eder?
- Açık portlar (22, 80, 443, 3306...)
- Eski servis versiyonları
- Şüpheli açık portlar
- Bilinen güvenlik zafiyetli servisler

---

## 2️⃣ OWASP ZAP

### 📋 Tanım
**Zed Attack Proxy** - OWASP'un resmi web uygulama güvenlik test aracı

### 🎯 Ne Yapar?
- Web uygulamalarında zafiyet tarar
- XSS, SQL Injection test eder
- Güvenlik header'larını kontrol eder
- Session yönetimini analiz eder

### 🔧 Kullanılan Komut
```bash
docker run --rm -v $PWD:/zap/wrk owasp/zap2docker-stable \
  zap-baseline.py -t https://target.com -J zap_output.json
```

**Parametreler:**
- `zap-baseline.py`: Non-aggressive baseline tarama
- `-t`: Target URL
- `-J`: JSON formatında çıktı

### 📄 Çıktı Formatı
- **Format:** JSON
- **Parse Edildiği Yer:** `worker/parsers/zap_parser.py`

### ⚠️ Ne Tespit Eder?
- XSS (Cross-Site Scripting)
- SQL Injection
- CSRF (Cross-Site Request Forgery)
- Güvenlik header eksiklikleri
- Cookie güvenlik sorunları
- OWASP Top 10 zafiyetleri

---

## 3️⃣ Trivy

### 📋 Tanım
**Container & Dependency Scanner** - Aqua Security'in açık kaynaklı tarayıcısı

### 🎯 Ne Yapar?
- Container image'larını tarar
- Dependency'lerdeki CVE'leri tespit eder
- Configuration dosyalarını analiz eder
- Infrastructure as Code güvenliğini test eder

### 🔧 Kullanılan Komut
```bash
docker run --rm -v $PWD:/output aquasec/trivy fs \
  --format json --output /output/trivy_output.json <target>
```

**Parametreler:**
- `fs`: Filesystem scan
- `--format json`: JSON formatında çıktı
- `--output`: Çıktı dosyası

### 📄 Çıktı Formatı
- **Format:** JSON
- **Parse Edildiği Yer:** `worker/parsers/trivy_parser.py`

### ⚠️ Ne Tespit Eder?
- CVE'ler (Common Vulnerabilities and Exposures)
- CVSS skorları
- Eski paket versiyonları
- Güvensiz bağımlılıklar
- Container zafiyetleri

---

## 4️⃣ Nikto

### 📋 Tanım
**Web Server Scanner** - CGI ve web sunucu zafiyet tarama aracı

### 🎯 Ne Yapar?
- Web sunucu yapılandırmalarını tarar
- Eski/deprecated özellikleri tespit eder
- Potansiyel tehlikeli dosyaları listeler
- Sunucu bilgi sızıntılarını tespit eder

### 🔧 Kullanılan Komut (Eklendi - Stub Mode'da)
```bash
nikto -h <target> -o nikto.txt -Format txt
```

**Parametreler:**
- `-h`: Host
- `-o`: Output file
- `-Format txt`: Text formatında çıktı

### 📄 Çıktı Formatı
- **Format:** TXT
- **Parse Edildiği Yer:** `worker/parsers/nikto_parser.py`

### ⚠️ Ne Tespit Eder?
- Bilinen CGI zafiyetleri
- Eski sunucu versiyonları
- Sunucu bilgi sızıntıları
- Potansiyel tehlikeli dosyalar
- Güvenlik yapılandırma hataları

---

## 5️⃣ Amass

### 📋 Tanım
**Subdomain Discovery** - OWASP'un subdomain enumeration aracı

### 🎯 Ne Yapar?
- Subdomain'leri keşfeder
- DNS bilgilerini toplar
- Tüm alan adı yapısını haritalar
- Passif ve aktif tarama yapar

### 🔧 Kullanılan Komut (Eklendi - Stub Mode'da)
```bash
amass enum -passive -d <target_domain> -o amass.txt
```

**Parametreler:**
- `enum`: Enumeration mode
- `-passive`: Passif tarama (daha güvenli)
- `-d`: Domain
- `-o`: Output file

### 📄 Çıktı Formatı
- **Format:** TXT/JSON
- **Parse Edildiği Yer:** `worker/parsers/amass_parser.py`

### ⚠️ Ne Tespit Eder?
- Gizli/keşfedilmemiş subdomain'ler
- Dış kaynaklardan bilgi toplama (OSINT)
- DNS zon transfer zafiyetleri
- Genişletilmiş ağ yapısı haritası

---

## 6️⃣ ffuf

### 📋 Tanım
**Fast Web Fuzzer** - Hızlı web fuzzing aracı

### 🎯 Ne Yapar?
- Endpoint keşfi yapar
- Directory brute-force yapar
- File fuzzing yapar
- Parametre keşfi yapar

### 🔧 Kullanılan Komut (Eklendi - Stub Mode'da)
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -o ffuf.json -of json
```

**Parametreler:**
- `-w`: Wordlist
- `-u`: URL with FUZZ placeholder
- `-o`: Output file
- `-of json`: JSON formatında çıktı

### 📄 Çıktı Formatı
- **Format:** JSON
- **Parse Edildiği Yer:** `worker/parsers/ffuf_parser.py`

### ⚠️ Ne Tespit Eder?
- Gizli dizinler
- Gizli dosyalar
- Admin panelleri
- Backup dosyaları
- API endpoint'leri

---

## 7️⃣ WhatWeb

### 📋 Tanım
**Web Technology Fingerprinter** - Web teknolojisi parmak izi aracı

### 🎯 Ne Yapar?
- Web uygulamasında kullanılan teknolojileri tespit eder
- CMS versiyonlarını belirler
- JavaScript framework'lerini tespit eder
- Server ve OS bilgisini toplar

### 🔧 Kullanılan Komut (Eklendi - Stub Mode'da)
```bash
whatweb -a 3 --json <target> | tee whatweb.json
```

**Parametreler:**
- `-a 3`: Aggressiveness level 3
- `--json`: JSON formatında çıktı

### 📄 Çıktı Formatı
- **Format:** JSON
- **Parse Edildiği Yer:** `worker/parsers/whatweb_parser.py`

### ⚠️ Ne Tespit Eder?
- Kullanılan CMS (WordPress, Drupal, Joomla)
- JavaScript framework'leri
- Web sunucusu (Apache, Nginx)
- Eklenti ve tema versiyonları
- İşletim sistemi ipuçları

---

## 8️⃣ testssl.sh

### 📋 Tanım
**SSL/TLS Scanner** - TLS ve SSL yapılandırma tarayıcısı

### 🎯 Ne Yapar?
- TLS/SSL versiyonlarını test eder
- Şifreleme suite'lerini analiz eder
- Sertifika bilgilerini toplar
- Güvenlik ayarlarını değerlendirir

### 🔧 Kullanılan Komut (Eklendi - Stub Mode'da)
```bash
testssl.sh --json testssl.json <target>
```

**Parametreler:**
- `--json`: JSON formatında çıktı

### 📄 Çıktı Formatı
- **Format:** JSON
- **Parse Edildiği Yer:** `worker/parsers/testssl_parser.py`

### ⚠️ Ne Tespit Eder?
- Eski SSL/TLS versiyonları (SSLv2, SSLv3)
- Zayıf şifreleme algoritmaları (RC4, MD5)
- Güvensiz cipher suite'ler
- Weak Diffie-Hellman anahtarları
- Sertifika sorunları

---

## 🎯 Tam Entegre Workflow

### Normal Mod
```bash
# .env dosyasında veya docker-compose.yml'de:
STUB_MODE=false
```

Araçlar gerçekten çalışır, Docker container'ları ile.

### Stub Mode (Test için)
```bash
STUB_MODE=true
```

Gerçek araçlar çalışmaz, örnek veriler üretilir (hızlı test için).

---

## 📊 Hangi Aracın Ne İçin Kullanılması Gerektiği

| Amaç | Önerilen Araç | Alternatif |
|------|---------------|------------|
| Port keşfi | Nmap | - |
| Web app zafiyeti | OWASP ZAP | Nikto |
| Dependency güvenliği | Trivy | - |
| Subdomain keşfi | Amass | - |
| Endpoint keşfi | ffuf | - |
| Teknoloji tespiti | WhatWeb | Nmap |
| TLS/SSL güvenliği | testssl.sh | - |

---

## 🔄 Otomatik Orkestrasyon

**Playbook Örneği:**
```
Amass → Subdomain'leri keşfet
  ↓
Nmap → Her subdomain'i tara
  ↓
WhatWeb → Teknolojileri tespit et
  ↓
OWASP ZAP → Web app zafiyetlerini bul
  ↓
ffuf → Gizli endpoint'leri keşfet
  ↓
Trivy → Dependency'leri analiz et
```

---

## ⚙️ Yapılandırma

Her araç için varsayılan parametreler `worker/tasks.py` dosyasında tanımlanmıştır.

**Non-intrusive Mod:** Tüm araçlar varsayılan olarak düşük agresiflik seviyesinde çalışır.

**Zaman Aşımı:** Her aracın maksimum çalışma süresi 10 dakikadır.

---

## 📚 Ek Kaynaklar

- [Nmap Documentation](https://nmap.org/book/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Nikto Documentation](https://cirt.net/nikto2-docs/)
- [Amass Documentation](https://github.com/owasp-amass/amass)
- [ffuf Documentation](https://github.com/ffuf/ffuf)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [testssl.sh Documentation](https://github.com/drwetter/testssl.sh)

---

**💡 İpucu:** STUB_MODE ile önce test edin, sonra gerçek araçları kullanın!

