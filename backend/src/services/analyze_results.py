import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import google.generativeai as genai
from pydantic import BaseModel
from dotenv import load_dotenv

from ..models.scan import ScanPlan

# .env dosyasını yükle - modül yüklendiğinde
def _load_env_file():
    """
    .env dosyasını yükle - birden fazla yolu dene
    Önce environment variable'ı kontrol et, yoksa .env dosyasını ara
    """
    # Önce environment variable'ı kontrol et (Docker Compose'dan gelebilir)
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        print(f"[SUCCESS] GEMINI_API_KEY environment variable'dan yüklendi, uzunluk: {len(api_key)}")
        return api_key
    
    # Environment variable yoksa .env dosyasını ara
    current_file = Path(__file__).resolve()
    
    # Proje root'u bul (backend/src/services -> backend -> SecTestOpsHub)
    project_root = current_file.parent.parent.parent.parent
    
    env_paths = [
        project_root / '.env',  # Proje root (en olası)
        current_file.parent.parent.parent / '.env',  # Backend klasörü
        Path.cwd() / '.env',  # Çalışma dizini
        Path.cwd().parent / '.env',  # Çalışma dizininin üstü
    ]
    
    print(f"[DEBUG] Aranan .env yolları:")
    for path in env_paths:
        print(f"  - {path} (exists: {path.exists()})")
    
    for env_path in env_paths:
        if env_path.exists():
            try:
                # Önce load_dotenv ile dene
                load_dotenv(dotenv_path=env_path, override=True)
                
                # Tekrar environment variable'ı kontrol et
                api_key = os.getenv("GEMINI_API_KEY")
                if api_key:
                    print(f"[SUCCESS] GEMINI_API_KEY .env dosyasından yüklendi: {env_path}")
                    print(f"[SUCCESS] API Key uzunluk: {len(api_key)}")
                    return api_key
                
                # Direkt dosyayı da oku (daha güvenilir)
                with open(env_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")
                            if key == 'GEMINI_API_KEY' and value:
                                os.environ['GEMINI_API_KEY'] = value
                                print(f"[SUCCESS] GEMINI_API_KEY direkt dosyadan yüklendi: {env_path}")
                                print(f"[SUCCESS] API Key uzunluk: {len(value)}")
                                return value
            except Exception as e:
                print(f"[ERROR] .env yüklenirken hata {env_path}: {e}")
                import traceback
                traceback.print_exc()
                continue
    
    print("[ERROR] GEMINI_API_KEY hiçbir .env dosyasında bulunamadı!")
    return None

# Modül yüklendiğinde API key'i kontrol et
print("[INFO] analyze_results.py modülü yükleniyor, GEMINI_API_KEY kontrol ediliyor...")
_loaded_api_key = _load_env_file()
if _loaded_api_key:
    print(f"[SUCCESS] Modül yükleme sırasında API key yüklendi")
else:
    print("[WARNING] Modül yükleme sırasında API key yüklenemedi, fonksiyon çağrısında tekrar denenecek")


class ToolAnalysis(BaseModel):
    """Her tool için ayrı analiz sonucu."""
    tool_name: str
    risk_level: str  # "critical", "high", "medium", "low", "safe"
    findings_count: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    summary: str  # Tool özelinde özet
    key_issues: List[str]  # Önemli sorunlar
    recommendations: List[str]  # Tool özelinde öneriler


class RiskLevelSummary(BaseModel):
    """Risk seviyesi özeti."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class SecurityRecommendation(BaseModel):
    """Güvenlik önerisi."""
    priority: str  # "critical", "high", "medium", "low"
    title: str
    description: str
    affected_tools: List[str]  # Hangi araçlardan geldiği
    action_items: List[str]  # Yapılacaklar listesi


class AnalysisResult(BaseModel):
    """AI analiz sonucu."""
    target_url: str
    overall_risk_level: str  # "critical", "high", "medium", "low", "safe"
    risk_summary: RiskLevelSummary
    total_findings: int
    tool_analyses: List[ToolAnalysis]  # Her tool için ayrı analiz
    recommendations: List[SecurityRecommendation]
    analysis_summary: str  # Genel analiz özeti
    risk_table: Dict[str, Any]  # Risk seviyesi tablosu


def analyze_scan_results(scan_plan: ScanPlan) -> AnalysisResult:
    """
    Gemini AI kullanarak tarama sonuçlarını analiz eder.
    Her tool için ayrı analiz yapar ve ortak rapor üretir.
    
    Args:
        scan_plan: Tarama planı (tüm araç sonuçları)
        
    Returns:
        AnalysisResult: Analiz sonuçları, risk seviyesi tablosu ve öneriler
    """
    # Gemini API key'i al - _load_env_file önce environment variable'ı kontrol eder
    api_key = _load_env_file()
    
    if not api_key:
        print("[ERROR] GEMINI_API_KEY yüklenemedi!")
    else:
        print(f"[INFO] GEMINI_API_KEY başarıyla yüklendi, uzunluk: {len(api_key)}")
    
    if not api_key:
        # API key yoksa analiz yapmadan devam et
        return AnalysisResult(
            target_url=scan_plan.target_url,
            overall_risk_level="unknown",
            risk_summary=RiskLevelSummary(),
            total_findings=0,
            tool_analyses=[],
            recommendations=[],
            analysis_summary="Gemini AI API key ayarlanmamış. Lütfen .env dosyasına GEMINI_API_KEY=your_key ekleyin ve backend'i yeniden başlatın.",
            risk_table={}
        )
    
    # Gemini AI'yı yapılandır
    genai.configure(api_key=api_key)
    
    # Model adını belirle - önce mevcut modelleri listele
    model = None
    model_name = None
    
    try:
        # Mevcut modelleri listele
        available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        print(f"[INFO] Mevcut Gemini modelleri: {available_models}")
        
        # Öncelik sırasına göre model dene (en yeni modeller önce)
        model_candidates = [
            'models/gemini-2.5-flash',      # En yeni ve hızlı
            'models/gemini-2.5-pro',        # En yeni ve güçlü
            'models/gemini-2.0-flash',      # 2.0 flash
            'models/gemini-2.0-flash-exp',   # 2.0 experimental
            'models/gemini-1.5-flash',       # 1.5 flash (eski)
            'models/gemini-1.5-pro',        # 1.5 pro (eski)
            'models/gemini-pro',            # Eski model
            'gemini-2.5-flash',             # Prefix olmadan
            'gemini-2.5-pro',
            'gemini-2.0-flash',
            'gemini-1.5-flash',
            'gemini-1.5-pro',
            'gemini-pro'
        ]
        
        for candidate in model_candidates:
            # Model adını normalize et (models/ prefix'i ekle/çıkar)
            normalized_name = candidate if candidate.startswith('models/') else f'models/{candidate}'
            
            # Mevcut modeller listesinde var mı kontrol et
            if any(normalized_name in m or candidate in m for m in available_models):
                try:
                    model = genai.GenerativeModel(candidate)
                    model_name = candidate
                    print(f"[SUCCESS] Gemini model '{candidate}' başarıyla yüklendi")
                    break
                except Exception as e:
                    print(f"[WARNING] Model '{candidate}' bulundu ama yüklenemedi: {e}")
                    continue
        
        # Hiçbiri çalışmadıysa, yine de en yaygın olanı dene
        if not model:
            print("[WARNING] Mevcut modeller listesinde uygun model bulunamadı, varsayılan modelleri deniyoruz...")
            for candidate in ['models/gemini-2.5-flash', 'models/gemini-2.5-pro', 'models/gemini-2.0-flash', 'gemini-pro', 'models/gemini-pro']:
                try:
                    model = genai.GenerativeModel(candidate)
                    model_name = candidate
                    print(f"[SUCCESS] Gemini model '{candidate}' başarıyla yüklendi (varsayılan)")
                    break
                except Exception as e:
                    print(f"[WARNING] Model '{candidate}' yüklenemedi: {e}")
                    continue
                    
    except Exception as e:
        print(f"[WARNING] Model listesi alınamadı: {e}, varsayılan modelleri deniyoruz...")
        # ListModels başarısız olursa direkt model yüklemeyi dene
        for candidate in ['models/gemini-2.5-flash', 'models/gemini-2.5-pro', 'models/gemini-2.0-flash', 'models/gemini-1.5-flash', 'models/gemini-pro', 'gemini-pro']:
            try:
                model = genai.GenerativeModel(candidate)
                model_name = candidate
                print(f"[SUCCESS] Gemini model '{candidate}' başarıyla yüklendi (fallback)")
                break
            except Exception as e2:
                print(f"[WARNING] Model '{candidate}' yüklenemedi: {e2}")
                continue
    
    if not model:
        error_msg = "Gemini model bulunamadı. Lütfen API key'inizin geçerli olduğundan ve model erişiminizin olduğundan emin olun."
        print(f"[ERROR] {error_msg}")
        raise RuntimeError(error_msg)
    
    # Tool mapping ve normalize edilmiş sonuçları topla
    tool_results = {}
    result_mapping = {
        "ping": scan_plan.ping_result,
        "whois": scan_plan.whois_result,
        "nmap": scan_plan.nmap_result,
        "nikto": scan_plan.nikto_result,
        "gobuster": scan_plan.gobuster_result,
        "zap": scan_plan.zap_result,
        "testssl": scan_plan.testssl_result,
        "dnsrecon": scan_plan.dnsrecon_result,
        "theharvester": scan_plan.theharvester_result,
        "subfinder": scan_plan.subfinder_result,
    }
    
    for tool_name, result in result_mapping.items():
        if result and result.normalized_json:
            tool_results[tool_name] = result.normalized_json
    
    if not tool_results:
        return AnalysisResult(
            target_url=scan_plan.target_url,
            overall_risk_level="safe",
            risk_summary=RiskLevelSummary(),
            total_findings=0,
            tool_analyses=[],
            recommendations=[],
            analysis_summary="Tarama sonucu bulunamadı.",
            risk_table={}
        )
    
    # Her tool için ayrı analiz yap
    tool_analyses = []
    all_findings = []
    
    print(f"[INFO] Toplam {len(tool_results)} tool için analiz yapılacak: {list(tool_results.keys())}")
    
    for tool_name, normalized_data in tool_results.items():
        try:
            findings_count = len(normalized_data.get("findings", []))
            metrics_keys = list(normalized_data.get("metrics", {}).keys())
            print(f"[INFO] {tool_name} için AI analizi başlatılıyor... (Findings: {findings_count}, Metrics: {metrics_keys})")
            
            tool_analysis = analyze_single_tool(model, tool_name, normalized_data, scan_plan.target_url)
            tool_analyses.append(tool_analysis)
            
            print(f"[SUCCESS] {tool_name} analizi tamamlandı:")
            print(f"  - Risk Level: {tool_analysis.risk_level}")
            print(f"  - Summary: {tool_analysis.summary[:100]}...")
            print(f"  - Key Issues: {len(tool_analysis.key_issues)}")
            print(f"  - Recommendations: {len(tool_analysis.recommendations)}")
            
            # Findings'leri topla
            if normalized_data.get("findings"):
                for finding in normalized_data["findings"]:
                    finding["tool"] = tool_name
                    all_findings.append(finding)
        except Exception as e:
            # Tool analizi başarısız olursa devam et
            import traceback
            print(f"[ERROR] Tool {tool_name} analizi başarısız: {e}")
            print(f"[ERROR] Hata detayı:\n{traceback.format_exc()}")
            # Hata olsa bile varsayılan bir analiz ekle
            tool_analyses.append(ToolAnalysis(
                tool_name=tool_name,
                risk_level="unknown",
                findings_count=len(normalized_data.get("findings", [])),
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
                info_findings=0,
                summary=f"{tool_name} analizi sırasında hata oluştu: {str(e)}",
                key_issues=[],
                recommendations=[]
            ))
            continue
    
    print(f"[INFO] Tool analizleri tamamlandı. Toplam {len(tool_analyses)} analiz, {len(all_findings)} finding.")
    
    # Ortak analiz yap
    try:
        print(f"[INFO] Genel analiz başlatılıyor...")
        overall_analysis = analyze_overall(model, tool_results, tool_analyses, scan_plan.target_url, all_findings)
        print(f"[SUCCESS] Genel analiz tamamlandı:")
        print(f"  - Overall Risk: {overall_analysis.get('overall_risk_level')}")
        print(f"  - Recommendations: {len(overall_analysis.get('recommendations', []))}")
        print(f"  - Analysis Summary: {overall_analysis.get('analysis_summary', '')[:100]}...")
    except Exception as e:
        # Ortak analiz başarısız olursa varsayılan döndür
        import traceback
        print(f"[ERROR] Ortak analiz başarısız: {e}")
        print(f"[ERROR] Hata detayı:\n{traceback.format_exc()}")
        overall_analysis = {
            "overall_risk_level": "medium",
            "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "total_findings": len(all_findings),
            "recommendations": [],
            "analysis_summary": f"Analiz tamamlandı ancak detaylı değerlendirme yapılamadı. Hata: {str(e)}",
            "risk_table": {}
        }
    
    # Risk özetini hesapla
    risk_summary = RiskLevelSummary(**overall_analysis.get("risk_summary", {}))
    
    # Önerileri oluştur
    recommendations = [
        SecurityRecommendation(**rec) for rec in overall_analysis.get("recommendations", [])
    ]
    
    return AnalysisResult(
        target_url=scan_plan.target_url,
        overall_risk_level=overall_analysis.get("overall_risk_level", "safe"),
        risk_summary=risk_summary,
        total_findings=overall_analysis.get("total_findings", len(all_findings)),
        tool_analyses=tool_analyses,
        recommendations=recommendations,
        analysis_summary=overall_analysis.get("analysis_summary", ""),
        risk_table=overall_analysis.get("risk_table", {})
    )


def analyze_single_tool(model, tool_name: str, normalized_data: Dict[str, Any], target_url: str) -> ToolAnalysis:
    """Tek bir tool için detaylı analiz yapar."""
    
    # Tool'a özel prompt oluştur - DETAYLI analiz için
    tool_prompts = {
        "nmap": """
Nmap tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- Açık portlar ve servisler: Hangi portlar açık, hangi servisler çalışıyor?
- Servis versiyonları: Eski versiyonlar var mı? Bilinen CVE'ler var mı?
- İşletim sistemi tespiti: OS bilgisi sızdırılıyor mu?
- Güvenlik açıkları: CVE'ler, zafiyetler tespit edildi mi?
- Port yapılandırması: Gereksiz portlar açık mı? Firewall kuralları yeterli mi?
- Servis yapılandırması: Servisler güvenli yapılandırılmış mı?

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları ve DETAYLI çözüm önerileri sun.
""",
        "zap": """
OWASP ZAP tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- Web uygulama güvenlik açıkları: XSS, SQL Injection, CSRF, Command Injection vb.
- OWASP Top 10 riskler: Tüm kategorileri kontrol et
- Güvenlik başlıkları: CSP, X-Frame-Options, HSTS, X-Content-Type-Options eksik mi?
- Authentication/Authorization: Zayıf kimlik doğrulama, yetkilendirme sorunları
- Session Management: Session güvenliği, cookie güvenliği
- Input Validation: Kullanıcı girdisi doğrulama eksiklikleri
- Error Handling: Hata mesajları bilgi sızdırıyor mu?

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları, kod örnekleri ve DETAYLI çözüm önerileri sun.
""",
        "nikto": """
Nikto tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- Web sunucu yapılandırma hataları: Yanlış yapılandırılmış ayarlar
- Eski yazılım versiyonları: Güncellenmemiş yazılımlar, bilinen zafiyetler
- Güvenlik açıkları: CVE'ler, bilinen zafiyetler
- Potansiyel güvenlik riskleri: Gizli dosyalar, yedek dosyalar, bilgi sızıntıları
- Sunucu başlıkları: Server header bilgileri sızdırılıyor mu?
- Dosya ve dizin keşfi: Gizli dosyalar, dizin listeleme

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları ve DETAYLI çözüm önerileri sun.
""",
        "testssl": """
testssl.sh SSL/TLS tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- SSL/TLS protokol desteği: TLS 1.0, 1.1 gibi eski protokoller destekleniyor mu?
- Cipher suite güvenliği: Zayıf şifreleme algoritmaları kullanılıyor mu?
- Sertifika sorunları: Geçersiz sertifika, süresi dolmuş sertifika, yanlış CN
- Güvenlik açıkları: Heartbleed, POODLE, BEAST, CRIME, BREACH vb.
- Perfect Forward Secrecy: PFS destekleniyor mu?
- Certificate Transparency: CT kayıtları var mı?

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları, konfigürasyon örnekleri ve DETAYLI çözüm önerileri sun.
""",
        "gobuster": """
Gobuster dizin tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- Gizli dizinler ve dosyalar: Hangi dizinler/f dosyalar keşfedildi?
- Yönetim panelleri: Admin paneli, yönetim arayüzü erişilebilir mi?
- Yedek dosyalar: .bak, .old, .backup gibi yedek dosyalar var mı?
- API endpoint'leri: Gizli API'ler keşfedildi mi?
- Bilgi sızıntısı: Hassas bilgiler içeren dosyalar erişilebilir mi?
- Dosya izinleri: Dosyalar yanlış izinlerle yapılandırılmış mı?

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları ve DETAYLI çözüm önerileri sun.
""",
        "dnsrecon": """
dnsrecon DNS tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- DNS kayıt güvenliği: DNS kayıtları doğru yapılandırılmış mı?
- DNSSEC durumu: DNSSEC etkin mi?
- Subdomain keşfi: Beklenmeyen subdomain'ler var mı?
- SPF, DMARC, DKIM kayıtları: E-posta güvenliği kayıtları var mı?
- DNS bilgi sızıntısı: DNS kayıtları fazla bilgi sızdırıyor mu?
- Zone transfer: Zone transfer açık mı?

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları ve DETAYLI çözüm önerileri sun.
""",
        "subfinder": """
Subfinder subdomain tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- Keşfedilen subdomain'ler: Hangi subdomain'ler keşfedildi?
- Subdomain güvenliği: Subdomain'ler güvenli yapılandırılmış mı?
- Potansiyel saldırı yüzeyi: Hangi subdomain'ler saldırıya açık?
- Gizli subdomain'ler: Beklenmeyen subdomain'ler var mı?
- Subdomain takeover riski: Kullanılmayan subdomain'ler var mı?

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları ve DETAYLI çözüm önerileri sun.
""",
        "theharvester": """
theHarvester OSINT tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- Açığa çıkan bilgiler: Hangi bilgiler halka açık?
- E-posta adresleri: E-posta adresleri sızdırılıyor mu?
- Host ve IP bilgileri: IP adresleri, host bilgileri açığa çıkmış mı?
- Bilgi sızıntısı riskleri: Hassas bilgiler halka açık mı?
- Sosyal mühendislik riskleri: Saldırganlar için bilgi kaynağı var mı?
- Metadata sızıntısı: Metadata'da hassas bilgiler var mı?

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları ve DETAYLI çözüm önerileri sun.
""",
        "whois": """
Whois tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- Domain kayıt bilgileri: Domain bilgileri doğru mu?
- Registrar bilgileri: Registrar güvenilir mi?
- Kayıt tarihleri: Domain süresi dolmak üzere mi?
- İletişim bilgileri: İletişim bilgileri güncel mi? Gizlilik koruması var mı?
- Domain hijacking riski: Domain ele geçirilme riski var mı?
- Bilgi sızıntısı: WHOIS'te fazla bilgi sızdırılıyor mu?

Her bulgu için: Risk seviyesi, etki analizi, saldırı senaryoları ve DETAYLI çözüm önerileri sun.
""",
        "ping": """
Ping tarama sonuçlarını DETAYLI analiz et. Özellikle şunlara dikkat et:
- Host erişilebilirliği: Host erişilebilir mi?
- DNS çözümlemesi: DNS doğru çalışıyor mu?
- Ağ bağlantısı: Ağ bağlantısı sağlıklı mı?
- Gecikme süreleri: Yüksek gecikme var mı?
- ICMP filtreleme: ICMP paketleri filtreleniyor mu? (Güvenlik açısından)
- Host keşfi: Host bilgileri sızdırılıyor mu?

Her bulgu için: Risk seviyesi, etki analizi ve DETAYLI çözüm önerileri sun.
"""
    }
    
    tool_specific_guidance = tool_prompts.get(tool_name, "Bu tool'un sonuçlarını analiz et.")
    
    findings = normalized_data.get("findings", [])
    metrics = normalized_data.get("metrics", {})
    summary = normalized_data.get("summary", "")
    status = normalized_data.get("status", "unknown")
    
    # Severity sayılarını hesapla
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")
    info_count = sum(1 for f in findings if f.get("severity") == "INFO")
    
    # Findings yoksa bile metrics'ten analiz yapılabilir
    has_findings = len(findings) > 0
    findings_note = ""
    if not has_findings:
        findings_note = "\nNOT: Bu tool için findings listesi boş, ancak metrics (metrikler) bilgilerinden analiz yapabilirsin. Metrics'teki bilgileri kullanarak risk seviyesi belirle."
    else:
        findings_note = f"\nÖNEMLİ: {len(findings)} adet bulgu var. Her bulgunun 'evidence' alanını DETAYLI analiz et. Özellikle teknik detayları (port numaraları, servis versiyonları, URL'ler, alert bilgileri, CPE bilgileri vb.) değerlendir."
    
    # Tool-specific detaylı analiz notları
    tool_specific_analysis = ""
    
    # NMAP için özel analiz
    if tool_name == "nmap" and metrics.get("ports"):
        ports_info = []
        for port in metrics.get("ports", []):
            if port.get("state") == "open":
                port_str = f"Port {port.get('port')}/{port.get('protocol')}: {port.get('service', 'unknown')}"
                if port.get("version"):
                    port_str += f" - Versiyon: {port.get('version')}"
                if port.get("product"):
                    port_str += f" - Ürün: {port.get('product')}"
                if port.get("cpe"):
                    port_str += f" - CPE: {port.get('cpe')}"
                ports_info.append(port_str)
        
        if ports_info:
            tool_specific_analysis += f"\n\n🔍 NMAP AÇIK PORTLAR ({len(ports_info)} adet):\n" + "\n".join(ports_info)
            tool_specific_analysis += "\n\nBu açık portları DETAYLI analiz et:\n"
            tool_specific_analysis += "- Her portun güvenlik riskini değerlendir (eski versiyonlar, bilinen zafiyetler, CVE'ler)\n"
            tool_specific_analysis += "- Gereksiz açık portlar var mı? Gereksiz servisler kapatılmalı\n"
            tool_specific_analysis += "- Servis versiyonları güncel mi? Eski versiyonlar HIGH/MEDIUM risk oluşturabilir\n"
            tool_specific_analysis += "- Bilinen güvenlik açıkları olan servisler var mı? CVE veritabanını kontrol et\n"
            tool_specific_analysis += "- Firewall kuralları yeterli mi? Gereksiz portlar kapatılmalı mı?\n"
            tool_specific_analysis += "- OS tespiti yapıldı mı? OS bilgisi sızdırılıyor mu?\n"
    
    # ZAP için özel analiz
    if tool_name == "zap" and metrics.get("risk_summary"):
        risk_summary = metrics.get("risk_summary", {})
        tool_specific_analysis += f"\n\n🔍 ZAP RİSK ÖZETİ:\n"
        tool_specific_analysis += f"- Yüksek Risk: {risk_summary.get('high', 0)}\n"
        tool_specific_analysis += f"- Orta Risk: {risk_summary.get('medium', 0)}\n"
        tool_specific_analysis += f"- Düşük Risk: {risk_summary.get('low', 0)}\n"
        tool_specific_analysis += f"- Bilgilendirme: {risk_summary.get('informational', 0)}\n"
        tool_specific_analysis += f"- Toplam Alert: {metrics.get('total_alerts', 0)}\n"
        tool_specific_analysis += "\nHer alert'i DETAYLI analiz et:\n"
        tool_specific_analysis += "- Alert türü, risk seviyesi, etkilenen URL'ler\n"
        tool_specific_analysis += "- OWASP Top 10 kategorisine göre sınıflandır\n"
        tool_specific_analysis += "- XSS, SQL Injection, CSRF gibi yaygın açıklar var mı?\n"
        tool_specific_analysis += "- Güvenlik başlıkları eksik mi? (CSP, HSTS, X-Frame-Options)\n"
        tool_specific_analysis += "- Authentication/Authorization sorunları var mı?\n"
        
        if metrics.get("alerts"):
            high_alerts = [a for a in metrics.get("alerts", []) if a.get("risk") == "High"]
            medium_alerts = [a for a in metrics.get("alerts", []) if a.get("risk") == "Medium"]
            if high_alerts:
                tool_specific_analysis += f"\n⚠️ YÜKSEK RİSKLİ ALERT'LER ({len(high_alerts)} adet):\n"
                for alert in high_alerts[:5]:  # İlk 5 tanesini göster
                    tool_specific_analysis += f"- {alert.get('name', 'Unknown')}: {alert.get('description', '')[:100]}...\n"
            if medium_alerts:
                tool_specific_analysis += f"\n⚠️ ORTA RİSKLİ ALERT'LER ({len(medium_alerts)} adet):\n"
                for alert in medium_alerts[:5]:
                    tool_specific_analysis += f"- {alert.get('name', 'Unknown')}: {alert.get('description', '')[:100]}...\n"
    
    # Nikto için özel analiz
    if tool_name == "nikto" and metrics.get("items_by_severity"):
        severity = metrics.get("items_by_severity", {})
        tool_specific_analysis += f"\n\n🔍 NIKTO BULGU ÖZETİ:\n"
        tool_specific_analysis += f"- Kritik: {severity.get('CRITICAL', 0)}\n"
        tool_specific_analysis += f"- Yüksek: {severity.get('HIGH', 0)}\n"
        tool_specific_analysis += f"- Orta: {severity.get('MEDIUM', 0)}\n"
        tool_specific_analysis += f"- Düşük: {severity.get('LOW', 0)}\n"
        tool_specific_analysis += f"- Bilgi: {severity.get('INFO', 0)}\n"
        tool_specific_analysis += f"- Toplam: {metrics.get('total_items', 0)}\n"
        if metrics.get("server"):
            tool_specific_analysis += f"- Sunucu: {metrics.get('server')}\n"
        tool_specific_analysis += "\nHer bulguyu DETAYLI analiz et:\n"
        tool_specific_analysis += "- Web sunucu yapılandırma hataları\n"
        tool_specific_analysis += "- Eski yazılım versiyonları ve bilinen zafiyetler\n"
        tool_specific_analysis += "- Gizli dosyalar, dizin listeleme sorunları\n"
        tool_specific_analysis += "- Güvenlik başlıkları eksiklikleri\n"
    
    # testssl için özel analiz
    if tool_name == "testssl" and metrics.get("vulnerabilities"):
        vulns = metrics.get("vulnerabilities", {})
        protocols = metrics.get("protocols", {})
        tool_specific_analysis += f"\n\n🔍 TESTSSL ANALİZ:\n"
        if protocols:
            tool_specific_analysis += f"Protokoller: {json.dumps(protocols, indent=2)}\n"
        if vulns:
            tool_specific_analysis += f"Güvenlik Açıkları: {json.dumps(vulns, indent=2)}\n"
        if metrics.get("certificate"):
            cert = metrics.get("certificate", {})
            tool_specific_analysis += f"Sertifika: CN={cert.get('cn')}, Geçerlilik={cert.get('validity_days')} gün\n"
        tool_specific_analysis += "\nDETAYLI analiz et:\n"
        tool_specific_analysis += "- TLS protokol desteği (TLS 1.0, 1.1 eski ve riskli)\n"
        tool_specific_analysis += "- Cipher suite güvenliği (zayıf şifreleme algoritmaları)\n"
        tool_specific_analysis += "- Sertifika sorunları (geçersiz, süresi dolmuş, yanlış CN)\n"
        tool_specific_analysis += "- Güvenlik açıkları (Heartbleed, POODLE, BEAST, CRIME, BREACH)\n"
        tool_specific_analysis += "- Perfect Forward Secrecy (PFS) desteği\n"
    
    # Gobuster için özel analiz
    if tool_name == "gobuster" and metrics.get("findings_by_status"):
        findings_by_status = metrics.get("findings_by_status", {})
        tool_specific_analysis += f"\n\n🔍 GOBUSTER BULGU ÖZETİ:\n"
        tool_specific_analysis += f"- Toplam Bulgu: {metrics.get('total_findings', 0)}\n"
        for status, count in findings_by_status.items():
            tool_specific_analysis += f"- Status {status}: {count} adet\n"
        tool_specific_analysis += "\nDETAYLI analiz et:\n"
        tool_specific_analysis += "- Gizli dizinler ve dosyalar (yönetim panelleri, yedek dosyalar)\n"
        tool_specific_analysis += "- API endpoint'leri ve gizli endpoint'ler\n"
        tool_specific_analysis += "- Bilgi sızıntısı riskleri (hassas dosyalar erişilebilir mi?)\n"
        tool_specific_analysis += "- Dosya izinleri ve erişim kontrolü sorunları\n"
        tool_specific_analysis += "- Yedek dosyalar (.bak, .old, .backup) var mı?\n"
    
    # DNS tools için özel analiz
    if tool_name in ["dnsrecon", "subfinder"] and metrics:
        if tool_name == "dnsrecon":
            tool_specific_analysis += f"\n\n🔍 DNSRECON ANALİZ:\n"
            tool_specific_analysis += "DETAYLI analiz et:\n"
            tool_specific_analysis += "- DNS kayıt güvenliği (A, AAAA, MX, TXT kayıtları)\n"
            tool_specific_analysis += "- DNSSEC durumu (etkin mi?)\n"
            tool_specific_analysis += "- SPF, DMARC, DKIM kayıtları (e-posta güvenliği)\n"
            tool_specific_analysis += "- Zone transfer açıkları\n"
            tool_specific_analysis += "- DNS bilgi sızıntısı riskleri\n"
        elif tool_name == "subfinder":
            tool_specific_analysis += f"\n\n🔍 SUBFINDER ANALİZ:\n"
            tool_specific_analysis += f"- Keşfedilen Subdomain Sayısı: {len(findings)}\n"
            tool_specific_analysis += "DETAYLI analiz et:\n"
            tool_specific_analysis += "- Keşfedilen subdomain'ler ve güvenlik durumları\n"
            tool_specific_analysis += "- Subdomain takeover riskleri (kullanılmayan subdomain'ler)\n"
            tool_specific_analysis += "- Potansiyel saldırı yüzeyi genişlemesi\n"
    
    # Ping için özel analiz
    if tool_name == "ping" and metrics:
        tool_specific_analysis += f"\n\n🔍 PING ANALİZ:\n"
        tool_specific_analysis += f"- Erişilebilirlik: {metrics.get('reachability', 'unknown')}\n"
        if metrics.get("resolved_ip"):
            tool_specific_analysis += f"- Çözümlenen IP: {metrics.get('resolved_ip')}\n"
        if metrics.get("rtt_ms"):
            rtt = metrics.get("rtt_ms", {})
            tool_specific_analysis += f"- Gecikme: Min={rtt.get('min')}ms, Avg={rtt.get('avg')}ms, Max={rtt.get('max')}ms\n"
        tool_specific_analysis += "DETAYLI analiz et:\n"
        tool_specific_analysis += "- Host erişilebilirliği ve ağ bağlantısı\n"
        tool_specific_analysis += "- DNS çözümlemesi doğru mu?\n"
        tool_specific_analysis += "- ICMP filtreleme (güvenlik açısından)\n"
    
    # Whois için özel analiz
    if tool_name == "whois" and metrics:
        tool_specific_analysis += f"\n\n🔍 WHOIS ANALİZ:\n"
        if metrics.get("domain"):
            tool_specific_analysis += f"- Domain: {metrics.get('domain')}\n"
        if metrics.get("registrar"):
            tool_specific_analysis += f"- Registrar: {metrics.get('registrar')}\n"
        if metrics.get("dates"):
            dates = metrics.get("dates", {})
            tool_specific_analysis += f"- Oluşturulma: {dates.get('creation')}\n"
            tool_specific_analysis += f"- Son Güncelleme: {dates.get('updated')}\n"
            tool_specific_analysis += f"- Son Kullanma: {dates.get('expiry')}\n"
        tool_specific_analysis += "DETAYLI analiz et:\n"
        tool_specific_analysis += "- Domain kayıt bilgileri ve güvenlik durumu\n"
        tool_specific_analysis += "- Domain süresi dolmak üzere mi? (hijacking riski)\n"
        tool_specific_analysis += "- İletişim bilgileri gizliliği (WHOIS privacy)\n"
        tool_specific_analysis += "- Bilgi sızıntısı riskleri\n"
    
    findings_note += tool_specific_analysis
    
    prompt = f"""
Sen bir siber güvenlik uzmanısın ve penetrasyon testi uzmanısın. {tool_name.upper()} tool'unun tarama sonuçlarını DETAYLI bir şekilde analiz et.

Hedef: {target_url}
Tool: {tool_name}
Durum: {status}
Özet: {summary}
Findings Sayısı: {len(findings)}

{tool_specific_guidance}
{findings_note}

Tool Sonuçları (JSON):
{json.dumps(normalized_data, indent=2, ensure_ascii=False)}

GÖREVİN:
1. Tüm bulguları (findings) ve metrikleri (metrics) DETAYLI analiz et
2. Findings'lerin 'evidence' alanlarını ÖZELLİKLE analiz et (port numaraları, servis versiyonları, CPE bilgileri vb.)
3. Her bulgu için gerçek risk seviyesini belirle (findings'teki severity sadece başlangıç, sen gerçek riski değerlendir):
   - Eski servis versiyonları → HIGH/MEDIUM risk
   - Bilinen güvenlik açıkları olan portlar → CRITICAL/HIGH risk
   - Gereksiz açık portlar → MEDIUM/LOW risk
   - Kritik servisler (SSH, RDP, FTP) → Yapılandırmaya göre risk değişir
4. Her sorun için UYGULANABİLİR ve DETAYLI çözüm önerileri sun
5. Öneriler şunları içermeli:
   - Sorunun ne olduğu (açıklama)
   - Neden riskli olduğu (etki analizi)
   - Nasıl çözüleceği (adım adım çözüm)
   - Hangi dosya/ayar değişiklikleri gerektiği
   - Örnek kod/konfigürasyon (mümkünse)

ÖNEMLİ: Findings'lerde severity "INFO" veya "LOW" olsa bile, gerçek güvenlik riskine göre risk_level belirle!
Örnekler:
- 4 açık port varsa ve bunlar eski versiyonlu servisler ise → risk_level "medium" veya "high"
- ZAP'te "informational" alert'ler bile güvenlik başlıkları eksikse → risk_level "medium"
- Gobuster'da gizli dizinler bulunduysa → risk_level "low" veya "medium"
- testssl'de eski TLS protokolleri destekleniyorsa → risk_level "high"

Lütfen şu formatta KISA ve PROFESYONEL analiz yap (SADECE JSON döndür):
{{
  "risk_level": "critical|high|medium|low|safe|unknown",
  "summary": "Tool özelinde KISA özet analiz (Türkçe, 3-4 cümle). Önemli bulguları ve risk seviyesini öz şekilde açıkla.",
  "key_issues": [
    "Sorun 1: [Sorunun kısa açıklaması, hangi port/servis/URL, neden riskli, kısa etki analizi]",
    "Sorun 2: [Sorunun kısa açıklaması, hangi port/servis/URL, neden riskli, kısa etki analizi]",
    ...
  ],
  "recommendations": [
    "Öneri 1: [Sorun] - Çözüm: [Kısa çözüm özeti, hangi dosya/ayar, örnek komut/konfigürasyon]",
    "Öneri 2: [Sorun] - Çözüm: [Kısa çözüm özeti, hangi dosya/ayar, örnek komut/konfigürasyon]",
    ...
  ]
}}

ÖNEMLİ KURALLAR (TÜM TOOL'LAR İÇİN):
- Summary: 3-4 cümle, öz ve profesyonel
- Key issues: Her sorun 1-2 cümle, teknik detaylar öz şekilde
- Recommendations: Her öneri 2-3 cümle, pratik çözüm, örnek komut/konfigürasyon
- Örnek kod/konfigürasyon ver (kısa ve öz - tek satır komut veya kısa config snippet)
- Findings yoksa bile metrics'ten analiz yap
- Her tool'un özel analiz notlarını DİKKATE AL
- Risk seviyesini gerçek güvenlik durumuna göre belirle
- Gereksiz tekrarlardan kaçın, öz ve net ol

SADECE JSON döndür, başka açıklama ekleme.
"""
    
    try:
        print(f"[DEBUG] {tool_name} için Gemini AI analizi başlatılıyor...")
        print(f"[DEBUG] Findings sayısı: {len(findings)}, Metrics keys: {list(metrics.keys())}")
        
        response = model.generate_content(prompt)
        response_text = response.text.strip()
        
        print(f"[DEBUG] Gemini yanıtı alındı, uzunluk: {len(response_text)}")
        print(f"[DEBUG] İlk 200 karakter: {response_text[:200]}")
        
        # JSON temizle
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()
        
        # JSON parse et
        try:
            analysis_data = json.loads(response_text)
        except json.JSONDecodeError as json_err:
            # JSON parse hatası - response_text'i düzeltmeyi dene
            print(f"[WARNING] JSON parse hatası: {json_err}")
            print(f"[DEBUG] Parse edilemeyen metin: {response_text}")
            
            # Sadece JSON objesini bulmaya çalış (iç içe objeler için)
            import re
            # İç içe süslü parantezleri sayarak JSON objesini bul
            start_idx = response_text.find('{')
            if start_idx != -1:
                brace_count = 0
                end_idx = start_idx
                for i in range(start_idx, len(response_text)):
                    if response_text[i] == '{':
                        brace_count += 1
                    elif response_text[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break
                if end_idx > start_idx:
                    response_text = response_text[start_idx:end_idx]
                    analysis_data = json.loads(response_text)
                else:
                    raise json_err
            else:
                raise json_err
        
        print(f"[DEBUG] {tool_name} analizi başarılı: risk_level={analysis_data.get('risk_level')}")
        
        return ToolAnalysis(
            tool_name=tool_name,
            risk_level=analysis_data.get("risk_level", "safe"),
            findings_count=len(findings),
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            low_findings=low_count,
            info_findings=info_count,
            summary=analysis_data.get("summary", ""),
            key_issues=analysis_data.get("key_issues", []),
            recommendations=analysis_data.get("recommendations", [])
        )
    except Exception as e:
        # Hata durumunda detaylı log ve varsayılan döndür
        import traceback
        error_trace = traceback.format_exc()
        print(f"[ERROR] {tool_name} analizi başarısız: {e}")
        print(f"[ERROR] Hata detayı:\n{error_trace}")
        
        # Metrics'ten basit bir analiz yap
        fallback_summary = f"{tool_name} analizi tamamlandı."
        if metrics:
            if tool_name == "ping":
                reachable = metrics.get("reachability", "unknown")
                if reachable == "up":
                    fallback_summary = f"Host erişilebilir. Ping başarılı."
                elif reachable == "down":
                    fallback_summary = f"Host erişilebilir değil."
            elif tool_name == "nmap":
                ports = metrics.get("ports", [])
                open_ports = [p for p in ports if isinstance(p, dict) and p.get("state") == "open"]
                if open_ports:
                    fallback_summary = f"{len(open_ports)} açık port tespit edildi."
            elif tool_name == "whois":
                domain = metrics.get("domain")
                if domain:
                    fallback_summary = f"Domain bilgileri alındı: {domain}"
        
        return ToolAnalysis(
            tool_name=tool_name,
            risk_level="unknown",
            findings_count=len(findings),
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            low_findings=low_count,
            info_findings=info_count,
            summary=fallback_summary,
            key_issues=[],
            recommendations=[]
        )


def analyze_overall(model, tool_results: Dict[str, Dict], tool_analyses: List[ToolAnalysis], target_url: str, all_findings: List[Dict]) -> Dict[str, Any]:
    """Tüm tool'ları birleştirerek ortak analiz yapar."""
    
    # Risk seviyesi sayılarını topla
    total_critical = sum(ta.critical_findings for ta in tool_analyses)
    total_high = sum(ta.high_findings for ta in tool_analyses)
    total_medium = sum(ta.medium_findings for ta in tool_analyses)
    total_low = sum(ta.low_findings for ta in tool_analyses)
    total_info = sum(ta.info_findings for ta in tool_analyses)
    
    # Genel risk seviyesini belirle
    if total_critical > 0:
        overall_risk = "critical"
    elif total_high > 0:
        overall_risk = "high"
    elif total_medium > 0:
        overall_risk = "medium"
    elif total_low > 0:
        overall_risk = "low"
    else:
        overall_risk = "safe"
    
    prompt = f"""
Sen bir siber güvenlik uzmanısın ve penetrasyon testi uzmanısın. Aşağıdaki tüm güvenlik tarama sonuçlarını birleştirerek KAPSAMLI ve DETAYLI bir güvenlik analizi yap.

Hedef: {target_url}
Kullanılan Araçlar: {', '.join(tool_results.keys())}

Tool Bazlı Analizler:
{json.dumps([ta.model_dump() for ta in tool_analyses], indent=2, ensure_ascii=False)}

Tüm Bulgular (İlk 100):
{json.dumps(all_findings[:100], indent=2, ensure_ascii=False)}

Risk Özeti:
- Critical: {total_critical}
- High: {total_high}
- Medium: {total_medium}
- Low: {total_low}
- Info: {total_info}

GÖREVİN:
1. Tüm tool sonuçlarını birleştirerek genel güvenlik durumunu KISA ve PROFESYONEL değerlendir
2. Tool'lar arası korelasyonları bul (örn: NMAP açık port + ZAP XSS = yüksek risk)
3. Her öncelik seviyesi için KISA ve UYGULANABİLİR öneriler sun
4. Öneriler şunları içermeli (KISA):
   - Sorunun ne olduğu ve öncelik seviyesi
   - Kısa etki analizi
   - Pratik çözüm (3-4 adım)
   - Hangi dosya/ayar değiştirilmeli
   - Örnek komut/konfigürasyon (kısa snippet)

Lütfen şu formatta KAPSAMLI analiz yap (SADECE JSON döndür):
{{
  "overall_risk_level": "critical|high|medium|low|safe",
  "risk_summary": {{
    "critical": {total_critical},
    "high": {total_high},
    "medium": {total_medium},
    "low": {total_low},
    "info": {total_info}
  }},
  "total_findings": {len(all_findings)},
  "recommendations": [
    {{
      "priority": "critical|high|medium|low",
      "title": "Öneri başlığı (Türkçe, açıklayıcı)",
      "description": "DETAYLI açıklama (Türkçe, EN AZ 5-7 cümle). Sorunun ne olduğu, neden riskli olduğu, etkisi, adım adım çözüm, hangi dosyalar/ayarlar değiştirilmeli, örnek kod/konfigürasyon, test adımları",
      "affected_tools": ["tool1", "tool2"],
      "action_items": [
        "Adım 1: [Detaylı açıklama]",
        "Adım 2: [Detaylı açıklama]",
        "Adım 3: [Detaylı açıklama]"
      ]
    }}
  ],
  "analysis_summary": "Genel güvenlik durumu DETAYLI özeti (Türkçe, EN AZ 8-10 cümle). Tüm önemli bulguları, riskleri, tool'lar arası korelasyonları ve genel güvenlik durumunu açıkla.",
  "risk_table": {{
    "critical": [
      {{"tool": "zap", "title": "Bulgu başlığı", "severity": "CRITICAL", "description": "Detaylı açıklama", "port": null, "service": null, "recommendation": "Çözüm önerisi"}}
    ],
    "high": [
      {{"tool": "nmap", "title": "Bulgu başlığı (örn: Port 22/ssh açık - eski versiyon)", "severity": "HIGH", "description": "Detaylı açıklama", "port": 22, "service": "ssh", "recommendation": "Çözüm önerisi"}}
    ],
    "medium": [
      {{"tool": "nmap", "title": "Bulgu başlığı", "severity": "MEDIUM", "description": "Detaylı açıklama", "port": 80, "service": "http", "recommendation": "Çözüm önerisi"}}
    ],
    "low": [],
    "info": []
  }}
}}

ÖNEMLİ KURALLAR:
- EN AZ 5-7 öneri sun (critical ve high öncelikli sorunlar için mutlaka öneri olmalı)
- Her önerinin "description" alanı 2-3 cümle olmalı, öz ve teknik
- Her önerinin "action_items" alanı 3-4 adım içermeli, kısa ve pratik
- Öneriler tool'lar arası korelasyonları da içermeli
- Örnek komut/konfigürasyon ver (kısa, tek satır veya snippet)
- Risk tablosunda her seviye için en önemli bulguları listele (kısa açıklamalar)
- Gereksiz tekrarlardan kaçın, profesyonel ve öz ol

SADECE JSON döndür, başka açıklama ekleme.
"""
    
    try:
        print(f"[DEBUG] Genel analiz için Gemini AI çağrısı yapılıyor...")
        response = model.generate_content(prompt)
        response_text = response.text.strip()
        
        print(f"[DEBUG] Genel analiz yanıtı alındı, uzunluk: {len(response_text)}")
        
        # JSON temizle
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()
        
        try:
            return json.loads(response_text)
        except json.JSONDecodeError as json_err:
            # JSON parse hatası - response_text'i düzeltmeyi dene
            print(f"[WARNING] Genel analiz JSON parse hatası: {json_err}")
            print(f"[DEBUG] Parse edilemeyen metin (ilk 500 karakter): {response_text[:500]}")
            
            # İç içe süslü parantezleri sayarak JSON objesini bul
            start_idx = response_text.find('{')
            if start_idx != -1:
                brace_count = 0
                end_idx = start_idx
                for i in range(start_idx, len(response_text)):
                    if response_text[i] == '{':
                        brace_count += 1
                    elif response_text[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break
                if end_idx > start_idx:
                    response_text = response_text[start_idx:end_idx]
                    return json.loads(response_text)
            
            raise json_err
    except Exception as e:
        # Hata durumunda varsayılan döndür
        return {
            "overall_risk_level": overall_risk,
            "risk_summary": {
                "critical": total_critical,
                "high": total_high,
                "medium": total_medium,
                "low": total_low,
                "info": total_info
            },
            "total_findings": len(all_findings),
            "recommendations": [],
            "analysis_summary": f"Analiz tamamlandı. {total_critical} kritik, {total_high} yüksek, {total_medium} orta seviye bulgu tespit edildi.",
            "risk_table": {}
        }
