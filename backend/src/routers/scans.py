import os
import re
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, status

from ..models.scan import ScanRequest, ScanPlan
from ..services import ping, whois, nmap, nikto, gobuster, zap, testssl, dnsrecon, theharvester, subfinder
from ..services.analyze_results import analyze_scan_results, AnalysisResult

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/", response_model=ScanPlan, status_code=status.HTTP_201_CREATED)
async def create_scan_plan(payload: ScanRequest) -> ScanPlan:
    """
    Tarama planı oluşturur ve seçilen güvenlik araçlarını çalıştırır.
    
    Args:
        payload: Tarama isteği (hedef URL ve araç listesi)
        
    Returns:
        ScanPlan: Tüm araç sonuçlarını içeren tarama planı
        
    Raises:
        HTTPException: Desteklenmeyen araç veya geçersiz hedef durumunda
    """
    # Desteklenen araçlar listesi
    supported_tools = {"ping", "whois", "nmap", "nikto", "gobuster", "zap", "testssl", "dnsrecon", "theharvester", "subfinder"}
    
    # Seçili araçlar (boş ise tümü seçili)
    selected_tools = payload.tools or ["ping", "whois", "nmap", "nikto", "gobuster", "zap", "testssl", "dnsrecon", "theharvester", "subfinder"]

    # Desteklenmeyen araçları kontrol et
    unsupported = [t for t in selected_tools if t not in supported_tools]
    if unsupported:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Desteklenmeyen araç(lar): {', '.join(unsupported)}",
        )

    # Çıktı dizini (varsayılan: ortam değişkeni veya /app/data)
    output_dir = payload.output_dir or os.getenv("OUTPUT_DIR", "/app/data")

    # Hedef URL'yi normalize et: şema yoksa http ekle
    # Böylece urlparse ile host bilgisi çıkarılabilir
    raw_target = payload.target_url.strip()
    if not raw_target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Hedef alanı boş olamaz.",
        )

    normalized_target = raw_target
    if not raw_target.startswith(("http://", "https://")):
        normalized_target = f"http://{raw_target}"

    # URL'den host, port, şema ve path bilgilerini çıkar
    parsed = urlparse(normalized_target)
    target_host = parsed.hostname
    if not target_host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Geçerli bir hedef host çözümlenemedi.",
        )
    
    # Port bilgisi (varsayılan: HTTPS için 443, HTTP için 80)
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    # SSL kullanımı (HTTPS şeması veya 443 portu)
    use_ssl = parsed.scheme == "https" or target_port == 443
    
    # Root path (varsayılan: /)
    root_path = parsed.path if parsed.path else "/"
    
    # Şema (varsayılan: http)
    scheme = parsed.scheme or "http"

    ping_result = None
    whois_result = None
    nmap_result = None
    nikto_result = None
    gobuster_result = None
    zap_result = None
    testssl_result = None
    dnsrecon_result = None
    theharvester_result = None
    subfinder_result = None

    if "ping" in selected_tools:
        try:
            ping_result = ping.run_ping(target_host, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "whois" in selected_tools:
        try:
            whois_result = whois.run_whois(target_host, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "nmap" in selected_tools:
        try:
            nmap_result = nmap.run_nmap(target_host, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "nikto" in selected_tools:
        try:
            nikto_result = nikto.run_nikto(
                target_host=target_host,
                output_dir=output_dir,
                port=target_port,
                use_ssl=use_ssl,
                root_path=root_path,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "gobuster" in selected_tools:
        try:
            gobuster_target = gobuster.build_target_url(scheme, target_host, target_port, root_path)
            gobuster_result = gobuster.run_gobuster(gobuster_target, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "zap" in selected_tools:
        try:
            zap_result = zap.run_zap_quick(normalized_target, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "testssl" in selected_tools:
        try:
            testssl_result = testssl.run_testssl(target_host, target_port, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "dnsrecon" in selected_tools:
        try:
            dnsrecon_result = dnsrecon.run_dnsrecon(target_host, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "theharvester" in selected_tools:
        try:
            theharvester_result = theharvester.run_theharvester(target_host, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    if "subfinder" in selected_tools:
        try:
            # Subfinder domain bekler, IP adresi değil
            # IP adresi kontrolü yap
            ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            if ip_pattern.match(target_host):
                # IP adresi ise subfinder çalıştırma
                raise RuntimeError(f"Subfinder domain bekler, IP adresi kabul etmez: {target_host}")
            # Domain olarak kullan
            subfinder_result = subfinder.run_subfinder(target_host, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    scan_plan = ScanPlan(
        target_url=normalized_target,
        tools=selected_tools,
        output_dir=output_dir,
        commands=[],
        ping_result=ping_result,
        whois_result=whois_result,
        nmap_result=nmap_result,
        nikto_result=nikto_result,
        gobuster_result=gobuster_result,
        zap_result=zap_result,
        testssl_result=testssl_result,
        dnsrecon_result=dnsrecon_result,
        theharvester_result=theharvester_result,
        subfinder_result=subfinder_result,
        note="Seçilen araçlar başarıyla çalıştırıldı.",
    )
    
    # AI analizi yap (otomatik)
    try:
        print(f"[INFO] AI analizi başlatılıyor... Hedef: {scan_plan.target_url}")
        analysis_result = analyze_scan_results(scan_plan)
        print(f"[INFO] AI analizi tamamlandı. Risk seviyesi: {analysis_result.overall_risk_level}")
        print(f"[INFO] Tool analizleri sayısı: {len(analysis_result.tool_analyses)}")
        print(f"[INFO] Öneriler sayısı: {len(analysis_result.recommendations)}")
        
        # Analiz sonucunu scan_plan'a ekle
        scan_plan.ai_analysis = analysis_result.model_dump()
        if analysis_result.analysis_summary:
            scan_plan.note = f"{scan_plan.note} AI Analiz: {analysis_result.overall_risk_level.upper()} risk seviyesi tespit edildi."
        
        print(f"[SUCCESS] AI analiz sonucu scan_plan'a eklendi.")
    except Exception as e:
        # Analiz başarısız olursa detaylı log ve devam et
        import traceback
        error_trace = traceback.format_exc()
        print(f"[ERROR] AI analizi başarısız: {e}")
        print(f"[ERROR] Hata detayı:\n{error_trace}")
        scan_plan.ai_analysis = None
        scan_plan.note = f"{scan_plan.note} AI Analiz hatası: {str(e)}"
    
    return scan_plan


@router.post("/analyze", response_model=AnalysisResult, status_code=status.HTTP_200_OK)
async def analyze_scan(payload: ScanPlan) -> AnalysisResult:
    """
    Tarama sonuçlarını Gemini AI ile analiz eder ve güvenlik önerileri sunar.
    
    Args:
        payload: Tarama planı (tüm araç sonuçları)
        
    Returns:
        AnalysisResult: AI analiz sonuçları, risk seviyesi tablosu ve öneriler
        
    Raises:
        HTTPException: Analiz başarısız olduğunda
    """
    try:
        analysis_result = analyze_scan_results(payload)
        return analysis_result
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analiz sırasında beklenmeyen hata: {str(exc)}",
        ) from exc


