import os
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, status

from ..models.scan import ScanRequest, ScanPlan
from ..services import ping, whois, nmap, nikto, gobuster, zap, testssl, dnsrecon, theharvester, amass

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/", response_model=ScanPlan, status_code=status.HTTP_201_CREATED)
async def create_scan_plan(payload: ScanRequest) -> ScanPlan:
    """
    Tarama talebini alır, ilk adım olarak hedefe ping atar ve IP bilgisini dosyaya kaydeder.
    Araçlar adım adım eklenecek; ping başlangıç doğrulama adımıdır.
    """
    supported_tools = {"ping", "whois", "nmap", "nikto", "gobuster", "zap", "testssl", "dnsrecon", "theharvester", "amass"}
    selected_tools = payload.tools or ["ping", "whois", "nmap", "nikto", "gobuster", "zap", "testssl", "dnsrecon", "theharvester", "amass"]

    unsupported = [t for t in selected_tools if t not in supported_tools]
    if unsupported:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Desteklenmeyen araç(lar): {', '.join(unsupported)}",
        )

    output_dir = payload.output_dir or os.getenv("OUTPUT_DIR", "/app/data")

    # Hedefi normalize et: şema yoksa http ekle, böylece urlparse ile host alınabilir
    raw_target = payload.target_url.strip()
    if not raw_target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Hedef alanı boş olamaz.",
        )

    normalized_target = raw_target
    if not raw_target.startswith(("http://", "https://")):
        normalized_target = f"http://{raw_target}"

    # URL'den host bilgisini çıkar
    parsed = urlparse(normalized_target)
    target_host = parsed.hostname
    if not target_host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Geçerli bir hedef host çözümlenemedi.",
        )
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https" or target_port == 443
    root_path = parsed.path if parsed.path else "/"
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
    amass_result = None

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

    if "amass" in selected_tools:
        try:
            amass_result = amass.run_amass(target_host, output_dir)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    return ScanPlan(
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
        amass_result=amass_result,
        note="Seçilen araçlar çalıştırıldı; diğer araçlar ilerleyen aşamalarda eklenecek.",
    )


