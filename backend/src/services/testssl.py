import os
import subprocess
from uuid import uuid4

from ..models.scan import TestsslResult


def run_testssl(target_host: str, target_port: int, output_dir: str) -> TestsslResult:
    """
    Hedef host:port için testssl.sh SSL/TLS taraması çalıştırır.
    testssl.sh format: domain:port veya IP:port
    JSON çıktı --jsonfile parametresi ile üretilir.
    
    Not: testssl.sh SSL/TLS test aracıdır, bu yüzden:
    - Port 80 ise otomatik olarak 443'e geçer (HTTPS)
    - Diğer portlar olduğu gibi kullanılır (örn: 8443, 8080)
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_json = os.path.join(output_dir, f"testssl-{scan_id}.json")
    output_txt = os.path.join(output_dir, f"testssl-{scan_id}.txt")

    # testssl.sh SSL/TLS test aracıdır, port 80 ise otomatik olarak 443'e geç
    # Çünkü port 80 HTTP için, SSL/TLS testi için port 443 (HTTPS) gerekli
    actual_port = target_port
    if target_port == 80:
        actual_port = 443

    # testssl.sh hedef formatı: host:port
    target = f"{target_host}:{actual_port}"

    # testssl.sh script yolu
    testssl_script = "/opt/testssl.sh/testssl.sh"
    if not os.path.exists(testssl_script):
        # Alternatif yol kontrolü
        testssl_script = "/usr/local/bin/testssl.sh"

    cmd = [
        "bash",
        testssl_script,
        "--jsonfile",
        output_json,
        "--quiet",  # Sadece önemli çıktıları göster
        "--warnings",
        "off",  # Etkileşimli uyarıları devre dışı bırak
        "--socket-timeout",
        "10",  # TCP socket bağlantı timeout'u (saniye)
        "--openssl-timeout",
        "10",  # OpenSSL bağlantı timeout'u (saniye)
        target,
    ]

    try:
        # testssl.sh uzun sürebilir, 10 dakika timeout
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,  # 10 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("testssl.sh taraması zaman aşımına uğradı.")

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    # JSON çıktısını txt dosyasına da kopyala (okunabilirlik için)
    if os.path.exists(output_json):
        try:
            with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                json_content = f.read()
            with open(output_txt, "w", encoding="utf-8") as f:
                f.write(json_content)
        except Exception:
            pass  # Hata durumunda devam et

    return TestsslResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )
