import os
import subprocess
import json
from uuid import uuid4

from ..models.scan import DnsreconResult


def run_dnsrecon(target_domain: str, output_dir: str) -> DnsreconResult:
    """
    Hedef domain için dnsrecon DNS enumeration çalıştırır.
    dnsrecon domain bekler, IP adresi değil.
    JSON çıktı -j parametresi ile üretilir.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_json = os.path.join(output_dir, f"dnsrecon-{scan_id}.json")
    output_txt = os.path.join(output_dir, f"dnsrecon-{scan_id}.txt")

    # dnsrecon komutu: -d domain, -j JSON çıktı
    # -t std: Standart DNS kayıtları (A, AAAA, MX, NS, TXT, SOA)
    # --lifetime: DNS sorgu timeout'u (saniye), çok yavaş DNS sunucuları için yüksek değer
    # Not: -n parametresi kaldırıldı, varsayılan DNS sunucuları kullanılacak
    cmd = [
        "dnsrecon",
        "-d",
        target_domain,
        "-j",
        output_json,
        "-t",
        "std",  # Standart DNS kayıtları
        "--lifetime",
        "120",  # DNS sorgu timeout'u 120 saniye (çok yavaş sunucular için)
    ]

    try:
        # dnsrecon uzun sürebilir, 10 dakika timeout (--lifetime 120 için yeterli)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,  # 10 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("dnsrecon taraması zaman aşımına uğradı.")

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

    # JSON dosyası varsa ve içinde veri varsa, kısmi başarı sayılabilir
    # Ama dnsrecon genellikle timeout olsa bile JSON üretmez, bu yüzden returncode'a bakıyoruz
    success = proc.returncode == 0
    
    # Eğer JSON dosyası varsa ve içinde veri varsa, kısmi başarı olarak kabul et
    if not success and os.path.exists(output_json):
        try:
            with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                json_data = json.load(f)
                # JSON'da veri varsa kısmi başarı
                if json_data and len(json_data) > 0:
                    success = True
        except Exception:
            pass  # JSON parse hatası varsa success=False kalır

    return DnsreconResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        success=success,
        command=" ".join(cmd),
    )
