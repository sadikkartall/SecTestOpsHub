import os
import subprocess
import json
import shutil
from uuid import uuid4

from ..models.scan import TheHarvesterResult


def run_theharvester(target_domain: str, output_dir: str) -> TheHarvesterResult:
    """
    Hedef domain için theHarvester OSINT taraması çalıştırır.
    theHarvester domain bekler, IP adresi değil.
    JSON çıktı -f parametresi ile üretilir.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_json = os.path.join(output_dir, f"theharvester-{scan_id}.json")
    output_txt = os.path.join(output_dir, f"theharvester-{scan_id}.txt")

    # theHarvester'ı Python modülü olarak çalıştır (daha güvenilir)
    theharvester_script = "/opt/theHarvester/theHarvester.py"
    if os.path.exists(theharvester_script):
        # Python ile direkt script'i çalıştır
        cmd = [
            "python",
            theharvester_script,
            "-d",
            target_domain,
            "-b",
            "all",  # Tüm kaynakları kullan (google, bing, shodan, vb.)
            "-f",
            output_json,  # JSON çıktı dosyası
        ]
    else:
        raise RuntimeError("theHarvester bulunamadı. Kurulum kontrol edilmeli.")

    try:
        # theHarvester uzun sürebilir (tüm kaynakları tarar), 10 dakika timeout
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,  # 10 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("theHarvester taraması zaman aşımına uğradı.")

    raw_output = (proc.stdout or "").strip()
    if proc.stderr:
        stderr_output = proc.stderr.strip()
        if stderr_output:
            # stderr'ı da raw_output'a ekle (bilgilendirme mesajları için)
            raw_output = f"{raw_output}\n{stderr_output}" if raw_output else stderr_output

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

    return TheHarvesterResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        success=success,
        command=" ".join(cmd),
    )
