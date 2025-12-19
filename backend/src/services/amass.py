import os
import subprocess
import json
from uuid import uuid4

from ..models.scan import AmassResult


def run_amass(target_domain: str, output_dir: str) -> AmassResult:
    """
    Hedef domain için amass subdomain enumeration çalıştırır.
    amass domain bekler, IP adresi değil.
    JSON çıktı -o parametresi ile üretilir.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_json = os.path.join(output_dir, f"amass-{scan_id}.json")
    output_txt = os.path.join(output_dir, f"amass-{scan_id}.txt")

    # amass komutu: -d domain, -o JSON çıktı
    # -passive: Pasif mod (daha hızlı, sadece pasif kaynaklar)
    # Progress bar'ları filtreleme ile temizleyeceğiz
    cmd = [
        "amass",
        "enum",
        "-d",
        target_domain,
        "-passive",  # Pasif mod (daha hızlı)
        "-o",
        output_json,  # JSON çıktı dosyası
    ]

    try:
        # amass uzun sürebilir, 10 dakika timeout
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,  # 10 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("amass taraması zaman aşımına uğradı.")

    # Progress bar'ları filtrele (satır başında [X / Y] formatındaki satırları kaldır)
    raw_output = (proc.stdout or "").strip()
    
    # stderr'den de progress bar'ları temizle
    if proc.stderr:
        stderr_output = proc.stderr.strip()
        # Progress bar satırlarını filtrele: [X / Y] formatı veya p/s içeren satırlar
        stderr_lines = []
        for line in stderr_output.split('\n'):
            line_stripped = line.strip()
            # Progress bar formatını tespit et: [X / Y] veya p/s içeren satırlar
            if not (line_stripped.startswith('[') and '/' in line_stripped and ']' in line_stripped and ('%' in line_stripped or 'p/s' in line_stripped)):
                stderr_lines.append(line)
        stderr_clean = '\n'.join(stderr_lines).strip()
        if stderr_clean:
            raw_output = f"{raw_output}\n{stderr_clean}" if raw_output else stderr_clean
    
    # Eğer hala progress bar içeriyorsa, temizle
    if raw_output:
        lines = raw_output.split('\n')
        cleaned_lines = []
        for line in lines:
            line_stripped = line.strip()
            # Progress bar formatını filtrele
            if not (line_stripped.startswith('[') and '/' in line_stripped and ']' in line_stripped and ('%' in line_stripped or 'p/s' in line_stripped)):
                cleaned_lines.append(line)
        raw_output = '\n'.join(cleaned_lines).strip()

    # JSON çıktısını txt dosyasına da kopyala (okunabilirlik için)
    if os.path.exists(output_json):
        try:
            with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                json_content = f.read()
            with open(output_txt, "w", encoding="utf-8") as f:
                f.write(json_content)
            
            # JSON dosyasından özet bilgi çıkar ve raw_output'a ekle
            try:
                lines = json_content.strip().split('\n')
                valid_json_lines = [line for line in lines if line.strip() and line.strip().startswith('{')]
                if valid_json_lines:
                    subdomains = set()
                    for line in valid_json_lines:
                        try:
                            data = json.loads(line)
                            if 'name' in data:
                                subdomains.add(data['name'])
                        except:
                            pass
                    if subdomains:
                        summary = f"Amass taraması tamamlandı. {len(subdomains)} subdomain bulundu:\n" + "\n".join(sorted(subdomains)[:20])
                        if len(subdomains) > 20:
                            summary += f"\n... ve {len(subdomains) - 20} subdomain daha (JSON dosyasına bakın)"
                        raw_output = summary if not raw_output else f"{raw_output}\n\n{summary}"
            except:
                pass
        except Exception:
            pass  # Hata durumunda devam et

    # JSON dosyası varsa ve içinde veri varsa, kısmi başarı sayılabilir
    success = proc.returncode == 0
    
    # Eğer JSON dosyası varsa ve içinde veri varsa, kısmi başarı olarak kabul et
    if not success and os.path.exists(output_json):
        try:
            # Amass JSON dosyası satır satır JSON objeleri içerir (JSONL format)
            with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                # En az bir geçerli JSON satırı varsa başarılı say
                if lines and len(lines) > 0:
                    success = True
        except Exception:
            pass  # JSON parse hatası varsa success=False kalır

    return AmassResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        success=success,
        command=" ".join(cmd),
    )
