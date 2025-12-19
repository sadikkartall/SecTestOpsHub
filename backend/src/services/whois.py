import os
import subprocess
from uuid import uuid4

from ..models.scan import WhoisResult


def run_whois(target_host: str, output_dir: str) -> WhoisResult:
    """
    Hedef domain/host için whois sorgusu çalıştırır, çıktıyı dosyaya yazar ve sonucu döner.
    Tüm yorumlar Türkçe tutulmuştur.
    """
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(output_dir, f"whois-{uuid4()}.txt")

    # Whois komutu; gerekirse timeout için `timeout` eklenebilir (altta subprocess timeout kullanıyoruz)
    cmd = ["whois", target_host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,  # Whois sunucusu yanıt vermezse beklemeyi sınırla
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Whois sorgusu zaman aşımına uğradı.")

    # Çıktıyı dosyaya yaz
    with open(output_file, "w", encoding="utf-8", errors="ignore") as f:
        f.write(proc.stdout or "")
        if proc.stderr:
            f.write("\n--- STDERR ---\n")
            f.write(proc.stderr)

    # Temel başarı kriteri: returncode 0
    success = proc.returncode == 0
    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    return WhoisResult(
        raw_output=raw_output,
        output_file=output_file,
        success=success,
    )


