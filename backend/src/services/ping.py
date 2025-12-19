import os
import socket
import subprocess
from uuid import uuid4

from ..models.scan import PingResult


def run_ping(target_host: str, output_dir: str) -> PingResult:
    """
    Hedef hostname/IP için ping çalıştırır, çıktıyı dosyaya yazar ve IP bilgisini döner.
    Tüm yorumlar Türkçe tutulmuştur.
    """
    os.makedirs(output_dir, exist_ok=True)

    # IP çözümleme
    try:
        resolved_ip = socket.gethostbyname(target_host)
    except socket.gaierror as exc:
        raise RuntimeError(f"Hedef çözümlenemedi: {exc}") from exc

    # Çıktı dosyası yolu
    output_file = os.path.join(output_dir, f"ping-{uuid4()}.txt")

    # Linux tabanlı imajda ping komutu -c ile sayım belirtiyor
    cmd = ["ping", "-c", "4", target_host]

    # Ping komutunu çalıştır ve stdout/stderr yakala
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    # Çıktıyı dosyaya yaz
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(proc.stdout)
        if proc.stderr:
            f.write("\n--- STDERR ---\n")
            f.write(proc.stderr)

    # Başarısız ping durumunda da IP bilgisini ve dosya yolunu döneriz; üst katman mesaj üretebilir
    return PingResult(
        ip_address=resolved_ip,
        output_file=output_file,
        raw_output=proc.stdout.strip() or proc.stderr.strip(),
        success=proc.returncode == 0,
    )


