import os
import subprocess
from uuid import uuid4

from ..models.scan import NiktoResult


def run_nikto(target_host: str, output_dir: str, port: int, use_ssl: bool, root_path: str) -> NiktoResult:
    """
    Hedef host için Nikto taraması çalıştırır.
    Varsayılan profil: JSON çıktı + ayrıntılı display; etkileşim kapalı.
    SSL ve port, gelen URL bilgisinden türetilir; path varsa -root ile eklenir.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_json = os.path.join(output_dir, f"nikto-{scan_id}.json")
    output_txt = os.path.join(output_dir, f"nikto-{scan_id}.txt")

    cmd = [
        "nikto",
        "-h",
        target_host,
        "-p",
        str(port),
        "-output",
        output_json,
        "-Format",
        "json",
        "-ask",
        "no",
        "-Display",
        "V",
        "-useragent",
        "Nikto/2.5.0 (SecTestOpsHub)",
        "-timeout",
        "10",
    ]

    # HTTPS ya da 443 için SSL bayrağı
    if use_ssl:
        cmd.append("-ssl")

    # Path bilgisi varsa kök olarak ekleyelim
    if root_path and root_path != "/":
        cmd.extend(["-root", root_path])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=900,  # 15 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Nikto taraması zaman aşımına uğradı.")

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    return NiktoResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )


