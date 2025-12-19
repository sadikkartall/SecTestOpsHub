import os
import subprocess
from uuid import uuid4

from ..models.scan import NmapResult


def run_nmap(target_host: str, output_dir: str) -> NmapResult:
    """
    Hedef host/IP için Nmap taraması çalıştırır.
    Varsayılan profil: -Pn -sS -sV -sC -O -T4 --top-ports 1000 (XML çıktı).
    Not: SYN/OS tespiti için konteynerde NET_RAW/NET_ADMIN yetkisi verilmiştir.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_xml = os.path.join(output_dir, f"nmap-{scan_id}.xml")
    output_txt = os.path.join(output_dir, f"nmap-{scan_id}.txt")

    cmd = [
        "nmap",
        "-Pn",
        "-sS",
        "-sV",
        "-sC",
        "-O",
        "-T4",
        "--top-ports",
        "1000",
        "-oX",
        output_xml,
        "-oN",
        output_txt,
        target_host,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,  # 5 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Nmap taraması zaman aşımına uğradı.")

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    return NmapResult(
        raw_output=raw_output,
        output_file_xml=output_xml,
        output_file_txt=output_txt,
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )


