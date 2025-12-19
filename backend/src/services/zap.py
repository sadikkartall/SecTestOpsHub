import os
import subprocess
import shutil
from uuid import uuid4

from ..models.scan import ZapResult

ZAP_CONTAINER = "sectestops-zap"
ZAP_WORKDIR = "/zap/wrk"


def run_zap_quick(target_url: str, output_dir: str) -> ZapResult:
    """
    ZAP hızlı tarama (quick scan) çalıştırır ve HTML çıktı üretir.
    Backend içinden docker exec ile ZAP konteynerine komut gönderilir.
    """
    docker_bin = shutil.which("docker")
    if not docker_bin:
        raise RuntimeError("Docker CLI bulunamadı. Backend imajında docker.io kurulmalı ve /var/run/docker.sock mount edilmeli.")

    os.makedirs(output_dir, exist_ok=True)

    # Host tarafında rapor yolu
    host_output_file = os.path.join(output_dir, f"zap-{uuid4()}.html")
    # ZAP konteynerinin göreceği yol
    zap_output_file = os.path.join(ZAP_WORKDIR, os.path.basename(host_output_file))

    cmd = [
        docker_bin,
        "exec",
        ZAP_CONTAINER,
        "zap.sh",
        "-cmd",
        "-quickurl",
        target_url,
        "-quickout",
        zap_output_file,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=900,  # 15 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("ZAP hızlı tarama zaman aşımına uğradı.")

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    return ZapResult(
        raw_output=raw_output,
        output_file=host_output_file,
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )


