import os
import subprocess
import json
import re
from uuid import uuid4

from ..models.scan import GobusterResult, GobusterFinding, GobusterFindingsSummary

# Varsayılan wordlist (küçük liste; gerekirse fallback ile orta liste)
DEFAULT_WORDLIST_PRIMARY = "/usr/share/seclists/Discovery/Web-Content/common.txt"
DEFAULT_WORDLIST_FALLBACK = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"

# Varsayılan uzantılar
DEFAULT_EXTENSIONS = ["php", "html", "txt", "js", "bak"]

# Varsayılan durum kodu süzgeci: 200/204/301/302/307/401/403'ü kabul, 404'ü filtrele
DEFAULT_STATUS_CODES = "200,204,301,302,307,401,403"
DEFAULT_BLACKLIST_CODES = "404"

# Hız/kaynak dengelemesi
DEFAULT_THREADS = 20          # Eşzamanlı thread sayısı
DEFAULT_TIMEOUT = 10           # İstek timeout (saniye)


def build_target_url(scheme: str, host: str, port: int, root_path: str) -> str:
    """
    Gobuster için hedef URL'yi üretir.
    Örn: http://example.com:80/path
    """
    base = f"{scheme}://{host}"
    if port not in {80, 443}:
        base = f"{base}:{port}"
    # root_path'i ekle
    if not root_path.startswith("/"):
        root_path = "/" + root_path
    return f"{base}{root_path}"


def run_gobuster(
    target_url: str,
    output_dir: str,
    wordlist: str = None,
    extensions: list = None,
    threads: int = DEFAULT_THREADS,
) -> GobusterResult:
    """
    Gobuster directory enumeration çalıştırır; JSON çıktısı döner.
    """
    os.makedirs(output_dir, exist_ok=True)
    extensions = extensions or DEFAULT_EXTENSIONS

    # Wordlist seçiminde fallback mantığı
    resolved_wordlist = (
        wordlist
        or (DEFAULT_WORDLIST_PRIMARY if os.path.exists(DEFAULT_WORDLIST_PRIMARY) else DEFAULT_WORDLIST_FALLBACK)
    )

    scan_id = uuid4()
    output_txt = os.path.join(output_dir, f"gobuster-{scan_id}.txt")
    output_json = os.path.join(output_dir, f"gobuster-{scan_id}.json")

    # Gobuster komutu: -s ile status codes belirtirken varsayılan blacklist'i devre dışı bırakmak için -b "" kullanılır
    cmd = [
        "gobuster",
        "dir",
        "-u",
        target_url,
        "-w",
        resolved_wordlist,
        "-t",
        str(threads),
        "-k",  # SSL sertifika doğrulamasını atla
        "--timeout",
        f"{DEFAULT_TIMEOUT}s",
        "-b",  # Önce blacklist'i devre dışı bırak (boş string)
        "",
        "-s",  # Sonra status codes'u belirt
        DEFAULT_STATUS_CODES,
        "-o",
        output_txt,
    ]

    # Extensions varsa ekle
    if extensions:
        cmd.extend(["-x", ",".join(extensions)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=900,  # 15 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Gobuster taraması zaman aşımına uğradı.")

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    # Gobuster text çıktısını JSON'a çevir
    json_data = parse_gobuster_output(raw_output, target_url)
    
    # JSON dosyasına yaz
    if json_data:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

    # JSON dosyasını okuyup findings'e çevir
    findings = None
    findings_summary = None
    if os.path.exists(output_json):
        try:
            findings, findings_summary = parse_gobuster_json(output_json)
        except Exception:
            # Parse hatasını taramayı "crash" ettirmeyelim
            findings = None
            findings_summary = None

    return GobusterResult(
        raw_output=raw_output,
        output_file_json=output_json,
        findings=findings,
        findings_summary=findings_summary,
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )


def parse_gobuster_output(raw_output: str, base_url: str) -> dict:
    """
    Gobuster'ın text çıktısını parse edip JSON formatına çevirir.
    Gobuster çıktı formatı: /path (Status: 200) [Size: 1234] [--> redirect_url]
    ANSI escape kodlarını da temizler.
    """
    results = []
    
    # ANSI escape kodlarını temizle (örn: [2K, ESC karakterleri)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\[2K')
    cleaned_output = ansi_escape.sub('', raw_output)
    
    # Gobuster çıktı satırlarını parse et
    # Format: /path (Status: 200) [Size: 1234] [--> redirect_url] (opsiyonel)
    pattern = r'^(\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\](?:\s+\[-->\s+([^\]]+)\])?'
    
    for line in cleaned_output.split('\n'):
        line = line.strip()
        # Boş satırları, header'ları ve separator'ları atla
        if not line or line.startswith('=') or line.startswith('Gobuster') or line.startswith('[+]') or line.startswith('Starting') or line.startswith('Finished'):
            continue
        
        match = re.match(pattern, line)
        if match:
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3))
            redirect = match.group(4)  # Redirect URL (opsiyonel)
            
            # Tam URL'yi oluştur
            if path.startswith('/'):
                full_url = f"{base_url.rstrip('/')}{path}"
            else:
                full_url = f"{base_url.rstrip('/')}/{path}"
            
            result_item = {
                "url": full_url,
                "status": status,
                "length": size,
            }
            
            # Redirect varsa ekle
            if redirect:
                result_item["redirect_location"] = redirect.strip()
            
            results.append(result_item)
    
    return {
        "commandline": "gobuster dir",
        "target": base_url,
        "results": results,
        "total": len(results)
    }


def parse_gobuster_json(output_file_json: str) -> tuple[list[GobusterFinding], GobusterFindingsSummary]:
    """
    Gobuster JSON çıktısını bulgu listesine çevirir.
    """
    with open(output_file_json, "r", encoding="utf-8", errors="ignore") as f:
        payload = json.load(f)

    results = payload.get("results") or []
    findings: list[GobusterFinding] = []
    by_status: dict[int, int] = {}

    for item in results:
        status = int(item.get("status", 0) or 0)
        by_status[status] = by_status.get(status, 0) + 1

        findings.append(
            GobusterFinding(
                url=str(item.get("url", "")),
                status=status,
                length=int(item.get("length", 0) or 0),
                redirect_location=item.get("redirect_location") or None,
            )
        )

    summary = GobusterFindingsSummary(total=len(findings), by_status=by_status)
    return findings, summary
