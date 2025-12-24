import os
import subprocess
import json
import re
from datetime import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any

from ..models.scan import GobusterResult, GobusterFinding, GobusterFindingsSummary
from ..models.normalized import NormalizedResult, Finding

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

    start_time = datetime.now()
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
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

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

    # Normalize edilmiş sonuç oluştur
    normalized_result = normalize_gobuster(
        raw_stdout=proc.stdout or "",
        raw_stderr=proc.stderr or "",
        exit_code=proc.returncode,
        target=target_url,
        command=" ".join(cmd),
        json_file_path=output_json,
        findings=findings,
        findings_summary=findings_summary,
        duration_ms=duration_ms
    )
    
    output_normalized_json = os.path.join(output_dir, f"gobuster-{scan_id}-normalized.json")
    with open(output_normalized_json, "w", encoding="utf-8") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    return GobusterResult(
        raw_output=raw_output,
        output_file_json=output_json,
        findings=findings,
        findings_summary=findings_summary,
        normalized_json=normalized_result.model_dump(),
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


def normalize_gobuster(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    json_file_path: Optional[str] = None,
    findings: Optional[List[GobusterFinding]] = None,
    findings_summary: Optional[GobusterFindingsSummary] = None,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize gobuster output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    
    metrics = {
        "target_url": target,
        "method": "GET",
        "threads": None,
        "wordlist": None,
        "extensions": [],
        "status_codes": [],
        "total_findings": 0,
        "status_distribution": {},
        "findings_by_status": {},
        "duration_ms": duration_ms
    }
    
    findings_list = []
    status = "partial"
    summary = f"Gobuster scan for {target} completed with partial parsing."
    
    # Parse command line for metadata
    if "gobuster" in command.lower():
        threads_match = re.search(r'-t\s+(\d+)', command)
        if threads_match:
            metrics["threads"] = int(threads_match.group(1))
        
        wordlist_match = re.search(r'-w\s+([^\s]+)', command)
        if wordlist_match:
            metrics["wordlist"] = wordlist_match.group(1)
        
        extensions_match = re.search(r'-x\s+([^\s]+)', command)
        if extensions_match:
            metrics["extensions"] = extensions_match.group(1).split(',')
    
    # Parse raw output for additional metadata
    lines = output.split('\n')
    for line in lines:
        if "[+] Url:" in line:
            url_match = re.search(r'Url:\s+(.+)', line)
            if url_match:
                metrics["target_url"] = url_match.group(1).strip()
        elif "[+] Method:" in line:
            method_match = re.search(r'Method:\s+(\w+)', line)
            if method_match:
                metrics["method"] = method_match.group(1)
        elif "[+] Threads:" in line:
            threads_match = re.search(r'Threads:\s+(\d+)', line)
            if threads_match:
                metrics["threads"] = int(threads_match.group(1))
        elif "[+] Wordlist:" in line:
            wordlist_match = re.search(r'Wordlist:\s+(.+)', line)
            if wordlist_match:
                metrics["wordlist"] = wordlist_match.group(1).strip()
        elif "[+] Status codes:" in line:
            status_match = re.search(r'Status codes:\s+(.+)', line)
            if status_match:
                codes_str = status_match.group(1).strip()
                metrics["status_codes"] = [int(c.strip()) for c in codes_str.split(',') if c.strip().isdigit()]
        elif "[+] Extensions:" in line:
            ext_match = re.search(r'Extensions:\s+(.+)', line)
            if ext_match:
                metrics["extensions"] = [e.strip() for e in ext_match.group(1).split(',')]
    
    # Use findings from JSON if available
    if findings and findings_summary:
        metrics["total_findings"] = findings_summary.total
        metrics["status_distribution"] = {str(k): v for k, v in findings_summary.by_status.items()}
        
        # Group findings by status
        findings_by_status = {}
        for finding in findings:
            status_key = str(finding.status)
            if status_key not in findings_by_status:
                findings_by_status[status_key] = []
            findings_by_status[status_key].append({
                "url": finding.url,
                "status": finding.status,
                "length": finding.length,
                "redirect_location": finding.redirect_location
            })
        metrics["findings_by_status"] = findings_by_status
        
        # Create findings with severity based on status code
        for finding in findings:
            severity = "INFO"
            if finding.status == 200:
                severity = "MEDIUM"  # Erişilebilir dosyalar/dizinler
            elif finding.status in [301, 302, 307]:
                severity = "LOW"  # Redirect'ler
            elif finding.status == 401:
                severity = "LOW"  # Authentication gerektiren
            elif finding.status == 403:
                severity = "INFO"  # Forbidden - hassas dosya varlığı
            elif finding.status in [204, 307]:
                severity = "INFO"
            
            findings_list.append(Finding(
                type="directory_enumeration",
                severity=severity,
                title=f"Path found: {finding.url} (Status: {finding.status})",
                evidence={
                    "url": finding.url,
                    "status": finding.status,
                    "length": finding.length,
                    "redirect_location": finding.redirect_location
                }
            ))
    else:
        # Fallback: Parse from raw output
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\[2K')
        cleaned_output = ansi_escape.sub('', output)
        
        pattern = r'^(\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\](?:\s+\[-->\s+([^\]]+)\])?'
        status_counts = {}
        
        for line in cleaned_output.split('\n'):
            line = line.strip()
            if not line or line.startswith('=') or line.startswith('Gobuster') or line.startswith('[+]') or line.startswith('Starting') or line.startswith('Finished'):
                continue
            
            match = re.match(pattern, line)
            if match:
                path = match.group(1)
                status = int(match.group(2))
                size = int(match.group(3))
                redirect = match.group(4)
                
                status_key = str(status)
                status_counts[status_key] = status_counts.get(status_key, 0) + 1
                
                if path.startswith('/'):
                    full_url = f"{target.rstrip('/')}{path}"
                else:
                    full_url = f"{target.rstrip('/')}/{path}"
                
                severity = "INFO"
                if status == 200:
                    severity = "MEDIUM"
                elif status in [301, 302, 307]:
                    severity = "LOW"
                elif status == 401:
                    severity = "LOW"
                elif status == 403:
                    severity = "INFO"
                
                findings_list.append(Finding(
                    type="directory_enumeration",
                    severity=severity,
                    title=f"Path found: {full_url} (Status: {status})",
                    evidence={
                        "url": full_url,
                        "status": status,
                        "length": size,
                        "redirect_location": redirect.strip() if redirect else None
                    }
                ))
        
        metrics["total_findings"] = len(findings_list)
        metrics["status_distribution"] = status_counts
    
    # Determine status
    if metrics["total_findings"] > 0:
        status = "success"
        status_200_count = metrics["status_distribution"].get("200", 0)
        status_301_count = metrics["status_distribution"].get("301", 0) + metrics["status_distribution"].get("302", 0)
        if status_200_count > 0:
            summary = f"Gobuster scan found {metrics['total_findings']} paths, including {status_200_count} accessible (200) path(s)."
        elif status_301_count > 0:
            summary = f"Gobuster scan found {metrics['total_findings']} paths, including {status_301_count} redirect(s)."
        else:
            summary = f"Gobuster scan found {metrics['total_findings']} paths."
    else:
        status = "success"
        summary = f"Gobuster scan completed for {target} with no findings."
    
    return NormalizedResult(
        tool="gobuster",
        target=target,
        status=status,
        summary=summary,
        findings=findings_list,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )
