import os
import subprocess
import json
import re
import shutil
from datetime import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any

from ..models.scan import TheHarvesterResult
from ..models.normalized import NormalizedResult, Finding


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

    start_time = datetime.now()
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
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

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

    normalized_result = normalize_theharvester(
        raw_stdout=proc.stdout or "",
        raw_stderr=proc.stderr or "",
        exit_code=proc.returncode,
        target=target_domain,
        command=" ".join(cmd),
        json_file_path=output_json,
        duration_ms=duration_ms
    )
    
    output_normalized_json = os.path.join(output_dir, f"theharvester-{scan_id}-normalized.json")
    with open(output_normalized_json, "w", encoding="utf-8") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    return TheHarvesterResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        normalized_json=normalized_result.model_dump(),
        success=success,
        command=" ".join(cmd),
    )


def normalize_theharvester(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    json_file_path: Optional[str] = None,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize theHarvester output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    combined_output = output + "\n" + error_output if error_output else output
    
    metrics = {
        "target": target,
        "sources_attempted": 0,
        "sources_successful": [],
        "sources_failed": [],
        "sources_missing_api_key": [],
        "sources_errors": [],
        "sources_results": {},  # Her kaynaktan bulunan sonuçlar
        "results": {
            "emails": [],
            "hosts": [],
            "subdomains": [],
            "ips": [],
            "urls": []
        },
        "total_results": 0,
        "duration_ms": duration_ms
    }
    
    findings = []
    status = "partial"
    summary = f"theHarvester scan for {target} completed with partial parsing."
    
    # Try to parse JSON first (more reliable)
    if json_file_path and os.path.exists(json_file_path):
        try:
            with open(json_file_path, "r", encoding="utf-8", errors="ignore") as f:
                theharvester_data = json.load(f)
            
            if isinstance(theharvester_data, dict):
                # theHarvester JSON structure: {"emails": [...], "hosts": [...], "ips": [...]}
                emails = theharvester_data.get("emails", [])
                hosts = theharvester_data.get("hosts", [])
                ips = theharvester_data.get("ips", [])
                urls = theharvester_data.get("urls", [])
                
                metrics["results"]["emails"] = list(set(emails)) if isinstance(emails, list) else []
                metrics["results"]["hosts"] = list(set(hosts)) if isinstance(hosts, list) else []
                metrics["results"]["ips"] = list(set(ips)) if isinstance(ips, list) else []
                metrics["results"]["urls"] = list(set(urls)) if isinstance(urls, list) else []
                
                # Extract subdomains from hosts
                for host in metrics["results"]["hosts"]:
                    if host and "." in host and not host.startswith("http"):
                        # Check if it's a subdomain of target
                        if target.lower() in host.lower():
                            metrics["results"]["subdomains"].append(host)
                
                metrics["total_results"] = (
                    len(metrics["results"]["emails"]) +
                    len(metrics["results"]["hosts"]) +
                    len(metrics["results"]["ips"]) +
                    len(metrics["results"]["urls"])
                )
        except Exception:
            # JSON parse failed, fall back to text parsing
            pass
    
    # Parse text output for source status and results
    lines = combined_output.split('\n')
    
    successful_sources = set()
    failed_sources = set()
    missing_api_key_sources = set()
    error_sources = set()
    current_source = None
    source_results = {}  # Temporary storage for source-based results
    
    for i, line in enumerate(lines):
        line_lower = line.lower()
        line_stripped = line.strip()
        
        # Parse successful sources: "[*] Searching Baidu."
        if "[*] Searching" in line:
            source_match = re.search(r'Searching\s+([^.]+)', line)
            if source_match:
                source = source_match.group(1).strip()
                successful_sources.add(source)
                current_source = source
                metrics["sources_attempted"] += 1
                if source not in source_results:
                    source_results[source] = {
                        "emails": [],
                        "hosts": [],
                        "ips": [],
                        "urls": [],
                        "count": 0
                    }
        
        # Parse results from current source
        # theHarvester sometimes shows results after "[*] Searching" or in subsequent lines
        if current_source:
            # Look for emails (contains @)
            if "@" in line_stripped and ("@" in line_stripped.split()[0] if line_stripped.split() else False):
                email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line_stripped)
                if email_match:
                    email = email_match.group(1)
                    if email not in metrics["results"]["emails"]:
                        metrics["results"]["emails"].append(email)
                    if email not in source_results[current_source]["emails"]:
                        source_results[current_source]["emails"].append(email)
                        source_results[current_source]["count"] += 1
            
            # Look for hosts/subdomains (contains target domain)
            if target.lower() in line_lower and "." in line_stripped:
                # Extract potential host/subdomain
                host_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line_stripped)
                if host_match:
                    host = host_match.group(1)
                    if target.lower() in host.lower() and host not in metrics["results"]["hosts"]:
                        metrics["results"]["hosts"].append(host)
                        if host not in source_results[current_source]["hosts"]:
                            source_results[current_source]["hosts"].append(host)
                            source_results[current_source]["count"] += 1
            
            # Look for IPs
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line_stripped)
            if ip_match:
                ip = ip_match.group(1)
                if ip not in metrics["results"]["ips"]:
                    metrics["results"]["ips"].append(ip)
                if ip not in source_results[current_source]["ips"]:
                    source_results[current_source]["ips"].append(ip)
                    source_results[current_source]["count"] += 1
        
        # Parse missing API key: "[!] Missing API key for Shodan."
        if "missing api key" in line_lower or "missing key" in line_lower:
            api_key_match = re.search(r'(?:Missing API key|Missing Key|Missing key)\s+for\s+([^.]+)', line, re.IGNORECASE)
            if api_key_match:
                source = api_key_match.group(1).strip()
                missing_api_key_sources.add(source)
                findings.append(Finding(
                    type="api_key_missing",
                    severity="INFO",
                    title=f"Missing API key for {source}",
                    evidence={"source": source, "message": line.strip()}
                ))
        
        # Parse errors: "Error in BuiltWith search: ..."
        if "error" in line_lower and ("search" in line_lower or "occurred" in line_lower):
            error_match = re.search(r'Error\s+in\s+([^:]+)|error\s+occurred\s+in\s+([^:]+)', line, re.IGNORECASE)
            if error_match:
                source = (error_match.group(1) or error_match.group(2)).strip()
                error_sources.add(source)
                metrics["sources_attempted"] += 1
                findings.append(Finding(
                    type="source_error",
                    severity="LOW",
                    title=f"Error in {source} search",
                    evidence={"source": source, "error": line.strip()}
                ))
        
        # Parse failed sources: "Failed to process bevigil search"
        if "failed to process" in line_lower:
            failed_match = re.search(r'Failed to process\s+([^\s]+)', line, re.IGNORECASE)
            if failed_match:
                source = failed_match.group(1).strip()
                failed_sources.add(source)
                metrics["sources_attempted"] += 1
        
        # Reset current_source when we see a new section or empty line after results
        if line_stripped == "" and current_source:
            # Check if next lines are about a new source
            if i + 1 < len(lines) and "[*] Searching" in lines[i + 1]:
                current_source = None
    
    # Store source-based results
    for source, results in source_results.items():
        if results["count"] > 0:
            metrics["sources_results"][source] = {
                "emails": len(results["emails"]),
                "hosts": len(results["hosts"]),
                "ips": len(results["ips"]),
                "total": results["count"]
            }
    
    metrics["sources_successful"] = list(successful_sources)
    metrics["sources_failed"] = list(failed_sources)
    metrics["sources_missing_api_key"] = list(missing_api_key_sources)
    metrics["sources_errors"] = list(error_sources)
    
    # Create findings for results
    if metrics["results"]["emails"]:
        for email in metrics["results"]["emails"][:10]:  # Limit to first 10
            findings.append(Finding(
                type="osint_result",
                severity="INFO",
                title=f"Email found: {email}",
                evidence={"type": "email", "value": email}
            ))
    
    if metrics["results"]["hosts"]:
        for host in metrics["results"]["hosts"][:10]:  # Limit to first 10
            findings.append(Finding(
                type="osint_result",
                severity="INFO",
                title=f"Host found: {host}",
                evidence={"type": "host", "value": host}
            ))
    
    # Determine status
    if metrics["total_results"] > 0:
        status = "success"
        email_count = len(metrics["results"]["emails"])
        host_count = len(metrics["results"]["hosts"])
        ip_count = len(metrics["results"]["ips"])
        summary = f"theHarvester found {metrics['total_results']} results"
        if email_count > 0:
            summary += f" ({email_count} emails, {host_count} hosts, {ip_count} IPs)"
        summary += f" from {len(metrics['sources_successful'])} source(s)."
    elif len(metrics["sources_successful"]) > 0:
        status = "success"
        summary = f"theHarvester completed scan using {len(metrics['sources_successful'])} source(s) but found no results."
    else:
        status = "partial"
        summary = f"theHarvester scan for {target} completed but no results found."
    
    return NormalizedResult(
        tool="theharvester",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )
