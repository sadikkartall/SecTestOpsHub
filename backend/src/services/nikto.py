import os
import json
import re
import subprocess
from datetime import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any

from ..models.scan import NiktoResult
from ..models.normalized import NormalizedResult, Finding


def normalize_nikto(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    json_file_path: Optional[str] = None,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize nikto output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    
    metrics = {
        "target_input": target,
        "target_ip": None,
        "target_hostname": None,
        "port": None,
        "server": None,
        "start_time": None,
        "total_items": 0,
        "items_by_severity": {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0
        },
        "duration_ms": duration_ms
    }
    
    findings = []
    status = "partial"
    summary = f"Nikto scan for {target} completed with partial parsing."
    
    # Try to parse JSON first (more reliable)
    if json_file_path and os.path.exists(json_file_path):
        try:
            with open(json_file_path, "r", encoding="utf-8") as f:
                nikto_data = json.load(f)
            
            # Nikto JSON structure: {"host": {...}, "items": [...]}
            if isinstance(nikto_data, dict):
                host_info = nikto_data.get("host", {})
                items = nikto_data.get("items", [])
                
                metrics["target_ip"] = host_info.get("targetip")
                metrics["target_hostname"] = host_info.get("targethostname")
                metrics["port"] = host_info.get("port")
                metrics["server"] = host_info.get("server")
                metrics["start_time"] = host_info.get("starttime")
                metrics["total_items"] = len(items)
                
                # Parse items (findings)
                for item in items:
                    item_id = item.get("id", "")
                    description = item.get("description", "")
                    method = item.get("method", "")
                    uri = item.get("uri", "")
                    osvdb_id = item.get("osvdbid", "")
                    
                    # Determine severity based on description keywords
                    severity = "INFO"
                    desc_lower = description.lower()
                    if any(keyword in desc_lower for keyword in ["critical", "vulnerability", "exploit", "remote code"]):
                        severity = "CRITICAL"
                    elif any(keyword in desc_lower for keyword in ["high", "security", "insecure", "weak"]):
                        severity = "HIGH"
                    elif any(keyword in desc_lower for keyword in ["medium", "warning", "deprecated"]):
                        severity = "MEDIUM"
                    elif any(keyword in desc_lower for keyword in ["low", "information", "info"]):
                        severity = "LOW"
                    
                    metrics["items_by_severity"][severity] += 1
                    
                    findings.append(Finding(
                        type="nikto_item",
                        severity=severity,
                        title=description or f"Item {item_id}",
                        evidence={
                            "id": item_id,
                            "method": method,
                            "uri": uri,
                            "osvdb_id": osvdb_id,
                            "description": description
                        }
                    ))
                
                # Determine status
                if metrics["total_items"] > 0:
                    status = "success"
                    critical_count = metrics["items_by_severity"]["CRITICAL"]
                    high_count = metrics["items_by_severity"]["HIGH"]
                    if critical_count > 0:
                        summary = f"Nikto scan found {metrics['total_items']} items, including {critical_count} critical finding(s)."
                    elif high_count > 0:
                        summary = f"Nikto scan found {metrics['total_items']} items, including {high_count} high severity finding(s)."
                    else:
                        summary = f"Nikto scan found {metrics['total_items']} items."
                else:
                    status = "success"
                    summary = f"Nikto scan completed for {target} with no findings."
                
                return NormalizedResult(
                    tool="nikto",
                    target=target,
                    status=status,
                    summary=summary,
                    findings=findings,
                    metrics=metrics,
                    raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
                )
        except Exception as e:
            # JSON parse failed, fall back to text parsing
            pass
    
    # Fallback: Parse text output
    lines = output.split('\n')
    
    # Parse target info from text
    for line in lines:
        if "Target IP:" in line:
            ip_match = re.search(r'Target IP:\s+([^\s]+)', line)
            if ip_match:
                metrics["target_ip"] = ip_match.group(1)
        elif "Target Hostname:" in line:
            hostname_match = re.search(r'Target Hostname:\s+([^\s]+)', line)
            if hostname_match:
                metrics["target_hostname"] = hostname_match.group(1)
        elif "Target Port:" in line:
            port_match = re.search(r'Target Port:\s+(\d+)', line)
            if port_match:
                metrics["port"] = int(port_match.group(1))
        elif "Start Time:" in line:
            time_match = re.search(r'Start Time:\s+(.+)', line)
            if time_match:
                metrics["start_time"] = time_match.group(1).strip()
        elif line.strip().startswith("+ Server:"):
            server_match = re.search(r'Server:\s+(.+)', line)
            if server_match:
                metrics["server"] = server_match.group(1).strip()
    
    # Parse findings from text (lines starting with "+")
    for line in lines:
        if line.strip().startswith("+") and not line.strip().startswith("+ Target") and not line.strip().startswith("+ Server:"):
            # Extract finding description
            finding_text = line.strip()[1:].strip()  # Remove "+" prefix
            
            # Skip separator lines
            if finding_text.startswith("-") or "---" in finding_text:
                continue
            
            # Determine severity
            severity = "INFO"
            finding_lower = finding_text.lower()
            if any(keyword in finding_lower for keyword in ["critical", "vulnerability", "exploit", "remote code"]):
                severity = "CRITICAL"
            elif any(keyword in finding_lower for keyword in ["high", "security", "insecure", "weak"]):
                severity = "HIGH"
            elif any(keyword in finding_lower for keyword in ["medium", "warning", "deprecated"]):
                severity = "MEDIUM"
            elif any(keyword in finding_lower for keyword in ["low", "information", "info"]):
                severity = "LOW"
            
            metrics["items_by_severity"][severity] += 1
            metrics["total_items"] += 1
            
            findings.append(Finding(
                type="nikto_item",
                severity=severity,
                title=finding_text,
                evidence={
                    "description": finding_text,
                    "raw_line": line.strip()
                }
            ))
    
    # Determine status
    if metrics["total_items"] > 0:
        status = "success"
        critical_count = metrics["items_by_severity"]["CRITICAL"]
        high_count = metrics["items_by_severity"]["HIGH"]
        if critical_count > 0:
            summary = f"Nikto scan found {metrics['total_items']} items, including {critical_count} critical finding(s)."
        elif high_count > 0:
            summary = f"Nikto scan found {metrics['total_items']} items, including {high_count} high severity finding(s)."
        else:
            summary = f"Nikto scan found {metrics['total_items']} items."
    else:
        status = "success"
        summary = f"Nikto scan completed for {target} with no findings."
    
    return NormalizedResult(
        tool="nikto",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )


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
        raise RuntimeError("Nikto taraması zaman aşımına uğradı.")
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    normalized_result = normalize_nikto(
        raw_stdout=proc.stdout or "",
        raw_stderr=proc.stderr or "",
        exit_code=proc.returncode,
        target=target_host,
        command=" ".join(cmd),
        json_file_path=output_json,
        duration_ms=duration_ms
    )
    
    output_normalized_json = os.path.join(output_dir, f"nikto-{scan_id}-normalized.json")
    with open(output_normalized_json, "w", encoding="utf-8") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    return NiktoResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        normalized_json=normalized_result.model_dump(),
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )
