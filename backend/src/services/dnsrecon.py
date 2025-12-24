import os
import subprocess
import json
import re
from datetime import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any

from ..models.scan import DnsreconResult
from ..models.normalized import NormalizedResult, Finding


def run_dnsrecon(target_domain: str, output_dir: str) -> DnsreconResult:
    """
    Hedef domain için dnsrecon DNS enumeration çalıştırır.
    dnsrecon domain bekler, IP adresi değil.
    JSON çıktı -j parametresi ile üretilir.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_json = os.path.join(output_dir, f"dnsrecon-{scan_id}.json")
    output_txt = os.path.join(output_dir, f"dnsrecon-{scan_id}.txt")

    # dnsrecon komutu: -d domain, -j JSON çıktı
    # -t std: Standart DNS kayıtları (A, AAAA, MX, NS, TXT, SOA)
    # --lifetime: DNS sorgu timeout'u (saniye), çok yavaş DNS sunucuları için yüksek değer
    # Not: -n parametresi kaldırıldı, varsayılan DNS sunucuları kullanılacak
    cmd = [
        "dnsrecon",
        "-d",
        target_domain,
        "-j",
        output_json,
        "-t",
        "std",  # Standart DNS kayıtları
        "--lifetime",
        "120",  # DNS sorgu timeout'u 120 saniye (çok yavaş sunucular için)
    ]

    start_time = datetime.now()
    try:
        # dnsrecon uzun sürebilir, 10 dakika timeout (--lifetime 120 için yeterli)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,  # 10 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("dnsrecon taraması zaman aşımına uğradı.")
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

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
    # Ama dnsrecon genellikle timeout olsa bile JSON üretmez, bu yüzden returncode'a bakıyoruz
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

    normalized_result = normalize_dnsrecon(
        raw_stdout=proc.stdout or "",
        raw_stderr=proc.stderr or "",
        exit_code=proc.returncode,
        target=target_domain,
        command=" ".join(cmd),
        json_file_path=output_json,
        duration_ms=duration_ms
    )
    
    output_normalized_json = os.path.join(output_dir, f"dnsrecon-{scan_id}-normalized.json")
    with open(output_normalized_json, "w", encoding="utf-8") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    return DnsreconResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        normalized_json=normalized_result.model_dump(),
        success=success,
        command=" ".join(cmd),
    )


def normalize_dnsrecon(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    json_file_path: Optional[str] = None,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize dnsrecon output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    
    metrics = {
        "target": target,
        "dnssec_configured": None,
        "record_types": {
            "SOA": 0,
            "NS": 0,
            "MX": 0,
            "A": 0,
            "AAAA": 0,
            "TXT": 0,
            "SRV": 0,
            "CNAME": 0
        },
        "name_servers": [],
        "mail_servers": [],
        "address_records": [],
        "txt_records": {
            "spf": None,
            "dmarc": None,
            "verifications": [],
            "others": []
        },
        "total_records": 0,
        "duration_ms": duration_ms
    }
    
    findings = []
    status = "partial"
    summary = f"dnsrecon scan for {target} completed with partial parsing."
    
    # Try to parse JSON first (more reliable)
    if json_file_path and os.path.exists(json_file_path):
        try:
            with open(json_file_path, "r", encoding="utf-8", errors="ignore") as f:
                dnsrecon_data = json.load(f)
            
            if isinstance(dnsrecon_data, list):
                for record in dnsrecon_data:
                    if isinstance(record, dict):
                        record_type = record.get("type", "").upper()
                        name = record.get("name", "")
                        address = record.get("address", "")
                        target_val = record.get("target", "")
                        
                        # Count record types
                        if record_type in metrics["record_types"]:
                            metrics["record_types"][record_type] += 1
                            metrics["total_records"] += 1
                        
                        # Parse specific record types
                        if record_type == "NS":
                            metrics["name_servers"].append({
                                "hostname": name,
                                "ip": address or target_val
                            })
                            findings.append(Finding(
                                type="dns_record",
                                severity="INFO",
                                title=f"NS record: {name} ({address or target_val})",
                                evidence=record
                            ))
                        elif record_type == "MX":
                            metrics["mail_servers"].append({
                                "hostname": name or target_val,
                                "ip": address,
                                "priority": record.get("priority")
                            })
                            findings.append(Finding(
                                type="dns_record",
                                severity="INFO",
                                title=f"MX record: {name or target_val} ({address})",
                                evidence=record
                            ))
                        elif record_type in ["A", "AAAA"]:
                            metrics["address_records"].append({
                                "hostname": name,
                                "ip": address or target_val,
                                "type": record_type
                            })
                        elif record_type == "TXT":
                            txt_value = record.get("strings", [])
                            if isinstance(txt_value, list) and len(txt_value) > 0:
                                txt_str = " ".join(txt_value) if isinstance(txt_value[0], str) else str(txt_value[0])
                            else:
                                txt_str = str(txt_value) if txt_value else ""
                            
                            # Parse SPF
                            if "v=spf1" in txt_str.lower():
                                metrics["txt_records"]["spf"] = txt_str
                                findings.append(Finding(
                                    type="dns_security",
                                    severity="LOW",
                                    title=f"SPF record found: {txt_str[:100]}",
                                    evidence={"type": "SPF", "value": txt_str}
                                ))
                            # Parse DMARC
                            elif "v=dmarc1" in txt_str.lower() or "dmarc" in txt_str.lower():
                                metrics["txt_records"]["dmarc"] = txt_str
                                findings.append(Finding(
                                    type="dns_security",
                                    severity="LOW",
                                    title=f"DMARC record found: {txt_str[:100]}",
                                    evidence={"type": "DMARC", "value": txt_str}
                                ))
                            # Parse verification codes
                            elif any(keyword in txt_str.lower() for keyword in ["verification", "verify", "google-site-verification", "facebook-domain-verification"]):
                                metrics["txt_records"]["verifications"].append(txt_str)
                            else:
                                metrics["txt_records"]["others"].append(txt_str)
                            
                            findings.append(Finding(
                                type="dns_record",
                                severity="INFO",
                                title=f"TXT record: {txt_str[:100]}",
                                evidence=record
                            ))
                        elif record_type == "SOA":
                            findings.append(Finding(
                                type="dns_record",
                                severity="INFO",
                                title=f"SOA record: {name}",
                                evidence=record
                            ))
        except Exception:
            # JSON parse failed, fall back to text parsing
            pass
    
    # Fallback: Parse text output
    lines = output.split('\n')
    
    # Parse DNSSEC status
    for line in lines:
        if "DNSSEC is not configured" in line:
            metrics["dnssec_configured"] = False
            findings.append(Finding(
                type="dns_security",
                severity="MEDIUM",
                title="DNSSEC is not configured",
                evidence={"dnssec": False}
            ))
            break
        elif "DNSSEC" in line and "configured" in line.lower():
            metrics["dnssec_configured"] = True
            break
    
    # Parse DNS records from text
    for line in lines:
        line = line.strip()
        if not line or line.startswith("[*]") and "Performing" in line:
            continue
        
        # Parse record lines: "[*] 	 SOA a.ns.instagram.com 129.134.30.12"
        # or "[*] 	 A instagram.com 157.240.234.174"
        # or "[*] 	 TXT instagram.com google-site-verification=..."
        record_match = re.match(r'^\[\*\]\s+(\w+)\s+([^\s]+)\s+(.+)$', line)
        if record_match:
            record_type = record_match.group(1).upper()
            name = record_match.group(2)
            value = record_match.group(3).strip()
            
            if record_type in metrics["record_types"]:
                metrics["record_types"][record_type] += 1
                metrics["total_records"] += 1
            
            if record_type == "NS":
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', value)
                ip = ip_match.group(1) if ip_match else value
                metrics["name_servers"].append({"hostname": name, "ip": ip})
            elif record_type == "MX":
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', value)
                ip = ip_match.group(1) if ip_match else None
                hostname = value.split()[0] if value else name
                metrics["mail_servers"].append({"hostname": hostname, "ip": ip})
            elif record_type in ["A", "AAAA"]:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)', value)
                ip = ip_match.group(1) if ip_match else value
                metrics["address_records"].append({"hostname": name, "ip": ip, "type": record_type})
            elif record_type == "TXT":
                # Parse SPF
                if "v=spf1" in value.lower():
                    metrics["txt_records"]["spf"] = value
                # Parse DMARC
                elif "v=dmarc1" in value.lower() or "dmarc" in value.lower():
                    metrics["txt_records"]["dmarc"] = value
                # Parse verification codes
                elif any(keyword in value.lower() for keyword in ["verification", "verify"]):
                    metrics["txt_records"]["verifications"].append(value)
                else:
                    metrics["txt_records"]["others"].append(value)
    
    # Determine status
    if metrics["total_records"] > 0:
        status = "success"
        ns_count = metrics["record_types"]["NS"]
        mx_count = metrics["record_types"]["MX"]
        a_count = metrics["record_types"]["A"]
        txt_count = metrics["record_types"]["TXT"]
        
        summary = f"dnsrecon found {metrics['total_records']} DNS records"
        if ns_count > 0:
            summary += f" ({ns_count} NS, {mx_count} MX, {a_count} A, {txt_count} TXT)"
        summary += "."
    else:
        status = "failed"
        summary = f"dnsrecon scan for {target} found no DNS records."
    
    return NormalizedResult(
        tool="dnsrecon",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )
