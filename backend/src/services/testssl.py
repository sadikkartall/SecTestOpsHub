import os
import json
import re
import subprocess
from datetime import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any

from ..models.scan import TestsslResult
from ..models.normalized import NormalizedResult, Finding


def run_testssl(target_host: str, target_port: int, output_dir: str) -> TestsslResult:
    """
    Hedef host:port için testssl.sh SSL/TLS taraması çalıştırır.
    testssl.sh format: domain:port veya IP:port
    JSON çıktı --jsonfile parametresi ile üretilir.
    
    Not: testssl.sh SSL/TLS test aracıdır, bu yüzden:
    - Port 80 ise otomatik olarak 443'e geçer (HTTPS)
    - Diğer portlar olduğu gibi kullanılır (örn: 8443, 8080)
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_json = os.path.join(output_dir, f"testssl-{scan_id}.json")
    output_txt = os.path.join(output_dir, f"testssl-{scan_id}.txt")

    # testssl.sh SSL/TLS test aracıdır, port 80 ise otomatik olarak 443'e geç
    # Çünkü port 80 HTTP için, SSL/TLS testi için port 443 (HTTPS) gerekli
    actual_port = target_port
    if target_port == 80:
        actual_port = 443

    # testssl.sh hedef formatı: host:port
    target = f"{target_host}:{actual_port}"

    # testssl.sh script yolu
    testssl_script = "/opt/testssl.sh/testssl.sh"
    if not os.path.exists(testssl_script):
        # Alternatif yol kontrolü
        testssl_script = "/usr/local/bin/testssl.sh"

    cmd = [
        "bash",
        testssl_script,
        "--jsonfile",
        output_json,
        "--quiet",  # Sadece önemli çıktıları göster
        "--warnings",
        "off",  # Etkileşimli uyarıları devre dışı bırak
        "--socket-timeout",
        "10",  # TCP socket bağlantı timeout'u (saniye)
        "--openssl-timeout",
        "10",  # OpenSSL bağlantı timeout'u (saniye)
        target,
    ]

    start_time = datetime.now()
    try:
        # testssl.sh uzun sürebilir, 10 dakika timeout
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,  # 10 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("testssl.sh taraması zaman aşımına uğradı.")
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

    normalized_result = normalize_testssl(
        raw_stdout=proc.stdout or "",
        raw_stderr=proc.stderr or "",
        exit_code=proc.returncode,
        target=target,
        command=" ".join(cmd),
        json_file_path=output_json,
        duration_ms=duration_ms
    )
    
    output_normalized_json = os.path.join(output_dir, f"testssl-{scan_id}-normalized.json")
    with open(output_normalized_json, "w", encoding="utf-8") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    return TestsslResult(
        raw_output=raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        normalized_json=normalized_result.model_dump(),
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )


def normalize_testssl(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    json_file_path: Optional[str] = None,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize testssl.sh output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    
    metrics = {
        "target": target,
        "hostname": None,
        "ip": None,
        "port": None,
        "protocols": {},
        "cipher_categories": {},
        "vulnerabilities": {},
        "certificate": {
            "cn": None,
            "issuer": None,
            "validity_days": None,
            "ocsp_stapling": None,
            "chain_of_trust": None
        },
        "http_headers": {
            "hsts": None,
            "security_headers": []
        },
        "rating": {
            "score": None,
            "grade": None,
            "grade_cap_reasons": []
        },
        "duration_ms": duration_ms
    }
    
    findings = []
    status = "partial"
    summary = f"testssl.sh scan for {target} completed with partial parsing."
    
    # Try to parse JSON first (more reliable)
    if json_file_path and os.path.exists(json_file_path):
        try:
            with open(json_file_path, "r", encoding="utf-8", errors="ignore") as f:
                testssl_data = json.load(f)
            
            # testssl.sh JSON structure varies, try to parse it
            if isinstance(testssl_data, list):
                for item in testssl_data:
                    if isinstance(item, dict):
                        id_val = item.get("id", "")
                        severity = item.get("severity", "")
                        finding = item.get("finding", "")
                        
                        # Map testssl severity to our severity
                        our_severity = "INFO"
                        if severity == "CRITICAL" or "VULNERABLE" in finding.upper():
                            our_severity = "CRITICAL"
                        elif severity == "HIGH" or "deprecated" in finding.lower():
                            our_severity = "HIGH"
                        elif severity == "MEDIUM":
                            our_severity = "MEDIUM"
                        elif severity == "LOW":
                            our_severity = "LOW"
                        
                        findings.append(Finding(
                            type="ssl_test",
                            severity=our_severity,
                            title=f"{id_val}: {finding}",
                            evidence=item
                        ))
        except Exception:
            # JSON parse failed, fall back to text parsing
            pass
    
    # Parse text output (ANSI escape codes removed)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned_output = ansi_escape.sub('', output)
    lines = cleaned_output.split('\n')
    
    # Parse target info
    for line in lines:
        if "Testing all IPv4 addresses" in line or "Testing" in line and ":" in line:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                metrics["ip"] = ip_match.group(1)
            hostname_match = re.search(r'\(([^)]+)\)', line)
            if hostname_match:
                metrics["hostname"] = hostname_match.group(1)
            port_match = re.search(r':(\d+)', line)
            if port_match:
                metrics["port"] = int(port_match.group(1))
    
    # Parse protocols
    in_protocols_section = False
    for line in lines:
        if "Testing protocols" in line:
            in_protocols_section = True
            continue
        if in_protocols_section:
            if line.strip().startswith("Testing") or line.strip() == "":
                if "Testing" in line:
                    in_protocols_section = False
                continue
            
            # Parse protocol lines: "SSLv2      not offered (OK)"
            protocol_match = re.match(r'^\s*(\w+(?:\s+\d+\.\d+)?)\s+(.+)$', line.strip())
            if protocol_match:
                protocol = protocol_match.group(1).strip()
                status_text = protocol_match.group(2).strip()
                metrics["protocols"][protocol] = status_text
                
                # Create findings for deprecated protocols
                if "deprecated" in status_text.lower() or protocol in ["TLS 1", "TLS 1.1"]:
                    findings.append(Finding(
                        type="deprecated_protocol",
                        severity="HIGH",
                        title=f"{protocol} is deprecated but still offered",
                        evidence={"protocol": protocol, "status": status_text}
                    ))
    
    # Parse vulnerabilities
    in_vuln_section = False
    for line in lines:
        if "Testing vulnerabilities" in line:
            in_vuln_section = True
            continue
        if in_vuln_section:
            if line.strip().startswith("Testing") or line.strip() == "" or "Running client" in line:
                if "Running client" in line:
                    in_vuln_section = False
                continue
            
            # Parse vulnerability lines: "Heartbleed (CVE-2014-0160)                not vulnerable (OK)"
            vuln_match = re.match(r'^\s*([^(]+)\s*\(([^)]+)\)\s*(.+)$', line.strip())
            if vuln_match:
                vuln_name = vuln_match.group(1).strip()
                cve = vuln_match.group(2).strip()
                status_text = vuln_match.group(3).strip()
                metrics["vulnerabilities"][vuln_name] = status_text
                
                # Create findings for vulnerabilities
                if "VULNERABLE" in status_text.upper() or "vulnerable" in status_text.lower():
                    findings.append(Finding(
                        type="vulnerability",
                        severity="CRITICAL",
                        title=f"{vuln_name} ({cve}) - VULNERABLE",
                        evidence={"vulnerability": vuln_name, "cve": cve, "status": status_text}
                    ))
                elif "not vulnerable" not in status_text.lower():
                    findings.append(Finding(
                        type="vulnerability_check",
                        severity="INFO",
                        title=f"{vuln_name} ({cve}): {status_text}",
                        evidence={"vulnerability": vuln_name, "cve": cve, "status": status_text}
                    ))
    
    # Parse certificate info
    in_cert_section = False
    cert_num = 1
    for line in lines:
        if "Server Certificate" in line:
            in_cert_section = True
            cert_num_match = re.search(r'#(\d+)', line)
            if cert_num_match:
                cert_num = int(cert_num_match.group(1))
            continue
        if in_cert_section:
            if "Common Name (CN)" in line:
                cn_match = re.search(r'CN\)\s+(.+)', line)
                if cn_match:
                    metrics["certificate"]["cn"] = cn_match.group(1).strip()
            elif "Issuer" in line and "Intermediate" not in line:
                issuer_match = re.search(r'Issuer\s+(.+)', line)
                if issuer_match:
                    metrics["certificate"]["issuer"] = issuer_match.group(1).strip()
            elif "Certificate Validity" in line:
                days_match = re.search(r'(\d+)\s*>=\s*\d+\s*days', line)
                if days_match:
                    metrics["certificate"]["validity_days"] = int(days_match.group(1))
            elif "OCSP stapling" in line:
                ocsp_match = re.search(r'OCSP stapling\s+(.+)', line)
                if ocsp_match:
                    ocsp_status = ocsp_match.group(1).strip()
                    metrics["certificate"]["ocsp_stapling"] = ocsp_status
                    if "not offered" in ocsp_status.lower():
                        findings.append(Finding(
                            type="missing_security_feature",
                            severity="MEDIUM",
                            title="OCSP stapling not offered",
                            evidence={"feature": "OCSP stapling", "status": ocsp_status}
                        ))
            elif "Chain of trust" in line:
                chain_match = re.search(r'Chain of trust\s+(.+)', line)
                if chain_match:
                    metrics["certificate"]["chain_of_trust"] = chain_match.group(1).strip()
            elif line.strip().startswith("Server Certificate") and cert_num > 1:
                in_cert_section = False
    
    # Parse HTTP headers
    in_http_section = False
    for line in lines:
        if "Testing HTTP header response" in line:
            in_http_section = True
            continue
        if in_http_section:
            if "Strict Transport Security" in line:
                hsts_match = re.search(r'Strict Transport Security\s+(.+)', line)
                if hsts_match:
                    hsts_status = hsts_match.group(1).strip()
                    metrics["http_headers"]["hsts"] = hsts_status
                    if "not offered" in hsts_status.lower():
                        findings.append(Finding(
                            type="missing_security_feature",
                            severity="MEDIUM",
                            title="HSTS (Strict Transport Security) not offered",
                            evidence={"feature": "HSTS", "status": hsts_status}
                        ))
            elif "Security headers" in line:
                # Security headers are listed in subsequent lines
                continue
            elif in_http_section and line.strip() and not line.strip().startswith("Testing"):
                # Parse security headers
                header_match = re.match(r'^\s*([^:]+):\s*(.+)$', line.strip())
                if header_match:
                    header_name = header_match.group(1).strip()
                    header_value = header_match.group(2).strip()
                    metrics["http_headers"]["security_headers"].append({
                        "name": header_name,
                        "value": header_value
                    })
            elif "Testing vulnerabilities" in line or "Rating" in line:
                in_http_section = False
    
    # Parse rating
    in_rating_section = False
    for line in lines:
        if "Rating (experimental)" in line or "Rating specs" in line:
            in_rating_section = True
            continue
        if in_rating_section:
            if "Final Score" in line:
                score_match = re.search(r'Final Score\s+(\d+)', line)
                if score_match:
                    metrics["rating"]["score"] = int(score_match.group(1))
            elif "Overall Grade" in line:
                grade_match = re.search(r'Overall Grade\s+([A-F])', line)
                if grade_match:
                    metrics["rating"]["grade"] = grade_match.group(1)
            elif "Grade cap reasons" in line:
                # Grade cap reasons are in subsequent lines
                continue
            elif in_rating_section and "Grade capped" in line:
                reason_match = re.search(r'Grade capped to\s+([A-F])\.\s+(.+)', line)
                if reason_match:
                    metrics["rating"]["grade_cap_reasons"].append(reason_match.group(2).strip())
    
    # Determine status
    vulnerable_count = len([f for f in findings if f.severity == "CRITICAL"])
    high_count = len([f for f in findings if f.severity == "HIGH"])
    
    if vulnerable_count > 0:
        status = "partial"
        summary = f"testssl.sh scan found {vulnerable_count} critical vulnerability/vulnerabilities."
    elif high_count > 0:
        status = "success"
        summary = f"testssl.sh scan found {high_count} high severity issue(s) (deprecated protocols)."
    elif metrics["rating"]["grade"]:
        status = "success"
        grade = metrics["rating"]["grade"]
        score = metrics["rating"]["score"]
        summary = f"testssl.sh scan completed. Rating: {grade} (Score: {score})."
    else:
        status = "success"
        summary = f"testssl.sh scan completed for {target}."
    
    return NormalizedResult(
        tool="testssl",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )
