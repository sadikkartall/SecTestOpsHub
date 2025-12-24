import os
import json
import re
import subprocess
from datetime import datetime
from uuid import uuid4
from typing import Optional

from ..models.scan import WhoisResult
from ..models.normalized import NormalizedResult, Finding


def normalize_whois(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize whois output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    combined_output = output + "\n" + error_output if error_output else output
    
    metrics = {
        "target_input": target,
        "domain": None,
        "registrar": None,
        "dates": {
            "creation": None,
            "updated": None,
            "expiry": None
        },
        "nameservers": [],
        "contacts": {
            "registrant": None,
            "admin": None,
            "tech": None
        },
        "ip_range": None,
        "duration_ms": duration_ms
    }
    
    findings = []
    status = "partial"
    summary = f"Whois query for {target} completed with partial parsing."
    
    if not output and not error_output:
        return NormalizedResult(
            tool="whois",
            target=target,
            status="failed",
            summary=f"Whois query for {target} produced no output.",
            metrics=metrics,
            raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
        )
    
    # Check for common error messages
    error_patterns = [
        r"no match",
        r"not found",
        r"not available",
        r"quota exceeded",
        r"rate limit",
        r"connection refused",
        r"timeout"
    ]
    
    combined_lower = combined_output.lower()
    for pattern in error_patterns:
        if re.search(pattern, combined_lower):
            if "quota" in pattern or "rate limit" in pattern:
                findings.append(Finding(
                    type="rate_limit",
                    severity="INFO",
                    title="Whois rate limit or quota exceeded",
                    evidence={"output": combined_output[:200]}
                ))
                status = "partial"
                summary = f"Whois query for {target} may be rate limited."
            else:
                status = "failed"
                summary = f"Whois query for {target} failed: domain not found or query error."
            break
    
    lines = output.split('\n')
    
    # Check if this is an IP whois (ARIN/RIPE/APNIC format) vs domain whois
    is_ip_whois = False
    ip_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
    if ip_pattern.match(target):
        is_ip_whois = True
        metrics["ip_range"] = None
        metrics["organization"] = None
        metrics["netname"] = None
        metrics["cidr"] = None
        metrics["country"] = None
        metrics["abuse_contact"] = None
    
    # Parse domain name (for domain whois)
    if not is_ip_whois:
        domain_patterns = [
            r'Domain Name:\s*(.+)',
            r'domain:\s*(.+)',
            r'Domain:\s*(.+)',
            r'domain name:\s*(.+)'
        ]
        for line in lines:
            for pattern in domain_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    metrics["domain"] = match.group(1).strip().lower()
                    break
            if metrics["domain"]:
                break
        
        if not metrics["domain"]:
            metrics["domain"] = target.lower()
    
    # Parse IP whois information (ARIN/RIPE/APNIC format)
    if is_ip_whois:
        for line in lines:
            # NetRange
            if re.match(r'^NetRange:\s+', line, re.IGNORECASE):
                match = re.search(r'^NetRange:\s+(.+)$', line, re.IGNORECASE)
                if match:
                    metrics["ip_range"] = match.group(1).strip()
            
            # CIDR
            if re.match(r'^CIDR:\s+', line, re.IGNORECASE):
                match = re.search(r'^CIDR:\s+(.+)$', line, re.IGNORECASE)
                if match:
                    metrics["cidr"] = match.group(1).strip()
            
            # NetName
            if re.match(r'^NetName:\s+', line, re.IGNORECASE):
                match = re.search(r'^NetName:\s+(.+)$', line, re.IGNORECASE)
                if match:
                    metrics["netname"] = match.group(1).strip()
            
            # Organization
            if re.match(r'^Organization:\s+', line, re.IGNORECASE):
                match = re.search(r'^Organization:\s+(.+)$', line, re.IGNORECASE)
                if match:
                    metrics["organization"] = match.group(1).strip()
            
            # OrgName (alternative)
            if not metrics["organization"] and re.match(r'^OrgName:\s+', line, re.IGNORECASE):
                match = re.search(r'^OrgName:\s+(.+)$', line, re.IGNORECASE)
                if match:
                    metrics["organization"] = match.group(1).strip()
            
            # Country
            if re.match(r'^Country:\s+', line, re.IGNORECASE):
                match = re.search(r'^Country:\s+(.+)$', line, re.IGNORECASE)
                if match:
                    metrics["country"] = match.group(1).strip()
            
            # Abuse contact email
            if re.match(r'^OrgAbuseEmail:\s+', line, re.IGNORECASE) or re.match(r'^RAbuseEmail:\s+', line, re.IGNORECASE):
                match = re.search(r'^.*AbuseEmail:\s+(.+)$', line, re.IGNORECASE)
                if match:
                    metrics["abuse_contact"] = match.group(1).strip()
        
        # Set domain to IP if it's an IP whois
        metrics["domain"] = target
    
    # Parse registrar (skip WHOIS Server, get actual registrar name)
    for line in lines:
        # Skip Registrar WHOIS Server and URL lines
        line_lower = line.lower()
        if 'registrar whois server' in line_lower or 'registrar url' in line_lower:
            continue
        
        # Look for "Registrar:" line (not WHOIS Server)
        if re.match(r'^\s*Registrar:\s+', line, re.IGNORECASE):
            # Extract everything after "Registrar:"
            match = re.search(r'^\s*Registrar:\s+(.+)$', line, re.IGNORECASE)
            if match:
                registrar_name = match.group(1).strip()
                # Remove trailing "Registrar" if present
                registrar_name = re.sub(r'\s+Registrar\s*$', '', registrar_name, flags=re.IGNORECASE)
                if registrar_name and len(registrar_name) > 2:
                    metrics["registrar"] = registrar_name
                    break
        
        # Alternative patterns
        if not metrics["registrar"]:
            patterns = [
                r'^\s*Registrar Name:\s*(.+)',
                r'^\s*Sponsoring Registrar:\s*(.+)',
            ]
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    registrar_name = match.group(1).strip()
                    if registrar_name and len(registrar_name) > 2:
                        metrics["registrar"] = registrar_name
                        break
            if metrics["registrar"]:
                break
    
    # Parse dates
    date_patterns = {
        "creation": [
            r'Creation Date:\s*(.+)',
            r'Created:\s*(.+)',
            r'Registered:\s*(.+)',
            r'Registration Date:\s*(.+)',
            r'Domain Registration Date:\s*(.+)'
        ],
        "updated": [
            r'Updated Date:\s*(.+)',
            r'Last Updated:\s*(.+)',
            r'Last Modified:\s*(.+)',
            r'Modified:\s*(.+)'
        ],
        "expiry": [
            r'Expiry Date:\s*(.+)',
            r'Expiration Date:\s*(.+)',
            r'Registry Expiry Date:\s*(.+)',
            r'Expires:\s*(.+)',
            r'Expires On:\s*(.+)'
        ]
    }
    
    for date_type, patterns in date_patterns.items():
        for line in lines:
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    date_str = match.group(1).strip()
                    # Try to extract date (format varies)
                    date_match = re.search(r'(\d{4}-\d{2}-\d{2})', date_str)
                    if date_match:
                        metrics["dates"][date_type] = date_match.group(1)
                    else:
                        metrics["dates"][date_type] = date_str
                    break
            if metrics["dates"][date_type]:
                break
    
    # Check if domain is expired
    if metrics["dates"]["expiry"]:
        try:
            expiry_date = datetime.strptime(metrics["dates"]["expiry"], "%Y-%m-%d")
            if expiry_date < datetime.now():
                findings.append(Finding(
                    type="domain_expired",
                    severity="CRITICAL",
                    title="Domain has expired",
                    evidence={"expiry_date": metrics["dates"]["expiry"]}
                ))
        except (ValueError, TypeError):
            pass
    
    # Parse name servers
    ns_patterns = [
        r'Name Server:\s*(.+)',
        r'Name Servers?:\s*(.+)',
        r'Nameserver:\s*(.+)',
        r'nserver:\s*(.+)'
    ]
    for line in lines:
        for pattern in ns_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                ns = match.group(1).strip().lower()
                if ns and ns not in metrics["nameservers"]:
                    metrics["nameservers"].append(ns)
    
    # Parse contacts (simplified - just extract if available)
    contact_sections = {
        "registrant": ["Registrant", "Registrant Contact", "Registrant Name"],
        "admin": ["Admin", "Administrative Contact", "Admin Contact"],
        "tech": ["Tech", "Technical Contact", "Tech Contact"]
    }
    
    for contact_type, keywords in contact_sections.items():
        for keyword in keywords:
            for i, line in enumerate(lines):
                if keyword.lower() in line.lower() and ":" in line:
                    # Try to extract contact info from next few lines
                    contact_info = {}
                    for j in range(i, min(i + 5, len(lines))):
                        contact_line = lines[j]
                        if ":" in contact_line and not contact_line.strip().startswith(keyword):
                            parts = contact_line.split(":", 1)
                            if len(parts) == 2:
                                key = parts[0].strip().lower()
                                value = parts[1].strip()
                                if value:
                                    contact_info[key] = value
                    if contact_info:
                        metrics["contacts"][contact_type] = contact_info
                        break
            if metrics["contacts"][contact_type]:
                break
    
    # Check for privacy protection
    privacy_keywords = ["privacy", "redacted", "whois privacy", "data protected"]
    for line in lines:
        if any(keyword in line.lower() for keyword in privacy_keywords):
            findings.append(Finding(
                type="privacy_protection",
                severity="INFO",
                title="Domain has privacy protection enabled",
                evidence={"line": line.strip()}
            ))
            break
    
    # Parse IP range (if querying an IP)
    ip_range_pattern = r'inetnum:\s*(.+)'
    for line in lines:
        match = re.search(ip_range_pattern, line, re.IGNORECASE)
        if match:
            metrics["ip_range"] = match.group(1).strip()
            break
    
    # Determine status and generate summary
    if status != "failed":
        if is_ip_whois:
            # IP whois summary
            if metrics["ip_range"] or metrics["organization"] or metrics["netname"]:
                status = "success"
                summary_parts = [f"IP {target}"]
                if metrics["organization"]:
                    summary_parts.append(f"belongs to {metrics['organization']}")
                if metrics["ip_range"]:
                    summary_parts.append(f"range {metrics['ip_range']}")
                if metrics["netname"]:
                    summary_parts.append(f"network {metrics['netname']}")
                summary = ", ".join(summary_parts) + "."
            else:
                status = "partial"
                summary = f"IP whois query for {target} completed but some information could not be parsed."
        else:
            # Domain whois summary
            if metrics["domain"] and (metrics["registrar"] or metrics["dates"]["creation"] or metrics["nameservers"]):
                status = "success"
                summary_parts = [f"Domain {metrics['domain']}"]
                if metrics["registrar"]:
                    summary_parts.append(f"registered with {metrics['registrar']}")
                if metrics["dates"]["expiry"]:
                    summary_parts.append(f"expires {metrics['dates']['expiry']}")
                summary = ", ".join(summary_parts) + "."
            else:
                status = "partial"
                summary = f"Whois query for {target} completed but some information could not be parsed."
    
    
    return NormalizedResult(
        tool="whois",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )


def run_whois(target_host: str, output_dir: str) -> WhoisResult:
    """
    Hedef domain/host için whois sorgusu çalıştırır, çıktıyı dosyaya yazar ve sonucu döner.
    Normalize edilmiş JSON çıktı da üretir.
    Tüm yorumlar Türkçe tutulmuştur.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_file_txt = os.path.join(output_dir, f"whois-{scan_id}.txt")
    output_file_json = os.path.join(output_dir, f"whois-{scan_id}.json")

    cmd = ["whois", target_host]

    start_time = datetime.now()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Whois sorgusu zaman aşımına uğradı.")
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    success = proc.returncode == 0
    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    with open(output_file_txt, "w", encoding="utf-8", errors="ignore") as f:
        f.write(proc.stdout or "")
        if proc.stderr:
            f.write("\n--- STDERR ---\n")
            f.write(proc.stderr)

    normalized_result = normalize_whois(
        raw_stdout=proc.stdout or "",
        raw_stderr=proc.stderr or "",
        exit_code=proc.returncode,
        target=target_host,
        command=" ".join(cmd),
        duration_ms=duration_ms
    )
    
    with open(output_file_json, "w", encoding="utf-8", errors="ignore") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    return WhoisResult(
        raw_output=raw_output,
        output_file=output_file_txt,
        normalized_json=normalized_result.model_dump(),
        success=success,
    )
