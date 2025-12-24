import os
import json
import re
import xml.etree.ElementTree as ET
import subprocess
from datetime import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any

from ..models.scan import NmapResult
from ..models.normalized import NormalizedResult, Finding


def normalize_nmap(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    xml_file_path: Optional[str] = None,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize nmap output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    combined_output = output + "\n" + error_output if error_output else output
    
    metrics = {
        "target_input": target,
        "host_status": "unknown",
        "latency_ms": None,
        "ports": [],
        "os": {
            "detected": False,
            "cpe": None,
            "accuracy": None,
            "osclass": []
        },
        "scan_duration_seconds": None,
        "warnings": [],
        "duration_ms": duration_ms
    }
    
    findings = []
    status = "partial"
    summary = f"Nmap scan for {target} completed with partial parsing."
    
    if not output and not error_output:
        return NormalizedResult(
            tool="nmap",
            target=target,
            status="failed",
            summary=f"Nmap scan for {target} produced no output.",
            metrics=metrics,
            raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
        )
    
    # Try to parse XML first (more reliable)
    if xml_file_path and os.path.exists(xml_file_path):
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
            
            # Parse host status
            host = root.find("host")
            if host is not None:
                status_elem = host.find("status")
                if status_elem is not None:
                    state = status_elem.get("state", "unknown")
                    metrics["host_status"] = state
                    if state == "up":
                        latency = status_elem.get("reason", "")
                        latency_match = re.search(r'(\d+(?:\.\d+)?)\s*ms', latency, re.IGNORECASE)
                        if latency_match:
                            metrics["latency_ms"] = float(latency_match.group(1))
                
                # Parse ports
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port_elem in ports_elem.findall("port"):
                        port_info = {
                            "port": int(port_elem.get("portid", 0)),
                            "protocol": port_elem.get("protocol", "tcp"),
                            "state": None,
                            "service": None,
                            "version": None,
                            "product": None,
                            "cpe": None,
                            "scripts": {}
                        }
                        
                        state_elem = port_elem.find("state")
                        if state_elem is not None:
                            port_info["state"] = state_elem.get("state", "unknown")
                        
                        service_elem = port_elem.find("service")
                        if service_elem is not None:
                            port_info["service"] = service_elem.get("name", "")
                            port_info["product"] = service_elem.get("product", "")
                            port_info["version"] = service_elem.get("version", "")
                            cpe_elem = service_elem.find("cpe")
                            if cpe_elem is not None:
                                port_info["cpe"] = cpe_elem.text
                        
                        # Parse scripts
                        for script_elem in port_elem.findall("script"):
                            script_id = script_elem.get("id", "")
                            script_output = script_elem.get("output", "")
                            port_info["scripts"][script_id] = script_output
                        
                        if port_info["state"] in ["open", "filtered"]:
                            metrics["ports"].append(port_info)
                            
                            # Create findings for open ports
                            if port_info["state"] == "open":
                                findings.append(Finding(
                                    type="open_port",
                                    severity="INFO",
                                    title=f"Port {port_info['port']}/{port_info['protocol']} is open",
                                    evidence={
                                        "port": port_info["port"],
                                        "service": port_info["service"],
                                        "version": port_info["version"]
                                    }
                                ))
                
                # Parse OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        metrics["os"]["detected"] = True
                        metrics["os"]["accuracy"] = osmatch.get("accuracy", "")
                        name = osmatch.get("name", "")
                        if name:
                            metrics["os"]["osclass"] = [{"name": name}]
                    
                    for osclass in os_elem.findall("osclass"):
                        cpe_elem = osclass.find("cpe")
                        if cpe_elem is not None and not metrics["os"]["cpe"]:
                            metrics["os"]["cpe"] = cpe_elem.text
                
                # Parse scan duration
                runstats = root.find("runstats")
                if runstats is not None:
                    finished = runstats.find("finished")
                    if finished is not None:
                        elapsed = finished.get("elapsed", "")
                        if elapsed:
                            try:
                                metrics["scan_duration_seconds"] = float(elapsed)
                            except ValueError:
                                pass
            
            # Determine status
            if metrics["host_status"] == "up" and len(metrics["ports"]) > 0:
                status = "success"
                open_ports = [p for p in metrics["ports"] if p["state"] == "open"]
                summary = f"Host {target} is up"
                if metrics["latency_ms"]:
                    summary += f" ({metrics['latency_ms']:.0f}ms latency)"
                summary += f", {len(open_ports)} open port(s) found."
            elif metrics["host_status"] == "up":
                status = "success"
                summary = f"Host {target} is up but no open ports found."
            elif metrics["host_status"] == "down":
                status = "failed"
                summary = f"Host {target} is down or unreachable."
            else:
                status = "partial"
                summary = f"Nmap scan for {target} completed but host status unclear."
            
            return NormalizedResult(
                tool="nmap",
                target=target,
                status=status,
                summary=summary,
                findings=findings,
                metrics=metrics,
                raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
            )
        except Exception as e:
            # XML parse failed, fall back to text parsing
            pass
    
    # Fallback: Parse text output
    lines = output.split('\n')
    
    # Parse host status
    for line in lines:
        if "Host is up" in line:
            metrics["host_status"] = "up"
            latency_match = re.search(r'\(([\d.]+)s?\s*latency\)', line, re.IGNORECASE)
            if latency_match:
                latency_val = float(latency_match.group(1))
                metrics["latency_ms"] = int(latency_val * 1000) if latency_val < 10 else int(latency_val)
            break
        elif "Host seems down" in line or "0 hosts up" in line:
            metrics["host_status"] = "down"
            break
    
    # Parse ports from text output
    # Format: "22/tcp    open     ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13"
    port_pattern = re.compile(r'^(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)$')
    in_port_section = False
    
    for line in lines:
        if "PORT" in line and "STATE" in line and "SERVICE" in line:
            in_port_section = True
            continue
        
        if in_port_section:
            if line.strip() == "" or line.startswith("OS") or line.startswith("Service") or "Nmap done" in line:
                in_port_section = False
                continue
            
            match = port_pattern.match(line.strip())
            if match:
                port_info = {
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4),
                    "version": match.group(5).strip() if match.group(5) else None,
                    "product": None,
                    "cpe": None,
                    "scripts": {}
                }
                
                # Extract product/version from version string
                if port_info["version"]:
                    version_parts = port_info["version"].split()
                    if version_parts:
                        port_info["product"] = version_parts[0]
                
                metrics["ports"].append(port_info)
                
                if port_info["state"] == "open":
                    findings.append(Finding(
                        type="open_port",
                        severity="INFO",
                        title=f"Port {port_info['port']}/{port_info['protocol']} is open",
                        evidence={
                            "port": port_info["port"],
                            "service": port_info["service"],
                            "version": port_info["version"]
                        }
                    ))
    
    # Parse OS detection
    for line in lines:
        if "OS details:" in line or "OS CPE:" in line:
            metrics["os"]["detected"] = True
            cpe_match = re.search(r'cpe:/[^\s]+', line)
            if cpe_match:
                metrics["os"]["cpe"] = cpe_match.group(0)
    
    # Parse scan duration
    for line in lines:
        if "scanned in" in line:
            duration_match = re.search(r'scanned in ([\d.]+)\s*seconds?', line, re.IGNORECASE)
            if duration_match:
                metrics["scan_duration_seconds"] = float(duration_match.group(1))
            break
    
    # Parse warnings
    for line in lines:
        if line.strip().startswith("Warning:"):
            metrics["warnings"].append(line.strip())
            findings.append(Finding(
                type="scan_warning",
                severity="INFO",
                title=line.strip(),
                evidence={"line": line.strip()}
            ))
    
    # Determine status
    if metrics["host_status"] == "up" and len(metrics["ports"]) > 0:
        status = "success"
        open_ports = [p for p in metrics["ports"] if p["state"] == "open"]
        summary = f"Host {target} is up"
        if metrics["latency_ms"]:
            summary += f" ({metrics['latency_ms']:.0f}ms latency)"
        summary += f", {len(open_ports)} open port(s) found."
    elif metrics["host_status"] == "up":
        status = "success"
        summary = f"Host {target} is up but no open ports found."
    elif metrics["host_status"] == "down":
        status = "failed"
        summary = f"Host {target} is down or unreachable."
    else:
        status = "partial"
        summary = f"Nmap scan for {target} completed but host status unclear."
    
    return NormalizedResult(
        tool="nmap",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )


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

    start_time = datetime.now()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Nmap taraması zaman aşımına uğradı.")
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    normalized_result = normalize_nmap(
        raw_stdout=proc.stdout or "",
        raw_stderr=proc.stderr or "",
        exit_code=proc.returncode,
        target=target_host,
        command=" ".join(cmd),
        xml_file_path=output_xml,
        duration_ms=duration_ms
    )
    
    output_json = os.path.join(output_dir, f"nmap-{scan_id}.json")
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    return NmapResult(
        raw_output=raw_output,
        output_file_xml=output_xml,
        output_file_txt=output_txt,
        normalized_json=normalized_result.model_dump(),
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )
