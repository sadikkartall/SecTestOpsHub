import os
import json
import re
import socket
import subprocess
from datetime import datetime
from uuid import uuid4
from typing import Optional

from ..models.scan import PingResult
from ..models.normalized import NormalizedResult, Finding


def normalize_ping(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    resolved_ip: Optional[str] = None,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize ping output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    combined_output = output + "\n" + error_output if error_output else output
    
    metrics = {
        "target_input": target,
        "resolved_ip": resolved_ip,
        "reachability": "unknown",
        "packets": {"sent": 0, "received": 0, "lost": 0, "loss_percent": 0.0},
        "rtt_ms": {"min": None, "avg": None, "max": None, "mdev": None},
        "duration_ms": duration_ms
    }
    
    findings = []
    status = "partial"
    summary = f"Ping to {target} inconclusive; parsing may be incomplete."
    
    if not output and not error_output:
        return NormalizedResult(
            tool="ping",
            target=target,
            status="failed",
            summary=f"Ping to {target} produced no output.",
            metrics=metrics,
            raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
        )
    
    if "permission denied" in combined_output.lower() or "operation not permitted" in combined_output.lower():
        metrics["reachability"] = "unknown"
        findings.append(Finding(
            type="icmp_blocked",
            severity="INFO",
            title="ICMP may be blocked or permission denied",
            evidence={"output": combined_output}
        ))
        summary = f"Ping to {target} inconclusive; ICMP may be blocked or permission denied."
        status = "partial"
        return NormalizedResult(
            tool="ping",
            target=target,
            status=status,
            summary=summary,
            findings=findings,
            metrics=metrics,
            raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
        )
    
    lines = output.split('\n')
    first_line = lines[0] if lines else ""
    ip_from_output = None
    
    ping_match = re.match(r'PING\s+([^\s]+)(?:\s+\(([^)]+)\))?', first_line)
    if ping_match:
        ip_from_output = ping_match.group(2)
        if not metrics["resolved_ip"]:
            metrics["resolved_ip"] = ip_from_output
    
    stats_line = None
    for line in lines:
        if "packets transmitted" in line.lower():
            stats_line = line
            break
    
    if stats_line:
        packets_match = re.search(r'(\d+)\s+packets\s+transmitted[,\s]+(\d+)\s+received', stats_line, re.IGNORECASE)
        if packets_match:
            metrics["packets"]["sent"] = int(packets_match.group(1))
            metrics["packets"]["received"] = int(packets_match.group(2))
            metrics["packets"]["lost"] = metrics["packets"]["sent"] - metrics["packets"]["received"]
        
        loss_match = re.search(r'(\d+(?:\.\d+)?)%\s+packet\s+loss', stats_line, re.IGNORECASE)
        if loss_match:
            metrics["packets"]["loss_percent"] = float(loss_match.group(1))
    
    rtt_line = None
    for line in lines:
        if "rtt min/avg/max/mdev" in line.lower() or "round-trip" in line.lower():
            rtt_line = line
            break
    
    if rtt_line:
        rtt_match = re.search(r'rtt\s+min/avg/max/mdev\s+=\s+([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s+ms', rtt_line, re.IGNORECASE)
        if rtt_match:
            metrics["rtt_ms"]["min"] = float(rtt_match.group(1))
            metrics["rtt_ms"]["avg"] = float(rtt_match.group(2))
            metrics["rtt_ms"]["max"] = float(rtt_match.group(3))
            metrics["rtt_ms"]["mdev"] = float(rtt_match.group(4))
    
    if metrics["packets"]["sent"] == 0:
        win_match = re.search(r'Packets:\s+Sent\s+=\s+(\d+),\s+Received\s+=\s+(\d+),\s+Lost\s+=\s+(\d+)', output, re.IGNORECASE)
        if win_match:
            metrics["packets"]["sent"] = int(win_match.group(1))
            metrics["packets"]["received"] = int(win_match.group(2))
            metrics["packets"]["lost"] = int(win_match.group(3))
            loss_pct_match = re.search(r'\((\d+(?:\.\d+)?)%\s+loss\)', output, re.IGNORECASE)
            if loss_pct_match:
                metrics["packets"]["loss_percent"] = float(loss_pct_match.group(1))
    
    if not metrics["resolved_ip"]:
        response_pattern = re.compile(r'(\d+)\s+bytes\s+from\s+([^:\s]+)', re.IGNORECASE)
        for line in lines:
            match = response_pattern.search(line)
            if match:
                metrics["resolved_ip"] = match.group(2)
                break
    
    received = metrics["packets"]["received"]
    loss_percent = metrics["packets"]["loss_percent"]
    
    if received > 0 and loss_percent < 100:
        metrics["reachability"] = "reachable"
        status = "success"
        avg_rtt = metrics["rtt_ms"]["avg"]
        ip_display = f" ({metrics['resolved_ip']})" if metrics["resolved_ip"] else ""
        summary = f"Host {target}{ip_display} is reachable"
        if avg_rtt is not None:
            summary += f" with avg latency {avg_rtt:.2f} ms"
        summary += f" and {loss_percent:.1f}% packet loss."
    elif received == 0 or loss_percent == 100:
        metrics["reachability"] = "unreachable"
        status = "failed"
        summary = f"Host {target} is unreachable (100% packet loss)."
        findings.append(Finding(
            type="host_unreachable",
            severity="INFO",
            title="Host unreachable",
            evidence={"packets_sent": metrics["packets"]["sent"], "packets_received": 0}
        ))
    else:
        metrics["reachability"] = "unknown"
        status = "partial"
        summary = f"Ping to {target} inconclusive; ICMP may be blocked."
    
    return NormalizedResult(
        tool="ping",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )


def run_ping(target_host: str, output_dir: str) -> PingResult:
    """
    Hedef hostname/IP için ping çalıştırır, çıktıyı dosyaya yazar ve IP bilgisini döner.
    Normalize edilmiş JSON çıktı da üretir.
    Tüm yorumlar Türkçe tutulmuştur.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    
    try:
        resolved_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        resolved_ip = None
    
    output_file_txt = os.path.join(output_dir, f"ping-{scan_id}.txt")
    output_file_json = os.path.join(output_dir, f"ping-{scan_id}.json")

    cmd = ["ping", "-c", "4", target_host]

    start_time = datetime.now()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    raw_output = proc.stdout.strip() or proc.stderr.strip()
    success = proc.returncode == 0

    with open(output_file_txt, "w", encoding="utf-8") as f:
        f.write(proc.stdout)
        if proc.stderr:
            f.write("\n--- STDERR ---\n")
            f.write(proc.stderr)

    normalized_result = normalize_ping(
        raw_stdout=proc.stdout,
        raw_stderr=proc.stderr,
        exit_code=proc.returncode,
        target=target_host,
        command=" ".join(cmd),
        resolved_ip=resolved_ip,
        duration_ms=duration_ms
    )
    
    with open(output_file_json, "w", encoding="utf-8") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    return PingResult(
        ip_address=resolved_ip or normalized_result.metrics.get("resolved_ip") or "",
        output_file=output_file_txt,
        output_file_json=output_file_json,
        normalized_json=normalized_result.model_dump(),
        raw_output=raw_output,
        success=success,
    )
