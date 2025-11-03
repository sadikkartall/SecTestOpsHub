from celery import Celery
import os
import subprocess
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from database import SessionLocal
from models import Scan, Finding, ScanStatus, Severity
from parsers.nmap_parser import NmapParser
from parsers.zap_parser import ZapParser
from parsers.trivy_parser import TrivyParser
from parsers import parse_nikto, parse_amass, parse_ffuf, parse_whatweb, parse_testssl
from ai_service import AIService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Celery
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
celery_app = Celery("sectestops", broker=REDIS_URL, backend=REDIS_URL)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# Configuration
ARTIFACTS_PATH = Path(os.getenv("ARTIFACTS_PATH", "/app/artifacts"))
ENABLE_AI = os.getenv("ENABLE_AI_ANALYSIS", "true").lower() == "true"
STUB_MODE = os.getenv("STUB_MODE", "false").lower() == "true"


def run_command(command: List[str], output_file: str = None, timeout: int = 600) -> Dict[str, Any]:
    """Run a shell command and capture output"""
    try:
        logger.info(f"Executing command: {' '.join(command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
        
        # Save output to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
        
        return output
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(command)}")
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        logger.error(f"Command failed: {str(e)}")
        return {"success": False, "error": str(e)}


@celery_app.task(bind=True, name="start_scan_task")
def start_scan_task(self, scan_id: str, target_url: str, tools: List[str]):
    """Main scan orchestration task"""
    logger.info(f"Starting scan {scan_id} for target {target_url} with tools: {tools}")
    
    db = SessionLocal()
    scan = None
    
    try:
        # Update scan status to running
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return {"error": "Scan not found"}
        
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()
        
        # Create artifacts directory for this scan
        scan_artifacts_path = ARTIFACTS_PATH / scan_id
        scan_artifacts_path.mkdir(parents=True, exist_ok=True)
        
        # Run each tool
        all_findings = []
        
        if "nmap" in tools:
            logger.info(f"Running Nmap scan for {scan_id}")
            findings = run_nmap_scan(scan_id, target_url, scan_artifacts_path, db)
            all_findings.extend(findings)
        
        if "zap" in tools:
            logger.info(f"Running ZAP scan for {scan_id}")
            findings = run_zap_scan(scan_id, target_url, scan_artifacts_path, db)
            all_findings.extend(findings)
        
        if "trivy" in tools:
            logger.info(f"Running Trivy scan for {scan_id}")
            findings = run_trivy_scan(scan_id, target_url, scan_artifacts_path, db)
            all_findings.extend(findings)

        # Additional tools
        if "nikto" in tools:
            logger.info(f"Running Nikto scan for {scan_id}")
            findings = run_nikto_scan(scan_id, target_url, scan_artifacts_path, db)
            all_findings.extend(findings)

        if "amass" in tools:
            logger.info(f"Running Amass scan for {scan_id}")
            findings = run_amass_scan(scan_id, target_url, scan_artifacts_path, db)
            all_findings.extend(findings)

        if "ffuf" in tools:
            logger.info(f"Running ffuf scan for {scan_id}")
            findings = run_ffuf_scan(scan_id, target_url, scan_artifacts_path, db)
            all_findings.extend(findings)

        if "whatweb" in tools:
            logger.info(f"Running WhatWeb scan for {scan_id}")
            findings = run_whatweb_scan(scan_id, target_url, scan_artifacts_path, db)
            all_findings.extend(findings)

        if "testssl" in tools:
            logger.info(f"Running testssl scan for {scan_id}")
            findings = run_testssl_scan(scan_id, target_url, scan_artifacts_path, db)
            all_findings.extend(findings)
        
        # AI Analysis (if enabled)
        if ENABLE_AI and all_findings:
            logger.info(f"Running AI analysis for {scan_id}")
            ai = AIService()
            for finding in all_findings:
                data = {
                    "tool": finding.tool,
                    "title": finding.title,
                    "severity": str(finding.severity),
                    "endpoint": finding.endpoint,
                    "description": finding.description or "",
                }
                result = ai.analyze(data)
                finding.ai_summary = result.get("ai_summary")
                finding.ai_recommendation = result.get("ai_recommendation")
                finding.probable_fp = bool(result.get("probable_fp"))
            db.commit()
        
        # Update scan status to completed
        scan.status = ScanStatus.COMPLETED
        scan.finished_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"Scan {scan_id} completed with {len(all_findings)} findings")
        return {
            "scan_id": scan_id,
            "status": "completed",
            "findings_count": len(all_findings)
        }
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.finished_at = datetime.utcnow()
            db.commit()
        return {"error": str(e)}
    
    finally:
        db.close()


def run_nmap_scan(scan_id: str, target: str, artifacts_path: Path, db) -> List[Finding]:
    """Run Nmap scan and parse results"""
    try:
        output_file = artifacts_path / "nmap_output.xml"
        if STUB_MODE:
            logger.info("STUB_MODE enabled: writing stub nmap_output.xml")
            stub_xml = f"""<?xml version='1.0'?>
<nmaprun>
  <host>
    <address addr="{target}"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
            output_file.write_text(stub_xml, encoding="utf-8")
        else:
            # Run Nmap
            command = [
                "nmap",
                "-sV",
                "--max-retries", "1",
                "--host-timeout", "300s",
                "-oX", str(output_file),
                target
            ]
            result = run_command(command)
            if not result.get("success"):
                logger.error(f"Nmap scan failed: {result.get('error')}")
                return []
        
        
        
        # Parse results
        parser = NmapParser()
        findings = parser.parse(output_file, scan_id)
        
        # Save to database
        for finding in findings:
            db.add(finding)
        db.commit()
        
        logger.info(f"Nmap scan completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"Nmap scan error: {str(e)}")
        return []


def run_zap_scan(scan_id: str, target: str, artifacts_path: Path, db) -> List[Finding]:
    """Run OWASP ZAP scan and parse results"""
    try:
        output_file = artifacts_path / "zap_output.json"
        if STUB_MODE:
            logger.info("STUB_MODE enabled: writing stub zap_output.json")
            stub = {
                "site": [
                    {
                        "@name": target,
                        "alerts": [
                            {
                                "name": "X-Content-Type-Options Header Missing",
                                "riskdesc": "Low (Confidence: Medium)",
                                "desc": "The response does not include the X-Content-Type-Options header.",
                                "solution": "Ensure the header 'X-Content-Type-Options: nosniff' is set.",
                                "instances": [{"uri": f"{target}/", "method": "GET"}]
                            }
                        ]
                    }
                ]
            }
            output_file.write_text(json.dumps(stub), encoding="utf-8")
        else:
            # Run ZAP in Docker (baseline scan - non-aggressive)
            command = [
                "docker", "run", "--rm",
                "-v", f"{artifacts_path}:/zap/wrk:rw",
                "owasp/zap2docker-stable",
                "zap-baseline.py",
                "-t", target,
                "-J", "zap_output.json"
            ]
            result = run_command(command)
        
        # ZAP returns non-zero even on successful scan with findings
        if not output_file.exists():
            logger.error("ZAP output file not found")
            return []
        
        # Parse results
        parser = ZapParser()
        findings = parser.parse(output_file, scan_id)
        
        # Save to database
        for finding in findings:
            db.add(finding)
        db.commit()
        
        logger.info(f"ZAP scan completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"ZAP scan error: {str(e)}")
        return []


def run_trivy_scan(scan_id: str, target: str, artifacts_path: Path, db) -> List[Finding]:
    """Run Trivy scan and parse results"""
    try:
        output_file = artifacts_path / "trivy_output.json"
        if STUB_MODE:
            logger.info("STUB_MODE enabled: writing stub trivy_output.json")
            stub = {
                "Results": [
                    {
                        "Target": target,
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-0001",
                                "PkgName": "openssl",
                                "InstalledVersion": "1.1.1f",
                                "FixedVersion": "1.1.1u",
                                "Severity": "HIGH",
                                "Title": "OpenSSL vulnerability",
                                "Description": "A sample vulnerability in OpenSSL",
                                "References": ["https://example.com/cve-2023-0001"]
                            }
                        ]
                    }
                ]
            }
            output_file.write_text(json.dumps(stub), encoding="utf-8")
        else:
            # Determine if target is a filesystem path or container image
            command = [
                "docker", "run", "--rm",
                "-v", f"{artifacts_path}:/output",
                "aquasec/trivy",
                "fs",
                "--format", "json",
                "--output", "/output/trivy_output.json",
                target
            ]
            result = run_command(command)
        
        if not output_file.exists():
            logger.warning("Trivy output file not found (may be no vulnerabilities)")
            return []
        
        # Parse results
        parser = TrivyParser()
        findings = parser.parse(output_file, scan_id)
        
        # Save to database
        for finding in findings:
            db.add(finding)
        db.commit()
        
        logger.info(f"Trivy scan completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"Trivy scan error: {str(e)}")
        return []


def run_nikto_scan(scan_id: str, target: str, artifacts_path: Path, db) -> List[Finding]:
    """Run Nikto scan and parse results"""
    try:
        output_file = artifacts_path / "nikto.txt"
        if STUB_MODE:
            logger.info("STUB_MODE enabled: writing stub nikto.txt")
            output_file.write_text("+ Server leaks inodes via ETags, header found on /\n+ OSVDB-3092: /phpinfo.php: This gives a lot of system information.\n", encoding="utf-8")
        else:
            # Run Nikto
            command = ["nikto", "-h", target, "-o", str(output_file), "-Format", "txt"]
            result = run_command(command)
            if not result.get("success"):
                logger.error(f"Nikto scan failed: {result.get('error')}")
                return []
        
        # Parse results
        findings = parse_nikto(output_file, scan_id)
        
        # Save to database
        for finding in findings:
            db.add(finding)
        db.commit()
        
        logger.info(f"Nikto scan completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"Nikto scan error: {str(e)}")
        return []


def run_amass_scan(scan_id: str, target: str, artifacts_path: Path, db) -> List[Finding]:
    """Run Amass subdomain discovery and parse results"""
    try:
        output_file = artifacts_path / "amass.txt"
        if STUB_MODE:
            logger.info("STUB_MODE enabled: writing stub amass.txt")
            output_file.write_text(f"sub.{target}\napi.{target}\nadmin.{target}\n", encoding="utf-8")
        else:
            # Amass works with domains, not IPs. If IP, skip or try passive mode
            if target.replace('.', '').isdigit() or not any(c.isalpha() for c in target):
                logger.warning(f"Amass requires a domain name, not IP address: {target}")
                return []
            
            # Extract domain from URL if needed
            domain = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            
            # Run Amass with passive mode (faster, no DNS brute force)
            command = ["amass", "enum", "-passive", "-d", domain, "-o", str(output_file)]
            result = run_command(command, timeout=300)  # 5 minute timeout
            if not result.get("success"):
                logger.error(f"Amass scan failed: {result.get('error')}")
                # If file exists, try to parse partial results
                if not output_file.exists():
                    return []
        
        # Parse results
        findings = parse_amass(output_file, scan_id)
        
        # Save to database
        for finding in findings:
            db.add(finding)
        db.commit()
        
        logger.info(f"Amass scan completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"Amass scan error: {str(e)}")
        return []


def run_ffuf_scan(scan_id: str, target: str, artifacts_path: Path, db) -> List[Finding]:
    """Run ffuf web fuzzer and parse results"""
    try:
        output_file = artifacts_path / "ffuf.json"
        if STUB_MODE:
            logger.info("STUB_MODE enabled: writing stub ffuf.json")
            stub_data = {
                "results": [
                    {"url": f"{target}/admin", "status": 200, "length": 1234},
                    {"url": f"{target}/backup", "status": 403, "length": 567}
                ]
            }
            output_file.write_text(json.dumps(stub_data), encoding="utf-8")
        else:
            # Prepare URL - add http:// if not present
            url = target if target.startswith(('http://', 'https://')) else f"http://{target}"
            # Run ffuf
            command = ["ffuf", "-u", f"{url}/FUZZ", "-w", "/usr/share/wordlists/common.txt", "-o", str(output_file), "-of", "json", "-t", "10", "-timeout", "5"]
            result = run_command(command, timeout=300)  # 5 minute timeout
            if not result.get("success"):
                logger.error(f"ffuf scan failed: {result.get('error')}")
                # Try to parse partial results if file exists
                if output_file.exists():
                    logger.info("Attempting to parse partial ffuf results")
                else:
                    return []
        
        # Parse results
        findings = parse_ffuf(output_file, scan_id)
        
        # Save to database
        for finding in findings:
            db.add(finding)
        db.commit()
        
        logger.info(f"ffuf scan completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"ffuf scan error: {str(e)}")
        return []


def run_whatweb_scan(scan_id: str, target: str, artifacts_path: Path, db) -> List[Finding]:
    """Run WhatWeb technology fingerprinting and parse results"""
    try:
        output_file = artifacts_path / "whatweb.json"
        if STUB_MODE:
            logger.info("STUB_MODE enabled: writing stub whatweb.json")
            stub_data = [{
                "target": target,
                "plugins": {
                    "Apache": {"version": "2.4.41"},
                    "OpenSSL": {},
                    "PHP": {"version": "7.4"}
                }
            }]
            output_file.write_text(json.dumps(stub_data), encoding="utf-8")
        else:
            # Prepare URL - add http:// if not present
            url = target if target.startswith(('http://', 'https://')) else f"http://{target}"
            # Run WhatWeb
            command = ["whatweb", url, "--log-json", str(output_file), "--no-errors"]
            result = run_command(command, timeout=120)
            if not result.get("success"):
                logger.error(f"WhatWeb scan failed: {result.get('error')}")
                # Try to parse if file exists (WhatWeb might write partial output)
                if not output_file.exists():
                    return []
        
        # Parse results
        findings = parse_whatweb(output_file, scan_id)
        
        # Save to database
        for finding in findings:
            db.add(finding)
        db.commit()
        
        logger.info(f"WhatWeb scan completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"WhatWeb scan error: {str(e)}")
        return []


def run_testssl_scan(scan_id: str, target: str, artifacts_path: Path, db) -> List[Finding]:
    """Run testssl.sh and parse results"""
    try:
        output_file = artifacts_path / "testssl.json"
        if STUB_MODE:
            logger.info("STUB_MODE enabled: writing stub testssl.json")
            stub_data = {
                "scanResult": [
                    {"id": "SSLv3", "finding": "Obsolete protocol enabled"},
                    {"id": "TLS1.2", "finding": "Good"}
                ]
            }
            output_file.write_text(json.dumps(stub_data), encoding="utf-8")
        else:
            # Prepare URL - testssl needs hostname:port format
            # If IP, try both 443 (HTTPS) and 80 (HTTP)
            if target.startswith(('http://', 'https://')):
                url = target.replace('http://', '').replace('https://', '')
            else:
                url = target
            
            # Try HTTPS first (port 443)
            test_target = f"{url}:443" if ':' not in url else url
            command = ["testssl.sh", "--json", str(output_file), test_target]
            result = run_command(command, timeout=300)
            
            # If HTTPS fails, try HTTP (port 80)
            if not result.get("success") and ':443' in test_target:
                logger.info(f"HTTPS scan failed, trying HTTP on port 80")
                test_target = f"{url}:80"
                command = ["testssl.sh", "--json", str(output_file), test_target]
                result = run_command(command, timeout=300)
            
            if not result.get("success"):
                logger.error(f"testssl scan failed: {result.get('error')}")
                if not output_file.exists():
                    return []
        
        # Parse results
        findings = parse_testssl(output_file, scan_id)
        
        # Save to database
        for finding in findings:
            db.add(finding)
        db.commit()
        
        logger.info(f"testssl scan completed: {len(findings)} findings")
        return findings
        
    except Exception as e:
        logger.error(f"testssl scan error: {str(e)}")
        return []


@celery_app.task(bind=True, name="start_playbook_task")
def start_playbook_task(self, scan_id: str, target_url: str, steps: List[str]):
    """Run an ordered list of tools as a playbook."""
    logger.info(f"Starting playbook for {scan_id} with steps: {steps}")
    return start_scan_task(scan_id, target_url, steps)  # reuse orchestration

