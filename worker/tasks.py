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
from ai_analyzer import AIAnalyzer

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


def run_command(command: List[str], output_file: str = None) -> Dict[str, Any]:
    """Run a shell command and capture output"""
    try:
        logger.info(f"Executing command: {' '.join(command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes timeout
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
        
        # AI Analysis (if enabled)
        if ENABLE_AI and all_findings:
            logger.info(f"Running AI analysis for {scan_id}")
            ai_analyzer = AIAnalyzer()
            for finding in all_findings:
                ai_analyzer.analyze_finding(finding, db)
        
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
        
        # Run Nmap
        command = [
            "nmap",
            "-sV",  # Service version detection
            "-sC",  # Default scripts
            "-oX", str(output_file),  # XML output
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
        
        # Determine if target is a filesystem path or container image
        # For now, we'll scan the target as a URL/filesystem
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

