from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from sqlalchemy.orm import Session
from typing import List, Optional
import logging
from io import BytesIO

from database import engine, Base, get_db
from models import Target, Scan, Finding
from schemas import (
    TargetCreate, TargetResponse,
    ScanCreate, ScanResponse,
    FindingResponse
)
from celery_client import start_scan_task
from report_generator import ReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables with retry logic
import time
from sqlalchemy.exc import OperationalError

max_retries = 5
for attempt in range(max_retries):
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        break
    except OperationalError as e:
        if attempt < max_retries - 1:
            logger.warning(f"Database not ready, retrying... ({attempt + 1}/{max_retries})")
            time.sleep(3)
        else:
            logger.error("Could not connect to database after maximum retries")
            raise

# Initialize FastAPI app
app = FastAPI(
    title="SecTestOps Hub API",
    description="Entegre Güvenlik Test Otomasyonu ve AI Destekli Analiz Platformu",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "SecTestOps Hub API",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "database": "connected",
        "worker": "available"
    }


# ==================== TARGET ENDPOINTS ====================

@app.post("/api/targets", response_model=TargetResponse, status_code=201)
async def create_target(target: TargetCreate, db: Session = Depends(get_db)):
    """Create a new target for scanning"""
    try:
        db_target = Target(
            url=target.url,
            description=target.description
        )
        db.add(db_target)
        db.commit()
        db.refresh(db_target)
        logger.info(f"Target created: {db_target.id} - {db_target.url}")
        return db_target
    except Exception as e:
        logger.error(f"Error creating target: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/targets", response_model=List[TargetResponse])
async def list_targets(db: Session = Depends(get_db)):
    """List all targets"""
    targets = db.query(Target).order_by(Target.created_at.desc()).all()
    return targets


@app.get("/api/targets/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: Session = Depends(get_db)):
    """Get a specific target"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@app.delete("/api/targets/{target_id}", status_code=204)
async def delete_target(target_id: str, db: Session = Depends(get_db)):
    """Delete a target"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Delete associated scans and findings
    scans = db.query(Scan).filter(Scan.target_id == target_id).all()
    for scan in scans:
        db.query(Finding).filter(Finding.scan_id == scan.id).delete()
        db.delete(scan)
    
    db.delete(target)
    db.commit()
    logger.info(f"Target deleted: {target_id}")
    return None


# ==================== SCAN ENDPOINTS ====================

@app.post("/api/scans", response_model=ScanResponse, status_code=201)
async def create_scan(scan: ScanCreate, db: Session = Depends(get_db)):
    """Create and start a new scan"""
    try:
        # Verify target exists
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Create scan record
        db_scan = Scan(
            target_id=scan.target_id,
            tools=scan.tools or ["nmap", "zap", "trivy"],
            status="pending"
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        # Start scan task asynchronously
        task = start_scan_task.delay(str(db_scan.id), target.url, db_scan.tools)
        
        logger.info(f"Scan created: {db_scan.id} for target {target.url}")
        logger.info(f"Celery task started: {task.id}")
        
        return db_scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating scan: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans", response_model=List[ScanResponse])
async def list_scans(
    target_id: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all scans with optional filters"""
    query = db.query(Scan)
    
    if target_id:
        query = query.filter(Scan.target_id == target_id)
    if status:
        query = query.filter(Scan.status == status)
    
    scans = query.order_by(Scan.created_at.desc()).all()
    return scans


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Get a specific scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ==================== FINDING ENDPOINTS ====================

@app.get("/api/findings", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    tool: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all findings with optional filters"""
    query = db.query(Finding)
    
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if tool:
        query = query.filter(Finding.tool == tool)
    
    findings = query.order_by(Finding.created_at.desc()).all()
    return findings


@app.get("/api/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Get a specific finding"""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@app.get("/api/scans/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(scan_id: str, db: Session = Depends(get_db)):
    """Get all findings for a specific scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return findings


# ==================== STATISTICS ENDPOINTS ====================

@app.get("/api/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    """Get overall statistics"""
    total_targets = db.query(Target).count()
    total_scans = db.query(Scan).count()
    total_findings = db.query(Finding).count()
    
    # Count by severity
    severity_counts = {}
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = db.query(Finding).filter(Finding.severity == severity).count()
        severity_counts[severity] = count
    
    # Count by status
    status_counts = {}
    for status in ["pending", "running", "completed", "failed"]:
        count = db.query(Scan).filter(Scan.status == status).count()
        status_counts[status] = count
    
    return {
        "targets": total_targets,
        "scans": total_scans,
        "findings": total_findings,
        "severity_breakdown": severity_counts,
        "scan_status_breakdown": status_counts
    }


# ==================== REPORT ENDPOINTS ====================

@app.get("/api/scans/{scan_id}/report/json")
async def download_json_report(scan_id: str, db: Session = Depends(get_db)):
    """Download scan report as JSON"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    generator = ReportGenerator(scan, target, findings)
    json_report = generator.generate_json()
    
    return Response(
        content=json_report,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=scan_report_{scan_id[:8]}.json"
        }
    )


@app.get("/api/scans/{scan_id}/report/markdown")
async def download_markdown_report(scan_id: str, db: Session = Depends(get_db)):
    """Download scan report as Markdown"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    generator = ReportGenerator(scan, target, findings)
    markdown_report = generator.generate_markdown()
    
    return Response(
        content=markdown_report,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=scan_report_{scan_id[:8]}.md"
        }
    )


@app.get("/api/scans/{scan_id}/report/pdf")
async def download_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    """Download scan report as PDF"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    generator = ReportGenerator(scan, target, findings)
    pdf_buffer = generator.generate_pdf()
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=scan_report_{scan_id[:8]}.pdf"
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

