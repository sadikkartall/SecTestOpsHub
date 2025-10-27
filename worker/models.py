# Import models from API (shared models)
# This file imports the same models used by the API

from sqlalchemy import Column, String, Text, DateTime, Float, Boolean, ForeignKey, ARRAY, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Target(Base):
    """Target model for storing scan targets"""
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    """Scan model for storing scan executions"""
    __tablename__ = "scans"
    __table_args__ = {'extend_existing': True}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    tools = Column(ARRAY(String), nullable=False, default=["nmap", "zap", "trivy"])
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    error_message = Column(Text, nullable=True)
    scan_metadata = Column(JSONB, nullable=True)

    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    """Finding model for storing vulnerability findings"""
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    tool = Column(String(50), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False, index=True)
    
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(50), nullable=True, index=True)
    owasp_category = Column(String(100), nullable=True)
    
    endpoint = Column(String(1000), nullable=True)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    
    ai_summary = Column(Text, nullable=True)
    ai_recommendation = Column(Text, nullable=True)
    probable_fp = Column(Boolean, default=False)
    
    raw_output = Column(JSONB, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")

