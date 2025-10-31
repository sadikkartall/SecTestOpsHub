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

    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Target(id={self.id}, url={self.url})>"


class Scan(Base):
    """Scan model for storing scan executions"""
    __tablename__ = "scans"
    __table_args__ = {'extend_existing': True}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True)
    tools = Column(ARRAY(String), nullable=False, default=["nmap", "zap", "trivy"])
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    error_message = Column(Text, nullable=True)
    scan_metadata = Column(JSONB, nullable=True)  # For storing additional scan configuration

    # Relationships
    target = relationship("Target", back_populates="scans")
    playbook = relationship("Playbook", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, target_id={self.target_id}, status={self.status})>"


class Finding(Base):
    """Finding model for storing vulnerability findings"""
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    tool = Column(String(50), nullable=False, index=True)  # nmap, zap, trivy
    title = Column(String(500), nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False, index=True)
    
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(50), nullable=True, index=True)
    owasp_category = Column(String(100), nullable=True)  # e.g., "A01:2021 – Broken Access Control"
    
    endpoint = Column(String(1000), nullable=True)  # URL or IP:PORT
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    
    # AI-generated fields
    ai_summary = Column(Text, nullable=True)
    ai_recommendation = Column(Text, nullable=True)
    probable_fp = Column(Boolean, default=False)  # False positive indicator
    
    raw_output = Column(JSONB, nullable=True)  # Original tool output for reference
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding(id={self.id}, tool={self.tool}, severity={self.severity}, title={self.title[:50]})>"


class Artifact(Base):
    """Artifact produced by tool executions"""
    __tablename__ = "artifacts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tool = Column(String(50), nullable=False, index=True)
    path = Column(String(1000), nullable=False)
    format = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", backref="artifacts")


class Playbook(Base):
    """Playbook definition for orchestrated scans"""
    __tablename__ = "playbooks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False, unique=True)
    steps = Column(JSONB, nullable=True)  # ordered list of tools/params
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scans = relationship("Scan", back_populates="playbook")
