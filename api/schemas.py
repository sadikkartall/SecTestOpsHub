from pydantic import BaseModel, HttpUrl, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID


# ==================== TARGET SCHEMAS ====================

class TargetBase(BaseModel):
    url: str = Field(..., description="Target URL or IP address", max_length=500)
    description: Optional[str] = Field(None, description="Target description")

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        # Basic validation - allow IP, domain, or URL
        if not any([
            v.startswith('http://'),
            v.startswith('https://'),
            v.replace('.', '').replace(':', '').replace('/', '').replace('-', '').isalnum()
        ]):
            raise ValueError("Invalid URL or IP format")
        return v


class TargetCreate(TargetBase):
    pass


class TargetResponse(TargetBase):
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


# ==================== SCAN SCHEMAS ====================

class ScanBase(BaseModel):
    target_id: UUID
    tools: Optional[List[str]] = Field(
        default=["nmap", "zap", "trivy"],
        description="List of tools to use in scan"
    )

    @field_validator('tools')
    @classmethod
    def validate_tools(cls, v: List[str]) -> List[str]:
        allowed_tools = {"nmap", "zap", "trivy"}
        for tool in v:
            if tool not in allowed_tools:
                raise ValueError(f"Invalid tool: {tool}. Allowed: {allowed_tools}")
        return v


class ScanCreate(ScanBase):
    pass


class ScanResponse(ScanBase):
    id: UUID
    status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    error_message: Optional[str]
    scan_metadata: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


# ==================== FINDING SCHEMAS ====================

class FindingBase(BaseModel):
    tool: str
    title: str
    severity: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    owasp_category: Optional[str] = None
    endpoint: Optional[str] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None


class FindingCreate(FindingBase):
    scan_id: UUID
    raw_output: Optional[Dict[str, Any]] = None


class FindingResponse(FindingBase):
    id: UUID
    scan_id: UUID
    ai_summary: Optional[str] = None
    ai_recommendation: Optional[str] = None
    probable_fp: bool = False
    created_at: datetime

    class Config:
        from_attributes = True


# ==================== STATISTICS SCHEMAS ====================

class StatisticsResponse(BaseModel):
    targets: int
    scans: int
    findings: int
    severity_breakdown: Dict[str, int]
    scan_status_breakdown: Dict[str, int]

