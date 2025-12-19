from typing import List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Taranacak hedef (domain, IP veya URL)")
    tools: Optional[List[str]] = Field(
        default=None,
        description="İleride eklenecek araç listesi; şu an kullanılmıyor",
    )
    output_dir: Optional[str] = Field(
        default=None,
        description="Çıktıların yazılacağı dizin; boş ise ortam değişkeni kullanılır",
    )


class PingResult(BaseModel):
    ip_address: str
    output_file: str
    raw_output: str
    success: bool


class WhoisResult(BaseModel):
    raw_output: str
    output_file: str
    success: bool


class NmapResult(BaseModel):
    raw_output: str
    output_file_xml: str
    output_file_txt: str
    success: bool
    command: str


class NiktoResult(BaseModel):
    raw_output: str
    output_file_json: str
    output_file_txt: str
    success: bool
    command: str


class GobusterFinding(BaseModel):
    """
    Gobuster sonuç satırının normalize edilmiş karşılığı.
    """
    url: str
    status: int
    length: int
    redirect_location: Optional[str] = None


class GobusterFindingsSummary(BaseModel):
    """
    UI/raporlama için basit özet: toplam bulgu ve status kırılımı.
    """
    total: int
    by_status: dict[int, int]


class GobusterResult(BaseModel):
    raw_output: str
    output_file_json: str
    findings: Optional[List[GobusterFinding]] = None
    findings_summary: Optional[GobusterFindingsSummary] = None
    success: bool
    command: str


class ZapResult(BaseModel):
    raw_output: str
    output_file: str
    success: bool
    command: str


class TestsslResult(BaseModel):
    """
    testssl.sh SSL/TLS tarama sonucu.
    JSON çıktı dosyası ve ham çıktı içerir.
    """
    raw_output: str
    output_file_json: str
    output_file_txt: str
    success: bool
    command: str


class DnsreconResult(BaseModel):
    """
    dnsrecon DNS enumeration sonucu.
    JSON çıktı dosyası ve ham çıktı içerir.
    """
    raw_output: str
    output_file_json: str
    output_file_txt: str
    success: bool
    command: str


class TheHarvesterResult(BaseModel):
    """
    theHarvester OSINT tarama sonucu.
    JSON çıktı dosyası ve ham çıktı içerir.
    """
    raw_output: str
    output_file_json: str
    output_file_txt: str
    success: bool
    command: str


class AmassResult(BaseModel):
    """
    amass subdomain enumeration sonucu.
    JSON çıktı dosyası ve ham çıktı içerir.
    """
    raw_output: str
    output_file_json: str
    output_file_txt: str
    success: bool
    command: str


class ScanCommand(BaseModel):
    tool: str
    command: List[str]
    output_file: str
    description: str


class ScanPlan(BaseModel):
    target_url: str
    tools: List[str]
    output_dir: str
    commands: List[ScanCommand]
    ping_result: Optional[PingResult] = None
    whois_result: Optional[WhoisResult] = None
    nmap_result: Optional[NmapResult] = None
    nikto_result: Optional[NiktoResult] = None
    gobuster_result: Optional[GobusterResult] = None
    zap_result: Optional[ZapResult] = None
    testssl_result: Optional[TestsslResult] = None
    dnsrecon_result: Optional[DnsreconResult] = None
    theharvester_result: Optional[TheHarvesterResult] = None
    amass_result: Optional[AmassResult] = None
    note: str


