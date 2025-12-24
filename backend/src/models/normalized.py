from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class Finding(BaseModel):
    """
    Güvenlik bulgusu/vulnerability modeli.
    
    Tüm güvenlik araçlarının bulgularını standart formatta temsil eder.
    """
    type: str  # Bulgu türü (örn: "vulnerability", "subdomain_discovery", "security_alert")
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]  # Önem seviyesi
    title: str  # Bulgu başlığı
    evidence: Dict[str, Any]  # Bulgu kanıtları (detaylı bilgiler)


class NormalizedResult(BaseModel):
    """
    Tüm güvenlik araçları için ortak normalizasyon şeması.
    
    Her araç çıktısı bu standart formata dönüştürülür,
    böylece frontend'de tutarlı bir görüntüleme sağlanır.
    """
    tool: str  # Araç adı (örn: "nmap", "nikto", "zap")
    target: str  # Hedef (domain, IP veya URL)
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())  # İşlem zamanı
    status: Literal["success", "partial", "failed"]  # İşlem durumu
    summary: str  # Özet bilgi
    findings: List[Finding] = Field(default_factory=list)  # Bulgular listesi
    metrics: Dict[str, Any]  # Metrikler (araç özelinde değişir)
    raw: Dict[str, Any] = Field(  # Ham çıktı bilgileri
        default_factory=lambda: {
            "stdout": "",  # Standart çıktı
            "stderr": "",  # Hata çıktısı
            "exit_code": 0,  # Çıkış kodu
            "command": ""  # Çalıştırılan komut
        }
    )
