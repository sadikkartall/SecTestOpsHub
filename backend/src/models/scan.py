from typing import List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """
    Tarama isteği modeli.
    
    Kullanıcıdan gelen tarama talebini temsil eder.
    """
    target_url: str = Field(..., description="Taranacak hedef (domain, IP veya URL)")
    tools: Optional[List[str]] = Field(
        default=None,
        description="Çalıştırılacak araç listesi (boş ise tümü seçili)",
    )
    output_dir: Optional[str] = Field(
        default=None,
        description="Çıktıların yazılacağı dizin (boş ise ortam değişkeni kullanılır)",
    )


class PingResult(BaseModel):
    """
    Ping tarama sonucu modeli.
    """
    ip_address: str  # Çözümlenmiş IP adresi
    output_file: str  # Ham çıktı dosyası (TXT)
    output_file_json: Optional[str] = None  # Normalize edilmiş JSON çıktı dosyası
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    raw_output: str  # Ham çıktı metni
    success: bool  # İşlem başarı durumu


class WhoisResult(BaseModel):
    raw_output: str
    output_file: str
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool


class NmapResult(BaseModel):
    """
    Nmap tarama sonucu modeli.
    """
    raw_output: str  # Ham çıktı metni
    output_file_xml: str  # XML çıktı dosyası
    output_file_txt: str  # TXT çıktı dosyası
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool  # İşlem başarı durumu
    command: str  # Çalıştırılan komut


class NiktoResult(BaseModel):
    """
    Nikto tarama sonucu modeli.
    """
    raw_output: str  # Ham çıktı metni
    output_file_json: str  # JSON çıktı dosyası
    output_file_txt: str  # TXT çıktı dosyası
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool  # İşlem başarı durumu
    command: str  # Çalıştırılan komut


class GobusterFinding(BaseModel):
    """
    Gobuster bulgu modeli.
    
    Her bir bulunan dizin/dosya için bilgileri içerir.
    """
    url: str  # Bulunan URL
    status: int  # HTTP status kodu
    length: int  # Yanıt boyutu (byte)
    redirect_location: Optional[str] = None  # Yönlendirme hedefi (varsa)


class GobusterFindingsSummary(BaseModel):
    """
    Gobuster bulguları özet modeli.
    
    UI ve raporlama için toplam bulgu sayısı ve status kod dağılımı.
    """
    total: int  # Toplam bulgu sayısı
    by_status: dict[int, int]  # Status koduna göre bulgu sayıları


class GobusterResult(BaseModel):
    """
    Gobuster tarama sonucu modeli.
    """
    raw_output: str  # Ham çıktı metni
    output_file_json: str  # JSON çıktı dosyası
    findings: Optional[List[GobusterFinding]] = None  # Bulgular listesi
    findings_summary: Optional[GobusterFindingsSummary] = None  # Bulgular özeti
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool  # İşlem başarı durumu
    command: str  # Çalıştırılan komut


class ZapResult(BaseModel):
    """
    OWASP ZAP tarama sonucu modeli.
    """
    raw_output: str  # Ham çıktı metni
    output_file: str  # HTML rapor dosyası
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool  # İşlem başarı durumu
    command: str  # Çalıştırılan komut


class TestsslResult(BaseModel):
    """
    testssl.sh SSL/TLS tarama sonucu modeli.
    """
    raw_output: str  # Ham çıktı metni
    output_file_json: str  # JSON çıktı dosyası
    output_file_txt: str  # TXT çıktı dosyası
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool  # İşlem başarı durumu
    command: str  # Çalıştırılan komut


class DnsreconResult(BaseModel):
    """
    dnsrecon DNS enumeration sonucu modeli.
    """
    raw_output: str  # Ham çıktı metni
    output_file_json: str  # JSON çıktı dosyası
    output_file_txt: str  # TXT çıktı dosyası
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool  # İşlem başarı durumu
    command: str  # Çalıştırılan komut


class TheHarvesterResult(BaseModel):
    """
    theHarvester OSINT tarama sonucu modeli.
    """
    raw_output: str  # Ham çıktı metni
    output_file_json: str  # JSON çıktı dosyası
    output_file_txt: str  # TXT çıktı dosyası
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool  # İşlem başarı durumu
    command: str  # Çalıştırılan komut


class SubfinderResult(BaseModel):
    """
    Subfinder subdomain enumeration sonucu modeli.
    """
    raw_output: str  # Ham çıktı metni
    output_file_json: str  # JSON çıktı dosyası (JSONL format)
    output_file_txt: str  # TXT çıktı dosyası
    normalized_json: Optional[dict] = None  # Normalize edilmiş JSON içeriği (frontend için)
    success: bool  # İşlem başarı durumu
    command: str  # Çalıştırılan komut


class ScanCommand(BaseModel):
    """
    Tarama komutu modeli (gelecekte kullanım için).
    """
    tool: str  # Araç adı
    command: List[str]  # Komut argümanları
    output_file: str  # Çıktı dosyası yolu
    description: str  # Komut açıklaması


class ScanPlan(BaseModel):
    """
    Tarama planı modeli.
    
    Tüm araç sonuçlarını içeren ana model.
    Frontend'e dönen yanıt bu formattadır.
    """
    target_url: str  # Normalize edilmiş hedef URL
    tools: List[str]  # Çalıştırılan araç listesi
    output_dir: str  # Çıktı dizini
    commands: List[ScanCommand]  # Komut listesi (şu an boş)
    ping_result: Optional[PingResult] = None  # Ping sonucu
    whois_result: Optional[WhoisResult] = None  # Whois sonucu
    nmap_result: Optional[NmapResult] = None  # Nmap sonucu
    nikto_result: Optional[NiktoResult] = None  # Nikto sonucu
    gobuster_result: Optional[GobusterResult] = None  # Gobuster sonucu
    zap_result: Optional[ZapResult] = None  # ZAP sonucu
    testssl_result: Optional[TestsslResult] = None  # testssl.sh sonucu
    dnsrecon_result: Optional[DnsreconResult] = None  # dnsrecon sonucu
    theharvester_result: Optional[TheHarvesterResult] = None  # theHarvester sonucu
    subfinder_result: Optional[SubfinderResult] = None  # Subfinder sonucu
    note: str  # Not/özet bilgi


