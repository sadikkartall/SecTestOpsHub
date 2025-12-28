import os
import subprocess
import shutil
import json
import re
from datetime import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any
from bs4 import BeautifulSoup

from ..models.scan import ZapResult
from ..models.normalized import NormalizedResult, Finding

ZAP_CONTAINER = "sectestops-zap"
ZAP_WORKDIR = "/zap/wrk"


def run_zap_quick(target_url: str, output_dir: str) -> ZapResult:
    """
    ZAP hızlı tarama (quick scan) çalıştırır ve HTML çıktı üretir.
    Backend içinden docker exec ile ZAP konteynerine komut gönderilir.
    """
    docker_bin = shutil.which("docker")
    if not docker_bin:
        raise RuntimeError("Docker CLI bulunamadı. Backend imajında docker.io kurulmalı ve /var/run/docker.sock mount edilmeli.")

    os.makedirs(output_dir, exist_ok=True)

    # Host tarafında rapor yolu
    host_output_file = os.path.join(output_dir, f"zap-{uuid4()}.html")
    # ZAP konteynerinin göreceği yol
    zap_output_file = os.path.join(ZAP_WORKDIR, os.path.basename(host_output_file))

    cmd = [
        docker_bin,
        "exec",
        ZAP_CONTAINER,
        "zap.sh",
        "-cmd",
        "-quickurl",
        target_url,
        "-quickout",
        zap_output_file,
    ]

    start_time = datetime.now()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=900,  # 15 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("ZAP hızlı tarama zaman aşımına uğradı.")
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    raw_output = (proc.stdout or "").strip()
    if not raw_output and proc.stderr:
        raw_output = proc.stderr.strip()

    # HTML dosyası varsa normalize et
    normalized_result = None
    if os.path.exists(host_output_file):
        try:
            with open(host_output_file, "r", encoding="utf-8", errors="ignore") as f:
                html_content = f.read()
            
            normalized_result = normalize_zap(
                html_content=html_content,
                raw_stdout=proc.stdout or "",
                raw_stderr=proc.stderr or "",
                exit_code=proc.returncode,
                target=target_url,
                command=" ".join(cmd),
                html_file_path=host_output_file,
                duration_ms=duration_ms
            )
        except Exception as e:
            # Normalizasyon hatası durumunda devam et
            pass

    return ZapResult(
        raw_output=raw_output,
        output_file=host_output_file,
        normalized_json=normalized_result.model_dump() if normalized_result else None,
        success=proc.returncode == 0,
        command=" ".join(cmd),
    )


def normalize_zap(
    html_content: str,
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    html_file_path: Optional[str] = None,
    duration_ms: Optional[int] = None
) -> NormalizedResult:
    """Normalize ZAP HTML output according to the shared contract."""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    metrics = {
        "target": target,
        "zap_version": None,
        "scan_date": None,
        "risk_summary": {
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "false_positives": 0
        },
        "total_alerts": 0,
        "alerts": [],
        "duration_ms": duration_ms
    }
    
    findings = []
    status = "partial"
    
    # ZAP Version ve tarih bilgisi
    h3_tags = soup.find_all('h3')
    for h3 in h3_tags:
        text = h3.get_text().strip()
        if 'Generated on' in text:
            metrics["scan_date"] = text.replace('Generated on', '').strip()
        elif 'ZAP Version:' in text:
            metrics["zap_version"] = text.replace('ZAP Version:', '').strip()
    
    # Site bilgisi
    h2_tag = soup.find('h2')
    if h2_tag:
        site_text = h2_tag.get_text().strip()
        if 'Site:' in site_text:
            metrics["target"] = site_text.replace('Site:', '').strip()
    
    # Summary of Alerts tablosunu parse et
    summary_table = soup.find('table', class_='summary')
    if summary_table:
        rows = summary_table.find_all('tr')[1:]  # İlk satır header
        for row in rows:
            cells = row.find_all('td')
            if len(cells) >= 2:
                risk_level_cell = cells[0]
                count_cell = cells[1]
                
                risk_text = risk_level_cell.get_text().strip()
                count_text = count_cell.get_text().strip()
                
                try:
                    count = int(count_text)
                    if 'High' in risk_text:
                        metrics["risk_summary"]["high"] = count
                    elif 'Medium' in risk_text:
                        metrics["risk_summary"]["medium"] = count
                    elif 'Low' in risk_text:
                        metrics["risk_summary"]["low"] = count
                    elif 'Informational' in risk_text:
                        metrics["risk_summary"]["informational"] = count
                    elif 'False Positives' in risk_text:
                        metrics["risk_summary"]["false_positives"] = count
                except ValueError:
                    pass
    
    # Alerts tablosunu parse et
    alerts_table = soup.find('table', class_='alerts')
    if alerts_table:
        rows = alerts_table.find_all('tr')[1:]  # İlk satır header
        for row in rows:
            cells = row.find_all('td')
            if len(cells) >= 3:
                name_cell = cells[0]
                risk_cell = cells[1]
                count_cell = cells[2]
                
                alert_name = name_cell.get_text().strip()
                risk_level = risk_cell.get_text().strip()
                count_text = count_cell.get_text().strip()
                
                try:
                    count = int(count_text)
                    alert_id = None
                    # Alert ID'yi link'ten çıkar
                    link = name_cell.find('a')
                    if link and link.get('href'):
                        href = link.get('href')
                        match = re.search(r'#(\d+)', href)
                        if match:
                            alert_id = match.group(1)
                    
                    alert_info = {
                        "id": alert_id,
                        "name": alert_name,
                        "risk_level": risk_level,
                        "instances": count
                    }
                    metrics["alerts"].append(alert_info)
                    metrics["total_alerts"] += count
                except ValueError:
                    pass
    
    # Alert isimlerini Türkçe'ye çevir
    def translate_alert_name(alert_name: str) -> str:
        """Yaygın ZAP alert isimlerini Türkçe'ye çevirir."""
        translations = {
            "Content Security Policy (CSP) Header Not Set": "Content Security Policy (CSP) Başlığı Ayarlanmamış",
            "Directory Browsing": "Dizin Tarama",
            "HTTP Only Site": "Sadece HTTP Kullanan Site",
            "Missing Anti-clickjacking Header": "Anti-clickjacking Başlığı Eksik",
            "Sub Resource Integrity Attribute Missing": "Sub Resource Integrity Özelliği Eksik",
            "In Page Banner Information Leak": "Sayfa İçi Banner Bilgi Sızıntısı",
            "Server Leaks Version Information via \"Server\" HTTP Response Header Field": "Sunucu \"Server\" HTTP Yanıt Başlığı Üzerinden Versiyon Bilgisi Sızdırıyor",
            "X-Content-Type-Options Header Missing": "X-Content-Type-Options Başlığı Eksik",
            "Modern Web Application": "Modern Web Uygulaması",
            "User Agent Fuzzer": "User Agent Fuzzer",
            "Cross Site Scripting (Reflected)": "Cross Site Scripting (Yansıtılmış)",
            "Cross Site Scripting (Stored)": "Cross Site Scripting (Depolanmış)",
            "SQL Injection": "SQL Injection",
            "Path Traversal": "Path Traversal",
            "Remote File Inclusion": "Uzak Dosya Ekleme",
            "Command Injection": "Komut Injection",
            "XML External Entity (XXE)": "XML External Entity (XXE)",
            "Server-Side Request Forgery (SSRF)": "Server-Side Request Forgery (SSRF)",
            "Insecure HTTP Methods": "Güvensiz HTTP Metodları",
            "Absence of Anti-CSRF Tokens": "Anti-CSRF Token Eksikliği",
            "Cookie Without Secure Flag": "Secure Bayrağı Olmayan Cookie",
            "Cookie Without HttpOnly Flag": "HttpOnly Bayrağı Olmayan Cookie",
            "Weak Authentication": "Zayıf Kimlik Doğrulama",
            "Session Fixation": "Oturum Sabitleme",
            "Insecure Randomness": "Güvensiz Rastgelelik",
            "Timestamp Disclosure": "Zaman Damgası Açığa Çıkması",
            "Information Disclosure - Debug Error Messages": "Bilgi Açığa Çıkması - Debug Hata Mesajları",
            "Information Disclosure - Sensitive Information in URL": "Bilgi Açığa Çıkması - URL'de Hassas Bilgi",
            "Information Disclosure - Suspicious Comments": "Bilgi Açığa Çıkması - Şüpheli Yorumlar",
        }
        return translations.get(alert_name, alert_name)
    
    # Description ve Solution metinlerini Türkçe'ye çevir
    def translate_description_solution(alert_name: str, description: str, solution: str) -> tuple[str, str]:
        """Alert tipine göre description ve solution metinlerini Türkçe'ye çevirir."""
        # Description çevirileri
        desc_translations = {
            "Content Security Policy (CSP) Header Not Set": "Content Security Policy (CSP), Cross Site Scripting (XSS) ve veri enjeksiyon saldırıları gibi belirli saldırı türlerini tespit etmeye ve azaltmaya yardımcı olan ek bir güvenlik katmanıdır. Bu saldırılar, veri hırsızlığından site defacement'ine kadar her şey için kullanılabilir.",
            "Directory Browsing": "Dizin listesini görüntülemek mümkündür. Dizin listesi, hassas bilgileri okumak için erişilebilen gizli script'leri, include dosyalarını, yedek kaynak dosyalarını vb. ortaya çıkarabilir.",
            "HTTP Only Site": "Site sadece HTTP altında sunulmaktadır ve HTTPS kullanmamaktadır.",
            "Missing Anti-clickjacking Header": "Yanıt 'ClickJacking' saldırılarına karşı koruma sağlamamaktadır. 'frame-ancestors' direktifi ile Content-Security-Policy veya X-Frame-Options içermelidir.",
            "Sub Resource Integrity Attribute Missing": "Harici bir sunucu tarafından sunulan bir script veya link etiketinde integrity özelliği eksiktir. Integrity etiketi, bu sunucuya erişim kazanmış bir saldırganın kötü amaçlı içerik enjekte etmesini önler.",
            "In Page Banner Information Leak": "Sunucu, yanıt içeriğinde bir versiyon banner dizisi döndürdü. Bu tür bilgi sızıntıları, saldırganların belirli sorunları etkileyen sistemleri daha fazla hedeflemesine izin verebilir.",
            "Server Leaks Version Information via \"Server\" HTTP Response Header Field": "Web/uygulama sunucusu, \"Server\" HTTP yanıt başlığı üzerinden versiyon bilgisi sızdırıyor. Bu tür bilgilere erişim, saldırganların bilinen güvenlik açıklarını hedeflemesini kolaylaştırabilir.",
            "X-Content-Type-Options Header Missing": "Anti-MIME-Sniffing başlığı X-Content-Type-Options 'nosniff' olarak ayarlanmamış. Bu, Internet Explorer ve Chrome'un eski sürümlerinin MIME türü algılaması yapmasına izin verir.",
        }
        
        # Solution çevirileri
        sol_translations = {
            "Content Security Policy (CSP) Header Not Set": "Web sunucunuzun, uygulama sunucunuzun, yük dengeleyicinizin vb. Content-Security-Policy başlığını ayarlamak üzere yapılandırıldığından emin olun.",
            "Directory Browsing": "Dizin taramayı devre dışı bırakın. Bu gerekliyse, listelenen dosyaların risk oluşturmadığından emin olun.",
            "HTTP Only Site": "Web veya uygulama sunucunuzu SSL (https) kullanacak şekilde yapılandırın.",
            "Missing Anti-clickjacking Header": "Modern Web tarayıcıları Content-Security-Policy ve X-Frame-Options HTTP başlıklarını destekler. Web sunucunuzun döndürdüğü tüm web sayfalarında bunlardan birinin ayarlandığından emin olun.",
            "Sub Resource Integrity Attribute Missing": "Etikete geçerli bir integrity özelliği sağlayın.",
            "In Page Banner Information Leak": "Sunucu yanıtlarından banner bilgilerini kaldırın.",
            "Server Leaks Version Information via \"Server\" HTTP Response Header Field": "Sunucu yanıt başlığından versiyon bilgisini kaldırın veya genel bir değer kullanın.",
            "X-Content-Type-Options Header Missing": "Tüm web sayfalarında X-Content-Type-Options başlığını 'nosniff' olarak ayarlayın.",
        }
        
        translated_desc = desc_translations.get(alert_name, description)
        translated_sol = sol_translations.get(alert_name, solution)
        
        return translated_desc, translated_sol
    
    # Alert Detail bölümlerini parse et
    alert_detail_sections = soup.find_all('table', class_='results')
    for section in alert_detail_sections:
        # Alert başlığını bul
        header_row = section.find('tr', height="24")
        if not header_row:
            continue
        
        th_tags = header_row.find_all('th')
        if len(th_tags) < 2:
            continue
        
        risk_th = th_tags[0]
        name_th = th_tags[1]
        
        risk_level = risk_th.get_text().strip()
        alert_name = name_th.get_text().strip()
        
        # Alert ID'yi bul
        alert_id = None
        link = risk_th.find('a')
        if link and link.get('id'):
            alert_id = link.get('id')
        
        # Description'ı bul
        description = ""
        desc_row = section.find('td', string=re.compile('Description', re.I))
        if desc_row:
            desc_cell = desc_row.find_next_sibling('td')
            if desc_cell:
                desc_div = desc_cell.find('div')
                if desc_div:
                    description = desc_div.get_text().strip()
        
        # URL'leri topla
        urls = []
        url_rows = section.find_all('td', class_='indent1', string=re.compile('URL', re.I))
        for url_row in url_rows:
            url_cell = url_row.find_next_sibling('td')
            if url_cell:
                url_link = url_cell.find('a')
                if url_link:
                    url = url_link.get('href') or url_link.get_text().strip()
                    if url:
                        urls.append(url)
        
        # Solution'ı bul
        solution = ""
        sol_row = section.find('td', string=re.compile('Solution', re.I))
        if sol_row:
            sol_cell = sol_row.find_next_sibling('td')
            if sol_cell:
                sol_div = sol_cell.find('div')
                if sol_div:
                    solution = sol_div.get_text().strip()
        
        # CWE ve WASC ID'leri bul
        cwe_id = None
        wasc_id = None
        plugin_id = None
        
        cwe_row = section.find('td', string=re.compile('CWE Id', re.I))
        if cwe_row:
            cwe_cell = cwe_row.find_next_sibling('td')
            if cwe_cell:
                cwe_link = cwe_cell.find('a')
                if cwe_link:
                    cwe_id = cwe_link.get_text().strip()
        
        wasc_row = section.find('td', string=re.compile('WASC Id', re.I))
        if wasc_row:
            wasc_cell = wasc_row.find_next_sibling('td')
            if wasc_cell:
                wasc_id = wasc_cell.get_text().strip()
        
        plugin_row = section.find('td', string=re.compile('Plugin Id', re.I))
        if plugin_row:
            plugin_cell = plugin_row.find_next_sibling('td')
            if plugin_cell:
                plugin_link = plugin_cell.find('a')
                if plugin_link:
                    plugin_id = plugin_link.get_text().strip()
        
        # Risk seviyesini severity'ye map et
        severity = "INFO"
        if 'High' in risk_level:
            severity = "HIGH"
        elif 'Medium' in risk_level:
            severity = "MEDIUM"
        elif 'Low' in risk_level:
            severity = "LOW"
        
        # Alert ismini Türkçe'ye çevir
        translated_alert_name = translate_alert_name(alert_name)
        
        # Description ve Solution'ı Türkçe'ye çevir
        translated_description, translated_solution = translate_description_solution(alert_name, description, solution)
        
        findings.append(Finding(
            type="security_alert",
            severity=severity,
            title=translated_alert_name,
            evidence={
                "alert_id": alert_id,
                "description": translated_description,
                "urls": urls[:10],  # İlk 10 URL
                "solution": translated_solution,
                "cwe_id": cwe_id,
                "wasc_id": wasc_id,
                "plugin_id": plugin_id
            }
        ))
    
    # Status belirle
    total_risk = (metrics["risk_summary"]["high"] + 
                  metrics["risk_summary"]["medium"] + 
                  metrics["risk_summary"]["low"] + 
                  metrics["risk_summary"]["informational"])
    
    if total_risk > 0:
        status = "success"
        summary = f"ZAP taraması {total_risk} güvenlik uyarısı buldu: {metrics['risk_summary']['high']} Yüksek, {metrics['risk_summary']['medium']} Orta, {metrics['risk_summary']['low']} Düşük, {metrics['risk_summary']['informational']} Bilgilendirme."
    else:
        status = "success"
        summary = f"ZAP taraması {target} için tamamlandı. Güvenlik uyarısı bulunamadı."
    
    return NormalizedResult(
        tool="zap",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )

