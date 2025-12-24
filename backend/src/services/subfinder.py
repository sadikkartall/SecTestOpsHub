import os
import subprocess
import json
import re
from datetime import datetime
from uuid import uuid4
from typing import Optional

from ..models.scan import SubfinderResult
from ..models.normalized import NormalizedResult, Finding


def run_subfinder(target_domain: str, output_dir: str) -> SubfinderResult:
    """
    Hedef domain için subfinder subdomain enumeration çalıştırır.
    subfinder domain bekler, IP adresi değil.
    JSON çıktı -oJ parametresi ile üretilir.
    """
    os.makedirs(output_dir, exist_ok=True)

    scan_id = uuid4()
    output_json = os.path.join(output_dir, f"subfinder-{scan_id}.json")
    output_txt = os.path.join(output_dir, f"subfinder-{scan_id}.txt")

    # subfinder komutu: pasif mod (hızlı ve güvenilir)
    # -d: Hedef domain
    # -oJ: JSON çıktı formatı
    # -silent: Sadece subdomain'leri göster (progress bar yok)
    # -timeout: Her kaynak için timeout (saniye)
    cmd = [
        "subfinder",
        "-d",
        target_domain,
        "-oJ",
        output_json,  # JSON çıktı dosyası
        "-silent",  # Sadece subdomain'leri göster
        "-timeout", "60",  # Her kaynak için 60 saniye timeout
    ]

    start_time = datetime.now()
    timeout_occurred = False
    proc = None
    try:
        # subfinder genelde 1-3 dakika sürer
        # Büyük domain'ler için 5 dakika yeterli
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,  # 5 dakikalık üst sınır
        )
    except subprocess.TimeoutExpired:
        timeout_occurred = True
        # Timeout oldu ama JSON dosyası oluşturulmuş olabilir, kontrol edelim
        proc = None
    except Exception as e:
        # Beklenmeyen hata (subfinder komutu bulunamadı, vb.)
        proc = None
    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    # stdout ve stderr'i hazırla
    raw_output = ""
    if proc:
        raw_output = (proc.stdout or "").strip()
        if proc.stderr:
            stderr_text = (proc.stderr or "").strip()
            if stderr_text:
                # stderr'de genelde progress bilgileri var, bunları filtrele
                # Sadece gerçek hata mesajlarını göster
                error_lines = [line for line in stderr_text.split('\n') 
                              if line.strip() and not any(x in line.lower() for x in ['inf', 'wrn', 'loading', 'enumerating', 'found'])]
                if error_lines:
                    raw_output = f"{raw_output}\n{chr(10).join(error_lines)}" if raw_output else chr(10).join(error_lines)
    else:
        # Timeout oldu, JSON dosyasından özet bilgi çıkar
        if os.path.exists(output_json):
            try:
                with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    valid_json_lines = [line for line in lines if line.strip() and line.strip().startswith('{')]
                    if valid_json_lines:
                        subdomains = set()
                        for line in valid_json_lines:
                            try:
                                data = json.loads(line)
                                if 'host' in data:
                                    host = data['host']
                                    # Ana domain'i filtrele
                                    if host.lower() != target_domain.lower():
                                        subdomains.add(host)
                            except:
                                pass
                        if subdomains:
                            raw_output = f"Subfinder taraması zaman aşımına uğradı (5 dakika), ancak kısmi sonuçlar alındı.\n{len(subdomains)} subdomain bulundu:\n" + "\n".join(sorted(subdomains)[:20])
                            if len(subdomains) > 20:
                                raw_output += f"\n... ve {len(subdomains) - 20} subdomain daha (JSON dosyasına bakın)"
            except:
                raw_output = "Subfinder taraması zaman aşımına uğradı (5 dakika)."

    # JSON çıktısını txt dosyasına da kopyala (okunabilirlik için)
    if os.path.exists(output_json):
        try:
            with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                json_content = f.read()
            with open(output_txt, "w", encoding="utf-8") as f:
                f.write(json_content)
        except Exception:
            pass  # Hata durumunda devam et

    # JSON dosyası kontrolü: Dosya varsa ve içinde veri varsa başarılı say
    json_file_exists = os.path.exists(output_json)
    json_file_has_data = False
    success = False

    # Önce komut başarılı mı kontrol et
    if proc:
        success = proc.returncode == 0
        # Komut başarısız olsa bile JSON dosyası oluşturulmuş olabilir
        if not success and proc.stderr:
            # Hata mesajını kontrol et
            error_msg = proc.stderr.strip()
            # Eğer JSON dosyası oluşturulmuşsa başarılı say
            if json_file_exists:
                success = True

    # JSON dosyası kontrolü
    if json_file_exists:
        try:
            file_size = os.path.getsize(output_json)
            if file_size > 0:
                # Dosya boş değil, içeriğini kontrol et
                with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                    if content and len(content) > 0:
                        # En az bir geçerli JSON satırı var mı kontrol et
                        lines = content.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line and line.startswith('{'):
                                try:
                                    # JSON parse edilebiliyor mu kontrol et
                                    data = json.loads(line)
                                    if isinstance(data, dict) and data.get("host"):
                                        json_file_has_data = True
                                        success = True
                                        break
                                except:
                                    continue
                        # Eğer hiçbir satır parse edilemediyse ama dosya varsa, yine de başarılı say
                        if not json_file_has_data and file_size > 10:  # En az 10 byte içerik varsa
                            success = True
                            json_file_has_data = True
        except Exception:
            pass

    # Timeout olduysa ve JSON dosyası yoksa hata fırlat
    if timeout_occurred and not success:
        if json_file_exists:
            # JSON dosyası var, başarılı say (içeriği normalize_subfinder kontrol edecek)
            success = True
        else:
            # JSON dosyası yok, hata mesajı ver ama exception fırlatma
            # Normalize et ve boş sonuç döndür
            pass

    # Normalize et (timeout olsa bile JSON dosyası varsa sonuçları göster)
    # stdout ve stderr'i hazırla
    stdout_text = proc.stdout if proc else ""
    stderr_text = proc.stderr if proc else ""
    
    # Eğer stdout boşsa ama JSON dosyası varsa, JSON içeriğini stdout'a ekle
    # Bu sayede normalize_subfinder hem JSON dosyasını hem de stdout'u parse edebilir
    # Ayrıca raw_output içindeki JSON satırlarını da stdout'a ekle
    if json_file_exists:
        try:
            with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                json_lines = f.readlines()
                # Tüm geçerli JSON satırlarını stdout'a ekle (parse için)
                valid_lines = [line.strip() for line in json_lines if line.strip() and line.strip().startswith('{')]
                if valid_lines:
                    json_stdout = "\n".join(valid_lines)
                    # Eğer stdout zaten varsa, birleştir; yoksa sadece JSON'u kullan
                    stdout_text = f"{stdout_text}\n{json_stdout}".strip() if stdout_text else json_stdout
        except:
            pass
    
    # raw_output içindeki JSON satırlarını da stdout'a ekle (eğer varsa)
    if raw_output:
        json_lines_in_raw = [line.strip() for line in raw_output.split('\n') 
                             if line.strip() and line.strip().startswith('{')]
        if json_lines_in_raw:
            json_from_raw = "\n".join(json_lines_in_raw)
            if json_from_raw not in stdout_text:
                stdout_text = f"{stdout_text}\n{json_from_raw}".strip() if stdout_text else json_from_raw

    # Eğer JSON dosyası yoksa ve stderr'de hata varsa, hatayı göster
    if not json_file_exists and stderr_text:
        # Subfinder komutu çalışmadı veya hata verdi
        error_msg = stderr_text.strip()
        if error_msg:
            stdout_text = f"Subfinder komutu hatası:\n{error_msg}"

    normalized_result = normalize_subfinder(
        raw_stdout=stdout_text,
        raw_stderr=stderr_text,
        exit_code=proc.returncode if proc else -1,
        target=target_domain,
        command=" ".join(cmd),
        json_file_path=output_json if json_file_exists else None,
        duration_ms=duration_ms,
        raw_output=raw_output  # Ham çıktıyı da geç (içinde JSON satırları olabilir)
    )

    output_normalized_json = os.path.join(output_dir, f"subfinder-{scan_id}-normalized.json")
    with open(output_normalized_json, "w", encoding="utf-8") as f:
        json.dump(normalized_result.model_dump(), f, indent=2, ensure_ascii=False)

    # Clean raw output for display
    cleaned_raw_output = raw_output

    return SubfinderResult(
        raw_output=cleaned_raw_output,
        output_file_json=output_json,
        output_file_txt=output_txt,
        normalized_json=normalized_result.model_dump(),
        success=success,
        command=" ".join(cmd),
    )


def normalize_subfinder(
    raw_stdout: str,
    raw_stderr: str,
    exit_code: int,
    target: str,
    command: str,
    json_file_path: Optional[str] = None,
    duration_ms: Optional[int] = None,
    raw_output: Optional[str] = None
) -> NormalizedResult:
    """Normalize subfinder output according to the shared contract."""
    output = (raw_stdout or "").strip()
    error_output = (raw_stderr or "").strip()
    # raw_output içindeki JSON satırlarını da output'a ekle
    if raw_output:
        raw_json_lines = [line.strip() for line in raw_output.split('\n') 
                         if line.strip() and line.strip().startswith('{')]
        if raw_json_lines:
            raw_json_content = "\n".join(raw_json_lines)
            if raw_json_content not in output:
                output = f"{output}\n{raw_json_content}".strip() if output else raw_json_content

    metrics = {
        "target": target,
        "subdomains": [],
        "total_subdomains": 0,
        "sources": [],
        "duration_ms": duration_ms
    }

    findings = []
    status = "partial"
    summary = f"Subfinder scan for {target} completed with partial parsing."

    # Tüm JSON satırlarını topla ve parse et
    subdomains_set = set()
    sources_set = set()
    all_json_lines = []
    
    # 1. JSON dosyasından oku
    if json_file_path and os.path.exists(json_file_path):
        try:
            with open(json_file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
                if content:
                    all_json_lines.extend([line.strip() for line in content.split('\n') 
                                          if line.strip() and line.strip().startswith('{')])
        except:
            pass
    
    # 2. stdout'dan oku
    if output:
        all_json_lines.extend([line.strip() for line in output.split('\n') 
                              if line.strip() and line.strip().startswith('{')])
    
    # 3. Tüm JSON satırlarını parse et
    target_lower = target.lower().strip()
    for line in all_json_lines:
        try:
            data = json.loads(line)
            subdomain = data.get("host", "")
            source = data.get("source", "")
            ip = data.get("ip", "")

            if subdomain and subdomain.strip():
                subdomain_clean = subdomain.strip()
                subdomain_lower = subdomain_clean.lower()
                
                # Ana domain'i subdomain listesinden çıkar (sadece gerçek subdomain'ler)
                # Subdomain, target domain ile bitmeli (örn: .iana.org) ve target domain'den farklı olmalı
                if (subdomain_lower != target_lower and 
                    subdomain_lower.endswith('.' + target_lower)):
                    subdomains_set.add(subdomain_clean)
                    if source:
                        sources_set.add(source)

                    findings.append(Finding(
                        type="subdomain_discovery",
                        severity="INFO",
                        title=f"Subdomain found: {subdomain_clean}",
                        evidence={
                            "subdomain": subdomain_clean,
                            "ip": ip,
                            "source": source,
                            "domain": target
                        }
                    ))
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError, ValueError):
            continue
    
    # Metrics'i güncelle
    metrics["subdomains"] = sorted(list(subdomains_set))
    metrics["total_subdomains"] = len(subdomains_set)
    metrics["sources"] = sorted(list(sources_set))

    # Determine status
    if metrics["total_subdomains"] > 0:
        status = "success"
        summary = f"Subfinder found {metrics['total_subdomains']} unique subdomain(s) for {target}."
        if metrics["sources"]:
            summary += f" Sources: {', '.join(metrics['sources'][:5])}"
            if len(metrics["sources"]) > 5:
                summary += f" and {len(metrics['sources']) - 5} more"
    else:
        status = "success"
        summary = f"Subfinder scan completed for {target} but found no subdomains."

    return NormalizedResult(
        tool="subfinder",
        target=target,
        status=status,
        summary=summary,
        findings=findings,
        metrics=metrics,
        raw={"stdout": raw_stdout, "stderr": raw_stderr, "exit_code": exit_code, "command": command}
    )
