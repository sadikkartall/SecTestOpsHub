// Modern API istemcisi; tüm yorumlar Türkçe tutulmuştur

const form = document.getElementById("scan-form");
const resultEl = document.getElementById("result");
const submitBtn = document.getElementById("submit-btn");
const cancelBtn = document.getElementById("cancel-btn");
const buttonText = submitBtn.querySelector(".button-text");
const buttonLoader = submitBtn.querySelector(".button-loader");

// Yardımcı: API kök adresi; gerekirse reverse proxy ile güncellenebilir
const API_BASE = "http://localhost:8000";

// AbortController for request cancellation
let abortController = null;

// JSON indirme fonksiyonu (window'a ekleniyor ki inline onclick'ten erişilebilsin)
window.downloadJSON = function(jsonString, filename) {
  const blob = new Blob([jsonString], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

// PDF indirme fonksiyonu (window'a ekleniyor ki inline onclick'ten erişilebilsin)
window.downloadPDF = function(jsonData, filename) {
  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    
    // Başlık
    doc.setFontSize(16);
    doc.text('JSON Report', 14, 20);
    
    // JSON'u düzgün formatlanmış string'e çevir
    const jsonString = JSON.stringify(jsonData, null, 2);
    
    // PDF'e yazmak için text'i satırlara böl
    const lines = doc.splitTextToSize(jsonString, 180);
    
    // İçeriği yaz
    doc.setFontSize(10);
    doc.setFont(undefined, 'courier');
    doc.text(lines, 14, 30);
    
    // Dosyayı indir
    doc.save(filename.replace('.txt', '.pdf'));
  } catch (error) {
    console.error('PDF oluşturma hatası:', error);
    alert('PDF oluşturulurken bir hata oluştu.');
  }
};

// Loading state yönetimi
function setLoading(isLoading) {
  if (isLoading) {
    submitBtn.disabled = true;
    buttonText.style.display = "none";
    buttonLoader.style.display = "flex";
    cancelBtn.style.display = "flex";
    const loadingText = typeof t !== 'undefined' ? t('loadingText') : '[SYSTEM] Scanning in progress... Please wait...';
    resultEl.innerHTML = `
      <div class="loading-state">
        <div class="loading-spinner"></div>
        <p>${loadingText}</p>
      </div>
    `;
  } else {
    submitBtn.disabled = false;
    buttonText.style.display = "block";
    buttonLoader.style.display = "none";
    cancelBtn.style.display = "none";
    abortController = null;
  }
}

// Cancel button handler
cancelBtn.addEventListener("click", () => {
  if (abortController) {
    abortController.abort();
    setLoading(false);
    const abortTitle = typeof t !== 'undefined' ? t('scanAborted') : '[ABORTED] Scan Terminated';
    const abortMsg = typeof t !== 'undefined' ? t('scanCancelled') : '[WARNING] Operation cancelled by user. Ready for new scan command.';
    resultEl.innerHTML = `
      <div class="result-card warning">
        <h3>${abortTitle}</h3>
        <p>${abortMsg}</p>
      </div>
    `;
  }
});

// Form gönderimi ile tarama planı oluşturulur
form.addEventListener("submit", async (event) => {
  event.preventDefault();

  // Form verileri okunuyor
  const targetUrl = document.getElementById("target-url").value.trim();
  const toolNodes = [...document.querySelectorAll('input[name="tool"]:checked')];
  const tools = toolNodes.map((n) => n.value);

  // Basit doğrulama: URL var mı
  if (!targetUrl) {
    const errorTitle = typeof t !== 'undefined' ? t('errorInvalidInput') : '[ERROR] Invalid Input';
    const errorMsg = typeof t !== 'undefined' ? t('errorRequired') : '[REQUIRED] Target URL/IP/domain is required. Please provide a valid target.';
    resultEl.innerHTML = `
      <div class="result-card error">
        <h3>${errorTitle}</h3>
        <p>${errorMsg}</p>
      </div>
    `;
    return;
  }

  // Loading state aktif
  setLoading(true);
  
  // AbortController oluştur
  abortController = new AbortController();

  try {
    const response = await fetch(`${API_BASE}/scans/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_url: targetUrl,
        tools: tools.length ? tools : null,
      }),
      signal: abortController.signal, // AbortController'ı bağla
    });

    if (!response.ok) {
      const error = await response.json();
      setLoading(false);
      const errorTitle = typeof t !== 'undefined' ? t('errorRequestFailed') : '[ERROR] Request Failed';
      const errorDetail = typeof t !== 'undefined' ? t('errorDetail') : '[DETAIL]';
      const errorUnknown = typeof t !== 'undefined' ? t('errorUnknown') : 'Unknown error occurred';
      resultEl.innerHTML = `
        <div class="result-card error">
          <h3>${errorTitle}</h3>
          <p><strong>${errorDetail}</strong> ${error.detail || errorUnknown}</p>
        </div>
      `;
      return;
    }

    const data = await response.json();
    setLoading(false);

    // Debug: Console'a yazdır
    console.log("Ping result:", data.ping_result);
    console.log("Normalized JSON:", data.ping_result?.normalized_json);

    // Sonuçları kullanıcıya okunaklı formatta göster
    const statusClass = (status) => {
      if (status === 'success') return 'success';
      if (status === 'failed') return 'error';
      return 'warning';
    };

    const scanPlanTitle = typeof t !== 'undefined' ? t('scanPlan') : '[SCAN PLAN] Execution Ready';
    const scanTarget = typeof t !== 'undefined' ? t('scanTarget') : '[TARGET]';
    const scanTools = typeof t !== 'undefined' ? t('scanTools') : '[TOOLS]';
    const scanOutputDir = typeof t !== 'undefined' ? t('scanOutputDir') : '[OUTPUT_DIR]';
    resultEl.innerHTML = `
      <div class="result-card success">
        <h3>${scanPlanTitle}</h3>
        <p><strong>${scanTarget}:</strong> <span style="color: var(--text-success);">${data.target_url}</span></p>
        <p><strong>${scanTools}:</strong> ${data.tools.join(", ")}</p>
        <p><strong>${scanOutputDir}:</strong> <code>${data.output_dir}</code></p>
      </div>
      ${
        data.ping_result
          ? (() => {
              const ping = data.ping_result;
              const norm = ping.normalized_json;
              console.log("norm:", norm);
              if (!norm) {
                console.log("normalized_json is null/undefined, showing raw output");
                return `<p><strong>Ping Çıktısı:</strong></p><pre class="pre-block">${ping.raw_output || "Çıktı yok"}</pre>`;
              }
              const metrics = norm.metrics || {};
              const packets = metrics.packets || {};
              const rtt = metrics.rtt_ms || {};
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>📡 ${norm.summary || 'Ping Sonuçları'}</h3>
              <p><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p><strong>Hedef:</strong> ${norm.target || ping.ip_address}</p>
              ${metrics.resolved_ip ? `<p><strong>IP Adresi:</strong> <code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px;">${metrics.resolved_ip}</code></p>` : ''}
              ${metrics.reachability ? `<p><strong>Erişilebilirlik:</strong> ${metrics.reachability === 'reachable' ? '✅ Erişilebilir' : metrics.reachability === 'unreachable' ? '❌ Erişilemiyor' : '❓ Bilinmiyor'}</p>` : ''}
              ${packets.sent ? `<p><strong>Paketler:</strong> ${packets.sent} gönderildi, ${packets.received} alındı, ${packets.lost} kayıp (${packets.loss_percent || 0}%)</p>` : ''}
              ${rtt.avg ? `<p><strong>Gecikme (RTT):</strong> Ortalama: ${rtt.avg.toFixed(2)} ms, Min: ${rtt.min?.toFixed(2) || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')} ms, Max: ${rtt.max?.toFixed(2) || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')} ms</p>` : ''}
              ${metrics.duration_ms ? `<p><strong>Süre:</strong> ${metrics.duration_ms} ms</p>` : ''}
              ${norm.findings && norm.findings.length > 0 ? `<p><strong>Bulgular:</strong> ${norm.findings.map(f => f.title).join(', ')}</p>` : ''}
              <details>
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block">${ping.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'ping').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-ping-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'ping').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-ping-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.whois_result
          ? (() => {
              const whois = data.whois_result;
              const norm = whois.normalized_json;
              if (!norm) {
                return `
                  <p><strong>Whois Başarısı:</strong> ${whois.success ? "Evet" : "Hayır"}</p>
            <p><strong>Whois Çıktısı:</strong></p>
                  <pre class="pre-block">${whois.raw_output || "Çıktı yok"}</pre>
                  <p><strong>Whois Dosyası:</strong> ${whois.output_file}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const dates = metrics.dates || {};
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>📋 ${norm.summary || 'Whois Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || metrics.domain || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              ${metrics.domain ? `<p style="color: #212529;"><strong>Domain:</strong> ${metrics.domain}</p>` : ''}
              ${metrics.registrar ? `<p style="color: #212529;"><strong>Registrar:</strong> ${metrics.registrar}</p>` : ''}
              ${dates.creation ? `<p style="color: #212529;"><strong>Kayıt Tarihi:</strong> ${dates.creation}</p>` : ''}
              ${dates.updated ? `<p style="color: #212529;"><strong>Son Güncelleme:</strong> ${dates.updated}</p>` : ''}
              ${dates.expiry ? `<p style="color: #212529;"><strong>Son Kullanma:</strong> ${dates.expiry}</p>` : ''}
              ${metrics.nameservers && metrics.nameservers.length > 0 ? `<p style="color: #212529;"><strong>Name Servers:</strong> ${metrics.nameservers.join(', ')}</p>` : ''}
              ${metrics.ip_range ? `<p style="color: #212529;"><strong>IP Range:</strong> ${metrics.ip_range}</p>` : ''}
              ${metrics.cidr ? `<p style="color: #212529;"><strong>CIDR:</strong> ${metrics.cidr}</p>` : ''}
              ${metrics.netname ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('networkName') : 'Ağ Adı'}:</strong> ${metrics.netname}</p>` : ''}
              ${metrics.organization ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('organization') : 'Kuruluş'}:</strong> ${metrics.organization}</p>` : ''}
              ${metrics.country ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('country') : 'Ülke'}:</strong> ${metrics.country}</p>` : ''}
              ${metrics.abuse_contact ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('abuseContact') : 'Kötüye Kullanım İletişim'}:</strong> ${metrics.abuse_contact}</p>` : ''}
              ${metrics.duration_ms ? `<p style="color: #212529;"><strong>Süre:</strong> ${metrics.duration_ms} ms</p>` : ''}
              ${norm.findings && norm.findings.length > 0 ? `<p style="color: #212529;"><strong>Bulgular:</strong> ${norm.findings.map(f => `${f.severity}: ${f.title}`).join(', ')}</p>` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${whois.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'whois').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-whois-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'whois').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-whois-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.nmap_result
          ? (() => {
              const nmap = data.nmap_result;
              const norm = nmap.normalized_json;
              if (!norm) {
                return `
                  <p><strong>Nmap Başarısı:</strong> ${nmap.success ? "Evet" : "Hayır"}</p>
                  <p><strong>Nmap Komutu:</strong> ${nmap.command}</p>
            <p><strong>Nmap Çıktısı:</strong></p>
                  <pre class="pre-block">${nmap.raw_output || "Çıktı yok"}</pre>
                  <p><strong>Nmap XML:</strong> ${nmap.output_file_xml}</p>
                  <p><strong>Nmap TXT:</strong> ${nmap.output_file_txt}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const ports = metrics.ports || [];
              const open_ports = ports.filter(p => p.state === "open");
              const os = metrics.os || {};
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>🔍 ${norm.summary || 'Nmap Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              <p style="color: #212529;"><strong>Host Durumu:</strong> ${metrics.host_status === 'up' ? `✅ ${typeof t !== 'undefined' ? t('up') : 'Açık'}` : metrics.host_status === 'down' ? `❌ ${typeof t !== 'undefined' ? t('down') : 'Kapalı'}` : `❓ ${typeof t !== 'undefined' ? t('unknown') : 'Bilinmiyor'}`}</p>
              ${metrics.latency_ms ? `<p style="color: #212529;"><strong>Gecikme:</strong> ${metrics.latency_ms} ms</p>` : ''}
              ${open_ports.length > 0 ? `<p style="color: #212529;"><strong>Açık Portlar:</strong> ${open_ports.length} port bulundu</p>` : ''}
              ${os.detected ? `<p style="color: #212529;"><strong>OS Tespiti:</strong> ${os.osclass && os.osclass.length > 0 ? os.osclass[0].name || (typeof t !== 'undefined' ? t('detected') : 'Tespit Edildi') : (typeof t !== 'undefined' ? t('detected') : 'Tespit Edildi')}</p>` : ''}
              ${metrics.scan_duration_seconds ? `<p style="color: #212529;"><strong>Tarama Süresi:</strong> ${metrics.scan_duration_seconds.toFixed(2)} saniye</p>` : ''}
              ${open_ports.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Açık Portlar:</strong></p>
                <table style="width: 100%; border-collapse: collapse; margin-top: 5px;">
                  <thead>
                    <tr style="background: #e9ecef;">
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('port') : 'Port'}</th>
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('state') : 'Durum'}</th>
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('service') : 'Servis'}</th>
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('version') : 'Versiyon'}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${open_ports.map(p => `
                      <tr>
                        <td style="padding: 8px; border: 1px solid #dee2e6;">${p.port}/${p.protocol || 'tcp'}</td>
                        <td style="padding: 8px; border: 1px solid #dee2e6;">${p.state}</td>
                        <td style="padding: 8px; border: 1px solid #dee2e6;">${p.service || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</td>
                        <td style="padding: 8px; border: 1px solid #dee2e6;">${p.version || p.product || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              ` : ''}
              ${norm.findings && norm.findings.length > 0 ? `<p style="color: #212529; margin-top: 10px;"><strong>Bulgular:</strong> ${norm.findings.length} bulgu</p>` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${nmap.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'nmap').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-nmap-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'nmap').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-nmap-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.nikto_result
          ? (() => {
              const nikto = data.nikto_result;
              const norm = nikto.normalized_json;
              if (!norm) {
                return `
                  <p><strong>Nikto Başarısı:</strong> ${nikto.success ? "Evet" : "Hayır"}</p>
                  <p><strong>Nikto Komutu:</strong> ${nikto.command}</p>
            <p><strong>Nikto Çıktısı:</strong></p>
                  <pre class="pre-block">${nikto.raw_output || "Çıktı yok"}</pre>
                  <p><strong>Nikto JSON:</strong> ${nikto.output_file_json}</p>
                  <p><strong>Nikto TXT:</strong> ${nikto.output_file_txt}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const severity_counts = metrics.items_by_severity || {};
              const findings = norm.findings || [];
              const critical_findings = findings.filter(f => f.severity === "CRITICAL");
              const high_findings = findings.filter(f => f.severity === "HIGH");
              const medium_findings = findings.filter(f => f.severity === "MEDIUM");
              const low_findings = findings.filter(f => f.severity === "LOW");
              const info_findings = findings.filter(f => f.severity === "INFO");
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>🛡️ ${norm.summary || 'Nikto Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              ${metrics.target_ip ? `<p style="color: #212529;"><strong>IP Adresi:</strong> ${metrics.target_ip}</p>` : ''}
              ${metrics.target_hostname ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('hostname') : 'Host Adı'}:</strong> ${metrics.target_hostname}</p>` : ''}
              ${metrics.port ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('port') : 'Port'}:</strong> ${metrics.port}</p>` : ''}
              ${metrics.server ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('server') : 'Sunucu'}:</strong> ${metrics.server}</p>` : ''}
              ${metrics.start_time ? `<p style="color: #212529;"><strong>Başlangıç Zamanı:</strong> ${metrics.start_time}</p>` : ''}
              ${metrics.duration_ms ? `<p style="color: #212529;"><strong>Süre:</strong> ${(metrics.duration_ms / 1000).toFixed(2)} saniye</p>` : ''}
              <p style="color: #212529; margin-top: 10px;"><strong>Toplam Bulgu:</strong> ${metrics.total_items || 0}</p>
              ${metrics.total_items > 0 ? `
                <p style="color: #212529;"><strong>Severity Dağılımı:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${severity_counts.CRITICAL > 0 ? `<li style="color: #dc3545;"><strong>CRITICAL:</strong> ${severity_counts.CRITICAL}</li>` : ''}
                  ${severity_counts.HIGH > 0 ? `<li style="color: #fd7e14;"><strong>HIGH:</strong> ${severity_counts.HIGH}</li>` : ''}
                  ${severity_counts.MEDIUM > 0 ? `<li style="color: #ffc107;"><strong>MEDIUM:</strong> ${severity_counts.MEDIUM}</li>` : ''}
                  ${severity_counts.LOW > 0 ? `<li style="color: #17a2b8;"><strong>LOW:</strong> ${severity_counts.LOW}</li>` : ''}
                  ${severity_counts.INFO > 0 ? `<li style="color: #6c757d;"><strong>INFO:</strong> ${severity_counts.INFO}</li>` : ''}
                </ul>
              ` : ''}
              ${critical_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #dc3545;">Kritik Bulgular (${critical_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${critical_findings.slice(0, 10).map(f => `<li>${f.title}</li>`).join('')}
                  ${critical_findings.length > 10 ? `<li><em>... ve ${critical_findings.length - 10} bulgu daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${high_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #fd7e14;">Yüksek Öncelikli Bulgular (${high_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${high_findings.slice(0, 10).map(f => `<li>${f.title}</li>`).join('')}
                  ${high_findings.length > 10 ? `<li><em>... ve ${high_findings.length - 10} bulgu daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${findings.length > 0 && critical_findings.length === 0 && high_findings.length === 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Bulgular:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${findings.slice(0, 20).map(f => `<li>${f.title}</li>`).join('')}
                  ${findings.length > 20 ? `<li><em>... ve ${findings.length - 20} bulgu daha</em></li>` : ''}
                </ul>
              ` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${nikto.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'nikto').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-nikto-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'nikto').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-nikto-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.gobuster_result
          ? (() => {
              const gobuster = data.gobuster_result;
              const norm = gobuster.normalized_json;
              if (!norm) {
                return `
                  <p><strong>Gobuster Başarısı:</strong> ${gobuster.success ? "Evet" : "Hayır"}</p>
                  <p><strong>Gobuster Komutu:</strong> ${gobuster.command}</p>
                  ${
                    gobuster.findings_summary
                      ? `
                        <p><strong>Gobuster Bulgu Sayısı:</strong> ${gobuster.findings_summary.total}</p>
                        <p><strong>Status Dağılımı:</strong> ${Object.entries(gobuster.findings_summary.by_status || {})
                          .sort((a, b) => Number(a[0]) - Number(b[0]))
                          .map(([k, v]) => `${k}:${v}`)
                          .join(", ")}</p>
                      `
                      : ""
                  }
                  ${
                    Array.isArray(gobuster.findings) && gobuster.findings.length
                      ? `
                        <p><strong>Gobuster Bulguları (ilk 50):</strong></p>
                        <pre class="pre-block">${gobuster.findings
                          .slice(0, 50)
                          .map((f) => `${String(f.status).padStart(3, " ")}  ${f.url}${f.redirect_location ? ` → ${f.redirect_location}` : ""}`)
                          .join("\n")}</pre>
                      `
                      : `<p><strong>Gobuster:</strong> Bulgu bulunamadı.</p>`
                  }
                  <p><strong>Gobuster Ham Çıktı:</strong></p>
                  <pre class="pre-block">${gobuster.raw_output || "Çıktı yok"}</pre>
                  <p><strong>Gobuster JSON:</strong> ${gobuster.output_file_json}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const status_dist = metrics.status_distribution || {};
              const findings_by_status = metrics.findings_by_status || {};
              const findings = norm.findings || [];
              
              // Önemli bulguları öne çıkar: 200, 301/302, 401
              const status_200_findings = findings.filter(f => f.evidence && f.evidence.status === 200);
              const status_301_findings = findings.filter(f => f.evidence && (f.evidence.status === 301 || f.evidence.status === 302));
              const status_401_findings = findings.filter(f => f.evidence && f.evidence.status === 401);
              const status_403_findings = findings.filter(f => f.evidence && f.evidence.status === 403);
              const other_findings = findings.filter(f => {
                const status = f.evidence && f.evidence.status;
                return status && ![200, 301, 302, 401, 403].includes(status);
              });
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>🔎 ${norm.summary || 'Gobuster Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              ${metrics.method ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('method') : 'Metot'}:</strong> ${metrics.method}</p>` : ''}
              ${metrics.threads ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('threads') : 'İş Parçacığı'}:</strong> ${metrics.threads}</p>` : ''}
              ${metrics.wordlist ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('wordlist') : 'Kelime Listesi'}:</strong> ${metrics.wordlist}</p>` : ''}
              ${metrics.extensions && metrics.extensions.length > 0 ? `<p style="color: #212529;"><strong>${typeof t !== 'undefined' ? t('extensions') : 'Uzantılar'}:</strong> ${metrics.extensions.join(', ')}</p>` : ''}
              ${metrics.duration_ms ? `<p style="color: #212529;"><strong>Süre:</strong> ${(metrics.duration_ms / 1000).toFixed(2)} saniye</p>` : ''}
              <p style="color: #212529; margin-top: 10px;"><strong>Toplam Bulgu:</strong> ${metrics.total_findings || 0}</p>
              ${Object.keys(status_dist).length > 0 ? `
                <p style="color: #212529;"><strong>Status Dağılımı:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${Object.entries(status_dist).sort((a, b) => Number(a[0]) - Number(b[0])).map(([status, count]) => {
                    const color = status === '200' ? '#28a745' : status === '301' || status === '302' ? '#17a2b8' : status === '401' ? '#ffc107' : status === '403' ? '#6c757d' : '#212529';
                    return `<li style="color: ${color};"><strong>${status}:</strong> ${count}</li>`;
                  }).join('')}
                </ul>
              ` : ''}
              ${status_200_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #28a745;">Erişilebilir Path'ler (200) - ${status_200_findings.length}:</strong></p>
                <table style="width: 100%; border-collapse: collapse; margin-top: 5px;">
                  <thead>
                    <tr style="background: #e9ecef;">
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('status') : 'Durum'}</th>
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('url') : 'URL'}</th>
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('size') : 'Boyut'}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${status_200_findings.map(f => `
                      <tr>
                        <td style="padding: 8px; border: 1px solid #dee2e6; color: #28a745;"><strong>${f.evidence.status}</strong></td>
                        <td style="padding: 8px; border: 1px solid #dee2e6;">${f.evidence.url}</td>
                        <td style="padding: 8px; border: 1px solid #dee2e6;">${f.evidence.length || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              ` : ''}
              ${status_301_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #17a2b8;">Redirect'ler (301/302) - ${status_301_findings.length}:</strong></p>
                <table style="width: 100%; border-collapse: collapse; margin-top: 5px;">
                  <thead>
                    <tr style="background: #e9ecef;">
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('status') : 'Durum'}</th>
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('url') : 'URL'}</th>
                      <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">${typeof t !== 'undefined' ? t('redirect') : 'Yönlendirme'}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${status_301_findings.map(f => `
                      <tr>
                        <td style="padding: 8px; border: 1px solid #dee2e6; color: #17a2b8;"><strong>${f.evidence.status}</strong></td>
                        <td style="padding: 8px; border: 1px solid #dee2e6;">${f.evidence.url}</td>
                        <td style="padding: 8px; border: 1px solid #dee2e6;">${f.evidence.redirect_location || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              ` : ''}
              ${status_401_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #ffc107;">Authentication Gerektiren (401) - ${status_401_findings.length}:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${status_401_findings.map(f => `<li>${f.evidence.url}</li>`).join('')}
                </ul>
              ` : ''}
              ${status_403_findings.length > 0 && status_403_findings.length <= 20 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #6c757d;">Forbidden (403) - ${status_403_findings.length}:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${status_403_findings.map(f => `<li>${f.evidence.url}</li>`).join('')}
                </ul>
              ` : status_403_findings.length > 20 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #6c757d;">Forbidden (403) - ${status_403_findings.length} bulgu (ilk 20):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${status_403_findings.slice(0, 20).map(f => `<li>${f.evidence.url}</li>`).join('')}
                  <li><em>... ve ${status_403_findings.length - 20} bulgu daha</em></li>
                </ul>
              ` : ''}
              ${other_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Diğer Bulgular (${other_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${other_findings.slice(0, 20).map(f => `<li>${f.evidence.status} - ${f.evidence.url}</li>`).join('')}
                  ${other_findings.length > 20 ? `<li><em>... ve ${other_findings.length - 20} bulgu daha</em></li>` : ''}
                </ul>
              ` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${gobuster.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'gobuster').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-gobuster-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'gobuster').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-gobuster-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.zap_result
          ? (() => {
              const zap = data.zap_result;
              const norm = zap.normalized_json;
              if (!norm) {
                return `
                  <p><strong>ZAP Başarısı:</strong> ${zap.success ? "Evet" : "Hayır"}</p>
                  <p><strong>ZAP Komutu:</strong> ${zap.command}</p>
            <p><strong>ZAP Çıktısı:</strong></p>
                  <pre class="pre-block">${zap.raw_output || "Çıktı yok"}</pre>
                  <p><strong>ZAP Raporu (HTML):</strong> ${zap.output_file}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const risk_summary = metrics.risk_summary || {};
              const alerts = metrics.alerts || [];
              const findings = norm.findings || [];
              
              const high_findings = findings.filter(f => f.severity === "HIGH");
              const medium_findings = findings.filter(f => f.severity === "MEDIUM");
              const low_findings = findings.filter(f => f.severity === "LOW");
              const info_findings = findings.filter(f => f.severity === "INFO");
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>⚡ ${norm.summary || 'ZAP Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              ${metrics.zap_version ? `<p style="color: #212529;"><strong>ZAP Versiyonu:</strong> ${metrics.zap_version}</p>` : ''}
              ${metrics.scan_date ? `<p style="color: #212529;"><strong>Tarama Tarihi:</strong> ${metrics.scan_date}</p>` : ''}
              ${metrics.duration_ms ? `<p style="color: #212529;"><strong>Süre:</strong> ${(metrics.duration_ms / 1000).toFixed(2)} saniye</p>` : ''}
              <p style="color: #212529; margin-top: 10px;"><strong>Risk Özeti:</strong></p>
              <table style="width: 100%; border-collapse: collapse; margin-top: 5px;">
                <thead>
                  <tr style="background: #e9ecef;">
                    <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Risk Seviyesi</th>
                    <th style="padding: 8px; text-align: center; border: 1px solid #dee2e6;">Alert Sayısı</th>
                  </tr>
                </thead>
                <tbody>
                  ${risk_summary.high > 0 ? `
                    <tr style="background: #f8d7da;">
                      <td style="padding: 8px; border: 1px solid #dee2e6;"><strong style="color: #dc3545;">High</strong></td>
                      <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;"><strong>${risk_summary.high}</strong></td>
                    </tr>
                  ` : ''}
                  ${risk_summary.medium > 0 ? `
                    <tr style="background: #fff3cd;">
                      <td style="padding: 8px; border: 1px solid #dee2e6;"><strong style="color: #856404;">Medium</strong></td>
                      <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;"><strong>${risk_summary.medium}</strong></td>
                    </tr>
                  ` : ''}
                  ${risk_summary.low > 0 ? `
                    <tr style="background: #fff3cd;">
                      <td style="padding: 8px; border: 1px solid #dee2e6;"><strong style="color: #856404;">Low</strong></td>
                      <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;"><strong>${risk_summary.low}</strong></td>
                    </tr>
                  ` : ''}
                  ${risk_summary.informational > 0 ? `
                    <tr style="background: #d1ecf1;">
                      <td style="padding: 8px; border: 1px solid #dee2e6;"><strong style="color: #0c5460;">Informational</strong></td>
                      <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;"><strong>${risk_summary.informational}</strong></td>
                    </tr>
                  ` : ''}
                  ${risk_summary.false_positives > 0 ? `
                    <tr>
                      <td style="padding: 8px; border: 1px solid #dee2e6;">False Positives</td>
                      <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;">${risk_summary.false_positives}</td>
                    </tr>
                  ` : ''}
                </tbody>
              </table>
              ${high_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 15px;"><strong style="color: #dc3545;">🔴 Yüksek Öncelikli Bulgular (${high_findings.length}):</strong></p>
                ${high_findings.map(f => `
                  <div style="background: #f8d7da; padding: 10px; margin: 5px 0; border-left: 4px solid #dc3545; border-radius: 3px;">
                    <p style="margin: 0; font-weight: bold; color: #721c24;">${f.title}</p>
                    ${f.evidence.description ? `<p style="margin: 5px 0 0 0; color: #212529; font-size: 0.9em;">${f.evidence.description.substring(0, 200)}${f.evidence.description.length > 200 ? '...' : ''}</p>` : ''}
                    ${f.evidence.urls && f.evidence.urls.length > 0 ? `
                      <p style="margin: 5px 0 0 0; color: #212529; font-size: 0.85em;"><strong>Etkilenen URL'ler:</strong> ${f.evidence.urls.length} adet</p>
                    ` : ''}
                    ${f.evidence.solution ? `<p style="margin: 5px 0 0 0; color: #212529; font-size: 0.85em;"><strong>Çözüm:</strong> ${f.evidence.solution.substring(0, 150)}${f.evidence.solution.length > 150 ? '...' : ''}</p>` : ''}
                  </div>
                `).join('')}
              ` : ''}
              ${medium_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 15px;"><strong style="color: #856404;">🟡 Orta Öncelikli Bulgular (${medium_findings.length}):</strong></p>
                ${medium_findings.map(f => `
                  <div style="background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; border-radius: 3px;">
                    <p style="margin: 0; font-weight: bold; color: #856404;">${f.title}</p>
                    ${f.evidence.description ? `<p style="margin: 5px 0 0 0; color: #212529; font-size: 0.9em;">${f.evidence.description.substring(0, 200)}${f.evidence.description.length > 200 ? '...' : ''}</p>` : ''}
                    ${f.evidence.urls && f.evidence.urls.length > 0 ? `
                      <p style="margin: 5px 0 0 0; color: #212529; font-size: 0.85em;"><strong>Etkilenen URL'ler:</strong> ${f.evidence.urls.length} adet</p>
                    ` : ''}
                    ${f.evidence.solution ? `<p style="margin: 5px 0 0 0; color: #212529; font-size: 0.85em;"><strong>Çözüm:</strong> ${f.evidence.solution.substring(0, 150)}${f.evidence.solution.length > 150 ? '...' : ''}</p>` : ''}
                  </div>
                `).join('')}
              ` : ''}
              ${low_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 15px;"><strong style="color: #856404;">🟡 Düşük Öncelikli Bulgular (${low_findings.length}):</strong></p>
                ${low_findings.slice(0, 5).map(f => `
                  <div style="background: #fff3cd; padding: 8px; margin: 3px 0; border-left: 3px solid #ffc107; border-radius: 3px;">
                    <p style="margin: 0; font-weight: bold; color: #856404; font-size: 0.95em;">${f.title}</p>
                    ${f.evidence.description ? `<p style="margin: 3px 0 0 0; color: #212529; font-size: 0.85em;">${f.evidence.description.substring(0, 150)}${f.evidence.description.length > 150 ? '...' : ''}</p>` : ''}
                  </div>
                `).join('')}
                ${low_findings.length > 5 ? `<p style="color: #212529; margin-top: 5px; font-size: 0.9em;"><em>... ve ${low_findings.length - 5} düşük öncelikli bulgu daha</em></p>` : ''}
              ` : ''}
              ${info_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 15px;"><strong style="color: #0c5460;">ℹ️ Bilgilendirme Bulguları (${info_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${info_findings.slice(0, 10).map(f => `<li>${f.title}</li>`).join('')}
                  ${info_findings.length > 10 ? `<li><em>... ve ${info_findings.length - 10} bilgilendirme daha</em></li>` : ''}
                </ul>
              ` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${zap.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'zap').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-zap-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'zap').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-zap-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.testssl_result
          ? (() => {
              const testssl = data.testssl_result;
              const norm = testssl.normalized_json;
              if (!norm) {
                return `
                  <p><strong>testssl.sh Başarısı:</strong> ${testssl.success ? "Evet" : "Hayır"}</p>
                  <p><strong>testssl.sh Komutu:</strong> ${testssl.command}</p>
                  <p><strong>testssl.sh Çıktısı:</strong></p>
                  <pre class="pre-block">${testssl.raw_output || "Çıktı yok"}</pre>
                  <p><strong>testssl.sh JSON:</strong> ${testssl.output_file_json}</p>
                  <p><strong>testssl.sh TXT:</strong> ${testssl.output_file_txt}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const protocols = metrics.protocols || {};
              const vulnerabilities = metrics.vulnerabilities || {};
              const certificate = metrics.certificate || {};
              const http_headers = metrics.http_headers || {};
              const rating = metrics.rating || {};
              const findings = norm.findings || [];
              
              const critical_findings = findings.filter(f => f.severity === "CRITICAL");
              const high_findings = findings.filter(f => f.severity === "HIGH");
              const medium_findings = findings.filter(f => f.severity === "MEDIUM");
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>🔒 ${norm.summary || 'testssl.sh Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              ${metrics.hostname ? `<p style="color: #212529;"><strong>Hostname:</strong> ${metrics.hostname}</p>` : ''}
              ${metrics.ip ? `<p style="color: #212529;"><strong>IP:</strong> ${metrics.ip}</p>` : ''}
              ${metrics.port ? `<p style="color: #212529;"><strong>Port:</strong> ${metrics.port}</p>` : ''}
              ${metrics.duration_ms ? `<p style="color: #212529;"><strong>Süre:</strong> ${(metrics.duration_ms / 1000).toFixed(2)} saniye</p>` : ''}
              ${rating.grade ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Rating:</strong> 
                  <span style="font-size: 1.2em; font-weight: bold; color: ${rating.grade === 'A' ? '#28a745' : rating.grade === 'B' ? '#17a2b8' : rating.grade === 'C' ? '#ffc107' : '#dc3545'};">
                    ${rating.grade}
                  </span>
                  ${rating.score ? ` (Score: ${rating.score})` : ''}
                </p>
                ${rating.grade_cap_reasons && rating.grade_cap_reasons.length > 0 ? `
                  <p style="color: #212529;"><strong>Grade Cap Reasons:</strong></p>
                  <ul style="color: #212529; margin-left: 20px;">
                    ${rating.grade_cap_reasons.map(r => `<li>${r}</li>`).join('')}
                  </ul>
                ` : ''}
              ` : ''}
              ${Object.keys(protocols).length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Protocol Support:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${Object.entries(protocols).map(([proto, status]) => {
                    const color = status.includes('OK') ? '#28a745' : status.includes('deprecated') ? '#ffc107' : '#6c757d';
                    return `<li style="color: ${color};">${proto}: ${status}</li>`;
                  }).join('')}
                </ul>
              ` : ''}
              ${certificate.cn ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Certificate:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  <li><strong>CN:</strong> ${certificate.cn}</li>
                  ${certificate.issuer ? `<li><strong>Issuer:</strong> ${certificate.issuer}</li>` : ''}
                  ${certificate.validity_days ? `<li><strong>Validity:</strong> ${certificate.validity_days} days</li>` : ''}
                  ${certificate.ocsp_stapling ? `<li><strong>OCSP Stapling:</strong> ${certificate.ocsp_stapling}</li>` : ''}
                  ${certificate.chain_of_trust ? `<li><strong>Chain of Trust:</strong> ${certificate.chain_of_trust}</li>` : ''}
                </ul>
              ` : ''}
              ${http_headers.hsts ? `
                <p style="color: #212529; margin-top: 10px;"><strong>HTTP Headers:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  <li><strong>HSTS:</strong> ${http_headers.hsts}</li>
                  ${http_headers.security_headers && http_headers.security_headers.length > 0 ? `
                    ${http_headers.security_headers.slice(0, 5).map(h => `<li>${h.name}: ${h.value.substring(0, 50)}${h.value.length > 50 ? '...' : ''}</li>`).join('')}
                  ` : ''}
                </ul>
              ` : ''}
              ${critical_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #dc3545;">Kritik Bulgular (${critical_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${critical_findings.map(f => `<li style="color: #dc3545;">${f.title}</li>`).join('')}
                </ul>
              ` : ''}
              ${high_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #ffc107;">Yüksek Öncelikli Bulgular (${high_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${high_findings.map(f => `<li style="color: #ffc107;">${f.title}</li>`).join('')}
                </ul>
              ` : ''}
              ${medium_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #17a2b8;">Orta Öncelikli Bulgular (${medium_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${medium_findings.slice(0, 10).map(f => `<li>${f.title}</li>`).join('')}
                  ${medium_findings.length > 10 ? `<li><em>... ve ${medium_findings.length - 10} bulgu daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${Object.keys(vulnerabilities).length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Vulnerability Checks:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${Object.entries(vulnerabilities).slice(0, 10).map(([vuln, status]) => {
                    const color = status.includes('VULNERABLE') ? '#dc3545' : status.includes('not vulnerable') ? '#28a745' : '#6c757d';
                    return `<li style="color: ${color};">${vuln}: ${status}</li>`;
                  }).join('')}
                  ${Object.keys(vulnerabilities).length > 10 ? `<li><em>... ve ${Object.keys(vulnerabilities).length - 10} kontrol daha</em></li>` : ''}
                </ul>
              ` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${testssl.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'testssl').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-testssl-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'testssl').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-testssl-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.dnsrecon_result
          ? (() => {
              const dnsrecon = data.dnsrecon_result;
              const norm = dnsrecon.normalized_json;
              if (!norm) {
                return `
                  <p><strong>dnsrecon Başarısı:</strong> ${dnsrecon.success ? "Evet" : "Hayır"}</p>
                  <p><strong>dnsrecon Komutu:</strong> ${dnsrecon.command}</p>
                  <p><strong>dnsrecon Çıktısı:</strong></p>
                  <pre class="pre-block">${dnsrecon.raw_output || "Çıktı yok"}</pre>
                  <p><strong>dnsrecon JSON:</strong> ${dnsrecon.output_file_json}</p>
                  <p><strong>dnsrecon TXT:</strong> ${dnsrecon.output_file_txt}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const record_types = metrics.record_types || {};
              const name_servers = metrics.name_servers || [];
              const mail_servers = metrics.mail_servers || [];
              const address_records = metrics.address_records || [];
              const txt_records = metrics.txt_records || {};
              const findings = norm.findings || [];
              
              const medium_findings = findings.filter(f => f.severity === "MEDIUM");
              const low_findings = findings.filter(f => f.severity === "LOW");
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>🌐 ${norm.summary || 'dnsrecon Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              ${metrics.duration_ms ? `<p style="color: #212529;"><strong>Süre:</strong> ${(metrics.duration_ms / 1000).toFixed(2)} saniye</p>` : ''}
              <p style="color: #212529; margin-top: 10px;"><strong>Toplam DNS Kayıtları:</strong> ${metrics.total_records || 0}</p>
              ${metrics.dnssec_configured === false ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #ffc107;">DNSSEC:</strong> <span style="color: #ffc107;">Not configured</span></p>
              ` : metrics.dnssec_configured === true ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #28a745;">DNSSEC:</strong> <span style="color: #28a745;">Configured</span></p>
              ` : ''}
              ${Object.keys(record_types).some(k => record_types[k] > 0) ? `
                <p style="color: #212529; margin-top: 10px;"><strong>DNS Kayıt Türleri:</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${Object.entries(record_types).filter(([k, v]) => v > 0).map(([type, count]) => `<li><strong>${type}:</strong> ${count}</li>`).join('')}
                </ul>
              ` : ''}
              ${name_servers.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Name Servers (${name_servers.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${name_servers.map(ns => `<li>${ns.hostname} ${ns.ip ? `(${ns.ip})` : ''}</li>`).join('')}
                </ul>
              ` : ''}
              ${mail_servers.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Mail Servers (${mail_servers.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${mail_servers.map(mx => `<li>${mx.hostname} ${mx.ip ? `(${mx.ip})` : ''}</li>`).join('')}
                </ul>
              ` : ''}
              ${address_records.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Address Records (${address_records.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${address_records.slice(0, 10).map(a => `<li>${a.hostname} → ${a.ip} (${a.type})</li>`).join('')}
                  ${address_records.length > 10 ? `<li><em>... ve ${address_records.length - 10} kayıt daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${txt_records.spf ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #17a2b8;">SPF Record:</strong></p>
                <p style="color: #212529; margin-left: 20px; font-family: monospace; font-size: 0.9em;">${txt_records.spf.substring(0, 150)}${txt_records.spf.length > 150 ? '...' : ''}</p>
              ` : ''}
              ${txt_records.dmarc ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #17a2b8;">DMARC Record:</strong></p>
                <p style="color: #212529; margin-left: 20px; font-family: monospace; font-size: 0.9em;">${txt_records.dmarc.substring(0, 150)}${txt_records.dmarc.length > 150 ? '...' : ''}</p>
              ` : ''}
              ${txt_records.verifications && txt_records.verifications.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Verification Records (${txt_records.verifications.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${txt_records.verifications.slice(0, 5).map(v => `<li style="font-family: monospace; font-size: 0.9em;">${v.substring(0, 100)}${v.length > 100 ? '...' : ''}</li>`).join('')}
                  ${txt_records.verifications.length > 5 ? `<li><em>... ve ${txt_records.verifications.length - 5} kayıt daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${medium_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #ffc107;">Orta Öncelikli Bulgular (${medium_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${medium_findings.map(f => `<li style="color: #ffc107;">${f.title}</li>`).join('')}
                </ul>
              ` : ''}
              ${low_findings.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #17a2b8;">Düşük Öncelikli Bulgular (${low_findings.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${low_findings.slice(0, 5).map(f => `<li>${f.title}</li>`).join('')}
                  ${low_findings.length > 5 ? `<li><em>... ve ${low_findings.length - 5} bulgu daha</em></li>` : ''}
                </ul>
              ` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${dnsrecon.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'dnsrecon').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-dnsrecon-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'dnsrecon').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-dnsrecon-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.theharvester_result
          ? (() => {
              const theharvester = data.theharvester_result;
              const norm = theharvester.normalized_json;
              if (!norm) {
                return `
                  <p><strong>theHarvester Başarısı:</strong> ${theharvester.success ? "Evet" : "Hayır"}</p>
                  <p><strong>theHarvester Komutu:</strong> ${theharvester.command}</p>
                  <p><strong>theHarvester Çıktısı:</strong></p>
                  <pre class="pre-block">${theharvester.raw_output || "Çıktı yok"}</pre>
                  <p><strong>theHarvester JSON:</strong> ${theharvester.output_file_json}</p>
                  <p><strong>theHarvester TXT:</strong> ${theharvester.output_file_txt}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const results = metrics.results || {};
              const successful_sources = metrics.sources_successful || [];
              const missing_api_keys = metrics.sources_missing_api_key || [];
              const error_sources = metrics.sources_errors || [];
              const sources_results = metrics.sources_results || {};
              const findings = norm.findings || [];
              
              const emails = results.emails || [];
              const hosts = results.hosts || [];
              const subdomains = results.subdomains || [];
              const ips = results.ips || [];
              const urls = results.urls || [];
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>🔍 ${norm.summary || 'theHarvester Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              ${metrics.duration_ms ? `<p style="color: #212529;"><strong>Süre:</strong> ${(metrics.duration_ms / 1000).toFixed(2)} saniye</p>` : ''}
              <p style="color: #212529; margin-top: 10px;"><strong>Toplam Sonuç:</strong> ${metrics.total_results || 0}</p>
              ${successful_sources.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #28a745;">Başarılı Kaynaklar (${successful_sources.length}):</strong></p>
                ${Object.keys(sources_results).length > 0 ? `
                  <table style="width: 100%; border-collapse: collapse; margin-top: 5px;">
                    <thead>
                      <tr style="background: #e9ecef;">
                        <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Kaynak</th>
                        <th style="padding: 8px; text-align: center; border: 1px solid #dee2e6;">Email</th>
                        <th style="padding: 8px; text-align: center; border: 1px solid #dee2e6;">Host</th>
                        <th style="padding: 8px; text-align: center; border: 1px solid #dee2e6;">IP</th>
                        <th style="padding: 8px; text-align: center; border: 1px solid #dee2e6;">Toplam</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${Object.entries(sources_results).map(([source, res]) => `
                        <tr>
                          <td style="padding: 8px; border: 1px solid #dee2e6;">${source}</td>
                          <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;">${res.emails || 0}</td>
                          <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;">${res.hosts || 0}</td>
                          <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;">${res.ips || 0}</td>
                          <td style="padding: 8px; border: 1px solid #dee2e6; text-align: center;"><strong>${res.total || 0}</strong></td>
                        </tr>
                      `).join('')}
                    </tbody>
                  </table>
                  <p style="color: #212529; margin-top: 10px; font-size: 0.9em;"><em>Not: Sadece sonuç bulunan kaynaklar gösterilmektedir.</em></p>
                ` : `
                  <ul style="color: #212529; margin-left: 20px;">
                    ${successful_sources.map(s => `<li style="color: #28a745;">${s}</li>`).join('')}
                  </ul>
                `}
              ` : ''}
              ${missing_api_keys.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #6c757d;">API Key Eksik Kaynaklar (${missing_api_keys.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${missing_api_keys.slice(0, 10).map(s => `<li style="color: #6c757d;">${s}</li>`).join('')}
                  ${missing_api_keys.length > 10 ? `<li><em>... ve ${missing_api_keys.length - 10} kaynak daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${error_sources.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong style="color: #ffc107;">Hata Olan Kaynaklar (${error_sources.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${error_sources.map(s => `<li style="color: #ffc107;">${s}</li>`).join('')}
                </ul>
              ` : ''}
              ${emails.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>E-posta Adresleri (${emails.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${emails.slice(0, 20).map(e => `<li>${e}</li>`).join('')}
                  ${emails.length > 20 ? `<li><em>... ve ${emails.length - 20} e-posta daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${hosts.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Host'lar (${hosts.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${hosts.slice(0, 20).map(h => `<li>${h}</li>`).join('')}
                  ${hosts.length > 20 ? `<li><em>... ve ${hosts.length - 20} host daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${subdomains.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Subdomain'ler (${subdomains.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${subdomains.slice(0, 20).map(s => `<li>${s}</li>`).join('')}
                  ${subdomains.length > 20 ? `<li><em>... ve ${subdomains.length - 20} subdomain daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${ips.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>IP Adresleri (${ips.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${ips.slice(0, 20).map(ip => `<li>${ip}</li>`).join('')}
                  ${ips.length > 20 ? `<li><em>... ve ${ips.length - 20} IP daha</em></li>` : ''}
                </ul>
              ` : ''}
              ${urls.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>URL'ler (${urls.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${urls.slice(0, 20).map(u => `<li>${u}</li>`).join('')}
                  ${urls.length > 20 ? `<li><em>... ve ${urls.length - 20} URL daha</em></li>` : ''}
                </ul>
              ` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${theharvester.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'theharvester').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-theharvester-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'theharvester').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-theharvester-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${
        data.subfinder_result
          ? (() => {
              const subfinder = data.subfinder_result;
              const norm = subfinder.normalized_json;
              if (!norm) {
                return `
                  <p><strong>Subfinder Başarısı:</strong> ${subfinder.success ? "Evet" : "Hayır"}</p>
                  <p><strong>Subfinder Komutu:</strong> ${subfinder.command}</p>
                  <p><strong>Subfinder Çıktısı:</strong></p>
                  <pre class="pre-block">${subfinder.raw_output || "Çıktı yok"}</pre>
                  <p><strong>Subfinder JSON:</strong> ${subfinder.output_file_json}</p>
                  <p><strong>Subfinder TXT:</strong> ${subfinder.output_file_txt}</p>
                `;
              }
              const metrics = norm.metrics || {};
              const subdomains = metrics.subdomains || [];
              const sources = metrics.sources || [];
              const findings = norm.findings || [];
              
              return `
            <div class="result-card ${statusClass(norm.status)}">
              <h3>🔎 ${norm.summary || 'Subfinder Sonuçları'}</h3>
              <p style="color: #212529;"><strong>Durum:</strong> ${norm.status === 'success' ? '✅ Başarılı' : norm.status === 'failed' ? '❌ Başarısız' : '⚠️ Kısmi'}</p>
              <p style="color: #212529;"><strong>Hedef:</strong> ${norm.target || (typeof t !== 'undefined' ? t('notAvailable') : 'Yok')}</p>
              ${metrics.duration_ms ? `<p style="color: #212529;"><strong>Süre:</strong> ${(metrics.duration_ms / 1000).toFixed(2)} saniye</p>` : ''}
              <p style="color: #212529; margin-top: 10px;"><strong>Toplam Subdomain:</strong> ${metrics.total_subdomains || 0}</p>
              ${sources.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Kaynaklar (${sources.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px;">
                  ${sources.map(s => `<li>${s}</li>`).join('')}
                </ul>
              ` : ''}
              ${subdomains.length > 0 ? `
                <p style="color: #212529; margin-top: 10px;"><strong>Subdomain'ler (${subdomains.length}):</strong></p>
                <ul style="color: #212529; margin-left: 20px; max-height: 300px; overflow-y: auto;">
                  ${subdomains.map(s => `<li>${s}</li>`).join('')}
                </ul>
              ` : ''}
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('rawOutput') : '[HAM ÇIKTI]'}</summary>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${subfinder.raw_output || "Çıktı yok"}</pre>
              </details>
              <details style="margin-top: 10px;">
                <summary>${typeof t !== 'undefined' ? t('normalizedJson') : '[NORMALİZE EDİLMİŞ JSON]'}</summary>
                <div style="margin-bottom: 10px; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                  <button class="download-json-btn" onclick="window.downloadJSON(${JSON.stringify(JSON.stringify(norm, null, 2))}, '${(norm.target || data.target_url || 'subfinder').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-subfinder-results.json.txt')">${typeof t !== 'undefined' ? t('downloadJson') : 'JSON İndir'}</button>
                  <button class="download-json-btn" onclick="window.downloadPDF(${JSON.stringify(norm)}, '${(norm.target || data.target_url || 'subfinder').replace(/[^a-z0-9]/gi, '_').toLowerCase()}-subfinder-results.json.pdf')">${typeof t !== 'undefined' ? t('downloadPdf') : 'PDF İndir'}</button>
                </div>
                <pre class="pre-block" style="margin-top: 10px; color: #212529;">${JSON.stringify(norm, null, 2)}</pre>
              </details>
            </div>
          `;
            })()
          : ""
      }
      ${data.note ? `<div class="result-card" style="margin-top: 1rem;"><p><strong>📝 Not:</strong> ${data.note}</p></div>` : ''}
    `;
  } catch (error) {
    console.error(error);
    setLoading(false);
    
    // AbortError kontrolü - kullanıcı iptal ettiyse özel mesaj göster
    if (error.name === 'AbortError') {
      resultEl.innerHTML = `
        <div class="result-card warning">
          <h3>⚠️ Tarama İptal Edildi</h3>
          <p>Tarama kullanıcı tarafından iptal edildi. Yeni bir tarama başlatabilirsiniz.</p>
        </div>
      `;
      return;
    }
    
    // Diğer hatalar için genel hata mesajı
    const errorTitle = typeof t !== 'undefined' ? t('errorSystemFailure') : '[ERROR] System Failure';
    const errorMsg = typeof t !== 'undefined' ? 'Unexpected error occurred during request processing.' : 'Unexpected error occurred during request processing.';
    resultEl.innerHTML = `
      <div class="result-card error">
        <h3>${errorTitle}</h3>
        <p><strong>[ERROR]:</strong> ${errorMsg}</p>
        <p style="margin-top: 0.5rem; font-size: 0.9rem; color: var(--text-muted);">${error.message || (typeof t !== 'undefined' ? t('errorUnknown') : 'Bilinmeyen hata')}</p>
      </div>
    `;
  }
});

// Dil değişikliği event listener'ı
document.addEventListener('languageChanged', (e) => {
  // Dil değiştiğinde UI güncellenir
  // Bu event lang.js tarafından gönderilir
});

// Sayfa yüklendiğinde input'a odaklan
window.addEventListener('load', () => {
  const input = document.getElementById("target-url");
  if (input) {
    setTimeout(() => input.focus(), 100);
  }
});

