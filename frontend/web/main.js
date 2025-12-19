// Basit API istemcisi; tüm yorumlar Türkçe tutulmuştur

const form = document.getElementById("scan-form");
const resultEl = document.getElementById("result");

// Yardımcı: API kök adresi; gerekirse reverse proxy ile güncellenebilir
const API_BASE = "http://localhost:8000";

// Form gönderimi ile tarama planı oluşturulur
form.addEventListener("submit", async (event) => {
  event.preventDefault();

  // Form verileri okunuyor
  const targetUrl = document.getElementById("target-url").value.trim();
  const toolNodes = [...document.querySelectorAll('input[name="tool"]:checked')];
  const tools = toolNodes.map((n) => n.value);

  // Basit doğrulama: URL var mı
  if (!targetUrl) {
    resultEl.textContent = "Hedef URL zorunludur.";
    return;
  }

  // Kullanıcıya durum bilgisi göster
  resultEl.textContent = "Plan oluşturuluyor...";

  try {
    const response = await fetch(`${API_BASE}/scans/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_url: targetUrl,
        tools: tools.length ? tools : null,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      resultEl.textContent = `Hata: ${error.detail || "Bilinmeyen hata"}`;
      return;
    }

    const data = await response.json();

    // Sonuçları kullanıcıya okunaklı formatta göster
    resultEl.innerHTML = `
      <p><strong>Hedef:</strong> ${data.target_url}</p>
      <p><strong>Araçlar:</strong> ${data.tools.join(", ")}</p>
      <p><strong>Çıktı Dizini:</strong> ${data.output_dir}</p>
      ${
        data.ping_result
          ? `
            <p><strong>Ping IP:</strong> ${data.ping_result.ip_address}</p>
            <p><strong>Ping Başarısı:</strong> ${data.ping_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>Ping Çıktısı:</strong></p>
            <pre class="pre-block">${data.ping_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>Ping Dosyası:</strong> ${data.ping_result.output_file}</p>
          `
          : "<p>Ping sonucu bulunamadı.</p>"
      }
      ${
        data.whois_result
          ? `
            <p><strong>Whois Başarısı:</strong> ${data.whois_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>Whois Çıktısı:</strong></p>
            <pre class="pre-block">${data.whois_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>Whois Dosyası:</strong> ${data.whois_result.output_file}</p>
          `
          : "<p>Whois sonucu bulunamadı.</p>"
      }
      ${
        data.nmap_result
          ? `
            <p><strong>Nmap Başarısı:</strong> ${data.nmap_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>Nmap Komutu:</strong> ${data.nmap_result.command}</p>
            <p><strong>Nmap Çıktısı:</strong></p>
            <pre class="pre-block">${data.nmap_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>Nmap XML:</strong> ${data.nmap_result.output_file_xml}</p>
            <p><strong>Nmap TXT:</strong> ${data.nmap_result.output_file_txt}</p>
          `
          : "<p>Nmap sonucu bulunamadı.</p>"
      }
      ${
        data.nikto_result
          ? `
            <p><strong>Nikto Başarısı:</strong> ${data.nikto_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>Nikto Komutu:</strong> ${data.nikto_result.command}</p>
            <p><strong>Nikto Çıktısı:</strong></p>
            <pre class="pre-block">${data.nikto_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>Nikto JSON:</strong> ${data.nikto_result.output_file_json}</p>
            <p><strong>Nikto TXT:</strong> ${data.nikto_result.output_file_txt}</p>
          `
          : "<p>Nikto sonucu bulunamadı.</p>"
      }
      ${
        data.gobuster_result
          ? `
            <p><strong>Gobuster Başarısı:</strong> ${data.gobuster_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>Gobuster Komutu:</strong> ${data.gobuster_result.command}</p>
            ${
              data.gobuster_result.findings_summary
                ? `
                  <p><strong>Gobuster Bulgu Sayısı:</strong> ${data.gobuster_result.findings_summary.total}</p>
                  <p><strong>Status Dağılımı:</strong> ${Object.entries(data.gobuster_result.findings_summary.by_status || {})
                    .sort((a, b) => Number(a[0]) - Number(b[0]))
                    .map(([k, v]) => `${k}:${v}`)
                    .join(", ")}</p>
                `
                : ""
            }
            ${
              Array.isArray(data.gobuster_result.findings) && data.gobuster_result.findings.length
                ? `
                  <p><strong>Gobuster Bulguları (ilk 50):</strong></p>
                  <pre class="pre-block">${data.gobuster_result.findings
                    .slice(0, 50)
                    .map((f) => `${String(f.status).padStart(3, " ")}  ${f.url}${f.redirect_location ? ` → ${f.redirect_location}` : ""}`)
                    .join("\n")}</pre>
                `
                : `<p><strong>Gobuster:</strong> Bulgu bulunamadı.</p>`
            }
            <p><strong>Gobuster Ham Çıktı:</strong></p>
            <pre class="pre-block">${data.gobuster_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>Gobuster JSON:</strong> ${data.gobuster_result.output_file_json}</p>
          `
          : "<p>Gobuster sonucu bulunamadı.</p>"
      }
      ${
        data.zap_result
          ? `
            <p><strong>ZAP Başarısı:</strong> ${data.zap_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>ZAP Komutu:</strong> ${data.zap_result.command}</p>
            <p><strong>ZAP Çıktısı:</strong></p>
            <pre class="pre-block">${data.zap_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>ZAP Raporu (HTML):</strong> ${data.zap_result.output_file}</p>
          `
          : "<p>ZAP sonucu bulunamadı.</p>"
      }
      ${
        data.testssl_result
          ? `
            <p><strong>testssl.sh Başarısı:</strong> ${data.testssl_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>testssl.sh Komutu:</strong> ${data.testssl_result.command}</p>
            <p><strong>testssl.sh Çıktısı:</strong></p>
            <pre class="pre-block">${data.testssl_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>testssl.sh JSON:</strong> ${data.testssl_result.output_file_json}</p>
            <p><strong>testssl.sh TXT:</strong> ${data.testssl_result.output_file_txt}</p>
          `
          : "<p>testssl.sh sonucu bulunamadı.</p>"
      }
      ${
        data.dnsrecon_result
          ? `
            <p><strong>dnsrecon Başarısı:</strong> ${data.dnsrecon_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>dnsrecon Komutu:</strong> ${data.dnsrecon_result.command}</p>
            <p><strong>dnsrecon Çıktısı:</strong></p>
            <pre class="pre-block">${data.dnsrecon_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>dnsrecon JSON:</strong> ${data.dnsrecon_result.output_file_json}</p>
            <p><strong>dnsrecon TXT:</strong> ${data.dnsrecon_result.output_file_txt}</p>
          `
          : "<p>dnsrecon sonucu bulunamadı.</p>"
      }
      ${
        data.theharvester_result
          ? `
            <p><strong>theHarvester Başarısı:</strong> ${data.theharvester_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>theHarvester Komutu:</strong> ${data.theharvester_result.command}</p>
            <p><strong>theHarvester Çıktısı:</strong></p>
            <pre class="pre-block">${data.theharvester_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>theHarvester JSON:</strong> ${data.theharvester_result.output_file_json}</p>
            <p><strong>theHarvester TXT:</strong> ${data.theharvester_result.output_file_txt}</p>
          `
          : "<p>theHarvester sonucu bulunamadı.</p>"
      }
      ${
        data.amass_result
          ? `
            <p><strong>Amass Başarısı:</strong> ${data.amass_result.success ? "Evet" : "Hayır"}</p>
            <p><strong>Amass Komutu:</strong> ${data.amass_result.command}</p>
            <p><strong>Amass Çıktısı:</strong></p>
            <pre class="pre-block">${data.amass_result.raw_output || "Çıktı yok"}</pre>
            <p><strong>Amass JSON:</strong> ${data.amass_result.output_file_json}</p>
            <p><strong>Amass TXT:</strong> ${data.amass_result.output_file_txt}</p>
          `
          : "<p>Amass sonucu bulunamadı.</p>"
      }
      <p><strong>Not:</strong> ${data.note}</p>
    `;
  } catch (error) {
    console.error(error);
    resultEl.textContent = "İstek sırasında beklenmeyen bir hata oluştu.";
  }
});


