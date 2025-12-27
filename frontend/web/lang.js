// Dil desteği - Language Support
const translations = {
  en: {
    // Header
    headerTitle: "SecTestOpsHub",
    headerSubtitle: "[SYSTEM] Security Testing Terminal v2.0",
    headerStatus: "[ONLINE]",
    
    // Main Content
    scanTitle: "Initialize Scan",
    scanDescription: "[INPUT] Enter target URL and select security tools",
    targetLabel: "Target URL / IP / Domain",
    targetPlaceholder: "e.g. example.com, 192.168.1.1 or https://example.com",
    toolsLabel: "Security Tools",
    
    // Tools
    toolPing: "Ping",
    toolWhois: "Whois",
    toolNmap: "Nmap",
    toolNikto: "Nikto",
    toolGobuster: "Gobuster",
    toolZap: "OWASP ZAP",
    toolTestssl: "testssl.sh",
    toolDnsrecon: "dnsrecon",
    toolTheharvester: "theHarvester",
    toolSubfinder: "Subfinder",
    
    // Buttons
    btnStartScan: "[EXECUTE] Start Scan",
    btnStopScan: "[ABORT] Stop Scan",
    
    // Form Hint
    formHint: "[NOTE] URL scheme (http/https) is auto-completed. Full security analysis available when all tools selected.",
    
    // Loading
    loadingText: "[SYSTEM] Scanning in progress... Please wait...",
    
    // Results
    scanPlan: "[SCAN PLAN] Execution Ready",
    scanTarget: "[TARGET]",
    scanTools: "[TOOLS]",
    scanOutputDir: "[OUTPUT_DIR]",


    
    // Status Messages
    errorInvalidInput: "[ERROR] Invalid Input",
    errorRequired: "[REQUIRED] Target URL/IP/domain is required. Please provide a valid target.",
    errorRequestFailed: "[ERROR] Request Failed",
    errorSystemFailure: "[ERROR] System Failure",
    errorDetail: "[DETAIL]",
    errorUnknown: "Unknown error occurred",
    
    scanAborted: "[ABORTED] Scan Terminated",
    scanCancelled: "[WARNING] Operation cancelled by user. Ready for new scan command.",
    
    // Result Details
    rawOutput: "[RAW OUTPUT]",
    normalizedJson: "[NORMALIZED JSON]",
    downloadJson: "Download JSON",
    downloadPdf: "Download PDF",
    
    // Common labels
    notAvailable: "N/A",
    up: "Up",
    down: "Down",
    unknown: "Unknown",
    detected: "Detected",
    port: "Port",
    state: "State",
    service: "Service",
    version: "Version",
    status: "Status",
    url: "URL",
    size: "Size",
    redirect: "Redirect",
    method: "Method",
    threads: "Threads",
    wordlist: "Wordlist",
    extensions: "Extensions",
    protocolSupport: "Protocol Support",
    networkName: "Network Name",
    organization: "Organization",
    country: "Country",
    abuseContact: "Abuse Contact",
    cidr: "CIDR",
    hostname: "Hostname",
    server: "Server",
    
    // Footer
    footerText: "[SYSTEM] SecTestOpsHub Terminal v2.0 - Security Testing Platform [ONLINE]",
    
    // Language Selector
    langLabel: "[LANG]",
    langEn: "EN",
    langTr: "TR"
  },
  
  tr: {
    // Header
    headerTitle: "SecTestOpsHub",
    headerSubtitle: "[SİSTEM] Güvenlik Test Terminali v2.0",
    headerStatus: "[ÇEVRİMİÇİ]",
    
    // Main Content
    scanTitle: "Tarama Başlat",
    scanDescription: "[GİRDİ] Hedef URL'yi girin ve güvenlik araçlarını seçin",
    targetLabel: "Hedef URL / IP / Domain",
    targetPlaceholder: "örn. example.com, 192.168.1.1 veya https://example.com",
    toolsLabel: "Güvenlik Araçları",
    
    // Tools
    toolPing: "Ping",
    toolWhois: "Whois",
    toolNmap: "Nmap",
    toolNikto: "Nikto",
    toolGobuster: "Gobuster",
    toolZap: "OWASP ZAP",
    toolTestssl: "testssl.sh",
    toolDnsrecon: "dnsrecon",
    toolTheharvester: "theHarvester",
    toolSubfinder: "Subfinder",
    
    // Buttons
    btnStartScan: "[ÇALIŞTIR] Taramayı Başlat",
    btnStopScan: "[DURDUR] Taramayı Durdur",
    
    // Form Hint
    formHint: "[NOT] URL şeması (http/https) otomatik olarak eklenir. Tüm araçlar seçiliyse kapsamlı bir güvenlik analizi yapılır.",
    
    // Loading
    loadingText: "[SİSTEM] Tarama devam ediyor... Lütfen bekleyin...",
    
    // Results
    scanPlan: "[TARAMA PLANI] Çalıştırmaya Hazır",
    scanTarget: "[HEDEF]",
    scanTools: "[ARAÇLAR]",
    scanOutputDir: "[ÇIKTI_DİZİNİ]",
    
    // Status Messages
    errorInvalidInput: "[HATA] Geçersiz Girdi",
    errorRequired: "[GEREKLİ] Hedef URL/IP/domain zorunludur. Lütfen geçerli bir hedef girin.",
    errorRequestFailed: "[HATA] İstek Başarısız",
    errorSystemFailure: "[HATA] Sistem Hatası",
    errorDetail: "[DETAY]",
    errorUnknown: "Bilinmeyen hata oluştu",
    
    scanAborted: "[İPTAL] Tarama Sonlandırıldı",
    scanCancelled: "[UYARI] İşlem kullanıcı tarafından iptal edildi. Yeni tarama komutu için hazır.",
    
    // Result Details
    rawOutput: "[HAM ÇIKTI]",
    normalizedJson: "[NORMALİZE EDİLMİŞ JSON]",
    downloadJson: "JSON İndir",
    downloadPdf: "PDF İndir",
    
    // Common labels
    notAvailable: "Yok",
    up: "Açık",
    down: "Kapalı",
    unknown: "Bilinmiyor",
    detected: "Tespit Edildi",
    port: "Port",
    state: "Durum",
    service: "Servis",
    version: "Versiyon",
    status: "Durum",
    url: "URL",
    size: "Boyut",
    redirect: "Yönlendirme",
    method: "Metot",
    threads: "İş Parçacığı",
    wordlist: "Kelime Listesi",
    extensions: "Uzantılar",
    protocolSupport: "Protokol Desteği",
    networkName: "Ağ Adı",
    organization: "Kuruluş",
    country: "Ülke",
    abuseContact: "Kötüye Kullanım İletişim",
    cidr: "CIDR",
    hostname: "Host Adı",
    server: "Sunucu",
    
    // Footer
    footerText: "[SİSTEM] SecTestOpsHub Terminal v2.0 - Güvenlik Test Platformu [ÇEVRİMİÇİ]",
    
    // Language Selector
    langLabel: "[DİL]",
    langEn: "EN",
    langTr: "TR"
  }
};

// Mevcut dili localStorage'dan al veya varsayılan olarak 'tr' kullan
let currentLang = localStorage.getItem('language') || 'tr';

// Dil değiştirme fonksiyonu
function setLanguage(lang) {
  if (!translations[lang]) return;
  currentLang = lang;
  localStorage.setItem('language', lang);
  updateUI();
}

// UI güncelleme fonksiyonu
function updateUI() {
  const t = translations[currentLang];
  
  // Header
  const headerTitle = document.getElementById('header-title');
  const headerSubtitle = document.getElementById('header-subtitle');
  const headerStatus = document.getElementById('header-status');
  if (headerTitle) headerTitle.textContent = t.headerTitle;
  if (headerSubtitle) headerSubtitle.textContent = t.headerSubtitle;
  if (headerStatus) headerStatus.textContent = t.headerStatus;
  
  // Main Content
  const scanTitle = document.getElementById('scan-title');
  const scanDescription = document.getElementById('scan-description');
  const targetLabel = document.getElementById('target-label');
  const targetInput = document.getElementById('target-url');
  const toolsLabel = document.getElementById('tools-label');
  
  if (scanTitle) scanTitle.textContent = t.scanTitle;
  if (scanDescription) scanDescription.textContent = t.scanDescription;
  if (targetLabel) targetLabel.textContent = t.targetLabel;
  if (targetInput) targetInput.placeholder = t.targetPlaceholder;
  if (toolsLabel) toolsLabel.textContent = t.toolsLabel;
  
  // Buttons
  const btnStartScan = document.getElementById('btn-start-scan');
  const btnStopScan = document.getElementById('btn-stop-scan');
  if (btnStartScan) btnStartScan.textContent = t.btnStartScan;
  if (btnStopScan) btnStopScan.textContent = t.btnStopScan;
  
  // Form Hint
  const formHint = document.getElementById('form-hint');
  if (formHint) formHint.textContent = t.formHint;
  
  // Footer
  const footerText = document.getElementById('footer-text');
  if (footerText) footerText.textContent = t.footerText;
  
  // Language Selector
  const langLabel = document.getElementById('lang-label');
  if (langLabel) langLabel.textContent = t.langLabel;
  
  // HTML lang attribute'unu güncelle
  const htmlLang = document.getElementById('html-lang') || document.documentElement;
  if (htmlLang) {
    htmlLang.setAttribute('lang', currentLang);
  }
  
  // Dil değişikliği event'i gönder
  document.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang: currentLang, t } }));
}

// Çeviri alma fonksiyonu
function t(key) {
  return translations[currentLang]?.[key] || key;
}

// Dil seçici event listener
document.addEventListener('DOMContentLoaded', () => {
  const langSelect = document.getElementById('lang-select');
  if (langSelect) {
    langSelect.value = currentLang;
    langSelect.addEventListener('change', (e) => {
      setLanguage(e.target.value);
    });
  }
  updateUI();
});

// Sayfa yüklendiğinde UI'ı güncelle
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    const langSelect = document.getElementById('lang-select');
    if (langSelect) {
      langSelect.value = currentLang;
      langSelect.addEventListener('change', (e) => {
        setLanguage(e.target.value);
      });
    }
    updateUI();
  });
} else {
  const langSelect = document.getElementById('lang-select');
  if (langSelect) {
    langSelect.value = currentLang;
    langSelect.addEventListener('change', (e) => {
      setLanguage(e.target.value);
    });
  }
  updateUI();
}

