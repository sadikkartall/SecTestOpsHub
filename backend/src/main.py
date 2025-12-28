import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Önce environment variable'ı kontrol et (Docker Compose'dan gelebilir)
api_key = os.getenv("GEMINI_API_KEY")

# Eğer environment variable yoksa .env dosyasını yükle
if not api_key:
    # .env dosyasını yükle - birden fazla yolu dene
    # backend/src/main.py -> backend -> SecTestOpsHub -> .env
    current_file = Path(__file__).resolve()
    project_root = current_file.parent.parent.parent
    env_path = project_root / '.env'

    # Alternatif yolları da dene
    env_paths = [
        env_path,  # Proje root
        project_root.parent / '.env',  # Bir üst dizin
        Path.cwd() / '.env',  # Çalışma dizini
        Path.cwd().parent / '.env',  # Çalışma dizininin üstü
    ]

    # İlk bulunan .env dosyasını yükle
    env_loaded = False
    for path in env_paths:
        if path.exists():
            load_dotenv(dotenv_path=path, override=True)
            print(f"[INFO] .env dosyası yüklendi: {path}")
            env_loaded = True
            # load_dotenv sonrası tekrar kontrol et
            api_key = os.getenv("GEMINI_API_KEY")
            if api_key:
                break
            
            # Eğer load_dotenv ile yüklenmediyse direkt dosyayı oku
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")
                            if key == 'GEMINI_API_KEY' and value:
                                api_key = value
                                os.environ['GEMINI_API_KEY'] = value
                                print(f"[INFO] GEMINI_API_KEY direkt dosyadan yüklendi: {path}")
                                break
                if api_key:
                    break
            except Exception as e:
                print(f"[ERROR] .env dosyası okunamadı {path}: {e}")
                continue
    
    if not api_key and not env_loaded:
        print(f"[WARNING] .env dosyası bulunamadı. Aranan yollar: {env_paths}")

# Debug: API key kontrolü
if api_key:
    print(f"[INFO] GEMINI_API_KEY yüklendi (uzunluk: {len(api_key)})")
else:
    print("[WARNING] GEMINI_API_KEY bulunamadı!")

from .routers import scans

# FastAPI uygulama örneği oluşturuluyor
app = FastAPI(
    title="SecTestOpsHub API",
    version="0.1.0",
    description="Birden fazla güvenlik aracını orkestre eden birleşik API",
)

# CORS (Cross-Origin Resource Sharing) ayarları
# Geliştirme için tüm origin'lere izin veriliyor; üretimde daraltılmalı
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Geliştirme için geniş; üretimde daraltılmalı
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """
    Sağlık kontrolü endpoint'i.
    Sistemin çalışıp çalışmadığını ve çıktı dizinini kontrol etmek için kullanılır.
    
    Returns:
        dict: Sistem durumu ve çıktı dizini bilgisi
    """
    api_key = os.getenv("GEMINI_API_KEY")
    
    # Eğer yoksa tekrar yükle
    if not api_key:
        from dotenv import load_dotenv
        for path in env_paths:
            if path.exists():
                load_dotenv(dotenv_path=path, override=True)
                api_key = os.getenv("GEMINI_API_KEY")
                if api_key:
                    break
        
        # Hala yoksa direkt oku
        if not api_key:
            for path in env_paths:
                if path.exists():
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#') and '=' in line:
                                    key, value = line.split('=', 1)
                                    key = key.strip()
                                    value = value.strip().strip('"').strip("'")
                                    if key == 'GEMINI_API_KEY':
                                        api_key = value
                                        os.environ['GEMINI_API_KEY'] = value
                                        break
                        if api_key:
                            break
                    except Exception:
                        continue
    
    return {
        "status": "ok", 
        "output_dir": os.getenv("OUTPUT_DIR", "/app/data"),
        "gemini_api_key_configured": bool(api_key),
        "gemini_api_key_length": len(api_key) if api_key else 0,
        "gemini_api_key_prefix": api_key[:10] + "..." if api_key and len(api_key) > 10 else None
    }


# Tarama router'ı ana uygulamaya ekleniyor
app.include_router(scans.router)


