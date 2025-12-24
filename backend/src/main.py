import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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
    return {"status": "ok", "output_dir": os.getenv("OUTPUT_DIR", "/app/data")}


# Tarama router'ı ana uygulamaya ekleniyor
app.include_router(scans.router)


