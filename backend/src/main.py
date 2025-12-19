import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import scans

# Uygulama örneği oluşturuluyor
app = FastAPI(
    title="SecTestOpsHub API",
    version="0.1.0",
    description="Birden fazla güvenlik aracını orkestre eden basit API",
)

# CORS ayarları: geliştirme sırasında localhost/8080 için açıyoruz
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
    Sağlık kontrolü ucu; orkestrasyonun çalıştığını doğrulamak için kullanılır.
    """
    return {"status": "ok", "output_dir": os.getenv("OUTPUT_DIR", "/app/data")}


# Scan router'ı ana uygulamaya ekleniyor
app.include_router(scans.router)


