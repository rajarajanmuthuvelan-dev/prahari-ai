from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db
from app.routers import email, cases, ioc, reports
from app.services.nlp_service import _ai_analysis_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await asyncio.to_thread(_ai_analysis_service.load_models)
    yield


app = FastAPI(
    title="PRAHARI AI",
    description="Email Threat Detection, GeoLocation & Forensic Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(email.router)
app.include_router(cases.router)
app.include_router(ioc.router)
app.include_router(reports.router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "PRAHARI AI Backend"}


@app.get("/api/status")
def api_status():
    import os
    return {
        "backend": True,
        "virustotal": bool(settings.virustotal_api_key),
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "geoip": bool(settings.geoip_db_path and os.path.exists(settings.geoip_db_path)),
    }
