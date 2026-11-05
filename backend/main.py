from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db
from app.routers import email, cases, ioc, reports
from app.services.nlp_service import _ai_analysis_service
from app.geoip_download import ensure_geoip_databases



@asynccontextmanager
async def lifespan(app: FastAPI):
    geoip_results = await asyncio.to_thread(
        ensure_geoip_databases
    )

    print(
        "GeoIP database status:",
        geoip_results,
    )

    await init_db()

    if settings.ai_models_enabled:
        await asyncio.to_thread(
            _ai_analysis_service.load_models
        )
    else:
        print("AI model loading disabled for startup.")

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
    from pathlib import Path

    city_available = Path(settings.geoip_db_path).is_file()
    asn_available = Path(settings.geoip_asn_db_path).is_file()

    return {
        "backend": True,
        "virustotal": bool(settings.virustotal_api_key),
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "geoip": city_available,
        "geoip_city": city_available,
        "geoip_asn": asn_available,
        "geoip_full": city_available and asn_available,
    }