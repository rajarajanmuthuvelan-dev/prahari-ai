from fastapi import APIRouter, HTTPException
from ..services.threat_intel import enrich_ioc
from ..services.local_ioc_db import LOCAL_IOC_DB
from ..services.ioc_normalizer import normalize_ioc

router = APIRouter(prefix="/api/ioc", tags=["ioc"])


@router.get("/lookup")
async def lookup_ioc(value: str, type: str = "IP"):
    normalized = normalize_ioc(type, value, "IOC Lookup")
    if not normalized["valid"]:
        raise HTTPException(422, f"Invalid {type.upper()} IOC value.")
    intel = await enrich_ioc(normalized["type"], normalized["normalized_value"])
    return {
        "value": value,
        "found": intel.get("lookup_status") == "FOUND",
        "intelligence": intel,
    }


@router.get("/db")
def local_db():
    return {"count": len(LOCAL_IOC_DB), "records": LOCAL_IOC_DB}
