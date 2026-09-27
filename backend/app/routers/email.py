import logging
from datetime import datetime, timezone
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from starlette.concurrency import run_in_threadpool
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..config import settings
from ..services.email_parser import parse_eml
from ..services.auth_checker import analyze_auth
from ..services.ioc_extractor import extract_iocs
from ..services.threat_intel import enrich_iocs
from ..services.geo_service import enrich_geo
from ..services.risk_engine import compute_risk_score
from ..services.mitre_mapper import map_mitre
from ..services.case_builder import build_case
from ..services.case_id import allocate_case_id
from .. import models

router = APIRouter(prefix="/api/email", tags=["email"])
logger = logging.getLogger(__name__)


@router.post("/upload")
async def upload_email(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files are accepted.")

    content = await file.read()
    investigation_created_at = datetime.now(timezone.utc)
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(413, f"File exceeds {settings.max_upload_size_mb} MB limit.")

    try:
        parsed = parse_eml(content)
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, f"Unable to parse EML file: {exc}") from exc
    auth = analyze_auth(parsed["headers"])
    raw_iocs = extract_iocs(parsed)
    iocs = await enrich_iocs(raw_iocs, allow_local_database=False)
    iocs = await enrich_geo(iocs)
    risk_score = await run_in_threadpool(compute_risk_score, parsed, auth, iocs)
    mitre_mappings = map_mitre(parsed, auth, iocs, risk_score)
    case_id, investigation_created_at = await allocate_case_id(db, investigation_created_at)
    case = build_case(case_id, parsed, auth, iocs, risk_score, mitre_mappings)
    case["created_at"] = investigation_created_at.isoformat()

    # Persist to DB
    db_case = models.Case(
        id=case["id"],
        created_at=investigation_created_at,
        threat_type=case["threat_type"],
        severity=case["severity"],
        verdict=case["verdict"],
        is_demo=False,
        risk_score_total=risk_score["total"],
        risk_score_level=risk_score["level"],
        risk_score_confidence=risk_score["confidence"],
        risk_breakdown={
            "content": risk_score["content"],
            "authentication": risk_score["authentication"],
            "reputation": risk_score["reputation"],
            "infrastructure": risk_score["infrastructure"],
            "ai_analysis": risk_score["ai_analysis"],
            "evidence_coverage": risk_score["evidence_coverage"],
        },
        risk_explanation=risk_score["explanation"],
        why_flagged=case["why_flagged"],
        summary=case["summary"],
        mitre_mappings=mitre_mappings,
        timeline=case["timeline"],
        graph_nodes=case["graph_nodes"],
        graph_edges=case["graph_edges"],
    )
    db_email = models.Email(
        case_id=case["id"],
        from_addr=parsed["from_addr"],
        to_addr=parsed["to_addr"],
        subject=parsed["subject"],
        date=parsed["date"],
        reply_to=parsed.get("reply_to"),
        message_id=parsed.get("message_id"),
        body_text=parsed["body_text"][:50000],
        received_ips=parsed["received_ips"],
        received_path=parsed["received_headers"],
        urls=parsed["urls"],
        email_addresses=parsed["email_addresses"],
        headers=parsed["headers"],
        attachments=parsed["attachments"],
        auth_spf=auth["spf"],
        auth_dkim=auth["dkim"],
        auth_dmarc=auth["dmarc"],
        auth_summary=auth["summary"],
        auth_spf_detail=auth.get("spf_detail"),
        auth_dkim_detail=auth.get("dkim_detail"),
        auth_dmarc_detail=auth.get("dmarc_detail"),
    )
    db_iocs = [
        models.IOC(
            id=i["id"], case_id=case["id"],
            type=i["type"], value=i["value"],
            source=i["source"], risk=i["risk"],
            status=i["status"],
            intelligence={
                **(i.get("intelligence") or {}),
                "_normalization": {
                    "normalized_value": i["normalized_value"],
                    "valid": i["valid"],
                    "confidence": i["confidence"],
                },
            },
        )
        for i in iocs
    ]
    db.add(db_case)
    db.add(db_email)
    db.add_all(db_iocs)
    try:
        await db.commit()
    except SQLAlchemyError as exc:
        await db.rollback()
        logger.exception("Failed to persist uploaded email investigation")
        raise HTTPException(
            503,
            "Investigation analysis completed but could not be saved. Check database connectivity.",
        ) from exc

    return case
