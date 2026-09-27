import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from ..database import get_db
from .. import models
from ..services.ioc_normalizer import normalize_ioc
from ..services.ioc_reputation import normalize_ioc_reputation
from ..services.evidence_coverage import calculate_evidence_coverage
from ..services.risk_presentation import (
    build_risk_presentation,
    format_investigation_explanation,
)
from ..services.threat_classifier import classify_threat_type, normalize_threat_type

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _normalize_geo_context(intel: dict) -> None:
    geo = intel.get("geo")
    if not isinstance(geo, dict):
        return

    geo = dict(geo)
    domain_hostname = geo.get("domain_hostname") or intel.get("domain_hostname")
    domain_hostname_source = (
        geo.get("domain_hostname_source")
        or intel.get("domain_hostname_source")
    )
    geo["domain_hostname"] = domain_hostname
    geo["domain_hostname_source"] = domain_hostname_source
    if not geo.get("reverse_dns") and domain_hostname_source == "DNS_PTR":
        geo["reverse_dns"] = domain_hostname

    if not isinstance(geo.get("field_status"), dict):
        provider_results = geo.get("provider_results") or {}
        source_results = [
            result for result in provider_results.values()
            if isinstance(result, dict)
        ] if isinstance(provider_results, dict) else []
        ptr_result = provider_results.get("DNS_PTR", {}) if isinstance(provider_results, dict) else {}
        has_found_source = any(
            result.get("status") == "FOUND"
            and result.get("source") != "DNS_PTR"
            for result in source_results
        )
        has_failed_source = any(
            result.get("status") in ("ERROR", "TIMEOUT")
            for result in source_results
        )
        fields = {
            "reverse_dns": geo.get("reverse_dns"),
            "network": geo.get("network"),
            "network_type": geo.get("network_type"),
            "infrastructure_type": geo.get("infrastructure_type"),
        }
        field_status = {}
        for field, value in fields.items():
            ptr_status = ptr_result.get("status") if field == "reverse_dns" else None
            if value:
                field_status[field] = "AVAILABLE"
            elif ptr_status in ("ERROR", "TIMEOUT"):
                field_status[field] = "LOOKUP_FAILED"
            elif field == "reverse_dns" and ptr_status == "NOT_FOUND":
                field_status[field] = "NOT_AVAILABLE"
            elif has_found_source:
                field_status[field] = "NOT_RETURNED_BY_SOURCE"
            elif has_failed_source:
                field_status[field] = "LOOKUP_FAILED"
            else:
                field_status[field] = "NOT_AVAILABLE"
        geo["field_status"] = field_status

    intel["geo"] = geo


def _serialize_case(c: models.Case) -> dict:
    e = c.email
    serialized_iocs = []
    for ioc in c.iocs or []:
        intel = dict(ioc.intelligence or {})
        _normalize_geo_context(intel)
        normalization = intel.pop("_normalization", None)
        if normalization is None:
            normalization = normalize_ioc(ioc.type, ioc.value, ioc.source or "")
        normalized_ioc = normalize_ioc_reputation({
            "type": ioc.type,
            "value": ioc.value,
            "source": ioc.source or "",
            "status": ioc.status,
            "risk": ioc.risk,
            "intelligence": intel,
        })
        serialized_iocs.append(
            {
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value,
                "source": ioc.source,
                "risk": ioc.risk,
                "status": normalized_ioc["status"],
                "reputation_status": normalized_ioc["reputation_status"],
                "risk_contribution": normalized_ioc["risk_contribution"],
                "lookup_source": normalized_ioc["lookup_source"],
                "lookup_status": normalized_ioc["lookup_status"],
                "geo_source": normalized_ioc["geo_source"],
                "evidence_category": normalized_ioc["evidence_category"],
                "normalized_value": normalization["normalized_value"],
                "valid": normalization["valid"],
                "confidence": normalization["confidence"],
                "intelligence": normalized_ioc["intelligence"],
            }
        )
    auth = {
        "spf": e.auth_spf if e else "NOT_AVAILABLE",
        "dkim": e.auth_dkim if e else "NOT_AVAILABLE",
        "dmarc": e.auth_dmarc if e else "NOT_AVAILABLE",
        "summary": e.auth_summary if e else "",
        "spf_detail": e.auth_spf_detail if e else None,
        "dkim_detail": e.auth_dkim_detail if e else None,
        "dmarc_detail": e.auth_dmarc_detail if e else None,
    }
    risk_breakdown = c.risk_breakdown or {}
    ai_analysis = risk_breakdown.get("ai_analysis") or {}
    threat_type = normalize_threat_type(c.threat_type) or classify_threat_type(
        {
            "from_addr": e.from_addr if e else "",
            "subject": e.subject if e else "",
            "body_text": e.body_text if e else "",
            "body_html": "",
            "urls": e.urls if e else [],
            "attachments": e.attachments if e else [],
            "headers": e.headers if e else [],
            "reply_to": e.reply_to if e else "",
        },
        auth,
        serialized_iocs,
        ai_analysis,
        risk_breakdown,
        c.mitre_mappings or [],
    )
    evidence_coverage = calculate_evidence_coverage(
        {
            "headers": e.headers if e else [],
            "body_text": e.body_text if e else "",
            "attachments": e.attachments if e else [],
            "received_headers": e.received_path if e else [],
            "received_ips": e.received_ips if e else [],
            "urls": e.urls if e else [],
        },
        auth,
        serialized_iocs,
        ai_analysis,
    )
    presentation_risk = {
        **risk_breakdown,
        "total": c.risk_score_total,
        "level": c.risk_score_level,
    }
    explanation = format_investigation_explanation(presentation_risk)
    risk_presentation = build_risk_presentation(
        presentation_risk,
        c.verdict,
        evidence_coverage,
    )
    summary = re.sub(
        r"\s*Threat type:.*?(?=(?:\s*Evidence coverage:)|$)",
        "",
        c.summary or "",
        flags=re.IGNORECASE,
    ).strip()
    summary = re.sub(
        r"\s*Evidence coverage(?: confidence)?:.*$",
        "",
        summary,
        flags=re.IGNORECASE,
    ).strip()
    summary = (
        f"{summary} Threat type: {threat_type} "
        "(investigative classification based on available evidence). "
        f"{evidence_coverage['summary']}"
    ).strip()
    timeline = [dict(event) for event in (c.timeline or [])]
    for event in timeline:
        if re.search(r"risk assessment", str(event.get("event", "")), re.IGNORECASE):
            detail = re.sub(
                r"\s*(?:Evidence coverage(?: confidence)?|Confidence):\s*\d+(?:\.\d+)?%\.?",
                "",
                str(event.get("detail", "")),
                flags=re.IGNORECASE,
            ).strip()
            event["detail"] = f"{detail} {evidence_coverage['summary']}".strip()

    return {
        "id": c.id,
        "created_at": c.created_at.isoformat(),
        "threat_type": threat_type,
        "severity": c.severity,
        "verdict": c.verdict,
        "is_demo": c.is_demo,
        "risk_score": {
            "total": c.risk_score_total,
            "level": c.risk_score_level,
            **risk_breakdown,
            "confidence": evidence_coverage["percentage"],
            "evidence_coverage": evidence_coverage,
            "explanation": explanation,
            "presentation": risk_presentation,
        },
        "ai_analysis": (c.risk_breakdown or {}).get("ai_analysis"),
        "email": {
            "from_addr": e.from_addr if e else "",
            "to_addr": e.to_addr if e else "",
            "subject": e.subject if e else "",
            "date": e.date if e else "",
            "reply_to": e.reply_to if e else None,
            "message_id": e.message_id if e else None,
            "received_ips": e.received_ips if e else [],
            "received_path": e.received_path if e and e.received_path else [],
            "urls": e.urls if e else [],
            "email_addresses": e.email_addresses if e else [],
            "headers": e.headers if e else [],
            "attachments": e.attachments if e else [],
            "body_text": e.body_text if e else "",
        },
        "auth": auth,
        "iocs": serialized_iocs,
        "mitre_mappings": c.mitre_mappings or [],
        "timeline": timeline,
        "graph_nodes": c.graph_nodes or [],
        "graph_edges": c.graph_edges or [],
        "why_flagged": c.why_flagged or [],
        "summary": summary,
        "evidence_count": len(c.iocs or []) + len(c.mitre_mappings or []),
    }


@router.get("")
async def list_cases(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(models.Case)
        .options(selectinload(models.Case.email), selectinload(models.Case.iocs))
        .order_by(desc(models.Case.created_at))
        .limit(100)
    )
    cases = result.scalars().all()
    items = []
    for c in cases:
        serialized = _serialize_case(c)
        items.append({
            "id": c.id,
            "created_at": c.created_at.isoformat(),
            "threat_type": serialized["threat_type"],
            "verdict": c.verdict,
            "severity": c.severity,
            "risk_score_total": c.risk_score_total,
            "from_addr": c.email.from_addr if c.email else "",
            "subject": c.email.subject if c.email else "",
            "ioc_count": len(c.iocs or []),
            "is_demo": c.is_demo,
        })
    return items


@router.get("/{case_id}")
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(models.Case)
        .options(selectinload(models.Case.email), selectinload(models.Case.iocs))
        .where(models.Case.id == case_id)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    return _serialize_case(case)


@router.delete("/{case_id}")
async def delete_case(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Case).where(models.Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    await db.delete(case)
    await db.commit()
    return {"deleted": case_id}
