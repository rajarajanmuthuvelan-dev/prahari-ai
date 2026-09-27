from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from ..database import get_db
from .. import models
from ..services.report_gen import generate_json_report, generate_html_report
from .cases import _serialize_case

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{case_id}/json")
async def download_json(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(models.Case)
        .options(selectinload(models.Case.email), selectinload(models.Case.iocs))
        .where(models.Case.id == case_id)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    body = generate_json_report(_serialize_case(case))
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="PRAHARI-{case_id}-Report.json"'},
    )


@router.get("/{case_id}/html")
async def download_html(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(models.Case)
        .options(selectinload(models.Case.email), selectinload(models.Case.iocs))
        .where(models.Case.id == case_id)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    serialized = _serialize_case(case)
    serialized.update({
        "from_addr": case.email.from_addr if case.email else "",
        "to_addr": case.email.to_addr if case.email else "",
        "subject": case.email.subject if case.email else "",
        "date": case.email.date if case.email else "",
        "reply_to": case.email.reply_to if case.email else None,
    })
    html = generate_html_report(serialized)
    return Response(
        content=html.encode("utf-8"),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="PRAHARI-{case_id}-Report.html"'},
    )
