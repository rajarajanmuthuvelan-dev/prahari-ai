from datetime import datetime, timezone

from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models


async def allocate_case_id(
    db: AsyncSession,
    created_at: datetime | None = None,
) -> tuple[str, datetime]:
    created_at = created_at or datetime.now(timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    created_at = created_at.astimezone(timezone.utc)

    date_key = created_at.strftime("%Y%m%d")
    dialect_name = db.get_bind().dialect.name
    if dialect_name == "postgresql":
        insert = postgres_insert(models.CaseIDSequence)
    elif dialect_name == "sqlite":
        insert = sqlite_insert(models.CaseIDSequence)
    else:
        raise RuntimeError(
            f"Atomic case ID sequence allocation is unsupported for database dialect {dialect_name!r}."
        )

    statement = (
        insert.values(date_key=date_key, last_sequence=1)
        .on_conflict_do_update(
            index_elements=[models.CaseIDSequence.date_key],
            set_={
                "last_sequence": models.CaseIDSequence.last_sequence + 1,
            },
        )
        .returning(models.CaseIDSequence.last_sequence)
    )
    sequence = (await db.execute(statement)).scalar_one()
    case_id = (
        f"PRH-{created_at.year:04d}-EML-"
        f"{created_at:%m%d}-{sequence:04d}"
    )
    return case_id, created_at
