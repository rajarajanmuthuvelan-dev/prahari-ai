from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import inspect, text
from sqlalchemy.orm import DeclarativeBase
from .config import settings

engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        email_columns = await conn.run_sync(
            lambda sync_conn: {
                column["name"] for column in inspect(sync_conn).get_columns("emails")
            }
        )
        if "received_path" not in email_columns:
            await conn.execute(text("ALTER TABLE emails ADD COLUMN received_path JSON"))
        case_columns = await conn.run_sync(
            lambda sync_conn: {
                column["name"] for column in inspect(sync_conn).get_columns("cases")
            }
        )
        if "threat_type" not in case_columns:
            await conn.execute(text("ALTER TABLE cases ADD COLUMN threat_type VARCHAR"))
        await conn.execute(text("""
            UPDATE cases
            SET threat_type = CASE LOWER(threat_type)
                WHEN 'bec' THEN 'Business Email Compromise'
                WHEN 'malware' THEN 'Malware / Suspicious Attachment'
                WHEN 'suspicious' THEN 'Suspicious Email'
                WHEN 'phishing' THEN 'Phishing'
                WHEN 'impersonation' THEN 'Impersonation'
                WHEN 'clean' THEN 'Clean'
                ELSE threat_type
            END
            WHERE threat_type IS NOT NULL
        """))
