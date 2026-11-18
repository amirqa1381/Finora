from collections.abc import AsyncIterator

from typing import Annotated
from fastapi import Request, Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_sessionmaker
from app.modules.audit.service import AuditService


async def get_db_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_redis(request: Request) -> Redis:
    return request.app.state.redis  # type: ignore[no-any-return]


async def get_audit_service(session: Annotated[AsyncSession, Depends(get_db_session)]) -> AuditService:
    return AuditService(session)