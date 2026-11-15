from collections.abc import AsyncIterator

from fastapi import Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_sessionmaker


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