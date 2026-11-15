import asyncio
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, get_redis

router = APIRouter(tags=["health"])
logger = structlog.get_logger(__name__)

CHECK_TIMEOUT_SECONDS = 2.0


@router.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


async def _check_database(session: AsyncSession) -> bool:
    try:
        await asyncio.wait_for(
            session.execute(text("SELECT 1")), timeout=CHECK_TIMEOUT_SECONDS
        )
    except Exception as exc:
        # Log only the exception TYPE: the message may contain a DSN or password.
        logger.warning("health_check_failed", check="database", error=type(exc).__name__)
        return False
    return True


async def _check_redis(redis: Redis) -> bool:
    try:
        await asyncio.wait_for(redis.ping(), timeout=CHECK_TIMEOUT_SECONDS)
    except Exception as exc:
        logger.warning("health_check_failed", check="redis", error=type(exc).__name__)
        return False
    return True


@router.get("/health/ready")
async def ready(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    redis: Annotated[Redis, Depends(get_redis)],
) -> JSONResponse:
    db_ok, redis_ok = await asyncio.gather(
        _check_database(session), _check_redis(redis)
    )
    all_ok = db_ok and redis_ok
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={
            "status": "ok" if all_ok else "error",
            "checks": {
                "database": "ok" if db_ok else "error",
                "redis": "ok" if redis_ok else "error",
            },
        },
    )