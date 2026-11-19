from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_sessionmaker
from app.modules.audit.service import AuditService
from app.modules.accounts.service import AccountsService
from app.core.exceptions import AuthenticationError
from app.core.rate_limit import RateLimiter
from app.core.security import InvalidTokenError, decode_access_token
from app.modules.accounts.models import User


_bearer = HTTPBearer(auto_error=False)  # we raise our own error format

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


async def get_accounts_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> AccountsService:
    return AccountsService(session, audit)

def get_client_ip(request: Request) -> str | None:
    # X-Forwarded-For is NOT trusted: anyone can send a fake one.
    # Enable it only behind a proxy you control.
    return request.client.host if request.client else None


async def get_rate_limiter(
    redis: Annotated[Redis, Depends(get_redis)],
) -> RateLimiter:
    return RateLimiter(redis)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    service: Annotated[AccountsService, Depends(get_accounts_service)],
) -> User:
    if credentials is None:
        raise AuthenticationError("Invalid or missing token")
    try:
        user_id = decode_access_token(credentials.credentials)
    except InvalidTokenError:
        raise AuthenticationError("Invalid or missing token") from None
    return await service.get_active_user(user_id)